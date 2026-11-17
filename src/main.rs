use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use nbde::agent::{self, AgentError};
use nbde::args::{self, Mode, USAGE};
use nbde::config::{Config, ConfigError};
use nbde::harden::{HardenError, harden_process};
use nbde::pin::{self, Context, HttpExchange, Outcome, PinError};
use nbde::ui::Ui;
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};
use snafu::{ResultExt, Snafu};

/// `check` has no config file; it uses the agent's default attempt timeout.
const CHECK_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);
/// Bytes of sha256(P) shown by `check`, enough to compare against a known P.
const DIGEST_PREFIX_LEN: usize = 8;

#[derive(Debug, Snafu)]
enum Error {
    #[snafu(display("invalid arguments\n{USAGE}"))]
    Args { source: args::ArgsError },

    #[snafu(transparent)]
    Harden { source: HardenError },

    #[snafu(transparent)]
    Config { source: ConfigError },

    #[snafu(transparent)]
    Agent { source: AgentError },

    #[snafu(display("unlock check failed"))]
    Check { source: PinError },
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("nbde-agent: {}", snafu::Report::from_error(e));
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Error> {
    match args::parse(std::env::args_os().skip(1)).context(ArgsSnafu)? {
        Mode::Help => {
            println!("{USAGE}");
            Ok(())
        }
        Mode::Version => {
            println!("nbde-agent {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Mode::Daemon { config } => {
            harden_process()?;
            let config = Config::load(&config)?;
            let ui = Ui::from_env(config.console());
            Ok(agent::run(&config, &ui)?)
        }
        Mode::Check { jwe } => {
            harden_process()?;
            check(&jwe)
        }
    }
}

/// Runs one unlock attempt and prints per-server outcomes plus a digest
/// prefix of the recovered secret. The secret itself is never printed.
fn check(path: &Path) -> Result<(), Error> {
    let text = agent::read_jwe(path)?;
    let ctx = Context::new(Arc::new(HttpExchange::new(CHECK_ATTEMPT_TIMEOUT)));
    let result = pin::decrypt(&text, &ctx);

    for event in ctx.events() {
        let outcome = match event.outcome {
            Outcome::Released => "released".to_owned(),
            Outcome::Denied => "denied".to_owned(),
            Outcome::Failed(reason) => format!("failed: {reason}"),
        };
        println!("{}  {outcome}", event.url);
    }

    let secret = result.context(CheckSnafu)?;
    let digest = Sha256::digest(secret.expose_secret());
    let prefix: String = digest[..DIGEST_PREFIX_LEN]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    println!("threshold met; sha256(P)[0..{DIGEST_PREFIX_LEN}] = {prefix}");
    Ok(())
}
