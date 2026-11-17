use std::process::ExitCode;

use nbde::args::{self, Mode, USAGE};
use nbde::config::{Config, ConfigError};
use nbde::harden::{HardenError, harden_process};
use snafu::{ResultExt, Snafu};

#[derive(Debug, Snafu)]
enum Error {
    #[snafu(display("invalid arguments\n{USAGE}"))]
    Args { source: args::ArgsError },

    #[snafu(transparent)]
    Harden { source: HardenError },

    #[snafu(transparent)]
    Config { source: ConfigError },

    #[snafu(display("{mode} mode is not implemented yet"))]
    NotImplemented { mode: &'static str },
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
            let _config = Config::load(&config)?;
            NotImplementedSnafu { mode: "daemon" }.fail()
        }
        Mode::Check { jwe: _ } => {
            harden_process()?;
            NotImplementedSnafu { mode: "check" }.fail()
        }
    }
}
