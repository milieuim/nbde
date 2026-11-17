//! Daemon mode (design §7.4, §7.5): acquire every configured volume's secret
//! over the network, retrying until the deadline, and hand each one to the
//! systemd-cryptsetup connection that asks for it.
//!
//! Acquisition starts before any connection arrives, so network waits overlap
//! with the rest of the boot. A connection that arrives early is held open;
//! at the deadline every held connection is closed without data, which sends
//! systemd-cryptsetup to its passphrase prompt.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use snafu::{ResultExt, Snafu, ensure};

use crate::config::Config;
use crate::jose::MAX_JWE_LEN;
use crate::pin::{self, Context, HttpExchange, Outcome, PinEvent};
use crate::secret::SecretBytes;
use crate::sink::{Accepted, KeySocket, Request, SinkError};
use crate::ui::Ui;

/// How often the main loop polls for connections and results.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Snafu)]
pub enum AgentError {
    #[snafu(display("read JWE {}", path.display()))]
    ReadJwe {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("JWE {} exceeds {MAX_JWE_LEN} bytes", path.display()))]
    JweTooLarge { path: PathBuf },

    #[snafu(transparent)]
    Sink { source: SinkError },

    #[snafu(display("start acquisition thread for {volume}"))]
    Spawn {
        volume: String,
        source: std::io::Error,
    },

    #[snafu(display("deadline reached before {} was unlocked", pending.join(", ")))]
    Deadline { pending: Vec<String> },
}

/// Reads a JWE file, refusing anything larger than [`MAX_JWE_LEN`].
pub fn read_jwe(path: &Path) -> Result<String, AgentError> {
    let file = std::fs::File::open(path).context(ReadJweSnafu { path })?;
    let mut text = String::new();
    let limit = u64::try_from(MAX_JWE_LEN)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    file.take(limit)
        .read_to_string(&mut text)
        .context(ReadJweSnafu { path })?;
    ensure!(text.len() <= MAX_JWE_LEN, JweTooLargeSnafu { path });
    Ok(text)
}

/// Timing for one acquisition loop.
#[derive(Debug, Clone, Copy)]
struct Timing {
    attempt_timeout: Duration,
    retry_interval: Duration,
    deadline: Instant,
}

/// Runs until every volume has been delivered (`Ok`) or the deadline passes.
pub fn run(config: &Config, ui: &Ui) -> Result<(), AgentError> {
    let timing = Timing {
        attempt_timeout: config.attempt_timeout(),
        retry_interval: config.retry_interval(),
        deadline: Instant::now() + config.deadline(),
    };
    let jwes = config
        .volumes()
        .iter()
        .map(|v| Ok((v.name.clone(), read_jwe(&v.jwe)?)))
        .collect::<Result<Vec<_>, AgentError>>()?;
    let socket = KeySocket::bind(config.socket())?;
    ui.ready();
    ui.status(&format!("waiting to unlock {}", names(config).join(", ")));

    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel();
    for (volume, text) in jwes {
        spawn_acquisition(volume, text, timing, &stop, tx.clone(), ui.clone())?;
    }
    drop(tx);

    let result = serve(config, ui, &socket, &rx, timing.deadline);
    stop.store(true, Ordering::Relaxed);
    ui.stopping();
    result
}

fn names(config: &Config) -> Vec<String> {
    config.volumes().iter().map(|v| v.name.clone()).collect()
}

fn serve(
    config: &Config,
    ui: &Ui,
    socket: &KeySocket,
    results: &Receiver<(String, SecretBytes)>,
    deadline: Instant,
) -> Result<(), AgentError> {
    let mut ready: HashMap<String, SecretBytes> = HashMap::new();
    let mut held: Vec<Request> = Vec::new();
    let mut delivered: HashSet<String> = HashSet::new();
    let total = config.volumes().len();

    loop {
        while let Ok((volume, secret)) = results.try_recv() {
            ready.insert(volume, secret);
        }

        let mut still_held = Vec::with_capacity(held.len());
        for request in held {
            match ready.get(request.volume()) {
                Some(secret) => {
                    let volume = request.volume().to_owned();
                    deliver(ui, request, secret);
                    delivered.insert(volume);
                }
                None => still_held.push(request),
            }
        }
        held = still_held;
        // A secret is handed out once; later connections get the passphrase prompt.
        ready.retain(|volume, _| !delivered.contains(volume));

        if delivered.len() == total {
            ui.status("all volumes unlocked");
            return Ok(());
        }
        if Instant::now() >= deadline {
            let pending: Vec<String> = names(config)
                .into_iter()
                .filter(|v| !delivered.contains(v))
                .collect();
            ui.status(&format!(
                "deadline reached; {} falls back to passphrase",
                pending.join(", ")
            ));
            held.into_iter().for_each(Request::refuse);
            return DeadlineSnafu { pending }.fail();
        }

        match socket.accept()? {
            Some(Accepted::Request(request)) => {
                let known = config.volume(request.volume()).is_some();
                if known && !delivered.contains(request.volume()) {
                    held.push(request);
                } else {
                    ui.detail(&format!("refusing request for {}", request.volume()));
                    request.refuse();
                }
            }
            Some(Accepted::Rejected(reason)) => {
                ui.detail(&format!("rejected connection: {reason}"))
            }
            None => thread::sleep(POLL_INTERVAL),
        }
    }
}

fn deliver(ui: &Ui, request: Request, secret: &SecretBytes) {
    let volume = request.volume().to_owned();
    match request.deliver(secret) {
        Ok(()) => ui.status(&format!("{volume}: key delivered")),
        Err(e) => ui.status(&format!("{volume}: delivery failed: {e}")),
    }
}

fn spawn_acquisition(
    volume: String,
    text: String,
    timing: Timing,
    stop: &Arc<AtomicBool>,
    tx: Sender<(String, SecretBytes)>,
    ui: Ui,
) -> Result<(), AgentError> {
    let stop = Arc::clone(stop);
    let name = volume.clone();
    thread::Builder::new()
        .name(format!("nbde-{volume}"))
        .spawn(move || acquire(&name, &text, timing, &stop, &tx, &ui))
        .map(drop)
        .context(SpawnSnafu { volume })
}

fn acquire(
    volume: &str,
    text: &str,
    timing: Timing,
    stop: &AtomicBool,
    tx: &Sender<(String, SecretBytes)>,
    ui: &Ui,
) {
    let mut attempt = 0u32;
    while !stop.load(Ordering::Relaxed) {
        let Some(remaining) = timing.deadline.checked_duration_since(Instant::now()) else {
            return;
        };
        attempt += 1;
        let timeout = timing.attempt_timeout.min(remaining);
        let ctx = Context::new(Arc::new(HttpExchange::new(timeout)));
        match pin::decrypt(text, &ctx) {
            Ok(secret) => {
                ui.status(&format!("{volume}: unlocked on attempt {attempt}"));
                // The receiver only disappears once the agent is finishing.
                let _ = tx.send((volume.to_owned(), secret));
                return;
            }
            Err(e) => {
                ui.status(&format!(
                    "{volume}: attempt {attempt} waiting ({})",
                    summarize(&ctx.events())
                ));
                ui.detail(&format!(
                    "{volume}: attempt {attempt}: {}",
                    pin::error_chain(&e)
                ));
            }
        }
        sleep_until(
            Instant::now() + timing.retry_interval,
            timing.deadline,
            stop,
        );
    }
}

fn summarize(events: &[PinEvent]) -> String {
    if events.is_empty() {
        return "no server reached".to_owned();
    }
    events
        .iter()
        .map(|e| {
            let outcome = match e.outcome {
                Outcome::Released => "released",
                Outcome::Denied => "denied",
                Outcome::Failed(_) => "unreachable",
            };
            format!("{} {outcome}", e.url)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn sleep_until(wake: Instant, deadline: Instant, stop: &AtomicBool) {
    let wake = wake.min(deadline);
    while !stop.load(Ordering::Relaxed) {
        let Some(left) = wake.checked_duration_since(Instant::now()) else {
            return;
        };
        thread::sleep(left.min(POLL_INTERVAL));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_jwe_enforces_the_size_limit() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| unreachable!("{e}"));
        let small = dir.path().join("small.jwe");
        let large = dir.path().join("large.jwe");
        std::fs::write(&small, "a.b.c.d.e").unwrap_or_else(|e| unreachable!("{e}"));
        std::fs::write(&large, "a".repeat(MAX_JWE_LEN + 1)).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(read_jwe(&small).ok().as_deref(), Some("a.b.c.d.e"));
        assert!(matches!(
            read_jwe(&large),
            Err(AgentError::JweTooLarge { .. })
        ));
        assert!(matches!(
            read_jwe(&dir.path().join("missing")),
            Err(AgentError::ReadJwe { .. })
        ));
    }

    #[test]
    fn summaries_name_each_server() {
        let events = [
            PinEvent {
                url: "http://a".into(),
                outcome: Outcome::Released,
            },
            PinEvent {
                url: "http://b".into(),
                outcome: Outcome::Failed("connect".into()),
            },
        ];
        assert_eq!(
            summarize(&events),
            "http://a released, http://b unreachable"
        );
        assert_eq!(summarize(&[]), "no server reached");
    }

    #[test]
    fn sleep_until_returns_at_the_deadline_or_on_stop() {
        let stop = AtomicBool::new(false);
        let start = Instant::now();
        sleep_until(
            start + Duration::from_secs(5),
            start + Duration::from_millis(150),
            &stop,
        );
        assert!(start.elapsed() < Duration::from_secs(1));

        stop.store(true, Ordering::Relaxed);
        let start = Instant::now();
        sleep_until(
            start + Duration::from_secs(5),
            start + Duration::from_secs(5),
            &stop,
        );
        assert!(start.elapsed() < Duration::from_millis(50));
    }
}
