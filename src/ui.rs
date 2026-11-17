//! Operator-facing status (design §8.3): the console (visible on the BMC),
//! `sd_notify` `STATUS=` and stderr, which systemd routes to the journal.
//! Every channel is best effort; a missing console must not stop an unlock.

use std::ffi::OsString;
use std::io::Write;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::path::PathBuf;

use rustix::fs::{Mode, OFlags};

const CONSOLE: &str = "/dev/console";

#[derive(Debug, Clone)]
enum NotifyTarget {
    Path(PathBuf),
    Abstract(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct Ui {
    console: bool,
    notify: Option<NotifyTarget>,
}

impl Ui {
    /// Reads `NOTIFY_SOCKET`; `console` enables `/dev/console` output.
    pub fn from_env(console: bool) -> Self {
        Self::new(console, std::env::var_os("NOTIFY_SOCKET"))
    }

    fn new(console: bool, notify_socket: Option<OsString>) -> Self {
        let notify = notify_socket.and_then(|value| match value.as_encoded_bytes() {
            [b'@', name @ ..] => Some(NotifyTarget::Abstract(name.to_vec())),
            [b'/', ..] => Some(NotifyTarget::Path(PathBuf::from(value))),
            _ => None,
        });
        Self { console, notify }
    }

    /// A one-line status for all channels.
    pub fn status(&self, message: &str) {
        let line = single_line(message);
        eprintln!("nbde-agent: {line}");
        if self.console {
            write_console(&format!("nbde: {line}\n"));
        }
        self.notify(&format!("STATUS={line}"));
    }

    /// Detail that belongs in the journal only.
    pub fn detail(&self, message: &str) {
        eprintln!("nbde-agent: {}", single_line(message));
    }

    pub fn ready(&self) {
        self.notify("READY=1");
    }

    pub fn stopping(&self) {
        self.notify("STOPPING=1");
    }

    fn notify(&self, payload: &str) {
        let Some(target) = &self.notify else { return };
        let Ok(socket) = UnixDatagram::unbound() else {
            return;
        };
        // Best effort: systemd may already have stopped listening.
        let _ = match target {
            NotifyTarget::Path(path) => socket.send_to(payload.as_bytes(), path),
            NotifyTarget::Abstract(name) => match SocketAddr::from_abstract_name(name) {
                Ok(addr) => socket.send_to_addr(payload.as_bytes(), &addr),
                Err(e) => Err(e),
            },
        };
    }
}

fn single_line(message: &str) -> String {
    message.replace(['\n', '\r'], " ")
}

/// Writes without acquiring the console as controlling terminal.
fn write_console(text: &str) {
    let Ok(fd) = rustix::fs::open(
        CONSOLE,
        OFlags::WRONLY | OFlags::NOCTTY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) else {
        return;
    };
    let _ = std::fs::File::from(fd).write_all(text.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notify_socket_forms_are_parsed() {
        assert!(matches!(
            Ui::new(false, Some("@abc".into())).notify,
            Some(NotifyTarget::Abstract(ref n)) if n == b"abc"
        ));
        assert!(matches!(
            Ui::new(false, Some("/run/systemd/notify".into())).notify,
            Some(NotifyTarget::Path(_))
        ));
        assert!(Ui::new(false, Some("relative".into())).notify.is_none());
        assert!(Ui::new(false, None).notify.is_none());
    }

    #[test]
    fn status_reaches_the_notify_socket_on_one_line() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| unreachable!("{e}"));
        let path = dir.path().join("notify");
        let receiver = UnixDatagram::bind(&path).unwrap_or_else(|e| unreachable!("{e}"));
        let ui = Ui::new(false, Some(path.into_os_string()));

        ui.status("two\nlines");
        ui.ready();
        let mut buf = [0u8; 256];
        let n = receiver
            .recv(&mut buf)
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(&buf[..n], b"STATUS=two lines");
        let n = receiver
            .recv(&mut buf)
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(&buf[..n], b"READY=1");
    }
}
