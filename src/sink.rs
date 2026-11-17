//! AF_UNIX key delivery to systemd-cryptsetup (design §7.5).
//!
//! systemd-cryptsetup connects from the abstract address
//! `\0<16 hex>/cryptsetup/<volume>` and reads the key until EOF; closing
//! without data makes it fall back to a passphrase prompt (verified by the
//! `vm-cryptsetup-socket` test).

use std::io::{ErrorKind, Write};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rustix::fs::Mode;
use secrecy::ExposeSecret;
use snafu::{ResultExt, Snafu, ensure};

use crate::secret::SecretBytes;

const PEER_MARKER: &str = "/cryptsetup/";
/// Bounds a stuck reader; systemd-cryptsetup reads 64 bytes immediately.
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Snafu)]
pub enum SinkError {
    #[snafu(display("prepare socket directory {}", path.display()))]
    Directory {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("{} exists and is not a socket", path.display()))]
    NotSocket { path: PathBuf },

    #[snafu(display("remove stale socket {}", path.display()))]
    Stale {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("bind {}", path.display()))]
    Bind {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("accept on {}", path.display()))]
    Accept {
        path: PathBuf,
        source: std::io::Error,
    },
}

/// The listening key socket; the socket file is removed on drop.
pub struct KeySocket {
    listener: UnixListener,
    path: PathBuf,
}

/// A connection from systemd-cryptsetup asking for `volume`.
#[derive(Debug)]
pub struct Request {
    stream: UnixStream,
    volume: String,
}

pub enum Accepted {
    Request(Request),
    /// The peer is not systemd-cryptsetup running as root; already closed.
    Rejected(&'static str),
}

impl KeySocket {
    /// Binds `path` with mode 0600 in a 0700 directory, replacing a stale
    /// socket from an earlier run but nothing else.
    pub fn bind(path: &Path) -> Result<Self, SinkError> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).context(DirectorySnafu { path: dir })?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .context(DirectorySnafu { path: dir })?;
        }
        match std::fs::symlink_metadata(path) {
            Ok(meta) => {
                ensure!(meta.file_type().is_socket(), NotSocketSnafu { path });
                std::fs::remove_file(path).context(StaleSnafu { path })?;
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(source) => {
                return Err(SinkError::Stale {
                    path: path.to_owned(),
                    source,
                });
            }
        }

        let previous = rustix::process::umask(Mode::from_raw_mode(0o177));
        let bound = UnixListener::bind(path);
        rustix::process::umask(previous);
        let listener = bound.context(BindSnafu { path })?;
        listener.set_nonblocking(true).context(BindSnafu { path })?;
        Ok(Self {
            listener,
            path: path.to_owned(),
        })
    }

    /// Accepts one pending connection, or `Ok(None)` if none is waiting.
    pub fn accept(&self) -> Result<Option<Accepted>, SinkError> {
        let stream = match self.listener.accept() {
            Ok((stream, _)) => stream,
            Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(None),
            Err(e) if e.kind() == ErrorKind::Interrupted => return Ok(None),
            Err(source) => {
                return Err(SinkError::Accept {
                    path: self.path.clone(),
                    source,
                });
            }
        };
        Ok(Some(match identify(&stream) {
            Ok(volume) => Accepted::Request(Request { stream, volume }),
            Err(reason) => Accepted::Rejected(reason),
        }))
    }
}

impl Drop for KeySocket {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Request {
    pub fn volume(&self) -> &str {
        &self.volume
    }

    /// Writes the key bytes and closes the connection.
    pub fn deliver(mut self, secret: &SecretBytes) -> std::io::Result<()> {
        self.stream.set_nonblocking(false)?;
        self.stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
        self.stream.write_all(secret.expose_secret())?;
        self.stream.shutdown(std::net::Shutdown::Write)
    }

    /// Closes without data, which sends systemd-cryptsetup to its passphrase
    /// prompt.
    pub fn refuse(self) {
        drop(self);
    }
}

fn identify(stream: &UnixStream) -> Result<String, &'static str> {
    let cred = rustix::net::sockopt::socket_peercred(stream).map_err(|_| "no peer credentials")?;
    if !cred.uid.is_root() {
        return Err("peer is not root");
    }
    let addr = stream.peer_addr().map_err(|_| "no peer address")?;
    let name = addr
        .as_abstract_name()
        .ok_or("peer is not bound to an abstract address")?;
    parse_peer(name)
        .map(str::to_owned)
        .ok_or("peer address is not systemd-cryptsetup's")
}

/// Extracts `<volume>` from `<16 hex>/cryptsetup/<volume>`.
fn parse_peer(name: &[u8]) -> Option<&str> {
    let name = std::str::from_utf8(name).ok()?;
    let (random, volume) = name.split_once(PEER_MARKER)?;
    let valid_random = !random.is_empty() && random.bytes().all(|b| b.is_ascii_hexdigit());
    let valid_volume = !volume.is_empty() && !volume.contains('/');
    (valid_random && valid_volume).then_some(volume)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn peer_names_are_parsed() {
        assert_eq!(
            parse_peer(b"5b7e16de1c404a81/cryptsetup/nbdetest"),
            Some("nbdetest")
        );
        for bad in [
            &b"/cryptsetup/x"[..],
            b"5b7e16de/cryptsetup/",
            b"zz/cryptsetup/x",
            b"5b7e/cryptsetup/a/b",
            b"5b7e/other/x",
            b"\xff/cryptsetup/x",
        ] {
            assert_eq!(parse_peer(bad), None, "{bad:?}");
        }
    }

    fn connect_as(socket: &Path, abstract_name: Option<&[u8]>) -> UnixStream {
        let ok = |r: std::io::Result<UnixStream>| r.unwrap_or_else(|e| unreachable!("{e}"));
        match abstract_name {
            None => ok(UnixStream::connect(socket)),
            Some(name) => {
                // std cannot bind a client before connecting; emulate with rustix.
                use rustix::net::{AddressFamily, SocketAddrUnix, SocketType};
                let fd = rustix::net::socket(AddressFamily::UNIX, SocketType::STREAM, None)
                    .unwrap_or_else(|e| unreachable!("{e}"));
                let local =
                    SocketAddrUnix::new_abstract_name(name).unwrap_or_else(|e| unreachable!("{e}"));
                rustix::net::bind(&fd, &local).unwrap_or_else(|e| unreachable!("{e}"));
                let remote = SocketAddrUnix::new(socket).unwrap_or_else(|e| unreachable!("{e}"));
                rustix::net::connect(&fd, &remote).unwrap_or_else(|e| unreachable!("{e}"));
                UnixStream::from(fd)
            }
        }
    }

    fn accept(socket: &KeySocket) -> Accepted {
        for _ in 0..100 {
            if let Some(accepted) = socket.accept().unwrap_or_else(|e| unreachable!("{e}")) {
                return accepted;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        unreachable!("no connection arrived")
    }

    fn unique(tag: &str) -> Vec<u8> {
        format!("{:016x}/cryptsetup/{tag}", std::process::id()).into_bytes()
    }

    #[test]
    fn binds_privately_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| unreachable!("{e}"));
        let path = dir.path().join("sub/key.sock");
        let socket = KeySocket::bind(&path).unwrap_or_else(|e| unreachable!("{e}"));
        let mode = |p: &Path| {
            std::fs::metadata(p)
                .map(|m| m.permissions().mode() & 0o777)
                .ok()
        };
        assert_eq!(mode(&path), Some(0o600));
        assert_eq!(mode(&dir.path().join("sub")), Some(0o700));
        drop(socket);
        assert!(!path.exists());

        // A stale socket is replaced; a regular file is not.
        let stale = UnixListener::bind(&path).unwrap_or_else(|e| unreachable!("{e}"));
        drop(stale);
        assert!(KeySocket::bind(&path).is_ok());
        let file = dir.path().join("file");
        std::fs::write(&file, b"x").unwrap_or_else(|e| unreachable!("{e}"));
        assert!(matches!(
            KeySocket::bind(&file),
            Err(SinkError::NotSocket { .. })
        ));
    }

    #[test]
    fn delivers_to_a_cryptsetup_shaped_peer_when_root() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| unreachable!("{e}"));
        let path = dir.path().join("key.sock");
        let socket = KeySocket::bind(&path).unwrap_or_else(|e| unreachable!("{e}"));
        let name = unique("root-volume");
        let mut client = connect_as(&path, Some(&name));

        match accept(&socket) {
            Accepted::Request(request) => {
                assert_eq!(request.volume(), "root-volume");
                let secret = crate::secret::secret_bytes(b"key-bytes");
                request
                    .deliver(&secret)
                    .unwrap_or_else(|e| unreachable!("{e}"));
                let mut got = Vec::new();
                client
                    .read_to_end(&mut got)
                    .unwrap_or_else(|e| unreachable!("{e}"));
                assert_eq!(got, b"key-bytes");
            }
            // Unprivileged test runs exercise the uid check instead.
            Accepted::Rejected(reason) => {
                assert!(!rustix::process::geteuid().is_root());
                assert_eq!(reason, "peer is not root");
            }
        }
    }

    #[test]
    fn rejects_peers_without_a_cryptsetup_address() {
        if !rustix::process::geteuid().is_root() {
            // The uid check fires first for unprivileged runs; covered above.
            return;
        }
        let dir = tempfile::tempdir().unwrap_or_else(|e| unreachable!("{e}"));
        let path = dir.path().join("key.sock");
        let socket = KeySocket::bind(&path).unwrap_or_else(|e| unreachable!("{e}"));
        let _plain = connect_as(&path, None);
        assert!(matches!(accept(&socket), Accepted::Rejected(_)));
        let _wrong = connect_as(&path, Some(b"not-systemd"));
        assert!(matches!(accept(&socket), Accepted::Rejected(_)));
    }
}
