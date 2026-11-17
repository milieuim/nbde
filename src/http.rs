//! Minimal plaintext HTTP/1.1 client for Tang `/rec` (design §7.4).
//!
//! Only IP-literal `http://` URLs are accepted: the initrd must not depend on
//! DNS, and Tang's security does not rely on the transport. There are no
//! redirects, proxies or keep-alive; every response is size-bounded.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use snafu::{ResultExt, Snafu, ensure};

/// Header block plus body.
pub const MAX_RESPONSE_LEN: usize = 16 * 1024;
pub const MAX_BODY_LEN: usize = 8 * 1024;

const DEFAULT_PORT: u16 = 80;

#[derive(Debug, Snafu)]
pub enum HttpError {
    #[snafu(display("invalid URL `{url}`: {reason}"))]
    Url { url: String, reason: &'static str },

    #[snafu(display("connect to {addr}"))]
    Connect {
        addr: SocketAddr,
        source: std::io::Error,
    },

    #[snafu(display("I/O with {addr}"))]
    Io {
        addr: SocketAddr,
        source: std::io::Error,
    },

    #[snafu(display("request to {addr} timed out"))]
    Timeout { addr: SocketAddr },

    #[snafu(display("response from {addr} exceeds {MAX_RESPONSE_LEN} bytes"))]
    TooLarge { addr: SocketAddr },

    #[snafu(display("malformed response: {reason}"))]
    Malformed { reason: &'static str },
}

/// A parsed `http://<ip-literal>[:port][/path]` base URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    addr: SocketAddr,
    authority: String,
    base_path: String,
}

impl Endpoint {
    pub fn parse(url: &str) -> Result<Self, HttpError> {
        let fail = |reason| HttpError::Url {
            url: url.to_owned(),
            reason,
        };
        let rest = url
            .strip_prefix("http://")
            .ok_or_else(|| fail("scheme must be http"))?;
        ensure!(
            rest.bytes().all(|b| b.is_ascii_graphic()),
            UrlSnafu {
                url,
                reason: "contains whitespace or control characters"
            }
        );
        ensure!(
            !rest.contains(['?', '#', '@']),
            UrlSnafu {
                url,
                reason: "query, fragment and userinfo are not supported"
            }
        );

        let (authority, base_path) = match rest.find('/') {
            Some(i) => rest.split_at(i),
            None => (rest, ""),
        };
        let (ip, port) =
            parse_authority(authority).ok_or_else(|| fail("host must be an IP literal"))?;
        Ok(Self {
            addr: SocketAddr::new(ip, port),
            authority: authority.to_owned(),
            base_path: base_path.to_owned(),
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

fn parse_authority(authority: &str) -> Option<(IpAddr, u16)> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let ip: Ipv6Addr = host.parse().ok()?;
        let port = match after {
            "" => None,
            p => Some(p.strip_prefix(':')?),
        };
        (IpAddr::V6(ip), port)
    } else {
        let (host, port) = match authority.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        };
        let ip: Ipv4Addr = host.parse().ok()?;
        (IpAddr::V4(ip), port)
    };
    let port = match port {
        None => DEFAULT_PORT,
        Some(p) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => p.parse().ok()?,
        Some(_) => return None,
    };
    Some((host, port))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

/// POSTs `body` to `<base_path><suffix>`. `suffix` must already be a valid
/// path fragment (the caller only passes `/rec/<base64url kid>`).
pub fn post(
    endpoint: &Endpoint,
    suffix: &str,
    content_type: &str,
    body: &[u8],
    timeout: Duration,
) -> Result<Response, HttpError> {
    let addr = endpoint.addr;
    let deadline = Instant::now() + timeout;
    let mut stream = TcpStream::connect_timeout(&addr, timeout).context(ConnectSnafu { addr })?;
    stream.set_nodelay(true).context(IoSnafu { addr })?;

    let head = format!(
        "POST {}{suffix} HTTP/1.1\r\nHost: {}\r\nContent-Type: {content_type}\r\n\
         Accept: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        endpoint.base_path,
        endpoint.authority,
        body.len()
    );
    stream
        .set_write_timeout(Some(remaining(deadline, addr)?))
        .context(IoSnafu { addr })?;
    stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.write_all(body))
        .map_err(|e| io_error(e, addr))?;

    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    loop {
        stream
            .set_read_timeout(Some(remaining(deadline, addr)?))
            .context(IoSnafu { addr })?;
        let n = stream.read(&mut chunk).map_err(|e| io_error(e, addr))?;
        let eof = n == 0;
        ensure!(buf.len() + n <= MAX_RESPONSE_LEN, TooLargeSnafu { addr });
        buf.extend_from_slice(&chunk[..n]);
        if let Some(response) = parse_response(&buf, eof)? {
            return Ok(response);
        }
    }
}

fn remaining(deadline: Instant, addr: SocketAddr) -> Result<Duration, HttpError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(HttpError::Timeout { addr })
}

fn io_error(source: std::io::Error, addr: SocketAddr) -> HttpError {
    match source.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
            HttpError::Timeout { addr }
        }
        _ => HttpError::Io { addr, source },
    }
}

/// Parses a buffered response. Returns `Ok(None)` while more input is needed.
fn parse_response(buf: &[u8], eof: bool) -> Result<Option<Response>, HttpError> {
    let malformed = |reason| HttpError::Malformed { reason };
    let Some(head_end) = find(buf, b"\r\n\r\n") else {
        return if eof {
            Err(malformed("connection closed before headers ended"))
        } else {
            Ok(None)
        };
    };
    let head = std::str::from_utf8(&buf[..head_end]).map_err(|_| malformed("non-UTF-8 headers"))?;
    let rest = &buf[head_end + 4..];
    let mut lines = head.split("\r\n");

    let status_line = lines
        .next()
        .ok_or_else(|| malformed("missing status line"))?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    ensure!(
        version == "HTTP/1.1" || version == "HTTP/1.0",
        MalformedSnafu {
            reason: "unsupported HTTP version"
        }
    );
    let code = parts.next().unwrap_or_default();
    ensure!(
        code.len() == 3 && code.bytes().all(|b| b.is_ascii_digit()),
        MalformedSnafu {
            reason: "invalid status code"
        }
    );
    let status: u16 = code.parse().map_err(|_| malformed("invalid status code"))?;

    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| malformed("invalid header line"))?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            ensure!(
                content_length.is_none(),
                MalformedSnafu {
                    reason: "repeated Content-Length"
                }
            );
            let len: usize = value
                .parse()
                .map_err(|_| malformed("invalid Content-Length"))?;
            content_length = Some(len);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            ensure!(
                value.eq_ignore_ascii_case("chunked"),
                MalformedSnafu {
                    reason: "unsupported Transfer-Encoding"
                }
            );
            chunked = true;
        }
    }
    ensure!(
        !(chunked && content_length.is_some()),
        MalformedSnafu {
            reason: "both Content-Length and chunked"
        }
    );

    let body = if chunked {
        match decode_chunked(rest)? {
            Some(body) => body,
            None if eof => return Err(malformed("truncated chunked body")),
            None => return Ok(None),
        }
    } else if let Some(len) = content_length {
        ensure!(
            len <= MAX_BODY_LEN,
            MalformedSnafu {
                reason: "body too large"
            }
        );
        if rest.len() < len {
            return if eof {
                Err(malformed("truncated body"))
            } else {
                Ok(None)
            };
        }
        rest[..len].to_vec()
    } else if eof {
        rest.to_vec()
    } else {
        return Ok(None);
    };
    ensure!(
        body.len() <= MAX_BODY_LEN,
        MalformedSnafu {
            reason: "body too large"
        }
    );
    Ok(Some(Response { status, body }))
}

/// Decodes a complete chunked body; `Ok(None)` if the terminating chunk has
/// not arrived yet. Trailers are not supported.
fn decode_chunked(mut input: &[u8]) -> Result<Option<Vec<u8>>, HttpError> {
    let malformed = |reason| HttpError::Malformed { reason };
    let mut body = Vec::new();
    loop {
        let Some(line_end) = find(input, b"\r\n") else {
            return Ok(None);
        };
        let size_text =
            std::str::from_utf8(&input[..line_end]).map_err(|_| malformed("invalid chunk size"))?;
        let size_text = size_text.split(';').next().unwrap_or_default().trim();
        let size =
            usize::from_str_radix(size_text, 16).map_err(|_| malformed("invalid chunk size"))?;
        ensure!(
            size <= MAX_BODY_LEN && body.len() + size <= MAX_BODY_LEN,
            MalformedSnafu {
                reason: "body too large"
            }
        );
        input = &input[line_end + 2..];
        if size == 0 {
            return match input {
                [b'\r', b'\n', ..] => Ok(Some(body)),
                [] | [b'\r'] => Ok(None),
                _ => Err(malformed("chunked trailers are not supported")),
            };
        }
        if input.len() < size + 2 {
            return Ok(None);
        }
        ensure!(
            &input[size..size + 2] == b"\r\n",
            MalformedSnafu {
                reason: "chunk missing CRLF"
            }
        );
        body.extend_from_slice(&input[..size]);
        input = &input[size + 2..];
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    fn ok<T, E: std::fmt::Display>(r: Result<T, E>) -> T {
        r.unwrap_or_else(|e| unreachable!("{e}"))
    }

    #[test]
    fn parses_ip_literal_urls() {
        let e = ok(Endpoint::parse("http://127.0.0.1:7500/c/eihort"));
        assert_eq!(e.addr(), ok("127.0.0.1:7500".parse::<SocketAddr>()));
        assert_eq!(e.base_path, "/c/eihort");
        assert_eq!(e.authority, "127.0.0.1:7500");

        let e = ok(Endpoint::parse("http://[2a0f::1]:7500"));
        assert_eq!(e.addr(), ok("[2a0f::1]:7500".parse::<SocketAddr>()));
        assert_eq!(e.base_path, "");

        let e = ok(Endpoint::parse("http://10.0.0.1"));
        assert_eq!(e.addr().port(), 80);
        let e = ok(Endpoint::parse("http://[::1]/x"));
        assert_eq!(e.addr().port(), 80);
    }

    #[test]
    fn rejects_unsupported_urls() {
        for url in [
            "https://127.0.0.1",
            "http://example.com",
            "http://user@127.0.0.1",
            "http://127.0.0.1/a?b",
            "http://127.0.0.1:",
            "http://127.0.0.1:99999",
            "http://[::1",
            "http://[::1]x",
            "http://127.0.0.1/a b",
            "http://127.0.0.1/a\r\nX: y",
        ] {
            assert!(Endpoint::parse(url).is_err(), "accepted {url:?}");
        }
    }

    #[test]
    fn parses_content_length_responses() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA";
        assert_eq!(
            ok(parse_response(raw, false)),
            Some(Response {
                status: 200,
                body: b"hello".to_vec()
            })
        );
        assert_eq!(ok(parse_response(&raw[..30], false)), None);
        assert!(parse_response(&raw[..40], true).is_err());
    }

    #[test]
    fn parses_chunked_and_close_delimited_responses() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\n";
        assert_eq!(
            ok(parse_response(raw, false)).map(|r| r.body),
            Some(b"abcde".to_vec())
        );
        assert_eq!(ok(parse_response(&raw[..raw.len() - 2], false)), None);

        let raw = b"HTTP/1.0 403 Forbidden\r\n\r\nno";
        assert_eq!(ok(parse_response(raw, false)), None);
        assert_eq!(
            ok(parse_response(raw, true)),
            Some(Response {
                status: 403,
                body: b"no".to_vec()
            })
        );
    }

    #[test]
    fn rejects_malformed_responses() {
        for raw in [
            &b"HTTP/2 200 OK\r\n\r\n"[..],
            b"HTTP/1.1 20 OK\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nbroken\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 99999\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX: y\r\n\r\n",
        ] {
            assert!(
                parse_response(raw, true).is_err(),
                "accepted {}",
                String::from_utf8_lossy(raw)
            );
        }
    }

    fn serve_once(reply: &'static [u8]) -> (SocketAddr, thread::JoinHandle<Vec<u8>>) {
        let listener = ok(TcpListener::bind("127.0.0.1:0"));
        let addr = ok(listener.local_addr());
        let handle = thread::spawn(move || {
            let (mut conn, _) = ok(listener.accept());
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            while find(&request, b"\r\n\r\n").is_none() || !request.ends_with(b"BODY") {
                let n = ok(conn.read(&mut chunk));
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..n]);
            }
            ok(conn.write_all(reply));
            request
        });
        (addr, handle)
    }

    #[test]
    fn posts_and_reads_a_response() {
        let (addr, handle) = serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
        let endpoint = ok(Endpoint::parse(&format!("http://{addr}/c/x")));
        let response = ok(post(
            &endpoint,
            "/rec/kid",
            "application/jwk+json",
            b"BODY",
            Duration::from_secs(5),
        ));
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"{}");

        let request =
            String::from_utf8(ok(handle.join().map_err(|_| "server panicked"))).unwrap_or_default();
        assert!(
            request.starts_with("POST /c/x/rec/kid HTTP/1.1\r\n"),
            "{request}"
        );
        assert!(
            request.contains(&format!("\r\nHost: {addr}\r\n")),
            "{request}"
        );
        assert!(request.contains("\r\nContent-Length: 4\r\n"), "{request}");
        assert!(request.contains("\r\nConnection: close\r\n"), "{request}");
    }

    #[test]
    fn times_out_on_a_silent_server() {
        let listener = ok(TcpListener::bind("127.0.0.1:0"));
        let addr = ok(listener.local_addr());
        let endpoint = ok(Endpoint::parse(&format!("http://{addr}")));
        let result = post(&endpoint, "/rec/k", "a/b", b"", Duration::from_millis(300));
        assert!(
            matches!(result, Err(HttpError::Timeout { .. })),
            "{result:?}"
        );
        drop(listener);
    }

    #[test]
    fn reports_connection_refused() {
        let listener = ok(TcpListener::bind("127.0.0.1:0"));
        let addr = ok(listener.local_addr());
        drop(listener);
        let endpoint = ok(Endpoint::parse(&format!("http://{addr}")));
        let result = post(&endpoint, "/rec/k", "a/b", b"", Duration::from_secs(2));
        assert!(
            matches!(result, Err(HttpError::Connect { .. })),
            "{result:?}"
        );
    }
}
