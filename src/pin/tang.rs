//! clevis `tang` pin: blinded ECMR exchange (`docs/clevis-format.md` §2).
//!
//! X = C + e·G is sent to `/rec`; the server answers Y = s·X; the agent
//! computes Z = Y − e·S = s·C locally. The server never sees C or Z.

use std::time::Duration;

use p521::elliptic_curve::Generate;
use p521::{NonZeroScalar, ProjectivePoint, PublicKey};
use serde::Deserialize;
use snafu::{OptionExt, ResultExt, Snafu, ensure};
use zeroize::Zeroizing;

use super::{Context, Outcome};
use crate::http::{self, Endpoint, HttpError};
use crate::jose::{self, Cek, CompactJwe, EcJwk, JoseError};
use crate::secret::SecretBytes;

/// Length of a base64url SHA-256 thumbprint.
const KID_LEN: usize = 43;
const JWK_CONTENT_TYPE: &str = "application/jwk+json";

#[derive(Debug, Snafu)]
pub enum TangError {
    #[snafu(display("tang header: {reason}"))]
    Header { reason: &'static str },

    #[snafu(display("tang header is malformed"))]
    HeaderJson { source: serde_json::Error },

    #[snafu(display("tang kid must be a {KID_LEN}-character S256 thumbprint"))]
    Kid,

    #[snafu(display("no advertised key matches kid"))]
    NoMatchingKey,

    #[snafu(display("tang key material"))]
    Key { source: JoseError },

    #[snafu(display("system random number generator failed"))]
    Random,

    #[snafu(display("blinded point is the identity"))]
    Identity,

    #[snafu(display("{url}: recovery denied"))]
    Denied { url: String },

    #[snafu(display("{url}: recovery failed"))]
    Exchange { url: String, source: ExchangeError },

    #[snafu(display("{url}: invalid reply"))]
    Reply { url: String, source: JoseError },

    #[snafu(display("{url}: decryption failed"))]
    Decrypt { url: String, source: JoseError },
}

/// Transport for `POST {url}/rec/{kid}`. Abstracted so tests can run the
/// exchange in-process.
pub trait Exchange: Send + Sync {
    fn recover(&self, url: &str, kid: &str, x: &EcJwk) -> Result<EcJwk, ExchangeError>;
}

#[derive(Debug, Snafu)]
pub enum ExchangeError {
    #[snafu(
        display("server denied the request"),
        context(name(ExchangeDeniedSnafu))
    )]
    Denied,

    #[snafu(display("server answered HTTP {code}"))]
    Status { code: u16 },

    #[snafu(transparent)]
    Transport { source: HttpError },

    #[snafu(display("reply is not a JWK"))]
    ReplyJson { source: serde_json::Error },
}

/// Plain HTTP transport with a per-request timeout.
pub struct HttpExchange {
    timeout: Duration,
}

impl HttpExchange {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl Exchange for HttpExchange {
    fn recover(&self, url: &str, kid: &str, x: &EcJwk) -> Result<EcJwk, ExchangeError> {
        let endpoint = Endpoint::parse(url)?;
        let body = serde_json::to_vec(x).context(ReplyJsonSnafu)?;
        let response = http::post(
            &endpoint,
            &format!("/rec/{kid}"),
            JWK_CONTENT_TYPE,
            &body,
            self.timeout,
        )?;
        match response.status {
            200 => serde_json::from_slice(&response.body).context(ReplyJsonSnafu),
            403 => Err(ExchangeError::Denied),
            code => Err(ExchangeError::Status { code }),
        }
    }
}

#[derive(Debug, Deserialize)]
struct TangHeader {
    url: String,
    adv: Advertisement,
}

#[derive(Debug, Deserialize)]
struct Advertisement {
    keys: Vec<serde_json::Value>,
}

/// Recovers the plaintext of a `tang` pin JWE and records the outcome.
pub fn recover(jwe: &CompactJwe, ctx: &Context) -> Result<SecretBytes, TangError> {
    let header = jwe.header();
    let tang = header
        .clevis
        .as_ref()
        .and_then(|c| c.get("tang"))
        .context(HeaderSnafu {
            reason: "missing clevis.tang",
        })?;
    let tang: TangHeader = serde_json::from_value(tang.clone()).context(HeaderJsonSnafu)?;
    let kid = header.kid.as_deref().context(HeaderSnafu {
        reason: "missing kid",
    })?;
    ensure!(valid_kid(kid), KidSnafu);
    let client = header
        .epk
        .as_ref()
        .context(HeaderSnafu {
            reason: "missing epk",
        })?
        .to_public_key()
        .context(KeySnafu)?;
    let server = select_key(&tang.adv, kid)?;

    let result = exchange(jwe, ctx, &tang.url, kid, &client, &server);
    let outcome = match &result {
        Ok(_) => Outcome::Released,
        Err(TangError::Denied { .. }) => Outcome::Denied,
        Err(e) => Outcome::Failed(super::error_chain(e)),
    };
    ctx.record(&tang.url, outcome);
    result
}

fn exchange(
    jwe: &CompactJwe,
    ctx: &Context,
    url: &str,
    kid: &str,
    client: &PublicKey,
    server: &PublicKey,
) -> Result<SecretBytes, TangError> {
    let e = Zeroizing::new(NonZeroScalar::try_generate().map_err(|_| TangError::Random)?);
    let blind = Zeroizing::new(ProjectivePoint::GENERATOR * **e);
    let x = PublicKey::from_affine((client.to_projective() + *blind).to_affine())
        .map_err(|_| TangError::Identity)?;

    let reply = match ctx
        .exchange()
        .recover(url, kid, &EcJwk::from_public_key(&x))
    {
        Ok(reply) => reply,
        Err(ExchangeError::Denied) => return DeniedSnafu { url }.fail(),
        Err(source) => {
            return Err(TangError::Exchange {
                url: url.to_owned(),
                source,
            });
        }
    };
    let y = reply.to_public_key().context(ReplySnafu { url })?;

    let unblind = Zeroizing::new(server.to_projective() * **e);
    let z = Zeroizing::new((y.to_projective() - *unblind).to_affine());
    let cek = Cek::ecdh_es(jwe.header(), jose::exchange_x(&z).as_slice())
        .context(DecryptSnafu { url })?;
    jwe.decrypt(&cek).context(DecryptSnafu { url })
}

/// Finds the advertised key whose S256 thumbprint is `kid`. Keys that are not
/// valid P-521 public keys (e.g. a future curve) are skipped.
fn select_key(adv: &Advertisement, kid: &str) -> Result<PublicKey, TangError> {
    adv.keys
        .iter()
        .filter_map(|v| serde_json::from_value::<EcJwk>(v.clone()).ok())
        .filter_map(|jwk| jwk.to_public_key().ok())
        .find(|key| jose::thumbprint_s256(key) == kid)
        .context(NoMatchingKeySnafu)
}

fn valid_kid(kid: &str) -> bool {
    kid.len() == KID_LEN
        && kid
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[cfg(test)]
mod tests {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use secrecy::ExposeSecret;

    use super::*;
    use crate::pin::testing::{MockTang, TANG_A_URL};
    use crate::pin::{Outcome, PinEvent};

    const TANG_JWE: &str = include_str!("../../tests/vectors/tang.jwe");
    const PLAINTEXT: &[u8] = include_bytes!("../../tests/vectors/plaintext");

    fn parse(text: &str) -> CompactJwe<'_> {
        CompactJwe::parse(text).unwrap_or_else(|e| unreachable!("{e}"))
    }

    #[test]
    fn recovers_the_reference_vector_through_ecmr() {
        let ctx = MockTang::new(&[]).context();
        let plaintext = recover(&parse(TANG_JWE), &ctx).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(plaintext.expose_secret(), PLAINTEXT);
        assert_eq!(
            ctx.events(),
            vec![PinEvent {
                url: TANG_A_URL.to_owned(),
                outcome: Outcome::Released
            }]
        );
    }

    #[test]
    fn blinding_differs_per_request() {
        struct Capture(std::sync::Mutex<Vec<EcJwk>>, MockTang);
        impl Exchange for Capture {
            fn recover(&self, url: &str, kid: &str, x: &EcJwk) -> Result<EcJwk, ExchangeError> {
                self.0
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(x.clone());
                self.1.recover(url, kid, x)
            }
        }
        let capture = std::sync::Arc::new(Capture(Default::default(), MockTang::new(&[])));
        let ctx = Context::new(capture.clone());
        for _ in 0..2 {
            assert!(recover(&parse(TANG_JWE), &ctx).is_ok());
        }
        let sent = capture
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(sent.len(), 2);
        assert_ne!(sent[0], sent[1]);
        let epk = parse(TANG_JWE).header().epk.clone();
        assert!(
            sent.iter().all(|x| Some(x) != epk.as_ref()),
            "C sent unblinded"
        );
    }

    #[test]
    fn denial_is_reported() {
        let ctx = MockTang::new(&[TANG_A_URL]).context();
        let result = recover(&parse(TANG_JWE), &ctx);
        assert!(
            matches!(result, Err(TangError::Denied { .. })),
            "{result:?}"
        );
        assert_eq!(ctx.events()[0].outcome, Outcome::Denied);
    }

    #[test]
    fn a_wrong_reply_fails_decryption() {
        let ctx = MockTang::corrupting().context();
        let result = recover(&parse(TANG_JWE), &ctx);
        assert!(
            matches!(result, Err(TangError::Decrypt { .. })),
            "{result:?}"
        );
        assert!(matches!(ctx.events()[0].outcome, Outcome::Failed(_)));
    }

    #[test]
    fn an_invalid_reply_point_is_rejected() {
        struct OffCurve;
        impl Exchange for OffCurve {
            fn recover(&self, _: &str, _: &str, x: &EcJwk) -> Result<EcJwk, ExchangeError> {
                let mut y = x.clone();
                let mut bytes = Base64UrlUnpadded::decode_vec(&y.y).unwrap_or_default();
                if let Some(last) = bytes.last_mut() {
                    *last ^= 1;
                }
                y.y = Base64UrlUnpadded::encode_string(&bytes);
                Ok(y)
            }
        }
        let ctx = Context::new(std::sync::Arc::new(OffCurve));
        let result = recover(&parse(TANG_JWE), &ctx);
        assert!(matches!(result, Err(TangError::Reply { .. })), "{result:?}");
    }

    fn with_header(edit: impl FnOnce(&mut serde_json::Value)) -> String {
        let (protected, rest) = TANG_JWE
            .trim_end()
            .split_once('.')
            .unwrap_or_else(|| unreachable!());
        let mut header: serde_json::Value =
            serde_json::from_slice(&Base64UrlUnpadded::decode_vec(protected).unwrap_or_default())
                .unwrap_or_else(|e| unreachable!("{e}"));
        edit(&mut header);
        let encoded = Base64UrlUnpadded::encode_string(header.to_string().as_bytes());
        format!("{encoded}.{rest}")
    }

    #[test]
    fn header_problems_are_rejected_before_any_request() {
        type Case = (fn(&mut serde_json::Value), fn(&TangError) -> bool);
        let cases: [Case; 5] = [
            (|h| h["kid"] = "x".into(), |e| matches!(e, TangError::Kid)),
            (
                |h| h["kid"] = "A".repeat(KID_LEN).into(),
                |e| matches!(e, TangError::NoMatchingKey),
            ),
            (
                |h| {
                    if let Some(o) = h.as_object_mut() {
                        o.remove("epk");
                    }
                },
                |e| matches!(e, TangError::Header { .. }),
            ),
            (
                |h| h["clevis"]["tang"]["adv"]["keys"] = serde_json::json!([]),
                |e| matches!(e, TangError::NoMatchingKey),
            ),
            (
                |h| h["epk"]["crv"] = "P-256".into(),
                |e| matches!(e, TangError::Key { .. }),
            ),
        ];
        for (edit, expected) in cases {
            let text = with_header(edit);
            let ctx = MockTang::new(&[]).context();
            let err = recover(&parse(&text), &ctx)
                .err()
                .unwrap_or_else(|| unreachable!());
            assert!(expected(&err), "{err:?}");
            assert!(ctx.events().is_empty(), "request sent despite bad header");
        }
    }

    #[test]
    fn a_tampered_header_cannot_decrypt() {
        // Re-pointing the URL keeps the exchange valid but breaks the AAD.
        let text = with_header(|h| h["clevis"]["tang"]["url"] = "http://127.0.0.1:1".into());
        let ctx = MockTang::new(&[]).context();
        let result = recover(&parse(&text), &ctx);
        assert!(
            matches!(result, Err(TangError::Decrypt { .. })),
            "{result:?}"
        );
    }

    #[test]
    fn http_exchange_matches_server_math() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| unreachable!("{e}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|e| unreachable!("{e}"));
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap_or_else(|e| unreachable!("{e}"));
            let mut request = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = conn.read(&mut chunk).unwrap_or(0);
                request.extend_from_slice(&chunk[..n]);
                if n == 0 || request.ends_with(b"}") {
                    break;
                }
            }
            let text = String::from_utf8(request).unwrap_or_default();
            let (head, body) = text.split_once("\r\n\r\n").unwrap_or_default();
            let kid = head
                .split_whitespace()
                .nth(1)
                .and_then(|p| p.strip_prefix("/rec/"))
                .unwrap_or_default()
                .to_owned();
            let x: EcJwk = serde_json::from_str(body).unwrap_or_else(|e| unreachable!("{e}"));
            let y = MockTang::new(&[])
                .recover(TANG_A_URL, &kid, &x)
                .unwrap_or_else(|e| unreachable!("{e}"));
            let reply = serde_json::to_string(&y).unwrap_or_default();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/jwk+json\r\nContent-Length: {}\r\n\r\n{reply}",
                reply.len()
            );
            conn.write_all(response.as_bytes())
                .unwrap_or_else(|e| unreachable!("{e}"));
        });

        // The vector's URL is fixed; route its exchange to the local server.
        struct Redirect(String, HttpExchange);
        impl Exchange for Redirect {
            fn recover(&self, _: &str, kid: &str, x: &EcJwk) -> Result<EcJwk, ExchangeError> {
                self.1.recover(&self.0, kid, x)
            }
        }
        let ctx = Context::new(std::sync::Arc::new(Redirect(
            format!("http://{addr}"),
            HttpExchange::new(Duration::from_secs(5)),
        )));
        let plaintext = recover(&parse(TANG_JWE), &ctx).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(plaintext.expose_secret(), PLAINTEXT);
        server
            .join()
            .unwrap_or_else(|_| unreachable!("server panicked"));
    }
}
