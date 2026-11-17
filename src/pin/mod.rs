//! clevis pin dispatch for the decrypt path (`docs/clevis-format.md`).
//!
//! Only `tang` and `sss` are supported; any other pin is rejected so that a
//! JWE cannot route the unlock through something the design did not review.

pub mod sss;
pub mod tang;

use std::sync::{Arc, Mutex, PoisonError};

use snafu::{OptionExt, Snafu, ensure};

use crate::jose::{CompactJwe, JoseError};
use crate::secret::SecretBytes;

pub use tang::{Exchange, ExchangeError, HttpExchange};

/// Nesting limit for sss pins (design §7.4).
pub const MAX_DEPTH: usize = 4;

#[derive(Debug, Snafu)]
pub enum PinError {
    #[snafu(transparent)]
    Jose { source: JoseError },

    #[snafu(display("pin nesting exceeds {MAX_DEPTH} levels"))]
    Depth,

    #[snafu(display("JWE header lacks clevis.pin"))]
    MissingPin,

    #[snafu(display("unsupported pin `{pin}`"))]
    UnsupportedPin { pin: String },

    #[snafu(transparent)]
    Tang { source: tang::TangError },

    #[snafu(transparent)]
    Sss { source: sss::SssError },
}

/// What happened to one Tang request, for status output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Released,
    Denied,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinEvent {
    pub url: String,
    pub outcome: Outcome,
}

/// Shared state for one decryption attempt. Cheap to clone; sss children run
/// on their own threads with a clone.
#[derive(Clone)]
pub struct Context {
    exchange: Arc<dyn Exchange>,
    events: Arc<Mutex<Vec<PinEvent>>>,
}

impl Context {
    pub fn new(exchange: Arc<dyn Exchange>) -> Self {
        Self {
            exchange,
            events: Arc::default(),
        }
    }

    pub fn exchange(&self) -> &dyn Exchange {
        self.exchange.as_ref()
    }

    /// Events recorded so far, in completion order.
    pub fn events(&self) -> Vec<PinEvent> {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn record(&self, url: &str, outcome: Outcome) {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(PinEvent {
                url: url.to_owned(),
                outcome,
            });
    }
}

/// Renders an error and its sources on one line (`a: b: c`), for per-server
/// status lines and aggregated sss failure lists.
pub fn error_chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

/// Decrypts a clevis JWE (compact serialization).
pub fn decrypt(text: &str, ctx: &Context) -> Result<SecretBytes, PinError> {
    decrypt_at(text, ctx, 0)
}

fn decrypt_at(text: &str, ctx: &Context, depth: usize) -> Result<SecretBytes, PinError> {
    ensure!(depth <= MAX_DEPTH, DepthSnafu);
    let jwe = CompactJwe::parse(text)?;
    let pin = jwe
        .header()
        .clevis
        .as_ref()
        .and_then(|c| c.get("pin"))
        .and_then(serde_json::Value::as_str)
        .context(MissingPinSnafu)?;
    match pin {
        "tang" => Ok(tang::recover(&jwe, ctx)?),
        "sss" => Ok(sss::recover(&jwe, ctx, depth)?),
        other => UnsupportedPinSnafu { pin: other }.fail(),
    }
}

#[cfg(test)]
pub(crate) mod testing {
    //! In-process Tang stand-in built from the test-only vector keys.

    use std::collections::HashMap;

    use base64ct::{Base64UrlUnpadded, Encoding};
    use p521::SecretKey;
    use p521::elliptic_curve::Group;

    use super::*;
    use crate::jose::EcJwk;

    pub const TANG_A_URL: &str = "http://127.0.0.1:18731";
    pub const TANG_B_URL: &str = "http://127.0.0.1:18732";

    const EXCHANGE_KEYS: [&str; 2] = [
        include_str!("../../tests/vectors/tang-a/diV5WZ05gNpMfmSvftSPqumUIKaAXPEpISm0CUH9DkY.jwk"),
        include_str!("../../tests/vectors/tang-b/V0HHiyl0gDy2zI52nSyFMlhR9ddC4Npm46aSD0OdlFk.jwk"),
    ];

    pub struct MockTang {
        keys: HashMap<String, SecretKey>,
        denied: Vec<&'static str>,
        corrupt: bool,
    }

    impl MockTang {
        /// Serves both test tang servers; `denied` URLs answer 403.
        pub fn new(denied: &[&'static str]) -> Self {
            let mut keys = HashMap::new();
            for text in EXCHANGE_KEYS {
                let jwk: serde_json::Value =
                    serde_json::from_str(text).unwrap_or_else(|e| unreachable!("{e}"));
                let d = jwk["d"].as_str().unwrap_or_else(|| unreachable!());
                let bytes =
                    Base64UrlUnpadded::decode_vec(d).unwrap_or_else(|e| unreachable!("{e}"));
                let key = SecretKey::from_slice(&bytes).unwrap_or_else(|e| unreachable!("{e}"));
                keys.insert(crate::jose::thumbprint_s256(&key.public_key()), key);
            }
            Self {
                keys,
                denied: denied.to_vec(),
                corrupt: false,
            }
        }

        /// Answers with a valid point that is not s·X.
        pub fn corrupting() -> Self {
            Self {
                corrupt: true,
                ..Self::new(&[])
            }
        }

        pub fn context(self) -> Context {
            Context::new(Arc::new(self))
        }
    }

    impl Exchange for MockTang {
        fn recover(&self, url: &str, kid: &str, x: &EcJwk) -> Result<EcJwk, ExchangeError> {
            if self.denied.contains(&url) {
                return Err(ExchangeError::Denied);
            }
            let key = self
                .keys
                .get(kid)
                .ok_or(ExchangeError::Status { code: 404 })?;
            let x = x
                .to_public_key()
                .map_err(|_| ExchangeError::Status { code: 400 })?;
            let y = if self.corrupt {
                x.to_projective().double()
            } else {
                x.to_projective() * *key.to_nonzero_scalar()
            };
            let y =
                p521::PublicKey::from_affine(y.to_affine()).unwrap_or_else(|e| unreachable!("{e}"));
            Ok(EcJwk::from_public_key(&y))
        }
    }
}
