//! clevis `sss` pin: Shamir threshold over child pins
//! (`docs/clevis-format.md` §3).
//!
//! Children run concurrently; the first `t` valid shares are combined by
//! Lagrange interpolation at zero, and the result is the outer JWE's key.
//! Like clevis, remaining children are abandoned once the outcome is known.

use std::sync::mpsc;
use std::thread;

use base64ct::{Base64UrlUnpadded, Encoding};
use crypto_bigint::{NonZero, Odd, U256};
use secrecy::ExposeSecret;
use serde::Deserialize;
use snafu::{OptionExt, ResultExt, Snafu, ensure};
use zeroize::Zeroizing;

use super::{Context, PinError};
use crate::jose::{ALG_DIR, Cek, CompactJwe, JoseError};
use crate::secret::SecretBytes;

/// clevis generates a 256-bit prime and 32-byte coordinates.
const FIELD_LEN: usize = 32;
const SHARE_LEN: usize = 2 * FIELD_LEN;
/// Bounds the number of concurrent child requests.
pub const MAX_CHILDREN: usize = 16;

#[derive(Debug, Snafu)]
pub enum SssError {
    #[snafu(display("sss header: {reason}"))]
    Header { reason: &'static str },

    #[snafu(display("sss header is malformed"))]
    HeaderJson { source: serde_json::Error },

    #[snafu(display("sss threshold {t} is invalid for {n} children (limit {MAX_CHILDREN})"))]
    Threshold { t: u64, n: usize },

    #[snafu(display("sss modulus must be an odd 32-byte value greater than 2"))]
    Modulus,

    #[snafu(display("only {got} of {needed} shares recovered: [{}]", failures.join("; ")))]
    Insufficient {
        got: usize,
        needed: usize,
        failures: Vec<String>,
    },

    #[snafu(display("shares do not combine (duplicate x)"))]
    Combine,

    #[snafu(display("outer sss decryption failed"))]
    Decrypt { source: JoseError },
}

#[derive(Debug, Deserialize)]
struct SssHeader {
    t: u64,
    p: String,
    jwe: Vec<String>,
}

/// One point of the polynomial; both coordinates are reduced mod p.
struct Share {
    x: Zeroizing<U256>,
    y: Zeroizing<U256>,
}

pub fn recover(jwe: &CompactJwe, ctx: &Context, depth: usize) -> Result<SecretBytes, SssError> {
    let header = jwe.header();
    ensure!(
        header.alg == ALG_DIR,
        HeaderSnafu {
            reason: "alg must be dir"
        }
    );
    let sss = header
        .clevis
        .as_ref()
        .and_then(|c| c.get("sss"))
        .context(HeaderSnafu {
            reason: "missing clevis.sss",
        })?;
    let sss: SssHeader = serde_json::from_value(sss.clone()).context(HeaderJsonSnafu)?;

    let n = sss.jwe.len();
    let t = usize::try_from(sss.t)
        .ok()
        .filter(|t| (1..=n).contains(t) && n <= MAX_CHILDREN)
        .context(ThresholdSnafu { t: sss.t, n })?;
    let p = modulus(&sss.p)?;

    let shares = collect_shares(sss.jwe, t, &p, ctx, depth)?;
    let key = combine(&shares, &p)?;
    let cek = Cek::from_slice(key.as_slice()).context(DecryptSnafu)?;
    jwe.decrypt(&cek).context(DecryptSnafu)
}

fn modulus(text: &str) -> Result<NonZero<U256>, SssError> {
    let bytes = Base64UrlUnpadded::decode_vec(text).map_err(|_| SssError::Modulus)?;
    ensure!(bytes.len() == FIELD_LEN, ModulusSnafu);
    let p = U256::from_be_slice(&bytes);
    ensure!(p.is_odd().into() && p > U256::from_u8(2), ModulusSnafu);
    Option::from(NonZero::new(p)).context(ModulusSnafu)
}

/// Runs every child concurrently and returns once `t` shares are valid or
/// success has become impossible.
fn collect_shares(
    children: Vec<String>,
    t: usize,
    p: &NonZero<U256>,
    ctx: &Context,
    depth: usize,
) -> Result<Vec<Share>, SssError> {
    let n = children.len();
    let (tx, rx) = mpsc::channel::<Result<SecretBytes, PinError>>();
    let mut failures = Vec::new();
    let mut running = 0;
    for child in children {
        let tx = tx.clone();
        let ctx = ctx.clone();
        let spawned = thread::Builder::new()
            .name("nbde-pin".to_owned())
            .spawn(move || {
                // The receiver may be gone once the outcome is decided.
                let _ = tx.send(super::decrypt_at(&child, &ctx, depth + 1));
            });
        match spawned {
            Ok(_) => running += 1,
            Err(e) => failures.push(format!("spawn child: {e}")),
        }
    }
    drop(tx);

    let mut shares: Vec<Share> = Vec::with_capacity(t);
    while shares.len() < t && failures.len() <= n - t {
        let Ok(result) = rx.recv() else { break };
        running -= 1;
        let share = result
            .map_err(|e| super::error_chain(&e))
            .and_then(|secret| parse_share(&secret, p));
        match share {
            Ok(share) if shares.iter().any(|s| *s.x == *share.x) => {
                failures.push("duplicate share x".to_owned());
            }
            Ok(share) => shares.push(share),
            Err(reason) => failures.push(reason),
        }
        if running == 0 {
            break;
        }
    }

    ensure!(
        shares.len() >= t,
        InsufficientSnafu {
            got: shares.len(),
            needed: t,
            failures,
        }
    );
    shares.truncate(t);
    Ok(shares)
}

fn parse_share(secret: &SecretBytes, p: &NonZero<U256>) -> Result<Share, String> {
    let bytes = secret.expose_secret();
    if bytes.len() != SHARE_LEN {
        return Err(format!(
            "share is {} bytes, expected {SHARE_LEN}",
            bytes.len()
        ));
    }
    let x = Zeroizing::new(U256::from_be_slice(&bytes[..FIELD_LEN]));
    let y = Zeroizing::new(U256::from_be_slice(&bytes[FIELD_LEN..]));
    let p = p.as_ref();
    if *x == U256::ZERO || *x >= *p || *y >= *p {
        return Err("share coordinate out of range".to_owned());
    }
    Ok(Share { x, y })
}

/// k = Σ y_i · Π_{j≠i} (−x_j) · (x_i − x_j)^{-1}  (mod p)
fn combine(shares: &[Share], p: &NonZero<U256>) -> Result<Zeroizing<[u8; FIELD_LEN]>, SssError> {
    let odd: Odd<U256> = Option::from(Odd::new(*p.as_ref())).context(ModulusSnafu)?;
    let mut k = Zeroizing::new(U256::ZERO);
    for (i, share) in shares.iter().enumerate() {
        let mut acc = Zeroizing::new(U256::ONE);
        for (j, other) in shares.iter().enumerate() {
            if i == j {
                continue;
            }
            let numerator = other.x.neg_mod(p);
            let denominator = share.x.sub_mod(&other.x, p);
            let inverse: U256 =
                Option::from(denominator.invert_odd_mod(&odd)).context(CombineSnafu)?;
            *acc = acc.mul_mod(&numerator, p).mul_mod(&inverse, p);
        }
        *k = k.add_mod(&acc.mul_mod(&share.y, p), p);
    }
    let mut out = Zeroizing::new([0u8; FIELD_LEN]);
    out.copy_from_slice(k.to_be_bytes().as_ref());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jose::{ENC_A256GCM, MAX_JWE_LEN};
    use crate::pin::testing::{MockTang, TANG_A_URL, TANG_B_URL};
    use crate::pin::{self, Outcome};

    const SSS_JWE: &str = include_str!("../../tests/vectors/sss.jwe");
    const NESTED_JWE: &str = include_str!("../../tests/vectors/nested-sss.jwe");
    const TANG_JWE: &str = include_str!("../../tests/vectors/tang.jwe");
    const PLAINTEXT: &[u8] = include_bytes!("../../tests/vectors/plaintext");

    fn expose(r: Result<SecretBytes, PinError>) -> Vec<u8> {
        r.unwrap_or_else(|e| unreachable!("{}", snafu::Report::from_error(e)))
            .expose_secret()
            .to_vec()
    }

    #[test]
    fn recovers_reference_vectors() {
        for text in [SSS_JWE, NESTED_JWE] {
            let ctx = MockTang::new(&[]).context();
            assert_eq!(expose(pin::decrypt(text, &ctx)), PLAINTEXT);
            let mut urls: Vec<String> = ctx.events().into_iter().map(|e| e.url).collect();
            urls.sort();
            assert_eq!(urls, [TANG_A_URL, TANG_B_URL]);
        }
    }

    #[test]
    fn one_denied_server_breaks_a_two_of_two_threshold() {
        for text in [SSS_JWE, NESTED_JWE] {
            let ctx = MockTang::new(&[TANG_B_URL]).context();
            let err = pin::decrypt(text, &ctx)
                .err()
                .unwrap_or_else(|| unreachable!());
            let report = snafu::Report::from_error(err).to_string();
            assert!(report.contains("shares recovered"), "{report}");
            assert!(
                ctx.events()
                    .iter()
                    .any(|e| e.url == TANG_B_URL && e.outcome == Outcome::Denied),
                "{:?}",
                ctx.events()
            );
        }
    }

    #[test]
    fn plain_tang_dispatch_still_works() {
        let ctx = MockTang::new(&[]).context();
        assert_eq!(expose(pin::decrypt(TANG_JWE, &ctx)), PLAINTEXT);
    }

    /// Builds an outer sss JWE whose header is the given clevis.sss object;
    /// IV, ciphertext and tag are dummies (validation fails before use).
    fn outer(sss: serde_json::Value) -> String {
        let header = serde_json::json!({
            "alg": "dir",
            "enc": ENC_A256GCM,
            "clevis": { "pin": "sss", "sss": sss },
        });
        format!(
            "{}..AAAAAAAAAAAAAAAA.AAAA.AAAAAAAAAAAAAAAAAAAAAA",
            Base64UrlUnpadded::encode_string(header.to_string().as_bytes())
        )
    }

    fn odd_prime_b64() -> String {
        // 2^256 - 189 is prime.
        let p = U256::MAX.wrapping_sub(&U256::from_u8(188));
        Base64UrlUnpadded::encode_string(p.to_be_bytes().as_ref())
    }

    fn error_of(text: &str) -> String {
        let ctx = MockTang::new(&[]).context();
        let err = pin::decrypt(text, &ctx)
            .err()
            .unwrap_or_else(|| unreachable!());
        snafu::Report::from_error(err).to_string()
    }

    #[test]
    fn malformed_headers_are_rejected() {
        let p = odd_prime_b64();
        let child = TANG_JWE.trim_end();
        for (sss, expected) in [
            (
                serde_json::json!({"t": 0, "p": p, "jwe": [child]}),
                "threshold",
            ),
            (
                serde_json::json!({"t": 2, "p": p, "jwe": [child]}),
                "threshold",
            ),
            (
                serde_json::json!({"t": 1, "p": p, "jwe": vec![child; MAX_CHILDREN + 1]}),
                "threshold",
            ),
            (
                serde_json::json!({"t": 1, "p": "AAAA", "jwe": [child]}),
                "modulus",
            ),
            (
                serde_json::json!({"t": 1, "p": Base64UrlUnpadded::encode_string(&[2u8; 32]), "jwe": [child]}),
                "modulus",
            ),
            (serde_json::json!({"t": 1, "jwe": [child]}), "malformed"),
            (serde_json::json!({"t": 1, "p": p, "jwe": [1]}), "malformed"),
        ] {
            let report = error_of(&outer(sss));
            assert!(report.contains(expected), "{expected}: {report}");
        }
    }

    #[test]
    fn nesting_is_bounded() {
        let p = odd_prime_b64();
        let mut text = TANG_JWE.trim_end().to_owned();
        for _ in 0..=pin::MAX_DEPTH {
            text = outer(serde_json::json!({"t": 1, "p": p, "jwe": [text]}));
        }
        assert!(text.len() < MAX_JWE_LEN);
        let report = error_of(&text);
        assert!(report.contains("nesting"), "{report}");
    }

    #[test]
    fn unsupported_child_pins_count_as_failures() {
        let p = odd_prime_b64();
        let header =
            serde_json::json!({"alg": "dir", "enc": ENC_A256GCM, "clevis": {"pin": "tpm2"}});
        let tpm2 = format!(
            "{}..AAAAAAAAAAAAAAAA.AAAA.AAAAAAAAAAAAAAAAAAAAAA",
            Base64UrlUnpadded::encode_string(header.to_string().as_bytes())
        );
        let report = error_of(&outer(serde_json::json!({"t": 1, "p": p, "jwe": [tpm2]})));
        assert!(report.contains("unsupported pin `tpm2`"), "{report}");
    }

    fn share(x: u64, y: u64) -> Share {
        Share {
            x: Zeroizing::new(U256::from_u64(x)),
            y: Zeroizing::new(U256::from_u64(y)),
        }
    }

    #[test]
    fn combine_interpolates_the_constant_term() {
        // f(x) = 5 + 3x + 2x^2 over the 256-bit prime field.
        let p = Option::from(NonZero::new(U256::MAX.wrapping_sub(&U256::from_u8(188))))
            .unwrap_or_else(|| unreachable!());
        let f = |x: u64| 5 + 3 * x + 2 * x * x;
        let shares = [share(1, f(1)), share(4, f(4)), share(9, f(9))];
        let key = combine(&shares, &p).unwrap_or_else(|e| unreachable!("{e}"));
        let mut expected = [0u8; FIELD_LEN];
        expected[FIELD_LEN - 1] = 5;
        assert_eq!(*key, expected);
    }

    #[test]
    fn invalid_shares_are_rejected() {
        let p = Option::from(NonZero::new(U256::MAX.wrapping_sub(&U256::from_u8(188))))
            .unwrap_or_else(|| unreachable!());
        let encode = |x: &U256, y: &U256| {
            let mut bytes = x.to_be_bytes().as_ref().to_vec();
            bytes.extend_from_slice(y.to_be_bytes().as_ref());
            crate::secret::secret_bytes(&bytes)
        };
        let one = U256::ONE;
        assert!(parse_share(&encode(&U256::ZERO, &one), &p).is_err());
        assert!(parse_share(&encode(p.as_ref(), &one), &p).is_err());
        assert!(parse_share(&encode(&one, p.as_ref()), &p).is_err());
        assert!(parse_share(&crate::secret::secret_bytes(&[1u8; 63]), &p).is_err());
        assert!(parse_share(&encode(&one, &one), &p).is_ok());
        assert!(combine(&[share(7, 1), share(7, 2)], &p).is_err());
    }
}
