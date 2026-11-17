//! Minimal JOSE for the clevis decrypt path (`docs/clevis-format.md` §1, §2.2,
//! §2.4): compact JWE with `A256GCM`, the ECDH-ES Concat KDF, P-521 JWKs and
//! RFC 7638 thumbprints. Nothing here encrypts.

use aes_gcm::aead::{AeadInOut, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use base64ct::{Base64UrlUnpadded, Encoding};
use p521::elliptic_curve::point::AffineCoordinates;
use p521::{AffinePoint, PublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snafu::{OptionExt, ResultExt, Snafu, ensure};
use zeroize::{Zeroize, Zeroizing};

use crate::secret::SecretBytes;

/// Upper bound for a whole JWE, including nested sss children.
pub const MAX_JWE_LEN: usize = 64 * 1024;

pub const ENC_A256GCM: &str = "A256GCM";
pub const ALG_DIR: &str = "dir";
pub const ALG_ECDH_ES: &str = "ECDH-ES";

const KTY_EC: &str = "EC";
const CRV_P521: &str = "P-521";

const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;
const CEK_LEN: usize = 32;
/// Length of a P-521 field element; JWK coordinates MUST use exactly this many bytes.
pub const P521_COORD_LEN: usize = 66;
/// Concat KDF output limit: one SHA-256 round.
const KDF_MAX_LEN: usize = 32;

#[derive(Debug, Snafu)]
pub enum JoseError {
    #[snafu(display("JWE is {len} bytes, above the {MAX_JWE_LEN} byte limit"))]
    TooLarge { len: usize },

    #[snafu(display("compact JWE must have 5 segments, found {count}"))]
    SegmentCount { count: usize },

    #[snafu(display("JWE encrypted key segment must be empty"))]
    EncryptedKeyPresent,

    #[snafu(display("`{field}` is not valid unpadded base64url"))]
    Base64 { field: &'static str },

    #[snafu(display("`{field}` must be {expected} bytes, found {actual}"))]
    Length {
        field: &'static str,
        expected: usize,
        actual: usize,
    },

    #[snafu(display("JWE protected header is not valid JSON"))]
    HeaderJson { source: serde_json::Error },

    #[snafu(display("unsupported content encryption `{enc}`"))]
    UnsupportedEnc { enc: String },

    #[snafu(display("unsupported key management algorithm `{alg}`"))]
    UnsupportedAlg { alg: String },

    #[snafu(display("unsupported JWE header parameter `{field}`"))]
    UnsupportedHeader { field: &'static str },

    #[snafu(display("JWE header lacks `{field}`"))]
    MissingHeader { field: &'static str },

    #[snafu(display("invalid JWK: {reason}"))]
    Jwk { reason: &'static str },

    #[snafu(display("JWE authentication failed"))]
    Decrypt,

    #[snafu(display("Concat KDF output length {len} is not supported"))]
    KdfLength { len: usize },
}

/// JWE protected header. Unknown members are ignored, except those that
/// change processing (`zip`, `crit`), which are rejected at parse time.
#[derive(Debug, Deserialize)]
pub struct Header {
    pub alg: String,
    pub enc: String,
    pub kid: Option<String>,
    pub epk: Option<EcJwk>,
    pub apu: Option<String>,
    pub apv: Option<String>,
    /// Pin specific metadata; interpreted by the pin modules.
    pub clevis: Option<serde_json::Value>,
    zip: Option<serde_json::Value>,
    crit: Option<serde_json::Value>,
}

/// A parsed compact JWE. `protected` keeps the original base64url text,
/// which is the AES-GCM additional authenticated data.
#[derive(Debug)]
pub struct CompactJwe<'a> {
    protected: &'a str,
    header: Header,
    iv: [u8; IV_LEN],
    ciphertext: Vec<u8>,
    tag: [u8; TAG_LEN],
}

impl<'a> CompactJwe<'a> {
    /// Parses and structurally validates a compact JWE. Trailing ASCII
    /// whitespace (a newline left by tools) is ignored.
    pub fn parse(input: &'a str) -> Result<Self, JoseError> {
        let input = input.trim_end_matches(|c: char| c.is_ascii_whitespace());
        ensure!(
            input.len() <= MAX_JWE_LEN,
            TooLargeSnafu { len: input.len() }
        );

        let segments: Vec<&str> = input.split('.').collect();
        let [protected, encrypted_key, iv, ciphertext, tag] = segments[..] else {
            return SegmentCountSnafu {
                count: segments.len(),
            }
            .fail();
        };
        ensure!(encrypted_key.is_empty(), EncryptedKeyPresentSnafu);

        let header_json = decode("protected", protected)?;
        let header: Header = serde_json::from_slice(&header_json).context(HeaderJsonSnafu)?;
        ensure!(
            header.enc == ENC_A256GCM,
            UnsupportedEncSnafu { enc: &header.enc }
        );
        ensure!(
            header.zip.is_none(),
            UnsupportedHeaderSnafu { field: "zip" }
        );
        ensure!(
            header.crit.is_none(),
            UnsupportedHeaderSnafu { field: "crit" }
        );

        Ok(Self {
            protected,
            header,
            iv: decode_fixed("iv", iv)?,
            ciphertext: decode("ciphertext", ciphertext)?,
            tag: decode_fixed("tag", tag)?,
        })
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Authenticates and decrypts with the content encryption key.
    pub fn decrypt(&self, cek: &Cek) -> Result<SecretBytes, JoseError> {
        let cipher = Aes256Gcm::new(&(*cek.0).into());
        let mut buffer = Zeroizing::new(self.ciphertext.clone());
        cipher
            .decrypt_inout_detached(
                &Nonce::from(self.iv),
                self.protected.as_bytes(),
                buffer.as_mut_slice().into(),
                &Tag::from(self.tag),
            )
            .map_err(|_| JoseError::Decrypt)?;
        Ok(SecretBytes::new(
            std::mem::take(&mut *buffer).into_boxed_slice(),
        ))
    }
}

/// AES-256-GCM content encryption key, zeroed on drop.
pub struct Cek(Zeroizing<[u8; CEK_LEN]>);

impl Cek {
    /// Takes a key from a big-endian byte string of exactly 32 bytes, as
    /// produced by the sss combination.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, JoseError> {
        let mut key = Zeroizing::new([0u8; CEK_LEN]);
        ensure!(
            bytes.len() == CEK_LEN,
            LengthSnafu {
                field: "cek",
                expected: CEK_LEN,
                actual: bytes.len(),
            }
        );
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }

    /// Derives the ECDH-ES content key from the exchange result `z_x` (the
    /// x coordinate of Z), per RFC 7518 §4.6 as implemented by jose.
    pub fn ecdh_es(header: &Header, z_x: &[u8]) -> Result<Self, JoseError> {
        ensure!(
            header.alg == ALG_ECDH_ES,
            UnsupportedAlgSnafu { alg: &header.alg }
        );
        let apu = Zeroizing::new(optional("apu", header.apu.as_deref())?);
        let apv = Zeroizing::new(optional("apv", header.apv.as_deref())?);
        let mut key = Zeroizing::new([0u8; CEK_LEN]);
        concat_kdf(z_x, &header.enc, &apu, &apv, key.as_mut_slice())?;
        Ok(Self(key))
    }
}

/// Single-round Concat KDF with SHA-256 (RFC 7518 §4.6.2, NIST SP 800-56A).
pub fn concat_kdf(
    z: &[u8],
    algorithm_id: &str,
    apu: &[u8],
    apv: &[u8],
    out: &mut [u8],
) -> Result<(), JoseError> {
    ensure!(
        (1..=KDF_MAX_LEN).contains(&out.len()),
        KdfLengthSnafu { len: out.len() }
    );
    let mut hash = Sha256::new();
    hash.update(1u32.to_be_bytes());
    hash.update(z);
    for field in [algorithm_id.as_bytes(), apu, apv] {
        hash.update(be32_len(field.len())?);
        hash.update(field);
    }
    hash.update(be32_len(out.len() * 8)?);
    let mut digest = hash.finalize();
    out.copy_from_slice(&digest[..out.len()]);
    digest.zeroize();
    Ok(())
}

/// An EC public JWK as it appears in headers and Tang messages. Extra members
/// (`alg`, `key_ops`, …) are ignored on input.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct EcJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

impl EcJwk {
    /// Validates the JWK as a P-521 public key: fixed-length coordinates, on
    /// the curve, not the identity.
    pub fn to_public_key(&self) -> Result<PublicKey, JoseError> {
        ensure!(
            self.kty == KTY_EC,
            JwkSnafu {
                reason: "kty is not EC"
            }
        );
        ensure!(
            self.crv == CRV_P521,
            JwkSnafu {
                reason: "crv is not P-521"
            }
        );
        let x: [u8; P521_COORD_LEN] = decode_fixed("x", &self.x)?;
        let y: [u8; P521_COORD_LEN] = decode_fixed("y", &self.y)?;

        let mut sec1 = [0u8; 1 + 2 * P521_COORD_LEN];
        sec1[0] = 0x04;
        sec1[1..=P521_COORD_LEN].copy_from_slice(&x);
        sec1[1 + P521_COORD_LEN..].copy_from_slice(&y);
        PublicKey::from_sec1_bytes(&sec1).map_err(|_| JoseError::Jwk {
            reason: "point is not on P-521 or is the identity",
        })
    }

    /// Encodes a P-521 public key with fixed-length coordinates.
    pub fn from_public_key(key: &PublicKey) -> Self {
        let point = key.as_affine();
        Self {
            kty: KTY_EC.to_owned(),
            crv: CRV_P521.to_owned(),
            x: Base64UrlUnpadded::encode_string(&point.x()),
            y: Base64UrlUnpadded::encode_string(&affine_y(point)),
        }
    }
}

/// RFC 7638 JWK thumbprint (SHA-256, base64url) of a validated P-521 key.
/// The canonical members are re-encoded from the key, so the result does not
/// depend on how the input JWK was spelled.
pub fn thumbprint_s256(key: &PublicKey) -> String {
    let jwk = EcJwk::from_public_key(key);
    let canonical = format!(
        r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
        jwk.crv, jwk.kty, jwk.x, jwk.y
    );
    Base64UrlUnpadded::encode_string(&Sha256::digest(canonical.as_bytes()))
}

/// The x coordinate of an exchange result, zeroed on drop.
pub fn exchange_x(point: &AffinePoint) -> Zeroizing<[u8; P521_COORD_LEN]> {
    let mut x = Zeroizing::new([0u8; P521_COORD_LEN]);
    let mut bytes = point.x();
    x.copy_from_slice(&bytes);
    bytes.zeroize();
    x
}

fn affine_y(point: &AffinePoint) -> [u8; P521_COORD_LEN] {
    use p521::elliptic_curve::sec1::ToSec1Point;

    let encoded = point.to_sec1_point(false);
    let mut y = [0u8; P521_COORD_LEN];
    if let Some(bytes) = encoded.y() {
        y.copy_from_slice(bytes);
    }
    y
}

fn decode(field: &'static str, text: &str) -> Result<Vec<u8>, JoseError> {
    Base64UrlUnpadded::decode_vec(text)
        .ok()
        .context(Base64Snafu { field })
}

fn decode_fixed<const N: usize>(field: &'static str, text: &str) -> Result<[u8; N], JoseError> {
    let bytes = Zeroizing::new(decode(field, text)?);
    bytes.as_slice().try_into().map_err(|_| JoseError::Length {
        field,
        expected: N,
        actual: bytes.len(),
    })
}

fn optional(field: &'static str, text: Option<&str>) -> Result<Vec<u8>, JoseError> {
    text.map_or_else(|| Ok(Vec::new()), |t| decode(field, t))
}

fn be32_len(len: usize) -> Result<[u8; 4], JoseError> {
    u32::try_from(len)
        .map(u32::to_be_bytes)
        .map_err(|_| JoseError::KdfLength { len })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p521::elliptic_curve::sec1::ToSec1Point;
    use p521::{ProjectivePoint, SecretKey};

    const TANG_JWE: &str = include_str!("../tests/vectors/tang.jwe");
    const SSS_JWE: &str = include_str!("../tests/vectors/sss.jwe");
    const PLAINTEXT: &[u8] = include_bytes!("../tests/vectors/plaintext");

    /// tang-a's exchange key; tang names key files by their S256 thumbprint.
    const TANG_A_EXCHANGE: (&str, &str) = (
        "diV5WZ05gNpMfmSvftSPqumUIKaAXPEpISm0CUH9DkY",
        include_str!("../tests/vectors/tang-a/diV5WZ05gNpMfmSvftSPqumUIKaAXPEpISm0CUH9DkY.jwk"),
    );
    const TANG_KEY_FILES: [(&str, &str); 4] = [
        TANG_A_EXCHANGE,
        (
            "9gG4g0xtF5Dx3o2EvnkIzwu9f_JLnyNMTRkGqDFyzw8",
            include_str!("../tests/vectors/tang-a/9gG4g0xtF5Dx3o2EvnkIzwu9f_JLnyNMTRkGqDFyzw8.jwk"),
        ),
        (
            "GzzJjrgSX9bacqGpilyf07yelxWmWjevc-b7nakgC2M",
            include_str!("../tests/vectors/tang-b/GzzJjrgSX9bacqGpilyf07yelxWmWjevc-b7nakgC2M.jwk"),
        ),
        (
            "V0HHiyl0gDy2zI52nSyFMlhR9ddC4Npm46aSD0OdlFk",
            include_str!("../tests/vectors/tang-b/V0HHiyl0gDy2zI52nSyFMlhR9ddC4Npm46aSD0OdlFk.jwk"),
        ),
    ];

    fn ok<T, E: std::fmt::Display>(r: Result<T, E>) -> T {
        r.unwrap_or_else(|e| unreachable!("{e}"))
    }

    fn some<T>(o: Option<T>) -> T {
        o.unwrap_or_else(|| unreachable!("unexpected None"))
    }

    fn tang_secret(jwk_text: &str) -> SecretKey {
        let jwk: serde_json::Value = ok(serde_json::from_str(jwk_text));
        let d = some(jwk["d"].as_str());
        ok(SecretKey::from_slice(&ok(Base64UrlUnpadded::decode_vec(d))))
    }

    #[test]
    fn parses_reference_tang_jwe() {
        let jwe = ok(CompactJwe::parse(TANG_JWE));
        let header = jwe.header();
        assert_eq!(header.alg, ALG_ECDH_ES);
        assert_eq!(header.kid.as_deref(), Some(TANG_A_EXCHANGE.0));
        assert!(some(header.epk.as_ref()).to_public_key().is_ok());
        assert_eq!(
            header.clevis.as_ref().and_then(|c| c["pin"].as_str()),
            Some("tang")
        );
    }

    #[test]
    fn parses_reference_sss_jwe() {
        let jwe = ok(CompactJwe::parse(SSS_JWE));
        assert_eq!(jwe.header().alg, ALG_DIR);
        assert!(jwe.header().epk.is_none());
    }

    #[test]
    fn trailing_newline_is_accepted() {
        assert!(CompactJwe::parse(&format!("{TANG_JWE}\n")).is_ok());
    }

    #[test]
    fn thumbprints_match_tang_key_file_names() {
        for (name, text) in TANG_KEY_FILES {
            let jwk: EcJwk = ok(serde_json::from_str(text));
            assert_eq!(thumbprint_s256(&ok(jwk.to_public_key())), name);
        }
    }

    #[test]
    fn decrypts_reference_tang_jwe_with_the_server_key() {
        // Without blinding: Z = s·C. pin::tang reaches the same Z via ECMR.
        let jwe = ok(CompactJwe::parse(TANG_JWE));
        let epk = ok(some(jwe.header().epk.as_ref()).to_public_key());
        let s = tang_secret(TANG_A_EXCHANGE.1);
        let z = (epk.to_projective() * *s.to_nonzero_scalar()).to_affine();

        let cek = ok(Cek::ecdh_es(jwe.header(), exchange_x(&z).as_slice()));
        let plaintext = ok(jwe.decrypt(&cek));
        use secrecy::ExposeSecret;
        assert_eq!(plaintext.expose_secret(), PLAINTEXT);
    }

    #[test]
    fn wrong_key_or_tampering_fails_authentication() {
        let jwe = ok(CompactJwe::parse(TANG_JWE));
        let wrong = ok(Cek::from_slice(&[7u8; CEK_LEN]));
        assert!(matches!(jwe.decrypt(&wrong), Err(JoseError::Decrypt)));

        let epk = ok(some(jwe.header().epk.as_ref()).to_public_key());
        let s = tang_secret(TANG_A_EXCHANGE.1);
        let z = (epk.to_projective() * *s.to_nonzero_scalar()).to_affine();
        let cek = ok(Cek::ecdh_es(jwe.header(), exchange_x(&z).as_slice()));

        let segments: Vec<&str> = TANG_JWE.trim_end().split('.').collect();
        for index in [0, 3, 4] {
            let mut tampered: Vec<String> = segments.iter().map(|s| (*s).to_owned()).collect();
            // Swap the last character for another valid base64url character.
            let last = some(tampered[index].pop());
            tampered[index].push(if last == 'A' { 'Q' } else { 'A' });
            let text = tampered.join(".");
            if let Ok(jwe) = CompactJwe::parse(&text) {
                assert!(
                    jwe.decrypt(&cek).is_err(),
                    "segment {index} tamper accepted"
                );
            }
        }
    }

    #[test]
    fn structural_errors_are_reported() {
        assert!(matches!(
            CompactJwe::parse("a.b.c"),
            Err(JoseError::SegmentCount { count: 3 })
        ));
        let segments: Vec<&str> = TANG_JWE.trim_end().split('.').collect();
        let with_key = [segments[0], "AAAA", segments[2], segments[3], segments[4]].join(".");
        assert!(matches!(
            CompactJwe::parse(&with_key),
            Err(JoseError::EncryptedKeyPresent)
        ));
        let short_iv = [segments[0], "", "AAAA", segments[3], segments[4]].join(".");
        assert!(matches!(
            CompactJwe::parse(&short_iv),
            Err(JoseError::Length { field: "iv", .. })
        ));
        let big = "A".repeat(MAX_JWE_LEN + 1);
        assert!(matches!(
            CompactJwe::parse(&big),
            Err(JoseError::TooLarge { .. })
        ));
    }

    #[test]
    fn unsupported_headers_are_rejected() {
        let rest = TANG_JWE.trim_end().split_once('.').map(|(_, r)| r);
        let rest = some(rest);
        for (header, matcher) in [
            (r#"{"alg":"dir","enc":"A128GCM"}"#, "enc"),
            (r#"{"alg":"dir","enc":"A256GCM","zip":"DEF"}"#, "zip"),
            (r#"{"alg":"dir","enc":"A256GCM","crit":["x"]}"#, "crit"),
        ] {
            let text = format!(
                "{}.{rest}",
                Base64UrlUnpadded::encode_string(header.as_bytes())
            );
            let err = some(CompactJwe::parse(&text).err());
            assert!(err.to_string().contains(matcher), "{err}");
        }
    }

    #[test]
    fn concat_kdf_matches_rfc7518_appendix_c() {
        let z = [
            158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49,
            110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196,
        ];
        let mut out = [0u8; 16];
        ok(concat_kdf(&z, "A128GCM", b"Alice", b"Bob", &mut out));
        assert_eq!(
            Base64UrlUnpadded::encode_string(&out),
            "VqqN6vgjbSBcIijNcacQGg"
        );
    }

    #[test]
    fn concat_kdf_rejects_unsupported_lengths() {
        assert!(concat_kdf(b"z", "A256GCM", b"", b"", &mut []).is_err());
        assert!(concat_kdf(b"z", "A256GCM", b"", b"", &mut [0u8; 33]).is_err());
    }

    #[test]
    fn invalid_jwks_are_rejected() {
        let base: EcJwk = ok(serde_json::from_str(TANG_A_EXCHANGE.1));
        let point = ok(base.to_public_key());
        assert_eq!(EcJwk::from_public_key(&point), base);

        let mut off_curve = base.clone();
        let mut y = ok(Base64UrlUnpadded::decode_vec(&base.y));
        y[65] ^= 1;
        off_curve.y = Base64UrlUnpadded::encode_string(&y);
        assert!(off_curve.to_public_key().is_err());

        let mut short = base.clone();
        short.x = Base64UrlUnpadded::encode_string(&[1u8; 65]);
        assert!(matches!(
            short.to_public_key(),
            Err(JoseError::Length { field: "x", .. })
        ));

        let mut wrong_curve = base.clone();
        wrong_curve.crv = "P-256".to_owned();
        assert!(wrong_curve.to_public_key().is_err());

        let identity = ProjectivePoint::IDENTITY.to_affine().to_sec1_point(false);
        assert!(PublicKey::from_sec1_bytes(identity.as_bytes()).is_err());
    }
}
