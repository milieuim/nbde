//! Secret byte containers. Every value derived from the unlock path (P, CEK,
//! shares, ECMR results) must be held in one of these so it is zeroed on drop
//! and cannot be printed.

pub use secrecy::{ExposeSecret, SecretBox};

/// Heap-allocated secret bytes, zeroed on drop, without `Debug` output of the
/// contents.
pub type SecretBytes = SecretBox<[u8]>;

/// Copies `bytes` into a fixed-size secret allocation; the caller remains
/// responsible for zeroing its own copy.
pub fn secret_bytes(bytes: &[u8]) -> SecretBytes {
    SecretBox::new(bytes.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_does_not_contain_the_secret() {
        let secret = secret_bytes(b"hunter2");
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("hunter2"));
        assert_eq!(secret.expose_secret(), b"hunter2");
    }
}
