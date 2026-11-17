//! nbde-agent: policy-gated network-bound disk unlock for systemd initrd.
//!
//! The decrypt path for clevis `sss`/`tang` JWEs is implemented after the
//! clevis wire format is pinned down in `docs/clevis-format.md`.

pub mod args;
pub mod config;
pub mod harden;
pub mod secret;
