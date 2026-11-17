//! nbde-agent: policy-gated network-bound disk unlock for systemd initrd.
//!
//! The decrypt path follows `docs/clevis-format.md`; see `docs/design.md`
//! for the overall design.

pub mod args;
pub mod config;
pub mod harden;
pub mod http;
pub mod jose;
pub mod pin;
pub mod secret;
