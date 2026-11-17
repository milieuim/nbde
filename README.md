# nbde

Policy-gated network-bound disk encryption for systemd initrd.

- `nbde-agent` (this crate, Rust): decrypts clevis `sss`/`tang` JWEs in the
  initrd and hands the LUKS passphrase to `systemd-cryptsetup` over an
  `AF_UNIX` keyfile socket. It implements the decrypt path only; binding uses
  the official clevis.
- `unlock-gate` (planned, Go): a Tang-compatible server that releases only
  under an explicit policy (a pre-reboot arm or a human approval).

Status: early development. Only argument parsing, configuration and process
hardening are implemented; the decrypt path follows `docs/clevis-format.md`.

## Documents

- `docs/design.md`: full design (BCP 14 keywords).
- `docs/clevis-format.md`: the clevis wire format the agent must match,
  derived from the clevis 22 / jose / tang 15 sources.

## Development

```sh
nix develop          # or direnv
just test            # cargo nextest
just lint            # clippy + rustfmt
nix flake check      # audit, clippy, fmt, nextest
```

`tests/vectors/` holds interop vectors produced by the reference
implementation; `tests/vectors/generate.sh` regenerates them. The tang keys in
that directory are test-only.
