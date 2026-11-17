# nbde

Policy-gated network-bound disk encryption for systemd initrd.

- `nbde-agent` (this crate, Rust): decrypts clevis `sss`/`tang` JWEs in the
  initrd and hands the LUKS passphrase to `systemd-cryptsetup` over an
  `AF_UNIX` keyfile socket. It implements the decrypt path only; binding uses
  the official clevis.
- `unlock-gate` (planned, Go): a Tang-compatible server that releases only
  under an explicit policy (a pre-reboot arm or a human approval).

Status: the agent side works end to end in VM tests (root on LUKS unlocked in
the systemd initrd through tang servers, with passphrase fallback).
unlock-gate is not implemented yet.

## NixOS module

```nix
{
  imports = [ nbde.nixosModules.default ];
  boot.initrd.systemd.enable = true;
  boot.initrd.network.enable = true;   # plus boot.initrd.systemd.network config
  boot.initrd.luks.devices.crypt-root.device = "/dev/disk/by-uuid/...";
  boot.initrd.nbde = {
    enable = true;
    # Runtime path, copied into the initrd as a secret; never in the store.
    volumes.crypt-root.jwe = "/persist/keys/crypt-root.jwe";
  };
}
```

Bind with the official clevis (`clevis encrypt sss ...`) and add the plaintext
as a LUKS keyslot; keep a recovery passphrase in another keyslot.

## Documents

- `docs/design.md`: full design (BCP 14 keywords).
- `docs/clevis-format.md`: the clevis wire format the agent must match,
  derived from the clevis 22 / jose / tang 15 sources.

## Development

```sh
nix develop          # or direnv
just test            # cargo nextest
just lint            # clippy + rustfmt
just vm-tests        # NixOS VM tests (needs KVM)
nix flake check      # audit, clippy, fmt, nextest, VM tests
```

`tests/vectors/` holds interop vectors produced by the reference
implementation; `tests/vectors/generate.sh` regenerates them. The tang keys in
that directory are test-only.
