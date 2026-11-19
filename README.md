# nbde

Policy-gated network-bound disk encryption for systemd initrd.

- `nbde-agent` (this crate, Rust): decrypts clevis `sss`/`tang` JWEs in the
  initrd and hands the LUKS passphrase to `systemd-cryptsetup` over an
  `AF_UNIX` keyfile socket. It implements the decrypt path only; binding uses
  the official clevis.
- `unlock-gate` (`gate/`, Go): a Tang-compatible server that releases only
  under an explicit policy: a one-shot arm sent by the running client before
  a planned reboot, or a one-shot approval signed with the approver's
  security key (`ssh-keygen -Y sign`). The same binary is the client-side
  sender (`send heartbeat|arm`) and the approver's tool (`approve`, `deny`).

Status: works end to end in VM tests. Root on LUKS is bound to two gates; a
planned reboot unlocks through the arm, and an unplanned boot waits in the
initrd until the approver signs, with a passphrase fallback at the deadline.

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

On each gate, the running client, and the approver's machine:

```nix
# gate
services.unlock-gate = {
  enable = true;
  gateId = "sgp";
  meshInterface = "vxlan0";
  clients.eihort = {
    agentPublicKey = "...";            # unlock-gate agent-key --public <key>
    # any one of these may sign approvals
    approvers = [ "sk-ssh-ed25519@openssh.com AAAA..." "sk-ssh-ed25519@openssh.com AAAA..." ];
  };
};

# client: heartbeat timer and `eihort-reboot` (arms, then reboots)
services.unlock-agent = {
  enable = true;
  keyFile = "/persist/keys/unlock-agent.ed25519";
  gates = { sgp = "http://[fdcc::4]:7501"; nrt = "http://[fdcc::5]:7501"; };
};

# approver: `unlock-gate approve` shows every gate's status, then signs once
programs.unlock-approve = {
  enable = true;
  client = "eihort";
  # tried in order; whichever security key is plugged in signs
  keyFiles = [ "/home/me/.ssh/id_ed25519_sk" "/home/me/.ssh/id_ed25519_sk2" ];
  gates = { sgp = "http://[fdcc::4]:7501"; nrt = "http://[fdcc::5]:7501"; };
};
```

Read each gate's `thp` for clevis with `unlock-gate ctl status --client eihort`
on the gate (root, over SSH).

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
that directory are test-only, as are the keys in `tests/gate/`.
