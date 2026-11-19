# The full flow of docs/design.md §9: root on LUKS bound to two unlock-gates.
# A planned reboot unlocks through the arm the running system sent; an
# unplanned boot waits in the initrd until the approver signs on another node.
{ self, ... }:
{
  perSystem =
    { pkgs, ... }:
    let
      keys = ../tests/gate;
      agentPub = pkgs.lib.removeSuffix "\n" (builtins.readFile (keys + "/agent.pub"));
      approverPub = builtins.readFile (keys + "/approver.pub");

      gateNode = id: {
        imports = [
          self.nixosModules.default
          ./immutable-etc.nix
        ];
        services.unlock-gate = {
          enable = true;
          gateId = id;
          meshInterface = "eth1";
          requireSecurityKey = false;
          clients.machine = {
            agentPublicKey = agentPub;
            approvers = [ approverPub ];
          };
        };
      };

      meshGates = nodes: {
        sgp = "http://${nodes.sgp.networking.primaryIPAddress}:7501";
        nrt = "http://${nodes.nrt.networking.primaryIPAddress}:7501";
      };
    in
    {
      checks.vm-gate-initrd = pkgs.testers.runNixOSTest {
        name = "nbde-gate-initrd";

        nodes.sgp = gateNode "sgp";
        nodes.nrt = gateNode "nrt";

        nodes.laptop =
          { nodes, ... }:
          {
            imports = [
              self.nixosModules.default
              ./immutable-etc.nix
            ];
            environment.etc."nbde-test".source = keys;
            programs.unlock-approve = {
              enable = true;
              client = "machine";
              keyFiles = [
                "/root/approver-absent"
                "/root/approver"
              ];
              gates = meshGates nodes;
            };
          };

        nodes.machine =
          {
            config,
            lib,
            nodes,
            ...
          }:
          {
            imports = [
              self.nixosModules.default
              ./immutable-etc.nix
            ];

            virtualisation = {
              emptyDiskImages = [ 512 ];
              useBootLoader = true;
              mountHostNixStore = true;
              useEFIBoot = true;
            };
            boot.loader.systemd-boot.enable = true;
            boot.initrd.systemd = {
              enable = true;
              emergencyAccess = true;
            };
            environment.systemPackages = [
              pkgs.clevis
              pkgs.cryptsetup
            ];
            environment.etc."nbde-test".source = keys;

            # Test only: the agent key is read from the store. On a real
            # client it lives on the encrypted disk.
            services.unlock-agent = {
              enable = true;
              keyFile = "/etc/nbde-test/agent.key";
              gates = meshGates nodes;
            };

            specialisation.boot-luks.configuration = {
              # See vm-initrd.nix: qemu-vm resets luks.devices with mkVMOverride.
              boot.initrd.luks.devices = lib.mkVMOverride {
                cryptroot = {
                  device = "/dev/vdb";
                  keyFile = "/run/nbde/key.sock";
                };
              };
              virtualisation.rootDevice = "/dev/mapper/cryptroot";

              boot.initrd.nbde = {
                enable = true;
                volumes.cryptroot.jwe = "/root/cryptroot.jwe";
                attemptTimeout = 3;
                retryInterval = 2;
                deadline = 300;
              };

              boot.initrd.availableKernelModules = [ "virtio_net" ];
              boot.initrd.network.enable = true;
              boot.initrd.systemd.network.networks."10-eth1" = {
                matchConfig.Name = "eth1";
                address = [ "${config.networking.primaryIPAddress}/24" ];
              };
            };
          };

        testScript =
          { nodes, ... }:
          let
            boot-luks = nodes.machine.specialisation.boot-luks.configuration.system.build.toplevel;
            ip = n: nodes.${n}.networking.primaryIPAddress;
          in
          ''
            import json
            import shlex

            def thp(gate):
                out = gate.succeed("unlock-gate ctl status --client machine")
                line = next(l for l in out.splitlines() if "thp (pin these in clevis):" in l)
                return line.split(":", 1)[1].split()[0]

            def reboot():
                machine.succeed("sync")
                machine.crash()
                machine.start()

            def booted_from_luks():
                machine.wait_for_unit("multi-user.target")
                out = machine.succeed("mount")
                assert "/dev/mapper/cryptroot on / type ext4" in out, out

            def released(gate, reason):
                gate.wait_until_succeeds(
                    f"journalctl -u unlock-gate | grep 'released=true reason={reason}' > /dev/null"
                )

            start_all()
            for g in [sgp, nrt]:
                g.wait_for_unit("unlock-gate.service")
            laptop.succeed("install -m 0600 /etc/nbde-test/approver /root/approver")
            machine.wait_for_unit("multi-user.target")

            with subtest("bind the encrypted root to both gates"):
                pins = [{"url": "http://${ip "sgp"}:7500/c/machine", "thp": thp(sgp)},
                        {"url": "http://${ip "nrt"}:7500/c/machine", "thp": thp(nrt)}]
                config = json.dumps({"t": 2, "pins": {"tang": pins}})
                machine.succeed(
                    "head -c 64 /dev/urandom > /root/p.bin",
                    "cryptsetup luksFormat -q --iter-time=1 -d /root/p.bin /dev/vdb",
                    "cryptsetup luksOpen --key-file /root/p.bin /dev/vdb cryptroot",
                    "mkfs.ext4 -q /dev/mapper/cryptroot",
                    f"clevis encrypt sss {shlex.quote(config)} < /root/p.bin > /root/cryptroot.jwe",
                    "${boot-luks}/bin/switch-to-configuration boot",
                )

            with subtest("a planned reboot unlocks through the arm"):
                machine.succeed("unlock-gate send arm")
                reboot()
                machine.wait_for_console_text("nbde-agent: cryptroot: key delivered")
                booted_from_luks()
                released(sgp, "arm")
                released(nrt, "arm")

            with subtest("the unlocked system arms the gates for the next reboot"):
                machine.succeed("unlock-gate send arm")
                reboot()
                machine.wait_for_console_text("nbde-agent: cryptroot: key delivered")
                booted_from_luks()

            with subtest("an unplanned boot waits until the approver signs"):
                # Close the grace period the last release opened for this source.
                for g in [sgp, nrt]:
                    g.succeed("unlock-gate ctl deny --client machine")
                reboot()
                machine.wait_for_console_text("denied")
                out = laptop.succeed("unlock-gate approve --yes --window 120 < /dev/null")
                assert "refused" in out, out  # the attempts the approver reviewed
                machine.wait_for_console_text("nbde-agent: cryptroot: key delivered")
                booted_from_luks()
                released(sgp, "approval")
                released(nrt, "approval")
          '';
      };
    };
}
