# End-to-end: root on LUKS, unlocked in the systemd initrd by nbde-agent
# (status lines are matched as forwarded by journald to the serial console)
# through tang servers on another node. Mirrors nixpkgs'
# systemd-initrd-luks-keyfile test for the boot mechanics.
{ self, ... }:
{
  perSystem =
    { pkgs, system, ... }:
    let
      agent = self.packages.${system}.default;
      ports = {
        a = 18731;
        b = 18732;
      };
    in
    {
      checks.vm-initrd = pkgs.testers.runNixOSTest {
        name = "nbde-initrd";

        nodes.tang = {
          environment.etc."nbde/vectors".source = ../tests/vectors;
          networking.firewall.allowedTCPPorts = builtins.attrValues ports;
          systemd.services = pkgs.lib.mapAttrs' (
            name: port:
            pkgs.lib.nameValuePair "tang-${name}" {
              wantedBy = [ "multi-user.target" ];
              serviceConfig.ExecStart = "${pkgs.tang}/libexec/tangd -l -p ${toString port} /etc/nbde/vectors/tang-${name}";
            }
          ) ports;
        };

        nodes.machine =
          { config, lib, ... }:
          {
            imports = [ self.nixosModules.default ];

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
              agent
              pkgs.clevis
              pkgs.cryptsetup
            ];

            specialisation.boot-luks.configuration = {
              # qemu-vm forces luks.devices to {} with mkVMOverride, which also
              # drops the module's keyFile; restate the whole entry at that
              # priority (the module asserts keyFile is its socket).
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
                deadline = 30;
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
            tangIp = nodes.tang.networking.primaryIPAddress;
          in
          ''
            import json
            import shlex

            A = "http://${tangIp}:${toString ports.a}"
            B = "http://${tangIp}:${toString ports.b}"
            FALLBACK = "fallback-passphrase"

            def reboot():
                machine.succeed("sync")
                machine.crash()
                machine.start()

            def booted_from_luks():
                machine.wait_for_unit("multi-user.target")
                out = machine.succeed("mount")
                assert "/dev/mapper/cryptroot on / type ext4" in out, out

            tang.start()
            tang.wait_for_open_port(${toString ports.a})
            tang.wait_for_open_port(${toString ports.b})
            machine.wait_for_unit("multi-user.target")

            with subtest("prepare an encrypted root bound to both tang servers"):
                config = json.dumps({"t": 2, "pins": {"tang": [{"url": A}, {"url": B}]}})
                machine.succeed(
                    "head -c 64 /dev/urandom > /root/p.bin",
                    "cryptsetup luksFormat -q --iter-time=1 -d /root/p.bin /dev/vdb",
                    f"echo -n {FALLBACK} | cryptsetup luksAddKey -q --iter-time=1 -d /root/p.bin /dev/vdb -",
                    "cryptsetup luksOpen --key-file /root/p.bin /dev/vdb cryptroot",
                    "mkfs.ext4 -q /dev/mapper/cryptroot",
                    f"clevis encrypt sss {shlex.quote(config)} -y < /root/p.bin > /root/cryptroot.jwe",
                )
                out = machine.succeed("nbde-agent check /root/cryptroot.jwe")
                assert "threshold met" in out, out
                # Installing the bootloader copies the JWE into the initrd as a secret.
                machine.succeed("${boot-luks}/bin/switch-to-configuration boot")

            with subtest("the initrd agent unlocks root"):
                reboot()
                machine.wait_for_console_text("nbde-agent: cryptroot: key delivered")
                booted_from_luks()

            with subtest("the initrd agent waits for a server that comes back"):
                tang.succeed("systemctl stop tang-b")
                reboot()
                machine.wait_for_console_text("nbde-agent: cryptroot: attempt 2 waiting")
                tang.succeed("systemctl start tang-b")
                machine.wait_for_console_text("nbde-agent: cryptroot: key delivered")
                booted_from_luks()

            with subtest("without tang the initrd falls back to the passphrase"):
                tang.succeed("systemctl stop tang-a tang-b")
                reboot()
                machine.wait_for_console_text("nbde-agent: deadline reached; cryptroot falls back to passphrase")
                machine.wait_for_console_text("Please enter passphrase for disk cryptroot")
                machine.send_console(f"{FALLBACK}\n")
                booted_from_luks()
          '';
      };
    };
}
