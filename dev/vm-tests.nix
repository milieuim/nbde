{ self, ... }:
{
  perSystem =
    { pkgs, system, ... }:
    let
      agent = self.packages.${system}.default;

      # Test-only stand-in for the agent's AF_UNIX sink. It records what
      # systemd-cryptsetup presents and replies according to a mode file, so the
      # VM test can pin down systemd's behaviour independently of the agent.
      keyFixture = pkgs.writers.writePython3 "nbde-key-fixture" { } ''
        import json
        import os
        import socket
        import struct
        import time

        RUN = "/run/nbde-fixture"
        SOCK = RUN + "/key.sock"

        try:
            os.unlink(SOCK)
        except FileNotFoundError:
            pass
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(SOCK)
        os.chmod(SOCK, 0o600)
        srv.listen(8)

        while True:
            conn, _ = srv.accept()
            peer = conn.getpeername()
            cred = conn.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
            )
            pid, uid, gid = struct.unpack("3i", cred)
            with open(RUN + "/mode") as f:
                mode = f.read().strip()
            entry = {
                "peer": peer.hex() if isinstance(peer, bytes) else peer,
                "uid": uid,
                "mode": mode,
                "t": time.time(),
            }
            with open(RUN + "/log", "a") as f:
                f.write(json.dumps(entry) + "\n")
            if mode.startswith("delay:"):
                time.sleep(int(mode.split(":")[1]))
                mode = "serve"
            if mode == "serve":
                with open("/root/p.bin", "rb") as f:
                    conn.sendall(f.read())
            elif mode == "wrong":
                conn.sendall(b"\0" * 64)
            conn.close()
      '';
    in
    {
      checks = {
        vm-agent = pkgs.testers.runNixOSTest {
          name = "nbde-agent";
          nodes.machine = {
            environment.systemPackages = [ agent ];
            environment.etc."nbde/agent.toml".text = ''
              [[volume]]
              name = "crypt-root"
              jwe = "/etc/nbde/crypt-root.jwe"
            '';
            environment.etc."nbde/crypt-root.jwe".source = ../tests/vectors/sss.jwe;
          };
          testScript = ''
            machine.wait_for_unit("multi-user.target")

            with subtest("informational modes"):
                machine.succeed("nbde-agent --version | grep -q '^nbde-agent 0.1.0'")
                machine.succeed("nbde-agent --help | grep -q 'usage: nbde-agent'")

            with subtest("argument errors exit non-zero with usage"):
                out = machine.fail("nbde-agent decrypt x 2>&1")
                assert "unexpected argument `decrypt`" in out, out
                assert "usage:" in out, out

            with subtest("root passes hardening before reaching the unimplemented modes"):
                out = machine.fail("nbde-agent 2>&1")
                assert "daemon mode is not implemented yet" in out, out
                out = machine.fail("nbde-agent check /etc/nbde/crypt-root.jwe 2>&1")
                assert "check mode is not implemented yet" in out, out

            with subtest("hardening fails closed without memlock headroom"):
                out = machine.fail(
                    "systemd-run --quiet --wait --pipe -p User=nobody "
                    "-p LimitMEMLOCK=65536 nbde-agent 2>&1"
                )
                assert "lock process memory" in out, out
                assert "not implemented" not in out, out

            with subtest("config errors are reported after hardening"):
                machine.succeed("printf 'secret = 1\\n' > /tmp/bad.toml")
                out = machine.fail("nbde-agent --config /tmp/bad.toml 2>&1")
                assert "parse config /tmp/bad.toml" in out, out
                out = machine.fail("nbde-agent --config /nonexistent.toml 2>&1")
                assert "read config /nonexistent.toml" in out, out
          '';
        };

        vm-cryptsetup-socket = pkgs.testers.runNixOSTest {
          name = "nbde-cryptsetup-socket";
          nodes.machine = {
            virtualisation.emptyDiskImages = [ 64 ];
            environment.systemPackages = [ pkgs.cryptsetup ];
            systemd.services.nbde-fixture = {
              wantedBy = [ "multi-user.target" ];
              serviceConfig = {
                ExecStart = keyFixture;
                RuntimeDirectory = "nbde-fixture";
                RuntimeDirectoryPreserve = true;
              };
            };
          };
          testScript = ''
            import json
            import re
            import time

            CS = "${pkgs.systemd}/lib/systemd/systemd-cryptsetup"
            ATTACH = f"{CS} attach nbdetest /dev/vdb /run/nbde-fixture/key.sock luks"

            def set_mode(mode):
                machine.succeed(f"echo {mode} > /run/nbde-fixture/mode")
                machine.succeed(": > /run/nbde-fixture/log")

            def connections():
                text = machine.succeed("cat /run/nbde-fixture/log")
                return [json.loads(line) for line in text.splitlines() if line]

            def detach():
                machine.succeed(f"{CS} detach nbdetest")

            def ask_files():
                return machine.succeed("ls /run/systemd/ask-password/ 2>/dev/null || true").split()

            machine.wait_for_unit("nbde-fixture.service")
            machine.wait_for_file("/run/nbde-fixture/key.sock")
            machine.succeed(
                "head -c 64 /dev/urandom > /root/p.bin",
                "cryptsetup luksFormat --batch-mode --type luks2 --pbkdf pbkdf2 "
                "--pbkdf-force-iterations 1000 /dev/vdb /root/p.bin",
            )

            with subtest("key is read from the socket; peer address names the volume"):
                set_mode("serve")
                machine.succeed(f"systemd-run --quiet --wait --pipe {ATTACH}")
                machine.succeed("test -b /dev/mapper/nbdetest")
                entries = connections()
                assert len(entries) == 1, entries
                peer = bytes.fromhex(entries[0]["peer"])
                print("peer address:", peer)
                assert re.fullmatch(rb"\x00[0-9a-f]+/cryptsetup/nbdetest", peer), peer
                assert entries[0]["uid"] == 0, entries
                detach()

            with subtest("a held connection makes systemd-cryptsetup wait for the key"):
                set_mode("delay:20")
                start = time.monotonic()
                machine.succeed(f"systemd-run --quiet --wait --pipe {ATTACH}")
                elapsed = time.monotonic() - start
                print(f"attach with 20s delay took {elapsed:.1f}s")
                assert elapsed >= 19, elapsed
                machine.succeed("test -b /dev/mapper/nbdetest")
                assert len(connections()) == 1, connections()
                detach()

            with subtest("closing without data falls back to a password prompt"):
                set_mode("close")
                machine.succeed(f"systemd-run --quiet --unit=attach-close {ATTACH}")
                machine.wait_until_succeeds("ls /run/systemd/ask-password/ | grep -q '^ask\\.'", timeout=30)
                print("connections before prompt:", len(connections()), connections())
                print("ask files:", ask_files())
                machine.succeed("test ! -b /dev/mapper/nbdetest")
                machine.succeed("systemctl stop attach-close.service")

            with subtest("a wrong key also falls back to a password prompt"):
                set_mode("wrong")
                machine.succeed(f"systemd-run --quiet --unit=attach-wrong {ATTACH}")
                machine.wait_until_succeeds("ls /run/systemd/ask-password/ | grep -q '^ask\\.'", timeout=30)
                print("connections before prompt:", len(connections()), connections())
                machine.succeed("test ! -b /dev/mapper/nbdetest")
                machine.succeed("systemctl stop attach-wrong.service")
          '';
        };
      };
    };
}
