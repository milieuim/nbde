# unlock-gate policy end to end: two gates, a client binding with official
# clevis and unlocking with nbde-agent, the running client's heartbeat and
# arm, and approver-signed tokens.
{ self, ... }:
{
  perSystem =
    { pkgs, system, ... }:
    let
      agent = self.packages.${system}.default;
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
          clients.eihort = {
            agentPublicKey = agentPub;
            approvers = [ approverPub ];
          };
        };
      };
    in
    {
      checks.vm-gate = pkgs.testers.runNixOSTest {
        name = "nbde-gate";

        nodes.sgp = gateNode "sgp";
        nodes.nrt = gateNode "nrt";

        nodes.client =
          { nodes, ... }:
          let
            mesh = n: "http://${nodes.${n}.networking.primaryIPAddress}:7501";
          in
          {
            imports = [
              self.nixosModules.default
              ./immutable-etc.nix
            ];
            networking.hostName = "eihort";
            environment.systemPackages = [
              agent
              pkgs.clevis
              pkgs.curl
            ];
            environment.etc."nbde-test".source = keys;
            services.unlock-agent = {
              enable = true;
              keyFile = "/root/agent.key";
              gates = {
                sgp = mesh "sgp";
                nrt = mesh "nrt";
              };
            };
            programs.unlock-approve = {
              enable = true;
              client = "eihort";
              keyFile = "/root/approver";
              gates = {
                sgp = mesh "sgp";
                nrt = mesh "nrt";
              };
            };
          };

        testScript =
          { nodes, ... }:
          let
            ip = n: nodes.${n}.networking.primaryIPAddress;
          in
          ''
            import json
            import shlex

            gates = [sgp, nrt]
            JWE = "/root/disk.jwe"

            def thp(gate):
                out = gate.succeed("unlock-gate ctl status --client eihort")
                line = next(l for l in out.splitlines() if "thp (pin these in clevis):" in l)
                return line.split(":", 1)[1].split()[0]

            def unlocks():
                out = client.succeed(f"nbde-agent check {JWE}")
                assert "threshold met" in out, out

            def refused():
                out = client.fail(f"nbde-agent check {JWE} 2>&1")
                assert "denied" in out, out

            def clear():
                for g in gates:
                    g.succeed("unlock-gate ctl deny --client eihort", "unlock-gate ctl disarm --client eihort")

            start_all()
            for m in [sgp, nrt, client]:
                m.wait_for_unit("multi-user.target")
                fs, opts = m.succeed("findmnt -no FSTYPE,OPTIONS /etc").split()
                assert fs == "overlay" and "ro" in opts.split(","), (fs, opts)
            for g in gates:
                g.wait_for_unit("unlock-gate.service")
                g.wait_for_open_port(7500)
                g.wait_for_open_port(7501)
            client.wait_for_unit("multi-user.target")
            client.succeed(
                "install -m 0400 /etc/nbde-test/agent.key /root/agent.key",
                "install -m 0600 /etc/nbde-test/approver /root/approver",
            )

            with subtest("bind with official clevis, pinning thp read over ctl"):
                pins = [{"url": "http://${ip "sgp"}:7500/c/eihort", "thp": thp(sgp)},
                        {"url": "http://${ip "nrt"}:7500/c/eihort", "thp": thp(nrt)}]
                config = json.dumps({"t": 2, "pins": {"tang": pins}})
                client.succeed(
                    "head -c 64 /dev/urandom > /root/p.bin",
                    f"clevis encrypt sss {shlex.quote(config)} < /root/p.bin > {JWE}",
                )

            with subtest("an unplanned unlock is refused and noted"):
                refused()
                sgp.wait_until_succeeds("journalctl -u unlock-gate | grep 'event=unlock_denied' > /dev/null")

            with subtest("the mesh interface is not on the public port"):
                client.fail("curl -sf 'http://${ip "sgp"}:7500/v1/status?client=eihort'")
                client.succeed("curl -sf 'http://${ip "sgp"}:7501/v1/status?client=eihort'")

            with subtest("heartbeats reach every gate"):
                client.succeed("systemctl start unlock-agent-heartbeat.service")
                for g in gates:
                    out = g.succeed("unlock-gate ctl status --client eihort")
                    assert "heartbeat: ok" in out, out

            with subtest("an arm releases once"):
                client.succeed("unlock-gate send arm")
                unlocks()
                clear()  # drops the grace period, not a consumed arm
                refused()

            with subtest("an arm that fewer than two gates hold is reported as failed"):
                nrt.succeed("systemctl stop unlock-gate")
                out = client.fail("unlock-gate send arm 2>&1")
                assert "need 2" in out, out
                client.fail("eihort-reboot")  # never reboots without the threshold
                nrt.succeed("systemctl start unlock-gate")
                nrt.wait_for_open_port(7501)
                clear()

            with subtest("a gate restart forgets its arm"):
                client.succeed("unlock-gate send arm")
                sgp.succeed("systemctl restart unlock-gate")
                sgp.wait_for_open_port(7500)
                refused()
                clear()

            with subtest("an approval token unlocks, also for official clevis"):
                client.succeed("unlock-gate approve --yes --window 120 < /dev/null")
                client.succeed(f"clevis decrypt < {JWE} | cmp - /root/p.bin")
                clear()

            with subtest("an approval limited to other sources does not release"):
                client.succeed("unlock-gate approve --yes --from 192.0.2.0/24 < /dev/null")
                refused()
                client.succeed("unlock-gate deny --yes < /dev/null")

            with subtest("approvals show in mesh status; malformed ones are refused"):
                client.succeed("unlock-gate approve --yes --window 60 < /dev/null")
                status = json.loads(client.succeed("curl -sf 'http://${ip "nrt"}:7501/v1/status?client=eihort'"))
                assert status["approval"] is not None, status
                clear()
                code = client.succeed(
                    "curl -s -o /dev/null -w '%{http_code}' -X POST -d '{}' 'http://${ip "nrt"}:7501/v1/approve'"
                )
                assert code == "401", code

            with subtest("ctl is root only"):
                sgp.fail("su nobody -s /bin/sh -c 'unlock-gate ctl status --client eihort'")

            with subtest("Tang keys persist across restarts"):
                before = thp(sgp)
                sgp.succeed("systemctl restart unlock-gate")
                sgp.wait_for_unit("unlock-gate.service")
                assert thp(sgp) == before
          '';
      };
    };
}
