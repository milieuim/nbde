# The running client's side of unlock-gate (docs/design.md §7.1): a heartbeat
# timer and a reboot command that arms the gates first.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib)
    mkEnableOption
    mkIf
    mkOption
    types
    ;
  cfg = config.services.unlock-agent;
  configPath = "/etc/unlock-gate/agent.json";

  agentConfig = (pkgs.formats.json { }).generate "unlock-agent.json" {
    inherit (cfg) client gates;
    key_file = cfg.keyFile;
    arm_ttl = cfg.armTTL;
  };

  rebootCommand = pkgs.writeShellApplication {
    name = cfg.rebootCommand;
    runtimeInputs = [ cfg.package ];
    text = ''
      if [ "$(id -u)" -ne 0 ]; then
        echo "${cfg.rebootCommand}: must run as root" >&2
        exit 1
      fi
      # unlock-gate exits non-zero unless at least two gates hold the arm;
      # rebooting then would leave the disk locked until someone approves.
      unlock-gate send --config ${configPath} arm
      exec systemctl reboot "$@"
    '';
  };
in
{
  options.services.unlock-agent = {
    enable = mkEnableOption "heartbeats and planned-reboot arms to unlock-gate";

    package = mkOption {
      type = types.package;
      description = "The unlock-gate package.";
    };

    client = mkOption {
      type = types.str;
      default = config.networking.hostName;
      defaultText = lib.literalExpression "config.networking.hostName";
      description = "Client name, as configured on the gates.";
    };

    keyFile = mkOption {
      type = types.str;
      example = "/persist/keys/unlock-agent.ed25519";
      description = ''
        Runtime path of the agent's Ed25519 seed (create it with
        `unlock-gate agent-key <path>`). It MUST live on encrypted storage.
      '';
    };

    gates = mkOption {
      type = types.attrsOf types.str;
      example = {
        sgp = "http://[fdcc::4]:7501";
      };
      description = "Gate id to mesh base URL.";
    };

    armTTL = mkOption {
      type = types.ints.between 1 600;
      default = 600;
      description = "Seconds an arm stays valid on the gates.";
    };

    heartbeatInterval = mkOption {
      type = types.str;
      default = "60s";
    };

    rebootCommand = mkOption {
      type = types.str;
      default = "${config.networking.hostName}-reboot";
      defaultText = lib.literalExpression ''"''${config.networking.hostName}-reboot"'';
      description = "Name of the command that arms the gates and then reboots.";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = builtins.length (builtins.attrNames cfg.gates) >= 2;
        message = "services.unlock-agent.gates needs at least two gates to reach the threshold.";
      }
    ];

    environment.etc."unlock-gate/agent.json".source = agentConfig;
    environment.systemPackages = [
      cfg.package
      rebootCommand
    ];

    systemd.services.unlock-agent-heartbeat = {
      description = "Send a heartbeat to unlock-gate";
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${lib.getExe cfg.package} send --config ${configPath} heartbeat";
      };
    };

    systemd.timers.unlock-agent-heartbeat = {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "15s";
        OnUnitActiveSec = cfg.heartbeatInterval;
        AccuracySec = "5s";
      };
    };
  };
}
