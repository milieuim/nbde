# unlock-gate on a gate node: Tang-compatible public interface plus the mesh
# interface for heartbeat, arm and approvals (docs/design.md §6).
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
  cfg = config.services.unlock-gate;

  listen =
    addr: port:
    if lib.hasInfix ":" addr then "[${addr}]:${toString port}" else "${addr}:${toString port}";
  credentialsDir = "/run/credentials/unlock-gate.service";
  ctlSocket = "/run/unlock-gate/ctl.sock";

  gateConfig = (pkgs.formats.json { }).generate "unlock-gate.json" (
    {
      gate_id = cfg.gateId;
      public_listen = map (a: listen a cfg.publicPort) cfg.publicAddresses;
      mesh_listen = map (a: listen a cfg.meshPort) cfg.meshAddresses;
      ctl_socket = ctlSocket;
      require_security_key = cfg.requireSecurityKey;
      clients = lib.mapAttrs (name: c: {
        keys_dir = "/var/lib/unlock-gate/${name}";
        agent_public_key = c.agentPublicKey;
        inherit (c) approvers;
        allow_from = c.allowFrom;
      }) cfg.clients;
    }
    // lib.optionalAttrs (cfg.telegram != null) {
      telegram = {
        token_file = "${credentialsDir}/telegram-token";
        chat_id = cfg.telegram.chatId;
      };
    }
  );
in
{
  options.services.unlock-gate = {
    enable = mkEnableOption "unlock-gate, a policy-gated Tang server";

    package = mkOption {
      type = types.package;
      description = "The unlock-gate package.";
    };

    gateId = mkOption {
      type = types.strMatching "[a-z0-9][a-z0-9-]{0,62}";
      example = "sgp";
      description = "This gate's id; signed messages name it as their audience.";
    };

    publicAddresses = mkOption {
      type = types.listOf types.str;
      default = [ "::" ];
      description = "Addresses for the public Tang interface. `::` also accepts IPv4.";
    };

    publicPort = mkOption {
      type = types.port;
      default = 7500;
    };

    meshAddresses = mkOption {
      type = types.listOf types.str;
      default = [ "::" ];
      description = "Addresses for the mesh interface (heartbeat, arm, approve, status).";
    };

    meshPort = mkOption {
      type = types.port;
      default = 7501;
    };

    openFirewall = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Open the public port everywhere and the mesh port only on
        meshInterface.
      '';
    };

    meshInterface = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "vxlan0";
      description = "Interface the mesh port is opened on.";
    };

    requireSecurityKey = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Accept only sk-* approver keys and require the user-presence flag on
        every approval signature.
      '';
    };

    clients = mkOption {
      type = types.attrsOf (
        types.submodule {
          options = {
            agentPublicKey = mkOption {
              type = types.str;
              description = "Ed25519 public key (base64url) that signs the client's heartbeat and arm.";
            };
            approvers = mkOption {
              type = types.listOf types.str;
              description = "OpenSSH public key lines allowed to sign approvals for this client.";
            };
            allowFrom = mkOption {
              type = types.listOf types.str;
              default = [ ];
              description = "If non-empty, /rec is only ever released to these source prefixes.";
            };
          };
        }
      );
      default = { };
      description = "Protected clients. Each gets its own Tang keys under /var/lib/unlock-gate/<name>.";
    };

    telegram = mkOption {
      type = types.nullOr (
        types.submodule {
          options = {
            tokenFile = mkOption {
              type = types.str;
              description = "Runtime path of the bot token; read as a systemd credential.";
            };
            chatId = mkOption { type = types.str; };
          };
        }
      );
      default = null;
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.clients != { };
        message = "services.unlock-gate.clients is empty.";
      }
      {
        assertion = !cfg.openFirewall || cfg.meshInterface != null;
        message = "services.unlock-gate.openFirewall needs meshInterface, so the mesh port stays off the public internet.";
      }
    ];

    environment.systemPackages = [ cfg.package ];

    networking.firewall = mkIf cfg.openFirewall {
      allowedTCPPorts = [ cfg.publicPort ];
      interfaces.${cfg.meshInterface}.allowedTCPPorts = [ cfg.meshPort ];
    };

    systemd.services.unlock-gate = {
      description = "unlock-gate policy-gated Tang server";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      serviceConfig = {
        Type = "notify";
        NotifyAccess = "main";
        ExecStart = "${lib.getExe cfg.package} serve --config ${gateConfig}";
        Restart = "always";
        RestartSec = 5;
        DynamicUser = true;
        StateDirectory = "unlock-gate";
        StateDirectoryMode = "0700";
        RuntimeDirectory = "unlock-gate";
        RuntimeDirectoryMode = "0700";
        LoadCredential = lib.optional (cfg.telegram != null) "telegram-token:${cfg.telegram.tokenFile}";
        AmbientCapabilities = lib.optional (
          cfg.publicPort < 1024 || cfg.meshPort < 1024
        ) "CAP_NET_BIND_SERVICE";
        CapabilityBoundingSet = lib.optional (
          cfg.publicPort < 1024 || cfg.meshPort < 1024
        ) "CAP_NET_BIND_SERVICE";
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        ProtectProc = "invisible";
        ProcSubset = "pid";
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
          "AF_UNIX"
        ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [
          "@system-service"
          "~@privileged @resources"
        ];
        UMask = "0077";
      };
    };
  };
}
