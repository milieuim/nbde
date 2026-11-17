# Runs nbde-agent in the systemd initrd and points LUKS volumes at its key
# socket (docs/design.md §7.6).
{
  config,
  lib,
  pkgs,
  utils,
  ...
}:
let
  inherit (lib)
    mkEnableOption
    mkIf
    mkOption
    types
    ;
  cfg = config.boot.initrd.nbde;
  names = lib.attrNames cfg.volumes;

  jwePath = name: "/etc/nbde/${name}.jwe";
  configPath = "/etc/nbde/agent.toml";

  agentConfig = (pkgs.formats.toml { }).generate "nbde-agent.toml" {
    attempt_timeout_secs = cfg.attemptTimeout;
    retry_interval_secs = cfg.retryInterval;
    deadline_secs = cfg.deadline;
    inherit (cfg) socket console;
    volume = map (name: {
      inherit name;
      jwe = jwePath name;
    }) names;
  };

  cryptsetupUnits = map (name: "systemd-cryptsetup@${utils.escapeSystemdPath name}.service") names;
in
{
  options.boot.initrd.nbde = {
    enable = mkEnableOption "network-bound unlock of LUKS volumes with nbde-agent";

    package = mkOption {
      type = types.package;
      description = "The nbde-agent package.";
    };

    volumes = mkOption {
      type = types.attrsOf (
        types.submodule {
          options.jwe = mkOption {
            type = types.str;
            example = "/persist/keys/crypt-root.jwe";
            description = ''
              Runtime path of the clevis JWE for this volume. It is copied into
              the initrd with boot.initrd.secrets when the bootloader is
              installed, so it never enters the Nix store.
            '';
          };
        }
      );
      default = { };
      description = "LUKS volumes (names from boot.initrd.luks.devices) to unlock.";
    };

    attemptTimeout = mkOption {
      type = types.ints.positive;
      default = 30;
      description = "Seconds allowed for one unlock attempt.";
    };

    retryInterval = mkOption {
      type = types.ints.positive;
      default = 10;
      description = "Seconds between unlock attempts.";
    };

    deadline = mkOption {
      type = types.ints.positive;
      default = 900;
      description = "Seconds before giving up and falling back to the passphrase prompt.";
    };

    console = mkOption {
      type = types.bool;
      default = true;
      description = "Print unlock status on /dev/console.";
    };

    socket = mkOption {
      type = types.str;
      default = "/run/nbde/key.sock";
      description = "AF_UNIX key socket that systemd-cryptsetup reads from.";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = config.boot.initrd.systemd.enable;
        message = "boot.initrd.nbde requires boot.initrd.systemd.enable.";
      }
      {
        assertion = names != [ ];
        message = "boot.initrd.nbde.volumes is empty.";
      }
      {
        assertion = cfg.attemptTimeout <= cfg.deadline && cfg.retryInterval <= cfg.deadline;
        message = "boot.initrd.nbde: attemptTimeout and retryInterval must not exceed deadline.";
      }
    ]
    ++ map (name: {
      assertion = config.boot.initrd.luks.devices ? ${name};
      message = "boot.initrd.nbde.volumes.${name} has no boot.initrd.luks.devices entry.";
    }) names
    ++ map (name: {
      assertion = (config.boot.initrd.luks.devices.${name}.keyFile or null) == cfg.socket;
      message = ''
        boot.initrd.luks.devices.${name}.keyFile must be ${cfg.socket} for nbde to unlock it;
        another definition overrode it (e.g. a whole-set mkOverride of boot.initrd.luks.devices).
      '';
    }) names
    ++ map (name: {
      assertion = lib.hasPrefix "/" cfg.volumes.${name}.jwe;
      message = "boot.initrd.nbde.volumes.${name}.jwe must be an absolute runtime path.";
    }) names;

    boot.initrd.luks.devices = lib.genAttrs names (_: {
      keyFile = cfg.socket;
    });

    boot.initrd.secrets = lib.listToAttrs (
      map (name: lib.nameValuePair (jwePath name) cfg.volumes.${name}.jwe) names
    );

    boot.initrd.systemd = {
      contents.${configPath}.source = agentConfig;
      storePaths = [ "${cfg.package}/bin/nbde-agent" ];
      services.nbde-agent = {
        description = "Network-bound disk unlock agent";
        wantedBy = cryptsetupUnits;
        # Type=notify: started means the key socket is bound.
        before = cryptsetupUnits ++ [ "initrd-switch-root.target" ];
        conflicts = [ "initrd-switch-root.target" ];
        unitConfig.DefaultDependencies = false;
        serviceConfig = {
          Type = "notify";
          NotifyAccess = "main";
          ExecStart = "${cfg.package}/bin/nbde-agent --config ${configPath}";
        };
      };
    };
  };
}
