# The approver's machine: installs unlock-gate and a system-wide approver
# config, so `unlock-gate approve` and `unlock-gate deny` work without flags.
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
  cfg = config.programs.unlock-approve;
in
{
  options.programs.unlock-approve = {
    enable = mkEnableOption "the unlock-gate approver tool";

    package = mkOption {
      type = types.package;
      description = "The unlock-gate package.";
    };

    client = mkOption {
      type = types.str;
      example = "eihort";
    };

    keyFile = mkOption {
      type = types.str;
      example = "/home/riro/.ssh/id_ed25519_sk";
      description = "SSH key passed to `ssh-keygen -Y sign -f`; normally a security-key handle.";
    };

    gates = mkOption {
      type = types.attrsOf types.str;
      description = "Gate id to mesh base URL.";
    };
  };

  config = mkIf cfg.enable {
    environment.systemPackages = [
      cfg.package
      pkgs.openssh
    ];
    environment.etc."unlock-gate/approver.json".source =
      (pkgs.formats.json { }).generate "approver.json"
        {
          inherit (cfg) client gates;
          key_file = cfg.keyFile;
        };
  };
}
