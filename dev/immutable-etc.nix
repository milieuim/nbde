# The hosts nbde is deployed on run with a read-only /etc overlay, userborn
# and no perl in the closure (the deployment repo's "perlless" and "cut"
# modules); the gate VM tests run every node that way.
{
  boot.initrd.systemd.enable = true;
  system.etc.overlay = {
    enable = true;
    mutable = false;
  };
  services.userborn.enable = true;
  # A read-only /etc cannot get a machine-id at first boot; the hosts pin
  # one, and the systemd-boot installer needs it.
  environment.etc.machine-id = {
    text = "b08dfa6083e7567a1921a715000001fb\n";
    mode = "0444";
  };

  system.tools.nixos-generate-config.enable = false;
  programs.less.lessopen = null;
  programs.command-not-found.enable = false;
  boot.enableContainers = false;
  environment.defaultPackages = [ ];
  documentation.info.enable = false;
  documentation.nixos.enable = false;
  networking.nftables.enable = true;
  system.forbiddenDependenciesRegexes = [ "perl" ];
}
