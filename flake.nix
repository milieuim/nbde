{
  description = "nbde: policy-gated network-bound disk encryption";

  inputs = {
    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    crane.url = "github:ipetkov/crane";
    pre-commit-hooks = {
      url = "github:cachix/git-hooks.nix";
      inputs = {
        flake-compat.follows = "";
        nixpkgs.follows = "nixpkgs";
      };
    };
  };

  outputs =
    inputs@{ flake-parts, self, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      partitionedAttrs = {
        checks = "dev";
      };
      partitions = {
        dev.extraInputsFlake = ./dev;
        dev.module = _: {
          imports = [
            ./dev/checks.nix
            ./dev/vm-tests.nix
          ];
        };
      };

      imports = [
        inputs.flake-parts.flakeModules.partitions
        inputs.pre-commit-hooks.flakeModule
      ];

      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      perSystem =
        {
          self',
          pkgs,
          config,
          ...
        }:
        {
          packages =
            let
              p = self.overlays.default pkgs pkgs;
            in
            p // { default = p.nbde-agent; };

          formatter = pkgs.nixfmt-tree;

          pre-commit = {
            check.enable = true;
            settings.hooks = {
              nixfmt.enable = true;
              rustfmt.enable = true;
            };
          };

          devShells.default = (inputs.crane.mkLib pkgs).devShell {
            shellHook = config.pre-commit.installationScript;
            inputsFrom = [ self'.packages.default ];
            packages = with pkgs; [
              just
              nushell
              cargo-nextest
              cargo-audit
              rust-analyzer
              typos
              # interop vectors are generated with the reference implementation
              clevis
              tang
              jose
            ];
          };
        };

      flake.overlays.default = final: _prev: {
        nbde-agent = final.callPackage ./package.nix {
          shortRev = self.shortRev or "dirty";
          craneLib = inputs.crane.mkLib final;
        };
      };
    };
}
