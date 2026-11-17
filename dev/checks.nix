{
  inputs,
  self,
  ...
}:
{
  perSystem =
    { pkgs, ... }:
    let
      craneLib = inputs.crane.mkLib pkgs;
      # Tests embed the interop vectors with include_str!, which
      # cleanCargoSource would drop.
      src = pkgs.lib.cleanSourceWith {
        src = self;
        name = "source";
        filter =
          path: type: craneLib.filterCargoSources path type || pkgs.lib.hasInfix "/tests/vectors" path;
      };

      commonArgs = {
        inherit src;
        nativeBuildInputs = [ pkgs.mold ];
        strictDeps = true;
      };
      cargoVendorDir = craneLib.vendorCargoDeps { cargoLock = self + "/Cargo.lock"; };
      cargoArtifacts = craneLib.buildDepsOnly commonArgs;
    in
    {
      checks = {
        crate-audit = craneLib.cargoAudit {
          inherit src cargoVendorDir;
          inherit (inputs) advisory-db;
        };

        crate-clippy = craneLib.cargoClippy (
          commonArgs
          // {
            inherit cargoArtifacts cargoVendorDir;
            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
          }
        );

        crate-fmt = craneLib.cargoFmt { inherit src; };

        crate-nextest = craneLib.cargoNextest (
          commonArgs
          // {
            inherit cargoArtifacts cargoVendorDir;
            cargoNextestExtraArgs = "--no-tests=pass";
          }
        );
      };
    };
}
