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
      src = craneLib.cleanCargoSource self;

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
