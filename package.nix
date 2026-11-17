{
  shortRev,
  craneLib,
  lib,
  stdenv,
  mold,
}:
let
  commonArgs = {
    src = craneLib.cleanCargoSource ./.;
    nativeBuildInputs = lib.optional stdenv.hostPlatform.isLinux mold;
    strictDeps = true;
  };
in
craneLib.buildPackage (
  commonArgs
  // {
    version = "${(craneLib.crateNameFromCargoToml { cargoToml = ./Cargo.toml; }).version}+${shortRev}";

    cargoVendorDir = craneLib.vendorCargoDeps { cargoLock = ./Cargo.lock; };
    cargoArtifacts = craneLib.buildDepsOnly commonArgs;

    # tests run in the dev partition checks
    doCheck = false;
    meta.mainProgram = "nbde-agent";
  }
)
