{
  shortRev,
  lib,
  buildGoModule,
  openssh,
}:
buildGoModule {
  pname = "unlock-gate";
  version = "0.1.0+${shortRev}";
  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./go.mod
      ./go.sum
      ./cmd
      ./internal
    ];
  };
  vendorHash = "sha256-n86r8ZpKLpoLH2Z0KpuJqvVHByVNtKbFz01NlgJ8ajY=";
  env.CGO_ENABLED = 0;
  ldflags = [ "-s" ];
  # TestRealSSHKeygenSignature checks sshsig interop against OpenSSH.
  nativeCheckInputs = [ openssh ];
  meta.mainProgram = "unlock-gate";
}
