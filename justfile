set shell := ["nu", "-c"]

default:
    @just --choose

build-package:
    nix build .

test:
    cargo nextest run --no-tests=pass

lint:
    cargo clippy --all-targets -- --deny warnings
    cargo fmt --check

check:
    nix flake check

vm-tests:
    nix build --no-link -L .#checks.x86_64-linux.vm-agent .#checks.x86_64-linux.vm-cryptsetup-socket .#checks.x86_64-linux.vm-daemon .#checks.x86_64-linux.vm-check .#checks.x86_64-linux.vm-initrd
