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
