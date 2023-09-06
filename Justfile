default:
  @just --list

actionlint:
  actionlint

build:                                                                 d
  cargo build

build-release:
  cargo build --release

check: actionlint clippy doc fmt test udeps

clean:
  cargo clean

clippy:
  cargo clippy --locked -- -D warnings

doc:
  RUSTDOCFLAGS="-D warnings" cargo +nightly doc --document-private-items

fmt:
  cargo fmt --all

pr:
  gh pr create --web

test:
  cargo test --locked

udeps:
  cargo +nightly udeps --all-targets --backend depinfo

# TODO: Stuff from Makefile
