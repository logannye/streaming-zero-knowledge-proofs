#!/usr/bin/env sh
set -eu
cargo clippy --workspace --all-targets -- -D warnings
