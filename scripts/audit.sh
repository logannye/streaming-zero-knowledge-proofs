#!/usr/bin/env sh
set -eu
cargo +stable install cargo-audit >/dev/null 2>&1 || true
cargo audit || true
