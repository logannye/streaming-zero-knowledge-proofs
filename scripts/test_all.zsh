#!/usr/bin/env zsh
set -e
set -u
set -o pipefail

echo "== 0) Clean + build =="
cargo clean
cargo build --workspace --all-targets

echo "== 1) Unit tests =="
cargo test -p sezkp-stark -- --nocapture
cargo test -p sezkp-fold  -- --nocapture

echo "== 2) Generate demo blocks =="
TMP="/tmp/sezkp_run_$$"
mkdir -p "$TMP"
cargo run -p sezkp-cli -- simulate --t 128 --b 16 --tau 2 --out-blocks "$TMP/blocks.cbor"

echo "== 3) Commit + verify commit =="
cargo run -p sezkp-cli -- commit        --blocks "$TMP/blocks.cbor" --out "$TMP/manifest.cbor"
cargo run -p sezkp-cli -- verify-commit --blocks "$TMP/blocks.cbor" --manifest "$TMP/manifest.cbor"

echo "== 4) STARK backend: prove + verify =="
cargo run -p sezkp-cli -- prove  --backend stark \
  --blocks "$TMP/blocks.cbor" --manifest "$TMP/manifest.cbor" \
  --out "$TMP/proof-stark.cbor"
cargo run -p sezkp-cli -- verify --backend stark \
  --blocks "$TMP/blocks.cbor" --manifest "$TMP/manifest.cbor" \
  --proof "$TMP/proof-stark.cbor" | tee "$TMP/verify-stark.log"
grep -q "OK: proof verified" "$TMP/verify-stark.log"

echo "== 5) FOLD backend (Balanced): prove + verify =="
cargo run -p sezkp-cli -- prove  --backend fold \
  --blocks "$TMP/blocks.cbor" --manifest "$TMP/manifest.cbor" \
  --out "$TMP/proof-fold-balanced.cbor" \
  --fold-mode balanced --fold-cache 64 --wrap-cadence 0
cargo run -p sezkp-cli -- verify --backend fold \
  --blocks "$TMP/blocks.cbor" --manifest "$TMP/manifest.cbor" \
  --proof "$TMP/proof-fold-balanced.cbor" | tee "$TMP/verify-fold-balanced.log"
grep -q "OK: proof verified" "$TMP/verify-fold-balanced.log"

echo "== 6) FOLD backend (MinRam + wraps): prove + verify =="
cargo run -p sezkp-cli -- prove  --backend fold \
  --blocks "$TMP/blocks.cbor" --manifest "$TMP/manifest.cbor" \
  --out "$TMP/proof-fold-minram.cbor" \
  --fold-mode minram --fold-cache 8 --wrap-cadence 3
cargo run -p sezkp-cli -- verify --backend fold \
  --blocks "$TMP/blocks.cbor" --manifest "$TMP/manifest.cbor" \
  --proof "$TMP/proof-fold-minram.cbor" | tee "$TMP/verify-fold-minram.log"
grep -q "OK: proof verified" "$TMP/verify-fold-minram.log"

echo "== 7) Proof sizes =="
ls -lh "$TMP"/proof-*.cbor

echo "✅ All tests + E2E checks passed"
