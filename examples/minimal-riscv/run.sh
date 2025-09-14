#!/usr/bin/env bash
set -euo pipefail

# End-to-end demo using the tiny RV-like VM → partition → commit → STARK prove/verify.
# You can tweak STEPS or B on the command line.

STEPS="${STEPS:-32}"
B="${B:-4}"

echo "== Build =="
cargo build --workspace

echo "== VM run =="
cargo run -p sezkp-vm-riscv -- --steps "${STEPS}" --b "${B}" --out-dir examples/minimal-riscv

echo "== Done =="
ls -lh examples/minimal-riscv/*.cbor || true
