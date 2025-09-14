#!/usr/bin/env zsh
set -euo pipefail

REPO="/Users/logannye/sezkp"
cd "$REPO"

# Build once so timing focuses on prove/verify
cargo build --workspace --all-targets -q

# ===== Config =====
T_LIST=(32768 65536 131072 262144 524288 1048576 2097152 4194304 8388608)   # bump/add entries as your machine allows
TAU=2
CACHE=8            # small cache to highlight minram behavior
WRAP=0             # no intermediate wraps
RUN_DIR="$(mktemp -d /tmp/sezkp_scale_XXXXXX)"
CSV="$RUN_DIR/results.csv"

echo "Artifacts -> $RUN_DIR"
echo "T,b,tau,mode,cache,wrap,elapsed_seconds,max_rss_bytes,proof_bytes" > "$CSV"

for T in $T_LIST; do
  B=$(( T / 1024 ))
  [[ $B -lt 1 ]] && B=1

  echo "\n== T=$T, b=$B, τ=$TAU, mode=minram, cache=$CACHE =="

  BLOCKS="$RUN_DIR/blocks-$T.cbor"
  MAN="$RUN_DIR/manifest-$T.cbor"
  PROOF="$RUN_DIR/proof-fold-minram-$T.cbor"
  LOG="$RUN_DIR/time-$T.txt"

  # Simulate + commit + verify-commit
  cargo run -q -p sezkp-cli -- simulate --t $T --b $B --tau $TAU --out-blocks "$BLOCKS"
  cargo run -q -p sezkp-cli -- commit   --blocks "$BLOCKS" --out "$MAN"
  cargo run -q -p sezkp-cli -- verify-commit --blocks "$BLOCKS" --manifest "$MAN"

  # Time + measure memory for PROVE (BSD /usr/bin/time -l prints max RSS)
  start=$(date +%s)
  /usr/bin/time -l \
    cargo run -q -p sezkp-cli -- prove \
      --backend fold \
      --blocks "$BLOCKS" \
      --manifest "$MAN" \
      --out "$PROOF" \
      --fold-mode minram \
      --fold-cache $CACHE \
      --wrap-cadence $WRAP \
    2> "$LOG"
  end=$(date +%s)
  dur=$(( end - start ))

  # Verify
  cargo run -q -p sezkp-cli -- verify \
    --backend fold \
    --blocks "$BLOCKS" \
    --manifest "$MAN" \
    --proof "$PROOF"

  # Parse metrics
  rss_line=$(grep -i 'maximum resident set size' "$LOG" || true)
  # First integer on that line:
  rss_val=$(echo "$rss_line" | awk '{for(i=1;i<=NF;i++) if ($i ~ /^[0-9]+$/){print $i; exit}}')
  # If the line mentions kbytes, convert to bytes:
  if echo "$rss_line" | grep -qi 'kbyte'; then
    rss_bytes=$(( rss_val * 1024 ))
  else
    rss_bytes=$rss_val
  fi
  proof_bytes=$(stat -f%z "$PROOF")

  echo "$T,$B,$TAU,minram,$CACHE,$WRAP,$dur,$rss_bytes,$proof_bytes" >> "$CSV"
done

echo "\n== Results CSV =="
column -s, -t "$CSV" || cat "$CSV"
echo "\nDone. See: $RUN_DIR"
