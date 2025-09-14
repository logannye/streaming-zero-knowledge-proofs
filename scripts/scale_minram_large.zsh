#!/usr/bin/env zsh
set -euo pipefail

# T grows; b fixed -> time ~ linear; memory ~ flat with minram
T_LIST=( 524288 1048576 2097152 4194304 8388608 16777216 33554432 67108864 134217728 )
B=64
TAU=2
MODE=minram
CACHE=8
WRAP=0

# Stable-ish RSS on macOS
export RAYON_NUM_THREADS=1
export MallocNanoZone=0

# Build in release for big runs
BUILD_PROFILE=--release

CLI="cargo run -q ${BUILD_PROFILE} -p sezkp-cli"

RUN_DIR=$(mktemp -d /tmp/sezkp_scale_large_XXXXXX)
echo "Artifacts -> ${RUN_DIR}"
CSV="${RUN_DIR}/results.csv"
print -r "T,b,tau,mode,cache,wrap,elapsed_seconds,max_rss_bytes,proof_bytes" > "$CSV"

now() { date -u +%s; }

for T in $T_LIST; do
  echo
  echo "== T=${T}, b=${B}, τ=${TAU}, mode=${MODE}, cache=${CACHE} =="

  BLOCKS="${RUN_DIR}/blocks-${T}.cbor"
  MAN="${RUN_DIR}/manifest-${T}.cbor"
  PROOF="${RUN_DIR}/proof-fold-${MODE}-${T}.cbor"
  LOG="${RUN_DIR}/prove-${T}.log"

  # 1) Simulate, 2) Commit, 3) Verify-commit
  ${=CLI} -- simulate --t $T --b $B --tau $TAU --out-blocks "$BLOCKS"
  ${=CLI} -- commit    --blocks "$BLOCKS" --out "$MAN"
  ${=CLI} -- verify-commit --blocks "$BLOCKS" --manifest "$MAN"

  # 4) Prove with minram (tiny cache), measure time + RSS
  export SEZKP_FOLD_MODE=$MODE
  export SEZKP_FOLD_CACHE=$CACHE
  export SEZKP_WRAP_CADENCE=$WRAP

  start=$(now)
  (/usr/bin/time -l ${=CLI} -- prove \
      --backend fold \
      --blocks "$BLOCKS" \
      --manifest "$MAN" \
      --out "$PROOF") &> "$LOG"
  end=$(now)
  dur=$(( end - start ))

  # 5) Verify proof
  ${=CLI} -- verify --backend fold --blocks "$BLOCKS" --manifest "$MAN" --proof "$PROOF"

  # 6) Parse RSS from /usr/bin/time -l and proof size (Darwin + Linux stat)
  rss_line=$(grep -i 'maximum resident set size' "$LOG" || true)
  rss_val=$(echo "$rss_line" | awk '{for(i=1;i<=NF;i++) if ($i ~ /^[0-9]+$/){print $i; exit}}')
  if echo "$rss_line" | grep -qi 'kbyte'; then
    rss_bytes=$(( rss_val * 1024 ))
  else
    rss_bytes=$rss_val
  fi

  proof_bytes=$(stat -f%z "$PROOF" 2>/dev/null || stat -c%s "$PROOF")
  print -r "$T,$B,$TAU,$MODE,$CACHE,$WRAP,$dur,$rss_bytes,$proof_bytes" >> "$CSV"
done

echo "\n== Results CSV =="
if command -v column >/dev/null 2>&1; then
  column -s, -t "$CSV" || cat "$CSV"
else
  cat "$CSV"
fi

echo "\nDone. See: $RUN_DIR"
