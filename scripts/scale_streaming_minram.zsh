#!/usr/bin/env zsh
set -euo pipefail

# ---- knobs ----
T_LIST=( 524288 1048576 2097152 4194304 8388608 )   # grow T (0.5M .. 8M)
B=1024                                              # keep #blocks fixed
TAU=2
MODE=minram
CACHE=8
WRAP=0
THREADS=1                                           # stable RSS on macOS

# Build release for speed
PROFILE=--release
ROOT="/Users/logannye/sezkp"
CLI="cargo run -q ${PROFILE} -p sezkp-cli"

# Output dir + CSV
RUN_DIR=$(mktemp -d /tmp/sezkp_stream_minram_XXXXXX)
CSV="${RUN_DIR}/results.csv"
echo "Artifacts -> ${RUN_DIR}"
print -r "T,b,blocks,tau,mode,cache,wrap,threads,prove_s,verify_s,max_rss_bytes,proof_bytes" > "$CSV"

# macOS RSS stabilizers
export RAYON_NUM_THREADS=$THREADS
export MallocNanoZone=0

now() { date -u +%s; }

for T in $T_LIST; do
  echo
  echo "== T=${T}, b=${B}, τ=${TAU}, mode=${MODE}, cache=${CACHE} =="

  BLOCKS_CBOR="${RUN_DIR}/blocks-${T}.cbor"
  BLOCKS_JSONL="${RUN_DIR}/blocks-${T}.jsonl"
  MAN="${RUN_DIR}/manifest-${T}.cbor"
  PROOF="${RUN_DIR}/proof-fold-${MODE}-${T}.cbor"
  LOGP="${RUN_DIR}/prove-${T}.log"
  LOGV="${RUN_DIR}/verify-${T}.log"

  # 1) simulate (CBOR)
  ${=CLI} -- simulate --t $T --b $B --tau $TAU --out-blocks "$BLOCKS_CBOR"

  # 2) commit + verify-commit (CBOR → manifest)
  ${=CLI} -- commit --blocks "$BLOCKS_CBOR" --out "$MAN"
  ${=CLI} -- verify-commit --blocks "$BLOCKS_CBOR" --manifest "$MAN"

  # 3) export to JSONL for streaming prover
  ${=CLI} -- export-jsonl --input "$BLOCKS_CBOR" --output "$BLOCKS_JSONL"

  # 4) prove (streaming, minram)
  start=$(now)
  (/usr/bin/time -l ${=CLI} -- prove \
      --backend fold \
      --blocks "$BLOCKS_JSONL" \
      --manifest "$MAN" \
      --out "$PROOF" \
      --fold-mode $MODE \
      --fold-cache $CACHE \
      --wrap-cadence $WRAP \
      --stream true) &> "$LOGP"
  prove_s=$(( $(now) - start ))

  # 5) verify (separate timing, reading CBOR blocks is fine)
  start=$(now)
  (/usr/bin/time -l ${=CLI} -- verify \
      --backend fold \
      --blocks "$BLOCKS_CBOR" \
      --manifest "$MAN" \
      --proof "$PROOF") &> "$LOGV"
  verify_s=$(( $(now) - start ))

  # 6) parse RSS from prove log (convert kbytes → bytes if needed)
  rss_line=$(grep -i 'maximum resident set size' "$LOGP" || true)
  rss_val=$(echo "$rss_line" | awk '{for(i=1;i<=NF;i++) if ($i ~ /^[0-9]+$/){print $i; exit}}')
  if echo "$rss_line" | grep -qi 'kbyte'; then
    rss_bytes=$(( rss_val * 1024 ))
  else
    rss_bytes=$rss_val
  fi
  proof_bytes=$(stat -f%z "$PROOF" 2>/dev/null || stat -c%s "$PROOF")

  # blocks is the number of leaves (=B here)
  print -r "$T,$B,$B,$TAU,$MODE,$CACHE,$WRAP,$THREADS,$prove_s,$verify_s,$rss_bytes,$proof_bytes" >> "$CSV"
done

echo "\n== Results CSV =="
if command -v column >/dev/null 2>&1; then
  column -s, -t "$CSV" || cat "$CSV"
else
  cat "$CSV"
fi

echo "\nDone. See: $RUN_DIR"
