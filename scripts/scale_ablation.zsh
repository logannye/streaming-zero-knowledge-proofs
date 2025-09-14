#!/usr/bin/env zsh
set -euo pipefail

# -------- knobs you can tweak --------
TAU=2
BUILD_PROFILE=--release
ROOT="/Users/logannye/sezkp"
CLI="cargo run -q ${BUILD_PROFILE} -p sezkp-cli"

# macOS: more stable RSS and fewer allocator side-effects
export MallocNanoZone=0

RUN_DIR=$(mktemp -d /tmp/sezkp_scale_ablate_XXXXXX)
echo "Artifacts -> ${RUN_DIR}"
CSV="${RUN_DIR}/results.csv"
print -r "exp,T,b,tau,mode,cache,wrap,threads,elapsed_prove_s,elapsed_verify_s,max_rss_bytes,proof_bytes" > "$CSV"

now() { date -u +%s; }

# Run one prove+verify with /usr/bin/time -l to capture RSS; append a row to CSV.
# args: EXP T B MODE CACHE WRAP THREADS
run_one() {
  local EXP=$1 T=$2 B=$3 MODE=$4 CACHE=$5 WRAP=$6 THREADS=$7

  echo
  echo "== [$EXP] T=${T}, b=${B}, τ=${TAU}, mode=${MODE}, cache=${CACHE}, wrap=${WRAP}, threads=${THREADS} =="

  local BLOCKS="${RUN_DIR}/${EXP}-blocks-${T}.cbor"
  local MAN="${RUN_DIR}/${EXP}-manifest-${T}.cbor"
  local PROOF="${RUN_DIR}/${EXP}-proof-${MODE}-${T}.cbor"
  local LOGP="${RUN_DIR}/${EXP}-prove-${T}.log"
  local LOGV="${RUN_DIR}/${EXP}-verify-${T}.log"

  # Generate inputs
  ${=CLI} -- simulate --t $T --b $B --tau $TAU --out-blocks "$BLOCKS"
  ${=CLI} -- commit    --blocks "$BLOCKS" --out "$MAN"
  ${=CLI} -- verify-commit --blocks "$BLOCKS" --manifest "$MAN"

  # Backend env
  export SEZKP_FOLD_MODE=$MODE
  export SEZKP_FOLD_CACHE=$CACHE
  export SEZKP_WRAP_CADENCE=$WRAP
  export RAYON_NUM_THREADS=$THREADS

  # Prove
  local start=$(now)
  (/usr/bin/time -l ${=CLI} -- prove \
      --backend fold \
      --blocks "$BLOCKS" \
      --manifest "$MAN" \
      --out "$PROOF") &> "$LOGP"
  local end=$(now)
  local dur_prove=$(( end - start ))

  # Verify (measure separately)
  start=$(now)
  (/usr/bin/time -l ${=CLI} -- verify \
      --backend fold \
      --blocks "$BLOCKS" \
      --manifest "$MAN" \
      --proof "$PROOF") &> "$LOGV"
  end=$(now)
  local dur_verify=$(( end - start ))

  # Parse RSS (bytes) from prove log
  local rss_line=$(grep -i 'maximum resident set size' "$LOGP" || true)
  local rss_val=$(echo "$rss_line" | awk '{for(i=1;i<=NF;i++) if ($i ~ /^[0-9]+$/){print $i; exit}}')
  if echo "$rss_line" | grep -qi 'kbyte'; then
    rss_bytes=$(( rss_val * 1024 ))
  else
    rss_bytes=$rss_val
  fi

  local proof_bytes=$(stat -f%z "$PROOF")
  print -r "$EXP,$T,$B,$TAU,$MODE,$CACHE,$WRAP,$THREADS,$dur_prove,$dur_verify,$rss_bytes,$proof_bytes" >> "$CSV"
}

# -------------------------- EXPERIMENTS --------------------------

# EXP A: T-scale (minram); b fixed; threads=1; cache=8; wrap=0
A_T_LIST=( 524288 1048576 2097152 4194304 8388608 16777216 33554432 )
A_B=64
for T in $A_T_LIST; do
  run_one A $T $A_B minram 8 0 1
done

# EXP B: Cache sweep at fixed T (8M), b fixed
B_T=8388608
B_B=64
B_CACHE_LIST=( 0 2 8 64 256 )
for C in $B_CACHE_LIST; do
  run_one B $B_T $B_B minram $C 0 1
done

# EXP C: Block count sweep at fixed T (8M)
C_T=8388608
C_B_LIST=( 32 64 128 256 )
for BB in $C_B_LIST; do
  run_one C $C_T $BB minram 8 0 1
done

# EXP D: Mode comparison (balanced vs minram) at modest T to avoid OOM
D_T_LIST=( 131072 262144 524288 )
D_B=64
for T in $D_T_LIST; do
  run_one D $T $D_B minram   8 0 1
  run_one D $T $D_B balanced 8 0 1
done

# EXP E: Thread scaling at fixed T (8M)
E_T=8388608
E_B=64
E_THREADS=( 1 4 8 )
for TH in $E_THREADS; do
  run_one E $E_T $E_B minram 8 0 $TH
done

# EXP F: Wrap cadence sweep at fixed T (8M)
F_T=8388608
F_B=64
F_WRAP=( 0 8 32 )
for W in $F_WRAP; do
  run_one F $F_T $F_B minram 8 $W 1
done

# ------------------------ RESULTS ------------------------
echo "\n== Results CSV =="
if command -v column >/dev/null 2>&1; then
  column -s, -t "$CSV" || cat "$CSV"
else
  cat "$CSV"
fi
echo "\nDone. See: $RUN_DIR"
