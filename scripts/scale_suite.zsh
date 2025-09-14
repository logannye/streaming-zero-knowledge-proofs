#!/usr/bin/env zsh
# Scale + ablation runner for SEZKP (macOS-friendly)
set -euo pipefail

# ---------------------------- knobs you can tweak ----------------------------
# T values (trace length). Add more if you want to run for hours.
T_LIST=( 32768 65536 131072 262144 524288 1048576 )
# Constant number of blocks = T / B (so per-block length grows with T).
NBLOCKS=1024
TAU=2
MODES=( balanced minram )
CACHES=( 0 8 64 )          # cache only matters for minram; harmless otherwise
WRAP=0

# Thread counts to try; 1 is best for stable RSS on macOS
THREADS=( 1 )

# Use --release for speed/stability at scale
BUILD_PROFILE=--release

# Project locations
ROOT="/Users/logannye/sezkp"
CLI="cargo run -q ${BUILD_PROFILE} -p sezkp-cli"

# ----------------------------- output directories ----------------------------
RUN_DIR=$(mktemp -d /tmp/sezkp_scale_suite_XXXXXX)
echo "Artifacts -> ${RUN_DIR}"
CSV="${RUN_DIR}/results.csv"

# CSV header
print -r "exp,T,b,blocks,tau,mode,cache,wrap,threads,prove_s,verify_s,max_rss_bytes,proof_bytes" > "$CSV"

# Helpers
now() { date -u +%s; }

# Parse RSS from /usr/bin/time -l (macOS) or /usr/bin/time -v (Linux)
parse_rss() {
  local log="$1"
  # macOS: "maximum resident set size"
  local line=$(grep -i 'maximum resident set size' "$log" || true)
  if [[ -n "$line" ]]; then
    # value may be "123456" (bytes) or "123456 kbytes"
    local val=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if ($i ~ /^[0-9]+$/){print $i; exit}}')
    if echo "$line" | grep -qi 'kbyte'; then
      echo $(( val * 1024 ))
    else
      echo "$val"
    fi
    return
  fi
  # Linux: "Maximum resident set size (kbytes): 123456"
  line=$(grep -i 'Maximum resident set size' "$log" || true)
  if [[ -n "$line" ]]; then
    local val=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if ($i ~ /^[0-9]+$/){print $i; exit}}')
    echo $(( val * 1024 ))
    return
  fi
  echo 0
}

# Build once
cd "$ROOT"
cargo build ${BUILD_PROFILE}

exp=A
for T in $T_LIST; do
  # keep block count constant -> choose per-block length b = T / NBLOCKS
  B=$(( T / NBLOCKS ))
  if (( B <= 0 )); then
    echo "Skipping T=$T (b computed non-positive)"; continue
  fi

  BLOCKS="${RUN_DIR}/blocks-${T}.cbor"
  MAN="${RUN_DIR}/manifest-${T}.cbor"

  echo
  echo "== Prepare inputs: T=${T}, b=${B}, blocks=${NBLOCKS}, τ=${TAU} =="

  # 1) Simulate, 2) Commit, 3) Verify-commit
  ${=CLI} -- simulate --t $T --b $B --tau $TAU --out-blocks "$BLOCKS"
  ${=CLI} -- commit    --blocks "$BLOCKS" --out "$MAN"
  ${=CLI} -- verify-commit --blocks "$BLOCKS" --manifest "$MAN"

  for mode in $MODES; do
    for cache in $CACHES; do
      for th in $THREADS; do
        echo
        echo "== Prove: T=${T}, b=${B}, mode=${mode}, cache=${cache}, threads=${th} =="

        PROOF="${RUN_DIR}/proof-fold-${mode}-c${cache}-t${th}-${T}.cbor"
        LOGP="${RUN_DIR}/prove-${mode}-c${cache}-t${th}-${T}.log"
        LOGV="${RUN_DIR}/verify-${mode}-c${cache}-t${th}-${T}.log"

        # Set env knobs the fold backend reads
        export SEZKP_FOLD_MODE="$mode"
        export SEZKP_FOLD_CACHE="$cache"
        export SEZKP_WRAP_CADENCE="$WRAP"
        export RAYON_NUM_THREADS="$th"
        export MallocNanoZone=0  # less noisy RSS on macOS

        # --- Prove (measure time + RSS) ---
        start=$(now)
        if /usr/bin/time -l true >/dev/null 2>&1; then
          # macOS
          (/usr/bin/time -l ${=CLI} -- prove \
              --backend fold \
              --blocks "$BLOCKS" \
              --manifest "$MAN" \
              --out "$PROOF" \
              --fold-mode "$mode" \
              --fold-cache "$cache" \
              --wrap-cadence "$WRAP") &> "$LOGP"
        else
          # Linux fallback: -v
          (/usr/bin/time -v ${=CLI} -- prove \
              --backend fold \
              --blocks "$BLOCKS" \
              --manifest "$MAN" \
              --out "$PROOF" \
              --fold-mode "$mode" \
              --fold-cache "$cache" \
              --wrap-cadence "$WRAP") &> "$LOGP"
        fi
        end=$(now)
        prove_s=$(( end - start ))

        # --- Verify (separately) ---
        start_v=$(now)
        ${=CLI} -- verify \
          --backend fold \
          --blocks "$BLOCKS" \
          --manifest "$MAN" \
          --proof "$PROOF" &> "$LOGV"
        end_v=$(now)
        verify_s=$(( end_v - start_v ))

        # Parse RSS + proof size
        rss_bytes=$(parse_rss "$LOGP")
        proof_bytes=$(stat -f%z "$PROOF" 2>/dev/null || stat -c%s "$PROOF")

        # Write CSV row
        print -r "$exp,$T,$B,$NBLOCKS,$TAU,$mode,$cache,$WRAP,$th,$prove_s,$verify_s,$rss_bytes,$proof_bytes" >> "$CSV"

        # Bump label (A,B,C,...)
        exp=$(echo $exp | tr "0-8A-Y" "1-9B-Z")
      done
    done
  done
done

echo "\n== Results CSV =="
if command -v column >/dev/null 2>&1; then
  column -s, -t "$CSV" || cat "$CSV"
else
  cat "$CSV"
fi
echo "\nArtifacts saved in: $RUN_DIR"
