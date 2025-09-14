#!/usr/bin/env zsh
set -euo pipefail

# ---------------- knobs ----------------
T_LIST=(32768 65536 131072 262144 524288 1048576 2097152 4194304 8388608 16777216 33554432 67108864 134217728)
BLOCK_LEN=64                # per-block length; n_blocks = T / BLOCK_LEN
TAU=8
WRAP=0
THREADS=1                   # stabilize RSS on macOS
BUILD_PROFILE=--release

MODES=(balanced minram)
CACHES=(0 8 64)             # cache only used in minram

ROOT="/Users/logannye/sezkp"
CLI="cargo run -q ${BUILD_PROFILE} -p sezkp-cli"

RUN_DIR=$(mktemp -d /tmp/sezkp_scale_stream_XXXXXX)
echo "Artifacts -> ${RUN_DIR}"
CSV="${RUN_DIR}/results.csv"
print -r "exp,T,block_len,n_blocks,tau,mode,cache,wrap,threads,streamed,prove_s,verify_s,max_rss_bytes,peak_mem_bytes,proof_bytes" > "$CSV"

TIME_BIN="/usr/bin/time"    # macOS
TIME_FLAG="-l"

now() { date -u +%s; }

export RAYON_NUM_THREADS=$THREADS
export MallocNanoZone=0

exp_i=1
for T in $T_LIST; do
  n_blocks=$(( T / BLOCK_LEN ))
  if (( n_blocks < 1 )); then
    echo "Skip T=${T} (BLOCK_LEN=${BLOCK_LEN} gives <1 block)"; continue
  fi

  echo
  echo "== T=${T}, block_len=${BLOCK_LEN}, n_blocks=${n_blocks}, τ=${TAU} =="

  BLOCKS_JSONL="${RUN_DIR}/blocks-T${T}-L${BLOCK_LEN}.jsonl"
  MAN="${RUN_DIR}/manifest-T${T}-L${BLOCK_LEN}.cbor"

  # 1) Simulate to JSONL *with the correct number of blocks*
  ${=CLI} -- simulate --t $T --b $n_blocks --tau $TAU --out-blocks "$BLOCKS_JSONL"

  # 2) Commit + verify-commit
  ${=CLI} -- commit         --blocks "$BLOCKS_JSONL" --out "$MAN"
  ${=CLI} -- verify-commit  --blocks "$BLOCKS_JSONL" --manifest "$MAN"

  for mode in $MODES; do
    if [[ "$mode" == "balanced" ]]; then
      caches=(0)
    else
      caches=("${CACHES[@]}")
    fi

    for cache in $caches; do
      echo "-- mode=${mode}, cache=${cache} --"

      PROOF="${RUN_DIR}/proof-${mode}-c${cache}-T${T}-L${BLOCK_LEN}.cbor"
      LOG="${RUN_DIR}/prove-${mode}-c${cache}-T${T}-L${BLOCK_LEN}.log"

      args=(
        -- prove
        --backend fold
        --blocks "$BLOCKS_JSONL"
        --manifest "$MAN"
        --out "$PROOF"
        --fold-mode "$mode"
        --fold-cache "$cache"
        --wrap-cadence "$WRAP"
        --stream
      )

      start=$(now)
      set +e
      (${TIME_BIN} ${TIME_FLAG} ${=CLI} "${args[@]}") &> "$LOG"
      rc=$?
      set -e
      end=$(now)
      prove_s=$(( end - start ))

      # Parse memory from /usr/bin/time -l (both forms)
      rss_line=$(grep -i 'maximum resident set size' "$LOG" || true)
      pmf_line=$(grep -i 'peak memory footprint' "$LOG" || true)
      rss_val=$(echo "$rss_line" | awk '{for(i=1;i<=NF;i++) if ($i ~ /^[0-9]+$/){print $i; exit}}')
      pmf_val=$(echo "$pmf_line" | awk '{for(i=1;i<=NF;i++) if ($i ~ /^[0-9]+$/){print $i; exit}}')
      # rss_val is in kbytes on macOS; pmf_val is bytes already
      if [[ -n "${rss_val:-}" ]]; then
        max_rss_bytes=$(( rss_val * 1024 ))
      else
        max_rss_bytes=0
      fi
      if [[ -z "${pmf_val:-}" ]]; then
        peak_mem_bytes=0
      else
        peak_mem_bytes=$pmf_val
      fi

      if (( rc != 0 )) || [[ ! -s "$PROOF" ]]; then
        echo "!! prove failed or proof missing (rc=${rc}) -- tail of log:"
        tail -n 80 "$LOG" || true
        print -r "$exp_i,$T,$BLOCK_LEN,$n_blocks,$TAU,$mode,$cache,$WRAP,$THREADS,true,$prove_s,0,$max_rss_bytes,$peak_mem_bytes,NA" >> "$CSV"
        exp_i=$((exp_i+1))
        continue
      fi

      # Verify (quietly)
      vstart=$(now)
      if ! ${=CLI} -- verify \
          --backend fold \
          --blocks "$BLOCKS_JSONL" \
          --manifest "$MAN" \
          --proof "$PROOF" >/dev/null 2>&1 ; then
        echo "!! verify failed -- $PROOF"
        tail -n 80 "$LOG" || true
        print -r "$exp_i,$T,$BLOCK_LEN,$n_blocks,$TAU,$mode,$cache,$WRAP,$THREADS,true,$prove_s,0,$max_rss_bytes,$peak_mem_bytes,NA" >> "$CSV"
        exp_i=$((exp_i+1))
        continue
      fi
      vend=$(now)
      verify_s=$(( vend - vstart ))

      proof_bytes=$(stat -f%z "$PROOF" 2>/dev/null || stat -c%s "$PROOF")
      print -r "$exp_i,$T,$BLOCK_LEN,$n_blocks,$TAU,$mode,$cache,$WRAP,$THREADS,true,$prove_s,$verify_s,$max_rss_bytes,$peak_mem_bytes,$proof_bytes" >> "$CSV"
      exp_i=$((exp_i+1))
    done
  done
done

echo "\n== Results CSV =="
if command -v column >/dev/null 2>&1; then
  column -s, -t "$CSV" || cat "$CSV"
else
  cat "$CSV"
fi

echo "\nDone. See: $RUN_DIR"
