#!/usr/bin/env zsh
set -euo pipefail
setopt NO_BANG_HIST   # avoid "event not found" on '!'

# ---------------- knobs ----------------
T_LIST=(32768 65536 131072 262144 524288 1048576 2097152 4194304 8388608 16777216 33554432 67108864 134217728)
BLOCK_LEN=64         # block length per leaf; n_blocks = T / BLOCK_LEN
TAU=8
WRAP=0
THREADS=1            # stabilize RSS on macOS
BUILD_PROFILE=--release

MODES=(balanced minram)
CACHES=(0 8 64)     # cache only matters in minram

# Compare true streaming vs a non-streamed baseline.
STREAMS=(true false)
# Safety cap for the non-stream baseline (loads full Vec):
NOSTREAM_T_MAX=4194304   # 4,194,304

CLI="cargo run -q ${BUILD_PROFILE} -p sezkp-cli"

RUN_DIR=$(mktemp -d /tmp/sezkp_scale_stream_XXXXXX)
echo "Artifacts -> ${RUN_DIR}"
CSV="${RUN_DIR}/results.csv"
print -r "exp,T,block_len,n_blocks,tau,mode,cache,wrap,threads,streamed,prove_s,verify_s,prove_rss_bytes,verify_rss_bytes,proof_bytes" > "$CSV"

TIME_BIN="/usr/bin/time" # macOS time(1)
TIME_FLAG="-l"           # prints 'maximum resident set size'

now() { date -u +%s; }

export RAYON_NUM_THREADS=$THREADS
export MallocNanoZone=0

parse_rss() {
  local log="$1"
  local rss_line rss_val
  rss_line=$(grep -i 'maximum resident set size' "$log" || true)
  rss_val=$(echo "$rss_line" | awk '{for(i=1;i<=NF;i++) if ($i ~ /^[0-9]+$/){print $i; exit}}')
  if echo "$rss_line" | grep -qi 'kbyte'; then
    echo $(( rss_val * 1024 ))
  else
    echo "$rss_val"
  fi
}

exp_i=1
for T in $T_LIST; do
  n_blocks=$(( T / BLOCK_LEN ))
  (( n_blocks >= 1 )) || { echo "Skip T=${T} (BLOCK_LEN=${BLOCK_LEN} gives <1 block)"; continue; }

  echo
  echo "== T=${T}, block_len=${BLOCK_LEN}, n_blocks=${n_blocks}, τ=${TAU} =="

  # Paths
  BLOCKS_CBOR="${RUN_DIR}/blocks-T${T}-L${BLOCK_LEN}.cbor"
  BLOCKS_JSONL="${RUN_DIR}/blocks-T${T}-L${BLOCK_LEN}.jsonl"
  MAN="${RUN_DIR}/manifest-T${T}-L${BLOCK_LEN}.cbor"

  # 1) Simulate to **CBOR** (note: --b is block length, not count)
  ${=CLI} -- simulate --t $T --b $BLOCK_LEN --tau $TAU --out-blocks "$BLOCKS_CBOR"

  # 2) Export a **JSONL** stream from the same CBOR, so content is identical
  ${=CLI} -- export-jsonl --input "$BLOCKS_CBOR" --output "$BLOCKS_JSONL"

  # 3) Commit + verify-commit (we can commit from CBOR)
  ${=CLI} -- commit --blocks "$BLOCKS_CBOR" --out "$MAN"
  ${=CLI} -- verify-commit --blocks "$BLOCKS_CBOR" --manifest "$MAN" >/dev/null
  # Optional: sanity-check the JSONL also matches the manifest
  ${=CLI} -- verify-commit --blocks "$BLOCKS_JSONL" --manifest "$MAN" >/dev/null

  for mode in $MODES; do
    if [[ "$mode" == "balanced" ]]; then
      caches=(0)   # not used; record as 0
    else
      caches=("${CACHES[@]}")
    fi

    for cache in $caches; do
      for streamed in $STREAMS; do
        # Gate the non-stream baseline on large T
        if [[ "$streamed" == "false" && $T -gt $NOSTREAM_T_MAX ]]; then
          echo "-- mode=${mode}, cache=${cache}, streamed=${streamed} (skip at T=${T} > ${NOSTREAM_T_MAX})"
          continue
        fi

        echo "-- mode=${mode}, cache=${cache}, streamed=${streamed} --"

        PROOF="${RUN_DIR}/proof-${mode}-c${cache}-T${T}-L${BLOCK_LEN}-s${streamed}.cbor"
        PLOG="${RUN_DIR}/prove-${mode}-c${cache}-T${T}-L${BLOCK_LEN}-s${streamed}.log"
        VLOG="${RUN_DIR}/verify-${mode}-c${cache}-T${T}-L${BLOCK_LEN}-s${streamed}.log"

        # Choose the blocks path per mode
        if [[ "$streamed" == "true" ]]; then
          BLOCKS_PATH="$BLOCKS_JSONL"
          stream_flag=(--stream)
        else
          BLOCKS_PATH="$BLOCKS_CBOR"
          stream_flag=()   # no --stream
        fi

        # --- Prove ---
        start=$(now)
        set +e
        (${TIME_BIN} ${TIME_FLAG} ${=CLI} \
          -- prove \
          --backend fold \
          --blocks "$BLOCKS_PATH" \
          --manifest "$MAN" \
          --out "$PROOF" \
          --fold-mode "$mode" \
          --fold-cache "$cache" \
          --wrap-cadence "$WRAP" \
          "${stream_flag[@]}") &> "$PLOG"
        rc=$?
        set -e
        end=$(now)
        prove_s=$(( end - start ))

        if (( rc != 0 )); then
          echo "!! prove failed (rc=${rc}) -- tail of log:"
          tail -n 100 "$PLOG" || true
          print -r "$exp_i,$T,$BLOCK_LEN,$n_blocks,$TAU,$mode,$cache,$WRAP,$THREADS,$streamed,$prove_s,0,0,0,0" >> "$CSV"
          ((exp_i++))
          continue
        fi

        # --- Verify (time + RSS) ---
        vstart=$(now)
        set +e
        (${TIME_BIN} ${TIME_FLAG} ${=CLI} -- verify \
          --backend fold \
          --blocks "$BLOCKS_PATH" \
          --manifest "$MAN" \
          --proof "$PROOF") &> "$VLOG"
        vrc=$?
        set -e
        vend=$(now)
        verify_s=$(( vend - vstart ))

        if (( vrc != 0 )); then
          echo "!! verify failed -- proof: $PROOF"
          tail -n 100 "$VLOG" || true
          print -r "$exp_i,$T,$BLOCK_LEN,$n_blocks,$TAU,$mode,$cache,$WRAP,$THREADS,$streamed,$prove_s,0,0,0,0" >> "$CSV"
          ((exp_i++))
          continue
        fi

        prove_rss=$(parse_rss "$PLOG")
        verify_rss=$(parse_rss "$VLOG")
        proof_bytes=$(stat -f%z "$PROOF" 2>/dev/null || stat -c%s "$PROOF")

        print -r "$exp_i,$T,$BLOCK_LEN,$n_blocks,$TAU,$mode,$cache,$WRAP,$THREADS,$streamed,$prove_s,$verify_s,$prove_rss,$verify_rss,$proof_bytes" >> "$CSV"
        ((exp_i++))
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

echo "\nDone. See: $RUN_DIR"
