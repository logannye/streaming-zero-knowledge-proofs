#!/usr/bin/env zsh
set -euo pipefail

REPO="/Users/logannye/sezkp"
TAU="${TAU:-2}"
MODE="minram"
CACHE="${CACHE:-8}"
WRAP="${WRAP:-0}"
ROUNDS="${ROUNDS:-3}"
T_LIST=(32768 65536 131072 262144 524288 1048576 2097152 4194304)

export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-1}"
export MallocNanoZone=0

human_mb() {
  bytes="$1"
  if [ -z "$bytes" ] || [ "$bytes" = "0" ]; then
    echo 0
  else
    awk -v b="$bytes" 'BEGIN{printf "%.1f", b/1048576.0}'
  fi
}

mkid() {
  LC_ALL=C tr -dc 'a-z0-9' < /dev/urandom | head -c 6
}

RUN_ID="$(mkid)"
RUN_DIR="/tmp/sezkp_scale_${RUN_ID}"
mkdir -p "$RUN_DIR"
echo "Artifacts -> $RUN_DIR"

CSV="$RUN_DIR/results.csv"
echo "ts_utc,round,T,b,tau,mode,cache,wrap,prove_sec,verify_sec,total_sec,max_rss_bytes,proof_bytes" > "$CSV"

cd "$REPO"
echo "Warm-up build..."
cargo build -q --workspace --all-targets || true

round=1
while [ "$round" -le "$ROUNDS" ]; do
  for T in "${T_LIST[@]}"; do
    B=$(( T / 1024 ))
    FILE="$RUN_DIR/blocks-${T}.cbor"
    MAN="$RUN_DIR/manifest-${T}.cbor"
    PROOF="$RUN_DIR/proof-fold-minram-${T}.cbor"
    LOGP="$RUN_DIR/prove-${T}.time"
    LOGV="$RUN_DIR/verify-${T}.time"

    echo ""
    echo "Round ${round}/${ROUNDS} :: T=${T}, b=${B}, tau=${TAU}, mode=${MODE}, cache=${CACHE}, wrap=${WRAP}"

    echo "Simulate..."
    cargo run -q -p sezkp-cli -- simulate --t "$T" --b "$B" --tau "$TAU" --out-blocks "$FILE"

    echo "Commit + verify-commit..."
    cargo run -q -p sezkp-cli -- commit --blocks "$FILE" --out "$MAN"
    cargo run -q -p sezkp-cli -- verify-commit --blocks "$FILE" --manifest "$MAN"

    echo "Prove..."
    SEZKP_FOLD_MODE="$MODE" SEZKP_FOLD_CACHE="$CACHE" SEZKP_WRAP_CADENCE="$WRAP" \
      sh -c '
        start=$(date +%s)
        (/usr/bin/time -l cargo run -q -p sezkp-cli -- prove --backend fold --blocks "$0" --manifest "$1" --out "$2") 2> "$3"
        end=$(date +%s)
        echo $((end-start))
      ' "$FILE" "$MAN" "$PROOF" "$LOGP" > "$RUN_DIR/prove-${T}.sec"
    prove_sec="$(cat "$RUN_DIR/prove-${T}.sec" | tr -d '\n' || echo 0)"

    echo "Verify..."
    sh -c '
      start=$(date +%s)
      (/usr/bin/time -l cargo run -q -p sezkp-cli -- verify --backend fold --blocks "$0" --manifest "$1" --proof "$2") 2> "$3"
      end=$(date +%s)
      echo $((end-start))
    ' "$FILE" "$MAN" "$PROOF" "$LOGV" > "$RUN_DIR/verify-${T}.sec"
    verify_sec="$(cat "$RUN_DIR/verify-${T}.sec" | tr -d '\n' || echo 0)"

    total_sec=$(( prove_sec + verify_sec ))

    rss_line="$(grep -i 'maximum resident set size' "$LOGP" || true)"
    rss_val="$(echo "$rss_line" | awk '{for(i=1;i<=NF;i++) if ($i ~ /^[0-9]+$/){print $i; exit}}')"
    if echo "$rss_line" | grep -qi 'kbyte'; then
      rss_bytes=$(( rss_val * 1024 ))
    else
      rss_bytes="$rss_val"
    fi

    proof_bytes="$(stat -f%z "$PROOF")"
    ts_iso="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

    echo "$ts_iso,$round,$T,$B,$TAU,$MODE,$CACHE,$WRAP,$prove_sec,$verify_sec,$total_sec,$rss_bytes,$proof_bytes" >> "$CSV"

    rss_mb="$(human_mb "$rss_bytes")"
    proof_mb="$(human_mb "$proof_bytes")"
    printf "   prove=%5ss  verify=%5ss  total=%5ss  RSS=%6s MB  proof=%6s MB\n" \
      "$prove_sec" "$verify_sec" "$total_sec" "$rss_mb" "$proof_mb"

    echo "   recent results:"
    tail -n 6 "$CSV"
  done
  round=$((round + 1))
done

echo ""
echo "== Full Results CSV =="
cat "$CSV"
echo ""
echo "Done. See: $RUN_DIR"
