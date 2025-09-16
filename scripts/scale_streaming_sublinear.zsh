#!/usr/bin/env zsh
set -euo pipefail
setopt NO_BANG_HIST   # avoid "event not found" on '!'

# ---------------- knobs ----------------
T_LIST=(32768 65536 131072 262144 524288 1048576 2097152 4194304 8388608 16777216 33554432 67108864 134217728)
BLOCK_LEN=64          # desired block length; CLI expects --b as BLOCK LENGTH (not count)
TAU=8
WRAP=0
THREADS=1             # stabilize RSS on macOS
BUILD_PROFILE=--release

MODES=(balanced minram)
CACHES=(0 8 64)       # cache only matters in minram

# Compare true streaming vs a non-streamed baseline.
STREAMS=(true false)

# Non-stream baseline policy beyond the cap:
#   skip   = never run > cap (previous behavior)
#   sample = run only for T values listed in NOSTREAM_EXTRA_TS
#   all    = run for all T (⚠️ may be slow / high RAM)
NOSTREAM_T_MAX=8388608                          # baseline cap
NOSTREAM_POLICY="sample"                        # skip|sample|all
NOSTREAM_EXTRA_TS=(16777216 67108864 134217728) # only used when policy=sample

CLI="cargo run -q ${BUILD_PROFILE} -p sezkp-cli"

# Build once (faster subsequent runs).
echo "Building CLI once (--release)…"
cargo build -q ${BUILD_PROFILE} -p sezkp-cli || { echo "Build failed"; exit 1; }

RUN_DIR=$(mktemp -d /tmp/sezkp_scale_stream_XXXXXX)
echo "Artifacts -> ${RUN_DIR}"
CSV="${RUN_DIR}/results.csv"
PRECSV="${RUN_DIR}/precheck.csv"

# Main results CSV
print -r "exp,T,block_len,n_blocks,tau,mode,cache,wrap,threads,streamed,prove_s,verify_s,prove_rss_bytes,verify_rss_bytes,proof_bytes,stream_bytes" > "$CSV"
# Extra CSV for manifest precheck
print -r "T,precheck_kind,seconds,rss_bytes" > "$PRECSV"

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

time_and_rss() { # usage: time_and_rss <logfile> <command...>
  local log="$1"; shift
  (${TIME_BIN} ${TIME_FLAG} "$@") &> "$log" || return $?
}

is_in_list() { # usage: is_in_list <needle> <list...>
  local needle="$1"; shift
  for x in "$@"; do [[ "$needle" == "$x" ]] && return 0; done
  return 1
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

  # 1) Simulate to **CBOR**
  ${=CLI} -- simulate --t $T --b $BLOCK_LEN --tau $TAU --out-blocks "$BLOCKS_CBOR"

  # 2) Export a **JSONL** stream from the same CBOR
  ${=CLI} -- export-jsonl --input "$BLOCKS_CBOR" --output "$BLOCKS_JSONL"

  # 3) Commit to manifest
  ${=CLI} -- commit --blocks "$BLOCKS_CBOR" --out "$MAN"

  # 4) Measure manifest verification RSS/time for CBOR and JSONL (diagnostics only)
  PCBOR_LOG="${RUN_DIR}/precheck-cbor-T${T}.log"
  PJSONL_LOG="${RUN_DIR}/precheck-jsonl-T${T}.log"

  start=$(now)
  if time_and_rss "$PCBOR_LOG" ${=CLI} -- verify-commit --blocks "$BLOCKS_CBOR" --manifest "$MAN"; then
    end=$(now); print -r "$T,cbor,$(( end - start )),$(parse_rss "$PCBOR_LOG")" >> "$PRECSV"
  else
    end=$(now); print -r "$T,cbor,$(( end - start )),0" >> "$PRECSV"
  fi

  start=$(now)
  if time_and_rss "$PJSONL_LOG" ${=CLI} -- verify-commit --blocks "$BLOCKS_JSONL" --manifest "$MAN"; then
    end=$(now); print -r "$T,jsonl,$(( end - start )),$(parse_rss "$PJSONL_LOG")" >> "$PRECSV"
  else
    end=$(now); print -r "$T,jsonl,$(( end - start )),0" >> "$PRECSV"
  fi

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
          case "$NOSTREAM_POLICY" in
            skip)
              echo "-- mode=${mode}, cache=${cache}, streamed=false (skip baseline at T=${T} > ${NOSTREAM_T_MAX})"
              continue
              ;;
            sample)
              if ! is_in_list "$T" "${NOSTREAM_EXTRA_TS[@]}"; then
                echo "-- mode=${mode}, cache=${cache}, streamed=false (skip: T=${T} not in sample set: ${NOSTREAM_EXTRA_TS[@]})"
                continue
              fi
              echo "-- mode=${mode}, cache=${cache}, streamed=false (RUN baseline sample at T=${T})"
              ;;
            all)
              echo "-- mode=${mode}, cache=${cache}, streamed=false (RUN baseline beyond cap — may be slow / high RAM)"
              ;;
          esac
        fi

        echo "-- mode=${mode}, cache=${cache}, streamed=${streamed} --"

        PROOF="${RUN_DIR}/proof-${mode}-c${cache}-T${T}-L${BLOCK_LEN}-s${streamed}.cbor"
        PROOF_STREAM="${PROOF:r}.cborseq"

        PLOG="${RUN_DIR}/prove-${mode}-c${cache}-T${T}-L${BLOCK_LEN}-s${streamed}.log"
        VLOG="${RUN_DIR}/verify-${mode}-c${cache}-T${T}-L${BLOCK_LEN}-s${streamed}.log"

        # Choose the blocks path per mode
        if [[ "$streamed" == "true" ]]; then
          BLOCKS_PATH="$BLOCKS_JSONL"
          stream_flag=(--stream)
        else
          BLOCKS_PATH="$BLOCKS_CBOR"
          stream_flag=()
        fi

        # --- Prove ---
        start=$(now)
        set +e
        ( SEZKP_FOLD_MODE="$mode" \
          SEZKP_FOLD_CACHE="$cache" \
          SEZKP_WRAP_CADENCE="$WRAP" \
          ${TIME_BIN} ${TIME_FLAG} ${=CLI} \
            -- prove \
            --backend fold \
            --blocks "$BLOCKS_PATH" \
            --manifest "$MAN" \
            --out "$PROOF" \
            --fold-mode "$mode" \
            --fold-cache "$cache" \
            --wrap-cadence "$WRAP" \
            --assume-committed \
            "${stream_flag[@]}" ) &> "$PLOG"
        rc=$?
        set -e
        end=$(now)
        prove_s=$(( end - start ))

        proof_bytes=0
        stream_bytes=0
        if (( rc == 0 )); then
          proof_bytes=$(stat -f%z "$PROOF" 2>/dev/null || stat -c%s "$PROOF" 2>/dev/null || echo 0)
          if [[ "$streamed" == "true" && -f "$PROOF_STREAM" ]]; then
            stream_bytes=$(stat -f%z "$PROOF_STREAM" 2>/dev/null || stat -c%s "$PROOF_STREAM" 2>/dev/null || echo 0)
          fi
        fi

        if (( rc != 0 )); then
          echo "!! prove failed (rc=${rc}) -- tail of log:"
          tail -n 100 "$PLOG" || true
          print -r "$exp_i,$T,$BLOCK_LEN,$n_blocks,$TAU,$mode,$cache,$WRAP,$THREADS,$streamed,$prove_s,0,0,0,$proof_bytes,$stream_bytes" >> "$CSV"
          ((exp_i++))
          continue
        fi

        # --- Verify ---
        vstart=$(now)
        set +e
        ( SEZKP_FOLD_MODE="$mode" \
          SEZKP_FOLD_CACHE="$cache" \
          SEZKP_WRAP_CADENCE="$WRAP" \
          ${TIME_BIN} ${TIME_FLAG} ${=CLI} -- verify \
            --backend fold \
            --blocks "$BLOCKS_PATH" \
            --manifest "$MAN" \
            --proof "$PROOF" \
            --assume-committed ) &> "$VLOG"
        vrc=$?
        set -e
        vend=$(now)
        verify_s=$(( vend - vstart ))

        if (( vrc != 0 )); then
          echo "!! verify failed -- proof: $PROOF"
          tail -n 100 "$VLOG" || true
          print -r "$exp_i,$T,$BLOCK_LEN,$n_blocks,$TAU,$mode,$cache,$WRAP,$THREADS,$streamed,$prove_s,0,0,0,$proof_bytes,$stream_bytes" >> "$CSV"
          ((exp_i++))
          continue
        fi

        prove_rss=$(parse_rss "$PLOG")
        verify_rss=$(parse_rss "$VLOG")

        printf "   [T=%-9s mode=%-8s cache=%-3s streamed=%-5s] prove_rss=%.1fMB verify_rss=%.1fMB\n" \
          "$T" "$mode" "$cache" "$streamed" \
          "$((prove_rss/1024/1024.0))" "$((verify_rss/1024/1024.0))"

        print -r "$exp_i,$T,$BLOCK_LEN,$n_blocks,$TAU,$mode,$cache,$WRAP,$THREADS,$streamed,$prove_s,$verify_s,$prove_rss,$verify_rss,$proof_bytes,$stream_bytes" >> "$CSV"
        ((exp_i++))
      done
    done
  done
done

# -------------------------- Post-run insights --------------------------

slope() {
  # args: csv filter awk_condition colT colY label
  local file="$1" cond="$2" colT="$3" colY="$4" label="$5"
  awk -F, -v colT="$colT" -v colY="$colY" '
    BEGIN{minT="";maxT="";minY="";maxY=""}
    NR>1 && '"$cond"' && $(colY)+0>0 {
      if (minT=="" || $(colT)+0 < minT+0) {minT=$(colT); minY=$(colY)}
      if (maxT=="" || $(colT)+0 > maxT+0) {maxT=$(colT); maxY=$(colY)}
    }
    END{
      if (minT=="" || maxT=="") {print "NA ("'"$label"'")"; exit}
      p = log(maxY/minY)/log(maxT/minT)
      printf "%s p ~= %.3f\n","'"$label"'", p
    }' "$file"
}

echo "\n== Memory scaling (RSS exponents; streaming only) =="
slope "$CSV" '$6=="minram" && $10=="true" && $14>0' 2 14 "Streaming-minram VERIFY RSS"
slope "$CSV" '$6=="balanced" && $10=="true" && $14>0' 2 14 "Streaming-balanced VERIFY RSS"
slope "$CSV" '$6=="minram" && $10=="true" && $13>0' 2 13 "Streaming-minram PROVE  RSS"

echo "\n== Time scaling (exponents; streaming only) =="
slope "$CSV" '$6=="minram" && $10=="true" && $12>0' 2 12 "Streaming-minram VERIFY time"
slope "$CSV" '$6=="balanced" && $10=="true" && $12>0' 2 12 "Streaming-balanced VERIFY time"
slope "$CSV" '$6=="minram" && $10=="true" && $11>0' 2 11 "Streaming-minram PROVE  time"

echo "\n== Manifest precheck (scaling exponents) =="
slope "$PRECSV" '$2=="jsonl" && $4>0' 1 4 "JSONL precheck RSS"
slope "$PRECSV" '$2=="cbor"  && $4>0' 1 4 "CBOR  precheck RSS"
slope "$PRECSV" '$2=="jsonl" && $3>0' 1 3 "JSONL precheck time"
slope "$PRECSV" '$2=="cbor"  && $3>0' 1 3 "CBOR  precheck time"

echo "\n== Manifest precheck JSONL vs CBOR (largest T ratios) =="
awk -F, '
  NR>1 { if($2=="jsonl"){js[$1]=$4; jt[$1]=$3} else if($2=="cbor"){cs[$1]=$4; ct[$1]=$3} }
  END{
    maxT=0; for(t in js){ if(t+0>maxT+0) maxT=t }
    if(maxT==0 || !(maxT in cs)) { print "NA"; exit }
    printf "T=%s  RSS(cbor)/RSS(jsonl) ~= %.2fx;  TIME(cbor)/TIME(jsonl) ~= %.2fx\n",
      maxT, cs[maxT]/js[maxT], ct[maxT]/jt[maxT]
  }' "$PRECSV"

echo "\n== Streaming throughput at max T (steps/sec) =="
awk -F, '
  NR==1{next}
  $10=="true" {
    key=$6
    if (!(key in bestT) || $2+0>bestT[key]+0) {
      bestT[key]=$2; proveS[key]=$11; verifyS[key]=$12
    }
  }
  END{
    for (m in bestT) {
      t=bestT[m]+0; ps=proveS[m]+0; vs=verifyS[m]+0
      if (ps>0 && vs>0)
        printf "mode=%-8s T=%-9s  prove=%.2f Msteps/s  verify=%.2f Msteps/s\n", m, bestT[m], t/ps/1e6, t/vs/1e6
    }
  }' "$CSV"

echo "\n== Mean RSS across T (streaming only) =="
awk -F, '
  NR>1 && $10=="true" {
    c[$6]++; sumP[$6]+=$13; sumV[$6]+=$14
  }
  END{
    for(m in c){
      printf "mode=%-8s  PROVE=%.2fMB  VERIFY=%.2fMB  (mean over T)\n",
        m, sumP[m]/c[m]/1024/1024, sumV[m]/c[m]/1024/1024
    }
  }' "$CSV"

echo "\n== Minram cache effect at max T (streaming) =="
awk -F, '
  NR==1{next}
  $6=="minram" && $10=="true" { if ($2+0>maxT+0) maxT=$2 }
  END{ if (maxT=="") {print "NA"; exit} else print "T="maxT }' "$CSV"
awk -F, '
  NR==1{next}
  $6=="minram" && $10=="true" { data[$7","$2]=$12; rss[$7","$2]=$14; }
  END{
    maxT=0; for (k in data){ split(k,a,","); t=a[2]+0; if(t>maxT) maxT=t }
    if(maxT==0){print "NA"; exit}
    printf "  verify_s @ T=%s  cache=0:%ss  8:%ss  64:%ss\n",
      maxT, data["0,"maxT]+0, data["8,"maxT]+0, data["64,"maxT]+0
    printf "  verify_rss @ T=%s  cache=0:%.2fMB  8:%.2fMB  64:%.2fMB\n",
      maxT, rss["0,"maxT]/1024/1024, rss["8,"maxT]/1024/1024, rss["64,"maxT]/1024/1024
  }' "$CSV"

echo "\n== Non-stream vs stream ratios (minram) =="
echo "Verify RSS: nostream/stream (where both present)"
awk -F, '
  NR==1{next}
  $6=="minram" {
    key=$2","$7
    if($10=="true"){vrss[key]=$14; vtime[key]=$12}
    else if (key in vrss && $14>0) {
      printf "T=%-9s cache=%-3s  RSS ratio=%.2fx  TIME ratio=%5.2fx\n",
        $2,$7,$14/vrss[key], ($12>0 && vtime[key]>0)?$12/vtime[key]:0
    }
  }' "$CSV" | sort -k1,1n -k2,2n

# Ratio growth exponent (how fast nostream/stream grows with T)
echo "\n== Ratio growth exponent (minram verify, RSS) =="
awk -F, '
  NR==1{next}
  $6=="minram" {
    k=$2","$7
    if($10=="true"){s[$2","$7]=$14}
    else if($10=="false"){n[$2","$7]=$14}
  }
  END{
    # Find common Ts (for cache=0 by default to keep it simple)
    minT=""; maxT=""
    for (t in s) {
      split(t,a,","); T=a[1]; C=a[2]
      if (C!="0") continue
      key=T","C
      if (key in n) {
        ratio = n[key]/s[key]
        if (minT=="" || T+0<minT+0) {minT=T; rmin=ratio}
        if (maxT=="" || T+0>maxT+0) {maxT=T; rmax=ratio}
      }
    }
    if (minT=="" || maxT=="") {print "NA"; exit}
    p = log(rmax/rmin)/log(maxT/minT)
    printf "p ~= %.3f  (slope of nostream/stream ratio vs T; higher => streaming advantage grows faster)\n", p
  }' "$CSV"

echo "\n== Stream bytes per step (streaming=true; first and max T) =="
awk -F, '
  NR==1{next}
  $10=="true" && $16>0 {
    if (!minT || $2+0<minT+0) {minT=$2; sb_min=$16}
    if (!maxT || $2+0>maxT+0) {maxT=$2; sb_max=$16}
  }
  END{
    if(!minT){print "NA"; exit}
    printf "T=%s: %.4f bytes/step\n", minT, sb_min/(minT+0)
    if(maxT!=minT) printf "T=%s: %.4f bytes/step\n", maxT, sb_max/(maxT+0)
  }' "$CSV"

echo "\n== Worst 5 verify RSS cases (by mode/streamed) =="
awk -F, 'NR>1 {print $0}' "$CSV" | sort -t, -k14,14nr | head -n 5 | awk -F, '{printf "T=%s mode=%s cache=%s streamed=%s verify_rss=%.1fMB\n",$2,$6,$7,$10,$14/1024/1024}'

echo "\n== Worst 5 prove RSS cases =="
awk -F, 'NR>1 {print $0}' "$CSV" | sort -t, -k13,13nr | head -n 5 | awk -F, '{printf "T=%s mode=%s cache=%s streamed=%s prove_rss=%.1fMB\n",$2,$6,$7,$10,$13/1024/1024}'

echo "\n== Sample tiny artifact sizes (streaming=true) =="
awk -F, 'NR==1{next} $10=="true"{print "T="$2,"artifact_bytes="$15,"stream_bytes="$16}' "$CSV" | head -n 8

echo "\nPrecheck CSV: $PRECSV"
echo "Main CSV:     $CSV"
echo "Done. See: $RUN_DIR"
