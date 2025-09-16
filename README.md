# SEZKP — Streaming, Sublinear-Space ZKP (reference implementation)

SEZKP is a reference pipeline for **streaming** proof generation & verification over long traces using **sublinear memory**. It includes:

* A canonical **Merkle commitment** over `BlockSummary` leaves (`sezkp-merkle`)
* A reference **CLI** (`sezkp-cli`) to simulate traces, commit/verify manifests, convert formats, and run proofs
* A **folding** backend (aggregate-style) and a **STARK v1** backend (PIOP/FRI) that support streaming I/O
* Test/benchmark scripts to validate **sublinear** memory growth and measure RSS vs. trace length

> ⚠️ Research/reference code. Interfaces may evolve; correctness tests exist, but **do not** treat this as production/security-audited.

---

## Repository layout

```
crates/
  sezkp-core/         # shared types, I/O helpers, backends glue, traits
  sezkp-crypto/       # transcript, domain separation, misc crypto helpers
  sezkp-merkle/       # canonical leaf hash + streaming Merkle manifest I/O
  sezkp-fold/         # fold/aggregate backend (Leaf, Fold, Wrap gadgets)
  sezkp-stark/        # STARK v1 backend (PIOP/FRI), streaming-friendly
  sezkp-ffts/         # FFT support (as needed by STARK)
  sezkp-scheduler/    # (if present) scheduling helpers
  ...
benchmarks/
  harness/            # (optional) benchmark harness
scripts/
  scale_streaming_sublinear.zsh   # memory-scaling test loop (macOS tuned)
```

---

## Requirements

* **Rust** stable (use `rustup update`)
* macOS or Linux

  * The provided script uses macOS `/usr/bin/time -l`. For Linux see notes below.
* For stable RSS on macOS:

  * `RAYON_NUM_THREADS=1`
  * `MallocNanoZone=0`

---

## Build

```bash
# at repo root
cargo build --release
```

---

## Quick start (end-to-end)

Simulate → commit → (optionally convert to JSONL) → prove → verify:

```bash
# 1) simulate a trace and write CBOR blocks
cargo run -q --release -p sezkp-cli -- simulate --t 32768 --b 512 --tau 8 --out-blocks blocks.cbor

# 2) commit → manifest
cargo run -q --release -p sezkp-cli -- commit --blocks blocks.cbor --out manifest.cbor

# 3a) (optional) convert to streaming JSONL
cargo run -q --release -p sezkp-cli -- export-jsonl --input blocks.cbor --output blocks.jsonl

# 3b) prove with fold backend (streaming path)
cargo run -q --release -p sezkp-cli -- prove \
  --backend fold \
  --blocks blocks.jsonl \
  --manifest manifest.cbor \
  --out proof.cbor \
  --fold-mode minram \
  --fold-cache 64 \
  --wrap-cadence 0 \
  --stream \
  --assume-committed

# 4) verify (streaming path preferred for sublinear memory)
cargo run -q --release -p sezkp-cli -- verify \
  --backend fold \
  --blocks blocks.jsonl \
  --manifest manifest.cbor \
  --proof proof.cbor \
  --assume-committed
```

**Backends**

* `--backend fold`: folding/aggregation backend (proof stream optional)
* `--backend stark`: STARK v1 backend (PIOP/FRI)

**Fold knobs (also read from env):**

* `--fold-mode {balanced|minram}`

  * `balanced` = keep more endpoints (higher memory, less recompute)
  * `minram`   = recompute endpoints (lower memory, more time)
* `--fold-cache <N>`: LRU cache capacity for minram (0 disables)
* `--wrap-cadence <k>`: emit wrap proofs every k folds (0 = disable)

**Streaming**

* Use `--stream` **and** give a `.jsonl`/`.ndjson` blocks file to avoid materializing the whole trace.

---

## Data formats

* **Blocks**: CBOR (`.cbor`), JSON (`.json`), or **JSON Lines** (`.jsonl`/`.ndjson`).
  JSONL is recommended for streaming prove/verify.
* **Manifest** (`sezkp-merkle::CommitManifest`):

  * `{ version: u32, root: [u8;32], n_leaves: u32 }`
  * Read/write as `.json` or `.cbor`
* **Proof artifacts**: written via `sezkp-core::io::write_proof_auto` (CBOR/JSON)

  * For folding+streaming, a sidecar `.cborseq` file holds the proof stream

---

## Canonical Merkle commitment (v1)

### Leaf hash schema

The canonical **leaf hash** is BLAKE3 over raw little-endian fields (no domain tag, no framing):

1. `version: u16`
2. `block_id: u32`
3. `step_lo: u64`
4. `step_hi: u64`
5. `ctrl_in: u16`
6. `ctrl_out: u16`
7. `in_head_in: i64`
8. `in_head_out: i64`
9. `windows.len(): u64`, then for each window: `left: i64`, `right: i64`
10. `head_in_offsets` values only (each `u32`)
11. `head_out_offsets` values only (each `u32`)
12. `movement_log.steps.len(): u64` (**length only** in v1)

> **Invariant:** The folding **Leaf** gadget must bind **exactly** the same byte layout as `sezkp_merkle::leaf_hash`.

### Tree shape

* Left-balanced; **odd** at a level is **promoted** (no duplicate last leaf).
* Parent combiner is `BLAKE3(left || right)`.

---

## Gadgets (fold backend)

* **Leaf**: proves π-consistency + transcript MAC that binds `(C, π-commit, boundary digests, micro-proof)`.
* **Fold**: combines two children → parent; transcript MAC binds `(C_left/right/parent, π-commits, interface, ARE proof bytes)`. Verifier only sees π **commitments**.
* **Wrap**: binds `(C_root, π_commit)` with a transcript MAC.

**Compatibility rule:** The **parent commitment** computed in fold MUST match `sezkp-merkle`’s parent combiner to keep the final folded commitment equal to the manifest root. Otherwise you’ll see “manifest root mismatch”.

---

## Streaming manifest precheck

`sezkp-merkle` provides:

* `commit_block_file(..)` – commits CBOR/JSON/JSONL; JSONL path streams
* `verify_block_file_against_manifest(..)` – **optimized JSONL** path that streams and hashes leaves without materializing all blocks into memory

To validate that the JSONL precheck path is optimized, use the scaling script and compare CBOR vs JSONL **RSS exponents** and **RSS ratios**.

---

## Benchmark: sublinear memory scaling

We include a macOS-tuned script that:

* Simulates multiple `T`
* Commits and prechecks (CBOR vs JSONL)
* Runs **prove/verify** across `{balanced,minram}` and caches `{0,8,64}`, both streaming and non-streaming
* Logs **RSS** via `/usr/bin/time -l`
* Prints **log–log slopes** (exponents) for memory growth vs `T`, “worst-case” summaries, and JSONL/CBOR ratios

```bash
scripts/scale_streaming_sublinear.zsh
```

**What to look for**

* **Streaming minram verify RSS exponent** `p` should be **≪ 1** (sublinear); the closer to 0, the better.
* **Manifest precheck JSONL exponent** should be **much smaller** than CBOR’s exponent; the largest-T ratio `RSS(cbor)/RSS(jsonl)` should be ≫ 1 if streaming precheck is working.
* For `T ≤ 4,194,304`, the script also runs a **non-stream** baseline to show `nostream/stream` RSS ratios.

> **Linux note:** change `TIME_BIN="/usr/bin/time"` and `TIME_FLAG="-v"`. Adjust the `parse_rss()` grep in the script to match “Maximum resident set size (kbytes)”.

---

## Environment variables (fold backend)

These mirror CLI flags and are picked up by the backend:

* `SEZKP_FOLD_MODE` = `balanced|minram`
* `SEZKP_FOLD_CACHE` = integer
* `SEZKP_WRAP_CADENCE` = integer
* `SEZKP_PROOF_STREAM_PATH` = path to `.cborseq` (streaming proof sidecar)

The test loop sets them inline to ensure backend parameters match the CSV.

---

## Troubleshooting

**`manifest root mismatch` / `CLI manifest root does not match final fold root`**

* Ensure `sezkp-merkle::leaf_hash` byte layout matches the folding leaf gadget exactly.
* Ensure the **parent combiner** in fold equals `BLAKE3(left || right)` (identical to `sezkp-merkle`’s tree logic).

**`unresolved import sezkp_merkle::node_hash`**

* The Merkle crate intentionally exposes high-level APIs and the canonical `leaf_hash`.
  If you need a parent combiner inside fold, either:

  * Re-export a `node_hash` from `sezkp-merkle`, **or**
  * Reimplement the parent combiner locally as `BLAKE3(left || right)` (recommended for decoupling).

**RSS looks linear in T**

* Double-check you’re using `--stream` **and** a `.jsonl` input.
* On macOS, set `RAYON_NUM_THREADS=1`, `MallocNanoZone=0`.
* Verify the script’s RSS parsing matches your OS.

---

## Testing

Run the full workspace tests:

```bash
cargo test --workspace
```

Modules include unit tests (e.g., Merkle odd-promotion, commit/validate roundtrip).

---

## Contributing

Issues and PRs are welcome. If you change any hashing layout (leaf schema or parent combiner), **bump the manifest version** and update both `sezkp-merkle` and the folding gadgets together.

---

## License

Specify your license here (e.g., MIT/Apache-2.0) and include the appropriate `LICENSE` files.

---

## Roadmap / Notes

* Strengthen Leaf/Fold micro-proofs and formalize DS constants
* Expand STARK streaming entry points to take true iterators
* CI jobs to run the scaling script on representative `T` and sanity-check exponents

---

### Appendix: Expected signals from the scaling script

* Streaming/minram **verify** exponent `p` typically in the **0.05–0.3** range on healthy builds.
  Higher than \~0.5 suggests a leak, buffering, or a non-streamed path.
* Manifest precheck:

  * JSONL path: noticeably lower exponent + much smaller absolute RSS
  * CBOR path: higher exponent (loads/decodes full vector)
