//! Streaming witness builder.
//!
//! We serialize each step into a compact, deterministic row encoding:
//!
//! ```text
//! [ input_mv (1B), for each tape: mv+1 (1B), write_flag (1B) ]
//! ```
//!
//! - `input_mv` ∈ {−1,0,+1} is stored as a single signed byte (debug-asserted).
//! - For each tape, `mv` ∈ {−1,0,+1} is stored as `mv+1` ∈ {0,1,2} (1B).
//! - `write_flag` is 1 if there was a write on that step/tape, else 0.
//!
//! This is *not* a full columnar AIR layout yet; it’s a single stream that
//! remains stable across chunking and is easy to hash incrementally.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![warn(
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used
)]

use sezkp_core::{BlockSummary, TapeOp};

/// Per-row encoding length in bytes for a given number of tapes (`tau`).
#[inline]
#[must_use]
pub fn row_size(tau: usize) -> usize {
    // 1 byte input_mv + (2 bytes per tape)
    1 + 2 * tau
}

/// Append the encoded row for one step into `out`, given `tau` tapes.
#[inline]
pub fn encode_step_row(out: &mut Vec<u8>, input_mv: i8, tapes: &[TapeOp]) {
    debug_assert!((-1..=1).contains(&input_mv), "input_mv must be in {{-1,0,1}}");
    out.push(input_mv as u8); // {-1,0,1} → {255,0,1} if violated; guarded by debug_assert

    for op in tapes {
        debug_assert!((-1..=1).contains(&op.mv), "mv must be in {{-1,0,1}}");
        // mv ∈ {-1,0,+1} ⇒ encode in {0,1,2}
        let mv_enc: u8 = (op.mv + 1) as u8;
        let wr_enc: u8 = u8::from(op.write.is_some());
        out.push(mv_enc);
        out.push(wr_enc);
    }
}

/// Stream all step rows of all blocks into a byte sink via a closure.
/// The closure is invoked per *chunk* to keep memory flat.
///
/// # Panics
/// Panics if `chunk_rows == 0` or if `tau` varies across blocks.
pub fn stream_rows<F: FnMut(&[u8])>(blocks: &[BlockSummary], chunk_rows: usize, mut emit_chunk: F) {
    if blocks.is_empty() {
        return;
    }
    assert!(chunk_rows > 0, "chunk_rows must be > 0");

    let tau = blocks[0].windows.len();
    let row_len = row_size(tau);
    let chunk_bytes = row_len * chunk_rows;

    let mut buf = Vec::with_capacity(chunk_bytes);
    let mut rows_in_buf = 0usize;

    for b in blocks {
        debug_assert_eq!(b.windows.len(), tau, "tau should be constant across blocks");
        for step in &b.movement_log.steps {
            encode_step_row(&mut buf, step.input_mv, &step.tapes);
            rows_in_buf += 1;
            if rows_in_buf == chunk_rows {
                emit_chunk(&buf);
                buf.clear();
                rows_in_buf = 0;
            }
        }
    }

    if !buf.is_empty() {
        emit_chunk(&buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sezkp_core::{MovementLog, StepProjection, Window};

    #[test]
    fn row_size_ok() {
        assert_eq!(row_size(0), 1);
        assert_eq!(row_size(1), 3);
        assert_eq!(row_size(2), 5);
    }

    #[test]
    fn stream_rows_chunks_and_remainder() {
        // Two blocks, tau=1, total 5 steps, chunk_rows=2 → emits 2 chunks then remainder.
        let mk_step = |mv: i8| StepProjection { input_mv: mv, tapes: vec![TapeOp { write: None, mv: 0 }] };
        let b1 = BlockSummary {
            version: 1,
            block_id: 1,
            step_lo: 1,
            step_hi: 3,
            ctrl_in: 0,
            ctrl_out: 0,
            in_head_in: 0,
            in_head_out: 0,
            windows: vec![Window { left: 0, right: 0 }],
            head_in_offsets: vec![0],
            head_out_offsets: vec![0],
            movement_log: MovementLog { steps: vec![mk_step(-1), mk_step(0), mk_step(1)] },
            pre_tags: vec![[0; 16]; 1],
            post_tags: vec![[0; 16]; 1],
        };
        let b2 = BlockSummary {
            version: 1,
            block_id: 2,
            step_lo: 4,
            step_hi: 5,
            ctrl_in: 0,
            ctrl_out: 0,
            in_head_in: 0,
            in_head_out: 0,
            windows: vec![Window { left: 0, right: 0 }],
            head_in_offsets: vec![0],
            head_out_offsets: vec![0],
            movement_log: MovementLog { steps: vec![mk_step(0), mk_step(1)] },
            pre_tags: vec![[0; 16]; 1],
            post_tags: vec![[0; 16]; 1],
        };

        let mut chunks = Vec::new();
        stream_rows(&[b1, b2], 2, |c| chunks.push(c.to_vec()));

        assert_eq!(chunks.len(), 3);
        // Each row is 1 (input_mv) + 2*tau = 3 bytes for tau=1.
        assert_eq!(chunks[0].len(), 2 * row_size(1));
        assert_eq!(chunks[1].len(), 2 * row_size(1));
        assert_eq!(chunks[2].len(), 1 * row_size(1));
    }
}
