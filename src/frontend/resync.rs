//! Decoding a trace whose beginning was lost, e.g. a DMA ring buffer that wrapped.
//!
//! The stream has no escaping, so the decoder cannot just look for a header byte.
//! It finds the first Sync Periodic checkpoint that passes every check below, and
//! rewrites the stream to start there with an equivalent Start packet, so the normal
//! decoder (which walks and verifies every later packet and checkpoint) takes over:
//!
//! 1. header byte is Sync Periodic (`0x56`);
//! 2. prv byte has its `0b10` check pattern, `from_priv = 0` and a valid `to_priv`;
//! 3. ctx / trap_addr / target_addr / time are well-formed varints;
//! 4. trap_addr carries the periodic magic in its upper bits;
//! 5. every packet after it parses up to the next Periodic, whose sequence number is
//!    one higher (or the stream ends cleanly before another checkpoint).

use anyhow::{anyhow, Result};
use log::info;
use std::io::{Cursor, ErrorKind};

use crate::frontend::packet::{Packet, PacketReader, SubFunc3};
use crate::frontend::sync_type::{SyncType, PERIODIC_HEADER, PERIODIC_MAGIC};

/// Header byte of a Sync Start packet; its trap_addr carries runtime_cfg.
const START_HEADER: u8 = 0x36;
/// runtime_cfg of the parallel encoder (always 0), as its one-byte varint.
const START_RUNTIME_CFG: u8 = 0x80;
const MAX_VARINT: usize = 10;

/// Length of the varint starting at `bytes[0]` (terminated by bit 7), if well formed.
fn varint_len(bytes: &[u8]) -> Option<usize> {
    bytes.iter().take(MAX_VARINT).position(|b| b & 0x80 != 0).map(|i| i + 1)
}

fn varint_value(bytes: &[u8]) -> u64 {
    bytes.iter().rev().fold(0u64, |acc, b| (acc << 7) | u64::from(b & 0x7f))
}

/// A Sync Periodic found at some offset: the raw bytes of each field, for rewriting.
struct Checkpoint<'a> {
    prv: u8,
    ctx: &'a [u8],
    target: &'a [u8],
    time: &'a [u8],
    seq: u64,
    len: usize,
}

/// Checks 1-4 at `bytes[off..]`.
fn parse_checkpoint(bytes: &[u8], off: usize) -> Option<Checkpoint<'_>> {
    let b = bytes.get(off..)?;
    if *b.first()? != PERIODIC_HEADER {
        return None;
    }
    let prv = *b.get(1)?;
    let to_prv = (prv >> 3) & 0b111;
    if prv >> 6 != 0b10 || prv & 0b111 != 0 || !matches!(to_prv, 0 | 1 | 3) {
        return None;
    }
    let mut pos = 2;
    let mut field = |pos: &mut usize| -> Option<&[u8]> {
        let n = varint_len(b.get(*pos..)?)?;
        let f = &b[*pos..*pos + n];
        *pos += n;
        Some(f)
    };
    let ctx = field(&mut pos)?;
    let trap = field(&mut pos)?;
    let target = field(&mut pos)?;
    let time = field(&mut pos)?;
    let trap_addr = varint_value(trap);
    if trap_addr >> 16 != PERIODIC_MAGIC {
        return None;
    }
    Some(Checkpoint { prv, ctx, target, time, seq: trap_addr & 0xffff, len: pos })
}

/// Check 5: everything after the checkpoint parses, up to the next one (with the
/// next sequence number) or a clean end of stream.
fn structurally_valid_after(bytes: &[u8], cp_end: usize, seq: u64) -> bool {
    let mut reader = PacketReader::new(Cursor::new(&bytes[cp_end..]));
    loop {
        let mut packet = Packet::new();
        match reader.read_packet(&mut packet) {
            Ok(_) => {}
            Err(e) => {
                // a clean end of stream is acceptable; any other error is not
                return e.downcast_ref::<std::io::Error>().map_or(false, |io| io.kind() == ErrorKind::UnexpectedEof)
                    && reader.stream.position() as usize == bytes.len() - cp_end;
            }
        }
        if let SubFunc3::SyncType(SyncType::SyncPeriodic) = packet.func3 {
            return packet.from_address >> 16 == PERIODIC_MAGIC && packet.from_address & 0xffff == (seq + 1) & 0xffff;
        }
    }
}

/// Returns the stream starting at the first valid checkpoint, with that checkpoint
/// turned into a Start, plus the byte offset it was found at.
pub fn trim_to_first_periodic(bytes: &[u8]) -> Result<(Vec<u8>, usize)> {
    for off in 0..bytes.len() {
        let Some(cp) = parse_checkpoint(bytes, off) else { continue };
        if !structurally_valid_after(bytes, off + cp.len, cp.seq) {
            continue;
        }
        let mut out = Vec::with_capacity(bytes.len() - off + 4);
        out.push(START_HEADER);
        out.push(cp.prv);
        out.extend_from_slice(cp.ctx);
        out.push(START_RUNTIME_CFG);
        out.extend_from_slice(cp.target);
        out.extend_from_slice(cp.time);
        out.extend_from_slice(&bytes[off + cp.len..]);
        info!("resync: first valid Sync Periodic (seq {}) at byte {} of {}", cp.seq, off, bytes.len());
        return Ok((out, off));
    }
    Err(anyhow!("resync: no valid Sync Periodic checkpoint in {} bytes", bytes.len()))
}

/// Writes `path.resync`: the trace trimmed to its first valid checkpoint, with that
/// checkpoint rewritten as an equivalent Start. Returns the new path.
pub fn rewrite_trimmed_trace_from_first_periodic(path: &str) -> Result<String> {
    let bytes = std::fs::read(path)?;
    let (out, _) = trim_to_first_periodic(&bytes)?;
    let out_path = format!("{}.resync", path);
    std::fs::write(&out_path, out)?;
    Ok(out_path)
}
