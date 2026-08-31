use crate::frontend::br_mode::*;

use serde::Serialize;

pub const BP_MODE_MASK: u8 = 0b11;
// The cfg value is a 7-bit payload carried in the sync `trap_addr` varint:
//   cfg[1:0] = bp_mode, cfg[6:2] = log2(bp_entries / 64).
// Bit 7 of the on-wire byte is the varint terminator, not part of the value.
pub const BP_ENTRY_MASK: u8 = 0b0111_1100;
pub const BP_ENTRY_OFFSET: u8 = 2;
pub const BP_BASE_VALUE: u64 = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecoderRuntimeCfg {
    pub br_mode: BrMode,
    pub bp_entries: u64,
}

impl DecoderRuntimeCfg {
    /// Decode the 7-bit runtime_cfg carried by a Sync Start (already varint-decoded).
    pub fn from_cfg_value(cfg: u64) -> Self {
        let cfg = cfg as u8;
        Self {
            br_mode: BrMode::from((cfg & BP_MODE_MASK) as u64),
            // RTL emits log2(n_entries / 64) in cfg[6:2] (TacitEncoder sSync).
            bp_entries: BP_BASE_VALUE << ((cfg & BP_ENTRY_MASK) >> BP_ENTRY_OFFSET),
        }
    }
}
