pub const SYNC_TYPE_MASK: u8 = 0b1110_0000;
pub const SYNC_TYPE_OFFSET: u8 = 5;

/// Sync subtypes (func3 of a Sync header byte).
///
/// All sync packets share one layout:
/// `header | prv | ctx: varint | trap_addr: varint | target_addr: varint | time: varint`
/// with `from_priv = 0` and an absolute `time`. The `trap_addr` field has no
/// trapping PC to carry for a sync and is reused per subtype:
///   Start  -> runtime_cfg (bp_mode[1:0], log2(bp_entries/64)[6:2])
///   End    -> 0
///   Pause  -> 0 (reserved)
///   Resume -> dropped packet count
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SyncType {
    SyncNone = 0b000,
    SyncStart = 0b001,
    SyncPeriodic = 0b010,
    SyncEnd = 0b011,
    /// Lossy mode: control flow is unknown from `target_addr` (first lost
    /// message's PC) until the following Resume.
    SyncPause = 0b100,
    /// Lossy mode: re-anchors PC/prv/ctx/time after a Pause.
    SyncResume = 0b101,
}

impl SyncType {
    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0b000 => Some(SyncType::SyncNone),
            0b001 => Some(SyncType::SyncStart),
            0b010 => Some(SyncType::SyncPeriodic),
            0b011 => Some(SyncType::SyncEnd),
            0b100 => Some(SyncType::SyncPause),
            0b101 => Some(SyncType::SyncResume),
            _ => None,
        }
    }

    /// Extract the sync type from a full Sync header byte.
    pub fn from_header_byte(header: u8) -> Option<Self> {
        Self::try_from_u8((header & SYNC_TYPE_MASK) >> SYNC_TYPE_OFFSET)
    }
}

impl From<u8> for SyncType {
    fn from(value: u8) -> Self {
        Self::try_from_u8(value)
            .unwrap_or_else(|| panic!("Invalid SyncType value: {:#05b}", value))
    }
}
