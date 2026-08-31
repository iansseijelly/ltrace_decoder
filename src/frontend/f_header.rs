use crate::frontend::c_header::CHeader;

pub const F_HEADER_MASK: u8 = 0b0001_1100;
pub const FHEADER_OFFSET: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FHeader {
    FTb = 0b000,   // taken branch
    FNt = 0b001,   // non taken branch
    FUj = 0b010,   // uninferable jump
    FIj = 0b011,   // inferable jump
    FTrap = 0b100, // trapping happened - could be interrupt or exception
    FSync = 0b101, // a synchronization packet
    FRes1 = 0b110, // this packets report a context change
    FRes2 = 0b111, // reserved for now
}

impl FHeader {
    /// Decode the 3-bit f_header field; `None` for the reserved codes 110/111.
    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0b000 => Some(FHeader::FTb),
            0b001 => Some(FHeader::FNt),
            0b010 => Some(FHeader::FUj),
            0b011 => Some(FHeader::FIj),
            0b100 => Some(FHeader::FTrap),
            0b101 => Some(FHeader::FSync),
            _ => None,
        }
    }
}

impl From<u8> for FHeader {
    fn from(value: u8) -> Self {
        Self::try_from_u8(value)
            .unwrap_or_else(|| panic!("Invalid FHeader value: {:#05b}", value))
    }
}

impl From<CHeader> for FHeader {
    fn from(c_header: CHeader) -> Self {
        match c_header {
            CHeader::CTb => FHeader::FTb,
            CHeader::CNt => FHeader::FNt,
            CHeader::CIj => FHeader::FIj,
            CHeader::CNa => panic!("CNa should not be converted to FHeader"),
        }
    }
}
