use anyhow::{anyhow, bail, Result};
use log::trace;
use std::io::Read;

use crate::common::prv::*;
use crate::frontend::c_header::*;
use crate::frontend::f_header::*;
use crate::frontend::runtime_cfg::*;
use crate::frontend::sync_type::*;
use crate::frontend::trap_type::*;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SubFunc3 {
    None,
    TrapType(TrapType),
    SyncType(SyncType),
}

/// One decoded packet. Field meaning depends on `f_header`/`func3`:
///
/// * `from_address` holds the on-wire `trap_addr` varint. For Trap packets that
///   is the trapping PC (`>> 1`). Sync packets have no trapping PC and reuse the
///   field: Start -> runtime_cfg, End/Pause -> 0, Resume -> dropped packet count.
/// * `target_address` is `>> 1` and either absolute (Sync) or XORed against the
///   resolving PC (UJ, Trap).
/// * `timestamp` is a delta for everything except Sync packets, where it is the
///   absolute cycle count.
#[derive(Debug, Clone)]
pub struct Packet {
    pub is_compressed: bool,
    pub c_header: CHeader,
    pub f_header: FHeader,
    pub func3: SubFunc3,
    pub target_address: u64,
    pub from_address: u64,
    pub target_prv: Prv,
    pub _from_ctx: u64, // used for debugging only
    pub target_ctx: u64,
    pub from_prv: Prv,
    pub timestamp: u64,
}

// Initialize a packet with default values
impl Packet {
    pub fn new() -> Packet {
        Packet {
            is_compressed: false,
            c_header: CHeader::CNa,
            f_header: FHeader::FRes1,
            func3: SubFunc3::None,
            target_address: 0,
            from_address: 0,
            target_prv: Prv::PrvUser,
            _from_ctx: 0,
            target_ctx: 0,
            from_prv: Prv::PrvUser,
            timestamp: 0,
        }
    }

    pub fn sync_type(&self) -> Option<SyncType> {
        match self.func3 {
            SubFunc3::SyncType(t) if self.f_header == FHeader::FSync => Some(t),
            _ => None,
        }
    }
}

fn read_u8<R: Read>(stream: &mut R) -> Result<u8> {
    let mut buf = [0u8; 1];
    stream.read_exact(&mut buf)?;
    Ok(buf[0])
}

const VAR_MASK: u8 = 0b1000_0000;
const VAR_LAST: u8 = 0b1000_0000;
const VAR_OFFSET: u8 = 7;
const VAR_VAL_MASK: u8 = 0b0111_1111;

pub struct PacketReader<R: Read> {
    pub stream: R,
    pub compressed_packet_count: u64,
    pub full_packet_count: u64,
}

impl<R: Read> PacketReader<R> {
    pub fn new(stream: R) -> Self {
        Self {
            stream,
            compressed_packet_count: 0,
            full_packet_count: 0,
        }
    }

    /// Read one packet. Returns the number of bytes consumed. An `Err` wrapping
    /// `std::io::ErrorKind::UnexpectedEof` on the very first byte means a clean
    /// end of stream.
    pub fn read_packet(&mut self, packet: &mut Packet) -> Result<u64> {
        let first_byte = read_u8(&mut self.stream)?;
        // trace!("first_byte: {:08b}", first_byte);
        let mut bytes_read = 1;
        let c_header = CHeader::from(first_byte & C_HEADER_MASK);
        match c_header {
            CHeader::CTb | CHeader::CNt | CHeader::CIj => {
                packet.timestamp = (first_byte & C_TIMESTAMP_MASK) as u64 >> 2;
                packet.f_header = FHeader::from(c_header.clone());
                packet.c_header = c_header.clone();
                packet.func3 = SubFunc3::None;
                packet.is_compressed = true;
                self.compressed_packet_count += 1;
            }
            CHeader::CNa => {
                packet.is_compressed = false;
                self.full_packet_count += 1;
                let f_header = FHeader::try_from_u8((first_byte & F_HEADER_MASK) >> FHEADER_OFFSET)
                    .ok_or_else(|| anyhow!("reserved f_header in header byte {:#04x}", first_byte))?;
                match f_header {
                    FHeader::FTb | FHeader::FNt | FHeader::FIj => {
                        let (timestamp, count) = read_varint(&mut self.stream)?;
                        packet.timestamp = timestamp;
                        bytes_read += count;
                        packet.f_header = f_header;
                        packet.c_header = CHeader::CNa;
                        packet.func3 = SubFunc3::None;
                    }
                    FHeader::FUj => {
                        let (target_address, count) = read_varint(&mut self.stream)?;
                        packet.target_address = target_address;
                        bytes_read += count;
                        let (timestamp, count) = read_varint(&mut self.stream)?;
                        packet.timestamp = timestamp;
                        bytes_read += count;
                        packet.f_header = f_header;
                        packet.c_header = CHeader::CNa;
                        packet.func3 = SubFunc3::None;
                    }
                    FHeader::FSync => {
                        bytes_read += read_sync_body(first_byte, &mut self.stream, packet)?;
                    }
                    FHeader::FTrap => {
                        let trap_type =
                            TrapType::from((first_byte & TRAP_TYPE_MASK) >> TRAP_TYPE_OFFSET);
                        packet.func3 = SubFunc3::TrapType(trap_type);
                        let (from_prv, target_prv) = read_prv(&mut self.stream)?;
                        packet.from_prv = from_prv;
                        bytes_read += 1;
                        packet.target_prv = target_prv;
                        if trap_type == TrapType::TReturn && target_prv == Prv::PrvUser {
                            let (target_ctx, count) = read_varint(&mut self.stream)?;
                            packet.target_ctx = target_ctx;
                            bytes_read += count;
                        }
                        let (from_address, count) = read_varint(&mut self.stream)?;
                        packet.from_address = from_address;
                        bytes_read += count;
                        let (target_address, count) = read_varint(&mut self.stream)?;
                        packet.target_address = target_address;
                        bytes_read += count;
                        let (timestamp, count) = read_varint(&mut self.stream)?;
                        packet.timestamp = timestamp;
                        bytes_read += count;
                        packet.f_header = f_header;
                        packet.c_header = CHeader::CNa;
                    }
                    FHeader::FRes1 | FHeader::FRes2 => {
                        bail!("reserved f_header {:?} in header byte {:#04x}", f_header, first_byte);
                    }
                }
            }
        }
        Ok(bytes_read)
    }
}

/// Parse the body shared by every Sync subtype, after the header byte:
/// `prv | ctx: varint | trap_addr: varint | target_addr: varint | time: varint`.
/// Returns the number of body bytes consumed (header byte not included).
fn read_sync_body<R: Read>(first_byte: u8, stream: &mut R, packet: &mut Packet) -> Result<u64> {
    let sync_type = SyncType::from_header_byte(first_byte)
        .ok_or_else(|| anyhow!("reserved sync type in header byte {:#04x}", first_byte))?;
    if sync_type == SyncType::SyncNone {
        bail!("SyncNone (func3 = 000) is never emitted; header byte {:#04x}", first_byte);
    }
    let mut bytes_read = 0;
    packet.is_compressed = false;
    packet.c_header = CHeader::CNa;
    packet.f_header = FHeader::FSync;
    packet.func3 = SubFunc3::SyncType(sync_type);

    let (from_prv, target_prv) = read_prv(stream)?;
    bytes_read += 1;
    if from_prv != Prv::PrvUser {
        bail!("sync {:?}: from_prv must be 0, got {:?}", sync_type, from_prv);
    }
    packet.from_prv = from_prv;
    packet.target_prv = target_prv;

    let (target_ctx, count) = read_varint(stream)?;
    packet.target_ctx = target_ctx;
    bytes_read += count;

    // trap_addr position: runtime_cfg (Start), 0 (End/Pause), dropped (Resume)
    let (trap_addr, count) = read_varint(stream)?;
    packet.from_address = trap_addr;
    bytes_read += count;

    let (target_address, count) = read_varint(stream)?;
    packet.target_address = target_address;
    bytes_read += count;

    let (timestamp, count) = read_varint(stream)?;
    packet.timestamp = timestamp;
    bytes_read += count;

    trace!("sync {:?}: {:?}", sync_type, packet);
    Ok(bytes_read)
}

fn read_varint<R: Read>(stream: &mut R) -> Result<(u64, u64)> {
    let mut scratch = [0u8; 10];
    let mut count = 0usize;
    loop {
        let byte = read_u8(stream)?;
        if count == scratch.len() {
            return Err(anyhow!("varint exceeded maximum length"));
        }
        scratch[count] = byte;
        count += 1;
        if byte & VAR_MASK == VAR_LAST {
            break;
        }
    }
    let mut value: u64 = 0;
    for &byte in scratch[..count].iter().rev() {
        value = (value << VAR_OFFSET) | u64::from(byte & VAR_VAL_MASK);
    }
    Ok((value, count as u64))
}

fn read_prv<R: Read>(stream: &mut R) -> Result<(Prv, Prv)> {
    let result = read_u8(stream)?;
    let from_prv = Prv::from((result & 0b111) as u64);
    let target_prv = Prv::from(((result >> 3) & 0b111) as u64);
    if (result >> 6) & 0b11 != 0b10 {
        bail!("prv byte {:#04x}: check pattern [7:6] must be 0b10", result);
    }
    Ok((from_prv, target_prv))
}

/// Derive the runtime configuration from a decoded Sync Start packet.
pub fn runtime_cfg_from_start(packet: &Packet) -> Result<DecoderRuntimeCfg> {
    if packet.sync_type() != Some(SyncType::SyncStart) {
        bail!("runtime_cfg is only carried by Sync Start, got {:?}", packet.func3);
    }
    if packet.from_address > 0x7F {
        bail!("Sync Start runtime_cfg {:#x} does not fit in 7 bits", packet.from_address);
    }
    Ok(DecoderRuntimeCfg::from_cfg_value(packet.from_address))
}

/// Read the first packet of a trace, which must be a Sync Start, and return it
/// with the runtime configuration it carries.
pub fn read_first_packet<R: Read>(stream: &mut R) -> Result<(Packet, DecoderRuntimeCfg)> {
    let mut packet = Packet::new();
    let first_byte = read_u8(stream)?;
    trace!("first_byte: {:08b}", first_byte);

    let c_header = CHeader::from(first_byte & C_HEADER_MASK);
    if c_header != CHeader::CNa {
        return Err(anyhow!("first packet must be CNa, got {:?}", c_header));
    }
    let f_header = FHeader::try_from_u8((first_byte & F_HEADER_MASK) >> FHEADER_OFFSET);
    if f_header != Some(FHeader::FSync) {
        return Err(anyhow!("first packet must be FSync, got {:?}", f_header));
    }
    let sync_type = SyncType::from_header_byte(first_byte);
    if sync_type != Some(SyncType::SyncStart) {
        return Err(anyhow!("first packet must be SYNC_START, got {:?}", sync_type));
    }

    read_sync_body(first_byte, stream, &mut packet)?;
    let runtime_cfg = runtime_cfg_from_start(&packet)?;
    Ok((packet, runtime_cfg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontend::br_mode::BrMode;
    use std::io::Cursor;

    fn read_one(bytes: &[u8]) -> (Packet, u64) {
        let mut reader = PacketReader::new(Cursor::new(bytes.to_vec()));
        let mut packet = Packet::new();
        let n = reader.read_packet(&mut packet).expect("packet should parse");
        assert_eq!(n as usize, bytes.len(), "must consume exactly the packet");
        (packet, n)
    }

    #[test]
    fn varint_zero_is_0x80() {
        let mut c = Cursor::new(vec![0x80u8]);
        assert_eq!(read_varint(&mut c).unwrap(), (0, 1));
    }

    #[test]
    fn varint_multi_byte() {
        // 1234 = 0x4D2 -> 0x52, 0x89
        let mut c = Cursor::new(vec![0x52u8, 0x89]);
        assert_eq!(read_varint(&mut c).unwrap(), (1234, 2));
        // 1_000_000 = 0xF4240 -> 0x40 0x04 0xBD
        let mut c = Cursor::new(vec![0x40u8, 0x04, 0xBD]);
        assert_eq!(read_varint(&mut c).unwrap(), (1_000_000, 3));
    }

    #[test]
    fn start_cfg_ignores_varint_terminator() {
        // Start in S, ASID 0, cfg = bp_mode 2 | log2(1024/64)=4 -> 0b0010010 = 0x12 -> byte 0x92
        // pc 0x10AB4 >> 1 = 0x855A -> 5A 0A 82 ; time 0
        let bytes = [0x36u8, 0x88, 0x80, 0x92, 0x5A, 0x0A, 0x82, 0x80];
        let (packet, cfg) = read_first_packet(&mut Cursor::new(bytes.to_vec())).unwrap();
        assert_eq!(packet.sync_type(), Some(SyncType::SyncStart));
        assert_eq!(packet.target_prv, Prv::PrvSupervisor);
        assert_eq!(packet.target_address << 1, 0x10AB4);
        assert_eq!(cfg.br_mode, BrMode::BrPredict);
        // erratum 8.1: this used to decode as (32 + 4) * 64; the field is log2(n/64)
        assert_eq!(cfg.bp_entries, 1024);
    }

    #[test]
    fn pause_example() {
        // Pause, S-mode, ASID 0, pause_pc 0x10AB4, time 1_000_000
        let bytes = [0x96u8, 0x88, 0x80, 0x80, 0x5A, 0x0A, 0x82, 0x40, 0x04, 0xBD];
        let (p, _) = read_one(&bytes);
        assert_eq!(p.sync_type(), Some(SyncType::SyncPause));
        assert_eq!(p.target_prv, Prv::PrvSupervisor);
        assert_eq!(p.from_prv, Prv::PrvUser);
        assert_eq!(p.target_ctx, 0);
        assert_eq!(p.from_address, 0);
        assert_eq!(p.target_address << 1, 0x10AB4);
        assert_eq!(p.timestamp, 1_000_000);
    }

    #[test]
    fn resume_example() {
        // Resume, U-mode, ASID 117, 1234 dropped, pc 0x10C00, time 1_004_096
        let bytes = [0xB6u8, 0x80, 0xF5, 0x52, 0x89, 0x00, 0x0C, 0x82, 0x40, 0x24, 0xBD];
        let (p, _) = read_one(&bytes);
        assert_eq!(p.sync_type(), Some(SyncType::SyncResume));
        assert_eq!(p.target_prv, Prv::PrvUser);
        assert_eq!(p.target_ctx, 117);
        assert_eq!(p.from_address, 1234);
        assert_eq!(p.target_address << 1, 0x10C00);
        assert_eq!(p.timestamp, 1_004_096);
    }

    #[test]
    fn end_example() {
        let bytes = [0x76u8, 0x88, 0x80, 0x80, 0x5A, 0x0A, 0x82, 0x80];
        let (p, _) = read_one(&bytes);
        assert_eq!(p.sync_type(), Some(SyncType::SyncEnd));
        assert_eq!(p.from_address, 0);
    }

    #[test]
    fn start_mid_stream_parses() {
        // read_packet no longer rejects Start; the decoder's grammar decides.
        let bytes = [0x36u8, 0x88, 0x80, 0x80, 0x5A, 0x0A, 0x82, 0x80];
        let (p, _) = read_one(&bytes);
        assert_eq!(p.sync_type(), Some(SyncType::SyncStart));
    }

    #[test]
    fn reserved_codes_are_errors_not_panics() {
        for header in [0xD6u8, 0xF6, 0x16 /* SyncNone */, 0x1A /* f=110 */, 0x1E /* f=111 */] {
            let mut reader = PacketReader::new(Cursor::new(vec![header, 0x88, 0x80, 0x80, 0x80, 0x80]));
            let mut packet = Packet::new();
            assert!(reader.read_packet(&mut packet).is_err(), "header {:#04x}", header);
        }
    }

    #[test]
    fn bad_prv_check_pattern_is_error() {
        let bytes = [0x96u8, 0x08, 0x80, 0x80, 0x80, 0x80];
        let mut reader = PacketReader::new(Cursor::new(bytes.to_vec()));
        let mut packet = Packet::new();
        assert!(reader.read_packet(&mut packet).is_err());
    }

    #[test]
    fn eof_on_first_byte_is_unexpected_eof() {
        let mut reader = PacketReader::new(Cursor::new(Vec::<u8>::new()));
        let mut packet = Packet::new();
        let err = reader.read_packet(&mut packet).unwrap_err();
        let io = err.downcast_ref::<std::io::Error>().expect("io error");
        assert_eq!(io.kind(), std::io::ErrorKind::UnexpectedEof);
    }
}
