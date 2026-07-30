use std::fs::File;
use std::io::{Read, BufReader};
use anyhow::Result;
use log::trace;

use crate::frontend::c_header::*;
use crate::frontend::f_header::*;
use crate::frontend::trap_type::*;

#[derive(Debug)]
pub struct Packet {
    pub is_compressed: bool,
    pub c_header: CHeader,
    pub f_header: FHeader,
    pub trap_type: TrapType,
    pub target_address: u64,
    pub from_address: u64,
    pub ctx: u64,
    pub timestamp: u64,
}

// Initialize a packet with default values
impl Packet {
    fn new() -> Packet {
        Packet {
            is_compressed: false,
            c_header: CHeader::CNa,
            f_header: FHeader::FRes,
            trap_type: TrapType::TNone,
            target_address: 0,
            from_address: 0,
            ctx: 0,
            timestamp: 0,
        }
    }
}

fn read_u8(stream: &mut BufReader<File>) -> Result<u8> {
    let mut buf = [0u8; 1];
    stream.read_exact(&mut buf)?;
    Ok(buf[0])
}

const VAR_MASK: u8 = 0b1000_0000;
const VAR_LAST: u8 = 0b1000_0000;
const VAR_OFFSET: u8 = 7;
const VAR_VAL_MASK: u8 = 0b0111_1111;

fn read_varint(stream: &mut BufReader<File>) -> Result<u64> {
    let mut result = Vec::new();
    loop {
        let byte = read_u8(stream)?;
        trace!("byte: {:08b}", byte);
        result.push(byte);
        if byte & VAR_MASK == VAR_LAST { break; }
    }
    Ok(result.iter().rev().fold(0, |acc, &x| (acc << VAR_OFFSET) | (x & VAR_VAL_MASK) as u64))
} 

pub fn read_packet(stream: &mut BufReader<File>) -> Result<Packet> {
    let mut packet = Packet::new();
    let first_byte = read_u8(stream)?;
    trace!("first_byte: {:08b}", first_byte);
    let c_header = CHeader::from(first_byte & C_HEADER_MASK);
    match c_header {
        CHeader::CTb | CHeader::CNt | CHeader::CIj => {
            packet.timestamp = (first_byte & C_TIMESTAMP_MASK) as u64 >> 2;
            packet.f_header = FHeader::from(c_header.clone());
            packet.c_header = c_header.clone();
            packet.is_compressed = true;
        }
        CHeader::CNa => {
            packet.is_compressed = false;
            let f_header = FHeader::from((first_byte & F_HEADER_MASK) >> FHEADER_OFFSET);
            // println!("f_header: {:?}", f_header);
            match f_header {
                FHeader::FTb | FHeader::FNt | FHeader::FIj => {
                    packet.timestamp = read_varint(stream)?;
                    packet.f_header = f_header;
                    packet.c_header = CHeader::CNa;
                }
                FHeader::FUj => {
                    packet.target_address = read_varint(stream)?;
                    packet.timestamp = read_varint(stream)?;
                    packet.f_header = f_header;
                    packet.c_header = CHeader::CNa;
                }
                FHeader::FSync => {
                    // Encoder layout (trace_encoder_l.cc::_generate_sync_packet):
                    //   header byte, prv byte, ctx (varlen),
                    //   runtime_cfg byte (S_START only), target (varlen), timestamp (varlen).
                    // The top 3 bits of the header carry the sync_type.
                    let sync_type = (first_byte & TRAP_TYPE_MASK) >> TRAP_TYPE_OFFSET;
                    let _prv = read_u8(stream)?;              // prv: from | to<<3 | 0b10<<6
                    packet.ctx = read_varint(stream)?;
                    if sync_type == 0b001 {                   // S_START carries runtime cfg
                        let _runtime_cfg = read_u8(stream)?;  // br_mode | (bp_size/64)<<2
                    }
                    packet.target_address = read_varint(stream)?;
                    packet.timestamp = read_varint(stream)?;
                    packet.f_header = f_header;
                    packet.c_header = CHeader::CNa;
                }
                FHeader::FTrap => {
                    // Encoder layout (trace_encoder_l.cc::_generate_trap_packet):
                    //   header byte, prv byte, ctx (varlen -- ONLY when returning to
                    //   U mode on a trap-return), from_address, target, timestamp.
                    let trap_type_raw = (first_byte & TRAP_TYPE_MASK) >> TRAP_TYPE_OFFSET;
                    let prv = read_u8(stream)?;
                    let to_priv = (prv >> 3) & 0x7;           // ingress_0.priv (destination)
                    if to_priv == 0 && trap_type_raw == 0b100 { // P_U && T_TRAP_RETURN
                        packet.ctx = read_varint(stream)?;
                    }
                    packet.from_address = read_varint(stream)?;
                    packet.target_address = read_varint(stream)?;
                    packet.timestamp = read_varint(stream)?;
                    packet.trap_type = TrapType::from(trap_type_raw);
                    packet.f_header = f_header;
                    packet.c_header = CHeader::CNa;
                }
                _ => {
                    println!("Invalid FHeader value: {}", first_byte);
                }
            }
        }
    }
    Ok(packet)
}

pub fn read_first_packet(stream: &mut BufReader<File>) -> Result<Packet> {
    // call read_packet
    let packet = read_packet(stream)?;
    assert!(packet.f_header == FHeader::FSync);
    assert!(packet.c_header == CHeader::CNa);
    Ok(packet)
}
