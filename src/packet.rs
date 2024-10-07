use std::fs::File;
use std::io::{Read, BufReader};

const C_HEADER_MASK: u8 = 0b0000_0011;
const C_TIMESTAMP_MASK: u8 = 0b1111_1100;
const F_HEADER_MASK: u8 = 0b0001_1100;

const VAR_MASK: u8 = 0b1000_0000;
const VAR_CONT: u8 = 0b0;
const VAR_LAST: u8 = 0b1;
const VAR_OFFSET: u8 = 7;
const VAR_VAL_MASK: u8 = 0b0111_1111;

#[derive(Debug)]
enum CHeader {
    CTb = 0b00, // taken branch
    CNt = 0b01, // not taken branch
    CNa = 0b10, // not applicable
    CIj = 0b11, // inferable jump
}

impl From<u8> for CHeader {
    fn from(value: u8) -> Self {
        match value {
            0b00 => CHeader::CTb,
            0b01 => CHeader::CNt,
            0b10 => CHeader::CNa,
            0b11 => CHeader::CIj,
            _ => panic!("Invalid CHeader value"),
        }
    }
}

#[derive(Debug)]
enum FHeader {
    FTb = 0b000,   // taken branch
    FNt = 0b001,   // non taken branch
    FUj = 0b010,   // uninferable jump
    FIj = 0b011,   // inferable jump
    FTr = 0b100, // trapping happened - could be interrupt or exception
    FSync = 0b101, // a synchronization packet
    FVal = 0b110,   // this packets report a certain value upon request
    FRes = 0b111,   // reserved for now
}

impl From<u8> for FHeader {
    fn from(value: u8) -> Self {
        match value {
            0b000 => FHeader::FTb,
            0b001 => FHeader::FNt,
            0b010 => FHeader::FUj,
            0b011 => FHeader::FIj,
            0b100 => FHeader::FTr,
            0b101 => FHeader::FSync,
            0b110 => FHeader::FVal,
            0b111 => FHeader::FRes,
            _ => panic!("Invalid FHeader value"),
        }
    }
}

impl From<CHeader> for FHeader {
    fn from(c_header: CHeader) -> Self {
        match c_header {
            CHeader::CTb  => FHeader::FTb,
            CHeader::CNt  => FHeader::FNt,
            CHeader::CIj  => FHeader::FIj,
            CHeader::CNa => panic!("CNa should not be converted to FHeader"),
        }
    }
}

#[derive(Debug)]
pub struct Packet {
    c_header: CHeader,
    f_header: FHeader,
    address: u64,
    timestamp: u64,
}

// Initialize a packet with default values
impl Packet {
    fn new() -> Packet {
        Packet {
            c_header: CHeader::CNa,
            f_header: FHeader::FRes,
            address: 0,
            timestamp: 0,
        }
    }
}

fn read_u8(stream: &mut BufReader<File>) -> Result<u8, Box<dyn std::error::Error>> {
    let mut buf = [0u8; 1];
    stream.read_exact(&mut buf)?;
    Ok(buf[0])
}

fn read_varint(stream: &mut BufReader<File>) -> Result<u64, Box<dyn std::error::Error>> {
    let mut result = Vec::new();
    loop {
        let byte = read_u8(stream)?;
        result.push(byte);
        if byte & VAR_MASK == VAR_LAST { break; }
    }
    Ok(result.iter().rev().fold(0, |acc, &x| (acc << VAR_OFFSET) | (x & VAR_VAL_MASK) as u64))
} 

pub fn read_packet(stream: &mut BufReader<File>) -> Result<Packet, Box<dyn std::error::Error>> {
    let mut packet = Packet::new();
    let first_byte = read_u8(stream)?;
    let c_header = CHeader::from(first_byte & C_HEADER_MASK);
    match c_header {
        CHeader::CTb | CHeader::CNt | CHeader::CIj => {
            packet.timestamp = (first_byte & C_TIMESTAMP_MASK) as u64;
            packet.c_header = c_header;
            packet.f_header = FHeader::from(c_header);
        }
        CHeader::CNa => {
            let f_header = FHeader::from(first_byte & F_HEADER_MASK);
            match f_header {
                FHeader::FTb | FHeader::FNt | FHeader::FIj => {
                    let timestamp = read_varint(stream)?;
                    packet.timestamp = timestamp;
                    packet.f_header = f_header;
                    packet.c_header = CHeader::CNa;
                }
                FHeader::FUj => {
                    let timestamp = read_varint(stream)?;
                    let address = read_varint(stream)?;
                    packet.timestamp = timestamp;
                    packet.address = address;
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