extern crate clap;
extern crate object;
extern crate capstone;

mod packet;
use std::fs::File;
use std::io::{Read, Write, BufReader, BufWriter};
use std::collections::HashMap;
use clap::Parser;
use capstone::prelude::*;
use capstone::arch::riscv::{ArchMode, ArchExtraMode};
use capstone::Insn;
use object::{Object, ObjectSection};

const BRANCH_OPCODES: &[&str] = &["beq", "bge", "bgeu", "blt", "bltu", "bne", "c.beqz", "c.bnez", "c.bltz", "c.bgez"];
const JUMP_OPCODES: &[&str] = &["jal", "jalr", "c.j", "c.jal", "c.jr", "c.jalr"];

#[derive(Parser)]
#[command(name = "trace-decoder", version = "0.1.0", about = "Decode trace files")]
struct Args {
    #[arg(short, long)]
    encoded_trace: String,
    #[arg(short, long)]
    elf: String,
    #[arg(short, long, default_value_t = false)]
    verbose: bool,
    #[arg(short, long, default_value_t = String::from("trace.dump"))]
    decoded_trace: String,
}

fn refund_addr(addr: u64) -> u64 {
    addr << 1
}

// FIXME: hacky way to get the offset operand, always the last one
fn compute_offset(insn: &Insn) -> i64 {
    let offset = insn.op_str().unwrap().split(",").last().unwrap();
    let offset_value: i64;
    if offset.starts_with(" -0x") {
        offset_value = i64::from_str_radix(&offset[4..], 16).unwrap() * -1;
    } else if offset.starts_with(" 0x") {
        offset_value = i64::from_str_radix(&offset[3..], 16).unwrap();
    } else if offset.starts_with(" -") {
        offset_value = i64::from_str_radix(&offset[
            2..], 10).unwrap() * -1;
    } else if offset.starts_with(" ") {
        offset_value = i64::from_str_radix(&offset[1..], 10).unwrap();
    } else {
        panic!("unknown offset format: {}", offset);
    }
    println!("offset_value: {}", offset_value);
    offset_value
}

// step until encountering a br/jump
fn step_bb(pc: u64, insn_map: &HashMap<u64, &Insn>) -> u64 {
    let mut pc = pc;
    loop {
        let insn = insn_map.get(&pc).unwrap();
        decoded_trace_writer.write_all(format!("{}", insn).as_bytes())?;
        decoded_trace_writer.write_all(b"\n")?;
        if BRANCH_OPCODES.contains(&insn.mnemonic().unwrap()) || JUMP_OPCODES.contains(&insn.mnemonic().unwrap()) {
            break;
        }
        pc += insn.len() as u64;
    }
    pc
}

fn step_bb_until(pc: u64, insn_map: &HashMap<u64, &Insn>, target_pc: u64) -> u64 {
    let mut pc = pc;
    loop {
        let insn = insn_map.get(&pc).unwrap();
        if BRANCH_OPCODES.contains(&insn.mnemonic().unwrap()) || JUMP_OPCODES.contains(&insn.mnemonic().unwrap()) {
            panic!("unexpected branch/jump when handling FSync packet at pc: {}", pc);
        }
        pc += insn.len() as u64;
        if pc == target_pc {
            break;
        }
    }
    pc
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let mut elf_file = File::open(args.elf)?;
    let mut elf_buffer = Vec::new();
    elf_file.read_to_end(&mut elf_buffer)?;

    let elf = object::File::parse(&*elf_buffer)?;
    
    // assert this is for 64 bit RISC-V
    assert!(elf.architecture() == object::Architecture::Riscv64);

    // Find the .text section (where the executable code resides)
    let text_section = elf.section_by_name(".text").ok_or("No .text section found")?;
    let text_data = text_section.data()?;
    let entry_point = elf.entry();
    
    let cs = Capstone::new()
        .riscv()
        .mode(ArchMode::RiscV64)
        .extra_mode([ArchExtraMode::RiscVC].iter().copied())
        .detail(true)
        .build()?;

    let decoded_instructions = cs.disasm_all(&text_data, entry_point)?;
    println!("found {} instructions", decoded_instructions.len());

    // create a map of address to instruction 
    let mut insn_map : HashMap<u64, &Insn> = HashMap::new();
    for insn in decoded_instructions.as_ref() {
        insn_map.insert(insn.address(), insn);
    }

    let encoded_trace_file = File::open(args.encoded_trace)?;
    let mut encoded_trace_reader : BufReader<File> = BufReader::new(encoded_trace_file);

    let decoded_trace_file = File::create(args.decoded_trace)?;
    let mut decoded_trace_writer = BufWriter::new(decoded_trace_file);

    let packet = packet::read_packet(&mut encoded_trace_reader)?;
    println!("packet: {:?}", packet);
    let mut pc = refund_addr(packet.f_addr);
    let mut prev_addr = packet.f_addr;
    while let Ok(packet) = packet::read_packet(&mut encoded_trace_reader) {
        // special handling for the last packet, should be unlikely hinted
        if packet.f_header == FHeader::FSync {
            pc = step_bb_until(pc, &insn_map, refund_addr(packet.f_addr));
            break;
        }
        pc = step_bb(pc, &insn_map);
        let insn_to_resolve = insn_map.get(&pc).unwrap();
        match packet.f_header {
            FHeader::FTb => {
                assert!(BRANCH_OPCODES.contains(&insn_to_resolve.mnemonic().unwrap()));
                pc = (pc as i64 + compute_offset(insn_to_resolve) as i64) as u64;
            }
            FHeader::FNt => {
                assert!(BRANCH_OPCODES.contains(&insn_to_resolve.mnemonic().unwrap()));
                pc = pc + insn_to_resolve.len() as u64;
            }
            FHeader::FIj => {
                assert!(JUMP_OPCODES.contains(&insn_to_resolve.mnemonic().unwrap()));
                pc = (pc as i64 + compute_offset(insn_to_resolve) as i64) as u64;
            }
            FHeader::FUj => {
                assert!(JUMP_OPCODES.contains(&insn_to_resolve.mnemonic().unwrap()));
                pc = refund_addr(packet.address ^ pc >> 1);
            }
        }
    }
}
