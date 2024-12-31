use crate::backend::event::{Entry, Event};
use crate::backend::abstract_receiver::{AbstractReceiver, BusReceiver};
use bus::BusReader;
use std::fs::File;
use std::io::{BufWriter, Write};

pub struct TxtReceiver {
    writer: BufWriter<File>,
    receiver: BusReceiver,
}

impl TxtReceiver {
    pub fn new(bus_rx: BusReader<Entry>) -> Self {
        Self { writer: BufWriter::new(File::create("trace.txt").unwrap()), 
                receiver: BusReceiver { name: "txt".to_string(), bus_rx: bus_rx, checksum: 0 } }
    }
}

impl AbstractReceiver for TxtReceiver {

    fn bus_rx(&mut self) -> &mut BusReader<Entry> {
        &mut self.receiver.bus_rx
    }

    fn _bump_checksum(&mut self) {
        self.receiver.checksum += 1;
    }

    fn _receive_entry(&mut self, entry: Entry) {
        match entry.event {
            Event::None => {
                // only arc.0 is used for none type events
                self.writer.write_all(format!("{:#x}:", entry.arc.0).as_bytes()).unwrap();
                if let Some(insn_mnemonic) = entry.insn_mnemonic {
                    self.writer.write_all(format!(" {}", insn_mnemonic).as_bytes()).unwrap();
                    if let Some(insn_op_str) = entry.insn_op_str {
                        self.writer.write_all(format!(" {}", insn_op_str).as_bytes()).unwrap();
                    }
                }
                self.writer.write_all(b"\n").unwrap();
            }
            _ => {
                if let Some(timestamp) = entry.timestamp {
                    self.writer.write_all(format!("[timestamp: {}]", timestamp).as_bytes()).unwrap();
                    // write the event
                    self.writer.write_all(format!(" {}", entry.event.to_string()).as_bytes()).unwrap();
                    self.writer.write_all(b"\n").unwrap();
                }
            }
        }
    }

    fn _flush(&mut self) {
        self.writer.flush().unwrap();
    }
}
