use crate::backend::event::{Entry, EventKind};
use crate::receivers::abstract_receiver::{AbstractReceiver, BusReceiver, Shared};
use bus::BusReader;
use std::fs::File;
use std::io::{BufWriter, Write};
use crate::receivers::stack_unwinder::StackUnwinder;
use crate::common::symbol_index::SymbolIndex;
use std::sync::Arc;

pub struct ReferenceFuncReceiver {
    writer: BufWriter<File>,
    receiver: BusReceiver,
    curr_timestamp: u64,
    unwinder: StackUnwinder,
    func_entry_time_stack: Vec<u64>,
}

/* Receiver for dumping the trace to a text file */
impl ReferenceFuncReceiver {
    pub fn new(bus_rx: BusReader<Entry>, symbols: Arc<SymbolIndex>, path: String) -> Self {
        let unwinder = StackUnwinder::new(symbols).expect("init unwinder");
        let mut writer = BufWriter::new(File::create(path).unwrap());
        writer.write_all(b"delta,event\n").unwrap();
        Self {
            writer: writer,
            receiver: BusReceiver {
                name: "reference_func".to_string(),
                bus_rx: bus_rx,
                checksum: 0,
            },
            curr_timestamp: 0,
            unwinder,
            func_entry_time_stack: Vec::new(),
        }
    }
}

pub fn factory(
    _shared: &Shared,
    _config: serde_json::Value,
    bus_rx: BusReader<Entry>,
) -> Box<dyn AbstractReceiver> {
    let path = _config
        .get("path")
        .and_then(|value| value.as_str())
        .unwrap_or("trace.reference_func.csv")
        .to_string();
    Box::new(ReferenceFuncReceiver::new(bus_rx, Arc::clone(&_shared.symbol_index), path))
}

crate::register_receiver!("reference_func", factory);

impl AbstractReceiver for ReferenceFuncReceiver {
    fn bus_rx(&mut self) -> &mut BusReader<Entry> {
        &mut self.receiver.bus_rx
    }

    fn _bump_checksum(&mut self) {
        self.receiver.checksum += 1;
    }

    fn _receive_entry(&mut self, entry: Entry) {
        match entry {
            Entry::Event {
                timestamp,
                kind: EventKind::SyncStart { .. },
            } => {
                self.curr_timestamp = timestamp;
            }
            Entry::Event { timestamp, kind } => {
                self.curr_timestamp = timestamp;
                if let Some(update) = self.unwinder.step(&Entry::Event { timestamp, kind }) {
                    for frame in update.frames_closed {
                        let func_entry_time = self.func_entry_time_stack.pop().unwrap();
                        let delta_time = timestamp - func_entry_time;
                        self.writer
                            .write_all(format!("{},{},{},{}\n", delta_time, frame.symbol.name, func_entry_time, timestamp).as_bytes())
                            .unwrap();
                    }
                
                    if let Some(_) = update.frames_opened {
                        self.func_entry_time_stack.push(timestamp);
                    }
                }
            }
            _ => {}
        }
    }

    fn _flush(&mut self) {
        self.writer.flush().unwrap();
    }
}
