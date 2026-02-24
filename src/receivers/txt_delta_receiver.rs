use crate::backend::event::{Entry, EventKind};
use crate::receivers::abstract_receiver::{AbstractReceiver, BusReceiver, Shared};
use bus::BusReader;
use std::fs::File;
use std::io::{BufWriter, Write};

pub struct TxtDeltaReceiver {
    writer: BufWriter<File>,
    receiver: BusReceiver,
    curr_timestamp: u64,
}

/* Receiver for dumping the trace to a text file */
impl TxtDeltaReceiver {
    pub fn new(bus_rx: BusReader<Entry>, path: String) -> Self {
        Self {
            writer: BufWriter::new(File::create(path).unwrap()),
            receiver: BusReceiver {
                name: "txt".to_string(),
                bus_rx: bus_rx,
                checksum: 0,
            },
            curr_timestamp: 0,
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
        .unwrap_or("trace.txt_delta.txt")
        .to_string();
    Box::new(TxtDeltaReceiver::new(bus_rx, path))
}

crate::register_receiver!("txt_delta", factory);

impl AbstractReceiver for TxtDeltaReceiver {
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
                self.writer
                    .write_all(format!("[delta: {}]", timestamp - self.curr_timestamp).as_bytes())
                    .unwrap();
                // write the event
                self.writer
                    .write_all(format!(" {}", kind).as_bytes())
                    .unwrap();
                self.writer.write_all(b"\n").unwrap();
                self.curr_timestamp = timestamp;
            }
            _ => {}
        }
    }

    fn _flush(&mut self) {
        self.writer.flush().unwrap();
    }
}
