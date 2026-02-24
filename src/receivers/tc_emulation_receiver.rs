use crate::backend::event::{Entry, EventKind};
use crate::receivers::abstract_receiver::{AbstractReceiver, BusReceiver, Shared};
use bus::BusReader;
use std::fs::File;
use std::io::{BufWriter, Write};

pub struct TcEmulationReceiver {
    writer: BufWriter<File>,
    receiver: BusReceiver,
    curr_tc: u64,
    interval: u64,
    event_staging: Vec<EventKind>,
}

/* Emulates the behavior of a TC-based encoder, used for accuracy analysis
  A TC-based encoder encodes timestamp as separate packets emitted in fixed intervals.
*/
impl TcEmulationReceiver {
    pub fn new(bus_rx: BusReader<Entry>, path: String, interval: u64) -> Self {
        Self {
            writer: BufWriter::new(File::create(path).unwrap()),
            receiver: BusReceiver {
                name: "tc_emulation".to_string(),
                bus_rx: bus_rx,
                checksum: 0,
            },
            curr_tc: 0,
            interval: interval,
            event_staging: Vec::new(),
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
        .unwrap_or("trace.tc_emulation.txt")
        .to_string();
    let interval = _config
        .get("interval")
        .and_then(|value| value.as_u64())
        .unwrap_or(1000000);
    Box::new(TcEmulationReceiver::new(bus_rx, path, interval))
}

crate::register_receiver!("tc_emulation", factory);

impl AbstractReceiver for TcEmulationReceiver {
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
                self.curr_tc = timestamp / self.interval;
            }

            Entry::Event { timestamp, kind } => {
                if timestamp / self.interval != self.curr_tc {
                    // smear the timestamps distributing across all events staged, excluding the current event
                    let next_tc = timestamp / self.interval;
                    let slack = (next_tc - self.curr_tc) * self.interval;
                    let num_events = self.event_staging.len() as u64;
                    let delta_tc = slack / num_events;
                    for event in self.event_staging.iter() {
                        self.writer
                            .write_all(format!("[delta: {}]", delta_tc).as_bytes())
                            .unwrap();
                        self.writer
                            .write_all(format!(" {}", event).as_bytes())
                            .unwrap();
                        self.writer.write_all(b"\n").unwrap();
                    }
                    
                    // clear the staged events
                    self.event_staging.clear();
                    
                    // update the current TC
                    self.curr_tc = next_tc;
                }
                self.event_staging.push(kind);
            }
            _ => {}
        }
    }

    fn _flush(&mut self) {
        self.writer.flush().unwrap();
    }
}
