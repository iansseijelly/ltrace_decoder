use crate::backend::event::{Entry, EventKind};
use crate::receivers::abstract_receiver::{AbstractReceiver, BusReceiver, Shared};
use bus::BusReader;
use std::fs::File;
use std::io::{BufWriter, Write};

pub struct CycEmulationReceiver {
    writer: BufWriter<File>,
    receiver: BusReceiver,
    curr_cyc: u64,
    lim_tnt: u64,
    n_tnt: u64,
    event_staging: Vec<EventKind>,
}

/* Emulates the behavior of a CYC-based encoder, used for accuracy analysis
  A CYC-based encoder encodes cycles as a property of each trace event.
*/
impl CycEmulationReceiver {
    pub fn new(bus_rx: BusReader<Entry>, path: String, lim_tnt: u64) -> Self {
        Self {
            writer: BufWriter::new(File::create(path).unwrap()),
            receiver: BusReceiver {
                name: "tc_emulation".to_string(),
                bus_rx: bus_rx,
                checksum: 0,
            },
            curr_cyc: 0,
            lim_tnt: lim_tnt,
            n_tnt: 0,
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
    let lim_tnt = _config
        .get("lim_tnt")
        .and_then(|value| value.as_u64())
        .unwrap_or(1000000);
    Box::new(CycEmulationReceiver::new(bus_rx, path, lim_tnt))
}

crate::register_receiver!("cyc_emulation", factory);

impl AbstractReceiver for CycEmulationReceiver {
    fn bus_rx(&mut self) -> &mut BusReader<Entry> {
        &mut self.receiver.bus_rx
    }

    fn _bump_checksum(&mut self) {
        self.receiver.checksum += 1;
    }

    fn _receive_entry(&mut self, entry: Entry) {
        match entry {
            Entry::Event { timestamp, kind } => {
                // first, always stage the event
                // this is safe because all events BEFORE a CYC packet is guaranteed to happen beforehand
                match kind {
                    EventKind::SyncStart { .. } => {
                        self.curr_cyc = timestamp;
                    }
                    EventKind::TakenBranch { .. } => {
                        self.n_tnt += 1;
                        self.event_staging.push(kind.clone());
                    }
                    EventKind::NonTakenBranch { .. } => {
                        self.n_tnt += 1;
                        self.event_staging.push(kind.clone());
                    }
                    _ => {
                        self.event_staging.push(kind.clone());
                    }
                }

                if self.n_tnt >= self.lim_tnt || matches!(&kind, EventKind::UninferableJump { .. })
                {
                    // smear the timestamps distributing across all events staged, excluding the current event
                    let slack = timestamp - self.curr_cyc;
                    let num_events = self.event_staging.len() as u64;
                    let delta_cyc = slack / num_events;
                    for event in self.event_staging.iter() {
                        self.writer
                            .write_all(format!("[delta: {}]", delta_cyc).as_bytes())
                            .unwrap();
                        self.writer
                            .write_all(format!(" {}", event).as_bytes())
                            .unwrap();
                        self.writer.write_all(b"\n").unwrap();
                    }

                    // clear the states
                    self.event_staging.clear();
                    self.n_tnt = 0;

                    // update the current cycle
                    self.curr_cyc = timestamp;
                }
            }
            _ => {}
        }
    }

    fn _flush(&mut self) {
        self.writer.flush().unwrap();
    }
}
