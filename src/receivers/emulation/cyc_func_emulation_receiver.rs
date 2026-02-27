use crate::backend::event::{Entry, EventKind};
use crate::receivers::abstract_receiver::{AbstractReceiver, BusReceiver, Shared};
use bus::BusReader;
use std::fs::File;
use std::io::{BufWriter, Write};
use crate::receivers::stack_unwinder::StackUnwinder;
use crate::common::symbol_index::SymbolIndex;
use std::sync::Arc;

pub struct CycFuncEmulationReceiver {
    writer: BufWriter<File>,
    receiver: BusReceiver,
    curr_cyc: u64,
    lim_tnt: u64,
    n_tnt: u64,
    event_staging: Vec<EventKind>,
    unwinder: StackUnwinder,
    func_entry_time_stack: Vec<u64>,
}

/* Emulates the behavior of a CYC-based encoder, used for accuracy analysis
  A CYC-based encoder encodes cycles as a property of each trace event.
*/
impl CycFuncEmulationReceiver {
    pub fn new(bus_rx: BusReader<Entry>, symbols: Arc<SymbolIndex>, path: String, lim_tnt: u64) -> Self {
        let unwinder = StackUnwinder::new(symbols).expect("init unwinder");
        let mut writer = BufWriter::new(File::create(path).unwrap());
        writer.write_all(b"delta,event\n").unwrap();
        Self {
            writer: writer,
            receiver: BusReceiver {
                name: "cyc_func_emulation".to_string(),
                bus_rx: bus_rx,
                checksum: 0,
            },
            curr_cyc: 0,
            lim_tnt: lim_tnt,
            n_tnt: 0,
            event_staging: Vec::new(),
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
        .unwrap_or("trace.cyc_func_emulation.csv")
        .to_string();
    let lim_tnt = _config
        .get("lim_tnt")
        .and_then(|value| value.as_u64())
        .unwrap_or(1000000);
    Box::new(CycFuncEmulationReceiver::new(bus_rx, Arc::clone(&_shared.symbol_index), path, lim_tnt))
}

crate::register_receiver!("cyc_func_emulation", factory);

impl AbstractReceiver for CycFuncEmulationReceiver {
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

                    if num_events > 0 {
                        // the last events gets the remainder as well
                        let last_event = self.event_staging.pop().unwrap();

                        for event in self.event_staging.iter() {
                            self.curr_cyc += delta_cyc;
                            if let Some(update) = self.unwinder.step(&Entry::Event { timestamp: self.curr_cyc, kind: event.clone() }) {
                                for frame in update.frames_closed {
                                    // pop the func_entry_time_stack
                                    let func_entry_time = self.func_entry_time_stack.pop().unwrap();
                                    let delta_time = self.curr_cyc - func_entry_time;
                                    self.writer
                                        .write_all(format!("{},{},{},{}", delta_time, frame.symbol.name, func_entry_time, self.curr_cyc).as_bytes())
                                        .unwrap();
                                    self.writer.write_all(b"\n").unwrap();
                                }
                                if let Some(_) = update.frames_opened {
                                    // push the current cycle to the func_entry_time_stack
                                    self.func_entry_time_stack.push(self.curr_cyc);
                                }
                            }
                        }
                        
                        // handle the last event
                        self.curr_cyc += delta_cyc + slack % num_events;
                        assert_eq!(self.curr_cyc, timestamp);
                        if let Some(update) = self.unwinder.step(&Entry::Event { timestamp: timestamp, kind: last_event.clone() }) {
                            for frame in update.frames_closed {
                                // pop the func_entry_time_stack
                                let func_entry_time = self.func_entry_time_stack.pop().unwrap();
                                let delta_time = self.curr_cyc - func_entry_time;
                                self.writer
                                    .write_all(format!("{},{},{},{}", delta_time, frame.symbol.name, func_entry_time, self.curr_cyc).as_bytes())
                                    .unwrap();
                                self.writer.write_all(b"\n").unwrap();
                            }
                            if let Some(_) = update.frames_opened {
                                // push the current cycle to the func_entry_time_stack
                                self.func_entry_time_stack.push(self.curr_cyc);
                            }
                        }
                        // clear the states
                        self.event_staging.clear();
                        self.n_tnt = 0;
                    }

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
