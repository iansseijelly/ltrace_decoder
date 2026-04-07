use crate::backend::event::{Entry, EventKind};
use crate::receivers::emulation::abstract_emulator::{AbstractEmulatedAnalyzer, AbstractEmulator, EmulationResult};

pub struct TCEmulator {
    event_staging: Vec<(u64, EventKind)>,
    analyzer: Box<dyn AbstractEmulatedAnalyzer>,
    curr_tc: u64,
    curr_timestamp: u64,
    interval: u64,
}

impl TCEmulator {
    pub fn new(analyzer: Box<dyn AbstractEmulatedAnalyzer>, interval: u64) -> Self {
        Self {
            event_staging: Vec::new(),
            analyzer,
            curr_tc: 0,
            curr_timestamp: 0,
            interval,
        }
    }
}

impl AbstractEmulator for TCEmulator {
    fn push_event(&mut self, entry: Entry) {
        match entry {
            Entry::Event { timestamp, kind: kind @ EventKind::SyncStart { .. } } => {
                self.curr_tc = timestamp / self.interval; // initialize the current TC
                self.curr_timestamp = timestamp;
                self.analyzer.push_emulated_event(EmulationResult {
                    reference_delta: 0,
                    emulated_delta: 0,
                    event: kind,
                });
            }
            Entry::Event { timestamp, kind } => {
                if timestamp / self.interval != self.curr_tc && !self.event_staging.is_empty() {
                    // smear the timestamps distributing across all events staged, excluding the current event
                    let next_tc = timestamp / self.interval;
                    let slack = (next_tc - self.curr_tc) * self.interval;
                    let num_events = self.event_staging.len() as u64;
                    let delta_tc = slack / num_events;

                    self.curr_tc = next_tc;

                    if num_events > 0 {
                        // the last events gets the remainder as well
                        let (last_event_timestamp, last_event) = self.event_staging.pop().unwrap();

                        for (event_timestamp, event) in self.event_staging.iter() {
                            self.analyzer.push_emulated_event(EmulationResult {
                                reference_delta: event_timestamp - self.curr_timestamp,
                                emulated_delta: delta_tc,
                                event: event.clone(),
                            });
                            self.curr_timestamp = *event_timestamp;
                        }
                    
                        // write the last event
                        self.analyzer.push_emulated_event(EmulationResult {
                            reference_delta: last_event_timestamp - self.curr_timestamp,
                            emulated_delta: delta_tc + slack % num_events,
                            event: last_event,
                        });
                        self.curr_timestamp = last_event_timestamp;
                        self.event_staging.clear();
                    }
                }
                self.event_staging.push((timestamp, kind.clone()));
            }
            _ => {}
        }
    }

    fn flush(&mut self) {
        self.event_staging.clear();
        self.analyzer.flush();
    }
}