use crate::backend::event::{Entry, EventKind};
use crate::receivers::emulation::abstract_emulator::{AbstractEmulatedAnalyzer, AbstractEmulator, EmulationResult};

// Emulates a TNT based encoder, emitting CYC packets
// It never compresses RET packets ever
pub struct TNTCycNRETEmulator {
    event_staging: Vec<(u64, EventKind)>,
    lim_tnt: u64,
    n_tnt: u64,
    curr_cyc: u64,
    analyzer: Box<dyn AbstractEmulatedAnalyzer>,
}

impl TNTCycNRETEmulator {
    pub fn new(analyzer: Box<dyn AbstractEmulatedAnalyzer>, lim_tnt: u64) -> Self {
        Self {
            event_staging: Vec::new(),
            analyzer,
            lim_tnt: lim_tnt,
            n_tnt: 0,
            curr_cyc: 0,
        }
    }
}

impl AbstractEmulator for TNTCycNRETEmulator {
    fn push_event(&mut self, entry: Entry) {
        match entry {
            Entry::Event { timestamp, kind } => {
                match kind {
                    // first, always stage the event
                    EventKind::SyncStart { .. } => {
                        self.curr_cyc = timestamp;
                        self.analyzer.push_emulated_event(EmulationResult {
                            reference_delta: 0,
                            emulated_delta: 0,
                            event: kind.clone(),
                        });
                    }
                    EventKind::TakenBranch { .. } => {
                        self.n_tnt += 1;
                        self.event_staging.push((timestamp, kind.clone()));
                    }
                    EventKind::NonTakenBranch { .. } => {
                        self.n_tnt += 1;
                        self.event_staging.push((timestamp, kind.clone()));
                    }
                    _ => {
                        self.event_staging.push((timestamp, kind.clone()));
                    }
                }

                // then, detect if we should release the events
                if self.n_tnt >= self.lim_tnt || matches!(&kind, EventKind::UninferableJump { .. }) || matches!(&kind, EventKind::Trap { .. })
                {
                    // smear the timestamps distributing across all events staged, excluding the current event
                    let slack = timestamp - self.curr_cyc;
                    let num_events = self.event_staging.len() as u64;
                    let delta_cyc = slack / num_events;

                    if num_events > 0 {
                        // the last events gets the remainder as well
                        let (last_event_timestamp, last_event) = self.event_staging.pop().unwrap();

                        for (event_timestamp, event) in self.event_staging.iter() {
                            self.analyzer.push_emulated_event(EmulationResult {
                                reference_delta: event_timestamp - self.curr_cyc,
                                emulated_delta: delta_cyc,
                                event: event.clone(),
                            });
                            self.curr_cyc = *event_timestamp;
                        }

                        // write the last event
                        self.analyzer.push_emulated_event(EmulationResult {
                            reference_delta: last_event_timestamp - self.curr_cyc,
                            emulated_delta: delta_cyc + slack % num_events,
                            event: last_event.clone(),
                        });
                        self.curr_cyc = last_event_timestamp;
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

    fn flush(&mut self) {
        self.event_staging.clear();
        self.analyzer.flush();
    }
}
