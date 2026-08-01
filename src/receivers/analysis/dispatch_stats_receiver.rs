use crate::backend::event::{Entry, EventKind};
use crate::receivers::abstract_receiver::{AbstractReceiver, BusReceiver, Shared};

use bus::BusReader;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufWriter, Write};

/* Interpreter dispatch profiler: given the set of handler entry addresses
   (e.g. a bytecode dispatch table), records the latency of each handler's
   ENTRY basic block conditioned on which handler ran immediately before it.
   Unlike bb_pair_stats' one-hop predecessor, the "from" side here is the
   last handler entered, which attributes transitions correctly even when
   the compiler merges handler tails into shared dispatch blocks of
   arbitrary chain depth. Traps/syncs reset the tracked handler. */
pub struct DispatchStatsReceiver {
    writer: BufWriter<File>,
    receiver: BusReceiver,
    handlers: HashSet<u64>,
    // (from_handler, to_handler) -> entry-block intervals
    records: HashMap<(u64, u64), Vec<u64>>,
    curr_handler: Option<u64>,
    // a handler entry whose entry-block interval is not yet complete:
    // (handler_addr, entry_timestamp, from_handler)
    pending: Option<(u64, u64, Option<u64>)>,
    prev_addr: u64,
}

impl DispatchStatsReceiver {
    pub fn new(bus_rx: BusReader<Entry>, path: String, handlers: HashSet<u64>) -> Self {
        Self {
            writer: BufWriter::new(File::create(path).unwrap()),
            receiver: BusReceiver {
                name: "dispatch_stats".to_string(),
                bus_rx,
                checksum: 0,
            },
            handlers,
            records: HashMap::new(),
            curr_handler: None,
            pending: None,
            prev_addr: 0,
        }
    }

    fn reset_flow(&mut self, to_addr: u64) {
        self.curr_handler = None;
        self.pending = None;
        self.prev_addr = to_addr;
    }

    // a CFI event: the BB [prev_addr, from_addr] just finished at `timestamp`,
    // and the next BB starts at to_addr
    fn step(&mut self, _from_addr: u64, to_addr: u64, timestamp: u64) {
        // complete a pending handler entry block
        if let Some((handler, entry_ts, from)) = self.pending.take() {
            if let Some(f) = from {
                self.records
                    .entry((f, handler))
                    .or_default()
                    .push(timestamp.saturating_sub(entry_ts));
            }
            self.curr_handler = Some(handler);
        }
        // does the next BB enter a handler?
        if self.handlers.contains(&to_addr) {
            self.pending = Some((to_addr, timestamp, self.curr_handler));
        }
        self.prev_addr = to_addr;
    }
}

pub fn factory(
    _shared: &Shared,
    config: serde_json::Value,
    bus_rx: BusReader<Entry>,
) -> Box<dyn AbstractReceiver> {
    let path = config
        .get("path")
        .and_then(|value| value.as_str())
        .unwrap_or("trace.dispatch_stats.csv")
        .to_string();
    let handlers: HashSet<u64> = config
        .get("handlers")
        .and_then(|value| value.as_array())
        .expect("dispatch_stats requires 'handlers': [\"0x...\", ...]")
        .iter()
        .map(|v| {
            let s = v.as_str().expect("handler addresses must be hex strings");
            u64::from_str_radix(s.trim_start_matches("0x"), 16).expect("bad handler address")
        })
        .collect();
    Box::new(DispatchStatsReceiver::new(bus_rx, path, handlers))
}

crate::register_receiver!("dispatch_stats", factory);

impl AbstractReceiver for DispatchStatsReceiver {
    fn bus_rx(&mut self) -> &mut BusReader<Entry> {
        &mut self.receiver.bus_rx
    }

    fn _bump_checksum(&mut self) {
        self.receiver.checksum += 1;
    }

    fn _receive_entry(&mut self, entry: Entry) {
        match entry {
            Entry::Event {
                timestamp: _,
                kind: EventKind::SyncStart { start_pc, .. },
            } => {
                self.reset_flow(start_pc);
            }
            Entry::Event {
                timestamp,
                kind: EventKind::InferrableJump { arc },
            } => self.step(arc.0, arc.1, timestamp),
            Entry::Event {
                timestamp,
                kind: EventKind::UninferableJump { arc },
            } => self.step(arc.0, arc.1, timestamp),
            Entry::Event {
                timestamp,
                kind: EventKind::TakenBranch { arc },
            } => self.step(arc.0, arc.1, timestamp),
            Entry::Event {
                timestamp,
                kind: EventKind::NonTakenBranch { arc },
            } => self.step(arc.0, arc.1, timestamp),
            Entry::Event {
                timestamp: _,
                kind: EventKind::Trap { arc, .. },
            } => {
                self.reset_flow(arc.1);
            }
            _ => {}
        }
    }

    fn _flush(&mut self) {
        self.writer
            .write_all(b"count,mean,min,p50,p90,p99,max,netvar,from_handler,to_handler\n")
            .unwrap();
        for ((from, to), intervals) in self.records.iter_mut() {
            if intervals.is_empty() {
                continue;
            }
            let sum: u64 = intervals.iter().sum();
            let count = intervals.len();
            let mean = sum as f64 / count as f64;
            intervals.sort_unstable();
            let min = intervals[0];
            let pct = |p: f64| -> u64 {
                let idx = (((count as f64 - 1.0) * p).round() as usize).min(count - 1);
                intervals[idx]
            };
            let netvar = sum - min * count as u64;
            self.writer
                .write_all(
                    format!(
                        "{}, {}, {}, {}, {}, {}, {}, {}, {:#x}, {:#x}\n",
                        count, mean, min, pct(0.50), pct(0.90), pct(0.99),
                        intervals[count - 1], netvar, from, to,
                    )
                    .as_bytes(),
                )
                .unwrap();
        }
        self.writer.flush().unwrap();
    }
}
