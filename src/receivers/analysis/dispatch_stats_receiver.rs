use crate::backend::event::{Entry, EventKind};
use crate::receivers::abstract_receiver::{AbstractReceiver, BusReceiver, Shared};
use crate::receivers::latency_hist::{LatencyHist, HIST_BINS};

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
    seq_writer: Option<BufWriter<File>>,
    seq_limit: u64,
    seq_written: u64,
    receiver: BusReceiver,
    handlers: HashSet<u64>,
    // (from_handler, to_handler) -> entry-block latency distribution
    records: HashMap<(u64, u64), LatencyHist>,
    hist_writer: Option<BufWriter<File>>,
    curr_handler: Option<u64>,
    // a handler entry whose entry-block interval is not yet complete:
    // (handler_addr, entry_timestamp, from_handler)
    pending: Option<(u64, u64, Option<u64>)>,
    prev_addr: u64,
}

impl DispatchStatsReceiver {
    pub fn new(bus_rx: BusReader<Entry>, path: String, handlers: HashSet<u64>,
               seq_path: Option<String>, seq_limit: u64, hist_path: Option<String>) -> Self {
        Self {
            writer: BufWriter::new(File::create(path).unwrap()),
            seq_writer: seq_path.map(|p| {
                let mut w = BufWriter::new(File::create(p).unwrap());
                w.write_all(b"timestamp,to_handler\n").unwrap();
                w
            }),
            seq_limit,
            seq_written: 0,
            receiver: BusReceiver {
                name: "dispatch_stats".to_string(),
                bus_rx,
                checksum: 0,
            },
            handlers,
            records: HashMap::new(),
            hist_writer: hist_path.map(|p| BufWriter::new(File::create(p).unwrap())),
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
                    .add(timestamp.saturating_sub(entry_ts));
            }
            self.curr_handler = Some(handler);
        }
        // does the next BB enter a handler?
        if self.handlers.contains(&to_addr) {
            self.pending = Some((to_addr, timestamp, self.curr_handler));
            if self.seq_written < self.seq_limit {
                if let Some(ref mut w) = self.seq_writer {
                    w.write_all(format!("{},{:#x}\n", timestamp, to_addr).as_bytes()).unwrap();
                    self.seq_written += 1;
                }
            }
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
    let seq_path = config.get("seq_path").and_then(|v| v.as_str()).map(|s| s.to_string());
    let seq_limit = config.get("seq_limit").and_then(|v| v.as_u64()).unwrap_or(0);
    let hist_path = config.get("hist_path").and_then(|v| v.as_str()).map(|s| s.to_string());
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
    Box::new(DispatchStatsReceiver::new(bus_rx, path, handlers, seq_path, seq_limit, hist_path))
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
            Entry::Event {
                timestamp: _,
                kind: EventKind::Resume { pc, .. },
            } => {
                self.reset_flow(pc);
            }
            _ => {}
        }
    }

    fn _flush(&mut self) {
        if let Some(ref mut w) = self.seq_writer {
            w.flush().unwrap();
        }
        self.writer
            .write_all(b"count,mean,min,p50,p90,p99,max,netvar,from_handler,to_handler\n")
            .unwrap();
        if let Some(ref mut w) = self.hist_writer {
            w.write_all(b"from_handler,to_handler,cycles,count\n").unwrap();
        }
        for ((from, to), d) in self.records.iter() {
            if d.n == 0 {
                continue;
            }
            let count = d.n;
            let mean = d.sum as f64 / count as f64;
            let min = d.min();
            // min() falls back to max when every sample overflowed the bins
            let netvar = d.sum.saturating_sub(min * count);
            self.writer
                .write_all(
                    format!(
                        "{}, {}, {}, {}, {}, {}, {}, {}, {:#x}, {:#x}\n",
                        count, mean, min, d.quantile(0.50), d.quantile(0.90),
                        d.quantile(0.99), d.max, netvar, from, to,
                    )
                    .as_bytes(),
                )
                .unwrap();
            if let Some(ref mut w) = self.hist_writer {
                for (c, &k) in d.hist.iter().enumerate() {
                    if k > 0 {
                        w.write_all(format!("{:#x},{:#x},{},{}\n", from, to, c, k).as_bytes())
                            .unwrap();
                    }
                }
                if d.over_n > 0 {
                    // everything at or past the last bin lands in one row (cycles ==
                    // HIST_BINS) so the column stays numeric and counts still sum to n
                    w.write_all(
                        format!("{:#x},{:#x},{},{}\n", from, to, HIST_BINS, d.over_n)
                            .as_bytes(),
                    )
                    .unwrap();
                }
            }
        }
        if let Some(ref mut w) = self.hist_writer {
            w.flush().unwrap();
        }
        self.writer.flush().unwrap();
    }
}
