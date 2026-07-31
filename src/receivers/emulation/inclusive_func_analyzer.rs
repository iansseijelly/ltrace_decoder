use crate::receivers::emulation::abstract_emulator::{AbstractEmulatedAnalyzer, EmulationResult};
use std::fs::File;
use std::io::{BufWriter, Write};
use crate::receivers::stack_unwinder::StackUnwinder;
use crate::common::symbol_index::SymbolIndex;
use std::sync::Arc;
use crate::backend::event::Entry;

// Like FuncAnalyzer, but reports INCLUSIVE (entry-to-exit) time per frame close,
// under both the reference clock and the emulated clock. Since EmulationResult
// carries absolute timestamps under both clocks, inclusive time is simply the
// close timestamp minus the timestamp recorded when the frame opened.
pub struct InclusiveFuncAnalyzer {
    writer: Option<BufWriter<File>>,
    total_abs_error: u64,
    total_ref_time: u64,
    // parallel to the unwinder's frame stack: (ref_ts, emu_ts) at frame open
    open_clocks: Vec<(u64, u64)>,
    unwinder: StackUnwinder,
    event_count: u64,
    name: String,
}

impl InclusiveFuncAnalyzer {
    pub fn new(name: String, path: Option<String>, dump_csv: bool, symbols: Arc<SymbolIndex>) -> Self {
        let writer = if dump_csv {
            path.as_ref().map(|p| {
                let mut w = BufWriter::new(File::create(p).unwrap());
                w.write_all(b"reference_inclusive,emulated_inclusive,event\n").unwrap();
                w
            })
        } else {
            None
        };
        Self {
            writer,
            total_abs_error: 0,
            total_ref_time: 0,
            open_clocks: Vec::new(),
            unwinder: StackUnwinder::new(symbols).expect("init unwinder"),
            event_count: 0,
            name,
        }
    }
}

impl AbstractEmulatedAnalyzer for InclusiveFuncAnalyzer {
    fn push_emulated_event(&mut self, event: EmulationResult) {
        if let Some(update) = self.unwinder.step(&Entry::Event { timestamp: 0, kind: event.event.clone() }) {
            for frame in update.frames_closed {
                if let Some((ref_open, emu_open)) = self.open_clocks.pop() {
                    let ref_time = event.ref_ts.saturating_sub(ref_open);
                    let emu_time = event.emu_ts.saturating_sub(emu_open);
                    self.total_abs_error += ref_time.abs_diff(emu_time);
                    self.total_ref_time += ref_time;
                    self.event_count += 1;
                    if let Some(ref mut writer) = self.writer {
                        writer.write_all(format!("{},{},{}\n", ref_time, emu_time, frame.symbol.name).as_bytes()).unwrap();
                    }
                }
            }
            if let Some(_) = update.frames_opened {
                self.open_clocks.push((event.ref_ts, event.emu_ts));
            }
        }
    }

    fn flush(&mut self) {
        if let Some(ref mut writer) = self.writer {
            writer.flush().unwrap();
        }

        let weighted_error = self.total_abs_error as f64 / self.total_ref_time as f64;
        println!("Inclusive Func Emulation Error ({}): Weighted Error {:.4}%", self.name, weighted_error * 100.0);
    }
}
