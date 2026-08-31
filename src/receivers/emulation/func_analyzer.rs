use crate::backend::event::{Entry, EventKind};
use crate::receivers::emulation::abstract_emulator::{AbstractEmulatedAnalyzer, EmulationResult};
use std::fs::File;
use std::io::{BufWriter, Write};
use crate::receivers::stack_unwinder::StackUnwinder;
use crate::common::symbol_index::SymbolIndex;
use std::sync::Arc;

// Reports SELF time (cycles accumulated while a frame is the innermost) per
// frame close, under both the reference and the emulated clock.
pub struct FuncAnalyzer {
    writer: Option<BufWriter<File>>,
    total_abs_error: u64,
    total_ref_time: u64,
    ref_time_stack: Vec<u64>,
    emu_time_stack: Vec<u64>,
    prev_ref_ts: u64,
    prev_emu_ts: u64,
    unwinder: StackUnwinder,
    event_count: u64,
    name: String,
}

impl FuncAnalyzer {
    pub fn new(name: String, path: Option<String>, dump_csv: bool, symbols: Arc<SymbolIndex>) -> Self {
        let writer = if dump_csv {
            path.as_ref().map(|p| {
                let mut w = BufWriter::new(File::create(p).unwrap());
                w.write_all(b"reference_delta,emulated_delta,event\n").unwrap();
                w
            })
        } else {
            None
        };
        Self {
            writer,
            total_abs_error: 0,
            total_ref_time: 0,
            ref_time_stack: Vec::new(),
            emu_time_stack: Vec::new(),
            prev_ref_ts: 0,
            prev_emu_ts: 0,
            unwinder: StackUnwinder::new(symbols).expect("init unwinder"),
            event_count: 0,
            name,
        }
    }
}

impl AbstractEmulatedAnalyzer for FuncAnalyzer {
    fn push_emulated_event(&mut self, event: EmulationResult) {
        // a sync (re)establishes the time base without accounting the gap
        let (ref_d, emu_d) = match event.event {
            EventKind::SyncStart { .. } | EventKind::Resume { .. } => (0, 0),
            _ => (
                event.ref_ts.saturating_sub(self.prev_ref_ts),
                event.emu_ts.saturating_sub(self.prev_emu_ts),
            ),
        };
        self.prev_ref_ts = event.ref_ts;
        self.prev_emu_ts = event.emu_ts;

        // first, always add the delta to the head value of the time stacks
        if let Some(top) = self.ref_time_stack.last_mut() {
            *top += ref_d;
        }
        if let Some(top) = self.emu_time_stack.last_mut() {
            *top += emu_d;
        }

        // then, ask the stack unwinder, where are we?
        if let Some(update) = self.unwinder.step(&Entry::Event { timestamp: 0, kind: event.event.clone() }) {
            for frame in update.frames_closed {
                let ref_time = self.ref_time_stack.pop().unwrap();
                let emu_time = self.emu_time_stack.pop().unwrap();
                let delta_time = ref_time.abs_diff(emu_time);
                self.total_abs_error += delta_time;
                self.total_ref_time += ref_time;
                self.event_count += 1;
                if let Some(ref mut writer) = self.writer {
                    writer.write_all(format!("{},{},{}\n", ref_time, emu_time, frame.symbol.name).as_bytes()).unwrap();
                }
            }
            if let Some(_) = update.frames_opened {
                self.ref_time_stack.push(0);
                self.emu_time_stack.push(0);
            }
        }
    }

    fn flush(&mut self) {
        if let Some(ref mut writer) = self.writer {
            writer.flush().unwrap();
        }

        let weighted_error = self.total_abs_error as f64 / self.total_ref_time as f64;
        println!("Func Emulation Error ({}): Weighted Error {:.4}%", self.name, weighted_error * 100.0);
    }
}
