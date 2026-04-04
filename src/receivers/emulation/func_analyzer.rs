use crate::receivers::emulation::abstract_emulator::{AbstractEmulatedAnalyzer, EmulationResult};
use std::fs::File;
use std::io::{BufWriter, Write};
use crate::receivers::stack_unwinder::StackUnwinder;
use crate::common::symbol_index::SymbolIndex;
use std::sync::Arc;
use crate::backend::event::Entry;

pub struct FuncAnalyzer {
    writer: Option<BufWriter<File>>,
    total_abs_error: u64,
    total_ref_time: u64,
    ref_time_stack: Vec<u64>,
    emu_time_stack: Vec<u64>,
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
            unwinder: StackUnwinder::new(symbols).expect("init unwinder"),
            event_count: 0,
            name,
        }
    }
}

impl AbstractEmulatedAnalyzer for FuncAnalyzer {
    fn push_emulated_event(&mut self, event: EmulationResult) {
        // first, always add the reference time to the head value of ref_time_stack
        if let Some(top) = self.ref_time_stack.last_mut() {
            *top += event.reference_delta;
        }
        if let Some(top) = self.emu_time_stack.last_mut() {
            *top += event.emulated_delta;
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

        // let ref_d = event.reference_delta;
        // let emu_d = event.emulated_delta;
        // self.total_abs_error += ref_d.abs_diff(emu_d);
        // self.total_ref_time += ref_d;
        // self.event_count += 1;

        // if let Some(ref mut writer) = self.writer {
        //     writer
        //         .write_all(
        //             format!(
        //                 "{},{},{}\n",
        //                 ref_d,
        //                 emu_d,
        //                 event.event.to_csv_string()
        //             )
        //             .as_bytes(),
        //         )
        //         .unwrap();
        // }
    }

    fn flush(&mut self) {
        if let Some(ref mut writer) = self.writer {
            writer.flush().unwrap();
        }

        let weighted_error = self.total_abs_error as f64 / self.total_ref_time as f64;
        println!("Func Emulation Error ({}): Weighted Error {:.4}%", self.name, weighted_error * 100.0);
    }
}
