use crate::backend::event::EventKind;
use crate::receivers::emulation::abstract_emulator::{AbstractEmulatedAnalyzer, EmulationResult};
use std::fs::File;
use std::io::{BufWriter, Write};

pub struct BBAnalyzer {
    writer: Option<BufWriter<File>>,
    total_abs_error: u64,
    total_ref_time: u64,
    event_count: u64,
    prev_ref_ts: u64,
    prev_emu_ts: u64,
    name: String,
}

impl BBAnalyzer {
    pub fn new(name: String, path: Option<String>, dump_csv: bool) -> Self {
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
            event_count: 0,
            prev_ref_ts: 0,
            prev_emu_ts: 0,
            name,
        }
    }
}

impl AbstractEmulatedAnalyzer for BBAnalyzer {
    fn push_emulated_event(&mut self, event: EmulationResult) {
        // a sync (re)establishes the time base without accounting the gap
        let (ref_d, emu_d) = match event.event {
            EventKind::SyncStart { .. } => (0, 0),
            _ => (
                event.ref_ts.saturating_sub(self.prev_ref_ts),
                event.emu_ts.saturating_sub(self.prev_emu_ts),
            ),
        };
        self.prev_ref_ts = event.ref_ts;
        self.prev_emu_ts = event.emu_ts;

        self.total_abs_error += ref_d.abs_diff(emu_d);
        self.total_ref_time += ref_d;
        self.event_count += 1;

        if let Some(ref mut writer) = self.writer {
            writer
                .write_all(
                    format!(
                        "{},{},{}\n",
                        ref_d,
                        emu_d,
                        event.event.to_csv_string()
                    )
                    .as_bytes(),
                )
                .unwrap();
        }
    }

    fn flush(&mut self) {
        if let Some(ref mut writer) = self.writer {
            writer.flush().unwrap();
        }

        let weighted_error = self.total_abs_error as f64 / self.total_ref_time as f64;
        println!("BB Emulation Error ({}): Weighted Error {:.4}%", self.name, weighted_error * 100.0);
    }
}
