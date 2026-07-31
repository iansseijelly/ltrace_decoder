use crate::backend::event::{Entry, EventKind};

pub trait AbstractEmulator: Send + 'static {
    fn push_event(&mut self, entry: Entry);
    fn flush(&mut self);

}

pub trait AbstractEmulatedAnalyzer: Send + 'static {
    fn push_emulated_event(&mut self, event: EmulationResult);
    fn flush(&mut self);
}

// One trace event under two clocks. `ref_ts` is the golden hardware timestamp;
// `emu_ts` is the timestamp the emulated sparse format would attribute to the
// same event. Both are absolute, so consumers can either diff consecutive
// results (error analyzers) or project `emu_ts` into a re-timed Entry stream
// (fan-out to ordinary receivers).
#[derive(Clone)]
pub struct EmulationResult {
    pub ref_ts: u64,
    pub emu_ts: u64,
    pub event: EventKind,
}