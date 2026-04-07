use crate::backend::event::{Entry, EventKind};

pub trait AbstractEmulator: Send + 'static {
    fn push_event(&mut self, entry: Entry);
    fn flush(&mut self);

}

pub trait AbstractEmulatedAnalyzer: Send + 'static {
    fn push_emulated_event(&mut self, event: EmulationResult);
    fn flush(&mut self);
}

pub struct EmulationResult {
    pub reference_delta: u64,
    pub emulated_delta: u64,
    pub event: EventKind,
}