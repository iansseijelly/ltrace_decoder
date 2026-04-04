use crate::backend::event::Entry;
use crate::receivers::abstract_receiver::{AbstractReceiver, BusReceiver, Shared};
use bus::BusReader;
use crate::receivers::emulation::abstract_emulator::AbstractEmulator;
use crate::receivers::emulation::bb_analyzer::BBAnalyzer;
use crate::receivers::emulation::func_analyzer::FuncAnalyzer;
use std::sync::Arc;
use crate::receivers::emulation::tnt_cyc_nret_emulator::TNTCycNRETEmulator;
use crate::receivers::emulation::tnt_cyc_retcompressed_emulator::TNTCycRETCompressedEmulator;
use crate::receivers::emulation::tc_emulator::TCEmulator;

// Generic receiver that wraps any AbstractEmulator
pub struct EmulationReceiver {
    receiver: BusReceiver,
    emulator: Box<dyn AbstractEmulator>,
}

impl EmulationReceiver {
    pub fn new(bus_rx: BusReader<Entry>, name: String, emulator: Box<dyn AbstractEmulator>) -> Self {
        Self {
            receiver: BusReceiver { name, bus_rx, checksum: 0 },
            emulator,
        }
    }
}

impl AbstractReceiver for EmulationReceiver {
    fn bus_rx(&mut self) -> &mut BusReader<Entry> { &mut self.receiver.bus_rx }
    fn _bump_checksum(&mut self) { self.receiver.checksum += 1; }
    fn _receive_entry(&mut self, entry: Entry) { self.emulator.push_event(entry); }
    fn _flush(&mut self) { self.emulator.flush(); }
}

// Helper to parse common config fields
fn parse_common(config: &serde_json::Value) -> (Option<String>, bool) {
    let path = config.get("path").and_then(|v| v.as_str()).map(|s| s.to_string());
    let dump_csv = config.get("dump_csv").and_then(|v| v.as_bool()).unwrap_or(false);
    (path, dump_csv)
}

// --- Factories ---

pub fn tnt_cyc_nret_bb_emulation_factory(
    _shared: &Shared, config: serde_json::Value, bus_rx: BusReader<Entry>,
) -> Box<dyn AbstractReceiver> {
    let (path, dump_csv) = parse_common(&config);
    let lim_tnt = config.get("lim_tnt").and_then(|v| v.as_u64()).unwrap_or(6);
    let name = format!("tnt_cyc_nret_bb_emulation_{}", lim_tnt);
    let analyzer = Box::new(BBAnalyzer::new(name.clone(), path, dump_csv));
    Box::new(EmulationReceiver::new(bus_rx, name, Box::new(TNTCycNRETEmulator::new(analyzer, lim_tnt))))
}
crate::register_receiver!("tnt_cyc_nret_bb_emulation", tnt_cyc_nret_bb_emulation_factory);

pub fn tnt_cyc_retcompressed_bb_emulation_factory(
    _shared: &Shared, config: serde_json::Value, bus_rx: BusReader<Entry>,
) -> Box<dyn AbstractReceiver> {
    let (path, dump_csv) = parse_common(&config);
    let lim_tnt = config.get("lim_tnt").and_then(|v| v.as_u64()).unwrap_or(6);
    let name = format!("tnt_cyc_retcompressed_bb_emulation_{}", lim_tnt);
    let analyzer = Box::new(BBAnalyzer::new(name.clone(), path, dump_csv));
    Box::new(EmulationReceiver::new(bus_rx, name, Box::new(TNTCycRETCompressedEmulator::new(analyzer, lim_tnt))))
}
crate::register_receiver!("tnt_cyc_retcompressed_bb_emulation", tnt_cyc_retcompressed_bb_emulation_factory);

pub fn tc_bb_emulation_factory(
    _shared: &Shared, config: serde_json::Value, bus_rx: BusReader<Entry>,
) -> Box<dyn AbstractReceiver> {
    let (path, dump_csv) = parse_common(&config);
    let interval = config.get("interval").and_then(|v| v.as_u64()).unwrap_or(1000000);
    let name = format!("tc_bb_emulation_{}", interval);
    let analyzer = Box::new(BBAnalyzer::new(name.clone(), path, dump_csv));
    Box::new(EmulationReceiver::new(bus_rx, name, Box::new(TCEmulator::new(analyzer, interval))))
}
crate::register_receiver!("tc_bb_emulation", tc_bb_emulation_factory);

// --- Func-level factories ---

pub fn tnt_cyc_nret_func_emulation_factory(
    shared: &Shared, config: serde_json::Value, bus_rx: BusReader<Entry>,
) -> Box<dyn AbstractReceiver> {
    let (path, dump_csv) = parse_common(&config);
    let lim_tnt = config.get("lim_tnt").and_then(|v| v.as_u64()).unwrap_or(6);
    let name = format!("tnt_cyc_nret_func_emulation_{}", lim_tnt);
    let analyzer = Box::new(FuncAnalyzer::new(name.clone(), path, dump_csv, Arc::clone(&shared.symbol_index)));
    Box::new(EmulationReceiver::new(bus_rx, name, Box::new(TNTCycNRETEmulator::new(analyzer, lim_tnt))))
}
crate::register_receiver!("tnt_cyc_nret_func_emulation", tnt_cyc_nret_func_emulation_factory);

pub fn tnt_cyc_retcompressed_func_emulation_factory(
    shared: &Shared, config: serde_json::Value, bus_rx: BusReader<Entry>,
) -> Box<dyn AbstractReceiver> {
    let (path, dump_csv) = parse_common(&config);
    let lim_tnt = config.get("lim_tnt").and_then(|v| v.as_u64()).unwrap_or(6);
    let name = format!("tnt_cyc_retcompressed_func_emulation_{}", lim_tnt);
    let analyzer = Box::new(FuncAnalyzer::new(name.clone(), path, dump_csv, Arc::clone(&shared.symbol_index)));
    Box::new(EmulationReceiver::new(bus_rx, name, Box::new(TNTCycRETCompressedEmulator::new(analyzer, lim_tnt))))
}
crate::register_receiver!("tnt_cyc_retcompressed_func_emulation", tnt_cyc_retcompressed_func_emulation_factory);

pub fn tc_func_emulation_factory(
    shared: &Shared, config: serde_json::Value, bus_rx: BusReader<Entry>,
) -> Box<dyn AbstractReceiver> {
    let (path, dump_csv) = parse_common(&config);
    let interval = config.get("interval").and_then(|v| v.as_u64()).unwrap_or(1000000);
    let name = format!("tc_func_emulation_{}", interval);
    let analyzer = Box::new(FuncAnalyzer::new(name.clone(), path, dump_csv, Arc::clone(&shared.symbol_index)));
    Box::new(EmulationReceiver::new(bus_rx, name, Box::new(TCEmulator::new(analyzer, interval))))
}
crate::register_receiver!("tc_func_emulation", tc_func_emulation_factory);
