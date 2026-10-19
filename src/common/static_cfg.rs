use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct DecoderStaticCfg {
    pub encoded_trace: String,
    pub user_binaries: Vec<UserBinaryCfg>,
    pub machine_binary: String,
    pub kernel_binary: String,
    pub kernel_jump_label_patch_log: String,
    pub driver_binary_entry_tuples: Vec<(String, String)>,
    pub receivers: HashMap<String, serde_json::Value>,
    // list of emulation pipelines: each spec bundles an emulated trace format
    // with its error analyzers and chained receivers (see emulation_pipeline.rs)
    pub emulations: Vec<serde_json::Value>,
    // the trace may start mid-stream (a wrapped DMA ring buffer): start decoding at
    // its first valid Sync Periodic checkpoint (see frontend/resync.rs)
    pub resync_periodic: bool,
}

pub fn load_file_config(path: &str) -> Result<DecoderStaticCfg> {
    let f = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(f);
    let cfg: DecoderStaticCfg = serde_json::from_reader(reader)?;
    Ok(cfg)
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct UserBinaryCfg {
    pub binary: String,
    pub asids: Vec<u64>,
}
