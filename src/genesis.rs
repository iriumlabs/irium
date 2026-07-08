use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
pub struct GenesisHeader {
    pub version: u32,
    pub prev_hash: String,
    pub merkle_root: String,
    pub time: u64,
    pub bits: String,
    pub nonce: u32,
    pub hash: String,
}

#[derive(Debug, Deserialize)]
pub struct LockedGenesis {
    #[allow(dead_code)]
    pub height: u64,
    pub header: GenesisHeader,
    #[serde(default)]
    pub transactions: Vec<String>,
}

#[derive(thiserror::Error, Debug)]
pub enum GenesisError {
    #[error("failed to read genesis file: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to parse genesis JSON: {0}")]
    Json(#[from] serde_json::Error),
}

#[allow(dead_code)] // dev/test utility for locating repo root at runtime; kept for tooling
pub fn repo_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if manifest_dir.join("configs").join("genesis-locked.json").exists() {
        return manifest_dir;
    }
    if let Ok(exe) = std::env::current_exe() {
        for candidate in exe.ancestors().skip(1).take(3) {
            if candidate.join("configs").join("genesis-locked.json").exists() {
                return candidate.to_path_buf();
            }
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        if cwd.join("configs").join("genesis-locked.json").exists() {
            return cwd;
        }
    }
    manifest_dir
}

#[allow(dead_code)] // path-based genesis loader; production uses include_str! but kept for external tooling
pub fn locked_genesis_path() -> PathBuf {
    repo_root().join("configs").join("genesis-locked.json")
}

pub fn load_locked_genesis() -> Result<LockedGenesis, GenesisError> {
    static GENESIS_JSON: &str = include_str!("../configs/genesis-locked.json");
    Ok(serde_json::from_str(GENESIS_JSON)?)
}
