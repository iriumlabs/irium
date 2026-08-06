
use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub struct Config {
    pub rpc_url: String,
    pub database_url: String,
    /// Blocks fetched per RPC batch (max 500)
    pub batch_size: u64,
    /// Milliseconds to wait between sync loops when caught up
    pub poll_interval_ms: u64,
    /// How far back to scan when a reorg is detected
    pub reorg_scan_depth: u64,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let rpc_url = env("IRIUMD_RPC_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:38300".to_string());
        let database_url = env("DATABASE_URL")
            .context("DATABASE_URL must be set")?;
        let batch_size: u64 = env("INDEXER_BATCH_SIZE")
            .unwrap_or_else(|_| "500".to_string())
            .parse()
            .context("INDEXER_BATCH_SIZE must be a positive integer")?;
        let poll_interval_ms: u64 = env("INDEXER_POLL_MS")
            .unwrap_or_else(|_| "2000".to_string())
            .parse()
            .context("INDEXER_POLL_MS must be a positive integer")?;
        let reorg_scan_depth: u64 = env("INDEXER_REORG_DEPTH")
            .unwrap_or_else(|_| "499".to_string())
            .parse()
            .context("INDEXER_REORG_DEPTH must be a positive integer")?;
        if !(1..=499).contains(&reorg_scan_depth) {
            anyhow::bail!("INDEXER_REORG_DEPTH must be between 1 and 499");
        }
        Ok(Self { rpc_url, database_url, batch_size, poll_interval_ms, reorg_scan_depth })
    }
}

fn env(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("{key} not set"))
}
