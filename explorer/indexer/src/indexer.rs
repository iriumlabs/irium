
use anyhow::Result;
use sqlx::PgPool;
use std::collections::HashMap;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::db::{read, write};
use crate::rpc::RpcClient;

pub async fn run(pool: PgPool, rpc: RpcClient, cfg: Config) -> Result<()> {
    info!("indexer started");
    loop {
        match sync_once(&pool, &rpc, &cfg).await {
            Ok(indexed) => {
                if indexed == 0 {
                    tokio::time::sleep(
                        std::time::Duration::from_millis(cfg.poll_interval_ms)
                    ).await;
                }
            }
            Err(e) => {
                error!("sync error: {e:#}");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    }
}

async fn sync_once(pool: &PgPool, rpc: &RpcClient, cfg: &Config) -> Result<u64> {
    let status = rpc.get_status().await?;
    let chain_height = status.height;

    let (mut synced_height, synced_hash) = read::get_indexer_state(pool).await?;

    if synced_height >= 0 {
        let scan_from = (synced_height - cfg.reorg_scan_depth as i64).max(0);
        let tip_hash_hint = (status.best_header_tip.height == synced_height)
            .then_some(status.best_header_tip.hash.as_str());
        match detect_reorg(
            pool,
            rpc,
            scan_from,
            synced_height,
            &synced_hash,
            tip_hash_hint,
        ).await {
            Ok(None) => {}
            Ok(Some((fork_height, _fork_hash))) => {
                warn!("reorg detected at height {fork_height}, rolling back");
                write::rollback_above(pool, fork_height).await?;
                synced_height = fork_height;
            }
            Err(e) => return Err(e),
        }
    }

    if synced_height >= chain_height { return Ok(0); }

    let from = (synced_height + 1).max(0);
    let count = ((chain_height - from + 1) as u64).min(cfg.batch_size);
    info!("indexing heights {from}..{}", from + count as i64 - 1);

    let resp = rpc.get_blocks(from, count).await?;
    let mut indexed = 0u64;
    for block in &resp.blocks {
        write::index_block(pool, block).await?;
        indexed += 1;
        if indexed % 100 == 0 {
            info!("  indexed {indexed} blocks (height {})", block.height);
        }
    }
    info!("batch done: {indexed} blocks");
    Ok(indexed)
}

async fn detect_reorg(
    pool: &PgPool,
    rpc: &RpcClient,
    scan_from: i64,
    synced_height: i64,
    synced_hash: &str,
    tip_hash_hint: Option<&str>,
) -> Result<Option<(i64, String)>> {
    if synced_hash.is_empty() { return Ok(None); }

    let tip_matches = match tip_hash_hint {
        Some(node_tip_hash) => node_tip_hash == synced_hash,
        None => {
            let resp = rpc.get_blocks(synced_height, 1).await?;
            let tip = resp.blocks.first().ok_or_else(|| anyhow::anyhow!(
                "node returned no block at indexed height {synced_height}"
            ))?;
            tip.header.hash == synced_hash
        }
    };
    if tip_matches { return Ok(None); }

    let count = (synced_height - scan_from + 1).max(1) as u64;
    let node_blocks = rpc.get_blocks(scan_from, count).await?;
    let indexed_hashes = read::get_block_hashes(pool, scan_from, synced_height).await?;
    find_common_ancestor(&indexed_hashes, &node_blocks.blocks)
        .map(Some)
        .ok_or_else(|| anyhow::anyhow!(
            "no common ancestor in reorg scan window {scan_from}..={synced_height}"
        ))
}

fn find_common_ancestor(
    indexed_hashes: &[(i64, String)],
    node_blocks: &[crate::rpc::RpcBlock],
) -> Option<(i64, String)> {
    let indexed: HashMap<i64, &str> = indexed_hashes
        .iter()
        .map(|(height, hash)| (*height, hash.as_str()))
        .collect();

    node_blocks
        .iter()
        .rev()
        .find(|block| indexed.get(&block.height).is_some_and(|hash| *hash == block.header.hash))
        .map(|block| (block.height, block.header.hash.clone()))
}

#[cfg(test)]
mod tests {
    use super::find_common_ancestor;
    use crate::rpc::{RpcBlock, RpcHeader};

    fn block(height: i64, hash: &str) -> RpcBlock {
        RpcBlock {
            height,
            miner_address: None,
            tx_hex: vec![],
            header: RpcHeader {
                hash: hash.to_string(),
                prev_hash: String::new(),
                merkle_root: String::new(),
                time: 0,
                bits: String::new(),
                nonce: 0,
                version: 0,
            },
            auxpow_hex: None,
        }
    }

    #[test]
    fn finds_highest_actual_common_ancestor() {
        let indexed = vec![
            (10, "a10".to_string()),
            (11, "a11".to_string()),
            (12, "old12".to_string()),
        ];
        let node = vec![block(10, "a10"), block(11, "a11"), block(12, "new12")];

        assert_eq!(find_common_ancestor(&indexed, &node), Some((11, "a11".to_string())));
    }

    #[test]
    fn fails_closed_when_scan_window_has_no_common_block() {
        let indexed = vec![(10, "old10".to_string())];
        let node = vec![block(10, "new10")];

        assert_eq!(find_common_ancestor(&indexed, &node), None);
    }
}
