use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;
use irium_node_rs::activation::{
    network_kind_from_env, resolved_htlcv1_activation_height, resolved_lwma_activation_height,
    resolved_lwma_v2_activation_height,
};
use irium_node_rs::chain::{block_from_locked, ChainParams, ChainState, LwmaParams};
use irium_node_rs::genesis::load_locked_genesis;
use irium_node_rs::mempool::MempoolManager;
use irium_node_rs::p2p::P2PNode;
use irium_node_rs::pow::Target;

/// Simple standalone P2P runner that mirrors the Python reference logs.
#[tokio::main]
async fn main() {
    fn mempool_file() -> PathBuf {
        if let Ok(path) = std::env::var("IRIUM_MEMPOOL_FILE") {
            PathBuf::from(path)
        } else {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/".to_string());
            PathBuf::from(home).join(".irium/mempool/pending.json")
        }
    }

    // Build minimal chain + mempool context so peer handshakes can advertise height
    // and accept transaction inventory.
    let locked = load_locked_genesis().expect("load locked genesis");
    let block = match block_from_locked(&locked) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Failed to build genesis block from locked config: {e}");
            return;
        }
    };
    let pow_limit = Target { bits: 0x1d00_ffff };
    let network = network_kind_from_env();
    let params = ChainParams {
        genesis_block: block,
        pow_limit,
        htlcv1_activation_height: resolved_htlcv1_activation_height(network),
        mpsov1_activation_height: None,
        lwma: LwmaParams::new(resolved_lwma_activation_height(network), pow_limit),
        lwma_v2: resolved_lwma_v2_activation_height(network)
            .map(|h| LwmaParams::new_v2(Some(h), pow_limit)),
        auxpow_activation_height: irium_node_rs::activation::resolved_auxpow_activation_height(network),
            btc_spv: None,
            ltc_spv: None,
            htlc_btc_swap_v1_activation_height: None,
            btc_swap_bech32_payment_activation_height: None,
            htlc_ltc_swap_v1_activation_height: None,
            swap_order_v1_activation_height: None,
            ltc_swap_order_v1_activation_height: None,
            coinbase_header_batch_activation_height: None,
    };
    let chain = Arc::new(Mutex::new(ChainState::new(params)));
    let mempool = Arc::new(Mutex::new(MempoolManager::new(mempool_file(), 1000, 100.0, 10_000)));

    let bind: SocketAddr = std::env::var("IRIUM_P2P_BIND")
        .unwrap_or_else(|_| {
            eprintln!("Error: IRIUM_P2P_BIND must be set (e.g. export IRIUM_P2P_BIND=0.0.0.0:38291)");
            std::process::exit(1);
        })
        .parse()
        .expect("valid bind address");
    let agent = std::env::var("IRIUM_NODE_AGENT").unwrap_or_else(|_| "Irium-Rust".to_string());
    let relay_address = std::env::var("IRIUM_RELAY_ADDRESS").ok();
    let marketplace_feed_url: Option<String> = std::env::var("IRIUM_MARKETPLACE_FEED_URL").ok();
    let external_endpoint: Option<String> = std::env::var("IRIUM_EXTERNAL_ENDPOINT")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    println!(
        "[{}] 🚀 Starting Irium P2P node on {} (agent {})",
        Utc::now().format("%H:%M:%S"),
        bind,
        agent
    );
    println!(
        "[{}] 🔗 chain initialized at height {}",
        Utc::now().format("%H:%M:%S"),
        chain.lock().unwrap_or_else(|e| e.into_inner()).tip_height()
    );

    let node = P2PNode::new(
        bind,
        agent.clone(),
        Some(chain.clone()),
        Some(mempool.clone()),
        relay_address,
        marketplace_feed_url,
        external_endpoint,
    );
    if let Err(e) = node.start().await {
        eprintln!("Failed to start P2P listener: {e}");
        return;
    }

    // Optional comma-separated seed list: "host1:port,host2:port".
    let seeds: Vec<SocketAddr> = std::env::var("IRIUM_P2P_SEEDS")
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    if !seeds.is_empty() {
        let agent_clone = agent.clone();
        let chain_clone = chain.clone();
        let node_clone = node.clone();
        tokio::spawn(async move {
            for addr in seeds {
                let h = chain_clone
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .tip_height();
                if let Err(e) = node_clone
                    .connect_and_handshake(addr, h, &agent_clone)
                    .await
                {
                    eprintln!("Failed outbound handshake with {addr}: {e}");
                }
            }
        });
    }

    // Heartbeat similar to the Python reference output so operators can observe liveness.
    let node_clone = node.clone();
    tokio::spawn(async move {
        loop {
            let peers = node_clone.peers_snapshot().await;
            let height = chain.lock().unwrap_or_else(|e| e.into_inner()).tip_height();
            let seeds = irium_node_rs::network::SeedlistManager::new(128).merged_seedlist();
            println!(
                "[{}] 🔁 height={} peers={} seeds={} [{}]",
                Utc::now().format("%H:%M:%S"),
                height,
                peers.len(),
                seeds.len(),
                seeds.iter().take(5).cloned().collect::<Vec<_>>().join(", ")
            );
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    // Keep process alive.
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}
