use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};

use chrono::Utc;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{tcp::OwnedWriteHalf, TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, Semaphore};

use crate::block::{Block, BlockHeader};
use crate::chain::classify_tx_priority;
use crate::chain::whatsminer_compat_pow_hash_for_height;
use crate::chain::ChainState;
use crate::mempool::{evict_invalid_mempool_entries, MempoolManager};
use crate::network::{PeerDirectory, PeerRecord};
use crate::pow::meets_target;
use crate::protocol::{
    BlockPayload, EmptyPayload, GetBlocksPayload, GetDataPayload, GetHeadersPayload,
    HandshakePayload, HeadersPayload, InvPayload, MempoolPayload, Message, MessageType,
    PeersPayload, PingPayload, RelayAddressPayload, TxPayload, UptimeChallengePayload,
    UptimeProofPayload, MAX_BLOCKS_PER_REQUEST, MAX_HEADERS_PER_REQUEST, MAX_MESSAGE_SIZE,
};
use crate::reputation::ReputationManager;
use crate::storage;
use crate::sybil::{SybilChallenge, SybilProof, SybilResistantHandshake};
use crate::tx::decode_full_tx;
use hex;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use serde_json::json;
use sha2::{Digest, Sha256};

// Global 60s throttle for "unsolicited headers ignored" log emission.
// The per-peer last_unsolicited_log field below already throttles each
// peer to ~once/30s, but with many connected peers the aggregate rate
// is still ~10 lines/minute. Real value is in the RATE not per-event
// detail — collapse to one log line per minute globally.
static LAST_UNSOLICITED_LOG_GLOBAL: AtomicU64 = AtomicU64::new(0);

fn should_emit_unsolicited_headers_log() -> bool {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let last = LAST_UNSOLICITED_LOG_GLOBAL.load(Ordering::Relaxed);
    if now_secs.saturating_sub(last) >= 60 {
        LAST_UNSOLICITED_LOG_GLOBAL.store(now_secs, Ordering::Relaxed);
        true
    } else {
        false
    }
}

/// Minimal P2P node skeleton: accepts incoming connections and can
/// broadcast raw block bytes to all connected peers.
const DEFAULT_MAX_PEERS: usize = 100;
/// Cap on peers returned per GetPeers response to prevent unbounded serialisation.
const MAX_PEERS_IN_RESPONSE: usize = 50;
const MAX_ADDR_PUSH: usize = 1000;
const MAX_MSGS_PER_SEC: u32 = 200;
const MAX_BULK_MSGS_PER_SEC: u32 = 2000;

fn is_same_subnet_24(a: IpAddr, b: IpAddr) -> bool {
    match (a, b) {
        (IpAddr::V4(a4), IpAddr::V4(b4)) => a4.octets()[..3] == b4.octets()[..3],
        _ => false,
    }
}

fn recent_block_cache_ttl() -> Duration {
    let secs = std::env::var("IRIUM_P2P_RECENT_BLOCK_TTL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(30)
        .clamp(5, 300);
    Duration::from_secs(secs)
}

fn recent_block_cache_limit() -> usize {
    std::env::var("IRIUM_P2P_RECENT_BLOCK_CACHE_LIMIT")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(256)
        .clamp(32, 4096)
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RelayTelemetrySnapshot {
    pub new_tip_announced_count: u64,
    pub block_announce_peers_count_total: u64,
    pub block_request_count: u64,
    pub duplicate_block_suppressed_count: u64,
    pub avg_block_processing_ms: u64,
    pub avg_block_announce_delay_ms: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PeerTelemetrySnapshot {
    pub outbound_dial_attempts_total: u64,
    pub outbound_dial_success_total: u64,
    pub outbound_dial_failure_total: u64,
    pub outbound_dial_failure_timeout_total: u64,
    pub outbound_dial_failure_refused_total: u64,
    pub outbound_dial_failure_no_route_total: u64,
    pub outbound_dial_failure_banned_total: u64,
    pub outbound_dial_failure_backoff_total: u64,
    pub outbound_dial_failure_other_total: u64,
    pub inbound_accepted_total: u64,
    pub handshake_failures_total: u64,
    pub temp_bans_total: u64,
    pub active_peers: u64,
    pub unique_connected_peer_ips: u64,
    pub attempted_peer_ips: u64,
    pub banned_peers: u64,
}

#[derive(Debug)]
struct RecentHashCache {
    ttl: Duration,
    limit: usize,
    seen_at: HashMap<[u8; 32], Instant>,
    order: VecDeque<([u8; 32], Instant)>,
}

fn block_request_cache_key(ip: IpAddr, start_hash: &[u8], count: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"block-request");
    match ip {
        IpAddr::V4(v4) => {
            hasher.update([4u8]);
            hasher.update(v4.octets());
        }
        IpAddr::V6(v6) => {
            hasher.update([6u8]);
            hasher.update(v6.octets());
        }
    }
    hasher.update(count.to_le_bytes());
    hasher.update(start_hash);
    let digest = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

impl RecentHashCache {
    fn new(ttl: Duration, limit: usize) -> Self {
        Self {
            ttl,
            limit,
            seen_at: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn prune(&mut self, now: Instant) {
        while let Some((hash, seen)) = self.order.front().copied() {
            let expired = now.duration_since(seen) > self.ttl;
            let over_limit = self.order.len() > self.limit;
            if !expired && !over_limit {
                break;
            }
            self.order.pop_front();
            if self.seen_at.get(&hash).copied() == Some(seen) {
                self.seen_at.remove(&hash);
            }
        }
    }

    fn record_at(&mut self, hash: [u8; 32], now: Instant) -> bool {
        self.prune(now);
        if self.seen_at.contains_key(&hash) {
            return false;
        }
        self.seen_at.insert(hash, now);
        self.order.push_back((hash, now));
        self.prune(now);
        true
    }

    #[allow(dead_code)]
    fn len(&self) -> usize {
        self.seen_at.len()
    }
}

static NEW_TIP_ANNOUNCED_COUNT: AtomicU64 = AtomicU64::new(0);
static BLOCK_ANNOUNCE_PEERS_COUNT_TOTAL: AtomicU64 = AtomicU64::new(0);
static BLOCK_REQUEST_COUNT: AtomicU64 = AtomicU64::new(0);
static DUPLICATE_BLOCK_SUPPRESSED_COUNT: AtomicU64 = AtomicU64::new(0);
static BLOCK_PROCESSING_MS_TOTAL: AtomicU64 = AtomicU64::new(0);
static BLOCK_PROCESSING_SAMPLES: AtomicU64 = AtomicU64::new(0);
static BLOCK_ANNOUNCE_DELAY_MS_TOTAL: AtomicU64 = AtomicU64::new(0);
static BLOCK_ANNOUNCE_DELAY_SAMPLES: AtomicU64 = AtomicU64::new(0);
static OUTBOUND_DIAL_ATTEMPTS_TOTAL: AtomicU64 = AtomicU64::new(0);
static OUTBOUND_DIAL_SUCCESS_TOTAL: AtomicU64 = AtomicU64::new(0);
static OUTBOUND_DIAL_FAILURE_TOTAL: AtomicU64 = AtomicU64::new(0);
static OUTBOUND_DIAL_FAILURE_TIMEOUT_TOTAL: AtomicU64 = AtomicU64::new(0);
static OUTBOUND_DIAL_FAILURE_REFUSED_TOTAL: AtomicU64 = AtomicU64::new(0);
static OUTBOUND_DIAL_FAILURE_NO_ROUTE_TOTAL: AtomicU64 = AtomicU64::new(0);
static OUTBOUND_DIAL_FAILURE_BANNED_TOTAL: AtomicU64 = AtomicU64::new(0);
static OUTBOUND_DIAL_FAILURE_BACKOFF_TOTAL: AtomicU64 = AtomicU64::new(0);
static OUTBOUND_DIAL_FAILURE_OTHER_TOTAL: AtomicU64 = AtomicU64::new(0);
static INBOUND_ACCEPTED_TOTAL: AtomicU64 = AtomicU64::new(0);
static HANDSHAKE_FAILURE_TOTAL: AtomicU64 = AtomicU64::new(0);
static TEMP_BAN_TOTAL: AtomicU64 = AtomicU64::new(0);

fn record_block_processing_ms(ms: u64) {
    BLOCK_PROCESSING_MS_TOTAL.fetch_add(ms, Ordering::Relaxed);
    BLOCK_PROCESSING_SAMPLES.fetch_add(1, Ordering::Relaxed);
}

fn record_block_announce_delay_ms(ms: u64) {
    BLOCK_ANNOUNCE_DELAY_MS_TOTAL.fetch_add(ms, Ordering::Relaxed);
    BLOCK_ANNOUNCE_DELAY_SAMPLES.fetch_add(1, Ordering::Relaxed);
}

fn average_counter(total: &AtomicU64, samples: &AtomicU64) -> u64 {
    let s = samples.load(Ordering::Relaxed);
    if s == 0 {
        0
    } else {
        total.load(Ordering::Relaxed) / s
    }
}

fn classify_outbound_dial_failure(err: &str) -> &'static str {
    let lower = err.to_ascii_lowercase();
    if lower.contains("dial backoff") || lower.contains("dial in progress") {
        "backoff"
    } else if lower.contains("timeout") {
        "timeout"
    } else if lower.contains("connection refused") || lower.contains("refused") {
        "refused"
    } else if lower.contains("no route to host") {
        "no_route"
    } else if lower.contains("banned") {
        "banned"
    } else {
        "other"
    }
}

fn recent_announced_blocks() -> Arc<Mutex<RecentHashCache>> {
    static VAL: OnceLock<Arc<Mutex<RecentHashCache>>> = OnceLock::new();
    VAL.get_or_init(|| {
        Arc::new(Mutex::new(RecentHashCache::new(
            recent_block_cache_ttl(),
            recent_block_cache_limit(),
        )))
    })
    .clone()
}

fn recent_requested_blocks() -> Arc<Mutex<RecentHashCache>> {
    static VAL: OnceLock<Arc<Mutex<RecentHashCache>>> = OnceLock::new();
    VAL.get_or_init(|| {
        Arc::new(Mutex::new(RecentHashCache::new(
            recent_block_cache_ttl(),
            recent_block_cache_limit(),
        )))
    })
    .clone()
}

fn recent_relayed_blocks() -> Arc<Mutex<RecentHashCache>> {
    static VAL: OnceLock<Arc<Mutex<RecentHashCache>>> = OnceLock::new();
    VAL.get_or_init(|| {
        Arc::new(Mutex::new(RecentHashCache::new(
            recent_block_cache_ttl(),
            recent_block_cache_limit(),
        )))
    })
    .clone()
}

fn p2p_blocking_concurrency() -> usize {
    std::env::var("IRIUM_P2P_BLOCKING_CONCURRENCY")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(2)
        .clamp(1, 32)
}

fn p2p_blocking_sem() -> Arc<Semaphore> {
    static VAL: OnceLock<Arc<Semaphore>> = OnceLock::new();
    VAL.get_or_init(|| Arc::new(Semaphore::new(p2p_blocking_concurrency())))
        .clone()
}

async fn spawn_blocking_limited<T, F>(f: F) -> Result<T, tokio::task::JoinError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let sem = p2p_blocking_sem();
    let permit = match sem.acquire_owned().await {
        Ok(p) => p,
        Err(_) => return tokio::task::spawn_blocking(f).await,
    };
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        f()
    })
    .await
}

#[derive(Clone)]
struct PersistTask {
    height: u64,
    hash: [u8; 32],
    block: Block,
    enqueued_at: Instant,
}

#[derive(Default)]
struct SyncPerf {
    blocks: u64,
    decode_ms: u128,
    precheck_ms: u128,
    connect_ms: u128,
    persist_ms: u128,
    start: Option<Instant>,
}

fn sync_perf_state() -> &'static StdMutex<SyncPerf> {
    static VAL: OnceLock<StdMutex<SyncPerf>> = OnceLock::new();
    VAL.get_or_init(|| StdMutex::new(SyncPerf::default()))
}

fn sync_perf_record(decode: u128, precheck: u128, connect: u128, persist: u128) {
    let m = sync_perf_state();
    let mut g = m.lock().unwrap_or_else(|e| e.into_inner());
    if g.start.is_none() {
        g.start = Some(Instant::now());
    }
    g.blocks = g.blocks.saturating_add(1);
    g.decode_ms = g.decode_ms.saturating_add(decode);
    g.precheck_ms = g.precheck_ms.saturating_add(precheck);
    g.connect_ms = g.connect_ms.saturating_add(connect);
    g.persist_ms = g.persist_ms.saturating_add(persist);
    if g.blocks.is_multiple_of(100) {
        let elapsed = g.start.map(|t| t.elapsed().as_secs_f64()).unwrap_or(0.0);
        let bps = if elapsed > 0.0 {
            g.blocks as f64 / elapsed
        } else {
            0.0
        };
        P2PNode::log_event(
            "info",
            "sync",
            format!(
                "sync perf: blocks={} bps={:.2} decode_ms={} precheck_ms={} connect_ms={} persist_ms={}",
                g.blocks, bps, g.decode_ms, g.precheck_ms, g.connect_ms, g.persist_ms
            ),
        );
    }
}

fn persist_queue_capacity() -> usize {
    std::env::var("IRIUM_PERSIST_QUEUE_CAPACITY")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(2048)
        .clamp(64, 16384)
}

fn persist_tx() -> mpsc::Sender<PersistTask> {
    static TX: OnceLock<mpsc::Sender<PersistTask>> = OnceLock::new();
    if let Some(tx) = TX.get() {
        return tx.clone();
    }
    let (tx, mut rx) = mpsc::channel::<PersistTask>(persist_queue_capacity());
    let _ = TX.set(tx.clone());
    tokio::spawn(async move {
        while let Some(task) = rx.recv().await {
            let started = Instant::now();
            let h = task.height;
            let bh = task.hash;
            let b = task.block;
            let write_res = spawn_blocking_limited(move || storage::write_block_json(h, &b)).await;
            let persist_ms = started.elapsed().as_millis();
            if let Ok(Err(e)) = write_res {
                let short = {
                    let hx = hex::encode(bh);
                    hx.get(0..12).unwrap_or(&hx).to_string()
                };
                P2PNode::log_event(
                    "warn",
                    "chain",
                    format!("persist failed for block {} at {}: {}", short, h, e),
                );
            }
            let queue_wait_ms = task.enqueued_at.elapsed().as_millis();
            sync_perf_record(0, 0, 0, persist_ms.saturating_add(queue_wait_ms));
        }
    });
    tx
}

async fn enqueue_persist_block(height: u64, hash: [u8; 32], block: Block) {
    let tx = persist_tx();
    let _ = tx
        .send(PersistTask {
            height,
            hash,
            block,
            enqueued_at: Instant::now(),
        })
        .await;
}

fn stateless_block_precheck(block: &Block, height: u64) -> Result<(), String> {
    let hash = block.header.hash_for_height(height);
    if !meets_target(&hash, block.header.target())
        && !whatsminer_compat_pow_hash_for_height(&block.header, height)
            .as_ref()
            .map(|h| meets_target(h, block.header.target()))
            .unwrap_or(false)
    {
        return Err("pow precheck failed".to_string());
    }
    if block.header.prev_hash != [0u8; 32] {
        let merkle = block.merkle_root();
        if block.header.merkle_root != merkle {
            return Err("merkle precheck failed".to_string());
        }
    }
    Ok(())
}

fn sync_cooldown() -> Duration {
    let secs = std::env::var("IRIUM_P2P_SYNC_COOLDOWN_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(2);
    Duration::from_secs(secs.max(1).min(300))
}

fn sync_cooldown_for(local_height: u64, peer_height: u64) -> Duration {
    let base = sync_cooldown();
    if peer_height <= local_height {
        return base;
    }
    let gap = peer_height.saturating_sub(local_height);
    let secs = if gap >= 10_000 {
        1
    } else if gap >= 1_000 {
        2
    } else if gap >= 100 {
        3
    } else if gap >= 10 {
        5
    } else {
        base.as_secs()
    };
    Duration::from_secs(secs.max(1).min(300))
}

fn outbound_dial_base_secs() -> u64 {
    std::env::var("IRIUM_SEED_DIAL_BASE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(2)
        .clamp(1, 30)
}

fn outbound_dial_max_secs() -> u64 {
    std::env::var("IRIUM_SEED_DIAL_MAX_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(300)
        .clamp(30, 3600)
}

fn outbound_dial_banned_secs() -> u64 {
    std::env::var("IRIUM_SEED_DIAL_BANNED_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(120)
        .clamp(30, 7200)
}

fn dynamic_ban_secs() -> u64 {
    std::env::var("IRIUM_P2P_TEMP_BAN_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(120)
        .clamp(30, 3600)
}

fn small_network_peer_floor() -> usize {
    std::env::var("IRIUM_P2P_SMALL_NETWORK_PEERS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(12)
        .clamp(2, 64)
}

fn small_network_handshake_fail_threshold() -> u32 {
    std::env::var("IRIUM_P2P_SMALL_NETWORK_HANDSHAKE_FAIL_THRESHOLD")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(10)
        .clamp(5, 50)
}

fn outbound_candidate_max_idle_hours() -> f64 {
    std::env::var("IRIUM_P2P_CANDIDATE_MAX_IDLE_HOURS")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(72.0)
        .clamp(1.0, 24.0 * 30.0)
}

fn connect_known_peer_scan_limit_ahead() -> usize {
    std::env::var("IRIUM_P2P_KNOWN_PEER_AHEAD_SCAN_LIMIT")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(128)
        .clamp(8, 1024)
}

fn connect_known_peer_scan_limit_fallback() -> usize {
    std::env::var("IRIUM_P2P_KNOWN_PEER_FALLBACK_SCAN_LIMIT")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(64)
        .clamp(8, 1024)
}

fn inbound_banned_log_cooldown_secs() -> u64 {
    static VAL: OnceLock<u64> = OnceLock::new();
    *VAL.get_or_init(|| {
        std::env::var("IRIUM_P2P_BANNED_LOG_COOLDOWN_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(|v| v.max(1).min(3600))
            .unwrap_or(120)
    })
}

fn handshake_error_log_cooldown_secs() -> u64 {
    static VAL: OnceLock<u64> = OnceLock::new();
    *VAL.get_or_init(|| {
        std::env::var("IRIUM_P2P_HANDSHAKE_LOG_COOLDOWN_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(|v| v.max(1).min(3600))
            .unwrap_or(20)
    })
}

fn send_blocks_log_cooldown_secs() -> u64 {
    static VAL: OnceLock<u64> = OnceLock::new();
    *VAL.get_or_init(|| {
        std::env::var("IRIUM_P2P_SEND_BLOCKS_LOG_COOLDOWN_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(|v| v.max(1).min(3600))
            .unwrap_or(15)
    })
}

fn incoming_conn_log_cooldown_secs() -> u64 {
    static VAL: OnceLock<u64> = OnceLock::new();
    *VAL.get_or_init(|| {
        std::env::var("IRIUM_P2P_INCOMING_LOG_COOLDOWN_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(|v| v.max(1).min(3600))
            .unwrap_or(120)
    })
}

fn headers_batch_log_cooldown_secs() -> u64 {
    static VAL: OnceLock<u64> = OnceLock::new();
    *VAL.get_or_init(|| {
        std::env::var("IRIUM_P2P_HEADERS_BATCH_LOG_COOLDOWN_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(|v| v.max(1).min(3600))
            .unwrap_or(30)
    })
}

fn incoming_conn_log_enabled() -> bool {
    static VAL: OnceLock<bool> = OnceLock::new();
    *VAL.get_or_init(|| {
        std::env::var("IRIUM_P2P_LOG_INCOMING")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(true)
    })
}

fn no_getblocks_log_cooldown_secs() -> u64 {
    static VAL: OnceLock<u64> = OnceLock::new();
    *VAL.get_or_init(|| {
        std::env::var("IRIUM_P2P_NO_GETBLOCKS_LOG_COOLDOWN_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(|v| v.max(1).min(3600))
            .unwrap_or(180)
    })
}

fn unknown_start_log_cooldown_secs() -> u64 {
    static VAL: OnceLock<u64> = OnceLock::new();
    *VAL.get_or_init(|| {
        std::env::var("IRIUM_P2P_UNKNOWN_START_LOG_COOLDOWN_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(|v| v.max(1).min(3600))
            .unwrap_or(120)
    })
}

fn headers_new_false_log_cooldown_secs() -> u64 {
    static VAL: OnceLock<u64> = OnceLock::new();
    *VAL.get_or_init(|| {
        std::env::var("IRIUM_P2P_HEADERS_NEW_FALSE_LOG_COOLDOWN_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(|v| v.max(1).min(3600))
            .unwrap_or(90)
    })
}

fn headers_new_true_log_cooldown_secs() -> u64 {
    static VAL: OnceLock<u64> = OnceLock::new();
    *VAL.get_or_init(|| {
        std::env::var("IRIUM_P2P_HEADERS_NEW_TRUE_LOG_COOLDOWN_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(|v| v.max(1).min(3600))
            .unwrap_or(120)
    })
}

fn header_state_log_cooldown_secs() -> u64 {
    static VAL: OnceLock<u64> = OnceLock::new();
    *VAL.get_or_init(|| {
        std::env::var("IRIUM_P2P_HEADER_STATE_LOG_COOLDOWN_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(|v| v.max(1).min(3600))
            .unwrap_or(60)
    })
}

fn orphan_header_log_cooldown_secs() -> u64 {
    static VAL: OnceLock<u64> = OnceLock::new();
    *VAL.get_or_init(|| {
        std::env::var("IRIUM_P2P_ORPHAN_HEADER_LOG_COOLDOWN_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(|v| v.max(1).min(3600))
            .unwrap_or(30)
    })
}

fn inbound_block_trace_log_cooldown_secs() -> u64 {
    static VAL: OnceLock<u64> = OnceLock::new();
    *VAL.get_or_init(|| {
        std::env::var("IRIUM_P2P_INBOUND_BLOCK_TRACE_LOG_COOLDOWN_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(|v| v.max(1).min(3600))
            .unwrap_or(60)
    })
}

fn locator_recovery_cooldown_secs() -> u64 {
    static VAL: OnceLock<u64> = OnceLock::new();
    *VAL.get_or_init(|| {
        std::env::var("IRIUM_P2P_LOCATOR_RECOVERY_COOLDOWN_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(|v| v.max(1).min(3600))
            .unwrap_or(30)
    })
}

fn locator_recovery_tip_cooldown_secs() -> u64 {
    static VAL: OnceLock<u64> = OnceLock::new();
    *VAL.get_or_init(|| {
        std::env::var("IRIUM_P2P_LOCATOR_RECOVERY_TIP_COOLDOWN_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(|v| v.max(10).min(7200))
            .unwrap_or(600)
    })
}

fn inbound_accept_cooldown_ms() -> u64 {
    static VAL: OnceLock<u64> = OnceLock::new();
    *VAL.get_or_init(|| {
        std::env::var("IRIUM_P2P_INBOUND_ACCEPT_COOLDOWN_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(|v| v.max(100).min(60000))
            .unwrap_or(5000)
    })
}

fn inbound_bulk_queue_capacity() -> usize {
    static VAL: OnceLock<usize> = OnceLock::new();
    *VAL.get_or_init(|| {
        std::env::var("IRIUM_P2P_INBOUND_BULK_QUEUE")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .map(|v| v.max(1).min(512))
            .unwrap_or(256)
    })
}

#[allow(dead_code)]
fn inbound_block_busy_wait_ms() -> u64 {
    static VAL: OnceLock<u64> = OnceLock::new();
    *VAL.get_or_init(|| {
        std::env::var("IRIUM_P2P_INBOUND_BLOCK_BUSY_WAIT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(|v| v.max(10).min(5000))
            .unwrap_or(5000)
    })
}

#[allow(dead_code)]
fn inbound_headers_busy_wait_ms() -> u64 {
    static VAL: OnceLock<u64> = OnceLock::new();
    *VAL.get_or_init(|| {
        std::env::var("IRIUM_P2P_INBOUND_HEADERS_BUSY_WAIT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(|v| v.max(10).min(5000))
            .unwrap_or(300)
    })
}

#[allow(dead_code)]
fn inbound_block_busy_log_cooldown_secs() -> u64 {
    static VAL: OnceLock<u64> = OnceLock::new();
    *VAL.get_or_init(|| {
        std::env::var("IRIUM_P2P_INBOUND_BLOCK_BUSY_LOG_COOLDOWN_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(|v| v.max(1).min(3600))
            .unwrap_or(30)
    })
}

#[allow(dead_code)]
fn inbound_block_busy_log() -> Arc<Mutex<HashMap<IpAddr, Instant>>> {
    static LOGS: OnceLock<Arc<Mutex<HashMap<IpAddr, Instant>>>> = OnceLock::new();
    LOGS.get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
        .clone()
}

#[allow(dead_code)]
fn inbound_headers_busy_log_cooldown_secs() -> u64 {
    static VAL: OnceLock<u64> = OnceLock::new();
    *VAL.get_or_init(|| {
        std::env::var("IRIUM_P2P_INBOUND_HEADERS_BUSY_LOG_COOLDOWN_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(|v| v.max(1).min(3600))
            .unwrap_or(30)
    })
}

#[allow(dead_code)]
fn inbound_headers_busy_log() -> Arc<Mutex<HashMap<IpAddr, Instant>>> {
    static LOGS: OnceLock<Arc<Mutex<HashMap<IpAddr, Instant>>>> = OnceLock::new();
    LOGS.get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
        .clone()
}

fn inbound_bulk_queue() -> Arc<tokio::sync::Semaphore> {
    static SEM: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
    SEM.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(inbound_bulk_queue_capacity())))
        .clone()
}

fn inbound_handshake_concurrency() -> usize {
    static VAL: OnceLock<usize> = OnceLock::new();
    *VAL.get_or_init(|| {
        std::env::var("IRIUM_P2P_INBOUND_HANDSHAKE_CONCURRENCY")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .map(|v| v.max(1).min(1024))
            .unwrap_or(32)
    })
}

fn inbound_handshake_sem() -> Arc<tokio::sync::Semaphore> {
    static SEM: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
    SEM.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(inbound_handshake_concurrency())))
        .clone()
}

fn trusted_seed_inbound_cooldown_secs() -> u64 {
    static VAL: OnceLock<u64> = OnceLock::new();
    *VAL.get_or_init(|| {
        std::env::var("IRIUM_TRUSTED_SEED_INBOUND_COOLDOWN_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(|v| v.max(1).min(60))
            .unwrap_or(10)
    })
}

fn trusted_seed_should_dial(local_ip: IpAddr, remote_ip: IpAddr) -> bool {
    // Deterministic tie-break for official trusted seeds to prevent bidirectional dial storms.
    // Rule: the lower IP dials, the higher IP accepts.
    match (local_ip, remote_ip) {
        (IpAddr::V4(a), IpAddr::V4(b)) => u32::from(a) < u32::from(b),
        // Fall back to a stable textual order for non-IPv4 (shouldn't happen for mainnet seeds).
        (a, b) => a.to_string() < b.to_string(),
    }
}

fn trusted_anchor_peer_id(addr: SocketAddr, _trusted_seed: bool) -> String {
    addr.ip().to_string()
}

async fn sync_request_allowed_for(
    sync_requests: &Arc<Mutex<HashMap<IpAddr, Instant>>>,
    ip: IpAddr,
    local_height: u64,
    peer_height: u64,
) -> bool {
    let cooldown = sync_cooldown_for(local_height, peer_height);
    let mut guard = sync_requests.lock().await;
    let now = Instant::now();
    if let Some(last) = guard.get(&ip) {
        if now.duration_since(*last) < cooldown {
            return false;
        }
    }
    guard.insert(ip, now);
    true
}

#[derive(Clone, Copy, Debug, Default)]
struct PeerSyncPerf {
    score: i32,
    last_progress: Option<Instant>,
    last_update: Option<Instant>,
}

fn peer_sync_perf() -> Arc<Mutex<HashMap<IpAddr, PeerSyncPerf>>> {
    static PERF: OnceLock<Arc<Mutex<HashMap<IpAddr, PeerSyncPerf>>>> = OnceLock::new();
    PERF.get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
        .clone()
}

fn block_range_owner_ttl() -> Duration {
    let secs = std::env::var("IRIUM_P2P_RANGE_OWNER_TTL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(6);
    Duration::from_secs(secs.clamp(2, 30))
}

fn block_range_owners() -> Arc<Mutex<HashMap<Vec<u8>, (IpAddr, Instant)>>> {
    static OWNERS: OnceLock<Arc<Mutex<HashMap<Vec<u8>, (IpAddr, Instant)>>>> = OnceLock::new();
    OWNERS
        .get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
        .clone()
}

async fn peer_block_lock(ip: IpAddr) -> Arc<Mutex<()>> {
    static LOCKS: OnceLock<Arc<Mutex<HashMap<IpAddr, Arc<Mutex<()>>>>>> = OnceLock::new();
    let locks = LOCKS
        .get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
        .clone();
    let mut guard = locks.lock().await;
    guard
        .entry(ip)
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

fn range_key(start_hash: &[u8], count: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(4 + start_hash.len());
    key.extend_from_slice(&count.to_be_bytes());
    key.extend_from_slice(start_hash);
    key
}

async fn claim_block_range_owner(ip: IpAddr, start_hash: &[u8], count: u32) -> bool {
    let owners = block_range_owners();
    let ttl = block_range_owner_ttl();
    let now = Instant::now();
    let key = range_key(start_hash, count);
    let mut guard = owners.lock().await;
    guard.retain(|_, (_, ts)| now.duration_since(*ts) <= ttl);
    if let Some((owner, ts)) = guard.get(&key).copied() {
        if owner != ip && now.duration_since(ts) <= ttl {
            return false;
        }
    }
    guard.insert(key, (ip, now));
    true
}

fn peer_score_gate_enabled() -> bool {
    std::env::var("IRIUM_P2P_PEER_SCORE_GATE")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true)
}

async fn peer_mark_header_event(ip: IpAddr, added_any: bool, header_count: u32) {
    let perf = peer_sync_perf();
    let now = Instant::now();
    let mut guard = perf.lock().await;
    let entry = guard.entry(ip).or_default();
    if added_any {
        entry.score = (entry.score + 1).clamp(-50, 50);
    } else if header_count > 0 {
        entry.score = (entry.score - 2).clamp(-50, 50);
    }
    entry.last_update = Some(now);
}

async fn peer_mark_block_progress(ip: IpAddr) {
    let perf = peer_sync_perf();
    let now = Instant::now();
    let mut guard = perf.lock().await;
    let entry = guard.entry(ip).or_default();
    entry.score = (entry.score + 6).clamp(-50, 50);
    entry.last_progress = Some(now);
    entry.last_update = Some(now);
}

async fn peer_score(ip: IpAddr) -> i32 {
    let perf = peer_sync_perf();
    let guard = perf.lock().await;
    guard.get(&ip).map(|p| p.score).unwrap_or(0)
}

async fn best_peer_score() -> i32 {
    let perf = peer_sync_perf();
    let guard = perf.lock().await;
    guard.values().map(|p| p.score).max().unwrap_or(0)
}

fn header_reject_counters() -> Arc<Mutex<HashMap<String, u64>>> {
    static COUNTERS: OnceLock<Arc<Mutex<HashMap<String, u64>>>> = OnceLock::new();
    COUNTERS
        .get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
        .clone()
}

fn header_reject_streaks() -> Arc<Mutex<HashMap<IpAddr, u32>>> {
    static STREAKS: OnceLock<Arc<Mutex<HashMap<IpAddr, u32>>>> = OnceLock::new();
    STREAKS
        .get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
        .clone()
}

fn header_state_log_gate() -> Arc<Mutex<HashMap<IpAddr, Instant>>> {
    static GATE: OnceLock<Arc<Mutex<HashMap<IpAddr, Instant>>>> = OnceLock::new();
    GATE.get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
        .clone()
}

fn header_state_log_interval() -> Duration {
    Duration::from_secs(30)
}

async fn should_emit_header_state_log(ip: IpAddr) -> bool {
    let gate = header_state_log_gate();
    let mut guard = gate.lock().await;
    let now = Instant::now();
    let interval = header_state_log_interval();
    if let Some(last) = guard.get(&ip) {
        if now.duration_since(*last) < interval {
            return false;
        }
    }
    guard.insert(ip, now);
    true
}

fn classify_header_reject_reason(err: &str) -> String {
    let e = err.to_ascii_lowercase();
    if e.contains("unknown parent") {
        "unknown_parent".to_string()
    } else if e.contains("target") || e.contains("pow") {
        "pow_or_target".to_string()
    } else if e.contains("retarget") {
        "retarget".to_string()
    } else if e.contains("timestamp") {
        "timestamp".to_string()
    } else if e.contains("bits") {
        "bits".to_string()
    } else if e.contains("anchor") {
        "anchors".to_string()
    } else {
        "other".to_string()
    }
}

async fn note_header_reject(ip: IpAddr, reason: &str) -> u32 {
    {
        let counters = header_reject_counters();
        let mut guard = counters.lock().await;
        *guard.entry(reason.to_string()).or_insert(0) += 1;
    }
    let streaks = header_reject_streaks();
    let mut guard = streaks.lock().await;
    let streak = guard.entry(ip).or_insert(0);
    *streak = streak.saturating_add(1);
    *streak
}

async fn clear_header_reject_streak(ip: IpAddr) {
    let streaks = header_reject_streaks();
    let mut guard = streaks.lock().await;
    guard.remove(&ip);
}

async fn top_header_reject_reasons(limit: usize) -> Vec<(String, u64)> {
    let counters = header_reject_counters();
    let guard = counters.lock().await;
    let mut v: Vec<(String, u64)> = guard.iter().map(|(k, v)| (k.clone(), *v)).collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v.truncate(limit);
    v
}

async fn penalize_rejecting_header_peer(ip: IpAddr, streak: u32) {
    let penalty = if streak >= 12 {
        8
    } else if streak >= 8 {
        5
    } else {
        2
    };
    for _ in 0..penalty {
        peer_mark_header_event(ip, false, 1).await;
    }
}

fn normalize_reason_hint(reason_hint: &str, local_h: u64, best_h: u64) -> Option<String> {
    if reason_hint.is_empty() {
        return None;
    }
    if reason_hint == "no_best_header_block_path" && best_h <= local_h {
        return Some("no_block_download_needed_at_tip".to_string());
    }
    Some(reason_hint.to_string())
}

fn trusted_remote_height(peer_h: u64, best_h: u64, local_h: u64) -> u64 {
    // Floor is our own local height — peers behind us are clamped up to local
    // (we trust our own validated tip more than a stale peer claim).
    let floor = local_h;
    // The cap previously clamped peer-advertised height to `best_h.max(local_h)`
    // regardless of whether we actually had validated headers above local. On a
    // fresh restart with `best_h == local_h` this collapses to `cap = local_h`,
    // which forces *every* peer-reported height back down to our own height —
    // even when peers are 200 blocks ahead. That made the "we're behind" check
    // in iriumd.rs's sync loop permanently false (see the periodic escape-hatch
    // burst added there), produced the irium-eu self-perpetuating-tip stall
    // observed on 2026-05-17, and could only be cleared with a nuclear resync.
    //
    // Fix: only apply the upper cap when we genuinely have validated headers
    // strictly above local. Otherwise just floor at local and trust whatever
    // the peer advertised — the sync burst it triggers will validate the
    // claim (or reject it) for real, instead of silently masking it.
    if best_h > local_h {
        let cap = best_h;
        peer_h.max(floor).min(cap)
    } else {
        peer_h.max(floor)
    }
}

fn short_hash(hash: [u8; 32]) -> String {
    let h = hex::encode(hash);
    h.get(0..12).unwrap_or(&h).to_string()
}

async fn best_scored_peer_snapshot() -> Option<(IpAddr, i32)> {
    let perf = peer_sync_perf();
    let guard = perf.lock().await;
    guard
        .iter()
        .max_by(|a, b| a.1.score.cmp(&b.1.score))
        .map(|(ip, p)| (*ip, p.score))
}

#[derive(Default)]
struct HeaderWatchdogState {
    no_best_since: Option<Instant>,
    last_warn: Option<Instant>,
}

fn header_watchdog_state() -> &'static StdMutex<HeaderWatchdogState> {
    static VAL: OnceLock<StdMutex<HeaderWatchdogState>> = OnceLock::new();
    VAL.get_or_init(|| StdMutex::new(HeaderWatchdogState::default()))
}

fn maybe_emit_header_watchdog(
    local_h: u64,
    best_h: u64,
    headers_known: usize,
    reason: &str,
    best_peer: &str,
    this_score: i32,
    headers_inflight: bool,
    headers_processing: bool,
    top_str: &str,
    path_debug: &str,
) {
    let now = Instant::now();
    let mut st = header_watchdog_state()
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let mut should_warn = false;
    let mut watchdog_reason = String::new();

    if headers_known == 0 {
        should_warn = true;
        watchdog_reason = "headers_known_zero".to_string();
    }

    let peer_ahead = best_h > local_h;
    if reason == "no_best_header_block_path" && peer_ahead {
        let since = st.no_best_since.get_or_insert(now);
        if now.duration_since(*since) >= Duration::from_secs(120) {
            should_warn = true;
            if watchdog_reason.is_empty() {
                watchdog_reason = "no_best_header_block_path_stuck".to_string();
            }
        }
    } else {
        st.no_best_since = None;
    }

    if !should_warn {
        return;
    }

    if let Some(last) = st.last_warn {
        if now.duration_since(last) < Duration::from_secs(600) {
            return;
        }
    }
    st.last_warn = Some(now);

    let ahead_by = best_h.saturating_sub(local_h);
    P2PNode::log_event(
        "warn",
        "sync",
        format!(
            "header watchdog: reason={} local={} best_header={} ahead_by={} headers_known={} headers_inflight={} headers_processing={} best_peer={} peer_score={} reject_top3={} path_debug={}",
            watchdog_reason,
            local_h,
            best_h,
            ahead_by,
            headers_known,
            headers_inflight,
            headers_processing,
            best_peer,
            this_score,
            top_str,
            path_debug,
        ),
    );
}

async fn maybe_log_header_sync_state(
    addr: SocketAddr,
    chain: &Arc<StdMutex<ChainState>>,
    peer_state: &Arc<Mutex<PeerSyncState>>,
    reason_hint: &str,
) {
    if !should_emit_header_state_log(addr.ip()).await {
        return;
    }

    let (local_h, local_hash, best_h, best_hash, headers_known, has_best_path, path_debug) = {
        let guard = chain.lock().unwrap_or_else(|e| e.into_inner());
        let local_h = guard.tip_height();
        let local_hash = guard.tip_hash();
        let best_hash = guard.best_header_hash();
        let best_h = guard
            .headers
            .get(&best_hash)
            .map(|hw| hw.height)
            .or_else(|| guard.heights.get(&best_hash).copied())
            .unwrap_or(local_h);
        let has_best_path = guard
            .best_header_if_better()
            .and_then(|best| guard.header_path_to_known(best.header.hash_for_height(best.height)))
            .map(|p| !p.is_empty())
            .unwrap_or(false);
        let path_debug = if !has_best_path && best_h > local_h {
            best_header_linkage_debug(&guard)
        } else {
            "ok".to_string()
        };
        (
            local_h,
            local_hash,
            best_h,
            best_hash,
            guard.headers.len(),
            has_best_path,
            path_debug,
        )
    };

    let (headers_inflight, headers_processing) = {
        let st = peer_state.lock().await;
        (st.headers_inflight, st.headers_processing)
    };

    let this_score = peer_score(addr.ip()).await;
    let best_peer = best_scored_peer_snapshot()
        .await
        .map(|(ip, score)| format!("{}({})", ip, score))
        .unwrap_or_else(|| "-".to_string());
    let top = top_header_reject_reasons(3).await;
    let top_str = if top.is_empty() {
        "none".to_string()
    } else {
        top.into_iter()
            .map(|(r, c)| format!("{}:{}", r, c))
            .collect::<Vec<_>>()
            .join(",")
    };

    let reason = if let Some(r) = normalize_reason_hint(reason_hint, local_h, best_h) {
        r
    } else if best_h <= local_h {
        "best_header_not_ahead".to_string()
    } else if !has_best_path {
        "no_best_header_block_path".to_string()
    } else if headers_processing {
        "headers_processing".to_string()
    } else if headers_inflight {
        "waiting_headers_response".to_string()
    } else {
        "ready".to_string()
    };

    maybe_emit_header_watchdog(
        local_h,
        best_h,
        headers_known,
        &reason,
        &best_peer,
        this_score,
        headers_inflight,
        headers_processing,
        &top_str,
        &path_debug,
    );

    P2PNode::log_event(
        "info",
        "sync",
        format!(
            "header-state peer={} local_tip={}/{} best_header_tip={}/{} headers_known={} headers_inflight={} headers_processing={} best_peer={} peer_score={} reason={} reject_top3={} path_debug={}",
            addr,
            local_h,
            short_hash(local_hash),
            best_h,
            short_hash(best_hash),
            headers_known,
            headers_inflight,
            headers_processing,
            best_peer,
            this_score,
            reason,
            top_str,
            path_debug,
        ),
    );
}

async fn sync_block_request_allowed_for(
    block_requests: &Arc<Mutex<HashMap<IpAddr, Instant>>>,
    ip: IpAddr,
    local_height: u64,
    peer_height: u64,
    start_hash: &[u8],
    count: u32,
) -> bool {
    let cooldown = sync_cooldown_for(local_height, peer_height);
    let mut guard = block_requests.lock().await;
    let now = Instant::now();
    if let Some(last) = guard.get(&ip) {
        if now.duration_since(*last) < cooldown {
            return false;
        }
    }

    if peer_score_gate_enabled() {
        let best = best_peer_score().await;
        let score = peer_score(ip).await;
        if best >= 10 && score <= -6 {
            return false;
        }
    }

    let request_key = block_request_cache_key(ip, start_hash, count);
    {
        let cache = recent_requested_blocks();
        let mut cache_guard = cache.lock().await;
        cache_guard.prune(now);
        if cache_guard.seen_at.contains_key(&request_key) {
            DUPLICATE_BLOCK_SUPPRESSED_COUNT.fetch_add(1, Ordering::Relaxed);
            return false;
        }
    }

    if !claim_block_range_owner(ip, start_hash, count).await {
        return false;
    }

    guard.insert(ip, now);
    true
}

async fn record_block_request_sent(ip: IpAddr, start_hash: &[u8], count: u32) {
    let now = Instant::now();
    let request_key = block_request_cache_key(ip, start_hash, count);
    let cache = recent_requested_blocks();
    let mut cache_guard = cache.lock().await;
    let _ = cache_guard.record_at(request_key, now);
    BLOCK_REQUEST_COUNT.fetch_add(1, Ordering::Relaxed);
}

fn headers_request_cooldown() -> Duration {
    let secs = std::env::var("IRIUM_P2P_HEADERS_REQUEST_COOLDOWN_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(30);
    Duration::from_secs(secs.max(2).min(120))
}

fn headers_request_cooldown_for(local_height: u64, peer_height: u64) -> Duration {
    let base = headers_request_cooldown();
    if peer_height <= local_height {
        return base;
    }
    let gap = peer_height.saturating_sub(local_height);
    let fast_secs = if gap >= 10_000 {
        2
    } else if gap >= 2_000 {
        3
    } else if gap >= 500 {
        4
    } else if gap >= 100 {
        6
    } else {
        base.as_secs()
    };
    Duration::from_secs(fast_secs.max(1).min(base.as_secs().max(1)))
}

fn headers_response_window() -> Duration {
    let secs = std::env::var("IRIUM_P2P_HEADERS_RESPONSE_WINDOW_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(30);
    Duration::from_secs(secs.clamp(5, 120))
}

fn headers_fallback_grace() -> Duration {
    let secs = std::env::var("IRIUM_P2P_HEADERS_FALLBACK_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(15);
    Duration::from_secs(secs.max(5).min(300))
}

fn getblocks_grace() -> Duration {
    let secs = std::env::var("IRIUM_P2P_GETBLOCKS_GRACE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(8);
    Duration::from_secs(secs.max(2).min(60))
}

fn no_getblocks_fallback_cooldown() -> Duration {
    let secs = std::env::var("IRIUM_P2P_NO_GETBLOCKS_COOLDOWN_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(20);
    Duration::from_secs(secs.max(5).min(300))
}

fn sync_stall_heartbeats() -> u32 {
    std::env::var("IRIUM_SYNC_STALL_HEARTBEATS")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(15)
        .clamp(5, 60)
}

fn sync_stall_ahead_delta() -> u64 {
    std::env::var("IRIUM_SYNC_STALL_AHEAD_DELTA")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(3)
        .clamp(1, 1000)
}

fn fallback_blocks_per_burst() -> usize {
    let default = 32usize;
    let max = MAX_BLOCKS_PER_REQUEST as usize;
    let blocks = std::env::var("IRIUM_P2P_FALLBACK_BLOCKS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default);
    blocks.clamp(1, max)
}

fn genesis_grace() -> Duration {
    let secs = std::env::var("IRIUM_P2P_GENESIS_GRACE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(300);
    Duration::from_secs(secs.max(30).min(3600))
}

async fn genesis_request_allowed(
    requests: &Arc<Mutex<HashMap<IpAddr, Instant>>>,
    ip: IpAddr,
) -> bool {
    let mut guard = requests.lock().await;
    let now = Instant::now();
    if let Some(last) = guard.get(&ip) {
        if now.duration_since(*last) < genesis_grace() {
            return false;
        }
    }
    guard.insert(ip, now);
    true
}

fn best_checkpoint(chain: &Option<Arc<StdMutex<ChainState>>>) -> (Option<u64>, Option<String>) {
    let chain_arc = match chain.as_ref() {
        Some(c) => c,
        None => return (None, None),
    };
    let guard = match chain_arc.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };

    // Prefer the most recent signed anchor at or below our tip height.
    if let Some(ref anchors) = guard.anchors {
        let tip_h = guard.tip_height();
        if let Some(anchor) = anchors.anchors().iter().rev().find(|a| a.height <= tip_h) {
            return (Some(anchor.height), Some(anchor.hash.to_lowercase()));
        }
    }

    // Fallback to genesis.
    match guard.chain.first() {
        Some(b) => (Some(0), Some(hex::encode(b.header.hash_for_height(0)))),
        None => (None, None),
    }
}
fn verify_peer_checkpoint(
    payload: &HandshakePayload,
    chain: &Option<Arc<StdMutex<ChainState>>>,
) -> Result<(), String> {
    let height = match payload.checkpoint_height {
        Some(h) => h,
        None => return Ok(()),
    };
    if height > payload.height {
        return Err(format!(
            "invalid checkpoint (height {} > advertised height {})",
            height, payload.height
        ));
    }

    let hash_hex = payload
        .checkpoint_hash
        .as_ref()
        .ok_or_else(|| "missing checkpoint hash".to_string())?;
    let bytes = hex::decode(hash_hex).map_err(|_| "invalid checkpoint hash hex".to_string())?;
    if bytes.len() != 32 {
        return Err("invalid checkpoint hash length".to_string());
    }
    let mut peer = [0u8; 32];
    peer.copy_from_slice(&bytes[..32]);

    let chain_arc = match chain.as_ref() {
        Some(c) => c,
        None => return Ok(()),
    };
    let guard = match chain_arc.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };

    let local = match guard.chain.get(height as usize) {
        Some(b) => b.header.hash_for_height(height),
        None => return Ok(()),
    };

    // If an anchor exists at this exact height, use it to disambiguate
    // "peer is forked" vs "we are forked".
    let anchor = guard
        .anchors
        .as_ref()
        .and_then(|a| a.get_anchor_at_height(height))
        .and_then(|a| hex::decode(a.hash.trim()).ok())
        .and_then(|b| {
            if b.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                Some(arr)
            } else {
                None
            }
        });

    if let Some(anchor_hash) = anchor {
        if peer == anchor_hash && local != anchor_hash {
            let local_hex = hex::encode(local);
            let anchor_hex = hex::encode(anchor_hash);
            return Err(format!(
                "LOCAL_FORK: checkpoint mismatch at height {} (local {} != anchor {})",
                height,
                local_hex.get(0..12).unwrap_or(&local_hex),
                anchor_hex.get(0..12).unwrap_or(&anchor_hex)
            ));
        }
        if local == anchor_hash && peer != anchor_hash {
            let peer_hex = hex::encode(peer);
            let anchor_hex = hex::encode(anchor_hash);
            return Err(format!(
                "peer on fork/split chain: checkpoint mismatch at height {} (peer {} != anchor {})",
                height,
                peer_hex.get(0..12).unwrap_or(&peer_hex),
                anchor_hex.get(0..12).unwrap_or(&anchor_hex)
            ));
        }
    }

    if local != peer {
        let local_hex = hex::encode(local);
        let peer_hex = hex::encode(peer);
        let local_short = local_hex.get(0..12).unwrap_or(&local_hex);
        let peer_short = peer_hex.get(0..12).unwrap_or(&peer_hex);
        return Err(format!(
            "checkpoint mismatch at height {} (local {} != peer {})",
            height, local_short, peer_short
        ));
    }

    Ok(())
}

#[derive(Debug)]
#[derive(Default)]
struct PeerSyncState {
    height: Option<u64>,
    tip: Option<[u8; 32]>,
    node_id: Option<Vec<u8>>,
    supports_uptime: bool,
    last_uptime_challenge: Option<UptimeChallengePayload>,
    last_uptime_sent: Option<Instant>,
    last_headers_request: Option<Instant>,
    last_headers_received: Option<Instant>,
    last_headers_start: Option<[u8; 32]>,

    // Anti-flood: only accept Headers when we recently requested them, and process one batch at a time.
    headers_inflight: bool,
    headers_processing: bool,
    unsolicited_headers: u32,
    last_unsolicited_log: Option<Instant>,
    last_headers_batch_log: Option<Instant>,
    last_bad_headers: Option<Instant>,

    // Header-path recovery tracking.
    last_best_header_height: u64,
    last_best_header_hash: [u8; 32],
    last_best_header_progress: Option<Instant>,
    headers_recovery_exp: u8,
    last_locator_recovery: Option<Instant>,
    // Last seen *applied* tip height for this peer's sync state. Used to drive
    // the "no progress" staleness timer instead of best_header_height: orphan
    // headers count toward best_header_height but not toward chain progress,
    // and tying the timer to orphans causes the locator-recovery walk-back
    // to be reset before its 120s threshold ever fires when a node is stuck
    // on a stale fork.
    last_applied_height: u64,
}


#[derive(Clone)]
struct OrphanHeaderEntry {
    header: BlockHeader,
    inserted_at: Instant,
}

fn orphan_headers_limit() -> usize {
    std::env::var("IRIUM_ORPHAN_HEADERS_MAX")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(20_000)
        .clamp(512, 200_000)
}

fn orphan_headers_ttl() -> Duration {
    let secs = std::env::var("IRIUM_ORPHAN_HEADERS_TTL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(600)
        .clamp(30, 3600);
    Duration::from_secs(secs)
}

fn orphan_headers_map() -> &'static StdMutex<HashMap<[u8; 32], Vec<OrphanHeaderEntry>>> {
    static MAP: OnceLock<StdMutex<HashMap<[u8; 32], Vec<OrphanHeaderEntry>>>> = OnceLock::new();
    MAP.get_or_init(|| StdMutex::new(HashMap::new()))
}

fn recent_orphan_header_hashes() -> &'static StdMutex<RecentHashCache> {
    static CACHE: OnceLock<StdMutex<RecentHashCache>> = OnceLock::new();
    CACHE.get_or_init(|| {
        StdMutex::new(RecentHashCache::new(
            orphan_headers_ttl(),
            orphan_headers_limit().saturating_mul(2),
        ))
    })
}

fn orphan_headers_count_locked(m: &HashMap<[u8; 32], Vec<OrphanHeaderEntry>>) -> usize {
    m.values().map(|v| v.len()).sum()
}

fn prune_orphan_headers_locked(m: &mut HashMap<[u8; 32], Vec<OrphanHeaderEntry>>) {
    let ttl = orphan_headers_ttl();
    let now = Instant::now();
    m.retain(|_, v| {
        v.retain(|e| now.duration_since(e.inserted_at) <= ttl);
        !v.is_empty()
    });

    let limit = orphan_headers_limit();
    while orphan_headers_count_locked(m) > limit {
        let key = match m.keys().next().copied() {
            Some(k) => k,
            None => break,
        };
        let mut remove_key = false;
        if let Some(v) = m.get_mut(&key) {
            if !v.is_empty() {
                v.remove(0);
            }
            if v.is_empty() {
                remove_key = true;
            }
        }
        if remove_key {
            m.remove(&key);
        }
    }
}

fn orphan_headers_count() -> usize {
    let guard = orphan_headers_map()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    orphan_headers_count_locked(&guard)
}

fn store_orphan_header(header: BlockHeader) -> (usize, bool) {
    // Orphan headers have no known parent yet, so we cannot derive their
    // height. We use hash_for_height(0) which yields pre-fork convention.
    // For pre-fork blocks this matches the canonical hash exactly. For
    // post-fork orphans the value differs from the eventually-correct hash;
    // worst case is the same orphan being stored twice (under two different
    // keys) when its parent eventually arrives. Acceptable for a transient
    // cache.
    let header_hash = header.hash_for_height(0);
    let now = Instant::now();
    {
        let mut recent = recent_orphan_header_hashes()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if !recent.record_at(header_hash, now) {
            let guard = orphan_headers_map()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            return (orphan_headers_count_locked(&guard), false);
        }
    }

    let mut guard = orphan_headers_map()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    prune_orphan_headers_locked(&mut guard);
    let entries = guard.entry(header.prev_hash).or_default();
    if entries.iter().any(|e| e.header.hash_for_height(0) == header_hash) {
        return (orphan_headers_count_locked(&guard), false);
    }
    entries.push(OrphanHeaderEntry {
        header,
        inserted_at: now,
    });
    (orphan_headers_count_locked(&guard), true)
}

fn take_orphan_header_children(parent_hash: [u8; 32]) -> Vec<BlockHeader> {
    let mut guard = orphan_headers_map()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    prune_orphan_headers_locked(&mut guard);
    let entries = guard.remove(&parent_hash).unwrap_or_default();
    entries.into_iter().map(|e| e.header).collect()
}

fn attach_orphan_header_chain(
    guard: &mut ChainState,
    root_hash: [u8; 32],
) -> (usize, Option<String>) {
    let mut attached = 0usize;
    let mut queue = VecDeque::new();
    queue.push_back(root_hash);
    let mut first_err: Option<String> = None;

    while let Some(parent_hash) = queue.pop_front() {
        let children = take_orphan_header_children(parent_hash);
        if children.is_empty() {
            continue;
        }
        for child in children {
            let child_hash = child.hash();
            if guard.headers.contains_key(&child_hash) || guard.heights.contains_key(&child_hash) {
                continue;
            }
            match guard.add_header(child.clone()) {
                Ok(_) => {
                    attached = attached.saturating_add(1);
                    queue.push_back(child_hash);
                }
                Err(e) => {
                    if e.contains("unknown parent") {
                        let _ = store_orphan_header(child);
                    } else if first_err.is_none() {
                        first_err = Some(classify_header_reject_reason(&e));
                    }
                }
            }
        }
    }

    (attached, first_err)
}

fn best_header_linkage_debug(chain: &ChainState) -> String {
    let Some(best) = chain.best_header_if_better() else {
        return "best_header_not_better".to_string();
    };
    let mut cur = best.header.hash_for_height(best.height);
    let mut steps: u32 = 0;
    loop {
        if let Some(h) = chain.heights.get(&cur) {
            return format!("linked_to_main_at_height={}", h);
        }
        let Some(hw) = chain.headers.get(&cur) else {
            return format!("break_missing_header_node hash={}", short_hash(cur));
        };
        let prev = hw.header.prev_hash;
        if prev == [0u8; 32] {
            return format!(
                "break_genesis_prev_without_main height={} hash={}",
                hw.height,
                short_hash(cur)
            );
        }
        if !chain.headers.contains_key(&prev) && !chain.heights.contains_key(&prev) {
            return format!(
                "break_missing_prev height={} hash={} prev={}",
                hw.height,
                short_hash(cur),
                short_hash(prev)
            );
        }
        cur = prev;
        steps = steps.saturating_add(1);
        if steps > 200_000 {
            return "break_walk_limit".to_string();
        }
    }
}

fn locator_hash_at_height(chain: &ChainState, height: u64) -> [u8; 32] {
    chain
        .chain
        .get(height as usize)
        .map(|b| b.header.hash_for_height(height))
        .unwrap_or([0u8; 32])
}

fn rewinded_getblocks_request(chain: &ChainState, peer_height: u64) -> Option<([u8; 32], u32)> {
    let tip_height = chain.tip_height();
    if peer_height <= tip_height {
        return None;
    }

    let max = MAX_BLOCKS_PER_REQUEST as u64;
    let ahead = peer_height.saturating_sub(tip_height);
    let rewind = if ahead < max {
        max.saturating_sub(ahead)
    } else {
        max / 2
    }
    .min(tip_height);
    let start_height = tip_height.saturating_sub(rewind);
    let count = peer_height
        .saturating_sub(start_height)
        .min(max) as u32;
    if count == 0 {
        return None;
    }

    Some((locator_hash_at_height(chain, start_height), count))
}

struct OutboundDialGuard {
    ip: IpAddr,
    inflight: Arc<StdMutex<HashSet<IpAddr>>>,
}

impl Drop for OutboundDialGuard {
    fn drop(&mut self) {
        let mut guard = match self.inflight.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.remove(&self.ip);
    }
}

pub struct SyncDebugSnapshot {
    pub sync_requests: usize,
    pub block_requests: usize,
    pub handshake_failures: usize,
    pub getblocks_inflight: usize,
}

async fn maybe_request_sync(
    writer: &Arc<Mutex<OwnedWriteHalf>>,
    addr: SocketAddr,
    chain: &Option<Arc<StdMutex<ChainState>>>,
    sync_requests: &Arc<Mutex<HashMap<IpAddr, Instant>>>,
    block_requests: &Arc<Mutex<HashMap<IpAddr, Instant>>>,
    peer_state: &Arc<Mutex<PeerSyncState>>,
) {
    let (peer_height, peer_tip) = {
        let guard = peer_state.lock().await;
        (guard.height, guard.tip)
    };
    let peer_height = match peer_height {
        Some(h) => h,
        None => return,
    };
    let (local_height, local_tip, best_header_height, best_header_hash) = match chain {
        Some(c) => {
            let guard = c.lock().unwrap_or_else(|e| e.into_inner());
            let local_height = guard.tip_height();
            let local_tip = guard.tip_hash();
            let best_header_hash = guard.best_header_hash();
            let best_header_height = guard
                .headers
                .get(&best_header_hash)
                .map(|hw| hw.height)
                .or_else(|| guard.heights.get(&best_header_hash).copied())
                .unwrap_or(local_height);
            (
                local_height,
                local_tip,
                best_header_height,
                best_header_hash,
            )
        }
        None => (0, [0u8; 32], 0, [0u8; 32]),
    };
    let tip_mismatch = peer_tip
        .map(|t| peer_height == local_height && t != local_tip)
        .unwrap_or(false);

    if peer_height < local_height || (peer_height == local_height && !tip_mismatch) {
        return;
    }

    // At validated tip with no mismatch, ignore inflated peer-advertised heights.
    if best_header_height <= local_height && !tip_mismatch {
        let mut state = peer_state.lock().await;
        state.headers_inflight = false;
        return;
    }

    let mut start_hash = if local_height == 0 || tip_mismatch {
        [0u8; 32]
    } else {
        local_tip
    };

    let mut recovery_triggered = false;
    #[allow(unused_assignments)]
    let mut recovery_exp = 0u8;
    {
        let mut state = peer_state.lock().await;
        let now = Instant::now();
        // Drive the "no progress" timer off the *applied* tip (local_height),
        // not off best_header_height. Orphan headers received from a stale
        // fork (or repeatedly re-pushed by peers we can't connect to via the
        // current locator) bump best_header_height without ever extending the
        // applied chain. Tying the timer to best_header_height resets it on
        // every such orphan, so the 120s staleness threshold below never
        // fires and locator-recovery never walks back to find common ground.
        // Tracked separately from last_best_header_* so we still keep those
        // updated for other consumers but only treat applied-tip advance as
        // real progress here.
        if state.last_applied_height != local_height {
            state.last_applied_height = local_height;
            state.last_best_header_progress = Some(now);
            state.headers_recovery_exp = 0;
        }
        state.last_best_header_height = best_header_height;
        state.last_best_header_hash = best_header_hash;
        if peer_height > local_height.saturating_add(8)
            && best_header_height <= local_height
            && state
                .last_best_header_progress
                .map(|t| now.duration_since(t) >= Duration::from_secs(120))
                .unwrap_or(false)
        {
            let at_tip = best_header_height >= local_height;
            let cooldown = if at_tip {
                Duration::from_secs(locator_recovery_tip_cooldown_secs())
            } else {
                Duration::from_secs(locator_recovery_cooldown_secs())
            };
            let allow_recovery = state
                .last_locator_recovery
                .map(|t| now.duration_since(t) >= cooldown)
                .unwrap_or(true);
            if allow_recovery {
                state.headers_recovery_exp = state.headers_recovery_exp.saturating_add(1).min(16);
                state.last_locator_recovery = Some(now);
                recovery_triggered = true;
            }
        }
        recovery_exp = state.headers_recovery_exp;
    }

    if recovery_triggered && start_hash != [0u8; 32] {
        if let Some(c) = chain {
            let rewind = 1u64 << recovery_exp;
            let guard = c.lock().unwrap_or_else(|e| e.into_inner());
            let start_height = guard.tip_height().saturating_sub(rewind);
            start_hash = locator_hash_at_height(&guard, start_height);
            P2PNode::log_event(
                "warn",
                "sync",
                format!(
                    "GetHeaders locator recovery: peer={} local={} best_header={} rewind={} start_height={} start_hash={}",
                    addr,
                    guard.tip_height(),
                    best_header_height,
                    rewind,
                    start_height,
                    short_hash(start_hash),
                ),
            );
        }
    }

    if sync_request_allowed_for(sync_requests, addr.ip(), local_height, peer_height).await {
        let get_headers = GetHeadersPayload {
            start_hash: start_hash.to_vec(),
            count: MAX_HEADERS_PER_REQUEST,
        };
        if let Ok(msg) = get_headers.to_message() {
            let _ = send_message(writer, msg, addr).await;
        }
        {
            let mut state = peer_state.lock().await;
            state.last_headers_request = Some(Instant::now());
            state.last_headers_start = Some(start_hash);
            state.headers_inflight = true;
        }
    }
    if (peer_height > local_height || tip_mismatch)
        && sync_block_request_allowed_for(
            block_requests,
            addr.ip(),
            local_height,
            peer_height,
            &start_hash,
            MAX_BLOCKS_PER_REQUEST,
        )
        .await
        {
            let get_blocks = GetBlocksPayload {
                start_hash: start_hash.to_vec(),
                count: MAX_BLOCKS_PER_REQUEST,
            };
            if let Ok(msg) = get_blocks.to_message() {
                let _ = send_message(writer, msg, addr).await;
            }
        }
}

async fn maybe_request_headers_fallback(
    writer: &Arc<Mutex<OwnedWriteHalf>>,
    addr: SocketAddr,
    chain: &Option<Arc<StdMutex<ChainState>>>,
    sync_requests: &Arc<Mutex<HashMap<IpAddr, Instant>>>,
    peer_state: &Arc<Mutex<PeerSyncState>>,
) {
    let (peer_height, last_request, last_received, last_start) = {
        let guard = peer_state.lock().await;
        (
            guard.height,
            guard.last_headers_request,
            guard.last_headers_received,
            guard.last_headers_start,
        )
    };
    let peer_height = match peer_height {
        Some(h) => h,
        None => return,
    };
    let local_height = chain
        .as_ref()
        .and_then(|c| c.lock().ok().map(|g| g.tip_height()))
        .unwrap_or(0);
    if peer_height <= local_height {
        return;
    }
    let last_request = match last_request {
        Some(ts) => ts,
        None => return,
    };
    let received_after_request = last_received.map(|ts| ts >= last_request).unwrap_or(false);
    if received_after_request {
        return;
    }
    if last_request.elapsed() < headers_fallback_grace() {
        return;
    }
    if last_start == Some([0u8; 32]) {
        return;
    }
    if sync_request_allowed_for(sync_requests, addr.ip(), local_height, peer_height).await {
        let mut start_hash = [0u8; 32];
        let mut rewind = 0u64;
        if let Some(c) = chain {
            let mut st = peer_state.lock().await;
            st.headers_recovery_exp = st.headers_recovery_exp.saturating_add(1).min(16);
            rewind = 1u64 << st.headers_recovery_exp;
            let guard = c.lock().unwrap_or_else(|e| e.into_inner());
            let start_height = guard.tip_height().saturating_sub(rewind);
            start_hash = locator_hash_at_height(&guard, start_height);
        }

        let get_headers = GetHeadersPayload {
            start_hash: start_hash.to_vec(),
            count: MAX_HEADERS_PER_REQUEST,
        };
        P2PNode::log_event(
            "warn",
            "sync",
            format!(
                "P2P {}: no headers response, locator rewind fallback (rewind={} start={})",
                addr,
                rewind,
                short_hash(start_hash)
            ),
        );
        if let Ok(msg) = get_headers.to_message() {
            let _ = send_message(writer, msg, addr).await;
        }
        let mut guard = peer_state.lock().await;
        guard.last_headers_request = Some(Instant::now());
        guard.last_headers_start = Some(start_hash);
        guard.headers_inflight = true;
    }
}

fn orphan_storm_threshold() -> u32 {
    std::env::var("IRIUM_ORPHAN_STORM_THRESHOLD")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(200)
        .clamp(20, 20000)
}

fn orphan_storm_window_secs() -> u64 {
    std::env::var("IRIUM_ORPHAN_STORM_WINDOW_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(60)
        .clamp(10, 600)
}

fn orphan_storm_tracker() -> &'static Mutex<(Instant, u32)> {
    static TRACK: OnceLock<Mutex<(Instant, u32)>> = OnceLock::new();
    TRACK.get_or_init(|| Mutex::new((Instant::now(), 0)))
}

async fn note_orphan_and_check_storm() -> bool {
    let window = Duration::from_secs(orphan_storm_window_secs());
    let threshold = orphan_storm_threshold();
    let now = Instant::now();
    let mut guard = orphan_storm_tracker().lock().await;
    if now.duration_since(guard.0) > window {
        guard.0 = now;
        guard.1 = 0;
    }
    guard.1 = guard.1.saturating_add(1);
    if guard.1 >= threshold {
        guard.0 = now;
        guard.1 = 0;
        return true;
    }
    false
}

async fn request_orphan_headers(
    writer: &Arc<Mutex<OwnedWriteHalf>>,
    addr: SocketAddr,
    prev_hash: [u8; 32],
    chain: &Option<Arc<StdMutex<ChainState>>>,
    sync_requests: &Arc<Mutex<HashMap<IpAddr, Instant>>>,
    peer_state: &Arc<Mutex<PeerSyncState>>,
) {
    let (local_height, prev_known, prev_in_headers) = chain
        .as_ref()
        .and_then(|c| {
            let guard = c.lock().ok()?;
            Some((
                guard.tip_height(),
                guard.heights.contains_key(&prev_hash),
                guard.headers.contains_key(&prev_hash),
            ))
        })
        .unwrap_or((0, false, false));

    let peer_height = {
        let guard = peer_state.lock().await;
        guard.height.unwrap_or(local_height.saturating_add(1))
    };

    if prev_hash != [0u8; 32] && !prev_known {
        let prev = hex::encode(prev_hash);
        let prev_short = prev.get(0..12).unwrap_or(&prev);
        P2PNode::log_event(
            "warn",
            "sync",
            format!(
                "Orphan block received (prev unknown={}; prev_in_headers={}; prev={}). Possible fork/split or missing ancestors. Attempting recovery...",
                !prev_known,
                prev_in_headers,
                prev_short
            ),
        );

        if note_orphan_and_check_storm().await {
            let cleared = chain
                .as_ref()
                .and_then(|c| c.lock().ok().map(|mut g| g.clear_orphan_pool()))
                .unwrap_or(0);
            sync_requests.lock().await.clear();
            P2PNode::log_event(
                "warn",
                "sync",
                format!(
                    "orphan storm detected; clearing orphan pool and restarting header-first sync from best peer (cleared={})",
                    cleared
                ),
            );
            let get_headers = GetHeadersPayload {
                start_hash: vec![0u8; 32],
                count: MAX_HEADERS_PER_REQUEST,
            };
            if let Ok(msg) = get_headers.to_message() {
                let _ = send_message(writer, msg, addr).await;
            }
            let mut guard = peer_state.lock().await;
            guard.last_headers_request = Some(Instant::now());
            guard.last_headers_start = Some([0u8; 32]);
            guard.headers_inflight = true;
            return;
        }
    }

    let start_hash = if prev_hash == [0u8; 32] || !prev_known {
        [0u8; 32]
    } else {
        prev_hash
    };

    if sync_request_allowed_for(sync_requests, addr.ip(), local_height, peer_height).await {
        let get_headers = GetHeadersPayload {
            start_hash: start_hash.to_vec(),
            count: MAX_HEADERS_PER_REQUEST,
        };
        if let Ok(msg) = get_headers.to_message() {
            let _ = send_message(writer, msg, addr).await;
        }
        let mut guard = peer_state.lock().await;
        guard.last_headers_request = Some(Instant::now());
        guard.last_headers_start = Some(start_hash);
        guard.headers_inflight = true;
    }
}

fn uptime_capability() -> &'static str {
    "uptime_hmac_v1"
}

fn uptime_enabled() -> bool {
    std::env::var("IRIUM_UPTIME_PROOFS")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true)
}

fn uptime_interval() -> Duration {
    let secs = std::env::var("IRIUM_UPTIME_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(300);
    Duration::from_secs(secs.clamp(60, 3600))
}

fn uptime_max_skew() -> u64 {
    std::env::var("IRIUM_UPTIME_MAX_SKEW_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(300)
}

fn uptime_timestamp_valid(timestamp: u64) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let skew = uptime_max_skew();
    if timestamp > now.saturating_add(skew) {
        return false;
    }
    now.saturating_sub(timestamp) <= skew
}

fn uptime_key(local_id: &[u8], peer_id: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    if local_id <= peer_id {
        hasher.update(local_id);
        hasher.update(peer_id);
    } else {
        hasher.update(peer_id);
        hasher.update(local_id);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn compute_uptime_hmac(key: &[u8; 32], nonce: &[u8; 32], timestamp: u64) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(nonce);
    mac.update(&timestamp.to_be_bytes());
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn local_capabilities() -> Option<Vec<String>> {
    let mut caps = Vec::new();
    if uptime_enabled() {
        caps.push(uptime_capability().to_string());
    }
    if caps.is_empty() {
        None
    } else {
        Some(caps)
    }
}

fn peer_supports_uptime(payload: &HandshakePayload) -> bool {
    payload
        .capabilities
        .as_ref()
        .map(|caps| caps.iter().any(|c| c == uptime_capability()))
        .unwrap_or(false)
}

fn parse_node_id_bytes(payload: &HandshakePayload) -> Option<Vec<u8>> {
    payload
        .node_id
        .as_ref()
        .and_then(|h| hex::decode(h).ok())
        .and_then(|b| if b.len() == 32 { Some(b) } else { None })
}

// Parse a self-advertised "host:port" endpoint from HandshakePayload.external_endpoint.
// Accepts only globally routable IPv4 socket addresses. Returns the parsed
// multiaddr string in `/ip4/.../tcp/...` form on success, otherwise None.
//
// Rejected: loopback, RFC1918 private, RFC6598 CGNAT (100.64.0.0/10),
// link-local, unspecified, broadcast, multicast, documentation, port == 0,
// and any IPv6 (callers fall back to TCP-source-IP behavior).
fn dialable_multiaddr_from_advertised(advertised: &str) -> Option<String> {
    use std::net::Ipv4Addr;
    let sock: SocketAddr = advertised.trim().parse().ok()?;
    if sock.port() == 0 {
        return None;
    }
    let v4: Ipv4Addr = match sock.ip() {
        IpAddr::V4(v) => v,
        IpAddr::V6(_) => return None,
    };
    if v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_multicast()
        || v4.is_documentation()
    {
        return None;
    }
    // RFC6598 CGNAT: 100.64.0.0/10 (octets 100.64 .. 100.127).
    let oct = v4.octets();
    if oct[0] == 100 && (64..=127).contains(&oct[1]) {
        return None;
    }
    Some(format!("/ip4/{}/tcp/{}", v4, sock.port()))
}

fn handshake_fail_window() -> Duration {
    Duration::from_secs(60)
}

fn handshake_fail_threshold() -> u32 {
    5
}

fn should_log_handshake_failure(count: u32) -> bool {
    count.is_multiple_of(handshake_fail_threshold())
}

async fn record_handshake_failure(
    failures: &Arc<Mutex<HashMap<IpAddr, (u32, Instant)>>>,
    dynamic_bans: &Arc<StdMutex<HashMap<IpAddr, Instant>>>,
    ip: IpAddr,
    trusted_seed: bool,
    connected_peers: usize,
) -> (u32, bool) {
    HANDSHAKE_FAILURE_TOTAL.fetch_add(1, Ordering::Relaxed);
    let now = Instant::now();
    let window = handshake_fail_window();
    let count = {
        let mut guard = failures.lock().await;
        if let Some((prev, first)) = guard.get(&ip).copied() {
            if now.duration_since(first) <= window {
                let next = prev.saturating_add(1);
                guard.insert(ip, (next, first));
                next
            } else {
                guard.insert(ip, (1, now));
                1
            }
        } else {
            guard.insert(ip, (1, now));
            1
        }
    };
    let threshold = if connected_peers < small_network_peer_floor() {
        small_network_handshake_fail_threshold()
    } else {
        handshake_fail_threshold()
    };
    let mut banned = false;
    if !trusted_seed && count >= threshold {
        {
            let mut guard = dynamic_bans.lock().unwrap_or_else(|e| e.into_inner());
            guard.insert(ip, Instant::now() + Duration::from_secs(dynamic_ban_secs()));
        }
        let mut guard = failures.lock().await;
        guard.remove(&ip);
        TEMP_BAN_TOTAL.fetch_add(1, Ordering::Relaxed);
        banned = true;
    }
    (count, banned)
}

async fn ip_log_allowed(
    logs: &Arc<Mutex<HashMap<IpAddr, Instant>>>,
    ip: IpAddr,
    cooldown: Duration,
) -> bool {
    let mut guard = logs.lock().await;
    let now = Instant::now();
    if let Some(last) = guard.get(&ip) {
        if now.duration_since(*last) < cooldown {
            return false;
        }
    }
    guard.insert(ip, now);
    true
}

fn max_peers() -> usize {
    let val = std::env::var("IRIUM_P2P_MAX_PEERS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_MAX_PEERS);
    val.clamp(10, 500)
}

async fn getblocks_request_allowed(
    requests: &Arc<Mutex<HashMap<IpAddr, (Vec<u8>, u32, Instant)>>>,
    ip: IpAddr,
    start_hash: &[u8],
    count: u32,
) -> bool {
    let grace = getblocks_grace();
    let now = Instant::now();
    let mut guard = requests.lock().await;
    if let Some((last_hash, last_count, last_ts)) = guard.get(&ip) {
        if *last_count == count
            && last_hash.as_slice() == start_hash
            && now.duration_since(*last_ts) < grace
        {
            return false;
        }
    }
    guard.insert(ip, (start_hash.to_vec(), count, now));
    true
}

fn p2p_data_dir() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("IRIUM_DATA_DIR") {
        return std::path::PathBuf::from(path);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    std::path::PathBuf::from(home).join(".irium")
}

fn record_discovered_feed(url: &str) {
    let url = url.trim().to_string();
    if url.is_empty() {
        return;
    }
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return;
    }
    let path = p2p_data_dir().join("discovered_feeds.json");
    let mut feeds: Vec<String> = if path.exists() {
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
            .and_then(|v| {
                v.get("feeds")
                    .and_then(|f| f.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|e| e.as_str().map(|s| s.to_string()))
                            .collect()
                    })
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    if feeds.iter().any(|f| f == &url) {
        return;
    }
    feeds.push(url);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string_pretty(&serde_json::json!({ "feeds": feeds })) {
        let _ = std::fs::write(&path, json);
    }
}

/// Phase 1A+1B (P2P offer gossip): caps for the OfferBroadcast handling
/// path. Defaults chosen to keep one busy seller well below the per-peer
/// cap while rejecting flood attempts. A normal offer JSON is < 2 KB; the
/// 64 KB MAX_BYTES is a comfortable safety margin. 20 offers/min is roughly
/// 1 every 3 seconds. 1000-entry LRU = ~40 KB memory.
const OFFER_BROADCAST_MAX_BYTES: usize = 65_536;
const OFFER_BROADCAST_PEER_RATE_PER_MIN: u32 = 20;
const OFFER_BROADCAST_RATE_WINDOW_SECS: u64 = 60;
const OFFER_BROADCAST_SEEN_CAP: usize = 1000;

#[derive(Clone)]
pub struct P2PNode {
    bind_addr: SocketAddr,
    peers: Arc<Mutex<Vec<Arc<Mutex<OwnedWriteHalf>>>>>,
    peers_directory: Arc<Mutex<PeerDirectory>>,
    connected: Arc<Mutex<HashSet<SocketAddr>>>,
    reputation: Arc<Mutex<ReputationManager>>,
    accept_log: Arc<Mutex<HashMap<IpAddr, Instant>>>,
    sync_requests: Arc<Mutex<HashMap<IpAddr, Instant>>>,
    block_requests: Arc<Mutex<HashMap<IpAddr, Instant>>>,
    getblocks_seen: Arc<Mutex<HashMap<IpAddr, Instant>>>,
    getblocks_last: Arc<Mutex<HashMap<IpAddr, (Vec<u8>, u32, Instant)>>>,
    getblocks_genesis: Arc<Mutex<HashMap<IpAddr, Instant>>>,
    handshake_failures: Arc<Mutex<HashMap<IpAddr, (u32, Instant)>>>,
    handshake_error_log: Arc<Mutex<HashMap<IpAddr, Instant>>>,
    banned_inbound_log: Arc<Mutex<HashMap<IpAddr, Instant>>>,
    send_blocks_log: Arc<Mutex<HashMap<IpAddr, Instant>>>,
    outbound_dial_inflight: Arc<StdMutex<HashSet<IpAddr>>>,
    outbound_dial_backoff: Arc<Mutex<HashMap<IpAddr, (u32, Instant)>>>,
    self_ips: Arc<Mutex<HashSet<IpAddr>>>,
    dynamic_bans: Arc<StdMutex<HashMap<IpAddr, Instant>>>,
    chain: Option<Arc<StdMutex<ChainState>>>,
    mempool: Option<Arc<StdMutex<MempoolManager>>>,
    agent: String,
    relay_address: Option<String>,
    marketplace_feed: Option<String>,
    external_endpoint: Option<String>,
    proof_gossip_inbox: Arc<tokio::sync::Mutex<Vec<String>>>,
    /// Inbox for incoming MessageType::OfferTakeNotification payloads.
    /// Mirrors proof_gossip_inbox. Drained by an iriumd background task
    /// that mutates the local matching offer file from "open" to "taken".
    offer_take_inbox: Arc<tokio::sync::Mutex<Vec<String>>>,
    /// Phase 1A+1B: inbox for incoming MessageType::OfferBroadcast payloads.
    /// Drained by an iriumd background task that writes the JSON to
    /// ~/.irium/offers/<id>.json so /offers/feed serves it locally.
    /// Push happens only AFTER LRU dedup + rate limit + size check pass.
    offer_broadcast_inbox: Arc<tokio::sync::Mutex<Vec<String>>>,
    /// Phase 1A+1B: bounded LRU of recently-seen offer IDs. FIFO eviction
    /// when len reaches OFFER_BROADCAST_SEEN_CAP. Used by both inbound and
    /// outbound receive arms to drop duplicate broadcasts (prevents
    /// amplification storms). VecDeque keeps insertion order for eviction;
    /// HashSet keeps O(1) membership.
    seen_offer_ids: Arc<tokio::sync::Mutex<(VecDeque<String>, HashSet<String>)>>,
    /// Phase 1A+1B: per-peer sliding-window rate limiter for offer broadcasts.
    /// Key: peer SocketAddr. Value: (window_start, count_in_window).
    offer_rate_limit: Arc<tokio::sync::Mutex<HashMap<SocketAddr, (Instant, u32)>>>,
    dispute_raised_inbox: Arc<tokio::sync::Mutex<Vec<String>>>,
    dispute_evidence_inbox: Arc<tokio::sync::Mutex<Vec<String>>>,
    dispute_resolved_inbox: Arc<tokio::sync::Mutex<Vec<String>>>,
    dispute_escalated_inbox: Arc<tokio::sync::Mutex<Vec<String>>>,
    node_id: Vec<u8>,
    trusted_seed_ips: Arc<HashSet<IpAddr>>,

    banned_ips: Arc<HashSet<IpAddr>>,
}

impl P2PNode {
    fn ts() -> String {
        Utc::now().format("%H:%M:%S").to_string()
    }

    fn json_log_enabled() -> bool {
        static FLAG: OnceLock<bool> = OnceLock::new();
        *FLAG.get_or_init(|| {
            std::env::var("IRIUM_JSON_LOG")
                .ok()
                .map(|v| v == "1" || v.to_lowercase() == "true")
                .unwrap_or(false)
        })
    }

    fn log_rate_limit_enabled() -> bool {
        static FLAG: OnceLock<bool> = OnceLock::new();
        *FLAG.get_or_init(|| {
            std::env::var("IRIUM_P2P_LOG_RATE_LIMIT")
                .ok()
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(true)
        })
    }

    fn log_event(level: &str, category: &str, msg: impl AsRef<str>) {
        use std::borrow::Cow;

        let icon = match category {
            "net" => "📡",
            "p2p" => "🔌",
            "chain" => "⛓️",
            "sync" => "🔁",
            "reputation" => "🛡️",
            "mempool" => "🧺",
            _ => "",
        };
        let msg_ref = msg.as_ref();

        let mut suffix: Option<String> = None;

        let extract_sock = |s: &str| s.trim().parse::<SocketAddr>().ok();
        let extract_ip_from_p2p_line = |line: &str| -> Option<IpAddr> {
            if let Some(rest) = line.strip_prefix("P2P ") {
                if let Some(end) = rest.find(": ") {
                    return extract_sock(&rest[..end]).map(|s| s.ip());
                }
            }
            None
        };
        let extract_ip_from_prefix =
            |line: &str, prefix: &str, suffix_marker: &str| -> Option<IpAddr> {
                let rest = line.strip_prefix(prefix)?;
                let end = rest.find(suffix_marker)?;
                extract_sock(&rest[..end]).map(|s| s.ip())
            };
        let extract_headers_count = |line: &str| -> Option<u32> {
            let idx = line.find("received ")?;
            let rest = &line[idx + 9..];
            let end = rest.find(" headers")?;
            rest[..end].trim().parse::<u32>().ok()
        };
        let extract_block_span = |line: &str, marker: &str| -> Option<(u32, u64, u64)> {
            let idx = line.find(marker)?;
            let rest = &line[idx + marker.len()..];
            let end_count = rest.find(" blocks [")?;
            let count = rest[..end_count].trim().parse::<u32>().ok()?;
            let range = &rest[end_count + 9..];
            let end_range = range.find(']')?;
            let range = &range[..end_range];
            let mut parts = range.split('-');
            let start = parts.next()?.trim().parse::<u64>().ok()?;
            let end = parts.next()?.trim().parse::<u64>().ok()?;
            Some((count, start, end))
        };

        let mut rl_spec: Option<(String, u64)> = None;

        if Self::log_rate_limit_enabled() && category == "sync" {
            let mut reason_key: Option<String> = None;
            let headers_count = extract_headers_count(msg_ref);
            let (kind, cooldown) = if msg_ref.contains("no getblocks after headers") {
                ("no_getblocks", no_getblocks_log_cooldown_secs())
            } else if msg_ref.contains("unknown start hash") {
                ("unknown_start", unknown_start_log_cooldown_secs())
            } else if msg_ref.contains("received ") && msg_ref.contains(" headers (new=false)") {
                ("headers_new_false", headers_new_false_log_cooldown_secs())
            } else if msg_ref.contains("received ") && msg_ref.contains(" headers (new=true)") {
                ("headers_new_true", headers_new_true_log_cooldown_secs())
            } else if msg_ref.starts_with("header-state peer=") {
                if let Some(idx) = msg_ref.find(" reason=") {
                    let rest = &msg_ref[idx + 8..];
                    let end = rest.find(' ').unwrap_or(rest.len());
                    reason_key = Some(rest[..end].to_string());
                }
                let cooldown = if reason_key.as_deref() == Some("no_block_download_needed_at_tip") {
                    header_state_log_cooldown_secs().max(180)
                } else {
                    header_state_log_cooldown_secs()
                };
                ("header_state", cooldown)
            } else if msg_ref.starts_with("stored orphan header: ") {
                ("orphan_header", orphan_header_log_cooldown_secs())
            } else if msg_ref.contains(": inbound block ") {
                (
                    "inbound_block_trace",
                    inbound_block_trace_log_cooldown_secs(),
                )
            } else {
                ("", 0)
            };
            if cooldown > 0 {
                if kind == "orphan_header" {
                    rl_spec = Some(("sync:orphan_header".to_string(), cooldown));
                } else if kind == "inbound_block_trace" {
                    if let Some(ip) = extract_ip_from_p2p_line(msg_ref) {
                        rl_spec = Some((format!("sync:{}:{}", kind, ip), cooldown));
                    }
                } else if kind == "header_state"
                    && reason_key.as_deref() == Some("no_block_download_needed_at_tip")
                {
                    rl_spec = Some((
                        "sync:header_state:no_block_download_needed_at_tip".to_string(),
                        cooldown,
                    ));
                } else if kind == "no_getblocks" {
                    if let Some((count, start, end)) = extract_block_span(msg_ref, "pushing ") {
                        let shared = count <= 32 || end.saturating_sub(start) <= 64;
                        let key = if shared {
                            format!("sync:{}:count:{}:range:{}-{}", kind, count, start, end)
                        } else if let Some(ip) = extract_ip_from_p2p_line(msg_ref) {
                            format!("sync:{}:{}:count:{}", kind, ip, count)
                        } else {
                            format!("sync:{}:count:{}", kind, count)
                        };
                        rl_spec = Some((key, cooldown.max(180)));
                    }
                } else if kind.starts_with("headers_new_") {
                    if let Some(count) = headers_count {
                        let key = if count >= 2000 {
                            format!("sync:{}:count:2000plus", kind)
                        } else if count <= 64 {
                            format!("sync:{}:count:{}", kind, count)
                        } else if let Some(ip) = extract_ip_from_p2p_line(msg_ref) {
                            format!("sync:{}:{}:count:{}", kind, ip, count)
                        } else {
                            format!("sync:{}:count:{}", kind, count)
                        };
                        let adjusted = if count >= 2000 {
                            cooldown.max(180)
                        } else {
                            cooldown
                        };
                        rl_spec = Some((key, adjusted));
                    }
                } else if let Some(ip) = extract_ip_from_p2p_line(msg_ref).or_else(|| {
                    extract_ip_from_prefix(msg_ref, "header-state peer=", " local_tip=")
                }) {
                    let key = if let Some(reason) = reason_key {
                        format!("sync:{}:{}:{}", kind, ip, reason)
                    } else {
                        format!("sync:{}:{}", kind, ip)
                    };
                    rl_spec = Some((key, cooldown));
                }
            }
        } else if Self::log_rate_limit_enabled() && category == "p2p" {
            if msg_ref.starts_with("Incoming P2P connection from ") {
                if let Some(rest) = msg_ref.strip_prefix("Incoming P2P connection from ") {
                    if let Some(sock) = extract_sock(rest) {
                        rl_spec = Some((
                            format!("p2p:incoming:{}", sock.ip()),
                            incoming_conn_log_cooldown_secs(),
                        ));
                    }
                }
            } else if msg_ref.starts_with("Rejecting inbound ") {
                if msg_ref.contains(": banned") {
                    if let Some(ip) =
                        extract_ip_from_prefix(msg_ref, "Rejecting inbound ", ": banned")
                    {
                        rl_spec = Some((
                            format!("p2p:reject_banned:{}", ip),
                            inbound_banned_log_cooldown_secs(),
                        ));
                    }
                } else if msg_ref.contains(": rate limit") {
                    if let Some(ip) =
                        extract_ip_from_prefix(msg_ref, "Rejecting inbound ", ": rate limit")
                    {
                        rl_spec = Some((
                            format!("p2p:reject_ratelimit:{}", ip),
                            inbound_banned_log_cooldown_secs(),
                        ));
                    }
                }
            } else if msg_ref.contains(": sending ") && msg_ref.contains(" blocks [") {
                if let Some((count, start, end)) = extract_block_span(msg_ref, "sending ") {
                    let cooldown = send_blocks_log_cooldown_secs();
                    if count <= 16 {
                        rl_spec = Some((
                            format!("p2p:send_blocks_small:{}:{}-{}", count, start, end),
                            cooldown.max(120),
                        ));
                    } else if count == 512 && start == 0 && end == 511 {
                        rl_spec = Some(("p2p:send_genesis_512".to_string(), cooldown.max(120)));
                    } else if let Some(ip) = extract_ip_from_p2p_line(msg_ref) {
                        rl_spec = Some((format!("p2p:send_blocks:{}:{}", ip, count), cooldown));
                    }
                }
            } else if msg_ref.contains("P2P handshake error from ") {
                if let Some(ip) = extract_ip_from_prefix(msg_ref, "P2P handshake error from ", ": ")
                {
                    rl_spec = Some((
                        format!("p2p:handshake_err:{}", ip),
                        handshake_error_log_cooldown_secs(),
                    ));
                }
            } else if msg_ref.contains("early eof") {
                if let Some(ip) = extract_ip_from_p2p_line(msg_ref).or_else(|| {
                    extract_ip_from_prefix(msg_ref, "early eof during sybil proof from ", ":")
                }) {
                    rl_spec = Some((
                        format!("p2p:early_eof:{}", ip),
                        handshake_error_log_cooldown_secs(),
                    ));
                }
            }
        }

        if Self::log_rate_limit_enabled() {
            static RL: OnceLock<StdMutex<HashMap<String, (Instant, u64)>>> = OnceLock::new();
            let rl = RL.get_or_init(|| StdMutex::new(HashMap::new()));

            if let Some((key, cooldown_secs)) = rl_spec {
                let now = Instant::now();
                let mut map = rl.lock().unwrap_or_else(|e| e.into_inner());
                let entry = map.entry(key).or_insert_with(|| {
                    (
                        Instant::now() - Duration::from_secs(cooldown_secs.saturating_add(1)),
                        0,
                    )
                });
                if now.duration_since(entry.0) < Duration::from_secs(cooldown_secs) {
                    entry.1 = entry.1.saturating_add(1);
                    return;
                }
                let suppressed = entry.1;
                entry.0 = now;
                entry.1 = 0;
                if suppressed > 0 {
                    suffix = Some(format!(" (suppressed {} repeats)", suppressed));
                }
            }
        }

        let msg_out: Cow<'_, str> = if let Some(suf) = suffix {
            Cow::Owned(format!("{}{}", msg_ref, suf))
        } else {
            Cow::Borrowed(msg_ref)
        };

        if Self::json_log_enabled() {
            let payload = json!({
                "ts": Self::ts(),
                "level": level,
                "cat": category,
                "icon": icon,
                "msg": msg_out,
            });
            if level == "error" {
                eprintln!("{}", payload);
            } else {
                eprintln!("{}", payload);
            }
        } else {
            let tag = if icon.is_empty() {
                category.to_string()
            } else {
                format!("{} {}", icon, category)
            };
            let line = format!("[{}] [{}] {}", Self::ts(), tag, msg_out);
            if level == "error" {
                eprintln!("{}", line);
            } else {
                eprintln!("{}", line);
            }
        }
    }

    fn log(msg: impl AsRef<str>) {
        Self::log_event("info", "p2p", msg);
    }

    fn log_err(msg: impl AsRef<str>) {
        Self::log_event("error", "p2p", msg);
    }

    fn verbose_messages() -> bool {
        static FLAG: OnceLock<bool> = OnceLock::new();
        *FLAG.get_or_init(|| {
            std::env::var("IRIUM_VERBOSE_P2P")
                .ok()
                .map(|v| {
                    let v = v.to_lowercase();
                    !(v == "0" || v == "false" || v == "off")
                })
                .unwrap_or(true)
        })
    }

    fn ping_interval() -> Duration {
        let secs = std::env::var("IRIUM_P2P_PING_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(60);
        let bounded = secs.max(5).min(300);
        Duration::from_secs(bounded)
    }

    fn handshake_interval() -> Duration {
        let secs = std::env::var("IRIUM_P2P_HANDSHAKE_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(120);
        let bounded = secs.max(30).min(600);
        Duration::from_secs(bounded)
    }

    fn peer_timeout() -> Duration {
        let secs = std::env::var("IRIUM_P2P_PEER_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(180);
        let bounded = secs.max(30).min(600);
        Duration::from_secs(bounded)
    }

    fn sybil_challenge_timeout() -> Duration {
        static DUR: OnceLock<Duration> = OnceLock::new();
        *DUR.get_or_init(|| {
            let secs = std::env::var("IRIUM_P2P_SYBIL_CHALLENGE_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .filter(|v| *v > 0)
                .unwrap_or(120);
            let bounded = secs.max(5).min(120);
            Duration::from_secs(bounded)
        })
    }

    fn outbound_connect_timeout() -> Duration {
        let secs = std::env::var("IRIUM_P2P_CONNECT_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(8);
        Duration::from_secs(secs.clamp(2, 30))
    }

    fn is_soft_block_reject(reason: &str) -> bool {
        let msg = reason.to_lowercase();
        msg.contains("duplicate block")
            || msg.contains("orphan")
            || msg.contains("unknown parent")
            || msg.contains("side chain")
    }

    fn is_duplicate_block(reason: &str) -> bool {
        reason.to_lowercase().contains("duplicate block")
    }

    fn is_banned(&self, ip: &IpAddr) -> bool {
        if self.banned_ips.contains(ip) {
            return true;
        }
        if self.trusted_seed_ips.contains(ip) {
            return false;
        }
        Self::is_banned_ip(ip, &self.banned_ips, &self.dynamic_bans)
    }

    fn is_banned_ip(
        ip: &IpAddr,
        static_bans: &HashSet<IpAddr>,
        dynamic_bans: &Arc<StdMutex<HashMap<IpAddr, Instant>>>,
    ) -> bool {
        if static_bans.contains(ip) {
            return true;
        }
        let mut guard = dynamic_bans.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        if let Some(until) = guard.get(ip).copied() {
            if now < until {
                return true;
            }
            guard.remove(ip);
        }
        false
    }

    fn tip_hash(chain: &Option<Arc<StdMutex<ChainState>>>) -> [u8; 32] {
        if let Some(ref c) = chain {
            let guard = c.lock().unwrap_or_else(|e| e.into_inner());
            let h = guard.tip_height();
            if let Some(last) = guard.chain.last() {
                return last.header.hash_for_height(h);
            }
        }
        [0u8; 32]
    }

    fn load_banned_ips() -> Arc<HashSet<IpAddr>> {
        let path = std::env::var("IRIUM_BANNED_LIST")
            .unwrap_or_else(|_| "bootstrap/banned_peers.txt".to_string());
        let mut ips = HashSet::new();
        let data = match fs::read_to_string(&path) {
            Ok(d) => d,
            Err(_) => return Arc::new(ips),
        };
        for line in data.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Ok(ip) = line.parse::<IpAddr>() {
                ips.insert(ip);
            }
        }
        Arc::new(ips)
    }

    fn load_trusted_seed_ips() -> Arc<HashSet<IpAddr>> {
        // Trusted peers are an explicit local operator override only.
        // Bootstrap sources must not implicitly bypass normal peer handling.
        let mut ips: HashSet<IpAddr> = HashSet::new();
        if let Ok(raw) = std::env::var("IRIUM_TRUSTED_PEERS") {
            for token in raw.split([',', ' ', '\n', '\t']) {
                let token = token.trim();
                if token.is_empty() {
                    continue;
                }
                if let Ok(ip) = token.parse::<IpAddr>() {
                    ips.insert(ip);
                    continue;
                }
                if let Ok(sa) = token.parse::<SocketAddr>() {
                    ips.insert(sa.ip());
                }
            }
        }
        Arc::new(ips)
    }

    fn sybil_difficulty() -> u8 {
        std::env::var("IRIUM_SYBIL_DIFFICULTY")
            .ok()
            .and_then(|v| v.parse::<u8>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(8)
    }

    fn sybil_banned_bump(banned_count: u8) -> u8 {
        let bump = std::env::var("IRIUM_SYBIL_BANNED_BUMP")
            .ok()
            .and_then(|v| v.parse::<u8>().ok())
            // Default 2: each wave of bans bumps difficulty up to 2 extra bits.
            .unwrap_or(2);
        if bump == 0 {
            return 0;
        }
        banned_count.min(bump)
    }
    fn max_peers_per_subnet_24() -> usize {
        std::env::var("IRIUM_P2P_MAX_PEERS_PER_SUBNET")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(3)
            .clamp(1, 20)
    }

    fn load_or_create_node_id() -> Vec<u8> {
        let path = storage::state_dir().join("node_id");
        if !path.exists() {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/".to_string());
            let legacy = PathBuf::from(home).join(".irium/node_id");
            if legacy.exists() {
                if let Some(parent) = path.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                let _ = fs::copy(&legacy, &path);
            }
        }
        if let Ok(existing) = fs::read_to_string(&path) {
            if let Ok(bytes) = hex::decode(existing.trim()) {
                if bytes.len() == 32 {
                    return bytes;
                }
            }
        }
        let mut buf = [0u8; 32];
        OsRng.fill_bytes(&mut buf);
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(&path, hex::encode(buf));
        buf.to_vec()
    }

    pub fn new(
        bind_addr: SocketAddr,
        agent: String,
        chain: Option<Arc<StdMutex<ChainState>>>,
        mempool: Option<Arc<StdMutex<MempoolManager>>>,
        relay_address: Option<String>,
        marketplace_feed: Option<String>,
        external_endpoint: Option<String>,
    ) -> Self {
        let proof_gossip_inbox = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let offer_take_inbox = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let offer_broadcast_inbox = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let seen_offer_ids = Arc::new(tokio::sync::Mutex::new((
            VecDeque::with_capacity(OFFER_BROADCAST_SEEN_CAP),
            HashSet::with_capacity(OFFER_BROADCAST_SEEN_CAP),
        )));
        let offer_rate_limit = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let dispute_raised_inbox = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let dispute_evidence_inbox = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let dispute_resolved_inbox = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let dispute_escalated_inbox = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        P2PNode {
            bind_addr,
            peers: Arc::new(Mutex::new(Vec::new())),
            peers_directory: Arc::new(Mutex::new(PeerDirectory::new())),
            connected: Arc::new(Mutex::new(HashSet::new())),
            reputation: Arc::new(Mutex::new(ReputationManager::new())),
            accept_log: Arc::new(Mutex::new(HashMap::new())),
            sync_requests: Arc::new(Mutex::new(HashMap::new())),
            block_requests: Arc::new(Mutex::new(HashMap::new())),
            getblocks_seen: Arc::new(Mutex::new(HashMap::new())),
            getblocks_last: Arc::new(Mutex::new(HashMap::new())),
            getblocks_genesis: Arc::new(Mutex::new(HashMap::new())),
            handshake_failures: Arc::new(Mutex::new(HashMap::new())),
            handshake_error_log: Arc::new(Mutex::new(HashMap::new())),
            banned_inbound_log: Arc::new(Mutex::new(HashMap::new())),
            send_blocks_log: Arc::new(Mutex::new(HashMap::new())),
            outbound_dial_inflight: Arc::new(StdMutex::new(HashSet::new())),
            outbound_dial_backoff: Arc::new(Mutex::new(HashMap::new())),
            self_ips: Arc::new(Mutex::new(HashSet::new())),
            dynamic_bans: Arc::new(StdMutex::new(HashMap::new())),
            chain,
            mempool,
            agent,
            relay_address,
            marketplace_feed,
            external_endpoint,
            proof_gossip_inbox,
            offer_take_inbox,
            offer_broadcast_inbox,
            seen_offer_ids,
            offer_rate_limit,
            dispute_raised_inbox,
            dispute_evidence_inbox,
            dispute_resolved_inbox,
            dispute_escalated_inbox,
            node_id: Self::load_or_create_node_id(),
            trusted_seed_ips: Self::load_trusted_seed_ips(),
            banned_ips: Self::load_banned_ips(),
        }
    }

    /// Start listening for incoming peers. This is a basic skeleton and
    /// performs a basic sybil-resistant handshake before accepting peers.
    pub async fn start(&self) -> Result<(), String> {
        let listener = TcpListener::bind(self.bind_addr)
            .await
            .map_err(|e| e.to_string())?;
        Self::log(format!("P2P listening on {}", self.bind_addr));

        let peers_arc = self.peers.clone();
        let bind = self.bind_addr;
        let dir_arc = self.peers_directory.clone();
        let rep_arc = self.reputation.clone();
        let connected = self.connected.clone();
        let chain = self.chain.clone();
        let mempool = self.mempool.clone();
        let agent = self.agent.clone();
        let relay_address = self.relay_address.clone();
        let marketplace_feed = self.marketplace_feed.clone();
        let external_endpoint = self.external_endpoint.clone();
        let proof_gossip_inbox = self.proof_gossip_inbox.clone();
        let offer_take_inbox = self.offer_take_inbox.clone();
        let offer_broadcast_inbox = self.offer_broadcast_inbox.clone();
        let seen_offer_ids = self.seen_offer_ids.clone();
        let offer_rate_limit = self.offer_rate_limit.clone();
        let dispute_raised_inbox = self.dispute_raised_inbox.clone();
        let dispute_evidence_inbox = self.dispute_evidence_inbox.clone();
        let dispute_resolved_inbox = self.dispute_resolved_inbox.clone();
        let dispute_escalated_inbox = self.dispute_escalated_inbox.clone();
        let accept_log = self.accept_log.clone();
        let sync_requests = self.sync_requests.clone();
        let block_requests = self.block_requests.clone();
        let getblocks_seen = self.getblocks_seen.clone();
        let getblocks_last = self.getblocks_last.clone();
        let getblocks_genesis = self.getblocks_genesis.clone();
        let handshake_failures = self.handshake_failures.clone();
        let handshake_error_log = self.handshake_error_log.clone();
        let banned_inbound_log = self.banned_inbound_log.clone();
        let send_blocks_log = self.send_blocks_log.clone();
        let self_ips = self.self_ips.clone();
        let dynamic_bans = self.dynamic_bans.clone();
        let trusted_seed_ips = self.trusted_seed_ips.clone();
        let node_id = self.node_id.clone();
        let banned_ips = self.banned_ips.clone();
        let dir_arc_for_periodic = self.peers_directory.clone();

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, addr)) => {
                        let ip = addr.ip();
                        let trusted = trusted_seed_ips.contains(&ip);
                        if trusted {
                            if let Ok(local_addr) = socket.local_addr() {
                                let local_ip = local_addr.ip();
                                if trusted_seed_should_dial(local_ip, ip) {
                                    // Deterministic tie-break: lower IP dials, higher IP accepts.
                                    // Prevents bidirectional trusted-seed connection storms.
                                    continue;
                                }
                            }
                            let guard = connected.lock().await;
                            if guard.iter().any(|a| a.ip() == ip) {
                                // Avoid multiple concurrent connections from the same trusted seed IP.
                                continue;
                            }
                        }
                        let dynamic_bans_check = dynamic_bans.clone();
                        if banned_ips.contains(&ip)
                            || (!trusted
                                && P2PNode::is_banned_ip(&ip, &banned_ips, &dynamic_bans_check))
                        {
                            let cooldown = Duration::from_secs(inbound_banned_log_cooldown_secs());
                            let mut guard = banned_inbound_log.lock().await;
                            let should_log = match guard.get(&ip) {
                                Some(last) => last.elapsed() >= cooldown,
                                None => true,
                            };
                            if should_log {
                                guard.insert(ip, Instant::now());
                                drop(guard);
                                Self::log_err(format!("Rejecting inbound {}: banned", addr));
                            }
                            continue;
                        }
                        {
                            let guard = self_ips.lock().await;
                            if guard.contains(&ip) {
                                P2PNode::log_event(
                                    "warn",
                                    "net",
                                    format!("Rejecting inbound {}: self-connection", addr),
                                );
                                continue;
                            }
                        }
                        let mut log_guard = accept_log.lock().await;
                        let cooldown = if trusted {
                            Duration::from_secs(trusted_seed_inbound_cooldown_secs())
                        } else {
                            Duration::from_millis(inbound_accept_cooldown_ms())
                        };
                        if let Some(last) = log_guard.get(&ip) {
                            if last.elapsed() < cooldown {
                                continue;
                            }
                        }
                        log_guard.insert(ip, Instant::now());
                        drop(log_guard);

                        let current = peers_arc.lock().await.len();
                        if current >= max_peers() {
                            Self::log_err(format!("Rejecting inbound {}: max peers reached", addr));
                            continue;
                        }
                        if !trusted {
                            let subnet_count = {
                                let guard = connected.lock().await;
                                guard
                                    .iter()
                                    .filter(|a| is_same_subnet_24(a.ip(), ip))
                                    .count()
                            };
                            if subnet_count >= P2PNode::max_peers_per_subnet_24() {
                                P2PNode::log_event(
                                    "warn",
                                    "net",
                                    format!(
                                        "Rejecting inbound {}: /24 subnet limit ({} peers)",
                                        addr, subnet_count
                                    ),
                                );
                                continue;
                            }
                        }
                        if incoming_conn_log_enabled() {
                            Self::log(format!("Incoming P2P connection from {}", addr));
                        }
                        let peers_inner = peers_arc.clone();
                        let connected_inner = connected.clone();
                        let dir = dir_arc.clone();
                        let rep = rep_arc.clone();
                        let chain_peer = chain.clone();
                        let mempool_peer = mempool.clone();
                        let agent_peer = agent.clone();
                        let relay_peer = relay_address.clone();
                        let marketplace_feed_peer = marketplace_feed.clone();
                        let external_endpoint_peer = external_endpoint.clone();
                        let proof_gossip_inbox_peer = proof_gossip_inbox.clone();
                        let offer_take_inbox_peer = offer_take_inbox.clone();
                        let offer_broadcast_inbox_peer = offer_broadcast_inbox.clone();
                        let seen_offer_ids_peer = seen_offer_ids.clone();
                        let offer_rate_limit_peer = offer_rate_limit.clone();
                        let dispute_raised_inbox_peer = dispute_raised_inbox.clone();
                        let dispute_evidence_inbox_peer = dispute_evidence_inbox.clone();
                        let dispute_resolved_inbox_peer = dispute_resolved_inbox.clone();
                        let dispute_escalated_inbox_peer = dispute_escalated_inbox.clone();
                        let node_id_peer = node_id.clone();
                        let self_ip_peer = self_ips.clone();
                        let sync_peer = sync_requests.clone();
                        let block_peer = block_requests.clone();
                        let getblocks_peer = getblocks_seen.clone();
                        let getblocks_last_peer = getblocks_last.clone();
                        let getblocks_genesis_peer = getblocks_genesis.clone();
                        let dynamic_bans_for_handshake = dynamic_bans.clone();
                        let handshake_failures_for_handshake = handshake_failures.clone();
                        let handshake_error_log_for_handshake = handshake_error_log.clone();
                        let send_blocks_log_peer = send_blocks_log.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_incoming_with_sybil(
                                socket,
                                addr,
                                bind,
                                peers_inner,
                                connected_inner.clone(),
                                dir.clone(),
                                rep.clone(),
                                sync_peer,
                                block_peer,
                                getblocks_peer,
                                getblocks_last_peer,
                                getblocks_genesis_peer,
                                send_blocks_log_peer,
                                self_ip_peer,
                                chain_peer,
                                mempool_peer,
                                agent_peer,
                                relay_peer,
                                marketplace_feed_peer,
                                external_endpoint_peer,
                                proof_gossip_inbox_peer,
                                offer_take_inbox_peer,
                                offer_broadcast_inbox_peer,
                                seen_offer_ids_peer,
                                offer_rate_limit_peer,
                                dispute_raised_inbox_peer,
                                dispute_evidence_inbox_peer,
                                dispute_resolved_inbox_peer,
                                dispute_escalated_inbox_peer,
                                node_id_peer,
                                trusted,
                            )
                            .await
                            {
                                let connected_peers_for_handshake =
                                    connected_inner.lock().await.len();
                                let (count, banned) = record_handshake_failure(
                                    &handshake_failures_for_handshake,
                                    &dynamic_bans_for_handshake,
                                    addr.ip(),
                                    trusted,
                                    connected_peers_for_handshake,
                                )
                                .await;
                                if banned {
                                    P2PNode::log_event(
                                        "warn",
                                        "reputation",
                                        format!(
                                            "P2P {}: temp-banning after {} handshake failures",
                                            addr.ip(),
                                            count
                                        ),
                                    );
                                } else if should_log_handshake_failure(count)
                                    && ip_log_allowed(
                                        &handshake_error_log_for_handshake,
                                        addr.ip(),
                                        Duration::from_secs(handshake_error_log_cooldown_secs()),
                                    )
                                    .await
                                {
                                    Self::log_err(format!(
                                        "P2P handshake error from {}: {}",
                                        addr, e
                                    ));
                                }
                            }
                        });
                    }
                    Err(e) => {
                        Self::log_err(format!("P2P accept error: {}", e));
                    }
                }
            }
        });

        // Periodic seedlist.runtime save every 10 minutes.
        {
            let dir = dir_arc_for_periodic;
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(600)).await;
                    dir.lock().await.refresh_seedlist_with_policy();
                }
            });
        }

        Ok(())
    }

    pub async fn flush_peers_to_runtime(&self) {
        self.peers_directory.lock().await.refresh_seedlist_with_policy();
    }

    /// Broadcast a raw serialized block to all currently known peers.
    pub async fn peer_count(&self) -> usize {
        self.peers.lock().await.len()
    }

    pub async fn peers_snapshot(&self) -> Vec<PeerRecord> {
        let dir = self.peers_directory.lock().await;
        let connected = self.connected.lock().await;
        dir.peers()
            .into_iter()
            .filter(|rec| {
                if let Some(addr) = Self::parse_multiaddr(&rec.multiaddr) {
                    connected.contains(&addr)
                } else {
                    false
                }
            })
            .collect()
    }

    pub async fn sync_debug_snapshot(&self) -> SyncDebugSnapshot {
        let sync_requests = self.sync_requests.lock().await.len();
        let block_requests = self.block_requests.lock().await.len();
        let handshake_failures = self.handshake_failures.lock().await.len();
        let getblocks_inflight = block_requests;
        SyncDebugSnapshot {
            sync_requests,
            block_requests,
            handshake_failures,
            getblocks_inflight,
        }
    }

    pub async fn peer_telemetry_snapshot(&self) -> PeerTelemetrySnapshot {
        let active_peers = self.peers.lock().await.len() as u64;
        let unique_connected_peer_ips = {
            let guard = self.connected.lock().await;
            guard
                .iter()
                .map(|addr| addr.ip())
                .collect::<HashSet<_>>()
                .len() as u64
        };
        let attempted_peer_ips = {
            let inflight = {
                let guard = self
                    .outbound_dial_inflight
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                guard.len() as u64
            };
            let backoff = {
                let now = Instant::now();
                let guard = self.outbound_dial_backoff.lock().await;
                guard.values().filter(|(_, until)| now < *until).count() as u64
            };
            inflight + backoff
        };
        let dynamic_bans = {
            let now = Instant::now();
            let mut guard = self.dynamic_bans.lock().unwrap_or_else(|e| e.into_inner());
            guard.retain(|_, until| now < *until);
            guard.len() as u64
        };
        let reputation_bans = {
            let rep = self.reputation.lock().await;
            rep.banned_count() as u64
        };
        PeerTelemetrySnapshot {
            outbound_dial_attempts_total: OUTBOUND_DIAL_ATTEMPTS_TOTAL.load(Ordering::Relaxed),
            outbound_dial_success_total: OUTBOUND_DIAL_SUCCESS_TOTAL.load(Ordering::Relaxed),
            outbound_dial_failure_total: OUTBOUND_DIAL_FAILURE_TOTAL.load(Ordering::Relaxed),
            outbound_dial_failure_timeout_total: OUTBOUND_DIAL_FAILURE_TIMEOUT_TOTAL
                .load(Ordering::Relaxed),
            outbound_dial_failure_refused_total: OUTBOUND_DIAL_FAILURE_REFUSED_TOTAL
                .load(Ordering::Relaxed),
            outbound_dial_failure_no_route_total: OUTBOUND_DIAL_FAILURE_NO_ROUTE_TOTAL
                .load(Ordering::Relaxed),
            outbound_dial_failure_banned_total: OUTBOUND_DIAL_FAILURE_BANNED_TOTAL
                .load(Ordering::Relaxed),
            outbound_dial_failure_backoff_total: OUTBOUND_DIAL_FAILURE_BACKOFF_TOTAL
                .load(Ordering::Relaxed),
            outbound_dial_failure_other_total: OUTBOUND_DIAL_FAILURE_OTHER_TOTAL
                .load(Ordering::Relaxed),
            inbound_accepted_total: INBOUND_ACCEPTED_TOTAL.load(Ordering::Relaxed),
            handshake_failures_total: HANDSHAKE_FAILURE_TOTAL.load(Ordering::Relaxed),
            temp_bans_total: TEMP_BAN_TOTAL.load(Ordering::Relaxed),
            active_peers,
            unique_connected_peer_ips,
            attempted_peer_ips,
            banned_peers: dynamic_bans + reputation_bans,
        }
    }

    pub async fn clear_sync_throttles(&self) {
        self.sync_requests.lock().await.clear();
        self.block_requests.lock().await.clear();
        self.getblocks_last.lock().await.clear();
        self.getblocks_genesis.lock().await.clear();
        // Allow fresh attempts against previously failing peers.
        self.handshake_failures.lock().await.clear();
    }

    pub async fn clear_transient_headers(&self) {
        let Some(chain_arc) = self.chain.as_ref() else {
            return;
        };
        let mut guard = chain_arc.lock().unwrap_or_else(|e| e.into_inner());
        let dropped = guard.headers.len();
        if dropped > 0 {
            guard.headers.clear();
            guard.header_chain.clear();
            P2PNode::log_event(
                "warn",
                "sync",
                format!("Cleared {} transient headers after sync stall", dropped),
            );
        }
    }

    /// Proactively request headers and blocks from all connected peers at the current tip.
    pub async fn force_sync_burst_from_tip(
        &self,
        start_hash: [u8; 32],
    ) -> Result<(usize, usize), String> {
        let headers = GetHeadersPayload {
            start_hash: start_hash.to_vec(),
            count: MAX_HEADERS_PER_REQUEST,
        }
        .to_message()?;
        let blocks = GetBlocksPayload {
            start_hash: start_hash.to_vec(),
            count: MAX_BLOCKS_PER_REQUEST,
        }
        .to_message()?;

        let headers_ok = broadcast_raw(&self.peers, &headers.serialize()).await;
        let blocks_ok = broadcast_raw(&self.peers, &blocks.serialize()).await;
        if headers_ok == 0 && blocks_ok == 0 {
            return Err("sync burst had no writable peers".to_string());
        }
        Ok((headers_ok, blocks_ok))
    }

    /// Request peer lists from all connected peers.
    pub async fn request_peers(&self) -> Result<(), String> {
        let msg = EmptyPayload::to_message(MessageType::GetPeers)?;
        let bytes = msg.serialize();
        let ok = broadcast_raw(&self.peers, &bytes).await;
        if ok == 0 {
            return Err("failed to send getpeers: no peers accepted the message".to_string());
        }
        Ok(())
    }

    /// Force a refresh of the runtime seedlist based on current peer directory.
    pub async fn refresh_seedlist(&self) {
        let mut dir = self.peers_directory.lock().await;
        dir.refresh_seedlist_with_policy();
    }

    /// Parse a multiaddr like /ip4/1.2.3.4/tcp/38291 into a SocketAddr.
    fn parse_multiaddr(multiaddr: &str) -> Option<std::net::SocketAddr> {
        let parts: Vec<&str> = multiaddr.split('/').filter(|s| !s.is_empty()).collect();
        if parts.len() < 4 {
            return None;
        }
        match parts[0] {
            "ip4" | "ip6" => {}
            _ => return None,
        }
        let ip: std::net::IpAddr = parts[1].parse().ok()?;
        if parts[2] != "tcp" {
            return None;
        }
        let port: u16 = parts[3].parse().ok()?;
        Some(std::net::SocketAddr::new(ip, port))
    }

    fn local_height_value(&self) -> u64 {
        local_height(&self.chain)
    }

    /// Opportunistically dial peers we have learned about from gossip.
    /// Opportunistically dial peers we have learned about from gossip.

    pub async fn outbound_dial_allowed(&self, addr: &SocketAddr) -> bool {
        let ip = addr.ip();
        if self.is_banned(&ip) {
            return false;
        }
        {
            let guard = match self.outbound_dial_inflight.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            if guard.contains(&ip) {
                return false;
            }
        }
        {
            let guard = self.outbound_dial_backoff.lock().await;
            if let Some((_, until)) = guard.get(&ip) {
                if Instant::now() < *until {
                    return false;
                }
            }
        }
        {
            let guard = self.connected.lock().await;
            if guard.iter().any(|a| a.ip() == ip) {
                return false;
            }
        }
        true
    }

    async fn begin_outbound_dial(&self, ip: IpAddr) -> Result<OutboundDialGuard, String> {
        if self.is_banned(&ip) {
            return Err(format!("peer {} is banned (banlist)", ip));
        }
        {
            let guard = self.connected.lock().await;
            if guard.iter().any(|a| a.ip() == ip) {
                return Err("already connected".to_string());
            }
        }
        {
            let guard = self.outbound_dial_backoff.lock().await;
            if let Some((_, until)) = guard.get(&ip) {
                if Instant::now() < *until {
                    return Err("dial backoff".to_string());
                }
            }
        }
        {
            let mut guard = match self.outbound_dial_inflight.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            if guard.contains(&ip) {
                return Err("dial in progress".to_string());
            }
            guard.insert(ip);
        }
        Ok(OutboundDialGuard {
            ip,
            inflight: self.outbound_dial_inflight.clone(),
        })
    }

    async fn record_outbound_dial_success(&self, ip: IpAddr) {
        OUTBOUND_DIAL_SUCCESS_TOTAL.fetch_add(1, Ordering::Relaxed);
        let mut guard = self.outbound_dial_backoff.lock().await;
        guard.remove(&ip);
    }

    async fn record_outbound_dial_failure(&self, ip: IpAddr, err: &str) {
        OUTBOUND_DIAL_FAILURE_TOTAL.fetch_add(1, Ordering::Relaxed);
        match classify_outbound_dial_failure(err) {
            "timeout" => OUTBOUND_DIAL_FAILURE_TIMEOUT_TOTAL.fetch_add(1, Ordering::Relaxed),
            "refused" => OUTBOUND_DIAL_FAILURE_REFUSED_TOTAL.fetch_add(1, Ordering::Relaxed),
            "no_route" => OUTBOUND_DIAL_FAILURE_NO_ROUTE_TOTAL.fetch_add(1, Ordering::Relaxed),
            "banned" => OUTBOUND_DIAL_FAILURE_BANNED_TOTAL.fetch_add(1, Ordering::Relaxed),
            "backoff" => OUTBOUND_DIAL_FAILURE_BACKOFF_TOTAL.fetch_add(1, Ordering::Relaxed),
            _ => OUTBOUND_DIAL_FAILURE_OTHER_TOTAL.fetch_add(1, Ordering::Relaxed),
        };
        let base_secs = outbound_dial_base_secs();
        let max_secs = outbound_dial_max_secs();
        let banned_secs = outbound_dial_banned_secs();
        if err.contains("trusted seed: prefer inbound") {
            let mut guard = self.outbound_dial_backoff.lock().await;
            guard.insert(ip, (1, Instant::now() + Duration::from_secs(banned_secs)));
            return;
        }
        let mut guard = self.outbound_dial_backoff.lock().await;
        let (fails, _) = guard.get(&ip).copied().unwrap_or((0, Instant::now()));
        let next = fails.saturating_add(1);
        let backoff = if err.contains("banned") {
            Duration::from_secs(banned_secs)
        } else {
            let exp = 2u64.saturating_pow(next.min(10));
            Duration::from_secs((base_secs.saturating_mul(exp)).min(max_secs))
        };
        guard.insert(ip, (next, Instant::now() + backoff));
    }

    pub async fn connect_known_peers(&self, max_new: usize) {
        let current = self.peer_count().await;
        let mut added = 0usize;
        let local_height = self.local_height_value();
        let mut peers = {
            let dir = self.peers_directory.lock().await;
            dir.peers()
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        peers.sort_by(|a, b| {
            let score = |record: &PeerRecord| {
                let trusted = Self::parse_multiaddr(&record.multiaddr)
                    .map(|addr| self.trusted_seed_ips.contains(&addr.ip()))
                    .unwrap_or(false);
                let ahead = record.last_height.unwrap_or(0) > local_height;
                let idle_hours =
                    ((now - record.last_seen.max(record.first_seen)).max(0.0)) / 3600.0;
                let freshness = if idle_hours <= 1.0 {
                    3u8
                } else if idle_hours <= 24.0 {
                    2u8
                } else if idle_hours <= outbound_candidate_max_idle_hours() {
                    1u8
                } else {
                    0u8
                };
                (
                    trusted as u8,
                    record.dialable as u8,
                    ahead as u8,
                    freshness,
                    record.last_height.unwrap_or(0),
                    record.last_seen as u64,
                )
            };
            score(b).cmp(&score(a))
        });
        let mut scanned = 0usize;
        let mut attempted_ahead = false;
        let mut attempted_ips: HashSet<IpAddr> = HashSet::new();

        for record in peers.iter() {
            scanned += 1;
            if scanned > connect_known_peer_scan_limit_ahead() {
                break;
            }
            if current + added >= max_peers() || added >= max_new {
                break;
            }
            let record_height = record.last_height.unwrap_or(0);
            if record_height <= local_height {
                continue;
            }
            attempted_ahead = true;
            if let Some(addr) = Self::parse_multiaddr(&record.multiaddr) {
                let trusted = self.trusted_seed_ips.contains(&addr.ip());
                let idle_hours =
                    ((now - record.last_seen.max(record.first_seen)).max(0.0)) / 3600.0;
                if !trusted && idle_hours > outbound_candidate_max_idle_hours() {
                    continue;
                }
                if !trusted && now > record.last_seen && (now - record.last_seen) < 15.0 {
                    continue;
                }
                if !attempted_ips.insert(addr.ip()) {
                    continue;
                }
                if !self.outbound_dial_allowed(&addr).await {
                    continue;
                }
                if (addr.ip() == self.bind_addr.ip() && addr.port() == self.bind_addr.port())
                    || self.is_banned(&addr.ip())
                {
                    continue;
                }
                if self.is_self_ip(addr.ip()).await {
                    continue;
                }
                if self.is_ip_connected(addr.ip()).await {
                    continue;
                }
                let node_clone = self.clone();
                let agent_clone = self.agent.clone();
                tokio::spawn(async move {
                    let _ = node_clone
                        .connect_and_handshake(addr, local_height, &agent_clone)
                        .await;
                });
                added += 1;
            }
        }

        if current + added >= max_peers() || added >= max_new {
            return;
        }

        scanned = 0;
        for record in peers {
            scanned += 1;
            if scanned > connect_known_peer_scan_limit_fallback() {
                break;
            }
            if current + added >= max_peers() || added >= max_new {
                break;
            }
            if let Some(addr) = Self::parse_multiaddr(&record.multiaddr) {
                let trusted = self.trusted_seed_ips.contains(&addr.ip());
                let idle_hours =
                    ((now - record.last_seen.max(record.first_seen)).max(0.0)) / 3600.0;
                if !trusted && idle_hours > outbound_candidate_max_idle_hours() {
                    continue;
                }
                if attempted_ahead && !trusted && record.last_height.unwrap_or(0) <= local_height {
                    continue;
                }
                if !trusted && now > record.last_seen && (now - record.last_seen) < 15.0 {
                    continue;
                }
                if !attempted_ips.insert(addr.ip()) {
                    continue;
                }
                if !self.outbound_dial_allowed(&addr).await {
                    continue;
                }
                if (addr.ip() == self.bind_addr.ip() && addr.port() == self.bind_addr.port())
                    || self.is_banned(&addr.ip())
                {
                    continue;
                }
                if self.is_self_ip(addr.ip()).await {
                    continue;
                }
                if self.is_ip_connected(addr.ip()).await {
                    continue;
                }
                let node_clone = self.clone();
                let agent_clone = self.agent.clone();
                tokio::spawn(async move {
                    let _ = node_clone
                        .connect_and_handshake(addr, local_height, &agent_clone)
                        .await;
                });
                added += 1;
            }
        }
    }

    pub async fn current_sybil_difficulty(&self) -> u8 {
        let base = Self::sybil_difficulty();
        let max = std::env::var("IRIUM_SYBIL_DIFFICULTY_MAX")
            .ok()
            .and_then(|v| v.parse::<u8>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(20);
        let banned = {
            let rep = self.reputation.lock().await;
            rep.banned_count() as u8
        };
        let bump = Self::sybil_banned_bump(banned);
        let adj = base.saturating_add(bump);
        adj.min(max)
    }

    pub fn node_id_hex(&self) -> String {
        hex::encode(&self.node_id)
    }

    pub async fn is_connected(&self, addr: &SocketAddr) -> bool {
        let guard = self.connected.lock().await;
        guard.contains(addr)
    }

    pub async fn is_ip_connected(&self, ip: IpAddr) -> bool {
        let guard = self.connected.lock().await;
        guard.iter().any(|addr| addr.ip() == ip)
    }

    pub async fn is_self_ip(&self, ip: IpAddr) -> bool {
        let guard = self.self_ips.lock().await;
        guard.contains(&ip)
    }

    pub fn relay_telemetry_snapshot() -> RelayTelemetrySnapshot {
        RelayTelemetrySnapshot {
            new_tip_announced_count: NEW_TIP_ANNOUNCED_COUNT.load(Ordering::Relaxed),
            block_announce_peers_count_total: BLOCK_ANNOUNCE_PEERS_COUNT_TOTAL
                .load(Ordering::Relaxed),
            block_request_count: BLOCK_REQUEST_COUNT.load(Ordering::Relaxed),
            duplicate_block_suppressed_count: DUPLICATE_BLOCK_SUPPRESSED_COUNT
                .load(Ordering::Relaxed),
            avg_block_processing_ms: average_counter(
                &BLOCK_PROCESSING_MS_TOTAL,
                &BLOCK_PROCESSING_SAMPLES,
            ),
            avg_block_announce_delay_ms: average_counter(
                &BLOCK_ANNOUNCE_DELAY_MS_TOTAL,
                &BLOCK_ANNOUNCE_DELAY_SAMPLES,
            ),
        }
    }

    pub async fn broadcast_block(&self, block_bytes: &[u8]) -> Result<(), String> {
        // Peek prev_hash from the raw bytes (fork-invariant byte order), look
        // up parent in our chain to derive block_height, then do the full
        // height-aware deserialize. Required so the merkle_root byte order
        // decodes correctly at/post the height-30000 hard fork. Pre-fork
        // heights produce identical bytes to the pre-Fix-2a behavior.
        let prev_peek = crate::block::BlockHeader::peek_prev_hash(block_bytes)?;
        let block_height = if let Some(chain_arc) = self.chain.as_ref() {
            let guard = chain_arc.lock().unwrap_or_else(|e| e.into_inner());
            if prev_peek == [0u8; 32] {
                0
            } else if let Some(h) = guard
                .heights
                .get(&prev_peek)
                .copied()
                .or_else(|| guard.headers.get(&prev_peek).map(|hw| hw.height))
            {
                h + 1
            } else {
                0
            }
        } else {
            0
        };
        let (block, _) = Block::deserialize_for_height(block_bytes, block_height)?;
        let block_hash = block.header.hash_for_height(block_height);
        let now = Instant::now();

        {
            let cache = recent_relayed_blocks();
            let mut guard = cache.lock().await;
            if !guard.record_at(block_hash, now) {
                DUPLICATE_BLOCK_SUPPRESSED_COUNT.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
        }

        let should_announce_headers = {
            let cache = recent_announced_blocks();
            let mut guard = cache.lock().await;
            guard.record_at(block_hash, now)
        };
        let header_peers = if should_announce_headers {
            let header_msg = HeadersPayload {
                headers: block.header.serialize_for_height(block_height),
            }
            .to_message();
            broadcast_raw(&self.peers, &header_msg.serialize()).await
        } else {
            0
        };

        let msg = BlockPayload {
            block_data: block_bytes.to_vec(),
        }
        .to_message();
        let serialized = msg.serialize();
        let block_peers = broadcast_raw(&self.peers, &serialized).await;
        let announced_peers = header_peers.max(block_peers) as u64;

        NEW_TIP_ANNOUNCED_COUNT.fetch_add(1, Ordering::Relaxed);
        BLOCK_ANNOUNCE_PEERS_COUNT_TOTAL.fetch_add(announced_peers, Ordering::Relaxed);
        record_block_announce_delay_ms(now.elapsed().as_millis() as u64);

        P2PNode::log_event(
            "info",
            "relay",
            format!(
                "P2P relay: announced block {} to {} peers (headers_first=true, full_block_fallback=true)",
                short_hash(block_hash),
                announced_peers
            ),
        );
        Ok(())
    }

    /// Broadcast a raw serialized transaction to all connected peers.
    pub async fn broadcast_tx(&self, tx_bytes: &[u8]) -> Result<(), String> {
        let msg = TxPayload {
            tx_data: tx_bytes.to_vec(),
        }
        .to_message();
        let serialized = msg.serialize();

        let _ = broadcast_raw(&self.peers, &serialized).await;
        Ok(())
    }

    /// Broadcast an INV for given txids.
    pub async fn broadcast_inv(&self, txids: Vec<String>) -> Result<(), String> {
        if txids.is_empty() {
            return Ok(());
        }
        let msg = InvPayload { txids }.to_message()?;
        let serialized = msg.serialize();
        let _ = broadcast_raw(&self.peers, &serialized).await;
        Ok(())
    }

    /// Broadcast a settlement proof to all connected peers.
    pub async fn broadcast_proof(&self, proof_json: &str) {
        let payload = crate::protocol::ProofGossipPayload {
            proof_json: proof_json.as_bytes().to_vec(),
        };
        let serialized = payload.to_message().serialize();
        let _ = broadcast_raw(&self.peers, &serialized).await;
    }

    /// Broadcast an offer-take notification to every connected peer. The
    /// seller's iriumd (if it's among our peers) parses the JSON, matches
    /// the offer_id+seller_pubkey against its own ~/.irium/offers/ files,
    /// and mutates status from "open" to "taken". All other peers ignore
    /// the message because no offer file matches.
    ///
    /// Best-effort: no acknowledgement is expected from the seller. If the
    /// notification is lost, the seller's relisting watchdog (the 5 s
    /// offer-watcher background task in iriumd) catches the un-funded
    /// taken-state after IRIUM_OFFER_RELIST_GRACE_BLOCKS and resets the
    /// offer to "open" automatically.
    pub async fn broadcast_offer_take(&self, take_json: &str) {
        let payload = crate::protocol::OfferTakeNotificationPayload {
            take_json: take_json.as_bytes().to_vec(),
        };
        let serialized = payload.to_message().serialize();
        let _ = broadcast_raw(&self.peers, &serialized).await;
    }

    /// Phase 1A+1B: broadcast a newly-created (or republished) local offer
    /// to all connected peers. Mirrors broadcast_offer_take — best-effort
    /// flood, no ack. Receiving peers run try_accept_offer_broadcast for
    /// size/rate/dedup checks before storing + re-broadcasting.
    pub async fn broadcast_offer(&self, offer_json: &str) {
        let payload = crate::protocol::OfferBroadcastPayload {
            offer_json: offer_json.as_bytes().to_vec(),
        };
        let serialized = payload.to_message().serialize();
        let _ = broadcast_raw(&self.peers, &serialized).await;
    }

    /// Phase 1A+1B: drain accumulated incoming offer JSON strings. Called
    /// by iriumd offer-watcher, which writes each JSON to
    /// ~/.irium/offers/<id>.json so /offers/feed serves it locally.
    pub async fn drain_offer_broadcasts(&self) -> Vec<String> {
        let mut inbox = self.offer_broadcast_inbox.lock().await;
        std::mem::take(&mut *inbox)
    }

    /// Drain all proof JSON strings received via P2P gossip since last call.
    pub async fn drain_proof_gossip(&self) -> Vec<String> {
        let mut inbox = self.proof_gossip_inbox.lock().await;
        std::mem::take(&mut *inbox)
    }

    /// Drain all offer-take notification JSON strings received via P2P
    /// since the last call. iriumd's offer-take drain task polls this on
    /// a 2 s cadence and processes each one (see process_received_offer_take).
    pub async fn drain_offer_take_notifications(&self) -> Vec<String> {
        let mut inbox = self.offer_take_inbox.lock().await;
        std::mem::take(&mut *inbox)
    }

    /// Broadcast a DisputeRaise (JSON) to every connected peer.
    pub async fn broadcast_dispute_raised(&self, json: &str) {
        let payload = crate::protocol::DisputeRaisedNotificationPayload {
            json: json.as_bytes().to_vec(),
        };
        let serialized = payload.to_message().serialize();
        let _ = broadcast_raw(&self.peers, &serialized).await;
    }

    /// Broadcast a DisputeEvidence (JSON) to every connected peer.
    pub async fn broadcast_dispute_evidence(&self, json: &str) {
        let payload = crate::protocol::DisputeEvidenceNotificationPayload {
            json: json.as_bytes().to_vec(),
        };
        let serialized = payload.to_message().serialize();
        let _ = broadcast_raw(&self.peers, &serialized).await;
    }

    /// Broadcast a DisputeResolution (JSON) to every connected peer.
    pub async fn broadcast_dispute_resolved(&self, json: &str) {
        let payload = crate::protocol::DisputeResolvedNotificationPayload {
            json: json.as_bytes().to_vec(),
        };
        let serialized = payload.to_message().serialize();
        let _ = broadcast_raw(&self.peers, &serialized).await;
    }

    /// Broadcast a dispute escalation announcement (JSON) to every peer.
    pub async fn broadcast_dispute_escalated(&self, json: &str) {
        let payload = crate::protocol::DisputeEscalatedNotificationPayload {
            json: json.as_bytes().to_vec(),
        };
        let serialized = payload.to_message().serialize();
        let _ = broadcast_raw(&self.peers, &serialized).await;
    }

    /// Drain incoming DisputeRaise JSON strings since last call.
    pub async fn drain_dispute_raised_notifications(&self) -> Vec<String> {
        let mut inbox = self.dispute_raised_inbox.lock().await;
        std::mem::take(&mut *inbox)
    }

    /// Drain incoming DisputeEvidence JSON strings since last call.
    pub async fn drain_dispute_evidence_notifications(&self) -> Vec<String> {
        let mut inbox = self.dispute_evidence_inbox.lock().await;
        std::mem::take(&mut *inbox)
    }

    /// Drain incoming DisputeResolution JSON strings since last call.
    pub async fn drain_dispute_resolved_notifications(&self) -> Vec<String> {
        let mut inbox = self.dispute_resolved_inbox.lock().await;
        std::mem::take(&mut *inbox)
    }

    /// Drain incoming dispute-escalated JSON announcements since last call.
    pub async fn drain_dispute_escalated_notifications(&self) -> Vec<String> {
        let mut inbox = self.dispute_escalated_inbox.lock().await;
        std::mem::take(&mut *inbox)
    }

    /// Establish an outbound connection to a peer and send a handshake
    /// message describing this node's view of the chain.
    ///
    /// This is a minimal implementation intended for mainnet nodes to
    /// begin forming a Rust-native P2P mesh; full peer management and
    /// message handling will be layered on top of this.
    pub async fn connect_and_handshake(
        &self,
        addr: SocketAddr,
        local_height_val: u64,
        agent: &str,
    ) -> Result<(), String> {
        if self.is_connected(&addr).await {
            return Ok(());
        }
        if self.is_self_ip(addr.ip()).await {
            return Ok(());
        }
        if self.is_ip_connected(addr.ip()).await {
            return Ok(());
        }
        if self.is_banned(&addr.ip()) {
            return Err(format!("peer {} is banned (banlist)", addr));
        }
        let ip = addr.ip();
        let _dial_guard = self.begin_outbound_dial(ip).await?;
        OUTBOUND_DIAL_ATTEMPTS_TOTAL.fetch_add(1, Ordering::Relaxed);
        // Simple jittered delay before connecting to avoid thundering herd.
        let jitter_ms = (rand_core::OsRng.next_u32() % 5000) as u64;
        tokio::time::sleep(std::time::Duration::from_millis(jitter_ms)).await;
        let mut stream =
            match tokio::time::timeout(Self::outbound_connect_timeout(), TcpStream::connect(addr))
                .await
            {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    let msg = format!("connect to {} failed: {}", addr, e);
                    self.record_outbound_dial_failure(ip, &msg).await;
                    return Err(msg);
                }
                Err(_) => {
                    let msg = format!(
                        "connect to {} failed: connect timeout after {}s",
                        addr,
                        Self::outbound_connect_timeout().as_secs()
                    );
                    self.record_outbound_dial_failure(ip, &msg).await;
                    return Err(msg);
                }
            };

        let trusted_seed = self.trusted_seed_ips.contains(&ip);
        if trusted_seed {
            if let Ok(local_addr) = stream.local_addr() {
                let local_ip = local_addr.ip();
                if !trusted_seed_should_dial(local_ip, ip) {
                    // We are the higher IP: prefer inbound-only for this trusted seed.
                    // This avoids seed<->seed double connections where both sides dial and then drop.
                    let _ = stream.shutdown().await;
                    self.record_outbound_dial_failure(ip, "trusted seed: prefer inbound")
                        .await;
                    return Ok(());
                }
            }
        }

        // Check reputation before keeping a long-lived connection.
        {
            let peer_id = trusted_anchor_peer_id(addr, trusted_seed);
            let mut rep = self.reputation.lock().await;
            if !trusted_seed && rep.is_banned(&peer_id) {
                return Err(format!("peer {} is banned", peer_id));
            }
            rep.record_success(&peer_id);
        }

        Self::log(format!(
            "P2P outbound {}: connected, awaiting challenge",
            addr
        ));
        // Expect a sybil challenge from the remote and respond with a proof
        // before proceeding with the normal handshake.
        let challenge_msg =
            match read_message_with_timeout(&mut stream, Self::sybil_challenge_timeout()).await {
                Ok(m) => m,
                Err(e) => {
                    self.record_outbound_dial_failure(ip, &e).await;
                    let mut rep = self.reputation.lock().await;
                    // FIX #128: no bytes received yet -> dial failure,
                    // not handshake misbehavior. Don't subtract score.
                    rep.record_dial_failure(&trusted_anchor_peer_id(addr, trusted_seed));
                    return Err(e);
                }
            };
        if challenge_msg.msg_type != MessageType::SybilChallenge {
            let mut rep = self.reputation.lock().await;
            rep.record_failure(&trusted_anchor_peer_id(addr, trusted_seed));
            return Err("expected sybil challenge from peer".to_string());
        }
        let challenge = match SybilChallenge::from_bytes(&challenge_msg.payload) {
            Some(c) => c,
            None => {
                let mut rep = self.reputation.lock().await;
                rep.record_failure(&trusted_anchor_peer_id(addr, trusted_seed));
                return Err("invalid sybil challenge payload".to_string());
            }
        };

        // Bind proof-of-work to a persistent node identity derived from disk.
        let peer_pubkey = self.node_id.clone();
        let difficulty = challenge.difficulty;
        let pubkey = peer_pubkey.to_vec();
        let proof = tokio::task::spawn_blocking(move || {
            let handshake = SybilResistantHandshake::new(difficulty);
            handshake.solve_challenge(challenge, pubkey)
        })
        .await
        .map_err(|e| format!("failed to join sybil solver: {}", e))?
        .map_err(|e| format!("failed to solve sybil challenge: {}", e))?;
        let proof_bytes = proof.to_bytes();
        let proof_msg = Message {
            msg_type: MessageType::SybilProof,
            payload: proof_bytes,
        };
        let proof_ser = proof_msg.serialize();
        if let Err(e) = stream.write_all(&proof_ser).await {
            let msg = format!("send sybil proof to {} failed: {}", addr, e);
            self.record_outbound_dial_failure(ip, &msg).await;
            return Err(msg);
        }
        Self::log(format!("P2P outbound {}: sent sybil proof", addr));

        let (checkpoint_height, checkpoint_hash) = best_checkpoint(&self.chain);
        let payload = HandshakePayload {
            version: 1,
            agent: agent.to_string(),
            height: local_height_val,
            timestamp: Utc::now().timestamp(),
            port: self.bind_addr.port(),
            checkpoint_height,
            checkpoint_hash,
            relay_address: self.relay_address.clone(),
            node_id: Some(hex::encode(&self.node_id)),
            tip_hash: Some(hex::encode(P2PNode::tip_hash(&self.chain))),
            capabilities: local_capabilities(),
            marketplace_feed: self.marketplace_feed.clone(),
            external_endpoint: self.external_endpoint.clone(),
        };

        let msg = payload
            .to_message()
            .map_err(|e| format!("build handshake message failed: {}", e))?;
        let bytes = msg.serialize();

        if let Err(e) = stream.write_all(&bytes).await {
            let msg = format!("send handshake to {} failed: {}", addr, e);
            self.record_outbound_dial_failure(ip, &msg).await;
            return Err(msg);
        }
        Self::log(format!("P2P outbound {}: sent handshake", addr));

        let (mut reader, writer_half) = stream.into_split();
        let writer = Arc::new(tokio::sync::Mutex::new(writer_half));

        {
            let mut guard = self.peers.lock().await;
            guard.push(writer.clone());
        }
        {
            let mut guard = self.connected.lock().await;
            guard.insert(addr);
        }

        self.record_outbound_dial_success(ip).await;

        {
            let mut dir = self.peers_directory.lock().await;
            let multiaddr = format!("/ip4/{}/tcp/{}", addr.ip(), addr.port());
            dir.register_connection(multiaddr, None, self.relay_address.clone(), None);
        }

        let peer_state = Arc::new(Mutex::new(PeerSyncState::default()));
        let (shutdown_tx_to_ping, mut shutdown_rx_to_ping) = tokio::sync::oneshot::channel::<()>();
        let (shutdown_tx_to_reader, mut shutdown_rx_to_reader) =
            tokio::sync::oneshot::channel::<()>();
        let ping_writer_weak = Arc::downgrade(&writer);
        let ping_addr = addr;
        let ping_chain = self.chain.clone();
        let ping_agent = agent.to_string();
        let ping_relay = self.relay_address.clone();
        let ping_marketplace_feed = self.marketplace_feed.clone();
        let ping_external_endpoint = self.external_endpoint.clone();
        let ping_port = self.bind_addr.port();
        let ping_node_id = self.node_id.clone();
        let ping_peer_state = peer_state.clone();
        let ping_sync_requests = self.sync_requests.clone();
        let ping_block_requests = self.block_requests.clone();
        let ping_peers_vec = self.peers.clone();
        let ping_connected_vec = self.connected.clone();
        tokio::spawn(async move {
            let mut shutdown_tx_to_reader = Some(shutdown_tx_to_reader);
            let ping_interval = P2PNode::ping_interval();
            let sync_tick = sync_tick_interval();
            let mut last_ping = Instant::now();
            let mut last_height = crate::p2p::local_height(&ping_chain);
            let mut last_handshake = Instant::now();
            let mut stalled_heartbeats: u32 = 0;
            let mut last_progress_height = crate::p2p::local_height(&ping_chain);
            let mut recovery_in_progress = false;
            let mut recovery_start_height = last_progress_height;
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(sync_tick) => {}
                    _ = &mut shutdown_rx_to_ping => {
                        break;
                    }
                }
                let ping_writer = match ping_writer_weak.upgrade() {
                    Some(w) => w,
                    None => break,
                };
                if last_ping.elapsed() >= ping_interval {
                    let nonce = rand_core::OsRng.next_u64();
                    let ping = PingPayload { nonce };
                    let msg = ping.to_message();
                    if !send_message_or_disconnect(
                        &ping_writer,
                        msg,
                        ping_addr,
                        &ping_peers_vec,
                        &ping_connected_vec,
                    )
                    .await
                    {
                        if let Some(tx) = shutdown_tx_to_reader.take() {
                            let _ = tx.send(());
                        }
                        break;
                    }
                    last_ping = Instant::now();
                }
                let current_height = crate::p2p::local_height(&ping_chain);
                let handshake_due = last_handshake.elapsed() >= P2PNode::handshake_interval();
                if handshake_due || current_height != last_height {
                    let (checkpoint_height, checkpoint_hash) = best_checkpoint(&ping_chain);
                    let payload = HandshakePayload {
                        version: 1,
                        agent: ping_agent.clone(),
                        height: current_height,
                        timestamp: Utc::now().timestamp(),
                        port: ping_port,
                        checkpoint_height,
                        checkpoint_hash,
                        relay_address: ping_relay.clone(),
                        node_id: Some(hex::encode(&ping_node_id)),
                        tip_hash: Some(hex::encode(P2PNode::tip_hash(&ping_chain))),
                        capabilities: local_capabilities(),
                        marketplace_feed: ping_marketplace_feed.clone(),
                        external_endpoint: ping_external_endpoint.clone(),
                    };
                    if let Ok(msg) = payload.to_message() {
                        if !send_message_or_disconnect(
                            &ping_writer,
                            msg,
                            ping_addr,
                            &ping_peers_vec,
                            &ping_connected_vec,
                        )
                        .await
                        {
                            break;
                        }
                    }
                    last_height = current_height;
                    last_handshake = Instant::now();
                    if uptime_enabled() {
                        let challenge = {
                            let mut state = ping_peer_state.lock().await;
                            if !state.supports_uptime {
                                None
                            } else {
                                let due = state
                                    .last_uptime_sent
                                    .map(|t| t.elapsed() >= uptime_interval())
                                    .unwrap_or(true);
                                if !due {
                                    None
                                } else {
                                    let mut nonce = [0u8; 32];
                                    OsRng.fill_bytes(&mut nonce);
                                    let timestamp = SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs();
                                    let payload = UptimeChallengePayload { nonce, timestamp };
                                    state.last_uptime_challenge = Some(payload.clone());
                                    state.last_uptime_sent = Some(Instant::now());
                                    Some(payload)
                                }
                            }
                        };
                        if let Some(payload) = challenge {
                            let msg = payload.to_message();
                            if !send_message_or_disconnect(
                                &ping_writer,
                                msg,
                                ping_addr,
                                &ping_peers_vec,
                                &ping_connected_vec,
                            )
                            .await
                            {
                                break;
                            }
                        }
                    }
                }
                maybe_request_sync(
                    &ping_writer,
                    ping_addr,
                    &ping_chain,
                    &ping_sync_requests,
                    &ping_block_requests,
                    &ping_peer_state,
                )
                .await;
                maybe_request_headers_fallback(
                    &ping_writer,
                    ping_addr,
                    &ping_chain,
                    &ping_sync_requests,
                    &ping_peer_state,
                )
                .await;
                let peer_height = {
                    let guard = ping_peer_state.lock().await;
                    guard.height
                };
                if let Some(net_height_raw) = peer_height {
                    let best_header_height = if let Some(ref c) = ping_chain {
                        let guard = c.lock().unwrap_or_else(|e| e.into_inner());
                        let best_hash = guard.best_header_hash();
                        guard
                            .headers
                            .get(&best_hash)
                            .map(|hw| hw.height)
                            .or_else(|| guard.heights.get(&best_hash).copied())
                            .unwrap_or(current_height)
                    } else {
                        current_height
                    };
                    let net_height =
                        trusted_remote_height(net_height_raw, best_header_height, current_height);
                    let ahead_delta = sync_stall_ahead_delta();
                    if best_header_height >= current_height.saturating_add(ahead_delta)
                        && net_height >= current_height.saturating_add(ahead_delta)
                    {
                        if current_height == last_progress_height {
                            stalled_heartbeats = stalled_heartbeats.saturating_add(1);
                        } else {
                            last_progress_height = current_height;
                            stalled_heartbeats = 0;
                            if recovery_in_progress {
                                P2PNode::log_event(
                                    "info",
                                    "sync",
                                    format!(
                                        "P2P {}: recovery complete (height advanced {} -> {})",
                                        ping_addr, recovery_start_height, current_height
                                    ),
                                );
                                recovery_in_progress = false;
                            }
                        }

                        let n = sync_stall_heartbeats();
                        if stalled_heartbeats >= n {
                            P2PNode::log_event(
                                "warn",
                                "sync",
                                format!(
                                    "Local chain appears stalled or on a fork/split (local height={}, network height={}). Attempting to recover by resyncing headers...",
                                    current_height, net_height
                                ),
                            );
                            let get_headers = GetHeadersPayload {
                                start_hash: vec![0u8; 32],
                                count: MAX_HEADERS_PER_REQUEST,
                            };
                            if let Ok(msg) = get_headers.to_message() {
                                if !send_message_or_disconnect(
                                    &ping_writer,
                                    msg,
                                    ping_addr,
                                    &ping_peers_vec,
                                    &ping_connected_vec,
                                )
                                .await
                                {
                                    break;
                                }
                            }
                            {
                                let mut state = ping_peer_state.lock().await;
                                state.last_headers_request = Some(Instant::now());
                                state.last_headers_start = Some([0u8; 32]);
                                state.headers_inflight = true;
                            }
                            stalled_heartbeats = 0;
                            recovery_in_progress = true;
                            recovery_start_height = current_height;
                        }
                    } else if current_height != last_progress_height {
                        last_progress_height = current_height;
                        stalled_heartbeats = 0;
                        if recovery_in_progress {
                            P2PNode::log_event(
                                "info",
                                "sync",
                                format!(
                                    "P2P {}: recovery complete (height advanced {} -> {})",
                                    ping_addr, recovery_start_height, current_height
                                ),
                            );
                            recovery_in_progress = false;
                        }
                    }
                }
            }
        });

        let dir = self.peers_directory.clone();
        let relay_addr = self.relay_address.clone();
        let _marketplace_feed_url = self.marketplace_feed.clone();
        let proof_gossip_inbox_outbound = self.proof_gossip_inbox.clone();
        let offer_take_inbox_outbound = self.offer_take_inbox.clone();
        let offer_broadcast_inbox_outbound = self.offer_broadcast_inbox.clone();
        let seen_offer_ids_outbound = self.seen_offer_ids.clone();
        let offer_rate_limit_outbound = self.offer_rate_limit.clone();
        let dispute_raised_inbox_outbound = self.dispute_raised_inbox.clone();
        let dispute_evidence_inbox_outbound = self.dispute_evidence_inbox.clone();
        let dispute_resolved_inbox_outbound = self.dispute_resolved_inbox.clone();
        let dispute_escalated_inbox_outbound = self.dispute_escalated_inbox.clone();
        let chain_for_sync = self.chain.clone();
        let mempool_for_sync = self.mempool.clone();
        let reputation = self.reputation.clone();
        let sync_requests = self.sync_requests.clone();
        let block_requests = self.block_requests.clone();
        let getblocks_seen = self.getblocks_seen.clone();
        let getblocks_last = self.getblocks_last.clone();
        let getblocks_genesis = self.getblocks_genesis.clone();
        let send_blocks_log = self.send_blocks_log.clone();
        let self_ips = self.self_ips.clone();
        let peers_vec = self.peers.clone();
        let connected_vec = self.connected.clone();
        let writer_for_drop = writer.clone();
        let peer_state = peer_state.clone();
        let local_node_id = hex::encode(&self.node_id);
        let local_node_id_bytes = self.node_id.clone();
        tokio::spawn(async move {
            let mut msg_count: u32 = 0;
            let mut window_start = Instant::now();
            let mut last_handshake_height: Option<u64> = None;
            let mut last_handshake_agent: Option<String> = None;
            let mut bulk_count: u32 = 0;
            loop {
                let msg = tokio::select! {
                    _ = &mut shutdown_rx_to_reader => {
                        break;
                    }
                    res = read_message_with_timeout(&mut reader, P2PNode::peer_timeout()) => res,
                };
                let msg = match msg {
                    Ok(msg) => msg,
                    Err(e) => {
                        Self::log_err(format!("P2P outbound {}: closing read loop: {}", addr, e));
                        let mut rep = reputation.lock().await;
                        // FIX #128: connection dropped mid-session is a
                        // network event, not malicious behavior.
                        rep.record_dial_failure(&trusted_anchor_peer_id(addr, trusted_seed));
                        break;
                    }
                };
                if window_start.elapsed() >= Duration::from_secs(1) {
                    window_start = Instant::now();
                    msg_count = 0;
                    bulk_count = 0;
                }
                let is_bulk = matches!(msg.msg_type, MessageType::Block | MessageType::Headers);
                if is_bulk {
                    bulk_count += 1;
                    if bulk_count > MAX_BULK_MSGS_PER_SEC {
                        Self::log_err(format!("P2P outbound {}: bulk rate limit", addr));
                        break;
                    }
                } else {
                    msg_count += 1;
                    if msg_count > MAX_MSGS_PER_SEC {
                        Self::log_err(format!("P2P outbound {}: rate limit", addr));
                        break;
                    }
                }
                if P2PNode::verbose_messages() {
                    match msg.msg_type {
                        MessageType::Ping
                        | MessageType::Pong
                        | MessageType::Handshake
                        | MessageType::Peers
                        | MessageType::GetPeers
                        | MessageType::GetHeaders
                        | MessageType::GetBlocks
                        | MessageType::Headers
                        | MessageType::Block
                        | MessageType::UptimeChallenge
                        | MessageType::UptimeProof
                        | MessageType::ProofGossip
                        | MessageType::OfferTakeNotification
                        | MessageType::OfferBroadcast
                        | MessageType::DisputeRaisedNotification
                        | MessageType::DisputeEvidenceNotification
                        | MessageType::DisputeResolvedNotification
                        | MessageType::DisputeEscalatedNotification => {}
                        _ => {
                            P2PNode::log_event(
                                "info",
                                "net",
                                format!("P2P {}: recv {:?}", addr, msg.msg_type),
                            );
                        }
                    }
                }
                match msg.msg_type {
                    MessageType::Ping => {
                        if let Ok(ping) = PingPayload::from_message(&msg) {
                            let mut payload = Vec::new();
                            payload.extend_from_slice(&ping.nonce.to_be_bytes());
                            let pong = Message {
                                msg_type: MessageType::Pong,
                                payload,
                            };
                            let _ = send_message(&writer, pong, addr).await;
                            let mut dir_guard = dir.lock().await;
                            let multiaddr = format!("/ip4/{}/tcp/{}", addr.ip(), addr.port());
                            dir_guard.mark_seen(&multiaddr);
                        }
                    }
                    MessageType::Handshake => {
                        if let Ok(payload) = HandshakePayload::from_message(&msg) {
                            if let Some(ref remote_id) = payload.node_id {
                                if remote_id == &local_node_id {
                                    {
                                        let mut guard = self_ips.lock().await;
                                        guard.insert(addr.ip());
                                    }
                                    P2PNode::log_event(
                                        "warn",
                                        "net",
                                        format!("P2P {}: self-connection detected, closing", addr),
                                    );
                                    break;
                                }
                            }
                            if let Err(reason) = verify_peer_checkpoint(&payload, &chain_for_sync) {
                                if let Some(rest) = reason.strip_prefix("LOCAL_FORK:") {
                                    P2PNode::log_event(
                                        "error",
                                        "sync",
                                        format!(
                                            "P2P {}: LOCAL node appears on a fork/split chain ({}). Attempting recovery...",
                                            addr,
                                            rest.trim()
                                        ),
                                    );
                                    // State-only recovery: clear sync throttles and request headers from genesis.
                                    sync_requests.lock().await.clear();
                                    block_requests.lock().await.clear();
                                    let get_headers = GetHeadersPayload {
                                        start_hash: vec![0u8; 32],
                                        count: MAX_HEADERS_PER_REQUEST,
                                    };
                                    if let Ok(msg) = get_headers.to_message() {
                                        send_message_detached(&writer, msg, addr);
                                    }
                                } else {
                                    P2PNode::log_event(
                                        "warn",
                                        "net",
                                        format!(
                                            "P2P {}: peer on fork/split or incompatible chain: {}",
                                            addr, reason
                                        ),
                                    );
                                    break;
                                }
                            }
                            let agent_str = payload.agent.clone();
                            let node_id = payload.node_id.clone();
                            let parsed_tip = payload
                                .tip_hash
                                .as_ref()
                                .and_then(|h| hex::decode(h).ok())
                                .and_then(|b| {
                                    if b.len() == 32 {
                                        let mut arr = [0u8; 32];
                                        arr.copy_from_slice(&b);
                                        Some(arr)
                                    } else {
                                        None
                                    }
                                });
                            let node_id_bytes = parse_node_id_bytes(&payload);
                            let supports_uptime = peer_supports_uptime(&payload);
                            {
                                let mut dir_guard = dir.lock().await;
                                // Prefer the peer's self-advertised external_endpoint when
                                // it parses as a globally routable IPv4:port; otherwise
                                // fall back to TCP source IP + the port we dialed.
                                let multiaddr = payload
                                    .external_endpoint
                                    .as_deref()
                                    .and_then(dialable_multiaddr_from_advertised)
                                    .unwrap_or_else(|| {
                                        format!("/ip4/{}/tcp/{}", addr.ip(), addr.port())
                                    });
                                dir_guard.register_connection(
                                    multiaddr.clone(),
                                    Some(agent_str.clone()),
                                    payload.relay_address.clone(),
                                    node_id.clone(),
                                );
                                dir_guard.mark_dialable(&multiaddr);
                            }
                            let should_log = last_handshake_height != Some(payload.height)
                                || last_handshake_agent.as_deref() != Some(agent_str.as_str());
                            if should_log {
                                Self::log(format!(
                                    "P2P outbound {}: received handshake (agent {}, height {})",
                                    addr, agent_str, payload.height
                                ));
                            }
                            last_handshake_height = Some(payload.height);
                            last_handshake_agent = Some(agent_str.clone());
                            if let Some(ref feed_url) = payload.marketplace_feed {
                                record_discovered_feed(feed_url);
                            }
                            {
                                let mut state = peer_state.lock().await;
                                state.tip = parsed_tip;
                                state.node_id = node_id_bytes.clone();
                                state.supports_uptime = supports_uptime;
                            }
                            // If we have a relay address, advertise it back.
                            if let Some(relay) = relay_addr.clone() {
                                let relay_msg = RelayAddressPayload {
                                    txid: String::new(),
                                    address: relay,
                                };
                                if let Ok(msg) = relay_msg.to_message() {
                                    send_message_detached(&writer, msg, addr);
                                }
                            }
                            // Ask for peers to grow the mesh.
                            if let Ok(msg) = EmptyPayload::to_message(MessageType::GetPeers) {
                                send_message_detached(&writer, msg, addr);
                                maybe_request_sync(
                                    &writer,
                                    addr,
                                    &chain_for_sync,
                                    &sync_requests,
                                    &block_requests,
                                    &peer_state,
                                )
                                .await;
                            }
                            // Proactive addr push: send up to 1000 dialable peers on connect.
                            {
                                let to_push: Vec<String> = {
                                    let d = dir.lock().await;
                                    d.peers().iter().filter(|p| p.dialable).take(MAX_ADDR_PUSH).map(|p| p.multiaddr.clone()).collect()
                                };
                                if !to_push.is_empty() {
                                    if let Ok(push_msg) = (PeersPayload { peers: to_push }).to_message() {
                                        send_message_detached(&writer, push_msg, addr);
                                    }
                                }
                            }
                            // Basic header-first sync trigger: if peer is ahead, request blocks.
                            let local_height = {
                                if let Some(ref c) = chain_for_sync {
                                    c.lock().unwrap_or_else(|e| e.into_inner()).tip_height()
                                } else {
                                    0
                                }
                            };
                            let peer_tip = payload
                                .tip_hash
                                .as_ref()
                                .and_then(|h| hex::decode(h).ok())
                                .and_then(|b| {
                                    if b.len() == 32 {
                                        let mut arr = [0u8; 32];
                                        arr.copy_from_slice(&b);
                                        Some(arr)
                                    } else {
                                        None
                                    }
                                });
                            let _peer_tip_on_main = if let (Some(tip), Some(chain_arc)) =
                                (peer_tip, chain_for_sync.as_ref())
                            {
                                let guard = chain_arc.lock().unwrap_or_else(|e| e.into_inner());
                                if let Some(h) = guard.heights.get(&tip) {
                                    guard
                                        .chain
                                        .get(*h as usize)
                                        .map(|b| b.header.hash_for_height(*h) == tip)
                                        .unwrap_or(false)
                                } else {
                                    false
                                }
                            } else {
                                true
                            };
                            let local_at_peer = if let Some(ref chain_arc) = chain_for_sync {
                                let guard = chain_arc.lock().unwrap_or_else(|e| e.into_inner());
                                guard
                                    .chain
                                    .get(payload.height as usize)
                                    .map(|b| b.header.hash_for_height(payload.height))
                            } else {
                                None
                            };
                            let tip_mismatch = if payload.height == local_height {
                                match peer_tip {
                                    Some(t) => local_at_peer.map(|h| h != t).unwrap_or(false),
                                    None => false,
                                }
                            } else {
                                false
                            };
                            let bad_recent = {
                                let state = peer_state.lock().await;
                                state
                                    .last_bad_headers
                                    .map(|ts| ts.elapsed() < Duration::from_secs(120))
                                    .unwrap_or(false)
                            };
                            if !bad_recent
                                && (payload.height > local_height
                                    || (payload.height == local_height && tip_mismatch))
                            {
                                let local_tip = P2PNode::tip_hash(&chain_for_sync);
                                let start_hash = if local_height == 0
                                    || (payload.height == local_height && tip_mismatch)
                                {
                                    [0u8; 32]
                                } else {
                                    local_tip
                                };
                                let get_headers = GetHeadersPayload {
                                    start_hash: start_hash.to_vec(),
                                    count: MAX_HEADERS_PER_REQUEST,
                                };
                                let short = if start_hash == [0u8; 32] {
                                    "genesis".to_string()
                                } else {
                                    let h = hex::encode(start_hash);
                                    h.get(0..12).unwrap_or(&h).to_string()
                                };

                                let mut allowed = sync_request_allowed_for(
                                    &sync_requests,
                                    addr.ip(),
                                    local_height,
                                    payload.height,
                                )
                                .await;
                                if allowed {
                                    let now = Instant::now();
                                    let (last_req, last_start) = {
                                        let mut guard = peer_state.lock().await;
                                        let stale_inflight = guard.headers_inflight
                                            && guard
                                                .last_headers_request
                                                .map(|ts| {
                                                    now.duration_since(ts)
                                                        > headers_response_window()
                                                })
                                                .unwrap_or(false);
                                        if stale_inflight {
                                            guard.headers_inflight = false;
                                            guard.headers_processing = false;
                                        }
                                        (guard.last_headers_request, guard.last_headers_start)
                                    };
                                    if let Some(ts) = last_req {
                                        if now.duration_since(ts)
                                            < headers_request_cooldown_for(
                                                local_height,
                                                payload.height,
                                            )
                                            && last_start == Some(start_hash)
                                        {
                                            allowed = false;
                                        }
                                    }
                                }

                                if allowed {
                                    Self::log(format!(
                                        "P2P {}: peer ahead ({} > {}), requesting headers from tip {}",
                                        addr, payload.height, local_height, short
                                    ));
                                    if let Ok(msg) = get_headers.to_message() {
                                        send_message_detached(&writer, msg, addr);
                                    }
                                    {
                                        let mut state = peer_state.lock().await;
                                        state.last_headers_request = Some(Instant::now());
                                        state.last_headers_start = Some(start_hash);
                                        state.headers_inflight = true;
                                    }
                                }
                            } else if payload.height < local_height {
                                // Peer is behind; push headers and fall back to block push if needed.
                                let behind_height = payload.height;
                                if let Some(ref chain_arc) = chain_for_sync {
                                    let headers_bytes = {
                                        let guard =
                                            chain_arc.lock().unwrap_or_else(|e| e.into_inner());
                                        let start = if tip_mismatch {
                                            0
                                        } else {
                                            payload.height.saturating_add(1) as usize
                                        };
                                        let mut headers = Vec::new();
                                        for (i, block) in guard.chain.iter().skip(start).take(32).enumerate() {
                                            let h = (start + i) as u64;
                                            headers.extend_from_slice(&block.header.serialize_for_height(h));
                                        }
                                        headers
                                    };
                                    if !headers_bytes.is_empty() {
                                        let msg = HeadersPayload {
                                            headers: headers_bytes,
                                        }
                                        .to_message();
                                        send_message_detached(&writer, msg, addr);
                                    }
                                }
                                if !tip_mismatch {
                                    let fallback_writer = Arc::downgrade(&writer);
                                    let fallback_chain = chain_for_sync.clone();
                                    let fallback_seen = getblocks_seen.clone();
                                    let fallback_addr = addr;
                                    tokio::spawn(async move {
                                        let grace = no_getblocks_fallback_cooldown();
                                        tokio::time::sleep(grace).await;
                                        let now = Instant::now();
                                        {
                                            let mut guard = fallback_seen.lock().await;
                                            if let Some(last) = guard.get(&fallback_addr.ip()) {
                                                if now.duration_since(*last) < grace {
                                                    return;
                                                }
                                            }
                                            guard.insert(fallback_addr.ip(), now);
                                        }
                                        let (blocks, start_height) = if let Some(ref chain_arc) =
                                            fallback_chain
                                        {
                                            let guard =
                                                chain_arc.lock().unwrap_or_else(|e| e.into_inner());
                                            let start_idx =
                                                behind_height.saturating_add(1) as usize;
                                            if start_idx >= guard.chain.len() {
                                                (Vec::new(), 0)
                                            } else {
                                                let mut blocks = Vec::new();
                                                for (i, b) in guard
                                                    .chain
                                                    .iter()
                                                    .skip(start_idx)
                                                    .take(fallback_blocks_per_burst())
                                                    .enumerate()
                                                {
                                                    let h = (start_idx + i) as u64;
                                                    blocks.push(b.serialize_for_height(h));
                                                }
                                                (blocks, start_idx as u64)
                                            }
                                        } else {
                                            (Vec::new(), 0)
                                        };
                                        if blocks.is_empty() {
                                            return;
                                        }
                                        let Some(fallback_writer) = fallback_writer.upgrade()
                                        else {
                                            return;
                                        };
                                        let end_h = start_height + blocks.len() as u64 - 1;
                                        P2PNode::log_event(
                                                "info",
                                                "sync",
                                                format!(
                                                    "P2P {}: no getblocks after headers, pushing {} blocks [{}-{}]",
                                                    fallback_addr,
                                                    blocks.len(),
                                                    start_height,
                                                    end_h
                                                ),
                                            );
                                        for block_data in blocks {
                                            let msg = BlockPayload { block_data }.to_message();
                                            let _ =
                                                send_message(&fallback_writer, msg, fallback_addr)
                                                    .await;
                                        }
                                    });
                                }
                            }
                        }
                    }
                    MessageType::Pong => {
                        let mut dir_guard = dir.lock().await;
                        let multiaddr = format!("/ip4/{}/tcp/{}", addr.ip(), addr.port());
                        dir_guard.mark_seen(&multiaddr);
                    }
                    MessageType::UptimeChallenge => {
                        if uptime_enabled() {
                            if let Ok(payload) = UptimeChallengePayload::from_message(&msg) {
                                if !uptime_timestamp_valid(payload.timestamp) {
                                    continue;
                                }
                                let peer_id = {
                                    let guard = peer_state.lock().await;
                                    guard.node_id.clone()
                                };
                                if let Some(peer_id) = peer_id {
                                    let key = uptime_key(&local_node_id_bytes, &peer_id);
                                    let hmac = compute_uptime_hmac(
                                        &key,
                                        &payload.nonce,
                                        payload.timestamp,
                                    );
                                    let proof = UptimeProofPayload {
                                        nonce: payload.nonce,
                                        timestamp: payload.timestamp,
                                        hmac,
                                    };
                                    let _ = send_message(&writer, proof.to_message(), addr).await;
                                }
                            }
                        }
                    }
                    MessageType::UptimeProof => {
                        if uptime_enabled() {
                            if let Ok(payload) = UptimeProofPayload::from_message(&msg) {
                                if !uptime_timestamp_valid(payload.timestamp) {
                                    continue;
                                }
                                let (challenge, peer_id) = {
                                    let guard = peer_state.lock().await;
                                    (guard.last_uptime_challenge.clone(), guard.node_id.clone())
                                };
                                if let (Some(challenge), Some(peer_id)) = (challenge, peer_id) {
                                    if challenge.nonce == payload.nonce
                                        && challenge.timestamp == payload.timestamp
                                    {
                                        let key = uptime_key(&local_node_id_bytes, &peer_id);
                                        let expected = compute_uptime_hmac(
                                            &key,
                                            &payload.nonce,
                                            payload.timestamp,
                                        );
                                        if expected == payload.hmac {
                                            let mut rep = reputation.lock().await;
                                            rep.record_uptime_proof(&trusted_anchor_peer_id(
                                                addr,
                                                trusted_seed,
                                            ));
                                            let mut guard = peer_state.lock().await;
                                            guard.last_uptime_challenge = None;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    MessageType::GetPeers => {
                        let peers_payload = {
                            let dir = dir.lock().await;
                            PeersPayload {
                                peers: dir
                                    .peers()
                                    .iter()
                                    .filter(|p| p.dialable)
                                    .take(MAX_PEERS_IN_RESPONSE)
                                    .map(|p| p.multiaddr.clone())
                                    .collect(),
                            }
                        };
                        if let Ok(resp) = peers_payload.to_message() {
                            send_message_detached(&writer, resp, addr);
                        }
                    }
                    MessageType::Peers => {
                        if let Ok(list) = PeersPayload::from_message(&msg) {
                            let source = format!("/ip4/{}/tcp/{}", addr.ip(), addr.port());
                            let filtered: Vec<String> = list.peers.into_iter()
                                .filter(|p| {
                                    if let Some(port_str) = p.split("/tcp/").nth(1) {
                                        port_str.trim().parse::<u16>().map(|port| port != 0).unwrap_or(true)
                                    } else if let Ok(sa) = p.parse::<std::net::SocketAddr>() {
                                        sa.port() != 0
                                    } else {
                                        true
                                    }
                                })
                                .collect();
                            let mut dir = dir.lock().await;
                            dir.register_peer_hints(filtered, Some(&source));
                        }
                    }
                    MessageType::GetHeaders => {
                        if let Some(ref chain_arc) = chain_for_sync {
                            if let Ok(payload) = GetHeadersPayload::from_message(&msg) {
                                let headers_bytes = {
                                    let guard = chain_arc.lock().unwrap_or_else(|e| e.into_inner());

                                    let mut start_idx = if guard.chain.len() > 1 { 1 } else { 0 };
                                    let mut start_hash_non_zero = false;
                                    let mut start_found = false;
                                    if payload.start_hash.len() == 32 {
                                        let mut target = [0u8; 32];
                                        target.copy_from_slice(&payload.start_hash);
                                        start_hash_non_zero = target.iter().any(|b| *b != 0);
                                        if start_hash_non_zero {
                                            if let Some((pos, _)) = guard
                                                .chain
                                                .iter()
                                                .enumerate()
                                                .find(|(idx, b)| b.header.hash_for_height(*idx as u64) == target)
                                            {
                                                start_idx = pos.saturating_add(1);
                                                start_found = true;
                                            }
                                        }
                                    }
                                    let count = payload.count.min(MAX_HEADERS_PER_REQUEST) as usize;
                                    let mut bytes = Vec::new();
                                    if !start_hash_non_zero || start_found {
                                        for (i, block) in guard.chain.iter().skip(start_idx).take(count).enumerate()
                                        {
                                            let h = (start_idx + i) as u64;
                                            bytes.extend_from_slice(&block.header.serialize_for_height(h));
                                        }
                                    }
                                    bytes
                                };

                                let msg = HeadersPayload {
                                    headers: headers_bytes,
                                }
                                .to_message();
                                send_message_detached(&writer, msg, addr);
                            }
                        }
                    }
                    MessageType::Headers => {
                        if let Some(ref chain_arc) = chain_for_sync {
                            if let Ok(payload) = HeadersPayload::from_message(&msg) {
                                {
                                    let mut state = peer_state.lock().await;
                                    let now = Instant::now();
                                    let inflight_recent = state
                                        .last_headers_request
                                        .map(|ts| {
                                            now.duration_since(ts) <= headers_response_window()
                                        })
                                        .unwrap_or(false);
                                    if !inflight_recent {
                                        state.unsolicited_headers =
                                            state.unsolicited_headers.saturating_add(1);
                                        let should_log = state
                                            .last_unsolicited_log
                                            .map(|t| {
                                                now.duration_since(t) > Duration::from_secs(30)
                                            })
                                            .unwrap_or(true);
                                        if should_log {
                                            state.last_unsolicited_log = Some(now);
                                            if should_emit_unsolicited_headers_log() {
                                                P2PNode::log_event(
                                                    "warn",
                                                    "sync",
                                                    format!(
                                                        "P2P {}: unsolicited headers ignored",
                                                        addr
                                                    ),
                                                );
                                            }
                                        }
                                        continue;
                                    }
                                    if state.headers_processing {
                                        // Prevent concurrent header batch processing for the same peer.
                                        state.unsolicited_headers =
                                            state.unsolicited_headers.saturating_add(1);
                                        continue;
                                    }
                                    state.headers_processing = true;
                                    state.headers_inflight = false;
                                }
                                let header_count = (payload.headers.len() / 80) as u32;
                                let header_bytes = payload.headers.clone();
                                let chain_arc2 = chain_arc.clone();
                                let peer_height_hint = last_handshake_height;

                                let (last_header_hash, header_error, unknown_parent, reset_headers, added_any, reject_reason, first_unknown_prev) =
                                    match spawn_blocking_limited(move || {
                                        let mut offset = 0usize;
                                        let mut last_header_hash: Option<[u8; 32]> = None;
                                        let mut header_error = false;
                                        let mut unknown_parent = false;
                                        let mut reset_headers = false;
                                        let mut added_any = false;
                                        let mut reject_reason: Option<String> = None;
                                        let mut first_unknown_prev: Option<[u8; 32]> = None;

                                        let mut guard = chain_arc2.lock().unwrap_or_else(|e| e.into_inner());

                                        while offset + 80 <= header_bytes.len() {
                                            let slice = &header_bytes[offset..offset + 80];
                                            // Peek prev_hash → look up parent → derive height
                                            // before height-aware deserialize.
                                            let prev_peek = match crate::block::BlockHeader::peek_prev_hash(slice) {
                                                Ok(p) => p,
                                                Err(_) => {
                                                    header_error = true;
                                                    reject_reason = Some("decode_error".to_string());
                                                    break;
                                                }
                                            };
                                            let header_height = if prev_peek == [0u8; 32] {
                                                0
                                            } else if let Some(h) = guard
                                                .heights
                                                .get(&prev_peek)
                                                .copied()
                                                .or_else(|| guard.headers.get(&prev_peek).map(|hw| hw.height))
                                            {
                                                h + 1
                                            } else {
                                                0
                                            };
                                            let (header, used) = match crate::block::BlockHeader::deserialize_for_height(slice, header_height) {
                                                Ok(v) => v,
                                                Err(_) => {
                                                    header_error = true;
                                                    reject_reason = Some("decode_error".to_string());
                                                    break;
                                                }
                                            };
                                            offset += used;
                                            last_header_hash = Some(header.hash_for_height(header_height));

                                            let header_hash = header.hash_for_height(header_height);
                                            if header.prev_hash == [0u8; 32] {
                                                let genesis_hash = guard.params.genesis_block.header.hash_for_height(0);
                                                if header_hash == genesis_hash {
                                                    continue;
                                                }
                                            }
                                        let already_known = guard.headers.contains_key(&header_hash)
                                            || guard.block_store.contains_key(&header_hash);
                                        if let Err(e) = guard.add_header(header.clone()) {
                                            if e.contains("unknown parent") {
                                                unknown_parent = true;
                                                if first_unknown_prev.is_none() {
                                                    first_unknown_prev = Some(header.prev_hash);
                                                }
                                                reject_reason.get_or_insert_with(|| classify_header_reject_reason(&e));
                                                let (orphan_n, inserted) = store_orphan_header(header.clone());
                                                if inserted {
                                                    P2PNode::log_event(
                                                        "info",
                                                        "sync",
                                                        format!(
                                                            "stored orphan header: hash={} prev={} orphan_headers={}",
                                                            short_hash(header_hash),
                                                            short_hash(header.prev_hash),
                                                            orphan_n
                                                        ),
                                                    );
                                                }
                                                if let Some(peer_height) = peer_height_hint {
                                                    let local_height = guard.tip_height();
                                                    if peer_height > local_height {
                                                        reset_headers = true;
                                                    }
                                                }
                                                continue;
                                            }
                                            header_error = true;
                                            reject_reason = Some(classify_header_reject_reason(&e));
                                            break;
                                        }
                                        if !already_known {
                                            added_any = true;
                                        }
                                        let (attached, attach_err) = attach_orphan_header_chain(&mut guard, header_hash);
                                        if attached > 0 {
                                            P2PNode::log_event(
                                                "info",
                                                "sync",
                                                format!(
                                                    "attached orphan header chain: attached={} orphan_headers={}",
                                                    attached,
                                                    orphan_headers_count()
                                                ),
                                            );
                                        }
                                        if let Some(reason) = attach_err {
                                            reject_reason.get_or_insert(reason);
                                        }
                                        }

                                        (last_header_hash, header_error, unknown_parent, reset_headers, added_any, reject_reason, first_unknown_prev)
                                    })
                                    .await
                                    {
                                        Ok(v) => v,
                                        Err(_) => (None, true, false, false, false, Some("task_join_error".to_string()), None),
                                    };

                                if header_count > 0 {
                                    peer_mark_header_event(addr.ip(), added_any, header_count)
                                        .await;
                                    let should_log = {
                                        let mut st = peer_state.lock().await;
                                        let now = Instant::now();
                                        let at_tip = {
                                            let g =
                                                chain_arc.lock().unwrap_or_else(|e| e.into_inner());
                                            let local_h = g.tip_height();
                                            let best_hash = g.best_header_hash();
                                            let best_h = g
                                                .headers
                                                .get(&best_hash)
                                                .map(|hw| hw.height)
                                                .or_else(|| g.heights.get(&best_hash).copied())
                                                .unwrap_or(local_h);
                                            best_h <= local_h
                                        };
                                        let noisy = (!added_any && header_count >= 16)
                                            || (at_tip && header_count >= 32)
                                            || header_count >= 2000;
                                        let allow = if noisy {
                                            st.last_headers_batch_log
                                                .map(|t| {
                                                    now.duration_since(t)
                                                        > Duration::from_secs(
                                                            headers_batch_log_cooldown_secs(),
                                                        )
                                                })
                                                .unwrap_or(true)
                                        } else {
                                            true
                                        };
                                        if allow {
                                            st.last_headers_batch_log = Some(now);
                                        }
                                        allow
                                    };
                                    if should_log {
                                        let last_short = last_header_hash
                                            .map(|h| {
                                                let hex = hex::encode(h);
                                                hex.get(0..12).unwrap_or(&hex).to_string()
                                            })
                                            .unwrap_or_else(|| "-".to_string());
                                        let msg = format!(
                                            "P2P {}: received {} headers (new={}) last={}",
                                            addr, header_count, added_any, last_short
                                        );
                                        if header_count < 2000 {
                                            P2PNode::log_event("info", "sync", msg);
                                        }
                                    }
                                }

                                if header_error {
                                    let reason = reject_reason
                                        .clone()
                                        .unwrap_or_else(|| "unknown".to_string());
                                    let streak = note_header_reject(addr.ip(), &reason).await;
                                    penalize_rejecting_header_peer(addr.ip(), streak).await;
                                    if streak >= 8 {
                                        P2PNode::log_event(
                                            "warn",
                                            "sync",
                                            format!("P2P {}: repeated rejected headers (reason={}, streak={}); lowering peer score", addr, reason, streak),
                                        );
                                    }
                                    if let Some(prev_hash) = first_unknown_prev {
                                        request_orphan_headers(
                                            &writer,
                                            addr,
                                            prev_hash,
                                            &chain_for_sync,
                                            &sync_requests,
                                            &peer_state,
                                        )
                                        .await;
                                    }

                                    if unknown_parent && !added_any {
                                        P2PNode::log_event(
                                                    "warn",
                                                    "sync",
                                                    format!("P2P {}: headers do not connect; ignoring peer height", addr),
                                                );
                                        let multiaddr =
                                            format!("/ip4/{}/tcp/{}", addr.ip(), addr.port());
                                        {
                                            let mut directory = dir.lock().await;
                                            directory.clear_height(&multiaddr);
                                        }
                                        let mut state = peer_state.lock().await;
                                        state.height = None;
                                        state.tip = None;
                                        state.last_bad_headers = Some(Instant::now());
                                    }
                                    if reset_headers {
                                        let get_headers = GetHeadersPayload {
                                            start_hash: vec![0u8; 32],
                                            count: MAX_HEADERS_PER_REQUEST,
                                        };
                                        if let Ok(msg) = get_headers.to_message() {
                                            send_message_detached(&writer, msg, addr);
                                        }
                                        {
                                            let mut state = peer_state.lock().await;
                                            state.last_headers_request = Some(Instant::now());
                                            state.last_headers_start = Some([0u8; 32]);
                                            state.headers_inflight = true;
                                        }
                                    }
                                    {
                                        let mut state = peer_state.lock().await;
                                        state.last_headers_received = Some(Instant::now());
                                        state.headers_processing = false;
                                    }
                                    continue;
                                }
                                let (local_height, best_header_height) = {
                                    let guard = chain_arc.lock().unwrap_or_else(|e| e.into_inner());
                                    let local_h = guard.tip_height();
                                    let best_hash = guard.best_header_hash();
                                    let best_h = guard
                                        .headers
                                        .get(&best_hash)
                                        .map(|hw| hw.height)
                                        .or_else(|| guard.heights.get(&best_hash).copied())
                                        .unwrap_or(local_h);
                                    (local_h, best_h)
                                };
                                let peer_height = {
                                    let state = peer_state.lock().await;
                                    let advertised = state
                                        .height
                                        .unwrap_or(last_handshake_height.unwrap_or(local_height))
                                        .max(last_handshake_height.unwrap_or(local_height));
                                    trusted_remote_height(
                                        advertised,
                                        best_header_height,
                                        local_height,
                                    )
                                };
                                if header_count >= 2000 && best_header_height <= local_height {
                                    peer_mark_header_event(addr.ip(), false, 1).await;
                                }
                                {
                                    let mut state = peer_state.lock().await;
                                    state.height = Some(peer_height);
                                    state.last_bad_headers = None;
                                }
                                clear_header_reject_streak(addr.ip()).await;
                                let multiaddr = format!("/ip4/{}/tcp/{}", addr.ip(), addr.port());
                                let mut directory = dir.lock().await;
                                directory.record_height(&multiaddr, peer_height);
                                if header_count == 0 && peer_height > local_height {
                                    if sync_request_allowed_for(
                                        &sync_requests,
                                        addr.ip(),
                                        local_height,
                                        peer_height,
                                    )
                                    .await
                                    {
                                        let get_headers = GetHeadersPayload {
                                            start_hash: vec![0u8; 32],
                                            count: MAX_HEADERS_PER_REQUEST,
                                        };
                                        if let Ok(msg) = get_headers.to_message() {
                                            send_message_detached(&writer, msg, addr);
                                        }
                                        let mut state = peer_state.lock().await;
                                        state.last_headers_request = Some(Instant::now());
                                        state.last_headers_start = Some([0u8; 32]);
                                        state.headers_inflight = true;
                                    }
                                    {
                                        let mut state = peer_state.lock().await;
                                        state.headers_processing = false;
                                    }
                                    continue;
                                }
                                if header_count > 0 && added_any && peer_height > local_height {
                                    if let Some(last_hash) = last_header_hash {
                                        let get_headers = GetHeadersPayload {
                                            start_hash: last_hash.to_vec(),
                                            count: MAX_HEADERS_PER_REQUEST,
                                        };
                                        if let Ok(msg) = get_headers.to_message() {
                                            send_message_detached(&writer, msg, addr);
                                        }
                                        {
                                            let mut state = peer_state.lock().await;
                                            state.last_headers_request = Some(Instant::now());
                                            state.last_headers_start = Some(last_hash);
                                            state.headers_inflight = true;
                                        }
                                    }
                                }

                                let request = {
                                    let guard = chain_arc.lock().unwrap_or_else(|e| e.into_inner());
                                    if let Some(best) = guard.best_header_if_better() {
                                        if let Some(path) =
                                            guard.header_path_to_known(best.header.hash_for_height(best.height))
                                        {
                                            if let Some(first_hash) = path.first() {
                                                let mut start_hash = guard
                                                    .headers
                                                    .get(first_hash)
                                                    .map(|hw| hw.header.prev_hash)
                                                    .unwrap_or([0u8; 32]);
                                                if start_hash != [0u8; 32]
                                                    && !guard.heights.contains_key(&start_hash)
                                                {
                                                    start_hash = rewinded_getblocks_request(
                                                        &guard,
                                                        peer_height,
                                                    )
                                                    .map(|(hash, _)| hash)
                                                    .unwrap_or_else(|| {
                                                        let tip_h = guard.tip_height();
                                                        guard
                                                            .chain
                                                            .last()
                                                            .map(|b| b.header.hash_for_height(tip_h))
                                                            .unwrap_or([0u8; 32])
                                                    });
                                                }
                                                let count = std::cmp::min(
                                                    path.len(),
                                                    MAX_BLOCKS_PER_REQUEST as usize,
                                                )
                                                    as u32;
                                                if count > 0 {
                                                    Some((start_hash, count))
                                                } else {
                                                    None
                                                }
                                            } else {
                                                None
                                            }
                                        } else {
                                            rewinded_getblocks_request(&guard, peer_height)
                                                .or_else(|| {
                                                    let tip_h = guard.tip_height();
                                                    let start_hash = guard
                                                        .chain
                                                        .last()
                                                        .map(|b| b.header.hash_for_height(tip_h))
                                                        .unwrap_or([0u8; 32]);
                                                    let count = std::cmp::min(
                                                        best.height.saturating_sub(tip_h) as usize,
                                                        MAX_BLOCKS_PER_REQUEST as usize,
                                                    ) as u32;
                                                    if count > 0 {
                                                        Some((start_hash, count))
                                                    } else {
                                                        None
                                                    }
                                                })
                                        }
                                    } else if peer_height > guard.tip_height() {
                                        rewinded_getblocks_request(&guard, peer_height)
                                    } else {
                                        None
                                    }
                                };
                                if let Some((start_hash, count)) = request {
                                    let short = if start_hash == [0u8; 32] {
                                        "genesis".to_string()
                                    } else {
                                        let h = hex::encode(start_hash);
                                        h.get(0..12).unwrap_or(&h).to_string()
                                    };
                                    let (range_start, range_end, header_tip_short) = {
                                        let guard =
                                            chain_arc.lock().unwrap_or_else(|e| e.into_inner());
                                        let start_h = if start_hash == [0u8; 32] {
                                            0
                                        } else {
                                            guard
                                                .heights
                                                .get(&start_hash)
                                                .copied()
                                                .unwrap_or(0)
                                                .saturating_add(1)
                                        };
                                        let end_h =
                                            start_h.saturating_add(count as u64).saturating_sub(1);
                                        let tip_hex = hex::encode(guard.best_header_hash());
                                        let tip_short =
                                            tip_hex.get(0..12).unwrap_or(&tip_hex).to_string();
                                        (start_h, end_h, tip_short)
                                    };
                                    P2PNode::log_event(
                                        "info",
                                        "sync",
                                        format!(
                                            "P2P {}: requesting {} blocks from {} (range=[{}-{}], header_tip={})",
                                            addr, count, short, range_start, range_end, header_tip_short
                                        ),
                                    );

                                    let get_blocks = GetBlocksPayload {
                                        start_hash: start_hash.to_vec(),
                                        count,
                                    };
                                    if sync_block_request_allowed_for(
                                        &block_requests,
                                        addr.ip(),
                                        local_height,
                                        peer_height,
                                        &start_hash,
                                        count,
                                    )
                                    .await
                                    {
                                        if let Ok(msg) = get_blocks.to_message() {
                                            send_message_detached(&writer, msg, addr);
                                            record_block_request_sent(
                                                addr.ip(),
                                                &start_hash,
                                                count,
                                            )
                                            .await;
                                        }
                                    }
                                } else if peer_height > local_height || header_count > 0 {
                                    maybe_log_header_sync_state(
                                        addr,
                                        chain_arc,
                                        &peer_state,
                                        "no_best_header_block_path",
                                    )
                                    .await;
                                }
                                maybe_log_header_sync_state(addr, chain_arc, &peer_state, "").await;
                                {
                                    let mut state = peer_state.lock().await;
                                    state.last_headers_received = Some(Instant::now());
                                    state.headers_processing = false;
                                }
                            }
                        }
                    }
                    MessageType::GetBlocks => {
                        if let Ok(payload) = GetBlocksPayload::from_message(&msg) {
                            let writer_weak = Arc::downgrade(&writer);
                            let chain_for_task = chain_for_sync.clone();
                            let addr2 = addr;
                            let getblocks_seen2 = getblocks_seen.clone();
                            let getblocks_last2 = getblocks_last.clone();
                            let getblocks_genesis2 = getblocks_genesis.clone();
                            let send_blocks_log2 = send_blocks_log.clone();

                            tokio::spawn(async move {
                                {
                                    let mut guard = getblocks_seen2.lock().await;
                                    guard.insert(addr2.ip(), Instant::now());
                                }

                                let Some(chain_arc) = chain_for_task else {
                                    return;
                                };

                                if !getblocks_request_allowed(
                                    &getblocks_last2,
                                    addr2.ip(),
                                    &payload.start_hash,
                                    payload.count,
                                )
                                .await
                                {
                                    return;
                                }

                                let is_zero = payload.start_hash.iter().all(|b| *b == 0);
                                let start_hash = payload.start_hash.clone();
                                let want = payload.count;

                                let (matched_pos, blocks, start_height) =
                                    match spawn_blocking_limited(move || {
                                        let guard =
                                            chain_arc.lock().unwrap_or_else(|e| e.into_inner());

                                        let mut start_idx = 0usize;
                                        let mut matched_pos = None;
                                        if start_hash.len() == 32 {
                                            let mut target = [0u8; 32];
                                            target.copy_from_slice(&start_hash);
                                            if let Some((pos, _)) = guard
                                                .chain
                                                .iter()
                                                .enumerate()
                                                .find(|(idx, b)| b.header.hash_for_height(*idx as u64) == target)
                                            {
                                                start_idx = pos + 1;
                                                matched_pos = Some(pos);
                                            }
                                        }

                                        if matched_pos.is_none() && !is_zero {
                                            return (matched_pos, Vec::new(), 0u64);
                                        }

                                        let mut blocks = Vec::new();
                                        let mut heights = Vec::new();
                                        let count = want.min(MAX_BLOCKS_PER_REQUEST) as usize;
                                        for (idx, b) in guard
                                            .chain
                                            .iter()
                                            .enumerate()
                                            .skip(start_idx)
                                            .take(count)
                                        {
                                            blocks.push(b.serialize_for_height(idx as u64));
                                            heights.push(idx as u64);
                                        }
                                        let start_h: u64 = heights.first().copied().unwrap_or(0);
                                        (matched_pos, blocks, start_h)
                                    })
                                    .await
                                    {
                                        Ok(v) => v,
                                        Err(_) => return,
                                    };

                                let genesis_locator = is_zero || matches!(matched_pos, Some(0));
                                if genesis_locator
                                    && !genesis_request_allowed(&getblocks_genesis2, addr2.ip())
                                        .await
                                {
                                    return;
                                }

                                if matched_pos.is_none() && !is_zero {
                                    P2PNode::log_event(
                                        "warn",
                                        "sync",
                                        format!(
                                            "P2P {}: ignoring getblocks unknown start hash {}",
                                            addr2,
                                            hex::encode(&payload.start_hash)
                                        ),
                                    );
                                    return;
                                }

                                if !blocks.is_empty() {
                                    let end_h = start_height + blocks.len() as u64 - 1;
                                    if ip_log_allowed(
                                        &send_blocks_log2,
                                        addr2.ip(),
                                        Duration::from_secs(send_blocks_log_cooldown_secs()),
                                    )
                                    .await
                                    {
                                        P2PNode::log(format!(
                                            "P2P {}: sending {} blocks [{}-{}]",
                                            addr2,
                                            blocks.len(),
                                            start_height,
                                            end_h
                                        ));
                                    }
                                }

                                for block_data in blocks {
                                    let Some(writer) = writer_weak.upgrade() else {
                                        break;
                                    };
                                    let msg = BlockPayload { block_data }.to_message();
                                    let _ = send_message(&writer, msg, addr2).await;
                                }
                            });
                        }
                    }

                    MessageType::Block => {
                        if let Some(ref chain_arc) = chain_for_sync {
                            if let Ok(payload) = BlockPayload::from_message(&msg) {
                                let peer_block_lock = peer_block_lock(addr.ip()).await;
                                let _peer_block_guard = peer_block_lock.lock_owned().await;
                                let decode_started = Instant::now();
                                // Peek prev_hash → look up parent → derive
                                // block_height before height-aware deserialize.
                                let prev_peek = match crate::block::BlockHeader::peek_prev_hash(&payload.block_data) {
                                    Ok(p) => p,
                                    Err(_) => {
                                        P2PNode::log_event(
                                            "warn",
                                            "chain",
                                            format!("P2P {}: block payload too short to peek prev_hash", addr),
                                        );
                                        continue;
                                    }
                                };
                                let block_height = {
                                    let guard = chain_arc.lock().unwrap_or_else(|e| e.into_inner());
                                    if prev_peek == [0u8; 32] {
                                        0
                                    } else if let Some(h) = guard
                                        .heights
                                        .get(&prev_peek)
                                        .copied()
                                        .or_else(|| guard.headers.get(&prev_peek).map(|hw| hw.height))
                                    {
                                        h + 1
                                    } else {
                                        0
                                    }
                                };
                                match Block::deserialize_for_height(&payload.block_data, block_height) {
                                    Ok((block, _)) => {
                                        let decode_ms = decode_started.elapsed().as_millis();
                                        let precheck_started = Instant::now();
                                        if let Err(e) = stateless_block_precheck(&block, block_height) {
                                            P2PNode::log_event(
                                                "warn",
                                                "chain",
                                                format!(
                                                    "P2P {}: stateless precheck failed: {}",
                                                    addr, e
                                                ),
                                            );
                                            continue;
                                        }
                                        let precheck_ms = precheck_started.elapsed().as_millis();
                                        let bhash = block.header.hash_for_height(block_height);
                                        let short = hex::encode(bhash);
                                        let short = short.get(0..12).unwrap_or(&short);
                                        let chain_arc2 = chain_arc.clone();
                                        let mempool2 = mempool_for_sync.clone();
                                        let addr2 = addr;
                                        let short2 = short.to_string();
                                        let bhash2 = bhash;
                                        let block2 = block.clone();
                                        let prev_hash = block.header.prev_hash;
                                        let (prev_in_headers, prev_in_blocks) = {
                                            let guard =
                                                chain_arc.lock().unwrap_or_else(|e| e.into_inner());
                                            (
                                                guard.headers.contains_key(&prev_hash),
                                                guard.heights.contains_key(&prev_hash),
                                            )
                                        };
                                        let prev_hex = hex::encode(prev_hash);
                                        let prev_short = prev_hex.get(0..12).unwrap_or(&prev_hex);
                                        P2PNode::log_event(
                                            "info",
                                            "sync",
                                            format!(
                                                "P2P {}: inbound block {} prev={} prev_in_headers={} prev_in_blocks={}",
                                                addr,
                                                short,
                                                prev_short,
                                                prev_in_headers,
                                                prev_in_blocks
                                            ),
                                        );

                                        let connect_started = Instant::now();
                                        let (
                                            new_height_opt,
                                            record_verdict,
                                            persist_blocks,
                                            orphan_prev,
                                        ) = match spawn_blocking_limited(move || {
                                            let mut guard = chain_arc2
                                                .lock()
                                                .unwrap_or_else(|e| e.into_inner());
                                            let mut new_height_opt = None;
                                            let mut record_verdict = None;
                                            let mut persist_blocks: Vec<(u64, Block)> = Vec::new();
                                            let mut orphan_prev = None;
                                            match guard.process_block(block2.clone()) {
                                                Ok((new_height, _tip)) => {
                                                    P2PNode::log(format!(
                                                        "P2P {}: accepted block height {} hash {}",
                                                        addr2,
                                                        new_height.saturating_sub(1),
                                                        short2
                                                    ));
                                                    if let Some(ref mem) = mempool2 {
                                                        let mut mem_guard = mem
                                                            .lock()
                                                            .unwrap_or_else(|e| e.into_inner());
                                                        for tx in block2.transactions.iter().skip(1)
                                                        {
                                                            mem_guard.remove(&tx.txid());
                                                        }
                                                        evict_invalid_mempool_entries(
                                                            &guard,
                                                            &mut mem_guard,
                                                        );
                                                    }
                                                    new_height_opt = Some(new_height);
                                                    record_verdict = Some(true);
                                                    if guard.tip_hash() == bhash2 {
                                                        let tip = guard.tip_height();
                                                        persist_blocks.push((tip, block2.clone()));
                                                        if tip > 0 {
                                                            if let Some(prev) =
                                                                guard.chain.get((tip - 1) as usize)
                                                            {
                                                                persist_blocks
                                                                    .push((tip - 1, prev.clone()));
                                                            }
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    if e.contains("orphan")
                                                        || e.contains("prev hash unknown")
                                                    {
                                                        orphan_prev = Some(block2.header.prev_hash);
                                                    }
                                                    if P2PNode::is_soft_block_reject(&e) {
                                                        if !P2PNode::is_duplicate_block(&e) {
                                                            P2PNode::log_event(
                                                                "info",
                                                                "chain",
                                                                format!(
                                                                    "P2P {}: ignored block {} ({})",
                                                                    addr2, short2, e
                                                                ),
                                                            );
                                                        }
                                                    } else {
                                                        P2PNode::log_event(
                                                            "warn",
                                                            "chain",
                                                            format!(
                                                                "P2P {}: rejected block {}: {}",
                                                                addr2, short2, e
                                                            ),
                                                        );
                                                        record_verdict = Some(false);
                                                    }
                                                }
                                            }
                                            (
                                                new_height_opt,
                                                record_verdict,
                                                persist_blocks,
                                                orphan_prev,
                                            )
                                        })
                                        .await
                                        {
                                            Ok(v) => v,
                                            Err(_) => (None, None, Vec::new(), None),
                                        };
                                        let connect_ms = connect_started.elapsed().as_millis();
                                        for (height, b) in persist_blocks {
                                            let h = b.header.hash_for_height(height);
                                            enqueue_persist_block(height, h, b).await;
                                        }
                                        sync_perf_record(decode_ms, precheck_ms, connect_ms, 0);
                                        record_block_processing_ms(connect_ms as u64);
                                        if let Some(prev_hash) = orphan_prev {
                                            request_orphan_headers(
                                                &writer,
                                                addr,
                                                prev_hash,
                                                &chain_for_sync,
                                                &sync_requests,
                                                &peer_state,
                                            )
                                            .await;
                                        }
                                        if let Some(new_height) = new_height_opt {
                                            peer_mark_block_progress(addr.ip()).await;
                                            let multiaddr =
                                                format!("/ip4/{}/tcp/{}", addr.ip(), addr.port());
                                            let mut directory = dir.lock().await;
                                            directory.record_height(
                                                &multiaddr,
                                                new_height.saturating_sub(1),
                                            );
                                        }
                                        maybe_request_sync(
                                            &writer,
                                            addr,
                                            &chain_for_sync,
                                            &sync_requests,
                                            &block_requests,
                                            &peer_state,
                                        )
                                        .await;
                                        if let Some(ok) = record_verdict {
                                            let mut rep = reputation.lock().await;
                                            rep.record_block(
                                                &trusted_anchor_peer_id(addr, trusted_seed),
                                                ok,
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "Failed to decode block payload from {}: {}",
                                            addr, e
                                        );
                                        let mut rep = reputation.lock().await;
                                        rep.record_decode_error(&trusted_anchor_peer_id(
                                            addr,
                                            trusted_seed,
                                        ));
                                    }
                                }
                            }
                        }
                    }
                    MessageType::Tx => {
                        if let Ok(payload) = TxPayload::from_message(&msg) {
                            match decode_full_tx(&payload.tx_data) {
                                Ok(tx) => {
                                    if let (Some(ref chain_arc), Some(ref mem)) =
                                        (&chain_for_sync, &mempool_for_sync)
                                    {
                                        let inv_bytes = {
                                            let (fee, priority) = {
                                                let guard = chain_arc
                                                    .lock()
                                                    .unwrap_or_else(|e| e.into_inner());
                                                let fee = match guard.calculate_fees(&tx) {
                                                    Ok(f) => f,
                                                    Err(e) => {
                                                        eprintln!(
                                                            "Rejecting tx from {}: {}",
                                                            addr, e
                                                        );
                                                        continue;
                                                    }
                                                };
                                                let priority =
                                                    classify_tx_priority(&tx, &guard);
                                                (fee, priority)
                                            };
                                            let relay_addr = {
                                                let dir = dir.lock().await;
                                                dir.relay_address_for_peer(&addr)
                                            };
                                            let mut mem_guard =
                                                mem.lock().unwrap_or_else(|e| e.into_inner());
                                            let peer_addr = addr.to_string();
                                            let txid = tx.txid();
                                            let txid_hex = hex::encode(txid);
                                            match mem_guard.add_transaction_with_priority(
                                                tx.clone(),
                                                payload.tx_data.clone(),
                                                fee,
                                                priority,
                                                Some(addr.ip()),
                                            ) {
                                                Ok(outcome) => {
                                                    P2PNode::log_event(
                                                        "info",
                                                        "mempool",
                                                        format!(
                                                            "P2P {}: accepted tx {} fee {}",
                                                            addr, txid_hex, fee
                                                        ),
                                                    );
                                                    if let Some(evicted) = outcome.evicted {
                                                        let evicted_hex = hex::encode(evicted);
                                                        P2PNode::log_event(
                                                            "info",
                                                            "mempool",
                                                            format!(
                                                                "P2P {}: evicted tx {}",
                                                                addr, evicted_hex
                                                            ),
                                                        );
                                                    }
                                                    mem_guard.record_relay(
                                                        &outcome.txid,
                                                        peer_addr.clone(),
                                                    );
                                                }
                                                Err(e) => {
                                                    P2PNode::log_event(
                                                        "warn",
                                                        "mempool",
                                                        format!(
                                                            "P2P {}: rejected tx {}: {}",
                                                            addr, txid_hex, e
                                                        ),
                                                    );
                                                    mem_guard.record_relay(&txid, peer_addr);
                                                }
                                            }
                                            if let Some(relay_addr) = relay_addr {
                                                mem_guard.record_relay_address(&txid, relay_addr);
                                            }
                                            InvPayload {
                                                txids: vec![hex::encode(tx.txid())],
                                            }
                                            .to_message()
                                            .ok()
                                            .map(|m| m.serialize())
                                        };

                                        if let Some(inv_bytes) = inv_bytes {
                                            // Never hold the peers lock while awaiting I/O.
                                            let peers_snapshot = {
                                                let guard = peers_vec.lock().await;
                                                guard.clone()
                                            };
                                            let mut dead: Vec<Arc<Mutex<OwnedWriteHalf>>> =
                                                Vec::new();
                                            for socket in peers_snapshot.iter() {
                                                let write_fut = async {
                                                    let mut w = socket.lock().await;
                                                    w.write_all(&inv_bytes).await
                                                };
                                                match tokio::time::timeout(
                                                    Duration::from_secs(2),
                                                    write_fut,
                                                )
                                                .await
                                                {
                                                    Ok(Ok(())) => {}
                                                    Ok(Err(_)) | Err(_) => {
                                                        // Drop noisy/stuck peers from the broadcast set.
                                                        {
                                                            let mut w = socket.lock().await;
                                                            let _ = w.shutdown().await;
                                                        }
                                                        dead.push(socket.clone());
                                                    }
                                                }
                                            }
                                            if !dead.is_empty() {
                                                let mut guard = peers_vec.lock().await;
                                                guard.retain(|p| {
                                                    !dead.iter().any(|d| Arc::ptr_eq(p, d))
                                                });
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    eprintln!("Failed to decode tx from {}: {}", addr, e);
                                }
                            }
                        }
                    }
                    MessageType::Inv => {
                        if let Some(ref mem) = mempool_for_sync {
                            if let Ok(inv) = InvPayload::from_message(&msg) {
                                let mut needed = Vec::new();
                                {
                                    let guard = mem.lock().unwrap_or_else(|e| e.into_inner());
                                    for txid_hex in inv.txids {
                                        if let Ok(bytes) = hex::decode(&txid_hex) {
                                            if bytes.len() == 32 {
                                                let mut txid = [0u8; 32];
                                                txid.copy_from_slice(&bytes);
                                                if !guard.contains(&txid) {
                                                    needed.push(txid_hex.clone());
                                                }
                                            }
                                        }
                                    }
                                }
                                if !needed.is_empty() {
                                    let gd = GetDataPayload { txids: needed };
                                    if let Ok(msg) = gd.to_message() {
                                        send_message_detached(&writer, msg, addr);
                                    }
                                }
                            }
                        }
                    }
                    MessageType::GetData => {
                        if let Some(ref mem) = mempool_for_sync {
                            if let Ok(gd) = GetDataPayload::from_message(&msg) {
                                let mut responses: Vec<Message> = Vec::new();
                                {
                                    let guard = mem.lock().unwrap_or_else(|e| e.into_inner());
                                    for txid_hex in gd.txids {
                                        if let Ok(bytes) = hex::decode(&txid_hex) {
                                            if bytes.len() != 32 {
                                                continue;
                                            }
                                            let mut txid = [0u8; 32];
                                            txid.copy_from_slice(&bytes);
                                            if let Some(raw) = guard.raw_tx(&txid) {
                                                responses
                                                    .push(TxPayload { tx_data: raw }.to_message());
                                            }
                                        }
                                    }
                                }
                                for msg in responses {
                                    send_message_detached(&writer, msg, addr);
                                }
                            }
                        }
                    }
                    MessageType::Mempool => {
                        if let Some(ref mem) = mempool_for_sync {
                            let tx_hashes: Vec<String> = {
                                let guard = mem.lock().unwrap_or_else(|e| e.into_inner());
                                guard.txids_hex()
                            };
                            let payload = MempoolPayload { tx_hashes };
                            if let Ok(msg) = payload.to_message() {
                                send_message_detached(&writer, msg, addr);
                            }
                        } else if let Ok(msg) = EmptyPayload::to_message(MessageType::Mempool) {
                            send_message_detached(&writer, msg, addr);
                        }
                    }
                    MessageType::RelayAddress => {
                        if let Some(ref mem) = mempool_for_sync {
                            if let Ok(relay) = RelayAddressPayload::from_message(&msg) {
                                if relay.txid.len() == 64 {
                                    if let Ok(bytes) = hex::decode(relay.txid) {
                                        if bytes.len() == 32 {
                                            let mut txid = [0u8; 32];
                                            txid.copy_from_slice(&bytes);
                                            let mut guard =
                                                mem.lock().unwrap_or_else(|e| e.into_inner());
                                            guard.record_relay_address(&txid, relay.address);
                                        }
                                    }
                                } else if relay.txid.is_empty() {
                                    let multiaddr =
                                        format!("/ip4/{}/tcp/{}", addr.ip(), addr.port());
                                    let mut dir = dir.lock().await;
                                    dir.register_connection(
                                        multiaddr,
                                        None,
                                        Some(relay.address),
                                        None,
                                    );
                                }
                            }
                        }
                    }
                    MessageType::ProofGossip => {
                        if let Ok(pg) = crate::protocol::ProofGossipPayload::from_message(&msg) {
                            if let Ok(json) = String::from_utf8(pg.proof_json) {
                                let mut inbox = proof_gossip_inbox_outbound.lock().await;
                                inbox.push(json);
                            }
                        }
                    }
                    MessageType::OfferTakeNotification => {
                        if let Ok(otn) = crate::protocol::OfferTakeNotificationPayload::from_message(&msg) {
                            if let Ok(json) = String::from_utf8(otn.take_json) {
                                let mut inbox = offer_take_inbox_outbound.lock().await;
                                inbox.push(json);
                            }
                        }
                    }
                    MessageType::OfferBroadcast => {
                        if let Ok(ob) = crate::protocol::OfferBroadcastPayload::from_message(&msg) {
                            if let Some(json) = try_accept_offer_broadcast(
                                &ob.offer_json,
                                addr,
                                &seen_offer_ids_outbound,
                                &offer_rate_limit_outbound,
                            ).await {
                                {
                                    let mut inbox = offer_broadcast_inbox_outbound.lock().await;
                                    inbox.push(json.clone());
                                }
                                let payload = crate::protocol::OfferBroadcastPayload {
                                    offer_json: json.into_bytes(),
                                };
                                let bytes = payload.to_message().serialize();
                                let _ = broadcast_raw(&peers_vec, &bytes).await;
                            }
                        }
                    }
                    MessageType::DisputeRaisedNotification => {
                        if let Ok(p) = crate::protocol::DisputeRaisedNotificationPayload::from_message(&msg) {
                            if let Ok(json) = String::from_utf8(p.json) {
                                let mut inbox = dispute_raised_inbox_outbound.lock().await;
                                inbox.push(json);
                            }
                        }
                    }
                    MessageType::DisputeEvidenceNotification => {
                        if let Ok(p) = crate::protocol::DisputeEvidenceNotificationPayload::from_message(&msg) {
                            if let Ok(json) = String::from_utf8(p.json) {
                                let mut inbox = dispute_evidence_inbox_outbound.lock().await;
                                inbox.push(json);
                            }
                        }
                    }
                    MessageType::DisputeResolvedNotification => {
                        if let Ok(p) = crate::protocol::DisputeResolvedNotificationPayload::from_message(&msg) {
                            if let Ok(json) = String::from_utf8(p.json) {
                                let mut inbox = dispute_resolved_inbox_outbound.lock().await;
                                inbox.push(json);
                            }
                        }
                    }
                    MessageType::DisputeEscalatedNotification => {
                        if let Ok(p) = crate::protocol::DisputeEscalatedNotificationPayload::from_message(&msg) {
                            if let Ok(json) = String::from_utf8(p.json) {
                                let mut inbox = dispute_escalated_inbox_outbound.lock().await;
                                inbox.push(json);
                            }
                        }
                    }
                    MessageType::Disconnect => break,
                    _ => {}
                }
            }
            let _ = shutdown_tx_to_ping.send(());
            {
                let mut w = writer_for_drop.lock().await;
                let _ = w.shutdown().await;
            }
            {
                let mut guard = peers_vec.lock().await;
                guard.retain(|p| !Arc::ptr_eq(p, &writer_for_drop));
            }
            {
                let mut guard = connected_vec.lock().await;
                guard.remove(&addr);
            }
        });

        Ok(())
    }
}

fn sync_tick_interval() -> Duration {
    let secs = std::env::var("IRIUM_P2P_SYNC_TICK_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(5);
    Duration::from_secs(secs.clamp(1, 30))
}

/// Read a single protocol message from the given TCP stream.
async fn read_message<R>(stream: &mut R) -> Result<Message, String>
where
    R: AsyncReadExt + Unpin,
{
    let mut header = [0u8; 6];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|e| format!("failed to read message header: {}", e))?;

    let version = header[0];
    if version != crate::protocol::PROTOCOL_VERSION {
        return Err(format!("unsupported protocol version: {}", version));
    }

    let _msg_type = header[1];
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&header[2..6]);
    let length = u32::from_be_bytes(len_bytes);
    if length > MAX_MESSAGE_SIZE {
        return Err("message too large".to_string());
    }

    let mut payload = vec![0u8; length as usize];
    if length > 0 {
        stream
            .read_exact(&mut payload)
            .await
            .map_err(|e| format!("failed to read message payload: {}", e))?;
    }

    Message::deserialize(&[&header[..], &payload[..]].concat())
}

async fn read_message_with_timeout<R>(stream: &mut R, timeout: Duration) -> Result<Message, String>
where
    R: AsyncReadExt + Unpin,
{
    match tokio::time::timeout(timeout, read_message(stream)).await {
        Ok(res) => res,
        Err(_) => Err("peer read timeout".to_string()),
    }
}

fn peer_write_timeout() -> Duration {
    let ms = std::env::var("IRIUM_P2P_WRITE_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(8000);
    Duration::from_millis(ms.clamp(500, 30_000))
}

async fn send_message(
    writer: &Arc<Mutex<OwnedWriteHalf>>,
    msg: Message,
    peer: SocketAddr,
) -> Result<(), String> {
    let bytes = msg.serialize();
    let write_fut = async {
        let mut w = writer.lock().await;
        w.write_all(&bytes).await
    };
    match tokio::time::timeout(peer_write_timeout(), write_fut).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(format!("failed to send to {}: {}", peer, e)),
        Err(_) => Err(format!("failed to send to {}: write timeout", peer)),
    }
}

fn send_message_detached(writer: &Arc<Mutex<OwnedWriteHalf>>, msg: Message, peer: SocketAddr) {
    let writer_weak = Arc::downgrade(writer);
    tokio::spawn(async move {
        let Some(writer) = writer_weak.upgrade() else {
            return;
        };
        let _ = send_message(&writer, msg, peer).await;
    });
}

async fn send_message_or_disconnect(
    writer: &Arc<Mutex<OwnedWriteHalf>>,
    msg: Message,
    peer: SocketAddr,
    peers: &Arc<Mutex<Vec<Arc<Mutex<OwnedWriteHalf>>>>>,
    connected: &Arc<Mutex<HashSet<SocketAddr>>>,
) -> bool {
    match send_message(writer, msg, peer).await {
        Ok(()) => true,
        Err(e) => {
            P2PNode::log_event(
                "warn",
                "p2p",
                format!("P2P {}: send failed, dropping peer: {}", peer, e),
            );
            {
                let mut w = writer.lock().await;
                let _ = w.shutdown().await;
            }
            {
                let mut guard = peers.lock().await;
                guard.retain(|p| !Arc::ptr_eq(p, writer));
            }
            {
                let mut guard = connected.lock().await;
                guard.remove(&peer);
            }
            false
        }
    }
}

/// Phase 1A+1B: shared validation pipeline for incoming OfferBroadcast
/// messages. Returns Some(json) if the offer should be ingested (pushed
/// to inbox + re-broadcast); None if dropped (size, rate, dedup, or
/// parse failure). Drop reasons are silent to avoid log spam from
/// misbehaving peers.
async fn try_accept_offer_broadcast(
    raw: &[u8],
    addr: SocketAddr,
    seen: &Arc<tokio::sync::Mutex<(VecDeque<String>, HashSet<String>)>>,
    rate: &Arc<tokio::sync::Mutex<HashMap<SocketAddr, (Instant, u32)>>>,
) -> Option<String> {
    if raw.len() > OFFER_BROADCAST_MAX_BYTES {
        return None;
    }
    let json = match String::from_utf8(raw.to_vec()) {
        Ok(s) => s,
        Err(_) => return None,
    };
    let parsed: serde_json::Value = match serde_json::from_str(&json) {
        Ok(v) => v,
        Err(_) => return None,
    };
    // Offer JSON uses the field name "offer_id" (set by irium-wallet's
    // save_offer at src/bin/irium-wallet.rs:7488 — file name is also
    // "offer-<offer_id>.json"). Reject broadcasts missing this field.
    let id = match parsed.get("offer_id").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => return None,
    };
    if parsed.get("status").and_then(|v| v.as_str()) != Some("open") {
        return None;
    }
    {
        let mut g = rate.lock().await;
        let now = Instant::now();
        let entry = g.entry(addr).or_insert((now, 0));
        if now.duration_since(entry.0).as_secs() >= OFFER_BROADCAST_RATE_WINDOW_SECS {
            *entry = (now, 0);
        }
        if entry.1 >= OFFER_BROADCAST_PEER_RATE_PER_MIN {
            return None;
        }
        entry.1 = entry.1.saturating_add(1);
    }
    {
        let mut g = seen.lock().await;
        let (order, set) = &mut *g;
        if set.contains(&id) {
            return None;
        }
        if order.len() >= OFFER_BROADCAST_SEEN_CAP {
            if let Some(oldest) = order.pop_front() {
                set.remove(&oldest);
            }
        }
        order.push_back(id.clone());
        set.insert(id);
    }
    Some(json)
}

async fn broadcast_raw(peers: &Arc<Mutex<Vec<Arc<Mutex<OwnedWriteHalf>>>>>, bytes: &[u8]) -> usize {
    // Never hold the peers lock while awaiting I/O.
    let peers_snapshot = {
        let guard = peers.lock().await;
        guard.clone()
    };
    let mut dead: Vec<Arc<Mutex<OwnedWriteHalf>>> = Vec::new();
    let mut ok: usize = 0;
    for socket in peers_snapshot.iter() {
        let write_fut = async {
            let mut w = socket.lock().await;
            w.write_all(bytes).await
        };
        match tokio::time::timeout(peer_write_timeout(), write_fut).await {
            Ok(Ok(())) => ok += 1,
            Ok(Err(_)) | Err(_) => {
                {
                    let mut w = socket.lock().await;
                    let _ = w.shutdown().await;
                }
                dead.push(socket.clone());
            }
        }
    }
    if !dead.is_empty() {
        let mut guard = peers.lock().await;
        guard.retain(|p| !dead.iter().any(|d| Arc::ptr_eq(p, d)));
    }
    ok
}

fn local_height(chain: &Option<Arc<StdMutex<ChainState>>>) -> u64 {
    chain
        .as_ref()
        .and_then(|c| c.lock().ok().map(|g| g.tip_height()))
        .unwrap_or(0)
}

/// Handle an incoming peer connection by performing sybil-resistant
/// handshake verification before accepting the peer into the set of
/// connected sockets.
async fn handle_incoming_with_sybil(
    mut socket: TcpStream,
    addr: SocketAddr,
    bind_addr: SocketAddr,
    peers: Arc<Mutex<Vec<Arc<Mutex<OwnedWriteHalf>>>>>,
    connected: Arc<Mutex<HashSet<SocketAddr>>>,
    directory: Arc<Mutex<PeerDirectory>>,
    reputation: Arc<Mutex<ReputationManager>>,
    sync_requests: Arc<Mutex<HashMap<IpAddr, Instant>>>,
    block_requests: Arc<Mutex<HashMap<IpAddr, Instant>>>,
    getblocks_seen: Arc<Mutex<HashMap<IpAddr, Instant>>>,
    getblocks_last: Arc<Mutex<HashMap<IpAddr, (Vec<u8>, u32, Instant)>>>,
    getblocks_genesis: Arc<Mutex<HashMap<IpAddr, Instant>>>,
    send_blocks_log: Arc<Mutex<HashMap<IpAddr, Instant>>>,
    self_ips: Arc<Mutex<HashSet<IpAddr>>>,
    chain: Option<Arc<StdMutex<ChainState>>>,
    mempool: Option<Arc<StdMutex<MempoolManager>>>,
    agent: String,
    relay_address: Option<String>,
    marketplace_feed_url: Option<String>,
    external_endpoint: Option<String>,
    proof_gossip_inbox: Arc<tokio::sync::Mutex<Vec<String>>>,
    offer_take_inbox: Arc<tokio::sync::Mutex<Vec<String>>>,
    offer_broadcast_inbox: Arc<tokio::sync::Mutex<Vec<String>>>,
    seen_offer_ids: Arc<tokio::sync::Mutex<(VecDeque<String>, HashSet<String>)>>,
    offer_rate_limit: Arc<tokio::sync::Mutex<HashMap<SocketAddr, (Instant, u32)>>>,
    dispute_raised_inbox: Arc<tokio::sync::Mutex<Vec<String>>>,
    dispute_evidence_inbox: Arc<tokio::sync::Mutex<Vec<String>>>,
    dispute_resolved_inbox: Arc<tokio::sync::Mutex<Vec<String>>>,
    dispute_escalated_inbox: Arc<tokio::sync::Mutex<Vec<String>>>,
    node_id: Vec<u8>,
    trusted_seed: bool,
) -> Result<(), String> {
    let local_node_id = hex::encode(&node_id);
    let local_node_id_bytes = node_id.clone();
    let _handshake_permit = if trusted_seed {
        inbound_handshake_sem()
            .acquire_owned()
            .await
            .map_err(|_| "inbound handshake semaphore closed".to_string())?
    } else {
        match inbound_handshake_sem().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                let _ = socket.shutdown().await;
                return Err("inbound handshake overloaded".to_string());
            }
        }
    };
    // Issue a fresh challenge with adaptive difficulty.
    let base = P2PNode::sybil_difficulty();
    let max = std::env::var("IRIUM_SYBIL_DIFFICULTY_MAX")
        .ok()
        .and_then(|v| v.parse::<u8>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(20);
    let difficulty = if trusted_seed {
        base
    } else {
        let banned = {
            let rep = reputation.lock().await;
            rep.banned_count() as u8
        };
        let bump = P2PNode::sybil_banned_bump(banned);
        std::cmp::min(max, base.saturating_add(bump))
    };
    let handshake = SybilResistantHandshake::new(difficulty);
    let challenge = handshake.create_challenge();
    let challenge_bytes = challenge.to_bytes();
    let challenge_msg = Message {
        msg_type: MessageType::SybilChallenge,
        payload: challenge_bytes,
    };
    let ser = challenge_msg.serialize();
    socket
        .write_all(&ser)
        .await
        .map_err(|e| format!("failed to send sybil challenge to {}: {}", addr, e))?;

    // Expect a proof in response.
    let proof_msg = match read_message_with_timeout(&mut socket, P2PNode::peer_timeout()).await {
        Ok(m) => m,
        Err(e) => {
            if e.contains("early eof") {
                let peer_id = trusted_anchor_peer_id(addr, trusted_seed);
                let mut rep = reputation.lock().await;
                for _ in 0..5 {
                    rep.record_failure(&peer_id);
                }
                return Err(format!("early eof during sybil proof from {}: {}", addr, e));
            }
            return Err(e);
        }
    };
    if proof_msg.msg_type != MessageType::SybilProof {
        return Err("expected sybil proof from peer".to_string());
    }
    let proof = SybilProof::from_bytes(&proof_msg.payload)
        .ok_or_else(|| "invalid sybil proof payload".to_string())?;
    let peer_pubkey = proof.peer_pubkey.clone();
    let proof_ok = tokio::task::spawn_blocking(move || handshake.verify_proof(&proof))
        .await
        .map_err(|e| format!("failed to join sybil verifier: {}", e))?;
    if !proof_ok {
        {
            let mut rep = reputation.lock().await;
            rep.record_failure(&trusted_anchor_peer_id(addr, trusted_seed));
        }
        return Err("sybil proof verification failed".to_string());
    }

    {
        let mut rep = reputation.lock().await;
        rep.record_success(&trusted_anchor_peer_id(addr, trusted_seed));
    }
    {
        let mut guard = connected.lock().await;
        guard.insert(addr);
    }
    // At this point, accept the peer and start reading further messages.
    let (mut reader, writer_half) = socket.into_split();
    let writer = Arc::new(tokio::sync::Mutex::new(writer_half));
    {
        let mut guard = peers.lock().await;
        guard.push(writer.clone());
    }

    let peer_state = Arc::new(Mutex::new(PeerSyncState::default()));
    let (shutdown_tx_to_ping, mut shutdown_rx_to_ping) = tokio::sync::oneshot::channel::<()>();
    let (shutdown_tx_to_reader, mut shutdown_rx_to_reader) = tokio::sync::oneshot::channel::<()>();
    let ping_writer_weak = Arc::downgrade(&writer);
    let ping_addr = addr;
    let ping_chain = chain.clone();
    let ping_agent = agent.clone();
    let ping_relay = relay_address.clone();
    let ping_marketplace_feed = marketplace_feed_url.clone();
    let ping_external_endpoint = external_endpoint.clone();
    let ping_port = bind_addr.port();
    let ping_node_id = node_id.clone();
    let ping_peer_state = peer_state.clone();
    let ping_sync_requests = sync_requests.clone();
    let ping_block_requests = block_requests.clone();
    let ping_peers_vec = peers.clone();
    let ping_connected_vec = connected.clone();
    tokio::spawn(async move {
        let mut shutdown_tx_to_reader = Some(shutdown_tx_to_reader);
        let ping_interval = P2PNode::ping_interval();
        let sync_tick = sync_tick_interval();
        let mut last_ping = Instant::now();
        let mut last_height = crate::p2p::local_height(&ping_chain);
        let mut last_handshake = Instant::now();
        loop {
            tokio::select! {
                _ = tokio::time::sleep(sync_tick) => {}
                _ = &mut shutdown_rx_to_ping => {
                    break;
                }
            }
            let ping_writer = match ping_writer_weak.upgrade() {
                Some(w) => w,
                None => break,
            };
            if last_ping.elapsed() >= ping_interval {
                let nonce = rand_core::OsRng.next_u64();
                let ping = PingPayload { nonce };
                let msg = ping.to_message();
                if !send_message_or_disconnect(
                    &ping_writer,
                    msg,
                    ping_addr,
                    &ping_peers_vec,
                    &ping_connected_vec,
                )
                .await
                {
                    if let Some(tx) = shutdown_tx_to_reader.take() {
                        let _ = tx.send(());
                    }
                    break;
                }
                last_ping = Instant::now();
            }
            let current_height = crate::p2p::local_height(&ping_chain);
            let handshake_due = last_handshake.elapsed() >= P2PNode::handshake_interval();
            if handshake_due || current_height != last_height {
                let (checkpoint_height, checkpoint_hash) = best_checkpoint(&ping_chain);
                let payload = HandshakePayload {
                    version: 1,
                    agent: ping_agent.clone(),
                    height: current_height,
                    timestamp: Utc::now().timestamp(),
                    port: ping_port,
                    checkpoint_height,
                    checkpoint_hash,
                    relay_address: ping_relay.clone(),
                    node_id: Some(hex::encode(&ping_node_id)),
                    tip_hash: Some(hex::encode(P2PNode::tip_hash(&ping_chain))),
                    capabilities: local_capabilities(),
                    marketplace_feed: ping_marketplace_feed.clone(),
                    external_endpoint: ping_external_endpoint.clone(),
                };
                if let Ok(msg) = payload.to_message() {
                    let _ = send_message(&ping_writer, msg, ping_addr).await;
                }
                last_height = current_height;
                last_handshake = Instant::now();
                if uptime_enabled() {
                    let challenge = {
                        let mut state = ping_peer_state.lock().await;
                        if !state.supports_uptime {
                            None
                        } else {
                            let due = state
                                .last_uptime_sent
                                .map(|t| t.elapsed() >= uptime_interval())
                                .unwrap_or(true);
                            if !due {
                                None
                            } else {
                                let mut nonce = [0u8; 32];
                                OsRng.fill_bytes(&mut nonce);
                                let timestamp = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs();
                                let payload = UptimeChallengePayload { nonce, timestamp };
                                state.last_uptime_challenge = Some(payload.clone());
                                state.last_uptime_sent = Some(Instant::now());
                                Some(payload)
                            }
                        }
                    };
                    if let Some(payload) = challenge {
                        let msg = payload.to_message();
                        if !send_message_or_disconnect(
                            &ping_writer,
                            msg,
                            ping_addr,
                            &ping_peers_vec,
                            &ping_connected_vec,
                        )
                        .await
                        {
                            break;
                        }
                    }
                }
            }
            maybe_request_sync(
                &ping_writer,
                ping_addr,
                &ping_chain,
                &ping_sync_requests,
                &ping_block_requests,
                &ping_peer_state,
            )
            .await;
            maybe_request_headers_fallback(
                &ping_writer,
                ping_addr,
                &ping_chain,
                &ping_sync_requests,
                &ping_peer_state,
            )
            .await;
        }
    });

    // Register the peer in the directory for future runtime seedlist updates.
    {
        let mut dir = directory.lock().await;
        let multiaddr = format!("/ip4/{}/tcp/{}", addr.ip(), addr.port());
        let node_id = hex::encode(&peer_pubkey);
        dir.register_connection(multiaddr.clone(), None, None, Some(node_id));
    }

    // Reply with our handshake so outbound peers learn our agent/height.
    let local_h = local_height(&chain);
    let (checkpoint_height, checkpoint_hash) = best_checkpoint(&chain);
    let payload = HandshakePayload {
        version: 1,
        agent: agent.clone(),
        height: local_h,
        timestamp: Utc::now().timestamp(),
        port: bind_addr.port(),
        checkpoint_height,
        checkpoint_hash,
        relay_address: relay_address.clone(),
        node_id: Some(hex::encode(&node_id)),
        tip_hash: Some(hex::encode(P2PNode::tip_hash(&chain))),
        capabilities: local_capabilities(),
        marketplace_feed: marketplace_feed_url.clone(),
        external_endpoint: external_endpoint.clone(),
    };
    if let Ok(msg) = payload.to_message() {
        send_message_detached(&writer, msg, addr);
    }

    let mut msg_count: u32 = 0;
    let mut window_start = Instant::now();
    let mut last_handshake_height: Option<u64> = None;
    // Process messages from the peer.
    let mut bulk_count: u32 = 0;
    loop {
        let msg = tokio::select! {
            _ = &mut shutdown_rx_to_reader => { break; }
            res = read_message_with_timeout(&mut reader, P2PNode::peer_timeout()) => res,
        };
        let msg = match msg {
            Ok(m) => m,
            Err(e) => {
                P2PNode::log_event(
                    "warn",
                    "net",
                    format!("P2P inbound {}: closing read loop: {}", addr, e),
                );
                let mut rep = reputation.lock().await;
                // FIX #128: connection dropped mid-session is a
                // network event, not malicious behavior.
                rep.record_dial_failure(&trusted_anchor_peer_id(addr, trusted_seed));
                break;
            }
        };
        if window_start.elapsed() >= Duration::from_secs(1) {
            window_start = Instant::now();
            msg_count = 0;
            bulk_count = 0;
        }
        let is_bulk = matches!(msg.msg_type, MessageType::Block | MessageType::Headers);
        if is_bulk {
            bulk_count += 1;
            if bulk_count > MAX_BULK_MSGS_PER_SEC {
                P2PNode::log_event(
                    "warn",
                    "net",
                    format!("P2P inbound {}: bulk rate limit", addr),
                );
                break;
            }
        } else {
            msg_count += 1;
            if msg_count > MAX_MSGS_PER_SEC {
                P2PNode::log_event("warn", "net", format!("P2P inbound {}: rate limit", addr));
                break;
            }
        }

        if P2PNode::verbose_messages() {
            match msg.msg_type {
                MessageType::Ping
                | MessageType::Pong
                | MessageType::Handshake
                | MessageType::Peers
                | MessageType::GetPeers
                | MessageType::GetHeaders
                | MessageType::GetBlocks
                | MessageType::Headers
                | MessageType::Block
                | MessageType::UptimeChallenge
                | MessageType::UptimeProof => {}
                _ => {
                    P2PNode::log_event(
                        "info",
                        "net",
                        format!("P2P {}: recv {:?}", addr, msg.msg_type),
                    );
                }
            }
        }

        match msg.msg_type {
            MessageType::Handshake => {
                if let Ok(payload) = HandshakePayload::from_message(&msg) {
                    if let Some(ref remote_id) = payload.node_id {
                        if remote_id == &local_node_id {
                            {
                                let mut guard = self_ips.lock().await;
                                guard.insert(addr.ip());
                            }
                            P2PNode::log_event(
                                "warn",
                                "net",
                                format!("P2P {}: self-connection detected, dropping", addr),
                            );
                            break;
                        }
                        // Fix 1: verify handshake node_id matches the sybil proof pubkey.
                        // Binds PoW identity to protocol identity: an attacker cannot
                        // solve with one node_id and then handshake as a different one.
                        if let Ok(id_bytes) = hex::decode(remote_id) {
                            if id_bytes != peer_pubkey {
                                P2PNode::log_event(
                                    "warn",
                                    "net",
                                    format!("P2P {}: handshake node_id does not match sybil pubkey, closing", addr),
                                );
                                break;
                            }
                        }
                    }
                    if let Err(reason) = verify_peer_checkpoint(&payload, &chain) {
                        if let Some(rest) = reason.strip_prefix("LOCAL_FORK:") {
                            P2PNode::log_event(
                                "error",
                                "sync",
                                format!(
                                    "P2P {}: LOCAL node appears on a fork/split chain ({}). Attempting recovery...",
                                    addr,
                                    rest.trim()
                                ),
                            );
                            // State-only recovery: clear sync throttles and request headers from genesis.
                            sync_requests.lock().await.clear();
                            block_requests.lock().await.clear();
                            let get_headers = GetHeadersPayload {
                                start_hash: vec![0u8; 32],
                                count: MAX_HEADERS_PER_REQUEST,
                            };
                            if let Ok(msg) = get_headers.to_message() {
                                send_message_detached(&writer, msg, addr);
                            }
                        } else {
                            P2PNode::log_event(
                                "warn",
                                "net",
                                format!(
                                    "P2P {}: peer on fork/split or incompatible chain: {}",
                                    addr, reason
                                ),
                            );
                            break;
                        }
                    }
                    let advertised_port = if payload.port > 0 {
                        payload.port
                    } else {
                        bind_addr.port()
                    };
                    // Prefer the peer's self-advertised external_endpoint when it
                    // parses as a globally routable IPv4:port. This is the key
                    // CGNAT escape hatch: TCP source IP equals the carrier-NAT
                    // address, so without an explicit advertisement we'd gossip
                    // an unroutable record. Old peers without the field fall
                    // through to the legacy TCP-source-IP form.
                    let multiaddr = payload
                        .external_endpoint
                        .as_deref()
                        .and_then(dialable_multiaddr_from_advertised)
                        .unwrap_or_else(|| {
                            format!("/ip4/{}/tcp/{}", addr.ip(), advertised_port)
                        });
                    {
                        let mut dir = directory.lock().await;
                        dir.register_connection(
                            multiaddr.clone(),
                            Some(payload.agent.clone()),
                            payload.relay_address.clone(),
                            payload.node_id.clone(),
                        );
                        // A peer that completed an inbound handshake and advertised a listen
                        // port is a viable runtime-seed candidate for later outbound refresh.
                        dir.mark_dialable(&multiaddr);
                    }

                    let parsed_tip = payload
                        .tip_hash
                        .as_ref()
                        .and_then(|h| hex::decode(h).ok())
                        .and_then(|b| {
                            if b.len() == 32 {
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(&b);
                                Some(arr)
                            } else {
                                None
                            }
                        });
                    let node_id_bytes = parse_node_id_bytes(&payload);
                    let supports_uptime = peer_supports_uptime(&payload);
                    {
                        let mut state = peer_state.lock().await;
                        state.tip = parsed_tip;
                        state.node_id = node_id_bytes.clone();
                        state.supports_uptime = supports_uptime;
                    }
                    last_handshake_height = Some(payload.height);
                    if let Some(ref feed_url) = payload.marketplace_feed {
                        record_discovered_feed(feed_url);
                    }

                    let (checkpoint_height, checkpoint_hash) = best_checkpoint(&chain);
                    let response = HandshakePayload {
                        version: payload.version,
                        agent: agent.clone(),
                        height: local_height(&chain),
                        timestamp: Utc::now().timestamp(),
                        port: bind_addr.port(),
                        checkpoint_height,
                        checkpoint_hash,
                        relay_address: relay_address.clone(),
                        node_id: Some(hex::encode(&node_id)),
                        tip_hash: Some(hex::encode(P2PNode::tip_hash(&chain))),
                        capabilities: local_capabilities(),
                        marketplace_feed: marketplace_feed_url.clone(),
                        external_endpoint: external_endpoint.clone(),
                    };
                    if let Ok(handshake_msg) = response.to_message() {
                        let _ = send_message(&writer, handshake_msg, addr).await;
                    }
                    // Ask peer for its view of the network.
                    if let Ok(msg) = EmptyPayload::to_message(MessageType::GetPeers) {
                        send_message_detached(&writer, msg, addr);
                        maybe_request_sync(
                            &writer,
                            addr,
                            &chain,
                            &sync_requests,
                            &block_requests,
                            &peer_state,
                        )
                        .await;
                    }
                    // Proactive addr push: send up to 1000 dialable peers on connect.
                    {
                        let to_push: Vec<String> = {
                            let d = directory.lock().await;
                            d.peers().iter().filter(|p| p.dialable).take(MAX_ADDR_PUSH).map(|p| p.multiaddr.clone()).collect()
                        };
                        if !to_push.is_empty() {
                            if let Ok(push_msg) = (PeersPayload { peers: to_push }).to_message() {
                                send_message_detached(&writer, push_msg, addr);
                            }
                        }
                    }
                    let local_height = local_height(&chain);
                    let peer_tip = payload
                        .tip_hash
                        .as_ref()
                        .and_then(|h| hex::decode(h).ok())
                        .and_then(|b| {
                            if b.len() == 32 {
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(&b);
                                Some(arr)
                            } else {
                                None
                            }
                        });
                    let _peer_tip_on_main =
                        if let (Some(tip), Some(chain_arc)) = (peer_tip, chain.as_ref()) {
                            let guard = chain_arc.lock().unwrap_or_else(|e| e.into_inner());
                            if let Some(h) = guard.heights.get(&tip) {
                                guard
                                    .chain
                                    .get(*h as usize)
                                    .map(|b| b.header.hash_for_height(*h) == tip)
                                    .unwrap_or(false)
                            } else {
                                false
                            }
                        } else {
                            true
                        };
                    let local_at_peer = if let Some(ref chain_arc) = chain {
                        let guard = chain_arc.lock().unwrap_or_else(|e| e.into_inner());
                        guard
                            .chain
                            .get(payload.height as usize)
                            .map(|b| b.header.hash_for_height(payload.height))
                    } else {
                        None
                    };
                    let tip_mismatch = if payload.height == local_height {
                        match peer_tip {
                            Some(t) => local_at_peer.map(|h| h != t).unwrap_or(false),
                            None => false,
                        }
                    } else {
                        false
                    };
                    let bad_recent = {
                        let state = peer_state.lock().await;
                        state
                            .last_bad_headers
                            .map(|ts| ts.elapsed() < Duration::from_secs(120))
                            .unwrap_or(false)
                    };
                    if !bad_recent
                        && (payload.height > local_height
                            || (payload.height == local_height && tip_mismatch))
                    {
                        let local_tip = P2PNode::tip_hash(&chain);
                        let start_hash = if local_height == 0
                            || (payload.height == local_height && tip_mismatch)
                        {
                            [0u8; 32]
                        } else {
                            local_tip
                        };
                        let get_headers = GetHeadersPayload {
                            start_hash: start_hash.to_vec(),
                            count: MAX_HEADERS_PER_REQUEST,
                        };
                        let short = if start_hash == [0u8; 32] {
                            "genesis".to_string()
                        } else {
                            let h = hex::encode(start_hash);
                            h.get(0..12).unwrap_or(&h).to_string()
                        };

                        let mut allowed = sync_request_allowed_for(
                            &sync_requests,
                            addr.ip(),
                            local_height,
                            payload.height,
                        )
                        .await;
                        if allowed {
                            let now = Instant::now();
                            let (last_req, last_start) = {
                                let mut guard = peer_state.lock().await;
                                let stale_inflight = guard.headers_inflight
                                    && guard
                                        .last_headers_request
                                        .map(|ts| {
                                            now.duration_since(ts) > headers_response_window()
                                        })
                                        .unwrap_or(false);
                                if stale_inflight {
                                    guard.headers_inflight = false;
                                    guard.headers_processing = false;
                                }
                                (guard.last_headers_request, guard.last_headers_start)
                            };
                            if let Some(ts) = last_req {
                                if now.duration_since(ts)
                                    < headers_request_cooldown_for(local_height, payload.height)
                                    && last_start == Some(start_hash)
                                {
                                    allowed = false;
                                }
                            }
                        }

                        if allowed {
                            P2PNode::log_event(
                                "info",
                                "sync",
                                format!(
                                    "P2P {}: peer ahead ({} > {}), requesting headers from tip {}",
                                    addr, payload.height, local_height, short
                                ),
                            );
                            if let Ok(msg) = get_headers.to_message() {
                                send_message_detached(&writer, msg, addr);
                            }
                            {
                                let mut state = peer_state.lock().await;
                                state.last_headers_request = Some(Instant::now());
                                state.last_headers_start = Some(start_hash);
                                state.headers_inflight = true;
                            }
                        }
                    } else if payload.height < local_height {
                        // Peer is behind; send headers and fall back to block push if needed.
                        let behind_height = payload.height;
                        if let Some(ref chain_arc) = chain {
                            let headers_bytes = {
                                let guard = chain_arc.lock().unwrap_or_else(|e| e.into_inner());
                                let start = if tip_mismatch {
                                    0
                                } else {
                                    payload.height.saturating_add(1) as usize
                                };
                                let mut headers = Vec::new();
                                for (i, block) in guard.chain.iter().skip(start).take(32).enumerate() {
                                    let h = (start + i) as u64;
                                    headers.extend_from_slice(&block.header.serialize_for_height(h));
                                }
                                headers
                            };
                            if !headers_bytes.is_empty() {
                                let msg = HeadersPayload {
                                    headers: headers_bytes,
                                }
                                .to_message();
                                send_message_detached(&writer, msg, addr);
                            }
                        }
                        if !tip_mismatch {
                            let fallback_writer = Arc::downgrade(&writer);
                            let fallback_chain = chain.clone();
                            let fallback_seen = getblocks_seen.clone();
                            let fallback_addr = addr;
                            tokio::spawn(async move {
                                let grace = no_getblocks_fallback_cooldown();
                                tokio::time::sleep(grace).await;
                                let now = Instant::now();
                                {
                                    let mut guard = fallback_seen.lock().await;
                                    if let Some(last) = guard.get(&fallback_addr.ip()) {
                                        if now.duration_since(*last) < grace {
                                            return;
                                        }
                                    }
                                    guard.insert(fallback_addr.ip(), now);
                                }
                                let (blocks, start_height) = if let Some(ref chain_arc) =
                                    fallback_chain
                                {
                                    let guard = chain_arc.lock().unwrap_or_else(|e| e.into_inner());
                                    let start_idx = behind_height.saturating_add(1) as usize;
                                    if start_idx >= guard.chain.len() {
                                        (Vec::new(), 0)
                                    } else {
                                        let mut blocks = Vec::new();
                                        for (i, b) in guard
                                            .chain
                                            .iter()
                                            .skip(start_idx)
                                            .take(fallback_blocks_per_burst())
                                            .enumerate()
                                        {
                                            let h = (start_idx + i) as u64;
                                            blocks.push(b.serialize_for_height(h));
                                        }
                                        (blocks, start_idx as u64)
                                    }
                                } else {
                                    (Vec::new(), 0)
                                };
                                if blocks.is_empty() {
                                    return;
                                }
                                let Some(fallback_writer) = fallback_writer.upgrade() else {
                                    return;
                                };
                                let end_h = start_height + blocks.len() as u64 - 1;
                                P2PNode::log_event(
                                    "info",
                                    "sync",
                                    format!(
                                    "P2P {}: no getblocks after headers, pushing {} blocks [{}-{}]",
                                    fallback_addr,
                                    blocks.len(),
                                    start_height,
                                    end_h
                                ),
                                );
                                for block_data in blocks {
                                    let msg = BlockPayload { block_data }.to_message();
                                    let _ =
                                        send_message(&fallback_writer, msg, fallback_addr).await;
                                }
                            });
                        }
                    }
                }
            }
            MessageType::Ping => {
                if let Ok(ping) = PingPayload::from_message(&msg) {
                    let mut payload = Vec::new();
                    payload.extend_from_slice(&ping.nonce.to_be_bytes());
                    let pong = Message {
                        msg_type: MessageType::Pong,
                        payload,
                    };
                    let _ = send_message(&writer, pong, addr).await;
                    let mut dir_guard = directory.lock().await;
                    let multiaddr = format!("/ip4/{}/tcp/{}", addr.ip(), addr.port());
                    dir_guard.mark_seen(&multiaddr);
                }
            }
            MessageType::UptimeChallenge => {
                if uptime_enabled() {
                    if let Ok(payload) = UptimeChallengePayload::from_message(&msg) {
                        if !uptime_timestamp_valid(payload.timestamp) {
                            continue;
                        }
                        let peer_id = {
                            let guard = peer_state.lock().await;
                            guard.node_id.clone()
                        };
                        if let Some(peer_id) = peer_id {
                            let key = uptime_key(&local_node_id_bytes, &peer_id);
                            let hmac = compute_uptime_hmac(&key, &payload.nonce, payload.timestamp);
                            let proof = UptimeProofPayload {
                                nonce: payload.nonce,
                                timestamp: payload.timestamp,
                                hmac,
                            };
                            let _ = send_message(&writer, proof.to_message(), addr).await;
                        }
                    }
                }
            }
            MessageType::UptimeProof => {
                if uptime_enabled() {
                    if let Ok(payload) = UptimeProofPayload::from_message(&msg) {
                        if !uptime_timestamp_valid(payload.timestamp) {
                            continue;
                        }
                        let (challenge, peer_id) = {
                            let guard = peer_state.lock().await;
                            (guard.last_uptime_challenge.clone(), guard.node_id.clone())
                        };
                        if let (Some(challenge), Some(peer_id)) = (challenge, peer_id) {
                            if challenge.nonce == payload.nonce
                                && challenge.timestamp == payload.timestamp
                            {
                                let key = uptime_key(&local_node_id_bytes, &peer_id);
                                let expected =
                                    compute_uptime_hmac(&key, &payload.nonce, payload.timestamp);
                                if expected == payload.hmac {
                                    let mut rep = reputation.lock().await;
                                    rep.record_uptime_proof(&trusted_anchor_peer_id(
                                        addr,
                                        trusted_seed,
                                    ));
                                    let mut guard = peer_state.lock().await;
                                    guard.last_uptime_challenge = None;
                                }
                            }
                        }
                    }
                }
            }
            MessageType::GetPeers => {
                let peers_payload = {
                    let dir = directory.lock().await;
                    PeersPayload {
                        peers: dir
                            .peers()
                            .iter()
                            .filter(|p| p.dialable)
                            .take(MAX_PEERS_IN_RESPONSE)
                            .map(|p| p.multiaddr.clone())
                            .collect(),
                    }
                };
                if let Ok(resp) = peers_payload.to_message() {
                    send_message_detached(&writer, resp, addr);
                }
            }
            MessageType::Peers => {
                if let Ok(list) = PeersPayload::from_message(&msg) {
                    let source = format!("/ip4/{}/tcp/{}", addr.ip(), addr.port());
                    let filtered: Vec<String> = list.peers.into_iter()
                        .filter(|p| {
                            if let Some(port_str) = p.split("/tcp/").nth(1) {
                                port_str.trim().parse::<u16>().map(|port| port != 0).unwrap_or(true)
                            } else if let Ok(sa) = p.parse::<std::net::SocketAddr>() {
                                sa.port() != 0
                            } else {
                                true
                            }
                        })
                        .collect();
                    let mut dir = directory.lock().await;
                    dir.register_peer_hints(filtered, Some(&source));
                }
            }

            MessageType::GetHeaders => {
                if let Some(ref chain_arc) = chain {
                    if let Ok(payload) = GetHeadersPayload::from_message(&msg) {
                        let chain_arc2 = chain_arc.clone();
                        let writer_weak = Arc::downgrade(&writer);
                        let addr2 = addr;

                        tokio::spawn(async move {
                            let start_hash = payload.start_hash;
                            let count = payload.count;

                            let headers_bytes = match spawn_blocking_limited(move || {
                                let guard = chain_arc2.lock().unwrap_or_else(|e| e.into_inner());

                                let mut start_idx = if guard.chain.len() > 1 { 1 } else { 0 };
                                let mut start_hash_non_zero = false;
                                let mut start_found = false;
                                if start_hash.len() == 32 {
                                    let mut target = [0u8; 32];
                                    target.copy_from_slice(&start_hash);
                                    start_hash_non_zero = target.iter().any(|b| *b != 0);
                                    if start_hash_non_zero {
                                        if let Some((pos, _)) = guard
                                            .chain
                                            .iter()
                                            .enumerate()
                                            .find(|(idx, b)| b.header.hash_for_height(*idx as u64) == target)
                                        {
                                            start_idx = pos.saturating_add(1);
                                            start_found = true;
                                        }
                                    }
                                }
                                let count = count.min(MAX_HEADERS_PER_REQUEST) as usize;
                                let mut bytes = Vec::new();
                                if !start_hash_non_zero || start_found {
                                    for (i, block) in guard.chain.iter().skip(start_idx).take(count).enumerate() {
                                        let h = (start_idx + i) as u64;
                                        bytes.extend_from_slice(&block.header.serialize_for_height(h));
                                    }
                                }
                                bytes
                            })
                            .await
                            {
                                Ok(v) => v,
                                Err(_) => return,
                            };

                            let msg = HeadersPayload {
                                headers: headers_bytes,
                            }
                            .to_message();
                            if let Some(writer) = writer_weak.upgrade() {
                                send_message_detached(&writer, msg, addr2);
                            }
                        });
                    }
                }
            }
            MessageType::Headers => {
                if let Some(ref chain_arc) = chain {
                    if let Ok(payload) = HeadersPayload::from_message(&msg) {
                        let header_count = (payload.headers.len() / 80) as u32;
                        let header_bytes = payload.headers;
                        let chain_arc_for_headers = chain_arc.clone();
                        let chain_arc_for_tip = chain_arc.clone();
                        let peer_height_hint = last_handshake_height;
                        let addr2 = addr;
                        let peer_state2 = peer_state.clone();
                        let sync_requests2 = sync_requests.clone();
                        let block_requests2 = block_requests.clone();
                        let writer_weak = Arc::downgrade(&writer);
                        let directory2 = directory.clone();

                        {
                            let mut state = peer_state.lock().await;
                            let now = Instant::now();
                            let inflight_recent = state
                                .last_headers_request
                                .map(|ts| now.duration_since(ts) <= headers_response_window())
                                .unwrap_or(false);
                            if !inflight_recent {
                                state.unsolicited_headers =
                                    state.unsolicited_headers.saturating_add(1);
                                let should_log = state
                                    .last_unsolicited_log
                                    .map(|t| now.duration_since(t) > Duration::from_secs(30))
                                    .unwrap_or(true);
                                if should_log {
                                    state.last_unsolicited_log = Some(now);
                                    if should_emit_unsolicited_headers_log() {
                                        P2PNode::log_event(
                                            "warn",
                                            "sync",
                                            format!("P2P {}: unsolicited headers ignored", addr),
                                        );
                                    }
                                }
                                continue;
                            }
                            if state.headers_processing {
                                state.unsolicited_headers =
                                    state.unsolicited_headers.saturating_add(1);
                                continue;
                            }
                            state.headers_processing = true;
                            state.headers_inflight = false;
                        }

                        let permit = match inbound_bulk_queue().acquire_owned().await {
                            Ok(p) => p,
                            Err(_) => continue,
                        };

                        tokio::spawn(async move {
                            let permit_guard = permit;

                            let (last_header_hash, header_error, unknown_parent, reset_headers, added_any, reject_reason, first_unknown_prev) =
                                match spawn_blocking_limited(move || {
                                    let mut offset = 0usize;
                                    let mut last_header_hash: Option<[u8; 32]> = None;
                                    let mut header_error = false;
                                    let mut unknown_parent = false;
                                    let mut reset_headers = false;
                                    let mut added_any = false;
                                    let mut reject_reason: Option<String> = None;
                                    let mut first_unknown_prev: Option<[u8; 32]> = None;

                                    let mut guard =
                                        chain_arc_for_headers.lock().unwrap_or_else(|e| e.into_inner());

                                    while offset + 80 <= header_bytes.len() {
                                        let slice = &header_bytes[offset..offset + 80];
                                        // Peek prev_hash → look up parent → derive height
                                        // before height-aware deserialize.
                                        let prev_peek =
                                            match crate::block::BlockHeader::peek_prev_hash(slice) {
                                                Ok(p) => p,
                                                Err(_) => {
                                                    header_error = true;
                                                    reject_reason = Some("decode_error".to_string());
                                                    break;
                                                }
                                            };
                                        let header_height = if prev_peek == [0u8; 32] {
                                            0
                                        } else if let Some(h) = guard
                                            .heights
                                            .get(&prev_peek)
                                            .copied()
                                            .or_else(|| guard.headers.get(&prev_peek).map(|hw| hw.height))
                                        {
                                            h + 1
                                        } else {
                                            0
                                        };
                                        let (header, used) = match crate::block::BlockHeader::deserialize_for_height(
                                            slice,
                                            header_height,
                                        ) {
                                            Ok(v) => v,
                                            Err(_) => {
                                                header_error = true;
                                                reject_reason = Some("decode_error".to_string());
                                                break;
                                            }
                                        };
                                        offset += used;
                                        last_header_hash = Some(header.hash_for_height(header_height));

                                        let header_hash = header.hash_for_height(header_height);
                                        if header.prev_hash == [0u8; 32] {
                                            let genesis_hash =
                                                guard.params.genesis_block.header.hash_for_height(0);
                                            if header_hash == genesis_hash {
                                                continue;
                                            }
                                        }
                                        let already_known = guard.headers.contains_key(&header_hash)
                                            || guard.block_store.contains_key(&header_hash);
                                        if let Err(e) = guard.add_header(header.clone()) {
                                            if e.contains("unknown parent") {
                                                unknown_parent = true;
                                                if first_unknown_prev.is_none() {
                                                    first_unknown_prev = Some(header.prev_hash);
                                                }
                                                reject_reason.get_or_insert_with(|| classify_header_reject_reason(&e));
                                                let (orphan_n, inserted) = store_orphan_header(header.clone());
                                                if inserted {
                                                    P2PNode::log_event(
                                                        "info",
                                                        "sync",
                                                        format!(
                                                            "stored orphan header: hash={} prev={} orphan_headers={}",
                                                            short_hash(header_hash),
                                                            short_hash(header.prev_hash),
                                                            orphan_n
                                                        ),
                                                    );
                                                }
                                                if let Some(peer_height) = peer_height_hint {
                                                    let local_height = guard.tip_height();
                                                    if peer_height > local_height {
                                                        reset_headers = true;
                                                    }
                                                }
                                                continue;
                                            }
                                            header_error = true;
                                            reject_reason = Some(classify_header_reject_reason(&e));
                                            break;
                                        }
                                        if !already_known {
                                            added_any = true;
                                        }
                                        let (attached, attach_err) = attach_orphan_header_chain(&mut guard, header_hash);
                                        if attached > 0 {
                                            P2PNode::log_event(
                                                "info",
                                                "sync",
                                                format!(
                                                    "attached orphan header chain: attached={} orphan_headers={}",
                                                    attached,
                                                    orphan_headers_count()
                                                ),
                                            );
                                        }
                                        if let Some(reason) = attach_err {
                                            reject_reason.get_or_insert(reason);
                                        }
                                    }

                                        (last_header_hash, header_error, unknown_parent, reset_headers, added_any, reject_reason, first_unknown_prev)
                                })
                                .await
                                {
                                    Ok(v) => v,
                                    Err(_) => (None, true, false, false, false, Some("task_join_error".to_string()), None),
                                };
                            drop(permit_guard);

                            if header_count > 0 {
                                peer_mark_header_event(addr2.ip(), added_any, header_count).await;
                                let should_log = {
                                    let mut st = peer_state2.lock().await;
                                    let now = Instant::now();
                                    let at_tip = {
                                        let g = chain_arc_for_tip
                                            .lock()
                                            .unwrap_or_else(|e| e.into_inner());
                                        let local_h = g.tip_height();
                                        let best_hash = g.best_header_hash();
                                        let best_h = g
                                            .headers
                                            .get(&best_hash)
                                            .map(|hw| hw.height)
                                            .or_else(|| g.heights.get(&best_hash).copied())
                                            .unwrap_or(local_h);
                                        best_h <= local_h
                                    };
                                    let noisy = (!added_any && header_count >= 16)
                                        || (at_tip && header_count >= 32)
                                        || header_count >= 2000;
                                    let allow = if noisy {
                                        st.last_headers_batch_log
                                            .map(|t| {
                                                now.duration_since(t)
                                                    > Duration::from_secs(
                                                        headers_batch_log_cooldown_secs(),
                                                    )
                                            })
                                            .unwrap_or(true)
                                    } else {
                                        true
                                    };
                                    if allow {
                                        st.last_headers_batch_log = Some(now);
                                    }
                                    allow
                                };
                                if should_log {
                                    let last_short = last_header_hash
                                        .map(|h| {
                                            let hex = hex::encode(h);
                                            hex.get(0..12).unwrap_or(&hex).to_string()
                                        })
                                        .unwrap_or_else(|| "-".to_string());
                                    let msg = format!(
                                        "P2P {}: received {} headers (new={}) last={}",
                                        addr2, header_count, added_any, last_short
                                    );
                                    if header_count < 2000 {
                                        P2PNode::log_event("info", "sync", msg);
                                    }
                                }
                            }

                            if header_error {
                                let reason = reject_reason
                                    .clone()
                                    .unwrap_or_else(|| "unknown".to_string());
                                let streak = note_header_reject(addr2.ip(), &reason).await;
                                penalize_rejecting_header_peer(addr2.ip(), streak).await;
                                if streak >= 8 {
                                    P2PNode::log_event(
                                        "warn",
                                        "sync",
                                        format!("P2P {}: repeated rejected headers (reason={}, streak={}); lowering peer score", addr2, reason, streak),
                                    );
                                }
                                if let Some(prev_hash) = first_unknown_prev {
                                    if let Some(writer) = writer_weak.upgrade() {
                                        request_orphan_headers(
                                            &writer,
                                            addr2,
                                            prev_hash,
                                            &Some(chain_arc_for_tip.clone()),
                                            &sync_requests2,
                                            &peer_state2,
                                        )
                                        .await;
                                    }
                                }

                                if unknown_parent && !added_any {
                                    P2PNode::log_event(
                                        "warn",
                                        "sync",
                                        format!(
                                            "P2P {}: headers do not connect; ignoring peer height",
                                            addr2
                                        ),
                                    );
                                    let multiaddr =
                                        format!("/ip4/{}/tcp/{}", addr2.ip(), addr2.port());
                                    {
                                        let mut dir = directory2.lock().await;
                                        dir.clear_height(&multiaddr);
                                    }
                                    let mut state = peer_state2.lock().await;
                                    state.height = None;
                                    state.tip = None;
                                    state.last_bad_headers = Some(Instant::now());
                                }
                                if reset_headers {
                                    let get_headers = GetHeadersPayload {
                                        start_hash: vec![0u8; 32],
                                        count: MAX_HEADERS_PER_REQUEST,
                                    };
                                    if let Ok(msg) = get_headers.to_message() {
                                        if let Some(writer) = writer_weak.upgrade() {
                                            send_message_detached(&writer, msg, addr2);
                                        }
                                    }
                                    {
                                        let mut state = peer_state2.lock().await;
                                        state.last_headers_request = Some(Instant::now());
                                        state.last_headers_start = Some([0u8; 32]);
                                        state.headers_inflight = true;
                                    }
                                }
                                {
                                    let mut state = peer_state2.lock().await;
                                    state.last_headers_received = Some(Instant::now());
                                    state.headers_processing = false;
                                }
                                return;
                            }

                            let (local_height, best_header_height) = {
                                let guard =
                                    chain_arc_for_tip.lock().unwrap_or_else(|e| e.into_inner());
                                let local_h = guard.tip_height();
                                let best_hash = guard.best_header_hash();
                                let best_h = guard
                                    .headers
                                    .get(&best_hash)
                                    .map(|hw| hw.height)
                                    .or_else(|| guard.heights.get(&best_hash).copied())
                                    .unwrap_or(local_h);
                                (local_h, best_h)
                            };
                            let peer_height = {
                                let state = peer_state2.lock().await;
                                let advertised = state
                                    .height
                                    .unwrap_or(last_handshake_height.unwrap_or(local_height))
                                    .max(last_handshake_height.unwrap_or(local_height));
                                trusted_remote_height(advertised, best_header_height, local_height)
                            };
                            if header_count >= 2000 && best_header_height <= local_height {
                                peer_mark_header_event(addr2.ip(), false, 1).await;
                            }
                            {
                                let mut state = peer_state2.lock().await;
                                state.height = Some(peer_height);
                                state.last_bad_headers = None;
                            }
                            clear_header_reject_streak(addr2.ip()).await;
                            let multiaddr = format!("/ip4/{}/tcp/{}", addr2.ip(), addr2.port());
                            let mut dir = directory2.lock().await;
                            dir.record_height(&multiaddr, peer_height);

                            if header_count == 0 && peer_height > local_height {
                                if sync_request_allowed_for(
                                    &sync_requests2,
                                    addr2.ip(),
                                    local_height,
                                    peer_height,
                                )
                                .await
                                {
                                    let get_headers = GetHeadersPayload {
                                        start_hash: vec![0u8; 32],
                                        count: MAX_HEADERS_PER_REQUEST,
                                    };
                                    if let Ok(msg) = get_headers.to_message() {
                                        if let Some(writer) = writer_weak.upgrade() {
                                            send_message_detached(&writer, msg, addr2);
                                        }
                                    }
                                    let mut state = peer_state2.lock().await;
                                    state.last_headers_request = Some(Instant::now());
                                    state.last_headers_start = Some([0u8; 32]);
                                    state.headers_inflight = true;
                                }
                                {
                                    let mut state = peer_state2.lock().await;
                                    state.headers_processing = false;
                                }
                                return;
                            }

                            if header_count > 0 && added_any && peer_height > local_height {
                                if let Some(last_hash) = last_header_hash {
                                    let get_headers = GetHeadersPayload {
                                        start_hash: last_hash.to_vec(),
                                        count: MAX_HEADERS_PER_REQUEST,
                                    };
                                    if let Ok(msg) = get_headers.to_message() {
                                        if let Some(writer) = writer_weak.upgrade() {
                                            send_message_detached(&writer, msg, addr2);
                                        }
                                    }
                                    {
                                        let mut state = peer_state2.lock().await;
                                        state.last_headers_request = Some(Instant::now());
                                        state.last_headers_start = Some(last_hash);
                                        state.headers_inflight = true;
                                    }
                                }
                            }

                            let request = {
                                let guard =
                                    chain_arc_for_tip.lock().unwrap_or_else(|e| e.into_inner());
                                if let Some(best) = guard.best_header_if_better() {
                                    if let Some(path) =
                                        guard.header_path_to_known(best.header.hash_for_height(best.height))
                                    {
                                        if let Some(first_hash) = path.first() {
                                            let mut start_hash = guard
                                                .headers
                                                .get(first_hash)
                                                .map(|hw| hw.header.prev_hash)
                                                .unwrap_or([0u8; 32]);
                                            if start_hash != [0u8; 32]
                                                && !guard.heights.contains_key(&start_hash)
                                            {
                                                start_hash = rewinded_getblocks_request(
                                                    &guard,
                                                    peer_height,
                                                )
                                                .map(|(hash, _)| hash)
                                                .unwrap_or_else(|| {
                                                    let tip_h = guard.tip_height();
                                                    guard
                                                        .chain
                                                        .last()
                                                        .map(|b| b.header.hash_for_height(tip_h))
                                                        .unwrap_or([0u8; 32])
                                                });
                                            }
                                            let count = std::cmp::min(
                                                path.len(),
                                                MAX_BLOCKS_PER_REQUEST as usize,
                                            )
                                                as u32;
                                            if count > 0 {
                                                Some((start_hash, count))
                                            } else {
                                                None
                                            }
                                        } else {
                                            None
                                        }
                                    } else {
                                        rewinded_getblocks_request(&guard, peer_height)
                                            .or_else(|| {
                                                let tip_h = guard.tip_height();
                                                let start_hash = guard
                                                    .chain
                                                    .last()
                                                    .map(|b| b.header.hash_for_height(tip_h))
                                                    .unwrap_or([0u8; 32]);
                                                let count = std::cmp::min(
                                                    best.height.saturating_sub(tip_h) as usize,
                                                    MAX_BLOCKS_PER_REQUEST as usize,
                                                ) as u32;
                                                if count > 0 {
                                                    Some((start_hash, count))
                                                } else {
                                                    None
                                                }
                                            })
                                    }
                                } else if peer_height > guard.tip_height() {
                                    rewinded_getblocks_request(&guard, peer_height)
                                } else {
                                    None
                                }
                            };

                            if let Some((start_hash, count)) = request {
                                let (range_start, range_end, header_tip_short) = {
                                    let guard =
                                        chain_arc_for_tip.lock().unwrap_or_else(|e| e.into_inner());
                                    let start_h = if start_hash == [0u8; 32] {
                                        0
                                    } else {
                                        guard
                                            .heights
                                            .get(&start_hash)
                                            .copied()
                                            .unwrap_or(0)
                                            .saturating_add(1)
                                    };
                                    let end_h =
                                        start_h.saturating_add(count as u64).saturating_sub(1);
                                    let tip_hex = hex::encode(guard.best_header_hash());
                                    let tip_short =
                                        tip_hex.get(0..12).unwrap_or(&tip_hex).to_string();
                                    (start_h, end_h, tip_short)
                                };
                                P2PNode::log_event(
                                    "info",
                                    "sync",
                                    format!(
                                        "P2P {}: requesting {} blocks (range=[{}-{}], header_tip={})",
                                        addr2, count, range_start, range_end, header_tip_short
                                    ),
                                );
                                let get_blocks = GetBlocksPayload {
                                    start_hash: start_hash.to_vec(),
                                    count,
                                };
                                if sync_block_request_allowed_for(
                                    &block_requests2,
                                    addr2.ip(),
                                    local_height,
                                    peer_height,
                                    &start_hash,
                                    count,
                                )
                                .await
                                {
                                    if let Ok(msg) = get_blocks.to_message() {
                                        if let Some(writer) = writer_weak.upgrade() {
                                            send_message_detached(&writer, msg, addr2);
                                            record_block_request_sent(
                                                addr2.ip(),
                                                &start_hash,
                                                count,
                                            )
                                            .await;
                                        }
                                    }
                                }
                            } else if peer_height > local_height || header_count > 0 {
                                maybe_log_header_sync_state(
                                    addr2,
                                    &chain_arc_for_tip,
                                    &peer_state2,
                                    "no_best_header_block_path",
                                )
                                .await;
                            }

                            maybe_log_header_sync_state(
                                addr2,
                                &chain_arc_for_tip,
                                &peer_state2,
                                "",
                            )
                            .await;

                            {
                                let mut state = peer_state2.lock().await;
                                state.last_headers_received = Some(Instant::now());
                                state.headers_processing = false;
                            }
                        });
                    }
                }
            }
            MessageType::GetBlocks => {
                if let Ok(payload) = GetBlocksPayload::from_message(&msg) {
                    let writer_weak = Arc::downgrade(&writer);
                    let chain_for_task = chain.clone();
                    let addr2 = addr;
                    let getblocks_seen2 = getblocks_seen.clone();
                    let getblocks_last2 = getblocks_last.clone();
                    let getblocks_genesis2 = getblocks_genesis.clone();
                    let send_blocks_log2 = send_blocks_log.clone();

                    tokio::spawn(async move {
                        {
                            let mut guard = getblocks_seen2.lock().await;
                            guard.insert(addr2.ip(), Instant::now());
                        }

                        let Some(chain_arc) = chain_for_task else {
                            return;
                        };

                        if !getblocks_request_allowed(
                            &getblocks_last2,
                            addr2.ip(),
                            &payload.start_hash,
                            payload.count,
                        )
                        .await
                        {
                            return;
                        }

                        let is_zero = payload.start_hash.iter().all(|b| *b == 0);
                        let start_hash = payload.start_hash.clone();
                        let want = payload.count;

                        let (matched_pos, blocks, start_height) =
                            match spawn_blocking_limited(move || {
                                let guard = chain_arc.lock().unwrap_or_else(|e| e.into_inner());

                                let mut start_idx = 0usize;
                                let mut matched_pos = None;
                                if start_hash.len() == 32 {
                                    let mut target = [0u8; 32];
                                    target.copy_from_slice(&start_hash);
                                    if let Some((pos, _)) =
                                        guard.chain.iter().enumerate().find(|(idx, b)| b.header.hash_for_height(*idx as u64) == target)
                                    {
                                        start_idx = pos + 1;
                                        matched_pos = Some(pos);
                                    }
                                }

                                if matched_pos.is_none() && !is_zero {
                                    return (matched_pos, Vec::new(), 0u64);
                                }

                                let mut blocks = Vec::new();
                                let mut heights = Vec::new();
                                let count = want.min(MAX_BLOCKS_PER_REQUEST) as usize;
                                for (idx, b) in
                                    guard.chain.iter().enumerate().skip(start_idx).take(count)
                                {
                                    blocks.push(b.serialize_for_height(idx as u64));
                                    heights.push(idx as u64);
                                }
                                let start_h: u64 = heights.first().copied().unwrap_or(0);
                                (matched_pos, blocks, start_h)
                            })
                            .await
                            {
                                Ok(v) => v,
                                Err(_) => return,
                            };

                        let genesis_locator = is_zero || matches!(matched_pos, Some(0));
                        if genesis_locator
                            && !genesis_request_allowed(&getblocks_genesis2, addr2.ip()).await
                        {
                            return;
                        }

                        if matched_pos.is_none() && !is_zero {
                            P2PNode::log_event(
                                "warn",
                                "sync",
                                format!(
                                    "P2P {}: ignoring getblocks unknown start hash {}",
                                    addr2,
                                    hex::encode(&payload.start_hash)
                                ),
                            );
                            return;
                        }

                        if !blocks.is_empty() {
                            let end_h = start_height + blocks.len() as u64 - 1;
                            if ip_log_allowed(
                                &send_blocks_log2,
                                addr2.ip(),
                                Duration::from_secs(send_blocks_log_cooldown_secs()),
                            )
                            .await
                            {
                                P2PNode::log(format!(
                                    "P2P {}: sending {} blocks [{}-{}]",
                                    addr2,
                                    blocks.len(),
                                    start_height,
                                    end_h
                                ));
                            }
                        }

                        for block_data in blocks {
                            let Some(writer) = writer_weak.upgrade() else {
                                break;
                            };
                            let msg = BlockPayload { block_data }.to_message();
                            let _ = send_message(&writer, msg, addr2).await;
                        }
                    });
                }
            }

            MessageType::Block => {
                if let Some(ref chain_arc) = chain {
                    if let Ok(payload) = BlockPayload::from_message(&msg) {
                        let decode_started = Instant::now();
                        let addr2 = addr;
                        let chain_arc2 = chain_arc.clone();
                        let mempool2 = mempool.clone();
                        let directory2 = directory.clone();
                        let reputation2 = reputation.clone();

                        let permit = match inbound_bulk_queue().acquire_owned().await {
                            Ok(p) => p,
                            Err(_) => continue,
                        };

                        tokio::spawn(async move {
                            let permit_guard = permit;
                            let peer_block_lock = peer_block_lock(addr2.ip()).await;
                            let _peer_block_guard = peer_block_lock.lock_owned().await;

                            // Peek prev_hash → look up parent → derive
                            // block_height before height-aware deserialize.
                            let prev_peek = match crate::block::BlockHeader::peek_prev_hash(&payload.block_data) {
                                Ok(p) => p,
                                Err(e) => {
                                    P2PNode::log_event(
                                        "warn",
                                        "net",
                                        format!(
                                            "P2P {}: block payload too short to peek prev_hash: {}",
                                            addr2, e
                                        ),
                                    );
                                    let mut rep = reputation2.lock().await;
                                    rep.record_decode_error(&addr2.to_string());
                                    return;
                                }
                            };
                            let block_height = {
                                let guard = chain_arc2.lock().unwrap_or_else(|e| e.into_inner());
                                if prev_peek == [0u8; 32] {
                                    0
                                } else if let Some(h) = guard
                                    .heights
                                    .get(&prev_peek)
                                    .copied()
                                    .or_else(|| guard.headers.get(&prev_peek).map(|hw| hw.height))
                                {
                                    h + 1
                                } else {
                                    0
                                }
                            };
                            let block = match Block::deserialize_for_height(&payload.block_data, block_height) {
                                Ok((b, _)) => b,
                                Err(e) => {
                                    P2PNode::log_event(
                                        "warn",
                                        "net",
                                        format!(
                                            "P2P {}: failed to decode block payload: {}",
                                            addr2, e
                                        ),
                                    );
                                    let mut rep = reputation2.lock().await;
                                    rep.record_decode_error(&addr2.to_string());
                                    return;
                                }
                            };

                            let decode_ms = decode_started.elapsed().as_millis();
                            let precheck_started = Instant::now();
                            if let Err(e) = stateless_block_precheck(&block, block_height) {
                                P2PNode::log_event(
                                    "warn",
                                    "chain",
                                    format!("P2P {}: stateless precheck failed: {}", addr2, e),
                                );
                                return;
                            }
                            let precheck_ms = precheck_started.elapsed().as_millis();

                            let bhash = block.header.hash_for_height(block_height);
                            let short = hex::encode(bhash);
                            let short = short.get(0..12).unwrap_or(&short).to_string();

                            let connect_started = Instant::now();
                            let (new_height_opt, verdict, persist_blocks) =
                                match spawn_blocking_limited(move || {
                                    let mut guard =
                                        chain_arc2.lock().unwrap_or_else(|e| e.into_inner());
                                    let mut new_height_opt = None;
                                    let mut verdict = None;
                                    let mut persist_blocks = Vec::new();

                                    match guard.process_block(block.clone()) {
                                        Ok((new_height, _)) => {
                                            new_height_opt = Some(new_height);
                                            verdict = Some(true);
                                            // Mempool cleanup while the chain
                                            // lock is held: txid match first,
                                            // then drop double-spend conflicts.
                                            if let Some(ref mem) = mempool2 {
                                                let mut mem_guard = mem
                                                    .lock()
                                                    .unwrap_or_else(|e| e.into_inner());
                                                for tx in block.transactions.iter().skip(1) {
                                                    mem_guard.remove(&tx.txid());
                                                }
                                                evict_invalid_mempool_entries(
                                                    &guard,
                                                    &mut mem_guard,
                                                );
                                            }
                                            if guard.tip_hash() == bhash {
                                                let tip = guard.tip_height();
                                                persist_blocks.push((tip, block.clone()));
                                            }
                                        }
                                        Err(e) => {
                                            if P2PNode::is_soft_block_reject(&e) {
                                                if !P2PNode::is_duplicate_block(&e) {
                                                    P2PNode::log_event(
                                                        "info",
                                                        "chain",
                                                        format!(
                                                            "P2P {}: ignored block {} ({})",
                                                            addr2, short, e
                                                        ),
                                                    );
                                                }
                                            } else {
                                                verdict = Some(false);
                                                P2PNode::log_event(
                                                    "warn",
                                                    "chain",
                                                    format!(
                                                        "P2P {}: rejected block {}: {}",
                                                        addr2, short, e
                                                    ),
                                                );
                                            }
                                        }
                                    }

                                    (new_height_opt, verdict, persist_blocks)
                                })
                                .await
                                {
                                    Ok(v) => v,
                                    Err(_) => return,
                                };
                            drop(permit_guard);
                            let connect_ms = connect_started.elapsed().as_millis();

                            for (height, b) in persist_blocks {
                                let h = b.header.hash_for_height(height);
                                enqueue_persist_block(height, h, b.clone()).await;
                                // Mempool eviction has moved into the
                                // spawn_blocking_limited closure above so it
                                // can run with the chain lock held and also
                                // evict double-spend conflicts (not just txid
                                // matches).
                            }
                            sync_perf_record(decode_ms, precheck_ms, connect_ms, 0);

                            if let Some(new_height) = new_height_opt {
                                peer_mark_block_progress(addr2.ip()).await;
                                let multiaddr = format!("/ip4/{}/tcp/{}", addr2.ip(), addr2.port());
                                let mut dir = directory2.lock().await;
                                dir.record_height(&multiaddr, new_height.saturating_sub(1));
                            }

                            if let Some(ok) = verdict {
                                let mut rep = reputation2.lock().await;
                                rep.record_block(&addr2.to_string(), ok);
                            }
                        });
                    }
                }
            }
            MessageType::Tx => {
                if let Ok(payload) = TxPayload::from_message(&msg) {
                    match decode_full_tx(&payload.tx_data) {
                        Ok(tx) => {
                            if let (Some(ref chain_arc), Some(ref mem)) = (&chain, &mempool) {
                                let inv_bytes = {
                                    let (fee, priority) = {
                                        let guard =
                                            chain_arc.lock().unwrap_or_else(|e| e.into_inner());
                                        let fee = match guard.calculate_fees(&tx) {
                                            Ok(f) => f,
                                            Err(e) => {
                                                eprintln!("Rejecting tx from {}: {}", addr, e);
                                                continue;
                                            }
                                        };
                                        let priority = classify_tx_priority(&tx, &guard);
                                        (fee, priority)
                                    };
                                    let relay_addr = {
                                        let dir = directory.lock().await;
                                        dir.relay_address_for_peer(&addr)
                                    };
                                    let mut mem_guard =
                                        mem.lock().unwrap_or_else(|e| e.into_inner());
                                    let peer_addr = addr.to_string();
                                    match mem_guard.add_transaction_with_priority(
                                        tx.clone(),
                                        payload.tx_data.clone(),
                                        fee,
                                        priority,
                                        Some(addr.ip()),
                                    ) {
                                        Ok(outcome) => {
                                            mem_guard
                                                .record_relay(&outcome.txid, peer_addr.clone());
                                        }
                                        Err(_) => {
                                            mem_guard.record_relay(&tx.txid(), peer_addr);
                                        }
                                    }
                                    if let Some(relay_addr) = relay_addr {
                                        mem_guard.record_relay_address(&tx.txid(), relay_addr);
                                    }
                                    InvPayload {
                                        txids: vec![hex::encode(tx.txid())],
                                    }
                                    .to_message()
                                    .ok()
                                    .map(|m| m.serialize())
                                };

                                if let Some(inv_bytes) = inv_bytes {
                                    // Never hold the peers lock while awaiting I/O.
                                    let peers_snapshot = {
                                        let guard = peers.lock().await;
                                        guard.clone()
                                    };
                                    let mut dead: Vec<Arc<Mutex<OwnedWriteHalf>>> = Vec::new();
                                    for socket in peers_snapshot.iter() {
                                        let write_fut = async {
                                            let mut w = socket.lock().await;
                                            w.write_all(&inv_bytes).await
                                        };
                                        match tokio::time::timeout(
                                            Duration::from_secs(2),
                                            write_fut,
                                        )
                                        .await
                                        {
                                            Ok(Ok(())) => {}
                                            Ok(Err(_)) | Err(_) => {
                                                {
                                                    let mut w = socket.lock().await;
                                                    let _ = w.shutdown().await;
                                                }
                                                dead.push(socket.clone());
                                            }
                                        }
                                    }
                                    if !dead.is_empty() {
                                        let mut guard = peers.lock().await;
                                        guard.retain(|p| !dead.iter().any(|d| Arc::ptr_eq(p, d)));
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to decode tx from {}: {}", addr, e);
                        }
                    }
                }
            }
            MessageType::Inv => {
                if let Some(ref mem) = mempool {
                    if let Ok(inv) = InvPayload::from_message(&msg) {
                        let mut needed = Vec::new();
                        {
                            let guard = mem.lock().unwrap_or_else(|e| e.into_inner());
                            for txid_hex in inv.txids {
                                if let Ok(bytes) = hex::decode(&txid_hex) {
                                    if bytes.len() == 32 {
                                        let mut txid = [0u8; 32];
                                        txid.copy_from_slice(&bytes);
                                        if !guard.contains(&txid) {
                                            needed.push(txid_hex.clone());
                                        }
                                    }
                                }
                            }
                        }
                        if !needed.is_empty() {
                            let gd = GetDataPayload { txids: needed };
                            if let Ok(msg) = gd.to_message() {
                                send_message_detached(&writer, msg, addr);
                            }
                        }
                    }
                }
            }
            MessageType::GetData => {
                if let Some(ref mem) = mempool {
                    if let Ok(gd) = GetDataPayload::from_message(&msg) {
                        let mut responses: Vec<Message> = Vec::new();
                        {
                            let guard = mem.lock().unwrap_or_else(|e| e.into_inner());
                            for txid_hex in gd.txids {
                                if let Ok(bytes) = hex::decode(&txid_hex) {
                                    if bytes.len() != 32 {
                                        continue;
                                    }
                                    let mut txid = [0u8; 32];
                                    txid.copy_from_slice(&bytes);
                                    if let Some(raw) = guard.raw_tx(&txid) {
                                        responses.push(TxPayload { tx_data: raw }.to_message());
                                    }
                                }
                            }
                        }
                        for msg in responses {
                            send_message_detached(&writer, msg, addr);
                        }
                    }
                }
            }
            MessageType::Mempool => {
                if let Some(ref mem) = mempool {
                    let tx_hashes: Vec<String> = {
                        let guard = mem.lock().unwrap_or_else(|e| e.into_inner());
                        guard.txids_hex()
                    };
                    let payload = MempoolPayload { tx_hashes };
                    if let Ok(msg) = payload.to_message() {
                        send_message_detached(&writer, msg, addr);
                    }
                } else if let Ok(msg) = EmptyPayload::to_message(MessageType::Mempool) {
                    send_message_detached(&writer, msg, addr);
                }
            }
            MessageType::RelayAddress => {
                if let Some(ref mem) = mempool {
                    if let Ok(relay) = RelayAddressPayload::from_message(&msg) {
                        if relay.txid.len() == 64 {
                            if let Ok(bytes) = hex::decode(relay.txid) {
                                if bytes.len() == 32 {
                                    let mut txid = [0u8; 32];
                                    txid.copy_from_slice(&bytes);
                                    let mut guard = mem.lock().unwrap_or_else(|e| e.into_inner());
                                    guard.record_relay_address(&txid, relay.address);
                                }
                            }
                        } else if relay.txid.is_empty() {
                            // Peer is advertising a default relay address; update directory mapping.
                            let multiaddr = format!("/ip4/{}/tcp/{}", addr.ip(), addr.port());
                            let mut dir = directory.lock().await;
                            dir.register_connection(multiaddr, None, Some(relay.address), None);
                        }
                    }
                }
            }
            MessageType::ProofGossip => {
                if let Ok(pg) = crate::protocol::ProofGossipPayload::from_message(&msg) {
                    if let Ok(json) = String::from_utf8(pg.proof_json) {
                        let mut inbox = proof_gossip_inbox.lock().await;
                        inbox.push(json);
                    }
                }
            }
            MessageType::OfferTakeNotification => {
                if let Ok(otn) = crate::protocol::OfferTakeNotificationPayload::from_message(&msg) {
                    if let Ok(json) = String::from_utf8(otn.take_json) {
                        let mut inbox = offer_take_inbox.lock().await;
                        inbox.push(json);
                    }
                }
            }
            MessageType::OfferBroadcast => {
                if let Ok(ob) = crate::protocol::OfferBroadcastPayload::from_message(&msg) {
                    if let Some(json) = try_accept_offer_broadcast(
                        &ob.offer_json,
                        addr,
                        &seen_offer_ids,
                        &offer_rate_limit,
                    ).await {
                        {
                            let mut inbox = offer_broadcast_inbox.lock().await;
                            inbox.push(json.clone());
                        }
                        let payload = crate::protocol::OfferBroadcastPayload {
                            offer_json: json.into_bytes(),
                        };
                        let bytes = payload.to_message().serialize();
                        let _ = broadcast_raw(&peers, &bytes).await;
                    }
                }
            }
            MessageType::DisputeRaisedNotification => {
                if let Ok(p) = crate::protocol::DisputeRaisedNotificationPayload::from_message(&msg) {
                    if let Ok(json) = String::from_utf8(p.json) {
                        let mut inbox = dispute_raised_inbox.lock().await;
                        inbox.push(json);
                    }
                }
            }
            MessageType::DisputeEvidenceNotification => {
                if let Ok(p) = crate::protocol::DisputeEvidenceNotificationPayload::from_message(&msg) {
                    if let Ok(json) = String::from_utf8(p.json) {
                        let mut inbox = dispute_evidence_inbox.lock().await;
                        inbox.push(json);
                    }
                }
            }
            MessageType::DisputeResolvedNotification => {
                if let Ok(p) = crate::protocol::DisputeResolvedNotificationPayload::from_message(&msg) {
                    if let Ok(json) = String::from_utf8(p.json) {
                        let mut inbox = dispute_resolved_inbox.lock().await;
                        inbox.push(json);
                    }
                }
            }
            MessageType::DisputeEscalatedNotification => {
                if let Ok(p) = crate::protocol::DisputeEscalatedNotificationPayload::from_message(&msg) {
                    if let Ok(json) = String::from_utf8(p.json) {
                        let mut inbox = dispute_escalated_inbox.lock().await;
                        inbox.push(json);
                    }
                }
            }
            MessageType::Disconnect => break,
            _ => {
                // Unhandled message types can be ignored for now.
            }
        }
    }
    let _ = shutdown_tx_to_ping.send(());
    {
        let mut w = writer.lock().await;
        let _ = w.shutdown().await;
    }
    {
        let mut guard = peers.lock().await;
        guard.retain(|p| !Arc::ptr_eq(p, &writer));
    }
    {
        let mut guard = connected.lock().await;
        if guard.remove(&addr) {
            P2PNode::log(format!("P2P inbound {}: disconnected", addr));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        attach_orphan_header_chain, block_request_cache_key, classify_outbound_dial_failure,
        dialable_multiaddr_from_advertised, orphan_headers_map, recent_orphan_header_hashes,
        record_handshake_failure, store_orphan_header, take_orphan_header_children, P2PNode,
        RecentHashCache,
    };
    use crate::block::BlockHeader;
    use crate::chain::{block_from_locked, ChainParams, ChainState};
    use crate::genesis::load_locked_genesis;
    use crate::pow::meets_target;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex as StdMutex};
    use std::time::{Duration, Instant};
    use tokio::sync::Mutex;

    /// Serialise all tests that touch the global orphan-header statics so they
    /// cannot race with each other under `cargo test` parallel execution.
    fn orphan_test_lock() -> &'static StdMutex<()> {
        static LOCK: std::sync::OnceLock<StdMutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| StdMutex::new(()))
    }

    fn mine_header(mut header: BlockHeader) -> BlockHeader {
        for nonce in 0u32..u32::MAX {
            header.nonce = nonce;
            // Test helper: pre-fork convention (height=0) is fine for synthetic mining.
            let h = header.hash_for_height(0);
            if meets_target(&h, header.target()) {
                return header;
            }
        }
        panic!("failed to mine test header");
    }

    #[test]
    fn attaches_out_of_order_orphan_headers() {
        let _serial = orphan_test_lock().lock().unwrap_or_else(|e| e.into_inner());
        let locked = load_locked_genesis().expect("load locked genesis");
        let genesis = block_from_locked(&locked).expect("build genesis block");
        let pow_limit = crate::pow::Target { bits: 0x207fffff };
        let params = ChainParams {
            genesis_block: genesis,
            pow_limit,
            htlcv1_activation_height: None,
            mpsov1_activation_height: None,
            lwma: crate::chain::LwmaParams::new(None, pow_limit),
            lwma_v2: None,
            auxpow_activation_height: None,
            btc_spv: None,
            ltc_spv: None,
            htlc_btc_swap_v1_activation_height: None,
            btc_swap_bech32_payment_activation_height: None,
            htlc_ltc_swap_v1_activation_height: None,
            swap_order_v1_activation_height: None,
            ltc_swap_order_v1_activation_height: None,
            coinbase_header_batch_activation_height: None,
        };
        let mut chain = ChainState::new(params);

        {
            let mut guard = orphan_headers_map()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            guard.clear();
        }

        let tip = chain.tip_hash();
        let parent = mine_header(BlockHeader {
            version: 1,
            prev_hash: tip,
            merkle_root: [1u8; 32],
            time: 1_900_000_001,
            bits: 0x207fffff,
            nonce: 0,
        });
        let child = mine_header(BlockHeader {
            version: 1,
            prev_hash: parent.hash(),
            merkle_root: [2u8; 32],
            time: 1_900_000_002,
            bits: 0x207fffff,
            nonce: 0,
        });

        let (orphan_count, inserted) = store_orphan_header(child.clone());
        assert!(inserted);
        assert!(orphan_count >= 1);

        chain.add_header(parent.clone()).expect("add parent header");
        let (attached, err) = attach_orphan_header_chain(&mut chain, parent.hash());
        assert_eq!(err, None);
        assert_eq!(attached, 1);
        assert!(chain.headers.contains_key(&child.hash()));
        let path = chain
            .header_path_to_known(child.hash())
            .expect("path from known to child");
        assert_eq!(path, vec![parent.hash(), child.hash()]);
    }

    #[test]
    fn duplicate_orphan_headers_are_not_reinserted() {
        let _serial = orphan_test_lock().lock().unwrap_or_else(|e| e.into_inner());
        let locked = load_locked_genesis().expect("load locked genesis");
        let genesis = block_from_locked(&locked).expect("build genesis block");
        let pow_limit = crate::pow::Target { bits: 0x207fffff };
        let params = ChainParams {
            genesis_block: genesis,
            pow_limit,
            htlcv1_activation_height: None,
            mpsov1_activation_height: None,
            lwma: crate::chain::LwmaParams::new(None, pow_limit),
            lwma_v2: None,
            auxpow_activation_height: None,
            btc_spv: None,
            ltc_spv: None,
            htlc_btc_swap_v1_activation_height: None,
            btc_swap_bech32_payment_activation_height: None,
            htlc_ltc_swap_v1_activation_height: None,
            swap_order_v1_activation_height: None,
            ltc_swap_order_v1_activation_height: None,
            coinbase_header_batch_activation_height: None,
        };
        let chain = ChainState::new(params);

        {
            let mut guard = orphan_headers_map()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            guard.clear();
        }

        let tip = chain.tip_hash();
        let orphan = mine_header(BlockHeader {
            version: 1,
            prev_hash: tip,
            merkle_root: [9u8; 32],
            time: 1_900_000_010,
            bits: 0x207fffff,
            nonce: 0,
        });
        let (count1, inserted1) = store_orphan_header(orphan.clone());
        let (count2, inserted2) = store_orphan_header(orphan);

        assert!(inserted1);
        assert!(!inserted2);
        assert_eq!(count1, 1);
        assert_eq!(count2, 1);
    }

    #[test]
    fn orphan_reinsert_after_removal_is_suppressed_within_ttl() {
        let _serial = orphan_test_lock().lock().unwrap_or_else(|e| e.into_inner());
        let locked = load_locked_genesis().expect("load locked genesis");
        let genesis = block_from_locked(&locked).expect("build genesis block");
        let pow_limit = crate::pow::Target { bits: 0x207fffff };
        let params = ChainParams {
            genesis_block: genesis,
            pow_limit,
            htlcv1_activation_height: None,
            mpsov1_activation_height: None,
            lwma: crate::chain::LwmaParams::new(None, pow_limit),
            lwma_v2: None,
            auxpow_activation_height: None,
            btc_spv: None,
            ltc_spv: None,
            htlc_btc_swap_v1_activation_height: None,
            btc_swap_bech32_payment_activation_height: None,
            htlc_ltc_swap_v1_activation_height: None,
            swap_order_v1_activation_height: None,
            ltc_swap_order_v1_activation_height: None,
            coinbase_header_batch_activation_height: None,
        };
        let chain = ChainState::new(params);

        {
            let mut guard = orphan_headers_map()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            guard.clear();
        }
        {
            let mut recent = recent_orphan_header_hashes()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *recent = RecentHashCache::new(Duration::from_secs(600), 32);
        }

        let tip = chain.tip_hash();
        let orphan = mine_header(BlockHeader {
            version: 1,
            prev_hash: tip,
            merkle_root: [10u8; 32],
            time: 1_900_000_011,
            bits: 0x207fffff,
            nonce: 0,
        });

        let (count1, inserted1) = store_orphan_header(orphan.clone());
        let removed = take_orphan_header_children(tip);
        let (count2, inserted2) = store_orphan_header(orphan);

        assert!(inserted1);
        assert_eq!(removed.len(), 1);
        assert!(!inserted2);
        assert_eq!(count1, 1);
        assert_eq!(count2, 0);
    }

    #[test]
    fn recent_hash_cache_suppresses_duplicates_within_ttl() {
        let now = Instant::now();
        let mut cache = RecentHashCache::new(Duration::from_secs(30), 8);
        let hash = [1u8; 32];
        assert!(cache.record_at(hash, now));
        assert!(!cache.record_at(hash, now + Duration::from_secs(5)));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn recent_hash_cache_expires_after_ttl() {
        let now = Instant::now();
        let mut cache = RecentHashCache::new(Duration::from_secs(10), 8);
        let hash = [2u8; 32];
        assert!(cache.record_at(hash, now));
        assert!(cache.record_at(hash, now + Duration::from_secs(11)));
    }

    #[test]
    fn recent_hash_cache_stays_bounded() {
        let now = Instant::now();
        let mut cache = RecentHashCache::new(Duration::from_secs(60), 2);
        assert!(cache.record_at([1u8; 32], now));
        assert!(cache.record_at([2u8; 32], now + Duration::from_secs(1)));
        assert!(cache.record_at([3u8; 32], now + Duration::from_secs(2)));
        assert!(cache.len() <= 2);
    }

    #[test]
    fn block_request_cache_key_distinguishes_peers() {
        let start_hash = [9u8; 32];
        let a = block_request_cache_key(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), &start_hash, 128);
        let b = block_request_cache_key(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), &start_hash, 128);
        assert_ne!(a, b);
    }

    #[test]
    fn block_request_cache_key_distinguishes_windows() {
        let start_hash = [7u8; 32];
        let ip = IpAddr::V4(Ipv4Addr::new(10, 1, 1, 9));
        let a = block_request_cache_key(ip, &start_hash, 64);
        let b = block_request_cache_key(ip, &start_hash, 128);
        assert_ne!(a, b);
    }

    #[test]
    fn recent_hash_cache_allows_retry_for_different_block_request_key() {
        let now = Instant::now();
        let mut cache = RecentHashCache::new(Duration::from_secs(30), 8);
        let start_hash = [5u8; 32];
        let first =
            block_request_cache_key(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), &start_hash, 128);
        let retry_other_peer =
            block_request_cache_key(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), &start_hash, 128);
        assert!(cache.record_at(first, now));
        assert!(cache.record_at(retry_other_peer, now + Duration::from_secs(1)));
    }

    #[tokio::test]
    async fn small_network_temp_ban_is_less_aggressive() {
        let failures = Arc::new(Mutex::new(HashMap::new()));
        let bans = Arc::new(StdMutex::new(HashMap::new()));
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        for _ in 0..5 {
            let (_, banned) = record_handshake_failure(&failures, &bans, ip, false, 4).await;
            assert!(!banned);
        }
        for _ in 0..5 {
            let (_, banned) = record_handshake_failure(&failures, &bans, ip, false, 4).await;
            if banned {
                return;
            }
        }
        panic!("expected small-network temp ban after extended failures");
    }

    #[test]
    fn peer_telemetry_snapshot_keeps_backoff_history_after_expiry() {
        let rt = tokio::runtime::Runtime::new().expect("runtime");
        rt.block_on(async {
            let node = P2PNode::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 38291),
                "test-agent".to_string(),
                None,
                None,
                None,
                None,
                None,
            );
            let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
            {
                let mut guard = node.outbound_dial_backoff.lock().await;
                guard.insert(ip, (7, Instant::now() - Duration::from_secs(1)));
            }
            let snapshot = node.peer_telemetry_snapshot().await;
            assert_eq!(snapshot.attempted_peer_ips, 0);
            let guard = node.outbound_dial_backoff.lock().await;
            assert_eq!(guard.get(&ip).map(|(fails, _)| *fails), Some(7));
        });
    }

    #[test]
    fn outbound_failure_classifier_maps_common_reasons() {
        assert_eq!(
            classify_outbound_dial_failure("connect timeout after 8s"),
            "timeout"
        );
        assert_eq!(
            classify_outbound_dial_failure("Connection refused (os error 111)"),
            "refused"
        );
        assert_eq!(
            classify_outbound_dial_failure("No route to host (os error 113)"),
            "no_route"
        );
        assert_eq!(
            classify_outbound_dial_failure("peer 1.2.3.4 is banned"),
            "banned"
        );
    }

    #[test]
    fn dialable_multiaddr_from_advertised_accepts_public_ipv4() {
        assert_eq!(
            dialable_multiaddr_from_advertised("8.8.8.8:38291"),
            Some("/ip4/8.8.8.8/tcp/38291".to_string())
        );
        assert_eq!(
            dialable_multiaddr_from_advertised(" 1.1.1.1:1234 "),
            Some("/ip4/1.1.1.1/tcp/1234".to_string())
        );
    }

    #[test]
    fn dialable_multiaddr_from_advertised_rejects_unroutable() {
        // Loopback, private, link-local, broadcast.
        assert_eq!(dialable_multiaddr_from_advertised("127.0.0.1:38291"), None);
        assert_eq!(dialable_multiaddr_from_advertised("10.0.0.5:38291"), None);
        assert_eq!(dialable_multiaddr_from_advertised("172.16.5.1:38291"), None);
        assert_eq!(
            dialable_multiaddr_from_advertised("192.168.1.10:38291"),
            None
        );
        assert_eq!(
            dialable_multiaddr_from_advertised("169.254.10.1:38291"),
            None
        );
        assert_eq!(
            dialable_multiaddr_from_advertised("255.255.255.255:38291"),
            None
        );
        assert_eq!(dialable_multiaddr_from_advertised("0.0.0.0:38291"), None);
        // RFC5737 documentation ranges must also be rejected.
        assert_eq!(dialable_multiaddr_from_advertised("192.0.2.1:38291"), None);
        assert_eq!(
            dialable_multiaddr_from_advertised("198.51.100.7:1234"),
            None
        );
        assert_eq!(dialable_multiaddr_from_advertised("203.0.113.9:38291"), None);
    }

    #[test]
    fn dialable_multiaddr_from_advertised_rejects_cgnat() {
        // RFC6598 CGNAT band: 100.64.0.0/10 → first octet 100, second 64..=127.
        assert_eq!(dialable_multiaddr_from_advertised("100.64.0.1:38291"), None);
        assert_eq!(
            dialable_multiaddr_from_advertised("100.127.255.254:38291"),
            None
        );
        // Boundary just outside: 100.63 and 100.128 should be accepted.
        assert!(dialable_multiaddr_from_advertised("100.63.0.1:38291").is_some());
        assert!(dialable_multiaddr_from_advertised("100.128.0.1:38291").is_some());
    }

    #[test]
    fn dialable_multiaddr_from_advertised_rejects_malformed_and_ipv6() {
        assert_eq!(dialable_multiaddr_from_advertised(""), None);
        assert_eq!(dialable_multiaddr_from_advertised("not-an-addr"), None);
        assert_eq!(dialable_multiaddr_from_advertised("203.0.113.9"), None);
        assert_eq!(dialable_multiaddr_from_advertised("203.0.113.9:0"), None);
        // IPv6 currently unsupported by the directory's /ip4/ format.
        assert_eq!(
            dialable_multiaddr_from_advertised("[2001:db8::1]:38291"),
            None
        );
    }
}
