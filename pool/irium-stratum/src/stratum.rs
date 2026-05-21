use crate::block::{
    build_coinbase_tx, build_merkle_branches, coinbase_prefix_suffix, header_bytes,
    merkle_root_from_coinbase, parse_address_to_pkh, parse_hex32, parse_u32_hex,
};
use crate::pow::{hash_meets_target, sha256d, target_from_bits, target_from_difficulty_with_limit};
use crate::template::{GetBlockTemplate, TemplateClient};
use anyhow::{anyhow, Result};
use num_bigint::BigUint;
use serde_json::{json, Value};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, RwLock};
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, warn};
use dashmap::DashMap;
use once_cell::sync::Lazy;

#[derive(Clone, Debug)]
pub enum HashCmpMode {
    Be,
    Le,
}

impl HashCmpMode {
    pub fn from_env(value: Option<String>) -> Self {
        match value.unwrap_or_else(|| "le".to_string()).to_ascii_lowercase().as_str() {
            "be" => Self::Be,
            _ => Self::Le,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Be => "be",
            Self::Le => "le",
        }
    }
}

#[derive(Clone, Debug)]
pub enum MinerFamilyMode {
    Auto,
    Asic,
    Ccminer,
    Cpuminer,
}

impl MinerFamilyMode {
    pub fn from_env(value: Option<String>) -> Self {
        match value.unwrap_or_else(|| "auto".to_string()).to_ascii_lowercase().as_str() {
            "asic" => Self::Asic,
            "ccminer" => Self::Ccminer,
            "cpuminer" => Self::Cpuminer,
            _ => Self::Auto,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Asic => "asic",
            Self::Ccminer => "ccminer",
            Self::Cpuminer => "cpuminer",
        }
    }
}

#[derive(Clone, Debug)]
pub enum AdapterMode {
    Auto,
    CpuminerCompatOnly,
    NativeRewardableOnly,
}

impl AdapterMode {
    pub fn from_env(value: Option<String>) -> Self {
        match value.unwrap_or_else(|| "auto".to_string()).to_ascii_lowercase().as_str() {
            "cpuminer_compat_only" | "cpuminer_compat" | "compat" => Self::CpuminerCompatOnly,
            "native_rewardable_only" | "native_rewardable" | "native" => Self::NativeRewardableOnly,
            _ => Self::Auto,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::CpuminerCompatOnly => "cpuminer_compat_only",
            Self::NativeRewardableOnly => "native_rewardable_only",
        }
    }
}

#[derive(Clone)]
pub struct StratumConfig {
    pub bind: String,
    pub metrics_bind: Option<String>,
    pub default_diff: f64,
    pub extranonce1_size: usize,
    pub refresh_ms: u64,
    pub rpc_base: String,
    pub rpc_token: String,
    pub pow_limit: BigUint,
    pub hash_cmp_mode: HashCmpMode,
    pub soft_accept_invalid_shares: bool,
    pub miner_family_mode: MinerFamilyMode,
    pub adapter_mode: AdapterMode,
    pub native_rewardable_enabled: bool,
    pub sharecheck_samples: usize,
    pub vardiff_enabled: bool,
    pub vardiff_min_diff: f64,
    pub vardiff_max_diff: f64,
    pub vardiff_target_share_secs: u64,
    pub vardiff_retarget_secs: u64,
    pub max_template_age_seconds: u64,
    pub coinbase_bip34: bool,
    pub found_blocks_file: String,
    pub keepalive_notify_secs: u64,
    pub auxpow_activation_height: Option<u64>,
    // Connection gating knobs (v1.9.23). A global session cap protects the
    // pool from runaway TCP accumulation; a per-IP rate limiter throttles
    // bursts from a single host; repeat offenders are temporarily banned.
    // Sensible defaults are picked in main.rs from env vars.
    pub max_sessions: u64,
    pub max_conn_per_ip: u32,
    pub conn_window_secs: u64,
    pub ban_threshold: u32,
    pub ban_duration_secs: u64,
}

#[derive(Clone)]
struct Job {
    job_id: String,
    height: u64,
    prev_hash: [u8; 32],
    bits: u32,
    nbits_hex: String,
    ntime_hex: String,
    coinbase_value: u64,
    tx_hex: Vec<String>,
    branches: Vec<[u8; 32]>,
    template_target_hex: String,
}

#[derive(Clone)]
struct CanonicalJobSnapshot {
    job_id: String,
    template_fingerprint: String,
    height: u64,
    version: u32,
    prev_hash_internal: [u8; 32],
    bits: u32,
    block_target: BigUint,
    coinbase_value: u64,
    base_ntime: u32,
    extranonce1: Vec<u8>,
    extranonce2_size: usize,
    coinbase_prefix: Vec<u8>,
    coinbase_suffix: Vec<u8>,
    payout_script: Vec<u8>,
    tx_hex: Vec<String>,
    tx_hashes_internal: Vec<[u8; 32]>,
    branches: Vec<[u8; 32]>,
    tip_hash_at_job_create: [u8; 32],
    created_at_unix: u64,
    auxpow_mode: bool,
    irium_header80: Option<[u8; 80]>,
    irium_coinbase_hex: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum AdapterKind {
    LegacyRewardable,
    CpuminerCompatibility,
    NativeRewardableReserved,
}

impl AdapterKind {
    fn as_str(&self) -> &'static str {
        match self {
            Self::LegacyRewardable => "legacy_rewardable",
            Self::CpuminerCompatibility => "cpuminer_compat",
            Self::NativeRewardableReserved => "native_rewardable_reserved",
        }
    }
}

#[derive(Clone)]
struct CanonicalSolve {
    adapter_id: &'static str,
    rewardable: bool,
    share_variant: &'static str,
    extranonce2_hex: String,
    ntime_hex: String,
    nonce_hex: String,
    coinbase_hex: String,
    coinbase_hash_internal: [u8; 32],
    canonical_merkle_root: [u8; 32],
    canonical_header80: [u8; 80],
    canonical_hash: [u8; 32],
    share_hash: [u8; 32],
    share_target: BigUint,
    block_target: BigUint,
    share_ok: bool,
    share_block_like: bool,
    block_ok: bool,
}

#[derive(Clone)]
struct NativeIssuedJob {
    snapshot: CanonicalJobSnapshot,
    version_hex: String,
    prevhash_internal_hex: String,
    nbits_hex: String,
    ntime_hex: String,
    extranonce1_hex: String,
    extranonce2_size: usize,
    coinbase1_hex: String,
    coinbase2_hex: String,
    merkle_branches_internal_hex: Vec<String>,
    template_fingerprint: String,
    clean_jobs: bool,
}

#[derive(Clone)]
struct NativeSubmit {
    job_id: String,
    extranonce2_hex: String,
    ntime_hex: String,
    nonce_hex: String,
}

enum NodeSubmitResult {
    Accepted {
        canonical_block_hash: [u8; 32],
        accepted_height: u64,
    },
    Rejected {
        reason: String,
    },
}

#[derive(Clone)]
struct RoundEligibleRecord {
    height: u64,
    job_id: String,
    template_fingerprint: String,
    canonical_block_hash: [u8; 32],
    accepted_at_unix: u64,
}

#[derive(Clone)]
struct SubmitTuple {
    job_id: String,
    extranonce2_hex: String,
    ntime_hex: String,
    nonce_hex: String,
    // BIP310 version-rolling submitted as params[5] when the miner rolls
    // bits in the version field. Bitaxe ESP-Miner v2+ sends this even
    // after we reply with `version-rolling: false` to mining.configure, so
    // we accept it and use it as the actual header version on validation.
    rolled_version_hex: Option<String>,
}

trait RewardableAdapter {
    fn adapter_id(&self) -> &'static str;
    fn rewardable(&self) -> bool;
    fn decode_submit(
        &self,
        snapshot: &CanonicalJobSnapshot,
        session: &SessionState,
        config: &StratumConfig,
        submit: &SubmitTuple,
    ) -> Result<CanonicalSolve>;
}

struct CpuminerCompatibilityAdapter;

impl RewardableAdapter for CpuminerCompatibilityAdapter {
    fn adapter_id(&self) -> &'static str {
        "cpuminer_compat"
    }

    fn rewardable(&self) -> bool {
        false
    }

    fn decode_submit(
        &self,
        snapshot: &CanonicalJobSnapshot,
        session: &SessionState,
        config: &StratumConfig,
        submit: &SubmitTuple,
    ) -> Result<CanonicalSolve> {
        decode_cpuminer_compat_submit(snapshot, session, config, submit)
    }
}

struct NativeRewardableAdapter;

impl RewardableAdapter for NativeRewardableAdapter {
    fn adapter_id(&self) -> &'static str {
        "native_rewardable"
    }

    fn rewardable(&self) -> bool {
        true
    }

    fn decode_submit(
        &self,
        snapshot: &CanonicalJobSnapshot,
        _session: &SessionState,
        _config: &StratumConfig,
        submit: &SubmitTuple,
    ) -> Result<CanonicalSolve> {
        let native_submit = NativeSubmit {
            job_id: submit.job_id.clone(),
            extranonce2_hex: submit.extranonce2_hex.clone(),
            ntime_hex: submit.ntime_hex.clone(),
            nonce_hex: submit.nonce_hex.clone(),
        };
        decode_native_rewardable_submit(snapshot, &native_submit)
    }
}

#[derive(Clone)]
struct SessionState {
    extranonce1: Vec<u8>,
    worker: Option<String>,
    pkh: Option<[u8; 20]>,
    difficulty: f64,
    current_job: Option<Job>,
    current_snapshot: Option<CanonicalJobSnapshot>,
    last_share_ts: Option<u64>,
    last_retarget_ts: u64,
    coinbase_bip34: bool,
    adapter_kind: AdapterKind,
}

#[derive(Clone, Default)]
struct TemplateState {
    last_height: u64,
    last_prevhash: String,
    last_update_unix: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CompatEvent {
    ShareAccepted,
    CompatSolvedShare,
    CompatCandidateBlocked,
}

static ACTIVE_SESSIONS: AtomicU64 = AtomicU64::new(0);
static ACCEPTED_SHARES: AtomicU64 = AtomicU64::new(0);
static REJECTED_SHARES: AtomicU64 = AtomicU64::new(0);
static CANDIDATES_DETECTED: AtomicU64 = AtomicU64::new(0);
static CANDIDATES_SUBMITTED: AtomicU64 = AtomicU64::new(0);
static SUBMIT_ACCEPTED: AtomicU64 = AtomicU64::new(0);
static SUBMIT_REJECTED: AtomicU64 = AtomicU64::new(0);
static BLOCK_SUBMIT_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static REWARDABLE_SHARES_ACCEPTED: AtomicU64 = AtomicU64::new(0);
static ROUNDS_ELIGIBLE: AtomicU64 = AtomicU64::new(0);
static CHAIN_HEIGHT_ADVANCED_BY_POOL: AtomicU64 = AtomicU64::new(0);
static COMPAT_SOLVED_SHARES: AtomicU64 = AtomicU64::new(0);
static COMPAT_BLOCK_LIKE_SHARES: AtomicU64 = AtomicU64::new(0);
static COMPAT_NONREWARDABLE_EVENTS: AtomicU64 = AtomicU64::new(0);
static LAST_SHARE_ACCEPTED_AT: AtomicU64 = AtomicU64::new(0);
static LAST_SHARE_REJECTED_AT: AtomicU64 = AtomicU64::new(0);

// v1.9.23 — connection-gate counters. Surfaced on /metrics so operators
// can see how often the cap / rate-limit / ban-list fire and tune the
// env knobs accordingly.
static GATE_DROPPED_SESSION_CAP: AtomicU64 = AtomicU64::new(0);
static GATE_DROPPED_RATE_LIMIT: AtomicU64 = AtomicU64::new(0);
static GATE_DROPPED_BANNED: AtomicU64 = AtomicU64::new(0);
static GATE_BANS_ISSUED: AtomicU64 = AtomicU64::new(0);

/// Per-IP connection accounting used by the rate limiter. `count` is the
/// number of accept()s from this IP inside the current sliding window;
/// `rate_limit_hits` is how many times this IP has tripped the limit
/// (rolled into a temporary ban once it reaches `ban_threshold`).
#[derive(Clone)]
struct ConnRecord {
    window_start: Instant,
    count: u32,
    rate_limit_hits: u32,
}

/// Per-IP burst tracking. Keys are unbounded in theory (every random
/// scanner gets an entry); we GC stale entries inside `gate_connection`
/// when the window has rolled over, and a periodic janitor task
/// (`spawn_gate_janitor`) also sweeps after `ban_duration_secs * 2` so
/// memory can't grow without bound.
static CONN_RECORDS: Lazy<DashMap<IpAddr, ConnRecord>> = Lazy::new(DashMap::new);

/// Banned IPs and the Instant at which their ban expires.
static BAN_LIST: Lazy<DashMap<IpAddr, Instant>> = Lazy::new(DashMap::new);

/// Outcome of an accept-time policy check.
enum GateDecision {
    /// Allow the connection. Caller must spawn the handler.
    Allow,
    /// Drop the connection. The accept loop discards `stream` and continues.
    Drop(&'static str),
}

/// Apply the v1.9.23 connection gates in this order:
///   1. Banned IP → drop
///   2. Global session cap reached → drop
///   3. Per-IP rate limit (per `conn_window_secs` window) → drop, and
///      bump rate_limit_hits; if it crosses `ban_threshold`, ban the IP
///      for `ban_duration_secs`.
/// Disabling: passing `max_sessions=0` skips the cap; `max_conn_per_ip=0`
/// or `conn_window_secs=0` skips the per-IP limiter. Sensible production
/// defaults are wired in main.rs.
fn gate_connection(ip: IpAddr, cfg: &StratumConfig) -> GateDecision {
    // 1. Ban check (and lazy expiry of the entry).
    if let Some(entry) = BAN_LIST.get(&ip) {
        let expires_at = *entry.value();
        drop(entry);
        if Instant::now() < expires_at {
            GATE_DROPPED_BANNED.fetch_add(1, Ordering::SeqCst);
            return GateDecision::Drop("banned");
        }
        BAN_LIST.remove(&ip);
        // Also clear the per-IP record so the post-ban budget starts fresh.
        CONN_RECORDS.remove(&ip);
    }

    // 2. Global session cap.
    if cfg.max_sessions > 0
        && ACTIVE_SESSIONS.load(Ordering::SeqCst) >= cfg.max_sessions
    {
        GATE_DROPPED_SESSION_CAP.fetch_add(1, Ordering::SeqCst);
        return GateDecision::Drop("session_cap");
    }

    // 3. Per-IP rate limiter.
    if cfg.max_conn_per_ip > 0 && cfg.conn_window_secs > 0 {
        let now = Instant::now();
        let window = Duration::from_secs(cfg.conn_window_secs);
        let mut entry = CONN_RECORDS.entry(ip).or_insert(ConnRecord {
            window_start: now,
            count: 0,
            rate_limit_hits: 0,
        });
        if now.duration_since(entry.window_start) >= window {
            entry.window_start = now;
            entry.count = 0;
        }
        entry.count += 1;
        if entry.count > cfg.max_conn_per_ip {
            entry.rate_limit_hits += 1;
            GATE_DROPPED_RATE_LIMIT.fetch_add(1, Ordering::SeqCst);
            let hits = entry.rate_limit_hits;
            let threshold = cfg.ban_threshold;
            // Release the mutable lock before touching BAN_LIST to avoid
            // a deadlock when the same IP is being checked concurrently.
            drop(entry);
            if threshold > 0 && hits >= threshold {
                let expires_at = Instant::now()
                    + Duration::from_secs(cfg.ban_duration_secs);
                BAN_LIST.insert(ip, expires_at);
                GATE_BANS_ISSUED.fetch_add(1, Ordering::SeqCst);
                eprintln!("[stratum] Banned IP: {} (hits={})", ip, hits);
            }
            return GateDecision::Drop("rate_limit");
        }
    }

    GateDecision::Allow
}

/// Background sweeper that prevents the DashMaps from growing without
/// bound when a wide fleet of scanners rotates through random IPs. Runs
/// every `ban_duration_secs` (clamped to >= 60s) and removes:
///   - CONN_RECORDS entries whose `window_start` is older than 2 windows
///     (i.e., the host has been quiet for at least 2 * window seconds).
///   - BAN_LIST entries whose ban has already expired.
fn spawn_gate_janitor(cfg: StratumConfig) {
    let mut interval = cfg.ban_duration_secs.max(60);
    if cfg.conn_window_secs > 0 {
        interval = interval.min(cfg.conn_window_secs.max(60));
    }
    let interval = Duration::from_secs(interval);
    let window = Duration::from_secs(cfg.conn_window_secs.max(1));
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            let now = Instant::now();
            CONN_RECORDS.retain(|_, rec| {
                now.duration_since(rec.window_start) < window * 2
                    || rec.rate_limit_hits > 0
            });
            BAN_LIST.retain(|_, expires_at| now < *expires_at);
        }
    });
}

fn mark_accepted_share() {
    ACCEPTED_SHARES.fetch_add(1, Ordering::SeqCst);
    LAST_SHARE_ACCEPTED_AT.store(unix_now_secs(), Ordering::SeqCst);
}

fn mark_rejected_share() {
    REJECTED_SHARES.fetch_add(1, Ordering::SeqCst);
    LAST_SHARE_REJECTED_AT.store(unix_now_secs(), Ordering::SeqCst);
}

fn mark_candidate_detected() {
    CANDIDATES_DETECTED.fetch_add(1, Ordering::SeqCst);
}

fn mark_candidate_submitted() {
    CANDIDATES_SUBMITTED.fetch_add(1, Ordering::SeqCst);
}

fn mark_submit_accepted() {
    SUBMIT_ACCEPTED.fetch_add(1, Ordering::SeqCst);
}

fn mark_submit_rejected() {
    SUBMIT_REJECTED.fetch_add(1, Ordering::SeqCst);
}

fn mark_block_submit_attempt() {
    BLOCK_SUBMIT_ATTEMPTS.fetch_add(1, Ordering::SeqCst);
}

fn mark_rewardable_share_accepted() {
    REWARDABLE_SHARES_ACCEPTED.fetch_add(1, Ordering::SeqCst);
}

fn mark_round_eligible_counter() {
    ROUNDS_ELIGIBLE.fetch_add(1, Ordering::SeqCst);
}

fn mark_chain_height_advanced_by_pool() {
    CHAIN_HEIGHT_ADVANCED_BY_POOL.fetch_add(1, Ordering::SeqCst);
}

fn mark_compat_solved_share() {
    COMPAT_SOLVED_SHARES.fetch_add(1, Ordering::SeqCst);
}

fn mark_compat_block_like_share() {
    COMPAT_BLOCK_LIKE_SHARES.fetch_add(1, Ordering::SeqCst);
}

fn mark_compat_nonrewardable_event() {
    COMPAT_NONREWARDABLE_EVENTS.fetch_add(1, Ordering::SeqCst);
}

async fn metrics_loop(
    bind: String,
    template_state: Arc<RwLock<TemplateState>>,
    max_template_age_seconds: u64,
) -> Result<()> {
    let listener = TcpListener::bind(&bind).await?;
    info!("[metrics] listening on http://{bind}/metrics");

    loop {
        let (mut stream, addr) = listener.accept().await?;
        let template_state = Arc::clone(&template_state);
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let n = match stream.read(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    debug!("[metrics] read failed from {addr}: {e}");
                    return;
                }
            };
            if n == 0 {
                return;
            }
            let req = String::from_utf8_lossy(&buf[..n]);
            let first = req.lines().next().unwrap_or("");

            let (status, body) = if first.starts_with("GET /metrics") {
                (
                    "200 OK",
                    json!({
                        "active_tcp_sessions": ACTIVE_SESSIONS.load(Ordering::SeqCst),
                        "accepted_shares": ACCEPTED_SHARES.load(Ordering::SeqCst),
                        "rejected_shares": REJECTED_SHARES.load(Ordering::SeqCst),
                        "candidates_detected": CANDIDATES_DETECTED.load(Ordering::SeqCst),
                        "candidates_submitted": CANDIDATES_SUBMITTED.load(Ordering::SeqCst),
                        "submit_accepted": SUBMIT_ACCEPTED.load(Ordering::SeqCst),
                        "submit_rejected": SUBMIT_REJECTED.load(Ordering::SeqCst),
                        "block_submit_attempts": BLOCK_SUBMIT_ATTEMPTS.load(Ordering::SeqCst),
                        "rewardable_shares_accepted": REWARDABLE_SHARES_ACCEPTED.load(Ordering::SeqCst),
                        "rounds_eligible": ROUNDS_ELIGIBLE.load(Ordering::SeqCst),
                        "chain_height_advanced_by_pool": CHAIN_HEIGHT_ADVANCED_BY_POOL.load(Ordering::SeqCst),
                        "compat_solved_shares": COMPAT_SOLVED_SHARES.load(Ordering::SeqCst),
                        "compat_block_like_shares": COMPAT_BLOCK_LIKE_SHARES.load(Ordering::SeqCst),
                        "compat_nonrewardable_events": COMPAT_NONREWARDABLE_EVENTS.load(Ordering::SeqCst),
                        "last_share_accepted_at": LAST_SHARE_ACCEPTED_AT.load(Ordering::SeqCst),
                        "last_share_rejected_at": LAST_SHARE_REJECTED_AT.load(Ordering::SeqCst),
                        // v1.9.23 connection-gate observability.
                        "gate_dropped_session_cap": GATE_DROPPED_SESSION_CAP.load(Ordering::SeqCst),
                        "gate_dropped_rate_limit": GATE_DROPPED_RATE_LIMIT.load(Ordering::SeqCst),
                        "gate_dropped_banned": GATE_DROPPED_BANNED.load(Ordering::SeqCst),
                        "gate_bans_issued": GATE_BANS_ISSUED.load(Ordering::SeqCst),
                        "gate_active_bans": BAN_LIST.len() as u64,
                        "gate_tracked_ips": CONN_RECORDS.len() as u64
                    })
                    .to_string(),
                )
            } else if first.starts_with("GET /health") {
                let now = unix_now_secs();
                let st = template_state.read().await;
                let age = now.saturating_sub(st.last_update_unix);
                let stale = st.last_update_unix == 0 || age > max_template_age_seconds;
                if stale {
                    error!(
                        "[health] template stale height={} age_seconds={} max_age_seconds={} prev={}",
                        st.last_height, age, max_template_age_seconds, st.last_prevhash
                    );
                }
                (
                    "200 OK",
                    json!({
                        "status": if stale { "stale" } else { "ok" },
                        "height": st.last_height,
                        "age_seconds": age,
                        "prevhash": st.last_prevhash,
                    })
                    .to_string(),
                )
            } else {
                ("404 Not Found", "{\"error\":\"not_found\"}".to_string())
            };

            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes()).await;
        });
    }
}

#[derive(serde::Serialize)]
struct SubmitHeader {
    version: u32,
    prev_hash: String,
    merkle_root: String,
    time: u32,
    bits: String,
    nonce: u32,
    hash: String,
}

#[derive(serde::Serialize)]
struct SubmitRequest {
    height: u64,
    header: SubmitHeader,
    tx_hex: Vec<String>,
    submit_source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    auxpow_hex: Option<String>,
}

#[derive(serde::Serialize)]
struct FoundBlockRecord {
    height: u64,
    hash: String,
    time: u64,
    worker: String,
    address: String,
}

fn worker_address(worker: &str) -> String {
    worker.split('.').next().unwrap_or(worker).to_string()
}

fn append_found_block(path: &str, row: &FoundBlockRecord) -> Result<()> {
    let p = Path::new(path);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = OpenOptions::new().create(true).append(true).open(p)?;
    let line = serde_json::to_string(row)?;
    writeln!(f, "{}", line)?;
    Ok(())
}

pub async fn run(config: StratumConfig) -> Result<()> {
    let listener = TcpListener::bind(&config.bind).await?;
    info!(
        "[stratum] listening on {} hash_cmp_mode={} miner_family_mode={} adapter_kind={} sharecheck_samples={} vardiff={} min={} max={} target_s={} retarget_s={} coinbase_bip34={}",
        config.bind,
        config.hash_cmp_mode.as_str(),
        config.miner_family_mode.as_str(),
        select_adapter_kind(&config).as_str(),
        config.sharecheck_samples,
        config.vardiff_enabled,
        config.vardiff_min_diff,
        config.vardiff_max_diff,
        config.vardiff_target_share_secs,
        config.vardiff_retarget_secs,
        config.coinbase_bip34,
    );

    let (tx, _) = broadcast::channel::<Job>(256);
    let current = Arc::new(RwLock::new(None::<Job>));
    let template_state = Arc::new(RwLock::new(TemplateState::default()));

    if let Some(bind) = config.metrics_bind.clone() {
        let health_state = Arc::clone(&template_state);
        let max_age = config.max_template_age_seconds;
        tokio::spawn(async move {
            if let Err(e) = metrics_loop(bind, health_state, max_age).await {
                error!("[metrics] loop stopped: {e}");
            }
        });
    }

    let cfg_clone = config.clone();
    let tx_clone = tx.clone();
    let current_clone = Arc::clone(&current);
    let template_state_clone = Arc::clone(&template_state);
    tokio::spawn(async move {
        if let Err(e) = template_loop(cfg_clone, tx_clone, current_clone, template_state_clone).await {
            error!("[tmpl] loop stopped: {e}");
        }
    });

    // v1.9.23 — start the periodic GC for CONN_RECORDS / BAN_LIST so the
    // maps don't grow without bound under sustained scanner pressure.
    spawn_gate_janitor(config.clone());

    let conn_id = Arc::new(AtomicU64::new(1));
    loop {
        let (stream, addr) = listener.accept().await?;
        // Apply v1.9.23 connection gates before spending any further work
        // on this socket. The stream goes out of scope on Drop here which
        // closes the connection; we deliberately don't send any goodbye
        // payload so scanners get nothing to fingerprint on.
        match gate_connection(addr.ip(), &config) {
            GateDecision::Allow => {}
            GateDecision::Drop(reason) => {
                debug!("[conn] dropped from {} reason={}", addr, reason);
                drop(stream);
                continue;
            }
        }
        let id = conn_id.fetch_add(1, Ordering::SeqCst);
        info!("[conn] accepted id={} from {}", id, addr);

        let mut rx = tx.subscribe();
        let current = Arc::clone(&current);
        let cfg = config.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(id, stream, cfg, &mut rx, current).await {
                warn!("[conn] id={} ended: {}", id, e);
            }
        });
    }
}

fn select_adapter_kind(config: &StratumConfig) -> AdapterKind {
    match config.adapter_mode {
        AdapterMode::CpuminerCompatOnly => AdapterKind::CpuminerCompatibility,
        AdapterMode::NativeRewardableOnly => {
            if config.native_rewardable_enabled {
                AdapterKind::NativeRewardableReserved
            } else {
                AdapterKind::CpuminerCompatibility
            }
        }
        AdapterMode::Auto => match config.miner_family_mode {
            MinerFamilyMode::Cpuminer => AdapterKind::CpuminerCompatibility,
            _ if config.native_rewardable_enabled => AdapterKind::NativeRewardableReserved,
            _ => AdapterKind::LegacyRewardable,
        },
    }
}

fn payout_script_from_pkh(pkh: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(25);
    script.push(0x76);
    script.push(0xa9);
    script.push(0x14);
    script.extend_from_slice(pkh);
    script.push(0x88);
    script.push(0xac);
    script
}

fn template_fingerprint(job: &Job) -> String {
    let mut data = Vec::new();
    data.extend_from_slice(job.job_id.as_bytes());
    data.extend_from_slice(&job.height.to_le_bytes());
    data.extend_from_slice(&job.prev_hash);
    data.extend_from_slice(&job.bits.to_le_bytes());
    data.extend_from_slice(job.ntime_hex.as_bytes());
    data.extend_from_slice(&job.coinbase_value.to_le_bytes());
    for tx in &job.tx_hex {
        data.extend_from_slice(tx.as_bytes());
    }
    hex::encode(sha256d(&data))
}


/// Build a 80-byte Irium block header for AuxPoW.
/// version = 1 | AUXPOW_VERSION_BIT (=257), nonce = 0.
/// prev_hash and merkle_root are stored reversed (Bitcoin wire convention),
/// matching BlockHeader::serialize() so sha256d produces the correct aux_hash.
fn build_irium_auxpow_header(
    prev_hash_internal: [u8; 32],
    merkle_root_natural: [u8; 32],
    ntime: u32,
    bits: u32,
) -> [u8; 80] {
    const AUXPOW_VERSION: u32 = 1 | (1 << 8);
    let mut h = [0u8; 80];
    h[0..4].copy_from_slice(&AUXPOW_VERSION.to_le_bytes());
    let mut prev_rev = prev_hash_internal;
    prev_rev.reverse();
    h[4..36].copy_from_slice(&prev_rev);
    let mut mr_rev = merkle_root_natural;
    mr_rev.reverse();
    h[36..68].copy_from_slice(&mr_rev);
    h[68..72].copy_from_slice(&ntime.to_le_bytes());
    h[72..76].copy_from_slice(&bits.to_le_bytes());
    // nonce = 0: miners solve the parent block, not Irium
    h
}

/// Build the AuxPoW parent coinbase prefix and suffix.
/// The Namecoin commitment (MAGIC + aux_hash + chain_count + nonce) is embedded
/// in the script_sig AFTER the extranonce split point so miners cannot alter it.
fn build_auxpow_parent_coinbase_prefix_suffix(
    height: u64,
    reward: u64,
    pkh: &[u8; 20],
    aux_hash: &[u8; 32],
    bip34_height: bool,
) -> (Vec<u8>, Vec<u8>) {
    let marker: [u8; 8] = [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x00, 0x01];

    let mut script_sig = if bip34_height {
        let mut s = encode_bip34_height_local(height);
        s.extend_from_slice(b"Irium");
        s
    } else {
        format!("Irium {height}").into_bytes()
    };
    // extranonce1(4)+extranonce2(4) placeholder
    script_sig.extend_from_slice(&marker);
    // commitment: MAGIC(4) + aux_hash(32) + chain_count=1(4 LE) + nonce=0(4 LE)
    script_sig.extend_from_slice(&[0xfa, 0xbe, 0x6d, 0x6d]);
    script_sig.extend_from_slice(aux_hash);
    script_sig.extend_from_slice(&1u32.to_le_bytes());
    script_sig.extend_from_slice(&0u32.to_le_bytes());

    let spk = payout_script_from_pkh(pkh);
    let mut tx = Vec::with_capacity(256);
    tx.extend_from_slice(&1u32.to_le_bytes()); // version
    tx.push(1u8); // input count
    tx.extend_from_slice(&[0u8; 32]); // coinbase prevout hash
    tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // prevout index
    encode_varint(script_sig.len(), &mut tx);
    tx.extend_from_slice(&script_sig);
    tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // sequence
    tx.push(1u8); // output count
    tx.extend_from_slice(&reward.to_le_bytes());
    encode_varint(spk.len(), &mut tx);
    tx.extend_from_slice(&spk);
    tx.extend_from_slice(&0u32.to_le_bytes()); // locktime

    let pos = tx.windows(marker.len()).position(|w| w == &marker).unwrap_or(tx.len());
    (tx[..pos].to_vec(), tx[pos + marker.len()..].to_vec())
}

/// Serialize an AuxPoW proof to hex for submission to iriumd.
/// The parent coinbase is the only transaction; branches are empty (single-chain, coinbase-only parent block).
/// Parent header uses NATURAL ORDER for merkle_root so iriumd validate can check:
///   sha256d(coinbase_txn) == parent_header[36..68]
fn build_auxpow_hex_from_solution(
    parent_coinbase_bytes: &[u8],
    ntime: u32,
    bits: u32,
    nonce: u32,
) -> String {
    let parent_coinbase_hash = sha256d(parent_coinbase_bytes);
    // Build parent header with natural-order merkle root (as header_bytes does: no reversal)
    let parent_header = header_bytes(
        1,
        [0u8; 32],
        parent_coinbase_hash,
        ntime,
        bits,
        nonce,
    );
    let parent_hash_natural = sha256d(&parent_header);

    let mut out = Vec::new();
    // coinbase_txn: varint length + bytes
    encode_varint(parent_coinbase_bytes.len(), &mut out);
    out.extend_from_slice(parent_coinbase_bytes);
    // parent_hash (32 bytes, natural order)
    out.extend_from_slice(&parent_hash_natural);
    // coinbase_branch: count=0, index=0
    out.push(0u8);
    out.extend_from_slice(&0u32.to_le_bytes());
    // blockchain_branch: count=0, index=0
    out.push(0u8);
    out.extend_from_slice(&0u32.to_le_bytes());
    // parent_header (80 bytes)
    out.extend_from_slice(&parent_header);
    hex::encode(out)
}

fn build_canonical_job_snapshot(job: &Job, session: &SessionState, config: &StratumConfig) -> Result<CanonicalJobSnapshot> {
    let pkh = session.pkh.ok_or_else(|| anyhow!("unauthorized"))?;
    let ntime = parse_u32_hex(&job.ntime_hex)?;

    let auxpow_active = config.auxpow_activation_height
        .map(|h| job.height >= h)
        .unwrap_or(false);

    let (coinbase_prefix, coinbase_suffix, prev_hash_internal, branches, auxpow_mode, irium_header80, irium_coinbase_hex) =
        if auxpow_active {
            // AuxPoW: build fixed Irium coinbase, compute Irium block hash, build parent coinbase
            let irium_coinbase = build_coinbase_tx(job.height, job.coinbase_value, &pkh, &[], session.coinbase_bip34);
            let irium_coinbase_hash = sha256d(&irium_coinbase);
            let irium_merkle_root = merkle_root_from_coinbase(irium_coinbase_hash, &job.branches);
            let irium_h80 = build_irium_auxpow_header(job.prev_hash, irium_merkle_root, ntime, job.bits);
            let aux_hash = sha256d(&irium_h80);
            let (pp, ps) = build_auxpow_parent_coinbase_prefix_suffix(
                job.height, job.coinbase_value, &pkh, &aux_hash, session.coinbase_bip34,
            );
            (pp, ps, [0u8; 32], vec![], true, Some(irium_h80), Some(hex::encode(&irium_coinbase)))
        } else {
            let (cp, cs) = coinbase_prefix_suffix(job.height, job.coinbase_value, &pkh, session.coinbase_bip34);
            (cp, cs, job.prev_hash, job.branches.clone(), false, None, None)
        };

    let mut tx_hashes_internal = Vec::with_capacity(job.tx_hex.len());
    for tx in &job.tx_hex {
        let raw = hex::decode(tx).map_err(|e| anyhow!("template tx decode: {e}"))?;
        tx_hashes_internal.push(sha256d(&raw));
    }

    Ok(CanonicalJobSnapshot {
        job_id: job.job_id.clone(),
        template_fingerprint: template_fingerprint(job),
        height: job.height,
        version: 1,
        prev_hash_internal,
        bits: job.bits,
        block_target: target_from_bits(job.bits),
        coinbase_value: job.coinbase_value,
        base_ntime: ntime,
        extranonce1: session.extranonce1.clone(),
        extranonce2_size: 4,
        coinbase_prefix,
        coinbase_suffix,
        payout_script: payout_script_from_pkh(&pkh),
        tx_hex: job.tx_hex.clone(),
        tx_hashes_internal,
        branches,
        tip_hash_at_job_create: job.prev_hash,
        created_at_unix: unix_now_secs(),
        auxpow_mode,
        irium_header80,
        irium_coinbase_hex,
    })
}

fn reconstruct_coinbase(snapshot: &CanonicalJobSnapshot, extranonce2: &[u8]) -> Vec<u8> {
    let mut cb = Vec::with_capacity(
        snapshot.coinbase_prefix.len()
            + snapshot.extranonce1.len()
            + extranonce2.len()
            + snapshot.coinbase_suffix.len(),
    );
    cb.extend_from_slice(&snapshot.coinbase_prefix);
    cb.extend_from_slice(&snapshot.extranonce1);
    cb.extend_from_slice(extranonce2);
    cb.extend_from_slice(&snapshot.coinbase_suffix);
    cb
}

fn encode_bip34_height_local(height: u64) -> Vec<u8> {
    let mut n = height;
    let mut raw = Vec::new();
    while n > 0 {
        raw.push((n & 0xff) as u8);
        n >>= 8;
    }
    if raw.is_empty() {
        raw.push(0);
    }
    if raw.last().copied().unwrap_or(0) & 0x80 != 0 {
        raw.push(0);
    }
    let mut out = Vec::with_capacity(raw.len() + 1);
    out.push(raw.len() as u8);
    out.extend_from_slice(&raw);
    out
}

fn build_native_coinbase_script_sig(
    height: u64,
    extranonce: &[u8],
    bip34_height: bool,
) -> Vec<u8> {
    let mut script_sig = if bip34_height {
        let mut s = encode_bip34_height_local(height);
        s.extend_from_slice(b"Irium");
        s
    } else {
        format!("Irium {height}").into_bytes()
    };
    script_sig.extend_from_slice(extranonce);
    script_sig
}

fn build_native_rewardable_coinbase(
    snapshot: &CanonicalJobSnapshot,
    extranonce2: &[u8],
) -> Result<Vec<u8>> {
    if extranonce2.len() != snapshot.extranonce2_size {
        return Err(anyhow!(
            "invalid extranonce2 size: expected {} got {}",
            snapshot.extranonce2_size,
            extranonce2.len()
        ));
    }

    let mut extranonce = snapshot.extranonce1.clone();
    extranonce.extend_from_slice(extranonce2);
    let script_sig = build_native_coinbase_script_sig(snapshot.height, &extranonce, true);

    let mut tx = Vec::new();
    tx.extend_from_slice(&1u32.to_le_bytes());
    tx.push(1); // inputs
    tx.push(32);
    tx.extend_from_slice(&[0u8; 32]);
    tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    tx.push(script_sig.len() as u8);
    tx.extend_from_slice(&script_sig);
    tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    tx.push(1); // outputs
    tx.extend_from_slice(&snapshot.coinbase_value.to_le_bytes());
    tx.push(snapshot.payout_script.len() as u8);
    tx.extend_from_slice(&snapshot.payout_script);
    tx.extend_from_slice(&0u32.to_le_bytes());
    Ok(tx)
}

fn reconstruct_canonical_coinbase(
    snapshot: &CanonicalJobSnapshot,
    extranonce2: &[u8],
) -> Result<Vec<u8>> {
    build_native_rewardable_coinbase(snapshot, extranonce2)
}

fn reconstruct_canonical_merkle_root(
    snapshot: &CanonicalJobSnapshot,
    coinbase_hash_internal: [u8; 32],
) -> [u8; 32] {
    merkle_root_from_coinbase(coinbase_hash_internal, &snapshot.branches)
}

fn reconstruct_canonical_header80(
    snapshot: &CanonicalJobSnapshot,
    merkle_root_internal: [u8; 32],
    ntime: u32,
    nonce: u32,
) -> [u8; 80] {
    let mut header = [0u8; 80];
    header[0..4].copy_from_slice(&snapshot.version.to_le_bytes());

    let mut prev_wire = snapshot.prev_hash_internal;
    prev_wire.reverse();
    header[4..36].copy_from_slice(&prev_wire);

    let mut merkle_wire = merkle_root_internal;
    merkle_wire.reverse();
    header[36..68].copy_from_slice(&merkle_wire);

    header[68..72].copy_from_slice(&ntime.to_le_bytes());
    header[72..76].copy_from_slice(&snapshot.bits.to_le_bytes());
    header[76..80].copy_from_slice(&nonce.to_le_bytes());
    header
}

fn build_native_rewardable_job(
    snapshot: &CanonicalJobSnapshot,
    _session: &SessionState,
    _config: &StratumConfig,
) -> Result<NativeIssuedJob> {
    let marker_extranonce2 = [0x1c, 0xab, 0xad, 0x1d];
    let full = build_native_rewardable_coinbase(snapshot, &marker_extranonce2)?;
    let mut marker = snapshot.extranonce1.clone();
    marker.extend_from_slice(&marker_extranonce2);
    let pos = full
        .windows(marker.len())
        .position(|w| w == marker.as_slice())
        .ok_or_else(|| anyhow!("native extranonce marker missing"))?;
    Ok(NativeIssuedJob {
        snapshot: snapshot.clone(),
        version_hex: format!("{:08x}", snapshot.version),
        prevhash_internal_hex: hex::encode(snapshot.prev_hash_internal),
        nbits_hex: format!("{:08x}", snapshot.bits),
        ntime_hex: format!("{:08x}", snapshot.base_ntime),
        extranonce1_hex: hex::encode(&snapshot.extranonce1),
        extranonce2_size: snapshot.extranonce2_size,
        coinbase1_hex: hex::encode(&full[..pos + snapshot.extranonce1.len()]),
        coinbase2_hex: hex::encode(&full[pos + marker.len()..]),
        merkle_branches_internal_hex: snapshot.branches.iter().map(hex::encode).collect(),
        template_fingerprint: snapshot.template_fingerprint.clone(),
        clean_jobs: true,
    })
}

async fn template_loop(
    config: StratumConfig,
    tx: broadcast::Sender<Job>,
    current: Arc<RwLock<Option<Job>>>,
    template_state: Arc<RwLock<TemplateState>>,
) -> Result<()> {
    let client = TemplateClient::new(config.rpc_base.clone(), config.rpc_token.clone())?;
    let mut last_key = String::new();
    let mut seq: u64 = 1;

    loop {
        match client.fetch_template().await {
            Ok(tpl) => {
                let job = to_job(seq, &tpl)?;
                let prevhash = hex::encode(job.prev_hash);
                let now_ts = unix_now_secs();
                {
                    let mut st = template_state.write().await;
                    st.last_height = job.height;
                    st.last_prevhash = prevhash.clone();
                    st.last_update_unix = now_ts;
                }
                info!("[tmpl] height={} prev={} ts={}", job.height, prevhash, now_ts);

                let key = format!("{}:{}", job.height, prevhash);
                if key != last_key {
                    last_key = key;
                    seq = seq.wrapping_add(1);
                    {
                        let mut w = current.write().await;
                        *w = Some(job.clone());
                    }
                    let _ = tx.send(job.clone());
                    info!(
                        "[job] id={} height={} block_target={} bits={} prev={}",
                        job.job_id,
                        job.height,
                        biguint_to_32hex(&target_from_bits(job.bits)),
                        job.nbits_hex,
                        hex::encode(job.prev_hash)
                    );
                    info!(
                        "[tmpl] new job id={} height={} txs={} target={}",
                        job.job_id,
                        job.height,
                        job.tx_hex.len(),
                        job.template_target_hex
                    );
                }
            }
            Err(e) => warn!("[tmpl] fetch failed: {e}"),
        }
        sleep(Duration::from_millis(config.refresh_ms)).await;
    }
}

fn to_job(seq: u64, tpl: &GetBlockTemplate) -> Result<Job> {
    let prev_hash = parse_hex32(&tpl.prev_hash)?;
    let bits = parse_u32_hex(&tpl.bits)?;
    let ntime_hex = format!("{:08x}", tpl.time);
    let tx_hex: Vec<String> = tpl.txs.iter().map(|t| t.hex.clone()).collect();
    let branches = build_merkle_branches(&tx_hex)?;

    Ok(Job {
        job_id: format!("{seq:016x}"),
        height: tpl.height,
        prev_hash,
        bits,
        nbits_hex: tpl.bits.clone(),
        ntime_hex,
        coinbase_value: tpl.coinbase_value,
        tx_hex,
        branches,
        template_target_hex: tpl.target.clone(),
    })
}

struct ActiveSessionGuard;

impl ActiveSessionGuard {
    fn new() -> Self {
        ACTIVE_SESSIONS.fetch_add(1, Ordering::SeqCst);
        Self
    }
}

impl Drop for ActiveSessionGuard {
    fn drop(&mut self) {
        ACTIVE_SESSIONS.fetch_sub(1, Ordering::SeqCst);
    }
}

async fn handle_conn(
    id: u64,
    stream: TcpStream,
    config: StratumConfig,
    rx: &mut broadcast::Receiver<Job>,
    current: Arc<RwLock<Option<Job>>>,
) -> Result<()> {
    let _session_guard = ActiveSessionGuard::new();

    let extranonce1 = id.to_be_bytes()[8 - config.extranonce1_size..].to_vec();
    let mut session = SessionState {
        extranonce1,
        worker: None,
        pkh: None,
        difficulty: config.default_diff,
        current_job: None,
        current_snapshot: None,
        last_share_ts: None,
        last_retarget_ts: unix_now_secs(),
        coinbase_bip34: config.coinbase_bip34,
        adapter_kind: select_adapter_kind(&config),
    };

    let (rd, mut wr) = stream.into_split();
    let mut lines = BufReader::new(rd).lines();
    let keepalive_secs = config.keepalive_notify_secs;

    let result = loop {
        let keepalive_wait = sleep(Duration::from_secs(keepalive_secs.max(1)));
        tokio::pin!(keepalive_wait);
        tokio::select! {
            job = rx.recv() => {
                if let Ok(j) = job {
                    if session.pkh.is_some() {
                        let snapshot = build_canonical_job_snapshot(&j, &session, &config)?;
                        session.current_snapshot = Some(snapshot);
                        if let Err(e) = send_set_difficulty(&mut wr, id, session.worker.as_deref(), session.difficulty).await { break Err(e); }
                        if let Err(e) = send_notify(&mut wr, &session, &j, true).await { break Err(e); }
                    } else {
                        session.current_snapshot = None;
                    }
                    session.current_job = Some(j);
                }
            }
            _ = &mut keepalive_wait, if keepalive_secs > 0 => {
                if session.pkh.is_some() {
                    if let Some(job) = session.current_job.clone() {
                        if let Err(e) = send_set_difficulty(&mut wr, id, session.worker.as_deref(), session.difficulty).await { break Err(e); }
                        if let Err(e) = send_notify(&mut wr, &session, &job, false).await { break Err(e); }
                        debug!("[keepalive] conn={} worker={} job={}", id, session.worker.as_deref().unwrap_or("-"), job.job_id);
                    }
                }
            }
            line = lines.next_line() => {
                let Some(line) = line? else { return Err(anyhow!("EOF")); };
                let v: Value = match serde_json::from_str(&line) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("[conn] id={} bad json: {e}", id);
                        continue;
                    }
                };
                if let Err(e) = handle_message(id, &mut wr, &mut session, &config, &current, v).await { break Err(e); }
            }
        }
    };

    result
}

async fn handle_message(
    conn_id: u64,
    wr: &mut tokio::net::tcp::OwnedWriteHalf,
    session: &mut SessionState,
    config: &StratumConfig,
    current: &Arc<RwLock<Option<Job>>>,
    msg: Value,
) -> Result<()> {
    let id = msg.get("id").cloned().unwrap_or(Value::Null);
    let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let params = msg
        .get("params")
        .and_then(|p| p.as_array())
        .cloned()
        .unwrap_or_default();

    match method {
        "mining.configure" => {
            // Bitaxe / ESP-Miner v2+ sends this before mining.subscribe with the
            // version-rolling extension. We do not support version-rolling
            // (the pool builds the header with version=00000001 fixed), so we
            // return false for the version-rolling result. Returning the JSON
            // explicitly — instead of falling through to the catch-all
            // "unsupported method" error — lets recent Bitaxe firmware drop
            // the AsicBoost flag and continue to mining.subscribe.
            let resp = json!({
                "id": id,
                "result": {
                    "version-rolling": false,
                    "version-rolling.mask": "00000000"
                },
                "error": null
            });
            write_json(wr, &resp).await?;
        }
        "mining.suggest_difficulty" => {
            // Some cgminer-family / Antminer firmware sends a difficulty hint
            // (mining.suggest_difficulty [diff]) before subscribe. We honour
            // vardiff regardless; acknowledge with true so the miner does not
            // log an error or disconnect.
            let resp = json!({"id": id, "result": true, "error": null});
            write_json(wr, &resp).await?;
        }
        "mining.multi_version" => {
            // Older Whatsminer BTMiner firmware sends mining.multi_version
            // to request multi-block-version templates. We do not support it;
            // return result: false so the miner falls back to single-version
            // mode rather than treating an error as fatal.
            let resp = json!({"id": id, "result": false, "error": null});
            write_json(wr, &resp).await?;
        }
        "mining.subscribe" => {
            // Stratum v1: result[2] is extranonce2_size (the number of bytes
            // the miner must append to extranonce1 in mining.submit). Internally
            // the snapshot hardcodes 4 (see build_canonical_job_snapshot line ~963);
            // surface that same 4 here. Previously we incorrectly sent
            // config.extranonce1_size which happened to be 4 by coincidence —
            // would have broken any deployment that tuned STRATUM_EXTRANONCE1_SIZE.
            let resp = json!({
                "id": id,
                "result": [
                    [["mining.set_difficulty","irium"],["mining.notify","irium"]],
                    hex::encode(&session.extranonce1),
                    4u32
                ],
                "error": null
            });
            write_json(wr, &resp).await?;
            send_set_difficulty(wr, conn_id, session.worker.as_deref(), session.difficulty).await?;
        }
        "mining.authorize" => {
            let user = params.first().and_then(|v| v.as_str()).unwrap_or("");
            let addr = user.split('.').next().unwrap_or("").trim();
            match parse_address_to_pkh(addr) {
                Ok(pkh) => {
                    session.worker = Some(user.to_string());
                    session.pkh = Some(pkh);
                    let resp = json!({"id": id, "result": true, "error": null});
                    write_json(wr, &resp).await?;
                    info!(
                        "[authorize] worker={} adapter_kind={} miner_family_mode={}",
                        user,
                        session.adapter_kind.as_str(),
                        config.miner_family_mode.as_str()
                    );

                    let cur = current.read().await;
                    if let Some(job) = cur.clone() {
                        session.current_snapshot = Some(build_canonical_job_snapshot(&job, session, config)?);
                        session.current_job = Some(job.clone());
                        send_set_difficulty(wr, conn_id, session.worker.as_deref(), session.difficulty).await?;
                        send_notify(wr, session, &job, true).await?;
                    }
                }
                Err(e) => {
                    let resp = json!({"id": id, "result": false, "error": [20, format!("invalid address: {e}"), null]});
                    write_json(wr, &resp).await?;
                }
            }
        }
        "mining.submit" => {
            let result = handle_submit(conn_id, wr, session, config, &params).await;
            match result {
                Ok(accepted) => {
                    let resp = json!({"id": id, "result": accepted, "error": null});
                    write_json(wr, &resp).await?;
                }
                Err(e) => {
                    let resp = json!({"id": id, "result": false, "error": [23, e.to_string(), null]});
                    write_json(wr, &resp).await?;
                }
            }
        }
        _ => {
            let resp = json!({"id": id, "result": null, "error": [20, "unsupported method", null]});
            write_json(wr, &resp).await?;
        }
    }
    Ok(())
}

fn mode_allows_combo(
    mode: &MinerFamilyMode,
    prev_name: &str,
    mr_name: &str,
    v_name: &str,
    t_name: &str,
    b_name: &str,
    n_name: &str,
) -> bool {
    // `v_rolled` / `v_rolled_raw` are the BIP310 version-rolling variants
    // (LE-encoded and raw-bytes respectively). All non-cpuminer modes treat
    // them the same way they treat v_be.
    let v_ok = v_name == "v_be"
        || v_name == "v_rolled"
        || v_name == "v_rolled_extra"
        || v_name == "v_rolled_raw";
    match mode {
        MinerFamilyMode::Asic => prev_name == "prev_canon" && mr_name == "mr_canon" && v_ok && t_name == "t_raw" && b_name == "b_raw" && n_name == "n_raw",
        MinerFamilyMode::Ccminer => (prev_name == "prev_canon" || prev_name == "prev_rev32") && (mr_name == "mr_canon" || mr_name == "mr_rev32") && v_ok && t_name == "t_raw" && b_name == "b_raw" && (n_name == "n_raw" || n_name == "n_rev"),
        MinerFamilyMode::Auto => (prev_name == "prev_canon" || prev_name == "prev_rev32" || prev_name == "prev_swap4" || prev_name == "prev_rev32_swap4") && (mr_name == "mr_canon" || mr_name == "mr_rev32") && v_ok && t_name == "t_raw" && b_name == "b_raw" && (n_name == "n_raw" || n_name == "n_rev"),
        MinerFamilyMode::Cpuminer => true,
    }
}

async fn handle_submit(
    conn_id: u64,
    wr: &mut tokio::net::tcp::OwnedWriteHalf,
    session: &mut SessionState,
    config: &StratumConfig,
    params: &[Value],
) -> Result<bool> {
    let job = session.current_job.clone().ok_or_else(|| anyhow!("no active job"))?;
    if params.len() < 5 {
        return Err(anyhow!("invalid params"));
    }

    let submit = SubmitTuple {
        job_id: params[1].as_str().unwrap_or("").to_string(),
        extranonce2_hex: params[2].as_str().unwrap_or("").to_string(),
        ntime_hex: params[3].as_str().unwrap_or("").to_string(),
        nonce_hex: params[4].as_str().unwrap_or("").to_string(),
        rolled_version_hex: params.get(5).and_then(|v| v.as_str()).map(String::from),
    };

    if submit.job_id != job.job_id {
        return Err(anyhow!("stale share"));
    }

    // AuxPoW mode: always use the native rewardable path (builds parent block header correctly)
    if session.current_snapshot.as_ref().map(|s| s.auxpow_mode).unwrap_or(false) {
        return handle_submit_native_rewardable(conn_id, wr, session, config, &submit).await;
    }

    match session.adapter_kind {
        AdapterKind::CpuminerCompatibility => {
            handle_submit_cpuminer_compat(conn_id, wr, session, config, &submit).await
        }
        AdapterKind::NativeRewardableReserved => {
            handle_submit_native_rewardable(conn_id, wr, session, config, &submit).await
        }
        _ => handle_submit_legacy_rewardable(conn_id, wr, session, config, &submit).await,
    }
}

fn decode_native_rewardable_submit(
    snapshot: &CanonicalJobSnapshot,
    submit: &NativeSubmit,
) -> Result<CanonicalSolve> {
    if submit.job_id != snapshot.job_id {
        return Err(anyhow!("stale share"));
    }
    let extranonce2 =
        hex::decode(&submit.extranonce2_hex).map_err(|e| anyhow!("extranonce2 decode: {e}"))?;
    let coinbase = reconstruct_canonical_coinbase(snapshot, &extranonce2)?;
    let coinbase_hash_internal = sha256d(&coinbase);
    let canonical_merkle_root =
        reconstruct_canonical_merkle_root(snapshot, coinbase_hash_internal);
    let ntime = parse_u32_hex(&submit.ntime_hex)?;
    let nonce = parse_u32_hex(&submit.nonce_hex)?;
    let canonical_header80 =
        reconstruct_canonical_header80(snapshot, canonical_merkle_root, ntime, nonce);
    let mut canonical_hash = sha256d(&canonical_header80);
    canonical_hash.reverse();
    let share_target = snapshot.block_target.clone();
    let share_ok = BigUint::from_bytes_be(&canonical_hash) <= share_target;
    let block_ok = BigUint::from_bytes_be(&canonical_hash) <= snapshot.block_target;

    Ok(CanonicalSolve {
        adapter_id: "native_rewardable",
        rewardable: true,
        share_variant: "canonical_native",
        extranonce2_hex: submit.extranonce2_hex.clone(),
        ntime_hex: submit.ntime_hex.clone(),
        nonce_hex: submit.nonce_hex.clone(),
        coinbase_hex: hex::encode(&coinbase),
        coinbase_hash_internal,
        canonical_merkle_root,
        canonical_header80,
        canonical_hash,
        share_hash: canonical_hash,
        share_target,
        block_target: snapshot.block_target.clone(),
        share_ok,
        share_block_like: block_ok,
        block_ok,
    })
}

fn decode_cpuminer_compat_submit(
    snapshot: &CanonicalJobSnapshot,
    session: &SessionState,
    config: &StratumConfig,
    submit: &SubmitTuple,
) -> Result<CanonicalSolve> {
    let extra2 = hex::decode(&submit.extranonce2_hex).map_err(|e| anyhow!("extranonce2 decode: {e}"))?;
    let cb = reconstruct_coinbase(snapshot, &extra2);
    let cb_hash = sha256d(&cb);
    let canonical_merkle_root = merkle_root_from_coinbase(cb_hash, &snapshot.branches);
    let ntime = parse_u32_hex(&submit.ntime_hex)?;
    let nonce = parse_u32_hex(&submit.nonce_hex)?;
    let canonical_header80 = header_bytes(
        snapshot.version,
        snapshot.prev_hash_internal,
        canonical_merkle_root,
        ntime,
        snapshot.bits,
        nonce,
    );
    let canonical_hash = sha256d(&canonical_header80);

    fn fold_merkle(root0: [u8; 32], branches: &[[u8; 32]], rev_branch: bool, rev_each_round: bool) -> [u8; 32] {
        let mut root = root0;
        for b in branches {
            let mut branch = *b;
            if rev_branch {
                branch.reverse();
            }
            let mut data = Vec::with_capacity(64);
            data.extend_from_slice(&root);
            data.extend_from_slice(&branch);
            root = sha256d(&data);
            if rev_each_round {
                root.reverse();
            }
        }
        root
    }

    let mr_raw_raw = fold_merkle(cb_hash, &snapshot.branches, false, false);
    let mr_raw_rev = fold_merkle(cb_hash, &snapshot.branches, true, false);
    let mr_round_raw = fold_merkle(cb_hash, &snapshot.branches, false, true);
    let mr_round_rev = fold_merkle(cb_hash, &snapshot.branches, true, true);

    let prev_canon = snapshot.prev_hash_internal;
    let prev_rev32 = reverse_32(snapshot.prev_hash_internal);
    let prev_swap4 = swap4_bytes_each_word(snapshot.prev_hash_internal);
    let prev_rev32_swap4 = swap4_bytes_each_word(prev_rev32);

    let prev_variants: [(&str, [u8; 32]); 4] = [
        ("prev_canon", prev_canon),
        ("prev_rev32", prev_rev32),
        ("prev_swap4", prev_swap4),
        ("prev_rev32_swap4", prev_rev32_swap4),
    ];

    let mut merkle_variants: Vec<(&str, [u8; 32])> = Vec::new();
    for (base_name, base) in [
        ("mr_fold_raw_raw", mr_raw_raw),
        ("mr_fold_raw_rev", mr_raw_rev),
        ("mr_fold_round_raw", mr_round_raw),
        ("mr_fold_round_rev", mr_round_rev),
    ] {
        let mut rev32 = base;
        rev32.reverse();
        merkle_variants.push((base_name, base));
        merkle_variants.push((Box::leak(format!("{}:rev32", base_name).into_boxed_str()), rev32));
        merkle_variants.push((Box::leak(format!("{}:swap4", base_name).into_boxed_str()), swap4_bytes_each_word(base)));
        merkle_variants.push((Box::leak(format!("{}:rev32_swap4", base_name).into_boxed_str()), swap4_bytes_each_word(rev32)));
    }

    let share_target = target_from_difficulty_with_limit(session.difficulty, &config.pow_limit);
    let block_target = snapshot.block_target.clone();

    #[derive(Clone)]
    struct CheckResult {
        name: &'static str,
        hash: [u8; 32],
        ok_share_be: bool,
        ok_share_le: bool,
        ok_block_be: bool,
        ok_block_le: bool,
    }

    let use_le = matches!(config.hash_cmp_mode, HashCmpMode::Le);
    let nbits_raw = decode_hex4(&format!("{:08x}", snapshot.bits))?;
    let ntime_raw = decode_hex4(&submit.ntime_hex)?;
    let nonce_raw = decode_hex4(&submit.nonce_hex)?;
    let version_be = [0x00, 0x00, 0x00, 0x01];
    let version_le = snapshot.version.to_le_bytes();
    // BIP310: params[5] carries version-rolling extra bits. Header version
    // = base | extra (header bytes LE-encoded). Different firmware encodes
    // params[5] slightly differently, so we test multiple interpretations
    // and accept whichever matches the miner's actual header.
    let version_opts: Vec<(&'static str, [u8; 4])> = match &submit.rolled_version_hex {
        Some(hex) => {
            let rolled_extra = parse_u32_hex(hex)?;
            let extra_raw = decode_hex4(hex)?;
            vec![
                ("v_rolled", (snapshot.version | rolled_extra).to_le_bytes()),
                ("v_rolled_extra", rolled_extra.to_le_bytes()),
                ("v_rolled_raw", extra_raw),
            ]
        }
        None => vec![("v_be", version_be), ("v_le", version_le)],
    };
    let time_opts = [("t_raw", ntime_raw), ("t_rev", reverse_4(ntime_raw))];
    let bits_opts = [("b_raw", nbits_raw), ("b_rev", reverse_4(nbits_raw))];
    let nonce_opts = [("n_raw", nonce_raw), ("n_rev", reverse_4(nonce_raw))];

    let mut checks: Vec<CheckResult> = Vec::new();
    let mut accepted_idx: Option<usize> = None;

    for (prev_name, prev_for_header) in prev_variants {
        for &(mr_name, mr_for_header) in merkle_variants.iter() {
            for &(v_name, v_bytes) in version_opts.iter() {
                for (t_name, t_bytes) in time_opts {
                    for (b_name, b_bytes) in bits_opts {
                        for (n_name, n_bytes) in nonce_opts {
                            let hdr_v = header_bytes_from_wire(
                                v_bytes,
                                prev_for_header,
                                mr_for_header,
                                t_bytes,
                                b_bytes,
                                n_bytes,
                            );
                            let mode = format!("{}:{}:{}:{}", v_name, t_name, b_name, n_name);
                            let hash_v = sha256d(&hdr_v);
                            let hash_int_be = BigUint::from_bytes_be(&hash_v);
                            let mut hash_rev = hash_v;
                            hash_rev.reverse();
                            let hash_int_le = BigUint::from_bytes_be(&hash_rev);
                            let ok_share_be = hash_int_be <= share_target;
                            let ok_share_le = hash_int_le <= share_target;
                            let ok_block_be = hash_int_be <= block_target;
                            let ok_block_le = hash_int_le <= block_target;
                            let ok_share = if use_le { ok_share_le } else { ok_share_be };
                            checks.push(CheckResult {
                                name: Box::leak(format!("{}+{}:{}", prev_name, mr_name, mode).into_boxed_str()),
                                hash: hash_v,
                                ok_share_be,
                                ok_share_le,
                                ok_block_be,
                                ok_block_le,
                            });
                            if ok_share && accepted_idx.is_none() {
                                accepted_idx = Some(checks.len() - 1);
                            }
                        }
                    }
                }
            }
        }
    }

    let (share_variant, share_hash, share_ok, share_block_like) = if let Some(idx) = accepted_idx {
        let chosen = &checks[idx];
        (
            chosen.name,
            chosen.hash,
            true,
            if use_le { chosen.ok_block_le } else { chosen.ok_block_be },
        )
    } else {
        ("none", canonical_hash, false, false)
    };

    Ok(CanonicalSolve {
        adapter_id: "cpuminer_compat",
        rewardable: false,
        share_variant,
        extranonce2_hex: submit.extranonce2_hex.clone(),
        ntime_hex: submit.ntime_hex.clone(),
        nonce_hex: submit.nonce_hex.clone(),
        coinbase_hex: hex::encode(&cb),
        coinbase_hash_internal: cb_hash,
        canonical_merkle_root,
        canonical_header80,
        canonical_hash,
        share_hash,
        share_target,
        block_target,
        share_ok,
        share_block_like,
        block_ok: hash_meets_target(&canonical_hash, &snapshot.block_target),
    })
}

fn process_cpuminer_compat_solve(
    worker: &str,
    snapshot: &CanonicalJobSnapshot,
    solve: &CanonicalSolve,
) -> Vec<CompatEvent> {
    let mut events = Vec::new();

    mark_accepted_share();
    info!(
        "[SHARE_ACCEPTED] worker={} adapter_id={} rewardable={} variant={} hash={} canonical_hash={}",
        worker,
        solve.adapter_id,
        solve.rewardable,
        solve.share_variant,
        hex::encode(solve.share_hash),
        hex::encode(solve.canonical_hash),
    );
    events.push(CompatEvent::ShareAccepted);

    if solve.share_block_like {
        mark_compat_solved_share();
        mark_compat_block_like_share();
        info!(
            "[COMPAT_SOLVED_SHARE] worker={} adapter_id={} rewardable={} job={} share_hash={} canonical_hash={} block_target={} template_fingerprint={}",
            worker,
            solve.adapter_id,
            solve.rewardable,
            snapshot.job_id,
            hex::encode(solve.share_hash),
            hex::encode(solve.canonical_hash),
            biguint_to_32hex(&solve.block_target),
            snapshot.template_fingerprint,
        );
        events.push(CompatEvent::CompatSolvedShare);
    }

    if solve.share_block_like || solve.block_ok {
        mark_compat_nonrewardable_event();
        warn!(
            "[COMPAT_CANDIDATE_BLOCKED] worker={} adapter_id={} rewardable={} job={} share_block_like={} canonical_block_ok={} share_hash={} canonical_hash={} block_target={} template_fingerprint={} action=no_candidate_promotion",
            worker,
            solve.adapter_id,
            solve.rewardable,
            snapshot.job_id,
            solve.share_block_like,
            solve.block_ok,
            hex::encode(solve.share_hash),
            hex::encode(solve.canonical_hash),
            biguint_to_32hex(&solve.block_target),
            snapshot.template_fingerprint,
        );
        events.push(CompatEvent::CompatCandidateBlocked);
    }

    events
}

fn allow_rewardable_promotion(solve: &CanonicalSolve) -> bool {
    solve.rewardable && solve.block_ok
}

async fn handle_submit_cpuminer_compat(
    conn_id: u64,
    wr: &mut tokio::net::tcp::OwnedWriteHalf,
    session: &mut SessionState,
    config: &StratumConfig,
    submit: &SubmitTuple,
) -> Result<bool> {
    let worker = session.worker.clone().unwrap_or_else(|| format!("conn-{conn_id}"));
    let snapshot = session
        .current_snapshot
        .clone()
        .ok_or_else(|| anyhow!("missing canonical snapshot"))?;
    let adapter = CpuminerCompatibilityAdapter;
    let solve = adapter.decode_submit(&snapshot, session, config, submit)?;

    info!(
        "[sharecheck-cpuminer] worker={} job={} adapter_id={} rewardable={} template_fingerprint={} extranonce1={} extranonce2={} ntime={} nonce={} raw_submitted_hash={} canonical_hash={} share_target={} block_target={} coinbase_hex={} coinbase_hash={} merkle_root={} miner_header80={} canonical_header80={} share_variant={}",
        worker,
        snapshot.job_id,
        adapter.adapter_id(),
        solve.rewardable,
        snapshot.template_fingerprint,
        hex::encode(&snapshot.extranonce1),
        solve.extranonce2_hex,
        solve.ntime_hex,
        solve.nonce_hex,
        hex::encode(solve.share_hash),
        hex::encode(solve.canonical_hash),
        biguint_to_32hex(&solve.share_target),
        biguint_to_32hex(&solve.block_target),
        solve.coinbase_hex,
        hex::encode(solve.coinbase_hash_internal),
        hex::encode(solve.canonical_merkle_root),
        hex::encode(cpuminer_miner_header_wire(&snapshot, solve.coinbase_hash_internal, &solve.ntime_hex, &solve.nonce_hex)?),
        hex::encode(solve.canonical_header80),
        solve.share_variant,
    );

    if !solve.share_ok {
        if config.soft_accept_invalid_shares {
            mark_accepted_share();
            warn!(
                "[SHARE_SOFT_ACCEPTED] worker={} adapter_id={} reason=compat_soft_accept hash={} canonical_hash={}",
                worker,
                solve.adapter_id,
                hex::encode(solve.share_hash),
                hex::encode(solve.canonical_hash),
            );
            return Ok(true);
        }
        mark_rejected_share();
        warn!(
            "[SHARE_REJECTED] worker={} adapter_id={} rewardable={} reason=low_difficulty job={} extranonce2={} ntime={} nonce={} raw_submitted_hash={} canonical_hash={} share_target={} block_target={} template_fingerprint={}",
            worker,
            solve.adapter_id,
            solve.rewardable,
            snapshot.job_id,
            solve.extranonce2_hex,
            solve.ntime_hex,
            solve.nonce_hex,
            hex::encode(solve.share_hash),
            hex::encode(solve.canonical_hash),
            biguint_to_32hex(&solve.share_target),
            biguint_to_32hex(&solve.block_target),
            snapshot.template_fingerprint,
        );
        return Err(anyhow!("low_difficulty"));
    }

    let _events = process_cpuminer_compat_solve(&worker, &snapshot, &solve);
    maybe_update_vardiff_after_accepted_share(conn_id, wr, session, config, &worker).await?;
    Ok(true)
}

fn encode_varint(v: usize, out: &mut Vec<u8>) {
    if v < 0xfd {
        out.push(v as u8);
    } else if v <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(v as u16).to_le_bytes());
    } else if v <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(v as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&(v as u64).to_le_bytes());
    }
}

fn build_canonical_block_hex(
    snapshot: &CanonicalJobSnapshot,
    solve: &CanonicalSolve,
) -> Result<String> {
    let mut block = Vec::new();
    block.extend_from_slice(&solve.canonical_header80);
    block.extend_from_slice(
        &hex::decode(&solve.coinbase_hex).map_err(|e| anyhow!("coinbase hex decode: {e}"))?,
    );
    for tx in &snapshot.tx_hex {
        block.extend_from_slice(&hex::decode(tx).map_err(|e| anyhow!("tx hex decode: {e}"))?);
    }
    Ok(hex::encode(block))
}

async fn submit_canonical_block(
    client: &reqwest::Client,
    config: &StratumConfig,
    snapshot: &CanonicalJobSnapshot,
    solve: &CanonicalSolve,
) -> Result<NodeSubmitResult> {
    let req = SubmitRequest {
        height: snapshot.height,
        header: SubmitHeader {
            version: snapshot.version,
            prev_hash: hex::encode(snapshot.prev_hash_internal),
            merkle_root: hex::encode(solve.canonical_merkle_root),
            time: parse_u32_hex(&solve.ntime_hex)?,
            bits: format!("{:08x}", snapshot.bits),
            nonce: parse_u32_hex(&solve.nonce_hex)?,
            hash: hex::encode(solve.canonical_hash),
        },
        tx_hex: {
            let mut txs = Vec::with_capacity(snapshot.tx_hex.len() + 1);
            txs.push(solve.coinbase_hex.clone());
            txs.extend(snapshot.tx_hex.clone());
            txs
        },
        submit_source: "pool_stratum_native_rewardable".to_string(),
        auxpow_hex: None,
    };

    let url = format!("{}/rpc/submit_block", config.rpc_base.trim_end_matches('/'));
    let resp = client
        .post(url)
        .bearer_auth(&config.rpc_token)
        .json(&req)
        .send()
        .await?;
    if resp.status().is_success() {
        Ok(NodeSubmitResult::Accepted {
            canonical_block_hash: solve.canonical_hash,
            accepted_height: snapshot.height,
        })
    } else {
        Ok(NodeSubmitResult::Rejected {
            reason: format!("http_status={}", resp.status()),
        })
    }
}

fn rewardable_candidate_allowed(solve: &CanonicalSolve) -> bool {
    solve.rewardable && solve.block_ok
}

fn mark_round_eligible(_record: &RoundEligibleRecord) -> Result<()> {
    mark_round_eligible_counter();
    Ok(())
}

async fn handle_submit_native_rewardable(
    conn_id: u64,
    wr: &mut tokio::net::tcp::OwnedWriteHalf,
    session: &mut SessionState,
    config: &StratumConfig,
    submit: &SubmitTuple,
) -> Result<bool> {
    let snapshot = session
        .current_snapshot
        .clone()
        .ok_or_else(|| anyhow!("missing canonical snapshot"))?;

    if snapshot.auxpow_mode {
        return handle_submit_auxpow(conn_id, wr, session, config, submit, snapshot).await;
    }

    if !config.native_rewardable_enabled {
        return Err(anyhow!("native rewardable adapter disabled"));
    }

    let worker = session.worker.clone().unwrap_or_else(|| "-".to_string());
    let adapter = NativeRewardableAdapter;
    let solve = adapter.decode_submit(&snapshot, session, config, submit)?;

    if !solve.share_ok {
        mark_rejected_share();
        warn!(
            "[share] reject worker={} adapter_id={} reason=low_difficulty",
            worker,
            solve.adapter_id
        );
        return Err(anyhow!("low_difficulty"));
    }

    mark_accepted_share();
    mark_rewardable_share_accepted();
    info!(
        "[REWARDABLE_SHARE_ACCEPTED] worker={} adapter_id={} rewardable={} job={} canonical_hash={} share_target={}",
        worker,
        solve.adapter_id,
        solve.rewardable,
        snapshot.job_id,
        hex::encode(solve.canonical_hash),
        biguint_to_32hex(&solve.share_target),
    );

    if rewardable_candidate_allowed(&solve) {
        mark_candidate_detected();
        info!(
            "[REWARDABLE_CANDIDATE] worker={} adapter_id={} rewardable={} job={} canonical_hash={} block_target={} template_fingerprint={}",
            worker,
            solve.adapter_id,
            solve.rewardable,
            snapshot.job_id,
            hex::encode(solve.canonical_hash),
            biguint_to_32hex(&solve.block_target),
            snapshot.template_fingerprint,
        );

        let block_hex = build_canonical_block_hex(&snapshot, &solve)?;
        mark_candidate_submitted();
        mark_block_submit_attempt();
        info!(
            "[BLOCK_SUBMITTED] worker={} job={} canonical_hash={} merkle_root={} block_hex_len={} template_fingerprint={}",
            worker,
            snapshot.job_id,
            hex::encode(solve.canonical_hash),
            hex::encode(solve.canonical_merkle_root),
            block_hex.len(),
            snapshot.template_fingerprint,
        );

        let client = reqwest::Client::builder().build()?;
        match submit_canonical_block(&client, config, &snapshot, &solve).await? {
            NodeSubmitResult::Accepted {
                canonical_block_hash,
                accepted_height,
            } => {
                mark_submit_accepted();
                mark_chain_height_advanced_by_pool();
                info!(
                    "[BLOCK_ACCEPTED] worker={} job={} canonical_hash={} accepted_height={} template_fingerprint={}",
                    worker,
                    snapshot.job_id,
                    hex::encode(canonical_block_hash),
                    accepted_height,
                    snapshot.template_fingerprint,
                );
                let record = RoundEligibleRecord {
                    height: accepted_height,
                    job_id: snapshot.job_id.clone(),
                    template_fingerprint: snapshot.template_fingerprint.clone(),
                    canonical_block_hash,
                    accepted_at_unix: unix_now_secs(),
                };
                mark_round_eligible(&record)?;
                info!(
                    "[ROUND_ELIGIBLE] height={} job={} canonical_hash={} template_fingerprint={}",
                    record.height,
                    record.job_id,
                    hex::encode(record.canonical_block_hash),
                    record.template_fingerprint,
                );
            }
            NodeSubmitResult::Rejected { reason } => {
                mark_submit_rejected();
                warn!(
                    "[BLOCK_REJECTED] worker={} job={} canonical_hash={} reason={} template_fingerprint={}",
                    worker,
                    snapshot.job_id,
                    hex::encode(solve.canonical_hash),
                    reason,
                    snapshot.template_fingerprint,
                );
            }
        }
    }

    maybe_update_vardiff_after_accepted_share(conn_id, wr, session, config, &worker).await?;
    Ok(true)
}


async fn handle_submit_auxpow(
    conn_id: u64,
    wr: &mut tokio::net::tcp::OwnedWriteHalf,
    session: &mut SessionState,
    config: &StratumConfig,
    submit: &SubmitTuple,
    snapshot: CanonicalJobSnapshot,
) -> Result<bool> {
    let worker = session.worker.clone().unwrap_or_else(|| format!("conn-{conn_id}"));

    let extranonce2 = hex::decode(&submit.extranonce2_hex)
        .map_err(|e| anyhow!("extranonce2 decode: {e}"))?;
    let parent_coinbase = reconstruct_canonical_coinbase(&snapshot, &extranonce2)?;
    let parent_coinbase_hash = sha256d(&parent_coinbase);

    let ntime = parse_u32_hex(&submit.ntime_hex)?;
    let nonce = parse_u32_hex(&submit.nonce_hex)?;

    // Build parent header with NATURAL ORDER merkle root so iriumd validate() passes:
    //   parent_header[36..68] == sha256d(coinbase_txn)
    let parent_header = header_bytes(1, snapshot.prev_hash_internal, parent_coinbase_hash, ntime, snapshot.bits, nonce);
    let mut parent_hash_display = sha256d(&parent_header);
    parent_hash_display.reverse();

    let share_target = target_from_difficulty_with_limit(session.difficulty, &config.pow_limit);
    let ok_share = BigUint::from_bytes_be(&parent_hash_display) <= share_target;
    let ok_block = BigUint::from_bytes_be(&parent_hash_display) <= snapshot.block_target;

    if !ok_share {
        if config.soft_accept_invalid_shares {
            mark_accepted_share();
            warn!("[AUXPOW_SHARE_SOFT_ACCEPTED] worker={}", worker);
            maybe_update_vardiff_after_accepted_share(conn_id, wr, session, config, &worker).await?;
            return Ok(true);
        }
        mark_rejected_share();
        warn!("[AUXPOW_SHARE_REJECTED] worker={} reason=low_difficulty hash={}", worker, hex::encode(parent_hash_display));
        return Err(anyhow!("low_difficulty"));
    }

    mark_accepted_share();
    mark_rewardable_share_accepted();
    info!(
        "[AUXPOW_SHARE_ACCEPTED] worker={} hash={} block_target={}",
        worker, hex::encode(parent_hash_display), biguint_to_32hex(&snapshot.block_target)
    );

    if ok_block {
        mark_candidate_detected();
        info!("[AUXPOW_CANDIDATE] worker={} height={} hash={}", worker, snapshot.height, hex::encode(parent_hash_display));

        let auxpow_hex = build_auxpow_hex_from_solution(&parent_coinbase, ntime, snapshot.bits, nonce);

        let irium_h80 = snapshot.irium_header80.ok_or_else(|| anyhow!("missing irium_header80"))?;
        let irium_coinbase_hex = snapshot.irium_coinbase_hex.as_ref().ok_or_else(|| anyhow!("missing irium_coinbase_hex"))?;

        // Extract Irium block fields from the pre-built header
        let irium_version = u32::from_le_bytes(irium_h80[0..4].try_into().unwrap());
        let mut irium_prev = [0u8; 32];
        irium_prev.copy_from_slice(&irium_h80[4..36]);
        irium_prev.reverse(); // wire order → internal order
        let mut irium_merkle = [0u8; 32];
        irium_merkle.copy_from_slice(&irium_h80[36..68]);
        irium_merkle.reverse(); // wire order → natural order
        let irium_ntime = u32::from_le_bytes(irium_h80[68..72].try_into().unwrap());
        let irium_bits_val = u32::from_le_bytes(irium_h80[72..76].try_into().unwrap());
        let irium_nonce = 0u32;
        let mut irium_hash = sha256d(&irium_h80);
        irium_hash.reverse();

        let mut tx_hex = Vec::with_capacity(snapshot.tx_hex.len() + 1);
        tx_hex.push(irium_coinbase_hex.clone());
        tx_hex.extend(snapshot.tx_hex.clone());

        let req = SubmitRequest {
            height: snapshot.height,
            header: SubmitHeader {
                version: irium_version,
                prev_hash: hex::encode(irium_prev),
                merkle_root: hex::encode(irium_merkle),
                time: irium_ntime,
                bits: format!("{:08x}", irium_bits_val),
                nonce: irium_nonce,
                hash: hex::encode(irium_hash),
            },
            tx_hex,
            submit_source: "pool_stratum_auxpow".to_string(),
            auxpow_hex: Some(auxpow_hex),
        };

        mark_candidate_submitted();
        mark_block_submit_attempt();

        let url = format!("{}/rpc/submit_block", config.rpc_base.trim_end_matches('/'));
        let client = reqwest::Client::builder().build()?;
        match client.post(&url).bearer_auth(&config.rpc_token).json(&req).send().await {
            Ok(resp) if resp.status().is_success() => {
                mark_submit_accepted();
                mark_chain_height_advanced_by_pool();
                info!(
                    "[AUXPOW_BLOCK_ACCEPTED] worker={} height={} irium_hash={}",
                    worker, snapshot.height, hex::encode(irium_hash)
                );
                let row = FoundBlockRecord {
                    height: snapshot.height,
                    hash: hex::encode(irium_hash),
                    time: unix_now_secs(),
                    worker: worker.to_string(),
                    address: worker_address(&worker),
                };
                if let Err(e) = append_found_block(&config.found_blocks_file, &row) {
                    warn!("[block] auxpow record append failed: {e}");
                }
            }
            Ok(resp) => {
                mark_submit_rejected();
                warn!("[AUXPOW_BLOCK_REJECTED] worker={} status={}", worker, resp.status());
            }
            Err(e) => {
                mark_submit_rejected();
                warn!("[AUXPOW_BLOCK_SUBMIT_ERROR] worker={} err={}", worker, e);
            }
        }
    }

    maybe_update_vardiff_after_accepted_share(conn_id, wr, session, config, &worker).await?;
    Ok(true)
}

async fn handle_submit_legacy_rewardable(
    conn_id: u64,
    wr: &mut tokio::net::tcp::OwnedWriteHalf,
    session: &mut SessionState,
    config: &StratumConfig,
    submit: &SubmitTuple,
) -> Result<bool> {
    let worker = session.worker.clone().unwrap_or_else(|| format!("conn-{conn_id}"));
    let pkh = session.pkh.ok_or_else(|| anyhow!("unauthorized"))?;
    let job = session.current_job.clone().ok_or_else(|| anyhow!("no active job"))?;

    let extra2 = hex::decode(&submit.extranonce2_hex).map_err(|e| anyhow!("extranonce2 decode: {e}"))?;
    let mut en = session.extranonce1.clone();
    en.extend_from_slice(&extra2);

    let cb = build_coinbase_tx(job.height, job.coinbase_value, &pkh, &en, config.coinbase_bip34);
    let cb_hash = sha256d(&cb);

    fn fold_merkle(root0: [u8; 32], branches: &[[u8; 32]], rev_branch: bool, rev_each_round: bool) -> [u8; 32] {
        let mut root = root0;
        for b in branches {
            let mut branch = *b;
            if rev_branch {
                branch.reverse();
            }
            let mut data = Vec::with_capacity(64);
            data.extend_from_slice(&root);
            data.extend_from_slice(&branch);
            root = sha256d(&data);
            if rev_each_round {
                root.reverse();
            }
        }
        root
    }

    let mr_raw_raw = fold_merkle(cb_hash, &job.branches, false, false);
    let mr_raw_rev = fold_merkle(cb_hash, &job.branches, true, false);
    let mr_round_raw = fold_merkle(cb_hash, &job.branches, false, true);
    let mr_round_rev = fold_merkle(cb_hash, &job.branches, true, true);
    let mr = mr_raw_raw;

    let ntime = parse_u32_hex(&submit.ntime_hex)?;
    let nonce = parse_u32_hex(&submit.nonce_hex)?;
    let version: u32 = 1;

    let prev_canon = job.prev_hash;
    let prev_rev32 = reverse_32(job.prev_hash);
    let prev_swap4 = swap4_bytes_each_word(job.prev_hash);
    let prev_rev32_swap4 = swap4_bytes_each_word(prev_rev32);

    let prev_variants: [(&str, [u8; 32]); 4] = [
        ("prev_canon", prev_canon),
        ("prev_rev32", prev_rev32),
        ("prev_swap4", prev_swap4),
        ("prev_rev32_swap4", prev_rev32_swap4),
    ];

    let mut merkle_variants: Vec<(&str, [u8; 32])> = Vec::new();
    for (base_name, base) in [
        ("mr_fold_raw_raw", mr_raw_raw),
        ("mr_fold_raw_rev", mr_raw_rev),
        ("mr_fold_round_raw", mr_round_raw),
        ("mr_fold_round_rev", mr_round_rev),
    ] {
        let mut rev32 = base;
        rev32.reverse();
        merkle_variants.push((base_name, base));
        merkle_variants.push((Box::leak(format!("{}:rev32", base_name).into_boxed_str()), rev32));
        merkle_variants.push((Box::leak(format!("{}:swap4", base_name).into_boxed_str()), swap4_bytes_each_word(base)));
        merkle_variants.push((Box::leak(format!("{}:rev32_swap4", base_name).into_boxed_str()), swap4_bytes_each_word(rev32)));
    }

    let share_target = target_from_difficulty_with_limit(session.difficulty, &config.pow_limit);
    let block_target = target_from_bits(job.bits);

    #[derive(Clone)]
    struct CheckResult {
        name: &'static str,
        header: [u8; 80],
        hash: [u8; 32],
        ok_share_be: bool,
        ok_share_le: bool,
        ok_block_be: bool,
        ok_block_le: bool,
    }

    let use_le = matches!(config.hash_cmp_mode, HashCmpMode::Le);
    let mut checks: Vec<CheckResult> = Vec::new();
    let mut accepted_idx: Option<usize> = None;

    let nbits_raw = decode_hex4(&job.nbits_hex)?;
    let ntime_raw = decode_hex4(&submit.ntime_hex)?;
    let nonce_raw = decode_hex4(&submit.nonce_hex)?;
    let version_be = [0x00, 0x00, 0x00, 0x01];
    let version_le = version.to_le_bytes();
    // BIP310: see SubmitTuple.rolled_version_hex and the matching block in
    // decode_cpuminer_compat_submit for the three-interpretation rationale.
    let version_opts: Vec<(&'static str, [u8; 4])> = match &submit.rolled_version_hex {
        Some(hex) => {
            let rolled_extra = parse_u32_hex(hex)?;
            let extra_raw = decode_hex4(hex)?;
            vec![
                ("v_rolled", (version | rolled_extra).to_le_bytes()),
                ("v_rolled_extra", rolled_extra.to_le_bytes()),
                ("v_rolled_raw", extra_raw),
            ]
        }
        None => vec![("v_be", version_be), ("v_le", version_le)],
    };
    let time_opts = [("t_raw", ntime_raw), ("t_rev", reverse_4(ntime_raw))];
    let bits_opts = [("b_raw", nbits_raw), ("b_rev", reverse_4(nbits_raw))];
    let nonce_opts = [("n_raw", nonce_raw), ("n_rev", reverse_4(nonce_raw))];

    for (prev_name, prev_for_header) in prev_variants {
        for &(mr_name, mr_for_header) in merkle_variants.iter() {
            for &(v_name, v_bytes) in version_opts.iter() {
                for (t_name, t_bytes) in time_opts {
                    for (b_name, b_bytes) in bits_opts {
                        for (n_name, n_bytes) in nonce_opts {
                            if !mode_allows_combo(&config.miner_family_mode, prev_name, mr_name, v_name, t_name, b_name, n_name) {
                                continue;
                            }
                            let hdr_v = header_bytes_from_wire(
                                v_bytes,
                                prev_for_header,
                                mr_for_header,
                                t_bytes,
                                b_bytes,
                                n_bytes,
                            );
                            let mode = format!("{}:{}:{}:{}", v_name, t_name, b_name, n_name);
                            let hash_v = sha256d(&hdr_v);
                            let hash_int_be = BigUint::from_bytes_be(&hash_v);
                            let mut hash_rev = hash_v;
                            hash_rev.reverse();
                            let hash_int_le = BigUint::from_bytes_be(&hash_rev);
                            let ok_share_be = hash_int_be <= share_target;
                            let ok_share_le = hash_int_le <= share_target;
                            let ok_block_be = hash_int_be <= block_target;
                            let ok_block_le = hash_int_le <= block_target;
                            let ok_share = if use_le { ok_share_le } else { ok_share_be };

                            checks.push(CheckResult {
                                name: Box::leak(format!("{}+{}:{}", prev_name, mr_name, mode).into_boxed_str()),
                                header: hdr_v,
                                hash: hash_v,
                                ok_share_be,
                                ok_share_le,
                                ok_block_be,
                                ok_block_le,
                            });

                            if ok_share && accepted_idx.is_none() {
                                accepted_idx = Some(checks.len() - 1);
                            }
                        }
                    }
                }
            }
        }
    }

    let canonical = &checks[0];
    info!(
        "[sharedebug-header] worker={} job={} variant={} version_hex={:08x} prevhash={} merkle_root={} ntime_hex={} nbits_hex={} nonce_hex={:08x} header80={} hash={}",
        worker,
        job.job_id,
        canonical.name,
        version,
        hex::encode(job.prev_hash),
        hex::encode(mr),
        submit.ntime_hex,
        job.nbits_hex,
        nonce,
        hex::encode(canonical.header),
        hex::encode(canonical.hash)
    );

    let total_variants = checks.len();
    let sample_n = config.sharecheck_samples.min(total_variants);
    let summary = checks
        .iter()
        .take(sample_n)
        .map(|c| {
            format!(
                "{}:sb={} sl={} bb={} bl={}",
                c.name,
                c.ok_share_be,
                c.ok_share_le,
                c.ok_block_be,
                c.ok_block_le
            )
        })
        .collect::<Vec<_>>()
        .join(" | ");

    let mut hash = canonical.hash;
    let mut ok_block = false;
    let selected_variant;

    let check_line = if let Some(idx) = accepted_idx {
        let chosen = &checks[idx];
        hash = chosen.hash;
        ok_block = if use_le { chosen.ok_block_le } else { chosen.ok_block_be };
        selected_variant = chosen.name;
        format!(
            "[sharecheck] worker={} job={} assigned_diff={} share_target={} block_target={} chosen_variant={} variants_checked={} sample={}",
            worker,
            job.job_id,
            session.difficulty,
            biguint_to_32hex(&share_target),
            biguint_to_32hex(&block_target),
            selected_variant,
            total_variants,
            summary
        )
    } else {
        selected_variant = "none";
        format!(
            "[sharecheck] worker={} job={} assigned_diff={} share_target={} block_target={} chosen_variant={} variants_checked={} sample={}",
            worker,
            job.job_id,
            session.difficulty,
            biguint_to_32hex(&share_target),
            biguint_to_32hex(&block_target),
            selected_variant,
            total_variants,
            summary
        )
    };

    let ok_share = accepted_idx.is_some();

    if ok_share {
        mark_accepted_share();
        info!("{}", check_line);
        info!("[share] accepted worker={} hash={}", worker, hex::encode(hash));
    } else if config.soft_accept_invalid_shares {
        mark_accepted_share();
        warn!("{}", check_line);
        warn!("[share] soft-accepted worker={} reason=compat_soft_accept", worker);
        return Ok(true);
    } else {
        mark_rejected_share();
        warn!("{}", check_line);
        warn!("[share] reject worker={} reason=low_difficulty", worker);
        return Err(anyhow!("low_difficulty"));
    }

    if ok_block {
        mark_candidate_detected();
        info!(
            "[block] candidate worker={} height={} hash={}",
            worker,
            job.height,
            hex::encode(hash)
        );
        let mut tx_hex = Vec::with_capacity(job.tx_hex.len() + 1);
        tx_hex.push(hex::encode(&cb));
        tx_hex.extend(job.tx_hex.clone());

        let req = SubmitRequest {
            height: job.height,
            header: SubmitHeader {
                version: 1,
                prev_hash: hex::encode(job.prev_hash),
                merkle_root: hex::encode(mr),
                time: ntime,
                bits: format!("{:08x}", job.bits),
                nonce,
                hash: hex::encode(hash),
            },
            tx_hex,
            submit_source: "pool_stratum".to_string(),
            auxpow_hex: None,
        };

        mark_candidate_submitted();
        mark_block_submit_attempt();
        let url = format!("{}/rpc/submit_block", config.rpc_base.trim_end_matches('/'));
        let client = reqwest::Client::builder().build()?;
        let resp = client
            .post(url)
            .bearer_auth(&config.rpc_token)
            .json(&req)
            .send()
            .await?;
        if resp.status().is_success() {
            mark_submit_accepted();
            info!("[block] submitted worker={} height={}", worker, job.height);
            let row = FoundBlockRecord {
                height: job.height,
                hash: hex::encode(hash),
                time: unix_now_secs(),
                worker: worker.to_string(),
                address: worker_address(&worker),
            };
            if let Err(e) = append_found_block(&config.found_blocks_file, &row) {
                warn!("[block] record append failed worker={} height={} err={}", worker, job.height, e);
            }
        } else {
            mark_submit_rejected();
            warn!("[block] submit failed status={} worker={}", resp.status(), worker);
        }
    }

    maybe_update_vardiff_after_accepted_share(conn_id, wr, session, config, &worker).await?;
    Ok(true)
}

async fn maybe_update_vardiff_after_accepted_share(
    conn_id: u64,
    wr: &mut tokio::net::tcp::OwnedWriteHalf,
    session: &mut SessionState,
    config: &StratumConfig,
    worker: &str,
) -> Result<()> {
    if config.vardiff_enabled {
        let now = unix_now_secs();
        if let Some(last_share) = session.last_share_ts {
            let observed = now.saturating_sub(last_share);
            let since_retarget = now.saturating_sub(session.last_retarget_ts);
            if since_retarget >= config.vardiff_retarget_secs {
                let mut new_diff = session.difficulty;
                let fast_threshold = (config.vardiff_target_share_secs / 2).max(1);
                let slow_threshold = config.vardiff_target_share_secs.saturating_mul(2);
                if observed < fast_threshold {
                    new_diff = (session.difficulty * 2.0).min(config.vardiff_max_diff);
                } else if observed > slow_threshold {
                    new_diff = (session.difficulty / 2.0).max(config.vardiff_min_diff);
                }
                if (new_diff - session.difficulty).abs() > f64::EPSILON {
                    let old = session.difficulty;
                    session.difficulty = new_diff;
                    session.last_retarget_ts = now;
                    info!(
                        "[vardiff] worker={} old_diff={} new_diff={} observed_share_s={} target_s={}",
                        worker,
                        old,
                        new_diff,
                        observed,
                        config.vardiff_target_share_secs
                    );
                    send_set_difficulty(wr, conn_id, session.worker.as_deref(), session.difficulty).await?;
                }
            }
        }
        session.last_share_ts = Some(now);
    }
    Ok(())
}

async fn send_set_difficulty(
    wr: &mut tokio::net::tcp::OwnedWriteHalf,
    conn_id: u64,
    worker: Option<&str>,
    diff: f64,
) -> Result<()> {
    let worker_name = worker.unwrap_or("-");
    info!(
        "[diff] send conn={} worker={} assigned_diff={}",
        conn_id, worker_name, diff
    );
    let msg = json!({"id": Value::Null, "method": "mining.set_difficulty", "params": [diff]});
    write_json(wr, &msg).await
}

async fn send_notify(
    wr: &mut tokio::net::tcp::OwnedWriteHalf,
    session: &SessionState,
    job: &Job,
    clean_jobs: bool,
) -> Result<()> {
    let pkh = session.pkh.ok_or_else(|| anyhow!("unauthorized"))?;

    let (prev_hex, cb1_hex, cb2_hex, branches) = if let Some(snap) = &session.current_snapshot {
        if snap.auxpow_mode {
            // AuxPoW: send parent block data (zeros prev, empty branches, parent coinbase)
            (
                hex::encode(snap.prev_hash_internal),
                hex::encode(&snap.coinbase_prefix),
                hex::encode(&snap.coinbase_suffix),
                snap.branches.iter().map(hex::encode).collect::<Vec<_>>(),
            )
        } else {
            let (cb1, cb2) = coinbase_prefix_suffix(job.height, job.coinbase_value, &pkh, session.coinbase_bip34);
            (hex::encode(job.prev_hash), hex::encode(&cb1), hex::encode(&cb2), job.branches.iter().map(hex::encode).collect())
        }
    } else {
        let (cb1, cb2) = coinbase_prefix_suffix(job.height, job.coinbase_value, &pkh, session.coinbase_bip34);
        (hex::encode(job.prev_hash), hex::encode(&cb1), hex::encode(&cb2), job.branches.iter().map(hex::encode).collect())
    };

    info!(
        "[notify] adapter_kind={} worker={} job={} version=00000001 prevhash={} nbits={} ntime={} extranonce1={} coinbase1={} coinbase2={} branches={}",
        session.adapter_kind.as_str(),
        session.worker.as_deref().unwrap_or("-"),
        job.job_id,
        prev_hex,
        job.nbits_hex,
        job.ntime_hex,
        hex::encode(&session.extranonce1),
        cb1_hex,
        cb2_hex,
        branches.join(",")
    );
    let msg = json!({
        "id": Value::Null,
        "method": "mining.notify",
        "params": [
            job.job_id,
            prev_hex,
            cb1_hex,
            cb2_hex,
            branches,
            "00000001",
            job.nbits_hex,
            job.ntime_hex,
            clean_jobs
        ]
    });
    write_json(wr, &msg).await
}

fn decode_hex4(s: &str) -> Result<[u8; 4]> {
    let raw = hex::decode(s).map_err(|e| anyhow!("hex decode: {e}"))?;
    let out: [u8; 4] = raw
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("expected 4-byte hex, got {} bytes", raw.len()))?;
    Ok(out)
}

fn header_bytes_from_wire(
    version: [u8; 4],
    prev_hash: [u8; 32],
    merkle_root: [u8; 32],
    ntime: [u8; 4],
    nbits: [u8; 4],
    nonce: [u8; 4],
) -> [u8; 80] {
    let mut h = [0u8; 80];
    h[0..4].copy_from_slice(&version);
    h[4..36].copy_from_slice(&prev_hash);
    h[36..68].copy_from_slice(&merkle_root);
    h[68..72].copy_from_slice(&ntime);
    h[72..76].copy_from_slice(&nbits);
    h[76..80].copy_from_slice(&nonce);
    h
}

fn cpuminer_miner_header_wire(
    snapshot: &CanonicalJobSnapshot,
    coinbase_hash_internal: [u8; 32],
    ntime_hex: &str,
    nonce_hex: &str,
) -> Result<[u8; 80]> {
    let ntime = parse_u32_hex(ntime_hex)?;
    let nonce = parse_u32_hex(nonce_hex)?;
    Ok(header_bytes(
        snapshot.version,
        snapshot.prev_hash_internal,
        coinbase_hash_internal,
        ntime,
        snapshot.bits,
        nonce,
    ))
}

fn reverse_4(input: [u8; 4]) -> [u8; 4] {
    [input[3], input[2], input[1], input[0]]
}

fn reverse_32(mut input: [u8; 32]) -> [u8; 32] {
    input.reverse();
    input
}

fn swap4_bytes_each_word(input: [u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..8 {
        let j = i * 4;
        out[j] = input[j + 3];
        out[j + 1] = input[j + 2];
        out[j + 2] = input[j + 1];
        out[j + 3] = input[j];
    }
    out
}

fn biguint_to_32hex(v: &BigUint) -> String {
    let mut bytes = v.to_bytes_be();
    if bytes.len() > 32 {
        bytes = bytes[bytes.len() - 32..].to_vec();
    }
    if bytes.len() < 32 {
        let mut padded = vec![0u8; 32 - bytes.len()];
        padded.extend_from_slice(&bytes);
        bytes = padded;
    }
    hex::encode(bytes)
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn write_json(wr: &mut tokio::net::tcp::OwnedWriteHalf, v: &Value) -> Result<()> {
    let mut s = serde_json::to_string(v)?;
    s.push('\n');
    wr.write_all(s.as_bytes()).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use irium_node_rs::block::Block as CoreBlock;

    fn test_config(mode: MinerFamilyMode) -> StratumConfig {
        StratumConfig {
            bind: "127.0.0.1:0".to_string(),
            metrics_bind: None,
            default_diff: 1.0,
            extranonce1_size: 4,
            refresh_ms: 1000,
            rpc_base: "http://127.0.0.1:1".to_string(),
            rpc_token: "test".to_string(),
            pow_limit: BigUint::from_bytes_be(&[0xff; 32]),
            hash_cmp_mode: HashCmpMode::Be,
            soft_accept_invalid_shares: false,
            miner_family_mode: mode,
            adapter_mode: AdapterMode::Auto,
            native_rewardable_enabled: false,
            sharecheck_samples: 4,
            vardiff_enabled: false,
            vardiff_min_diff: 1.0,
            vardiff_max_diff: 1024.0,
            vardiff_target_share_secs: 15,
            vardiff_retarget_secs: 90,
            max_template_age_seconds: 300,
            coinbase_bip34: true,
            found_blocks_file: "/tmp/irium-phase1-found-blocks.jsonl".to_string(),
            keepalive_notify_secs: 30,
            auxpow_activation_height: None,
            // v1.9.23 — disable connection gating in unit tests so the
            // existing fixtures don't have to think about it.
            max_sessions: 0,
            max_conn_per_ip: 0,
            conn_window_secs: 0,
            ban_threshold: 0,
            ban_duration_secs: 0,
        }
    }

    fn test_session(mode: AdapterKind) -> SessionState {
        SessionState {
            extranonce1: vec![0, 0, 0, 1],
            worker: Some("QTestAddress.worker1".to_string()),
            pkh: Some([0x11; 20]),
            difficulty: 0.0001,
            current_job: None,
            current_snapshot: None,
            last_share_ts: None,
            last_retarget_ts: 0,
            coinbase_bip34: true,
            adapter_kind: mode,
        }
    }

    fn test_job() -> Job {
        Job {
            job_id: "0000000000000001".to_string(),
            height: 12345,
            prev_hash: [0x22; 32],
            bits: 0x1d00ffff,
            nbits_hex: "1d00ffff".to_string(),
            ntime_hex: "5f5e1000".to_string(),
            coinbase_value: 50_0000_0000,
            tx_hex: vec![],
            branches: vec![],
            template_target_hex: biguint_to_32hex(&target_from_bits(0x1d00ffff)),
        }
    }

    fn native_test_job() -> Job {
        Job {
            job_id: "native-job-0001".to_string(),
            height: 22222,
            prev_hash: [0x44; 32],
            bits: 0x207fffff,
            nbits_hex: "207fffff".to_string(),
            ntime_hex: "5f5e10aa".to_string(),
            coinbase_value: 50_0000_0000,
            tx_hex: vec![],
            branches: vec![],
            template_target_hex: biguint_to_32hex(&target_from_bits(0x207fffff)),
        }
    }

    fn native_fixture() -> (StratumConfig, SessionState, CanonicalJobSnapshot, NativeIssuedJob, NativeSubmit, CanonicalSolve) {
        let mut config = test_config(MinerFamilyMode::Asic);
        config.adapter_mode = AdapterMode::NativeRewardableOnly;
        config.native_rewardable_enabled = true;
        let session = test_session(AdapterKind::NativeRewardableReserved);
        let snapshot = build_canonical_job_snapshot(&native_test_job(), &session, &config).unwrap();
        let issued = build_native_rewardable_job(&snapshot, &session, &config).unwrap();
        let submit = NativeSubmit {
            job_id: snapshot.job_id.clone(),
            extranonce2_hex: "01020304".to_string(),
            ntime_hex: format!("{:08x}", snapshot.base_ntime),
            nonce_hex: "0a0b0c0d".to_string(),
        };
        let solve = decode_native_rewardable_submit(&snapshot, &submit).unwrap();
        (config, session, snapshot, issued, submit, solve)
    }

    fn process_native_submit_result_for_test(
        snapshot: &CanonicalJobSnapshot,
        solve: &CanonicalSolve,
        result: NodeSubmitResult,
    ) -> Result<Option<RoundEligibleRecord>> {
        if !solve.share_ok {
            mark_rejected_share();
            return Ok(None);
        }

        mark_accepted_share();
        mark_rewardable_share_accepted();

        if !rewardable_candidate_allowed(solve) {
            return Ok(None);
        }

        mark_candidate_detected();
        let _ = build_canonical_block_hex(snapshot, solve)?;
        mark_candidate_submitted();
        mark_block_submit_attempt();

        match result {
            NodeSubmitResult::Accepted {
                canonical_block_hash,
                accepted_height,
            } => {
                mark_submit_accepted();
                mark_chain_height_advanced_by_pool();
                let record = RoundEligibleRecord {
                    height: accepted_height,
                    job_id: snapshot.job_id.clone(),
                    template_fingerprint: snapshot.template_fingerprint.clone(),
                    canonical_block_hash,
                    accepted_at_unix: unix_now_secs(),
                };
                mark_round_eligible(&record)?;
                Ok(Some(record))
            }
            NodeSubmitResult::Rejected { .. } => {
                mark_submit_rejected();
                Ok(None)
            }
        }
    }

    static TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn test_guard() -> std::sync::MutexGuard<'static, ()> {
        TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn reset_phase1_counters() {
        ACCEPTED_SHARES.store(0, Ordering::SeqCst);
        REJECTED_SHARES.store(0, Ordering::SeqCst);
        CANDIDATES_DETECTED.store(0, Ordering::SeqCst);
        CANDIDATES_SUBMITTED.store(0, Ordering::SeqCst);
        SUBMIT_ACCEPTED.store(0, Ordering::SeqCst);
        SUBMIT_REJECTED.store(0, Ordering::SeqCst);
        BLOCK_SUBMIT_ATTEMPTS.store(0, Ordering::SeqCst);
        REWARDABLE_SHARES_ACCEPTED.store(0, Ordering::SeqCst);
        ROUNDS_ELIGIBLE.store(0, Ordering::SeqCst);
        CHAIN_HEIGHT_ADVANCED_BY_POOL.store(0, Ordering::SeqCst);
        COMPAT_SOLVED_SHARES.store(0, Ordering::SeqCst);
        COMPAT_BLOCK_LIKE_SHARES.store(0, Ordering::SeqCst);
        COMPAT_NONREWARDABLE_EVENTS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn cpuminer_adapter_is_nonrewardable() {
        let _guard = test_guard();
        let adapter = CpuminerCompatibilityAdapter;
        assert_eq!(adapter.adapter_id(), "cpuminer_compat");
        assert!(!adapter.rewardable());
    }

    #[test]
    fn cpuminer_share_flow_still_accepts_with_large_target() {
        let _guard = test_guard();
        let config = test_config(MinerFamilyMode::Cpuminer);
        let session = test_session(AdapterKind::CpuminerCompatibility);
        let snapshot = build_canonical_job_snapshot(&test_job(), &session).unwrap();
        let submit = SubmitTuple {
            job_id: snapshot.job_id.clone(),
            extranonce2_hex: "00000000".to_string(),
            ntime_hex: format!("{:08x}", snapshot.base_ntime),
            nonce_hex: "00000001".to_string(),
            rolled_version_hex: None,
        };
        let adapter = CpuminerCompatibilityAdapter;
        let solve = adapter.decode_submit(&snapshot, &session, &config, &submit).unwrap();
        assert!(solve.share_ok);
        assert!(!solve.rewardable);
        assert_eq!(solve.adapter_id, "cpuminer_compat");
    }

    #[test]
    fn cpuminer_rewardable_flow_is_blocked_by_design() {
        let _guard = test_guard();
        let solve = CanonicalSolve {
            adapter_id: "cpuminer_compat",
            rewardable: false,
            share_variant: "synthetic",
            extranonce2_hex: "00000000".to_string(),
            ntime_hex: "5f5e1000".to_string(),
            nonce_hex: "00000001".to_string(),
            coinbase_hex: "00".to_string(),
            coinbase_hash_internal: [0u8; 32],
            canonical_merkle_root: [0u8; 32],
            canonical_header80: [0u8; 80],
            canonical_hash: [0u8; 32],
            share_hash: [0u8; 32],
            share_target: BigUint::from(1u8),
            block_target: BigUint::from(1u8),
            share_ok: true,
            share_block_like: true,
            block_ok: true,
        };
        assert!(!allow_rewardable_promotion(&solve));
    }

    #[test]
    fn cpuminer_block_like_share_only_hits_compatibility_counters() {
        let _guard = test_guard();
        reset_phase1_counters();
        let snapshot = CanonicalJobSnapshot {
            job_id: "job-compat".to_string(),
            template_fingerprint: "fp-compat".to_string(),
            height: 1,
            version: 1,
            prev_hash_internal: [0u8; 32],
            bits: 0x1d00ffff,
            block_target: BigUint::from(1u8),
            coinbase_value: 50_0000_0000,
            base_ntime: 0,
            extranonce1: vec![0, 0, 0, 1],
            extranonce2_size: 4,
            coinbase_prefix: vec![],
            coinbase_suffix: vec![],
            payout_script: vec![],
            tx_hex: vec![],
            tx_hashes_internal: vec![],
            branches: vec![],
            tip_hash_at_job_create: [0u8; 32],
            created_at_unix: 0,
        };
        let solve = CanonicalSolve {
            adapter_id: "cpuminer_compat",
            rewardable: false,
            share_variant: "compat_block_like",
            extranonce2_hex: "00000000".to_string(),
            ntime_hex: "00000000".to_string(),
            nonce_hex: "00000000".to_string(),
            coinbase_hex: "00".to_string(),
            coinbase_hash_internal: [0u8; 32],
            canonical_merkle_root: [0u8; 32],
            canonical_header80: [0u8; 80],
            canonical_hash: [0x11; 32],
            share_hash: [0x22; 32],
            share_target: BigUint::from(1u8),
            block_target: BigUint::from(1u8),
            share_ok: true,
            share_block_like: true,
            block_ok: false,
        };

        let events = process_cpuminer_compat_solve("worker1", &snapshot, &solve);

        assert_eq!(
            events,
            vec![
                CompatEvent::ShareAccepted,
                CompatEvent::CompatSolvedShare,
                CompatEvent::CompatCandidateBlocked,
            ]
        );
        assert_eq!(ACCEPTED_SHARES.load(Ordering::SeqCst), 1);
        assert_eq!(REJECTED_SHARES.load(Ordering::SeqCst), 0);
        assert_eq!(COMPAT_SOLVED_SHARES.load(Ordering::SeqCst), 1);
        assert_eq!(COMPAT_BLOCK_LIKE_SHARES.load(Ordering::SeqCst), 1);
        assert_eq!(COMPAT_NONREWARDABLE_EVENTS.load(Ordering::SeqCst), 1);
        assert_eq!(CANDIDATES_DETECTED.load(Ordering::SeqCst), 0);
        assert_eq!(CANDIDATES_SUBMITTED.load(Ordering::SeqCst), 0);
        assert_eq!(SUBMIT_ACCEPTED.load(Ordering::SeqCst), 0);
        assert_eq!(SUBMIT_REJECTED.load(Ordering::SeqCst), 0);
        assert_eq!(BLOCK_SUBMIT_ATTEMPTS.load(Ordering::SeqCst), 0);
        assert!(!allow_rewardable_promotion(&solve));
    }

    #[test]
    fn native_rewardable_disabled_by_default_keeps_phase1_selection() {
        let _guard = test_guard();
        let config = test_config(MinerFamilyMode::Cpuminer);
        assert!(matches!(
            select_adapter_kind(&config),
            AdapterKind::CpuminerCompatibility
        ));
    }

    #[test]
    fn native_rewardable_adapter_is_rewardable() {
        let _guard = test_guard();
        let adapter = NativeRewardableAdapter;
        assert_eq!(adapter.adapter_id(), "native_rewardable");
        assert!(adapter.rewardable());
    }

    #[test]
    fn native_rewardable_job_builds_from_snapshot() {
        let _guard = test_guard();
        let (_config, _session, snapshot, issued, _submit, _solve) = native_fixture();
        assert_eq!(issued.version_hex, format!("{:08x}", snapshot.version));
        assert_eq!(issued.prevhash_internal_hex, hex::encode(snapshot.prev_hash_internal));
        assert_eq!(issued.nbits_hex, format!("{:08x}", snapshot.bits));
        assert_eq!(issued.ntime_hex, format!("{:08x}", snapshot.base_ntime));
        assert_eq!(issued.extranonce1_hex, hex::encode(&snapshot.extranonce1));
        assert_eq!(issued.extranonce2_size, snapshot.extranonce2_size);
        let marker_extranonce2 = [0x1c, 0xab, 0xad, 0x1d];
        let full = build_native_rewardable_coinbase(&snapshot, &marker_extranonce2).unwrap();
        let mut marker = snapshot.extranonce1.clone();
        marker.extend_from_slice(&marker_extranonce2);
        let pos = full.windows(marker.len()).position(|w| w == marker.as_slice()).unwrap();
        assert_eq!(issued.coinbase1_hex, hex::encode(&full[..pos + snapshot.extranonce1.len()]));
        assert_eq!(issued.coinbase2_hex, hex::encode(&full[pos + marker.len()..]));
        assert_eq!(issued.merkle_branches_internal_hex, snapshot.branches.iter().map(hex::encode).collect::<Vec<_>>());
        assert_eq!(issued.template_fingerprint, snapshot.template_fingerprint);
        assert!(issued.clean_jobs);
    }

    #[test]
    fn native_rewardable_submit_reconstructs_one_canonical_solve() {
        let _guard = test_guard();
        let (_config, _session, snapshot, _issued, submit, solve) = native_fixture();
        let solve2 = decode_native_rewardable_submit(&snapshot, &submit).unwrap();
        assert!(solve.rewardable);
        assert_eq!(solve.adapter_id, "native_rewardable");
        assert_eq!(solve.share_variant, "canonical_native");
        assert_eq!(solve.extranonce2_hex, submit.extranonce2_hex);
        assert_eq!(solve.ntime_hex, submit.ntime_hex);
        assert_eq!(solve.nonce_hex, submit.nonce_hex);
        assert_eq!(solve.coinbase_hex, solve2.coinbase_hex);
        assert_eq!(solve.canonical_merkle_root, solve2.canonical_merkle_root);
        assert_eq!(solve.canonical_header80, solve2.canonical_header80);
        assert_eq!(solve.canonical_hash, solve2.canonical_hash);
        assert_eq!(solve.share_hash, solve.canonical_hash);
    }

    #[test]
    fn canonical_coinbase_reconstruction_matches_expected_bytes() {
        let _guard = test_guard();
        let (_config, session, snapshot, _issued, submit, solve) = native_fixture();
        let extranonce2 = hex::decode(&submit.extranonce2_hex).unwrap();
        let actual = reconstruct_canonical_coinbase(&snapshot, &extranonce2).unwrap();
        let mut full_extranonce = session.extranonce1.clone();
        full_extranonce.extend_from_slice(&extranonce2);
        let expected = build_native_rewardable_coinbase(&snapshot, &extranonce2).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(hex::encode(actual), solve.coinbase_hex);
    }

    #[test]
    fn canonical_merkle_root_matches_full_block_body() {
        let _guard = test_guard();
        let (_config, _session, snapshot, _issued, _submit, solve) = native_fixture();
        let block_hex = build_canonical_block_hex(&snapshot, &solve).unwrap();
        let raw = hex::decode(block_hex).unwrap();
        let (block, consumed) = CoreBlock::deserialize(&raw).expect("core parser should accept canonical block bytes");
        assert_eq!(consumed, raw.len());
        assert_eq!(block.transactions.len(), snapshot.tx_hex.len() + 1);
        assert_eq!(block.merkle_root(), solve.canonical_merkle_root);
        assert_eq!(block.header.merkle_root, solve.canonical_merkle_root);
    }

    #[test]
    fn canonical_header80_matches_expected_bytes() {
        let _guard = test_guard();
        let (_config, _session, snapshot, _issued, submit, solve) = native_fixture();
        let mut expected = [0u8; 80];
        expected[0..4].copy_from_slice(&snapshot.version.to_le_bytes());
        let mut prev_wire = snapshot.prev_hash_internal;
        prev_wire.reverse();
        expected[4..36].copy_from_slice(&prev_wire);
        let mut merkle_wire = solve.canonical_merkle_root;
        merkle_wire.reverse();
        expected[36..68].copy_from_slice(&merkle_wire);
        expected[68..72].copy_from_slice(&parse_u32_hex(&submit.ntime_hex).unwrap().to_le_bytes());
        expected[72..76].copy_from_slice(&snapshot.bits.to_le_bytes());
        expected[76..80].copy_from_slice(&parse_u32_hex(&submit.nonce_hex).unwrap().to_le_bytes());
        assert_eq!(solve.canonical_header80, expected);
    }

    #[test]
    fn native_rewardable_block_candidate_depends_only_on_canonical_hash() {
        let _guard = test_guard();
        let (_config, _session, _snapshot, _issued, _submit, solve) = native_fixture();
        let mut variant = solve.clone();
        variant.block_ok = true;
        variant.share_hash = [0xff; 32];
        assert!(rewardable_candidate_allowed(&variant));
        variant.block_ok = false;
        variant.share_hash = [0u8; 32];
        assert!(!rewardable_candidate_allowed(&variant));
        variant.rewardable = false;
        assert!(!rewardable_candidate_allowed(&variant));
    }

    #[test]
    fn build_canonical_block_hex_roundtrips_through_core_block_parser() {
        let _guard = test_guard();
        let (_config, _session, snapshot, _issued, _submit, solve) = native_fixture();
        let block_hex = build_canonical_block_hex(&snapshot, &solve).unwrap();
        let raw = hex::decode(&block_hex).unwrap();
        let (block, consumed) = CoreBlock::deserialize(&raw).expect("core parser should accept canonical block bytes");
        assert_eq!(consumed, raw.len());
        assert_eq!(hex::encode(block.serialize()), block_hex);
        assert_eq!(block.header.hash(), solve.canonical_hash);
    }

    #[test]
    fn block_submit_result_rejected_preserves_round_ineligible() {
        let _guard = test_guard();
        reset_phase1_counters();
        let (_config, _session, snapshot, _issued, _submit, mut solve) = native_fixture();
        solve.share_ok = true;
        solve.block_ok = true;
        let record = process_native_submit_result_for_test(
            &snapshot,
            &solve,
            NodeSubmitResult::Rejected { reason: "rejected".to_string() },
        ).unwrap();
        assert!(record.is_none());
        assert_eq!(ACCEPTED_SHARES.load(Ordering::SeqCst), 1);
        assert_eq!(REWARDABLE_SHARES_ACCEPTED.load(Ordering::SeqCst), 1);
        assert_eq!(CANDIDATES_DETECTED.load(Ordering::SeqCst), 1);
        assert_eq!(CANDIDATES_SUBMITTED.load(Ordering::SeqCst), 1);
        assert_eq!(BLOCK_SUBMIT_ATTEMPTS.load(Ordering::SeqCst), 1);
        assert_eq!(SUBMIT_ACCEPTED.load(Ordering::SeqCst), 0);
        assert_eq!(SUBMIT_REJECTED.load(Ordering::SeqCst), 1);
        assert_eq!(ROUNDS_ELIGIBLE.load(Ordering::SeqCst), 0);
        assert_eq!(CHAIN_HEIGHT_ADVANCED_BY_POOL.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn block_submit_result_accepted_creates_round_eligible() {
        let _guard = test_guard();
        reset_phase1_counters();
        let (_config, _session, snapshot, _issued, _submit, mut solve) = native_fixture();
        solve.share_ok = true;
        solve.block_ok = true;
        let record = process_native_submit_result_for_test(
            &snapshot,
            &solve,
            NodeSubmitResult::Accepted {
                canonical_block_hash: solve.canonical_hash,
                accepted_height: snapshot.height,
            },
        ).unwrap().expect("accepted submit should create round record");
        assert_eq!(record.height, snapshot.height);
        assert_eq!(record.job_id, snapshot.job_id);
        assert_eq!(record.template_fingerprint, snapshot.template_fingerprint);
        assert_eq!(record.canonical_block_hash, solve.canonical_hash);
        assert_eq!(ACCEPTED_SHARES.load(Ordering::SeqCst), 1);
        assert_eq!(REWARDABLE_SHARES_ACCEPTED.load(Ordering::SeqCst), 1);
        assert_eq!(CANDIDATES_DETECTED.load(Ordering::SeqCst), 1);
        assert_eq!(CANDIDATES_SUBMITTED.load(Ordering::SeqCst), 1);
        assert_eq!(BLOCK_SUBMIT_ATTEMPTS.load(Ordering::SeqCst), 1);
        assert_eq!(SUBMIT_ACCEPTED.load(Ordering::SeqCst), 1);
        assert_eq!(SUBMIT_REJECTED.load(Ordering::SeqCst), 0);
        assert_eq!(ROUNDS_ELIGIBLE.load(Ordering::SeqCst), 1);
        assert_eq!(CHAIN_HEIGHT_ADVANCED_BY_POOL.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cpuminer_compat_path_still_nonrewardable_under_phase2a() {
        let _guard = test_guard();
        let config = test_config(MinerFamilyMode::Cpuminer);
        let session = test_session(AdapterKind::CpuminerCompatibility);
        let snapshot = build_canonical_job_snapshot(&test_job(), &session).unwrap();
        let submit = SubmitTuple {
            job_id: snapshot.job_id.clone(),
            extranonce2_hex: "00000000".to_string(),
            ntime_hex: format!("{:08x}", snapshot.base_ntime),
            nonce_hex: "00000001".to_string(),
            rolled_version_hex: None,
        };
        let solve = CpuminerCompatibilityAdapter.decode_submit(&snapshot, &session, &config, &submit).unwrap();
        assert!(!solve.rewardable);
        assert!(!allow_rewardable_promotion(&solve));
        assert_eq!(solve.adapter_id, "cpuminer_compat");
    }
}
