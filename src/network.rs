use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::storage;

static SEEDLIST_WARN_PRINTED: AtomicBool = AtomicBool::new(false);

#[allow(dead_code)] // baseline path kept for reference; runtime uses seedlist.runtime
const DEFAULT_SEEDLIST_BASELINE: &str = "bootstrap/seedlist.txt";
const DEFAULT_SEEDLIST_RUNTIME: &str = "bootstrap/seedlist.runtime";
const DEFAULT_SEEDLIST_STATIC: &str = "bootstrap/static_peers.txt";
const DEFAULT_PEER_DB: &str = "state/peers.json";

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn now_day() -> i64 {
    (now_secs() / 86_400.0).floor() as i64
}

fn repo_root() -> PathBuf {
    std::env::var("IRIUM_REPO_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

fn normalize_seed(addr: &str) -> Option<String> {
    let candidate = addr.trim();
    if candidate.is_empty() {
        return None;
    }
    if candidate.starts_with("/ip4/") {
        let parts: Vec<&str> = candidate.split('/').collect();
        if parts.len() >= 3 {
            return Some(parts[2].to_string());
        }
        return None;
    }
    if let Ok(ip) = candidate.parse::<IpAddr>() {
        return Some(ip.to_string());
    }
    // handle host:port form; strip port
    if let Ok(sock) = candidate.parse::<SocketAddr>() {
        return Some(sock.ip().to_string());
    }
    None
}

/// Record of an observed peer, mirroring `PeerRecord` in Python.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRecord {
    pub multiaddr: String,
    pub agent: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    pub last_seen: f64,
    pub first_seen: f64,
    #[serde(default)]
    pub seen_days: Vec<i64>,
    pub relay_address: Option<String>,
    pub last_height: Option<u64>,
    pub node_id: Option<String>,
    #[serde(default)]
    pub dialable: bool,
    #[serde(default)]
    pub last_successful_connect: Option<f64>,
    #[serde(default)]
    pub last_successful_handshake: Option<f64>,
}

impl PeerRecord {
    pub fn new(multiaddr: String, agent: Option<String>) -> PeerRecord {
        let t = now_secs();
        let day = (t / 86_400.0).floor() as i64;
        PeerRecord {
            multiaddr,
            agent,
            source: None,
            last_seen: t,
            first_seen: t,
            seen_days: vec![day],
            relay_address: None,
            last_height: None,
            node_id: None,
            dialable: false,
            last_successful_connect: None,
            last_successful_handshake: None,
        }
    }

    pub fn touch(&mut self) {
        self.last_seen = now_secs();
        let day = now_day();
        if !self.seen_days.contains(&day) {
            self.seen_days.push(day);
            self.seen_days.sort_unstable();
            if self.seen_days.len() > 30 {
                let start = self.seen_days.len() - 30;
                self.seen_days = self.seen_days[start..].to_vec();
            }
        }
    }
}

/// Manage baseline + runtime seedlists, mirroring `SeedlistManager`.
#[derive(Debug)]
pub struct SeedlistManager {
    baseline: PathBuf,
    extra: PathBuf,
    runtime: PathBuf,
    limit: usize,
}

impl SeedlistManager {
    pub fn new(limit: usize) -> SeedlistManager {
        let root = repo_root();
        let bootstrap = storage::bootstrap_dir();
        let baseline = bootstrap.join("seedlist.txt");
        let extra = bootstrap.join("seedlist.extra");
        let runtime = root.join(DEFAULT_SEEDLIST_RUNTIME);
        if let Some(parent) = runtime.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if !runtime.exists() {
            let _ = fs::write(
                &runtime,
                "# Auto-generated runtime seedlist. Do not edit manually.\n",
            );
        }
        SeedlistManager {
            baseline,
            extra,
            runtime,
            limit,
        }
    }

    fn allow_unsigned_seedlist() -> bool {
        std::env::var("IRIUM_SEEDLIST_ALLOW_UNSIGNED")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }

    /// Distinct days a learned peer must have been seen dialable before it is promoted
    /// into the runtime seedlist.
    ///
    /// This is a sybil control, not a tuning knob: whatever is in the runtime seedlist is
    /// what this node will dial on its next cold start, so anything that gets promoted
    /// cheaply gets to place itself in the bootstrap path of every node that met it.
    /// Seven days of *observed, dialable* uptime cannot be faked by an address that
    /// appears for an afternoon. `seen_days` retains 30 days and dialable records survive
    /// 14 days idle, so the requirement is reachable for an honest peer.
    fn runtime_seed_min_days() -> i64 {
        std::env::var("IRIUM_RUNTIME_SEED_DAYS")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(7)
            .clamp(1, 30)
    }

    fn runtime_seed_max_idle_hours() -> f64 {
        std::env::var("IRIUM_RUNTIME_SEED_MAX_IDLE_HOURS")
            .ok()
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(24.0)
            .clamp(1.0, 168.0)
    }

    fn seedlist_sig_principal() -> String {
        std::env::var("IRIUM_SEEDLIST_SIG_PRINCIPAL")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| "bootstrap-signer".to_string())
    }

    fn seedlist_sig_namespace() -> String {
        std::env::var("IRIUM_SEEDLIST_SIG_NAMESPACE")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| "file".to_string())
    }

    fn seedlist_allowed_signers() -> PathBuf {
        std::env::var("IRIUM_SEEDLIST_ALLOWED_SIGNERS")
            .map(PathBuf::from)
            .unwrap_or_else(|_| storage::bootstrap_dir().join("trust/allowed_signers"))
    }

    fn seedlist_sig_path(&self) -> PathBuf {
        PathBuf::from(format!("{}.sig", self.baseline.to_string_lossy()))
    }

    fn verify_seedlist_signature(&self) -> bool {
        let seed_data = match fs::read_to_string(&self.baseline) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let sig_path = self.seedlist_sig_path();
        if !sig_path.exists() {
            return false;
        }
        let allowed = Self::seedlist_allowed_signers();
        if !allowed.exists() {
            return false;
        }
        let principal = Self::seedlist_sig_principal();
        let namespace = Self::seedlist_sig_namespace();
        let mut child = match Command::new("ssh-keygen")
            .arg("-Y")
            .arg("verify")
            .arg("-f")
            .arg(&allowed)
            .arg("-I")
            .arg(&principal)
            .arg("-n")
            .arg(&namespace)
            .arg("-s")
            .arg(&sig_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(_) => return false,
        };
        if let Some(stdin) = child.stdin.as_mut() {
            if stdin.write_all(seed_data.as_bytes()).is_err() {
                return false;
            }
        }
        match child.wait() {
            Ok(status) => status.success(),
            Err(_) => false,
        }
    }
    fn load_seed_entries(&self, path: &PathBuf) -> Vec<String> {
        let mut entries = Vec::new();
        let text = match fs::read_to_string(path) {
            Ok(t) => t,
            Err(_) => return entries,
        };
        for line in text.lines() {
            if let Some(ip) = normalize_seed(line) {
                if !entries.contains(&ip) {
                    entries.push(ip);
                }
            }
        }
        entries
    }

    fn load_runtime_entries(&self) -> Vec<String> {
        self.load_seed_entries(&self.runtime)
    }

    fn load_extra_entries(&self) -> Vec<String> {
        self.load_seed_entries(&self.extra)
    }

    fn load_static_entries(&self) -> Vec<String> {
        let mut entries = self.load_seed_entries(&repo_root().join(DEFAULT_SEEDLIST_STATIC));
        if let Ok(raw) = std::env::var("IRIUM_STATIC_PEERS") {
            for token in raw.split([',', ' ', '\n', '\t']) {
                if let Some(ip) = normalize_seed(token) {
                    if !entries.contains(&ip) {
                        entries.push(ip);
                    }
                }
            }
        }
        entries
    }

    fn runtime_seed_min_count() -> usize {
        std::env::var("IRIUM_RUNTIME_SEED_MIN_COUNT")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(8)
            .clamp(1, 64)
    }

    fn stale_dialable_prune_hours() -> f64 {
        std::env::var("IRIUM_PEER_STALE_DIALABLE_HOURS")
            .ok()
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(24.0 * 14.0)
            .clamp(24.0, 24.0 * 60.0)
    }

    fn stale_undialable_prune_hours() -> f64 {
        std::env::var("IRIUM_PEER_STALE_UNDIALABLE_HOURS")
            .ok()
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(24.0)
            .clamp(1.0, 24.0 * 14.0)
    }

    pub fn write_runtime_entries<I>(&self, entries: I)
    where
        I: IntoIterator<Item = String>,
    {
        let mut unique = Vec::new();
        for addr in entries {
            if let Some(ip) = normalize_seed(&addr) {
                if !unique.contains(&ip) {
                    unique.push(ip);
                }
                if unique.len() >= self.limit {
                    break;
                }
            }
        }
        let timestamp = chrono::Utc::now().to_rfc3339();
        let mut body = format!("# Runtime seedlist refreshed {}\n", timestamp);
        for entry in &unique {
            body.push_str(entry);
            body.push('\n');
        }
        let _ = fs::write(&self.runtime, body);
    }

    pub fn merged_seedlist(&self) -> Vec<String> {
        let mut combined = Vec::new();
        for ip in self.load_static_entries() {
            if !combined.contains(&ip) {
                combined.push(ip);
            }
        }
        let baseline_entries = if self.verify_seedlist_signature() {
            self.load_seed_entries(&self.baseline)
        } else if Self::allow_unsigned_seedlist() {
            if !SEEDLIST_WARN_PRINTED.swap(true, Ordering::Relaxed) {
                eprintln!(
                    "[SECURITY WARNING] Seedlist signature invalid or missing. \nBootstrapping from unsigned peer list because IRIUM_SEEDLIST_ALLOW_UNSIGNED=1. \nThis disables seedlist integrity protection. Do not use in production without a valid signature."
                );
            }
            self.load_seed_entries(&self.baseline)
        } else {
            if !SEEDLIST_WARN_PRINTED.swap(true, Ordering::Relaxed) {
                eprintln!(
                    "[warn] Seedlist signature invalid or missing; skipping baseline seeds. \nSet IRIUM_SEEDLIST_ALLOW_UNSIGNED=1 to override (not recommended for production)."
                );
            }
            Vec::new()
        };
        for ip in baseline_entries {
            if !combined.contains(&ip) {
                combined.push(ip);
            }
        }
        for ip in self.load_extra_entries() {
            if !combined.contains(&ip) {
                combined.push(ip);
            }
        }
        for ip in self.load_runtime_entries() {
            if !combined.contains(&ip) {
                combined.push(ip);
            }
            if combined.len() >= self.limit {
                break;
            }
        }
        combined
    }
}

/// Persistent peer directory, mirroring Python `PeerDirectory`.
#[derive(Debug)]
pub struct PeerDirectory {
    db_path: PathBuf,
    seed_manager: SeedlistManager,
    records: HashMap<String, PeerRecord>,
    last_flush: f64,
    last_learned_log_at: f64,
    suppressed_learned_bursts: usize,
    suppressed_learned_total: usize,
    suppressed_learned_private: usize,
    suppressed_learned_duplicate: usize,
    suppressed_learned_rate_limited: usize,
}

impl Default for PeerDirectory {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerDirectory {
    pub fn new() -> PeerDirectory {
        let db_path = storage::state_dir().join("peers.json");
        if !db_path.exists() {
            let root = repo_root();
            let legacy = root.join(DEFAULT_PEER_DB);
            if legacy.exists() {
                if let Some(parent) = db_path.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                let _ = fs::copy(&legacy, &db_path);
            }
        }
        if let Some(parent) = db_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let seed_manager = SeedlistManager::new(512);
        let mut dir = PeerDirectory {
            db_path,
            seed_manager,
            records: HashMap::new(),
            last_flush: 0.0,
            last_learned_log_at: 0.0,
            suppressed_learned_bursts: 0,
            suppressed_learned_total: 0,
            suppressed_learned_private: 0,
            suppressed_learned_duplicate: 0,
            suppressed_learned_rate_limited: 0,
        };
        dir.load();
        dir.prune_stale_records();
        dir
    }

    fn load(&mut self) {
        let text = match fs::read_to_string(&self.db_path) {
            Ok(t) => t,
            Err(_) => return,
        };
        let parsed: serde_json::Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) => return,
        };
        let map = match parsed.as_object() {
            Some(m) => m,
            None => return,
        };
        for (addr, value) in map {
            if let Some(obj) = value.as_object() {
                let agent = obj
                    .get("agent")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let seen_days = obj
                    .get("seen_days")
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter().filter_map(|v| v.as_i64()).collect::<Vec<i64>>())
                    .unwrap_or_default();
                let first_seen = obj
                    .get("first_seen")
                    .and_then(|v| v.as_f64())
                    .unwrap_or_else(now_secs);
                let last_seen = obj
                    .get("last_seen")
                    .and_then(|v| v.as_f64())
                    .unwrap_or_else(now_secs);
                let relay_address = obj
                    .get("relay_address")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let last_height = obj.get("last_height").and_then(|v| v.as_u64());
                let node_id = obj
                    .get("node_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let source = obj
                    .get("source")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let dialable = obj
                    .get("dialable")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let last_successful_connect =
                    obj.get("last_successful_connect").and_then(|v| v.as_f64());
                let last_successful_handshake = obj
                    .get("last_successful_handshake")
                    .and_then(|v| v.as_f64());
                self.records.insert(
                    addr.clone(),
                    PeerRecord {
                        multiaddr: addr.clone(),
                        agent,
                        source,
                        first_seen,
                        last_seen,
                        seen_days,
                        relay_address,
                        last_height,
                        node_id,
                        dialable,
                        last_successful_connect,
                        last_successful_handshake,
                    },
                );
            }
        }
    }

    /// TEST-ONLY: allow loopback/private peers so a multi-node harness can run on one box.
    ///
    /// Without this, two local nodes can never peer (`peers=0` while each knows the other is
    /// in its seedlist), so fork/convergence behaviour can only ever be "harness-proven" in
    /// unit tests against a reconstruction -- which is exactly how a fork fix reached
    /// production unvalidated on 2026-07-28.
    ///
    /// HARD-REFUSED ON MAINNET (network_id == 0) regardless of the env var: a mainnet-byte
    /// node that accepted private peers is precisely the isolation gap that lets a "test"
    /// node touch the live network.
    fn allow_local_peers() -> bool {
        if crate::activation::network_id_byte() == 0 {
            return false;
        }
        std::env::var("IRIUM_P2P_ALLOW_LOCAL")
            .map(|v| {
                let v = v.trim();
                v == "1" || v.eq_ignore_ascii_case("true")
            })
            .unwrap_or(false)
    }

    fn is_private_or_unroutable(ip: &IpAddr) -> bool {
        if Self::allow_local_peers() {
            return false;
        }
        match ip {
            IpAddr::V4(v4) => {
                v4.is_private()
                    || v4.is_loopback()
                    || v4.is_link_local()
                    || v4.is_broadcast()
                    || v4.is_documentation()
                    || v4.is_unspecified()
                    || *v4 == Ipv4Addr::new(0, 0, 0, 0)
            }
            IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_unique_local()
                    || v6.is_unicast_link_local()
                    || (v6.segments()[0] == 0x2001 && v6.segments()[1] == 0x0db8)
                    || *v6 == Ipv6Addr::LOCALHOST
            }
        }
    }

    fn flush_suppressed_learned_summary(&mut self, force: bool) {
        if self.suppressed_learned_bursts == 0 {
            return;
        }
        let now = now_secs();
        if !force && self.last_learned_log_at > 0.0 && now - self.last_learned_log_at < 180.0 {
            return;
        }
        eprintln!(
            "peer_mgr: learned bursts suppressed={} peers={} private={} duplicate={} rate_limited={}",
            self.suppressed_learned_bursts,
            self.suppressed_learned_total,
            self.suppressed_learned_private,
            self.suppressed_learned_duplicate,
            self.suppressed_learned_rate_limited,
        );
        self.suppressed_learned_bursts = 0;
        self.suppressed_learned_total = 0;
        self.suppressed_learned_private = 0;
        self.suppressed_learned_duplicate = 0;
        self.suppressed_learned_rate_limited = 0;
        self.last_learned_log_at = now;
    }

    fn insert_peer_hint_inner(&mut self, multiaddr: String) -> Result<bool, &'static str> {
        let normalized = normalize_seed(&multiaddr).ok_or("invalid")?;
        let ip: IpAddr = normalized.parse().map_err(|_| "invalid")?;
        if Self::is_private_or_unroutable(&ip) {
            return Err("private");
        }
        if self.records.contains_key(&multiaddr)
            || self
                .records
                .keys()
                .any(|existing| normalize_seed(existing).as_deref() == Some(normalized.as_str()))
        {
            return Ok(false);
        }
        let t = now_secs();
        self.records.insert(
            multiaddr.clone(),
            PeerRecord {
                multiaddr,
                agent: None,
                source: Some("gossip".to_string()),
                last_seen: 0.0,
                first_seen: t,
                seen_days: Vec::new(),
                relay_address: None,
                last_height: None,
                node_id: None,
                dialable: false,
                last_successful_connect: None,
                last_successful_handshake: None,
            },
        );
        Ok(true)
    }

    fn flush(&mut self) {
        let now = now_secs();
        if now - self.last_flush < 2.0 {
            return;
        }
        self.last_flush = now;

        let mut map = serde_json::Map::new();
        for (addr, rec) in &self.records {
            let mut obj = serde_json::Map::new();
            if let Some(agent) = &rec.agent {
                obj.insert(
                    "agent".to_string(),
                    serde_json::Value::String(agent.clone()),
                );
            }
            if let Some(source) = &rec.source {
                obj.insert(
                    "source".to_string(),
                    serde_json::Value::String(source.clone()),
                );
            }
            if let Some(relay) = &rec.relay_address {
                obj.insert(
                    "relay_address".to_string(),
                    serde_json::Value::String(relay.clone()),
                );
            }
            if !rec.seen_days.is_empty() {
                let arr = rec
                    .seen_days
                    .iter()
                    .map(|v| serde_json::Value::Number(serde_json::Number::from(*v)))
                    .collect();
                obj.insert("seen_days".to_string(), serde_json::Value::Array(arr));
            }
            obj.insert(
                "first_seen".to_string(),
                serde_json::Value::Number(
                    serde_json::Number::from_f64(rec.first_seen)
                        .unwrap_or_else(|| serde_json::Number::from(0)),
                ),
            );
            obj.insert(
                "last_seen".to_string(),
                serde_json::Value::Number(
                    serde_json::Number::from_f64(rec.last_seen)
                        .unwrap_or_else(|| serde_json::Number::from(0)),
                ),
            );
            if let Some(h) = rec.last_height {
                obj.insert(
                    "last_height".to_string(),
                    serde_json::Value::Number(serde_json::Number::from(h)),
                );
            }
            if let Some(id) = &rec.node_id {
                obj.insert("node_id".to_string(), serde_json::Value::String(id.clone()));
            }
            obj.insert(
                "dialable".to_string(),
                serde_json::Value::Bool(rec.dialable),
            );
            if let Some(ts) = rec.last_successful_connect {
                obj.insert(
                    "last_successful_connect".to_string(),
                    serde_json::Value::Number(
                        serde_json::Number::from_f64(ts)
                            .unwrap_or_else(|| serde_json::Number::from(0)),
                    ),
                );
            }
            if let Some(ts) = rec.last_successful_handshake {
                obj.insert(
                    "last_successful_handshake".to_string(),
                    serde_json::Value::Number(
                        serde_json::Number::from_f64(ts)
                            .unwrap_or_else(|| serde_json::Number::from(0)),
                    ),
                );
            }
            map.insert(addr.clone(), serde_json::Value::Object(obj));
        }
        let value = serde_json::Value::Object(map);
        if let Ok(text) = serde_json::to_string_pretty(&value) {
            let tmp = self
                .db_path
                .with_extension(format!("json.tmp.{}", std::process::id()));
            if let Ok(mut file) = fs::File::create(&tmp) {
                if file.write_all(text.as_bytes()).is_ok() && file.sync_all().is_ok() {
                    if let Err(e) = fs::rename(&tmp, &self.db_path) {
                        eprintln!("Failed to rename peer db {}: {}", self.db_path.display(), e);
                        let _ = fs::remove_file(&tmp);
                    }
                } else {
                    let _ = fs::remove_file(&tmp);
                    eprintln!("Failed to write peer db {}", self.db_path.display());
                }
            } else {
                eprintln!("Failed to create peer db tmp {}", tmp.display());
            }
        }
    }

    /// Register a successful connection and update runtime seedlist via policy.
    pub fn register_connection(
        &mut self,
        multiaddr: String,
        agent: Option<String>,
        relay_address: Option<String>,
        node_id: Option<String>,
    ) {
        let entry = self
            .records
            .entry(multiaddr.clone())
            .or_insert_with(|| PeerRecord::new(multiaddr.clone(), agent.clone()));
        entry.agent = agent;
        if entry.source.is_none() {
            entry.source = Some("live".to_string());
        }
        entry.relay_address = relay_address.or(entry.relay_address.clone());
        entry.node_id = node_id.or(entry.node_id.clone());
        let now = now_secs();
        entry.last_successful_connect = Some(now);
        entry.last_successful_handshake = Some(now);
        entry.touch();

        self.flush();
        self.refresh_seedlist_with_policy();
    }

    /// Register a peer from a hint list without marking it active.
    pub fn register_peer_hint(&mut self, multiaddr: String) {
        if matches!(self.insert_peer_hint_inner(multiaddr), Ok(true)) {
            self.flush();
        }
    }

    /// Register a batch of learned peers and coalesce repetitive giant duplicate bursts.
    pub fn register_peer_hints(&mut self, peers: Vec<String>, announced_by: Option<&str>) {
        let mut accepted = 0usize;
        let mut invalid = 0usize;
        let mut private = 0usize;
        let mut duplicate = 0usize;
        for multiaddr in peers {
            match self.insert_peer_hint_inner(multiaddr) {
                Ok(true) => accepted += 1,
                Ok(false) => duplicate += 1,
                Err("private") => private += 1,
                Err(_) => invalid += 1,
            }
        }
        let total = accepted + invalid + private + duplicate;
        if total == 0 {
            return;
        }
        let suppressible_burst =
            accepted == 0 && invalid == 0 && total >= 64 && private + duplicate == total;
        if suppressible_burst {
            self.suppressed_learned_bursts = self.suppressed_learned_bursts.saturating_add(1);
            self.suppressed_learned_total = self.suppressed_learned_total.saturating_add(total);
            self.suppressed_learned_private =
                self.suppressed_learned_private.saturating_add(private);
            self.suppressed_learned_duplicate =
                self.suppressed_learned_duplicate.saturating_add(duplicate);
            self.flush_suppressed_learned_summary(false);
        } else {
            self.flush_suppressed_learned_summary(true);
            eprintln!(
                "peer_mgr: learned source={} total={} accepted={} dropped={} reason=invalid:{} private:{} duplicate:{} rate_limited:{} capped:{}",
                announced_by.unwrap_or("unknown"),
                total,
                accepted,
                invalid + private + duplicate,
                invalid,
                private,
                duplicate,
                0,
                0,
            );
            self.last_learned_log_at = now_secs();
        }
        if accepted > 0 {
            self.flush();
        }
    }

    /// Mark a peer as seen without changing its metadata.
    pub fn mark_dialable(&mut self, multiaddr: &str) {
        if let Some(rec) = self.records.get_mut(multiaddr) {
            let now = now_secs();
            let mut changed = false;
            if !rec.dialable {
                rec.dialable = true;
                changed = true;
            }
            if rec.last_successful_handshake.is_none() {
                rec.last_successful_handshake = Some(now);
                changed = true;
            }
            rec.touch();
            if changed {
                self.flush();
            }
        }
    }

    pub fn mark_seen(&mut self, multiaddr: &str) {
        if let Some(rec) = self.records.get_mut(multiaddr) {
            let before = rec.seen_days.len();
            rec.touch();
            if rec.seen_days.len() != before {
                self.flush();
            }
        }
    }

    pub fn peers(&self) -> Vec<PeerRecord> {
        self.records.values().cloned().collect()
    }

    pub fn relay_address_for_peer(&self, socket: &SocketAddr) -> Option<String> {
        let multiaddr = format!("/ip4/{}/tcp/{}", socket.ip(), socket.port());
        self.records
            .get(&multiaddr)
            .and_then(|r| r.relay_address.clone())
    }

    fn static_seed_set(&self) -> HashSet<String> {
        self.seed_manager
            .load_static_entries()
            .into_iter()
            .collect()
    }

    fn prune_stale_records(&mut self) {
        let now = now_secs();
        let protected = self.static_seed_set();
        let dialable_cutoff = SeedlistManager::stale_dialable_prune_hours();
        let undialable_cutoff = SeedlistManager::stale_undialable_prune_hours();
        self.records.retain(|addr, rec| {
            if normalize_seed(addr)
                .as_ref()
                .map(|ip| protected.contains(ip))
                .unwrap_or(false)
            {
                return true;
            }
            let last_touch = if rec.last_seen > 0.0 {
                rec.last_seen
            } else {
                rec.first_seen
            };
            let idle_hours = ((now - last_touch).max(0.0)) / 3600.0;
            if rec.dialable {
                idle_hours <= dialable_cutoff
            } else {
                idle_hours <= undialable_cutoff
            }
        });
    }

    /// Promote recently dialable learned peers into the runtime seedlist with
    /// scoring/aging, while keeping static seeds as a baseline.
    pub fn refresh_seedlist_with_policy(&mut self) {
        self.prune_stale_records();
        let now = now_secs();
        let today = now_day();
        let min_days = SeedlistManager::runtime_seed_min_days();
        let max_idle = SeedlistManager::runtime_seed_max_idle_hours();
        let start_day = today.saturating_sub(min_days.saturating_sub(1));
        let mut seeds = self.seed_manager.load_static_entries();

        for rec in self.records.values() {
            if !rec.dialable {
                continue;
            }
            let idle_hours = (now - rec.last_seen) / 3600.0;
            if idle_hours > max_idle {
                continue;
            }
            let mut active_days = 0;
            for day in start_day..=today {
                if rec.seen_days.contains(&day) {
                    active_days += 1;
                }
            }
            // Must be present on min_days DISTINCT days, not merely once inside the
            // window. The old `>= 1` made runtime_seed_min_days non-binding at any value:
            // it widened the lookback but never demanded multi-day presence, so a peer
            // seen for a single afternoon was promoted into the bootstrap list of every
            // node that saw it -- a free sybil foothold in the one list a cold node trusts.
            if active_days >= min_days {
                if let Some(ip) = normalize_seed(&rec.multiaddr) {
                    seeds.push(ip);
                }
            }
        }

        seeds.sort();
        seeds.dedup();
        if seeds.is_empty() {
            return;
        }

        let min_runtime = SeedlistManager::runtime_seed_min_count();
        if seeds.len() < min_runtime {
            for prev in self.seed_manager.load_runtime_entries() {
                if !seeds.contains(&prev) {
                    seeds.push(prev);
                }
                if seeds.len() >= min_runtime {
                    break;
                }
            }
        }
        self.seed_manager.write_runtime_entries(seeds);
    }

    pub fn record_height(&mut self, multiaddr: &str, height: u64) {
        if let Some(rec) = self.records.get_mut(multiaddr) {
            rec.last_height = Some(height);
            rec.touch();
            self.flush();
        }
    }

    pub fn clear_height(&mut self, multiaddr: &str) {
        if let Some(rec) = self.records.get_mut(multiaddr) {
            rec.last_height = None;
            rec.touch();
            self.flush();
        }
    }
}

#[cfg(test)]
mod local_peer_gate_tests {
    use super::*;


    /// The local-peer affordance exists so a multi-node harness can run on one box (without
    /// it two local nodes never peer, so fork/convergence can only be "proven" against a
    /// reconstruction -- which is how an unvalidated fork fix reached production 2026-07-28).
    /// It must be impossible to enable for MAINNET: a mainnet-byte node accepting private
    /// peers is exactly the isolation gap that lets a test node reach the live network.
    /// Promotion into the runtime seedlist is a SYBIL control, so pin its boundary by
    /// driving the REAL `refresh_seedlist_with_policy`, not a copy of its arithmetic.
    ///
    /// Whatever lands in the runtime seedlist is what this node dials on its next cold
    /// start — so a cheap promotion lets an address install itself in the bootstrap path
    /// of every node that ever met it. The rule was `active_days >= 1`, which made
    /// `runtime_seed_min_days` non-binding at ANY setting: one afternoon of uptime was
    /// enough to get in.
    #[test]
    fn runtime_seed_promotion_requires_min_days_of_distinct_uptime() {
        let _env = crate::test_env::guard();

        let home = std::path::PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()));
        let sandbox = home.join(format!(".irium_seedpromo_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&sandbox);
        std::fs::create_dir_all(sandbox.join("bootstrap")).unwrap();
        std::env::set_var("IRIUM_REPO_ROOT", &sandbox);
        std::env::set_var("IRIUM_BOOTSTRAP_DIR", sandbox.join("bootstrap"));
        std::env::set_var("IRIUM_DATA_DIR", &sandbox);
        std::env::set_var("IRIUM_RUNTIME_SEED_DAYS", "7");

        let today = now_day();
        let now = now_secs();
        let mk = |addr: &str, days: i64| {
            let mut rec = PeerRecord::new(addr.to_string(), None);
            rec.dialable = true;
            rec.last_seen = now;               // not idle, so only the day rule decides
            rec.seen_days = (0..days).map(|d| today - d).collect();
            rec
        };
        let veteran = mk("203.0.113.9:38291", 7);
        let newcomer = mk("198.51.100.4:38291", 6);

        let mut dir = PeerDirectory::new();
        dir.records.insert(veteran.multiaddr.clone(), veteran);
        dir.records.insert(newcomer.multiaddr.clone(), newcomer);
        dir.refresh_seedlist_with_policy();

        let promoted = dir.seed_manager.load_runtime_entries();
        let has = |ip: &str| promoted.iter().any(|e| e.starts_with(ip));

        let (v, n) = (has("203.0.113.9"), has("198.51.100.4"));
        std::env::remove_var("IRIUM_RUNTIME_SEED_DAYS");
        std::env::remove_var("IRIUM_REPO_ROOT");
        std::env::remove_var("IRIUM_BOOTSTRAP_DIR");
        std::env::remove_var("IRIUM_DATA_DIR");
        let _ = std::fs::remove_dir_all(&sandbox);

        assert!(v, "7 distinct dialable days must be promoted; got {promoted:?}");
        assert!(
            !n,
            "6 days must NOT be promoted — that is the boundary, and under the old \
             `>= 1` rule this peer (and a one-afternoon peer) sailed in: {promoted:?}"
        );
    }

    /// The default is the control that actually ships; an env-only fix protects nobody.
    #[test]
    fn runtime_seed_min_days_defaults_to_seven() {
        let _env = crate::test_env::guard();
        std::env::remove_var("IRIUM_RUNTIME_SEED_DAYS");
        assert_eq!(SeedlistManager::runtime_seed_min_days(), 7);
        // Idle eviction is the other half of the policy and must stay at 24h.
        assert_eq!(SeedlistManager::runtime_seed_max_idle_hours(), 24.0);
    }

    #[test]
    fn allow_local_peers_is_refused_on_mainnet_and_opt_in_elsewhere() {
        let _env = crate::test_env::guard();
                let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        let private: IpAddr = "192.168.1.5".parse().unwrap();

        std::env::set_var("IRIUM_NETWORK", "mainnet");
        std::env::set_var("IRIUM_P2P_ALLOW_LOCAL", "1");
        assert_eq!(crate::activation::network_id_byte(), 0, "mainnet context");
        assert!(
            PeerDirectory::is_private_or_unroutable(&loopback),
            "mainnet must NEVER accept loopback peers, flag or not"
        );
        assert!(
            PeerDirectory::is_private_or_unroutable(&private),
            "mainnet must NEVER accept private peers, flag or not"
        );

        std::env::set_var("IRIUM_NETWORK", "devnet");
        assert!(
            !PeerDirectory::is_private_or_unroutable(&loopback),
            "devnet with the flag set must accept loopback so a local harness can peer"
        );
        std::env::remove_var("IRIUM_P2P_ALLOW_LOCAL");
        assert!(
            PeerDirectory::is_private_or_unroutable(&loopback),
            "default (flag unset) must still reject loopback"
        );
        std::env::remove_var("IRIUM_NETWORK");
    }
}
