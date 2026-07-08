use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::storage;

const REPUTATION_PRUNE_AFTER_SECS: f64 = 30.0 * 24.0 * 60.0 * 60.0;
const REPUTATION_LOW_ACTIVITY_THRESHOLD: u32 = 3;

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn normalize_peer_id(peer_id: &str) -> String {
    // NAT peers connect from a different ephemeral source port each time.
    // Track reputation by IP only so one host = one entry.
    if let Some(colon) = peer_id.rfind(':') {
        if peer_id[colon + 1..].parse::<u16>().is_ok() {
            return peer_id[..colon].to_string();
        }
    }
    peer_id.to_string()
}

fn default_reputation_path() -> PathBuf {
    let path = storage::state_dir().join("peer_reputation.json");
    if !path.exists() {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/".to_string());
        let legacy = PathBuf::from(home).join(".irium/peer_reputation.json");
        if legacy.exists() {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::copy(&legacy, &path);
        }
    }
    path
}

/// FIX #128: env-tunable ban threshold. On small networks (~30 users)
/// the legacy hardcoded score < 20 banned legitimate peers after ~17
/// connectivity blips. Operators can now relax (or disable) reputation
/// bans without rebuilding by exporting
/// IRIUM_REPUTATION_BAN_SCORE_THRESHOLD. Clamped to [-100, 100] -
/// values <= score-floor (0) effectively disable banning since
/// update_score floors at 0 anyway.
pub fn reputation_ban_score_threshold() -> i32 {
    std::env::var("IRIUM_REPUTATION_BAN_SCORE_THRESHOLD")
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
        .map(|v| v.clamp(-100, 100))
        .unwrap_or(20)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerReputation {
    pub peer_id: String,
    pub score: i32,
    pub successful_connections: u32,
    pub failed_connections: u32,
    /// FIX #128: pure-telemetry counter incremented when a peer is
    /// merely unreachable (dial failure / connection drop, no bytes
    /// exchanged). Does NOT subtract from `score` - unreachability
    /// is not the peer's fault on a small network where most peers
    /// are offline at any given time.
    #[serde(default)]
    pub dial_failures: u32,
    pub blocks_received: u32,
    pub invalid_blocks: u32,
    pub uptime_proofs: u32,
    pub last_seen: f64,
}

impl PeerReputation {
    pub fn new(peer_id: String) -> PeerReputation {
        PeerReputation {
            peer_id,
            score: 100,
            successful_connections: 0,
            failed_connections: 0,
            dial_failures: 0,
            blocks_received: 0,
            invalid_blocks: 0,
            uptime_proofs: 0,
            last_seen: now_secs(),
        }
    }

    pub fn update_score(&mut self) {
        let mut score = 100_i32;
        score += (self.successful_connections as i32) * 2;
        // FIX #128: dial_failures intentionally absent from the score
        // formula. Only handshake-stage failures (failed_connections)
        // count against the peer.
        score -= (self.failed_connections as i32) * 5;
        score += (self.blocks_received as i32) * 10;
        score -= (self.invalid_blocks as i32) * 50;
        score += (self.uptime_proofs as i32) * 5;
        if score < 0 {
            score = 0;
        }
        if score > 1000 {
            score = 1000;
        }
        self.score = score;
    }

    pub fn is_trusted(&self) -> bool {
        self.score > 80
    }

    pub fn is_banned(&self) -> bool {
        self.score < reputation_ban_score_threshold()
    }

    pub fn total_activity(&self) -> u32 {
        self.successful_connections
            .saturating_add(self.failed_connections)
            .saturating_add(self.dial_failures)
            .saturating_add(self.blocks_received)
            .saturating_add(self.invalid_blocks)
            .saturating_add(self.uptime_proofs)
    }

    pub fn should_prune(&self, now: f64) -> bool {
        if self.last_seen <= 0.0 || now <= self.last_seen {
            return false;
        }
        let age = now - self.last_seen;
        age >= REPUTATION_PRUNE_AFTER_SECS
            && (self.successful_connections == 0
                || self.total_activity() <= REPUTATION_LOW_ACTIVITY_THRESHOLD)
    }
}

#[derive(Debug)]
pub struct ReputationManager {
    path: PathBuf,
    reputations: HashMap<String, PeerReputation>,
}

impl Default for ReputationManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ReputationManager {
    pub fn banned_count(&self) -> usize {
        self.reputations.values().filter(|r| r.is_banned()).count()
    }

    pub fn new() -> ReputationManager {
        let path = default_reputation_path();
        let mut mgr = ReputationManager {
            path,
            reputations: HashMap::new(),
        };
        mgr.load();
        mgr
    }

    fn load(&mut self) {
        let text = match fs::read_to_string(&self.path) {
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
        let now = now_secs();
        let mut pruned_any = false;
        let mut migrated_any = false;
        for (peer_id, value) in map {
            if let Some(obj) = value.as_object() {
                let key = normalize_peer_id(peer_id);
                if key != *peer_id {
                    migrated_any = true;
                }
                let mut rep = PeerReputation::new(key.clone());
                rep.score = obj.get("score").and_then(|v| v.as_i64()).unwrap_or(100) as i32;
                rep.successful_connections = obj
                    .get("successful_connections")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32;
                rep.failed_connections = obj
                    .get("failed_connections")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32;
                rep.dial_failures = obj
                    .get("dial_failures")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32;
                rep.blocks_received = obj
                    .get("blocks_received")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32;
                rep.invalid_blocks = obj
                    .get("invalid_blocks")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32;
                rep.uptime_proofs = obj
                    .get("uptime_proofs")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32;
                rep.last_seen = obj
                    .get("last_seen")
                    .and_then(|v| v.as_f64())
                    .unwrap_or_else(now_secs);
                rep.update_score();
                if rep.should_prune(now) {
                    pruned_any = true;
                    continue;
                }
                match self.reputations.entry(key) {
                    std::collections::hash_map::Entry::Occupied(mut e) => {
                        let existing = e.get_mut();
                        if rep.successful_connections > existing.successful_connections
                            || (rep.successful_connections == existing.successful_connections
                                && rep.score > existing.score)
                        {
                            *existing = rep;
                        }
                    }
                    std::collections::hash_map::Entry::Vacant(e) => {
                        e.insert(rep);
                    }
                }
            }
        }
        if pruned_any || migrated_any {
            self.save();
        }
    }

    fn save(&self) {
        if let Some(parent) = self.path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let mut map = serde_json::Map::new();
        for (peer_id, rep) in &self.reputations {
            map.insert(
                peer_id.clone(),
                serde_json::json!({
                    "score": rep.score,
                    "successful_connections": rep.successful_connections,
                    "failed_connections": rep.failed_connections,
                    "dial_failures": rep.dial_failures,
                    "blocks_received": rep.blocks_received,
                    "invalid_blocks": rep.invalid_blocks,
                    "uptime_proofs": rep.uptime_proofs,
                    "last_seen": rep.last_seen,
                }),
            );
        }
        let value = serde_json::Value::Object(map);
        let Ok(text) = serde_json::to_string_pretty(&value) else {
            return;
        };
        let tmp = self
            .path
            .with_extension(format!("json.tmp.{}", process::id()));
        if let Ok(mut file) = File::create(&tmp) {
            if file.write_all(text.as_bytes()).is_ok() && file.sync_all().is_ok() {
                let _ = fs::rename(&tmp, &self.path);
                return;
            }
        }
        let _ = fs::remove_file(&tmp);
    }

    pub fn get_reputation(&mut self, peer_id: &str) -> &mut PeerReputation {
        self.reputations
            .entry(peer_id.to_string())
            .or_insert_with(|| PeerReputation::new(peer_id.to_string()))
    }

    pub fn record_success(&mut self, peer_id: &str) {
        let rep = self.get_reputation(peer_id);
        rep.successful_connections = rep.successful_connections.saturating_add(1);
        rep.last_seen = now_secs();
        rep.update_score();
        self.save();
    }

    pub fn record_failure(&mut self, peer_id: &str) {
        let rep = self.get_reputation(peer_id);
        rep.failed_connections = rep.failed_connections.saturating_add(1);
        rep.last_seen = now_secs();
        rep.update_score();
        self.save();
    }

    /// FIX #128: bump the dial_failures counter for telemetry but do
    /// NOT touch `score`. Used at sites that only know the peer is
    /// unreachable (no bytes exchanged) - they don't represent
    /// misbehavior on a small network where most peers are offline at
    /// any given time. Existing `record_failure` is reserved for true
    /// handshake-stage failures (peer reachable, sent invalid data).
    pub fn record_dial_failure(&mut self, peer_id: &str) {
        let rep = self.get_reputation(peer_id);
        rep.dial_failures = rep.dial_failures.saturating_add(1);
        rep.last_seen = now_secs();
        // No update_score call: dial_failures is informational only.
        self.save();
    }

    pub fn record_block(&mut self, peer_id: &str, valid: bool) {
        let rep = self.get_reputation(peer_id);
        if valid {
            rep.blocks_received = rep.blocks_received.saturating_add(1);
        } else {
            rep.invalid_blocks = rep.invalid_blocks.saturating_add(1);
        }
        rep.last_seen = now_secs();
        rep.update_score();
        self.save();
    }

    pub fn record_uptime_proof(&mut self, peer_id: &str) {
        let rep = self.get_reputation(peer_id);
        rep.uptime_proofs = rep.uptime_proofs.saturating_add(1);
        rep.last_seen = now_secs();
        rep.update_score();
        self.save();
    }

    pub fn is_banned(&mut self, peer_id: &str) -> bool {
        self.get_reputation(peer_id).is_banned()
    }

    pub fn score_of(&mut self, peer_id: &str) -> i32 {
        let rep = self.get_reputation(peer_id);
        rep.score
    }

    pub fn record_decode_error(&mut self, peer_id: &str) {
        let rep = self.get_reputation(peer_id);
        rep.invalid_blocks = rep.invalid_blocks.saturating_add(1);
        rep.last_seen = now_secs();
        rep.update_score();
        self.save();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prunes_old_low_activity_entries() {
        let now = now_secs();
        let mut rep = PeerReputation::new("1.2.3.4:38291".to_string());
        rep.last_seen = now - (REPUTATION_PRUNE_AFTER_SECS + 60.0);
        rep.failed_connections = 1;
        rep.update_score();
        assert!(rep.should_prune(now));
    }

    #[test]
    fn keeps_old_successful_entries() {
        let now = now_secs();
        let mut rep = PeerReputation::new("1.2.3.4:38291".to_string());
        rep.last_seen = now - (REPUTATION_PRUNE_AFTER_SECS + 60.0);
        rep.successful_connections = 2;
        rep.failed_connections = 5;
        rep.blocks_received = 2;
        rep.update_score();
        assert!(!rep.should_prune(now));
    }

    // ── FIX #128: dial-fail vs handshake-fail + env threshold ──────────

    #[test]
    fn fix128_dial_failures_do_not_subtract_score() {
        let mut rep = PeerReputation::new("1.2.3.4:38291".to_string());
        rep.dial_failures = 100;
        rep.update_score();
        // Score formula: base 100, no dial_failures term -> stays 100.
        assert_eq!(rep.score, 100);
        assert!(!rep.is_banned());
    }

    #[test]
    fn fix128_handshake_failures_still_subtract_score_as_before() {
        let mut rep = PeerReputation::new("1.2.3.4:38291".to_string());
        rep.failed_connections = 17;
        rep.update_score();
        // 100 - (17 * 5) = 15, below the default ban threshold of 20.
        assert_eq!(rep.score, 15);
        assert!(rep.is_banned());
    }

    #[test]
    fn fix128_is_banned_respects_env_threshold() {
        let mut rep = PeerReputation::new("1.2.3.4:38291".to_string());
        rep.failed_connections = 17;
        rep.update_score();
        assert_eq!(rep.score, 15);
        // Default (no env set, or value 20): banned.
        std::env::remove_var("IRIUM_REPUTATION_BAN_SCORE_THRESHOLD");
        assert!(rep.is_banned(), "score 15 must be banned at default threshold 20");
        // Operator sets a relaxed threshold: not banned anymore.
        std::env::set_var("IRIUM_REPUTATION_BAN_SCORE_THRESHOLD", "10");
        assert!(!rep.is_banned(), "score 15 must NOT be banned at threshold 10");
        // Clamp test: out-of-range high value gets clamped to 100.
        std::env::set_var("IRIUM_REPUTATION_BAN_SCORE_THRESHOLD", "9999");
        assert!(rep.is_banned(), "out-of-range high clamps to 100, score 15 still banned");
        // Clamp test: out-of-range low value gets clamped to -100.
        std::env::set_var("IRIUM_REPUTATION_BAN_SCORE_THRESHOLD", "-9999");
        assert!(!rep.is_banned(), "out-of-range low clamps to -100, score 15 not banned");
        std::env::remove_var("IRIUM_REPUTATION_BAN_SCORE_THRESHOLD");
    }

    #[test]
    fn fix128_record_dial_failure_increments_counter_and_updates_last_seen() {
        let tmp = std::env::temp_dir().join(format!(
            "irium_rep_test_{}_{}.json",
            std::process::id(),
            (now_secs() * 1000.0) as u64
        ));
        let mut mgr = ReputationManager {
            path: tmp.clone(),
            reputations: HashMap::new(),
        };
        let before = now_secs();
        mgr.record_dial_failure("9.9.9.9");
        let rep = mgr.get_reputation("9.9.9.9");
        assert_eq!(rep.dial_failures, 1);
        assert_eq!(rep.failed_connections, 0);
        assert_eq!(rep.score, 100, "dial failure must not move score");
        assert!(rep.last_seen >= before);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn fix128_reputation_json_legacy_file_without_dial_failures_loads() {
        // Build a legacy-format JSON object (no dial_failures field)
        // and confirm load() defaults the missing field to 0 without
        // crashing.
        let tmp = std::env::temp_dir().join(format!(
            "irium_rep_legacy_{}_{}.json",
            std::process::id(),
            (now_secs() * 1000.0) as u64
        ));
        let legacy = serde_json::json!({
            "1.2.3.4": {
                "score": 100,
                "successful_connections": 2,
                "failed_connections": 1,
                "blocks_received": 0,
                "invalid_blocks": 0,
                "uptime_proofs": 0,
                "last_seen": now_secs(),
            }
        });
        std::fs::write(&tmp, legacy.to_string()).unwrap();
        let mut mgr = ReputationManager {
            path: tmp.clone(),
            reputations: HashMap::new(),
        };
        mgr.load();
        let rep = mgr.get_reputation("1.2.3.4");
        assert_eq!(rep.dial_failures, 0, "missing dial_failures must default to 0");
        assert_eq!(rep.failed_connections, 1);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn fix128_reputation_ban_threshold_default_is_20() {
        std::env::remove_var("IRIUM_REPUTATION_BAN_SCORE_THRESHOLD");
        assert_eq!(reputation_ban_score_threshold(), 20);
    }
}
