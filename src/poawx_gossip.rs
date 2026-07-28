//! Phase 20 Step 6D: node-side in-memory PoAW-X role-gossip cache + wire DTOs.
//!
//! This is the node half of the live cross-process bridge. The node P2P receive
//! loop ingests `MessageType::PoawxRolePrecommit`/`PoawxRoleReveal` gossip into
//! this cache; loopback RPC endpoints let the pool fetch the collected payloads
//! (and submit local ones for P2P rebroadcast). Testnet/devnet only, **mainnet
//! hard-off**, default disabled. It validates the SAME Step 6C wire payloads
//! (versioned envelopes wrapping the Step 6B DTO model), dedupes by stable
//! digest, bounds by a height window, and prunes old heights.
//!
//! It does NOT affect consensus: Step 6A hidden-precommit enforcement stays
//! purely block-driven (a node that never receives a gossip message is not
//! penalised beyond the already-enforced missing-precommit rule). The cache is a
//! process-global singleton (`global_cache()`) so the P2P task(s) and the axum
//! RPC handlers share one instance without threading an Arc through `P2PNode`.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::poawx::{
    role_precommit_commitment, role_precommit_leaf, ROLE_COMPUTE_CONTRIBUTOR,
    ROLE_SUPPORT_CONTRIBUTOR, ROLE_VERIFY_CONTRIBUTOR,
};

/// Versioned role-gossip envelope version (matches the pool's `ROLE_GOSSIP_VERSION`).
pub const ROLE_GOSSIP_VERSION: u8 = 1;
/// Conservative upper bound on an accepted role-gossip payload (bytes).
pub const ROLE_GOSSIP_MAX_BYTES: usize = 4096;
/// Soft cap on the dedupe seen-set before it is cleared.
pub const ROLE_GOSSIP_SEEN_CAP: usize = 8192;
/// Default height window (overridable via `IRIUM_POAWX_ROLE_GOSSIP_WINDOW`).
pub const DEFAULT_ROLE_GOSSIP_WINDOW: u64 = 64;

/// Height window for accepting precommits/reveals: `[tip, tip + window]`.
pub fn role_gossip_window() -> u64 {
    std::env::var("IRIUM_POAWX_ROLE_GOSSIP_WINDOW")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&w| w > 0 && w <= 100_000)
        .unwrap_or(DEFAULT_ROLE_GOSSIP_WINDOW)
}

/// Whether node role gossip is enabled. **Mainnet hard-off** (network id 0);
/// requires `IRIUM_POAWX_ROLE_GOSSIP_ENABLED=1`. Default off.
pub fn role_gossip_enabled() -> bool {
    if crate::activation::network_id_byte() == 0 {
        return false; // mainnet
    }
    std::env::var("IRIUM_POAWX_ROLE_GOSSIP_ENABLED")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}

fn is_production_role(role_id: u8) -> bool {
    matches!(
        role_id,
        ROLE_COMPUTE_CONTRIBUTOR | ROLE_VERIFY_CONTRIBUTOR | ROLE_SUPPORT_CONTRIBUTOR
    )
}

fn decode20(s: &str) -> Option<[u8; 20]> {
    let b = hex::decode(s.trim()).ok()?;
    if b.len() != 20 {
        return None;
    }
    let mut a = [0u8; 20];
    a.copy_from_slice(&b);
    Some(a)
}

fn decode32(s: &str) -> Option<[u8; 32]> {
    let b = hex::decode(s.trim()).ok()?;
    if b.len() != 32 {
        return None;
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&b);
    Some(a)
}

// ── Wire DTOs (field-identical to the pool's Step 6B/6C JSON) ─────────────────

/// Role precommit DTO. HIDES secret/nonce — only `commitment_hash`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RolePrecommitDto {
    pub network_id: u8,
    pub target_height: u64,
    pub role_id: u8,
    pub solver_pkh: String,
    pub commitment_hash: String,
    #[serde(default)]
    pub worker: String,
}

/// Role reveal DTO. Carries secret/nonce + claim fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoleRevealDto {
    pub network_id: u8,
    pub target_height: u64,
    pub role_id: u8,
    pub lane_id: u8,
    pub solver_pkh: String,
    pub secret: String,
    pub nonce: String,
    pub commitment_hash: String,
    pub claim_digest: String,
}

/// Versioned gossip envelope for a precommit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolePrecommitGossip {
    pub gossip_version: u8,
    pub precommit: RolePrecommitDto,
}

/// Versioned gossip envelope for a reveal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleRevealGossip {
    pub gossip_version: u8,
    pub reveal: RoleRevealDto,
}

impl RolePrecommitGossip {
    pub fn new(precommit: RolePrecommitDto) -> Self {
        Self {
            gossip_version: ROLE_GOSSIP_VERSION,
            precommit,
        }
    }
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > ROLE_GOSSIP_MAX_BYTES {
            return Err("role gossip: precommit payload too large".to_string());
        }
        let g: RolePrecommitGossip = serde_json::from_slice(bytes)
            .map_err(|e| format!("role gossip: malformed precommit: {e}"))?;
        if g.gossip_version != ROLE_GOSSIP_VERSION {
            return Err(format!(
                "role gossip: unsupported precommit version {}",
                g.gossip_version
            ));
        }
        Ok(g)
    }
}

impl RoleRevealGossip {
    pub fn new(reveal: RoleRevealDto) -> Self {
        Self {
            gossip_version: ROLE_GOSSIP_VERSION,
            reveal,
        }
    }
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > ROLE_GOSSIP_MAX_BYTES {
            return Err("role gossip: reveal payload too large".to_string());
        }
        let g: RoleRevealGossip = serde_json::from_slice(bytes)
            .map_err(|e| format!("role gossip: malformed reveal: {e}"))?;
        if g.gossip_version != ROLE_GOSSIP_VERSION {
            return Err(format!(
                "role gossip: unsupported reveal version {}",
                g.gossip_version
            ));
        }
        Ok(g)
    }
}

/// Decoded key + digest fields for a validated precommit.
struct PcKey {
    key: (u64, u8, [u8; 20]),
    leaf: [u8; 32],
    commitment: [u8; 32],
}

fn validate_precommit(dto: &RolePrecommitDto, expected_network: u8) -> Result<PcKey, String> {
    if expected_network == 0 {
        return Err("role gossip: mainnet hard-off".to_string());
    }
    if dto.network_id != expected_network {
        return Err("role gossip: precommit network_id mismatch".to_string());
    }
    if !is_production_role(dto.role_id) {
        return Err(format!(
            "role gossip: bad precommit role_id {}",
            dto.role_id
        ));
    }
    let solver = decode20(&dto.solver_pkh).ok_or("role gossip: bad precommit solver_pkh")?;
    let commitment =
        decode32(&dto.commitment_hash).ok_or("role gossip: bad precommit commitment_hash")?;
    let leaf = role_precommit_leaf(
        dto.network_id,
        dto.target_height,
        dto.role_id,
        &solver,
        &commitment,
    );
    Ok(PcKey {
        key: (dto.target_height, dto.role_id, solver),
        leaf,
        commitment,
    })
}

struct RvKey {
    key: (u64, u8, [u8; 20]),
    commitment: [u8; 32],
    digest: [u8; 32],
}

fn validate_reveal(dto: &RoleRevealDto, expected_network: u8) -> Result<RvKey, String> {
    if expected_network == 0 {
        return Err("role gossip: mainnet hard-off".to_string());
    }
    if dto.network_id != expected_network {
        return Err("role gossip: reveal network_id mismatch".to_string());
    }
    if !is_production_role(dto.role_id) {
        return Err(format!("role gossip: bad reveal role_id {}", dto.role_id));
    }
    let solver = decode20(&dto.solver_pkh).ok_or("role gossip: bad reveal solver_pkh")?;
    let secret = decode32(&dto.secret).ok_or("role gossip: bad reveal secret")?;
    let nonce = decode32(&dto.nonce).ok_or("role gossip: bad reveal nonce")?;
    let commitment =
        decode32(&dto.commitment_hash).ok_or("role gossip: bad reveal commitment_hash")?;
    let claim_digest = decode32(&dto.claim_digest).ok_or("role gossip: bad reveal claim_digest")?;
    // commitment binding: a mutated secret/nonce fails closed.
    if role_precommit_commitment(&secret, &nonce) != commitment {
        return Err("role gossip: reveal commitment != H(secret||nonce)".to_string());
    }
    let mut h = Sha256::new();
    h.update(b"IRIUM_POAWX_ROLE_REVEAL_GOSSIP_V1");
    h.update([dto.network_id]);
    h.update(dto.target_height.to_le_bytes());
    h.update([dto.role_id, dto.lane_id]);
    h.update(solver);
    h.update(nonce);
    h.update(secret);
    h.update(claim_digest);
    h.update(commitment);
    Ok(RvKey {
        key: (dto.target_height, dto.role_id, solver),
        commitment,
        digest: h.finalize().into(),
    })
}

/// Outcome of ingesting one gossip payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GossipOutcome {
    /// Valid and newly stored — caller SHOULD rebroadcast.
    AcceptedNew,
    /// Valid but already seen — do NOT rebroadcast.
    Duplicate,
    /// Invalid / disabled / out-of-window / no-matching-precommit — not stored,
    /// never rebroadcast.
    Rejected(String),
}

impl GossipOutcome {
    pub fn should_rebroadcast(&self) -> bool {
        matches!(self, GossipOutcome::AcceptedNew)
    }
    pub fn accepted(&self) -> bool {
        matches!(self, GossipOutcome::AcceptedNew | GossipOutcome::Duplicate)
    }
}

/// Process-global node role-gossip cache (one per node process).
pub struct NodeRoleGossipCache {
    precommits: Mutex<BTreeMap<(u64, u8, [u8; 20]), RolePrecommitDto>>,
    reveals: Mutex<BTreeMap<(u64, u8, [u8; 20]), RoleRevealDto>>,
    seen: Mutex<BTreeSet<[u8; 32]>>,
    tip: AtomicU64,
}

impl Default for NodeRoleGossipCache {
    fn default() -> Self {
        Self {
            precommits: Mutex::new(BTreeMap::new()),
            reveals: Mutex::new(BTreeMap::new()),
            seen: Mutex::new(BTreeSet::new()),
            tip: AtomicU64::new(0),
        }
    }
}

impl NodeRoleGossipCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_tip(&self, tip: u64) {
        self.tip.store(tip, Ordering::Relaxed);
    }
    pub fn tip(&self) -> u64 {
        self.tip.load(Ordering::Relaxed)
    }

    fn in_window(&self, target: u64) -> bool {
        let tip = self.tip();
        target >= tip && target <= tip.saturating_add(role_gossip_window())
    }

    fn already_seen(&self, d: &[u8; 32]) -> bool {
        self.seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(d)
    }
    fn mark_seen(&self, d: [u8; 32]) {
        let mut s = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        if s.len() >= ROLE_GOSSIP_SEEN_CAP {
            s.clear();
        }
        s.insert(d);
    }

    /// Ingest a precommit gossip envelope (raw JSON bytes).
    pub fn ingest_precommit_bytes(&self, bytes: &[u8]) -> GossipOutcome {
        if !role_gossip_enabled() {
            return GossipOutcome::Rejected("role gossip disabled".to_string());
        }
        let net = crate::activation::network_id_byte();
        let g = match RolePrecommitGossip::decode(bytes) {
            Ok(g) => g,
            Err(e) => return GossipOutcome::Rejected(e),
        };
        let v = match validate_precommit(&g.precommit, net) {
            Ok(v) => v,
            Err(e) => return GossipOutcome::Rejected(e),
        };
        if !self.in_window(g.precommit.target_height) {
            return GossipOutcome::Rejected(format!(
                "role gossip: precommit height {} outside window",
                g.precommit.target_height
            ));
        }
        if self.already_seen(&v.leaf) {
            return GossipOutcome::Duplicate;
        }
        {
            let mut pc = self.precommits.lock().unwrap_or_else(|e| e.into_inner());
            match pc.get(&v.key) {
                Some(existing) => {
                    if decode32(&existing.commitment_hash) != Some(v.commitment) {
                        return GossipOutcome::Rejected(
                            "role gossip: precommit dup with different commitment".to_string(),
                        );
                    }
                    // idempotent — already stored; treat as duplicate.
                    self.mark_seen(v.leaf);
                    return GossipOutcome::Duplicate;
                }
                None => {
                    pc.insert(v.key, g.precommit.clone());
                }
            }
        }
        self.mark_seen(v.leaf);
        GossipOutcome::AcceptedNew
    }

    /// Ingest a reveal gossip envelope. A reveal with no matching precommit is
    /// rejected gracefully (no crash), per the Step 6B store policy.
    pub fn ingest_reveal_bytes(&self, bytes: &[u8]) -> GossipOutcome {
        if !role_gossip_enabled() {
            return GossipOutcome::Rejected("role gossip disabled".to_string());
        }
        let net = crate::activation::network_id_byte();
        let g = match RoleRevealGossip::decode(bytes) {
            Ok(g) => g,
            Err(e) => return GossipOutcome::Rejected(e),
        };
        let v = match validate_reveal(&g.reveal, net) {
            Ok(v) => v,
            Err(e) => return GossipOutcome::Rejected(e),
        };
        if !self.in_window(g.reveal.target_height) {
            return GossipOutcome::Rejected(format!(
                "role gossip: reveal height {} outside window",
                g.reveal.target_height
            ));
        }
        // require a matching precommit (same key + commitment).
        {
            let pc = self.precommits.lock().unwrap_or_else(|e| e.into_inner());
            match pc.get(&v.key) {
                Some(existing) if decode32(&existing.commitment_hash) == Some(v.commitment) => {}
                _ => {
                    return GossipOutcome::Rejected(
                        "role gossip: reveal has no matching precommit".to_string(),
                    )
                }
            }
        }
        if self.already_seen(&v.digest) {
            return GossipOutcome::Duplicate;
        }
        {
            let mut rv = self.reveals.lock().unwrap_or_else(|e| e.into_inner());
            match rv.get(&v.key) {
                Some(existing) if *existing != g.reveal => {
                    return GossipOutcome::Rejected(
                        "role gossip: reveal dup with different claim".to_string(),
                    );
                }
                Some(_) => {
                    self.mark_seen(v.digest);
                    return GossipOutcome::Duplicate;
                }
                None => {
                    rv.insert(v.key, g.reveal.clone());
                }
            }
        }
        self.mark_seen(v.digest);
        GossipOutcome::AcceptedNew
    }

    /// Stored precommit envelopes for `target_height` (for the loopback GET).
    pub fn precommits_for(&self, target_height: u64) -> Vec<RolePrecommitGossip> {
        let pc = self.precommits.lock().unwrap_or_else(|e| e.into_inner());
        pc.iter()
            .filter(|((t, _, _), _)| *t == target_height)
            .map(|(_, dto)| RolePrecommitGossip::new(dto.clone()))
            .collect()
    }

    /// Stored reveal envelopes for `target_height` (for the loopback GET).
    pub fn reveals_for(&self, target_height: u64) -> Vec<RoleRevealGossip> {
        let rv = self.reveals.lock().unwrap_or_else(|e| e.into_inner());
        rv.iter()
            .filter(|((t, _, _), _)| *t == target_height)
            .map(|(_, dto)| RoleRevealGossip::new(dto.clone()))
            .collect()
    }

    /// Drop precommits/reveals targeting heights at/below `tip - window`, and
    /// refresh the tip.
    pub fn prune(&self, tip: u64) {
        self.set_tip(tip);
        let cutoff = tip.saturating_sub(role_gossip_window());
        self.precommits
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|k, _| k.0 > cutoff);
        self.reveals
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|k, _| k.0 > cutoff);
    }
}

static GLOBAL_CACHE: OnceLock<NodeRoleGossipCache> = OnceLock::new();

/// The process-global node role-gossip cache. Shared by the P2P receive task(s)
/// and the loopback RPC handlers.
pub fn global_cache() -> &'static NodeRoleGossipCache {
    GLOBAL_CACHE.get_or_init(NodeRoleGossipCache::new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poawx::{assign_lane, role_claim_digest};

    // env-mutating tests serialize on this lock (IRIUM_NETWORK etc.).
    fn env_lock() -> &'static Mutex<()> {
        crate::poawx::poawx_test_env_lock()
    }

    fn enable() {
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_ROLE_GOSSIP_ENABLED", "1");
    }
    fn disable() {
        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_ROLE_GOSSIP_ENABLED");
        std::env::remove_var("IRIUM_POAWX_ROLE_GOSSIP_WINDOW");
    }

    fn pc_dto(
        net: u8,
        h: u64,
        role: u8,
        solver: [u8; 20],
        s: [u8; 32],
        n: [u8; 32],
    ) -> RolePrecommitDto {
        RolePrecommitDto {
            network_id: net,
            target_height: h,
            role_id: role,
            solver_pkh: hex::encode(solver),
            commitment_hash: hex::encode(role_precommit_commitment(&s, &n)),
            worker: String::new(),
        }
    }
    fn rv_dto(
        net: u8,
        h: u64,
        prev: &[u8; 32],
        role: u8,
        solver: [u8; 20],
        s: [u8; 32],
        n: [u8; 32],
    ) -> RoleRevealDto {
        let lane = assign_lane(net, h, prev, role, 0).id();
        let cd = role_claim_digest(net, h, prev, role, lane, &solver, &n, &s);
        RoleRevealDto {
            network_id: net,
            target_height: h,
            role_id: role,
            lane_id: lane,
            solver_pkh: hex::encode(solver),
            secret: hex::encode(s),
            nonce: hex::encode(n),
            commitment_hash: hex::encode(role_precommit_commitment(&s, &n)),
            claim_digest: hex::encode(cd),
        }
    }

    #[test]
    fn node_role_gossip_envelope_roundtrip_hides_secret() {
        let _env = crate::test_env::guard();
        let (s, n) = ([0x11u8; 32], [0x22u8; 32]);
        let pc = pc_dto(1, 2, ROLE_COMPUTE_CONTRIBUTOR, [0xA1u8; 20], s, n);
        let bytes = RolePrecommitGossip::new(pc.clone()).encode();
        assert!(!String::from_utf8(bytes.clone())
            .unwrap()
            .contains(&hex::encode(s)));
        let dec = RolePrecommitGossip::decode(&bytes).unwrap();
        assert_eq!(dec.precommit, pc);
        // bad version / oversize / malformed reject.
        let mut bad = RolePrecommitGossip::new(pc);
        bad.gossip_version = 9;
        assert!(RolePrecommitGossip::decode(&bad.encode()).is_err());
        assert!(RolePrecommitGossip::decode(&vec![b'{'; ROLE_GOSSIP_MAX_BYTES + 1]).is_err());
        assert!(RolePrecommitGossip::decode(b"nope").is_err());
    }

    #[test]
    fn node_cache_ingest_validate_window_dedupe() {
        let _env = crate::test_env::guard();
        let _g = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        enable();
        let net = 1u8;
        let prev = [0x44u8; 32];
        let (s, n) = ([0x31u8; 32], [0x32u8; 32]);
        let cache = NodeRoleGossipCache::new();
        cache.set_tip(1);

        let pc =
            RolePrecommitGossip::new(pc_dto(net, 2, ROLE_COMPUTE_CONTRIBUTOR, [0xD1u8; 20], s, n))
                .encode();
        // (3) valid stores; (4) duplicate dedupes.
        assert_eq!(
            cache.ingest_precommit_bytes(&pc),
            GossipOutcome::AcceptedNew
        );
        assert_eq!(cache.ingest_precommit_bytes(&pc), GossipOutcome::Duplicate);
        assert_eq!(cache.precommits_for(2).len(), 1);
        // (5) malformed rejects.
        assert!(matches!(
            cache.ingest_precommit_bytes(b"garbage"),
            GossipOutcome::Rejected(_)
        ));
        // (9) stale / far-future reject.
        let stale =
            RolePrecommitGossip::new(pc_dto(net, 0, ROLE_VERIFY_CONTRIBUTOR, [0xD2u8; 20], s, n))
                .encode();
        assert!(matches!(
            cache.ingest_precommit_bytes(&stale),
            GossipOutcome::Rejected(_)
        ));
        let far = RolePrecommitGossip::new(pc_dto(
            net,
            1 + role_gossip_window() + 1,
            ROLE_VERIFY_CONTRIBUTOR,
            [0xD3u8; 20],
            s,
            n,
        ))
        .encode();
        assert!(matches!(
            cache.ingest_precommit_bytes(&far),
            GossipOutcome::Rejected(_)
        ));

        // (7) reveal without matching precommit rejects gracefully.
        let orphan = RoleRevealGossip::new(rv_dto(
            net,
            2,
            &prev,
            ROLE_SUPPORT_CONTRIBUTOR,
            [0xEEu8; 20],
            s,
            n,
        ))
        .encode();
        assert!(matches!(
            cache.ingest_reveal_bytes(&orphan),
            GossipOutcome::Rejected(_)
        ));
        // (6) reveal with matching precommit stores; (8) GET returns it.
        let rv = RoleRevealGossip::new(rv_dto(
            net,
            2,
            &prev,
            ROLE_COMPUTE_CONTRIBUTOR,
            [0xD1u8; 20],
            s,
            n,
        ))
        .encode();
        assert_eq!(cache.ingest_reveal_bytes(&rv), GossipOutcome::AcceptedNew);
        assert_eq!(cache.reveals_for(2).len(), 1);
        assert_eq!(cache.ingest_reveal_bytes(&rv), GossipOutcome::Duplicate);

        // prune drops stale.
        cache.prune(2 + role_gossip_window() + 5);
        assert_eq!(cache.precommits_for(2).len(), 0);
        disable();
    }

    #[test]
    fn node_gossip_outcome_rebroadcast_policy() {
        let _env = crate::test_env::guard();
        // P2P dispatch policy: only AcceptedNew rebroadcasts; duplicate/invalid do not.
        assert!(GossipOutcome::AcceptedNew.should_rebroadcast());
        assert!(!GossipOutcome::Duplicate.should_rebroadcast());
        assert!(!GossipOutcome::Rejected("x".to_string()).should_rebroadcast());
        assert!(GossipOutcome::AcceptedNew.accepted());
        assert!(GossipOutcome::Duplicate.accepted());
        assert!(!GossipOutcome::Rejected("x".to_string()).accepted());
    }

    #[test]
    fn node_cache_mainnet_and_disabled_hard_off() {
        let _env = crate::test_env::guard();
        let _g = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        // disabled (no env) -> reject.
        disable();
        let cache = NodeRoleGossipCache::new();
        cache.set_tip(1);
        let (s, n) = ([0x51u8; 32], [0x52u8; 32]);
        let pc =
            RolePrecommitGossip::new(pc_dto(1, 2, ROLE_COMPUTE_CONTRIBUTOR, [0xA1u8; 20], s, n))
                .encode();
        assert!(matches!(
            cache.ingest_precommit_bytes(&pc),
            GossipOutcome::Rejected(_)
        ));
        assert!(!role_gossip_enabled());
        // mainnet (IRIUM_NETWORK unset -> id 0) even with gossip flag -> still off.
        std::env::set_var("IRIUM_POAWX_ROLE_GOSSIP_ENABLED", "1");
        std::env::remove_var("IRIUM_NETWORK");
        assert!(!role_gossip_enabled(), "below the mainnet activation height; NOT hard-off (see activation::mainnet_gate_truth)");
        assert!(matches!(
            cache.ingest_precommit_bytes(&pc),
            GossipOutcome::Rejected(_)
        ));
        disable();
    }
}
