//! PoAW-X VRF-assigned proposer sortition (Phase 31). Devnet/testnet only;
//! mainnet hard-off (`network_id == 0`). See `docs/poawx-proposer-vrf-design.md`.
//!
//! The chain decides who may propose each height via a VRF lottery on the
//! committee-controlled epoch seed: hashrate gives zero advantage. A backup
//! cascade keyed to the block time keeps the chain live if the primary is offline:
//!   round 0 = top 1 (lowest VRF score), round 1 = top 4 (+3), round 2 = top 14
//!   (+10), round 3+ = all eligible.
//!
//! This module is the PURE math + gate layer (no chain state). The eligibility
//! registry, validator gate, fork-choice rank, and wiring live in `chain.rs` /
//! `bin/iriumd.rs` / `bin/irium-miner.rs`.

use crate::activation::network_id_byte;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, OnceLock};

/// The PRIMARY proposer role id for the proposer VRF (distinct from the
/// compute/verify/support sub-roles 1/2/3). The block's `worker_pkh` IS the
/// proposer, so the proposer proof is bound to `ROLE_PROPOSER`.
pub const ROLE_PROPOSER: u8 = 0;

/// Default freeze depth (blocks): eligibility for height `H` uses the registry
/// state at `H - FREEZE_DEPTH`, so the seed `S_H` (revealed at H-1) cannot be used
/// to register a favorable key after the fact. Env-tunable; clamped `>= 2`.
pub const DEFAULT_PROPOSER_FREEZE_DEPTH: u64 = 16;

/// Default round interval (seconds) = target block time. Mainnet 120; devnet 30.
pub const DEFAULT_PROPOSER_ROUND_INTERVAL_SECS: u64 = 120;

/// Cumulative admitted proposer-slot count by `round`: round 0 = top 1,
/// round 1 = top 4 (next 3), round 2 = top 14 (next 10), round 3+ = all. Capped at
/// `eligible_count` (>= 1). Realizes the ordered cascade via thresholds.
pub fn cumulative_slots(round: u32, eligible_count: u64) -> u64 {
    let cum: u64 = match round {
        0 => 1,
        1 => 4,
        2 => 14,
        _ => u64::MAX, // round 3+ => all eligible
    };
    cum.min(eligible_count.max(1))
}

/// Proposer-lottery priority from a VRF output: lower = higher priority (closer to
/// slot 1). Reuses the V2 score (first 8 bytes of the VRF output, LE).
pub fn proposer_priority(vrf_output: &[u8; 32]) -> u64 {
    crate::poawx_candidate::assignment_v2_score_from_output(vrf_output)
}

/// Selection threshold at `round` for `eligible_count` registered keys. A miner is
/// admitted iff `proposer_priority < tau`. `tau = (U64_MAX / n) * slots` (saturating);
/// at round 3+ (`slots == n`) `tau == U64_MAX` so ALL eligible are admitted =>
/// liveness. With an empty registry (`n == 0`) treated as `n == 1` => permissive
/// bootstrap (everyone admitted) until keys register.
pub fn proposer_threshold(eligible_count: u64, round: u32) -> u64 {
    let n = eligible_count.max(1);
    let slots = cumulative_slots(round, n);
    if slots >= n {
        return u64::MAX;
    }
    (u64::MAX / n).saturating_mul(slots)
}

/// Whether `priority` is admitted (selected) at `round` for `eligible_count` keys.
pub fn is_selected(priority: u64, eligible_count: u64, round: u32) -> bool {
    priority < proposer_threshold(eligible_count, round)
}

/// Earliest header timestamp allowed for a `round`-r block: `parent_time + r*interval`.
/// The validator rejects a round-r block whose timestamp is earlier (anti round-grind).
pub fn min_time_for_round(parent_time: u32, round: u32, round_interval_secs: u64) -> u32 {
    let add = (round as u64).saturating_mul(round_interval_secs);
    parent_time.saturating_add(add.min(u32::MAX as u64) as u32)
}

/// Highest round a miner may attempt given `elapsed_secs` since the parent block.
/// Round 0 is open immediately; round r opens after `r * interval` seconds.
pub fn max_round_for_elapsed(elapsed_secs: u64, round_interval_secs: u64) -> u32 {
    let iv = round_interval_secs.max(1);
    (elapsed_secs / iv).min(u32::MAX as u64) as u32
}

// ── env-configurable params (devnet/testnet) ─────────────────────────────────

pub fn proposer_freeze_depth() -> u64 {
    std::env::var("IRIUM_POAWX_PROPOSER_FREEZE_DEPTH")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_PROPOSER_FREEZE_DEPTH)
        .max(2)
}

pub fn proposer_round_interval_secs() -> u64 {
    std::env::var("IRIUM_POAWX_PROPOSER_ROUND_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_PROPOSER_ROUND_INTERVAL_SECS)
        .max(1)
}

/// Default anti-spam PoW floor (leading-zero bits) when the proposer VRF gate is
/// enforced. PoW is then only a trivial spam deterrent, not a selection signal.
pub const DEFAULT_PROPOSER_ANTI_SPAM_BITS: u32 = 8;

pub fn proposer_anti_spam_bits() -> u32 {
    if network_id_byte() == 0 {
        return 20; // mainnet anti-spam PoW floor (bits)
    }
    std::env::var("IRIUM_POAWX_PROPOSER_ANTISPAM_BITS")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(DEFAULT_PROPOSER_ANTI_SPAM_BITS)
}

/// Pure cap: when `enforced`, the effective puzzle difficulty is capped at the
/// anti-spam `floor` (never raised), so hashrate cannot be cranked up to matter;
/// otherwise the configured value passes through verbatim.
pub fn cap_difficulty_if_enforced(configured: u32, enforced: bool, floor: u32) -> u32 {
    if enforced {
        configured.min(floor)
    } else {
        configured
    }
}

/// Effective puzzle difficulty at `height`: capped at the anti-spam floor when the
/// proposer VRF gate is enforced (mainnet hard-off => configured value verbatim).
pub fn effective_puzzle_difficulty_bits(configured: u32, height: u64) -> u32 {
    cap_difficulty_if_enforced(
        configured,
        proposer_vrf_enforced(height),
        proposer_anti_spam_bits(),
    )
}

// ── activation gate (mainnet hard-off) ───────────────────────────────────────

pub fn proposer_vrf_activation_height() -> Option<u64> {
    std::env::var("IRIUM_POAWX_PROPOSER_VRF_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

pub fn proposer_vrf_required() -> bool {
    if crate::activation::network_id_byte() == 0 {
        return true; // mainnet: enforced once the gate is active (height-gated)
    }
    std::env::var("IRIUM_POAWX_PROPOSER_VRF_REQUIRED")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}

/// Pure gate (param-driven for race-free tests). `network_id == 0` (mainnet) hard-off.
pub fn proposer_vrf_gate(network_id: u8, activation: Option<u64>, height: u64) -> bool {
    matches!(crate::activation::poawx_effective_activation(network_id, activation), Some(h) if height >= h)
}

pub fn proposer_vrf_active(height: u64) -> bool {
    proposer_vrf_gate(
        network_id_byte(),
        proposer_vrf_activation_height(),
        height,
    )
}

pub fn proposer_vrf_enforced(height: u64) -> bool {
    proposer_vrf_active(height) && proposer_vrf_required()
}

// ââ proposer registration / onboarding (gated) ââââââââââââââââââ
/// Max registrations force-drained (activated) from the FIFO queue head per block.
pub const PROPOSER_REG_CAP: usize = 8;
/// Max new registrations a producer may announce (enqueue) per block.
pub const PROPOSER_ANNOUNCE_CAP: usize = 8;
/// A registration's sybil anchor must be within the last this-many blocks of the
/// including height (bounds offline precomputation of the sybil work).
pub const PROPOSER_REG_ANCHOR_WINDOW: u64 = 64;

/// Whether a registration `anchor_height` is acceptable for inclusion in a block at
/// `height`: strictly in the past and within `window` of it. Used IDENTICALLY by the
/// block builder (to filter announce candidates) and the validator (connect_block) so
/// they never diverge -- a stale anchor must never be offered AND is always rejected.
pub fn registration_anchor_valid(anchor_height: u64, height: u64, window: u64) -> bool {
    anchor_height < height && !(height > window && anchor_height < height - window)
}

pub fn proposer_registration_activation_height() -> Option<u64> {
    std::env::var("IRIUM_POAWX_PROPOSER_REGISTRATION_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// Pure gate (param-driven for race-free tests). Registration is active only where the
/// proposer VRF is active (so `network_id == 0` mainnet is hard-off) AND at/after the
/// registration activation height.
pub fn proposer_registration_gate(vrf_active: bool, activation: Option<u64>, height: u64) -> bool {
    vrf_active && matches!(activation, Some(h) if height >= h)
}

pub fn proposer_registration_active(height: u64) -> bool {
    proposer_registration_gate(
        proposer_vrf_active(height),
        crate::activation::poawx_effective_activation(
            crate::activation::network_id_byte(),
            proposer_registration_activation_height(),
        ),
        height,
    )
}

/// Emergency liveness-recovery stall threshold (seconds). If the parent block is
/// older than this, the chain is treated as genuinely stalled and (when the recovery
/// gate is active) the frozen-window proposer check is relaxed to any prior on-chain
/// registration. Hard floor 14400 (2x MAX_FUTURE_BLOCK_TIME) so a miner cannot forge
/// the stall gap via a future timestamp.
pub const DEFAULT_PROPOSER_STALL_RECOVERY_SECS: u64 = 21_600; // 6h
pub fn proposer_stall_recovery_secs() -> u64 {
    std::env::var("IRIUM_POAWX_PROPOSER_STALL_RECOVERY_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_PROPOSER_STALL_RECOVERY_SECS)
        .max(14_400)
}

pub fn proposer_expiry_window() -> u64 {
    std::env::var("IRIUM_POAWX_PROPOSER_EXPIRY_WINDOW")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(2016)
        .max(1)
}

/// Reorg-safe registry of eligible proposer VRF keys. A key is eligible for height
/// `H` only via on-chain registrations FROZEN at `H - FREEZE_DEPTH`, so the seed
/// `S_H` (revealed at H-1) cannot be used to register a winning key after the fact.
/// Registrations apply on `connect_block` and revert on `disconnect_tip_block`
/// (exact inverse), so the frozen view is deterministic on any fork. Mainnet-off:
/// only populated when `proposer_vrf_active(height)`.
#[derive(Debug, Clone, Default)]
pub struct ProposerEligibilityRegistry {
    keys: BTreeMap<[u8; 33], ProposerKeyRecord>,
}

#[derive(Debug, Clone, Default)]
struct ProposerKeyRecord {
    pkh: [u8; 20],
    heights: BTreeSet<u64>,
}

impl ProposerEligibilityRegistry {
    pub fn from_env() -> Self {
        Self::default()
    }

    /// Record that `vrf_pubkey` (owned by `pkh`) appeared on-chain at `height`.
    pub fn register(&mut self, vrf_pubkey: [u8; 33], pkh: [u8; 20], height: u64) {
        let rec = self.keys.entry(vrf_pubkey).or_default();
        rec.pkh = pkh;
        rec.heights.insert(height);
    }

    /// Exact inverse of `register` for the same `(vrf_pubkey, height)`.
    pub fn unregister(&mut self, vrf_pubkey: &[u8; 33], height: u64) {
        if let Some(rec) = self.keys.get_mut(vrf_pubkey) {
            rec.heights.remove(&height);
            if rec.heights.is_empty() {
                self.keys.remove(vrf_pubkey);
            }
        }
    }

    /// Inclusive frozen registration window `[lo, hi]` for target `H` with the given
    /// freeze depth `fd` and expiry window `ew`. `None` if there is not yet `fd`
    /// history (bootstrap => no eligibility => the sortition threshold is permissive).
    fn frozen_window_with(fd: u64, ew: u64, target_height: u64) -> Option<(u64, u64)> {
        if target_height < fd {
            return None;
        }
        let hi = target_height - fd;
        let lo = hi.saturating_sub(ew.saturating_sub(1));
        Some((lo, hi))
    }

    fn record_in_window(rec: &ProposerKeyRecord, lo: u64, hi: u64) -> bool {
        rec.heights.range(lo..=hi).next().is_some()
    }

    pub fn eligible_count_with(&self, target_height: u64, fd: u64, ew: u64) -> u64 {
        match Self::frozen_window_with(fd, ew, target_height) {
            None => 0,
            Some((lo, hi)) => self
                .keys
                .values()
                .filter(|r| Self::record_in_window(r, lo, hi))
                .count() as u64,
        }
    }

    pub fn is_eligible_with(
        &self,
        vrf_pubkey: &[u8; 33],
        target_height: u64,
        fd: u64,
        ew: u64,
    ) -> bool {
        match Self::frozen_window_with(fd, ew, target_height) {
            None => false,
            Some((lo, hi)) => self
                .keys
                .get(vrf_pubkey)
                .map_or(false, |r| Self::record_in_window(r, lo, hi)),
        }
    }

    /// Eligible count at `H` using env-configured freeze depth + expiry window.
    pub fn eligible_count(&self, target_height: u64) -> u64 {
        self.eligible_count_with(target_height, proposer_freeze_depth(), proposer_expiry_window())
    }

    pub fn is_eligible(&self, vrf_pubkey: &[u8; 33], target_height: u64) -> bool {
        self.is_eligible_with(
            vrf_pubkey,
            target_height,
            proposer_freeze_depth(),
            proposer_expiry_window(),
        )
    }

    /// Whether this VRF key has ANY on-chain registration (regardless of freeze).
    /// Fix #9: all proposer pkhs eligible at `target_height` (the frozen-registered set).
    /// Diagnostic so an operator can see whether their miner's key is actually registered.
    /// Deterministic (BTreeMap order).
    pub fn eligible_pkhs(&self, target_height: u64) -> Vec<[u8; 20]> {
        self.eligible_pkhs_with(target_height, proposer_freeze_depth(), proposer_expiry_window())
    }
    pub fn eligible_pkhs_with(&self, target_height: u64, fd: u64, ew: u64) -> Vec<[u8; 20]> {
        match Self::frozen_window_with(fd, ew, target_height) {
            None => Vec::new(),
            Some((lo, hi)) => self
                .keys
                .values()
                .filter(|r| Self::record_in_window(r, lo, hi))
                .map(|r| r.pkh)
                .collect(),
        }
    }

    pub fn is_registered(&self, vrf_pubkey: &[u8; 33]) -> bool {
        self.keys.contains_key(vrf_pubkey)
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Max pending gossiped registrations a node will hold.
// ââ fork-choice hardening (Fix 1-4): bounded reorgs, honest finality, no-length tiebreak ââ
// One activation gate covers the whole bundle (depth cap + tip-hash tiebreak + genuine
// finality + header-sync floor). network_id == 0 (mainnet) hard-off; off until the
// activation height is set, so existing chains are byte-identical until coordinated activation.
pub const DEFAULT_MAX_REORG_DEPTH_MAINNET: u64 = 1000;
pub const DEFAULT_MAX_REORG_DEPTH_DEVNET: u64 = 100;
/// Hard floor: a configured cap can never drop below this (keeps normal shallow reorgs
/// working; an operator cannot cripple reorg recovery by setting it too low).
pub const MAX_REORG_DEPTH_HARD_FLOOR: u64 = 10;
pub const DEFAULT_MIN_FINALITY_COMMITTEE_MAINNET: u64 = 16;
pub const DEFAULT_MIN_FINALITY_COMMITTEE_DEVNET: u64 = 4;

pub fn fork_choice_hardening_activation_height() -> Option<u64> {
    std::env::var("IRIUM_POAWX_FORKCHOICE_HARDENING_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// Pure gate (param-driven for race-free tests). Mainnet (`network_id == 0`) hard-off.
pub fn fork_choice_hardening_gate(network_id: u8, activation: Option<u64>, height: u64) -> bool {
    matches!(crate::activation::poawx_effective_activation(network_id, activation), Some(h) if height >= h)
}

pub fn fork_choice_hardening_active(height: u64) -> bool {
    fork_choice_hardening_gate(
        network_id_byte(),
        fork_choice_hardening_activation_height(),
        height,
    )
}

// ââ audit hardening (pre-mainnet audit fixes): deterministic receipts root, finality
// parent/equivocation checks, VRF binding defense-in-depth, sig coverage, lane validation,
// strict leaf decoding, ticket epoch binding, role distinctness (>=3 candidates). One
// activation gate; network_id == 0 (mainnet) hard-off; off => byte-identical to pre-audit.
pub fn audit_hardening_activation_height() -> Option<u64> {
    std::env::var("IRIUM_POAWX_AUDIT_HARDENING_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

pub fn audit_hardening_gate(network_id: u8, activation: Option<u64>, height: u64) -> bool {
    matches!(crate::activation::poawx_effective_activation(network_id, activation), Some(h) if height >= h)
}

pub fn audit_hardening_active(height: u64) -> bool {
    audit_hardening_gate(
        network_id_byte(),
        audit_hardening_activation_height(),
        height,
    )
}

/// Option A (multi-participant role attribution): mainnet activation height for the
/// contributor-role solver binding. `None` => NOT live-active on mainnet -- the actual
/// future, announced, coordinated activation is a SEPARATE deferred decision (mirrors the
/// block-50000 discipline). Rig/devnet activate it low via the env var below for testing.
pub const MAINNET_CONTRIBUTOR_ROLE_BINDING_HEIGHT: Option<u64> = Some(57_794);

pub fn contributor_role_binding_activation_height() -> Option<u64> {
    std::env::var("IRIUM_POAWX_CONTRIBUTOR_ROLE_BINDING_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// Pure gate (param-driven for race-free tests). Mainnet (network 0) resolves to the
/// hard-coded future height (`None` today => off), so the mainnet-facing code is NOT
/// live-active; non-mainnet uses the env activation for rig/devnet testing.
pub fn contributor_role_binding_gate(
    network_id: u8,
    env_activation: Option<u64>,
    height: u64,
) -> bool {
    let eff = if network_id == 0 {
        MAINNET_CONTRIBUTOR_ROLE_BINDING_HEIGHT
    } else {
        env_activation
    };
    matches!(eff, Some(h) if height >= h)
}

/// Whether contributor-role solvers (COMPUTE/VERIFY/SUPPORT) must bind to their VRF key
/// (Option A) at `height`. Mainnet hard-off until a separate announced activation.
pub fn contributor_role_binding_active(height: u64) -> bool {
    contributor_role_binding_gate(
        network_id_byte(),
        contributor_role_binding_activation_height(),
        height,
    )
}

/// Max blocks a single reorg may disconnect (Fix 1). Finality-independent backstop:
/// the effective reorg floor is `max(finalized_height, tip - max_reorg_depth())`.
/// Network default + env override, floored at `MAX_REORG_DEPTH_HARD_FLOOR`.
pub fn max_reorg_depth() -> u64 {
    let default = if network_id_byte() == 0 {
        DEFAULT_MAX_REORG_DEPTH_MAINNET
    } else {
        DEFAULT_MAX_REORG_DEPTH_DEVNET
    };
    std::env::var("IRIUM_POAWX_MAX_REORG_DEPTH")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(default)
        .max(MAX_REORG_DEPTH_HARD_FLOOR)
}

/// Minimum distinct registered committee keys required before genuine finality can
/// advance `finalized_height` (Fix 2). Below this, finality does not advance and the
/// depth cap is the protection.
pub fn min_finality_committee() -> u64 {
    let default = if network_id_byte() == 0 {
        DEFAULT_MIN_FINALITY_COMMITTEE_MAINNET
    } else {
        DEFAULT_MIN_FINALITY_COMMITTEE_DEVNET
    };
    std::env::var("IRIUM_POAWX_MIN_FINALITY_COMMITTEE")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(default)
        .max(1)
}

pub const PROPOSER_REG_POOL_MAX: usize = 1024;

/// Whether proposer-registration gossip is enabled (non-mainnet only).
pub fn proposer_registration_gossip_enabled() -> bool {
    crate::activation::network_id_byte() != 0
        || crate::activation::MAINNET_POAWX_ACTIVATION_HEIGHT.is_some()
}

/// Node-local pool of gossiped proposer registrations awaiting on-chain announcement.
/// Gossip ingest is LIGHT (claimed sybil bits + self-signature + dedup); the full
/// anchor-bound validation runs at block inclusion (connect_block). Mainnet hard-off.
#[derive(Default)]
pub struct NodeProposerRegistrationPool {
    pending: Mutex<BTreeMap<[u8; 33], crate::poawx::ProposerRegistrationV1>>,
}

impl NodeProposerRegistrationPool {
    pub fn ingest_bytes(&self, bytes: &[u8]) -> crate::poawx_gossip::GossipOutcome {
        use crate::poawx_gossip::GossipOutcome;
        if !proposer_registration_gossip_enabled() {
            return GossipOutcome::Rejected("registration gossip disabled".to_string());
        }
        if bytes.len() != crate::poawx::PROPOSER_REGISTRATION_V1_WIRE {
            return GossipOutcome::Rejected("registration: bad length".to_string());
        }
        let reg = match crate::poawx::ProposerRegistrationV1::deserialize(bytes) {
            Ok(r) => r,
            Err(e) => return GossipOutcome::Rejected(e),
        };
        let net = crate::activation::network_id_byte();
        if !crate::poawx_ticket::meets_sybil_target(
            &reg.sybil_digest,
            crate::poawx_ticket::effective_sybil_bits(),
        ) {
            return GossipOutcome::Rejected("registration: insufficient sybil work".to_string());
        }
        if !reg.signature_ok(net) {
            return GossipOutcome::Rejected("registration: bad signature".to_string());
        }
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        match pending.get(&reg.vrf_pubkey) {
            // already have an equal-or-fresher anchor for this key: ignore.
            Some(existing) if reg.anchor_height <= existing.anchor_height => {
                return GossipOutcome::Duplicate;
            }
            // a fresher anchor for a known key: refresh + rebroadcast so the network
            // converges on the newest (non-stale) registration for the key.
            Some(_) => {
                pending.insert(reg.vrf_pubkey, reg);
                return GossipOutcome::AcceptedNew;
            }
            None => {}
        }
        if pending.len() >= PROPOSER_REG_POOL_MAX {
            return GossipOutcome::Rejected("registration: pool full".to_string());
        }
        pending.insert(reg.vrf_pubkey, reg);
        GossipOutcome::AcceptedNew
    }

    /// Local submit (RPC path): store + return the wire bytes to gossip.
    pub fn submit(&self, reg: crate::poawx::ProposerRegistrationV1) -> Vec<u8> {
        // Fix #14: re-validate before inserting into the local pool so the RPC path cannot inject
        // an unsigned / insufficient-sybil-work registration that the block builder would then
        // offer as an announce candidate (self-built invalid block). Mirrors ingest_bytes; an
        // invalid submission returns empty bytes (nothing is pooled or rebroadcast).
        let net = crate::activation::network_id_byte();
        if !crate::poawx_ticket::meets_sybil_target(
            &reg.sybil_digest,
            crate::poawx_ticket::effective_sybil_bits(),
        ) || !reg.signature_ok(net)
        {
            return Vec::new();
        }
        let bytes = reg.serialize();
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        pending.insert(reg.vrf_pubkey, reg);
        bytes
    }

    /// Up to `max` pending registrations whose key is NOT in `exclude` (already queued or
    /// on-chain), as announce candidates for the next block.
    pub fn announce_candidates(
        &self,
        max: usize,
        exclude: &BTreeSet<[u8; 33]>,
    ) -> Vec<crate::poawx::ProposerRegistrationV1> {
        let pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        pending
            .values()
            .filter(|r| !exclude.contains(&r.vrf_pubkey))
            .take(max)
            .cloned()
            .collect()
    }

    pub fn forget(&self, keys: &[[u8; 33]]) {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        for k in keys {
            pending.remove(k);
        }
    }

    pub fn contains(&self, key: &[u8; 33]) -> bool {
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(key)
    }

    pub fn len(&self) -> usize {
        self.pending.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

static GLOBAL_PROPOSER_REG_POOL: OnceLock<NodeProposerRegistrationPool> = OnceLock::new();

pub fn global_proposer_reg_pool() -> &'static NodeProposerRegistrationPool {
    GLOBAL_PROPOSER_REG_POOL.get_or_init(NodeProposerRegistrationPool::default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contributor_role_binding_gate_mainnet_activates_at_height() {
        // Activation binary (v1.9.127): mainnet (network 0) activates the contributor-role
        // binding at the fixed code height MAINNET_CONTRIBUTOR_ROLE_BINDING_HEIGHT, ignoring
        // env. Below it, off; at/above it, on (coordinated hard fork).
        let h = MAINNET_CONTRIBUTOR_ROLE_BINDING_HEIGHT.expect("activation height is set");
        assert!(!contributor_role_binding_gate(0, Some(1), h - 1));
        assert!(contributor_role_binding_gate(0, Some(1), h));
        assert!(contributor_role_binding_gate(0, None, h + 1));
        assert!(!contributor_role_binding_gate(0, None, 100));
        // devnet/rig (network 2): the env activation height gates it (low for testing).
        assert!(!contributor_role_binding_gate(2, None, 100));
        assert!(!contributor_role_binding_gate(2, Some(50), 49));
        assert!(contributor_role_binding_gate(2, Some(50), 50));
        assert!(contributor_role_binding_gate(2, Some(50), 100));
    }

    #[test]
    fn cumulative_slots_cascade() {
        // counts: round0=1, round1=4, round2=14, round3+=all, capped at n.
        assert_eq!(cumulative_slots(0, 100), 1);
        assert_eq!(cumulative_slots(1, 100), 4);
        assert_eq!(cumulative_slots(2, 100), 14);
        assert_eq!(cumulative_slots(3, 100), 100);
        assert_eq!(cumulative_slots(9, 100), 100);
        // capped at eligible_count
        assert_eq!(cumulative_slots(2, 5), 5);
        assert_eq!(cumulative_slots(0, 5), 1);
        // empty registry treated as 1
        assert_eq!(cumulative_slots(0, 0), 1);
    }

    #[test]
    fn threshold_widens_and_saturates() {
        // n=100: round0 admits ~1/100 of the space, round2 ~14/100, round3 all.
        assert_eq!(proposer_threshold(100, 0), u64::MAX / 100);
        assert_eq!(proposer_threshold(100, 1), (u64::MAX / 100) * 4);
        assert_eq!(proposer_threshold(100, 2), (u64::MAX / 100) * 14);
        assert_eq!(proposer_threshold(100, 3), u64::MAX); // all
        // n=1 (single eligible): always saturates -> that one is always selected.
        assert_eq!(proposer_threshold(1, 0), u64::MAX);
        // n=4 round1: slots(4)==n -> saturates.
        assert_eq!(proposer_threshold(4, 1), u64::MAX);
        // monotonic non-decreasing in round
        let n = 50;
        let mut prev = 0u64;
        for r in 0..6u32 {
            let t = proposer_threshold(n, r);
            assert!(t >= prev, "threshold must be non-decreasing in round");
            prev = t;
        }
        assert_eq!(prev, u64::MAX);
    }

    #[test]
    fn selection_by_priority() {
        // lowest priority (0) always selected at round 0; priority at/above tau not.
        let n = 100;
        let tau0 = proposer_threshold(n, 0);
        assert!(is_selected(0, n, 0));
        assert!(is_selected(tau0 - 1, n, 0));
        assert!(!is_selected(tau0, n, 0)); // strictly < tau
        assert!(!is_selected(u64::MAX, n, 0));
        // a miner not selected at round 0 may be selected at a later (wider) round.
        let p = tau0 + 1; // above round-0 cut
        assert!(!is_selected(p, n, 0));
        assert!(is_selected(p, n, 3)); // round 3 admits all
    }

    #[test]
    fn round_timing() {
        // round r opens at parent + r*interval; validator floor is the same.
        assert_eq!(min_time_for_round(1000, 0, 30), 1000);
        assert_eq!(min_time_for_round(1000, 1, 30), 1030);
        assert_eq!(min_time_for_round(1000, 2, 30), 1060);
        // elapsed -> max allowed round
        assert_eq!(max_round_for_elapsed(0, 30), 0);
        assert_eq!(max_round_for_elapsed(29, 30), 0);
        assert_eq!(max_round_for_elapsed(30, 30), 1);
        assert_eq!(max_round_for_elapsed(95, 30), 3);
    }

    #[test]
    fn gate_mainnet_activates_at_50000() {
        // network 0 (mainnet) PoAW-X activates at the fixed code height (50_000),
        // ignoring any env activation: off below it, on at/after it.
        assert!(!proposer_vrf_gate(0, Some(1), 49_999)); // mainnet: off before activation
        assert!(proposer_vrf_gate(0, Some(1), 50_000)); // mainnet: on at activation
        assert!(proposer_vrf_gate(0, None, 1_000_000)); // mainnet ignores env -> on past 50_000
        // devnet/testnet: active at/after the env activation height.
        assert!(proposer_vrf_gate(2, Some(1), 1));
        assert!(proposer_vrf_gate(1, Some(100), 100));
        assert!(!proposer_vrf_gate(2, Some(100), 99));
        assert!(!proposer_vrf_gate(2, None, 1)); // unset => off
    }

    #[test]
    fn priority_from_output_le() {
        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&7u64.to_le_bytes());
        assert_eq!(proposer_priority(&out), 7);
    }

    #[test]
    fn fork_choice_hardening_gate_and_depth_floor() {
        assert!(!fork_choice_hardening_gate(0, Some(1), 100)); // mainnet hard-off
        assert!(fork_choice_hardening_gate(2, Some(50), 50));
        assert!(fork_choice_hardening_gate(2, Some(50), 999));
        assert!(!fork_choice_hardening_gate(2, Some(50), 49));
        assert!(!fork_choice_hardening_gate(2, None, 100)); // unset => off
        std::env::set_var("IRIUM_NETWORK", "devnet");
        std::env::set_var("IRIUM_POAWX_MAX_REORG_DEPTH", "2");
        assert_eq!(max_reorg_depth(), MAX_REORG_DEPTH_HARD_FLOOR); // 2 floored to 10
        std::env::set_var("IRIUM_POAWX_MAX_REORG_DEPTH", "250");
        assert_eq!(max_reorg_depth(), 250);
        std::env::remove_var("IRIUM_POAWX_MAX_REORG_DEPTH");
        assert_eq!(max_reorg_depth(), DEFAULT_MAX_REORG_DEPTH_DEVNET);
        assert_eq!(min_finality_committee(), DEFAULT_MIN_FINALITY_COMMITTEE_DEVNET);
        std::env::remove_var("IRIUM_NETWORK");
    }

    #[test]
    fn registration_gate_pure() {
        assert!(!proposer_registration_gate(false, Some(1), 100)); // vrf off => off
        assert!(!proposer_registration_gate(true, None, 100)); // no activation => off
        assert!(proposer_registration_gate(true, Some(50), 50)); // active at height
        assert!(proposer_registration_gate(true, Some(50), 999)); // active after
        assert!(!proposer_registration_gate(true, Some(50), 49)); // before activation
    }

    #[test]
    fn registration_anchor_window_math() {
        // in the past + within window.
        assert!(registration_anchor_valid(60, 66, 64));
        assert!(registration_anchor_valid(65, 66, 64));
        // genesis anchor goes stale once height passes anchor + window.
        assert!(!registration_anchor_valid(0, 66, 64)); // 0 < 66-64=2 => stale
        assert!(registration_anchor_valid(0, 64, 64)); // height==window => no lower bound
        assert!(!registration_anchor_valid(0, 65, 64)); // 0 < 1 => stale
        // not in the past.
        assert!(!registration_anchor_valid(66, 66, 64));
        assert!(!registration_anchor_valid(67, 66, 64));
    }

    #[test]
    fn registry_is_registered_tracks_keys() {
        let mut reg = ProposerEligibilityRegistry::default();
        let k = [0x9u8; 33];
        assert!(!reg.is_registered(&k));
        reg.register(k, [0x1u8; 20], 5);
        assert!(reg.is_registered(&k));
        reg.unregister(&k, 5);
        assert!(!reg.is_registered(&k));
    }

    #[test]
    fn pool_refreshes_to_fresher_anchor() {
        std::env::set_var("IRIUM_NETWORK", "devnet");
        let net = crate::activation::network_id_byte();
        let pool = NodeProposerRegistrationPool::default();
        let r0 = crate::poawx::ProposerRegistrationV1::build_signed(&[0x7u8; 32], net, 0, &[0x9u8; 32], 0)
            .unwrap();
        let r5 = crate::poawx::ProposerRegistrationV1::build_signed(&[0x7u8; 32], net, 5, &[0x9u8; 32], 0)
            .unwrap();
        assert!(matches!(
            pool.ingest_bytes(&r0.serialize()),
            crate::poawx_gossip::GossipOutcome::AcceptedNew
        ));
        // fresher anchor (5 > 0) => refresh + rebroadcast.
        assert!(matches!(
            pool.ingest_bytes(&r5.serialize()),
            crate::poawx_gossip::GossipOutcome::AcceptedNew
        ));
        // older/equal anchor => duplicate (no downgrade).
        assert!(matches!(
            pool.ingest_bytes(&r0.serialize()),
            crate::poawx_gossip::GossipOutcome::Duplicate
        ));
        assert_eq!(pool.len(), 1);
        std::env::remove_var("IRIUM_NETWORK");
    }

    #[test]
    fn pool_ingest_dedup_and_filter() {
        std::env::set_var("IRIUM_NETWORK", "devnet");
        let net = crate::activation::network_id_byte();
        let pool = NodeProposerRegistrationPool::default();
        let reg =
            crate::poawx::ProposerRegistrationV1::build_signed(&[0x7u8; 32], net, 0, &[0x9u8; 32], 0)
                .unwrap();
        let bytes = reg.serialize();
        assert!(matches!(
            pool.ingest_bytes(&bytes),
            crate::poawx_gossip::GossipOutcome::AcceptedNew
        ));
        assert!(matches!(
            pool.ingest_bytes(&bytes),
            crate::poawx_gossip::GossipOutcome::Duplicate
        ));
        let mut bad = reg.clone();
        bad.signature[0] ^= 0xff;
        assert!(matches!(
            pool.ingest_bytes(&bad.serialize()),
            crate::poawx_gossip::GossipOutcome::Rejected(_)
        ));
        assert_eq!(pool.len(), 1);
        std::env::remove_var("IRIUM_NETWORK");
    }

    #[test]
    fn anti_spam_cap_math() {
        // gate off => configured value passes through verbatim.
        assert_eq!(cap_difficulty_if_enforced(20, false, 8), 20);
        // enforced => capped downward at the floor.
        assert_eq!(cap_difficulty_if_enforced(20, true, 8), 8);
        // enforced never raises a low configured value.
        assert_eq!(cap_difficulty_if_enforced(4, true, 8), 4);
    }

    #[test]
    fn registry_freeze_and_expiry() {
        let mut reg = ProposerEligibilityRegistry::default();
        let k1 = [0x11u8; 33];
        let k2 = [0x22u8; 33];
        let (fd, ew) = (16u64, 100u64);
        reg.register(k1, [0x01u8; 20], 10);
        reg.register(k2, [0x02u8; 20], 12);
        // not enough history => no eligibility (bootstrap permissive).
        assert_eq!(reg.eligible_count_with(10, fd, ew), 0);
        // k1 (h=10) eligible at H=26 (window hi = 26-16 = 10); k2 (h=12) not yet.
        assert!(reg.is_eligible_with(&k1, 26, fd, ew));
        assert!(!reg.is_eligible_with(&k2, 26, fd, ew));
        assert_eq!(reg.eligible_count_with(26, fd, ew), 1);
        // at H=28 (hi=12) both are in the frozen window.
        assert_eq!(reg.eligible_count_with(28, fd, ew), 2);
        // expiry: at H=126 (window [11,110]) k1(10) drops out, k2(12) remains.
        assert!(!reg.is_eligible_with(&k1, 126, fd, ew));
        assert!(reg.is_eligible_with(&k2, 126, fd, ew));
    }

    #[test]
    fn registry_register_unregister_symmetry() {
        let mut reg = ProposerEligibilityRegistry::default();
        let k = [0x33u8; 33];
        let (fd, ew) = (4u64, 100u64);
        reg.register(k, [0x03u8; 20], 20);
        reg.register(k, [0x03u8; 20], 21);
        assert_eq!(reg.len(), 1);
        assert!(reg.is_eligible_with(&k, 24, fd, ew)); // hi=20, has 20
        reg.unregister(&k, 20);
        reg.unregister(&k, 21);
        assert_eq!(reg.len(), 0); // exact inverse => fully removed
        assert!(!reg.is_eligible_with(&k, 24, fd, ew));
    }
}
