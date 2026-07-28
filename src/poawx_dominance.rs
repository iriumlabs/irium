//! Phase 21A: PoAW-X anti-domination recent-reward state primitives.
//!
//! Bounded per-miner recent-reward tracker + a deterministic fixed-point fairness
//! weight so a miner that has recently captured a large reward share is
//! down-weighted in future role assignment. Data-only foundation (Phase 21B may
//! wire it into assignment). No floating point; saturating arithmetic; mainnet
//! hard-off. Does NOT touch chain difficulty / LWMA-144.
//!
//! ⚠ MAINNET STATUS (corrected 2026-07-19): this module's gates are NOT "mainnet
//! hard-off". They route through `activation::poawx_effective_activation`, which on
//! `network_id == 0` IGNORES the env and substitutes the compiled
//! `MAINNET_POAWX_ACTIVATION_HEIGHT = Some(50_000)`. Mainnet is far past that height,
//! so these gates are ACTIVE in production. Any remaining "mainnet hard-off" wording
//! below is stale. The authoritative, height-accurate check is
//! `activation::mainnet_gate_truth`.
#![allow(dead_code)]

use std::collections::BTreeMap;

use crate::activation::network_id_byte;

/// Which role-reward bucket a payment belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleRewardKind {
    Primary,
    Compute,
    Verify,
    Support,
}

/// Per-miner recent reward history (reset per window/epoch).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MinerRewardHistory {
    pub recent_primary: u64,
    pub recent_compute: u64,
    pub recent_verify: u64,
    pub recent_support: u64,
    pub total_recent: u64,
    pub window_id: u64,
    pub last_reward_height: u64,
}

impl MinerRewardHistory {
    /// Record a reward (saturating). A window change resets the buckets first.
    pub fn record(&mut self, kind: RoleRewardKind, amount: u64, height: u64, window_id: u64) {
        if window_id != self.window_id {
            *self = MinerRewardHistory {
                window_id,
                ..Default::default()
            };
        }
        match kind {
            RoleRewardKind::Primary => {
                self.recent_primary = self.recent_primary.saturating_add(amount)
            }
            RoleRewardKind::Compute => {
                self.recent_compute = self.recent_compute.saturating_add(amount)
            }
            RoleRewardKind::Verify => {
                self.recent_verify = self.recent_verify.saturating_add(amount)
            }
            RoleRewardKind::Support => {
                self.recent_support = self.recent_support.saturating_add(amount)
            }
        }
        self.total_recent = self.total_recent.saturating_add(amount);
        self.last_reward_height = height;
    }
}

/// Bounded recent-reward tracker keyed by miner pkh.
#[derive(Debug, Default)]
pub struct DominanceTracker {
    miners: BTreeMap<[u8; 20], MinerRewardHistory>,
    window_id: u64,
    network_recent_total: u64,
}

impl DominanceTracker {
    pub fn new(window_id: u64) -> Self {
        Self {
            miners: BTreeMap::new(),
            window_id,
            network_recent_total: 0,
        }
    }

    /// Advance to a new window: prune all per-miner histories + reset totals.
    pub fn set_window(&mut self, window_id: u64) {
        if window_id != self.window_id {
            self.miners.clear();
            self.network_recent_total = 0;
            self.window_id = window_id;
        }
    }

    pub fn record(&mut self, pkh: [u8; 20], kind: RoleRewardKind, amount: u64, height: u64) {
        let w = self.window_id;
        self.miners
            .entry(pkh)
            .or_default()
            .record(kind, amount, height, w);
        self.network_recent_total = self.network_recent_total.saturating_add(amount);
    }

    pub fn history(&self, pkh: &[u8; 20]) -> Option<&MinerRewardHistory> {
        self.miners.get(pkh)
    }

    pub fn network_recent_total(&self) -> u64 {
        self.network_recent_total
    }

    /// Miner's recent reward share in permille (0..=1000), relative to the network
    /// recent total. 0 when the network total is 0.
    pub fn recent_reward_share_permille(&self, pkh: &[u8; 20]) -> u32 {
        if self.network_recent_total == 0 {
            return 0;
        }
        let mine = self.miners.get(pkh).map(|h| h.total_recent).unwrap_or(0) as u128;
        let share = mine.saturating_mul(1000) / (self.network_recent_total as u128);
        share.min(1000) as u32
    }
}

/// Deterministic fixed-point fairness weight:
/// `weight = valid_work_score * 1000 / (1000 + recent_reward_share_permille)`.
/// A miner with no recent rewards keeps its full `valid_work_score`; a heavily
/// rewarded miner is reduced (e.g. 1000 permille share → halved). Saturating.
pub fn fairness_weight(valid_work_score: u64, recent_reward_share_permille: u32) -> u64 {
    let num = (valid_work_score as u128).saturating_mul(1000);
    let den = 1000u128 + recent_reward_share_permille as u128;
    (num / den) as u64
}

/// Activation height for anti-domination (env-gated; mainnet hard-off).
pub fn anti_domination_activation_height() -> Option<u64> {
    std::env::var("IRIUM_POAWX_ANTI_DOMINATION_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// Pure gate logic (network 0 = mainnet hard-off); param-driven for race-free tests.
pub fn anti_domination_gate(network_id: u8, activation: Option<u64>, height: u64) -> bool {
    matches!(crate::activation::poawx_effective_activation(network_id, activation), Some(h) if height >= h)
}

/// Whether anti-domination weighting is active at `height`. Mainnet hard-off.
pub fn anti_domination_active(height: u64) -> bool {
    anti_domination_gate(
        network_id_byte(),
        anti_domination_activation_height(),
        height,
    )
}

/// Whether anti-domination enforcement is REQUIRED (env flag). With the
/// activation gate this turns on consensus validation of included dominance
/// weights (Phase 21C).
pub fn anti_domination_required() -> bool {
    if crate::activation::network_id_byte() == 0 {
        return true; // mainnet: enforced once the gate is active (height-gated)
    }
    std::env::var("IRIUM_POAWX_ANTI_DOMINATION_REQUIRED")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}

/// Pure enforcement gate: active AND required. Param-driven for race-free tests.
pub fn anti_domination_enforced_gate(
    network_id: u8,
    activation: Option<u64>,
    required: bool,
    height: u64,
) -> bool {
    anti_domination_gate(network_id, activation, height) && required
}

/// Whether anti-domination weights are ENFORCED at `height` (validated in
/// connect_block). Mainnet hard-off.
pub fn anti_domination_enforced(height: u64) -> bool {
    anti_domination_enforced_gate(
        network_id_byte(),
        anti_domination_activation_height(),
        anti_domination_required(),
        height,
    )
}

/// Window length (blocks) for dominance accounting. Configurable only behind the
/// testnet/devnet gate; clamped to >= 1. Default `DEFAULT_ANTI_DOMINATION_WINDOW`.
pub fn anti_domination_window() -> u64 {
    std::env::var("IRIUM_POAWX_ANTI_DOMINATION_WINDOW")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|w| *w >= 1)
        .unwrap_or(DEFAULT_ANTI_DOMINATION_WINDOW)
}

/// Number of recent windows (including the current) that count as "recent".
/// Clamped to >= 1. Default `DEFAULT_ANTI_DOMINATION_LOOKBACK`.
pub fn anti_domination_lookback() -> u64 {
    std::env::var("IRIUM_POAWX_ANTI_DOMINATION_LOOKBACK")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|w| *w >= 1)
        .unwrap_or(DEFAULT_ANTI_DOMINATION_LOOKBACK)
}

/// Default window length (blocks) for a dominance accounting window.
pub const DEFAULT_ANTI_DOMINATION_WINDOW: u64 = 2016;
/// Default number of recent windows (incl. current) counted as "recent".
pub const DEFAULT_ANTI_DOMINATION_LOOKBACK: u64 = 2;
/// Extra windows kept beyond the lookback before pruning. The live disconnect
/// path only touches recent tips; restart/reorg rebuild-from-chain reconstructs
/// everything regardless, so this is a conservative safety margin only.
const PRUNE_MARGIN_WINDOWS: u64 = 8;

/// Domain tag for the dominance state commitment digest.
const DOMINANCE_DIGEST_TAG: &[u8] = b"IRIUM_POAWX_DOMINANCE_STATE_V1";

/// Magic prefix for the Phase 21C trailing dominance-weight ext section.
pub const DOMINANCE_SECTION_MAGIC: &[u8] = b"DOM1";
/// Wire size of the 4 role weights (LE u64) carried in the dominance section.
pub const DOMINANCE_WEIGHTS_WIRE: usize = 32;
/// Deterministic baseline valid-work score that the per-claim dominance weight
/// scales down by the miner recent reward share. A constant baseline makes the
/// included weight a pure, node-recomputable function of the persisted state.
pub const DOMINANCE_BASE_WORK_SCORE: u64 = 1000;

/// Per-(miner, window) reward bucket. Integer-only; exactly revertible.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DominanceBucket {
    pub primary: u64,
    pub compute: u64,
    pub verify: u64,
    pub support: u64,
    pub total: u64,
    /// Count of rewarded role events credited to this (miner, window).
    pub valid_role_count: u64,
    /// Highest height that credited this bucket (informational; not in digest).
    pub last_reward_height: u64,
}

impl DominanceBucket {
    fn is_empty(&self) -> bool {
        self.primary == 0
            && self.compute == 0
            && self.verify == 0
            && self.support == 0
            && self.total == 0
            && self.valid_role_count == 0
    }
    fn add(&mut self, kind: RoleRewardKind, amount: u64, height: u64) {
        match kind {
            RoleRewardKind::Primary => self.primary = self.primary.saturating_add(amount),
            RoleRewardKind::Compute => self.compute = self.compute.saturating_add(amount),
            RoleRewardKind::Verify => self.verify = self.verify.saturating_add(amount),
            RoleRewardKind::Support => self.support = self.support.saturating_add(amount),
        }
        self.total = self.total.saturating_add(amount);
        self.valid_role_count = self.valid_role_count.saturating_add(1);
        if height > self.last_reward_height {
            self.last_reward_height = height;
        }
    }
    fn sub(&mut self, kind: RoleRewardKind, amount: u64) {
        match kind {
            RoleRewardKind::Primary => self.primary = self.primary.saturating_sub(amount),
            RoleRewardKind::Compute => self.compute = self.compute.saturating_sub(amount),
            RoleRewardKind::Verify => self.verify = self.verify.saturating_sub(amount),
            RoleRewardKind::Support => self.support = self.support.saturating_sub(amount),
        }
        self.total = self.total.saturating_sub(amount);
        self.valid_role_count = self.valid_role_count.saturating_sub(1);
    }
}

/// Persistent, reorg-safe dominance state: explicit per-(miner_pkh, window_id)
/// buckets so `apply_event`/`revert_event` are EXACT inverses. Held in
/// `ChainState`, applied on `connect_block` and reverted on
/// `disconnect_tip_block`, and deterministically rebuilt by chain replay on
/// restart / rebuild-style reorg. Integer/fixed-point only; no floats. Gated +
/// mainnet hard-off.
#[derive(Debug, Clone)]
pub struct PersistentDominance {
    window_len: u64,
    lookback: u64,
    buckets: BTreeMap<([u8; 20], u64), DominanceBucket>,
}

impl Default for PersistentDominance {
    fn default() -> Self {
        Self::new(
            DEFAULT_ANTI_DOMINATION_WINDOW,
            DEFAULT_ANTI_DOMINATION_LOOKBACK,
        )
    }
}

impl PersistentDominance {
    pub fn new(window_len: u64, lookback: u64) -> Self {
        Self {
            window_len: window_len.max(1),
            lookback: lookback.max(1),
            buckets: BTreeMap::new(),
        }
    }

    /// Build from env-configured window/lookback (testnet/devnet only).
    pub fn from_env() -> Self {
        Self::new(anti_domination_window(), anti_domination_lookback())
    }

    pub fn window_len(&self) -> u64 {
        self.window_len
    }
    pub fn lookback(&self) -> u64 {
        self.lookback
    }
    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }
    pub fn bucket_count(&self) -> usize {
        self.buckets.len()
    }

    pub fn window_id(&self, height: u64) -> u64 {
        height / self.window_len
    }

    /// Inclusive `(lo, hi)` window-id range counted as "recent" for `height`.
    fn recent_range(&self, height: u64) -> (u64, u64) {
        let hi = self.window_id(height);
        let lo = hi.saturating_sub(self.lookback.saturating_sub(1));
        (lo, hi)
    }

    /// Credit a reward event (saturating). EXACT inverse of `revert_event`.
    pub fn apply_event(&mut self, pkh: [u8; 20], kind: RoleRewardKind, amount: u64, height: u64) {
        let wid = self.window_id(height);
        self.buckets
            .entry((pkh, wid))
            .or_default()
            .add(kind, amount, height);
        self.prune(height);
    }

    /// Reverse a previously-applied reward event (saturating). Removes the
    /// bucket if it becomes empty.
    pub fn revert_event(&mut self, pkh: [u8; 20], kind: RoleRewardKind, amount: u64, height: u64) {
        let wid = self.window_id(height);
        if let Some(b) = self.buckets.get_mut(&(pkh, wid)) {
            b.sub(kind, amount);
            if b.is_empty() {
                self.buckets.remove(&(pkh, wid));
            }
        }
    }

    /// Drop buckets older than the recent range plus a conservative margin.
    fn prune(&mut self, height: u64) {
        let hi = self.window_id(height);
        let keep_floor = hi.saturating_sub(self.lookback.saturating_sub(1) + PRUNE_MARGIN_WINDOWS);
        if keep_floor == 0 {
            return;
        }
        self.buckets.retain(|(_, wid), _| *wid >= keep_floor);
    }

    pub fn bucket(&self, pkh: &[u8; 20], window_id: u64) -> Option<&DominanceBucket> {
        self.buckets.get(&(*pkh, window_id))
    }

    /// Sum of a miner's recent-window totals at `height`.
    pub fn recent_total(&self, pkh: &[u8; 20], height: u64) -> u64 {
        let (lo, hi) = self.recent_range(height);
        let mut sum = 0u64;
        for wid in lo..=hi {
            if let Some(b) = self.buckets.get(&(*pkh, wid)) {
                sum = sum.saturating_add(b.total);
            }
        }
        sum
    }

    /// Network-wide recent-window total at `height`.
    pub fn network_recent_total(&self, height: u64) -> u64 {
        let (lo, hi) = self.recent_range(height);
        let mut sum = 0u64;
        for ((_, wid), b) in self.buckets.iter() {
            if *wid >= lo && *wid <= hi {
                sum = sum.saturating_add(b.total);
            }
        }
        sum
    }

    /// Miner recent reward share in permille (0..=1000) at `height`.
    pub fn recent_reward_share_permille(&self, pkh: &[u8; 20], height: u64) -> u32 {
        let net = self.network_recent_total(height) as u128;
        if net == 0 {
            return 0;
        }
        let mine = self.recent_total(pkh, height) as u128;
        (mine.saturating_mul(1000) / net).min(1000) as u32
    }

    /// Deterministic dominance weight for a miner at `height`:
    /// `fairness_weight(valid_work_score, recent_share_permille)`.
    pub fn weight(&self, valid_work_score: u64, pkh: &[u8; 20], height: u64) -> u64 {
        fairness_weight(
            valid_work_score,
            self.recent_reward_share_permille(pkh, height),
        )
    }

    /// Deterministic wire encoding of the full dominance snapshot, so a
    /// standalone miner can fetch the node's authoritative state and build
    /// weight-correct blocks in a multi-miner setting. Inverse of `from_bytes`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(24 + self.buckets.len() * 84);
        out.extend_from_slice(&self.window_len.to_le_bytes());
        out.extend_from_slice(&self.lookback.to_le_bytes());
        out.extend_from_slice(&(self.buckets.len() as u64).to_le_bytes());
        for ((pkh, wid), b) in self.buckets.iter() {
            out.extend_from_slice(pkh);
            out.extend_from_slice(&wid.to_le_bytes());
            out.extend_from_slice(&b.primary.to_le_bytes());
            out.extend_from_slice(&b.compute.to_le_bytes());
            out.extend_from_slice(&b.verify.to_le_bytes());
            out.extend_from_slice(&b.support.to_le_bytes());
            out.extend_from_slice(&b.total.to_le_bytes());
            out.extend_from_slice(&b.valid_role_count.to_le_bytes());
            out.extend_from_slice(&b.last_reward_height.to_le_bytes());
        }
        out
    }

    /// Reconstruct a dominance snapshot from `to_bytes`. Rejects trailing bytes.
    pub fn from_bytes(raw: &[u8]) -> Result<Self, String> {
        let rd = |o: usize| -> Result<u64, String> {
            raw.get(o..o + 8)
                .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
                .ok_or_else(|| "dominance: truncated".to_string())
        };
        let window_len = rd(0)?;
        let lookback = rd(8)?;
        let count = rd(16)? as usize;
        let mut d = Self::new(window_len, lookback);
        let mut off = 24usize;
        for _ in 0..count {
            let pkh: [u8; 20] = raw
                .get(off..off + 20)
                .ok_or_else(|| "dominance: truncated pkh".to_string())?
                .try_into()
                .unwrap();
            off += 20;
            let wid = rd(off)?;
            off += 8;
            let primary = rd(off)?;
            off += 8;
            let compute = rd(off)?;
            off += 8;
            let verify = rd(off)?;
            off += 8;
            let support = rd(off)?;
            off += 8;
            let total = rd(off)?;
            off += 8;
            let valid_role_count = rd(off)?;
            off += 8;
            let last_reward_height = rd(off)?;
            off += 8;
            d.buckets.insert(
                (pkh, wid),
                DominanceBucket {
                    primary,
                    compute,
                    verify,
                    support,
                    total,
                    valid_role_count,
                    last_reward_height,
                },
            );
        }
        if off != raw.len() {
            return Err(format!(
                "dominance: trailing bytes ({} parsed, {} given)",
                off,
                raw.len()
            ));
        }
        Ok(d)
    }

    /// Canonical state commitment over all non-empty buckets (sorted by
    /// (pkh, window_id)). Two nodes with identical accepted chains + identical
    /// gate config produce the identical digest.
    pub fn digest(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(DOMINANCE_DIGEST_TAG);
        h.update(self.window_len.to_le_bytes());
        h.update(self.lookback.to_le_bytes());
        h.update((self.buckets.len() as u64).to_le_bytes());
        for ((pkh, wid), b) in self.buckets.iter() {
            h.update(pkh);
            h.update(wid.to_le_bytes());
            h.update(b.primary.to_le_bytes());
            h.update(b.compute.to_le_bytes());
            h.update(b.verify.to_le_bytes());
            h.update(b.support.to_le_bytes());
            h.update(b.total.to_le_bytes());
            h.update(b.valid_role_count.to_le_bytes());
        }
        h.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_recent_reward_keeps_full_weight() {
        let _env = crate::test_env::guard();
        let t = DominanceTracker::new(1);
        let pkh = [0x01u8; 20];
        assert_eq!(t.recent_reward_share_permille(&pkh), 0);
        assert_eq!(
            fairness_weight(1000, 0),
            1000,
            "full weight with no recent reward"
        );
    }

    #[test]
    fn high_recent_reward_reduces_weight_deterministic_ordering() {
        let _env = crate::test_env::guard();
        let mut t = DominanceTracker::new(1);
        let a = [0xAAu8; 20];
        let b = [0xBBu8; 20];
        // A captures 3/4 of recent rewards, B captures 1/4.
        t.record(a, RoleRewardKind::Primary, 3_000, 10);
        t.record(b, RoleRewardKind::Compute, 1_000, 10);
        let sa = t.recent_reward_share_permille(&a);
        let sb = t.recent_reward_share_permille(&b);
        assert_eq!(sa, 750);
        assert_eq!(sb, 250);
        let wa = fairness_weight(1000, sa); // 1000*1000/1750 = 571
        let wb = fairness_weight(1000, sb); // 1000*1000/1250 = 800
        assert!(wb > wa, "less-rewarded miner keeps more weight");
        assert_eq!(wa, 571);
        assert_eq!(wb, 800);
    }

    #[test]
    fn overflow_safe() {
        let _env = crate::test_env::guard();
        let mut t = DominanceTracker::new(1);
        let pkh = [0x09u8; 20];
        t.record(pkh, RoleRewardKind::Primary, u64::MAX, 1);
        t.record(pkh, RoleRewardKind::Compute, u64::MAX, 2); // saturates
        assert_eq!(t.history(&pkh).unwrap().total_recent, u64::MAX);
        assert_eq!(t.recent_reward_share_permille(&pkh), 1000);
        assert_eq!(
            fairness_weight(u64::MAX, 1000),
            (u64::MAX as u128 * 1000 / 2000) as u64
        );
    }

    #[test]
    fn window_reset_prunes() {
        let _env = crate::test_env::guard();
        let mut t = DominanceTracker::new(1);
        let pkh = [0x05u8; 20];
        t.record(pkh, RoleRewardKind::Primary, 500, 10);
        assert!(t.history(&pkh).is_some());
        assert_eq!(t.network_recent_total(), 500);
        t.set_window(2);
        assert!(t.history(&pkh).is_none(), "window change prunes histories");
        assert_eq!(t.network_recent_total(), 0);
        assert_eq!(t.recent_reward_share_permille(&pkh), 0);
        // recording under the new window starts fresh.
        t.record(pkh, RoleRewardKind::Verify, 100, 20);
        assert_eq!(t.history(&pkh).unwrap().recent_verify, 100);
    }

    #[test]
    fn phase20_role_rewards_feed_tracker() {
        let _env = crate::test_env::guard();
        // Prove a Phase 20 multi-role reward event (RoleReward pkhs + the canonical
        // 55/22/13/10 split) can feed the dominance tracker.
        use crate::poawx::multi_role_amounts;
        let amts = multi_role_amounts(5_000_000_000); // [primary, compute, verify, support]
        let primary = [0x11u8; 20];
        let compute = [0x22u8; 20];
        let verify = [0x33u8; 20];
        let support = [0x44u8; 20];
        let mut t = DominanceTracker::new(7);
        t.record(primary, RoleRewardKind::Primary, amts[0], 2);
        t.record(compute, RoleRewardKind::Compute, amts[1], 2);
        t.record(verify, RoleRewardKind::Verify, amts[2], 2);
        t.record(support, RoleRewardKind::Support, amts[3], 2);
        assert_eq!(t.network_recent_total(), 5_000_000_000);
        // PRIMARY (55%) has the largest recent share.
        assert!(
            t.recent_reward_share_permille(&primary) > t.recent_reward_share_permille(&support)
        );
        assert_eq!(t.recent_reward_share_permille(&primary), 550);
        assert_eq!(t.recent_reward_share_permille(&support), 100);
    }

    #[test]
    fn gate_logic_pure() {
        let _env = crate::test_env::guard();
        assert!(!anti_domination_gate(0, Some(1), 100), "below the mainnet activation height; NOT hard-off (see activation::mainnet_gate_truth)");
        assert!(anti_domination_gate(1, Some(1), 100));
        assert!(!anti_domination_gate(1, None, 100));
        assert!(!anti_domination_gate(1, Some(50), 10));
    }

    #[test]
    fn enforced_gate_logic_pure() {
        let _env = crate::test_env::guard();
        assert!(anti_domination_enforced_gate(1, Some(1), true, 100));
        assert!(!anti_domination_enforced_gate(1, Some(1), false, 100));
        assert!(
            !anti_domination_enforced_gate(0, Some(1), true, 100),
            "below the mainnet activation height; NOT hard-off (see activation::mainnet_gate_truth)"
        );
        assert!(!anti_domination_enforced_gate(1, None, true, 100));
        assert!(!anti_domination_enforced_gate(1, Some(200), true, 100));
    }

    #[test]
    fn persistent_apply_revert_exact_inverse() {
        let _env = crate::test_env::guard();
        let mut d = PersistentDominance::new(100, 2);
        let empty = d.digest();
        let a = [0xA1u8; 20];
        let c = [0xC2u8; 20];
        d.apply_event(a, RoleRewardKind::Primary, 2_750_000_000, 150);
        d.apply_event(c, RoleRewardKind::Compute, 1_100_000_000, 150);
        let after = d.digest();
        assert_ne!(after, empty);
        // exact reverse (LIFO) restores the empty digest.
        d.revert_event(c, RoleRewardKind::Compute, 1_100_000_000, 150);
        d.revert_event(a, RoleRewardKind::Primary, 2_750_000_000, 150);
        assert_eq!(d.digest(), empty, "apply then revert is an exact inverse");
        assert!(d.is_empty());
    }

    #[test]
    fn persistent_recent_share_and_weight() {
        let _env = crate::test_env::guard();
        let mut d = PersistentDominance::new(100, 2);
        let a = [0xAAu8; 20];
        let b = [0xBBu8; 20];
        d.apply_event(a, RoleRewardKind::Primary, 3_000, 150);
        d.apply_event(b, RoleRewardKind::Compute, 1_000, 150);
        assert_eq!(d.recent_reward_share_permille(&a, 150), 750);
        assert_eq!(d.recent_reward_share_permille(&b, 150), 250);
        assert!(
            d.weight(1000, &b, 150) > d.weight(1000, &a, 150),
            "heavier miner is down-weighted"
        );
        assert_eq!(d.weight(1000, &a, 150), fairness_weight(1000, 750));
    }

    #[test]
    fn persistent_window_rolls_off_recent() {
        let _env = crate::test_env::guard();
        let mut d = PersistentDominance::new(100, 1); // only current window counts
        let a = [0x01u8; 20];
        d.apply_event(a, RoleRewardKind::Primary, 1_000, 50); // window 0
        assert_eq!(d.recent_reward_share_permille(&a, 50), 1000);
        // a later height in a different window no longer counts window 0.
        assert_eq!(d.recent_reward_share_permille(&a, 150), 0);
    }

    #[test]
    fn persistent_prune_is_bounded() {
        let _env = crate::test_env::guard();
        let mut d = PersistentDominance::new(10, 2);
        let a = [0x07u8; 20];
        for h in 0..2000u64 {
            d.apply_event(a, RoleRewardKind::Primary, 1, h);
        }
        assert!(
            d.bucket_count() <= (2 + PRUNE_MARGIN_WINDOWS + 1) as usize,
            "pruning keeps the bucket set bounded"
        );
    }

    #[test]
    fn persistent_digest_deterministic_regardless_of_apply_order() {
        let _env = crate::test_env::guard();
        let a = [0x11u8; 20];
        let b = [0x22u8; 20];
        let mut d1 = PersistentDominance::new(100, 2);
        d1.apply_event(a, RoleRewardKind::Primary, 500, 110);
        d1.apply_event(b, RoleRewardKind::Compute, 200, 120);
        let mut d2 = PersistentDominance::new(100, 2);
        d2.apply_event(b, RoleRewardKind::Compute, 200, 120);
        d2.apply_event(a, RoleRewardKind::Primary, 500, 110);
        assert_eq!(d1.digest(), d2.digest(), "digest is order-independent");
    }
}

#[cfg(test)]
mod d2a_reorg_symmetry_audit {
    use super::*;

    /// D2a FINDING. `apply_event` calls `prune`; `revert_event` does NOT restore what
    /// prune removed. So the pair is NOT an exact inverse in general: reverting a block
    /// whose apply pruned a bucket cannot bring that bucket back.
    ///
    /// This is SAFE today only because pruning retains far more history than any reorg
    /// can reach:
    ///
    ///   retained span = (lookback - 1 + PRUNE_MARGIN_WINDOWS) * window
    ///                 = (2 - 1 + 8) * 2016 = 18,144 blocks
    ///   max reorg     = DEFAULT_MAX_REORG_DEPTH_MAINNET = 1,000 blocks
    ///
    /// 18,144 >> 1,000, so a reorg can never disconnect a block old enough for its
    /// bucket to have been pruned, and the asymmetry is unreachable.
    ///
    /// That safety rests on an invariant nothing currently asserts, between parameters
    /// that are independently env-tunable (window, lookback, max reorg depth). This test
    /// pins the relationship so shrinking the window or raising the reorg cap fails here
    /// rather than silently making dominance state reorg-divergent -- which, because
    /// weights are re-derived and compared in connect_block, would surface as nodes
    /// rejecting each other's blocks.
    #[test]
    fn prune_retention_must_exceed_max_reorg_depth() {
        let _env = crate::test_env::guard();
        let window = DEFAULT_ANTI_DOMINATION_WINDOW;
        let lookback = DEFAULT_ANTI_DOMINATION_LOOKBACK;
        let retained_windows = lookback.saturating_sub(1) + PRUNE_MARGIN_WINDOWS;
        let retained_blocks = retained_windows.saturating_mul(window);
        let max_reorg = crate::poawx_proposer::DEFAULT_MAX_REORG_DEPTH_MAINNET;
        assert!(
            retained_blocks > max_reorg,
            "dominance prune retains {retained_blocks} blocks but a reorg may reach \
             {max_reorg}; apply/revert is not an exact inverse across a prune, so this \
             would make dominance state diverge after a deep reorg"
        );
        // Keep a generous margin rather than a bare inequality.
        assert!(
            retained_blocks >= max_reorg.saturating_mul(4),
            "retention margin too thin: {retained_blocks} vs {max_reorg}"
        );
    }

    /// The other half of D2a: within reach of a reorg, apply/revert IS exact.
    #[test]
    fn apply_then_revert_is_exact_within_reorg_reach() {
        let _env = crate::test_env::guard();
        let mut d = PersistentDominance::new(DEFAULT_ANTI_DOMINATION_WINDOW, DEFAULT_ANTI_DOMINATION_LOOKBACK);
        let pkh = [0x5u8; 20];
        let before = d.digest();
        for h in 1..=50u64 {
            d.apply_event(pkh, RoleRewardKind::Primary, 1_000, h);
        }
        assert_ne!(d.digest(), before, "fixture vacuous: applies changed nothing");
        for h in (1..=50u64).rev() {
            d.revert_event(pkh, RoleRewardKind::Primary, 1_000, h);
        }
        assert_eq!(
            d.digest(),
            before,
            "apply/revert must be an exact inverse within reorg reach"
        );
    }
}
