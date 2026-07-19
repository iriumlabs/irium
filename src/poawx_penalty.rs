//! Phase 21A: PoAW-X penalty / fraud state primitives (data-only, gated, mainnet-ACTIVE at height >= 50_000).
//!
//! Tracks per-miner penalty state so high-trust role assignment (e.g. the
//! finality/SUPPORT role) can be withheld from misbehaving identities. This is a
//! FOUNDATION layer: it is not wired into live block acceptance yet (Phase 21B),
//! and is hard-off on mainnet and disabled unless the activation gate is set.
//! `SlashedPlaceholder` (id 4) remains a no-op placeholder for backward
//! compatibility. The real, fraud-proof-triggered economic exclusion is
//! `Slashed` (id 5): applied by [`PersistentPenalty::apply_slash`] when a
//! verified [`crate::poawx_challenge::FraudProofV1`] is accepted in
//! `connect_block`, and reverted on `disconnect_tip_block`. Mainnet hard-off.
//!
//! ⚠ MAINNET STATUS (corrected 2026-07-19): this module's gates are NOT "mainnet
//! hard-off". They route through `activation::poawx_effective_activation`, which on
//! `network_id == 0` IGNORES the env and substitutes the compiled
//! `MAINNET_POAWX_ACTIVATION_HEIGHT = Some(50_000)`. Mainnet is far past that height,
//! so these gates are ACTIVE in production. Any remaining "mainnet hard-off" wording
//! below is stale. The authoritative, height-accurate check is
//! `activation::mainnet_gate_truth`.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use crate::activation::network_id_byte;

/// Penalty status for a miner identity / work ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PenaltyStatus {
    Clean = 0,
    Warned = 1,
    TemporarilyReduced = 2,
    SuspendedForEpoch = 3,
    /// Legacy no-op placeholder (no economic effect). Kept for wire/id stability.
    SlashedPlaceholder = 4,
    /// Real slash: identity is permanently excluded from high-trust roles and
    /// earns zero role-reward weight. Set only by an accepted fraud proof.
    Slashed = 5,
}

impl PenaltyStatus {
    pub fn id(self) -> u8 {
        self as u8
    }
    pub fn from_id(b: u8) -> Option<Self> {
        Some(match b {
            0 => PenaltyStatus::Clean,
            1 => PenaltyStatus::Warned,
            2 => PenaltyStatus::TemporarilyReduced,
            3 => PenaltyStatus::SuspendedForEpoch,
            4 => PenaltyStatus::SlashedPlaceholder,
            5 => PenaltyStatus::Slashed,
            _ => return None,
        })
    }

    /// Whether a miner in this state may be assigned a HIGH-TRUST role
    /// (VERIFY/SUPPORT/finality). Clean + Warned + (reduced) are eligible;
    /// Suspended/Slashed are not.
    pub fn eligible_for_high_trust_role(self) -> bool {
        matches!(
            self,
            PenaltyStatus::Clean | PenaltyStatus::Warned | PenaltyStatus::TemporarilyReduced
        )
    }

    /// Fixed-point eligibility weight multiplier in permille (1000 = full).
    /// Deterministic; no floats.
    pub fn weight_multiplier_permille(self) -> u32 {
        match self {
            PenaltyStatus::Clean => 1000,
            PenaltyStatus::Warned => 1000,
            PenaltyStatus::TemporarilyReduced => 500,
            PenaltyStatus::SuspendedForEpoch => 0,
            PenaltyStatus::SlashedPlaceholder => 0,
            PenaltyStatus::Slashed => 0,
        }
    }
}

/// Escalation thresholds (configurable; deterministic).
#[derive(Debug, Clone, Copy)]
pub struct PenaltyThresholds {
    pub warn_at: u32,
    pub reduce_at: u32,
    pub suspend_at: u32,
    /// Number of epochs a suspension lasts.
    pub suspend_epochs: u64,
}

impl Default for PenaltyThresholds {
    fn default() -> Self {
        Self {
            warn_at: 1,
            reduce_at: 3,
            suspend_at: 5,
            suspend_epochs: 1,
        }
    }
}

/// Mutable per-miner penalty record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PenaltyRecord {
    pub status: PenaltyStatus,
    pub invalid_count: u32,
    pub valid_count: u32,
    pub suspended_until_epoch: u64,
    pub last_update_height: u64,
    /// Number of distinct accepted fraud offences currently slashing this
    /// identity. While `> 0` the status is `Slashed`; reaching `0` restores
    /// `Clean`. Tracked so `slash`/`unslash` are EXACT inverses under reorg.
    pub slash_count: u32,
}

impl Default for PenaltyRecord {
    fn default() -> Self {
        Self {
            status: PenaltyStatus::Clean,
            invalid_count: 0,
            valid_count: 0,
            suspended_until_epoch: 0,
            last_update_height: 0,
            slash_count: 0,
        }
    }
}

/// Fixed wire size of a serialized `PenaltyRecord`:
/// status(1)+invalid(4)+valid(4)+suspended_until(8)+last_update(8)+slash(4) = 29.
pub const PENALTY_RECORD_WIRE: usize = 1 + 4 + 4 + 8 + 8 + 4;

impl PenaltyRecord {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one unit of valid work (saturating).
    pub fn record_valid_work(&mut self, height: u64) {
        self.valid_count = self.valid_count.saturating_add(1);
        self.last_update_height = height;
    }

    /// Record invalid work; escalate the penalty status deterministically.
    pub fn record_invalid_work(&mut self, height: u64, epoch: u64, t: &PenaltyThresholds) {
        self.invalid_count = self.invalid_count.saturating_add(1);
        self.last_update_height = height;
        if self.invalid_count >= t.suspend_at {
            self.status = PenaltyStatus::SuspendedForEpoch;
            self.suspended_until_epoch = epoch.saturating_add(t.suspend_epochs);
        } else if self.invalid_count >= t.reduce_at {
            self.status = PenaltyStatus::TemporarilyReduced;
        } else if self.invalid_count >= t.warn_at {
            self.status = PenaltyStatus::Warned;
        }
    }

    /// Clear an expired suspension back to Warned once the epoch passes.
    pub fn expire_if_due(&mut self, current_epoch: u64) {
        if self.status == PenaltyStatus::SuspendedForEpoch
            && current_epoch >= self.suspended_until_epoch
        {
            self.status = PenaltyStatus::Warned;
        }
    }

    pub fn eligible_for_high_trust_role(&self) -> bool {
        self.status.eligible_for_high_trust_role()
    }

    /// Apply one fraud-proof slash (saturating). The status becomes `Slashed`
    /// and stays there while any offence remains. EXACT inverse of `unslash`.
    pub fn slash(&mut self, height: u64) {
        self.slash_count = self.slash_count.saturating_add(1);
        self.status = PenaltyStatus::Slashed;
        if height > self.last_update_height {
            self.last_update_height = height;
        }
    }

    /// Reverse one previously-applied slash (reorg disconnect). When the last
    /// slash is removed the status returns to `Clean`.
    pub fn unslash(&mut self) {
        self.slash_count = self.slash_count.saturating_sub(1);
        if self.slash_count == 0 && self.status == PenaltyStatus::Slashed {
            self.status = PenaltyStatus::Clean;
        }
    }

    /// True when the record carries no state (a fresh `Clean` default).
    pub fn is_clean_default(&self) -> bool {
        *self == PenaltyRecord::default()
    }

    /// Fixed-size little-endian serialization (`PENALTY_RECORD_WIRE` bytes).
    pub fn serialize(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(PENALTY_RECORD_WIRE);
        o.push(self.status.id());
        o.extend_from_slice(&self.invalid_count.to_le_bytes());
        o.extend_from_slice(&self.valid_count.to_le_bytes());
        o.extend_from_slice(&self.suspended_until_epoch.to_le_bytes());
        o.extend_from_slice(&self.last_update_height.to_le_bytes());
        o.extend_from_slice(&self.slash_count.to_le_bytes());
        o
    }

    pub fn deserialize(raw: &[u8]) -> Result<Self, String> {
        if raw.len() != PENALTY_RECORD_WIRE {
            return Err("penalty record: bad length".to_string());
        }
        let status =
            PenaltyStatus::from_id(raw[0]).ok_or_else(|| "penalty record: bad status".to_string())?;
        let invalid_count = u32::from_le_bytes(raw[1..5].try_into().expect("4"));
        let valid_count = u32::from_le_bytes(raw[5..9].try_into().expect("4"));
        let suspended_until_epoch = u64::from_le_bytes(raw[9..17].try_into().expect("8"));
        let last_update_height = u64::from_le_bytes(raw[17..25].try_into().expect("8"));
        let slash_count = u32::from_le_bytes(raw[25..29].try_into().expect("4"));
        Ok(Self {
            status,
            invalid_count,
            valid_count,
            suspended_until_epoch,
            last_update_height,
            slash_count,
        })
    }
}

/// Activation height for penalty-state enforcement (env-gated; mainnet hard-off).
pub fn penalty_state_activation_height() -> Option<u64> {
    std::env::var("IRIUM_POAWX_PENALTY_STATE_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// Pure gate logic (network 0 = mainnet hard-off). Kept pure + param-driven so
/// tests need not mutate global env (avoids parallel-test env races).
pub fn penalty_gate(network_id: u8, activation: Option<u64>, height: u64) -> bool {
    matches!(crate::activation::poawx_effective_activation(network_id, activation), Some(h) if height >= h)
}

/// Whether penalty-state enforcement is active at `height`. Mainnet hard-off.
pub fn penalty_state_active(height: u64) -> bool {
    penalty_gate(network_id_byte(), penalty_state_activation_height(), height)
}

/// Whether penalty enforcement is REQUIRED (`IRIUM_POAWX_PENALTY_STATE_REQUIRED=1`).
/// Mainnet hard-off.
pub fn penalty_state_required() -> bool {
    if network_id_byte() == 0 {
        return true; // mainnet: enforced once the gate is active (height-gated)
    }
    std::env::var("IRIUM_POAWX_PENALTY_STATE_REQUIRED")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}

/// Penalty enforcement is ON only when active at `height` AND required. Mainnet
/// hard-off. Used by the Phase 21B ticket-proof validator to block suspended/
/// slashed identities from high-trust roles.
pub fn penalty_state_enforced(height: u64) -> bool {
    penalty_state_active(height) && penalty_state_required()
}

/// Domain tag for the persistent penalty-state commitment digest.
const PENALTY_DIGEST_TAG: &[u8] = b"IRIUM_POAWX_PENALTY_STATE_V1";

/// Persistent, reorg-safe penalty state driven by accepted fraud proofs. Held on
/// `ChainState`, applied on `connect_block` and reverted on
/// `disconnect_tip_block`, and deterministically rebuilt by chain replay on
/// restart / rebuild-style reorg (the proofs live in the blocks). This MIRRORS
/// `crate::poawx_dominance::PersistentDominance`: explicit per-offence keys so
/// `apply_slash`/`revert_slash` are EXACT inverses. Integer-only; mainnet
/// hard-off (gated by the caller).
#[derive(Debug, Clone, Default)]
pub struct PersistentPenalty {
    records: BTreeMap<[u8; 20], PenaltyRecord>,
    /// Accepted, currently-active offences keyed by `(offender, target_height,
    /// kind_id)`. Drives both de-duplication and exact revert.
    offences: BTreeSet<([u8; 20], u64, u8)>,
}

impl PersistentPenalty {
    pub fn new() -> Self {
        Self::default()
    }

    /// Construction parity with the dominance tracker (no env params in v1).
    pub fn from_env() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty() && self.offences.is_empty()
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn offence_count(&self) -> usize {
        self.offences.len()
    }

    /// Count of currently-active offences whose `target_height >= since_height`.
    /// Used by the adaptive engine as a windowed "recent invalid work" signal so
    /// it does not latch into Defense permanently after old slashes.
    pub fn recent_offence_count(&self, since_height: u64) -> usize {
        self.offences
            .iter()
            .filter(|(_, target_height, _)| *target_height >= since_height)
            .count()
    }

    /// Current status for an identity (`Clean` if untracked).
    pub fn status(&self, pkh: &[u8; 20]) -> PenaltyStatus {
        self.records
            .get(pkh)
            .map(|r| r.status)
            .unwrap_or(PenaltyStatus::Clean)
    }

    pub fn record(&self, pkh: &[u8; 20]) -> Option<&PenaltyRecord> {
        self.records.get(pkh)
    }

    /// Whether an identity is currently slashed (excluded from high-trust roles).
    pub fn is_slashed(&self, pkh: &[u8; 20]) -> bool {
        self.status(pkh) == PenaltyStatus::Slashed
    }

    /// Whether this exact offence has already been recorded (de-dup guard).
    pub fn is_offence_recorded(&self, offender: [u8; 20], target_height: u64, kind: u8) -> bool {
        self.offences.contains(&(offender, target_height, kind))
    }

    /// Apply one verified fraud offence (idempotent on a duplicate key). EXACT
    /// inverse of `revert_slash`.
    pub fn apply_slash(&mut self, offender: [u8; 20], target_height: u64, kind: u8, height: u64) {
        if self.offences.insert((offender, target_height, kind)) {
            self.records.entry(offender).or_default().slash(height);
        }
    }

    /// Reverse one previously-applied offence (reorg disconnect). Removes the
    /// record once it returns to a clean default.
    pub fn revert_slash(&mut self, offender: [u8; 20], target_height: u64, kind: u8) {
        if self.offences.remove(&(offender, target_height, kind)) {
            if let Some(rec) = self.records.get_mut(&offender) {
                rec.unslash();
                // In the fraud-proof flow a record exists ONLY because of
                // slashing, so once no offences remain it is removed entirely.
                // This keeps apply/revert an EXACT inverse (the informational
                // `last_update_height` set by `slash` does not linger).
                if rec.slash_count == 0 {
                    self.records.remove(&offender);
                }
            }
        }
    }

    /// Canonical state commitment over all offences + records (sorted by key).
    /// Two nodes with identical accepted chains produce the identical digest.
    pub fn digest(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(PENALTY_DIGEST_TAG);
        h.update((self.offences.len() as u64).to_le_bytes());
        for (pkh, height, kind) in self.offences.iter() {
            h.update(pkh);
            h.update(height.to_le_bytes());
            h.update([*kind]);
        }
        h.update((self.records.len() as u64).to_le_bytes());
        for (pkh, rec) in self.records.iter() {
            h.update(pkh);
            h.update(rec.serialize());
        }
        h.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn penalty_status_roundtrip_and_eligibility() {
        for s in [
            PenaltyStatus::Clean,
            PenaltyStatus::Warned,
            PenaltyStatus::TemporarilyReduced,
            PenaltyStatus::SuspendedForEpoch,
            PenaltyStatus::SlashedPlaceholder,
            PenaltyStatus::Slashed,
        ] {
            assert_eq!(PenaltyStatus::from_id(s.id()), Some(s));
        }
        assert!(PenaltyStatus::from_id(9).is_none());
        // clean + warned eligible; suspended + slashed not.
        assert!(PenaltyStatus::Clean.eligible_for_high_trust_role());
        assert!(PenaltyStatus::Warned.eligible_for_high_trust_role());
        assert!(PenaltyStatus::TemporarilyReduced.eligible_for_high_trust_role());
        assert!(!PenaltyStatus::SuspendedForEpoch.eligible_for_high_trust_role());
        assert!(!PenaltyStatus::SlashedPlaceholder.eligible_for_high_trust_role());
        assert!(!PenaltyStatus::Slashed.eligible_for_high_trust_role());
    }

    #[test]
    fn penalty_weight_multipliers_fixed_point() {
        assert_eq!(PenaltyStatus::Clean.weight_multiplier_permille(), 1000);
        assert_eq!(PenaltyStatus::Warned.weight_multiplier_permille(), 1000);
        assert_eq!(
            PenaltyStatus::TemporarilyReduced.weight_multiplier_permille(),
            500
        );
        assert_eq!(
            PenaltyStatus::SuspendedForEpoch.weight_multiplier_permille(),
            0
        );
        assert_eq!(
            PenaltyStatus::SlashedPlaceholder.weight_multiplier_permille(),
            0
        );
        assert_eq!(PenaltyStatus::Slashed.weight_multiplier_permille(), 0);
    }

    #[test]
    fn penalty_record_wire_roundtrip() {
        let mut r = PenaltyRecord::new();
        r.slash(42);
        r.invalid_count = 7;
        r.valid_count = 3;
        let bytes = r.serialize();
        assert_eq!(bytes.len(), PENALTY_RECORD_WIRE);
        assert_eq!(PenaltyRecord::deserialize(&bytes).unwrap(), r);
        assert!(PenaltyRecord::deserialize(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn record_slash_unslash_exact_inverse() {
        let mut r = PenaltyRecord::new();
        assert_eq!(r.status, PenaltyStatus::Clean);
        r.slash(10);
        assert_eq!(r.status, PenaltyStatus::Slashed);
        assert_eq!(r.slash_count, 1);
        assert!(!r.eligible_for_high_trust_role());
        // a second offence keeps it slashed; one revert is not enough.
        r.slash(11);
        assert_eq!(r.slash_count, 2);
        r.unslash();
        assert_eq!(r.status, PenaltyStatus::Slashed, "still slashed at count 1");
        r.unslash();
        assert_eq!(r.status, PenaltyStatus::Clean, "clean once last offence gone");
        assert_eq!(r.slash_count, 0);
    }

    #[test]
    fn persistent_penalty_apply_revert_exact_inverse() {
        let mut p = PersistentPenalty::new();
        let empty = p.digest();
        let off = [0xABu8; 20];
        p.apply_slash(off, 100, 0, 150);
        assert!(p.is_slashed(&off));
        assert!(p.is_offence_recorded(off, 100, 0));
        assert_ne!(p.digest(), empty);
        // duplicate apply is a no-op (de-dup).
        p.apply_slash(off, 100, 0, 150);
        assert_eq!(p.offence_count(), 1);
        // revert restores the empty state exactly.
        p.revert_slash(off, 100, 0);
        assert!(!p.is_slashed(&off));
        assert_eq!(p.status(&off), PenaltyStatus::Clean);
        assert!(p.is_empty());
        assert_eq!(p.digest(), empty, "apply then revert is an exact inverse");
    }

    #[test]
    fn persistent_penalty_multi_offence_per_offender() {
        let mut p = PersistentPenalty::new();
        let off = [0x07u8; 20];
        p.apply_slash(off, 100, 0, 150);
        p.apply_slash(off, 101, 0, 151); // distinct offence (different height)
        assert_eq!(p.offence_count(), 2);
        assert!(p.is_slashed(&off));
        p.revert_slash(off, 101, 0);
        assert!(p.is_slashed(&off), "still slashed by the first offence");
        p.revert_slash(off, 100, 0);
        assert!(!p.is_slashed(&off));
        assert!(p.is_empty());
    }

    #[test]
    fn persistent_penalty_digest_order_independent() {
        let a = [0x11u8; 20];
        let b = [0x22u8; 20];
        let mut p1 = PersistentPenalty::new();
        p1.apply_slash(a, 10, 0, 100);
        p1.apply_slash(b, 20, 0, 110);
        let mut p2 = PersistentPenalty::new();
        p2.apply_slash(b, 20, 0, 110);
        p2.apply_slash(a, 10, 0, 100);
        assert_eq!(p1.digest(), p2.digest());
    }

    #[test]
    fn penalty_escalation_and_expiry() {
        let t = PenaltyThresholds::default();
        let mut r = PenaltyRecord::new();
        assert!(r.eligible_for_high_trust_role());
        r.record_invalid_work(10, 5, &t); // 1 -> Warned
        assert_eq!(r.status, PenaltyStatus::Warned);
        assert!(r.eligible_for_high_trust_role());
        r.record_invalid_work(11, 5, &t); // 2
        r.record_invalid_work(12, 5, &t); // 3 -> TemporarilyReduced
        assert_eq!(r.status, PenaltyStatus::TemporarilyReduced);
        r.record_invalid_work(13, 5, &t); // 4
        r.record_invalid_work(14, 5, &t); // 5 -> Suspended (epoch 5 + 1 = 6)
        assert_eq!(r.status, PenaltyStatus::SuspendedForEpoch);
        assert_eq!(r.suspended_until_epoch, 6);
        assert!(
            !r.eligible_for_high_trust_role(),
            "suspended blocked for high-trust"
        );
        // not yet expired
        r.expire_if_due(5);
        assert_eq!(r.status, PenaltyStatus::SuspendedForEpoch);
        // expired
        r.expire_if_due(6);
        assert_eq!(r.status, PenaltyStatus::Warned);
        assert!(r.eligible_for_high_trust_role());
    }

    #[test]
    fn penalty_overflow_safe() {
        let t = PenaltyThresholds::default();
        let mut r = PenaltyRecord::new();
        r.invalid_count = u32::MAX;
        r.record_invalid_work(1, 1, &t); // saturating, no panic
        assert_eq!(r.invalid_count, u32::MAX);
        r.valid_count = u32::MAX;
        r.record_valid_work(2);
        assert_eq!(r.valid_count, u32::MAX);
    }

    #[test]
    fn penalty_gate_logic_pure() {
        assert!(!penalty_gate(0, Some(1), 100), "below the mainnet activation height; NOT hard-off (see activation::mainnet_gate_truth)");
        assert!(
            penalty_gate(1, Some(1), 100),
            "testnet active at/after height"
        );
        assert!(!penalty_gate(1, None, 100), "no activation -> off");
        assert!(!penalty_gate(1, Some(50), 10), "below activation -> off");
    }
}
