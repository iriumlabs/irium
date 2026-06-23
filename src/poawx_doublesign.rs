//! Phase 29: PoAW-X finality double-sign evidence + deterministic penalty wiring.
//!
//! Validates equivocation evidence — two individually-valid finality votes by the
//! SAME committee identity in the SAME finality domain
//! `(network_id, target_height, committee_epoch, vote_type, member_pkh)` but for
//! DIFFERENT `block_hash` — and applies a DETERMINISTIC, REPLAYABLE penalty
//! (suspension for a deterministic window) via the existing `poawx_penalty`
//! primitives. Testnet/devnet only; mainnet hard-off (`network_id == 0`).
//!
//! CONSENSUS-SAFETY (important): evidence validation + penalty state here are
//! PURE, deterministic, replayable PRIMITIVES. They are NOT wired into block
//! acceptance, the reward manifest, or committee selection in this phase, because
//! blocks do not yet CARRY double-sign evidence — letting local gossip evidence
//! affect consensus would let nodes that saw different evidence DIVERGE. A bounded
//! LOCAL evidence cache + a detection helper are provided for observability only;
//! they never reject blocks or change consensus. Full consensus enforcement
//! requires a future block-carried-evidence design (see Phase 29 docs).
#![allow(dead_code)]

use crate::activation::network_id_byte;
use crate::poawx_finality::{FinalityVoteV1, FINALITY_VOTE_WIRE};
use crate::poawx_gossip::GossipOutcome;
use crate::poawx_penalty::{PenaltyRecord, PenaltyStatus};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

pub const DOUBLE_SIGN_EVIDENCE_VERSION: u8 = 1;
const EVIDENCE_DOMAIN: &[u8] = b"IRIUM_POAWX_DOUBLE_SIGN_EVIDENCE_V1";
const PENALTY_STATE_DOMAIN: &[u8] = b"IRIUM_POAWX_DOUBLE_SIGN_PENALTY_STATE_V1";
/// version(1) + network(1) + two full finality votes.
pub const EVIDENCE_WIRE: usize = 1 + 1 + 2 * FINALITY_VOTE_WIRE;
pub const DOUBLE_SIGN_EVIDENCE_MAX_BYTES: usize = EVIDENCE_WIRE + 8;
/// Default suspension window (committee epochs) for a confirmed double-sign.
pub const DEFAULT_SUSPEND_EPOCHS: u64 = 1;
const EVIDENCE_CACHE_CAP: usize = 4096;

// ── Gate (testnet/devnet only; mainnet hard-off) ─────────────────────────────

pub fn double_sign_penalty_activation_height() -> Option<u64> {
    std::env::var("IRIUM_POAWX_DOUBLE_SIGN_PENALTY_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// Pure gate logic (network 0 = mainnet hard-off); param-driven for race-free tests.
pub fn double_sign_penalty_gate(network_id: u8, activation: Option<u64>, height: u64) -> bool {
    if network_id == 0 {
        return false;
    }
    matches!(activation, Some(h) if height >= h)
}

pub fn double_sign_penalty_active(height: u64) -> bool {
    double_sign_penalty_gate(
        network_id_byte(),
        double_sign_penalty_activation_height(),
        height,
    )
}

// ── Evidence ─────────────────────────────────────────────────────────────────

/// Validated double-sign (equivocation) evidence: two conflicting finality votes.
/// Stored in canonical order (votes sorted by digest) so the evidence id and wire
/// bytes do not depend on which vote was presented first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoawxDoubleSignEvidenceV1 {
    pub network_id: u8,
    pub vote_a: FinalityVoteV1,
    pub vote_b: FinalityVoteV1,
}

impl PoawxDoubleSignEvidenceV1 {
    /// Build evidence, canonicalizing the vote order (by digest).
    pub fn new(network_id: u8, v1: FinalityVoteV1, v2: FinalityVoteV1) -> Self {
        let (vote_a, vote_b) = if v1.digest() <= v2.digest() {
            (v1, v2)
        } else {
            (v2, v1)
        };
        Self {
            network_id,
            vote_a,
            vote_b,
        }
    }

    pub fn member_pkh(&self) -> [u8; 20] {
        self.vote_a.member_pkh
    }
    pub fn target_height(&self) -> u64 {
        self.vote_a.target_height
    }
    pub fn committee_epoch(&self) -> u64 {
        self.vote_a.committee_epoch
    }

    /// Canonical, order-independent evidence id (sorted vote digests).
    pub fn evidence_id(&self) -> [u8; 32] {
        let da = self.vote_a.digest();
        let db = self.vote_b.digest();
        let (lo, hi) = if da <= db { (da, db) } else { (db, da) };
        let mut h = Sha256::new();
        h.update(EVIDENCE_DOMAIN);
        h.update([DOUBLE_SIGN_EVIDENCE_VERSION]);
        h.update([self.network_id]);
        h.update(lo);
        h.update(hi);
        h.finalize().into()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(EVIDENCE_WIRE);
        o.push(DOUBLE_SIGN_EVIDENCE_VERSION);
        o.push(self.network_id);
        o.extend_from_slice(&self.vote_a.serialize());
        o.extend_from_slice(&self.vote_b.serialize());
        o
    }

    pub fn deserialize(raw: &[u8]) -> Result<Self, String> {
        if raw.len() != EVIDENCE_WIRE {
            return Err("double-sign evidence: bad length".to_string());
        }
        if raw[0] != DOUBLE_SIGN_EVIDENCE_VERSION {
            return Err("double-sign evidence: bad version".to_string());
        }
        let network_id = raw[1];
        let a = FinalityVoteV1::deserialize(&raw[2..2 + FINALITY_VOTE_WIRE])?;
        let b = FinalityVoteV1::deserialize(&raw[2 + FINALITY_VOTE_WIRE..])?;
        // Re-canonicalize on parse so the id is order-independent.
        Ok(Self::new(network_id, a, b))
    }

    /// Validate that this is genuine double-sign evidence against `committee`
    /// (the set of committee member pkhs eligible to vote). Mainnet hard-off.
    /// Fails closed: any check that does not hold ⇒ not evidence ⇒ no penalty.
    pub fn validate(&self, expected_network: u8, committee: &[[u8; 20]]) -> Result<(), String> {
        if expected_network == 0 {
            return Err("double-sign: mainnet hard-off".to_string());
        }
        if self.network_id != expected_network {
            return Err("double-sign: wrong network".to_string());
        }
        let a = &self.vote_a;
        let b = &self.vote_b;
        if a.network_id != expected_network || b.network_id != expected_network {
            return Err("double-sign: vote wrong network".to_string());
        }
        // Both votes individually valid (signature + binding to their own hash).
        a.verify(a.network_id, a.target_height, &a.block_hash)?;
        b.verify(b.network_id, b.target_height, &b.block_hash)?;
        // Same finality domain.
        if a.target_height != b.target_height {
            return Err("double-sign: different heights (not equivocation)".to_string());
        }
        if a.committee_epoch != b.committee_epoch {
            return Err("double-sign: different epoch".to_string());
        }
        if a.vote_type != b.vote_type {
            return Err("double-sign: different vote type".to_string());
        }
        // Same identity.
        if a.member_pkh != b.member_pkh || a.member_pubkey != b.member_pubkey {
            return Err("double-sign: different identity".to_string());
        }
        // The equivocation: different committed block hashes.
        if a.block_hash == b.block_hash {
            return Err("double-sign: same block hash (duplicate, not evidence)".to_string());
        }
        // Not the literal same vote.
        if a.digest() == b.digest() {
            return Err("double-sign: identical vote".to_string());
        }
        // Committee eligibility: the signer must be a committee member.
        if !committee.contains(&a.member_pkh) {
            return Err("double-sign: non-committee voter".to_string());
        }
        Ok(())
    }
}

/// Detect double-sign evidence among a set of finality votes (LOCAL/observability
/// helper). Returns one canonical evidence per equivocating identity pair found.
/// Pure + deterministic; does not validate committee membership (caller does).
pub fn detect_double_sign(votes: &[FinalityVoteV1]) -> Vec<PoawxDoubleSignEvidenceV1> {
    let mut out: Vec<PoawxDoubleSignEvidenceV1> = Vec::new();
    let mut seen: BTreeSet<[u8; 32]> = BTreeSet::new();
    for i in 0..votes.len() {
        for j in (i + 1)..votes.len() {
            let a = &votes[i];
            let b = &votes[j];
            if a.network_id == b.network_id
                && a.target_height == b.target_height
                && a.committee_epoch == b.committee_epoch
                && a.vote_type == b.vote_type
                && a.member_pkh == b.member_pkh
                && a.member_pubkey == b.member_pubkey
                && a.block_hash != b.block_hash
            {
                let ev = PoawxDoubleSignEvidenceV1::new(a.network_id, a.clone(), b.clone());
                let id = ev.evidence_id();
                if seen.insert(id) {
                    out.push(ev);
                }
            }
        }
    }
    out
}

// ── Deterministic, replayable penalty state ──────────────────────────────────

/// Penalty state driven by validated double-sign evidence. A pure function of the
/// SET of applied evidence: idempotent by evidence id, and the suspension window
/// uses a monotonic max, so the resulting state (and `digest`) is independent of
/// application order — i.e. replayable on every node from the same evidence set.
#[derive(Debug, Clone, Default)]
pub struct PoawxDoubleSignPenaltyState {
    records: BTreeMap<[u8; 20], PenaltyRecord>,
    applied: BTreeSet<[u8; 32]>,
}

impl PoawxDoubleSignPenaltyState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Validate + apply one piece of evidence. Returns Ok(true) if newly applied,
    /// Ok(false) if already applied (idempotent), Err if not valid evidence.
    pub fn apply_evidence(
        &mut self,
        ev: &PoawxDoubleSignEvidenceV1,
        committee: &[[u8; 20]],
        expected_network: u8,
        height: u64,
        suspend_epochs: u64,
    ) -> Result<bool, String> {
        ev.validate(expected_network, committee)?;
        let id = ev.evidence_id();
        if self.applied.contains(&id) {
            return Ok(false);
        }
        self.applied.insert(id);
        let rec = self.records.entry(ev.member_pkh()).or_default();
        rec.status = PenaltyStatus::SuspendedForEpoch;
        rec.invalid_count = rec.invalid_count.saturating_add(1);
        let until = ev.committee_epoch().saturating_add(suspend_epochs);
        rec.suspended_until_epoch = rec.suspended_until_epoch.max(until);
        rec.last_update_height = rec.last_update_height.max(height);
        Ok(true)
    }

    /// Effective penalty status for `pkh` at `current_epoch` (applies expiry).
    pub fn status(&self, pkh: &[u8; 20], current_epoch: u64) -> PenaltyStatus {
        match self.records.get(pkh) {
            None => PenaltyStatus::Clean,
            Some(r) => {
                let mut r = r.clone();
                r.expire_if_due(current_epoch);
                r.status
            }
        }
    }

    /// Whether `pkh` is eligible for the finality / high-trust role at `current_epoch`.
    pub fn is_eligible_for_finality(&self, pkh: &[u8; 20], current_epoch: u64) -> bool {
        self.status(pkh, current_epoch)
            .eligible_for_high_trust_role()
    }

    pub fn penalized_count(&self) -> usize {
        self.records.len()
    }
    pub fn evidence_count(&self) -> usize {
        self.applied.len()
    }

    /// Deterministic state commitment (order-independent). Useful for replay tests
    /// and a future consensus-carried-evidence design.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(PENALTY_STATE_DOMAIN);
        h.update((self.records.len() as u64).to_le_bytes());
        for (pkh, r) in &self.records {
            h.update(pkh);
            h.update([r.status.id()]);
            h.update(r.invalid_count.to_le_bytes());
            h.update(r.suspended_until_epoch.to_le_bytes());
        }
        h.finalize().into()
    }
}

// ── Bounded LOCAL evidence cache (observability only; NOT consensus) ──────────

/// A bounded, dedup'd local cache of validated double-sign evidence. LOCAL ONLY:
/// it never rejects blocks or alters consensus. Mainnet hard-off.
pub struct NodeDoubleSignEvidenceCache {
    evidence: Mutex<BTreeMap<[u8; 32], PoawxDoubleSignEvidenceV1>>,
}

impl Default for NodeDoubleSignEvidenceCache {
    fn default() -> Self {
        Self {
            evidence: Mutex::new(BTreeMap::new()),
        }
    }
}

impl NodeDoubleSignEvidenceCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn ingest(&self, ev: PoawxDoubleSignEvidenceV1, committee: &[[u8; 20]]) -> GossipOutcome {
        let net = network_id_byte();
        if net == 0 {
            return GossipOutcome::Rejected("mainnet hard-off".to_string());
        }
        if let Err(e) = ev.validate(net, committee) {
            return GossipOutcome::Rejected(e);
        }
        let id = ev.evidence_id();
        let mut map = self.evidence.lock().unwrap_or_else(|e| e.into_inner());
        if map.contains_key(&id) {
            return GossipOutcome::Duplicate;
        }
        // Bounded: evict the lexicographically-smallest id deterministically.
        while map.len() >= EVIDENCE_CACHE_CAP {
            if let Some((&k, _)) = map.iter().next() {
                map.remove(&k);
            } else {
                break;
            }
        }
        map.insert(id, ev);
        GossipOutcome::AcceptedNew
    }

    pub fn ingest_bytes(&self, bytes: &[u8], committee: &[[u8; 20]]) -> GossipOutcome {
        if bytes.len() > DOUBLE_SIGN_EVIDENCE_MAX_BYTES {
            return GossipOutcome::Rejected("double-sign evidence oversize".to_string());
        }
        match PoawxDoubleSignEvidenceV1::deserialize(bytes) {
            Ok(ev) => self.ingest(ev, committee),
            Err(e) => GossipOutcome::Rejected(e),
        }
    }

    pub fn len(&self) -> usize {
        self.evidence
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn clear(&self) {
        self.evidence
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }
    pub fn all(&self) -> Vec<PoawxDoubleSignEvidenceV1> {
        self.evidence
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poawx_finality::FinalityVoteType;
    use k256::ecdsa::SigningKey;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_slice(&[seed; 32]).expect("sk")
    }

    /// Build a signed Commit vote for the given context.
    fn vote(
        sk: &SigningKey,
        net: u8,
        height: u64,
        epoch: u64,
        block_hash: [u8; 32],
    ) -> FinalityVoteV1 {
        FinalityVoteV1::signed(
            sk,
            net,
            height,
            block_hash,
            [0x33u8; 32],
            epoch,
            [0x11u8; 32],
            FinalityVoteType::Commit,
        )
    }

    const NET: u8 = 1; // testnet

    #[test]
    fn phase29_accepts_valid_double_sign_evidence() {
        let sk = key(0x21);
        let va = vote(&sk, NET, 10, 0, [0xAAu8; 32]);
        let vb = vote(&sk, NET, 10, 0, [0xBBu8; 32]);
        let committee = vec![va.member_pkh];
        let ev = PoawxDoubleSignEvidenceV1::new(NET, va.clone(), vb.clone());
        assert!(ev.validate(NET, &committee).is_ok(), "valid equivocation");

        let mut st = PoawxDoubleSignPenaltyState::new();
        assert_eq!(
            st.apply_evidence(&ev, &committee, NET, 10, DEFAULT_SUSPEND_EPOCHS),
            Ok(true)
        );
        assert_eq!(st.penalized_count(), 1, "one identity penalized");
        assert_eq!(
            st.status(&va.member_pkh, 0),
            PenaltyStatus::SuspendedForEpoch
        );
        // Re-applying the same evidence is idempotent (no double count).
        assert_eq!(
            st.apply_evidence(&ev, &committee, NET, 10, DEFAULT_SUSPEND_EPOCHS),
            Ok(false)
        );
        assert_eq!(st.evidence_count(), 1);
    }

    #[test]
    fn phase29_duplicate_vote_is_not_double_sign() {
        let sk = key(0x22);
        let v = vote(&sk, NET, 10, 0, [0xAAu8; 32]);
        let committee = vec![v.member_pkh];
        let ev = PoawxDoubleSignEvidenceV1::new(NET, v.clone(), v.clone());
        assert!(
            ev.validate(NET, &committee).is_err(),
            "same vote is not equivocation"
        );
        let mut st = PoawxDoubleSignPenaltyState::new();
        assert!(st.apply_evidence(&ev, &committee, NET, 10, 1).is_err());
        assert_eq!(st.penalized_count(), 0);
    }

    #[test]
    fn phase29_rejects_invalid_double_sign_signature() {
        let sk = key(0x23);
        let va = vote(&sk, NET, 10, 0, [0xAAu8; 32]);
        let mut vb = vote(&sk, NET, 10, 0, [0xBBu8; 32]);
        vb.signature[0] ^= 0xFF; // corrupt one signature
        let committee = vec![va.member_pkh];
        let ev = PoawxDoubleSignEvidenceV1::new(NET, va, vb);
        assert!(
            ev.validate(NET, &committee).is_err(),
            "invalid signature is not valid evidence"
        );
    }

    #[test]
    fn phase29_rejects_wrong_network_evidence() {
        let sk = key(0x24);
        let va = vote(&sk, NET, 10, 0, [0xAAu8; 32]);
        let vb = vote(&sk, NET, 10, 0, [0xBBu8; 32]);
        let committee = vec![va.member_pkh];
        let ev = PoawxDoubleSignEvidenceV1::new(NET, va, vb);
        // Validating against a different network id is rejected.
        assert!(ev.validate(2, &committee).is_err(), "wrong network");
        // Mainnet hard-off.
        assert!(ev.validate(0, &committee).is_err(), "mainnet hard-off");
    }

    #[test]
    fn phase29_rejects_non_committee_double_sign() {
        let sk = key(0x25);
        let va = vote(&sk, NET, 10, 0, [0xAAu8; 32]);
        let vb = vote(&sk, NET, 10, 0, [0xBBu8; 32]);
        let ev = PoawxDoubleSignEvidenceV1::new(NET, va, vb);
        // Empty committee / different member ⇒ not a committee voter.
        assert!(ev.validate(NET, &[]).is_err(), "non-committee voter");
        assert!(ev.validate(NET, &[[0x00u8; 20]]).is_err());
    }

    #[test]
    fn phase29_different_heights_not_double_sign() {
        let sk = key(0x26);
        let va = vote(&sk, NET, 10, 0, [0xAAu8; 32]);
        let vb = vote(&sk, NET, 11, 0, [0xBBu8; 32]); // different height
        let committee = vec![va.member_pkh];
        let ev = PoawxDoubleSignEvidenceV1::new(NET, va, vb);
        assert!(
            ev.validate(NET, &committee).is_err(),
            "different heights is not equivocation"
        );
    }

    #[test]
    fn phase29_double_sign_evidence_canonical_order() {
        let sk = key(0x27);
        let va = vote(&sk, NET, 10, 0, [0xAAu8; 32]);
        let vb = vote(&sk, NET, 10, 0, [0xBBu8; 32]);
        let e1 = PoawxDoubleSignEvidenceV1::new(NET, va.clone(), vb.clone());
        let e2 = PoawxDoubleSignEvidenceV1::new(NET, vb, va);
        assert_eq!(e1.evidence_id(), e2.evidence_id(), "order-independent id");
        assert_eq!(e1.serialize(), e2.serialize(), "order-independent wire");
        // Wire round-trip preserves the id.
        let parsed = PoawxDoubleSignEvidenceV1::deserialize(&e1.serialize()).unwrap();
        assert_eq!(parsed.evidence_id(), e1.evidence_id());
    }

    #[test]
    fn phase29_penalized_finality_member_ineligible() {
        let sk = key(0x28);
        let va = vote(&sk, NET, 10, 5, [0xAAu8; 32]); // committee_epoch = 5
        let vb = vote(&sk, NET, 10, 5, [0xBBu8; 32]);
        let committee = vec![va.member_pkh];
        let ev = PoawxDoubleSignEvidenceV1::new(NET, va.clone(), vb);
        let mut st = PoawxDoubleSignPenaltyState::new();
        st.apply_evidence(&ev, &committee, NET, 10, 1).unwrap();
        // Suspended through epoch < until (5 + 1 = 6): ineligible at epoch 5.
        assert!(
            !st.is_eligible_for_finality(&va.member_pkh, 5),
            "penalized member ineligible during window"
        );
        // After the window (epoch >= 6): eligible again (Warned).
        assert!(
            st.is_eligible_for_finality(&va.member_pkh, 6),
            "eligible after suspension window expires"
        );
        // An unpenalized member is always eligible.
        assert!(st.is_eligible_for_finality(&[0x77u8; 20], 5));
    }

    #[test]
    fn phase29_penalty_state_replays_deterministically() {
        // Two distinct pieces of evidence for two members. Applying them in either
        // order yields the same state digest (order-independent ⇒ replayable).
        let ska = key(0x31);
        let skb = key(0x32);
        let a1 = vote(&ska, NET, 20, 2, [0x01u8; 32]);
        let a2 = vote(&ska, NET, 20, 2, [0x02u8; 32]);
        let b1 = vote(&skb, NET, 21, 2, [0x03u8; 32]);
        let b2 = vote(&skb, NET, 21, 2, [0x04u8; 32]);
        let committee = vec![a1.member_pkh, b1.member_pkh];
        let ea = PoawxDoubleSignEvidenceV1::new(NET, a1, a2);
        let eb = PoawxDoubleSignEvidenceV1::new(NET, b1, b2);

        let mut s1 = PoawxDoubleSignPenaltyState::new();
        s1.apply_evidence(&ea, &committee, NET, 20, 1).unwrap();
        s1.apply_evidence(&eb, &committee, NET, 21, 1).unwrap();

        let mut s2 = PoawxDoubleSignPenaltyState::new();
        s2.apply_evidence(&eb, &committee, NET, 21, 1).unwrap();
        s2.apply_evidence(&ea, &committee, NET, 20, 1).unwrap();
        // Re-apply (idempotent) — must not change the state.
        s2.apply_evidence(&ea, &committee, NET, 20, 1).unwrap();

        assert_eq!(
            s1.digest(),
            s2.digest(),
            "penalty state is order-independent"
        );
        assert_eq!(s1.penalized_count(), 2);
    }

    #[test]
    fn phase29_mainnet_applies_no_penalty() {
        let sk = key(0x29);
        let va = vote(&sk, 0, 10, 0, [0xAAu8; 32]); // network 0 = mainnet
        let vb = vote(&sk, 0, 10, 0, [0xBBu8; 32]);
        let committee = vec![va.member_pkh];
        let ev = PoawxDoubleSignEvidenceV1::new(0, va, vb);
        let mut st = PoawxDoubleSignPenaltyState::new();
        assert!(
            st.apply_evidence(&ev, &committee, 0, 10, 1).is_err(),
            "mainnet hard-off: no penalty"
        );
        assert_eq!(st.penalized_count(), 0);
        assert!(
            !double_sign_penalty_gate(0, Some(1), 100),
            "gate mainnet off"
        );
        assert!(double_sign_penalty_gate(1, Some(1), 100), "gate testnet on");
    }

    #[test]
    fn phase29_detect_double_sign_from_votes() {
        let sk = key(0x2A);
        let other = key(0x2B);
        let va = vote(&sk, NET, 10, 0, [0xAAu8; 32]);
        let vb = vote(&sk, NET, 10, 0, [0xBBu8; 32]); // equivocation
        let vc = vote(&other, NET, 10, 0, [0xCCu8; 32]); // different member, honest
        let found = detect_double_sign(&[va.clone(), vc, vb.clone()]);
        assert_eq!(found.len(), 1, "exactly one equivocation pair");
        assert_eq!(found[0].member_pkh(), va.member_pkh);
    }

    #[test]
    fn phase29_local_evidence_cache_bounded_and_dedup() {
        // Uses the real network id; the cache validates against network_id_byte().
        // Build evidence on the current network and assert dedup + malformed reject.
        let net = network_id_byte();
        if net == 0 {
            // On mainnet the cache rejects everything (hard-off) — assert that.
            let cache = NodeDoubleSignEvidenceCache::new();
            let sk = key(0x2C);
            let va = vote(&sk, net, 10, 0, [0xAAu8; 32]);
            let vb = vote(&sk, net, 10, 0, [0xBBu8; 32]);
            let ev = PoawxDoubleSignEvidenceV1::new(net, va, vb);
            assert!(matches!(cache.ingest(ev, &[]), GossipOutcome::Rejected(_)));
            return;
        }
        let cache = NodeDoubleSignEvidenceCache::new();
        let sk = key(0x2C);
        let va = vote(&sk, net, 10, 0, [0xAAu8; 32]);
        let vb = vote(&sk, net, 10, 0, [0xBBu8; 32]);
        let committee = vec![va.member_pkh];
        let ev = PoawxDoubleSignEvidenceV1::new(net, va, vb);
        assert_eq!(
            cache.ingest(ev.clone(), &committee),
            GossipOutcome::AcceptedNew
        );
        assert_eq!(
            cache.ingest(ev.clone(), &committee),
            GossipOutcome::Duplicate
        );
        assert_eq!(cache.len(), 1);
        // Malformed bytes rejected.
        assert!(matches!(
            cache.ingest_bytes(&[0u8; 4], &committee),
            GossipOutcome::Rejected(_)
        ));
        // Wire round-trip ingests as duplicate (same id).
        assert_eq!(
            cache.ingest_bytes(&ev.serialize(), &committee),
            GossipOutcome::Duplicate
        );
        cache.clear();
        assert!(cache.is_empty());
    }
}
