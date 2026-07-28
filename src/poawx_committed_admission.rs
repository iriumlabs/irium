//! Phase 22A: chain-committed candidate admission.
//!
//! Strengthens Phase 21E (which validated a block's candidate set against the
//! validating node's *local* admission cache) by **chain-committing** the admitted
//! candidate-set root in a prior block. Block `H-1` carries an
//! `AdmissionCommitmentV1` for target height `H` (root over the admitted candidate
//! set, bound to the freeze seed = `H-1`'s parent hash, known when `H-1` is
//! produced — no circularity). Block `H`'s candidate set must reproduce that exact
//! committed root, so the producer of `H` cannot silently add/omit candidates
//! relative to the `H-1` commitment.
//!
//! HONEST LIMITATION: this does NOT prove offline / never-gossiped miners existed.
//! It makes the admitted set chain-committed before selection (removing the
//! per-node-cache divergence at selection time and the silent-omission attack at
//! `H`). Deterministic, bounded, no floats, no wall-clock. Gated + mainnet-ACTIVE at height >= 50_000.
//!
//! ⚠ MAINNET STATUS (corrected 2026-07-19): this module's gates are NOT "mainnet
//! hard-off". They route through `activation::poawx_effective_activation`, which on
//! `network_id == 0` IGNORES the env and substitutes the compiled
//! `MAINNET_POAWX_ACTIVATION_HEIGHT = Some(50_000)`. Mainnet is far past that height,
//! so these gates are ACTIVE in production. Any remaining "mainnet hard-off" wording
//! below is stale. The authoritative, height-accurate check is
//! `activation::mainnet_gate_truth`.
#![allow(dead_code)]

use sha2::{Digest, Sha256};

use crate::activation::network_id_byte;
use crate::block::Block;
use crate::poawx_candidate::CandidateSet;

const COMMITMENT_DOMAIN: &[u8] = b"IRIUM_POAWX_ADMISSION_COMMITMENT_V1";
/// 4-byte trailing-section magic for the committed admission in the Phase 20 ext.
pub const COMMITTED_ADMISSION_SECTION_MAGIC: &[u8; 4] = b"CAC1";
pub const ADMISSION_COMMITMENT_VERSION: u8 = 1;
/// Wire: version(1)+net(1)+target(8)+commit(8)+seed(32)+root(32)+count(2)+window(8)+digest(32).
pub const ADMISSION_COMMITMENT_WIRE: usize = 1 + 1 + 8 + 8 + 32 + 32 + 2 + 8 + 32; // 124
/// Upper bound on committed candidate count (matches the candidate-set bound).
pub const MAX_COMMITTED_CANDIDATES: u16 = 4096;
/// Default admission-freeze window length (blocks).
pub const DEFAULT_COMMITTED_ADMISSION_WINDOW: u64 = 64;

/// Chain-committed admission root for a target height. Carried in the COMMIT block
/// (`commit_height = target_height - 1`) and matched by the candidate set at the
/// target block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionCommitmentV1 {
    pub version: u8,
    pub network_id: u8,
    pub target_height: u64,
    pub commit_height: u64,
    pub seed: [u8; 32],
    pub candidate_admission_root: [u8; 32],
    pub candidate_count: u16,
    pub window_id: u64,
    pub digest: [u8; 32],
}

#[allow(clippy::too_many_arguments)]
fn commitment_digest(
    network_id: u8,
    target_height: u64,
    commit_height: u64,
    seed: &[u8; 32],
    candidate_admission_root: &[u8; 32],
    candidate_count: u16,
    window_id: u64,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(COMMITMENT_DOMAIN);
    h.update([ADMISSION_COMMITMENT_VERSION]);
    h.update([network_id]);
    h.update(target_height.to_le_bytes());
    h.update(commit_height.to_le_bytes());
    h.update(seed);
    h.update(candidate_admission_root);
    h.update(candidate_count.to_le_bytes());
    h.update(window_id.to_le_bytes());
    h.finalize().into()
}

impl AdmissionCommitmentV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network_id: u8,
        target_height: u64,
        commit_height: u64,
        seed: [u8; 32],
        candidate_admission_root: [u8; 32],
        candidate_count: u16,
        window_id: u64,
    ) -> Self {
        let digest = commitment_digest(
            network_id,
            target_height,
            commit_height,
            &seed,
            &candidate_admission_root,
            candidate_count,
            window_id,
        );
        Self {
            version: ADMISSION_COMMITMENT_VERSION,
            network_id,
            target_height,
            commit_height,
            seed,
            candidate_admission_root,
            candidate_count,
            window_id,
            digest,
        }
    }

    /// Build the commitment for `target_height` from the admitted candidate set
    /// (which carries the freeze seed + the candidates). `commit_height` is the
    /// producing block's height (`target_height - 1`).
    pub fn from_candidate_set(cs: &CandidateSet, commit_height: u64) -> Self {
        Self::new(
            cs.network_id,
            cs.target_height,
            commit_height,
            cs.seed,
            cs.root(),
            cs.candidates.len().min(u16::MAX as usize) as u16,
            committed_admission_window_id(cs.target_height),
        )
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(ADMISSION_COMMITMENT_WIRE);
        o.push(self.version);
        o.push(self.network_id);
        o.extend_from_slice(&self.target_height.to_le_bytes());
        o.extend_from_slice(&self.commit_height.to_le_bytes());
        o.extend_from_slice(&self.seed);
        o.extend_from_slice(&self.candidate_admission_root);
        o.extend_from_slice(&self.candidate_count.to_le_bytes());
        o.extend_from_slice(&self.window_id.to_le_bytes());
        o.extend_from_slice(&self.digest);
        o
    }

    pub fn deserialize(raw: &[u8]) -> Result<Self, String> {
        if raw.len() != ADMISSION_COMMITMENT_WIRE {
            return Err("admission commitment: bad length".to_string());
        }
        let version = raw[0];
        if version != ADMISSION_COMMITMENT_VERSION {
            return Err(format!("admission commitment: unknown version {version}"));
        }
        let network_id = raw[1];
        let mut p = 2usize;
        let mut h8 = [0u8; 8];
        h8.copy_from_slice(&raw[p..p + 8]);
        let target_height = u64::from_le_bytes(h8);
        p += 8;
        h8.copy_from_slice(&raw[p..p + 8]);
        let commit_height = u64::from_le_bytes(h8);
        p += 8;
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&raw[p..p + 32]);
        p += 32;
        let mut candidate_admission_root = [0u8; 32];
        candidate_admission_root.copy_from_slice(&raw[p..p + 32]);
        p += 32;
        let candidate_count = u16::from_le_bytes([raw[p], raw[p + 1]]);
        p += 2;
        h8.copy_from_slice(&raw[p..p + 8]);
        let window_id = u64::from_le_bytes(h8);
        p += 8;
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&raw[p..p + 32]);
        if candidate_count > MAX_COMMITTED_CANDIDATES {
            return Err("admission commitment: candidate count over cap".to_string());
        }
        Ok(Self {
            version,
            network_id,
            target_height,
            commit_height,
            seed,
            candidate_admission_root,
            candidate_count,
            window_id,
            digest,
        })
    }

    /// Validate self-consistency + binding: recompute the digest, check version,
    /// network, target height, commit_height == target_height - 1, and count cap.
    pub fn validate(&self, network_id: u8, target_height: u64) -> Result<(), String> {
        if self.version != ADMISSION_COMMITMENT_VERSION {
            return Err("admission commitment: bad version".to_string());
        }
        if self.network_id != network_id {
            return Err("admission commitment: wrong network".to_string());
        }
        if self.target_height != target_height {
            return Err("admission commitment: wrong target height".to_string());
        }
        // Self-commit (commit_height == target) OR legacy one-ahead (target - 1).
        if self.commit_height != self.target_height
            && self.commit_height + 1 != self.target_height
        {
            return Err("admission commitment: commit_height must be target or target-1".to_string());
        }
        if self.candidate_count > MAX_COMMITTED_CANDIDATES {
            return Err("admission commitment: candidate count over cap".to_string());
        }
        let expect = commitment_digest(
            self.network_id,
            self.target_height,
            self.commit_height,
            &self.seed,
            &self.candidate_admission_root,
            self.candidate_count,
            self.window_id,
        );
        if expect != self.digest {
            return Err("admission commitment: digest mismatch".to_string());
        }
        Ok(())
    }

    /// Whether a candidate set exactly matches this commitment (root + count +
    /// seed). The candidate set's `root()` binds network/height/seed/candidates.
    pub fn matches_candidate_set(&self, cs: &CandidateSet) -> bool {
        cs.root() == self.candidate_admission_root
            && (cs.candidates.len().min(u16::MAX as usize) as u16) == self.candidate_count
            && cs.seed == self.seed
            && cs.network_id == self.network_id
            && cs.target_height == self.target_height
    }
}

// ── Admission epoch seed (Phase 26B seed reconciliation) ─────────────────────

/// The candidate-admission EPOCH seed for a block at height `H`.
///
/// The candidate set / admissions for `H` are FROZEN one block ahead by the
/// parent's outgoing committed admission, whose freeze seed is the parent block's
/// `prev_hash` (= the grandparent hash, `hash(H-2)`). So the epoch seed for `H` is
/// the parent's `prev_hash`. At the activation boundary — when the parent is the
/// genesis block, whose `prev_hash` is all-zero — the epoch seed is THIS block's
/// `prev_hash` (the genesis hash), and the incoming committed-admission check is
/// graced. This reconciles the phase21d candidate-set gate (which validates this
/// seed) with the phase22a committed-admission gate (whose parent commitment
/// carries exactly this seed), making multi-block chains satisfiable WITHOUT
/// weakening either gate. Pure; no wire-format change. Mainnet behavior is
/// unaffected (the PoAW-X gates remain hard-off for `network_id == 0`).
///
/// `parent_prev_hash` is the parent (tip) block's own `prev_hash` (`None` if there
/// is no parent). `block_prev_hash` is the current block's `prev_hash`.
pub fn admission_epoch_seed(parent_prev_hash: Option<[u8; 32]>, block_prev_hash: [u8; 32]) -> [u8; 32] {
    match parent_prev_hash {
        // Parent is a real (non-genesis) block: its prev_hash is the grandparent
        // hash and equals the seed it froze for this height.
        Some(p) if p != [0u8; 32] => p,
        // Activation boundary (parent is genesis, or no parent): use this block's
        // prev_hash (the genesis hash); incoming committed admission is graced.
        _ => block_prev_hash,
    }
}

// ── Gap 3: multi-source assignment seed (gated; mainnet-ACTIVE at height >= 50_000) ─────────────
//
// The legacy assignment seed (above) is the single grandparent hash, which a
// party mining consecutive blocks can grind. When the multi-source gate is
// active, the seed for height T mixes FOUR sources, all sealed by/at block T-1
// (so the committed-admission freeze one block ahead and the validator at T
// agree, and the proposer of T cannot set them):
//   1. base grandparent hash  (= legacy `admission_epoch_seed`; the prev-block source)
//   2. parent finality-proof digest  (committee signatures -> the anti-grind core)
//   3. parent precommit_root         (hidden-precommit miner commitments)
//   4. epoch index keying            (epoch_entropy; domain-separates per epoch)
// Off by default => `resolve_epoch_seed` returns the legacy base, byte-identical.

const ASSIGNMENT_SEED_DOMAIN_V2: &[u8] = b"IRIUM_POAWX_ASSIGNMENT_SEED_V2";
/// Blocks per seed epoch (epoch index = target_height / SEED_EPOCH_LEN).
pub const SEED_EPOCH_LEN: u64 = 2016;

pub fn multisource_seed_activation_height() -> Option<u64> {
    std::env::var("IRIUM_POAWX_MULTISOURCE_SEED_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// Pure gate (network 0 = mainnet hard-off); param-driven for race-free tests.
pub fn multisource_seed_gate(network_id: u8, activation: Option<u64>, height: u64) -> bool {
    matches!(crate::activation::poawx_effective_activation(network_id, activation), Some(h) if height >= h)
}

/// Whether the multi-source assignment seed is active at `height`. Mainnet hard-off.
pub fn multisource_seed_active(height: u64) -> bool {
    multisource_seed_gate(
        network_id_byte(),
        multisource_seed_activation_height(),
        height,
    )
}

/// Pure v2 seed math: SHA256(DOMAIN ‖ base ‖ finality_sig_digest ‖
/// precommit_digest ‖ epoch_index_le). Deterministic; integer-only.
pub fn assignment_seed_v2(
    base: &[u8; 32],
    finality_sig_digest: &[u8; 32],
    precommit_digest: &[u8; 32],
    epoch_index: u64,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ASSIGNMENT_SEED_DOMAIN_V2);
    h.update(base);
    h.update(finality_sig_digest);
    h.update(precommit_digest);
    h.update(epoch_index.to_le_bytes());
    h.finalize().into()
}

/// Extract the (finality_sig_digest, precommit_digest) seed components from a
/// block's first PoAW-X receipt extension. Absent block / receipt / section =>
/// the zero digest (so pre-gate parents contribute nothing). Pure.
pub fn seed_components_from_block(b: Option<&Block>) -> ([u8; 32], [u8; 32]) {
    let ext = b
        .and_then(|bl| bl.poawx_receipts.as_ref())
        .and_then(|rs| rs.first())
        .and_then(|r| r.phase20_ext.as_ref());
    let finality_sig_digest = ext
        .and_then(|e| e.finality_proof.as_ref())
        .map(|fp| fp.digest())
        .unwrap_or([0u8; 32]);
    let precommit_digest = ext.and_then(|e| e.precommit_root).unwrap_or([0u8; 32]);
    (finality_sig_digest, precommit_digest)
}

/// Resolve the epoch (assignment) seed for `target_height` from explicit parts.
/// Off (gate inactive) => the legacy `base` grandparent hash, byte-identical.
/// Used by builders (e.g. the harness) that hold the parts directly.
pub fn resolve_epoch_seed_parts(
    target_height: u64,
    base: [u8; 32],
    finality_sig_digest: [u8; 32],
    precommit_digest: [u8; 32],
) -> [u8; 32] {
    resolve_epoch_seed_parts_with(
        multisource_seed_active(target_height),
        target_height,
        base,
        finality_sig_digest,
        precommit_digest,
    )
}

/// Like [`resolve_epoch_seed_parts`] but with the multi-source gate state supplied
/// explicitly (e.g. by the node's block template), so a standalone miner uses the
/// node-authoritative flag instead of its own env. Mainnet-hard-off semantics
/// unchanged (the node computes the flag from its own gates).
pub fn resolve_epoch_seed_parts_with(
    multisource_active: bool,
    target_height: u64,
    base: [u8; 32],
    finality_sig_digest: [u8; 32],
    precommit_digest: [u8; 32],
) -> [u8; 32] {
    if !multisource_active {
        return base;
    }
    assignment_seed_v2(
        &base,
        &finality_sig_digest,
        &precommit_digest,
        target_height / SEED_EPOCH_LEN,
    )
}

/// Resolve the epoch (assignment) seed for `target_height` given the block whose
/// hash is `target_prev_hash` (T's prev) and T's `parent` block (T-1) from which
/// the finality/precommit components are taken. Off => legacy grandparent hash.
/// This is the single source of truth used by the candidate-set gate and BOTH
/// committed-admission seed checks so they never diverge.
pub fn expected_epoch_seed(
    target_height: u64,
    target_prev_hash: [u8; 32],
    parent: Option<&Block>,
) -> [u8; 32] {
    let base = admission_epoch_seed(parent.map(|p| p.header.prev_hash), target_prev_hash);
    let (fin, pre) = seed_components_from_block(parent);
    resolve_epoch_seed_parts(target_height, base, fin, pre)
}

// ── Gates (param-driven; mainnet-ACTIVE at height >= 50_000) ───────────────────────────────────

pub fn committed_admission_window() -> u64 {
    std::env::var("IRIUM_POAWX_COMMITTED_ADMISSION_WINDOW")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|w| *w >= 1)
        .unwrap_or(DEFAULT_COMMITTED_ADMISSION_WINDOW)
}
pub fn committed_admission_window_id(target_height: u64) -> u64 {
    target_height / committed_admission_window()
}
pub fn committed_admission_activation_height() -> Option<u64> {
    std::env::var("IRIUM_POAWX_COMMITTED_ADMISSION_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}
pub fn committed_admission_required() -> bool {
    if crate::activation::network_id_byte() == 0 {
        return true; // mainnet: enforced once the gate is active (height-gated)
    }
    std::env::var("IRIUM_POAWX_COMMITTED_ADMISSION_REQUIRED")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}
pub fn committed_admission_gate(network_id: u8, activation: Option<u64>, height: u64) -> bool {
    matches!(crate::activation::poawx_effective_activation(network_id, activation), Some(h) if height >= h)
}
pub fn committed_admission_enforced_gate(
    network_id: u8,
    activation: Option<u64>,
    required: bool,
    height: u64,
) -> bool {
    committed_admission_gate(network_id, activation, height) && required
}
pub fn committed_admission_active(height: u64) -> bool {
    committed_admission_gate(
        network_id_byte(),
        committed_admission_activation_height(),
        height,
    )
}
pub fn committed_admission_enforced(height: u64) -> bool {
    committed_admission_enforced_gate(
        network_id_byte(),
        committed_admission_activation_height(),
        committed_admission_required(),
        height,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poawx_candidate::{CandidateSet, RoleCandidate};
    use crate::poawx_penalty::PenaltyStatus;

    fn sample_set(net: u8, h: u64, seed: [u8; 32]) -> CandidateSet {
        let mut cs = CandidateSet::new(net, h, seed);
        cs.push(RoleCandidate::build(
            net,
            h,
            &seed,
            1,
            [0xC1u8; 20],
            [0x02u8; 33],
            [0x11u8; 32],
            PenaltyStatus::Clean.id(),
            1000,
            [0x21u8; 32],
        ));
        cs.push(RoleCandidate::build(
            net,
            h,
            &seed,
            2,
            [0xC2u8; 20],
            [0x02u8; 33],
            [0x12u8; 32],
            PenaltyStatus::Clean.id(),
            1000,
            [0x22u8; 32],
        ));
        cs.sort_canonical();
        cs
    }

    #[test]
    fn phase24a_committed_admission_wire_malformed_rejected() {
        let _env = crate::test_env::guard();
        assert!(AdmissionCommitmentV1::deserialize(&[0u8; ADMISSION_COMMITMENT_WIRE - 1]).is_err());
        assert!(AdmissionCommitmentV1::deserialize(&[0u8; ADMISSION_COMMITMENT_WIRE + 1]).is_err());
        assert!(AdmissionCommitmentV1::deserialize(&[]).is_err());
        // all-zeros at exact length still rejects (version byte guard).
        assert!(AdmissionCommitmentV1::deserialize(&[0u8; ADMISSION_COMMITMENT_WIRE]).is_err());
    }

    #[test]
    fn commitment_wire_roundtrip_and_validate() {
        let _env = crate::test_env::guard();
        let seed = [0x44u8; 32];
        let cs = sample_set(1, 11, seed);
        let c = AdmissionCommitmentV1::from_candidate_set(&cs, 10);
        let b = c.serialize();
        assert_eq!(b.len(), ADMISSION_COMMITMENT_WIRE);
        assert_eq!(AdmissionCommitmentV1::deserialize(&b).unwrap(), c);
        assert!(c.validate(1, 11).is_ok());
        assert!(c.validate(2, 11).is_err(), "wrong network");
        assert!(c.validate(1, 12).is_err(), "wrong target height");
        assert!(c.matches_candidate_set(&cs), "matches its source set");
    }

    #[test]
    fn mutation_changes_digest_and_breaks_match() {
        let _env = crate::test_env::guard();
        let seed = [0x44u8; 32];
        let cs = sample_set(1, 11, seed);
        let c = AdmissionCommitmentV1::from_candidate_set(&cs, 10);
        // mutate the committed root -> validate (digest) fails + match fails.
        let mut m = c.clone();
        m.candidate_admission_root[0] ^= 1;
        assert!(m.validate(1, 11).is_err(), "root mutation breaks digest");
        // a different candidate set (mutated) no longer matches the commitment.
        let mut cs2 = cs.clone();
        cs2.candidates[0].dominance_weight ^= 1;
        assert!(!c.matches_candidate_set(&cs2), "mutated set fails match");
    }

    #[test]
    fn commit_height_must_be_target_minus_one() {
        let _env = crate::test_env::guard();
        let seed = [0x44u8; 32];
        let cs = sample_set(1, 11, seed);
        // commit_height 9 (not 10) for target 11 -> invalid.
        let bad = AdmissionCommitmentV1::new(1, 11, 9, seed, cs.root(), 2, 0);
        assert!(
            bad.validate(1, 11).is_err(),
            "commit_height must be target-1"
        );
        let good = AdmissionCommitmentV1::new(1, 11, 10, seed, cs.root(), 2, 0);
        assert!(good.validate(1, 11).is_ok());
    }

    #[test]
    fn count_cap_enforced_on_deserialize() {
        let _env = crate::test_env::guard();
        let seed = [0x44u8; 32];
        let mut c = AdmissionCommitmentV1::new(1, 11, 10, seed, [0u8; 32], 2, 0);
        c.candidate_count = MAX_COMMITTED_CANDIDATES + 1;
        // re-stamp digest so only the cap check fires.
        c.digest = commitment_digest(1, 11, 10, &seed, &[0u8; 32], c.candidate_count, 0);
        assert!(AdmissionCommitmentV1::deserialize(&c.serialize()).is_err());
    }

    #[test]
    fn gate_logic_pure_and_mainnet_off() {
        let _env = crate::test_env::guard();
        assert!(
            !committed_admission_gate(0, Some(1), 100),
            "below the mainnet activation height; NOT hard-off (see activation::mainnet_gate_truth)"
        );
        assert!(committed_admission_gate(1, Some(1), 100));
        assert!(!committed_admission_gate(1, None, 100));
        assert!(committed_admission_enforced_gate(1, Some(1), true, 100));
        assert!(!committed_admission_enforced_gate(1, Some(1), false, 100));
        assert!(
            !committed_admission_enforced_gate(0, Some(1), true, 100),
            "below the mainnet activation height; NOT hard-off (see activation::mainnet_gate_truth)"
        );
    }

    #[test]
    fn multisource_seed_gate_pure() {
        let _env = crate::test_env::guard();
        assert!(!multisource_seed_gate(0, Some(1), 100), "below the mainnet activation height; NOT hard-off (see activation::mainnet_gate_truth)");
        assert!(multisource_seed_gate(1, Some(1), 100));
        assert!(!multisource_seed_gate(1, None, 100));
        assert!(!multisource_seed_gate(1, Some(50), 10));
    }

    #[test]
    fn assignment_seed_v2_anti_grind() {
        let _env = crate::test_env::guard();
        let base = [0x11u8; 32];
        let fin = [0x22u8; 32];
        let pre = [0x33u8; 32];
        let s = assignment_seed_v2(&base, &fin, &pre, 0);
        // distinct from the legacy base (single grandparent hash).
        assert_ne!(s, base);
        // changing ANY of the four sources changes the seed (anti-grind).
        assert_ne!(s, assignment_seed_v2(&[0x12u8; 32], &fin, &pre, 0), "base matters");
        assert_ne!(s, assignment_seed_v2(&base, &[0x23u8; 32], &pre, 0), "finality sig matters");
        assert_ne!(s, assignment_seed_v2(&base, &fin, &[0x34u8; 32], 0), "precommit matters");
        assert_ne!(s, assignment_seed_v2(&base, &fin, &pre, 1), "epoch index matters");
        // deterministic.
        assert_eq!(s, assignment_seed_v2(&base, &fin, &pre, 0));
    }

    #[test]
    fn resolve_epoch_seed_parts_off_is_legacy_passthrough() {
        let _env = crate::test_env::guard();
        // Gate off (no activation height) => returns the legacy base unchanged,
        // byte-identical, regardless of the other components. Env-mutating =>
        // serialized via the crate-wide PoAW-X test env lock.
        let _g = crate::poawx::poawx_test_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "devnet");
        std::env::remove_var("IRIUM_POAWX_MULTISOURCE_SEED_ACTIVATION_HEIGHT");
        let base = [0xABu8; 32];
        let got = resolve_epoch_seed_parts(100, base, [0x01u8; 32], [0x02u8; 32]);
        assert_eq!(got, base, "gate off => legacy grandparent hash");
        std::env::remove_var("IRIUM_NETWORK");
    }
}
