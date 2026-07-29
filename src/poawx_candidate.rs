//! Phase 21D: PoAW-X candidate-set + assignment-proof foundation.
//!
//! This module adds the data + validation foundation for **global role selection**:
//! a canonical candidate set per block, a deterministic *effective score*, and a
//! **VRF-style assignment proof placeholder** (`AssignmentProofV1`).
//!
//! IMPORTANT — `AssignmentProofV1` is a **VRF-style placeholder, NOT a final
//! cryptographic VRF**. The repo ships no VRF library, so the proof is a
//! domain-separated, public-key-bound, hash-based digest that is deterministic and
//! independently *recomputable* by every node. It is NOT unpredictable-before-reveal
//! the way a true VRF output is. Replacing it with a real VRF is future work. No
//! miner private key is ever required to build it.
//!
//! Everything here is integer/fixed-point only (no floats), saturating arithmetic,
//! gated, and **mainnet-ACTIVE at height >= 50_000** via `crate::activation::network_id_byte() == 0`.
//! It does NOT touch chain difficulty / LWMA-144.
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
use ripemd::Ripemd160;

use crate::activation::network_id_byte;
use crate::poawx_penalty::PenaltyStatus;
use secp256kfun::KeyPair;
use vrf_fun::rfc9381::tai;
use vrf_fun::VrfProof;

/// Domain tag for the assignment-proof digest.
pub const ASSIGNMENT_PROOF_DOMAIN: &[u8] = b"IRIUM_POAWX_ASSIGNMENT_PROOF_V1";
/// Domain tag for the candidate-set root.
pub const CANDIDATE_SET_DOMAIN: &[u8] = b"IRIUM_POAWX_CANDIDATE_SET_V1";
/// 4-byte magic for the trailing candidate-set ext section (fits the existing
/// magic-dispatch loop alongside TPK1/DOM1).
pub const CANDIDATE_SECTION_MAGIC: &[u8; 4] = b"CND1";
/// Wire size of one `RoleCandidate`.
pub const ROLE_CANDIDATE_WIRE: usize = 1 + 20 + 33 + 32 + 1 + 32 + 8 + 8 + 8 + 32; // 175
/// Upper bound on candidates in a set (deserialize safety / size bound).
pub const MAX_CANDIDATES: usize = 256;
/// Fixed-point scale for the effective-score weight product (permille × permille).
pub const EFFECTIVE_SCORE_SCALE: u128 = 1_000_000;

/// Deterministic, domain-separated, public-key-bound assignment-proof digest.
/// VRF-style placeholder (see module docs). No private key required.
pub fn compute_assignment_proof_digest(
    network_id: u8,
    target_height: u64,
    role_id: u8,
    solver_pkh: &[u8; 20],
    assignment_public_key: &[u8; 33],
    ticket_digest: &[u8; 32],
    seed: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ASSIGNMENT_PROOF_DOMAIN);
    h.update([network_id]);
    h.update(target_height.to_le_bytes());
    h.update([role_id]);
    h.update(solver_pkh);
    h.update(assignment_public_key);
    h.update(ticket_digest);
    h.update(seed);
    h.finalize().into()
}

/// Derive the (deterministic) assignment score from a proof digest: the first 8
/// digest bytes as a little-endian u64. Higher score wins.
pub fn assignment_score_from_digest(proof_digest: &[u8; 32]) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&proof_digest[0..8]);
    u64::from_le_bytes(b)
}

/// Deterministic effective score (HIGHER WINS). Fixed-point: the assignment score
/// scaled by the dominance fairness weight (permille-scale) and the penalty weight
/// (permille). Suspended/slashed (penalty_weight 0) => score 0. Saturating.
pub fn effective_score(assignment_score: u64, dominance_weight: u64, penalty_weight: u64) -> u64 {
    let v = (assignment_score as u128)
        .saturating_mul(dominance_weight as u128)
        .saturating_mul(penalty_weight as u128)
        / EFFECTIVE_SCORE_SCALE;
    v.min(u64::MAX as u128) as u64
}

/// VRF-style assignment proof placeholder (see module docs). Binds network/height/
/// role/solver/assignment-key/ticket/seed; `proof_digest` is recomputable and
/// `score()` is derived from it. NOT a final cryptographic VRF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignmentProofV1 {
    pub network_id: u8,
    pub target_height: u64,
    pub role_id: u8,
    pub solver_pkh: [u8; 20],
    pub assignment_public_key: [u8; 33],
    pub ticket_digest: [u8; 32],
    pub seed: [u8; 32],
    pub proof_digest: [u8; 32],
}

impl AssignmentProofV1 {
    pub fn new(
        network_id: u8,
        target_height: u64,
        role_id: u8,
        solver_pkh: [u8; 20],
        assignment_public_key: [u8; 33],
        ticket_digest: [u8; 32],
        seed: [u8; 32],
    ) -> Self {
        let proof_digest = compute_assignment_proof_digest(
            network_id,
            target_height,
            role_id,
            &solver_pkh,
            &assignment_public_key,
            &ticket_digest,
            &seed,
        );
        Self {
            network_id,
            target_height,
            role_id,
            solver_pkh,
            assignment_public_key,
            ticket_digest,
            seed,
            proof_digest,
        }
    }

    pub fn score(&self) -> u64 {
        assignment_score_from_digest(&self.proof_digest)
    }

    /// Validate the proof against the expected binding context. Rejects wrong
    /// network/height/role/ticket/seed and any digest mutation. Mainnet hard-off
    /// is enforced by the caller's gate, not here.
    pub fn validate(
        &self,
        network_id: u8,
        target_height: u64,
        role_id: u8,
        ticket_digest: &[u8; 32],
        seed: &[u8; 32],
    ) -> Result<(), String> {
        if self.network_id != network_id {
            return Err("assignment proof: wrong network".to_string());
        }
        if self.target_height != target_height {
            return Err("assignment proof: wrong height".to_string());
        }
        if self.role_id != role_id {
            return Err("assignment proof: wrong role".to_string());
        }
        if &self.ticket_digest != ticket_digest {
            return Err("assignment proof: wrong ticket digest".to_string());
        }
        if &self.seed != seed {
            return Err("assignment proof: wrong seed".to_string());
        }
        let expect = compute_assignment_proof_digest(
            self.network_id,
            self.target_height,
            self.role_id,
            &self.solver_pkh,
            &self.assignment_public_key,
            &self.ticket_digest,
            &self.seed,
        );
        if expect != self.proof_digest {
            return Err("assignment proof: digest mismatch".to_string());
        }
        Ok(())
    }
}

/// One candidate for a role slot. Carries everything a node needs to recompute its
/// assignment-proof digest, penalty weight, and effective score, and to match it
/// against the selected role solver. `dominance_weight` is validated against the
/// node's persisted state externally (chain.rs) when dominance is active.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleCandidate {
    pub role_id: u8,
    pub solver_pkh: [u8; 20],
    pub assignment_public_key: [u8; 33],
    pub ticket_digest: [u8; 32],
    pub penalty_status: u8,
    pub assignment_proof_digest: [u8; 32],
    pub dominance_weight: u64,
    pub penalty_weight: u64,
    pub effective_score: u64,
    pub role_claim_digest: [u8; 32],
}

impl RoleCandidate {
    /// Build a candidate, computing the proof digest, penalty weight, and effective
    /// score deterministically. `dominance_weight` is supplied by the producer (the
    /// node validates it against persisted state when dominance is active).
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        network_id: u8,
        target_height: u64,
        seed: &[u8; 32],
        role_id: u8,
        solver_pkh: [u8; 20],
        assignment_public_key: [u8; 33],
        ticket_digest: [u8; 32],
        penalty_status: u8,
        dominance_weight: u64,
        role_claim_digest: [u8; 32],
    ) -> Self {
        let assignment_proof_digest = compute_assignment_proof_digest(
            network_id,
            target_height,
            role_id,
            &solver_pkh,
            &assignment_public_key,
            &ticket_digest,
            seed,
        );
        let penalty_weight = PenaltyStatus::from_id(penalty_status)
            .map(|p| p.weight_multiplier_permille() as u64)
            .unwrap_or(0);
        let assignment_score = assignment_score_from_digest(&assignment_proof_digest);
        let effective_score = effective_score(assignment_score, dominance_weight, penalty_weight);
        Self {
            role_id,
            solver_pkh,
            assignment_public_key,
            ticket_digest,
            penalty_status,
            assignment_proof_digest,
            dominance_weight,
            penalty_weight,
            effective_score,
            role_claim_digest,
        }
    }

    /// Phase 22E: build a candidate from a true-VRF AssignmentProofV2. The
    /// candidate's assignment_proof_digest IS the VRF output (so the effective
    /// score derives from the VRF output); role/solver/assignment key/ticket are
    /// taken from the proof. No secret material.
    pub fn from_assignment_v2(
        proof: &AssignmentProofV2,
        penalty_status: u8,
        dominance_weight: u64,
        role_claim_digest: [u8; 32],
    ) -> Self {
        let assignment_proof_digest = proof.vrf_output;
        let penalty_weight = PenaltyStatus::from_id(penalty_status)
            .map(|p| p.weight_multiplier_permille() as u64)
            .unwrap_or(0);
        let assignment_score = assignment_score_from_digest(&assignment_proof_digest);
        let effective_score = effective_score(assignment_score, dominance_weight, penalty_weight);
        Self {
            role_id: proof.role_id,
            solver_pkh: proof.solver_pkh,
            assignment_public_key: proof.assignment_public_key,
            ticket_digest: proof.ticket_digest,
            penalty_status,
            assignment_proof_digest,
            dominance_weight,
            penalty_weight,
            effective_score,
            role_claim_digest,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ROLE_CANDIDATE_WIRE);
        out.push(self.role_id);
        out.extend_from_slice(&self.solver_pkh);
        out.extend_from_slice(&self.assignment_public_key);
        out.extend_from_slice(&self.ticket_digest);
        out.push(self.penalty_status);
        out.extend_from_slice(&self.assignment_proof_digest);
        out.extend_from_slice(&self.dominance_weight.to_le_bytes());
        out.extend_from_slice(&self.penalty_weight.to_le_bytes());
        out.extend_from_slice(&self.effective_score.to_le_bytes());
        out.extend_from_slice(&self.role_claim_digest);
        out
    }

    pub fn deserialize(raw: &[u8]) -> Result<Self, String> {
        if raw.len() != ROLE_CANDIDATE_WIRE {
            return Err("role candidate: bad length".to_string());
        }
        let mut p = 0usize;
        let rd = |p: &mut usize, n: usize| -> Vec<u8> {
            let s = raw[*p..*p + n].to_vec();
            *p += n;
            s
        };
        let role_id = raw[p];
        p += 1;
        let mut solver_pkh = [0u8; 20];
        solver_pkh.copy_from_slice(&rd(&mut p, 20));
        let mut assignment_public_key = [0u8; 33];
        assignment_public_key.copy_from_slice(&rd(&mut p, 33));
        let mut ticket_digest = [0u8; 32];
        ticket_digest.copy_from_slice(&rd(&mut p, 32));
        let penalty_status = raw[p];
        p += 1;
        let mut assignment_proof_digest = [0u8; 32];
        assignment_proof_digest.copy_from_slice(&rd(&mut p, 32));
        let mut w = [0u8; 8];
        w.copy_from_slice(&rd(&mut p, 8));
        let dominance_weight = u64::from_le_bytes(w);
        w.copy_from_slice(&rd(&mut p, 8));
        let penalty_weight = u64::from_le_bytes(w);
        w.copy_from_slice(&rd(&mut p, 8));
        let effective_score = u64::from_le_bytes(w);
        let mut role_claim_digest = [0u8; 32];
        role_claim_digest.copy_from_slice(&rd(&mut p, 32));
        Ok(Self {
            role_id,
            solver_pkh,
            assignment_public_key,
            ticket_digest,
            penalty_status,
            assignment_proof_digest,
            dominance_weight,
            penalty_weight,
            effective_score,
            role_claim_digest,
        })
    }

    /// Total canonical sort key: (role_id, solver_pkh, ticket_digest,
    /// assignment_proof_digest). Defines the stable candidate-set ordering.
    fn sort_key(&self) -> ([u8; 1], [u8; 20], [u8; 32], [u8; 32]) {
        (
            [self.role_id],
            self.solver_pkh,
            self.ticket_digest,
            self.assignment_proof_digest,
        )
    }

    /// Self-consistency: recompute the assignment-proof digest, penalty weight, and
    /// effective score from the bound fields and confirm they match the stored
    /// values. Does NOT check dominance_weight vs persisted state (external).
    pub fn validate_self(
        &self,
        network_id: u8,
        target_height: u64,
        seed: &[u8; 32],
    ) -> Result<(), String> {
        let expect_digest = compute_assignment_proof_digest(
            network_id,
            target_height,
            self.role_id,
            &self.solver_pkh,
            &self.assignment_public_key,
            &self.ticket_digest,
            seed,
        );
        if expect_digest != self.assignment_proof_digest {
            return Err("candidate: assignment proof digest mismatch".to_string());
        }
        self.validate_scoring()
    }

    /// Phase 22E: penalty + effective-score consistency only (no assignment-proof
    /// digest recompute). Used under the true-VRF gate, where assignment_proof_digest
    /// is the VRF output (verified via AssignmentProofV2), not the V1 placeholder.
    pub fn validate_scoring(&self) -> Result<(), String> {
        let ps =
            PenaltyStatus::from_id(self.penalty_status).ok_or("candidate: bad penalty status")?;
        if self.penalty_weight != ps.weight_multiplier_permille() as u64 {
            return Err("candidate: penalty weight mismatch".to_string());
        }
        let score = assignment_score_from_digest(&self.assignment_proof_digest);
        if self.effective_score
            != effective_score(score, self.dominance_weight, self.penalty_weight)
        {
            return Err("candidate: effective score mismatch".to_string());
        }
        Ok(())
    }
}

/// "Is candidate `a` strictly better than `b`?" Higher effective_score wins; ties
/// break by SMALLER assignment_proof_digest, then solver_pkh, then ticket_digest.
fn candidate_better(a: &RoleCandidate, b: &RoleCandidate) -> bool {
    if a.effective_score != b.effective_score {
        return a.effective_score > b.effective_score;
    }
    if a.assignment_proof_digest != b.assignment_proof_digest {
        return a.assignment_proof_digest < b.assignment_proof_digest;
    }
    if a.solver_pkh != b.solver_pkh {
        return a.solver_pkh < b.solver_pkh;
    }
    a.ticket_digest < b.ticket_digest
}

/// Canonical candidate set for a block: header (network/height/seed) + a sorted,
/// duplicate-free candidate list. The root binds all of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateSet {
    pub network_id: u8,
    pub target_height: u64,
    pub seed: [u8; 32],
    pub candidates: Vec<RoleCandidate>,
}

impl CandidateSet {
    pub fn new(network_id: u8, target_height: u64, seed: [u8; 32]) -> Self {
        Self {
            network_id,
            target_height,
            seed,
            candidates: Vec::new(),
        }
    }

    pub fn push(&mut self, c: RoleCandidate) {
        self.candidates.push(c);
    }

    /// Sort into canonical order (stable, total). Call before computing the root.
    pub fn sort_canonical(&mut self) {
        self.candidates
            .sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
        // Dedup identical candidates so the result satisfies `is_canonical` (strictly
        // increasing sort_key). Duplicates can arise when a fan-out extra restates a
        // candidate already present (e.g. a collected worker also gossiped as an admission).
        self.candidates.dedup_by(|a, b| a.sort_key() == b.sort_key());
    }

    /// Whether the candidate list is in canonical order with no duplicate keys.
    pub fn is_canonical(&self) -> bool {
        for w in self.candidates.windows(2) {
            if w[0].sort_key() >= w[1].sort_key() {
                return false;
            }
        }
        true
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(1 + 8 + 32 + 2 + self.candidates.len() * ROLE_CANDIDATE_WIRE);
        out.push(self.network_id);
        out.extend_from_slice(&self.target_height.to_le_bytes());
        out.extend_from_slice(&self.seed);
        out.extend_from_slice(&(self.candidates.len() as u16).to_le_bytes());
        for c in &self.candidates {
            out.extend_from_slice(&c.serialize());
        }
        out
    }

    pub fn deserialize(raw: &[u8]) -> Result<Self, String> {
        if raw.len() < 1 + 8 + 32 + 2 {
            return Err("candidate set: truncated header".to_string());
        }
        let network_id = raw[0];
        let mut p = 1usize;
        let mut hb = [0u8; 8];
        hb.copy_from_slice(&raw[p..p + 8]);
        let target_height = u64::from_le_bytes(hb);
        p += 8;
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&raw[p..p + 32]);
        p += 32;
        let count = u16::from_le_bytes([raw[p], raw[p + 1]]) as usize;
        p += 2;
        if count > MAX_CANDIDATES {
            return Err("candidate set: too many candidates".to_string());
        }
        if raw.len() != p + count * ROLE_CANDIDATE_WIRE {
            return Err("candidate set: bad length".to_string());
        }
        let mut candidates = Vec::with_capacity(count);
        for _ in 0..count {
            candidates.push(RoleCandidate::deserialize(
                &raw[p..p + ROLE_CANDIDATE_WIRE],
            )?);
            p += ROLE_CANDIDATE_WIRE;
        }
        Ok(Self {
            network_id,
            target_height,
            seed,
            candidates,
        })
    }

    /// Canonical root over the (canonically serialized) set. Any mutation or
    /// reorder changes the root.
    pub fn root(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(CANDIDATE_SET_DOMAIN);
        h.update(self.serialize());
        h.finalize().into()
    }

    /// Role order used for exclusive assignment. FIXED: builder and every validator must walk
    /// it identically or they disagree about who a block owes and the chain forks.
    pub const EXCLUSIVE_ROLE_ORDER: [u8; 3] = [
        crate::poawx::ROLE_COMPUTE_CONTRIBUTOR,
        crate::poawx::ROLE_VERIFY_CONTRIBUTOR,
        crate::poawx::ROLE_SUPPORT_CONTRIBUTOR,
    ];

    /// THE selection entry point. Every builder and validator site must call this, never
    /// `best_for_role` directly, so selection can never differ between producing and checking.
    ///
    /// With the gate off this is exactly `best_for_role(role_id)` — byte-identical.
    ///
    /// With the gate on, a node holds at most ONE role per block. Roles are resolved in
    /// `EXCLUSIVE_ROLE_ORDER`, each taking the best-scoring candidate whose identity is not
    /// already taken; `primary_pkh` (the proposer / receipt worker) is taken first, so the
    /// producer cannot also draw a contributor role. The node chooses nothing: its VRF score is
    /// bound to (height, role, seed) and every validator recomputes the same assignment.
    ///
    /// LIVENESS: if exclusivity leaves a role with no free identity — fewer participants than
    /// roles, the normal case with two nodes — that role falls back to the unrestricted best
    /// candidate rather than being unfillable. A rule that cannot be satisfied would halt the
    /// chain; this one degrades instead.
    pub fn selected_for_role(
        &self,
        role_id: u8,
        height: u64,
        primary_pkh: Option<&[u8; 20]>,
    ) -> Option<&RoleCandidate> {
        if !crate::poawx_proposer::exclusive_role_assignment_active(height) {
            return self.best_for_role(role_id);
        }
        let mut taken: Vec<[u8; 20]> = Vec::with_capacity(4);
        if let Some(p) = primary_pkh {
            taken.push(*p);
        }
        for role in Self::EXCLUSIVE_ROLE_ORDER {
            // Best candidate for this role whose identity is still free.
            let mut pick: Option<&RoleCandidate> = None;
            for c in self.candidates.iter().filter(|c| c.role_id == role) {
                if taken.contains(&c.solver_pkh) {
                    continue;
                }
                match pick {
                    None => pick = Some(c),
                    Some(b) if candidate_better(c, b) => pick = Some(c),
                    _ => {}
                }
            }
            // Fall back to the unrestricted best so a short participant set cannot make the
            // role unfillable (see LIVENESS above).
            let chosen = pick.or_else(|| self.best_for_role(role));
            if role == role_id {
                return chosen;
            }
            if let Some(c) = chosen {
                taken.push(c.solver_pkh);
            }
        }
        // role_id outside the contributor set (e.g. proposer): no exclusivity to apply.
        self.best_for_role(role_id)
    }

    /// The best candidate for `role_id` under the deterministic ordering, or None.
    pub fn best_for_role(&self, role_id: u8) -> Option<&RoleCandidate> {
        let mut best: Option<&RoleCandidate> = None;
        for c in self.candidates.iter().filter(|c| c.role_id == role_id) {
            match best {
                None => best = Some(c),
                Some(b) if candidate_better(c, b) => best = Some(c),
                _ => {}
            }
        }
        best
    }
}

// ── Gates (param-driven pure logic; mainnet-ACTIVE at height >= 50_000) ────────────────────────

pub fn candidate_set_activation_height() -> Option<u64> {
    std::env::var("IRIUM_POAWX_CANDIDATE_SET_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}
pub fn candidate_set_required() -> bool {
    if crate::activation::network_id_byte() == 0 {
        return true; // mainnet: enforced once the gate is active (height-gated)
    }
    std::env::var("IRIUM_POAWX_CANDIDATE_SET_REQUIRED")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}
pub fn assignment_proof_activation_height() -> Option<u64> {
    std::env::var("IRIUM_POAWX_ASSIGNMENT_PROOF_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}
pub fn assignment_proof_required() -> bool {
    if crate::activation::network_id_byte() == 0 {
        return true; // mainnet: enforced once the gate is active (height-gated)
    }
    std::env::var("IRIUM_POAWX_ASSIGNMENT_PROOF_REQUIRED")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}

/// Pure gate: network 0 (mainnet/unset) hard-off; else active at/after activation.
pub fn poawx_phase21d_gate(network_id: u8, activation: Option<u64>, height: u64) -> bool {
    matches!(crate::activation::poawx_effective_activation(network_id, activation), Some(h) if height >= h)
}
/// Pure enforcement gate: active AND required.
pub fn poawx_phase21d_enforced_gate(
    network_id: u8,
    activation: Option<u64>,
    required: bool,
    height: u64,
) -> bool {
    poawx_phase21d_gate(network_id, activation, height) && required
}

pub fn candidate_set_active(height: u64) -> bool {
    poawx_phase21d_gate(network_id_byte(), candidate_set_activation_height(), height)
}
pub fn candidate_set_enforced(height: u64) -> bool {
    poawx_phase21d_enforced_gate(
        network_id_byte(),
        candidate_set_activation_height(),
        candidate_set_required(),
        height,
    )
}
pub fn assignment_proof_active(height: u64) -> bool {
    poawx_phase21d_gate(
        network_id_byte(),
        assignment_proof_activation_height(),
        height,
    )
}
pub fn assignment_proof_enforced(height: u64) -> bool {
    poawx_phase21d_enforced_gate(
        network_id_byte(),
        assignment_proof_activation_height(),
        assignment_proof_required(),
        height,
    )
}

/// ── Phase 22D: true secp256k1 RFC 9381 ECVRF (AssignmentProofV2) ─────────────
/// A real cryptographic VRF (vrf_fun/secp256kfun, pure Rust, no OpenSSL) replacing
/// the recomputable `AssignmentProofV1` placeholder when the true-VRF gate is on.
/// Keeps the secp256k1 key model: the VRF key IS a secp256k1 keypair; the 33-byte
/// `assignment_public_key` is the compressed VRF public key. Gated + mainnet hard-off.
pub const ASSIGNMENT_PROOF_V2_VERSION: u8 = 2;
/// bincode-encoded `VrfProof<U16>` (gamma 33 + challenge 16 + response 32) = 81 bytes.
pub const VRF_PROOF_WIRE: usize = 81;
pub const ASSIGNMENT_PROOF_V2_WIRE: usize =
    1 + 1 + 8 + 1 + 20 + 33 + 32 + 32 + 32 + VRF_PROOF_WIRE + 32; // 273
const ASSIGNMENT_V2_DOMAIN: &[u8] = b"IRIUM_POAWX_ASSIGNMENT_PROOF_V2";
/// 4-byte trailing-section magic for the V2 assignment proofs in the Phase 20 ext.
pub const ASSIGNMENT_V2_SECTION_MAGIC: &[u8; 4] = b"AVR2";
const VRF_MESSAGE_DOMAIN: &[u8] = b"IRIUM_POAWX_VRF_MESSAGE_V2";

fn vrf_bincode_config() -> impl bincode::config::Config {
    bincode::config::standard()
}

/// The VRF input message (alpha): domain-separated, binds the full assignment context.
#[allow(clippy::too_many_arguments)]
fn vrf_message(
    network_id: u8,
    target_height: u64,
    role_id: u8,
    solver_pkh: &[u8; 20],
    ticket_digest: &[u8; 32],
    seed: &[u8; 32],
    assignment_public_key: &[u8; 33],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(VRF_MESSAGE_DOMAIN.len() + 1 + 8 + 1 + 20 + 32 + 32 + 33);
    m.extend_from_slice(VRF_MESSAGE_DOMAIN);
    m.push(network_id);
    m.extend_from_slice(&target_height.to_le_bytes());
    m.push(role_id);
    m.extend_from_slice(solver_pkh);
    m.extend_from_slice(ticket_digest);
    m.extend_from_slice(seed);
    m.extend_from_slice(assignment_public_key);
    m
}

/// Derive the deterministic assignment score from a VRF output (first 8 bytes LE).
pub fn assignment_v2_score_from_output(vrf_output: &[u8; 32]) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&vrf_output[0..8]);
    u64::from_le_bytes(b)
}

/// True-VRF assignment proof (RFC 9381 ECVRF over secp256k1). No secret key bytes
/// are stored; `vrf_output` + `vrf_proof` are public and verifiable against
/// `assignment_public_key` + the bound message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignmentProofV2 {
    pub version: u8,
    pub network_id: u8,
    pub target_height: u64,
    pub role_id: u8,
    pub solver_pkh: [u8; 20],
    pub assignment_public_key: [u8; 33],
    pub ticket_digest: [u8; 32],
    pub seed: [u8; 32],
    pub vrf_output: [u8; 32],
    pub vrf_proof: [u8; VRF_PROOF_WIRE],
    pub digest: [u8; 32],
}

impl AssignmentProofV2 {
    fn compute_digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(ASSIGNMENT_V2_DOMAIN);
        h.update([self.version]);
        h.update([self.network_id]);
        h.update(self.target_height.to_le_bytes());
        h.update([self.role_id]);
        h.update(self.solver_pkh);
        h.update(self.assignment_public_key);
        h.update(self.ticket_digest);
        h.update(self.seed);
        h.update(self.vrf_output);
        h.update(self.vrf_proof);
        h.finalize().into()
    }

    /// Produce a V2 proof from a secp256k1 secret key (prover/wallet side). The
    /// secret never leaves this function; only the public key, output, and proof
    /// are retained. `assignment_public_key` is derived from the secret.
    #[allow(clippy::too_many_arguments)]
    pub fn prove(
        secret: &[u8; 32],
        network_id: u8,
        target_height: u64,
        role_id: u8,
        solver_pkh: [u8; 20],
        ticket_digest: [u8; 32],
        seed: [u8; 32],
    ) -> Result<Self, String> {
        let sk = secp256kfun::Scalar::from_bytes(*secret)
            .and_then(|s| s.non_zero())
            .ok_or_else(|| "assignment v2: invalid/zero secret key".to_string())?;
        let kp = KeyPair::new(sk);
        let pk = kp.public_key();
        let assignment_public_key: [u8; 33] = pk.to_bytes();
        let alpha = vrf_message(
            network_id,
            target_height,
            role_id,
            &solver_pkh,
            &ticket_digest,
            &seed,
            &assignment_public_key,
        );
        let proof = tai::prove::<Sha256>(&kp, &alpha);
        let verified = tai::verify::<Sha256>(pk, &alpha, &proof)
            .ok_or_else(|| "assignment v2: self-verify failed".to_string())?;
        let vrf_output = tai::output::<Sha256>(verified);
        let encoded = bincode::encode_to_vec(&proof, vrf_bincode_config())
            .map_err(|e| format!("assignment v2: proof encode: {e}"))?;
        if encoded.len() != VRF_PROOF_WIRE {
            return Err(format!(
                "assignment v2: unexpected proof length {}",
                encoded.len()
            ));
        }
        let mut vrf_proof = [0u8; VRF_PROOF_WIRE];
        vrf_proof.copy_from_slice(&encoded);
        let mut me = Self {
            version: ASSIGNMENT_PROOF_V2_VERSION,
            network_id,
            target_height,
            role_id,
            solver_pkh,
            assignment_public_key,
            ticket_digest,
            seed,
            vrf_output,
            vrf_proof,
            digest: [0u8; 32],
        };
        me.digest = me.compute_digest();
        Ok(me)
    }

    /// Phase 31: prove an assignment whose `solver_pkh` is `hash160(the VRF public
    /// key)` itself -- the proposer IS the block worker. The solver is derived from
    /// the SAME secp256kfun public key carried in the proof, so the C4 invariant
    /// `solver_pkh == hash160(assignment_public_key)` holds by construction with no
    /// external key-encoding assumption.
    pub fn prove_self_solver(
        secret: &[u8; 32],
        network_id: u8,
        target_height: u64,
        role_id: u8,
        ticket_digest: [u8; 32],
        seed: [u8; 32],
    ) -> Result<Self, String> {
        let sk = secp256kfun::Scalar::from_bytes(*secret)
            .and_then(|s| s.non_zero())
            .ok_or_else(|| "assignment v2: invalid/zero secret key".to_string())?;
        let kp = KeyPair::new(sk);
        let pk_bytes: [u8; 33] = kp.public_key().to_bytes();
        let mut solver_pkh = [0u8; 20];
        solver_pkh.copy_from_slice(&Ripemd160::digest(Sha256::digest(pk_bytes)));
        Self::prove(
            secret,
            network_id,
            target_height,
            role_id,
            solver_pkh,
            ticket_digest,
            seed,
        )
    }

    pub fn score(&self) -> u64 {
        assignment_v2_score_from_output(&self.vrf_output)
    }

    /// Verify the VRF proof against the assignment public key + bound message, and
    /// confirm the carried output + digest. Deterministic; no secret key needed.
    pub fn validate(&self, network_id: u8, target_height: u64) -> Result<(), String> {
        if self.version != ASSIGNMENT_PROOF_V2_VERSION {
            return Err("assignment v2: bad version".to_string());
        }
        if self.network_id != network_id {
            return Err("assignment v2: wrong network".to_string());
        }
        if self.target_height != target_height {
            return Err("assignment v2: wrong height".to_string());
        }
        if self.compute_digest() != self.digest {
            return Err("assignment v2: digest mismatch".to_string());
        }
        let pk = secp256kfun::Point::from_bytes(self.assignment_public_key)
            .ok_or_else(|| "assignment v2: bad vrf public key".to_string())?;
        let (proof, used): (VrfProof, usize) =
            bincode::decode_from_slice(&self.vrf_proof, vrf_bincode_config())
                .map_err(|_| "assignment v2: malformed vrf proof".to_string())?;
        if used != VRF_PROOF_WIRE {
            return Err("assignment v2: trailing proof bytes".to_string());
        }
        let alpha = vrf_message(
            self.network_id,
            self.target_height,
            self.role_id,
            &self.solver_pkh,
            &self.ticket_digest,
            &self.seed,
            &self.assignment_public_key,
        );
        let verified = tai::verify::<Sha256>(pk, &alpha, &proof)
            .ok_or_else(|| "assignment v2: vrf verification failed".to_string())?;
        let out = tai::output::<Sha256>(verified);
        if out != self.vrf_output {
            return Err("assignment v2: vrf output mismatch".to_string());
        }
        // Fix #4 (audit-gated, proposer-scoped): bind the PROPOSER's solver identity to its
        // VRF key. The VRF message commits to solver_pkh, so this stops a proposer grinding
        // solver_pkh (free, no new keys) for a favorable priority. Role assignments
        // (COMPUTE/VERIFY/SUPPORT) are intentionally EXEMPT: a block's proposer legitimately
        // fills all roles of its own block, so a role solver is the miner payout identity, not
        // hash160(per-role vrf key) -- enforcing the binding there would reject every honest
        // block (Option A; role distinctness is a documented protocol property, not a validity
        // rule). chain.rs validate_block_proposer enforces the same proposer binding ungated;
        // this is belt-and-suspenders for any caller. Mainnet hard-off.
        if crate::poawx_proposer::audit_hardening_active(target_height)
            && self.role_id == crate::poawx_proposer::ROLE_PROPOSER
        {
            let mut expect_pkh = [0u8; 20];
            expect_pkh.copy_from_slice(&Ripemd160::digest(Sha256::digest(self.assignment_public_key)));
            if self.solver_pkh != expect_pkh {
                return Err(
                    "assignment v2: solver pkh not derived from vrf key (audit)".to_string(),
                );
            }
        }
        // Option A: bind CONTRIBUTOR-role solvers (COMPUTE/VERIFY/SUPPORT) to their VRF key
        // once the contributor-role binding is active (mainnet not live-active until a
        // separate announced activation; rig/devnet env-overridable). This removes the
        // former exemption: a contributor role's payout must be the hash160 of the key that
        // produced its ECVRF proof. Off => byte-identical (contributor roles stay exempt).
        if crate::poawx_proposer::contributor_role_binding_active(target_height)
            && self.role_id != crate::poawx_proposer::ROLE_PROPOSER
        {
            let mut expect_pkh = [0u8; 20];
            expect_pkh.copy_from_slice(&Ripemd160::digest(Sha256::digest(self.assignment_public_key)));
            if self.solver_pkh != expect_pkh {
                return Err(
                    "assignment v2: contributor solver pkh not derived from vrf key".to_string(),
                );
            }
        }
        Ok(())
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(ASSIGNMENT_PROOF_V2_WIRE);
        o.push(self.version);
        o.push(self.network_id);
        o.extend_from_slice(&self.target_height.to_le_bytes());
        o.push(self.role_id);
        o.extend_from_slice(&self.solver_pkh);
        o.extend_from_slice(&self.assignment_public_key);
        o.extend_from_slice(&self.ticket_digest);
        o.extend_from_slice(&self.seed);
        o.extend_from_slice(&self.vrf_output);
        o.extend_from_slice(&self.vrf_proof);
        o.extend_from_slice(&self.digest);
        o
    }

    pub fn deserialize(raw: &[u8]) -> Result<Self, String> {
        if raw.len() != ASSIGNMENT_PROOF_V2_WIRE {
            return Err("assignment v2: bad length".to_string());
        }
        let mut p = 0usize;
        let take = |p: &mut usize, n: usize| -> Vec<u8> {
            let v = raw[*p..*p + n].to_vec();
            *p += n;
            v
        };
        let version = raw[p];
        p += 1;
        let network_id = raw[p];
        p += 1;
        let mut h8 = [0u8; 8];
        h8.copy_from_slice(&take(&mut p, 8));
        let target_height = u64::from_le_bytes(h8);
        let role_id = raw[p];
        p += 1;
        let mut solver_pkh = [0u8; 20];
        solver_pkh.copy_from_slice(&take(&mut p, 20));
        let mut assignment_public_key = [0u8; 33];
        assignment_public_key.copy_from_slice(&take(&mut p, 33));
        let mut ticket_digest = [0u8; 32];
        ticket_digest.copy_from_slice(&take(&mut p, 32));
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&take(&mut p, 32));
        let mut vrf_output = [0u8; 32];
        vrf_output.copy_from_slice(&take(&mut p, 32));
        let mut vrf_proof = [0u8; VRF_PROOF_WIRE];
        vrf_proof.copy_from_slice(&take(&mut p, VRF_PROOF_WIRE));
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&take(&mut p, 32));
        Ok(Self {
            version,
            network_id,
            target_height,
            role_id,
            solver_pkh,
            assignment_public_key,
            ticket_digest,
            seed,
            vrf_output,
            vrf_proof,
            digest,
        })
    }
}

// True-VRF gates (reserved Phase 22B names; mainnet hard-off; reuse the pure gate fns).
pub fn true_vrf_activation_height() -> Option<u64> {
    std::env::var("IRIUM_POAWX_TRUE_VRF_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}
pub fn true_vrf_required() -> bool {
    if crate::activation::network_id_byte() == 0 {
        return true; // mainnet: enforced once the gate is active (height-gated)
    }
    std::env::var("IRIUM_POAWX_TRUE_VRF_REQUIRED")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}
pub fn true_vrf_active(height: u64) -> bool {
    poawx_phase21d_gate(network_id_byte(), true_vrf_activation_height(), height)
}
pub fn true_vrf_enforced(height: u64) -> bool {
    poawx_phase21d_enforced_gate(
        network_id_byte(),
        true_vrf_activation_height(),
        true_vrf_required(),
        height,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apk() -> [u8; 33] {
        [0x02u8; 33]
    }

    #[test]
    fn audit_assignment_rejects_forged_solver_pkh() {
        let _env = crate::test_env::guard();
        use crate::poawx_proposer::ROLE_PROPOSER;
        // Fix #4 (proposer-scoped): AssignmentProofV2::validate binds solver_pkh ==
        // hash160(vrf key) for ROLE_PROPOSER when the audit gate is active, so a proposer
        // cannot grind solver_pkh for priority. Role assignments are intentionally EXEMPT
        // (Option A: role solver = miner payout identity). Mainnet hard-off.
        let _g = crate::poawx::poawx_test_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "testnet");
        let net = crate::activation::network_id_byte();
        let secret = [7u8; 32];
        let height = 5u64;
        let seed = [0x9au8; 32];
        let good = AssignmentProofV2::prove_self_solver(
            &secret, net, height, ROLE_PROPOSER, [0u8; 32], seed,
        )
        .expect("prove self solver");
        // forged PROPOSER proof: real VRF proof whose solver_pkh != hash160(vrf key).
        let forged = AssignmentProofV2::prove(
            &secret, net, height, ROLE_PROPOSER, [0xABu8; 20], [0u8; 32], seed,
        )
        .expect("prove forged solver");
        // a forged ROLE (non-proposer) assignment: solver intentionally not the vrf key.
        let role_forged =
            AssignmentProofV2::prove(&secret, net, height, 1, [0xABu8; 20], [0u8; 32], seed)
                .expect("prove role solver");
        // gate OFF => everything passes (byte-identical legacy).
        std::env::remove_var("IRIUM_POAWX_AUDIT_HARDENING_ACTIVATION_HEIGHT");
        assert!(good.validate(net, height).is_ok(), "genuine ok, gate off");
        assert!(forged.validate(net, height).is_ok(), "forged passes when gate off");
        // gate ON => genuine proposer ok; forged proposer rejected; role assignment exempt.
        std::env::set_var("IRIUM_POAWX_AUDIT_HARDENING_ACTIVATION_HEIGHT", "1");
        assert!(good.validate(net, height).is_ok(), "genuine proposer ok, gate on");
        let err = forged
            .validate(net, height)
            .expect_err("forged proposer rejected when gate on");
        assert!(err.contains("solver pkh not derived"), "got: {err}");
        assert!(
            role_forged.validate(net, height).is_ok(),
            "role assignment not bound to vrf key (Option A exemption)"
        );
        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_AUDIT_HARDENING_ACTIVATION_HEIGHT");
    }

    #[test]
    fn assignment_proof_digest_deterministic_and_sensitive() {
        let _env = crate::test_env::guard();
        let d0 = compute_assignment_proof_digest(
            1,
            10,
            1,
            &[0xAAu8; 20],
            &apk(),
            &[0x11u8; 32],
            &[0x22u8; 32],
        );
        let same = compute_assignment_proof_digest(
            1,
            10,
            1,
            &[0xAAu8; 20],
            &apk(),
            &[0x11u8; 32],
            &[0x22u8; 32],
        );
        assert_eq!(d0, same, "deterministic");
        // each input changes the digest.
        assert_ne!(
            d0,
            compute_assignment_proof_digest(
                2,
                10,
                1,
                &[0xAAu8; 20],
                &apk(),
                &[0x11u8; 32],
                &[0x22u8; 32]
            )
        );
        assert_ne!(
            d0,
            compute_assignment_proof_digest(
                1,
                11,
                1,
                &[0xAAu8; 20],
                &apk(),
                &[0x11u8; 32],
                &[0x22u8; 32]
            )
        );
        assert_ne!(
            d0,
            compute_assignment_proof_digest(
                1,
                10,
                2,
                &[0xAAu8; 20],
                &apk(),
                &[0x11u8; 32],
                &[0x22u8; 32]
            )
        );
        assert_ne!(
            d0,
            compute_assignment_proof_digest(
                1,
                10,
                1,
                &[0xABu8; 20],
                &apk(),
                &[0x11u8; 32],
                &[0x22u8; 32]
            )
        );
        assert_ne!(
            d0,
            compute_assignment_proof_digest(
                1,
                10,
                1,
                &[0xAAu8; 20],
                &[0x03u8; 33],
                &[0x11u8; 32],
                &[0x22u8; 32]
            )
        );
        assert_ne!(
            d0,
            compute_assignment_proof_digest(
                1,
                10,
                1,
                &[0xAAu8; 20],
                &apk(),
                &[0x12u8; 32],
                &[0x22u8; 32]
            )
        );
        assert_ne!(
            d0,
            compute_assignment_proof_digest(
                1,
                10,
                1,
                &[0xAAu8; 20],
                &apk(),
                &[0x11u8; 32],
                &[0x23u8; 32]
            )
        );
    }

    #[test]
    fn assignment_proof_validate_accept_reject() {
        let _env = crate::test_env::guard();
        let p = AssignmentProofV1::new(1, 10, 1, [0xAAu8; 20], apk(), [0x11u8; 32], [0x22u8; 32]);
        assert!(p.validate(1, 10, 1, &[0x11u8; 32], &[0x22u8; 32]).is_ok());
        assert!(
            p.validate(2, 10, 1, &[0x11u8; 32], &[0x22u8; 32]).is_err(),
            "wrong net"
        );
        assert!(
            p.validate(1, 11, 1, &[0x11u8; 32], &[0x22u8; 32]).is_err(),
            "wrong height"
        );
        assert!(
            p.validate(1, 10, 2, &[0x11u8; 32], &[0x22u8; 32]).is_err(),
            "wrong role"
        );
        assert!(
            p.validate(1, 10, 1, &[0x99u8; 32], &[0x22u8; 32]).is_err(),
            "wrong ticket"
        );
        assert!(
            p.validate(1, 10, 1, &[0x11u8; 32], &[0x99u8; 32]).is_err(),
            "wrong seed"
        );
        // digest mutation rejects.
        let mut m = p.clone();
        m.proof_digest[0] ^= 1;
        assert!(
            m.validate(1, 10, 1, &[0x11u8; 32], &[0x22u8; 32]).is_err(),
            "mutated digest"
        );
        // score derived from digest changes when digest changes.
        assert_ne!(p.score(), assignment_score_from_digest(&m.proof_digest));
    }

    #[test]
    fn effective_score_rules() {
        let _env = crate::test_env::guard();
        let s = 1_000_000u64;
        // penalty 0 => score 0.
        assert_eq!(effective_score(s, 1000, 0), 0);
        // higher dominance weight => higher score.
        assert!(effective_score(s, 1000, 1000) > effective_score(s, 500, 1000));
        // full weights => assignment score preserved (1000*1000/1e6 = 1).
        assert_eq!(effective_score(s, 1000, 1000), s);
        // saturating: no panic on large inputs.
        let _ = effective_score(u64::MAX, 1000, 1000);
    }

    #[test]
    fn candidate_wire_roundtrip() {
        let _env = crate::test_env::guard();
        let c = RoleCandidate::build(
            1,
            10,
            &[0x22u8; 32],
            1,
            [0xAAu8; 20],
            apk(),
            [0x11u8; 32],
            PenaltyStatus::Clean.id(),
            800,
            [0x44u8; 32],
        );
        let b = c.serialize();
        assert_eq!(b.len(), ROLE_CANDIDATE_WIRE);
        assert_eq!(RoleCandidate::deserialize(&b).unwrap(), c);
        assert!(c.validate_self(1, 10, &[0x22u8; 32]).is_ok());
        // wrong seed/height fail self-consistency (digest recompute).
        assert!(c.validate_self(1, 11, &[0x22u8; 32]).is_err());
        assert!(c.validate_self(1, 10, &[0x23u8; 32]).is_err());
    }

    #[test]
    fn candidate_set_root_and_mutation() {
        let _env = crate::test_env::guard();
        let mut cs = CandidateSet::new(1, 10, [0x22u8; 32]);
        let c1 = RoleCandidate::build(
            1,
            10,
            &cs.seed,
            1,
            [0x01u8; 20],
            apk(),
            [0x11u8; 32],
            PenaltyStatus::Clean.id(),
            1000,
            [0x44u8; 32],
        );
        let c2 = RoleCandidate::build(
            1,
            10,
            &cs.seed,
            1,
            [0x02u8; 20],
            apk(),
            [0x12u8; 32],
            PenaltyStatus::Clean.id(),
            1000,
            [0x45u8; 32],
        );
        cs.push(c1.clone());
        cs.push(c2.clone());
        cs.sort_canonical();
        assert!(cs.is_canonical());
        let r = cs.root();
        // round-trip stable.
        let rt = CandidateSet::deserialize(&cs.serialize()).unwrap();
        assert_eq!(rt, cs);
        assert_eq!(rt.root(), r);
        // mutate a candidate weight => different root.
        let mut cs2 = cs.clone();
        cs2.candidates[0].dominance_weight ^= 1;
        assert_ne!(cs2.root(), r, "mutation changes root");
    }

    /// One identity must not hold two roles in the same block once the gate is on.
    ///
    /// Without it, `best_for_role` resolves each role independently, so a single dominant
    /// identity sweeps all three contributor roles — which is exactly how one operator host
    /// came to appear as four distinct payees.
    #[test]
    fn exclusive_assignment_gives_one_role_per_identity() {
        let _env = crate::test_env::guard();
        let prev_net = std::env::var("IRIUM_NETWORK").ok();
        let prev_act = std::env::var("IRIUM_POAWX_EXCLUSIVE_ROLE_ACTIVATION_HEIGHT").ok();
        std::env::set_var("IRIUM_NETWORK", "devnet");

        let h = 10u64;
        let mut cs = CandidateSet::new(1, h, [0x55u8; 32]);
        // Three distinct identities, each offering candidacy for ALL THREE contributor roles —
        // the "one address registered for every role" model.
        let ids = [[0xA1u8; 20], [0xB2u8; 20], [0xC3u8; 20]];
        for id in ids.iter() {
            for role in CandidateSet::EXCLUSIVE_ROLE_ORDER {
                let c = RoleCandidate::build(
                    1, h, &cs.seed, role, *id, apk(), [0x11u8; 32],
                    PenaltyStatus::Clean.id(), 1000, [0x44u8; 32],
                );
                cs.candidates.push(c);
            }
        }
        cs.sort_canonical();

        // GATE OFF: independent resolution — nothing stops one identity sweeping the roles.
        std::env::remove_var("IRIUM_POAWX_EXCLUSIVE_ROLE_ACTIVATION_HEIGHT");
        let off: Vec<[u8; 20]> = CandidateSet::EXCLUSIVE_ROLE_ORDER
            .iter()
            .map(|r| cs.selected_for_role(*r, h, None).unwrap().solver_pkh)
            .collect();
        assert_eq!(
            off.len(), 3,
            "control precondition: every role must resolve with the gate off"
        );

        // GATE ON: three roles must land on three DIFFERENT identities.
        std::env::set_var("IRIUM_POAWX_EXCLUSIVE_ROLE_ACTIVATION_HEIGHT", "0");
        let on: Vec<[u8; 20]> = CandidateSet::EXCLUSIVE_ROLE_ORDER
            .iter()
            .map(|r| cs.selected_for_role(*r, h, None).unwrap().solver_pkh)
            .collect();
        let mut uniq = on.clone();
        uniq.sort();
        uniq.dedup();
        assert_eq!(
            uniq.len(), 3,
            "each role must go to a DIFFERENT identity, got {on:?}"
        );

        // The proposer identity is taken first, so it cannot also draw a contributor role.
        // Needs FOUR identities: proposer + one per contributor role. With only three, one
        // role legitimately falls back to the proposer (liveness), which is asserted below.
        let mut cs4 = CandidateSet::new(1, h, [0x55u8; 32]);
        let ids4 = [[0xA1u8; 20], [0xB2u8; 20], [0xC3u8; 20], [0xE5u8; 20]];
        for id in ids4.iter() {
            for role in CandidateSet::EXCLUSIVE_ROLE_ORDER {
                cs4.candidates.push(RoleCandidate::build(
                    1, h, &cs.seed, role, *id, apk(), [0x11u8; 32],
                    PenaltyStatus::Clean.id(), 1000, [0x44u8; 32],
                ));
            }
        }
        cs4.sort_canonical();
        let proposer = ids4[0];
        let with_primary: Vec<[u8; 20]> = CandidateSet::EXCLUSIVE_ROLE_ORDER
            .iter()
            .map(|r| cs4.selected_for_role(*r, h, Some(&proposer)).unwrap().solver_pkh)
            .collect();
        assert!(
            !with_primary.contains(&proposer),
            "proposer must not also hold a contributor role, got {with_primary:?}"
        );
        let mut u4 = with_primary.clone();
        u4.sort();
        u4.dedup();
        assert_eq!(u4.len(), 3, "the three roles must still be three distinct identities");

        // Too few participants to honour exclusivity => falls back rather than failing.
        // Three identities with the proposer excluded leaves only two for three roles.
        let short: Vec<[u8; 20]> = CandidateSet::EXCLUSIVE_ROLE_ORDER
            .iter()
            .map(|r| cs.selected_for_role(*r, h, Some(&ids[0])).unwrap().solver_pkh)
            .collect();
        assert_eq!(short.len(), 3, "every role must still resolve (liveness)");

        // LIVENESS: with a SINGLE identity there are not enough participants to go round, so
        // roles fall back rather than becoming unfillable — a rule that cannot be satisfied
        // would halt the chain.
        let mut solo = CandidateSet::new(1, h, [0x66u8; 32]);
        for role in CandidateSet::EXCLUSIVE_ROLE_ORDER {
            solo.candidates.push(RoleCandidate::build(
                1, h, &solo.seed.clone(), role, [0xD4u8; 20], apk(), [0x11u8; 32],
                PenaltyStatus::Clean.id(), 1000, [0x44u8; 32],
            ));
        }
        solo.sort_canonical();
        for role in CandidateSet::EXCLUSIVE_ROLE_ORDER {
            assert!(
                solo.selected_for_role(role, h, None).is_some(),
                "role {role} must still resolve with one participant (liveness)"
            );
        }

        match prev_net {
            Some(v) => std::env::set_var("IRIUM_NETWORK", v),
            None => std::env::remove_var("IRIUM_NETWORK"),
        }
        match prev_act {
            Some(v) => std::env::set_var("IRIUM_POAWX_EXCLUSIVE_ROLE_ACTIVATION_HEIGHT", v),
            None => std::env::remove_var("IRIUM_POAWX_EXCLUSIVE_ROLE_ACTIVATION_HEIGHT"),
        }
    }

    #[test]
    fn best_for_role_and_tiebreak() {
        let _env = crate::test_env::guard();
        let mut cs = CandidateSet::new(1, 10, [0x22u8; 32]);
        // two candidates same role; pick higher effective_score.
        let mut hi = RoleCandidate::build(
            1,
            10,
            &cs.seed,
            1,
            [0x01u8; 20],
            apk(),
            [0x11u8; 32],
            PenaltyStatus::Clean.id(),
            1000,
            [0x44u8; 32],
        );
        let mut lo = RoleCandidate::build(
            1,
            10,
            &cs.seed,
            1,
            [0x02u8; 20],
            apk(),
            [0x12u8; 32],
            PenaltyStatus::Clean.id(),
            1000,
            [0x45u8; 32],
        );
        hi.effective_score = 5000;
        lo.effective_score = 100;
        cs.push(lo.clone());
        cs.push(hi.clone());
        assert_eq!(cs.best_for_role(1).unwrap().solver_pkh, hi.solver_pkh);
        // tie on score => smaller assignment_proof_digest wins.
        let mut a = hi.clone();
        let mut b = hi.clone();
        a.effective_score = 5000;
        b.effective_score = 5000;
        a.assignment_proof_digest = [0x01u8; 32];
        a.solver_pkh = [0xA1u8; 20];
        b.assignment_proof_digest = [0x02u8; 32];
        b.solver_pkh = [0xB2u8; 20];
        let mut cs2 = CandidateSet::new(1, 10, [0x22u8; 32]);
        cs2.push(b);
        cs2.push(a.clone());
        assert_eq!(
            cs2.best_for_role(1).unwrap().assignment_proof_digest,
            a.assignment_proof_digest
        );
    }

    #[test]
    fn assignment_v2_prove_verify_and_rejects() {
        let _env = crate::test_env::guard();
        let secret = [7u8; 32];
        let solver = [0xAAu8; 20];
        let ticket = [0x11u8; 32];
        let seed = [0x22u8; 32];
        let p = AssignmentProofV2::prove(&secret, 1, 10, 1, solver, ticket, seed).expect("prove");
        assert!(p.validate(1, 10).is_ok(), "valid V2 proof accepts");
        // deterministic output + digest for same key/message.
        let p2 = AssignmentProofV2::prove(&secret, 1, 10, 1, solver, ticket, seed).unwrap();
        assert_eq!(p.vrf_output, p2.vrf_output, "deterministic VRF output");
        assert_eq!(p.digest, p2.digest);
        // score derives from VRF output.
        assert_eq!(p.score(), assignment_v2_score_from_output(&p.vrf_output));
        // wire round-trip.
        let b = p.serialize();
        assert_eq!(b.len(), ASSIGNMENT_PROOF_V2_WIRE);
        assert_eq!(AssignmentProofV2::deserialize(&b).unwrap(), p);
        // wrong network / height (validate args).
        assert!(p.validate(2, 10).is_err(), "wrong network");
        assert!(p.validate(1, 11).is_err(), "wrong height");
        // re-stamp digest after a field mutation so the VRF/verify check is what fails.
        let restamp = |mut m: AssignmentProofV2| {
            m.digest = m.compute_digest();
            m
        };
        let mut m = p.clone();
        m.role_id ^= 1;
        assert!(restamp(m).validate(1, 10).is_err(), "wrong role");
        let mut m = p.clone();
        m.solver_pkh[0] ^= 1;
        assert!(restamp(m).validate(1, 10).is_err(), "wrong solver");
        let mut m = p.clone();
        m.ticket_digest[0] ^= 1;
        assert!(restamp(m).validate(1, 10).is_err(), "wrong ticket");
        let mut m = p.clone();
        m.seed[0] ^= 1;
        assert!(restamp(m).validate(1, 10).is_err(), "wrong seed");
        let mut m = p.clone();
        m.assignment_public_key[1] ^= 1;
        assert!(restamp(m).validate(1, 10).is_err(), "wrong pubkey");
        let mut m = p.clone();
        m.vrf_output[0] ^= 1;
        assert!(restamp(m).validate(1, 10).is_err(), "mutated output");
        let mut m = p.clone();
        m.vrf_proof[0] ^= 1;
        assert!(restamp(m).validate(1, 10).is_err(), "mutated proof");
        let mut m = p.clone();
        m.vrf_proof = [0u8; VRF_PROOF_WIRE];
        assert!(restamp(m).validate(1, 10).is_err(), "malformed proof");
        // mutate WITHOUT re-stamp -> digest mismatch caught.
        let mut m = p.clone();
        m.solver_pkh[0] ^= 1;
        assert!(m.validate(1, 10).is_err(), "digest mismatch");
        // a different key/message yields a different output (unpredictability proxy).
        let q = AssignmentProofV2::prove(&[9u8; 32], 1, 10, 1, solver, ticket, seed).unwrap();
        assert_ne!(
            p.vrf_output, q.vrf_output,
            "different key -> different output"
        );
    }

    #[test]
    fn phase23a_assignment_v2_deserialize_rejects_bad_length() {
        let _env = crate::test_env::guard();
        let p = AssignmentProofV2::prove(
            &[7u8; 32],
            1,
            10,
            1,
            [0xAAu8; 20],
            [0x11u8; 32],
            [0x22u8; 32],
        )
        .unwrap();
        let w = p.serialize();
        assert_eq!(w.len(), ASSIGNMENT_PROOF_V2_WIRE);
        assert!(
            AssignmentProofV2::deserialize(&w[..w.len() - 1]).is_err(),
            "short"
        );
        let mut over = w.clone();
        over.push(0);
        assert!(AssignmentProofV2::deserialize(&over).is_err(), "long");
        assert!(AssignmentProofV2::deserialize(&[]).is_err(), "empty");
        // exact length parses structurally; validate() is the crypto gate (covered
        // by assignment_v2_prove_verify_and_rejects).
        assert!(AssignmentProofV2::deserialize(&[0u8; ASSIGNMENT_PROOF_V2_WIRE]).is_ok());
    }

    #[test]
    fn true_vrf_gates() {
        let _env = crate::test_env::guard();
        let _g = crate::poawx::poawx_test_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_TRUE_VRF_ACTIVATION_HEIGHT", "5");
        std::env::set_var("IRIUM_POAWX_TRUE_VRF_REQUIRED", "1");
        assert!(true_vrf_active(5));
        assert!(true_vrf_enforced(5));
        assert!(!true_vrf_active(4), "below activation");
        std::env::set_var("IRIUM_NETWORK", "mainnet");
        assert!(!true_vrf_active(5), "below the mainnet activation height; NOT hard-off (see activation::mainnet_gate_truth)");
        assert!(!true_vrf_enforced(5), "below the mainnet activation height; NOT hard-off (see activation::mainnet_gate_truth)");
        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_TRUE_VRF_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_TRUE_VRF_REQUIRED");
    }

    #[test]
    fn gate_logic_pure() {
        let _env = crate::test_env::guard();
        assert!(!poawx_phase21d_gate(0, Some(1), 100), "below the mainnet activation height; NOT hard-off (see activation::mainnet_gate_truth)");
        assert!(poawx_phase21d_gate(1, Some(1), 100));
        assert!(!poawx_phase21d_gate(1, None, 100));
        assert!(!poawx_phase21d_gate(1, Some(200), 100));
        assert!(poawx_phase21d_enforced_gate(1, Some(1), true, 100));
        assert!(!poawx_phase21d_enforced_gate(1, Some(1), false, 100));
        assert!(
            !poawx_phase21d_enforced_gate(0, Some(1), true, 100),
            "below the mainnet activation height; NOT hard-off (see activation::mainnet_gate_truth)"
        );
    }
}
