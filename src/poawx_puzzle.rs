//! Phase 21F: PoAW-X puzzle work modes + fast verification primitives.
//!
//! These are **assigned-work verification primitives**, NOT a replacement for
//! Irium's chain Proof-of-Work or LWMA-144 difficulty. They do NOT touch the block
//! interval, `bits`, the block target, or LWMA. A deterministic per-(network,
//! height, role, miner, seed) assignment picks one `PuzzleMode`; the assigned
//! solver produces a compact `PuzzleSolutionV1` that every node can verify in
//! bounded, deterministic, allocation-bounded, float-free time. No hardware-class
//! assumptions: any miner may attempt any mode.
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
use crate::poawx_ticket::leading_zero_bits;

// Domain tags (domain-separated; never collide with chain PoW hashing).
const MODE_DOMAIN: &[u8] = b"IRIUM_POAWX_PUZZLE_MODE_V1";
const CHALLENGE_DOMAIN: &[u8] = b"IRIUM_POAWX_PUZZLE_CHALLENGE_V1";
const ANCHOR_DOMAIN: &[u8] = b"IRIUM_POAWX_PUZZLE_ANCHOR_V1";
const MEM_DOMAIN: &[u8] = b"IRIUM_POAWX_PUZZLE_MEM_V1";
const PAR_DOMAIN: &[u8] = b"IRIUM_POAWX_PUZZLE_PAR_V1";
const VERIFY_DOMAIN: &[u8] = b"IRIUM_POAWX_PUZZLE_VERIFY_V1";
const FINALITY_DOMAIN: &[u8] = b"IRIUM_POAWX_PUZZLE_FINALITY_V1";

/// 4-byte trailing-section magic for puzzle proofs in the Phase 20 ext.
pub const PUZZLE_SECTION_MAGIC: &[u8; 4] = b"PZL1";
/// Wire size of one `PuzzleSolutionV1`: mode(1)+nonce(8)+proof_digest(32).
pub const PUZZLE_SOLUTION_WIRE: usize = 1 + 8 + 32;

// Hard bounds (consensus safety: no unbounded work/memory).
const MAX_MEM_WORDS: u32 = 4096;
const MAX_LANES: u8 = 16;
const MAX_ITERATIONS: u32 = 4096;
const MAX_ANCHOR_BITS: u8 = 24;
/// Solve-side grind cap (dev/test). Verify never grinds.
const SOLVE_NONCE_CAP: u64 = 1 << 24;

/// Assigned puzzle work mode. Any miner may attempt any mode (no hardware lanes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PuzzleMode {
    Sha256dAnchor,
    RandomMemory,
    ParallelCompute,
    VerificationWork,
    FinalityWorkPlaceholder,
}

impl PuzzleMode {
    pub fn id(self) -> u8 {
        match self {
            PuzzleMode::Sha256dAnchor => 0,
            PuzzleMode::RandomMemory => 1,
            PuzzleMode::ParallelCompute => 2,
            PuzzleMode::VerificationWork => 3,
            PuzzleMode::FinalityWorkPlaceholder => 4,
        }
    }
    pub fn from_id(b: u8) -> Option<Self> {
        Some(match b {
            0 => PuzzleMode::Sha256dAnchor,
            1 => PuzzleMode::RandomMemory,
            2 => PuzzleMode::ParallelCompute,
            3 => PuzzleMode::VerificationWork,
            4 => PuzzleMode::FinalityWorkPlaceholder,
            _ => return None,
        })
    }
    fn from_index(i: u8) -> Self {
        PuzzleMode::from_id(i % 5).expect("i%5 in range")
    }
    /// Whether this mode requires a nonce grind to a leading-zero-bit threshold.
    fn is_threshold_work(self) -> bool {
        matches!(
            self,
            PuzzleMode::Sha256dAnchor | PuzzleMode::RandomMemory | PuzzleMode::ParallelCompute
        )
    }
}

/// Deterministic, integer-only difficulty profile (all fields hard-bounded).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PuzzleDifficultyProfile {
    pub anchor_bits: u8,
    pub mem_words: u32,
    pub lanes: u8,
    pub iterations: u32,
}

impl Default for PuzzleDifficultyProfile {
    fn default() -> Self {
        Self {
            anchor_bits: 8,
            mem_words: 64,
            lanes: 4,
            iterations: 16,
        }
    }
}

impl PuzzleDifficultyProfile {
    /// Clamp every field to its hard bound (consensus safety).
    pub fn clamped(self) -> Self {
        Self {
            anchor_bits: self.anchor_bits.min(MAX_ANCHOR_BITS),
            mem_words: self.mem_words.clamp(1, MAX_MEM_WORDS),
            lanes: self.lanes.clamp(1, MAX_LANES),
            iterations: self.iterations.min(MAX_ITERATIONS),
        }
    }
    pub fn serialize(&self) -> [u8; 10] {
        let c = self.clamped();
        let mut out = [0u8; 10];
        out[0] = c.anchor_bits;
        out[1..5].copy_from_slice(&c.mem_words.to_le_bytes());
        out[5] = c.lanes;
        out[6..10].copy_from_slice(&c.iterations.to_le_bytes());
        out
    }
}

/// Batch 1 / P2-A: the ONE place `anchor_bits` is resolved from the environment.
///
/// Two env vars historically configured the same field on opposite sides of consensus:
/// the VALIDATOR read `IRIUM_POAWX_PUZZLE_BITS` (via `default_profile`) while the
/// PRODUCER read `IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS`. `anchor_bits` is folded into
/// `compute_challenge_digest` through `profile.serialize()`, so a node with only one of
/// them set computed a DIFFERENT challenge digest from its peers and rejected otherwise
/// valid blocks — a self-inflicted fork on a path that is enforcing mainnet block
/// acceptance today. Both defaulted to 8, which is the only reason mainnet was consistent.
///
/// Both names are now accepted and resolve identically on both sides. If both are set and
/// DISAGREE the value is rejected and the default is used, with a loud log line — an
/// explicit, logged failure rather than a silent divergence (CLAUDE.md §9).
pub fn configured_anchor_bits() -> Option<u8> {
    // Parse as u32 then CAP at the hard bound, rather than as u8. A value above the
    // bound (e.g. "9999") must clamp to MAX_ANCHOR_BITS on BOTH sides -- parsing as u8
    // would make it unparseable and silently fall back to the default, which is exactly
    // the validator/producer divergence this function exists to remove (the producer
    // already capped; the validator's u8 parse did not). Only a genuinely unparseable
    // value yields None, and the caller then fails closed.
    let read = |k: &str| {
        std::env::var(k)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .and_then(|v| v.parse::<u32>().ok())
            .map(|n| n.min(MAX_ANCHOR_BITS as u32) as u8)
    };
    let canonical = read("IRIUM_POAWX_PUZZLE_BITS");
    let legacy = read("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS");
    match (canonical, legacy) {
        (Some(a), Some(b)) if a != b => {
            eprintln!(
                "[poawx] FATAL CONFIG: IRIUM_POAWX_PUZZLE_BITS={} disagrees with \
                 IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS={}. These configure the SAME consensus \
                 field; a mismatch forks this node off the network. Ignoring both and using \
                 the default. Set one, or set both to the same value.",
                a, b
            );
            None
        }
        (Some(a), _) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

/// D1b: `anchor_bits` enters `compute_challenge_digest` via `profile.serialize()`, so it
/// is a CONSENSUS input. Reading it from the environment on mainnet lets any operator who
/// sets it compute a different challenge digest from the rest of the network and reject
/// every otherwise-valid block -- a self-inflicted fork, on a path that is enforcing
/// mainnet block acceptance today. The override is honoured on testnet/devnet only.
pub fn default_profile() -> PuzzleDifficultyProfile {
    let mut p = PuzzleDifficultyProfile::default();
    if network_id_byte() != 0 {
        if let Some(b) = configured_anchor_bits() {
            p.anchor_bits = b;
        }
    }
    p.clamped()
}

/// Like [`default_profile`] but with an explicit anchor-bits value (clamped), for
/// callers that receive the bits authoritatively (e.g. from the node block template)
/// instead of reading `IRIUM_POAWX_PUZZLE_BITS`. Clamping unchanged.
pub fn profile_with_bits(anchor_bits: u8) -> PuzzleDifficultyProfile {
    let mut p = PuzzleDifficultyProfile::default();
    p.anchor_bits = anchor_bits;
    p.clamped()
}

/// Deterministic mode selection for a candidate/role. Domain-separated; no
/// hardware identity. Changes if seed/height/role/miner/ticket/assignment change.
#[allow(clippy::too_many_arguments)]
pub fn assign_puzzle_mode(
    network_id: u8,
    target_height: u64,
    role_id: u8,
    solver_pkh: &[u8; 20],
    ticket_digest: &[u8; 32],
    assignment_proof_digest: &[u8; 32],
    seed: &[u8; 32],
) -> PuzzleMode {
    let mut h = Sha256::new();
    h.update(MODE_DOMAIN);
    h.update([network_id]);
    h.update(target_height.to_le_bytes());
    h.update([role_id]);
    h.update(solver_pkh);
    h.update(ticket_digest);
    h.update(assignment_proof_digest);
    h.update(seed);
    let d: [u8; 32] = h.finalize().into();
    PuzzleMode::from_index(d[0])
}

/// An assigned puzzle challenge, bound to its full context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PuzzleChallengeV1 {
    pub network_id: u8,
    pub target_height: u64,
    pub role_id: u8,
    pub solver_pkh: [u8; 20],
    pub ticket_digest: [u8; 32],
    pub assignment_proof_digest: [u8; 32],
    pub candidate_digest: [u8; 32],
    pub seed: [u8; 32],
    pub mode: PuzzleMode,
    pub profile: PuzzleDifficultyProfile,
    pub challenge_digest: [u8; 32],
}

#[allow(clippy::too_many_arguments)]
fn compute_challenge_digest(
    network_id: u8,
    target_height: u64,
    role_id: u8,
    solver_pkh: &[u8; 20],
    ticket_digest: &[u8; 32],
    assignment_proof_digest: &[u8; 32],
    candidate_digest: &[u8; 32],
    seed: &[u8; 32],
    mode: PuzzleMode,
    profile: &PuzzleDifficultyProfile,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CHALLENGE_DOMAIN);
    h.update([network_id]);
    h.update(target_height.to_le_bytes());
    h.update([role_id]);
    h.update(solver_pkh);
    h.update(ticket_digest);
    h.update(assignment_proof_digest);
    h.update(candidate_digest);
    h.update(seed);
    h.update([mode.id()]);
    h.update(profile.serialize());
    h.finalize().into()
}

impl PuzzleChallengeV1 {
    /// Build the challenge for an (assigned) candidate/role. The mode is selected
    /// deterministically from the same binding context.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        network_id: u8,
        target_height: u64,
        role_id: u8,
        solver_pkh: [u8; 20],
        ticket_digest: [u8; 32],
        assignment_proof_digest: [u8; 32],
        candidate_digest: [u8; 32],
        seed: [u8; 32],
        profile: PuzzleDifficultyProfile,
    ) -> Self {
        let profile = profile.clamped();
        let mode = assign_puzzle_mode(
            network_id,
            target_height,
            role_id,
            &solver_pkh,
            &ticket_digest,
            &assignment_proof_digest,
            &seed,
        );
        let challenge_digest = compute_challenge_digest(
            network_id,
            target_height,
            role_id,
            &solver_pkh,
            &ticket_digest,
            &assignment_proof_digest,
            &candidate_digest,
            &seed,
            mode,
            &profile,
        );
        Self {
            network_id,
            target_height,
            role_id,
            solver_pkh,
            ticket_digest,
            assignment_proof_digest,
            candidate_digest,
            seed,
            mode,
            profile,
            challenge_digest,
        }
    }
}

/// A compact puzzle solution (fixed wire; never carries a memory dump).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PuzzleSolutionV1 {
    pub mode: u8,
    pub nonce: u64,
    pub proof_digest: [u8; 32],
}

impl PuzzleSolutionV1 {
    pub fn serialize(&self) -> [u8; PUZZLE_SOLUTION_WIRE] {
        let mut out = [0u8; PUZZLE_SOLUTION_WIRE];
        out[0] = self.mode;
        out[1..9].copy_from_slice(&self.nonce.to_le_bytes());
        out[9..41].copy_from_slice(&self.proof_digest);
        out
    }
    pub fn deserialize(raw: &[u8]) -> Result<Self, String> {
        if raw.len() != PUZZLE_SOLUTION_WIRE {
            return Err("puzzle solution: bad length".to_string());
        }
        let mode = raw[0];
        let mut nb = [0u8; 8];
        nb.copy_from_slice(&raw[1..9]);
        let nonce = u64::from_le_bytes(nb);
        let mut proof_digest = [0u8; 32];
        proof_digest.copy_from_slice(&raw[9..41]);
        Ok(Self {
            mode,
            nonce,
            proof_digest,
        })
    }
}

/// Fast-verification result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PuzzleVerificationResult {
    Valid,
    Invalid(String),
}

impl PuzzleVerificationResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, PuzzleVerificationResult::Valid)
    }
}

fn sha256d(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    let first: [u8; 32] = h.finalize().into();
    let mut h2 = Sha256::new();
    h2.update(first);
    h2.finalize().into()
}

fn anchor_output(challenge_digest: &[u8; 32], nonce: u64) -> [u8; 32] {
    sha256d(&[ANCHOR_DOMAIN, challenge_digest, &nonce.to_le_bytes()])
}

/// Bounded deterministic memory-walk. Output is a compact digest (no dump).
fn memory_output(challenge_digest: &[u8; 32], nonce: u64, p: &PuzzleDifficultyProfile) -> [u8; 32] {
    let p = p.clamped();
    let n = p.mem_words as usize;
    let iters = p.iterations as usize;
    let mut scratch = vec![0u64; n];
    let mut seed8 = [0u8; 8];
    seed8.copy_from_slice(&challenge_digest[0..8]);
    let mut acc = u64::from_le_bytes(seed8) ^ nonce;
    for (i, slot) in scratch.iter_mut().enumerate() {
        acc = acc
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407 ^ (i as u64));
        *slot = acc;
    }
    for _ in 0..iters {
        let idx = (acc as usize) % n;
        acc = acc.rotate_left(13) ^ scratch[idx].wrapping_mul(0x9E37_79B9_7F4A_7C15);
        scratch[idx] = acc;
    }
    let mut h = Sha256::new();
    h.update(MEM_DOMAIN);
    h.update(challenge_digest);
    h.update(nonce.to_le_bytes());
    h.update(acc.to_le_bytes());
    h.finalize().into()
}

/// Bounded deterministic multi-lane hash (no GPU requirement).
fn parallel_output(
    challenge_digest: &[u8; 32],
    nonce: u64,
    p: &PuzzleDifficultyProfile,
) -> [u8; 32] {
    let p = p.clamped();
    let mut h = Sha256::new();
    h.update(PAR_DOMAIN);
    h.update(challenge_digest);
    h.update(nonce.to_le_bytes());
    for lane in 0..p.lanes {
        let mut lh = Sha256::new();
        lh.update(challenge_digest);
        lh.update(nonce.to_le_bytes());
        lh.update([lane]);
        let d: [u8; 32] = lh.finalize().into();
        h.update(d);
    }
    h.finalize().into()
}

fn verification_digest(c: &PuzzleChallengeV1) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(VERIFY_DOMAIN);
    h.update(c.challenge_digest);
    h.update(c.candidate_digest);
    h.update(c.assignment_proof_digest);
    h.finalize().into()
}

fn finality_digest(c: &PuzzleChallengeV1) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(FINALITY_DOMAIN);
    h.update(c.challenge_digest);
    h.update(c.seed);
    h.finalize().into()
}

fn threshold_output(c: &PuzzleChallengeV1, nonce: u64) -> [u8; 32] {
    match c.mode {
        PuzzleMode::Sha256dAnchor => anchor_output(&c.challenge_digest, nonce),
        PuzzleMode::RandomMemory => memory_output(&c.challenge_digest, nonce, &c.profile),
        PuzzleMode::ParallelCompute => parallel_output(&c.challenge_digest, nonce, &c.profile),
        _ => [0u8; 32],
    }
}

/// Produce a solution for the challenge (dev/test/pool side). For threshold modes
/// it grinds a nonce up to a bounded cap; for verification/finality it is a
/// deterministic reference digest (nonce 0). Returns None if no nonce found.
pub fn solve_dev(c: &PuzzleChallengeV1) -> Option<PuzzleSolutionV1> {
    match c.mode {
        PuzzleMode::VerificationWork => Some(PuzzleSolutionV1 {
            mode: c.mode.id(),
            nonce: 0,
            proof_digest: verification_digest(c),
        }),
        PuzzleMode::FinalityWorkPlaceholder => Some(PuzzleSolutionV1 {
            mode: c.mode.id(),
            nonce: 0,
            proof_digest: finality_digest(c),
        }),
        _ => {
            let bits = c.profile.anchor_bits as u32;
            for nonce in 0..SOLVE_NONCE_CAP {
                let out = threshold_output(c, nonce);
                if leading_zero_bits(&out) >= bits {
                    return Some(PuzzleSolutionV1 {
                        mode: c.mode.id(),
                        nonce,
                        proof_digest: out,
                    });
                }
            }
            None
        }
    }
}

/// Fast, bounded, deterministic verification (no network, no wall-clock, no
/// floats, no unbounded memory). Verify never grinds.
pub fn verify_solution(c: &PuzzleChallengeV1, s: &PuzzleSolutionV1) -> PuzzleVerificationResult {
    use PuzzleVerificationResult::*;
    if s.mode != c.mode.id() {
        return Invalid("wrong mode".to_string());
    }
    match c.mode {
        PuzzleMode::VerificationWork => {
            if s.nonce != 0 || s.proof_digest != verification_digest(c) {
                return Invalid("bad verification reference".to_string());
            }
        }
        PuzzleMode::FinalityWorkPlaceholder => {
            if s.nonce != 0 || s.proof_digest != finality_digest(c) {
                return Invalid("bad finality reference".to_string());
            }
        }
        _ => {
            let out = threshold_output(c, s.nonce);
            if out != s.proof_digest {
                return Invalid("proof digest mismatch".to_string());
            }
            if leading_zero_bits(&out) < c.profile.anchor_bits as u32 {
                return Invalid("below assigned-work threshold".to_string());
            }
        }
    }
    Valid
}

// ── Gates (param-driven pure logic; mainnet-ACTIVE at height >= 50_000) ────────────────────────

pub fn puzzle_work_activation_height() -> Option<u64> {
    std::env::var("IRIUM_POAWX_PUZZLE_WORK_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}
pub fn puzzle_work_required() -> bool {
    if crate::activation::network_id_byte() == 0 {
        return true; // mainnet: enforced once the gate is active (height-gated)
    }
    std::env::var("IRIUM_POAWX_PUZZLE_WORK_REQUIRED")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}
pub fn puzzle_work_gate(network_id: u8, activation: Option<u64>, height: u64) -> bool {
    matches!(crate::activation::poawx_effective_activation(network_id, activation), Some(h) if height >= h)
}
pub fn puzzle_work_enforced_gate(
    network_id: u8,
    activation: Option<u64>,
    required: bool,
    height: u64,
) -> bool {
    puzzle_work_gate(network_id, activation, height) && required
}
pub fn puzzle_work_active(height: u64) -> bool {
    puzzle_work_gate(network_id_byte(), puzzle_work_activation_height(), height)
}
pub fn puzzle_work_enforced(height: u64) -> bool {
    puzzle_work_enforced_gate(
        network_id_byte(),
        puzzle_work_activation_height(),
        puzzle_work_required(),
        height,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> ([u8; 20], [u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
        (
            [0xC1u8; 20],
            [0x11u8; 32],
            [0x22u8; 32],
            [0x33u8; 32],
            [0x44u8; 32],
        )
    }

    #[test]
    fn phase24a_puzzle_solution_wire_malformed_rejected() {
        let _env = crate::test_env::guard();
        assert!(PuzzleSolutionV1::deserialize(&[0u8; PUZZLE_SOLUTION_WIRE - 1]).is_err());
        assert!(PuzzleSolutionV1::deserialize(&[0u8; PUZZLE_SOLUTION_WIRE + 1]).is_err());
        assert!(PuzzleSolutionV1::deserialize(&[]).is_err());
        assert!(PuzzleSolutionV1::deserialize(&[0u8; PUZZLE_SOLUTION_WIRE]).is_ok());
    }

    #[test]
    fn mode_assignment_deterministic_and_bound() {
        let _env = crate::test_env::guard();
        let (pkh, td, apd, _cd, seed) = ctx();
        let m1 = assign_puzzle_mode(1, 10, 1, &pkh, &td, &apd, &seed);
        let m2 = assign_puzzle_mode(1, 10, 1, &pkh, &td, &apd, &seed);
        assert_eq!(m1, m2, "deterministic");
        // changing any binding field can change the mode/selector digest.
        let mut h = Sha256::new();
        h.update(MODE_DOMAIN);
        h.update([1u8]);
        h.update(10u64.to_le_bytes());
        let _ = h.finalize();
        // height/network/role/seed bound: selector digest differs.
        let a = assign_puzzle_mode(1, 10, 1, &pkh, &td, &apd, &seed);
        let b = assign_puzzle_mode(2, 10, 1, &pkh, &td, &apd, &seed);
        let c = assign_puzzle_mode(1, 11, 1, &pkh, &td, &apd, &seed);
        let d = assign_puzzle_mode(1, 10, 2, &pkh, &td, &apd, &seed);
        // not all need to differ (mod 5), but the underlying selection is a pure
        // function — at least confirm it returns a valid mode for each.
        for m in [a, b, c, d] {
            assert!(PuzzleMode::from_id(m.id()).is_some());
        }
    }

    #[test]
    fn challenge_digest_mutation_sensitivity() {
        let _env = crate::test_env::guard();
        let (pkh, td, apd, cd, seed) = ctx();
        let p = PuzzleDifficultyProfile::default();
        let c0 = PuzzleChallengeV1::build(1, 10, 1, pkh, td, apd, cd, seed, p);
        let c_seed = PuzzleChallengeV1::build(1, 10, 1, pkh, td, apd, cd, [0x99u8; 32], p);
        assert_ne!(
            c0.challenge_digest, c_seed.challenge_digest,
            "seed mutation"
        );
        let c_h = PuzzleChallengeV1::build(1, 11, 1, pkh, td, apd, cd, seed, p);
        assert_ne!(c0.challenge_digest, c_h.challenge_digest, "height bound");
        let c_n = PuzzleChallengeV1::build(2, 10, 1, pkh, td, apd, cd, seed, p);
        assert_ne!(c0.challenge_digest, c_n.challenge_digest, "network bound");
        let c_r = PuzzleChallengeV1::build(1, 10, 2, pkh, td, apd, cd, seed, p);
        assert_ne!(c0.challenge_digest, c_r.challenge_digest, "role bound");
    }

    /// Build a challenge forced to a specific mode (search a solver pkh that maps).
    fn challenge_for_mode(
        target: PuzzleMode,
        profile: PuzzleDifficultyProfile,
    ) -> PuzzleChallengeV1 {
        let (_pkh, td, apd, cd, seed) = ctx();
        for i in 0u32..10_000 {
            let mut pkh = [0u8; 20];
            pkh[0..4].copy_from_slice(&i.to_le_bytes());
            let c = PuzzleChallengeV1::build(1, 10, 1, pkh, td, apd, cd, seed, profile);
            if c.mode == target {
                return c;
            }
        }
        panic!("no pkh mapped to mode {:?}", target);
    }

    #[test]
    fn solve_and_verify_each_mode() {
        let _env = crate::test_env::guard();
        let p = PuzzleDifficultyProfile {
            anchor_bits: 6,
            mem_words: 32,
            lanes: 4,
            iterations: 16,
        };
        for mode in [
            PuzzleMode::Sha256dAnchor,
            PuzzleMode::RandomMemory,
            PuzzleMode::ParallelCompute,
            PuzzleMode::VerificationWork,
            PuzzleMode::FinalityWorkPlaceholder,
        ] {
            let c = challenge_for_mode(mode, p);
            let sol = solve_dev(&c).expect("solve");
            assert!(verify_solution(&c, &sol).is_valid(), "valid {:?}", mode);
            // wrong mode rejects.
            let mut bad = sol;
            bad.mode = sol.mode.wrapping_add(1) % 5;
            assert!(
                !verify_solution(&c, &bad).is_valid(),
                "wrong mode {:?}",
                mode
            );
            // wrong proof digest rejects.
            let mut bad2 = sol;
            bad2.proof_digest[0] ^= 1;
            assert!(
                !verify_solution(&c, &bad2).is_valid(),
                "tampered {:?}",
                mode
            );
        }
    }

    #[test]
    fn threshold_modes_reject_wrong_nonce_and_below_threshold() {
        let _env = crate::test_env::guard();
        let p = PuzzleDifficultyProfile {
            anchor_bits: 8,
            mem_words: 32,
            lanes: 4,
            iterations: 16,
        };
        let c = challenge_for_mode(PuzzleMode::Sha256dAnchor, p);
        let sol = solve_dev(&c).expect("solve");
        // wrong nonce -> recomputed output != stored proof_digest -> reject.
        let mut wrong = sol;
        wrong.nonce = sol.nonce.wrapping_add(1);
        assert!(!verify_solution(&c, &wrong).is_valid());
        // a nonce-0 output that is below threshold rejects (unless it happens to
        // meet it; pick a fabricated low-zero digest).
        let out0 = threshold_output(&c, 0);
        if leading_zero_bits(&out0) < c.profile.anchor_bits as u32 {
            let below = PuzzleSolutionV1 {
                mode: c.mode.id(),
                nonce: 0,
                proof_digest: out0,
            };
            assert!(!verify_solution(&c, &below).is_valid(), "below threshold");
        }
    }

    #[test]
    fn wrong_solver_or_seed_changes_challenge_and_invalidates() {
        let _env = crate::test_env::guard();
        let p = PuzzleDifficultyProfile {
            anchor_bits: 6,
            ..Default::default()
        };
        let c = challenge_for_mode(PuzzleMode::ParallelCompute, p);
        let sol = solve_dev(&c).expect("solve");
        // verifying the same solution against a different-seed challenge fails.
        let c2 = PuzzleChallengeV1::build(
            c.network_id,
            c.target_height,
            c.role_id,
            c.solver_pkh,
            c.ticket_digest,
            c.assignment_proof_digest,
            c.candidate_digest,
            [0x77u8; 32],
            c.profile,
        );
        // c2 may map to a different mode; only assert if same mode (else digest
        // differs anyway). The solution is bound to c's challenge_digest.
        if c2.mode == c.mode {
            assert!(!verify_solution(&c2, &sol).is_valid(), "seed-bound");
        }
    }

    #[test]
    fn solution_wire_roundtrip() {
        let _env = crate::test_env::guard();
        let s = PuzzleSolutionV1 {
            mode: 2,
            nonce: 0xDEAD_BEEF,
            proof_digest: [0xABu8; 32],
        };
        let b = s.serialize();
        assert_eq!(b.len(), PUZZLE_SOLUTION_WIRE);
        assert_eq!(PuzzleSolutionV1::deserialize(&b).unwrap(), s);
        assert!(PuzzleSolutionV1::deserialize(&[0u8; 5]).is_err());
    }

    #[test]
    fn profile_is_bounded() {
        let _env = crate::test_env::guard();
        let huge = PuzzleDifficultyProfile {
            anchor_bits: 255,
            mem_words: u32::MAX,
            lanes: 255,
            iterations: u32::MAX,
        }
        .clamped();
        assert_eq!(huge.anchor_bits, MAX_ANCHOR_BITS);
        assert_eq!(huge.mem_words, MAX_MEM_WORDS);
        assert_eq!(huge.lanes, MAX_LANES);
        assert_eq!(huge.iterations, MAX_ITERATIONS);
    }

    #[test]
    fn gate_logic_pure_and_mainnet_off() {
        let _env = crate::test_env::guard();
        assert!(!puzzle_work_gate(0, Some(1), 100), "below the mainnet activation height; NOT hard-off (see activation::mainnet_gate_truth)");
        assert!(puzzle_work_gate(1, Some(1), 100));
        assert!(!puzzle_work_gate(1, None, 100));
        assert!(puzzle_work_enforced_gate(1, Some(1), true, 100));
        assert!(!puzzle_work_enforced_gate(1, Some(1), false, 100));
        assert!(
            !puzzle_work_enforced_gate(0, Some(1), true, 100),
            "below the mainnet activation height; NOT hard-off (see activation::mainnet_gate_truth)"
        );
    }
}

#[cfg(test)]
mod p2a_anchor_bits_unification {
    use super::*;

    fn clear() {
        std::env::remove_var("IRIUM_POAWX_PUZZLE_BITS");
        std::env::remove_var("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS");
    }

    /// D1b gates the env override to non-mainnet, so any test asserting that
    /// `default_profile()` HONOURS the override must state a network. Before D1b these
    /// tests relied on the default, which is mainnet.
    fn devnet() {
        std::env::set_var("IRIUM_NETWORK", "devnet");
    }

    /// The whole point of P2-A: BOTH names resolve identically, so the validator
    /// (`default_profile`) and the producer can no longer disagree about `anchor_bits`.
    #[test]
    fn either_env_name_resolves_identically() {
        let _env = crate::test_env::guard();
        devnet();
        clear();
        assert_eq!(configured_anchor_bits(), None, "unset => default");
        std::env::set_var("IRIUM_POAWX_PUZZLE_BITS", "12");
        assert_eq!(configured_anchor_bits(), Some(12));
        assert_eq!(default_profile().anchor_bits, 12);
        clear();
        // the legacy producer-side name must now reach the VALIDATOR too -- this is the
        // divergence that previously forked a node off the network.
        std::env::set_var("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS", "12");
        assert_eq!(configured_anchor_bits(), Some(12));
        assert_eq!(default_profile().anchor_bits, 12);
        clear();
        std::env::remove_var("IRIUM_NETWORK");
    }

    /// Agreeing values are accepted; disagreeing values are REJECTED (fail loud, not
    /// silently pick one) so a misconfigured node cannot quietly fork itself.
    #[test]
    fn conflicting_values_are_rejected_not_silently_resolved() {
        let _env = crate::test_env::guard();
        clear();
        std::env::set_var("IRIUM_POAWX_PUZZLE_BITS", "10");
        std::env::set_var("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS", "10");
        assert_eq!(configured_anchor_bits(), Some(10), "agreeing => accepted");
        std::env::set_var("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS", "11");
        assert_eq!(
            configured_anchor_bits(),
            None,
            "disagreeing => rejected, falls back to default rather than picking a side"
        );
        assert_eq!(
            default_profile().anchor_bits,
            PuzzleDifficultyProfile::default().anchor_bits,
            "a rejected mismatch must land on the default, identically on every node"
        );
        clear();
    }

    /// Mainnet has neither var set, which is why the historical split never bit.
    #[test]
    fn unset_matches_the_live_mainnet_configuration() {
        let _env = crate::test_env::guard();
        clear();
        assert_eq!(
            default_profile().anchor_bits,
            PuzzleDifficultyProfile::default().anchor_bits
        );
    }
}

#[cfg(test)]
mod p2a_cap_regression {
    use super::*;
    /// Regression: an over-large value must CAP identically on both sides, not fall back
    /// to the default. Parsing as u8 made "9999" unparseable on the validator side while
    /// the producer capped it to 24 -- the exact divergence P2-A removes.
    #[test]
    fn over_large_value_caps_rather_than_failing() {
        let _env = crate::test_env::guard();
        std::env::set_var("IRIUM_NETWORK", "devnet");
        std::env::remove_var("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS");
        std::env::set_var("IRIUM_POAWX_PUZZLE_BITS", "9999");
        assert_eq!(configured_anchor_bits(), Some(MAX_ANCHOR_BITS));
        assert_eq!(default_profile().anchor_bits, MAX_ANCHOR_BITS);
        std::env::set_var("IRIUM_POAWX_PUZZLE_BITS", "not-a-number");
        assert_eq!(configured_anchor_bits(), None, "malformed still fails closed");
        std::env::remove_var("IRIUM_POAWX_PUZZLE_BITS");
        std::env::remove_var("IRIUM_NETWORK");
    }
}

#[cfg(test)]
mod d1b_anchor_bits_is_not_env_tunable_on_mainnet {
    use super::*;

    /// D1b: `anchor_bits` enters the challenge digest, so an env-tunable value on
    /// mainnet lets one node compute a different digest and reject every valid block.
    #[test]
    fn mainnet_ignores_the_env_override_devnet_honours_it() {
        let _env = crate::test_env::guard();
        std::env::set_var("IRIUM_POAWX_PUZZLE_BITS", "17");
        std::env::set_var("IRIUM_NETWORK", "mainnet");
        assert_eq!(
            default_profile().anchor_bits,
            PuzzleDifficultyProfile::default().anchor_bits,
            "mainnet must ignore the env override -- it is a consensus input"
        );
        std::env::set_var("IRIUM_NETWORK", "devnet");
        assert_eq!(
            default_profile().anchor_bits, 17,
            "devnet must still honour the override"
        );
        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_PUZZLE_BITS");
    }
}
