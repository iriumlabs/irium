//! PoAW-X consensus helpers shared between the daemon, P2P layer, and tests.
//!
//! Env-var reads are intentionally absent here — callers own activation gating.

use crate::block::Block;
use crate::poawx_candidate::{
    AssignmentProofV2, CandidateSet, ASSIGNMENT_PROOF_V2_WIRE, ASSIGNMENT_V2_SECTION_MAGIC,
    CANDIDATE_SECTION_MAGIC,
};
use crate::poawx_challenge::{
    FraudProofV1, FRAUD_PROOF_MAX_PER_BLOCK, FRAUD_PROOF_SECTION_MAGIC, FRAUD_PROOF_V1_WIRE,
};
use crate::poawx_committed_admission::{
    AdmissionCommitmentV1, ADMISSION_COMMITMENT_WIRE, COMMITTED_ADMISSION_SECTION_MAGIC,
};
use crate::poawx_dominance::{DOMINANCE_SECTION_MAGIC, DOMINANCE_WEIGHTS_WIRE};
use crate::poawx_finality::{FinalityProofV1, FINALITY_SECTION_MAGIC};
use crate::poawx_puzzle::{PuzzleSolutionV1, PUZZLE_SECTION_MAGIC, PUZZLE_SOLUTION_WIRE};
use crate::poawx_ticket::{TicketProof, TICKET_PROOF_WIRE, TICKET_SECTION_MAGIC};
use sha2::{Digest, Sha256};

const IRX1_TAG: &[u8] = b"irx1";
/// 0x6a 0x24 b"irx1" <32-byte root> = 38 bytes
const IRX1_SCRIPT_LEN: usize = 38;

/// Returns `true` when the block coinbase contains a well-formed `irx1`
/// OP_RETURN commitment with a non-zero 32-byte root.
///
/// Wire format: `0x6a 0x24 "irx1" <32-byte root>` (38 bytes); root must not be all-zeros.
pub fn block_has_irx1_commitment(block: &Block) -> bool {
    let coinbase = match block.transactions.first() {
        Some(tx) => tx,
        None => return false,
    };
    coinbase.outputs.iter().any(|out| {
        let s = &out.script_pubkey;
        s.len() == IRX1_SCRIPT_LEN
            && s[0] == 0x6a
            && s[1] == 0x24
            && &s[2..6] == IRX1_TAG
            && s[6..38] != [0u8; 32]
    })
}

/// Eight-byte magic that precedes the PoAW-X receipt section appended after
/// all transactions in the block wire encoding. Chosen to be unambiguous
/// as a transaction start (version `0x575041AF` is not a real tx version).
pub const POAWX_RECEIPT_SECTION_MAGIC: &[u8; 8] = b"POAWXR\x01\x00";

/// Worker reward per receipt as permille (1/1000) of the block subsidy.
pub const POAWX_WORKER_REWARD_PERMILLE: u64 = 100;

/// Phase 18B: eight-byte magic for the v2 receipt section. A block uses this
/// (instead of `POAWX_RECEIPT_SECTION_MAGIC`) only when it carries at least one
/// mode-1 (delegated) receipt. Pure mode-0 blocks keep the v1 magic and are
/// byte-for-byte identical to the Phase 13-A encoding.
pub const POAWX_RECEIPT_SECTION_MAGIC_V2: &[u8; 8] = b"POAWXR\x02\x00";

/// Phase 20: eight-byte magic for the v3 receipt section. A block uses this only
/// when at least one receipt carries a `Phase20ReceiptExt`. Blocks with no
/// extension keep the v1/v2 magic and are byte-for-byte identical to Phase 13-A/18B.
/// (Data threading only — Step 1 does not enforce the extension.)
pub const POAWX_RECEIPT_SECTION_MAGIC_V3: &[u8; 8] = b"POAWXR\x03\x00";

/// Phase 18B: domain separator for the one-time miner delegation signature.
pub const DOMAIN_DELEG: &[u8] = b"irium.poawx.delegation.v1";

/// Receipt mode discriminator used in the v2 receipt section.
pub const RECEIPT_MODE_DIRECT: u8 = 0;
pub const RECEIPT_MODE_DELEGATED: u8 = 1;

// ── Phase 20: multi-role reward split (testnet/devnet-gated) ──────────────────
//
// Owner-supplied spec. Basis points of the block subsidy per role; total = 10000.
// PRIMARY_MINER is the miner/block-producing identity = the receipt `worker_pkh`
// (never the pool delegate key). COMPUTE/VERIFY/SUPPORT are consensus-bound payout
// roles only here; their eligibility/fairness assignment is a SEPARATE task (the
// CPU/GPU/ASIC fairness matrix), and this code invents no assignment rules.
//
// Activation is gated by `IRIUM_POAWX_MULTI_ROLE_REWARD_ACTIVATION_HEIGHT`
// (testnet/devnet only); mainnet is hard-off until an explicit future governance
// activation. Before activation, nothing here is used and existing Phase 18/19
// behavior is byte-identical.
pub const MULTI_ROLE_PRIMARY_BPS: u64 = 5500;
pub const MULTI_ROLE_COMPUTE_BPS: u64 = 2200;
pub const MULTI_ROLE_VERIFY_BPS: u64 = 1300;
pub const MULTI_ROLE_SUPPORT_BPS: u64 = 1000;
pub const MULTI_ROLE_TOTAL_BPS: u64 = 10000;

/// The three non-primary role payout identities for a multi-role PoAW-X block.
/// The PRIMARY role pkh is the receipt `worker_pkh` (the miner = payout identity)
/// and is intentionally NOT stored here so it can never be replaced by a pool key.
/// Canonical 60-byte wire encoding: compute || verify || support (20 bytes each).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleReward {
    pub compute_contributor_pkh: [u8; 20],
    pub verify_contributor_pkh: [u8; 20],
    pub support_contributor_pkh: [u8; 20],
}

impl RoleReward {
    /// Fixed wire size: 3 × 20 = 60 bytes.
    pub const WIRE_SIZE: usize = 60;

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::WIRE_SIZE);
        out.extend_from_slice(&self.compute_contributor_pkh);
        out.extend_from_slice(&self.verify_contributor_pkh);
        out.extend_from_slice(&self.support_contributor_pkh);
        out
    }

    pub fn deserialize(raw: &[u8]) -> Result<Self, String> {
        // Fix #11: RoleReward is always decoded from an exact WIRE_SIZE slice; reject any other
        // length (incl. trailing bytes) for canonical-encoding hardening, matching Fix-D for role
        // claims. (Delegation / PoawxBlockReceipt are prefix readers and keep `<` by design.)
        if raw.len() != Self::WIRE_SIZE {
            return Err(format!(
                "role reward bad length: {} != {}",
                raw.len(),
                Self::WIRE_SIZE
            ));
        }
        let mut compute_contributor_pkh = [0u8; 20];
        compute_contributor_pkh.copy_from_slice(&raw[0..20]);
        let mut verify_contributor_pkh = [0u8; 20];
        verify_contributor_pkh.copy_from_slice(&raw[20..40]);
        let mut support_contributor_pkh = [0u8; 20];
        support_contributor_pkh.copy_from_slice(&raw[40..60]);
        Ok(Self {
            compute_contributor_pkh,
            verify_contributor_pkh,
            support_contributor_pkh,
        })
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.serialize());
        h.finalize().into()
    }
}

/// Split `total_reward` (atomic units) into the four canonical role amounts in
/// fixed order `[primary, compute, verify, support]`. Each non-primary role gets
/// `floor(total * bps / 10000)`; any integer-division remainder goes to PRIMARY.
/// The returned amounts always sum to exactly `total_reward` (no over/underpay).
/// Uses u128 intermediates to avoid overflow.
pub fn multi_role_amounts(total_reward: u64) -> [u64; 4] {
    let bps = |b: u64| -> u64 { ((total_reward as u128 * b as u128) / 10000u128) as u64 };
    let compute = bps(MULTI_ROLE_COMPUTE_BPS);
    let verify = bps(MULTI_ROLE_VERIFY_BPS);
    let support = bps(MULTI_ROLE_SUPPORT_BPS);
    let primary_floor = bps(MULTI_ROLE_PRIMARY_BPS);
    // remainder (from all four floors) goes to PRIMARY so the sum is exact.
    let remainder = total_reward - primary_floor - compute - verify - support;
    let primary = primary_floor + remainder;
    [primary, compute, verify, support]
}

// ── Phase 20: third-party pool fee (testnet/devnet-gated) ────────────────────
//
// Official Irium pool fee remains 0% (fee_bps=0 default everywhere). A nonzero fee
// is allowed ONLY in explicit third-party pool mode, capped at THIRD_PARTY_FEE_CAP_BPS
// (200 bps = 2.00%), with a fee_pkh that is SIGNED into the miner delegation — the
// 226-byte `Delegation` already binds `fee_bps` + `fee_pkh` in `message_hash()`, so
// fee terms cannot be mutated after the miner signs. No hidden fee output. Mainnet is
// hard-off (the `chain` gate returns false on mainnet). The fee is deducted ONLY from
// the PRIMARY/miner allocation; compute/verify/support role rewards are never taxed.
pub const THIRD_PARTY_FEE_CAP_BPS: u16 = 200;
pub const THIRD_PARTY_FEE_DOMAIN_V1: &[u8] = b"IRIUM_POAWX_THIRD_PARTY_FEE_V1";

/// Validate fee terms against the third-party policy (pure; no env). `fee_bps=0`
/// is always allowed (official mode; requires no fee_pkh and no fee output).
/// `fee_bps>0` requires explicit third-party mode, a non-zero `fee_pkh`, and
/// `fee_bps <= THIRD_PARTY_FEE_CAP_BPS`.
pub fn validate_fee_terms(
    fee_bps: u16,
    fee_pkh: &[u8; 20],
    third_party_mode: bool,
) -> Result<(), String> {
    if fee_bps == 0 {
        return Ok(());
    }
    if !third_party_mode {
        return Err("fee_bps > 0 requires explicit third-party pool mode".to_string());
    }
    if fee_bps > THIRD_PARTY_FEE_CAP_BPS {
        return Err(format!(
            "fee_bps {} exceeds third-party cap {} (2.00%)",
            fee_bps, THIRD_PARTY_FEE_CAP_BPS
        ));
    }
    if fee_pkh == &[0u8; 20] {
        return Err("fee_bps > 0 requires a fee_pkh".to_string());
    }
    Ok(())
}

/// Split a PRIMARY/miner gross allocation into `(net, fee)`:
/// `fee = floor(gross * fee_bps / 10000)`, miner keeps the remainder; `net + fee == gross`.
/// Only the PRIMARY allocation is fee-taxed (compute/verify/support untouched).
pub fn apply_fee(gross: u64, fee_bps: u16) -> (u64, u64) {
    let fee = ((gross as u128 * fee_bps as u128) / 10000u128) as u64;
    (gross - fee, fee)
}

// ── Phase 20: CPU/GPU/ASIC fairness matrix (testnet/devnet-gated primitives) ──
//
// Hardware is NEVER detected or trusted. The chain does not ask "is this a
// CPU/GPU/ASIC?". Instead there are verifiable puzzle *lanes* with different
// resource profiles; any miner may attempt any lane. The protocol deterministically
// assigns lanes per (height, role slot) so no hardware class permanently dominates,
// targeting a 34/33/33 distribution across the three production lanes.
//
// This is the future SOURCE of COMPUTE/VERIFY/SUPPORT role claims for the
// multi-role reward split. These are primitives only — they do NOT change chain
// difficulty (LWMA-144) and are not wired into connect_block in this task.

/// Lane wire ids. UNIVERSAL_FALLBACK is dev/test only and is NOT a production
/// fairness lane (never produced by `assign_lane`, excluded from distribution).
pub const LANE_CPU_FRIENDLY: u8 = 0;
pub const LANE_GPU_PARALLEL: u8 = 1;
pub const LANE_ASIC_STREAMING: u8 = 2;
pub const LANE_UNIVERSAL_FALLBACK: u8 = 255;

/// PoAW-X puzzle lane (resource profile, NOT a mandatory hardware label).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoawxLane {
    CpuFriendly,
    GpuParallel,
    AsicStreaming,
    /// Dev/test fallback only — excluded from production fairness distribution.
    UniversalFallback,
}

impl PoawxLane {
    pub fn id(self) -> u8 {
        match self {
            PoawxLane::CpuFriendly => LANE_CPU_FRIENDLY,
            PoawxLane::GpuParallel => LANE_GPU_PARALLEL,
            PoawxLane::AsicStreaming => LANE_ASIC_STREAMING,
            PoawxLane::UniversalFallback => LANE_UNIVERSAL_FALLBACK,
        }
    }
    pub fn from_id(b: u8) -> Option<Self> {
        match b {
            LANE_CPU_FRIENDLY => Some(PoawxLane::CpuFriendly),
            LANE_GPU_PARALLEL => Some(PoawxLane::GpuParallel),
            LANE_ASIC_STREAMING => Some(PoawxLane::AsicStreaming),
            LANE_UNIVERSAL_FALLBACK => Some(PoawxLane::UniversalFallback),
            _ => None,
        }
    }
    /// True for the three production fairness lanes (fallback excluded).
    pub fn is_fairness_lane(self) -> bool {
        matches!(
            self,
            PoawxLane::CpuFriendly | PoawxLane::GpuParallel | PoawxLane::AsicStreaming
        )
    }
}

/// Role-slot ids that the fairness matrix assigns lanes for. These align with the
/// multi-role reward split's non-primary roles. PRIMARY_MINER (the existing path)
/// is intentionally NOT a fairness role and is never assigned a lane here.
pub const ROLE_COMPUTE_CONTRIBUTOR: u8 = 1;
pub const ROLE_VERIFY_CONTRIBUTOR: u8 = 2;
pub const ROLE_SUPPORT_CONTRIBUTOR: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoawxRoleSlot {
    ComputeContributor,
    VerifyContributor,
    SupportContributor,
}

impl PoawxRoleSlot {
    pub fn id(self) -> u8 {
        match self {
            PoawxRoleSlot::ComputeContributor => ROLE_COMPUTE_CONTRIBUTOR,
            PoawxRoleSlot::VerifyContributor => ROLE_VERIFY_CONTRIBUTOR,
            PoawxRoleSlot::SupportContributor => ROLE_SUPPORT_CONTRIBUTOR,
        }
    }
    pub fn from_id(b: u8) -> Option<Self> {
        match b {
            ROLE_COMPUTE_CONTRIBUTOR => Some(PoawxRoleSlot::ComputeContributor),
            ROLE_VERIFY_CONTRIBUTOR => Some(PoawxRoleSlot::VerifyContributor),
            ROLE_SUPPORT_CONTRIBUTOR => Some(PoawxRoleSlot::SupportContributor),
            _ => None,
        }
    }
}

/// Domain separators (versioned) for the fairness assignment and role-claim hashes.
pub const FAIRNESS_DOMAIN_V1: &[u8] = b"IRIUM_POAWX_FAIRNESS_V1";
pub const ROLE_CLAIM_DOMAIN_V1: &[u8] = b"IRIUM_POAWX_ROLE_CLAIM_V1";

/// Distribution thresholds over a mod-10000 reduction: 0..3399 CPU (34%),
/// 3400..6699 GPU (33%), 6700..9999 ASIC (33%).
pub const FAIRNESS_CPU_UPPER: u32 = 3400; // [0, 3400)
pub const FAIRNESS_GPU_UPPER: u32 = 6700; // [3400, 6700) ; [6700, 10000) = ASIC

/// Deterministic, independently-verifiable assignment digest for a role slot.
/// `H(FAIRNESS_DOMAIN_V1 || network_id || height_le8 || prev_hash || role_id || slot_index_le4)`.
pub fn fairness_assignment_digest(
    network_id: u8,
    height: u64,
    prev_hash: &[u8; 32],
    role_id: u8,
    slot_index: u32,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(FAIRNESS_DOMAIN_V1);
    h.update([network_id]);
    h.update(height.to_le_bytes());
    h.update(prev_hash);
    h.update([role_id]);
    h.update(slot_index.to_le_bytes());
    h.finalize().into()
}

/// Deterministically assign a production lane (CPU/GPU/ASIC) for a role slot.
/// Reduces the assignment digest mod 10000 and maps to the 34/33/33 bands.
/// Never returns UniversalFallback (that lane is dev/test-only).
pub fn assign_lane(
    network_id: u8,
    height: u64,
    prev_hash: &[u8; 32],
    role_id: u8,
    slot_index: u32,
) -> PoawxLane {
    let d = fairness_assignment_digest(network_id, height, prev_hash, role_id, slot_index);
    // Unbiased-enough deterministic reduction: first 8 bytes LE mod 10000.
    let v = (u64::from_le_bytes(d[0..8].try_into().expect("len 8")) % 10_000) as u32;
    if v < FAIRNESS_CPU_UPPER {
        PoawxLane::CpuFriendly
    } else if v < FAIRNESS_GPU_UPPER {
        PoawxLane::GpuParallel
    } else {
        PoawxLane::AsicStreaming
    }
}

/// Claim digest binding the revealed fields:
/// `H(ROLE_CLAIM_DOMAIN_V1 || network_id || height_le8 || prev_hash || role_id ||
///    lane_id || solver_pkh || nonce || secret)`.
#[allow(clippy::too_many_arguments)]
pub fn role_claim_digest(
    network_id: u8,
    height: u64,
    prev_hash: &[u8; 32],
    role_id: u8,
    lane_id: u8,
    solver_pkh: &[u8; 20],
    nonce: &[u8; 32],
    secret: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ROLE_CLAIM_DOMAIN_V1);
    h.update([network_id]);
    h.update(height.to_le_bytes());
    h.update(prev_hash);
    h.update([role_id]);
    h.update([lane_id]);
    h.update(solver_pkh);
    h.update(nonce);
    h.update(secret);
    h.finalize().into()
}

/// A revealed role claim. `commitment_hash` is an OPTIONAL pre-commitment
/// (`H(secret || nonce)`); see the design-gap doc — without a prior on-chain
/// commitment root the protocol cannot yet prove the commitment existed before
/// the assignment seed (`prev_hash`) was known, so hidden-precommit enforcement
/// is PARTIAL (documented).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoawxRoleClaim {
    pub role_id: u8,
    pub lane_id: u8,
    pub solver_pkh: [u8; 20],
    pub nonce: [u8; 32],
    pub secret: [u8; 32],
    pub claim_digest: [u8; 32],
    pub commitment_hash: Option<[u8; 32]>,
}

impl PoawxRoleClaim {
    /// Fixed prefix size (without the optional commitment): 1+1+20+32+32+32 = 118.
    pub const FIXED_SIZE: usize = 1 + 1 + 20 + 32 + 32 + 32;

    /// Wire: fixed prefix, then 1 flag byte (0/1), then 32-byte commitment iff flag=1.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::FIXED_SIZE + 1 + 32);
        out.push(self.role_id);
        out.push(self.lane_id);
        out.extend_from_slice(&self.solver_pkh);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.secret);
        out.extend_from_slice(&self.claim_digest);
        match &self.commitment_hash {
            Some(c) => {
                out.push(1);
                out.extend_from_slice(c);
            }
            None => out.push(0),
        }
        out
    }

    pub fn deserialize(raw: &[u8]) -> Result<Self, String> {
        if raw.len() < Self::FIXED_SIZE + 1 {
            return Err(format!(
                "role claim too short: {} < {}",
                raw.len(),
                Self::FIXED_SIZE + 1
            ));
        }
        let mut off = 0usize;
        let role_id = raw[off];
        off += 1;
        let lane_id = raw[off];
        off += 1;
        let mut solver_pkh = [0u8; 20];
        solver_pkh.copy_from_slice(&raw[off..off + 20]);
        off += 20;
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&raw[off..off + 32]);
        off += 32;
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&raw[off..off + 32]);
        off += 32;
        let mut claim_digest = [0u8; 32];
        claim_digest.copy_from_slice(&raw[off..off + 32]);
        off += 32;
        let flag = raw[off];
        off += 1;
        let commitment_hash = match flag {
            0 => None,
            1 => {
                if raw.len() < off + 32 {
                    return Err("role claim: commitment flag set but bytes truncated".to_string());
                }
                let mut c = [0u8; 32];
                c.copy_from_slice(&raw[off..off + 32]);
                off += 32;
                Some(c)
            }
            other => return Err(format!("role claim: bad commitment flag {}", other)),
        };
        // Fix D: reject any trailing bytes (exact wire-length match) so two distinct
        // encodings cannot deserialize to the same claim (consensus malleability).
        if off != raw.len() {
            return Err(format!(
                "role claim: trailing bytes ({} parsed, {} given)",
                off,
                raw.len()
            ));
        }
        Ok(Self {
            role_id,
            lane_id,
            solver_pkh,
            nonce,
            secret,
            claim_digest,
            commitment_hash,
        })
    }
}

/// Validate a revealed role claim against the deterministic assignment (pure).
/// Checks: role id known, lane id known (production lane), claim digest recomputes
/// from revealed fields, and the assigned lane for `(network, height, prev_hash,
/// role, slot)` equals the claimed lane. Does NOT enforce hidden-precommit (see
/// design-gap doc — needs a future on-chain commitment root).
pub fn validate_role_claim(
    claim: &PoawxRoleClaim,
    network_id: u8,
    height: u64,
    prev_hash: &[u8; 32],
    slot_index: u32,
) -> Result<(), String> {
    let role = PoawxRoleSlot::from_id(claim.role_id)
        .ok_or_else(|| format!("role claim: unknown role id {}", claim.role_id))?;
    let lane = PoawxLane::from_id(claim.lane_id)
        .ok_or_else(|| format!("role claim: unknown lane id {}", claim.lane_id))?;
    if !lane.is_fairness_lane() {
        return Err("role claim: lane is not a production fairness lane".to_string());
    }
    // Recompute the claim digest from the revealed fields.
    let expect = role_claim_digest(
        network_id,
        height,
        prev_hash,
        claim.role_id,
        claim.lane_id,
        &claim.solver_pkh,
        &claim.nonce,
        &claim.secret,
    );
    if expect != claim.claim_digest {
        return Err("role claim: digest does not verify from revealed fields".to_string());
    }
    // The claimed lane must equal the deterministic assignment for this slot.
    let assigned = assign_lane(network_id, height, prev_hash, role.id(), slot_index);
    if assigned != lane {
        return Err(format!(
            "role claim: lane {} != assigned lane {} for role {} slot {}",
            claim.lane_id,
            assigned.id(),
            claim.role_id,
            slot_index
        ));
    }
    Ok(())
}

// ── Phase 20 Step 6A: hidden role-precommit commitment root ──────────────────
//
// Anti-fabrication for fairness role claims: a claim revealed in block H must have
// been pre-committed in block H-1. Block H-1's `Phase20ReceiptExt.precommit_root`
// is the SHA256-over-sorted-leaves root committing block H's role-claim leaves.
// Each leaf binds (network, target_height, role, solver_pkh, commitment_hash),
// where `commitment_hash = H(COMMIT_DOMAIN || secret || nonce)` HIDES the revealed
// secret/nonce until block H. At reveal, the secret/nonce reconstruct the
// commitment, the leaf reconstructs, and the sorted root must equal the parent's
// committed root — so a miner cannot invent a claim only at reveal time.
//
// The lane is deliberately NOT in the leaf: the lane is `assign_lane(hash(H-1))`,
// which is unknowable when the precommit is placed in H-1 (it depends on H-1's own
// hash). The lane is non-grindable (deterministic from the assignment) and is
// enforced at reveal by `validate_role_claim`, so binding height/role/solver/secret
// in the precommit is the meaningful anti-fabrication property. (A lane-bound
// variant would need a grandparent-shifted assignment; deferred.)
pub const ROLE_PRECOMMIT_DOMAIN_V1: &[u8] = b"IRIUM_POAWX_ROLE_PRECOMMIT_V1";
pub const ROLE_PRECOMMIT_COMMIT_DOMAIN_V1: &[u8] = b"IRIUM_POAWX_ROLE_PRECOMMIT_COMMIT_V1";

/// Hiding commitment to a role claim's revealed secret + nonce:
/// `H(COMMIT_DOMAIN || secret || nonce)`. Stored in `PoawxRoleClaim.commitment_hash`
/// before reveal; recomputed from the revealed `secret`/`nonce` at reveal time.
pub fn role_precommit_commitment(secret: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ROLE_PRECOMMIT_COMMIT_DOMAIN_V1);
    h.update(secret);
    h.update(nonce);
    h.finalize().into()
}

/// Deterministic precommit leaf binding the pre-committable claim identity:
/// `H(PRECOMMIT_DOMAIN || network_id || target_height_le8 || role_id || solver_pkh
///    || commitment_hash)`. Replaying to another height/network/role/solver, or a
/// different `commitment_hash` (different secret/nonce), yields a different leaf.
pub fn role_precommit_leaf(
    network_id: u8,
    target_height: u64,
    role_id: u8,
    solver_pkh: &[u8; 20],
    commitment_hash: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ROLE_PRECOMMIT_DOMAIN_V1);
    h.update([network_id]);
    h.update(target_height.to_le_bytes());
    h.update([role_id]);
    h.update(solver_pkh);
    h.update(commitment_hash);
    h.finalize().into()
}

/// SHA256 over the canonically-sorted leaves (order-independent), matching the
/// receipts-root style used elsewhere. Empty leaf set => SHA256 of nothing.
pub fn role_precommit_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    let mut sorted: Vec<[u8; 32]> = leaves.to_vec();
    sorted.sort_unstable();
    let mut h = Sha256::new();
    for l in &sorted {
        h.update(l);
    }
    h.finalize().into()
}

/// Validate a revealed claim's hidden-precommit binding and return its leaf:
/// the claim MUST carry `commitment_hash == role_precommit_commitment(secret,nonce)`
/// (so a mutated secret/nonce fails closed), then the leaf is reconstructed for
/// `(network_id, target_height, role_id, solver_pkh, commitment_hash)`.
pub fn role_precommit_leaf_for_claim(
    claim: &PoawxRoleClaim,
    network_id: u8,
    target_height: u64,
) -> Result<[u8; 32], String> {
    let commitment = claim
        .commitment_hash
        .ok_or_else(|| "role precommit: claim missing commitment_hash".to_string())?;
    let expect = role_precommit_commitment(&claim.secret, &claim.nonce);
    if expect != commitment {
        return Err(
            "role precommit: commitment_hash != H(secret||nonce) (mutated reveal)".to_string(),
        );
    }
    Ok(role_precommit_leaf(
        network_id,
        target_height,
        claim.role_id,
        &claim.solver_pkh,
        &commitment,
    ))
}

// ── Phase 20: production receipt extension (carries the role/fee payout data) ──
//
// `Phase20ReceiptExt` is the versioned block-receipt extension that travels with a
// Phase 20 production block after activation. It carries the three revealed role
// claims, the RoleReward payout pkhs, the (signed) third-party fee terms, and
// (Step 6A) the optional `precommit_root` committing the NEXT block's role-claim
// leaves. Encoded only when present, so pre-activation receipt v1/v2 encoding stays
// byte-identical; the precommit_root is a trailing-optional field so pre-Step-6A
// Phase 20 exts remain byte-identical too.
pub const PHASE20_EXT_VERSION: u8 = 1;

/// Phase 31: 4-byte trailing-section magic for the proposer VRF assignment.
pub const PROPOSER_SECTION_MAGIC: &[u8; 4] = b"PRP1";
/// Wire size of a `ProposerAssignmentV1`: round(4) + AssignmentProofV2(273).
pub const PROPOSER_ASSIGNMENT_V1_WIRE: usize = 4 + ASSIGNMENT_PROOF_V2_WIRE;

/// Phase 31: the block's VRF-proposer assignment — the proposer's ECVRF proof
/// (role = ROLE_PROPOSER, bound to the epoch seed) plus the cascade `round` it
/// claims. The block's `worker_pkh` IS the proposer (`proof.solver_pkh == worker_pkh`,
/// enforced in connect_block under the gate). Mainnet hard-off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposerAssignmentV1 {
    pub round: u32,
    pub proof: AssignmentProofV2,
}

impl ProposerAssignmentV1 {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PROPOSER_ASSIGNMENT_V1_WIRE);
        out.extend_from_slice(&self.round.to_le_bytes());
        out.extend_from_slice(&self.proof.serialize());
        out
    }

    pub fn deserialize(raw: &[u8]) -> Result<Self, String> {
        if raw.len() != PROPOSER_ASSIGNMENT_V1_WIRE {
            return Err(format!(
                "proposer assignment: bad wire len {} (want {})",
                raw.len(),
                PROPOSER_ASSIGNMENT_V1_WIRE
            ));
        }
        let round = u32::from_le_bytes(raw[0..4].try_into().expect("len 4"));
        let proof = AssignmentProofV2::deserialize(&raw[4..4 + ASSIGNMENT_PROOF_V2_WIRE])?;
        Ok(Self { round, proof })
    }
}

/// Phase 31R: wire size of a `ProposerRegistrationV1`:
/// vrf_pubkey(33) + anchor_height(8) + sybil_nonce(32) + sybil_digest(32) + signature(64).
pub const PROPOSER_REGISTRATION_V1_WIRE: usize = 33 + 8 + 32 + 32 + 64;
/// Domain separator for the registration self-signature.
pub const PROPOSER_REG_SIGN_DOMAIN: &[u8] = b"IRIUM_POAWX_PROPOSER_REG_V1";

/// HASH160 of a compressed secp256k1 public key.
fn reg_hash160(pk: &[u8; 33]) -> [u8; 20] {
    let rip = ripemd::Ripemd160::digest(Sha256::digest(pk));
    let mut out = [0u8; 20];
    out.copy_from_slice(&rip);
    out
}

/// Phase 31R: an on-chain proposer-VRF key registration. Lets a miner register its
/// proposer key WITHOUT first winning a block (fixes the eligibility chicken-and-egg),
/// paying a one-time sybil PoW cost bound to a recent anchor block + the key itself.
/// `pkh = hash160(vrf_pubkey)` is derived. Carried in the `PRG1` block section and,
/// once activated off the FIFO queue, registered into the eligibility registry at the
/// activation height (eligible `FREEZE_DEPTH` blocks later). Mainnet hard-off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposerRegistrationV1 {
    pub vrf_pubkey: [u8; 33],
    pub anchor_height: u64,
    pub sybil_nonce: [u8; 32],
    pub sybil_digest: [u8; 32],
    pub signature: [u8; 64],
}

impl ProposerRegistrationV1 {
    pub fn pkh(&self) -> [u8; 20] {
        reg_hash160(&self.vrf_pubkey)
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PROPOSER_REGISTRATION_V1_WIRE);
        out.extend_from_slice(&self.vrf_pubkey);
        out.extend_from_slice(&self.anchor_height.to_le_bytes());
        out.extend_from_slice(&self.sybil_nonce);
        out.extend_from_slice(&self.sybil_digest);
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn deserialize(raw: &[u8]) -> Result<Self, String> {
        if raw.len() != PROPOSER_REGISTRATION_V1_WIRE {
            return Err(format!(
                "proposer registration: bad wire len {} (want {})",
                raw.len(),
                PROPOSER_REGISTRATION_V1_WIRE
            ));
        }
        let mut vrf_pubkey = [0u8; 33];
        vrf_pubkey.copy_from_slice(&raw[0..33]);
        let anchor_height = u64::from_le_bytes(raw[33..41].try_into().expect("len 8"));
        let mut sybil_nonce = [0u8; 32];
        sybil_nonce.copy_from_slice(&raw[41..73]);
        let mut sybil_digest = [0u8; 32];
        sybil_digest.copy_from_slice(&raw[73..105]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&raw[105..169]);
        Ok(Self {
            vrf_pubkey,
            anchor_height,
            sybil_nonce,
            sybil_digest,
            signature,
        })
    }

    /// Domain-separated digest the self-signature covers (binds every field).
    pub fn signing_digest(&self, network_id: u8) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(PROPOSER_REG_SIGN_DOMAIN);
        h.update([network_id]);
        h.update(self.vrf_pubkey);
        h.update(self.anchor_height.to_le_bytes());
        h.update(self.sybil_nonce);
        h.update(self.sybil_digest);
        h.finalize().into()
    }

    /// Pure self-validation given the resolved `anchor_hash` (chain[anchor_height])
    /// and the required sybil bits. Does NOT check anchor recency/canonicity — the
    /// connect_block gate does that. Mainnet hard-off is enforced by the caller.
    pub fn validate(
        &self,
        network_id: u8,
        anchor_hash: &[u8; 32],
        required_bits: u32,
    ) -> Result<(), String> {
        let pkh = self.pkh();
        let expect = crate::poawx_ticket::compute_sybil_digest(
            network_id,
            anchor_hash,
            &pkh,
            self.anchor_height,
            &self.vrf_pubkey,
            &self.sybil_nonce,
        );
        if self.sybil_digest != expect {
            return Err("registration: sybil_digest mismatch".to_string());
        }
        if !crate::poawx_ticket::meets_sybil_target(&self.sybil_digest, required_bits) {
            return Err("registration: insufficient sybil work".to_string());
        }
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        use k256::ecdsa::{Signature, VerifyingKey};
        let vk = VerifyingKey::from_sec1_bytes(&self.vrf_pubkey)
            .map_err(|_| "registration: invalid vrf_pubkey".to_string())?;
        let sig = Signature::from_slice(&self.signature)
            .map_err(|_| "registration: malformed signature".to_string())?;
        vk.verify_prehash(&self.signing_digest(network_id), &sig)
            .map_err(|_| "registration: signature verification failed".to_string())?;
        Ok(())
    }

    /// Build + grind + self-sign a registration for `secret` against a recent anchor.
    /// Used by the miner and tests. Derives `vrf_pubkey` from `secret` (k256), grinds
    /// `sybil_nonce` until the digest meets `required_bits`, then signs.
    pub fn build_signed(
        secret: &[u8; 32],
        network_id: u8,
        anchor_height: u64,
        anchor_hash: &[u8; 32],
        required_bits: u32,
    ) -> Result<Self, String> {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        let sk = k256::ecdsa::SigningKey::from_slice(secret)
            .map_err(|_| "registration: invalid secret".to_string())?;
        let vk = sk.verifying_key();
        let pt = vk.to_encoded_point(true);
        let mut vrf_pubkey = [0u8; 33];
        vrf_pubkey.copy_from_slice(pt.as_bytes());
        let pkh = reg_hash160(&vrf_pubkey);
        let mut nonce = [0u8; 32];
        let mut counter: u64 = 0;
        let sybil_digest = loop {
            nonce[..8].copy_from_slice(&counter.to_le_bytes());
            let d = crate::poawx_ticket::compute_sybil_digest(
                network_id,
                anchor_hash,
                &pkh,
                anchor_height,
                &vrf_pubkey,
                &nonce,
            );
            if crate::poawx_ticket::meets_sybil_target(&d, required_bits) {
                break d;
            }
            counter += 1;
            if counter > 200_000_000 {
                return Err("registration: sybil grind exceeded budget".to_string());
            }
        };
        let mut me = Self {
            vrf_pubkey,
            anchor_height,
            sybil_nonce: nonce,
            sybil_digest,
            signature: [0u8; 64],
        };
        let sig: k256::ecdsa::Signature = sk
            .sign_prehash(&me.signing_digest(network_id))
            .map_err(|_| "registration: signing failed".to_string())?;
        me.signature.copy_from_slice(&sig.to_bytes());
        Ok(me)
    }

    /// Verify only the self-signature over the signing digest (cheap; no anchor/sybil
    /// binding). Used for light gossip-ingest filtering; connect_block does the full
    /// anchor-bound validation.
    pub fn signature_ok(&self, network_id: u8) -> bool {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        use k256::ecdsa::{Signature, VerifyingKey};
        let vk = match VerifyingKey::from_sec1_bytes(&self.vrf_pubkey) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let sig = match Signature::from_slice(&self.signature) {
            Ok(s) => s,
            Err(_) => return false,
        };
        vk.verify_prehash(&self.signing_digest(network_id), &sig).is_ok()
    }
}

/// Phase 31R: 4-byte trailing-section magic for proposer registrations.
pub const PROPOSER_REG_SECTION_MAGIC: &[u8; 4] = b"PRG1";

/// Phase 31R: the block's proposer-registration section. `announces` are NEW
/// registrations the producer enqueues onto the on-chain FIFO queue (best-effort from
/// its gossip pool); `activations` are the registrations force-drained from the queue
/// head this block (must equal the deterministic head up to PROPOSER_REG_CAP, checked
/// in connect_block). Absent (None) => byte-identical to pre-Phase-31R exts.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProposerRegistrationSection {
    pub announces: Vec<ProposerRegistrationV1>,
    pub activations: Vec<ProposerRegistrationV1>,
}

impl ProposerRegistrationSection {
    pub fn is_empty(&self) -> bool {
        self.announces.is_empty() && self.activations.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Phase20ReceiptExt {
    pub role_reward: RoleReward,
    pub compute_claim: PoawxRoleClaim,
    pub verify_claim: PoawxRoleClaim,
    pub support_claim: PoawxRoleClaim,
    /// Third-party fee terms (must match the signed delegation). `fee_bps==0` => official.
    pub fee_bps: u16,
    pub fee_pkh: [u8; 20],
    /// Phase 20 Step 6A: optional hidden-precommit root committing the NEXT block's
    /// role-claim leaves. `None` => absent (pre-Step-6A; trailing-optional so older
    /// Phase 20 exts stay byte-identical). After hidden-precommit activation this is
    /// required on every production block.
    pub precommit_root: Option<[u8; 32]>,
    /// Phase 21B: optional per-role ticket proofs (compute/verify/support) bound
    /// to this block/height. `None` => absent (trailing ticket section omitted, so
    /// pre-Step-21B exts stay byte-identical). Required on every production block
    /// when the ticket gate is enabled (validated in connect_block).
    pub role_ticket_proofs: Option<[TicketProof; 3]>,
    /// Phase 21C: optional per-role anti-domination fairness weights
    /// [PRIMARY, COMPUTE, VERIFY, SUPPORT]. `None` => absent (trailing DOM1
    /// section omitted, byte-identical to pre-21C exts). Required + validated
    /// against persisted dominance state in connect_block when the
    /// anti-domination gate is enforced.
    pub role_dominance_weights: Option<[u64; 4]>,
    /// Phase 21D: optional candidate set (trailing CND1 section; None =>
    /// byte-identical to pre-21D). Carries the full canonical candidate set so
    /// the node can validate the selected role solvers are the best candidates;
    /// required + validated in connect_block when the candidate-set gate is
    /// enforced.
    pub candidate_set: Option<CandidateSet>,
    /// Phase 21F: optional per-role assigned puzzle-work solutions
    /// [compute, verify, support] (trailing PZL1 section; None => byte-identical
    /// to pre-21F). Required + validated in connect_block when the puzzle-work
    /// gate is enforced. Assigned-work proofs only; NOT chain PoW.
    pub role_puzzle_proofs: Option<[PuzzleSolutionV1; 3]>,
    /// Phase 21H: optional finality-committee proof finalizing the parent
    /// block (trailing FIN1 section; None => byte-identical to pre-21H).
    /// Required + validated in connect_block when the finality gate is enforced.
    pub finality_proof: Option<FinalityProofV1>,
    /// Phase 22A: optional chain-committed admission for the NEXT height
    /// (commit_height = this block; target = this+1) — trailing CAC1 section;
    /// None => byte-identical to pre-22A. Validated in connect_block when the
    /// committed-admission gate is enforced.
    pub committed_admission: Option<AdmissionCommitmentV1>,
    /// Phase 22D: optional per-role true-VRF assignment proofs [compute, verify,
    /// support] (trailing AVR2 section; None => byte-identical to pre-22D).
    /// Required + validated in connect_block when the true-VRF gate is enforced.
    pub role_assignment_v2: Option<[AssignmentProofV2; 3]>,
    /// Phase 26+: optional fraud proofs (trailing FRD1 section; None =>
    /// byte-identical to pre-fraud-proof exts). Each is a self-contained,
    /// deterministically-verifiable accusation (v1: finality-vote equivocation).
    /// Verified + slashing-applied in connect_block when the fraud-proof gate is
    /// enforced; reverted on disconnect. OPTIONAL even under the gate (a block
    /// with no fraud to report omits the section).
    pub fraud_proofs: Option<Vec<FraudProofV1>>,
    /// Phase 31: optional VRF-proposer assignment (trailing PRP1 section; None =>
    /// byte-identical to pre-Phase-31). Validated in connect_block under the gate.
    pub proposer_assignment: Option<ProposerAssignmentV1>,
    /// Phase 31R: optional proposer-registration section (trailing PRG1; None =>
    /// byte-identical to pre-31R). Announces enqueue, activations force-drain the
    /// FIFO queue head; validated + applied in connect_block under the gate.
    pub proposer_registrations: Option<ProposerRegistrationSection>,
}

impl Phase20ReceiptExt {
    /// Wire: version(1) || role_reward(60) || (len_u16 || claim) ×3 || fee_bps(2) ||
    /// fee_pkh(20) || [precommit flag(1) + root(32) IFF Some]. The precommit section
    /// is a TRAILING optional: when `precommit_root` is None nothing is appended, so
    /// pre-Step-6A exts serialize byte-identically.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(PHASE20_EXT_VERSION);
        out.extend_from_slice(&self.role_reward.serialize());
        for claim in [&self.compute_claim, &self.verify_claim, &self.support_claim] {
            let b = claim.serialize();
            out.extend_from_slice(&(b.len() as u16).to_le_bytes());
            out.extend_from_slice(&b);
        }
        out.extend_from_slice(&self.fee_bps.to_le_bytes());
        out.extend_from_slice(&self.fee_pkh);
        // Step 6A precommit_root (present-only) followed by the Step 21B trailing
        // ticket section (present-only). When a ticket section is present but
        // precommit_root is None, an explicit `0` precommit flag is written first so
        // the reader can unambiguously skip to the ticket magic. When both are
        // absent, nothing is appended -> byte-identical to pre-Step-21B exts.
        match &self.precommit_root {
            Some(root) => {
                out.push(1);
                out.extend_from_slice(root);
            }
            None => {
                if self.role_ticket_proofs.is_some()
                    || self.role_dominance_weights.is_some()
                    || self.candidate_set.is_some()
                    || self.role_puzzle_proofs.is_some()
                    || self.finality_proof.is_some()
                    || self.committed_admission.is_some()
                    || self.role_assignment_v2.is_some()
                    || self.fraud_proofs.is_some()
                    || self.proposer_assignment.is_some()
                    || self.proposer_registrations.is_some()
                {
                    out.push(0);
                }
            }
        }
        if let Some(proofs) = &self.role_ticket_proofs {
            out.extend_from_slice(TICKET_SECTION_MAGIC);
            for p in proofs.iter() {
                out.extend_from_slice(&p.serialize());
            }
        }
        // Phase 21C trailing dominance-weight section (present-only): magic + 4
        // role weights (LE u64). Absent => byte-identical to pre-21C exts.
        if let Some(weights) = &self.role_dominance_weights {
            out.extend_from_slice(DOMINANCE_SECTION_MAGIC);
            for w in weights.iter() {
                out.extend_from_slice(&w.to_le_bytes());
            }
        }
        // Phase 21D trailing CND1 candidate-set section (present-only): magic +
        // u32 length + canonical candidate-set bytes. Absent => byte-identical.
        if let Some(cs) = &self.candidate_set {
            let body = cs.serialize();
            out.extend_from_slice(CANDIDATE_SECTION_MAGIC);
            out.extend_from_slice(&(body.len() as u32).to_le_bytes());
            out.extend_from_slice(&body);
        }
        // Phase 21F trailing PZL1 puzzle-solution section (present-only): magic +
        // 3 fixed solutions. Absent => byte-identical to pre-21F exts.
        if let Some(sols) = &self.role_puzzle_proofs {
            out.extend_from_slice(PUZZLE_SECTION_MAGIC);
            for sol in sols.iter() {
                out.extend_from_slice(&sol.serialize());
            }
        }
        // Phase 21H trailing FIN1 finality-proof section (present-only): magic +
        // u32 length + finality-proof bytes. Absent => byte-identical to pre-21H.
        if let Some(fp) = &self.finality_proof {
            let body = fp.serialize();
            out.extend_from_slice(FINALITY_SECTION_MAGIC);
            out.extend_from_slice(&(body.len() as u32).to_le_bytes());
            out.extend_from_slice(&body);
        }
        // Phase 22A trailing CAC1 committed-admission section (present-only,
        // fixed-size). Absent => byte-identical to pre-22A exts.
        if let Some(ca) = &self.committed_admission {
            out.extend_from_slice(COMMITTED_ADMISSION_SECTION_MAGIC);
            out.extend_from_slice(&ca.serialize());
        }
        // Phase 22D trailing AVR2 true-VRF section (present-only): magic + 3 fixed
        // V2 proofs. Absent => byte-identical to pre-22D exts.
        if let Some(proofs) = &self.role_assignment_v2 {
            out.extend_from_slice(ASSIGNMENT_V2_SECTION_MAGIC);
            for pr in proofs.iter() {
                out.extend_from_slice(&pr.serialize());
            }
        }
        // Phase 26+ trailing FRD1 fraud-proof section (present-only): magic +
        // u16 count + count × fixed proofs. Absent => byte-identical to pre-FRD1.
        if let Some(proofs) = &self.fraud_proofs {
            out.extend_from_slice(FRAUD_PROOF_SECTION_MAGIC);
            out.extend_from_slice(&(proofs.len() as u16).to_le_bytes());
            for fp in proofs.iter() {
                out.extend_from_slice(&fp.serialize());
            }
        }
        // Phase 31 trailing PRP1 proposer-assignment section (present-only): magic +
        // round(4) + V2 proof. Absent => byte-identical to pre-Phase-31 exts.
        if let Some(pa) = &self.proposer_assignment {
            out.extend_from_slice(PROPOSER_SECTION_MAGIC);
            out.extend_from_slice(&pa.serialize());
        }
        // Phase 31R trailing PRG1 proposer-registration section (present-only):
        // magic + u16 announce_count + announces + u16 activation_count + activations.
        if let Some(reg) = &self.proposer_registrations {
            out.extend_from_slice(PROPOSER_REG_SECTION_MAGIC);
            out.extend_from_slice(&(reg.announces.len() as u16).to_le_bytes());
            for r in &reg.announces {
                out.extend_from_slice(&r.serialize());
            }
            out.extend_from_slice(&(reg.activations.len() as u16).to_le_bytes());
            for r in &reg.activations {
                out.extend_from_slice(&r.serialize());
            }
        }
        out
    }

    pub fn deserialize(raw: &[u8]) -> Result<Self, String> {
        let mut off = 0usize;
        let need = |off: usize, n: usize, what: &str| -> Result<(), String> {
            if raw.len() < off + n {
                Err(format!("phase20 ext: truncated reading {}", what))
            } else {
                Ok(())
            }
        };
        need(off, 1, "version")?;
        if raw[off] != PHASE20_EXT_VERSION {
            return Err(format!("phase20 ext: unknown version {}", raw[off]));
        }
        off += 1;
        need(off, RoleReward::WIRE_SIZE, "role_reward")?;
        let role_reward = RoleReward::deserialize(&raw[off..off + RoleReward::WIRE_SIZE])?;
        off += RoleReward::WIRE_SIZE;
        let read_claim = |off: &mut usize| -> Result<PoawxRoleClaim, String> {
            need(*off, 2, "claim len")?;
            let len = u16::from_le_bytes(raw[*off..*off + 2].try_into().expect("len 2")) as usize;
            *off += 2;
            need(*off, len, "claim body")?;
            let c = PoawxRoleClaim::deserialize(&raw[*off..*off + len])?;
            *off += len;
            Ok(c)
        };
        let compute_claim = read_claim(&mut off)?;
        let verify_claim = read_claim(&mut off)?;
        let support_claim = read_claim(&mut off)?;
        need(off, 2, "fee_bps")?;
        let fee_bps = u16::from_le_bytes(raw[off..off + 2].try_into().expect("len 2"));
        off += 2;
        need(off, 20, "fee_pkh")?;
        let mut fee_pkh = [0u8; 20];
        fee_pkh.copy_from_slice(&raw[off..off + 20]);
        off += 20;
        // Step 6A trailing-optional precommit_root: present iff there are more bytes.
        let precommit_root = if off < raw.len() {
            let flag = raw[off];
            off += 1;
            match flag {
                0 => None,
                1 => {
                    need(off, 32, "precommit_root")?;
                    let mut r = [0u8; 32];
                    r.copy_from_slice(&raw[off..off + 32]);
                    off += 32;
                    Some(r)
                }
                other => return Err(format!("phase20 ext: bad precommit flag {}", other)),
            }
        } else {
            None
        };
        // Trailing magic-prefixed sections (present-only, strict): the Step 21B
        // ticket section and the Phase 21C dominance-weight section, in any
        // order. An unrecognized or truncated trailing magic is rejected (same
        // strictness as pre-21C). Absent => byte-identical to the pre-section ext.
        let mut role_ticket_proofs: Option<[TicketProof; 3]> = None;
        let mut role_dominance_weights: Option<[u64; 4]> = None;
        let mut candidate_set: Option<CandidateSet> = None;
        let mut role_puzzle_proofs: Option<[PuzzleSolutionV1; 3]> = None;
        let mut finality_proof: Option<FinalityProofV1> = None;
        let mut committed_admission: Option<AdmissionCommitmentV1> = None;
        let mut role_assignment_v2: Option<[AssignmentProofV2; 3]> = None;
        let mut fraud_proofs: Option<Vec<FraudProofV1>> = None;
        let mut proposer_assignment: Option<ProposerAssignmentV1> = None;
        let mut proposer_registrations: Option<ProposerRegistrationSection> = None;
        while off < raw.len() {
            need(off, 4, "trailing section magic")?;
            let magic = &raw[off..off + 4];
            if magic == TICKET_SECTION_MAGIC {
                if role_ticket_proofs.is_some() {
                    return Err("phase20 ext: duplicate ticket section".to_string());
                }
                off += 4;
                let mut proofs: Vec<TicketProof> = Vec::with_capacity(3);
                for _ in 0..3 {
                    need(off, TICKET_PROOF_WIRE, "ticket proof")?;
                    proofs.push(TicketProof::deserialize(
                        &raw[off..off + TICKET_PROOF_WIRE],
                    )?);
                    off += TICKET_PROOF_WIRE;
                }
                role_ticket_proofs =
                    Some([proofs[0].clone(), proofs[1].clone(), proofs[2].clone()]);
            } else if magic == DOMINANCE_SECTION_MAGIC {
                if role_dominance_weights.is_some() {
                    return Err("phase20 ext: duplicate dominance section".to_string());
                }
                off += 4;
                need(off, DOMINANCE_WEIGHTS_WIRE, "dominance weights")?;
                let mut w = [0u64; 4];
                for slot in w.iter_mut() {
                    let mut b = [0u8; 8];
                    b.copy_from_slice(&raw[off..off + 8]);
                    *slot = u64::from_le_bytes(b);
                    off += 8;
                }
                role_dominance_weights = Some(w);
            } else if magic == CANDIDATE_SECTION_MAGIC {
                if candidate_set.is_some() {
                    return Err("phase20 ext: duplicate candidate section".to_string());
                }
                off += 4;
                need(off, 4, "candidate section length")?;
                let len = u32::from_le_bytes(raw[off..off + 4].try_into().expect("len 4")) as usize;
                off += 4;
                need(off, len, "candidate section body")?;
                candidate_set = Some(CandidateSet::deserialize(&raw[off..off + len])?);
                off += len;
            } else if magic == PUZZLE_SECTION_MAGIC {
                if role_puzzle_proofs.is_some() {
                    return Err("phase20 ext: duplicate puzzle section".to_string());
                }
                off += 4;
                let mut sols: Vec<PuzzleSolutionV1> = Vec::with_capacity(3);
                for _ in 0..3 {
                    need(off, PUZZLE_SOLUTION_WIRE, "puzzle solution")?;
                    sols.push(PuzzleSolutionV1::deserialize(
                        &raw[off..off + PUZZLE_SOLUTION_WIRE],
                    )?);
                    off += PUZZLE_SOLUTION_WIRE;
                }
                role_puzzle_proofs = Some([sols[0], sols[1], sols[2]]);
            } else if magic == FINALITY_SECTION_MAGIC {
                if finality_proof.is_some() {
                    return Err("phase20 ext: duplicate finality section".to_string());
                }
                off += 4;
                need(off, 4, "finality section length")?;
                let len = u32::from_le_bytes(raw[off..off + 4].try_into().expect("len 4")) as usize;
                off += 4;
                need(off, len, "finality section body")?;
                finality_proof = Some(FinalityProofV1::deserialize(&raw[off..off + len])?);
                off += len;
            } else if magic == COMMITTED_ADMISSION_SECTION_MAGIC {
                if committed_admission.is_some() {
                    return Err("phase20 ext: duplicate committed-admission section".to_string());
                }
                off += 4;
                need(off, ADMISSION_COMMITMENT_WIRE, "committed admission")?;
                committed_admission = Some(AdmissionCommitmentV1::deserialize(
                    &raw[off..off + ADMISSION_COMMITMENT_WIRE],
                )?);
                off += ADMISSION_COMMITMENT_WIRE;
            } else if magic == ASSIGNMENT_V2_SECTION_MAGIC {
                if role_assignment_v2.is_some() {
                    return Err("phase20 ext: duplicate true-vrf section".to_string());
                }
                off += 4;
                let mut ps: Vec<AssignmentProofV2> = Vec::with_capacity(3);
                for _ in 0..3 {
                    need(off, ASSIGNMENT_PROOF_V2_WIRE, "v2 assignment proof")?;
                    ps.push(AssignmentProofV2::deserialize(
                        &raw[off..off + ASSIGNMENT_PROOF_V2_WIRE],
                    )?);
                    off += ASSIGNMENT_PROOF_V2_WIRE;
                }
                role_assignment_v2 = Some([ps[0].clone(), ps[1].clone(), ps[2].clone()]);
            } else if magic == FRAUD_PROOF_SECTION_MAGIC {
                if fraud_proofs.is_some() {
                    return Err("phase20 ext: duplicate fraud-proof section".to_string());
                }
                off += 4;
                need(off, 2, "fraud-proof count")?;
                let count = u16::from_le_bytes(raw[off..off + 2].try_into().expect("len 2")) as usize;
                off += 2;
                if count == 0 || count > FRAUD_PROOF_MAX_PER_BLOCK {
                    return Err("phase20 ext: fraud-proof count out of range".to_string());
                }
                let mut fps: Vec<FraudProofV1> = Vec::with_capacity(count);
                for _ in 0..count {
                    need(off, FRAUD_PROOF_V1_WIRE, "fraud proof")?;
                    fps.push(FraudProofV1::deserialize(&raw[off..off + FRAUD_PROOF_V1_WIRE])?);
                    off += FRAUD_PROOF_V1_WIRE;
                }
                fraud_proofs = Some(fps);
            } else if magic == PROPOSER_SECTION_MAGIC {
                if proposer_assignment.is_some() {
                    return Err("phase20 ext: duplicate proposer section".to_string());
                }
                off += 4;
                need(off, PROPOSER_ASSIGNMENT_V1_WIRE, "proposer assignment")?;
                proposer_assignment = Some(ProposerAssignmentV1::deserialize(
                    &raw[off..off + PROPOSER_ASSIGNMENT_V1_WIRE],
                )?);
                off += PROPOSER_ASSIGNMENT_V1_WIRE;
            } else if magic == PROPOSER_REG_SECTION_MAGIC {
                if proposer_registrations.is_some() {
                    return Err("phase20 ext: duplicate proposer registration section".to_string());
                }
                off += 4;
                need(off, 2, "registration announce count")?;
                let ac =
                    u16::from_le_bytes(raw[off..off + 2].try_into().expect("len 2")) as usize;
                off += 2;
                if ac > crate::poawx_proposer::PROPOSER_ANNOUNCE_CAP {
                    return Err("phase20 ext: registration announce count over cap".to_string());
                }
                let mut announces = Vec::with_capacity(ac);
                for _ in 0..ac {
                    need(off, PROPOSER_REGISTRATION_V1_WIRE, "registration announce")?;
                    announces.push(ProposerRegistrationV1::deserialize(
                        &raw[off..off + PROPOSER_REGISTRATION_V1_WIRE],
                    )?);
                    off += PROPOSER_REGISTRATION_V1_WIRE;
                }
                need(off, 2, "registration activation count")?;
                let cc =
                    u16::from_le_bytes(raw[off..off + 2].try_into().expect("len 2")) as usize;
                off += 2;
                if cc > crate::poawx_proposer::PROPOSER_REG_CAP {
                    return Err("phase20 ext: registration activation count over cap".to_string());
                }
                let mut activations = Vec::with_capacity(cc);
                for _ in 0..cc {
                    need(off, PROPOSER_REGISTRATION_V1_WIRE, "registration activation")?;
                    activations.push(ProposerRegistrationV1::deserialize(
                        &raw[off..off + PROPOSER_REGISTRATION_V1_WIRE],
                    )?);
                    off += PROPOSER_REGISTRATION_V1_WIRE;
                }
                proposer_registrations = Some(ProposerRegistrationSection {
                    announces,
                    activations,
                });
            } else {
                return Err("phase20 ext: unknown trailing section magic".to_string());
            }
        }
        Ok(Self {
            role_reward,
            compute_claim,
            verify_claim,
            support_claim,
            fee_bps,
            fee_pkh,
            precommit_root,
            role_ticket_proofs,
            role_dominance_weights,
            candidate_set,
            role_puzzle_proofs,
            finality_proof,
            committed_admission,
            role_assignment_v2,
            fraud_proofs,
            proposer_assignment,
            proposer_registrations,
        })
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.serialize());
        h.finalize().into()
    }
}

/// Per-receipt data embedded in the block wire/storage format so that every
/// node can validate PoAW-X receipts from block-contained data (Phase 13-A).
/// All multi-byte integers are little-endian.
#[derive(Debug, Clone, PartialEq)]
pub struct PoawxBlockReceipt {
    pub height: u64,
    /// Raw lane byte (e.g. `b'A'`).
    pub lane: u8,
    pub worker_pkh: [u8; 20],
    pub worker_pubkey: [u8; 33],
    pub worker_sig: [u8; 64],
    pub solution: [u8; 8],
    pub commitment_nonce: [u8; 32],
    /// Phase 18B: `None` => mode-0 (direct miner-signed; `worker_pubkey`/
    /// `worker_sig` are the miner's own). `Some` => mode-1 (delegated;
    /// `worker_pubkey`/`worker_sig` are the pool delegate's signer key, and
    /// `worker_pkh` still belongs to the miner = payout identity).
    pub delegation: Option<Delegation>,
    /// Phase 20: optional production payout extension (role claims + RoleReward +
    /// fee terms). `None` => no extension (v1/v2 encoding, byte-identical to
    /// Phase 13-A/18B). `Some` => the receipt section uses the v3 magic and the
    /// extension round-trips through wire/persistence/P2P/reorg. NOT enforced in
    /// Step 1 (data threading only).
    pub phase20_ext: Option<Phase20ReceiptExt>,
}

impl PoawxBlockReceipt {
    /// Fixed wire size of the legacy mode-0 element: 8 + 1 + 20 + 33 + 64 + 8 + 32 = 166 bytes.
    pub const WIRE_SIZE: usize = 8 + 1 + 20 + 33 + 64 + 8 + 32;

    /// Mode discriminator for this receipt.
    pub fn mode(&self) -> u8 {
        if self.delegation.is_some() {
            RECEIPT_MODE_DELEGATED
        } else {
            RECEIPT_MODE_DIRECT
        }
    }

    /// Phase 18B v2 element encoding: `mode(1)` followed by the legacy 166-byte
    /// payload, and (mode-1 only) the 226-byte delegation blob. Mode-0 here is
    /// the legacy payload prefixed with a single `0x00` byte.
    pub fn serialize_v2(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + Self::WIRE_SIZE + Delegation::WIRE_SIZE);
        out.push(self.mode());
        out.extend_from_slice(&self.serialize());
        if let Some(d) = &self.delegation {
            out.extend_from_slice(&d.serialize());
        }
        out
    }

    /// Parse a single v2 element, returning the receipt and the number of bytes
    /// consumed. Errors on unknown mode or truncation.
    pub fn deserialize_v2(raw: &[u8]) -> Result<(Self, usize), String> {
        if raw.is_empty() {
            return Err("poawx v2 receipt: missing mode byte".to_string());
        }
        let mode = raw[0];
        let body = &raw[1..];
        if body.len() < Self::WIRE_SIZE {
            return Err("poawx v2 receipt: legacy body truncated".to_string());
        }
        let mut receipt = Self::deserialize(body)?;
        match mode {
            RECEIPT_MODE_DIRECT => {
                receipt.delegation = None;
                Ok((receipt, 1 + Self::WIRE_SIZE))
            }
            RECEIPT_MODE_DELEGATED => {
                let deleg_start = Self::WIRE_SIZE;
                if body.len() < deleg_start + Delegation::WIRE_SIZE_V1 {
                    return Err("poawx v2 receipt: delegation truncated".to_string());
                }
                let d = Delegation::deserialize(&body[deleg_start..])?;
                let deleg_len = d.wire_len();
                receipt.delegation = Some(d);
                Ok((receipt, 1 + Self::WIRE_SIZE + deleg_len))
            }
            other => Err(format!("poawx v2 receipt: unknown mode {}", other)),
        }
    }

    /// Phase 20 v3 element: the full v2 element, then a 1-byte flag and (flag=1)
    /// a u32-LE length-prefixed `Phase20ReceiptExt`. Length-prefixed so parsing
    /// needs no knowledge of the (variable) extension size. v2 bytes are unchanged.
    pub fn serialize_v3(&self) -> Vec<u8> {
        let mut out = self.serialize_v2();
        match &self.phase20_ext {
            Some(e) => {
                let b = e.serialize();
                out.push(1);
                out.extend_from_slice(&(b.len() as u32).to_le_bytes());
                out.extend_from_slice(&b);
            }
            None => out.push(0),
        }
        out
    }

    /// Parse a single v3 element, returning the receipt and bytes consumed.
    pub fn deserialize_v3(raw: &[u8]) -> Result<(Self, usize), String> {
        let (mut receipt, mut used) = Self::deserialize_v2(raw)?;
        if raw.len() < used + 1 {
            return Err("poawx v3 receipt: missing extension flag".to_string());
        }
        let flag = raw[used];
        used += 1;
        match flag {
            0 => receipt.phase20_ext = None,
            1 => {
                if raw.len() < used + 4 {
                    return Err("poawx v3 receipt: missing extension length".to_string());
                }
                let len =
                    u32::from_le_bytes(raw[used..used + 4].try_into().expect("len 4")) as usize;
                used += 4;
                if raw.len() < used + len {
                    return Err("poawx v3 receipt: extension truncated".to_string());
                }
                let ext = Phase20ReceiptExt::deserialize(&raw[used..used + len])?;
                used += len;
                receipt.phase20_ext = Some(ext);
            }
            other => return Err(format!("poawx v3 receipt: bad extension flag {}", other)),
        }
        Ok((receipt, used))
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::WIRE_SIZE);
        out.extend_from_slice(&self.height.to_le_bytes());
        out.push(self.lane);
        out.extend_from_slice(&self.worker_pkh);
        out.extend_from_slice(&self.worker_pubkey);
        out.extend_from_slice(&self.worker_sig);
        out.extend_from_slice(&self.solution);
        out.extend_from_slice(&self.commitment_nonce);
        out
    }

    pub fn deserialize(raw: &[u8]) -> Result<Self, String> {
        if raw.len() < Self::WIRE_SIZE {
            return Err(format!(
                "poawx receipt too short: {} < {}",
                raw.len(),
                Self::WIRE_SIZE
            ));
        }
        let mut off = 0usize;
        let height = u64::from_le_bytes(raw[off..off + 8].try_into().expect("slice len checked"));
        off += 8;
        let lane = raw[off];
        off += 1;
        let mut worker_pkh = [0u8; 20];
        worker_pkh.copy_from_slice(&raw[off..off + 20]);
        off += 20;
        let mut worker_pubkey = [0u8; 33];
        worker_pubkey.copy_from_slice(&raw[off..off + 33]);
        off += 33;
        let mut worker_sig = [0u8; 64];
        worker_sig.copy_from_slice(&raw[off..off + 64]);
        off += 64;
        let mut solution = [0u8; 8];
        solution.copy_from_slice(&raw[off..off + 8]);
        off += 8;
        let mut commitment_nonce = [0u8; 32];
        commitment_nonce.copy_from_slice(&raw[off..off + 32]);
        Ok(Self {
            height,
            lane,
            worker_pkh,
            worker_pubkey,
            worker_sig,
            solution,
            commitment_nonce,
            delegation: None,
            phase20_ext: None,
        })
    }
}

/// Phase 18B: a one-time miner delegation authorizing a specific pool delegate
/// key (`pool_pubkey`) to create PoAW-X receipts paying the miner (`miner_pubkey`,
/// whose HASH160 is the receipt `worker_pkh`). Signed by the miner key over
/// `message_hash()`; the signature never contains a private key. All multi-byte
/// integers are little-endian.
#[derive(Debug, Clone, PartialEq)]
pub struct Delegation {
    pub deleg_version: u8,
    pub network_id: u8,
    pub miner_pubkey: [u8; 33],
    pub pool_pubkey: [u8; 33],
    pub worker_tag: [u8; 32],
    pub expiry_height: u64,
    pub fee_bps: u16,
    pub fee_pkh: [u8; 20],
    pub deleg_nonce: [u8; 32],
    /// Phase 31 / Stage D (v2 only): the miner's separate custodial proposer key,
    /// authorized to make the delegated proposer-VRF assignment. All-zero and
    /// excluded from the wire form and `message_hash()` for v1 delegations.
    pub proposer_pubkey: [u8; 33],
    pub delegation_sig: [u8; 64],
}

impl Delegation {
    /// Current delegation format version (v2 adds `proposer_pubkey`).
    pub const VERSION: u8 = 2;
    /// v1 wire size: 1 + 1 + 33 + 33 + 32 + 8 + 2 + 20 + 32 + 64 = 226 bytes.
    pub const WIRE_SIZE_V1: usize = 1 + 1 + 33 + 33 + 32 + 8 + 2 + 20 + 32 + 64;
    /// v2 wire size: v1 + 33 (proposer_pubkey) = 259 bytes.
    pub const WIRE_SIZE_V2: usize = Self::WIRE_SIZE_V1 + 33;
    /// "Current"/maximum wire size = v2 (259). Capacity hints and fixed-size
    /// assertions use this; length-critical parsing uses `wire_len()`/version.
    pub const WIRE_SIZE: usize = Self::WIRE_SIZE_V2;

    /// Actual serialized length for THIS delegation, per its version byte.
    pub fn wire_len(&self) -> usize {
        if self.deleg_version >= 2 {
            Self::WIRE_SIZE_V2
        } else {
            Self::WIRE_SIZE_V1
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::WIRE_SIZE);
        out.push(self.deleg_version);
        out.push(self.network_id);
        out.extend_from_slice(&self.miner_pubkey);
        out.extend_from_slice(&self.pool_pubkey);
        out.extend_from_slice(&self.worker_tag);
        out.extend_from_slice(&self.expiry_height.to_le_bytes());
        out.extend_from_slice(&self.fee_bps.to_le_bytes());
        out.extend_from_slice(&self.fee_pkh);
        out.extend_from_slice(&self.deleg_nonce);
        if self.deleg_version >= 2 {
            out.extend_from_slice(&self.proposer_pubkey);
        }
        out.extend_from_slice(&self.delegation_sig);
        out
    }

    pub fn deserialize(raw: &[u8]) -> Result<Self, String> {
        if raw.len() < Self::WIRE_SIZE_V1 {
            return Err(format!(
                "delegation too short: {} < {}",
                raw.len(),
                Self::WIRE_SIZE_V1
            ));
        }
        let mut off = 0usize;
        let deleg_version = raw[off];
        off += 1;
        let expected = if deleg_version >= 2 {
            Self::WIRE_SIZE_V2
        } else {
            Self::WIRE_SIZE_V1
        };
        if raw.len() < expected {
            return Err(format!(
                "delegation too short: {} < {} (v{})",
                raw.len(),
                expected,
                deleg_version
            ));
        }
        let network_id = raw[off];
        off += 1;
        let mut miner_pubkey = [0u8; 33];
        miner_pubkey.copy_from_slice(&raw[off..off + 33]);
        off += 33;
        let mut pool_pubkey = [0u8; 33];
        pool_pubkey.copy_from_slice(&raw[off..off + 33]);
        off += 33;
        let mut worker_tag = [0u8; 32];
        worker_tag.copy_from_slice(&raw[off..off + 32]);
        off += 32;
        let expiry_height =
            u64::from_le_bytes(raw[off..off + 8].try_into().expect("slice len checked"));
        off += 8;
        let fee_bps = u16::from_le_bytes(raw[off..off + 2].try_into().expect("slice len checked"));
        off += 2;
        let mut fee_pkh = [0u8; 20];
        fee_pkh.copy_from_slice(&raw[off..off + 20]);
        off += 20;
        let mut deleg_nonce = [0u8; 32];
        deleg_nonce.copy_from_slice(&raw[off..off + 32]);
        off += 32;
        let mut proposer_pubkey = [0u8; 33];
        if deleg_version >= 2 {
            proposer_pubkey.copy_from_slice(&raw[off..off + 33]);
            off += 33;
        }
        let mut delegation_sig = [0u8; 64];
        delegation_sig.copy_from_slice(&raw[off..off + 64]);
        Ok(Self {
            deleg_version,
            network_id,
            miner_pubkey,
            pool_pubkey,
            worker_tag,
            expiry_height,
            fee_bps,
            fee_pkh,
            deleg_nonce,
            proposer_pubkey,
            delegation_sig,
        })
    }

    /// The 32-byte message the miner signs. Excludes `delegation_sig`.
    pub fn message_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(DOMAIN_DELEG);
        h.update([self.deleg_version]);
        h.update([self.network_id]);
        h.update(self.miner_pubkey);
        h.update(self.pool_pubkey);
        h.update(self.worker_tag);
        h.update(self.expiry_height.to_le_bytes());
        h.update(self.fee_bps.to_le_bytes());
        h.update(self.fee_pkh);
        h.update(self.deleg_nonce);
        if self.deleg_version >= 2 {
            h.update(self.proposer_pubkey);
        }
        h.finalize().into()
    }

    /// Tamper-evident digest over the full delegation bytes (including the
    /// signature). Bound into the mode-1 irx1 inner hash so any alteration of
    /// the embedded delegation changes the receipts root.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.serialize());
        h.finalize().into()
    }

    /// HASH160(miner_pubkey) — the miner pkh that must equal the receipt
    /// `worker_pkh` (payout identity).
    pub fn miner_pkh(&self) -> [u8; 20] {
        let sha = Sha256::digest(self.miner_pubkey);
        let rip = ripemd::Ripemd160::digest(sha);
        let mut pkh = [0u8; 20];
        pkh.copy_from_slice(&rip);
        pkh
    }

    /// Verify the miner's delegation signature over `message_hash()`.
    pub fn verify_signature(&self) -> Result<(), &'static str> {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        use k256::ecdsa::{Signature, VerifyingKey};
        let vk = VerifyingKey::from_sec1_bytes(&self.miner_pubkey)
            .map_err(|_| "delegation: invalid miner_pubkey")?;
        let sig = Signature::from_slice(&self.delegation_sig)
            .map_err(|_| "delegation: malformed delegation_sig")?;
        vk.verify_prehash(&self.message_hash(), &sig)
            .map_err(|_| "delegation: signature verification failed")
    }
}

/// Extracts the 32-byte `irx1` root from the block coinbase if a well-formed
/// `irx1` OP_RETURN output is present. Root may be all-zeros.
pub fn irx1_root_from_block_bytes(block: &Block) -> Option<[u8; 32]> {
    let coinbase = block.transactions.first()?;
    for out in &coinbase.outputs {
        let s = &out.script_pubkey;
        if s.len() == IRX1_SCRIPT_LEN && s[0] == 0x6a && s[1] == 0x24 && &s[2..6] == IRX1_TAG {
            let mut root = [0u8; 32];
            root.copy_from_slice(&s[6..38]);
            return Some(root);
        }
    }
    None
}

/// Counts leading zero bits in a 32-byte hash.
/// Used by connect_block (Phase 13-B) and submit_block_extended for puzzle PoW checks.
pub fn count_leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut bits = 0u32;
    for &b in hash.iter() {
        let z = b.leading_zeros();
        bits += z;
        if z < 8 {
            break;
        }
    }
    bits
}

/// Computes the irx1 root from block-contained receipt data deterministically.
///
/// Sort order and inner hash algorithm match `compute_poawx_receipts_root` in
/// iriumd.rs (which operates on `PoawxPendingReceipt` hex fields):
///   inner = SHA256(height_le8 || lane_byte || worker_pkh_bytes ||
///                  solution_bytes || commitment_nonce_bytes)
///   root  = SHA256(concat inner hashes; receipts sorted by
///                  (height, lane, worker_pkh, commitment_nonce))
pub fn irx1_root_from_block_receipts(receipts: &[PoawxBlockReceipt]) -> [u8; 32] {
    irx1_root_from_block_receipts_gated(receipts, false)
}

/// Phase 20: gated variant of [`irx1_root_from_block_receipts`]. When
/// `phase20_active` is true, a receipt's `phase20_ext` digest is bound into its
/// inner hash (after the optional mode-1 delegation digest), so any change to the
/// production extension (role claims, RoleReward, fee terms) changes the receipts
/// root and is tamper-evident. When `phase20_active` is false — every pre-activation
/// and non-production caller — the result is **byte-identical** to the Phase 13-A /
/// 18B root (the extension is ignored, exactly as the wrapper above). The inner
/// hash field order mirrors `compute_poawx_receipts_root_gated` in iriumd.rs.
// Fix #1 (audit-gated): deterministic, collision-proof receipts root. Audit OFF => delegates
// to the legacy `_gated` root (byte-identical). Audit ON => the root is built from receipts
// sorted by their FULL inner hash (a total order over [u8;32]), so a block carrying receipts
// that collide on (height,lane,worker_pkh,commitment_nonce) can no longer yield a node-
// dependent root via `sort_unstable_by`'s undefined order on equal keys. For single-receipt
// blocks (every honest block) the result is identical to legacy either way.
pub fn irx1_root_from_block_receipts_audit(
    receipts: &[PoawxBlockReceipt],
    phase20_active: bool,
    audit_active: bool,
) -> [u8; 32] {
    if !audit_active {
        return irx1_root_from_block_receipts_gated(receipts, phase20_active);
    }
    let mut inners: Vec<[u8; 32]> = receipts
        .iter()
        .map(|r| {
            let mut inner = Sha256::new();
            inner.update(r.height.to_le_bytes());
            inner.update([r.lane]);
            inner.update(r.worker_pkh);
            // Fix #5: bind signer pubkey + signature so the receipt signature is consensus-
            // committed (no block-hash-stable wire variants from a different valid sig).
            inner.update(r.worker_pubkey);
            inner.update(r.worker_sig);
            inner.update(r.solution);
            inner.update(r.commitment_nonce);
            if let Some(d) = &r.delegation {
                inner.update(d.digest());
            }
            if phase20_active {
                if let Some(e) = &r.phase20_ext {
                    inner.update(e.digest());
                }
            }
            inner.finalize().into()
        })
        .collect();
    inners.sort_unstable();
    let mut outer = Sha256::new();
    for h in &inners {
        outer.update(h);
    }
    outer.finalize().into()
}

pub fn irx1_root_from_block_receipts_gated(
    receipts: &[PoawxBlockReceipt],
    phase20_active: bool,
) -> [u8; 32] {
    let mut sorted: Vec<&PoawxBlockReceipt> = receipts.iter().collect();
    sorted.sort_unstable_by(|a, b| {
        a.height
            .cmp(&b.height)
            .then_with(|| a.lane.cmp(&b.lane))
            .then_with(|| a.worker_pkh.cmp(&b.worker_pkh))
            .then_with(|| a.commitment_nonce.cmp(&b.commitment_nonce))
    });
    let mut outer = Sha256::new();
    for r in &sorted {
        let mut inner = Sha256::new();
        inner.update(r.height.to_le_bytes());
        inner.update([r.lane]);
        inner.update(r.worker_pkh);
        inner.update(r.solution);
        inner.update(r.commitment_nonce);
        // Phase 18B: mode-1 binds the delegation digest into the inner hash so
        // the embedded delegation is tamper-evident. Mode-0 (delegation None)
        // is byte-identical to the Phase 13-A inner hash.
        if let Some(d) = &r.delegation {
            inner.update(d.digest());
        }
        // Phase 20: bind the production-extension digest (gated). Absent extension
        // or `phase20_active == false` => byte-identical to the Phase 13-A/18B root.
        if phase20_active {
            if let Some(e) = &r.phase20_ext {
                inner.update(e.digest());
            }
        }
        outer.update(inner.finalize());
    }
    outer.finalize().into()
}

/// Process-global lock serialising all PoAW-X lib tests that mutate global env
/// (IRIUM_NETWORK etc.) so the parallel `cargo test --lib poawx` run is race-free.
#[cfg(test)]
pub(crate) fn poawx_test_env_lock() -> &'static std::sync::Mutex<()> {
    static L: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    L.get_or_init(|| std::sync::Mutex::new(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::Block;
    use crate::tx::{Transaction, TxInput, TxOutput};

    fn make_block_with_coinbase_script(script: Vec<u8>) -> Block {
        use crate::block::BlockHeader;
        Block {
            header: BlockHeader {
                version: 1,
                prev_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                time: 0,
                bits: 0x207fffff,
                nonce: 0,
            },
            transactions: vec![Transaction {
                version: 1,
                inputs: vec![TxInput {
                    prev_txid: [0u8; 32],
                    prev_index: 0xffff_ffff,
                    script_sig: vec![0x01, 0x00],
                    sequence: 0xffff_ffff,
                }],
                outputs: vec![
                    TxOutput {
                        value: 50_0000_0000,
                        script_pubkey: vec![0x51],
                    },
                    TxOutput {
                        value: 0,
                        script_pubkey: script,
                    },
                ],
                locktime: 0,
            }],
            auxpow: None,
            poawx_receipts: None,
        }
    }

    fn valid_irx1_script(root: [u8; 32]) -> Vec<u8> {
        let mut s = vec![0x6a, 0x24];
        s.extend_from_slice(b"irx1");
        s.extend_from_slice(&root);
        s
    }

    #[test]
    fn no_coinbase_returns_false() {
        use crate::block::BlockHeader;
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                time: 0,
                bits: 0,
                nonce: 0,
            },
            transactions: vec![],
            auxpow: None,
            poawx_receipts: None,
        };
        assert!(!block_has_irx1_commitment(&block));
    }

    #[test]
    fn no_irx1_output_returns_false() {
        let block = make_block_with_coinbase_script(vec![0x51]);
        assert!(!block_has_irx1_commitment(&block));
    }

    #[test]
    fn irx1_with_nonzero_root_returns_true() {
        let mut root = [0u8; 32];
        root[0] = 0xde;
        root[31] = 0xad;
        let block = make_block_with_coinbase_script(valid_irx1_script(root));
        assert!(block_has_irx1_commitment(&block));
    }

    #[test]
    fn irx1_with_zero_root_returns_false() {
        let block = make_block_with_coinbase_script(valid_irx1_script([0u8; 32]));
        assert!(!block_has_irx1_commitment(&block));
    }

    #[test]
    fn wrong_tag_returns_false() {
        let mut s = vec![0x6a, 0x24];
        s.extend_from_slice(b"irx2");
        s.extend_from_slice(&[0xab; 32]);
        let block = make_block_with_coinbase_script(s);
        assert!(!block_has_irx1_commitment(&block));
    }

    #[test]
    fn too_short_script_returns_false() {
        let block = make_block_with_coinbase_script(vec![0x6a, 0x24, b'i', b'r', b'x', b'1']);
        assert!(!block_has_irx1_commitment(&block));
    }

    #[test]
    fn irx1_root_extraction_works() {
        let mut expected = [0u8; 32];
        expected[0] = 0x3a;
        expected[31] = 0xfe;
        let block = make_block_with_coinbase_script(valid_irx1_script(expected));
        assert_eq!(irx1_root_from_block_bytes(&block), Some(expected));
    }

    #[test]
    fn irx1_root_absent_returns_none() {
        let block = make_block_with_coinbase_script(vec![0x51]);
        assert_eq!(irx1_root_from_block_bytes(&block), None);
    }

    // ── Phase 13-A receipt wire format tests ─────────────────────────────

    fn make_test_receipt(height: u64) -> PoawxBlockReceipt {
        PoawxBlockReceipt {
            height,
            lane: b'A',
            worker_pkh: [0x11u8; 20],
            worker_pubkey: [0x22u8; 33],
            worker_sig: [0x33u8; 64],
            solution: [0x44u8; 8],
            commitment_nonce: [0x55u8; 32],
            delegation: None,
            phase20_ext: None,
        }
    }

    #[test]
    fn audit_receipts_root_deterministic_under_colliding_keys() {
        // Fix #1: two receipts that collide on the legacy sort key (height, lane, worker_pkh,
        // commitment_nonce) but differ in `solution` produce an order-INDEPENDENT audit root
        // (sorted by full inner hash), eliminating sort_unstable's undefined tie order -- a
        // chain-split risk with adversarial multi-receipt blocks.
        let mut a = make_test_receipt(7);
        let mut b = make_test_receipt(7);
        a.solution = [0x44u8; 8];
        b.solution = [0x77u8; 8];
        assert_eq!(a.height, b.height);
        assert_eq!(a.lane, b.lane);
        assert_eq!(a.worker_pkh, b.worker_pkh);
        assert_eq!(a.commitment_nonce, b.commitment_nonce);
        let fwd = irx1_root_from_block_receipts_audit(&[a.clone(), b.clone()], true, true);
        let rev = irx1_root_from_block_receipts_audit(&[b.clone(), a.clone()], true, true);
        assert_eq!(fwd, rev, "audit root order-independent for colliding keys");
        // a 3-element shuffle is also invariant.
        let c = make_test_receipt(8);
        let r1 = irx1_root_from_block_receipts_audit(&[a.clone(), b.clone(), c.clone()], true, true);
        let r2 = irx1_root_from_block_receipts_audit(&[c.clone(), a.clone(), b.clone()], true, true);
        let r3 = irx1_root_from_block_receipts_audit(&[b.clone(), c.clone(), a.clone()], true, true);
        assert_eq!(r1, r2);
        assert_eq!(r1, r3);
        // gate OFF delegates to the legacy gated root (byte-identical when off).
        let one = make_test_receipt(9);
        assert_eq!(
            irx1_root_from_block_receipts_audit(&[one.clone()], true, false),
            irx1_root_from_block_receipts_gated(&[one.clone()], true),
            "audit=false is byte-identical to legacy gated root"
        );
    }

    #[test]
    fn phase13a_receipt_serialize_deserialize_roundtrip() {
        let r = make_test_receipt(42);
        let bytes = r.serialize();
        assert_eq!(bytes.len(), PoawxBlockReceipt::WIRE_SIZE);
        let r2 = PoawxBlockReceipt::deserialize(&bytes).expect("deserialize");
        assert_eq!(r, r2);
        assert_eq!(r2.height, 42);
        assert_eq!(r2.lane, b'A');
        assert_eq!(r2.worker_pkh, [0x11u8; 20]);
        assert_eq!(r2.worker_pubkey, [0x22u8; 33]);
        assert_eq!(r2.worker_sig, [0x33u8; 64]);
        assert_eq!(r2.solution, [0x44u8; 8]);
        assert_eq!(r2.commitment_nonce, [0x55u8; 32]);
    }

    // ── Phase 20: multi-role reward split primitives ─────────────────────────

    #[test]
    fn phase20_multi_role_amounts_exact_split_and_remainder() {
        // 55/22/13/10 of a clean total divides exactly.
        let amts = multi_role_amounts(10_000);
        assert_eq!(amts, [5500, 2200, 1300, 1000]);
        assert_eq!(amts.iter().sum::<u64>(), 10_000);
        // A reward that does not divide evenly: remainder goes to PRIMARY, sum exact.
        let total = 5_000_000_001u64; // odd, forces a remainder
        let a = multi_role_amounts(total);
        assert_eq!(a[1], (total as u128 * 2200 / 10000) as u64);
        assert_eq!(a[2], (total as u128 * 1300 / 10000) as u64);
        assert_eq!(a[3], (total as u128 * 1000 / 10000) as u64);
        assert_eq!(a.iter().sum::<u64>(), total, "sum equals total exactly");
        // remainder lands in PRIMARY: primary >= its floor.
        assert!(a[0] >= (total as u128 * 5500 / 10000) as u64);
        // zero reward → all zero.
        assert_eq!(multi_role_amounts(0), [0, 0, 0, 0]);
    }

    #[test]
    fn phase20_role_reward_wire_roundtrip() {
        let r = RoleReward {
            compute_contributor_pkh: [0xC0u8; 20],
            verify_contributor_pkh: [0x7Eu8; 20],
            support_contributor_pkh: [0x5Au8; 20],
        };
        let bytes = r.serialize();
        assert_eq!(bytes.len(), RoleReward::WIRE_SIZE);
        assert_eq!(RoleReward::WIRE_SIZE, 60);
        let r2 = RoleReward::deserialize(&bytes).expect("deserialize");
        assert_eq!(r, r2);
        // digest is deterministic + sensitive to content.
        assert_eq!(r.digest(), r2.digest());
        let mut r3 = r.clone();
        r3.support_contributor_pkh = [0x5Bu8; 20];
        assert_ne!(r.digest(), r3.digest());
        // truncated input rejects.
        assert!(RoleReward::deserialize(&bytes[..59]).is_err());
    }

    #[test]
    fn phase20_role_reward_json_roundtrip() {
        // serde round-trip of the role pkhs (hex) — the persistence carrier shape.
        let r = RoleReward {
            compute_contributor_pkh: [1u8; 20],
            verify_contributor_pkh: [2u8; 20],
            support_contributor_pkh: [3u8; 20],
        };
        let j = serde_json::json!({
            "compute_contributor_pkh": hex::encode(r.compute_contributor_pkh),
            "verify_contributor_pkh": hex::encode(r.verify_contributor_pkh),
            "support_contributor_pkh": hex::encode(r.support_contributor_pkh),
        });
        let s = serde_json::to_string(&j).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        let back = RoleReward {
            compute_contributor_pkh: {
                let b = hex::decode(v["compute_contributor_pkh"].as_str().unwrap()).unwrap();
                let mut a = [0u8; 20];
                a.copy_from_slice(&b);
                a
            },
            verify_contributor_pkh: {
                let b = hex::decode(v["verify_contributor_pkh"].as_str().unwrap()).unwrap();
                let mut a = [0u8; 20];
                a.copy_from_slice(&b);
                a
            },
            support_contributor_pkh: {
                let b = hex::decode(v["support_contributor_pkh"].as_str().unwrap()).unwrap();
                let mut a = [0u8; 20];
                a.copy_from_slice(&b);
                a
            },
        };
        assert_eq!(r, back);
    }

    #[test]
    fn phase20_bps_constants_total_10000() {
        assert_eq!(
            MULTI_ROLE_PRIMARY_BPS
                + MULTI_ROLE_COMPUTE_BPS
                + MULTI_ROLE_VERIFY_BPS
                + MULTI_ROLE_SUPPORT_BPS,
            MULTI_ROLE_TOTAL_BPS
        );
        assert_eq!(MULTI_ROLE_TOTAL_BPS, 10_000);
    }

    #[test]
    fn phase20_v1_v2_receipt_encoding_unchanged() {
        // Adding the multi-role primitives must NOT change the existing receipt
        // wire size or mode-0 encoding (pre-activation byte-identical guarantee).
        assert_eq!(PoawxBlockReceipt::WIRE_SIZE, 166);
        let r = make_test_receipt(7);
        assert_eq!(r.serialize().len(), 166);
        assert_eq!(r.mode(), RECEIPT_MODE_DIRECT);
        // mode-0 v2 element = 1 (mode) + 166 (legacy), no delegation/role bytes.
        assert_eq!(r.serialize_v2().len(), 1 + 166);
    }

    // ── Phase 20: CPU/GPU/ASIC fairness matrix primitives ────────────────────

    fn fairness_valid_claim(
        net: u8,
        height: u64,
        prev: &[u8; 32],
        role_id: u8,
        slot: u32,
    ) -> PoawxRoleClaim {
        let lane = assign_lane(net, height, prev, role_id, slot);
        let solver_pkh = [0xABu8; 20];
        let nonce = [0x01u8; 32];
        let secret = [0x02u8; 32];
        let claim_digest = role_claim_digest(
            net,
            height,
            prev,
            role_id,
            lane.id(),
            &solver_pkh,
            &nonce,
            &secret,
        );
        let mut ch = Sha256::new();
        ch.update(secret);
        ch.update(nonce);
        PoawxRoleClaim {
            role_id,
            lane_id: lane.id(),
            solver_pkh,
            nonce,
            secret,
            claim_digest,
            commitment_hash: Some(ch.finalize().into()),
        }
    }

    #[test]
    fn phase20_fairness_assignment_deterministic_and_sensitive() {
        let prev = [0x07u8; 32];
        // same inputs -> same lane (deterministic).
        let a = assign_lane(1, 100, &prev, ROLE_COMPUTE_CONTRIBUTOR, 0);
        let b = assign_lane(1, 100, &prev, ROLE_COMPUTE_CONTRIBUTOR, 0);
        assert_eq!(a, b);
        // never the dev/test fallback.
        assert!(a.is_fairness_lane());
        // changing any field can change the assignment across a small sweep
        // (proves height/role/prev/slot all feed the digest).
        let mut prev2 = prev;
        prev2[0] ^= 0xFF;
        let changed = (0..8).any(|s| {
            assign_lane(1, 100, &prev, ROLE_COMPUTE_CONTRIBUTOR, s)
                != assign_lane(1, 101, &prev, ROLE_COMPUTE_CONTRIBUTOR, s)
        }) || (0..8).any(|s| {
            assign_lane(1, 100, &prev, ROLE_COMPUTE_CONTRIBUTOR, s)
                != assign_lane(1, 100, &prev2, ROLE_COMPUTE_CONTRIBUTOR, s)
        });
        assert!(changed, "assignment must depend on height/prev_hash");
    }

    #[test]
    fn phase20_fairness_distribution_34_33_33() {
        // Deterministic (not random): sweep 3600 slot indices.
        let prev = [0x5Au8; 32];
        let n = 3600u32;
        let (mut cpu, mut gpu, mut asic) = (0u32, 0u32, 0u32);
        for s in 0..n {
            match assign_lane(2, 12345, &prev, ROLE_VERIFY_CONTRIBUTOR, s) {
                PoawxLane::CpuFriendly => cpu += 1,
                PoawxLane::GpuParallel => gpu += 1,
                PoawxLane::AsicStreaming => asic += 1,
                PoawxLane::UniversalFallback => panic!("fallback must never be assigned"),
            }
        }
        assert_eq!(cpu + gpu + asic, n);
        let pct = |c: u32| (c as f64) * 100.0 / (n as f64);
        // ±3 percentage-point tolerance around 34/33/33.
        assert!((31.0..=37.0).contains(&pct(cpu)), "cpu% = {}", pct(cpu));
        assert!((30.0..=36.0).contains(&pct(gpu)), "gpu% = {}", pct(gpu));
        assert!((30.0..=36.0).contains(&pct(asic)), "asic% = {}", pct(asic));
    }

    #[test]
    fn phase20_lane_and_role_id_roundtrip() {
        for l in [
            PoawxLane::CpuFriendly,
            PoawxLane::GpuParallel,
            PoawxLane::AsicStreaming,
            PoawxLane::UniversalFallback,
        ] {
            assert_eq!(PoawxLane::from_id(l.id()), Some(l));
        }
        assert_eq!(PoawxLane::from_id(7), None, "unknown lane id");
        assert!(!PoawxLane::UniversalFallback.is_fairness_lane());
        for r in [
            PoawxRoleSlot::ComputeContributor,
            PoawxRoleSlot::VerifyContributor,
            PoawxRoleSlot::SupportContributor,
        ] {
            assert_eq!(PoawxRoleSlot::from_id(r.id()), Some(r));
        }
        assert_eq!(
            PoawxRoleSlot::from_id(0),
            None,
            "PRIMARY is not a fairness role"
        );
        assert_eq!(PoawxRoleSlot::from_id(99), None);
    }

    #[test]
    fn phase20_role_claim_wire_roundtrip() {
        let prev = [0x11u8; 32];
        let c = fairness_valid_claim(1, 50, &prev, ROLE_SUPPORT_CONTRIBUTOR, 3);
        let bytes = c.serialize();
        let c2 = PoawxRoleClaim::deserialize(&bytes).expect("deserialize");
        assert_eq!(c, c2);
        // no-commitment variant round-trips and is shorter.
        let mut c3 = c.clone();
        c3.commitment_hash = None;
        let b3 = c3.serialize();
        assert_eq!(b3.len(), PoawxRoleClaim::FIXED_SIZE + 1);
        assert_eq!(PoawxRoleClaim::deserialize(&b3).unwrap(), c3);
        // truncation rejects (wrong pkh/field length).
        assert!(PoawxRoleClaim::deserialize(&bytes[..PoawxRoleClaim::FIXED_SIZE]).is_err());
        // commitment flag set but bytes missing rejects.
        let mut bad = c3.serialize();
        *bad.last_mut().unwrap() = 1; // flag=1 but no 32 bytes follow
        assert!(PoawxRoleClaim::deserialize(&bad).is_err());
    }

    #[test]
    fn phase20_role_claim_validation_accept_and_reject() {
        let net = 1u8;
        let height = 777u64;
        let prev = [0x22u8; 32];
        let slot = 5u32;
        let role = ROLE_COMPUTE_CONTRIBUTOR;

        // valid claim accepted.
        let good = fairness_valid_claim(net, height, &prev, role, slot);
        assert!(validate_role_claim(&good, net, height, &prev, slot).is_ok());

        // wrong lane (correct digest for a non-assigned lane) rejects.
        let assigned = assign_lane(net, height, &prev, role, slot);
        let other = match assigned {
            PoawxLane::CpuFriendly => PoawxLane::GpuParallel,
            _ => PoawxLane::CpuFriendly,
        };
        let mut wl = good.clone();
        wl.lane_id = other.id();
        wl.claim_digest = role_claim_digest(
            net,
            height,
            &prev,
            role,
            other.id(),
            &wl.solver_pkh,
            &wl.nonce,
            &wl.secret,
        );
        assert!(validate_role_claim(&wl, net, height, &prev, slot)
            .unwrap_err()
            .contains("assigned lane"));

        // tampered nonce/secret -> digest fails to verify.
        let mut wn = good.clone();
        wn.nonce[0] ^= 0xFF;
        assert!(validate_role_claim(&wn, net, height, &prev, slot)
            .unwrap_err()
            .contains("digest"));

        // unknown role id rejects.
        let mut wr = good.clone();
        wr.role_id = 99;
        assert!(validate_role_claim(&wr, net, height, &prev, slot)
            .unwrap_err()
            .contains("unknown role"));

        // unknown lane id rejects.
        let mut wlid = good.clone();
        wlid.lane_id = 200;
        assert!(validate_role_claim(&wlid, net, height, &prev, slot)
            .unwrap_err()
            .contains("unknown lane"));

        // fallback lane is not a valid production fairness lane.
        let mut wfb = good.clone();
        wfb.lane_id = LANE_UNIVERSAL_FALLBACK;
        assert!(validate_role_claim(&wfb, net, height, &prev, slot).is_err());

        // wrong slot/height/prev -> assignment differs (or digest differs) -> reject.
        assert!(
            validate_role_claim(&good, net, height, &prev, slot + 1).is_err()
                || validate_role_claim(&good, net, height + 1, &prev, slot).is_err()
        );
    }

    // ── Phase 20: third-party pool fee primitives ────────────────────────────

    #[test]
    fn phase20_validate_fee_terms() {
        let fpkh = [0xFEu8; 20];
        let zero = [0u8; 20];
        // official: fee 0 ok in any mode, no fee_pkh required.
        assert!(validate_fee_terms(0, &zero, false).is_ok());
        assert!(validate_fee_terms(0, &zero, true).is_ok());
        // fee>0 without third-party mode rejects.
        assert!(validate_fee_terms(50, &fpkh, false)
            .unwrap_err()
            .contains("third-party"));
        // fee>0 in third-party mode with pkh: 1 and the 200 cap accepted.
        assert!(validate_fee_terms(1, &fpkh, true).is_ok());
        assert!(validate_fee_terms(THIRD_PARTY_FEE_CAP_BPS, &fpkh, true).is_ok());
        // over cap (201) rejects.
        assert!(validate_fee_terms(201, &fpkh, true)
            .unwrap_err()
            .contains("cap"));
        // fee>0 without fee_pkh rejects.
        assert!(validate_fee_terms(100, &zero, true)
            .unwrap_err()
            .contains("fee_pkh"));
    }

    #[test]
    fn phase20_apply_fee_floor_and_remainder() {
        // floor + miner keeps remainder; net + fee == gross exactly.
        let g = 5_000_000_001u64;
        let (net, fee) = apply_fee(g, 200);
        assert_eq!(fee, (g as u128 * 200 / 10000) as u64);
        assert_eq!(net + fee, g);
        // fee rounds down (1% of 101 = 1.01 -> 1; miner keeps 100).
        assert_eq!(apply_fee(101, 100), (100, 1));
        // fee 0 -> net == gross.
        assert_eq!(apply_fee(123, 0), (123, 0));
    }

    #[test]
    fn phase20_delegation_binds_fee_terms() {
        // fee_bps + fee_pkh round-trip AND are covered by the signed message_hash,
        // so the pool cannot mutate fee terms after the miner signs.
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        let sk = test_sk();
        let mut d = make_signed_delegation(&sk, 150);
        d.fee_pkh = [0xFEu8; 20];
        let sig: k256::ecdsa::Signature = sk.sign_prehash(&d.message_hash()).unwrap();
        d.delegation_sig.copy_from_slice(&sig.to_bytes());
        assert!(d.verify_signature().is_ok());
        // wire round-trip preserves fee terms.
        let d2 = Delegation::deserialize(&d.serialize()).unwrap();
        assert_eq!(d2.fee_bps, 150);
        assert_eq!(d2.fee_pkh, [0xFEu8; 20]);
        assert_eq!(d, d2);
        // mutating fee_bps or fee_pkh changes message_hash AND breaks the signature.
        let mut m_bps = d.clone();
        m_bps.fee_bps = 151;
        assert_ne!(d.message_hash(), m_bps.message_hash());
        assert!(
            m_bps.verify_signature().is_err(),
            "fee_bps mutation must break the signature"
        );
        let mut m_pkh = d.clone();
        m_pkh.fee_pkh = [0xABu8; 20];
        assert_ne!(d.message_hash(), m_pkh.message_hash());
        assert!(
            m_pkh.verify_signature().is_err(),
            "fee_pkh mutation must break the signature"
        );
    }

    #[test]
    fn phase20_receipt_ext_wire_roundtrip() {
        let prev = [0x33u8; 32];
        let ext = Phase20ReceiptExt {
            role_reward: RoleReward {
                compute_contributor_pkh: [0xC1u8; 20],
                verify_contributor_pkh: [0xC2u8; 20],
                support_contributor_pkh: [0xC3u8; 20],
            },
            compute_claim: fairness_valid_claim(1, 90, &prev, ROLE_COMPUTE_CONTRIBUTOR, 0),
            verify_claim: fairness_valid_claim(1, 90, &prev, ROLE_VERIFY_CONTRIBUTOR, 0),
            support_claim: fairness_valid_claim(1, 90, &prev, ROLE_SUPPORT_CONTRIBUTOR, 0),
            fee_bps: 150,
            fee_pkh: [0xFEu8; 20],
            precommit_root: None,
            role_ticket_proofs: None,
            role_dominance_weights: None,
            candidate_set: None,
            role_puzzle_proofs: None,
            finality_proof: None,
            committed_admission: None,
            role_assignment_v2: None,
            fraud_proofs: None,
            proposer_assignment: None,
            proposer_registrations: None,
        };
        let bytes = ext.serialize();
        let ext2 = Phase20ReceiptExt::deserialize(&bytes).expect("deserialize");
        assert_eq!(ext, ext2);
        assert_eq!(ext.digest(), ext2.digest());
        // truncation rejects.
        assert!(Phase20ReceiptExt::deserialize(&bytes[..bytes.len() - 1]).is_err());
        assert!(Phase20ReceiptExt::deserialize(&[]).is_err());
        // unknown version rejects.
        let mut badver = bytes.clone();
        badver[0] = 9;
        assert!(Phase20ReceiptExt::deserialize(&badver).is_err());
        // a digest change is sensitive to fee terms (binding visible in the ext digest).
        let mut ext3 = ext.clone();
        ext3.fee_bps = 151;
        assert_ne!(ext.digest(), ext3.digest());
    }

    #[test]
    fn phase20_hidden_precommit_primitives() {
        let secret = [7u8; 32];
        let nonce = [9u8; 32];
        let c = role_precommit_commitment(&secret, &nonce);
        // commitment deterministic + sensitive to secret/nonce.
        assert_eq!(c, role_precommit_commitment(&secret, &nonce));
        assert_ne!(c, role_precommit_commitment(&[8u8; 32], &nonce));
        assert_ne!(c, role_precommit_commitment(&secret, &[10u8; 32]));
        // leaf deterministic + mutation/replay sensitive.
        let solver = [0xA1u8; 20];
        let leaf = role_precommit_leaf(1, 100, ROLE_COMPUTE_CONTRIBUTOR, &solver, &c);
        assert_eq!(
            leaf,
            role_precommit_leaf(1, 100, ROLE_COMPUTE_CONTRIBUTOR, &solver, &c)
        );
        assert_ne!(
            leaf,
            role_precommit_leaf(2, 100, ROLE_COMPUTE_CONTRIBUTOR, &solver, &c),
            "network"
        );
        assert_ne!(
            leaf,
            role_precommit_leaf(1, 101, ROLE_COMPUTE_CONTRIBUTOR, &solver, &c),
            "height replay"
        );
        assert_ne!(
            leaf,
            role_precommit_leaf(1, 100, ROLE_VERIFY_CONTRIBUTOR, &solver, &c),
            "role"
        );
        assert_ne!(
            leaf,
            role_precommit_leaf(1, 100, ROLE_COMPUTE_CONTRIBUTOR, &[0xB2u8; 20], &c),
            "solver"
        );
        assert_ne!(
            leaf,
            role_precommit_leaf(1, 100, ROLE_COMPUTE_CONTRIBUTOR, &solver, &[0u8; 32]),
            "commitment"
        );
        // root order-independent + set-sensitive.
        let (l1, l2, l3) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        assert_eq!(
            role_precommit_root(&[l1, l2, l3]),
            role_precommit_root(&[l3, l1, l2])
        );
        assert_ne!(
            role_precommit_root(&[l1, l2]),
            role_precommit_root(&[l1, l3])
        );
        // leaf_for_claim: valid claim reconstructs the leaf; mutated/missing reject.
        let claim = PoawxRoleClaim {
            role_id: ROLE_COMPUTE_CONTRIBUTOR,
            lane_id: 0,
            solver_pkh: solver,
            nonce,
            secret,
            claim_digest: [0u8; 32],
            commitment_hash: Some(c),
        };
        assert_eq!(role_precommit_leaf_for_claim(&claim, 1, 100).unwrap(), leaf);
        let mut mutated = claim.clone();
        mutated.secret = [0xFFu8; 32];
        assert!(
            role_precommit_leaf_for_claim(&mutated, 1, 100).is_err(),
            "mutated secret"
        );
        let mut nocommit = claim.clone();
        nocommit.commitment_hash = None;
        assert!(
            role_precommit_leaf_for_claim(&nocommit, 1, 100).is_err(),
            "missing commitment"
        );
    }

    #[test]
    fn proposer_registration_build_validate_roundtrip() {
        let net = 2u8;
        let anchor_hash = [0x5a_u8; 32];
        let secret = [0x33u8; 32];
        let bits = 8u32;
        let reg =
            ProposerRegistrationV1::build_signed(&secret, net, 123, &anchor_hash, bits).unwrap();
        // wire roundtrip
        let w = reg.serialize();
        assert_eq!(w.len(), PROPOSER_REGISTRATION_V1_WIRE);
        assert_eq!(ProposerRegistrationV1::deserialize(&w).unwrap(), reg);
        // self-validation passes against the same anchor + bits.
        assert!(reg.validate(net, &anchor_hash, bits).is_ok());
        // tamper signature -> fail.
        let mut bad = reg.clone();
        bad.signature[0] ^= 0xff;
        assert!(bad.validate(net, &anchor_hash, bits).is_err());
        // wrong anchor hash -> sybil digest mismatch.
        assert!(reg.validate(net, &[0u8; 32], bits).is_err());
        // higher required bits than ground -> insufficient work (probabilistic but the
        // grind targeted exactly `bits`, so requiring bits+20 is overwhelmingly short).
        assert!(reg.validate(net, &anchor_hash, bits + 20).is_err());
    }

    #[test]
    fn proposer_assignment_section_roundtrip() {
        let prev = [0x44u8; 32];
        let proof = crate::poawx_candidate::AssignmentProofV2::prove(
            &[0x11u8; 32],
            1,
            100,
            crate::poawx_proposer::ROLE_PROPOSER,
            [0x22u8; 20],
            [0x33u8; 32],
            [0x55u8; 32],
        )
        .expect("v2 prove");
        let pa = ProposerAssignmentV1 { round: 3, proof };
        // section wire roundtrip
        let sb = pa.serialize();
        assert_eq!(sb.len(), PROPOSER_ASSIGNMENT_V1_WIRE);
        assert_eq!(ProposerAssignmentV1::deserialize(&sb).unwrap(), pa);
        // full-ext roundtrip: absent => byte-identical (no PRP1), present => +section.
        let mut ext = Phase20ReceiptExt {
            role_reward: RoleReward {
                compute_contributor_pkh: [0xC1u8; 20],
                verify_contributor_pkh: [0xC2u8; 20],
                support_contributor_pkh: [0xC3u8; 20],
            },
            compute_claim: fairness_valid_claim(1, 60, &prev, ROLE_COMPUTE_CONTRIBUTOR, 0),
            verify_claim: fairness_valid_claim(1, 60, &prev, ROLE_VERIFY_CONTRIBUTOR, 0),
            support_claim: fairness_valid_claim(1, 60, &prev, ROLE_SUPPORT_CONTRIBUTOR, 0),
            fee_bps: 0,
            fee_pkh: [0u8; 20],
            precommit_root: None,
            role_ticket_proofs: None,
            role_dominance_weights: None,
            candidate_set: None,
            role_puzzle_proofs: None,
            finality_proof: None,
            committed_admission: None,
            role_assignment_v2: None,
            fraud_proofs: None,
            proposer_assignment: None,
            proposer_registrations: None,
        };
        let absent = ext.serialize();
        assert!(!absent.windows(4).any(|w| w == PROPOSER_SECTION_MAGIC));
        assert_eq!(Phase20ReceiptExt::deserialize(&absent).unwrap(), ext);
        ext.proposer_assignment = Some(pa.clone());
        let present = ext.serialize();
        assert_eq!(present.len(), absent.len() + 1 + 4 + PROPOSER_ASSIGNMENT_V1_WIRE);
        let back = Phase20ReceiptExt::deserialize(&present).unwrap();
        assert_eq!(back.proposer_assignment, Some(pa));
        assert_eq!(back, ext);
    }

    #[test]
    fn proposer_registration_section_roundtrip() {
        let prev = [0x44u8; 32];
        let net = 2u8;
        let anchor_h = [0x5au8; 32];
        let ra = ProposerRegistrationV1::build_signed(&[0x01u8; 32], net, 10, &anchor_h, 8).unwrap();
        let rb = ProposerRegistrationV1::build_signed(&[0x02u8; 32], net, 11, &anchor_h, 8).unwrap();
        let sec = ProposerRegistrationSection {
            announces: vec![ra.clone()],
            activations: vec![rb.clone()],
        };
        let mut ext = Phase20ReceiptExt {
            role_reward: RoleReward {
                compute_contributor_pkh: [0xC1u8; 20],
                verify_contributor_pkh: [0xC2u8; 20],
                support_contributor_pkh: [0xC3u8; 20],
            },
            compute_claim: fairness_valid_claim(1, 60, &prev, ROLE_COMPUTE_CONTRIBUTOR, 0),
            verify_claim: fairness_valid_claim(1, 60, &prev, ROLE_VERIFY_CONTRIBUTOR, 0),
            support_claim: fairness_valid_claim(1, 60, &prev, ROLE_SUPPORT_CONTRIBUTOR, 0),
            fee_bps: 0,
            fee_pkh: [0u8; 20],
            precommit_root: None,
            role_ticket_proofs: None,
            role_dominance_weights: None,
            candidate_set: None,
            role_puzzle_proofs: None,
            finality_proof: None,
            committed_admission: None,
            role_assignment_v2: None,
            fraud_proofs: None,
            proposer_assignment: None,
            proposer_registrations: None,
        };
        let absent = ext.serialize();
        assert!(!absent.windows(4).any(|w| w == PROPOSER_REG_SECTION_MAGIC));
        assert_eq!(Phase20ReceiptExt::deserialize(&absent).unwrap(), ext);
        ext.proposer_registrations = Some(sec.clone());
        let present = ext.serialize();
        let extra = 1
            + 4
            + 2
            + sec.announces.len() * PROPOSER_REGISTRATION_V1_WIRE
            + 2
            + sec.activations.len() * PROPOSER_REGISTRATION_V1_WIRE;
        assert_eq!(present.len(), absent.len() + extra);
        let back = Phase20ReceiptExt::deserialize(&present).unwrap();
        assert_eq!(back.proposer_registrations, Some(sec));
        assert_eq!(back, ext);
    }

    #[test]
    fn phase20_ext_precommit_root_roundtrip_and_digest() {
        let prev = [0x44u8; 32];
        let base = || Phase20ReceiptExt {
            role_reward: RoleReward {
                compute_contributor_pkh: [0xC1u8; 20],
                verify_contributor_pkh: [0xC2u8; 20],
                support_contributor_pkh: [0xC3u8; 20],
            },
            compute_claim: fairness_valid_claim(1, 60, &prev, ROLE_COMPUTE_CONTRIBUTOR, 0),
            verify_claim: fairness_valid_claim(1, 60, &prev, ROLE_VERIFY_CONTRIBUTOR, 0),
            support_claim: fairness_valid_claim(1, 60, &prev, ROLE_SUPPORT_CONTRIBUTOR, 0),
            fee_bps: 0,
            fee_pkh: [0u8; 20],
            precommit_root: None,
            role_ticket_proofs: None,
            role_dominance_weights: None,
            candidate_set: None,
            role_puzzle_proofs: None,
            finality_proof: None,
            committed_admission: None,
            role_assignment_v2: None,
            fraud_proofs: None,
            proposer_assignment: None,
            proposer_registrations: None,
        };
        let none = base();
        let mut some = base();
        some.precommit_root = Some([0xABu8; 32]);
        // None is trailing-byte-free (byte-identical to pre-6A); Some adds flag(1)+32.
        assert_eq!(some.serialize().len(), none.serialize().len() + 33);
        assert_eq!(
            Phase20ReceiptExt::deserialize(&none.serialize()).unwrap(),
            none
        );
        assert_eq!(
            Phase20ReceiptExt::deserialize(&some.serialize()).unwrap(),
            some
        );
        // ext digest changes when precommit_root changes (G7).
        assert_ne!(none.digest(), some.digest());
        let mut some2 = base();
        some2.precommit_root = Some([0xCDu8; 32]);
        assert_ne!(some.digest(), some2.digest());
    }

    #[test]
    fn phase20_ext_ticket_section_roundtrip_backward_compatible() {
        let prev = [0x44u8; 32];
        let base = || Phase20ReceiptExt {
            role_reward: RoleReward {
                compute_contributor_pkh: [0xC1u8; 20],
                verify_contributor_pkh: [0xC2u8; 20],
                support_contributor_pkh: [0xC3u8; 20],
            },
            compute_claim: fairness_valid_claim(1, 60, &prev, ROLE_COMPUTE_CONTRIBUTOR, 0),
            verify_claim: fairness_valid_claim(1, 60, &prev, ROLE_VERIFY_CONTRIBUTOR, 0),
            support_claim: fairness_valid_claim(1, 60, &prev, ROLE_SUPPORT_CONTRIBUTOR, 0),
            fee_bps: 0,
            fee_pkh: [0u8; 20],
            precommit_root: None,
            role_ticket_proofs: None,
            role_dominance_weights: None,
            candidate_set: None,
            role_puzzle_proofs: None,
            finality_proof: None,
            committed_admission: None,
            role_assignment_v2: None,
            fraud_proofs: None,
            proposer_assignment: None,
            proposer_registrations: None,
        };
        let proofs = [
            TicketProof::new(
                1,
                60,
                [0u8; 32],
                ROLE_COMPUTE_CONTRIBUTOR,
                [0xC1u8; 20],
                1,
                200,
                [0x02u8; 33],
                [0x11u8; 32],
                0,
            ),
            TicketProof::new(
                1,
                60,
                [0u8; 32],
                ROLE_VERIFY_CONTRIBUTOR,
                [0xC2u8; 20],
                1,
                200,
                [0x02u8; 33],
                [0x12u8; 32],
                0,
            ),
            TicketProof::new(
                1,
                60,
                [0u8; 32],
                ROLE_SUPPORT_CONTRIBUTOR,
                [0xC3u8; 20],
                1,
                200,
                [0x02u8; 33],
                [0x13u8; 32],
                0,
            ),
        ];
        // (1) ticket ABSENT == byte-identical (no TPK1 magic; round-trips).
        let none = base();
        let none_bytes = none.serialize();
        assert!(
            none_bytes.windows(4).all(|w| w != TICKET_SECTION_MAGIC),
            "no ticket magic when absent"
        );
        assert_eq!(Phase20ReceiptExt::deserialize(&none_bytes).unwrap(), none);
        // (2) ticket PRESENT (precommit None): +1 precommit flag +4 magic +3*proof.
        let mut t = base();
        t.role_ticket_proofs = Some(proofs.clone());
        let tb = t.serialize();
        assert_eq!(tb.len(), none_bytes.len() + 1 + 4 + 3 * TICKET_PROOF_WIRE);
        assert_eq!(Phase20ReceiptExt::deserialize(&tb).unwrap(), t);
        assert_ne!(none.digest(), t.digest(), "ticket section changes digest");
        // (3) precommit Some + ticket Some round-trips.
        let mut pt = base();
        pt.precommit_root = Some([0xABu8; 32]);
        pt.role_ticket_proofs = Some(proofs.clone());
        assert_eq!(Phase20ReceiptExt::deserialize(&pt.serialize()).unwrap(), pt);
        // (4) precommit Some + ticket None unchanged (no magic).
        let mut p_only = base();
        p_only.precommit_root = Some([0xABu8; 32]);
        let pob = p_only.serialize();
        assert!(pob.windows(4).all(|w| w != TICKET_SECTION_MAGIC));
        assert_eq!(Phase20ReceiptExt::deserialize(&pob).unwrap(), p_only);
    }

    #[test]
    fn phase23a_ext_rejects_malformed_avr2_section() {
        use crate::poawx_candidate::AssignmentProofV2;
        let prev = [0x44u8; 32];
        let proofs = [
            AssignmentProofV2::prove(
                &[7u8; 32],
                1,
                61,
                ROLE_COMPUTE_CONTRIBUTOR,
                [0xC1u8; 20],
                [1u8; 32],
                [0x55u8; 32],
            )
            .unwrap(),
            AssignmentProofV2::prove(
                &[8u8; 32],
                1,
                61,
                ROLE_VERIFY_CONTRIBUTOR,
                [0xC2u8; 20],
                [2u8; 32],
                [0x55u8; 32],
            )
            .unwrap(),
            AssignmentProofV2::prove(
                &[9u8; 32],
                1,
                61,
                ROLE_SUPPORT_CONTRIBUTOR,
                [0xC3u8; 20],
                [3u8; 32],
                [0x55u8; 32],
            )
            .unwrap(),
        ];
        let ext = Phase20ReceiptExt {
            role_reward: RoleReward {
                compute_contributor_pkh: [0xC1u8; 20],
                verify_contributor_pkh: [0xC2u8; 20],
                support_contributor_pkh: [0xC3u8; 20],
            },
            compute_claim: fairness_valid_claim(1, 60, &prev, ROLE_COMPUTE_CONTRIBUTOR, 0),
            verify_claim: fairness_valid_claim(1, 60, &prev, ROLE_VERIFY_CONTRIBUTOR, 0),
            support_claim: fairness_valid_claim(1, 60, &prev, ROLE_SUPPORT_CONTRIBUTOR, 0),
            fee_bps: 0,
            fee_pkh: [0u8; 20],
            precommit_root: None,
            role_ticket_proofs: None,
            role_dominance_weights: None,
            candidate_set: None,
            role_puzzle_proofs: None,
            finality_proof: None,
            committed_admission: None,
            role_assignment_v2: Some(proofs),
            fraud_proofs: None,
            proposer_assignment: None,
            proposer_registrations: None,
        };
        let good = ext.serialize();
        assert_eq!(Phase20ReceiptExt::deserialize(&good).unwrap(), ext);
        // Truncated AVR2 section (drop the last byte) -> bounded deserialize rejects.
        assert!(
            Phase20ReceiptExt::deserialize(&good[..good.len() - 1]).is_err(),
            "truncated AVR2 rejects"
        );
        // Truncate one whole proof's worth (only 2 proofs present) -> rejects.
        assert!(
            Phase20ReceiptExt::deserialize(&good[..good.len() - ASSIGNMENT_PROOF_V2_WIRE]).is_err(),
            "missing third proof rejects"
        );
        // Oversized: stray trailing byte after a complete section -> unknown magic.
        let mut over = good.clone();
        over.push(0xAB);
        assert!(
            Phase20ReceiptExt::deserialize(&over).is_err(),
            "trailing junk rejects"
        );
    }

    #[test]
    fn phase22d_ext_true_vrf_section_roundtrip_backward_compatible() {
        use crate::poawx_candidate::{AssignmentProofV2, ASSIGNMENT_V2_SECTION_MAGIC};
        let prev = [0x44u8; 32];
        let base = || Phase20ReceiptExt {
            role_reward: RoleReward {
                compute_contributor_pkh: [0xC1u8; 20],
                verify_contributor_pkh: [0xC2u8; 20],
                support_contributor_pkh: [0xC3u8; 20],
            },
            compute_claim: fairness_valid_claim(1, 60, &prev, ROLE_COMPUTE_CONTRIBUTOR, 0),
            verify_claim: fairness_valid_claim(1, 60, &prev, ROLE_VERIFY_CONTRIBUTOR, 0),
            support_claim: fairness_valid_claim(1, 60, &prev, ROLE_SUPPORT_CONTRIBUTOR, 0),
            fee_bps: 0,
            fee_pkh: [0u8; 20],
            precommit_root: None,
            role_ticket_proofs: None,
            role_dominance_weights: None,
            candidate_set: None,
            role_puzzle_proofs: None,
            finality_proof: None,
            committed_admission: None,
            role_assignment_v2: None,
            fraud_proofs: None,
            proposer_assignment: None,
            proposer_registrations: None,
        };
        let seed = [0x55u8; 32];
        let mk = |secret: u8, role: u8, solver: [u8; 20]| {
            AssignmentProofV2::prove(&[secret; 32], 1, 61, role, solver, [role; 32], seed)
                .expect("v2 prove")
        };
        let proofs = [
            mk(7, ROLE_COMPUTE_CONTRIBUTOR, [0xC1u8; 20]),
            mk(8, ROLE_VERIFY_CONTRIBUTOR, [0xC2u8; 20]),
            mk(9, ROLE_SUPPORT_CONTRIBUTOR, [0xC3u8; 20]),
        ];
        // (1) absent => no AVR2 magic, byte-identical, round-trips.
        let none = base();
        let nb = none.serialize();
        assert!(
            nb.windows(4).all(|w| w != &ASSIGNMENT_V2_SECTION_MAGIC[..]),
            "no AVR2 magic when absent"
        );
        assert_eq!(Phase20ReceiptExt::deserialize(&nb).unwrap(), none);
        // (2) present => round-trips + changes the ext digest.
        let mut c = base();
        c.role_assignment_v2 = Some(proofs.clone());
        let cb = c.serialize();
        assert!(cb.windows(4).any(|w| w == &ASSIGNMENT_V2_SECTION_MAGIC[..]));
        assert_eq!(Phase20ReceiptExt::deserialize(&cb).unwrap(), c);
        assert_ne!(none.digest(), c.digest(), "true-VRF section changes digest");
        // (3) mutating a proof changes the ext digest.
        let mut c2 = base();
        let mut p2 = proofs.clone();
        p2[0].vrf_output[0] ^= 1;
        c2.role_assignment_v2 = Some(p2);
        assert_ne!(c.digest(), c2.digest(), "v2 mutation changes ext digest");
        // (4) together with a candidate set + committed admission round-trips.
        use crate::poawx_candidate::{CandidateSet, RoleCandidate};
        use crate::poawx_committed_admission::AdmissionCommitmentV1;
        use crate::poawx_penalty::PenaltyStatus;
        let mut cs = CandidateSet::new(1, 61, seed);
        cs.push(RoleCandidate::build(
            1,
            61,
            &seed,
            1,
            [0xC1u8; 20],
            [0x02u8; 33],
            [0x11u8; 32],
            PenaltyStatus::Clean.id(),
            1000,
            [0x21u8; 32],
        ));
        cs.sort_canonical();
        let ca = AdmissionCommitmentV1::from_candidate_set(&cs, 60);
        let mut all = base();
        all.candidate_set = Some(cs);
        all.committed_admission = Some(ca);
        all.role_assignment_v2 = Some(proofs);
        assert_eq!(
            Phase20ReceiptExt::deserialize(&all.serialize()).unwrap(),
            all
        );
    }

    #[test]
    fn phase22a_ext_committed_admission_roundtrip_backward_compatible() {
        use crate::poawx_candidate::{CandidateSet, RoleCandidate};
        use crate::poawx_committed_admission::{
            AdmissionCommitmentV1, COMMITTED_ADMISSION_SECTION_MAGIC,
        };
        use crate::poawx_penalty::PenaltyStatus;
        let prev = [0x44u8; 32];
        let base = || Phase20ReceiptExt {
            role_reward: RoleReward {
                compute_contributor_pkh: [0xC1u8; 20],
                verify_contributor_pkh: [0xC2u8; 20],
                support_contributor_pkh: [0xC3u8; 20],
            },
            compute_claim: fairness_valid_claim(1, 60, &prev, ROLE_COMPUTE_CONTRIBUTOR, 0),
            verify_claim: fairness_valid_claim(1, 60, &prev, ROLE_VERIFY_CONTRIBUTOR, 0),
            support_claim: fairness_valid_claim(1, 60, &prev, ROLE_SUPPORT_CONTRIBUTOR, 0),
            fee_bps: 0,
            fee_pkh: [0u8; 20],
            precommit_root: None,
            role_ticket_proofs: None,
            role_dominance_weights: None,
            candidate_set: None,
            role_puzzle_proofs: None,
            finality_proof: None,
            committed_admission: None,
            role_assignment_v2: None,
            fraud_proofs: None,
            proposer_assignment: None,
            proposer_registrations: None,
        };
        let seed = [0x55u8; 32];
        let mut cs = CandidateSet::new(1, 61, seed);
        cs.push(RoleCandidate::build(
            1,
            61,
            &seed,
            1,
            [0xC1u8; 20],
            [0x02u8; 33],
            [0x11u8; 32],
            PenaltyStatus::Clean.id(),
            1000,
            [0x21u8; 32],
        ));
        cs.sort_canonical();
        let ca = AdmissionCommitmentV1::from_candidate_set(&cs, 60);
        // (1) absent => no CAC1 magic, byte-identical, round-trips.
        let none = base();
        let nb = none.serialize();
        assert!(
            nb.windows(4)
                .all(|w| w != &COMMITTED_ADMISSION_SECTION_MAGIC[..]),
            "no CAC1 magic when absent"
        );
        assert_eq!(Phase20ReceiptExt::deserialize(&nb).unwrap(), none);
        // (2) present => round-trips + changes the ext digest.
        let mut c = base();
        c.committed_admission = Some(ca.clone());
        assert_eq!(Phase20ReceiptExt::deserialize(&c.serialize()).unwrap(), c);
        assert_ne!(
            none.digest(),
            c.digest(),
            "committed-admission section changes digest"
        );
        // (3) mutation changes the ext digest.
        let mut c2 = base();
        let mut ca2 = ca.clone();
        ca2.candidate_admission_root[0] ^= 1;
        ca2.digest = ca2.digest; // (digest stays; mutating root still changes serialized bytes)
        c2.committed_admission = Some(ca2);
        assert_ne!(
            c.digest(),
            c2.digest(),
            "commitment mutation changes ext digest"
        );
        // (4) committed admission together with candidate set + finality round-trips.
        let mut all = base();
        all.candidate_set = Some(cs.clone());
        all.committed_admission = Some(ca);
        let ab = all.serialize();
        assert!(ab
            .windows(4)
            .any(|w| w == &COMMITTED_ADMISSION_SECTION_MAGIC[..]));
        assert_eq!(Phase20ReceiptExt::deserialize(&ab).unwrap(), all);
    }

    #[test]
    fn phase21h_ext_finality_section_roundtrip_backward_compatible() {
        use crate::poawx_finality::{FinalityProofV1, FinalityVoteType, FinalityVoteV1};
        let prev = [0x44u8; 32];
        let base = || Phase20ReceiptExt {
            role_reward: RoleReward {
                compute_contributor_pkh: [0xC1u8; 20],
                verify_contributor_pkh: [0xC2u8; 20],
                support_contributor_pkh: [0xC3u8; 20],
            },
            compute_claim: fairness_valid_claim(1, 60, &prev, ROLE_COMPUTE_CONTRIBUTOR, 0),
            verify_claim: fairness_valid_claim(1, 60, &prev, ROLE_VERIFY_CONTRIBUTOR, 0),
            support_claim: fairness_valid_claim(1, 60, &prev, ROLE_SUPPORT_CONTRIBUTOR, 0),
            fee_bps: 0,
            fee_pkh: [0u8; 20],
            precommit_root: None,
            role_ticket_proofs: None,
            role_dominance_weights: None,
            candidate_set: None,
            role_puzzle_proofs: None,
            finality_proof: None,
            committed_admission: None,
            role_assignment_v2: None,
            fraud_proofs: None,
            proposer_assignment: None,
            proposer_registrations: None,
        };
        let sk = k256::ecdsa::SigningKey::from_slice(&[0x21u8; 32]).unwrap();
        let mut fp = FinalityProofV1::new(1, 60, prev, [0u8; 32], 0, 1, 1);
        fp.push(FinalityVoteV1::signed(
            &sk,
            1,
            60,
            prev,
            [0u8; 32],
            0,
            [0x11u8; 32],
            FinalityVoteType::Commit,
        ));
        fp.sort_canonical();
        // (1) absent => no FIN1 magic, byte-identical, round-trips.
        let none = base();
        let nb = none.serialize();
        assert!(
            nb.windows(4)
                .all(|w| w != &crate::poawx_finality::FINALITY_SECTION_MAGIC[..]),
            "no FIN1 magic when absent"
        );
        assert_eq!(Phase20ReceiptExt::deserialize(&nb).unwrap(), none);
        // (2) present => round-trips and changes the ext digest.
        let mut p = base();
        p.finality_proof = Some(fp.clone());
        assert_eq!(Phase20ReceiptExt::deserialize(&p.serialize()).unwrap(), p);
        assert_ne!(
            none.digest(),
            p.digest(),
            "finality section changes ext digest"
        );
        // (3) mutation changes the ext digest.
        let mut p2 = base();
        let mut fp2 = fp.clone();
        fp2.votes[0].signature[0] ^= 1;
        p2.finality_proof = Some(fp2);
        assert_ne!(
            p.digest(),
            p2.digest(),
            "finality mutation changes ext digest"
        );
        // (4) finality together with candidate set + puzzle round-trips.
        let mut all = base();
        all.role_dominance_weights = Some([1000, 900, 800, 700]);
        all.finality_proof = Some(fp);
        let ab = all.serialize();
        assert!(ab
            .windows(4)
            .any(|w| w == &crate::poawx_finality::FINALITY_SECTION_MAGIC[..]));
        assert_eq!(Phase20ReceiptExt::deserialize(&ab).unwrap(), all);
    }

    #[test]
    fn phase21f_ext_puzzle_section_roundtrip_backward_compatible() {
        use crate::poawx_puzzle::{PuzzleSolutionV1, PUZZLE_SECTION_MAGIC};
        let prev = [0x44u8; 32];
        let base = || Phase20ReceiptExt {
            role_reward: RoleReward {
                compute_contributor_pkh: [0xC1u8; 20],
                verify_contributor_pkh: [0xC2u8; 20],
                support_contributor_pkh: [0xC3u8; 20],
            },
            compute_claim: fairness_valid_claim(1, 60, &prev, ROLE_COMPUTE_CONTRIBUTOR, 0),
            verify_claim: fairness_valid_claim(1, 60, &prev, ROLE_VERIFY_CONTRIBUTOR, 0),
            support_claim: fairness_valid_claim(1, 60, &prev, ROLE_SUPPORT_CONTRIBUTOR, 0),
            fee_bps: 0,
            fee_pkh: [0u8; 20],
            precommit_root: None,
            role_ticket_proofs: None,
            role_dominance_weights: None,
            candidate_set: None,
            role_puzzle_proofs: None,
            finality_proof: None,
            committed_admission: None,
            role_assignment_v2: None,
            fraud_proofs: None,
            proposer_assignment: None,
            proposer_registrations: None,
        };
        let sol = |m: u8, n: u64, t: u8| PuzzleSolutionV1 {
            mode: m,
            nonce: n,
            proof_digest: [t; 32],
        };
        let proofs = [sol(0, 1, 0x10), sol(1, 2, 0x20), sol(2, 3, 0x30)];
        // (1) absent => no PZL1 magic, byte-identical, round-trips.
        let none = base();
        let nb = none.serialize();
        assert!(
            nb.windows(4).all(|w| w != &PUZZLE_SECTION_MAGIC[..]),
            "no PZL1 magic when absent"
        );
        assert_eq!(Phase20ReceiptExt::deserialize(&nb).unwrap(), none);
        // (2) present => round-trips and changes the digest (bound into ext digest).
        let mut p = base();
        p.role_puzzle_proofs = Some(proofs);
        assert_eq!(Phase20ReceiptExt::deserialize(&p.serialize()).unwrap(), p);
        assert_ne!(
            none.digest(),
            p.digest(),
            "puzzle section changes ext digest"
        );
        // (3) mutation changes the ext digest.
        let mut p2 = base();
        let mut m = proofs;
        m[0].nonce ^= 1;
        p2.role_puzzle_proofs = Some(m);
        assert_ne!(
            p.digest(),
            p2.digest(),
            "puzzle mutation changes ext digest"
        );
        // (4) puzzle together with candidate set round-trips.
        let mut cd = base();
        cd.role_dominance_weights = Some([1000, 900, 800, 700]);
        cd.role_puzzle_proofs = Some(proofs);
        let cdb = cd.serialize();
        assert!(cdb.windows(4).any(|w| w == &PUZZLE_SECTION_MAGIC[..]));
        assert_eq!(Phase20ReceiptExt::deserialize(&cdb).unwrap(), cd);
    }

    #[test]
    fn phase21d_ext_candidate_section_roundtrip_backward_compatible() {
        use crate::poawx_candidate::{CandidateSet, RoleCandidate, CANDIDATE_SECTION_MAGIC};
        use crate::poawx_penalty::PenaltyStatus;
        let prev = [0x44u8; 32];
        let base = || Phase20ReceiptExt {
            role_reward: RoleReward {
                compute_contributor_pkh: [0xC1u8; 20],
                verify_contributor_pkh: [0xC2u8; 20],
                support_contributor_pkh: [0xC3u8; 20],
            },
            compute_claim: fairness_valid_claim(1, 60, &prev, ROLE_COMPUTE_CONTRIBUTOR, 0),
            verify_claim: fairness_valid_claim(1, 60, &prev, ROLE_VERIFY_CONTRIBUTOR, 0),
            support_claim: fairness_valid_claim(1, 60, &prev, ROLE_SUPPORT_CONTRIBUTOR, 0),
            fee_bps: 0,
            fee_pkh: [0u8; 20],
            precommit_root: None,
            role_ticket_proofs: None,
            role_dominance_weights: None,
            candidate_set: None,
            role_puzzle_proofs: None,
            finality_proof: None,
            committed_admission: None,
            role_assignment_v2: None,
            fraud_proofs: None,
            proposer_assignment: None,
            proposer_registrations: None,
        };
        let mut cs = CandidateSet::new(1, 60, prev);
        cs.push(RoleCandidate::build(
            1,
            60,
            &prev,
            ROLE_COMPUTE_CONTRIBUTOR,
            [0xC1u8; 20],
            [0x02u8; 33],
            [0x11u8; 32],
            PenaltyStatus::Clean.id(),
            1000,
            [0x21u8; 32],
        ));
        cs.sort_canonical();
        // (1) absent => no CND1 magic, byte-identical, round-trips.
        let none = base();
        let nb = none.serialize();
        assert!(
            nb.windows(4).all(|w| w != &CANDIDATE_SECTION_MAGIC[..]),
            "no CND1 magic when absent"
        );
        assert_eq!(Phase20ReceiptExt::deserialize(&nb).unwrap(), none);
        // (2) present => round-trips and changes the digest.
        let mut c = base();
        c.candidate_set = Some(cs.clone());
        assert_eq!(Phase20ReceiptExt::deserialize(&c.serialize()).unwrap(), c);
        assert_ne!(
            none.digest(),
            c.digest(),
            "candidate section changes digest"
        );
        // (3) candidate-set mutation changes the ext digest.
        let mut c2 = base();
        let mut cs2 = cs.clone();
        cs2.candidates[0].effective_score ^= 1;
        c2.candidate_set = Some(cs2);
        assert_ne!(
            c.digest(),
            c2.digest(),
            "candidate mutation changes ext digest"
        );
        // (4) candidate together with dominance weights round-trips.
        let mut cd = base();
        cd.role_dominance_weights = Some([1000, 900, 800, 700]);
        cd.candidate_set = Some(cs.clone());
        let cdb = cd.serialize();
        assert!(cdb.windows(4).any(|w| w == &CANDIDATE_SECTION_MAGIC[..]));
        assert_eq!(Phase20ReceiptExt::deserialize(&cdb).unwrap(), cd);
    }

    #[test]
    fn phase21c_ext_dominance_section_roundtrip_backward_compatible() {
        let prev = [0x44u8; 32];
        let base = || Phase20ReceiptExt {
            role_reward: RoleReward {
                compute_contributor_pkh: [0xC1u8; 20],
                verify_contributor_pkh: [0xC2u8; 20],
                support_contributor_pkh: [0xC3u8; 20],
            },
            compute_claim: fairness_valid_claim(1, 60, &prev, ROLE_COMPUTE_CONTRIBUTOR, 0),
            verify_claim: fairness_valid_claim(1, 60, &prev, ROLE_VERIFY_CONTRIBUTOR, 0),
            support_claim: fairness_valid_claim(1, 60, &prev, ROLE_SUPPORT_CONTRIBUTOR, 0),
            fee_bps: 0,
            fee_pkh: [0u8; 20],
            precommit_root: None,
            role_ticket_proofs: None,
            role_dominance_weights: None,
            candidate_set: None,
            role_puzzle_proofs: None,
            finality_proof: None,
            committed_admission: None,
            role_assignment_v2: None,
            fraud_proofs: None,
            proposer_assignment: None,
            proposer_registrations: None,
        };
        let weights = [1000u64, 800, 900, 950];
        // (1) absent => no DOM1 magic, byte-identical, round-trips.
        let none = base();
        let nb = none.serialize();
        assert!(
            nb.windows(4).all(|w| w != DOMINANCE_SECTION_MAGIC),
            "no DOM1 magic when absent"
        );
        assert_eq!(Phase20ReceiptExt::deserialize(&nb).unwrap(), none);
        // (2) dominance present (precommit + ticket None): +1 flag +4 magic +32 bytes.
        let mut d = base();
        d.role_dominance_weights = Some(weights);
        let db = d.serialize();
        assert_eq!(db.len(), nb.len() + 1 + 4 + DOMINANCE_WEIGHTS_WIRE);
        assert_eq!(Phase20ReceiptExt::deserialize(&db).unwrap(), d);
        assert_ne!(
            none.digest(),
            d.digest(),
            "dominance section changes digest"
        );
        // (3) precommit + dominance round-trips.
        let mut pd = base();
        pd.precommit_root = Some([0xABu8; 32]);
        pd.role_dominance_weights = Some(weights);
        assert_eq!(Phase20ReceiptExt::deserialize(&pd.serialize()).unwrap(), pd);
        // (4) ticket + dominance (both sections) round-trips in order.
        let proofs = [
            TicketProof::new(
                1,
                60,
                [0u8; 32],
                ROLE_COMPUTE_CONTRIBUTOR,
                [0xC1u8; 20],
                1,
                200,
                [0x02u8; 33],
                [0x11u8; 32],
                0,
            ),
            TicketProof::new(
                1,
                60,
                [0u8; 32],
                ROLE_VERIFY_CONTRIBUTOR,
                [0xC2u8; 20],
                1,
                200,
                [0x02u8; 33],
                [0x12u8; 32],
                0,
            ),
            TicketProof::new(
                1,
                60,
                [0u8; 32],
                ROLE_SUPPORT_CONTRIBUTOR,
                [0xC3u8; 20],
                1,
                200,
                [0x02u8; 33],
                [0x13u8; 32],
                0,
            ),
        ];
        let mut td = base();
        td.role_ticket_proofs = Some(proofs);
        td.role_dominance_weights = Some(weights);
        let tdb = td.serialize();
        assert!(tdb.windows(4).any(|w| w == TICKET_SECTION_MAGIC));
        assert!(tdb.windows(4).any(|w| w == DOMINANCE_SECTION_MAGIC));
        assert_eq!(Phase20ReceiptExt::deserialize(&tdb).unwrap(), td);
        // (5) unknown trailing magic is rejected (strict).
        let mut junk = d.serialize();
        junk.extend_from_slice(b"ZZZZ");
        assert!(
            Phase20ReceiptExt::deserialize(&junk).is_err(),
            "unknown trailing magic rejects"
        );
    }

    #[test]
    fn phase20_block_receipt_v3_element_roundtrip() {
        let prev = [0x44u8; 32];
        let mk_ext = || Phase20ReceiptExt {
            role_reward: RoleReward {
                compute_contributor_pkh: [0xC1u8; 20],
                verify_contributor_pkh: [0xC2u8; 20],
                support_contributor_pkh: [0xC3u8; 20],
            },
            compute_claim: fairness_valid_claim(1, 60, &prev, ROLE_COMPUTE_CONTRIBUTOR, 0),
            verify_claim: fairness_valid_claim(1, 60, &prev, ROLE_VERIFY_CONTRIBUTOR, 0),
            support_claim: fairness_valid_claim(1, 60, &prev, ROLE_SUPPORT_CONTRIBUTOR, 0),
            fee_bps: 0,
            fee_pkh: [0u8; 20],
            precommit_root: None,
            role_ticket_proofs: None,
            role_dominance_weights: None,
            candidate_set: None,
            role_puzzle_proofs: None,
            finality_proof: None,
            committed_admission: None,
            role_assignment_v2: None,
            fraud_proofs: None,
            proposer_assignment: None,
            proposer_registrations: None,
        };
        // no-ext v3 element == v2 element + a single 0 flag byte (present-only).
        let r = make_test_receipt(9);
        assert!(r.phase20_ext.is_none());
        let mut expect = r.serialize_v2();
        expect.push(0);
        assert_eq!(r.serialize_v3(), expect);
        let (r0, used0) = PoawxBlockReceipt::deserialize_v3(&r.serialize_v3()).unwrap();
        assert_eq!(r0, r);
        assert_eq!(used0, r.serialize_v3().len());
        // with-ext v3 element round-trips and preserves the extension.
        let mut r2 = make_test_receipt(9);
        r2.phase20_ext = Some(mk_ext());
        let bytes = r2.serialize_v3();
        let (r3, used) = PoawxBlockReceipt::deserialize_v3(&bytes).unwrap();
        assert_eq!(r3, r2);
        assert_eq!(r3.phase20_ext, Some(mk_ext()));
        assert_eq!(used, bytes.len());
    }

    #[test]
    fn phase20_root_gating_and_mutation_sensitivity() {
        let prev = [0x44u8; 32];
        let mk_ext = |fee_bps: u16, fee_pkh: [u8; 20]| Phase20ReceiptExt {
            role_reward: RoleReward {
                compute_contributor_pkh: [0xC1u8; 20],
                verify_contributor_pkh: [0xC2u8; 20],
                support_contributor_pkh: [0xC3u8; 20],
            },
            compute_claim: fairness_valid_claim(1, 60, &prev, ROLE_COMPUTE_CONTRIBUTOR, 0),
            verify_claim: fairness_valid_claim(1, 60, &prev, ROLE_VERIFY_CONTRIBUTOR, 0),
            support_claim: fairness_valid_claim(1, 60, &prev, ROLE_SUPPORT_CONTRIBUTOR, 0),
            fee_bps,
            fee_pkh,
            precommit_root: None,
            role_ticket_proofs: None,
            role_dominance_weights: None,
            candidate_set: None,
            role_puzzle_proofs: None,
            finality_proof: None,
            committed_admission: None,
            role_assignment_v2: None,
            fraud_proofs: None,
            proposer_assignment: None,
            proposer_registrations: None,
        };

        // Base mode-0 receipt with a production extension attached.
        let mut r = make_test_receipt(7);
        r.phase20_ext = Some(mk_ext(0, [0u8; 20]));

        // Gate OFF: the extension is ignored -> byte-identical to the no-ext root
        // and to the public wrapper (old behavior unchanged before activation).
        let mut r_no_ext = make_test_receipt(7);
        r_no_ext.phase20_ext = None;
        assert_eq!(
            irx1_root_from_block_receipts_gated(&[r.clone()], false),
            irx1_root_from_block_receipts(&[r_no_ext]),
            "gate off: extension must not affect the root"
        );
        assert_eq!(
            irx1_root_from_block_receipts_gated(&[r.clone()], false),
            irx1_root_from_block_receipts(&[r.clone()]),
            "wrapper must equal gated(false)"
        );

        // Gate ON: the extension contributes -> root differs from the gate-off root,
        // and is deterministic across calls.
        let base = irx1_root_from_block_receipts_gated(&[r.clone()], true);
        assert_ne!(
            base,
            irx1_root_from_block_receipts_gated(&[r.clone()], false),
            "gate on: extension must change the root"
        );
        assert_eq!(
            base,
            irx1_root_from_block_receipts_gated(&[r.clone()], true)
        );

        // Mutating ANY extension field changes the gated-on root.
        let mut m = r.clone();
        m.phase20_ext.as_mut().unwrap().compute_claim.lane_id ^= 0x01;
        assert_ne!(
            base,
            irx1_root_from_block_receipts_gated(&[m], true),
            "role claim mutation must change root"
        );
        let mut m = r.clone();
        m.phase20_ext
            .as_mut()
            .unwrap()
            .role_reward
            .support_contributor_pkh = [0xDEu8; 20];
        assert_ne!(
            base,
            irx1_root_from_block_receipts_gated(&[m], true),
            "RoleReward mutation must change root"
        );
        let mut m = r.clone();
        m.phase20_ext.as_mut().unwrap().fee_bps = 200;
        assert_ne!(
            base,
            irx1_root_from_block_receipts_gated(&[m], true),
            "fee_bps mutation must change root"
        );
        let mut m = r.clone();
        m.phase20_ext.as_mut().unwrap().fee_pkh = [0xFEu8; 20];
        assert_ne!(
            base,
            irx1_root_from_block_receipts_gated(&[m], true),
            "fee_pkh mutation must change root"
        );

        // Malformed extension bytes fail to deserialize (fail-closed at the wire).
        assert!(Phase20ReceiptExt::deserialize(&[]).is_err());
        let good = mk_ext(0, [0u8; 20]).serialize();
        assert!(
            Phase20ReceiptExt::deserialize(&good[..good.len() - 1]).is_err(),
            "truncated extension must fail to deserialize"
        );
    }

    #[test]
    fn phase13a_receipt_wire_size_is_166() {
        assert_eq!(PoawxBlockReceipt::WIRE_SIZE, 166);
        let r = make_test_receipt(1);
        assert_eq!(r.serialize().len(), 166);
    }

    #[test]
    fn phase13a_receipt_truncated_deserialize_fails() {
        let r = make_test_receipt(1);
        let bytes = r.serialize();
        // Truncate by 1 byte — must error.
        assert!(
            PoawxBlockReceipt::deserialize(&bytes[..165]).is_err(),
            "truncated bytes must fail to deserialize"
        );
        // Empty slice — must also error.
        assert!(PoawxBlockReceipt::deserialize(&[]).is_err());
    }

    #[test]
    fn phase13a_receipt_section_magic_length() {
        assert_eq!(POAWX_RECEIPT_SECTION_MAGIC.len(), 8);
    }

    // ── Phase 18B delegated-receipt primitive tests ──────────────────────

    fn test_sk() -> k256::ecdsa::SigningKey {
        k256::ecdsa::SigningKey::from_slice(&[7u8; 32]).expect("valid sk")
    }

    fn miner_pubkey_from(sk: &k256::ecdsa::SigningKey) -> [u8; 33] {
        let vk = k256::ecdsa::VerifyingKey::from(sk);
        let enc = vk.to_encoded_point(true);
        let mut pk = [0u8; 33];
        pk.copy_from_slice(enc.as_bytes());
        pk
    }

    fn make_signed_delegation(sk: &k256::ecdsa::SigningKey, fee_bps: u16) -> Delegation {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        let mut d = Delegation {
            deleg_version: Delegation::VERSION,
            network_id: 1,
            miner_pubkey: miner_pubkey_from(sk),
            pool_pubkey: [0x02u8; 33],
            worker_tag: [0xaau8; 32],
            expiry_height: 1000,
            fee_bps,
            fee_pkh: [0u8; 20],
            deleg_nonce: [0xcdu8; 32],
            proposer_pubkey: [0u8; 33],
            delegation_sig: [0u8; 64],
        };
        let sig: k256::ecdsa::Signature = sk.sign_prehash(&d.message_hash()).unwrap();
        d.delegation_sig.copy_from_slice(&sig.to_bytes());
        d
    }

    fn mode1_receipt(height: u64, d: Delegation) -> PoawxBlockReceipt {
        let mut r = make_test_receipt(height);
        r.delegation = Some(d);
        r
    }

    #[test]
    fn phase18b_delegation_roundtrip() {
        let sk = test_sk();
        let d = make_signed_delegation(&sk, 0);
        let bytes = d.serialize();
        assert_eq!(Delegation::WIRE_SIZE_V1, 226);
        assert_eq!(Delegation::WIRE_SIZE, 259);
        assert_eq!(bytes.len(), Delegation::WIRE_SIZE);
        let d2 = Delegation::deserialize(&bytes).expect("deserialize");
        assert_eq!(d, d2);
    }

    #[test]
    fn phase18b_delegation_truncated_fails() {
        let sk = test_sk();
        let d = make_signed_delegation(&sk, 0);
        let bytes = d.serialize();
        assert!(Delegation::deserialize(&bytes[..225]).is_err());
        assert!(Delegation::deserialize(&[]).is_err());
    }

    #[test]
    fn phase18b_delegation_signature_verifies_and_tamper_fails() {
        let sk = test_sk();
        let d = make_signed_delegation(&sk, 0);
        assert!(d.verify_signature().is_ok());
        let mut t = d.clone();
        t.expiry_height ^= 1;
        assert!(t.verify_signature().is_err(), "tampered expiry must fail");
        let mut t2 = d.clone();
        t2.pool_pubkey[0] ^= 0xff;
        assert!(
            t2.verify_signature().is_err(),
            "tampered pool_pubkey must fail"
        );
    }

    #[test]
    fn phase18b_delegation_miner_pkh_matches_pubkey() {
        let sk = test_sk();
        let d = make_signed_delegation(&sk, 0);
        let pkh = d.miner_pkh();
        let sha = Sha256::digest(d.miner_pubkey);
        let rip = ripemd::Ripemd160::digest(sha);
        assert_eq!(&pkh[..], &rip[..]);
    }

    #[test]
    fn phase18b_message_hash_excludes_sig() {
        let sk = test_sk();
        let d = make_signed_delegation(&sk, 0);
        let h1 = d.message_hash();
        let mut d2 = d.clone();
        d2.delegation_sig = [0xffu8; 64];
        assert_eq!(h1, d2.message_hash(), "sig must not affect message_hash");
    }

    #[test]
    fn phase18b_digest_changes_with_any_field() {
        let sk = test_sk();
        let d = make_signed_delegation(&sk, 0);
        let base = d.digest();
        let mut a = d.clone();
        a.network_id ^= 1;
        assert_ne!(base, a.digest());
        let mut b = d.clone();
        b.fee_bps ^= 1;
        assert_ne!(base, b.digest());
        let mut c = d.clone();
        c.deleg_nonce[0] ^= 1;
        assert_ne!(base, c.digest());
        let mut e = d.clone();
        e.delegation_sig[0] ^= 1;
        assert_ne!(base, e.digest(), "digest must cover the signature too");
    }

    #[test]
    fn phase18b_mode0_root_unchanged() {
        let r = make_test_receipt(5);
        let got = irx1_root_from_block_receipts(&[r.clone()]);
        let expected: [u8; 32] = {
            let mut inner = Sha256::new();
            inner.update(r.height.to_le_bytes());
            inner.update([r.lane]);
            inner.update(r.worker_pkh);
            inner.update(r.solution);
            inner.update(r.commitment_nonce);
            let mut outer = Sha256::new();
            outer.update(inner.finalize());
            outer.finalize().into()
        };
        assert_eq!(
            got, expected,
            "mode-0 root must be byte-identical to Phase 13-A"
        );
    }

    #[test]
    fn phase18b_mode1_root_includes_delegation_digest() {
        let sk = test_sk();
        let d = make_signed_delegation(&sk, 0);
        let r0 = make_test_receipt(5);
        let r1 = mode1_receipt(5, d);
        assert_ne!(
            irx1_root_from_block_receipts(&[r0]),
            irx1_root_from_block_receipts(&[r1.clone()]),
            "mode-1 root must differ from mode-0 with same base fields"
        );
        let expected: [u8; 32] = {
            let mut inner = Sha256::new();
            inner.update(r1.height.to_le_bytes());
            inner.update([r1.lane]);
            inner.update(r1.worker_pkh);
            inner.update(r1.solution);
            inner.update(r1.commitment_nonce);
            inner.update(r1.delegation.as_ref().unwrap().digest());
            let mut outer = Sha256::new();
            outer.update(inner.finalize());
            outer.finalize().into()
        };
        assert_eq!(irx1_root_from_block_receipts(&[r1]), expected);
    }

    #[test]
    fn phase18b_v2_mode0_roundtrip() {
        let r = make_test_receipt(9);
        let bytes = r.serialize_v2();
        assert_eq!(bytes.len(), 1 + PoawxBlockReceipt::WIRE_SIZE);
        assert_eq!(bytes[0], RECEIPT_MODE_DIRECT);
        let (r2, used) = PoawxBlockReceipt::deserialize_v2(&bytes).expect("v2 de");
        assert_eq!(used, bytes.len());
        assert_eq!(r, r2);
        assert!(r2.delegation.is_none());
    }

    #[test]
    fn phase18b_v2_mode1_roundtrip() {
        let sk = test_sk();
        let d = make_signed_delegation(&sk, 0);
        let r = mode1_receipt(9, d);
        let bytes = r.serialize_v2();
        assert_eq!(
            bytes.len(),
            1 + PoawxBlockReceipt::WIRE_SIZE + Delegation::WIRE_SIZE
        );
        assert_eq!(bytes[0], RECEIPT_MODE_DELEGATED);
        let (r2, used) = PoawxBlockReceipt::deserialize_v2(&bytes).expect("v2 de");
        assert_eq!(used, bytes.len());
        assert_eq!(r, r2);
        assert!(r2.delegation.is_some());
    }

    #[test]
    fn phase18b_v2_mixed_stream_roundtrip() {
        let sk = test_sk();
        let d = make_signed_delegation(&sk, 0);
        let r0 = make_test_receipt(1);
        let r1 = mode1_receipt(2, d);
        let mut stream = Vec::new();
        stream.extend_from_slice(&r0.serialize_v2());
        stream.extend_from_slice(&r1.serialize_v2());
        let (a, ua) = PoawxBlockReceipt::deserialize_v2(&stream).unwrap();
        let (b, _ub) = PoawxBlockReceipt::deserialize_v2(&stream[ua..]).unwrap();
        assert_eq!(a, r0);
        assert_eq!(b, r1);
    }

    #[test]
    fn phase18b_v2_unknown_mode_and_truncation_fail() {
        let sk = test_sk();
        let d = make_signed_delegation(&sk, 0);
        let r = mode1_receipt(3, d);
        let mut bytes = r.serialize_v2();
        assert!(PoawxBlockReceipt::deserialize_v2(&bytes[..bytes.len() - 1]).is_err());
        bytes[0] = 0x09;
        assert!(PoawxBlockReceipt::deserialize_v2(&bytes).is_err());
    }
}
