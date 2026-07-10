//! Phase 24K/24L: Irium-native PoAW-X all-gates mining submit harness (helpers).
//!
//! Phase 24J proved the remaining blocker for a real all-gates block was mining
//! TOOLING, not PoAW-X consensus: stock cpuminer/minerd hashes a standard
//! Bitcoin 80-byte header with `sha256d`, but Irium hashes the block header via
//! [`crate::block::BlockHeader::hash_for_height`] (a height-bound serialization),
//! so minerd's shares never match Irium's PoW target. The fix is to mine with
//! Irium's ACTUAL PoW hash.
//!
//! This module provides the small, reusable primitives a live harness
//! (in-process tests and the explicit `poawx-live-proof-harness` binary for the
//! Phase 24L Windows live proof) needs to produce a real all-gates block:
//!   * [`guard_network`] — accept the known Irium network ids and reject unknown
//!     ids.
//!   * [`guard_isolated_storage`] — refuse missing/default/`/tmp` runtime
//!     storage; require an explicit isolated dir that is NOT the production
//!     default (`$HOME/.irium` on Unix, `%USERPROFILE%\.irium` on Windows).
//!   * [`mine_pow`] — grind the header nonce using Irium's REAL PoW path. This
//!     NEVER touches LWMA / difficulty / target logic.
//!   * [`build_devnet_all_gates_block`] — assemble a complete all-gates block
//!     (admissions + candidate set + puzzle + finality + committed admission +
//!     true-VRF + canonical 0%-fee coinbase + mined PoW) from public APIs. Used
//!     by the live-proof binary AND validated end-to-end by a `connect_block`
//!     test (so the binary's exact construction is proven node-acceptable).
//!
//! Nothing here prints private keys, seeds, or VRF secrets. Harness keys are
//! deterministic for test/dev paths; live mining supplies external key material.

use crate::block::{Block, BlockHeader};
use crate::constants::block_reward;
use crate::poawx::{
    count_leading_zero_bits, multi_role_amounts,
    Phase20ReceiptExt, PoawxBlockReceipt, PoawxRoleClaim, RoleReward, ROLE_COMPUTE_CONTRIBUTOR,
    ROLE_SUPPORT_CONTRIBUTOR, ROLE_VERIFY_CONTRIBUTOR,
};
use crate::poawx_admission::CandidateAdmissionV1;
use crate::poawx_candidate::{AssignmentProofV2, CandidateSet, RoleCandidate};
use crate::poawx_committed_admission::{admission_epoch_seed, AdmissionCommitmentV1};
use crate::poawx_dominance::{PersistentDominance, RoleRewardKind, DOMINANCE_BASE_WORK_SCORE};
use crate::poawx_finality::{
    finality_threshold, FinalityProofV1, FinalityVoteType, FinalityVoteV1,
};
use crate::poawx_penalty::PenaltyStatus;
use crate::poawx_puzzle::{default_profile, solve_dev, PuzzleChallengeV1};
use crate::pow::{meets_target, sha256d, Target};
use crate::tx::{p2pkh_script, Transaction, TxInput, TxOutput};
use k256::ecdsa::SigningKey;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use std::path::Path;

/// Accept only known Irium network ids. Mainnet is `network_id == 0`
/// ([`crate::activation::NetworkKind::id_byte`]), testnet is 1, and devnet is 2.
/// The caller MUST pass the resolved network id.
pub fn guard_network(network_id: u8) -> Result<(), String> {
    match network_id {
        0 | 1 | 2 => Ok(()),
        other => Err(format!(
            "poawx mining harness: unknown network_id {other}; require mainnet(0)/testnet(1)/devnet(2)"
        )),
    }
}

/// Refuse to use runtime storage unless it is an EXPLICIT isolated directory.
///
/// `None` (no dir chosen) is rejected. A `/tmp` path is rejected. The production
/// default dir is rejected on BOTH platforms: `$HOME/.irium` (Unix) and
/// `%USERPROFILE%\.irium` (Windows), plus any path whose final component is
/// `.irium` directly under the home dir. Fails closed before touching disk.
pub fn guard_isolated_storage(dir: Option<&Path>) -> Result<(), String> {
    let dir = dir.ok_or_else(|| {
        "poawx mining harness: runtime storage requires an explicit isolated dir \
         (none provided)"
            .to_string()
    })?;
    if dir.starts_with("/tmp") {
        return Err(format!(
            "poawx mining harness: refusing /tmp storage dir {}",
            dir.display()
        ));
    }
    // Reject the production default `.irium` dir under the user's home on either
    // platform (HOME on Unix, USERPROFILE on Windows).
    for var in ["HOME", "USERPROFILE"] {
        if let Ok(home) = std::env::var(var) {
            if home.is_empty() {
                continue;
            }
            let home = Path::new(&home);
            if dir == home.join(".irium") {
                return Err(format!(
                    "poawx mining harness: refusing the production default dir {} \
                     (use an explicit isolated dir)",
                    dir.display()
                ));
            }
            if dir.parent() == Some(home)
                && dir.file_name().and_then(|s| s.to_str()) == Some(".irium")
            {
                return Err(format!(
                    "poawx mining harness: refusing a home/.irium default dir {}",
                    dir.display()
                ));
            }
        }
    }
    Ok(())
}

/// Mine Irium's REAL proof-of-work for `header` at `height`: search the nonce
/// space `[0, max_iters)` until `hash_for_height(height)` satisfies `target`
/// (the EXACT check `validate_block_header` performs). On success the header's
/// `nonce` is set and the winning nonce is returned. Returns `Err` if the range
/// is exhausted. Does NOT read or modify any LWMA/difficulty/target state.
pub fn mine_pow(
    header: &mut BlockHeader,
    height: u64,
    target: Target,
    max_iters: u64,
) -> Result<u32, String> {
    let cap = max_iters.min(u32::MAX as u64 + 1);
    for n in 0..cap {
        header.nonce = n as u32;
        if meets_target(&header.hash_for_height(height), target) {
            return Ok(header.nonce);
        }
    }
    Err(format!(
        "poawx mining harness: no nonce satisfied target in {cap} iterations"
    ))
}

fn poawx_mine_pow_max_iters() -> u64 {
    std::env::var("IRIUM_POAWX_MINE_POW_MAX_ITERS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(50_000_000)
        .max(1)
}

fn hash160(data: &[u8]) -> [u8; 20] {
    let mut o = [0u8; 20];
    o.copy_from_slice(&Ripemd160::digest(Sha256::digest(data)));
    o
}

/// Deterministic per-(height, role) hidden-precommit claim secret, bound to the
/// identity set claim_seed so the block at H-1 (which commits H leaves) and the
/// block at H (which reveals them) derive byte-identical values. Dev/devnet only;
/// not production key material.
fn derive_claim_secret(claim_seed: &[u8; 32], height: u64, role: u8) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"IRIUM_POAWX_CLAIM_SECRET_V1");
    h.update(claim_seed);
    h.update(height.to_le_bytes());
    h.update([role]);
    h.finalize().into()
}

/// Companion of [`derive_claim_secret`] for the claim nonce (domain-separated).
fn derive_claim_nonce(claim_seed: &[u8; 32], height: u64, role: u8) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"IRIUM_POAWX_CLAIM_NONCE_V1");
    h.update(claim_seed);
    h.update(height.to_le_bytes());
    h.update([role]);
    h.finalize().into()
}

/// A complete, mined all-gates block plus the candidate admissions a node must
/// have ingested for `connect_block` to accept it. Returned by
/// [`build_devnet_all_gates_block`]. `admissions` are the canonical wire bytes a
/// live harness POSTs to `/poawx/candidate-admission` before submitting `block`.
pub struct AllGatesProof {
    pub height: u64,
    pub block: Block,
    pub admissions: Vec<Vec<u8>>,
    pub block_hash: [u8; 32],
    pub irx1_root: [u8; 32],
}

/// Build a complete mined all-gates PoAW-X block for `height` over `prev_hash`,
/// using ONLY public consensus APIs (the same construction proven node-acceptable
/// by the Phase 24K `connect_block` test). Mainnet-hard-off: returns `Err` for
/// `network_id == 0`. Deterministic devnet/dev keys (never printed). The PoW is
/// mined with the real Irium hash against `Target { bits }` (caller supplies the
/// chain's `bits` — this does not touch difficulty/LWMA logic).
///
/// Gate env (network, activation heights, `IRIUM_POAWX_PUZZLE_BITS`, finality
/// threshold) must be set identically in this process and the target node so the
/// built sections match the node validators.
///
/// `parent_prev_hash` is the parent (tip) block's own `prev_hash` (`None` for the
/// genesis-parent / activation case). It is used ONLY to compute the
/// candidate-admission epoch seed (Phase 26B): the candidate set / admissions /
/// AVR2 are seeded by [`admission_epoch_seed`] (the grandparent hash), while the
/// puzzle/finality/claim sections and the outgoing committed admission keep using
/// this block's `prev_hash`. For `height == 1` (genesis parent) the epoch seed is
/// `prev_hash` (the genesis hash) and behavior is unchanged. This makes blocks at
/// `height >= 2` satisfy BOTH the phase21d candidate-set gate and the phase22a
/// committed-admission gate.
/// The PoAW-X identities an all-gates block needs. `dev()` reproduces the fixed
/// devnet keys (byte-identical to the original harness); `solo()` derives every
/// role from a single miner secret so a real solo miner plays all roles.
pub struct AllGatesIdentities {
    pub worker_sk: SigningKey,
    pub member_sk: SigningKey,
    pub compute_solver: [u8; 20],
    pub verify_solver: [u8; 20],
    pub support_solver: [u8; 20],
    pub compute_assign: [u8; 32],
    pub verify_assign: [u8; 32],
    pub support_assign: [u8; 32],
    /// Base entropy for the deterministic per-(height,role) hidden-precommit claim
    /// secret/nonce. Identity-bound so H-1 commit and H reveal derive identically.
    pub claim_seed: [u8; 32],
    /// Stage D Step 5 (delegated/mode-1): when Some, the receipt `worker_pkh` (the
    /// PRIMARY payout) is this value (the miner's payout pkh) instead of
    /// hash160(worker_sk pubkey). None => solo/dev (worker == payee).
    pub worker_pkh_override: Option<[u8; 20]>,
    /// Stage D Step 5 (delegated/mode-1): the miner-signed Delegation v2 to embed in
    /// the receipt. None => solo/dev (mode-0). When Some, `worker_sk` is the pool
    /// delegate key (signs the receipt + does role work) and the proposer proof is
    /// bound to `delegation.proposer_pubkey` rather than to `worker_pkh`.
    pub delegation: Option<crate::poawx::Delegation>,
    /// Stage D Step 5 Milestone F: optional delegation-revocation records to embed in
    /// the block's RVK1 ext section (a producer revoking miners' delegations on-chain).
    /// None for solo/dev and for delegated blocks that carry no revocation.
    pub revocations: Option<Vec<crate::poawx::DelegationRevocationV1>>,
}

impl AllGatesIdentities {
    /// Fixed devnet identities (matches the original harness exactly; the SUPPORT
    /// solver MUST be hash160(finality member pubkey) so the committee vote validates).
    pub fn dev() -> Result<Self, String> {
        let member_sk = SigningKey::from_bytes((&[0xC3u8; 32]).into())
            .map_err(|_| "harness: bad member key".to_string())?;
        let member_pub = member_sk.verifying_key().to_encoded_point(true);
        let support_solver = hash160(member_pub.as_bytes());
        Ok(Self {
            worker_sk: SigningKey::from_bytes((&[0x55u8; 32]).into())
                .map_err(|_| "harness: bad worker key".to_string())?,
            member_sk,
            compute_solver: [0xC1u8; 20],
            verify_solver: [0xC2u8; 20],
            support_solver,
            compute_assign: [7u8; 32],
            verify_assign: [8u8; 32],
            support_assign: [9u8; 32],
            claim_seed: [0x2Au8; 32],
            worker_pkh_override: None,
            delegation: None,
            revocations: None,
        })
    }

    /// Solo identities: one miner secret plays worker + finality member + all three
    /// roles (compute/verify/support all == the miner pkh). Per-role assignment
    /// secrets are domain-separated from the miner secret. The SUPPORT solver equals
    /// hash160(miner pubkey) == the finality member pkh, so the committee validates.
    pub fn solo(miner_secret: &[u8; 32]) -> Result<Self, String> {
        let sk = SigningKey::from_bytes(miner_secret.into())
            .map_err(|_| "solo: bad miner key".to_string())?;
        let pub_pt = sk.verifying_key().to_encoded_point(true);
        let pkh = hash160(pub_pt.as_bytes());
        let derive = |tag: &[u8]| -> [u8; 32] {
            let mut h = Sha256::new();
            h.update(b"IRIUM_POAWX_SOLO_ASSIGN_V1");
            h.update(tag);
            h.update(miner_secret);
            h.finalize().into()
        };
        let member_sk = SigningKey::from_bytes(miner_secret.into())
            .map_err(|_| "solo: bad miner key".to_string())?;
        Ok(Self {
            worker_sk: sk,
            member_sk,
            compute_solver: pkh,
            verify_solver: pkh,
            support_solver: pkh,
            compute_assign: derive(b"compute"),
            verify_assign: derive(b"verify"),
            support_assign: derive(b"support"),
            claim_seed: derive(b"claim"),
            worker_pkh_override: None,
            delegation: None,
            revocations: None,
        })
    }

    /// Multi-participant identities (role-attribution Phase 4): three GENUINELY DISTINCT
    /// contributor participants, each proving its role with its OWN key so that the role
    /// solver_pkh == hash160(assignment_public_key) -- satisfying the new contributor-role
    /// binding rule. The worker plays PRIMARY; the SUPPORT participant is the finality
    /// member (support_solver == hash160(member pubkey), as the committee requires).
    pub fn multi_participant(
        worker_secret: &[u8; 32],
        compute_secret: &[u8; 32],
        verify_secret: &[u8; 32],
        support_secret: &[u8; 32],
    ) -> Result<Self, String> {
        let sk_of = |b: &[u8; 32]| SigningKey::from_bytes(b.into())
            .map_err(|_| "multi: bad key".to_string());
        let pkh_of = |b: &[u8; 32]| -> Result<[u8; 20], String> {
            let sk = sk_of(b)?;
            let pt = sk.verifying_key().to_encoded_point(true);
            Ok(hash160(pt.as_bytes()))
        };
        let derive = |tag: &[u8]| -> [u8; 32] {
            let mut h = Sha256::new();
            h.update(b"IRIUM_POAWX_MULTI_ASSIGN_V1");
            h.update(tag);
            h.update(worker_secret);
            h.finalize().into()
        };
        Ok(Self {
            worker_sk: sk_of(worker_secret)?,
            member_sk: sk_of(support_secret)?,
            compute_solver: pkh_of(compute_secret)?,
            verify_solver: pkh_of(verify_secret)?,
            support_solver: pkh_of(support_secret)?,
            compute_assign: *compute_secret,
            verify_assign: *verify_secret,
            support_assign: *support_secret,
            claim_seed: derive(b"claim"),
            worker_pkh_override: None,
            delegation: None,
            revocations: None,
        })
    }

    /// Delegated (mode-1) identities for Stage D Step 5 (C1 custodial-proposer model).
    /// The pool DELEGATE key plays worker-signer + all three roles + finality member
    /// (the pool does the PoAW-X role work the ASIC can't); the receipt `worker_pkh`
    /// (PRIMARY payout) is overridden to the miner's payout pkh from the delegation, so
    /// the block reward is paid DIRECTLY to the miner. The custodial proposer proof is
    /// supplied separately via `ProposerCtx`; here we only carry the delegation (whose
    /// `proposer_pubkey` the builder binds the proof to). `delegation.pool_pubkey` MUST
    /// equal the delegate key so the node's mode-1 verifier accepts the signer.
    pub fn delegated(
        delegate_secret: &[u8; 32],
        delegation: crate::poawx::Delegation,
        revocations: Vec<crate::poawx::DelegationRevocationV1>,
    ) -> Result<Self, String> {
        let sk = SigningKey::from_bytes(delegate_secret.into())
            .map_err(|_| "delegated: bad delegate key".to_string())?;
        let pub_pt = sk.verifying_key().to_encoded_point(true);
        let mut delegate_pubkey = [0u8; 33];
        delegate_pubkey.copy_from_slice(pub_pt.as_bytes());
        if delegate_pubkey != delegation.pool_pubkey {
            return Err(
                "delegated: delegate key does not match delegation.pool_pubkey".to_string(),
            );
        }
        let pkh = hash160(&delegate_pubkey);
        let derive = |tag: &[u8]| -> [u8; 32] {
            let mut h = Sha256::new();
            h.update(b"IRIUM_POAWX_DELEGATED_ASSIGN_V1");
            h.update(tag);
            h.update(delegate_secret);
            h.finalize().into()
        };
        let member_sk = SigningKey::from_bytes(delegate_secret.into())
            .map_err(|_| "delegated: bad delegate key".to_string())?;
        Ok(Self {
            worker_sk: sk,
            member_sk,
            compute_solver: pkh,
            verify_solver: pkh,
            support_solver: pkh,
            compute_assign: derive(b"compute"),
            verify_assign: derive(b"verify"),
            support_assign: derive(b"support"),
            claim_seed: derive(b"claim"),
            worker_pkh_override: Some(delegation.miner_pkh()),
            delegation: Some(delegation),
            revocations: if revocations.is_empty() {
                None
            } else {
                Some(revocations)
            },
        })
    }
}

/// Build a mined all-gates block with the fixed devnet identities (test/proof
/// tooling). Byte-identical to the original harness output.
pub fn build_devnet_all_gates_block(
    network_id: u8,
    height: u64,
    prev_hash: [u8; 32],
    parent_prev_hash: Option<[u8; 32]>,
    bits: u32,
    time: u32,
    receipt_difficulty_bits: u32,
) -> Result<AllGatesProof, String> {
    build_all_gates_block_with(
        &AllGatesIdentities::dev()?,
        network_id,
        height,
        prev_hash,
        parent_prev_hash,
        bits,
        time,
        receipt_difficulty_bits,
        ([0u8; 32], [0u8; 32]),
        None,
        None,
        None,
        None,
    )
}

/// Build a mined all-gates block where a single miner secret plays every role
/// (worker + finality member + compute/verify/support). For solo devnet/testnet
/// PoAW-X mining with the miner's own reward key. Mainnet-hard-off.
pub fn build_solo_poawx_block(
    miner_secret: &[u8; 32],
    network_id: u8,
    height: u64,
    prev_hash: [u8; 32],
    parent_prev_hash: Option<[u8; 32]>,
    bits: u32,
    time: u32,
    receipt_difficulty_bits: u32,
) -> Result<AllGatesProof, String> {
    build_all_gates_block_with(
        &AllGatesIdentities::solo(miner_secret)?,
        network_id,
        height,
        prev_hash,
        parent_prev_hash,
        bits,
        time,
        receipt_difficulty_bits,
        ([0u8; 32], [0u8; 32]),
        None,
        None,
        None,
        None,
    )
}

/// Like [`build_solo_poawx_block`] but threads the PARENT block seed components
/// (finality-proof digest, precommit root) into the multi-source assignment seed so
/// blocks at `height >= 2` validate once the multi-source gate is active. For the
/// genesis-parent case pass `([0u8; 32], [0u8; 32])`. Mainnet-hard-off.
#[allow(clippy::too_many_arguments)]
/// Role-attribution Phase 4: build a mined all-gates block whose three contributor roles
/// are performed by three DISTINCT participant keys (each role solver == hash160 of its own
/// VRF key), so the block is valid under the active contributor-role binding rule.
#[allow(clippy::too_many_arguments)]
pub fn build_multi_participant_poawx_block_with_parent(
    worker_secret: &[u8; 32],
    compute_secret: &[u8; 32],
    verify_secret: &[u8; 32],
    support_secret: &[u8; 32],
    network_id: u8,
    height: u64,
    prev_hash: [u8; 32],
    parent_prev_hash: Option<[u8; 32]>,
    bits: u32,
    time: u32,
    receipt_difficulty_bits: u32,
    parent_seed_components: ([u8; 32], [u8; 32]),
) -> Result<AllGatesProof, String> {
    build_all_gates_block_with(
        &AllGatesIdentities::multi_participant(
            worker_secret, compute_secret, verify_secret, support_secret,
        )?,
        network_id,
        height,
        prev_hash,
        parent_prev_hash,
        bits,
        time,
        receipt_difficulty_bits,
        parent_seed_components,
        None,
        None,
        None,
        None,
    )
}

pub fn build_solo_poawx_block_with_parent(
    miner_secret: &[u8; 32],
    network_id: u8,
    height: u64,
    prev_hash: [u8; 32],
    parent_prev_hash: Option<[u8; 32]>,
    bits: u32,
    time: u32,
    receipt_difficulty_bits: u32,
    parent_seed_components: ([u8; 32], [u8; 32]),
) -> Result<AllGatesProof, String> {
    build_all_gates_block_with(
        &AllGatesIdentities::solo(miner_secret)?,
        network_id,
        height,
        prev_hash,
        parent_prev_hash,
        bits,
        time,
        receipt_difficulty_bits,
        parent_seed_components,
        None,
        None,
        None,
        None,
    )
}

/// Like [`build_solo_poawx_block_with_parent`] but uses a REAL dominance snapshot
/// (the node's state through H-1) for candidate weights, so alternating / multi-miner
/// blocks carry weights matching the node. Mainnet-hard-off.
#[allow(clippy::too_many_arguments)]
pub fn build_solo_poawx_block_with_parent_and_dominance(
    miner_secret: &[u8; 32],
    network_id: u8,
    height: u64,
    prev_hash: [u8; 32],
    parent_prev_hash: Option<[u8; 32]>,
    bits: u32,
    time: u32,
    receipt_difficulty_bits: u32,
    parent_seed_components: ([u8; 32], [u8; 32]),
    dominance: &PersistentDominance,
    node_gates: Option<&NodeGateFlags>,
) -> Result<AllGatesProof, String> {
    build_all_gates_block_with(
        &AllGatesIdentities::solo(miner_secret)?,
        network_id,
        height,
        prev_hash,
        parent_prev_hash,
        bits,
        time,
        receipt_difficulty_bits,
        parent_seed_components,
        Some(dominance),
        node_gates,
        None,
        None,
    )
}

/// Like [`build_solo_poawx_block_with_parent_and_dominance`] but also embeds the
/// miner's PRIVATE proposer-VRF assignment (`proposer_ctx`). The caller runs its own
/// sortition and supplies the assignment only when selected; the builder verifies it
/// belongs to the worker and binds it into the receipt. `None` => no proposer
/// assignment (identical to the non-proposer builder).
#[allow(clippy::too_many_arguments)]
/// Stage D Step 5: build a mined all-gates DELEGATED (mode-1) block. The pool holds
/// `delegate_secret` (== delegation.pool_pubkey) and supplies the miner-signed
/// `delegation`; the custodial proposer proof is passed via `proposer_ctx`. The result
/// is a receipt the node's mode-1 submit verifier + Step-3 delegated proposer branch
/// accept, whose coinbase PRIMARY pays the miner's payout pkh directly.
#[allow(clippy::too_many_arguments)]
pub fn build_delegated_poawx_block_with_proposer(
    delegate_secret: &[u8; 32],
    delegation: crate::poawx::Delegation,
    network_id: u8,
    height: u64,
    prev_hash: [u8; 32],
    parent_prev_hash: Option<[u8; 32]>,
    bits: u32,
    time: u32,
    receipt_difficulty_bits: u32,
    parent_seed_components: ([u8; 32], [u8; 32]),
    dominance: &PersistentDominance,
    node_gates: Option<&NodeGateFlags>,
    proposer_ctx: Option<&ProposerCtx>,
    registration_section: Option<&crate::poawx::ProposerRegistrationSection>,
    revocations: Vec<crate::poawx::DelegationRevocationV1>,
) -> Result<AllGatesProof, String> {
    build_all_gates_block_with(
        &AllGatesIdentities::delegated(delegate_secret, delegation, revocations)?,
        network_id,
        height,
        prev_hash,
        parent_prev_hash,
        bits,
        time,
        receipt_difficulty_bits,
        parent_seed_components,
        Some(dominance),
        node_gates,
        proposer_ctx,
        registration_section,
    )
}

pub fn build_solo_poawx_block_with_proposer(
    miner_secret: &[u8; 32],
    network_id: u8,
    height: u64,
    prev_hash: [u8; 32],
    parent_prev_hash: Option<[u8; 32]>,
    bits: u32,
    time: u32,
    receipt_difficulty_bits: u32,
    parent_seed_components: ([u8; 32], [u8; 32]),
    dominance: &PersistentDominance,
    node_gates: Option<&NodeGateFlags>,
    proposer_ctx: Option<&ProposerCtx>,
    registration_section: Option<&crate::poawx::ProposerRegistrationSection>,
) -> Result<AllGatesProof, String> {
    build_all_gates_block_with(
        &AllGatesIdentities::solo(miner_secret)?,
        network_id,
        height,
        prev_hash,
        parent_prev_hash,
        bits,
        time,
        receipt_difficulty_bits,
        parent_seed_components,
        Some(dominance),
        node_gates,
        proposer_ctx,
        registration_section,
    )
}

/// Build a mined all-gates block with THREE genuinely distinct role participants
/// (compute/verify/support) AND the PRIMARY worker's proposer-VRF assignment. For the
/// role-attribution + proposer-VRF combination (Option A distinct role-workers + Option 2
/// single custodial proposer): the worker plays PRIMARY and holds the proposer key -- the
/// non-delegated builder binds the proposer proof to worker_pkh -- while each role is paid
/// to its own distinct participant. Mirrors build_solo_poawx_block_with_proposer with the
/// multi-participant identity set. Mainnet-hard-off.
#[allow(clippy::too_many_arguments)]
pub fn build_multi_participant_poawx_block_with_proposer(
    worker_secret: &[u8; 32],
    compute_secret: &[u8; 32],
    verify_secret: &[u8; 32],
    support_secret: &[u8; 32],
    network_id: u8,
    height: u64,
    prev_hash: [u8; 32],
    parent_prev_hash: Option<[u8; 32]>,
    bits: u32,
    time: u32,
    receipt_difficulty_bits: u32,
    parent_seed_components: ([u8; 32], [u8; 32]),
    dominance: &PersistentDominance,
    node_gates: Option<&NodeGateFlags>,
    proposer_ctx: Option<&ProposerCtx>,
    registration_section: Option<&crate::poawx::ProposerRegistrationSection>,
) -> Result<AllGatesProof, String> {
    build_all_gates_block_with(
        &AllGatesIdentities::multi_participant(
            worker_secret,
            compute_secret,
            verify_secret,
            support_secret,
        )?,
        network_id,
        height,
        prev_hash,
        parent_prev_hash,
        bits,
        time,
        receipt_difficulty_bits,
        parent_seed_components,
        Some(dominance),
        node_gates,
        proposer_ctx,
        registration_section,
    )
}

/// Node-authoritative gate-activation flags for a target height, supplied by the
/// block template so a standalone miner builds exactly what its node will validate
/// (instead of reading its own env). `None` at a call site => fall back to the
/// env-derived gate predicates (existing in-process behavior). Mainnet-off.
pub struct NodeGateFlags {
    pub hidden_precommit_active: bool,
    pub tickets_active: bool,
    pub multisource_seed_active: bool,
    pub penalty_state_active: bool,
    pub puzzle_anchor_bits: u32,
    pub effective_sybil_bits: u32,
    /// Audit-hardening gate for this height (node-authoritative). Drives the deterministic,
    /// signature-bound receipts root (Fix #5/#1) so the miner builds exactly what the node
    /// validates, instead of relying on the miner's local env.
    pub audit_hardening_active: bool,
}

/// Phase 31: the miner's already-built proposer-VRF assignment, threaded into the
/// block builder. The miner runs its private sortition (it owns the secret) and
/// supplies this only when selected at some allowed cascade round; the builder
/// verifies it belongs to the worker and binds it into the receipt.
pub struct ProposerCtx {
    pub assignment: crate::poawx::ProposerAssignmentV1,
}

#[allow(clippy::too_many_arguments)]
fn build_all_gates_block_with(
    ids: &AllGatesIdentities,
    network_id: u8,
    height: u64,
    prev_hash: [u8; 32],
    parent_prev_hash: Option<[u8; 32]>,
    bits: u32,
    time: u32,
    receipt_difficulty_bits: u32,
    parent_seed_components: ([u8; 32], [u8; 32]),
    dominance_override: Option<&PersistentDominance>,
    node_gates: Option<&NodeGateFlags>,
    proposer_ctx: Option<&ProposerCtx>,
    registration_section: Option<&crate::poawx::ProposerRegistrationSection>,
) -> Result<AllGatesProof, String> {
    guard_network(network_id)?;
    // Resolve the standard-header activation height into the process global the
    // SAME way the node does at startup, so `hash_for_height` here serializes the
    // header identically to the node's validator. A standalone harness has no
    // ChainState to set this, so without it the global falls back to the mainnet
    // constant (22_888) and mined-block height-1 headers hash differently than
    // the node (which, on devnet/testnet, resolves it to 1). Idempotent OnceLock.
    crate::block::set_standard_header_activation_height(
        crate::activation::resolved_standard_header_activation_height(
            crate::activation::network_kind_from_env(),
        ),
    );
    let net = network_id;

    // Identities supplied by the caller (dev or solo). The SUPPORT solver MUST be
    // hash160(finality member pubkey) so the committee vote validates (guaranteed
    // by both AllGatesIdentities constructors).
    let worker_sk = &ids.worker_sk;
    let worker_pubkey_pt = worker_sk.verifying_key().to_encoded_point(true);
    let worker_pubkey_bytes = worker_pubkey_pt.as_bytes();
    let worker_pkh = match ids.worker_pkh_override {
        Some(p) => p,
        None => hash160(worker_pubkey_bytes),
    };
    let member_sk = &ids.member_sk;
    let compute_solver = ids.compute_solver;
    let verify_solver = ids.verify_solver;
    let support_solver = ids.support_solver;

    // Anti-domination weights are validated against the node's PERSISTED dominance
    // state, which evolves as each accepted block credits its role rewards. A
    // standalone builder has no ChainState, so replay every prior height's reward
    // events into a local tracker to compute weights at any target height. This
    // builder makes deterministic, identical blocks (fixed role identities above),
    // so each prior height `h` credited exactly these 4 role pkhs with
    // `multi_role_amounts(block_reward(h))` — the SAME events the node applies in
    // `apply_block_dominance`. `dom_at(upto)` holds events for blocks `[1, upto)`;
    // for height 1 the replay is empty (genesis baseline weights == 1000).
    let dom_at = |upto: u64| -> PersistentDominance {
        let mut d = PersistentDominance::from_env();
        for h in 1..upto {
            let amts = multi_role_amounts(block_reward(h));
            d.apply_event(worker_pkh, RoleRewardKind::Primary, amts[0], h);
            d.apply_event(compute_solver, RoleRewardKind::Compute, amts[1], h);
            d.apply_event(verify_solver, RoleRewardKind::Verify, amts[2], h);
            d.apply_event(support_solver, RoleRewardKind::Support, amts[3], h);
        }
        d
    };

    // Phase 26B: candidate-admission EPOCH seed for THIS block — the grandparent
    // hash the parent froze in its outgoing committed admission, decoupled from
    // the block's own `prev_hash`. The candidate set / admissions / AVR2 use the
    // epoch seed (what phase21d/21e/22d validate); the puzzle/finality/claim
    // sections and the outgoing commitment use `prev_hash`.
    // Gap 3: harness builds height-1 over genesis, so the PARENT (genesis) carries
    // no finality/precommit => the multi-source seed components are zero; the gate
    // (off by default) then returns the legacy grandparent hash byte-identically.
    let (parent_finality_digest, parent_precommit_digest) = parent_seed_components;
    let base_seed = admission_epoch_seed(parent_prev_hash, prev_hash);
    let multisource_active = node_gates
        .map(|g| g.multisource_seed_active)
        .unwrap_or_else(|| crate::poawx_committed_admission::multisource_seed_active(height));
    let epoch_seed = crate::poawx_committed_admission::resolve_epoch_seed_parts_with(
        multisource_active,
        height,
        base_seed,
        parent_finality_digest,
        parent_precommit_digest,
    );
    // Gap-extension gate state used by the hidden-precommit reveal + commit below.
    let hp_active = node_gates
        .map(|g| g.hidden_precommit_active)
        .unwrap_or_else(|| crate::chain::hidden_precommit_active(height));
    let claim_seed = ids.claim_seed;

    // Build the 3 role candidates + V2 proofs for a `(target_height, seed)` under a
    // dominance state. Returns proofs + candidates in [compute, verify, support]
    // order plus the canonical candidate set.
    let build_roles = |th: u64,
                       sd: [u8; 32],
                       dom: &PersistentDominance|
     -> Result<([AssignmentProofV2; 3], [RoleCandidate; 3], CandidateSet), String> {
        let mk = |secret: &[u8; 32], role: u8, solver: [u8; 20], ticket: [u8; 32]| {
            let p = AssignmentProofV2::prove(secret, net, th, role, solver, ticket, sd)?;
            let w = dom.weight(DOMINANCE_BASE_WORK_SCORE, &solver, th);
            let c = RoleCandidate::from_assignment_v2(&p, PenaltyStatus::Clean.id(), w, [role; 32]);
            Ok::<_, String>((p, c))
        };
        let (pc, cc) = mk(&ids.compute_assign, ROLE_COMPUTE_CONTRIBUTOR, compute_solver, [0x11u8; 32])?;
        let (pv, cv) = mk(&ids.verify_assign, ROLE_VERIFY_CONTRIBUTOR, verify_solver, [0x12u8; 32])?;
        let (ps, csup) = mk(&ids.support_assign, ROLE_SUPPORT_CONTRIBUTOR, support_solver, [0x13u8; 32])?;
        let mut cs = CandidateSet::new(net, th, sd);
        for c in [cc.clone(), cv.clone(), csup.clone()] {
            cs.push(c);
        }
        cs.sort_canonical();
        Ok(([pc, pv, ps], [cc, cv, csup], cs))
    };

    // INCOMING set for THIS block (height H, epoch seed, weights at H). A3: with a
    // real dominance snapshot (the node state through H-1) the candidate weights are
    // correct regardless of who mined prior blocks; without one, fall back to the
    // solo replay (single-miner back-compat).
    let dom_in = match dominance_override {
        Some(d) => d.clone(),
        None => dom_at(height),
    };
    let (in_proofs, in_cands, cs) = build_roles(height, epoch_seed, &dom_in)?;
    let dw_in = |pkh: &[u8; 20]| dom_in.weight(DOMINANCE_BASE_WORK_SCORE, pkh, height);

    // Candidate admissions (canonical wire bytes the node must ingest), epoch-seeded.
    let admissions: Vec<Vec<u8>> = in_proofs
        .iter()
        .zip(in_cands.iter())
        .map(|(p, c)| {
            CandidateAdmissionV1::new_with_v2(net, height, epoch_seed, c.clone(), Some(p.clone()))
                .serialize()
        })
        .collect();

    // Per-role assigned puzzle solutions.
    let profile = match node_gates {
        Some(g) => crate::poawx_puzzle::profile_with_bits(g.puzzle_anchor_bits as u8),
        None => default_profile(),
    };
    let mut sols = Vec::with_capacity(3);
    for role in [
        ROLE_COMPUTE_CONTRIBUTOR,
        ROLE_VERIFY_CONTRIBUTOR,
        ROLE_SUPPORT_CONTRIBUTOR,
    ] {
        let cand = cs
            .best_for_role(role)
            .ok_or_else(|| format!("harness: no candidate for role {role}"))?;
        let cdg: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(cand.serialize());
            h.finalize().into()
        };
        let challenge = PuzzleChallengeV1::build(
            net,
            height,
            role,
            cand.solver_pkh,
            cand.ticket_digest,
            cand.assignment_proof_digest,
            cdg,
            prev_hash,
            profile,
        );
        sols.push(solve_dev(&challenge).ok_or_else(|| "harness: puzzle solve failed".to_string())?);
    }

    // SUPPORT-committee finality proof finalizing the parent (block_hash = prev_hash).
    let (num, den) = finality_threshold();
    let mut fproof = FinalityProofV1::new(net, height, prev_hash, [0u8; 32], 0, num, den);
    fproof.push(FinalityVoteV1::signed(
        member_sk,
        net,
        height,
        prev_hash,
        [0u8; 32],
        0,
        [0x11u8; 32],
        FinalityVoteType::Commit,
    ));
    fproof.sort_canonical();

    // Fix A1: hidden-precommit root committing THIS block's OWN role-claim leaves
    // (the exact leaves H reveals via `derive_claim_secret(claim_seed, height, role)`),
    // so any miner can extend any block — no dependency on the previous block's miner.
    // Binding: the root is in the receipt -> merkle -> header -> PoW; each claim's
    // commitment_hash binds its secret/nonce. The NEXT block's multi-source seed reads
    // THIS block's precommit_root from the block itself (miner-independent).
    let precommit_root = if hp_active {
        let leaf = |role: u8, solver: [u8; 20]| -> [u8; 32] {
            let s = derive_claim_secret(&claim_seed, height, role);
            let n = derive_claim_nonce(&claim_seed, height, role);
            let c = crate::poawx::role_precommit_commitment(&s, &n);
            crate::poawx::role_precommit_leaf(net, height, role, &solver, &c)
        };
        let leaves = [
            leaf(ROLE_COMPUTE_CONTRIBUTOR, compute_solver),
            leaf(ROLE_VERIFY_CONTRIBUTOR, verify_solver),
            leaf(ROLE_SUPPORT_CONTRIBUTOR, support_solver),
        ];
        Some(crate::poawx::role_precommit_root(&leaves))
    } else {
        None
    };
    // Fix A2: committed-admission self-commit — block H commits its OWN candidate set
    // (target H, commit_height H), NOT H+1's. Removes the cross-block / cross-miner
    // dependency that prevented a different miner from extending the chain.
    let commitment = AdmissionCommitmentV1::from_candidate_set(&cs, height);

    let claim = |role: u8, solver: [u8; 20]| -> PoawxRoleClaim {
        let lane = crate::poawx::assign_lane(net, height, &prev_hash, role, 0);
        // Hidden-precommit reveal: derived secret/nonce + hiding commitment when the
        // gate is active; legacy fixed values + None otherwise (byte-identical).
        let (secret, nonce) = if hp_active {
            (
                derive_claim_secret(&claim_seed, height, role),
                derive_claim_nonce(&claim_seed, height, role),
            )
        } else {
            ([0x02u8; 32], [0x01u8; 32])
        };
        let cd = crate::poawx::role_claim_digest(
            net,
            height,
            &prev_hash,
            role,
            lane.id(),
            &solver,
            &nonce,
            &secret,
        );
        let commitment_hash = if hp_active {
            Some(crate::poawx::role_precommit_commitment(&secret, &nonce))
        } else {
            None
        };
        PoawxRoleClaim {
            role_id: role,
            lane_id: lane.id(),
            solver_pkh: solver,
            nonce,
            secret,
            claim_digest: cd,
            commitment_hash,
        }
    };

    // Gap-extension: per-role ticket proofs (Sybil-work + penalty eligibility). Emit
    // when the ticket gate is active at H; the node validates them when tickets are
    // REQUIRED. Solo: every role solver is the miner pkh; the assignment pubkey is
    // the miner compressed key (bound into the digests, not cross-checked). Penalty
    // status = Clean (a non-slashed miner is eligible for high-trust roles).
    let tickets_on = node_gates
        .map(|g| g.tickets_active)
        .unwrap_or_else(|| crate::poawx_ticket::tickets_active(height));
    let role_ticket_proofs = if tickets_on {
        let mut apk = [0u8; 33];
        apk.copy_from_slice(worker_pubkey_bytes);
        // Fix B/C: grind to the EFFECTIVE (floored) bits and bind to prev_hash.
        let sybil_bits = node_gates
            .map(|g| g.effective_sybil_bits)
            .unwrap_or_else(|| crate::poawx_ticket::effective_sybil_bits());
        let epoch = height;
        let expiry = height + 100_000;
        let mk_ticket =
            |role: u8, solver: [u8; 20]| -> Result<crate::poawx_ticket::TicketProof, String> {
                let nonce = if sybil_bits > 0 {
                    crate::poawx_ticket::grind_sybil_nonce(
                        net, &prev_hash, &solver, epoch, &apk, sybil_bits, 50_000_000,
                    )
                    .map(|(n, _d)| n)
                    .ok_or_else(|| {
                        format!("harness: ticket sybil-work grind failed for role {role}")
                    })?
                } else {
                    [0u8; 32]
                };
                Ok(crate::poawx_ticket::TicketProof::new(
                    net,
                    height,
                    prev_hash,
                    role,
                    solver,
                    epoch,
                    expiry,
                    apk,
                    nonce,
                    PenaltyStatus::Clean.id(),
                ))
            };
        Some([
            mk_ticket(ROLE_COMPUTE_CONTRIBUTOR, compute_solver)?,
            mk_ticket(ROLE_VERIFY_CONTRIBUTOR, verify_solver)?,
            mk_ticket(ROLE_SUPPORT_CONTRIBUTOR, support_solver)?,
        ])
    } else {
        None
    };

    // Phase 31: embed the miner's private proposer-VRF assignment when supplied.
    // The builder only verifies the assignment belongs to THIS block's worker; the
    // sortition decision (selected at which round) is the caller's. Gate-off => None
    // => byte-identical to the pre-Phase-31 receipt.
    let proposer_assignment: Option<crate::poawx::ProposerAssignmentV1> = match proposer_ctx {
        None => None,
        Some(ctx) => {
            match &ids.delegation {
                Some(d) => {
                    // Delegated (mode-1): the proposer proof is made with the miner's
                    // custodial proposer key, which the miner authorised in the delegation.
                    // worker_pkh is the miner PAYOUT (not the proposer key), so bind the
                    // proof to proposer_pubkey -- exactly what chain.rs validate_block_proposer
                    // checks in its delegated branch (Step 3).
                    if d.proposer_pubkey != ctx.assignment.proof.assignment_public_key {
                        return Err(
                            "proposer: assignment vrf key does not match delegated proposer key"
                                .to_string(),
                        );
                    }
                }
                None => {
                    if hash160(&ctx.assignment.proof.assignment_public_key) != worker_pkh {
                        return Err(
                            "proposer: assignment vrf key does not match worker identity"
                                .to_string(),
                        );
                    }
                }
            }
            Some(ctx.assignment.clone())
        }
    };
    // Phase 31R: embed the producer's proposer-registration section (queue-head
    // activations + announces) supplied by the caller from the node template. The node
    // re-validates it at connect_block (R3); the builder just binds it into the receipt.
    let proposer_registrations: Option<crate::poawx::ProposerRegistrationSection> =
        registration_section.cloned();

    let ext = Phase20ReceiptExt {
        role_reward: RoleReward {
            compute_contributor_pkh: compute_solver,
            verify_contributor_pkh: verify_solver,
            support_contributor_pkh: support_solver,
        },
        compute_claim: claim(ROLE_COMPUTE_CONTRIBUTOR, compute_solver),
        verify_claim: claim(ROLE_VERIFY_CONTRIBUTOR, verify_solver),
        support_claim: claim(ROLE_SUPPORT_CONTRIBUTOR, support_solver),
        fee_bps: 0,
        fee_pkh: [0u8; 20],
        precommit_root,
        role_ticket_proofs,
        role_dominance_weights: Some([
            dw_in(&worker_pkh),
            dw_in(&compute_solver),
            dw_in(&verify_solver),
            dw_in(&support_solver),
        ]),
        candidate_set: Some(cs),
        role_puzzle_proofs: Some([sols[0], sols[1], sols[2]]),
        finality_proof: Some(fproof),
        committed_admission: Some(commitment),
        role_assignment_v2: Some(in_proofs),
        fraud_proofs: None,
        proposer_assignment,
        proposer_registrations,
        delegation_revocations: ids.revocations.clone(),
    };

    // Worker receipt: real receipt PoW solution + signed challenge (mode-0).
    let parent_height = height.saturating_sub(1);
    let r_seed: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(prev_hash);
        h.update(parent_height.to_le_bytes());
        h.update(b"poawx_assignment_seed_v1");
        h.finalize().into()
    };
    let r_nonce: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(r_seed);
        h.update(b"commitment_nonce");
        h.finalize().into()
    };
    let mut solution = [0u8; 8];
    let mut found = false;
    for n in 0u64..200_000_000 {
        let cand = n.to_le_bytes();
        let mut pow_input = [0u8; 72];
        pow_input[..32].copy_from_slice(&r_seed);
        pow_input[32..64].copy_from_slice(&r_nonce);
        pow_input[64..].copy_from_slice(&cand);
        if count_leading_zero_bits(&sha256d(&pow_input)) >= receipt_difficulty_bits {
            solution = cand;
            found = true;
            break;
        }
    }
    if !found {
        return Err("harness: receipt PoW not found".to_string());
    }
    let challenge: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(solution);
        h.update(r_nonce);
        h.update(height.to_le_bytes());
        h.finalize().into()
    };
    let sig: k256::ecdsa::Signature = {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        worker_sk
            .sign_prehash(&challenge)
            .map_err(|_| "harness: sign failed".to_string())?
    };
    let mut worker_sig = [0u8; 64];
    worker_sig.copy_from_slice(&sig.to_bytes());
    let mut worker_pubkey = [0u8; 33];
    worker_pubkey.copy_from_slice(worker_pubkey_bytes);

    let receipt = PoawxBlockReceipt {
        height,
        lane: b'A',
        worker_pkh,
        worker_pubkey,
        worker_sig,
        solution,
        commitment_nonce: r_nonce,
        delegation: ids.delegation.clone(),
        phase20_ext: Some(ext.clone()),
    };

    // Canonical 0%-fee multi-role coinbase + the gated (ext-bound) irx1 root.
    let total = block_reward(height);
    let a = multi_role_amounts(total);
    // Fix #5/#1: build the gated (deterministic, sig-bound) audit root so the miner's root
    // matches connect_block's validator when the audit gate is active. Gate off => byte-identical.
    // Audit flag is node-authoritative (from the template via NodeGateFlags); fall back to
    // local env only when no node flags were supplied (node-internal builds / older callers).
    let audit_active = node_gates
        .map(|g| g.audit_hardening_active)
        .unwrap_or_else(|| crate::poawx_proposer::audit_hardening_active(height));
    let irx1_root = crate::poawx::irx1_root_from_block_receipts_audit(
        std::slice::from_ref(&receipt),
        true,
        audit_active,
    );
    let mut irx1_script = vec![0x6a, 0x24u8];
    irx1_script.extend_from_slice(b"irx1");
    irx1_script.extend_from_slice(&irx1_root);
    let outputs = vec![
        TxOutput {
            value: 0,
            script_pubkey: irx1_script,
        },
        TxOutput {
            value: a[0],
            script_pubkey: p2pkh_script(&worker_pkh),
        },
        TxOutput {
            value: a[1],
            script_pubkey: p2pkh_script(&compute_solver),
        },
        TxOutput {
            value: a[2],
            script_pubkey: p2pkh_script(&verify_solver),
        },
        TxOutput {
            value: a[3],
            script_pubkey: p2pkh_script(&support_solver),
        },
    ];
    let coinbase = Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid: [0u8; 32],
            prev_index: 0xffff_ffff,
            script_sig: vec![0x01, 0x00],
            sequence: 0xffff_ffff,
        }],
        outputs,
        locktime: 0,
    };

    let mut block = Block {
        header: BlockHeader {
            version: 1,
            prev_hash,
            merkle_root: [0u8; 32],
            time,
            bits,
            nonce: 0,
        },
        transactions: vec![coinbase],
        auxpow: None,
        poawx_receipts: Some(vec![receipt]),
    };
    block.header.merkle_root = block.merkle_root();
    if std::env::var("IRIUM_POAWX_SKIP_HEADER_POW")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        // Receipt export mode: build/validate the PoAW-X receipt material without
        // spending mainnet-scale work on the enclosing block header.
    } else {
        mine_pow(&mut block.header, height, Target { bits }, poawx_mine_pow_max_iters())?;
    }
    let block_hash = block.header.hash_for_height(height);

    Ok(AllGatesProof {
        height,
        block,
        admissions,
        block_hash,
        irx1_root,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_network_accepts_known_networks() {
        // E1: harness accepts known Irium networks and refuses unknown ids.
        assert!(guard_network(0).is_ok(), "mainnet (0) allowed");
        assert!(guard_network(1).is_ok(), "testnet (1) allowed");
        assert!(guard_network(2).is_ok(), "devnet (2) allowed");
        assert!(guard_network(7).is_err(), "unknown id refused");
        let msg = guard_network(7).unwrap_err().to_lowercase();
        assert!(!msg.contains("secret") && !msg.contains("private") && !msg.contains("mnemonic"));
    }

    #[test]
    fn guard_isolated_storage_refuses_default_and_missing() {
        // E2: missing dir refused.
        assert!(guard_isolated_storage(None).is_err(), "no dir refused");
        assert!(
            guard_isolated_storage(Some(Path::new("/tmp/irium-x"))).is_err(),
            "/tmp refused"
        );
        // Unix default refused.
        std::env::set_var("HOME", "/home/tester");
        assert!(
            guard_isolated_storage(Some(Path::new("/home/tester/.irium"))).is_err(),
            "Unix default $HOME/.irium refused"
        );
        assert!(
            guard_isolated_storage(Some(Path::new("/home/tester/irium-p24l"))).is_ok(),
            "explicit isolated dir accepted"
        );
        // USERPROFILE (Windows home) default `.irium` refused. Use Path::join so
        // the separator is correct on whatever platform runs this test.
        let up = if cfg!(windows) {
            "C:\\Users\\tester"
        } else {
            "/home/winuser"
        };
        std::env::set_var("USERPROFILE", up);
        let up_path = Path::new(up);
        assert!(
            guard_isolated_storage(Some(&up_path.join(".irium"))).is_err(),
            "USERPROFILE/.irium default refused"
        );
        assert!(
            guard_isolated_storage(Some(&up_path.join("irium-poawx-live-proof"))).is_ok(),
            "explicit USERPROFILE-rooted isolated dir accepted"
        );
        std::env::remove_var("USERPROFILE");
    }

    #[test]
    fn mine_pow_finds_nonce_with_real_irium_hash() {
        // E11 (unit level): grinding the nonce with Irium's actual hash path
        // produces a header that satisfies the target via the SAME check the
        // node validator (`validate_block_header`) uses.
        let mut header = BlockHeader {
            version: 1,
            prev_hash: [0u8; 32],
            merkle_root: [0x11u8; 32],
            time: 1,
            bits: 0x1f00ffff,
            nonce: 0,
        };
        let height = 1u64;
        let target = header.target();
        let nonce = mine_pow(&mut header, height, target, 5_000_000).expect("mine a nonce");
        assert_eq!(header.nonce, nonce);
        assert!(meets_target(&header.hash_for_height(height), target));
        let mut h2 = header.clone();
        let impossible = Target { bits: 0x0300_0001 };
        assert!(mine_pow(&mut h2, height, impossible, 2_000).is_err());
    }

    #[test]
    fn build_devnet_all_gates_block_accepts_mainnet() {
        assert!(
            build_devnet_all_gates_block(0, 1, [0x44u8; 32], None, 0x207fffff, 1, 1).is_ok(),
            "builder accepts known mainnet network id"
        );
    }
}
