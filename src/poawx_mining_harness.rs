//! Phase 24K/24L: Irium-native PoAW-X all-gates mining submit harness (helpers).
//!
//! Phase 24J proved the remaining blocker for a real all-gates block was mining
//! TOOLING, not PoAW-X consensus: stock cpuminer/minerd hashes a standard
//! Bitcoin 80-byte header with `sha256d`, but Irium hashes the block header via
//! [`crate::block::BlockHeader::hash_for_height`] (a height-bound serialization),
//! so minerd's shares never match Irium's PoW target. The fix is to mine with
//! Irium's ACTUAL PoW hash.
//!
//! This module provides the small, reusable, **mainnet-hard-off** primitives a
//! devnet/testnet harness (in-process tests and the explicit
//! `poawx-live-proof-harness` binary for the Phase 24L Windows live proof) needs
//! to produce a real all-gates block:
//!   * [`guard_network`] — refuse mainnet (`network_id == 0`); require an
//!     explicit devnet/testnet id.
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
//! deterministic test/dev keys; this is devnet/testnet-only (mainnet hard-off).

use crate::block::{Block, BlockHeader};
use crate::constants::block_reward;
use crate::poawx::{
    count_leading_zero_bits, irx1_root_from_block_receipts_gated, multi_role_amounts,
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

/// Refuse to run the harness on mainnet. Mainnet is `network_id == 0`
/// ([`crate::activation::NetworkKind::id_byte`]). Only testnet (1) and devnet
/// (2) are permitted. The caller MUST pass the resolved network id; this is the
/// single mainnet-hard-off choke point for every harness entry point.
pub fn guard_network(network_id: u8) -> Result<(), String> {
    match network_id {
        0 => Err(
            "poawx mining harness: refusing to run on mainnet (network_id==0); \
             require explicit devnet/testnet"
                .to_string(),
        ),
        1 | 2 => Ok(()),
        other => Err(format!(
            "poawx mining harness: unknown network_id {other}; require testnet(1)/devnet(2)"
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

fn hash160(data: &[u8]) -> [u8; 20] {
    let mut o = [0u8; 20];
    o.copy_from_slice(&Ripemd160::digest(Sha256::digest(data)));
    o
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
pub fn build_devnet_all_gates_block(
    network_id: u8,
    height: u64,
    prev_hash: [u8; 32],
    parent_prev_hash: Option<[u8; 32]>,
    bits: u32,
    time: u32,
    receipt_difficulty_bits: u32,
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

    // Identities (deterministic dev keys; the SUPPORT solver MUST be
    // hash160(finality member pubkey) so the committee vote validates).
    let worker_sk = SigningKey::from_bytes((&[0x55u8; 32]).into())
        .map_err(|_| "harness: bad worker key".to_string())?;
    let worker_pubkey_pt = worker_sk.verifying_key().to_encoded_point(true);
    let worker_pubkey_bytes = worker_pubkey_pt.as_bytes();
    let worker_pkh = hash160(worker_pubkey_bytes);
    let member_sk = SigningKey::from_bytes((&[0xC3u8; 32]).into())
        .map_err(|_| "harness: bad member key".to_string())?;
    let member_pub = member_sk.verifying_key().to_encoded_point(true);
    let support_solver = hash160(member_pub.as_bytes());
    let compute_solver = [0xC1u8; 20];
    let verify_solver = [0xC2u8; 20];

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
    let epoch_seed = admission_epoch_seed(parent_prev_hash, prev_hash);

    // Build the 3 role candidates + V2 proofs for a `(target_height, seed)` under a
    // dominance state. Returns proofs + candidates in [compute, verify, support]
    // order plus the canonical candidate set.
    let build_roles =
        |th: u64,
         sd: [u8; 32],
         dom: &PersistentDominance|
         -> Result<([AssignmentProofV2; 3], [RoleCandidate; 3], CandidateSet), String> {
            let mk = |secret: u8, role: u8, solver: [u8; 20], ticket: [u8; 32]| {
                let p = AssignmentProofV2::prove(&[secret; 32], net, th, role, solver, ticket, sd)?;
                let w = dom.weight(DOMINANCE_BASE_WORK_SCORE, &solver, th);
                let c =
                    RoleCandidate::from_assignment_v2(&p, PenaltyStatus::Clean.id(), w, [role; 32]);
                Ok::<_, String>((p, c))
            };
            let (pc, cc) = mk(7, ROLE_COMPUTE_CONTRIBUTOR, compute_solver, [0x11u8; 32])?;
            let (pv, cv) = mk(8, ROLE_VERIFY_CONTRIBUTOR, verify_solver, [0x12u8; 32])?;
            let (ps, csup) = mk(9, ROLE_SUPPORT_CONTRIBUTOR, support_solver, [0x13u8; 32])?;
            let mut cs = CandidateSet::new(net, th, sd);
            for c in [cc.clone(), cv.clone(), csup.clone()] {
                cs.push(c);
            }
            cs.sort_canonical();
            Ok(([pc, pv, ps], [cc, cv, csup], cs))
        };

    // INCOMING set for THIS block (height H, epoch seed, weights at H).
    let dom_in = dom_at(height);
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
    let profile = default_profile();
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
        &member_sk,
        net,
        height,
        prev_hash,
        [0u8; 32],
        0,
        [0x11u8; 32],
        FinalityVoteType::Commit,
    ));
    fproof.sort_canonical();

    // OUTGOING committed-admission commitment for H+1. The committed set is EXACTLY
    // what block H+1 will present: candidates for `(H+1, seed = this block's
    // prev_hash)` — i.e. H+1's epoch seed — with weights at H+1. Self-consistent:
    // commit_height = H, freeze seed = prev_hash (== `admission_epoch_seed` of H+1).
    // Incoming committed admission is graced at the activation height (H1).
    let dom_out = dom_at(height + 1);
    let (_out_proofs, _out_cands, cs_next) = build_roles(height + 1, prev_hash, &dom_out)?;
    let commitment = AdmissionCommitmentV1::from_candidate_set(&cs_next, height);

    let claim = |role: u8, solver: [u8; 20]| -> PoawxRoleClaim {
        let lane = crate::poawx::assign_lane(net, height, &prev_hash, role, 0);
        let nonce = [0x01u8; 32];
        let secret = [0x02u8; 32];
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
        PoawxRoleClaim {
            role_id: role,
            lane_id: lane.id(),
            solver_pkh: solver,
            nonce,
            secret,
            claim_digest: cd,
            commitment_hash: None,
        }
    };

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
        precommit_root: None,
        role_ticket_proofs: None,
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
        double_sign_evidence: None,
        ticket_registrations: None,
        dominance_commitment: None,
        adaptive_mode_commitment: None,
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
        delegation: None,
        phase20_ext: Some(ext.clone()),
    };

    // Canonical 0%-fee multi-role coinbase + the gated (ext-bound) irx1 root.
    let total = block_reward(height);
    let a = multi_role_amounts(total);
    let irx1_root = irx1_root_from_block_receipts_gated(std::slice::from_ref(&receipt), true);
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
    mine_pow(&mut block.header, height, Target { bits }, 50_000_000)?;
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
    fn guard_network_rejects_mainnet() {
        // E1: harness refuses mainnet; accepts only testnet/devnet.
        assert!(guard_network(0).is_err(), "mainnet (0) must be refused");
        assert!(guard_network(1).is_ok(), "testnet (1) allowed");
        assert!(guard_network(2).is_ok(), "devnet (2) allowed");
        assert!(guard_network(7).is_err(), "unknown id refused");
        let msg = guard_network(0).unwrap_err().to_lowercase();
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
    fn build_devnet_all_gates_block_rejects_mainnet() {
        assert!(
            build_devnet_all_gates_block(0, 1, [0x44u8; 32], None, 0x207fffff, 1, 1).is_err(),
            "builder refuses mainnet"
        );
    }
}
