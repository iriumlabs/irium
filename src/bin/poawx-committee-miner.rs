//! PoAW-X committee miner (devnet build-out).
//!
//! Assembles a block carrying a GENUINE multi-member SUPPORT finality committee — a
//! candidate set with N support candidates and a finality proof with N signed Commit
//! votes — so the node's `block_finality_has_genuine_quorum` gate can advance
//! `finalized_height`. This is the piece the existing solo/collected builders never
//! had (they collapse the committee to one member + one vote).
//!
//! Model: ONE proposer key (from IRIUM_POAWX_MINER_SECRET_HEX) plays PRIMARY + the
//! compute/verify role winners; a pool of registered committee keys (from
//! IRIUM_POAWX_COMMITTEE_KEYS_FILE, one 32-byte hex secret per line) each produce a
//! SUPPORT-role VRF assignment (→ a support candidate) and sign a finality vote. The
//! max-effective-score member is the SUPPORT reward winner (so it stays
//! `best_for_role(SUPPORT)` and carries the real VRF proof the true-VRF gate verifies).
//! All committee keys MUST be registered proposer keys so their votes count toward the
//! genuine quorum. Mainnet-hard-off (devnet tool: reuses `poawx_miner_client`).

use irium_node_rs::activation::network_id_byte;
use irium_node_rs::poawx::{
    ProposerAssignmentV1, ProposerRegistrationSection, ProposerRegistrationV1,
    ROLE_COMPUTE_CONTRIBUTOR, ROLE_SUPPORT_CONTRIBUTOR, ROLE_VERIFY_CONTRIBUTOR,
};
use irium_node_rs::poawx_candidate::{AssignmentProofV2, CandidateSet, RoleCandidate};
use irium_node_rs::poawx_committed_admission::{admission_epoch_seed, resolve_epoch_seed_parts_with};
use irium_node_rs::poawx_dominance::DOMINANCE_BASE_WORK_SCORE;
use irium_node_rs::poawx_finality::{FinalityVoteType, FinalityVoteV1};
use irium_node_rs::poawx_miner_client::{
    build_poawx_submit_request, fetch_block_template, poawx_decode_hash32, poawx_fetch_dominance,
    poawx_fetch_parent_info, poawx_miner_interval_secs, poawx_miner_secret, poawx_post_admission,
    poawx_receipt_difficulty_bits, poawx_submit_extended, poawx_submit_registration, rpc_client,
};
use irium_node_rs::poawx_mining_harness::{
    build_committee_poawx_block_with_proposer, NodeGateFlags, ProposerCtx,
};
use irium_node_rs::poawx_penalty::PenaltyStatus;
use irium_node_rs::poawx_proposer::{
    is_selected, pool_sortition_admitted, pool_sortition_k, proposer_priority, ROLE_PROPOSER,
};
use irium_node_rs::poawx_ticket::{effective_sybil_bits, grind_sybil_nonce, TicketProof};
use k256::ecdsa::SigningKey;
use std::{env, fs, thread, time::Duration};

/// A built candidate for one role: (secret, candidate, optional finality vote, ECVRF
/// assignment proof, optional sybil ticket). Proof + ticket feed the Step-3 PLA1
/// pool-admission section for the paid VERIFY/SUPPORT fan-out roles.
type PoolEntry = (
    [u8; 32],
    RoleCandidate,
    Option<FinalityVoteV1>,
    AssignmentProofV2,
    Option<TicketProof>,
);

fn load_committee_keys() -> Result<Vec<[u8; 32]>, String> {
    let path = env::var("IRIUM_POAWX_COMMITTEE_KEYS_FILE")
        .map_err(|_| "set IRIUM_POAWX_COMMITTEE_KEYS_FILE to a file of 32-byte hex secrets".to_string())?;
    read_keys_file(&path)
}

fn read_keys_file(path: &str) -> Result<Vec<[u8; 32]>, String> {
    let data = fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    let mut out = Vec::new();
    for line in data.lines() {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        let b = hex::decode(l).map_err(|e| format!("bad key hex in {path}: {e}"))?;
        if b.len() != 32 {
            return Err(format!("key not 32 bytes in {path}: {} bytes", b.len()));
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&b);
        out.push(k);
    }
    if out.is_empty() {
        return Err(format!("keys file {path} is empty"));
    }
    Ok(out)
}

/// Load a role key pool from `env_var`'s file, or fall back to a single-key pool
/// containing `fallback` (Step-1 behaviour: that role is played only by the proposer).
fn load_role_keys(env_var: &str, fallback: &[u8; 32]) -> Result<Vec<[u8; 32]>, String> {
    match env::var(env_var) {
        Ok(p) if !p.trim().is_empty() => read_keys_file(p.trim()),
        _ => Ok(vec![*fallback]),
    }
}

fn run() -> Result<(), String> {
    let net = network_id_byte();
    let proposer_secret = poawx_miner_secret()?;
    let committee = load_committee_keys()?;
    let compute_keys = load_role_keys("IRIUM_POAWX_COMPUTE_KEYS_FILE", &proposer_secret)?;
    let verify_keys = load_role_keys("IRIUM_POAWX_VERIFY_KEYS_FILE", &proposer_secret)?;
    let client = rpc_client()?;
    let diff = poawx_receipt_difficulty_bits();
    let interval = poawx_miner_interval_secs();
    let want = env::var("IRIUM_POAWX_COMMITTEE_SIZE")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(committee.len())
        .min(committee.len());
    println!(
        "[committee] miner started net={net} support_keys={} compute_keys={} verify_keys={} target_size={want} interval={interval}s",
        committee.len(),
        compute_keys.len(),
        verify_keys.len()
    );
    let mut last_reg: u64 = 0;
    loop {
        let tmpl = match fetch_block_template(&client, false) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("[committee] template fetch failed: {e}; retrying");
                thread::sleep(Duration::from_secs(3));
                continue;
            }
        };
        let height = tmpl.height;
        let prev_hash = poawx_decode_hash32(&tmpl.prev_hash)?;
        let bits = u32::from_str_radix(tmpl.bits.trim_start_matches("0x"), 16)
            .map_err(|e| format!("bad template bits {}: {e}", tmpl.bits))?;
        let (parent_prev_hash, parent_seed_components) = poawx_fetch_parent_info(&client, height)?;
        let dominance = match poawx_fetch_dominance(&client) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("[committee] dominance fetch failed: {e}; retrying");
                thread::sleep(Duration::from_secs(3));
                continue;
            }
        };

        // Gate flags from the node template (authoritative).
        let node_gates = match (
            tmpl.poawx_hidden_precommit_active,
            tmpl.poawx_tickets_active,
            tmpl.poawx_multisource_seed_active,
            tmpl.poawx_penalty_state_active,
            tmpl.poawx_puzzle_anchor_bits,
            tmpl.poawx_effective_sybil_bits,
        ) {
            (Some(hp), Some(tk), Some(ms), Some(pn), Some(pb), Some(sb)) => Some(NodeGateFlags {
                hidden_precommit_active: hp,
                tickets_active: tk,
                multisource_seed_active: ms,
                penalty_state_active: pn,
                puzzle_anchor_bits: pb,
                effective_sybil_bits: sb,
                audit_hardening_active: tmpl.poawx_audit_hardening_active.unwrap_or_else(|| {
                    irium_node_rs::poawx_proposer::audit_hardening_active(height)
                }),
            }),
            _ => None,
        };

        // Compute the candidate-set / assignment epoch seed EXACTLY as the builder does
        // (same public functions), so each committee member's support proof binds to the
        // seed the node validates against.
        let multisource_active = node_gates
            .as_ref()
            .map(|g| g.multisource_seed_active)
            .unwrap_or_else(|| {
                irium_node_rs::poawx_committed_admission::multisource_seed_active(height)
            });
        let (fin_digest, precommit_digest) = parent_seed_components;
        let base_seed = admission_epoch_seed(parent_prev_hash, prev_hash);
        let epoch_seed = resolve_epoch_seed_parts_with(
            multisource_active,
            height,
            base_seed,
            fin_digest,
            precommit_digest,
        );

        // Keep the proposer key registered on-chain (throttled) so eligible_count holds.
        if tmpl.poawx_reg_active.unwrap_or(false)
            && (last_reg == 0 || height.saturating_sub(last_reg) >= 20)
        {
            if let Some(ah) = tmpl.poawx_reg_anchor_hash.clone() {
                if let Ok(a_hash) = poawx_decode_hash32(&ah) {
                    let a_h = tmpl.poawx_reg_anchor_height.unwrap_or(0);
                    let sb = tmpl.poawx_reg_required_sybil_bits.unwrap_or(0);
                    if let Ok(reg) =
                        ProposerRegistrationV1::build_signed(&proposer_secret, net, a_h, &a_hash, sb)
                    {
                        if poawx_submit_registration(&client, &reg.serialize()).is_ok() {
                            last_reg = height;
                        }
                    }
                }
            }
        }

        // Proposer-VRF sortition (identical to the solo miner).
        let proposer_ctx = if tmpl.poawx_proposer_vrf_active.unwrap_or(false) {
            let seed = match tmpl.poawx_proposer_seed.as_deref() {
                Some(s) => match poawx_decode_hash32(s) {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("[committee] bad proposer seed: {e}; retrying");
                        thread::sleep(Duration::from_secs(3));
                        continue;
                    }
                },
                None => {
                    eprintln!("[committee] proposer active but no seed; retrying");
                    thread::sleep(Duration::from_secs(3));
                    continue;
                }
            };
            let eligible = tmpl.poawx_proposer_eligible_count.unwrap_or(0);
            let max_round = tmpl.poawx_proposer_max_allowed_round.unwrap_or(0);
            let proof = match AssignmentProofV2::prove_self_solver(
                &proposer_secret,
                net,
                height,
                ROLE_PROPOSER,
                [0u8; 32],
                seed,
            ) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("[committee] proposer proof failed: {e}; retrying");
                    thread::sleep(Duration::from_secs(3));
                    continue;
                }
            };
            let priority = proposer_priority(&proof.vrf_output);
            match (0..=max_round).find(|r| is_selected(priority, eligible, *r)) {
                Some(r) => {
                    println!(
                        "[committee] proposer SELECTED height={height} round={r} eligible={eligible}"
                    );
                    Some(ProposerCtx {
                        assignment: ProposerAssignmentV1 { round: r, proof },
                    })
                }
                None => {
                    println!(
                        "[committee] not proposer height={height} (eligible={eligible} max_round={max_round}); waiting"
                    );
                    thread::sleep(Duration::from_secs(3));
                    continue;
                }
            }
        } else {
            None
        };

        // Producer registration section from the template (drain activations/announces).
        let registration_section = {
            let parse = |v: &Option<Vec<String>>| -> Vec<ProposerRegistrationV1> {
                v.as_ref()
                    .map(|l| {
                        l.iter()
                            .filter_map(|h| hex::decode(h).ok())
                            .filter_map(|b| ProposerRegistrationV1::deserialize(&b).ok())
                            .collect()
                    })
                    .unwrap_or_default()
            };
            let activations = parse(&tmpl.poawx_reg_activations);
            let announces = parse(&tmpl.poawx_reg_announces);
            if tmpl.poawx_reg_active.unwrap_or(false)
                && (!activations.is_empty() || !announces.is_empty())
            {
                Some(ProposerRegistrationSection {
                    announces,
                    activations,
                })
            } else {
                None
            }
        };

        // Build a role candidate pool from a key list: one candidate per key, proving the
        // given role with the per-role ticket that `build_roles` uses (COMPUTE=0x11,
        // VERIFY=0x12, SUPPORT=0x13) so the winner's pool candidate is byte-identical to
        // the one the builder constructs. SUPPORT members also self-sign a finality vote.
        // Returns (secret, candidate, Option<vote>) per key.
        let ticket_for = |role: u8| -> [u8; 32] {
            match role {
                ROLE_COMPUTE_CONTRIBUTOR => [0x11u8; 32],
                ROLE_VERIFY_CONTRIBUTOR => [0x12u8; 32],
                _ => [0x13u8; 32],
            }
        };
        let sybil_bits = effective_sybil_bits();
        let build_pool = |role: u8, keys: &[[u8; 32]], sign_vote: bool, need_ticket: bool|
         -> Vec<PoolEntry> {
            let mut out = Vec::new();
            for secret in keys {
                let proof = match AssignmentProofV2::prove_self_solver(
                    secret,
                    net,
                    height,
                    role,
                    ticket_for(role),
                    epoch_seed,
                ) {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                let sk = match SigningKey::from_bytes(secret.into()) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let w = dominance.weight(DOMINANCE_BASE_WORK_SCORE, &proof.solver_pkh, height);
                let cand = RoleCandidate::from_assignment_v2(
                    &proof,
                    PenaltyStatus::Clean.id(),
                    w,
                    [role; 32],
                );
                let vote = if sign_vote {
                    Some(FinalityVoteV1::signed(
                        &sk,
                        net,
                        height,
                        prev_hash,
                        [0u8; 32],
                        0,
                        [0x11u8; 32],
                        FinalityVoteType::Commit,
                    ))
                } else {
                    None
                };
                // Sybil ticket for the paid fan-out roles: grind the sybil nonce bound to
                // this member's own pkh + assignment key (the node re-verifies it in PLA1).
                let ticket = if need_ticket {
                    let apk = proof.assignment_public_key;
                    let nonce = if sybil_bits > 0 {
                        match grind_sybil_nonce(
                            net,
                            &prev_hash,
                            &proof.solver_pkh,
                            height,
                            &apk,
                            sybil_bits,
                            50_000_000,
                        ) {
                            Some((n, _)) => n,
                            None => continue,
                        }
                    } else {
                        [0u8; 32]
                    };
                    Some(TicketProof::new(
                        net,
                        height,
                        prev_hash,
                        role,
                        proof.solver_pkh,
                        height,
                        height + 100_000,
                        apk,
                        nonce,
                        PenaltyStatus::Clean.id(),
                    ))
                } else {
                    None
                };
                out.push((*secret, cand, vote, proof, ticket));
            }
            out
        };
        // Pick a role's winner exactly as the node does (`best_for_role`), then split into
        // (winner_secret, extra_candidates, extra_votes, extra_proofs, extra_tickets). The
        // extra proofs+tickets are the NON-WINNER members' pool-admission evidence (PLA1).
        #[allow(clippy::type_complexity)]
        // NEGATIVE-CONTROL tamper: bypass the miner's sortition filter so it stuffs the pool
        // with NON-CLEARING members — the node's validate_pool_sortition must then reject.
        let sortition_on = irium_node_rs::chain::pool_sortition_enforced(height)
            && env::var("IRIUM_POAWX_TAMPER_SORTITION").is_err();
        let select_winner = |role: u8, eligible: u64, pool: &[PoolEntry]|
         -> Result<
            (
                [u8; 32],
                Vec<RoleCandidate>,
                Vec<FinalityVoteV1>,
                Vec<AssignmentProofV2>,
                Vec<TicketProof>,
            ),
            String,
        > {
            let mut sel = CandidateSet::new(net, height, epoch_seed);
            for e in pool {
                sel.push(e.1.clone());
            }
            sel.sort_canonical();
            let winner_pkh = sel
                .best_for_role(role)
                .map(|c| c.solver_pkh)
                .ok_or_else(|| format!("no winner for role {role}"))?;
            let win_idx = pool
                .iter()
                .position(|e| e.1.solver_pkh == winner_pkh)
                .ok_or_else(|| format!("winner not in pool for role {role}"))?;
            let k = pool_sortition_k(role);
            // A1/A2: keep a NON-WINNER member only if it clears the VRF sortition threshold
            // (when the gate is active). The winner is always kept. This is what the node's
            // validate_pool_sortition re-checks, so the miner only submits admissible pools.
            let keep = |i: usize, e: &PoolEntry| -> bool {
                if i == win_idx {
                    return false;
                }
                if sortition_on {
                    let pri = proposer_priority(&e.1.assignment_proof_digest);
                    pool_sortition_admitted(pri, eligible, k)
                } else {
                    true
                }
            };
            let extras = pool
                .iter()
                .enumerate()
                .filter(|(i, e)| keep(*i, e))
                .map(|(_, e)| e.1.clone())
                .collect();
            let votes = pool
                .iter()
                .enumerate()
                .filter(|(i, e)| keep(*i, e))
                .filter_map(|(_, e)| e.2.clone())
                .collect();
            let proofs = pool
                .iter()
                .enumerate()
                .filter(|(i, e)| keep(*i, e))
                .map(|(_, e)| e.3.clone())
                .collect();
            let tickets = pool
                .iter()
                .enumerate()
                .filter(|(i, e)| keep(*i, e))
                .filter_map(|(_, e)| e.4.clone())
                .collect();
            Ok((pool[win_idx].0, extras, votes, proofs, tickets))
        };

        // SUPPORT = finality committee (registered keys, they vote + are ticketed).
        // VERIFY = "other valid workers" pool (ticketed). COMPUTE = best-worker pool
        // (single winner paid, no per-member ticket needed for the unpaid rest).
        let support_pool = build_pool(ROLE_SUPPORT_CONTRIBUTOR, &committee[..want], true, true);
        let compute_pool = build_pool(ROLE_COMPUTE_CONTRIBUTOR, &compute_keys, false, false);
        let verify_pool = build_pool(ROLE_VERIFY_CONTRIBUTOR, &verify_keys, false, true);
        if support_pool.len() < 2 || compute_pool.is_empty() || verify_pool.is_empty() {
            eprintln!("[committee] pool too small (support>=2, compute>=1, verify>=1); waiting");
            thread::sleep(Duration::from_secs(3));
            continue;
        }
        // eligible_count drives the sortition threshold — must match the node's
        // eligible_count(H-1). Stable registration => template value == node value.
        let sortition_eligible = tmpl.poawx_proposer_eligible_count.unwrap_or(0);

        let (support_winner, extra_support, extra_votes, support_proofs, support_tickets) =
            match select_winner(ROLE_SUPPORT_CONTRIBUTOR, sortition_eligible, &support_pool) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("[committee] support winner: {e}; retrying");
                    thread::sleep(Duration::from_secs(3));
                    continue;
                }
            };
        let (compute_winner, extra_compute, _, _, _) =
            match select_winner(ROLE_COMPUTE_CONTRIBUTOR, sortition_eligible, &compute_pool) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("[committee] compute winner: {e}; retrying");
                    thread::sleep(Duration::from_secs(3));
                    continue;
                }
            };
        let (verify_winner, extra_verify, _, verify_proofs, verify_tickets) =
            match select_winner(ROLE_VERIFY_CONTRIBUTOR, sortition_eligible, &verify_pool) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("[committee] verify winner: {e}; retrying");
                    thread::sleep(Duration::from_secs(3));
                    continue;
                }
            };
        // Combine the non-winner VERIFY + SUPPORT members' proofs+tickets for the PLA1
        // pool-admission section (COMPUTE non-winners are unpaid → no admission needed).
        let mut pool_proofs = verify_proofs;
        pool_proofs.extend(support_proofs);
        let mut pool_tickets = verify_tickets;
        pool_tickets.extend(support_tickets);
        // NEGATIVE-CONTROL hook (devnet): under-admit or forge the pool evidence so the
        // block still carries the paid pool member in its candidate set but LACKS valid
        // admission — the node's pool-admission gate must reject. Simulates a builder
        // stuffing the fan-out pools with pkhs it cannot legitimately admit.
        if let Ok(mode) = env::var("IRIUM_POAWX_TAMPER_POOL") {
            match mode.as_str() {
                "drop_proof" => {
                    pool_proofs.pop();
                }
                "drop_ticket" => {
                    pool_tickets.pop();
                }
                "forge_proof" => {
                    if let Some(p) = pool_proofs.first_mut() {
                        p.vrf_output[0] ^= 0xFF; // no longer matches the candidate digest / VRF
                    }
                }
                _ => {}
            }
        }
        let winner_pkh = support_pool
            .iter()
            .find(|e| e.0 == support_winner)
            .map(|e| e.1.solver_pkh)
            .unwrap_or([0u8; 20]);
        let members_count = support_pool.len();
        let verify_count = verify_pool.len();

        let proof = match build_committee_poawx_block_with_proposer(
            &proposer_secret,
            &compute_winner,
            &verify_winner,
            &support_winner,
            extra_support,
            extra_votes,
            extra_compute,
            extra_verify,
            pool_proofs,
            pool_tickets,
            net,
            height,
            prev_hash,
            parent_prev_hash,
            bits,
            tmpl.time,
            diff,
            parent_seed_components,
            &dominance,
            node_gates.as_ref(),
            proposer_ctx.as_ref(),
            registration_section.as_ref(),
        ) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[committee] build failed at height {height}: {e}; retrying");
                thread::sleep(Duration::from_secs(3));
                continue;
            }
        };

        for (i, adm) in proof.admissions.iter().enumerate() {
            if let Err(e) = poawx_post_admission(&client, adm) {
                eprintln!("[committee] admission[{i}] gossip post failed (non-fatal): {e}");
            }
        }
        let req = build_poawx_submit_request(&proof)?;
        match poawx_submit_extended(&client, &req) {
            Ok(()) => println!(
                "[committee] SUBMITTED height={height} support_committee={} verify_pool={} finality_winner={}",
                members_count,
                verify_count,
                hex::encode(winner_pkh)
            ),
            Err(e) => eprintln!("[committee] submit failed at height {height}: {e}"),
        }
        thread::sleep(Duration::from_secs(interval));
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("[committee] error: {e}");
        std::process::exit(1);
    }
}
