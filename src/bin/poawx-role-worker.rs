//! PoAW-X light-miner enrollment worker.
//!
//! A DISTINCT miner independently performs one PoAW-X contributor role
//! (COMPUTE/VERIFY/SUPPORT) per block, bound to its OWN payout key so that
//! solver_pkh == hash160(assignment_public_key) (the Phase-1 rule). It fetches the
//! role-work params, grinds the real sybil ticket + the real assigned puzzle, builds the
//! payout-bound ECVRF assignment proof, the role claim (reveal) and the precommit,
//! then SELF-VERIFIES every artifact against the node validators, and SUBMITS it to the
//! node's /poawx/role-bundle endpoint to ENROLL — so this miner's own payout_pkh is paid
//! its role share. `IRIUM_NODE_RPC` may be a co-located node (loopback) OR a remote pool /
//! Irium Core node that opted in via IRIUM_POAWX_REMOTE_ENROLLMENT=1 (seamless-enrollment
//! Step 1). This is the light-miner path: a keypair + a cheap per-height sybil grind + VRF,
//! no full node required. Fair-distribution PAYOUT of enrolled members is consensus-gated —
//! advisory until the coupled fair-distribution activation, enforced after.
//!
//! Modes:
//!   - default: one-shot — enroll once for the current height, then exit (a scheduler or
//!     the pool can invoke per height).
//!   - IRIUM_POAWX_ROLE_WORKER_LOOP=1: stay-enrolled — poll every
//!     IRIUM_POAWX_ROLE_WORKER_POLL_SECS (default 10s) and re-enroll on each NEW height,
//!     retrying transient errors instead of exiting. This is the "set and forget" client.
//!
//! Env: IRIUM_POAWX_ROLE_SECRET_HEX (payout key), IRIUM_NODE_RPC, IRIUM_RPC_TOKEN,
//!      IRIUM_NETWORK, IRIUM_POAWX_ROLE_WORKER_SUBMIT (=0 to print instead of submit),
//!      IRIUM_POAWX_ROLE_WORKER_LOOP, IRIUM_POAWX_ROLE_WORKER_POLL_SECS.
//!      Arg 1: role = compute|verify|support.
use irium_node_rs::poawx::{
    role_claim_digest, role_precommit_commitment, PoawxRoleClaim, ROLE_COMPUTE_CONTRIBUTOR,
    ROLE_SUPPORT_CONTRIBUTOR, ROLE_VERIFY_CONTRIBUTOR,
};
use irium_node_rs::poawx_candidate::{AssignmentProofV2, RoleCandidate};
use irium_node_rs::poawx_dominance::{PersistentDominance, DOMINANCE_BASE_WORK_SCORE};
use irium_node_rs::poawx_penalty::PenaltyStatus;
use irium_node_rs::poawx_puzzle::{profile_with_bits, solve_dev, verify_solution, PuzzleChallengeV1};
use irium_node_rs::poawx_ticket::{grind_sybil_nonce, TicketProof};
use k256::ecdsa::{SigningKey, VerifyingKey};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

fn h32(s: &str) -> [u8; 32] {
    let b = hex::decode(s.trim()).expect("hex32");
    let mut o = [0u8; 32];
    o.copy_from_slice(&b);
    o
}
fn hash160(b: &[u8]) -> [u8; 20] {
    let mut o = [0u8; 20];
    o.copy_from_slice(&Ripemd160::digest(Sha256::digest(b)));
    o
}
fn role_id(name: &str) -> u8 {
    match name {
        "compute" => ROLE_COMPUTE_CONTRIBUTOR,
        "verify" => ROLE_VERIFY_CONTRIBUTOR,
        "support" => ROLE_SUPPORT_CONTRIBUTOR,
        _ => panic!("role must be compute|verify|support"),
    }
}

/// Build + self-verify + submit one enrollment for the current role-work height. Returns
/// `Ok(Some(height))` after enrolling that height, or `Ok(None)` if the height is unchanged
/// from `last_height` (nothing to do this poll).
#[allow(clippy::too_many_arguments)]
fn enroll_once(
    client: &reqwest::blocking::Client,
    base: &str,
    token: &str,
    role: u8,
    role_name: &str,
    net: u8,
    secret: &[u8; 32],
    sk: &SigningKey,
    payout_pubkey: [u8; 33],
    payout_pkh: [u8; 20],
    last_height: Option<u64>,
) -> Result<Option<u64>, String> {
    // ---- fetch the R3 role-work params (works regardless of proposer-VRF: the epoch
    //      seed used for role assignments is provided here, not the proposer-VRF seed) ----
    // Check the status BEFORE parsing. A busy node answers 503 and a rate-limited one
    // answers 429 with an EMPTY body; decoding first turned both into
    // "role-work json: error decoding response body", which reads like malformed data
    // from a healthy node. That one misleading string cost real time here — the actual
    // condition was a 429, and nothing in the log said so.
    let resp = client
        .get(format!("{base}/poawx/role-work"))
        .bearer_auth(token)
        .send()
        .map_err(|e| format!("role-work fetch: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().unwrap_or_default();
        return Err(format!(
            "role-work rejected by node: {status} {}",
            body.trim()
        ));
    }
    let t: serde_json::Value = resp
        .json()
        .map_err(|e| format!("role-work json: {e}"))?;
    let height = t["height"].as_u64().ok_or("role-work: no height")?;
    // In loop mode, only enroll once per new height.
    if last_height == Some(height) {
        return Ok(None);
    }
    let prev_hash = h32(t["prev_hash"].as_str().ok_or("role-work: no prev_hash")?);
    let seed = h32(t["epoch_seed"].as_str().ok_or("role-work: no epoch_seed")?);
    let puzzle_bits = t["puzzle_anchor_bits"].as_u64().unwrap_or(8) as u8;
    let sybil_bits = t["sybil_bits"].as_u64().unwrap_or(8) as u32;
    let profile = profile_with_bits(puzzle_bits);
    let epoch = height;

    // Node-authoritative dominance: the candidate's `dominance_weight` is consensus-validated
    // (chain.rs `validate_block_dominance_weights`) against the node's persisted dominance, and
    // it is serialized into the candidate whose SHA-256 digest seeds the puzzle challenge. So it
    // MUST be derived from the node's snapshot, never hardcoded. The endpoint ships this snapshot
    // precisely so the worker can build against it (see role-work's dominance note).
    let dominance = PersistentDominance::from_bytes(
        &hex::decode(
            t["dominance_snapshot"]
                .as_str()
                .ok_or("role-work: no dominance_snapshot")?
                .trim(),
        )
        .map_err(|e| format!("dominance_snapshot hex: {e}"))?,
    )?;
    let dominance_weight = dominance.weight(DOMINANCE_BASE_WORK_SCORE, &payout_pkh, height);

    println!("[role-worker] role={role_name} height={height} net={net} payout_pkh={} sybil_bits={sybil_bits} puzzle_bits={puzzle_bits} dominance_weight={dominance_weight}", hex::encode(payout_pkh));

    // ---- 1. real sybil ticket (bound to prev_hash + payout identity) ----
    let nonce = if sybil_bits > 0 {
        grind_sybil_nonce(net, &prev_hash, &payout_pkh, epoch, &payout_pubkey, sybil_bits, 50_000_000)
            .map(|(n, _)| n)
            .ok_or("ticket sybil grind failed")?
    } else {
        [0u8; 32]
    };
    let ticket = TicketProof::new(
        net, height, prev_hash, role, payout_pkh, epoch, height + 100_000, payout_pubkey, nonce,
        PenaltyStatus::Clean.id(),
    );

    // ---- 2. payout-BOUND assignment proof (prove_self_solver => solver==hash160(apk)) ----
    let a_ticket = [(0x11u8 + role); 32];
    let proof = AssignmentProofV2::prove_self_solver(secret, net, height, role, a_ticket, seed)?;
    let cand =
        RoleCandidate::from_assignment_v2(&proof, PenaltyStatus::Clean.id(), dominance_weight, [role; 32]);

    // ---- 3. real assigned puzzle solution (the genuine role WORK) ----
    let cdg: [u8; 32] = Sha256::digest(cand.serialize()).into();
    let challenge = PuzzleChallengeV1::build(
        net, height, role, cand.solver_pkh, cand.ticket_digest, cand.assignment_proof_digest, cdg,
        prev_hash, profile,
    );
    let sol = solve_dev(&challenge).ok_or("puzzle solve failed")?;

    // ---- 4. role claim (reveal) + precommit commitment ----
    let lane = irium_node_rs::poawx::assign_lane(net, height, &prev_hash, role, 0);
    // deterministic per-(height,role) secret/nonce from the payout key (so reveal==precommit)
    let mk = |tag: &[u8]| -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"IRIUM_ROLE_WORKER_CLAIM_V1");
        h.update(tag);
        h.update(secret);
        h.update(height.to_le_bytes());
        h.update([role]);
        h.finalize().into()
    };
    let c_secret = mk(b"secret");
    let c_nonce = mk(b"nonce");
    let commitment = role_precommit_commitment(&c_secret, &c_nonce);
    let claim_digest =
        role_claim_digest(net, height, &prev_hash, role, lane.id(), &payout_pkh, &c_nonce, &c_secret);
    let claim = PoawxRoleClaim {
        role_id: role,
        lane_id: lane.id(),
        solver_pkh: payout_pkh,
        nonce: c_nonce,
        secret: c_secret,
        claim_digest,
        commitment_hash: Some(commitment),
    };

    // ---- 5. SELF-VERIFY every artifact against the node validators ----
    proof.validate(net, height)?;
    let expect = hash160(&proof.assignment_public_key);
    if proof.solver_pkh != expect {
        return Err("PHASE1 FAIL: solver_pkh != hash160(assignment_public_key)".into());
    }
    if proof.solver_pkh != payout_pkh {
        return Err("assignment solver != payout pkh".into());
    }
    ticket.validate(net, height, &prev_hash, role, &payout_pkh, sybil_bits, false)?;
    match verify_solution(&challenge, &sol) {
        irium_node_rs::poawx_puzzle::PuzzleVerificationResult::Valid => {}
        other => return Err(format!("puzzle verify: {other:?}")),
    }
    irium_node_rs::poawx::validate_role_claim(&claim, net, height, &prev_hash, 0)?;
    if role_precommit_commitment(&claim.secret, &claim.nonce) != commitment {
        return Err("precommit commitment mismatch".into());
    }

    // ---- 6. R4: SUPPORT doubles as the finality committee member, so it self-signs its
    //         OWN finality vote (the builder holds no key for it). The vote finalizes the
    //         PARENT (block_hash = prev_hash), bound to this worker's real ticket_digest.
    let finality_vote = if role == ROLE_SUPPORT_CONTRIBUTOR {
        let v = irium_node_rs::poawx_finality::FinalityVoteV1::signed(
            sk,
            net,
            height,
            prev_hash,
            [0u8; 32],
            0,
            ticket.ticket_digest,
            irium_node_rs::poawx_finality::FinalityVoteType::Commit,
        );
        v.verify(net, height, &prev_hash)?;
        Some(v)
    } else {
        None
    };

    // ---- 7. assemble the payout-bound bundle ----
    let mut bundle = serde_json::json!({
        "network_id": net, "target_height": height, "role_id": role, "role": role_name,
        "solver_pkh": hex::encode(payout_pkh),
        "assignment_public_key": hex::encode(payout_pubkey),
        "assignment_proof": hex::encode(proof.serialize()),
        "ticket_proof": hex::encode(ticket.serialize()),
        "puzzle_solution": hex::encode(sol.serialize()),
        "claim": {
            "lane_id": lane.id(),
            "secret": hex::encode(c_secret), "nonce": hex::encode(c_nonce),
            "commitment_hash": hex::encode(commitment), "claim_digest": hex::encode(claim_digest),
        },
    });
    if let Some(v) = &finality_vote {
        bundle["finality_vote"] = serde_json::Value::String(hex::encode(v.serialize()));
    }

    // ---- 8. SUBMIT the enrollment (or print it in inspection mode) ----
    let submit = std::env::var("IRIUM_POAWX_ROLE_WORKER_SUBMIT")
        .map(|v| v.trim() != "0")
        .unwrap_or(true);
    if !submit {
        println!("{}", serde_json::to_string_pretty(&bundle).unwrap());
        return Ok(Some(height));
    }
    let resp = client
        .post(format!("{base}/poawx/role-bundle"))
        .bearer_auth(token)
        .json(&bundle)
        .send()
        .map_err(|e| format!("role-bundle submit: {e}"))?;
    let status = resp.status();
    let body = resp.text().unwrap_or_default();
    if !status.is_success() {
        return Err(format!(
            "role-bundle submit rejected by node: {status} {}",
            body.trim()
        ));
    }
    println!(
        "[role-worker] ENROLLED role={role_name} height={height} pkh={} -> {status} {}",
        hex::encode(payout_pkh),
        body.trim()
    );
    Ok(Some(height))
}

fn main() -> Result<(), String> {
    let role_name = std::env::args().nth(1).unwrap_or_else(|| "compute".into());
    let role = role_id(&role_name);
    let net = irium_node_rs::activation::network_id_byte();
    let secret = {
        let hx = std::env::var("IRIUM_POAWX_ROLE_SECRET_HEX")
            .map_err(|_| "set IRIUM_POAWX_ROLE_SECRET_HEX (payout key, 64 hex)".to_string())?;
        let b = hex::decode(hx.trim()).map_err(|e| format!("bad secret hex: {e}"))?;
        let mut o = [0u8; 32];
        o.copy_from_slice(&b);
        o
    };
    let sk = SigningKey::from_bytes((&secret).into()).map_err(|_| "bad secret".to_string())?;
    let mut payout_pubkey = [0u8; 33];
    payout_pubkey.copy_from_slice(VerifyingKey::from(&sk).to_encoded_point(true).as_bytes());
    let payout_pkh = hash160(&payout_pubkey);

    let base = std::env::var("IRIUM_NODE_RPC").unwrap_or_else(|_| "http://127.0.0.1:38500".into());
    let token = std::env::var("IRIUM_RPC_TOKEN").unwrap_or_default();
    let client = reqwest::blocking::Client::new();

    let loop_mode = std::env::var("IRIUM_POAWX_ROLE_WORKER_LOOP")
        .map(|v| v.trim() == "1")
        .unwrap_or(false);

    // One-shot: run once and propagate errors (nonzero exit) exactly as before.
    if !loop_mode {
        return enroll_once(
            &client, &base, &token, role, &role_name, net, &secret, &sk, payout_pubkey, payout_pkh,
            None,
        )
        .map(|_| ());
    }

    // Stay-enrolled: poll for new heights and re-enroll, retrying transient errors.
    // Default 2s: the block producer only waits a bounded window (IRIUM_POAWX_FANOUT_WAIT_MS,
    // ~3s) for enrollments before it fixes the coinbase and grinds PoW, so a slow poll would
    // miss fast (burst) blocks and self-fill them. Keep enroll latency (poll + grind) well
    // under the producer's wait.
    let poll_secs = std::env::var("IRIUM_POAWX_ROLE_WORKER_POLL_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|s| *s > 0)
        .unwrap_or(2);
    // Back off on CONSECUTIVE failures, and only on failures. Retrying a refused node at the
    // normal poll rate is what turned a transient refusal into a standing one on 2026-07-29:
    // the node answered 429, the worker retried immediately, and the retries kept the source
    // over its allowance so it never recovered. Backoff makes that trap unreachable from this
    // side regardless of how the node budgets requests. Doubling from the poll interval, capped
    // so a worker still re-enrolls promptly once the node recovers — a role that stays quiet
    // costs its operator the block's role share.
    let backoff_cap_secs = std::env::var("IRIUM_POAWX_ROLE_WORKER_BACKOFF_MAX_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|s| *s > 0)
        .unwrap_or(60);
    println!(
        "[role-worker] loop mode: role={role_name} poll={poll_secs}s backoff_max={backoff_cap_secs}s node={base}"
    );
    let mut last_height: Option<u64> = None;
    let mut consecutive_errors: u32 = 0;
    loop {
        match enroll_once(
            &client, &base, &token, role, &role_name, net, &secret, &sk, payout_pubkey, payout_pkh,
            last_height,
        ) {
            Ok(Some(h)) => {
                last_height = Some(h);
                consecutive_errors = 0;
            }
            Ok(None) => consecutive_errors = 0,
            Err(e) => {
                consecutive_errors = consecutive_errors.saturating_add(1);
                let wait = backoff_secs(poll_secs, consecutive_errors, backoff_cap_secs);
                eprintln!(
                    "[role-worker] enrollment error #{consecutive_errors} (retry in {wait}s): {e}"
                );
            }
        }
        let wait = if consecutive_errors == 0 {
            poll_secs
        } else {
            backoff_secs(poll_secs, consecutive_errors, backoff_cap_secs)
        };
        std::thread::sleep(std::time::Duration::from_secs(wait));
    }
}

/// Exponential backoff for consecutive enrollment failures: `poll * 2^(errors-1)`, capped.
/// `errors == 0` means "no failure" and is not a backoff case, but is handled as the plain
/// poll interval so the caller cannot accidentally stall a healthy worker.
fn backoff_secs(poll_secs: u64, consecutive_errors: u32, cap_secs: u64) -> u64 {
    if consecutive_errors == 0 {
        return poll_secs;
    }
    let shift = consecutive_errors.saturating_sub(1).min(16);
    let scaled = poll_secs.saturating_mul(1u64 << shift);
    scaled.clamp(poll_secs, cap_secs.max(poll_secs))
}

#[cfg(test)]
mod tests {
    use super::backoff_secs;

    #[test]
    fn backoff_grows_then_caps_and_never_stalls_a_healthy_worker() {
        // No failures => plain poll interval, never a backoff.
        assert_eq!(backoff_secs(2, 0, 60), 2);
        // Consecutive failures double from the poll interval.
        assert_eq!(backoff_secs(2, 1, 60), 2);
        assert_eq!(backoff_secs(2, 2, 60), 4);
        assert_eq!(backoff_secs(2, 3, 60), 8);
        assert_eq!(backoff_secs(2, 4, 60), 16);
        // ... and are capped, so a long outage never pushes re-enrollment out to hours.
        assert_eq!(backoff_secs(2, 20, 60), 60);
        // A huge error count must not overflow into a tiny or absurd wait.
        assert_eq!(backoff_secs(2, u32::MAX, 60), 60);
        // The cap can never drop the wait below the configured poll interval.
        assert_eq!(backoff_secs(30, 5, 10), 30);
    }
}
