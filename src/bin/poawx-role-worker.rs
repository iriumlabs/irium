//! Stage D role-attribution Phase 2: miner-side role-work worker.
//!
//! A DISTINCT pool-connected miner independently performs one PoAW-X contributor
//! role (COMPUTE/VERIFY/SUPPORT) per block, bound to its OWN payout key so that
//! solver_pkh == hash160(assignment_public_key) (the Phase-1 rule). It fetches the
//! node template, grinds the real sybil ticket + the real assigned puzzle, builds the
//! payout-bound ECVRF assignment proof, the role claim (reveal) and the precommit,
//! then SELF-VERIFIES every artifact against the node validators. Off mainnet /
//! isolated rig only. Emits the full bundle for the Phase-3 collection channel.
//!
//! Env: IRIUM_POAWX_ROLE_SECRET_HEX (payout key), IRIUM_NODE_RPC, IRIUM_RPC_TOKEN,
//!      IRIUM_NETWORK. Arg 1: role = compute|verify|support.
use irium_node_rs::poawx::{
    role_claim_digest, role_precommit_commitment, PoawxRoleClaim, ROLE_COMPUTE_CONTRIBUTOR,
    ROLE_SUPPORT_CONTRIBUTOR, ROLE_VERIFY_CONTRIBUTOR,
};
use irium_node_rs::poawx_candidate::{AssignmentProofV2, RoleCandidate};
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

    // ---- fetch the node template (isolated rig) ----
    let base = std::env::var("IRIUM_NODE_RPC").unwrap_or_else(|_| "http://127.0.0.1:38500".into());
    let token = std::env::var("IRIUM_RPC_TOKEN").unwrap_or_default();
    let client = reqwest::blocking::Client::new();
    let t: serde_json::Value = client
        .get(format!("{base}/rpc/getblocktemplate"))
        .bearer_auth(&token)
        .send()
        .map_err(|e| format!("template fetch: {e}"))?
        .json()
        .map_err(|e| format!("template json: {e}"))?;
    let height = t["height"].as_u64().ok_or("template: no height")?;
    let prev_hash = h32(t["prev_hash"].as_str().ok_or("template: no prev_hash")?);
    let seed = h32(
        t["poawx_proposer_seed"]
            .as_str()
            .ok_or("template: no poawx_proposer_seed (epoch seed) -- proposer-VRF must be active")?,
    );
    let puzzle_bits = t["poawx_puzzle_anchor_bits"].as_u64().unwrap_or(8) as u8;
    let sybil_bits = t["poawx_effective_sybil_bits"].as_u64().unwrap_or(8) as u32;
    let profile = profile_with_bits(puzzle_bits);
    let epoch = height;

    println!("[role-worker] role={role_name} height={height} net={net} payout_pkh={} sybil_bits={sybil_bits} puzzle_bits={puzzle_bits}", hex::encode(payout_pkh));

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
    //     assignment ticket_digest mirrors the accepted harness pattern (per-role constant).
    let a_ticket = [(0x11u8 + role); 32];
    let proof = AssignmentProofV2::prove_self_solver(&secret, net, height, role, a_ticket, seed)?;
    let cand = RoleCandidate::from_assignment_v2(&proof, PenaltyStatus::Clean.id(), 1000, [role; 32]);

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

    // ---- 6. emit the payout-bound bundle (for the Phase-3 collection channel) ----
    println!("[role-worker] ALL ARTIFACTS SELF-VERIFIED. Phase-1 binding holds: solver_pkh == hash160(assignment_public_key) == payout_pkh.");
    let bundle = serde_json::json!({
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
    println!("{}", serde_json::to_string_pretty(&bundle).unwrap());
    Ok(())
}
