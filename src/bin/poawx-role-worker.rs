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
use irium_node_rs::poawx::ProposerRegistrationV1;
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
/// Parse the role argument. `auto` (or no argument) means the chain decides, and is carried
/// as a PLACEHOLDER role that the assignment lookup replaces before any work is done.
/// Returns an error rather than panicking on a typo, so a mistyped role is a clean message
/// instead of a stack trace.
fn parse_role_arg(name: &str) -> Result<u8, String> {
    match name {
        "auto" => Ok(ROLE_COMPUTE_CONTRIBUTOR),
        "compute" => Ok(ROLE_COMPUTE_CONTRIBUTOR),
        "verify" => Ok(ROLE_VERIFY_CONTRIBUTOR),
        "support" => Ok(ROLE_SUPPORT_CONTRIBUTOR),
        other => Err(format!(
            "role must be auto|compute|verify|support (got {other:?}); \
             `auto` lets the chain assign it"
        )),
    }
}

fn role_id(name: &str) -> u8 {
    match name {
        "compute" => ROLE_COMPUTE_CONTRIBUTOR,
        "verify" => ROLE_VERIFY_CONTRIBUTOR,
        "support" => ROLE_SUPPORT_CONTRIBUTOR,
        _ => panic!("role must be compute|verify|support"),
    }
}

/// Build + self-verify + submit one enrollment for the current role-work slot. Returns
/// `Ok(Some((height, prev_hash)))` after enrolling, or `Ok(None)` if BOTH the height and the
/// parent are unchanged from `last_slot` (nothing to do this poll).
#[allow(clippy::too_many_arguments)]
fn enroll_once(
    transport: &mut Transport,
    role: u8,
    role_name: &str,
    net: u8,
    secret: &[u8; 32],
    sk: &SigningKey,
    payout_pubkey: [u8; 33],
    payout_pkh: [u8; 20],
    last_slot: Option<(u64, [u8; 32])>,
) -> Result<Option<(u64, [u8; 32])>, String> {
    // ---- fetch the R3 role-work params (works regardless of proposer-VRF: the epoch
    //      seed used for role assignments is provided here, not the proposer-VRF seed) ----
    // Check the status BEFORE parsing. A busy node answers 503 and a rate-limited one
    // answers 429 with an EMPTY body; decoding first turned both into
    // "role-work json: error decoding response body", which reads like malformed data
    // from a healthy node. That one misleading string cost real time here — the actual
    // condition was a 429, and nothing in the log said so.
    // Over HTTP this is a node GET; over Stratum the pool relays the same GET. Identical
    // JSON either way, so everything below is transport-agnostic.
    let t: serde_json::Value = transport.role_work()?;
    let height = t["height"].as_u64().ok_or("role-work: no height")?;
    let prev_hash = h32(t["prev_hash"].as_str().ok_or("role-work: no prev_hash")?);
    // In loop mode, enroll once per (height, PARENT) -- not once per height.
    //
    // Every artifact below is bound to `prev_hash`: the sybil ticket, the role claim, the
    // finality vote, and -- critically -- the assigned puzzle, whose MODE is seeded from it
    // (`assign_puzzle_mode`). So when the parent changes while the height does not (a sibling
    // lands, or a reorg replaces the tip), a bundle enrolled against the OLD parent describes
    // a puzzle no builder will ever derive. It cannot verify, at any producer, ever.
    //
    // Keying on height alone meant the worker never re-enrolled and stayed poisoned for that
    // whole height. Measured on mainnet at 64,560: all three eu role bundles were bound to a
    // parent vps did not hold, so vps could not use any of them; before v1.9.159 that aborted
    // its block build outright (~250 retries, 20 minutes, zero blocks), and after v1.9.159 it
    // costs eu its 22/13/10 share for the block instead. Re-binding on a parent change is
    // what actually gets the worker PAID rather than merely ignored.
    if last_slot == Some((height, prev_hash)) {
        return Ok(None);
    }
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
        return Ok(Some((height, prev_hash)));
    }
    // The NODE validates this either way. Over Stratum the pool forwards the bytes opaquely
    // and returns the node's verdict, so a pool miner is enrolled on exactly the same terms as
    // a miner with its own node -- and the payout address is `solver_pkh` inside the bundle,
    // derived from this worker's own key, which the relay cannot alter without breaking the
    // ECVRF binding.
    let body = transport.submit_bundle(&bundle)?;
    println!(
        "[role-worker] ENROLLED role={role_name} height={height} pkh={} -> {}",
        hex::encode(payout_pkh),
        body.trim()
    );

    // Register this address ON CHAIN so the chain can draw it for a role.
    //
    // Enrolling a bundle and being eligible for the draw are different things: a worker can
    // enrol every block, be paid by the fan-out, and still be invisible to the draw. But the
    // eligible set consensus uses is CHAIN-DERIVED (`ChainState::consensus_eligible_pkhs`) --
    // it is deliberately NOT the node-local `/poawx/miner` announce map, because unioning that
    // in made two honest nodes derive different role holders (vps 5 vs eu 2, measured
    // 2026-08-01) and would fork the fleet the moment the four-role gate armed.
    //
    // PRG1 is the convergent path: signed, sybil-worked, gossiped over P2P, and applied in
    // connect_block from the same bytes on every node. `build_signed` grinds the registration
    // sybil work itself, bound to (network, anchor block, pkh, pubkey) -- so it cannot be
    // replayed onto another chain or another identity.
    //
    // The anchor is the PARENT block: the node recomputes the digest via `anchor_hash_at()`
    // and fails closed if it does not know that height, so anchoring to a block we just read
    // the hash of is what it can actually verify.
    //
    // Best-effort: registration failing must never stop enrollment. But it is never silent --
    // an unregistered miner is one the chain can never select, and that is invisible from the
    // outside (it looks exactly like losing the draw).
    match ProposerRegistrationV1::build_signed(
        secret,
        net,
        height.saturating_sub(1),
        &prev_hash,
        irium_node_rs::poawx_ticket::effective_sybil_bits(),
    ) {
        Ok(reg) => {
            // Hard check, not a debug_assert: release builds are what run, and registering an
            // identity other than the one we are paid at is silently useless -- from outside it
            // is indistinguishable from losing the draw. Both sides are
            // Ripemd160(Sha256(compressed pubkey)) over the same secret, so this should never
            // fire; if it ever does, the registration is worthless and must not be sent.
            if reg.pkh() != payout_pkh {
                eprintln!(
                    "[role-worker] REFUSING to register: identity {} != payout identity {}",
                    hex::encode(reg.pkh()),
                    hex::encode(payout_pkh)
                );
                return Ok(Some((height, prev_hash)));
            }
            match transport.submit_registration(reg.serialize()) {
                Ok(body) => println!(
                    "[role-worker] REGISTERED ON CHAIN pkh={} anchor={} -> {}",
                    hex::encode(payout_pkh),
                    height.saturating_sub(1),
                    body.trim()
                ),
                Err(e) => eprintln!("[role-worker] on-chain registration refused: {e}"),
            }
        }
        Err(e) => eprintln!("[role-worker] could not build registration: {e}"),
    }
    Ok(Some((height, prev_hash)))
}


/// How this worker reaches the chain.
///
/// A miner with its own node (or one whose pool/Core node opted into remote enrollment) talks
/// HTTP directly. A POOL-ONLY miner has no node at all: it holds a Stratum connection and
/// nothing else, so its three calls -- role-work parameters, "was I drawn and for what", and
/// the bundle submit -- are relayed by the pool over that same connection.
///
/// The bundle is submitted as opaque JSON either way, and the NODE validates it either way.
/// The pool is a relay, so choosing this transport does not put the pool between a miner and
/// its money: the payout address is `solver_pkh`, derived from the miner's own key inside the
/// bundle, and the pool cannot alter it without invalidating the ECVRF binding.
enum Transport {
    Http {
        client: reqwest::blocking::Client,
        base: String,
        token: String,
    },
    Stratum(StratumClient),
}

impl Transport {
    fn role_work(&mut self) -> Result<serde_json::Value, String> {
        match self {
            Transport::Http { client, base, token } => {
                let resp = client
                    .get(format!("{base}/poawx/role-work"))
                    .bearer_auth(token)
                    .send()
                    .map_err(|e| format!("role-work fetch: {e}"))?;
                let status = resp.status();
                if !status.is_success() {
                    let body = resp.text().unwrap_or_default();
                    return Err(format!("role-work fetch: HTTP {status}: {body}"));
                }
                resp.json().map_err(|e| format!("role-work decode: {e}"))
            }
            Transport::Stratum(c) => c.call("poawx.get_role_work", serde_json::json!([])),
        }
    }

    fn assignment(&mut self, payout_pkh: [u8; 20]) -> Result<serde_json::Value, String> {
        let pkh = hex::encode(payout_pkh);
        match self {
            Transport::Http { client, base, token } => {
                let url = format!("{}/poawx/assignment?pkh={}", base.trim_end_matches('/'), pkh);
                let mut req = client.get(&url);
                if !token.is_empty() {
                    req = req.bearer_auth(token.clone());
                }
                req.send()
                    .map_err(|e| format!("role assignment request failed: {e}"))?
                    .json()
                    .map_err(|e| format!("role assignment decode failed: {e}"))
            }
            Transport::Stratum(c) => {
                c.call("poawx.get_assignment", serde_json::json!([pkh]))
            }
        }
    }

    /// PRG1 on-chain registration. A pool-only miner needs this as much as anyone: enrolling
    /// a bundle and being ELIGIBLE FOR THE DRAW are different things, and the eligible set is
    /// chain-derived, so an unregistered miner is never drawn no matter how much it enrols.
    /// The wire is 169 raw bytes; over Stratum they travel hex-encoded and the pool decodes
    /// them straight back to bytes without interpreting them.
    fn submit_registration(&mut self, wire: Vec<u8>) -> Result<String, String> {
        match self {
            Transport::Http { client, base, token } => {
                let r = client
                    .post(format!("{base}/poawx/registration"))
                    .bearer_auth(token)
                    .body(wire)
                    .send()
                    .map_err(|e| format!("registration submit: {e}"))?;
                let status = r.status();
                let body = r.text().unwrap_or_default();
                if status.is_success() {
                    Ok(body)
                } else {
                    Err(format!("{status} {}", body.trim()))
                }
            }
            Transport::Stratum(c) => c
                .call("poawx.submit_registration", serde_json::json!([hex::encode(wire)]))
                .map(|v| v.to_string()),
        }
    }

    fn submit_bundle(&mut self, bundle: &serde_json::Value) -> Result<String, String> {
        match self {
            Transport::Http { client, base, token } => {
                let resp = client
                    .post(format!("{base}/poawx/role-bundle"))
                    .bearer_auth(token)
                    .json(bundle)
                    .send()
                    .map_err(|e| format!("role-bundle submit: {e}"))?;
                let status = resp.status();
                let body = resp.text().unwrap_or_default();
                if status.is_success() {
                    Ok(body)
                } else {
                    Err(format!("role-bundle submit: HTTP {status}: {body}"))
                }
            }
            Transport::Stratum(c) => c
                .call("poawx.submit_role_bundle", serde_json::json!([bundle.to_string()]))
                .map(|v| v.to_string()),
        }
    }
}

/// A minimal Stratum client: line-delimited JSON-RPC over TCP, which is all the pool channel
/// needs. It subscribes and authorizes exactly as a mining client does, because the pool
/// refuses PoAW-X methods on an unauthorized session -- an anonymous socket must not be able
/// to push work through the pool into its node.
struct StratumClient {
    reader: std::io::BufReader<std::net::TcpStream>,
    writer: std::net::TcpStream,
    next_id: u64,
}

impl StratumClient {
    fn connect(addr: &str, worker: &str) -> Result<Self, String> {
        let stream = std::net::TcpStream::connect(addr)
            .map_err(|e| format!("stratum connect {addr}: {e}"))?;
        // Bounded, so a silent pool cannot wedge the worker forever; the caller retries.
        let to = std::time::Duration::from_secs(30);
        stream.set_read_timeout(Some(to)).ok();
        stream.set_write_timeout(Some(to)).ok();
        let mut c = StratumClient {
            reader: std::io::BufReader::new(
                stream.try_clone().map_err(|e| format!("stratum clone: {e}"))?,
            ),
            writer: stream,
            next_id: 1,
        };
        c.call("mining.subscribe", serde_json::json!(["irium-role-worker"]))?;
        c.call("mining.authorize", serde_json::json!([worker, "x"]))?;
        Ok(c)
    }

    /// One request/response. Notifications the pool pushes unsolicited (`mining.notify`,
    /// `mining.set_difficulty`) arrive interleaved on this socket and are SKIPPED rather than
    /// mistaken for our answer -- matching on the request id is what makes that safe.
    fn call(&mut self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
        use std::io::{BufRead, Write};
        let id = self.next_id;
        self.next_id += 1;
        let req = serde_json::json!({"id": id, "method": method, "params": params});
        writeln!(self.writer, "{req}").map_err(|e| format!("stratum write {method}: {e}"))?;
        self.writer.flush().map_err(|e| format!("stratum flush: {e}"))?;
        for _ in 0..64 {
            let mut line = String::new();
            let n = self
                .reader
                .read_line(&mut line)
                .map_err(|e| format!("stratum read {method}: {e}"))?;
            if n == 0 {
                return Err(format!("stratum: pool closed the connection during {method}"));
            }
            let v: serde_json::Value = match serde_json::from_str(line.trim()) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if v.get("id").and_then(|x| x.as_u64()) != Some(id) {
                continue; // a push notification, not our reply
            }
            if let Some(err) = v.get("error") {
                if !err.is_null() {
                    return Err(format!("stratum {method} rejected: {err}"));
                }
            }
            return Ok(v.get("result").cloned().unwrap_or(serde_json::Value::Null));
        }
        Err(format!("stratum: no reply to {method} within 64 messages"))
    }
}

/// Register this identity on chain, independently of whether it was drawn.
///
/// THE BOOTSTRAP DEADLOCK this closes: registration used to live only at the end of the
/// enrollment path, and `auto` mode skips that path entirely when the chain did not draw this
/// miner. But the chain draws from the CHAIN-DERIVED eligible set, which a miner only enters
/// by registering -- so an unregistered worker was never drawn, therefore never registered,
/// therefore never drawn. Self-perpetuating, and from the outside indistinguishable from
/// simply losing the draw every time. It is the same shape as the n==1 proposer lockout.
///
/// Cheap enough to attempt every idle poll: one GET plus a ~2^20 sybil grind, and the node
/// rejects a duplicate registration harmlessly.
fn ensure_registered(
    transport: &mut Transport,
    net: u8,
    secret: &[u8; 32],
    payout_pkh: [u8; 20],
) -> Result<(), String> {
    let t = transport.role_work()?;
    let height = t["height"].as_u64().ok_or("role-work: no height")?;
    let prev_hash = h32(t["prev_hash"].as_str().ok_or("role-work: no prev_hash")?);
    let reg = ProposerRegistrationV1::build_signed(
        secret,
        net,
        height.saturating_sub(1),
        &prev_hash,
        irium_node_rs::poawx_ticket::effective_sybil_bits(),
    )
    .map_err(|e| format!("could not build registration: {e}"))?;
    if reg.pkh() != payout_pkh {
        return Err(format!(
            "REFUSING to register: identity {} != payout identity {}",
            hex::encode(reg.pkh()),
            hex::encode(payout_pkh)
        ));
    }
    match transport.submit_registration(reg.serialize()) {
        Ok(body) => println!(
            "[role-worker] REGISTERED ON CHAIN pkh={} anchor={} -> {}",
            hex::encode(payout_pkh),
            height.saturating_sub(1),
            body.trim()
        ),
        // Not fatal and never silent: a duplicate is expected once eligible, but a real
        // refusal means this miner can never be drawn and must be visible.
        Err(e) => eprintln!("[role-worker] on-chain registration refused: {e}"),
    }
    Ok(())
}

/// Ask the chain which role THIS identity holds for the next block.
///
/// `Ok(Some((role_id, name)))` => drawn, work that role. `Ok(None)` => NOT DRAWN, do nothing.
/// An error is propagated rather than swallowed: a miner that cannot learn its assignment must
/// not fall back to a self-chosen role, which is the behaviour this whole path removes.
///
/// The answer changes EVERY HEIGHT, because the draw does. It is deterministic, bound to this
/// identity, and unpredictable before the parent lands, so a role cannot be shopped for.
fn resolve_assigned_role(
    transport: &mut Transport,
    payout_pkh: [u8; 20],
) -> Result<Option<(u8, String)>, String> {
    let v = transport.assignment(payout_pkh)?;
    Ok(assigned_role_from_response(&v))
}

/// The pure half of [`resolve_assigned_role`]: read this identity's role out of the node's
/// answer. `None` means the `role` field is ABSENT, which the endpoint documents as NOT DRAWN
/// -- it must never be read as "pick something".
fn assigned_role_from_response(v: &serde_json::Value) -> Option<(u8, String)> {
    v.get("role")
        .and_then(|x| x.as_str())
        .map(|name| (role_id(name), name.to_string()))
}

fn main() -> Result<(), String> {
    // Default AUTO: with no argument the CHAIN assigns the role, which is the model --
    // selection first, work after. An explicit compute|verify|support still overrides, so
    // every existing harness and negative control is unaffected.
    let role_name = std::env::args().nth(1).unwrap_or_else(|| "auto".into());
    // `role_id` PANICS on an unknown name, so it must not be called on "auto". It was, and
    // that made auto mode dead on arrival: every worker aborted at startup with
    // `role must be compute|verify|support` before reaching the auto branch below. No unit
    // test caught it because none of them ran `main` -- it took an end-to-end devnet run.
    let role = parse_role_arg(&role_name)?;
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

    // POOL-ONLY MINERS: set IRIUM_POAWX_POOL_STRATUM=host:port and every call -- role-work,
    // assignment, registration, bundle submit -- is relayed by the pool over one Stratum
    // connection, so a miner with no node of its own participates on identical terms. Unset
    // (the default) keeps the direct HTTP path byte-for-byte as before.
    let mut transport = match std::env::var("IRIUM_POAWX_POOL_STRATUM").ok().filter(|v| !v.trim().is_empty()) {
        Some(addr) => {
            println!(
                "[role-worker] pool transport: stratum {} (payout {})",
                addr.trim(),
                hex::encode(payout_pkh)
            );
            Transport::Stratum(StratumClient::connect(addr.trim(), &hex::encode(payout_pkh))?)
        }
        None => Transport::Http {
            client: reqwest::blocking::Client::new(),
            base: base.clone(),
            token: token.clone(),
        },
    };

    // ASK THE CHAIN which role to work, per docs/POAWX.md: "The miner requests the current
    // role assignment from your node, performs the role work, and submits role receipts."
    //
    // The role used to come from argv[1] alone -- the miner chose, and the producer arbitrated
    // afterwards. `auto` (and no argument at all) now takes the node's answer for THIS
    // identity, which is deterministic, identity-bound and unpredictable before the parent
    // block, so a role cannot be shopped for. An explicit role argument still overrides, which
    // keeps every existing harness and negative-control test working unchanged.
    // ONE NODE, ONE MINING ADDRESS. `IRIUM_POAWX_ROLE_SECRET_HEX` is this node's single
    // mining identity and the chain draws at most one role for it per block. Running several
    // identities from one node -- as `poawx-role-workers-only.sh` did by deriving a distinct
    // key per role, sha256("IRIUM_POAWX_WORKER_v1|<role>|<secret>") -- put three addresses on
    // the chain for a single machine and let one operator occupy several role slots at once.
    // Run ONE worker in `auto` mode per node instead.
    // `auto` (the default for a miner that does not pass a role) asks the CHAIN which role it
    // holds. An explicit role argument still overrides, which keeps every harness and negative
    // control working unchanged.
    //
    // ONE NODE, ONE MINING ADDRESS. `IRIUM_POAWX_ROLE_SECRET_HEX` is this node's single mining
    // identity and the chain draws at most one role for it per block. Running several
    // identities from one node -- as `poawx-role-workers-only.sh` did, deriving a key per role
    // -- put three addresses on the chain for one machine and let one operator occupy several
    // role slots at once. Run ONE worker in `auto` mode per node instead.
    let auto = role_name == "auto";
    let (role, role_name) = if auto {
        match resolve_assigned_role(&mut transport, payout_pkh)? {
            Some((r, name)) => {
                println!(
                    "[role-worker] chain drew role={name} for pkh={}",
                    hex::encode(payout_pkh)
                );
                (r, name)
            }
            None => {
                println!(
                    "[role-worker] not drawn for this block (pkh={}); a miner may NOT pick its \
                     own role",
                    hex::encode(payout_pkh)
                );
                // One-shot: nothing to do. Loop mode re-asks every height below, so an
                // undrawn identity idles now and works the moment the chain draws it.
                if !std::env::var("IRIUM_POAWX_ROLE_WORKER_LOOP")
                    .map(|v| v.trim() == "1")
                    .unwrap_or(false)
                {
                    return Ok(());
                }
                (ROLE_COMPUTE_CONTRIBUTOR, "unassigned".to_string())
            }
        }
    } else {
        (role, role_name)
    };

    let loop_mode = std::env::var("IRIUM_POAWX_ROLE_WORKER_LOOP")
        .map(|v| v.trim() == "1")
        .unwrap_or(false);

    // One-shot: run once and propagate errors (nonzero exit) exactly as before.
    if !loop_mode {
        return enroll_once(
            &mut transport, role, &role_name, net, &secret, &sk, payout_pubkey, payout_pkh,
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
    let mut last_slot: Option<(u64, [u8; 32])> = None;
    let mut consecutive_errors: u32 = 0;
    // The role the chain drew LAST iteration. In `auto` mode it is re-asked every pass,
    // because the draw is per height: latching onto the role resolved at startup made a worker
    // keep performing it for the life of the process, including heights where the chain drew it
    // for a DIFFERENT role or did not draw it at all. Building compute work for a verify
    // assignment is the 65,117 stall exactly -- `Invalid("wrong mode")` on every attempt.
    let mut role = role;
    let mut role_name = role_name;
    loop {
        if auto {
            match resolve_assigned_role(&mut transport, payout_pkh) {
                Ok(Some((r, name))) => {
                    if r != role {
                        println!(
                            "[role-worker] chain drew role={name} (was {role_name}) for pkh={}",
                            hex::encode(payout_pkh)
                        );
                    }
                    role = r;
                    role_name = name;
                    consecutive_errors = 0;
                }
                Ok(None) => {
                    // NOT DRAWN this height. Do no ROLE WORK -- that is what makes "only the
                    // four selected do the work" true rather than aspirational. But DO keep
                    // the on-chain registration current, or an unregistered miner can never
                    // enter the eligible set the draw reads, and so can never be drawn: a
                    // self-perpetuating lockout that looks exactly like bad luck.
                    if let Err(e) = ensure_registered(&mut transport, net, &secret, payout_pkh) {
                        eprintln!("[role-worker] registration while idle: {e}");
                    }
                    consecutive_errors = 0;
                    std::thread::sleep(std::time::Duration::from_secs(poll_secs));
                    continue;
                }
                Err(e) => {
                    consecutive_errors = consecutive_errors.saturating_add(1);
                    let wait = backoff_secs(poll_secs, consecutive_errors, backoff_cap_secs);
                    eprintln!(
                        "[role-worker] assignment error #{consecutive_errors} (retry in {wait}s): {e}"
                    );
                    std::thread::sleep(std::time::Duration::from_secs(wait));
                    continue;
                }
            }
        }
        match enroll_once(
            &mut transport, role, &role_name, net, &secret, &sk, payout_pubkey, payout_pkh,
            last_slot,
        ) {
            Ok(Some(slot)) => {
                if let Some((h, p)) = last_slot {
                    if h == slot.0 && p != slot.1 {
                        println!(
                            "[role-worker] re-enrolled role={role_name} height={h}: parent changed                              {} -> {}; the previous bundle was bound to a parent no builder holds",
                            hex::encode(&p[..4]),
                            hex::encode(&slot.1[..4])
                        );
                    }
                }
                last_slot = Some(slot);
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
    use irium_node_rs::poawx::{
        ROLE_COMPUTE_CONTRIBUTOR, ROLE_SUPPORT_CONTRIBUTOR, ROLE_VERIFY_CONTRIBUTOR,
    };


    /// The node answers with `role` only when THIS identity was drawn. Absent means not drawn,
    /// and the worker must idle -- a self-chosen role is the behaviour the chain draw removes.
    #[test]
    fn an_absent_role_field_means_not_drawn_not_free_choice() {
        use super::assigned_role_from_response;
        let drawn = serde_json::json!({"role": "verify", "role_id": 2, "eligible_count": 30});
        assert_eq!(
            assigned_role_from_response(&drawn).map(|(r, n)| (r, n)),
            Some((ROLE_VERIFY_CONTRIBUTOR, "verify".to_string()))
        );
        // Drawn for some OTHER identity: holders are listed, but no `role` for us.
        let not_drawn = serde_json::json!({
            "eligible_count": 30,
            "role_holders": [{"role": "compute", "pkh": "aa".repeat(20)}]
        });
        assert!(
            assigned_role_from_response(&not_drawn).is_none(),
            "role_holders naming somebody else must NOT be read as our assignment"
        );
        assert!(assigned_role_from_response(&serde_json::json!({})).is_none());
        for (name, id) in [
            ("compute", ROLE_COMPUTE_CONTRIBUTOR),
            ("verify", ROLE_VERIFY_CONTRIBUTOR),
            ("support", ROLE_SUPPORT_CONTRIBUTOR),
        ] {
            let v = serde_json::json!({ "role": name });
            assert_eq!(assigned_role_from_response(&v).unwrap().0, id, "{name} maps to its id");
        }
    }



    /// `auto` MUST parse. It did not: `role_id` panics on any name outside
    /// compute|verify|support and was called on argv[1] BEFORE the auto branch, so every
    /// worker started with `auto` aborted instantly with `role must be
    /// compute|verify|support`. Auto mode -- the whole selection-first model on the miner
    /// side -- was dead on arrival.
    ///
    /// Nothing caught it, and the reason is worth keeping: the unit tests exercised the
    /// response parser and the source structure, but never `main`'s argument handling, so
    /// they all passed against a binary that could not start. It took an end-to-end devnet
    /// run to surface it, which is exactly why the boundary harness exists.
    #[test]
    fn auto_is_a_valid_role_argument_and_a_typo_is_not_a_panic() {
        use super::parse_role_arg;
        // The regression: this call is what aborted every auto worker.
        assert_eq!(parse_role_arg("auto").unwrap(), ROLE_COMPUTE_CONTRIBUTOR);
        assert_eq!(parse_role_arg("compute").unwrap(), ROLE_COMPUTE_CONTRIBUTOR);
        assert_eq!(parse_role_arg("verify").unwrap(), ROLE_VERIFY_CONTRIBUTOR);
        assert_eq!(parse_role_arg("support").unwrap(), ROLE_SUPPORT_CONTRIBUTOR);
        // A typo is a message, not a stack trace.
        let e = parse_role_arg("verfiy").unwrap_err();
        assert!(e.contains("verfiy") && e.contains("auto"), "unhelpful error: {e}");
    }

    /// A pool-only miner has NO node, so every call it must make has to be relayed. If any one
    /// of the four is missing the miner is stranded in a way that looks like bad luck rather
    /// than a broken client:
    ///   * role-work    -> nothing to build a bundle from;
    ///   * assignment   -> never learns it was drawn, so it never works its role;
    ///   * registration -> never enters the chain-derived eligible set, so it is never DRAWN
    ///                     at all, however much it enrols;
    ///   * bundle       -> does the work and cannot deliver it.
    /// The pool must answer all four, and the method names on both sides must agree exactly.
    #[test]
    fn the_pool_transport_covers_every_call_a_nodeless_miner_makes() {
        let worker = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/bin/poawx-role-worker.rs"
        ))
        .expect("read own source");
        let pool = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/pool/irium-stratum/src/stratum.rs"
        ))
        .expect("read pool source");

        for m in [
            "poawx.get_role_work",
            "poawx.get_assignment",
            "poawx.submit_registration",
            "poawx.submit_role_bundle",
        ] {
            // Match the QUOTED literal, not the bare substring: a first attempt at this
            // test asserted `contains(m)` and stayed green when the pool arm was renamed to
            // "poawx.submit_registration_DISABLED", which still contains the name. Quoting
            // pins the exact method string on both sides.
            let quoted = format!("\"{m}\"");
            assert!(
                worker.contains(&quoted),
                "the worker must call {m} over the Stratum transport"
            );
            assert!(
                pool.contains(&quoted),
                "the pool must answer {m}; a method the worker calls and the pool does not \
                 serve strands every pool miner"
            );
        }

        // And the pool must refuse all of them on an unauthorized session: an anonymous socket
        // must not be able to push work through the pool into its node.
        let guarded = pool.matches("unauthorized").count();
        assert!(
            guarded >= 3,
            "every PoAW-X relay arm must check authorization first (found {guarded})"
        );
    }

    /// THE BUG THIS FIXES: the role was resolved ONCE before the loop, so a worker in
    /// auto+loop mode kept performing its first assignment for the life of the process --
    /// including heights where the chain drew it for a DIFFERENT role, or not at all. Feeding
    /// compute work into a verify challenge fails `Invalid("wrong mode")` on every attempt,
    /// which is the 65,117 stall exactly.
    ///
    /// Source-level because the loop is an unbounded network poll that a unit test cannot
    /// drive. What it pins is the one structural property that was wrong: the assignment is
    /// re-asked INSIDE the loop, not only before it.
    #[test]
    fn the_assignment_is_re_asked_every_height_not_latched_at_startup() {
        let src = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/bin/poawx-role-worker.rs"
        ))
        .expect("read own source");
        let needle = concat!("resolve_assigned_", "role(");
        let loop_at = src.find("\n    loop {").expect("the poll loop exists");
        let calls_in_loop = src[loop_at..].matches(needle).count();
        assert!(
            calls_in_loop >= 1,
            "the role assignment must be re-resolved INSIDE the poll loop; the draw changes \
             every height, so resolving once at startup latches the worker to a stale role"
        );
        // And still resolved before the loop, so one-shot mode keeps working.
        assert!(
            src[..loop_at].matches(needle).count() >= 1,
            "one-shot mode still resolves the assignment before the loop"
        );
    }

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
