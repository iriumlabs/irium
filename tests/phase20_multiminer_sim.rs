//! Multi-miner adversarial simulation for the PoAW-X Phase-20 production payout
//! validator (`validate_phase20_production_payout`).
//!
//! Fully isolated: these are pure-function black-box tests over the crate's PUBLIC
//! API. They touch no node, no network, no chain state, no activation gate, and
//! never reference mainnet (network id 0). The goal is to build confidence, before
//! any governance/activation decision, that:
//!   (a) distinct miners are each attributed their OWN role reward under their OWN pkh,
//!   (b) the coinbase is the exact 55/22/13/10 split,
//!   (c) forged / duplicate / replayed / misattributed / redirected claims are rejected.
//!
//! Scope note: `validate_phase20_production_payout` validates role CLAIMS, binds each
//! role payout pkh to the claim's solver, and validates the split. The separate
//! "best-candidate among the admitted set" rule is enforced by a DIFFERENT validator
//! (committed-admission / CandidateSet best_for_role) that needs a chain-state harness;
//! it is out of scope for this pure-validator sim and called out in the report.

use irium_node_rs::chain::validate_phase20_production_payout;
use irium_node_rs::poawx::{
    assign_lane, multi_role_amounts, role_claim_digest, Phase20ReceiptExt, PoawxLane,
    PoawxRoleClaim, RoleReward, LANE_ASIC_STREAMING, LANE_CPU_FRIENDLY, LANE_GPU_PARALLEL,
    ROLE_COMPUTE_CONTRIBUTOR, ROLE_SUPPORT_CONTRIBUTOR, ROLE_VERIFY_CONTRIBUTOR,
};
use irium_node_rs::tx::TxOutput;

const NET: u8 = 3; // devnet/test network id -- deliberately NOT mainnet (0)
const HEIGHT: u64 = 12_345;
const TOTAL: u64 = 5_000_000_000; // clean multiple of 10_000 so the split is exact

// Distinct participant keys.
const KP: [u8; 20] = [0xA0; 20]; // primary / proposer
const KC: [u8; 20] = [0xC1; 20]; // compute solver
const KV: [u8; 20] = [0xC2; 20]; // verify solver
const KS: [u8; 20] = [0xC3; 20]; // support solver
const ATTACKER: [u8; 20] = [0xEE; 20];

fn prev() -> [u8; 32] {
    [0x11u8; 32]
}

fn p2pkh(pkh: &[u8; 20]) -> Vec<u8> {
    let mut s = vec![0x76, 0xa9, 0x14];
    s.extend_from_slice(pkh);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

fn out(pkh: &[u8; 20], value: u64) -> TxOutput {
    TxOutput {
        value,
        script_pubkey: p2pkh(pkh),
    }
}

/// A VALID role claim for `solver` at slot 0 (the slot the validator checks), bound
/// to (NET, height, prev). Honest miners produce exactly this.
fn valid_claim(role_id: u8, solver: [u8; 20], prev: &[u8; 32], height: u64) -> PoawxRoleClaim {
    let lane = assign_lane(NET, height, prev, role_id, 0);
    let nonce = [0x01u8; 32];
    let secret = [0x02u8; 32];
    let claim_digest =
        role_claim_digest(NET, height, prev, role_id, lane.id(), &solver, &nonce, &secret);
    PoawxRoleClaim {
        role_id,
        lane_id: lane.id(),
        solver_pkh: solver,
        nonce,
        secret,
        claim_digest,
        commitment_hash: None,
    }
}

fn make_ext(
    rr: RoleReward,
    cc: PoawxRoleClaim,
    vc: PoawxRoleClaim,
    sc: PoawxRoleClaim,
) -> Phase20ReceiptExt {
    Phase20ReceiptExt {
        role_reward: rr,
        compute_claim: cc,
        verify_claim: vc,
        support_claim: sc,
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
    }
}

/// Honest three-distinct-miner block: compute->KC, verify->KV, support->KS, primary->KP.
fn honest() -> (Phase20ReceiptExt, Vec<TxOutput>) {
    let p = prev();
    let cc = valid_claim(ROLE_COMPUTE_CONTRIBUTOR, KC, &p, HEIGHT);
    let vc = valid_claim(ROLE_VERIFY_CONTRIBUTOR, KV, &p, HEIGHT);
    let sc = valid_claim(ROLE_SUPPORT_CONTRIBUTOR, KS, &p, HEIGHT);
    let rr = RoleReward {
        compute_contributor_pkh: KC,
        verify_contributor_pkh: KV,
        support_contributor_pkh: KS,
    };
    let a = multi_role_amounts(TOTAL);
    let outs = vec![out(&KP, a[0]), out(&KC, a[1]), out(&KV, a[2]), out(&KS, a[3])];
    (make_ext(rr, cc, vc, sc), outs)
}

fn run(ext: &Phase20ReceiptExt, outs: &[TxOutput]) -> Result<(), String> {
    validate_phase20_production_payout(outs, &KP, TOTAL, HEIGHT, &prev(), NET, ext, false)
}

// ---------------------------------------------------------------------------
// (a) + (b) honest path: accept, attribute, exact split
// ---------------------------------------------------------------------------

#[test]
fn accepts_distinct_miners_each_paid_own_key_exact_split() {
    let (ext, outs) = honest();
    assert!(
        run(&ext, &outs).is_ok(),
        "valid distinct-miner block must validate: {:?}",
        run(&ext, &outs).err()
    );

    // Exact 55/22/13/10 and sum == total.
    let a = multi_role_amounts(TOTAL);
    assert_eq!(a[0], TOTAL * 5500 / 10000, "primary 55%");
    assert_eq!(a[1], TOTAL * 2200 / 10000, "compute 22%");
    assert_eq!(a[2], TOTAL * 1300 / 10000, "verify 13%");
    assert_eq!(a[3], TOTAL * 1000 / 10000, "support 10%");
    assert_eq!(a[0] + a[1] + a[2] + a[3], TOTAL, "split must be exact");

    // Each role output pays the distinct solver's own pkh (order: primary,c,v,s).
    assert_eq!(outs[1].script_pubkey, p2pkh(&KC));
    assert_eq!(outs[2].script_pubkey, p2pkh(&KV));
    assert_eq!(outs[3].script_pubkey, p2pkh(&KS));
}

#[test]
fn split_is_exact_even_for_non_round_total_remainder_to_primary() {
    // Non-round total: floors leave a remainder that must go to PRIMARY so the sum is exact.
    let total = 5_000_000_007u64;
    let a = multi_role_amounts(total);
    assert_eq!(a[0] + a[1] + a[2] + a[3], total, "remainder absorbed by primary");
    let (mut ext, _) = honest();
    // Rebuild honest outputs for this total and validate against it.
    let outs = vec![out(&KP, a[0]), out(&KC, a[1]), out(&KV, a[2]), out(&KS, a[3])];
    ext.fee_bps = 0;
    assert!(
        validate_phase20_production_payout(&outs, &KP, total, HEIGHT, &prev(), NET, &ext, false)
            .is_ok(),
        "honest block with non-round total must validate with remainder to primary"
    );
}

// ---------------------------------------------------------------------------
// (c) + (d) adversarial: misattribution, forgery, replay, redirection
// ---------------------------------------------------------------------------

#[test]
fn rejects_reward_to_key_that_did_not_produce_the_claim() {
    // THE core anti-theft check: role_reward pkh must equal the validated claim solver.
    let (mut ext, mut outs) = honest();
    ext.role_reward.compute_contributor_pkh = ATTACKER; // claim solver is still KC
    let a = multi_role_amounts(TOTAL);
    outs[1] = out(&ATTACKER, a[1]); // pay the attacker to keep outputs==role_reward
    let e = run(&ext, &outs).expect_err("must reject: paid pkh != claim solver");
    assert!(
        e.contains("does not match validated role claim"),
        "unexpected error: {e}"
    );
}

#[test]
fn rejects_forged_claim_tampered_digest() {
    let (mut ext, outs) = honest();
    ext.compute_claim.claim_digest = [0xFFu8; 32]; // forged
    let e = run(&ext, &outs).expect_err("must reject forged digest");
    assert!(e.contains("digest does not verify"), "unexpected error: {e}");
}

#[test]
fn rejects_claim_for_a_lane_not_assigned() {
    // Miner claims a role/lane it was not deterministically assigned. Digest is made
    // self-consistent (so the digest check passes) but the ASSIGNMENT check must fail.
    let (mut ext, outs) = honest();
    let p = prev();
    let assigned = assign_lane(NET, HEIGHT, &p, ROLE_COMPUTE_CONTRIBUTOR, 0).id();
    let wrong = [LANE_CPU_FRIENDLY, LANE_GPU_PARALLEL, LANE_ASIC_STREAMING]
        .into_iter()
        .find(|&l| l != assigned && PoawxLane::from_id(l).map_or(false, |x| x.is_fairness_lane()))
        .expect("a second fairness lane exists");
    let solver = ext.compute_claim.solver_pkh;
    let (nonce, secret) = (ext.compute_claim.nonce, ext.compute_claim.secret);
    ext.compute_claim.lane_id = wrong;
    ext.compute_claim.claim_digest = role_claim_digest(
        NET,
        HEIGHT,
        &p,
        ROLE_COMPUTE_CONTRIBUTOR,
        wrong,
        &solver,
        &nonce,
        &secret,
    );
    let e = run(&ext, &outs).expect_err("must reject wrong-lane claim");
    assert!(e.contains("assigned lane"), "unexpected error: {e}");
}

#[test]
fn rejects_duplicate_or_wrong_role_in_slot() {
    // Put a COMPUTE-role claim in the VERIFY slot (role substitution / duplicate role).
    let (mut ext, outs) = honest();
    ext.verify_claim = valid_claim(ROLE_COMPUTE_CONTRIBUTOR, KV, &prev(), HEIGHT);
    let e = run(&ext, &outs).expect_err("must reject wrong role_id in slot");
    assert!(
        e.contains("role_id") && e.contains("expected"),
        "unexpected error: {e}"
    );
}

#[test]
fn rejects_replayed_claim_bound_to_stale_height_and_prev() {
    // Claims validly produced for a DIFFERENT (height, prev) then replayed here.
    let stale_prev = [0x99u8; 32];
    let stale_height = HEIGHT - 100;
    let cc = valid_claim(ROLE_COMPUTE_CONTRIBUTOR, KC, &stale_prev, stale_height);
    let vc = valid_claim(ROLE_VERIFY_CONTRIBUTOR, KV, &stale_prev, stale_height);
    let sc = valid_claim(ROLE_SUPPORT_CONTRIBUTOR, KS, &stale_prev, stale_height);
    let rr = RoleReward {
        compute_contributor_pkh: KC,
        verify_contributor_pkh: KV,
        support_contributor_pkh: KS,
    };
    let ext = make_ext(rr, cc, vc, sc);
    let a = multi_role_amounts(TOTAL);
    let outs = vec![out(&KP, a[0]), out(&KC, a[1]), out(&KV, a[2]), out(&KS, a[3])];
    // Validate at the CURRENT (HEIGHT, prev) -- the stale binding must fail.
    let e = run(&ext, &outs).expect_err("must reject replayed/stale claim");
    assert!(
        e.contains("digest does not verify") || e.contains("assigned lane"),
        "unexpected error: {e}"
    );
}

#[test]
fn rejects_inflated_role_output_amount() {
    let (ext, mut outs) = honest();
    outs[1].value += 1; // steal 1 satoshi into the compute output
    assert!(run(&ext, &outs).is_err(), "payout must be the exact split");
}

#[test]
fn rejects_role_output_redirected_to_other_key() {
    // role_reward says KC, but the coinbase output pays the attacker.
    let (ext, mut outs) = honest();
    let a = multi_role_amounts(TOTAL);
    outs[1] = out(&ATTACKER, a[1]);
    let e = run(&ext, &outs).expect_err("must reject redirected role output");
    assert!(e.contains("pkh/order mismatch"), "unexpected error: {e}");
}

#[test]
fn rejects_hidden_fee_value_bearing_non_p2pkh_output() {
    // Sneak an extra OP_RETURN-style value-bearing output (hidden fee).
    let (ext, mut outs) = honest();
    outs.push(TxOutput {
        value: 1,
        script_pubkey: vec![0x6a, 0x01, 0x00], // OP_RETURN, not p2pkh
    });
    assert!(
        run(&ext, &outs).is_err(),
        "value-bearing non-p2pkh output must be rejected"
    );
}
