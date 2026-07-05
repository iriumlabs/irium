//! Stage 1 (devnet-scoped, isolated): prove the per-role best-candidate SELECTION
//! that the stratum's `pool_role_reward_from_admitted` delegates to
//! (`cs.best_for_role(role)?.solver_pkh`) yields GENUINELY DISTINCT solvers per role
//! across heights and multiple distinct miner keys, that the strictly-highest
//! effective-score candidate wins (basis for "non-best" rejection), and that a role
//! with NO admitted candidate returns `None` (fail-closed) -- so attribution can
//! never silently collapse onto one key.
//!
//! Node-crate integration test: no node process, no network, no mainnet (net id 3).
//! Prints the raw key->role->height mapping for plain review.

use irium_node_rs::poawx::{
    ROLE_COMPUTE_CONTRIBUTOR, ROLE_SUPPORT_CONTRIBUTOR, ROLE_VERIFY_CONTRIBUTOR,
};
use irium_node_rs::poawx_candidate::{AssignmentProofV2, CandidateSet, RoleCandidate};
use irium_node_rs::poawx_penalty::PenaltyStatus;

const NET: u8 = 3; // devnet/test network id -- never mainnet (0)

fn hx(p: &[u8; 20]) -> String {
    format!("{:02x}{:02x}", p[0], p[1])
}

fn candidate(
    height: u64,
    seed: [u8; 32],
    role: u8,
    solver: [u8; 20],
    secret: u8,
    dominance_weight: u64,
) -> RoleCandidate {
    let proof = AssignmentProofV2::prove(&[secret; 32], NET, height, role, solver, [role; 32], seed)
        .expect("assignment proof");
    RoleCandidate::from_assignment_v2(&proof, PenaltyStatus::Clean.id(), dominance_weight, [role; 32])
}

fn cset(height: u64, seed: [u8; 32], cands: Vec<RoleCandidate>) -> CandidateSet {
    CandidateSet {
        network_id: NET,
        target_height: height,
        seed,
        candidates: cands,
    }
}

#[test]
fn stage1_distinct_best_candidate_per_role_and_fail_closed() {
    let seed = [0x44u8; 32];
    // six distinct external-miner keys (pkh fill == secret fill for the test).
    let miners: [u8; 6] = [0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6];
    let key = |i: usize| -> [u8; 20] { [miners[i]; 20] };

    println!("=== Stage 1 raw evidence: distinct best-candidate solver per role (net={NET}) ===");

    // Rotate the six distinct miners through the three roles across heights; each
    // role has exactly one admitted candidate (a distinct key).
    let plan: [(u64, [usize; 3]); 5] = [
        (100, [0, 1, 2]),
        (101, [3, 4, 5]),
        (102, [1, 2, 0]),
        (103, [5, 3, 4]),
        (104, [2, 0, 5]),
    ];
    for (h, idx) in plan {
        let cs = cset(
            h,
            seed,
            vec![
                candidate(h, seed, ROLE_COMPUTE_CONTRIBUTOR, key(idx[0]), miners[idx[0]], 1000),
                candidate(h, seed, ROLE_VERIFY_CONTRIBUTOR, key(idx[1]), miners[idx[1]], 1000),
                candidate(h, seed, ROLE_SUPPORT_CONTRIBUTOR, key(idx[2]), miners[idx[2]], 1000),
            ],
        );
        let c = cs.best_for_role(ROLE_COMPUTE_CONTRIBUTOR).unwrap().solver_pkh;
        let v = cs.best_for_role(ROLE_VERIFY_CONTRIBUTOR).unwrap().solver_pkh;
        let s = cs.best_for_role(ROLE_SUPPORT_CONTRIBUTOR).unwrap().solver_pkh;
        println!("height {h}: compute->{} verify->{} support->{}", hx(&c), hx(&v), hx(&s));
        assert_eq!(c, key(idx[0]));
        assert_eq!(v, key(idx[1]));
        assert_eq!(s, key(idx[2]));
        assert!(c != v && v != s && c != s, "three genuinely distinct solvers");
    }

    // Best-among-competing: two distinct keys compete for COMPUTE with different
    // dominance weights; the strictly-higher effective score must win (the basis on
    // which the node rejects a "non-best" selected solver).
    let h = 200u64;
    let low = key(0);
    let high = key(1);
    let cs = cset(
        h,
        seed,
        vec![
            candidate(h, seed, ROLE_COMPUTE_CONTRIBUTOR, low, miners[0], 10),
            candidate(h, seed, ROLE_COMPUTE_CONTRIBUTOR, high, miners[1], 5000),
        ],
    );
    let best = cs.best_for_role(ROLE_COMPUTE_CONTRIBUTOR).unwrap().solver_pkh;
    println!(
        "best-among-competing @ {h}: winner={} (low={} high={})",
        hx(&best), hx(&low), hx(&high)
    );
    assert_eq!(best, high, "strictly-higher effective score must win");
    assert_ne!(best, low, "the weaker candidate must NOT be selected");

    // Fail-closed: a role with NO admitted candidate returns None -- the source of
    // the stratum helper returning None (fail closed) instead of collapsing to a key.
    let cs_missing = cset(
        h,
        seed,
        vec![
            candidate(h, seed, ROLE_COMPUTE_CONTRIBUTOR, key(0), miners[0], 1000),
            candidate(h, seed, ROLE_VERIFY_CONTRIBUTOR, key(1), miners[1], 1000),
            // SUPPORT deliberately absent
        ],
    );
    let support = cs_missing.best_for_role(ROLE_SUPPORT_CONTRIBUTOR);
    println!(
        "fail-closed: SUPPORT with no admitted candidate => {}",
        if support.is_none() { "None (correct -- no collapse)" } else { "SOME (WRONG)" }
    );
    assert!(support.is_none(), "a role with no candidate must return None, not collapse");
    // the present roles still resolve to their own distinct keys.
    assert_eq!(cs_missing.best_for_role(ROLE_COMPUTE_CONTRIBUTOR).unwrap().solver_pkh, key(0));
    assert_eq!(cs_missing.best_for_role(ROLE_VERIFY_CONTRIBUTOR).unwrap().solver_pkh, key(1));
}
