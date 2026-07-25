//! PoAW-X VRF-assigned proposer sortition (Phase 31). See `docs/poawx-proposer-vrf-design.md`.
//!
//! ⚠ MAINNET STATUS (reconciled 2026-07-25; authoritative check: `activation::mainnet_gate_truth`):
//! the per-fn "mainnet hard-off (`network_id == 0`)" wording below is STALE for any gate whose
//! `MAINNET_*_ACTIVATION_HEIGHT` is `Some` — those route through `activation::poawx_effective_activation`,
//! which on `network_id == 0` IGNORES the env and substitutes the COMPILED activation height, so the gate is
//! ACTIVE in production at/after it. Proposer-VRF + proposer REGISTRATION are LIVE on mainnet ≥50,000, and N1
//! non-exclusive eligibility ≥59,900. A gate is genuinely hard-off ONLY when its const is `None`. Do not read
//! per-fn "mainnet hard-off" comments as literal.
//!
//! The chain decides who may propose each height via a VRF lottery on the
//! committee-controlled epoch seed: hashrate gives zero advantage. A backup
//! cascade keyed to the block time keeps the chain live if the primary is offline:
//!   round 0 = top 1 (lowest VRF score), round 1 = top 4 (+3), round 2 = top 14
//!   (+10), round 3+ = all eligible.
//!
//! This module is the PURE math + gate layer (no chain state). The eligibility
//! registry, validator gate, fork-choice rank, and wiring live in `chain.rs` /
//! `bin/iriumd.rs` / `bin/irium-miner.rs`.

use crate::activation::network_id_byte;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, OnceLock};

/// The PRIMARY proposer role id for the proposer VRF (distinct from the
/// compute/verify/support sub-roles 1/2/3). The block's `worker_pkh` IS the
/// proposer, so the proposer proof is bound to `ROLE_PROPOSER`.
pub const ROLE_PROPOSER: u8 = 0;

/// Default freeze depth (blocks): eligibility for height `H` uses the registry
/// state at `H - FREEZE_DEPTH`, so the seed `S_H` (revealed at H-1) cannot be used
/// to register a favorable key after the fact. Env-tunable; clamped `>= 2`.
pub const DEFAULT_PROPOSER_FREEZE_DEPTH: u64 = 16;

/// Default round interval (seconds) = target block time. Mainnet 120; devnet 30.
pub const DEFAULT_PROPOSER_ROUND_INTERVAL_SECS: u64 = 120;

/// Cumulative admitted proposer-slot count by `round`: round 0 = top 1,
/// round 1 = top 4 (next 3), round 2 = top 14 (next 10), round 3+ = all. Capped at
/// `eligible_count` (>= 1). Realizes the ordered cascade via thresholds.
pub fn cumulative_slots(round: u32, eligible_count: u64) -> u64 {
    let cum: u64 = match round {
        0 => 1,
        1 => 4,
        2 => 14,
        _ => u64::MAX, // round 3+ => all eligible
    };
    cum.min(eligible_count.max(1))
}

/// Proposer-lottery priority from a VRF output: lower = higher priority (closer to
/// slot 1). Reuses the V2 score (first 8 bytes of the VRF output, LE).
pub fn proposer_priority(vrf_output: &[u8; 32]) -> u64 {
    crate::poawx_candidate::assignment_v2_score_from_output(vrf_output)
}

/// Selection threshold at `round` for `eligible_count` registered keys. A miner is
/// admitted iff `proposer_priority < tau`. `tau = (U64_MAX / n) * slots` (saturating);
/// at round 3+ (`slots == n`) `tau == U64_MAX` so ALL eligible are admitted =>
/// liveness. With an empty registry (`n == 0`) treated as `n == 1` => permissive
/// bootstrap (everyone admitted) until keys register.
pub fn proposer_threshold(eligible_count: u64, round: u32) -> u64 {
    let n = eligible_count.max(1);
    let slots = cumulative_slots(round, n);
    if slots >= n {
        return u64::MAX;
    }
    (u64::MAX / n).saturating_mul(slots)
}

/// Whether `priority` is admitted (selected) at `round` for `eligible_count` keys.
pub fn is_selected(priority: u64, eligible_count: u64, round: u32) -> bool {
    priority < proposer_threshold(eligible_count, round)
}

// ── A1/A2 fix: VRF sortition threshold bounding pool/committee size ────────────
//
// Closes the A1 (pool-stuffing) + A2 (finality-liveness DoS via registration
// inflation) root cause — cheap UNBOUNDED admission — by capping the admitted
// VERIFY/SUPPORT pool members per role to ~K via the SAME VRF-lottery pattern that
// bounds the proposer set. A candidate's priority is its ECVRF output score (fixed
// per key/seed, NOT grindable): grinding tickets cannot change it. So the admitted
// set is bounded to those keys whose VRF genuinely clears the threshold — an
// attacker's share is its share of the frozen registered set, not the number of
// tickets it is willing to burn. Mainnet-hard-off at the gate (`pool_sortition_enforced`).

/// Default target committee/pool size K per role.
pub const DEFAULT_POOL_SORTITION_K_SUPPORT: u64 = 16;
pub const DEFAULT_POOL_SORTITION_K_VERIFY: u64 = 8;

/// Sortition threshold admitting ~`k` of `eligible_count` keys: a candidate whose VRF
/// priority `< tau` is admitted. `tau = (u64::MAX / n) * k` (saturating). `k >= n` =>
/// `u64::MAX` (all admitted; liveness bootstrap when few keys are registered). Mirrors
/// `proposer_threshold` with `k` in place of the round cascade's `slots`.
pub fn pool_sortition_threshold(eligible_count: u64, k: u64) -> u64 {
    let n = eligible_count.max(1);
    if k >= n {
        return u64::MAX;
    }
    (u64::MAX / n).saturating_mul(k)
}

/// Whether a candidate with VRF `priority` is sortition-admitted to a ~`k`-size pool
/// out of `eligible_count` registered keys.
pub fn pool_sortition_admitted(priority: u64, eligible_count: u64, k: u64) -> bool {
    priority < pool_sortition_threshold(eligible_count, k)
}

/// Target pool/committee size K for a contributor role (env-overridable on devnet;
/// fixed default per role). SUPPORT is the finality committee; VERIFY the "other
/// workers" pool. `>= 1`.
pub fn pool_sortition_k(role: u8) -> u64 {
    let (var, default) = if role == crate::poawx::ROLE_SUPPORT_CONTRIBUTOR {
        ("IRIUM_POAWX_POOL_SORTITION_K_SUPPORT", DEFAULT_POOL_SORTITION_K_SUPPORT)
    } else {
        ("IRIUM_POAWX_POOL_SORTITION_K_VERIFY", DEFAULT_POOL_SORTITION_K_VERIFY)
    };
    std::env::var(var)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(default)
        .max(1)
}

/// Earliest header timestamp allowed for a `round`-r block: `parent_time + r*interval`.
/// The validator rejects a round-r block whose timestamp is earlier (anti round-grind).
pub fn min_time_for_round(parent_time: u32, round: u32, round_interval_secs: u64) -> u32 {
    let add = (round as u64).saturating_mul(round_interval_secs);
    parent_time.saturating_add(add.min(u32::MAX as u64) as u32)
}

/// Highest round a miner may attempt given `elapsed_secs` since the parent block.
/// Round 0 is open immediately; round r opens after `r * interval` seconds.
pub fn max_round_for_elapsed(elapsed_secs: u64, round_interval_secs: u64) -> u32 {
    let iv = round_interval_secs.max(1);
    (elapsed_secs / iv).min(u32::MAX as u64) as u32
}

// ── env-configurable params (devnet/testnet) ─────────────────────────────────

pub fn proposer_freeze_depth() -> u64 {
    std::env::var("IRIUM_POAWX_PROPOSER_FREEZE_DEPTH")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_PROPOSER_FREEZE_DEPTH)
        .max(2)
}

pub fn proposer_round_interval_secs() -> u64 {
    std::env::var("IRIUM_POAWX_PROPOSER_ROUND_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_PROPOSER_ROUND_INTERVAL_SECS)
        .max(1)
}

/// Default anti-spam PoW floor (leading-zero bits) when the proposer VRF gate is
/// enforced. PoW is then only a trivial spam deterrent, not a selection signal.
pub const DEFAULT_PROPOSER_ANTI_SPAM_BITS: u32 = 8;

pub fn proposer_anti_spam_bits() -> u32 {
    if network_id_byte() == 0 {
        return 20; // mainnet anti-spam PoW floor (bits)
    }
    std::env::var("IRIUM_POAWX_PROPOSER_ANTISPAM_BITS")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(DEFAULT_PROPOSER_ANTI_SPAM_BITS)
}

/// Activation height for PoAW-X block-header PoW demotion (env-gated). Reading the
/// env alone does NOT enable demotion; see `pow_demotion_gate`.
pub fn pow_demotion_activation_height() -> Option<u64> {
    std::env::var("IRIUM_POAWX_POW_DEMOTION_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// Compiled mainnet activation height for PoAW-X PoW demotion, analogous to
/// `MAINNET_CONTRIBUTOR_ROLE_BINDING_HEIGHT`. `None` = hard-off on mainnet: no
/// environment value can enable demotion on net 0. Set to `Some(H)` (a height
/// past the then-current tip) ONLY for a coordinated demotion-activation release,
/// after the change is devnet-proven under mainnet-parity gates.
///
/// REVERTED TO `None` 2026-07-18 (safety). v1.9.129 set this to `Some(58_242)`,
/// which made demotion genuinely LIVE on mainnet. Demotion is not usable on a real
/// network: only 1 of 5 PoW validation paths is demotion-aware (`connect_block`).
/// Both P2P paths (`add_header`, `process_block`) and both restart paths
/// (`parse_persisted_block_file`, `rebuild_startup_header_index`) validate against
/// the DECLARED target, so a demoted block cannot propagate to peers and does not
/// survive a restart. With the gate live, a floor-PoW (20-bit) block from a holder
/// of an eligible proposer key would be accepted locally and orphaned by the
/// network — a self-inflicted chain split.
///
/// No harm occurred: every block in 58242..=58778 was verified to satisfy the FULL
/// target (537/537, tightest margin +0 bits), so reverting invalidates nothing and
/// is strictly more conservative than the shipped behaviour.
///
/// Do NOT set this back to `Some(H)` until the propagation-layer work (Track 1C)
/// lands and is proven on a MULTI-NODE devnet. See
/// `docs/poawx-pow-demotion-mainnet-status.md`.
pub const MAINNET_POW_DEMOTION_ACTIVATION_HEIGHT: Option<u64> =
    crate::activation::MAINNET_COMBINED_ACTIVATION_HEIGHT; // combined deploy knob (None => off)

/// Pure mainnet-const evaluation for PoW demotion (param-driven for race-free
/// tests): active iff the compiled mainnet height is set and reached.
pub fn mainnet_pow_demotion_active(mainnet_activation: Option<u64>, height: u64) -> bool {
    matches!(mainnet_activation, Some(h) if height >= h)
}

/// Master gate for PoW demotion, which changes block-header validity (a
/// consensus rule). On mainnet (`network_id == 0`) the ENV is IGNORED: demotion is
/// controlled solely by the compiled `MAINNET_POW_DEMOTION_ACTIVATION_HEIGHT` const
/// (`None` => hard-off), so no environment value can enable it. This deliberately
/// does NOT route through `poawx_effective_activation` (which returns
/// `MAINNET_POAWX_ACTIVATION_HEIGHT` for net 0). On non-mainnet networks demotion is
/// OFF unless `IRIUM_POAWX_POW_DEMOTION_ACTIVATION_HEIGHT` is explicitly set, and
/// then only at or after that height. Param-driven for race-free tests.
pub fn pow_demotion_gate(network_id: u8, activation: Option<u64>, height: u64) -> bool {
    if network_id == 0 {
        // mainnet: env can NEVER enable demotion; only the compiled const can.
        return mainnet_pow_demotion_active(MAINNET_POW_DEMOTION_ACTIVATION_HEIGHT, height);
    }
    matches!(activation, Some(h) if height >= h)
}

/// Whether PoW demotion is active at `height`. Mainnet hard-off; default off on all
/// networks until the activation-height env is explicitly set.
pub fn pow_demotion_active(height: u64) -> bool {
    pow_demotion_gate(network_id_byte(), pow_demotion_activation_height(), height)
}

// ── V1 fix: rank-fork-choice length/height floor (gated) ──────────────────────
//
// Closes the "one better-ranked block rewinds up to 1000 blocks" gap: rank fork
// choice (`proposer_rank_chain_better`) decides at the first differing height with no
// length floor, so a single better-ranked block at a sub-tip height could reorg every
// block down to its fork point. Once this gate is active a candidate branch SHORTER
// than the current chain can never win a rank reorg; equal-height sibling forks and
// legitimate longer chains are unaffected. This TIGHTENS validity (rejects reorgs
// previously accepted), so it must arrive inert and switch on only at a coordinated,
// reviewed activation height -- never merely by deploying a binary.
/// Compiled mainnet activation height for the rank-fork-choice length floor.
/// `None` => ships INERT: byte-identical to pre-fix on every network until this const
/// is deliberately set in a later, reviewed release. Modeled EXACTLY on
/// `pow_demotion_gate`: on mainnet (net 0) the ENV is IGNORED; only this const enables it.
pub const MAINNET_RANK_LENGTH_FLOOR_ACTIVATION_HEIGHT: Option<u64> =
    crate::activation::MAINNET_COMBINED_ACTIVATION_HEIGHT; // combined deploy knob (None => off)

pub fn rank_length_floor_activation_height() -> Option<u64> {
    std::env::var("IRIUM_POAWX_RANK_LENGTH_FLOOR_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// Pure gate (param-driven for race-free tests). Mainnet: env ignored, only the
/// compiled const enables it. Non-mainnet: env-driven, off unless explicitly set.
pub fn rank_length_floor_gate(network_id: u8, activation: Option<u64>, height: u64) -> bool {
    if network_id == 0 {
        return matches!(MAINNET_RANK_LENGTH_FLOOR_ACTIVATION_HEIGHT, Some(h) if height >= h);
    }
    matches!(activation, Some(h) if height >= h)
}

/// Whether the rank-fork-choice length floor is active at `height`. Ships inert on
/// every network until deliberately activated.
pub fn rank_length_floor_active(height: u64) -> bool {
    rank_length_floor_gate(network_id_byte(), rank_length_floor_activation_height(), height)
}

/// B (bounded rank-rewind window): the reorg depth (number of our own blocks a reorg
/// would disconnect) at or below which the rank-length floor is RELAXED, so a
/// better-ranked shorter chain can win — this converges shallow simultaneous-failover
/// races. BEYOND this depth the absolute V1 floor holds, preserving deep-rewind /
/// long-range-attack protection. Env-driven on the harness; a reviewed mainnet const
/// would replace the default at productionization (paired with the same activation as
/// the length floor).
pub const DEFAULT_RANK_REWIND_WINDOW: u64 = 20;
pub fn rank_rewind_window() -> u64 {
    // K is a CONSENSUS parameter: two nodes with different K compute different fork-choice
    // verdicts and permanently fork. On mainnet (net-0) it MUST be identical fleet-wide, so
    // ignore the env override and use the compiled const (mirrors rank_length_floor_gate /
    // pow_demotion_gate, which also ignore env on net-0). Env stays live off-mainnet for tests.
    if crate::activation::network_id_byte() == 0 {
        return DEFAULT_RANK_REWIND_WINDOW;
    }
    std::env::var("IRIUM_POAWX_RANK_REWIND_WINDOW")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_RANK_REWIND_WINDOW)
}

/// CONVERGENCE FIX (symmetric deep-fork rule) — the content-only fork-choice TOTAL ORDER.
/// Returns true iff `candidate` is preferred over `current`. Each branch is its proposer-rank
/// sequence ABOVE the common ancestor (index 0 = the first block after the ancestor). Because
/// the decision is a pure function of chain CONTENT (never of "which branch this node holds"),
/// it is antisymmetric — `prefers(A,B) == !prefers(B,A)` for A≠B — so every node computes the
/// same winner ⇒ convergent, and it is a genuine total order (TALL branches `len > K` ordered by
/// length rank ABOVE SHORT branches `len ≤ K` ordered by rank-lex ⇒ transitive, arrival-order-
/// independent). This REPLACES the asymmetric `rank_length_floor_blocks` early-return, whose
/// gating on the evaluating node's own `current_len` made it NOT a total order (the beyond-K
/// permanent-fork bug: the short-branch node kept its own chain on rank instead of adopting the
/// longer one). Semantics preserved: beyond K the LONGER chain wins (rank cannot force a deep
/// rewind — the original floor's intent, now made symmetric); within K, rank-lexicographic at the
/// first differing height; final tie = lower tip hash (hardening on) / longer branch (legacy).
/// `floor_active == false` (gate off / pre-activation) ⇒ no deep rule ⇒ byte-identical legacy.
pub fn fork_choice_prefers_candidate(
    floor_active: bool,
    rewind_window: u64,
    candidate_ranks: &[(u32, u64)],
    current_ranks: &[(u32, u64)],
    candidate_tip: &[u8; 32],
    current_tip: &[u8; 32],
    hardening_active: bool,
) -> bool {
    let (cl, ml) = (candidate_ranks.len(), current_ranks.len());
    // Beyond K (node-independent: max of the two lengths), LENGTH decides — symmetric.
    if floor_active && (cl.max(ml) as u64) > rewind_window && cl != ml {
        return cl > ml;
    }
    // Within K (or equal-length deep): rank-lexicographic at the first differing height.
    let shared = cl.min(ml);
    for i in 0..shared {
        if candidate_ranks[i] != current_ranks[i] {
            return candidate_ranks[i] < current_ranks[i];
        }
    }
    // Tie over the shared prefix: deterministic lowest-tip-hash (hardening) removes length as a
    // lever; legacy path keeps longest-branch (byte-identical when hardening is off).
    if hardening_active {
        candidate_tip < current_tip
    } else if cl != ml {
        cl > ml
    } else {
        // Equal length + identical rank prefix with hardening OFF: the legacy longest-branch
        // rule (cl > ml) is false in BOTH directions => not a total order (a latent permanent
        // fork for equal-length identical-rank siblings). Unreachable on mainnet (wherever the
        // floor is active hardening is too), but reachable in an off-mainnet floor-on/
        // hardening-off config, so fall through to the deterministic tip-hash to keep this a
        // total order there. Byte-identical to legacy for the (overwhelmingly common) unequal-
        // length case above.
        candidate_tip < current_tip
    }
}

/// B (pure, unit-testable core of the bounded rank-rewind window): does the rank-length
/// floor BLOCK adopting a candidate branch? It blocks ONLY a strictly-SHORTER candidate
/// whose adoption would disconnect MORE than `rewind_window` (K) of our own blocks
/// (`current_len`). Longer/equal candidates and within-K shorter candidates are never
/// blocked here — they fall through to the rank comparison, so a better-ranked shorter
/// chain within K WINS (this is what converges a simultaneous-failover deadlock).
/// `floor_active == false` => never blocks (legacy byte-identical). `rewind_window == 0`
/// reproduces the absolute V1 floor (blocks any shorter candidate = pre-fix deadlock).
pub fn rank_length_floor_blocks(
    floor_active: bool,
    candidate_len: usize,
    current_len: usize,
    rewind_window: u64,
) -> bool {
    floor_active && candidate_len < current_len && current_len as u64 > rewind_window
}

#[cfg(test)]
mod rank_rewind_tests {
    use super::rank_length_floor_blocks as blk;
    #[test]
    fn bounded_rank_rewind_window() {
        // shorter candidate, floor ACTIVE, WITHIN K => NOT blocked: rank alone decides,
        // so a better-ranked shorter chain can be adopted. THIS converges the deadlock.
        assert!(!blk(true, 3, 5, 10), "within-K shorter must fall through to rank");
        assert!(!blk(true, 3, 10, 10), "current_len == K is inside the window");
        // shorter candidate, floor ACTIVE, BEYOND K => BLOCKED: V1 deep-rewind protection.
        assert!(blk(true, 3, 11, 10), "beyond-K shorter stays blocked (V1 preserved)");
        assert!(blk(true, 1, 500, 10), "deep shorter reorg stays blocked (V1)");
        // longer / equal candidate => never blocked (independent of K / depth).
        assert!(!blk(true, 8, 5, 2), "longer candidate never blocked");
        assert!(!blk(true, 5, 5, 2), "equal-length candidate never blocked");
        // floor INACTIVE => never blocks (legacy byte-identical behavior).
        assert!(!blk(false, 1, 999, 0), "inactive floor never blocks");
        // K == 0 reproduces the PRE-FIX absolute floor: any shorter candidate blocked =
        // the exact deadlock B removes within the window.
        assert!(blk(true, 3, 5, 0), "K=0 == pre-fix: shorter always blocked (deadlock)");
    }

    use super::fork_choice_prefers_candidate as prefers;

    #[test]
    fn fork_choice_converges_the_beyond_k_permanent_fork() {
        // Reproduces the CONFIRMED 61,690-class break, then proves the fix converges it.
        // Branch A: 25 blocks above the ancestor. Branch B: 22 blocks, BETTER-ranked at the
        // first differing height. Fork depth (25) > K=20.
        let k = 20u64;
        let (a_tip, b_tip) = ([0xAAu8; 32], [0xBBu8; 32]);
        let mut a = vec![(1u32, 500u64)]; // A[0]: worse (higher) rank
        let mut b = vec![(0u32, 100u64)]; // B[0]: better (lower) rank
        for i in 1..25 { a.push((0, 1_000 + i as u64)); }
        for i in 1..22 { b.push((0, 2_000 + i as u64)); }
        assert_eq!((a.len(), b.len()), (25, 22));

        // THE BUG (old asymmetric floor): the long node blocks the short reorg, the short
        // node keeps its own on rank => BOTH keep their own => permanent fork.
        let long_node_blocks_b = blk(true, b.len(), a.len(), k); // node on A vs cand B
        let short_node_blocks_a = blk(true, a.len(), b.len(), k); // node on B vs cand A
        assert!(long_node_blocks_b && !short_node_blocks_a,
            "old floor is asymmetric (blocks only on the long node) => the permanent fork");

        // THE FIX: content-only total order converges BOTH nodes onto A (longer, beyond K).
        let a_node_prefers_b = prefers(true, k, &b, &a, &b_tip, &a_tip, true); // node on A, cand B
        let b_node_prefers_a = prefers(true, k, &a, &b, &a_tip, &b_tip, true); // node on B, cand A
        assert!(!a_node_prefers_b, "node on A keeps A");
        assert!(b_node_prefers_a, "node on B ADOPTS A (short node adopts the longer beyond K)");
        // => both nodes end on A. Converged.
    }

    #[test]
    fn fork_choice_prefers_candidate_is_antisymmetric_total_order() {
        // For any two DISTINCT chains, prefers(X,Y) == !prefers(Y,X) (a total order => no
        // permanent two-way fork). Covers within-K, at-K, beyond-K, equal-length, and tie.
        let k = 4u64;
        let (tx, ty) = ([1u8; 32], [2u8; 32]); // X always carries tx, Y always ty
        let mk = |len: usize, base: u64| -> Vec<(u32, u64)> {
            (0..len).map(|i| (0u32, base + i as u64)).collect()
        };
        let cases = [
            (mk(6, 10), mk(3, 20)), // beyond K, different length => length
            (mk(6, 10), mk(6, 20)), // beyond K, equal length => rank
            (mk(3, 10), mk(2, 20)), // within K, different length
            (mk(2, 10), mk(2, 10)), // identical ranks => tie => tip hash
            (mk(5, 10), mk(4, 10)), // K boundary (5 > K=4)
            (mk(4, 10), mk(4, 20)), // exactly K, equal length => rank
            (mk(21, 1), mk(1, 9)),  // deep vs tiny
        ];
        for (x, y) in &cases {
            let xy = prefers(true, k, x, y, &tx, &ty, true);
            let yx = prefers(true, k, y, x, &ty, &tx, true);
            assert_ne!(xy, yx,
                "antisymmetry: exactly one of prefers(X,Y)/prefers(Y,X) for distinct chains (lens {} vs {})",
                x.len(), y.len());
        }
        // gate OFF => legacy: no deep rule, so a beyond-K shorter better-ranked chain wins on
        // rank (byte-identical to pre-activation behavior).
        let short_better = mk(1, 1);
        let long_worse = mk(30, 100);
        assert!(prefers(false, k, &short_better, &long_worse, &tx, &ty, true),
            "gate off: rank alone decides (legacy) => shorter better-ranked preferred");
        // Fix #4: the LEGACY tiebreak (hardening OFF) must ALSO be a total order for the
        // equal-length identical-rank sibling case (old `cl > ml` was false both ways => fork).
        let (ida, idb) = (mk(2, 10), mk(2, 10)); // identical ranks, equal length, distinct tips
        assert_ne!(
            prefers(true, k, &ida, &idb, &tx, &ty, false),
            prefers(true, k, &idb, &ida, &ty, &tx, false),
            "legacy (hardening-off) tiebreak must be a total order for equal-length identical-rank siblings"
        );
    }
}

// ── non-exclusive proposer eligibility (N1) ──────────────────────────────────
//
// Fixes the n==1 exclusionary lockout: with exactly one eligible key,
// `proposer_threshold(1, r)` saturates to `u64::MAX` (sortition admits everyone)
// while `check_block_proposer`'s `n > 0` guard switches the eligibility test ON --
// so the single eligible key is the ONLY key that may produce a block, and every
// other miner's block is rejected outright. It is self-perpetuating: a newcomer's
// key becomes eligible only by appearing in a block it produced, which it cannot
// produce while ineligible.
//
// Under this gate, eligibility / sortition / round-timing stop being BLOCK-VALIDITY
// rules and become PROPOSER-PRIVILEGE rules: failing them yields "no proposer status"
// (`Ok(false)`) instead of `Err`, so the block stands or falls on its own PoW alone,
// exactly as a block carrying no assignment already does. Structural/integrity
// failures (bad VRF proof, wrong seed/role, non-canonical ticket digest, solver-pkh
// mismatch, proposer != worker, delegation-v2 mismatch) are UNCHANGED and still `Err`.
//
// This is a RELAXATION of block validity: blocks that were rejected become accepted.
// The fork risk therefore runs new->old (an upgraded node accepts a block a
// non-upgraded node rejects), so it must not switch on merely by deploying a binary.
/// Compiled mainnet activation height for non-exclusive proposer eligibility.
/// `None` => the fix ships INERT: behaviour is byte-identical to pre-N1 on every
/// network until this const is deliberately set in a later, reviewed release.
pub const MAINNET_PROPOSER_NONEXCLUSIVE_ACTIVATION_HEIGHT: Option<u64> = Some(59_900);

pub fn proposer_nonexclusive_activation_height() -> Option<u64> {
    std::env::var("IRIUM_POAWX_PROPOSER_NONEXCLUSIVE_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// Pure mainnet-const evaluation (param-driven for race-free tests).
pub fn mainnet_proposer_nonexclusive_active(
    mainnet_activation: Option<u64>,
    height: u64,
) -> bool {
    matches!(mainnet_activation, Some(h) if height >= h)
}

/// Master gate. Modelled EXACTLY on `pow_demotion_gate`: on mainnet
/// (`network_id == 0`) the ENV is IGNORED and only the compiled const can enable
/// this. It deliberately does NOT route through `poawx_effective_activation`, which
/// substitutes `MAINNET_POAWX_ACTIVATION_HEIGHT` (`Some(50_000)`) for net 0 and would
/// therefore activate the change instantly on deploy, mainnet already being past that
/// height. That substitution is exactly how the PoAW-X gate set came to be live on
/// mainnet without a deliberate activation step; this gate must not repeat it.
pub fn proposer_nonexclusive_gate(network_id: u8, activation: Option<u64>, height: u64) -> bool {
    if network_id == 0 {
        return mainnet_proposer_nonexclusive_active(
            MAINNET_PROPOSER_NONEXCLUSIVE_ACTIVATION_HEIGHT,
            height,
        );
    }
    matches!(activation, Some(h) if height >= h)
}

/// Whether eligibility/sortition/round-timing are non-exclusionary at `height`.
pub fn proposer_nonexclusive_active(height: u64) -> bool {
    proposer_nonexclusive_gate(
        network_id_byte(),
        proposer_nonexclusive_activation_height(),
        height,
    )
}

/// Track 1C / C4: whether chain selection must be BLOCK-FIRST at `height`.
///
/// This is deliberately the SAME conjunction that makes demotion possible in
/// `ChainState::proposer_demotion_applies` (minus the per-block assignment check,
/// which selection cannot evaluate). Gating selection on `pow_demotion_active`
/// alone would be a latent liveness bug: in the demotion-on / VRF-off
/// configuration the SELECTOR would be rank-based while the ADOPTER
/// (`process_block`'s do_reorg branch, which switches on `proposer_vrf_enforced`)
/// stayed work-based. After C6 a demoted chain can never win on work, so the node
/// would chase a chain it then refuses to adopt -- a silent sync livelock, not a
/// crash. Selector and adopter must never be governed by different rules.
pub fn block_first_selection_active(height: u64) -> bool {
    pow_demotion_active(height) && proposer_vrf_enforced(height)
}

/// Track 1C / C1: the PoW target a HEADER must satisfy to be ADMITTED to the
/// header index.
///
/// Header-only paths never see a body, so the proposer assignment that
/// `ChainState::proposer_demotion_applies` requires is structurally unavailable
/// here. That is why this gate is COARSE (height-only) where
/// `validate_block_header` is PRECISE (body-aware), and the two must not be
/// made to match: when demotion is possible at `height` we admit against the
/// constant anti-spam floor and defer the real, assignment-checked verdict to
/// `connect_block`.
///
/// A *constant* is the only demotion-compatible target a header-only path can
/// evaluate — it needs no registry, no parent, no chain state. That is precisely
/// why every header-derivable-rank design was rejected and why this one works.
///
/// Admission is deliberately permissive: it bounds nothing on its own. What
/// bounds the resulting exposure is block-first selection (C4) and the peer
/// request policy (C7). Do not read this function as a security boundary.
///
/// Gate off — which includes all of mainnet, where
/// `MAINNET_POW_DEMOTION_ACTIVATION_HEIGHT` is `None` — returns `declared`
/// unchanged, so every caller stays byte-identical to its legacy behaviour.
pub fn header_admission_target(declared: crate::pow::Target, height: u64) -> crate::pow::Target {
    if pow_demotion_active(height) {
        crate::pow::floor_target(proposer_anti_spam_bits())
    } else {
        declared
    }
}

/// Pure cap: when `enforced`, the effective puzzle difficulty is capped at the
/// anti-spam `floor` (never raised), so hashrate cannot be cranked up to matter;
/// otherwise the configured value passes through verbatim.
pub fn cap_difficulty_if_enforced(configured: u32, enforced: bool, floor: u32) -> u32 {
    if enforced {
        configured.min(floor)
    } else {
        configured
    }
}

/// Effective puzzle difficulty at `height`: capped at the anti-spam floor when the
/// proposer VRF gate is enforced (mainnet hard-off => configured value verbatim).
pub fn effective_puzzle_difficulty_bits(configured: u32, height: u64) -> u32 {
    cap_difficulty_if_enforced(
        configured,
        proposer_vrf_enforced(height),
        proposer_anti_spam_bits(),
    )
}

// ── activation gate (mainnet hard-off) ───────────────────────────────────────

pub fn proposer_vrf_activation_height() -> Option<u64> {
    std::env::var("IRIUM_POAWX_PROPOSER_VRF_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

pub fn proposer_vrf_required() -> bool {
    if crate::activation::network_id_byte() == 0 {
        return true; // mainnet: enforced once the gate is active (height-gated)
    }
    std::env::var("IRIUM_POAWX_PROPOSER_VRF_REQUIRED")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}

/// Pure gate (param-driven for race-free tests). `network_id == 0` (mainnet) hard-off.
pub fn proposer_vrf_gate(network_id: u8, activation: Option<u64>, height: u64) -> bool {
    matches!(crate::activation::poawx_effective_activation(network_id, activation), Some(h) if height >= h)
}

pub fn proposer_vrf_active(height: u64) -> bool {
    proposer_vrf_gate(
        network_id_byte(),
        proposer_vrf_activation_height(),
        height,
    )
}

pub fn proposer_vrf_enforced(height: u64) -> bool {
    proposer_vrf_active(height) && proposer_vrf_required()
}

// ââ proposer registration / onboarding (gated) ââââââââââââââââââ
/// Max registrations force-drained (activated) from the FIFO queue head per block.
pub const PROPOSER_REG_CAP: usize = 8;
/// Max new registrations a producer may announce (enqueue) per block.
pub const PROPOSER_ANNOUNCE_CAP: usize = 8;
/// A registration's sybil anchor must be within the last this-many blocks of the
/// including height (bounds offline precomputation of the sybil work).
pub const PROPOSER_REG_ANCHOR_WINDOW: u64 = 64;

/// Whether a registration `anchor_height` is acceptable for inclusion in a block at
/// `height`: strictly in the past and within `window` of it. Used IDENTICALLY by the
/// block builder (to filter announce candidates) and the validator (connect_block) so
/// they never diverge -- a stale anchor must never be offered AND is always rejected.
pub fn registration_anchor_valid(anchor_height: u64, height: u64, window: u64) -> bool {
    anchor_height < height && !(height > window && anchor_height < height - window)
}

pub fn proposer_registration_activation_height() -> Option<u64> {
    std::env::var("IRIUM_POAWX_PROPOSER_REGISTRATION_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// Pure gate (param-driven for race-free tests). Registration is active only where the
/// proposer VRF is active (so `network_id == 0` mainnet is hard-off) AND at/after the
/// registration activation height.
pub fn proposer_registration_gate(vrf_active: bool, activation: Option<u64>, height: u64) -> bool {
    vrf_active && matches!(activation, Some(h) if height >= h)
}

pub fn proposer_registration_active(height: u64) -> bool {
    proposer_registration_gate(
        proposer_vrf_active(height),
        crate::activation::poawx_effective_activation(
            crate::activation::network_id_byte(),
            proposer_registration_activation_height(),
        ),
        height,
    )
}

/// Emergency liveness-recovery stall threshold (seconds). If the parent block is
/// older than this, the chain is treated as genuinely stalled and (when the recovery
/// gate is active) the frozen-window proposer check is relaxed to any prior on-chain
/// registration. Hard floor 14400 (2x MAX_FUTURE_BLOCK_TIME) so a miner cannot forge
/// the stall gap via a future timestamp.
pub const DEFAULT_PROPOSER_STALL_RECOVERY_SECS: u64 = 21_600; // 6h
pub fn proposer_stall_recovery_secs() -> u64 {
    std::env::var("IRIUM_POAWX_PROPOSER_STALL_RECOVERY_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_PROPOSER_STALL_RECOVERY_SECS)
        .max(14_400)
}

pub fn proposer_expiry_window() -> u64 {
    std::env::var("IRIUM_POAWX_PROPOSER_EXPIRY_WINDOW")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(2016)
        .max(1)
}

/// Reorg-safe registry of eligible proposer VRF keys. A key is eligible for height
/// `H` only via on-chain registrations FROZEN at `H - FREEZE_DEPTH`, so the seed
/// `S_H` (revealed at H-1) cannot be used to register a winning key after the fact.
/// Registrations apply on `connect_block` and revert on `disconnect_tip_block`
/// (exact inverse), so the frozen view is deterministic on any fork. Mainnet-off:
/// only populated when `proposer_vrf_active(height)`.
#[derive(Debug, Clone, Default)]
pub struct ProposerEligibilityRegistry {
    keys: BTreeMap<[u8; 33], ProposerKeyRecord>,
}

#[derive(Debug, Clone, Default)]
struct ProposerKeyRecord {
    pkh: [u8; 20],
    heights: BTreeSet<u64>,
}

impl ProposerEligibilityRegistry {
    pub fn from_env() -> Self {
        Self::default()
    }

    /// Record that `vrf_pubkey` (owned by `pkh`) appeared on-chain at `height`.
    pub fn register(&mut self, vrf_pubkey: [u8; 33], pkh: [u8; 20], height: u64) {
        let rec = self.keys.entry(vrf_pubkey).or_default();
        rec.pkh = pkh;
        rec.heights.insert(height);
    }

    /// Exact inverse of `register` for the same `(vrf_pubkey, height)`.
    pub fn unregister(&mut self, vrf_pubkey: &[u8; 33], height: u64) {
        if let Some(rec) = self.keys.get_mut(vrf_pubkey) {
            rec.heights.remove(&height);
            if rec.heights.is_empty() {
                self.keys.remove(vrf_pubkey);
            }
        }
    }

    /// Inclusive frozen registration window `[lo, hi]` for target `H` with the given
    /// freeze depth `fd` and expiry window `ew`. `None` if there is not yet `fd`
    /// history (bootstrap => no eligibility => the sortition threshold is permissive).
    fn frozen_window_with(fd: u64, ew: u64, target_height: u64) -> Option<(u64, u64)> {
        if target_height < fd {
            return None;
        }
        let hi = target_height - fd;
        let lo = hi.saturating_sub(ew.saturating_sub(1));
        Some((lo, hi))
    }

    fn record_in_window(rec: &ProposerKeyRecord, lo: u64, hi: u64) -> bool {
        rec.heights.range(lo..=hi).next().is_some()
    }

    pub fn eligible_count_with(&self, target_height: u64, fd: u64, ew: u64) -> u64 {
        match Self::frozen_window_with(fd, ew, target_height) {
            None => 0,
            Some((lo, hi)) => self
                .keys
                .values()
                .filter(|r| Self::record_in_window(r, lo, hi))
                .count() as u64,
        }
    }

    pub fn is_eligible_with(
        &self,
        vrf_pubkey: &[u8; 33],
        target_height: u64,
        fd: u64,
        ew: u64,
    ) -> bool {
        match Self::frozen_window_with(fd, ew, target_height) {
            None => false,
            Some((lo, hi)) => self
                .keys
                .get(vrf_pubkey)
                .map_or(false, |r| Self::record_in_window(r, lo, hi)),
        }
    }

    /// Eligible count at `H` using env-configured freeze depth + expiry window.
    pub fn eligible_count(&self, target_height: u64) -> u64 {
        self.eligible_count_with(target_height, proposer_freeze_depth(), proposer_expiry_window())
    }

    pub fn is_eligible(&self, vrf_pubkey: &[u8; 33], target_height: u64) -> bool {
        self.is_eligible_with(
            vrf_pubkey,
            target_height,
            proposer_freeze_depth(),
            proposer_expiry_window(),
        )
    }

    /// Whether this VRF key has ANY on-chain registration (regardless of freeze).
    /// Fix #9: all proposer pkhs eligible at `target_height` (the frozen-registered set).
    /// Diagnostic so an operator can see whether their miner's key is actually registered.
    /// Deterministic (BTreeMap order).
    pub fn eligible_pkhs(&self, target_height: u64) -> Vec<[u8; 20]> {
        self.eligible_pkhs_with(target_height, proposer_freeze_depth(), proposer_expiry_window())
    }
    pub fn eligible_pkhs_with(&self, target_height: u64, fd: u64, ew: u64) -> Vec<[u8; 20]> {
        match Self::frozen_window_with(fd, ew, target_height) {
            None => Vec::new(),
            Some((lo, hi)) => self
                .keys
                .values()
                .filter(|r| Self::record_in_window(r, lo, hi))
                .map(|r| r.pkh)
                .collect(),
        }
    }

    pub fn is_registered(&self, vrf_pubkey: &[u8; 33]) -> bool {
        self.keys.contains_key(vrf_pubkey)
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Max pending gossiped registrations a node will hold.
// ââ fork-choice hardening (Fix 1-4): bounded reorgs, honest finality, no-length tiebreak ââ
// One activation gate covers the whole bundle (depth cap + tip-hash tiebreak + genuine
// finality + header-sync floor). network_id == 0 (mainnet) hard-off; off until the
// activation height is set, so existing chains are byte-identical until coordinated activation.
pub const DEFAULT_MAX_REORG_DEPTH_MAINNET: u64 = 1000;
pub const DEFAULT_MAX_REORG_DEPTH_DEVNET: u64 = 100;
/// Hard floor: a configured cap can never drop below this (keeps normal shallow reorgs
/// working; an operator cannot cripple reorg recovery by setting it too low).
pub const MAX_REORG_DEPTH_HARD_FLOOR: u64 = 10;
pub const DEFAULT_MIN_FINALITY_COMMITTEE_MAINNET: u64 = 16;
pub const DEFAULT_MIN_FINALITY_COMMITTEE_DEVNET: u64 = 4;

pub fn fork_choice_hardening_activation_height() -> Option<u64> {
    std::env::var("IRIUM_POAWX_FORKCHOICE_HARDENING_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// Pure gate (param-driven for race-free tests). Mainnet (`network_id == 0`) hard-off.
pub fn fork_choice_hardening_gate(network_id: u8, activation: Option<u64>, height: u64) -> bool {
    matches!(crate::activation::poawx_effective_activation(network_id, activation), Some(h) if height >= h)
}

pub fn fork_choice_hardening_active(height: u64) -> bool {
    fork_choice_hardening_gate(
        network_id_byte(),
        fork_choice_hardening_activation_height(),
        height,
    )
}

// ââ audit hardening (pre-mainnet audit fixes): deterministic receipts root, finality
// parent/equivocation checks, VRF binding defense-in-depth, sig coverage, lane validation,
// strict leaf decoding, ticket epoch binding, role distinctness (>=3 candidates). One
// activation gate; network_id == 0 (mainnet) hard-off; off => byte-identical to pre-audit.
pub fn audit_hardening_activation_height() -> Option<u64> {
    std::env::var("IRIUM_POAWX_AUDIT_HARDENING_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

pub fn audit_hardening_gate(network_id: u8, activation: Option<u64>, height: u64) -> bool {
    matches!(crate::activation::poawx_effective_activation(network_id, activation), Some(h) if height >= h)
}

pub fn audit_hardening_active(height: u64) -> bool {
    audit_hardening_gate(
        network_id_byte(),
        audit_hardening_activation_height(),
        height,
    )
}

/// Option A (multi-participant role attribution): mainnet activation height for the
/// contributor-role solver binding. `None` => NOT live-active on mainnet -- the actual
/// future, announced, coordinated activation is a SEPARATE deferred decision (mirrors the
/// block-50000 discipline). Rig/devnet activate it low via the env var below for testing.
pub const MAINNET_CONTRIBUTOR_ROLE_BINDING_HEIGHT: Option<u64> = Some(57_920);

pub fn contributor_role_binding_activation_height() -> Option<u64> {
    std::env::var("IRIUM_POAWX_CONTRIBUTOR_ROLE_BINDING_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// Pure gate (param-driven for race-free tests). Mainnet (network 0) resolves to the
/// hard-coded future height (`None` today => off), so the mainnet-facing code is NOT
/// live-active; non-mainnet uses the env activation for rig/devnet testing.
pub fn contributor_role_binding_gate(
    network_id: u8,
    env_activation: Option<u64>,
    height: u64,
) -> bool {
    let eff = if network_id == 0 {
        MAINNET_CONTRIBUTOR_ROLE_BINDING_HEIGHT
    } else {
        env_activation
    };
    matches!(eff, Some(h) if height >= h)
}

/// Whether contributor-role solvers (COMPUTE/VERIFY/SUPPORT) must bind to their VRF key
/// (Option A) at `height`. Mainnet hard-off until a separate announced activation.
pub fn contributor_role_binding_active(height: u64) -> bool {
    contributor_role_binding_gate(
        network_id_byte(),
        contributor_role_binding_activation_height(),
        height,
    )
}

/// Max blocks a single reorg may disconnect (Fix 1). Finality-independent backstop:
/// the effective reorg floor is `max(finalized_height, tip - max_reorg_depth())`.
/// Network default + env override, floored at `MAX_REORG_DEPTH_HARD_FLOOR`.
pub fn max_reorg_depth() -> u64 {
    // Consensus parameter (bounds every reorg in `reorg_to_tip`): on mainnet (net-0) it MUST
    // be identical fleet-wide — two nodes with different caps accept/reject different reorgs
    // => permanent fork — so ignore the env override and use the compiled const (mirrors
    // rank_rewind_window / pow_demotion_gate, which also ignore env on net-0).
    if network_id_byte() == 0 {
        return DEFAULT_MAX_REORG_DEPTH_MAINNET.max(MAX_REORG_DEPTH_HARD_FLOOR);
    }
    std::env::var("IRIUM_POAWX_MAX_REORG_DEPTH")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_MAX_REORG_DEPTH_DEVNET)
        .max(MAX_REORG_DEPTH_HARD_FLOOR)
}

/// Minimum distinct registered committee keys required before genuine finality can
/// advance `finalized_height` (Fix 2). Below this, finality does not advance and the
/// depth cap is the protection.
pub fn min_finality_committee() -> u64 {
    // Consensus parameter (gates finalized_height advancement): const-forced on mainnet
    // (net-0), env-honored off-mainnet — same fleet-consistency rationale as max_reorg_depth.
    if network_id_byte() == 0 {
        return DEFAULT_MIN_FINALITY_COMMITTEE_MAINNET.max(1);
    }
    std::env::var("IRIUM_POAWX_MIN_FINALITY_COMMITTEE")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_MIN_FINALITY_COMMITTEE_DEVNET)
        .max(1)
}

pub const PROPOSER_REG_POOL_MAX: usize = 1024;

/// Whether proposer-registration gossip is enabled. LIVE on mainnet too: the
/// `MAINNET_POAWX_ACTIVATION_HEIGHT.is_some()` clause makes this return true on
/// `network_id == 0`, so independent producers CAN self-register via `/poawx/registration`.
pub fn proposer_registration_gossip_enabled() -> bool {
    crate::activation::network_id_byte() != 0
        || crate::activation::MAINNET_POAWX_ACTIVATION_HEIGHT.is_some()
}

/// Node-local pool of gossiped proposer registrations awaiting on-chain announcement.
/// Gossip ingest is LIGHT (claimed sybil bits + self-signature + dedup); the full
/// anchor-bound validation runs at block inclusion (connect_block). LIVE on mainnet
/// (registration gossip + on-chain announcement are active ≥50,000).
/// A0: minimum anchor-height advance before a refresh of an already-pooled key is
/// treated as new and rebroadcast. Below this the record is still updated (the pool
/// keeps the freshest anchor) but the outcome is `Duplicate`, so it does not
/// re-amplify. Without this a squatter re-anchors its keys every block and each
/// refresh fans out to every peer at zero cost.
pub const PROPOSER_REG_REFRESH_MIN_ANCHOR_DELTA: u64 = 8;

/// A pooled registration plus its ARRIVAL SEQUENCE.
///
/// A0: announce candidates were previously taken in `BTreeMap` key order, i.e.
/// lexicographically by VRF public key, so the 8 per-block announce slots always went
/// to the numerically smallest keys. Grinding a vanity key beginning `0x02 0x00 0x00...`
/// is cheap and entirely independent of the sybil PoW, so one party could permanently
/// occupy the head of every node's candidate list and starve every honest registrant at
/// any submission rate. `seq` makes selection first-come-first-served instead.
#[derive(Debug, Clone)]
struct PooledRegistration {
    /// Arrival order. PRESERVED across refreshes on purpose: if a refresh re-stamped
    /// this, a squatter could hold the head of the queue indefinitely by re-anchoring,
    /// which is the same capture A0 exists to remove.
    seq: u64,
    reg: crate::poawx::ProposerRegistrationV1,
}

#[derive(Default)]
pub struct NodeProposerRegistrationPool {
    pending: Mutex<BTreeMap<[u8; 33], PooledRegistration>>,
    next_seq: std::sync::atomic::AtomicU64,
}

impl NodeProposerRegistrationPool {
    pub fn ingest_bytes(
        &self,
        bytes: &[u8],
        resolve_anchor: impl Fn(u64) -> Option<[u8; 32]>,
    ) -> crate::poawx_gossip::GossipOutcome {
        use crate::poawx_gossip::GossipOutcome;
        if !proposer_registration_gossip_enabled() {
            return GossipOutcome::Rejected("registration gossip disabled".to_string());
        }
        if bytes.len() != crate::poawx::PROPOSER_REGISTRATION_V1_WIRE {
            return GossipOutcome::Rejected("registration: bad length".to_string());
        }
        let reg = match crate::poawx::ProposerRegistrationV1::deserialize(bytes) {
            Ok(r) => r,
            Err(e) => return GossipOutcome::Rejected(e),
        };
        let net = crate::activation::network_id_byte();
        // A4: independently RECOMPUTE the sybil digest from the anchor block instead of
        // trusting the peer-supplied `sybil_digest` field. The old check called
        // `meets_sybil_target(&reg.sybil_digest, ...)` directly, so a peer could set
        // `sybil_digest` to any value that trivially clears the target (e.g. all zeros),
        // self-sign it, and pay ZERO proof-of-work -- a ~2^bits (~10^6 at 20 bits)
        // cost asymmetry versus an honest registrant, who must grind the nonce until
        // `compute_sybil_digest()` clears the target. `validate()` recomputes the digest
        // from (anchor_hash, pkh, key, nonce), rejects if it does not equal the field,
        // checks it meets the target, AND verifies the self-signature.
        //
        // Recomputation needs the anchor block. If we cannot resolve it (we are behind
        // that height, or the peer pinned a future/unknown anchor), FAIL CLOSED -- a peer
        // must not be able to skip verification by choosing an anchor we do not hold.
        let anchor_hash = match resolve_anchor(reg.anchor_height) {
            Some(h) => h,
            None => {
                return GossipOutcome::Rejected(
                    "registration: anchor unavailable; cannot verify sybil work".to_string(),
                )
            }
        };
        if let Err(e) =
            reg.validate(net, &anchor_hash, crate::poawx_ticket::effective_sybil_bits())
        {
            return GossipOutcome::Rejected(e);
        }
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        match pending.get(&reg.vrf_pubkey) {
            // already have an equal-or-fresher anchor for this key: ignore.
            Some(existing) if reg.anchor_height <= existing.reg.anchor_height => {
                return GossipOutcome::Duplicate;
            }
            // A fresher anchor for a known key. Keep the freshest record so the pool
            // never offers a stale anchor, but only treat it as NEW (and therefore
            // rebroadcast) when the anchor advanced meaningfully -- see A2 above.
            // `seq` is deliberately carried over so a refresh cannot jump the queue.
            Some(existing) => {
                let seq = existing.seq;
                let advanced = reg
                    .anchor_height
                    .saturating_sub(existing.reg.anchor_height)
                    >= PROPOSER_REG_REFRESH_MIN_ANCHOR_DELTA;
                pending.insert(reg.vrf_pubkey, PooledRegistration { seq, reg });
                return if advanced {
                    GossipOutcome::AcceptedNew
                } else {
                    GossipOutcome::Duplicate
                };
            }
            None => {}
        }
        if pending.len() >= PROPOSER_REG_POOL_MAX {
            return GossipOutcome::Rejected("registration: pool full".to_string());
        }
        let seq = self
            .next_seq
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        pending.insert(reg.vrf_pubkey, PooledRegistration { seq, reg });
        GossipOutcome::AcceptedNew
    }

    /// Local submit (RPC path): store + return the wire bytes to gossip.
    pub fn submit(
        &self,
        reg: crate::poawx::ProposerRegistrationV1,
        resolve_anchor: impl Fn(u64) -> Option<[u8; 32]>,
    ) -> Vec<u8> {
        // Fix #14: re-validate before inserting into the local pool so the RPC path cannot inject
        // an unsigned / insufficient-sybil-work registration that the block builder would then
        // offer as an announce candidate (self-built invalid block). Mirrors ingest_bytes; an
        // invalid submission returns empty bytes (nothing is pooled or rebroadcast).
        // A4: the sybil digest is RECOMPUTED against the anchor (see ingest_bytes), not
        // trusted from the field; an unverifiable or under-worked registration pools nothing.
        let net = crate::activation::network_id_byte();
        let anchor_hash = match resolve_anchor(reg.anchor_height) {
            Some(h) => h,
            None => return Vec::new(),
        };
        if reg
            .validate(net, &anchor_hash, crate::poawx_ticket::effective_sybil_bits())
            .is_err()
        {
            return Vec::new();
        }
        let bytes = reg.serialize();
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let seq = match pending.get(&reg.vrf_pubkey) {
            Some(existing) => existing.seq, // never let a resubmit jump the queue
            None => self
                .next_seq
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        };
        pending.insert(reg.vrf_pubkey, PooledRegistration { seq, reg });
        bytes
    }

    /// Up to `max` pending registrations whose key is NOT in `exclude` (already queued or
    /// on-chain), as announce candidates for the next block.
    pub fn announce_candidates(
        &self,
        max: usize,
        exclude: &BTreeSet<[u8; 33]>,
    ) -> Vec<crate::poawx::ProposerRegistrationV1> {
        let pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        // A0: FIRST-COME-FIRST-SERVED by arrival sequence. Iterating the BTreeMap
        // directly would return lexicographic public-key order, which is grindable.
        let mut c: Vec<&PooledRegistration> = pending
            .values()
            .filter(|p| !exclude.contains(&p.reg.vrf_pubkey))
            .collect();
        c.sort_by_key(|p| p.seq);
        c.into_iter().take(max).map(|p| p.reg.clone()).collect()
    }

    pub fn forget(&self, keys: &[[u8; 33]]) {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        for k in keys {
            pending.remove(k);
        }
    }

    pub fn contains(&self, key: &[u8; 33]) -> bool {
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(key)
    }

    pub fn len(&self) -> usize {
        self.pending.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

static GLOBAL_PROPOSER_REG_POOL: OnceLock<NodeProposerRegistrationPool> = OnceLock::new();

pub fn global_proposer_reg_pool() -> &'static NodeProposerRegistrationPool {
    GLOBAL_PROPOSER_REG_POOL.get_or_init(NodeProposerRegistrationPool::default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_sortition_bounds_admitted_to_k() {
        // Evenly-spaced priorities: EXACTLY k of n clear the threshold, so the admitted
        // pool/committee is bounded to ~k regardless of how many keys/tickets exist.
        let n = 24u64;
        let step = u64::MAX / n;
        for k in [1u64, 8, 16, 20, 24, 30] {
            let admitted = (0..n)
                .filter(|i| pool_sortition_admitted(i * step, n, k))
                .count() as u64;
            if k >= n {
                assert_eq!(admitted, n, "k>=n admits all (liveness bootstrap)");
                assert_eq!(pool_sortition_threshold(n, k), u64::MAX);
            } else {
                assert_eq!(admitted, k, "exactly k of n admitted (k={k})");
            }
        }
        // A key's priority is its FIXED VRF output — grinding tickets can't change it, so a
        // key above tau is NEVER admitted (can't buy its way into the pool).
        let (n, k) = (20u64, 16u64);
        let tau = pool_sortition_threshold(n, k);
        assert!(!pool_sortition_admitted(tau, n, k), "priority == tau rejected");
        assert!(
            pool_sortition_admitted(tau.saturating_sub(1), n, k),
            "just below tau admitted"
        );
        // Inflating n (registration inflation) LOWERS the threshold, so the admitted set
        // stays ~k — it does NOT grow the committee. This is the A2 property.
        let tau_inflated = pool_sortition_threshold(n * 5, k);
        assert!(tau_inflated < tau, "more registered keys => lower per-key admission prob");
        let admitted_inflated = (0..(n * 5))
            .filter(|i| pool_sortition_admitted(i * (u64::MAX / (n * 5)), n * 5, k))
            .count() as u64;
        assert_eq!(admitted_inflated, k, "committee still ~k after 5x registration inflation");
        // n==0 treated as 1 (no divide-by-zero).
        assert_eq!(pool_sortition_threshold(0, 1), u64::MAX);
    }

    #[test]
    fn contributor_role_binding_gate_mainnet_activates_at_height() {
        // Activation binary (v1.9.127): mainnet (network 0) activates the contributor-role
        // binding at the fixed code height MAINNET_CONTRIBUTOR_ROLE_BINDING_HEIGHT, ignoring
        // env. Below it, off; at/above it, on (coordinated hard fork).
        let h = MAINNET_CONTRIBUTOR_ROLE_BINDING_HEIGHT.expect("activation height is set");
        assert!(!contributor_role_binding_gate(0, Some(1), h - 1));
        assert!(contributor_role_binding_gate(0, Some(1), h));
        assert!(contributor_role_binding_gate(0, None, h + 1));
        assert!(!contributor_role_binding_gate(0, None, 100));
        // devnet/rig (network 2): the env activation height gates it (low for testing).
        assert!(!contributor_role_binding_gate(2, None, 100));
        assert!(!contributor_role_binding_gate(2, Some(50), 49));
        assert!(contributor_role_binding_gate(2, Some(50), 50));
        assert!(contributor_role_binding_gate(2, Some(50), 100));
    }

    #[test]
    fn cumulative_slots_cascade() {
        // counts: round0=1, round1=4, round2=14, round3+=all, capped at n.
        assert_eq!(cumulative_slots(0, 100), 1);
        assert_eq!(cumulative_slots(1, 100), 4);
        assert_eq!(cumulative_slots(2, 100), 14);
        assert_eq!(cumulative_slots(3, 100), 100);
        assert_eq!(cumulative_slots(9, 100), 100);
        // capped at eligible_count
        assert_eq!(cumulative_slots(2, 5), 5);
        assert_eq!(cumulative_slots(0, 5), 1);
        // empty registry treated as 1
        assert_eq!(cumulative_slots(0, 0), 1);
    }

    #[test]
    fn threshold_widens_and_saturates() {
        // n=100: round0 admits ~1/100 of the space, round2 ~14/100, round3 all.
        assert_eq!(proposer_threshold(100, 0), u64::MAX / 100);
        assert_eq!(proposer_threshold(100, 1), (u64::MAX / 100) * 4);
        assert_eq!(proposer_threshold(100, 2), (u64::MAX / 100) * 14);
        assert_eq!(proposer_threshold(100, 3), u64::MAX); // all
        // n=1 (single eligible): always saturates -> that one is always selected.
        assert_eq!(proposer_threshold(1, 0), u64::MAX);
        // n=4 round1: slots(4)==n -> saturates.
        assert_eq!(proposer_threshold(4, 1), u64::MAX);
        // monotonic non-decreasing in round
        let n = 50;
        let mut prev = 0u64;
        for r in 0..6u32 {
            let t = proposer_threshold(n, r);
            assert!(t >= prev, "threshold must be non-decreasing in round");
            prev = t;
        }
        assert_eq!(prev, u64::MAX);
    }

    #[test]
    fn selection_by_priority() {
        // lowest priority (0) always selected at round 0; priority at/above tau not.
        let n = 100;
        let tau0 = proposer_threshold(n, 0);
        assert!(is_selected(0, n, 0));
        assert!(is_selected(tau0 - 1, n, 0));
        assert!(!is_selected(tau0, n, 0)); // strictly < tau
        assert!(!is_selected(u64::MAX, n, 0));
        // a miner not selected at round 0 may be selected at a later (wider) round.
        let p = tau0 + 1; // above round-0 cut
        assert!(!is_selected(p, n, 0));
        assert!(is_selected(p, n, 3)); // round 3 admits all
    }

    #[test]
    fn round_timing() {
        // round r opens at parent + r*interval; validator floor is the same.
        assert_eq!(min_time_for_round(1000, 0, 30), 1000);
        assert_eq!(min_time_for_round(1000, 1, 30), 1030);
        assert_eq!(min_time_for_round(1000, 2, 30), 1060);
        // elapsed -> max allowed round
        assert_eq!(max_round_for_elapsed(0, 30), 0);
        assert_eq!(max_round_for_elapsed(29, 30), 0);
        assert_eq!(max_round_for_elapsed(30, 30), 1);
        assert_eq!(max_round_for_elapsed(95, 30), 3);
    }

    #[test]
    fn gate_mainnet_activates_at_50000() {
        // network 0 (mainnet) PoAW-X activates at the fixed code height (50_000),
        // ignoring any env activation: off below it, on at/after it.
        assert!(!proposer_vrf_gate(0, Some(1), 49_999)); // mainnet: off before activation
        assert!(proposer_vrf_gate(0, Some(1), 50_000)); // mainnet: on at activation
        assert!(proposer_vrf_gate(0, None, 1_000_000)); // mainnet ignores env -> on past 50_000
        // devnet/testnet: active at/after the env activation height.
        assert!(proposer_vrf_gate(2, Some(1), 1));
        assert!(proposer_vrf_gate(1, Some(100), 100));
        assert!(!proposer_vrf_gate(2, Some(100), 99));
        assert!(!proposer_vrf_gate(2, None, 1)); // unset => off
    }

    #[test]
    fn pow_demotion_gate_mainnet_is_const_controlled_env_ignored() {
        // On mainnet the ENV is IGNORED entirely: demotion is controlled SOLELY by the compiled
        // `MAINNET_POW_DEMOTION_ACTIVATION_HEIGHT` const. RECONCILED 2026-07-24: after the
        // 2026-07-18 safety revert to None, the combined deploy knob re-aliased that const to
        // `MAINNET_COMBINED_ACTIVATION_HEIGHT = Some(61_414)`, LIVE on mainnet since v1.9.133
        // (2026-07-23). So demotion is OFF below 61,414 and ON at/after — and NO env can change it.
        let c = crate::activation::MAINNET_COMBINED_ACTIVATION_HEIGHT.expect("combined set");
        assert_eq!(MAINNET_POW_DEMOTION_ACTIVATION_HEIGHT, Some(c));
        assert!(!pow_demotion_gate(0, Some(1), c - 1)); // off just below activation, env ignored
        assert!(pow_demotion_gate(0, Some(1), c)); // on AT activation, env ignored
        assert!(pow_demotion_gate(0, None, u64::MAX)); // on far past it, no env needed
        // env can NEVER change the mainnet result: Some(1) and None agree at every height.
        for h in [0u64, 58_242, c - 1, c, u64::MAX] {
            assert_eq!(
                pow_demotion_gate(0, Some(1), h),
                pow_demotion_gate(0, None, h),
                "mainnet ignores env (h={h})"
            );
        }
        // non-mainnet: OFF unless explicitly activated, then on at/after the height.
        assert!(!pow_demotion_gate(2, None, 1)); // devnet unset => off
        assert!(!pow_demotion_gate(1, None, 1)); // testnet unset => off
        assert!(!pow_demotion_gate(2, Some(10), 9)); // before activation => off
        assert!(pow_demotion_gate(2, Some(10), 10)); // at activation => on
        assert!(pow_demotion_gate(1, Some(1), 999)); // after activation => on
    }

    #[test]
    fn mainnet_pow_demotion_const_controls_net0_activation() {
        // The mainnet activation path is the compiled const, evaluated by the pure
        // param-driven helper (testable without mutating the shipped const or env):
        assert!(!mainnet_pow_demotion_active(None, 10_000_000)); // unset => off at any height
        assert!(!mainnet_pow_demotion_active(Some(100), 99)); // before activation => off
        assert!(mainnet_pow_demotion_active(Some(100), 100)); // at activation => on
        assert!(mainnet_pow_demotion_active(Some(100), 101)); // after activation => on
        // The gate wires the const into net 0 (env ignored); the shipped const is None.
        assert_eq!(
            pow_demotion_gate(0, Some(1), 10_000_000),
            mainnet_pow_demotion_active(MAINNET_POW_DEMOTION_ACTIVATION_HEIGHT, 10_000_000)
        );
    }

    #[test]
    fn priority_from_output_le() {
        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&7u64.to_le_bytes());
        assert_eq!(proposer_priority(&out), 7);
    }

    #[test]
    fn fork_choice_hardening_gate_and_depth_floor() {
        assert!(!fork_choice_hardening_gate(0, Some(1), 100)); // mainnet hard-off
        assert!(fork_choice_hardening_gate(2, Some(50), 50));
        assert!(fork_choice_hardening_gate(2, Some(50), 999));
        assert!(!fork_choice_hardening_gate(2, Some(50), 49));
        assert!(!fork_choice_hardening_gate(2, None, 100)); // unset => off
        std::env::set_var("IRIUM_NETWORK", "devnet");
        std::env::set_var("IRIUM_POAWX_MAX_REORG_DEPTH", "2");
        assert_eq!(max_reorg_depth(), MAX_REORG_DEPTH_HARD_FLOOR); // 2 floored to 10
        std::env::set_var("IRIUM_POAWX_MAX_REORG_DEPTH", "250");
        assert_eq!(max_reorg_depth(), 250);
        std::env::remove_var("IRIUM_POAWX_MAX_REORG_DEPTH");
        assert_eq!(max_reorg_depth(), DEFAULT_MAX_REORG_DEPTH_DEVNET);
        assert_eq!(min_finality_committee(), DEFAULT_MIN_FINALITY_COMMITTEE_DEVNET);
        std::env::remove_var("IRIUM_NETWORK");
    }

    #[test]
    fn registration_gate_pure() {
        assert!(!proposer_registration_gate(false, Some(1), 100)); // vrf off => off
        assert!(!proposer_registration_gate(true, None, 100)); // no activation => off
        assert!(proposer_registration_gate(true, Some(50), 50)); // active at height
        assert!(proposer_registration_gate(true, Some(50), 999)); // active after
        assert!(!proposer_registration_gate(true, Some(50), 49)); // before activation
    }

    #[test]
    fn registration_anchor_window_math() {
        // in the past + within window.
        assert!(registration_anchor_valid(60, 66, 64));
        assert!(registration_anchor_valid(65, 66, 64));
        // genesis anchor goes stale once height passes anchor + window.
        assert!(!registration_anchor_valid(0, 66, 64)); // 0 < 66-64=2 => stale
        assert!(registration_anchor_valid(0, 64, 64)); // height==window => no lower bound
        assert!(!registration_anchor_valid(0, 65, 64)); // 0 < 1 => stale
        // not in the past.
        assert!(!registration_anchor_valid(66, 66, 64));
        assert!(!registration_anchor_valid(67, 66, 64));
    }

    #[test]
    fn registry_is_registered_tracks_keys() {
        let mut reg = ProposerEligibilityRegistry::default();
        let k = [0x9u8; 33];
        assert!(!reg.is_registered(&k));
        reg.register(k, [0x1u8; 20], 5);
        assert!(reg.is_registered(&k));
        reg.unregister(&k, 5);
        assert!(!reg.is_registered(&k));
    }

    #[test]
    fn pool_refreshes_to_fresher_anchor() {
        std::env::set_var("IRIUM_NETWORK", "devnet");
        let net = crate::activation::network_id_byte();
        let pool = NodeProposerRegistrationPool::default();
        let r0 = crate::poawx::ProposerRegistrationV1::build_signed(&[0x7u8; 32], net, 0, &[0x9u8; 32], 0)
            .unwrap();
        let r5 = crate::poawx::ProposerRegistrationV1::build_signed(&[0x7u8; 32], net, 5, &[0x9u8; 32], 0)
            .unwrap();
        assert!(matches!(
            pool.ingest_bytes(&r0.serialize(), |_h| Some([0x9u8; 32])),
            crate::poawx_gossip::GossipOutcome::AcceptedNew
        ));
        // A2 CONTRACT CHANGE: a fresher anchor still REFRESHES the stored record (so the
        // pool converges on the newest, as before), but it only counts as AcceptedNew --
        // and therefore rebroadcasts -- when the anchor advanced by at least
        // PROPOSER_REG_REFRESH_MIN_ANCHOR_DELTA. Previously ANY advance rebroadcast, which
        // let a squatter re-anchor every block and fan out to every peer for free.
        // Here 5 - 0 = 5 < 8, so it is a silent refresh.
        assert!(matches!(
            pool.ingest_bytes(&r5.serialize(), |_h| Some([0x9u8; 32])),
            crate::poawx_gossip::GossipOutcome::Duplicate
        ));
        // ...but convergence is preserved: the stored record IS the fresher one.
        let held = pool.announce_candidates(1, &BTreeSet::new());
        assert_eq!(
            held[0].anchor_height, 5,
            "sub-threshold refresh must still update the stored record"
        );
        // A large enough advance does rebroadcast.
        let r20 = crate::poawx::ProposerRegistrationV1::build_signed(
            &[0x7u8; 32], net, 5 + PROPOSER_REG_REFRESH_MIN_ANCHOR_DELTA, &[0x9u8; 32], 0,
        )
        .unwrap();
        assert!(matches!(
            pool.ingest_bytes(&r20.serialize(), |_h| Some([0x9u8; 32])),
            crate::poawx_gossip::GossipOutcome::AcceptedNew
        ));
        // older/equal anchor => duplicate (no downgrade).
        assert!(matches!(
            pool.ingest_bytes(&r0.serialize(), |_h| Some([0x9u8; 32])),
            crate::poawx_gossip::GossipOutcome::Duplicate
        ));
        assert_eq!(pool.len(), 1);
        std::env::remove_var("IRIUM_NETWORK");
    }

    #[test]
    fn pool_ingest_dedup_and_filter() {
        std::env::set_var("IRIUM_NETWORK", "devnet");
        let net = crate::activation::network_id_byte();
        let pool = NodeProposerRegistrationPool::default();
        let reg =
            crate::poawx::ProposerRegistrationV1::build_signed(&[0x7u8; 32], net, 0, &[0x9u8; 32], 0)
                .unwrap();
        let bytes = reg.serialize();
        assert!(matches!(
            pool.ingest_bytes(&bytes, |_h| Some([0x9u8; 32])),
            crate::poawx_gossip::GossipOutcome::AcceptedNew
        ));
        assert!(matches!(
            pool.ingest_bytes(&bytes, |_h| Some([0x9u8; 32])),
            crate::poawx_gossip::GossipOutcome::Duplicate
        ));
        let mut bad = reg.clone();
        bad.signature[0] ^= 0xff;
        assert!(matches!(
            pool.ingest_bytes(&bad.serialize(), |_h| Some([0x9u8; 32])),
            crate::poawx_gossip::GossipOutcome::Rejected(_)
        ));
        assert_eq!(pool.len(), 1);
        std::env::remove_var("IRIUM_NETWORK");
    }

    #[test]
    fn anti_spam_cap_math() {
        // gate off => configured value passes through verbatim.
        assert_eq!(cap_difficulty_if_enforced(20, false, 8), 20);
        // enforced => capped downward at the floor.
        assert_eq!(cap_difficulty_if_enforced(20, true, 8), 8);
        // enforced never raises a low configured value.
        assert_eq!(cap_difficulty_if_enforced(4, true, 8), 4);
    }

    #[test]
    fn registry_freeze_and_expiry() {
        let mut reg = ProposerEligibilityRegistry::default();
        let k1 = [0x11u8; 33];
        let k2 = [0x22u8; 33];
        let (fd, ew) = (16u64, 100u64);
        reg.register(k1, [0x01u8; 20], 10);
        reg.register(k2, [0x02u8; 20], 12);
        // not enough history => no eligibility (bootstrap permissive).
        assert_eq!(reg.eligible_count_with(10, fd, ew), 0);
        // k1 (h=10) eligible at H=26 (window hi = 26-16 = 10); k2 (h=12) not yet.
        assert!(reg.is_eligible_with(&k1, 26, fd, ew));
        assert!(!reg.is_eligible_with(&k2, 26, fd, ew));
        assert_eq!(reg.eligible_count_with(26, fd, ew), 1);
        // at H=28 (hi=12) both are in the frozen window.
        assert_eq!(reg.eligible_count_with(28, fd, ew), 2);
        // expiry: at H=126 (window [11,110]) k1(10) drops out, k2(12) remains.
        assert!(!reg.is_eligible_with(&k1, 126, fd, ew));
        assert!(reg.is_eligible_with(&k2, 126, fd, ew));
    }

    #[test]
    fn registry_register_unregister_symmetry() {
        let mut reg = ProposerEligibilityRegistry::default();
        let k = [0x33u8; 33];
        let (fd, ew) = (4u64, 100u64);
        reg.register(k, [0x03u8; 20], 20);
        reg.register(k, [0x03u8; 20], 21);
        assert_eq!(reg.len(), 1);
        assert!(reg.is_eligible_with(&k, 24, fd, ew)); // hi=20, has 20
        reg.unregister(&k, 20);
        reg.unregister(&k, 21);
        assert_eq!(reg.len(), 0); // exact inverse => fully removed
        assert!(!reg.is_eligible_with(&k, 24, fd, ew));
    }
}

#[cfg(test)]
mod a0_a2_registration_fairness {
    use super::*;
    use crate::poawx::ProposerRegistrationV1;

    fn reg_for(secret_byte: u8, anchor_height: u64, net: u8) -> ProposerRegistrationV1 {
        ProposerRegistrationV1::build_signed(&[secret_byte; 32], net, anchor_height, &[0x9u8; 32], 0)
            .expect("build_signed")
    }

    /// A0: announce slots must be first-come-first-served, NOT ordered by public key.
    /// Before this fix the 8 slots always went to the numerically smallest keys, so a
    /// cheap vanity key (independent of the sybil PoW) captured every node's list.
    #[test]
    fn announce_order_is_arrival_not_key_order() {
        std::env::set_var("IRIUM_NETWORK", "devnet");
        let net = crate::activation::network_id_byte();
        let pool = NodeProposerRegistrationPool::default();

        // Insert several keys, then check arrival order != key order for this sample,
        // so the test cannot pass by coincidence.
        let mut arrival: Vec<[u8; 33]> = Vec::new();
        for b in [0x51u8, 0x22, 0x77, 0x13, 0x66] {
            let r = reg_for(b, 0, net);
            arrival.push(r.vrf_pubkey);
            assert!(matches!(
                pool.ingest_bytes(&r.serialize(), |_h| Some([0x9u8; 32])),
                crate::poawx_gossip::GossipOutcome::AcceptedNew
            ));
        }
        let mut key_sorted = arrival.clone();
        key_sorted.sort();
        assert_ne!(
            arrival, key_sorted,
            "fixture is vacuous: arrival order happens to equal key order"
        );

        let got: Vec<[u8; 33]> = pool
            .announce_candidates(5, &BTreeSet::new())
            .into_iter()
            .map(|r| r.vrf_pubkey)
            .collect();
        assert_eq!(got, arrival, "candidates must be in ARRIVAL order");
        assert_ne!(got, key_sorted, "candidates must NOT be in public-key order");

        // And the head of the queue is the FIRST arrival, not the smallest key.
        let smallest = key_sorted[0];
        let first_arrival = arrival[0];
        if smallest != first_arrival {
            let head = pool.announce_candidates(1, &BTreeSet::new());
            assert_eq!(head[0].vrf_pubkey, first_arrival);
            assert_ne!(head[0].vrf_pubkey, smallest, "smallest key must not capture the slot");
        }
        std::env::remove_var("IRIUM_NETWORK");
    }

    /// A2: a refresh only counts as new (and so rebroadcasts) when the anchor advanced
    /// meaningfully. Otherwise a squatter re-anchors every block and each refresh fans
    /// out to every peer for free.
    #[test]
    fn small_refresh_does_not_rebroadcast_large_one_does() {
        std::env::set_var("IRIUM_NETWORK", "devnet");
        let net = crate::activation::network_id_byte();
        let pool = NodeProposerRegistrationPool::default();
        let base = reg_for(0x31, 100, net);
        assert!(matches!(
            pool.ingest_bytes(&base.serialize(), |_h| Some([0x9u8; 32])),
            crate::poawx_gossip::GossipOutcome::AcceptedNew
        ));
        // advance by less than the minimum delta => updated but NOT rebroadcast
        let small = reg_for(0x31, 100 + PROPOSER_REG_REFRESH_MIN_ANCHOR_DELTA - 1, net);
        assert!(
            matches!(
                pool.ingest_bytes(&small.serialize(), |_h| Some([0x9u8; 32])),
                crate::poawx_gossip::GossipOutcome::Duplicate
            ),
            "sub-threshold refresh must not re-amplify"
        );
        // advance by at least the minimum delta => genuinely new
        let big = reg_for(0x31, 100 + PROPOSER_REG_REFRESH_MIN_ANCHOR_DELTA * 2, net);
        assert!(matches!(
            pool.ingest_bytes(&big.serialize(), |_h| Some([0x9u8; 32])),
            crate::poawx_gossip::GossipOutcome::AcceptedNew
        ));
        // an older anchor is still ignored outright
        let older = reg_for(0x31, 50, net);
        assert!(matches!(
            pool.ingest_bytes(&older.serialize(), |_h| Some([0x9u8; 32])),
            crate::poawx_gossip::GossipOutcome::Duplicate
        ));
        assert_eq!(pool.len(), 1, "refreshes must not grow the pool");
        std::env::remove_var("IRIUM_NETWORK");
    }

    /// A0 anti-gaming: a refresh must NOT re-stamp arrival order, or a squatter holds
    /// the head of the queue forever by re-anchoring -- the same capture A0 removes.
    #[test]
    fn refresh_does_not_jump_the_queue() {
        std::env::set_var("IRIUM_NETWORK", "devnet");
        let net = crate::activation::network_id_byte();
        let pool = NodeProposerRegistrationPool::default();
        // Warm-up arrival so `first` does NOT land on seq 0. Without this, a control
        // that re-stamps a refresh to seq 0 merely TIES with `first` and the assertion
        // can pass by accident of tie-break order -- i.e. the test would be vacuous.
        let warm = reg_for(0x40, 100, net);
        pool.ingest_bytes(&warm.serialize(), |_h| Some([0x9u8; 32]));
        let first = reg_for(0x41, 100, net);
        let second = reg_for(0x42, 100, net);
        pool.ingest_bytes(&first.serialize(), |_h| Some([0x9u8; 32]));
        pool.ingest_bytes(&second.serialize(), |_h| Some([0x9u8; 32]));
        // `second` refreshes aggressively; it must still stay behind `first`.
        for d in 1..=5u64 {
            let bump = reg_for(0x42, 100 + d * PROPOSER_REG_REFRESH_MIN_ANCHOR_DELTA * 2, net);
            pool.ingest_bytes(&bump.serialize(), |_h| Some([0x9u8; 32]));
        }
        let got: Vec<[u8; 33]> = pool
            .announce_candidates(3, &BTreeSet::new())
            .into_iter()
            .map(|r| r.vrf_pubkey)
            .collect();
        assert_eq!(got[0], warm.vrf_pubkey, "warm-up must remain first");
        assert_eq!(got[1], first.vrf_pubkey, "refreshing must not jump the queue");
        assert_eq!(got[2], second.vrf_pubkey, "the refresher must stay last");
        std::env::remove_var("IRIUM_NETWORK");
    }
}

#[cfg(test)]
mod a4_sybil_recompute {
    use super::*;
    use crate::poawx::ProposerRegistrationV1;

    /// Fixed anchor hash the tests build/verify against.
    const ANCHOR: [u8; 32] = [0x9u8; 32];

    /// A validly-SIGNED registration whose `sybil_digest` is FABRICATED (all zeros,
    /// which clears any target for free) instead of the real hash of its inputs. This is
    /// exactly what an attacker submits to pay ~0 proof-of-work. `build_signed` cannot
    /// produce it (it grinds a real digest), so we self-sign a hand-set digest directly.
    fn forged_zero_digest_reg(secret_byte: u8, anchor_height: u64, net: u8) -> ProposerRegistrationV1 {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        let secret = [secret_byte; 32];
        let sk = k256::ecdsa::SigningKey::from_slice(&secret).unwrap();
        let vk = sk.verifying_key();
        let pt = vk.to_encoded_point(true);
        let mut vrf_pubkey = [0u8; 33];
        vrf_pubkey.copy_from_slice(pt.as_bytes());
        let mut reg = ProposerRegistrationV1 {
            vrf_pubkey,
            anchor_height,
            sybil_nonce: [0u8; 32],
            sybil_digest: [0u8; 32], // forged: 256 leading zeros => clears any target for free
            signature: [0u8; 64],
        };
        let sig: k256::ecdsa::Signature = sk.sign_prehash(&reg.signing_digest(net)).unwrap();
        reg.signature.copy_from_slice(&sig.to_bytes());
        reg
    }

    fn honest_reg(secret_byte: u8, anchor_height: u64, net: u8) -> ProposerRegistrationV1 {
        ProposerRegistrationV1::build_signed(
            &[secret_byte; 32],
            net,
            anchor_height,
            &ANCHOR,
            crate::poawx_ticket::effective_sybil_bits(),
        )
        .expect("build_signed")
    }

    /// THE A4 CONTROL. The forged registration passes BOTH checks the pre-A4 ingest used
    /// (`meets_sybil_target` on the field + `signature_ok`), so it was ACCEPTED with zero
    /// PoW -- the ~2^bits asymmetry. With the anchor resolvable, ingest now RECOMPUTES the
    /// digest, finds it does not match, and REJECTS. Reverting `ingest_bytes` to the
    /// field-check makes this test pass a forged registration again.
    #[test]
    fn forged_zero_digest_rejected_but_passes_the_old_field_check() {
        std::env::set_var("IRIUM_NETWORK", "devnet");
        let net = crate::activation::network_id_byte();
        let pool = NodeProposerRegistrationPool::default();
        let forged = forged_zero_digest_reg(0x51, 10, net);

        // Exactly what the OLD ingest checked -- both true, so pre-A4 it was accepted.
        assert!(
            crate::poawx_ticket::meets_sybil_target(
                &forged.sybil_digest,
                crate::poawx_ticket::effective_sybil_bits()
            ),
            "forged all-zero digest trivially clears the target -- this is the free-PoW hole"
        );
        assert!(forged.signature_ok(net), "forged reg is validly self-signed");

        // NEW: recompute against the real anchor rejects it.
        let outcome = pool.ingest_bytes(&forged.serialize(), |_h| Some(ANCHOR));
        assert!(
            matches!(&outcome, crate::poawx_gossip::GossipOutcome::Rejected(e) if e.contains("mismatch")),
            "forged digest must be rejected by recompute, got {outcome:?}"
        );
        assert_eq!(pool.len(), 0, "nothing forged may enter the pool");
        std::env::remove_var("IRIUM_NETWORK");
    }

    /// An honestly-ground registration is accepted when the anchor recomputes to match.
    #[test]
    fn honest_registration_with_matching_anchor_is_accepted() {
        std::env::set_var("IRIUM_NETWORK", "devnet");
        let net = crate::activation::network_id_byte();
        let pool = NodeProposerRegistrationPool::default();
        let reg = honest_reg(0x22, 10, net);
        assert!(matches!(
            pool.ingest_bytes(&reg.serialize(), |_h| Some(ANCHOR)),
            crate::poawx_gossip::GossipOutcome::AcceptedNew
        ));
        assert_eq!(pool.len(), 1);
        std::env::remove_var("IRIUM_NETWORK");
    }

    /// Fail-closed: if the node cannot resolve the anchor (it is behind that height, or a
    /// peer pinned a future/unknown anchor), the registration is rejected -- a peer must
    /// not be able to skip verification by choosing an anchor we do not hold.
    #[test]
    fn unresolvable_anchor_fails_closed() {
        std::env::set_var("IRIUM_NETWORK", "devnet");
        let net = crate::activation::network_id_byte();
        let pool = NodeProposerRegistrationPool::default();
        let reg = honest_reg(0x33, 10, net);
        let outcome = pool.ingest_bytes(&reg.serialize(), |_h| None);
        assert!(
            matches!(&outcome, crate::poawx_gossip::GossipOutcome::Rejected(e) if e.contains("anchor unavailable")),
            "unknown anchor must fail closed, got {outcome:?}"
        );
        assert_eq!(pool.len(), 0);
        std::env::remove_var("IRIUM_NETWORK");
    }

    /// The digest binds to a SPECIFIC anchor block: an honest registration verified
    /// against the wrong anchor recomputes to a different digest and is rejected.
    #[test]
    fn honest_registration_against_wrong_anchor_is_rejected() {
        std::env::set_var("IRIUM_NETWORK", "devnet");
        let net = crate::activation::network_id_byte();
        let pool = NodeProposerRegistrationPool::default();
        let reg = honest_reg(0x44, 10, net); // built against ANCHOR
        let outcome = pool.ingest_bytes(&reg.serialize(), |_h| Some([0xAAu8; 32]));
        assert!(
            matches!(&outcome, crate::poawx_gossip::GossipOutcome::Rejected(e) if e.contains("mismatch")),
            "wrong-anchor recompute must reject, got {outcome:?}"
        );
        std::env::remove_var("IRIUM_NETWORK");
    }
}
