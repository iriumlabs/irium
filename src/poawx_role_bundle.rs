//! C1/C2/C3 — the role-worker bundle collection channel.
//!
//! A contributor role-worker (COMPUTE / VERIFY / SUPPORT) performs its assigned work
//! independently, bound to its OWN payout key, and emits a bundle. Until now the only
//! transport for that bundle was a human copying JSON files into `IRIUM_M3_DIR` for the
//! `#[ignore]`d rig tests. This module is the actual channel.
//!
//! TRANSPORT CHOICE: node-local RPC, not gossip and not the mempool.
//!  - Mempool semantics are wrong: a bundle is bound to exactly one `target_height` and
//!    is worthless at H+1, whereas the mempool persists until inclusion.
//!  - Gossip would be wasteful (a bundle is only useful to whoever builds the NEXT
//!    block, not to 100 peers) and would create exactly the unauthenticated remote
//!    ingest surface that produced the registration-pool defects.
//!  - RPC mirrors the existing proposer-registration bridge: worker -> node -> pool ->
//!    block template. No new wire message, no protocol change, no activation.
//!
//! VALIDATED ON INGEST, NOT ON USE. Every bundle is fully verified when it arrives:
//! the payout binding is recomputed rather than trusted, and the ECVRF proof is checked.
//! The registration pool's sybil check trusted an attacker-supplied digest field and so
//! provided no protection at all; that mistake is not repeated here.
//!
//! SCOPE / KNOWN LIMITATION: the RPC route this pool serves is LOOPBACK-ONLY in this
//! unit. Co-located miners (standalone CLI, GPU, Irium Core with a bundled node) can
//! submit; a POOL-based miner submitting to a remote pool node CANNOT yet. Remote
//! exposure is a deliberately separate, separately-approved unit. Do not read this as
//! "all mining paths are now collected".
#![allow(dead_code)]

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

use crate::poawx_candidate::AssignmentProofV2;
use crate::poawx_puzzle::PuzzleSolutionV1;
use crate::poawx_finality::FinalityVoteV1;
use crate::poawx_ticket::TicketProof;

/// Hard bound on pooled bundles. Small: bundles are height-scoped and pruned, and only
/// the best per (role, height) is ever retained.
pub const ROLE_BUNDLE_POOL_MAX: usize = 512;

/// Contributor roles that may submit a bundle. ROLE_PROPOSER is deliberately excluded:
/// the proposer is the block builder, not a collected contributor.
pub fn is_collectable_role(role_id: u8) -> bool {
    role_id == crate::poawx::ROLE_COMPUTE_CONTRIBUTOR
        || role_id == crate::poawx::ROLE_VERIFY_CONTRIBUTOR
        || role_id == crate::poawx::ROLE_SUPPORT_CONTRIBUTOR
}

fn hash160(bytes: &[u8]) -> [u8; 20] {
    let mut o = [0u8; 20];
    o.copy_from_slice(&Ripemd160::digest(Sha256::digest(bytes)));
    o
}

/// A collected role-worker bundle. Field-for-field the JSON that `poawx-role-worker`
/// already emits, so existing workers and existing rig fixtures are compatible.
#[derive(Debug, Clone, PartialEq)]
pub struct RoleBundleV1 {
    pub network_id: u8,
    pub target_height: u64,
    pub role_id: u8,
    pub solver_pkh: [u8; 20],
    pub assignment_public_key: [u8; 33],
    pub assignment_proof: AssignmentProofV2,
    pub ticket_proof: TicketProof,
    pub puzzle_solution: PuzzleSolutionV1,
    pub lane_id: u8,
    pub claim_secret: [u8; 32],
    pub claim_nonce: [u8; 32],
    pub commitment_hash: [u8; 32],
    pub claim_digest: [u8; 32],
    /// R4: SUPPORT doubles as the FINALITY COMMITTEE MEMBER, so a collected SUPPORT
    /// worker must supply its own signed finality vote -- the builder holds no key for
    /// it. `None` for COMPUTE/VERIFY, which have no committee role.
    ///
    /// The vote binds to the PARENT block (block_hash = prev_hash), not to the block
    /// under construction, so a worker can produce it at bundle-build time without
    /// circularity.
    pub finality_vote: Option<FinalityVoteV1>,
}

fn hex_field(v: &serde_json::Value, k: &str) -> Result<Vec<u8>, String> {
    let s = v
        .get(k)
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("role bundle: missing field {k}"))?;
    hex::decode(s).map_err(|e| format!("role bundle: field {k} not hex: {e}"))
}

fn fixed<const N: usize>(b: Vec<u8>, k: &str) -> Result<[u8; N], String> {
    if b.len() != N {
        return Err(format!(
            "role bundle: field {k} wrong length {} (want {N})",
            b.len()
        ));
    }
    let mut o = [0u8; N];
    o.copy_from_slice(&b);
    Ok(o)
}

impl RoleBundleV1 {
    pub fn from_json(s: &str) -> Result<Self, String> {
        let v: serde_json::Value =
            serde_json::from_str(s).map_err(|e| format!("role bundle: bad json: {e}"))?;
        let u64f = |k: &str| -> Result<u64, String> {
            v.get(k)
                .and_then(|x| x.as_u64())
                .ok_or_else(|| format!("role bundle: missing/!u64 field {k}"))
        };
        let claim = v
            .get("claim")
            .ok_or_else(|| "role bundle: missing claim".to_string())?;
        Ok(Self {
            network_id: u64f("network_id")? as u8,
            target_height: u64f("target_height")?,
            role_id: u64f("role_id")? as u8,
            solver_pkh: fixed::<20>(hex_field(&v, "solver_pkh")?, "solver_pkh")?,
            assignment_public_key: fixed::<33>(
                hex_field(&v, "assignment_public_key")?,
                "assignment_public_key",
            )?,
            assignment_proof: AssignmentProofV2::deserialize(&hex_field(&v, "assignment_proof")?)?,
            ticket_proof: TicketProof::deserialize(&hex_field(&v, "ticket_proof")?)?,
            puzzle_solution: PuzzleSolutionV1::deserialize(&hex_field(&v, "puzzle_solution")?)?,
            lane_id: claim
                .get("lane_id")
                .and_then(|x| x.as_u64())
                .ok_or_else(|| "role bundle: missing claim.lane_id".to_string())?
                as u8,
            claim_secret: fixed::<32>(hex_field(claim, "secret")?, "claim.secret")?,
            claim_nonce: fixed::<32>(hex_field(claim, "nonce")?, "claim.nonce")?,
            commitment_hash: fixed::<32>(
                hex_field(claim, "commitment_hash")?,
                "claim.commitment_hash",
            )?,
            claim_digest: fixed::<32>(hex_field(claim, "claim_digest")?, "claim.claim_digest")?,
            finality_vote: match v.get("finality_vote").and_then(|x| x.as_str()) {
                Some(h) => Some(FinalityVoteV1::deserialize(
                    &hex::decode(h)
                        .map_err(|e| format!("role bundle: finality_vote not hex: {e}"))?,
                )?),
                None => None,
            },
        })
    }

    /// Inverse of `from_json` (round-trips). Used by the dev-only collected-bundles
    /// endpoint so a genuinely SEPARATE proposer process can rebuild the block from the
    /// pool's validated bundles without holding any worker's key. Non-mainnet/test use.
    pub fn to_json(&self) -> String {
        let mut o = serde_json::json!({
            "network_id": self.network_id,
            "target_height": self.target_height,
            "role_id": self.role_id,
            "solver_pkh": hex::encode(self.solver_pkh),
            "assignment_public_key": hex::encode(self.assignment_public_key),
            "assignment_proof": hex::encode(self.assignment_proof.serialize()),
            "ticket_proof": hex::encode(self.ticket_proof.serialize()),
            "puzzle_solution": hex::encode(self.puzzle_solution.serialize()),
            "claim": {
                "lane_id": self.lane_id,
                "secret": hex::encode(self.claim_secret),
                "nonce": hex::encode(self.claim_nonce),
                "commitment_hash": hex::encode(self.commitment_hash),
                "claim_digest": hex::encode(self.claim_digest),
            },
        });
        if let Some(v) = &self.finality_vote {
            o["finality_vote"] = serde_json::Value::String(hex::encode(v.serialize()));
        }
        serde_json::to_string(&o).unwrap()
    }

    /// The self-VRF score used to resolve competition between workers for one role,
    /// matching `best_for_role`'s ordering.
    pub fn score(&self) -> u64 {
        self.assignment_proof.score()
    }

    /// Full validation. Every check recomputes rather than trusting a declared field.
    ///
    /// `expected_seed` is checked when supplied; a collector that does not yet know the
    /// epoch seed may pass `None` and still get every other guarantee.
    pub fn validate(
        &self,
        expected_network: u8,
        expected_height: u64,
        expected_seed: Option<[u8; 32]>,
        expected_parent: Option<[u8; 32]>,
    ) -> Result<(), String> {
        if self.network_id != expected_network {
            return Err("role bundle: wrong network".to_string());
        }
        if self.target_height != expected_height {
            return Err("role bundle: wrong height".to_string());
        }
        if !is_collectable_role(self.role_id) {
            return Err("role bundle: role is not a collectable contributor role".to_string());
        }
        // THE PAYOUT BINDING. Recomputed, never trusted. This is the rule
        // `contributor_role_binding` enforces on-chain; a bundle failing it can never be
        // paid, so it is rejected at ingest regardless of whether the gate is active.
        if self.solver_pkh != hash160(&self.assignment_public_key) {
            return Err("role bundle: solver pkh not derived from assignment key".to_string());
        }
        // The proof must be for THIS worker, THIS role.
        if self.assignment_proof.solver_pkh != self.solver_pkh {
            return Err("role bundle: assignment proof solver pkh mismatch".to_string());
        }
        if self.assignment_proof.assignment_public_key != self.assignment_public_key {
            return Err("role bundle: assignment proof key mismatch".to_string());
        }
        if self.assignment_proof.role_id != self.role_id {
            return Err("role bundle: assignment proof role mismatch".to_string());
        }
        if let Some(seed) = expected_seed {
            if self.assignment_proof.seed != seed {
                return Err("role bundle: assignment proof wrong seed".to_string());
            }
        }
        // The ECVRF proof itself (checks version/network/height/digest and the curve op).
        self.assignment_proof
            .validate(expected_network, expected_height)
            .map_err(|e| format!("role bundle: {e}"))?;
        self.validate_finality_vote(expected_network, expected_height, expected_parent)?;
        Ok(())
    }

    /// R4: a SUPPORT bundle MUST carry a valid, self-signed finality vote; any other
    /// role must not carry one. Every field is recomputed or re-derived, never trusted.
    fn validate_finality_vote(
        &self,
        expected_network: u8,
        expected_height: u64,
        expected_parent: Option<[u8; 32]>,
    ) -> Result<(), String> {
        let is_support = self.role_id == crate::poawx::ROLE_SUPPORT_CONTRIBUTOR;
        let v = match (&self.finality_vote, is_support) {
            (Some(_), false) => {
                return Err("role bundle: finality vote on a non-SUPPORT role".to_string())
            }
            (None, true) => {
                return Err("role bundle: SUPPORT bundle missing its finality vote".to_string())
            }
            (None, false) => return Ok(()),
            (Some(v), true) => v,
        };
        if v.network_id != expected_network {
            return Err("role bundle: finality vote wrong network".to_string());
        }
        if v.target_height != expected_height {
            return Err("role bundle: finality vote wrong height".to_string());
        }
        if v.vote_type != crate::poawx_finality::FinalityVoteType::Commit.id() {
            return Err("role bundle: finality vote is not a Commit".to_string());
        }
        // The member identity must be the worker's own, derived not declared.
        if v.member_pkh != hash160(&v.member_pubkey) {
            return Err("role bundle: finality vote member pkh not derived from its pubkey"
                .to_string());
        }
        if v.member_pkh != self.solver_pkh {
            return Err("role bundle: finality vote member pkh != solver pkh".to_string());
        }
        // The vote finalizes the PARENT, so it must name the parent we expect.
        if let Some(parent) = expected_parent {
            if v.block_hash != parent {
                return Err("role bundle: finality vote wrong parent block hash".to_string());
            }
        }
        // Bind the vote to the worker's OWN ticket. The chain does NOT enforce this --
        // FinalityProofV1::validate never cross-checks ticket_digest against anything
        // external, so the field is signed but otherwise free. Binding it here keeps a
        // collected bundle internally coherent rather than merely self-consistent.
        if v.ticket_digest != self.ticket_proof.ticket_digest {
            return Err("role bundle: finality vote ticket digest != bundle ticket".to_string());
        }
        v.verify(expected_network, expected_height, &v.block_hash)
            .map_err(|e| format!("role bundle: finality vote {e}"))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleOutcome {
    /// First bundle seen for this (height, role).
    AcceptedNew,
    /// Replaced a lower-scoring bundle for the same (height, role).
    ReplacedLower,
    /// Ignored: an equal-or-better bundle for this (height, role) is already held.
    Duplicate,
}

#[derive(Default)]
struct Inner {
    /// Only bundles for this height are retained; advancing prunes everything older.
    height: u64,
    best: BTreeMap<(u8, [u8; 20]), RoleBundleV1>,
}

/// Node-local, height-scoped pool of validated contributor bundles.
#[derive(Default)]
pub struct NodeRoleBundlePool {
    inner: Mutex<Inner>,
}

impl NodeRoleBundlePool {
    /// Validate and pool a bundle. Rejection reasons are returned verbatim so the RPC
    /// layer can surface a specific cause rather than a generic failure.
    pub fn ingest(
        &self,
        bundle: RoleBundleV1,
        expected_network: u8,
        expected_height: u64,
        expected_seed: Option<[u8; 32]>,
        expected_parent: Option<[u8; 32]>,
    ) -> Result<BundleOutcome, String> {
        bundle.validate(expected_network, expected_height, expected_seed, expected_parent)?;
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if expected_height > g.height {
            g.height = expected_height;
            g.best.clear(); // height advanced: previous-height bundles are worthless
        } else if expected_height < g.height {
            return Err("role bundle: stale height".to_string());
        }
        if g.best.len() >= ROLE_BUNDLE_POOL_MAX
            && !g.best.contains_key(&(bundle.role_id, bundle.solver_pkh))
        {
            return Err("role bundle: pool full".to_string());
        }
        let key = (bundle.role_id, bundle.solver_pkh);
        match g.best.get(&key) {
            Some(existing) if existing.score() >= bundle.score() => Ok(BundleOutcome::Duplicate),
            Some(_) => {
                g.best.insert(key, bundle);
                Ok(BundleOutcome::ReplacedLower)
            }
            None => {
                g.best.insert(key, bundle);
                Ok(BundleOutcome::AcceptedNew)
            }
        }
    }

    /// R1: the full tiered path. `src` is the submitting source. Ordering is asserted
    /// by `tier1_rejection_never_reaches_validation`.
    pub fn ingest_tiered(
        &self,
        src: std::net::IpAddr,
        bundle: RoleBundleV1,
        expected_network: u8,
        expected_height: u64,
        expected_seed: Option<[u8; 32]>,
        expected_parent: Option<[u8; 32]>,
    ) -> Result<BundleOutcome, String> {
        // TIER 1 -- per source. Cheap, and it runs BEFORE validation so that the cost of
        // validating is itself protected.
        if !crate::poawx_admission::admission_rate_allowed(src) {
            return Err("role bundle: source rate limited".to_string());
        }
        // TIER 2 -- validation. Counted so a test can prove tier 1 short-circuits it.
        VALIDATIONS_PERFORMED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        bundle.validate(expected_network, expected_height, expected_seed, expected_parent)?;
        // TIER 3 -- per identity, only ever reached by an identity that already cost a
        // real ECVRF prove.
        if !identity_rate_allowed(&bundle.solver_pkh) {
            return Err("role bundle: identity rate limited".to_string());
        }
        self.ingest(bundle, expected_network, expected_height, expected_seed, expected_parent)
    }

    pub fn ingest_json(
        &self,
        json: &str,
        expected_network: u8,
        expected_height: u64,
        expected_seed: Option<[u8; 32]>,
        expected_parent: Option<[u8; 32]>,
    ) -> Result<BundleOutcome, String> {
        let b = RoleBundleV1::from_json(json)?;
        self.ingest(b, expected_network, expected_height, expected_seed, expected_parent)
    }

    /// Highest-scoring collected bundle for `role_id` at the pool's current height.
    /// Mirrors `best_for_role`'s ordering so collection and on-chain selection agree.
    pub fn best_for_role(&self, role_id: u8, height: u64) -> Option<RoleBundleV1> {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.height != height {
            return None;
        }
        g.best
            .iter()
            .filter(|((r, _), _)| *r == role_id)
            .map(|(_, b)| b)
            .max_by_key(|b| b.score())
            .cloned()
    }

    /// Every bundle held for `height`, for template exposure.
    pub fn collected_for_height(&self, height: u64) -> Vec<RoleBundleV1> {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.height != height {
            return Vec::new();
        }
        g.best.values().cloned().collect()
    }

    /// Drop everything below `height`.
    pub fn prune_below(&self, height: u64) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.height < height {
            g.height = height;
            g.best.clear();
        }
    }

    /// Every pooled bundle at `height` as `(solver_pkh, role_id, vrf_output)`.
    ///
    /// This node's OWN record of who revealed a role claim. Private sortition selects from the
    /// reveals, and a producer must not be able to shrink that set: if selection used only the
    /// candidates a block chose to carry, a producer could simply omit anyone with a better
    /// priority and hand itself the role. Unioning this in means a candidate THIS node already
    /// saw cannot be hidden from it.
    pub fn revealed_at(&self, height: u64) -> Vec<([u8; 20], u8, [u8; 32])> {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.height != height {
            return Vec::new();
        }
        g.best
            .values()
            .map(|b| (b.solver_pkh, b.role_id, b.assignment_proof.vrf_output))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .best
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn current_height(&self) -> u64 {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .height
    }
}

// ── R1: per-identity rate limiting (tier 3) ─────────────────────────────────
//
// TIER ORDERING IS THE DESIGN, and reversing it defeats the purpose:
//   1. per-SOURCE (cheap)   -- guards the cost of validation itself
//   2. VALIDATE             -- recompute the payout binding, verify the ECVRF
//   3. per-IDENTITY         -- guards POOL SLOTS, and only ever sees identities that
//                              already cost a real ECVRF prove (~1089us measured on
//                              this host), so minting identities is not free
//
// Limiting by identity FIRST would be useless: garbage carries no valid solver_pkh, so
// the identity limiter would never engage and validation would become the DoS surface.
// Validating first without a source gate makes validation itself the attack.
//
// This also resolves the aggregator caveat carried from A1: a pool relaying for 500
// miners is ONE source but 500 identities, so it needs headroom at tier 1 while tier 3
// keeps any single worker from monopolising pool slots.

const IDENTITY_RATE_WINDOW_SECS: u64 = 60;
const IDENTITY_RATE_MAX: u32 = 8;

/// Per-identity role-bundle submission limit. MAINNET (network_id==0) is FIXED at the consts —
/// env-ignored, so the anti-DoS bound cannot be relaxed in production. Devnet/testnet may raise it
/// via `IRIUM_POAWX_IDENTITY_RATE_{MAX,WINDOW_SECS}` for many-contributor / fast-block harnesses where
/// a contributor legitimately submits on every block (8/60s is designed for ~2-min production blocks).
pub fn identity_rate_window_secs() -> u64 {
    if crate::activation::network_id_byte() == 0 {
        return IDENTITY_RATE_WINDOW_SECS;
    }
    std::env::var("IRIUM_POAWX_IDENTITY_RATE_WINDOW_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(|w| w.clamp(1, 3600))
        .unwrap_or(IDENTITY_RATE_WINDOW_SECS)
}
pub fn identity_rate_max() -> u32 {
    if crate::activation::network_id_byte() == 0 {
        return IDENTITY_RATE_MAX;
    }
    std::env::var("IRIUM_POAWX_IDENTITY_RATE_MAX")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(IDENTITY_RATE_MAX)
}

struct IdentityRate {
    window_start: std::time::Instant,
    count: u32,
}

fn identity_rate_map() -> &'static Mutex<BTreeMap<[u8; 20], IdentityRate>> {
    static M: OnceLock<Mutex<BTreeMap<[u8; 20], IdentityRate>>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Monotonic (`Instant`) sliding window per identity. Deliberately NOT the generic
/// `rate_limiter::RateLimiter`, which is keyed on wall-clock `SystemTime` -- a clock
/// jump would reset every bucket.
pub fn identity_rate_allowed(solver_pkh: &[u8; 20]) -> bool {
    let now = std::time::Instant::now();
    let window = std::time::Duration::from_secs(identity_rate_window_secs());
    let mut m = identity_rate_map().lock().unwrap_or_else(|e| e.into_inner());
    if m.len() > 8192 {
        m.retain(|_, r| now.duration_since(r.window_start) < window);
    }
    let e = m.entry(*solver_pkh).or_insert(IdentityRate {
        window_start: now,
        count: 0,
    });
    if now.duration_since(e.window_start) >= window {
        e.window_start = now;
        e.count = 0;
    }
    e.count = e.count.saturating_add(1);
    e.count <= identity_rate_max()
}

/// Test observability: how many times a bundle actually reached VALIDATION. Lets a test
/// assert that a tier-1 rejection never paid the validation cost, rather than inferring it.
pub static VALIDATIONS_PERFORMED: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// R2: whether the submission endpoint accepts non-loopback sources. Default OFF --
/// an operator must deliberately opt in. Ships inert.
pub fn role_bundle_public_submission_enabled() -> bool {
    std::env::var("IRIUM_POAWX_ROLE_BUNDLE_PUBLIC")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}

static GLOBAL_ROLE_BUNDLE_POOL: OnceLock<NodeRoleBundlePool> = OnceLock::new();

pub fn global_role_bundle_pool() -> &'static NodeRoleBundlePool {
    GLOBAL_ROLE_BUNDLE_POOL.get_or_init(NodeRoleBundlePool::default)
}

/// C3: the assembled contributor set a builder would use — the best collected worker
/// for each contributor role at `height`. Returns `None` for a role with no collected
/// bundle, so a builder can fall back to its own identity for that role and remain
/// byte-identical to today's behaviour when nothing has been collected.
#[derive(Debug, Clone, Default)]
pub struct CollectedRoles {
    pub compute: Option<RoleBundleV1>,
    pub verify: Option<RoleBundleV1>,
    pub support: Option<RoleBundleV1>,
}

impl CollectedRoles {
    pub fn distinct_payees(&self) -> usize {
        let mut s = std::collections::BTreeSet::new();
        for b in [&self.compute, &self.verify, &self.support].into_iter().flatten() {
            s.insert(b.solver_pkh);
        }
        s.len()
    }
    pub fn is_empty(&self) -> bool {
        self.compute.is_none() && self.verify.is_none() && self.support.is_none()
    }
}

pub fn collect_roles_for_height(height: u64) -> CollectedRoles {
    let p = global_role_bundle_pool();
    CollectedRoles {
        compute: p.best_for_role(crate::poawx::ROLE_COMPUTE_CONTRIBUTOR, height),
        verify: p.best_for_role(crate::poawx::ROLE_VERIFY_CONTRIBUTOR, height),
        support: p.best_for_role(crate::poawx::ROLE_SUPPORT_CONTRIBUTOR, height),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poawx::{ROLE_COMPUTE_CONTRIBUTOR, ROLE_SUPPORT_CONTRIBUTOR, ROLE_VERIFY_CONTRIBUTOR};

    const NET: u8 = 2; // devnet
    const H: u64 = 42;
    const SEED: [u8; 32] = [0x5Au8; 32];
    const PARENT: [u8; 32] = [0x11u8; 32];

    /// Build a genuinely valid bundle for `secret` in `role`, in the exact JSON shape
    /// `poawx-role-worker` emits, so the fixture exercises the real parser.
    pub(super) fn bundle_json(secret_byte: u8, role: u8) -> String {
        bundle_json_at(secret_byte, role, H)
    }

    fn bundle_json_at(secret_byte: u8, role: u8, height: u64) -> String {
        let secret = [secret_byte; 32];
        let proof = AssignmentProofV2::prove_self_solver(&secret, NET, height, role, [0u8; 32], SEED)
            .expect("prove");
        let pkh = proof.solver_pkh;
        let apk = proof.assignment_public_key;
        let ticket = TicketProof::new(
            NET, height, PARENT, role, pkh, height, height + 100, apk, [0x22u8; 32], 0,
        );
        let sol = PuzzleSolutionV1 { mode: 0, nonce: 7, proof_digest: [0x33u8; 32] };
        // R4: a SUPPORT bundle must carry the worker's own signed finality vote.
        let fv = if role == crate::poawx::ROLE_SUPPORT_CONTRIBUTOR {
            let sk = k256::ecdsa::SigningKey::from_bytes((&secret).into()).unwrap();
            Some(hex::encode(
                crate::poawx_finality::FinalityVoteV1::signed(
                    &sk,
                    NET,
                    height,
                    PARENT,
                    [0u8; 32],
                    0,
                    ticket.ticket_digest,
                    crate::poawx_finality::FinalityVoteType::Commit,
                )
                .serialize(),
            ))
        } else {
            None
        };
        serde_json::json!({
            "network_id": NET, "target_height": height, "role_id": role, "role": "compute",
            "solver_pkh": hex::encode(pkh),
            "assignment_public_key": hex::encode(apk),
            "assignment_proof": hex::encode(proof.serialize()),
            "ticket_proof": hex::encode(ticket.serialize()),
            "puzzle_solution": hex::encode(sol.serialize()),
            "claim": {
                "lane_id": 1u8,
                "secret": hex::encode([0x44u8; 32]),
                "nonce": hex::encode([0x55u8; 32]),
                "commitment_hash": hex::encode([0x66u8; 32]),
                "claim_digest": hex::encode([0x77u8; 32]),
            },
            "finality_vote": fv,
        })
        .to_string()
    }

    #[test]
    fn valid_bundle_parses_and_validates() {
        let _env = crate::test_env::guard();
        let b = RoleBundleV1::from_json(&bundle_json(0x01, ROLE_COMPUTE_CONTRIBUTOR)).expect("parse");
        b.validate(NET, H, Some(SEED), None).expect("must validate");
        // and the payout binding genuinely holds
        assert_eq!(b.solver_pkh, hash160(&b.assignment_public_key));
    }

    /// Each rejection asserts the SPECIFIC error, not merely that something failed --
    /// a test that accepts any error passes for the wrong reason.
    #[test]
    fn each_malformation_is_rejected_with_its_own_reason() {
        let _env = crate::test_env::guard();
        let ok = RoleBundleV1::from_json(&bundle_json(0x02, ROLE_COMPUTE_CONTRIBUTOR)).unwrap();

        let mut b = ok.clone();
        b.network_id = NET + 1;
        assert!(b.validate(NET, H, None, None).unwrap_err().contains("wrong network"));

        let mut b = ok.clone();
        b.target_height = H + 1;
        assert!(b.validate(NET, H, None, None).unwrap_err().contains("wrong height"));

        let mut b = ok.clone();
        b.role_id = crate::poawx_proposer::ROLE_PROPOSER;
        assert!(b
            .validate(NET, H, None, None)
            .unwrap_err()
            .contains("not a collectable contributor role"));

        // THE PAYOUT BINDING -- the rule that makes a bundle payable at all.
        let mut b = ok.clone();
        b.solver_pkh[0] ^= 0xff;
        assert!(b
            .validate(NET, H, None, None)
            .unwrap_err()
            .contains("solver pkh not derived from assignment key"));

        let mut b = ok.clone();
        b.assignment_proof.role_id = ROLE_VERIFY_CONTRIBUTOR;
        assert!(b
            .validate(NET, H, None, None)
            .unwrap_err()
            .contains("assignment proof role mismatch"));

        let mut b = ok.clone();
        assert!(b
            .validate(NET, H, Some([0x00u8; 32]), None)
            .unwrap_err()
            .contains("wrong seed"));
        let _ = &mut b;

        // a tampered ECVRF proof must fail the curve check, not slip through
        let mut b = ok.clone();
        b.assignment_proof.vrf_output[0] ^= 0xff;
        assert!(b.validate(NET, H, Some(SEED), None).is_err());
    }

    #[test]
    fn pool_keeps_best_per_role_and_prunes_on_height_advance() {
        let _env = crate::test_env::guard();
        let pool = NodeRoleBundlePool::default();
        let a = RoleBundleV1::from_json(&bundle_json(0x03, ROLE_COMPUTE_CONTRIBUTOR)).unwrap();
        let b = RoleBundleV1::from_json(&bundle_json(0x04, ROLE_COMPUTE_CONTRIBUTOR)).unwrap();
        assert_eq!(pool.ingest(a.clone(), NET, H, Some(SEED), None).unwrap(), BundleOutcome::AcceptedNew);
        assert_eq!(pool.ingest(b.clone(), NET, H, Some(SEED), None).unwrap(), BundleOutcome::AcceptedNew);
        // two DISTINCT competitors for the same role are both held; best_for_role picks
        // the higher self-VRF score, matching on-chain best_for_role ordering.
        let best = pool.best_for_role(ROLE_COMPUTE_CONTRIBUTOR, H).unwrap();
        let expect = if a.score() >= b.score() { &a } else { &b };
        assert_eq!(best.solver_pkh, expect.solver_pkh);
        assert_eq!(pool.len(), 2);
        // resubmitting the same worker is a duplicate, not growth
        assert_eq!(pool.ingest(a.clone(), NET, H, Some(SEED), None).unwrap(), BundleOutcome::Duplicate);
        assert_eq!(pool.len(), 2);
        // A bundle genuinely targeting an OLDER height is refused as stale. Note the
        // bundle must really be for H-1: validate() checks target_height first, so
        // submitting an H-bundle as H-1 fails earlier with "wrong height" instead --
        // which is what an earlier version of this test asserted, and it would have
        // passed while never exercising the stale branch at all.
        let old_b = RoleBundleV1::from_json(&bundle_json_at(0x03, ROLE_COMPUTE_CONTRIBUTOR, H - 1))
            .unwrap();
        assert!(pool
            .ingest(old_b, NET, H - 1, Some(SEED), None)
            .unwrap_err()
            .contains("stale height"));
        // advancing the height clears everything: bundles are height-bound
        pool.prune_below(H + 1);
        assert_eq!(pool.len(), 0);
        assert!(pool.best_for_role(ROLE_COMPUTE_CONTRIBUTOR, H).is_none());
    }

    #[test]
    fn collect_roles_reports_distinct_payees() {
        let _env = crate::test_env::guard();
        let pool = NodeRoleBundlePool::default();
        for (sk, role) in [
            (0x05u8, ROLE_COMPUTE_CONTRIBUTOR),
            (0x06, ROLE_VERIFY_CONTRIBUTOR),
            (0x07, ROLE_SUPPORT_CONTRIBUTOR),
        ] {
            let b = RoleBundleV1::from_json(&bundle_json(sk, role)).unwrap();
            pool.ingest(b, NET, H, Some(SEED), None).unwrap();
        }
        let c = CollectedRoles {
            compute: pool.best_for_role(ROLE_COMPUTE_CONTRIBUTOR, H),
            verify: pool.best_for_role(ROLE_VERIFY_CONTRIBUTOR, H),
            support: pool.best_for_role(ROLE_SUPPORT_CONTRIBUTOR, H),
        };
        assert_eq!(c.distinct_payees(), 3, "three distinct workers collected");
        assert!(!c.is_empty());
    }

    #[test]
    fn empty_pool_yields_no_collected_roles_so_builders_are_unchanged() {
        let _env = crate::test_env::guard();
        let c = collect_roles_for_height(u64::MAX); // nothing ever ingested at this height
        assert!(c.is_empty());
        assert_eq!(c.distinct_payees(), 0);
    }
}

#[cfg(test)]
mod r1_r2_r3_tests {
    use super::*;
    use crate::poawx::ROLE_COMPUTE_CONTRIBUTOR;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::Ordering;

    const NET: u8 = 2;
    const H: u64 = 42;
    const SEED: [u8; 32] = [0x5Au8; 32];

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    fn valid_bundle(secret_byte: u8) -> RoleBundleV1 {
        RoleBundleV1::from_json(&super::tests::bundle_json(
            secret_byte,
            ROLE_COMPUTE_CONTRIBUTOR,
        ))
        .expect("parse")
    }

    /// R1 ORDERING -- the load-bearing property. A tier-1 (source) rejection must
    /// short-circuit BEFORE validation, so a flood never buys an ECVRF verify. Asserted
    /// directly against a validation counter rather than inferred from timing.
    #[test]
    fn tier1_rejection_never_reaches_validation() {
        let _env = crate::test_env::guard();
        let pool = NodeRoleBundlePool::default();
        let src = ip(11);
        let b = valid_bundle(0x21);
        // Exhaust tier 1 for this source.
        let mut exhausted = false;
        for _ in 0..10_000 {
            if pool
                .ingest_tiered(src, b.clone(), NET, H, Some(SEED), None)
                .err()
                .map(|e| e.contains("source rate limited"))
                .unwrap_or(false)
            {
                exhausted = true;
                break;
            }
        }
        assert!(exhausted, "tier 1 never engaged; the limiter is not wired");
        // With tier 1 now rejecting, validation must NOT run.
        let before = VALIDATIONS_PERFORMED.load(Ordering::Relaxed);
        let err = pool
            .ingest_tiered(src, b, NET, H, Some(SEED), None)
            .expect_err("must still be source-limited");
        assert!(err.contains("source rate limited"), "got: {err}");
        assert_eq!(
            VALIDATIONS_PERFORMED.load(Ordering::Relaxed),
            before,
            "a tier-1 rejection paid for validation -- the tiers are in the wrong order"
        );
    }

    /// R1 INDEPENDENCE -- the identity limiter must bite even when every request comes
    /// from a FRESH source, which is exactly the aggregator case: one pool relaying for
    /// many workers, or one worker spread across many addresses.
    #[test]
    fn identity_limit_engages_independently_of_source_limit() {
        let _env = crate::test_env::guard();
        let pool = NodeRoleBundlePool::default();
        let b = valid_bundle(0x22);
        let mut identity_limited = false;
        // A different source every time, so tier 1 is always fresh.
        for i in 0..(IDENTITY_RATE_MAX + 4) {
            let r = pool.ingest_tiered(ip(100 + i as u8), b.clone(), NET, H, Some(SEED), None);
            if let Err(e) = r {
                if e.contains("identity rate limited") {
                    identity_limited = true;
                    break;
                }
            }
        }
        assert!(
            identity_limited,
            "identity limiting never engaged across distinct sources -- one identity can \
             monopolise pool slots by rotating addresses"
        );
    }

    /// The identity limiter must be per identity, not global: a DIFFERENT worker is
    /// unaffected by another's exhaustion.
    #[test]
    fn identity_limit_is_per_identity_not_global() {
        let _env = crate::test_env::guard();
        let pool = NodeRoleBundlePool::default();
        let noisy = valid_bundle(0x23);
        for i in 0..(IDENTITY_RATE_MAX + 4) {
            let _ = pool.ingest_tiered(ip(150 + i as u8), noisy.clone(), NET, H, Some(SEED), None);
        }
        let quiet = valid_bundle(0x24);
        let r = pool.ingest_tiered(ip(200), quiet, NET, H, Some(SEED), None);
        assert!(
            !matches!(&r, Err(e) if e.contains("identity rate limited")),
            "a quiet worker was limited because a different one flooded: {r:?}"
        );
    }

    /// R2 -- public submission is OFF unless an operator opts in. Default loopback.
    #[test]
    fn public_submission_defaults_off_and_is_opt_in() {
        let _env = crate::test_env::guard();
        std::env::remove_var("IRIUM_POAWX_ROLE_BUNDLE_PUBLIC");
        assert!(
            !role_bundle_public_submission_enabled(),
            "public submission must default OFF"
        );
        std::env::set_var("IRIUM_POAWX_ROLE_BUNDLE_PUBLIC", "1");
        assert!(role_bundle_public_submission_enabled());
        std::env::set_var("IRIUM_POAWX_ROLE_BUNDLE_PUBLIC", "0");
        assert!(!role_bundle_public_submission_enabled(), "only \"1\" enables it");
        std::env::remove_var("IRIUM_POAWX_ROLE_BUNDLE_PUBLIC");
    }
}

#[cfg(test)]
mod r4_finality_vote_tests {
    use super::*;
    use crate::poawx::{ROLE_COMPUTE_CONTRIBUTOR, ROLE_SUPPORT_CONTRIBUTOR};
    use crate::poawx_finality::{FinalityVoteType, FinalityVoteV1};

    const NET: u8 = 2;
    const H: u64 = 42;
    const SEED: [u8; 32] = [0x5Au8; 32];
    const PARENT: [u8; 32] = [0x11u8; 32];

    fn support_bundle(b: u8) -> RoleBundleV1 {
        RoleBundleV1::from_json(&super::tests::bundle_json(b, ROLE_SUPPORT_CONTRIBUTOR))
            .expect("parse")
    }

    #[test]
    fn valid_support_bundle_with_its_own_vote_validates() {
        let _env = crate::test_env::guard();
        let b = support_bundle(0x31);
        b.validate(NET, H, Some(SEED), Some(PARENT))
            .expect("SUPPORT bundle with its own vote must validate");
        let v = b.finality_vote.as_ref().expect("vote present");
        assert_eq!(v.member_pkh, b.solver_pkh, "the voter IS the paid worker");
    }

    /// Each malformation asserts its SPECIFIC error. A test that accepts any error
    /// passes for the wrong reason.
    #[test]
    fn each_vote_malformation_is_rejected_with_its_own_reason() {
        let _env = crate::test_env::guard();
        let ok = support_bundle(0x32);

        // SUPPORT without a vote at all
        let mut b = ok.clone();
        b.finality_vote = None;
        assert!(b
            .validate(NET, H, Some(SEED), Some(PARENT))
            .unwrap_err()
            .contains("SUPPORT bundle missing its finality vote"));

        // a non-SUPPORT role carrying one
        let mut b = RoleBundleV1::from_json(&super::tests::bundle_json(
            0x33,
            ROLE_COMPUTE_CONTRIBUTOR,
        ))
        .unwrap();
        b.finality_vote = ok.finality_vote.clone();
        assert!(b
            .validate(NET, H, Some(SEED), Some(PARENT))
            .unwrap_err()
            .contains("finality vote on a non-SUPPORT role"));

        // bad signature
        let mut b = ok.clone();
        b.finality_vote.as_mut().unwrap().signature[0] ^= 0xff;
        assert!(b
            .validate(NET, H, Some(SEED), Some(PARENT))
            .unwrap_err()
            .contains("finality vote"));

        // member_pkh not derived from member_pubkey
        let mut b = ok.clone();
        b.finality_vote.as_mut().unwrap().member_pkh[0] ^= 0xff;
        assert!(b
            .validate(NET, H, Some(SEED), Some(PARENT))
            .unwrap_err()
            .contains("member pkh not derived from its pubkey"));

        // member_pkh valid but belonging to a DIFFERENT worker than the payee
        let other = support_bundle(0x34);
        let mut b = ok.clone();
        b.finality_vote = other.finality_vote.clone();
        assert!(b
            .validate(NET, H, Some(SEED), Some(PARENT))
            .unwrap_err()
            .contains("member pkh != solver pkh"));

        // wrong height
        let mut b = ok.clone();
        b.finality_vote.as_mut().unwrap().target_height = H + 1;
        assert!(b
            .validate(NET, H, Some(SEED), Some(PARENT))
            .unwrap_err()
            .contains("finality vote wrong height"));

        // wrong parent block hash
        let mut b = ok.clone();
        b.finality_vote.as_mut().unwrap().block_hash = [0x99u8; 32];
        assert!(b
            .validate(NET, H, Some(SEED), Some(PARENT))
            .unwrap_err()
            .contains("wrong parent block hash"));

        // wrong vote type
        let mut b = ok.clone();
        b.finality_vote.as_mut().unwrap().vote_type =
            FinalityVoteType::Commit.id().wrapping_add(1);
        assert!(b
            .validate(NET, H, Some(SEED), Some(PARENT))
            .unwrap_err()
            .contains("not a Commit"));

        // THE FLAGGED BUG SITE: ticket_digest unbound from the worker's real ticket.
        // The chain does NOT enforce this -- FinalityProofV1::validate never cross-checks
        // it -- so a vote with a foreign ticket digest still verifies cryptographically.
        // Ingest binds it so a collected bundle is coherent, not merely self-consistent.
        let mut b = ok.clone();
        let sk = k256::ecdsa::SigningKey::from_bytes(&[0x32u8; 32].into()).unwrap();
        b.finality_vote = Some(FinalityVoteV1::signed(
            &sk, NET, H, PARENT, [0u8; 32], 0, [0xEEu8; 32], FinalityVoteType::Commit,
        ));
        let e = b.validate(NET, H, Some(SEED), Some(PARENT)).unwrap_err();
        assert!(
            e.contains("ticket digest != bundle ticket"),
            "a validly-signed vote over a FOREIGN ticket digest must still be rejected; got: {e}"
        );
    }
}
