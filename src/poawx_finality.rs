//! Phase 21H: PoAW-X finality-committee votes + proofs for the 10% SUPPORT/finality
//! role.
//!
//! A finality committee = the SUPPORT-role candidates (role id 3) admitted/selected
//! via the existing Phase 21D/21E candidate path. Each committee member signs a
//! `FinalityVoteV1` (real **secp256k1 ECDSA** over a domain-separated vote digest —
//! the same signing primitive used by `Delegation`), and a `FinalityProofV1` bundles
//! a threshold of votes finalizing a block. Deterministic, bounded, no floats, no
//! network/wall-clock in verification. Gated + mainnet-ACTIVE at height >= 50_000; does NOT touch chain
//! PoW / LWMA-144.
//!
//! The proof in a block finalizes the block's PARENT (`block_hash = the carrying
//! block's prev_hash`), so votes are over an already-known hash (no circularity).
//!
//! ⚠ MAINNET STATUS (corrected 2026-07-19): this module's gates are NOT "mainnet
//! hard-off". They route through `activation::poawx_effective_activation`, which on
//! `network_id == 0` IGNORES the env and substitutes the compiled
//! `MAINNET_POAWX_ACTIVATION_HEIGHT = Some(50_000)`. Mainnet is far past that height,
//! so these gates are ACTIVE in production. Any remaining "mainnet hard-off" wording
//! below is stale. The authoritative, height-accurate check is
//! `activation::mainnet_gate_truth`.
#![allow(dead_code)]

use sha2::{Digest, Sha256};

use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::activation::network_id_byte;
use crate::poawx_gossip::GossipOutcome;

const VOTE_DOMAIN: &[u8] = b"IRIUM_POAWX_FINALITY_VOTE_V1";
const PROOF_DOMAIN: &[u8] = b"IRIUM_POAWX_FINALITY_PROOF_V1";

/// 4-byte trailing-section magic for the finality proof in the Phase 20 ext.
pub const FINALITY_SECTION_MAGIC: &[u8; 4] = b"FIN1";
pub const FINALITY_VOTE_VERSION: u8 = 1;
pub const FINALITY_PROOF_VERSION: u8 = 1;
/// Wire size of one `FinalityVoteV1`.
pub const FINALITY_VOTE_WIRE: usize = 1 + 1 + 8 + 32 + 32 + 8 + 20 + 33 + 32 + 1 + 64; // 232
/// Proof header: version+net+height+block+parent+epoch+num+den+count.
const FINALITY_PROOF_HEADER: usize = 1 + 1 + 8 + 32 + 32 + 8 + 2 + 2 + 2; // 88
/// Bound on votes in a proof (anti-oversize).
pub const FINALITY_MAX_VOTES: usize = 256;

/// Finality vote phase. Only `Commit` votes count toward the finalization
/// threshold; Precommit/Checkpoint are bound + verified but informational here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalityVoteType {
    Precommit,
    Commit,
    Checkpoint,
}
impl FinalityVoteType {
    pub fn id(self) -> u8 {
        match self {
            FinalityVoteType::Precommit => 0,
            FinalityVoteType::Commit => 1,
            FinalityVoteType::Checkpoint => 2,
        }
    }
    pub fn from_id(b: u8) -> Option<Self> {
        Some(match b {
            0 => FinalityVoteType::Precommit,
            1 => FinalityVoteType::Commit,
            2 => FinalityVoteType::Checkpoint,
            _ => return None,
        })
    }
}

fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let rip = ripemd::Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&rip);
    out
}

/// One finality-committee vote (SUPPORT role member, secp256k1-signed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalityVoteV1 {
    pub version: u8,
    pub network_id: u8,
    pub target_height: u64,
    pub block_hash: [u8; 32],
    pub parent_hash: [u8; 32],
    pub committee_epoch: u64,
    pub member_pkh: [u8; 20],
    pub member_pubkey: [u8; 33],
    pub ticket_digest: [u8; 32],
    pub vote_type: u8,
    pub signature: [u8; 64],
}

#[allow(clippy::too_many_arguments)]
fn vote_digest(
    network_id: u8,
    target_height: u64,
    block_hash: &[u8; 32],
    parent_hash: &[u8; 32],
    committee_epoch: u64,
    member_pkh: &[u8; 20],
    ticket_digest: &[u8; 32],
    vote_type: u8,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(VOTE_DOMAIN);
    h.update([FINALITY_VOTE_VERSION]);
    h.update([network_id]);
    h.update(target_height.to_le_bytes());
    h.update(block_hash);
    h.update(parent_hash);
    h.update(committee_epoch.to_le_bytes());
    h.update(member_pkh);
    h.update(ticket_digest);
    h.update([vote_type]);
    h.finalize().into()
}

impl FinalityVoteV1 {
    /// Build + sign a vote with the member's secp256k1 key (member_pkh derived from
    /// the verifying key). No secret key material is retained in the vote.
    #[allow(clippy::too_many_arguments)]
    pub fn signed(
        sk: &SigningKey,
        network_id: u8,
        target_height: u64,
        block_hash: [u8; 32],
        parent_hash: [u8; 32],
        committee_epoch: u64,
        ticket_digest: [u8; 32],
        vote_type: FinalityVoteType,
    ) -> Self {
        let vk = sk.verifying_key();
        let enc = vk.to_encoded_point(true);
        let mut member_pubkey = [0u8; 33];
        member_pubkey.copy_from_slice(enc.as_bytes());
        let member_pkh = hash160(&member_pubkey);
        let digest = vote_digest(
            network_id,
            target_height,
            &block_hash,
            &parent_hash,
            committee_epoch,
            &member_pkh,
            &ticket_digest,
            vote_type.id(),
        );
        let sig: Signature = sk.sign_prehash(&digest).expect("sign vote");
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&sig.to_bytes());
        Self {
            version: FINALITY_VOTE_VERSION,
            network_id,
            target_height,
            block_hash,
            parent_hash,
            committee_epoch,
            member_pkh,
            member_pubkey,
            ticket_digest,
            vote_type: vote_type.id(),
            signature,
        }
    }

    pub fn digest(&self) -> [u8; 32] {
        vote_digest(
            self.network_id,
            self.target_height,
            &self.block_hash,
            &self.parent_hash,
            self.committee_epoch,
            &self.member_pkh,
            &self.ticket_digest,
            self.vote_type,
        )
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(FINALITY_VOTE_WIRE);
        o.push(self.version);
        o.push(self.network_id);
        o.extend_from_slice(&self.target_height.to_le_bytes());
        o.extend_from_slice(&self.block_hash);
        o.extend_from_slice(&self.parent_hash);
        o.extend_from_slice(&self.committee_epoch.to_le_bytes());
        o.extend_from_slice(&self.member_pkh);
        o.extend_from_slice(&self.member_pubkey);
        o.extend_from_slice(&self.ticket_digest);
        o.push(self.vote_type);
        o.extend_from_slice(&self.signature);
        o
    }

    pub fn deserialize(raw: &[u8]) -> Result<Self, String> {
        if raw.len() != FINALITY_VOTE_WIRE {
            return Err("finality vote: bad length".to_string());
        }
        let mut p = 0usize;
        let take = |p: &mut usize, n: usize| -> Vec<u8> {
            let v = raw[*p..*p + n].to_vec();
            *p += n;
            v
        };
        let version = raw[p];
        p += 1;
        let network_id = raw[p];
        p += 1;
        let mut h8 = [0u8; 8];
        h8.copy_from_slice(&take(&mut p, 8));
        let target_height = u64::from_le_bytes(h8);
        let mut block_hash = [0u8; 32];
        block_hash.copy_from_slice(&take(&mut p, 32));
        let mut parent_hash = [0u8; 32];
        parent_hash.copy_from_slice(&take(&mut p, 32));
        h8.copy_from_slice(&take(&mut p, 8));
        let committee_epoch = u64::from_le_bytes(h8);
        let mut member_pkh = [0u8; 20];
        member_pkh.copy_from_slice(&take(&mut p, 20));
        let mut member_pubkey = [0u8; 33];
        member_pubkey.copy_from_slice(&take(&mut p, 33));
        let mut ticket_digest = [0u8; 32];
        ticket_digest.copy_from_slice(&take(&mut p, 32));
        let vote_type = raw[p];
        p += 1;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&take(&mut p, 64));
        Ok(Self {
            version,
            network_id,
            target_height,
            block_hash,
            parent_hash,
            committee_epoch,
            member_pkh,
            member_pubkey,
            ticket_digest,
            vote_type,
            signature,
        })
    }

    /// Verify the vote binds to (network, height, block_hash) and the signature is a
    /// valid secp256k1 signature by `member_pubkey` (whose HASH160 == member_pkh).
    pub fn verify(
        &self,
        network_id: u8,
        target_height: u64,
        block_hash: &[u8; 32],
    ) -> Result<(), String> {
        if self.version != FINALITY_VOTE_VERSION {
            return Err("finality vote: bad version".to_string());
        }
        if self.network_id != network_id {
            return Err("finality vote: wrong network".to_string());
        }
        if self.target_height != target_height {
            return Err("finality vote: wrong height".to_string());
        }
        if &self.block_hash != block_hash {
            return Err("finality vote: wrong block hash".to_string());
        }
        if FinalityVoteType::from_id(self.vote_type).is_none() {
            return Err("finality vote: bad vote type".to_string());
        }
        if hash160(&self.member_pubkey) != self.member_pkh {
            return Err("finality vote: pubkey/pkh mismatch".to_string());
        }
        let vk = VerifyingKey::from_sec1_bytes(&self.member_pubkey)
            .map_err(|_| "finality vote: bad pubkey".to_string())?;
        let sig = Signature::from_slice(&self.signature)
            .map_err(|_| "finality vote: bad signature encoding".to_string())?;
        vk.verify_prehash(&self.digest(), &sig)
            .map_err(|_| "finality vote: signature verification failed".to_string())
    }
}

/// A bundled, threshold finality proof finalizing `block_hash` (= the carrying
/// block's parent). Votes are canonical (sorted by member_pkh, deduped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalityProofV1 {
    pub version: u8,
    pub network_id: u8,
    pub target_height: u64,
    pub block_hash: [u8; 32],
    pub parent_hash: [u8; 32],
    pub committee_epoch: u64,
    pub threshold_num: u16,
    pub threshold_den: u16,
    pub votes: Vec<FinalityVoteV1>,
}

impl FinalityProofV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network_id: u8,
        target_height: u64,
        block_hash: [u8; 32],
        parent_hash: [u8; 32],
        committee_epoch: u64,
        threshold_num: u16,
        threshold_den: u16,
    ) -> Self {
        Self {
            version: FINALITY_PROOF_VERSION,
            network_id,
            target_height,
            block_hash,
            parent_hash,
            committee_epoch,
            threshold_num,
            threshold_den,
            votes: Vec::new(),
        }
    }
    pub fn push(&mut self, v: FinalityVoteV1) {
        self.votes.push(v);
    }
    pub fn sort_canonical(&mut self) {
        self.votes.sort_by(|a, b| {
            a.member_pkh
                .cmp(&b.member_pkh)
                .then_with(|| a.vote_type.cmp(&b.vote_type))
        });
    }
    pub fn is_canonical(&self) -> bool {
        for w in self.votes.windows(2) {
            // strictly increasing member_pkh => no duplicate member.
            if w[0].member_pkh >= w[1].member_pkh {
                return false;
            }
        }
        true
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut o =
            Vec::with_capacity(FINALITY_PROOF_HEADER + self.votes.len() * FINALITY_VOTE_WIRE);
        o.push(self.version);
        o.push(self.network_id);
        o.extend_from_slice(&self.target_height.to_le_bytes());
        o.extend_from_slice(&self.block_hash);
        o.extend_from_slice(&self.parent_hash);
        o.extend_from_slice(&self.committee_epoch.to_le_bytes());
        o.extend_from_slice(&self.threshold_num.to_le_bytes());
        o.extend_from_slice(&self.threshold_den.to_le_bytes());
        o.extend_from_slice(&(self.votes.len() as u16).to_le_bytes());
        for v in &self.votes {
            o.extend_from_slice(&v.serialize());
        }
        o
    }

    pub fn deserialize(raw: &[u8]) -> Result<Self, String> {
        if raw.len() < FINALITY_PROOF_HEADER {
            return Err("finality proof: truncated header".to_string());
        }
        let version = raw[0];
        let network_id = raw[1];
        let mut p = 2usize;
        let mut h8 = [0u8; 8];
        h8.copy_from_slice(&raw[p..p + 8]);
        let target_height = u64::from_le_bytes(h8);
        p += 8;
        let mut block_hash = [0u8; 32];
        block_hash.copy_from_slice(&raw[p..p + 32]);
        p += 32;
        let mut parent_hash = [0u8; 32];
        parent_hash.copy_from_slice(&raw[p..p + 32]);
        p += 32;
        h8.copy_from_slice(&raw[p..p + 8]);
        let committee_epoch = u64::from_le_bytes(h8);
        p += 8;
        let threshold_num = u16::from_le_bytes([raw[p], raw[p + 1]]);
        p += 2;
        let threshold_den = u16::from_le_bytes([raw[p], raw[p + 1]]);
        p += 2;
        let count = u16::from_le_bytes([raw[p], raw[p + 1]]) as usize;
        p += 2;
        if count > FINALITY_MAX_VOTES {
            return Err("finality proof: too many votes".to_string());
        }
        if raw.len() != p + count * FINALITY_VOTE_WIRE {
            return Err("finality proof: bad length".to_string());
        }
        let mut votes = Vec::with_capacity(count);
        for _ in 0..count {
            votes.push(FinalityVoteV1::deserialize(
                &raw[p..p + FINALITY_VOTE_WIRE],
            )?);
            p += FINALITY_VOTE_WIRE;
        }
        Ok(Self {
            version,
            network_id,
            target_height,
            block_hash,
            parent_hash,
            committee_epoch,
            threshold_num,
            threshold_den,
            votes,
        })
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(PROOF_DOMAIN);
        h.update(self.serialize());
        h.finalize().into()
    }

    /// Number of Commit votes required for `committee_size` under num/den
    /// (deterministic integer ceil; clamped to >= 1 and <= committee_size).
    pub fn required_votes(&self, committee_size: usize) -> usize {
        if committee_size == 0 {
            return 0;
        }
        let num = self.threshold_num.max(1) as usize;
        let den = self.threshold_den.max(1) as usize;
        let needed = (committee_size * num + den - 1) / den;
        needed.clamp(1, committee_size)
    }

    /// Validate the proof finalizes `block_hash` at `target_height` on `network_id`
    /// with committee `committee` (allowed member pkhs): canonical, every vote
    /// verifies + binds + is a committee member + same epoch, and the number of
    /// valid **Commit** votes meets the threshold. Deterministic.
    pub fn validate(
        &self,
        network_id: u8,
        target_height: u64,
        block_hash: &[u8; 32],
        committee: &[[u8; 20]],
    ) -> Result<(), String> {
        if self.version != FINALITY_PROOF_VERSION {
            return Err("finality proof: bad version".to_string());
        }
        if self.network_id != network_id {
            return Err("finality proof: wrong network".to_string());
        }
        if self.target_height != target_height {
            return Err("finality proof: wrong height".to_string());
        }
        if &self.block_hash != block_hash {
            return Err("finality proof: wrong block hash".to_string());
        }
        if !self.is_canonical() {
            return Err("finality proof: not canonical / duplicate member".to_string());
        }
        if committee.is_empty() {
            return Err("finality proof: empty committee".to_string());
        }
        let mut commit_votes = 0usize;
        for v in &self.votes {
            v.verify(network_id, target_height, block_hash)?;
            if &v.block_hash != block_hash || v.committee_epoch != self.committee_epoch {
                return Err("finality proof: vote context mismatch".to_string());
            }
            if !committee.contains(&v.member_pkh) {
                return Err("finality proof: vote from non-committee member".to_string());
            }
            if v.vote_type == FinalityVoteType::Commit.id() {
                commit_votes += 1;
            }
        }
        let needed = self.required_votes(committee.len());
        if commit_votes < needed {
            return Err(format!(
                "finality proof: insufficient commit votes {}/{}",
                commit_votes, needed
            ));
        }
        Ok(())
    }
}

// ── Gates (param-driven; mainnet-ACTIVE at height >= 50_000) ───────────────────────────────────

pub fn finality_committee_activation_height() -> Option<u64> {
    std::env::var("IRIUM_POAWX_FINALITY_COMMITTEE_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}
pub fn finality_committee_required() -> bool {
    if crate::activation::network_id_byte() == 0 {
        return true; // mainnet: enforced once the gate is active (height-gated)
    }
    std::env::var("IRIUM_POAWX_FINALITY_COMMITTEE_REQUIRED")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}
/// Pure resolution of the (num, den) finality threshold from optional, already
/// parsed env values. Applies the `>= 1` floor and the **2/3 supermajority
/// default** (Gap 7). Param-driven so tests need not mutate global env (mirrors
/// the `anti_domination_gate` / `penalty_gate` pure-helper pattern).
pub fn finality_threshold_values(num: Option<u16>, den: Option<u16>) -> (u16, u16) {
    let num = num.filter(|n| *n >= 1).unwrap_or(2);
    let den = den.filter(|d| *d >= 1).unwrap_or(3);
    (num, den)
}

/// Threshold (num, den), default **2/3** (supermajority of the present committee).
/// Tunable only behind the testnet/devnet gate via
/// `IRIUM_POAWX_FINALITY_THRESHOLD_{NUM,DEN}`.
pub fn finality_threshold() -> (u16, u16) {
    let num = std::env::var("IRIUM_POAWX_FINALITY_THRESHOLD_NUM")
        .ok()
        .and_then(|v| v.trim().parse::<u16>().ok());
    let den = std::env::var("IRIUM_POAWX_FINALITY_THRESHOLD_DEN")
        .ok()
        .and_then(|v| v.trim().parse::<u16>().ok());
    finality_threshold_values(num, den)
}
pub fn finality_committee_gate(network_id: u8, activation: Option<u64>, height: u64) -> bool {
    matches!(crate::activation::poawx_effective_activation(network_id, activation), Some(h) if height >= h)
}
pub fn finality_committee_enforced_gate(
    network_id: u8,
    activation: Option<u64>,
    required: bool,
    height: u64,
) -> bool {
    finality_committee_gate(network_id, activation, height) && required
}
pub fn finality_committee_active(height: u64) -> bool {
    finality_committee_gate(
        network_id_byte(),
        finality_committee_activation_height(),
        height,
    )
}
pub fn finality_committee_enforced(height: u64) -> bool {
    finality_committee_enforced_gate(
        network_id_byte(),
        finality_committee_activation_height(),
        finality_committee_required(),
        height,
    )
}

/// ── Phase 21I: live finality-vote gossip + node cache ───────────────────────
pub const FINALITY_VOTE_MAX_BYTES: usize = 512;
const FINALITY_SEEN_CAP: usize = 100_000;
const FINALITY_PRUNE_KEEP: u64 = 64;
pub const DEFAULT_FINALITY_GOSSIP_WINDOW: u64 = 64;

pub fn finality_gossip_window() -> u64 {
    std::env::var("IRIUM_POAWX_FINALITY_GOSSIP_WINDOW")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|w| *w >= 1)
        .unwrap_or(DEFAULT_FINALITY_GOSSIP_WINDOW)
}
pub fn finality_gossip_activation_height() -> Option<u64> {
    std::env::var("IRIUM_POAWX_FINALITY_GOSSIP_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}
pub fn finality_gossip_required() -> bool {
    std::env::var("IRIUM_POAWX_FINALITY_GOSSIP_REQUIRED")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}
pub fn finality_gossip_gate(network_id: u8, activation: Option<u64>, height: u64) -> bool {
    matches!(crate::activation::poawx_effective_activation(network_id, activation), Some(h) if height >= h)
}
pub fn finality_gossip_enforced_gate(
    network_id: u8,
    activation: Option<u64>,
    required: bool,
    height: u64,
) -> bool {
    finality_gossip_gate(network_id, activation, height) && required
}
pub fn finality_gossip_active(height: u64) -> bool {
    finality_gossip_gate(
        network_id_byte(),
        finality_gossip_activation_height(),
        height,
    )
}
pub fn finality_gossip_enforced(height: u64) -> bool {
    finality_gossip_enforced_gate(
        network_id_byte(),
        finality_gossip_activation_height(),
        finality_gossip_required(),
        height,
    )
}
/// Whether this node ingests/gossips finality votes (testnet/devnet + gate set).
pub fn finality_gossip_enabled() -> bool {
    crate::activation::poawx_effective_activation(network_id_byte(), finality_gossip_activation_height())
        .is_some()
}

/// Process-global node finality-vote cache (mirror of the admission cache).
/// Keyed by (target_height, block_hash, vote_type, member_pkh); deduped by the
/// signed vote digest.
pub struct NodeFinalityVoteCache {
    votes: Mutex<BTreeMap<(u64, [u8; 32], u8, [u8; 20]), FinalityVoteV1>>,
    seen: Mutex<BTreeSet<[u8; 32]>>,
    tip: AtomicU64,
}

impl Default for NodeFinalityVoteCache {
    fn default() -> Self {
        Self {
            votes: Mutex::new(BTreeMap::new()),
            seen: Mutex::new(BTreeSet::new()),
            tip: AtomicU64::new(0),
        }
    }
}

impl NodeFinalityVoteCache {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set_tip(&self, tip: u64) {
        self.tip.store(tip, Ordering::Relaxed);
    }
    pub fn tip(&self) -> u64 {
        self.tip.load(Ordering::Relaxed)
    }
    fn in_window(&self, target: u64) -> bool {
        let tip = self.tip();
        target >= tip && target <= tip.saturating_add(finality_gossip_window())
    }
    fn already_seen(&self, d: &[u8; 32]) -> bool {
        self.seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(d)
    }
    fn mark_seen(&self, d: [u8; 32]) {
        let mut s = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        if s.len() >= FINALITY_SEEN_CAP {
            s.clear();
        }
        s.insert(d);
    }

    /// Ingest one finality vote (raw wire). validate(sig) -> window -> dedupe ->
    /// store. AcceptedNew (rebroadcast) / Duplicate / Rejected.
    pub fn ingest_bytes(&self, bytes: &[u8]) -> GossipOutcome {
        if !finality_gossip_enabled() {
            return GossipOutcome::Rejected("finality gossip disabled".to_string());
        }
        if bytes.len() > FINALITY_VOTE_MAX_BYTES {
            return GossipOutcome::Rejected("finality vote oversize".to_string());
        }
        let v = match FinalityVoteV1::deserialize(bytes) {
            Ok(v) => v,
            Err(e) => return GossipOutcome::Rejected(e),
        };
        if v.network_id != network_id_byte() {
            return GossipOutcome::Rejected("wrong network".to_string());
        }
        if let Err(e) = v.verify(v.network_id, v.target_height, &v.block_hash) {
            return GossipOutcome::Rejected(e);
        }
        if !self.in_window(v.target_height) {
            return GossipOutcome::Rejected("out of finality window".to_string());
        }
        let d = v.digest();
        if self.already_seen(&d) {
            return GossipOutcome::Duplicate;
        }
        let key = (v.target_height, v.block_hash, v.vote_type, v.member_pkh);
        let mut map = self.votes.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ex) = map.get(&key) {
            if ex.digest() != d {
                return GossipOutcome::Rejected("conflicting vote for member".to_string());
            }
            return GossipOutcome::Duplicate;
        }
        // Fix #6 (audit-gated): equivocation detection. The per-key dedup above only catches a
        // member double-signing the SAME block; this catches a member casting a Commit vote for a
        // DIFFERENT block at the same height (the two-fork double-sign used to finalize competing
        // chains). Reject the equivocating vote so the cache cannot assemble two conflicting
        // finality proofs. Mainnet hard-off (gate false on network_id 0).
        if crate::poawx_proposer::audit_hardening_active(v.target_height)
            && v.vote_type == FinalityVoteType::Commit.id()
        {
            for ((h, bh, vt, m), _) in map.iter() {
                if *h == v.target_height
                    && *m == v.member_pkh
                    && *vt == v.vote_type
                    && *bh != v.block_hash
                {
                    return GossipOutcome::Rejected(
                        "equivocating finality vote: member voted two blocks at one height"
                            .to_string(),
                    );
                }
            }
        }
        map.insert(key, v.clone());
        drop(map);
        self.mark_seen(d);
        GossipOutcome::AcceptedNew
    }

    /// Votes for (height, block_hash, vote_type), sorted by member_pkh.
    pub fn votes_for(
        &self,
        height: u64,
        block_hash: &[u8; 32],
        vote_type: u8,
    ) -> Vec<FinalityVoteV1> {
        let map = self.votes.lock().unwrap_or_else(|e| e.into_inner());
        map.iter()
            .filter(|((h, bh, vt, _), _)| *h == height && bh == block_hash && *vt == vote_type)
            .map(|(_, v)| v.clone())
            .collect()
    }
    /// All votes for a height (any block/type), for RPC export (sorted by key).
    pub fn votes_for_height(&self, height: u64) -> Vec<FinalityVoteV1> {
        let map = self.votes.lock().unwrap_or_else(|e| e.into_inner());
        map.iter()
            .filter(|((h, _, _, _), _)| *h == height)
            .map(|(_, v)| v.clone())
            .collect()
    }
    pub fn vote_count(&self, height: u64) -> usize {
        self.votes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|((h, _, _, _), _)| *h == height)
            .count()
    }
    /// Deterministic root over the sorted votes for (height, block_hash, type).
    pub fn root(&self, height: u64, block_hash: &[u8; 32], vote_type: u8) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"IRIUM_POAWX_FINALITY_VOTE_CACHE_ROOT_V1");
        for v in self.votes_for(height, block_hash, vote_type) {
            h.update(v.digest());
        }
        h.finalize().into()
    }
    pub fn prune(&self, tip: u64) {
        self.set_tip(tip);
        let floor = tip.saturating_sub(FINALITY_PRUNE_KEEP);
        if floor == 0 {
            return;
        }
        let mut map = self.votes.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|(h, _, _, _), _| *h >= floor);
    }
    pub fn clear(&self) {
        self.votes.lock().unwrap_or_else(|e| e.into_inner()).clear();
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }
}

static GLOBAL_FINALITY_VOTE_CACHE: OnceLock<NodeFinalityVoteCache> = OnceLock::new();
pub fn global_finality_vote_cache() -> &'static NodeFinalityVoteCache {
    GLOBAL_FINALITY_VOTE_CACHE.get_or_init(NodeFinalityVoteCache::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finality_threshold_defaults_to_two_thirds() {
        // Gap 7: with no env override the threshold is 2/3 (supermajority),
        // not the old 1/1 unanimous. Pure + race-free (no env mutation).
        assert_eq!(finality_threshold_values(None, None), (2, 3));
        // sub-1 values are floored to the default.
        assert_eq!(finality_threshold_values(Some(0), Some(0)), (2, 3));
        // explicit overrides are honored, including the legacy 1/1 unanimous.
        assert_eq!(finality_threshold_values(Some(2), Some(3)), (2, 3));
        assert_eq!(finality_threshold_values(Some(3), Some(4)), (3, 4));
        assert_eq!(finality_threshold_values(Some(1), Some(1)), (1, 1));
        // the 2/3 default yields a real supermajority for multi-member committees.
        let (n, d) = finality_threshold_values(None, None);
        let p = FinalityProofV1::new(1, 1, [0u8; 32], [0u8; 32], 0, n, d);
        assert_eq!(p.required_votes(3), 2); // ceil(3*2/3) = 2 of 3
        assert_eq!(p.required_votes(1), 1); // clamped to >= 1 for tiny committees
    }

    #[test]
    fn phase24a_finality_wire_malformed_rejected() {
        let bh = [0x11u8; 32];
        let ph = [0x22u8; 32];
        // vote: exact wire.
        assert!(FinalityVoteV1::deserialize(&[0u8; FINALITY_VOTE_WIRE - 1]).is_err());
        assert!(FinalityVoteV1::deserialize(&[0u8; FINALITY_VOTE_WIRE + 1]).is_err());
        assert!(FinalityVoteV1::deserialize(&[]).is_err());
        // proof: build a valid 1-vote proof, then corrupt the wire.
        let mut p = FinalityProofV1::new(1, 10, bh, ph, 0, 1, 1);
        p.push(FinalityVoteV1::signed(
            &key(7),
            1,
            10,
            bh,
            ph,
            0,
            [0u8; 32],
            FinalityVoteType::Commit,
        ));
        let w = p.serialize();
        assert!(FinalityProofV1::deserialize(&w).is_ok());
        assert!(
            FinalityProofV1::deserialize(&w[..3]).is_err(),
            "truncated header"
        );
        assert!(
            FinalityProofV1::deserialize(&w[..w.len() - 1]).is_err(),
            "truncated body"
        );
        let mut over = w.clone();
        over.push(0);
        assert!(
            FinalityProofV1::deserialize(&over).is_err(),
            "trailing junk"
        );
        // count field (u16 LE) at offset 86 -> set huge -> too many votes (cap 256).
        let mut huge = w.clone();
        huge[86] = 0xFF;
        huge[87] = 0x01;
        assert!(
            FinalityProofV1::deserialize(&huge).is_err(),
            "count overflow"
        );
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_slice(&[seed; 32]).expect("sk")
    }
    fn pkh_of(sk: &SigningKey) -> [u8; 20] {
        let enc = sk.verifying_key().to_encoded_point(true);
        hash160(enc.as_bytes())
    }

    #[test]
    fn vote_sign_verify_and_rejects() {
        let sk = key(0x21);
        let bh = [0x44u8; 32];
        let ph = [0x33u8; 32];
        let v = FinalityVoteV1::signed(
            &sk,
            1,
            10,
            bh,
            ph,
            0,
            [0x11u8; 32],
            FinalityVoteType::Commit,
        );
        assert!(v.verify(1, 10, &bh).is_ok());
        assert!(v.verify(2, 10, &bh).is_err(), "wrong network");
        assert!(v.verify(1, 11, &bh).is_err(), "wrong height");
        assert!(v.verify(1, 10, &[0x99u8; 32]).is_err(), "wrong block hash");
        // mutated signature rejects.
        let mut m = v.clone();
        m.signature[0] ^= 1;
        assert!(m.verify(1, 10, &bh).is_err(), "mutated sig");
        // mutated member_pkh (pubkey/pkh mismatch) rejects.
        let mut m2 = v.clone();
        m2.member_pkh[0] ^= 1;
        assert!(m2.verify(1, 10, &bh).is_err(), "pkh mismatch");
        // wire round-trip.
        assert_eq!(v.serialize().len(), FINALITY_VOTE_WIRE);
        assert_eq!(FinalityVoteV1::deserialize(&v.serialize()).unwrap(), v);
        // digest mutation sensitivity.
        let v2 = FinalityVoteV1::signed(
            &sk,
            1,
            10,
            bh,
            ph,
            1,
            [0x11u8; 32],
            FinalityVoteType::Commit,
        );
        assert_ne!(v.digest(), v2.digest(), "epoch changes digest");
    }

    #[test]
    fn proof_threshold_pass_and_fail() {
        // committee of 3.
        let sks = [key(0xA1), key(0xB2), key(0xC3)];
        let committee: Vec<[u8; 20]> = sks.iter().map(pkh_of).collect();
        let bh = [0x44u8; 32];
        let ph = [0x33u8; 32];
        let mk_proof = |n: usize, num: u16, den: u16| -> FinalityProofV1 {
            let mut p = FinalityProofV1::new(1, 10, bh, ph, 0, num, den);
            for sk in sks.iter().take(n) {
                p.push(FinalityVoteV1::signed(
                    sk,
                    1,
                    10,
                    bh,
                    ph,
                    0,
                    [0x11u8; 32],
                    FinalityVoteType::Commit,
                ));
            }
            p.sort_canonical();
            p
        };
        // 2-of-3: 2 commit votes pass, 1 fails.
        assert!(
            mk_proof(2, 2, 3).validate(1, 10, &bh, &committee).is_ok(),
            "2of3 with 2 passes"
        );
        assert!(
            mk_proof(1, 2, 3).validate(1, 10, &bh, &committee).is_err(),
            "2of3 with 1 fails"
        );
        // 1-of-1 low participation (committee of 1): single vote passes.
        let solo = vec![committee[0]];
        let mut p1 = FinalityProofV1::new(1, 10, bh, ph, 0, 1, 1);
        p1.push(FinalityVoteV1::signed(
            &sks[0],
            1,
            10,
            bh,
            ph,
            0,
            [0x11u8; 32],
            FinalityVoteType::Commit,
        ));
        assert!(p1.validate(1, 10, &bh, &solo).is_ok(), "1of1 passes");
        // non-committee member rejects.
        let outsider = key(0xEE);
        let mut pbad = FinalityProofV1::new(1, 10, bh, ph, 0, 1, 3);
        pbad.push(FinalityVoteV1::signed(
            &outsider,
            1,
            10,
            bh,
            ph,
            0,
            [0x11u8; 32],
            FinalityVoteType::Commit,
        ));
        assert!(
            pbad.validate(1, 10, &bh, &committee).is_err(),
            "non-member rejects"
        );
        // wrong block hash rejects.
        assert!(
            mk_proof(3, 2, 3)
                .validate(1, 10, &[0x77u8; 32], &committee)
                .is_err(),
            "wrong block"
        );
        // proof wire round-trip.
        let full = mk_proof(3, 2, 3);
        assert_eq!(
            FinalityProofV1::deserialize(&full.serialize()).unwrap(),
            full
        );
        // duplicate member (non-canonical) rejects.
        let mut dup = FinalityProofV1::new(1, 10, bh, ph, 0, 1, 3);
        dup.push(FinalityVoteV1::signed(
            &sks[0],
            1,
            10,
            bh,
            ph,
            0,
            [0x11u8; 32],
            FinalityVoteType::Commit,
        ));
        dup.push(FinalityVoteV1::signed(
            &sks[0],
            1,
            10,
            bh,
            ph,
            0,
            [0x11u8; 32],
            FinalityVoteType::Commit,
        ));
        assert!(
            dup.validate(1, 10, &bh, &committee).is_err(),
            "duplicate member rejects"
        );
        // mutation changes proof digest.
        let mut mut_proof = full.clone();
        mut_proof.votes[0].signature[0] ^= 1;
        assert_ne!(
            full.digest(),
            mut_proof.digest(),
            "vote mutation changes proof digest"
        );
    }

    #[test]
    fn required_votes_math() {
        let p = FinalityProofV1::new(1, 10, [0u8; 32], [0u8; 32], 0, 2, 3);
        assert_eq!(p.required_votes(3), 2); // ceil(3*2/3)=2
        assert_eq!(p.required_votes(1), 1); // clamp >=1
        let p2 = FinalityProofV1::new(1, 10, [0u8; 32], [0u8; 32], 0, 1, 1);
        assert_eq!(p2.required_votes(4), 4); // unanimous
    }

    #[test]
    fn audit_finality_cache_rejects_equivocation() {
        // Fix #6: a member casting a Commit vote for a DIFFERENT block at the same height is
        // rejected by the gossip cache when the audit gate is active, so two conflicting
        // finality proofs cannot be assembled. Mainnet hard-off.
        let _g = crate::poawx::poawx_test_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_FINALITY_GOSSIP_ACTIVATION_HEIGHT", "1");
        let net = network_id_byte();
        let h = 10u64;
        let bh1 = [0x11u8; 32];
        let bh2 = [0x22u8; 32];
        let mk = |bh: [u8; 32]| {
            FinalityVoteV1::signed(
                &key(0xA1),
                net,
                h,
                bh,
                [0u8; 32],
                0,
                [0x33u8; 32],
                FinalityVoteType::Commit,
            )
        };
        // gate OFF => same member voting two blocks is accepted (legacy).
        std::env::remove_var("IRIUM_POAWX_AUDIT_HARDENING_ACTIVATION_HEIGHT");
        let c0 = NodeFinalityVoteCache::new();
        c0.set_tip(h);
        assert_eq!(
            c0.ingest_bytes(&mk(bh1).serialize()),
            GossipOutcome::AcceptedNew
        );
        assert_eq!(
            c0.ingest_bytes(&mk(bh2).serialize()),
            GossipOutcome::AcceptedNew,
            "legacy allows equivocation"
        );
        // gate ON => the second (conflicting) vote is rejected.
        std::env::set_var("IRIUM_POAWX_AUDIT_HARDENING_ACTIVATION_HEIGHT", "1");
        let c1 = NodeFinalityVoteCache::new();
        c1.set_tip(h);
        assert_eq!(
            c1.ingest_bytes(&mk(bh1).serialize()),
            GossipOutcome::AcceptedNew
        );
        match c1.ingest_bytes(&mk(bh2).serialize()) {
            GossipOutcome::Rejected(e) => assert!(e.contains("equivocating"), "got: {e}"),
            other => panic!("expected equivocation rejection, got {other:?}"),
        }
        // a non-conflicting different member is still accepted.
        let other_member = FinalityVoteV1::signed(
            &key(0xB2),
            net,
            h,
            bh1,
            [0u8; 32],
            0,
            [0x33u8; 32],
            FinalityVoteType::Commit,
        );
        assert_eq!(
            c1.ingest_bytes(&other_member.serialize()),
            GossipOutcome::AcceptedNew
        );
        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_FINALITY_GOSSIP_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_AUDIT_HARDENING_ACTIVATION_HEIGHT");
    }

    #[test]
    fn finality_gossip_cache_ingest_dedupe_window_prune() {
        let _g = crate::poawx::poawx_test_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_FINALITY_GOSSIP_ACTIVATION_HEIGHT", "1");
        let net = network_id_byte();
        let bh = [0x44u8; 32];
        let cache = NodeFinalityVoteCache::new();
        cache.set_tip(10);
        let v1 = FinalityVoteV1::signed(
            &key(0xA1),
            net,
            10,
            bh,
            [0u8; 32],
            0,
            [0x11u8; 32],
            FinalityVoteType::Commit,
        );
        let v2 = FinalityVoteV1::signed(
            &key(0xB2),
            net,
            10,
            bh,
            [0u8; 32],
            0,
            [0x11u8; 32],
            FinalityVoteType::Commit,
        );
        assert_eq!(
            cache.ingest_bytes(&v1.serialize()),
            GossipOutcome::AcceptedNew
        );
        assert_eq!(
            cache.ingest_bytes(&v1.serialize()),
            GossipOutcome::Duplicate
        );
        assert_eq!(
            cache.ingest_bytes(&v2.serialize()),
            GossipOutcome::AcceptedNew
        );
        assert_eq!(cache.vote_count(10), 2);
        // malformed rejects, no panic.
        assert!(matches!(
            cache.ingest_bytes(&[0u8; 9]),
            GossipOutcome::Rejected(_)
        ));
        // invalid signature rejects.
        let mut bad = v1.clone();
        bad.signature[0] ^= 1;
        assert!(matches!(
            cache.ingest_bytes(&bad.serialize()),
            GossipOutcome::Rejected(_)
        ));
        // out of window rejects.
        let far = FinalityVoteV1::signed(
            &key(0xC3),
            net,
            9000,
            bh,
            [0u8; 32],
            0,
            [0x11u8; 32],
            FinalityVoteType::Commit,
        );
        assert!(matches!(
            cache.ingest_bytes(&far.serialize()),
            GossipOutcome::Rejected(_)
        ));
        // deterministic sorted export + root.
        let r1 = cache.root(10, &bh, FinalityVoteType::Commit.id());
        assert_eq!(cache.root(10, &bh, FinalityVoteType::Commit.id()), r1);
        let got = cache.votes_for(10, &bh, FinalityVoteType::Commit.id());
        assert_eq!(got.len(), 2);
        assert!(
            got[0].member_pkh < got[1].member_pkh,
            "sorted by member_pkh"
        );
        // prune drops old heights.
        cache.prune(9000);
        assert_eq!(cache.vote_count(10), 0);
        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_FINALITY_GOSSIP_ACTIVATION_HEIGHT");
    }

    #[test]
    fn gate_logic_pure_and_mainnet_off() {
        assert!(
            !finality_committee_gate(0, Some(1), 100),
            "below the mainnet activation height; NOT hard-off (see activation::mainnet_gate_truth)"
        );
        assert!(finality_committee_gate(1, Some(1), 100));
        assert!(!finality_committee_gate(1, None, 100));
        assert!(finality_committee_enforced_gate(1, Some(1), true, 100));
        assert!(!finality_committee_enforced_gate(1, Some(1), false, 100));
        assert!(
            !finality_committee_enforced_gate(0, Some(1), true, 100),
            "below the mainnet activation height; NOT hard-off (see activation::mainnet_gate_truth)"
        );
    }
}
