//! Phase 21A: PoAW-X Miner Work Ticket + lightweight Sybil-resistance primitive.
//!
//! A Miner Work Ticket is a per-epoch, network-bound identity/eligibility token.
//! It carries a small proof-of-work ("sybil work") that imposes a cheap identity
//! cost in testnet/devnet (configurable, default OFF) — this is NOT chain PoW and
//! does NOT touch LWMA-144. Data-only foundation (Phase 21B may enforce it).
//! Mainnet hard-off; no private key material; deterministic.
#![allow(dead_code)]

use sha2::{Digest, Sha256};

use crate::activation::network_id_byte;
use crate::poawx_penalty::PenaltyStatus;

pub const TICKET_VERSION: u8 = 1;
pub const TICKET_DOMAIN: &[u8] = b"IRIUM_POAWX_TICKET_V1";
pub const SYBIL_DOMAIN: &[u8] = b"IRIUM_POAWX_SYBIL_WORK_V1";

/// Miner Work Ticket. `assignment_public_key` is a placeholder for a future
/// VRF/private-assignment public key (Phase 21B+). No private material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinerWorkTicket {
    pub version: u8,
    pub network_id: u8,
    pub miner_pkh: [u8; 20],
    pub epoch: u64,
    pub assignment_public_key: [u8; 33],
    pub sybil_work_nonce: [u8; 32],
    pub sybil_work_digest: [u8; 32],
    pub recent_reward_score: u64,
    pub valid_work_count: u32,
    pub invalid_work_count: u32,
    pub penalty_status: u8,
    pub bond_reference: Option<[u8; 32]>,
    pub issued_height: u64,
    pub expiry_height: u64,
}

/// Recompute the sybil-work digest for a candidate nonce. Binding fields prevent
/// reuse across network/miner/epoch/assignment-key.
pub fn compute_sybil_digest(
    network_id: u8,
    miner_pkh: &[u8; 20],
    epoch: u64,
    assignment_public_key: &[u8; 33],
    nonce: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(SYBIL_DOMAIN);
    h.update([network_id]);
    h.update(miner_pkh);
    h.update(epoch.to_le_bytes());
    h.update(assignment_public_key);
    h.update(nonce);
    h.finalize().into()
}

/// Count leading zero bits of a 32-byte digest (big-endian).
pub fn leading_zero_bits(d: &[u8; 32]) -> u32 {
    let mut n = 0u32;
    for &b in d.iter() {
        if b == 0 {
            n += 8;
        } else {
            n += b.leading_zeros();
            break;
        }
    }
    n
}

/// Whether a sybil digest meets the leading-zero-bits target.
pub fn meets_sybil_target(digest: &[u8; 32], bits: u32) -> bool {
    leading_zero_bits(digest) >= bits
}

/// Configured sybil threshold (leading-zero bits). `0` = disabled (default).
/// Env `IRIUM_POAWX_TICKET_SYBIL_BITS`. Mainnet hard-off (always 0).
pub fn sybil_threshold_bits() -> u32 {
    if network_id_byte() == 0 {
        return 0;
    }
    std::env::var("IRIUM_POAWX_TICKET_SYBIL_BITS")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|&b| b <= 32)
        .unwrap_or(0)
}

impl MinerWorkTicket {
    /// Canonical serialization. `bond_reference` present-flag is a single byte.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(1 + 1 + 20 + 8 + 33 + 32 + 32 + 8 + 4 + 4 + 1 + 1 + 8 + 8 + 32);
        out.push(self.version);
        out.push(self.network_id);
        out.extend_from_slice(&self.miner_pkh);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.assignment_public_key);
        out.extend_from_slice(&self.sybil_work_nonce);
        out.extend_from_slice(&self.sybil_work_digest);
        out.extend_from_slice(&self.recent_reward_score.to_le_bytes());
        out.extend_from_slice(&self.valid_work_count.to_le_bytes());
        out.extend_from_slice(&self.invalid_work_count.to_le_bytes());
        out.push(self.penalty_status);
        match &self.bond_reference {
            Some(b) => {
                out.push(1);
                out.extend_from_slice(b);
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.issued_height.to_le_bytes());
        out.extend_from_slice(&self.expiry_height.to_le_bytes());
        out
    }

    pub fn deserialize(b: &[u8]) -> Result<Self, String> {
        // fixed prefix up to penalty_status = 1+1+20+8+33+32+32+8+4+4+1 = 144
        if b.len() < 144 + 1 {
            return Err("ticket: too short".to_string());
        }
        if b[0] != TICKET_VERSION {
            return Err(format!("ticket: bad version {}", b[0]));
        }
        let mut p = 0usize;
        let rd = |p: &mut usize, n: usize| {
            let s = b[*p..*p + n].to_vec();
            *p += n;
            s
        };
        let version = b[p];
        p += 1;
        let network_id = b[p];
        p += 1;
        let mut miner_pkh = [0u8; 20];
        miner_pkh.copy_from_slice(&rd(&mut p, 20));
        let epoch = u64::from_le_bytes(rd(&mut p, 8).try_into().unwrap());
        let mut assignment_public_key = [0u8; 33];
        assignment_public_key.copy_from_slice(&rd(&mut p, 33));
        let mut sybil_work_nonce = [0u8; 32];
        sybil_work_nonce.copy_from_slice(&rd(&mut p, 32));
        let mut sybil_work_digest = [0u8; 32];
        sybil_work_digest.copy_from_slice(&rd(&mut p, 32));
        let recent_reward_score = u64::from_le_bytes(rd(&mut p, 8).try_into().unwrap());
        let valid_work_count = u32::from_le_bytes(rd(&mut p, 4).try_into().unwrap());
        let invalid_work_count = u32::from_le_bytes(rd(&mut p, 4).try_into().unwrap());
        let penalty_status = b[p];
        p += 1;
        let bond_flag = b[p];
        p += 1;
        let bond_reference = match bond_flag {
            0 => None,
            1 => {
                if b.len() < p + 32 + 16 {
                    return Err("ticket: truncated bond".to_string());
                }
                let mut bond = [0u8; 32];
                bond.copy_from_slice(&rd(&mut p, 32));
                Some(bond)
            }
            _ => return Err("ticket: bad bond flag".to_string()),
        };
        if b.len() < p + 16 {
            return Err("ticket: truncated tail".to_string());
        }
        let issued_height = u64::from_le_bytes(rd(&mut p, 8).try_into().unwrap());
        let expiry_height = u64::from_le_bytes(rd(&mut p, 8).try_into().unwrap());
        Ok(MinerWorkTicket {
            version,
            network_id,
            miner_pkh,
            epoch,
            assignment_public_key,
            sybil_work_nonce,
            sybil_work_digest,
            recent_reward_score,
            valid_work_count,
            invalid_work_count,
            penalty_status,
            bond_reference,
            issued_height,
            expiry_height,
        })
    }

    /// Stable ticket digest over the full canonical serialization.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(TICKET_DOMAIN);
        h.update(self.serialize());
        h.finalize().into()
    }

    fn recompute_sybil(&self) -> [u8; 32] {
        compute_sybil_digest(
            self.network_id,
            &self.miner_pkh,
            self.epoch,
            &self.assignment_public_key,
            &self.sybil_work_nonce,
        )
    }

    /// Validate the ticket. `expected_network` 0 = mainnet hard-off. `require_bits`
    /// (typically `sybil_threshold_bits()`) enforces the Sybil cost when > 0.
    pub fn validate(
        &self,
        expected_network: u8,
        current_height: u64,
        require_bits: u32,
    ) -> Result<(), String> {
        if expected_network == 0 {
            return Err("ticket: mainnet hard-off".to_string());
        }
        if self.version != TICKET_VERSION {
            return Err("ticket: bad version".to_string());
        }
        if self.network_id != expected_network {
            return Err("ticket: network mismatch".to_string());
        }
        if self.issued_height > current_height {
            return Err("ticket: issued in the future".to_string());
        }
        if self.expiry_height <= current_height {
            return Err("ticket: expired".to_string());
        }
        if PenaltyStatus::from_id(self.penalty_status).is_none() {
            return Err("ticket: bad penalty status".to_string());
        }
        // sybil-work binding: the digest must match the recomputed value.
        if self.sybil_work_digest != self.recompute_sybil() {
            return Err("ticket: sybil_work_digest mismatch".to_string());
        }
        if require_bits > 0 && !meets_sybil_target(&self.sybil_work_digest, require_bits) {
            return Err("ticket: insufficient sybil work".to_string());
        }
        Ok(())
    }

    /// Whether this ticket's holder may receive a high-trust role.
    pub fn eligible_for_high_trust_role(&self) -> bool {
        PenaltyStatus::from_id(self.penalty_status)
            .map(|s| s.eligible_for_high_trust_role())
            .unwrap_or(false)
    }
}

/// Test/dev helper: grind a sybil nonce meeting `bits` (small targets only).
pub fn grind_sybil_nonce(
    network_id: u8,
    miner_pkh: &[u8; 20],
    epoch: u64,
    assignment_public_key: &[u8; 33],
    bits: u32,
    max_iters: u64,
) -> Option<([u8; 32], [u8; 32])> {
    let mut nonce = [0u8; 32];
    for i in 0..max_iters {
        nonce[0..8].copy_from_slice(&i.to_le_bytes());
        let d = compute_sybil_digest(network_id, miner_pkh, epoch, assignment_public_key, &nonce);
        if meets_sybil_target(&d, bits) {
            return Some((nonce, d));
        }
    }
    None
}

/// Activation height for ticket enforcement (env-gated; mainnet hard-off).
pub fn tickets_activation_height() -> Option<u64> {
    std::env::var("IRIUM_POAWX_TICKETS_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// Pure gate logic (network 0 = mainnet hard-off); param-driven for race-free tests.
pub fn tickets_gate(network_id: u8, activation: Option<u64>, height: u64) -> bool {
    if network_id == 0 {
        return false;
    }
    matches!(activation, Some(h) if height >= h)
}

/// Whether ticket validation is active at `height`. Mainnet hard-off.
pub fn tickets_active(height: u64) -> bool {
    tickets_gate(network_id_byte(), tickets_activation_height(), height)
}

/// Whether a valid ticket is REQUIRED (vs. advisory) — `IRIUM_POAWX_TICKETS_REQUIRED=1`.
pub fn tickets_required() -> bool {
    if network_id_byte() == 0 {
        return false;
    }
    std::env::var("IRIUM_POAWX_TICKETS_REQUIRED")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}

/// Ticket enforcement is ON only when the gate is active at `height` AND the
/// required flag is set. Mainnet hard-off (both inputs are). When off, connect_block
/// ignores ticket proofs (old Phase 20 behavior unchanged).
pub fn tickets_enforced(height: u64) -> bool {
    tickets_active(height) && tickets_required()
}

// ── Phase 21B: compact role-ticket proof (binds a ticket to a Phase 20 role) ──
//
// A `TicketProof` is the compact, self-verifiable binding carried in the Phase 20
// ext (one per rewarded role) when the ticket gate is enabled. It binds
// network/height/role/miner-pkh and carries the sybil-work (nonce + digest) so a
// validator can independently recompute the sybil digest + check the threshold,
// plus a deterministic `ticket_digest` over the binding fields (recomputable, so
// "digest matches canonical" is enforceable from the proof alone). No private key.

pub const TICKET_PROOF_DOMAIN: &[u8] = b"IRIUM_POAWX_TICKET_PROOF_V1";
pub const TICKET_PROOF_WIRE: usize = 1 + 8 + 1 + 20 + 8 + 8 + 33 + 32 + 32 + 1 + 32; // 176
/// Magic prefixing the optional trailing ticket section in `Phase20ReceiptExt`.
pub const TICKET_SECTION_MAGIC: &[u8; 4] = b"TPK1";

/// High-trust roles (VERIFY + SUPPORT/finality). COMPUTE is not high-trust.
pub fn is_high_trust_role(role_id: u8) -> bool {
    role_id == crate::poawx::ROLE_VERIFY_CONTRIBUTOR
        || role_id == crate::poawx::ROLE_SUPPORT_CONTRIBUTOR
}

/// Deterministic, recomputable digest over the proof's binding fields.
pub fn compute_ticket_proof_digest(
    network_id: u8,
    target_height: u64,
    role_id: u8,
    miner_pkh: &[u8; 20],
    epoch: u64,
    expiry_height: u64,
    assignment_public_key: &[u8; 33],
    sybil_work_digest: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(TICKET_PROOF_DOMAIN);
    h.update([network_id]);
    h.update(target_height.to_le_bytes());
    h.update([role_id]);
    h.update(miner_pkh);
    h.update(epoch.to_le_bytes());
    h.update(expiry_height.to_le_bytes());
    h.update(assignment_public_key);
    h.update(sybil_work_digest);
    h.finalize().into()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketProof {
    pub network_id: u8,
    pub target_height: u64,
    pub role_id: u8,
    pub miner_pkh: [u8; 20],
    pub epoch: u64,
    pub expiry_height: u64,
    pub assignment_public_key: [u8; 33],
    pub sybil_work_nonce: [u8; 32],
    pub sybil_work_digest: [u8; 32],
    pub penalty_status: u8,
    pub ticket_digest: [u8; 32],
}

impl TicketProof {
    /// Build a proof for `role_id` at `height` from the miner's identity + a sybil
    /// nonce. Computes the sybil digest + deterministic ticket digest.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network_id: u8,
        target_height: u64,
        role_id: u8,
        miner_pkh: [u8; 20],
        epoch: u64,
        expiry_height: u64,
        assignment_public_key: [u8; 33],
        sybil_work_nonce: [u8; 32],
        penalty_status: u8,
    ) -> Self {
        let sybil_work_digest = compute_sybil_digest(
            network_id,
            &miner_pkh,
            epoch,
            &assignment_public_key,
            &sybil_work_nonce,
        );
        let ticket_digest = compute_ticket_proof_digest(
            network_id,
            target_height,
            role_id,
            &miner_pkh,
            epoch,
            expiry_height,
            &assignment_public_key,
            &sybil_work_digest,
        );
        Self {
            network_id,
            target_height,
            role_id,
            miner_pkh,
            epoch,
            expiry_height,
            assignment_public_key,
            sybil_work_nonce,
            sybil_work_digest,
            penalty_status,
            ticket_digest,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(TICKET_PROOF_WIRE);
        out.push(self.network_id);
        out.extend_from_slice(&self.target_height.to_le_bytes());
        out.push(self.role_id);
        out.extend_from_slice(&self.miner_pkh);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.expiry_height.to_le_bytes());
        out.extend_from_slice(&self.assignment_public_key);
        out.extend_from_slice(&self.sybil_work_nonce);
        out.extend_from_slice(&self.sybil_work_digest);
        out.push(self.penalty_status);
        out.extend_from_slice(&self.ticket_digest);
        out
    }

    pub fn deserialize(b: &[u8]) -> Result<Self, String> {
        if b.len() != TICKET_PROOF_WIRE {
            return Err(format!(
                "ticket proof: bad len {} (want {})",
                b.len(),
                TICKET_PROOF_WIRE
            ));
        }
        let mut p = 0usize;
        let rd = |p: &mut usize, n: usize| {
            let s = b[*p..*p + n].to_vec();
            *p += n;
            s
        };
        let network_id = b[p];
        p += 1;
        let target_height = u64::from_le_bytes(rd(&mut p, 8).try_into().unwrap());
        let role_id = b[p];
        p += 1;
        let mut miner_pkh = [0u8; 20];
        miner_pkh.copy_from_slice(&rd(&mut p, 20));
        let epoch = u64::from_le_bytes(rd(&mut p, 8).try_into().unwrap());
        let expiry_height = u64::from_le_bytes(rd(&mut p, 8).try_into().unwrap());
        let mut assignment_public_key = [0u8; 33];
        assignment_public_key.copy_from_slice(&rd(&mut p, 33));
        let mut sybil_work_nonce = [0u8; 32];
        sybil_work_nonce.copy_from_slice(&rd(&mut p, 32));
        let mut sybil_work_digest = [0u8; 32];
        sybil_work_digest.copy_from_slice(&rd(&mut p, 32));
        let penalty_status = b[p];
        p += 1;
        let mut ticket_digest = [0u8; 32];
        ticket_digest.copy_from_slice(&rd(&mut p, 32));
        Ok(Self {
            network_id,
            target_height,
            role_id,
            miner_pkh,
            epoch,
            expiry_height,
            assignment_public_key,
            sybil_work_nonce,
            sybil_work_digest,
            penalty_status,
            ticket_digest,
        })
    }

    /// Validate the proof against block context + the rewarded role's solver pkh.
    /// `require_sybil_bits` enforces the sybil cost when > 0; `penalty_enforced`
    /// blocks suspended/slashed identities from high-trust roles.
    pub fn validate(
        &self,
        expected_network: u8,
        height: u64,
        role_id: u8,
        role_solver_pkh: &[u8; 20],
        require_sybil_bits: u32,
        penalty_enforced: bool,
    ) -> Result<(), String> {
        if expected_network == 0 {
            return Err("ticket proof: mainnet hard-off".to_string());
        }
        if self.network_id != expected_network {
            return Err("ticket proof: network mismatch".to_string());
        }
        if self.target_height != height {
            return Err("ticket proof: height mismatch".to_string());
        }
        if self.role_id != role_id {
            return Err("ticket proof: role mismatch".to_string());
        }
        if &self.miner_pkh != role_solver_pkh {
            return Err("ticket proof: miner pkh != role solver".to_string());
        }
        if self.expiry_height <= height {
            return Err("ticket proof: expired".to_string());
        }
        let recomputed_sybil = compute_sybil_digest(
            self.network_id,
            &self.miner_pkh,
            self.epoch,
            &self.assignment_public_key,
            &self.sybil_work_nonce,
        );
        if recomputed_sybil != self.sybil_work_digest {
            return Err("ticket proof: sybil digest mismatch".to_string());
        }
        if require_sybil_bits > 0
            && !meets_sybil_target(&self.sybil_work_digest, require_sybil_bits)
        {
            return Err("ticket proof: insufficient sybil work".to_string());
        }
        let expect_digest = compute_ticket_proof_digest(
            self.network_id,
            self.target_height,
            self.role_id,
            &self.miner_pkh,
            self.epoch,
            self.expiry_height,
            &self.assignment_public_key,
            &self.sybil_work_digest,
        );
        if expect_digest != self.ticket_digest {
            return Err("ticket proof: ticket_digest mismatch".to_string());
        }
        let pen = crate::poawx_penalty::PenaltyStatus::from_id(self.penalty_status)
            .ok_or("ticket proof: bad penalty status")?;
        if penalty_enforced && is_high_trust_role(role_id) && !pen.eligible_for_high_trust_role() {
            return Err(
                "ticket proof: penalized identity ineligible for high-trust role".to_string(),
            );
        }
        Ok(())
    }
}

// ── Phase 32: block-carried ticket registrations + on-chain ticket store ──────
//
// A registration is a `MinerWorkTicket` (self-authenticating via its Sybil PoW;
// unsigned by the existing deterministic design). Registrations are block-carried
// in a trailing-optional `TKT1` ext section (committed into the irx1 root) and
// applied to a deterministic, replayable on-chain ticket store. Testnet/devnet
// only; mainnet hard-off. Only block-carried, replayed registrations affect
// consensus — a local cache is provided for builders (observability only).

use std::collections::BTreeMap;
use std::sync::Mutex;

/// Trailing `Phase20ReceiptExt` section magic for block-carried registrations.
pub const TICKET_SECTION_MAGIC_TKT1: &[u8; 4] = b"TKT1";
/// Max ticket registrations carried in a single block (anti-spam bound).
pub const MAX_TICKET_REGISTRATIONS_PER_BLOCK: usize = 16;
const TICKET_STORE_DOMAIN: &[u8] = b"IRIUM_POAWX_TICKET_STORE_V1";
const TICKET_REG_CACHE_CAP: usize = 4096;

/// A block-carried ticket registration (the full Miner Work Ticket).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoawxTicketRegistrationV1 {
    pub ticket: MinerWorkTicket,
}

impl PoawxTicketRegistrationV1 {
    pub fn new(ticket: MinerWorkTicket) -> Self {
        Self { ticket }
    }
    /// Stable, order-independent id == the ticket digest.
    pub fn ticket_id(&self) -> [u8; 32] {
        self.ticket.digest()
    }
    pub fn miner_pkh(&self) -> [u8; 20] {
        self.ticket.miner_pkh
    }
    pub fn epoch(&self) -> u64 {
        self.ticket.epoch
    }
    pub fn assignment_public_key(&self) -> [u8; 33] {
        self.ticket.assignment_public_key
    }
    pub fn expiry_height(&self) -> u64 {
        self.ticket.expiry_height
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.ticket.serialize()
    }
    pub fn deserialize(raw: &[u8]) -> Result<Self, String> {
        Ok(Self {
            ticket: MinerWorkTicket::deserialize(raw)?,
        })
    }

    /// Validate the registration (reuses the existing ticket validator). Mainnet
    /// hard-off. Fails closed.
    pub fn validate(
        &self,
        expected_network: u8,
        current_height: u64,
        require_bits: u32,
    ) -> Result<(), String> {
        if expected_network == 0 {
            return Err("phase32: ticket registration mainnet hard-off".to_string());
        }
        self.ticket
            .validate(expected_network, current_height, require_bits)
            .map_err(|e| format!("phase32: invalid ticket registration: {e}"))
    }
}

/// One entry in the on-chain ticket store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoawxTicketStoreEntry {
    pub ticket_id: [u8; 32],
    pub miner_pkh: [u8; 20],
    pub epoch: u64,
    pub assignment_public_key: [u8; 33],
    pub expiry_height: u64,
    pub registered_height: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoawxTicketStoreValidationError {
    MainnetHardOff,
    Invalid,
    DuplicateTicketId,
    MinerEpochRateLimited,
    VrfEpochRateLimited,
}

/// Deterministic, replayable on-chain ticket store (derived from the active
/// chain's block-carried registrations). Testnet/devnet only; empty on mainnet.
#[derive(Debug, Clone, Default)]
pub struct PoawxTicketStore {
    by_id: BTreeMap<[u8; 32], PoawxTicketStoreEntry>,
}

impl PoawxTicketStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Deterministically prune entries that have expired at `tip_height`.
    pub fn prune_expired(&mut self, tip_height: u64) {
        self.by_id.retain(|_, e| e.expiry_height > tip_height);
    }

    fn miner_epoch_live(&self, miner_pkh: &[u8; 20], epoch: u64, height: u64) -> bool {
        self.by_id
            .values()
            .any(|e| &e.miner_pkh == miner_pkh && e.epoch == epoch && e.expiry_height > height)
    }
    fn vrf_epoch_live(&self, key: &[u8; 33], epoch: u64, height: u64) -> bool {
        self.by_id.values().any(|e| {
            &e.assignment_public_key == key && e.epoch == epoch && e.expiry_height > height
        })
    }

    /// Apply a VALIDATED registration. Idempotent by ticket id; enforces the
    /// one-active-per-(miner,epoch) and one-active-per-(vrf,epoch) rate limits.
    /// `applied_height` = the block that carried it (effective from the next block).
    pub fn apply_registration(
        &mut self,
        reg: &PoawxTicketRegistrationV1,
        applied_height: u64,
    ) -> Result<bool, PoawxTicketStoreValidationError> {
        let id = reg.ticket_id();
        if self.by_id.contains_key(&id) {
            return Ok(false); // idempotent
        }
        let (miner, epoch, key, expiry) = (
            reg.miner_pkh(),
            reg.epoch(),
            reg.assignment_public_key(),
            reg.expiry_height(),
        );
        if self.miner_epoch_live(&miner, epoch, applied_height) {
            return Err(PoawxTicketStoreValidationError::MinerEpochRateLimited);
        }
        if self.vrf_epoch_live(&key, epoch, applied_height) {
            return Err(PoawxTicketStoreValidationError::VrfEpochRateLimited);
        }
        self.by_id.insert(
            id,
            PoawxTicketStoreEntry {
                ticket_id: id,
                miner_pkh: miner,
                epoch,
                assignment_public_key: key,
                expiry_height: expiry,
                registered_height: applied_height,
            },
        );
        Ok(true)
    }

    /// Whether `(miner_pkh, epoch, assignment_public_key)` has an ACTIVE registered
    /// ticket at `height` (registered earlier, not expired). The eligibility query.
    pub fn has_active(
        &self,
        miner_pkh: &[u8; 20],
        epoch: u64,
        assignment_public_key: &[u8; 33],
        height: u64,
    ) -> bool {
        self.by_id.values().any(|e| {
            &e.miner_pkh == miner_pkh
                && e.epoch == epoch
                && &e.assignment_public_key == assignment_public_key
                && e.registered_height < height
                && e.expiry_height > height
        })
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }
    pub fn active_count(&self, height: u64) -> usize {
        self.by_id
            .values()
            .filter(|e| e.expiry_height > height)
            .count()
    }

    /// Deterministic state commitment (order-independent; for tests/replay checks).
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(TICKET_STORE_DOMAIN);
        h.update((self.by_id.len() as u64).to_le_bytes());
        for (id, e) in &self.by_id {
            h.update(id);
            h.update(e.miner_pkh);
            h.update(e.epoch.to_le_bytes());
            h.update(e.assignment_public_key);
            h.update(e.expiry_height.to_le_bytes());
            h.update(e.registered_height.to_le_bytes());
        }
        h.finalize().into()
    }
}

// ── Phase 32 gates (testnet-only; mainnet hard-off) ──────────────────────────

pub fn ticket_store_activation_height() -> Option<u64> {
    std::env::var("IRIUM_POAWX_TICKET_STORE_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

pub fn ticket_store_gate(network_id: u8, activation: Option<u64>, height: u64) -> bool {
    if network_id == 0 {
        return false;
    }
    matches!(activation, Some(h) if height >= h)
}

pub fn ticket_store_active(height: u64) -> bool {
    ticket_store_gate(network_id_byte(), ticket_store_activation_height(), height)
}

pub fn ticket_store_required() -> bool {
    if network_id_byte() == 0 {
        return false;
    }
    std::env::var("IRIUM_POAWX_TICKET_STORE_REQUIRED")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}

/// Eligibility enforcement (additive) is ON only when active AND required. Mainnet
/// hard-off. When on, a rewarded role's ticket proof must match an active on-chain
/// registered ticket.
pub fn ticket_store_enforced(height: u64) -> bool {
    ticket_store_active(height) && ticket_store_required()
}

// ── Bounded LOCAL registration cache (observability only; NOT consensus) ──────

pub struct NodeTicketRegistrationCache {
    regs: Mutex<BTreeMap<[u8; 32], PoawxTicketRegistrationV1>>,
}

impl Default for NodeTicketRegistrationCache {
    fn default() -> Self {
        Self {
            regs: Mutex::new(BTreeMap::new()),
        }
    }
}

impl NodeTicketRegistrationCache {
    pub fn new() -> Self {
        Self::default()
    }
    /// Validate + cache locally. Returns true if newly cached. Mainnet hard-off.
    pub fn ingest(&self, reg: PoawxTicketRegistrationV1, height: u64) -> bool {
        let net = network_id_byte();
        if net == 0 {
            return false;
        }
        if reg.validate(net, height, sybil_threshold_bits()).is_err() {
            return false;
        }
        let id = reg.ticket_id();
        let mut m = self.regs.lock().unwrap_or_else(|e| e.into_inner());
        if m.contains_key(&id) {
            return false;
        }
        while m.len() >= TICKET_REG_CACHE_CAP {
            if let Some((&k, _)) = m.iter().next() {
                m.remove(&k);
            } else {
                break;
            }
        }
        m.insert(id, reg);
        true
    }
    pub fn len(&self) -> usize {
        self.regs.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn clear(&self) {
        self.regs.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(net: u8, h_issue: u64, h_exp: u64) -> MinerWorkTicket {
        let pkh = [0xA1u8; 20];
        let apk = [0x02u8; 33];
        let epoch = 7u64;
        let (nonce, digest) = grind_sybil_nonce(net, &pkh, epoch, &apk, 0, 1).unwrap();
        MinerWorkTicket {
            version: TICKET_VERSION,
            network_id: net,
            miner_pkh: pkh,
            epoch,
            assignment_public_key: apk,
            sybil_work_nonce: nonce,
            sybil_work_digest: digest,
            recent_reward_score: 42,
            valid_work_count: 3,
            invalid_work_count: 0,
            penalty_status: PenaltyStatus::Clean.id(),
            bond_reference: None,
            issued_height: h_issue,
            expiry_height: h_exp,
        }
    }

    #[test]
    fn phase24a_ticket_wire_malformed_rejected() {
        // MinerWorkTicket requires a minimum length; short input rejects, no panic.
        assert!(
            MinerWorkTicket::deserialize(&[0u8; 50]).is_err(),
            "too short"
        );
        assert!(MinerWorkTicket::deserialize(&[]).is_err());
        // TicketProof is exact-length.
        assert!(TicketProof::deserialize(&[0u8; TICKET_PROOF_WIRE - 1]).is_err());
        assert!(TicketProof::deserialize(&[0u8; TICKET_PROOF_WIRE + 1]).is_err());
        // a valid ticket round-trips; truncating the tail rejects (no panic).
        let t = mk(2, 100, 200);
        let w = t.serialize();
        assert!(MinerWorkTicket::deserialize(&w).is_ok());
        assert!(
            MinerWorkTicket::deserialize(&w[..w.len() - 1]).is_err(),
            "truncated tail"
        );
    }

    #[test]
    fn ticket_serialize_roundtrip_and_digest_mutation() {
        let t = mk(1, 10, 100);
        let b = t.serialize();
        let t2 = MinerWorkTicket::deserialize(&b).unwrap();
        assert_eq!(t, t2);
        let d0 = t.digest();
        let mut t3 = t.clone();
        t3.recent_reward_score += 1;
        assert_ne!(d0, t3.digest(), "mutation changes digest");
        // with bond reference
        let mut tb = t.clone();
        tb.bond_reference = Some([0x09u8; 32]);
        assert_eq!(MinerWorkTicket::deserialize(&tb.serialize()).unwrap(), tb);
    }

    #[test]
    fn ticket_validate_accept_and_rejects() {
        let net = 1u8;
        let t = mk(net, 10, 100);
        assert!(t.validate(net, 50, 0).is_ok(), "valid in-window ticket");
        // mainnet hard-off
        assert!(t.validate(0, 50, 0).is_err());
        // wrong network
        assert!(t.validate(2, 50, 0).is_err());
        // expired
        assert!(t.validate(net, 100, 0).is_err());
        // future-issued
        let tf = mk(net, 60, 100);
        assert!(tf.validate(net, 50, 0).is_err());
        // tampered sybil nonce -> digest mismatch
        let mut tt = t.clone();
        tt.sybil_work_nonce[0] ^= 1;
        assert!(tt.validate(net, 50, 0).is_err());
        // malformed deserialize
        assert!(MinerWorkTicket::deserialize(b"short").is_err());
    }

    #[test]
    fn sybil_threshold_disabled_permits_enabled_rejects_insufficient() {
        let net = 1u8;
        let pkh = [0xB2u8; 20];
        let apk = [0x03u8; 33];
        let epoch = 9u64;
        // threshold disabled (bits=0): any nonce permitted.
        let (n0, d0) = grind_sybil_nonce(net, &pkh, epoch, &apk, 0, 1).unwrap();
        assert!(meets_sybil_target(&d0, 0));
        // enabled with a tiny target: grind finds a valid nonce.
        let (n1, d1) =
            grind_sybil_nonce(net, &pkh, epoch, &apk, 8, 200_000).expect("grind tiny target");
        assert!(meets_sybil_target(&d1, 8));
        assert_eq!(
            compute_sybil_digest(net, &pkh, epoch, &apk, &n1),
            d1,
            "binding"
        );
        // an insufficient digest is rejected at the higher threshold.
        assert!(!meets_sybil_target(&d0, 8) || leading_zero_bits(&d0) >= 8);
        // a ticket carrying d0 fails validate when require_bits=8 (unless d0 happens to meet it).
        let mut t = mk(net, 10, 100);
        t.miner_pkh = pkh;
        t.epoch = epoch;
        t.assignment_public_key = apk;
        t.sybil_work_nonce = n0;
        t.sybil_work_digest = compute_sybil_digest(net, &pkh, epoch, &apk, &n0);
        let res = t.validate(net, 50, 24); // require 24 bits — astronomically unlikely for d0
        assert!(
            res.is_err(),
            "insufficient sybil work rejected at high threshold"
        );
        let _ = n1;
    }

    #[test]
    fn ticket_penalized_not_high_trust_eligible() {
        let net = 1u8;
        let mut t = mk(net, 10, 100);
        t.penalty_status = PenaltyStatus::SuspendedForEpoch.id();
        assert!(!t.eligible_for_high_trust_role());
        t.penalty_status = PenaltyStatus::Clean.id();
        assert!(t.eligible_for_high_trust_role());
    }

    #[test]
    fn ticket_gate_logic_pure() {
        // pure gate (no global env mutation -> race-free under parallel tests).
        assert!(!tickets_gate(0, Some(1), 100), "mainnet hard-off");
        assert!(tickets_gate(1, Some(1), 100), "testnet active");
        assert!(!tickets_gate(1, None, 100), "no activation -> off");
        assert!(!tickets_gate(1, Some(50), 10), "below activation -> off");
        // validate() already enforces mainnet hard-off via expected_network==0:
        let t = mk(1, 10, 100);
        assert!(t.validate(0, 50, 0).is_err(), "validate mainnet hard-off");
    }

    #[test]
    fn ticket_proof_roundtrip_and_validate() {
        use crate::poawx::{ROLE_SUPPORT_CONTRIBUTOR, ROLE_VERIFY_CONTRIBUTOR};
        let net = 1u8;
        let solver = [0xC7u8; 20];
        let apk = [0x02u8; 33];
        let p = TicketProof::new(
            net,
            5,
            ROLE_VERIFY_CONTRIBUTOR,
            solver,
            2,
            100,
            apk,
            [0x44u8; 32],
            0,
        );
        // wire round-trip (fixed size).
        let b = p.serialize();
        assert_eq!(b.len(), TICKET_PROOF_WIRE);
        assert_eq!(TicketProof::deserialize(&b).unwrap(), p);
        // valid against matching context.
        assert!(p
            .validate(net, 5, ROLE_VERIFY_CONTRIBUTOR, &solver, 0, false)
            .is_ok());
        // rejects: wrong net / height / role / solver / expired / mainnet.
        assert!(p
            .validate(2, 5, ROLE_VERIFY_CONTRIBUTOR, &solver, 0, false)
            .is_err());
        assert!(p
            .validate(net, 6, ROLE_VERIFY_CONTRIBUTOR, &solver, 0, false)
            .is_err());
        assert!(p
            .validate(net, 5, ROLE_SUPPORT_CONTRIBUTOR, &solver, 0, false)
            .is_err());
        assert!(p
            .validate(net, 5, ROLE_VERIFY_CONTRIBUTOR, &[0u8; 20], 0, false)
            .is_err());
        assert!(p
            .validate(0, 5, ROLE_VERIFY_CONTRIBUTOR, &solver, 0, false)
            .is_err());
        let exp = TicketProof::new(
            net,
            5,
            ROLE_VERIFY_CONTRIBUTOR,
            solver,
            2,
            5,
            apk,
            [0x44u8; 32],
            0,
        );
        assert!(
            exp.validate(net, 5, ROLE_VERIFY_CONTRIBUTOR, &solver, 0, false)
                .is_err(),
            "expired"
        );
        // tampered sybil nonce -> digest mismatch.
        let mut bad = p.clone();
        bad.sybil_work_nonce[0] ^= 1;
        assert!(bad
            .validate(net, 5, ROLE_VERIFY_CONTRIBUTOR, &solver, 0, false)
            .is_err());
        // insufficient sybil work at a high required threshold.
        assert!(p
            .validate(net, 5, ROLE_VERIFY_CONTRIBUTOR, &solver, 28, false)
            .is_err());
        // penalty enforcement: suspended ineligible for high-trust role.
        let susp = TicketProof::new(
            net,
            5,
            ROLE_VERIFY_CONTRIBUTOR,
            solver,
            2,
            100,
            apk,
            [0x44u8; 32],
            crate::poawx_penalty::PenaltyStatus::SuspendedForEpoch.id(),
        );
        assert!(
            susp.validate(net, 5, ROLE_VERIFY_CONTRIBUTOR, &solver, 0, true)
                .is_err(),
            "suspended high-trust"
        );
        // ...but penalty not enforced -> accepts; and suspended COMPUTE (not high-trust) accepts.
        assert!(susp
            .validate(net, 5, ROLE_VERIFY_CONTRIBUTOR, &solver, 0, false)
            .is_ok());
        let susp_c = TicketProof::new(
            net,
            5,
            crate::poawx::ROLE_COMPUTE_CONTRIBUTOR,
            solver,
            2,
            100,
            apk,
            [0x44u8; 32],
            crate::poawx_penalty::PenaltyStatus::SuspendedForEpoch.id(),
        );
        assert!(
            susp_c
                .validate(
                    net,
                    5,
                    crate::poawx::ROLE_COMPUTE_CONTRIBUTOR,
                    &solver,
                    0,
                    true
                )
                .is_ok(),
            "compute not high-trust"
        );
        // malformed.
        assert!(TicketProof::deserialize(b"short").is_err());
    }

    // ── Phase 32: on-chain ticket store tests ───────────────────────────────

    /// Parameterized valid registration on network `net`.
    fn mk_reg(
        net: u8,
        miner_byte: u8,
        apk_byte: u8,
        epoch: u64,
        h_issue: u64,
        h_exp: u64,
    ) -> PoawxTicketRegistrationV1 {
        let pkh = [miner_byte; 20];
        let apk = [apk_byte; 33];
        let (nonce, digest) = grind_sybil_nonce(net, &pkh, epoch, &apk, 0, 1).unwrap();
        PoawxTicketRegistrationV1::new(MinerWorkTicket {
            version: TICKET_VERSION,
            network_id: net,
            miner_pkh: pkh,
            epoch,
            assignment_public_key: apk,
            sybil_work_nonce: nonce,
            sybil_work_digest: digest,
            recent_reward_score: 0,
            valid_work_count: 0,
            invalid_work_count: 0,
            penalty_status: PenaltyStatus::Clean.id(),
            bond_reference: None,
            issued_height: h_issue,
            expiry_height: h_exp,
        })
    }

    const NET: u8 = 1;

    #[test]
    fn phase32_registration_roundtrip_and_id() {
        let r = mk_reg(NET, 0xA1, 0x02, 7, 1, 100);
        assert!(r.validate(NET, 5, 0).is_ok());
        assert_eq!(
            PoawxTicketRegistrationV1::deserialize(&r.serialize()).unwrap(),
            r
        );
        assert_eq!(r.ticket_id(), r.ticket.digest());
        // mainnet hard-off.
        assert!(r.validate(0, 5, 0).is_err());
    }

    #[test]
    fn phase32_store_apply_and_has_active() {
        let mut store = PoawxTicketStore::new();
        let r = mk_reg(NET, 0xA1, 0x02, 7, 1, 100);
        // applied at height 10 => active from 11.
        assert_eq!(store.apply_registration(&r, 10), Ok(true));
        assert!(
            store.has_active(&[0xA1u8; 20], 7, &[0x02u8; 33], 11),
            "active at H+1"
        );
        assert!(
            !store.has_active(&[0xA1u8; 20], 7, &[0x02u8; 33], 10),
            "not active at the registering height (non-retroactive)"
        );
        // wrong identity not active.
        assert!(!store.has_active(&[0xB2u8; 20], 7, &[0x02u8; 33], 11));
        // re-apply same id is idempotent.
        assert_eq!(store.apply_registration(&r, 10), Ok(false));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn phase32_rate_limit_one_per_miner_and_vrf_per_epoch() {
        let mut store = PoawxTicketStore::new();
        let a = mk_reg(NET, 0xA1, 0x02, 7, 1, 100);
        store.apply_registration(&a, 10).unwrap();
        // Same miner + epoch, different VRF key => miner-epoch rate limit.
        let same_miner = mk_reg(NET, 0xA1, 0x09, 7, 1, 100);
        assert_eq!(
            store.apply_registration(&same_miner, 10),
            Err(PoawxTicketStoreValidationError::MinerEpochRateLimited)
        );
        // Different miner, same VRF key + epoch => vrf-epoch rate limit.
        let same_vrf = mk_reg(NET, 0xB2, 0x02, 7, 1, 100);
        assert_eq!(
            store.apply_registration(&same_vrf, 10),
            Err(PoawxTicketStoreValidationError::VrfEpochRateLimited)
        );
        // Same miner, DIFFERENT epoch => allowed.
        let next_epoch = mk_reg(NET, 0xA1, 0x02, 8, 1, 100);
        assert_eq!(store.apply_registration(&next_epoch, 10), Ok(true));
    }

    #[test]
    fn phase32_expiry_is_deterministic() {
        let mut store = PoawxTicketStore::new();
        let r = mk_reg(NET, 0xA1, 0x02, 7, 1, 50); // expires at height 50
        store.apply_registration(&r, 10).unwrap();
        assert!(store.has_active(&[0xA1u8; 20], 7, &[0x02u8; 33], 49));
        assert!(
            !store.has_active(&[0xA1u8; 20], 7, &[0x02u8; 33], 50),
            "expired at expiry_height"
        );
        // prune at tip 50 removes it.
        store.prune_expired(50);
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn phase32_store_digest_deterministic() {
        let mut a = PoawxTicketStore::new();
        let mut b = PoawxTicketStore::new();
        let r1 = mk_reg(NET, 0xA1, 0x02, 7, 1, 100);
        let r2 = mk_reg(NET, 0xB2, 0x03, 8, 1, 100);
        a.apply_registration(&r1, 10).unwrap();
        a.apply_registration(&r2, 11).unwrap();
        // apply in the other order.
        b.apply_registration(&r2, 11).unwrap();
        b.apply_registration(&r1, 10).unwrap();
        assert_eq!(a.digest(), b.digest(), "store digest order-independent");
    }

    #[test]
    fn phase32_local_cache_does_not_touch_consensus() {
        // The local cache validates + caches but never returns store state.
        let cache = NodeTicketRegistrationCache::new();
        let net = network_id_byte();
        if net == 0 {
            // mainnet: ingest refuses.
            let r = mk_reg(2, 0xA1, 0x02, 7, 1, 100);
            assert!(!cache.ingest(r, 5));
            return;
        }
        let r = mk_reg(net, 0xA1, 0x02, 7, 1, 100);
        assert!(cache.ingest(r.clone(), 5));
        assert!(!cache.ingest(r, 5), "dedup");
        assert_eq!(cache.len(), 1);
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn phase32_gate_mainnet_hard_off() {
        assert!(!ticket_store_gate(0, Some(1), 100), "mainnet off");
        assert!(ticket_store_gate(1, Some(1), 100), "testnet on");
        assert!(!ticket_store_gate(1, None, 100), "no activation off");
    }
}
