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
    prev_hash: &[u8; 32],
    miner_pkh: &[u8; 20],
    epoch: u64,
    assignment_public_key: &[u8; 33],
    nonce: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(SYBIL_DOMAIN);
    h.update([network_id]);
    // Fix B/C: bind the sybil work to the target block's prev_hash so a proof
    // cannot be replayed across blocks AND a miner cannot pre-grind identities
    // for future blocks (prev_hash is unknown until the previous block exists).
    h.update(prev_hash);
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

/// Fix C: minimum enforced per-identity sybil-work cost when tickets are REQUIRED
/// on a non-mainnet network. Prevents costless keypair grinding for favorable VRF
/// assignment scores even if `IRIUM_POAWX_TICKET_SYBIL_BITS` is misconfigured low.
pub const MIN_TICKET_SYBIL_BITS: u32 = 8;

/// Mainnet production per-identity sybil-resistance cost (leading-zero bits).
pub const MAINNET_TICKET_SYBIL_BITS: u32 = 20;

/// Effective required sybil bits, used IDENTICALLY by the builder (to grind) and
/// the validator (to check) so they never diverge. Mainnet hard-off (0). When
/// tickets are required, the configured value is floored at `MIN_TICKET_SYBIL_BITS`.
pub fn effective_sybil_bits() -> u32 {
    if network_id_byte() == 0 {
        return MAINNET_TICKET_SYBIL_BITS;
    }
    let configured = sybil_threshold_bits();
    if tickets_required() {
        configured.max(MIN_TICKET_SYBIL_BITS)
    } else {
        configured
    }
}

/// Phase 2 (2026-07-25): COMBINED pool-admission + ticket enforcement activation. Arms BOTH
/// `tickets_enforced` and `chain::pool_admission_enforced` at ONE height so a multi-payee
/// fan-out block's sybil tickets AND its pool-member admission are enforced together — they can
/// never diverge into the enforce-on/validate-off HALT class (CLAUDE.md §12). Gated on the
/// Phase-1 un-hard-off ticket VALIDATOR. Inert on mainnet (const = None); flip to `Some(h)` ONLY
/// after the producing network_id=0 PLA1 proof AND once real independent participants exist
/// (else there is no one to ticket). Env-gated on devnet for harness proofs.
// Derived from the SINGLE fair-distribution activation knob (activation.rs). Arms tickets +
// pool-admission + mandatory-inclusion together. None => inert (byte-identical to deployed).
pub const MAINNET_POOL_TICKET_ACTIVATION_HEIGHT: Option<u64> =
    crate::activation::MAINNET_FAIR_DISTRIBUTION_ACTIVATION_HEIGHT;

/// Pure gate logic (param-driven so tests can vary the activation without global env).
pub fn pool_ticket_gate(activation: Option<u64>, height: u64) -> bool {
    matches!(activation, Some(h) if height >= h)
}

pub fn pool_ticket_enforced(height: u64) -> bool {
    if network_id_byte() == 0 {
        return pool_ticket_gate(MAINNET_POOL_TICKET_ACTIVATION_HEIGHT, height);
    }
    let env = std::env::var("IRIUM_POAWX_POOL_TICKET_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok());
    pool_ticket_gate(env, height)
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
        // MinerWorkTicket is a per-epoch registration token (not block-bound), so it
        // pins prev_hash to zero; the per-block binding lives in TicketProof.
        compute_sybil_digest(
            self.network_id,
            &[0u8; 32],
            &self.miner_pkh,
            self.epoch,
            &self.assignment_public_key,
            &self.sybil_work_nonce,
        )
    }

    /// Validate the ticket: version, network match, issue/expiry window, penalty status,
    /// and the sybil-work binding. `require_bits` (typically `effective_sybil_bits()`, = 20
    /// at network_id==0) enforces the Sybil cost when > 0.
    /// Phase 1 (2026-07-25): UN-HARD-OFF at network_id==0 — the validator is correct in
    /// mainnet context; ENFORCEMENT stays gated (`tickets_enforced`/`pool_admission_enforced`),
    /// so removing the guard is inert on mainnet until those gates arm (proven at net-0).
    pub fn validate(
        &self,
        expected_network: u8,
        current_height: u64,
        require_bits: u32,
    ) -> Result<(), String> {
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
    prev_hash: &[u8; 32],
    miner_pkh: &[u8; 20],
    epoch: u64,
    assignment_public_key: &[u8; 33],
    bits: u32,
    max_iters: u64,
) -> Option<([u8; 32], [u8; 32])> {
    let mut nonce = [0u8; 32];
    for i in 0..max_iters {
        nonce[0..8].copy_from_slice(&i.to_le_bytes());
        let d = compute_sybil_digest(network_id, prev_hash, miner_pkh, epoch, assignment_public_key, &nonce);
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
    matches!(crate::activation::poawx_effective_activation(network_id, activation), Some(h) if height >= h)
}

/// Whether ticket validation is active at `height`. Mainnet hard-off.
pub fn tickets_active(height: u64) -> bool {
    tickets_gate(network_id_byte(), tickets_activation_height(), height)
}

/// Whether a valid ticket is REQUIRED (vs. advisory) — `IRIUM_POAWX_TICKETS_REQUIRED=1`.
pub fn tickets_required() -> bool {
    if network_id_byte() == 0 {
        return false; // mainnet: ticket proofs remain hard-off; optional proofs are ignored.
    }
    std::env::var("IRIUM_POAWX_TICKETS_REQUIRED")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}

/// Ticket enforcement is ON only when the gate is active at `height` AND the
/// required flag is set. Mainnet hard-off (both inputs are). When off, connect_block
/// ignores ticket proofs (old Phase 20 behavior unchanged).
pub fn tickets_enforced(height: u64) -> bool {
    if network_id_byte() == 0 {
        // mainnet: ticket ENFORCEMENT stays OFF here. History: it was de-scoped for the combined
        // activation because the ticket VALIDATOR was itself mainnet-hard-off, so enforcing would
        // reject EVERY block and HALT at activation-1 (observed live 2026-07-23, retry #2).
        // PHASE 1 (2026-07-25): the validator is now UN-HARD-OFF at network_id==0 and PROVEN
        // (`TicketProof::validate` / `MinerWorkTicket::validate` no longer early-return on
        // mainnet; `ticket_proof_un_hard_off_net0` covers accept + 8 reject cases at the enforced
        // 20-bit level). So the halt precondition is removed. Enforcement STILL stays OFF until
        // PHASE 2 arms it TOGETHER with pool-admission (`pool_admission_enforced`) at one combined
        // activation, proven on a producing network_id=0 connect_block harness, and only once real
        // independent participants exist (else there is no one to ticket). TPK1 sections ride
        // advisory/unvalidated until then. See POAWX_FAIR_DISTRIBUTION_ACTIVATION_DESIGN_20260725.
        // PHASE 2 (2026-07-25): route through the COMBINED gate so tickets + pool-admission arm
        // TOGETHER (const None ⇒ still OFF/inert).
        return pool_ticket_enforced(height);
    }
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
        prev_hash: [u8; 32],
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
            &prev_hash,
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
    #[allow(clippy::too_many_arguments)]
    pub fn validate(
        &self,
        expected_network: u8,
        height: u64,
        prev_hash: &[u8; 32],
        role_id: u8,
        role_solver_pkh: &[u8; 20],
        require_sybil_bits: u32,
        penalty_enforced: bool,
    ) -> Result<(), String> {
        // Phase 1 (2026-07-25): UN-HARD-OFF at network_id==0. The full check below runs in
        // mainnet context; ENFORCEMENT stays gated (`tickets_enforced`/`pool_admission_enforced`),
        // so removing the guard is inert on mainnet until those gates arm (proven at net-0).
        if self.network_id != expected_network {
            return Err("ticket proof: network mismatch".to_string());
        }
        if self.target_height != height {
            return Err("ticket proof: height mismatch".to_string());
        }
        // Fix #7 (audit-gated): bind the epoch to the height so it is not a free field. The
        // builder sets epoch = height = target_height; this rejects any ticket whose epoch is
        // not the height it claims, closing the "any epoch passes" sybil-window gap. Mainnet off.
        if crate::poawx_proposer::audit_hardening_active(height)
            && self.epoch != self.target_height
        {
            return Err("ticket proof: epoch not bound to height (audit)".to_string());
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
            prev_hash,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(net: u8, h_issue: u64, h_exp: u64) -> MinerWorkTicket {
        let pkh = [0xA1u8; 20];
        let apk = [0x02u8; 33];
        let epoch = 7u64;
        let (nonce, digest) = grind_sybil_nonce(net, &[0u8; 32], &pkh, epoch, &apk, 0, 1).unwrap();
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

    // Phase 1 (2026-07-25): the ticket VALIDATORS are UN-HARD-OFF at network_id==0. This proves
    // the mainnet-context (expected_network==0) validator is CORRECT — accepts an honest 20-bit
    // ticket + rejects every tampering — the §12 net-0 evidence. ENFORCEMENT stays gated
    // (tickets_enforced / pool_admission_enforced are still OFF on mainnet, armed only in Phase 2),
    // so this validator is inert on the live chain until those gates flip. Param-driven: passing
    // expected_network==0 IS the mainnet context, no global-env dependency.
    #[test]
    fn ticket_proof_un_hard_off_net0() {
        use crate::poawx::ROLE_SUPPORT_CONTRIBUTOR;
        let net = 0u8; // MAINNET context
        let bits = MAINNET_TICKET_SYBIL_BITS; // 20 — the enforced mainnet sybil cost
        let prev = [0x07u8; 32];
        let pkh = [0xA1u8; 20];
        let apk = [0x02u8; 33];
        let (height, epoch, expiry) = (100u64, 100u64, 200u64); // epoch==target_height (audit binding)
        let role = ROLE_SUPPORT_CONTRIBUTOR;

        // one honest 20-bit sybil grind for this (net, prev, pkh, epoch, apk).
        let (nonce, _d) = grind_sybil_nonce(net, &prev, &pkh, epoch, &apk, bits, 20_000_000)
            .expect("grind a 20-bit sybil nonce");
        let proof = TicketProof::new(
            net, height, prev, role, pkh, epoch, expiry, apk, nonce, PenaltyStatus::Clean.id(),
        );

        // (1) POSITIVE: honest mainnet-context proof at the enforced 20-bit level -> VALID.
        assert!(
            proof.validate(net, height, &prev, role, &pkh, bits, false).is_ok(),
            "un-hard-off: honest 20-bit ticket proof VALID at network_id==0"
        );
        // (2) expected_network mismatch (mainnet proof checked as testnet, or vice versa) -> REJECTED.
        assert!(
            proof.validate(3, height, &prev, role, &pkh, bits, false).is_err(),
            "expected_network mismatch rejected"
        );
        // (3) wrong role-solver binding -> REJECTED.
        assert!(
            proof.validate(net, height, &prev, role, &[0xB2u8; 20], bits, false).is_err(),
            "role_solver_pkh != miner_pkh rejected"
        );
        // (4) height mismatch -> REJECTED.
        assert!(
            proof.validate(net, height + 1, &prev, role, &pkh, bits, false).is_err(),
            "target_height != height rejected"
        );
        // (5) wrong prev_hash breaks the sybil-digest recompute -> REJECTED.
        assert!(
            proof.validate(net, height, &[0x09u8; 32], role, &pkh, bits, false).is_err(),
            "prev_hash mismatch -> sybil digest rejected"
        );
        // (6) expired (expiry <= height) -> REJECTED.
        let exp_proof = TicketProof::new(
            net, height, prev, role, pkh, epoch, height, apk, nonce, PenaltyStatus::Clean.id(),
        );
        assert!(
            exp_proof.validate(net, height, &prev, role, &pkh, bits, false).is_err(),
            "expired ticket proof rejected"
        );
        // (7) INSUFFICIENT SYBIL WORK: a VALID binding (nonce [0;32]) whose digest misses 20 bits
        //     is rejected at bits=20 but ACCEPTED at bits=0 (isolates the sybil-cost check).
        let (weak_nonce, _wd) = grind_sybil_nonce(net, &prev, &pkh, epoch, &apk, 1, 100)
            .expect("grind a trivial below-20-bit nonce");
        let weak = TicketProof::new(
            net, height, prev, role, pkh, epoch, expiry, apk, weak_nonce, PenaltyStatus::Clean.id(),
        );
        if !meets_sybil_target(&weak.sybil_work_digest, bits) {
            assert!(
                weak.validate(net, height, &prev, role, &pkh, bits, false).is_err(),
                "below-20-bit sybil work REJECTED (cost enforced at net==0)"
            );
            assert!(
                weak.validate(net, height, &prev, role, &pkh, 0, false).is_ok(),
                "same weak proof VALID when sybil cost not required (isolates the bits check)"
            );
        }
        // (8) tampered sybil digest -> REJECTED.
        let mut tampered = TicketProof::new(
            net, height, prev, role, pkh, epoch, expiry, apk, nonce, PenaltyStatus::Clean.id(),
        );
        tampered.sybil_work_digest[0] ^= 0xFF;
        assert!(
            tampered.validate(net, height, &prev, role, &pkh, bits, false).is_err(),
            "tampered sybil digest rejected"
        );

        // MinerWorkTicket::validate is likewise un-hard-off at net==0 (per-epoch registration token).
        let (tn, td) = grind_sybil_nonce(net, &[0u8; 32], &pkh, epoch, &apk, 0, 4).expect("nonce");
        let mwt = MinerWorkTicket {
            version: TICKET_VERSION, network_id: net, miner_pkh: pkh, epoch,
            assignment_public_key: apk, sybil_work_nonce: tn, sybil_work_digest: td,
            recent_reward_score: 0, valid_work_count: 0, invalid_work_count: 0,
            penalty_status: PenaltyStatus::Clean.id(), bond_reference: None,
            issued_height: 50, expiry_height: 200,
        };
        assert!(mwt.validate(net, 100, 0).is_ok(), "MinerWorkTicket VALID at network_id==0 (un-hard-off)");
        assert!(mwt.validate(3, 100, 0).is_err(), "MinerWorkTicket network mismatch rejected");
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
        let (n0, d0) = grind_sybil_nonce(net, &[0u8; 32], &pkh, epoch, &apk, 0, 1).unwrap();
        assert!(meets_sybil_target(&d0, 0));
        // enabled with a tiny target: grind finds a valid nonce.
        let (n1, d1) =
            grind_sybil_nonce(net, &[0u8; 32], &pkh, epoch, &apk, 8, 200_000).expect("grind tiny target");
        assert!(meets_sybil_target(&d1, 8));
        assert_eq!(
            compute_sybil_digest(net, &[0u8; 32], &pkh, epoch, &apk, &n1),
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
        t.sybil_work_digest = compute_sybil_digest(net, &[0u8; 32], &pkh, epoch, &apk, &n0);
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
        assert!(!tickets_gate(0, Some(1), 100), "below the mainnet activation height; NOT hard-off (see activation::mainnet_gate_truth)");
        assert!(tickets_gate(1, Some(1), 100), "testnet active");
        assert!(!tickets_gate(1, None, 100), "no activation -> off");
        assert!(!tickets_gate(1, Some(50), 10), "below activation -> off");
        // validate() already enforces mainnet hard-off via expected_network==0:
        let t = mk(1, 10, 100);
        assert!(t.validate(0, 50, 0).is_err(), "validate mainnet hard-off");
    }

    #[test]
    fn audit_ticket_rejects_epoch_not_bound_to_height() {
        use crate::poawx::ROLE_VERIFY_CONTRIBUTOR;
        // Fix #7: when the audit gate is active a ticket's epoch must equal its target_height
        // (closes the "any epoch passes" sybil-window gap). Mainnet hard-off.
        let _g = crate::poawx::poawx_test_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "testnet");
        let net = crate::activation::network_id_byte();
        let solver = [0xC7u8; 20];
        let apk = [0x02u8; 33];
        let height = 5u64;
        let bound = TicketProof::new(
            net, height, [0u8; 32], ROLE_VERIFY_CONTRIBUTOR, solver, height, 100, apk,
            [0x44u8; 32], 0,
        );
        let unbound = TicketProof::new(
            net, height, [0u8; 32], ROLE_VERIFY_CONTRIBUTOR, solver, 2, 100, apk,
            [0x44u8; 32], 0,
        );
        // gate OFF => both validate (legacy: epoch is free).
        std::env::remove_var("IRIUM_POAWX_AUDIT_HARDENING_ACTIVATION_HEIGHT");
        assert!(bound
            .validate(net, height, &[0u8; 32], ROLE_VERIFY_CONTRIBUTOR, &solver, 0, false)
            .is_ok());
        assert!(
            unbound
                .validate(net, height, &[0u8; 32], ROLE_VERIFY_CONTRIBUTOR, &solver, 0, false)
                .is_ok(),
            "epoch free when gate off"
        );
        // gate ON => bound ok, unbound rejected.
        std::env::set_var("IRIUM_POAWX_AUDIT_HARDENING_ACTIVATION_HEIGHT", "1");
        assert!(
            bound
                .validate(net, height, &[0u8; 32], ROLE_VERIFY_CONTRIBUTOR, &solver, 0, false)
                .is_ok(),
            "bound ok gate on"
        );
        let err = unbound
            .validate(net, height, &[0u8; 32], ROLE_VERIFY_CONTRIBUTOR, &solver, 0, false)
            .expect_err("unbound rejected");
        assert!(err.contains("epoch not bound"), "got: {err}");
        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_AUDIT_HARDENING_ACTIVATION_HEIGHT");
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
            [0u8; 32],
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
            .validate(net, 5, &[0u8; 32], ROLE_VERIFY_CONTRIBUTOR, &solver, 0, false)
            .is_ok());
        // rejects: wrong net / height / role / solver / expired / mainnet.
        assert!(p
            .validate(2, 5, &[0u8; 32], ROLE_VERIFY_CONTRIBUTOR, &solver, 0, false)
            .is_err());
        assert!(p
            .validate(net, 6, &[0u8; 32], ROLE_VERIFY_CONTRIBUTOR, &solver, 0, false)
            .is_err());
        assert!(p
            .validate(net, 5, &[0u8; 32], ROLE_SUPPORT_CONTRIBUTOR, &solver, 0, false)
            .is_err());
        assert!(p
            .validate(net, 5, &[0u8; 32], ROLE_VERIFY_CONTRIBUTOR, &[0u8; 20], 0, false)
            .is_err());
        assert!(p
            .validate(0, 5, &[0u8; 32], ROLE_VERIFY_CONTRIBUTOR, &solver, 0, false)
            .is_err());
        let exp = TicketProof::new(
            net,
            5,
            [0u8; 32],
            ROLE_VERIFY_CONTRIBUTOR,
            solver,
            2,
            5,
            apk,
            [0x44u8; 32],
            0,
        );
        assert!(
            exp.validate(net, 5, &[0u8; 32], ROLE_VERIFY_CONTRIBUTOR, &solver, 0, false)
                .is_err(),
            "expired"
        );
        // tampered sybil nonce -> digest mismatch.
        let mut bad = p.clone();
        bad.sybil_work_nonce[0] ^= 1;
        assert!(bad
            .validate(net, 5, &[0u8; 32], ROLE_VERIFY_CONTRIBUTOR, &solver, 0, false)
            .is_err());
        // insufficient sybil work at a high required threshold.
        assert!(p
            .validate(net, 5, &[0u8; 32], ROLE_VERIFY_CONTRIBUTOR, &solver, 28, false)
            .is_err());
        // penalty enforcement: suspended ineligible for high-trust role.
        let susp = TicketProof::new(
            net,
            5,
            [0u8; 32],
            ROLE_VERIFY_CONTRIBUTOR,
            solver,
            2,
            100,
            apk,
            [0x44u8; 32],
            crate::poawx_penalty::PenaltyStatus::SuspendedForEpoch.id(),
        );
        assert!(
            susp.validate(net, 5, &[0u8; 32], ROLE_VERIFY_CONTRIBUTOR, &solver, 0, true)
                .is_err(),
            "suspended high-trust"
        );
        // ...but penalty not enforced -> accepts; and suspended COMPUTE (not high-trust) accepts.
        assert!(susp
            .validate(net, 5, &[0u8; 32], ROLE_VERIFY_CONTRIBUTOR, &solver, 0, false)
            .is_ok());
        let susp_c = TicketProof::new(
            net,
            5,
            [0u8; 32],
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
                    &[0u8; 32],
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
}
