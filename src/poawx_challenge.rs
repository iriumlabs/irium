//! Phase 26+: PoAW-X fraud-proof / challenge system (v1 — finality equivocation).
//!
//! A `FraudProofV1` is a self-contained, deterministically-verifiable accusation
//! that a single identity provably misbehaved. v1 implements ONE fraud kind:
//! **finality-vote equivocation** — a committee member who signed two conflicting
//! `FinalityVoteV1`s (same network/height/committee-epoch/vote-type but DIFFERENT
//! `block_hash`). Both signatures are real secp256k1 ECDSA, so any node can verify
//! the proof from the two votes alone (no chain state, no trust in the reporter).
//!
//! A verified proof triggers a real `Slashed` penalty for the offender (see
//! [`crate::poawx_penalty`]): the offender is permanently excluded from high-trust
//! roles and earns zero role-reward weight. The slash is applied in `connect_block`
//! and reverted in `disconnect_tip_block`, and is deterministically rebuilt by
//! chain replay (the proof lives in the block), exactly mirroring the persistent
//! anti-domination pattern.
//!
//! No floats; saturating/integer only; bounded deserialization; domain-separated
//! digest; mainnet-ACTIVE at height >= 50_000 (`network_id == 0` => every gate false). The proof is
//! carried as a trailing-optional `FRD1` section inside `Phase20ReceiptExt`.
//!
//! ⚠ MAINNET STATUS (corrected 2026-07-19): this module's gates are NOT "mainnet
//! hard-off". They route through `activation::poawx_effective_activation`, which on
//! `network_id == 0` IGNORES the env and substitutes the compiled
//! `MAINNET_POAWX_ACTIVATION_HEIGHT = Some(50_000)`. Mainnet is far past that height,
//! so these gates are ACTIVE in production. Any remaining "mainnet hard-off" wording
//! below is stale. The authoritative, height-accurate check is
//! `activation::mainnet_gate_truth`.
#![allow(dead_code)]

use crate::activation::network_id_byte;
use crate::poawx_finality::{FinalityVoteV1, FINALITY_VOTE_WIRE};

/// Domain tag for any future fraud-proof digest commitments.
pub const FRAUD_PROOF_DOMAIN_V1: &[u8] = b"IRIUM_POAWX_FRAUD_PROOF_V1";

/// Magic prefix for the trailing FRD1 fraud-proof ext section.
pub const FRAUD_PROOF_SECTION_MAGIC: &[u8; 4] = b"FRD1";

/// Current fraud-proof wire version.
pub const FRAUD_PROOF_VERSION: u8 = 1;

/// Wire size of one `FraudProofV1`:
/// version(1)+kind(1)+network_id(1)+target_height(8)+offender_pkh(20)+
/// reporter_pkh(20)+vote_a(232)+vote_b(232) = 515.
pub const FRAUD_PROOF_V1_WIRE: usize = 1 + 1 + 1 + 8 + 20 + 20 + FINALITY_VOTE_WIRE * 2;

/// Anti-oversize bound on fraud proofs carried by a single block.
pub const FRAUD_PROOF_MAX_PER_BLOCK: usize = 16;

/// Kinds of provable misbehavior. v1 implements only `FinalityEquivocation`.
/// `InvalidReceipt` and `CandidateEquivocation` are RESERVED slots — `from_id`
/// returns `None` for them so any proof claiming an unimplemented kind fails
/// closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FraudKind {
    /// Two conflicting signed finality votes from the same committee member.
    FinalityEquivocation = 0,
    // RESERVED (NOT implemented in v1):
    //   InvalidReceipt = 1,
    //   CandidateEquivocation = 2,
}

impl FraudKind {
    pub fn id(self) -> u8 {
        self as u8
    }

    /// Only the implemented kind decodes; reserved/unknown ids => `None` (fail-closed).
    pub fn from_id(b: u8) -> Option<Self> {
        match b {
            0 => Some(FraudKind::FinalityEquivocation),
            _ => None,
        }
    }
}

/// A verified offence: the identity to slash + the (height, kind) it is keyed by.
/// Used for de-duplication (offender + target_height + kind) and for the
/// persistent penalty store's apply/revert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FraudOffence {
    pub offender_pkh: [u8; 20],
    pub target_height: u64,
    pub kind: u8,
}

/// A self-contained, deterministically-verifiable fraud proof (v1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FraudProofV1 {
    pub version: u8,
    pub kind: u8,
    pub network_id: u8,
    /// The height at which the offence occurred (== the votes' `target_height`).
    pub target_height: u64,
    /// The identity to slash (== both votes' `member_pkh`).
    pub offender_pkh: [u8; 20],
    /// The challenger that submitted the proof (reward target; may be zero in v1).
    pub reporter_pkh: [u8; 20],
    /// The two conflicting finality votes (canonical order: a.block_hash < b.block_hash).
    pub vote_a: FinalityVoteV1,
    pub vote_b: FinalityVoteV1,
}

impl FraudProofV1 {
    /// Build a finality-equivocation proof from two votes (no validation here;
    /// callers must `verify_fraud_proof`). Votes are placed in canonical order so
    /// each distinct offence has exactly one encoding.
    pub fn finality_equivocation(
        network_id: u8,
        reporter_pkh: [u8; 20],
        vote_a: FinalityVoteV1,
        vote_b: FinalityVoteV1,
    ) -> Self {
        let target_height = vote_a.target_height;
        let offender_pkh = vote_a.member_pkh;
        let (a, b) = if vote_a.block_hash <= vote_b.block_hash {
            (vote_a, vote_b)
        } else {
            (vote_b, vote_a)
        };
        Self {
            version: FRAUD_PROOF_VERSION,
            kind: FraudKind::FinalityEquivocation.id(),
            network_id,
            target_height,
            offender_pkh,
            reporter_pkh,
            vote_a: a,
            vote_b: b,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(FRAUD_PROOF_V1_WIRE);
        o.push(self.version);
        o.push(self.kind);
        o.push(self.network_id);
        o.extend_from_slice(&self.target_height.to_le_bytes());
        o.extend_from_slice(&self.offender_pkh);
        o.extend_from_slice(&self.reporter_pkh);
        o.extend_from_slice(&self.vote_a.serialize());
        o.extend_from_slice(&self.vote_b.serialize());
        o
    }

    pub fn deserialize(raw: &[u8]) -> Result<Self, String> {
        if raw.len() != FRAUD_PROOF_V1_WIRE {
            return Err("fraud proof: bad length".to_string());
        }
        let mut p = 0usize;
        let version = raw[p];
        p += 1;
        let kind = raw[p];
        p += 1;
        let network_id = raw[p];
        p += 1;
        let mut h8 = [0u8; 8];
        h8.copy_from_slice(&raw[p..p + 8]);
        let target_height = u64::from_le_bytes(h8);
        p += 8;
        let mut offender_pkh = [0u8; 20];
        offender_pkh.copy_from_slice(&raw[p..p + 20]);
        p += 20;
        let mut reporter_pkh = [0u8; 20];
        reporter_pkh.copy_from_slice(&raw[p..p + 20]);
        p += 20;
        let vote_a = FinalityVoteV1::deserialize(&raw[p..p + FINALITY_VOTE_WIRE])?;
        p += FINALITY_VOTE_WIRE;
        let vote_b = FinalityVoteV1::deserialize(&raw[p..p + FINALITY_VOTE_WIRE])?;
        Ok(Self {
            version,
            kind,
            network_id,
            target_height,
            offender_pkh,
            reporter_pkh,
            vote_a,
            vote_b,
        })
    }
}

/// Verify a fraud proof PURELY (no chain state). Returns the [`FraudOffence`] to
/// slash on success. Fail-closed: any structural/cryptographic inconsistency is an
/// error. Mainnet hard-off: `network_id == 0` is always rejected.
///
/// `current_height` is the height of the block carrying the proof; the offence's
/// `target_height` must not be in the future relative to it.
pub fn verify_fraud_proof(
    fp: &FraudProofV1,
    network_id: u8,
    current_height: u64,
) -> Result<FraudOffence, String> {
    if network_id == 0 {
        return Err("fraud proof: mainnet hard-off".to_string());
    }
    if fp.version != FRAUD_PROOF_VERSION {
        return Err("fraud proof: bad version".to_string());
    }
    if fp.network_id != network_id {
        return Err("fraud proof: wrong network".to_string());
    }
    let kind = FraudKind::from_id(fp.kind)
        .ok_or_else(|| "fraud proof: unknown/unimplemented kind".to_string())?;
    match kind {
        FraudKind::FinalityEquivocation => {
            verify_finality_equivocation(fp, network_id, current_height)
        }
    }
}

fn verify_finality_equivocation(
    fp: &FraudProofV1,
    network_id: u8,
    current_height: u64,
) -> Result<FraudOffence, String> {
    let a = &fp.vote_a;
    let b = &fp.vote_b;

    // The offence cannot be in the future.
    if fp.target_height > current_height {
        return Err("fraud proof: target height in the future".to_string());
    }

    // Each vote's secp256k1 signature must be valid over its OWN contents
    // (verify binds network/height/block_hash to the vote's self-fields).
    a.verify(network_id, a.target_height, &a.block_hash)
        .map_err(|e| format!("fraud proof: vote_a invalid: {}", e))?;
    b.verify(network_id, b.target_height, &b.block_hash)
        .map_err(|e| format!("fraud proof: vote_b invalid: {}", e))?;

    // Same signer = the offender, and it must match the claimed offender_pkh.
    if a.member_pkh != b.member_pkh {
        return Err("fraud proof: votes from different signers".to_string());
    }
    if a.member_pkh != fp.offender_pkh {
        return Err("fraud proof: offender_pkh mismatch".to_string());
    }

    // Same height (and matching the proof header) + same committee round + same
    // vote type => the two votes are genuinely conflicting, not legitimately
    // distinct across heights/epochs/phases.
    if a.target_height != b.target_height {
        return Err("fraud proof: vote height mismatch".to_string());
    }
    if a.target_height != fp.target_height {
        return Err("fraud proof: target height mismatch".to_string());
    }
    if a.committee_epoch != b.committee_epoch {
        return Err("fraud proof: committee epoch mismatch".to_string());
    }
    if a.vote_type != b.vote_type {
        return Err("fraud proof: vote type mismatch".to_string());
    }

    // The actual equivocation: two DIFFERENT blocks voted at the same slot.
    if a.block_hash == b.block_hash {
        return Err("fraud proof: not an equivocation (same block hash)".to_string());
    }
    // Canonical encoding: exactly one ordering per offence (replay/dup resistance).
    if a.block_hash >= b.block_hash {
        return Err("fraud proof: non-canonical vote ordering".to_string());
    }

    Ok(FraudOffence {
        offender_pkh: fp.offender_pkh,
        target_height: fp.target_height,
        kind: fp.kind,
    })
}

// ── Gates (env, mainnet-ACTIVE at height >= 50_000) — mirror poawx_dominance/poawx_penalty ──────

/// Activation height for fraud-proof enforcement (env-gated; mainnet hard-off).
pub fn fraud_proof_activation_height() -> Option<u64> {
    std::env::var("IRIUM_POAWX_FRAUD_PROOF_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// Pure gate logic (network 0 = mainnet hard-off); param-driven for race-free tests.
pub fn fraud_proof_gate(network_id: u8, activation: Option<u64>, height: u64) -> bool {
    matches!(crate::activation::poawx_effective_activation(network_id, activation), Some(h) if height >= h)
}

/// Whether fraud-proof handling is active at `height`. Mainnet hard-off.
pub fn fraud_proof_active(height: u64) -> bool {
    fraud_proof_gate(network_id_byte(), fraud_proof_activation_height(), height)
}

/// Whether fraud-proof enforcement is REQUIRED (`IRIUM_POAWX_FRAUD_PROOF_REQUIRED=1`).
/// Mainnet hard-off.
pub fn fraud_proof_required() -> bool {
    if network_id_byte() == 0 {
        return true; // mainnet: enforced once the gate is active (height-gated)
    }
    std::env::var("IRIUM_POAWX_FRAUD_PROOF_REQUIRED")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}

/// Pure enforcement gate: active AND required. Param-driven for race-free tests.
pub fn fraud_proof_enforced_gate(
    network_id: u8,
    activation: Option<u64>,
    required: bool,
    height: u64,
) -> bool {
    fraud_proof_gate(network_id, activation, height) && required
}

/// Fraud-proof enforcement is ON only when active at `height` AND required.
/// This single gate governs validation, slashing apply, and reorg revert so that
/// connect/disconnect are exact inverses and no unvalidated slash is ever applied.
/// Mainnet hard-off.
pub fn fraud_proof_enforced(height: u64) -> bool {
    if network_id_byte() == 0 {
        // HALT-TRAP DISARM (2026-07-24, mirrors `tickets_enforced`). On mainnet the fraud-proof
        // VALIDATOR is hard-off: `verify_fraud_proof` returns Err("fraud proof: mainnet hard-off")
        // for network_id == 0 (poawx_challenge.rs:194). But enforcement here was ON
        // (`fraud_proof_required()` is hardcoded true on net-0 AND the gate is active >= 50,000),
        // so the FIRST block carrying a fraud-proof section would be validated -> hard-off Err ->
        // rejected -> chain HALT. That is the enforce-ON / validate-OFF class that halted mainnet
        // 2026-07-23 (CLAUDE.md §12). Kept OFF: fraud-proof sections ride advisory/unvalidated,
        // and slashing apply/revert stay off in lock-step (connect/disconnect remain exact
        // inverses). No-op for the running chain (no live block carries a fraud proof). Re-enable
        // ONLY once the validator is un-hard-off AND proven on a network_id==0 connect_block test.
        return false;
    }
    fraud_proof_enforced_gate(
        network_id_byte(),
        fraud_proof_activation_height(),
        fraud_proof_required(),
        height,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poawx_finality::{FinalityVoteType, FinalityVoteV1};
    use k256::ecdsa::SigningKey;

    const NET: u8 = 2; // devnet

    fn sk(seed: u8) -> SigningKey {
        SigningKey::from_slice(&[seed; 32]).expect("valid scalar")
    }

    /// Build a signed finality vote for the given block hash (default height/epoch).
    fn vote_for(
        signer: &SigningKey,
        height: u64,
        epoch: u64,
        block_hash: [u8; 32],
        vote_type: FinalityVoteType,
    ) -> FinalityVoteV1 {
        FinalityVoteV1::signed(
            signer,
            NET,
            height,
            block_hash,
            [0x07u8; 32], // parent_hash (irrelevant to equivocation)
            epoch,
            [0x09u8; 32], // ticket_digest
            vote_type,
        )
    }

    fn good_proof() -> (FraudProofV1, [u8; 20]) {
        let signer = sk(0x11);
        let a = vote_for(&signer, 100, 5, [0xAAu8; 32], FinalityVoteType::Commit);
        let b = vote_for(&signer, 100, 5, [0xBBu8; 32], FinalityVoteType::Commit);
        let offender = a.member_pkh;
        let fp = FraudProofV1::finality_equivocation(NET, [0x01u8; 20], a, b);
        (fp, offender)
    }

    #[test]
    fn kind_id_roundtrip_and_reserved_fail_closed() {
        assert_eq!(FraudKind::from_id(0), Some(FraudKind::FinalityEquivocation));
        assert_eq!(FraudKind::FinalityEquivocation.id(), 0);
        // reserved-but-unimplemented kinds decode to None (fail-closed).
        assert_eq!(FraudKind::from_id(1), None);
        assert_eq!(FraudKind::from_id(2), None);
        assert_eq!(FraudKind::from_id(255), None);
    }

    #[test]
    fn valid_equivocation_accepts() {
        let (fp, offender) = good_proof();
        let off = verify_fraud_proof(&fp, NET, 200).expect("valid proof");
        assert_eq!(off.offender_pkh, offender);
        assert_eq!(off.target_height, 100);
        assert_eq!(off.kind, FraudKind::FinalityEquivocation.id());
    }

    #[test]
    fn canonical_ordering_is_enforced_by_constructor() {
        // Regardless of arg order, the constructor canonicalizes a < b.
        let signer = sk(0x11);
        let a = vote_for(&signer, 100, 5, [0xBBu8; 32], FinalityVoteType::Commit);
        let b = vote_for(&signer, 100, 5, [0xAAu8; 32], FinalityVoteType::Commit);
        let fp = FraudProofV1::finality_equivocation(NET, [0u8; 20], a, b);
        assert!(fp.vote_a.block_hash < fp.vote_b.block_hash);
        assert!(verify_fraud_proof(&fp, NET, 200).is_ok());
    }

    #[test]
    fn non_canonical_ordering_rejects() {
        let (mut fp, _) = good_proof();
        std::mem::swap(&mut fp.vote_a, &mut fp.vote_b); // now a > b
        let err = verify_fraud_proof(&fp, NET, 200).unwrap_err();
        assert!(err.contains("non-canonical"), "got: {}", err);
    }

    #[test]
    fn same_block_hash_is_not_equivocation() {
        let signer = sk(0x11);
        let a = vote_for(&signer, 100, 5, [0xAAu8; 32], FinalityVoteType::Commit);
        let b = vote_for(&signer, 100, 5, [0xAAu8; 32], FinalityVoteType::Commit);
        // Build the struct directly (constructor would also place them equal).
        let fp = FraudProofV1 {
            version: FRAUD_PROOF_VERSION,
            kind: FraudKind::FinalityEquivocation.id(),
            network_id: NET,
            target_height: 100,
            offender_pkh: a.member_pkh,
            reporter_pkh: [0u8; 20],
            vote_a: a,
            vote_b: b,
        };
        let err = verify_fraud_proof(&fp, NET, 200).unwrap_err();
        assert!(err.contains("not an equivocation"), "got: {}", err);
    }

    #[test]
    fn different_signers_reject() {
        let s1 = sk(0x11);
        let s2 = sk(0x22);
        let a = vote_for(&s1, 100, 5, [0xAAu8; 32], FinalityVoteType::Commit);
        let b = vote_for(&s2, 100, 5, [0xBBu8; 32], FinalityVoteType::Commit);
        let fp = FraudProofV1::finality_equivocation(NET, [0u8; 20], a, b);
        let err = verify_fraud_proof(&fp, NET, 200).unwrap_err();
        assert!(err.contains("different signers"), "got: {}", err);
    }

    #[test]
    fn height_mismatch_rejects() {
        let signer = sk(0x11);
        let a = vote_for(&signer, 100, 5, [0xAAu8; 32], FinalityVoteType::Commit);
        let b = vote_for(&signer, 101, 5, [0xBBu8; 32], FinalityVoteType::Commit);
        let fp = FraudProofV1::finality_equivocation(NET, [0u8; 20], a, b);
        let err = verify_fraud_proof(&fp, NET, 200).unwrap_err();
        assert!(err.contains("height mismatch"), "got: {}", err);
    }

    #[test]
    fn committee_epoch_mismatch_rejects() {
        let signer = sk(0x11);
        let a = vote_for(&signer, 100, 5, [0xAAu8; 32], FinalityVoteType::Commit);
        let b = vote_for(&signer, 100, 6, [0xBBu8; 32], FinalityVoteType::Commit);
        let fp = FraudProofV1::finality_equivocation(NET, [0u8; 20], a, b);
        let err = verify_fraud_proof(&fp, NET, 200).unwrap_err();
        assert!(err.contains("committee epoch mismatch"), "got: {}", err);
    }

    #[test]
    fn vote_type_mismatch_rejects() {
        let signer = sk(0x11);
        let a = vote_for(&signer, 100, 5, [0xAAu8; 32], FinalityVoteType::Commit);
        let b = vote_for(&signer, 100, 5, [0xBBu8; 32], FinalityVoteType::Precommit);
        let fp = FraudProofV1::finality_equivocation(NET, [0u8; 20], a, b);
        let err = verify_fraud_proof(&fp, NET, 200).unwrap_err();
        assert!(err.contains("vote type mismatch"), "got: {}", err);
    }

    #[test]
    fn tampered_signature_rejects() {
        let (mut fp, _) = good_proof();
        fp.vote_a.signature[0] ^= 0xFF; // corrupt the signature
        let err = verify_fraud_proof(&fp, NET, 200).unwrap_err();
        assert!(err.contains("vote_a invalid"), "got: {}", err);
    }

    #[test]
    fn offender_pkh_mismatch_rejects() {
        let (mut fp, _) = good_proof();
        fp.offender_pkh = [0xEEu8; 20];
        let err = verify_fraud_proof(&fp, NET, 200).unwrap_err();
        assert!(err.contains("offender_pkh mismatch"), "got: {}", err);
    }

    #[test]
    fn future_target_height_rejects() {
        let (fp, _) = good_proof(); // target_height = 100
        let err = verify_fraud_proof(&fp, NET, 50).unwrap_err();
        assert!(err.contains("future"), "got: {}", err);
    }

    #[test]
    fn mainnet_hard_off_rejects() {
        let (fp, _) = good_proof();
        let err = verify_fraud_proof(&fp, 0, 200).unwrap_err();
        assert!(err.contains("mainnet hard-off"), "got: {}", err);
    }

    #[test]
    fn wrong_network_rejects() {
        let (fp, _) = good_proof(); // network_id = NET (2)
        let err = verify_fraud_proof(&fp, 3, 200).unwrap_err();
        assert!(err.contains("wrong network"), "got: {}", err);
    }

    #[test]
    fn wire_roundtrip_exact() {
        let (fp, _) = good_proof();
        let bytes = fp.serialize();
        assert_eq!(bytes.len(), FRAUD_PROOF_V1_WIRE);
        let back = FraudProofV1::deserialize(&bytes).expect("roundtrip");
        assert_eq!(back, fp);
    }

    #[test]
    fn truncated_wire_rejects() {
        let (fp, _) = good_proof();
        let bytes = fp.serialize();
        assert!(FraudProofV1::deserialize(&bytes[..bytes.len() - 1]).is_err());
        assert!(FraudProofV1::deserialize(&[]).is_err());
    }

    #[test]
    fn gate_logic_pure() {
        assert!(!fraud_proof_gate(0, Some(1), 100), "below the mainnet activation height; NOT hard-off (see activation::mainnet_gate_truth)");
        assert!(fraud_proof_gate(1, Some(1), 100));
        assert!(!fraud_proof_gate(1, None, 100));
        assert!(!fraud_proof_gate(1, Some(50), 10));
    }

    #[test]
    fn enforced_gate_logic_pure() {
        assert!(fraud_proof_enforced_gate(1, Some(1), true, 100));
        assert!(!fraud_proof_enforced_gate(1, Some(1), false, 100));
        assert!(
            !fraud_proof_enforced_gate(0, Some(1), true, 100),
            "below the mainnet activation height; NOT hard-off (see activation::mainnet_gate_truth)"
        );
        assert!(!fraud_proof_enforced_gate(1, None, true, 100));
        assert!(!fraud_proof_enforced_gate(1, Some(200), true, 100));
    }
}
