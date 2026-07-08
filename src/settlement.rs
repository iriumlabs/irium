use crate::tx::{encode_htlcv1_script, parse_htlcv1_script, HtlcV1Output, Transaction, TxOutput};
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub const AGREEMENT_OBJECT_VERSION: u32 = 1;
pub const AGREEMENT_AUDIT_RECORD_VERSION: u32 = 1;
pub const AGREEMENT_STATEMENT_VERSION: u32 = 1;
pub const AGREEMENT_ARTIFACT_VERIFICATION_VERSION: u32 = 1;
pub const AGREEMENT_SHARE_PACKAGE_VERSION: u32 = 1;
pub const AGREEMENT_SHARE_PACKAGE_VERIFICATION_VERSION: u32 = 1;
pub const AGREEMENT_BUNDLE_VERSION: u32 = 1;
pub const AGREEMENT_SIGNATURE_VERSION: u32 = 1;
pub const AGREEMENT_AUDIT_CSV_SCHEMA: &str = "agreement_audit_csv_v1";
pub const AGREEMENT_NETWORK_MARKER: &str = "IRIUM";
pub const AGREEMENT_SCHEMA_ID_V1: &str = "irium.phase1.canonical.v1";
pub const AGREEMENT_BUNDLE_SCHEMA_ID_V1: &str = "irium.phase1.bundle.v1";
pub const AGREEMENT_SHARE_PACKAGE_SCHEMA_ID_V1: &str = "irium.phase1.share_package.v1";
pub const AGREEMENT_SIGNATURE_TYPE_SECP256K1: &str = "secp256k1_ecdsa_sha256";
pub const AGREEMENT_ANCHOR_PREFIX: &str = "agr1:";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgreementTemplateType {
    SimpleReleaseRefund,
    MilestoneSettlement,
    RefundableDeposit,
    OtcSettlement,
    MerchantDelayedSettlement,
    ContractorMilestone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgreementLifecycleState {
    Draft,
    Proposed,
    Funded,
    PartiallyReleased,
    Released,
    Refunded,
    Expired,
    Cancelled,
    DisputedMetadataOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgreementAnchorRole {
    Funding,
    Release,
    Refund,
    MilestoneRelease,
    DepositLock,
    CollateralLock,
    OtcSettlement,
    MerchantSettlement,
    DisputeRaise,
    DisputeEvidence,
    DisputeResolve,
    ResolverRegister,
}

impl AgreementAnchorRole {
    pub fn short_code(self) -> &'static str {
        match self {
            Self::Funding => "f",
            Self::Release => "l",
            Self::Refund => "r",
            Self::MilestoneRelease => "m",
            Self::DepositLock => "d",
            Self::CollateralLock => "c",
            Self::OtcSettlement => "o",
            Self::MerchantSettlement => "t",
            Self::DisputeRaise => "e",
            Self::DisputeEvidence => "v",
            Self::DisputeResolve => "x",
            Self::ResolverRegister => "y",
        }
    }

    pub fn from_short_code(v: &str) -> Option<Self> {
        match v {
            "f" => Some(Self::Funding),
            "l" => Some(Self::Release),
            "r" => Some(Self::Refund),
            "m" => Some(Self::MilestoneRelease),
            "d" => Some(Self::DepositLock),
            "c" => Some(Self::CollateralLock),
            "o" => Some(Self::OtcSettlement),
            "t" => Some(Self::MerchantSettlement),
            "e" => Some(Self::DisputeRaise),
            "v" => Some(Self::DisputeEvidence),
            "x" => Some(Self::DisputeResolve),
            "y" => Some(Self::ResolverRegister),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementParty {
    pub party_id: String,
    pub display_name: String,
    pub address: String,
    #[serde(default)]
    pub role: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementDeadlines {
    #[serde(default)]
    pub settlement_deadline: Option<u64>,
    #[serde(default)]
    pub refund_deadline: Option<u64>,
    #[serde(default)]
    pub dispute_window: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementReleaseCondition {
    pub mode: String,
    #[serde(default)]
    pub secret_hash_hex: Option<String>,
    #[serde(default)]
    pub release_authorizer: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementRefundCondition {
    pub refund_address: String,
    pub timeout_height: u64,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementMilestone {
    pub milestone_id: String,
    pub title: String,
    pub amount: u64,
    pub recipient_address: String,
    pub refund_address: String,
    pub secret_hash_hex: String,
    pub timeout_height: u64,
    #[serde(default)]
    pub metadata_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementDepositRule {
    pub amount: u64,
    pub beneficiary_address: String,
    pub refund_address: String,
    pub timeout_height: u64,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AgreementBundleChainObservationSnapshot {
    #[serde(default)]
    pub observed_at: Option<u64>,
    #[serde(default)]
    pub linked_transactions: Vec<AgreementLinkedTx>,
    #[serde(default)]
    pub funding_txids: Vec<String>,
    #[serde(default)]
    pub linked_tx_count: usize,
    #[serde(default)]
    pub anchor_notice: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AgreementBundleArtifacts {
    #[serde(default)]
    pub metadata_summary: Option<String>,
    #[serde(default)]
    pub audit: Option<Value>,
    #[serde(default)]
    pub statement: Option<Value>,
    #[serde(default)]
    pub chain_observation_snapshot: Option<AgreementBundleChainObservationSnapshot>,
    #[serde(default)]
    pub external_document_hashes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementObject {
    pub agreement_id: String,
    #[serde(default = "default_agreement_version")]
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_id: Option<String>,
    pub template_type: AgreementTemplateType,
    pub parties: Vec<AgreementParty>,
    pub payer: String,
    pub payee: String,
    #[serde(default)]
    pub mediator_reference: Option<String>,
    pub total_amount: u64,
    #[serde(default = "default_network_marker")]
    pub network_marker: String,
    pub creation_time: u64,
    pub deadlines: AgreementDeadlines,
    pub release_conditions: Vec<AgreementReleaseCondition>,
    pub refund_conditions: Vec<AgreementRefundCondition>,
    #[serde(default)]
    pub milestones: Vec<AgreementMilestone>,
    #[serde(default)]
    pub deposit_rule: Option<AgreementDepositRule>,
    #[serde(default)]
    pub proof_policy_reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset_reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose_reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refund_summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestor_reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolver_reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    pub document_hash: String,
    #[serde(default)]
    pub metadata_hash: Option<String>,
    #[serde(default)]
    pub invoice_reference: Option<String>,
    #[serde(default)]
    pub external_reference: Option<String>,
    #[serde(default)]
    pub disputed_metadata_only: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_resolver: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_resolver: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_resolver_fee: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_resolver_fee: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementSummary {
    pub agreement_hash: String,
    pub total_amount: u64,
    pub template_type: AgreementTemplateType,
    pub milestone_count: usize,
    pub uses_htlc_timeout: bool,
    pub has_deposit_rule: bool,
    pub canonical_json: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementAnchor {
    pub agreement_hash: String,
    pub role: AgreementAnchorRole,
    #[serde(default)]
    pub milestone_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementLinkedTx {
    pub txid: String,
    pub role: AgreementAnchorRole,
    #[serde(default)]
    pub milestone_id: Option<String>,
    #[serde(default)]
    pub height: Option<u64>,
    pub confirmed: bool,
    #[serde(default)]
    pub value: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementMilestoneStatus {
    pub milestone_id: String,
    pub title: String,
    pub amount: u64,
    pub funded: bool,
    pub released: bool,
    pub refunded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementLifecycleView {
    pub state: AgreementLifecycleState,
    pub agreement_hash: String,
    pub funded_amount: u64,
    pub released_amount: u64,
    pub refunded_amount: u64,
    pub milestones: Vec<AgreementMilestoneStatus>,
    pub linked_txs: Vec<AgreementLinkedTx>,
    pub trust_model_note: String,
}

// ============================================================
// GROUP F: Escrow Receipt — signed snapshot export
// ============================================================

pub const ESCROW_RECEIPT_SCHEMA_ID: &str = "irium.escrow_receipt.v1";
pub const ESCROW_RECEIPT_VERSION: u32 = 1;

/// Per-tx reference inside an escrow receipt. Carries the txid plus
/// the height at which it was confirmed and (for milestone templates)
/// the milestone_id, so a single receipt can describe N funding /
/// release / refund legs without flattening them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxidWithHeight {
    pub txid: String,
    #[serde(default)]
    pub height: Option<u64>,
    #[serde(default)]
    pub milestone_id: Option<String>,
    pub value: u64,
}

/// Proof reference carried in a receipt. Only the minimal proof
/// metadata is exported - the full evidence payload remains in the
/// proof store and is referenced by proof_id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowReceiptProofRef {
    pub proof_id: String,
    pub proof_type: String,
    pub attestation_time: u64,
    #[serde(default)]
    pub anchored_at_height: Option<u64>,
    #[serde(default)]
    pub anchor_txid: Option<String>,
}

/// Dispute reference carried in a receipt. The full resolution message
/// is replaced with its SHA-256 hash so the receipt does not leak the
/// resolver's private rationale - the message remains in iriumd's
/// dispute store for the parties to inspect separately.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowReceiptDisputeRef {
    pub resolver_address: String,
    pub resolver_role: String,
    pub outcome: String,
    pub resolved_at_height: u64,
    pub message_hash: String,
    #[serde(default)]
    pub anchor_txid: Option<String>,
}

/// Signature envelope attached by the exporter (a party to the
/// agreement) to a finished escrow receipt. Distinct from
/// AgreementSignatureEnvelope because the receipt has no
/// target_type/target_hash semantics - it signs the canonical receipt
/// bytes directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExporterSignatureEnvelope {
    pub version: u32,
    pub signer_public_key: String,
    pub signer_address: String,
    pub signature_type: String,
    /// Hex-encoded 64-byte secp256k1 signature. Cleared during canonical
    /// serialization so signing/verifying are deterministic.
    pub signature: String,
    /// Hex-encoded SHA-256 of the canonical receipt bytes used as
    /// signing input. Cleared during canonical serialization.
    pub payload_hash: String,
}

/// Signed, exportable snapshot of an agreement's full on-chain story.
/// Field set is fixed by the GROUP F spec; deposit-template receipts
/// simply omit some funding/release fields. Schema bumps go through
/// ESCROW_RECEIPT_SCHEMA_ID + ESCROW_RECEIPT_VERSION.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementEscrowReceipt {
    pub schema_id: String,
    pub version: u32,
    pub agreement_id: String,
    pub agreement_hash: String,
    pub template_type: AgreementTemplateType,
    pub parties: Vec<AgreementParty>,
    pub payer_address: String,
    pub payee_address: String,
    pub total_amount: u64,
    pub final_state: AgreementLifecycleState,
    pub funded_amount: u64,
    pub released_amount: u64,
    pub refunded_amount: u64,
    #[serde(default)]
    pub funding_txids: Vec<TxidWithHeight>,
    #[serde(default)]
    pub release_txids: Vec<TxidWithHeight>,
    #[serde(default)]
    pub refund_txids: Vec<TxidWithHeight>,
    #[serde(default)]
    pub resolved_height: Option<u64>,
    #[serde(default)]
    pub milestones: Vec<AgreementMilestoneStatus>,
    #[serde(default)]
    pub proofs: Vec<EscrowReceiptProofRef>,
    #[serde(default)]
    pub dispute: Option<EscrowReceiptDisputeRef>,
    pub linked_txs: Vec<AgreementLinkedTx>,
    pub export_timestamp: u64,
    pub exporter_address: String,
    pub exporter_pubkey_hex: String,
    pub exporter_signature: ExporterSignatureEnvelope,
}

/// Build an unsigned escrow receipt by joining the local AgreementObject
/// with chain-observed lifecycle data, proofs (with optional anchor
/// info) and an optional dispute resolution (with optional anchor info).
/// The returned receipt has an empty exporter_signature.signature /
/// payload_hash; callers fill them via escrow_receipt_signing_digest +
/// secp256k1 sign before serializing.
pub fn build_escrow_receipt_unsigned(
    agreement: &AgreementObject,
    agreement_hash: &str,
    lifecycle: &AgreementLifecycleView,
    proofs: &[(SettlementProof, Option<(u64, Option<String>)>)],
    dispute: Option<(&DisputeResolution, Option<String>)>,
    exporter_address: &str,
    exporter_pubkey_hex: &str,
    export_timestamp: u64,
) -> AgreementEscrowReceipt {
    let funding_txids: Vec<TxidWithHeight> = lifecycle
        .linked_txs
        .iter()
        .filter(|t| {
            matches!(
                t.role,
                AgreementAnchorRole::Funding
                    | AgreementAnchorRole::DepositLock
                    | AgreementAnchorRole::OtcSettlement
                    | AgreementAnchorRole::MerchantSettlement
            )
        })
        .map(|t| TxidWithHeight {
            txid: t.txid.clone(),
            height: t.height,
            milestone_id: t.milestone_id.clone(),
            value: t.value,
        })
        .collect();
    let release_txids: Vec<TxidWithHeight> = lifecycle
        .linked_txs
        .iter()
        .filter(|t| {
            matches!(
                t.role,
                AgreementAnchorRole::Release | AgreementAnchorRole::MilestoneRelease
            )
        })
        .map(|t| TxidWithHeight {
            txid: t.txid.clone(),
            height: t.height,
            milestone_id: t.milestone_id.clone(),
            value: t.value,
        })
        .collect();
    let refund_txids: Vec<TxidWithHeight> = lifecycle
        .linked_txs
        .iter()
        .filter(|t| matches!(t.role, AgreementAnchorRole::Refund))
        .map(|t| TxidWithHeight {
            txid: t.txid.clone(),
            height: t.height,
            milestone_id: t.milestone_id.clone(),
            value: t.value,
        })
        .collect();
    let resolved_height = release_txids
        .iter()
        .chain(refund_txids.iter())
        .filter_map(|t| t.height)
        .max();
    let payer_address = agreement
        .parties
        .iter()
        .find(|p| p.party_id == agreement.payer)
        .map(|p| p.address.clone())
        .unwrap_or_default();
    let payee_address = agreement
        .parties
        .iter()
        .find(|p| p.party_id == agreement.payee)
        .map(|p| p.address.clone())
        .unwrap_or_default();
    let proof_refs: Vec<EscrowReceiptProofRef> = proofs
        .iter()
        .map(|(p, anchor)| EscrowReceiptProofRef {
            proof_id: p.proof_id.clone(),
            proof_type: p.proof_type.clone(),
            attestation_time: p.attestation_time,
            anchored_at_height: anchor.as_ref().map(|(h, _)| *h),
            anchor_txid: anchor.as_ref().and_then(|(_, t)| t.clone()),
        })
        .collect();
    let dispute_ref = dispute.map(|(r, anchor_txid)| {
        let message_hash = hex::encode(Sha256::digest(r.message.as_bytes()));
        EscrowReceiptDisputeRef {
            resolver_address: r.resolver_address.clone(),
            resolver_role: r.resolver_role.clone(),
            outcome: r.outcome.clone(),
            resolved_at_height: r.resolved_at_height,
            message_hash,
            anchor_txid,
        }
    });
    AgreementEscrowReceipt {
        schema_id: ESCROW_RECEIPT_SCHEMA_ID.to_string(),
        version: ESCROW_RECEIPT_VERSION,
        agreement_id: agreement.agreement_id.clone(),
        agreement_hash: agreement_hash.to_string(),
        template_type: agreement.template_type,
        parties: agreement.parties.clone(),
        payer_address,
        payee_address,
        total_amount: agreement.total_amount,
        final_state: lifecycle.state,
        funded_amount: lifecycle.funded_amount,
        released_amount: lifecycle.released_amount,
        refunded_amount: lifecycle.refunded_amount,
        funding_txids,
        release_txids,
        refund_txids,
        resolved_height,
        milestones: lifecycle.milestones.clone(),
        proofs: proof_refs,
        dispute: dispute_ref,
        linked_txs: lifecycle.linked_txs.clone(),
        export_timestamp,
        exporter_address: exporter_address.to_string(),
        exporter_pubkey_hex: exporter_pubkey_hex.to_string(),
        exporter_signature: ExporterSignatureEnvelope {
            version: ESCROW_RECEIPT_VERSION,
            signer_public_key: exporter_pubkey_hex.to_string(),
            signer_address: exporter_address.to_string(),
            signature_type: AGREEMENT_SIGNATURE_TYPE_SECP256K1.to_string(),
            signature: String::new(),
            payload_hash: String::new(),
        },
    }
}

/// Canonical receipt bytes for signing/verification. Clears the
/// exporter_signature.signature and .payload_hash fields, serializes
/// with sorted keys, and returns the deterministic byte vector.
pub fn escrow_receipt_canonical_bytes(
    receipt: &AgreementEscrowReceipt,
) -> Result<Vec<u8>, String> {
    let mut canon = receipt.clone();
    canon.exporter_signature.signature.clear();
    canon.exporter_signature.payload_hash.clear();
    let value =
        serde_json::to_value(&canon).map_err(|e| format!("escrow receipt to json: {e}"))?;
    let sorted = sort_json(value);
    serde_json::to_vec(&sorted).map_err(|e| format!("escrow receipt canonical serialize: {e}"))
}

/// SHA-256 of the canonical receipt bytes. The 32-byte digest is the
/// secp256k1 signing input.
pub fn escrow_receipt_signing_digest(
    receipt: &AgreementEscrowReceipt,
) -> Result<[u8; 32], String> {
    let bytes = escrow_receipt_canonical_bytes(receipt)?;
    let digest = Sha256::digest(&bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

/// Verify an escrow receipt's exporter_signature against its canonical
/// digest. Returns Err if the schema_id/version is wrong, the signature
/// is malformed, or the secp256k1 verification fails. Does NOT
/// re-validate chain claims - the receipt is a signed snapshot, not a
/// substitute for chain access.
pub fn verify_escrow_receipt_signature(
    receipt: &AgreementEscrowReceipt,
) -> Result<(), String> {
    if receipt.schema_id != ESCROW_RECEIPT_SCHEMA_ID {
        return Err(format!(
            "unsupported escrow_receipt schema_id {}",
            receipt.schema_id
        ));
    }
    if receipt.version != ESCROW_RECEIPT_VERSION {
        return Err(format!(
            "unsupported escrow_receipt version {}",
            receipt.version
        ));
    }
    if receipt.exporter_signature.signature.is_empty() {
        return Err("exporter_signature.signature is empty".to_string());
    }
    let digest = escrow_receipt_signing_digest(receipt)?;
    let pubkey_bytes = hex::decode(&receipt.exporter_signature.signer_public_key)
        .map_err(|_| "exporter signer_public_key must be hex".to_string())?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&pubkey_bytes)
        .map_err(|_| "exporter signer_public_key must be valid secp256k1 SEC1".to_string())?;
    let sig_bytes = hex::decode(&receipt.exporter_signature.signature)
        .map_err(|_| "exporter signature must be 64-byte hex".to_string())?;
    let parsed = Signature::from_slice(&sig_bytes)
        .map_err(|_| "exporter signature must be 64-byte hex".to_string())?;
    verifying_key
        .verify_prehash(&digest, &parsed)
        .map_err(|_| "exporter signature verification failed".to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementFundingLeg {
    pub role: AgreementAnchorRole,
    pub milestone_id: Option<String>,
    pub amount: u64,
    pub output: TxOutput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementFundingLegRef {
    pub funding_txid: String,
    pub htlc_vout: u32,
    pub anchor_vout: u32,
    pub role: AgreementAnchorRole,
    pub milestone_id: Option<String>,
    pub amount: u64,
    pub timeout_height: u64,
    pub expected_hash: String,
    pub recipient_address: String,
    pub refund_address: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgreementActivitySource {
    LocalBundle,
    ChainObserved,
    DerivedIndexed,
    HtlcEligibility,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementFundingLegCandidate {
    pub agreement_hash: String,
    pub funding_txid: String,
    pub htlc_vout: u32,
    pub anchor_vout: u32,
    pub role: AgreementAnchorRole,
    #[serde(default)]
    pub milestone_id: Option<String>,
    pub amount: u64,
    pub htlc_backed: bool,
    pub timeout_height: u64,
    pub recipient_address: String,
    pub refund_address: String,
    #[serde(default)]
    pub source_notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementActivityEvent {
    pub event_type: String,
    pub source: AgreementActivitySource,
    #[serde(default)]
    pub txid: Option<String>,
    #[serde(default)]
    pub height: Option<u64>,
    #[serde(default)]
    pub timestamp: Option<u64>,
    #[serde(default)]
    pub milestone_id: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AgreementBundleMilestoneHint {
    pub milestone_id: String,
    #[serde(default)]
    pub funding_txid: Option<String>,
    #[serde(default)]
    pub htlc_vout: Option<u32>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AgreementBundleMetadata {
    #[serde(default)]
    pub saved_at: u64,
    #[serde(default)]
    pub source_label: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub linked_funding_txids: Vec<String>,
    #[serde(default)]
    pub milestone_hints: Vec<AgreementBundleMilestoneHint>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgreementSignatureTargetType {
    Agreement,
    Bundle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementSignatureEnvelope {
    #[serde(default = "default_agreement_signature_version")]
    pub version: u32,
    pub target_type: AgreementSignatureTargetType,
    pub target_hash: String,
    pub signer_public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_address: Option<String>,
    pub signature_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_role: Option<String>,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementBundle {
    #[serde(default = "default_agreement_bundle_version")]
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_schema_id: Option<String>,
    pub agreement_id: String,
    pub agreement_hash: String,
    pub agreement: AgreementObject,
    #[serde(default)]
    pub metadata: AgreementBundleMetadata,
    #[serde(default)]
    pub artifacts: AgreementBundleArtifacts,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<AgreementSignatureEnvelope>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementSharePackage {
    #[serde(default = "default_agreement_share_package_version")]
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_schema_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_note: Option<String>,
    #[serde(default)]
    pub included_artifact_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<AgreementSharePackageManifest>,
    pub trust_notice: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agreement: Option<AgreementObject>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle: Option<AgreementBundle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<AgreementAuditRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement: Option<AgreementStatement>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub detached_agreement_signatures: Vec<AgreementSignatureEnvelope>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub detached_bundle_signatures: Vec<AgreementSignatureEnvelope>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementSharePackageManifest {
    pub package_profile: String,
    #[serde(default)]
    pub included_artifact_types: Vec<String>,
    #[serde(default)]
    pub omitted_artifact_types: Vec<String>,
    pub verification_notice: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementSignatureVerification {
    pub target_type: AgreementSignatureTargetType,
    pub target_hash: String,
    pub signer_public_key: String,
    #[serde(default)]
    pub signer_address: Option<String>,
    #[serde(default)]
    pub signer_role: Option<String>,
    pub signature_type: String,
    #[serde(default)]
    pub timestamp: Option<u64>,
    pub valid: bool,
    pub matches_expected_target: bool,
    pub authenticity_note: String,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementAuditMilestoneSummary {
    pub milestone_id: String,
    pub title: String,
    pub amount: u64,
    pub timeout_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementAuditMetadata {
    #[serde(default = "default_agreement_audit_record_version")]
    pub version: u32,
    pub generated_at: u64,
    pub generator_surface: String,
    pub trust_model_summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementAuditAgreementSummary {
    pub agreement_id: String,
    pub agreement_hash: String,
    pub template_type: AgreementTemplateType,
    pub network_marker: String,
    pub payer: String,
    pub payee: String,
    pub parties: Vec<AgreementParty>,
    pub total_amount: u64,
    pub milestone_count: usize,
    pub milestones: Vec<AgreementAuditMilestoneSummary>,
    #[serde(default)]
    pub settlement_deadline: Option<u64>,
    #[serde(default)]
    pub refund_deadline: Option<u64>,
    #[serde(default)]
    pub dispute_window: Option<u64>,
    pub document_hash: String,
    #[serde(default)]
    pub metadata_hash: Option<String>,
    #[serde(default)]
    pub invoice_reference: Option<String>,
    #[serde(default)]
    pub external_reference: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementAuditBundleContext {
    pub bundle_used: bool,
    pub verification_ok: bool,
    #[serde(default)]
    pub saved_at: Option<u64>,
    #[serde(default)]
    pub source_label: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub linked_funding_txids: Vec<String>,
    #[serde(default)]
    pub milestone_hints: Vec<AgreementBundleMilestoneHint>,
    pub local_only_notice: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementAuditChainObservedContext {
    pub linked_transactions: Vec<AgreementLinkedTx>,
    pub linked_transaction_count: usize,
    pub anchor_observation_notice: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementAuditFundingLegRecord {
    pub funding_txid: String,
    pub htlc_vout: u32,
    pub anchor_vout: u32,
    pub role: AgreementAnchorRole,
    #[serde(default)]
    pub milestone_id: Option<String>,
    pub amount: u64,
    pub htlc_backed: bool,
    pub timeout_height: u64,
    pub recipient_address: String,
    pub refund_address: String,
    #[serde(default)]
    pub source_notes: Vec<String>,
    #[serde(default)]
    pub release_eligible: Option<bool>,
    #[serde(default)]
    pub release_reasons: Vec<String>,
    #[serde(default)]
    pub refund_eligible: Option<bool>,
    #[serde(default)]
    pub refund_reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementAuditFundingLegSummary {
    pub candidate_count: usize,
    pub selection_required: bool,
    #[serde(default)]
    pub selected_leg: Option<AgreementAuditFundingLegRecord>,
    #[serde(default)]
    pub ambiguity_warning: Option<String>,
    pub candidates: Vec<AgreementAuditFundingLegRecord>,
    pub notice: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementAuditTimelineSummary {
    pub reconstructed: bool,
    pub event_count: usize,
    pub events: Vec<AgreementActivityEvent>,
    pub notice: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementAuditSettlementStateSummary {
    pub lifecycle_state: AgreementLifecycleState,
    pub derived_state_label: String,
    pub selection_required: bool,
    pub funded_amount: u64,
    pub released_amount: u64,
    pub refunded_amount: u64,
    pub summary_note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementAuditTrustBoundaries {
    pub consensus_enforced: Vec<String>,
    pub htlc_enforced: Vec<String>,
    pub metadata_indexed: Vec<String>,
    pub local_bundle_only: Vec<String>,
    pub off_chain_required: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementAuditRecord {
    pub metadata: AgreementAuditMetadata,
    pub agreement: AgreementAuditAgreementSummary,
    pub local_bundle: AgreementAuditBundleContext,
    pub chain_observed: AgreementAuditChainObservedContext,
    pub funding_legs: AgreementAuditFundingLegSummary,
    pub timeline: AgreementAuditTimelineSummary,
    pub settlement_state: AgreementAuditSettlementStateSummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticity: Option<AgreementAuthenticitySummary>,
    pub trust_boundaries: AgreementAuditTrustBoundaries,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementStatementMetadata {
    #[serde(default = "default_agreement_statement_version")]
    pub version: u32,
    pub generated_at: u64,
    pub derived_notice: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementStatementIdentity {
    pub agreement_id: String,
    pub agreement_hash: String,
    pub template_type: AgreementTemplateType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementStatementCounterparties {
    pub payer: String,
    pub payee: String,
    pub parties_summary: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementStatementCommercialSummary {
    pub total_amount: u64,
    pub milestone_summary: String,
    #[serde(default)]
    pub settlement_deadline: Option<u64>,
    #[serde(default)]
    pub refund_deadline: Option<u64>,
    pub release_path_summary: String,
    pub refund_path_summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementStatementObservedSummary {
    pub funding_observed: bool,
    pub release_observed: bool,
    pub refund_observed: bool,
    #[serde(default)]
    pub ambiguity_warning: Option<String>,
    pub linked_txids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementStatementDerivedSummary {
    pub derived_state_label: String,
    pub funded_amount: u64,
    pub released_amount: u64,
    pub refunded_amount: u64,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementStatementTrustNotice {
    pub consensus_visible: Vec<String>,
    pub htlc_enforced: Vec<String>,
    pub derived_indexed: Vec<String>,
    pub local_off_chain: Vec<String>,
    pub canonical_notice: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementStatementReferences {
    pub linked_txids: Vec<String>,
    #[serde(default)]
    pub selected_funding_txid: Option<String>,
    pub canonical_agreement_notice: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementAuthenticitySummary {
    pub detached_agreement_signatures_supplied: usize,
    pub detached_bundle_signatures_supplied: usize,
    pub embedded_bundle_signatures_supplied: usize,
    pub valid_signatures: usize,
    pub invalid_signatures: usize,
    pub unverifiable_signatures: usize,
    #[serde(default)]
    pub signer_summaries: Vec<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
    pub authenticity_notice: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementStatementAuthenticitySummary {
    pub valid_signatures: usize,
    pub invalid_signatures: usize,
    pub unverifiable_signatures: usize,
    pub compact_summary: String,
    pub authenticity_notice: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementStatement {
    pub metadata: AgreementStatementMetadata,
    pub identity: AgreementStatementIdentity,
    pub counterparties: AgreementStatementCounterparties,
    pub commercial: AgreementStatementCommercialSummary,
    pub observed: AgreementStatementObservedSummary,
    pub derived: AgreementStatementDerivedSummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticity: Option<AgreementStatementAuthenticitySummary>,
    pub trust_notice: AgreementStatementTrustNotice,
    pub references: AgreementStatementReferences,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementArtifactVerificationMetadata {
    #[serde(default = "default_agreement_artifact_verification_version")]
    pub version: u32,
    pub generated_at: u64,
    pub derived_notice: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementArtifactVerificationInputSummary {
    pub supplied_artifact_types: Vec<String>,
    pub canonical_agreement_present: bool,
    pub extracted_from_bundle: bool,
    #[serde(default)]
    pub claimed_agreement_id: Vec<String>,
    #[serde(default)]
    pub claimed_agreement_hash: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementArtifactCanonicalVerification {
    pub canonical_agreement_present: bool,
    #[serde(default)]
    pub computed_agreement_hash: Option<String>,
    #[serde(default)]
    pub computed_agreement_id: Option<String>,
    #[serde(default)]
    pub bundle_hash_match: Option<bool>,
    #[serde(default)]
    pub audit_identity_match: Option<bool>,
    #[serde(default)]
    pub statement_identity_match: Option<bool>,
    #[serde(default)]
    pub matches: Vec<String>,
    #[serde(default)]
    pub mismatches: Vec<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementArtifactConsistencyVerification {
    #[serde(default)]
    pub bundle_matches_canonical: Option<bool>,
    #[serde(default)]
    pub audit_matches_canonical: Option<bool>,
    #[serde(default)]
    pub statement_matches_canonical: Option<bool>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementArtifactChainVerification {
    pub linked_tx_references_found: bool,
    pub anchor_observations_found: bool,
    #[serde(default)]
    pub checked_txids: Vec<String>,
    #[serde(default)]
    pub audit_chain_match: Option<bool>,
    #[serde(default)]
    pub statement_chain_match: Option<bool>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementArtifactDerivedVerification {
    #[serde(default)]
    pub audit_derived_match: Option<bool>,
    #[serde(default)]
    pub statement_derived_match: Option<bool>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementArtifactAuthenticityVerification {
    pub detached_agreement_signatures_supplied: usize,
    pub detached_bundle_signatures_supplied: usize,
    pub embedded_bundle_signatures_supplied: usize,
    pub valid_signatures: usize,
    pub invalid_signatures: usize,
    pub unverifiable_signatures: usize,
    #[serde(default)]
    pub signer_summaries: Vec<String>,
    pub verifications: Vec<AgreementSignatureVerification>,
    #[serde(default)]
    pub warnings: Vec<String>,
    pub authenticity_notice: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementArtifactVerificationTrustSummary {
    pub consensus_visible: Vec<String>,
    pub htlc_enforced: Vec<String>,
    pub derived_indexed: Vec<String>,
    pub local_artifact_only: Vec<String>,
    pub unverifiable_from_chain_alone: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementArtifactVerificationResult {
    pub metadata: AgreementArtifactVerificationMetadata,
    pub input_summary: AgreementArtifactVerificationInputSummary,
    pub canonical_verification: AgreementArtifactCanonicalVerification,
    pub artifact_consistency: AgreementArtifactConsistencyVerification,
    pub chain_verification: AgreementArtifactChainVerification,
    pub derived_verification: AgreementArtifactDerivedVerification,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticity: Option<AgreementArtifactAuthenticityVerification>,
    pub trust_summary: AgreementArtifactVerificationTrustSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementSharePackageInspection {
    pub version: u32,
    pub package_schema_id: Option<String>,
    pub created_at: Option<u64>,
    pub sender_label: Option<String>,
    pub package_note: Option<String>,
    pub package_profile: String,
    pub included_artifact_types: Vec<String>,
    pub omitted_artifact_types: Vec<String>,
    pub agreement_present: bool,
    pub bundle_present: bool,
    pub audit_present: bool,
    pub statement_present: bool,
    pub detached_agreement_signature_count: usize,
    pub detached_bundle_signature_count: usize,
    pub verification_notice: String,
    pub canonical_agreement_id: Option<String>,
    pub canonical_agreement_hash: Option<String>,
    pub bundle_hash: Option<String>,
    pub trust_notice: String,
    pub informational_notice: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementSharePackageVerificationMetadata {
    #[serde(default = "default_agreement_share_package_verification_version")]
    pub version: u32,
    pub generated_at: u64,
    pub derived_notice: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementSharePackageVerificationResult {
    pub metadata: AgreementSharePackageVerificationMetadata,
    pub package: AgreementSharePackageInspection,
    pub artifact_verification: AgreementArtifactVerificationResult,
    #[serde(default)]
    pub informational_notices: Vec<String>,
}

fn default_agreement_version() -> u32 {
    AGREEMENT_OBJECT_VERSION
}

fn default_agreement_artifact_verification_version() -> u32 {
    AGREEMENT_ARTIFACT_VERIFICATION_VERSION
}

fn default_agreement_share_package_version() -> u32 {
    AGREEMENT_SHARE_PACKAGE_VERSION
}

fn default_agreement_share_package_verification_version() -> u32 {
    AGREEMENT_SHARE_PACKAGE_VERIFICATION_VERSION
}

fn default_agreement_bundle_version() -> u32 {
    AGREEMENT_BUNDLE_VERSION
}

fn default_agreement_signature_version() -> u32 {
    AGREEMENT_SIGNATURE_VERSION
}

fn default_agreement_audit_record_version() -> u32 {
    AGREEMENT_AUDIT_RECORD_VERSION
}

fn default_agreement_statement_version() -> u32 {
    AGREEMENT_STATEMENT_VERSION
}

fn default_network_marker() -> String {
    AGREEMENT_NETWORK_MARKER.to_string()
}

fn validate_optional_text_field(name: &str, value: &Option<String>) -> Result<(), String> {
    if let Some(value) = value {
        if value.trim().is_empty() {
            return Err(format!("{name} must not be empty when provided"));
        }
    }
    Ok(())
}

fn sort_json(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<_> = map.keys().cloned().collect();
            keys.sort();
            let mut out = Map::new();
            for key in keys {
                if let Some(v) = map.get(&key) {
                    out.insert(key, sort_json(v.clone()));
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.into_iter().map(sort_json).collect()),
        other => other,
    }
}

pub fn agreement_canonical_value(agreement: &AgreementObject) -> Result<Value, String> {
    let value = serde_json::to_value(agreement).map_err(|e| format!("agreement to json: {e}"))?;
    Ok(sort_json(value))
}

pub fn agreement_canonical_bytes(agreement: &AgreementObject) -> Result<Vec<u8>, String> {
    let value = agreement_canonical_value(agreement)?;
    serde_json::to_vec(&value).map_err(|e| format!("canonical serialize: {e}"))
}

pub fn canonical_serialization_rules() -> Vec<&'static str> {
    vec![
        "Canonical agreement JSON is UTF-8 encoded with lexicographically sorted object keys.",
        "Fields with Option::None and vectors marked empty via skip rules are omitted.",
        "Array ordering is preserved exactly as supplied by the canonical agreement object.",
        "The canonical agreement hash is sha256(canonical_json_bytes).",
        "Legacy agreements without schema_id remain valid; Phase 1.5 templates set schema_id explicitly.",
    ]
}

pub fn compute_agreement_hash(agreement: &AgreementObject) -> Result<[u8; 32], String> {
    agreement.validate()?;
    let bytes = agreement_canonical_bytes(agreement)?;
    let digest = Sha256::digest(&bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

pub fn compute_agreement_hash_hex(agreement: &AgreementObject) -> Result<String, String> {
    Ok(hex::encode(compute_agreement_hash(agreement)?))
}

pub fn build_simple_settlement_agreement(
    agreement_id: String,
    creation_time: u64,
    party_a: AgreementParty,
    party_b: AgreementParty,
    total_amount: u64,
    settlement_deadline: Option<u64>,
    refund_timeout_height: u64,
    secret_hash_hex: String,
    document_hash: String,
    metadata_hash: Option<String>,
    release_summary: Option<String>,
    refund_summary: Option<String>,
    notes: Option<String>,
) -> Result<AgreementObject, String> {
    let party_a_id = party_a.party_id.clone();
    let party_b_id = party_b.party_id.clone();
    let agreement = AgreementObject {
        agreement_id,
        version: AGREEMENT_OBJECT_VERSION,
        schema_id: Some(AGREEMENT_SCHEMA_ID_V1.to_string()),
        template_type: AgreementTemplateType::SimpleReleaseRefund,
        parties: vec![party_a.clone(), party_b.clone()],
        payer: party_a_id,
        payee: party_b_id,
        mediator_reference: None,
        total_amount,
        network_marker: AGREEMENT_NETWORK_MARKER.to_string(),
        creation_time,
        deadlines: AgreementDeadlines {
            settlement_deadline,
            refund_deadline: Some(refund_timeout_height),
            dispute_window: None,
        },
        release_conditions: vec![AgreementReleaseCondition {
            mode: "secret_preimage".to_string(),
            secret_hash_hex: Some(secret_hash_hex),
            release_authorizer: Some("payer".to_string()),
            notes: release_summary.clone(),
        }],
        refund_conditions: vec![AgreementRefundCondition {
            refund_address: party_a.address.clone(),
            timeout_height: refund_timeout_height,
            notes: refund_summary.clone(),
        }],
        milestones: vec![],
        deposit_rule: None,
        proof_policy_reference: None,
        asset_reference: None,
        payment_reference: None,
        purpose_reference: None,
        release_summary,
        refund_summary,
        attestor_reference: None,
        resolver_reference: None,
        notes,
        document_hash,
        metadata_hash,
        invoice_reference: None,
        external_reference: None,
        disputed_metadata_only: false,
        primary_resolver: None,
        fallback_resolver: None,
        primary_resolver_fee: None,
        fallback_resolver_fee: None,
    };
    agreement.validate()?;
    Ok(agreement)
}

pub fn build_deposit_agreement(
    agreement_id: String,
    creation_time: u64,
    payer: AgreementParty,
    payee: AgreementParty,
    deposit_amount: u64,
    purpose_reference: String,
    refundable_conditions_summary: String,
    refund_timeout_height: u64,
    secret_hash_hex: String,
    document_hash: String,
    metadata_hash: Option<String>,
    notes: Option<String>,
) -> Result<AgreementObject, String> {
    let payer_id = payer.party_id.clone();
    let payee_id = payee.party_id.clone();
    let agreement = AgreementObject {
        agreement_id,
        version: AGREEMENT_OBJECT_VERSION,
        schema_id: Some(AGREEMENT_SCHEMA_ID_V1.to_string()),
        template_type: AgreementTemplateType::RefundableDeposit,
        parties: vec![payer.clone(), payee.clone()],
        payer: payer_id,
        payee: payee_id,
        mediator_reference: None,
        total_amount: deposit_amount,
        network_marker: AGREEMENT_NETWORK_MARKER.to_string(),
        creation_time,
        deadlines: AgreementDeadlines {
            settlement_deadline: None,
            refund_deadline: Some(refund_timeout_height),
            dispute_window: None,
        },
        release_conditions: vec![AgreementReleaseCondition {
            mode: "secret_preimage".to_string(),
            secret_hash_hex: Some(secret_hash_hex),
            release_authorizer: Some("payer".to_string()),
            notes: Some("Deposit release requires the agreed HTLC release path".to_string()),
        }],
        refund_conditions: vec![AgreementRefundCondition {
            refund_address: payer.address.clone(),
            timeout_height: refund_timeout_height,
            notes: Some(refundable_conditions_summary.clone()),
        }],
        milestones: vec![],
        deposit_rule: Some(AgreementDepositRule {
            amount: deposit_amount,
            beneficiary_address: payee.address.clone(),
            refund_address: payer.address.clone(),
            timeout_height: refund_timeout_height,
            notes: Some(refundable_conditions_summary.clone()),
        }),
        proof_policy_reference: None,
        asset_reference: None,
        payment_reference: None,
        purpose_reference: Some(purpose_reference),
        release_summary: Some("HTLC-backed deposit release path".to_string()),
        refund_summary: Some(refundable_conditions_summary),
        attestor_reference: None,
        resolver_reference: None,
        notes,
        document_hash,
        metadata_hash,
        invoice_reference: None,
        external_reference: None,
        disputed_metadata_only: false,
        primary_resolver: None,
        fallback_resolver: None,
        primary_resolver_fee: None,
        fallback_resolver_fee: None,
    };
    agreement.validate()?;
    Ok(agreement)
}

pub fn build_otc_agreement(
    agreement_id: String,
    creation_time: u64,
    buyer: AgreementParty,
    seller: AgreementParty,
    total_amount: u64,
    asset_reference: String,
    payment_reference: String,
    refund_timeout_height: u64,
    secret_hash_hex: String,
    document_hash: String,
    metadata_hash: Option<String>,
    notes: Option<String>,
) -> Result<AgreementObject, String> {
    let buyer_id = buyer.party_id.clone();
    let seller_id = seller.party_id.clone();
    let agreement = AgreementObject {
        agreement_id,
        version: AGREEMENT_OBJECT_VERSION,
        schema_id: Some(AGREEMENT_SCHEMA_ID_V1.to_string()),
        template_type: AgreementTemplateType::OtcSettlement,
        parties: vec![buyer.clone(), seller.clone()],
        payer: seller_id,
        payee: buyer_id,
        mediator_reference: None,
        total_amount,
        network_marker: AGREEMENT_NETWORK_MARKER.to_string(),
        creation_time,
        deadlines: AgreementDeadlines {
            settlement_deadline: None,
            refund_deadline: Some(refund_timeout_height),
            dispute_window: None,
        },
        release_conditions: vec![AgreementReleaseCondition {
            mode: "secret_preimage".to_string(),
            secret_hash_hex: Some(secret_hash_hex),
            release_authorizer: Some("seller".to_string()),
            notes: Some(
                "OTC release path: seller authorizes payout to buyer after receiving off-chain payment"
                    .to_string(),
            ),
        }],
        refund_conditions: vec![AgreementRefundCondition {
            refund_address: seller.address.clone(),
            timeout_height: refund_timeout_height,
            notes: Some(
                "Refund returns escrowed IRM to seller on HTLC timeout when no release is authorized".to_string(),
            ),
        }],
        milestones: vec![],
        deposit_rule: None,
        proof_policy_reference: None,
        asset_reference: Some(asset_reference),
        payment_reference: Some(payment_reference),
        purpose_reference: None,
        release_summary: Some("HTLC-backed OTC release path".to_string()),
        refund_summary: Some("Timeout refund path for the OTC funding leg".to_string()),
        attestor_reference: None,
        resolver_reference: None,
        notes,
        document_hash,
        metadata_hash,
        invoice_reference: None,
        external_reference: None,
        disputed_metadata_only: false,
        primary_resolver: None,
        fallback_resolver: None,
        primary_resolver_fee: None,
        fallback_resolver_fee: None,
    };
    agreement.validate()?;
    Ok(agreement)
}

pub fn build_milestone_agreement(
    agreement_id: String,
    creation_time: u64,
    payer: AgreementParty,
    payee: AgreementParty,
    milestones: Vec<AgreementMilestone>,
    refund_deadline: u64,
    document_hash: String,
    metadata_hash: Option<String>,
    notes: Option<String>,
) -> Result<AgreementObject, String> {
    let total_amount: u64 = milestones.iter().map(|m| m.amount).sum();
    let payer_id = payer.party_id.clone();
    let payee_id = payee.party_id.clone();
    let agreement = AgreementObject {
        agreement_id,
        version: AGREEMENT_OBJECT_VERSION,
        schema_id: Some(AGREEMENT_SCHEMA_ID_V1.to_string()),
        template_type: AgreementTemplateType::MilestoneSettlement,
        parties: vec![payer.clone(), payee.clone()],
        payer: payer_id,
        payee: payee_id,
        mediator_reference: None,
        total_amount,
        network_marker: AGREEMENT_NETWORK_MARKER.to_string(),
        creation_time,
        deadlines: AgreementDeadlines {
            settlement_deadline: milestones.iter().map(|m| m.timeout_height).max(),
            refund_deadline: Some(refund_deadline),
            dispute_window: None,
        },
        release_conditions: vec![AgreementReleaseCondition {
            mode: "secret_preimage".to_string(),
            secret_hash_hex: milestones.first().map(|m| m.secret_hash_hex.clone()),
            release_authorizer: Some("payer".to_string()),
            notes: Some("Milestone completion is off-chain agreement context; HTLC branches enforce only the funded leg paths".to_string()),
        }],
        refund_conditions: vec![AgreementRefundCondition {
            refund_address: payer.address.clone(),
            timeout_height: refund_deadline,
            notes: Some("Fallback refund applies when milestone legs remain unspent until timeout".to_string()),
        }],
        milestones,
        deposit_rule: None,
        proof_policy_reference: None,
        asset_reference: None,
        payment_reference: None,
        purpose_reference: Some("Milestone settlement schedule".to_string()),
        release_summary: Some("Each milestone leg may use its own HTLC-backed release branch".to_string()),
        refund_summary: Some("Each milestone leg may use its own timeout refund branch".to_string()),
        attestor_reference: None,
        resolver_reference: None,
        notes,
        document_hash,
        metadata_hash,
        invoice_reference: None,
        external_reference: None,
        disputed_metadata_only: false,
        primary_resolver: None,
        fallback_resolver: None,
        primary_resolver_fee: None,
        fallback_resolver_fee: None,
    };
    agreement.validate()?;
    Ok(agreement)
}

pub fn build_agreement_bundle_with_artifacts(
    agreement: &AgreementObject,
    saved_at: u64,
    source_label: Option<String>,
    note: Option<String>,
    linked_funding_txids: Vec<String>,
    milestone_hints: Vec<AgreementBundleMilestoneHint>,
    artifacts: AgreementBundleArtifacts,
) -> Result<AgreementBundle, String> {
    let agreement_hash = compute_agreement_hash_hex(agreement)?;
    Ok(AgreementBundle {
        version: AGREEMENT_BUNDLE_VERSION,
        bundle_schema_id: Some(AGREEMENT_BUNDLE_SCHEMA_ID_V1.to_string()),
        agreement_id: agreement.agreement_id.clone(),
        agreement_hash,
        agreement: agreement.clone(),
        metadata: AgreementBundleMetadata {
            saved_at,
            source_label,
            note,
            linked_funding_txids,
            milestone_hints,
        },
        artifacts,
        signatures: Vec::new(),
    })
}

pub fn build_agreement_bundle(
    agreement: &AgreementObject,
    saved_at: u64,
    source_label: Option<String>,
    note: Option<String>,
    linked_funding_txids: Vec<String>,
    milestone_hints: Vec<AgreementBundleMilestoneHint>,
) -> Result<AgreementBundle, String> {
    build_agreement_bundle_with_artifacts(
        agreement,
        saved_at,
        source_label,
        note,
        linked_funding_txids,
        milestone_hints,
        AgreementBundleArtifacts::default(),
    )
}

pub fn agreement_bundle_canonical_value(bundle: &AgreementBundle) -> Result<Value, String> {
    let mut canonical = bundle.clone();
    canonical.signatures.clear();
    let value = serde_json::to_value(canonical).map_err(|e| format!("bundle to json: {e}"))?;
    Ok(sort_json(value))
}

pub fn agreement_share_package_included_artifact_types(
    package: &AgreementSharePackage,
) -> Vec<String> {
    let mut out = Vec::new();
    if package.agreement.is_some() {
        out.push("agreement".to_string());
    }
    if package.bundle.is_some() {
        out.push("bundle".to_string());
    }
    if package.audit.is_some() {
        out.push("audit".to_string());
    }
    if package.statement.is_some() {
        out.push("statement".to_string());
    }
    if !package.detached_agreement_signatures.is_empty() {
        out.push("agreement_signatures".to_string());
    }
    if !package.detached_bundle_signatures.is_empty() {
        out.push("bundle_signatures".to_string());
    }
    out
}

pub fn agreement_share_package_all_artifact_types() -> Vec<String> {
    vec![
        "agreement".to_string(),
        "bundle".to_string(),
        "audit".to_string(),
        "statement".to_string(),
        "agreement_signatures".to_string(),
        "bundle_signatures".to_string(),
    ]
}

fn infer_agreement_share_package_profile(package: &AgreementSharePackage) -> String {
    let has_review = package.audit.is_some() || package.statement.is_some();
    let has_signatures = !package.detached_agreement_signatures.is_empty()
        || !package.detached_bundle_signatures.is_empty();
    if has_review && has_signatures && package.bundle.is_some() {
        "full_informational_package".to_string()
    } else if has_signatures {
        "verification_package".to_string()
    } else if has_review {
        "review_package".to_string()
    } else {
        "minimal_agreement_handoff".to_string()
    }
}

fn build_agreement_share_package_manifest(
    package: &AgreementSharePackage,
) -> AgreementSharePackageManifest {
    let included_artifact_types = agreement_share_package_included_artifact_types(package);
    let omitted_artifact_types = agreement_share_package_all_artifact_types()
        .into_iter()
        .filter(|item| {
            !included_artifact_types
                .iter()
                .any(|included| included == item)
        })
        .collect::<Vec<_>>();
    AgreementSharePackageManifest {
        package_profile: infer_agreement_share_package_profile(package),
        included_artifact_types,
        omitted_artifact_types,
        verification_notice: "Manifest is descriptive only. Verify included artifacts against canonical agreement or bundle hashes, detached signatures, and derived verification output before relying on them.".to_string(),
    }
}

pub fn build_agreement_share_package(
    created_at: Option<u64>,
    sender_label: Option<String>,
    package_note: Option<String>,
    agreement: Option<AgreementObject>,
    bundle: Option<AgreementBundle>,
    audit: Option<AgreementAuditRecord>,
    statement: Option<AgreementStatement>,
    detached_agreement_signatures: Vec<AgreementSignatureEnvelope>,
    detached_bundle_signatures: Vec<AgreementSignatureEnvelope>,
) -> Result<AgreementSharePackage, String> {
    let mut package = AgreementSharePackage {
        version: AGREEMENT_SHARE_PACKAGE_VERSION,
        package_schema_id: Some(AGREEMENT_SHARE_PACKAGE_SCHEMA_ID_V1.to_string()),
        created_at,
        sender_label,
        package_note,
        included_artifact_types: Vec::new(),
        manifest: None,
        trust_notice: "Share package contents are supplied off-chain artifacts for handoff and re-verification. Authenticity must still be checked against canonical agreement or bundle hashes and any supplied signatures. Derived audit and statement content remains informational only and is not native consensus contract state.".to_string(),
        agreement,
        bundle,
        audit,
        statement,
        detached_agreement_signatures,
        detached_bundle_signatures,
    };
    package.included_artifact_types = agreement_share_package_included_artifact_types(&package);
    package.manifest = Some(build_agreement_share_package_manifest(&package));
    verify_agreement_share_package(&package)?;
    Ok(package)
}

pub fn compute_agreement_bundle_hash_hex(bundle: &AgreementBundle) -> Result<String, String> {
    verify_agreement_bundle(bundle)?;
    let bytes = serde_json::to_vec(&agreement_bundle_canonical_value(bundle)?)
        .map_err(|e| format!("bundle canonical serialize: {e}"))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub fn verify_agreement_bundle(bundle: &AgreementBundle) -> Result<(), String> {
    if bundle.version != AGREEMENT_BUNDLE_VERSION {
        return Err(format!(
            "unsupported agreement bundle version {}",
            bundle.version
        ));
    }
    if let Some(schema_id) = &bundle.bundle_schema_id {
        if schema_id != AGREEMENT_BUNDLE_SCHEMA_ID_V1 {
            return Err(format!(
                "unsupported agreement bundle schema_id {}",
                schema_id
            ));
        }
    }
    bundle.agreement.validate()?;
    if bundle.agreement_id != bundle.agreement.agreement_id {
        return Err("bundle agreement_id does not match contained agreement".to_string());
    }
    let expected_hash = compute_agreement_hash_hex(&bundle.agreement)?;
    if bundle.agreement_hash != expected_hash {
        return Err("bundle agreement_hash does not match contained agreement".to_string());
    }
    for txid in &bundle.metadata.linked_funding_txids {
        let bytes = hex::decode(txid)
            .map_err(|_| "bundle linked funding txid must be 32-byte hex".to_string())?;
        if bytes.len() != 32 {
            return Err("bundle linked funding txid must be 32-byte hex".to_string());
        }
    }
    for hint in &bundle.metadata.milestone_hints {
        if hint.milestone_id.trim().is_empty() {
            return Err("bundle milestone hint milestone_id required".to_string());
        }
        if !bundle
            .agreement
            .milestones
            .iter()
            .any(|m| m.milestone_id == hint.milestone_id)
        {
            return Err(format!(
                "bundle milestone hint references unknown milestone_id {}",
                hint.milestone_id
            ));
        }
        if let Some(txid) = &hint.funding_txid {
            let bytes = hex::decode(txid).map_err(|_| {
                "bundle milestone hint funding_txid must be 32-byte hex".to_string()
            })?;
            if bytes.len() != 32 {
                return Err("bundle milestone hint funding_txid must be 32-byte hex".to_string());
            }
        }
    }
    for hash in &bundle.artifacts.external_document_hashes {
        if hash.len() != 64 || hex::decode(hash).is_err() {
            return Err("bundle external_document_hashes entries must be 32-byte hex".to_string());
        }
    }
    if let Some(audit_value) = &bundle.artifacts.audit {
        let audit: AgreementAuditRecord = serde_json::from_value(audit_value.clone())
            .map_err(|e| format!("bundle audit artifact invalid: {e}"))?;
        if audit.agreement.agreement_hash != bundle.agreement_hash {
            return Err("bundle audit artifact agreement_hash does not match bundle".to_string());
        }
    }
    if let Some(statement_value) = &bundle.artifacts.statement {
        let statement: AgreementStatement = serde_json::from_value(statement_value.clone())
            .map_err(|e| format!("bundle statement artifact invalid: {e}"))?;
        if statement.identity.agreement_hash != bundle.agreement_hash {
            return Err(
                "bundle statement artifact agreement_hash does not match bundle".to_string(),
            );
        }
    }
    let expected_bundle_hash = {
        let bytes = serde_json::to_vec(&agreement_bundle_canonical_value(bundle)?)
            .map_err(|e| format!("bundle canonical serialize: {e}"))?;
        hex::encode(Sha256::digest(bytes))
    };
    for signature in &bundle.signatures {
        validate_agreement_signature_envelope(signature)?;
        match signature.target_type {
            AgreementSignatureTargetType::Agreement => {
                if signature.target_hash != bundle.agreement_hash {
                    return Err(
                        "bundle signature target_hash does not match contained agreement hash"
                            .to_string(),
                    );
                }
            }
            AgreementSignatureTargetType::Bundle => {
                if signature.target_hash != expected_bundle_hash {
                    return Err(
                        "bundle signature target_hash does not match contained bundle hash"
                            .to_string(),
                    );
                }
            }
        }
    }
    Ok(())
}

fn validate_hex_len(name: &str, value: &str, bytes_len: usize) -> Result<(), String> {
    let raw = hex::decode(value).map_err(|_| format!("{name} must be {}-byte hex", bytes_len))?;
    if raw.len() != bytes_len {
        return Err(format!("{name} must be {}-byte hex", bytes_len));
    }
    Ok(())
}

fn validate_agreement_signature_envelope_inner(
    signature: &AgreementSignatureEnvelope,
    require_signature: bool,
) -> Result<(), String> {
    if signature.version != AGREEMENT_SIGNATURE_VERSION {
        return Err(format!(
            "unsupported agreement signature version {}",
            signature.version
        ));
    }
    validate_hex_len("signature target_hash", &signature.target_hash, 32)?;
    validate_optional_text_field("signer_address", &signature.signer_address)?;
    validate_optional_text_field("signer_role", &signature.signer_role)?;
    if signature.signature_type != AGREEMENT_SIGNATURE_TYPE_SECP256K1 {
        return Err(format!(
            "unsupported signature_type {}",
            signature.signature_type
        ));
    }
    let pubkey_bytes = hex::decode(&signature.signer_public_key)
        .map_err(|_| "signer_public_key must be hex-encoded SEC1 bytes".to_string())?;
    VerifyingKey::from_sec1_bytes(&pubkey_bytes)
        .map_err(|_| "signer_public_key must be a valid secp256k1 SEC1 public key".to_string())?;
    if require_signature {
        let sig_bytes = hex::decode(&signature.signature)
            .map_err(|_| "signature must be 64-byte hex".to_string())?;
        Signature::from_slice(&sig_bytes)
            .map_err(|_| "signature must be 64-byte hex".to_string())?;
    }
    Ok(())
}

pub fn validate_agreement_signature_envelope(
    signature: &AgreementSignatureEnvelope,
) -> Result<(), String> {
    validate_agreement_signature_envelope_inner(signature, true)
}

pub fn agreement_signature_canonical_value(
    signature: &AgreementSignatureEnvelope,
) -> Result<Value, String> {
    let mut unsigned = signature.clone();
    unsigned.signature.clear();
    let value = serde_json::to_value(unsigned).map_err(|e| format!("signature to json: {e}"))?;
    Ok(sort_json(value))
}

pub fn agreement_signature_canonical_bytes(
    signature: &AgreementSignatureEnvelope,
) -> Result<Vec<u8>, String> {
    let value = agreement_signature_canonical_value(signature)?;
    serde_json::to_vec(&value).map_err(|e| format!("signature canonical serialize: {e}"))
}

pub fn compute_agreement_signature_payload_hash(
    signature: &AgreementSignatureEnvelope,
) -> Result<[u8; 32], String> {
    validate_agreement_signature_envelope_inner(signature, false)?;
    let bytes = agreement_signature_canonical_bytes(signature)?;
    let digest = Sha256::digest(&bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

pub fn verify_agreement_signature_envelope(
    signature: &AgreementSignatureEnvelope,
) -> Result<(), String> {
    validate_agreement_signature_envelope(signature)?;
    let digest = compute_agreement_signature_payload_hash(signature)?;
    let pubkey_bytes = hex::decode(&signature.signer_public_key)
        .map_err(|_| "signer_public_key must be hex-encoded SEC1 bytes".to_string())?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&pubkey_bytes)
        .map_err(|_| "signer_public_key must be a valid secp256k1 SEC1 public key".to_string())?;
    let sig_bytes = hex::decode(&signature.signature)
        .map_err(|_| "signature must be 64-byte hex".to_string())?;
    let parsed = Signature::from_slice(&sig_bytes)
        .map_err(|_| "signature must be 64-byte hex".to_string())?;
    verifying_key
        .verify_prehash(&digest, &parsed)
        .map_err(|_| "signature verification failed".to_string())
}

pub fn inspect_agreement_signature(
    signature: &AgreementSignatureEnvelope,
    expected_agreement_hash: Option<&str>,
    expected_bundle_hash: Option<&str>,
) -> AgreementSignatureVerification {
    let mut warnings = Vec::new();
    let valid = match verify_agreement_signature_envelope(signature) {
        Ok(()) => true,
        Err(err) => {
            warnings.push(err);
            false
        }
    };
    let expected = match signature.target_type {
        AgreementSignatureTargetType::Agreement => expected_agreement_hash,
        AgreementSignatureTargetType::Bundle => expected_bundle_hash,
    };
    let matches_expected_target = expected
        .map(|value| value.eq_ignore_ascii_case(&signature.target_hash))
        .unwrap_or(false);
    if expected.is_some() && !matches_expected_target {
        warnings.push("signature target hash did not match the supplied artifact".to_string());
    }
    let authenticity_note = if valid {
        "Signature authenticity is valid for the signed target hash. This proves authorship or intent only, not correctness of the agreement.".to_string()
    } else {
        "Signature authenticity could not be verified for the supplied target hash.".to_string()
    };
    AgreementSignatureVerification {
        target_type: signature.target_type,
        target_hash: signature.target_hash.clone(),
        signer_public_key: signature.signer_public_key.clone(),
        signer_address: signature.signer_address.clone(),
        signer_role: signature.signer_role.clone(),
        signature_type: signature.signature_type.clone(),
        timestamp: signature.timestamp,
        valid,
        matches_expected_target,
        authenticity_note,
        warnings,
    }
}

pub fn verify_bundle_signatures(bundle: &AgreementBundle) -> Vec<AgreementSignatureVerification> {
    let bundle_hash = compute_agreement_bundle_hash_hex(bundle).ok();
    bundle
        .signatures
        .iter()
        .map(|signature| {
            inspect_agreement_signature(
                signature,
                Some(&bundle.agreement_hash),
                bundle_hash.as_deref(),
            )
        })
        .collect()
}

pub fn verify_agreement_share_package(package: &AgreementSharePackage) -> Result<(), String> {
    if package.version != AGREEMENT_SHARE_PACKAGE_VERSION {
        return Err(format!(
            "unsupported agreement share package version {}",
            package.version
        ));
    }
    if let Some(schema_id) = &package.package_schema_id {
        if schema_id != AGREEMENT_SHARE_PACKAGE_SCHEMA_ID_V1 {
            return Err(format!(
                "unsupported agreement share package schema_id {}",
                schema_id
            ));
        }
    }
    validate_optional_text_field("share package sender_label", &package.sender_label)?;
    validate_optional_text_field("share package package_note", &package.package_note)?;
    if package.trust_notice.trim().is_empty() {
        return Err("share package trust_notice required".to_string());
    }
    let expected_types = agreement_share_package_included_artifact_types(package);
    if package.included_artifact_types != expected_types {
        return Err(
            "share package included_artifact_types did not match supplied contents".to_string(),
        );
    }
    if let Some(manifest) = &package.manifest {
        let expected_manifest = build_agreement_share_package_manifest(package);
        if manifest != &expected_manifest {
            return Err("share package manifest did not match supplied contents".to_string());
        }
    }
    if let Some(agreement) = &package.agreement {
        agreement.validate()?;
    }
    if let Some(bundle) = &package.bundle {
        verify_agreement_bundle(bundle)?;
    }
    if let Some(audit) = &package.audit {
        if audit.metadata.version != AGREEMENT_AUDIT_RECORD_VERSION {
            return Err(format!(
                "unsupported agreement audit record version {}",
                audit.metadata.version
            ));
        }
    }
    if let Some(statement) = &package.statement {
        if statement.metadata.version != AGREEMENT_STATEMENT_VERSION {
            return Err(format!(
                "unsupported agreement statement version {}",
                statement.metadata.version
            ));
        }
    }
    for signature in &package.detached_agreement_signatures {
        validate_agreement_signature_envelope(signature)?;
    }
    for signature in &package.detached_bundle_signatures {
        validate_agreement_signature_envelope(signature)?;
    }
    Ok(())
}

pub fn inspect_agreement_share_package(
    package: &AgreementSharePackage,
) -> Result<AgreementSharePackageInspection, String> {
    verify_agreement_share_package(package)?;
    let canonical = package
        .agreement
        .as_ref()
        .or_else(|| package.bundle.as_ref().map(|b| &b.agreement));
    let canonical_agreement_hash = canonical
        .map(compute_agreement_hash_hex)
        .transpose()?
        .or_else(|| package.bundle.as_ref().map(|b| b.agreement_hash.clone()));
    let bundle_hash = package
        .bundle
        .as_ref()
        .map(compute_agreement_bundle_hash_hex)
        .transpose()?;
    let manifest = package
        .manifest
        .clone()
        .unwrap_or_else(|| build_agreement_share_package_manifest(package));
    Ok(AgreementSharePackageInspection {
        version: package.version,
        package_schema_id: package.package_schema_id.clone(),
        created_at: package.created_at,
        sender_label: package.sender_label.clone(),
        package_note: package.package_note.clone(),
        package_profile: manifest.package_profile,
        included_artifact_types: manifest.included_artifact_types,
        omitted_artifact_types: manifest.omitted_artifact_types,
        agreement_present: package.agreement.is_some(),
        bundle_present: package.bundle.is_some(),
        audit_present: package.audit.is_some(),
        statement_present: package.statement.is_some(),
        detached_agreement_signature_count: package.detached_agreement_signatures.len(),
        detached_bundle_signature_count: package.detached_bundle_signatures.len(),
        verification_notice: manifest.verification_notice,
        canonical_agreement_id: canonical.map(|agreement| agreement.agreement_id.clone()),
        canonical_agreement_hash,
        bundle_hash,
        trust_notice: package.trust_notice.clone(),
        informational_notice: "Share packages are handoff artifacts only. They help counterparties exchange canonical agreement, bundle, audit, statement, and detached signature files together, but they do not create a new trust root or native agreement state. Omitted artifacts are not treated as proof that such artifacts do not exist elsewhere.".to_string(),
    })
}

fn agreement_signature_status_label(
    verification: &AgreementSignatureVerification,
    expected_target_known: bool,
) -> &'static str {
    if verification.valid && verification.matches_expected_target {
        "valid"
    } else if verification.valid && !expected_target_known {
        "unverifiable"
    } else {
        "invalid"
    }
}

fn agreement_signature_signer_summary(
    verification: &AgreementSignatureVerification,
    expected_target_known: bool,
) -> String {
    format!(
        "{} {} role {} target {} status {}",
        serde_json::to_string(&verification.target_type)
            .unwrap_or_else(|_| "\"unknown\"".to_string())
            .trim_matches('"'),
        verification
            .signer_address
            .as_deref()
            .unwrap_or(verification.signer_public_key.as_str()),
        verification.signer_role.as_deref().unwrap_or("unspecified"),
        verification.target_hash,
        agreement_signature_status_label(verification, expected_target_known),
    )
}

pub fn build_agreement_artifact_authenticity_verification(
    agreement: Option<&AgreementObject>,
    bundle: Option<&AgreementBundle>,
    detached_agreement_signatures: &[AgreementSignatureEnvelope],
    detached_bundle_signatures: &[AgreementSignatureEnvelope],
) -> Option<AgreementArtifactAuthenticityVerification> {
    let agreement_hash = agreement
        .map(compute_agreement_hash_hex)
        .transpose()
        .ok()
        .flatten()
        .or_else(|| bundle.map(|value| value.agreement_hash.clone()));
    let bundle_hash = bundle
        .map(compute_agreement_bundle_hash_hex)
        .transpose()
        .ok()
        .flatten();
    let mut verifications = Vec::new();
    let mut warnings = Vec::new();

    for signature in detached_agreement_signatures {
        let mut verification =
            inspect_agreement_signature(signature, agreement_hash.as_deref(), None);
        if signature.target_type != AgreementSignatureTargetType::Agreement {
            verification
                .warnings
                .push("detached agreement signature target_type was not agreement".to_string());
        }
        if agreement_hash.is_none() {
            verification.warnings.push(
                "no canonical agreement hash was available; detached agreement signature target match could not be checked"
                    .to_string(),
            );
        }
        verifications.push(verification);
    }
    for signature in detached_bundle_signatures {
        let mut verification = inspect_agreement_signature(signature, None, bundle_hash.as_deref());
        if signature.target_type != AgreementSignatureTargetType::Bundle {
            verification
                .warnings
                .push("detached bundle signature target_type was not bundle".to_string());
        }
        if bundle_hash.is_none() {
            verification.warnings.push(
                "no canonical bundle hash was available; detached bundle signature target match could not be checked"
                    .to_string(),
            );
        }
        verifications.push(verification);
    }
    if let Some(bundle) = bundle {
        verifications.extend(verify_bundle_signatures(bundle));
    }
    if verifications.is_empty() {
        return None;
    }

    let mut valid_signatures = 0usize;
    let mut invalid_signatures = 0usize;
    let mut unverifiable_signatures = 0usize;
    let mut signer_summaries = Vec::new();
    for verification in &verifications {
        let expected_target_known = match verification.target_type {
            AgreementSignatureTargetType::Agreement => agreement_hash.is_some(),
            AgreementSignatureTargetType::Bundle => bundle_hash.is_some(),
        };
        match agreement_signature_status_label(verification, expected_target_known) {
            "valid" => valid_signatures += 1,
            "unverifiable" => unverifiable_signatures += 1,
            _ => invalid_signatures += 1,
        }
        signer_summaries.push(agreement_signature_signer_summary(
            verification,
            expected_target_known,
        ));
        warnings.extend(verification.warnings.clone());
    }
    if invalid_signatures > 0 {
        warnings.push(
            "one or more supplied signatures were invalid or targeted a different artifact hash"
                .to_string(),
        );
    }
    Some(AgreementArtifactAuthenticityVerification {
        detached_agreement_signatures_supplied: detached_agreement_signatures.len(),
        detached_bundle_signatures_supplied: detached_bundle_signatures.len(),
        embedded_bundle_signatures_supplied: bundle.map(|value| value.signatures.len()).unwrap_or(0),
        valid_signatures,
        invalid_signatures,
        unverifiable_signatures,
        signer_summaries,
        verifications,
        warnings,
        authenticity_notice: "Signature validity is an authenticity layer only. It shows which supplied key signed which supplied hash target. It does not prove agreement truth, fairness, authorization, or settlement enforceability.".to_string(),
    })
}

pub fn summarize_agreement_authenticity(
    authenticity: &AgreementArtifactAuthenticityVerification,
) -> AgreementAuthenticitySummary {
    AgreementAuthenticitySummary {
        detached_agreement_signatures_supplied: authenticity.detached_agreement_signatures_supplied,
        detached_bundle_signatures_supplied: authenticity.detached_bundle_signatures_supplied,
        embedded_bundle_signatures_supplied: authenticity.embedded_bundle_signatures_supplied,
        valid_signatures: authenticity.valid_signatures,
        invalid_signatures: authenticity.invalid_signatures,
        unverifiable_signatures: authenticity.unverifiable_signatures,
        signer_summaries: authenticity.signer_summaries.clone(),
        warnings: authenticity.warnings.clone(),
        authenticity_notice: authenticity.authenticity_notice.clone(),
    }
}

impl AgreementObject {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != AGREEMENT_OBJECT_VERSION {
            return Err(format!("unsupported agreement version {}", self.version));
        }
        if let Some(schema_id) = &self.schema_id {
            if schema_id != AGREEMENT_SCHEMA_ID_V1 {
                return Err(format!("unsupported agreement schema_id {}", schema_id));
            }
        }
        if self.network_marker.trim() != AGREEMENT_NETWORK_MARKER {
            return Err("network_marker must be IRIUM".to_string());
        }
        if self.agreement_id.trim().is_empty() {
            return Err("agreement_id required".to_string());
        }
        if self.total_amount == 0 {
            return Err("total_amount must be > 0".to_string());
        }
        if self.parties.len() < 2 {
            return Err("at least two parties required".to_string());
        }
        let mut party_ids = std::collections::HashSet::new();
        for party in &self.parties {
            if party.party_id.trim().is_empty() {
                return Err("party_id required".to_string());
            }
            if party.display_name.trim().is_empty() {
                return Err(format!("display_name required for {}", party.party_id));
            }
            if party.address.trim().is_empty() {
                return Err(format!("address required for {}", party.party_id));
            }
            if !party_ids.insert(party.party_id.as_str()) {
                return Err(format!("duplicate party_id {}", party.party_id));
            }
        }
        if self.payer == self.payee {
            return Err("payer and payee must differ".to_string());
        }
        if !self.parties.iter().any(|p| p.party_id == self.payer) {
            return Err("payer must reference a declared party".to_string());
        }
        if !self.parties.iter().any(|p| p.party_id == self.payee) {
            return Err("payee must reference a declared party".to_string());
        }
        validate_optional_text_field("asset_reference", &self.asset_reference)?;
        validate_optional_text_field("payment_reference", &self.payment_reference)?;
        validate_optional_text_field("purpose_reference", &self.purpose_reference)?;
        validate_optional_text_field("release_summary", &self.release_summary)?;
        validate_optional_text_field("refund_summary", &self.refund_summary)?;
        validate_optional_text_field("attestor_reference", &self.attestor_reference)?;
        validate_optional_text_field("resolver_reference", &self.resolver_reference)?;
        validate_optional_text_field("notes", &self.notes)?;
        if self.document_hash.len() != 64 || hex::decode(&self.document_hash).is_err() {
            return Err("document_hash must be 32-byte hex".to_string());
        }
        if let Some(metadata_hash) = &self.metadata_hash {
            if metadata_hash.len() != 64 || hex::decode(metadata_hash).is_err() {
                return Err("metadata_hash must be 32-byte hex".to_string());
            }
        }
        if self.release_conditions.is_empty() {
            return Err("at least one release condition required".to_string());
        }
        if self.refund_conditions.is_empty() {
            return Err("at least one refund condition required".to_string());
        }
        if let (Some(settlement_deadline), Some(refund_deadline)) = (
            self.deadlines.settlement_deadline,
            self.deadlines.refund_deadline,
        ) {
            if settlement_deadline > refund_deadline {
                return Err("settlement_deadline must be <= refund_deadline".to_string());
            }
        }
        let mut milestone_ids = std::collections::HashSet::new();
        match self.template_type {
            AgreementTemplateType::MilestoneSettlement
            | AgreementTemplateType::ContractorMilestone => {
                if self.milestones.is_empty() {
                    return Err("milestone template requires milestones".to_string());
                }
                let sum: u64 = self.milestones.iter().map(|m| m.amount).sum();
                if sum != self.total_amount {
                    return Err("milestone amounts must sum to total_amount".to_string());
                }
            }
            _ => {
                if !self.milestones.is_empty() {
                    let sum: u64 = self.milestones.iter().map(|m| m.amount).sum();
                    if sum != self.total_amount {
                        return Err(
                            "milestone amounts must sum to total_amount when present".to_string()
                        );
                    }
                }
            }
        }
        for cond in &self.release_conditions {
            if cond.mode.trim().is_empty() {
                return Err("release condition mode required".to_string());
            }
            if cond.mode == "secret_preimage" {
                let secret_hash_hex = cond.secret_hash_hex.as_ref().ok_or_else(|| {
                    "secret_preimage release condition requires secret_hash_hex".to_string()
                })?;
                if secret_hash_hex.len() != 64 || hex::decode(secret_hash_hex).is_err() {
                    return Err("release secret_hash_hex must be 32-byte hex".to_string());
                }
            }
        }
        for cond in &self.refund_conditions {
            if cond.refund_address.trim().is_empty() {
                return Err("refund address required".to_string());
            }
            if cond.timeout_height == 0 {
                return Err("refund timeout_height must be > 0".to_string());
            }
        }
        for milestone in &self.milestones {
            if milestone.milestone_id.trim().is_empty() {
                return Err("milestone_id required".to_string());
            }
            if !milestone_ids.insert(milestone.milestone_id.as_str()) {
                return Err(format!("duplicate milestone_id {}", milestone.milestone_id));
            }
            if milestone.title.trim().is_empty() {
                return Err(format!(
                    "milestone title required for {}",
                    milestone.milestone_id
                ));
            }
            if milestone.amount == 0 {
                return Err("milestone amount must be > 0".to_string());
            }
            if milestone.recipient_address.trim().is_empty() {
                return Err(format!(
                    "milestone recipient_address required for {}",
                    milestone.milestone_id
                ));
            }
            if milestone.refund_address.trim().is_empty() {
                return Err(format!(
                    "milestone refund_address required for {}",
                    milestone.milestone_id
                ));
            }
            if milestone.secret_hash_hex.len() != 64
                || hex::decode(&milestone.secret_hash_hex).is_err()
            {
                return Err(format!(
                    "invalid milestone secret_hash_hex for {}",
                    milestone.milestone_id
                ));
            }
            if milestone.timeout_height == 0 {
                return Err(format!(
                    "milestone timeout_height must be > 0 for {}",
                    milestone.milestone_id
                ));
            }
        }
        if let Some(rule) = &self.deposit_rule {
            if rule.amount == 0 {
                return Err("deposit amount must be > 0".to_string());
            }
            if rule.beneficiary_address.trim().is_empty() {
                return Err("deposit beneficiary_address required".to_string());
            }
            if rule.refund_address.trim().is_empty() {
                return Err("deposit refund_address required".to_string());
            }
            if rule.timeout_height == 0 {
                return Err("deposit timeout_height must be > 0".to_string());
            }
        }
        // Resolver fields are only allowed on dispute-eligible templates.
        let resolver_eligible = matches!(
            self.template_type,
            AgreementTemplateType::OtcSettlement
                | AgreementTemplateType::MilestoneSettlement
                | AgreementTemplateType::ContractorMilestone
        );
        if !resolver_eligible
            && (self.primary_resolver.is_some()
                || self.fallback_resolver.is_some()
                || self.primary_resolver_fee.is_some()
                || self.fallback_resolver_fee.is_some())
        {
            return Err(
                "resolver fields are only allowed on OTC, milestone, and contractor templates"
                    .to_string(),
            );
        }
        if let Some(addr) = &self.primary_resolver {
            let fee = self.primary_resolver_fee.ok_or_else(|| {
                "primary_resolver_fee required when primary_resolver is set".to_string()
            })?;
            if fee == 0 {
                return Err("primary_resolver_fee must be > 0".to_string());
            }
            if fee >= self.total_amount {
                return Err("primary_resolver_fee must be < total_amount".to_string());
            }
            if addr.trim().is_empty() {
                return Err("primary_resolver address required".to_string());
            }
        } else if self.primary_resolver_fee.is_some() {
            return Err("primary_resolver_fee set without primary_resolver".to_string());
        }
        if let Some(addr) = &self.fallback_resolver {
            let primary = self.primary_resolver.as_ref().ok_or_else(|| {
                "fallback_resolver requires primary_resolver".to_string()
            })?;
            let fee = self.fallback_resolver_fee.ok_or_else(|| {
                "fallback_resolver_fee required when fallback_resolver is set".to_string()
            })?;
            if fee == 0 {
                return Err("fallback_resolver_fee must be > 0".to_string());
            }
            if addr.trim().is_empty() {
                return Err("fallback_resolver address required".to_string());
            }
            if addr.trim() == primary.trim() {
                return Err("fallback_resolver must differ from primary_resolver".to_string());
            }
            let prim_fee = self.primary_resolver_fee.unwrap_or(0);
            if prim_fee.saturating_add(fee) >= self.total_amount {
                return Err(
                    "primary + fallback resolver fees must be < total_amount".to_string(),
                );
            }
        } else if self.fallback_resolver_fee.is_some() {
            return Err("fallback_resolver_fee set without fallback_resolver".to_string());
        }
        Ok(())
    }

    pub fn summary(&self) -> Result<AgreementSummary, String> {
        Ok(AgreementSummary {
            agreement_hash: compute_agreement_hash_hex(self)?,
            total_amount: self.total_amount,
            template_type: self.template_type,
            milestone_count: self.milestones.len(),
            uses_htlc_timeout: true,
            has_deposit_rule: self.deposit_rule.is_some(),
            canonical_json: agreement_canonical_value(self)?,
        })
    }
}

pub fn build_agreement_anchor_payload(anchor: &AgreementAnchor) -> Result<Vec<u8>, String> {
    if anchor.agreement_hash.len() != 64 || hex::decode(&anchor.agreement_hash).is_err() {
        return Err("agreement hash must be 32-byte hex".to_string());
    }
    let mut payload = format!(
        "{}{}:{}",
        AGREEMENT_ANCHOR_PREFIX,
        anchor.agreement_hash,
        anchor.role.short_code()
    );
    if let Some(m) = &anchor.milestone_id {
        payload.push(':');
        payload.push_str(m);
    }
    if payload.len() > 75 {
        return Err("agreement anchor payload too large".to_string());
    }
    Ok(payload.into_bytes())
}

pub fn build_agreement_anchor_output(anchor: &AgreementAnchor) -> Result<TxOutput, String> {
    let payload = build_agreement_anchor_payload(anchor)?;
    let mut script = Vec::with_capacity(2 + payload.len());
    script.push(0x6a);
    script.push(payload.len() as u8);
    script.extend_from_slice(&payload);
    Ok(TxOutput {
        value: 0,
        script_pubkey: script,
    })
}

pub fn parse_agreement_anchor(script_pubkey: &[u8]) -> Option<AgreementAnchor> {
    if script_pubkey.len() < 2 || script_pubkey[0] != 0x6a {
        return None;
    }
    let len = script_pubkey[1] as usize;
    if script_pubkey.len() != len + 2 {
        return None;
    }
    let payload = std::str::from_utf8(&script_pubkey[2..]).ok()?;
    let rest = payload.strip_prefix(AGREEMENT_ANCHOR_PREFIX)?;
    let mut parts = rest.split(':');
    let agreement_hash = parts.next()?.to_string();
    let role = AgreementAnchorRole::from_short_code(parts.next()?)?;
    let milestone_id = parts.next().map(|v| v.to_string());
    if parts.next().is_some() {
        return None;
    }
    Some(AgreementAnchor {
        agreement_hash,
        role,
        milestone_id,
    })
}

// ============================================================
// GROUP H: on-chain reputation event anchoring
// ============================================================

pub const REPUTATION_EVENT_PREFIX: &str = "rep1:";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReputationEventKind {
    /// Recorded in the same tx as an agr1:l or agr1:m release anchor.
    /// Names a party who completed a trade. Q3: both parties get one
    /// rep1:s anchor per release tx (two outputs).
    SuccessfulTrade,
    /// Recorded in the same tx as an agr1:x dispute-resolve anchor.
    /// Names the party whose position the resolver upheld.
    DisputeWin,
    /// Recorded in the same tx as an agr1:x dispute-resolve anchor.
    /// Names the party whose position the resolver rejected.
    DisputeLoss,
    /// Standalone tx broadcast by any party after the resolver's
    /// response window has elapsed without a resolution anchor. Names
    /// the unresponsive resolver. Carries a short 8-byte agreement
    /// hash prefix so iriumd can locate the dispute being indicted.
    ResolverNonResponse,
}

impl ReputationEventKind {
    pub fn short_code(self) -> &'static str {
        match self {
            Self::SuccessfulTrade => "s",
            Self::DisputeWin => "w",
            Self::DisputeLoss => "l",
            Self::ResolverNonResponse => "n",
        }
    }

    pub fn from_short_code(v: &str) -> Option<Self> {
        match v {
            "s" => Some(Self::SuccessfulTrade),
            "w" => Some(Self::DisputeWin),
            "l" => Some(Self::DisputeLoss),
            "n" => Some(Self::ResolverNonResponse),
            _ => None,
        }
    }

    /// Whether this event kind expects a 16-hex-char agreement short
    /// hash carried inside the rep1 payload. Only ResolverNonResponse
    /// does (it has no co-located agr1 anchor in the same tx to
    /// recover the full hash from).
    pub fn carries_agreement_short_hash(self) -> bool {
        matches!(self, Self::ResolverNonResponse)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReputationEvent {
    pub kind: ReputationEventKind,
    /// Base58Check address of the party being attested. The on-chain
    /// payload carries the address as the user-facing base58 string so
    /// the payload remains human-readable and parseable without
    /// requiring iriumd to know the version byte.
    pub address: String,
    /// First 16 hex chars (8 bytes) of the agreement hash. Set only
    /// for ResolverNonResponse; None otherwise (recover the full hash
    /// from the carrying tx's agr1: anchor).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agreement_short_hash: Option<String>,
}

/// Build the bare ASCII payload (no OP_RETURN wrapper). 75-byte cap
/// matches the agr1 anchor cap so the same downstream OP_RETURN
/// builders can carry it.
pub fn build_reputation_event_payload(event: &ReputationEvent) -> Result<Vec<u8>, String> {
    if event.address.trim().is_empty() {
        return Err("reputation event address must not be empty".to_string());
    }
    if event.address.contains(':') {
        return Err("reputation event address must not contain ':'".to_string());
    }
    let mut payload = format!(
        "{}{}:{}",
        REPUTATION_EVENT_PREFIX,
        event.kind.short_code(),
        event.address
    );
    if event.kind.carries_agreement_short_hash() {
        let sh = event
            .agreement_short_hash
            .as_deref()
            .ok_or_else(|| "ResolverNonResponse requires agreement_short_hash".to_string())?;
        if sh.len() != 16 || !sh.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("agreement_short_hash must be 16 hex chars (8 bytes)".to_string());
        }
        payload.push(':');
        payload.push_str(sh);
    } else if event.agreement_short_hash.is_some() {
        return Err(
            "agreement_short_hash is only valid for ResolverNonResponse events".to_string(),
        );
    }
    if payload.len() > 75 {
        return Err(format!(
            "reputation event payload too large ({} > 75 bytes)",
            payload.len()
        ));
    }
    Ok(payload.into_bytes())
}

pub fn build_reputation_event_output(event: &ReputationEvent) -> Result<TxOutput, String> {
    let payload = build_reputation_event_payload(event)?;
    let mut script = Vec::with_capacity(2 + payload.len());
    script.push(0x6a);
    script.push(payload.len() as u8);
    script.extend_from_slice(&payload);
    Ok(TxOutput {
        value: 0,
        script_pubkey: script,
    })
}

pub fn parse_reputation_event(script_pubkey: &[u8]) -> Option<ReputationEvent> {
    if script_pubkey.len() < 2 || script_pubkey[0] != 0x6a {
        return None;
    }
    let len = script_pubkey[1] as usize;
    if script_pubkey.len() != len + 2 {
        return None;
    }
    let payload = std::str::from_utf8(&script_pubkey[2..]).ok()?;
    let rest = payload.strip_prefix(REPUTATION_EVENT_PREFIX)?;
    let mut parts = rest.split(':');
    let kind = ReputationEventKind::from_short_code(parts.next()?)?;
    let address = parts.next()?.to_string();
    if address.is_empty() {
        return None;
    }
    let agreement_short_hash = if kind.carries_agreement_short_hash() {
        let sh = parts.next()?.to_string();
        if sh.len() != 16 || !sh.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        Some(sh)
    } else {
        None
    };
    if parts.next().is_some() {
        return None;
    }
    Some(ReputationEvent {
        kind,
        address,
        agreement_short_hash,
    })
}

/// Convenience helper: first 16 hex chars of an agreement hash, used as
/// the on-chain short hash for ResolverNonResponse events. Returns Err
/// when the input is not a 64-hex-char string.
pub fn agreement_short_hash_from_full(full_hex: &str) -> Result<String, String> {
    if full_hex.len() != 64 || !full_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("agreement hash must be 64 hex chars".to_string());
    }
    Ok(full_hex[..16].to_string())
}

pub fn extract_agreement_funding_leg_refs_from_tx(
    tx: &Transaction,
    agreement_hash: &str,
) -> Vec<AgreementFundingLegRef> {
    let funding_txid = hex::encode(tx.txid());
    let mut out = Vec::new();
    for (idx, output) in tx.outputs.iter().enumerate() {
        let Some(htlc) = parse_htlcv1_script(&output.script_pubkey) else {
            continue;
        };
        let anchor_vout = idx + 1;
        let Some(anchor_output) = tx.outputs.get(anchor_vout) else {
            continue;
        };
        let Some(anchor) = parse_agreement_anchor(&anchor_output.script_pubkey) else {
            continue;
        };
        if anchor.agreement_hash != agreement_hash {
            continue;
        }
        out.push(AgreementFundingLegRef {
            funding_txid: funding_txid.clone(),
            htlc_vout: idx as u32,
            anchor_vout: anchor_vout as u32,
            role: anchor.role,
            milestone_id: anchor.milestone_id,
            amount: output.value,
            timeout_height: htlc.timeout_height,
            expected_hash: hex::encode(htlc.expected_hash),
            recipient_address: bs58::encode({
                let mut body = Vec::with_capacity(1 + 20 + 4);
                body.push(0x00);
                body.extend_from_slice(&htlc.recipient_pkh);
                let first = sha2::Sha256::digest(&body);
                let second = sha2::Sha256::digest(first);
                body.extend_from_slice(&second[0..4]);
                body
            })
            .into_string(),
            refund_address: bs58::encode({
                let mut body = Vec::with_capacity(1 + 20 + 4);
                body.push(0x00);
                body.extend_from_slice(&htlc.refund_pkh);
                let first = sha2::Sha256::digest(&body);
                let second = sha2::Sha256::digest(first);
                body.extend_from_slice(&second[0..4]);
                body
            })
            .into_string(),
        });
    }
    out
}

pub fn build_funding_legs(
    agreement: &AgreementObject,
    payer_pkh: [u8; 20],
    payee_pkh: [u8; 20],
) -> Result<Vec<SettlementFundingLeg>, String> {
    agreement.validate()?;
    let mut legs = Vec::new();
    match agreement.template_type {
        AgreementTemplateType::MilestoneSettlement | AgreementTemplateType::ContractorMilestone => {
            for milestone in &agreement.milestones {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(
                    &hex::decode(&milestone.secret_hash_hex)
                        .map_err(|_| "invalid milestone secret hash".to_string())?,
                );
                let output = HtlcV1Output {
                    expected_hash: hash,
                    recipient_pkh: payee_pkh,
                    refund_pkh: payer_pkh,
                    timeout_height: milestone.timeout_height,
                };
                legs.push(SettlementFundingLeg {
                    role: AgreementAnchorRole::Funding,
                    milestone_id: Some(milestone.milestone_id.clone()),
                    amount: milestone.amount,
                    output: TxOutput {
                        value: milestone.amount,
                        script_pubkey: encode_htlcv1_script(&output),
                    },
                });
            }
        }
        _ => {
            let release = agreement
                .release_conditions
                .iter()
                .find(|c| c.mode == "secret_preimage")
                .ok_or_else(|| {
                    "simple agreement requires secret_preimage release condition".to_string()
                })?;
            let secret_hash_hex = release.secret_hash_hex.as_ref().ok_or_else(|| {
                "secret_preimage release condition requires secret_hash_hex".to_string()
            })?;
            let mut hash = [0u8; 32];
            hash.copy_from_slice(
                &hex::decode(secret_hash_hex).map_err(|_| "invalid secret_hash_hex".to_string())?,
            );
            let refund = agreement
                .refund_conditions
                .first()
                .ok_or_else(|| "refund condition required".to_string())?;
            let output = HtlcV1Output {
                expected_hash: hash,
                recipient_pkh: payee_pkh,
                refund_pkh: payer_pkh,
                timeout_height: refund.timeout_height,
            };
            let role = match agreement.template_type {
                AgreementTemplateType::RefundableDeposit => AgreementAnchorRole::DepositLock,
                AgreementTemplateType::OtcSettlement => AgreementAnchorRole::OtcSettlement,
                AgreementTemplateType::MerchantDelayedSettlement => {
                    AgreementAnchorRole::MerchantSettlement
                }
                _ => AgreementAnchorRole::Funding,
            };
            legs.push(SettlementFundingLeg {
                role,
                milestone_id: None,
                amount: agreement.total_amount,
                output: TxOutput {
                    value: agreement.total_amount,
                    script_pubkey: encode_htlcv1_script(&output),
                },
            });
        }
    }
    Ok(legs)
}

fn is_funding_leg_role(role: AgreementAnchorRole) -> bool {
    matches!(
        role,
        AgreementAnchorRole::Funding
            | AgreementAnchorRole::DepositLock
            | AgreementAnchorRole::OtcSettlement
            | AgreementAnchorRole::MerchantSettlement
    )
}

pub fn discover_agreement_funding_leg_candidates(
    agreement_hash: &str,
    linked_txs: &[AgreementLinkedTx],
    observed_refs: &[AgreementFundingLegRef],
    bundle_metadata: Option<&AgreementBundleMetadata>,
) -> Result<Vec<AgreementFundingLegCandidate>, String> {
    let mut candidates = Vec::new();
    for leg in observed_refs {
        if !is_funding_leg_role(leg.role) {
            continue;
        }
        let mut source_notes = vec!["direct_anchor_match".to_string()];
        if linked_txs.iter().any(|tx| {
            tx.txid == leg.funding_txid
                && tx.role == leg.role
                && tx.milestone_id == leg.milestone_id
        }) {
            source_notes.push("linked_tx_observed".to_string());
        }
        if let Some(meta) = bundle_metadata {
            if meta
                .linked_funding_txids
                .iter()
                .any(|txid| txid.eq_ignore_ascii_case(&leg.funding_txid))
            {
                source_notes.push("bundle_linked_funding_txid".to_string());
            }
            if let Some(mid) = leg.milestone_id.as_deref() {
                let milestone_hint_match = meta.milestone_hints.iter().any(|hint| {
                    hint.milestone_id == mid
                        && hint
                            .funding_txid
                            .as_deref()
                            .map(|txid| txid.eq_ignore_ascii_case(&leg.funding_txid))
                            .unwrap_or(true)
                        && hint
                            .htlc_vout
                            .map(|vout| vout == leg.htlc_vout)
                            .unwrap_or(true)
                });
                if milestone_hint_match {
                    source_notes.push("bundle_milestone_hint".to_string());
                }
            }
        }
        candidates.push(AgreementFundingLegCandidate {
            agreement_hash: agreement_hash.to_string(),
            funding_txid: leg.funding_txid.clone(),
            htlc_vout: leg.htlc_vout,
            anchor_vout: leg.anchor_vout,
            role: leg.role,
            milestone_id: leg.milestone_id.clone(),
            amount: leg.amount,
            htlc_backed: true,
            timeout_height: leg.timeout_height,
            recipient_address: leg.recipient_address.clone(),
            refund_address: leg.refund_address.clone(),
            source_notes,
        });
    }
    if let Some(meta) = bundle_metadata {
        for txid in &meta.linked_funding_txids {
            if !candidates
                .iter()
                .any(|candidate| candidate.funding_txid.eq_ignore_ascii_case(txid))
            {
                return Err(format!(
                    "bundle linked funding txid {} not found in observed agreement funding legs",
                    txid
                ));
            }
        }
        for hint in &meta.milestone_hints {
            let matches = candidates
                .iter()
                .filter(|candidate| {
                    candidate.milestone_id.as_deref() == Some(hint.milestone_id.as_str())
                })
                .filter(|candidate| {
                    hint.funding_txid
                        .as_deref()
                        .map(|txid| candidate.funding_txid.eq_ignore_ascii_case(txid))
                        .unwrap_or(true)
                })
                .filter(|candidate| {
                    hint.htlc_vout
                        .map(|v| candidate.htlc_vout == v)
                        .unwrap_or(true)
                })
                .count();
            if matches == 0 {
                return Err(format!(
                    "bundle milestone hint for {} conflicts with observed agreement funding legs",
                    hint.milestone_id
                ));
            }
        }
    }
    candidates.sort_by(|a, b| {
        a.milestone_id
            .cmp(&b.milestone_id)
            .then_with(|| a.funding_txid.cmp(&b.funding_txid))
            .then_with(|| a.htlc_vout.cmp(&b.htlc_vout))
    });
    Ok(candidates)
}

pub fn build_agreement_activity_timeline(
    agreement_hash: &str,
    lifecycle: &AgreementLifecycleView,
    linked_txs: &[AgreementLinkedTx],
    funding_legs: &[AgreementFundingLegCandidate],
    bundle: Option<&AgreementBundle>,
) -> Vec<AgreementActivityEvent> {
    let mut events = Vec::new();
    events.push(AgreementActivityEvent {
        event_type: "agreement_hash_computed".to_string(),
        source: AgreementActivitySource::DerivedIndexed,
        txid: None,
        height: None,
        timestamp: None,
        milestone_id: None,
        note: Some(format!(
            "canonical agreement hash {} verified from supplied agreement object",
            agreement_hash
        )),
    });
    if let Some(bundle) = bundle {
        events.push(AgreementActivityEvent {
            event_type: "bundle_hash_verified".to_string(),
            source: AgreementActivitySource::LocalBundle,
            txid: None,
            height: None,
            timestamp: Some(bundle.metadata.saved_at),
            milestone_id: None,
            note: Some(
                "saved agreement bundle matches the contained canonical agreement object"
                    .to_string(),
            ),
        });
        if bundle.metadata.saved_at > 0 {
            events.push(AgreementActivityEvent {
                event_type: "agreement_saved_local".to_string(),
                source: AgreementActivitySource::LocalBundle,
                txid: None,
                height: None,
                timestamp: Some(bundle.metadata.saved_at),
                milestone_id: None,
                note: Some("agreement bundle saved in the local Phase 1 bundle store".to_string()),
            });
        }
    }
    let mut ordered_linked = linked_txs.to_vec();
    ordered_linked.sort_by(|a, b| {
        a.height
            .cmp(&b.height)
            .then_with(|| a.txid.cmp(&b.txid))
            .then_with(|| a.milestone_id.cmp(&b.milestone_id))
    });
    for tx in ordered_linked {
        let event_type = match tx.role {
            AgreementAnchorRole::Funding
            | AgreementAnchorRole::DepositLock
            | AgreementAnchorRole::OtcSettlement
            | AgreementAnchorRole::MerchantSettlement => "funding_tx_observed",
            AgreementAnchorRole::Release | AgreementAnchorRole::MilestoneRelease => {
                "release_tx_observed"
            }
            AgreementAnchorRole::Refund => "refund_tx_observed",
            AgreementAnchorRole::CollateralLock => "linked_tx_observed",
            AgreementAnchorRole::DisputeRaise => "dispute_raise_tx_observed",
            AgreementAnchorRole::DisputeEvidence => "dispute_evidence_tx_observed",
            AgreementAnchorRole::DisputeResolve => "dispute_resolve_tx_observed",
            AgreementAnchorRole::ResolverRegister => "resolver_register_tx_observed",
        };
        events.push(AgreementActivityEvent {
            event_type: event_type.to_string(),
            source: AgreementActivitySource::ChainObserved,
            txid: Some(tx.txid.clone()),
            height: tx.height,
            timestamp: None,
            milestone_id: tx.milestone_id.clone(),
            note: Some(format!(
                "linked transaction observed with anchor role {:?}",
                tx.role
            )),
        });
    }
    for leg in funding_legs {
        events.push(AgreementActivityEvent {
            event_type: "funding_leg_discovered".to_string(),
            source: AgreementActivitySource::DerivedIndexed,
            txid: Some(leg.funding_txid.clone()),
            height: linked_txs
                .iter()
                .find(|tx| {
                    tx.txid == leg.funding_txid
                        && tx.role == leg.role
                        && tx.milestone_id == leg.milestone_id
                })
                .and_then(|tx| tx.height),
            timestamp: None,
            milestone_id: leg.milestone_id.clone(),
            note: Some(format!(
                "candidate HTLC-backed funding leg discovered from anchor role {:?}",
                leg.role
            )),
        });
        if leg.milestone_id.is_some() {
            events.push(AgreementActivityEvent {
                event_type: "milestone_linked".to_string(),
                source: AgreementActivitySource::DerivedIndexed,
                txid: Some(leg.funding_txid.clone()),
                height: linked_txs
                    .iter()
                    .find(|tx| {
                        tx.txid == leg.funding_txid
                            && tx.role == leg.role
                            && tx.milestone_id == leg.milestone_id
                    })
                    .and_then(|tx| tx.height),
                timestamp: None,
                milestone_id: leg.milestone_id.clone(),
                note: Some("funding leg tied to a specific agreement milestone".to_string()),
            });
        }
    }
    if funding_legs.len() > 1 {
        events.push(AgreementActivityEvent {
            event_type: "ambiguous_funding_leg_detected".to_string(),
            source: AgreementActivitySource::DerivedIndexed,
            txid: None,
            height: None,
            timestamp: None,
            milestone_id: None,
            note: Some(
                "multiple candidate funding legs were discovered; explicit operator selection may be required"
                    .to_string(),
            ),
        });
    }
    if lifecycle.state == AgreementLifecycleState::Expired {
        events.push(AgreementActivityEvent {
            event_type: "agreement_expired".to_string(),
            source: AgreementActivitySource::DerivedIndexed,
            txid: None,
            height: None,
            timestamp: None,
            milestone_id: None,
            note: Some(
                "refund timeout has been reached according to the reconstructed lifecycle view"
                    .to_string(),
            ),
        });
    }
    events
}

fn agreement_lifecycle_state_label(state: AgreementLifecycleState) -> String {
    match state {
        AgreementLifecycleState::Draft => "draft",
        AgreementLifecycleState::Proposed => "proposed",
        AgreementLifecycleState::Funded => "funded",
        AgreementLifecycleState::PartiallyReleased => "partially_released",
        AgreementLifecycleState::Released => "released",
        AgreementLifecycleState::Refunded => "refunded",
        AgreementLifecycleState::Expired => "expired",
        AgreementLifecycleState::Cancelled => "cancelled",
        AgreementLifecycleState::DisputedMetadataOnly => "disputed_metadata_only",
    }
    .to_string()
}

fn csv_escape(value: &str) -> String {
    let escaped = value.replace('"', "\"\"");
    format!("\"{}\"", escaped)
}

fn csv_bool(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn csv_opt_bool(value: Option<bool>) -> String {
    value.map(|v| csv_bool(v).to_string()).unwrap_or_default()
}

fn csv_template_name(template: AgreementTemplateType) -> String {
    serde_json::to_string(&template)
        .unwrap_or_else(|_| "\"unknown\"".to_string())
        .trim_matches('"')
        .to_string()
}

fn csv_push_row(out: &mut String, cols: &[String]) {
    out.push_str(
        &cols
            .iter()
            .map(|v| csv_escape(v))
            .collect::<Vec<_>>()
            .join(","),
    );
    out.push('\n');
}

pub fn render_agreement_audit_csv(record: &AgreementAuditRecord) -> String {
    let mut out = String::new();
    csv_push_row(
        &mut out,
        &[
            "record_version".to_string(),
            "csv_schema".to_string(),
            "section".to_string(),
            "row_index".to_string(),
            "data_source".to_string(),
            "trust_boundary".to_string(),
            "agreement_id".to_string(),
            "agreement_hash".to_string(),
            "template_type".to_string(),
            "payer".to_string(),
            "payee".to_string(),
            "total_amount".to_string(),
            "derived_state".to_string(),
            "bundle_used".to_string(),
            "selection_required".to_string(),
            "ambiguity_flag".to_string(),
            "txid".to_string(),
            "vout".to_string(),
            "anchor_vout".to_string(),
            "anchor_role".to_string(),
            "milestone_id".to_string(),
            "amount".to_string(),
            "height".to_string(),
            "confirmed".to_string(),
            "htlc_backed".to_string(),
            "release_eligible".to_string(),
            "refund_eligible".to_string(),
            "event_type".to_string(),
            "timestamp".to_string(),
            "detail".to_string(),
            "note".to_string(),
        ],
    );

    csv_push_row(
        &mut out,
        &[
            record.metadata.version.to_string(),
            AGREEMENT_AUDIT_CSV_SCHEMA.to_string(),
            "summary".to_string(),
            "0".to_string(),
            "derived_report".to_string(),
            "derived_indexed".to_string(),
            record.agreement.agreement_id.clone(),
            record.agreement.agreement_hash.clone(),
            csv_template_name(record.agreement.template_type),
            record.agreement.payer.clone(),
            record.agreement.payee.clone(),
            record.agreement.total_amount.to_string(),
            record.settlement_state.derived_state_label.clone(),
            csv_bool(record.local_bundle.bundle_used).to_string(),
            csv_bool(record.funding_legs.selection_required).to_string(),
            csv_bool(record.funding_legs.ambiguity_warning.is_some()).to_string(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            format!(
                "derived_report=true; linked_tx_count={}; timeline_events={}; trust_model={}",
                record.chain_observed.linked_transaction_count,
                record.timeline.event_count,
                record.metadata.trust_model_summary
            ),
            record.settlement_state.summary_note.clone(),
        ],
    );

    for (idx, tx) in record.chain_observed.linked_transactions.iter().enumerate() {
        csv_push_row(
            &mut out,
            &[
                record.metadata.version.to_string(),
                AGREEMENT_AUDIT_CSV_SCHEMA.to_string(),
                "linked_tx".to_string(),
                idx.to_string(),
                "chain_observed".to_string(),
                "consensus_visible_anchor_or_tx".to_string(),
                record.agreement.agreement_id.clone(),
                record.agreement.agreement_hash.clone(),
                csv_template_name(record.agreement.template_type),
                record.agreement.payer.clone(),
                record.agreement.payee.clone(),
                record.agreement.total_amount.to_string(),
                record.settlement_state.derived_state_label.clone(),
                csv_bool(record.local_bundle.bundle_used).to_string(),
                csv_bool(record.funding_legs.selection_required).to_string(),
                csv_bool(record.funding_legs.ambiguity_warning.is_some()).to_string(),
                tx.txid.clone(),
                String::new(),
                serde_json::to_string(&tx.role)
                    .unwrap_or_else(|_| "\"unknown\"".to_string())
                    .trim_matches('"')
                    .to_string(),
                tx.milestone_id.clone().unwrap_or_default(),
                tx.value.to_string(),
                tx.height.map(|v| v.to_string()).unwrap_or_default(),
                csv_bool(tx.confirmed).to_string(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                record.chain_observed.anchor_observation_notice.clone(),
                String::new(),
            ],
        );
    }

    for (idx, leg) in record.funding_legs.candidates.iter().enumerate() {
        let selected = record
            .funding_legs
            .selected_leg
            .as_ref()
            .map(|sel| sel.funding_txid == leg.funding_txid && sel.htlc_vout == leg.htlc_vout)
            .unwrap_or(false);
        csv_push_row(
            &mut out,
            &[
                record.metadata.version.to_string(),
                AGREEMENT_AUDIT_CSV_SCHEMA.to_string(),
                "funding_leg".to_string(),
                idx.to_string(),
                "derived_funding_leg".to_string(),
                if leg.htlc_backed {
                    "htlc_enforced_branch_candidate".to_string()
                } else {
                    "derived_non_htlc_candidate".to_string()
                },
                record.agreement.agreement_id.clone(),
                record.agreement.agreement_hash.clone(),
                csv_template_name(record.agreement.template_type),
                record.agreement.payer.clone(),
                record.agreement.payee.clone(),
                record.agreement.total_amount.to_string(),
                record.settlement_state.derived_state_label.clone(),
                csv_bool(record.local_bundle.bundle_used).to_string(),
                csv_bool(record.funding_legs.selection_required).to_string(),
                csv_bool(record.funding_legs.ambiguity_warning.is_some()).to_string(),
                leg.funding_txid.clone(),
                leg.htlc_vout.to_string(),
                leg.anchor_vout.to_string(),
                serde_json::to_string(&leg.role)
                    .unwrap_or_else(|_| "\"unknown\"".to_string())
                    .trim_matches('"')
                    .to_string(),
                leg.milestone_id.clone().unwrap_or_default(),
                leg.amount.to_string(),
                leg.timeout_height.to_string(),
                String::new(),
                csv_bool(leg.htlc_backed).to_string(),
                csv_opt_bool(leg.release_eligible),
                csv_opt_bool(leg.refund_eligible),
                String::new(),
                String::new(),
                format!(
                    "selected_candidate={}; source_notes={}",
                    csv_bool(selected),
                    leg.source_notes.join(" | ")
                ),
                record.funding_legs.notice.clone(),
            ],
        );
    }

    for (idx, event) in record.timeline.events.iter().enumerate() {
        let (data_source, trust_boundary) = match event.source {
            AgreementActivitySource::LocalBundle => ("local_bundle", "local_bundle_only"),
            AgreementActivitySource::ChainObserved => {
                ("chain_observed", "consensus_visible_anchor_or_tx")
            }
            AgreementActivitySource::DerivedIndexed => ("derived_indexed", "derived_indexed"),
            AgreementActivitySource::HtlcEligibility => {
                ("htlc_eligibility", "htlc_enforced_branch_candidate")
            }
        };
        csv_push_row(
            &mut out,
            &[
                record.metadata.version.to_string(),
                AGREEMENT_AUDIT_CSV_SCHEMA.to_string(),
                "timeline_event".to_string(),
                idx.to_string(),
                data_source.to_string(),
                trust_boundary.to_string(),
                record.agreement.agreement_id.clone(),
                record.agreement.agreement_hash.clone(),
                csv_template_name(record.agreement.template_type),
                record.agreement.payer.clone(),
                record.agreement.payee.clone(),
                record.agreement.total_amount.to_string(),
                record.settlement_state.derived_state_label.clone(),
                csv_bool(record.local_bundle.bundle_used).to_string(),
                csv_bool(record.funding_legs.selection_required).to_string(),
                csv_bool(record.funding_legs.ambiguity_warning.is_some()).to_string(),
                event.txid.clone().unwrap_or_default(),
                String::new(),
                String::new(),
                String::new(),
                event.milestone_id.clone().unwrap_or_default(),
                String::new(),
                event.height.map(|v| v.to_string()).unwrap_or_default(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                event.event_type.clone(),
                event.timestamp.map(|v| v.to_string()).unwrap_or_default(),
                event.note.clone().unwrap_or_default(),
                record.timeline.notice.clone(),
            ],
        );
    }

    let trust_sections = [
        (
            "consensus_enforced",
            &record.trust_boundaries.consensus_enforced,
        ),
        ("htlc_enforced", &record.trust_boundaries.htlc_enforced),
        (
            "metadata_indexed",
            &record.trust_boundaries.metadata_indexed,
        ),
        (
            "local_bundle_only",
            &record.trust_boundaries.local_bundle_only,
        ),
        (
            "off_chain_required",
            &record.trust_boundaries.off_chain_required,
        ),
    ];
    for (section_idx, (section, items)) in trust_sections.iter().enumerate() {
        for (item_idx, item) in items.iter().enumerate() {
            csv_push_row(
                &mut out,
                &[
                    record.metadata.version.to_string(),
                    AGREEMENT_AUDIT_CSV_SCHEMA.to_string(),
                    "trust_boundary".to_string(),
                    format!("{}.{}", section_idx, item_idx),
                    "trust_boundary_summary".to_string(),
                    (*section).to_string(),
                    record.agreement.agreement_id.clone(),
                    record.agreement.agreement_hash.clone(),
                    csv_template_name(record.agreement.template_type),
                    record.agreement.payer.clone(),
                    record.agreement.payee.clone(),
                    record.agreement.total_amount.to_string(),
                    record.settlement_state.derived_state_label.clone(),
                    csv_bool(record.local_bundle.bundle_used).to_string(),
                    csv_bool(record.funding_legs.selection_required).to_string(),
                    csv_bool(record.funding_legs.ambiguity_warning.is_some()).to_string(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    item.clone(),
                    String::new(),
                ],
            );
        }
    }

    out
}

fn build_agreement_statement_authenticity(
    authenticity: Option<&AgreementAuthenticitySummary>,
) -> Option<AgreementStatementAuthenticitySummary> {
    authenticity.map(|authenticity| AgreementStatementAuthenticitySummary {
        valid_signatures: authenticity.valid_signatures,
        invalid_signatures: authenticity.invalid_signatures,
        unverifiable_signatures: authenticity.unverifiable_signatures,
        compact_summary: format!(
            "Agreement authenticity summary: {} valid, {} invalid, {} unverifiable signature(s)",
            authenticity.valid_signatures,
            authenticity.invalid_signatures,
            authenticity.unverifiable_signatures
        ),
        authenticity_notice: authenticity.authenticity_notice.clone(),
    })
}

pub fn build_agreement_statement(record: &AgreementAuditRecord) -> AgreementStatement {
    let parties_summary = record
        .agreement
        .parties
        .iter()
        .map(|party| {
            let role = party.role.as_deref().unwrap_or("party");
            format!("{}: {} <{}>", role, party.display_name, party.address)
        })
        .collect::<Vec<_>>();
    let milestone_summary = if record.agreement.milestones.is_empty() {
        "No milestone schedule in the supplied agreement".to_string()
    } else {
        format!(
            "{} milestone(s) totaling {} smallest units",
            record.agreement.milestones.len(),
            record
                .agreement
                .milestones
                .iter()
                .map(|m| m.amount)
                .sum::<u64>()
        )
    };
    let release_path_summary = if record
        .funding_legs
        .selected_leg
        .as_ref()
        .map(|leg| leg.htlc_backed)
        .unwrap_or(false)
        || record
            .funding_legs
            .candidates
            .iter()
            .any(|leg| leg.htlc_backed)
    {
        "HTLC-backed release spend may be available for observed funding legs; release still depends on the correct spend path and may require off-chain coordination.".to_string()
    } else {
        "No HTLC-backed release leg has been confirmed from the supplied agreement data and observed chain links.".to_string()
    };
    let refund_path_summary = if record
        .funding_legs
        .selected_leg
        .as_ref()
        .map(|leg| leg.htlc_backed)
        .unwrap_or(false)
        || record
            .funding_legs
            .candidates
            .iter()
            .any(|leg| leg.htlc_backed)
    {
        "HTLC-backed timeout refund may be available where a funded leg reaches its timeout; refund still requires the correct spend path.".to_string()
    } else {
        "No HTLC-backed refund leg has been confirmed from the supplied agreement data and observed chain links.".to_string()
    };
    let funding_observed = record
        .chain_observed
        .linked_transactions
        .iter()
        .any(|tx| tx.role == AgreementAnchorRole::Funding);
    let release_observed = record.chain_observed.linked_transactions.iter().any(|tx| {
        matches!(
            tx.role,
            AgreementAnchorRole::Release | AgreementAnchorRole::MilestoneRelease
        )
    });
    let refund_observed = record
        .chain_observed
        .linked_transactions
        .iter()
        .any(|tx| tx.role == AgreementAnchorRole::Refund);
    let linked_txids = record
        .chain_observed
        .linked_transactions
        .iter()
        .map(|tx| tx.txid.clone())
        .collect::<Vec<_>>();
    AgreementStatement {
        metadata: AgreementStatementMetadata {
            version: AGREEMENT_STATEMENT_VERSION,
            generated_at: record.metadata.generated_at,
            derived_notice: "Derived settlement statement from supplied agreement data plus observed chain activity. This is not native consensus contract state.".to_string(),
        },
        identity: AgreementStatementIdentity {
            agreement_id: record.agreement.agreement_id.clone(),
            agreement_hash: record.agreement.agreement_hash.clone(),
            template_type: record.agreement.template_type,
        },
        counterparties: AgreementStatementCounterparties {
            payer: record.agreement.payer.clone(),
            payee: record.agreement.payee.clone(),
            parties_summary,
        },
        commercial: AgreementStatementCommercialSummary {
            total_amount: record.agreement.total_amount,
            milestone_summary,
            settlement_deadline: record.agreement.settlement_deadline,
            refund_deadline: record.agreement.refund_deadline,
            release_path_summary,
            refund_path_summary,
        },
        observed: AgreementStatementObservedSummary {
            funding_observed,
            release_observed,
            refund_observed,
            ambiguity_warning: record.funding_legs.ambiguity_warning.clone(),
            linked_txids: linked_txids.clone(),
        },
        derived: AgreementStatementDerivedSummary {
            derived_state_label: record.settlement_state.derived_state_label.clone(),
            funded_amount: record.settlement_state.funded_amount,
            released_amount: record.settlement_state.released_amount,
            refunded_amount: record.settlement_state.refunded_amount,
            note: record.settlement_state.summary_note.clone(),
        },
        authenticity: build_agreement_statement_authenticity(record.authenticity.as_ref()),
        trust_notice: AgreementStatementTrustNotice {
            consensus_visible: record.trust_boundaries.consensus_enforced.clone(),
            htlc_enforced: record.trust_boundaries.htlc_enforced.clone(),
            derived_indexed: record.trust_boundaries.metadata_indexed.clone(),
            local_off_chain: record
                .trust_boundaries
                .local_bundle_only
                .iter()
                .cloned()
                .chain(record.trust_boundaries.off_chain_required.iter().cloned())
                .collect(),
            canonical_notice: "Canonical agreement JSON remains the source of truth for agreement terms. This statement is a shorter derived report artifact.".to_string(),
        },
        references: AgreementStatementReferences {
            linked_txids,
            selected_funding_txid: record
                .funding_legs
                .selected_leg
                .as_ref()
                .map(|leg| leg.funding_txid.clone()),
            canonical_agreement_notice: "Canonical agreement JSON remains required for full agreement context; chain data alone cannot recover the full agreement object.".to_string(),
        },
    }
}

fn same_linked_transactions(a: &[AgreementLinkedTx], b: &[AgreementLinkedTx]) -> bool {
    a == b
}

fn same_audit_funding_view(
    a: &AgreementAuditFundingLegSummary,
    b: &AgreementAuditFundingLegSummary,
) -> bool {
    a.candidate_count == b.candidate_count
        && a.selection_required == b.selection_required
        && a.selected_leg == b.selected_leg
        && a.candidates == b.candidates
}

fn same_timeline_view(
    a: &AgreementAuditTimelineSummary,
    b: &AgreementAuditTimelineSummary,
) -> bool {
    a.reconstructed == b.reconstructed && a.events == b.events
}

pub fn build_agreement_artifact_verification(
    agreement: Option<&AgreementObject>,
    bundle: Option<&AgreementBundle>,
    supplied_audit: Option<&AgreementAuditRecord>,
    supplied_statement: Option<&AgreementStatement>,
    detached_agreement_signatures: &[AgreementSignatureEnvelope],
    detached_bundle_signatures: &[AgreementSignatureEnvelope],
    recomputed_audit: Option<&AgreementAuditRecord>,
    generated_at: u64,
) -> AgreementArtifactVerificationResult {
    let canonical = agreement.or_else(|| bundle.map(|b| &b.agreement));
    let computed_hash = canonical.and_then(|agreement| compute_agreement_hash_hex(agreement).ok());
    let computed_id = canonical.map(|agreement| agreement.agreement_id.clone());

    let mut supplied_types = Vec::new();
    let mut claimed_ids = Vec::new();
    let mut claimed_hashes = Vec::new();
    if agreement.is_some() {
        supplied_types.push("agreement".to_string());
    }
    if let Some(bundle) = bundle {
        supplied_types.push("bundle".to_string());
        claimed_ids.push(bundle.agreement_id.clone());
        claimed_hashes.push(bundle.agreement_hash.clone());
    }
    if let Some(audit) = supplied_audit {
        supplied_types.push("audit".to_string());
        claimed_ids.push(audit.agreement.agreement_id.clone());
        claimed_hashes.push(audit.agreement.agreement_hash.clone());
    }
    if let Some(statement) = supplied_statement {
        supplied_types.push("statement".to_string());
        claimed_ids.push(statement.identity.agreement_id.clone());
        claimed_hashes.push(statement.identity.agreement_hash.clone());
    }
    if !detached_agreement_signatures.is_empty() {
        supplied_types.push("agreement_signature".to_string());
    }
    if !detached_bundle_signatures.is_empty() {
        supplied_types.push("bundle_signature".to_string());
    }

    let mut canonical_matches = Vec::new();
    let mut canonical_mismatches = Vec::new();
    let mut canonical_warnings = Vec::new();

    let bundle_hash_match = match (bundle, computed_hash.as_ref()) {
        (Some(bundle), Some(hash)) => {
            let ok = bundle.agreement_hash.eq_ignore_ascii_case(hash)
                && bundle.agreement_id == bundle.agreement.agreement_id;
            if ok {
                canonical_matches.push("Bundle matches canonical agreement hash".to_string());
            } else {
                canonical_mismatches
                    .push("Bundle does not match canonical agreement hash or id".to_string());
            }
            Some(ok)
        }
        (Some(_), None) => {
            canonical_warnings.push(
                "Bundle was supplied, but no canonical agreement could be recomputed".to_string(),
            );
            None
        }
        _ => None,
    };

    let audit_identity_match = match (supplied_audit, computed_hash.as_ref(), computed_id.as_ref())
    {
        (Some(audit), Some(hash), Some(agreement_id)) => {
            let ok = audit.agreement.agreement_hash.eq_ignore_ascii_case(hash)
                && audit.agreement.agreement_id == *agreement_id;
            if ok {
                canonical_matches.push("Audit identity matches canonical agreement".to_string());
            } else {
                canonical_mismatches
                    .push("Audit identity does not match canonical agreement".to_string());
            }
            Some(ok)
        }
        (Some(_), _, _) => {
            canonical_warnings.push(
                "Audit was supplied without canonical agreement context; identity match is limited"
                    .to_string(),
            );
            None
        }
        _ => None,
    };

    let statement_identity_match = match (
        supplied_statement,
        computed_hash.as_ref(),
        computed_id.as_ref(),
    ) {
        (Some(statement), Some(hash), Some(agreement_id)) => {
            let ok = statement.identity.agreement_hash.eq_ignore_ascii_case(hash)
                && statement.identity.agreement_id == *agreement_id;
            if ok {
                canonical_matches
                    .push("Statement identity matches canonical agreement".to_string());
            } else {
                canonical_mismatches
                    .push("Statement identity does not match canonical agreement".to_string());
            }
            Some(ok)
        }
        (Some(_), _, _) => {
            canonical_warnings.push("Statement was supplied without canonical agreement context; identity match is limited".to_string());
            None
        }
        _ => None,
    };

    let mut consistency_warnings = Vec::new();
    if agreement.is_none() && bundle.is_none() {
        consistency_warnings.push(
            "No canonical agreement or bundle was supplied; full verification is not possible"
                .to_string(),
        );
    }

    let mut chain_warnings = Vec::new();
    let mut checked_txids = Vec::new();
    let linked_tx_references_found = recomputed_audit
        .map(|audit| !audit.chain_observed.linked_transactions.is_empty())
        .unwrap_or(false);
    let anchor_observations_found = recomputed_audit
        .map(|audit| audit.chain_observed.linked_transaction_count > 0)
        .unwrap_or(false);
    if let Some(audit) = recomputed_audit {
        checked_txids = audit
            .chain_observed
            .linked_transactions
            .iter()
            .map(|tx| tx.txid.clone())
            .collect();
    } else {
        chain_warnings.push(
            "No recomputed audit context was available; chain-observed checks are limited"
                .to_string(),
        );
    }

    let audit_chain_match = match (supplied_audit, recomputed_audit) {
        (Some(supplied), Some(recomputed)) => {
            let ok = same_linked_transactions(
                &supplied.chain_observed.linked_transactions,
                &recomputed.chain_observed.linked_transactions,
            );
            if !ok {
                chain_warnings.push("Supplied audit linked transaction set differs from current chain-observed view".to_string());
            }
            Some(ok)
        }
        _ => None,
    };

    let statement_chain_match = match (supplied_statement, recomputed_audit) {
        (Some(statement), Some(recomputed)) => {
            let expected = build_agreement_statement(recomputed);
            let ok = statement.references.linked_txids == expected.references.linked_txids;
            if !ok {
                chain_warnings.push("Supplied statement linked transaction references differ from current chain-observed view".to_string());
            }
            Some(ok)
        }
        _ => None,
    };

    let mut derived_warnings = Vec::new();
    let audit_derived_match = match (supplied_audit, recomputed_audit) {
        (Some(supplied), Some(recomputed)) => {
            let ok = same_audit_funding_view(&supplied.funding_legs, &recomputed.funding_legs)
                && same_timeline_view(&supplied.timeline, &recomputed.timeline)
                && supplied.settlement_state == recomputed.settlement_state;
            if !ok {
                derived_warnings.push("Supplied audit derived funding, timeline, or settlement summary differs from current recomputation".to_string());
            }
            Some(ok)
        }
        _ => None,
    };

    let statement_derived_match = match (supplied_statement, recomputed_audit) {
        (Some(statement), Some(recomputed)) => {
            let expected = build_agreement_statement(recomputed);
            let ok = statement.identity == expected.identity
                && statement.observed == expected.observed
                && statement.derived == expected.derived
                && statement.references == expected.references;
            if !ok {
                derived_warnings.push("Supplied statement observed or derived sections differ from current recomputation".to_string());
            }
            Some(ok)
        }
        _ => None,
    };

    let authenticity = build_agreement_artifact_authenticity_verification(
        canonical,
        bundle,
        detached_agreement_signatures,
        detached_bundle_signatures,
    );
    if let Some(authenticity) = authenticity.as_ref() {
        consistency_warnings.extend(authenticity.warnings.iter().cloned());
    }

    let trust_summary = if let Some(audit) = recomputed_audit {
        AgreementArtifactVerificationTrustSummary {
            consensus_visible: audit.trust_boundaries.consensus_enforced.clone(),
            htlc_enforced: audit.trust_boundaries.htlc_enforced.clone(),
            derived_indexed: audit.trust_boundaries.metadata_indexed.clone(),
            local_artifact_only: audit.trust_boundaries.local_bundle_only.clone(),
            unverifiable_from_chain_alone: vec![
                "Full agreement terms cannot be reconstructed from chain data alone".to_string(),
                "Derived lifecycle, timeline, and statement sections remain informational"
                    .to_string(),
            ],
        }
    } else {
        AgreementArtifactVerificationTrustSummary {
            consensus_visible: vec!["Only ordinary transaction validity and visible anchors are independently consensus-checkable".to_string()],
            htlc_enforced: vec!["Existing HTLCv1 release/refund branches remain objective when present".to_string()],
            derived_indexed: vec!["Audit, statement, funding-leg, and timeline views are derived software outputs".to_string()],
            local_artifact_only: vec!["Bundle metadata and shared artifact files are off-chain artifacts".to_string()],
            unverifiable_from_chain_alone: vec!["Full agreement terms cannot be reconstructed from chain data alone".to_string()],
        }
    };

    AgreementArtifactVerificationResult {
        metadata: AgreementArtifactVerificationMetadata {
            version: AGREEMENT_ARTIFACT_VERIFICATION_VERSION,
            generated_at,
            derived_notice: "Derived verification result built from supplied artifacts plus canonical hashing and observed chain data where available".to_string(),
        },
        input_summary: AgreementArtifactVerificationInputSummary {
            supplied_artifact_types: supplied_types,
            canonical_agreement_present: canonical.is_some(),
            extracted_from_bundle: agreement.is_none() && bundle.is_some(),
            claimed_agreement_id: claimed_ids,
            claimed_agreement_hash: claimed_hashes,
        },
        canonical_verification: AgreementArtifactCanonicalVerification {
            canonical_agreement_present: canonical.is_some(),
            computed_agreement_hash: computed_hash,
            computed_agreement_id: computed_id,
            bundle_hash_match,
            audit_identity_match,
            statement_identity_match,
            matches: canonical_matches,
            mismatches: canonical_mismatches,
            warnings: canonical_warnings,
        },
        artifact_consistency: AgreementArtifactConsistencyVerification {
            bundle_matches_canonical: bundle_hash_match,
            audit_matches_canonical: audit_identity_match,
            statement_matches_canonical: statement_identity_match,
            warnings: consistency_warnings,
        },
        chain_verification: AgreementArtifactChainVerification {
            linked_tx_references_found,
            anchor_observations_found,
            checked_txids,
            audit_chain_match,
            statement_chain_match,
            warnings: chain_warnings,
        },
        derived_verification: AgreementArtifactDerivedVerification {
            audit_derived_match,
            statement_derived_match,
            warnings: derived_warnings,
        },
        authenticity,
        trust_summary,
    }
}

pub fn build_agreement_share_package_verification(
    package: &AgreementSharePackage,
    recomputed_audit: Option<&AgreementAuditRecord>,
    generated_at: u64,
) -> Result<AgreementSharePackageVerificationResult, String> {
    let inspection = inspect_agreement_share_package(package)?;
    let artifact_verification = build_agreement_artifact_verification(
        package.agreement.as_ref(),
        package.bundle.as_ref(),
        package.audit.as_ref(),
        package.statement.as_ref(),
        &package.detached_agreement_signatures,
        &package.detached_bundle_signatures,
        recomputed_audit,
        generated_at,
    );
    let mut informational_notices = vec![
        "Share package contents are supplied handoff artifacts. Verification results remain derived from the package contents plus canonical hashing and observed chain data where available.".to_string(),
    ];
    if package.audit.is_some() {
        informational_notices.push(
            "Embedded audit content is informational and derived; it is not native consensus contract state.".to_string(),
        );
    }
    if package.statement.is_some() {
        informational_notices.push(
            "Embedded statement content is informational and derived; it is not native consensus contract state.".to_string(),
        );
    }
    if !inspection.omitted_artifact_types.is_empty() {
        informational_notices.push(
            "Omitted artifacts are absent from this handoff package only. Recipients should not treat omissions as proof that no additional off-chain artifacts or signatures exist elsewhere.".to_string(),
        );
    }
    Ok(AgreementSharePackageVerificationResult {
        metadata: AgreementSharePackageVerificationMetadata {
            version: AGREEMENT_SHARE_PACKAGE_VERIFICATION_VERSION,
            generated_at,
            derived_notice: "Derived share-package verification result built from supplied package contents plus canonical hashing and observed chain data where available".to_string(),
        },
        package: inspection,
        artifact_verification,
        informational_notices,
    })
}

pub fn build_agreement_audit_record(
    agreement: &AgreementObject,
    agreement_hash: &str,
    bundle: Option<&AgreementBundle>,
    lifecycle: &AgreementLifecycleView,
    linked_txs: &[AgreementLinkedTx],
    funding_legs: &[AgreementAuditFundingLegRecord],
    selected_leg: Option<&AgreementAuditFundingLegRecord>,
    events: &[AgreementActivityEvent],
    generated_at: u64,
    generator_surface: &str,
) -> AgreementAuditRecord {
    let selection_required = funding_legs.len() != 1;
    let ambiguity_warning = if selection_required && !funding_legs.is_empty() {
        Some(
            "multiple candidate funding legs remain; this derived report does not pick one silently"
                .to_string(),
        )
    } else {
        None
    };
    let derived_state_label = if selection_required && !funding_legs.is_empty() {
        "ambiguous".to_string()
    } else {
        agreement_lifecycle_state_label(lifecycle.state)
    };
    AgreementAuditRecord {
        metadata: AgreementAuditMetadata {
            version: AGREEMENT_AUDIT_RECORD_VERSION,
            generated_at,
            generator_surface: generator_surface.to_string(),
            trust_model_summary: "This Phase 1 audit record is a derived report built from the supplied canonical agreement object, optional local bundle metadata, observed linked transactions, HTLCv1 branch checks, and reconstructed timeline data. It is not native consensus contract state.".to_string(),
        },
        agreement: AgreementAuditAgreementSummary {
            agreement_id: agreement.agreement_id.clone(),
            agreement_hash: agreement_hash.to_string(),
            template_type: agreement.template_type,
            network_marker: agreement.network_marker.clone(),
            payer: agreement.payer.clone(),
            payee: agreement.payee.clone(),
            parties: agreement.parties.clone(),
            total_amount: agreement.total_amount,
            milestone_count: agreement.milestones.len(),
            milestones: agreement
                .milestones
                .iter()
                .map(|m| AgreementAuditMilestoneSummary {
                    milestone_id: m.milestone_id.clone(),
                    title: m.title.clone(),
                    amount: m.amount,
                    timeout_height: m.timeout_height,
                })
                .collect(),
            settlement_deadline: agreement.deadlines.settlement_deadline,
            refund_deadline: agreement.deadlines.refund_deadline,
            dispute_window: agreement.deadlines.dispute_window,
            document_hash: agreement.document_hash.clone(),
            metadata_hash: agreement.metadata_hash.clone(),
            invoice_reference: agreement.invoice_reference.clone(),
            external_reference: agreement.external_reference.clone(),
        },
        local_bundle: AgreementAuditBundleContext {
            bundle_used: bundle.is_some(),
            verification_ok: bundle.is_some(),
            saved_at: bundle.and_then(|b| (b.metadata.saved_at > 0).then_some(b.metadata.saved_at)),
            source_label: bundle.and_then(|b| b.metadata.source_label.clone()),
            note: bundle.and_then(|b| b.metadata.note.clone()),
            linked_funding_txids: bundle
                .map(|b| b.metadata.linked_funding_txids.clone())
                .unwrap_or_default(),
            milestone_hints: bundle
                .map(|b| b.metadata.milestone_hints.clone())
                .unwrap_or_default(),
            local_only_notice: "Bundle metadata is local/off-chain convenience only. It can assist wallet and explorer flows, but it does not create consensus-native agreement state and cannot override canonical agreement hashing.".to_string(),
        },
        chain_observed: AgreementAuditChainObservedContext {
            linked_transactions: linked_txs.to_vec(),
            linked_transaction_count: linked_txs.len(),
            anchor_observation_notice: "Linked transactions and anchor roles are chain-observed facts only when present. They still do not reconstruct the full agreement object without supplied canonical agreement JSON or a verified local bundle.".to_string(),
        },
        funding_legs: AgreementAuditFundingLegSummary {
            candidate_count: funding_legs.len(),
            selection_required,
            selected_leg: selected_leg.cloned(),
            ambiguity_warning,
            candidates: funding_legs.to_vec(),
            notice: "Funding legs are derived convenience candidates from agreement anchors, observed transactions, and optional bundle hints. They are not native agreement UTXO state.".to_string(),
        },
        timeline: AgreementAuditTimelineSummary {
            reconstructed: true,
            event_count: events.len(),
            events: events.to_vec(),
            notice: "Timeline events are reconstructed/indexed software output from supplied agreement data plus observed chain activity. They are useful for audit and review, but not consensus-native contract state.".to_string(),
        },
        settlement_state: AgreementAuditSettlementStateSummary {
            lifecycle_state: lifecycle.state,
            derived_state_label,
            selection_required,
            funded_amount: lifecycle.funded_amount,
            released_amount: lifecycle.released_amount,
            refunded_amount: lifecycle.refunded_amount,
            summary_note: "Settlement state here is a conservative derived summary based on linked transaction observation, milestone metadata, and HTLC context. It is not native consensus contract state.".to_string(),
        },
        authenticity: None,
        trust_boundaries: AgreementAuditTrustBoundaries {
            consensus_enforced: vec![
                "Standard transaction validity and OP_RETURN anchor visibility on chain".to_string(),
            ],
            htlc_enforced: vec![
                "Existing HTLCv1 preimage release and timeout refund branches when a discovered leg is actually HTLC-backed".to_string(),
            ],
            metadata_indexed: vec![
                "Agreement lifecycle reconstruction, milestone meaning, funding-leg discovery, and timeline events".to_string(),
                "Document and metadata hash references carried by the canonical agreement object".to_string(),
            ],
            local_bundle_only: vec![
                "Saved bundle labels, notes, linked funding tx hints, and milestone hints".to_string(),
            ],
            off_chain_required: vec![
                "Exchange of the canonical agreement object".to_string(),
                "Interpretation of milestone/business intent beyond objectively encoded HTLC conditions".to_string(),
                "Operator choice when multiple candidate funding legs remain ambiguous".to_string(),
            ],
        },
    }
}

pub fn derive_lifecycle(
    agreement: &AgreementObject,
    agreement_hash: &str,
    linked_txs: Vec<AgreementLinkedTx>,
    tip_height: u64,
) -> AgreementLifecycleView {
    let funded_amount: u64 = linked_txs
        .iter()
        .filter(|t| {
            matches!(
                t.role,
                AgreementAnchorRole::Funding
                    | AgreementAnchorRole::DepositLock
                    | AgreementAnchorRole::OtcSettlement
                    | AgreementAnchorRole::MerchantSettlement
            )
        })
        .map(|t| t.value)
        .sum();
    let released_amount: u64 = linked_txs
        .iter()
        .filter(|t| {
            matches!(
                t.role,
                AgreementAnchorRole::Release | AgreementAnchorRole::MilestoneRelease
            )
        })
        .map(|t| t.value)
        .sum();
    let refunded_amount: u64 = linked_txs
        .iter()
        .filter(|t| matches!(t.role, AgreementAnchorRole::Refund))
        .map(|t| t.value)
        .sum();
    let mut milestones = Vec::new();
    for milestone in &agreement.milestones {
        let funded = linked_txs.iter().any(|t| {
            t.role == AgreementAnchorRole::Funding
                && t.milestone_id.as_deref() == Some(milestone.milestone_id.as_str())
        });
        let released = linked_txs.iter().any(|t| {
            t.role == AgreementAnchorRole::MilestoneRelease
                && t.milestone_id.as_deref() == Some(milestone.milestone_id.as_str())
        });
        let refunded = linked_txs.iter().any(|t| {
            t.role == AgreementAnchorRole::Refund
                && t.milestone_id.as_deref() == Some(milestone.milestone_id.as_str())
        });
        milestones.push(AgreementMilestoneStatus {
            milestone_id: milestone.milestone_id.clone(),
            title: milestone.title.clone(),
            amount: milestone.amount,
            funded,
            released,
            refunded,
        });
    }
    let state = if agreement.disputed_metadata_only {
        AgreementLifecycleState::DisputedMetadataOnly
    } else if refunded_amount > 0
        || linked_txs
            .iter()
            .any(|t| t.role == AgreementAnchorRole::Refund)
    {
        AgreementLifecycleState::Refunded
    } else if released_amount >= agreement.total_amount && released_amount > 0 {
        AgreementLifecycleState::Released
    } else if released_amount > 0 {
        AgreementLifecycleState::PartiallyReleased
    } else if funded_amount > 0 {
        let refund_timeout = agreement
            .refund_conditions
            .iter()
            .map(|c| c.timeout_height)
            .min()
            .unwrap_or(u64::MAX);
        if tip_height >= refund_timeout {
            AgreementLifecycleState::Expired
        } else {
            AgreementLifecycleState::Funded
        }
    } else if agreement
        .deadlines
        .settlement_deadline
        .map(|d| tip_height >= d)
        .unwrap_or(false)
    {
        AgreementLifecycleState::Expired
    } else {
        AgreementLifecycleState::Proposed
    };
    AgreementLifecycleView {
        state,
        agreement_hash: agreement_hash.to_string(),
        funded_amount,
        released_amount,
        refunded_amount,
        milestones,
        linked_txs,
        trust_model_note: "Phase 1 lifecycle is derived from observable on-chain links plus agreement metadata. Release authorization and milestone completion remain off-chain coordination unless explicitly expressed by existing HTLC timeout/preimage primitives.".to_string(),
    }
}

// ============================================================
// Phase 2: Proof-Based Objective Automation — Foundation Types
// ============================================================

pub const AGREEMENT_SCHEMA_ID_V2: &str = "irium.phase2.canonical.v1";
pub const PROOF_POLICY_SCHEMA_ID: &str = "irium.phase2.proof_policy.v1";
pub const SETTLEMENT_PROOF_SCHEMA_ID: &str = "irium.phase2.settlement_proof.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofResolution {
    Release,
    Refund,
    MilestoneRelease,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoResponseTrigger {
    FundedAndNoRelease,
    DisputedAndNoResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoResponseRule {
    pub rule_id: String,
    pub deadline_height: u64,
    pub trigger: NoResponseTrigger,
    pub resolution: ProofResolution,
    pub milestone_id: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovedAttestor {
    pub attestor_id: String,
    pub pubkey_hex: String,
    pub display_name: Option<String>,
    pub domain: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofRequirement {
    pub requirement_id: String,
    pub proof_type: String,
    pub required_by: Option<u64>,
    pub required_attestor_ids: Vec<String>,
    pub resolution: ProofResolution,
    pub milestone_id: Option<String>,
    /// Minimum number of distinct approved attestors whose proofs must satisfy
    /// this requirement. Defaults to 1 when absent (single-attestor behaviour).
    #[serde(default)]
    pub threshold: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofPolicy {
    pub policy_id: String,
    pub schema_id: String,
    pub agreement_hash: String,
    pub required_proofs: Vec<ProofRequirement>,
    pub no_response_rules: Vec<NoResponseRule>,
    pub attestors: Vec<ApprovedAttestor>,
    pub notes: Option<String>,
    /// Block height at which this policy expires. None means the policy never expires.
    #[serde(default)]
    pub expires_at_height: Option<u64>,
    /// Declared milestones for tranche-based evaluation. When non-empty,
    /// requirements and rules are grouped by their `milestone_id` field
    /// and each milestone is evaluated independently.
    #[serde(default)]
    pub milestones: Vec<PolicyMilestone>,
    /// Top-level holdback applied in the non-milestone evaluation path.
    /// Ignored when `milestones` is non-empty (use `PolicyMilestone.holdback` instead).
    #[serde(default)]
    pub holdback: Option<PolicyHoldback>,
}

/// Normalized application-layer proof payload metadata.
/// Carried alongside the proof but excluded from `settlement_proof_payload_bytes` -
/// existing signatures remain valid. Policy evaluation continues to match on `proof_type`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TypedProofPayload {
    /// Normalized proof category. Must be non-empty.
    pub proof_kind: String,
    /// SHA-256 hex (64 lowercase chars) of the attached evidence object.
    /// When set alongside `evidence_hash` on the parent proof the two must agree.
    #[serde(default)]
    pub content_hash: Option<String>,
    /// Opaque external reference (tracking number, invoice ID, etc.).
    #[serde(default)]
    pub reference_id: Option<String>,
    /// Additional typed key-value attributes; must be a JSON object when present.
    #[serde(default)]
    pub attributes: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofSignatureEnvelope {
    pub signature_type: String,
    pub pubkey_hex: String,
    pub signature_hex: String,
    pub payload_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementProof {
    pub proof_id: String,
    pub schema_id: String,
    pub proof_type: String,
    pub agreement_hash: String,
    pub milestone_id: Option<String>,
    pub attested_by: String,
    pub attestation_time: u64,
    pub evidence_hash: Option<String>,
    pub evidence_summary: Option<String>,
    pub signature: ProofSignatureEnvelope,
    /// Height at which this proof becomes inactive for stored evaluation.
    /// When None the proof never expires. When tip_height >= expires_at_height
    /// the proof is skipped in evaluate_policy_rpc. Does not affect check_policy_rpc.
    #[serde(default)]
    pub expires_at_height: Option<u64>,
    /// Optional normalized proof payload metadata. Excluded from signature payload bytes;
    /// backward compatible - legacy proofs without this field deserialize fine.
    #[serde(default)]
    pub typed_payload: Option<TypedProofPayload>,
}

/// Attestor threshold evaluation result for a single requirement.
/// Only populated for requirements where `threshold` is explicitly set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequirementThresholdResult {
    pub requirement_id: String,
    /// Minimum distinct approved attestors required.
    pub threshold_required: u32,
    /// Number of distinct approved attestors whose verified proofs matched.
    pub approved_attestor_count: usize,
    /// IDs of the matched attestors (deduplicated, deterministic order).
    pub matched_attestor_ids: Vec<String>,
    /// Whether the threshold was met.
    pub threshold_satisfied: bool,
}

/// Holdback (retention) configuration attached to a policy or milestone.
/// `holdback_bps` basis points of the settlement amount are held until either
/// `release_requirement_id` is satisfied or `deadline_height` is reached.
/// At least one of the two release conditions must be supplied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyHoldback {
    /// Basis points to hold back (1–9999; 10000 bps = 100 %).
    pub holdback_bps: u32,
    /// ID of an existing `ProofRequirement` whose satisfaction releases the holdback.
    /// When `None` the holdback is released only by `deadline_height`.
    #[serde(default)]
    pub release_requirement_id: Option<String>,
    /// Block height at or after which the holdback is automatically released.
    /// When `None` the holdback is released only by `release_requirement_id`.
    #[serde(default)]
    pub deadline_height: Option<u64>,
}

/// Outcome of evaluating the holdback condition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldbackOutcome {
    /// Base condition not yet satisfied; holdback not yet active.
    Pending,
    /// Base satisfied but neither release requirement nor deadline has been met.
    Held,
    /// Holdback released (by proof or deadline).
    Released,
}

/// Result of evaluating a holdback condition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoldbackEvaluationResult {
    pub holdback_present: bool,
    pub holdback_released: bool,
    pub holdback_bps: u32,
    /// Basis points immediately releasable (10000 - holdback_bps when holdback held; 10000 when released).
    pub immediate_release_bps: u32,
    pub holdback_outcome: HoldbackOutcome,
    pub holdback_reason: String,
    /// Block height at which the holdback becomes releasable; None if released by proof condition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deadline_height: Option<u64>,
}

/// Declares a named milestone (tranche) within a policy.
/// `ProofRequirement` and `NoResponseRule` entries with a matching `milestone_id`
/// are grouped under this milestone and evaluated independently.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyMilestone {
    pub milestone_id: String,
    /// Human-readable label shown in evaluation output.
    pub label: Option<String>,
    /// Optional holdback declaration for this milestone.
    #[serde(default)]
    pub holdback: Option<PolicyHoldback>,
}

/// Outcome of evaluating a single milestone independently.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MilestoneEvaluationResult {
    pub milestone_id: String,
    pub label: Option<String>,
    /// Outcome for this milestone only.
    pub outcome: PolicyOutcome,
    pub release_eligible: bool,
    pub refund_eligible: bool,
    pub matched_proof_ids: Vec<String>,
    pub reason: String,
    /// Holdback result for this milestone; `None` when no holdback is configured.
    pub holdback: Option<HoldbackEvaluationResult>,
    /// Threshold results for requirements with explicit `threshold` set; empty otherwise.
    pub threshold_results: Vec<RequirementThresholdResult>,
}

/// Objective, deterministic outcome of a policy evaluation.
///
/// - `satisfied`   — all required proofs present and signature-verified.
/// - `timeout`     — a no-response deadline or refund required_by deadline elapsed
///                   before release was achieved; proofs absent or insufficient.
/// - `unsatisfied` — neither condition met; proofs missing, expired, or
///                   signature-invalid, and no deadline has elapsed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyOutcome {
    Satisfied,
    Timeout,
    Unsatisfied,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvaluationResult {
    /// Objective classification of this evaluation.
    pub outcome: PolicyOutcome,
    pub release_eligible: bool,
    pub refund_eligible: bool,
    pub reason: String,
    pub evaluated_rules: Vec<String>,
    /// Proof IDs that passed signature verification and matched the policy.
    pub matched_proof_ids: Vec<String>,
    /// Per-milestone results; empty when no milestones are declared.
    pub milestone_results: Vec<MilestoneEvaluationResult>,
    /// Number of milestones with outcome == Satisfied.
    pub completed_milestone_count: usize,
    /// Total declared milestones (len of policy.milestones).
    pub total_milestone_count: usize,
    /// Top-level holdback result; `None` when no holdback is configured or
    /// when the policy uses milestone-level holdbacks.
    pub holdback: Option<HoldbackEvaluationResult>,
    /// Threshold results for requirements with explicit `threshold` set; empty otherwise.
    pub threshold_results: Vec<RequirementThresholdResult>,
}

fn proof_policy_canonical_bytes(policy: &ProofPolicy) -> Result<Vec<u8>, String> {
    let value = serde_json::to_value(policy).map_err(|e| format!("proof policy to json: {e}"))?;
    let sorted = sort_json(value);
    serde_json::to_vec(&sorted).map_err(|e| format!("canonical serialize: {e}"))
}

pub fn compute_proof_policy_hash(policy: &ProofPolicy) -> Result<String, String> {
    let bytes = proof_policy_canonical_bytes(policy)?;
    let digest = Sha256::digest(&bytes);
    Ok(hex::encode(digest))
}

/// SIGNED FIELDS (included in signature payload - changing these breaks all existing signatures):
///   proof_id, schema_id, proof_type, agreement_hash, milestone_id, attested_by,
///   attestation_time, evidence_hash, evidence_summary
///
/// EXCLUDED FROM SIGNATURE (unsigned application-layer fields - safe to evolve):
///   expires_at_height  - lifecycle filter only, unsigned by design
///   typed_payload      - display/normalization metadata, unsigned by design
///
/// INVARIANT: do not add typed_payload or expires_at_height here.
/// Any new field added to this function becomes a breaking change for all prior signatures.
pub fn settlement_proof_payload_bytes(proof: &SettlementProof) -> Result<Vec<u8>, String> {
    let value = serde_json::json!({
        "proof_id": proof.proof_id,
        "schema_id": proof.schema_id,
        "proof_type": proof.proof_type,
        "agreement_hash": proof.agreement_hash,
        "milestone_id": proof.milestone_id,
        "attested_by": proof.attested_by,
        "attestation_time": proof.attestation_time,
        "evidence_hash": proof.evidence_hash,
        "evidence_summary": proof.evidence_summary,
    });
    let sorted = sort_json(value);
    serde_json::to_vec(&sorted).map_err(|e| format!("canonical serialize: {e}"))
}

fn compute_settlement_proof_payload_hash(proof: &SettlementProof) -> Result<[u8; 32], String> {
    let bytes = settlement_proof_payload_bytes(proof)?;
    let digest = Sha256::digest(&bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

/// Validates a typed proof payload object.
/// - proof_kind must be non-empty
/// - content_hash when present must be 64 lowercase hex chars
/// - content_hash must equal evidence_hash when both are set
/// - attributes when present must be a JSON object
pub fn validate_typed_proof_payload(
    payload: &TypedProofPayload,
    evidence_hash: Option<&str>,
) -> Result<(), String> {
    if payload.proof_kind.trim().is_empty() {
        return Err("typed_payload.proof_kind must not be empty".to_string());
    }
    if let Some(ref ch) = payload.content_hash {
        if ch.len() != 64
            || !ch
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
        {
            return Err(format!(
                "typed_payload.content_hash must be 64 lowercase hex chars, got: {ch}"
            ));
        }
        if let Some(eh) = evidence_hash {
            if ch.as_str() != eh {
                return Err(format!(
                    "typed_payload.content_hash {ch} does not match proof evidence_hash {eh}"
                ));
            }
        }
    }
    if let Some(ref attrs) = payload.attributes {
        if !attrs.is_object() {
            return Err("typed_payload.attributes must be a JSON object".to_string());
        }
    }
    Ok(())
}

// ─── GROUP D: Proof Schema Registry ────────────────────────────────────
// Each standard proof_type carries a list of required attribute keys that
// MUST be present in `typed_payload.attributes` (a JSON object). Proofs
// with an unknown `proof_type` (anything not in STANDARD_PROOF_SCHEMAS)
// pass through unchallenged so legacy clients and future proof types
// keep working — that's the forward-compatibility guarantee.
//
// v1 enforcement model:
//   - presence-only: each required field must be a key in attributes and
//     non-null. Type validation (numeric `amount`, positive `timestamp`,
//     hex-format `*_hash`, etc) is deliberately NOT enforced in v1.
//   - strict going forward: a proof with `proof_type = "payment_received"`
//     and no typed_payload (or typed_payload without the required keys)
//     is REJECTED at /rpc/submitproof. Pre-FIX-1 clients that haven't
//     been updated will surface the schema validation error and must
//     upgrade.
//
// Standard schemas registered in this commit (per GROUP D spec):
//   payment_received        : payment_method, payment_reference, amount, currency, timestamp
//   delivery_confirmed      : delivery_method, tracking_reference, delivery_address_hash, timestamp
//   work_completed          : deliverable_hash, completion_notes, timestamp
//   milestone_delivered     : milestone_id, deliverable_hash, completion_notes, timestamp
//   deposit_conditions_met  : condition_description, evidence_hash, timestamp
//
// Note: legacy proof_type strings (e.g. "delivery_confirmation",
// "otc_release", "delivery_confirmation") are NOT in this list. They
// pass through as unknown and continue working as today.

/// A single proof_type schema entry. Required fields must all appear as
/// keys in the proof's typed_payload.attributes JSON object.
#[derive(Debug, Clone, Copy)]
pub struct ProofSchema {
    pub proof_type: &'static str,
    pub required_fields: &'static [&'static str],
}

pub const STANDARD_PROOF_SCHEMAS: &[ProofSchema] = &[
    ProofSchema {
        proof_type: "payment_received",
        required_fields: &[
            "payment_method",
            "payment_reference",
            "amount",
            "currency",
            "timestamp",
        ],
    },
    ProofSchema {
        proof_type: "delivery_confirmed",
        required_fields: &[
            "delivery_method",
            "tracking_reference",
            "delivery_address_hash",
            "timestamp",
        ],
    },
    ProofSchema {
        proof_type: "work_completed",
        // milestone_id is optional per spec — omit from required_fields.
        required_fields: &["deliverable_hash", "completion_notes", "timestamp"],
    },
    ProofSchema {
        proof_type: "milestone_delivered",
        required_fields: &[
            "milestone_id",
            "deliverable_hash",
            "completion_notes",
            "timestamp",
        ],
    },
    ProofSchema {
        proof_type: "deposit_conditions_met",
        required_fields: &["condition_description", "evidence_hash", "timestamp"],
    },
];

/// Returns the schema for a known proof_type, or None if the proof_type
/// is unknown (and therefore not subject to schema validation).
pub fn lookup_proof_schema(proof_type: &str) -> Option<&'static ProofSchema> {
    STANDARD_PROOF_SCHEMAS
        .iter()
        .find(|s| s.proof_type == proof_type)
}

/// GROUP D: validate a proof against its registered schema. Returns
/// Ok(()) for any proof_type not in STANDARD_PROOF_SCHEMAS (forward
/// compatibility). For registered types, requires typed_payload to
/// exist, typed_payload.attributes to be a JSON object, and every
/// required field to be a present non-null key in that object.
pub fn validate_proof_against_schema(proof: &SettlementProof) -> Result<(), String> {
    let Some(schema) = lookup_proof_schema(&proof.proof_type) else {
        return Ok(());
    };
    let Some(tp) = proof.typed_payload.as_ref() else {
        return Err(format!(
            "proof_type '{}' requires typed_payload with attributes: [{}]",
            schema.proof_type,
            schema.required_fields.join(", ")
        ));
    };
    let attrs_val = tp.attributes.as_ref().ok_or_else(|| {
        format!(
            "proof_type '{}' requires typed_payload.attributes (got None); required: [{}]",
            schema.proof_type,
            schema.required_fields.join(", ")
        )
    })?;
    let obj = attrs_val.as_object().ok_or_else(|| {
        format!(
            "proof_type '{}': typed_payload.attributes must be a JSON object",
            schema.proof_type
        )
    })?;
    let mut missing: Vec<&str> = Vec::new();
    for field in schema.required_fields {
        match obj.get(*field) {
            None => missing.push(*field),
            Some(v) if v.is_null() => missing.push(*field),
            _ => {}
        }
    }
    if !missing.is_empty() {
        return Err(format!(
            "proof_type '{}' missing required field(s): [{}]",
            schema.proof_type,
            missing.join(", ")
        ));
    }
    Ok(())
}

pub fn verify_settlement_proof(
    proof: &SettlementProof,
    policy: &ProofPolicy,
) -> Result<(), String> {
    if proof.signature.signature_type != AGREEMENT_SIGNATURE_TYPE_SECP256K1 {
        return Err(format!(
            "unsupported signature type: {}",
            proof.signature.signature_type
        ));
    }
    let approved = policy
        .attestors
        .iter()
        .any(|a| a.attestor_id == proof.attested_by && a.pubkey_hex == proof.signature.pubkey_hex);
    if !approved {
        return Err(format!(
            "attestor '{}' is not approved in this policy",
            proof.attested_by
        ));
    }
    let digest = compute_settlement_proof_payload_hash(proof)?;
    let pubkey_bytes = hex::decode(&proof.signature.pubkey_hex)
        .map_err(|_| "pubkey_hex must be hex-encoded SEC1 bytes".to_string())?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&pubkey_bytes)
        .map_err(|_| "pubkey_hex must be a valid secp256k1 SEC1 public key".to_string())?;
    let sig_bytes = hex::decode(&proof.signature.signature_hex)
        .map_err(|_| "signature_hex must be 64-byte hex".to_string())?;
    let parsed = Signature::from_slice(&sig_bytes)
        .map_err(|_| "signature_hex must be valid compact secp256k1 bytes".to_string())?;
    verifying_key
        .verify_prehash(&digest, &parsed)
        .map_err(|_| "proof signature verification failed".to_string())
}

/// Evaluates a subset of requirements and rules against the pre-verified proof set.
/// Used internally for per-milestone evaluation.
/// `satisfied` lists proof_ids that passed signature verification in Step 1.
/// Returns (outcome, release_eligible, refund_eligible, reason, matched_proof_ids).
/// Returns true if `req` is satisfied by at least `threshold` distinct approved attestors.
/// When `threshold` is None the effective minimum is 1 (original single-attestor behaviour).
fn req_satisfied_threshold(
    req: &ProofRequirement,
    proofs: &[SettlementProof],
    satisfied: &[String],
) -> bool {
    let threshold = req.threshold.unwrap_or(1).max(1) as usize;
    if threshold == 1 {
        return proofs.iter().any(|p| {
            satisfied.contains(&p.proof_id)
                && p.proof_type == req.proof_type
                && req.required_attestor_ids.contains(&p.attested_by)
                && (p.milestone_id.is_none()
                    || req.milestone_id.is_none()
                    || req.milestone_id == p.milestone_id)
        });
    }
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for p in proofs {
        if satisfied.contains(&p.proof_id)
            && p.proof_type == req.proof_type
            && req.required_attestor_ids.contains(&p.attested_by)
            && (p.milestone_id.is_none()
                || req.milestone_id.is_none()
                || req.milestone_id == p.milestone_id)
        {
            seen.insert(p.attested_by.as_str());
            if seen.len() >= threshold {
                return true;
            }
        }
    }
    false
}

/// Builds a `RequirementThresholdResult` for `req` if `threshold` is explicitly set.
/// Returns `None` for requirements without a threshold (backward-compatible path).
fn build_threshold_result(
    req: &ProofRequirement,
    proofs: &[SettlementProof],
    satisfied: &[String],
) -> Option<RequirementThresholdResult> {
    let threshold = (req.threshold? as usize).max(1);
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut attestor_ids: Vec<String> = Vec::new();
    for p in proofs {
        if satisfied.contains(&p.proof_id)
            && p.proof_type == req.proof_type
            && req.required_attestor_ids.contains(&p.attested_by)
            && (p.milestone_id.is_none()
                || req.milestone_id.is_none()
                || req.milestone_id == p.milestone_id)
            && seen.insert(p.attested_by.as_str())
        {
            attestor_ids.push(p.attested_by.clone());
        }
    }
    let count = attestor_ids.len();
    Some(RequirementThresholdResult {
        requirement_id: req.requirement_id.clone(),
        threshold_required: threshold as u32,
        approved_attestor_count: count,
        matched_attestor_ids: attestor_ids,
        threshold_satisfied: count >= threshold,
    })
}

fn eval_milestone_subset(
    release_reqs: &[&ProofRequirement],
    refund_reqs: &[&ProofRequirement],
    no_response_rules: &[&NoResponseRule],
    proofs: &[SettlementProof],
    satisfied: &[String],
    tip_height: u64,
) -> (
    PolicyOutcome,
    bool,
    bool,
    String,
    Vec<String>,
    Vec<RequirementThresholdResult>,
) {
    // Proofs attested after the milestone's refund deadline cannot count toward
    // release eligibility — once the refund deadline passes the payer's claim is
    // vested and cannot be retroactively overridden by a late attestation.
    let ms_refund_cutoff: Option<u64> = no_response_rules
        .iter()
        .filter(|r| matches!(r.resolution, ProofResolution::Refund))
        .map(|r| r.deadline_height)
        .min();
    let timely: Vec<String> = match ms_refund_cutoff {
        None => satisfied.to_vec(),
        Some(cutoff) => satisfied
            .iter()
            .filter(|id| {
                proofs
                    .iter()
                    .any(|p| &p.proof_id == *id && p.attestation_time <= cutoff)
            })
            .cloned()
            .collect(),
    };
    let all_release_met = !release_reqs.is_empty()
        && release_reqs
            .iter()
            .all(|req| req_satisfied_threshold(req, proofs, &timely));
    if all_release_met {
        let matched: Vec<String> = proofs
            .iter()
            .filter(|p| {
                timely.contains(&p.proof_id)
                    && release_reqs.iter().any(|r| {
                        p.proof_type == r.proof_type
                            && r.required_attestor_ids.contains(&p.attested_by)
                    })
            })
            .map(|p| p.proof_id.clone())
            .collect();
        let thr: Vec<RequirementThresholdResult> = release_reqs
            .iter()
            .chain(refund_reqs.iter())
            .filter_map(|r| build_threshold_result(r, proofs, &timely))
            .collect();
        return (
            PolicyOutcome::Satisfied,
            true,
            false,
            "all release requirements satisfied by verified proofs".to_string(),
            matched,
            thr,
        );
    }

    for rule in no_response_rules {
        if tip_height >= rule.deadline_height {
            let trigger_label = match rule.trigger {
                NoResponseTrigger::FundedAndNoRelease => "funded_and_no_release",
                NoResponseTrigger::DisputedAndNoResponse => "disputed_and_no_response",
            };
            let label = format!(
                "no_response_rule '{}' deadline {} reached at tip {} trigger {}",
                rule.rule_id, rule.deadline_height, tip_height, trigger_label
            );
            let (release, refund) = match rule.resolution {
                ProofResolution::Release | ProofResolution::MilestoneRelease => (true, false),
                ProofResolution::Refund => (false, true),
            };
            let thr: Vec<RequirementThresholdResult> = release_reqs
                .iter()
                .chain(refund_reqs.iter())
                .filter_map(|r| build_threshold_result(r, proofs, satisfied))
                .collect();
            return (PolicyOutcome::Timeout, release, refund, label, vec![], thr);
        }
    }

    for req in refund_reqs {
        if let Some(deadline) = req.required_by {
            if !req_satisfied_threshold(req, proofs, satisfied) && tip_height >= deadline {
                let label = format!(
                    "requirement '{}' refund deadline {} reached at tip {} with no satisfying proof",
                    req.requirement_id, deadline, tip_height
                );
                let thr: Vec<RequirementThresholdResult> = release_reqs
                    .iter()
                    .chain(refund_reqs.iter())
                    .filter_map(|r| build_threshold_result(r, proofs, satisfied))
                    .collect();
                return (PolicyOutcome::Timeout, false, true, label, vec![], thr);
            }
        }
    }

    let thr: Vec<RequirementThresholdResult> = release_reqs
        .iter()
        .chain(refund_reqs.iter())
        .filter_map(|r| build_threshold_result(r, proofs, satisfied))
        .collect();
    (
        PolicyOutcome::Unsatisfied,
        false,
        false,
        "no release or refund condition was met".to_string(),
        vec![],
        thr,
    )
}

/// Evaluate a holdback condition given the base satisfaction state.
///
/// - If base is not satisfied: returns `Pending` (holdback not yet active).
/// - If `release_requirement_id` is provided and satisfied: returns `Released`.
/// - If `deadline_height` has been reached: returns `Released`.
/// - Otherwise: returns `Held` with the split bps.
fn evaluate_holdback(
    holdback: &PolicyHoldback,
    base_satisfied: bool,
    scope_reqs: &[&ProofRequirement],
    proofs: &[SettlementProof],
    satisfied: &[String],
    tip_height: u64,
) -> HoldbackEvaluationResult {
    if !base_satisfied {
        return HoldbackEvaluationResult {
            holdback_present: true,
            holdback_released: false,
            holdback_bps: holdback.holdback_bps,
            immediate_release_bps: 0,
            holdback_outcome: HoldbackOutcome::Pending,
            holdback_reason: "base condition not yet satisfied".to_string(),
            deadline_height: holdback.deadline_height,
        };
    }

    // Proof-condition release takes priority over deadline release.
    if let Some(ref req_id) = holdback.release_requirement_id {
        let req_met = scope_reqs.iter().any(|req| {
            req.requirement_id == *req_id && req_satisfied_threshold(req, proofs, satisfied)
        });
        if req_met {
            return HoldbackEvaluationResult {
                holdback_present: true,
                holdback_released: true,
                holdback_bps: holdback.holdback_bps,
                immediate_release_bps: 10000,
                holdback_outcome: HoldbackOutcome::Released,
                holdback_reason: format!("holdback released by requirement '{}'", req_id),
                deadline_height: holdback.deadline_height,
            };
        }
    }

    if let Some(deadline) = holdback.deadline_height {
        if tip_height >= deadline {
            return HoldbackEvaluationResult {
                holdback_present: true,
                holdback_released: true,
                holdback_bps: holdback.holdback_bps,
                immediate_release_bps: 10000,
                holdback_outcome: HoldbackOutcome::Released,
                holdback_reason: format!("holdback released by deadline at height {}", deadline),
                deadline_height: Some(deadline),
            };
        }
    }

    HoldbackEvaluationResult {
        holdback_present: true,
        holdback_released: false,
        holdback_bps: holdback.holdback_bps,
        immediate_release_bps: 10000u32.saturating_sub(holdback.holdback_bps),
        holdback_outcome: HoldbackOutcome::Held,
        holdback_reason: "base satisfied; holdback pending release condition".to_string(),
        deadline_height: holdback.deadline_height,
    }
}

pub fn evaluate_policy(
    agreement: &AgreementObject,
    policy: &ProofPolicy,
    proofs: &[SettlementProof],
    tip_height: u64,
) -> Result<PolicyEvaluationResult, String> {
    let agreement_hash = {
        let bytes = agreement_canonical_bytes(agreement)?;
        let digest = Sha256::digest(&bytes);
        hex::encode(digest)
    };
    if !policy.agreement_hash.eq_ignore_ascii_case(&agreement_hash) {
        return Err(format!(
            "policy agreement_hash '{}' does not match the supplied agreement '{}'",
            policy.agreement_hash, agreement_hash
        ));
    }

    let mut evaluated_rules: Vec<String> = Vec::new();

    // Step 1: evaluate all submitted proofs before any deadline/rule checks.
    let mut satisfied: Vec<String> = Vec::new();
    for proof in proofs {
        if !proof.agreement_hash.eq_ignore_ascii_case(&agreement_hash) {
            evaluated_rules.push(format!(
                "proof '{}' rejected: agreement_hash mismatch (proof={}, expected={})",
                proof.proof_id, proof.agreement_hash, agreement_hash
            ));
            continue;
        }
        match verify_settlement_proof(proof, policy) {
            Ok(()) => {
                evaluated_rules.push(format!("proof '{}' verified ok", proof.proof_id));
                satisfied.push(proof.proof_id.clone());
            }
            Err(e) => {
                evaluated_rules.push(format!("proof '{}' rejected: {}", proof.proof_id, e));
            }
        }
    }

    // ── Milestone-based evaluation ───────────────────────────────────────────
    // When the policy declares milestones, requirements and rules are grouped
    // by milestone_id and evaluated independently.  The overall outcome is the
    // aggregate of all milestone outcomes.
    if !policy.milestones.is_empty() {
        let mut milestone_results: Vec<MilestoneEvaluationResult> = Vec::new();

        for ms in &policy.milestones {
            let mid = ms.milestone_id.as_str();

            let ms_release_reqs: Vec<&ProofRequirement> = policy
                .required_proofs
                .iter()
                .filter(|r| {
                    r.milestone_id.as_deref() == Some(mid)
                        && matches!(
                            r.resolution,
                            ProofResolution::Release | ProofResolution::MilestoneRelease
                        )
                })
                .collect();

            let ms_refund_reqs: Vec<&ProofRequirement> = policy
                .required_proofs
                .iter()
                .filter(|r| {
                    r.milestone_id.as_deref() == Some(mid)
                        && matches!(r.resolution, ProofResolution::Refund)
                })
                .collect();

            let ms_rules: Vec<&NoResponseRule> = policy
                .no_response_rules
                .iter()
                .filter(|r| r.milestone_id.as_deref() == Some(mid))
                .collect();

            let (ms_outcome, ms_release, ms_refund, ms_reason, ms_matched, ms_thr) =
                eval_milestone_subset(
                    &ms_release_reqs,
                    &ms_refund_reqs,
                    &ms_rules,
                    proofs,
                    &satisfied,
                    tip_height,
                );

            evaluated_rules.push(format!("milestone '{}' outcome {:?}", mid, ms_outcome));

            let ms_holdback = ms.holdback.as_ref().map(|hb| {
                evaluate_holdback(
                    hb,
                    ms_outcome == PolicyOutcome::Satisfied,
                    &ms_release_reqs,
                    proofs,
                    &satisfied,
                    tip_height,
                )
            });

            milestone_results.push(MilestoneEvaluationResult {
                milestone_id: ms.milestone_id.clone(),
                label: ms.label.clone(),
                outcome: ms_outcome,
                release_eligible: ms_release,
                refund_eligible: ms_refund,
                matched_proof_ids: ms_matched,
                reason: ms_reason,
                holdback: ms_holdback,
                threshold_results: ms_thr,
            });
        }

        let completed = milestone_results
            .iter()
            .filter(|r| r.outcome == PolicyOutcome::Satisfied)
            .count();
        let total = milestone_results.len();
        // Collect all matched proof ids across milestones (deduplicated).
        let mut seen = std::collections::HashSet::new();
        let all_matched: Vec<String> = milestone_results
            .iter()
            .flat_map(|r| r.matched_proof_ids.iter().cloned())
            .filter(|id| seen.insert(id.clone()))
            .collect();

        let (agg_outcome, agg_release, agg_refund, agg_reason) = if total > 0 && completed == total
        {
            (
                PolicyOutcome::Satisfied,
                true,
                false,
                "all milestones satisfied".to_string(),
            )
        } else if let Some(to) = milestone_results
            .iter()
            .find(|r| r.outcome == PolicyOutcome::Timeout)
        {
            (
                PolicyOutcome::Timeout,
                to.release_eligible,
                to.refund_eligible,
                format!("milestone '{}' timed out: {}", to.milestone_id, to.reason),
            )
        } else {
            let unsat = total - completed;
            (
                PolicyOutcome::Unsatisfied,
                false,
                false,
                format!(
                    "{} of {} milestones satisfied; {} unsatisfied",
                    completed, total, unsat
                ),
            )
        };

        return Ok(PolicyEvaluationResult {
            outcome: agg_outcome,
            release_eligible: agg_release,
            refund_eligible: agg_refund,
            reason: agg_reason,
            evaluated_rules,
            matched_proof_ids: all_matched,
            milestone_results,
            completed_milestone_count: completed,
            total_milestone_count: total,
            holdback: None,
            threshold_results: vec![],
        });
    }

    // ── Non-milestone (backward-compatible) evaluation ───────────────────────
    let release_requirements: Vec<&ProofRequirement> = policy
        .required_proofs
        .iter()
        .filter(|r| {
            matches!(
                r.resolution,
                ProofResolution::Release | ProofResolution::MilestoneRelease
            )
        })
        .collect();

    let refund_requirements: Vec<&ProofRequirement> = policy
        .required_proofs
        .iter()
        .filter(|r| matches!(r.resolution, ProofResolution::Refund))
        .collect();

    // Step 2: if all release requirements are already satisfied by *timely* proofs,
    // return release. Proofs submitted after the refund deadline are excluded from
    // release eligibility — once the refund deadline passes the payer's claim is
    // vested and cannot be retroactively overridden by a late attestation.
    let refund_cutoff: Option<u64> = policy
        .no_response_rules
        .iter()
        .filter(|r| r.milestone_id.is_none() && matches!(r.resolution, ProofResolution::Refund))
        .map(|r| r.deadline_height)
        .min();
    let timely_satisfied: Vec<String> = match refund_cutoff {
        None => satisfied.clone(),
        Some(cutoff) => satisfied
            .iter()
            .filter(|id| {
                proofs
                    .iter()
                    .any(|p| &p.proof_id == *id && p.attestation_time <= cutoff)
            })
            .cloned()
            .collect(),
    };
    for id in &satisfied {
        if !timely_satisfied.contains(id) {
            evaluated_rules.push(format!(
                "proof '{}' excluded from release eligibility: attestation_time exceeds refund deadline {}",
                id,
                refund_cutoff.unwrap_or(0)
            ));
        }
    }
    let all_release_met = !release_requirements.is_empty()
        && release_requirements
            .iter()
            .all(|req| req_satisfied_threshold(req, proofs, &timely_satisfied));

    if all_release_met {
        let top_holdback = policy.holdback.as_ref().map(|hb| {
            evaluate_holdback(
                hb,
                true,
                &release_requirements,
                proofs,
                &timely_satisfied,
                tip_height,
            )
        });
        let top_thr: Vec<RequirementThresholdResult> = policy
            .required_proofs
            .iter()
            .filter_map(|r| build_threshold_result(r, proofs, &timely_satisfied))
            .collect();
        return Ok(PolicyEvaluationResult {
            outcome: PolicyOutcome::Satisfied,
            release_eligible: true,
            refund_eligible: false,
            reason: "all release requirements satisfied by verified proofs".to_string(),
            evaluated_rules,
            matched_proof_ids: timely_satisfied.clone(),
            milestone_results: vec![],
            completed_milestone_count: 0,
            total_milestone_count: 0,
            holdback: top_holdback,
            threshold_results: top_thr,
        });
    }

    // Step 3: check no-response rules.
    // Both FundedAndNoRelease and DisputedAndNoResponse fire only when release
    // has not been achieved. Since all_release_met is false here, all triggered
    // rules fire unconditionally.
    for rule in &policy.no_response_rules {
        if tip_height >= rule.deadline_height {
            let trigger_label = match rule.trigger {
                NoResponseTrigger::FundedAndNoRelease => "funded_and_no_release",
                NoResponseTrigger::DisputedAndNoResponse => "disputed_and_no_response",
            };
            let label = format!(
                "no_response_rule '{}' deadline {} reached at tip {} trigger {}",
                rule.rule_id, rule.deadline_height, tip_height, trigger_label
            );
            evaluated_rules.push(label.clone());
            let (release, refund) = match rule.resolution {
                ProofResolution::Release | ProofResolution::MilestoneRelease => (true, false),
                ProofResolution::Refund => (false, true),
            };
            let thr: Vec<RequirementThresholdResult> = policy
                .required_proofs
                .iter()
                .filter_map(|r| build_threshold_result(r, proofs, &satisfied))
                .collect();
            return Ok(PolicyEvaluationResult {
                outcome: PolicyOutcome::Timeout,
                release_eligible: release,
                refund_eligible: refund,
                reason: label,
                evaluated_rules,
                matched_proof_ids: satisfied.clone(),
                milestone_results: vec![],
                completed_milestone_count: 0,
                total_milestone_count: 0,
                holdback: None,
                threshold_results: thr,
            });
        }
    }

    // Step 4: check required_by deadlines on refund requirements.
    // If the deadline has passed with no satisfying proof, trigger refund.
    for req in refund_requirements {
        if let Some(deadline) = req.required_by {
            if tip_height >= deadline {
                if req_satisfied_threshold(req, proofs, &satisfied) {
                    evaluated_rules.push(format!(
                        "requirement '{}' refund deadline {} reached but satisfied",
                        req.requirement_id, deadline
                    ));
                } else {
                    let label = format!(
                        "requirement '{}' refund deadline {} reached at tip {} with no satisfying proof",
                        req.requirement_id, deadline, tip_height
                    );
                    evaluated_rules.push(label.clone());
                    let thr: Vec<RequirementThresholdResult> = policy
                        .required_proofs
                        .iter()
                        .filter_map(|r| build_threshold_result(r, proofs, &satisfied))
                        .collect();
                    return Ok(PolicyEvaluationResult {
                        outcome: PolicyOutcome::Timeout,
                        release_eligible: false,
                        refund_eligible: true,
                        reason: label,
                        evaluated_rules,
                        matched_proof_ids: satisfied.clone(),
                        milestone_results: vec![],
                        completed_milestone_count: 0,
                        total_milestone_count: 0,
                        holdback: None,
                        threshold_results: thr,
                    });
                }
            }
        }
    }

    // Step 5: record missed release deadlines for observability.
    // A late proof is still accepted; required_by on a release requirement
    // is not a hard acceptance cutoff.
    for req in release_requirements {
        if let Some(deadline) = req.required_by {
            if tip_height >= deadline && !req_satisfied_threshold(req, proofs, &satisfied) {
                evaluated_rules.push(format!(
                    "requirement '{}' release deadline {} missed at tip {}",
                    req.requirement_id, deadline, tip_height
                ));
            }
        }
    }

    let top_thr: Vec<RequirementThresholdResult> = policy
        .required_proofs
        .iter()
        .filter_map(|r| build_threshold_result(r, proofs, &satisfied))
        .collect();
    Ok(PolicyEvaluationResult {
        outcome: PolicyOutcome::Unsatisfied,
        release_eligible: false,
        refund_eligible: false,
        reason: "no release or refund condition was met".to_string(),
        evaluated_rules,
        matched_proof_ids: satisfied,
        milestone_results: vec![],
        completed_milestone_count: 0,
        total_milestone_count: 0,
        holdback: None,
        threshold_results: top_thr,
    })
}

// ---- Proof storage ----

#[derive(Debug)]
pub struct SubmitProofOutcome {
    pub proof_id: String,
    pub agreement_hash: String,
    pub accepted: bool,
    pub duplicate: bool,
    pub message: String,
}

pub fn verify_settlement_proof_signature_only(proof: &SettlementProof) -> Result<(), String> {
    if proof.signature.signature_type != AGREEMENT_SIGNATURE_TYPE_SECP256K1 {
        return Err(format!(
            "unsupported signature type: {}",
            proof.signature.signature_type
        ));
    }
    if proof.proof_id.trim().is_empty() {
        return Err("proof_id must not be empty".to_string());
    }
    if proof.agreement_hash.trim().is_empty() {
        return Err("agreement_hash must not be empty".to_string());
    }
    let digest = compute_settlement_proof_payload_hash(proof)?;
    let pubkey_bytes = hex::decode(&proof.signature.pubkey_hex)
        .map_err(|_| "pubkey_hex must be hex-encoded SEC1 bytes".to_string())?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&pubkey_bytes)
        .map_err(|_| "pubkey_hex must be a valid secp256k1 SEC1 public key".to_string())?;
    let sig_bytes = hex::decode(&proof.signature.signature_hex)
        .map_err(|_| "signature_hex must be 64-byte hex".to_string())?;
    let parsed = Signature::from_slice(&sig_bytes)
        .map_err(|_| "signature_hex must be valid compact secp256k1 bytes".to_string())?;
    verifying_key
        .verify_prehash(&digest, &parsed)
        .map_err(|_| "proof signature verification failed".to_string())
}

pub struct ProofStore {
    proofs: std::collections::HashMap<String, SettlementProof>,
    path: std::path::PathBuf,
}

impl ProofStore {
    pub fn new(path: std::path::PathBuf) -> Self {
        let mut store = Self {
            proofs: std::collections::HashMap::new(),
            path,
        };
        store.load_from_disk();
        store
    }

    fn load_from_disk(&mut self) {
        let data = match std::fs::read_to_string(&self.path) {
            Ok(d) => d,
            Err(_) => return,
        };
        let parsed: Vec<SettlementProof> = match serde_json::from_str(&data) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Failed to parse proof store {}: {e}", self.path.display());
                return;
            }
        };
        for proof in parsed {
            self.proofs.insert(proof.proof_id.clone(), proof);
        }
    }

    fn persist(&self) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let mut proofs: Vec<&SettlementProof> = self.proofs.values().collect();
        proofs.sort_by(|a, b| a.proof_id.cmp(&b.proof_id));
        let json = serde_json::to_string_pretty(&proofs).map_err(|e| e.to_string())?;
        std::fs::write(&self.path, json).map_err(|e| e.to_string())
    }

    pub fn submit(&mut self, proof: SettlementProof) -> Result<SubmitProofOutcome, String> {
        if proof.schema_id != SETTLEMENT_PROOF_SCHEMA_ID {
            return Err(format!(
                "proof schema_id must be {SETTLEMENT_PROOF_SCHEMA_ID}"
            ));
        }
        if let Some(ref tp) = proof.typed_payload {
            validate_typed_proof_payload(tp, proof.evidence_hash.as_deref())
                .map_err(|e| format!("typed_payload validation: {e}"))?;
        }
        // GROUP D: proof schema registry — proof_types with a registered
        // schema must carry typed_payload.attributes with all required keys.
        // Unknown proof_types pass through (forward compatibility).
        validate_proof_against_schema(&proof)
            .map_err(|e| format!("schema validation: {e}"))?;
        verify_settlement_proof_signature_only(&proof)?;
        let agreement_hash = proof.agreement_hash.clone();
        let proof_id = proof.proof_id.clone();
        if self.proofs.contains_key(&proof_id) {
            return Ok(SubmitProofOutcome {
                proof_id,
                agreement_hash,
                accepted: false,
                duplicate: true,
                message: "proof already stored".to_string(),
            });
        }
        self.proofs.insert(proof_id.clone(), proof);
        if let Err(e) = self.persist() {
            eprintln!("proof store persist error: {e}");
        }
        Ok(SubmitProofOutcome {
            proof_id,
            agreement_hash,
            accepted: true,
            duplicate: false,
            message: "proof accepted".to_string(),
        })
    }

    pub fn list_by_agreement(&self, agreement_hash: &str) -> Vec<&SettlementProof> {
        let lower = agreement_hash.to_lowercase();
        let mut proofs: Vec<&SettlementProof> = self
            .proofs
            .values()
            .filter(|p| p.agreement_hash.to_lowercase() == lower)
            .collect();
        proofs.sort_by(|a, b| {
            a.attestation_time
                .cmp(&b.attestation_time)
                .then_with(|| a.proof_id.cmp(&b.proof_id))
        });
        proofs
    }

    /// Return all proofs in the store, sorted by attestation_time ascending then proof_id
    /// ascending as a stable tie-breaker. This ordering is consistent with list_by_agreement.
    pub fn list_all(&self) -> Vec<&SettlementProof> {
        let mut proofs: Vec<&SettlementProof> = self.proofs.values().collect();
        proofs.sort_by(|a, b| {
            a.attestation_time
                .cmp(&b.attestation_time)
                .then_with(|| a.proof_id.cmp(&b.proof_id))
        });
        proofs
    }

    pub fn count(&self) -> usize {
        self.proofs.len()
    }

    /// Return the proof with the given proof_id, or None if not found.
    pub fn get_by_id(&self, proof_id: &str) -> Option<&SettlementProof> {
        self.proofs.get(proof_id)
    }
}

// ---- Policy storage ----

#[derive(Debug)]
pub struct StorePolicyOutcome {
    pub policy_id: String,
    pub agreement_hash: String,
    pub accepted: bool,
    pub updated: bool,
    pub message: String,
}

pub struct PolicyStore {
    policies: std::collections::HashMap<String, ProofPolicy>,
    path: std::path::PathBuf,
}

impl PolicyStore {
    pub fn new(path: std::path::PathBuf) -> Self {
        let mut store = Self {
            policies: std::collections::HashMap::new(),
            path,
        };
        store.load_from_disk();
        store
    }

    fn load_from_disk(&mut self) {
        let data = match std::fs::read_to_string(&self.path) {
            Ok(d) => d,
            Err(_) => return,
        };
        let parsed: Vec<ProofPolicy> = match serde_json::from_str(&data) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Failed to parse policy store {}: {e}", self.path.display());
                return;
            }
        };
        for policy in parsed {
            self.policies
                .insert(policy.agreement_hash.to_lowercase(), policy);
        }
    }

    fn persist(&self) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let mut policies: Vec<&ProofPolicy> = self.policies.values().collect();
        policies.sort_by(|a, b| a.policy_id.cmp(&b.policy_id));
        let json = serde_json::to_string_pretty(&policies).map_err(|e| e.to_string())?;
        std::fs::write(&self.path, json).map_err(|e| e.to_string())
    }

    pub fn store(
        &mut self,
        policy: ProofPolicy,
        replace: bool,
    ) -> Result<StorePolicyOutcome, String> {
        if policy.agreement_hash.trim().is_empty() {
            return Err("policy.agreement_hash must not be empty".to_string());
        }
        // Validate milestone declarations: no empty or duplicate milestone_ids.
        let mut seen_ms_ids = std::collections::HashSet::new();
        for ms in &policy.milestones {
            if ms.milestone_id.trim().is_empty() {
                return Err("milestone_id must not be empty".to_string());
            }
            if !seen_ms_ids.insert(ms.milestone_id.as_str()) {
                return Err(format!("duplicate milestone_id '{}'", ms.milestone_id));
            }
        }
        // Validate top-level holdback (non-milestone path).
        if let Some(ref hb) = policy.holdback {
            if hb.holdback_bps == 0 || hb.holdback_bps >= 10000 {
                return Err("holdback_bps must be between 1 and 9999".to_string());
            }
            if hb.release_requirement_id.is_none() && hb.deadline_height.is_none() {
                return Err(
                    "holdback must specify at least one release condition (release_requirement_id or deadline_height)"
                        .to_string(),
                );
            }
            if let Some(ref req_id) = hb.release_requirement_id {
                if !policy
                    .required_proofs
                    .iter()
                    .any(|r| r.requirement_id == *req_id)
                {
                    return Err(format!(
                        "holdback release_requirement_id '{}' not found in policy requirements",
                        req_id
                    ));
                }
            }
        }
        // Validate per-milestone holdbacks.
        for ms in &policy.milestones {
            if let Some(ref hb) = ms.holdback {
                if hb.holdback_bps == 0 || hb.holdback_bps >= 10000 {
                    return Err(format!(
                        "milestone '{}' holdback_bps must be between 1 and 9999",
                        ms.milestone_id
                    ));
                }
                if hb.release_requirement_id.is_none() && hb.deadline_height.is_none() {
                    return Err(format!(
                        "milestone '{}' holdback must specify at least one release condition",
                        ms.milestone_id
                    ));
                }
                if let Some(ref req_id) = hb.release_requirement_id {
                    let in_scope = policy.required_proofs.iter().any(|r| {
                        r.requirement_id == *req_id
                            && r.milestone_id.as_deref() == Some(ms.milestone_id.as_str())
                    });
                    if !in_scope {
                        return Err(format!(
                            "milestone '{}' holdback release_requirement_id '{}' not found in milestone requirements",
                            ms.milestone_id, req_id
                        ));
                    }
                }
            }
        }
        // Validate threshold declarations on requirements.
        for req in &policy.required_proofs {
            if let Some(thr) = req.threshold {
                if thr == 0 {
                    return Err(format!(
                        "requirement '{}' threshold must be >= 1",
                        req.requirement_id
                    ));
                }
                if req.required_attestor_ids.is_empty() {
                    return Err(format!(
                        "requirement '{}' has threshold but no required_attestor_ids",
                        req.requirement_id
                    ));
                }
                if thr as usize > req.required_attestor_ids.len() {
                    return Err(format!(
                        "requirement '{}' threshold {} exceeds required_attestor_ids count {}",
                        req.requirement_id,
                        thr,
                        req.required_attestor_ids.len()
                    ));
                }
            }
        }
        // Validate threshold declarations on requirements.
        for req in &policy.required_proofs {
            if let Some(thr) = req.threshold {
                if thr == 0 {
                    return Err(format!(
                        "requirement '{}' threshold must be >= 1",
                        req.requirement_id
                    ));
                }
                if req.required_attestor_ids.is_empty() {
                    return Err(format!(
                        "requirement '{}' has threshold but no required_attestor_ids",
                        req.requirement_id
                    ));
                }
                if thr as usize > req.required_attestor_ids.len() {
                    return Err(format!(
                        "requirement '{}' threshold {} exceeds required_attestor_ids count {}",
                        req.requirement_id,
                        thr,
                        req.required_attestor_ids.len()
                    ));
                }
            }
        }
        let key = policy.agreement_hash.to_lowercase();
        let policy_id = policy.policy_id.clone();
        let agreement_hash = policy.agreement_hash.clone();
        if let Some(existing) = self.policies.get(&key) {
            if existing.policy_id == policy_id {
                return Ok(StorePolicyOutcome {
                    policy_id,
                    agreement_hash,
                    accepted: false,
                    updated: false,
                    message: "policy already stored (same policy_id)".to_string(),
                });
            }
            if !replace {
                return Ok(StorePolicyOutcome {
                    policy_id,
                    agreement_hash,
                    accepted: false,
                    updated: false,
                    message: format!(
                        "a policy '{}' already exists for this agreement; use --replace to overwrite",
                        existing.policy_id
                    ),
                });
            }
        }
        let updated = self.policies.contains_key(&key);
        self.policies.insert(key, policy);
        if let Err(e) = self.persist() {
            eprintln!("policy store persist error: {e}");
        }
        Ok(StorePolicyOutcome {
            policy_id,
            agreement_hash,
            accepted: true,
            updated,
            message: if updated {
                "policy replaced".to_string()
            } else {
                "policy accepted".to_string()
            },
        })
    }

    pub fn get(&self, agreement_hash: &str) -> Option<&ProofPolicy> {
        self.policies.get(&agreement_hash.to_lowercase())
    }

    pub fn count(&self) -> usize {
        self.policies.len()
    }

    pub fn list_all(&self) -> Vec<&ProofPolicy> {
        let mut policies: Vec<&ProofPolicy> = self.policies.values().collect();
        policies.sort_by(|a, b| a.agreement_hash.cmp(&b.agreement_hash));
        policies
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::SigningKey;

    fn sample_signing_key() -> SigningKey {
        SigningKey::from_bytes((&[7u8; 32]).into()).expect("static signing key")
    }

    fn signed_test_envelope(
        target_type: AgreementSignatureTargetType,
        target_hash: String,
        signer_role: Option<&str>,
        timestamp: Option<u64>,
    ) -> AgreementSignatureEnvelope {
        let signing_key = sample_signing_key();
        let mut envelope = AgreementSignatureEnvelope {
            version: AGREEMENT_SIGNATURE_VERSION,
            target_type,
            target_hash,
            signer_public_key: hex::encode(
                signing_key
                    .verifying_key()
                    .to_encoded_point(true)
                    .as_bytes(),
            ),
            signer_address: Some("Qsigtest".to_string()),
            signature_type: AGREEMENT_SIGNATURE_TYPE_SECP256K1.to_string(),
            timestamp,
            signer_role: signer_role.map(|value| value.to_string()),
            signature: String::new(),
        };
        let digest = compute_agreement_signature_payload_hash(&envelope).expect("payload hash");
        let signature: Signature = signing_key.sign_prehash(&digest).expect("sign prehash");
        envelope.signature = hex::encode(signature.to_bytes());
        envelope
    }

    fn sample_agreement() -> AgreementObject {
        AgreementObject {
            schema_id: Some(AGREEMENT_SCHEMA_ID_V1.to_string()),
            agreement_id: "agr-001".to_string(),
            version: AGREEMENT_OBJECT_VERSION,
            template_type: AgreementTemplateType::SimpleReleaseRefund,
            parties: vec![
                AgreementParty {
                    party_id: "payer".to_string(),
                    display_name: "Payer".to_string(),
                    address: "Qpayer".to_string(),
                    role: Some("payer".to_string()),
                },
                AgreementParty {
                    party_id: "payee".to_string(),
                    display_name: "Payee".to_string(),
                    address: "Qpayee".to_string(),
                    role: Some("payee".to_string()),
                },
            ],
            payer: "payer".to_string(),
            payee: "payee".to_string(),
            mediator_reference: Some("meta-only".to_string()),
            total_amount: 50_000_000,
            network_marker: AGREEMENT_NETWORK_MARKER.to_string(),
            creation_time: 1_700_000_000,
            deadlines: AgreementDeadlines {
                settlement_deadline: Some(100),
                refund_deadline: Some(120),
                dispute_window: Some(10),
            },
            release_conditions: vec![AgreementReleaseCondition {
                mode: "secret_preimage".to_string(),
                secret_hash_hex: Some("11".repeat(32)),
                release_authorizer: Some("payer".to_string()),
                notes: None,
            }],
            refund_conditions: vec![AgreementRefundCondition {
                refund_address: "Qpayer".to_string(),
                timeout_height: 120,
                notes: None,
            }],
            milestones: vec![],
            deposit_rule: None,
            proof_policy_reference: Some("phase2-placeholder".to_string()),
            asset_reference: None,
            payment_reference: None,
            purpose_reference: None,
            release_summary: Some("Release follows the agreed HTLC path".to_string()),
            refund_summary: Some("Refund follows the agreed timeout path".to_string()),
            attestor_reference: None,
            resolver_reference: None,
            notes: Some("fixture".to_string()),
            document_hash: "22".repeat(32),
            metadata_hash: Some("33".repeat(32)),
            invoice_reference: Some("INV-1".to_string()),
            external_reference: Some("PO-9".to_string()),
            disputed_metadata_only: false,
            primary_resolver: None,
            fallback_resolver: None,
            primary_resolver_fee: None,
            fallback_resolver_fee: None,
        }
    }

    #[test]
    fn canonical_serialization_rules_reference_phase15_schema() {
        let rules = canonical_serialization_rules();
        assert!(rules.iter().any(|rule| rule.contains("schema_id")));
        assert!(rules
            .iter()
            .any(|rule| rule.contains("lexicographically sorted object keys")));
    }

    #[test]
    fn phase15_template_builders_set_schema_and_hash_deterministically() {
        let payer = AgreementParty {
            party_id: "payer".to_string(),
            display_name: "Payer".to_string(),
            address: "Qpayer".to_string(),
            role: Some("payer".to_string()),
        };
        let payee = AgreementParty {
            party_id: "payee".to_string(),
            display_name: "Payee".to_string(),
            address: "Qpayee".to_string(),
            role: Some("payee".to_string()),
        };
        let first = build_simple_settlement_agreement(
            "agr-template-1".to_string(),
            1_700_000_000,
            payer.clone(),
            payee.clone(),
            50_000_000,
            Some(100),
            120,
            "11".repeat(32),
            "22".repeat(32),
            None,
            Some("Release by HTLC branch".to_string()),
            Some("Refund after timeout".to_string()),
            Some("notes".to_string()),
        )
        .unwrap();
        let second = build_simple_settlement_agreement(
            "agr-template-1".to_string(),
            1_700_000_000,
            payer,
            payee,
            50_000_000,
            Some(100),
            120,
            "11".repeat(32),
            "22".repeat(32),
            None,
            Some("Release by HTLC branch".to_string()),
            Some("Refund after timeout".to_string()),
            Some("notes".to_string()),
        )
        .unwrap();
        assert_eq!(first.schema_id.as_deref(), Some(AGREEMENT_SCHEMA_ID_V1));
        assert_eq!(
            compute_agreement_hash_hex(&first).unwrap(),
            compute_agreement_hash_hex(&second).unwrap()
        );
    }

    #[test]
    fn agreement_bundle_hash_is_deterministic_with_artifacts() {
        let agreement = sample_agreement();
        let bundle_a = build_agreement_bundle_with_artifacts(
            &agreement,
            1_710_000_000,
            Some("wallet".to_string()),
            Some("note".to_string()),
            vec!["aa".repeat(32)],
            vec![],
            AgreementBundleArtifacts {
                metadata_summary: Some("summary".to_string()),
                external_document_hashes: vec![agreement.document_hash.clone()],
                ..AgreementBundleArtifacts::default()
            },
        )
        .unwrap();
        let bundle_b = build_agreement_bundle_with_artifacts(
            &agreement,
            1_710_000_000,
            Some("wallet".to_string()),
            Some("note".to_string()),
            vec!["aa".repeat(32)],
            vec![],
            AgreementBundleArtifacts {
                metadata_summary: Some("summary".to_string()),
                external_document_hashes: vec![agreement.document_hash.clone()],
                ..AgreementBundleArtifacts::default()
            },
        )
        .unwrap();
        assert_eq!(
            compute_agreement_bundle_hash_hex(&bundle_a).unwrap(),
            compute_agreement_bundle_hash_hex(&bundle_b).unwrap()
        );
    }

    #[test]
    fn agreement_hash_is_deterministic() {
        let a = sample_agreement();
        let b = sample_agreement();
        assert_eq!(
            compute_agreement_hash_hex(&a).unwrap(),
            compute_agreement_hash_hex(&b).unwrap()
        );
    }

    #[test]
    fn agreement_anchor_roundtrip() {
        let anchor = AgreementAnchor {
            agreement_hash: "aa".repeat(32),
            role: AgreementAnchorRole::MilestoneRelease,
            milestone_id: Some("ms1".to_string()),
        };
        let out = build_agreement_anchor_output(&anchor).unwrap();
        let parsed = parse_agreement_anchor(&out.script_pubkey).unwrap();
        assert_eq!(parsed, anchor);
    }

    #[test]
    fn lifecycle_prefers_release_and_refund_events() {
        let agreement = sample_agreement();
        let hash = compute_agreement_hash_hex(&agreement).unwrap();
        let view = derive_lifecycle(
            &agreement,
            &hash,
            vec![AgreementLinkedTx {
                txid: "01".repeat(32),
                role: AgreementAnchorRole::Funding,
                milestone_id: None,
                height: Some(10),
                confirmed: true,
                value: agreement.total_amount,
            }],
            50,
        );
        assert_eq!(view.state, AgreementLifecycleState::Funded);
        let view2 = derive_lifecycle(
            &agreement,
            &hash,
            vec![AgreementLinkedTx {
                txid: "02".repeat(32),
                role: AgreementAnchorRole::Release,
                milestone_id: None,
                height: Some(11),
                confirmed: true,
                value: agreement.total_amount,
            }],
            50,
        );
        assert_eq!(view2.state, AgreementLifecycleState::Released);
        let view3 = derive_lifecycle(
            &agreement,
            &hash,
            vec![AgreementLinkedTx {
                txid: "03".repeat(32),
                role: AgreementAnchorRole::Refund,
                milestone_id: None,
                height: Some(12),
                confirmed: true,
                value: agreement.total_amount,
            }],
            130,
        );
        assert_eq!(view3.state, AgreementLifecycleState::Refunded);
        let view4 = derive_lifecycle(&agreement, &hash, vec![], 121);
        assert_eq!(view4.state, AgreementLifecycleState::Expired);
    }

    #[test]
    fn malformed_agreement_rejected() {
        let mut agreement = sample_agreement();
        agreement.document_hash = "zz".to_string();
        assert!(agreement.validate().is_err());
    }

    #[test]
    fn invalid_milestone_accounting_rejected() {
        let mut agreement = sample_agreement();
        agreement.template_type = AgreementTemplateType::MilestoneSettlement;
        agreement.milestones = vec![AgreementMilestone {
            milestone_id: "m1".to_string(),
            title: "Kickoff".to_string(),
            amount: 10,
            recipient_address: "Qpayee".to_string(),
            refund_address: "Qpayer".to_string(),
            secret_hash_hex: "11".repeat(32),
            timeout_height: 100,
            metadata_hash: None,
        }];
        assert!(agreement.validate().is_err());
    }

    #[test]
    fn invalid_deadline_ordering_rejected() {
        let mut agreement = sample_agreement();
        agreement.deadlines.settlement_deadline = Some(200);
        agreement.deadlines.refund_deadline = Some(100);
        assert!(agreement.validate().is_err());
    }

    #[test]
    fn funding_builder_output_sanity() {
        let agreement = sample_agreement();
        let legs = build_funding_legs(&agreement, [1u8; 20], [2u8; 20]).unwrap();
        assert_eq!(legs.len(), 1);
        assert_eq!(legs[0].amount, agreement.total_amount);
        assert!(!legs[0].output.script_pubkey.is_empty());
    }

    #[test]
    fn funding_leg_refs_follow_htlc_anchor_pairs() {
        let agreement = sample_agreement();
        let hash = compute_agreement_hash_hex(&agreement).unwrap();
        let legs = build_funding_legs(&agreement, [1u8; 20], [2u8; 20]).unwrap();
        let mut outputs = Vec::new();
        for leg in &legs {
            outputs.push(leg.output.clone());
            outputs.push(
                build_agreement_anchor_output(&AgreementAnchor {
                    agreement_hash: hash.clone(),
                    role: leg.role,
                    milestone_id: leg.milestone_id.clone(),
                })
                .unwrap(),
            );
        }
        let tx = Transaction {
            version: 1,
            inputs: vec![],
            outputs,
            locktime: 0,
        };
        let refs = extract_agreement_funding_leg_refs_from_tx(&tx, &hash);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].htlc_vout, 0);
        assert_eq!(refs[0].anchor_vout, 1);
        assert_eq!(refs[0].amount, agreement.total_amount);
    }

    #[test]
    fn agreement_bundle_roundtrip_and_verification() {
        let agreement = sample_agreement();
        let bundle = build_agreement_bundle(
            &agreement,
            1_710_000_000,
            Some("local-test".to_string()),
            Some("saved for reuse".to_string()),
            vec!["aa".repeat(32)],
            vec![],
        )
        .unwrap();
        verify_agreement_bundle(&bundle).unwrap();

        let raw = serde_json::to_vec_pretty(&bundle).unwrap();
        let parsed: AgreementBundle = serde_json::from_slice(&raw).unwrap();
        assert_eq!(parsed, bundle);
    }

    #[test]
    fn agreement_bundle_tamper_detection() {
        let agreement = sample_agreement();
        let mut bundle =
            build_agreement_bundle(&agreement, 1_710_000_000, None, None, vec![], vec![]).unwrap();
        bundle.metadata.linked_funding_txids.push("01".repeat(31));
        assert!(verify_agreement_bundle(&bundle).is_err());

        let mut bundle =
            build_agreement_bundle(&agreement, 1_710_000_000, None, None, vec![], vec![]).unwrap();
        bundle.agreement_hash = "ff".repeat(32);
        assert!(verify_agreement_bundle(&bundle).is_err());
    }

    #[test]
    fn discovered_funding_legs_respect_bundle_hints() {
        let agreement = sample_agreement();
        let hash = compute_agreement_hash_hex(&agreement).unwrap();
        let observed = vec![AgreementFundingLegRef {
            funding_txid: "aa".repeat(32),
            htlc_vout: 0,
            anchor_vout: 1,
            role: AgreementAnchorRole::Funding,
            milestone_id: None,
            amount: agreement.total_amount,
            timeout_height: 120,
            expected_hash: "11".repeat(32),
            recipient_address: "Qpayee".to_string(),
            refund_address: "Qpayer".to_string(),
        }];
        let linked = vec![AgreementLinkedTx {
            txid: "aa".repeat(32),
            role: AgreementAnchorRole::Funding,
            milestone_id: None,
            height: Some(10),
            confirmed: true,
            value: agreement.total_amount,
        }];
        let bundle = build_agreement_bundle(
            &agreement,
            1_710_000_000,
            Some("local-test".to_string()),
            None,
            vec!["aa".repeat(32)],
            vec![],
        )
        .unwrap();
        let candidates = discover_agreement_funding_leg_candidates(
            &hash,
            &linked,
            &observed,
            Some(&bundle.metadata),
        )
        .unwrap();
        assert_eq!(candidates.len(), 1);
        assert!(candidates[0]
            .source_notes
            .iter()
            .any(|note| note == "bundle_linked_funding_txid"));
    }

    #[test]
    fn agreement_activity_timeline_marks_local_and_derived_sources() {
        let agreement = sample_agreement();
        let hash = compute_agreement_hash_hex(&agreement).unwrap();
        let linked = vec![AgreementLinkedTx {
            txid: "aa".repeat(32),
            role: AgreementAnchorRole::Funding,
            milestone_id: None,
            height: Some(10),
            confirmed: true,
            value: agreement.total_amount,
        }];
        let lifecycle = derive_lifecycle(&agreement, &hash, linked.clone(), 10);
        let bundle =
            build_agreement_bundle(&agreement, 1_710_000_000, None, None, vec![], vec![]).unwrap();
        let legs = vec![AgreementFundingLegCandidate {
            agreement_hash: hash.clone(),
            funding_txid: "aa".repeat(32),
            htlc_vout: 0,
            anchor_vout: 1,
            role: AgreementAnchorRole::Funding,
            milestone_id: None,
            amount: agreement.total_amount,
            htlc_backed: true,
            timeout_height: 120,
            recipient_address: "Qpayee".to_string(),
            refund_address: "Qpayer".to_string(),
            source_notes: vec!["direct_anchor_match".to_string()],
        }];
        let timeline =
            build_agreement_activity_timeline(&hash, &lifecycle, &linked, &legs, Some(&bundle));
        assert!(timeline
            .iter()
            .any(|event| event.event_type == "agreement_saved_local"));
        assert!(timeline
            .iter()
            .any(|event| event.event_type == "funding_leg_discovered"));
        assert!(timeline
            .iter()
            .any(|event| event.event_type == "funding_tx_observed"));
    }

    #[test]
    fn agreement_audit_record_includes_bundle_chain_and_derived_sections() {
        let agreement = sample_agreement();
        let hash = compute_agreement_hash_hex(&agreement).unwrap();
        let linked = vec![AgreementLinkedTx {
            txid: "aa".repeat(32),
            role: AgreementAnchorRole::Funding,
            milestone_id: None,
            height: Some(10),
            confirmed: true,
            value: agreement.total_amount,
        }];
        let lifecycle = derive_lifecycle(&agreement, &hash, linked.clone(), 10);
        let bundle = build_agreement_bundle(
            &agreement,
            1_710_000_000,
            Some("test-bundle".to_string()),
            Some("saved locally".to_string()),
            vec!["aa".repeat(32)],
            vec![],
        )
        .unwrap();
        let legs = vec![AgreementAuditFundingLegRecord {
            funding_txid: "aa".repeat(32),
            htlc_vout: 0,
            anchor_vout: 1,
            role: AgreementAnchorRole::Funding,
            milestone_id: None,
            amount: agreement.total_amount,
            htlc_backed: true,
            timeout_height: 120,
            recipient_address: "Qpayee".to_string(),
            refund_address: "Qpayer".to_string(),
            source_notes: vec!["direct_anchor_match".to_string()],
            release_eligible: Some(false),
            release_reasons: vec!["secret_hex_required_for_release".to_string()],
            refund_eligible: Some(false),
            refund_reasons: vec!["refund_timeout_not_reached".to_string()],
        }];
        let discovery_legs = vec![AgreementFundingLegCandidate {
            agreement_hash: hash.clone(),
            funding_txid: "aa".repeat(32),
            htlc_vout: 0,
            anchor_vout: 1,
            role: AgreementAnchorRole::Funding,
            milestone_id: None,
            amount: agreement.total_amount,
            htlc_backed: true,
            timeout_height: 120,
            recipient_address: "Qpayee".to_string(),
            refund_address: "Qpayer".to_string(),
            source_notes: vec!["direct_anchor_match".to_string()],
        }];
        let timeline = build_agreement_activity_timeline(
            &hash,
            &lifecycle,
            &linked,
            &discovery_legs,
            Some(&bundle),
        );
        let record = build_agreement_audit_record(
            &agreement,
            &hash,
            Some(&bundle),
            &lifecycle,
            &linked,
            &legs,
            Some(&legs[0]),
            &timeline,
            1_710_000_123,
            "settlement_test",
        );
        assert_eq!(record.metadata.version, AGREEMENT_AUDIT_RECORD_VERSION);
        assert!(record.local_bundle.bundle_used);
        assert_eq!(record.chain_observed.linked_transaction_count, 1);
        assert_eq!(record.funding_legs.candidate_count, 1);
        assert_eq!(record.settlement_state.derived_state_label, "funded");
        assert!(record.timeline.reconstructed);
    }

    #[test]
    fn agreement_audit_record_marks_ambiguous_selection_requirements() {
        let agreement = sample_agreement();
        let hash = compute_agreement_hash_hex(&agreement).unwrap();
        let lifecycle = derive_lifecycle(&agreement, &hash, vec![], 0);
        let legs = vec![
            AgreementAuditFundingLegRecord {
                funding_txid: "aa".repeat(32),
                htlc_vout: 0,
                anchor_vout: 1,
                role: AgreementAnchorRole::Funding,
                milestone_id: Some("m1".to_string()),
                amount: 1,
                htlc_backed: true,
                timeout_height: 100,
                recipient_address: "Qpayee".to_string(),
                refund_address: "Qpayer".to_string(),
                source_notes: vec!["direct_anchor_match".to_string()],
                release_eligible: Some(false),
                release_reasons: vec![],
                refund_eligible: Some(false),
                refund_reasons: vec![],
            },
            AgreementAuditFundingLegRecord {
                funding_txid: "bb".repeat(32),
                htlc_vout: 0,
                anchor_vout: 1,
                role: AgreementAnchorRole::Funding,
                milestone_id: Some("m2".to_string()),
                amount: 1,
                htlc_backed: true,
                timeout_height: 100,
                recipient_address: "Qpayee".to_string(),
                refund_address: "Qpayer".to_string(),
                source_notes: vec!["direct_anchor_match".to_string()],
                release_eligible: Some(false),
                release_reasons: vec![],
                refund_eligible: Some(false),
                refund_reasons: vec![],
            },
        ];
        let record = build_agreement_audit_record(
            &agreement,
            &hash,
            None,
            &lifecycle,
            &[],
            &legs,
            None,
            &[],
            1_710_000_123,
            "settlement_test",
        );
        assert!(record.funding_legs.selection_required);
        assert_eq!(record.settlement_state.derived_state_label, "ambiguous");
        assert!(record.funding_legs.ambiguity_warning.is_some());
    }
    #[test]
    fn agreement_statement_generation_is_stable() {
        let agreement = sample_agreement();
        let agreement_hash = compute_agreement_hash_hex(&agreement).unwrap();
        let lifecycle = derive_lifecycle(&agreement, &agreement_hash, vec![], 10);
        let record = build_agreement_audit_record(
            &agreement,
            &agreement_hash,
            None,
            &lifecycle,
            &[],
            &[],
            None,
            &[],
            1_710_000_123,
            "test",
        );
        let statement = build_agreement_statement(&record);
        assert_eq!(statement.metadata.version, AGREEMENT_STATEMENT_VERSION);
        assert_eq!(statement.identity.agreement_id, agreement.agreement_id);
        assert!(statement
            .metadata
            .derived_notice
            .contains("not native consensus contract state"));
        assert!(statement
            .trust_notice
            .canonical_notice
            .contains("source of truth"));
    }

    #[test]
    fn agreement_artifact_verification_detects_bundle_tamper() {
        let agreement = sample_agreement();
        let bundle = build_agreement_bundle(&agreement, 1, None, None, vec![], vec![]).unwrap();
        let mut tampered_bundle = bundle.clone();
        tampered_bundle.agreement_hash = "00".repeat(32);
        let result = build_agreement_artifact_verification(
            Some(&agreement),
            Some(&tampered_bundle),
            None,
            None,
            &[],
            &[],
            None,
            1,
        );
        assert_eq!(result.canonical_verification.bundle_hash_match, Some(false));
        assert!(!result.canonical_verification.mismatches.is_empty());
    }

    #[test]
    fn agreement_artifact_verification_reports_statement_mismatch() {
        let agreement = sample_agreement();
        let hash = compute_agreement_hash_hex(&agreement).unwrap();
        let lifecycle = derive_lifecycle(&agreement, &hash, vec![], 10);
        let audit = build_agreement_audit_record(
            &agreement,
            &hash,
            None,
            &lifecycle,
            &[],
            &[],
            None,
            &[],
            1,
            "test",
        );
        let mut statement = build_agreement_statement(&audit);
        statement.identity.agreement_hash = "ff".repeat(32);
        let result = build_agreement_artifact_verification(
            Some(&agreement),
            None,
            Some(&audit),
            Some(&statement),
            &[],
            &[],
            Some(&audit),
            2,
        );
        assert_eq!(
            result.canonical_verification.statement_identity_match,
            Some(false)
        );
        assert_eq!(result.chain_verification.statement_chain_match, Some(true));
    }
    #[test]
    fn agreement_signature_payload_hash_and_verification_are_deterministic() {
        let agreement = sample_agreement();
        let agreement_hash = compute_agreement_hash_hex(&agreement).unwrap();
        let first = signed_test_envelope(
            AgreementSignatureTargetType::Agreement,
            agreement_hash.clone(),
            Some("payer"),
            Some(1_710_000_555),
        );
        let second = signed_test_envelope(
            AgreementSignatureTargetType::Agreement,
            agreement_hash,
            Some("payer"),
            Some(1_710_000_555),
        );
        assert_eq!(first.signature, second.signature);
        assert_eq!(
            compute_agreement_signature_payload_hash(&first).unwrap(),
            compute_agreement_signature_payload_hash(&second).unwrap()
        );
        let inspected = inspect_agreement_signature(
            &first,
            Some(&compute_agreement_hash_hex(&agreement).unwrap()),
            None,
        );
        assert!(inspected.valid);
        assert!(inspected.matches_expected_target);
        assert!(inspected.authenticity_note.contains("authenticity"));
    }

    #[test]
    fn agreement_signature_verification_detects_invalid_signature_and_target_mismatch() {
        let agreement = sample_agreement();
        let agreement_hash = compute_agreement_hash_hex(&agreement).unwrap();
        let mut envelope = signed_test_envelope(
            AgreementSignatureTargetType::Agreement,
            agreement_hash.clone(),
            Some("payee"),
            None,
        );
        envelope.signature.replace_range(0..2, "00");
        let inspected = inspect_agreement_signature(&envelope, Some(&agreement_hash), None);
        assert!(!inspected.valid);
        let mismatched = inspect_agreement_signature(&envelope, Some(&"ff".repeat(32)), None);
        assert!(!mismatched.matches_expected_target);
        assert!(mismatched
            .warnings
            .iter()
            .any(|warning| warning.contains("target hash")));
    }

    #[test]
    fn bundle_hash_excludes_embedded_signatures_and_multiple_signatures_verify() {
        let agreement = sample_agreement();
        let mut bundle = build_agreement_bundle(
            &agreement,
            1_710_000_000,
            Some("bundle-sig-test".to_string()),
            None,
            vec![],
            vec![],
        )
        .unwrap();
        let bundle_hash = compute_agreement_bundle_hash_hex(&bundle).unwrap();
        let agreement_sig = signed_test_envelope(
            AgreementSignatureTargetType::Agreement,
            bundle.agreement_hash.clone(),
            Some("payer"),
            Some(1_710_000_600),
        );
        let bundle_sig = signed_test_envelope(
            AgreementSignatureTargetType::Bundle,
            bundle_hash.clone(),
            Some("payee"),
            Some(1_710_000_601),
        );
        bundle.signatures.push(agreement_sig);
        bundle.signatures.push(bundle_sig);
        verify_agreement_bundle(&bundle).unwrap();
        assert_eq!(
            compute_agreement_bundle_hash_hex(&bundle).unwrap(),
            bundle_hash
        );
        let verifications = verify_bundle_signatures(&bundle);
        assert_eq!(verifications.len(), 2);
        assert!(verifications.iter().all(|item| item.valid));
        assert!(verifications
            .iter()
            .all(|item| item.matches_expected_target));
    }
    #[test]
    fn agreement_artifact_verification_includes_authenticity_for_matching_signature() {
        let agreement = sample_agreement();
        let agreement_hash = compute_agreement_hash_hex(&agreement).unwrap();
        let signature = signed_test_envelope(
            AgreementSignatureTargetType::Agreement,
            agreement_hash,
            Some("payer"),
            Some(1_710_000_900),
        );
        let detached_agreement_signatures = vec![signature];
        let result = build_agreement_artifact_verification(
            Some(&agreement),
            None,
            None,
            None,
            &detached_agreement_signatures,
            &[],
            None,
            3,
        );
        let authenticity = result.authenticity.expect("authenticity");
        assert_eq!(authenticity.valid_signatures, 1);
        assert_eq!(authenticity.invalid_signatures, 0);
        assert!(authenticity
            .authenticity_notice
            .contains("authenticity layer only"));
    }

    #[test]
    fn agreement_statement_includes_compact_authenticity_summary_when_present() {
        let agreement = sample_agreement();
        let agreement_hash = compute_agreement_hash_hex(&agreement).unwrap();
        let lifecycle = derive_lifecycle(&agreement, &agreement_hash, vec![], 10);
        let mut audit = build_agreement_audit_record(
            &agreement,
            &agreement_hash,
            None,
            &lifecycle,
            &[],
            &[],
            None,
            &[],
            4,
            "test",
        );
        audit.authenticity = Some(AgreementAuthenticitySummary {
            detached_agreement_signatures_supplied: 1,
            detached_bundle_signatures_supplied: 0,
            embedded_bundle_signatures_supplied: 0,
            valid_signatures: 1,
            invalid_signatures: 0,
            unverifiable_signatures: 0,
            signer_summaries: vec![
                "agreement Qpayer role payer target hash status valid".to_string()
            ],
            warnings: vec![],
            authenticity_notice: "Authenticity only; signatures do not enforce settlement"
                .to_string(),
        });
        let statement = build_agreement_statement(&audit);
        let authenticity = statement.authenticity.expect("statement authenticity");
        assert_eq!(authenticity.valid_signatures, 1);
        assert!(authenticity.compact_summary.contains("1 valid"));
        assert!(authenticity
            .authenticity_notice
            .contains("do not enforce settlement"));
    }
    #[test]
    fn agreement_share_package_roundtrip_and_verification_are_stable() {
        let agreement = sample_agreement();
        let agreement_hash = compute_agreement_hash_hex(&agreement).unwrap();
        let bundle = build_agreement_bundle(
            &agreement,
            1_710_001_000,
            Some("share-test".to_string()),
            Some("handoff".to_string()),
            vec![],
            vec![],
        )
        .unwrap();
        let lifecycle = derive_lifecycle(&agreement, &agreement_hash, vec![], 10);
        let audit = build_agreement_audit_record(
            &agreement,
            &agreement_hash,
            Some(&bundle),
            &lifecycle,
            &[],
            &[],
            None,
            &[],
            12,
            "test",
        );
        let statement = build_agreement_statement(&audit);
        let package = build_agreement_share_package(
            Some(1_710_001_001),
            Some("counterparty-a".to_string()),
            Some("handoff".to_string()),
            Some(agreement.clone()),
            Some(bundle.clone()),
            Some(audit.clone()),
            Some(statement),
            vec![],
            vec![],
        )
        .unwrap();
        let encoded = serde_json::to_string_pretty(&package).unwrap();
        let decoded: AgreementSharePackage = serde_json::from_str(&encoded).unwrap();
        verify_agreement_share_package(&decoded).unwrap();
        let inspection = inspect_agreement_share_package(&decoded).unwrap();
        assert_eq!(inspection.canonical_agreement_hash, Some(agreement_hash));
        assert!(inspection
            .included_artifact_types
            .contains(&"agreement".to_string()));
        assert!(inspection
            .included_artifact_types
            .contains(&"bundle".to_string()));
        let verification =
            build_agreement_share_package_verification(&decoded, Some(&audit), 13).unwrap();
        assert_eq!(
            verification
                .artifact_verification
                .canonical_verification
                .bundle_hash_match,
            Some(true)
        );
        assert_eq!(
            verification
                .artifact_verification
                .canonical_verification
                .statement_identity_match,
            Some(true)
        );
    }

    #[test]
    fn agreement_share_package_manifest_summary_is_stable() {
        let agreement = sample_agreement();
        let agreement_hash = compute_agreement_hash_hex(&agreement).unwrap();
        let lifecycle = derive_lifecycle(&agreement, &agreement_hash, vec![], 10);
        let audit = build_agreement_audit_record(
            &agreement,
            &agreement_hash,
            None,
            &lifecycle,
            &[],
            &[],
            None,
            &[],
            12,
            "test",
        );
        let package = build_agreement_share_package(
            Some(1_710_001_111),
            Some("counterparty-c".to_string()),
            Some("review handoff".to_string()),
            Some(agreement),
            None,
            None,
            Some(build_agreement_statement(&audit)),
            vec![],
            vec![],
        )
        .unwrap();
        let inspection = inspect_agreement_share_package(&package).unwrap();
        assert_eq!(inspection.package_profile, "review_package");
        assert!(inspection
            .included_artifact_types
            .contains(&"agreement".to_string()));
        assert!(inspection
            .omitted_artifact_types
            .contains(&"bundle".to_string()));
        assert!(inspection.verification_notice.contains("descriptive only"));
    }

    #[test]
    fn agreement_share_package_verification_detects_mismatches_and_invalid_signature() {
        let agreement = sample_agreement();
        let agreement_hash = compute_agreement_hash_hex(&agreement).unwrap();
        let lifecycle = derive_lifecycle(&agreement, &agreement_hash, vec![], 10);
        let audit = build_agreement_audit_record(
            &agreement,
            &agreement_hash,
            None,
            &lifecycle,
            &[],
            &[],
            None,
            &[],
            14,
            "test",
        );
        let mut statement = build_agreement_statement(&audit);
        statement.identity.agreement_hash = "ff".repeat(32);
        let mut signature = signed_test_envelope(
            AgreementSignatureTargetType::Agreement,
            agreement_hash,
            Some("payer"),
            Some(1_710_001_200),
        );
        signature.signature.replace_range(0..2, "00");
        let package = build_agreement_share_package(
            Some(1_710_001_201),
            Some("counterparty-b".to_string()),
            None,
            Some(agreement),
            None,
            Some(audit),
            Some(statement),
            vec![signature],
            vec![],
        )
        .unwrap();
        let verification = build_agreement_share_package_verification(&package, None, 15).unwrap();
        assert_eq!(
            verification
                .artifact_verification
                .canonical_verification
                .statement_identity_match,
            Some(false)
        );
        let authenticity = verification
            .artifact_verification
            .authenticity
            .expect("authenticity");
        assert_eq!(authenticity.invalid_signatures, 1);
        assert!(verification
            .informational_notices
            .iter()
            .any(|note| note.contains("informational")));
    }

    // ---- Phase 2 tests ----

    fn make_test_policy(agreement_hash: &str, pubkey_hex: &str, attestor_id: &str) -> ProofPolicy {
        ProofPolicy {
            policy_id: "pol-001".to_string(),
            schema_id: PROOF_POLICY_SCHEMA_ID.to_string(),
            agreement_hash: agreement_hash.to_string(),
            required_proofs: vec![ProofRequirement {
                requirement_id: "req-001".to_string(),
                proof_type: "delivery_confirmation".to_string(),
                required_by: None,
                required_attestor_ids: vec![attestor_id.to_string()],
                resolution: ProofResolution::Release,
                milestone_id: None,
                threshold: None,
            }],
            no_response_rules: vec![],
            attestors: vec![ApprovedAttestor {
                attestor_id: attestor_id.to_string(),
                pubkey_hex: pubkey_hex.to_string(),
                display_name: None,
                domain: None,
            }],
            notes: None,
            expires_at_height: None,
            milestones: vec![],
            holdback: None,
        }
    }

    fn make_test_policy_with_expiry(agreement_hash: &str, expires_at_height: u64) -> ProofPolicy {
        let mut p = make_test_policy(agreement_hash, "pk-expiry", "att-expiry");
        p.expires_at_height = Some(expires_at_height);
        p
    }

    fn sign_proof(proof: &SettlementProof, signing_key: &SigningKey) -> ProofSignatureEnvelope {
        let payload_bytes = settlement_proof_payload_bytes(proof).unwrap();
        let digest = Sha256::digest(&payload_bytes);
        let mut digest_arr = [0u8; 32];
        digest_arr.copy_from_slice(&digest);
        let sig: k256::ecdsa::Signature = signing_key.sign_prehash(&digest_arr).unwrap();
        let pubkey_hex = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        ProofSignatureEnvelope {
            signature_type: AGREEMENT_SIGNATURE_TYPE_SECP256K1.to_string(),
            pubkey_hex,
            signature_hex: hex::encode(sig.to_bytes()),
            payload_hash: hex::encode(digest),
        }
    }

    fn make_test_proof(
        agreement_hash: &str,
        attestor_id: &str,
        signing_key: &SigningKey,
    ) -> SettlementProof {
        let pubkey_hex = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let mut proof = SettlementProof {
            proof_id: "prf-001".to_string(),
            schema_id: SETTLEMENT_PROOF_SCHEMA_ID.to_string(),
            proof_type: "delivery_confirmation".to_string(),
            agreement_hash: agreement_hash.to_string(),
            milestone_id: None,
            attested_by: attestor_id.to_string(),
            attestation_time: 0,
            evidence_hash: None,
            evidence_summary: Some("goods delivered and received".to_string()),
            signature: ProofSignatureEnvelope {
                signature_type: AGREEMENT_SIGNATURE_TYPE_SECP256K1.to_string(),
                pubkey_hex: pubkey_hex.clone(),
                signature_hex: String::new(),
                payload_hash: String::new(),
            },
            expires_at_height: None,
            typed_payload: None,
        };
        proof.signature = sign_proof(&proof, signing_key);
        proof
    }

    #[test]
    fn proof_policy_hash_is_deterministic() {
        let signing_key = sample_signing_key();
        let pubkey_hex = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let policy = make_test_policy("deadbeef", &pubkey_hex, "attestor-a");
        let h1 = compute_proof_policy_hash(&policy).unwrap();
        let h2 = compute_proof_policy_hash(&policy).unwrap();
        assert_eq!(h1, h2, "hash must be deterministic");
        assert_eq!(h1.len(), 64, "must be 64-char hex SHA-256");
    }

    #[test]
    fn verify_settlement_proof_accepts_valid_signature() {
        let signing_key = sample_signing_key();
        let pubkey_hex = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let policy = make_test_policy("cafebabe", &pubkey_hex, "attestor-a");
        let proof = make_test_proof("cafebabe", "attestor-a", &signing_key);
        assert!(
            verify_settlement_proof(&proof, &policy).is_ok(),
            "valid proof must verify"
        );
    }

    #[test]
    fn verify_settlement_proof_rejects_wrong_pubkey() {
        let signing_key = sample_signing_key();
        let wrong_key = SigningKey::from_bytes((&[9u8; 32]).into()).unwrap();
        let wrong_pubkey_hex =
            hex::encode(wrong_key.verifying_key().to_encoded_point(false).as_bytes());
        let policy = make_test_policy("cafebabe", &wrong_pubkey_hex, "attestor-a");
        let proof = make_test_proof("cafebabe", "attestor-a", &signing_key);
        assert!(
            verify_settlement_proof(&proof, &policy).is_err(),
            "proof signed with wrong key must be rejected"
        );
    }

    #[test]
    fn unapproved_attestor_rejected() {
        let signing_key = sample_signing_key();
        let pubkey_hex = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let policy = make_test_policy("cafebabe", &pubkey_hex, "attestor-approved");
        let proof = make_test_proof("cafebabe", "attestor-unknown", &signing_key);
        let err = verify_settlement_proof(&proof, &policy).unwrap_err();
        assert!(err.contains("not approved"), "must mention approval: {err}");
    }

    #[test]
    fn no_response_rule_triggers_at_deadline() {
        let agreement = sample_agreement();
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));

        let signing_key = sample_signing_key();
        let pubkey_hex = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let mut policy = make_test_policy(&agreement_hash, &pubkey_hex, "attestor-a");
        policy.no_response_rules.push(NoResponseRule {
            rule_id: "rule-refund-200".to_string(),
            deadline_height: 200,
            trigger: NoResponseTrigger::FundedAndNoRelease,
            resolution: ProofResolution::Refund,
            milestone_id: None,
            notes: None,
        });

        let result = evaluate_policy(&agreement, &policy, &[], 200).unwrap();
        assert!(result.refund_eligible, "refund must trigger at deadline");
        assert!(!result.release_eligible);
    }

    #[test]
    fn no_response_rule_not_triggered_before_deadline() {
        let agreement = sample_agreement();
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));

        let signing_key = sample_signing_key();
        let pubkey_hex = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let mut policy = make_test_policy(&agreement_hash, &pubkey_hex, "attestor-a");
        policy.no_response_rules.push(NoResponseRule {
            rule_id: "rule-refund-200".to_string(),
            deadline_height: 200,
            trigger: NoResponseTrigger::FundedAndNoRelease,
            resolution: ProofResolution::Refund,
            milestone_id: None,
            notes: None,
        });

        let result = evaluate_policy(&agreement, &policy, &[], 199).unwrap();
        assert!(!result.refund_eligible);
        assert!(!result.release_eligible);
    }

    #[test]
    fn evaluate_policy_outcome_satisfied() {
        let signing_key = sample_signing_key();
        let pubkey_hex = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let agreement = sample_agreement();
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));
        let policy = make_test_policy(&agreement_hash, &pubkey_hex, "attestor-a");
        let proof = make_test_proof(&agreement_hash, "attestor-a", &signing_key);
        let result = evaluate_policy(&agreement, &policy, &[proof], 0).unwrap();
        assert_eq!(result.outcome, PolicyOutcome::Satisfied);
        assert!(result.release_eligible);
        assert!(!result.refund_eligible);
    }

    #[test]
    fn evaluate_policy_outcome_unsatisfied_missing_proofs() {
        let signing_key = sample_signing_key();
        let pubkey_hex = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let agreement = sample_agreement();
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));
        let policy = make_test_policy(&agreement_hash, &pubkey_hex, "attestor-a");
        let result = evaluate_policy(&agreement, &policy, &[], 0).unwrap();
        assert_eq!(result.outcome, PolicyOutcome::Unsatisfied);
        assert!(!result.release_eligible);
        assert!(!result.refund_eligible);
    }

    #[test]
    fn evaluate_policy_outcome_unsatisfied_wrong_attestor() {
        let signing_key = sample_signing_key();
        let pubkey_hex = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let agreement = sample_agreement();
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));
        let policy = make_test_policy(&agreement_hash, &pubkey_hex, "attestor-a");
        let mut policy2 = policy.clone();
        policy2.required_proofs[0].required_attestor_ids = vec!["attestor-b".to_string()];
        let proof = make_test_proof(&agreement_hash, "attestor-a", &signing_key);
        // proof is attested_by "attestor-a"; policy2 requires "attestor-b" -> req unsatisfied
        let result = evaluate_policy(&agreement, &policy2, &[proof], 0).unwrap();
        assert_eq!(result.outcome, PolicyOutcome::Unsatisfied);
        assert!(!result.release_eligible);
    }

    #[test]
    fn evaluate_policy_outcome_timeout_no_response_rule() {
        let signing_key = sample_signing_key();
        let pubkey_hex = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let agreement = sample_agreement();
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));
        let mut policy = make_test_policy(&agreement_hash, &pubkey_hex, "attestor-a");
        policy.no_response_rules.push(NoResponseRule {
            rule_id: "rule-refund-100".to_string(),
            deadline_height: 100,
            trigger: NoResponseTrigger::FundedAndNoRelease,
            resolution: ProofResolution::Refund,
            milestone_id: None,
            notes: None,
        });
        let result = evaluate_policy(&agreement, &policy, &[], 100).unwrap();
        assert_eq!(result.outcome, PolicyOutcome::Timeout);
        assert!(result.refund_eligible);
        assert!(!result.release_eligible);
    }

    #[test]
    fn evaluate_policy_outcome_timeout_required_by_deadline() {
        let signing_key = sample_signing_key();
        let pubkey_hex = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let agreement = sample_agreement();
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));
        let mut policy = make_test_policy(&agreement_hash, &pubkey_hex, "attestor-a");
        policy.required_proofs.clear();
        policy.required_proofs.push(ProofRequirement {
            requirement_id: "req-refund-deadline".to_string(),
            proof_type: "refund_proof".to_string(),
            required_by: Some(50),
            required_attestor_ids: vec!["attestor-a".to_string()],
            resolution: ProofResolution::Refund,
            milestone_id: None,
            threshold: None,
        });
        let result = evaluate_policy(&agreement, &policy, &[], 50).unwrap();
        assert_eq!(result.outcome, PolicyOutcome::Timeout);
        assert!(result.refund_eligible);
        assert!(!result.release_eligible);
    }

    #[test]
    fn evaluate_policy_outcome_satisfied_suppresses_no_response_rule() {
        // Proofs satisfy release; no-response rule deadline also elapsed.
        // Satisfied takes priority; outcome must be Satisfied.
        let signing_key = sample_signing_key();
        let pubkey_hex = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let agreement = sample_agreement();
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));
        let mut policy = make_test_policy(&agreement_hash, &pubkey_hex, "attestor-a");
        policy.no_response_rules.push(NoResponseRule {
            rule_id: "rule-refund-200".to_string(),
            deadline_height: 200,
            trigger: NoResponseTrigger::FundedAndNoRelease,
            resolution: ProofResolution::Refund,
            milestone_id: None,
            notes: None,
        });
        let proof = make_test_proof(&agreement_hash, "attestor-a", &signing_key);
        let result = evaluate_policy(&agreement, &policy, &[proof], 300).unwrap();
        assert_eq!(result.outcome, PolicyOutcome::Satisfied);
        assert!(result.release_eligible);
        assert!(!result.refund_eligible);
    }

    // ---- milestone-based evaluation tests ----

    fn make_milestone_policy(
        agreement_hash: &str,
        pubkey_hex: &str,
        attestor_id: &str,
        milestones: Vec<(&str, Option<&str>)>, // (milestone_id, label)
    ) -> ProofPolicy {
        let ms_decls: Vec<PolicyMilestone> = milestones
            .iter()
            .map(|(id, label)| PolicyMilestone {
                milestone_id: id.to_string(),
                label: label.map(|l| l.to_string()),
                holdback: None,
            })
            .collect();
        let reqs: Vec<ProofRequirement> = milestones
            .iter()
            .map(|(id, _)| ProofRequirement {
                requirement_id: format!("req-{}", id),
                proof_type: format!("proof_type_{}", id),
                required_by: None,
                required_attestor_ids: vec![attestor_id.to_string()],
                resolution: ProofResolution::MilestoneRelease,
                milestone_id: Some(id.to_string()),
                threshold: None,
            })
            .collect();
        ProofPolicy {
            policy_id: "pol-ms".to_string(),
            schema_id: PROOF_POLICY_SCHEMA_ID.to_string(),
            agreement_hash: agreement_hash.to_string(),
            required_proofs: reqs,
            no_response_rules: vec![],
            attestors: vec![ApprovedAttestor {
                attestor_id: attestor_id.to_string(),
                pubkey_hex: pubkey_hex.to_string(),
                display_name: None,
                domain: None,
            }],
            notes: None,
            expires_at_height: None,
            milestones: ms_decls,
            holdback: None,
        }
    }

    fn make_milestone_proof(
        agreement_hash: &str,
        attestor_id: &str,
        milestone_id: &str,
        signing_key: &SigningKey,
    ) -> SettlementProof {
        let pubkey_hex = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let mut proof = SettlementProof {
            proof_id: format!("prf-{}", milestone_id),
            schema_id: SETTLEMENT_PROOF_SCHEMA_ID.to_string(),
            // proof_type must match format!("proof_type_{}", milestone_id) from make_milestone_policy
            proof_type: format!("proof_type_{}", milestone_id),
            agreement_hash: agreement_hash.to_string(),
            milestone_id: Some(milestone_id.to_string()),
            attested_by: attestor_id.to_string(),
            attestation_time: 0,
            evidence_hash: None,
            evidence_summary: None,
            signature: ProofSignatureEnvelope {
                signature_type: AGREEMENT_SIGNATURE_TYPE_SECP256K1.to_string(),
                pubkey_hex: pubkey_hex.clone(),
                signature_hex: String::new(),
                payload_hash: String::new(),
            },
            expires_at_height: None,
            typed_payload: None,
        };
        proof.signature = sign_proof(&proof, signing_key);
        proof
    }

    #[test]
    fn evaluate_policy_milestone_single_satisfied() {
        // One milestone declared; proof satisfies it -> overall Satisfied.
        let sk = sample_signing_key();
        let pk = hex::encode(sk.verifying_key().to_encoded_point(false).as_bytes());
        let agreement = sample_agreement();
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let hash = hex::encode(Sha256::digest(&bytes));
        let policy = make_milestone_policy(&hash, &pk, "att", vec![("ms-a", Some("Delivery"))]);
        let proof = make_milestone_proof(&hash, "att", "ms-a", &sk);
        let result = evaluate_policy(&agreement, &policy, &[proof], 0).unwrap();
        assert_eq!(result.outcome, PolicyOutcome::Satisfied);
        assert!(result.release_eligible);
        assert_eq!(result.total_milestone_count, 1);
        assert_eq!(result.completed_milestone_count, 1);
        assert_eq!(result.milestone_results[0].milestone_id, "ms-a");
        assert_eq!(
            result.milestone_results[0].outcome,
            PolicyOutcome::Satisfied
        );
    }

    #[test]
    fn evaluate_policy_milestone_all_satisfied() {
        // Two milestones; both proofs provided -> overall Satisfied.
        let sk = sample_signing_key();
        let pk = hex::encode(sk.verifying_key().to_encoded_point(false).as_bytes());
        let agreement = sample_agreement();
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let hash = hex::encode(Sha256::digest(&bytes));
        let policy = make_milestone_policy(&hash, &pk, "att", vec![("ms-a", None), ("ms-b", None)]);
        let proof_a = make_milestone_proof(&hash, "att", "ms-a", &sk);
        let proof_b = make_milestone_proof(&hash, "att", "ms-b", &sk);
        let result = evaluate_policy(&agreement, &policy, &[proof_a, proof_b], 0).unwrap();
        assert_eq!(result.outcome, PolicyOutcome::Satisfied);
        assert_eq!(result.total_milestone_count, 2);
        assert_eq!(result.completed_milestone_count, 2);
    }

    #[test]
    fn evaluate_policy_milestone_partial_unsatisfied() {
        // Two milestones; only ms-a proof provided -> 1 of 2 satisfied -> Unsatisfied.
        let sk = sample_signing_key();
        let pk = hex::encode(sk.verifying_key().to_encoded_point(false).as_bytes());
        let agreement = sample_agreement();
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let hash = hex::encode(Sha256::digest(&bytes));
        let policy = make_milestone_policy(&hash, &pk, "att", vec![("ms-a", None), ("ms-b", None)]);
        let proof_a = make_milestone_proof(&hash, "att", "ms-a", &sk);
        let result = evaluate_policy(&agreement, &policy, &[proof_a], 0).unwrap();
        assert_eq!(result.outcome, PolicyOutcome::Unsatisfied);
        assert!(!result.release_eligible);
        assert_eq!(result.total_milestone_count, 2);
        assert_eq!(result.completed_milestone_count, 1);
        assert_eq!(
            result.milestone_results[0].outcome,
            PolicyOutcome::Satisfied
        );
        assert_eq!(
            result.milestone_results[1].outcome,
            PolicyOutcome::Unsatisfied
        );
    }

    #[test]
    fn evaluate_policy_milestone_timeout_on_one() {
        // ms-b has a no_response_rule deadline at height 50.
        // No proofs; tip = 51 -> ms-b times out -> overall Timeout.
        let sk = sample_signing_key();
        let pk = hex::encode(sk.verifying_key().to_encoded_point(false).as_bytes());
        let agreement = sample_agreement();
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let hash = hex::encode(Sha256::digest(&bytes));
        let mut policy =
            make_milestone_policy(&hash, &pk, "att", vec![("ms-a", None), ("ms-b", None)]);
        policy.no_response_rules.push(NoResponseRule {
            rule_id: "rule-ms-b-timeout".to_string(),
            deadline_height: 50,
            trigger: NoResponseTrigger::FundedAndNoRelease,
            resolution: ProofResolution::Refund,
            milestone_id: Some("ms-b".to_string()),
            notes: None,
        });
        let result = evaluate_policy(&agreement, &policy, &[], 51).unwrap();
        assert_eq!(result.outcome, PolicyOutcome::Timeout);
        assert!(result.refund_eligible);
        assert!(!result.release_eligible);
        assert_eq!(result.total_milestone_count, 2);
        // ms-a has no deadline so it is Unsatisfied; ms-b has timed out
        let ms_b = result
            .milestone_results
            .iter()
            .find(|r| r.milestone_id == "ms-b")
            .unwrap();
        assert_eq!(ms_b.outcome, PolicyOutcome::Timeout);
    }

    #[test]
    fn evaluate_policy_milestone_satisfied_overrides_timeout() {
        // ms-a satisfied, ms-b not. ms-b has no deadline -> Unsatisfied (not Timeout).
        // Also: satisfying ms-a does NOT suppress ms-b timeout if ms-b has one.
        // Here we test: all satisfied -> Satisfied, even if one had a deadline.
        let sk = sample_signing_key();
        let pk = hex::encode(sk.verifying_key().to_encoded_point(false).as_bytes());
        let agreement = sample_agreement();
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let hash = hex::encode(Sha256::digest(&bytes));
        let mut policy =
            make_milestone_policy(&hash, &pk, "att", vec![("ms-a", None), ("ms-b", None)]);
        policy.no_response_rules.push(NoResponseRule {
            rule_id: "rule-ms-b-dl".to_string(),
            deadline_height: 50,
            trigger: NoResponseTrigger::FundedAndNoRelease,
            resolution: ProofResolution::Refund,
            milestone_id: Some("ms-b".to_string()),
            notes: None,
        });
        // Provide both proofs; ms-b proof satisfies ms-b before deadline check
        let proof_a = make_milestone_proof(&hash, "att", "ms-a", &sk);
        let proof_b = make_milestone_proof(&hash, "att", "ms-b", &sk);
        let result = evaluate_policy(&agreement, &policy, &[proof_a, proof_b], 51).unwrap();
        assert_eq!(result.outcome, PolicyOutcome::Satisfied);
        assert!(result.release_eligible);
        assert_eq!(result.completed_milestone_count, 2);
    }

    #[test]
    fn evaluate_policy_milestone_backward_compat_no_milestones() {
        // Policy with no milestones declared: milestone_results must be empty.
        let sk = sample_signing_key();
        let pk = hex::encode(sk.verifying_key().to_encoded_point(false).as_bytes());
        let agreement = sample_agreement();
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let hash = hex::encode(Sha256::digest(&bytes));
        let policy = make_test_policy(&hash, &pk, "attestor-a");
        let proof = make_test_proof(&hash, "attestor-a", &sk);
        let result = evaluate_policy(&agreement, &policy, &[proof], 0).unwrap();
        assert_eq!(result.outcome, PolicyOutcome::Satisfied);
        assert!(result.milestone_results.is_empty());
        assert_eq!(result.total_milestone_count, 0);
        assert_eq!(result.completed_milestone_count, 0);
    }

    #[test]
    fn policy_hash_mismatch_rejected() {
        let signing_key = sample_signing_key();
        let pubkey_hex = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let agreement = sample_agreement();
        let policy = make_test_policy("000000wrong_hash", &pubkey_hex, "attestor-a");
        let err = evaluate_policy(&agreement, &policy, &[], 0).unwrap_err();
        assert!(
            err.contains("does not match"),
            "must mention mismatch: {err}"
        );
    }

    #[test]
    fn cross_agreement_proof_rejected_in_evaluate_policy() {
        // A proof signed for agreement_A must be rejected when evaluating against agreement_B,
        // even when the attestor is approved in the policy for agreement_B and the signature is valid.
        let signing_key = sample_signing_key();
        let pubkey_hex = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );

        // Two different agreements with distinct hashes
        let agreement_a = sample_agreement();
        let bytes_a = agreement_canonical_bytes(&agreement_a).unwrap();
        let hash_a = hex::encode(Sha256::digest(&bytes_a));

        // Construct a minimal distinct agreement (different total_amount so hash differs)
        let mut agreement_b = sample_agreement();
        agreement_b.total_amount = agreement_a.total_amount + 1;
        let bytes_b = agreement_canonical_bytes(&agreement_b).unwrap();
        let hash_b = hex::encode(Sha256::digest(&bytes_b));
        assert_ne!(
            hash_a, hash_b,
            "test requires two distinct agreement hashes"
        );

        // Proof is correctly signed for agreement_A
        let proof_for_a = make_test_proof(&hash_a, "attestor-a", &signing_key);
        assert_eq!(proof_for_a.agreement_hash, hash_a);

        // Policy is for agreement_B but uses the same attestor
        let policy_b = make_test_policy(&hash_b, &pubkey_hex, "attestor-a");

        // Evaluate: proof_for_a must be rejected for policy_b
        let result = evaluate_policy(&agreement_b, &policy_b, &[proof_for_a], 0).unwrap();
        assert!(
            !result.release_eligible,
            "cross-agreement proof must not grant release"
        );
        assert!(!result.refund_eligible);
        assert!(
            result
                .evaluated_rules
                .iter()
                .any(|r| r.contains("agreement_hash mismatch")),
            "evaluated_rules must record the mismatch; got: {:?}",
            result.evaluated_rules
        );
    }

    #[test]
    fn same_agreement_proof_still_accepted_in_evaluate_policy() {
        // A proof for the correct agreement must still be accepted after the fix.
        let signing_key = sample_signing_key();
        let pubkey_hex = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );

        let agreement = sample_agreement();
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));

        let mut policy = make_test_policy(&agreement_hash, &pubkey_hex, "attestor-a");
        policy.required_proofs.push(ProofRequirement {
            requirement_id: "req-001".to_string(),
            proof_type: "delivery_confirmation".to_string(),
            required_by: None,
            required_attestor_ids: vec!["attestor-a".to_string()],
            resolution: ProofResolution::Release,
            milestone_id: None,
            threshold: None,
        });

        let proof = make_test_proof(&agreement_hash, "attestor-a", &signing_key);
        let result = evaluate_policy(&agreement, &policy, &[proof], 0).unwrap();
        assert!(result.release_eligible, "correct proof must grant release");
        assert!(!result.refund_eligible);
        assert!(
            result
                .evaluated_rules
                .iter()
                .any(|r| r.contains("verified ok")),
            "evaluated_rules must record verification; got: {:?}",
            result.evaluated_rules
        );
    }

    #[test]
    fn cross_agreement_proof_rejected_does_not_satisfy_release_requirement() {
        // Even if a cross-agreement proof passes all other checks (attestor approved,
        // correct proof_type, valid signature), it must not satisfy a release requirement.
        let signing_key = sample_signing_key();
        let pubkey_hex = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );

        let agreement_a = sample_agreement();
        let bytes_a = agreement_canonical_bytes(&agreement_a).unwrap();
        let hash_a = hex::encode(Sha256::digest(&bytes_a));

        let mut agreement_b = sample_agreement();
        agreement_b.total_amount = agreement_a.total_amount + 99;
        let bytes_b = agreement_canonical_bytes(&agreement_b).unwrap();
        let hash_b = hex::encode(Sha256::digest(&bytes_b));
        assert_ne!(hash_a, hash_b);

        let proof_for_a = make_test_proof(&hash_a, "attestor-a", &signing_key);

        let mut policy_b = make_test_policy(&hash_b, &pubkey_hex, "attestor-a");
        policy_b.required_proofs.push(ProofRequirement {
            requirement_id: "req-001".to_string(),
            proof_type: "delivery_confirmation".to_string(),
            required_by: None,
            required_attestor_ids: vec!["attestor-a".to_string()],
            resolution: ProofResolution::Release,
            milestone_id: None,
            threshold: None,
        });

        let result = evaluate_policy(&agreement_b, &policy_b, &[proof_for_a], 0).unwrap();
        assert!(
            !result.release_eligible,
            "cross-agreement proof must not satisfy release requirement"
        );
        let mismatch_logged = result
            .evaluated_rules
            .iter()
            .any(|r| r.contains("agreement_hash mismatch"));
        assert!(
            mismatch_logged,
            "mismatch must appear in evaluated_rules; got: {:?}",
            result.evaluated_rules
        );
    }

    // ---- ProofStore tests ----

    fn make_proof_store() -> ProofStore {
        let path = std::env::temp_dir().join(format!(
            "irium_test_proofs_{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos()
        ));
        ProofStore::new(path)
    }

    fn build_signed_proof(
        agreement_hash: &str,
        attestor_id: &str,
        signing_key: &SigningKey,
    ) -> SettlementProof {
        let pubkey_hex = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let mut proof = SettlementProof {
            proof_id: format!("prf-store-{}-{}", attestor_id, agreement_hash),
            schema_id: SETTLEMENT_PROOF_SCHEMA_ID.to_string(),
            proof_type: "delivery_confirmation".to_string(),
            agreement_hash: agreement_hash.to_string(),
            milestone_id: None,
            attested_by: attestor_id.to_string(),
            attestation_time: 1_700_100_000,
            evidence_hash: None,
            evidence_summary: Some("store test delivery".to_string()),
            signature: ProofSignatureEnvelope {
                signature_type: AGREEMENT_SIGNATURE_TYPE_SECP256K1.to_string(),
                pubkey_hex: pubkey_hex.clone(),
                signature_hex: String::new(),
                payload_hash: String::new(),
            },
            expires_at_height: None,
            typed_payload: None,
        };
        let payload = settlement_proof_payload_bytes(&proof).unwrap();
        let digest = sha2::Sha256::digest(&payload);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&digest);
        let sig: k256::ecdsa::Signature = signing_key.sign_prehash(&arr).unwrap();
        proof.signature.signature_hex = hex::encode(sig.to_bytes());
        proof.signature.payload_hash = hex::encode(digest);
        proof
    }

    /// Variant of build_signed_proof that accepts a custom attestation_time.
    /// Used by ordering tests to control the temporal field in the signed payload.
    fn build_signed_proof_at_time(
        agreement_hash: &str,
        attestor_id: &str,
        signing_key: &SigningKey,
        attestation_time: u64,
    ) -> SettlementProof {
        let pubkey_hex = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let mut proof = SettlementProof {
            proof_id: format!("prf-store-{}-{}", attestor_id, agreement_hash),
            schema_id: SETTLEMENT_PROOF_SCHEMA_ID.to_string(),
            proof_type: "delivery_confirmation".to_string(),
            agreement_hash: agreement_hash.to_string(),
            milestone_id: None,
            attested_by: attestor_id.to_string(),
            attestation_time,
            evidence_hash: None,
            evidence_summary: Some("ordering test".to_string()),
            signature: ProofSignatureEnvelope {
                signature_type: AGREEMENT_SIGNATURE_TYPE_SECP256K1.to_string(),
                pubkey_hex: pubkey_hex.clone(),
                signature_hex: String::new(),
                payload_hash: String::new(),
            },
            expires_at_height: None,
            typed_payload: None,
        };
        let payload = settlement_proof_payload_bytes(&proof).unwrap();
        let digest = sha2::Sha256::digest(&payload);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&digest);
        let sig: k256::ecdsa::Signature = signing_key.sign_prehash(&arr).unwrap();
        proof.signature.signature_hex = hex::encode(sig.to_bytes());
        proof.signature.payload_hash = hex::encode(digest);
        proof
    }

    #[test]
    fn proof_store_list_by_agreement_orders_by_attestation_time() {
        // Proofs submitted out of time-order must be returned oldest-first.
        let mut store = make_proof_store();
        let sk1 = SigningKey::from_bytes((&[50u8; 32]).into()).unwrap();
        let sk2 = SigningKey::from_bytes((&[51u8; 32]).into()).unwrap();
        let sk3 = SigningKey::from_bytes((&[52u8; 32]).into()).unwrap();
        let p_latest = build_signed_proof_at_time("ord-hash", "att-c", &sk3, 3_000);
        let p_mid = build_signed_proof_at_time("ord-hash", "att-b", &sk2, 2_000);
        let p_oldest = build_signed_proof_at_time("ord-hash", "att-a", &sk1, 1_000);
        // submit in reverse time order to rule out insertion-order artefacts
        store.submit(p_latest).unwrap();
        store.submit(p_mid).unwrap();
        store.submit(p_oldest).unwrap();
        let listed = store.list_by_agreement("ord-hash");
        assert_eq!(listed.len(), 3);
        assert_eq!(listed[0].attestation_time, 1_000, "oldest must be first");
        assert_eq!(listed[1].attestation_time, 2_000);
        assert_eq!(listed[2].attestation_time, 3_000, "latest must be last");
    }

    #[test]
    fn proof_store_list_all_orders_by_attestation_time() {
        // list_all must apply the same ordering even across different agreement hashes.
        let mut store = make_proof_store();
        let sk1 = SigningKey::from_bytes((&[53u8; 32]).into()).unwrap();
        let sk2 = SigningKey::from_bytes((&[54u8; 32]).into()).unwrap();
        let sk3 = SigningKey::from_bytes((&[55u8; 32]).into()).unwrap();
        // different agreement hashes; p3 has smallest time, p1 largest
        let p1 = build_signed_proof_at_time("hash-z", "att-z", &sk1, 9_000);
        let p2 = build_signed_proof_at_time("hash-a", "att-a", &sk2, 5_000);
        let p3 = build_signed_proof_at_time("hash-m", "att-m", &sk3, 1_000);
        store.submit(p1).unwrap();
        store.submit(p2).unwrap();
        store.submit(p3).unwrap();
        let all = store.list_all();
        assert_eq!(all.len(), 3);
        assert_eq!(
            all[0].attestation_time, 1_000,
            "oldest first regardless of agreement_hash"
        );
        assert_eq!(all[1].attestation_time, 5_000);
        assert_eq!(
            all[2].attestation_time, 9_000,
            "latest last regardless of agreement_hash"
        );
    }

    #[test]
    fn proof_store_list_tie_breaks_by_proof_id() {
        // Two proofs with identical attestation_time must be ordered by proof_id ascending.
        let mut store = make_proof_store();
        let sk1 = SigningKey::from_bytes((&[56u8; 32]).into()).unwrap();
        let sk2 = SigningKey::from_bytes((&[57u8; 32]).into()).unwrap();
        let mut pa = build_signed_proof_at_time("tie-hash", "att-b", &sk1, 7_000);
        let mut pb = build_signed_proof_at_time("tie-hash", "att-a", &sk2, 7_000);
        // Override proof_ids so we control alphabetical order explicitly
        pa.proof_id = "prf-zzz".to_string();
        pb.proof_id = "prf-aaa".to_string();
        // Re-sign after changing proof_id since proof_id is part of the payload
        let payload_a = settlement_proof_payload_bytes(&pa).unwrap();
        let digest_a = sha2::Sha256::digest(&payload_a);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&digest_a);
        let sig_a: k256::ecdsa::Signature = sk1.sign_prehash(&arr).unwrap();
        pa.signature.signature_hex = hex::encode(sig_a.to_bytes());
        pa.signature.payload_hash = hex::encode(digest_a);
        let payload_b = settlement_proof_payload_bytes(&pb).unwrap();
        let digest_b = sha2::Sha256::digest(&payload_b);
        arr.copy_from_slice(&digest_b);
        let sig_b: k256::ecdsa::Signature = sk2.sign_prehash(&arr).unwrap();
        pb.signature.signature_hex = hex::encode(sig_b.to_bytes());
        pb.signature.payload_hash = hex::encode(digest_b);
        store.submit(pa).unwrap();
        store.submit(pb).unwrap();
        let listed = store.list_by_agreement("tie-hash");
        assert_eq!(listed.len(), 2);
        assert_eq!(
            listed[0].proof_id, "prf-aaa",
            "alphabetically earlier proof_id must be first on tie"
        );
        assert_eq!(listed[1].proof_id, "prf-zzz");
    }

    #[test]
    fn proof_store_accepts_valid_proof() {
        let mut store = make_proof_store();
        let sk = SigningKey::from_bytes((&[13u8; 32]).into()).unwrap();
        let proof = build_signed_proof("aabbcc", "att-1", &sk);
        let outcome = store.submit(proof).unwrap();
        assert!(outcome.accepted);
        assert!(!outcome.duplicate);
        assert_eq!(outcome.proof_id, "prf-store-att-1-aabbcc");
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn proof_store_rejects_invalid_signature() {
        let mut store = make_proof_store();
        let sk = SigningKey::from_bytes((&[13u8; 32]).into()).unwrap();
        let mut proof = build_signed_proof("aabbcc", "att-1", &sk);
        // Corrupt the signature
        proof.signature.signature_hex = "ff".repeat(64);
        let err = store.submit(proof).unwrap_err();
        assert!(
            err.contains("verification failed") || err.contains("secp256k1"),
            "got: {err}"
        );
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn proof_store_deduplicates_by_proof_id() {
        let mut store = make_proof_store();
        let sk = SigningKey::from_bytes((&[13u8; 32]).into()).unwrap();
        let proof = build_signed_proof("aabbcc", "att-1", &sk);
        let first = store.submit(proof.clone()).unwrap();
        let second = store.submit(proof).unwrap();
        assert!(first.accepted);
        assert!(!second.accepted);
        assert!(second.duplicate);
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn proof_store_lists_by_agreement_hash() {
        let mut store = make_proof_store();
        let sk1 = SigningKey::from_bytes((&[13u8; 32]).into()).unwrap();
        let sk2 = SigningKey::from_bytes((&[14u8; 32]).into()).unwrap();
        let p1 = build_signed_proof("target-hash", "att-1", &sk1);
        let p2 = build_signed_proof("target-hash", "att-2", &sk2);
        let p3 = build_signed_proof("other-hash", "att-1", &sk1);
        store.submit(p1).unwrap();
        store.submit(p2).unwrap();
        store.submit(p3).unwrap();
        let listed = store.list_by_agreement("target-hash");
        assert_eq!(listed.len(), 2);
        let other = store.list_by_agreement("other-hash");
        assert_eq!(other.len(), 1);
        let none = store.list_by_agreement("nonexistent");
        assert_eq!(none.len(), 0);
    }

    #[test]
    fn proof_store_rejects_wrong_schema_id() {
        let mut store = make_proof_store();
        let sk = SigningKey::from_bytes((&[13u8; 32]).into()).unwrap();
        let mut proof = build_signed_proof("aabbcc", "att-1", &sk);
        proof.schema_id = "wrong.schema".to_string();
        let err = store.submit(proof).unwrap_err();
        assert!(err.contains("schema_id"), "got: {err}");
    }

    #[test]
    fn proof_expiry_field_roundtrips_through_store() {
        let sk = SigningKey::from_bytes((&[41u8; 32]).into()).unwrap();
        let mut store = make_proof_store();
        let mut proof = build_signed_proof("expiry-hash", "att-exp", &sk);
        // expires_at_height is not part of the signature payload;
        // set it after signing and verify the store preserves it.
        proof.expires_at_height = Some(999);
        store
            .submit(proof)
            .expect("submit with expiry must succeed");
        let stored = store.list_by_agreement("expiry-hash");
        assert_eq!(stored.len(), 1);
        assert_eq!(
            stored[0].expires_at_height,
            Some(999),
            "expiry must be preserved in store"
        );
    }

    #[test]
    fn proof_no_expiry_field_defaults_to_none() {
        let sk = SigningKey::from_bytes((&[42u8; 32]).into()).unwrap();
        let mut store = make_proof_store();
        let proof = build_signed_proof("no-expiry-hash", "att-noexp", &sk);
        store
            .submit(proof)
            .expect("submit without expiry must succeed");
        let stored = store.list_by_agreement("no-expiry-hash");
        assert_eq!(stored[0].expires_at_height, None, "no expiry must be None");
    }

    #[test]
    fn proof_expiry_survives_disk_roundtrip() {
        let path = std::env::temp_dir().join(format!(
            "irium_test_expiry_disk_{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos()
        ));
        let sk = SigningKey::from_bytes((&[43u8; 32]).into()).unwrap();
        {
            let mut store = ProofStore::new(path.clone());
            let mut proof = build_signed_proof("disk-exp-hash", "att-disk", &sk);
            proof.expires_at_height = Some(77777);
            store.submit(proof).unwrap();
        }
        let store2 = ProofStore::new(path.clone());
        let stored = store2.list_by_agreement("disk-exp-hash");
        assert_eq!(
            stored[0].expires_at_height,
            Some(77777),
            "expiry must survive disk reload"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn proof_store_roundtrip_persist_and_reload() {
        let path = std::env::temp_dir().join(format!(
            "irium_test_roundtrip_{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos()
        ));
        let sk = SigningKey::from_bytes((&[13u8; 32]).into()).unwrap();
        {
            let mut store = ProofStore::new(path.clone());
            let proof = build_signed_proof("persist-hash", "att-1", &sk);
            store.submit(proof).unwrap();
            assert_eq!(store.count(), 1);
        }
        // Reload from disk
        let store2 = ProofStore::new(path.clone());
        assert_eq!(store2.count(), 1);
        let listed = store2.list_by_agreement("persist-hash");
        assert_eq!(listed.len(), 1);
        let _ = std::fs::remove_file(&path);
    }

    // ---- PolicyStore tests ----

    fn make_policy_store() -> PolicyStore {
        let path = std::env::temp_dir().join(format!(
            "irium_test_policies_{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos()
        ));
        PolicyStore::new(path)
    }

    #[test]
    fn policy_store_accepts_valid_policy() {
        let mut store = make_policy_store();
        let policy = make_test_policy("abc123", "pubkey", "att-1");
        let outcome = store.store(policy, false).expect("must accept");
        assert!(outcome.accepted);
        assert!(!outcome.updated);
        assert_eq!(outcome.agreement_hash, "abc123");
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn policy_store_rejects_empty_agreement_hash() {
        let mut store = make_policy_store();
        let mut policy = make_test_policy("abc123", "pubkey", "att-1");
        policy.agreement_hash = "".to_string();
        let err = store.store(policy, false).unwrap_err();
        assert!(err.contains("agreement_hash"), "got: {err}");
    }

    #[test]
    fn policy_store_get_existing_policy() {
        let mut store = make_policy_store();
        let policy = make_test_policy("deadbeef", "pk1", "att-a");
        store.store(policy.clone(), false).expect("must accept");
        let found = store.get("deadbeef").expect("must find");
        assert_eq!(found.policy_id, policy.policy_id);
        assert_eq!(found.agreement_hash, "deadbeef");
    }

    #[test]
    fn policy_store_missing_policy_returns_none() {
        let store = make_policy_store();
        assert!(store.get("nonexistent").is_none());
    }

    #[test]
    fn policy_store_duplicate_same_policy_id() {
        let mut store = make_policy_store();
        let policy = make_test_policy("cafebabe", "pk1", "att-1");
        let first = store.store(policy.clone(), false).expect("first");
        assert!(first.accepted);
        let second = store.store(policy, false).expect("second");
        assert!(!second.accepted);
        assert!(!second.updated);
        assert!(
            second.message.contains("already stored"),
            "got: {}",
            second.message
        );
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn policy_store_overwrite_different_policy_id_same_hash() {
        let mut store = make_policy_store();
        let mut policy_a = make_test_policy("aabbcc", "pk1", "att-1");
        policy_a.policy_id = "pol-001".to_string();
        store.store(policy_a, false).expect("first");

        let mut policy_b = make_test_policy("aabbcc", "pk2", "att-2");
        policy_b.policy_id = "pol-002".to_string();
        let outcome = store.store(policy_b, true).expect("second");
        assert!(outcome.accepted);
        assert!(outcome.updated);
        assert_eq!(store.count(), 1);
        let found = store.get("aabbcc").expect("must find");
        assert_eq!(found.policy_id, "pol-002");
    }

    #[test]
    fn policy_store_roundtrip_persist_and_reload() {
        let path = std::env::temp_dir().join(format!(
            "irium_test_policy_persist_{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos()
        ));
        {
            let mut store = PolicyStore::new(path.clone());
            let policy = make_test_policy("persist-hash", "pk1", "att-1");
            store.store(policy, false).expect("must accept");
            assert_eq!(store.count(), 1);
        }
        let store2 = PolicyStore::new(path.clone());
        assert_eq!(store2.count(), 1);
        let found = store2.get("persist-hash").expect("must find after reload");
        assert_eq!(found.agreement_hash, "persist-hash");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn required_by_refund_triggers_when_deadline_passed_and_no_proof() {
        let signing_key = sample_signing_key();
        let pubkey_hex = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let agreement = sample_agreement();
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));

        let mut policy = make_test_policy(&agreement_hash, &pubkey_hex, "attestor-a");
        // Replace the default release requirement with a refund requirement that has a deadline
        policy.required_proofs = vec![ProofRequirement {
            requirement_id: "req-refund-100".to_string(),
            proof_type: "delivery_confirmation".to_string(),
            required_by: Some(100),
            required_attestor_ids: vec!["attestor-a".to_string()],
            resolution: ProofResolution::Refund,
            milestone_id: None,
            threshold: None,
        }];

        // At tip == deadline: refund triggered
        let result = evaluate_policy(&agreement, &policy, &[], 100).unwrap();
        assert!(
            result.refund_eligible,
            "refund must trigger at required_by deadline"
        );
        assert!(!result.release_eligible);
        assert!(
            result
                .evaluated_rules
                .iter()
                .any(|r| r.contains("refund deadline") && r.contains("no satisfying proof")),
            "evaluated_rules must record the deadline miss; got: {:?}",
            result.evaluated_rules
        );
    }

    #[test]
    fn required_by_refund_not_triggered_before_deadline() {
        let signing_key = sample_signing_key();
        let pubkey_hex = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let agreement = sample_agreement();
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));

        let mut policy = make_test_policy(&agreement_hash, &pubkey_hex, "attestor-a");
        policy.required_proofs = vec![ProofRequirement {
            requirement_id: "req-refund-100".to_string(),
            proof_type: "delivery_confirmation".to_string(),
            required_by: Some(100),
            required_attestor_ids: vec!["attestor-a".to_string()],
            resolution: ProofResolution::Refund,
            milestone_id: None,
            threshold: None,
        }];

        // One block before deadline: no trigger
        let result = evaluate_policy(&agreement, &policy, &[], 99).unwrap();
        assert!(!result.refund_eligible);
        assert!(!result.release_eligible);
    }

    #[test]
    fn required_by_refund_requirement_satisfied_no_trigger() {
        // If the refund requirement is satisfied (proof present), no refund, even past deadline.
        let signing_key = sample_signing_key();
        let pubkey_hex = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let agreement = sample_agreement();
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));

        let mut policy = make_test_policy(&agreement_hash, &pubkey_hex, "attestor-a");
        policy.required_proofs = vec![ProofRequirement {
            requirement_id: "req-refund-100".to_string(),
            proof_type: "delivery_confirmation".to_string(),
            required_by: Some(100),
            required_attestor_ids: vec!["attestor-a".to_string()],
            resolution: ProofResolution::Refund,
            milestone_id: None,
            threshold: None,
        }];

        let proof = make_test_proof(&agreement_hash, "attestor-a", &signing_key);
        let result = evaluate_policy(&agreement, &policy, &[proof], 200).unwrap();
        assert!(
            !result.refund_eligible,
            "satisfied refund requirement must not trigger refund"
        );
        assert!(!result.release_eligible, "no release requirement present");
        assert!(
            result
                .evaluated_rules
                .iter()
                .any(|r| r.contains("refund deadline") && r.contains("but satisfied")),
            "must record that refund deadline was reached but satisfied; got: {:?}",
            result.evaluated_rules
        );
    }

    #[test]
    fn required_by_release_deadline_missed_still_grants_release_when_proof_present() {
        // A proof arriving after required_by deadline must still satisfy the release requirement.
        let signing_key = sample_signing_key();
        let pubkey_hex = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let agreement = sample_agreement();
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));

        let mut policy = make_test_policy(&agreement_hash, &pubkey_hex, "attestor-a");
        // Set a required_by deadline in the past on the release requirement
        policy.required_proofs[0].required_by = Some(50);

        // Tip is well past the deadline, but proof is present
        let proof = make_test_proof(&agreement_hash, "attestor-a", &signing_key);
        let result = evaluate_policy(&agreement, &policy, &[proof], 200).unwrap();
        assert!(
            result.release_eligible,
            "late proof must still satisfy release requirement"
        );
        assert!(!result.refund_eligible);
    }

    #[test]
    fn no_response_rule_suppressed_when_release_already_met() {
        // If all release requirements are satisfied, a no-response rule with
        // FundedAndNoRelease trigger at a passed deadline must NOT fire.
        let signing_key = sample_signing_key();
        let pubkey_hex = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let agreement = sample_agreement();
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));

        let mut policy = make_test_policy(&agreement_hash, &pubkey_hex, "attestor-a");
        policy.no_response_rules.push(NoResponseRule {
            rule_id: "rule-refund-at-100".to_string(),
            deadline_height: 100,
            trigger: NoResponseTrigger::FundedAndNoRelease,
            resolution: ProofResolution::Refund,
            milestone_id: None,
            notes: None,
        });

        // Tip is past the no-response deadline, but a valid proof satisfies release
        let proof = make_test_proof(&agreement_hash, "attestor-a", &signing_key);
        let result = evaluate_policy(&agreement, &policy, &[proof], 200).unwrap();
        assert!(
            result.release_eligible,
            "release must be granted when proofs satisfy requirements"
        );
        assert!(
            !result.refund_eligible,
            "no-response rule must be suppressed when release is met"
        );
    }

    #[test]
    fn no_response_rule_triggers_when_release_not_met() {
        // With no valid proofs, the no-response rule fires at its deadline.
        let signing_key = sample_signing_key();
        let pubkey_hex = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let agreement = sample_agreement();
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));

        let mut policy = make_test_policy(&agreement_hash, &pubkey_hex, "attestor-a");
        policy.no_response_rules.push(NoResponseRule {
            rule_id: "rule-refund-at-100".to_string(),
            deadline_height: 100,
            trigger: NoResponseTrigger::FundedAndNoRelease,
            resolution: ProofResolution::Refund,
            milestone_id: None,
            notes: None,
        });

        // No proofs submitted, tip past deadline
        let result = evaluate_policy(&agreement, &policy, &[], 100).unwrap();
        assert!(
            result.refund_eligible,
            "no-response rule must fire when release not met"
        );
        assert!(!result.release_eligible);
        assert!(
            result
                .evaluated_rules
                .iter()
                .any(|r| r.contains("rule-refund-at-100") && r.contains("funded_and_no_release")),
            "trigger label must appear in evaluated_rules; got: {:?}",
            result.evaluated_rules
        );
    }

    #[test]
    fn policy_store_rejects_overwrite_without_replace_flag() {
        let mut store = make_policy_store();
        let signing_key = sample_signing_key();
        let pubkey_hex = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let policy_a = make_test_policy("aabbcc", &pubkey_hex, "att-a");
        store
            .store(policy_a, false)
            .expect("first store must succeed");

        // Different policy_id, same agreement_hash, replace=false -> rejected
        let mut policy_b = make_test_policy("aabbcc", &pubkey_hex, "att-a");
        policy_b.policy_id = "pol-002".to_string();
        let outcome = store.store(policy_b, false).expect("must not error");
        assert!(
            !outcome.accepted,
            "must not accept overwrite without replace flag"
        );
        assert!(!outcome.updated);
        assert!(
            outcome.message.contains("already exists") && outcome.message.contains("--replace"),
            "message must explain how to replace; got: {}",
            outcome.message
        );
        // Original policy must still be in place
        let stored = store.get("aabbcc").unwrap();
        assert_eq!(
            stored.policy_id, "pol-001",
            "original policy must not be replaced"
        );
    }

    #[test]
    fn policy_store_allows_replace_with_flag() {
        let mut store = make_policy_store();
        let signing_key = sample_signing_key();
        let pubkey_hex = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let policy_a = make_test_policy("aabbcc", &pubkey_hex, "att-a");
        store
            .store(policy_a, false)
            .expect("first store must succeed");

        // Different policy_id, replace=true -> accepted, updated
        let mut policy_b = make_test_policy("aabbcc", &pubkey_hex, "att-a");
        policy_b.policy_id = "pol-002".to_string();
        let outcome = store.store(policy_b, true).expect("must not error");
        assert!(outcome.accepted, "must accept with replace flag");
        assert!(outcome.updated, "must be marked as updated");
        assert!(
            outcome.message.contains("replaced"),
            "message must say replaced; got: {}",
            outcome.message
        );
        // New policy must be in place
        let stored = store.get("aabbcc").unwrap();
        assert_eq!(stored.policy_id, "pol-002", "new policy must replace old");
    }

    #[test]
    fn policy_store_duplicate_same_policy_id_with_replace_is_still_no_op() {
        // Even with replace=true, same policy_id is a no-op
        let mut store = make_policy_store();
        let signing_key = sample_signing_key();
        let pubkey_hex = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let policy = make_test_policy("aabbcc", &pubkey_hex, "att-a");
        store.store(policy.clone(), false).expect("first store");
        let outcome = store.store(policy, true).expect("second store");
        assert!(
            !outcome.accepted,
            "same policy_id with replace=true must still be no-op"
        );
        assert!(!outcome.updated);
        assert!(
            outcome.message.contains("same policy_id"),
            "message must mention same policy_id; got: {}",
            outcome.message
        );
    }

    #[test]
    fn proof_policy_expiry_field_roundtrips_through_store() {
        let mut store = make_policy_store();
        let policy = make_test_policy_with_expiry("exp-hash-001", 42);
        store.store(policy.clone(), false).expect("must accept");
        let got = store.get("exp-hash-001").expect("must exist");
        assert_eq!(got.expires_at_height, Some(42), "expiry must round-trip");
    }

    #[test]
    fn proof_policy_no_expiry_defaults_none() {
        let mut store = make_policy_store();
        let policy = make_test_policy("no-exp-hash", "pk-abc", "att-abc");
        store.store(policy, false).expect("must accept");
        let got = store.get("no-exp-hash").expect("must exist");
        assert_eq!(got.expires_at_height, None);
    }

    #[test]
    fn proof_policy_expiry_persists_across_reload() {
        let path = std::env::temp_dir().join(format!(
            "irium_test_exp_{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos()
        ));
        {
            let mut store = PolicyStore::new(path.clone());
            let policy = make_test_policy_with_expiry("exp-persist-hash", 9999);
            store.store(policy, false).expect("must accept");
        }
        let store2 = PolicyStore::new(path);
        let got = store2
            .get("exp-persist-hash")
            .expect("must exist after reload");
        assert_eq!(got.expires_at_height, Some(9999));
    }

    #[test]
    fn store_policy_rejects_empty_milestone_id() {
        let mut store = make_policy_store();
        let signing_key = sample_signing_key();
        let pubkey_hex = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let agreement = sample_agreement();
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let hash = hex::encode(Sha256::digest(&bytes));
        let mut policy = make_test_policy(&hash, &pubkey_hex, "att");
        policy.milestones = vec![PolicyMilestone {
            milestone_id: "  ".to_string(), // blank
            label: None,
            holdback: None,
        }];
        let err = store.store(policy, false).unwrap_err();
        assert!(err.contains("milestone_id must not be empty"), "got: {err}");
    }

    #[test]
    fn store_policy_rejects_duplicate_milestone_id() {
        let mut store = make_policy_store();
        let signing_key = sample_signing_key();
        let pubkey_hex = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let agreement = sample_agreement();
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let hash = hex::encode(Sha256::digest(&bytes));
        let mut policy = make_test_policy(&hash, &pubkey_hex, "att");
        policy.milestones = vec![
            PolicyMilestone {
                milestone_id: "ms-dup".to_string(),
                label: None,
                holdback: None,
            },
            PolicyMilestone {
                milestone_id: "ms-dup".to_string(),
                label: None,
                holdback: None,
            },
        ];
        let err = store.store(policy, false).unwrap_err();
        assert!(err.contains("duplicate milestone_id"), "got: {err}");
        assert!(err.contains("ms-dup"), "got: {err}");
    }

    // ---- Holdback tests ----

    #[test]
    fn holdback_none_when_base_not_satisfied() {
        // Holdback is only computed when base is satisfied (Satisfied path).
        // When no proofs: Unsatisfied, holdback must be None.
        let agreement = sample_agreement();
        let sk = sample_signing_key();
        let pubkey_hex = hex::encode(sk.verifying_key().to_encoded_point(false).as_bytes());
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let hash = hex::encode(Sha256::digest(&bytes));
        let mut policy = make_test_policy(&hash, &pubkey_hex, "att");
        policy.holdback = Some(PolicyHoldback {
            holdback_bps: 2000,
            release_requirement_id: None,
            deadline_height: Some(500),
        });
        let result = evaluate_policy(&agreement, &policy, &[], 100).unwrap();
        assert_eq!(result.outcome, PolicyOutcome::Unsatisfied);
        assert!(
            result.holdback.is_none(),
            "holdback must be None when base not satisfied"
        );
    }

    #[test]
    fn holdback_held_when_base_satisfied_deadline_not_reached() {
        let agreement = sample_agreement();
        let sk = sample_signing_key();
        let pubkey_hex = hex::encode(sk.verifying_key().to_encoded_point(false).as_bytes());
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let hash = hex::encode(Sha256::digest(&bytes));
        let mut policy = make_test_policy(&hash, &pubkey_hex, "att");
        policy.holdback = Some(PolicyHoldback {
            holdback_bps: 1000,
            release_requirement_id: None,
            deadline_height: Some(1000), // deadline in the future
        });
        let proof = make_test_proof(&hash, "att", &sk);
        let result = evaluate_policy(&agreement, &policy, &[proof], 100).unwrap();
        assert_eq!(result.outcome, PolicyOutcome::Satisfied);
        let hb = result
            .holdback
            .expect("holdback must be present when base satisfied");
        assert!(hb.holdback_present);
        assert!(!hb.holdback_released);
        assert_eq!(hb.holdback_outcome, HoldbackOutcome::Held);
        assert_eq!(hb.holdback_bps, 1000);
        assert_eq!(hb.immediate_release_bps, 9000);
    }

    #[test]
    fn holdback_released_by_deadline() {
        let agreement = sample_agreement();
        let sk = sample_signing_key();
        let pubkey_hex = hex::encode(sk.verifying_key().to_encoded_point(false).as_bytes());
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let hash = hex::encode(Sha256::digest(&bytes));
        let mut policy = make_test_policy(&hash, &pubkey_hex, "att");
        policy.holdback = Some(PolicyHoldback {
            holdback_bps: 500,
            release_requirement_id: None,
            deadline_height: Some(200),
        });
        let proof = make_test_proof(&hash, "att", &sk);
        // tip_height >= 200 → deadline fires.
        let result = evaluate_policy(&agreement, &policy, &[proof], 200).unwrap();
        assert_eq!(result.outcome, PolicyOutcome::Satisfied);
        let hb = result.holdback.expect("holdback must be present");
        assert!(hb.holdback_released);
        assert_eq!(hb.holdback_outcome, HoldbackOutcome::Released);
        assert_eq!(hb.immediate_release_bps, 10000);
        assert!(
            hb.holdback_reason.contains("deadline"),
            "got: {}",
            hb.holdback_reason
        );
    }

    #[test]
    fn holdback_released_by_proof() {
        let agreement = sample_agreement();
        let sk = sample_signing_key();
        let pubkey_hex = hex::encode(sk.verifying_key().to_encoded_point(false).as_bytes());
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let hash = hex::encode(Sha256::digest(&bytes));
        // req-001 is both the base requirement and the holdback release requirement.
        // When the proof satisfies req-001, holdback is also released immediately.
        let mut policy = make_test_policy(&hash, &pubkey_hex, "att");
        policy.holdback = Some(PolicyHoldback {
            holdback_bps: 3000,
            release_requirement_id: Some("req-001".to_string()),
            deadline_height: Some(9999),
        });
        let proof = make_test_proof(&hash, "att", &sk);
        let result = evaluate_policy(&agreement, &policy, &[proof], 100).unwrap();
        assert_eq!(result.outcome, PolicyOutcome::Satisfied);
        let hb = result.holdback.expect("holdback must be present");
        assert!(hb.holdback_released);
        assert_eq!(hb.holdback_outcome, HoldbackOutcome::Released);
        assert_eq!(hb.immediate_release_bps, 10000);
        assert!(
            hb.holdback_reason.contains("req-001"),
            "got: {}",
            hb.holdback_reason
        );
    }

    #[test]
    fn holdback_absent_when_no_holdback_configured() {
        let agreement = sample_agreement();
        let sk = sample_signing_key();
        let pubkey_hex = hex::encode(sk.verifying_key().to_encoded_point(false).as_bytes());
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let hash = hex::encode(Sha256::digest(&bytes));
        let policy = make_test_policy(&hash, &pubkey_hex, "att");
        let proof = make_test_proof(&hash, "att", &sk);
        let result = evaluate_policy(&agreement, &policy, &[proof], 100).unwrap();
        assert_eq!(result.outcome, PolicyOutcome::Satisfied);
        assert!(
            result.holdback.is_none(),
            "holdback field must be None when not configured"
        );
    }

    #[test]
    fn store_policy_rejects_invalid_holdback_bps() {
        let mut store = make_policy_store();
        let sk = sample_signing_key();
        let pubkey_hex = hex::encode(sk.verifying_key().to_encoded_point(false).as_bytes());
        let agreement = sample_agreement();
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let hash = hex::encode(Sha256::digest(&bytes));
        let mut policy = make_test_policy(&hash, &pubkey_hex, "att");
        policy.holdback = Some(PolicyHoldback {
            holdback_bps: 0,
            release_requirement_id: None,
            deadline_height: Some(100),
        });
        let err = store.store(policy, false).unwrap_err();
        assert!(err.contains("holdback_bps"), "got: {err}");
    }

    #[test]
    fn store_policy_rejects_holdback_with_no_release_condition() {
        let mut store = make_policy_store();
        let sk = sample_signing_key();
        let pubkey_hex = hex::encode(sk.verifying_key().to_encoded_point(false).as_bytes());
        let agreement = sample_agreement();
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let hash = hex::encode(Sha256::digest(&bytes));
        let mut policy = make_test_policy(&hash, &pubkey_hex, "att");
        policy.holdback = Some(PolicyHoldback {
            holdback_bps: 1000,
            release_requirement_id: None,
            deadline_height: None,
        });
        let err = store.store(policy, false).unwrap_err();
        assert!(err.contains("release condition"), "got: {err}");
    }

    #[test]
    fn store_policy_rejects_holdback_with_unknown_req_id() {
        let mut store = make_policy_store();
        let sk = sample_signing_key();
        let pubkey_hex = hex::encode(sk.verifying_key().to_encoded_point(false).as_bytes());
        let agreement = sample_agreement();
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let hash = hex::encode(Sha256::digest(&bytes));
        let mut policy = make_test_policy(&hash, &pubkey_hex, "att");
        policy.holdback = Some(PolicyHoldback {
            holdback_bps: 500,
            release_requirement_id: Some("no-such-req".to_string()),
            deadline_height: None,
        });
        let err = store.store(policy, false).unwrap_err();
        assert!(err.contains("no-such-req"), "got: {err}");
    }

    // ---- Threshold / multi-attestor tests ----

    fn make_threshold_policy(
        hash: &str,
        pubkey_hex_a: &str,
        pubkey_hex_b: &str,
        threshold: u32,
    ) -> ProofPolicy {
        ProofPolicy {
            policy_id: "pol-thr".to_string(),
            schema_id: PROOF_POLICY_SCHEMA_ID.to_string(),
            agreement_hash: hash.to_string(),
            required_proofs: vec![ProofRequirement {
                requirement_id: "req-thr".to_string(),
                proof_type: "delivery_confirmation".to_string(),
                required_by: None,
                required_attestor_ids: vec!["att-a".to_string(), "att-b".to_string()],
                resolution: ProofResolution::Release,
                milestone_id: None,
                threshold: Some(threshold),
            }],
            no_response_rules: vec![],
            attestors: vec![
                ApprovedAttestor {
                    attestor_id: "att-a".to_string(),
                    pubkey_hex: pubkey_hex_a.to_string(),
                    display_name: None,
                    domain: None,
                },
                ApprovedAttestor {
                    attestor_id: "att-b".to_string(),
                    pubkey_hex: pubkey_hex_b.to_string(),
                    display_name: None,
                    domain: None,
                },
            ],
            notes: None,
            expires_at_height: None,
            milestones: vec![],
            holdback: None,
        }
    }

    fn make_threshold_proof(
        hash: &str,
        attestor_id: &str,
        signing_key: &SigningKey,
        proof_id: &str,
    ) -> SettlementProof {
        let pubkey_hex = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let mut proof = SettlementProof {
            proof_id: proof_id.to_string(),
            schema_id: SETTLEMENT_PROOF_SCHEMA_ID.to_string(),
            proof_type: "delivery_confirmation".to_string(),
            agreement_hash: hash.to_string(),
            milestone_id: None,
            attested_by: attestor_id.to_string(),
            attestation_time: 0,
            evidence_hash: None,
            evidence_summary: None,
            signature: ProofSignatureEnvelope {
                signature_type: AGREEMENT_SIGNATURE_TYPE_SECP256K1.to_string(),
                pubkey_hex: pubkey_hex.clone(),
                signature_hex: String::new(),
                payload_hash: String::new(),
            },
            expires_at_height: None,
            typed_payload: None,
        };
        proof.signature = sign_proof(&proof, signing_key);
        proof
    }

    #[test]
    fn threshold_single_attestor_backward_compat() {
        // Policy with no threshold field: single valid proof satisfies release.
        let agreement = sample_agreement();
        let sk = sample_signing_key();
        let pubkey_hex = hex::encode(sk.verifying_key().to_encoded_point(false).as_bytes());
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let hash = hex::encode(Sha256::digest(&bytes));
        let policy = make_test_policy(&hash, &pubkey_hex, "att");
        let proof = make_test_proof(&hash, "att", &sk);
        let result = evaluate_policy(&agreement, &policy, &[proof], 0).unwrap();
        assert_eq!(result.outcome, PolicyOutcome::Satisfied);
        assert!(
            result.threshold_results.is_empty(),
            "no threshold configured -> empty"
        );
    }

    #[test]
    fn threshold_single_attestor_no_threshold_field() {
        // Requirement with threshold: None uses single-attestor logic.
        let agreement = sample_agreement();
        let sk = sample_signing_key();
        let pubkey_hex = hex::encode(sk.verifying_key().to_encoded_point(false).as_bytes());
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let hash = hex::encode(Sha256::digest(&bytes));
        let policy = make_test_policy(&hash, &pubkey_hex, "att");
        assert!(policy.required_proofs[0].threshold.is_none());
        let proof = make_test_proof(&hash, "att", &sk);
        let result = evaluate_policy(&agreement, &policy, &[proof], 0).unwrap();
        assert_eq!(result.outcome, PolicyOutcome::Satisfied);
    }

    #[test]
    fn threshold_2_of_2_both_satisfied() {
        // Both approved attestors submit proofs → threshold 2 met.
        let agreement = sample_agreement();
        let sk_a = SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
        let sk_b = SigningKey::from_bytes((&[2u8; 32]).into()).unwrap();
        let pk_a = hex::encode(sk_a.verifying_key().to_encoded_point(false).as_bytes());
        let pk_b = hex::encode(sk_b.verifying_key().to_encoded_point(false).as_bytes());
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let hash = hex::encode(Sha256::digest(&bytes));
        let policy = make_threshold_policy(&hash, &pk_a, &pk_b, 2);
        let proof_a = make_threshold_proof(&hash, "att-a", &sk_a, "prf-a");
        let proof_b = make_threshold_proof(&hash, "att-b", &sk_b, "prf-b");
        let result = evaluate_policy(&agreement, &policy, &[proof_a, proof_b], 0).unwrap();
        assert_eq!(result.outcome, PolicyOutcome::Satisfied);
        assert!(result.release_eligible);
        assert_eq!(result.threshold_results.len(), 1);
        let thr = &result.threshold_results[0];
        assert_eq!(thr.requirement_id, "req-thr");
        assert_eq!(thr.threshold_required, 2);
        assert_eq!(thr.approved_attestor_count, 2);
        assert!(thr.threshold_satisfied);
        assert!(thr.matched_attestor_ids.contains(&"att-a".to_string()));
        assert!(thr.matched_attestor_ids.contains(&"att-b".to_string()));
    }

    #[test]
    fn threshold_2_of_2_only_one_attestor() {
        // Only one attestor submitted → threshold 2 not met.
        let agreement = sample_agreement();
        let sk_a = SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
        let sk_b = SigningKey::from_bytes((&[2u8; 32]).into()).unwrap();
        let pk_a = hex::encode(sk_a.verifying_key().to_encoded_point(false).as_bytes());
        let pk_b = hex::encode(sk_b.verifying_key().to_encoded_point(false).as_bytes());
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let hash = hex::encode(Sha256::digest(&bytes));
        let policy = make_threshold_policy(&hash, &pk_a, &pk_b, 2);
        let proof_a = make_threshold_proof(&hash, "att-a", &sk_a, "prf-a");
        let result = evaluate_policy(&agreement, &policy, &[proof_a], 0).unwrap();
        assert_eq!(result.outcome, PolicyOutcome::Unsatisfied);
        assert!(!result.release_eligible);
        assert_eq!(result.threshold_results.len(), 1);
        let thr = &result.threshold_results[0];
        assert_eq!(thr.threshold_required, 2);
        assert_eq!(thr.approved_attestor_count, 1);
        assert!(!thr.threshold_satisfied);
    }

    #[test]
    fn threshold_unapproved_attestor_does_not_count() {
        // Proof from an attestor not in required_attestor_ids must not contribute.
        let agreement = sample_agreement();
        let sk_a = SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
        let sk_bad = SigningKey::from_bytes((&[9u8; 32]).into()).unwrap();
        let pk_a = hex::encode(sk_a.verifying_key().to_encoded_point(false).as_bytes());
        let pk_b_dummy = hex::encode(sk_a.verifying_key().to_encoded_point(false).as_bytes());
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let hash = hex::encode(Sha256::digest(&bytes));
        let policy = make_threshold_policy(&hash, &pk_a, &pk_b_dummy, 2);
        let proof_a = make_threshold_proof(&hash, "att-a", &sk_a, "prf-a");
        // "att-bad" is NOT in required_attestor_ids (only att-a and att-b are)
        // However verify_settlement_proof checks against policy.attestors.
        // Proof from att-bad will fail signature verification (wrong pubkey).
        // Let's use att-a's key but claim att-b to simulate unapproved scenario:
        // Actually, build a proof claiming attested_by = "att-bad" which is not
        // in the policy attestors list — it will fail verification in evaluate_policy
        // step 1, so won't appear in `satisfied`.
        let mut proof_bad = make_threshold_proof(&hash, "att-bad", &sk_bad, "prf-bad");
        // Tweak: even if we add att-bad to attestors, it's not in required_attestor_ids
        // For the threshold check, what matters is required_attestor_ids.contains(&p.attested_by)
        // So even if signature verifies, att-bad won't count toward "req-thr".
        // Force att-bad into policy attestors (bypass store) to test just the threshold filter:
        let mut policy2 = policy.clone();
        policy2.attestors.push(ApprovedAttestor {
            attestor_id: "att-bad".to_string(),
            pubkey_hex: hex::encode(sk_bad.verifying_key().to_encoded_point(false).as_bytes()),
            display_name: None,
            domain: None,
        });
        // Re-sign with the correct key (sk_bad signs as att-bad)
        proof_bad.signature = sign_proof(&proof_bad, &sk_bad);
        let result = evaluate_policy(&agreement, &policy2, &[proof_a, proof_bad], 0).unwrap();
        // att-bad verified OK but NOT in required_attestor_ids → does not count toward threshold
        assert_eq!(result.outcome, PolicyOutcome::Unsatisfied);
        let thr = &result.threshold_results[0];
        assert_eq!(
            thr.approved_attestor_count, 1,
            "only att-a counted, att-bad excluded"
        );
        assert!(!thr.threshold_satisfied);
    }

    #[test]
    fn threshold_duplicate_proofs_from_same_attestor_count_as_one() {
        // Two proofs from the same attestor must only count as 1 distinct attestor.
        let agreement = sample_agreement();
        let sk_a = SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
        let sk_b = SigningKey::from_bytes((&[2u8; 32]).into()).unwrap();
        let pk_a = hex::encode(sk_a.verifying_key().to_encoded_point(false).as_bytes());
        let pk_b = hex::encode(sk_b.verifying_key().to_encoded_point(false).as_bytes());
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let hash = hex::encode(Sha256::digest(&bytes));
        let policy = make_threshold_policy(&hash, &pk_a, &pk_b, 2);
        // Two proofs from att-a with different proof_ids
        let mut proof_a2 = make_threshold_proof(&hash, "att-a", &sk_a, "prf-a2");
        proof_a2.proof_id = "prf-a-dup".to_string();
        proof_a2.signature = sign_proof(&proof_a2, &sk_a);
        let proof_a = make_threshold_proof(&hash, "att-a", &sk_a, "prf-a");
        let result = evaluate_policy(&agreement, &policy, &[proof_a, proof_a2], 0).unwrap();
        assert_eq!(result.outcome, PolicyOutcome::Unsatisfied);
        let thr = &result.threshold_results[0];
        assert_eq!(
            thr.approved_attestor_count, 1,
            "two proofs same attestor = 1 distinct"
        );
        assert!(!thr.threshold_satisfied);
    }

    #[test]
    fn threshold_milestone_interaction() {
        // Threshold on a milestone-scoped requirement.
        let agreement = sample_agreement();
        let sk_a = SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
        let sk_b = SigningKey::from_bytes((&[2u8; 32]).into()).unwrap();
        let pk_a = hex::encode(sk_a.verifying_key().to_encoded_point(false).as_bytes());
        let pk_b = hex::encode(sk_b.verifying_key().to_encoded_point(false).as_bytes());
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let hash = hex::encode(Sha256::digest(&bytes));
        let policy = ProofPolicy {
            policy_id: "pol-ms-thr".to_string(),
            schema_id: PROOF_POLICY_SCHEMA_ID.to_string(),
            agreement_hash: hash.clone(),
            required_proofs: vec![ProofRequirement {
                requirement_id: "req-ms-thr".to_string(),
                proof_type: "ms_delivery".to_string(),
                required_by: None,
                required_attestor_ids: vec!["att-a".to_string(), "att-b".to_string()],
                resolution: ProofResolution::MilestoneRelease,
                milestone_id: Some("ms-1".to_string()),
                threshold: Some(2),
            }],
            no_response_rules: vec![],
            attestors: vec![
                ApprovedAttestor {
                    attestor_id: "att-a".to_string(),
                    pubkey_hex: pk_a.clone(),
                    display_name: None,
                    domain: None,
                },
                ApprovedAttestor {
                    attestor_id: "att-b".to_string(),
                    pubkey_hex: pk_b.clone(),
                    display_name: None,
                    domain: None,
                },
            ],
            notes: None,
            expires_at_height: None,
            milestones: vec![PolicyMilestone {
                milestone_id: "ms-1".to_string(),
                label: None,
                holdback: None,
            }],
            holdback: None,
        };
        // One attestor: milestone unsatisfied.
        let mut prf_a = SettlementProof {
            proof_id: "prf-ms-a".to_string(),
            schema_id: SETTLEMENT_PROOF_SCHEMA_ID.to_string(),
            proof_type: "ms_delivery".to_string(),
            agreement_hash: hash.clone(),
            milestone_id: Some("ms-1".to_string()),
            attested_by: "att-a".to_string(),
            attestation_time: 0,
            evidence_hash: None,
            evidence_summary: None,
            signature: ProofSignatureEnvelope {
                signature_type: AGREEMENT_SIGNATURE_TYPE_SECP256K1.to_string(),
                pubkey_hex: pk_a.clone(),
                signature_hex: String::new(),
                payload_hash: String::new(),
            },
            expires_at_height: None,
            typed_payload: None,
        };
        prf_a.signature = sign_proof(&prf_a, &sk_a);
        let result1 = evaluate_policy(&agreement, &policy, &[prf_a.clone()], 0).unwrap();
        assert_eq!(result1.outcome, PolicyOutcome::Unsatisfied);
        assert_eq!(result1.milestone_results.len(), 1);
        let ms_thr = &result1.milestone_results[0].threshold_results;
        assert_eq!(ms_thr.len(), 1);
        assert_eq!(ms_thr[0].approved_attestor_count, 1);
        assert!(!ms_thr[0].threshold_satisfied);
        // Two attestors: milestone satisfied.
        let mut prf_b = SettlementProof {
            proof_id: "prf-ms-b".to_string(),
            schema_id: SETTLEMENT_PROOF_SCHEMA_ID.to_string(),
            proof_type: "ms_delivery".to_string(),
            agreement_hash: hash.clone(),
            milestone_id: Some("ms-1".to_string()),
            attested_by: "att-b".to_string(),
            attestation_time: 0,
            evidence_hash: None,
            evidence_summary: None,
            signature: ProofSignatureEnvelope {
                signature_type: AGREEMENT_SIGNATURE_TYPE_SECP256K1.to_string(),
                pubkey_hex: pk_b.clone(),
                signature_hex: String::new(),
                payload_hash: String::new(),
            },
            expires_at_height: None,
            typed_payload: None,
        };
        prf_b.signature = sign_proof(&prf_b, &sk_b);
        let result2 = evaluate_policy(&agreement, &policy, &[prf_a, prf_b], 0).unwrap();
        assert_eq!(result2.outcome, PolicyOutcome::Satisfied);
        let ms_thr2 = &result2.milestone_results[0].threshold_results;
        assert_eq!(ms_thr2[0].approved_attestor_count, 2);
        assert!(ms_thr2[0].threshold_satisfied);
    }

    #[test]
    fn threshold_holdback_release_with_approved_proof() {
        // Holdback release_requirement_id satisfied by an approved attestor.
        let agreement = sample_agreement();
        let sk_a = SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
        let sk_b = SigningKey::from_bytes((&[2u8; 32]).into()).unwrap();
        let pk_a = hex::encode(sk_a.verifying_key().to_encoded_point(false).as_bytes());
        let pk_b = hex::encode(sk_b.verifying_key().to_encoded_point(false).as_bytes());
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let hash = hex::encode(Sha256::digest(&bytes));
        // Base requirement: threshold 2. Holdback: released by req-base itself.
        let mut policy = make_threshold_policy(&hash, &pk_a, &pk_b, 2);
        policy.holdback = Some(PolicyHoldback {
            holdback_bps: 1000,
            release_requirement_id: Some("req-thr".to_string()),
            deadline_height: Some(9999),
        });
        let proof_a = make_threshold_proof(&hash, "att-a", &sk_a, "prf-a");
        let proof_b = make_threshold_proof(&hash, "att-b", &sk_b, "prf-b");
        let result = evaluate_policy(&agreement, &policy, &[proof_a, proof_b], 0).unwrap();
        assert_eq!(result.outcome, PolicyOutcome::Satisfied);
        let hb = result.holdback.expect("holdback present");
        // Both attestors satisfied threshold => holdback release req is also met.
        assert!(hb.holdback_released);
    }

    #[test]
    fn store_policy_rejects_threshold_zero() {
        let mut store = make_policy_store();
        let sk = sample_signing_key();
        let pubkey_hex = hex::encode(sk.verifying_key().to_encoded_point(false).as_bytes());
        let agreement = sample_agreement();
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let hash = hex::encode(Sha256::digest(&bytes));
        let mut policy = make_test_policy(&hash, &pubkey_hex, "att");
        policy.required_proofs[0].threshold = Some(0);
        let err = store.store(policy, false).unwrap_err();
        assert!(err.contains("threshold must be >= 1"), "got: {err}");
    }

    #[test]
    fn store_policy_rejects_threshold_exceeds_attestor_count() {
        let mut store = make_policy_store();
        let sk = sample_signing_key();
        let pubkey_hex = hex::encode(sk.verifying_key().to_encoded_point(false).as_bytes());
        let agreement = sample_agreement();
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let hash = hex::encode(Sha256::digest(&bytes));
        let mut policy = make_test_policy(&hash, &pubkey_hex, "att");
        // required_attestor_ids has 1 entry, threshold=2 is invalid
        policy.required_proofs[0].threshold = Some(2);
        let err = store.store(policy, false).unwrap_err();
        assert!(err.contains("threshold"), "got: {err}");
        assert!(err.contains("exceeds"), "got: {err}");
    }

    // ── Audit regression tests ───────────────────────────────────────────

    /// Bug1 (latent): evaluate_holdback must use req_satisfied_threshold for
    /// its release-requirement check, not a bare single-attestor .any().
    /// With threshold 2 and both attestors present, holdback must release.
    /// With threshold 2 and only one attestor, base is unsatisfied → Pending.
    #[test]
    fn audit_holdback_release_respects_threshold() {
        let agreement = sample_agreement();
        let sk_a = SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
        let sk_b = SigningKey::from_bytes((&[2u8; 32]).into()).unwrap();
        let pk_a = hex::encode(sk_a.verifying_key().to_encoded_point(false).as_bytes());
        let pk_b = hex::encode(sk_b.verifying_key().to_encoded_point(false).as_bytes());
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let hash = hex::encode(Sha256::digest(&bytes));
        let mut policy = make_threshold_policy(&hash, &pk_a, &pk_b, 2);
        policy.holdback = Some(PolicyHoldback {
            holdback_bps: 500,
            release_requirement_id: Some("req-thr".to_string()),
            deadline_height: Some(9999),
        });

        // Only att-a: base NOT satisfied (threshold 2 unmet) → holdback Pending.
        let proof_a = make_threshold_proof(&hash, "att-a", &sk_a, "prf-a");
        let r1 = evaluate_policy(&agreement, &policy, std::slice::from_ref(&proof_a), 0).unwrap();
        assert_eq!(r1.outcome, PolicyOutcome::Unsatisfied);
        // holdback is None when base is Unsatisfied: evaluate_holdback is only
        // called on the Satisfied path. Pending state is represented as None.
        assert!(
            r1.holdback.is_none(),
            "holdback not evaluated when base unsatisfied (represented as None)"
        );

        // Both att-a and att-b: base satisfied AND holdback release req met.
        let proof_b = make_threshold_proof(&hash, "att-b", &sk_b, "prf-b");
        let r2 = evaluate_policy(&agreement, &policy, &[proof_a, proof_b], 0).unwrap();
        assert_eq!(r2.outcome, PolicyOutcome::Satisfied);
        let hb2 = r2.holdback.expect("holdback field present");
        assert_eq!(
            hb2.holdback_outcome,
            HoldbackOutcome::Released,
            "threshold met → holdback Released"
        );
    }

    /// Bug2 (active): no-response-rule Timeout must populate threshold_results
    /// for requirements with explicit thresholds, consistent with Unsatisfied path.
    #[test]
    fn audit_timeout_noresp_populates_threshold_results() {
        let agreement = sample_agreement();
        let sk_a = SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
        let sk_b = SigningKey::from_bytes((&[2u8; 32]).into()).unwrap();
        let pk_a = hex::encode(sk_a.verifying_key().to_encoded_point(false).as_bytes());
        let pk_b = hex::encode(sk_b.verifying_key().to_encoded_point(false).as_bytes());
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let hash = hex::encode(Sha256::digest(&bytes));
        // Policy: threshold-2 release req + no_response_rule firing at height 50.
        let mut policy = make_threshold_policy(&hash, &pk_a, &pk_b, 2);
        policy.no_response_rules = vec![NoResponseRule {
            rule_id: "nr-001".to_string(),
            deadline_height: 50,
            trigger: NoResponseTrigger::FundedAndNoRelease,
            resolution: ProofResolution::Refund,
            milestone_id: None,
            notes: None,
        }];
        // att-a submits (1 of 2 needed) — threshold not yet met.
        let proof_a = make_threshold_proof(&hash, "att-a", &sk_a, "prf-a");
        let result = evaluate_policy(&agreement, &policy, &[proof_a], 50).unwrap();
        assert_eq!(result.outcome, PolicyOutcome::Timeout);
        assert!(!result.release_eligible);
        assert!(result.refund_eligible);
        // threshold_results must be populated even on Timeout.
        assert_eq!(
            result.threshold_results.len(),
            1,
            "Timeout with threshold req must populate threshold_results"
        );
        let thr = &result.threshold_results[0];
        assert_eq!(thr.requirement_id, "req-thr");
        assert_eq!(thr.threshold_required, 2);
        assert_eq!(thr.approved_attestor_count, 1);
        assert!(
            !thr.threshold_satisfied,
            "1 of 2 attestors → not satisfied at timeout"
        );
    }

    /// Bug2 (active): refund-deadline Timeout must populate threshold_results
    /// for requirements with explicit thresholds, consistent with Unsatisfied path.
    #[test]
    fn audit_timeout_refund_deadline_populates_threshold_results() {
        let agreement = sample_agreement();
        let sk_a = SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
        let sk_b = SigningKey::from_bytes((&[2u8; 32]).into()).unwrap();
        let pk_a = hex::encode(sk_a.verifying_key().to_encoded_point(false).as_bytes());
        let pk_b = hex::encode(sk_b.verifying_key().to_encoded_point(false).as_bytes());
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let hash = hex::encode(Sha256::digest(&bytes));
        // Policy: refund requirement with threshold 2 and deadline 100.
        let policy = ProofPolicy {
            policy_id: "pol-ref-thr".to_string(),
            schema_id: PROOF_POLICY_SCHEMA_ID.to_string(),
            agreement_hash: hash.clone(),
            required_proofs: vec![ProofRequirement {
                requirement_id: "req-refund-thr".to_string(),
                proof_type: "delivery_confirmation".to_string(),
                required_by: Some(100),
                required_attestor_ids: vec!["att-a".to_string(), "att-b".to_string()],
                resolution: ProofResolution::Refund,
                milestone_id: None,
                threshold: Some(2),
            }],
            no_response_rules: vec![],
            attestors: vec![
                ApprovedAttestor {
                    attestor_id: "att-a".to_string(),
                    pubkey_hex: pk_a,
                    display_name: None,
                    domain: None,
                },
                ApprovedAttestor {
                    attestor_id: "att-b".to_string(),
                    pubkey_hex: pk_b,
                    display_name: None,
                    domain: None,
                },
            ],
            notes: None,
            expires_at_height: None,
            milestones: vec![],
            holdback: None,
        };
        // att-a submits (1 of 2) — threshold not met at deadline.
        let proof_a = make_threshold_proof(&hash, "att-a", &sk_a, "prf-a");
        let result = evaluate_policy(&agreement, &policy, &[proof_a], 100).unwrap();
        assert_eq!(result.outcome, PolicyOutcome::Timeout);
        assert!(result.refund_eligible);
        // threshold_results must reflect partial attestor progress.
        assert_eq!(
            result.threshold_results.len(),
            1,
            "Timeout with threshold req must populate threshold_results"
        );
        let thr = &result.threshold_results[0];
        assert_eq!(thr.requirement_id, "req-refund-thr");
        assert_eq!(thr.threshold_required, 2);
        assert_eq!(thr.approved_attestor_count, 1);
        assert!(!thr.threshold_satisfied);
        // Confirm: at height 99 (before deadline), outcome is Unsatisfied and
        // threshold_results is also populated (consistency check).
        let proof_a2 = make_threshold_proof(&hash, "att-a", &sk_a, "prf-a");
        let result_pre = evaluate_policy(&agreement, &policy, &[proof_a2], 99).unwrap();
        assert_eq!(result_pre.outcome, PolicyOutcome::Unsatisfied);
        assert_eq!(
            result_pre.threshold_results.len(),
            1,
            "Unsatisfied with threshold req also populates threshold_results"
        );
    }

    // ---- Typed proof payload tests --------------------------------------

    #[test]
    fn typed_payload_none_is_backward_compat() {
        let agreement = sample_agreement();
        let sk = sample_signing_key();
        let pk = hex::encode(sk.verifying_key().to_encoded_point(false).as_bytes());
        let hash = hex::encode(Sha256::digest(
            agreement_canonical_bytes(&agreement).unwrap(),
        ));
        let policy = make_test_policy(&hash, &pk, "att");
        let proof = make_test_proof(&hash, "att", &sk);
        assert!(proof.typed_payload.is_none());
        let result = evaluate_policy(&agreement, &policy, &[proof], 0).unwrap();
        assert_eq!(result.outcome, PolicyOutcome::Satisfied);
    }

    #[test]
    fn typed_payload_stored_and_retrieved() {
        let mut store = make_proof_store();
        let sk = sample_signing_key();
        let pk = hex::encode(sk.verifying_key().to_encoded_point(false).as_bytes());
        let mut proof = SettlementProof {
            proof_id: "prf-typed-001".to_string(),
            schema_id: SETTLEMENT_PROOF_SCHEMA_ID.to_string(),
            proof_type: "delivery_confirmation".to_string(),
            agreement_hash: "aabbccdd".to_string(),
            milestone_id: None,
            attested_by: "att-typed".to_string(),
            attestation_time: 0,
            evidence_hash: None,
            evidence_summary: None,
            signature: ProofSignatureEnvelope {
                signature_type: AGREEMENT_SIGNATURE_TYPE_SECP256K1.to_string(),
                pubkey_hex: pk.clone(),
                signature_hex: String::new(),
                payload_hash: String::new(),
            },
            expires_at_height: None,
            typed_payload: Some(TypedProofPayload {
                proof_kind: "delivery_confirmation".to_string(),
                content_hash: None,
                reference_id: Some("TRK-12345".to_string()),
                attributes: Some(serde_json::json!({"carrier": "DHL"})),
            }),
        };
        proof.signature = sign_proof(&proof, &sk);
        let outcome = store.submit(proof).unwrap();
        assert!(outcome.accepted);
        let tp = store
            .get_by_id("prf-typed-001")
            .unwrap()
            .typed_payload
            .as_ref()
            .unwrap();
        assert_eq!(tp.proof_kind, "delivery_confirmation");
        assert_eq!(tp.reference_id.as_deref(), Some("TRK-12345"));
    }

    #[test]
    fn typed_payload_does_not_affect_signature_verification() {
        let sk = sample_signing_key();
        let pk = hex::encode(sk.verifying_key().to_encoded_point(false).as_bytes());
        let agreement = sample_agreement();
        let hash = hex::encode(Sha256::digest(
            agreement_canonical_bytes(&agreement).unwrap(),
        ));
        let policy = make_test_policy(&hash, &pk, "att");
        let mut proof = make_test_proof(&hash, "att", &sk);
        proof.typed_payload = Some(TypedProofPayload {
            proof_kind: "delivery_confirmation".to_string(),
            content_hash: None,
            reference_id: None,
            attributes: None,
        });
        verify_settlement_proof(&proof, &policy).expect("signature must still be valid");
    }

    #[test]
    fn typed_payload_empty_proof_kind_rejected() {
        let tp = TypedProofPayload {
            proof_kind: "  ".to_string(),
            content_hash: None,
            reference_id: None,
            attributes: None,
        };
        let err = validate_typed_proof_payload(&tp, None).unwrap_err();
        assert!(err.contains("proof_kind must not be empty"), "got: {err}");
    }

    #[test]
    fn typed_payload_invalid_content_hash_rejected() {
        let tp = TypedProofPayload {
            proof_kind: "x".to_string(),
            content_hash: Some("not-hex".to_string()),
            reference_id: None,
            attributes: None,
        };
        let err = validate_typed_proof_payload(&tp, None).unwrap_err();
        assert!(
            err.contains("content_hash must be 64 lowercase hex"),
            "got: {err}"
        );
    }

    #[test]
    fn typed_payload_content_hash_mismatch_rejected() {
        let ch = "a".repeat(64);
        let eh = "b".repeat(64);
        let tp = TypedProofPayload {
            proof_kind: "x".to_string(),
            content_hash: Some(ch),
            reference_id: None,
            attributes: None,
        };
        let err = validate_typed_proof_payload(&tp, Some(&eh)).unwrap_err();
        assert!(
            err.contains("does not match proof evidence_hash"),
            "got: {err}"
        );
    }

    #[test]
    fn typed_payload_content_hash_matching_evidence_hash_ok() {
        let h = "a".repeat(64);
        let tp = TypedProofPayload {
            proof_kind: "x".to_string(),
            content_hash: Some(h.clone()),
            reference_id: None,
            attributes: None,
        };
        validate_typed_proof_payload(&tp, Some(&h)).expect("matching hashes must be ok");
    }

    #[test]
    fn typed_payload_attributes_must_be_object() {
        let tp = TypedProofPayload {
            proof_kind: "x".to_string(),
            content_hash: None,
            reference_id: None,
            attributes: Some(serde_json::json!([1, 2, 3])),
        };
        let err = validate_typed_proof_payload(&tp, None).unwrap_err();
        assert!(err.contains("must be a JSON object"), "got: {err}");
    }

    #[test]
    fn typed_payload_submit_rejects_invalid_payload() {
        let mut store = make_proof_store();
        let sk = sample_signing_key();
        let pk = hex::encode(sk.verifying_key().to_encoded_point(false).as_bytes());
        let mut proof = SettlementProof {
            proof_id: "prf-bad-tp".to_string(),
            schema_id: SETTLEMENT_PROOF_SCHEMA_ID.to_string(),
            proof_type: "delivery_confirmation".to_string(),
            agreement_hash: "aabbccdd".to_string(),
            milestone_id: None,
            attested_by: "att-tp".to_string(),
            attestation_time: 1_700_000_001,
            evidence_hash: None,
            evidence_summary: None,
            signature: ProofSignatureEnvelope {
                signature_type: AGREEMENT_SIGNATURE_TYPE_SECP256K1.to_string(),
                pubkey_hex: pk.clone(),
                signature_hex: String::new(),
                payload_hash: String::new(),
            },
            expires_at_height: None,
            typed_payload: Some(TypedProofPayload {
                proof_kind: String::new(),
                content_hash: None,
                reference_id: None,
                attributes: None,
            }),
        };
        proof.signature = sign_proof(&proof, &sk);
        let err = store.submit(proof).unwrap_err();
        assert!(err.contains("proof_kind must not be empty"), "got: {err}");
    }

    #[test]
    fn typed_payload_policy_evaluation_unchanged() {
        let agreement = sample_agreement();
        let sk = sample_signing_key();
        let pk = hex::encode(sk.verifying_key().to_encoded_point(false).as_bytes());
        let hash = hex::encode(Sha256::digest(
            agreement_canonical_bytes(&agreement).unwrap(),
        ));
        let policy = make_test_policy(&hash, &pk, "att");
        let mut proof = make_test_proof(&hash, "att", &sk);
        proof.typed_payload = Some(TypedProofPayload {
            proof_kind: "delivery_confirmation".to_string(),
            content_hash: None,
            reference_id: Some("REF-001".to_string()),
            attributes: Some(serde_json::json!({"notes": "signed by receiver"})),
        });
        let result = evaluate_policy(&agreement, &policy, &[proof], 0).unwrap();
        assert_eq!(
            result.outcome,
            PolicyOutcome::Satisfied,
            "typed_payload must not interfere with policy evaluation"
        );
    }

    #[test]
    /// Regression guard: a proof whose typed_payload.proof_kind deliberately differs
    /// from proof_type must still satisfy a policy matching on proof_type.
    /// Fails immediately if proof_kind-based matching is accidentally added to
    /// req_satisfied_threshold or evaluate_policy.
    fn typed_payload_proof_kind_contradiction_does_not_affect_policy() {
        let agreement = sample_agreement();
        let sk = sample_signing_key();
        let pk = hex::encode(sk.verifying_key().to_encoded_point(false).as_bytes());
        let hash = hex::encode(Sha256::digest(
            agreement_canonical_bytes(&agreement).unwrap(),
        ));
        let policy = make_test_policy(&hash, &pk, "att");
        let mut proof = make_test_proof(&hash, "att", &sk);
        // typed_payload.proof_kind deliberately contradicts signed proof_type.
        // Policy evaluation must use the signed proof_type, not this unsigned field.
        proof.typed_payload = Some(TypedProofPayload {
            proof_kind: "completely_unrelated_category".to_string(),
            content_hash: None,
            reference_id: None,
            attributes: None,
        });
        let result = evaluate_policy(&agreement, &policy, &[proof], 0).unwrap();
        assert_eq!(
            result.outcome, PolicyOutcome::Satisfied,
            "proof_kind contradiction must not change policy outcome; only signed proof_type counts"
        );
    }

    // ---- Commercial Policy Template Tests ----

    fn test_attestor_tmpl(id: &str, pk: &str) -> TemplateAttestor {
        TemplateAttestor {
            attestor_id: id.to_string(),
            pubkey_hex: pk.to_string(),
            display_name: None,
        }
    }

    fn dummy_hash_64() -> String {
        "a".repeat(64)
    }

    fn ms_spec(
        id: &str,
        pt: &str,
        dl: Option<u64>,
        hb: Option<u32>,
        hb_ht: Option<u64>,
    ) -> MilestoneSpec {
        MilestoneSpec {
            milestone_id: id.to_string(),
            label: None,
            proof_type: pt.to_string(),
            deadline_height: dl,
            holdback_bps: hb,
            holdback_release_height: hb_ht,
        }
    }

    #[test]
    fn contractor_template_valid_two_milestones() {
        let policy = contractor_milestone_template(
            "pol-c1",
            &dummy_hash_64(),
            &[test_attestor_tmpl("att", "pk")],
            &[
                ms_spec("ms-1", "completion", Some(1000), None, None),
                ms_spec("ms-2", "delivery", Some(2000), Some(500), Some(2500)),
            ],
            None,
        )
        .unwrap();
        assert_eq!(policy.schema_id, PROOF_POLICY_SCHEMA_ID);
        assert_eq!(policy.milestones.len(), 2);
        assert_eq!(policy.required_proofs.len(), 2);
        assert_eq!(policy.no_response_rules.len(), 2);
        assert_eq!(
            policy
                .milestones
                .iter()
                .find(|m| m.milestone_id == "ms-2")
                .unwrap()
                .holdback
                .as_ref()
                .unwrap()
                .holdback_bps,
            500
        );
        assert!(policy
            .milestones
            .iter()
            .find(|m| m.milestone_id == "ms-1")
            .unwrap()
            .holdback
            .is_none());
    }

    #[test]
    fn contractor_template_no_deadline_no_rule() {
        let policy = contractor_milestone_template(
            "p",
            &dummy_hash_64(),
            &[test_attestor_tmpl("a", "pk")],
            &[ms_spec("ms-nodl", "t", None, None, None)],
            None,
        )
        .unwrap();
        assert!(policy.no_response_rules.is_empty());
    }

    #[test]
    fn contractor_template_rejects_empty_attestors() {
        let err = contractor_milestone_template(
            "p",
            &dummy_hash_64(),
            &[],
            &[ms_spec("m", "t", None, None, None)],
            None,
        )
        .unwrap_err();
        assert!(err.contains("attestors must not be empty"), "got: {err}");
    }

    #[test]
    fn contractor_template_rejects_empty_milestones() {
        let err = contractor_milestone_template(
            "p",
            &dummy_hash_64(),
            &[test_attestor_tmpl("a", "pk")],
            &[],
            None,
        )
        .unwrap_err();
        assert!(err.contains("milestones must not be empty"), "got: {err}");
    }

    #[test]
    fn contractor_template_rejects_duplicate_milestone_ids() {
        let err = contractor_milestone_template(
            "p",
            &dummy_hash_64(),
            &[test_attestor_tmpl("a", "pk")],
            &[
                ms_spec("ms-x", "t", None, None, None),
                ms_spec("ms-x", "t", None, None, None),
            ],
            None,
        )
        .unwrap_err();
        assert!(err.contains("duplicate milestone_id"), "got: {err}");
    }

    #[test]
    fn contractor_template_rejects_holdback_without_release_height() {
        let err = contractor_milestone_template(
            "p",
            &dummy_hash_64(),
            &[test_attestor_tmpl("a", "pk")],
            &[ms_spec("ms-1", "t", None, Some(300), None)],
            None,
        )
        .unwrap_err();
        assert!(err.contains("holdback_release_height"), "got: {err}");
    }

    #[test]
    fn contractor_template_rejects_holdback_bps_out_of_range() {
        let err = contractor_milestone_template(
            "p",
            &dummy_hash_64(),
            &[test_attestor_tmpl("a", "pk")],
            &[ms_spec("ms-1", "t", None, Some(10000), Some(999))],
            None,
        )
        .unwrap_err();
        assert!(err.contains("out of range"), "got: {err}");
    }

    #[test]
    fn preorder_template_basic() {
        let policy = preorder_deposit_template(
            "pol-pre",
            &dummy_hash_64(),
            &[test_attestor_tmpl("att", "pk")],
            "delivery_confirmation",
            5000,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            policy.required_proofs[0].proof_type,
            "delivery_confirmation"
        );
        assert_eq!(
            policy.required_proofs[0].resolution,
            ProofResolution::Release
        );
        assert_eq!(policy.no_response_rules[0].deadline_height, 5000);
        assert_eq!(
            policy.no_response_rules[0].resolution,
            ProofResolution::Refund
        );
        assert!(policy.holdback.is_none());
        assert!(policy.milestones.is_empty());
    }

    #[test]
    fn preorder_template_with_holdback() {
        let policy = preorder_deposit_template(
            "pol-pre-hb",
            &dummy_hash_64(),
            &[test_attestor_tmpl("att", "pk")],
            "delivery_confirmation",
            5000,
            Some(1000),
            Some(6000),
            None,
        )
        .unwrap();
        let hb = policy.holdback.as_ref().unwrap();
        assert_eq!(hb.holdback_bps, 1000);
        assert_eq!(hb.deadline_height, Some(6000));
        assert!(hb.release_requirement_id.is_none());
    }

    #[test]
    fn preorder_template_rejects_empty_attestors() {
        let err = preorder_deposit_template("p", &dummy_hash_64(), &[], "t", 100, None, None, None)
            .unwrap_err();
        assert!(err.contains("attestors must not be empty"), "got: {err}");
    }

    #[test]
    fn preorder_template_rejects_holdback_without_release_height() {
        let err = preorder_deposit_template(
            "p",
            &dummy_hash_64(),
            &[test_attestor_tmpl("a", "pk")],
            "t",
            100,
            Some(500),
            None,
            None,
        )
        .unwrap_err();
        assert!(err.contains("holdback_release_height"), "got: {err}");
    }

    #[test]
    fn preorder_template_rejects_holdback_bps_out_of_range() {
        let err = preorder_deposit_template(
            "p",
            &dummy_hash_64(),
            &[test_attestor_tmpl("a", "pk")],
            "t",
            100,
            Some(0),
            Some(200),
            None,
        )
        .unwrap_err();
        assert!(err.contains("out of range"), "got: {err}");
    }

    #[test]
    fn otc_template_single_attestor() {
        let policy = basic_otc_escrow_template(
            "pol-otc",
            &dummy_hash_64(),
            &[test_attestor_tmpl("agent", "pk")],
            "trade_settlement",
            10000,
            None,
            None,
        )
        .unwrap();
        assert!(policy.required_proofs[0].threshold.is_none());
        assert_eq!(
            policy.required_proofs[0].resolution,
            ProofResolution::Release
        );
        assert_eq!(
            policy.no_response_rules[0].resolution,
            ProofResolution::Refund
        );
    }

    #[test]
    fn otc_template_multi_attestor_threshold() {
        let policy = basic_otc_escrow_template(
            "pol-otc-2of3",
            &dummy_hash_64(),
            &[
                test_attestor_tmpl("a1", "pk1"),
                test_attestor_tmpl("a2", "pk2"),
                test_attestor_tmpl("a3", "pk3"),
            ],
            "trade_settlement",
            10000,
            Some(2),
            None,
        )
        .unwrap();
        assert_eq!(policy.required_proofs[0].threshold, Some(2));
        assert_eq!(policy.required_proofs[0].required_attestor_ids.len(), 3);
    }

    #[test]
    fn otc_template_threshold_1_does_not_set_field() {
        let policy = basic_otc_escrow_template(
            "p",
            &dummy_hash_64(),
            &[test_attestor_tmpl("a", "pk")],
            "t",
            100,
            Some(1),
            None,
        )
        .unwrap();
        assert!(
            policy.required_proofs[0].threshold.is_none(),
            "threshold=1 must not set the threshold field (backward compat)"
        );
    }

    #[test]
    fn otc_template_rejects_threshold_exceeds_attestors() {
        let err = basic_otc_escrow_template(
            "p",
            &dummy_hash_64(),
            &[
                test_attestor_tmpl("a1", "pk1"),
                test_attestor_tmpl("a2", "pk2"),
            ],
            "t",
            100,
            Some(3),
            None,
        )
        .unwrap_err();
        assert!(
            err.contains("threshold 3 exceeds attestor count"),
            "got: {err}"
        );
    }

    #[test]
    fn otc_template_rejects_empty_attestors() {
        let err = basic_otc_escrow_template("p", &dummy_hash_64(), &[], "t", 100, None, None)
            .unwrap_err();
        assert!(err.contains("attestors must not be empty"), "got: {err}");
    }

    #[test]
    fn preorder_evaluates_satisfied_when_proof_present() {
        let sk = sample_signing_key();
        let pk = hex::encode(sk.verifying_key().to_encoded_point(false).as_bytes());
        let agreement = sample_agreement();
        let hash = hex::encode(Sha256::digest(
            agreement_canonical_bytes(&agreement).unwrap(),
        ));
        let policy = preorder_deposit_template(
            "pol-eval-pre",
            &hash,
            &[TemplateAttestor {
                attestor_id: "att".to_string(),
                pubkey_hex: pk.clone(),
                display_name: None,
            }],
            "delivery_confirmation",
            9999,
            None,
            None,
            None,
        )
        .unwrap();
        let mut proof = SettlementProof {
            proof_id: "prf-pre-001".to_string(),
            schema_id: SETTLEMENT_PROOF_SCHEMA_ID.to_string(),
            proof_type: "delivery_confirmation".to_string(),
            agreement_hash: hash.clone(),
            milestone_id: None,
            attested_by: "att".to_string(),
            attestation_time: 0,
            evidence_hash: None,
            evidence_summary: None,
            signature: ProofSignatureEnvelope {
                signature_type: AGREEMENT_SIGNATURE_TYPE_SECP256K1.to_string(),
                pubkey_hex: pk.clone(),
                signature_hex: String::new(),
                payload_hash: String::new(),
            },
            expires_at_height: None,
            typed_payload: None,
        };
        proof.signature = sign_proof(&proof, &sk);
        let result = evaluate_policy(&agreement, &policy, &[proof], 0).unwrap();
        assert_eq!(result.outcome, PolicyOutcome::Satisfied);
        assert!(result.release_eligible);
        assert!(!result.refund_eligible);
    }

    #[test]
    fn preorder_evaluates_timeout_when_deadline_passed_no_proof() {
        let agreement = sample_agreement();
        let hash = hex::encode(Sha256::digest(
            agreement_canonical_bytes(&agreement).unwrap(),
        ));
        let policy = preorder_deposit_template(
            "pol-eval-timeout",
            &hash,
            &[TemplateAttestor {
                attestor_id: "att".to_string(),
                pubkey_hex: "pk-dummy".to_string(),
                display_name: None,
            }],
            "delivery_confirmation",
            100,
            None,
            None,
            None,
        )
        .unwrap();
        let result = evaluate_policy(&agreement, &policy, &[], 200).unwrap();
        assert_eq!(result.outcome, PolicyOutcome::Timeout);
        assert!(!result.release_eligible);
        assert!(result.refund_eligible);
    }

    #[test]
    fn contractor_milestone_evaluates_partial_completion() {
        let sk = sample_signing_key();
        let pk = hex::encode(sk.verifying_key().to_encoded_point(false).as_bytes());
        let agreement = sample_agreement();
        let hash = hex::encode(Sha256::digest(
            agreement_canonical_bytes(&agreement).unwrap(),
        ));
        let policy = contractor_milestone_template(
            "pol-c-eval",
            &hash,
            &[TemplateAttestor {
                attestor_id: "att".to_string(),
                pubkey_hex: pk.clone(),
                display_name: None,
            }],
            &[
                ms_spec("ms-1", "milestone_completion", Some(5000), None, None),
                ms_spec("ms-2", "delivery_confirmation", Some(8000), None, None),
            ],
            None,
        )
        .unwrap();
        let mut proof = SettlementProof {
            proof_id: "prf-ms1".to_string(),
            schema_id: SETTLEMENT_PROOF_SCHEMA_ID.to_string(),
            proof_type: "milestone_completion".to_string(),
            agreement_hash: hash.clone(),
            milestone_id: None,
            attested_by: "att".to_string(),
            attestation_time: 0,
            evidence_hash: None,
            evidence_summary: None,
            signature: ProofSignatureEnvelope {
                signature_type: AGREEMENT_SIGNATURE_TYPE_SECP256K1.to_string(),
                pubkey_hex: pk.clone(),
                signature_hex: String::new(),
                payload_hash: String::new(),
            },
            expires_at_height: None,
            typed_payload: None,
        };
        proof.signature = sign_proof(&proof, &sk);
        let result = evaluate_policy(&agreement, &policy, &[proof], 0).unwrap();
        assert_eq!(result.outcome, PolicyOutcome::Unsatisfied);
        assert_eq!(result.milestone_results.len(), 2);
        assert_eq!(
            result
                .milestone_results
                .iter()
                .find(|m| m.milestone_id == "ms-1")
                .unwrap()
                .outcome,
            PolicyOutcome::Satisfied
        );
        assert_eq!(
            result
                .milestone_results
                .iter()
                .find(|m| m.milestone_id == "ms-2")
                .unwrap()
                .outcome,
            PolicyOutcome::Unsatisfied
        );
    }

    #[test]
    fn otc_escrow_threshold_evaluates_correctly() {
        let sk1 = SigningKey::from_bytes((&[11u8; 32]).into()).unwrap();
        let sk2 = SigningKey::from_bytes((&[22u8; 32]).into()).unwrap();
        let pk1 = hex::encode(sk1.verifying_key().to_encoded_point(false).as_bytes());
        let pk2 = hex::encode(sk2.verifying_key().to_encoded_point(false).as_bytes());
        let agreement = sample_agreement();
        let hash = hex::encode(Sha256::digest(
            agreement_canonical_bytes(&agreement).unwrap(),
        ));
        let policy = basic_otc_escrow_template(
            "pol-otc-thr",
            &hash,
            &[
                TemplateAttestor {
                    attestor_id: "arb-1".to_string(),
                    pubkey_hex: pk1.clone(),
                    display_name: None,
                },
                TemplateAttestor {
                    attestor_id: "arb-2".to_string(),
                    pubkey_hex: pk2.clone(),
                    display_name: None,
                },
            ],
            "trade_settlement",
            9999,
            Some(2),
            None,
        )
        .unwrap();
        let make_p = |id: &str, att: &str, pk: String, sk: &SigningKey| -> SettlementProof {
            let mut p = SettlementProof {
                proof_id: id.to_string(),
                schema_id: SETTLEMENT_PROOF_SCHEMA_ID.to_string(),
                proof_type: "trade_settlement".to_string(),
                agreement_hash: hash.clone(),
                milestone_id: None,
                attested_by: att.to_string(),
                attestation_time: 0,
                evidence_hash: None,
                evidence_summary: None,
                signature: ProofSignatureEnvelope {
                    signature_type: AGREEMENT_SIGNATURE_TYPE_SECP256K1.to_string(),
                    pubkey_hex: pk,
                    signature_hex: String::new(),
                    payload_hash: String::new(),
                },
                expires_at_height: None,
                typed_payload: None,
            };
            p.signature = sign_proof(&p, sk);
            p
        };
        let p1 = make_p("prf-1", "arb-1", pk1.clone(), &sk1);
        let p2 = make_p("prf-2", "arb-2", pk2.clone(), &sk2);
        assert_eq!(
            evaluate_policy(&agreement, &policy, std::slice::from_ref(&p1), 0)
                .unwrap()
                .outcome,
            PolicyOutcome::Unsatisfied
        );
        let result = evaluate_policy(&agreement, &policy, &[p1, p2], 0).unwrap();
        assert_eq!(result.outcome, PolicyOutcome::Satisfied);
        assert!(result.release_eligible);
    }

    #[test]
    fn policy_template_to_json_roundtrips() {
        let policy = basic_otc_escrow_template(
            "pol-json",
            &dummy_hash_64(),
            &[test_attestor_tmpl("att", "pk")],
            "trade_settlement",
            1000,
            None,
            None,
        )
        .unwrap();
        let json = policy_template_to_json(&policy).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["schema_id"], PROOF_POLICY_SCHEMA_ID);
        let reparsed: ProofPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(reparsed.policy_id, policy.policy_id);
    }

    #[test]
    fn template_backward_compat_vs_handcrafted_policy() {
        let sk = sample_signing_key();
        let pk = hex::encode(sk.verifying_key().to_encoded_point(false).as_bytes());
        let agreement = sample_agreement();
        let hash = hex::encode(Sha256::digest(
            agreement_canonical_bytes(&agreement).unwrap(),
        ));
        let legacy = make_test_policy(&hash, &pk, "att");
        let template = basic_otc_escrow_template(
            "pol-001",
            &hash,
            &[TemplateAttestor {
                attestor_id: "att".to_string(),
                pubkey_hex: pk.clone(),
                display_name: None,
            }],
            "delivery_confirmation",
            99999,
            None,
            None,
        )
        .unwrap();
        let mut proof = SettlementProof {
            proof_id: "prf-bc".to_string(),
            schema_id: SETTLEMENT_PROOF_SCHEMA_ID.to_string(),
            proof_type: "delivery_confirmation".to_string(),
            agreement_hash: hash.clone(),
            milestone_id: None,
            attested_by: "att".to_string(),
            attestation_time: 0,
            evidence_hash: None,
            evidence_summary: None,
            signature: ProofSignatureEnvelope {
                signature_type: AGREEMENT_SIGNATURE_TYPE_SECP256K1.to_string(),
                pubkey_hex: pk.clone(),
                signature_hex: String::new(),
                payload_hash: String::new(),
            },
            expires_at_height: None,
            typed_payload: None,
        };
        proof.signature = sign_proof(&proof, &sk);
        assert_eq!(
            evaluate_policy(&agreement, &legacy, &[proof.clone()], 0)
                .unwrap()
                .outcome,
            PolicyOutcome::Satisfied
        );
        assert_eq!(
            evaluate_policy(&agreement, &template, &[proof], 0)
                .unwrap()
                .outcome,
            PolicyOutcome::Satisfied
        );
    }

    // ── Phase 3 audit hardening tests ────────────────────────────────────────

    // policy_id validation
    #[test]
    fn contractor_template_rejects_empty_policy_id() {
        let err = contractor_milestone_template(
            "",
            &dummy_hash_64(),
            &[test_attestor_tmpl("a", "pk")],
            &[ms_spec("ms-1", "t", None, None, None)],
            None,
        )
        .unwrap_err();
        assert!(err.contains("policy_id must not be empty"), "got: {err}");
    }

    #[test]
    fn preorder_template_rejects_empty_policy_id() {
        let err = preorder_deposit_template(
            "",
            &dummy_hash_64(),
            &[test_attestor_tmpl("a", "pk")],
            "delivery",
            500,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(err.contains("policy_id must not be empty"), "got: {err}");
    }

    #[test]
    fn otc_template_rejects_empty_policy_id() {
        let err = basic_otc_escrow_template(
            "",
            &dummy_hash_64(),
            &[test_attestor_tmpl("a", "pk")],
            "trade",
            500,
            None,
            None,
        )
        .unwrap_err();
        assert!(err.contains("policy_id must not be empty"), "got: {err}");
    }

    // per-attestor validation
    #[test]
    fn contractor_template_rejects_empty_attestor_id() {
        let att = TemplateAttestor {
            attestor_id: "".to_string(),
            pubkey_hex: "pk".to_string(),
            display_name: None,
        };
        let err = contractor_milestone_template(
            "p",
            &dummy_hash_64(),
            &[att],
            &[ms_spec("m", "t", None, None, None)],
            None,
        )
        .unwrap_err();
        assert!(err.contains("attestor_id must not be empty"), "got: {err}");
    }

    #[test]
    fn contractor_template_rejects_empty_pubkey_hex() {
        let att = TemplateAttestor {
            attestor_id: "att".to_string(),
            pubkey_hex: "".to_string(),
            display_name: None,
        };
        let err = contractor_milestone_template(
            "p",
            &dummy_hash_64(),
            &[att],
            &[ms_spec("m", "t", None, None, None)],
            None,
        )
        .unwrap_err();
        assert!(err.contains("pubkey_hex must not be empty"), "got: {err}");
    }

    #[test]
    fn preorder_template_rejects_empty_attestor_id() {
        let att = TemplateAttestor {
            attestor_id: "".to_string(),
            pubkey_hex: "pk".to_string(),
            display_name: None,
        };
        let err = preorder_deposit_template(
            "p",
            &dummy_hash_64(),
            &[att],
            "delivery",
            100,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(err.contains("attestor_id must not be empty"), "got: {err}");
    }

    #[test]
    fn preorder_template_rejects_empty_pubkey_hex() {
        let att = TemplateAttestor {
            attestor_id: "att".to_string(),
            pubkey_hex: "".to_string(),
            display_name: None,
        };
        let err = preorder_deposit_template(
            "p",
            &dummy_hash_64(),
            &[att],
            "delivery",
            100,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(err.contains("pubkey_hex must not be empty"), "got: {err}");
    }

    #[test]
    fn otc_template_rejects_empty_attestor_id() {
        let att = TemplateAttestor {
            attestor_id: "".to_string(),
            pubkey_hex: "pk".to_string(),
            display_name: None,
        };
        let err =
            basic_otc_escrow_template("p", &dummy_hash_64(), &[att], "trade", 100, None, None)
                .unwrap_err();
        assert!(err.contains("attestor_id must not be empty"), "got: {err}");
    }

    #[test]
    fn otc_template_rejects_empty_pubkey_hex() {
        let att = TemplateAttestor {
            attestor_id: "att".to_string(),
            pubkey_hex: "".to_string(),
            display_name: None,
        };
        let err =
            basic_otc_escrow_template("p", &dummy_hash_64(), &[att], "trade", 100, None, None)
                .unwrap_err();
        assert!(err.contains("pubkey_hex must not be empty"), "got: {err}");
    }

    // proof_type validation
    #[test]
    fn contractor_template_rejects_empty_proof_type_in_milestone() {
        let err = contractor_milestone_template(
            "p",
            &dummy_hash_64(),
            &[test_attestor_tmpl("a", "pk")],
            &[ms_spec("ms-1", "", None, None, None)],
            None,
        )
        .unwrap_err();
        assert!(err.contains("proof_type must not be empty"), "got: {err}");
    }

    #[test]
    fn preorder_template_rejects_empty_delivery_proof_type() {
        let err = preorder_deposit_template(
            "p",
            &dummy_hash_64(),
            &[test_attestor_tmpl("a", "pk")],
            "",
            100,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(
            err.contains("delivery_proof_type must not be empty"),
            "got: {err}"
        );
    }

    #[test]
    fn otc_template_rejects_empty_release_proof_type() {
        let err = basic_otc_escrow_template(
            "p",
            &dummy_hash_64(),
            &[test_attestor_tmpl("a", "pk")],
            "",
            100,
            None,
            None,
        )
        .unwrap_err();
        assert!(
            err.contains("release_proof_type must not be empty"),
            "got: {err}"
        );
    }

    // threshold=0 explicit rejection
    #[test]
    fn otc_template_rejects_threshold_zero_explicitly() {
        let err = basic_otc_escrow_template(
            "p",
            &dummy_hash_64(),
            &[test_attestor_tmpl("a", "pk")],
            "trade",
            100,
            Some(0),
            None,
        )
        .unwrap_err();
        assert!(err.contains("threshold must be >= 1"), "got: {err}");
    }

    // summary derives from generated policy (milestone_count consistency)
    #[test]
    fn policy_template_to_json_round_trips() {
        let policy = contractor_milestone_template(
            "pol-rt",
            &dummy_hash_64(),
            &[test_attestor_tmpl(
                "att",
                &("03".to_string() + &"ab".repeat(32)),
            )],
            &[ms_spec("ms-1", "proof_a", None, None, None)],
            None,
        )
        .unwrap();
        let json = policy_template_to_json(&policy).unwrap();
        let reparsed: ProofPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(reparsed.policy_id, policy.policy_id);
        assert_eq!(reparsed.required_proofs.len(), policy.required_proofs.len());
        assert_eq!(reparsed.milestones.len(), policy.milestones.len());
    }

    // ── Phase 5 review: milestone scope matching semantics ───────────────────

    /// A proof without milestone_id (scope-unspecified) must satisfy a requirement
    /// scoped to a specific milestone.  This maintains backward compatibility with
    /// proofs created before milestone_id support was added.
    #[test]
    fn proof_without_milestone_id_satisfies_scoped_requirement() {
        let sk = sample_signing_key();
        let pk = hex::encode(sk.verifying_key().to_encoded_point(false).as_bytes());
        let agreement = sample_agreement();
        let hash = hex::encode(Sha256::digest(
            agreement_canonical_bytes(&agreement).unwrap(),
        ));
        let policy = contractor_milestone_template(
            "pol-scope-01",
            &hash,
            &[TemplateAttestor {
                attestor_id: "att".to_string(),
                pubkey_hex: pk.clone(),
                display_name: None,
            }],
            &[ms_spec("ms-1", "milestone_completion", None, None, None)],
            None,
        )
        .unwrap();
        // Proof with no milestone_id — backward-compatible generic proof.
        let mut proof = SettlementProof {
            proof_id: "prf-generic-01".to_string(),
            schema_id: SETTLEMENT_PROOF_SCHEMA_ID.to_string(),
            proof_type: "milestone_completion".to_string(),
            agreement_hash: hash.clone(),
            milestone_id: None,
            attested_by: "att".to_string(),
            attestation_time: 0,
            evidence_hash: None,
            evidence_summary: None,
            signature: ProofSignatureEnvelope {
                signature_type: AGREEMENT_SIGNATURE_TYPE_SECP256K1.to_string(),
                pubkey_hex: pk.clone(),
                signature_hex: String::new(),
                payload_hash: String::new(),
            },
            expires_at_height: None,
            typed_payload: None,
        };
        proof.signature = sign_proof(&proof, &sk);
        let result = evaluate_policy(&agreement, &policy, &[proof], 0).unwrap();
        assert_eq!(
            result.outcome,
            PolicyOutcome::Satisfied,
            "proof without milestone_id must satisfy scoped requirement (backward compat)"
        );
        assert!(result.release_eligible);
    }

    /// A proof with an explicit milestone_id must satisfy a requirement scoped to
    /// the same milestone.
    #[test]
    fn proof_with_milestone_id_satisfies_matching_requirement() {
        let sk = sample_signing_key();
        let pk = hex::encode(sk.verifying_key().to_encoded_point(false).as_bytes());
        let agreement = sample_agreement();
        let hash = hex::encode(Sha256::digest(
            agreement_canonical_bytes(&agreement).unwrap(),
        ));
        let policy = contractor_milestone_template(
            "pol-scope-02",
            &hash,
            &[TemplateAttestor {
                attestor_id: "att".to_string(),
                pubkey_hex: pk.clone(),
                display_name: None,
            }],
            &[ms_spec("ms-1", "milestone_completion", None, None, None)],
            None,
        )
        .unwrap();
        let mut proof = SettlementProof {
            proof_id: "prf-ms1-01".to_string(),
            schema_id: SETTLEMENT_PROOF_SCHEMA_ID.to_string(),
            proof_type: "milestone_completion".to_string(),
            agreement_hash: hash.clone(),
            milestone_id: Some("ms-1".to_string()),
            attested_by: "att".to_string(),
            attestation_time: 0,
            evidence_hash: None,
            evidence_summary: None,
            signature: ProofSignatureEnvelope {
                signature_type: AGREEMENT_SIGNATURE_TYPE_SECP256K1.to_string(),
                pubkey_hex: pk.clone(),
                signature_hex: String::new(),
                payload_hash: String::new(),
            },
            expires_at_height: None,
            typed_payload: None,
        };
        proof.signature = sign_proof(&proof, &sk);
        let result = evaluate_policy(&agreement, &policy, &[proof], 0).unwrap();
        assert_eq!(
            result.outcome,
            PolicyOutcome::Satisfied,
            "proof with matching milestone_id must satisfy scoped requirement"
        );
    }

    /// A proof scoped to ms-2 must NOT satisfy a requirement scoped to ms-1.
    /// This is the core bug fix in Phase 5.
    #[test]
    fn proof_with_mismatched_milestone_id_does_not_satisfy_requirement() {
        let sk = sample_signing_key();
        let pk = hex::encode(sk.verifying_key().to_encoded_point(false).as_bytes());
        let agreement = sample_agreement();
        let hash = hex::encode(Sha256::digest(
            agreement_canonical_bytes(&agreement).unwrap(),
        ));
        let policy = contractor_milestone_template(
            "pol-scope-03",
            &hash,
            &[TemplateAttestor {
                attestor_id: "att".to_string(),
                pubkey_hex: pk.clone(),
                display_name: None,
            }],
            &[
                ms_spec("ms-1", "milestone_completion", None, None, None),
                ms_spec("ms-2", "milestone_completion", None, None, None),
            ],
            None,
        )
        .unwrap();
        // Only submit a proof for ms-2.
        let mut proof = SettlementProof {
            proof_id: "prf-ms2-wrong".to_string(),
            schema_id: SETTLEMENT_PROOF_SCHEMA_ID.to_string(),
            proof_type: "milestone_completion".to_string(),
            agreement_hash: hash.clone(),
            milestone_id: Some("ms-2".to_string()),
            attested_by: "att".to_string(),
            attestation_time: 0,
            evidence_hash: None,
            evidence_summary: None,
            signature: ProofSignatureEnvelope {
                signature_type: AGREEMENT_SIGNATURE_TYPE_SECP256K1.to_string(),
                pubkey_hex: pk.clone(),
                signature_hex: String::new(),
                payload_hash: String::new(),
            },
            expires_at_height: None,
            typed_payload: None,
        };
        proof.signature = sign_proof(&proof, &sk);
        let result = evaluate_policy(&agreement, &policy, &[proof], 0).unwrap();
        // ms-2 proof satisfies ms-2 but NOT ms-1; overall still Unsatisfied.
        assert_ne!(
            result.outcome,
            PolicyOutcome::Satisfied,
            "proof for ms-2 must NOT satisfy ms-1 requirement"
        );
        let ms1 = result
            .milestone_results
            .iter()
            .find(|m| m.milestone_id == "ms-1")
            .unwrap();
        let ms2 = result
            .milestone_results
            .iter()
            .find(|m| m.milestone_id == "ms-2")
            .unwrap();
        assert_ne!(
            ms1.outcome,
            PolicyOutcome::Satisfied,
            "ms-1 must not be satisfied by ms-2 proof"
        );
        assert_eq!(
            ms2.outcome,
            PolicyOutcome::Satisfied,
            "ms-2 must be satisfied by its own proof"
        );
    }

    /// When multiple proofs are present (one per milestone), each milestone's
    /// requirement is satisfied only by its own proof.  Overall outcome is Satisfied.
    #[test]
    fn multiple_proofs_each_satisfies_own_milestone() {
        let sk = sample_signing_key();
        let pk = hex::encode(sk.verifying_key().to_encoded_point(false).as_bytes());
        let agreement = sample_agreement();
        let hash = hex::encode(Sha256::digest(
            agreement_canonical_bytes(&agreement).unwrap(),
        ));
        let policy = contractor_milestone_template(
            "pol-scope-04",
            &hash,
            &[TemplateAttestor {
                attestor_id: "att".to_string(),
                pubkey_hex: pk.clone(),
                display_name: None,
            }],
            &[
                ms_spec("ms-1", "milestone_completion", None, None, None),
                ms_spec("ms-2", "milestone_completion", None, None, None),
            ],
            None,
        )
        .unwrap();
        let make_proof = |pid: &str, mid: &str| {
            let mut p = SettlementProof {
                proof_id: pid.to_string(),
                schema_id: SETTLEMENT_PROOF_SCHEMA_ID.to_string(),
                proof_type: "milestone_completion".to_string(),
                agreement_hash: hash.clone(),
                milestone_id: Some(mid.to_string()),
                attested_by: "att".to_string(),
                attestation_time: 0,
                evidence_hash: None,
                evidence_summary: None,
                signature: ProofSignatureEnvelope {
                    signature_type: AGREEMENT_SIGNATURE_TYPE_SECP256K1.to_string(),
                    pubkey_hex: pk.clone(),
                    signature_hex: String::new(),
                    payload_hash: String::new(),
                },
                expires_at_height: None,
                typed_payload: None,
            };
            p.signature = sign_proof(&p, &sk);
            p
        };
        let proof1 = make_proof("prf-ms1", "ms-1");
        let proof2 = make_proof("prf-ms2", "ms-2");
        let result = evaluate_policy(&agreement, &policy, &[proof1, proof2], 0).unwrap();
        assert_eq!(
            result.outcome,
            PolicyOutcome::Satisfied,
            "both milestones satisfied → overall satisfied"
        );
        assert_eq!(result.completed_milestone_count, 2);
    }

    #[test]
    fn build_otc_agreement_assigns_seller_as_payer() {
        let buyer = AgreementParty {
            party_id: "buyer".to_string(),
            display_name: "Buyer".to_string(),
            address: "Qbuyer".to_string(),
            role: Some("buyer".to_string()),
        };
        let seller = AgreementParty {
            party_id: "seller".to_string(),
            display_name: "Seller".to_string(),
            address: "Qseller".to_string(),
            role: Some("seller".to_string()),
        };
        let agreement = build_otc_agreement(
            "otc-test-direction".to_string(),
            1_700_000_000,
            buyer.clone(),
            seller.clone(),
            500_000_000,
            "IRM".to_string(),
            "off-chain".to_string(),
            120,
            "ab".repeat(32),
            "cd".repeat(32),
            None,
            None,
        )
        .expect("build_otc_agreement");
        assert_eq!(agreement.payer, "seller", "seller must be the payer (HTLC funder)");
        assert_eq!(agreement.payee, "buyer", "buyer must be the payee (release recipient)");
        assert_eq!(agreement.refund_conditions.len(), 1);
        assert_eq!(
            agreement.refund_conditions[0].refund_address, "Qseller",
            "refund returns to seller on timeout"
        );
        assert_eq!(agreement.release_conditions.len(), 1);
        assert_eq!(
            agreement.release_conditions[0].release_authorizer.as_deref(),
            Some("seller"),
            "release authorizer must be seller after fix"
        );
    }
}

// ============================================================================
// Commercial Policy Templates
// ============================================================================
//
// Pure composition helpers: each function returns a valid ProofPolicy built from
// existing primitives.  No new evaluation logic, no new consensus rules.
// Templates validate their inputs before constructing the policy; callers receive
// a descriptive error when parameters are inconsistent.
//
// To submit a template to the node call /rpc/storepolicy with the serialised JSON.
// Use `policy_template_to_json` to obtain the canonical JSON string.
// ============================================================================

/// Serialise a `ProofPolicy` to a canonical JSON string for RPC submission.
pub fn policy_template_to_json(policy: &ProofPolicy) -> Result<String, String> {
    serde_json::to_string_pretty(policy).map_err(|e| format!("serialize policy: {e}"))
}

// ── Shared input types ────────────────────────────────────────────────────────

/// A single approved attestor descriptor used by template builders.
#[derive(Debug, Clone)]
pub struct TemplateAttestor {
    /// Unique identifier referenced in `required_attestor_ids` and `attestors`.
    pub attestor_id: String,
    /// Uncompressed secp256k1 public key (130 hex chars) or compressed (66 hex chars).
    pub pubkey_hex: String,
    /// Optional human-readable label.
    pub display_name: Option<String>,
}

/// Per-milestone descriptor used by `contractor_milestone_template`.
#[derive(Debug, Clone)]
pub struct MilestoneSpec {
    /// Unique identifier for this milestone (e.g. "ms-design", "ms-delivery").
    pub milestone_id: String,
    /// Human-readable label shown in evaluation output.
    pub label: Option<String>,
    /// Proof type that must be attested to release this milestone.
    pub proof_type: String,
    /// Block height deadline after which a missing proof triggers a timeout refund.
    /// `None` means no timeout rule for this milestone.
    pub deadline_height: Option<u64>,
    /// Basis points (1-9999) held back after release until `holdback_release_height`.
    /// `None` means no holdback on this milestone.
    pub holdback_bps: Option<u32>,
    /// Block height at which an active holdback is automatically released.
    /// Required when `holdback_bps` is set.
    pub holdback_release_height: Option<u64>,
}

// ── Template 1: contractor_milestone_template ─────────────────────────────────

/// Build a milestone-based contractor payment policy.
///
/// Each milestone becomes an independent tranche evaluated separately.
/// Release is gated on a proof of `milestone.proof_type` from any attestor in
/// `attestors`.  When `deadline_height` is set a `funded_and_no_release` timeout
/// rule triggers refund eligibility if no proof arrives by that height.
/// When `holdback_bps` is set on a milestone a fraction is held back until
/// `holdback_release_height`.
pub fn contractor_milestone_template(
    policy_id: &str,
    agreement_hash: &str,
    attestors: &[TemplateAttestor],
    milestones: &[MilestoneSpec],
    notes: Option<String>,
) -> Result<ProofPolicy, String> {
    if policy_id.trim().is_empty() {
        return Err("contractor_milestone_template: policy_id must not be empty".to_string());
    }
    if attestors.is_empty() {
        return Err("contractor_milestone_template: attestors must not be empty".to_string());
    }
    for a in attestors {
        if a.attestor_id.trim().is_empty() {
            return Err("contractor_milestone_template: attestor_id must not be empty".to_string());
        }
        if a.pubkey_hex.trim().is_empty() {
            return Err("contractor_milestone_template: pubkey_hex must not be empty".to_string());
        }
    }
    if milestones.is_empty() {
        return Err("contractor_milestone_template: milestones must not be empty".to_string());
    }
    let mut seen_ids = std::collections::HashSet::new();
    for ms in milestones {
        if ms.milestone_id.trim().is_empty() {
            return Err(
                "contractor_milestone_template: milestone_id must not be empty".to_string(),
            );
        }
        if !seen_ids.insert(ms.milestone_id.as_str()) {
            return Err(format!(
                "contractor_milestone_template: duplicate milestone_id '{}'",
                ms.milestone_id
            ));
        }
        if ms.proof_type.trim().is_empty() {
            return Err(format!(
                "contractor_milestone_template: milestone '{}' proof_type must not be empty",
                ms.milestone_id
            ));
        }
        if let Some(bps) = ms.holdback_bps {
            if bps == 0 || bps >= 10000 {
                return Err(format!(
                    "contractor_milestone_template: milestone '{}' holdback_bps {} out of range (1-9999)",
                    ms.milestone_id, bps
                ));
            }
            if ms.holdback_release_height.is_none() {
                return Err(format!(
                    "contractor_milestone_template: milestone '{}' holdback_bps set but holdback_release_height not supplied",
                    ms.milestone_id
                ));
            }
        }
    }

    let approved_attestors: Vec<ApprovedAttestor> = attestors
        .iter()
        .map(|a| ApprovedAttestor {
            attestor_id: a.attestor_id.clone(),
            pubkey_hex: a.pubkey_hex.clone(),
            display_name: a.display_name.clone(),
            domain: None,
        })
        .collect();

    let attestor_ids: Vec<String> = attestors.iter().map(|a| a.attestor_id.clone()).collect();

    let mut required_proofs: Vec<ProofRequirement> = Vec::new();
    let mut no_response_rules: Vec<NoResponseRule> = Vec::new();
    let mut policy_milestones: Vec<PolicyMilestone> = Vec::new();

    for ms in milestones {
        let req_id = format!("req-{}", ms.milestone_id);

        required_proofs.push(ProofRequirement {
            requirement_id: req_id.clone(),
            proof_type: ms.proof_type.clone(),
            required_by: ms.deadline_height,
            required_attestor_ids: attestor_ids.clone(),
            resolution: ProofResolution::MilestoneRelease,
            milestone_id: Some(ms.milestone_id.clone()),
            threshold: None,
        });

        if let Some(dl) = ms.deadline_height {
            no_response_rules.push(NoResponseRule {
                rule_id: format!("rule-{}", ms.milestone_id),
                deadline_height: dl,
                trigger: NoResponseTrigger::FundedAndNoRelease,
                resolution: ProofResolution::Refund,
                milestone_id: Some(ms.milestone_id.clone()),
                notes: Some(format!(
                    "timeout refund for milestone '{}'",
                    ms.milestone_id
                )),
            });
        }

        let holdback = ms.holdback_bps.map(|bps| PolicyHoldback {
            holdback_bps: bps,
            release_requirement_id: None,
            deadline_height: ms.holdback_release_height,
        });

        policy_milestones.push(PolicyMilestone {
            milestone_id: ms.milestone_id.clone(),
            label: ms.label.clone(),
            holdback,
        });
    }

    Ok(ProofPolicy {
        policy_id: policy_id.to_string(),
        schema_id: PROOF_POLICY_SCHEMA_ID.to_string(),
        agreement_hash: agreement_hash.to_string(),
        required_proofs,
        no_response_rules,
        attestors: approved_attestors,
        notes,
        expires_at_height: None,
        milestones: policy_milestones,
        holdback: None,
    })
}

// ── Template 2: preorder_deposit_template ────────────────────────────────────

/// Build a preorder/deposit protection policy.
///
/// Funds release when an approved attestor provides a `delivery_proof_type` proof.
/// If no proof arrives by `refund_deadline_height` the buyer becomes refund-eligible.
/// Optional holdback: `holdback_bps` fraction retained after delivery proof, released
/// at `holdback_release_height`.
pub fn preorder_deposit_template(
    policy_id: &str,
    agreement_hash: &str,
    attestors: &[TemplateAttestor],
    delivery_proof_type: &str,
    refund_deadline_height: u64,
    holdback_bps: Option<u32>,
    holdback_release_height: Option<u64>,
    notes: Option<String>,
) -> Result<ProofPolicy, String> {
    if policy_id.trim().is_empty() {
        return Err("preorder_deposit_template: policy_id must not be empty".to_string());
    }
    if delivery_proof_type.trim().is_empty() {
        return Err("preorder_deposit_template: delivery_proof_type must not be empty".to_string());
    }
    if attestors.is_empty() {
        return Err("preorder_deposit_template: attestors must not be empty".to_string());
    }
    for a in attestors {
        if a.attestor_id.trim().is_empty() {
            return Err("preorder_deposit_template: attestor_id must not be empty".to_string());
        }
        if a.pubkey_hex.trim().is_empty() {
            return Err("preorder_deposit_template: pubkey_hex must not be empty".to_string());
        }
    }
    if let Some(bps) = holdback_bps {
        if bps == 0 || bps >= 10000 {
            return Err(format!(
                "preorder_deposit_template: holdback_bps {} out of range (1-9999)",
                bps
            ));
        }
        if holdback_release_height.is_none() {
            return Err(
                "preorder_deposit_template: holdback_bps set but holdback_release_height not supplied"
                    .to_string(),
            );
        }
    }

    let attestor_ids: Vec<String> = attestors.iter().map(|a| a.attestor_id.clone()).collect();
    let approved_attestors: Vec<ApprovedAttestor> = attestors
        .iter()
        .map(|a| ApprovedAttestor {
            attestor_id: a.attestor_id.clone(),
            pubkey_hex: a.pubkey_hex.clone(),
            display_name: a.display_name.clone(),
            domain: None,
        })
        .collect();

    let required_proofs = vec![ProofRequirement {
        requirement_id: "req-delivery".to_string(),
        proof_type: delivery_proof_type.to_string(),
        required_by: Some(refund_deadline_height),
        required_attestor_ids: attestor_ids,
        resolution: ProofResolution::Release,
        milestone_id: None,
        threshold: None,
    }];

    let no_response_rules = vec![NoResponseRule {
        rule_id: "rule-timeout-refund".to_string(),
        deadline_height: refund_deadline_height,
        trigger: NoResponseTrigger::FundedAndNoRelease,
        resolution: ProofResolution::Refund,
        milestone_id: None,
        notes: Some("refund buyer if delivery proof not provided by deadline".to_string()),
    }];

    let holdback = holdback_bps.map(|bps| PolicyHoldback {
        holdback_bps: bps,
        release_requirement_id: None,
        deadline_height: holdback_release_height,
    });

    Ok(ProofPolicy {
        policy_id: policy_id.to_string(),
        schema_id: PROOF_POLICY_SCHEMA_ID.to_string(),
        agreement_hash: agreement_hash.to_string(),
        required_proofs,
        no_response_rules,
        attestors: approved_attestors,
        notes,
        expires_at_height: None,
        milestones: vec![],
        holdback,
    })
}

// ── Template 3: basic_otc_escrow_template ────────────────────────────────────

/// Build a basic OTC escrow policy.
///
/// Funds release when `threshold` approved attestors provide a `release_proof_type` proof.
/// `threshold` defaults to 1 (single-sig escrow).  Values > 1 enable multi-party release.
/// Timeout refund triggers at `refund_deadline_height` if the quorum is not reached.
pub fn basic_otc_escrow_template(
    policy_id: &str,
    agreement_hash: &str,
    attestors: &[TemplateAttestor],
    release_proof_type: &str,
    refund_deadline_height: u64,
    threshold: Option<u32>,
    notes: Option<String>,
) -> Result<ProofPolicy, String> {
    if policy_id.trim().is_empty() {
        return Err("basic_otc_escrow_template: policy_id must not be empty".to_string());
    }
    if release_proof_type.trim().is_empty() {
        return Err("basic_otc_escrow_template: release_proof_type must not be empty".to_string());
    }
    if attestors.is_empty() {
        return Err("basic_otc_escrow_template: attestors must not be empty".to_string());
    }
    for a in attestors {
        if a.attestor_id.trim().is_empty() {
            return Err("basic_otc_escrow_template: attestor_id must not be empty".to_string());
        }
        if a.pubkey_hex.trim().is_empty() {
            return Err("basic_otc_escrow_template: pubkey_hex must not be empty".to_string());
        }
    }
    if let Some(0) = threshold {
        return Err("basic_otc_escrow_template: threshold must be >= 1".to_string());
    }
    let eff_threshold = threshold.unwrap_or(1).max(1);
    if eff_threshold as usize > attestors.len() {
        return Err(format!(
            "basic_otc_escrow_template: threshold {} exceeds attestor count {}",
            eff_threshold,
            attestors.len()
        ));
    }

    let attestor_ids: Vec<String> = attestors.iter().map(|a| a.attestor_id.clone()).collect();
    let approved_attestors: Vec<ApprovedAttestor> = attestors
        .iter()
        .map(|a| ApprovedAttestor {
            attestor_id: a.attestor_id.clone(),
            pubkey_hex: a.pubkey_hex.clone(),
            display_name: a.display_name.clone(),
            domain: None,
        })
        .collect();

    // Only set threshold field when > 1 to preserve single-attestor backward-compatible path.
    let threshold_field = if eff_threshold > 1 {
        Some(eff_threshold)
    } else {
        None
    };

    let required_proofs = vec![ProofRequirement {
        requirement_id: "req-release".to_string(),
        proof_type: release_proof_type.to_string(),
        required_by: Some(refund_deadline_height),
        required_attestor_ids: attestor_ids,
        resolution: ProofResolution::Release,
        milestone_id: None,
        threshold: threshold_field,
    }];

    let no_response_rules = vec![NoResponseRule {
        rule_id: "rule-timeout-refund".to_string(),
        deadline_height: refund_deadline_height,
        trigger: NoResponseTrigger::FundedAndNoRelease,
        resolution: ProofResolution::Refund,
        milestone_id: None,
        notes: Some("refund if release proof quorum not reached by deadline".to_string()),
    }];

    Ok(ProofPolicy {
        policy_id: policy_id.to_string(),
        schema_id: PROOF_POLICY_SCHEMA_ID.to_string(),
        agreement_hash: agreement_hash.to_string(),
        required_proofs,
        no_response_rules,
        attestors: approved_attestors,
        notes,
        expires_at_height: None,
        milestones: vec![],
        holdback: None,
    })
}

// ============================================================================
// Dispute and Resolver Canonical Types (Stage 3.1)
// ============================================================================

pub const DISPUTE_RAISE_SCHEMA_ID: &str = "irium.phase3.dispute_raise.v1";
pub const DISPUTE_RAISE_VERSION: u32 = 1;
pub const DISPUTE_EVIDENCE_SCHEMA_ID: &str = "irium.phase3.dispute_evidence.v1";
pub const DISPUTE_EVIDENCE_VERSION: u32 = 1;
pub const DISPUTE_RESOLUTION_SCHEMA_ID: &str = "irium.phase3.dispute_resolution.v1";
pub const DISPUTE_RESOLUTION_VERSION: u32 = 1;
pub const RESOLVER_REGISTRATION_SCHEMA_ID: &str = "irium.phase3.resolver_registration.v1";
pub const RESOLVER_REGISTRATION_VERSION: u32 = 1;

pub const DISPUTE_RERESOLVE_SCHEMA_ID: &str = "irium.phase3.dispute_reresolve.v1";
pub const DISPUTE_RERESOLVE_VERSION: u32 = 1;

fn validate_hex_hash(field: &str, value: &str) -> Result<(), String> {
    if value.len() != 64 || hex::decode(value).is_err() {
        return Err(format!("{} must be 32-byte hex", field));
    }
    Ok(())
}

fn default_dispute_raise_version() -> u32 { DISPUTE_RAISE_VERSION }
fn default_dispute_evidence_version() -> u32 { DISPUTE_EVIDENCE_VERSION }
fn default_dispute_resolution_version() -> u32 { DISPUTE_RESOLUTION_VERSION }
fn default_resolver_registration_version() -> u32 { RESOLVER_REGISTRATION_VERSION }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisputeRaise {
    #[serde(default = "default_dispute_raise_version")]
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_id: Option<String>,
    pub agreement_hash: String,
    pub raising_party: String,
    pub raised_at_height: u64,
    pub raised_at_unix: u64,
    pub reason: String,
    pub initial_evidence_hash: String,
    pub signature: AgreementSignatureEnvelope,
}

impl DisputeRaise {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != DISPUTE_RAISE_VERSION {
            return Err(format!("unsupported dispute_raise version {}", self.version));
        }
        if let Some(sid) = &self.schema_id {
            if sid != DISPUTE_RAISE_SCHEMA_ID {
                return Err(format!("unsupported dispute_raise schema_id {}", sid));
            }
        }
        validate_hex_hash("agreement_hash", &self.agreement_hash)?;
        validate_hex_hash("initial_evidence_hash", &self.initial_evidence_hash)?;
        if self.raising_party.trim().is_empty() {
            return Err("raising_party required".to_string());
        }
        if self.reason.trim().is_empty() {
            return Err("reason required".to_string());
        }
        if self.reason.len() > 4096 {
            return Err("reason too long (max 4096 chars)".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisputeEvidence {
    #[serde(default = "default_dispute_evidence_version")]
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_id: Option<String>,
    pub agreement_hash: String,
    pub submitter_party: String,
    pub submitted_at_height: u64,
    pub evidence_type: String,
    pub evidence_payload: String,
    pub evidence_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub signature: AgreementSignatureEnvelope,
}

impl DisputeEvidence {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != DISPUTE_EVIDENCE_VERSION {
            return Err(format!(
                "unsupported dispute_evidence version {}",
                self.version
            ));
        }
        if let Some(sid) = &self.schema_id {
            if sid != DISPUTE_EVIDENCE_SCHEMA_ID {
                return Err(format!("unsupported dispute_evidence schema_id {}", sid));
            }
        }
        validate_hex_hash("agreement_hash", &self.agreement_hash)?;
        validate_hex_hash("evidence_hash", &self.evidence_hash)?;
        if self.submitter_party.trim().is_empty() {
            return Err("submitter_party required".to_string());
        }
        match self.evidence_type.as_str() {
            "payment_proof" | "delivery_proof" | "communication_proof" => {}
            other => {
                return Err(format!(
                    "evidence_type must be payment_proof|delivery_proof|communication_proof (got {})",
                    other
                ))
            }
        }
        if self.evidence_payload.is_empty() {
            return Err("evidence_payload required".to_string());
        }
        if let Some(msg) = &self.message {
            if msg.len() > 4096 {
                return Err("message too long (max 4096 chars)".to_string());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisputeResolution {
    #[serde(default = "default_dispute_resolution_version")]
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_id: Option<String>,
    pub agreement_hash: String,
    pub resolver_address: String,
    pub resolver_role: String,
    pub outcome: String,
    pub resolved_at_height: u64,
    pub message: String,
    pub signature: AgreementSignatureEnvelope,
}

impl DisputeResolution {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != DISPUTE_RESOLUTION_VERSION {
            return Err(format!(
                "unsupported dispute_resolution version {}",
                self.version
            ));
        }
        if let Some(sid) = &self.schema_id {
            if sid != DISPUTE_RESOLUTION_SCHEMA_ID {
                return Err(format!(
                    "unsupported dispute_resolution schema_id {}",
                    sid
                ));
            }
        }
        validate_hex_hash("agreement_hash", &self.agreement_hash)?;
        if self.resolver_address.trim().is_empty() {
            return Err("resolver_address required".to_string());
        }
        match self.resolver_role.as_str() {
            "primary" | "fallback" => {}
            other => return Err(format!("resolver_role must be primary|fallback (got {})", other)),
        }
        match self.outcome.as_str() {
            "release" | "refund" => {}
            other => return Err(format!("outcome must be release|refund (got {})", other)),
        }
        if self.message.len() > 4096 {
            return Err("message too long (max 4096 chars)".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolverRegistration {
    #[serde(default = "default_resolver_registration_version")]
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_id: Option<String>,
    pub resolver_address: String,
    pub registered_at_height: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bio: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee_bps_self_quoted: Option<u32>,
    pub signature: AgreementSignatureEnvelope,
}

impl ResolverRegistration {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != RESOLVER_REGISTRATION_VERSION {
            return Err(format!(
                "unsupported resolver_registration version {}",
                self.version
            ));
        }
        if let Some(sid) = &self.schema_id {
            if sid != RESOLVER_REGISTRATION_SCHEMA_ID {
                return Err(format!(
                    "unsupported resolver_registration schema_id {}",
                    sid
                ));
            }
        }
        if self.resolver_address.trim().is_empty() {
            return Err("resolver_address required".to_string());
        }
        if let Some(bps) = self.fee_bps_self_quoted {
            if bps > 10_000 {
                return Err("fee_bps_self_quoted must be <= 10000 (100%)".to_string());
            }
        }
        if let Some(name) = &self.display_name {
            if name.len() > 128 {
                return Err("display_name too long (max 128 chars)".to_string());
            }
        }
        if let Some(bio) = &self.bio {
            if bio.len() > 1024 {
                return Err("bio too long (max 1024 chars)".to_string());
            }
        }
        Ok(())
    }
}

pub fn dispute_raise_canonical_value(d: &DisputeRaise) -> Result<Value, String> {
    let value = serde_json::to_value(d).map_err(|e| format!("dispute_raise to json: {e}"))?;
    Ok(sort_json(value))
}
pub fn dispute_raise_canonical_bytes(d: &DisputeRaise) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&dispute_raise_canonical_value(d)?)
        .map_err(|e| format!("dispute_raise serialize: {e}"))
}
pub fn dispute_evidence_canonical_value(d: &DisputeEvidence) -> Result<Value, String> {
    let value = serde_json::to_value(d).map_err(|e| format!("dispute_evidence to json: {e}"))?;
    Ok(sort_json(value))
}
pub fn dispute_evidence_canonical_bytes(d: &DisputeEvidence) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&dispute_evidence_canonical_value(d)?)
        .map_err(|e| format!("dispute_evidence serialize: {e}"))
}
pub fn dispute_resolution_canonical_value(d: &DisputeResolution) -> Result<Value, String> {
    let value = serde_json::to_value(d).map_err(|e| format!("dispute_resolution to json: {e}"))?;
    Ok(sort_json(value))
}
pub fn dispute_resolution_canonical_bytes(d: &DisputeResolution) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&dispute_resolution_canonical_value(d)?)
        .map_err(|e| format!("dispute_resolution serialize: {e}"))
}
pub fn resolver_registration_canonical_value(r: &ResolverRegistration) -> Result<Value, String> {
    let value = serde_json::to_value(r).map_err(|e| format!("resolver_registration to json: {e}"))?;
    Ok(sort_json(value))
}
pub fn resolver_registration_canonical_bytes(r: &ResolverRegistration) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&resolver_registration_canonical_value(r)?)
        .map_err(|e| format!("resolver_registration serialize: {e}"))
}

fn default_dispute_reresolve_version() -> u32 { DISPUTE_RERESOLVE_VERSION }

/// Co-signed nomination of new primary and (optional) fallback resolvers
/// when both originally-named resolvers have failed to respond. Both
/// parties of the agreement sign the same canonical payload; iriumd
/// verifies both signatures against the addresses in the agreement's
/// parties list before swapping the effective resolvers on the dispute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisputeReResolverNomination {
    #[serde(default = "default_dispute_reresolve_version")]
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_id: Option<String>,
    pub agreement_hash: String,
    pub new_primary_resolver: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_fallback_resolver: Option<String>,
    pub nominated_at_height: u64,
    pub party_a_signature: AgreementSignatureEnvelope,
    pub party_b_signature: AgreementSignatureEnvelope,
}

impl DisputeReResolverNomination {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != DISPUTE_RERESOLVE_VERSION {
            return Err(format!(
                "unsupported dispute_reresolve version {}",
                self.version
            ));
        }
        if let Some(sid) = &self.schema_id {
            if sid != DISPUTE_RERESOLVE_SCHEMA_ID {
                return Err(format!(
                    "unsupported dispute_reresolve schema_id {}",
                    sid
                ));
            }
        }
        if self.agreement_hash.len() != 64 || hex::decode(&self.agreement_hash).is_err() {
            return Err("agreement_hash must be 32-byte hex".to_string());
        }
        if self.new_primary_resolver.trim().is_empty() {
            return Err("new_primary_resolver required".to_string());
        }
        if let Some(fb) = &self.new_fallback_resolver {
            if fb.trim() == self.new_primary_resolver.trim() {
                return Err(
                    "new_fallback_resolver must differ from new_primary_resolver".to_string(),
                );
            }
        }
        Ok(())
    }
}

pub fn dispute_reresolve_canonical_value(d: &DisputeReResolverNomination) -> Result<Value, String> {
    let value =
        serde_json::to_value(d).map_err(|e| format!("dispute_reresolve to json: {e}"))?;
    Ok(sort_json(value))
}

pub fn dispute_reresolve_canonical_bytes(
    d: &DisputeReResolverNomination,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&dispute_reresolve_canonical_value(d)?)
        .map_err(|e| format!("dispute_reresolve serialize: {e}"))
}

#[cfg(test)]
mod stage_3_1_tests {
    use super::*;

    fn otc_parties() -> (AgreementParty, AgreementParty) {
        let buyer = AgreementParty {
            party_id: "buyer".to_string(),
            display_name: "Buyer".to_string(),
            address: "Qbuyer".to_string(),
            role: Some("buyer".to_string()),
        };
        let seller = AgreementParty {
            party_id: "seller".to_string(),
            display_name: "Seller".to_string(),
            address: "Qseller".to_string(),
            role: Some("seller".to_string()),
        };
        (buyer, seller)
    }

    fn build_test_otc() -> AgreementObject {
        let (buyer, seller) = otc_parties();
        build_otc_agreement(
            "otc-stage31-test".to_string(),
            1_700_000_000,
            buyer,
            seller,
            500_000_000,
            "IRM".to_string(),
            "off-chain".to_string(),
            120,
            "ab".repeat(32),
            "cd".repeat(32),
            None,
            None,
        )
        .expect("build_otc_agreement")
    }

    #[test]
    fn agreement_without_resolver_fields_canonical_json_omits_them() {
        let agreement = build_test_otc();
        let canonical = agreement_canonical_value(&agreement).expect("canonical_value");
        let json = serde_json::to_string(&canonical).expect("serialize");
        assert!(!json.contains("primary_resolver"), "primary_resolver must be omitted when None");
        assert!(!json.contains("fallback_resolver"), "fallback_resolver must be omitted when None");
        assert!(!json.contains("primary_resolver_fee"), "primary_resolver_fee must be omitted when None");
        assert!(!json.contains("fallback_resolver_fee"), "fallback_resolver_fee must be omitted when None");
    }

    #[test]
    fn agreement_hash_stable_when_resolver_fields_set_to_none_explicitly() {
        let mut a = build_test_otc();
        let h1 = compute_agreement_hash_hex(&a).expect("hash1");
        a.primary_resolver = None;
        a.fallback_resolver = None;
        a.primary_resolver_fee = None;
        a.fallback_resolver_fee = None;
        let h2 = compute_agreement_hash_hex(&a).expect("hash2");
        assert_eq!(h1, h2, "explicit None must hash identically to absent");
    }

    #[test]
    fn validate_rejects_resolver_fields_on_deposit_template() {
        let (buyer, seller) = otc_parties();
        let mut a = build_deposit_agreement(
            "dep-stage31".to_string(),
            1_700_000_000,
            buyer,
            seller,
            500_000_000,
            "purpose".to_string(),
            "refundable".to_string(),
            120,
            "ab".repeat(32),
            "cd".repeat(32),
            None,
            None,
        )
        .expect("build_deposit");
        a.primary_resolver = Some("Qresolver".to_string());
        a.primary_resolver_fee = Some(1_000_000);
        let err = a.validate().expect_err("should reject");
        assert!(err.contains("resolver fields are only allowed"), "got: {err}");
    }

    #[test]
    fn validate_accepts_otc_with_valid_primary_resolver() {
        let mut a = build_test_otc();
        a.primary_resolver = Some("Qresolver1".to_string());
        a.primary_resolver_fee = Some(1_000_000);
        a.validate().expect("should accept");
    }

    #[test]
    fn validate_rejects_fallback_without_primary() {
        let mut a = build_test_otc();
        a.fallback_resolver = Some("Qresolver2".to_string());
        a.fallback_resolver_fee = Some(500_000);
        let err = a.validate().expect_err("should reject");
        assert!(err.contains("fallback_resolver requires primary_resolver"), "got: {err}");
    }

    #[test]
    fn validate_rejects_fee_zero() {
        let mut a = build_test_otc();
        a.primary_resolver = Some("Qresolver".to_string());
        a.primary_resolver_fee = Some(0);
        let err = a.validate().expect_err("should reject");
        assert!(err.contains("primary_resolver_fee must be > 0"), "got: {err}");
    }

    #[test]
    fn validate_rejects_fee_geq_total_amount() {
        let mut a = build_test_otc();
        a.primary_resolver = Some("Qresolver".to_string());
        a.primary_resolver_fee = Some(a.total_amount);
        let err = a.validate().expect_err("should reject");
        assert!(err.contains("primary_resolver_fee must be < total_amount"), "got: {err}");
    }

    #[test]
    fn validate_rejects_fallback_equal_primary() {
        let mut a = build_test_otc();
        a.primary_resolver = Some("QresolverSame".to_string());
        a.primary_resolver_fee = Some(1_000_000);
        a.fallback_resolver = Some("QresolverSame".to_string());
        a.fallback_resolver_fee = Some(500_000);
        let err = a.validate().expect_err("should reject");
        assert!(err.contains("must differ"), "got: {err}");
    }

    #[test]
    fn validate_rejects_combined_fees_geq_total_amount() {
        let mut a = build_test_otc();
        let half = a.total_amount / 2;
        a.primary_resolver = Some("Qprim".to_string());
        a.primary_resolver_fee = Some(half);
        a.fallback_resolver = Some("Qfall".to_string());
        a.fallback_resolver_fee = Some(half);
        let err = a.validate().expect_err("should reject");
        assert!(err.contains("primary + fallback resolver fees must be < total_amount"), "got: {err}");
    }

    fn sample_signature_envelope() -> AgreementSignatureEnvelope {
        AgreementSignatureEnvelope {
            version: AGREEMENT_SIGNATURE_VERSION,
            target_type: AgreementSignatureTargetType::Agreement,
            target_hash: "11".repeat(32),
            signer_public_key: "02".to_string() + &"aa".repeat(32),
            signer_address: Some("Qsigner".to_string()),
            signature_type: AGREEMENT_SIGNATURE_TYPE_SECP256K1.to_string(),
            timestamp: Some(1_700_000_000),
            signer_role: Some("party".to_string()),
            signature: "deadbeef".to_string(),
        }
    }

    #[test]
    fn dispute_raise_round_trip_validate() {
        let d = DisputeRaise {
            version: DISPUTE_RAISE_VERSION,
            schema_id: Some(DISPUTE_RAISE_SCHEMA_ID.to_string()),
            agreement_hash: "aa".repeat(32),
            raising_party: "buyer".to_string(),
            raised_at_height: 100,
            raised_at_unix: 1_700_000_000,
            reason: "buyer paid but seller refused release".to_string(),
            initial_evidence_hash: "bb".repeat(32),
            signature: sample_signature_envelope(),
        };
        d.validate().expect("validate");
        let bytes = dispute_raise_canonical_bytes(&d).expect("canonical");
        let parsed: DisputeRaise = serde_json::from_slice(&bytes).expect("parse");
        assert_eq!(parsed, d);
    }

    #[test]
    fn dispute_evidence_validate_rejects_unknown_type() {
        let mut d = DisputeEvidence {
            version: DISPUTE_EVIDENCE_VERSION,
            schema_id: None,
            agreement_hash: "aa".repeat(32),
            submitter_party: "seller".to_string(),
            submitted_at_height: 110,
            evidence_type: "garbage".to_string(),
            evidence_payload: "AAAA".to_string(),
            evidence_hash: "cc".repeat(32),
            message: None,
            signature: sample_signature_envelope(),
        };
        let err = d.validate().expect_err("should reject");
        assert!(err.contains("evidence_type"), "got: {err}");
        d.evidence_type = "payment_proof".to_string();
        d.validate().expect("now valid");
    }

    #[test]
    fn dispute_resolution_validate_rejects_unknown_outcome() {
        let mut d = DisputeResolution {
            version: DISPUTE_RESOLUTION_VERSION,
            schema_id: None,
            agreement_hash: "aa".repeat(32),
            resolver_address: "Qresolver".to_string(),
            resolver_role: "primary".to_string(),
            outcome: "split".to_string(),
            resolved_at_height: 200,
            message: "resolved".to_string(),
            signature: sample_signature_envelope(),
        };
        let err = d.validate().expect_err("should reject");
        assert!(err.contains("outcome must be"), "got: {err}");
        d.outcome = "release".to_string();
        d.validate().expect("now valid");
    }

    #[test]
    fn resolver_registration_validate_rejects_bps_over_10000() {
        let mut r = ResolverRegistration {
            version: RESOLVER_REGISTRATION_VERSION,
            schema_id: Some(RESOLVER_REGISTRATION_SCHEMA_ID.to_string()),
            resolver_address: "Qresolver".to_string(),
            registered_at_height: 10,
            display_name: Some("Resolver One".to_string()),
            bio: None,
            fee_bps_self_quoted: Some(10_001),
            signature: sample_signature_envelope(),
        };
        let err = r.validate().expect_err("should reject");
        assert!(err.contains("fee_bps_self_quoted"), "got: {err}");
        r.fee_bps_self_quoted = Some(500);
        r.validate().expect("now valid");
    }

    #[test]
    fn agreement_anchor_role_short_codes_round_trip() {
        for role in [
            AgreementAnchorRole::DisputeRaise,
            AgreementAnchorRole::DisputeEvidence,
            AgreementAnchorRole::DisputeResolve,
            AgreementAnchorRole::ResolverRegister,
        ] {
            let code = role.short_code();
            let parsed = AgreementAnchorRole::from_short_code(code).expect("parse");
            assert_eq!(parsed, role);
        }
    }

    #[test]
    fn agreement_anchor_payload_dispute_raise_within_op_return_cap() {
        let anchor = AgreementAnchor {
            agreement_hash: "aa".repeat(32),
            role: AgreementAnchorRole::DisputeRaise,
            milestone_id: None,
        };
        let payload = build_agreement_anchor_payload(&anchor).expect("payload");
        assert!(payload.len() <= 75, "OP_RETURN cap exceeded: {}", payload.len());
        let txout = build_agreement_anchor_output(&anchor).expect("output");
        assert_eq!(txout.value, 0);
    }

    // ── GROUP D: proof schema registry validation tests ──────────────

    fn group_d_proof(
        proof_type: &str,
        typed_payload: Option<TypedProofPayload>,
    ) -> SettlementProof {
        SettlementProof {
            proof_id: "p-d-test".to_string(),
            schema_id: SETTLEMENT_PROOF_SCHEMA_ID.to_string(),
            proof_type: proof_type.to_string(),
            agreement_hash: "a".repeat(64),
            milestone_id: None,
            attested_by: "attestor-1".to_string(),
            attestation_time: 1_700_000_000,
            evidence_hash: None,
            evidence_summary: None,
            signature: ProofSignatureEnvelope {
                signature_type: AGREEMENT_SIGNATURE_TYPE_SECP256K1.to_string(),
                pubkey_hex: "00".repeat(33),
                signature_hex: "00".repeat(64),
                payload_hash: "00".repeat(32),
            },
            expires_at_height: None,
            typed_payload,
        }
    }

    fn typed_payload_with_attrs(attrs: serde_json::Value) -> TypedProofPayload {
        TypedProofPayload {
            proof_kind: "test".to_string(),
            content_hash: None,
            reference_id: None,
            attributes: Some(attrs),
        }
    }

    #[test]
    fn group_d_schema_unknown_proof_type_passes() {
        let proof = group_d_proof("legacy_made_up_type", None);
        validate_proof_against_schema(&proof).expect("unknown type must pass");
    }

    #[test]
    fn group_d_schema_legacy_delivery_confirmation_passes() {
        // The legacy '-ation' string is NOT in the schema registry; the new
        // '-ed' string IS. Legacy proofs continue working unchanged.
        let proof = group_d_proof("delivery_confirmation", None);
        validate_proof_against_schema(&proof).expect("legacy string must pass");
    }

    #[test]
    fn group_d_schema_payment_received_full_payload_accepted() {
        let attrs = serde_json::json!({
            "payment_method": "bank-transfer",
            "payment_reference": "REF-12345",
            "amount": 250.0,
            "currency": "USD",
            "timestamp": 1_700_000_000_u64,
        });
        let proof = group_d_proof(
            "payment_received",
            Some(typed_payload_with_attrs(attrs)),
        );
        validate_proof_against_schema(&proof).expect("full payload must pass");
    }

    #[test]
    fn group_d_schema_payment_received_missing_amount_rejected() {
        let attrs = serde_json::json!({
            "payment_method": "bank-transfer",
            "payment_reference": "REF-12345",
            "currency": "USD",
            "timestamp": 1_700_000_000_u64,
        });
        let proof = group_d_proof(
            "payment_received",
            Some(typed_payload_with_attrs(attrs)),
        );
        let err = validate_proof_against_schema(&proof).unwrap_err();
        assert!(
            err.contains("amount"),
            "error must name missing 'amount' field, got: {err}"
        );
    }

    #[test]
    fn group_d_schema_payment_received_no_typed_payload_rejected() {
        let proof = group_d_proof("payment_received", None);
        let err = validate_proof_against_schema(&proof).unwrap_err();
        assert!(err.contains("typed_payload"));
        assert!(err.contains("payment_method"), "error must list required fields, got: {err}");
    }

    #[test]
    fn group_d_schema_milestone_delivered_missing_milestone_id_rejected() {
        let attrs = serde_json::json!({
            "deliverable_hash": "ab".repeat(32),
            "completion_notes": "shipped",
            "timestamp": 1_700_000_000_u64,
        });
        let proof = group_d_proof(
            "milestone_delivered",
            Some(typed_payload_with_attrs(attrs)),
        );
        let err = validate_proof_against_schema(&proof).unwrap_err();
        assert!(
            err.contains("milestone_id"),
            "error must name missing 'milestone_id', got: {err}"
        );
    }

    #[test]
    fn group_d_schema_attributes_not_object_rejected() {
        let proof = group_d_proof(
            "payment_received",
            Some(typed_payload_with_attrs(serde_json::json!("not an object"))),
        );
        let err = validate_proof_against_schema(&proof).unwrap_err();
        assert!(
            err.contains("attributes must be a JSON object"),
            "error must reject non-object attributes, got: {err}"
        );
    }

    #[test]
    fn group_d_schema_work_completed_milestone_id_optional() {
        // milestone_id is in the spec as optional for work_completed; the
        // registry leaves it out of required_fields so a proof without it
        // is accepted.
        let attrs = serde_json::json!({
            "deliverable_hash": "cd".repeat(32),
            "completion_notes": "draft v2",
            "timestamp": 1_700_000_000_u64,
        });
        let proof = group_d_proof(
            "work_completed",
            Some(typed_payload_with_attrs(attrs)),
        );
        validate_proof_against_schema(&proof)
            .expect("work_completed without milestone_id must pass");
    }

    #[test]
    fn group_d_schema_null_field_treated_as_missing() {
        let attrs = serde_json::json!({
            "payment_method": "bank-transfer",
            "payment_reference": "REF-12345",
            "amount": serde_json::Value::Null,
            "currency": "USD",
            "timestamp": 1_700_000_000_u64,
        });
        let proof = group_d_proof(
            "payment_received",
            Some(typed_payload_with_attrs(attrs)),
        );
        let err = validate_proof_against_schema(&proof).unwrap_err();
        assert!(
            err.contains("amount"),
            "null value must count as missing, got: {err}"
        );
    }

    // ── GROUP F: escrow receipt ────────────────────────────────────────

    fn group_f_synthetic_lifecycle(agreement_hash: &str) -> AgreementLifecycleView {
        AgreementLifecycleView {
            state: AgreementLifecycleState::Funded,
            agreement_hash: agreement_hash.to_string(),
            funded_amount: 500_000_000,
            released_amount: 0,
            refunded_amount: 0,
            milestones: vec![],
            linked_txs: vec![AgreementLinkedTx {
                txid: "cd".repeat(32),
                role: AgreementAnchorRole::OtcSettlement,
                milestone_id: None,
                height: Some(101),
                confirmed: true,
                value: 500_000_000,
            }],
            trust_model_note: "test".to_string(),
        }
    }

    #[test]
    fn group_f_build_escrow_receipt_unsigned_carries_chain_data() {
        let agreement = build_test_otc();
        let hash = compute_agreement_hash_hex(&agreement).unwrap();
        let lifecycle = group_f_synthetic_lifecycle(&hash);
        let receipt = build_escrow_receipt_unsigned(
            &agreement,
            &hash,
            &lifecycle,
            &[],
            None,
            "Qbuyer",
            "03aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
            1_700_000_001,
        );
        assert_eq!(receipt.schema_id, ESCROW_RECEIPT_SCHEMA_ID);
        assert_eq!(receipt.version, ESCROW_RECEIPT_VERSION);
        assert_eq!(receipt.agreement_hash, hash);
        assert_eq!(receipt.funding_txids.len(), 1);
        assert_eq!(receipt.funding_txids[0].txid, "cd".repeat(32));
        assert_eq!(receipt.funding_txids[0].value, 500_000_000);
        assert_eq!(receipt.funded_amount, 500_000_000);
        assert!(receipt.exporter_signature.signature.is_empty());
        assert!(receipt.exporter_signature.payload_hash.is_empty());
        assert_eq!(receipt.exporter_address, "Qbuyer");
    }

    #[test]
    fn group_f_escrow_receipt_canonical_clears_signature_and_payload_hash() {
        let agreement = build_test_otc();
        let hash = compute_agreement_hash_hex(&agreement).unwrap();
        let lifecycle = group_f_synthetic_lifecycle(&hash);
        let mut receipt = build_escrow_receipt_unsigned(
            &agreement,
            &hash,
            &lifecycle,
            &[],
            None,
            "Qbuyer",
            "03aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
            1_700_000_001,
        );
        let bytes_empty = escrow_receipt_canonical_bytes(&receipt).unwrap();
        receipt.exporter_signature.signature = "ff".repeat(32);
        receipt.exporter_signature.payload_hash = "ee".repeat(32);
        let bytes_filled = escrow_receipt_canonical_bytes(&receipt).unwrap();
        assert_eq!(
            bytes_empty, bytes_filled,
            "canonical bytes must be independent of signature/payload_hash"
        );
    }

    #[test]
    fn group_f_escrow_receipt_dispute_message_hashed_not_leaked() {
        let agreement = build_test_otc();
        let hash = compute_agreement_hash_hex(&agreement).unwrap();
        let lifecycle = group_f_synthetic_lifecycle(&hash);
        let secret_msg =
            "RESOLVER PRIVATE NOTE — do not leak in exported receipts.";
        let dispute = DisputeResolution {
            version: DISPUTE_RESOLUTION_VERSION,
            schema_id: None,
            agreement_hash: hash.clone(),
            resolver_address: "Qresolver".to_string(),
            resolver_role: "primary".to_string(),
            outcome: "release".to_string(),
            resolved_at_height: 250,
            message: secret_msg.to_string(),
            signature: AgreementSignatureEnvelope {
                version: AGREEMENT_SIGNATURE_VERSION,
                target_type: AgreementSignatureTargetType::Agreement,
                target_hash: hash.clone(),
                signer_public_key: "03".to_string() + &"aa".repeat(32),
                signer_address: Some("Qresolver".to_string()),
                signature_type: AGREEMENT_SIGNATURE_TYPE_SECP256K1.to_string(),
                timestamp: None,
                signer_role: Some("resolver".to_string()),
                signature: "00".repeat(64),
            },
        };
        let receipt = build_escrow_receipt_unsigned(
            &agreement,
            &hash,
            &lifecycle,
            &[],
            Some((&dispute, Some("aa".repeat(32)))),
            "Qbuyer",
            "03aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
            1_700_000_001,
        );
        let dref = receipt.dispute.as_ref().expect("dispute ref must be present");
        let expected_hash = hex::encode(Sha256::digest(secret_msg.as_bytes()));
        assert_eq!(dref.message_hash, expected_hash);
        let canonical = String::from_utf8(escrow_receipt_canonical_bytes(&receipt).unwrap())
            .unwrap();
        assert!(
            !canonical.contains("PRIVATE NOTE"),
            "raw dispute message must NOT appear in canonical receipt bytes"
        );
        assert_eq!(dref.outcome, "release");
        assert_eq!(dref.resolver_address, "Qresolver");
    }

    // ── GROUP G: partial milestone release lifecycle ─────────────────────

    fn group_g_three_milestone_agreement() -> AgreementObject {
        let payer = AgreementParty {
            party_id: "payer".to_string(),
            display_name: "Payer".to_string(),
            address: "Qpayer".to_string(),
            role: Some("buyer".to_string()),
        };
        let payee = AgreementParty {
            party_id: "payee".to_string(),
            display_name: "Payee".to_string(),
            address: "Qpayee".to_string(),
            role: Some("seller".to_string()),
        };
        let milestones = (1..=3u32)
            .map(|i| AgreementMilestone {
                milestone_id: format!("m{}", i),
                title: format!("Milestone {}", i),
                amount: 100_000,
                recipient_address: "Qpayee".to_string(),
                refund_address: "Qpayer".to_string(),
                secret_hash_hex: format!("{:02x}", i).repeat(32),
                timeout_height: 1_000 + (i as u64) * 100,
                metadata_hash: None,
            })
            .collect();
        build_milestone_agreement(
            "agr-g-test".to_string(),
            1_700_000_000,
            payer,
            payee,
            milestones,
            10_000,
            "cd".repeat(32),
            None,
            None,
        )
        .expect("build milestone agreement")
    }

    fn group_g_funding_tx(milestone_id: &str, height: u64) -> AgreementLinkedTx {
        AgreementLinkedTx {
            txid: format!("aa{}", milestone_id).repeat(2),
            role: AgreementAnchorRole::Funding,
            milestone_id: Some(milestone_id.to_string()),
            height: Some(height),
            confirmed: true,
            value: 100_000,
        }
    }

    fn group_g_milestone_release_tx(milestone_id: &str, height: u64) -> AgreementLinkedTx {
        AgreementLinkedTx {
            txid: format!("bb{}", milestone_id).repeat(2),
            role: AgreementAnchorRole::MilestoneRelease,
            milestone_id: Some(milestone_id.to_string()),
            height: Some(height),
            confirmed: true,
            value: 100_000,
        }
    }

    #[test]
    fn group_g_lifecycle_funded_when_zero_milestones_released() {
        let agreement = group_g_three_milestone_agreement();
        let hash = compute_agreement_hash_hex(&agreement).unwrap();
        let linked = vec![
            group_g_funding_tx("m1", 200),
            group_g_funding_tx("m2", 201),
            group_g_funding_tx("m3", 202),
        ];
        let lifecycle = derive_lifecycle(&agreement, &hash, linked, 500);
        assert!(
            matches!(lifecycle.state, AgreementLifecycleState::Funded),
            "expected Funded, got {:?}",
            lifecycle.state
        );
        assert_eq!(lifecycle.released_amount, 0);
        assert_eq!(lifecycle.funded_amount, 300_000);
    }

    #[test]
    fn group_g_lifecycle_partially_released_when_one_of_three_released() {
        let agreement = group_g_three_milestone_agreement();
        let hash = compute_agreement_hash_hex(&agreement).unwrap();
        let linked = vec![
            group_g_funding_tx("m1", 200),
            group_g_funding_tx("m2", 201),
            group_g_funding_tx("m3", 202),
            group_g_milestone_release_tx("m2", 300),
        ];
        let lifecycle = derive_lifecycle(&agreement, &hash, linked, 500);
        assert!(
            matches!(lifecycle.state, AgreementLifecycleState::PartiallyReleased),
            "expected PartiallyReleased, got {:?}",
            lifecycle.state
        );
        assert_eq!(lifecycle.released_amount, 100_000);
        assert_eq!(lifecycle.funded_amount, 300_000);
        let m2 = lifecycle
            .milestones
            .iter()
            .find(|m| m.milestone_id == "m2")
            .expect("m2 in lifecycle");
        assert!(m2.released, "m2 must be marked released");
        let m1 = lifecycle
            .milestones
            .iter()
            .find(|m| m.milestone_id == "m1")
            .expect("m1 in lifecycle");
        assert!(!m1.released, "m1 must NOT be marked released");
    }

    #[test]
    fn group_g_lifecycle_partially_released_two_of_three() {
        let agreement = group_g_three_milestone_agreement();
        let hash = compute_agreement_hash_hex(&agreement).unwrap();
        let linked = vec![
            group_g_funding_tx("m1", 200),
            group_g_funding_tx("m2", 201),
            group_g_funding_tx("m3", 202),
            group_g_milestone_release_tx("m1", 300),
            group_g_milestone_release_tx("m2", 301),
        ];
        let lifecycle = derive_lifecycle(&agreement, &hash, linked, 500);
        assert!(
            matches!(lifecycle.state, AgreementLifecycleState::PartiallyReleased),
            "expected PartiallyReleased with 2/3 released, got {:?}",
            lifecycle.state
        );
        assert_eq!(lifecycle.released_amount, 200_000);
        assert!(lifecycle
            .milestones
            .iter()
            .find(|m| m.milestone_id == "m1")
            .unwrap()
            .released);
        assert!(lifecycle
            .milestones
            .iter()
            .find(|m| m.milestone_id == "m2")
            .unwrap()
            .released);
        assert!(!lifecycle
            .milestones
            .iter()
            .find(|m| m.milestone_id == "m3")
            .unwrap()
            .released);
    }

    #[test]
    fn group_g_milestone_status_marks_only_funded_milestones() {
        let agreement = group_g_three_milestone_agreement();
        let hash = compute_agreement_hash_hex(&agreement).unwrap();
        // Only m1 and m3 funded; m2 not funded.
        let linked = vec![
            group_g_funding_tx("m1", 200),
            group_g_funding_tx("m3", 202),
        ];
        let lifecycle = derive_lifecycle(&agreement, &hash, linked, 500);
        let m1 = lifecycle
            .milestones
            .iter()
            .find(|m| m.milestone_id == "m1")
            .unwrap();
        let m2 = lifecycle
            .milestones
            .iter()
            .find(|m| m.milestone_id == "m2")
            .unwrap();
        let m3 = lifecycle
            .milestones
            .iter()
            .find(|m| m.milestone_id == "m3")
            .unwrap();
        assert!(m1.funded, "m1 must be funded");
        assert!(!m2.funded, "m2 must NOT be funded");
        assert!(m3.funded, "m3 must be funded");
        assert_eq!(lifecycle.funded_amount, 200_000);
    }

    #[test]
    fn group_g_lifecycle_released_when_all_three_released() {
        let agreement = group_g_three_milestone_agreement();
        let hash = compute_agreement_hash_hex(&agreement).unwrap();
        let linked = vec![
            group_g_funding_tx("m1", 200),
            group_g_funding_tx("m2", 201),
            group_g_funding_tx("m3", 202),
            group_g_milestone_release_tx("m1", 300),
            group_g_milestone_release_tx("m2", 301),
            group_g_milestone_release_tx("m3", 302),
        ];
        let lifecycle = derive_lifecycle(&agreement, &hash, linked, 500);
        assert!(
            matches!(lifecycle.state, AgreementLifecycleState::Released),
            "expected Released, got {:?}",
            lifecycle.state
        );
        assert_eq!(lifecycle.released_amount, 300_000);
        assert!(
            lifecycle.milestones.iter().all(|m| m.released),
            "all milestones must be marked released"
        );
    }

    #[test]
    fn group_f_verify_escrow_receipt_rejects_wrong_schema_id() {
        let agreement = build_test_otc();
        let hash = compute_agreement_hash_hex(&agreement).unwrap();
        let lifecycle = group_f_synthetic_lifecycle(&hash);
        let mut receipt = build_escrow_receipt_unsigned(
            &agreement,
            &hash,
            &lifecycle,
            &[],
            None,
            "Qbuyer",
            "03aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
            1_700_000_001,
        );
        receipt.schema_id = "bogus.schema".to_string();
        receipt.exporter_signature.signature = "ab".repeat(32);
        let err = verify_escrow_receipt_signature(&receipt).unwrap_err();
        assert!(
            err.contains("schema_id"),
            "wrong schema_id must be rejected, got: {err}"
        );
    }

    // ── GROUP H: on-chain reputation event anchoring ─────────────────────

    #[test]
    fn group_h_reputation_event_payload_roundtrip_successful_trade() {
        let event = ReputationEvent {
            kind: ReputationEventKind::SuccessfulTrade,
            address: "Qabc123def456".to_string(),
            agreement_short_hash: None,
        };
        let payload = build_reputation_event_payload(&event).unwrap();
        let s = std::str::from_utf8(&payload).unwrap();
        assert!(s.starts_with("rep1:s:Q"));
        let output = build_reputation_event_output(&event).unwrap();
        let parsed = parse_reputation_event(&output.script_pubkey).expect("parse round-trip");
        assert_eq!(parsed, event);
    }

    #[test]
    fn group_h_reputation_event_payload_roundtrip_resolver_non_response_carries_short_hash() {
        let event = ReputationEvent {
            kind: ReputationEventKind::ResolverNonResponse,
            address: "Qresolver1234567".to_string(),
            agreement_short_hash: Some("ab".repeat(8)),
        };
        let output = build_reputation_event_output(&event).unwrap();
        let parsed = parse_reputation_event(&output.script_pubkey).expect("parse round-trip");
        assert_eq!(parsed, event);
        assert_eq!(parsed.agreement_short_hash.as_deref(), Some("abababababababab"));
    }

    #[test]
    fn group_h_reputation_event_payload_too_long_rejected() {
        let event = ReputationEvent {
            kind: ReputationEventKind::SuccessfulTrade,
            address: "Q".to_string() + &"x".repeat(80),
            agreement_short_hash: None,
        };
        let err = build_reputation_event_payload(&event).unwrap_err();
        assert!(
            err.contains("too large"),
            "expected too-large error, got: {err}"
        );
    }

    #[test]
    fn group_h_parse_rejects_wrong_prefix() {
        // OP_RETURN with an agr1 payload must not parse as a reputation event.
        let agr_payload = b"agr1:l:".to_vec();
        let mut hash_part = "ab".repeat(32).into_bytes();
        let mut all = agr_payload;
        all.append(&mut hash_part);
        let mut script = vec![0x6a, all.len() as u8];
        script.extend_from_slice(&all);
        assert!(parse_reputation_event(&script).is_none());
    }

    #[test]
    fn group_h_parse_rejects_unknown_event_short_code() {
        let payload = b"rep1:z:Qabc".to_vec();
        let mut script = vec![0x6a, payload.len() as u8];
        script.extend_from_slice(&payload);
        assert!(parse_reputation_event(&script).is_none());
    }

    #[test]
    fn group_h_resolver_non_response_missing_short_hash_rejected() {
        let event = ReputationEvent {
            kind: ReputationEventKind::ResolverNonResponse,
            address: "Qresolver".to_string(),
            agreement_short_hash: None,
        };
        let err = build_reputation_event_payload(&event).unwrap_err();
        assert!(
            err.contains("agreement_short_hash"),
            "expected required-short-hash error, got: {err}"
        );
    }

    #[test]
    fn group_h_successful_trade_with_short_hash_rejected() {
        let event = ReputationEvent {
            kind: ReputationEventKind::SuccessfulTrade,
            address: "Qabc".to_string(),
            agreement_short_hash: Some("ab".repeat(8)),
        };
        let err = build_reputation_event_payload(&event).unwrap_err();
        assert!(
            err.contains("only valid for ResolverNonResponse"),
            "expected only-valid-for-non-response error, got: {err}"
        );
    }

    #[test]
    fn group_h_agreement_short_hash_from_full_takes_first_16_chars() {
        let full = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
        let short = agreement_short_hash_from_full(full).unwrap();
        assert_eq!(short, "aabbccddeeff0011");
        assert_eq!(short.len(), 16);
        assert!(agreement_short_hash_from_full("not-hex").is_err());
    }
}
