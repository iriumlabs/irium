//! Phase 31: PoAW-X reward manifest wrapper, role caps, deterministic fallback.
//!
//! A PURE formalization AROUND the existing, working reward primitives
//! (`poawx::multi_role_amounts`, `poawx::apply_fee`, the canonical coinbase
//! validator `chain::validate_poawx_coinbase_payout`). It does NOT change the
//! production reward path; it provides a versioned, cap-checked, fallback-aware
//! manifest plus an ADDITIVE (gated, off-by-default, mainnet-hard-off) consensus
//! cap gate that is a strict SUPERSET of the existing exact-match validation
//! (it can only add rejections, never weaken or false-reject).
//!
//! Caps are rounding-aware: compute/verify/support are hard-capped at their bps
//! floors; PRIMARY is the RESIDUAL (`total - others`) and absorbs the ≤3-wei
//! rounding remainder (so a naive `primary <= 55%` ceiling would be wrong). The
//! fallback policy is non-inflationary: absent roles are simply not minted.
//! Testnet/devnet only; mainnet hard-off (`network_id == 0`).
#![allow(dead_code)]

use crate::activation::network_id_byte;
use crate::poawx::{
    MULTI_ROLE_COMPUTE_BPS, MULTI_ROLE_PRIMARY_BPS, MULTI_ROLE_SUPPORT_BPS, MULTI_ROLE_VERIFY_BPS,
    THIRD_PARTY_FEE_CAP_BPS,
};
use sha2::{Digest, Sha256};

pub const REWARD_MANIFEST_VERSION: u8 = 1;
const MANIFEST_DOMAIN: &[u8] = b"IRIUM_POAWX_REWARD_MANIFEST_V1";

/// C1: trailing `RMF1` block-carried reward-manifest section magic (mirrors the
/// DMC1/ADM1 pattern). Present-only; absent ⇒ byte-identical to pre-RMF1 exts.
pub const REWARD_MANIFEST_SECTION_MAGIC: &[u8; 4] = b"RMF1";
/// version(1)+network(1)+height(8)+total(8)+fee_bps(2)+fee_pkh(20)+fallback(1)
/// + 4 × output{ role(1)+pkh(20)+amount(8)+present(1) } = 41 + 120 = 161 bytes.
pub const REWARD_MANIFEST_WIRE: usize = 1 + 1 + 8 + 8 + 2 + 20 + 1 + 4 * (1 + 20 + 8 + 1);

// ── Roles + caps ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoawxRewardRole {
    Primary,
    Compute,
    Verify,
    Support,
}

impl PoawxRewardRole {
    pub fn id(self) -> u8 {
        match self {
            PoawxRewardRole::Primary => 0,
            PoawxRewardRole::Compute => 1,
            PoawxRewardRole::Verify => 2,
            PoawxRewardRole::Support => 3,
        }
    }
    pub fn bps(self) -> u64 {
        match self {
            PoawxRewardRole::Primary => MULTI_ROLE_PRIMARY_BPS,
            PoawxRewardRole::Compute => MULTI_ROLE_COMPUTE_BPS,
            PoawxRewardRole::Verify => MULTI_ROLE_VERIFY_BPS,
            PoawxRewardRole::Support => MULTI_ROLE_SUPPORT_BPS,
        }
    }
    pub fn from_id(id: u8) -> Option<Self> {
        match id {
            0 => Some(PoawxRewardRole::Primary),
            1 => Some(PoawxRewardRole::Compute),
            2 => Some(PoawxRewardRole::Verify),
            3 => Some(PoawxRewardRole::Support),
            _ => None,
        }
    }
}

impl PoawxRewardFallbackMode {
    pub fn to_byte(self) -> u8 {
        match self {
            PoawxRewardFallbackMode::FullParticipation => 0,
            PoawxRewardFallbackMode::PresentRolesOnly => 1,
        }
    }
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(PoawxRewardFallbackMode::FullParticipation),
            1 => Some(PoawxRewardFallbackMode::PresentRolesOnly),
            _ => None,
        }
    }
}

/// A per-role reward ceiling (bps of the total). For non-primary roles this is a
/// hard cap; PRIMARY is validated as the residual (`total - others`) instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoawxRoleRewardCap {
    pub role: PoawxRewardRole,
    pub bps: u64,
}

impl PoawxRoleRewardCap {
    pub fn for_role(role: PoawxRewardRole) -> Self {
        Self {
            role,
            bps: role.bps(),
        }
    }
    /// floor(bps * total / 10000) — the hard ceiling for a non-primary role.
    pub fn ceiling(&self, total: u64) -> u64 {
        ((total as u128 * self.bps as u128) / 10000u128) as u64
    }
}

/// Deterministic fallback policy for participation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoawxRewardFallbackMode {
    /// All four roles have valid recipients (the only production mode today): the
    /// canonical exact split is paid in full.
    FullParticipation,
    /// Low participation: only roles with a valid recipient are minted; absent role
    /// shares are NOT minted (non-inflationary). Pure spec; not the production path.
    PresentRolesOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoawxRewardManifestValidationError {
    WrongVersion,
    WrongNetwork,
    MainnetHardOff,
    RoleCapExceeded(PoawxRewardRole),
    PrimaryNotResidual,
    TotalOverpay,
    SumMismatch,
    FeeOverCap,
    PenalizedRecipient(PoawxRewardRole),
    DigestMismatch,
}

impl std::fmt::Display for PoawxRewardManifestValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use PoawxRewardManifestValidationError::*;
        match self {
            WrongVersion => write!(f, "phase31: reward manifest wrong version"),
            WrongNetwork => write!(f, "phase31: reward manifest wrong network"),
            MainnetHardOff => write!(f, "phase31: reward manifest mainnet hard-off"),
            RoleCapExceeded(r) => write!(f, "phase31: role {:?} reward exceeds cap", r),
            PrimaryNotResidual => write!(f, "phase31: primary reward is not the residual"),
            TotalOverpay => write!(f, "phase31: total reward exceeds subsidy + fees"),
            SumMismatch => write!(f, "phase31: role rewards do not sum to minted total"),
            FeeOverCap => write!(f, "phase31: fee exceeds third-party cap"),
            PenalizedRecipient(r) => write!(f, "phase31: role {:?} recipient is penalized", r),
            DigestMismatch => write!(f, "phase31: reward manifest digest mismatch"),
        }
    }
}

// ── Role output + manifest ───────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoawxRewardRoleOutput {
    pub role: PoawxRewardRole,
    pub pkh: [u8; 20],
    pub amount: u64,
    pub present: bool,
}

/// Versioned, pure reward manifest. Derived from existing data (no new wire field
/// or block root). `outputs` are the GROSS role allocations in canonical order
/// `[Primary, Compute, Verify, Support]`; `total_reward` is the subsidy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoawxRewardManifestV1 {
    pub version: u8,
    pub network_id: u8,
    pub block_height: u64,
    pub total_reward: u64,
    pub fee_bps: u16,
    pub fee_pkh: [u8; 20],
    pub fallback: PoawxRewardFallbackMode,
    pub outputs: [PoawxRewardRoleOutput; 4],
}

/// Rounding-aware role amounts with a deterministic, non-inflationary fallback.
/// `present[i]` flags whether role i has a valid recipient. Present non-primary
/// roles get their bps floor; absent roles get 0 (NOT minted). The rounding
/// remainder attaches to PRIMARY when present, else it is not minted. Returns the
/// four amounts `[primary, compute, verify, support]`; their sum (the MINTED
/// total) is always <= `total`.
pub fn role_amounts_with_fallback(total: u64, present: [bool; 4]) -> [u64; 4] {
    let floor = |bps: u64| -> u64 { ((total as u128 * bps as u128) / 10000u128) as u64 };
    let c = if present[1] {
        floor(MULTI_ROLE_COMPUTE_BPS)
    } else {
        0
    };
    let v = if present[2] {
        floor(MULTI_ROLE_VERIFY_BPS)
    } else {
        0
    };
    let s = if present[3] {
        floor(MULTI_ROLE_SUPPORT_BPS)
    } else {
        0
    };
    // Full-split remainder = total - sum(all four floors). It legitimately belongs
    // to PRIMARY (the residual). When PRIMARY is present it is added to PRIMARY's
    // floor; otherwise it is not minted (non-inflationary).
    let primary_floor = floor(MULTI_ROLE_PRIMARY_BPS);
    let remainder = total
        - primary_floor
        - floor(MULTI_ROLE_COMPUTE_BPS)
        - floor(MULTI_ROLE_VERIFY_BPS)
        - floor(MULTI_ROLE_SUPPORT_BPS);
    let p = if present[0] {
        primary_floor + remainder
    } else {
        0
    };
    [p, c, v, s]
}

impl PoawxRewardManifestV1 {
    /// Full-participation manifest (the production case): the canonical exact split.
    pub fn new_full(
        network_id: u8,
        block_height: u64,
        total_reward: u64,
        primary_pkh: [u8; 20],
        compute_pkh: [u8; 20],
        verify_pkh: [u8; 20],
        support_pkh: [u8; 20],
        fee_bps: u16,
        fee_pkh: [u8; 20],
    ) -> Self {
        let amts = crate::poawx::multi_role_amounts(total_reward);
        Self {
            version: REWARD_MANIFEST_VERSION,
            network_id,
            block_height,
            total_reward,
            fee_bps,
            fee_pkh,
            fallback: PoawxRewardFallbackMode::FullParticipation,
            outputs: [
                role_out(PoawxRewardRole::Primary, primary_pkh, amts[0], true),
                role_out(PoawxRewardRole::Compute, compute_pkh, amts[1], true),
                role_out(PoawxRewardRole::Verify, verify_pkh, amts[2], true),
                role_out(PoawxRewardRole::Support, support_pkh, amts[3], true),
            ],
        }
    }

    /// Low-participation manifest: present roles only. `recipients[i] == None`
    /// means role i is absent and its share is NOT minted (non-inflationary).
    pub fn new_fallback(
        network_id: u8,
        block_height: u64,
        total_reward: u64,
        recipients: [Option<[u8; 20]>; 4],
        fee_bps: u16,
        fee_pkh: [u8; 20],
    ) -> Self {
        let present = [
            recipients[0].is_some(),
            recipients[1].is_some(),
            recipients[2].is_some(),
            recipients[3].is_some(),
        ];
        let amts = role_amounts_with_fallback(total_reward, present);
        let role_of = |i: usize| match i {
            0 => PoawxRewardRole::Primary,
            1 => PoawxRewardRole::Compute,
            2 => PoawxRewardRole::Verify,
            _ => PoawxRewardRole::Support,
        };
        let mk = |i: usize| {
            role_out(
                role_of(i),
                recipients[i].unwrap_or([0u8; 20]),
                amts[i],
                present[i],
            )
        };
        Self {
            version: REWARD_MANIFEST_VERSION,
            network_id,
            block_height,
            total_reward,
            fee_bps,
            fee_pkh,
            fallback: PoawxRewardFallbackMode::PresentRolesOnly,
            outputs: [mk(0), mk(1), mk(2), mk(3)],
        }
    }

    /// Minted total = sum of role amounts (always <= total_reward).
    pub fn minted_total(&self) -> u64 {
        self.outputs
            .iter()
            .fold(0u64, |a, o| a.saturating_add(o.amount))
    }

    /// Deterministic digest (for tests/observability; NOT a new consensus root).
    pub fn manifest_digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(MANIFEST_DOMAIN);
        h.update([self.version]);
        h.update([self.network_id]);
        h.update(self.block_height.to_le_bytes());
        h.update(self.total_reward.to_le_bytes());
        h.update(self.fee_bps.to_le_bytes());
        h.update(self.fee_pkh);
        for o in &self.outputs {
            h.update([o.role.id()]);
            h.update(o.pkh);
            h.update(o.amount.to_le_bytes());
            h.update([o.present as u8]);
        }
        h.finalize().into()
    }

    /// C1: fixed-size wire encoding for the block-carried `RMF1` section.
    pub fn serialize(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(REWARD_MANIFEST_WIRE);
        o.push(self.version);
        o.push(self.network_id);
        o.extend_from_slice(&self.block_height.to_le_bytes());
        o.extend_from_slice(&self.total_reward.to_le_bytes());
        o.extend_from_slice(&self.fee_bps.to_le_bytes());
        o.extend_from_slice(&self.fee_pkh);
        o.push(self.fallback.to_byte());
        for out in &self.outputs {
            o.push(out.role.id());
            o.extend_from_slice(&out.pkh);
            o.extend_from_slice(&out.amount.to_le_bytes());
            o.push(out.present as u8);
        }
        o
    }

    /// C1: parse the fixed-size `RMF1` wire encoding. Strict: exact length, known
    /// version, canonical role order `[Primary, Compute, Verify, Support]`, valid
    /// fallback/present bytes.
    pub fn deserialize(raw: &[u8]) -> Result<Self, String> {
        if raw.len() != REWARD_MANIFEST_WIRE {
            return Err("reward manifest: bad length".to_string());
        }
        if raw[0] != REWARD_MANIFEST_VERSION {
            return Err("reward manifest: bad version".to_string());
        }
        let network_id = raw[1];
        let block_height = u64::from_le_bytes(raw[2..10].try_into().expect("8"));
        let total_reward = u64::from_le_bytes(raw[10..18].try_into().expect("8"));
        let fee_bps = u16::from_le_bytes(raw[18..20].try_into().expect("2"));
        let mut fee_pkh = [0u8; 20];
        fee_pkh.copy_from_slice(&raw[20..40]);
        let fallback = PoawxRewardFallbackMode::from_byte(raw[40])
            .ok_or_else(|| "reward manifest: bad fallback".to_string())?;
        let mut outputs: [PoawxRewardRoleOutput; 4] =
            [role_out(PoawxRewardRole::Primary, [0u8; 20], 0, false); 4];
        let mut off = 41usize;
        for (i, expected) in [
            PoawxRewardRole::Primary,
            PoawxRewardRole::Compute,
            PoawxRewardRole::Verify,
            PoawxRewardRole::Support,
        ]
        .iter()
        .enumerate()
        {
            let role = PoawxRewardRole::from_id(raw[off])
                .ok_or_else(|| "reward manifest: bad role id".to_string())?;
            if role != *expected {
                return Err("reward manifest: non-canonical role order".to_string());
            }
            off += 1;
            let mut pkh = [0u8; 20];
            pkh.copy_from_slice(&raw[off..off + 20]);
            off += 20;
            let amount = u64::from_le_bytes(raw[off..off + 8].try_into().expect("8"));
            off += 8;
            let present = match raw[off] {
                0 => false,
                1 => true,
                _ => return Err("reward manifest: bad present flag".to_string()),
            };
            off += 1;
            outputs[i] = role_out(role, pkh, amount, present);
        }
        Ok(Self {
            version: REWARD_MANIFEST_VERSION,
            network_id,
            block_height,
            total_reward,
            fee_bps,
            fee_pkh,
            fallback,
            outputs,
        })
    }

    /// Validate caps + non-inflation (rounding-aware). `subsidy`/`fees` bound the
    /// declared total. Pure; mainnet hard-off. This is ADDITIVE to the existing
    /// exact-match coinbase validation — it only adds rejections.
    pub fn validate_caps(
        &self,
        expected_network: u8,
        subsidy: u64,
        fees: u64,
    ) -> Result<(), PoawxRewardManifestValidationError> {
        use PoawxRewardManifestValidationError::*;
        if expected_network == 0 {
            return Err(MainnetHardOff);
        }
        if self.version != REWARD_MANIFEST_VERSION {
            return Err(WrongVersion);
        }
        if self.network_id != expected_network {
            return Err(WrongNetwork);
        }
        // Declared total must not exceed subsidy + fees.
        if self.total_reward > subsidy.saturating_add(fees) {
            return Err(TotalOverpay);
        }
        // Fee within the third-party cap.
        if self.fee_bps > THIRD_PARTY_FEE_CAP_BPS {
            return Err(FeeOverCap);
        }
        // Non-primary role hard caps (floors). Absent roles must be 0.
        for (i, role) in [
            PoawxRewardRole::Compute,
            PoawxRewardRole::Verify,
            PoawxRewardRole::Support,
        ]
        .iter()
        .enumerate()
        {
            let o = &self.outputs[i + 1];
            let cap = PoawxRoleRewardCap::for_role(*role).ceiling(self.total_reward);
            if !o.present {
                if o.amount != 0 {
                    return Err(RoleCapExceeded(*role));
                }
                continue;
            }
            if o.amount > cap {
                return Err(RoleCapExceeded(*role));
            }
        }
        // PRIMARY is the residual: amount == total - (present non-primary roles).
        let others = self.outputs[1].amount + self.outputs[2].amount + self.outputs[3].amount;
        let primary = &self.outputs[0];
        if primary.present {
            // residual rule: primary == total_reward - others (full participation)
            // OR primary == primary_floor + remainder (fallback already encodes this).
            if primary.amount.saturating_add(others) != self.minted_total() {
                return Err(SumMismatch);
            }
            // primary must never exceed the declared total.
            if primary.amount > self.total_reward {
                return Err(RoleCapExceeded(PoawxRewardRole::Primary));
            }
        } else if primary.amount != 0 {
            return Err(RoleCapExceeded(PoawxRewardRole::Primary));
        }
        // Minted total must not exceed declared total (non-inflationary).
        if self.minted_total() > self.total_reward {
            return Err(TotalOverpay);
        }
        Ok(())
    }

    /// Validate the manifest against an actual coinbase: FIRST the existing
    /// canonical exact-match validator (strict; unchanged), THEN the additive
    /// caps. A strict superset of the existing check.
    pub fn validate_against_coinbase(
        &self,
        outputs: &[crate::tx::TxOutput],
        primary_pkh: &[u8; 20],
        role: &crate::poawx::RoleReward,
        fee: Option<(u16, [u8; 20])>,
        subsidy: u64,
        fees: u64,
    ) -> Result<(), String> {
        crate::chain::validate_poawx_coinbase_payout(
            outputs,
            primary_pkh,
            self.total_reward,
            Some(role),
            fee,
        )?;
        self.validate_caps(self.network_id, subsidy, fees)
            .map_err(|e| e.to_string())
    }

    /// Phase 30 link: the SUPPORT/finality recipient must not be a penalized
    /// (suspended) signer. Pure; reuses the double-sign penalty state.
    pub fn validate_finality_recipient_eligibility(
        &self,
        penalty: &crate::poawx_doublesign::PoawxDoubleSignPenaltyState,
        current_epoch: u64,
    ) -> Result<(), PoawxRewardManifestValidationError> {
        let support = &self.outputs[3];
        if support.present
            && support.amount > 0
            && !penalty.is_eligible_for_finality(&support.pkh, current_epoch)
        {
            return Err(PoawxRewardManifestValidationError::PenalizedRecipient(
                PoawxRewardRole::Support,
            ));
        }
        Ok(())
    }
}

fn role_out(
    role: PoawxRewardRole,
    pkh: [u8; 20],
    amount: u64,
    present: bool,
) -> PoawxRewardRoleOutput {
    PoawxRewardRoleOutput {
        role,
        pkh,
        amount,
        present,
    }
}

// ── Additive consensus cap gate (testnet-only; mainnet hard-off; off by default) ─

pub fn reward_manifest_caps_activation_height() -> Option<u64> {
    std::env::var("IRIUM_POAWX_REWARD_MANIFEST_CAPS_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

pub fn reward_manifest_caps_gate(network_id: u8, activation: Option<u64>, height: u64) -> bool {
    if network_id == 0 {
        return false;
    }
    matches!(activation, Some(h) if height >= h)
}

pub fn reward_manifest_caps_active(height: u64) -> bool {
    reward_manifest_caps_gate(
        network_id_byte(),
        reward_manifest_caps_activation_height(),
        height,
    )
}

pub fn reward_manifest_caps_required() -> bool {
    if network_id_byte() == 0 {
        return false;
    }
    std::env::var("IRIUM_POAWX_REWARD_MANIFEST_CAPS_REQUIRED")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}

/// Additive cap gate is ON only when active at `height` AND required. Mainnet
/// hard-off. When ON, `validate_phase20_production_block` re-derives the manifest
/// and runs `validate_caps` as defense-in-depth (a strict superset of the existing
/// exact-match check). OFF by default ⇒ zero regression.
pub fn reward_manifest_caps_enforced(height: u64) -> bool {
    reward_manifest_caps_active(height) && reward_manifest_caps_required()
}

/// C1: whether the block-carried `RMF1` SECTION must be PRESENT. This is a SEPARATE
/// flag from the cap-validation `*_CAPS_REQUIRED` (which only requires the additive
/// cap check, NOT a carried section). Off by default ⇒ pre-RMF1 / legacy blocks are
/// accepted even when the cap gate is required. Mainnet hard-off.
pub fn reward_manifest_section_required() -> bool {
    if network_id_byte() == 0 {
        return false;
    }
    std::env::var("IRIUM_POAWX_REWARD_MANIFEST_REQUIRED")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}

/// The `RMF1` section is required-present only when the reward-manifest gate is
/// active AND the section-required flag is set. Mainnet hard-off.
pub fn reward_manifest_section_enforced(height: u64) -> bool {
    reward_manifest_caps_active(height) && reward_manifest_section_required()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NET: u8 = 1;
    const SUBSIDY: u64 = 50_000_000_000; // 50 IRM in base units (example)

    fn full(total: u64) -> PoawxRewardManifestV1 {
        PoawxRewardManifestV1::new_full(
            NET,
            10,
            total,
            [0x01u8; 20],
            [0x02u8; 20],
            [0x03u8; 20],
            [0x04u8; 20],
            0,
            [0u8; 20],
        )
    }

    #[test]
    fn phase31_valid_reward_manifest_accepts_55_22_13_10() {
        let m = full(SUBSIDY);
        // exact bps amounts.
        assert_eq!(m.outputs[1].amount, SUBSIDY * 2200 / 10000);
        assert_eq!(m.outputs[2].amount, SUBSIDY * 1300 / 10000);
        assert_eq!(m.outputs[3].amount, SUBSIDY * 1000 / 10000);
        // primary is the residual.
        assert_eq!(
            m.outputs[0].amount,
            SUBSIDY - m.outputs[1].amount - m.outputs[2].amount - m.outputs[3].amount
        );
        assert_eq!(m.minted_total(), SUBSIDY);
        assert!(m.validate_caps(NET, SUBSIDY, 0).is_ok());
    }

    #[test]
    fn phase31_rejects_role_cap_overpay() {
        // compute over its cap.
        let mut m = full(SUBSIDY);
        m.outputs[1].amount += 1;
        assert!(matches!(
            m.validate_caps(NET, SUBSIDY, 0),
            Err(PoawxRewardManifestValidationError::RoleCapExceeded(
                PoawxRewardRole::Compute
            )) | Err(PoawxRewardManifestValidationError::SumMismatch)
        ));
        // verify over cap.
        let mut m = full(SUBSIDY);
        m.outputs[2].amount =
            PoawxRoleRewardCap::for_role(PoawxRewardRole::Verify).ceiling(SUBSIDY) + 1;
        assert!(m.validate_caps(NET, SUBSIDY, 0).is_err());
        // support over cap.
        let mut m = full(SUBSIDY);
        m.outputs[3].amount =
            PoawxRoleRewardCap::for_role(PoawxRewardRole::Support).ceiling(SUBSIDY) + 1;
        assert!(m.validate_caps(NET, SUBSIDY, 0).is_err());
    }

    #[test]
    fn phase31_rejects_total_coinbase_overpay() {
        let m = full(SUBSIDY);
        // declared total exceeds subsidy + fees.
        assert_eq!(
            m.validate_caps(NET, SUBSIDY - 1, 0),
            Err(PoawxRewardManifestValidationError::TotalOverpay)
        );
        // primary inflated beyond total => overpay / sum mismatch.
        let mut m2 = full(SUBSIDY);
        m2.outputs[0].amount += 1000;
        assert!(m2.validate_caps(NET, SUBSIDY, 0).is_err());
    }

    #[test]
    fn phase31_low_participation_fallback_non_inflationary() {
        // No support role: its share is not minted; total minted < subsidy.
        let m = PoawxRewardManifestV1::new_fallback(
            NET,
            10,
            SUBSIDY,
            [
                Some([0x01u8; 20]),
                Some([0x02u8; 20]),
                Some([0x03u8; 20]),
                None,
            ],
            0,
            [0u8; 20],
        );
        assert_eq!(m.outputs[3].amount, 0, "absent support not minted");
        assert!(
            m.minted_total() < SUBSIDY,
            "minted < subsidy (non-inflationary)"
        );
        assert!(m.validate_caps(NET, SUBSIDY, 0).is_ok());
        // Only the proposer present: still non-inflationary, caps hold.
        let m1 = PoawxRewardManifestV1::new_fallback(
            NET,
            10,
            SUBSIDY,
            [Some([0x01u8; 20]), None, None, None],
            0,
            [0u8; 20],
        );
        assert!(m1.minted_total() <= SUBSIDY);
        assert!(m1.validate_caps(NET, SUBSIDY, 0).is_ok());
        // Absolutely no participants: nothing minted.
        let m0 = PoawxRewardManifestV1::new_fallback(NET, 10, SUBSIDY, [None; 4], 0, [0u8; 20]);
        assert_eq!(m0.minted_total(), 0);
        assert!(m0.validate_caps(NET, SUBSIDY, 0).is_ok());
    }

    #[test]
    fn phase31_rounding_is_deterministic() {
        // Odd / non-divisible totals: remainder always to PRIMARY; sum == total.
        for total in [1u64, 3, 7, 9999, 10001, 50_000_000_001, u64::MAX / 2] {
            let m = full(total);
            assert_eq!(m.minted_total(), total, "exact sum for total={total}");
            let amts = crate::poawx::multi_role_amounts(total);
            assert_eq!(
                [
                    m.outputs[0].amount,
                    m.outputs[1].amount,
                    m.outputs[2].amount,
                    m.outputs[3].amount
                ],
                amts,
                "manifest matches canonical split for total={total}"
            );
            // determinism: recompute equal.
            assert_eq!(role_amounts_with_fallback(total, [true; 4]), amts);
        }
    }

    #[test]
    fn phase31_penalized_finality_signer_cannot_receive_reward() {
        use crate::poawx_doublesign::PoawxDoubleSignPenaltyState;
        use crate::poawx_finality::{FinalityVoteType, FinalityVoteV1};
        use k256::ecdsa::SigningKey;
        // A real committee member key; the SUPPORT recipient is its pkh.
        let sk = SigningKey::from_slice(&[0xC3u8; 32]).unwrap();
        let va = FinalityVoteV1::signed(
            &sk,
            NET,
            5,
            [0xA1u8; 32],
            [0u8; 32],
            0,
            [0x11u8; 32],
            FinalityVoteType::Commit,
        );
        let support_pkh = va.member_pkh;
        let vb = FinalityVoteV1::signed(
            &sk,
            NET,
            5,
            [0xB2u8; 32],
            [0u8; 32],
            0,
            [0x11u8; 32],
            FinalityVoteType::Commit,
        );
        let ev = crate::poawx_doublesign::PoawxDoubleSignEvidenceV1::new(NET, va, vb);
        let m = PoawxRewardManifestV1::new_full(
            NET,
            10,
            SUBSIDY,
            [0x01u8; 20],
            [0x02u8; 20],
            [0x03u8; 20],
            support_pkh,
            0,
            [0u8; 20],
        );

        // Not penalized => eligible.
        let mut penalty = PoawxDoubleSignPenaltyState::new();
        assert!(m
            .validate_finality_recipient_eligibility(&penalty, 0)
            .is_ok());

        // Penalize the SUPPORT recipient (committee epoch 0, window 1 => suspended
        // through epoch < 1). The manifest now rejects paying it the finality reward.
        penalty
            .apply_evidence(&ev, &[support_pkh], NET, 5, 1)
            .unwrap();
        assert_eq!(
            m.validate_finality_recipient_eligibility(&penalty, 0),
            Err(PoawxRewardManifestValidationError::PenalizedRecipient(
                PoawxRewardRole::Support
            )),
            "penalized support signer cannot receive the finality reward"
        );
        // After the suspension window expires (epoch >= 1), eligible again.
        assert!(m
            .validate_finality_recipient_eligibility(&penalty, 1)
            .is_ok());
    }

    #[test]
    fn phase31_manifest_digest_changes_with_content() {
        let a = full(SUBSIDY);
        let mut b = full(SUBSIDY);
        b.outputs[0].pkh[0] ^= 1;
        assert_ne!(a.manifest_digest(), b.manifest_digest());
        // deterministic.
        assert_eq!(a.manifest_digest(), full(SUBSIDY).manifest_digest());
    }

    #[test]
    fn phase31_mainnet_no_manifest_caps() {
        let m = full(SUBSIDY);
        assert_eq!(
            m.validate_caps(0, SUBSIDY, 0),
            Err(PoawxRewardManifestValidationError::MainnetHardOff)
        );
        assert!(
            !reward_manifest_caps_gate(0, Some(1), 100),
            "mainnet gate off"
        );
        assert!(
            reward_manifest_caps_gate(1, Some(1), 100),
            "testnet gate on"
        );
        assert!(
            !reward_manifest_caps_gate(1, None, 100),
            "no activation off"
        );
    }
}
