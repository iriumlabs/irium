//! Phase 21A: PoAW-X adaptive mining/security mode primitives.
//!
//! Deterministic state machine that maps observed network signals to a security
//! posture (Normal / Caution / Defense / Recovery) and a policy (confirmation
//! multiplier, stricter verification, ticket/finality requirements, role
//! fallback). It makes NO hardware-class assumptions (no CPU/GPU/ASIC anywhere).
//! The chain continues as long as at least one valid miner exists; low
//! participation enters Caution (not halt). Data-only foundation (Phase 21B may
//! consume the policy). Mainnet hard-off; does NOT touch difficulty / LWMA-144.
#![allow(dead_code)]

use crate::activation::network_id_byte;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdaptiveMode {
    Normal,
    Caution,
    Defense,
    Recovery,
}

/// Observed network signals (caller-supplied, deterministic snapshot).
#[derive(Debug, Clone, Copy)]
pub struct NetworkSignals {
    pub active_miner_count: u32,
    pub valid_role_count: u32,
    pub recent_invalid_work: u32,
    pub recent_reorg_signal: u32,
    pub reward_concentration_permille: u32,
    pub finality_available: bool,
}

/// Policy output for a mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdaptivePolicy {
    pub mode: AdaptiveMode,
    pub confirmation_multiplier: u32,
    pub stricter_verification: bool,
    pub require_ticket_threshold: bool,
    pub require_finality: bool,
    pub role_fallback: bool,
}

// Deterministic thresholds.
pub const CAUTION_MIN_MINERS: u32 = 3;
pub const CAUTION_MIN_ROLES: u32 = 3;
pub const DEFENSE_INVALID_WORK: u32 = 5;
pub const DEFENSE_REORG_SIGNAL: u32 = 2;
pub const DEFENSE_CONCENTRATION_PERMILLE: u32 = 700;

impl NetworkSignals {
    /// The chain can produce a block as long as at least one valid miner exists.
    /// No hardware class is required.
    pub fn can_produce_block(&self) -> bool {
        self.active_miner_count >= 1
    }

    fn is_defense(&self) -> bool {
        self.recent_invalid_work >= DEFENSE_INVALID_WORK
            || self.recent_reorg_signal >= DEFENSE_REORG_SIGNAL
            || self.reward_concentration_permille >= DEFENSE_CONCENTRATION_PERMILLE
    }

    fn is_low_participation(&self) -> bool {
        self.active_miner_count < CAUTION_MIN_MINERS || self.valid_role_count < CAUTION_MIN_ROLES
    }

    /// Signals are "stable" (clean) — eligible to leave Defense/Recovery.
    fn is_stable(&self) -> bool {
        self.recent_invalid_work == 0
            && self.recent_reorg_signal == 0
            && self.reward_concentration_permille < DEFENSE_CONCENTRATION_PERMILLE
    }
}

fn policy_for(mode: AdaptiveMode) -> AdaptivePolicy {
    match mode {
        AdaptiveMode::Normal => AdaptivePolicy {
            mode,
            confirmation_multiplier: 1,
            stricter_verification: false,
            require_ticket_threshold: false,
            require_finality: false,
            role_fallback: false,
        },
        AdaptiveMode::Caution => AdaptivePolicy {
            mode,
            confirmation_multiplier: 2,
            stricter_verification: false,
            require_ticket_threshold: false,
            require_finality: false,
            role_fallback: true,
        },
        AdaptiveMode::Defense => AdaptivePolicy {
            mode,
            confirmation_multiplier: 4,
            stricter_verification: true,
            require_ticket_threshold: true,
            require_finality: true, // placeholder until finality committee wired
            role_fallback: true,
        },
        AdaptiveMode::Recovery => AdaptivePolicy {
            mode,
            confirmation_multiplier: 2,
            stricter_verification: true,
            require_ticket_threshold: true,
            require_finality: false,
            role_fallback: true,
        },
    }
}

/// Deterministically assess the adaptive mode given current signals and the prior
/// mode (for hysteresis: Defense → Recovery → Normal on sustained stability).
pub fn assess(signals: &NetworkSignals, prior_mode: AdaptiveMode) -> AdaptivePolicy {
    // Active instability always takes precedence.
    if signals.is_defense() {
        return policy_for(AdaptiveMode::Defense);
    }
    // Post-instability: leaving Defense goes through Recovery when stable.
    if prior_mode == AdaptiveMode::Defense && signals.is_stable() {
        return policy_for(AdaptiveMode::Recovery);
    }
    // Low participation is Caution, never a halt.
    if signals.is_low_participation() {
        return policy_for(AdaptiveMode::Caution);
    }
    // Recovery returns to Normal once stable AND participation is healthy.
    if prior_mode == AdaptiveMode::Recovery {
        if signals.is_stable() {
            return policy_for(AdaptiveMode::Normal);
        }
        return policy_for(AdaptiveMode::Recovery);
    }
    policy_for(AdaptiveMode::Normal)
}

/// Activation height for adaptive-mode use (env-gated; mainnet hard-off).
pub fn adaptive_mode_activation_height() -> Option<u64> {
    std::env::var("IRIUM_POAWX_ADAPTIVE_MODE_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// Pure gate logic (network 0 = mainnet hard-off); param-driven for race-free tests.
pub fn adaptive_mode_gate(network_id: u8, activation: Option<u64>, height: u64) -> bool {
    if network_id == 0 {
        return false;
    }
    matches!(activation, Some(h) if height >= h)
}

/// Whether adaptive-mode policy is active at `height`. Mainnet hard-off.
pub fn adaptive_mode_active(height: u64) -> bool {
    adaptive_mode_gate(network_id_byte(), adaptive_mode_activation_height(), height)
}

// ──────────────────────────────────────────────────────────────────────────
// Phase 34: deterministic, chain-derived adaptive-mode CONSENSUS integration.
//
// The legacy `AdaptiveMode` / `NetworkSignals` / `assess()` above remain a
// data-only primitive used by the off-chain simulator and operator reporting;
// two of `NetworkSignals`' fields (recent_invalid_work / recent_reorg_signal)
// are LOCAL-ONLY and therefore must never reach consensus. The types below are
// the consensus-grade path: they read ONLY chain-derived, replayable signals,
// evolve a small reorg-safe state, and are committed in each block via the
// trailing-optional `ADM1` section. Mainnet (network_id == 0) is hard-off.
// ──────────────────────────────────────────────────────────────────────────

/// Reuse the single 4-variant mode enum for the consensus path (no duplicate
/// enum): `PoawxAdaptiveMode` is an alias of `AdaptiveMode`.
pub type PoawxAdaptiveMode = AdaptiveMode;

impl AdaptiveMode {
    /// Stable wire byte (used by the ADM1 commitment + state digest).
    pub fn to_byte(self) -> u8 {
        match self {
            AdaptiveMode::Normal => 0,
            AdaptiveMode::Caution => 1,
            AdaptiveMode::Defense => 2,
            AdaptiveMode::Recovery => 3,
        }
    }
    pub fn from_byte(b: u8) -> Result<Self, PoawxAdaptiveValidationError> {
        match b {
            0 => Ok(AdaptiveMode::Normal),
            1 => Ok(AdaptiveMode::Caution),
            2 => Ok(AdaptiveMode::Defense),
            3 => Ok(AdaptiveMode::Recovery),
            _ => Err(PoawxAdaptiveValidationError::BadMode),
        }
    }
}

// Deterministic CONSENSUS constants (identical on every node; NOT per-node env).
// Only the activation height + required flag are env-gated; the transition math
// is fixed so a given chain yields the same mode on every node.
/// Recent committed-block window scanned for participation / evidence counts.
pub const ADAPTIVE_RECENT_WINDOW: u64 = 16;
/// Below this many recent registered tickets ⇒ low participation (Caution).
pub const CAUTION_MIN_TICKETS: u32 = 3;
/// Below this many recent distinct rewarded miners ⇒ low participation (Caution).
pub const CAUTION_MIN_ROLE_PARTICIPATION: u32 = 3;
/// At/above this many recent chain-carried double-sign evidence entries ⇒ Defense.
pub const DEFENSE_EVIDENCE_COUNT: u32 = 1;
/// Deterministic number of blocks to remain in Recovery after leaving Defense.
pub const RECOVERY_WINDOW: u32 = 4;
// (DEFENSE_CONCENTRATION_PERMILLE is reused from the Phase 21A constants above.)

const ADAPTIVE_STATE_DIGEST_TAG: &[u8] = b"IRIUM_POAWX_ADAPTIVE_STATE_V1";
const ADAPTIVE_METRICS_DIGEST_TAG: &[u8] = b"IRIUM_POAWX_ADAPTIVE_METRICS_V1";

/// ADM1 trailing-section magic (mirrors the Phase 33 `DMC1` pattern).
pub const ADAPTIVE_COMMITMENT_SECTION_MAGIC: &[u8; 4] = b"ADM1";
pub const ADAPTIVE_COMMITMENT_VERSION: u8 = 1;
/// version(1)+network(1)+height(8)+pre_mode(1)+post_mode(1)+pre(32)+post(32)+metrics(32).
pub const ADAPTIVE_COMMITMENT_WIRE: usize = 1 + 1 + 8 + 1 + 1 + 32 + 32 + 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoawxAdaptiveValidationError {
    MainnetHardOff,
    WrongVersion,
    WrongNetwork,
    WrongHeight,
    BadMode,
    PreModeMismatch,
    PostModeMismatch,
    PreStateMismatch,
    PostStateMismatch,
    MetricsMismatch,
    Malformed,
}

/// STRICTLY chain-derived signals — the ONLY input to the consensus transition.
/// Every field is computed from `self.dominance` (kept consistent across
/// connect/disconnect/reorg) and a bounded scan of committed blocks. There is no
/// field for local-only data (peer count, rejected forks, mempool, clock), so
/// local observations are structurally excluded from the consensus mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoawxAdaptiveChainSignals {
    /// Max recent reward share across miners (Phase 33 dominance state), permille.
    pub dominance_concentration_permille: u32,
    /// Distinct miners with recent rewards (chain-derived role participation).
    pub active_role_participation: u32,
    /// Block-carried ticket registrations within the recent committed-block window.
    pub registered_ticket_count: u32,
    /// Block-carried double-sign evidence within the recent committed-block window.
    pub double_sign_evidence_count: u32,
    /// Whether a finalized checkpoint exists (chain-derived).
    pub finality_available: bool,
}

impl PoawxAdaptiveChainSignals {
    fn is_defense(&self) -> bool {
        self.dominance_concentration_permille >= DEFENSE_CONCENTRATION_PERMILLE
            || self.double_sign_evidence_count >= DEFENSE_EVIDENCE_COUNT
    }
    fn is_low_participation(&self) -> bool {
        self.registered_ticket_count < CAUTION_MIN_TICKETS
            || self.active_role_participation < CAUTION_MIN_ROLE_PARTICIPATION
    }
    /// Deterministic digest over the signals (bound into the commitment so the
    /// transition inputs are tamper-evident and self-describing).
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(ADAPTIVE_METRICS_DIGEST_TAG);
        h.update(self.dominance_concentration_permille.to_le_bytes());
        h.update(self.active_role_participation.to_le_bytes());
        h.update(self.registered_ticket_count.to_le_bytes());
        h.update(self.double_sign_evidence_count.to_le_bytes());
        h.update([self.finality_available as u8]);
        h.finalize().into()
    }
}

/// Small, reorg-safe adaptive state carried forward block-to-block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoawxAdaptiveState {
    pub mode: PoawxAdaptiveMode,
    pub recovery_window_remaining: u32,
}

impl PoawxAdaptiveState {
    /// Initial state (pre-activation and genesis): Normal, no recovery window.
    pub fn genesis() -> Self {
        Self {
            mode: AdaptiveMode::Normal,
            recovery_window_remaining: 0,
        }
    }

    /// Deterministic digest, stable across replay.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(ADAPTIVE_STATE_DIGEST_TAG);
        h.update([self.mode.to_byte()]);
        h.update(self.recovery_window_remaining.to_le_bytes());
        h.finalize().into()
    }

    /// Pure, deterministic transition from `self` (prior state) under chain-derived
    /// `signals`. See the Phase 34 design doc §5.3.
    pub fn next(&self, signals: &PoawxAdaptiveChainSignals) -> Self {
        // Active instability always takes precedence.
        if signals.is_defense() {
            return Self {
                mode: AdaptiveMode::Defense,
                recovery_window_remaining: RECOVERY_WINDOW,
            };
        }
        // First clean block after Defense -> enter the deterministic Recovery window.
        if self.mode == AdaptiveMode::Defense {
            return Self {
                mode: AdaptiveMode::Recovery,
                recovery_window_remaining: RECOVERY_WINDOW,
            };
        }
        // Inside the Recovery window: decrement; stay Recovery until it elapses.
        if self.mode == AdaptiveMode::Recovery {
            let rem = self.recovery_window_remaining.saturating_sub(1);
            if rem > 0 {
                return Self {
                    mode: AdaptiveMode::Recovery,
                    recovery_window_remaining: rem,
                };
            }
            // Window elapsed -> fall through to the base mode.
        }
        // Base mode: low participation -> Caution, else Normal.
        if signals.is_low_participation() {
            Self {
                mode: AdaptiveMode::Caution,
                recovery_window_remaining: 0,
            }
        } else {
            Self {
                mode: AdaptiveMode::Normal,
                recovery_window_remaining: 0,
            }
        }
    }
}

/// Phase 34 block-carried adaptive-mode commitment (trailing `ADM1` section).
/// Binds the pre/post adaptive state digests, the pre/post modes, and the digest
/// of the chain-derived signals used for the transition at this height.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoawxAdaptiveCommitmentV1 {
    pub version: u8,
    pub network_id: u8,
    pub block_height: u64,
    pub pre_mode: u8,
    pub post_mode: u8,
    pub pre_state_digest: [u8; 32],
    pub post_state_digest: [u8; 32],
    pub metrics_digest: [u8; 32],
}

impl PoawxAdaptiveCommitmentV1 {
    pub fn new(
        network_id: u8,
        block_height: u64,
        pre: &PoawxAdaptiveState,
        post: &PoawxAdaptiveState,
        signals: &PoawxAdaptiveChainSignals,
    ) -> Self {
        Self {
            version: ADAPTIVE_COMMITMENT_VERSION,
            network_id,
            block_height,
            pre_mode: pre.mode.to_byte(),
            post_mode: post.mode.to_byte(),
            pre_state_digest: pre.digest(),
            post_state_digest: post.digest(),
            metrics_digest: signals.digest(),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(ADAPTIVE_COMMITMENT_WIRE);
        o.push(self.version);
        o.push(self.network_id);
        o.extend_from_slice(&self.block_height.to_le_bytes());
        o.push(self.pre_mode);
        o.push(self.post_mode);
        o.extend_from_slice(&self.pre_state_digest);
        o.extend_from_slice(&self.post_state_digest);
        o.extend_from_slice(&self.metrics_digest);
        o
    }

    pub fn deserialize(raw: &[u8]) -> Result<Self, String> {
        if raw.len() != ADAPTIVE_COMMITMENT_WIRE {
            return Err("adaptive commitment: bad length".to_string());
        }
        if raw[0] != ADAPTIVE_COMMITMENT_VERSION {
            return Err("adaptive commitment: bad version".to_string());
        }
        let network_id = raw[1];
        let block_height = u64::from_le_bytes(raw[2..10].try_into().expect("8"));
        let pre_mode = raw[10];
        let post_mode = raw[11];
        let mut pre = [0u8; 32];
        pre.copy_from_slice(&raw[12..44]);
        let mut post = [0u8; 32];
        post.copy_from_slice(&raw[44..76]);
        let mut metrics = [0u8; 32];
        metrics.copy_from_slice(&raw[76..108]);
        Ok(Self {
            version: ADAPTIVE_COMMITMENT_VERSION,
            network_id,
            block_height,
            pre_mode,
            post_mode,
            pre_state_digest: pre,
            post_state_digest: post,
            metrics_digest: metrics,
        })
    }

    /// Validate the commitment against the deterministically recomputed pre/post
    /// state and signals. Mainnet hard-off (network 0 rejects).
    pub fn validate(
        &self,
        expected_network: u8,
        height: u64,
        pre: &PoawxAdaptiveState,
        post: &PoawxAdaptiveState,
        signals: &PoawxAdaptiveChainSignals,
    ) -> Result<(), PoawxAdaptiveValidationError> {
        use PoawxAdaptiveValidationError::*;
        if expected_network == 0 {
            return Err(MainnetHardOff);
        }
        if self.version != ADAPTIVE_COMMITMENT_VERSION {
            return Err(WrongVersion);
        }
        if self.network_id != expected_network {
            return Err(WrongNetwork);
        }
        if self.block_height != height {
            return Err(WrongHeight);
        }
        // Reject unknown mode bytes.
        let _ = AdaptiveMode::from_byte(self.pre_mode)?;
        let _ = AdaptiveMode::from_byte(self.post_mode)?;
        if self.pre_mode != pre.mode.to_byte() {
            return Err(PreModeMismatch);
        }
        if self.post_mode != post.mode.to_byte() {
            return Err(PostModeMismatch);
        }
        if self.pre_state_digest != pre.digest() {
            return Err(PreStateMismatch);
        }
        if self.post_state_digest != post.digest() {
            return Err(PostStateMismatch);
        }
        if self.metrics_digest != signals.digest() {
            return Err(MetricsMismatch);
        }
        Ok(())
    }
}

/// Whether an ADM1 commitment is REQUIRED on every block (vs. validated-if-present)
/// — only when active AND required. Mainnet hard-off. Off by default ⇒ zero regression.
pub fn adaptive_commitment_required() -> bool {
    if network_id_byte() == 0 {
        return false;
    }
    std::env::var("IRIUM_POAWX_ADAPTIVE_COMMITMENT_REQUIRED")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}

/// Pure form of `adaptive_commitment_required` for race-free tests.
pub fn adaptive_commitment_required_pure(network_id: u8, required: bool) -> bool {
    network_id != 0 && required
}

/// A commitment is enforced (required-present) only when adaptive mode is active
/// AND the required flag is set. Mainnet hard-off.
pub fn adaptive_commitment_enforced(height: u64) -> bool {
    adaptive_mode_active(height) && adaptive_commitment_required()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy() -> NetworkSignals {
        NetworkSignals {
            active_miner_count: 10,
            valid_role_count: 3,
            recent_invalid_work: 0,
            recent_reorg_signal: 0,
            reward_concentration_permille: 300,
            finality_available: true,
        }
    }

    #[test]
    fn healthy_is_normal() {
        let p = assess(&healthy(), AdaptiveMode::Normal);
        assert_eq!(p.mode, AdaptiveMode::Normal);
        assert_eq!(p.confirmation_multiplier, 1);
        assert!(!p.stricter_verification && !p.require_ticket_threshold && !p.role_fallback);
    }

    #[test]
    fn low_miner_count_is_caution_not_halt() {
        let mut s = healthy();
        s.active_miner_count = 1;
        s.valid_role_count = 1;
        let p = assess(&s, AdaptiveMode::Normal);
        assert_eq!(p.mode, AdaptiveMode::Caution);
        assert!(
            s.can_produce_block(),
            "one miner still produces blocks (not halt)"
        );
    }

    #[test]
    fn reorg_or_invalid_or_concentration_is_defense() {
        let mut s = healthy();
        s.recent_reorg_signal = DEFENSE_REORG_SIGNAL;
        assert_eq!(assess(&s, AdaptiveMode::Normal).mode, AdaptiveMode::Defense);
        let mut s2 = healthy();
        s2.recent_invalid_work = DEFENSE_INVALID_WORK;
        assert_eq!(
            assess(&s2, AdaptiveMode::Normal).mode,
            AdaptiveMode::Defense
        );
        let mut s3 = healthy();
        s3.reward_concentration_permille = DEFENSE_CONCENTRATION_PERMILLE;
        let p3 = assess(&s3, AdaptiveMode::Normal);
        assert_eq!(p3.mode, AdaptiveMode::Defense);
        assert_eq!(p3.confirmation_multiplier, 4);
        assert!(p3.stricter_verification && p3.require_ticket_threshold && p3.require_finality);
    }

    #[test]
    fn defense_to_recovery_then_normal() {
        // clean signals after Defense -> Recovery.
        let p = assess(&healthy(), AdaptiveMode::Defense);
        assert_eq!(p.mode, AdaptiveMode::Recovery);
        // sustained stability from Recovery -> Normal.
        let p2 = assess(&healthy(), AdaptiveMode::Recovery);
        assert_eq!(p2.mode, AdaptiveMode::Normal);
        // Recovery with lingering instability stays Recovery (not Normal).
        let mut s = healthy();
        s.recent_invalid_work = 1; // below Defense threshold but not stable
        let p3 = assess(&s, AdaptiveMode::Recovery);
        assert_eq!(p3.mode, AdaptiveMode::Recovery);
    }

    #[test]
    fn zero_miners_cannot_produce() {
        let mut s = healthy();
        s.active_miner_count = 0;
        assert!(
            !s.can_produce_block(),
            "zero miners -> no block production possible"
        );
        // mode assessment still deterministic (Caution), but production is gated by can_produce_block.
        let _ = assess(&s, AdaptiveMode::Normal);
    }

    #[test]
    fn gate_logic_pure() {
        assert!(!adaptive_mode_gate(0, Some(1), 100), "mainnet hard-off");
        assert!(adaptive_mode_gate(1, Some(1), 100));
        assert!(!adaptive_mode_gate(1, None, 100));
        assert!(!adaptive_mode_gate(1, Some(50), 10));
    }

    // ── Phase 34: consensus-grade chain-derived path ───────────────────────────

    fn healthy_chain_signals() -> PoawxAdaptiveChainSignals {
        PoawxAdaptiveChainSignals {
            dominance_concentration_permille: 300,
            active_role_participation: 5,
            registered_ticket_count: 5,
            double_sign_evidence_count: 0,
            finality_available: true,
        }
    }

    #[test]
    fn phase34_normal_mode_stays_normal() {
        let st = PoawxAdaptiveState::genesis();
        let next = st.next(&healthy_chain_signals());
        assert_eq!(next.mode, AdaptiveMode::Normal);
        assert_eq!(next.recovery_window_remaining, 0);
        // Stays Normal across repeated healthy blocks.
        let next2 = next.next(&healthy_chain_signals());
        assert_eq!(next2.mode, AdaptiveMode::Normal);
    }

    #[test]
    fn phase34_low_ticket_count_enters_caution() {
        let mut sig = healthy_chain_signals();
        sig.registered_ticket_count = CAUTION_MIN_TICKETS - 1;
        let next = PoawxAdaptiveState::genesis().next(&sig);
        assert_eq!(next.mode, AdaptiveMode::Caution);
        // Low role participation is also Caution.
        let mut sig2 = healthy_chain_signals();
        sig2.active_role_participation = CAUTION_MIN_ROLE_PARTICIPATION - 1;
        assert_eq!(
            PoawxAdaptiveState::genesis().next(&sig2).mode,
            AdaptiveMode::Caution
        );
    }

    #[test]
    fn phase34_double_sign_penalty_enters_defense() {
        let mut sig = healthy_chain_signals();
        sig.double_sign_evidence_count = DEFENSE_EVIDENCE_COUNT;
        let next = PoawxAdaptiveState::genesis().next(&sig);
        assert_eq!(next.mode, AdaptiveMode::Defense);
        assert_eq!(next.recovery_window_remaining, RECOVERY_WINDOW);
    }

    #[test]
    fn phase34_dominance_concentration_enters_defense() {
        let mut sig = healthy_chain_signals();
        sig.dominance_concentration_permille = DEFENSE_CONCENTRATION_PERMILLE;
        assert_eq!(
            PoawxAdaptiveState::genesis().next(&sig).mode,
            AdaptiveMode::Defense
        );
    }

    #[test]
    fn phase34_recovery_exits_after_clean_window() {
        // Enter Defense, then clean signals: Defense -> Recovery, then count down
        // RECOVERY_WINDOW clean blocks, then back to Normal (healthy participation).
        let mut sig = healthy_chain_signals();
        sig.double_sign_evidence_count = DEFENSE_EVIDENCE_COUNT;
        let mut st = PoawxAdaptiveState::genesis().next(&sig);
        assert_eq!(st.mode, AdaptiveMode::Defense);
        // First clean block -> Recovery (full window).
        st = st.next(&healthy_chain_signals());
        assert_eq!(st.mode, AdaptiveMode::Recovery);
        assert_eq!(st.recovery_window_remaining, RECOVERY_WINDOW);
        // Count down: stays Recovery until the window elapses.
        let mut seen_recovery = 0;
        for _ in 0..(RECOVERY_WINDOW - 1) {
            st = st.next(&healthy_chain_signals());
            assert_eq!(st.mode, AdaptiveMode::Recovery);
            seen_recovery += 1;
        }
        assert_eq!(seen_recovery, RECOVERY_WINDOW - 1);
        // Window elapsed -> Normal.
        st = st.next(&healthy_chain_signals());
        assert_eq!(st.mode, AdaptiveMode::Normal);
    }

    #[test]
    fn phase34_recovery_relapses_to_defense_on_instability() {
        let mut sig = healthy_chain_signals();
        sig.double_sign_evidence_count = DEFENSE_EVIDENCE_COUNT;
        let st = PoawxAdaptiveState::genesis().next(&sig); // Defense
        let st = st.next(&healthy_chain_signals()); // Recovery
        assert_eq!(st.mode, AdaptiveMode::Recovery);
        // Instability during recovery -> straight back to Defense.
        let relapse = st.next(&sig);
        assert_eq!(relapse.mode, AdaptiveMode::Defense);
    }

    #[test]
    fn phase34_invalid_adaptive_commitment_rejected() {
        let net = 1u8;
        let pre = PoawxAdaptiveState::genesis();
        let sig = healthy_chain_signals();
        let post = pre.next(&sig);
        let good = PoawxAdaptiveCommitmentV1::new(net, 7, &pre, &post, &sig);
        assert!(good.validate(net, 7, &pre, &post, &sig).is_ok());

        // Wrong pre-mode.
        let mut bad = good;
        bad.pre_mode = AdaptiveMode::Defense.to_byte();
        assert_eq!(
            bad.validate(net, 7, &pre, &post, &sig),
            Err(PoawxAdaptiveValidationError::PreModeMismatch)
        );
        // Wrong post-mode.
        let mut bad = good;
        bad.post_mode = AdaptiveMode::Defense.to_byte();
        assert_eq!(
            bad.validate(net, 7, &pre, &post, &sig),
            Err(PoawxAdaptiveValidationError::PostModeMismatch)
        );
        // Wrong digest.
        let mut bad = good;
        bad.post_state_digest = [0x99u8; 32];
        assert_eq!(
            bad.validate(net, 7, &pre, &post, &sig),
            Err(PoawxAdaptiveValidationError::PostStateMismatch)
        );
        // Wrong metrics digest.
        let mut bad = good;
        bad.metrics_digest = [0x42u8; 32];
        assert_eq!(
            bad.validate(net, 7, &pre, &post, &sig),
            Err(PoawxAdaptiveValidationError::MetricsMismatch)
        );
        // Wrong height / network.
        assert_eq!(
            good.validate(net, 8, &pre, &post, &sig),
            Err(PoawxAdaptiveValidationError::WrongHeight)
        );
        assert_eq!(
            good.validate(2, 7, &pre, &post, &sig),
            Err(PoawxAdaptiveValidationError::WrongNetwork)
        );
        // Invalid transition: post that does not follow from pre+signals.
        let bogus_post = PoawxAdaptiveState {
            mode: AdaptiveMode::Defense,
            recovery_window_remaining: 0,
        };
        let bogus = PoawxAdaptiveCommitmentV1::new(net, 7, &pre, &bogus_post, &sig);
        // Validating the bogus commitment against the REAL post fails.
        assert!(bogus.validate(net, 7, &pre, &post, &sig).is_err());
    }

    #[test]
    fn phase34_mainnet_no_op() {
        // network_id == 0 (mainnet) is hard-off: gate is false and validate rejects.
        assert!(!adaptive_mode_gate(0, Some(1), 100));
        assert!(!adaptive_commitment_required_pure(0, true));
        let pre = PoawxAdaptiveState::genesis();
        let sig = healthy_chain_signals();
        let post = pre.next(&sig);
        let c = PoawxAdaptiveCommitmentV1::new(0, 7, &pre, &post, &sig);
        assert_eq!(
            c.validate(0, 7, &pre, &post, &sig),
            Err(PoawxAdaptiveValidationError::MainnetHardOff)
        );
    }

    #[test]
    fn phase34_local_signals_not_consensus() {
        // The LEGACY (data-only) primitive reacts to local-only signals: a local
        // reorg sighting flips it to Defense.
        let mut local = NetworkSignals {
            active_miner_count: 10,
            valid_role_count: 5,
            recent_invalid_work: 0,
            recent_reorg_signal: DEFENSE_REORG_SIGNAL,
            reward_concentration_permille: 300,
            finality_available: true,
        };
        assert_eq!(
            assess(&local, AdaptiveMode::Normal).mode,
            AdaptiveMode::Defense
        );
        local.recent_invalid_work = DEFENSE_INVALID_WORK;
        assert_eq!(
            assess(&local, AdaptiveMode::Normal).mode,
            AdaptiveMode::Defense
        );

        // The CONSENSUS path has NO field for local reorg sightings / invalid-work /
        // peer count / mempool — they cannot be expressed, so they cannot move the
        // mode. With healthy chain-derived signals the consensus mode stays Normal
        // no matter the local conditions above.
        let sig = healthy_chain_signals();
        assert_eq!(
            PoawxAdaptiveState::genesis().next(&sig).mode,
            AdaptiveMode::Normal
        );
        // Determinism: identical chain signals always yield the identical mode.
        assert_eq!(
            PoawxAdaptiveState::genesis().next(&sig),
            PoawxAdaptiveState::genesis().next(&sig)
        );
    }

    #[test]
    fn phase34_commitment_wire_roundtrips_and_state_digest_stable() {
        let net = 1u8;
        let pre = PoawxAdaptiveState::genesis();
        let sig = healthy_chain_signals();
        let post = pre.next(&sig);
        let c = PoawxAdaptiveCommitmentV1::new(net, 12345, &pre, &post, &sig);
        let bytes = c.serialize();
        assert_eq!(bytes.len(), ADAPTIVE_COMMITMENT_WIRE);
        assert_eq!(PoawxAdaptiveCommitmentV1::deserialize(&bytes).unwrap(), c);
        // Truncated / over-length rejected.
        assert!(PoawxAdaptiveCommitmentV1::deserialize(&bytes[..bytes.len() - 1]).is_err());
        // State digest is stable across reconstruction.
        assert_eq!(post.digest(), pre.next(&sig).digest());
        // Different state => different digest.
        let other = PoawxAdaptiveState {
            mode: AdaptiveMode::Defense,
            recovery_window_remaining: RECOVERY_WINDOW,
        };
        assert_ne!(post.digest(), other.digest());
    }

    #[test]
    fn phase34_bad_mode_byte_rejected() {
        assert_eq!(
            AdaptiveMode::from_byte(9),
            Err(PoawxAdaptiveValidationError::BadMode)
        );
        for m in [
            AdaptiveMode::Normal,
            AdaptiveMode::Caution,
            AdaptiveMode::Defense,
            AdaptiveMode::Recovery,
        ] {
            assert_eq!(AdaptiveMode::from_byte(m.to_byte()).unwrap(), m);
        }
    }
}
