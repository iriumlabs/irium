//! Phase 21A: PoAW-X adaptive mining/security mode primitives.
//!
//! Deterministic state machine that maps observed network signals to a security
//! posture (Normal / Caution / Defense / Recovery) and a policy (confirmation
//! multiplier, stricter verification, ticket/finality requirements, role
//! fallback). It makes NO hardware-class assumptions (no CPU/GPU/ASIC anywhere).
//! The chain continues as long as at least one valid miner exists; low
//! participation enters Caution (not halt). Data-only foundation (Phase 21B may
//! consume the policy). Mainnet hard-off; does NOT touch difficulty / LWMA-144.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdaptiveMode {
    Normal,
    Caution,
    Defense,
    Recovery,
}

impl AdaptiveMode {
    /// Stable lowercase label for status/RPC exposure.
    pub fn as_str(self) -> &'static str {
        match self {
            AdaptiveMode::Normal => "normal",
            AdaptiveMode::Caution => "caution",
            AdaptiveMode::Defense => "defense",
            AdaptiveMode::Recovery => "recovery",
        }
    }
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

pub fn policy_for(mode: AdaptiveMode) -> AdaptivePolicy {
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
    matches!(crate::activation::poawx_effective_activation(network_id, activation), Some(h) if height >= h)
}

/// Whether adaptive-mode policy is active at `height`. Mainnet hard-off.
pub fn adaptive_mode_active(height: u64) -> bool {
    adaptive_mode_gate(network_id_byte(), adaptive_mode_activation_height(), height)
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
        let _env = crate::test_env::guard();
        let p = assess(&healthy(), AdaptiveMode::Normal);
        assert_eq!(p.mode, AdaptiveMode::Normal);
        assert_eq!(p.confirmation_multiplier, 1);
        assert!(!p.stricter_verification && !p.require_ticket_threshold && !p.role_fallback);
    }

    #[test]
    fn low_miner_count_is_caution_not_halt() {
        let _env = crate::test_env::guard();
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
        let _env = crate::test_env::guard();
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
        let _env = crate::test_env::guard();
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
        let _env = crate::test_env::guard();
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
        let _env = crate::test_env::guard();
        assert!(!adaptive_mode_gate(0, Some(1), 100), "below the mainnet activation height; NOT hard-off (see activation::mainnet_gate_truth)");
        assert!(adaptive_mode_gate(1, Some(1), 100));
        assert!(!adaptive_mode_gate(1, None, 100));
        assert!(!adaptive_mode_gate(1, Some(50), 10));
    }
}
