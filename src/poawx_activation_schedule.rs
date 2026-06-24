//! C1: phased PoAW-X mainnet activation schedule (DISABLED by default).
//!
//! PoAW-X cannot require full on-chain ticket eligibility from its first active
//! block: a block's role tickets must be registered in an EARLIER block (the
//! consensus H→H+1 timing), so the genesis/activation block has no prior
//! registration to satisfy. This module formalizes a safe **phased** activation:
//!
//! * Pre-activation (`height < A`): normal PoW; no PoAW-X sections required.
//! * Activation height `A`: PoAW-X extension support begins (sections accepted /
//!   commitments validated where their own gates are on).
//! * Warm-up window `A ..= A + W`: ticket registrations (TKT1) are collected and
//!   applied, building the on-chain store; ticket-store ELIGIBILITY is NOT yet
//!   required (no prior registrations exist at `A`).
//! * Enforcement height `E = A + W + 1`: full ticket-store role eligibility is
//!   required.
//!
//! **Mainnet is hard-disabled:** [`MAINNET_POAWX_ACTIVATION_HEIGHT`] is `None` and
//! is returned for `network_id == 0` regardless of any env. There is NO real
//! activation height anywhere in this code — testnet/devnet activation is supplied
//! only via env for testing the schedule. This module changes no consensus path on
//! its own; it provides the deterministic gate arithmetic the C1 tests + (later)
//! the node use to phase enforcement in. It does not touch PoW/LWMA/base reward.
#![allow(dead_code)]

use crate::activation::network_id_byte;

/// Real mainnet PoAW-X activation height. **`None` = disabled / future placeholder.**
/// Setting a real height here is an explicit, owner/governance-gated decision that
/// is intentionally NOT made in C1.
pub const MAINNET_POAWX_ACTIVATION_HEIGHT: Option<u64> = None;

/// Default warm-up window length (blocks between activation `A` and enforcement
/// `E = A + W + 1`). Example/engineering default — NOT a committed mainnet value.
pub const DEFAULT_POAWX_WARMUP_WINDOW: u64 = 100;

/// Resolved activation height for `network_id`. Mainnet (`0`) is ALWAYS the
/// hard-coded [`MAINNET_POAWX_ACTIVATION_HEIGHT`] (`None`); testnet/devnet read an
/// explicit env height (for tests). No real height is embedded.
pub fn poawx_activation_height(network_id: u8) -> Option<u64> {
    if network_id == 0 {
        return MAINNET_POAWX_ACTIVATION_HEIGHT; // None — mainnet disabled
    }
    std::env::var("IRIUM_POAWX_SCHEDULE_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// Warm-up window length (env-overridable for tests; default
/// [`DEFAULT_POAWX_WARMUP_WINDOW`]).
pub fn poawx_warmup_window() -> u64 {
    std::env::var("IRIUM_POAWX_SCHEDULE_WARMUP_WINDOW")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_POAWX_WARMUP_WINDOW)
}

/// Enforcement height `E = A + W + 1` (pure).
pub fn ticket_enforcement_height(activation: u64, warmup: u64) -> u64 {
    activation.saturating_add(warmup).saturating_add(1)
}

// ── Pure gate arithmetic (param-driven for race-free tests) ──────────────────

/// Whether PoAW-X extension support has begun at `height` (`height >= A`). Mainnet
/// (`network_id == 0`) or no activation ⇒ false.
pub fn poawx_supported_at(network_id: u8, activation: Option<u64>, height: u64) -> bool {
    if network_id == 0 {
        return false;
    }
    matches!(activation, Some(a) if height >= a)
}

/// Whether `height` is inside the warm-up window `A ..= A + W`.
pub fn in_warmup_at(network_id: u8, activation: Option<u64>, warmup: u64, height: u64) -> bool {
    if network_id == 0 {
        return false;
    }
    match activation {
        Some(a) => height >= a && height <= a.saturating_add(warmup),
        None => false,
    }
}

/// Whether full ticket-store role eligibility is enforced at `height`
/// (`height >= E = A + W + 1`). Mainnet / no activation ⇒ false.
pub fn ticket_enforced_at(
    network_id: u8,
    activation: Option<u64>,
    warmup: u64,
    height: u64,
) -> bool {
    if network_id == 0 {
        return false;
    }
    match activation {
        Some(a) => height >= ticket_enforcement_height(a, warmup),
        None => false,
    }
}

// ── Env-resolved convenience wrappers ────────────────────────────────────────

pub fn poawx_supported(height: u64) -> bool {
    let net = network_id_byte();
    poawx_supported_at(net, poawx_activation_height(net), height)
}

pub fn in_warmup(height: u64) -> bool {
    let net = network_id_byte();
    in_warmup_at(
        net,
        poawx_activation_height(net),
        poawx_warmup_window(),
        height,
    )
}

pub fn ticket_enforced(height: u64) -> bool {
    let net = network_id_byte();
    ticket_enforced_at(
        net,
        poawx_activation_height(net),
        poawx_warmup_window(),
        height,
    )
}

/// True iff mainnet PoAW-X activation is disabled (the only supported state in C1).
pub fn mainnet_activation_disabled() -> bool {
    MAINNET_POAWX_ACTIVATION_HEIGHT.is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c1_mainnet_activation_disabled_by_default() {
        assert!(MAINNET_POAWX_ACTIVATION_HEIGHT.is_none());
        assert!(mainnet_activation_disabled());
        // Mainnet (network 0) never has an activation height, and no gate is ever on,
        // regardless of any (testnet) env override.
        assert_eq!(poawx_activation_height(0), None);
        assert!(!poawx_supported_at(0, Some(1), 1_000_000));
        assert!(!in_warmup_at(0, Some(1), 100, 1));
        assert!(!ticket_enforced_at(0, Some(1), 100, 1_000_000));
    }

    #[test]
    fn c1_enforcement_height_is_a_plus_w_plus_one() {
        assert_eq!(ticket_enforcement_height(1000, 100), 1101);
        assert_eq!(ticket_enforcement_height(1, 0), 2);
    }

    #[test]
    fn c1_phase_boundaries_pure() {
        let net = 1u8; // testnet
        let a = Some(1000u64);
        let w = 100u64;
        // pre-activation: not supported, not warmup, not enforced
        assert!(!poawx_supported_at(net, a, 999));
        assert!(!in_warmup_at(net, a, w, 999));
        assert!(!ticket_enforced_at(net, a, w, 999));
        // activation height A: supported + in warmup, NOT enforced
        assert!(poawx_supported_at(net, a, 1000));
        assert!(in_warmup_at(net, a, w, 1000));
        assert!(!ticket_enforced_at(net, a, w, 1000));
        // last warmup block A+W: supported + warmup, NOT enforced
        assert!(in_warmup_at(net, a, w, 1100));
        assert!(!ticket_enforced_at(net, a, w, 1100));
        // enforcement height E = A+W+1: supported, NOT warmup, ENFORCED
        assert!(poawx_supported_at(net, a, 1101));
        assert!(!in_warmup_at(net, a, w, 1101));
        assert!(ticket_enforced_at(net, a, w, 1101));
        // well past E: still enforced
        assert!(ticket_enforced_at(net, a, w, 5000));
    }

    #[test]
    fn c1_no_activation_means_nothing_on() {
        let net = 1u8;
        assert!(!poawx_supported_at(net, None, 10));
        assert!(!in_warmup_at(net, None, 100, 10));
        assert!(!ticket_enforced_at(net, None, 100, 10));
    }

    #[test]
    fn c1_zero_warmup_enforces_immediately_after_activation() {
        let net = 2u8; // devnet
        let a = Some(5u64);
        // W=0 => E = A+1. Activation block A=5 is warmup-only; A+1=6 enforced.
        assert!(in_warmup_at(net, a, 0, 5));
        assert!(!ticket_enforced_at(net, a, 0, 5));
        assert!(ticket_enforced_at(net, a, 0, 6));
    }
}
