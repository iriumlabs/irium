#![allow(dead_code)]
// Consensus and economic constants for Irium mainnet (Rust mirror of constants.py)

use crate::activation::{network_kind_from_env, resolved_block_time_v2_activation_height};

pub const MAX_MONEY: u64 = 100_000_000 * 100_000_000; // 1e8 * 1e8 sat-equivalent

/// Pre-V2 protocol block-time target (seconds).
///
/// Used unconditionally for every height below the block-time V2 activation
/// height. Legacy difficulty retargets (pre-LWMA codepath) and historical
/// LWMA windows reference this value directly: at the V2 activation height
/// the LWMA expected-time/clamp arithmetic switches to
/// `BLOCK_TARGET_INTERVAL_V2`, but anything below the fork height continues
/// to compute against this constant, so historical consensus is unaffected.
pub const BLOCK_TARGET_INTERVAL_V1: u64 = 600;

/// Post-V2 protocol block-time target (seconds).
///
/// Takes effect at heights at or above `MAINNET_BLOCK_TIME_V2_ACTIVATION_HEIGHT`
/// (mainnet) or the matching devnet env override. Coupled with
/// `HALVING_INTERVAL_V2`: when the block time shrinks 5×, the halving
/// interval expands 5× so the emission calendar stays roughly four years
/// per halving.
pub const BLOCK_TARGET_INTERVAL_V2: u64 = 120;

pub const DIFFICULTY_RETARGET_INTERVAL: u64 = 2016; // blocks
pub const MAX_FUTURE_BLOCK_TIME: i64 = 7200; // 2 hours
pub const MTP_ACTIVATION_HEIGHT: u64 = 32_000;
pub const COINBASE_MATURITY: u64 = 100; // blocks
pub const LWMA_WINDOW: u64 = 60; // blocks
pub const LWMA_SOLVETIME_CLAMP_FACTOR: u64 = 6; // clamp to [1, 6T]
pub const LWMA_MAX_TARGET_UP_FACTOR: u64 = 2; // target may ease by at most 2x per block
pub const LWMA_MAX_TARGET_DOWN_FACTOR: u64 = 2; // target may tighten by at most 2x per block
pub const LWMA_MIN_DIFFICULTY_FLOOR: u64 = 1; // 1 disables any stricter post-activation max-target cap

#[allow(dead_code)]
const INITIAL_SUBSIDY: u64 = 50 * 100_000_000; // 50 IRM in sat-equivalent

/// Pre-V2 halving interval (blocks).
///
/// Bitcoin-style 210_000-block epochs. At the original T=600s design, this
/// yields a ~four-year halving calendar. Used for every halving epoch whose
/// boundary falls at or below the block-time V2 activation height.
pub const HALVING_INTERVAL_V1: u64 = 210_000;

/// Post-V2 halving interval (blocks).
///
/// Set to 5 × V1 so that at T=120s the calendar between halvings stays at
/// roughly four years (1_050_000 × 120s ≈ 9.6 months per halving in nominal
/// terms — actual cadence depends on observed block time, but the protocol
/// target matches the original four-year intent at the new T).
///
/// The cumulative `halving_count(height)` formula stitches V1 and V2 epochs
/// together so the per-block reward curve is continuous across the fork
/// boundary: the halving count at `fork_height` equals the count at
/// `fork_height + 1`.
pub const HALVING_INTERVAL_V2: u64 = 1_050_000;

/// Returns the block-time V2 activation height for the running network
/// (env-derived on devnet/testnet, code-constant on mainnet). Returns
/// `None` when V2 is disabled, in which case `block_target_interval` and
/// `halving_count` fall through to the V1-only formulas.
fn resolved_block_time_v2_fork_height() -> Option<u64> {
    resolved_block_time_v2_activation_height(network_kind_from_env())
}

/// Returns the protocol block-time target (seconds) effective at `height`.
///
/// Below the V2 fork height (or whenever V2 is disabled): returns
/// `BLOCK_TARGET_INTERVAL_V1` (600). At/above the V2 fork height: returns
/// `BLOCK_TARGET_INTERVAL_V2` (120). LWMA consensus reads this at every
/// expected-time / solvetime-clamp computation so the same chain.rs code
/// path serves both eras without forking the LWMA implementation.
pub fn block_target_interval(height: u64) -> u64 {
    match resolved_block_time_v2_fork_height() {
        Some(fork) if height >= fork => BLOCK_TARGET_INTERVAL_V2,
        _ => BLOCK_TARGET_INTERVAL_V1,
    }
}

/// Returns the number of halvings that have occurred by `height`.
///
/// Cumulative across the V2 fork boundary: pre-fork halvings are counted
/// against `HALVING_INTERVAL_V1`, post-fork blocks add halvings against
/// `HALVING_INTERVAL_V2`. The split ensures the reward curve is continuous
/// at the boundary — `halving_count(F) == halving_count(F+1)`.
///
/// The `(height - fork - 1) / V2` form on the post-fork branch matches the
/// V1 convention `(height - 1) / V1`, where the k-th halving occurs at
/// height `k * V1 + 1` (subsidy stays at the previous level THROUGH
/// `k * V1`, then halves at `k * V1 + 1`). Without the `- 1`, the first
/// post-fork halving would land one block early relative to the V1
/// analogue.
pub fn halving_count(height: u64) -> u64 {
    if height == 0 {
        return 0;
    }
    match resolved_block_time_v2_fork_height() {
        Some(fork) if height > fork => {
            let pre = if fork == 0 {
                0
            } else {
                (fork - 1) / HALVING_INTERVAL_V1
            };
            let post = (height - fork - 1) / HALVING_INTERVAL_V2;
            pre + post
        }
        _ => (height - 1) / HALVING_INTERVAL_V1,
    }
}

#[allow(dead_code)]
pub fn block_reward(height: u64) -> u64 {
    if height == 0 {
        return 0;
    }
    let halvings = halving_count(height);
    if halvings >= 64 {
        return 0;
    }
    INITIAL_SUBSIDY >> halvings
}

// LWMA v2 parameters (inactive until MAINNET_LWMA_V2_ACTIVATION_HEIGHT is set).
//
// Motivation: real-world observation (blocks 19639-19704) showed that after a
// dominant miner left the network, the 60-block window dilutes slow-block signal
// so heavily that difficulty takes ~7.5 days to reach usable levels for infra
// miners alone. Smaller window and larger solvetime clamp both increase the
// signal each slow block contributes without weakening the per-block step clamp.
//
// Simulation (infra at 16.7 MH/s, difficulty 1.02e12, T=600s):
//   v1 (N=60, clamp=6T): usable after 7.1d, near-target after 7.5d
//   v2 (N=30, clamp=10T): usable after 2.6d, near-target after 2.7d
//
// Max single-block ease is unchanged (2x step clamp), preserving manipulation
// resistance. Upward step clamp (hardening) is also unchanged.
pub const LWMA_V2_WINDOW: u64 = 30; // reduced from 60 for faster response
pub const LWMA_V2_SOLVETIME_CLAMP_FACTOR: u64 = 10; // increased from 6 for stronger slow-block signal
pub const LWMA_V2_MAX_TARGET_UP_FACTOR: u64 = 2; // unchanged: max 2x ease per block
pub const LWMA_V2_MAX_TARGET_DOWN_FACTOR: u64 = 2; // unchanged: max 2x harden per block

/// Hard fork: BlockHeader wire serialization switches to Bitcoin-standard
/// convention at and above this height. Pre-fork (height < this) reverses
/// BOTH prev_hash and merkle_root before writing the 80-byte header (iriumd
/// historical convention). At/post-fork only prev_hash is reversed; the
/// merkle_root is written in natural byte order, matching Bitcoin and
/// allowing cgminer-family miners (Bitaxe, Antminer, Whatsminer, …) to
/// produce canonical chain bytes directly.
///
/// See src/block.rs::BlockHeader::serialize_for_height for the implementation
/// and the Fix 2a plan for the migration / activation rationale.
pub const STANDARD_HEADER_ACTIVATION_HEIGHT: u64 = 22_888;

/// Network-aware coinbase maturity. Mainnet uses the const `COINBASE_MATURITY`
/// (100 blocks). Devnet/regtest reads `IRIUM_COINBASE_MATURITY` (default 5)
/// so end-to-end tests don't have to mine 100 real blocks before spending
/// coinbase outputs.
pub fn coinbase_maturity() -> u64 {
    match std::env::var("IRIUM_NETWORK").as_deref() {
        Ok("devnet") | Ok("regtest") => std::env::var("IRIUM_COINBASE_MATURITY")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5),
        _ => COINBASE_MATURITY,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    /// Pins the live mainnet block-time-V2 fork boundary. With no env
    /// overrides set, `block_target_interval` follows
    /// `MAINNET_BLOCK_TIME_V2_ACTIVATION_HEIGHT = Some(24_250)`: V1 for
    /// every height below 24_250, V2 for every height at-or-above. The
    /// transition is sharp at the activation height.
    #[test]
    fn block_target_interval_uses_mainnet_v2_fork_at_24250() {
        let _guard = env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::env::remove_var("IRIUM_BLOCK_TIME_V2_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_NETWORK"); // mainnet default
        assert_eq!(block_target_interval(0), BLOCK_TARGET_INTERVAL_V1);
        assert_eq!(block_target_interval(1), BLOCK_TARGET_INTERVAL_V1);
        assert_eq!(block_target_interval(24_249), BLOCK_TARGET_INTERVAL_V1);
        assert_eq!(block_target_interval(24_250), BLOCK_TARGET_INTERVAL_V2);
        assert_eq!(block_target_interval(24_251), BLOCK_TARGET_INTERVAL_V2);
        assert_eq!(block_target_interval(1_000_000), BLOCK_TARGET_INTERVAL_V2);
    }

    /// With V2 enabled at a devnet fork height, `block_target_interval`
    /// returns V1 below the fork and V2 at-or-above, with the boundary
    /// landing on the fork height itself.
    #[test]
    fn block_target_interval_is_v1_pre_fork_v2_post_fork() {
        let _guard = env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Use "testnet", not "devnet": the chain.rs LWMA/legacy retarget
        // functions short-circuit to pow_limit when IRIUM_NETWORK is
        // devnet|regtest, which would corrupt parallel-running chain tests
        // that don't expect that shortcut.
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_BLOCK_TIME_V2_ACTIVATION_HEIGHT", "100");

        assert_eq!(block_target_interval(0), BLOCK_TARGET_INTERVAL_V1);
        assert_eq!(block_target_interval(99), BLOCK_TARGET_INTERVAL_V1);
        assert_eq!(block_target_interval(100), BLOCK_TARGET_INTERVAL_V2);
        assert_eq!(block_target_interval(101), BLOCK_TARGET_INTERVAL_V2);
        assert_eq!(block_target_interval(10_000), BLOCK_TARGET_INTERVAL_V2);

        std::env::remove_var("IRIUM_BLOCK_TIME_V2_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_NETWORK");
    }

    /// `halving_count(F) == halving_count(F+1)` — the post-V2 branch must
    /// pick up exactly where the pre-V2 branch left off, so the reward
    /// curve stays continuous through the fork.
    #[test]
    fn halving_count_is_continuous_across_fork() {
        let _guard = env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Use "testnet", not "devnet": the chain.rs LWMA/legacy retarget
        // functions short-circuit to pow_limit when IRIUM_NETWORK is
        // devnet|regtest, which would corrupt parallel-running chain tests
        // that don't expect that shortcut.
        std::env::set_var("IRIUM_NETWORK", "testnet");

        for fork in [1u64, 100, 30_000, 210_000, 210_001, 250_000, 419_999, 420_000] {
            std::env::set_var(
                "IRIUM_BLOCK_TIME_V2_ACTIVATION_HEIGHT",
                fork.to_string(),
            );
            assert_eq!(
                halving_count(fork),
                halving_count(fork + 1),
                "halving_count must be continuous across fork at height {fork}"
            );
        }

        std::env::remove_var("IRIUM_BLOCK_TIME_V2_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_NETWORK");
    }

    /// `block_reward(F) == block_reward(F+1)` follows directly from
    /// `halving_count` continuity; pin it as its own regression so a
    /// future refactor of `block_reward` can't silently re-introduce a
    /// discontinuity.
    #[test]
    fn block_reward_is_continuous_across_fork() {
        let _guard = env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Use "testnet", not "devnet": the chain.rs LWMA/legacy retarget
        // functions short-circuit to pow_limit when IRIUM_NETWORK is
        // devnet|regtest, which would corrupt parallel-running chain tests
        // that don't expect that shortcut.
        std::env::set_var("IRIUM_NETWORK", "testnet");

        for fork in [1u64, 100, 30_000, 210_000, 210_001, 250_000] {
            std::env::set_var(
                "IRIUM_BLOCK_TIME_V2_ACTIVATION_HEIGHT",
                fork.to_string(),
            );
            assert_eq!(
                block_reward(fork),
                block_reward(fork + 1),
                "block_reward must be continuous across fork at height {fork}"
            );
        }

        std::env::remove_var("IRIUM_BLOCK_TIME_V2_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_NETWORK");
    }

    /// With the V2 fork at a small height and the reward last halved at
    /// pre-fork height H1, the next halving must occur exactly
    /// `HALVING_INTERVAL_V2` blocks past the fork (not at the V1 cadence).
    #[test]
    fn block_reward_post_fork_halves_after_v2_interval_blocks() {
        let _guard = env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Use "testnet", not "devnet": the chain.rs LWMA/legacy retarget
        // functions short-circuit to pow_limit when IRIUM_NETWORK is
        // devnet|regtest, which would corrupt parallel-running chain tests
        // that don't expect that shortcut.
        std::env::set_var("IRIUM_NETWORK", "testnet");
        let fork = 30_000u64;
        std::env::set_var(
            "IRIUM_BLOCK_TIME_V2_ACTIVATION_HEIGHT",
            fork.to_string(),
        );

        // No halvings yet at the fork (we are well before V1's first
        // halving at 210_000, and V2 hasn't accrued any blocks yet).
        assert_eq!(block_reward(fork), INITIAL_SUBSIDY);
        assert_eq!(block_reward(fork + 1), INITIAL_SUBSIDY);

        // First post-fork halving lands HALVING_INTERVAL_V2 blocks past
        // the fork.
        let first_post_halving = fork + HALVING_INTERVAL_V2;
        assert_eq!(block_reward(first_post_halving), INITIAL_SUBSIDY);
        assert_eq!(block_reward(first_post_halving + 1), INITIAL_SUBSIDY >> 1);

        // Second post-fork halving another HALVING_INTERVAL_V2 blocks on.
        let second_post_halving = fork + 2 * HALVING_INTERVAL_V2;
        assert_eq!(block_reward(second_post_halving + 1), INITIAL_SUBSIDY >> 2);

        std::env::remove_var("IRIUM_BLOCK_TIME_V2_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_NETWORK");
    }

    /// Pins the live mainnet `block_reward` curve given
    /// `MAINNET_BLOCK_TIME_V2_ACTIVATION_HEIGHT = Some(24_250)`. Pre-fork
    /// heights follow the classic `(h-1) / HALVING_INTERVAL_V1` rule;
    /// post-fork heights use the cumulative formula with halvings
    /// landing every `HALVING_INTERVAL_V2 = 1_050_000` blocks past the
    /// fork. The k-th post-fork halving sits at
    /// `24_250 + k * 1_050_000 + 1`.
    #[test]
    fn block_reward_mainnet_post_fork_curve() {
        let _guard = env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::env::remove_var("IRIUM_BLOCK_TIME_V2_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_NETWORK");

        // Pre-fork: classic V1 curve up to the activation height.
        // At fork=24_250 the V1 cumulative count is (24_250-1)/210_000 = 0,
        // so no halvings have occurred yet by the fork.
        assert_eq!(block_reward(0), 0);
        assert_eq!(block_reward(1), INITIAL_SUBSIDY);
        assert_eq!(block_reward(24_249), INITIAL_SUBSIDY);
        assert_eq!(block_reward(24_250), INITIAL_SUBSIDY);

        // Post-fork branch picks up the count. h=24_251 is the first
        // post-fork height; cumulative halvings = 0 + 0 = 0.
        assert_eq!(block_reward(24_251), INITIAL_SUBSIDY);

        // V1's would-be halving at h = 210_001 no longer applies after
        // the fork — under the cumulative formula, we're still on the
        // initial subsidy until the first V2-cadence halving.
        assert_eq!(block_reward(210_001), INITIAL_SUBSIDY);

        // First post-fork halving: 24_250 + 1_050_000 + 1 = 1_074_251.
        assert_eq!(block_reward(1_074_250), INITIAL_SUBSIDY);
        assert_eq!(block_reward(1_074_251), INITIAL_SUBSIDY >> 1);

        // Second post-fork halving: 24_250 + 2*1_050_000 + 1 = 2_124_251.
        assert_eq!(block_reward(2_124_250), INITIAL_SUBSIDY >> 1);
        assert_eq!(block_reward(2_124_251), INITIAL_SUBSIDY >> 2);

        // Third post-fork halving: 24_250 + 3*1_050_000 + 1 = 3_174_251.
        assert_eq!(block_reward(3_174_251), INITIAL_SUBSIDY >> 3);
    }
}
