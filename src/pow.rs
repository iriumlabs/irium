use num_bigint::BigUint;
use num_traits::Zero;
use sha2::{Digest, Sha256};

/// Compact proof-of-work target, mirroring Python `Target`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target {
    pub bits: u32,
}

impl Target {
    /// Convert compact bits to full target integer (Bitcoin-style).
    pub fn to_target(self) -> BigUint {
        let exponent = self.bits >> 24;
        let mantissa = self.bits & 0x00ff_ffff;
        let mut value = BigUint::from(mantissa);
        if exponent <= 3 {
            let shift = 8 * (3 - exponent);
            value >>= shift;
        } else {
            let shift = 8 * (exponent - 3);
            value <<= shift;
        }
        value
    }

    /// Construct a compact target from a full integer, mirroring Python `Target.from_target`.
    pub fn from_target(value: &BigUint) -> Target {
        if value.is_zero() {
            return Target { bits: 0 };
        }

        let value_bytes = value.to_bytes_be();
        let mut exponent = value_bytes.len() as u32;

        let mantissa_big = if exponent <= 3 {
            let shift_bytes = 3 - exponent;
            value << (8 * shift_bytes)
        } else {
            let shift_bytes = exponent - 3;
            value >> (8 * shift_bytes)
        };

        let mut mantissa_bytes = mantissa_big.to_bytes_be();
        if mantissa_bytes.len() > 3 {
            let start = mantissa_bytes.len() - 3;
            mantissa_bytes = mantissa_bytes[start..].to_vec();
        } else if mantissa_bytes.len() < 3 {
            let mut padded = vec![0u8; 3 - mantissa_bytes.len()];
            padded.extend_from_slice(&mantissa_bytes);
            mantissa_bytes = padded;
        }

        let mut mantissa = ((mantissa_bytes[0] as u32) << 16)
            | ((mantissa_bytes[1] as u32) << 8)
            | (mantissa_bytes[2] as u32);

        if mantissa & 0x0080_0000 != 0 {
            mantissa >>= 8;
            exponent += 1;
        }

        let bits = (exponent << 24) | (mantissa & 0x00ff_ffff);
        Target { bits }
    }
}

/// Convert a consensus difficulty floor into its maximum target representation.
///
/// The effective post-activation maximum target is:
/// `pow_limit_target / min_difficulty_floor`.
///
/// A floor of `1` disables any extra cap and leaves the PoW limit unchanged.
/// Larger values tighten the maximum target deterministically using integer
/// math only.
pub fn min_difficulty_target(pow_limit: Target, min_difficulty: u64) -> Target {
    if min_difficulty <= 1 {
        return pow_limit;
    }

    let mut target = pow_limit.to_target();
    target /= BigUint::from(min_difficulty);
    if target.is_zero() {
        target = BigUint::from(1u8);
    }
    Target::from_target(&target)
}

/// Target representing a proof-of-work floor of `leading_zero_bits` leading zero
/// bits: a hash satisfies it iff its top `leading_zero_bits` bits are zero, i.e.
/// `hash <= 2^(256 - leading_zero_bits) - 1`.
///
/// This is the PoAW-X proposer PoW *demotion* target. A VRF-selected proposer's
/// block header is validated against this trivial anti-spam floor instead of the
/// full network target, so block *production* is hashrate-independent for a
/// validly-selected proposer. It is applied ONLY when a block carries a valid,
/// selected proposer assignment (see `chain::ChainState::check_block_proposer`);
/// a block with no valid assignment still requires the full network target.
pub fn floor_target(leading_zero_bits: u32) -> Target {
    let n = leading_zero_bits.min(255) as usize;
    // 2^(256 - n) - 1: every value with at least `n` leading zero bits satisfies it.
    let value = (BigUint::from(1u8) << (256 - n)) - BigUint::from(1u8);
    Target::from_target(&value)
}

pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

pub fn header_hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut buf = Vec::new();
    for p in parts {
        buf.extend_from_slice(p);
    }
    sha256d(&buf)
}

pub fn meets_target(hash: &[u8; 32], target: Target) -> bool {
    let value = BigUint::from_bytes_be(hash);
    value <= target.to_target()
}

/// Bitcoin-convention PoW check. Bitcoin block hashes are interpreted as
/// little-endian integers when compared to target (display hex is the
/// natural-order bytes reversed, which is why real BTC hashes look like
/// 0x0000...something - those leading zeros are the high-order bytes after
/// reversal). iriumd's own meets_target uses big-endian which works for
/// iriumd-native hashes but mis-interprets BTC headers. Apply this when
/// validating real Bitcoin headers (BTC SPV relay).
pub fn meets_target_btc(hash: &[u8; 32], target: Target) -> bool {
    let value = BigUint::from_bytes_le(hash);
    value <= target.to_target()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_roundtrip_for_canonical_targets() {
        for bits in [0x1d00ffff, 0x1f00ffff, 0x207fffff, 0x1b0404cb] {
            let target = Target { bits };
            assert_eq!(Target::from_target(&target.to_target()).bits, bits);
        }
    }

    #[test]
    fn floor_target_enforces_leading_zero_bits() {
        let t = floor_target(8);
        // Top byte zero => >= 8 leading zero bits => satisfies the floor.
        let mut ok = [0u8; 32];
        ok[1] = 0xff;
        assert!(meets_target(&ok, t));
        // Top byte nonzero => 0 leading zero bits => fails the 8-bit floor.
        let mut bad = [0u8; 32];
        bad[0] = 0x01;
        assert!(!meets_target(&bad, t));
        // The demotion floor is vastly easier than a hard network target: a hash
        // meeting the floor need not meet a real mainnet-style target.
        let hard = Target { bits: 0x1d00ffff };
        assert!(t.to_target() > hard.to_target());
        // A CPU-reachable hash (8 leading zero bits) that does NOT meet the hard
        // target: this is exactly the "demoted proposer block" case.
        assert!(meets_target(&ok, t));
        assert!(!meets_target(&ok, hard));
    }

    #[test]
    fn min_difficulty_target_scales_pow_limit() {
        let pow_limit = Target { bits: 0x207fffff };
        let floored = min_difficulty_target(pow_limit, 2);
        assert!(floored.to_target() < pow_limit.to_target());

        let mut expected = pow_limit.to_target();
        expected /= BigUint::from(2u8);
        assert_eq!(
            floored.to_target(),
            Target::from_target(&expected).to_target()
        );
    }

    #[test]
    fn min_difficulty_target_one_preserves_pow_limit() {
        let pow_limit = Target { bits: 0x1d00ffff };
        assert_eq!(min_difficulty_target(pow_limit, 1), pow_limit);
    }
}
