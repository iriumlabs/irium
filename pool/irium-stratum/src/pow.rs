use num_bigint::BigUint;
use sha2::{Digest, Sha256};

pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

pub fn target_from_bits(bits: u32) -> BigUint {
    let exponent = (bits >> 24) as u8;
    let mantissa = bits & 0x007f_ffff;
    if mantissa == 0 {
        return BigUint::from(0u8);
    }
    let mut target = BigUint::from(mantissa as u64);
    if exponent <= 3 {
        target >>= 8 * (3 - exponent as usize);
    } else {
        target <<= 8 * (exponent as usize - 3);
    }
    target
}

pub fn default_pow_limit() -> BigUint {
    target_from_bits(0x1d00_ffff)
}

pub fn parse_pow_limit_hex(value: &str) -> Option<BigUint> {
    let v = value.trim().trim_start_matches("0x").trim_start_matches("0X");
    if v.is_empty() {
        return None;
    }
    BigUint::parse_bytes(v.as_bytes(), 16)
}

pub fn target_from_difficulty_with_limit(diff: f64, pow_limit: &BigUint) -> BigUint {
    if diff <= 0.0 {
        return pow_limit.clone();
    }

    let scale: u64 = 1_000_000;
    let scaled = (diff * scale as f64) as u64;
    if scaled == 0 {
        return pow_limit.clone();
    }

    let mut target = pow_limit * BigUint::from(scale) / BigUint::from(scaled);
    if target > *pow_limit {
        target = pow_limit.clone();
    }
    target
}

pub fn target_from_difficulty(diff: f64) -> BigUint {
    target_from_difficulty_with_limit(diff, &default_pow_limit())
}

pub fn hash_meets_target(hash: &[u8; 32], target: &BigUint) -> bool {
    BigUint::from_bytes_be(hash) <= *target
}
