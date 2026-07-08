//! Scrypt Proof-of-Work primitive for the LTC SPV header relay.
//!
//! Litecoin uses scrypt(N=1024, r=1, p=1) over the 80-byte block header,
//! with the SAME header bytes serving as both password AND salt
//! (Litecoin's specific binding — RFC 7914 scrypt accepts independent
//! password and salt but the LTC PoW reuses the header for both inputs).
//! Output is 32 bytes interpreted as a little-endian 256-bit integer,
//! compared against the target in the same byte order as Bitcoin's PoW.
//!
//! Chain linkage on Litecoin is still sha256d — `header.prev_hash`
//! references the sha256d of the parent header, just like Bitcoin.
//! Scrypt is consulted ONLY for the PoW target check.
//!
//! Cost: ~10 ms per call on commodity hardware vs ~1 µs for sha256d.
//! Downstream batch verification will need rayon-parallel evaluation
//! across cores to keep per-block validation budget reasonable; this
//! module is intentionally the single-threaded primitive.
//!
//! No consensus wiring lives here. The LTC SPV header validator hasn't
//! landed yet — this primitive is staged ahead of time so the future
//! activation gate doesn't depend on this code first having to compile.

use crate::pow::{meets_target_btc, Target};
use scrypt::{scrypt as scrypt_kdf, Params};

/// log2(N) for Litecoin's scrypt cost parameter (N = 1024).
const LTC_SCRYPT_LOG_N: u8 = 10;
/// Litecoin scrypt block-size mixing parameter.
const LTC_SCRYPT_R: u32 = 1;
/// Litecoin scrypt parallelisation parameter.
const LTC_SCRYPT_P: u32 = 1;
/// Output length in bytes (256-bit hash).
const LTC_SCRYPT_OUT: usize = 32;

/// Compute Litecoin's scrypt PoW hash for an 80-byte block header.
///
/// The same header bytes are passed as BOTH password and salt — this is
/// Litecoin's specific PoW binding, distinct from generic scrypt KDF
/// usage where password and salt are independent. Returns a 32-byte
/// hash in raw byte order; downstream callers feed it directly into
/// `meets_target_btc`, which interprets it as a little-endian 256-bit
/// integer per the BTC/LTC PoW convention.
pub fn scrypt_hash(header_80_bytes: &[u8; 80]) -> [u8; 32] {
    let params = Params::new(LTC_SCRYPT_LOG_N, LTC_SCRYPT_R, LTC_SCRYPT_P, LTC_SCRYPT_OUT)
        .expect("hardcoded LTC scrypt params are valid");
    let mut out = [0u8; 32];
    scrypt_kdf(header_80_bytes, header_80_bytes, &params, &mut out)
        .expect("32-byte output never overflows scrypt's output buffer");
    out
}

/// Whether a Litecoin block header satisfies its difficulty target.
///
/// Byte-order semantics are identical to `meets_target_btc`: the scrypt
/// result is treated as a little-endian 256-bit integer, mirroring how
/// Bitcoin's sha256d PoW is compared. The only difference between BTC
/// and LTC PoW verification, end to end, is the choice of hash function.
pub fn meets_target_ltc(header_bytes: &[u8; 80], target: Target) -> bool {
    let hash = scrypt_hash(header_bytes);
    meets_target_btc(&hash, target)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Determinism — identical input must always produce identical output.
    /// Foundational property: if this fails, the scrypt crate is broken
    /// or the parameters are being mutated between calls.
    #[test]
    fn scrypt_hash_is_deterministic() {
        let header = [0xAAu8; 80];
        let a = scrypt_hash(&header);
        let b = scrypt_hash(&header);
        assert_eq!(a, b, "scrypt must produce identical output for identical input");
    }

    /// Output shape — LTC scrypt always returns exactly 32 bytes. Locked
    /// here so a future typo in the params constant (e.g. dkLen=16) is
    /// caught before it can ship.
    #[test]
    fn scrypt_hash_returns_32_bytes() {
        let header = [0u8; 80];
        let h = scrypt_hash(&header);
        assert_eq!(h.len(), 32);
    }

    /// Different inputs produce different outputs — sanity guard against
    /// a degenerate implementation that returns a constant value for
    /// every header.
    #[test]
    fn scrypt_hash_distinguishes_inputs() {
        let a = scrypt_hash(&[0u8; 80]);
        let mut header_b = [0u8; 80];
        header_b[0] = 1;
        let b = scrypt_hash(&header_b);
        assert_ne!(a, b);
    }

    /// Cross-implementation reference vector against the LTC SPV anchor
    /// candidate header. Asserts that `scrypt_hash` byte-equals the output
    /// produced by Python's `hashlib.scrypt` (independent C-backed scrypt
    /// implementation, RFC 7914 compliant) given identical inputs and
    /// Litecoin parameters.
    ///
    /// Target: LTC mainnet block 3,106,656 (anchor candidate for the SPV
    /// relay; chosen because it sits on a 2016-block retarget boundary
    /// and was 17+ days deep at pick time).
    ///   - hash (display):  8a89d2e52329aabe63fabeb9d4cf734d8a44de158598afb6560f20f8c947be64
    ///   - timestamp:       1778676649  (2026-05-13 04:50:49 UTC)
    ///   - bits:            0x1929b619
    ///   - version:         0x20000000
    ///   - prev (display):  d025f09b02adbaaeee722173a89f654577e0f5fba7301e992f0da57b6ee3dc1a
    ///   - merkle (display):9fee8a55c04cb632aa424d867e7eec7a23e3e20b7ed04aa113fc1da6b72a40e6
    ///   - nonce:           2239964745
    ///
    /// The expected scrypt output ends with seven zero bytes when viewed
    /// in raw byte order — that's what a valid LTC PoW hash looks like
    /// once interpreted as a little-endian 256-bit integer (small number
    /// = trailing low-magnitude bytes in LE = leading zeros in BE).
    #[test]
    fn scrypt_hash_matches_litecoin_core_reference() {
        // LTC mainnet block 3,106,656 raw 80-byte header in wire order.
        // Source: litecoinspace.org/api/block/<hash>/header
        const HEADER: [u8; 80] = [
            0x00, 0x00, 0x00, 0x20, 0x1a, 0xdc, 0xe3, 0x6e,
            0x7b, 0xa5, 0x0d, 0x2f, 0x99, 0x1e, 0x30, 0xa7,
            0xfb, 0xf5, 0xe0, 0x77, 0x45, 0x65, 0x9f, 0xa8,
            0x73, 0x21, 0x72, 0xee, 0xae, 0xba, 0xad, 0x02,
            0x9b, 0xf0, 0x25, 0xd0, 0xe6, 0x40, 0x2a, 0xb7,
            0xa6, 0x1d, 0xfc, 0x13, 0xa1, 0x4a, 0xd0, 0x7e,
            0x0b, 0xe2, 0xe3, 0x23, 0x7a, 0xec, 0x7e, 0x7e,
            0x86, 0x4d, 0x42, 0xaa, 0x32, 0xb6, 0x4c, 0xc0,
            0x55, 0x8a, 0xee, 0x9f, 0xa9, 0x73, 0x04, 0x6a,
            0x19, 0xb6, 0x29, 0x19, 0x49, 0x26, 0x83, 0x85,
        ];
        // Reference scrypt(N=1024, r=1, p=1, output 32) computed via
        // Python 3.12 hashlib.scrypt(password=HEADER, salt=HEADER,
        // n=1024, r=1, p=1, dklen=32). Raw byte order — feed straight
        // to meets_target_btc for the PoW comparison.
        const EXPECTED: [u8; 32] = [
            0xdf, 0xab, 0x61, 0x0c, 0x22, 0x16, 0x45, 0xe7,
            0xf4, 0x8b, 0x27, 0xb5, 0x3b, 0xce, 0x33, 0x73,
            0x13, 0xf1, 0x34, 0xa9, 0xf0, 0xc5, 0x61, 0x9b,
            0x29, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let actual = scrypt_hash(&HEADER);
        assert_eq!(
            actual, EXPECTED,
            "scrypt_hash output diverged from the Python hashlib reference \
             on a known LTC mainnet header — likely a parameter typo or a \
             scrypt-crate semantic change between versions"
        );
    }
}
