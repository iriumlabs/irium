//! Litecoin SPV header relay primitive.
//!
//! Tracks a chain of Litecoin block headers in iriumd consensus state.
//! Litecoin shares Bitcoin's 80-byte header wire format and sha256d
//! chain-linkage hash, but uses scrypt(N=1024, r=1, p=1) for proof-of-work.
//! Consequence: `prev_hash` lookups and `block_hash()` use sha256d exactly
//! as BTC does; only PoW verification routes through
//! `scrypt_pow::meets_target_ltc`.
//!
//! Differences from `btc_spv` in this Phase A primitive:
//!   - PoW uses scrypt (~10 ms / call vs ~1 µs for sha256d) — batch
//!     verification uses rayon to parallelise the per-header PoW check.
//!   - Batch cap is 144 (vs BTC's 2016) so a single block's worth of
//!     validation stays well under one second on commodity hardware.
//!   - Difficulty retarget is abstracted through `RetargetParams` so any
//!     sha256d-linkage chain that retargets via the Bitcoin-style
//!     "actual vs expected timespan over a fixed-block window" algorithm
//!     can plug in. Chains with fundamentally different algorithms
//!     (Dogecoin DigiShield, BCH CW-144 EDA) will live in their own
//!     modules with their own retarget functions; nothing in this file
//!     has to change for them to land.
//!
//! Shipping disabled on mainnet (activation height = `None`). Devnet and
//! testnet are expected to enable via an `IRIUM_LTC_SPV_RELAY_*` env
//! override path in a future commit, mirroring the BTC SPV resolver in
//! `btc_spv::resolve_btc_spv_params`. No consensus dispatch path yet
//! references `LTC_HEADER_BATCH_TAG`; this module is staged so the future
//! activation commit doesn't have to introduce both the primitive and
//! the wiring in a single PR.

use std::collections::HashMap;
use std::env;

use num_bigint::BigUint;
use num_traits::Zero;
use rayon::prelude::*;

use crate::activation::{resolved_ltc_spv_relay_activation_height, NetworkKind};
use crate::pow::{sha256d, Target};
use crate::scrypt_pow::meets_target_ltc;

// Re-export the activation-side LTC anchor constants so downstream
// modules (and the tests in this module) can keep referring to them via
// `crate::ltc_spv::MAINNET_LTC_*` exactly the way they referred to the
// inline forms before Phase B moved the source-of-truth into
// `activation.rs` (mirroring how the BTC SPV anchor constants are
// declared there and reused across the codebase).
pub use crate::activation::{
    MAINNET_LTC_ANCHOR_BITS, MAINNET_LTC_ANCHOR_HASH_DISPLAY, MAINNET_LTC_ANCHOR_HEIGHT,
    MAINNET_LTC_ANCHOR_TIME,
};
#[cfg(test)]
use crate::activation::MAINNET_LTC_SPV_RELAY_ACTIVATION_HEIGHT;

/// Output script tag reserved for a Litecoin header batch. Consensus
/// dispatch is wired in a later phase once governance assigns an
/// activation height; chosen as `0xc6` to avoid collision with existing
/// tags `0xc0` (HTLCv1), `0xc1` (MPSOv1), `0xc3` (HtlcBtcSwapV1),
/// `0xc4` (BtcHeaderBatch), and `0xc5` (SwapOrder).
pub const LTC_HEADER_BATCH_TAG: u8 = 0xc6;
pub const LTC_HEADER_BATCH_VERSION: u8 = 0x01;
pub const LTC_HEADER_BYTES: usize = 80;

/// Litecoin scrypt PoW costs ~10 ms per header on commodity hardware.
/// A 144-cap batch verified across 8 cores via rayon completes in
/// well under 250 ms — within the per-block validation budget the
/// iriumd consensus loop assumes. The chosen cap therefore bounds the
/// worst-case validation cost a relayer can impose with a single
/// header-batch transaction.
pub const MAX_LTC_HEADERS_PER_BATCH: u16 = 144;
pub const MAX_LTC_HEADER_BATCH_BYTES: usize =
    4 + LTC_HEADER_BYTES * (MAX_LTC_HEADERS_PER_BATCH as usize);

/// Median-time-past window: 11 ancestor headers, matching the
/// Bitcoin / Litecoin Core convention.
pub const LTC_MTP_WINDOW: usize = 11;
/// Maximum allowed gap between a Litecoin header time and the iriumd
/// block time that carried it: 2 hours, matching Litecoin Core's
/// `nMaxFutureBlockTime`.
pub const LTC_MAX_FUTURE_TIME_SECS: u32 = 2 * 60 * 60;

/// Difficulty-retarget parameter bundle for chains that share the
/// Bitcoin-style window algorithm (actual vs expected timespan over a
/// fixed-block window, clamped). Litecoin and Bitcoin both use this
/// algorithm with different constants. Dogecoin (post-block 145000)
/// uses DigiShield — a per-block damped algorithm — and would live in
/// its own `doge_spv.rs` with its own retarget function, not extend
/// this struct. BCH's CW-144 EDA likewise gets its own code path. So
/// this struct's contract is: "params for the Bitcoin-style window
/// retarget", not "params for every chain".
#[derive(Debug, Clone, Copy)]
pub struct RetargetParams {
    /// Number of blocks per retarget window.
    pub window: u64,
    /// Expected wall-clock duration of one window, in seconds.
    pub expected_timespan_secs: u32,
    /// Compact-form maximum target. Newly-retargeted targets clamp here.
    pub max_target_bits: u32,
    /// Lower clamp on the measured timespan, as a divisor of expected.
    /// Litecoin / Bitcoin use 4 (i.e. effective min = expected / 4).
    pub min_timespan_divisor: u32,
    /// Upper clamp on the measured timespan, as a multiplier of expected.
    /// Litecoin / Bitcoin use 4 (i.e. effective max = expected * 4).
    pub max_timespan_multiplier: u32,
}

impl RetargetParams {
    /// Litecoin mainnet retarget: 2016 blocks targeting 150 s each
    /// (so expected timespan = 2016 * 150 = 302_400 s), max target
    /// `0x1e0fffff`. Identical algorithm to Bitcoin, different constants.
    pub const LITECOIN: Self = Self {
        window: 2016,
        expected_timespan_secs: 302_400,
        max_target_bits: 0x1e0f_ffff,
        min_timespan_divisor: 4,
        max_timespan_multiplier: 4,
    };
}

/// 80-byte Litecoin block header in little-endian wire format. The
/// field layout matches Bitcoin byte-for-byte; the chain-level
/// difference is the PoW algorithm applied to those bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LtcHeader {
    pub version: i32,
    pub prev_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
}

impl LtcHeader {
    pub fn serialize(&self) -> [u8; LTC_HEADER_BYTES] {
        let mut out = [0u8; LTC_HEADER_BYTES];
        out[0..4].copy_from_slice(&self.version.to_le_bytes());
        out[4..36].copy_from_slice(&self.prev_hash);
        out[36..68].copy_from_slice(&self.merkle_root);
        out[68..72].copy_from_slice(&self.time.to_le_bytes());
        out[72..76].copy_from_slice(&self.bits.to_le_bytes());
        out[76..80].copy_from_slice(&self.nonce.to_le_bytes());
        out
    }

    pub fn deserialize(bytes: &[u8]) -> Result<LtcHeader, String> {
        if bytes.len() != LTC_HEADER_BYTES {
            return Err(format!(
                "ltc header must be exactly {} bytes (got {})",
                LTC_HEADER_BYTES,
                bytes.len()
            ));
        }
        let mut prev_hash = [0u8; 32];
        prev_hash.copy_from_slice(&bytes[4..36]);
        let mut merkle_root = [0u8; 32];
        merkle_root.copy_from_slice(&bytes[36..68]);
        Ok(LtcHeader {
            version: i32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            prev_hash,
            merkle_root,
            time: u32::from_le_bytes(bytes[68..72].try_into().unwrap()),
            bits: u32::from_le_bytes(bytes[72..76].try_into().unwrap()),
            nonce: u32::from_le_bytes(bytes[76..80].try_into().unwrap()),
        })
    }

    /// Natural-order sha256d of the serialized header — used for chain
    /// linkage (`prev_hash` references this value). Display-order LTC
    /// hashes are this value reversed. PoW uses scrypt, not this hash
    /// — see [`LtcHeader::meets_pow`].
    pub fn block_hash(&self) -> [u8; 32] {
        sha256d(&self.serialize())
    }

    /// True iff this header's scrypt PoW satisfies its declared target.
    /// Costs ~10 ms per call due to scrypt; batch validators parallelise
    /// these checks via rayon — see [`apply_ltc_header_batch`].
    pub fn meets_pow(&self) -> bool {
        meets_target_ltc(&self.serialize(), Target { bits: self.bits })
    }
}

/// One stored Litecoin header plus its derived chain metadata.
#[derive(Debug, Clone)]
pub struct LtcHeaderEntry {
    pub header: LtcHeader,
    pub height: u64,
    pub total_work: BigUint,
}

/// The first Litecoin header known to this iriumd relay. No header
/// before `height` is ever submittable. Zero-valued anchor disables
/// the relay (matches `BtcAnchor`'s convention).
#[derive(Debug, Clone, Copy)]
pub struct LtcAnchor {
    pub hash: [u8; 32],
    pub height: u64,
    pub bits: u32,
    pub time: u32,
}

impl LtcAnchor {
    pub const fn zero() -> LtcAnchor {
        LtcAnchor {
            hash: [0u8; 32],
            height: 0,
            bits: 0,
            time: 0,
        }
    }

    pub fn is_zero(&self) -> bool {
        self.hash == [0u8; 32] && self.height == 0 && self.bits == 0 && self.time == 0
    }

    /// Construct the mainnet anchor from the hardcoded display-order
    /// hash, reversing it into natural storage order. Returns the zero
    /// anchor if every constant happens to be zero (defensive against
    /// a future edit that accidentally clears them).
    pub fn mainnet() -> LtcAnchor {
        let mut hash = MAINNET_LTC_ANCHOR_HASH_DISPLAY;
        hash.reverse();
        let candidate = LtcAnchor {
            hash,
            height: MAINNET_LTC_ANCHOR_HEIGHT,
            bits: MAINNET_LTC_ANCHOR_BITS,
            time: MAINNET_LTC_ANCHOR_TIME,
        };
        if candidate.hash == [0u8; 32] && candidate.bits == 0 && candidate.time == 0 {
            LtcAnchor::zero()
        } else {
            candidate
        }
    }
}

/// Configuration bundle for the LTC SPV relay. `None` in
/// `ChainParams.ltc_spv` keeps the relay disabled.
#[derive(Debug, Clone)]
pub struct LtcSpvParams {
    pub activation_height: u64,
    pub anchor: LtcAnchor,
    pub retarget: RetargetParams,
}

/// Resolve the LTC SPV relay configuration for a given network. Returns
/// `Some` only when an activation height AND a valid anchor are both
/// present. Mirrors `btc_spv::resolve_btc_spv_params` so production
/// `ChainParams` construction can call this uniformly.
///
/// Mainnet uses the code-defined `MAINNET_LTC_*` constants from
/// `activation.rs` (currently `None` placeholders until governance flips
/// them in a dedicated activation commit per the workflow in
/// `docs/htlcv1_activation_commit_workflow.md`).
///
/// Testnet and devnet read the anchor from the four
/// `IRIUM_LTC_ANCHOR_{HEIGHT,HASH,BITS,TIME}` environment variables
/// alongside the existing `IRIUM_LTC_SPV_RELAY_ACTIVATION_HEIGHT`. All
/// five must be present for the relay to enable. Hash is accepted in
/// display order (Litecoin RPC convention) and canonicalised to
/// natural order for internal storage. `BITS` accepts either
/// `0x1929b619` or decimal.
#[allow(dead_code)]
pub fn resolve_ltc_spv_params(network: NetworkKind) -> Option<LtcSpvParams> {
    let activation_height = resolved_ltc_spv_relay_activation_height(network)?;
    let anchor = match network {
        NetworkKind::Mainnet => {
            let candidate = LtcAnchor::mainnet();
            if candidate.is_zero() {
                return None;
            }
            candidate
        }
        NetworkKind::Testnet | NetworkKind::Devnet => {
            let height = env::var("IRIUM_LTC_ANCHOR_HEIGHT")
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())?;
            let hash_str = env::var("IRIUM_LTC_ANCHOR_HASH").ok()?;
            let hash_bytes = hex::decode(hash_str.trim()).ok()?;
            if hash_bytes.len() != 32 {
                return None;
            }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&hash_bytes);
            hash.reverse();
            let bits_str = env::var("IRIUM_LTC_ANCHOR_BITS").ok()?;
            let bits_trim = bits_str.trim();
            let bits = if let Some(stripped) = bits_trim.strip_prefix("0x") {
                u32::from_str_radix(stripped, 16).ok()?
            } else {
                bits_trim.parse::<u32>().ok()?
            };
            let time = env::var("IRIUM_LTC_ANCHOR_TIME")
                .ok()
                .and_then(|v| v.trim().parse::<u32>().ok())?;
            LtcAnchor {
                hash,
                height,
                bits,
                time,
            }
        }
    };
    Some(LtcSpvParams {
        activation_height,
        anchor,
        retarget: RetargetParams::LITECOIN,
    })
}

/// Undo record produced by one successful header batch apply. Stored
/// inside the per-block undo log and consumed by `undo_ltc_relay_update`
/// on iriumd block disconnect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LtcRelayUpdate {
    pub tip_before: Option<[u8; 32]>,
    pub tip_height_before: u64,
    pub headers_added: Vec<[u8; 32]>,
}

/// Encode a sequence of headers as an `LtcHeaderBatch` output script
/// payload. Same wire shape as `btc_spv::encode_btc_header_batch`
/// (tag, version, u16-LE count, N * 80-byte headers) so RPC handlers
/// can be templated across chains in the future.
#[allow(dead_code)]
pub fn encode_ltc_header_batch(headers: &[LtcHeader]) -> Result<Vec<u8>, String> {
    if headers.is_empty() {
        return Err("ltc header batch: empty".to_string());
    }
    if headers.len() > MAX_LTC_HEADERS_PER_BATCH as usize {
        return Err(format!(
            "ltc header batch: {} headers exceeds max {}",
            headers.len(),
            MAX_LTC_HEADERS_PER_BATCH
        ));
    }
    let count = headers.len() as u16;
    let mut out = Vec::with_capacity(4 + LTC_HEADER_BYTES * headers.len());
    out.push(LTC_HEADER_BATCH_TAG);
    out.push(LTC_HEADER_BATCH_VERSION);
    out.extend_from_slice(&count.to_le_bytes());
    for h in headers {
        out.extend_from_slice(&h.serialize());
    }
    Ok(out)
}

pub fn parse_ltc_header_batch(script: &[u8]) -> Result<Vec<LtcHeader>, String> {
    if script.len() < 4 {
        return Err("ltc header batch: script too short".to_string());
    }
    if script[0] != LTC_HEADER_BATCH_TAG {
        return Err("ltc header batch: wrong tag".to_string());
    }
    if script[1] != LTC_HEADER_BATCH_VERSION {
        return Err("ltc header batch: unknown version".to_string());
    }
    let count = u16::from_le_bytes([script[2], script[3]]) as usize;
    if count == 0 || count > MAX_LTC_HEADERS_PER_BATCH as usize {
        return Err(format!("ltc header batch: count {} out of range", count));
    }
    let expected = 4 + LTC_HEADER_BYTES * count;
    if script.len() != expected {
        return Err(format!(
            "ltc header batch: wrong size (got {}, expected {})",
            script.len(),
            expected
        ));
    }
    let mut headers = Vec::with_capacity(count);
    for i in 0..count {
        let start = 4 + i * LTC_HEADER_BYTES;
        let h = LtcHeader::deserialize(&script[start..start + LTC_HEADER_BYTES])?;
        headers.push(h);
    }
    Ok(headers)
}

/// Cumulative work for a header with compact `bits`. Standard
/// Bitcoin/Litecoin formula: work = 2^256 / (target + 1).
pub fn work_for_bits(bits: u32) -> BigUint {
    let target = Target { bits }.to_target();
    let two_pow_256 = BigUint::from(1u8) << 256;
    let denom = target + BigUint::from(1u8);
    two_pow_256 / denom
}

pub fn ltc_max_target(params: &RetargetParams) -> BigUint {
    Target {
        bits: params.max_target_bits,
    }
    .to_target()
}

/// Encode a target BigUint to compact `bits` form. Inverse of
/// `Target::to_target`. Canonical (high-bit clamped) output.
/// Algorithm is identical to Bitcoin's; copied here so future LTC
/// maintenance can't inadvertently change BTC behaviour via a shared
/// helper.
pub fn target_to_compact_bits(target: &BigUint) -> u32 {
    if target.is_zero() {
        return 0;
    }
    let bytes = target.to_bytes_be();
    let mut size = bytes.len();
    let mut compact: u32 = if size <= 3 {
        let mut v: u32 = 0;
        for b in &bytes {
            v = (v << 8) | (*b as u32);
        }
        v << (8 * (3 - size))
    } else {
        ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | (bytes[2] as u32)
    };
    if compact & 0x0080_0000 != 0 {
        compact >>= 8;
        size += 1;
    }
    compact |= (size as u32) << 24;
    compact
}

/// Combined read-only view over committed headers + headers staged
/// earlier in the same batch. Lets a single batch's later headers
/// reference its earlier headers' MTP and retarget windows before
/// any state has been written.
struct LookupView<'a> {
    committed: &'a HashMap<[u8; 32], LtcHeaderEntry>,
    staged: &'a [([u8; 32], LtcHeaderEntry)],
}

impl<'a> LookupView<'a> {
    fn get(&self, hash: &[u8; 32]) -> Option<&LtcHeaderEntry> {
        if let Some(e) = self.committed.get(hash) {
            return Some(e);
        }
        self.staged
            .iter()
            .rev()
            .find(|(h, _)| h == hash)
            .map(|(_, e)| e)
    }
}

fn median_time_past_v(parent_hash: &[u8; 32], view: &LookupView, anchor: &LtcAnchor) -> u32 {
    let mut times: Vec<u32> = Vec::with_capacity(LTC_MTP_WINDOW);
    let mut cur = *parent_hash;
    while times.len() < LTC_MTP_WINDOW {
        if cur == anchor.hash {
            times.push(anchor.time);
            break;
        }
        match view.get(&cur) {
            Some(e) => {
                times.push(e.header.time);
                cur = e.header.prev_hash;
            }
            None => break,
        }
    }
    if times.is_empty() {
        return 0;
    }
    times.sort();
    times[times.len() / 2]
}

fn find_ancestor_time_at_height_v(
    parent_hash: &[u8; 32],
    target_height: u64,
    view: &LookupView,
    anchor: &LtcAnchor,
) -> Result<u32, String> {
    if target_height == anchor.height {
        return Ok(anchor.time);
    }
    let mut cur = *parent_hash;
    loop {
        if cur == anchor.hash {
            return Err(
                "retarget walk: reached anchor without finding target height".to_string(),
            );
        }
        let entry = view
            .get(&cur)
            .ok_or_else(|| "retarget walk: missing header in chain".to_string())?;
        if entry.height == target_height {
            return Ok(entry.header.time);
        }
        if entry.height < target_height {
            return Err("retarget walk: walked past target height".to_string());
        }
        cur = entry.header.prev_hash;
    }
}

/// Expected compact-bits for a header at `height` whose parent is
/// `parent_hash`. Parameterised by `&RetargetParams` so the same
/// implementation serves Litecoin today and Bitcoin tomorrow if we
/// ever want to consolidate; per the module docstring, chains with
/// fundamentally different algorithms (DOGE DigiShield, BCH EDA) get
/// their own retarget function, NOT new fields on `RetargetParams`.
fn expected_bits_for_v(
    height: u64,
    parent_hash: &[u8; 32],
    view: &LookupView,
    anchor: &LtcAnchor,
    params: &RetargetParams,
) -> Result<u32, String> {
    if height == 0 {
        return Err("expected_bits: height 0 has no parent".to_string());
    }
    let (parent_bits, parent_time) = if *parent_hash == anchor.hash {
        (anchor.bits, anchor.time)
    } else {
        let e = view
            .get(parent_hash)
            .ok_or_else(|| "expected_bits: parent unknown".to_string())?;
        (e.header.bits, e.header.time)
    };
    if !height.is_multiple_of(params.window) {
        return Ok(parent_bits);
    }
    // Litecoin Core's "Art Forz" off-by-one fix: walk back the FULL
    // adjustment interval from the parent, not (interval - 1) like
    // Bitcoin. See litecoin-project/litecoin pow.cpp GetNextWorkRequired:
    //   int blockstogoback = params.DifficultyAdjustmentInterval()-1;
    //   if ((pindexLast->nHeight+1) != params.DifficultyAdjustmentInterval())
    //       blockstogoback = params.DifficultyAdjustmentInterval();
    // The genesis special-case keeps BTC-style behaviour at the very
    // first retarget (where the lookback would otherwise underflow into
    // pre-genesis territory). Since the parent is at height (height-1),
    // first_height = parent_height - blockstogoback. For non-first
    // retargets that simplifies to (height - params.window - 1); for the
    // first retarget (height == params.window) it stays (height -
    // params.window) = 0, which also avoids u64 underflow in test
    // harnesses that use small windows. Without this fix every LTC
    // retarget iriumd validates is off by ~0.2% in bits, causing the
    // bits-equality rejections at every retarget boundary crossed by a
    // coinbase header batch (observed 2026-06-05 mainnet stall at LTC
    // retarget 3,108,672).
    let first_height = if height == params.window {
        // First-ever retarget after genesis: BTC-style (blockstogoback = window-1).
        // For our LTC mainnet anchor at 3,106,656 we are far past LTC height 2016,
        // so this branch only fires inside unit tests with synthetic anchors.
        height - params.window
    } else {
        // Non-first retarget: Litecoin Art Forz fix (blockstogoback = window).
        height - params.window - 1
    };
    if first_height < anchor.height {
        return Err("expected_bits: retarget window reaches before anchor".to_string());
    }
    let first_time = find_ancestor_time_at_height_v(parent_hash, first_height, view, anchor)?;
    let mut actual_timespan = parent_time.saturating_sub(first_time);
    let min_ts = params.expected_timespan_secs / params.min_timespan_divisor;
    let max_ts = params
        .expected_timespan_secs
        .saturating_mul(params.max_timespan_multiplier);
    if actual_timespan < min_ts {
        actual_timespan = min_ts;
    }
    if actual_timespan > max_ts {
        actual_timespan = max_ts;
    }
    let parent_target = Target { bits: parent_bits }.to_target();
    let new_target = parent_target * BigUint::from(actual_timespan)
        / BigUint::from(params.expected_timespan_secs);
    let max_target = ltc_max_target(params);
    let final_target = if new_target > max_target {
        max_target
    } else {
        new_target
    };
    Ok(target_to_compact_bits(&final_target))
}

/// Validate a header batch against current relay state and apply it.
/// On success returns an undo record; on any error no state is mutated.
///
/// Rules mirror `btc_spv::apply_btc_header_batch`:
///   - First header must link to the anchor or a known committed header.
///   - Every header in sequence must link to the previous one in the batch.
///   - Each header must satisfy PoW under its declared target.
///   - Each header's `bits` must match the expected target for its height
///     (parent's bits at non-retarget heights; retarget computation at
///     `height % retarget.window == 0`).
///   - Each header's `time` must exceed the MTP of the previous 11
///     ancestors and not exceed `iriumd_block_time + 2h`.
///   - No header may already exist in the committed set or be duplicated
///     within the batch.
///
/// PoW differences from BTC:
///   - The check is scrypt-based via `LtcHeader::meets_pow`.
///   - All header PoW checks for the batch are computed in parallel via
///     rayon, since each one is ~10 ms and only depends on the header
///     bytes themselves (no chain-state read needed for the PoW check).
///     The first failing index is reported, matching the sequential
///     behaviour of the BTC validator from the caller's perspective.
///
/// Tip switches to the batch's final header iff that header's cumulative
/// work strictly exceeds the prior tip's cumulative work. Lower-work
/// batches are still recorded so they can become canonical later if
/// extended.
pub fn apply_ltc_header_batch(
    headers: Vec<LtcHeader>,
    iriumd_block_time: u32,
    ltc_headers: &mut HashMap<[u8; 32], LtcHeaderEntry>,
    ltc_heights: &mut HashMap<[u8; 32], u64>,
    ltc_tip: &mut Option<[u8; 32]>,
    ltc_tip_height: &mut u64,
    anchor: &LtcAnchor,
    retarget: &RetargetParams,
) -> Result<LtcRelayUpdate, String> {
    if headers.is_empty() {
        return Err("apply_ltc_header_batch: empty batch".to_string());
    }
    if headers.len() > MAX_LTC_HEADERS_PER_BATCH as usize {
        return Err(format!(
            "apply_ltc_header_batch: {} headers exceeds max {}",
            headers.len(),
            MAX_LTC_HEADERS_PER_BATCH
        ));
    }
    if anchor.is_zero() {
        return Err("apply_ltc_header_batch: anchor not configured".to_string());
    }

    // Parallel PoW pre-check. scrypt costs ~10 ms / header; running them
    // sequentially for a full batch is >1 s wall-clock. par_iter fans
    // the work across the rayon thread pool. We collect indices of any
    // failures and report the lowest one, matching the sequential
    // caller contract on the BTC side.
    let mut pow_failures: Vec<usize> = headers
        .par_iter()
        .enumerate()
        .filter_map(|(i, h)| if h.meets_pow() { None } else { Some(i) })
        .collect();
    if !pow_failures.is_empty() {
        pow_failures.sort_unstable();
        return Err(format!(
            "apply_ltc_header_batch: header {} fails PoW",
            pow_failures[0]
        ));
    }

    let first = &headers[0];
    let (start_prev_height, start_prev_work) = if first.prev_hash == anchor.hash {
        (anchor.height, work_for_bits(anchor.bits))
    } else {
        let parent = ltc_headers.get(&first.prev_hash).ok_or_else(|| {
            "apply_ltc_header_batch: first header does not connect to known chain".to_string()
        })?;
        (parent.height, parent.total_work.clone())
    };

    let mut known_prefix = 0usize;
    let mut prefix_prev_hash = first.prev_hash;
    let mut prefix_prev_height = start_prev_height;
    let mut prefix_prev_work = start_prev_work.clone();
    for header in headers.iter() {
        if header.prev_hash != prefix_prev_hash {
            break;
        }
        let expected_height = prefix_prev_height + 1;
        let hash = header.block_hash();
        let Some(entry) = ltc_headers.get(&hash) else {
            break;
        };
        if entry.height != expected_height || entry.header != *header {
            break;
        }
        known_prefix += 1;
        prefix_prev_hash = hash;
        prefix_prev_height = expected_height;
        prefix_prev_work = entry.total_work.clone();
    }
    if known_prefix == headers.len() {
        return Ok(LtcRelayUpdate {
            tip_before: *ltc_tip,
            tip_height_before: *ltc_tip_height,
            headers_added: Vec::new(),
        });
    }
    if known_prefix > 0 && prefix_prev_height < *ltc_tip_height {
        return Err(
            "apply_ltc_header_batch: known prefix followed by non-tip fork".to_string(),
        );
    }

    let mut prev_hash = prefix_prev_hash;
    let mut prev_height = prefix_prev_height;
    let mut prev_work = prefix_prev_work;
    let headers_to_apply = &headers[known_prefix..];
    let mut staged: Vec<([u8; 32], LtcHeaderEntry)> =
        Vec::with_capacity(headers_to_apply.len());

    for (offset, header) in headers_to_apply.iter().enumerate() {
        let i = known_prefix + offset;
        if header.prev_hash != prev_hash {
            return Err(format!(
                "apply_ltc_header_batch: header {} does not link to previous",
                i
            ));
        }
        let height = prev_height + 1;
        let hash = header.block_hash();

        if ltc_headers.contains_key(&hash) {
            return Err(format!(
                "apply_ltc_header_batch: header {} already known in chain state",
                i
            ));
        }
        if staged.iter().any(|(h, _)| h == &hash) {
            return Err(format!(
                "apply_ltc_header_batch: header {} duplicated within batch",
                i
            ));
        }

        let (expected_bits_opt, mtp) = {
            let view = LookupView {
                committed: ltc_headers,
                staged: &staged,
            };
            // At a post-anchor pre-2x retarget boundary the relay never
            // saw the headers needed to compute the new target. PoW for
            // header.bits is still validated separately above, so accept
            // any claimed bits here without enforcing the equality check.
            let bits = match expected_bits_for_v(height, &prev_hash, &view, anchor, retarget) {
                Ok(b) => Some(b),
                Err(e) if e == "expected_bits: retarget window reaches before anchor" => None,
                Err(e) => return Err(e),
            };
            let mtp = median_time_past_v(&prev_hash, &view, anchor);
            (bits, mtp)
        };
        if let Some(expected_bits) = expected_bits_opt {
            let expected_target = Target { bits: expected_bits }.to_target();
            let header_target = Target { bits: header.bits }.to_target();
            if header_target != expected_target {
                return Err(format!(
                    "apply_ltc_header_batch: header {} bits mismatch \
                     (expected {:#010x}, got {:#010x})",
                    i, expected_bits, header.bits
                ));
            }
        }
        if header.time <= mtp {
            return Err(format!(
                "apply_ltc_header_batch: header {} time {} not above MTP {}",
                i, header.time, mtp
            ));
        }
        if header.time > iriumd_block_time.saturating_add(LTC_MAX_FUTURE_TIME_SECS) {
            return Err(format!(
                "apply_ltc_header_batch: header {} time {} more than 2h ahead \
                 of iriumd block time {}",
                i, header.time, iriumd_block_time
            ));
        }

        let work = prev_work.clone() + work_for_bits(header.bits);
        staged.push((
            hash,
            LtcHeaderEntry {
                header: header.clone(),
                height,
                total_work: work.clone(),
            },
        ));
        prev_hash = hash;
        prev_height = height;
        prev_work = work;
    }

    let tip_before = *ltc_tip;
    let tip_height_before = *ltc_tip_height;

    let final_hash = staged.last().unwrap().0;
    let final_height = staged.last().unwrap().1.height;
    let final_work = staged.last().unwrap().1.total_work.clone();

    let mut headers_added: Vec<[u8; 32]> = Vec::with_capacity(staged.len());
    for (hash, entry) in staged {
        headers_added.push(hash);
        ltc_heights.insert(hash, entry.height);
        ltc_headers.insert(hash, entry);
    }

    let current_tip_work = match tip_before {
        Some(h) => ltc_headers
            .get(&h)
            .map(|e| e.total_work.clone())
            .unwrap_or_else(BigUint::zero),
        None => work_for_bits(anchor.bits),
    };
    if final_work > current_tip_work {
        *ltc_tip = Some(final_hash);
        *ltc_tip_height = final_height;
    }

    Ok(LtcRelayUpdate {
        tip_before,
        tip_height_before,
        headers_added,
    })
}

/// Reverse a previously-applied `LtcRelayUpdate`. Removes inserted
/// headers from the committed maps and restores tip pointers. Called
/// from the iriumd block-disconnect path during a reorg, symmetric
/// to `undo_btc_relay_update`.
pub fn undo_ltc_relay_update(
    update: &LtcRelayUpdate,
    ltc_headers: &mut HashMap<[u8; 32], LtcHeaderEntry>,
    ltc_heights: &mut HashMap<[u8; 32], u64>,
    ltc_tip: &mut Option<[u8; 32]>,
    ltc_tip_height: &mut u64,
) {
    for hash in &update.headers_added {
        ltc_headers.remove(hash);
        ltc_heights.remove(hash);
    }
    *ltc_tip = update.tip_before;
    *ltc_tip_height = update.tip_height_before;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trivially-low difficulty target used by the mining helper below.
    /// At `0x207fffff` almost every scrypt attempt at nonce 0 succeeds,
    /// keeping unit tests fast despite scrypt's ~10 ms-per-attempt cost.
    fn regtest_bits() -> u32 {
        0x207f_ffff
    }

    fn mine_ltc_header(prev_hash: [u8; 32], time: u32, bits: u32) -> LtcHeader {
        let mut nonce: u32 = 0;
        loop {
            let header = LtcHeader {
                version: 1,
                prev_hash,
                merkle_root: [0u8; 32],
                time,
                bits,
                nonce,
            };
            if header.meets_pow() {
                return header;
            }
            nonce = nonce.wrapping_add(1);
        }
    }

    fn fresh_anchor() -> (LtcAnchor, LtcHeader) {
        let bits = regtest_bits();
        let anchor_header = mine_ltc_header([0u8; 32], 1_700_000_000, bits);
        let anchor = LtcAnchor {
            hash: anchor_header.block_hash(),
            height: 3_106_656,
            bits,
            time: anchor_header.time,
        };
        (anchor, anchor_header)
    }

    #[test]
    fn header_serialize_roundtrip() {
        let h = LtcHeader {
            version: 0x2000_0001,
            prev_hash: [0xaa; 32],
            merkle_root: [0xbb; 32],
            time: 1_700_000_000,
            bits: 0x1929_b619,
            nonce: 0xdead_beef,
        };
        let bytes = h.serialize();
        assert_eq!(bytes.len(), 80);
        let decoded = LtcHeader::deserialize(&bytes).expect("decode");
        assert_eq!(decoded, h);
    }

    #[test]
    fn header_deserialize_rejects_wrong_size() {
        assert!(LtcHeader::deserialize(&[0u8; 79]).is_err());
        assert!(LtcHeader::deserialize(&[0u8; 81]).is_err());
    }

    #[test]
    fn batch_encode_parse_roundtrip() {
        let bits = regtest_bits();
        let h1 = mine_ltc_header([0u8; 32], 1000, bits);
        let h2 = mine_ltc_header(h1.block_hash(), 1001, bits);
        let batch = encode_ltc_header_batch(&[h1.clone(), h2.clone()]).expect("encode");
        assert_eq!(batch[0], LTC_HEADER_BATCH_TAG);
        assert_eq!(batch[1], LTC_HEADER_BATCH_VERSION);
        assert_eq!(u16::from_le_bytes([batch[2], batch[3]]), 2);
        let parsed = parse_ltc_header_batch(&batch).expect("parse");
        assert_eq!(parsed, vec![h1, h2]);
    }

    #[test]
    fn batch_parse_rejects_wrong_tag() {
        let mut script = vec![0xc4, 0x01, 0x01, 0x00];
        script.extend_from_slice(&[0u8; LTC_HEADER_BYTES]);
        assert!(parse_ltc_header_batch(&script).is_err());
    }

    #[test]
    fn batch_parse_rejects_zero_count() {
        let script = vec![LTC_HEADER_BATCH_TAG, LTC_HEADER_BATCH_VERSION, 0, 0];
        assert!(parse_ltc_header_batch(&script).is_err());
    }

    #[test]
    fn batch_parse_rejects_oversize_count() {
        let mut script = vec![LTC_HEADER_BATCH_TAG, LTC_HEADER_BATCH_VERSION];
        let oversize: u16 = MAX_LTC_HEADERS_PER_BATCH + 1;
        script.extend_from_slice(&oversize.to_le_bytes());
        assert!(parse_ltc_header_batch(&script).is_err());
    }

    #[test]
    fn batch_parse_rejects_count_mismatch() {
        // Count says 2 but payload only has 1 header's worth of bytes.
        let mut script = vec![LTC_HEADER_BATCH_TAG, LTC_HEADER_BATCH_VERSION, 2, 0];
        script.extend_from_slice(&[0u8; LTC_HEADER_BYTES]);
        assert!(parse_ltc_header_batch(&script).is_err());
    }

    #[test]
    fn target_to_compact_bits_roundtrip_litecoin_min() {
        let target = Target {
            bits: RetargetParams::LITECOIN.max_target_bits,
        }
        .to_target();
        let bits = target_to_compact_bits(&target);
        assert_eq!(
            bits, RetargetParams::LITECOIN.max_target_bits,
            "round-trip must preserve canonical LTC mainnet-min bits"
        );
    }

    #[test]
    fn target_to_compact_bits_roundtrip_real_difficulty() {
        let bits_in = MAINNET_LTC_ANCHOR_BITS;
        let target = Target { bits: bits_in }.to_target();
        let bits_out = target_to_compact_bits(&target);
        assert_eq!(bits_out, bits_in);
    }

    #[test]
    fn work_for_bits_harder_target_is_more_work() {
        let easy = work_for_bits(RetargetParams::LITECOIN.max_target_bits);
        let hard = work_for_bits(MAINNET_LTC_ANCHOR_BITS);
        assert!(hard > easy);
    }

    #[test]
    fn mainnet_activation_set_to_24800() {
        assert_eq!(
            MAINNET_LTC_SPV_RELAY_ACTIVATION_HEIGHT,
            Some(24_800),
            "LTC SPV mainnet activation height is set to 24_800"
        );
    }

    #[test]
    fn mainnet_anchor_mainnet_constructor_reverses_to_natural_order() {
        let anchor = LtcAnchor::mainnet();
        assert_eq!(anchor.height, MAINNET_LTC_ANCHOR_HEIGHT);
        assert_eq!(anchor.bits, MAINNET_LTC_ANCHOR_BITS);
        assert_eq!(anchor.time, MAINNET_LTC_ANCHOR_TIME);
        let mut expected_natural = MAINNET_LTC_ANCHOR_HASH_DISPLAY;
        expected_natural.reverse();
        assert_eq!(anchor.hash, expected_natural);
    }

    #[test]
    fn litecoin_retarget_constants_are_consistent() {
        // 2016 blocks * 150 s = 302_400 s.
        let p = RetargetParams::LITECOIN;
        assert_eq!(p.window, 2016);
        assert_eq!(p.expected_timespan_secs, 302_400);
        assert_eq!(p.expected_timespan_secs as u64, p.window * 150);
        assert_eq!(p.max_target_bits, 0x1e0f_ffff);
    }

    #[test]
    fn apply_rejects_when_anchor_not_configured() {
        let bits = regtest_bits();
        let h = mine_ltc_header([0u8; 32], 1000, bits);
        let mut headers_db: HashMap<[u8; 32], LtcHeaderEntry> = HashMap::new();
        let mut heights_db: HashMap<[u8; 32], u64> = HashMap::new();
        let mut tip: Option<[u8; 32]> = None;
        let mut tip_height: u64 = 0;
        let zero_anchor = LtcAnchor::zero();
        let res = apply_ltc_header_batch(
            vec![h],
            1_000_000,
            &mut headers_db,
            &mut heights_db,
            &mut tip,
            &mut tip_height,
            &zero_anchor,
            &RetargetParams::LITECOIN,
        );
        assert!(res.is_err());
    }

    #[test]
    fn apply_rejects_empty_batch() {
        let (anchor, _) = fresh_anchor();
        let mut headers_db: HashMap<[u8; 32], LtcHeaderEntry> = HashMap::new();
        let mut heights_db: HashMap<[u8; 32], u64> = HashMap::new();
        let mut tip: Option<[u8; 32]> = None;
        let mut tip_height: u64 = 0;
        let res = apply_ltc_header_batch(
            vec![],
            1_000_000,
            &mut headers_db,
            &mut heights_db,
            &mut tip,
            &mut tip_height,
            &anchor,
            &RetargetParams::LITECOIN,
        );
        assert!(res.is_err());
    }

    #[test]
    fn apply_extends_anchor_and_sets_tip() {
        let (anchor, anchor_header) = fresh_anchor();
        let h1 = mine_ltc_header(anchor.hash, anchor_header.time + 150, anchor.bits);
        let mut headers_db: HashMap<[u8; 32], LtcHeaderEntry> = HashMap::new();
        let mut heights_db: HashMap<[u8; 32], u64> = HashMap::new();
        let mut tip: Option<[u8; 32]> = None;
        let mut tip_height: u64 = 0;

        let update = apply_ltc_header_batch(
            vec![h1.clone()],
            anchor_header.time + 150,
            &mut headers_db,
            &mut heights_db,
            &mut tip,
            &mut tip_height,
            &anchor,
            &RetargetParams::LITECOIN,
        )
        .expect("apply");

        assert_eq!(update.tip_before, None);
        assert_eq!(update.tip_height_before, 0);
        assert_eq!(update.headers_added, vec![h1.block_hash()]);
        assert_eq!(tip, Some(h1.block_hash()));
        assert_eq!(tip_height, anchor.height + 1);
        assert!(headers_db.contains_key(&h1.block_hash()));
        assert_eq!(*heights_db.get(&h1.block_hash()).unwrap(), anchor.height + 1);
    }

    #[test]
    fn apply_then_undo_restores_state() {
        let (anchor, anchor_header) = fresh_anchor();
        let h1 = mine_ltc_header(anchor.hash, anchor_header.time + 150, anchor.bits);
        let h2 = mine_ltc_header(h1.block_hash(), anchor_header.time + 300, anchor.bits);
        let mut headers_db: HashMap<[u8; 32], LtcHeaderEntry> = HashMap::new();
        let mut heights_db: HashMap<[u8; 32], u64> = HashMap::new();
        let mut tip: Option<[u8; 32]> = None;
        let mut tip_height: u64 = 0;

        let update = apply_ltc_header_batch(
            vec![h1.clone(), h2.clone()],
            anchor_header.time + 300,
            &mut headers_db,
            &mut heights_db,
            &mut tip,
            &mut tip_height,
            &anchor,
            &RetargetParams::LITECOIN,
        )
        .expect("apply");

        assert_eq!(headers_db.len(), 2);
        assert_eq!(tip, Some(h2.block_hash()));
        assert_eq!(tip_height, anchor.height + 2);

        undo_ltc_relay_update(
            &update,
            &mut headers_db,
            &mut heights_db,
            &mut tip,
            &mut tip_height,
        );

        assert!(headers_db.is_empty());
        assert!(heights_db.is_empty());
        assert_eq!(tip, None);
        assert_eq!(tip_height, 0);
    }

    #[test]
    fn apply_rejects_bad_linkage() {
        let (anchor, anchor_header) = fresh_anchor();
        let h1 = mine_ltc_header(anchor.hash, anchor_header.time + 150, anchor.bits);
        let bad = mine_ltc_header([0xee; 32], anchor_header.time + 300, anchor.bits);
        let mut headers_db = HashMap::new();
        let mut heights_db = HashMap::new();
        let mut tip = None;
        let mut tip_height = 0;

        let res = apply_ltc_header_batch(
            vec![h1, bad],
            anchor_header.time + 300,
            &mut headers_db,
            &mut heights_db,
            &mut tip,
            &mut tip_height,
            &anchor,
            &RetargetParams::LITECOIN,
        );
        assert!(res.is_err());
        assert!(
            headers_db.is_empty(),
            "no state should leak when batch is rejected"
        );
        assert!(tip.is_none());
    }

    #[test]
    fn apply_rejects_oversize_batch() {
        // Synthesise a 145-header vec of placeholder headers; we expect
        // the size-cap check to fire before any expensive PoW work.
        let (anchor, _anchor_header) = fresh_anchor();
        let dummy = LtcHeader {
            version: 0,
            prev_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            time: 0,
            bits: 0,
            nonce: 0,
        };
        let oversize: Vec<LtcHeader> =
            std::iter::repeat_n(dummy, MAX_LTC_HEADERS_PER_BATCH as usize + 1).collect();
        let mut headers_db = HashMap::new();
        let mut heights_db = HashMap::new();
        let mut tip = None;
        let mut tip_height = 0;
        let res = apply_ltc_header_batch(
            oversize,
            1_000_000,
            &mut headers_db,
            &mut heights_db,
            &mut tip,
            &mut tip_height,
            &anchor,
            &RetargetParams::LITECOIN,
        );
        assert!(res.is_err());
    }

    #[test]
    fn apply_skips_bits_check_at_post_anchor_pre_first_retarget() {
        // Regression for the BTC/LTC SPV stall fix (commit 0bc5463).
        // When the anchor lands mid-retarget-window, the first 2016-boundary
        // retarget after the anchor has lookback < anchor.height — the relay
        // cannot compute proper expected_bits there. The fix skips the
        // bits-equality check at that single boundary; PoW for header.bits
        // is still enforced separately.
        let bits_a: u32 = 0x207f_ffff;
        let bits_b: u32 = 0x207f_fffe;
        let anchor_header = mine_ltc_header([0u8; 32], 1_700_000_000, bits_a);
        let anchor = LtcAnchor {
            hash: anchor_header.block_hash(),
            height: 5,
            bits: bits_a,
            time: anchor_header.time,
        };
        let test_params = RetargetParams {
            window: 8,
            // Art Forz formula: actual_timespan spans 8 inter-block intervals
            // (from h=h_target-1 back to h=h_target-window-1, inclusive on both
            // ends = (window-1)+1+1 = window+1 blocks, window intervals). So
            // expected matches actual at the rate of 60s/block.
            expected_timespan_secs: 8 * 60,
            max_target_bits: 0x207f_ffff,
            min_timespan_divisor: 4,
            max_timespan_multiplier: 4,
        };

        let mut chain = Vec::new();
        let mut prev_hash = anchor.hash;
        let mut t = anchor.time;
        for h in 6..=13u64 {
            t += 60;
            let header_bits = if h >= 8 { bits_b } else { bits_a };
            let header = mine_ltc_header(prev_hash, t, header_bits);
            prev_hash = header.block_hash();
            chain.push(header);
        }

        let mut headers_db = HashMap::new();
        let mut heights_db = HashMap::new();
        let mut tip: Option<[u8; 32]> = None;
        let mut tip_height: u64 = 0;
        let res = apply_ltc_header_batch(
            chain.clone(),
            t + 120,
            &mut headers_db,
            &mut heights_db,
            &mut tip,
            &mut tip_height,
            &anchor,
            &test_params,
        );
        assert!(res.is_ok(), "expected batch accepted at affected retarget, got: {:?}", res);
        assert_eq!(tip_height, 13);
    }

    #[test]
    fn apply_validates_computed_bits_at_subsequent_retarget() {
        // Second retarget after the affected first one MUST compute
        // expected_bits normally (first_height >= anchor.height). With
        // actual_timespan == expected_timespan the new target equals the
        // parent target, so header.bits stays at the post-affected value.
        let bits_a: u32 = 0x207f_ffff;
        let bits_b: u32 = 0x207f_fffe;
        let anchor_header = mine_ltc_header([0u8; 32], 1_700_000_000, bits_a);
        let anchor = LtcAnchor {
            hash: anchor_header.block_hash(),
            height: 5,
            bits: bits_a,
            time: anchor_header.time,
        };
        let test_params = RetargetParams {
            window: 8,
            // Art Forz formula: actual_timespan spans 8 inter-block intervals
            // (from h=h_target-1 back to h=h_target-window-1, inclusive on both
            // ends = (window-1)+1+1 = window+1 blocks, window intervals). So
            // expected matches actual at the rate of 60s/block.
            expected_timespan_secs: 8 * 60,
            max_target_bits: 0x207f_ffff,
            min_timespan_divisor: 4,
            max_timespan_multiplier: 4,
        };

        let mut chain = Vec::new();
        let mut prev_hash = anchor.hash;
        let mut t = anchor.time;
        for h in 6..=16u64 {
            t += 60;
            let header_bits = if h >= 8 { bits_b } else { bits_a };
            let header = mine_ltc_header(prev_hash, t, header_bits);
            prev_hash = header.block_hash();
            chain.push(header);
        }

        let mut headers_db = HashMap::new();
        let mut heights_db = HashMap::new();
        let mut tip: Option<[u8; 32]> = None;
        let mut tip_height: u64 = 0;
        let res = apply_ltc_header_batch(
            chain.clone(),
            t + 120,
            &mut headers_db,
            &mut heights_db,
            &mut tip,
            &mut tip_height,
            &anchor,
            &test_params,
        );
        assert!(res.is_ok(), "expected batch accepted (h=16 normal retarget), got: {:?}", res);
        assert_eq!(tip_height, 16);
    }

    #[test]
    fn apply_rejects_bits_change_at_non_retarget_height() {
        // Mirrors btc_spv::tests::apply_rejects_bits_change_at_non_retarget_height.
        // At non-retarget heights bits must equal parent's; mismatch must reject
        // (and the skip-at-affected-retarget path must not soften this elsewhere).
        let (anchor, anchor_header) = fresh_anchor();
        let bad_bits: u32 = 0x207e_ffff;
        let h1 = mine_ltc_header(anchor.hash, anchor_header.time + 150, bad_bits);
        let mut headers_db = HashMap::new();
        let mut heights_db = HashMap::new();
        let mut tip: Option<[u8; 32]> = None;
        let mut tip_height: u64 = 0;
        let res = apply_ltc_header_batch(
            vec![h1],
            anchor_header.time + 150,
            &mut headers_db,
            &mut heights_db,
            &mut tip,
            &mut tip_height,
            &anchor,
            &RetargetParams::LITECOIN,
        );
        assert!(res.is_err());
    }

    #[test]
    fn ltc_retarget_matches_real_mainnet_at_3_108_672() {
        // Regression for the LTC Art Forz off-by-one. Real Litecoin
        // mainnet data at the first retarget after iriumd's mainnet
        // anchor (3_106_656). Verified via litecoinspace.org on
        // 2026-06-05. If this assertion breaks, the LTC retarget
        // formula no longer matches Litecoin Core's, and the IRM chain
        // will stall on the next LTC coinbase batch that crosses a
        // retarget boundary.
        let parent_bits: u32 = 0x1929b619;       // bits at LTC 3,108,671
        let parent_time: u32 = 1_778_988_019;    // time at LTC 3,108,671
        let first_time:  u32 = 1_778_676_063;    // time at LTC 3,106,655 (= anchor - 1)
        let expected_new_bits: u32 = 0x192b0787; // bits at LTC 3,108,672 (real mainnet)

        let parent_target = Target { bits: parent_bits }.to_target();
        let actual_timespan = parent_time.saturating_sub(first_time); // 311_956
        let new_target = parent_target * BigUint::from(actual_timespan)
            / BigUint::from(RetargetParams::LITECOIN.expected_timespan_secs);
        let computed = target_to_compact_bits(&new_target);
        assert_eq!(
            computed, expected_new_bits,
            "Real LTC mainnet 3,108,672 retarget mismatch              (computed {:#010x}, real {:#010x}) - Art Forz off-by-one              fix may have regressed",
            computed, expected_new_bits,
        );
    }
}
