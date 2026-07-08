//! Bitcoin SPV header relay (Phase 1).
//!
//! Tracks a chain of Bitcoin block headers in iriumd consensus state so that
//! Phase 2 can verify Bitcoin payment proofs against it. Phase 1 only relays
//! headers; no spend path consumes them yet.
//!
//! Headers travel inside a special transaction output type (tag `0xc4`).
//! `apply_btc_header_batch` is called when a block containing such an output
//! is connected, and produces a `BtcRelayUpdate` undo record that
//! `undo_btc_relay_update` reverses if the iriumd block is later disconnected.
//!
//! Shipping disabled on mainnet (activation height = `None`). Devnet/testnet
//! enable via `IRIUM_BTC_SPV_RELAY_ACTIVATION_HEIGHT` env override.

use std::collections::HashMap;
use std::env;

use num_bigint::BigUint;
use num_traits::Zero;

use crate::activation::{
    resolved_btc_spv_relay_activation_height, NetworkKind, MAINNET_BTC_ANCHOR_BITS,
    MAINNET_BTC_ANCHOR_HASH, MAINNET_BTC_ANCHOR_HEIGHT, MAINNET_BTC_ANCHOR_TIME,
};
#[cfg(test)]
use crate::pow::meets_target;
use crate::pow::{meets_target_btc, sha256d, Target};

/// Output script tag for a Bitcoin header batch.
pub const BTC_HEADER_BATCH_TAG: u8 = 0xc4;
pub const BTC_HEADER_BATCH_VERSION: u8 = 0x01;
pub const BTC_HEADER_BYTES: usize = 80;
pub const MAX_BTC_HEADERS_PER_BATCH: u16 = 2016;
pub const MAX_BTC_HEADER_BATCH_BYTES: usize =
    4 + BTC_HEADER_BYTES * (MAX_BTC_HEADERS_PER_BATCH as usize);

/// Bitcoin difficulty retarget every 2016 blocks.
pub const BTC_RETARGET_INTERVAL: u64 = 2016;
/// Expected timespan over a retarget window: 14 days, in seconds.
pub const BTC_EXPECTED_TIMESPAN: u32 = 14 * 24 * 3600;
/// MTP is computed over the previous 11 headers.
pub const BTC_MTP_WINDOW: usize = 11;
/// Maximum allowed gap between a Bitcoin header time and the iriumd block
/// time that carried it: 2 hours, matching Bitcoin Core's nMaxFutureBlockTime.
pub const BTC_MAX_FUTURE_TIME_SECS: u32 = 2 * 60 * 60;

/// Maximum target on BTC mainnet (compact). Targets clamp here after retarget.
pub const BTC_MAX_TARGET_BITS: u32 = 0x1d00ffff;

/// 80-byte Bitcoin block header, little-endian wire format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtcHeader {
    pub version: i32,
    pub prev_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
}

impl BtcHeader {
    pub fn serialize(&self) -> [u8; BTC_HEADER_BYTES] {
        let mut out = [0u8; BTC_HEADER_BYTES];
        out[0..4].copy_from_slice(&self.version.to_le_bytes());
        out[4..36].copy_from_slice(&self.prev_hash);
        out[36..68].copy_from_slice(&self.merkle_root);
        out[68..72].copy_from_slice(&self.time.to_le_bytes());
        out[72..76].copy_from_slice(&self.bits.to_le_bytes());
        out[76..80].copy_from_slice(&self.nonce.to_le_bytes());
        out
    }

    pub fn deserialize(bytes: &[u8]) -> Result<BtcHeader, String> {
        if bytes.len() != BTC_HEADER_BYTES {
            return Err(format!(
                "btc header must be exactly {} bytes (got {})",
                BTC_HEADER_BYTES,
                bytes.len()
            ));
        }
        let mut prev_hash = [0u8; 32];
        prev_hash.copy_from_slice(&bytes[4..36]);
        let mut merkle_root = [0u8; 32];
        merkle_root.copy_from_slice(&bytes[36..68]);
        Ok(BtcHeader {
            version: i32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            prev_hash,
            merkle_root,
            time: u32::from_le_bytes(bytes[68..72].try_into().unwrap()),
            bits: u32::from_le_bytes(bytes[72..76].try_into().unwrap()),
            nonce: u32::from_le_bytes(bytes[76..80].try_into().unwrap()),
        })
    }

    /// sha256d of the serialized header in natural (non-display) byte order.
    /// Display-order BTC hashes are this value reversed.
    pub fn block_hash(&self) -> [u8; 32] {
        sha256d(&self.serialize())
    }
}

/// One stored Bitcoin header plus its derived metadata.
#[derive(Debug, Clone)]
pub struct BtcHeaderEntry {
    pub header: BtcHeader,
    pub height: u64,
    pub total_work: BigUint,
}

/// Hardcoded anchor: the first Bitcoin header known to this iriumd relay.
/// No header before `height` is ever submittable.
#[derive(Debug, Clone, Copy)]
pub struct BtcAnchor {
    pub hash: [u8; 32],
    pub height: u64,
    pub bits: u32,
    pub time: u32,
}

impl BtcAnchor {
    pub const fn zero() -> BtcAnchor {
        BtcAnchor {
            hash: [0u8; 32],
            height: 0,
            bits: 0,
            time: 0,
        }
    }

    pub fn is_zero(&self) -> bool {
        self.hash == [0u8; 32] && self.height == 0 && self.bits == 0 && self.time == 0
    }
}

/// Bundle of the two pieces of configuration a node needs to run the BTC
/// SPV relay: the iriumd height at which submissions become valid, and the
/// pre-chosen Bitcoin checkpoint header. `None` in `ChainParams.btc_spv`
/// keeps the relay disabled.
#[derive(Debug, Clone)]
pub struct BtcSpvParams {
    pub activation_height: u64,
    pub anchor: BtcAnchor,
}

/// Resolve the SPV relay configuration for a given network. Returns `Some`
/// only when both an activation height AND a valid anchor are present.
///
/// Mainnet uses the code-defined `MAINNET_BTC_ANCHOR_*` constants from
/// `activation.rs` (zero placeholders until governance flips them in a
/// dedicated activation commit per `docs/htlcv1_activation_commit_workflow.md`).
/// The `is_zero()` check refuses to enable the relay until the anchor has
/// been populated.
///
/// Testnet and devnet read the anchor from the four
/// `IRIUM_BTC_ANCHOR_{HEIGHT,HASH,BITS,TIME}` environment variables alongside
/// the existing `IRIUM_BTC_SPV_RELAY_ACTIVATION_HEIGHT`. All five must be
/// present for the relay to enable. Hash is accepted in display-order
/// (Bitcoin RPC convention — the hex string of bytes reversed) and
/// canonicalized to natural-order for internal storage. `BITS` accepts
/// either `0x1d00ffff` or decimal `486604799`.
#[allow(dead_code)] // wired into ChainParams construction in iriumd.rs production path
pub fn resolve_btc_spv_params(network: NetworkKind) -> Option<BtcSpvParams> {
    let activation_height = resolved_btc_spv_relay_activation_height(network)?;
    let anchor = match network {
        NetworkKind::Mainnet => {
            let candidate = BtcAnchor {
                hash: MAINNET_BTC_ANCHOR_HASH,
                height: MAINNET_BTC_ANCHOR_HEIGHT,
                bits: MAINNET_BTC_ANCHOR_BITS,
                time: MAINNET_BTC_ANCHOR_TIME,
            };
            if candidate.is_zero() {
                return None;
            }
            candidate
        }
        NetworkKind::Testnet | NetworkKind::Devnet => {
            let height = env::var("IRIUM_BTC_ANCHOR_HEIGHT")
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())?;
            let hash_str = env::var("IRIUM_BTC_ANCHOR_HASH").ok()?;
            let hash_bytes = hex::decode(hash_str.trim()).ok()?;
            if hash_bytes.len() != 32 {
                return None;
            }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&hash_bytes);
            hash.reverse();
            let bits_str = env::var("IRIUM_BTC_ANCHOR_BITS").ok()?;
            let bits_trim = bits_str.trim();
            let bits = if let Some(stripped) = bits_trim.strip_prefix("0x") {
                u32::from_str_radix(stripped, 16).ok()?
            } else {
                bits_trim.parse::<u32>().ok()?
            };
            let time = env::var("IRIUM_BTC_ANCHOR_TIME")
                .ok()
                .and_then(|v| v.trim().parse::<u32>().ok())?;
            BtcAnchor {
                hash,
                height,
                bits,
                time,
            }
        }
    };
    Some(BtcSpvParams {
        activation_height,
        anchor,
    })
}

/// Undo record produced by a single successful header batch apply.
/// Stored inside `BlockUndo` and consumed by `undo_btc_relay_update` on
/// block disconnect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtcRelayUpdate {
    pub tip_before: Option<[u8; 32]>,
    pub tip_height_before: u64,
    pub headers_added: Vec<[u8; 32]>,
}

/// Encode a sequence of headers as a `BtcHeaderBatch` output script payload.
#[allow(dead_code)] // wallet/RPC encoder used by Phase 5 RPC handlers
pub fn encode_btc_header_batch(headers: &[BtcHeader]) -> Result<Vec<u8>, String> {
    if headers.is_empty() {
        return Err("btc header batch: empty".to_string());
    }
    if headers.len() > MAX_BTC_HEADERS_PER_BATCH as usize {
        return Err(format!(
            "btc header batch: {} headers exceeds max {}",
            headers.len(),
            MAX_BTC_HEADERS_PER_BATCH
        ));
    }
    let count = headers.len() as u16;
    let mut out = Vec::with_capacity(4 + BTC_HEADER_BYTES * headers.len());
    out.push(BTC_HEADER_BATCH_TAG);
    out.push(BTC_HEADER_BATCH_VERSION);
    out.extend_from_slice(&count.to_le_bytes());
    for h in headers {
        out.extend_from_slice(&h.serialize());
    }
    Ok(out)
}

/// Parse a `BtcHeaderBatch` output script into its raw header sequence.
/// Returns an error if the tag, version, count, or total length is malformed.
pub fn parse_btc_header_batch(script: &[u8]) -> Result<Vec<BtcHeader>, String> {
    if script.len() < 4 {
        return Err("btc header batch: script too short".to_string());
    }
    if script[0] != BTC_HEADER_BATCH_TAG {
        return Err("btc header batch: wrong tag".to_string());
    }
    if script[1] != BTC_HEADER_BATCH_VERSION {
        return Err("btc header batch: unknown version".to_string());
    }
    let count = u16::from_le_bytes([script[2], script[3]]) as usize;
    if count == 0 || count > MAX_BTC_HEADERS_PER_BATCH as usize {
        return Err(format!("btc header batch: count {} out of range", count));
    }
    let expected = 4 + BTC_HEADER_BYTES * count;
    if script.len() != expected {
        return Err(format!(
            "btc header batch: wrong size (got {}, expected {})",
            script.len(),
            expected
        ));
    }
    let mut headers = Vec::with_capacity(count);
    for i in 0..count {
        let start = 4 + i * BTC_HEADER_BYTES;
        let h = BtcHeader::deserialize(&script[start..start + BTC_HEADER_BYTES])?;
        headers.push(h);
    }
    Ok(headers)
}

/// Cumulative work attributable to a header with the given compact `bits`.
/// Standard Bitcoin formula: work = 2^256 / (target + 1).
pub fn work_for_bits(bits: u32) -> BigUint {
    let target = Target { bits }.to_target();
    let two_pow_256 = BigUint::from(1u8) << 256;
    let denom = target + BigUint::from(1u8);
    two_pow_256 / denom
}

pub fn btc_max_target() -> BigUint {
    Target {
        bits: BTC_MAX_TARGET_BITS,
    }
    .to_target()
}

/// Encode a target BigUint to Bitcoin's compact `bits` form.
/// Inverse of `Target::to_target` but always emits canonical form.
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

/// Combined read-only view over committed headers + headers staged earlier
/// in the same batch. Used during validation so a single batch can extend
/// itself across multiple new headers before any state is mutated.
struct LookupView<'a> {
    committed: &'a HashMap<[u8; 32], BtcHeaderEntry>,
    staged: &'a [([u8; 32], BtcHeaderEntry)],
}

impl<'a> LookupView<'a> {
    fn get(&self, hash: &[u8; 32]) -> Option<&BtcHeaderEntry> {
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

fn median_time_past_v(parent_hash: &[u8; 32], view: &LookupView, anchor: &BtcAnchor) -> u32 {
    let mut times: Vec<u32> = Vec::with_capacity(BTC_MTP_WINDOW);
    let mut cur = *parent_hash;
    while times.len() < BTC_MTP_WINDOW {
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
    anchor: &BtcAnchor,
) -> Result<u32, String> {
    if target_height == anchor.height {
        return Ok(anchor.time);
    }
    let mut cur = *parent_hash;
    loop {
        if cur == anchor.hash {
            return Err("retarget walk: reached anchor without finding target height".to_string());
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

fn expected_bits_for_v(
    height: u64,
    parent_hash: &[u8; 32],
    view: &LookupView,
    anchor: &BtcAnchor,
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
    if !height.is_multiple_of(BTC_RETARGET_INTERVAL) {
        return Ok(parent_bits);
    }
    let first_height = height - BTC_RETARGET_INTERVAL;
    if first_height < anchor.height {
        return Err("expected_bits: retarget window reaches before anchor".to_string());
    }
    let first_time = find_ancestor_time_at_height_v(parent_hash, first_height, view, anchor)?;
    let mut actual_timespan = parent_time.saturating_sub(first_time);
    let min_ts = BTC_EXPECTED_TIMESPAN / 4;
    let max_ts = BTC_EXPECTED_TIMESPAN.saturating_mul(4);
    if actual_timespan < min_ts {
        actual_timespan = min_ts;
    }
    if actual_timespan > max_ts {
        actual_timespan = max_ts;
    }
    let parent_target = Target { bits: parent_bits }.to_target();
    let new_target =
        parent_target * BigUint::from(actual_timespan) / BigUint::from(BTC_EXPECTED_TIMESPAN);
    let max_target = btc_max_target();
    let final_target = if new_target > max_target {
        max_target
    } else {
        new_target
    };
    Ok(target_to_compact_bits(&final_target))
}

/// Validate a header batch against current relay state and apply it.
/// On success, returns an undo record. On any error, no state is mutated.
///
/// Phase 1 rules:
/// - First header must link to the anchor or a known committed header.
/// - Every header in sequence must link to the previous one in the batch.
/// - Each header must satisfy PoW under its declared target.
/// - Each header's `bits` must match the expected target for its height
///   (parent's bits at non-retarget heights; retarget computation at H%2016==0).
/// - Each header's `time` must exceed the MTP of its 11 ancestors and not
///   exceed `iriumd_block_time + 2h`.
/// - No header may already exist in the committed set or be duplicated
///   within the batch.
///
/// Tip switches to the batch's final header iff that header's cumulative
/// work exceeds the prior tip's cumulative work. Lower-work batches are
/// recorded but don't switch the tip — they sit as known headers on a
/// non-canonical branch.
pub fn apply_btc_header_batch(
    headers: Vec<BtcHeader>,
    iriumd_block_time: u32,
    btc_headers: &mut HashMap<[u8; 32], BtcHeaderEntry>,
    btc_heights: &mut HashMap<[u8; 32], u64>,
    btc_tip: &mut Option<[u8; 32]>,
    btc_tip_height: &mut u64,
    anchor: &BtcAnchor,
) -> Result<BtcRelayUpdate, String> {
    if headers.is_empty() {
        return Err("apply_btc_header_batch: empty batch".to_string());
    }
    if anchor.is_zero() {
        return Err("apply_btc_header_batch: anchor not configured".to_string());
    }

    let first = &headers[0];
    let (start_prev_height, start_prev_work) = if first.prev_hash == anchor.hash {
        (anchor.height, work_for_bits(anchor.bits))
    } else {
        let parent = btc_headers.get(&first.prev_hash).ok_or_else(|| {
            "apply_btc_header_batch: first header does not connect to known chain".to_string()
        })?;
        (parent.height, parent.total_work.clone())
    };

    // Idempotency: when the wrapping BtcHeaderBatch tx that was already
    // applied via /rpc/submitbtcheaders is later mined into an iriumd
    // block, apply_btc_header_batch runs again against the same headers.
    // The "already known in chain state" check below would reject the
    // block and stall chain production (issue #59). If every header in
    // this batch is already committed at the expected height AND matches
    // the stored entry byte-for-byte, treat the call as a no-op success
    // instead. Fork attempts (different header data at the same heights)
    // still fall through to the normal validation path below, which will
    // fail fast on the first mismatching header.
    {
        let mut all_known_and_matching = true;
        let mut probe_prev_hash = first.prev_hash;
        let mut probe_prev_height = start_prev_height;
        for header in headers.iter() {
            if header.prev_hash != probe_prev_hash {
                all_known_and_matching = false;
                break;
            }
            let expected_height = probe_prev_height + 1;
            let hash = header.block_hash();
            let Some(entry) = btc_headers.get(&hash) else {
                all_known_and_matching = false;
                break;
            };
            if entry.height != expected_height || entry.header != *header {
                all_known_and_matching = false;
                break;
            }
            probe_prev_hash = hash;
            probe_prev_height = expected_height;
        }
        if all_known_and_matching {
            return Ok(BtcRelayUpdate {
                tip_before: *btc_tip,
                tip_height_before: *btc_tip_height,
                headers_added: Vec::new(),
            });
        }
    }

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
        let Some(entry) = btc_headers.get(&hash) else {
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
        return Ok(BtcRelayUpdate {
            tip_before: *btc_tip,
            tip_height_before: *btc_tip_height,
            headers_added: Vec::new(),
        });
    }
    if known_prefix > 0 && prefix_prev_height < *btc_tip_height {
        return Err(
            "apply_btc_header_batch: known prefix followed by non-tip fork".to_string(),
        );
    }

    let mut prev_hash = prefix_prev_hash;
    let mut prev_height = prefix_prev_height;
    let mut prev_work = prefix_prev_work;
    let headers_to_apply = &headers[known_prefix..];
    let mut staged: Vec<([u8; 32], BtcHeaderEntry)> =
        Vec::with_capacity(headers_to_apply.len());

    for (offset, header) in headers_to_apply.iter().enumerate() {
        let i = known_prefix + offset;
        if header.prev_hash != prev_hash {
            return Err(format!(
                "apply_btc_header_batch: header {} does not link to previous",
                i
            ));
        }
        let height = prev_height + 1;
        let hash = header.block_hash();

        if btc_headers.contains_key(&hash) {
            return Err(format!(
                "apply_btc_header_batch: header {} already known in chain state",
                i
            ));
        }
        if staged.iter().any(|(h, _)| h == &hash) {
            return Err(format!(
                "apply_btc_header_batch: header {} duplicated within batch",
                i
            ));
        }

        let header_target = Target { bits: header.bits };
        if !meets_target_btc(&hash, header_target) {
            return Err(format!("apply_btc_header_batch: header {} fails PoW", i));
        }

        let (expected_bits_opt, mtp) = {
            let view = LookupView {
                committed: btc_headers,
                staged: &staged,
            };
            // At a post-anchor pre-2x2016 retarget boundary the relay never
            // saw the headers needed to compute the new target. PoW for
            // header.bits is still validated separately above, so accept
            // any claimed bits here without enforcing the equality check.
            let bits = match expected_bits_for_v(height, &prev_hash, &view, anchor) {
                Ok(b) => Some(b),
                Err(e) if e == "expected_bits: retarget window reaches before anchor" => None,
                Err(e) => return Err(e),
            };
            let mtp = median_time_past_v(&prev_hash, &view, anchor);
            (bits, mtp)
        };
        if let Some(expected_bits) = expected_bits_opt {
            let expected_target = Target { bits: expected_bits }.to_target();
            if header_target.to_target() != expected_target {
                return Err(format!(
                    "apply_btc_header_batch: header {} bits mismatch (expected {:#010x}, got {:#010x})",
                    i, expected_bits, header.bits
                ));
            }
        }

        if header.time <= mtp {
            return Err(format!(
                "apply_btc_header_batch: header {} time {} not above MTP {}",
                i, header.time, mtp
            ));
        }
        if header.time > iriumd_block_time.saturating_add(BTC_MAX_FUTURE_TIME_SECS) {
            return Err(format!(
                "apply_btc_header_batch: header {} time {} more than 2h ahead of iriumd block time {}",
                i, header.time, iriumd_block_time
            ));
        }

        let work = prev_work.clone() + work_for_bits(header.bits);
        staged.push((
            hash,
            BtcHeaderEntry {
                header: header.clone(),
                height,
                total_work: work.clone(),
            },
        ));
        prev_hash = hash;
        prev_height = height;
        prev_work = work;
    }

    let tip_before = *btc_tip;
    let tip_height_before = *btc_tip_height;

    let final_hash = staged.last().unwrap().0;
    let final_height = staged.last().unwrap().1.height;
    let final_work = staged.last().unwrap().1.total_work.clone();

    let mut headers_added: Vec<[u8; 32]> = Vec::with_capacity(staged.len());
    for (hash, entry) in staged {
        headers_added.push(hash);
        btc_heights.insert(hash, entry.height);
        btc_headers.insert(hash, entry);
    }

    let current_tip_work = match tip_before {
        Some(h) => btc_headers
            .get(&h)
            .map(|e| e.total_work.clone())
            .unwrap_or_else(BigUint::zero),
        None => work_for_bits(anchor.bits),
    };
    if final_work > current_tip_work {
        *btc_tip = Some(final_hash);
        *btc_tip_height = final_height;
    }

    Ok(BtcRelayUpdate {
        tip_before,
        tip_height_before,
        headers_added,
    })
}

/// Reverse a previously-applied `BtcRelayUpdate`. Removes inserted headers
/// from the committed maps and restores tip pointers. Called from
/// `disconnect_tip_block` when an iriumd block carrying a header batch is
/// disconnected during a reorg.
pub fn undo_btc_relay_update(
    update: &BtcRelayUpdate,
    btc_headers: &mut HashMap<[u8; 32], BtcHeaderEntry>,
    btc_heights: &mut HashMap<[u8; 32], u64>,
    btc_tip: &mut Option<[u8; 32]>,
    btc_tip_height: &mut u64,
) {
    for hash in &update.headers_added {
        btc_headers.remove(hash);
        btc_heights.remove(hash);
    }
    *btc_tip = update.tip_before;
    *btc_tip_height = update.tip_height_before;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn clear_btc_spv_env() {
        std::env::remove_var("IRIUM_BTC_SPV_RELAY_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_BTC_ANCHOR_HEIGHT");
        std::env::remove_var("IRIUM_BTC_ANCHOR_HASH");
        std::env::remove_var("IRIUM_BTC_ANCHOR_BITS");
        std::env::remove_var("IRIUM_BTC_ANCHOR_TIME");
    }

    #[test]
    fn mainnet_btc_spv_resolves_with_populated_anchor() {
        let _guard = env_lock().lock().unwrap();
        clear_btc_spv_env();
        // Mainnet activation height and anchor are both populated as of
        // the height-23850 activation commit; resolve must return Some
        // with the production anchor.
        let resolved = resolve_btc_spv_params(NetworkKind::Mainnet);
        let params = resolved.expect("mainnet BTC SPV should resolve");
        assert_eq!(params.activation_height, 23_850);
        assert_eq!(params.anchor.height, MAINNET_BTC_ANCHOR_HEIGHT);
        assert_eq!(params.anchor.bits, MAINNET_BTC_ANCHOR_BITS);
        assert_eq!(params.anchor.time, MAINNET_BTC_ANCHOR_TIME);
        assert_eq!(params.anchor.hash, MAINNET_BTC_ANCHOR_HASH);
    }

    #[test]
    fn devnet_btc_spv_returns_some_when_all_env_vars_present() {
        let _guard = env_lock().lock().unwrap();
        clear_btc_spv_env();
        std::env::set_var("IRIUM_BTC_SPV_RELAY_ACTIVATION_HEIGHT", "100");
        std::env::set_var("IRIUM_BTC_ANCHOR_HEIGHT", "880000");
        // Display-order hex (Bitcoin RPC convention) — 64 hex chars, no 0x.
        std::env::set_var(
            "IRIUM_BTC_ANCHOR_HASH",
            "00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054",
        );
        std::env::set_var("IRIUM_BTC_ANCHOR_BITS", "0x1d00ffff");
        std::env::set_var("IRIUM_BTC_ANCHOR_TIME", "1730000000");
        let resolved = resolve_btc_spv_params(NetworkKind::Devnet);
        clear_btc_spv_env();
        let params = resolved.expect("devnet env-configured relay should resolve");
        assert_eq!(params.activation_height, 100);
        assert_eq!(params.anchor.height, 880000);
        assert_eq!(params.anchor.bits, 0x1d00ffff);
        assert_eq!(params.anchor.time, 1730000000);
        // Display-order input should be reversed to natural-order in storage.
        let mut expected_natural = [0u8; 32];
        let display_bytes = hex::decode(
            "00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054",
        )
        .unwrap();
        expected_natural.copy_from_slice(&display_bytes);
        expected_natural.reverse();
        assert_eq!(params.anchor.hash, expected_natural);
    }

    #[test]
    fn devnet_btc_spv_returns_none_when_activation_env_missing() {
        let _guard = env_lock().lock().unwrap();
        clear_btc_spv_env();
        std::env::set_var("IRIUM_BTC_ANCHOR_HEIGHT", "880000");
        std::env::set_var(
            "IRIUM_BTC_ANCHOR_HASH",
            "00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054",
        );
        std::env::set_var("IRIUM_BTC_ANCHOR_BITS", "0x1d00ffff");
        std::env::set_var("IRIUM_BTC_ANCHOR_TIME", "1730000000");
        let resolved = resolve_btc_spv_params(NetworkKind::Devnet);
        clear_btc_spv_env();
        assert!(resolved.is_none());
    }

    #[test]
    fn devnet_btc_spv_returns_none_when_anchor_env_partial() {
        let _guard = env_lock().lock().unwrap();
        clear_btc_spv_env();
        std::env::set_var("IRIUM_BTC_SPV_RELAY_ACTIVATION_HEIGHT", "100");
        std::env::set_var("IRIUM_BTC_ANCHOR_HEIGHT", "880000");
        // HASH missing — should refuse.
        std::env::set_var("IRIUM_BTC_ANCHOR_BITS", "0x1d00ffff");
        std::env::set_var("IRIUM_BTC_ANCHOR_TIME", "1730000000");
        let resolved = resolve_btc_spv_params(NetworkKind::Devnet);
        clear_btc_spv_env();
        assert!(resolved.is_none());
    }

    #[test]
    fn devnet_btc_spv_returns_none_on_malformed_anchor_hash() {
        let _guard = env_lock().lock().unwrap();
        clear_btc_spv_env();
        std::env::set_var("IRIUM_BTC_SPV_RELAY_ACTIVATION_HEIGHT", "100");
        std::env::set_var("IRIUM_BTC_ANCHOR_HEIGHT", "880000");
        std::env::set_var("IRIUM_BTC_ANCHOR_HASH", "not_valid_hex");
        std::env::set_var("IRIUM_BTC_ANCHOR_BITS", "0x1d00ffff");
        std::env::set_var("IRIUM_BTC_ANCHOR_TIME", "1730000000");
        let resolved = resolve_btc_spv_params(NetworkKind::Devnet);
        clear_btc_spv_env();
        assert!(resolved.is_none());
    }

    #[test]
    fn devnet_btc_spv_accepts_decimal_bits() {
        let _guard = env_lock().lock().unwrap();
        clear_btc_spv_env();
        std::env::set_var("IRIUM_BTC_SPV_RELAY_ACTIVATION_HEIGHT", "100");
        std::env::set_var("IRIUM_BTC_ANCHOR_HEIGHT", "880000");
        std::env::set_var(
            "IRIUM_BTC_ANCHOR_HASH",
            "00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054",
        );
        // Decimal form of 0x1d00ffff.
        std::env::set_var("IRIUM_BTC_ANCHOR_BITS", "486604799");
        std::env::set_var("IRIUM_BTC_ANCHOR_TIME", "1730000000");
        let resolved = resolve_btc_spv_params(NetworkKind::Devnet);
        clear_btc_spv_env();
        let params = resolved.expect("decimal bits should resolve");
        assert_eq!(params.anchor.bits, 0x1d00ffff);
    }

    #[test]
    fn testnet_btc_spv_uses_same_env_path_as_devnet() {
        let _guard = env_lock().lock().unwrap();
        clear_btc_spv_env();
        std::env::set_var("IRIUM_BTC_SPV_RELAY_ACTIVATION_HEIGHT", "50");
        std::env::set_var("IRIUM_BTC_ANCHOR_HEIGHT", "100");
        std::env::set_var(
            "IRIUM_BTC_ANCHOR_HASH",
            "0000000000000000000000000000000000000000000000000000000000000001",
        );
        std::env::set_var("IRIUM_BTC_ANCHOR_BITS", "0x207fffff");
        std::env::set_var("IRIUM_BTC_ANCHOR_TIME", "1700000000");
        let resolved = resolve_btc_spv_params(NetworkKind::Testnet);
        clear_btc_spv_env();
        let params = resolved.expect("testnet env-configured relay should resolve");
        assert_eq!(params.activation_height, 50);
        assert_eq!(params.anchor.height, 100);
    }

    fn regtest_bits() -> u32 {
        0x207f_ffff
    }

    fn mine_btc_header(prev_hash: [u8; 32], time: u32, bits: u32) -> BtcHeader {
        let mut nonce: u32 = 0;
        loop {
            let header = BtcHeader {
                version: 1,
                prev_hash,
                merkle_root: [0u8; 32],
                time,
                bits,
                nonce,
            };
            if meets_target_btc(&header.block_hash(), Target { bits }) {
                return header;
            }
            nonce = nonce.wrapping_add(1);
        }
    }

    fn fresh_anchor() -> (BtcAnchor, BtcHeader) {
        let bits = regtest_bits();
        let anchor_header = mine_btc_header([0u8; 32], 1_700_000_000, bits);
        let anchor = BtcAnchor {
            hash: anchor_header.block_hash(),
            height: 880_000,
            bits,
            time: anchor_header.time,
        };
        (anchor, anchor_header)
    }

    #[test]
    fn header_serialize_roundtrip() {
        let h = BtcHeader {
            version: 0x2000_0001,
            prev_hash: [0xaa; 32],
            merkle_root: [0xbb; 32],
            time: 1_700_000_000,
            bits: 0x1903_a30c,
            nonce: 0xdead_beef,
        };
        let bytes = h.serialize();
        assert_eq!(bytes.len(), 80);
        let decoded = BtcHeader::deserialize(&bytes).expect("decode");
        assert_eq!(decoded, h);
    }

    #[test]
    fn header_deserialize_rejects_wrong_size() {
        assert!(BtcHeader::deserialize(&[0u8; 79]).is_err());
        assert!(BtcHeader::deserialize(&[0u8; 81]).is_err());
    }

    #[test]
    fn batch_encode_parse_roundtrip() {
        let bits = regtest_bits();
        let h1 = mine_btc_header([0u8; 32], 1000, bits);
        let h2 = mine_btc_header(h1.block_hash(), 1001, bits);
        let batch = encode_btc_header_batch(&[h1.clone(), h2.clone()]).expect("encode");
        assert_eq!(batch[0], BTC_HEADER_BATCH_TAG);
        assert_eq!(batch[1], BTC_HEADER_BATCH_VERSION);
        assert_eq!(u16::from_le_bytes([batch[2], batch[3]]), 2);
        let parsed = parse_btc_header_batch(&batch).expect("parse");
        assert_eq!(parsed, vec![h1, h2]);
    }

    #[test]
    fn batch_parse_rejects_wrong_tag() {
        let mut script = vec![0xc3, 0x01, 0x01, 0x00];
        script.extend_from_slice(&[0u8; BTC_HEADER_BYTES]);
        assert!(parse_btc_header_batch(&script).is_err());
    }

    #[test]
    fn batch_parse_rejects_zero_count() {
        let script = vec![BTC_HEADER_BATCH_TAG, BTC_HEADER_BATCH_VERSION, 0, 0];
        assert!(parse_btc_header_batch(&script).is_err());
    }

    #[test]
    fn batch_parse_rejects_count_mismatch() {
        // count says 2 but payload has only 1 header worth of bytes
        let mut script = vec![BTC_HEADER_BATCH_TAG, BTC_HEADER_BATCH_VERSION, 2, 0];
        script.extend_from_slice(&[0u8; BTC_HEADER_BYTES]);
        assert!(parse_btc_header_batch(&script).is_err());
    }

    #[test]
    fn batch_parse_rejects_oversize_count() {
        let mut script = vec![BTC_HEADER_BATCH_TAG, BTC_HEADER_BATCH_VERSION];
        let oversize: u16 = MAX_BTC_HEADERS_PER_BATCH + 1;
        script.extend_from_slice(&oversize.to_le_bytes());
        assert!(parse_btc_header_batch(&script).is_err());
    }

    #[test]
    fn target_to_compact_bits_roundtrip_mainnet_min() {
        let target = Target {
            bits: BTC_MAX_TARGET_BITS,
        }
        .to_target();
        let bits = target_to_compact_bits(&target);
        assert_eq!(
            bits, BTC_MAX_TARGET_BITS,
            "round-trip must preserve canonical mainnet-min bits"
        );
    }

    #[test]
    fn target_to_compact_bits_roundtrip_real_difficulty() {
        let bits_in = 0x1903_a30c;
        let target = Target { bits: bits_in }.to_target();
        let bits_out = target_to_compact_bits(&target);
        assert_eq!(
            bits_out, bits_in,
            "round-trip must preserve a realistic mainnet bits value"
        );
    }

    #[test]
    fn target_to_compact_bits_handles_high_bit_shift() {
        // Pick a target whose top mantissa byte has the high bit set; encoding
        // must shift right and increment exponent to keep the value positive.
        let bits_in = 0x1d00_ffff;
        let target = Target { bits: bits_in }.to_target();
        let bits_out = target_to_compact_bits(&target);
        assert_eq!(bits_out, bits_in);
    }

    #[test]
    fn work_for_bits_minimum_mainnet_is_smallest_positive() {
        // At the minimum difficulty bits, work per header is at the floor for
        // mainnet. Sanity-check it is positive and non-trivial.
        let w = work_for_bits(BTC_MAX_TARGET_BITS);
        assert!(w > BigUint::from(0u8));
    }

    #[test]
    fn work_for_bits_harder_target_is_more_work() {
        let easy = work_for_bits(BTC_MAX_TARGET_BITS);
        let hard = work_for_bits(0x1903_a30c);
        assert!(hard > easy);
    }

    #[test]
    fn apply_rejects_when_anchor_not_configured() {
        let bits = regtest_bits();
        let h = mine_btc_header([0u8; 32], 1000, bits);
        let mut headers_db: HashMap<[u8; 32], BtcHeaderEntry> = HashMap::new();
        let mut heights_db: HashMap<[u8; 32], u64> = HashMap::new();
        let mut tip: Option<[u8; 32]> = None;
        let mut tip_height: u64 = 0;
        let zero_anchor = BtcAnchor::zero();
        let res = apply_btc_header_batch(
            vec![h],
            1_000_000,
            &mut headers_db,
            &mut heights_db,
            &mut tip,
            &mut tip_height,
            &zero_anchor,
        );
        assert!(res.is_err());
    }

    #[test]
    fn apply_extends_anchor_and_sets_tip() {
        let (anchor, anchor_header) = fresh_anchor();
        let h1 = mine_btc_header(anchor.hash, anchor_header.time + 600, anchor.bits);
        let mut headers_db: HashMap<[u8; 32], BtcHeaderEntry> = HashMap::new();
        let mut heights_db: HashMap<[u8; 32], u64> = HashMap::new();
        let mut tip: Option<[u8; 32]> = None;
        let mut tip_height: u64 = 0;

        let update = apply_btc_header_batch(
            vec![h1.clone()],
            anchor_header.time + 600,
            &mut headers_db,
            &mut heights_db,
            &mut tip,
            &mut tip_height,
            &anchor,
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
        let h1 = mine_btc_header(anchor.hash, anchor_header.time + 600, anchor.bits);
        let h2 = mine_btc_header(h1.block_hash(), anchor_header.time + 1200, anchor.bits);
        let mut headers_db: HashMap<[u8; 32], BtcHeaderEntry> = HashMap::new();
        let mut heights_db: HashMap<[u8; 32], u64> = HashMap::new();
        let mut tip: Option<[u8; 32]> = None;
        let mut tip_height: u64 = 0;

        let update = apply_btc_header_batch(
            vec![h1.clone(), h2.clone()],
            anchor_header.time + 1200,
            &mut headers_db,
            &mut heights_db,
            &mut tip,
            &mut tip_height,
            &anchor,
        )
        .expect("apply");

        assert_eq!(headers_db.len(), 2);
        assert_eq!(heights_db.len(), 2);
        assert_eq!(tip, Some(h2.block_hash()));
        assert_eq!(tip_height, anchor.height + 2);

        undo_btc_relay_update(
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
    fn replaying_identical_batch_is_noop_success() {
        // Issue #59: when /rpc/submitbtcheaders has already applied a batch
        // to chain state and the wrapping mempool tx is later mined into an
        // iriumd block, apply_btc_header_batch must accept the duplicate
        // apply as a no-op rather than rejecting with "already known in
        // chain state". Otherwise every miner block built on a template
        // that includes the tx gets rejected and the chain stalls.
        let (anchor, anchor_header) = fresh_anchor();
        let h1 = mine_btc_header(anchor.hash, anchor_header.time + 600, anchor.bits);
        let h2 = mine_btc_header(h1.block_hash(), anchor_header.time + 1200, anchor.bits);
        let mut headers_db: HashMap<[u8; 32], BtcHeaderEntry> = HashMap::new();
        let mut heights_db: HashMap<[u8; 32], u64> = HashMap::new();
        let mut tip: Option<[u8; 32]> = None;
        let mut tip_height: u64 = 0;

        // First apply: extends chain. Both hashes appear in headers_added.
        let first = apply_btc_header_batch(
            vec![h1.clone(), h2.clone()],
            anchor_header.time + 1200,
            &mut headers_db,
            &mut heights_db,
            &mut tip,
            &mut tip_height,
            &anchor,
        )
        .expect("first apply");
        assert_eq!(first.headers_added.len(), 2);
        assert_eq!(tip, Some(h2.block_hash()));
        assert_eq!(tip_height, anchor.height + 2);

        // Snapshot state for post-no-op comparison.
        let headers_before = headers_db.len();
        let heights_before = heights_db.len();
        let tip_snapshot = tip;
        let tip_height_snapshot = tip_height;

        // Second apply with the SAME batch: must succeed as a no-op.
        let second = apply_btc_header_batch(
            vec![h1.clone(), h2.clone()],
            anchor_header.time + 1200,
            &mut headers_db,
            &mut heights_db,
            &mut tip,
            &mut tip_height,
            &anchor,
        )
        .expect("idempotent re-apply must succeed");
        assert!(
            second.headers_added.is_empty(),
            "idempotent re-apply should add no headers"
        );
        assert_eq!(second.tip_before, tip_snapshot);
        assert_eq!(second.tip_height_before, tip_height_snapshot);
        assert_eq!(headers_db.len(), headers_before, "no headers added");
        assert_eq!(heights_db.len(), heights_before, "no heights added");
        assert_eq!(tip, tip_snapshot, "tip unchanged");
        assert_eq!(tip_height, tip_height_snapshot, "tip_height unchanged");

        // Sanity: a batch where one header is tampered (same prev_hash and
        // same height, different nonce -> different hash) must NOT be
        // silently treated as idempotent. It falls through to the existing
        // validation path which rejects h1 with "already known in chain
        // state". This proves the idempotency check requires byte-equal
        // headers, not just height/prev_hash linkage.
        let mut h2_tampered = h2.clone();
        h2_tampered.nonce = h2.nonce.wrapping_add(1);
        let mismatch = apply_btc_header_batch(
            vec![h1.clone(), h2_tampered],
            anchor_header.time + 1200,
            &mut headers_db,
            &mut heights_db,
            &mut tip,
            &mut tip_height,
            &anchor,
        );
        assert!(
            mismatch.is_err(),
            "modified header in re-applied batch must not be idempotent"
        );
    }

    #[test]
    fn apply_rejects_bad_linkage() {
        let (anchor, anchor_header) = fresh_anchor();
        let h1 = mine_btc_header(anchor.hash, anchor_header.time + 600, anchor.bits);
        let bad = mine_btc_header([0xee; 32], anchor_header.time + 1200, anchor.bits);
        let mut headers_db = HashMap::new();
        let mut heights_db = HashMap::new();
        let mut tip = None;
        let mut tip_height = 0;

        let res = apply_btc_header_batch(
            vec![h1, bad],
            anchor_header.time + 1200,
            &mut headers_db,
            &mut heights_db,
            &mut tip,
            &mut tip_height,
            &anchor,
        );
        assert!(res.is_err());
        assert!(
            headers_db.is_empty(),
            "no state should leak when batch is rejected"
        );
        assert!(tip.is_none());
    }

    #[test]
    fn apply_rejects_bad_pow() {
        let (anchor, anchor_header) = fresh_anchor();
        // Mine valid, then corrupt the nonce so it no longer meets target.
        let mut h1 = mine_btc_header(anchor.hash, anchor_header.time + 600, anchor.bits);
        // Find a nonce that does NOT meet target.
        for n in 0u32..1_000_000 {
            h1.nonce = n;
            if !meets_target(&h1.block_hash(), Target { bits: h1.bits }) {
                break;
            }
        }
        let mut headers_db = HashMap::new();
        let mut heights_db = HashMap::new();
        let mut tip = None;
        let mut tip_height = 0;

        let res = apply_btc_header_batch(
            vec![h1],
            anchor_header.time + 600,
            &mut headers_db,
            &mut heights_db,
            &mut tip,
            &mut tip_height,
            &anchor,
        );
        assert!(res.is_err());
    }

    #[test]
    fn apply_rejects_bits_change_at_non_retarget_height() {
        let (anchor, anchor_header) = fresh_anchor();
        // Different (still trivially-meetable) bits, but not the parent's:
        // at non-retarget heights bits must equal parent's, so this must reject.
        let bad_bits: u32 = 0x207e_ffff;
        let h1 = mine_btc_header(anchor.hash, anchor_header.time + 600, bad_bits);
        let mut headers_db = HashMap::new();
        let mut heights_db = HashMap::new();
        let mut tip = None;
        let mut tip_height = 0;

        let res = apply_btc_header_batch(
            vec![h1],
            anchor_header.time + 600,
            &mut headers_db,
            &mut heights_db,
            &mut tip,
            &mut tip_height,
            &anchor,
        );
        assert!(res.is_err());
    }

    #[test]
    fn apply_rejects_time_below_mtp() {
        let (anchor, anchor_header) = fresh_anchor();
        // Build 11 valid headers each 600s apart so MTP is well-defined.
        let mut headers_db = HashMap::new();
        let mut heights_db = HashMap::new();
        let mut tip = None;
        let mut tip_height = 0;
        let mut chain = Vec::new();
        let mut prev_hash = anchor.hash;
        let mut t = anchor_header.time;
        for _ in 0..11 {
            t += 600;
            let h = mine_btc_header(prev_hash, t, anchor.bits);
            prev_hash = h.block_hash();
            chain.push(h);
        }
        apply_btc_header_batch(
            chain.clone(),
            t,
            &mut headers_db,
            &mut heights_db,
            &mut tip,
            &mut tip_height,
            &anchor,
        )
        .expect("seed");

        // Now try a header with time at MTP exactly (the median of the 11 times).
        let mut times: Vec<u32> = chain.iter().map(|h| h.time).collect();
        times.sort();
        let mtp = times[times.len() / 2];
        let bad = mine_btc_header(prev_hash, mtp, anchor.bits);
        let res = apply_btc_header_batch(
            vec![bad],
            t + 600,
            &mut headers_db,
            &mut heights_db,
            &mut tip,
            &mut tip_height,
            &anchor,
        );
        assert!(res.is_err(), "header at MTP must be rejected");
    }

    #[test]
    fn apply_rejects_time_too_far_in_future() {
        let (anchor, anchor_header) = fresh_anchor();
        let iriumd_time = anchor_header.time + 600;
        // Mine a header with time = iriumd_time + 3h (above the 2h tolerance).
        let h1 = mine_btc_header(
            anchor.hash,
            iriumd_time + BTC_MAX_FUTURE_TIME_SECS + 3600,
            anchor.bits,
        );
        let mut headers_db = HashMap::new();
        let mut heights_db = HashMap::new();
        let mut tip = None;
        let mut tip_height = 0;
        let res = apply_btc_header_batch(
            vec![h1],
            iriumd_time,
            &mut headers_db,
            &mut heights_db,
            &mut tip,
            &mut tip_height,
            &anchor,
        );
        assert!(res.is_err());
    }

    #[test]
    fn apply_rejects_duplicate_inside_batch() {
        let (anchor, anchor_header) = fresh_anchor();
        let h1 = mine_btc_header(anchor.hash, anchor_header.time + 600, anchor.bits);
        let mut headers_db = HashMap::new();
        let mut heights_db = HashMap::new();
        let mut tip = None;
        let mut tip_height = 0;
        let res = apply_btc_header_batch(
            vec![h1.clone(), h1],
            anchor_header.time + 1200,
            &mut headers_db,
            &mut heights_db,
            &mut tip,
            &mut tip_height,
            &anchor,
        );
        assert!(res.is_err());
    }

    #[test]
    fn apply_treats_already_known_header_as_noop() {
        // Issue #59: re-applying a single-header batch whose header is
        // already committed at the expected height MUST be a no-op
        // success, not a rejection. The previous behavior (rejecting with
        // "already known in chain state") caused mainnet to stall when the
        // BtcHeaderBatch mempool tx was mined into a block.
        let (anchor, anchor_header) = fresh_anchor();
        let h1 = mine_btc_header(anchor.hash, anchor_header.time + 600, anchor.bits);
        let mut headers_db = HashMap::new();
        let mut heights_db = HashMap::new();
        let mut tip = None;
        let mut tip_height = 0;
        apply_btc_header_batch(
            vec![h1.clone()],
            anchor_header.time + 600,
            &mut headers_db,
            &mut heights_db,
            &mut tip,
            &mut tip_height,
            &anchor,
        )
        .expect("first apply");
        let update = apply_btc_header_batch(
            vec![h1],
            anchor_header.time + 1200,
            &mut headers_db,
            &mut heights_db,
            &mut tip,
            &mut tip_height,
            &anchor,
        )
        .expect("second apply must be idempotent (issue #59)");
        assert!(
            update.headers_added.is_empty(),
            "idempotent re-apply should add no headers"
        );
    }

    #[test]
    fn fork_with_less_work_records_but_does_not_switch_tip() {
        let (anchor, anchor_header) = fresh_anchor();
        // Canonical branch: two headers extending the anchor.
        let h1a = mine_btc_header(anchor.hash, anchor_header.time + 600, anchor.bits);
        let h2a = mine_btc_header(h1a.block_hash(), anchor_header.time + 1200, anchor.bits);
        let mut headers_db = HashMap::new();
        let mut heights_db = HashMap::new();
        let mut tip = None;
        let mut tip_height = 0;
        apply_btc_header_batch(
            vec![h1a.clone(), h2a.clone()],
            anchor_header.time + 1200,
            &mut headers_db,
            &mut heights_db,
            &mut tip,
            &mut tip_height,
            &anchor,
        )
        .expect("canonical apply");
        assert_eq!(tip, Some(h2a.block_hash()));
        let canonical_tip = tip;
        let canonical_height = tip_height;

        // Fork branch: a single header off the anchor (shorter than canonical).
        let h1b = mine_btc_header(anchor.hash, anchor_header.time + 700, anchor.bits);
        let _ = apply_btc_header_batch(
            vec![h1b.clone()],
            anchor_header.time + 1200,
            &mut headers_db,
            &mut heights_db,
            &mut tip,
            &mut tip_height,
            &anchor,
        )
        .expect("fork apply");
        assert_eq!(
            tip, canonical_tip,
            "shorter-work fork must not change canonical tip"
        );
        assert_eq!(tip_height, canonical_height);
        assert!(
            headers_db.contains_key(&h1b.block_hash()),
            "fork header is still recorded"
        );
    }

    #[test]
    fn longer_fork_switches_tip() {
        let (anchor, anchor_header) = fresh_anchor();
        let h1a = mine_btc_header(anchor.hash, anchor_header.time + 600, anchor.bits);
        let mut headers_db = HashMap::new();
        let mut heights_db = HashMap::new();
        let mut tip = None;
        let mut tip_height = 0;
        apply_btc_header_batch(
            vec![h1a.clone()],
            anchor_header.time + 600,
            &mut headers_db,
            &mut heights_db,
            &mut tip,
            &mut tip_height,
            &anchor,
        )
        .expect("seed");
        assert_eq!(tip, Some(h1a.block_hash()));

        // Fork off the anchor with a longer branch (2 vs 1) — must switch tip.
        let h1b = mine_btc_header(anchor.hash, anchor_header.time + 800, anchor.bits);
        let h2b = mine_btc_header(h1b.block_hash(), anchor_header.time + 1400, anchor.bits);
        apply_btc_header_batch(
            vec![h1b.clone(), h2b.clone()],
            anchor_header.time + 1400,
            &mut headers_db,
            &mut heights_db,
            &mut tip,
            &mut tip_height,
            &anchor,
        )
        .expect("fork apply");
        assert_eq!(tip, Some(h2b.block_hash()));
        assert_eq!(tip_height, anchor.height + 2);
    }
}
