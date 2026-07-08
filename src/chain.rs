#![allow(dead_code)]
use std::collections::{HashMap, HashSet};
use std::env;

use crate::anchors::AnchorManager;
use chrono::Utc;
use num_bigint::BigUint;
use num_traits::Zero;

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use crate::block::{Block, BlockHeader};
use crate::btc_spv::{
    apply_btc_header_batch, parse_btc_header_batch, undo_btc_relay_update, BtcAnchor,
    BtcHeaderEntry, BtcRelayUpdate, BtcSpvParams, BTC_HEADER_BATCH_TAG,
    MAX_BTC_HEADER_BATCH_BYTES,
};
use crate::btc_tx_parse::{btc_txid, parse_btc_tx_outputs, BtcOutputScript};
use crate::ltc_spv::{
    apply_ltc_header_batch, parse_ltc_header_batch, undo_ltc_relay_update, LtcAnchor,
    LtcHeaderEntry, LtcRelayUpdate, LtcSpvParams, RetargetParams, LTC_HEADER_BATCH_TAG,
    MAX_LTC_HEADER_BATCH_BYTES,
};
use crate::constants::{
    block_reward, block_target_interval, coinbase_maturity, BLOCK_TARGET_INTERVAL_V1, DIFFICULTY_RETARGET_INTERVAL, LWMA_MAX_TARGET_DOWN_FACTOR,
    LWMA_MAX_TARGET_UP_FACTOR, LWMA_MIN_DIFFICULTY_FLOOR, LWMA_SOLVETIME_CLAMP_FACTOR,
    LWMA_V2_MAX_TARGET_DOWN_FACTOR, LWMA_V2_MAX_TARGET_UP_FACTOR, LWMA_V2_SOLVETIME_CLAMP_FACTOR,
    LWMA_V2_WINDOW, LWMA_WINDOW, MAX_FUTURE_BLOCK_TIME, MAX_MONEY, MTP_ACTIVATION_HEIGHT,
};
use crate::genesis::LockedGenesis;
use crate::pow::{meets_target, min_difficulty_target, sha256d, Target};
use crate::tx::{
    compute_funding_binding, decode_hex,
    encode_htlc_btc_swap_v1_script, encode_htlc_ltc_swap_v1_script,
    encode_htlcv1_script,
    encode_ltc_swap_order_script,
    encode_mpso_script, encode_swap_order_script,
    p2pkh_script,
    parse_htlc_btc_swap_v1_script, parse_htlc_btc_swap_witness,
    parse_htlc_ltc_swap_v1_script, parse_htlc_ltc_swap_witness,
    parse_htlcv1_script, parse_input_witness,
    parse_ltc_swap_order_script, parse_ltc_swap_order_witness, parse_mpso_script,
    parse_output_encumbrance, parse_swap_order_script, parse_swap_order_witness,
    HtlcBtcSwapV1Output, HtlcBtcSwapWitness,
    HtlcLtcSwapV1Output, HtlcLtcSwapWitness,
    HtlcV1Output, InputWitness, LtcSwapOrderWitness, MpsoV1Output,
    OutputEncumbrance, SwapOrderWitness, Transaction, TxInput, TxOutput,
    BTC_OP_RETURN_BINDING_LEN, BTC_OP_RETURN_BINDING_MAGIC,
    LTC_OP_RETURN_BINDING_LEN, LTC_OP_RETURN_BINDING_MAGIC,
    HTLC_BTC_SWAP_V1_SCRIPT_LEN, HTLC_BTC_SWAP_V1_TAG,
    HTLC_LTC_SWAP_V1_SCRIPT_LEN, HTLC_LTC_SWAP_V1_TAG,
    HTLC_V1_SCRIPT_TAG,
    LTC_SWAP_ORDER_BUY_SCRIPT_LEN, LTC_SWAP_ORDER_DIRECTION_BUY,
    LTC_SWAP_ORDER_DIRECTION_SELL, LTC_SWAP_ORDER_MAX_SWEEP_FEE,
    LTC_SWAP_ORDER_MIN_LOCKED_VALUE, LTC_SWAP_ORDER_SELL_SCRIPT_LEN, LTC_SWAP_ORDER_V1_TAG,
    MAX_HTLC_BTC_SWAP_CONFIRMATIONS, MAX_HTLC_LTC_SWAP_CONFIRMATIONS,
    MIN_HTLC_BTC_SWAP_CONFIRMATIONS, MIN_HTLC_LTC_SWAP_CONFIRMATIONS,
    MPSO_V1_MAX_WITNESS_SIZE, MPSO_V1_TAG,
    SWAP_ORDER_BUY_SCRIPT_LEN, SWAP_ORDER_DIRECTION_BUY, SWAP_ORDER_DIRECTION_SELL,
    SWAP_ORDER_MAX_SWEEP_FEE, SWAP_ORDER_MIN_LOCKED_VALUE, SWAP_ORDER_SELL_SCRIPT_LEN,
    SWAP_ORDER_V1_TAG,
};

const MAX_ORPHAN_BLOCKS: usize = 100;

fn header_cache_window() -> u64 {
    env::var("IRIUM_HEADER_CACHE_WINDOW")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(10_000)
        .min(200_000)
}

fn block_store_window() -> u64 {
    env::var("IRIUM_BLOCK_STORE_WINDOW")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(5_000)
        .min(200_000)
}

/// Chain parameters for the Irium mainnet.
///
/// `solvetime_clamp_factor` replaces the previously-precomputed
/// `max_solvetime: u64` field. The clamp ceiling is now derived at use time
/// as `solvetime_clamp_factor × block_target_interval(target_height)`, so
/// the LWMA window correctly scales when the height crosses the block-time
/// V2 fork boundary. The two constructors continue to take
/// `(activation_height, pow_limit)` so every existing `ChainParams { ... }`
/// site compiles unchanged.
#[derive(Debug, Clone, Copy)]
pub struct LwmaParams {
    pub activation_height: Option<u64>,
    pub window: u64,
    pub min_solvetime: u64,
    pub solvetime_clamp_factor: u64,
    pub max_target_up_factor: u64,
    pub max_target_down_factor: u64,
    pub max_target: Target,
}

impl LwmaParams {
    pub fn new(activation_height: Option<u64>, pow_limit: Target) -> Self {
        Self {
            activation_height,
            window: LWMA_WINDOW,
            min_solvetime: 1,
            solvetime_clamp_factor: LWMA_SOLVETIME_CLAMP_FACTOR,
            max_target_up_factor: LWMA_MAX_TARGET_UP_FACTOR,
            max_target_down_factor: LWMA_MAX_TARGET_DOWN_FACTOR,
            max_target: min_difficulty_target(pow_limit, LWMA_MIN_DIFFICULTY_FLOOR),
        }
    }

    /// Construct LWMA v2 parameters: smaller window + larger solvetime clamp
    /// for faster post-collapse recovery. Per-block step clamp factors are
    /// unchanged, preserving manipulation resistance.
    pub fn new_v2(activation_height: Option<u64>, pow_limit: Target) -> Self {
        Self {
            activation_height,
            window: LWMA_V2_WINDOW,
            min_solvetime: 1,
            solvetime_clamp_factor: LWMA_V2_SOLVETIME_CLAMP_FACTOR,
            max_target_up_factor: LWMA_V2_MAX_TARGET_UP_FACTOR,
            max_target_down_factor: LWMA_V2_MAX_TARGET_DOWN_FACTOR,
            max_target: min_difficulty_target(pow_limit, LWMA_MIN_DIFFICULTY_FLOOR),
        }
    }

    /// LWMA solvetime ceiling at `target_height`. Multiplies the per-version
    /// clamp factor by `block_target_interval(target_height)` so the ceiling
    /// is V1=6×600=3600s (v1) / V1=10×600=6000s (v2) pre-fork and
    /// V2=6×120=720s / V2=10×120=1200s post-fork. Per-block step clamps
    /// (max_target_up_factor / max_target_down_factor) are NOT scaled — they
    /// are ratio clamps, not time clamps.
    pub fn max_solvetime_at(&self, target_height: u64) -> u64 {
        self.solvetime_clamp_factor
            .saturating_mul(block_target_interval(target_height))
    }
}

#[derive(Debug, Clone)]
pub struct ChainParams {
    pub genesis_block: Block,
    pub pow_limit: Target,
    pub htlcv1_activation_height: Option<u64>,
    pub mpsov1_activation_height: Option<u64>,
    pub lwma: LwmaParams,
    /// Optional LWMA v2 params. When Some and height >= v2.activation_height,
    /// replaces v1. None keeps v1 behavior indefinitely.
    pub lwma_v2: Option<LwmaParams>,
    pub auxpow_activation_height: Option<u64>,
    /// Bitcoin SPV header relay parameters. `None` keeps the relay disabled.
    /// When `Some`, blocks at or after `activation_height` may carry a
    /// `BtcHeaderBatch` output and `anchor` seeds the relay's view of the
    /// Bitcoin chain.
    pub btc_spv: Option<BtcSpvParams>,
    /// Litecoin SPV header relay parameters (Phase B). `None` keeps the
    /// LTC relay disabled. When `Some`, blocks at or after
    /// `activation_height` may carry an `LtcHeaderBatch` output (tag
    /// `0xc6`) and the validator will apply such batches into
    /// `ChainState.ltc_headers`. No claim path consumes these yet —
    /// Phase B is header relay only.
    pub ltc_spv: Option<LtcSpvParams>,
    /// HtlcBtcSwapV1 activation height (Phase 2). `None` keeps the
    /// BTC-proof claim path disabled. Activation should not precede the
    /// `btc_spv` relay's `activation_height`, otherwise proofs cannot
    /// resolve, but consensus does not refuse a misordered configuration
    /// — it just means no claim will ever succeed.
    pub htlc_btc_swap_v1_activation_height: Option<u64>,
    /// Activation height for accepting bech32 P2WPKH BTC payments in
    /// HtlcBtcSwapV1 claim proofs (in addition to the always-accepted
    /// legacy P2PKH form). `None` keeps the rule at "P2PKH only"; setting
    /// to `Some(<height>)` broadens acceptance from `<height>` onwards.
    /// This is a consensus-rule relaxation — old nodes will reject claims
    /// new nodes accept, so activation requires a coordinated upgrade
    /// window per the workflow in
    /// docs/htlcv1_activation_commit_workflow.md. LTC piggybacks on
    /// `htlc_ltc_swap_v1_activation_height` and needs no separate gate.
    pub btc_swap_bech32_payment_activation_height: Option<u64>,
    /// HtlcLtcSwapV1 activation height (Phase C). `None` keeps the
    /// LTC-proof claim path disabled. Same precondition relationship to
    /// `ltc_spv.activation_height` as the BTC pair above.
    pub htlc_ltc_swap_v1_activation_height: Option<u64>,
    /// SwapOrder activation height (Phase 3). `None` keeps the on-chain
    /// order book disabled. Sell-direction fills emit HtlcBtcSwapV1
    /// outputs, so activating before `htlc_btc_swap_v1_activation_height`
    /// would cause every fill to fail the output's structural check.
    pub swap_order_v1_activation_height: Option<u64>,
    /// LtcSwapOrder activation height (Phase D). `None` keeps the LTC
    /// on-chain order book disabled. Sell-direction fills emit
    /// HtlcLtcSwapV1 outputs (Phase C), so activating before
    /// `htlc_ltc_swap_v1_activation_height` would cause every sell-fill
    /// to fail the output's structural check.
    pub ltc_swap_order_v1_activation_height: Option<u64>,
    /// v1.9.62 issue #60: when set, blocks at or above this height may carry
    /// BTC/LTC header batches in the coinbase as zero-value outputs.
    /// Pre-activation blocks still reject coinbase batch outputs (the
    /// historical rule). `None` keeps the rule strict on this network.

    pub coinbase_header_batch_activation_height: Option<u64>,
}

/// Reference to a specific transaction output.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct OutPoint {
    pub txid: [u8; 32],
    pub index: u32,
}

/// UTXO with height tracking and coinbase flag.
#[derive(Debug, Clone)]
pub struct UtxoEntry {
    pub output: TxOutput,
    pub height: u64,
    pub is_coinbase: bool,
}

/// In-memory chain state: height, tip, total work, and UTXO set.
#[derive(Debug, Clone, Default)]
struct BlockUndo {
    spent: Vec<(OutPoint, UtxoEntry)>,
    created: Vec<OutPoint>,
    subsidy_created: u64,
    /// If this block applied a `BtcHeaderBatch` output, the relay-state
    /// change record needed to roll it back on disconnect.
    btc_relay_update: Option<BtcRelayUpdate>,
    /// If this block applied an `LtcHeaderBatch` output (Phase B), the
    /// relay-state change record needed to roll it back on disconnect.
    ltc_relay_update: Option<LtcRelayUpdate>,
    /// BTC outpoints `(btc_txid, op_return_vout)` newly inserted into
    /// `ChainState.claimed_btc_outpoints` by HtlcBtcSwapV1 BTC-proof claims
    /// in this block. Removed on disconnect.
    claimed_btc_outpoints_added: Vec<([u8; 32], u32)>,
    /// LTC outpoints newly inserted into `ChainState.claimed_ltc_outpoints`
    /// by HtlcLtcSwapV1 LTC-proof claims in this block (Phase C). Removed
    /// on disconnect.
    claimed_ltc_outpoints_added: Vec<([u8; 32], u32)>,
}

/// Read-only handle over the consensus state fields a transaction validator
/// needs beyond the UTXO set and the spending tx itself. Built once per
/// transaction inside `validate_transaction_internal` from the immutable
/// view of `ChainState` and passed down to `verify_transaction_signature`.
pub struct ConsensusView<'a> {
    pub btc_headers: &'a HashMap<[u8; 32], BtcHeaderEntry>,
    pub btc_heights: &'a HashMap<[u8; 32], u64>,
    pub btc_tip_height: u64,
    pub claimed_btc_outpoints: &'a HashSet<([u8; 32], u32)>,
    /// Phase C: LTC SPV state needed by HtlcLtcSwapV1 claim verification.
    pub ltc_headers: &'a HashMap<[u8; 32], LtcHeaderEntry>,
    pub ltc_heights: &'a HashMap<[u8; 32], u64>,
    pub ltc_tip_height: u64,
    pub claimed_ltc_outpoints: &'a HashSet<([u8; 32], u32)>,
}

#[derive(Debug)]
pub struct ChainState {
    pub params: ChainParams,
    pub height: u64,
    pub chain: Vec<Block>,
    pub total_work: BigUint,
    pub utxos: HashMap<OutPoint, UtxoEntry>,
    pub issued: u64,
    /// Pending headers indexed by their hash with cumulative work.
    pub headers: HashMap<[u8; 32], HeaderWork>,
    pub header_chain: Vec<[u8; 32]>,
    /// Orphans waiting on a parent hash.
    pub orphan_pool: HashMap<[u8; 32], Vec<Block>>,
    /// Stored blocks for fork/reorg handling.
    pub block_store: HashMap<[u8; 32], Block>,
    pub heights: HashMap<[u8; 32], u64>,
    pub cumulative_work: HashMap<[u8; 32], BigUint>,
    pub anchors: Option<AnchorManager>,
    pub best_tip: [u8; 32],
    undo_logs: HashMap<[u8; 32], BlockUndo>,
    /// BTC SPV header relay state — populated only after activation.
    pub btc_headers: HashMap<[u8; 32], BtcHeaderEntry>,
    pub btc_heights: HashMap<[u8; 32], u64>,
    pub btc_tip: Option<[u8; 32]>,
    pub btc_tip_height: u64,
    /// Replay-protection set: BTC outpoints `(btc_txid, op_return_vout)`
    /// already consumed by an HtlcBtcSwapV1 claim. Inserted at apply time,
    /// removed on disconnect via `BlockUndo.claimed_btc_outpoints_added`.
    pub claimed_btc_outpoints: HashSet<([u8; 32], u32)>,
    /// LTC SPV header relay state — populated only after Phase B
    /// activation. Mirrors the BTC SPV layout.
    pub ltc_headers: HashMap<[u8; 32], LtcHeaderEntry>,
    pub ltc_heights: HashMap<[u8; 32], u64>,
    pub ltc_tip: Option<[u8; 32]>,
    pub ltc_tip_height: u64,
    /// Replay-protection set: LTC outpoints already consumed by an
    /// HtlcLtcSwapV1 claim (Phase C). Mirrors `claimed_btc_outpoints`.
    pub claimed_ltc_outpoints: HashSet<([u8; 32], u32)>,
}

#[derive(Debug, Clone)]
pub struct HeaderWork {
    pub header: BlockHeader,
    pub height: u64,
    pub work: BigUint,
}

fn swap4_bytes_each_word(input: [u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..8 {
        let j = i * 4;
        out[j] = input[j + 3];
        out[j + 1] = input[j + 2];
        out[j + 2] = input[j + 1];
        out[j + 3] = input[j];
    }
    out
}

pub(crate) fn whatsminer_compat_pow_hash_for_height(
    header: &BlockHeader,
    height: u64,
) -> Option<[u8; 32]> {
    if height < crate::constants::STANDARD_HEADER_ACTIVATION_HEIGHT {
        return None;
    }

    let mut prev_natural = header.prev_hash;
    prev_natural.reverse();
    let prev_whatsminer = swap4_bytes_each_word(prev_natural);

    let mut ser = Vec::with_capacity(80);
    ser.extend_from_slice(&header.version.to_le_bytes());
    ser.extend_from_slice(&prev_whatsminer);
    ser.extend_from_slice(&header.merkle_root);
    ser.extend_from_slice(&header.time.to_le_bytes());
    ser.extend_from_slice(&header.bits.to_le_bytes());
    ser.extend_from_slice(&header.nonce.to_le_bytes());

    let mut h = sha256d(&ser);
    h.reverse();
    Some(h)
}

impl ChainState {
    pub fn new(params: ChainParams) -> Self {
        let mut state = ChainState {
            params,
            height: 0,
            chain: Vec::new(),
            total_work: BigUint::zero(),
            utxos: HashMap::new(),
            issued: 0,
            headers: HashMap::new(),
            header_chain: Vec::new(),
            orphan_pool: HashMap::new(),
            block_store: HashMap::new(),
            heights: HashMap::new(),
            cumulative_work: HashMap::new(),
            anchors: None,
            best_tip: [0u8; 32],
            undo_logs: HashMap::new(),
            btc_headers: HashMap::new(),
            btc_heights: HashMap::new(),
            btc_tip: None,
            btc_tip_height: 0,
            claimed_btc_outpoints: HashSet::new(),
            ltc_headers: HashMap::new(),
            ltc_heights: HashMap::new(),
            ltc_tip: None,
            ltc_tip_height: 0,
            claimed_ltc_outpoints: HashSet::new(),
        };
        let genesis = state.params.genesis_block.clone();
        state
            .connect_genesis(genesis.clone())
            .expect("valid genesis block");
        let genesis_hash = genesis.header.hash_for_height(0);
        let work = ChainState::block_work(&genesis);
        state.block_store.insert(genesis_hash, genesis);
        state.heights.insert(genesis_hash, 0);
        state.cumulative_work.insert(genesis_hash, work.clone());
        state.total_work = work;
        state.best_tip = genesis_hash;
        state
    }

    pub fn tip_height(&self) -> u64 {
        self.height.saturating_sub(1)
    }

    pub fn median_time_past(&self) -> u32 {
        let count = self.chain.len().min(11);
        if count == 0 {
            return 0;
        }
        let start = self.chain.len() - count;
        let mut times: Vec<u32> = self.chain[start..].iter().map(|b| b.header.time).collect();
        times.sort_unstable();
        times[count / 2]
    }

    fn htlcv1_active_at(&self, height: u64) -> bool {
        self.params
            .htlcv1_activation_height
            .map(|h| height >= h)
            .unwrap_or(false)
    }

    fn mpsov1_active_at(&self, height: u64) -> bool {
        self.params
            .mpsov1_activation_height
            .map(|h| height >= h)
            .unwrap_or(false)
    }

    fn btc_spv_relay_active_at(&self, height: u64) -> bool {
        self.params
            .btc_spv
            .as_ref()
            .map(|p| height >= p.activation_height)
            .unwrap_or(false)
    }

    /// v1.9.62 issue #60: true iff coinbase header-batch outputs are
    /// allowed at the given block height. Pre-activation blocks continue
    /// to reject any BTC/LTC batch output in the coinbase.
    fn coinbase_header_batch_active_at(&self, height: u64) -> bool {
        self.params
            .coinbase_header_batch_activation_height
            .map(|h| height >= h)
            .unwrap_or(false)
    }

    fn btc_anchor(&self) -> BtcAnchor {
        self.params
            .btc_spv
            .as_ref()
            .map(|p| p.anchor)
            .unwrap_or_else(BtcAnchor::zero)
    }

    fn ltc_spv_relay_active_at(&self, height: u64) -> bool {
        self.params
            .ltc_spv
            .as_ref()
            .map(|p| height >= p.activation_height)
            .unwrap_or(false)
    }

    fn ltc_anchor(&self) -> LtcAnchor {
        self.params
            .ltc_spv
            .as_ref()
            .map(|p| p.anchor)
            .unwrap_or_else(LtcAnchor::zero)
    }

    fn ltc_retarget_params(&self) -> RetargetParams {
        self.params
            .ltc_spv
            .as_ref()
            .map(|p| p.retarget)
            .unwrap_or(RetargetParams::LITECOIN)
    }

    fn htlc_ltc_swap_v1_active_at(&self, height: u64) -> bool {
        self.params
            .htlc_ltc_swap_v1_activation_height
            .map(|h| height >= h)
            .unwrap_or(false)
    }

    fn ltc_swap_order_v1_active_at(&self, height: u64) -> bool {
        self.params
            .ltc_swap_order_v1_activation_height
            .map(|h| height >= h)
            .unwrap_or(false)
    }

    fn swap_order_v1_active_at(&self, height: u64) -> bool {
        self.params
            .swap_order_v1_activation_height
            .map(|h| height >= h)
            .unwrap_or(false)
    }

    fn htlc_btc_swap_v1_active_at(&self, height: u64) -> bool {
        self.params
            .htlc_btc_swap_v1_activation_height
            .map(|h| height >= h)
            .unwrap_or(false)
    }

    fn btc_swap_bech32_payment_active_at(&self, height: u64) -> bool {
        self.params
            .btc_swap_bech32_payment_activation_height
            .map(|h| height >= h)
            .unwrap_or(false)
    }

    fn build_consensus_view(&self) -> ConsensusView<'_> {
        ConsensusView {
            btc_headers: &self.btc_headers,
            btc_heights: &self.btc_heights,
            btc_tip_height: self.btc_tip_height,
            claimed_btc_outpoints: &self.claimed_btc_outpoints,
            ltc_headers: &self.ltc_headers,
            ltc_heights: &self.ltc_heights,
            ltc_tip_height: self.ltc_tip_height,
            claimed_ltc_outpoints: &self.claimed_ltc_outpoints,
        }
    }

    /// Convenience wrapper: compute LWMA target using v1 parameters at
    /// `target_height`. Threads `target_height` into the underlying
    /// implementation so the LWMA expected-time / solvetime clamp uses the
    /// height-aware `block_target_interval(target_height)` for blocks that
    /// land at or past the block-time V2 fork.
    fn lwma_target_for_height(&self, target_height: u64) -> Target {
        self.lwma_target_for_height_with(&self.params.lwma, target_height)
    }

    fn lwma_active_at(&self, height: u64) -> bool {
        self.params
            .lwma
            .activation_height
            .map(|h| height >= h)
            .unwrap_or(false)
    }

    fn lwma_trace_enabled() -> bool {
        env::var("IRIUM_TRACE_LWMA")
            .ok()
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false)
    }

    fn orphan_pool_size(&self) -> usize {
        self.orphan_pool.values().map(|v| v.len()).sum()
    }

    fn prune_orphan_pool(&mut self) {
        while self.orphan_pool_size() > MAX_ORPHAN_BLOCKS {
            let key = match self.orphan_pool.keys().next().cloned() {
                Some(k) => k,
                None => break,
            };
            self.orphan_pool.remove(&key);
        }
    }

    pub fn clear_orphan_pool(&mut self) -> usize {
        let count = self.orphan_pool_size();
        self.orphan_pool.clear();
        count
    }

    fn prune_header_cache(&mut self) {
        let window = header_cache_window();
        if window == 0 {
            return;
        }
        let tip = self.tip_height();
        if tip <= window {
            return;
        }
        let min_height = tip.saturating_sub(window);
        self.headers.retain(|_, hw| hw.height >= min_height);
        if !self.header_chain.is_empty() {
            self.header_chain.retain(|h| self.headers.contains_key(h));
        }
    }

    fn prune_block_store(&mut self) {
        let window = block_store_window();
        if window == 0 {
            return;
        }
        let tip = self.tip_height();
        if tip <= window {
            return;
        }
        let min_height = tip.saturating_sub(window);
        let mut remove = Vec::new();
        for (hash, _) in self.block_store.iter() {
            if let Some(h) = self.heights.get(hash) {
                if *h <= min_height {
                    if let Some(block) = self.chain.get(*h as usize) {
                        if block.header.hash_for_height(*h) == *hash {
                            remove.push(*hash);
                        }
                    }
                }
            }
        }
        for hash in remove {
            self.block_store.remove(&hash);
        }
    }

    fn prune_caches(&mut self) {
        self.prune_header_cache();
        self.prune_block_store();
    }

    fn block_by_hash(&self, hash: &[u8; 32]) -> Option<Block> {
        if let Some(block) = self.block_store.get(hash) {
            return Some(block.clone());
        }
        let height = *self.heights.get(hash)?;
        self.chain.get(height as usize).cloned()
    }

    fn legacy_target_for_height(&self, height: u64) -> Target {
        // Devnet/regtest fast-mining override: return a near-maximum target so
        // commodity CPU mining finds blocks effectively instantly. Skip for
        // height 0 - the genesis block keeps its locked bits; otherwise
        // connect_genesis panics with a bits mismatch. Override is applied
        // at the target-lookup layer so miner-expected and validator-required
        // bits agree, avoiding a fork between them.
        if height > 0 && matches!(
            std::env::var("IRIUM_NETWORK").as_deref(),
            Ok("devnet") | Ok("regtest")
        ) {
            return Target { bits: 0x207fffff };
        }
        if height == 0 {
            return self.params.genesis_block.header.target();
        }
        let last_block = self
            .chain
            .last()
            .expect("chain should have at least genesis when querying target");

        // Pre-activation consensus path. Historical blocks must remain unchanged.
        if height < DIFFICULTY_RETARGET_INTERVAL || !height.is_multiple_of(DIFFICULTY_RETARGET_INTERVAL) {
            return last_block.header.target();
        }

        let interval = DIFFICULTY_RETARGET_INTERVAL as usize;
        if self.chain.len() <= interval {
            return last_block.header.target();
        }

        let prev_index = self.chain.len() - interval;
        let prev_block = &self.chain[prev_index];

        let actual_time = (last_block.header.time as i64) - (prev_block.header.time as i64);
        // Legacy 2016-block retarget. On live mainnet this codepath is dead
        // (LWMA activated at h=16_462, so legacy retarget heights 2016/4032
        // never reach this branch in practice — pre-LWMA blocks took the
        // `height < INTERVAL || height % INTERVAL != 0` early return above).
        // Pre-LWMA heights are all far below any future block-time V2 fork,
        // so we hardcode `BLOCK_TARGET_INTERVAL_V1` here for clarity and to
        // freeze the historical formula.
        let mut expected_time = (DIFFICULTY_RETARGET_INTERVAL * BLOCK_TARGET_INTERVAL_V1) as i64;
        if expected_time <= 0 {
            expected_time = 1;
        }

        let mut adj_num = if actual_time <= 0 {
            expected_time / 4
        } else {
            actual_time
        };
        let adj_den = expected_time;

        if adj_num * 4 < adj_den {
            adj_num = adj_den / 4;
        } else if adj_num > adj_den * 4 {
            adj_num = adj_den * 4;
        }

        let last_target = last_block.header.target().to_target();
        let mut new_target = last_target * BigUint::from(adj_num as u64);
        new_target /= BigUint::from(adj_den as u64);

        Target::from_target(&new_target)
    }

    /// Deterministic LWMA next-work calculation used at and after activation.
    ///
    /// Formula in target space:
    /// 1. For the last `N` solved blocks, clamp each solvetime to `[1, 6*T]`.
    /// 2. Compute `weighted_solvetimes = sum_i(i * solvetime_i)` for weights `i = 1..N`.
    /// 3. Compute `avg_target = sum(target_i) / N` over the same window.
    /// 4. Compute `expected = T * sum_i(i)`.
    /// 5. Compute `next_target = avg_target * weighted_solvetimes / expected`.
    /// 6. Clamp `next_target` against the previous target so it cannot tighten
    ///    or ease by more than the configured per-block step factor.
    /// 7. Cap `next_target` by `min(pow_limit, lwma.max_target)`.
    ///
    /// All arithmetic is integer-only and deterministic. Compact bits encoding
    /// is used only at the boundaries.
    fn lwma_target_for_height_with(&self, params: &LwmaParams, target_height: u64) -> Target {
        // Devnet/regtest fast-mining override: return a near-maximum target so
        // commodity CPU mining finds blocks effectively instantly. Skip for
        // height 0 - the genesis block keeps its locked bits; otherwise
        // connect_genesis panics with a bits mismatch. Override is applied
        // at the target-lookup layer so miner-expected and validator-required
        // bits agree, avoiding a fork between them.
        if self.chain.len() > 1 && matches!(
            std::env::var("IRIUM_NETWORK").as_deref(),
            Ok("devnet") | Ok("regtest")
        ) {
            return Target { bits: 0x207fffff };
        }
        let last_block = self
            .chain
            .last()
            .expect("chain should have at least genesis when querying target");
        let sample_count =
            std::cmp::min(params.window as usize, self.chain.len().saturating_sub(1));
        if sample_count == 0 {
            return last_block.header.target();
        }

        // Height-aware protocol target. Pre-V2-fork heights resolve to
        // BLOCK_TARGET_INTERVAL_V1=600; at/past the fork they resolve to
        // BLOCK_TARGET_INTERVAL_V2=120. Both the solvetime clamp ceiling
        // and the LWMA expected-time scale from the same value, keeping
        // the algorithm self-consistent across the fork boundary.
        let target_t = block_target_interval(target_height);
        let max_solvetime = params.max_solvetime_at(target_height);

        let start = self.chain.len() - sample_count;
        let mut weighted_solvetimes = 0u128;
        let mut weight_total = 0u128;
        let mut target_sum = BigUint::zero();

        for (offset, idx) in (start..self.chain.len()).enumerate() {
            let current = &self.chain[idx];
            let previous = &self.chain[idx - 1];
            let raw_solvetime = current
                .header
                .time
                .saturating_sub(previous.header.time)
                .max(params.min_solvetime as u32) as u64;
            let solvetime = raw_solvetime.min(max_solvetime);
            let weight = (offset as u128) + 1;
            weighted_solvetimes += weight * u128::from(solvetime);
            weight_total += weight;
            target_sum += current.header.target().to_target();
        }

        let mut avg_target = target_sum / BigUint::from(sample_count as u64);
        if avg_target.is_zero() {
            avg_target = BigUint::from(1u8);
        }

        let observed = BigUint::from(weighted_solvetimes.max(1));
        let expected = BigUint::from((target_t as u128) * weight_total);
        let mut next_target = avg_target * observed;
        next_target /= expected;
        if next_target.is_zero() {
            next_target = BigUint::from(1u8);
        }

        let previous_target = last_block.header.target().to_target();
        let mut min_step_target = previous_target.clone();
        min_step_target /= BigUint::from(params.max_target_down_factor.max(1));
        if min_step_target.is_zero() {
            min_step_target = BigUint::from(1u8);
        }
        let max_step_target = &previous_target * BigUint::from(params.max_target_up_factor.max(1));

        if next_target < min_step_target {
            next_target = min_step_target;
        }
        if next_target > max_step_target {
            next_target = max_step_target;
        }

        let mut hard_max_target = self.params.pow_limit.to_target();
        let lwma_max_target = params.max_target.to_target();
        if lwma_max_target < hard_max_target {
            hard_max_target = lwma_max_target;
        }
        if next_target > hard_max_target {
            next_target = hard_max_target;
        }

        Target::from_target(&next_target)
    }

    /// Returns true if LWMA v2 is active at the given height.
    fn lwma_v2_active_at(&self, height: u64) -> bool {
        self.params
            .lwma_v2
            .and_then(|v2| v2.activation_height)
            .map(|h| height >= h)
            .unwrap_or(false)
    }

    pub fn target_for_height(&self, height: u64) -> Target {
        let legacy_target = self.legacy_target_for_height(height);
        if !self.lwma_active_at(height) {
            return legacy_target;
        }

        // Use LWMA v2 params if active; otherwise fall back to v1. Both
        // arms thread `height` through so the LWMA expected-time and
        // solvetime clamp see the height-aware protocol target.
        let (lwma_target, version) = if self.lwma_v2_active_at(height) {
            let v2 = self
                .params
                .lwma_v2
                .expect("lwma_v2 must be Some when v2 is active");
            (self.lwma_target_for_height_with(&v2, height), 2u8)
        } else {
            (self.lwma_target_for_height(height), 1u8)
        };

        if Self::lwma_trace_enabled() {
            eprintln!(
                "[trace][lwma] height={} version={} old_bits={:08x} lwma_bits={:08x} selected_bits={:08x}",
                height, version, legacy_target.bits, lwma_target.bits, lwma_target.bits
            );
        }
        lwma_target
    }
    /// Attach an anchor manager for checkpoint enforcement.
    pub fn set_anchors(&mut self, anchors: AnchorManager) {
        self.anchors = Some(anchors);
    }

    /// Work for a block based on its target (Bitcoin-style).
    pub fn block_work(block: &Block) -> BigUint {
        Self::work_for_target(block.header.target())
    }

    fn work_for_target(target: Target) -> BigUint {
        let target = target.to_target();
        if target.is_zero() {
            return BigUint::zero();
        }
        let max = BigUint::from(1u8) << 256;
        max / (target + BigUint::from(1u8))
    }
    #[allow(dead_code)]
    pub fn connect_block(&mut self, block: Block) -> Result<(), String> {
        let expected_height = self.height;
        let previous = self.chain.last();
        self.validate_block_header(&block, expected_height, previous)?;

        let reward = block_reward(expected_height);
        let (_fees, _coinbase_total, subsidy_created, undo) = self
            .validate_and_apply_transactions(
                &block,
                reward,
                expected_height,
                true,
                Some(MAX_MONEY - self.issued),
            )?;

        let new_supply = self
            .issued
            .checked_add(subsidy_created)
            .ok_or_else(|| "Supply overflow".to_string())?;

        let work = ChainState::block_work(&block);
        self.total_work += work;
        let hash = block.header.hash_for_height(expected_height);
        self.chain.push(block.clone());
        self.height += 1;
        self.issued = new_supply;

        self.block_store.insert(hash, block);
        self.heights.insert(hash, expected_height);
        self.cumulative_work.insert(hash, self.total_work.clone());
        self.undo_logs.insert(hash, undo);
        self.best_tip = hash;
        self.prune_caches();

        Ok(())
    }

    fn is_hash_on_main_chain(&self, hash: &[u8; 32]) -> Option<u64> {
        let h = *self.heights.get(hash)?;
        if self
            .chain
            .get(h as usize)
            .map(|b| b.header.hash_for_height(h) == *hash)
            .unwrap_or(false)
        {
            Some(h)
        } else {
            None
        }
    }

    fn disconnect_tip_block(&mut self) -> Result<Block, String> {
        let tip_block = self
            .chain
            .last()
            .cloned()
            .ok_or_else(|| "cannot disconnect empty chain".to_string())?;
        if self.chain.len() <= 1 {
            return Err("cannot disconnect genesis".to_string());
        }
        let tip_height = self.height.saturating_sub(1);
        let tip_hash = tip_block.header.hash_for_height(tip_height);
        let undo = self
            .undo_logs
            .remove(&tip_hash)
            .ok_or_else(|| "missing undo data for tip block".to_string())?;

        for consumed in &undo.claimed_btc_outpoints_added {
            self.claimed_btc_outpoints.remove(consumed);
        }

        if let Some(update) = undo.btc_relay_update.as_ref() {
            undo_btc_relay_update(
                update,
                &mut self.btc_headers,
                &mut self.btc_heights,
                &mut self.btc_tip,
                &mut self.btc_tip_height,
            );
        }

        if let Some(update) = undo.ltc_relay_update.as_ref() {
            undo_ltc_relay_update(
                update,
                &mut self.ltc_headers,
                &mut self.ltc_heights,
                &mut self.ltc_tip,
                &mut self.ltc_tip_height,
            );
        }

        for consumed in &undo.claimed_ltc_outpoints_added {
            self.claimed_ltc_outpoints.remove(consumed);
        }
        for op in undo.created {
            self.utxos.remove(&op);
        }
        for (op, entry) in undo.spent {
            self.utxos.insert(op, entry);
        }

        self.issued = self.issued.saturating_sub(undo.subsidy_created);
        let work = ChainState::block_work(&tip_block);
        if self.total_work >= work {
            self.total_work -= work;
        } else {
            self.total_work = BigUint::zero();
        }

        self.chain.pop();
        self.height = self.chain.len() as u64;
        let new_tip_height = self.height.saturating_sub(1);
        self.best_tip = self
            .chain
            .last()
            .map(|b| b.header.hash_for_height(new_tip_height))
            .unwrap_or([0u8; 32]);
        Ok(tip_block)
    }

    fn find_reorg_path(&self, new_tip: [u8; 32]) -> Result<(u64, Vec<Block>), String> {
        let mut cur = new_tip;
        let mut new_branch_rev: Vec<Block> = Vec::new();
        loop {
            if let Some(h) = self.is_hash_on_main_chain(&cur) {
                new_branch_rev.reverse();
                return Ok((h, new_branch_rev));
            }
            let block = self
                .block_by_hash(&cur)
                .ok_or_else(|| "missing block for reorg path".to_string())?;
            let prev = block.header.prev_hash;
            new_branch_rev.push(block);
            if prev == [0u8; 32] {
                return Err("reorg path has no common ancestor".to_string());
            }
            cur = prev;
        }
    }

    fn reorg_to_tip(&mut self, new_tip: [u8; 32]) -> Result<(), String> {
        let (ancestor_height, new_branch) = self.find_reorg_path(new_tip)?;
        let current_tip_height = self.tip_height();
        if ancestor_height >= current_tip_height {
            return Ok(());
        }

        // Observability: capture old-tip hash and counts before mutating
        // chain state. Emitted as a single [reorg] log line on success
        // below so operators can finally see how often the chain reorgs
        // and at what depth — successful reorgs were previously silent.
        let old_tip_hash = self.tip_hash();
        let disconnected_count = current_tip_height - ancestor_height;
        let connected_count = new_branch.len() as u64;

        let mut disconnected: Vec<Block> = Vec::new();
        while self.tip_height() > ancestor_height {
            disconnected.push(self.disconnect_tip_block()?);
        }

        let mut connected_new: Vec<Block> = Vec::new();
        for block in &new_branch {
            if let Err(e) = self.connect_block(block.clone()) {
                for _ in 0..connected_new.len() {
                    let _ = self.disconnect_tip_block();
                }
                for old in disconnected.iter().rev() {
                    let _ = self.connect_block(old.clone());
                }
                return Err(format!("reorg connect failed: {}", e));
            }
            connected_new.push(block.clone());
        }

        eprintln!(
            "[reorg] old tip: {} new tip: {} height: {} disconnected: {} blocks",
            hex::encode(old_tip_hash),
            hex::encode(new_tip),
            ancestor_height + connected_count,
            disconnected_count,
        );
        let _ = connected_count;
        Ok(())
    }

    /// Try to connect a block at an explicit height and return true if accepted.
    pub fn try_connect_at(&mut self, height: u64, block: Block) -> bool {
        if height != self.height {
            return false;
        }
        self.connect_block(block).is_ok()
    }

    /// Add a header to the header tree if it extends a known header and compute cumulative work.
    pub fn add_header(&mut self, header: BlockHeader) -> Result<u64, String> {
        // Look up the parent first so we know `height` before computing the
        // height-aware hash. Pre-Fix-2a the hash was computed before height,
        // but the post-30000 byte-order convention depends on height.
        let prev_hash = header.prev_hash;
        let (parent_height, parent_work) = if let Some(h) = self.heights.get(&prev_hash) {
            let work = self
                .cumulative_work
                .get(&prev_hash)
                .cloned()
                .unwrap_or_else(BigUint::zero);
            (*h, work)
        } else if let Some(h) = self.headers.get(&prev_hash) {
            (h.height, h.work.clone())
        } else {
            return Err("unknown parent".to_string());
        };

        // Basic PoW check.
        let height = parent_height + 1;
        let hash = header.hash_for_height(height);
        if self.headers.contains_key(&hash) || self.heights.contains_key(&hash) {
            if let Some(h) = self.heights.get(&hash) {
                return Ok(*h);
            }
            return Ok(self.headers.get(&hash).map(|hw| hw.height).unwrap_or(0));
        }
        let auxpow_active = self.params.auxpow_activation_height
            .map(|ah| height >= ah)
            .unwrap_or(false);
        if header.version & crate::auxpow::AUXPOW_VERSION_BIT != 0 && auxpow_active {
            // Full AuxPoW validation requires the complete block; deferred to process_block.
        } else if !meets_target(&hash, header.target()) {
            return Err("header does not meet target".to_string());
        }

        let work = parent_work + Self::work_for_target(header.target());
        self.headers.insert(
            hash,
            HeaderWork {
                header: header.clone(),
                height,
                work: work.clone(),
            },
        );
        // Track header chain for best-work selection.
        self.header_chain.push(hash);
        Ok(height)
    }

    /// Best header hash by total work (main chain tip or best header).
    pub fn best_header_hash(&self) -> [u8; 32] {
        let tip_height = self.height.saturating_sub(1);
        let mut best = (
            self.total_work.clone(),
            self.chain.last().map(|b| b.header.hash_for_height(tip_height)),
        );
        for hw in self.headers.values() {
            if hw.work > best.0 {
                best = (hw.work.clone(), Some(hw.header.hash_for_height(hw.height)));
            }
        }
        best.1.unwrap_or([0u8; 32])
    }

    /// Best-work header entry if it beats the current chain tip.
    pub fn best_header_if_better(&self) -> Option<HeaderWork> {
        let mut best: Option<HeaderWork> = None;
        for hw in self.headers.values() {
            if hw.work > self.total_work
                && best.as_ref().map(|b| b.work < hw.work).unwrap_or(true) {
                    best = Some(hw.clone());
                }
        }
        best
    }

    /// Check if a header connects to current tip.
    pub fn connects_to_tip(&self, header: &BlockHeader) -> bool {
        let tip_height = self.height.saturating_sub(1);
        self.chain
            .last()
            .map(|b| b.header.hash_for_height(tip_height) == header.prev_hash)
            .unwrap_or(false)
    }

    /// Attempt to reorganize to the best-work header by requesting/connecting supplied blocks.
    /// The caller is responsible for providing blocks in order for the target fork.
    pub fn try_reorg(&mut self, new_blocks: &[Block]) -> Result<bool, String> {
        if let Some(_best_header) = self.best_header_if_better() {
            // Simple sanity: the provided blocks must connect from current tip.
            let tip_height = self.height.saturating_sub(1);
            let mut current_hash = self
                .chain
                .last()
                .map(|b| b.header.hash_for_height(tip_height))
                .unwrap_or([0u8; 32]);
            for block in new_blocks {
                if block.header.prev_hash != current_hash {
                    return Err("Reorg block does not connect".to_string());
                }
                self.connect_block(block.clone())?;
                // After connect_block self.height has incremented; the block
                // just connected sits at self.height - 1.
                current_hash = block.header.hash_for_height(self.height.saturating_sub(1));
            }
            // Clear headers since we have advanced main chain.
            self.headers.clear();
            self.header_chain.clear();
            return Ok(true);
        }
        Ok(false)
    }

    fn connect_genesis(&mut self, block: Block) -> Result<(), String> {
        if !self.chain.is_empty() {
            return Err("Genesis block already connected".to_string());
        }
        self.validate_block_header(&block, 0, None)?;
        let (_fees, _coinbase_total, subsidy_created, _undo) =
            self.validate_and_apply_transactions(&block, 0, 0, false, Some(MAX_MONEY))?;

        self.total_work = ChainState::block_work(&block);
        let h = block.header.hash_for_height(0);
        self.chain.push(block);
        self.height = 1;
        self.issued = subsidy_created;
        self.best_tip = h;
        Ok(())
    }

    fn validate_block_header(
        &self,
        block: &Block,
        height: u64,
        previous: Option<&Block>,
    ) -> Result<(), String> {
        if let Some(prev) = previous {
            if block.header.prev_hash != prev.header.hash_for_height(height.saturating_sub(1)) {
                return Err("Block does not extend the current tip".to_string());
            }
        } else if block.header.prev_hash != [0u8; 32] {
            return Err("Genesis block must reference null hash".to_string());
        }

        // Timestamp validation
        let current_time = Utc::now().timestamp();
        if (block.header.time as i64) > current_time + MAX_FUTURE_BLOCK_TIME {
            return Err("Block timestamp too far in future".to_string());
        }
        if height >= MTP_ACTIVATION_HEIGHT {
            let mtp = self.median_time_past();
            if block.header.time <= mtp {
                return Err("Block timestamp must be greater than median time past".to_string());
            }
        } else if let Some(prev) = previous {
            if block.header.time <= prev.header.time {
                return Err("Block timestamp must be greater than previous block".to_string());
            }
        }

        // Merkle root (skip recompute for genesis; trust locked genesis file)
        if height > 0 {
            let recalculated_root = block.merkle_root();
            if block.header.merkle_root != recalculated_root {
                return Err("Block merkle root mismatch".to_string());
            }
        }

        // POW / bits
        let header_hash = block.header.hash_for_height(height);
        let whatsminer_compat_hash = whatsminer_compat_pow_hash_for_height(&block.header, height);
        let target = self.target_for_height(height);
        if block.header.target().bits != target.bits {
            return Err("Block bits mismatch".to_string());
        }
        let auxpow_active = self.params.auxpow_activation_height
            .map(|ah| height >= ah)
            .unwrap_or(false);
        if block.header.version & crate::auxpow::AUXPOW_VERSION_BIT != 0 && auxpow_active {
            let header_bytes = block.header.serialize_for_height(height);
            let ap = block.auxpow.as_ref()
                .ok_or_else(|| "AuxPoW block is missing AuxPoW data".to_string())?;
            crate::auxpow::validate(ap, &header_bytes, target)?;
        } else if !meets_target(&header_hash, target)
            && !whatsminer_compat_hash
                .as_ref()
                .map(|h| meets_target(h, target))
                .unwrap_or(false)
        {
            return Err("Block does not satisfy proof-of-work target".to_string());
        }

        Ok(())
    }

    fn validate_and_apply_transactions(
        &mut self,
        block: &Block,
        block_reward_value: u64,
        height: u64,
        enforce_reward: bool,
        max_subsidy: Option<u64>,
    ) -> Result<(u64, u64, u64, BlockUndo), String> {
        if block.transactions.is_empty() {
            return Err("Block must include transactions".to_string());
        }
        let coinbase = &block.transactions[0];
        if !is_coinbase(coinbase) {
            return Err("First transaction must be coinbase".to_string());
        }
        if coinbase.outputs.is_empty() {
            return Err("Coinbase transaction must create outputs".to_string());
        }

        let mut created: Vec<(OutPoint, TxOutput, bool)> = Vec::new();
        let mut fees: i64 = 0;
        let mut seen_inputs: HashSet<OutPoint> = HashSet::new();
        let mut btc_relay_update: Option<BtcRelayUpdate> = None;
        let mut btc_batch_count: usize = 0;
        let mut btc_outpoints_consumed: Vec<([u8; 32], u32)> = Vec::new();
        let mut ltc_relay_update: Option<LtcRelayUpdate> = None;
        let mut ltc_batch_count: usize = 0;
        let mut ltc_outpoints_consumed: Vec<([u8; 32], u32)> = Vec::new();

        for tx in block.transactions.iter().skip(1) {
            self.validate_transaction_internal(
                tx,
                height,
                &mut seen_inputs,
                &mut fees,
                &mut btc_outpoints_consumed,
                &mut ltc_outpoints_consumed,
            )?;
            let txid = tx.txid();
            for (index, output) in tx.outputs.iter().cloned().enumerate() {
                let op = OutPoint {
                    txid,
                    index: index as u32,
                };
                if output.script_pubkey.first().copied() == Some(BTC_HEADER_BATCH_TAG) {
                    // Structural validity already enforced by validate_output via
                    // validate_transaction_internal above. Now apply the batch
                    // into BTC relay state.
                    if !self.btc_spv_relay_active_at(height) {
                        return Err(
                            "BtcHeaderBatch output before SPV relay activation".to_string(),
                        );
                    }
                    btc_batch_count += 1;
                    if btc_batch_count > 1 {
                        return Err("block contains more than one BtcHeaderBatch output".to_string());
                    }
                    let headers = parse_btc_header_batch(&output.script_pubkey)
                        .map_err(|e| format!("BtcHeaderBatch apply parse failed: {}", e))?;
                    let anchor = self.btc_anchor();
                    let update = apply_btc_header_batch(
                        headers,
                        block.header.time,
                        &mut self.btc_headers,
                        &mut self.btc_heights,
                        &mut self.btc_tip,
                        &mut self.btc_tip_height,
                        &anchor,
                    )?;
                    btc_relay_update = Some(update);
                    // Header-batch outputs are consumed at apply time and not
                    // added to the UTXO set.
                    continue;
                }
                if output.script_pubkey.first().copied() == Some(LTC_HEADER_BATCH_TAG) {
                    // Phase B: LtcHeaderBatch apply path. Structural validity
                    // already enforced by validate_output. Now thread the batch
                    // into LTC relay state, parallel to the BTC arm above.
                    if !self.ltc_spv_relay_active_at(height) {
                        return Err(
                            "LtcHeaderBatch output before SPV relay activation".to_string(),
                        );
                    }
                    ltc_batch_count += 1;
                    if ltc_batch_count > 1 {
                        return Err("block contains more than one LtcHeaderBatch output".to_string());
                    }
                    let headers = parse_ltc_header_batch(&output.script_pubkey)
                        .map_err(|e| format!("LtcHeaderBatch apply parse failed: {}", e))?;
                    let anchor = self.ltc_anchor();
                    let retarget = self.ltc_retarget_params();
                    let update = apply_ltc_header_batch(
                        headers,
                        block.header.time,
                        &mut self.ltc_headers,
                        &mut self.ltc_heights,
                        &mut self.ltc_tip,
                        &mut self.ltc_tip_height,
                        &anchor,
                        &retarget,
                    )?;
                    ltc_relay_update = Some(update);
                    continue;
                }
                created.push((op, output, false));
            }
        }

        let mut coinbase_total: u64 = 0;
        // v1.9.62 issue #60: coinbase batch acceptance — when the
        // coinbase_header_batch activation height has been crossed, BTC/
        // LTC header-batch scripts are accepted as zero-value
        // coinbase outputs and applied via apply_*_header_batch, instead
        // of unconditionally rejected. The one-per-chain-per-block cap
        // still applies; a block cannot carry both a coinbase batch and
        // a regular-tx batch for the same chain.
        let coinbase_batch_active = self.coinbase_header_batch_active_at(height);
        let coinbase_carrier_soft_apply_error = |e: &str| {
            e.contains("first header does not connect to known chain")
                || e.contains("already known in chain state")
        };
        let mut coinbase_btc_batch_count = 0u32;
        let mut coinbase_ltc_batch_count = 0u32;
        for output in &coinbase.outputs {
            let tag = output.script_pubkey.first().copied();
            if tag == Some(BTC_HEADER_BATCH_TAG) {
                if !coinbase_batch_active {
                    return Err("BtcHeaderBatch output not allowed in coinbase".to_string());
                }
                if !self.btc_spv_relay_active_at(height) {
                    return Err(
                        "coinbase BtcHeaderBatch before SPV relay activation".to_string(),
                    );
                }
                if output.value != 0 {
                    return Err("coinbase BtcHeaderBatch output must have value=0".to_string());
                }
                coinbase_btc_batch_count += 1;
                if coinbase_btc_batch_count > 1 {
                    return Err(
                        "coinbase contains more than one BtcHeaderBatch output".to_string(),
                    );
                }
                if btc_relay_update.is_some() {
                    return Err(
                        "block contains both coinbase and regular-tx BtcHeaderBatch".to_string(),
                    );
                }
                let headers = parse_btc_header_batch(&output.script_pubkey)
                    .map_err(|e| format!("coinbase BtcHeaderBatch parse failed: {}", e))?;
                let anchor = self.btc_anchor();
                match apply_btc_header_batch(
                    headers,
                    block.header.time,
                    &mut self.btc_headers,
                    &mut self.btc_heights,
                    &mut self.btc_tip,
                    &mut self.btc_tip_height,
                    &anchor,
                ) {
                    Ok(update) => btc_relay_update = Some(update),
                    Err(e) if coinbase_carrier_soft_apply_error(&e) => {}
                    Err(e) => return Err(e),
                }
                continue;
            }
            if tag == Some(LTC_HEADER_BATCH_TAG) {
                if !coinbase_batch_active {
                    return Err("LtcHeaderBatch output not allowed in coinbase".to_string());
                }
                if !self.ltc_spv_relay_active_at(height) {
                    return Err(
                        "coinbase LtcHeaderBatch before SPV relay activation".to_string(),
                    );
                }
                if output.value != 0 {
                    return Err("coinbase LtcHeaderBatch output must have value=0".to_string());
                }
                coinbase_ltc_batch_count += 1;
                if coinbase_ltc_batch_count > 1 {
                    return Err(
                        "coinbase contains more than one LtcHeaderBatch output".to_string(),
                    );
                }
                if ltc_relay_update.is_some() {
                    return Err(
                        "block contains both coinbase and regular-tx LtcHeaderBatch".to_string(),
                    );
                }
                let headers = parse_ltc_header_batch(&output.script_pubkey)
                    .map_err(|e| format!("coinbase LtcHeaderBatch parse failed: {}", e))?;
                let anchor = self.ltc_anchor();
                let retarget = self.ltc_retarget_params();
                match apply_ltc_header_batch(
                    headers,
                    block.header.time,
                    &mut self.ltc_headers,
                    &mut self.ltc_heights,
                    &mut self.ltc_tip,
                    &mut self.ltc_tip_height,
                    &anchor,
                    &retarget,
                ) {
                    Ok(update) => ltc_relay_update = Some(update),
                    Err(e) if coinbase_carrier_soft_apply_error(&e) => {}
                    Err(e) => return Err(e),
                }
                continue;
            }
            // Legacy DOGE header batch carrier (tag 0xc9) was removed from
            // active relay in v1.9.94, but blocks mined before that deployment
            // may contain these outputs and must remain valid for chain replay.
            // Block 26,757 is the only known instance on the canonical chain.
            const DOGE_CARRIER_LEGACY_CUTOFF: u64 = 27_880;
            if output.script_pubkey.first().copied() == Some(0xc9)
                && height < DOGE_CARRIER_LEGACY_CUTOFF
            {
                continue;
            }
            validate_output(
                output,
                self.htlcv1_active_at(height),
                self.mpsov1_active_at(height),
                self.btc_spv_relay_active_at(height),
                self.ltc_spv_relay_active_at(height),
                self.htlc_btc_swap_v1_active_at(height),
                self.htlc_ltc_swap_v1_active_at(height),
                self.swap_order_v1_active_at(height),
                self.ltc_swap_order_v1_active_at(height),
                height,
            )?;
            coinbase_total = coinbase_total
                .checked_add(output.value)
                .ok_or_else(|| "Coinbase outputs overflow".to_string())?;
            if coinbase_total > MAX_MONEY {
                return Err("Coinbase outputs overflow".to_string());
            }
        }
        if enforce_reward && coinbase_total > block_reward_value + (fees as u64) {
            return Err("Coinbase transaction exceeds allowed reward".to_string());
        }

        let coinbase_txid = coinbase.txid();
        for (index, output) in coinbase.outputs.iter().cloned().enumerate() {
            let op = OutPoint {
                txid: coinbase_txid,
                index: index as u32,
            };
            created.push((op, output, true));
        }

        let available_fees = std::cmp::min(fees, coinbase_total as i64);
        let mut subsidy_created = coinbase_total.saturating_sub(available_fees as u64);
        if enforce_reward {
            subsidy_created = std::cmp::min(block_reward_value, subsidy_created);
        }
        if let Some(max_subsidy) = max_subsidy {
            if subsidy_created > max_subsidy {
                return Err("Coinbase subsidy would exceed permitted supply".to_string());
            }
        }

        let mut spent_for_undo: Vec<(OutPoint, UtxoEntry)> = Vec::new();
        for key in &seen_inputs {
            if let Some(entry) = self.utxos.get(key) {
                spent_for_undo.push((key.clone(), entry.clone()));
            }
        }

        for key in &seen_inputs {
            self.utxos.remove(key);
        }
        let mut created_outpoints: Vec<OutPoint> = Vec::new();
        for (op, output, is_coinbase) in created {
            created_outpoints.push(op.clone());
            self.utxos.insert(
                op,
                UtxoEntry {
                    output,
                    height,
                    is_coinbase,
                },
            );
        }

        for consumed in &btc_outpoints_consumed {
            self.claimed_btc_outpoints.insert(*consumed);
        }
        for consumed in &ltc_outpoints_consumed {
            self.claimed_ltc_outpoints.insert(*consumed);
        }

        let undo = BlockUndo {
            spent: spent_for_undo,
            created: created_outpoints,
            subsidy_created,
            btc_relay_update,
            ltc_relay_update,
            claimed_btc_outpoints_added: btc_outpoints_consumed,
            claimed_ltc_outpoints_added: ltc_outpoints_consumed,
        };

        Ok((fees as u64, coinbase_total, subsidy_created, undo))
    }

    /// Validate a single transaction against the current UTXO set,
    /// using similar rules as block validation but without mutating state.
    #[allow(dead_code)]
    pub fn validate_transaction(&self, tx: &Transaction) -> Result<(), String> {
        if tx.inputs.is_empty() {
            return Err("Transaction must have at least one input".to_string());
        }
        if tx.outputs.is_empty() {
            return Err("Transaction must have at least one output".to_string());
        }

        let mut seen_inputs: HashSet<OutPoint> = HashSet::new();
        let mut fees: i64 = 0;
        let mut btc_consumed: Vec<([u8; 32], u32)> = Vec::new();
        let mut ltc_consumed: Vec<([u8; 32], u32)> = Vec::new();
        self.validate_transaction_internal(
            tx,
            self.height,
            &mut seen_inputs,
            &mut fees,
            &mut btc_consumed,
            &mut ltc_consumed,
        )
    }

    /// Calculate transaction fees against the current UTXO set without mutating state.
    pub fn calculate_fees(&self, tx: &Transaction) -> Result<u64, String> {
        let mut seen_inputs: HashSet<OutPoint> = HashSet::new();
        let mut fees: i64 = 0;
        let mut btc_consumed: Vec<([u8; 32], u32)> = Vec::new();
        let mut ltc_consumed: Vec<([u8; 32], u32)> = Vec::new();
        self.validate_transaction_internal(
            tx,
            self.height,
            &mut seen_inputs,
            &mut fees,
            &mut btc_consumed,
            &mut ltc_consumed,
        )?;
        Ok(fees as u64)
    }

    /// Hash of the current main chain tip.
    pub fn tip_hash(&self) -> [u8; 32] {
        let tip_height = self.height.saturating_sub(1);
        self.chain
            .last()
            .map(|b| b.header.hash_for_height(tip_height))
            .unwrap_or([0u8; 32])
    }

    fn is_connected_chain_hash(&self, hash: &[u8; 32]) -> bool {
        let Some(height) = self.heights.get(hash).copied() else {
            return false;
        };
        let Some(block) = self.chain.get(height as usize) else {
            return false;
        };
        block.header.hash_for_height(height) == *hash
    }

    /// Path of header hashes from the nearest known block up to the provided header tip.
    pub fn header_path_to_known(&self, tip: [u8; 32]) -> Option<Vec<[u8; 32]>> {
        let mut path = Vec::new();
        let mut current = tip;
        loop {
            if self.is_connected_chain_hash(&current) {
                path.reverse();
                return Some(path);
            }
            let hw = self.headers.get(&current)?;
            path.push(current);
            if hw.header.prev_hash == [0u8; 32] {
                return None;
            }
            current = hw.header.prev_hash;
        }
    }

    fn gather_branch_to_genesis(&self, tip: [u8; 32]) -> Result<Vec<Block>, String> {
        let mut path = Vec::new();
        let mut current = tip;
        loop {
            let block = self
                .block_by_hash(&current)
                .ok_or_else(|| "missing block in store".to_string())?;
            let prev_hash = block.header.prev_hash;
            path.push(block);
            if prev_hash == [0u8; 32] {
                break;
            }
            current = prev_hash;
        }
        path.reverse();
        Ok(path)
    }

    fn rebuild_to_tip(&self, tip_hash: [u8; 32]) -> Result<ChainState, String> {
        let mut new_state = ChainState {
            params: self.params.clone(),
            height: 0,
            chain: Vec::new(),
            total_work: BigUint::zero(),
            utxos: HashMap::new(),
            issued: 0,
            headers: self.headers.clone(),
            header_chain: Vec::new(),
            orphan_pool: self.orphan_pool.clone(),
            block_store: self.block_store.clone(),
            heights: self.heights.clone(),
            cumulative_work: self.cumulative_work.clone(),
            anchors: self.anchors.clone(),
            best_tip: self.best_tip,
            undo_logs: self.undo_logs.clone(),
            btc_headers: self.btc_headers.clone(),
            btc_heights: self.btc_heights.clone(),
            btc_tip: self.btc_tip,
            btc_tip_height: self.btc_tip_height,
            claimed_btc_outpoints: self.claimed_btc_outpoints.clone(),
            ltc_headers: self.ltc_headers.clone(),
            ltc_heights: self.ltc_heights.clone(),
            ltc_tip: self.ltc_tip,
            ltc_tip_height: self.ltc_tip_height,
            claimed_ltc_outpoints: self.claimed_ltc_outpoints.clone(),
        };

        let branch = self.gather_branch_to_genesis(tip_hash)?;
        if branch.is_empty() {
            return Err("empty branch".to_string());
        }
        let genesis = &branch[0];
        new_state.connect_genesis(genesis.clone())?;
        let mut cumulative = ChainState::block_work(genesis);
        let genesis_hash = genesis.header.hash_for_height(0);
        new_state
            .block_store
            .insert(genesis_hash, genesis.clone());
        new_state.heights.insert(genesis_hash, 0);
        new_state
            .cumulative_work
            .insert(genesis_hash, cumulative.clone());

        for (idx, block) in branch.iter().enumerate().skip(1) {
            if let Err(e) = new_state.connect_block(block.clone()) {
                return Err(format!("failed applying block {}: {}", idx, e));
            }
            cumulative += ChainState::block_work(block);
            let h = block.header.hash_for_height(idx as u64);
            new_state.block_store.insert(h, block.clone());
            new_state.heights.insert(h, idx as u64);
            new_state.cumulative_work.insert(h, cumulative.clone());
        }

        Ok(new_state)
    }

    /// Store a block and update best chain incrementally.
    pub fn process_block(&mut self, block: Block) -> Result<(u64, [u8; 32]), String> {
        // Resolve parent + height before hashing: the post-30000 hash byte
        // order depends on the block's height, so we cannot compute the hash
        // (and use it as a map key) until we know which height to bind to.
        let parent_hash = block.header.prev_hash;
        if parent_hash != [0u8; 32] && !self.block_store.contains_key(&parent_hash) {
            self.orphan_pool.entry(parent_hash).or_default().push(block);
            self.prune_orphan_pool();
            return Err("block stored as orphan (prev hash unknown)".to_string());
        }

        let block_height = if parent_hash == [0u8; 32] {
            0
        } else {
            self.heights.get(&parent_hash).copied().unwrap_or(0) + 1
        };

        let hash = block.header.hash_for_height(block_height);
        if self.block_store.contains_key(&hash) {
            return Err("duplicate block".to_string());
        }

        let auxpow_active = self.params.auxpow_activation_height
            .map(|ah| block_height >= ah)
            .unwrap_or(false);
        if block.header.version & crate::auxpow::AUXPOW_VERSION_BIT != 0 && auxpow_active {
            let header_bytes = block.header.serialize_for_height(block_height);
            let ap = block.auxpow.as_ref()
                .ok_or_else(|| "AuxPoW block is missing AuxPoW data".to_string())?;
            crate::auxpow::validate(ap, &header_bytes, block.header.target())?;
        } else if !meets_target(&hash, block.header.target())
            && !whatsminer_compat_pow_hash_for_height(&block.header, block_height)
                .as_ref()
                .map(|h| meets_target(h, block.header.target()))
                .unwrap_or(false)
        {
            return Err("block does not satisfy proof-of-work target".to_string());
        }

        let parent_height = if parent_hash == [0u8; 32] {
            0
        } else {
            *self.heights.get(&parent_hash).unwrap_or(&0)
        };
        let parent_work = if parent_hash == [0u8; 32] {
            BigUint::zero()
        } else {
            self.cumulative_work
                .get(&parent_hash)
                .cloned()
                .unwrap_or_else(BigUint::zero)
        };
        let cumulative = parent_work + ChainState::block_work(&block);
        let height = parent_height + 1;

        if let Some(a) = &self.anchors {
            let hhex = hex::encode(hash);
            if !a.verify_block_against_anchors(height, &hhex) {
                return Err("block violates anchor checkpoint".to_string());
            }
        }

        self.block_store.insert(hash, block.clone());
        self.heights.insert(hash, height);
        self.cumulative_work.insert(hash, cumulative.clone());

        let mut advanced_tip = false;
        if parent_hash == self.tip_hash() {
            if let Err(e) = self.connect_block(block.clone()) {
                self.block_store.remove(&hash);
                self.heights.remove(&hash);
                self.cumulative_work.remove(&hash);
                return Err(e);
            }
            advanced_tip = true;
        } else if cumulative > self.total_work {
            if let Err(e) = self.reorg_to_tip(hash) {
                self.block_store.remove(&hash);
                self.heights.remove(&hash);
                self.cumulative_work.remove(&hash);
                return Err(e);
            }
            advanced_tip = true;
        }

        let mut new_hash = self.tip_hash();
        while let Some(children) = self.orphan_pool.remove(&new_hash) {
            for child in children {
                if let Ok((_h, c_hash)) = self.process_block(child) {
                    new_hash = c_hash;
                }
            }
        }
        self.prune_caches();

        if !advanced_tip && self.tip_hash() != hash {
            return Err("block stored on side chain".to_string());
        }

        Ok((self.height, self.tip_hash()))
    }

    fn validate_transaction_internal(
        &self,
        tx: &Transaction,
        height: u64,
        seen_inputs: &mut HashSet<OutPoint>,
        fees: &mut i64,
        btc_outpoints_consumed: &mut Vec<([u8; 32], u32)>,
        ltc_outpoints_consumed: &mut Vec<([u8; 32], u32)>,
    ) -> Result<(), String> {
        let view = self.build_consensus_view();
        let mut input_total: i64 = 0;
        for (input_index, txin) in tx.inputs.iter().enumerate() {
            if txin.prev_txid.len() != 32 {
                return Err("Transaction input has invalid txid length".to_string());
            }
            let key = OutPoint {
                txid: txin.prev_txid,
                index: txin.prev_index,
            };
            if seen_inputs.contains(&key) {
                return Err("Transaction input double spent within block".to_string());
            }
            let utxo_entry = self
                .utxos
                .get(&key)
                .ok_or_else(|| "Referenced UTXO is missing".to_string())?;

            if utxo_entry.is_coinbase {
                let confirmations = height.saturating_sub(utxo_entry.height);
                if confirmations < coinbase_maturity() {
                    return Err("Coinbase UTXO not mature".to_string());
                }
            }

            if !verify_transaction_signature(
                tx,
                input_index,
                txin,
                &utxo_entry.output,
                height,
                self.htlcv1_active_at(height),
                self.mpsov1_active_at(height),
                self.htlc_btc_swap_v1_active_at(height),
                self.btc_swap_bech32_payment_active_at(height),
                self.htlc_ltc_swap_v1_active_at(height),
                self.swap_order_v1_active_at(height),
                self.ltc_swap_order_v1_active_at(height),
                &view,
                btc_outpoints_consumed,
                ltc_outpoints_consumed,
            ) {
                return Err("Transaction signature verification failed".to_string());
            }

            seen_inputs.insert(key);
            input_total += utxo_entry.output.value as i64;
        }

        let mut output_total: i64 = 0;
        for output in &tx.outputs {
            validate_output(
                output,
                self.htlcv1_active_at(height),
                self.mpsov1_active_at(height),
                self.btc_spv_relay_active_at(height),
                self.ltc_spv_relay_active_at(height),
                self.htlc_btc_swap_v1_active_at(height),
                self.htlc_ltc_swap_v1_active_at(height),
                self.swap_order_v1_active_at(height),
                self.ltc_swap_order_v1_active_at(height),
                height,
            )?;
            output_total += output.value as i64;
        }
        if input_total < output_total {
            return Err("Transaction spends more than available inputs".to_string());
        }
        *fees += input_total - output_total;
        if *fees < 0 || *fees as u64 > MAX_MONEY {
            return Err("Fee accounting overflow".to_string());
        }

        Ok(())
    }
}

fn is_coinbase(tx: &Transaction) -> bool {
    if tx.inputs.len() != 1 {
        return false;
    }
    let coinbase_input = &tx.inputs[0];
    coinbase_input.prev_txid == [0u8; 32] && coinbase_input.prev_index == 0xffff_ffff
}

fn validate_output(
    output: &TxOutput,
    htlcv1_active: bool,
    mpsov1_active: bool,
    btc_spv_relay_active: bool,
    ltc_spv_relay_active: bool,
    htlc_btc_swap_v1_active: bool,
    htlc_ltc_swap_v1_active: bool,
    swap_order_v1_active: bool,
    ltc_swap_order_v1_active: bool,
    height: u64,
) -> Result<(), String> {
    if output.value > MAX_MONEY {
        return Err("Output value out of range".to_string());
    }

    let tag = output.script_pubkey.first().copied();

    // MPSOv1 has its own size cap (640 bytes); checked before the 255-byte legacy limit.
    if tag == Some(MPSO_V1_TAG) {
        if !mpsov1_active {
            return Err("MPSOv1 output before activation".to_string());
        }
        if output.script_pubkey.len() > 640 {
            return Err("MPSOv1 script_pubkey too large".to_string());
        }
        let mpso = parse_mpso_script(&output.script_pubkey)
            .ok_or_else(|| "Malformed MPSOv1 output".to_string())?;
        validate_mpso_pubkeys_on_curve(&mpso)?;
        if mpso.timeout_height <= height {
            return Err("MPSOv1 timeout_height must be greater than current height".to_string());
        }
        return Ok(());
    }

    // BTC SPV header batch output: exempt from the 255-byte cap (can be up
    // to 161_284 bytes for a full 2016-header batch), must carry zero value.
    if tag == Some(BTC_HEADER_BATCH_TAG) {
        if !btc_spv_relay_active {
            return Err("BtcHeaderBatch output before SPV relay activation".to_string());
        }
        if output.value != 0 {
            return Err("BtcHeaderBatch output must have value 0".to_string());
        }
        if output.script_pubkey.len() > MAX_BTC_HEADER_BATCH_BYTES {
            return Err("BtcHeaderBatch script_pubkey too large".to_string());
        }
        parse_btc_header_batch(&output.script_pubkey)
            .map_err(|e| format!("Malformed BtcHeaderBatch: {}", e))?;
        return Ok(());
    }

    // LTC SPV header batch output (Phase B): exempt from the 255-byte cap
    // (can be up to ~11.5 KB for a full 144-header batch), must carry zero
    // value. Mirrors the BTC SPV gate exactly.
    if tag == Some(LTC_HEADER_BATCH_TAG) {
        if !ltc_spv_relay_active {
            return Err("LtcHeaderBatch output before SPV relay activation".to_string());
        }
        if output.value != 0 {
            return Err("LtcHeaderBatch output must have value 0".to_string());
        }
        if output.script_pubkey.len() > MAX_LTC_HEADER_BATCH_BYTES {
            return Err("LtcHeaderBatch script_pubkey too large".to_string());
        }
        parse_ltc_header_batch(&output.script_pubkey)
            .map_err(|e| format!("Malformed LtcHeaderBatch: {}", e))?;
        return Ok(());
    }

    // All non-MPSOv1, non-{Btc,Ltc}HeaderBatch outputs keep the existing 255-byte limit.
    if output.script_pubkey.len() > 0xff {
        return Err("script_pubkey too large".to_string());
    }

    if tag == Some(HTLC_V1_SCRIPT_TAG) {
        if !htlcv1_active {
            return Err("HTLCv1 output before activation".to_string());
        }
        if parse_htlcv1_script(&output.script_pubkey).is_none() {
            return Err("Malformed HTLCv1 output".to_string());
        }
    }

    if tag == Some(HTLC_BTC_SWAP_V1_TAG) {
        if !htlc_btc_swap_v1_active {
            return Err("HtlcBtcSwapV1 output before activation".to_string());
        }
        if output.script_pubkey.len() != HTLC_BTC_SWAP_V1_SCRIPT_LEN {
            return Err("HtlcBtcSwapV1 script wrong size".to_string());
        }
        let swap = parse_htlc_btc_swap_v1_script(&output.script_pubkey)
            .ok_or_else(|| "Malformed HtlcBtcSwapV1 output".to_string())?;
        if swap.confirmations_required < MIN_HTLC_BTC_SWAP_CONFIRMATIONS
            || swap.confirmations_required > MAX_HTLC_BTC_SWAP_CONFIRMATIONS
        {
            return Err(
                "HtlcBtcSwapV1 confirmations_required out of allowed range".to_string()
            );
        }
        if swap.timeout_height <= height {
            return Err("HtlcBtcSwapV1 timeout_height must exceed current height".to_string());
        }
    }

    if tag == Some(HTLC_LTC_SWAP_V1_TAG) {
        if !htlc_ltc_swap_v1_active {
            return Err("HtlcLtcSwapV1 output before activation".to_string());
        }
        if output.script_pubkey.len() != HTLC_LTC_SWAP_V1_SCRIPT_LEN {
            return Err("HtlcLtcSwapV1 script wrong size".to_string());
        }
        let swap = parse_htlc_ltc_swap_v1_script(&output.script_pubkey)
            .ok_or_else(|| "Malformed HtlcLtcSwapV1 output".to_string())?;
        if swap.confirmations_required < MIN_HTLC_LTC_SWAP_CONFIRMATIONS
            || swap.confirmations_required > MAX_HTLC_LTC_SWAP_CONFIRMATIONS
        {
            return Err(
                "HtlcLtcSwapV1 confirmations_required out of allowed range".to_string()
            );
        }
        if swap.timeout_height <= height {
            return Err("HtlcLtcSwapV1 timeout_height must exceed current height".to_string());
        }
    }
    if tag == Some(SWAP_ORDER_V1_TAG) {
        if !swap_order_v1_active {
            return Err("SwapOrder output before activation".to_string());
        }
        if output.script_pubkey.len() != SWAP_ORDER_SELL_SCRIPT_LEN
            && output.script_pubkey.len() != SWAP_ORDER_BUY_SCRIPT_LEN
        {
            return Err("SwapOrder script wrong size".to_string());
        }
        let order = parse_swap_order_script(&output.script_pubkey)
            .ok_or_else(|| "Malformed SwapOrder output".to_string())?;
        if order.expiry_height <= height {
            return Err("SwapOrder expiry_height must exceed current height".to_string());
        }
        if output.value < SWAP_ORDER_MIN_LOCKED_VALUE {
            return Err("SwapOrder locked value below minimum".to_string());
        }
        if order.direction == SWAP_ORDER_DIRECTION_SELL {
            if output.value != order.irm_amount {
                return Err(
                    "Sell-IRM SwapOrder output value must equal irm_amount".to_string(),
                );
            }
            if order.confirmations_required < MIN_HTLC_BTC_SWAP_CONFIRMATIONS
                || order.confirmations_required > MAX_HTLC_BTC_SWAP_CONFIRMATIONS
            {
                return Err(
                    "SwapOrder confirmations_required out of range".to_string()
                );
            }
        }
    }

    if tag == Some(LTC_SWAP_ORDER_V1_TAG) {
        if !ltc_swap_order_v1_active {
            return Err("LtcSwapOrder output before activation".to_string());
        }
        if output.script_pubkey.len() != LTC_SWAP_ORDER_SELL_SCRIPT_LEN
            && output.script_pubkey.len() != LTC_SWAP_ORDER_BUY_SCRIPT_LEN
        {
            return Err("LtcSwapOrder script wrong size".to_string());
        }
        let order = parse_ltc_swap_order_script(&output.script_pubkey)
            .ok_or_else(|| "Malformed LtcSwapOrder output".to_string())?;
        if order.expiry_height <= height {
            return Err("LtcSwapOrder expiry_height must exceed current height".to_string());
        }
        if output.value < LTC_SWAP_ORDER_MIN_LOCKED_VALUE {
            return Err("LtcSwapOrder locked value below minimum".to_string());
        }
        if order.direction == LTC_SWAP_ORDER_DIRECTION_SELL {
            if output.value != order.irm_amount {
                return Err(
                    "Sell-IRM LtcSwapOrder output value must equal irm_amount".to_string(),
                );
            }
            if order.confirmations_required < MIN_HTLC_LTC_SWAP_CONFIRMATIONS
                || order.confirmations_required > MAX_HTLC_LTC_SWAP_CONFIRMATIONS
            {
                return Err(
                    "LtcSwapOrder confirmations_required out of range".to_string()
                );
            }
        }
    }
    Ok(())
}

fn validate_mpso_pubkeys_on_curve(mpso: &MpsoV1Output) -> Result<(), String> {
    use k256::ecdsa::VerifyingKey;
    for pk in mpso.claim_pubkeys.iter().chain(mpso.refund_pubkeys.iter()) {
        VerifyingKey::from_sec1_bytes(pk.as_ref())
            .map_err(|_| "MPSOv1 output contains invalid secp256k1 pubkey".to_string())?;
    }
    Ok(())
}

fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let rip = Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&rip);
    out
}

fn signature_digest(tx: &Transaction, input_index: usize, script_pubkey: &[u8]) -> [u8; 32] {
    let mut tx_copy = tx.clone();
    for (idx, input) in tx_copy.inputs.iter_mut().enumerate() {
        if idx == input_index {
            input.script_sig = script_pubkey.to_vec();
        } else {
            input.script_sig.clear();
        }
    }
    let mut data = tx_copy.serialize();
    data.extend_from_slice(&1u32.to_le_bytes());
    sha256d(&data)
}

fn verify_sig_with_pubkey(
    tx: &Transaction,
    input_index: usize,
    script_pubkey: &[u8],
    sig: &[u8],
    pubkey: &[u8],
) -> bool {
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    use k256::ecdsa::{Signature, VerifyingKey};

    if sig.len() < 2 || sig.last() != Some(&0x01) {
        return false;
    }
    if !(pubkey.len() == 33 || pubkey.len() == 65) {
        return false;
    }
    if input_index >= tx.inputs.len() {
        return false;
    }

    let der = &sig[..sig.len() - 1];
    let signature = match Signature::from_der(der) {
        Ok(s) => s,
        Err(_) => return false,
    };
    if signature.normalize_s().is_some() {
        return false;
    }
    let vk = match VerifyingKey::from_sec1_bytes(pubkey) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let digest = signature_digest(tx, input_index, script_pubkey);
    vk.verify_prehash(&digest, &signature).is_ok()
}

fn verify_transaction_signature(
    tx: &Transaction,
    input_index: usize,
    txin: &TxInput,
    utxo: &TxOutput,
    spend_height: u64,
    htlcv1_active: bool,
    mpsov1_active: bool,
    htlc_btc_swap_v1_active: bool,
    btc_swap_bech32_payment_active: bool,
    htlc_ltc_swap_v1_active: bool,
    swap_order_v1_active: bool,
    ltc_swap_order_v1_active: bool,
    view: &ConsensusView<'_>,
    btc_outpoints_consumed: &mut Vec<([u8; 32], u32)>,
    ltc_outpoints_consumed: &mut Vec<([u8; 32], u32)>,
) -> bool {
    match parse_output_encumbrance(&utxo.script_pubkey) {
        OutputEncumbrance::P2pkh(expected_pkh) => {
            let witness = parse_input_witness(&txin.script_sig);
            let (sig, pubkey) = match witness {
                InputWitness::P2pkh { sig, pubkey } => (sig, pubkey),
                _ => return false,
            };
            if hash160(&pubkey) != expected_pkh {
                return false;
            }
            verify_sig_with_pubkey(tx, input_index, &utxo.script_pubkey, &sig, &pubkey)
        }
        OutputEncumbrance::HtlcV1(htlc) => {
            if !htlcv1_active {
                return false;
            }
            match parse_input_witness(&txin.script_sig) {
                InputWitness::HtlcClaim {
                    sig,
                    pubkey,
                    preimage,
                } => {
                    if preimage.is_empty() || preimage.len() > 64 {
                        return false;
                    }
                    let pre_hash = Sha256::digest(&preimage);
                    if pre_hash[..] != htlc.expected_hash {
                        return false;
                    }
                    if hash160(&pubkey) != htlc.recipient_pkh {
                        return false;
                    }
                    let script = encode_htlcv1_script(&htlc);
                    verify_sig_with_pubkey(tx, input_index, &script, &sig, &pubkey)
                }
                InputWitness::HtlcRefund { sig, pubkey } => {
                    if spend_height < htlc.timeout_height {
                        return false;
                    }
                    if hash160(&pubkey) != htlc.refund_pkh {
                        return false;
                    }
                    let script = encode_htlcv1_script(&htlc);
                    verify_sig_with_pubkey(tx, input_index, &script, &sig, &pubkey)
                }
                _ => false,
            }
        }
        OutputEncumbrance::MpsoV1(ref mpso) => {
            if !mpsov1_active {
                return false;
            }
            let script_sig = &txin.script_sig;
            if script_sig.len() > MPSO_V1_MAX_WITNESS_SIZE {
                return false;
            }
            if script_sig.is_empty() {
                return false;
            }
            let scriptcode = encode_mpso_script(mpso);
            match script_sig[0] {
                0x01 => {
                    // Claim path: valid only when spend_height < timeout_height.
                    if spend_height >= mpso.timeout_height {
                        return false;
                    }
                    if script_sig.len() < 2 {
                        return false;
                    }
                    let bitmap = script_sig[1];
                    let valid_mask: u8 = if mpso.claim_n == 8 {
                        0xff
                    } else {
                        (1u8 << mpso.claim_n) - 1
                    };
                    if bitmap & !valid_mask != 0 {
                        return false;
                    }
                    if bitmap.count_ones() != mpso.claim_m as u32 {
                        return false;
                    }
                    let mut pos = 2usize;
                    for i in 0..mpso.claim_n {
                        if bitmap & (1u8 << i) == 0 {
                            continue;
                        }
                        if pos >= script_sig.len() {
                            return false;
                        }
                        let sig_len = script_sig[pos] as usize;
                        pos += 1;
                        if sig_len == 0 || pos + sig_len > script_sig.len() {
                            return false;
                        }
                        let sig = &script_sig[pos..pos + sig_len];
                        pos += sig_len;
                        if !verify_sig_with_pubkey(
                            tx,
                            input_index,
                            &scriptcode,
                            sig,
                            &mpso.claim_pubkeys[i as usize],
                        ) {
                            return false;
                        }
                    }
                    if mpso.flags & 0x01 != 0 {
                        if pos >= script_sig.len() {
                            return false;
                        }
                        let pre_len = script_sig[pos] as usize;
                        pos += 1;
                        if pre_len == 0 || pre_len > 64 {
                            return false;
                        }
                        if pos + pre_len > script_sig.len() {
                            return false;
                        }
                        let preimage = &script_sig[pos..pos + pre_len];
                        pos += pre_len;
                        let hash = Sha256::digest(preimage);
                        let expected = mpso
                            .optional_hash
                            .expect("flags bit 0 set implies optional_hash");
                        if hash[..] != expected {
                            return false;
                        }
                    }
                    pos == script_sig.len()
                }
                0x02 => {
                    // Refund path: valid only when spend_height >= timeout_height.
                    if spend_height < mpso.timeout_height {
                        return false;
                    }
                    if script_sig.len() < 2 {
                        return false;
                    }
                    let bitmap = script_sig[1];
                    let valid_mask: u8 = if mpso.refund_n == 8 {
                        0xff
                    } else {
                        (1u8 << mpso.refund_n) - 1
                    };
                    if bitmap & !valid_mask != 0 {
                        return false;
                    }
                    if bitmap.count_ones() != mpso.refund_m as u32 {
                        return false;
                    }
                    let mut pos = 2usize;
                    for i in 0..mpso.refund_n {
                        if bitmap & (1u8 << i) == 0 {
                            continue;
                        }
                        if pos >= script_sig.len() {
                            return false;
                        }
                        let sig_len = script_sig[pos] as usize;
                        pos += 1;
                        if sig_len == 0 || pos + sig_len > script_sig.len() {
                            return false;
                        }
                        let sig = &script_sig[pos..pos + sig_len];
                        pos += sig_len;
                        if !verify_sig_with_pubkey(
                            tx,
                            input_index,
                            &scriptcode,
                            sig,
                            &mpso.refund_pubkeys[i as usize],
                        ) {
                            return false;
                        }
                    }
                    pos == script_sig.len()
                }
                _ => false,
            }
        }
        OutputEncumbrance::HtlcBtcSwapV1(swap) => {
            if !htlc_btc_swap_v1_active {
                return false;
            }
            let witness = match parse_htlc_btc_swap_witness(&txin.script_sig) {
                Some(w) => w,
                None => return false,
            };
            match witness {
                HtlcBtcSwapWitness::Claim {
                    sig,
                    pubkey,
                    btc_block_hash,
                    btc_merkle_branch,
                    btc_merkle_index,
                    btc_tx_raw,
                } => {
                    let proof_height = match view.btc_heights.get(&btc_block_hash) {
                        Some(h) => *h,
                        None => return false,
                    };
                    let confs = view
                        .btc_tip_height
                        .saturating_add(1)
                        .saturating_sub(proof_height);
                    if confs < swap.confirmations_required as u64 {
                        return false;
                    }
                    let header_entry = match view.btc_headers.get(&btc_block_hash) {
                        Some(e) => e,
                        None => return false,
                    };
                    let btc_txid_val = match btc_txid(&btc_tx_raw) {
                        Ok(t) => t,
                        Err(_) => return false,
                    };
                    let computed_root = crate::auxpow::compute_merkle_root(
                        &btc_txid_val,
                        &btc_merkle_branch,
                        btc_merkle_index,
                    );
                    if computed_root != header_entry.header.merkle_root {
                        return false;
                    }
                    let outs = match parse_btc_tx_outputs(&btc_tx_raw) {
                        Ok(o) => o,
                        Err(_) => return false,
                    };
                    let mut expected_payload =
                        Vec::with_capacity(BTC_OP_RETURN_BINDING_LEN);
                    expected_payload.extend_from_slice(&BTC_OP_RETURN_BINDING_MAGIC);
                    expected_payload.extend_from_slice(&swap.funding_binding);
                    let mut pays = false;
                    let mut op_return_vout: Option<u32> = None;
                    for o in &outs {
                        match &o.script {
                            BtcOutputScript::P2pkh(pkh) => {
                                if *pkh == swap.btc_recipient_pkh
                                    && o.value >= swap.btc_amount_sats
                                {
                                    pays = true;
                                }
                            }
                            BtcOutputScript::P2wpkh(pkh) => {
                                // Native-SegWit P2WPKH payment. Both forms
                                // encode HASH160(pubkey), so the same
                                // `btc_recipient_pkh` comparison applies —
                                // only the on-chain script shape differs.
                                // Acceptance is gated by the bech32 payment
                                // relaxation; pre-activation this branch
                                // never sets `pays`, preserving the strict
                                // P2PKH-only rule.
                                if btc_swap_bech32_payment_active
                                    && *pkh == swap.btc_recipient_pkh
                                    && o.value >= swap.btc_amount_sats
                                {
                                    pays = true;
                                }
                            }
                            BtcOutputScript::OpReturn(data) => {
                                if data == &expected_payload {
                                    if op_return_vout.is_some() {
                                        return false;
                                    }
                                    op_return_vout = Some(o.vout);
                                }
                            }
                            BtcOutputScript::Other => {}
                        }
                    }
                    if !pays {
                        return false;
                    }
                    let vout = match op_return_vout {
                        Some(v) => v,
                        None => return false,
                    };
                    let consumed = (btc_txid_val, vout);
                    if view.claimed_btc_outpoints.contains(&consumed) {
                        return false;
                    }
                    if btc_outpoints_consumed.contains(&consumed) {
                        return false;
                    }
                    if hash160(&pubkey) != swap.recipient_pkh {
                        return false;
                    }
                    let scriptcode = encode_htlc_btc_swap_v1_script(&swap);
                    if !verify_sig_with_pubkey(
                        tx,
                        input_index,
                        &scriptcode,
                        &sig,
                        &pubkey,
                    ) {
                        return false;
                    }
                    btc_outpoints_consumed.push(consumed);
                    true
                }
                HtlcBtcSwapWitness::Refund { sig, pubkey } => {
                    if spend_height < swap.timeout_height {
                        return false;
                    }
                    if hash160(&pubkey) != swap.refund_pkh {
                        return false;
                    }
                    let scriptcode = encode_htlc_btc_swap_v1_script(&swap);
                    verify_sig_with_pubkey(tx, input_index, &scriptcode, &sig, &pubkey)
                }
            }
        }
        OutputEncumbrance::HtlcLtcSwapV1(swap) => {
            // Phase C: byte-level mirror of the HtlcBtcSwapV1 arm above,
            // reading LTC SPV state from `view.ltc_*` instead of BTC's
            // and threading `ltc_outpoints_consumed` for replay protection.
            // The Bitcoin tx parser (`btc_txid`, `parse_btc_tx_outputs`) is
            // reused as-is because LTC transactions are byte-identical to
            // BTC's; only the PoW algorithm differs and that was already
            // validated by the LTC SPV relay when the header was applied.
            if !htlc_ltc_swap_v1_active {
                return false;
            }
            let witness = match parse_htlc_ltc_swap_witness(&txin.script_sig) {
                Some(w) => w,
                None => return false,
            };
            match witness {
                HtlcLtcSwapWitness::Claim {
                    sig,
                    pubkey,
                    ltc_block_hash,
                    ltc_merkle_branch,
                    ltc_merkle_index,
                    ltc_tx_raw,
                } => {
                    let proof_height = match view.ltc_heights.get(&ltc_block_hash) {
                        Some(h) => *h,
                        None => return false,
                    };
                    let confs = view
                        .ltc_tip_height
                        .saturating_add(1)
                        .saturating_sub(proof_height);
                    if confs < swap.confirmations_required as u64 {
                        return false;
                    }
                    let header_entry = match view.ltc_headers.get(&ltc_block_hash) {
                        Some(e) => e,
                        None => return false,
                    };
                    let ltc_txid_val = match btc_txid(&ltc_tx_raw) {
                        Ok(t) => t,
                        Err(_) => return false,
                    };
                    let computed_root = crate::auxpow::compute_merkle_root(
                        &ltc_txid_val,
                        &ltc_merkle_branch,
                        ltc_merkle_index,
                    );
                    if computed_root != header_entry.header.merkle_root {
                        return false;
                    }
                    let outs = match parse_btc_tx_outputs(&ltc_tx_raw) {
                        Ok(o) => o,
                        Err(_) => return false,
                    };
                    let mut expected_payload =
                        Vec::with_capacity(LTC_OP_RETURN_BINDING_LEN);
                    expected_payload.extend_from_slice(&LTC_OP_RETURN_BINDING_MAGIC);
                    expected_payload.extend_from_slice(&swap.funding_binding);
                    let mut pays = false;
                    let mut op_return_vout: Option<u32> = None;
                    for o in &outs {
                        match &o.script {
                            BtcOutputScript::P2pkh(pkh) => {
                                if *pkh == swap.ltc_recipient_pkh
                                    && o.value >= swap.ltc_amount_sats
                                {
                                    pays = true;
                                }
                            }
                            BtcOutputScript::P2wpkh(pkh) => {
                                // LTC native-SegWit P2WPKH payment. No
                                // separate gate: the LTC swap claim path
                                // itself ships disabled today
                                // (`htlc_ltc_swap_v1_active` already
                                // returned at function entry), and its
                                // initial mainnet activation will land
                                // with bech32 acceptance on day one.
                                if *pkh == swap.ltc_recipient_pkh
                                    && o.value >= swap.ltc_amount_sats
                                {
                                    pays = true;
                                }
                            }
                            BtcOutputScript::OpReturn(data) => {
                                if data == &expected_payload {
                                    if op_return_vout.is_some() {
                                        return false;
                                    }
                                    op_return_vout = Some(o.vout);
                                }
                            }
                            BtcOutputScript::Other => {}
                        }
                    }
                    if !pays {
                        return false;
                    }
                    let vout = match op_return_vout {
                        Some(v) => v,
                        None => return false,
                    };
                    let consumed = (ltc_txid_val, vout);
                    if view.claimed_ltc_outpoints.contains(&consumed) {
                        return false;
                    }
                    if ltc_outpoints_consumed.contains(&consumed) {
                        return false;
                    }
                    if hash160(&pubkey) != swap.recipient_pkh {
                        return false;
                    }
                    let scriptcode = encode_htlc_ltc_swap_v1_script(&swap);
                    if !verify_sig_with_pubkey(
                        tx,
                        input_index,
                        &scriptcode,
                        &sig,
                        &pubkey,
                    ) {
                        return false;
                    }
                    ltc_outpoints_consumed.push(consumed);
                    true
                }
                HtlcLtcSwapWitness::Refund { sig, pubkey } => {
                    if spend_height < swap.timeout_height {
                        return false;
                    }
                    if hash160(&pubkey) != swap.refund_pkh {
                        return false;
                    }
                    let scriptcode = encode_htlc_ltc_swap_v1_script(&swap);
                    verify_sig_with_pubkey(tx, input_index, &scriptcode, &sig, &pubkey)
                }
            }
        }
        OutputEncumbrance::SwapOrder(order) => {
            if !swap_order_v1_active {
                return false;
            }
            let witness = match parse_swap_order_witness(&txin.script_sig, order.direction) {
                Some(w) => w,
                None => return false,
            };
            match witness {
                SwapOrderWitness::FillSell {
                    sig,
                    pubkey,
                    taker_iriumd_pkh,
                    timeout_height,
                } => {
                    if order.direction != SWAP_ORDER_DIRECTION_SELL {
                        return false;
                    }
                    if spend_height > order.expiry_height {
                        return false;
                    }
                    if timeout_height <= spend_height {
                        return false;
                    }
                    if tx.outputs.is_empty() {
                        return false;
                    }
                    // Derive funding_binding from the SPENT order outpoint
                    // (txin.prev_txid + txin.prev_index), not from the
                    // spending tx's own txid. The binding lives inside
                    // vout 0's script so deriving it from tx.txid() would
                    // be self-referential — every iteration of the wallet
                    // changes the tx hash and the expected binding with
                    // it, with no closed-form fixed point. Using the order
                    // outpoint breaks the loop: it's known before the
                    // spending tx is built and matches what the wallet
                    // (iriumd.rs fillswaporder) writes into the script.
                    let funding_binding =
                        compute_funding_binding(&txin.prev_txid, txin.prev_index);
                    let expected = HtlcBtcSwapV1Output {
                        confirmations_required: order.confirmations_required,
                        recipient_pkh: taker_iriumd_pkh,
                        refund_pkh: order.maker_iriumd_pkh,
                        btc_recipient_pkh: order.maker_btc_pkh,
                        btc_amount_sats: order.btc_amount_sats,
                        timeout_height,
                        funding_binding,
                    };
                    let expected_script = encode_htlc_btc_swap_v1_script(&expected);
                    if tx.outputs[0].script_pubkey != expected_script {
                        return false;
                    }
                    if tx.outputs[0].value != order.irm_amount {
                        return false;
                    }
                    let scriptcode = encode_swap_order_script(&order);
                    verify_sig_with_pubkey(tx, input_index, &scriptcode, &sig, &pubkey)
                }
                SwapOrderWitness::FillBuy {
                    sig,
                    pubkey,
                    irm_timeout_height,
                } => {
                    if order.direction != SWAP_ORDER_DIRECTION_BUY {
                        return false;
                    }
                    if spend_height > order.expiry_height {
                        return false;
                    }
                    if irm_timeout_height <= spend_height {
                        return false;
                    }
                    if tx.outputs.is_empty() {
                        return false;
                    }
                    let expected_hash = match order.expected_hash {
                        Some(h) => h,
                        None => return false,
                    };
                    let taker_refund_pkh = hash160(&pubkey);
                    let expected_htlc = HtlcV1Output {
                        expected_hash,
                        recipient_pkh: order.maker_iriumd_pkh,
                        refund_pkh: taker_refund_pkh,
                        timeout_height: irm_timeout_height,
                    };
                    let expected_script = encode_htlcv1_script(&expected_htlc);
                    if tx.outputs[0].script_pubkey != expected_script {
                        return false;
                    }
                    if tx.outputs[0].value != order.irm_amount {
                        return false;
                    }
                    let scriptcode = encode_swap_order_script(&order);
                    verify_sig_with_pubkey(tx, input_index, &scriptcode, &sig, &pubkey)
                }
                SwapOrderWitness::Cancel { sig, pubkey } => {
                    if spend_height >= order.expiry_height {
                        return false;
                    }
                    if hash160(&pubkey) != order.maker_iriumd_pkh {
                        return false;
                    }
                    let scriptcode = encode_swap_order_script(&order);
                    verify_sig_with_pubkey(tx, input_index, &scriptcode, &sig, &pubkey)
                }
                SwapOrderWitness::ExpireSweep => {
                    if spend_height < order.expiry_height {
                        return false;
                    }
                    if tx.outputs.is_empty() {
                        return false;
                    }
                    let expected_p2pkh = p2pkh_script(&order.maker_iriumd_pkh);
                    if tx.outputs[0].script_pubkey != expected_p2pkh {
                        return false;
                    }
                    let minimum_payout = utxo.value.saturating_sub(SWAP_ORDER_MAX_SWEEP_FEE);
                    if tx.outputs[0].value < minimum_payout {
                        return false;
                    }
                    true
                }
            }
        }
        OutputEncumbrance::LtcSwapOrder(order) => {
            // Phase D: byte-level mirror of the SwapOrder arm. Sell-fill
            // covenant builds an HtlcLtcSwapV1 (not BTC); buy-fill covenant
            // builds an HtlcV1 identical to the BTC SwapOrder buy-fill
            // (chain-agnostic preimage hashlock); cancel and expire-sweep
            // mirror BTC's behaviour exactly.
            if !ltc_swap_order_v1_active {
                return false;
            }
            let witness = match parse_ltc_swap_order_witness(&txin.script_sig, order.direction) {
                Some(w) => w,
                None => return false,
            };
            match witness {
                LtcSwapOrderWitness::FillSell {
                    sig,
                    pubkey,
                    taker_iriumd_pkh,
                    timeout_height,
                } => {
                    if order.direction != LTC_SWAP_ORDER_DIRECTION_SELL {
                        return false;
                    }
                    if spend_height > order.expiry_height {
                        return false;
                    }
                    if timeout_height <= spend_height {
                        return false;
                    }
                    if tx.outputs.is_empty() {
                        return false;
                    }
                    // Funding binding derived from the spent order outpoint,
                    // matching the BTC SwapOrder pattern — using tx.txid()
                    // would be self-referential.
                    let funding_binding =
                        compute_funding_binding(&txin.prev_txid, txin.prev_index);
                    let expected = HtlcLtcSwapV1Output {
                        confirmations_required: order.confirmations_required,
                        recipient_pkh: taker_iriumd_pkh,
                        refund_pkh: order.maker_iriumd_pkh,
                        ltc_recipient_pkh: order.maker_ltc_pkh,
                        ltc_amount_sats: order.ltc_amount_sats,
                        timeout_height,
                        funding_binding,
                    };
                    let expected_script = encode_htlc_ltc_swap_v1_script(&expected);
                    if tx.outputs[0].script_pubkey != expected_script {
                        return false;
                    }
                    if tx.outputs[0].value != order.irm_amount {
                        return false;
                    }
                    let scriptcode = encode_ltc_swap_order_script(&order);
                    verify_sig_with_pubkey(tx, input_index, &scriptcode, &sig, &pubkey)
                }
                LtcSwapOrderWitness::FillBuy {
                    sig,
                    pubkey,
                    irm_timeout_height,
                } => {
                    if order.direction != LTC_SWAP_ORDER_DIRECTION_BUY {
                        return false;
                    }
                    if spend_height > order.expiry_height {
                        return false;
                    }
                    if irm_timeout_height <= spend_height {
                        return false;
                    }
                    if tx.outputs.is_empty() {
                        return false;
                    }
                    let expected_hash = match order.expected_hash {
                        Some(h) => h,
                        None => return false,
                    };
                    let taker_refund_pkh = hash160(&pubkey);
                    let expected_htlc = HtlcV1Output {
                        expected_hash,
                        recipient_pkh: order.maker_iriumd_pkh,
                        refund_pkh: taker_refund_pkh,
                        timeout_height: irm_timeout_height,
                    };
                    let expected_script = encode_htlcv1_script(&expected_htlc);
                    if tx.outputs[0].script_pubkey != expected_script {
                        return false;
                    }
                    if tx.outputs[0].value != order.irm_amount {
                        return false;
                    }
                    let scriptcode = encode_ltc_swap_order_script(&order);
                    verify_sig_with_pubkey(tx, input_index, &scriptcode, &sig, &pubkey)
                }
                LtcSwapOrderWitness::Cancel { sig, pubkey } => {
                    if spend_height >= order.expiry_height {
                        return false;
                    }
                    if hash160(&pubkey) != order.maker_iriumd_pkh {
                        return false;
                    }
                    let scriptcode = encode_ltc_swap_order_script(&order);
                    verify_sig_with_pubkey(tx, input_index, &scriptcode, &sig, &pubkey)
                }
                LtcSwapOrderWitness::ExpireSweep => {
                    if spend_height < order.expiry_height {
                        return false;
                    }
                    if tx.outputs.is_empty() {
                        return false;
                    }
                    let expected_p2pkh = p2pkh_script(&order.maker_iriumd_pkh);
                    if tx.outputs[0].script_pubkey != expected_p2pkh {
                        return false;
                    }
                    let minimum_payout = utxo.value.saturating_sub(LTC_SWAP_ORDER_MAX_SWEEP_FEE);
                    if tx.outputs[0].value < minimum_payout {
                        return false;
                    }
                    true
                }
            }
        }
        OutputEncumbrance::Unknown => false,
    }
}

pub fn block_from_locked(gen: &LockedGenesis) -> Result<Block, String> {
    // Decode header fields
    let header = &gen.header;
    let prev_hash = hex::decode(&header.prev_hash)
        .map_err(|e| format!("invalid locked genesis prev_hash hex: {e}"))?;
    let merkle_root = hex::decode(&header.merkle_root)
        .map_err(|e| format!("invalid locked genesis merkle_root hex: {e}"))?;
    if prev_hash.len() != 32 {
        return Err(format!(
            "invalid locked genesis prev_hash length: expected 32 bytes, got {}",
            prev_hash.len()
        ));
    }
    if merkle_root.len() != 32 {
        return Err(format!(
            "invalid locked genesis merkle_root length: expected 32 bytes, got {}",
            merkle_root.len()
        ));
    }
    let mut prev = [0u8; 32];
    prev.copy_from_slice(&prev_hash);
    let mut merkle = [0u8; 32];
    merkle.copy_from_slice(&merkle_root);

    let bits = u32::from_str_radix(header.bits.trim_start_matches("0x"), 16)
        .or_else(|_| u32::from_str_radix(header.bits.as_str(), 16))
        .map_err(|e| format!("invalid locked genesis bits field '{}': {e}", header.bits))?;

    let block_header = BlockHeader {
        version: header.version,
        prev_hash: prev,
        merkle_root: merkle,
        time: header.time as u32,
        bits,
        nonce: header.nonce,
    };

    let mut txs: Vec<Transaction> = Vec::new();
    for tx_hex in &gen.transactions {
        let raw = decode_hex(tx_hex)
            .map_err(|e| format!("invalid locked genesis tx hex '{}': {e}", tx_hex))?;
        let tx = decode_compact_tx(&raw);
        txs.push(tx);
    }

    Ok(Block {
        header: block_header,
        transactions: txs,
        auxpow: None,
    })
}

/// Decode the compact transaction format used in `genesis-locked.json`.
pub fn decode_compact_tx(raw: &[u8]) -> Transaction {
    let mut offset = 0usize;

    let read_u8 = |buf: &[u8], off: &mut usize| -> u8 {
        let v = buf[*off];
        *off += 1;
        v
    };
    let read_u32 = |buf: &[u8], off: &mut usize| -> u32 {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&buf[*off..*off + 4]);
        *off += 4;
        u32::from_le_bytes(bytes)
    };
    let read_u64 = |buf: &[u8], off: &mut usize| -> u64 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&buf[*off..*off + 8]);
        *off += 8;
        u64::from_le_bytes(bytes)
    };
    let read_bytes = |buf: &[u8], off: &mut usize, len: usize| -> Vec<u8> {
        let out = buf[*off..*off + len].to_vec();
        *off += len;
        out
    };

    let version = read_u32(raw, &mut offset);
    let input_count = read_u8(raw, &mut offset) as usize;
    let mut inputs = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        let prev_len = read_u8(raw, &mut offset) as usize;
        let prev_txid_bytes = read_bytes(raw, &mut offset, prev_len);
        let mut prev_txid = [0u8; 32];
        if prev_txid_bytes.len() == 32 {
            prev_txid.copy_from_slice(&prev_txid_bytes);
        } else {
            let start = 32 - prev_txid_bytes.len();
            prev_txid[start..].copy_from_slice(&prev_txid_bytes);
        }
        let prev_index = read_u32(raw, &mut offset);
        let script_sig_len = read_u8(raw, &mut offset) as usize;
        let script_sig = read_bytes(raw, &mut offset, script_sig_len);
        let sequence = read_u32(raw, &mut offset);
        inputs.push(TxInput {
            prev_txid,
            prev_index,
            script_sig,
            sequence,
        });
    }

    let output_count = read_u8(raw, &mut offset) as usize;
    let mut outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        let value = read_u64(raw, &mut offset);
        // Bug fix: outputs with script_pubkey > 252 bytes (BtcHeaderBatch
        // header batches, large MPSO covenants, etc.) need varint length
        // decoding. Backward-compatible: for n < 253 the encoding is a
        // single byte identical to the previous u8.
        let script_len = crate::tx::read_varint_at(raw, &mut offset)
            .unwrap_or(0) as usize;
        let script_pubkey = read_bytes(raw, &mut offset, script_len);
        outputs.push(TxOutput {
            value,
            script_pubkey,
        });
    }

    let locktime = read_u32(raw, &mut offset);

    Transaction {
        version,
        inputs,
        outputs,
        locktime,
    }
}

/// Classify a tx for mempool admission. Returns
/// [`MempoolPriority::ZeroFeeAllowed`] for the buyer-side shapes
/// across BTC and LTC:
///   - any tx whose outputs include a `BtcHeaderBatch` or `LtcHeaderBatch` script tag,
///   - any tx whose input 0 spends an `HtlcBtcSwapV1` or `HtlcLtcSwapV1`
///     UTXO with witness selector `0x01` (chain-proof claim),
///   - any tx whose input 0 spends a `SwapOrder` or `LtcSwapOrder` UTXO
///     of sell_irm direction with witness selector `0x01` (sell-direction fill).
///
/// All other shapes return [`MempoolPriority::Standard`]. Used by the
/// P2P ingress path so peer-relayed buyer-side txs receive the same
/// exemption local handlers grant explicitly. RPC handlers that build
/// these txs directly call `add_transaction_with_priority(..., ZFA, ..)`
/// without going through this classifier.
pub fn classify_tx_priority(
    tx: &Transaction,
    chain: &ChainState,
) -> crate::mempool::MempoolPriority {
    use crate::btc_spv::BTC_HEADER_BATCH_TAG;
    use crate::ltc_spv::LTC_HEADER_BATCH_TAG;
    use crate::mempool::MempoolPriority;

    for o in &tx.outputs {
        match o.script_pubkey.first().copied() {
            Some(BTC_HEADER_BATCH_TAG)
            | Some(LTC_HEADER_BATCH_TAG) => {
                return MempoolPriority::ZeroFeeAllowed;
            }
            _ => {}
        }
    }

    if let Some(input0) = tx.inputs.first() {
        let outpoint = OutPoint {
            txid: input0.prev_txid,
            index: input0.prev_index,
        };
        if let Some(utxo) = chain.utxos.get(&outpoint) {
            let script = &utxo.output.script_pubkey;
            let first_witness_byte = input0.script_sig.first().copied();
            // BTC buyer paths.
            if parse_htlc_btc_swap_v1_script(script).is_some()
                && first_witness_byte == Some(0x01)
            {
                return MempoolPriority::ZeroFeeAllowed;
            }
            if let Some(order) = parse_swap_order_script(script) {
                if order.direction == SWAP_ORDER_DIRECTION_SELL
                    && first_witness_byte == Some(0x01)
                {
                    return MempoolPriority::ZeroFeeAllowed;
                }
            }
            // LTC buyer paths (Phase C/D parity).
            if parse_htlc_ltc_swap_v1_script(script).is_some()
                && first_witness_byte == Some(0x01)
            {
                return MempoolPriority::ZeroFeeAllowed;
            }
            if let Some(order) = parse_ltc_swap_order_script(script) {
                if order.direction == LTC_SWAP_ORDER_DIRECTION_SELL
                    && first_witness_byte == Some(0x01)
                {
                    return MempoolPriority::ZeroFeeAllowed;
                }
            }
        }
    }

    MempoolPriority::Standard
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis::load_locked_genesis;
    use crate::pow::Target;
    use crate::tx::{
        encode_htlcv1_claim_witness, encode_htlcv1_refund_witness, encode_htlcv1_script,
        p2pkh_script, HtlcV1Output,
    };
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::{Signature, SigningKey};

    fn base_chain(activation: Option<u64>) -> ChainState {
        let locked = load_locked_genesis().expect("locked genesis");
        let genesis = block_from_locked(&locked).expect("genesis block");
        let pow_limit = Target { bits: 0x1f00ffff };
        let params = ChainParams {
            genesis_block: genesis,
            pow_limit,
            htlcv1_activation_height: activation,
            mpsov1_activation_height: None,
            lwma: LwmaParams::new(None, pow_limit),
            lwma_v2: None,
        auxpow_activation_height: None,
            btc_spv: None,
            ltc_spv: None,
            htlc_btc_swap_v1_activation_height: None,
            btc_swap_bech32_payment_activation_height: None,
            htlc_ltc_swap_v1_activation_height: None,
            swap_order_v1_activation_height: None,
            ltc_swap_order_v1_activation_height: None,
            coinbase_header_batch_activation_height: None,
        };
        ChainState::new(params)
    }

    fn signing_key(seed: u8) -> SigningKey {
        let mut sk = [0u8; 32];
        sk.fill(seed);
        SigningKey::from_bytes((&sk).into()).expect("signing key")
    }

    fn key_hash(sk: &SigningKey) -> [u8; 20] {
        let pubkey = sk.verifying_key().to_encoded_point(true);
        hash160(pubkey.as_bytes())
    }

    fn p2pkh_witness(
        tx: &Transaction,
        input_index: usize,
        script: &[u8],
        sk: &SigningKey,
    ) -> Vec<u8> {
        let digest = signature_digest(tx, input_index, script);
        let sig: Signature = sk.sign_prehash(&digest).expect("sign");
        let sig = sig.normalize_s().unwrap_or(sig);
        let mut sig_bytes = sig.to_der().as_bytes().to_vec();
        sig_bytes.push(0x01);
        let pubkey = sk
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();

        let mut out = Vec::with_capacity(1 + sig_bytes.len() + 1 + pubkey.len());
        out.push(sig_bytes.len() as u8);
        out.extend_from_slice(&sig_bytes);
        out.push(pubkey.len() as u8);
        out.extend_from_slice(&pubkey);
        out
    }

    fn add_spendable_p2pkh_utxo(chain: &mut ChainState, sk: &SigningKey, value: u64) -> OutPoint {
        let pkh = key_hash(sk);
        let op = OutPoint {
            txid: [7u8; 32],
            index: 0,
        };
        chain.utxos.insert(
            op.clone(),
            UtxoEntry {
                output: TxOutput {
                    value,
                    script_pubkey: p2pkh_script(&pkh),
                },
                height: chain.tip_height(),
                is_coinbase: false,
            },
        );
        op
    }

    fn difficulty_chain(lwma_activation: Option<u64>, pow_limit_bits: u32) -> ChainState {
        let locked = load_locked_genesis().expect("locked genesis");
        let genesis = block_from_locked(&locked).expect("genesis block");
        let pow_limit = Target {
            bits: pow_limit_bits,
        };
        let params = ChainParams {
            genesis_block: genesis,
            pow_limit,
            htlcv1_activation_height: None,
            mpsov1_activation_height: None,
            lwma: LwmaParams::new(lwma_activation, pow_limit),
            lwma_v2: None,
        auxpow_activation_height: None,
            btc_spv: None,
            ltc_spv: None,
            htlc_btc_swap_v1_activation_height: None,
            btc_swap_bech32_payment_activation_height: None,
            htlc_ltc_swap_v1_activation_height: None,
            swap_order_v1_activation_height: None,
            ltc_swap_order_v1_activation_height: None,
            coinbase_header_batch_activation_height: None,
        };
        ChainState::new(params)
    }

    fn push_synthetic_block(chain: &mut ChainState, time: u32, bits: u32) {
        let prev_height = chain.chain.len().saturating_sub(1) as u64;
        let prev_hash = chain
            .chain
            .last()
            .expect("prev block")
            .header
            .hash_for_height(prev_height);
        chain.chain.push(Block {
            header: BlockHeader {
                version: 1,
                prev_hash,
                merkle_root: [chain.chain.len() as u8; 32],
                time,
                bits,
                nonce: chain.chain.len() as u32,
            },
            transactions: Vec::new(),
            auxpow: None,
        });
        chain.height = chain.chain.len() as u64;
    }

    fn synthetic_working_bits(chain: &ChainState) -> u32 {
        let target = chain.params.lwma.max_target.to_target() / BigUint::from(2u8);
        Target::from_target(&target).bits
    }

    fn manual_legacy_target(chain: &ChainState, height: u64) -> Target {
        if height == 0 {
            return chain.params.genesis_block.header.target();
        }
        let last_block = chain.chain.last().expect("last block");
        if height < DIFFICULTY_RETARGET_INTERVAL || !height.is_multiple_of(DIFFICULTY_RETARGET_INTERVAL) {
            return last_block.header.target();
        }
        let interval = DIFFICULTY_RETARGET_INTERVAL as usize;
        if chain.chain.len() <= interval {
            return last_block.header.target();
        }
        let prev_block = &chain.chain[chain.chain.len() - interval];
        let actual_time = (last_block.header.time as i64) - (prev_block.header.time as i64);
        // Test mirror of the production legacy retarget. Same V1-hardcoded
        // rationale: legacy retarget heights are all pre-LWMA and thus
        // well below any future block-time V2 fork.
        let mut expected_time = (DIFFICULTY_RETARGET_INTERVAL * BLOCK_TARGET_INTERVAL_V1) as i64;
        if expected_time <= 0 {
            expected_time = 1;
        }
        let mut adj_num = if actual_time <= 0 {
            expected_time / 4
        } else {
            actual_time
        };
        let adj_den = expected_time;
        if adj_num * 4 < adj_den {
            adj_num = adj_den / 4;
        } else if adj_num > adj_den * 4 {
            adj_num = adj_den * 4;
        }
        let mut new_target = last_block.header.target().to_target() * BigUint::from(adj_num as u64);
        new_target /= BigUint::from(adj_den as u64);
        Target::from_target(&new_target)
    }

    #[test]
    fn htlc_activation_boundary_n_minus_1_n_n_plus_1() {
        let mut chain = base_chain(Some(10));
        let sender = signing_key(1);
        let recipient = signing_key(2);
        let refund = signing_key(3);
        let prev = add_spendable_p2pkh_utxo(&mut chain, &sender, 5_000);

        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: prev.txid,
                prev_index: prev.index,
                script_sig: Vec::new(),
                sequence: 0xffff_ffff,
            }],
            outputs: vec![TxOutput {
                value: 4_000,
                script_pubkey: encode_htlcv1_script(&HtlcV1Output {
                    expected_hash: [0x42; 32],
                    recipient_pkh: key_hash(&recipient),
                    refund_pkh: key_hash(&refund),
                    timeout_height: 20,
                }),
            }],
            locktime: 0,
        };
        let utxo_script = chain.utxos.get(&prev).unwrap().output.script_pubkey.clone();
        tx.inputs[0].script_sig = p2pkh_witness(&tx, 0, &utxo_script, &sender);

        chain.height = 9;
        assert!(
            chain.validate_transaction(&tx).is_err(),
            "N-1 must reject HTLC output"
        );

        chain.height = 10;
        assert!(
            chain.validate_transaction(&tx).is_ok(),
            "N must allow HTLC output"
        );

        chain.height = 11;
        assert!(
            chain.validate_transaction(&tx).is_ok(),
            "N+1 must allow HTLC output"
        );
    }

    #[test]
    fn htlc_output_rejected_before_activation() {
        let mut chain = base_chain(Some(100));
        let sender = signing_key(1);
        let recipient = signing_key(2);
        let refund = signing_key(3);
        let prev = add_spendable_p2pkh_utxo(&mut chain, &sender, 5_000);

        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: prev.txid,
                prev_index: prev.index,
                script_sig: Vec::new(),
                sequence: 0xffff_ffff,
            }],
            outputs: vec![TxOutput {
                value: 4_000,
                script_pubkey: encode_htlcv1_script(&HtlcV1Output {
                    expected_hash: [11u8; 32],
                    recipient_pkh: key_hash(&recipient),
                    refund_pkh: key_hash(&refund),
                    timeout_height: 10,
                }),
            }],
            locktime: 0,
        };
        let utxo_script = chain.utxos.get(&prev).unwrap().output.script_pubkey.clone();
        tx.inputs[0].script_sig = p2pkh_witness(&tx, 0, &utxo_script, &sender);

        let err = chain
            .validate_transaction(&tx)
            .expect_err("must reject pre-activation");
        assert!(err.contains("HTLCv1 output before activation"));
    }

    #[test]
    fn htlc_output_accepted_after_activation() {
        let mut chain = base_chain(Some(1));
        let sender = signing_key(4);
        let recipient = signing_key(5);
        let refund = signing_key(6);
        let prev = add_spendable_p2pkh_utxo(&mut chain, &sender, 10_000);

        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: prev.txid,
                prev_index: prev.index,
                script_sig: Vec::new(),
                sequence: 0xffff_ffff,
            }],
            outputs: vec![TxOutput {
                value: 8_000,
                script_pubkey: encode_htlcv1_script(&HtlcV1Output {
                    expected_hash: [22u8; 32],
                    recipient_pkh: key_hash(&recipient),
                    refund_pkh: key_hash(&refund),
                    timeout_height: 10,
                }),
            }],
            locktime: 0,
        };

        let utxo_script = chain.utxos.get(&prev).unwrap().output.script_pubkey.clone();
        tx.inputs[0].script_sig = p2pkh_witness(&tx, 0, &utxo_script, &sender);
        assert!(chain.validate_transaction(&tx).is_ok());
    }

    fn add_htlc_utxo(
        chain: &mut ChainState,
        value: u64,
        recipient: &SigningKey,
        refund: &SigningKey,
        expected_hash: [u8; 32],
        timeout_height: u64,
    ) -> (OutPoint, HtlcV1Output) {
        let htlc = HtlcV1Output {
            expected_hash,
            recipient_pkh: key_hash(recipient),
            refund_pkh: key_hash(refund),
            timeout_height,
        };
        let op = OutPoint {
            txid: [9u8; 32],
            index: 1,
        };
        chain.utxos.insert(
            op.clone(),
            UtxoEntry {
                output: TxOutput {
                    value,
                    script_pubkey: encode_htlcv1_script(&htlc),
                },
                height: chain.tip_height(),
                is_coinbase: false,
            },
        );
        (op, htlc)
    }

    #[test]
    fn htlc_claim_valid_and_wrong_preimage() {
        let mut chain = base_chain(Some(1));
        chain.height = 50;
        let recipient = signing_key(7);
        let refund = signing_key(8);
        let preimage = b"secret-htlc";
        let mut expected_hash = [0u8; 32];
        expected_hash.copy_from_slice(&Sha256::digest(preimage));

        let (prev, htlc) =
            add_htlc_utxo(&mut chain, 10_000, &recipient, &refund, expected_hash, 60);

        let out_script = p2pkh_script(&key_hash(&recipient));
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: prev.txid,
                prev_index: prev.index,
                script_sig: Vec::new(),
                sequence: 0xffff_fffe,
            }],
            outputs: vec![TxOutput {
                value: 9_000,
                script_pubkey: out_script,
            }],
            locktime: 0,
        };

        let htlc_script = encode_htlcv1_script(&htlc);
        let digest = signature_digest(&tx, 0, &htlc_script);
        let sig: Signature = recipient.sign_prehash(&digest).expect("sign claim");
        let sig = sig.normalize_s().unwrap_or(sig);
        let mut sig_bytes = sig.to_der().as_bytes().to_vec();
        sig_bytes.push(0x01);
        let pubkey = recipient
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        tx.inputs[0].script_sig =
            encode_htlcv1_claim_witness(&sig_bytes, &pubkey, preimage).expect("claim witness");

        assert!(chain.validate_transaction(&tx).is_ok());

        let mut wrong = tx.clone();
        wrong.inputs[0].script_sig = encode_htlcv1_claim_witness(&sig_bytes, &pubkey, b"wrong")
            .expect("claim witness wrong");
        assert!(chain.validate_transaction(&wrong).is_err());
    }

    #[test]
    fn htlc_refund_respects_timeout() {
        let mut chain = base_chain(Some(1));
        let recipient = signing_key(9);
        let refund = signing_key(10);
        let (prev, htlc) = add_htlc_utxo(&mut chain, 10_000, &recipient, &refund, [44u8; 32], 120);

        let out_script = p2pkh_script(&key_hash(&refund));
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: prev.txid,
                prev_index: prev.index,
                script_sig: Vec::new(),
                sequence: 0xffff_fffe,
            }],
            outputs: vec![TxOutput {
                value: 9_000,
                script_pubkey: out_script,
            }],
            locktime: 0,
        };

        let htlc_script = encode_htlcv1_script(&htlc);
        let digest = signature_digest(&tx, 0, &htlc_script);
        let sig: Signature = refund.sign_prehash(&digest).expect("sign refund");
        let sig = sig.normalize_s().unwrap_or(sig);
        let mut sig_bytes = sig.to_der().as_bytes().to_vec();
        sig_bytes.push(0x01);
        let pubkey = refund
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        tx.inputs[0].script_sig =
            encode_htlcv1_refund_witness(&sig_bytes, &pubkey).expect("refund witness");

        chain.height = 119;
        assert!(chain.validate_transaction(&tx).is_err());

        chain.height = 120;
        assert!(chain.validate_transaction(&tx).is_ok());
    }

    #[test]
    fn htlc_malformed_witness_fails() {
        let mut chain = base_chain(Some(1));
        chain.height = 50;
        let recipient = signing_key(11);
        let refund = signing_key(12);
        let (prev, _htlc) = add_htlc_utxo(&mut chain, 10_000, &recipient, &refund, [55u8; 32], 10);

        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: prev.txid,
                prev_index: prev.index,
                script_sig: vec![0x01, 0x02],
                sequence: 0xffff_fffe,
            }],
            outputs: vec![TxOutput {
                value: 9_000,
                script_pubkey: p2pkh_script(&key_hash(&recipient)),
            }],
            locktime: 0,
        };

        assert!(chain.validate_transaction(&tx).is_err());

        tx.inputs[0].script_sig = vec![];
        assert!(chain.validate_transaction(&tx).is_err());
    }

    #[test]
    fn htlc_claim_wrong_recipient_pubkey_fails() {
        let mut chain = base_chain(Some(1));
        chain.height = 50;
        let recipient = signing_key(15);
        let wrong = signing_key(16);
        let refund = signing_key(17);
        let mut expected_hash = [0u8; 32];
        expected_hash.copy_from_slice(&Sha256::digest(b"ok-secret"));

        let (prev, htlc) =
            add_htlc_utxo(&mut chain, 10_000, &recipient, &refund, expected_hash, 80);
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: prev.txid,
                prev_index: prev.index,
                script_sig: Vec::new(),
                sequence: 0xffff_fffe,
            }],
            outputs: vec![TxOutput {
                value: 9_000,
                script_pubkey: p2pkh_script(&key_hash(&recipient)),
            }],
            locktime: 0,
        };

        let htlc_script = encode_htlcv1_script(&htlc);
        let digest = signature_digest(&tx, 0, &htlc_script);
        let sig: Signature = wrong.sign_prehash(&digest).expect("sign wrong");
        let sig = sig.normalize_s().unwrap_or(sig);
        let mut sig_bytes = sig.to_der().as_bytes().to_vec();
        sig_bytes.push(0x01);
        let pubkey = wrong
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        tx.inputs[0].script_sig =
            encode_htlcv1_claim_witness(&sig_bytes, &pubkey, b"ok-secret").expect("claim witness");

        assert!(chain.validate_transaction(&tx).is_err());
    }

    #[test]
    fn htlc_refund_wrong_pubkey_fails() {
        let mut chain = base_chain(Some(1));
        chain.height = 500;
        let recipient = signing_key(18);
        let refund = signing_key(19);
        let wrong = signing_key(20);
        let (prev, htlc) = add_htlc_utxo(&mut chain, 10_000, &recipient, &refund, [66u8; 32], 120);

        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: prev.txid,
                prev_index: prev.index,
                script_sig: Vec::new(),
                sequence: 0xffff_fffe,
            }],
            outputs: vec![TxOutput {
                value: 9_000,
                script_pubkey: p2pkh_script(&key_hash(&refund)),
            }],
            locktime: 0,
        };

        let htlc_script = encode_htlcv1_script(&htlc);
        let digest = signature_digest(&tx, 0, &htlc_script);
        let sig: Signature = wrong.sign_prehash(&digest).expect("sign wrong refund");
        let sig = sig.normalize_s().unwrap_or(sig);
        let mut sig_bytes = sig.to_der().as_bytes().to_vec();
        sig_bytes.push(0x01);
        let pubkey = wrong
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        tx.inputs[0].script_sig =
            encode_htlcv1_refund_witness(&sig_bytes, &pubkey).expect("refund witness");

        assert!(chain.validate_transaction(&tx).is_err());
    }

    #[test]
    fn pre_activation_uses_legacy_retarget_exactly() {
        let mut chain = difficulty_chain(Some(30_000), 0x207fffff);
        let mut time = chain.chain[0].header.time;
        for _ in 1..DIFFICULTY_RETARGET_INTERVAL {
            time += (BLOCK_TARGET_INTERVAL_V1 * 2) as u32;
            push_synthetic_block(&mut chain, time, 0x207fffff);
        }

        let expected = manual_legacy_target(&chain, DIFFICULTY_RETARGET_INTERVAL);
        assert_eq!(
            chain.target_for_height(DIFFICULTY_RETARGET_INTERVAL),
            expected
        );
    }

    #[test]
    fn activation_boundary_switches_to_lwma() {
        let activation = 70;
        let mut chain = difficulty_chain(Some(activation), 0x207fffff);
        let mut time = chain.chain[0].header.time;
        for i in 1..activation {
            time += if i < 60 {
                BLOCK_TARGET_INTERVAL_V1 as u32
            } else {
                60
            };
            push_synthetic_block(&mut chain, time, 0x207fffff);
        }

        assert_eq!(
            chain.target_for_height(activation - 1),
            chain.legacy_target_for_height(activation - 1)
        );
        assert_eq!(
            chain.target_for_height(activation),
            chain.lwma_target_for_height(activation)
        );
    }

    #[test]
    fn lwma_is_deterministic_for_same_headers() {
        let activation = 70;
        let mut chain_a = difficulty_chain(Some(activation), 0x207fffff);
        let mut chain_b = difficulty_chain(Some(activation), 0x207fffff);
        let mut time = chain_a.chain[0].header.time;
        for i in 1..activation {
            time += if i % 2 == 0 { 300 } else { 900 };
            push_synthetic_block(&mut chain_a, time, 0x207fffff);
            push_synthetic_block(&mut chain_b, time, 0x207fffff);
        }

        let first = chain_a.target_for_height(activation);
        let second = chain_a.target_for_height(activation);
        let repeated = chain_b.target_for_height(activation);
        assert_eq!(first, second);
        assert_eq!(first, repeated);
    }

    #[test]
    fn lwma_recovers_from_hashrate_increase_with_step_clamp() {
        let activation = 70;
        let mut chain = difficulty_chain(Some(activation), 0x207fffff);
        let test_bits = synthetic_working_bits(&chain);
        let mut time = chain.chain[0].header.time;
        for i in 1..activation {
            time += if i < 40 { 600 } else { 60 };
            push_synthetic_block(&mut chain, time, test_bits);
        }

        let prev_target = chain.chain.last().unwrap().header.target().to_target();
        let next_target = chain.target_for_height(activation).to_target();
        let min_step_target =
            Target::from_target(&(prev_target.clone() / BigUint::from(2u8))).to_target();
        assert!(
            next_target < prev_target,
            "difficulty should rise after faster blocks"
        );
        assert!(
            next_target >= min_step_target,
            "hardening must respect 2x step clamp"
        );
    }

    #[test]
    fn lwma_recovers_from_hashrate_drop_with_step_clamp() {
        let activation = 70;
        let mut chain = difficulty_chain(Some(activation), 0x207fffff);
        let test_bits = synthetic_working_bits(&chain);
        let mut time = chain.chain[0].header.time;
        for i in 1..activation {
            time += if i < 40 { 600 } else { 1800 };
            push_synthetic_block(&mut chain, time, test_bits);
        }

        let prev_target = chain.chain.last().unwrap().header.target().to_target();
        let next_target = chain.target_for_height(activation).to_target();
        let max_step_target =
            Target::from_target(&(prev_target.clone() * BigUint::from(2u8))).to_target();
        assert!(
            next_target > prev_target,
            "difficulty should ease after slower blocks"
        );
        assert!(
            next_target <= max_step_target,
            "easing must respect 2x step clamp"
        );
        assert!(next_target <= chain.params.lwma.max_target.to_target());
    }

    #[test]
    fn lwma_clamps_forward_timestamp_spikes() {
        let activation = 70;
        let mut clamped = difficulty_chain(Some(activation), 0x207fffff);
        let mut time_a = clamped.chain[0].header.time;
        for i in 1..activation {
            time_a += if i == activation - 1 {
                (BLOCK_TARGET_INTERVAL_V1 * 6) as u32
            } else {
                BLOCK_TARGET_INTERVAL_V1 as u32
            };
            push_synthetic_block(&mut clamped, time_a, 0x207fffff);
        }

        let mut spiked = difficulty_chain(Some(activation), 0x207fffff);
        let mut time_b = spiked.chain[0].header.time;
        for i in 1..activation {
            time_b += if i == activation - 1 {
                200_000
            } else {
                BLOCK_TARGET_INTERVAL_V1 as u32
            };
            push_synthetic_block(&mut spiked, time_b, 0x207fffff);
        }

        assert_eq!(
            spiked.target_for_height(activation),
            clamped.target_for_height(activation)
        );
    }

    #[test]
    fn lwma_clamps_non_monotonic_timestamps_to_one_second() {
        let activation = 70;
        let mut monotonic = difficulty_chain(Some(activation), 0x207fffff);
        let mut time_a = monotonic.chain[0].header.time;
        for i in 1..activation {
            time_a += if i == activation - 1 {
                1
            } else {
                BLOCK_TARGET_INTERVAL_V1 as u32
            };
            push_synthetic_block(&mut monotonic, time_a, 0x207fffff);
        }

        let mut non_monotonic = difficulty_chain(Some(activation), 0x207fffff);
        let mut time_b = non_monotonic.chain[0].header.time;
        for i in 1..activation {
            if i == activation - 1 {
                time_b = time_b.saturating_sub(500);
            } else {
                time_b += BLOCK_TARGET_INTERVAL_V1 as u32;
            }
            push_synthetic_block(&mut non_monotonic, time_b, 0x207fffff);
        }

        assert_eq!(
            non_monotonic.target_for_height(activation),
            monotonic.target_for_height(activation)
        );
    }

    #[test]
    fn lwma_respects_post_activation_max_target_floor() {
        let activation = 70;
        let mut chain = difficulty_chain(Some(activation), 0x207fffff);
        let mut time = chain.chain[0].header.time;
        for _ in 1..activation {
            time += 3600;
            push_synthetic_block(&mut chain, time, 0x207fffff);
        }

        let next = chain.target_for_height(activation).to_target();
        assert_eq!(next, chain.params.lwma.max_target.to_target());
        assert!(next <= chain.params.pow_limit.to_target());
    }

    #[test]
    fn activation_future_does_not_rewrite_historical_targets() {
        let mut future = difficulty_chain(Some(30_000), 0x207fffff);
        let mut disabled = difficulty_chain(None, 0x207fffff);
        let mut time = future.chain[0].header.time;
        for _ in 1..DIFFICULTY_RETARGET_INTERVAL {
            time += 1200;
            push_synthetic_block(&mut future, time, 0x207fffff);
            push_synthetic_block(&mut disabled, time, 0x207fffff);
        }

        assert_eq!(
            future.target_for_height(DIFFICULTY_RETARGET_INTERVAL),
            disabled.target_for_height(DIFFICULTY_RETARGET_INTERVAL)
        );
    }

    #[test]
    fn reorg_across_activation_boundary_recomputes_safely() {
        let activation = 70;
        let mut chain = difficulty_chain(Some(activation), 0x207fffff);
        let mut time = chain.chain[0].header.time;
        for i in 1..activation {
            time += if i < 60 { 600 } else { 120 };
            push_synthetic_block(&mut chain, time, 0x207fffff);
        }
        let target_at_activation = chain.target_for_height(activation);

        time += 120;
        push_synthetic_block(&mut chain, time, target_at_activation.bits);
        let _post_activation_target = chain.target_for_height(activation + 1);

        chain.chain.pop();
        chain.height = chain.chain.len() as u64;

        assert_eq!(chain.target_for_height(activation), target_at_activation);
        assert_eq!(
            chain.target_for_height(activation - 1),
            chain.legacy_target_for_height(activation - 1)
        );
    }

    #[test]
    fn legacy_p2pkh_unchanged() {
        let mut chain = base_chain(None);
        let sender = signing_key(13);
        let recipient = signing_key(14);
        let prev = add_spendable_p2pkh_utxo(&mut chain, &sender, 20_000);

        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: prev.txid,
                prev_index: prev.index,
                script_sig: Vec::new(),
                sequence: 0xffff_ffff,
            }],
            outputs: vec![TxOutput {
                value: 18_000,
                script_pubkey: p2pkh_script(&key_hash(&recipient)),
            }],
            locktime: 0,
        };

        let utxo_script = chain.utxos.get(&prev).unwrap().output.script_pubkey.clone();
        tx.inputs[0].script_sig = p2pkh_witness(&tx, 0, &utxo_script, &sender);

        assert!(chain.validate_transaction(&tx).is_ok());
    }

    // -----------------------------------------------------------------------
    // LWMA v2 tests (N=30, clamp=10T) -- gated behind lwma_v2 activation
    // -----------------------------------------------------------------------

    fn difficulty_chain_v2(
        lwma_v1_activation: Option<u64>,
        v2_activation: Option<u64>,
        pow_limit_bits: u32,
    ) -> ChainState {
        let locked = crate::genesis::load_locked_genesis().expect("locked genesis");
        let genesis = block_from_locked(&locked).expect("genesis block");
        let pow_limit = Target {
            bits: pow_limit_bits,
        };
        let v2 = v2_activation.map(|h| LwmaParams::new_v2(Some(h), pow_limit));
        let params = ChainParams {
            genesis_block: genesis,
            pow_limit,
            htlcv1_activation_height: None,
            mpsov1_activation_height: None,
            lwma: LwmaParams::new(lwma_v1_activation, pow_limit),
            lwma_v2: v2,
            auxpow_activation_height: None,
            btc_spv: None,
            ltc_spv: None,
            htlc_btc_swap_v1_activation_height: None,
            btc_swap_bech32_payment_activation_height: None,
            htlc_ltc_swap_v1_activation_height: None,
            swap_order_v1_activation_height: None,
            ltc_swap_order_v1_activation_height: None,
            coinbase_header_batch_activation_height: None,
        };
        ChainState::new(params)
    }

    #[test]
    fn lwma_v2_inactive_when_field_is_none() {
        // With lwma_v2: None the chain must behave identically to v1.
        let activation = 70u64;
        let mut v1_chain = difficulty_chain(Some(activation), 0x207fffff);
        let mut v2_chain = difficulty_chain_v2(Some(activation), None, 0x207fffff);
        let bits = synthetic_working_bits(&v1_chain);
        let mut time = v1_chain.chain[0].header.time;
        for _ in 1..=80 {
            time += 600;
            push_synthetic_block(&mut v1_chain, time, bits);
            push_synthetic_block(&mut v2_chain, time, bits);
        }
        let t1 = v1_chain.target_for_height(80);
        let t2 = v2_chain.target_for_height(80);
        assert_eq!(
            t1.bits, t2.bits,
            "v2=None must produce same target as pure v1"
        );
    }

    #[test]
    fn lwma_v2_activates_at_boundary() {
        let v1_act = 10u64;
        let v2_act = 50u64;
        let mut chain = difficulty_chain_v2(Some(v1_act), Some(v2_act), 0x207fffff);
        let bits = synthetic_working_bits(&chain);
        let mut time = chain.chain[0].header.time;
        for _ in 1..=80 {
            time += 600;
            push_synthetic_block(&mut chain, time, bits);
        }
        let below = chain.target_for_height(v2_act - 1);
        let at = chain.target_for_height(v2_act);
        let above = chain.target_for_height(v2_act + 5);
        let pow_limit = chain.params.pow_limit.to_target();
        assert!(below.to_target() <= pow_limit);
        assert!(at.to_target() <= pow_limit);
        assert!(above.to_target() <= pow_limit);
        assert_ne!(at.bits, 0, "v2 target must be non-zero at activation");
        assert_ne!(above.bits, 0, "v2 target must be non-zero above activation");
    }

    #[test]
    fn lwma_v2_step_clamp_unchanged() {
        let v1_act = 10u64;
        let v2_act = 20u64;
        let mut chain = difficulty_chain_v2(Some(v1_act), Some(v2_act), 0x207fffff);
        let bits = synthetic_working_bits(&chain);
        let mut time = chain.chain[0].header.time;
        for _ in 1..=20 {
            time += 600;
            push_synthetic_block(&mut chain, time, bits);
        }
        // Slow blocks at v2 max solvetime (10T = 6000s).
        let mut prev_target = chain.target_for_height(20);
        for h in 21u64..=50 {
            time += 6000;
            push_synthetic_block(&mut chain, time, bits);
            let next_target = chain.target_for_height(h);
            let max_allowed = Target::from_target(&(prev_target.to_target() * BigUint::from(2u8)));
            assert!(
                next_target.to_target() <= max_allowed.to_target(),
                "v2 step clamp violated at height {}: {:?} > 2x {:?}",
                h,
                next_target,
                prev_target
            );
            prev_target = next_target;
        }
    }

    #[test]
    fn lwma_v2_recovers_faster_than_v1_after_hashrate_drop() {
        // Use a hard initial bits (well below max_target) so there is ample room to
        // ease without saturating.  After exactly 35 moderate-slow blocks (900s =
        // 1.5x T, step-clamp NOT binding), v2's 30-block window is fully refreshed
        // while v1's 60-block window is still half diluted by old fast blocks.
        // Therefore v2 must produce a strictly higher (easier) target.
        let v1_act = 10u64;
        let v2_act = 10u64;
        // Hard bits: far from the 0x207fffff max_target so no saturation.
        let hard_bits: u32 = 0x1a007fff;
        let slow_st: u32 = 900; // 1.5x T; ratio < 2x so step clamp never fires

        let mut v1 = difficulty_chain(Some(v1_act), 0x207fffff);
        let mut v2 = difficulty_chain_v2(Some(v1_act), Some(v2_act), 0x207fffff);

        let mut time_v1 = v1.chain[0].header.time;
        let mut time_v2 = v2.chain[0].header.time;

        // 70 normal blocks to fill both windows with fast-block history.
        for _ in 1..=70 {
            time_v1 += 600;
            push_synthetic_block(&mut v1, time_v1, hard_bits);
            time_v2 += 600;
            push_synthetic_block(&mut v2, time_v2, hard_bits);
        }

        // 35 slow blocks.  After 30 slow blocks v2 window is fully refreshed;
        // v1 still carries 25 old fast blocks in its 60-block window.
        for _ in 0..35 {
            time_v1 += slow_st;
            push_synthetic_block(&mut v1, time_v1, hard_bits);
            time_v2 += slow_st;
            push_synthetic_block(&mut v2, time_v2, hard_bits);
        }

        let h = v1.height;
        let t_v1 = v1.target_for_height(h).to_target();
        let t_v2 = v2.target_for_height(h).to_target();

        // v2: weighted_avg_st=900s -> ratio 1.5x; v1: ~847s -> ratio ~1.41x
        // Both < 2x so step clamp does not fire. v2 must be strictly easier.
        assert!(
            t_v2 > t_v1,
            "v2 (N=30) should ease faster: v2_target={} v1_target={}",
            t_v2,
            t_v1
        );
    }

    #[test]
    fn lwma_v2_steady_state_stable() {
        let v1_act = 10u64;
        let v2_act = 20u64;
        let mut chain = difficulty_chain_v2(Some(v1_act), Some(v2_act), 0x207fffff);
        let bits = synthetic_working_bits(&chain);
        let mut time = chain.chain[0].header.time;
        for _ in 1..=20 {
            time += 600;
            push_synthetic_block(&mut chain, time, bits);
        }
        let base = chain.target_for_height(v2_act).to_target();
        for h in (v2_act + 1)..=(v2_act + 100) {
            time += 600;
            push_synthetic_block(&mut chain, time, bits);
            let t = chain.target_for_height(h).to_target();
            let lo = &base / BigUint::from(4u8);
            let hi = &base * BigUint::from(4u8);
            assert!(
                t >= lo && t <= hi,
                "v2 target drifted out of 4x band at height {}: {} vs base {}",
                h,
                t,
                base
            );
        }
    }

    // -----------------------------------------------------------------------
    // Activation boundary simulation: heights 19738-19741
    // -----------------------------------------------------------------------

    #[test]
    fn lwma_v2_boundary_no_off_by_one() {
        // Build a chain with v1 active from height 16462 and v2 from 19740.
        // Populate synthetic blocks up to height 19741 and verify:
        //   heights < 19740  => v1 params (N=60, clamp=6T)
        //   heights >= 19740 => v2 params (N=30, clamp=10T)
        // Also verifies: no panic, deterministic target, no off-by-one.
        let v1_act: u64 = 16_462;
        let v2_act: u64 = 19_740;

        let mut chain = difficulty_chain_v2(Some(v1_act), Some(v2_act), 0x207fffff);
        let bits = synthetic_working_bits(&chain);
        let mut time = chain.chain[0].header.time;

        // Push 19741 blocks at 600s each to go past the activation boundary.
        for _ in 1..=19_741u64 {
            time += 600;
            push_synthetic_block(&mut chain, time, bits);
        }

        // Collect targets at the four boundary heights.
        let t_19738 = chain.target_for_height(19_738);
        let t_19739 = chain.target_for_height(19_739);
        let t_19740 = chain.target_for_height(19_740);
        let t_19741 = chain.target_for_height(19_741);

        // All must be non-zero and within pow_limit.
        let pow_limit = chain.params.pow_limit.to_target();
        for (h, t) in [
            (19_738u64, &t_19738),
            (19_739, &t_19739),
            (19_740, &t_19740),
            (19_741, &t_19741),
        ] {
            assert_ne!(t.bits, 0, "target at height {} must be non-zero", h);
            assert!(
                t.to_target() <= pow_limit,
                "target at height {} must not exceed pow_limit",
                h
            );
        }

        // Below activation: lwma_v2_active_at must be false.
        assert!(
            !chain.lwma_v2_active_at(19_739),
            "lwma_v2 must NOT be active at height 19739 (one below activation)"
        );

        // At and above activation: lwma_v2_active_at must be true.
        assert!(
            chain.lwma_v2_active_at(19_740),
            "lwma_v2 must be active at height 19740 (activation height)"
        );
        assert!(
            chain.lwma_v2_active_at(19_741),
            "lwma_v2 must be active at height 19741 (above activation)"
        );

        // Under steady-state 600s intervals the target should be stable across the
        // boundary -- no sudden jump.  Allow a 4x band around the pre-activation
        // target to account for legitimate parameter differences.
        let base = t_19739.to_target();
        let lo = &base / BigUint::from(4u8);
        let hi = &base * BigUint::from(4u8);
        assert!(
            t_19740.to_target() >= lo && t_19740.to_target() <= hi,
            "target at activation (19740) must not jump more than 4x from prior block:              19739={} 19740={}", t_19739.bits, t_19740.bits
        );
        assert!(
            t_19741.to_target() >= lo && t_19741.to_target() <= hi,
            "target at 19741 must not jump more than 4x from prior block:              19739={} 19741={}", t_19739.bits, t_19741.bits
        );
    }

    // -----------------------------------------------------------------------
    // Block-time V2 fork tests (T 600 -> 120, halving rescale 210k -> 1.05M)
    //
    // The protocol target T is height-aware via
    // constants::block_target_interval(height). All other LwmaParams fields
    // (window, clamp factors, step factors, max_target) are unchanged across
    // the fork — only the solvetime clamp ceiling and the LWMA expected-time
    // scale with T. These tests exercise the boundary inside the LWMA
    // codepath that handles both eras with a single implementation.
    // -----------------------------------------------------------------------

    use std::sync::{Mutex as StdMutex, OnceLock, PoisonError};

    fn block_time_v2_env_lock() -> &'static StdMutex<()> {
        static LOCK: OnceLock<StdMutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| StdMutex::new(()))
    }

    /// `IRIUM_NETWORK=testnet` is used here (not "devnet") because
    /// `legacy_target_for_height` and `lwma_target_for_height_with` both
    /// short-circuit to `pow_limit` when `IRIUM_NETWORK == devnet | regtest`
    /// for fast CPU mining on dev networks. That shortcut would mask the
    /// LWMA boundary math these tests are trying to exercise. Testnet keeps
    /// the env-overridable activation height resolver without triggering
    /// the fast-mining shortcut.
    fn set_block_time_v2_fork(fork: u64) {
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var(
            "IRIUM_BLOCK_TIME_V2_ACTIVATION_HEIGHT",
            fork.to_string(),
        );
    }

    fn clear_block_time_v2_fork() {
        std::env::remove_var("IRIUM_BLOCK_TIME_V2_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_NETWORK");
    }

    #[test]
    fn block_time_v2_clamp_uses_v1_below_fork_v2_above() {
        // Construct LwmaParams once (no env active during construction; the
        // solvetime ceiling is computed at use time, not at construction
        // time). Then set the env and confirm `max_solvetime_at` picks V1
        // below the fork and V2 at/above it.
        let _guard = block_time_v2_env_lock()
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        clear_block_time_v2_fork();

        let pow_limit = Target { bits: 0x207fffff };
        let v1_params = LwmaParams::new(Some(10), pow_limit);
        let v2_params = LwmaParams::new_v2(Some(10), pow_limit);

        set_block_time_v2_fork(100);

        // V1 below fork: clamp = LWMA_SOLVETIME_CLAMP_FACTOR (6) * 600 = 3600s.
        assert_eq!(v1_params.max_solvetime_at(99), 6 * 600);
        // V1 at/above fork: 6 * 120 = 720s.
        assert_eq!(v1_params.max_solvetime_at(100), 6 * 120);
        assert_eq!(v1_params.max_solvetime_at(101), 6 * 120);

        // V2 below fork: clamp = LWMA_V2_SOLVETIME_CLAMP_FACTOR (10) * 600 = 6000s.
        assert_eq!(v2_params.max_solvetime_at(99), 10 * 600);
        // V2 at/above fork: 10 * 120 = 1200s.
        assert_eq!(v2_params.max_solvetime_at(100), 10 * 120);

        clear_block_time_v2_fork();
    }

    #[test]
    fn block_time_v2_lwma_target_changes_at_fork_boundary() {
        // Build a chain with LWMA active early and produce a synthetic
        // window of equal-interval blocks. With the V2 fork enabled at
        // height H, computing target_for_height(H-1) and target_for_height(H)
        // should reflect different protocol targets T inside the LWMA
        // expected-time formula. The two results must differ when the
        // observed solvetime is far from both T_V1 and T_V2 (i.e. the LWMA
        // is not yet at equilibrium for either era).
        let _guard = block_time_v2_env_lock()
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        clear_block_time_v2_fork();

        let activation = 10u64;
        let fork = 100u64;
        let mut chain = difficulty_chain(Some(activation), 0x207fffff);
        let bits = synthetic_working_bits(&chain);

        // 300s solvetimes — between V1 (600) and V2 (120). Pre-fork this
        // is below-target (LWMA hardens); post-fork it is above-target
        // (LWMA eases). So the post-fork target must be GREATER than the
        // pre-fork target for the same observed history.
        let mut time = chain.chain[0].header.time;
        for _ in 1..fork {
            time += 300;
            push_synthetic_block(&mut chain, time, bits);
        }

        set_block_time_v2_fork(fork);
        let t_at_fork = chain.target_for_height(fork).to_target();
        clear_block_time_v2_fork();
        let t_at_fork_v1 = chain.target_for_height(fork).to_target();

        assert!(
            t_at_fork > t_at_fork_v1,
            "post-fork LWMA must yield a LARGER target (easier difficulty) than pre-fork for the same 300s observed history: pre={} post={}",
            t_at_fork_v1, t_at_fork
        );
    }

    #[test]
    fn block_time_v2_disabled_preserves_pre_change_behavior() {
        // Regression: with the V2 fork height left at None (mainnet ships
        // this way), every LWMA target computation must be byte-identical
        // to the pre-change implementation. We assert this indirectly by
        // computing two equivalent chains and verifying their targets
        // match — one with the env explicitly cleared, one with the env
        // set to a height above any height we query.
        let _guard = block_time_v2_env_lock()
            .lock()
            .unwrap_or_else(PoisonError::into_inner);

        let activation = 10u64;
        let mut chain_a = difficulty_chain(Some(activation), 0x207fffff);
        let mut chain_b = difficulty_chain(Some(activation), 0x207fffff);
        let bits = synthetic_working_bits(&chain_a);
        let mut time = chain_a.chain[0].header.time;
        for _ in 1..50 {
            time += 600;
            push_synthetic_block(&mut chain_a, time, bits);
            push_synthetic_block(&mut chain_b, time, bits);
        }

        clear_block_time_v2_fork();
        let t_a = chain_a.target_for_height(50);

        set_block_time_v2_fork(10_000); // far above the heights we query
        let t_b = chain_b.target_for_height(50);
        clear_block_time_v2_fork();

        assert_eq!(
            t_a.bits, t_b.bits,
            "V2 fork above queried heights must produce the same target as V2 disabled"
        );
    }

    // -----------------------------------------------------------------------
    // MPSOv1 tests
    // -----------------------------------------------------------------------

    fn mpso_chain(activation: Option<u64>) -> ChainState {
        let locked = load_locked_genesis().expect("locked genesis");
        let genesis = block_from_locked(&locked).expect("genesis block");
        let pow_limit = Target { bits: 0x1f00ffff };
        let params = ChainParams {
            genesis_block: genesis,
            pow_limit,
            htlcv1_activation_height: None,
            mpsov1_activation_height: activation,
            lwma: LwmaParams::new(None, pow_limit),
            lwma_v2: None,
        auxpow_activation_height: None,
            btc_spv: None,
            ltc_spv: None,
            htlc_btc_swap_v1_activation_height: None,
            btc_swap_bech32_payment_activation_height: None,
            htlc_ltc_swap_v1_activation_height: None,
            swap_order_v1_activation_height: None,
            ltc_swap_order_v1_activation_height: None,
            coinbase_header_batch_activation_height: None,
        };
        ChainState::new(params)
    }

    fn mpso_signing_key(seed: u8) -> SigningKey {
        let mut sk = [0u8; 32];
        sk[31] = seed;
        SigningKey::from_bytes((&sk).into()).expect("signing key")
    }

    fn mpso_pubkey_bytes(sk: &SigningKey) -> [u8; 33] {
        let encoded = sk.verifying_key().to_encoded_point(true);
        let bytes = encoded.as_bytes();
        let mut pk = [0u8; 33];
        pk.copy_from_slice(bytes);
        pk
    }

    fn make_mpso_output(
        claim_keys: &[&SigningKey],
        claim_m: u8,
        refund_keys: &[&SigningKey],
        refund_m: u8,
        timeout_height: u64,
        secret: Option<&[u8]>,
    ) -> (
        crate::tx::MpsoV1Output,
        Vec<u8>, // script
    ) {
        use crate::tx::{encode_mpso_script, MpsoV1Output};
        use sha2::{Digest, Sha256};

        let flags = if secret.is_some() { 0x01u8 } else { 0x00u8 };
        let optional_hash = secret.map(|pre| {
            let h = Sha256::digest(pre);
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&h);
            arr
        });
        let mpso = MpsoV1Output {
            flags,
            claim_n: claim_keys.len() as u8,
            claim_m,
            refund_n: refund_keys.len() as u8,
            refund_m,
            agreement_hash: [0x55u8; 32],
            claim_pubkeys: claim_keys.iter().map(|sk| mpso_pubkey_bytes(sk)).collect(),
            refund_pubkeys: refund_keys.iter().map(|sk| mpso_pubkey_bytes(sk)).collect(),
            timeout_height,
            optional_hash,
        };
        let script = encode_mpso_script(&mpso);
        (mpso, script)
    }

    fn add_mpso_utxo(
        chain: &mut ChainState,
        value: u64,
        claim_keys: &[&SigningKey],
        claim_m: u8,
        refund_keys: &[&SigningKey],
        refund_m: u8,
        timeout_height: u64,
        secret: Option<&[u8]>,
    ) -> (OutPoint, crate::tx::MpsoV1Output) {
        let (mpso, script) = make_mpso_output(
            claim_keys,
            claim_m,
            refund_keys,
            refund_m,
            timeout_height,
            secret,
        );
        let op = OutPoint {
            txid: [0xaau8; 32],
            index: 0,
        };
        chain.utxos.insert(
            op.clone(),
            UtxoEntry {
                output: TxOutput {
                    value,
                    script_pubkey: script,
                },
                height: 1,
                is_coinbase: false,
            },
        );
        (op, mpso)
    }

    fn mpso_sign_claim(
        tx: &Transaction,
        input_index: usize,
        mpso: &crate::tx::MpsoV1Output,
        signers: &[&SigningKey],
        bitmap: u8,
        preimage: Option<&[u8]>,
    ) -> Vec<u8> {
        use crate::tx::{encode_mpso_claim_witness, encode_mpso_script};
        let scriptcode = encode_mpso_script(mpso);
        let digest = signature_digest(tx, input_index, &scriptcode);
        let mut sigs = Vec::new();
        for sk in signers {
            let sig: Signature = sk.sign_prehash(&digest).expect("sign");
            let sig = sig.normalize_s().unwrap_or(sig);
            let mut sig_bytes = sig.to_der().as_bytes().to_vec();
            sig_bytes.push(0x01);
            sigs.push(sig_bytes);
        }
        encode_mpso_claim_witness(bitmap, &sigs, preimage).expect("claim witness")
    }

    fn mpso_sign_refund(
        tx: &Transaction,
        input_index: usize,
        mpso: &crate::tx::MpsoV1Output,
        signers: &[&SigningKey],
        bitmap: u8,
    ) -> Vec<u8> {
        use crate::tx::{encode_mpso_refund_witness, encode_mpso_script};
        let scriptcode = encode_mpso_script(mpso);
        let digest = signature_digest(tx, input_index, &scriptcode);
        let mut sigs = Vec::new();
        for sk in signers {
            let sig: Signature = sk.sign_prehash(&digest).expect("sign");
            let sig = sig.normalize_s().unwrap_or(sig);
            let mut sig_bytes = sig.to_der().as_bytes().to_vec();
            sig_bytes.push(0x01);
            sigs.push(sig_bytes);
        }
        encode_mpso_refund_witness(bitmap, &sigs).expect("refund witness")
    }

    fn simple_spend_tx(prev: &OutPoint, dest: &SigningKey) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: prev.txid,
                prev_index: prev.index,
                script_sig: Vec::new(),
                sequence: 0xffff_fffe,
            }],
            outputs: vec![TxOutput {
                value: 9_000,
                script_pubkey: p2pkh_script(&key_hash(dest)),
            }],
            locktime: 0,
        }
    }

    #[test]
    fn mpso_disabled_by_default_mainnet() {
        let chain = mpso_chain(None);
        assert!(!chain.mpsov1_active_at(0));
        assert!(!chain.mpsov1_active_at(u64::MAX));
    }

    #[test]
    fn mpso_activation_boundary() {
        let chain = mpso_chain(Some(100));
        assert!(!chain.mpsov1_active_at(99));
        assert!(chain.mpsov1_active_at(100));
        assert!(chain.mpsov1_active_at(101));
    }

    #[test]
    fn mpso_output_rejected_before_activation() {
        let mut chain = mpso_chain(Some(100));
        chain.height = 50;
        let sender = mpso_signing_key(1);
        let ck1 = mpso_signing_key(2);
        let rk1 = mpso_signing_key(3);
        let prev = add_spendable_p2pkh_utxo(&mut chain, &sender, 10_000);
        let (_, mpso_script) = make_mpso_output(&[&ck1], 1, &[&rk1], 1, 1000, None);

        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: prev.txid,
                prev_index: prev.index,
                script_sig: Vec::new(),
                sequence: 0xffff_ffff,
            }],
            outputs: vec![TxOutput {
                value: 9_000,
                script_pubkey: mpso_script,
            }],
            locktime: 0,
        };
        let utxo_script = chain.utxos.get(&prev).unwrap().output.script_pubkey.clone();
        tx.inputs[0].script_sig = p2pkh_witness(&tx, 0, &utxo_script, &sender);

        let err = chain
            .validate_transaction(&tx)
            .expect_err("must reject before activation");
        assert!(
            err.contains("MPSOv1 output before activation"),
            "got: {err}"
        );
    }

    #[test]
    fn mpso_output_accepted_after_activation() {
        let mut chain = mpso_chain(Some(1));
        chain.height = 50;
        let sender = mpso_signing_key(1);
        let ck1 = mpso_signing_key(2);
        let rk1 = mpso_signing_key(3);
        let prev = add_spendable_p2pkh_utxo(&mut chain, &sender, 10_000);
        let (_, mpso_script) = make_mpso_output(&[&ck1], 1, &[&rk1], 1, 100, None);

        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: prev.txid,
                prev_index: prev.index,
                script_sig: Vec::new(),
                sequence: 0xffff_ffff,
            }],
            outputs: vec![TxOutput {
                value: 9_000,
                script_pubkey: mpso_script,
            }],
            locktime: 0,
        };
        let utxo_script = chain.utxos.get(&prev).unwrap().output.script_pubkey.clone();
        tx.inputs[0].script_sig = p2pkh_witness(&tx, 0, &utxo_script, &sender);
        assert!(chain.validate_transaction(&tx).is_ok());
    }

    #[test]
    fn mpso_output_reject_timeout_not_in_future() {
        let mut chain = mpso_chain(Some(1));
        chain.height = 50;
        let sender = mpso_signing_key(1);
        let ck1 = mpso_signing_key(2);
        let rk1 = mpso_signing_key(3);
        let prev = add_spendable_p2pkh_utxo(&mut chain, &sender, 10_000);
        // timeout_height = 50 == current height, must be rejected
        let (_, mpso_script) = make_mpso_output(&[&ck1], 1, &[&rk1], 1, 50, None);

        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: prev.txid,
                prev_index: prev.index,
                script_sig: Vec::new(),
                sequence: 0xffff_ffff,
            }],
            outputs: vec![TxOutput {
                value: 9_000,
                script_pubkey: mpso_script,
            }],
            locktime: 0,
        };
        let utxo_script = chain.utxos.get(&prev).unwrap().output.script_pubkey.clone();
        tx.inputs[0].script_sig = p2pkh_witness(&tx, 0, &utxo_script, &sender);
        let err = chain
            .validate_transaction(&tx)
            .expect_err("timeout not in future");
        assert!(err.contains("timeout_height"), "got: {err}");
    }

    #[test]
    fn mpso_valid_1of1_claim_before_timeout() {
        let mut chain = mpso_chain(Some(1));
        chain.height = 50;
        let ck1 = mpso_signing_key(10);
        let rk1 = mpso_signing_key(11);
        let dest = mpso_signing_key(12);
        let (prev, mpso) = add_mpso_utxo(&mut chain, 10_000, &[&ck1], 1, &[&rk1], 1, 100, None);

        let mut tx = simple_spend_tx(&prev, &dest);
        tx.inputs[0].script_sig = mpso_sign_claim(&tx, 0, &mpso, &[&ck1], 0b00000001, None);
        assert!(
            chain.validate_transaction(&tx).is_ok(),
            "valid 1-of-1 claim"
        );
    }

    #[test]
    fn mpso_reject_claim_at_timeout() {
        let mut chain = mpso_chain(Some(1));
        chain.height = 100; // exactly timeout height
        let ck1 = mpso_signing_key(10);
        let rk1 = mpso_signing_key(11);
        let dest = mpso_signing_key(12);
        let (prev, mpso) = add_mpso_utxo(&mut chain, 10_000, &[&ck1], 1, &[&rk1], 1, 100, None);

        let mut tx = simple_spend_tx(&prev, &dest);
        tx.inputs[0].script_sig = mpso_sign_claim(&tx, 0, &mpso, &[&ck1], 0b00000001, None);
        assert!(
            chain.validate_transaction(&tx).is_err(),
            "claim at timeout must fail"
        );
    }

    #[test]
    fn mpso_reject_claim_after_timeout() {
        let mut chain = mpso_chain(Some(1));
        chain.height = 150;
        let ck1 = mpso_signing_key(10);
        let rk1 = mpso_signing_key(11);
        let dest = mpso_signing_key(12);
        let (prev, mpso) = add_mpso_utxo(&mut chain, 10_000, &[&ck1], 1, &[&rk1], 1, 100, None);

        let mut tx = simple_spend_tx(&prev, &dest);
        tx.inputs[0].script_sig = mpso_sign_claim(&tx, 0, &mpso, &[&ck1], 0b00000001, None);
        assert!(
            chain.validate_transaction(&tx).is_err(),
            "claim after timeout must fail"
        );
    }

    #[test]
    fn mpso_valid_refund_at_timeout() {
        let mut chain = mpso_chain(Some(1));
        chain.height = 100;
        let ck1 = mpso_signing_key(10);
        let rk1 = mpso_signing_key(11);
        let dest = mpso_signing_key(12);
        let (prev, mpso) = add_mpso_utxo(&mut chain, 10_000, &[&ck1], 1, &[&rk1], 1, 100, None);

        let mut tx = simple_spend_tx(&prev, &dest);
        tx.inputs[0].script_sig = mpso_sign_refund(&tx, 0, &mpso, &[&rk1], 0b00000001);
        assert!(
            chain.validate_transaction(&tx).is_ok(),
            "refund at timeout must succeed"
        );
    }

    #[test]
    fn mpso_valid_refund_after_timeout() {
        let mut chain = mpso_chain(Some(1));
        chain.height = 200;
        let ck1 = mpso_signing_key(10);
        let rk1 = mpso_signing_key(11);
        let dest = mpso_signing_key(12);
        let (prev, mpso) = add_mpso_utxo(&mut chain, 10_000, &[&ck1], 1, &[&rk1], 1, 100, None);

        let mut tx = simple_spend_tx(&prev, &dest);
        tx.inputs[0].script_sig = mpso_sign_refund(&tx, 0, &mpso, &[&rk1], 0b00000001);
        assert!(
            chain.validate_transaction(&tx).is_ok(),
            "refund after timeout must succeed"
        );
    }

    #[test]
    fn mpso_reject_refund_before_timeout() {
        let mut chain = mpso_chain(Some(1));
        chain.height = 50;
        let ck1 = mpso_signing_key(10);
        let rk1 = mpso_signing_key(11);
        let dest = mpso_signing_key(12);
        let (prev, mpso) = add_mpso_utxo(&mut chain, 10_000, &[&ck1], 1, &[&rk1], 1, 100, None);

        let mut tx = simple_spend_tx(&prev, &dest);
        tx.inputs[0].script_sig = mpso_sign_refund(&tx, 0, &mpso, &[&rk1], 0b00000001);
        assert!(
            chain.validate_transaction(&tx).is_err(),
            "refund before timeout must fail"
        );
    }

    #[test]
    fn mpso_valid_2of3_claim() {
        let mut chain = mpso_chain(Some(1));
        chain.height = 50;
        let ck1 = mpso_signing_key(20);
        let ck2 = mpso_signing_key(21);
        let ck3 = mpso_signing_key(22);
        let rk1 = mpso_signing_key(23);
        let dest = mpso_signing_key(24);
        let (prev, mpso) = add_mpso_utxo(
            &mut chain,
            10_000,
            &[&ck1, &ck2, &ck3],
            2,
            &[&rk1],
            1,
            100,
            None,
        );

        // Use signers 0 and 2 (bitmap = 0b00000101)
        let mut tx = simple_spend_tx(&prev, &dest);
        tx.inputs[0].script_sig = mpso_sign_claim(&tx, 0, &mpso, &[&ck1, &ck3], 0b00000101, None);
        assert!(
            chain.validate_transaction(&tx).is_ok(),
            "2-of-3 claim with keys 0,2"
        );
    }

    #[test]
    fn mpso_reject_1of2_when_threshold_is_2() {
        let mut chain = mpso_chain(Some(1));
        chain.height = 50;
        let ck1 = mpso_signing_key(20);
        let ck2 = mpso_signing_key(21);
        let rk1 = mpso_signing_key(22);
        let dest = mpso_signing_key(23);
        let (prev, mpso) =
            add_mpso_utxo(&mut chain, 10_000, &[&ck1, &ck2], 2, &[&rk1], 1, 100, None);

        // Only 1 signer but threshold is 2
        let mut tx = simple_spend_tx(&prev, &dest);
        tx.inputs[0].script_sig = mpso_sign_claim(&tx, 0, &mpso, &[&ck1], 0b00000001, None);
        assert!(
            chain.validate_transaction(&tx).is_err(),
            "1-of-2 when threshold=2 must fail"
        );
    }

    #[test]
    fn mpso_reject_high_bitmap_bits() {
        let mut chain = mpso_chain(Some(1));
        chain.height = 50;
        let ck1 = mpso_signing_key(30);
        let rk1 = mpso_signing_key(31);
        let dest = mpso_signing_key(32);
        let (prev, mpso) = add_mpso_utxo(&mut chain, 10_000, &[&ck1], 1, &[&rk1], 1, 100, None);

        let mut tx = simple_spend_tx(&prev, &dest);
        // bitmap = 0b10000001: bit 0 is valid (ck1), bit 7 is out of range for N=1
        // popcount = 2, but claim_m = 1, so this also fails the popcount check
        // Use bitmap = 0b10000000 with 0 valid signers but popcount=1 matches M=1
        // (but bit 7 is out of range for claim_n=1)
        let raw_witness = {
            use crate::tx::encode_mpso_script;
            let scriptcode = encode_mpso_script(&mpso);
            let digest = signature_digest(&tx, 0, &scriptcode);
            let sig: Signature = ck1.sign_prehash(&digest).expect("sign");
            let sig = sig.normalize_s().unwrap_or(sig);
            let mut sig_bytes = sig.to_der().as_bytes().to_vec();
            sig_bytes.push(0x01);
            let mut w = Vec::new();
            w.push(0x01u8); // claim
            w.push(0b10000000u8); // bit 7 set, out of range for N=1
            w.push(sig_bytes.len() as u8);
            w.extend_from_slice(&sig_bytes);
            w
        };
        tx.inputs[0].script_sig = raw_witness;
        assert!(
            chain.validate_transaction(&tx).is_err(),
            "high bitmap bit must fail"
        );
    }

    #[test]
    fn mpso_reject_extra_signatures_trailing_bytes() {
        let mut chain = mpso_chain(Some(1));
        chain.height = 50;
        let ck1 = mpso_signing_key(40);
        let rk1 = mpso_signing_key(41);
        let dest = mpso_signing_key(42);
        let (prev, mpso) = add_mpso_utxo(&mut chain, 10_000, &[&ck1], 1, &[&rk1], 1, 100, None);

        let mut tx = simple_spend_tx(&prev, &dest);
        let mut witness = mpso_sign_claim(&tx, 0, &mpso, &[&ck1], 0b00000001, None);
        // Append a trailing byte
        witness.push(0x00);
        tx.inputs[0].script_sig = witness;
        assert!(
            chain.validate_transaction(&tx).is_err(),
            "trailing witness byte must fail"
        );
    }

    #[test]
    fn mpso_valid_secret_gated_claim() {
        let mut chain = mpso_chain(Some(1));
        chain.height = 50;
        let ck1 = mpso_signing_key(50);
        let rk1 = mpso_signing_key(51);
        let dest = mpso_signing_key(52);
        let preimage = b"test-mpso-secret";
        let (prev, mpso) = add_mpso_utxo(
            &mut chain,
            10_000,
            &[&ck1],
            1,
            &[&rk1],
            1,
            100,
            Some(preimage),
        );

        let mut tx = simple_spend_tx(&prev, &dest);
        tx.inputs[0].script_sig =
            mpso_sign_claim(&tx, 0, &mpso, &[&ck1], 0b00000001, Some(preimage));
        assert!(
            chain.validate_transaction(&tx).is_ok(),
            "secret-gated claim must succeed"
        );
    }

    #[test]
    fn mpso_reject_missing_preimage_when_secret_gate_set() {
        let mut chain = mpso_chain(Some(1));
        chain.height = 50;
        let ck1 = mpso_signing_key(50);
        let rk1 = mpso_signing_key(51);
        let dest = mpso_signing_key(52);
        let preimage = b"test-mpso-secret";
        let (prev, mpso) = add_mpso_utxo(
            &mut chain,
            10_000,
            &[&ck1],
            1,
            &[&rk1],
            1,
            100,
            Some(preimage),
        );

        let mut tx = simple_spend_tx(&prev, &dest);
        // No preimage provided
        tx.inputs[0].script_sig = mpso_sign_claim(&tx, 0, &mpso, &[&ck1], 0b00000001, None);
        assert!(
            chain.validate_transaction(&tx).is_err(),
            "missing preimage must fail"
        );
    }

    #[test]
    fn mpso_reject_wrong_preimage() {
        let mut chain = mpso_chain(Some(1));
        chain.height = 50;
        let ck1 = mpso_signing_key(50);
        let rk1 = mpso_signing_key(51);
        let dest = mpso_signing_key(52);
        let preimage = b"correct-preimage";
        let (prev, mpso) = add_mpso_utxo(
            &mut chain,
            10_000,
            &[&ck1],
            1,
            &[&rk1],
            1,
            100,
            Some(preimage),
        );

        let mut tx = simple_spend_tx(&prev, &dest);
        tx.inputs[0].script_sig =
            mpso_sign_claim(&tx, 0, &mpso, &[&ck1], 0b00000001, Some(b"wrong-preimage"));
        assert!(
            chain.validate_transaction(&tx).is_err(),
            "wrong preimage must fail"
        );
    }

    #[test]
    fn mpso_reject_preimage_too_long() {
        let mut chain = mpso_chain(Some(1));
        chain.height = 50;
        let ck1 = mpso_signing_key(50);
        let rk1 = mpso_signing_key(51);
        let dest = mpso_signing_key(52);
        let preimage = b"correct-preimage";
        let (prev, mpso) = add_mpso_utxo(
            &mut chain,
            10_000,
            &[&ck1],
            1,
            &[&rk1],
            1,
            100,
            Some(preimage),
        );

        let mut tx = simple_spend_tx(&prev, &dest);
        let raw_witness = {
            use crate::tx::encode_mpso_script;
            let scriptcode = encode_mpso_script(&mpso);
            let digest = signature_digest(&tx, 0, &scriptcode);
            let sig: Signature = ck1.sign_prehash(&digest).expect("sign");
            let sig = sig.normalize_s().unwrap_or(sig);
            let mut sig_bytes = sig.to_der().as_bytes().to_vec();
            sig_bytes.push(0x01);
            let long_pre = vec![0xffu8; 65];
            let mut w = Vec::new();
            w.push(0x01u8);
            w.push(0b00000001u8);
            w.push(sig_bytes.len() as u8);
            w.extend_from_slice(&sig_bytes);
            w.push(65u8);
            w.extend_from_slice(&long_pre);
            w
        };
        tx.inputs[0].script_sig = raw_witness;
        assert!(
            chain.validate_transaction(&tx).is_err(),
            "65-byte preimage must fail"
        );
    }
    #[test]
    fn mpso_reject_claim_with_refund_key() {
        let mut chain = mpso_chain(Some(1));
        chain.height = 50;
        let ck1 = mpso_signing_key(60);
        let rk1 = mpso_signing_key(61);
        let dest = mpso_signing_key(62);
        let (prev, mpso) = add_mpso_utxo(&mut chain, 10_000, &[&ck1], 1, &[&rk1], 1, 100, None);

        let mut tx = simple_spend_tx(&prev, &dest);
        // Sign with the refund key but present as claim
        tx.inputs[0].script_sig = mpso_sign_claim(&tx, 0, &mpso, &[&rk1], 0b00000001, None);
        assert!(
            chain.validate_transaction(&tx).is_err(),
            "refund key cannot claim"
        );
    }

    #[test]
    fn mpso_reject_refund_with_claim_key() {
        let mut chain = mpso_chain(Some(1));
        chain.height = 200;
        let ck1 = mpso_signing_key(60);
        let rk1 = mpso_signing_key(61);
        let dest = mpso_signing_key(62);
        let (prev, mpso) = add_mpso_utxo(&mut chain, 10_000, &[&ck1], 1, &[&rk1], 1, 100, None);

        let mut tx = simple_spend_tx(&prev, &dest);
        // Sign with the claim key but present as refund
        tx.inputs[0].script_sig = mpso_sign_refund(&tx, 0, &mpso, &[&ck1], 0b00000001);
        assert!(
            chain.validate_transaction(&tx).is_err(),
            "claim key cannot refund"
        );
    }

    #[test]
    fn mpso_htlcv1_still_works_with_mpso_active() {
        let mut chain = mpso_chain(Some(1));
        // Also activate HTLCv1
        chain.params.htlcv1_activation_height = Some(1);
        chain.height = 50;
        let sender = signing_key(1);
        let recipient = signing_key(2);
        let refund_sk = signing_key(3);
        let prev = add_spendable_p2pkh_utxo(&mut chain, &sender, 10_000);

        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: prev.txid,
                prev_index: prev.index,
                script_sig: Vec::new(),
                sequence: 0xffff_ffff,
            }],
            outputs: vec![TxOutput {
                value: 9_000,
                script_pubkey: encode_htlcv1_script(&HtlcV1Output {
                    expected_hash: [0x42; 32],
                    recipient_pkh: key_hash(&recipient),
                    refund_pkh: key_hash(&refund_sk),
                    timeout_height: 200,
                }),
            }],
            locktime: 0,
        };
        let utxo_script = chain.utxos.get(&prev).unwrap().output.script_pubkey.clone();
        tx.inputs[0].script_sig = p2pkh_witness(&tx, 0, &utxo_script, &sender);
        assert!(
            chain.validate_transaction(&tx).is_ok(),
            "HTLCv1 must still work when MPSOv1 is also active"
        );
    }

    #[test]
    fn mpso_reject_invalid_compressed_pubkey_in_output() {
        let mut chain = mpso_chain(Some(1));
        chain.height = 50;
        let sender = mpso_signing_key(1);
        let prev = add_spendable_p2pkh_utxo(&mut chain, &sender, 10_000);

        // Build a script with an invalid pubkey (all-zero 33 bytes with prefix 0x02).
        use crate::tx::{encode_mpso_script, MpsoV1Output};
        let mpso_bad = MpsoV1Output {
            flags: 0x00,
            claim_n: 1,
            claim_m: 1,
            refund_n: 1,
            refund_m: 1,
            agreement_hash: [0x55u8; 32],
            claim_pubkeys: vec![[
                0x02u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0,
            ]],
            refund_pubkeys: vec![[
                0x03u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0,
            ]],
            timeout_height: 100,
            optional_hash: None,
        };
        let bad_script = encode_mpso_script(&mpso_bad);
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: prev.txid,
                prev_index: prev.index,
                script_sig: Vec::new(),
                sequence: 0xffff_ffff,
            }],
            outputs: vec![TxOutput {
                value: 9_000,
                script_pubkey: bad_script,
            }],
            locktime: 0,
        };
        let utxo_script = chain.utxos.get(&prev).unwrap().output.script_pubkey.clone();
        tx.inputs[0].script_sig = p2pkh_witness(&tx, 0, &utxo_script, &sender);
        let err = chain
            .validate_transaction(&tx)
            .expect_err("invalid pubkey must fail");
        assert!(
            err.contains("invalid secp256k1 pubkey") || err.contains("Malformed"),
            "got: {err}"
        );
    }

    #[test]
    fn mpso_witness_over_768_bytes_rejected() {
        let mut chain = mpso_chain(Some(1));
        chain.height = 50;
        let ck1 = mpso_signing_key(70);
        let rk1 = mpso_signing_key(71);
        let dest = mpso_signing_key(72);
        let (prev, mpso) = add_mpso_utxo(&mut chain, 10_000, &[&ck1], 1, &[&rk1], 1, 100, None);

        let mut tx = simple_spend_tx(&prev, &dest);
        let mut witness = mpso_sign_claim(&tx, 0, &mpso, &[&ck1], 0b00000001, None);
        // Pad to 769 bytes
        while witness.len() < 769 {
            witness.push(0x00);
        }
        tx.inputs[0].script_sig = witness;
        assert!(
            chain.validate_transaction(&tx).is_err(),
            "769-byte witness must fail"
        );
    }

    #[test]
    fn mpso_full_quorum_claim_valid() {
        // claim_m == claim_n (full quorum)
        let mut chain = mpso_chain(Some(1));
        chain.height = 50;
        let ck1 = mpso_signing_key(80);
        let ck2 = mpso_signing_key(81);
        let rk1 = mpso_signing_key(82);
        let dest = mpso_signing_key(83);
        let (prev, mpso) =
            add_mpso_utxo(&mut chain, 10_000, &[&ck1, &ck2], 2, &[&rk1], 1, 100, None);

        let mut tx = simple_spend_tx(&prev, &dest);
        tx.inputs[0].script_sig = mpso_sign_claim(&tx, 0, &mpso, &[&ck1, &ck2], 0b00000011, None);
        assert!(
            chain.validate_transaction(&tx).is_ok(),
            "full quorum claim must succeed"
        );
    }

    #[test]
    fn mpso_different_claim_refund_thresholds() {
        // refund_m != claim_m
        let mut chain = mpso_chain(Some(1));
        let ck1 = mpso_signing_key(90);
        let ck2 = mpso_signing_key(91);
        let ck3 = mpso_signing_key(92);
        let rk1 = mpso_signing_key(93);
        let rk2 = mpso_signing_key(94);
        let dest = mpso_signing_key(95);

        // Claim: 2-of-3, Refund: 1-of-2
        chain.height = 50;
        let (prev, mpso) = add_mpso_utxo(
            &mut chain,
            10_000,
            &[&ck1, &ck2, &ck3],
            2,
            &[&rk1, &rk2],
            1,
            100,
            None,
        );

        // Valid claim: 2-of-3
        let mut tx = simple_spend_tx(&prev, &dest);
        tx.inputs[0].script_sig = mpso_sign_claim(&tx, 0, &mpso, &[&ck1, &ck2], 0b00000011, None);
        assert!(chain.validate_transaction(&tx).is_ok(), "2-of-3 claim");

        // Valid refund: 1-of-2
        chain.height = 200;
        let (prev2, mpso2) = add_mpso_utxo(
            &mut chain,
            10_000,
            &[&ck1, &ck2, &ck3],
            2,
            &[&rk1, &rk2],
            1,
            100,
            None,
        );
        let mut tx2 = simple_spend_tx(&prev2, &dest);
        tx2.inputs[0].script_sig = mpso_sign_refund(&tx2, 0, &mpso2, &[&rk2], 0b00000010);
        assert!(
            chain.validate_transaction(&tx2).is_ok(),
            "1-of-2 refund (key index 1)"
        );
    }

    // ----- Mempool eviction on block connect (FIX 2) -----

    fn fresh_mempool_path(label: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "irium_chain_mempool_evict_{}_{}_{}",
            label,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn build_signed_spend(
        chain: &ChainState,
        sender: &SigningKey,
        prev: &OutPoint,
        value: u64,
        recipient_pkh: [u8; 20],
    ) -> Transaction {
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: prev.txid,
                prev_index: prev.index,
                script_sig: Vec::new(),
                sequence: 0xffff_ffff,
            }],
            outputs: vec![TxOutput {
                value,
                script_pubkey: p2pkh_script(&recipient_pkh),
            }],
            locktime: 0,
        };
        let utxo_script = chain.utxos.get(prev).unwrap().output.script_pubkey.clone();
        tx.inputs[0].script_sig = p2pkh_witness(&tx, 0, &utxo_script, sender);
        tx
    }

    #[test]
    fn evict_invalid_mempool_entries_drops_double_spend() {
        let mut chain = base_chain(None);
        let sender = signing_key(11);
        let prev = add_spendable_p2pkh_utxo(&mut chain, &sender, 10_000);
        let tx = build_signed_spend(&chain, &sender, &prev, 5_000, [0xaa; 20]);
        assert!(
            chain.validate_transaction(&tx).is_ok(),
            "test setup: signed spend must validate against fresh chain"
        );

        let path = fresh_mempool_path("double_spend");
        let mut mempool =
            crate::mempool::MempoolManager::new(path.clone(), 100, 0.0, 0);
        let raw = tx.serialize();
        mempool
            .add_transaction(tx.clone(), raw, 0)
            .expect("admit tx to mempool");
        assert_eq!(mempool.len(), 1);

        // Simulate a block that connected a *different* transaction which
        // spent the same UTXO: remove the prev outpoint from chain.utxos
        // (that's what ChainState::connect_block does internally via the
        // undo log). The mempool entry now references a missing UTXO.
        chain.utxos.remove(&prev);

        let evicted =
            crate::mempool::evict_invalid_mempool_entries(&chain, &mut mempool);
        assert_eq!(evicted, 1, "double-spend conflict must be evicted");
        assert_eq!(mempool.len(), 0);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn evict_invalid_mempool_entries_keeps_valid_tx_unchanged() {
        let mut chain = base_chain(None);
        let sender = signing_key(12);
        let prev = add_spendable_p2pkh_utxo(&mut chain, &sender, 10_000);
        let tx = build_signed_spend(&chain, &sender, &prev, 5_000, [0xbb; 20]);
        assert!(chain.validate_transaction(&tx).is_ok());

        let path = fresh_mempool_path("valid_kept");
        let mut mempool =
            crate::mempool::MempoolManager::new(path.clone(), 100, 0.0, 0);
        let raw = tx.serialize();
        mempool
            .add_transaction(tx.clone(), raw, 0)
            .expect("admit tx to mempool");
        assert_eq!(mempool.len(), 1);

        // No conflict: chain still has the UTXO; tx is still valid.
        let evicted =
            crate::mempool::evict_invalid_mempool_entries(&chain, &mut mempool);
        assert_eq!(evicted, 0, "still-valid tx must not be evicted");
        assert_eq!(mempool.len(), 1);
        assert!(mempool.contains(&tx.txid()));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn evict_invalid_mempool_entries_drops_all_conflicts_in_one_pass() {
        let mut chain = base_chain(None);
        let sender = signing_key(13);
        let pkh = key_hash(&sender);

        // Three separate UTXOs spendable by the same key. add_spendable_p2pkh_utxo
        // uses a fixed prev txid [7u8; 32], so for the other two we insert
        // directly with distinct keys.
        let prev0 = add_spendable_p2pkh_utxo(&mut chain, &sender, 10_000);
        let prev1 = OutPoint {
            txid: [8u8; 32],
            index: 0,
        };
        chain.utxos.insert(
            prev1.clone(),
            UtxoEntry {
                output: TxOutput {
                    value: 10_000,
                    script_pubkey: p2pkh_script(&pkh),
                },
                height: chain.tip_height(),
                is_coinbase: false,
            },
        );
        let prev2 = OutPoint {
            txid: [9u8; 32],
            index: 0,
        };
        chain.utxos.insert(
            prev2.clone(),
            UtxoEntry {
                output: TxOutput {
                    value: 10_000,
                    script_pubkey: p2pkh_script(&pkh),
                },
                height: chain.tip_height(),
                is_coinbase: false,
            },
        );

        let path = fresh_mempool_path("multi_conflict");
        let mut mempool =
            crate::mempool::MempoolManager::new(path.clone(), 100, 0.0, 0);
        for (i, prev) in [&prev0, &prev1, &prev2].iter().enumerate() {
            let tx = build_signed_spend(
                &chain,
                &sender,
                prev,
                5_000 + i as u64, // distinct value -> distinct txid
                [0xcc; 20],
            );
            let raw = tx.serialize();
            mempool
                .add_transaction(tx, raw, 0)
                .expect("admit tx to mempool");
        }
        assert_eq!(mempool.len(), 3);

        // Remove all three UTXOs (a block confirmed conflicting txs for each).
        chain.utxos.remove(&prev0);
        chain.utxos.remove(&prev1);
        chain.utxos.remove(&prev2);

        let evicted =
            crate::mempool::evict_invalid_mempool_entries(&chain, &mut mempool);
        assert_eq!(
            evicted, 3,
            "all three conflicting entries must be evicted in one pass"
        );
        assert_eq!(mempool.len(), 0);

        let _ = std::fs::remove_file(path);
    }
}
