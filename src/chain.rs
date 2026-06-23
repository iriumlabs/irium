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
    BtcHeaderEntry, BtcRelayUpdate, BtcSpvParams, BTC_HEADER_BATCH_TAG, MAX_BTC_HEADER_BATCH_BYTES,
};
use crate::btc_tx_parse::{btc_txid, parse_btc_tx_outputs, BtcOutputScript};
use crate::constants::{
    block_reward, block_target_interval, coinbase_maturity, BLOCK_TARGET_INTERVAL_V1,
    DIFFICULTY_RETARGET_INTERVAL, LWMA_MAX_TARGET_DOWN_FACTOR, LWMA_MAX_TARGET_UP_FACTOR,
    LWMA_MIN_DIFFICULTY_FLOOR, LWMA_SOLVETIME_CLAMP_FACTOR, LWMA_V2_MAX_TARGET_DOWN_FACTOR,
    LWMA_V2_MAX_TARGET_UP_FACTOR, LWMA_V2_SOLVETIME_CLAMP_FACTOR, LWMA_V2_WINDOW, LWMA_WINDOW,
    MAX_FUTURE_BLOCK_TIME, MAX_MONEY, MTP_ACTIVATION_HEIGHT,
};
use crate::genesis::LockedGenesis;
use crate::ltc_spv::{
    apply_ltc_header_batch, parse_ltc_header_batch, undo_ltc_relay_update, LtcAnchor,
    LtcHeaderEntry, LtcRelayUpdate, LtcSpvParams, RetargetParams, LTC_HEADER_BATCH_TAG,
    MAX_LTC_HEADER_BATCH_BYTES,
};
use crate::pow::{meets_target, min_difficulty_target, sha256d, Target};
use crate::tx::{
    compute_funding_binding, decode_hex, encode_htlc_btc_swap_v1_script,
    encode_htlc_ltc_swap_v1_script, encode_htlcv1_script, encode_ltc_swap_order_script,
    encode_mpso_script, encode_swap_order_script, p2pkh_script, parse_htlc_btc_swap_v1_script,
    parse_htlc_btc_swap_witness, parse_htlc_ltc_swap_v1_script, parse_htlc_ltc_swap_witness,
    parse_htlcv1_script, parse_input_witness, parse_ltc_swap_order_script,
    parse_ltc_swap_order_witness, parse_mpso_script, parse_output_encumbrance,
    parse_swap_order_script, parse_swap_order_witness, HtlcBtcSwapV1Output, HtlcBtcSwapWitness,
    HtlcLtcSwapV1Output, HtlcLtcSwapWitness, HtlcV1Output, InputWitness, LtcSwapOrderWitness,
    MpsoV1Output, OutputEncumbrance, SwapOrderWitness, Transaction, TxInput, TxOutput,
    BTC_OP_RETURN_BINDING_LEN, BTC_OP_RETURN_BINDING_MAGIC, HTLC_BTC_SWAP_V1_SCRIPT_LEN,
    HTLC_BTC_SWAP_V1_TAG, HTLC_LTC_SWAP_V1_SCRIPT_LEN, HTLC_LTC_SWAP_V1_TAG, HTLC_V1_SCRIPT_TAG,
    LTC_OP_RETURN_BINDING_LEN, LTC_OP_RETURN_BINDING_MAGIC, LTC_SWAP_ORDER_BUY_SCRIPT_LEN,
    LTC_SWAP_ORDER_DIRECTION_BUY, LTC_SWAP_ORDER_DIRECTION_SELL, LTC_SWAP_ORDER_MAX_SWEEP_FEE,
    LTC_SWAP_ORDER_MIN_LOCKED_VALUE, LTC_SWAP_ORDER_SELL_SCRIPT_LEN, LTC_SWAP_ORDER_V1_TAG,
    MAX_HTLC_BTC_SWAP_CONFIRMATIONS, MAX_HTLC_LTC_SWAP_CONFIRMATIONS,
    MIN_HTLC_BTC_SWAP_CONFIRMATIONS, MIN_HTLC_LTC_SWAP_CONFIRMATIONS, MPSO_V1_MAX_WITNESS_SIZE,
    MPSO_V1_TAG, SWAP_ORDER_BUY_SCRIPT_LEN, SWAP_ORDER_DIRECTION_BUY, SWAP_ORDER_DIRECTION_SELL,
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
    /// Blocks disconnected during a reorg that carried PoAW-X receipts.
    /// Drained by iriumd.rs `submit_block_extended` to restore orphaned
    /// receipts to `poawx_pending_receipts` (Phase 13-C).
    pub reorg_orphaned_blocks: Vec<Block>,
    /// Phase 21C: persistent, reorg-safe anti-domination reward state.
    /// Updated in `connect_block` and reverted in `disconnect_tip_block`
    /// (both gated + mainnet hard-off); deterministically rebuilt by chain
    /// replay on restart / rebuild-style reorg.
    pub dominance: crate::poawx_dominance::PersistentDominance,
    /// Phase 28: PoAW-X finalized checkpoint (testnet/devnet only; stays
    /// `0`/zeros on mainnet, which is hard-off). Highest block height finalized
    /// by a validated finality proof, plus that block's hash. Derived inside
    /// `connect_block` (so cold replay / `rebuild_to_tip` reconstruct it) and
    /// advanced monotonically (never backward). `reorg_to_tip` consults it to
    /// reject any reorg that would disconnect finalized history.
    pub poawx_finalized_height: u64,
    pub poawx_finalized_hash: [u8; 32],
    /// Phase 30: deterministic, replayable double-sign penalty state, derived from
    /// the active chain's block-carried evidence (testnet/devnet only; empty on
    /// mainnet, hard-off). Applied in `connect_block` (effective from the NEXT
    /// block), reconstructed by replay, and rebuilt from the active chain on reorg.
    pub doublesign_penalty: crate::poawx_doublesign::PoawxDoubleSignPenaltyState,
    /// Phase 32: deterministic, replayable on-chain ticket store, derived from the
    /// active chain's block-carried ticket registrations (testnet/devnet only;
    /// empty on mainnet, hard-off). Applied in `connect_block` (effective from the
    /// NEXT block), reconstructed by replay, and rebuilt from the active chain on
    /// reorg.
    pub ticket_store: crate::poawx_ticket::PoawxTicketStore,
    /// Phase 34: deterministic, reorg-safe adaptive-mode state derived ONLY from
    /// chain-derived signals (testnet/devnet only; stays `genesis()`/Normal on
    /// mainnet, hard-off). Advanced in `connect_block` (the post-H mode it stores
    /// governs validation of H+1), reconstructed by cold replay, and rebuilt from
    /// the active chain on reorg. No local-only signal can affect it.
    pub adaptive_state: crate::poawx_adaptive::PoawxAdaptiveState,
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
    if height < crate::block::standard_header_activation_height() {
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
            reorg_orphaned_blocks: Vec::new(),
            dominance: crate::poawx_dominance::PersistentDominance::from_env(),
            poawx_finalized_height: 0,
            poawx_finalized_hash: [0u8; 32],
            doublesign_penalty: crate::poawx_doublesign::PoawxDoubleSignPenaltyState::new(),
            ticket_store: crate::poawx_ticket::PoawxTicketStore::new(),
            adaptive_state: crate::poawx_adaptive::PoawxAdaptiveState::genesis(),
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
        if height > 0
            && matches!(
                std::env::var("IRIUM_NETWORK").as_deref(),
                Ok("devnet") | Ok("regtest")
            )
        {
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
        if height < DIFFICULTY_RETARGET_INTERVAL
            || !height.is_multiple_of(DIFFICULTY_RETARGET_INTERVAL)
        {
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
        if self.chain.len() > 1
            && matches!(
                std::env::var("IRIUM_NETWORK").as_deref(),
                Ok("devnet") | Ok("regtest")
            )
        {
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
        validate_poawx_coinbase(&block, expected_height)?;
        validate_poawx_block_receipts(&block, expected_height, previous)?;
        if crate::poawx_dominance::anti_domination_enforced(expected_height) {
            self.validate_block_dominance_weights(&block, expected_height)?;
        }
        // Phase 33: validate the block-carried dominance-state commitment (testnet-
        // gated; mainnet hard-off). `pre` must equal the current (pre-block) state
        // digest and `post` the digest after applying this block's role rewards
        // (computed without mutating). Non-retroactive + replayable; additive to the
        // existing weight validation (does not change reward amounts or weights).
        if crate::poawx_dominance::dominance_commitment_active(expected_height) {
            self.validate_block_dominance_commitment(&block, expected_height)?;
        }
        if crate::poawx_candidate::candidate_set_enforced(expected_height)
            || crate::poawx_admission::candidate_admission_enforced(expected_height)
        {
            self.validate_block_candidate_sets(&block, expected_height)?;
        }
        if crate::poawx_puzzle::puzzle_work_enforced(expected_height) {
            self.validate_block_puzzle_proofs(&block, expected_height)?;
        }
        // Phase 28: capture the finalized-parent decision here (after the proof
        // is validated, so an invalid proof can never set a checkpoint), but
        // apply it AFTER the block is committed below — `previous` borrows
        // `self.chain` immutably through the committed-admission check.
        let mut finalize_parent: Option<(u64, [u8; 32])> = None;
        if crate::poawx_finality::finality_committee_enforced(expected_height) {
            self.validate_block_finality(&block, expected_height)?;
            // The validated proof finalizes the PARENT block (block_hash =
            // prev_hash at expected_height - 1).
            if expected_height >= 1 {
                finalize_parent = Some((expected_height - 1, block.header.prev_hash));
            }
        }
        if crate::poawx_committed_admission::committed_admission_enforced(expected_height) {
            self.validate_block_committed_admission(&block, previous, expected_height)?;
        }
        if crate::poawx_candidate::true_vrf_enforced(expected_height) {
            self.validate_block_true_vrf(&block, expected_height)?;
        }
        // Phase 30: validate any block-carried double-sign evidence (testnet-gated;
        // mainnet hard-off). Invalid/over-cap/duplicate/non-canonical evidence
        // rejects the block. Capture the validated set to APPLY AFTER commit, so
        // evidence in block H is effective from H+1 (non-retroactive; H's own
        // finality, validated above, is unaffected by H's evidence).
        let pending_double_sign: Vec<crate::poawx_doublesign::PoawxDoubleSignEvidenceV1> =
            if crate::poawx_doublesign::double_sign_penalty_active(expected_height) {
                self.validate_block_double_sign_evidence(&block, expected_height)?
            } else {
                Vec::new()
            };
        // Phase 32: validate any block-carried ticket registrations (testnet-gated;
        // mainnet hard-off). Invalid/over-cap/duplicate/non-canonical/rate-limited
        // registrations reject the block. Captured to APPLY AFTER commit, so a
        // registration in block H is usable from H+1 (non-retroactive).
        let pending_ticket_regs: Vec<crate::poawx_ticket::PoawxTicketRegistrationV1> =
            if crate::poawx_ticket::ticket_store_active(expected_height) {
                self.validate_block_ticket_registrations(&block, expected_height)?
            } else {
                Vec::new()
            };
        // Phase 32 eligibility (ADDITIVE, gated): when enforced, every rewarded
        // role's ticket proof must match an ACTIVE on-chain registered ticket from
        // EARLIER blocks (this block's own registrations are applied only after
        // commit). Strict superset of the existing ticket-proof validation.
        if crate::poawx_ticket::ticket_store_enforced(expected_height) {
            self.validate_block_ticket_store_eligibility(&block, expected_height)?;
        }
        // Phase 34: adaptive-mode consensus integration (testnet-gated; mainnet
        // hard-off). Block H's stricter mode EFFECTS key off the PRE-mode (the mode
        // active for H, = current `self.adaptive_state.mode`, derived from blocks <
        // H) — non-retroactive. The block's ADM1 commitment is validated against the
        // deterministically recomputed pre/post adaptive state; the captured
        // post-state is applied after commit so it governs H+1. Additive: derives
        // ONLY from chain-derived signals, never weakens an existing check.
        let adaptive_post: Option<crate::poawx_adaptive::PoawxAdaptiveState> =
            if crate::poawx_adaptive::adaptive_mode_active(expected_height) {
                self.enforce_adaptive_mode_effects(&block, expected_height)?;
                Some(self.validate_block_adaptive_commitment(&block, expected_height)?)
            } else {
                None
            };

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
        self.apply_block_dominance(expected_height);
        // Phase 28: now that the block is committed, advance the finalized
        // checkpoint monotonically (derived here so cold replay/rebuild
        // reconstruct it). Mainnet stays off (the finality gate is hard-off).
        if let Some((h, fhash)) = finalize_parent {
            self.advance_finalized(h, fhash);
        }
        // Phase 30: apply the validated block-carried double-sign evidence to the
        // deterministic penalty state (effective from the NEXT block). Derived here
        // so cold replay reconstructs it; rebuilt from the active chain on reorg.
        if !pending_double_sign.is_empty() {
            let net = crate::activation::network_id_byte();
            for ev in &pending_double_sign {
                if let Some(committee) = self.committee_pkhs_at(ev.target_height()) {
                    let _ = self.doublesign_penalty.apply_evidence(
                        ev,
                        &committee,
                        net,
                        expected_height,
                        crate::poawx_doublesign::DEFAULT_SUSPEND_EPOCHS,
                    );
                }
            }
        }
        // Phase 32: apply the validated ticket registrations to the on-chain store
        // (effective from the NEXT block), then deterministically prune expired
        // entries. Derived here so cold replay reconstructs it; rebuilt from the
        // active chain on reorg.
        if !pending_ticket_regs.is_empty() {
            for reg in &pending_ticket_regs {
                let _ = self.ticket_store.apply_registration(reg, expected_height);
            }
        }
        if crate::poawx_ticket::ticket_store_active(expected_height) {
            self.ticket_store.prune_expired(expected_height);
        }
        // Phase 34: commit the validated post-H adaptive state (derived here so cold
        // replay reconstructs it; rebuilt from the active chain on reorg). It becomes
        // the PRE-mode for H+1.
        if let Some(post) = adaptive_post {
            self.adaptive_state = post;
        }
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
        self.revert_block_dominance(&tip_block, tip_height);
        Ok(tip_block)
    }

    /// Phase 21C: derive the canonical anti-domination reward events from an
    /// accepted block's Phase 20 receipt extensions. Role amounts come from the
    /// block subsidy via the canonical 55/22/13/10 split, so official fee-0 and
    /// third-party-fee blocks produce IDENTICAL role amounts. The PRIMARY credit
    /// goes to the receipt `worker_pkh` (the payout identity); the fee output and
    /// the delegate are NOT credited as worker rewards (they are not role
    /// allocations). Deterministic across nodes (no env, no ordering effects
    /// beyond receipt order).
    fn dominance_events_from_block(
        block: &Block,
        height: u64,
    ) -> Vec<([u8; 20], crate::poawx_dominance::RoleRewardKind, u64)> {
        use crate::poawx_dominance::RoleRewardKind;
        let mut events = Vec::new();
        let receipts = match &block.poawx_receipts {
            Some(r) => r,
            None => return events,
        };
        for r in receipts {
            let ext = match &r.phase20_ext {
                Some(e) => e,
                None => continue,
            };
            let amts = crate::poawx::multi_role_amounts(block_reward(height));
            events.push((r.worker_pkh, RoleRewardKind::Primary, amts[0]));
            events.push((
                ext.role_reward.compute_contributor_pkh,
                RoleRewardKind::Compute,
                amts[1],
            ));
            events.push((
                ext.role_reward.verify_contributor_pkh,
                RoleRewardKind::Verify,
                amts[2],
            ));
            events.push((
                ext.role_reward.support_contributor_pkh,
                RoleRewardKind::Support,
                amts[3],
            ));
        }
        events
    }

    /// Phase 21H: when finality-committee enforcement is on, every production
    /// receipt must carry a finality proof finalizing the PARENT block
    /// (block_hash = the block's prev_hash). The committee is the SUPPORT-role
    /// candidates in the candidate set; the proof must use the node-authoritative
    /// threshold and meet it with valid committee Commit votes. The SUPPORT/
    /// finality 10% reward therefore stands only with a valid finality proof.
    /// Fails closed. The Phase 21F FinalityWorkPlaceholder puzzle alone is NOT
    /// sufficient when finality is required (the full committee proof is required).
    fn validate_block_finality(&self, block: &Block, height: u64) -> Result<(), String> {
        use crate::poawx::ROLE_SUPPORT_CONTRIBUTOR;
        use crate::poawx_finality::finality_threshold;
        let net = crate::activation::network_id_byte();
        let receipts = match &block.poawx_receipts {
            Some(r) => r,
            None => return Ok(()),
        };
        let (num, den) = finality_threshold();
        for r in receipts {
            let ext = match &r.phase20_ext {
                Some(e) => e,
                None => continue,
            };
            let fp = ext
                .finality_proof
                .as_ref()
                .ok_or_else(|| "phase21h: missing required finality proof".to_string())?;
            let cs = ext.candidate_set.as_ref().ok_or_else(|| {
                "phase21h: finality enforcement requires candidate set".to_string()
            })?;
            let committee: Vec<[u8; 20]> = cs
                .candidates
                .iter()
                .filter(|c| c.role_id == ROLE_SUPPORT_CONTRIBUTOR)
                .map(|c| c.solver_pkh)
                .collect();
            if fp.threshold_num != num || fp.threshold_den != den {
                return Err("phase21h: finality threshold mismatch".to_string());
            }
            fp.validate(net, height, &block.header.prev_hash, &committee)?;
            // Phase 30: exclude penalized signers. A finality vote by an identity
            // that is currently suspended (per the deterministic penalty state from
            // EARLIER blocks — this block's own evidence is applied only after
            // commit) makes the block invalid. Testnet-gated; mainnet hard-off.
            if crate::poawx_doublesign::double_sign_penalty_active(height) {
                for v in &fp.votes {
                    if !self
                        .doublesign_penalty
                        .is_eligible_for_finality(&v.member_pkh, fp.committee_epoch)
                    {
                        return Err("phase30: penalized signer in finality committee".to_string());
                    }
                }
            }
        }
        Ok(())
    }

    /// Phase 30: SUPPORT-committee member pkhs at `height` (from the on-chain
    /// block's candidate set). Deterministic + replayable (every node has the same
    /// chain). Returns None if the height/candidate-set is unavailable.
    fn committee_pkhs_at(&self, height: u64) -> Option<Vec<[u8; 20]>> {
        use crate::poawx::ROLE_SUPPORT_CONTRIBUTOR;
        let block = self.chain.get(height as usize)?;
        let receipts = block.poawx_receipts.as_ref()?;
        let mut pkhs: Vec<[u8; 20]> = Vec::new();
        for r in receipts {
            if let Some(ext) = &r.phase20_ext {
                if let Some(cs) = &ext.candidate_set {
                    for c in &cs.candidates {
                        if c.role_id == ROLE_SUPPORT_CONTRIBUTOR {
                            pkhs.push(c.solver_pkh);
                        }
                    }
                }
            }
        }
        if pkhs.is_empty() {
            None
        } else {
            Some(pkhs)
        }
    }

    /// Phase 30: collect + validate the block-carried double-sign evidence. Returns
    /// the validated, canonically-ordered, deduped evidence (to apply after commit).
    /// Rejects: over-cap, in-block duplicate id, non-canonical order, future/unknown
    /// offense height, or any evidence failing `validate` (bad sig / wrong network /
    /// non-committee / not equivocation). Committee is derived from the on-chain
    /// offense block (deterministic + replayable).
    fn validate_block_double_sign_evidence(
        &self,
        block: &Block,
        height: u64,
    ) -> Result<Vec<crate::poawx_doublesign::PoawxDoubleSignEvidenceV1>, String> {
        let net = crate::activation::network_id_byte();
        let mut collected: Vec<crate::poawx_doublesign::PoawxDoubleSignEvidenceV1> = Vec::new();
        if let Some(receipts) = &block.poawx_receipts {
            for r in receipts {
                if let Some(ext) = &r.phase20_ext {
                    if let Some(evs) = &ext.double_sign_evidence {
                        collected.extend(evs.iter().cloned());
                    }
                }
            }
        }
        if collected.is_empty() {
            return Ok(collected);
        }
        if collected.len() > crate::poawx_doublesign::MAX_DOUBLE_SIGN_EVIDENCE_PER_BLOCK {
            return Err("phase30: too many double-sign evidence entries".to_string());
        }
        // Canonical order (strictly increasing evidence id) + no in-block duplicates.
        let mut prev_id: Option<[u8; 32]> = None;
        for ev in &collected {
            let id = ev.evidence_id();
            match prev_id {
                Some(p) if id <= p => {
                    return Err(
                        "phase30: double-sign evidence not canonically ordered/deduped".to_string(),
                    )
                }
                _ => {}
            }
            prev_id = Some(id);
        }
        // Validate each against the committee derived from the on-chain offense block.
        for ev in &collected {
            let th = ev.target_height();
            if th >= height {
                return Err("phase30: evidence offense height not in the past".to_string());
            }
            let committee = self.committee_pkhs_at(th).ok_or_else(|| {
                "phase30: cannot derive committee for evidence height".to_string()
            })?;
            ev.validate(net, &committee)
                .map_err(|e| format!("phase30: invalid block-carried evidence: {e}"))?;
        }
        Ok(collected)
    }

    /// Phase 30: rebuild the double-sign penalty state from the ACTIVE chain's
    /// block-carried evidence (used after a successful reorg so abandoned-fork
    /// evidence never pollutes the active chain). Deterministic.
    fn rebuild_doublesign_penalty_from_chain(&mut self) {
        let net = crate::activation::network_id_byte();
        // Phase 1 (immutable): collect (evidence, committee, apply_height).
        let mut to_apply: Vec<(
            crate::poawx_doublesign::PoawxDoubleSignEvidenceV1,
            Vec<[u8; 20]>,
            u64,
        )> = Vec::new();
        for h in 1..self.chain.len() as u64 {
            if !crate::poawx_doublesign::double_sign_penalty_active(h) {
                continue;
            }
            let evs: Vec<crate::poawx_doublesign::PoawxDoubleSignEvidenceV1> = {
                let mut v = Vec::new();
                if let Some(receipts) = &self.chain[h as usize].poawx_receipts {
                    for r in receipts {
                        if let Some(ext) = &r.phase20_ext {
                            if let Some(e) = &ext.double_sign_evidence {
                                v.extend(e.iter().cloned());
                            }
                        }
                    }
                }
                v
            };
            for ev in evs {
                if let Some(committee) = self.committee_pkhs_at(ev.target_height()) {
                    to_apply.push((ev, committee, h));
                }
            }
        }
        // Phase 2 (mutable): rebuild fresh state.
        let mut st = crate::poawx_doublesign::PoawxDoubleSignPenaltyState::new();
        for (ev, committee, h) in to_apply {
            let _ = st.apply_evidence(
                &ev,
                &committee,
                net,
                h,
                crate::poawx_doublesign::DEFAULT_SUSPEND_EPOCHS,
            );
        }
        self.doublesign_penalty = st;
    }

    /// Phase 32: collect + validate block-carried ticket registrations. Returns the
    /// validated, canonically-ordered, deduped registrations (to apply after commit).
    /// Rejects: over-cap, in-block duplicate id, non-canonical order, or any
    /// registration failing `validate` (bad sybil / wrong network / expired /
    /// future / malformed). Reuses the existing `MinerWorkTicket` validator.
    fn validate_block_ticket_registrations(
        &self,
        block: &Block,
        height: u64,
    ) -> Result<Vec<crate::poawx_ticket::PoawxTicketRegistrationV1>, String> {
        let net = crate::activation::network_id_byte();
        let require_bits = crate::poawx_ticket::sybil_threshold_bits();
        let mut collected: Vec<crate::poawx_ticket::PoawxTicketRegistrationV1> = Vec::new();
        if let Some(receipts) = &block.poawx_receipts {
            for r in receipts {
                if let Some(ext) = &r.phase20_ext {
                    if let Some(regs) = &ext.ticket_registrations {
                        collected.extend(regs.iter().cloned());
                    }
                }
            }
        }
        if collected.is_empty() {
            return Ok(collected);
        }
        if collected.len() > crate::poawx_ticket::MAX_TICKET_REGISTRATIONS_PER_BLOCK {
            return Err("phase32: too many ticket registrations".to_string());
        }
        // Canonical order (strictly increasing ticket id) + no in-block duplicates.
        let mut prev_id: Option<[u8; 32]> = None;
        for reg in &collected {
            let id = reg.ticket_id();
            match prev_id {
                Some(p) if id <= p => {
                    return Err(
                        "phase32: ticket registrations not canonically ordered/deduped".to_string(),
                    )
                }
                _ => {}
            }
            prev_id = Some(id);
        }
        // Each registration must be individually valid (reuses ticket validation).
        for reg in &collected {
            reg.validate(net, height, require_bits)?;
        }
        Ok(collected)
    }

    /// Phase 32 (additive): when ticket-store enforcement is ON, every rewarded
    /// role's ticket proof must correspond to an ACTIVE on-chain registered ticket
    /// (matching miner/epoch/assignment-key, not expired). Strict superset of the
    /// existing `validate_phase20_ticket_proofs`.
    fn validate_block_ticket_store_eligibility(
        &self,
        block: &Block,
        height: u64,
    ) -> Result<(), String> {
        let receipts = match &block.poawx_receipts {
            Some(r) => r,
            None => return Ok(()),
        };
        for r in receipts {
            let ext = match &r.phase20_ext {
                Some(e) => e,
                None => continue,
            };
            let proofs = match &ext.role_ticket_proofs {
                Some(p) => p,
                None => {
                    return Err(
                        "phase32: ticket-store enforced but role ticket proofs missing".to_string(),
                    )
                }
            };
            for p in proofs.iter() {
                if !self.ticket_store.has_active(
                    &p.miner_pkh,
                    p.epoch,
                    &p.assignment_public_key,
                    height,
                ) {
                    return Err("phase32: role ticket not registered on-chain".to_string());
                }
            }
        }
        Ok(())
    }

    /// Phase 32: rebuild the on-chain ticket store from the ACTIVE chain's
    /// block-carried registrations (used after a successful reorg so abandoned-fork
    /// registrations never pollute the active chain). Deterministic.
    fn rebuild_ticket_store_from_chain(&mut self) {
        // Phase 1 (immutable): collect (registration, applied_height) in order.
        let mut to_apply: Vec<(crate::poawx_ticket::PoawxTicketRegistrationV1, u64)> = Vec::new();
        for h in 1..self.chain.len() as u64 {
            if !crate::poawx_ticket::ticket_store_active(h) {
                continue;
            }
            if let Some(receipts) = &self.chain[h as usize].poawx_receipts {
                for r in receipts {
                    if let Some(ext) = &r.phase20_ext {
                        if let Some(regs) = &ext.ticket_registrations {
                            for reg in regs {
                                to_apply.push((reg.clone(), h));
                            }
                        }
                    }
                }
            }
        }
        // Phase 2 (mutable): rebuild fresh store in chain order, then prune at tip.
        let mut store = crate::poawx_ticket::PoawxTicketStore::new();
        for (reg, h) in to_apply {
            let _ = store.apply_registration(&reg, h);
        }
        let tip = self.tip_height();
        store.prune_expired(tip);
        self.ticket_store = store;
    }

    // ── Phase 34: adaptive-mode consensus integration ──────────────────────────

    /// Dominance state AFTER applying block H's role rewards, WITHOUT mutating
    /// self (mirrors `compute_post_dominance_digest`). Used so the adaptive
    /// concentration/participation signals reflect the state "after H".
    fn dominance_after_block(
        &self,
        block: &Block,
        height: u64,
    ) -> crate::poawx_dominance::PersistentDominance {
        let mut clone = self.dominance.clone();
        for (pkh, kind, amount) in Self::dominance_events_from_block(block, height) {
            clone.apply_event(pkh, kind, amount, height);
        }
        clone
    }

    /// Derive the STRICTLY chain-derived adaptive signals for the transition at
    /// `height`, from `dominance_after` (dominance state after applying block H's
    /// role rewards) and a bounded scan of the recent committed blocks. `block_h`
    /// is block H when it is not yet in `self.chain` (connect-time); pass `None`
    /// during a from-chain rebuild (block H already in `self.chain`). NO local-only
    /// signal is read here — local observations cannot affect the consensus mode.
    fn adaptive_chain_signals(
        &self,
        dominance_after: &crate::poawx_dominance::PersistentDominance,
        height: u64,
        block_h: Option<&Block>,
    ) -> crate::poawx_adaptive::PoawxAdaptiveChainSignals {
        use crate::poawx_adaptive::ADAPTIVE_RECENT_WINDOW;
        let concentration = dominance_after.max_recent_reward_share_permille(height);
        let participation = dominance_after.distinct_recent_miners(height);
        let start = height
            .saturating_sub(ADAPTIVE_RECENT_WINDOW.saturating_sub(1))
            .max(1);
        let mut registered_ticket_count: u32 = 0;
        let mut double_sign_evidence_count: u32 = 0;
        let mut finality_available = false;
        for h in start..=height {
            let blk: Option<&Block> = if h == height {
                block_h.or_else(|| self.chain.get(h as usize))
            } else {
                self.chain.get(h as usize)
            };
            let blk = match blk {
                Some(b) => b,
                None => continue,
            };
            if let Some(receipts) = &blk.poawx_receipts {
                for r in receipts {
                    if let Some(ext) = &r.phase20_ext {
                        if let Some(regs) = &ext.ticket_registrations {
                            registered_ticket_count =
                                registered_ticket_count.saturating_add(regs.len() as u32);
                        }
                        if let Some(evs) = &ext.double_sign_evidence {
                            double_sign_evidence_count =
                                double_sign_evidence_count.saturating_add(evs.len() as u32);
                        }
                        if ext.finality_proof.is_some() {
                            finality_available = true;
                        }
                    }
                }
            }
        }
        crate::poawx_adaptive::PoawxAdaptiveChainSignals {
            dominance_concentration_permille: concentration,
            active_role_participation: participation,
            registered_ticket_count,
            double_sign_evidence_count,
            finality_available,
        }
    }

    /// Compute (pre_state, post_state, signals) for the adaptive transition at H
    /// during connect (block H not yet in self.chain). pre = `self.adaptive_state`
    /// (derived from blocks < H); post = pre.next(signals incl. H).
    fn adaptive_transition_for_block(
        &self,
        block: &Block,
        height: u64,
    ) -> (
        crate::poawx_adaptive::PoawxAdaptiveState,
        crate::poawx_adaptive::PoawxAdaptiveState,
        crate::poawx_adaptive::PoawxAdaptiveChainSignals,
    ) {
        let pre = self.adaptive_state;
        let dom_after = self.dominance_after_block(block, height);
        let signals = self.adaptive_chain_signals(&dom_after, height, Some(block));
        let post = pre.next(&signals);
        (pre, post, signals)
    }

    /// Phase 34: validate the block-carried ADM1 adaptive-mode commitment. The
    /// modes/digests must match the deterministically recomputed pre (blocks < H)
    /// and post (including H) adaptive state. When enforcement is required and NO
    /// commitment is present, the block is rejected. Returns the post-state to
    /// apply after commit.
    fn validate_block_adaptive_commitment(
        &self,
        block: &Block,
        height: u64,
    ) -> Result<crate::poawx_adaptive::PoawxAdaptiveState, String> {
        let net = crate::activation::network_id_byte();
        let (pre, post, signals) = self.adaptive_transition_for_block(block, height);
        let mut seen = false;
        if let Some(receipts) = &block.poawx_receipts {
            for r in receipts {
                if let Some(ext) = &r.phase20_ext {
                    if let Some(amc) = &ext.adaptive_mode_commitment {
                        seen = true;
                        amc.validate(net, height, &pre, &post, &signals)
                            .map_err(|e| format!("phase34: {:?}", e))?;
                    }
                }
            }
        }
        if !seen && crate::poawx_adaptive::adaptive_commitment_enforced(height) {
            return Err("phase34: adaptive mode commitment required but missing".to_string());
        }
        Ok(post)
    }

    fn block_has_dominance_commitment(block: &Block) -> bool {
        block.poawx_receipts.as_ref().is_some_and(|rs| {
            rs.iter().any(|r| {
                r.phase20_ext
                    .as_ref()
                    .is_some_and(|e| e.dominance_commitment.is_some())
            })
        })
    }
    fn block_has_committed_admission(block: &Block) -> bool {
        block.poawx_receipts.as_ref().is_some_and(|rs| {
            rs.iter().any(|r| {
                r.phase20_ext
                    .as_ref()
                    .is_some_and(|e| e.committed_admission.is_some())
            })
        })
    }

    /// Phase 34: additive, mode-driven validation effects for block H under
    /// `pre_mode` (the mode active FOR H, = `self.adaptive_state.mode`, derived from
    /// blocks < H). Effects only ADD strictness and only when the relevant
    /// underlying gate is ACTIVE (so they never fabricate enforcement). They never
    /// touch PoW/LWMA/reward/mainnet, and never relax an existing check.
    fn enforce_adaptive_mode_effects(&self, block: &Block, height: u64) -> Result<(), String> {
        use crate::poawx_adaptive::AdaptiveMode;
        let mode = self.adaptive_state.mode; // pre-mode for H
        if mode == AdaptiveMode::Normal {
            return Ok(());
        }
        let caution_plus = matches!(
            mode,
            AdaptiveMode::Caution | AdaptiveMode::Defense | AdaptiveMode::Recovery
        );
        let defense_plus = matches!(mode, AdaptiveMode::Defense | AdaptiveMode::Recovery);
        if caution_plus {
            if crate::poawx_dominance::dominance_commitment_active(height)
                && !Self::block_has_dominance_commitment(block)
            {
                return Err(format!(
                    "phase34: {:?} mode requires dominance commitment",
                    mode
                ));
            }
            if crate::poawx_ticket::ticket_store_active(height) {
                self.validate_block_ticket_store_eligibility(block, height)?;
            }
        }
        if defense_plus {
            if crate::poawx_committed_admission::committed_admission_active(height)
                && !Self::block_has_committed_admission(block)
            {
                return Err(format!(
                    "phase34: {:?} mode requires committed admission",
                    mode
                ));
            }
            // The existing finality validator already requires a valid proof AND
            // rejects suspended/penalized signers (Phase 30) — exactly the Defense
            // "reject finality proofs containing suspended signers" requirement.
            if crate::poawx_finality::finality_committee_active(height) {
                self.validate_block_finality(block, height)?;
            }
        }
        Ok(())
    }

    /// Phase 34: rebuild adaptive state from the ACTIVE chain by a fresh
    /// deterministic replay (reconstructing dominance with `from_env()` so the
    /// concentration signal matches connect-time exactly). Used after a reorg so
    /// abandoned-fork modes never pollute the active chain. Shares the signal
    /// helper with connect so the two paths cannot diverge.
    fn rebuild_adaptive_state_from_chain(&mut self) {
        let mut state = crate::poawx_adaptive::PoawxAdaptiveState::genesis();
        let mut dom = crate::poawx_dominance::PersistentDominance::from_env();
        for h in 1..self.chain.len() as u64 {
            for (pkh, kind, amount) in Self::dominance_events_from_block(&self.chain[h as usize], h)
            {
                dom.apply_event(pkh, kind, amount, h);
            }
            if crate::poawx_adaptive::adaptive_mode_active(h) {
                let signals = self.adaptive_chain_signals(&dom, h, None);
                state = state.next(&signals);
            }
        }
        self.adaptive_state = state;
    }

    /// Phase 21F: when puzzle-work enforcement is on, every production receipt
    /// must carry per-role `role_puzzle_proofs` whose solution verifies against
    /// the node-recomputed challenge for that role's selected candidate. The
    /// challenge binds (network, height, role, solver, ticket digest, assignment
    /// proof digest, candidate digest, parent seed); the mode is assigned
    /// deterministically. Requires the candidate set (the per-role challenge is
    /// derived from the selected candidate). Assigned-work proofs only -- this
    /// NEVER affects chain PoW / LWMA. Fails closed.
    fn validate_block_puzzle_proofs(&self, block: &Block, height: u64) -> Result<(), String> {
        use crate::poawx::{
            ROLE_COMPUTE_CONTRIBUTOR, ROLE_SUPPORT_CONTRIBUTOR, ROLE_VERIFY_CONTRIBUTOR,
        };
        use crate::poawx_puzzle::{default_profile, verify_solution, PuzzleChallengeV1};
        use sha2::{Digest, Sha256};
        let net = crate::activation::network_id_byte();
        let receipts = match &block.poawx_receipts {
            Some(r) => r,
            None => return Ok(()),
        };
        let profile = default_profile();
        for r in receipts {
            let ext = match &r.phase20_ext {
                Some(e) => e,
                None => continue,
            };
            let sols = ext
                .role_puzzle_proofs
                .as_ref()
                .ok_or_else(|| "phase21f: missing required puzzle proofs".to_string())?;
            let cs = ext
                .candidate_set
                .as_ref()
                .ok_or_else(|| "phase21f: puzzle enforcement requires candidate set".to_string())?;
            let roles = [
                ROLE_COMPUTE_CONTRIBUTOR,
                ROLE_VERIFY_CONTRIBUTOR,
                ROLE_SUPPORT_CONTRIBUTOR,
            ];
            for (i, role) in roles.iter().enumerate() {
                let cand = cs
                    .best_for_role(*role)
                    .ok_or_else(|| format!("phase21f: no candidate for role {}", role))?;
                let candidate_digest: [u8; 32] = {
                    let mut h = Sha256::new();
                    h.update(cand.serialize());
                    h.finalize().into()
                };
                let challenge = PuzzleChallengeV1::build(
                    net,
                    height,
                    *role,
                    cand.solver_pkh,
                    cand.ticket_digest,
                    cand.assignment_proof_digest,
                    candidate_digest,
                    block.header.prev_hash,
                    profile,
                );
                if let crate::poawx_puzzle::PuzzleVerificationResult::Invalid(e) =
                    verify_solution(&challenge, &sols[i])
                {
                    return Err(format!(
                        "phase21f: puzzle proof role {} invalid: {}",
                        role, e
                    ));
                }
            }
        }
        Ok(())
    }

    /// Phase 21D: when candidate-set enforcement is on, every production
    /// receipt must include a canonical `CandidateSet` bound to (network,
    /// height, parent seed); each candidate must be self-consistent (recomputed
    /// assignment-proof digest + penalty weight + effective score); its
    /// `dominance_weight` must match the node's persisted state when dominance is
    /// active; and the SELECTED role solver (`role_reward`) must be the BEST
    /// candidate for that role under the deterministic effective-score ordering.
    /// Fails closed on missing/malformed/non-best.
    ///
    /// HONEST LIMITATION: the node can only validate the INCLUDED candidate set;
    /// it cannot prove unseen miners did not exist (no mandatory candidate
    /// admission / gossip rule yet). Best-within-included-set, NOT global best.
    /// Phase 22A: chain-committed candidate admission. When enforced, the
    /// admitted candidate-set root for height H must have been committed in the
    /// PARENT block (commit_height = H-1, freeze seed = parent's prev_hash =
    /// grandparent hash, known when the parent was produced -> no circularity),
    /// and block H's candidate set must reproduce that exact committed root
    /// (root + count + seed). The producer of H therefore cannot add/omit
    /// candidates vs the H-1 commitment. Also validates this block's OWN
    /// commitment (for H+1) is self-consistent. Reorg-safe: the commitment is
    /// block data (parent ext), so it is replayed/reverted with the chain. At
    /// the activation height a one-block grace allows a pre-gate parent. Fails
    /// closed otherwise. Does NOT prove offline/never-gossiped miners existed.
    fn validate_block_committed_admission(
        &self,
        block: &Block,
        previous: Option<&Block>,
        height: u64,
    ) -> Result<(), String> {
        use crate::poawx_committed_admission::{
            committed_admission_activation_height, AdmissionCommitmentV1,
        };
        let net = crate::activation::network_id_byte();
        let receipts = match &block.poawx_receipts {
            Some(r) => r,
            None => return Ok(()),
        };
        // (1) Outgoing: if this block carries a commitment (for H+1), it must be
        // self-consistent: target = H+1, commit_height = H, freeze seed = this
        // block's prev_hash.
        for r in receipts {
            if let Some(ext) = &r.phase20_ext {
                if let Some(ca) = &ext.committed_admission {
                    ca.validate(net, height + 1)?;
                    if ca.commit_height != height {
                        return Err("phase22a: own commitment wrong commit height".to_string());
                    }
                    if ca.seed != block.header.prev_hash {
                        return Err("phase22a: own commitment wrong freeze seed".to_string());
                    }
                }
            }
        }
        // (2) Incoming: H's candidate set must match the parent's committed root
        // for target H.
        let is_activation =
            matches!(committed_admission_activation_height(), Some(a) if a == height);
        let parent_commit: Option<AdmissionCommitmentV1> = previous.and_then(|p| {
            p.poawx_receipts.as_ref().and_then(|rs| {
                rs.iter().find_map(|r| {
                    r.phase20_ext
                        .as_ref()
                        .and_then(|e| e.committed_admission.clone())
                        .filter(|ca| ca.target_height == height)
                })
            })
        });
        match parent_commit {
            Some(pc) => {
                pc.validate(net, height)?;
                if let Some(prev) = previous {
                    if pc.seed != prev.header.prev_hash {
                        return Err(
                            "phase22a: parent commitment seed != grandparent hash".to_string()
                        );
                    }
                }
                for r in receipts {
                    let ext = match &r.phase20_ext {
                        Some(e) => e,
                        None => continue,
                    };
                    let cs = ext.candidate_set.as_ref().ok_or_else(|| {
                        "phase22a: committed admission requires a candidate set".to_string()
                    })?;
                    if !pc.matches_candidate_set(cs) {
                        return Err(
                            "phase22a: candidate set does not match committed admission root"
                                .to_string(),
                        );
                    }
                }
            }
            None => {
                if !is_activation {
                    return Err(
                        "phase22a: missing parent committed admission for height".to_string()
                    );
                }
                // activation-height grace: the parent predates the gate.
            }
        }
        Ok(())
    }

    /// Phase 22D: when the true-VRF gate is enforced, every production receipt
    /// must carry per-role AssignmentProofV2 (real secp256k1 RFC 9381 ECVRF) for
    /// the SELECTED candidates -- the V1 placeholder is NOT accepted. Each V2
    /// proof is VRF-verified and bound to its role's selected candidate (role,
    /// solver, ticket digest, assignment public key, candidate-set seed), and the
    /// candidate's assignment_proof_digest must equal the V2 VRF output (so the
    /// effective score derives from the VRF output). Fails closed.
    fn validate_block_true_vrf(&self, block: &Block, height: u64) -> Result<(), String> {
        use crate::poawx::{
            ROLE_COMPUTE_CONTRIBUTOR, ROLE_SUPPORT_CONTRIBUTOR, ROLE_VERIFY_CONTRIBUTOR,
        };
        let net = crate::activation::network_id_byte();
        let receipts = match &block.poawx_receipts {
            Some(r) => r,
            None => return Ok(()),
        };
        for r in receipts {
            let ext = match &r.phase20_ext {
                Some(e) => e,
                None => continue,
            };
            let proofs = ext.role_assignment_v2.as_ref().ok_or_else(|| {
                "phase22d: missing required V2 assignment proofs (V1 not accepted)".to_string()
            })?;
            let cs = ext
                .candidate_set
                .as_ref()
                .ok_or_else(|| "phase22d: true-VRF requires a candidate set".to_string())?;
            let roles = [
                (
                    0usize,
                    ROLE_COMPUTE_CONTRIBUTOR,
                    ext.role_reward.compute_contributor_pkh,
                ),
                (
                    1usize,
                    ROLE_VERIFY_CONTRIBUTOR,
                    ext.role_reward.verify_contributor_pkh,
                ),
                (
                    2usize,
                    ROLE_SUPPORT_CONTRIBUTOR,
                    ext.role_reward.support_contributor_pkh,
                ),
            ];
            for (i, role, sel) in roles {
                let cand = cs
                    .best_for_role(role)
                    .ok_or_else(|| format!("phase22d: no candidate for role {}", role))?;
                if cand.solver_pkh != sel {
                    return Err(format!(
                        "phase22d: role {} selected != best candidate",
                        role
                    ));
                }
                let pr = &proofs[i];
                pr.validate(net, height)?;
                if pr.role_id != role {
                    return Err("phase22d: v2 proof wrong role".to_string());
                }
                if pr.solver_pkh != cand.solver_pkh {
                    return Err("phase22d: v2 proof wrong solver".to_string());
                }
                if pr.ticket_digest != cand.ticket_digest {
                    return Err("phase22d: v2 proof wrong ticket digest".to_string());
                }
                if pr.assignment_public_key != cand.assignment_public_key {
                    return Err("phase22d: v2 proof wrong assignment key".to_string());
                }
                if pr.seed != cs.seed {
                    return Err("phase22d: v2 proof wrong seed".to_string());
                }
                if pr.vrf_output != cand.assignment_proof_digest {
                    return Err("phase22d: candidate score not derived from VRF output".to_string());
                }
            }
        }
        Ok(())
    }

    fn validate_block_candidate_sets(&self, block: &Block, height: u64) -> Result<(), String> {
        use crate::poawx::{
            ROLE_COMPUTE_CONTRIBUTOR, ROLE_SUPPORT_CONTRIBUTOR, ROLE_VERIFY_CONTRIBUTOR,
        };
        use crate::poawx_dominance::{anti_domination_active, DOMINANCE_BASE_WORK_SCORE};
        let net = crate::activation::network_id_byte();
        let receipts = match &block.poawx_receipts {
            Some(r) => r,
            None => return Ok(()),
        };
        // Phase 26B: the candidate set / admissions for height H are frozen one
        // block ahead by the parent's committed admission, whose freeze seed is the
        // parent block's prev_hash (the grandparent hash). So the candidate-set seed
        // for H is that EPOCH seed, NOT the immediate prev_hash; at the activation
        // boundary (genesis parent, whose prev_hash is all-zero) it falls back to
        // this block's prev_hash. The parent is the current tip (this block is not
        // yet pushed). This reconciles phase21d with phase22a without weakening
        // either gate. `prev_hash`-bound gates (puzzle/finality/claims) are unchanged.
        let epoch_seed = crate::poawx_committed_admission::admission_epoch_seed(
            self.chain.last().map(|p| p.header.prev_hash),
            block.header.prev_hash,
        );
        let dom_active = anti_domination_active(height);
        for r in receipts {
            let ext = match &r.phase20_ext {
                Some(e) => e,
                None => continue,
            };
            let cs = ext
                .candidate_set
                .as_ref()
                .ok_or_else(|| "phase21d: missing required candidate set".to_string())?;
            if cs.network_id != net {
                return Err("phase21d: candidate set wrong network".to_string());
            }
            if cs.target_height != height {
                return Err("phase21d: candidate set wrong height".to_string());
            }
            if cs.seed != epoch_seed {
                return Err("phase21d: candidate set wrong seed".to_string());
            }
            if !cs.is_canonical() {
                return Err("phase21d: candidate set not canonical".to_string());
            }
            for cand in &cs.candidates {
                // Phase 22E: under the true-VRF gate the candidate digest is the VRF
                // output (verified via the AVR2 section), so check scoring only;
                // otherwise recompute the V1 placeholder digest.
                if crate::poawx_candidate::true_vrf_active(height) {
                    cand.validate_scoring()?;
                } else {
                    cand.validate_self(net, height, &cs.seed)?;
                }
                if dom_active {
                    let expect =
                        self.dominance
                            .weight(DOMINANCE_BASE_WORK_SCORE, &cand.solver_pkh, height);
                    if cand.dominance_weight != expect {
                        return Err(format!(
                            "phase21d: candidate dominance weight mismatch got {} expected {}",
                            cand.dominance_weight, expect
                        ));
                    }
                }
            }
            let selected = [
                (
                    ROLE_COMPUTE_CONTRIBUTOR,
                    ext.role_reward.compute_contributor_pkh,
                ),
                (
                    ROLE_VERIFY_CONTRIBUTOR,
                    ext.role_reward.verify_contributor_pkh,
                ),
                (
                    ROLE_SUPPORT_CONTRIBUTOR,
                    ext.role_reward.support_contributor_pkh,
                ),
            ];
            for (role_id, sel) in selected {
                let best = cs
                    .best_for_role(role_id)
                    .ok_or_else(|| format!("phase21d: no candidate for role {}", role_id))?;
                if best.solver_pkh != sel {
                    return Err(format!(
                        "phase21d: selected role {} solver is not the best candidate",
                        role_id
                    ));
                }
            }
            // Phase 21E: when admission is enforced, the included set must EQUAL
            // the node's admitted candidates for this height/seed (missing or
            // extra candidate => mismatch => reject). Fail closed when a selected
            // role has no admitted candidate. HONEST: best among candidates
            // admitted to THIS node in the window, not among unseen offline miners.
            if crate::poawx_admission::candidate_admission_enforced(height) {
                let cache = crate::poawx_admission::global_admission_cache();
                let admitted = cache.admitted_candidate_set(net, height, &epoch_seed);
                if cs.serialize() != admitted.serialize() {
                    return Err(
                        "phase21e: candidate set does not match admitted candidates".to_string()
                    );
                }
                for (role_id, _) in selected {
                    if admitted.best_for_role(role_id).is_none() {
                        return Err(format!(
                            "phase21e: no admitted candidate for role {}",
                            role_id
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Phase 21C: when anti-domination enforcement is on, every production
    /// receipt must carry `role_dominance_weights` whose 4 entries equal the
    /// node-recomputed fairness weights for [PRIMARY, COMPUTE, VERIFY, SUPPORT]
    /// from the PERSISTED dominance state. This block is validated BEFORE it is
    /// applied, so the persisted state is exactly the parent state the producer
    /// used. Fails closed on missing/mismatched weights. The weight is a
    /// per-claim quantity (a deterministic baseline scaled by the miner recent
    /// reward share); proving the producer also selected the GLOBALLY
    /// best-weighted worker among all (possibly unseen) candidates is Phase 21D
    /// (candidate-set / VRF), documented as pending.
    fn validate_block_dominance_weights(&self, block: &Block, height: u64) -> Result<(), String> {
        use crate::poawx_dominance::DOMINANCE_BASE_WORK_SCORE;
        let receipts = match &block.poawx_receipts {
            Some(r) => r,
            None => return Ok(()),
        };
        for r in receipts {
            let ext = match &r.phase20_ext {
                Some(e) => e,
                None => continue,
            };
            let weights = ext
                .role_dominance_weights
                .ok_or_else(|| "phase21c: missing required role_dominance_weights".to_string())?;
            let pkhs = [
                r.worker_pkh,
                ext.role_reward.compute_contributor_pkh,
                ext.role_reward.verify_contributor_pkh,
                ext.role_reward.support_contributor_pkh,
            ];
            for (i, pkh) in pkhs.iter().enumerate() {
                let expected = self
                    .dominance
                    .weight(DOMINANCE_BASE_WORK_SCORE, pkh, height);
                if weights[i] != expected {
                    return Err(format!(
                        "phase21c: dominance weight mismatch role {} got {} expected {}",
                        i, weights[i], expected
                    ));
                }
            }
        }
        Ok(())
    }

    /// Apply the accepted tip block's reward events to the dominance state.
    /// No-op unless `anti_domination_active(height)` (mainnet hard-off, default
    /// off, so existing behavior is unchanged when the gate is off).
    /// Phase 33: the dominance-state digest AFTER applying `block`'s role rewards,
    /// computed WITHOUT mutating self (clone + apply, exactly mirroring
    /// `apply_block_dominance`, incl. internal pruning). When anti-domination is
    /// inactive the state does not change, so post == current digest.
    fn compute_post_dominance_digest(&self, block: &Block, height: u64) -> [u8; 32] {
        if !crate::poawx_dominance::anti_domination_active(height) {
            return self.dominance.digest();
        }
        let mut clone = self.dominance.clone();
        for (pkh, kind, amount) in Self::dominance_events_from_block(block, height) {
            clone.apply_event(pkh, kind, amount, height);
        }
        clone.digest()
    }

    /// Phase 33: validate every DMC1 dominance commitment carried in `block`. `pre`
    /// must equal the current (pre-block) state digest; `post` the digest after
    /// applying this block's role rewards. Rejects on mismatch / wrong meta. When
    /// enforcement is required and NO commitment is present, the block is rejected.
    fn validate_block_dominance_commitment(
        &self,
        block: &Block,
        height: u64,
    ) -> Result<(), String> {
        let net = crate::activation::network_id_byte();
        let pre = self.dominance.digest();
        let post = self.compute_post_dominance_digest(block, height);
        let mut seen = false;
        if let Some(receipts) = &block.poawx_receipts {
            for r in receipts {
                if let Some(ext) = &r.phase20_ext {
                    if let Some(dc) = &ext.dominance_commitment {
                        seen = true;
                        dc.validate(net, height, &pre, &post)
                            .map_err(|e| format!("phase33: {:?}", e))?;
                    }
                }
            }
        }
        if !seen && crate::poawx_dominance::dominance_commitment_enforced(height) {
            return Err("phase33: dominance commitment required but missing".to_string());
        }
        Ok(())
    }

    fn apply_block_dominance(&mut self, height: u64) {
        if !crate::poawx_dominance::anti_domination_active(height) {
            return;
        }
        let events = match self.chain.last() {
            Some(b) => Self::dominance_events_from_block(b, height),
            None => return,
        };
        for (pkh, kind, amount) in events {
            self.dominance.apply_event(pkh, kind, amount, height);
        }
    }

    /// Reverse the reward events of a disconnected tip block — the EXACT inverse
    /// of `apply_block_dominance` for that block. Gated identically.
    fn revert_block_dominance(&mut self, block: &Block, height: u64) {
        if !crate::poawx_dominance::anti_domination_active(height) {
            return;
        }
        for (pkh, kind, amount) in Self::dominance_events_from_block(block, height) {
            self.dominance.revert_event(pkh, kind, amount, height);
        }
    }

    /// Phase 28: monotonically advance the PoAW-X finalized checkpoint. Only
    /// moves forward (never backward, rule 4); called from `connect_block` after
    /// a finality proof has been validated, so an invalid proof can never set a
    /// checkpoint. No-op on mainnet (finality is hard-off there, so this is never
    /// reached with a real height).
    fn advance_finalized(&mut self, height: u64, hash: [u8; 32]) {
        if height > self.poawx_finalized_height {
            self.poawx_finalized_height = height;
            self.poawx_finalized_hash = hash;
        }
    }

    /// Phase 28: pure decision — does a reorg whose common-ancestor (fork) height
    /// is `ancestor_height` disconnect the finalized checkpoint at
    /// `finalized_height`? A reorg removes every block above the fork point, so a
    /// finalized block at height F is removed iff the fork point is below F. No
    /// checkpoint (`finalized_height == 0`) ⇒ never a violation (existing reorg
    /// behavior, including all of mainnet, is unchanged).
    fn reorg_violates_finalized(finalized_height: u64, ancestor_height: u64) -> bool {
        finalized_height > 0 && ancestor_height < finalized_height
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

        // Phase 28: reject a reorg that would disconnect a finalized checkpoint.
        // A reorg removes every block above `ancestor_height`; a finalized block
        // at height F is removed iff `ancestor_height < F`. Deterministic and
        // consensus-level (returns Err, blocking the reorg before any disconnect).
        // No-op when no checkpoint exists (`poawx_finalized_height == 0`, which
        // includes all of mainnet, where finality is hard-off). Even a
        // higher-work / longer fork is rejected here.
        if Self::reorg_violates_finalized(self.poawx_finalized_height, ancestor_height) {
            return Err(format!(
                "phase28: reorg would disconnect finalized checkpoint at height {}",
                self.poawx_finalized_height
            ));
        }
        // Snapshot finalized state so a mid-reorg failure (which reconnects the
        // old branch) can restore it; new-branch `connect_block` calls below may
        // advance it, and the monotonic setter would otherwise leave it stuck.
        let finalized_snapshot = (self.poawx_finalized_height, self.poawx_finalized_hash);
        // Phase 30: snapshot the double-sign penalty state so a failed reorg can
        // restore it exactly. On success it is REBUILT from the new active chain
        // (below) so abandoned-fork evidence never pollutes the active chain.
        let doublesign_snapshot = self.doublesign_penalty.clone();
        // Phase 32: snapshot the on-chain ticket store so a failed reorg can restore
        // it exactly; on success it is REBUILT from the new active chain (below).
        let ticket_store_snapshot = self.ticket_store.clone();
        // Phase 34: snapshot the adaptive state so a failed reorg can restore it
        // exactly; on success it is REBUILT from the new active chain (below).
        let adaptive_snapshot = self.adaptive_state;

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
        // Phase 34: now that the chain is back at the common ancestor (dominance was
        // reverted per disconnected block), rebuild the adaptive state to the
        // ancestor so the new-branch connect loop below validates each block's ADM1
        // commitment against the correct pre-state. Deterministic + chain-only.
        self.rebuild_adaptive_state_from_chain();

        let mut connected_new: Vec<Block> = Vec::new();
        for block in &new_branch {
            if let Err(e) = self.connect_block(block.clone()) {
                for _ in 0..connected_new.len() {
                    let _ = self.disconnect_tip_block();
                }
                for old in disconnected.iter().rev() {
                    let _ = self.connect_block(old.clone());
                }
                // Phase 28: restore the pre-reorg finalized checkpoint (partial
                // new-branch connects above may have advanced it past the now-
                // restored old chain).
                self.poawx_finalized_height = finalized_snapshot.0;
                self.poawx_finalized_hash = finalized_snapshot.1;
                // Phase 30: restore the pre-reorg double-sign penalty state.
                self.doublesign_penalty = doublesign_snapshot;
                // Phase 32: restore the pre-reorg ticket store.
                self.ticket_store = ticket_store_snapshot;
                // Phase 34: restore the pre-reorg adaptive state.
                self.adaptive_state = adaptive_snapshot;
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
        // Phase 30: rebuild the double-sign penalty state from the NEW active chain
        // so evidence carried only on the abandoned fork no longer applies, and the
        // new chain's evidence is fully reflected. (`doublesign_snapshot` is dropped
        // on this success path.)
        let _ = &doublesign_snapshot;
        self.rebuild_doublesign_penalty_from_chain();
        // Phase 32: rebuild the on-chain ticket store from the new active chain so
        // abandoned-fork registrations never apply. (`ticket_store_snapshot` is
        // dropped on this success path.)
        let _ = &ticket_store_snapshot;
        self.rebuild_ticket_store_from_chain();
        // Phase 34: rebuild the adaptive state from the new active chain so
        // abandoned-fork modes never apply. (`adaptive_snapshot` is dropped on this
        // success path.)
        let _ = &adaptive_snapshot;
        self.rebuild_adaptive_state_from_chain();
        // Phase 13-C: stash blocks with PoAW-X receipts for iriumd.rs to restore
        self.reorg_orphaned_blocks
            .extend(disconnected.into_iter().filter(|b| {
                b.poawx_receipts
                    .as_ref()
                    .map(|r| !r.is_empty())
                    .unwrap_or(false)
            }));
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
        let auxpow_active = self
            .params
            .auxpow_activation_height
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
            self.chain
                .last()
                .map(|b| b.header.hash_for_height(tip_height)),
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
            if hw.work > self.total_work && best.as_ref().map(|b| b.work < hw.work).unwrap_or(true)
            {
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
        let auxpow_active = self
            .params
            .auxpow_activation_height
            .map(|ah| height >= ah)
            .unwrap_or(false);
        if block.header.version & crate::auxpow::AUXPOW_VERSION_BIT != 0 && auxpow_active {
            let header_bytes = block.header.serialize_for_height(height);
            let ap = block
                .auxpow
                .as_ref()
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
                        return Err("BtcHeaderBatch output before SPV relay activation".to_string());
                    }
                    btc_batch_count += 1;
                    if btc_batch_count > 1 {
                        return Err(
                            "block contains more than one BtcHeaderBatch output".to_string()
                        );
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
                        return Err("LtcHeaderBatch output before SPV relay activation".to_string());
                    }
                    ltc_batch_count += 1;
                    if ltc_batch_count > 1 {
                        return Err(
                            "block contains more than one LtcHeaderBatch output".to_string()
                        );
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
                    return Err("coinbase BtcHeaderBatch before SPV relay activation".to_string());
                }
                if output.value != 0 {
                    return Err("coinbase BtcHeaderBatch output must have value=0".to_string());
                }
                coinbase_btc_batch_count += 1;
                if coinbase_btc_batch_count > 1 {
                    return Err("coinbase contains more than one BtcHeaderBatch output".to_string());
                }
                if btc_relay_update.is_some() {
                    return Err(
                        "block contains both coinbase and regular-tx BtcHeaderBatch".to_string()
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
                    return Err("coinbase LtcHeaderBatch before SPV relay activation".to_string());
                }
                if output.value != 0 {
                    return Err("coinbase LtcHeaderBatch output must have value=0".to_string());
                }
                coinbase_ltc_batch_count += 1;
                if coinbase_ltc_batch_count > 1 {
                    return Err("coinbase contains more than one LtcHeaderBatch output".to_string());
                }
                if ltc_relay_update.is_some() {
                    return Err(
                        "block contains both coinbase and regular-tx LtcHeaderBatch".to_string()
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
            reorg_orphaned_blocks: Vec::new(),
            dominance: crate::poawx_dominance::PersistentDominance::from_env(),
            poawx_finalized_height: 0,
            poawx_finalized_hash: [0u8; 32],
            doublesign_penalty: crate::poawx_doublesign::PoawxDoubleSignPenaltyState::new(),
            ticket_store: crate::poawx_ticket::PoawxTicketStore::new(),
            adaptive_state: crate::poawx_adaptive::PoawxAdaptiveState::genesis(),
        };

        let branch = self.gather_branch_to_genesis(tip_hash)?;
        if branch.is_empty() {
            return Err("empty branch".to_string());
        }
        let genesis = &branch[0];
        new_state.connect_genesis(genesis.clone())?;
        let mut cumulative = ChainState::block_work(genesis);
        let genesis_hash = genesis.header.hash_for_height(0);
        new_state.block_store.insert(genesis_hash, genesis.clone());
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

        let auxpow_active = self
            .params
            .auxpow_activation_height
            .map(|ah| block_height >= ah)
            .unwrap_or(false);
        if block.header.version & crate::auxpow::AUXPOW_VERSION_BIT != 0 && auxpow_active {
            let header_bytes = block.header.serialize_for_height(block_height);
            let ap = block
                .auxpow
                .as_ref()
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

fn validate_poawx_coinbase(block: &Block, height: u64) -> Result<(), String> {
    let act_h = match std::env::var("IRIUM_POAWX_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        Some(h) => h,
        None => return Ok(()),
    };
    if !std::env::var("IRIUM_POAWX_MODE")
        .map(|v| v.trim() == "active")
        .unwrap_or(false)
    {
        return Ok(());
    }
    if crate::activation::network_kind_from_env() == crate::activation::NetworkKind::Mainnet {
        return Ok(());
    }
    if height < act_h {
        return Ok(());
    }
    if !crate::poawx::block_has_irx1_commitment(block) {
        return Err(format!(
            "connect_block: poawx irx1 commitment missing at height {} (active from {})",
            height, act_h
        ));
    }
    Ok(())
}

/// Reads IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS. Semantics match iriumd.rs.
fn poawx_block_difficulty_bits() -> u32 {
    const DEFAULT: u32 = 8;
    const MAX: u32 = 24;
    match std::env::var("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS")
        .ok()
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        None => DEFAULT,
        Some(v) => match v.parse::<u32>() {
            Ok(n) => n.min(MAX),
            Err(_) => 0,
        },
    }
}

/// Phase 18B: true when mode-1 (delegated) PoAW-X receipts are active for
/// `height`. Mainnet always returns false (mode-1 hard-off). Testnet/devnet
/// gate on `IRIUM_POAWX_DELEGATION_ACTIVATION_HEIGHT`.
fn poawx_delegation_active(height: u64) -> bool {
    if crate::activation::network_kind_from_env() == crate::activation::NetworkKind::Mainnet {
        return false;
    }
    match crate::activation::poawx_delegation_activation_height() {
        Some(h) => height >= h,
        None => false,
    }
}

/// Phase 20: true when the multi-role reward split is active for `height`.
/// **Mainnet always returns false** (multi-role split hard-off until an explicit
/// future governance activation). Testnet/devnet gate on
/// `IRIUM_POAWX_MULTI_ROLE_REWARD_ACTIVATION_HEIGHT`. Before activation the
/// existing reward behavior (10%/receipt to worker) is unchanged.
pub fn multi_role_reward_active(height: u64) -> bool {
    if crate::activation::network_kind_from_env() == crate::activation::NetworkKind::Mainnet {
        return false;
    }
    match crate::activation::poawx_multi_role_reward_activation_height() {
        Some(h) => height >= h,
        None => false,
    }
}

/// Phase 20: true when the CPU/GPU/ASIC fairness matrix primitives are active for
/// `height`. **Mainnet always returns false** (hard-off until explicit future
/// governance activation). Testnet/devnet gate on
/// `IRIUM_POAWX_FAIRNESS_MATRIX_ACTIVATION_HEIGHT`. Gates *use* of the fairness
/// assignment/role-claim primitives by future role-claim validation; does not
/// change chain difficulty (LWMA-144) or existing block validation.
pub fn fairness_matrix_active(height: u64) -> bool {
    if crate::activation::network_kind_from_env() == crate::activation::NetworkKind::Mainnet {
        return false;
    }
    match crate::activation::poawx_fairness_matrix_activation_height() {
        Some(h) => height >= h,
        None => false,
    }
}

/// Phase 20: whether the third-party pool fee is active for `height`. **Mainnet
/// always false** (hard-off until explicit future governance activation).
/// Testnet/devnet gate on `IRIUM_POAWX_THIRD_PARTY_FEE_ACTIVATION_HEIGHT`.
pub fn third_party_fee_active(height: u64) -> bool {
    if crate::activation::network_kind_from_env() == crate::activation::NetworkKind::Mainnet {
        return false;
    }
    match crate::activation::poawx_third_party_fee_activation_height() {
        Some(h) => height >= h,
        None => false,
    }
}

/// Phase 20: whether explicit third-party pool mode is enabled
/// (`IRIUM_POAWX_THIRD_PARTY_POOL_MODE=1`). **Mainnet always false.** This is the
/// runtime opt-in required (in addition to the activation height) before any
/// nonzero fee is permitted; official pools leave it unset (fee stays 0%).
pub fn third_party_pool_mode_enabled() -> bool {
    if crate::activation::network_kind_from_env() == crate::activation::NetworkKind::Mainnet {
        return false;
    }
    std::env::var("IRIUM_POAWX_THIRD_PARTY_POOL_MODE")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}

/// Phase 20 Step 6A: whether the hidden role-precommit commitment root is active
/// for `height`. **Mainnet always false.** Testnet/devnet gate on
/// `IRIUM_POAWX_HIDDEN_PRECOMMIT_ACTIVATION_HEIGHT`. When active, every Phase 20
/// production block must carry a `precommit_root` (committing the next block's
/// role-claim leaves) and its role claims must reveal pre-committed leaves matching
/// the parent block's `precommit_root` (one transition-block grace at the exact
/// activation height, whose parent predates activation).
pub fn hidden_precommit_active(height: u64) -> bool {
    if crate::activation::network_kind_from_env() == crate::activation::NetworkKind::Mainnet {
        return false;
    }
    match crate::activation::poawx_hidden_precommit_activation_height() {
        Some(h) => height >= h,
        None => false,
    }
}

/// Phase 20: parse a standard 25-byte P2PKH script `76 a9 14 <20> 88 ac` to its pkh.
fn parse_p2pkh_pkh(script: &[u8]) -> Option<[u8; 20]> {
    if script.len() == 25
        && script[0] == 0x76
        && script[1] == 0xa9
        && script[2] == 0x14
        && script[23] == 0x88
        && script[24] == 0xac
    {
        let mut pkh = [0u8; 20];
        pkh.copy_from_slice(&script[3..23]);
        Some(pkh)
    } else {
        None
    }
}

/// Phase 20: validate the canonical multi-role coinbase outputs (pure; no env).
///
/// After the multi-role activation height a PoAW-X mode-1 coinbase must pay
/// exactly the four canonical role outputs in fixed order
/// `[PRIMARY, COMPUTE, VERIFY, SUPPORT]` with the exact `multi_role_amounts`
/// split of `total_reward`. Zero-value non-P2PKH outputs (e.g. the `irx1`
/// OP_RETURN) are allowed and ignored; any value-bearing non-P2PKH output
/// (a hidden fee) or any extra/mis-ordered/wrong-amount P2PKH output rejects.
/// `primary_pkh` MUST be the receipt `worker_pkh` (caller enforces). Duplicate
/// role pkhs are kept as separate outputs (no aggregation).
fn validate_multi_role_coinbase_outputs(
    outputs: &[crate::tx::TxOutput],
    primary_pkh: &[u8; 20],
    role: &crate::poawx::RoleReward,
    total_reward: u64,
) -> Result<(), String> {
    let amts = crate::poawx::multi_role_amounts(total_reward);
    let expected: [([u8; 20], u64); 4] = [
        (*primary_pkh, amts[0]),
        (role.compute_contributor_pkh, amts[1]),
        (role.verify_contributor_pkh, amts[2]),
        (role.support_contributor_pkh, amts[3]),
    ];
    let mut p2pkh: Vec<([u8; 20], u64)> = Vec::new();
    for out in outputs {
        match parse_p2pkh_pkh(&out.script_pubkey) {
            Some(pkh) => p2pkh.push((pkh, out.value)),
            None => {
                if out.value != 0 {
                    return Err(
                        "multi-role coinbase: value-bearing non-p2pkh output (hidden fee?)"
                            .to_string(),
                    );
                }
            }
        }
    }
    if p2pkh.len() != 4 {
        return Err(format!(
            "multi-role coinbase: expected exactly 4 role outputs, found {}",
            p2pkh.len()
        ));
    }
    for (i, (epkh, eval)) in expected.iter().enumerate() {
        if &p2pkh[i].0 != epkh {
            return Err(format!(
                "multi-role coinbase: role index {} pkh/order mismatch",
                i
            ));
        }
        if p2pkh[i].1 != *eval {
            return Err(format!(
                "multi-role coinbase: role index {} amount {} != expected {}",
                i, p2pkh[i].1, eval
            ));
        }
    }
    // Defensive: split must total the allowed reward exactly (guaranteed by
    // multi_role_amounts, re-checked so a future change cannot silently over/underpay).
    let sum: u64 = amts.iter().sum();
    if sum != total_reward {
        return Err(format!(
            "multi-role coinbase: split sum {} != total reward {}",
            sum, total_reward
        ));
    }
    Ok(())
}

/// Phase 20: comprehensive canonical PoAW-X coinbase payout validator (pure; no env).
/// Handles all four canonical formats — official/third-party-fee × no-multi-role/multi-role:
/// - `role = None`  => single PRIMARY/miner payout; `role = Some` => 4-role split.
/// - `fee = None` (official) => no fee output allowed; `fee = Some((bps, fee_pkh))`
///   (third-party) => when `bps > 0`, a fee output is appended LAST. The fee is taken
///   ONLY from the PRIMARY allocation (`fee = floor(primary_gross * bps / 10000)`,
///   miner keeps the remainder); compute/verify/support are never taxed.
///
/// Canonical P2PKH output order (zero-value `irx1` OP_RETURN allowed and ignored):
///   PRIMARY(net) [, COMPUTE, VERIFY, SUPPORT if multi-role] [, FEE if bps>0].
/// Rejects: wrong count/order/amount, value-bearing non-p2pkh (hidden fee), a fee
/// output in official mode, and any over/underpay. Callers gate by activation/mode
/// and verify `fee_pkh`/`fee_bps` against the signed delegation. Exposed `pub`
/// for the stratum pool's Step 3 parity dev-tests (see validate_phase20_production_payout).
pub fn validate_poawx_coinbase_payout(
    outputs: &[crate::tx::TxOutput],
    primary_pkh: &[u8; 20],
    total_reward: u64,
    role: Option<&crate::poawx::RoleReward>,
    fee: Option<(u16, [u8; 20])>,
) -> Result<(), String> {
    // PRIMARY gross + the (untaxed) role outputs.
    let (primary_gross, role_outs): (u64, Vec<([u8; 20], u64)>) = match role {
        Some(r) => {
            let a = crate::poawx::multi_role_amounts(total_reward);
            (
                a[0],
                vec![
                    (r.compute_contributor_pkh, a[1]),
                    (r.verify_contributor_pkh, a[2]),
                    (r.support_contributor_pkh, a[3]),
                ],
            )
        }
        None => (total_reward, Vec::new()),
    };
    // Fee from PRIMARY only.
    let (primary_net, fee_out): (u64, Option<([u8; 20], u64)>) = match fee {
        Some((bps, fpkh)) if bps > 0 => {
            let (net, f) = crate::poawx::apply_fee(primary_gross, bps);
            (net, Some((fpkh, f)))
        }
        _ => (primary_gross, None),
    };
    // Build expected outputs in canonical order.
    let mut expected: Vec<([u8; 20], u64)> = Vec::with_capacity(6);
    expected.push((*primary_pkh, primary_net));
    expected.extend(role_outs);
    if let Some(fo) = fee_out {
        expected.push(fo);
    }
    // Collect actual p2pkh outputs; reject value-bearing non-p2pkh (hidden fee).
    let mut p2pkh: Vec<([u8; 20], u64)> = Vec::new();
    for out in outputs {
        match parse_p2pkh_pkh(&out.script_pubkey) {
            Some(pkh) => p2pkh.push((pkh, out.value)),
            None => {
                if out.value != 0 {
                    return Err(
                        "poawx coinbase: value-bearing non-p2pkh output (hidden fee?)".to_string(),
                    );
                }
            }
        }
    }
    if p2pkh.len() != expected.len() {
        return Err(format!(
            "poawx coinbase: expected {} payout outputs, found {}",
            expected.len(),
            p2pkh.len()
        ));
    }
    for (i, (epkh, eval)) in expected.iter().enumerate() {
        if &p2pkh[i].0 != epkh {
            return Err(format!("poawx coinbase: output {} pkh/order mismatch", i));
        }
        if p2pkh[i].1 != *eval {
            return Err(format!(
                "poawx coinbase: output {} amount {} != expected {}",
                i, p2pkh[i].1, eval
            ));
        }
    }
    let sum: u64 = expected.iter().map(|(_, v)| *v).sum();
    if sum != total_reward {
        return Err(format!(
            "poawx coinbase: payout sum {} != total reward {}",
            sum, total_reward
        ));
    }
    Ok(())
}

/// Phase 20 production gate: both multi-role reward split AND the fairness matrix
/// are active for `height` (third-party fee is layered separately). Mainnet always
/// false (both sub-gates are mainnet-hard-off).
pub fn phase20_production_active(height: u64) -> bool {
    multi_role_reward_active(height) && fairness_matrix_active(height)
}

/// Phase 20 INTEGRATED production-block validator (the connect_block entry point
/// once the receipt extension is threaded through the node wire). Pure given the
/// supplied `ext`; reads only the runtime `third_party_mode` flag for fee policy.
///
/// Validates, in order:
///   1. each role claim (compute/verify/support) against the deterministic fairness
///      assignment (slot 0 per role) — wrong role/lane/height/prev/digest reject;
///   2. that the RoleReward payout pkhs equal the validated claim solver pkhs;
///   3. the fee terms (cap/mode/pkh) via `validate_fee_terms`;
///   4. the canonical fee-aware multi-role coinbase via `validate_poawx_coinbase_payout`.
///
/// Callers gate by `phase20_production_active(height)` (mainnet-off) before calling.
/// Exposed `pub` so the stratum pool's dev-tests can validate a pool-produced
/// Phase 20 fixture against the authoritative node validator (Step 3 parity).
#[allow(clippy::too_many_arguments)]
pub fn validate_phase20_production_payout(
    coinbase_outputs: &[crate::tx::TxOutput],
    primary_pkh: &[u8; 20],
    total_reward: u64,
    height: u64,
    prev_hash: &[u8; 32],
    network_id: u8,
    ext: &crate::poawx::Phase20ReceiptExt,
    third_party_mode: bool,
) -> Result<(), String> {
    use crate::poawx::{
        validate_fee_terms, validate_role_claim, ROLE_COMPUTE_CONTRIBUTOR,
        ROLE_SUPPORT_CONTRIBUTOR, ROLE_VERIFY_CONTRIBUTOR,
    };
    // 1. each role claim must carry its expected role and validate against fairness.
    //    Distinct expected role_ids also reject a duplicate claim for the same role.
    let claims = [
        (ROLE_COMPUTE_CONTRIBUTOR, &ext.compute_claim),
        (ROLE_VERIFY_CONTRIBUTOR, &ext.verify_claim),
        (ROLE_SUPPORT_CONTRIBUTOR, &ext.support_claim),
    ];
    for (expected_role, claim) in claims.iter() {
        if claim.role_id != *expected_role {
            return Err(format!(
                "phase20: claim role_id {} != expected {}",
                claim.role_id, expected_role
            ));
        }
        validate_role_claim(claim, network_id, height, prev_hash, 0)?;
    }
    // 2. RoleReward pkhs must equal the validated claim solver pkhs.
    if ext.role_reward.compute_contributor_pkh != ext.compute_claim.solver_pkh
        || ext.role_reward.verify_contributor_pkh != ext.verify_claim.solver_pkh
        || ext.role_reward.support_contributor_pkh != ext.support_claim.solver_pkh
    {
        return Err("phase20: RoleReward pkh does not match validated role claim".to_string());
    }
    // 3. fee terms (official => fee_bps 0; third-party => mode + cap + pkh).
    validate_fee_terms(ext.fee_bps, &ext.fee_pkh, third_party_mode)?;
    let fee = if ext.fee_bps > 0 {
        Some((ext.fee_bps, ext.fee_pkh))
    } else {
        None
    };
    // 4. canonical fee-aware multi-role coinbase.
    validate_poawx_coinbase_payout(
        coinbase_outputs,
        primary_pkh,
        total_reward,
        Some(&ext.role_reward),
        fee,
    )
}

/// Phase 20 connect_block enforcement entry: validate each block-contained PoAW-X
/// receipt's production extension against the canonical fee-aware multi-role
/// coinbase. Called from `validate_poawx_block_receipts` only when
/// `phase20_production_active(height)` (which is mainnet-hard-off). Fails closed if
/// any receipt is missing its extension. The payout PRIMARY is the receipt
/// `worker_pkh` (the miner payout identity), and `total_reward` is the block
/// subsidy: the supported single-miner producer builds a coinbase-only block (no
/// fee-bearing txs), so the subsidy is the full distributable amount. `prev_hash`
/// is the parent block hash used by the deterministic fairness assignment.
fn validate_phase20_production_block(
    block: &Block,
    receipts: &[crate::poawx::PoawxBlockReceipt],
    height: u64,
    prev_hash: &[u8; 32],
    previous: Option<&Block>,
) -> Result<(), String> {
    let coinbase = block
        .transactions
        .first()
        .ok_or_else(|| "phase20: no coinbase for production payout check".to_string())?;
    let total_reward = block_reward(height);
    let network_id = crate::activation::network_id_byte();
    // Third-party fee is permitted ONLY when both the fee activation height is
    // reached AND explicit third-party pool mode is enabled (both mainnet-off).
    // Otherwise `third_party_mode == false` and any nonzero fee fails closed via
    // `validate_fee_terms` inside the production validator.
    let third_party_mode = third_party_fee_active(height) && third_party_pool_mode_enabled();
    for (i, r) in receipts.iter().enumerate() {
        let ext = r.phase20_ext.as_ref().ok_or_else(|| {
            format!(
                "phase20: production active but receipt[{}] missing extension at height {}",
                i, height
            )
        })?;
        // Bind the coinbase fee to the miner-signed delegation: when the receipt
        // is delegated (mode-1), the extension fee terms MUST equal the signed
        // delegation fee terms, so a pool cannot pay itself a fee the miner did
        // not sign. (Mode-0 has no delegation to bind; its ext fee is still gated
        // + capped by validate_phase20_production_payout below.)
        if let Some(d) = &r.delegation {
            if ext.fee_bps != d.fee_bps || ext.fee_pkh != d.fee_pkh {
                return Err(format!(
                    "phase20: receipt[{}] extension fee terms != signed delegation fee terms at height {}",
                    i, height
                ));
            }
        }
        validate_phase20_production_payout(
            &coinbase.outputs,
            &r.worker_pkh,
            total_reward,
            height,
            prev_hash,
            network_id,
            ext,
            third_party_mode,
        )?;
        // Phase 31 (ADDITIVE, gated, mainnet hard-off, off by default): re-derive
        // the reward manifest and assert role caps + non-inflation as defense-in-
        // depth. A strict SUPERSET of the exact-match payout check above (derives
        // from the same `multi_role_amounts`), so it can only add named rejections,
        // never weaken or false-reject a block that already passed.
        if crate::poawx_reward::reward_manifest_caps_enforced(height) {
            let manifest = crate::poawx_reward::PoawxRewardManifestV1::new_full(
                network_id,
                height,
                total_reward,
                r.worker_pkh,
                ext.role_reward.compute_contributor_pkh,
                ext.role_reward.verify_contributor_pkh,
                ext.role_reward.support_contributor_pkh,
                ext.fee_bps,
                ext.fee_pkh,
            );
            // The PoAW-X multi-role split is over the subsidy (`total_reward ==
            // block_reward(height)`); fees are bounded separately by the general
            // coinbase-value check. Declared total must not exceed subsidy.
            manifest
                .validate_caps(network_id, total_reward, 0)
                .map_err(|e| e.to_string())?;
        }
    }
    // Step 6A: hidden role-precommit commitment-root enforcement (gated; mainnet-off).
    if hidden_precommit_active(height) {
        validate_hidden_precommit(receipts, height, network_id, previous)?;
    }
    // Phase 21B: ticket + penalty enforcement (gated; mainnet-off). When the ticket
    // gate is ENFORCED (active + required), every rewarded role must carry a valid
    // ticket proof bound to the role solver pkh; when penalty enforcement is on,
    // suspended/slashed identities are blocked from high-trust roles. When the gate
    // is off, the ext's optional ticket proofs are ignored (old behavior unchanged).
    if crate::poawx_ticket::tickets_enforced(height) {
        validate_phase20_ticket_proofs(receipts, height, network_id)?;
    }
    Ok(())
}

/// Phase 21B: validate per-role ticket proofs carried in each receipt's Phase 20
/// extension. Gated by `poawx_ticket::tickets_enforced(height)` (mainnet-off) before
/// being called. Fails closed if the extension or its ticket proofs are missing.
fn validate_phase20_ticket_proofs(
    receipts: &[crate::poawx::PoawxBlockReceipt],
    height: u64,
    network_id: u8,
) -> Result<(), String> {
    let require_sybil = crate::poawx_ticket::sybil_threshold_bits();
    let penalty_enforced = crate::poawx_penalty::penalty_state_enforced(height);
    for (i, r) in receipts.iter().enumerate() {
        let ext = r.phase20_ext.as_ref().ok_or_else(|| {
            format!(
                "phase20: ticket gate active but receipt[{}] missing extension at height {}",
                i, height
            )
        })?;
        let proofs = ext.role_ticket_proofs.as_ref().ok_or_else(|| {
            format!(
                "phase20: ticket gate active but receipt[{}] missing ticket proofs at height {}",
                i, height
            )
        })?;
        let roles = [
            (
                crate::poawx::ROLE_COMPUTE_CONTRIBUTOR,
                ext.role_reward.compute_contributor_pkh,
            ),
            (
                crate::poawx::ROLE_VERIFY_CONTRIBUTOR,
                ext.role_reward.verify_contributor_pkh,
            ),
            (
                crate::poawx::ROLE_SUPPORT_CONTRIBUTOR,
                ext.role_reward.support_contributor_pkh,
            ),
        ];
        for (j, (role_id, solver)) in roles.iter().enumerate() {
            proofs[j]
                .validate(
                    network_id,
                    height,
                    *role_id,
                    solver,
                    require_sybil,
                    penalty_enforced,
                )
                .map_err(|e| {
                    format!(
                        "phase20: receipt[{}] role {} ticket proof invalid: {}",
                        i, role_id, e
                    )
                })?;
        }
    }
    Ok(())
}

/// Phase 20 Step 6A: enforce the hidden role-precommit commitment root. Each block
/// after activation MUST carry a `precommit_root` (committing the NEXT block's
/// role-claim leaves), and each revealed role claim must reconstruct a leaf whose
/// sorted root equals the PARENT block's committed `precommit_root`. One transition
/// grace at the exact activation height (its parent predates activation).
fn validate_hidden_precommit(
    receipts: &[crate::poawx::PoawxBlockReceipt],
    height: u64,
    network_id: u8,
    previous: Option<&Block>,
) -> Result<(), String> {
    let act_h = crate::activation::poawx_hidden_precommit_activation_height()
        .ok_or_else(|| "hidden precommit: active but no activation height".to_string())?;
    // Reconstruct this block's role-claim leaves (validating each commitment) and
    // require every receipt to carry a precommit_root for the next height.
    let mut leaves: Vec<[u8; 32]> = Vec::new();
    for (i, r) in receipts.iter().enumerate() {
        let ext = r.phase20_ext.as_ref().ok_or_else(|| {
            format!(
                "hidden precommit: receipt[{}] missing extension at height {}",
                i, height
            )
        })?;
        if ext.precommit_root.is_none() {
            return Err(format!(
                "hidden precommit: receipt[{}] missing precommit_root for next height at {}",
                i, height
            ));
        }
        for claim in [&ext.compute_claim, &ext.verify_claim, &ext.support_claim] {
            leaves.push(crate::poawx::role_precommit_leaf_for_claim(
                claim, network_id, height,
            )?);
        }
    }
    let computed_root = crate::poawx::role_precommit_root(&leaves);
    // Grace: the single transition block at the activation height has a parent that
    // predates activation (no committed root), so the parent-root match is skipped.
    if height == act_h {
        return Ok(());
    }
    let parent = previous.ok_or_else(|| {
        format!(
            "hidden precommit: no parent block to load committed root at height {}",
            height
        )
    })?;
    let parent_root = parent
        .poawx_receipts
        .as_ref()
        .and_then(|v| v.first())
        .and_then(|r| r.phase20_ext.as_ref())
        .and_then(|e| e.precommit_root)
        .ok_or_else(|| {
            format!(
                "hidden precommit: parent block has no precommit_root at height {}",
                height
            )
        })?;
    if computed_root != parent_root {
        return Err(format!(
            "hidden precommit: role-claim leaves root {} != parent committed root {} at height {}",
            hex::encode(computed_root),
            hex::encode(parent_root),
            height
        ));
    }
    Ok(())
}

fn validate_poawx_reward_split_from_block(
    block: &Block,
    receipts: &[crate::poawx::PoawxBlockReceipt],
    height: u64,
) -> Result<(), String> {
    if receipts.is_empty() {
        return Ok(());
    }
    let coinbase = block
        .transactions
        .first()
        .ok_or_else(|| "connect_block: no coinbase for reward split check".to_string())?;
    let base_reward = block_reward(height);
    let worker_due = base_reward * crate::poawx::POAWX_WORKER_REWARD_PERMILLE / 1000;
    let mut worker_counts: std::collections::HashMap<[u8; 20], u64> = Default::default();
    for r in receipts {
        *worker_counts.entry(r.worker_pkh).or_insert(0) += 1;
    }
    for (pkh, count) in &worker_counts {
        let expected_script = p2pkh_script(pkh);
        let total_paid: u64 = coinbase
            .outputs
            .iter()
            .filter(|out| out.script_pubkey == expected_script)
            .map(|out| out.value)
            .sum();
        let required = worker_due.saturating_mul(*count);
        if total_paid < required {
            return Err(format!(
                "connect_block: worker {} underpaid: paid {} < required {} ({} receipt(s) x {})",
                hex::encode(pkh),
                total_paid,
                required,
                count,
                worker_due,
            ));
        }
    }
    Ok(())
}

/// Phase 13-B: Verify block-contained PoAW-X receipts in connect_block.
///
/// Checks (active non-mainnet after activation only):
///  1. Receipts present and non-empty.
///  2. irx1 root recomputed from receipts matches coinbase OP_RETURN.
///  3. Every receipt commitment_nonce equals the deterministic parent-derived nonce.
///  4. Every receipt worker_pkh = RIPEMD160(SHA256(worker_pubkey)).
///  5. Every receipt worker_sig is a valid secp256k1 ECDSA signature over
///     SHA256(solution || commitment_nonce || height_le8).
///  6. Every receipt sha256d(seed || nonce || solution) >= configured difficulty.
///  7. Reward split: each worker_pkh paid at least worker_due * receipt_count.
fn validate_poawx_block_receipts(
    block: &Block,
    height: u64,
    previous: Option<&Block>,
) -> Result<(), String> {
    // Phase 18B (fail-closed): mode-1 (delegated) receipts are NEVER valid on
    // mainnet. This is checked before any activation early-return so a malicious
    // mainnet block carrying delegated receipts is rejected regardless of env.
    // Legitimate mainnet blocks carry no receipts, so this is a no-op for them.
    if crate::activation::network_kind_from_env() == crate::activation::NetworkKind::Mainnet {
        if let Some(receipts) = &block.poawx_receipts {
            if receipts.iter().any(|r| r.delegation.is_some()) {
                return Err(format!(
                    "connect_block: delegated (mode-1) poawx receipts rejected on mainnet at height {}",
                    height
                ));
            }
        }
    }

    // Activation gate — identical conditions to validate_poawx_coinbase.
    let act_h = match std::env::var("IRIUM_POAWX_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        Some(h) => h,
        None => return Ok(()),
    };
    if !std::env::var("IRIUM_POAWX_MODE")
        .map(|v| v.trim() == "active")
        .unwrap_or(false)
    {
        return Ok(());
    }
    if crate::activation::network_kind_from_env() == crate::activation::NetworkKind::Mainnet {
        return Ok(());
    }
    if height < act_h {
        return Ok(());
    }

    // Require non-empty receipts.
    let receipts = match block.poawx_receipts.as_ref().filter(|v| !v.is_empty()) {
        Some(r) => r.as_slice(),
        None => {
            return Err(format!(
                "connect_block: poawx receipts missing or empty at height {} (active from {})",
                height, act_h
            ))
        }
    };

    // Extract irx1 root from coinbase OP_RETURN.
    let coinbase_root = crate::poawx::irx1_root_from_block_bytes(block).ok_or_else(|| {
        format!(
            "connect_block: no irx1 OP_RETURN in coinbase at height {}",
            height
        )
    })?;
    if coinbase_root == [0u8; 32] {
        return Err(format!(
            "connect_block: zero irx1 root at height {}",
            height
        ));
    }

    // Recompute root from block-contained receipts; must match coinbase.
    // Phase 20: after production activation the extension is bound into the root,
    // so a missing/mutated extension changes `computed_root` and is rejected here
    // (in addition to the explicit production validator below). Mainnet-off: the
    // gate is false on mainnet, so the root is byte-identical to Phase 13-A/18B.
    let phase20_active = phase20_production_active(height);
    let computed_root = crate::poawx::irx1_root_from_block_receipts_gated(receipts, phase20_active);
    if computed_root != coinbase_root {
        return Err(format!(
            "connect_block: irx1 root mismatch at height {} coinbase={} computed={}",
            height,
            hex::encode(coinbase_root),
            hex::encode(computed_root),
        ));
    }

    // Derive deterministic seed and nonce from the parent block.
    let parent_block = previous.ok_or_else(|| {
        format!(
            "connect_block: no parent block for poawx nonce derivation at height {}",
            height
        )
    })?;
    let parent_height = height.saturating_sub(1);
    let parent_hash = parent_block.header.hash_for_height(parent_height);
    let seed: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(parent_hash);
        h.update(parent_height.to_le_bytes());
        h.update(b"poawx_assignment_seed_v1");
        h.finalize().into()
    };
    let expected_nonce: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(seed);
        h.update(b"commitment_nonce");
        h.finalize().into()
    };

    let difficulty = poawx_block_difficulty_bits();

    for (i, r) in receipts.iter().enumerate() {
        // (1) Commitment nonce must match the deterministic expected value.
        if r.commitment_nonce != expected_nonce {
            return Err(format!(
                "connect_block: receipt[{}] commitment_nonce mismatch at height {}",
                i, height
            ));
        }

        // (2+3) Worker identity + delegation. Mode-0 (direct) is unchanged from
        // Phase 13-B. Mode-1 (delegated) additionally verifies the miner's
        // one-time delegation and that the receipt signer is the delegated pool
        // key, while keeping the miner pkh as the payout identity.
        {
            use k256::ecdsa::signature::hazmat::PrehashVerifier;
            use k256::ecdsa::{Signature, VerifyingKey};

            let challenge: [u8; 32] = {
                let mut h = Sha256::new();
                h.update(r.solution);
                h.update(r.commitment_nonce);
                h.update(r.height.to_le_bytes());
                h.finalize().into()
            };

            match &r.delegation {
                None => {
                    // Mode-0: signer is the miner; HASH160(worker_pubkey) == worker_pkh.
                    let vk = VerifyingKey::from_sec1_bytes(&r.worker_pubkey).map_err(|_| {
                        format!(
                            "connect_block: receipt[{}] invalid worker_pubkey at height {}",
                            i, height
                        )
                    })?;
                    let sha_of_pk = Sha256::digest(r.worker_pubkey);
                    let rip = Ripemd160::digest(sha_of_pk);
                    let mut computed_pkh = [0u8; 20];
                    computed_pkh.copy_from_slice(&rip);
                    if computed_pkh != r.worker_pkh {
                        return Err(format!(
                            "connect_block: receipt[{}] worker_pkh/pubkey mismatch at height {}",
                            i, height
                        ));
                    }
                    let sig = Signature::from_slice(&r.worker_sig).map_err(|_| {
                        format!(
                            "connect_block: receipt[{}] malformed worker_sig at height {}",
                            i, height
                        )
                    })?;
                    vk.verify_prehash(&challenge, &sig).map_err(|_| {
                        format!(
                            "connect_block: receipt[{}] worker_sig verification failed at height {}",
                            i, height
                        )
                    })?;
                }
                Some(d) => {
                    // Mode-1: delegated. Never reaches here on mainnet (hard-rejected above).
                    if !poawx_delegation_active(height) {
                        return Err(format!(
                            "connect_block: receipt[{}] mode-1 delegated receipt before delegation activation at height {}",
                            i, height
                        ));
                    }
                    if d.network_id != crate::activation::network_id_byte() {
                        return Err(format!(
                            "connect_block: receipt[{}] delegation network_id mismatch at height {}",
                            i, height
                        ));
                    }
                    // Miner pkh (payout identity) must equal the delegation's miner key hash.
                    if d.miner_pkh() != r.worker_pkh {
                        return Err(format!(
                            "connect_block: receipt[{}] delegation miner_pkh != worker_pkh at height {}",
                            i, height
                        ));
                    }
                    if height > d.expiry_height {
                        return Err(format!(
                            "connect_block: receipt[{}] delegation expired (height {} > expiry {})",
                            i, height, d.expiry_height
                        ));
                    }
                    // Official pool is 0%. Phase 20 Step 4: a nonzero delegation fee
                    // is allowed ONLY in explicit third-party mode with the fee gate
                    // active, capped at THIRD_PARTY_FEE_CAP_BPS, with a nonzero
                    // fee_pkh. Both gates are mainnet-hard-off, so mainnet stays 0%.
                    if d.fee_bps != 0 {
                        let third_party =
                            third_party_fee_active(height) && third_party_pool_mode_enabled();
                        if !third_party {
                            return Err(format!(
                                "connect_block: receipt[{}] nonzero delegation fee_bps {} rejected (third-party mode/fee gate not active)",
                                i, d.fee_bps
                            ));
                        }
                        if d.fee_bps > crate::poawx::THIRD_PARTY_FEE_CAP_BPS {
                            return Err(format!(
                                "connect_block: receipt[{}] delegation fee_bps {} exceeds cap {}",
                                i,
                                d.fee_bps,
                                crate::poawx::THIRD_PARTY_FEE_CAP_BPS
                            ));
                        }
                        if d.fee_pkh == [0u8; 20] {
                            return Err(format!(
                                "connect_block: receipt[{}] nonzero delegation fee_bps with zero fee_pkh",
                                i
                            ));
                        }
                    }
                    // Miner's one-time delegation signature.
                    d.verify_signature().map_err(|e| {
                        format!("connect_block: receipt[{}] {} at height {}", i, e, height)
                    })?;
                    // Receipt signer must be the delegated pool key.
                    if r.worker_pubkey != d.pool_pubkey {
                        return Err(format!(
                            "connect_block: receipt[{}] signer != delegated pool_pubkey at height {}",
                            i, height
                        ));
                    }
                    let vk = VerifyingKey::from_sec1_bytes(&r.worker_pubkey).map_err(|_| {
                        format!(
                            "connect_block: receipt[{}] invalid signer pubkey at height {}",
                            i, height
                        )
                    })?;
                    let sig = Signature::from_slice(&r.worker_sig).map_err(|_| {
                        format!(
                            "connect_block: receipt[{}] malformed signer sig at height {}",
                            i, height
                        )
                    })?;
                    vk.verify_prehash(&challenge, &sig).map_err(|_| {
                        format!(
                            "connect_block: receipt[{}] signer sig verification failed at height {}",
                            i, height
                        )
                    })?;
                }
            }
        }

        // (4) Puzzle PoW: sha256d(seed || nonce || solution) >= difficulty leading zeros.
        {
            let mut pow_input = [0u8; 72];
            pow_input[..32].copy_from_slice(&seed);
            pow_input[32..64].copy_from_slice(&expected_nonce);
            pow_input[64..].copy_from_slice(&r.solution);
            let pow_hash = sha256d(&pow_input);
            let leading = crate::poawx::count_leading_zero_bits(&pow_hash);
            if leading < difficulty {
                return Err(format!(
                    "connect_block: receipt[{}] insufficient puzzle PoW: {} bits < {} required at height {}",
                    i, leading, difficulty, height
                ));
            }
        }
    }

    // (5) Reward split (legacy) OR Phase 20 production payout (after activation).
    // Pre-activation behavior is byte-identical (legacy 10%/receipt floor). After
    // `phase20_production_active(height)` (mainnet-off), the integrated production
    // validator enforces role claims + RoleReward + the canonical fee-aware
    // multi-role coinbase, and a missing extension fails closed.
    if phase20_active {
        validate_phase20_production_block(block, receipts, height, &parent_hash, previous)?;
    } else {
        validate_poawx_reward_split_from_block(block, receipts, height)?;
    }

    Ok(())
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
            return Err("HtlcBtcSwapV1 confirmations_required out of allowed range".to_string());
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
            return Err("HtlcLtcSwapV1 confirmations_required out of allowed range".to_string());
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
                return Err("Sell-IRM SwapOrder output value must equal irm_amount".to_string());
            }
            if order.confirmations_required < MIN_HTLC_BTC_SWAP_CONFIRMATIONS
                || order.confirmations_required > MAX_HTLC_BTC_SWAP_CONFIRMATIONS
            {
                return Err("SwapOrder confirmations_required out of range".to_string());
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
                return Err("Sell-IRM LtcSwapOrder output value must equal irm_amount".to_string());
            }
            if order.confirmations_required < MIN_HTLC_LTC_SWAP_CONFIRMATIONS
                || order.confirmations_required > MAX_HTLC_LTC_SWAP_CONFIRMATIONS
            {
                return Err("LtcSwapOrder confirmations_required out of range".to_string());
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
                    let mut expected_payload = Vec::with_capacity(BTC_OP_RETURN_BINDING_LEN);
                    expected_payload.extend_from_slice(&BTC_OP_RETURN_BINDING_MAGIC);
                    expected_payload.extend_from_slice(&swap.funding_binding);
                    let mut pays = false;
                    let mut op_return_vout: Option<u32> = None;
                    for o in &outs {
                        match &o.script {
                            BtcOutputScript::P2pkh(pkh) => {
                                if *pkh == swap.btc_recipient_pkh && o.value >= swap.btc_amount_sats
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
                    if !verify_sig_with_pubkey(tx, input_index, &scriptcode, &sig, &pubkey) {
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
                    let mut expected_payload = Vec::with_capacity(LTC_OP_RETURN_BINDING_LEN);
                    expected_payload.extend_from_slice(&LTC_OP_RETURN_BINDING_MAGIC);
                    expected_payload.extend_from_slice(&swap.funding_binding);
                    let mut pays = false;
                    let mut op_return_vout: Option<u32> = None;
                    for o in &outs {
                        match &o.script {
                            BtcOutputScript::P2pkh(pkh) => {
                                if *pkh == swap.ltc_recipient_pkh && o.value >= swap.ltc_amount_sats
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
                                if *pkh == swap.ltc_recipient_pkh && o.value >= swap.ltc_amount_sats
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
                    if !verify_sig_with_pubkey(tx, input_index, &scriptcode, &sig, &pubkey) {
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
                    let funding_binding = compute_funding_binding(&txin.prev_txid, txin.prev_index);
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
                    let funding_binding = compute_funding_binding(&txin.prev_txid, txin.prev_index);
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
        poawx_receipts: None,
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
        let script_len = crate::tx::read_varint_at(raw, &mut offset).unwrap_or(0) as usize;
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
            Some(BTC_HEADER_BATCH_TAG) | Some(LTC_HEADER_BATCH_TAG) => {
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
            if parse_htlc_btc_swap_v1_script(script).is_some() && first_witness_byte == Some(0x01) {
                return MempoolPriority::ZeroFeeAllowed;
            }
            if let Some(order) = parse_swap_order_script(script) {
                if order.direction == SWAP_ORDER_DIRECTION_SELL && first_witness_byte == Some(0x01)
                {
                    return MempoolPriority::ZeroFeeAllowed;
                }
            }
            // LTC buyer paths (Phase C/D parity).
            if parse_htlc_ltc_swap_v1_script(script).is_some() && first_witness_byte == Some(0x01) {
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
            poawx_receipts: None,
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
        if height < DIFFICULTY_RETARGET_INTERVAL
            || !height.is_multiple_of(DIFFICULTY_RETARGET_INTERVAL)
        {
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
        std::env::set_var("IRIUM_BLOCK_TIME_V2_ACTIVATION_HEIGHT", fork.to_string());
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
        let mut mempool = crate::mempool::MempoolManager::new(path.clone(), 100, 0.0, 0);
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

        let evicted = crate::mempool::evict_invalid_mempool_entries(&chain, &mut mempool);
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
        let mut mempool = crate::mempool::MempoolManager::new(path.clone(), 100, 0.0, 0);
        let raw = tx.serialize();
        mempool
            .add_transaction(tx.clone(), raw, 0)
            .expect("admit tx to mempool");
        assert_eq!(mempool.len(), 1);

        // No conflict: chain still has the UTXO; tx is still valid.
        let evicted = crate::mempool::evict_invalid_mempool_entries(&chain, &mut mempool);
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
        let mut mempool = crate::mempool::MempoolManager::new(path.clone(), 100, 0.0, 0);
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

        let evicted = crate::mempool::evict_invalid_mempool_entries(&chain, &mut mempool);
        assert_eq!(
            evicted, 3,
            "all three conflicting entries must be evicted in one pass"
        );
        assert_eq!(mempool.len(), 0);

        let _ = std::fs::remove_file(path);
    }

    fn chain_poawx_env_lock() -> &'static std::sync::Mutex<()> {
        // Phase 21J: delegate to the single crate-wide PoAW-X test env lock so
        // chain + poawx-module env-mutating tests serialise together (race-free
        // under the full parallel `cargo test --lib`).
        crate::poawx::poawx_test_env_lock()
    }

    fn make_poawx_test_block(coinbase_script: Vec<u8>) -> Block {
        use crate::block::BlockHeader;
        Block {
            header: BlockHeader {
                version: 1,
                prev_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                time: 0,
                bits: 0x207fffff,
                nonce: 0,
            },
            transactions: vec![Transaction {
                version: 1,
                inputs: vec![TxInput {
                    prev_txid: [0u8; 32],
                    prev_index: 0xffff_ffff,
                    script_sig: vec![0x01, 0x00],
                    sequence: 0xffff_ffff,
                }],
                outputs: vec![
                    TxOutput {
                        value: 50_0000_0000,
                        script_pubkey: vec![0x51],
                    },
                    TxOutput {
                        value: 0,
                        script_pubkey: coinbase_script,
                    },
                ],
                locktime: 0,
            }],
            auxpow: None,
            poawx_receipts: None,
        }
    }

    fn irx1_script_for_chain(root: [u8; 32]) -> Vec<u8> {
        let mut s = vec![0x6a, 0x24u8];
        s.extend_from_slice(b"irx1");
        s.extend_from_slice(&root);
        s
    }

    #[test]
    fn test_validate_poawx_coinbase_no_activation_env_always_ok() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("IRIUM_POAWX_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_MODE");
        std::env::remove_var("IRIUM_NETWORK");
        let block = make_poawx_test_block(vec![0x51]);
        assert!(validate_poawx_coinbase(&block, 100).is_ok());
    }

    #[test]
    fn test_validate_poawx_coinbase_mode_inactive_always_ok() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_POAWX_ACTIVATION_HEIGHT", "10");
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::remove_var("IRIUM_POAWX_MODE");
        let block = make_poawx_test_block(vec![0x51]);
        assert!(validate_poawx_coinbase(&block, 100).is_ok());
        std::env::remove_var("IRIUM_POAWX_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_NETWORK");
    }

    #[test]
    fn test_validate_poawx_coinbase_pre_activation_height_ok() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_POAWX_ACTIVATION_HEIGHT", "100");
        std::env::set_var("IRIUM_POAWX_MODE", "active");
        std::env::set_var("IRIUM_NETWORK", "testnet");
        let block = make_poawx_test_block(vec![0x51]);
        assert!(validate_poawx_coinbase(&block, 99).is_ok());
        std::env::remove_var("IRIUM_POAWX_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_MODE");
        std::env::remove_var("IRIUM_NETWORK");
    }

    #[test]
    fn test_validate_poawx_coinbase_rejects_missing_commitment() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_POAWX_ACTIVATION_HEIGHT", "10");
        std::env::set_var("IRIUM_POAWX_MODE", "active");
        std::env::set_var("IRIUM_NETWORK", "testnet");
        let block = make_poawx_test_block(vec![0x51]);
        let result = validate_poawx_coinbase(&block, 10);
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("irx1"), "error must mention irx1: {}", msg);
        std::env::remove_var("IRIUM_POAWX_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_MODE");
        std::env::remove_var("IRIUM_NETWORK");
    }

    #[test]
    fn test_validate_poawx_coinbase_rejects_zero_root() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_POAWX_ACTIVATION_HEIGHT", "10");
        std::env::set_var("IRIUM_POAWX_MODE", "active");
        std::env::set_var("IRIUM_NETWORK", "testnet");
        let script = irx1_script_for_chain([0u8; 32]);
        let block = make_poawx_test_block(script);
        let result = validate_poawx_coinbase(&block, 100);
        assert!(result.is_err(), "zero irx1 root must be rejected");
        std::env::remove_var("IRIUM_POAWX_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_MODE");
        std::env::remove_var("IRIUM_NETWORK");
    }

    #[test]
    fn test_validate_poawx_coinbase_accepts_valid_irx1() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_POAWX_ACTIVATION_HEIGHT", "10");
        std::env::set_var("IRIUM_POAWX_MODE", "active");
        std::env::set_var("IRIUM_NETWORK", "testnet");
        let mut root = [0u8; 32];
        root[0] = 0xca;
        root[31] = 0xfe;
        let script = irx1_script_for_chain(root);
        let block = make_poawx_test_block(script);
        assert!(validate_poawx_coinbase(&block, 100).is_ok());
        std::env::remove_var("IRIUM_POAWX_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_MODE");
        std::env::remove_var("IRIUM_NETWORK");
    }

    #[test]
    fn test_validate_poawx_coinbase_mainnet_gate_skips_check() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_POAWX_ACTIVATION_HEIGHT", "10");
        std::env::set_var("IRIUM_POAWX_MODE", "active");
        std::env::set_var("IRIUM_NETWORK", "mainnet");
        let block = make_poawx_test_block(vec![0x51]);
        assert!(
            validate_poawx_coinbase(&block, 100).is_ok(),
            "mainnet must skip irx1 check"
        );
        std::env::remove_var("IRIUM_POAWX_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_MODE");
        std::env::remove_var("IRIUM_NETWORK");
    }

    // ── Phase 13-B: validate_poawx_block_receipts tests ──────────────────

    fn test_signing_key() -> k256::ecdsa::SigningKey {
        // Fixed non-zero 32-byte scalar — valid k256 private key.
        k256::ecdsa::SigningKey::from_bytes((&[0x42u8; 32]).into()).unwrap()
    }

    fn phase13b_parent_block() -> Block {
        Block {
            header: BlockHeader {
                version: 1,
                prev_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                time: 0,
                bits: 0x207fffff,
                nonce: 0,
            },
            transactions: vec![],
            auxpow: None,
            poawx_receipts: None,
        }
    }

    /// Build a PoawxBlockReceipt that satisfies all Phase 13-B checks with
    /// the given difficulty (number of required leading zero bits).
    fn make_test_receipt(
        height: u64,
        sk: &k256::ecdsa::SigningKey,
        parent_hash: [u8; 32],
        difficulty: u32,
    ) -> crate::poawx::PoawxBlockReceipt {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        use k256::ecdsa::VerifyingKey;

        let vk = VerifyingKey::from(sk);
        let pubkey_bytes: Vec<u8> = vk.to_encoded_point(true).as_bytes().to_vec();
        let sha_of_pk = Sha256::digest(&pubkey_bytes);
        let rip = ripemd::Ripemd160::digest(sha_of_pk);
        let mut worker_pkh = [0u8; 20];
        worker_pkh.copy_from_slice(&rip);
        let mut worker_pubkey = [0u8; 33];
        worker_pubkey.copy_from_slice(&pubkey_bytes);

        let parent_height = height.saturating_sub(1);
        let seed: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(parent_hash);
            h.update(parent_height.to_le_bytes());
            h.update(b"poawx_assignment_seed_v1");
            h.finalize().into()
        };
        let nonce: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(seed);
            h.update(b"commitment_nonce");
            h.finalize().into()
        };

        // Search for a solution satisfying the required difficulty.
        let mut solution = [0u8; 8];
        for n in 0u64..100_000_000 {
            solution.copy_from_slice(&n.to_le_bytes());
            let mut pow_input = [0u8; 72];
            pow_input[..32].copy_from_slice(&seed);
            pow_input[32..64].copy_from_slice(&nonce);
            pow_input[64..].copy_from_slice(&solution);
            let pow_hash = sha256d(&pow_input);
            if crate::poawx::count_leading_zero_bits(&pow_hash) >= difficulty {
                break;
            }
        }

        // Sign the challenge.
        let challenge: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(solution);
            h.update(nonce);
            h.update(height.to_le_bytes());
            h.finalize().into()
        };
        let sig: k256::ecdsa::Signature = sk.sign_prehash(&challenge).unwrap();
        let mut worker_sig = [0u8; 64];
        worker_sig.copy_from_slice(&sig.to_bytes());

        crate::poawx::PoawxBlockReceipt {
            height,
            lane: b'A',
            worker_pkh,
            worker_pubkey,
            worker_sig,
            solution,
            commitment_nonce: nonce,
            delegation: None,
            phase20_ext: None,
        }
    }

    /// Build a valid Phase 13-B block from a receipt.
    fn make_valid_poawx_block(
        parent_hash: [u8; 32],
        height: u64,
        receipt: crate::poawx::PoawxBlockReceipt,
        payout_ok: bool,
    ) -> Block {
        use crate::poawx::irx1_root_from_block_receipts;

        let irx1_root = irx1_root_from_block_receipts(&[receipt.clone()]);
        let mut irx1_script = vec![0x6a, 0x24u8];
        irx1_script.extend_from_slice(b"irx1");
        irx1_script.extend_from_slice(&irx1_root);

        let base_reward = block_reward(height);
        let worker_due = base_reward * 100 / 1000;
        let payout_val = if payout_ok { worker_due } else { 0 };
        let worker_script = p2pkh_script(&receipt.worker_pkh);

        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: [0u8; 32],
                prev_index: 0xffff_ffff,
                script_sig: vec![0x01, 0x00],
                sequence: 0xffff_ffff,
            }],
            outputs: vec![
                TxOutput {
                    value: base_reward - payout_val,
                    script_pubkey: vec![0x51],
                },
                TxOutput {
                    value: payout_val,
                    script_pubkey: worker_script,
                },
                TxOutput {
                    value: 0,
                    script_pubkey: irx1_script,
                },
            ],
            locktime: 0,
        };
        Block {
            header: BlockHeader {
                version: 1,
                prev_hash: parent_hash,
                merkle_root: [0u8; 32],
                time: 0,
                bits: 0x207fffff,
                nonce: 0,
            },
            transactions: vec![coinbase],
            auxpow: None,
            poawx_receipts: Some(vec![receipt]),
        }
    }

    #[test]
    fn phase13b_inactive_mode_always_ok() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_POAWX_ACTIVATION_HEIGHT", "10");
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::remove_var("IRIUM_POAWX_MODE");
        let parent = phase13b_parent_block();
        let block = make_poawx_test_block(vec![0x51]);
        assert!(validate_poawx_block_receipts(&block, 100, Some(&parent)).is_ok());
        std::env::remove_var("IRIUM_POAWX_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_NETWORK");
    }

    #[test]
    fn phase13b_pre_activation_height_ok() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_POAWX_ACTIVATION_HEIGHT", "100");
        std::env::set_var("IRIUM_POAWX_MODE", "active");
        std::env::set_var("IRIUM_NETWORK", "testnet");
        let parent = phase13b_parent_block();
        let block = make_poawx_test_block(vec![0x51]);
        assert!(validate_poawx_block_receipts(&block, 99, Some(&parent)).is_ok());
        std::env::remove_var("IRIUM_POAWX_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_MODE");
        std::env::remove_var("IRIUM_NETWORK");
    }

    #[test]
    fn phase13b_mainnet_unchanged() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_POAWX_ACTIVATION_HEIGHT", "10");
        std::env::set_var("IRIUM_POAWX_MODE", "active");
        std::env::set_var("IRIUM_NETWORK", "mainnet");
        let parent = phase13b_parent_block();
        let block = make_poawx_test_block(vec![0x51]);
        assert!(
            validate_poawx_block_receipts(&block, 100, Some(&parent)).is_ok(),
            "mainnet must skip poawx receipt check"
        );
        std::env::remove_var("IRIUM_POAWX_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_MODE");
        std::env::remove_var("IRIUM_NETWORK");
    }

    #[test]
    fn phase13b_missing_receipts_rejected() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_POAWX_ACTIVATION_HEIGHT", "10");
        std::env::set_var("IRIUM_POAWX_MODE", "active");
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS", "1");
        let parent = phase13b_parent_block();
        // Block has irx1 commitment but poawx_receipts = None.
        let mut root = [0u8; 32];
        root[0] = 0xde;
        let block = make_poawx_test_block(irx1_script_for_chain(root));
        let result = validate_poawx_block_receipts(&block, 10, Some(&parent));
        assert!(result.is_err(), "missing receipts must be rejected");
        assert!(result.unwrap_err().contains("missing or empty"));
        std::env::remove_var("IRIUM_POAWX_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_MODE");
        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS");
    }

    #[test]
    fn phase13b_empty_receipts_rejected() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_POAWX_ACTIVATION_HEIGHT", "10");
        std::env::set_var("IRIUM_POAWX_MODE", "active");
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS", "1");
        let parent = phase13b_parent_block();
        let mut root = [0u8; 32];
        root[0] = 0xde;
        let mut block = make_poawx_test_block(irx1_script_for_chain(root));
        block.poawx_receipts = Some(vec![]);
        let result = validate_poawx_block_receipts(&block, 10, Some(&parent));
        assert!(result.is_err(), "empty receipts must be rejected");
        std::env::remove_var("IRIUM_POAWX_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_MODE");
        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS");
    }

    #[test]
    fn phase13b_zero_irx1_root_rejected() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_POAWX_ACTIVATION_HEIGHT", "10");
        std::env::set_var("IRIUM_POAWX_MODE", "active");
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS", "1");
        let parent = phase13b_parent_block();
        let mut block = make_poawx_test_block(irx1_script_for_chain([0u8; 32]));
        block.poawx_receipts = Some(vec![]);
        let result = validate_poawx_block_receipts(&block, 10, Some(&parent));
        assert!(result.is_err(), "zero irx1 root must be rejected");
        std::env::remove_var("IRIUM_POAWX_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_MODE");
        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS");
    }

    #[test]
    fn phase13b_valid_block_accepted() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_POAWX_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_MODE", "active");
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS", "1");
        let sk = test_signing_key();
        let parent = phase13b_parent_block();
        let parent_hash = parent.header.hash_for_height(0);
        let height = 1u64;
        let receipt = make_test_receipt(height, &sk, parent_hash, 1);
        let block = make_valid_poawx_block(parent_hash, height, receipt, true);
        let result = validate_poawx_block_receipts(&block, height, Some(&parent));
        assert!(
            result.is_ok(),
            "valid poawx block must be accepted: {:?}",
            result
        );
        std::env::remove_var("IRIUM_POAWX_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_MODE");
        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS");
    }

    // ── Phase 18B: mode-1 (delegated) receipt verification tests ─────────

    fn sk_from(seed: u8) -> k256::ecdsa::SigningKey {
        k256::ecdsa::SigningKey::from_slice(&[seed; 32]).expect("valid sk")
    }

    fn pubkey33(sk: &k256::ecdsa::SigningKey) -> [u8; 33] {
        use k256::ecdsa::VerifyingKey;
        let vk = VerifyingKey::from(sk);
        let enc = vk.to_encoded_point(true);
        let mut pk = [0u8; 33];
        pk.copy_from_slice(enc.as_bytes());
        pk
    }

    fn pkh_of(sk: &k256::ecdsa::SigningKey) -> [u8; 20] {
        let pk = pubkey33(sk);
        let sha = Sha256::digest(pk);
        let rip = ripemd::Ripemd160::digest(sha);
        let mut pkh = [0u8; 20];
        pkh.copy_from_slice(&rip);
        pkh
    }

    /// Build a valid mode-1 (delegated) receipt: miner key signs the delegation,
    /// pool delegate key signs the per-height challenge, worker_pkh = miner pkh.
    #[allow(clippy::too_many_arguments)]
    fn make_mode1_receipt(
        height: u64,
        miner_sk: &k256::ecdsa::SigningKey,
        pool_sk: &k256::ecdsa::SigningKey,
        parent_hash: [u8; 32],
        difficulty: u32,
        network_id: u8,
        expiry_height: u64,
        fee_bps: u16,
    ) -> crate::poawx::PoawxBlockReceipt {
        use k256::ecdsa::signature::hazmat::PrehashSigner;

        let miner_pubkey = pubkey33(miner_sk);
        let worker_pkh = pkh_of(miner_sk);
        let pool_pubkey = pubkey33(pool_sk);

        let parent_height = height.saturating_sub(1);
        let seed: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(parent_hash);
            h.update(parent_height.to_le_bytes());
            h.update(b"poawx_assignment_seed_v1");
            h.finalize().into()
        };
        let nonce: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(seed);
            h.update(b"commitment_nonce");
            h.finalize().into()
        };
        let mut solution = [0u8; 8];
        for n in 0u64..100_000_000 {
            solution.copy_from_slice(&n.to_le_bytes());
            let mut pow_input = [0u8; 72];
            pow_input[..32].copy_from_slice(&seed);
            pow_input[32..64].copy_from_slice(&nonce);
            pow_input[64..].copy_from_slice(&solution);
            if crate::poawx::count_leading_zero_bits(&sha256d(&pow_input)) >= difficulty {
                break;
            }
        }

        let mut d = crate::poawx::Delegation {
            deleg_version: crate::poawx::Delegation::VERSION,
            network_id,
            miner_pubkey,
            pool_pubkey,
            worker_tag: [0u8; 32],
            expiry_height,
            fee_bps,
            fee_pkh: [0u8; 20],
            deleg_nonce: [0x33u8; 32],
            delegation_sig: [0u8; 64],
        };
        let dsig: k256::ecdsa::Signature = miner_sk.sign_prehash(&d.message_hash()).unwrap();
        d.delegation_sig.copy_from_slice(&dsig.to_bytes());

        let challenge: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(solution);
            h.update(nonce);
            h.update(height.to_le_bytes());
            h.finalize().into()
        };
        let rsig: k256::ecdsa::Signature = pool_sk.sign_prehash(&challenge).unwrap();
        let mut worker_sig = [0u8; 64];
        worker_sig.copy_from_slice(&rsig.to_bytes());

        crate::poawx::PoawxBlockReceipt {
            height,
            lane: b'A',
            worker_pkh,
            worker_pubkey: pool_pubkey,
            worker_sig,
            solution,
            commitment_nonce: nonce,
            delegation: Some(d),
            phase20_ext: None,
        }
    }

    fn set_mode1_env() {
        std::env::set_var("IRIUM_POAWX_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_DELEGATION_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_MODE", "active");
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS", "1");
    }
    fn clear_mode1_env() {
        std::env::remove_var("IRIUM_POAWX_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_DELEGATION_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_MODE");
        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS");
    }

    #[test]
    fn phase18b_mode1_accepts_valid_delegated_receipt() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        set_mode1_env();
        let miner = sk_from(3);
        let pool = sk_from(5);
        let parent = phase13b_parent_block();
        let parent_hash = parent.header.hash_for_height(0);
        let height = 1u64;
        let receipt = make_mode1_receipt(height, &miner, &pool, parent_hash, 1, 1, 1000, 0);
        let block = make_valid_poawx_block(parent_hash, height, receipt, true);
        let result = validate_poawx_block_receipts(&block, height, Some(&parent));
        assert!(
            result.is_ok(),
            "valid mode-1 block must be accepted: {result:?}"
        );
        clear_mode1_env();
    }

    #[test]
    fn phase18b_mode1_rejected_before_activation() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        set_mode1_env();
        // Delegation activation NOT reached (set far above the block height).
        std::env::set_var("IRIUM_POAWX_DELEGATION_ACTIVATION_HEIGHT", "100");
        let miner = sk_from(3);
        let pool = sk_from(5);
        let parent = phase13b_parent_block();
        let parent_hash = parent.header.hash_for_height(0);
        let height = 1u64;
        let receipt = make_mode1_receipt(height, &miner, &pool, parent_hash, 1, 1, 1000, 0);
        let block = make_valid_poawx_block(parent_hash, height, receipt, true);
        let result = validate_poawx_block_receipts(&block, height, Some(&parent));
        assert!(result.is_err(), "mode-1 before activation must reject");
        assert!(result.unwrap_err().contains("before delegation activation"));
        clear_mode1_env();
    }

    #[test]
    fn phase18b_mode1_rejected_on_mainnet() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        set_mode1_env();
        std::env::set_var("IRIUM_NETWORK", "mainnet");
        let miner = sk_from(3);
        let pool = sk_from(5);
        let parent = phase13b_parent_block();
        let parent_hash = parent.header.hash_for_height(0);
        let height = 1u64;
        // network_id 0 = mainnet; the mainnet hard-reject fires first regardless.
        let receipt = make_mode1_receipt(height, &miner, &pool, parent_hash, 1, 0, 1000, 0);
        let block = make_valid_poawx_block(parent_hash, height, receipt, true);
        let result = validate_poawx_block_receipts(&block, height, Some(&parent));
        assert!(result.is_err(), "mode-1 on mainnet must hard-reject");
        assert!(result.unwrap_err().contains("rejected on mainnet"));
        clear_mode1_env();
    }

    #[test]
    fn phase18b_mode1_rejects_wrong_miner_pkh() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        set_mode1_env();
        let miner = sk_from(3);
        let pool = sk_from(5);
        let parent = phase13b_parent_block();
        let parent_hash = parent.header.hash_for_height(0);
        let height = 1u64;
        let mut receipt = make_mode1_receipt(height, &miner, &pool, parent_hash, 1, 1, 1000, 0);
        // worker_pkh no longer equals HASH160(delegation.miner_pubkey).
        receipt.worker_pkh = [0xff; 20];
        let block = make_valid_poawx_block(parent_hash, height, receipt, true);
        let result = validate_poawx_block_receipts(&block, height, Some(&parent));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("miner_pkh != worker_pkh"));
        clear_mode1_env();
    }

    #[test]
    fn phase18b_mode1_rejects_bad_delegation_sig() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        set_mode1_env();
        let miner = sk_from(3);
        let pool = sk_from(5);
        let parent = phase13b_parent_block();
        let parent_hash = parent.header.hash_for_height(0);
        let height = 1u64;
        let mut receipt = make_mode1_receipt(height, &miner, &pool, parent_hash, 1, 1, 1000, 0);
        if let Some(d) = receipt.delegation.as_mut() {
            d.delegation_sig[0] ^= 0xff;
        }
        // Rebuild block so the irx1 root matches the (tampered) receipt digest.
        let block = make_valid_poawx_block(parent_hash, height, receipt, true);
        let result = validate_poawx_block_receipts(&block, height, Some(&parent));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("signature verification failed"));
        clear_mode1_env();
    }

    #[test]
    fn phase18b_mode1_rejects_expired_delegation() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        set_mode1_env();
        let miner = sk_from(3);
        let pool = sk_from(5);
        let parent = phase13b_parent_block();
        let parent_hash = parent.header.hash_for_height(0);
        let height = 2u64;
        // expiry_height 1 < block height 2 -> expired.
        let receipt = make_mode1_receipt(height, &miner, &pool, parent_hash, 1, 1, 1, 0);
        let block = make_valid_poawx_block(parent_hash, height, receipt, true);
        let result = validate_poawx_block_receipts(&block, height, Some(&parent));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expired"));
        clear_mode1_env();
    }

    #[test]
    fn phase18b_mode1_rejects_network_mismatch() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        set_mode1_env();
        let miner = sk_from(3);
        let pool = sk_from(5);
        let parent = phase13b_parent_block();
        let parent_hash = parent.header.hash_for_height(0);
        let height = 1u64;
        // network_id 2 (devnet) but node is testnet (1).
        let receipt = make_mode1_receipt(height, &miner, &pool, parent_hash, 1, 2, 1000, 0);
        let block = make_valid_poawx_block(parent_hash, height, receipt, true);
        let result = validate_poawx_block_receipts(&block, height, Some(&parent));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("network_id mismatch"));
        clear_mode1_env();
    }

    #[test]
    fn phase18b_mode1_rejects_signer_not_pool_pubkey() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        set_mode1_env();
        let miner = sk_from(3);
        let pool = sk_from(5);
        let other = sk_from(9);
        let parent = phase13b_parent_block();
        let parent_hash = parent.header.hash_for_height(0);
        let height = 1u64;
        let mut receipt = make_mode1_receipt(height, &miner, &pool, parent_hash, 1, 1, 1000, 0);
        // Signer pubkey no longer matches the delegated pool_pubkey.
        receipt.worker_pubkey = pubkey33(&other);
        let block = make_valid_poawx_block(parent_hash, height, receipt, true);
        let result = validate_poawx_block_receipts(&block, height, Some(&parent));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("signer != delegated pool_pubkey"));
        clear_mode1_env();
    }

    #[test]
    fn phase18b_mode1_rejects_nonzero_fee() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        set_mode1_env();
        let miner = sk_from(3);
        let pool = sk_from(5);
        let parent = phase13b_parent_block();
        let parent_hash = parent.header.hash_for_height(0);
        let height = 1u64;
        // fee_bps = 100 must fail closed in step 1 (official pool 0%).
        let receipt = make_mode1_receipt(height, &miner, &pool, parent_hash, 1, 1, 1000, 100);
        let block = make_valid_poawx_block(parent_hash, height, receipt, true);
        let result = validate_poawx_block_receipts(&block, height, Some(&parent));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("nonzero delegation fee_bps"));
        clear_mode1_env();
    }

    #[test]
    fn phase18b_mode1_reward_split_requires_miner_payout() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        set_mode1_env();
        let miner = sk_from(3);
        let pool = sk_from(5);
        let parent = phase13b_parent_block();
        let parent_hash = parent.header.hash_for_height(0);
        let height = 1u64;
        // payout_ok=false -> miner pkh receives 0 -> reward split must reject,
        // proving the split keys on the MINER pkh (not the pool).
        let receipt = make_mode1_receipt(height, &miner, &pool, parent_hash, 1, 1, 1000, 0);
        let block = make_valid_poawx_block(parent_hash, height, receipt, false);
        let result = validate_poawx_block_receipts(&block, height, Some(&parent));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("underpaid"));
        clear_mode1_env();
    }

    // ── Phase 20: multi-role reward split (validator is pure; gate uses env lock) ──

    fn p20_role() -> crate::poawx::RoleReward {
        crate::poawx::RoleReward {
            compute_contributor_pkh: [0xC0u8; 20],
            verify_contributor_pkh: [0x7Eu8; 20],
            support_contributor_pkh: [0x5Au8; 20],
        }
    }

    fn p20_canonical_outputs(
        primary: &[u8; 20],
        role: &crate::poawx::RoleReward,
        total: u64,
        with_irx1: bool,
    ) -> Vec<crate::tx::TxOutput> {
        use crate::tx::{p2pkh_script, TxOutput};
        let a = crate::poawx::multi_role_amounts(total);
        let mut outs = Vec::new();
        if with_irx1 {
            // zero-value OP_RETURN (irx1-style) must be ignored by the validator.
            outs.push(TxOutput {
                value: 0,
                script_pubkey: vec![0x6a, 0x24, b'i', b'r', b'x', b'1'],
            });
        }
        outs.push(TxOutput {
            value: a[0],
            script_pubkey: p2pkh_script(primary),
        });
        outs.push(TxOutput {
            value: a[1],
            script_pubkey: p2pkh_script(&role.compute_contributor_pkh),
        });
        outs.push(TxOutput {
            value: a[2],
            script_pubkey: p2pkh_script(&role.verify_contributor_pkh),
        });
        outs.push(TxOutput {
            value: a[3],
            script_pubkey: p2pkh_script(&role.support_contributor_pkh),
        });
        outs
    }

    #[test]
    fn phase20_multi_role_coinbase_valid_accepted() {
        let primary = [0xA1u8; 20];
        let role = p20_role();
        let total = 5_000_000_000u64;
        // with and without the optional irx1 OP_RETURN both validate.
        assert!(validate_multi_role_coinbase_outputs(
            &p20_canonical_outputs(&primary, &role, total, true),
            &primary,
            &role,
            total
        )
        .is_ok());
        assert!(validate_multi_role_coinbase_outputs(
            &p20_canonical_outputs(&primary, &role, total, false),
            &primary,
            &role,
            total
        )
        .is_ok());
    }

    #[test]
    fn phase20_multi_role_coinbase_rejections() {
        use crate::tx::{p2pkh_script, TxOutput};
        let primary = [0xA1u8; 20];
        let role = p20_role();
        let total = 5_000_000_001u64; // odd -> remainder to primary
        let amts = crate::poawx::multi_role_amounts(total);

        // wrong amount (primary off by one)
        let mut o = p20_canonical_outputs(&primary, &role, total, true);
        o[1].value += 1;
        assert!(
            validate_multi_role_coinbase_outputs(&o, &primary, &role, total)
                .unwrap_err()
                .contains("amount")
        );

        // wrong order (swap compute and verify)
        let mut o = p20_canonical_outputs(&primary, &role, total, false);
        o.swap(1, 2);
        assert!(
            validate_multi_role_coinbase_outputs(&o, &primary, &role, total)
                .unwrap_err()
                .contains("order")
        );

        // missing role (only 3 outputs)
        let mut o = p20_canonical_outputs(&primary, &role, total, false);
        o.pop();
        assert!(
            validate_multi_role_coinbase_outputs(&o, &primary, &role, total)
                .unwrap_err()
                .contains("4 role outputs")
        );

        // extra value-bearing non-p2pkh output (hidden fee)
        let mut o = p20_canonical_outputs(&primary, &role, total, false);
        o.push(TxOutput {
            value: 1,
            script_pubkey: vec![0x6a, 0x01, 0x00],
        });
        assert!(
            validate_multi_role_coinbase_outputs(&o, &primary, &role, total)
                .unwrap_err()
                .contains("hidden fee")
        );

        // extra p2pkh output (delegate/5th payout) -> count != 4
        let mut o = p20_canonical_outputs(&primary, &role, total, false);
        o.push(TxOutput {
            value: 1,
            script_pubkey: p2pkh_script(&[0xDEu8; 20]),
        });
        assert!(validate_multi_role_coinbase_outputs(&o, &primary, &role, total).is_err());

        // primary pkh mismatch (caller binds primary=worker_pkh; a wrong primary rejects)
        let wrong_primary = [0xBBu8; 20];
        let o = p20_canonical_outputs(&primary, &role, total, false);
        assert!(validate_multi_role_coinbase_outputs(&o, &wrong_primary, &role, total).is_err());

        // sanity: amounts sum exactly even for the odd total
        assert_eq!(amts.iter().sum::<u64>(), total);
    }

    #[test]
    fn phase20_multi_role_duplicate_pkh_kept_separate() {
        use crate::tx::{p2pkh_script, TxOutput};
        // primary == support pkh: duplicates are allowed but remain 4 separate outputs
        // in canonical order (no aggregation).
        let same = [0x77u8; 20];
        let role = crate::poawx::RoleReward {
            compute_contributor_pkh: [0xC0u8; 20],
            verify_contributor_pkh: [0x7Eu8; 20],
            support_contributor_pkh: same, // == primary
        };
        let total = 5_000_000_000u64;
        let a = crate::poawx::multi_role_amounts(total);
        let outs = vec![
            TxOutput {
                value: a[0],
                script_pubkey: p2pkh_script(&same),
            },
            TxOutput {
                value: a[1],
                script_pubkey: p2pkh_script(&role.compute_contributor_pkh),
            },
            TxOutput {
                value: a[2],
                script_pubkey: p2pkh_script(&role.verify_contributor_pkh),
            },
            TxOutput {
                value: a[3],
                script_pubkey: p2pkh_script(&role.support_contributor_pkh),
            },
        ];
        assert!(validate_multi_role_coinbase_outputs(&outs, &same, &role, total).is_ok());
        // aggregating the duplicate into 3 outputs must be REJECTED (separate required).
        let agg = vec![
            TxOutput {
                value: a[0] + a[3],
                script_pubkey: p2pkh_script(&same),
            },
            TxOutput {
                value: a[1],
                script_pubkey: p2pkh_script(&role.compute_contributor_pkh),
            },
            TxOutput {
                value: a[2],
                script_pubkey: p2pkh_script(&role.verify_contributor_pkh),
            },
        ];
        assert!(validate_multi_role_coinbase_outputs(&agg, &same, &role, total).is_err());
    }

    #[test]
    fn phase20_multi_role_gate_mainnet_off_and_testnet_height() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // mainnet: hard-off even with an activation height set.
        std::env::set_var("IRIUM_NETWORK", "mainnet");
        std::env::set_var("IRIUM_POAWX_MULTI_ROLE_REWARD_ACTIVATION_HEIGHT", "5");
        assert!(!multi_role_reward_active(10), "mainnet must be hard-off");
        // testnet: gated by height.
        std::env::set_var("IRIUM_NETWORK", "testnet");
        assert!(!multi_role_reward_active(4), "below activation height");
        assert!(multi_role_reward_active(5), "at activation height");
        assert!(multi_role_reward_active(6), "above activation height");
        // no activation height -> off.
        std::env::remove_var("IRIUM_POAWX_MULTI_ROLE_REWARD_ACTIVATION_HEIGHT");
        assert!(
            !multi_role_reward_active(100),
            "no activation height -> off"
        );
        std::env::remove_var("IRIUM_NETWORK");
    }

    #[test]
    fn phase20_fairness_matrix_gate_mainnet_off_and_testnet_height() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // mainnet: hard-off even with an activation height set.
        std::env::set_var("IRIUM_NETWORK", "mainnet");
        std::env::set_var("IRIUM_POAWX_FAIRNESS_MATRIX_ACTIVATION_HEIGHT", "8");
        assert!(!fairness_matrix_active(20), "mainnet must be hard-off");
        // testnet: gated by height.
        std::env::set_var("IRIUM_NETWORK", "testnet");
        assert!(!fairness_matrix_active(7), "below activation height");
        assert!(fairness_matrix_active(8), "at activation height");
        assert!(fairness_matrix_active(9), "above activation height");
        // no activation height -> off.
        std::env::remove_var("IRIUM_POAWX_FAIRNESS_MATRIX_ACTIVATION_HEIGHT");
        assert!(!fairness_matrix_active(100), "no activation height -> off");
        std::env::remove_var("IRIUM_NETWORK");
    }

    #[test]
    fn phase20_third_party_fee_gate_mainnet_off_and_testnet() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // mainnet: hard-off (both gate + mode) even with env set.
        std::env::set_var("IRIUM_NETWORK", "mainnet");
        std::env::set_var("IRIUM_POAWX_THIRD_PARTY_FEE_ACTIVATION_HEIGHT", "3");
        std::env::set_var("IRIUM_POAWX_THIRD_PARTY_POOL_MODE", "1");
        assert!(!third_party_fee_active(10), "mainnet fee gate hard-off");
        assert!(!third_party_pool_mode_enabled(), "mainnet mode hard-off");
        // testnet: gated by height + explicit mode.
        std::env::set_var("IRIUM_NETWORK", "testnet");
        assert!(!third_party_fee_active(2), "below activation height");
        assert!(third_party_fee_active(3), "at activation height");
        assert!(third_party_pool_mode_enabled(), "explicit mode on");
        std::env::remove_var("IRIUM_POAWX_THIRD_PARTY_POOL_MODE");
        assert!(!third_party_pool_mode_enabled(), "mode off when unset");
        std::env::remove_var("IRIUM_POAWX_THIRD_PARTY_FEE_ACTIVATION_HEIGHT");
        assert!(!third_party_fee_active(100), "no activation height -> off");
        std::env::remove_var("IRIUM_NETWORK");
    }

    #[test]
    fn phase20_fee_aware_coinbase_payout() {
        use crate::tx::{p2pkh_script, TxOutput};
        let primary = [0xA1u8; 20];
        let role = crate::poawx::RoleReward {
            compute_contributor_pkh: [0xC0u8; 20],
            verify_contributor_pkh: [0x7Eu8; 20],
            support_contributor_pkh: [0x5Au8; 20],
        };
        let fee_pkh = [0xFEu8; 20];
        let total = 5_000_000_001u64; // odd -> remainder
        let p2 = |pkh: &[u8; 20], v: u64| TxOutput {
            value: v,
            script_pubkey: p2pkh_script(pkh),
        };
        let irx1 = || TxOutput {
            value: 0,
            script_pubkey: vec![0x6a, 0x24, b'i', b'r', b'x', b'1'],
        };

        // (a) official, no multi-role: single miner output == total.
        assert!(validate_poawx_coinbase_payout(
            &[irx1(), p2(&primary, total)],
            &primary,
            total,
            None,
            None
        )
        .is_ok());
        // fee output in official mode (fee=None) rejects.
        let (onet, ofee) = crate::poawx::apply_fee(total, 100);
        assert!(validate_poawx_coinbase_payout(
            &[p2(&primary, onet), p2(&fee_pkh, ofee)],
            &primary,
            total,
            None,
            None
        )
        .is_err());

        // (b) third-party fee, no multi-role: [miner_net, fee].
        let bps = crate::poawx::THIRD_PARTY_FEE_CAP_BPS; // 200 = 2%
        let (net, fee) = crate::poawx::apply_fee(total, bps);
        assert_eq!(net + fee, total);
        assert!(validate_poawx_coinbase_payout(
            &[irx1(), p2(&primary, net), p2(&fee_pkh, fee)],
            &primary,
            total,
            None,
            Some((bps, fee_pkh))
        )
        .is_ok());
        // wrong fee amount rejects.
        assert!(validate_poawx_coinbase_payout(
            &[p2(&primary, net), p2(&fee_pkh, fee + 1)],
            &primary,
            total,
            None,
            Some((bps, fee_pkh))
        )
        .is_err());
        // fee_pkh mismatch rejects.
        assert!(validate_poawx_coinbase_payout(
            &[p2(&primary, net), p2(&[0xBBu8; 20], fee)],
            &primary,
            total,
            None,
            Some((bps, fee_pkh))
        )
        .is_err());

        // (c) multi-role + fee: fee from PRIMARY only; roles untouched.
        let a = crate::poawx::multi_role_amounts(total);
        let (pnet, pfee) = crate::poawx::apply_fee(a[0], bps);
        assert!(validate_poawx_coinbase_payout(
            &[
                irx1(),
                p2(&primary, pnet),
                p2(&role.compute_contributor_pkh, a[1]),
                p2(&role.verify_contributor_pkh, a[2]),
                p2(&role.support_contributor_pkh, a[3]),
                p2(&fee_pkh, pfee)
            ],
            &primary,
            total,
            Some(&role),
            Some((bps, fee_pkh))
        )
        .is_ok());
        // taxing a role (compute) instead of staying within primary rejects.
        assert!(validate_poawx_coinbase_payout(
            &[
                p2(&primary, pnet),
                p2(&role.compute_contributor_pkh, a[1] - 1),
                p2(&role.verify_contributor_pkh, a[2]),
                p2(&role.support_contributor_pkh, a[3]),
                p2(&fee_pkh, pfee + 1)
            ],
            &primary,
            total,
            Some(&role),
            Some((bps, fee_pkh))
        )
        .is_err());

        // (d) multi-role official (no fee).
        assert!(validate_poawx_coinbase_payout(
            &[
                p2(&primary, a[0]),
                p2(&role.compute_contributor_pkh, a[1]),
                p2(&role.verify_contributor_pkh, a[2]),
                p2(&role.support_contributor_pkh, a[3])
            ],
            &primary,
            total,
            Some(&role),
            None
        )
        .is_ok());

        // (e) hidden value-bearing non-p2pkh output rejects.
        assert!(validate_poawx_coinbase_payout(
            &[
                p2(&primary, net),
                p2(&fee_pkh, fee),
                TxOutput {
                    value: 1,
                    script_pubkey: vec![0x6a, 0x01, 0x00]
                }
            ],
            &primary,
            total,
            None,
            Some((bps, fee_pkh))
        )
        .unwrap_err()
        .contains("hidden fee"));
    }

    // ── Phase 20: integrated production-block validator + gate ───────────────

    fn p20_claim(
        net: u8,
        height: u64,
        prev: &[u8; 32],
        role_id: u8,
        solver: [u8; 20],
    ) -> crate::poawx::PoawxRoleClaim {
        let lane = crate::poawx::assign_lane(net, height, prev, role_id, 0);
        let nonce = [0x01u8; 32];
        let secret = [0x02u8; 32];
        let cd = crate::poawx::role_claim_digest(
            net,
            height,
            prev,
            role_id,
            lane.id(),
            &solver,
            &nonce,
            &secret,
        );
        crate::poawx::PoawxRoleClaim {
            role_id,
            lane_id: lane.id(),
            solver_pkh: solver,
            nonce,
            secret,
            claim_digest: cd,
            commitment_hash: None,
        }
    }

    fn p20_ext(
        net: u8,
        height: u64,
        prev: &[u8; 32],
        fee_bps: u16,
        fee_pkh: [u8; 20],
    ) -> crate::poawx::Phase20ReceiptExt {
        let c = [0xC1u8; 20];
        let v = [0xC2u8; 20];
        let s = [0xC3u8; 20];
        crate::poawx::Phase20ReceiptExt {
            role_reward: crate::poawx::RoleReward {
                compute_contributor_pkh: c,
                verify_contributor_pkh: v,
                support_contributor_pkh: s,
            },
            compute_claim: p20_claim(net, height, prev, crate::poawx::ROLE_COMPUTE_CONTRIBUTOR, c),
            verify_claim: p20_claim(net, height, prev, crate::poawx::ROLE_VERIFY_CONTRIBUTOR, v),
            support_claim: p20_claim(net, height, prev, crate::poawx::ROLE_SUPPORT_CONTRIBUTOR, s),
            fee_bps,
            fee_pkh,
            precommit_root: None,
            role_ticket_proofs: None,
            role_dominance_weights: None,
            candidate_set: None,
            role_puzzle_proofs: None,
            finality_proof: None,
            committed_admission: None,
            role_assignment_v2: None,
            double_sign_evidence: None,
            ticket_registrations: None,
            dominance_commitment: None,
            adaptive_mode_commitment: None,
        }
    }

    // Build the canonical coinbase outputs for a given ext + total.
    fn p20_coinbase(
        primary: &[u8; 20],
        ext: &crate::poawx::Phase20ReceiptExt,
        total: u64,
    ) -> Vec<crate::tx::TxOutput> {
        use crate::tx::{p2pkh_script, TxOutput};
        let a = crate::poawx::multi_role_amounts(total);
        let (pnet, pfee) = if ext.fee_bps > 0 {
            crate::poawx::apply_fee(a[0], ext.fee_bps)
        } else {
            (a[0], 0)
        };
        let mut outs = vec![
            TxOutput {
                value: 0,
                script_pubkey: vec![0x6a, 0x24, b'i', b'r', b'x', b'1'],
            },
            TxOutput {
                value: pnet,
                script_pubkey: p2pkh_script(primary),
            },
            TxOutput {
                value: a[1],
                script_pubkey: p2pkh_script(&ext.role_reward.compute_contributor_pkh),
            },
            TxOutput {
                value: a[2],
                script_pubkey: p2pkh_script(&ext.role_reward.verify_contributor_pkh),
            },
            TxOutput {
                value: a[3],
                script_pubkey: p2pkh_script(&ext.role_reward.support_contributor_pkh),
            },
        ];
        if ext.fee_bps > 0 {
            outs.push(TxOutput {
                value: pfee,
                script_pubkey: p2pkh_script(&ext.fee_pkh),
            });
        }
        outs
    }

    #[test]
    fn phase20_integrated_production_validator() {
        let net = 1u8;
        let height = 500u64;
        let prev = [0x44u8; 32];
        let primary = [0xA1u8; 20];
        let total = 5_000_000_001u64;

        // (1) official (fee 0): valid integrated block accepted.
        let ext = p20_ext(net, height, &prev, 0, [0u8; 20]);
        let cb = p20_coinbase(&primary, &ext, total);
        assert!(validate_phase20_production_payout(
            &cb, &primary, total, height, &prev, net, &ext, false
        )
        .is_ok());

        // (2) third-party fee (mode on): valid accepted; coinbase has the fee output.
        let fee_pkh = [0xFEu8; 20];
        let extf = p20_ext(net, height, &prev, 200, fee_pkh);
        let cbf = p20_coinbase(&primary, &extf, total);
        assert!(validate_phase20_production_payout(
            &cbf, &primary, total, height, &prev, net, &extf, true
        )
        .is_ok());
        // same fee ext without third-party mode rejects (fee policy).
        assert!(validate_phase20_production_payout(
            &cbf, &primary, total, height, &prev, net, &extf, false
        )
        .is_err());

        // (3) wrong role claim (compute_claim carries the verify role) rejects.
        let mut wrole = ext.clone();
        wrole.compute_claim.role_id = crate::poawx::ROLE_VERIFY_CONTRIBUTOR;
        assert!(validate_phase20_production_payout(
            &cb, &primary, total, height, &prev, net, &wrole, false
        )
        .is_err());

        // (4) tampered claim (lane) rejects.
        let mut wlane = ext.clone();
        wlane.verify_claim.lane_id ^= 0x01;
        assert!(validate_phase20_production_payout(
            &cb, &primary, total, height, &prev, net, &wlane, false
        )
        .is_err());

        // (5) RoleReward pkh != validated claim solver rejects.
        let mut wrr = ext.clone();
        wrr.role_reward.support_contributor_pkh = [0xDEu8; 20];
        let cb_wrr = p20_coinbase(&primary, &wrr, total);
        assert!(validate_phase20_production_payout(
            &cb_wrr, &primary, total, height, &prev, net, &wrr, false
        )
        .unwrap_err()
        .contains("RoleReward pkh"));

        // (6) wrong height/prev rejects (claim digest/assignment differ).
        assert!(validate_phase20_production_payout(
            &cb,
            &primary,
            total,
            height + 1,
            &prev,
            net,
            &ext,
            false
        )
        .is_err());

        // (7) coinbase tamper (wrong primary amount) rejects.
        let mut cb_bad = cb.clone();
        cb_bad[1].value += 1;
        assert!(validate_phase20_production_payout(
            &cb_bad, &primary, total, height, &prev, net, &ext, false
        )
        .is_err());

        // (8) fee output present but ext is official (fee_bps 0) -> count mismatch rejects.
        assert!(validate_phase20_production_payout(
            &cbf, &primary, total, height, &prev, net, &ext, false
        )
        .is_err());

        // (9) fee over cap (201) rejects via fee policy.
        let mut over = p20_ext(net, height, &prev, 201, fee_pkh);
        over.role_reward = ext.role_reward.clone();
        let cb_over = p20_coinbase(&primary, &over, total);
        assert!(validate_phase20_production_payout(
            &cb_over, &primary, total, height, &prev, net, &over, true
        )
        .is_err());
    }

    #[test]
    fn phase20_production_gate_requires_multirole_and_fairness_mainnet_off() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_MULTI_ROLE_REWARD_ACTIVATION_HEIGHT", "5");
        // fairness not yet active -> production gate off.
        std::env::remove_var("IRIUM_POAWX_FAIRNESS_MATRIX_ACTIVATION_HEIGHT");
        assert!(!phase20_production_active(10), "needs fairness too");
        std::env::set_var("IRIUM_POAWX_FAIRNESS_MATRIX_ACTIVATION_HEIGHT", "5");
        assert!(!phase20_production_active(4), "below activation");
        assert!(phase20_production_active(5), "both active at height");
        // mainnet hard-off even with both env set.
        std::env::set_var("IRIUM_NETWORK", "mainnet");
        assert!(!phase20_production_active(10), "mainnet hard-off");
        std::env::remove_var("IRIUM_POAWX_MULTI_ROLE_REWARD_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_FAIRNESS_MATRIX_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_NETWORK");
    }

    #[test]
    fn phase20_connect_block_production_enforcement() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_MODE", "active");
        std::env::set_var("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS", "1");
        std::env::set_var("IRIUM_POAWX_MULTI_ROLE_REWARD_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_FAIRNESS_MATRIX_ACTIVATION_HEIGHT", "1");
        std::env::remove_var("IRIUM_POAWX_THIRD_PARTY_FEE_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_THIRD_PARTY_POOL_MODE");

        let net = crate::activation::network_id_byte();
        let sk = test_signing_key();
        let parent = phase13b_parent_block();
        let parent_hash = parent.header.hash_for_height(0);
        let height = 1u64;
        let total = block_reward(height);
        let base_receipt = make_test_receipt(height, &sk, parent_hash, 1);
        let primary = base_receipt.worker_pkh;

        // Build a valid Phase 20 production block: the receipt carries `ext`, the
        // coinbase is the canonical multi-role (+ optional fee) payout, and the irx1
        // root is the gated-on root over the ext-bearing receipt.
        let build = |ext: &crate::poawx::Phase20ReceiptExt| -> Block {
            let mut receipt = base_receipt.clone();
            receipt.phase20_ext = Some(ext.clone());
            let root = crate::poawx::irx1_root_from_block_receipts_gated(
                std::slice::from_ref(&receipt),
                true,
            );
            let mut irx1_script = vec![0x6a, 0x24u8];
            irx1_script.extend_from_slice(b"irx1");
            irx1_script.extend_from_slice(&root);
            let mut payout = p20_coinbase(&primary, ext, total);
            // Replace the stub irx1 (index 0) with the full 38-byte commitment.
            payout[0] = TxOutput {
                value: 0,
                script_pubkey: irx1_script,
            };
            let coinbase = Transaction {
                version: 1,
                inputs: vec![TxInput {
                    prev_txid: [0u8; 32],
                    prev_index: 0xffff_ffff,
                    script_sig: vec![0x01, 0x00],
                    sequence: 0xffff_ffff,
                }],
                outputs: payout,
                locktime: 0,
            };
            Block {
                header: BlockHeader {
                    version: 1,
                    prev_hash: parent_hash,
                    merkle_root: [0u8; 32],
                    time: 0,
                    bits: 0x207fffff,
                    nonce: 0,
                },
                transactions: vec![coinbase],
                auxpow: None,
                poawx_receipts: Some(vec![receipt]),
            }
        };

        // (13) valid Phase 20 production block accepted.
        let ext = p20_ext(net, height, &parent_hash, 0, [0u8; 20]);
        let ok = build(&ext);
        let r = validate_poawx_block_receipts(&ok, height, Some(&parent));
        assert!(
            r.is_ok(),
            "valid phase20 production block must be accepted: {:?}",
            r
        );

        // (14) bad role claim (compute carries the verify role) rejects.
        let mut e = ext.clone();
        e.compute_claim.role_id = crate::poawx::ROLE_VERIFY_CONTRIBUTOR;
        assert!(
            validate_poawx_block_receipts(&build(&e), height, Some(&parent)).is_err(),
            "bad role claim must reject"
        );

        // (15) RoleReward pkh != validated claim solver rejects.
        let mut e = ext.clone();
        e.role_reward.support_contributor_pkh = [0xDEu8; 20];
        assert!(
            validate_poawx_block_receipts(&build(&e), height, Some(&parent)).is_err(),
            "RoleReward mismatch must reject"
        );

        // (16) wrong coinbase order rejects (swap two p2pkh payout outputs).
        let mut b = build(&ext);
        b.transactions[0].outputs.swap(1, 2);
        assert!(
            validate_poawx_block_receipts(&b, height, Some(&parent)).is_err(),
            "wrong coinbase order must reject"
        );

        // (17) wrong coinbase amount rejects.
        let mut b = build(&ext);
        b.transactions[0].outputs[1].value += 1;
        assert!(
            validate_poawx_block_receipts(&b, height, Some(&parent)).is_err(),
            "wrong coinbase amount must reject"
        );

        // (18) hidden extra value-bearing p2pkh payout rejects (count mismatch).
        let mut b = build(&ext);
        b.transactions[0].outputs.push(TxOutput {
            value: 1,
            script_pubkey: p2pkh_script(&[0x9Au8; 20]),
        });
        assert!(
            validate_poawx_block_receipts(&b, height, Some(&parent)).is_err(),
            "hidden extra payout must reject"
        );

        // (19/20) third-party fee: rejected without mode; accepted with fee gate + mode.
        let fee_pkh = [0xFEu8; 20];
        let extf = p20_ext(net, height, &parent_hash, 200, fee_pkh);
        assert!(
            validate_poawx_block_receipts(&build(&extf), height, Some(&parent)).is_err(),
            "third-party fee without mode must reject"
        );
        std::env::set_var("IRIUM_POAWX_THIRD_PARTY_FEE_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_THIRD_PARTY_POOL_MODE", "1");
        let rf = validate_poawx_block_receipts(&build(&extf), height, Some(&parent));
        assert!(
            rf.is_ok(),
            "third-party fee with gate+mode must be accepted: {:?}",
            rf
        );

        // (21) fee over cap (201 bps) rejects even with mode enabled.
        let over = p20_ext(net, height, &parent_hash, 201, fee_pkh);
        assert!(
            validate_poawx_block_receipts(&build(&over), height, Some(&parent)).is_err(),
            "fee over cap must reject"
        );
        std::env::remove_var("IRIUM_POAWX_THIRD_PARTY_FEE_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_THIRD_PARTY_POOL_MODE");

        // (11) missing extension after activation rejects (root still matches because
        // a no-ext receipt contributes no phase20 digest; the production validator
        // fails closed on the absent extension).
        {
            let mut receipt = base_receipt.clone();
            receipt.phase20_ext = None;
            let root = crate::poawx::irx1_root_from_block_receipts_gated(
                std::slice::from_ref(&receipt),
                true,
            );
            let mut irx1_script = vec![0x6a, 0x24u8];
            irx1_script.extend_from_slice(b"irx1");
            irx1_script.extend_from_slice(&root);
            let worker_due = total * 100 / 1000;
            let coinbase = Transaction {
                version: 1,
                inputs: vec![TxInput {
                    prev_txid: [0u8; 32],
                    prev_index: 0xffff_ffff,
                    script_sig: vec![0x01, 0x00],
                    sequence: 0xffff_ffff,
                }],
                outputs: vec![
                    TxOutput {
                        value: 0,
                        script_pubkey: irx1_script,
                    },
                    TxOutput {
                        value: total - worker_due,
                        script_pubkey: vec![0x51],
                    },
                    TxOutput {
                        value: worker_due,
                        script_pubkey: p2pkh_script(&primary),
                    },
                ],
                locktime: 0,
            };
            let block = Block {
                header: BlockHeader {
                    version: 1,
                    prev_hash: parent_hash,
                    merkle_root: [0u8; 32],
                    time: 0,
                    bits: 0x207fffff,
                    nonce: 0,
                },
                transactions: vec![coinbase],
                auxpow: None,
                poawx_receipts: Some(vec![receipt]),
            };
            let res = validate_poawx_block_receipts(&block, height, Some(&parent));
            assert!(
                res.is_err(),
                "missing extension after activation must reject"
            );
            let msg = res.unwrap_err();
            assert!(msg.contains("missing extension"), "unexpected err: {}", msg);
        }

        // (22) mainnet hard-off: the SAME multi-role block is not production-validated
        // (mainnet skips PoAW-X receipt validation entirely) => no enforcement.
        std::env::set_var("IRIUM_NETWORK", "mainnet");
        assert!(!phase20_production_active(height), "mainnet hard-off");
        assert!(
            validate_poawx_block_receipts(&ok, height, Some(&parent)).is_ok(),
            "mainnet must skip phase20 production enforcement"
        );

        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_MODE");
        std::env::remove_var("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS");
        std::env::remove_var("IRIUM_POAWX_MULTI_ROLE_REWARD_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_FAIRNESS_MATRIX_ACTIVATION_HEIGHT");
    }

    #[test]
    fn phase21c_dominance_weight_enforcement() {
        use crate::poawx_dominance::{RoleRewardKind, DOMINANCE_BASE_WORK_SCORE};
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_ANTI_DOMINATION_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_ANTI_DOMINATION_REQUIRED", "1");
        std::env::set_var("IRIUM_POAWX_ANTI_DOMINATION_WINDOW", "1000");
        std::env::set_var("IRIUM_POAWX_ANTI_DOMINATION_LOOKBACK", "4");
        assert!(
            crate::poawx_dominance::anti_domination_enforced(1),
            "enforced on testnet with gate+required"
        );

        let net = crate::activation::network_id_byte();
        let parent = phase13b_parent_block();
        let parent_hash = parent.header.hash_for_height(0);
        let height = 1u64;
        let sk = signing_key(0x41);
        let ext0 = p20_ext(net, height, &parent_hash, 0, [0u8; 20]);
        let receipt = make_test_receipt(height, &sk, parent_hash, 1);
        let primary = receipt.worker_pkh;

        let mut cs = base_chain(None);
        // give PRIMARY a prior recent reward so its weight drops below the base.
        cs.dominance
            .apply_event(primary, RoleRewardKind::Primary, 5_000, height);

        let pkhs = [
            primary,
            ext0.role_reward.compute_contributor_pkh,
            ext0.role_reward.verify_contributor_pkh,
            ext0.role_reward.support_contributor_pkh,
        ];
        let mut expected = [0u64; 4];
        for (i, p) in pkhs.iter().enumerate() {
            expected[i] = cs.dominance.weight(DOMINANCE_BASE_WORK_SCORE, p, height);
        }
        assert!(
            expected[0] < DOMINANCE_BASE_WORK_SCORE,
            "primary down-weighted by its recent reward"
        );
        assert_eq!(
            expected[1], DOMINANCE_BASE_WORK_SCORE,
            "a fresh role keeps full weight"
        );

        let mk = |weights: Option<[u64; 4]>| -> Block {
            let mut ext = ext0.clone();
            ext.role_dominance_weights = weights;
            let mut r = receipt.clone();
            r.phase20_ext = Some(ext);
            Block {
                header: BlockHeader {
                    version: 1,
                    prev_hash: parent_hash,
                    merkle_root: [0u8; 32],
                    time: 0,
                    bits: 0x207fffff,
                    nonce: 0,
                },
                transactions: vec![],
                auxpow: None,
                poawx_receipts: Some(vec![r]),
            }
        };
        // correct weights accept.
        assert!(
            cs.validate_block_dominance_weights(&mk(Some(expected)), height)
                .is_ok(),
            "node-recomputed weights must accept"
        );
        // wrong weight rejects.
        let mut bad = expected;
        bad[0] = bad[0].wrapping_add(1);
        assert!(
            cs.validate_block_dominance_weights(&mk(Some(bad)), height)
                .is_err(),
            "mismatched weight must reject"
        );
        // missing weights reject (fail closed).
        assert!(
            cs.validate_block_dominance_weights(&mk(None), height)
                .is_err(),
            "missing required weights must reject"
        );

        // mainnet hard-off: enforcement gate is false regardless of env.
        std::env::set_var("IRIUM_NETWORK", "mainnet");
        assert!(
            !crate::poawx_dominance::anti_domination_enforced(1),
            "mainnet hard-off"
        );

        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_ANTI_DOMINATION_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_ANTI_DOMINATION_REQUIRED");
        std::env::remove_var("IRIUM_POAWX_ANTI_DOMINATION_WINDOW");
        std::env::remove_var("IRIUM_POAWX_ANTI_DOMINATION_LOOKBACK");
    }

    #[test]
    fn phase22e_wrong_candidate_score_rejects() {
        // (26) a block whose candidate digest does NOT equal the VRF output is rejected
        // by validate_block_true_vrf, even with a self-valid AVR2 proof attached.
        use crate::poawx::{
            ROLE_COMPUTE_CONTRIBUTOR, ROLE_SUPPORT_CONTRIBUTOR, ROLE_VERIFY_CONTRIBUTOR,
        };
        use crate::poawx_candidate::{AssignmentProofV2, CandidateSet, RoleCandidate};
        use crate::poawx_penalty::PenaltyStatus;
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_TRUE_VRF_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_TRUE_VRF_REQUIRED", "1");
        let net = crate::activation::network_id_byte();
        let height = 1u64;
        let seed = [0x44u8; 32];
        let sk = test_signing_key();
        let base_ext = p20_ext(net, height, &seed, 0, [0u8; 20]);
        let receipt = make_test_receipt(height, &sk, seed, 1);
        let mk = |secret: u8,
                  role: u8,
                  solver: [u8; 20],
                  ticket: [u8; 32]|
         -> (AssignmentProofV2, RoleCandidate) {
            let p =
                AssignmentProofV2::prove(&[secret; 32], net, height, role, solver, ticket, seed)
                    .expect("v2 prove");
            let c =
                RoleCandidate::from_assignment_v2(&p, PenaltyStatus::Clean.id(), 1000, [role; 32]);
            (p, c)
        };
        let (pc, mut cc) = mk(7, ROLE_COMPUTE_CONTRIBUTOR, [0xC1u8; 20], [0x11u8; 32]);
        let (pv, cv) = mk(8, ROLE_VERIFY_CONTRIBUTOR, [0xC2u8; 20], [0x12u8; 32]);
        let (ps, csup) = mk(9, ROLE_SUPPORT_CONTRIBUTOR, [0xC3u8; 20], [0x13u8; 32]);
        // tamper: candidate digest no longer equals the VRF output.
        cc.assignment_proof_digest[0] ^= 1;
        let mut cs = CandidateSet::new(net, height, seed);
        for c in [cc, cv, csup] {
            cs.push(c);
        }
        cs.sort_canonical();
        let mut ext = base_ext.clone();
        ext.role_reward.compute_contributor_pkh = [0xC1u8; 20];
        ext.role_reward.verify_contributor_pkh = [0xC2u8; 20];
        ext.role_reward.support_contributor_pkh = [0xC3u8; 20];
        ext.candidate_set = Some(cs);
        ext.role_assignment_v2 = Some([pc, pv, ps]);
        let mut r = receipt.clone();
        r.phase20_ext = Some(ext);
        let blk = Block {
            header: BlockHeader {
                version: 1,
                prev_hash: seed,
                merkle_root: [0u8; 32],
                time: 0,
                bits: 0x207fffff,
                nonce: 0,
            },
            transactions: vec![],
            auxpow: None,
            poawx_receipts: Some(vec![r]),
        };
        let st = base_chain(None);
        assert!(
            st.validate_block_true_vrf(&blk, height).is_err(),
            "candidate score not derived from VRF output -> reject"
        );
        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_TRUE_VRF_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_TRUE_VRF_REQUIRED");
    }

    #[test]
    fn phase22e_true_vrf_e2e_block() {
        // End-to-end: with candidate-set + admission + true-VRF ALL enforced, a block
        // carrying V2 candidates (digest = VRF output) + the AVR2 section must satisfy
        // BOTH validate_block_candidate_sets (V1 recompute skipped under the gate) AND
        // validate_block_true_vrf. Proves the Phase 22E reconciliation.
        use crate::poawx::{
            ROLE_COMPUTE_CONTRIBUTOR, ROLE_SUPPORT_CONTRIBUTOR, ROLE_VERIFY_CONTRIBUTOR,
        };
        use crate::poawx_admission::{
            candidate_admission_enforced, global_admission_cache, CandidateAdmissionV1,
        };
        use crate::poawx_candidate::{AssignmentProofV2, CandidateSet, RoleCandidate};
        use crate::poawx_penalty::PenaltyStatus;
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_CANDIDATE_SET_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_CANDIDATE_SET_REQUIRED", "1");
        std::env::set_var("IRIUM_POAWX_ASSIGNMENT_PROOF_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_ASSIGNMENT_PROOF_REQUIRED", "1");
        std::env::set_var("IRIUM_POAWX_CANDIDATE_ADMISSION_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_CANDIDATE_ADMISSION_REQUIRED", "1");
        std::env::set_var("IRIUM_POAWX_TRUE_VRF_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_TRUE_VRF_REQUIRED", "1");

        let net = crate::activation::network_id_byte();
        let height = 1u64;
        let seed = [0x44u8; 32];
        let sk = test_signing_key();
        let base_ext = p20_ext(net, height, &seed, 0, [0u8; 20]);
        let receipt = make_test_receipt(height, &sk, seed, 1);

        let mk = |secret: u8,
                  role: u8,
                  solver: [u8; 20],
                  ticket: [u8; 32]|
         -> (AssignmentProofV2, RoleCandidate) {
            let p =
                AssignmentProofV2::prove(&[secret; 32], net, height, role, solver, ticket, seed)
                    .expect("v2 prove");
            let c =
                RoleCandidate::from_assignment_v2(&p, PenaltyStatus::Clean.id(), 1000, [role; 32]);
            (p, c)
        };
        let (pc, cc) = mk(7, ROLE_COMPUTE_CONTRIBUTOR, [0xC1u8; 20], [0x11u8; 32]);
        let (pv, cv) = mk(8, ROLE_VERIFY_CONTRIBUTOR, [0xC2u8; 20], [0x12u8; 32]);
        let (ps, csup) = mk(9, ROLE_SUPPORT_CONTRIBUTOR, [0xC3u8; 20], [0x13u8; 32]);

        // Node ingest: the global admission cache accepts the valid V2 admissions
        // (and rejects a mutated one), exactly as the loopback RPC bridge would.
        let cache = global_admission_cache();
        cache.clear();
        cache.set_tip(height);
        assert!(candidate_admission_enforced(height));
        for (p, c) in [(&pc, &cc), (&pv, &cv), (&ps, &csup)] {
            let adm =
                CandidateAdmissionV1::new_with_v2(net, height, seed, c.clone(), Some(p.clone()));
            assert!(adm.validate(net, height).is_ok());
            assert_eq!(
                cache.ingest_bytes(&adm.serialize()),
                crate::poawx_gossip::GossipOutcome::AcceptedNew
            );
        }
        // a mutated V2 admission is rejected at ingest.
        let mut bad =
            CandidateAdmissionV1::new_with_v2(net, height, seed, cc.clone(), Some(pc.clone()));
        bad.assignment_proof_v2.as_mut().unwrap().vrf_output[0] ^= 1;
        bad.digest = crate::poawx_admission::CandidateAdmissionV1::new_with_v2(
            net,
            height,
            seed,
            cc.clone(),
            bad.assignment_proof_v2.clone(),
        )
        .digest;
        assert!(matches!(
            cache.ingest_bytes(&bad.serialize()),
            crate::poawx_gossip::GossipOutcome::Rejected(_)
        ));

        // The candidate set the node admitted == what we build for the block ext.
        let admitted = cache.admitted_candidate_set(net, height, &seed);
        let mut cs = CandidateSet::new(net, height, seed);
        for c in [cc, cv, csup] {
            cs.push(c);
        }
        cs.sort_canonical();
        assert_eq!(
            cs.serialize(),
            admitted.serialize(),
            "block cs == node admitted set"
        );

        let blk = |with_v2: bool| -> Block {
            let mut ext = base_ext.clone();
            ext.role_reward.compute_contributor_pkh = [0xC1u8; 20];
            ext.role_reward.verify_contributor_pkh = [0xC2u8; 20];
            ext.role_reward.support_contributor_pkh = [0xC3u8; 20];
            ext.candidate_set = Some(cs.clone());
            ext.role_assignment_v2 = if with_v2 {
                Some([pc.clone(), pv.clone(), ps.clone()])
            } else {
                None
            };
            let mut r = receipt.clone();
            r.phase20_ext = Some(ext);
            Block {
                header: BlockHeader {
                    version: 1,
                    prev_hash: seed,
                    merkle_root: [0u8; 32],
                    time: 0,
                    bits: 0x207fffff,
                    nonce: 0,
                },
                transactions: vec![],
                auxpow: None,
                poawx_receipts: Some(vec![r]),
            }
        };

        let st = base_chain(None);
        let good = blk(true);
        // V2 candidates satisfy candidate-set validation (V1 recompute skipped) ...
        assert!(
            st.validate_block_candidate_sets(&good, height).is_ok(),
            "candidate-set validation accepts V2 candidates"
        );
        // ... and the true-VRF section validates against the selected candidates.
        assert!(
            st.validate_block_true_vrf(&good, height).is_ok(),
            "true-VRF validation accepts the AVR2 section"
        );
        // A V1-only block (no AVR2) is rejected under V2 enforcement.
        assert!(
            st.validate_block_true_vrf(&blk(false), height).is_err(),
            "V1-only block rejected when V2 required"
        );

        cache.clear();
        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_CANDIDATE_SET_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_CANDIDATE_SET_REQUIRED");
        std::env::remove_var("IRIUM_POAWX_ASSIGNMENT_PROOF_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_ASSIGNMENT_PROOF_REQUIRED");
        std::env::remove_var("IRIUM_POAWX_CANDIDATE_ADMISSION_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_CANDIDATE_ADMISSION_REQUIRED");
        std::env::remove_var("IRIUM_POAWX_TRUE_VRF_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_TRUE_VRF_REQUIRED");
    }

    #[test]
    #[test]
    fn phase24k_native_pow_all_gates_validators() {
        // Phase 24K Stage 1: build ONE PoAW-X block at height 1 over the real
        // locked genesis, carrying EVERY gate section, MINE it with Irium's
        // actual PoW hash (the same `hash_for_height` path the node validator
        // uses), then assert each AUTHORITATIVE node validator accepts it:
        //   - validate_block_header        (real Irium PoW + bits + merkle)
        //   - validate_block_dominance_weights
        //   - validate_block_candidate_sets (candidate set + admission match)
        //   - validate_block_puzzle_proofs
        //   - validate_block_finality      (SUPPORT committee proof)
        //   - validate_block_committed_admission
        //   - validate_block_true_vrf      (AVR2 ECVRF)
        //   - validate_poawx_coinbase_payout (canonical 0% fee split)
        // Plus the E13-E18 negatives. No validator is weakened; no PoW bypass.
        use crate::poawx::{
            multi_role_amounts, ROLE_COMPUTE_CONTRIBUTOR, ROLE_SUPPORT_CONTRIBUTOR,
            ROLE_VERIFY_CONTRIBUTOR,
        };
        use crate::poawx_admission::{global_admission_cache, CandidateAdmissionV1};
        use crate::poawx_candidate::{AssignmentProofV2, CandidateSet, RoleCandidate};
        use crate::poawx_committed_admission::AdmissionCommitmentV1;
        use crate::poawx_dominance::DOMINANCE_BASE_WORK_SCORE;
        use crate::poawx_finality::{FinalityProofV1, FinalityVoteType, FinalityVoteV1};
        use crate::poawx_penalty::PenaltyStatus;
        use crate::poawx_puzzle::{
            default_profile, solve_dev, PuzzleChallengeV1, PuzzleSolutionV1,
        };
        use sha2::{Digest, Sha256};

        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "devnet");
        for (k, v) in [
            ("IRIUM_POAWX_ANTI_DOMINATION_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_ANTI_DOMINATION_REQUIRED", "1"),
            ("IRIUM_POAWX_CANDIDATE_SET_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_CANDIDATE_SET_REQUIRED", "1"),
            ("IRIUM_POAWX_ASSIGNMENT_PROOF_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_ASSIGNMENT_PROOF_REQUIRED", "1"),
            ("IRIUM_POAWX_CANDIDATE_ADMISSION_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_CANDIDATE_ADMISSION_REQUIRED", "1"),
            ("IRIUM_POAWX_PUZZLE_WORK_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_PUZZLE_WORK_REQUIRED", "1"),
            ("IRIUM_POAWX_PUZZLE_BITS", "4"),
            ("IRIUM_POAWX_FINALITY_COMMITTEE_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_FINALITY_COMMITTEE_REQUIRED", "1"),
            ("IRIUM_POAWX_FINALITY_THRESHOLD_NUM", "1"),
            ("IRIUM_POAWX_FINALITY_THRESHOLD_DEN", "1"),
            ("IRIUM_POAWX_COMMITTED_ADMISSION_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_COMMITTED_ADMISSION_REQUIRED", "1"),
            ("IRIUM_POAWX_TRUE_VRF_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_TRUE_VRF_REQUIRED", "1"),
        ] {
            std::env::set_var(k, v);
        }

        // Real locked genesis (same source base_chain uses) -> the parent.
        let locked = load_locked_genesis().expect("locked genesis");
        let genesis = block_from_locked(&locked).expect("genesis block");
        let genesis_hash = genesis.header.hash_for_height(0);
        let seed = genesis_hash; // every gate binds the seed to the block's prev_hash.

        let st = base_chain(None);
        let net = crate::activation::network_id_byte();
        let height = 1u64;
        let target = st.target_for_height(height);

        // Identities. The SUPPORT solver MUST be hash160(finality member pubkey)
        // so the committee finality vote validates.
        let worker_sk = signing_key(0x55);
        let worker_pkh = key_hash(&worker_sk);
        let member_sk = signing_key(0xC3); // finality committee member (SUPPORT)
        let support_solver = key_hash(&member_sk);
        let compute_solver = [0xC1u8; 20];
        let verify_solver = [0xC2u8; 20];

        // Per-role dominance weight the node expects from PERSISTED state.
        let dw = |pkh: &[u8; 20]| st.dominance.weight(DOMINANCE_BASE_WORK_SCORE, pkh, height);

        // V2 (true-VRF) proofs + candidates for the three roles.
        let mk = |secret: u8,
                  role: u8,
                  solver: [u8; 20],
                  ticket: [u8; 32]|
         -> (AssignmentProofV2, RoleCandidate) {
            let p =
                AssignmentProofV2::prove(&[secret; 32], net, height, role, solver, ticket, seed)
                    .expect("v2 prove");
            let c = RoleCandidate::from_assignment_v2(
                &p,
                PenaltyStatus::Clean.id(),
                dw(&solver),
                [role; 32],
            );
            (p, c)
        };
        let (pc, cc) = mk(7, ROLE_COMPUTE_CONTRIBUTOR, compute_solver, [0x11u8; 32]);
        let (pv, cv) = mk(8, ROLE_VERIFY_CONTRIBUTOR, verify_solver, [0x12u8; 32]);
        let (ps, csup) = mk(9, ROLE_SUPPORT_CONTRIBUTOR, support_solver, [0x13u8; 32]);

        // Candidate set for height 1, seed = genesis hash.
        let mut cs = CandidateSet::new(net, height, seed);
        for c in [cc.clone(), cv.clone(), csup.clone()] {
            cs.push(c);
        }
        cs.sort_canonical();

        // Prime the node admission cache exactly as the loopback RPC bridge would.
        let cache = global_admission_cache();
        cache.clear();
        cache.set_tip(height);
        for (p, c) in [(&pc, &cc), (&pv, &cv), (&ps, &csup)] {
            let adm =
                CandidateAdmissionV1::new_with_v2(net, height, seed, c.clone(), Some(p.clone()));
            assert!(adm.validate(net, height).is_ok());
            assert_eq!(
                cache.ingest_bytes(&adm.serialize()),
                crate::poawx_gossip::GossipOutcome::AcceptedNew
            );
        }
        assert_eq!(
            cs.serialize(),
            cache.admitted_candidate_set(net, height, &seed).serialize(),
            "block candidate set == node admitted set"
        );

        // Puzzle solutions for the selected (best) candidate of each role.
        let profile = default_profile();
        let mut sols: Vec<PuzzleSolutionV1> = Vec::new();
        for role in [
            ROLE_COMPUTE_CONTRIBUTOR,
            ROLE_VERIFY_CONTRIBUTOR,
            ROLE_SUPPORT_CONTRIBUTOR,
        ] {
            let cand = cs.best_for_role(role).expect("best candidate");
            let cdg: [u8; 32] = {
                let mut h = Sha256::new();
                h.update(cand.serialize());
                h.finalize().into()
            };
            let challenge = PuzzleChallengeV1::build(
                net,
                height,
                role,
                cand.solver_pkh,
                cand.ticket_digest,
                cand.assignment_proof_digest,
                cdg,
                seed,
                profile,
            );
            sols.push(solve_dev(&challenge).expect("solve puzzle"));
        }
        let puzzle_proofs = [sols[0], sols[1], sols[2]];

        // SUPPORT-committee finality proof finalizing the parent (block_hash = prev_hash).
        let committee: Vec<[u8; 20]> = cs
            .candidates
            .iter()
            .filter(|c| c.role_id == ROLE_SUPPORT_CONTRIBUTOR)
            .map(|c| c.solver_pkh)
            .collect();
        let mut fproof = FinalityProofV1::new(net, height, genesis_hash, [0u8; 32], 0, 1, 1);
        fproof.push(FinalityVoteV1::signed(
            &member_sk,
            net,
            height,
            genesis_hash,
            [0u8; 32],
            0,
            [0x11u8; 32],
            FinalityVoteType::Commit,
        ));
        fproof.sort_canonical();
        assert!(
            fproof
                .validate(net, height, &genesis_hash, &committee)
                .is_ok(),
            "finality proof self-check"
        );

        // OUTGOING committed-admission commitment for H+1=2 (incoming is graced
        // at the activation height). Self-consistent: commit_height = H, seed =
        // this block's prev_hash.
        let mut cs2 = CandidateSet::new(net, height + 1, seed);
        for c in [cc.clone(), cv.clone(), csup.clone()] {
            cs2.push(c);
        }
        cs2.sort_canonical();
        let commitment = AdmissionCommitmentV1::from_candidate_set(&cs2, height);

        // Assemble the all-gates ext.
        let total = block_reward(height);
        let mut ext = p20_ext(net, height, &seed, 0, [0u8; 20]);
        ext.role_reward.compute_contributor_pkh = compute_solver;
        ext.role_reward.verify_contributor_pkh = verify_solver;
        ext.role_reward.support_contributor_pkh = support_solver;
        ext.support_claim = p20_claim(net, height, &seed, ROLE_SUPPORT_CONTRIBUTOR, support_solver);
        ext.role_dominance_weights = Some([
            dw(&worker_pkh),
            dw(&compute_solver),
            dw(&verify_solver),
            dw(&support_solver),
        ]);
        ext.candidate_set = Some(cs.clone());
        ext.role_puzzle_proofs = Some(puzzle_proofs);
        ext.finality_proof = Some(fproof.clone());
        ext.committed_admission = Some(commitment.clone());
        ext.role_assignment_v2 = Some([pc.clone(), pv.clone(), ps.clone()]);

        // Receipt + canonical 0%-fee coinbase.
        let mut receipt = make_test_receipt(height, &worker_sk, genesis_hash, 1);
        receipt.phase20_ext = Some(ext.clone());
        let coinbase = crate::tx::Transaction {
            version: 1,
            inputs: vec![crate::tx::TxInput {
                prev_txid: [0u8; 32],
                prev_index: 0xffff_ffff,
                script_sig: vec![0x01, 0x00],
                sequence: 0xffff_ffff,
            }],
            outputs: p20_coinbase(&worker_pkh, &ext, total),
            locktime: 0,
        };

        let mut block = Block {
            header: BlockHeader {
                version: 1,
                prev_hash: genesis_hash,
                merkle_root: [0u8; 32],
                time: genesis.header.time + 1,
                bits: target.bits,
                nonce: 0,
            },
            transactions: vec![coinbase],
            auxpow: None,
            poawx_receipts: Some(vec![receipt]),
        };
        block.header.merkle_root = block.merkle_root();

        // MINE Irium's REAL PoW (Irium-native hash, NOT stock-cpuminer sha256d).
        let nonce =
            crate::poawx_mining_harness::mine_pow(&mut block.header, height, target, 50_000_000)
                .expect("mine real Irium PoW");
        assert!(
            crate::pow::meets_target(&block.header.hash_for_height(height), target),
            "mined header satisfies Irium PoW target (nonce={nonce})"
        );

        // ===== authoritative validators accept the mined all-gates block =====
        assert!(
            st.validate_block_header(&block, height, Some(&genesis))
                .is_ok(),
            "header (real PoW + bits + merkle) accepts"
        );
        assert!(
            st.validate_block_dominance_weights(&block, height).is_ok(),
            "dominance/fairness weights accept"
        );
        assert!(
            st.validate_block_candidate_sets(&block, height).is_ok(),
            "candidate set + admission accept"
        );
        assert!(
            st.validate_block_puzzle_proofs(&block, height).is_ok(),
            "puzzle proofs accept"
        );
        assert!(
            st.validate_block_finality(&block, height).is_ok(),
            "finality committee proof accepts"
        );
        assert!(
            st.validate_block_committed_admission(&block, Some(&genesis), height)
                .is_ok(),
            "committed admission accepts"
        );
        assert!(
            st.validate_block_true_vrf(&block, height).is_ok(),
            "true-VRF (AVR2) accepts"
        );
        // canonical 0% official-fee payout.
        assert!(
            validate_poawx_coinbase_payout(
                &block.transactions[0].outputs,
                &worker_pkh,
                total,
                Some(&ext.role_reward),
                None,
            )
            .is_ok(),
            "official 0% role-reward coinbase payout accepts"
        );

        // ===== negatives (E13-E17): each missing/wrong section rejects =====
        let neg = |mutate: &dyn Fn(&mut crate::poawx::Phase20ReceiptExt)| -> Block {
            let mut e = ext.clone();
            mutate(&mut e);
            let mut r = make_test_receipt(height, &worker_sk, genesis_hash, 1);
            r.phase20_ext = Some(e);
            let mut b = block.clone();
            b.poawx_receipts = Some(vec![r]);
            b
        };
        // E13: missing V2 assignment proofs.
        assert!(
            st.validate_block_true_vrf(&neg(&|e| e.role_assignment_v2 = None), height)
                .is_err(),
            "missing AVR2 rejects"
        );
        // E14: missing finality proof.
        assert!(
            st.validate_block_finality(&neg(&|e| e.finality_proof = None), height)
                .is_err(),
            "missing finality rejects"
        );
        // E15: missing puzzle proofs.
        assert!(
            st.validate_block_puzzle_proofs(&neg(&|e| e.role_puzzle_proofs = None), height)
                .is_err(),
            "missing puzzle rejects"
        );
        // E16: wrong role solver (support != best admitted candidate).
        assert!(
            st.validate_block_candidate_sets(
                &neg(&|e| e.role_reward.support_contributor_pkh = [0xEEu8; 20]),
                height
            )
            .is_err(),
            "wrong role solver rejects"
        );
        // E17: wrong committed-admission freeze seed.
        assert!(
            st.validate_block_committed_admission(
                &neg(&|e| {
                    let mut c = commitment.clone();
                    c.seed = [0xABu8; 32];
                    e.committed_admission = Some(c);
                }),
                Some(&genesis),
                height
            )
            .is_err(),
            "wrong committed-admission seed rejects"
        );

        cache.clear();
        for k in [
            "IRIUM_NETWORK",
            "IRIUM_POAWX_ANTI_DOMINATION_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_ANTI_DOMINATION_REQUIRED",
            "IRIUM_POAWX_CANDIDATE_SET_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_CANDIDATE_SET_REQUIRED",
            "IRIUM_POAWX_ASSIGNMENT_PROOF_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_ASSIGNMENT_PROOF_REQUIRED",
            "IRIUM_POAWX_CANDIDATE_ADMISSION_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_CANDIDATE_ADMISSION_REQUIRED",
            "IRIUM_POAWX_PUZZLE_WORK_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_PUZZLE_WORK_REQUIRED",
            "IRIUM_POAWX_PUZZLE_BITS",
            "IRIUM_POAWX_FINALITY_COMMITTEE_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_FINALITY_COMMITTEE_REQUIRED",
            "IRIUM_POAWX_FINALITY_THRESHOLD_NUM",
            "IRIUM_POAWX_FINALITY_THRESHOLD_DEN",
            "IRIUM_POAWX_COMMITTED_ADMISSION_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_COMMITTED_ADMISSION_REQUIRED",
            "IRIUM_POAWX_TRUE_VRF_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_TRUE_VRF_REQUIRED",
        ] {
            std::env::remove_var(k);
        }
    }

    #[test]
    fn phase24k_native_pow_all_gates_connect_block() {
        // Phase 24K Stage 2: the FULL node entry point. Build a mined all-gates
        // block at height 1 over the real locked genesis and drive the entire
        // `connect_block` pipeline (header PoW -> irx1 coinbase -> receipts +
        // production payout -> dominance -> candidate set + admission -> puzzle
        // -> finality -> committed admission -> true-VRF -> apply txns) to
        // acceptance, then confirm the chain advanced to height 2.
        //
        // Covers the connect_block-INTEGRATED gates with material built here.
        // The independent hidden-precommit, ticket-proof, and mode-1 delegation
        // gates are left OFF (each has its own dedicated tests); leaving an
        // optional gate disabled does not weaken the gates under test.
        use crate::poawx::{
            irx1_root_from_block_receipts_gated, multi_role_amounts, ROLE_COMPUTE_CONTRIBUTOR,
            ROLE_SUPPORT_CONTRIBUTOR, ROLE_VERIFY_CONTRIBUTOR,
        };
        use crate::poawx_admission::{global_admission_cache, CandidateAdmissionV1};
        use crate::poawx_candidate::{AssignmentProofV2, CandidateSet, RoleCandidate};
        use crate::poawx_committed_admission::AdmissionCommitmentV1;
        use crate::poawx_dominance::DOMINANCE_BASE_WORK_SCORE;
        use crate::poawx_finality::{FinalityProofV1, FinalityVoteType, FinalityVoteV1};
        use crate::poawx_penalty::PenaltyStatus;
        use crate::poawx_puzzle::{
            default_profile, solve_dev, PuzzleChallengeV1, PuzzleSolutionV1,
        };
        use sha2::{Digest, Sha256};

        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "devnet");
        for (k, v) in [
            ("IRIUM_POAWX_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_MODE", "active"),
            ("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS", "4"), // receipt PoW difficulty
            ("IRIUM_POAWX_PUZZLE_BITS", "4"),            // assigned-puzzle gate difficulty
            ("IRIUM_POAWX_MULTI_ROLE_REWARD_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_FAIRNESS_MATRIX_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_ANTI_DOMINATION_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_ANTI_DOMINATION_REQUIRED", "1"),
            ("IRIUM_POAWX_CANDIDATE_SET_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_CANDIDATE_SET_REQUIRED", "1"),
            ("IRIUM_POAWX_ASSIGNMENT_PROOF_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_ASSIGNMENT_PROOF_REQUIRED", "1"),
            ("IRIUM_POAWX_CANDIDATE_ADMISSION_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_CANDIDATE_ADMISSION_REQUIRED", "1"),
            ("IRIUM_POAWX_PUZZLE_WORK_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_PUZZLE_WORK_REQUIRED", "1"),
            ("IRIUM_POAWX_FINALITY_COMMITTEE_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_FINALITY_COMMITTEE_REQUIRED", "1"),
            ("IRIUM_POAWX_FINALITY_THRESHOLD_NUM", "1"),
            ("IRIUM_POAWX_FINALITY_THRESHOLD_DEN", "1"),
            ("IRIUM_POAWX_COMMITTED_ADMISSION_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_COMMITTED_ADMISSION_REQUIRED", "1"),
            ("IRIUM_POAWX_TRUE_VRF_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_TRUE_VRF_REQUIRED", "1"),
        ] {
            std::env::set_var(k, v);
        }

        let locked = load_locked_genesis().expect("locked genesis");
        let genesis = block_from_locked(&locked).expect("genesis block");
        let genesis_hash = genesis.header.hash_for_height(0);
        let seed = genesis_hash;

        let mut st = base_chain(None);
        let net = crate::activation::network_id_byte();
        let height = 1u64;
        let target = st.target_for_height(height);

        let worker_sk = signing_key(0x55);
        let worker_pkh = key_hash(&worker_sk);
        let member_sk = signing_key(0xC3);
        let support_solver = key_hash(&member_sk);
        let compute_solver = [0xC1u8; 20];
        let verify_solver = [0xC2u8; 20];

        let dw = |pkh: &[u8; 20]| st.dominance.weight(DOMINANCE_BASE_WORK_SCORE, pkh, height);

        let mk = |secret: u8,
                  role: u8,
                  solver: [u8; 20],
                  ticket: [u8; 32]|
         -> (AssignmentProofV2, RoleCandidate) {
            let p =
                AssignmentProofV2::prove(&[secret; 32], net, height, role, solver, ticket, seed)
                    .expect("v2 prove");
            let c = RoleCandidate::from_assignment_v2(
                &p,
                PenaltyStatus::Clean.id(),
                dw(&solver),
                [role; 32],
            );
            (p, c)
        };
        let (pc, cc) = mk(7, ROLE_COMPUTE_CONTRIBUTOR, compute_solver, [0x11u8; 32]);
        let (pv, cv) = mk(8, ROLE_VERIFY_CONTRIBUTOR, verify_solver, [0x12u8; 32]);
        let (ps, csup) = mk(9, ROLE_SUPPORT_CONTRIBUTOR, support_solver, [0x13u8; 32]);

        let mut cs = CandidateSet::new(net, height, seed);
        for c in [cc.clone(), cv.clone(), csup.clone()] {
            cs.push(c);
        }
        cs.sort_canonical();

        let cache = global_admission_cache();
        cache.clear();
        cache.set_tip(height);
        for (p, c) in [(&pc, &cc), (&pv, &cv), (&ps, &csup)] {
            let adm =
                CandidateAdmissionV1::new_with_v2(net, height, seed, c.clone(), Some(p.clone()));
            assert_eq!(
                cache.ingest_bytes(&adm.serialize()),
                crate::poawx_gossip::GossipOutcome::AcceptedNew
            );
        }

        let profile = default_profile();
        let mut sols: Vec<PuzzleSolutionV1> = Vec::new();
        for role in [
            ROLE_COMPUTE_CONTRIBUTOR,
            ROLE_VERIFY_CONTRIBUTOR,
            ROLE_SUPPORT_CONTRIBUTOR,
        ] {
            let cand = cs.best_for_role(role).expect("best candidate");
            let cdg: [u8; 32] = {
                let mut h = Sha256::new();
                h.update(cand.serialize());
                h.finalize().into()
            };
            let challenge = PuzzleChallengeV1::build(
                net,
                height,
                role,
                cand.solver_pkh,
                cand.ticket_digest,
                cand.assignment_proof_digest,
                cdg,
                seed,
                profile,
            );
            sols.push(solve_dev(&challenge).expect("solve puzzle"));
        }
        let puzzle_proofs = [sols[0], sols[1], sols[2]];

        let committee: Vec<[u8; 20]> = cs
            .candidates
            .iter()
            .filter(|c| c.role_id == ROLE_SUPPORT_CONTRIBUTOR)
            .map(|c| c.solver_pkh)
            .collect();
        let mut fproof = FinalityProofV1::new(net, height, genesis_hash, [0u8; 32], 0, 1, 1);
        fproof.push(FinalityVoteV1::signed(
            &member_sk,
            net,
            height,
            genesis_hash,
            [0u8; 32],
            0,
            [0x11u8; 32],
            FinalityVoteType::Commit,
        ));
        fproof.sort_canonical();

        let mut cs2 = CandidateSet::new(net, height + 1, seed);
        for c in [cc.clone(), cv.clone(), csup.clone()] {
            cs2.push(c);
        }
        cs2.sort_canonical();
        let commitment = AdmissionCommitmentV1::from_candidate_set(&cs2, height);

        let total = block_reward(height);
        let mut ext = p20_ext(net, height, &seed, 0, [0u8; 20]);
        ext.role_reward.compute_contributor_pkh = compute_solver;
        ext.role_reward.verify_contributor_pkh = verify_solver;
        ext.role_reward.support_contributor_pkh = support_solver;
        ext.support_claim = p20_claim(net, height, &seed, ROLE_SUPPORT_CONTRIBUTOR, support_solver);
        ext.role_dominance_weights = Some([
            dw(&worker_pkh),
            dw(&compute_solver),
            dw(&verify_solver),
            dw(&support_solver),
        ]);
        ext.candidate_set = Some(cs.clone());
        ext.role_puzzle_proofs = Some(puzzle_proofs);
        ext.finality_proof = Some(fproof);
        ext.committed_admission = Some(commitment);
        ext.role_assignment_v2 = Some([pc, pv, ps]);

        let mut receipt = make_test_receipt(height, &worker_sk, genesis_hash, 4);
        receipt.phase20_ext = Some(ext.clone());

        // Coinbase: canonical 0%-fee role payout + the gated irx1 root (ext bound).
        let receipts = vec![receipt];
        let irx1_root = irx1_root_from_block_receipts_gated(&receipts, true);
        assert_ne!(irx1_root, [0u8; 32], "gated irx1 root is non-zero");
        let mut outputs = p20_coinbase(&worker_pkh, &ext, total);
        let mut irx1_script = vec![0x6a, 0x24u8];
        irx1_script.extend_from_slice(b"irx1");
        irx1_script.extend_from_slice(&irx1_root);
        outputs[0].script_pubkey = irx1_script; // replace the placeholder OP_RETURN
        let coinbase = crate::tx::Transaction {
            version: 1,
            inputs: vec![crate::tx::TxInput {
                prev_txid: [0u8; 32],
                prev_index: 0xffff_ffff,
                script_sig: vec![0x01, 0x00],
                sequence: 0xffff_ffff,
            }],
            outputs,
            locktime: 0,
        };
        // sanity: canonical 0% payout self-checks.
        let _ = multi_role_amounts(total);

        let mut block = Block {
            header: BlockHeader {
                version: 1,
                prev_hash: genesis_hash,
                merkle_root: [0u8; 32],
                time: genesis.header.time + 1,
                bits: target.bits,
                nonce: 0,
            },
            transactions: vec![coinbase],
            auxpow: None,
            poawx_receipts: Some(receipts),
        };
        block.header.merkle_root = block.merkle_root();

        // MINE Irium's real PoW.
        crate::poawx_mining_harness::mine_pow(&mut block.header, height, target, 50_000_000)
            .expect("mine real Irium PoW");

        // FULL node entry point: connect_block validates every section + applies.
        let before = st.height;
        st.connect_block(block)
            .expect("connect_block accepts mined all-gates block");
        assert_eq!(st.height, before + 1, "chain advanced to height 2");

        cache.clear();
        for k in [
            "IRIUM_NETWORK",
            "IRIUM_POAWX_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_MODE",
            "IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS",
            "IRIUM_POAWX_PUZZLE_BITS",
            "IRIUM_POAWX_MULTI_ROLE_REWARD_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_FAIRNESS_MATRIX_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_ANTI_DOMINATION_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_ANTI_DOMINATION_REQUIRED",
            "IRIUM_POAWX_CANDIDATE_SET_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_CANDIDATE_SET_REQUIRED",
            "IRIUM_POAWX_ASSIGNMENT_PROOF_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_ASSIGNMENT_PROOF_REQUIRED",
            "IRIUM_POAWX_CANDIDATE_ADMISSION_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_CANDIDATE_ADMISSION_REQUIRED",
            "IRIUM_POAWX_PUZZLE_WORK_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_PUZZLE_WORK_REQUIRED",
            "IRIUM_POAWX_FINALITY_COMMITTEE_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_FINALITY_COMMITTEE_REQUIRED",
            "IRIUM_POAWX_FINALITY_THRESHOLD_NUM",
            "IRIUM_POAWX_FINALITY_THRESHOLD_DEN",
            "IRIUM_POAWX_COMMITTED_ADMISSION_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_COMMITTED_ADMISSION_REQUIRED",
            "IRIUM_POAWX_TRUE_VRF_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_TRUE_VRF_REQUIRED",
        ] {
            std::env::remove_var(k);
        }
    }

    #[test]
    fn phase24l_lib_builder_connect_block() {
        // Phase 24L: the live-proof binary builds its all-gates block via the lib
        // helper `build_devnet_all_gates_block`. This test exercises that EXACT
        // builder and proves its output is accepted by the full `connect_block`
        // pipeline (chain advances H1 -> H2) after the node ingests the builder's
        // candidate admissions — i.e. the binary's construction is node-acceptable
        // WITHOUT needing a live node. Same gate env as the Stage 2 test.
        use crate::poawx_admission::global_admission_cache;
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "devnet");
        for (k, v) in [
            ("IRIUM_POAWX_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_MODE", "active"),
            ("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS", "4"),
            ("IRIUM_POAWX_PUZZLE_BITS", "4"),
            ("IRIUM_POAWX_MULTI_ROLE_REWARD_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_FAIRNESS_MATRIX_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_ANTI_DOMINATION_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_ANTI_DOMINATION_REQUIRED", "1"),
            ("IRIUM_POAWX_CANDIDATE_SET_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_CANDIDATE_SET_REQUIRED", "1"),
            ("IRIUM_POAWX_ASSIGNMENT_PROOF_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_ASSIGNMENT_PROOF_REQUIRED", "1"),
            ("IRIUM_POAWX_CANDIDATE_ADMISSION_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_CANDIDATE_ADMISSION_REQUIRED", "1"),
            ("IRIUM_POAWX_PUZZLE_WORK_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_PUZZLE_WORK_REQUIRED", "1"),
            ("IRIUM_POAWX_FINALITY_COMMITTEE_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_FINALITY_COMMITTEE_REQUIRED", "1"),
            ("IRIUM_POAWX_FINALITY_THRESHOLD_NUM", "1"),
            ("IRIUM_POAWX_FINALITY_THRESHOLD_DEN", "1"),
            ("IRIUM_POAWX_COMMITTED_ADMISSION_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_COMMITTED_ADMISSION_REQUIRED", "1"),
            ("IRIUM_POAWX_TRUE_VRF_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_TRUE_VRF_REQUIRED", "1"),
        ] {
            std::env::set_var(k, v);
        }

        let locked = load_locked_genesis().expect("locked genesis");
        let genesis = block_from_locked(&locked).expect("genesis block");
        let genesis_hash = genesis.header.hash_for_height(0);

        let mut st = base_chain(None);
        let net = crate::activation::network_id_byte();
        let height = 1u64;
        let bits = st.target_for_height(height).bits;
        let time = genesis.header.time + 1;

        // The exact builder the live-proof binary uses.
        let proof = crate::poawx_mining_harness::build_devnet_all_gates_block(
            net,
            height,
            genesis_hash,
            None, // genesis parent: epoch seed falls back to prev_hash (genesis)
            bits,
            time,
            4, // receipt PoW difficulty == IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS
        )
        .expect("builder produces a mined all-gates block");
        assert_ne!(proof.irx1_root, [0u8; 32], "non-zero gated irx1 root");
        assert_eq!(proof.height, height);

        // Node ingests the builder's candidate admissions (as the loopback
        // /poawx/candidate-admission bridge would), then accepts the block.
        let cache = global_admission_cache();
        cache.clear();
        cache.set_tip(height);
        for adm in &proof.admissions {
            assert_eq!(
                cache.ingest_bytes(adm),
                crate::poawx_gossip::GossipOutcome::AcceptedNew,
                "node ingests builder admission"
            );
        }

        let before = st.height;
        st.connect_block(proof.block)
            .expect("connect_block accepts the builder's mined all-gates block");
        assert_eq!(st.height, before + 1, "chain advanced one block");

        cache.clear();
        for k in [
            "IRIUM_NETWORK",
            "IRIUM_POAWX_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_MODE",
            "IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS",
            "IRIUM_POAWX_PUZZLE_BITS",
            "IRIUM_POAWX_MULTI_ROLE_REWARD_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_FAIRNESS_MATRIX_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_ANTI_DOMINATION_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_ANTI_DOMINATION_REQUIRED",
            "IRIUM_POAWX_CANDIDATE_SET_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_CANDIDATE_SET_REQUIRED",
            "IRIUM_POAWX_ASSIGNMENT_PROOF_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_ASSIGNMENT_PROOF_REQUIRED",
            "IRIUM_POAWX_CANDIDATE_ADMISSION_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_CANDIDATE_ADMISSION_REQUIRED",
            "IRIUM_POAWX_PUZZLE_WORK_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_PUZZLE_WORK_REQUIRED",
            "IRIUM_POAWX_FINALITY_COMMITTEE_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_FINALITY_COMMITTEE_REQUIRED",
            "IRIUM_POAWX_FINALITY_THRESHOLD_NUM",
            "IRIUM_POAWX_FINALITY_THRESHOLD_DEN",
            "IRIUM_POAWX_COMMITTED_ADMISSION_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_COMMITTED_ADMISSION_REQUIRED",
            "IRIUM_POAWX_TRUE_VRF_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_TRUE_VRF_REQUIRED",
        ] {
            std::env::remove_var(k);
        }
    }

    // Shared gate env for the Phase 26B multi-block tests (all gates required from
    // height 1; devnet; finality 1/1; puzzle bits 4).
    fn phase26b_set_gate_env() {
        std::env::set_var("IRIUM_NETWORK", "devnet");
        for (k, v) in [
            ("IRIUM_POAWX_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_MODE", "active"),
            ("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS", "4"),
            ("IRIUM_POAWX_PUZZLE_BITS", "4"),
            ("IRIUM_POAWX_MULTI_ROLE_REWARD_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_FAIRNESS_MATRIX_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_ANTI_DOMINATION_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_ANTI_DOMINATION_REQUIRED", "1"),
            ("IRIUM_POAWX_CANDIDATE_SET_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_CANDIDATE_SET_REQUIRED", "1"),
            ("IRIUM_POAWX_ASSIGNMENT_PROOF_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_ASSIGNMENT_PROOF_REQUIRED", "1"),
            ("IRIUM_POAWX_CANDIDATE_ADMISSION_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_CANDIDATE_ADMISSION_REQUIRED", "1"),
            ("IRIUM_POAWX_PUZZLE_WORK_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_PUZZLE_WORK_REQUIRED", "1"),
            ("IRIUM_POAWX_FINALITY_COMMITTEE_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_FINALITY_COMMITTEE_REQUIRED", "1"),
            ("IRIUM_POAWX_FINALITY_THRESHOLD_NUM", "1"),
            ("IRIUM_POAWX_FINALITY_THRESHOLD_DEN", "1"),
            ("IRIUM_POAWX_COMMITTED_ADMISSION_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_COMMITTED_ADMISSION_REQUIRED", "1"),
            ("IRIUM_POAWX_TRUE_VRF_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_TRUE_VRF_REQUIRED", "1"),
        ] {
            std::env::set_var(k, v);
        }
    }

    fn phase26b_clear_gate_env() {
        for k in [
            "IRIUM_NETWORK",
            "IRIUM_POAWX_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_MODE",
            "IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS",
            "IRIUM_POAWX_PUZZLE_BITS",
            "IRIUM_POAWX_MULTI_ROLE_REWARD_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_FAIRNESS_MATRIX_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_ANTI_DOMINATION_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_ANTI_DOMINATION_REQUIRED",
            "IRIUM_POAWX_CANDIDATE_SET_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_CANDIDATE_SET_REQUIRED",
            "IRIUM_POAWX_ASSIGNMENT_PROOF_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_ASSIGNMENT_PROOF_REQUIRED",
            "IRIUM_POAWX_CANDIDATE_ADMISSION_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_CANDIDATE_ADMISSION_REQUIRED",
            "IRIUM_POAWX_PUZZLE_WORK_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_PUZZLE_WORK_REQUIRED",
            "IRIUM_POAWX_FINALITY_COMMITTEE_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_FINALITY_COMMITTEE_REQUIRED",
            "IRIUM_POAWX_FINALITY_THRESHOLD_NUM",
            "IRIUM_POAWX_FINALITY_THRESHOLD_DEN",
            "IRIUM_POAWX_COMMITTED_ADMISSION_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_COMMITTED_ADMISSION_REQUIRED",
            "IRIUM_POAWX_TRUE_VRF_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_TRUE_VRF_REQUIRED",
        ] {
            std::env::remove_var(k);
        }
    }

    #[test]
    fn phase26b_multiblock_epoch_seed_soak() {
        // Phase 26B: with epoch-seed alignment the multi-block all-gates chain is
        // satisfiable. Build + connect 6 sequential blocks (genesis -> 6) via the
        // EXACT live-proof builder, every gate enforced each step (connect_block
        // runs phase21c/d/e + puzzle + finality + phase22a committed-admission +
        // true-VRF). Assert the candidate-set seed equals the admission epoch seed
        // (grandparent) at every height and that dominance weights evolve. phase22a
        // is exercised on EVERY block >= 2 (the parent's commitment must match), so
        // a passing soak proves both gates hold together.
        use crate::poawx_admission::global_admission_cache;
        use crate::poawx_committed_admission::admission_epoch_seed;
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        phase26b_set_gate_env();

        let locked = load_locked_genesis().expect("locked genesis");
        let genesis = block_from_locked(&locked).expect("genesis block");
        let genesis_hash = genesis.header.hash_for_height(0);
        let mut st = base_chain(None);
        let net = crate::activation::network_id_byte();
        let cache = global_admission_cache();

        let n_blocks = 6u64;
        let mut prev = genesis_hash;
        let mut parent_prev: Option<[u8; 32]> = None;
        for h in 1..=n_blocks {
            let bits = st.target_for_height(h).bits;
            let time = genesis.header.time + h as u32;
            let proof = crate::poawx_mining_harness::build_devnet_all_gates_block(
                net,
                h,
                prev,
                parent_prev,
                bits,
                time,
                4,
            )
            .unwrap_or_else(|e| panic!("build H{h}: {e}"));

            // Candidate-set seed invariant: equals the epoch seed (grandparent).
            let ext = proof.block.poawx_receipts.as_ref().unwrap()[0]
                .phase20_ext
                .as_ref()
                .unwrap();
            let cs = ext.candidate_set.as_ref().unwrap();
            assert_eq!(
                cs.seed,
                admission_epoch_seed(parent_prev, prev),
                "H{h}: candidate-set seed must equal the admission epoch seed"
            );
            assert_eq!(cs.target_height, h, "H{h}: candidate-set target height");
            let weights = ext.role_dominance_weights.unwrap();

            // Ingest the (epoch-seeded) admissions then connect — all gates enforced.
            cache.clear();
            cache.set_tip(h);
            for adm in &proof.admissions {
                assert_eq!(
                    cache.ingest_bytes(adm),
                    crate::poawx_gossip::GossipOutcome::AcceptedNew,
                    "H{h}: admission ingested"
                );
            }
            let before = st.height;
            let blk_hash = proof.block_hash;
            let blk_prev = prev;
            st.connect_block(proof.block)
                .unwrap_or_else(|e| panic!("connect_block H{h} failed: {e}"));
            assert_eq!(st.height, before + 1, "H{h}: tip advanced by one");

            // Dominance evolves: H1 is the genesis baseline; later blocks are below.
            if h == 1 {
                assert_eq!(weights, [1000u64; 4], "H1: genesis baseline weights");
            } else {
                assert!(
                    weights.iter().all(|&w| w < 1000),
                    "H{h}: dominance weights evolved below baseline: {weights:?}"
                );
            }

            // Advance: this block's prev becomes the next block's grandparent; this
            // block's hash becomes the next block's prev_hash (tip).
            parent_prev = Some(blk_prev);
            prev = blk_hash;
        }
        assert!(
            st.height >= 6,
            "at least 5 sequential all-gates blocks accepted (final tip height {})",
            st.height
        );

        cache.clear();
        phase26b_clear_gate_env();
    }

    // ── Phase 28: finalized-checkpoint reorg rejection ──────────────────────────

    /// Build + connect `n` all-gates blocks (genesis -> n) using the EXACT
    /// live-proof builder, every gate enforced (incl. finality). Returns the block
    /// hash by height (index 0 = genesis). Mirrors `phase26b_multiblock` but is a
    /// reusable helper for the Phase 28 tests. Caller holds the env lock + gate env.
    #[allow(clippy::type_complexity)]
    fn phase28_build_connect_chain(
        st: &mut ChainState,
        n: u64,
    ) -> (Vec<[u8; 32]>, Vec<(Block, Vec<Vec<u8>>)>) {
        use crate::poawx_admission::global_admission_cache;
        let locked = load_locked_genesis().expect("locked genesis");
        let genesis = block_from_locked(&locked).expect("genesis block");
        let genesis_hash = genesis.header.hash_for_height(0);
        let net = crate::activation::network_id_byte();
        let cache = global_admission_cache();
        let mut hashes = vec![genesis_hash];
        let mut captured: Vec<(Block, Vec<Vec<u8>>)> = Vec::new();
        let mut prev = genesis_hash;
        let mut parent_prev: Option<[u8; 32]> = None;
        for h in 1..=n {
            let bits = st.target_for_height(h).bits;
            let time = genesis.header.time + h as u32;
            let proof = crate::poawx_mining_harness::build_devnet_all_gates_block(
                net,
                h,
                prev,
                parent_prev,
                bits,
                time,
                4,
            )
            .unwrap_or_else(|e| panic!("phase28 build H{h}: {e}"));
            cache.clear();
            cache.set_tip(h);
            for adm in &proof.admissions {
                assert_eq!(
                    cache.ingest_bytes(adm),
                    crate::poawx_gossip::GossipOutcome::AcceptedNew,
                    "phase28 H{h}: admission ingested"
                );
            }
            let blk_hash = proof.block_hash;
            let blk_prev = prev;
            // Capture (block, admissions) for faithful replay tests.
            captured.push((proof.block.clone(), proof.admissions.clone()));
            st.connect_block(proof.block)
                .unwrap_or_else(|e| panic!("phase28 connect H{h}: {e}"));
            hashes.push(blk_hash);
            parent_prev = Some(blk_prev);
            prev = blk_hash;
        }
        (hashes, captured)
    }

    /// Insert a synthetic fork-point block at `height` whose parent is the main
    /// chain's block at `height-1` (`prev_at_height_minus_1`) but with a distinct
    /// hash (nonce tweaked). It is registered in `block_store`/`heights` only, so
    /// `find_reorg_path` resolves its fork point to `height-1` WITHOUT it being on
    /// the main chain. Returns the fork block hash. The block is intentionally not
    /// valid for `connect_block` — it is used only to drive the reorg fork point.
    fn phase28_insert_fork_point(
        st: &mut ChainState,
        height: u64,
        prev_at_height_minus_1: [u8; 32],
    ) -> [u8; 32] {
        let mut fork = st.chain[height as usize].clone();
        fork.header.prev_hash = prev_at_height_minus_1;
        fork.header.nonce = fork.header.nonce.wrapping_add(0x5151_5151);
        let fork_hash = fork.header.hash_for_height(height);
        st.block_store.insert(fork_hash, fork);
        st.heights.insert(fork_hash, height);
        fork_hash
    }

    #[test]
    fn phase28_finalized_checkpoint_set_by_valid_finality() {
        // A valid all-gates chain advances the finalized checkpoint to the parent
        // of the tip (block H finalizes H-1). After 5 blocks, finalized == 4 with
        // the height-4 block hash; only a VALIDATED finality proof advances it.
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        phase26b_set_gate_env();
        let mut st = base_chain(None);
        let (hashes, _) = phase28_build_connect_chain(&mut st, 5);
        assert_eq!(
            st.poawx_finalized_height, 4,
            "block 5 finalizes its parent at height 4"
        );
        assert_eq!(
            st.poawx_finalized_hash, hashes[4],
            "finalized hash is the height-4 block hash"
        );
        crate::poawx_admission::global_admission_cache().clear();
        phase26b_clear_gate_env();
    }

    #[test]
    fn phase28_rejects_reorg_replacing_finalized_checkpoint() {
        // Finalize height 4; a reorg whose fork point is below 4 (here height 2)
        // is rejected deterministically BEFORE any disconnect — even though the
        // reorg path is reached directly (bypassing the more-work gate).
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        phase26b_set_gate_env();
        let mut st = base_chain(None);
        let (hashes, _) = phase28_build_connect_chain(&mut st, 5);
        assert_eq!(st.poawx_finalized_height, 4);
        let pre = (st.poawx_finalized_height, st.poawx_finalized_hash);

        // Fork point at height 2 (< finalized 4): diverges below the checkpoint.
        let fork_hash = phase28_insert_fork_point(&mut st, 2, hashes[1]);
        let err = st
            .reorg_to_tip(fork_hash)
            .expect_err("reorg below finalized checkpoint must be rejected");
        assert!(
            err.contains("phase28") && err.contains("finalized"),
            "expected phase28 finalized rejection, got: {err}"
        );
        // Chain + checkpoint unchanged (rejected before any disconnect).
        assert_eq!(st.tip_height(), 5, "tip unchanged after rejected reorg");
        assert_eq!(
            (st.poawx_finalized_height, st.poawx_finalized_hash),
            pre,
            "finalized checkpoint unchanged"
        );
        crate::poawx_admission::global_admission_cache().clear();
        phase26b_clear_gate_env();
    }

    #[test]
    fn phase28_allows_fork_after_finalized_checkpoint() {
        // Finalize height 4; a fork that shares block 4 and diverges at height 5
        // (fork point == finalized height) is NOT blocked by the finality guard —
        // it proceeds to normal chain rules (and here fails to connect for an
        // unrelated reason, proving the guard let it through).
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        phase26b_set_gate_env();
        let mut st = base_chain(None);
        let (hashes, _) = phase28_build_connect_chain(&mut st, 5);
        assert_eq!(st.poawx_finalized_height, 4);

        // Fork point at height 5 (> finalized 4): shares the finalized block 4.
        let fork_hash = phase28_insert_fork_point(&mut st, 5, hashes[4]);
        let res = st.reorg_to_tip(fork_hash);
        // The guard must NOT reject it; any error must be a normal connect failure.
        if let Err(e) = res {
            assert!(
                !(e.contains("phase28") && e.contains("finalized")),
                "fork after finalized must not be blocked by the finality guard, got: {e}"
            );
        }
        // Finalized checkpoint never moved backward.
        assert_eq!(
            st.poawx_finalized_height, 4,
            "finalized height unchanged / not backward"
        );
        crate::poawx_admission::global_admission_cache().clear();
        phase26b_clear_gate_env();
    }

    #[test]
    fn phase28_no_finalized_checkpoint_preserves_existing_reorg() {
        // With no checkpoint (poawx_finalized_height == 0), the guard is inactive
        // and pre-existing reorg behavior is unchanged. A fresh chain has no
        // checkpoint; the pure decision is false for all fork points.
        let st = base_chain(None);
        assert_eq!(
            st.poawx_finalized_height, 0,
            "no checkpoint on a fresh chain"
        );
        for ancestor in [0u64, 1, 5, 100] {
            assert!(
                !ChainState::reorg_violates_finalized(0, ancestor),
                "no checkpoint must never block a reorg (ancestor {ancestor})"
            );
        }
    }

    #[test]
    fn phase28_reorg_violates_finalized_pure_boundary() {
        // Exhaustive boundary of the pure decision.
        // F=0: never blocks.
        assert!(!ChainState::reorg_violates_finalized(0, 0));
        assert!(!ChainState::reorg_violates_finalized(0, 10));
        // F=4: fork points 0..=3 block; 4 and above allowed.
        for a in 0..=3 {
            assert!(
                ChainState::reorg_violates_finalized(4, a),
                "fork below finalized must block (a={a})"
            );
        }
        for a in 4..=8 {
            assert!(
                !ChainState::reorg_violates_finalized(4, a),
                "fork at/after finalized must be allowed (a={a})"
            );
        }
    }

    #[test]
    fn phase28_finalized_checkpoint_monotonic_no_backward() {
        // The checkpoint advances as blocks connect and never decreases.
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        phase26b_set_gate_env();
        let mut st = base_chain(None);
        let _ = phase28_build_connect_chain(&mut st, 5);
        assert_eq!(st.poawx_finalized_height, 4);
        // A lower advance is a no-op (rule 4: never backward).
        st.advance_finalized(2, [0x22u8; 32]);
        assert_eq!(
            st.poawx_finalized_height, 4,
            "checkpoint must not move backward"
        );
        // A higher advance moves it forward.
        st.advance_finalized(5, [0x55u8; 32]);
        assert_eq!(st.poawx_finalized_height, 5);
        assert_eq!(st.poawx_finalized_hash, [0x55u8; 32]);
        crate::poawx_admission::global_admission_cache().clear();
        phase26b_clear_gate_env();
    }

    #[test]
    fn phase28_invalid_finality_does_not_lock_chain() {
        // A block whose finality proof is tampered must be REJECTED by
        // connect_block and must NOT advance the finalized checkpoint.
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        phase26b_set_gate_env();
        let mut st = base_chain(None);
        let _ = phase28_build_connect_chain(&mut st, 3);
        let finalized_before = st.poawx_finalized_height; // == 2
        assert_eq!(finalized_before, 2);

        // Build a valid height-4 block, then tamper its finality proof.
        let locked = load_locked_genesis().expect("locked genesis");
        let genesis = block_from_locked(&locked).expect("genesis block");
        let net = crate::activation::network_id_byte();
        let prev = st.chain[3].header.hash_for_height(3);
        let parent_prev = Some(st.chain[2].header.hash_for_height(2));
        let bits = st.target_for_height(4).bits;
        let time = genesis.header.time + 4;
        let mut proof = crate::poawx_mining_harness::build_devnet_all_gates_block(
            net,
            4,
            prev,
            parent_prev,
            bits,
            time,
            4,
        )
        .expect("build H4");
        // Ingest admissions so only finality is the failing gate of interest.
        let cache = crate::poawx_admission::global_admission_cache();
        cache.clear();
        cache.set_tip(4);
        for adm in &proof.admissions {
            let _ = cache.ingest_bytes(adm);
        }
        // Tamper the finality proof: corrupt the first vote's signature.
        if let Some(receipts) = proof.block.poawx_receipts.as_mut() {
            for r in receipts.iter_mut() {
                if let Some(ext) = r.phase20_ext.as_mut() {
                    if let Some(fp) = ext.finality_proof.as_mut() {
                        if let Some(v) = fp.votes.first_mut() {
                            v.signature[0] ^= 0xFF;
                        }
                    }
                }
            }
        }
        let res = st.connect_block(proof.block);
        assert!(res.is_err(), "tampered finality must be rejected");
        assert_eq!(
            st.poawx_finalized_height, finalized_before,
            "rejected block must not advance the finalized checkpoint"
        );
        cache.clear();
        phase26b_clear_gate_env();
    }

    #[test]
    fn phase28_finalized_checkpoint_survives_replay() {
        // The checkpoint is DERIVED inside connect_block, so replaying the same
        // blocks (re-ingesting their admissions, as the real cold-replay path does
        // after reloading persisted admissions) into a FRESH state reconstructs the
        // same checkpoint — and the replayed state still rejects a conflicting reorg.
        use crate::poawx_admission::global_admission_cache;
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        phase26b_set_gate_env();
        let mut st = base_chain(None);
        let (hashes, captured) = phase28_build_connect_chain(&mut st, 5);
        assert_eq!(st.poawx_finalized_height, 4);

        // Replay the captured blocks into a brand-new ChainState.
        let cache = global_admission_cache();
        let mut replayed = base_chain(None);
        for (h, (block, admissions)) in captured.iter().enumerate() {
            let height = (h + 1) as u64;
            cache.clear();
            cache.set_tip(height);
            for adm in admissions {
                let _ = cache.ingest_bytes(adm);
            }
            replayed
                .connect_block(block.clone())
                .unwrap_or_else(|e| panic!("replay H{height}: {e}"));
        }
        assert_eq!(
            replayed.poawx_finalized_height, 4,
            "replay reconstructs the finalized checkpoint"
        );
        assert_eq!(replayed.poawx_finalized_hash, hashes[4]);

        // The replayed state rejects a reorg below the reconstructed checkpoint.
        let fork_hash = phase28_insert_fork_point(&mut replayed, 2, hashes[1]);
        let err = replayed
            .reorg_to_tip(fork_hash)
            .expect_err("replayed state must still reject reorg below finalized");
        assert!(
            err.contains("phase28") && err.contains("finalized"),
            "expected phase28 rejection after replay, got: {err}"
        );
        cache.clear();
        phase26b_clear_gate_env();
    }

    // ── Phase 30: block-carried double-sign evidence ────────────────────────────

    /// The all-gates builder signs the SUPPORT-committee finality vote with this
    /// exact key, so `committee_pkhs_at(h)` for a built block == `[member_pkh]`.
    fn phase30_member_sk() -> k256::ecdsa::SigningKey {
        k256::ecdsa::SigningKey::from_slice(&[0xC3u8; 32]).expect("sk")
    }

    fn phase30_member_pkh() -> [u8; 20] {
        use crate::poawx_finality::{FinalityVoteType, FinalityVoteV1};
        FinalityVoteV1::signed(
            &phase30_member_sk(),
            1,
            1,
            [0u8; 32],
            [0u8; 32],
            0,
            [0x11u8; 32],
            FinalityVoteType::Commit,
        )
        .member_pkh
    }

    /// Build double-sign evidence: the committee member signs two conflicting
    /// Commit votes (same net/height/epoch, different block hashes).
    fn phase30_evidence(
        net: u8,
        height: u64,
        epoch: u64,
        bh_a: [u8; 32],
        bh_b: [u8; 32],
    ) -> crate::poawx_doublesign::PoawxDoubleSignEvidenceV1 {
        use crate::poawx_finality::{FinalityVoteType, FinalityVoteV1};
        let sk = phase30_member_sk();
        let va = FinalityVoteV1::signed(
            &sk,
            net,
            height,
            bh_a,
            [0u8; 32],
            epoch,
            [0x11u8; 32],
            FinalityVoteType::Commit,
        );
        let vb = FinalityVoteV1::signed(
            &sk,
            net,
            height,
            bh_b,
            [0u8; 32],
            epoch,
            [0x11u8; 32],
            FinalityVoteType::Commit,
        );
        crate::poawx_doublesign::PoawxDoubleSignEvidenceV1::new(net, va, vb)
    }

    /// Clone a built block and inject `evs` into its first receipt's ext.
    fn phase30_block_with_evidence(
        src: &Block,
        evs: Vec<crate::poawx_doublesign::PoawxDoubleSignEvidenceV1>,
    ) -> Block {
        let mut blk = src.clone();
        if let Some(rs) = blk.poawx_receipts.as_mut() {
            if let Some(ext) = rs[0].phase20_ext.as_mut() {
                ext.double_sign_evidence = Some(evs);
            }
        }
        blk
    }

    /// Build (but do not connect) the next all-gates block on a chain at tip `n`.
    fn phase30_build_next(st: &ChainState, n: u64) -> crate::poawx_mining_harness::AllGatesProof {
        let locked = load_locked_genesis().expect("locked genesis");
        let genesis = block_from_locked(&locked).expect("genesis block");
        let net = crate::activation::network_id_byte();
        let h = n + 1;
        let prev = st.chain[n as usize].header.hash_for_height(n);
        let parent_prev = Some(st.chain[(n - 1) as usize].header.hash_for_height(n - 1));
        let bits = st.target_for_height(h).bits;
        let time = genesis.header.time + h as u32;
        crate::poawx_mining_harness::build_devnet_all_gates_block(
            net,
            h,
            prev,
            parent_prev,
            bits,
            time,
            4,
        )
        .unwrap_or_else(|e| panic!("phase30 build H{h}: {e}"))
    }

    fn phase30_ingest_admissions(proof: &crate::poawx_mining_harness::AllGatesProof, h: u64) {
        let cache = crate::poawx_admission::global_admission_cache();
        cache.clear();
        cache.set_tip(h);
        for adm in &proof.admissions {
            let _ = cache.ingest_bytes(adm);
        }
    }

    #[test]
    fn phase30_block_carried_evidence_validates_and_applies() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        phase26b_set_gate_env();
        std::env::set_var("IRIUM_POAWX_DOUBLE_SIGN_PENALTY_ACTIVATION_HEIGHT", "1");
        let mut st = base_chain(None);
        let _ = phase28_build_connect_chain(&mut st, 3);
        let net = crate::activation::network_id_byte();

        // The SUPPORT committee at height 1 is exactly the builder's member.
        let committee = st.committee_pkhs_at(1).expect("committee at h1");
        assert_eq!(
            committee,
            vec![phase30_member_pkh()],
            "committee == builder member"
        );

        // Valid evidence: member double-signs at height 1.
        let ev = phase30_evidence(net, 1, 0, [0xA1u8; 32], [0xB2u8; 32]);
        let blk = phase30_block_with_evidence(&st.chain[3], vec![ev.clone()]);
        let validated = st
            .validate_block_double_sign_evidence(&blk, 4)
            .expect("valid block-carried evidence");
        assert_eq!(validated.len(), 1);

        // Evidence is committed: it changes the ext digest (-> irx1 root).
        let ext_with = blk.poawx_receipts.as_ref().unwrap()[0]
            .phase20_ext
            .clone()
            .unwrap();
        let mut ext_none = ext_with.clone();
        ext_none.double_sign_evidence = None;
        assert_ne!(
            ext_with.digest(),
            ext_none.digest(),
            "evidence changes the ext digest (committed into irx1 root)"
        );
        // And it round-trips on the wire.
        assert_eq!(
            crate::poawx::Phase20ReceiptExt::deserialize(&ext_with.serialize()).unwrap(),
            ext_with
        );

        // Applying updates the deterministic penalty state.
        st.doublesign_penalty
            .apply_evidence(
                &ev,
                &committee,
                net,
                4,
                crate::poawx_doublesign::DEFAULT_SUSPEND_EPOCHS,
            )
            .unwrap();
        assert!(
            !st.doublesign_penalty
                .is_eligible_for_finality(&phase30_member_pkh(), 0),
            "member penalized after evidence applied"
        );

        std::env::remove_var("IRIUM_POAWX_DOUBLE_SIGN_PENALTY_ACTIVATION_HEIGHT");
        crate::poawx_admission::global_admission_cache().clear();
        phase26b_clear_gate_env();
    }

    #[test]
    fn phase30_invalid_block_carried_evidence_rejected() {
        use crate::poawx_finality::{FinalityVoteType, FinalityVoteV1};
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        phase26b_set_gate_env();
        std::env::set_var("IRIUM_POAWX_DOUBLE_SIGN_PENALTY_ACTIVATION_HEIGHT", "1");
        let mut st = base_chain(None);
        let _ = phase28_build_connect_chain(&mut st, 3);
        let net = crate::activation::network_id_byte();

        // Baseline valid evidence accepted.
        let good = phase30_evidence(net, 1, 0, [0xA1u8; 32], [0xB2u8; 32]);
        assert!(st
            .validate_block_double_sign_evidence(
                &phase30_block_with_evidence(&st.chain[3], vec![good.clone()]),
                4
            )
            .is_ok());

        // Bad signature => rejected.
        let mut bad = good.clone();
        bad.vote_a.signature[0] ^= 0xFF;
        let bad =
            crate::poawx_doublesign::PoawxDoubleSignEvidenceV1::new(net, bad.vote_a, bad.vote_b);
        assert!(st
            .validate_block_double_sign_evidence(
                &phase30_block_with_evidence(&st.chain[3], vec![bad]),
                4
            )
            .is_err());

        // Non-committee signer => rejected.
        let other = k256::ecdsa::SigningKey::from_slice(&[0x09u8; 32]).unwrap();
        let oa = FinalityVoteV1::signed(
            &other,
            net,
            1,
            [0xA1u8; 32],
            [0u8; 32],
            0,
            [0x11u8; 32],
            FinalityVoteType::Commit,
        );
        let ob = FinalityVoteV1::signed(
            &other,
            net,
            1,
            [0xB2u8; 32],
            [0u8; 32],
            0,
            [0x11u8; 32],
            FinalityVoteType::Commit,
        );
        let nonmember = crate::poawx_doublesign::PoawxDoubleSignEvidenceV1::new(net, oa, ob);
        assert!(st
            .validate_block_double_sign_evidence(
                &phase30_block_with_evidence(&st.chain[3], vec![nonmember]),
                4
            )
            .is_err());

        // Offense height not in the past (>= connecting height) => rejected.
        let future = phase30_evidence(net, 4, 0, [0xA1u8; 32], [0xB2u8; 32]);
        assert!(st
            .validate_block_double_sign_evidence(
                &phase30_block_with_evidence(&st.chain[3], vec![future]),
                4
            )
            .is_err());

        // In-block duplicate id => rejected (non-canonical/dedup).
        assert!(st
            .validate_block_double_sign_evidence(
                &phase30_block_with_evidence(&st.chain[3], vec![good.clone(), good.clone()]),
                4
            )
            .is_err());

        // Non-canonical order of two distinct evidence => rejected.
        let e1 = phase30_evidence(net, 1, 0, [0x01u8; 32], [0x02u8; 32]);
        let e2 = phase30_evidence(net, 1, 0, [0x03u8; 32], [0x04u8; 32]);
        let (lo, hi) = if e1.evidence_id() <= e2.evidence_id() {
            (e1, e2)
        } else {
            (e2, e1)
        };
        assert!(
            st.validate_block_double_sign_evidence(
                &phase30_block_with_evidence(&st.chain[3], vec![hi, lo]),
                4
            )
            .is_err(),
            "descending order rejected"
        );

        std::env::remove_var("IRIUM_POAWX_DOUBLE_SIGN_PENALTY_ACTIVATION_HEIGHT");
        crate::poawx_admission::global_admission_cache().clear();
        phase26b_clear_gate_env();
    }

    #[test]
    fn phase30_evidence_cap_enforced() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        phase26b_set_gate_env();
        std::env::set_var("IRIUM_POAWX_DOUBLE_SIGN_PENALTY_ACTIVATION_HEIGHT", "1");
        let mut st = base_chain(None);
        let _ = phase28_build_connect_chain(&mut st, 3);
        let net = crate::activation::network_id_byte();
        let cap = crate::poawx_doublesign::MAX_DOUBLE_SIGN_EVIDENCE_PER_BLOCK;
        // cap+1 distinct evidence.
        let mut evs = Vec::new();
        for i in 0..(cap + 1) as u8 {
            evs.push(phase30_evidence(net, 1, 0, [0x10 + i; 32], [0x90 + i; 32]));
        }
        evs.sort_by_key(|e| e.evidence_id());
        assert!(
            st.validate_block_double_sign_evidence(
                &phase30_block_with_evidence(&st.chain[3], evs),
                4
            )
            .is_err(),
            "over-cap evidence rejected"
        );
        std::env::remove_var("IRIUM_POAWX_DOUBLE_SIGN_PENALTY_ACTIVATION_HEIGHT");
        crate::poawx_admission::global_admission_cache().clear();
        phase26b_clear_gate_env();
    }

    #[test]
    fn phase30_penalized_signer_excluded_from_future_finality() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        phase26b_set_gate_env();
        std::env::set_var("IRIUM_POAWX_DOUBLE_SIGN_PENALTY_ACTIVATION_HEIGHT", "1");
        let net = crate::activation::network_id_byte();

        // CONTROL: with the gate ON but NO penalty, the next block connects (its
        // finality vote by the member is allowed; the gate is not retroactive).
        {
            let mut st = base_chain(None);
            let _ = phase28_build_connect_chain(&mut st, 3);
            let proof = phase30_build_next(&st, 3);
            phase30_ingest_admissions(&proof, 4);
            assert!(
                st.connect_block(proof.block).is_ok(),
                "no penalty => block 4 connects (non-retroactive gate)"
            );
        }

        // PENALIZED: penalize the member (as an earlier block's evidence would),
        // then the next all-gates block — whose finality vote is by that member —
        // is REJECTED by the Phase 30 exclusion hook.
        {
            let mut st = base_chain(None);
            let _ = phase28_build_connect_chain(&mut st, 3);
            let committee = st.committee_pkhs_at(1).expect("committee");
            let ev = phase30_evidence(net, 1, 0, [0xA1u8; 32], [0xB2u8; 32]);
            st.doublesign_penalty
                .apply_evidence(&ev, &committee, net, 3, 1)
                .unwrap();
            let proof = phase30_build_next(&st, 3);
            phase30_ingest_admissions(&proof, 4);
            let err = st
                .connect_block(proof.block)
                .expect_err("penalized signer must be excluded from finality");
            assert!(
                err.contains("phase30") && err.contains("penalized"),
                "expected phase30 penalized-signer rejection, got: {err}"
            );
        }

        std::env::remove_var("IRIUM_POAWX_DOUBLE_SIGN_PENALTY_ACTIVATION_HEIGHT");
        crate::poawx_admission::global_admission_cache().clear();
        phase26b_clear_gate_env();
    }

    #[test]
    fn phase30_local_evidence_not_consensus_until_included() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        phase26b_set_gate_env();
        std::env::set_var("IRIUM_POAWX_DOUBLE_SIGN_PENALTY_ACTIVATION_HEIGHT", "1");
        let mut st = base_chain(None);
        let _ = phase28_build_connect_chain(&mut st, 3);
        let net = crate::activation::network_id_byte();

        // Put valid evidence into a LOCAL cache only.
        let committee = st.committee_pkhs_at(1).expect("committee");
        let ev = phase30_evidence(net, 1, 0, [0xA1u8; 32], [0xB2u8; 32]);
        let cache = crate::poawx_doublesign::NodeDoubleSignEvidenceCache::new();
        let outcome = cache.ingest(ev, &committee);
        assert_eq!(outcome, crate::poawx_gossip::GossipOutcome::AcceptedNew);

        // Consensus penalty state is UNAFFECTED by the local cache.
        assert_eq!(
            st.doublesign_penalty.penalized_count(),
            0,
            "local cache evidence must not touch consensus penalty state"
        );
        // And the next block (carrying no evidence) connects normally and leaves
        // the consensus penalty state empty.
        let proof = phase30_build_next(&st, 3);
        phase30_ingest_admissions(&proof, 4);
        st.connect_block(proof.block).expect("block 4 connects");
        assert_eq!(st.doublesign_penalty.penalized_count(), 0);

        std::env::remove_var("IRIUM_POAWX_DOUBLE_SIGN_PENALTY_ACTIVATION_HEIGHT");
        crate::poawx_admission::global_admission_cache().clear();
        phase26b_clear_gate_env();
    }

    #[test]
    fn phase30_rebuild_penalty_clears_stale_evidence() {
        // Rebuilding penalty state from the active chain (used after a successful
        // reorg) drops penalties not justified by block-carried evidence on the
        // active chain — abandoned-fork evidence cannot pollute the active chain.
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        phase26b_set_gate_env();
        std::env::set_var("IRIUM_POAWX_DOUBLE_SIGN_PENALTY_ACTIVATION_HEIGHT", "1");
        let mut st = base_chain(None);
        let _ = phase28_build_connect_chain(&mut st, 3);
        let net = crate::activation::network_id_byte();
        let committee = st.committee_pkhs_at(1).expect("committee");
        let ev = phase30_evidence(net, 1, 0, [0xA1u8; 32], [0xB2u8; 32]);
        st.doublesign_penalty
            .apply_evidence(&ev, &committee, net, 3, 1)
            .unwrap();
        assert_eq!(st.doublesign_penalty.penalized_count(), 1);

        // The active chain's blocks carry NO evidence => rebuild yields empty state.
        st.rebuild_doublesign_penalty_from_chain();
        assert_eq!(
            st.doublesign_penalty.penalized_count(),
            0,
            "stale (non-chain) penalty cleared on rebuild"
        );

        std::env::remove_var("IRIUM_POAWX_DOUBLE_SIGN_PENALTY_ACTIVATION_HEIGHT");
        crate::poawx_admission::global_admission_cache().clear();
        phase26b_clear_gate_env();
    }

    #[test]
    fn phase30_mainnet_no_consensus_penalty() {
        // Mainnet hard-off: the consensus penalty gate is false for network 0.
        assert!(!crate::poawx_doublesign::double_sign_penalty_gate(
            0,
            Some(1),
            100
        ));
        assert!(crate::poawx_doublesign::double_sign_penalty_gate(
            1,
            Some(1),
            100
        ));
        assert!(!crate::poawx_doublesign::double_sign_penalty_gate(
            1, None, 100
        ));
    }

    #[test]
    fn phase31_additive_cap_gate_no_false_reject() {
        // With the Phase 31 additive reward-manifest cap gate ENABLED, a valid
        // all-gates chain still connects: the gate is a strict superset of the
        // existing exact-match payout check and never false-rejects a valid block.
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        phase26b_set_gate_env();
        std::env::set_var("IRIUM_POAWX_REWARD_MANIFEST_CAPS_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_REWARD_MANIFEST_CAPS_REQUIRED", "1");
        assert!(
            crate::poawx_reward::reward_manifest_caps_enforced(2),
            "additive cap gate is enabled"
        );
        let mut st = base_chain(None);
        let (hashes, _captured) = phase28_build_connect_chain(&mut st, 4);
        assert_eq!(st.tip_height(), 4, "valid chain connects with cap gate on");
        assert_eq!(hashes.len(), 5);
        std::env::remove_var("IRIUM_POAWX_REWARD_MANIFEST_CAPS_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_REWARD_MANIFEST_CAPS_REQUIRED");
        crate::poawx_admission::global_admission_cache().clear();
        phase26b_clear_gate_env();
    }

    // ── Phase 32: on-chain ticket store (consensus helpers) ─────────────────────

    fn phase32_reg(
        net: u8,
        miner_byte: u8,
        epoch: u64,
        h_exp: u64,
    ) -> crate::poawx_ticket::PoawxTicketRegistrationV1 {
        let pkh = [miner_byte; 20];
        let apk = [miner_byte.wrapping_add(0x40); 33];
        let (nonce, digest) =
            crate::poawx_ticket::grind_sybil_nonce(net, &pkh, epoch, &apk, 0, 1).unwrap();
        crate::poawx_ticket::PoawxTicketRegistrationV1::new(crate::poawx_ticket::MinerWorkTicket {
            version: crate::poawx_ticket::TICKET_VERSION,
            network_id: net,
            miner_pkh: pkh,
            epoch,
            assignment_public_key: apk,
            sybil_work_nonce: nonce,
            sybil_work_digest: digest,
            recent_reward_score: 0,
            valid_work_count: 0,
            invalid_work_count: 0,
            penalty_status: crate::poawx_penalty::PenaltyStatus::Clean.id(),
            bond_reference: None,
            issued_height: 1,
            expiry_height: h_exp,
        })
    }

    fn phase32_block_with_regs(
        src: &Block,
        regs: Vec<crate::poawx_ticket::PoawxTicketRegistrationV1>,
    ) -> Block {
        let mut blk = src.clone();
        if let Some(rs) = blk.poawx_receipts.as_mut() {
            if let Some(ext) = rs[0].phase20_ext.as_mut() {
                ext.ticket_registrations = Some(regs);
            }
        }
        blk
    }

    #[test]
    fn phase32_block_carried_ticket_registration_accepted() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        phase26b_set_gate_env();
        std::env::set_var("IRIUM_POAWX_TICKET_STORE_ACTIVATION_HEIGHT", "1");
        let mut st = base_chain(None);
        let _ = phase28_build_connect_chain(&mut st, 3);
        let net = crate::activation::network_id_byte();
        let reg = phase32_reg(net, 0xA1, 7, 100);
        let blk = phase32_block_with_regs(&st.chain[3], vec![reg.clone()]);
        let validated = st
            .validate_block_ticket_registrations(&blk, 4)
            .expect("valid registration");
        assert_eq!(validated.len(), 1);
        // ext digest changes (committed) + wire round-trips.
        let ext = blk.poawx_receipts.as_ref().unwrap()[0]
            .phase20_ext
            .clone()
            .unwrap();
        let mut none = ext.clone();
        none.ticket_registrations = None;
        assert_ne!(ext.digest(), none.digest());
        assert_eq!(
            crate::poawx::Phase20ReceiptExt::deserialize(&ext.serialize()).unwrap(),
            ext
        );
        // apply -> active from H+1.
        st.ticket_store.apply_registration(&reg, 4).unwrap();
        assert!(st
            .ticket_store
            .has_active(&[0xA1u8; 20], 7, &reg.assignment_public_key(), 5));
        std::env::remove_var("IRIUM_POAWX_TICKET_STORE_ACTIVATION_HEIGHT");
        crate::poawx_admission::global_admission_cache().clear();
        phase26b_clear_gate_env();
    }

    #[test]
    fn phase32_invalid_ticket_registrations_rejected() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        phase26b_set_gate_env();
        std::env::set_var("IRIUM_POAWX_TICKET_STORE_ACTIVATION_HEIGHT", "1");
        let mut st = base_chain(None);
        let _ = phase28_build_connect_chain(&mut st, 3);
        let net = crate::activation::network_id_byte();
        // expired (expiry <= connecting height 4).
        let expired = phase32_reg(net, 0xA1, 7, 4);
        assert!(st
            .validate_block_ticket_registrations(
                &phase32_block_with_regs(&st.chain[3], vec![expired]),
                4
            )
            .is_err());
        // wrong network.
        let wrong_net = phase32_reg(2u8.wrapping_add(net), 0xA2, 7, 100);
        assert!(st
            .validate_block_ticket_registrations(
                &phase32_block_with_regs(&st.chain[3], vec![wrong_net]),
                4
            )
            .is_err());
        // over cap.
        let mut many = Vec::new();
        for i in 0..(crate::poawx_ticket::MAX_TICKET_REGISTRATIONS_PER_BLOCK as u8 + 1) {
            many.push(phase32_reg(net, 0x10 + i, 7, 100));
        }
        many.sort_by_key(|r| r.ticket_id());
        assert!(st
            .validate_block_ticket_registrations(&phase32_block_with_regs(&st.chain[3], many), 4)
            .is_err());
        // in-block duplicate id.
        let dup = phase32_reg(net, 0xA3, 7, 100);
        assert!(st
            .validate_block_ticket_registrations(
                &phase32_block_with_regs(&st.chain[3], vec![dup.clone(), dup]),
                4
            )
            .is_err());
        std::env::remove_var("IRIUM_POAWX_TICKET_STORE_ACTIVATION_HEIGHT");
        crate::poawx_admission::global_admission_cache().clear();
        phase26b_clear_gate_env();
    }

    #[test]
    fn phase32_missing_onchain_ticket_rejected_for_role() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        phase26b_set_gate_env();
        let mut st = base_chain(None);
        let _ = phase28_build_connect_chain(&mut st, 3);
        let net = crate::activation::network_id_byte();
        // Build a block whose receipt carries 3 role ticket proofs for (miner,epoch,apk).
        let (miner, epoch, apk) = ([0xA1u8; 20], 7u64, [0xE1u8; 33]);
        let proof = |role: u8| {
            crate::poawx_ticket::TicketProof::new(
                net,
                4,
                role,
                miner,
                epoch,
                100,
                apk,
                [0u8; 32],
                crate::poawx_penalty::PenaltyStatus::Clean.id(),
            )
        };
        let mut blk = st.chain[3].clone();
        if let Some(rs) = blk.poawx_receipts.as_mut() {
            if let Some(ext) = rs[0].phase20_ext.as_mut() {
                ext.role_ticket_proofs = Some([
                    proof(crate::poawx::ROLE_COMPUTE_CONTRIBUTOR),
                    proof(crate::poawx::ROLE_VERIFY_CONTRIBUTOR),
                    proof(crate::poawx::ROLE_SUPPORT_CONTRIBUTOR),
                ]);
            }
        }
        // Empty store => eligibility rejects.
        let err = st
            .validate_block_ticket_store_eligibility(&blk, 4)
            .expect_err("missing on-chain ticket rejected");
        assert!(
            err.contains("phase32") && err.contains("not registered"),
            "got: {err}"
        );
        // Register a matching ticket (active before height 4) => eligibility passes.
        let reg = crate::poawx_ticket::PoawxTicketRegistrationV1::new(
            crate::poawx_ticket::MinerWorkTicket {
                version: crate::poawx_ticket::TICKET_VERSION,
                network_id: net,
                miner_pkh: miner,
                epoch,
                assignment_public_key: apk,
                sybil_work_nonce: [0u8; 32],
                sybil_work_digest: crate::poawx_ticket::compute_sybil_digest(
                    net, &miner, epoch, &apk, &[0u8; 32],
                ),
                recent_reward_score: 0,
                valid_work_count: 0,
                invalid_work_count: 0,
                penalty_status: crate::poawx_penalty::PenaltyStatus::Clean.id(),
                bond_reference: None,
                issued_height: 1,
                expiry_height: 100,
            },
        );
        st.ticket_store.apply_registration(&reg, 2).unwrap();
        assert!(
            st.validate_block_ticket_store_eligibility(&blk, 4).is_ok(),
            "registered + active ticket satisfies eligibility"
        );
        crate::poawx_admission::global_admission_cache().clear();
        phase26b_clear_gate_env();
    }

    #[test]
    fn phase32_rebuild_ticket_store_clears_stale() {
        // Rebuild from a chain with no registrations clears stale store state
        // (abandoned-fork safety).
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        phase26b_set_gate_env();
        std::env::set_var("IRIUM_POAWX_TICKET_STORE_ACTIVATION_HEIGHT", "1");
        let mut st = base_chain(None);
        let _ = phase28_build_connect_chain(&mut st, 3);
        let net = crate::activation::network_id_byte();
        let reg = phase32_reg(net, 0xA1, 7, 100);
        st.ticket_store.apply_registration(&reg, 2).unwrap();
        assert_eq!(st.ticket_store.len(), 1);
        st.rebuild_ticket_store_from_chain();
        assert_eq!(
            st.ticket_store.len(),
            0,
            "stale (non-chain) registration cleared on rebuild"
        );
        std::env::remove_var("IRIUM_POAWX_TICKET_STORE_ACTIVATION_HEIGHT");
        crate::poawx_admission::global_admission_cache().clear();
        phase26b_clear_gate_env();
    }

    #[test]
    fn phase32_local_ticket_not_consensus_until_included() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        phase26b_set_gate_env();
        std::env::set_var("IRIUM_POAWX_TICKET_STORE_ACTIVATION_HEIGHT", "1");
        let mut st = base_chain(None);
        let _ = phase28_build_connect_chain(&mut st, 3);
        let net = crate::activation::network_id_byte();
        let reg = phase32_reg(net, 0xA1, 7, 100);
        let cache = crate::poawx_ticket::NodeTicketRegistrationCache::new();
        assert!(cache.ingest(reg, 3));
        // Consensus store is UNAFFECTED by the local cache.
        assert_eq!(
            st.ticket_store.len(),
            0,
            "local cache registration must not touch the consensus store"
        );
        std::env::remove_var("IRIUM_POAWX_TICKET_STORE_ACTIVATION_HEIGHT");
        crate::poawx_admission::global_admission_cache().clear();
        phase26b_clear_gate_env();
    }

    // ── Phase 33: dominance-state commitment (consensus) ────────────────────────

    fn phase33_block_with_commitment(
        src: &Block,
        c: crate::poawx_dominance::PoawxDominanceCommitmentV1,
    ) -> Block {
        let mut blk = src.clone();
        if let Some(rs) = blk.poawx_receipts.as_mut() {
            if let Some(ext) = rs[0].phase20_ext.as_mut() {
                ext.dominance_commitment = Some(c);
            }
        }
        blk
    }

    #[test]
    fn phase33_valid_dominance_commitment_accepted() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        phase26b_set_gate_env();
        std::env::set_var("IRIUM_POAWX_DOMINANCE_COMMITMENT_ACTIVATION_HEIGHT", "1");
        let mut st = base_chain(None);
        let _ = phase28_build_connect_chain(&mut st, 3);
        let net = crate::activation::network_id_byte();
        // Compute the correct pre/post for a hypothetical block 4 = chain[3]'s rewards.
        let pre = st.dominance.digest();
        let post = st.compute_post_dominance_digest(&st.chain[3], 4);
        let good = crate::poawx_dominance::PoawxDominanceCommitmentV1::new(net, 4, pre, post);
        let blk = phase33_block_with_commitment(&st.chain[3], good);
        assert!(
            st.validate_block_dominance_commitment(&blk, 4).is_ok(),
            "matching pre/post accepted"
        );
        // ext digest changed (committed) + wire round-trips.
        let ext = blk.poawx_receipts.as_ref().unwrap()[0]
            .phase20_ext
            .clone()
            .unwrap();
        let mut none = ext.clone();
        none.dominance_commitment = None;
        assert_ne!(ext.digest(), none.digest());
        assert_eq!(
            crate::poawx::Phase20ReceiptExt::deserialize(&ext.serialize()).unwrap(),
            ext
        );
        std::env::remove_var("IRIUM_POAWX_DOMINANCE_COMMITMENT_ACTIVATION_HEIGHT");
        crate::poawx_admission::global_admission_cache().clear();
        phase26b_clear_gate_env();
    }

    #[test]
    fn phase33_bad_dominance_digest_rejected() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        phase26b_set_gate_env();
        std::env::set_var("IRIUM_POAWX_DOMINANCE_COMMITMENT_ACTIVATION_HEIGHT", "1");
        let mut st = base_chain(None);
        let _ = phase28_build_connect_chain(&mut st, 3);
        let net = crate::activation::network_id_byte();
        let pre = st.dominance.digest();
        let post = st.compute_post_dominance_digest(&st.chain[3], 4);
        // bad post.
        let bad_post =
            crate::poawx_dominance::PoawxDominanceCommitmentV1::new(net, 4, pre, [0x99u8; 32]);
        let err = st
            .validate_block_dominance_commitment(
                &phase33_block_with_commitment(&st.chain[3], bad_post),
                4,
            )
            .expect_err("bad post digest rejected");
        assert!(
            err.contains("phase33") && err.contains("PostStateMismatch"),
            "got: {err}"
        );
        // bad pre.
        let bad_pre =
            crate::poawx_dominance::PoawxDominanceCommitmentV1::new(net, 4, [0x99u8; 32], post);
        assert!(st
            .validate_block_dominance_commitment(
                &phase33_block_with_commitment(&st.chain[3], bad_pre),
                4
            )
            .is_err());
        std::env::remove_var("IRIUM_POAWX_DOMINANCE_COMMITMENT_ACTIVATION_HEIGHT");
        crate::poawx_admission::global_admission_cache().clear();
        phase26b_clear_gate_env();
    }

    #[test]
    fn phase33_dominance_state_updates_from_rewards() {
        // Connecting all-gates blocks evolves the dominance digest as role rewards
        // apply; a longer chain has a different digest than a shorter one.
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        phase26b_set_gate_env();
        let mut s1 = base_chain(None);
        let empty = s1.dominance.digest();
        let _ = phase28_build_connect_chain(&mut s1, 1);
        let after1 = s1.dominance.digest();
        assert_ne!(empty, after1, "rewards change the dominance digest");

        let mut s4 = base_chain(None);
        let _ = phase28_build_connect_chain(&mut s4, 4);
        let after4 = s4.dominance.digest();
        assert_ne!(after1, after4, "more reward events => different digest");
        crate::poawx_admission::global_admission_cache().clear();
        phase26b_clear_gate_env();
    }

    #[test]
    fn phase33_dominance_state_replays_from_blocks() {
        // The committed digest is a pure function of the active chain: a fresh state
        // that replays the same blocks reaches the same dominance digest (no local
        // input). Mirrors the cold-replay path.
        use crate::poawx_admission::global_admission_cache;
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        phase26b_set_gate_env();
        let mut st = base_chain(None);
        let (_h, captured) = phase28_build_connect_chain(&mut st, 4);
        let original = st.dominance.digest();

        let cache = global_admission_cache();
        let mut replayed = base_chain(None);
        for (i, (block, admissions)) in captured.iter().enumerate() {
            let height = (i + 1) as u64;
            cache.clear();
            cache.set_tip(height);
            for adm in admissions {
                let _ = cache.ingest_bytes(adm);
            }
            replayed.connect_block(block.clone()).unwrap();
        }
        assert_eq!(
            replayed.dominance.digest(),
            original,
            "replay reconstructs the dominance digest"
        );
        cache.clear();
        phase26b_clear_gate_env();
    }

    #[test]
    fn phase33_enforced_requires_commitment() {
        // With the gate ACTIVE + REQUIRED, a block lacking a DMC1 commitment is
        // rejected by connect_block (builder blocks carry None).
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        phase26b_set_gate_env();
        std::env::set_var("IRIUM_POAWX_DOMINANCE_COMMITMENT_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_DOMINANCE_COMMITMENT_REQUIRED", "1");
        assert!(crate::poawx_dominance::dominance_commitment_enforced(2));
        let mut st = base_chain(None);
        // Block 1 finalizes genesis; with enforcement on, build+connect H1 must fail
        // because the builder carries no commitment.
        let locked = load_locked_genesis().expect("genesis");
        let genesis = block_from_locked(&locked).expect("block");
        let net = crate::activation::network_id_byte();
        let proof = crate::poawx_mining_harness::build_devnet_all_gates_block(
            net,
            1,
            genesis.header.hash_for_height(0),
            None,
            st.target_for_height(1).bits,
            genesis.header.time + 1,
            4,
        )
        .expect("build H1");
        let cache = crate::poawx_admission::global_admission_cache();
        cache.clear();
        cache.set_tip(1);
        for adm in &proof.admissions {
            let _ = cache.ingest_bytes(adm);
        }
        let err = st
            .connect_block(proof.block)
            .expect_err("missing required commitment rejected");
        assert!(
            err.contains("phase33") && err.contains("required"),
            "got: {err}"
        );
        std::env::remove_var("IRIUM_POAWX_DOMINANCE_COMMITMENT_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_DOMINANCE_COMMITMENT_REQUIRED");
        cache.clear();
        phase26b_clear_gate_env();
    }

    #[test]
    fn phase33_additive_gate_no_false_reject() {
        // Gate ACTIVE but NOT required: a valid all-gates chain (no DMC1 carried)
        // still connects — the commitment is validated-if-present only.
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        phase26b_set_gate_env();
        std::env::set_var("IRIUM_POAWX_DOMINANCE_COMMITMENT_ACTIVATION_HEIGHT", "1");
        let mut st = base_chain(None);
        let _ = phase28_build_connect_chain(&mut st, 3);
        assert_eq!(st.tip_height(), 3, "valid chain connects with gate active");
        std::env::remove_var("IRIUM_POAWX_DOMINANCE_COMMITMENT_ACTIVATION_HEIGHT");
        crate::poawx_admission::global_admission_cache().clear();
        phase26b_clear_gate_env();
    }

    #[test]
    fn phase33_mainnet_no_commitment_validation() {
        assert!(!crate::poawx_dominance::dominance_commitment_gate(
            0,
            Some(1),
            100
        ));
    }

    // ── Phase 34: adaptive-mode consensus integration (chain) ───────────────────

    fn phase34_clear_adaptive_env() {
        std::env::remove_var("IRIUM_POAWX_ADAPTIVE_MODE_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_ADAPTIVE_COMMITMENT_REQUIRED");
    }

    /// Build (do NOT connect) the next all-gates block at `height`, ingesting its
    /// admissions into the global cache. Mirrors phase28_build_connect_chain's loop.
    fn phase34_build_next_block(
        st: &ChainState,
        height: u64,
        prev: [u8; 32],
        parent_prev: Option<[u8; 32]>,
    ) -> Block {
        use crate::poawx_admission::global_admission_cache;
        let net = crate::activation::network_id_byte();
        let genesis_time = st.chain[0].header.time;
        let bits = st.target_for_height(height).bits;
        let proof = crate::poawx_mining_harness::build_devnet_all_gates_block(
            net,
            height,
            prev,
            parent_prev,
            bits,
            genesis_time + height as u32,
            4,
        )
        .unwrap_or_else(|e| panic!("phase34 build H{height}: {e}"));
        let cache = global_admission_cache();
        cache.clear();
        cache.set_tip(height);
        for adm in &proof.admissions {
            let _ = cache.ingest_bytes(adm);
        }
        proof.block
    }

    fn phase34_attach_commitment(
        src: &Block,
        c: crate::poawx_adaptive::PoawxAdaptiveCommitmentV1,
    ) -> Block {
        let mut blk = src.clone();
        if let Some(rs) = blk.poawx_receipts.as_mut() {
            if let Some(ext) = rs[0].phase20_ext.as_mut() {
                ext.adaptive_mode_commitment = Some(c);
            }
        }
        blk
    }

    #[test]
    fn phase34_valid_adaptive_commitment_accepted() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        phase26b_set_gate_env();
        std::env::set_var("IRIUM_POAWX_ADAPTIVE_MODE_ACTIVATION_HEIGHT", "1");
        let mut st = base_chain(None);
        let (hashes, _) = phase28_build_connect_chain(&mut st, 3);
        let net = crate::activation::network_id_byte();
        let blk = phase34_build_next_block(&st, 4, hashes[3], Some(hashes[2]));
        let (pre, post, signals) = st.adaptive_transition_for_block(&blk, 4);
        let good =
            crate::poawx_adaptive::PoawxAdaptiveCommitmentV1::new(net, 4, &pre, &post, &signals);
        let with_c = phase34_attach_commitment(&blk, good);
        assert!(
            st.validate_block_adaptive_commitment(&with_c, 4).is_ok(),
            "matching adaptive commitment accepted"
        );
        // Tampered post-state digest rejected.
        let mut bad = good;
        bad.post_state_digest = [0x99u8; 32];
        assert!(st
            .validate_block_adaptive_commitment(&phase34_attach_commitment(&blk, bad), 4)
            .is_err());
        // The commitment changes the ext digest (affects irx1 root) + wire round-trips.
        let ext = with_c.poawx_receipts.as_ref().unwrap()[0]
            .phase20_ext
            .clone()
            .unwrap();
        let mut none = ext.clone();
        none.adaptive_mode_commitment = None;
        assert_ne!(ext.digest(), none.digest());
        assert_eq!(
            crate::poawx::Phase20ReceiptExt::deserialize(&ext.serialize()).unwrap(),
            ext
        );
        crate::poawx_admission::global_admission_cache().clear();
        phase34_clear_adaptive_env();
        phase26b_clear_gate_env();
    }

    #[test]
    fn phase34_missing_commitment_rejected_only_when_enforced() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        phase26b_set_gate_env();
        std::env::set_var("IRIUM_POAWX_ADAPTIVE_MODE_ACTIVATION_HEIGHT", "1");
        let mut st = base_chain(None);
        let (hashes, _) = phase28_build_connect_chain(&mut st, 3);
        let blk = phase34_build_next_block(&st, 4, hashes[3], Some(hashes[2]));
        // Not required: a block WITHOUT an ADM1 commitment is accepted (validated-if-present).
        assert!(
            st.validate_block_adaptive_commitment(&blk, 4).is_ok(),
            "missing commitment OK when not required"
        );
        // Required: the same block is rejected.
        std::env::set_var("IRIUM_POAWX_ADAPTIVE_COMMITMENT_REQUIRED", "1");
        let err = st
            .validate_block_adaptive_commitment(&blk, 4)
            .expect_err("missing commitment rejected when enforced");
        assert!(
            err.contains("phase34") && err.contains("required"),
            "got: {err}"
        );
        crate::poawx_admission::global_admission_cache().clear();
        phase34_clear_adaptive_env();
        phase26b_clear_gate_env();
    }

    #[test]
    fn phase34_adaptive_state_replays_from_blocks() {
        // The adaptive state is a pure function of the active chain: rebuilding from
        // the active chain matches the forward connect, and an independent identical
        // build reaches the same state (cold-replay equivalence). No local input.
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        phase26b_set_gate_env();
        std::env::set_var("IRIUM_POAWX_ADAPTIVE_MODE_ACTIVATION_HEIGHT", "1");
        let mut st = base_chain(None);
        let _ = phase28_build_connect_chain(&mut st, 4);
        let forward = st.adaptive_state;
        // Rebuild from the active chain reproduces the forward-connected state.
        st.rebuild_adaptive_state_from_chain();
        assert_eq!(
            st.adaptive_state, forward,
            "rebuild-from-chain matches forward connect"
        );
        // Independent identical build reaches the same adaptive state.
        let mut st_b = base_chain(None);
        let _ = phase28_build_connect_chain(&mut st_b, 4);
        assert_eq!(
            st_b.adaptive_state, forward,
            "deterministic replay reaches the same adaptive state"
        );
        crate::poawx_admission::global_admission_cache().clear();
        phase34_clear_adaptive_env();
        phase26b_clear_gate_env();
    }

    #[test]
    fn phase34_reorg_restores_adaptive_state() {
        // (1) A rejected reorg (below the finalized checkpoint) leaves the adaptive
        // state intact. (2) The reorg-rebuild mechanism (rebuild_adaptive_state_from_chain)
        // clears any stale/abandoned-fork mode and restores the active-chain state.
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        phase26b_set_gate_env();
        std::env::set_var("IRIUM_POAWX_ADAPTIVE_MODE_ACTIVATION_HEIGHT", "1");
        let mut st = base_chain(None);
        let (hashes, _) = phase28_build_connect_chain(&mut st, 5);
        let before = st.adaptive_state;
        // (1) Reorg below finalized (height 4) is rejected; adaptive state unchanged.
        let fork_hash = phase28_insert_fork_point(&mut st, 2, hashes[1]);
        let err = st
            .reorg_to_tip(fork_hash)
            .expect_err("reorg below finalized rejected");
        assert!(err.contains("phase28"), "got: {err}");
        assert_eq!(
            st.adaptive_state, before,
            "rejected reorg leaves adaptive state intact"
        );
        // (2) A stale/abandoned-fork mode is cleared by the active-chain rebuild.
        st.adaptive_state = crate::poawx_adaptive::PoawxAdaptiveState {
            mode: crate::poawx_adaptive::AdaptiveMode::Caution,
            recovery_window_remaining: 99,
        };
        st.rebuild_adaptive_state_from_chain();
        assert_eq!(
            st.adaptive_state, before,
            "rebuild from active chain restores the adaptive state"
        );
        crate::poawx_admission::global_admission_cache().clear();
        phase34_clear_adaptive_env();
        phase26b_clear_gate_env();
    }

    #[test]
    fn phase34_mode_effects_enforced() {
        // Under Caution+, an active-but-not-required dominance commitment becomes
        // REQUIRED; Normal imposes no extra requirement. Additive, never weakening.
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        phase26b_set_gate_env();
        std::env::set_var("IRIUM_POAWX_ADAPTIVE_MODE_ACTIVATION_HEIGHT", "1");
        let mut st = base_chain(None);
        // Build with dominance-commitment INACTIVE so harness blocks (no DMC) connect
        // even though the chain enters Caution (recent registered tickets == 0).
        let (hashes, _) = phase28_build_connect_chain(&mut st, 2);
        let blk = phase34_build_next_block(&st, 3, hashes[2], Some(hashes[1]));
        // Now activate the dominance-commitment gate so the Caution effect bites.
        std::env::set_var("IRIUM_POAWX_DOMINANCE_COMMITMENT_ACTIVATION_HEIGHT", "1");
        // Normal: no extra requirement (the all-gates block has no DMC1 but passes).
        st.adaptive_state = crate::poawx_adaptive::PoawxAdaptiveState {
            mode: crate::poawx_adaptive::AdaptiveMode::Normal,
            recovery_window_remaining: 0,
        };
        let normal_ok = st.enforce_adaptive_mode_effects(&blk, 3).is_ok();
        // Caution: dominance commitment now required; the block lacks it -> rejected.
        st.adaptive_state = crate::poawx_adaptive::PoawxAdaptiveState {
            mode: crate::poawx_adaptive::AdaptiveMode::Caution,
            recovery_window_remaining: 0,
        };
        let caution_res = st.enforce_adaptive_mode_effects(&blk, 3);
        // Clean up env BEFORE asserting so a failure can never leak gate state.
        std::env::remove_var("IRIUM_POAWX_DOMINANCE_COMMITMENT_ACTIVATION_HEIGHT");
        crate::poawx_admission::global_admission_cache().clear();
        phase34_clear_adaptive_env();
        phase26b_clear_gate_env();
        assert!(normal_ok, "Normal: no extra requirement");
        let err = caution_res.expect_err("Caution requires dominance commitment");
        assert!(
            err.contains("phase34") && err.contains("dominance commitment"),
            "got: {err}"
        );
    }

    #[test]
    fn phase34_inactive_is_noop_and_byte_identical() {
        // With adaptive mode INACTIVE, connect_block does not validate/evolve adaptive
        // state, and a receipt ext with no ADM1 serializes byte-identically to before.
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        phase26b_set_gate_env();
        phase34_clear_adaptive_env();
        let mut st = base_chain(None);
        let _ = phase28_build_connect_chain(&mut st, 3);
        assert_eq!(
            st.adaptive_state,
            crate::poawx_adaptive::PoawxAdaptiveState::genesis(),
            "inactive: adaptive state stays genesis (Normal)"
        );
        // Byte-identity: an ext without an ADM1 section round-trips unchanged.
        let ext = st.chain[1].poawx_receipts.as_ref().unwrap()[0]
            .phase20_ext
            .clone()
            .unwrap();
        assert!(ext.adaptive_mode_commitment.is_none());
        assert_eq!(
            crate::poawx::Phase20ReceiptExt::deserialize(&ext.serialize()).unwrap(),
            ext
        );
        crate::poawx_admission::global_admission_cache().clear();
        phase26b_clear_gate_env();
    }

    #[test]
    fn phase26b_stale_immediate_parent_seed_rejected() {
        // Negative: a height-2 block whose candidate set is seeded by the IMMEDIATE
        // parent hash (the pre-26B / stale seeding — reproduced by building with
        // parent_prev = None so the epoch seed falls back to prev_hash = hash(H1))
        // must be REJECTED by phase21d, because the node expects the epoch seed
        // (grandparent = genesis). Proves phase21d is preserved, not bypassed.
        use crate::poawx_admission::global_admission_cache;
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        phase26b_set_gate_env();

        let locked = load_locked_genesis().expect("locked genesis");
        let genesis = block_from_locked(&locked).expect("genesis block");
        let genesis_hash = genesis.header.hash_for_height(0);
        let mut st = base_chain(None);
        let net = crate::activation::network_id_byte();
        let cache = global_admission_cache();

        // H1 (correct).
        let p1 = crate::poawx_mining_harness::build_devnet_all_gates_block(
            net,
            1,
            genesis_hash,
            None,
            st.target_for_height(1).bits,
            genesis.header.time + 1,
            4,
        )
        .expect("build H1");
        let h1_hash = p1.block_hash;
        cache.clear();
        cache.set_tip(1);
        for adm in &p1.admissions {
            assert_eq!(
                cache.ingest_bytes(adm),
                crate::poawx_gossip::GossipOutcome::AcceptedNew
            );
        }
        st.connect_block(p1.block).expect("connect H1");

        // H2 built with the STALE seed (parent_prev = None => epoch seed = prev_hash
        // = hash(H1), instead of the correct grandparent = genesis).
        let bad = crate::poawx_mining_harness::build_devnet_all_gates_block(
            net,
            2,
            h1_hash,
            None,
            st.target_for_height(2).bits,
            genesis.header.time + 2,
            4,
        )
        .expect("build stale H2");
        cache.clear();
        cache.set_tip(2);
        for adm in &bad.admissions {
            let _ = cache.ingest_bytes(adm);
        }
        let err = st
            .connect_block(bad.block)
            .expect_err("stale immediate-parent candidate-set seed must be rejected");
        assert!(
            err.contains("phase21d") && err.contains("seed"),
            "expected phase21d seed rejection, got: {err}"
        );

        cache.clear();
        phase26b_clear_gate_env();
    }

    #[test]
    fn phase26b_committed_admission_root_and_replay_rejected() {
        // Negative (phase22a binding): the committed-admission commitment binds the
        // candidate set by (network, target_height, seed, root, count). A tampered
        // root, a wrong seed (replay/stale from a different epoch), or a wrong
        // target_height must all fail `matches_candidate_set`. Pure; no block mining.
        use crate::poawx_candidate::{CandidateSet, RoleCandidate};
        use crate::poawx_committed_admission::AdmissionCommitmentV1;
        use crate::poawx_penalty::PenaltyStatus;
        let net = 2u8;
        let mk_set = |th: u64, sd: [u8; 32]| -> CandidateSet {
            let mut cs = CandidateSet::new(net, th, sd);
            for role in 0u8..3 {
                cs.push(RoleCandidate::build(
                    net,
                    th,
                    &sd,
                    role,
                    [role + 1; 20],
                    [role + 2; 33],
                    [role + 3; 32],
                    PenaltyStatus::Clean.id(),
                    1000,
                    [role + 4; 32],
                ));
            }
            cs.sort_canonical();
            cs
        };

        let seed = [0x55u8; 32];
        let target = 7u64;
        let cs = mk_set(target, seed);

        // Correct commitment matches the set.
        let good = AdmissionCommitmentV1::from_candidate_set(&cs, target - 1);
        assert!(good.matches_candidate_set(&cs), "honest commitment matches");

        // Tampered root: a set with different candidates (different height-bound
        // assignment digests) has a different root.
        let cs_tampered = mk_set(target + 100, seed);
        let mut cs_tampered = cs_tampered;
        cs_tampered.target_height = target; // force the height field to match...
        assert!(
            !good.matches_candidate_set(&cs_tampered),
            "commitment must reject a set with a different candidate root"
        );

        // Replay / stale: a commitment frozen for a DIFFERENT seed (epoch) must not
        // match this set.
        let stale =
            AdmissionCommitmentV1::from_candidate_set(&mk_set(target, [0xAAu8; 32]), target - 1);
        assert!(
            !stale.matches_candidate_set(&cs),
            "commitment frozen for a different seed/epoch must not match (replay-safe)"
        );

        // Wrong target height must not match either.
        let wrong_h = AdmissionCommitmentV1::from_candidate_set(&mk_set(target + 1, seed), target);
        assert!(
            !wrong_h.matches_candidate_set(&cs),
            "commitment for a different target height must not match"
        );
    }

    #[test]
    fn phase26d_cold_replay_with_persisted_admissions() {
        // Phase 26D: prove a restarted node can re-validate persisted blocks
        // through the UNCHANGED phase21e gate by reloading the durable
        // candidate-admission snapshot. Build a 6-block all-gates chain (ingesting
        // + persisting admissions), then simulate a restart (clear the in-memory
        // admission cache) and show:
        //   (a) WITHOUT the reload, connect_block is REJECTED by phase21e (gate
        //       intact — persistence is not a bypass);
        //   (b) WITH the reload from disk, a fresh chain re-connects every block.
        use crate::poawx_admission::global_admission_cache;
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        phase26b_set_gate_env();

        let locked = load_locked_genesis().expect("locked genesis");
        let genesis = block_from_locked(&locked).expect("genesis block");
        let genesis_hash = genesis.header.hash_for_height(0);
        let net = crate::activation::network_id_byte();
        let cache = global_admission_cache();
        let path = std::path::PathBuf::from("target")
            .join(format!("p26d_chain_adm_{}.dat", std::process::id()));
        let _ = std::fs::remove_file(&path);
        cache.set_persist_path(path.clone());
        cache.clear();

        // ---- Build + connect 6 blocks; admissions auto-persist on ingest. ----
        let n_blocks = 6u64;
        let mut st1 = base_chain(None);
        let mut prev = genesis_hash;
        let mut parent_prev: Option<[u8; 32]> = None;
        let mut blocks: Vec<Block> = Vec::new();
        for h in 1..=n_blocks {
            let bits = st1.target_for_height(h).bits;
            let proof = crate::poawx_mining_harness::build_devnet_all_gates_block(
                net,
                h,
                prev,
                parent_prev,
                bits,
                genesis.header.time + h as u32,
                4,
            )
            .unwrap_or_else(|e| panic!("build H{h}: {e}"));
            cache.set_tip(h);
            for adm in &proof.admissions {
                assert_eq!(
                    cache.ingest_bytes(adm),
                    crate::poawx_gossip::GossipOutcome::AcceptedNew
                );
            }
            let blk_prev = prev;
            let blk_hash = proof.block_hash;
            blocks.push(proof.block.clone());
            st1.connect_block(proof.block)
                .unwrap_or_else(|e| panic!("connect H{h}: {e}"));
            parent_prev = Some(blk_prev);
            prev = blk_hash;
        }
        assert!(path.exists(), "admissions persisted to disk on ingest");

        // ---- (a) Simulated restart with EMPTY cache: phase21e must reject. ----
        cache.clear();
        {
            let mut st_neg = base_chain(None);
            let err = st_neg
                .connect_block(blocks[0].clone())
                .expect_err("phase21e must reject without admitted candidates");
            assert!(
                err.contains("phase21e"),
                "expected phase21e admitted-set rejection, got: {err}"
            );
        }

        // ---- (b) Reload persisted admissions, then a FRESH chain reconnects. ----
        cache.clear();
        let reloaded = cache.load_persisted();
        assert_eq!(
            reloaded,
            (n_blocks as usize) * 3,
            "all per-height role admissions reloaded from disk"
        );
        let mut st2 = base_chain(None);
        let before = st2.height;
        for (i, blk) in blocks.iter().enumerate() {
            st2.connect_block(blk.clone())
                .unwrap_or_else(|e| panic!("cold replay H{} failed: {e}", i + 1));
        }
        assert_eq!(
            st2.height,
            before + n_blocks,
            "cold replay reached the 6-block tip via the reloaded admitted set"
        );

        cache.clear();
        let _ = std::fs::remove_file(&path);
        phase26b_clear_gate_env();
    }

    #[test]
    fn phase26e_fresh_sync_via_served_admissions() {
        // Phase 26E: a brand-new / fresh-wipe node (empty admission cache, no
        // persisted snapshot) can sync a 6-block chain when a peer SERVES the
        // historical candidate admissions for the synced heights. The receiver
        // ingests them via the NORMAL gossip path (`ingest_bytes`, window 64,
        // cache tip 0) — phase21e is UNCHANGED. This mirrors the P2P serving
        // wired into the block-serve handlers (admissions sent before blocks).
        use crate::poawx_admission::global_admission_cache;
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        phase26b_set_gate_env();

        let locked = load_locked_genesis().expect("locked genesis");
        let genesis = block_from_locked(&locked).expect("genesis block");
        let genesis_hash = genesis.header.hash_for_height(0);
        let net = crate::activation::network_id_byte();
        let cache = global_admission_cache();
        cache.clear();

        // ---- "Server" builds a 6-block chain and admits each height. ----
        let n_blocks = 6u64;
        let mut st_srv = base_chain(None);
        let mut prev = genesis_hash;
        let mut parent_prev: Option<[u8; 32]> = None;
        let mut blocks: Vec<Block> = Vec::new();
        for h in 1..=n_blocks {
            let bits = st_srv.target_for_height(h).bits;
            let proof = crate::poawx_mining_harness::build_devnet_all_gates_block(
                net,
                h,
                prev,
                parent_prev,
                bits,
                genesis.header.time + h as u32,
                4,
            )
            .unwrap_or_else(|e| panic!("build H{h}: {e}"));
            cache.set_tip(h);
            for adm in &proof.admissions {
                assert_eq!(
                    cache.ingest_bytes(adm),
                    crate::poawx_gossip::GossipOutcome::AcceptedNew
                );
            }
            let blk_prev = prev;
            let blk_hash = proof.block_hash;
            blocks.push(proof.block.clone());
            st_srv
                .connect_block(proof.block)
                .unwrap_or_else(|e| panic!("connect H{h}: {e}"));
            parent_prev = Some(blk_prev);
            prev = blk_hash;
        }

        // What a peer SERVES to a syncing node: admissions_for_height(h) (exactly
        // what the P2P block-serve handlers now send before the block bodies).
        let mut served: Vec<Vec<u8>> = Vec::new();
        for h in 1..=n_blocks {
            for adm in cache.admissions_for_height(h) {
                served.push(adm.serialize());
            }
        }
        assert_eq!(
            served.len(),
            (n_blocks as usize) * 3,
            "server can serve the historical admissions for the synced heights"
        );

        // ---- Fresh node: empty cache, tip 0 (as a fresh syncing node has). ----
        cache.clear();
        cache.set_tip(0);

        // (a) Negative: phase21e rejects without the admissions.
        {
            let mut st_neg = base_chain(None);
            let err = st_neg
                .connect_block(blocks[0].clone())
                .expect_err("phase21e must reject a fresh node lacking admissions");
            assert!(
                err.contains("phase21e"),
                "expected phase21e rejection, got: {err}"
            );
        }

        // (b) Receiver ingests the SERVED admissions via the normal gossip path
        // (window 64, tip 0 covers heights 1..=6). Tampered/wrong-network served
        // records are rejected by that same path.
        cache.clear();
        cache.set_tip(0);
        let mut tampered = served[0].clone();
        tampered[20] ^= 0xFF;
        assert_ne!(
            cache.ingest_bytes(&tampered),
            crate::poawx_gossip::GossipOutcome::AcceptedNew,
            "tampered served admission rejected by the receiver"
        );
        let mut ingested = 0usize;
        for raw in &served {
            if cache.ingest_bytes(raw) == crate::poawx_gossip::GossipOutcome::AcceptedNew {
                ingested += 1;
            }
        }
        assert_eq!(
            ingested,
            (n_blocks as usize) * 3,
            "fresh node ingested all served historical admissions"
        );

        // (c) The fresh node now connects every block normally through phase21e.
        let mut st_fresh = base_chain(None);
        let before = st_fresh.height;
        for (i, blk) in blocks.iter().enumerate() {
            st_fresh
                .connect_block(blk.clone())
                .unwrap_or_else(|e| panic!("fresh sync H{} failed: {e}", i + 1));
        }
        assert_eq!(
            st_fresh.height,
            before + n_blocks,
            "fresh node synced the 6-block chain to the tip via served admissions"
        );

        cache.clear();
        phase26b_clear_gate_env();
    }

    #[test]
    fn phase22d_true_vrf_enforcement() {
        use crate::poawx::{
            ROLE_COMPUTE_CONTRIBUTOR, ROLE_SUPPORT_CONTRIBUTOR, ROLE_VERIFY_CONTRIBUTOR,
        };
        use crate::poawx_candidate::{
            assignment_v2_score_from_output, effective_score, true_vrf_enforced, AssignmentProofV2,
            CandidateSet, RoleCandidate,
        };
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_TRUE_VRF_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_TRUE_VRF_REQUIRED", "1");
        assert!(true_vrf_enforced(1), "enforced on testnet");

        let net = crate::activation::network_id_byte();
        let sk = test_signing_key();
        let height = 1u64;
        let seed = [0x44u8; 32]; // candidate-set seed
        let base_ext = p20_ext(net, height, &seed, 0, [0u8; 20]);
        let receipt = make_test_receipt(height, &sk, seed, 1);

        // For each role: a real V2 proof + a candidate whose assignment_proof_digest is
        // the VRF output (so the score derives from the VRF output).
        let mk = |secret: u8,
                  role: u8,
                  solver: [u8; 20],
                  ticket: [u8; 32]|
         -> (AssignmentProofV2, RoleCandidate) {
            let pr =
                AssignmentProofV2::prove(&[secret; 32], net, height, role, solver, ticket, seed)
                    .expect("v2 prove");
            let dw = 1000u64;
            let pw = 1000u64;
            let es = effective_score(assignment_v2_score_from_output(&pr.vrf_output), dw, pw);
            let cand = RoleCandidate {
                role_id: role,
                solver_pkh: solver,
                assignment_public_key: pr.assignment_public_key,
                ticket_digest: ticket,
                penalty_status: 0,
                assignment_proof_digest: pr.vrf_output,
                dominance_weight: dw,
                penalty_weight: pw,
                effective_score: es,
                role_claim_digest: [role; 32],
            };
            (pr, cand)
        };
        let (pc, cc) = mk(7, ROLE_COMPUTE_CONTRIBUTOR, [0xC1u8; 20], [0x11u8; 32]);
        let (pv, cv) = mk(8, ROLE_VERIFY_CONTRIBUTOR, [0xC2u8; 20], [0x12u8; 32]);
        let (ps, csup) = mk(9, ROLE_SUPPORT_CONTRIBUTOR, [0xC3u8; 20], [0x13u8; 32]);
        let mut cs = CandidateSet::new(net, height, seed);
        for c in [cc, cv, csup] {
            cs.push(c);
        }
        cs.sort_canonical();
        let proofs = [pc.clone(), pv.clone(), ps.clone()];

        let blk = |v2: Option<[AssignmentProofV2; 3]>, with_cs: bool| -> Block {
            let mut ext = base_ext.clone();
            ext.role_reward.compute_contributor_pkh = [0xC1u8; 20];
            ext.role_reward.verify_contributor_pkh = [0xC2u8; 20];
            ext.role_reward.support_contributor_pkh = [0xC3u8; 20];
            ext.candidate_set = if with_cs { Some(cs.clone()) } else { None };
            ext.role_assignment_v2 = v2;
            let mut r = receipt.clone();
            r.phase20_ext = Some(ext);
            Block {
                header: BlockHeader {
                    version: 1,
                    prev_hash: seed,
                    merkle_root: [0u8; 32],
                    time: 0,
                    bits: 0x207fffff,
                    nonce: 0,
                },
                transactions: vec![],
                auxpow: None,
                poawx_receipts: Some(vec![r]),
            }
        };

        let st = base_chain(None);
        // valid V2 accepts.
        assert!(
            st.validate_block_true_vrf(&blk(Some(proofs.clone()), true), height)
                .is_ok(),
            "valid V2 proofs accept"
        );
        // V1-only (no V2 section) rejects under V2-required.
        assert!(
            st.validate_block_true_vrf(&blk(None, true), height)
                .is_err(),
            "missing V2 proofs reject (V1 not accepted)"
        );
        // missing candidate set rejects.
        assert!(
            st.validate_block_true_vrf(&blk(Some(proofs.clone()), false), height)
                .is_err(),
            "missing candidate set rejects"
        );
        // mutated VRF proof rejects (digest mismatch and/or VRF-verify failure).
        let mut bad = proofs.clone();
        bad[0].vrf_proof[0] ^= 1;
        assert!(
            st.validate_block_true_vrf(&blk(Some(bad), true), height)
                .is_err(),
            "mutated VRF proof rejects"
        );
        // wrong height rejects.
        assert!(
            st.validate_block_true_vrf(&blk(Some(proofs.clone()), true), height + 1)
                .is_err(),
            "wrong height rejects"
        );

        // mainnet hard-off.
        std::env::set_var("IRIUM_NETWORK", "mainnet");
        assert!(!true_vrf_enforced(1), "mainnet hard-off");

        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_TRUE_VRF_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_TRUE_VRF_REQUIRED");
    }

    #[test]
    fn phase22a_committed_admission_enforcement() {
        use crate::poawx::{
            ROLE_COMPUTE_CONTRIBUTOR, ROLE_SUPPORT_CONTRIBUTOR, ROLE_VERIFY_CONTRIBUTOR,
        };
        use crate::poawx_candidate::{CandidateSet, RoleCandidate};
        use crate::poawx_committed_admission::{
            committed_admission_enforced, AdmissionCommitmentV1,
        };
        use crate::poawx_penalty::PenaltyStatus;
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_COMMITTED_ADMISSION_ACTIVATION_HEIGHT", "2");
        std::env::set_var("IRIUM_POAWX_COMMITTED_ADMISSION_REQUIRED", "1");
        assert!(
            committed_admission_enforced(3),
            "enforced on testnet at H>=2"
        );

        let net = crate::activation::network_id_byte();
        let sk = test_signing_key();
        let grandparent = [0x6Au8; 32]; // freeze seed = parent's prev_hash
        let target = 3u64;
        let base_ext = p20_ext(net, target, &grandparent, 0, [0u8; 20]);

        // admitted candidate set for H=3, bound to the freeze seed (grandparent).
        let mk = |role: u8, solver: [u8; 20], tag: u8| {
            RoleCandidate::build(
                net,
                target,
                &grandparent,
                role,
                solver,
                [0x02u8; 33],
                [tag; 32],
                PenaltyStatus::Clean.id(),
                1000,
                [tag.wrapping_add(1); 32],
            )
        };
        let mut cs = CandidateSet::new(net, target, grandparent);
        for c in [
            mk(ROLE_COMPUTE_CONTRIBUTOR, [0xC1u8; 20], 0x11),
            mk(ROLE_VERIFY_CONTRIBUTOR, [0xC2u8; 20], 0x12),
            mk(ROLE_SUPPORT_CONTRIBUTOR, [0xC3u8; 20], 0x13),
        ] {
            cs.push(c);
        }
        cs.sort_canonical();

        // PARENT block H=2: prev_hash = grandparent; ext commits admission for H=3.
        let parent = {
            let mut ext = p20_ext(net, 2, &grandparent, 0, [0u8; 20]);
            ext.committed_admission = Some(AdmissionCommitmentV1::from_candidate_set(&cs, 2));
            let mut r = make_test_receipt(2, &sk, grandparent, 1);
            r.phase20_ext = Some(ext);
            Block {
                header: BlockHeader {
                    version: 1,
                    prev_hash: grandparent,
                    merkle_root: [0u8; 32],
                    time: 0,
                    bits: 0x207fffff,
                    nonce: 0,
                },
                transactions: vec![],
                auxpow: None,
                poawx_receipts: Some(vec![r]),
            }
        };
        let parent_hash = parent.header.hash_for_height(2);

        // CHILD block H=3 carrying the matching candidate set.
        let child = |set: Option<CandidateSet>| -> Block {
            let mut ext = base_ext.clone();
            ext.candidate_set = set;
            let mut r = make_test_receipt(target, &sk, parent_hash, 1);
            r.phase20_ext = Some(ext);
            Block {
                header: BlockHeader {
                    version: 1,
                    prev_hash: parent_hash,
                    merkle_root: [0u8; 32],
                    time: 0,
                    bits: 0x207fffff,
                    nonce: 0,
                },
                transactions: vec![],
                auxpow: None,
                poawx_receipts: Some(vec![r]),
            }
        };

        let st = base_chain(None);
        // exact committed set => accept.
        assert!(
            st.validate_block_committed_admission(&child(Some(cs.clone())), Some(&parent), target)
                .is_ok(),
            "matching committed candidate set accepts"
        );
        // mutated candidate set => root mismatch => reject.
        let mut mutated = cs.clone();
        mutated.candidates[0].dominance_weight ^= 1;
        assert!(
            st.validate_block_committed_admission(&child(Some(mutated)), Some(&parent), target)
                .is_err(),
            "mutated set rejects (root mismatch)"
        );
        // missing candidate set => reject.
        assert!(
            st.validate_block_committed_admission(&child(None), Some(&parent), target)
                .is_err(),
            "missing candidate set rejects"
        );
        // parent without a commitment (and not activation height) => reject.
        let bare_parent = {
            let mut r = make_test_receipt(2, &sk, grandparent, 1);
            r.phase20_ext = Some(p20_ext(net, 2, &grandparent, 0, [0u8; 20]));
            Block {
                header: BlockHeader {
                    version: 1,
                    prev_hash: grandparent,
                    merkle_root: [0u8; 32],
                    time: 0,
                    bits: 0x207fffff,
                    nonce: 0,
                },
                transactions: vec![],
                auxpow: None,
                poawx_receipts: Some(vec![r]),
            }
        };
        assert!(
            st.validate_block_committed_admission(
                &child(Some(cs.clone())),
                Some(&bare_parent),
                target
            )
            .is_err(),
            "missing parent commitment rejects (H>activation)"
        );
        // activation-height grace: at H=2 a bare parent (H=1, pre-gate) is accepted.
        let h2_block = {
            let mut r = make_test_receipt(2, &sk, grandparent, 1);
            r.phase20_ext = Some(p20_ext(net, 2, &grandparent, 0, [0u8; 20]));
            Block {
                header: BlockHeader {
                    version: 1,
                    prev_hash: grandparent,
                    merkle_root: [0u8; 32],
                    time: 0,
                    bits: 0x207fffff,
                    nonce: 0,
                },
                transactions: vec![],
                auxpow: None,
                poawx_receipts: Some(vec![r]),
            }
        };
        assert!(
            st.validate_block_committed_admission(&h2_block, Some(&bare_parent), 2)
                .is_ok(),
            "activation-height grace accepts pre-gate parent"
        );
        // outgoing self-consistency: a block committing with the WRONG freeze seed rejects.
        let bad_commit = {
            let mut ext = p20_ext(net, 2, &grandparent, 0, [0u8; 20]);
            // commit for target 3 but freeze seed != this block's prev_hash.
            let mut bogus = cs.clone();
            bogus.seed = [0x99u8; 32];
            ext.committed_admission = Some(AdmissionCommitmentV1::from_candidate_set(&bogus, 2));
            let mut r = make_test_receipt(2, &sk, grandparent, 1);
            r.phase20_ext = Some(ext);
            Block {
                header: BlockHeader {
                    version: 1,
                    prev_hash: grandparent,
                    merkle_root: [0u8; 32],
                    time: 0,
                    bits: 0x207fffff,
                    nonce: 0,
                },
                transactions: vec![],
                auxpow: None,
                poawx_receipts: Some(vec![r]),
            }
        };
        assert!(
            st.validate_block_committed_admission(&bad_commit, Some(&bare_parent), 2)
                .is_err(),
            "own commitment with wrong freeze seed rejects"
        );

        // mainnet hard-off.
        std::env::set_var("IRIUM_NETWORK", "mainnet");
        assert!(!committed_admission_enforced(3), "mainnet hard-off");

        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_COMMITTED_ADMISSION_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_COMMITTED_ADMISSION_REQUIRED");
    }

    #[test]
    fn phase21h_finality_enforcement() {
        use crate::poawx::ROLE_SUPPORT_CONTRIBUTOR;
        use crate::poawx_candidate::{CandidateSet, RoleCandidate};
        use crate::poawx_finality::{
            finality_committee_enforced, FinalityProofV1, FinalityVoteType, FinalityVoteV1,
        };
        use crate::poawx_penalty::PenaltyStatus;
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_FINALITY_COMMITTEE_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_FINALITY_COMMITTEE_REQUIRED", "1");
        std::env::set_var("IRIUM_POAWX_FINALITY_THRESHOLD_NUM", "2");
        std::env::set_var("IRIUM_POAWX_FINALITY_THRESHOLD_DEN", "3");
        assert!(finality_committee_enforced(1), "enforced on testnet");

        let net = crate::activation::network_id_byte();
        let parent = phase13b_parent_block();
        let parent_hash = parent.header.hash_for_height(0);
        let height = 1u64;
        let sk = signing_key(0x41);
        let base_ext = p20_ext(net, height, &parent_hash, 0, [0u8; 20]);
        let receipt = make_test_receipt(height, &sk, parent_hash, 1);

        // committee = 3 SUPPORT candidates keyed by 3 secp256k1 keys.
        let members = [signing_key(0xA1), signing_key(0xB2), signing_key(0xC3)];
        let mut cs = CandidateSet::new(net, height, parent_hash);
        for (i, m) in members.iter().enumerate() {
            cs.push(RoleCandidate::build(
                net,
                height,
                &parent_hash,
                ROLE_SUPPORT_CONTRIBUTOR,
                key_hash(m),
                [0x02u8; 33],
                [(0x30 + i as u8); 32],
                PenaltyStatus::Clean.id(),
                1000,
                [(0x40 + i as u8); 32],
            ));
        }
        cs.sort_canonical();

        // finality proof finalizing the parent (block_hash = prev_hash).
        let mk_proof = |signers: usize| -> FinalityProofV1 {
            let mut p = FinalityProofV1::new(net, height, parent_hash, [0u8; 32], 0, 2, 3);
            for m in members.iter().take(signers) {
                p.push(FinalityVoteV1::signed(
                    m,
                    net,
                    height,
                    parent_hash,
                    [0u8; 32],
                    0,
                    [0x11u8; 32],
                    FinalityVoteType::Commit,
                ));
            }
            p.sort_canonical();
            p
        };

        let blk = |proof: Option<FinalityProofV1>, with_cs: bool| -> Block {
            let mut ext = base_ext.clone();
            ext.candidate_set = if with_cs { Some(cs.clone()) } else { None };
            ext.finality_proof = proof;
            let mut r = receipt.clone();
            r.phase20_ext = Some(ext);
            Block {
                header: BlockHeader {
                    version: 1,
                    prev_hash: parent_hash,
                    merkle_root: [0u8; 32],
                    time: 0,
                    bits: 0x207fffff,
                    nonce: 0,
                },
                transactions: vec![],
                auxpow: None,
                poawx_receipts: Some(vec![r]),
            }
        };

        let st = base_chain(None);
        // 2-of-3 commit votes => threshold met => accept.
        assert!(
            st.validate_block_finality(&blk(Some(mk_proof(2)), true), height)
                .is_ok(),
            "2-of-3 finality proof accepts"
        );
        // 1 vote => below threshold => reject.
        assert!(
            st.validate_block_finality(&blk(Some(mk_proof(1)), true), height)
                .is_err(),
            "insufficient threshold rejects"
        );
        // missing finality proof => reject (placeholder/puzzle alone NOT enough).
        assert!(
            st.validate_block_finality(&blk(None, true), height)
                .is_err(),
            "missing finality proof rejects"
        );
        // missing candidate set (no committee source) => reject.
        assert!(
            st.validate_block_finality(&blk(Some(mk_proof(2)), false), height)
                .is_err(),
            "missing candidate set rejects"
        );
        // producer-weakened threshold (1/1 vs configured 2/3) => reject.
        let mut weak = mk_proof(1);
        weak.threshold_num = 1;
        weak.threshold_den = 1;
        weak.sort_canonical();
        assert!(
            st.validate_block_finality(&blk(Some(weak), true), height)
                .is_err(),
            "weakened threshold rejects"
        );

        // mainnet hard-off.
        std::env::set_var("IRIUM_NETWORK", "mainnet");
        assert!(!finality_committee_enforced(1), "mainnet hard-off");

        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_FINALITY_COMMITTEE_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_FINALITY_COMMITTEE_REQUIRED");
        std::env::remove_var("IRIUM_POAWX_FINALITY_THRESHOLD_NUM");
        std::env::remove_var("IRIUM_POAWX_FINALITY_THRESHOLD_DEN");
    }

    #[test]
    fn phase21f_puzzle_enforcement() {
        use crate::poawx::{
            ROLE_COMPUTE_CONTRIBUTOR, ROLE_SUPPORT_CONTRIBUTOR, ROLE_VERIFY_CONTRIBUTOR,
        };
        use crate::poawx_candidate::{CandidateSet, RoleCandidate};
        use crate::poawx_penalty::PenaltyStatus;
        use crate::poawx_puzzle::{
            default_profile, puzzle_work_enforced, solve_dev, PuzzleChallengeV1, PuzzleSolutionV1,
        };
        use sha2::{Digest, Sha256};
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_PUZZLE_WORK_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_PUZZLE_WORK_REQUIRED", "1");
        std::env::set_var("IRIUM_POAWX_PUZZLE_BITS", "4");
        assert!(puzzle_work_enforced(1), "enforced on testnet");

        let net = crate::activation::network_id_byte();
        let parent = phase13b_parent_block();
        let parent_hash = parent.header.hash_for_height(0);
        let height = 1u64;
        let sk = signing_key(0x41);
        let base_ext = p20_ext(net, height, &parent_hash, 0, [0u8; 20]);
        let receipt = make_test_receipt(height, &sk, parent_hash, 1);
        let profile = default_profile();

        let mk = |role: u8, solver: [u8; 20], tag: u8| {
            RoleCandidate::build(
                net,
                height,
                &parent_hash,
                role,
                solver,
                [0x02u8; 33],
                [tag; 32],
                PenaltyStatus::Clean.id(),
                1000,
                [tag.wrapping_add(1); 32],
            )
        };
        let cands = [
            mk(ROLE_COMPUTE_CONTRIBUTOR, [0xC1u8; 20], 0x11),
            mk(ROLE_VERIFY_CONTRIBUTOR, [0xC2u8; 20], 0x12),
            mk(ROLE_SUPPORT_CONTRIBUTOR, [0xC3u8; 20], 0x13),
        ];
        let mut cs = CandidateSet::new(net, height, parent_hash);
        for c in cands.iter() {
            cs.push(c.clone());
        }
        cs.sort_canonical();

        // solve the assigned puzzle for each selected role (from its candidate).
        let roles = [
            ROLE_COMPUTE_CONTRIBUTOR,
            ROLE_VERIFY_CONTRIBUTOR,
            ROLE_SUPPORT_CONTRIBUTOR,
        ];
        let mut sols: Vec<PuzzleSolutionV1> = Vec::new();
        for role in roles {
            let cand = cs.best_for_role(role).unwrap();
            let cdg: [u8; 32] = {
                let mut h = Sha256::new();
                h.update(cand.serialize());
                h.finalize().into()
            };
            let challenge = PuzzleChallengeV1::build(
                net,
                height,
                role,
                cand.solver_pkh,
                cand.ticket_digest,
                cand.assignment_proof_digest,
                cdg,
                parent_hash,
                profile,
            );
            sols.push(solve_dev(&challenge).expect("solve"));
        }
        let proofs = [sols[0], sols[1], sols[2]];

        let blk = |puzzle: Option<[PuzzleSolutionV1; 3]>, with_cs: bool| -> Block {
            let mut ext = base_ext.clone();
            ext.role_reward.compute_contributor_pkh = [0xC1u8; 20];
            ext.role_reward.verify_contributor_pkh = [0xC2u8; 20];
            ext.role_reward.support_contributor_pkh = [0xC3u8; 20];
            ext.candidate_set = if with_cs { Some(cs.clone()) } else { None };
            ext.role_puzzle_proofs = puzzle;
            let mut r = receipt.clone();
            r.phase20_ext = Some(ext);
            Block {
                header: BlockHeader {
                    version: 1,
                    prev_hash: parent_hash,
                    merkle_root: [0u8; 32],
                    time: 0,
                    bits: 0x207fffff,
                    nonce: 0,
                },
                transactions: vec![],
                auxpow: None,
                poawx_receipts: Some(vec![r]),
            }
        };

        let st = base_chain(None);
        // valid puzzle proofs accept.
        assert!(
            st.validate_block_puzzle_proofs(&blk(Some(proofs), true), height)
                .is_ok(),
            "valid puzzle proofs accept"
        );
        // missing puzzle proofs reject.
        assert!(
            st.validate_block_puzzle_proofs(&blk(None, true), height)
                .is_err(),
            "missing puzzle proofs reject"
        );
        // missing candidate set reject (puzzle binds to candidate).
        assert!(
            st.validate_block_puzzle_proofs(&blk(Some(proofs), false), height)
                .is_err(),
            "missing candidate set rejects"
        );
        // tampered solution reject.
        let mut bad = proofs;
        bad[0].proof_digest[0] ^= 1;
        assert!(
            st.validate_block_puzzle_proofs(&blk(Some(bad), true), height)
                .is_err(),
            "tampered puzzle solution rejects"
        );
        // wrong height => recomputed challenge differs => reject.
        assert!(
            st.validate_block_puzzle_proofs(&blk(Some(proofs), true), height + 1)
                .is_err(),
            "wrong height rejects"
        );

        // mainnet hard-off.
        std::env::set_var("IRIUM_NETWORK", "mainnet");
        assert!(!puzzle_work_enforced(1), "mainnet hard-off");

        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_PUZZLE_WORK_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_PUZZLE_WORK_REQUIRED");
        std::env::remove_var("IRIUM_POAWX_PUZZLE_BITS");
    }

    #[test]
    fn phase21e_admission_enforcement() {
        use crate::poawx::{
            ROLE_COMPUTE_CONTRIBUTOR, ROLE_SUPPORT_CONTRIBUTOR, ROLE_VERIFY_CONTRIBUTOR,
        };
        use crate::poawx_admission::{
            candidate_admission_enforced, global_admission_cache, CandidateAdmissionV1,
        };
        use crate::poawx_candidate::{CandidateSet, RoleCandidate};
        use crate::poawx_penalty::PenaltyStatus;
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_CANDIDATE_SET_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_CANDIDATE_SET_REQUIRED", "1");
        std::env::set_var("IRIUM_POAWX_CANDIDATE_ADMISSION_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_CANDIDATE_ADMISSION_REQUIRED", "1");
        std::env::remove_var("IRIUM_POAWX_ANTI_DOMINATION_ACTIVATION_HEIGHT");
        assert!(candidate_admission_enforced(1), "enforced on testnet");

        let net = crate::activation::network_id_byte();
        let parent = phase13b_parent_block();
        let parent_hash = parent.header.hash_for_height(0);
        let height = 1u64;
        let sk = signing_key(0x41);
        let base_ext = p20_ext(net, height, &parent_hash, 0, [0u8; 20]);
        let receipt = make_test_receipt(height, &sk, parent_hash, 1);

        let mk = |role: u8, solver: [u8; 20], tag: u8| {
            RoleCandidate::build(
                net,
                height,
                &parent_hash,
                role,
                solver,
                [0x02u8; 33],
                [tag; 32],
                PenaltyStatus::Clean.id(),
                1000,
                [tag.wrapping_add(1); 32],
            )
        };
        let c = mk(ROLE_COMPUTE_CONTRIBUTOR, [0xC1u8; 20], 0x11);
        let v = mk(ROLE_VERIFY_CONTRIBUTOR, [0xC2u8; 20], 0x12);
        let s = mk(ROLE_SUPPORT_CONTRIBUTOR, [0xC3u8; 20], 0x13);
        let cx = mk(ROLE_COMPUTE_CONTRIBUTOR, [0xCEu8; 20], 0x55);
        let mut cs = CandidateSet::new(net, height, parent_hash);
        for cand in [c.clone(), v.clone(), s.clone()] {
            cs.push(cand);
        }
        cs.sort_canonical();

        let blk = {
            let mut ext = base_ext.clone();
            ext.role_reward.compute_contributor_pkh = [0xC1u8; 20];
            ext.role_reward.verify_contributor_pkh = [0xC2u8; 20];
            ext.role_reward.support_contributor_pkh = [0xC3u8; 20];
            ext.candidate_set = Some(cs.clone());
            let mut r = receipt.clone();
            r.phase20_ext = Some(ext);
            Block {
                header: BlockHeader {
                    version: 1,
                    prev_hash: parent_hash,
                    merkle_root: [0u8; 32],
                    time: 0,
                    bits: 0x207fffff,
                    nonce: 0,
                },
                transactions: vec![],
                auxpow: None,
                poawx_receipts: Some(vec![r]),
            }
        };

        let cache = global_admission_cache();
        let admit = |cand: &RoleCandidate| {
            let a = CandidateAdmissionV1::new(net, height, parent_hash, cand.clone());
            cache.set_tip(height);
            let _ = cache.ingest_bytes(&a.serialize());
        };
        let st = base_chain(None);

        // exact admitted set == ext set => accept.
        cache.clear();
        cache.set_tip(height);
        for cand in [&c, &v, &s] {
            admit(cand);
        }
        assert!(
            st.validate_block_candidate_sets(&blk, height).is_ok(),
            "exact admitted set accepts"
        );
        // missing admitted candidate (support not admitted) => reject.
        cache.clear();
        for cand in [&c, &v] {
            admit(cand);
        }
        assert!(
            st.validate_block_candidate_sets(&blk, height).is_err(),
            "missing admitted candidate rejects"
        );
        // extra non-admitted candidate (cx admitted but not in ext) => reject.
        cache.clear();
        for cand in [&c, &v, &s, &cx] {
            admit(cand);
        }
        assert!(
            st.validate_block_candidate_sets(&blk, height).is_err(),
            "extra admitted candidate not in ext rejects"
        );
        // no admitted candidates => fail closed.
        cache.clear();
        assert!(
            st.validate_block_candidate_sets(&blk, height).is_err(),
            "no admitted candidates fails closed"
        );

        // admission gate OFF => old 21D behavior (cs present + best) accepts.
        std::env::remove_var("IRIUM_POAWX_CANDIDATE_ADMISSION_REQUIRED");
        cache.clear();
        assert!(
            !candidate_admission_enforced(height),
            "admission not enforced when REQUIRED unset"
        );
        assert!(
            st.validate_block_candidate_sets(&blk, height).is_ok(),
            "gate off: 21D candidate-set behavior unchanged"
        );

        // mainnet hard-off.
        std::env::set_var("IRIUM_NETWORK", "mainnet");
        assert!(!candidate_admission_enforced(height), "mainnet hard-off");

        cache.clear();
        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_CANDIDATE_SET_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_CANDIDATE_SET_REQUIRED");
        std::env::remove_var("IRIUM_POAWX_CANDIDATE_ADMISSION_ACTIVATION_HEIGHT");
    }

    #[test]
    fn phase21d_candidate_set_enforcement() {
        use crate::poawx::{
            ROLE_COMPUTE_CONTRIBUTOR, ROLE_SUPPORT_CONTRIBUTOR, ROLE_VERIFY_CONTRIBUTOR,
        };
        use crate::poawx_candidate::{candidate_set_enforced, CandidateSet, RoleCandidate};
        use crate::poawx_penalty::PenaltyStatus;
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_CANDIDATE_SET_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_CANDIDATE_SET_REQUIRED", "1");
        std::env::remove_var("IRIUM_POAWX_ANTI_DOMINATION_ACTIVATION_HEIGHT");
        assert!(candidate_set_enforced(1), "enforced on testnet");

        let net = crate::activation::network_id_byte();
        let parent = phase13b_parent_block();
        let parent_hash = parent.header.hash_for_height(0);
        let height = 1u64;
        let sk = signing_key(0x41);
        let base_ext = p20_ext(net, height, &parent_hash, 0, [0u8; 20]);
        let receipt = make_test_receipt(height, &sk, parent_hash, 1);
        let apk = [0x02u8; 33];

        let mk = |role: u8, solver: [u8; 20], tag: u8| {
            RoleCandidate::build(
                net,
                height,
                &parent_hash,
                role,
                solver,
                apk,
                [tag; 32],
                PenaltyStatus::Clean.id(),
                1000,
                [tag.wrapping_add(1); 32],
            )
        };
        let c1 = mk(ROLE_COMPUTE_CONTRIBUTOR, [0xC1u8; 20], 0x11);
        let cx = mk(ROLE_COMPUTE_CONTRIBUTOR, [0xCEu8; 20], 0x55);
        let v = mk(ROLE_VERIFY_CONTRIBUTOR, [0xC2u8; 20], 0x12);
        let s = mk(ROLE_SUPPORT_CONTRIBUTOR, [0xC3u8; 20], 0x13);
        let mut cs = CandidateSet::new(net, height, parent_hash);
        for c in [c1.clone(), cx.clone(), v, s] {
            cs.push(c);
        }
        cs.sort_canonical();
        let best_c = cs
            .best_for_role(ROLE_COMPUTE_CONTRIBUTOR)
            .unwrap()
            .solver_pkh;
        let non_best = if best_c == c1.solver_pkh {
            cx.solver_pkh
        } else {
            c1.solver_pkh
        };

        let blk = |compute_sel: [u8; 20], set: Option<CandidateSet>| -> Block {
            let mut ext = base_ext.clone();
            ext.role_reward.compute_contributor_pkh = compute_sel;
            ext.role_reward.verify_contributor_pkh = [0xC2u8; 20];
            ext.role_reward.support_contributor_pkh = [0xC3u8; 20];
            ext.candidate_set = set;
            let mut r = receipt.clone();
            r.phase20_ext = Some(ext);
            Block {
                header: BlockHeader {
                    version: 1,
                    prev_hash: parent_hash,
                    merkle_root: [0u8; 32],
                    time: 0,
                    bits: 0x207fffff,
                    nonce: 0,
                },
                transactions: vec![],
                auxpow: None,
                poawx_receipts: Some(vec![r]),
            }
        };

        let st = base_chain(None);
        // selected == best candidate => accept.
        assert!(
            st.validate_block_candidate_sets(&blk(best_c, Some(cs.clone())), height)
                .is_ok(),
            "selected best candidate accepts"
        );
        // selected != best => reject.
        assert!(
            st.validate_block_candidate_sets(&blk(non_best, Some(cs.clone())), height)
                .is_err(),
            "non-best selection rejects"
        );
        // missing candidate set => reject.
        assert!(
            st.validate_block_candidate_sets(&blk(best_c, None), height)
                .is_err(),
            "missing candidate set rejects"
        );
        // self-inconsistent candidate (mutated score) => reject.
        let mut bad = cs.clone();
        bad.candidates[0].effective_score ^= 1;
        assert!(
            st.validate_block_candidate_sets(&blk(best_c, Some(bad)), height)
                .is_err(),
            "mutated candidate rejects"
        );
        // wrong seed => reject.
        let mut wrong = cs.clone();
        wrong.seed = [0x99u8; 32];
        assert!(
            st.validate_block_candidate_sets(&blk(best_c, Some(wrong)), height)
                .is_err(),
            "wrong seed rejects"
        );

        // mainnet hard-off.
        std::env::set_var("IRIUM_NETWORK", "mainnet");
        assert!(!candidate_set_enforced(1), "mainnet hard-off");

        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_CANDIDATE_SET_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_CANDIDATE_SET_REQUIRED");
    }

    #[test]
    fn phase21c_dominance_connect_disconnect_reorg() {
        use crate::poawx_dominance::RoleRewardKind;
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_ANTI_DOMINATION_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_ANTI_DOMINATION_WINDOW", "1000");
        std::env::set_var("IRIUM_POAWX_ANTI_DOMINATION_LOOKBACK", "4");

        let net = crate::activation::network_id_byte();
        let parent = phase13b_parent_block();
        let parent_hash = parent.header.hash_for_height(0);

        // Build a Phase 20 block whose primary miner is keyed by `seed` and whose
        // role solvers come from `p20_ext` (compute/verify/support = C1/C2/C3).
        let mk_block = |seed: u8, fee_bps: u16, fee_pkh: [u8; 20], height: u64| -> Block {
            let sk = signing_key(seed);
            let ext = p20_ext(net, height, &parent_hash, fee_bps, fee_pkh);
            let mut receipt = make_test_receipt(height, &sk, parent_hash, 1);
            receipt.phase20_ext = Some(ext.clone());
            let total = block_reward(height);
            let payout = p20_coinbase(&receipt.worker_pkh, &ext, total);
            let coinbase = Transaction {
                version: 1,
                inputs: vec![TxInput {
                    prev_txid: [0u8; 32],
                    prev_index: 0xffff_ffff,
                    script_sig: vec![0x01, 0x00],
                    sequence: 0xffff_ffff,
                }],
                outputs: payout,
                locktime: 0,
            };
            Block {
                header: BlockHeader {
                    version: 1,
                    prev_hash: parent_hash,
                    merkle_root: [0u8; 32],
                    time: 0,
                    bits: 0x207fffff,
                    nonce: 0,
                },
                transactions: vec![coinbase],
                auxpow: None,
                poawx_receipts: Some(vec![receipt]),
            }
        };

        let amts = crate::poawx::multi_role_amounts(block_reward(1));
        let key_a = key_hash(&signing_key(0x41));
        let (c, v, s) = ([0xC1u8; 20], [0xC2u8; 20], [0xC3u8; 20]);

        // (C) reward-event derivation: PRIMARY=worker_pkh, roles=ext solvers,
        // amounts from the canonical split.
        let a1 = mk_block(0x41, 0, [0u8; 20], 1);
        let ev = ChainState::dominance_events_from_block(&a1, 1);
        assert_eq!(
            ev,
            vec![
                (key_a, RoleRewardKind::Primary, amts[0]),
                (c, RoleRewardKind::Compute, amts[1]),
                (v, RoleRewardKind::Verify, amts[2]),
                (s, RoleRewardKind::Support, amts[3]),
            ]
        );
        // third-party fee block => IDENTICAL role amounts (fee/delegate not
        // credited as worker rewards).
        let a1_fee = mk_block(0x41, 200, [0xFEu8; 20], 1);
        assert_eq!(
            ChainState::dominance_events_from_block(&a1_fee, 1),
            ev,
            "fee output must not change role-reward accounting"
        );

        // Connect chain A = {a1@1, a2@2} through the real gated hook.
        let mut cs = base_chain(None);
        let base_dig = cs.dominance.digest();
        cs.chain.push(a1.clone());
        cs.apply_block_dominance(1);
        let a2 = mk_block(0x42, 0, [0u8; 20], 2);
        cs.chain.push(a2.clone());
        cs.apply_block_dominance(2);
        let dig_a = cs.dominance.digest();
        assert_ne!(dig_a, base_dig, "applying chain A changed dominance state");

        // (D) disconnect tip a2: revert restores the a1-only state exactly.
        cs.revert_block_dominance(&a2, 2);
        cs.chain.pop();
        let dig_after_disc = cs.dominance.digest();
        assert_ne!(dig_after_disc, base_dig);
        assert_ne!(dig_after_disc, dig_a);

        // reorg A -> B: reconnect a competing tip b2 at height 2.
        let b2 = mk_block(0x43, 0, [0u8; 20], 2);
        cs.chain.push(b2.clone());
        cs.apply_block_dominance(2);
        let dig_b = cs.dominance.digest();
        assert_ne!(
            dig_b, dig_a,
            "reorg to a different tip yields different state"
        );

        // restart/rebuild: replaying {a1,b2} from scratch reproduces dig_b.
        let mut cs2 = base_chain(None);
        cs2.chain.push(a1.clone());
        cs2.apply_block_dominance(1);
        cs2.chain.push(b2.clone());
        cs2.apply_block_dominance(2);
        assert_eq!(
            cs2.dominance.digest(),
            dig_b,
            "reorg A->B equals independently rebuilt B-state"
        );

        // disconnect-restored state equals an independent rebuild of {a1}.
        let mut cs3 = base_chain(None);
        cs3.chain.push(a1.clone());
        cs3.apply_block_dominance(1);
        assert_eq!(
            cs3.dominance.digest(),
            dig_after_disc,
            "disconnect restored the exact pre-connect state"
        );

        // (F) gate OFF => apply is a no-op (old behavior unchanged).
        std::env::remove_var("IRIUM_POAWX_ANTI_DOMINATION_ACTIVATION_HEIGHT");
        let mut cs4 = base_chain(None);
        let g = cs4.dominance.digest();
        cs4.chain.push(a1.clone());
        cs4.apply_block_dominance(1);
        assert_eq!(cs4.dominance.digest(), g, "gate off: apply is a no-op");

        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_ANTI_DOMINATION_WINDOW");
        std::env::remove_var("IRIUM_POAWX_ANTI_DOMINATION_LOOKBACK");
    }

    #[test]
    fn phase21b_ticket_penalty_enforcement() {
        use crate::poawx::{
            ROLE_COMPUTE_CONTRIBUTOR, ROLE_SUPPORT_CONTRIBUTOR, ROLE_VERIFY_CONTRIBUTOR,
        };
        use crate::poawx_penalty::PenaltyStatus;
        use crate::poawx_ticket::TicketProof;
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_MODE", "active");
        std::env::set_var("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS", "1");
        std::env::set_var("IRIUM_POAWX_MULTI_ROLE_REWARD_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_FAIRNESS_MATRIX_ACTIVATION_HEIGHT", "1");
        std::env::remove_var("IRIUM_POAWX_THIRD_PARTY_FEE_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_THIRD_PARTY_POOL_MODE");
        std::env::remove_var("IRIUM_POAWX_HIDDEN_PRECOMMIT_ACTIVATION_HEIGHT");

        let net = crate::activation::network_id_byte();
        let sk = test_signing_key();
        let parent = phase13b_parent_block();
        let parent_hash = parent.header.hash_for_height(0);
        let height = 1u64;
        let total = block_reward(height);
        let base_receipt = make_test_receipt(height, &sk, parent_hash, 1);
        let primary = base_receipt.worker_pkh;

        let build = |ext: &crate::poawx::Phase20ReceiptExt| -> Block {
            let mut receipt = base_receipt.clone();
            receipt.phase20_ext = Some(ext.clone());
            let root = crate::poawx::irx1_root_from_block_receipts_gated(
                std::slice::from_ref(&receipt),
                true,
            );
            let mut irx1_script = vec![0x6a, 0x24u8];
            irx1_script.extend_from_slice(b"irx1");
            irx1_script.extend_from_slice(&root);
            let mut payout = p20_coinbase(&primary, ext, total);
            payout[0] = TxOutput {
                value: 0,
                script_pubkey: irx1_script,
            };
            let coinbase = Transaction {
                version: 1,
                inputs: vec![TxInput {
                    prev_txid: [0u8; 32],
                    prev_index: 0xffff_ffff,
                    script_sig: vec![0x01, 0x00],
                    sequence: 0xffff_ffff,
                }],
                outputs: payout,
                locktime: 0,
            };
            Block {
                header: BlockHeader {
                    version: 1,
                    prev_hash: parent_hash,
                    merkle_root: [0u8; 32],
                    time: 0,
                    bits: 0x207fffff,
                    nonce: 0,
                },
                transactions: vec![coinbase],
                auxpow: None,
                poawx_receipts: Some(vec![receipt]),
            }
        };
        // ext role solvers are c/v/s = 0xC1/0xC2/0xC3 (see p20_ext).
        let tickets = |expiry: u64, verify_status: u8| {
            [
                TicketProof::new(
                    net,
                    height,
                    ROLE_COMPUTE_CONTRIBUTOR,
                    [0xC1u8; 20],
                    1,
                    expiry,
                    [0x02u8; 33],
                    [0x11u8; 32],
                    PenaltyStatus::Clean.id(),
                ),
                TicketProof::new(
                    net,
                    height,
                    ROLE_VERIFY_CONTRIBUTOR,
                    [0xC2u8; 20],
                    1,
                    expiry,
                    [0x02u8; 33],
                    [0x12u8; 32],
                    verify_status,
                ),
                TicketProof::new(
                    net,
                    height,
                    ROLE_SUPPORT_CONTRIBUTOR,
                    [0xC3u8; 20],
                    1,
                    expiry,
                    [0x02u8; 33],
                    [0x13u8; 32],
                    PenaltyStatus::Clean.id(),
                ),
            ]
        };

        // (20) gate OFF: ext WITHOUT tickets accepts (old behavior unchanged).
        std::env::remove_var("IRIUM_POAWX_TICKETS_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_TICKETS_REQUIRED");
        let ext_plain = p20_ext(net, height, &parent_hash, 0, [0u8; 20]);
        assert!(
            validate_poawx_block_receipts(&build(&ext_plain), height, Some(&parent)).is_ok(),
            "gate off: ticketless ext must accept"
        );

        // gate ON.
        std::env::set_var("IRIUM_POAWX_TICKETS_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_TICKETS_REQUIRED", "1");
        // (2) gate on + missing tickets -> reject.
        assert!(
            validate_poawx_block_receipts(&build(&ext_plain), height, Some(&parent)).is_err(),
            "gate on: missing ticket proofs must reject"
        );
        // (3) gate on + valid tickets -> accept.
        let mut ext_ok = ext_plain.clone();
        ext_ok.role_ticket_proofs = Some(tickets(100, PenaltyStatus::Clean.id()));
        assert!(
            validate_poawx_block_receipts(&build(&ext_ok), height, Some(&parent)).is_ok(),
            "gate on: valid tickets must accept"
        );
        // (5) gate on + expired ticket -> reject.
        let mut ext_exp = ext_plain.clone();
        ext_exp.role_ticket_proofs = Some(tickets(1, PenaltyStatus::Clean.id())); // expiry==height
        assert!(
            validate_poawx_block_receipts(&build(&ext_exp), height, Some(&parent)).is_err(),
            "gate on: expired ticket must reject"
        );
        // (12) penalty enforced + suspended VERIFY (high-trust) -> reject.
        std::env::set_var("IRIUM_POAWX_PENALTY_STATE_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_PENALTY_STATE_REQUIRED", "1");
        let mut ext_susp = ext_plain.clone();
        ext_susp.role_ticket_proofs = Some(tickets(100, PenaltyStatus::SuspendedForEpoch.id()));
        assert!(
            validate_poawx_block_receipts(&build(&ext_susp), height, Some(&parent)).is_err(),
            "penalty on: suspended high-trust role must reject"
        );
        // (13) penalty NOT enforced: same suspended ticket accepts.
        std::env::remove_var("IRIUM_POAWX_PENALTY_STATE_REQUIRED");
        assert!(
            validate_poawx_block_receipts(&build(&ext_susp), height, Some(&parent)).is_ok(),
            "penalty off: suspended ticket accepts (penalty not enforced)"
        );

        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_MODE");
        std::env::remove_var("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS");
        std::env::remove_var("IRIUM_POAWX_MULTI_ROLE_REWARD_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_FAIRNESS_MATRIX_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_TICKETS_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_TICKETS_REQUIRED");
        std::env::remove_var("IRIUM_POAWX_PENALTY_STATE_ACTIVATION_HEIGHT");
    }

    #[test]
    fn phase20_connect_block_mode1_third_party_fee_and_binding() {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        set_mode1_env();
        std::env::set_var("IRIUM_POAWX_MULTI_ROLE_REWARD_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_FAIRNESS_MATRIX_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_THIRD_PARTY_FEE_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_THIRD_PARTY_POOL_MODE", "1");

        let net = crate::activation::network_id_byte();
        let miner = sk_from(3);
        let pool = sk_from(5);
        let parent = phase13b_parent_block();
        let parent_hash = parent.header.hash_for_height(0);
        let height = 1u64;
        let total = block_reward(height);
        let fee_pkh = [0xFEu8; 20];
        let fee_bps = 150u16;

        // Base mode-1 receipt, then upgrade its delegation to carry a third-party
        // fee (re-signed by the miner) and attach a matching production extension.
        let base = make_mode1_receipt(height, &miner, &pool, parent_hash, 1, 1, 1000, 0);
        let primary = base.worker_pkh;

        // Build a (receipt, ext) pair with the given ext fee, and a canonical fee
        // coinbase whose irx1 root is the gated-on root over the receipt.
        let build = |ext_fee_bps: u16| -> (Block, crate::poawx::PoawxBlockReceipt) {
            let mut receipt = base.clone();
            // re-sign the delegation with the third-party fee terms.
            {
                let d = receipt.delegation.as_mut().unwrap();
                d.fee_bps = fee_bps;
                d.fee_pkh = fee_pkh;
                let sig: k256::ecdsa::Signature = miner.sign_prehash(&d.message_hash()).unwrap();
                d.delegation_sig.copy_from_slice(&sig.to_bytes());
            }
            let ext = p20_ext(net, height, &parent_hash, ext_fee_bps, fee_pkh);
            receipt.phase20_ext = Some(ext.clone());
            let root = crate::poawx::irx1_root_from_block_receipts_gated(
                std::slice::from_ref(&receipt),
                true,
            );
            let mut irx1 = vec![0x6a, 0x24u8];
            irx1.extend_from_slice(b"irx1");
            irx1.extend_from_slice(&root);
            // p20_coinbase appends the fee output when ext.fee_bps > 0.
            let mut payout = p20_coinbase(&primary, &ext, total);
            payout[0] = TxOutput {
                value: 0,
                script_pubkey: irx1,
            };
            let coinbase = Transaction {
                version: 1,
                inputs: vec![TxInput {
                    prev_txid: [0u8; 32],
                    prev_index: 0xffff_ffff,
                    script_sig: vec![0x01, 0x00],
                    sequence: 0xffff_ffff,
                }],
                outputs: payout,
                locktime: 0,
            };
            let block = Block {
                header: BlockHeader {
                    version: 1,
                    prev_hash: parent_hash,
                    merkle_root: [0u8; 32],
                    time: 0,
                    bits: 0x207fffff,
                    nonce: 0,
                },
                transactions: vec![coinbase],
                auxpow: None,
                poawx_receipts: Some(vec![receipt.clone()]),
            };
            (block, receipt)
        };

        // (1) ext fee == delegation fee (150): accepted (mode-1 fee relaxation +
        // fee-aware multi-role coinbase + ext↔delegation binding all hold).
        let (ok_block, _r) = build(fee_bps);
        let res = validate_poawx_block_receipts(&ok_block, height, Some(&parent));
        assert!(
            res.is_ok(),
            "mode-1 third-party fee block must be accepted: {res:?}"
        );

        // (2) ext fee (100) != signed delegation fee (150): binding rejects.
        let (bad_block, _r) = build(100);
        let res = validate_poawx_block_receipts(&bad_block, height, Some(&parent));
        assert!(res.is_err(), "ext/delegation fee mismatch must reject");
        assert!(
            res.unwrap_err().contains("extension fee terms"),
            "expected binding error"
        );

        // (3) same valid block rejects once the third-party gate is off (the
        // delegation fee>0 is no longer permitted).
        std::env::remove_var("IRIUM_POAWX_THIRD_PARTY_POOL_MODE");
        let res = validate_poawx_block_receipts(&ok_block, height, Some(&parent));
        assert!(res.is_err(), "third-party fee rejected when mode off");

        std::env::remove_var("IRIUM_POAWX_MULTI_ROLE_REWARD_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_FAIRNESS_MATRIX_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_THIRD_PARTY_FEE_ACTIVATION_HEIGHT");
        clear_mode1_env();
    }

    #[test]
    fn phase20_hidden_precommit_enforcement() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_MODE", "active");
        std::env::set_var("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS", "1");
        std::env::set_var("IRIUM_POAWX_MULTI_ROLE_REWARD_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_FAIRNESS_MATRIX_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_HIDDEN_PRECOMMIT_ACTIVATION_HEIGHT", "1");

        let net = crate::activation::network_id_byte();
        let sk = test_signing_key();
        let parent = phase13b_parent_block();
        let parent_hash = parent.header.hash_for_height(0);
        let roles = [
            crate::poawx::ROLE_COMPUTE_CONTRIBUTOR,
            crate::poawx::ROLE_VERIFY_CONTRIBUTOR,
            crate::poawx::ROLE_SUPPORT_CONTRIBUTOR,
        ];
        let solvers = [[0xC1u8; 20], [0xC2u8; 20], [0xC3u8; 20]];
        // Deterministic per-(height,role) secret/nonce — computable at precommit time
        // (block H-1) WITHOUT knowing hash(H-1), so the precommit and reveal agree.
        let sn = |h: u64, role: u8| -> ([u8; 32], [u8; 32]) {
            let mk = |tag: &[u8]| -> [u8; 32] {
                let mut x = Sha256::new();
                x.update(b"hp_test");
                x.update(tag);
                x.update(h.to_le_bytes());
                x.update([role]);
                x.finalize().into()
            };
            (mk(b"s"), mk(b"n"))
        };
        let mk_claim = |h: u64, prev: &[u8; 32], i: usize| -> crate::poawx::PoawxRoleClaim {
            let role = roles[i];
            let solver = solvers[i];
            let lane = crate::poawx::assign_lane(net, h, prev, role, 0);
            let (secret, nonce) = sn(h, role);
            let cd = crate::poawx::role_claim_digest(
                net,
                h,
                prev,
                role,
                lane.id(),
                &solver,
                &nonce,
                &secret,
            );
            crate::poawx::PoawxRoleClaim {
                role_id: role,
                lane_id: lane.id(),
                solver_pkh: solver,
                nonce,
                secret,
                claim_digest: cd,
                commitment_hash: Some(crate::poawx::role_precommit_commitment(&secret, &nonce)),
            }
        };
        // precommit root committing height h's leaves (no prev/lane in the leaf).
        let root_for = |h: u64| -> [u8; 32] {
            let leaves: Vec<[u8; 32]> = (0..3)
                .map(|i| {
                    let (s, n) = sn(h, roles[i]);
                    let c = crate::poawx::role_precommit_commitment(&s, &n);
                    crate::poawx::role_precommit_leaf(net, h, roles[i], &solvers[i], &c)
                })
                .collect();
            crate::poawx::role_precommit_root(&leaves)
        };
        let mk_ext = |h: u64,
                      prev: &[u8; 32],
                      next_root: Option<[u8; 32]>|
         -> crate::poawx::Phase20ReceiptExt {
            crate::poawx::Phase20ReceiptExt {
                role_reward: crate::poawx::RoleReward {
                    compute_contributor_pkh: solvers[0],
                    verify_contributor_pkh: solvers[1],
                    support_contributor_pkh: solvers[2],
                },
                compute_claim: mk_claim(h, prev, 0),
                verify_claim: mk_claim(h, prev, 1),
                support_claim: mk_claim(h, prev, 2),
                fee_bps: 0,
                fee_pkh: [0u8; 20],
                precommit_root: next_root,
                role_ticket_proofs: None,
                role_dominance_weights: None,
                candidate_set: None,
                role_puzzle_proofs: None,
                finality_proof: None,
                committed_admission: None,
                role_assignment_v2: None,
                double_sign_evidence: None,
                ticket_registrations: None,
                dominance_commitment: None,
                adaptive_mode_commitment: None,
            }
        };
        let build = |h: u64, prev: &[u8; 32], ext: &crate::poawx::Phase20ReceiptExt| -> Block {
            let mut receipt = make_test_receipt(h, &sk, *prev, 1);
            receipt.phase20_ext = Some(ext.clone());
            let primary = receipt.worker_pkh;
            let root = crate::poawx::irx1_root_from_block_receipts_gated(
                std::slice::from_ref(&receipt),
                true,
            );
            let mut irx1 = vec![0x6a, 0x24u8];
            irx1.extend_from_slice(b"irx1");
            irx1.extend_from_slice(&root);
            let mut payout = p20_coinbase(&primary, ext, block_reward(h));
            payout[0] = TxOutput {
                value: 0,
                script_pubkey: irx1,
            };
            let cb = Transaction {
                version: 1,
                inputs: vec![TxInput {
                    prev_txid: [0u8; 32],
                    prev_index: 0xffff_ffff,
                    script_sig: vec![0x01, 0x00],
                    sequence: 0xffff_ffff,
                }],
                outputs: payout,
                locktime: 0,
            };
            Block {
                header: BlockHeader {
                    version: 1,
                    prev_hash: *prev,
                    merkle_root: [0u8; 32],
                    time: 0,
                    bits: 0x207fffff,
                    nonce: 0,
                },
                transactions: vec![cb],
                auxpow: None,
                poawx_receipts: Some(vec![receipt]),
            }
        };

        // Block 1 = grace (activation height): parent predates activation, so the
        // parent-root match is skipped, but the block must carry a precommit_root
        // (for block 2) and its claim commitments must be valid.
        let block1 = build(1, &parent_hash, &mk_ext(1, &parent_hash, Some(root_for(2))));
        assert!(
            validate_poawx_block_receipts(&block1, 1, Some(&parent)).is_ok(),
            "grace block: {:?}",
            validate_poawx_block_receipts(&block1, 1, Some(&parent))
        );
        let h1 = block1.header.hash_for_height(1);

        // Block 2 (non-grace): reveals leaves matching block1's committed root.
        let block2 = build(2, &h1, &mk_ext(2, &h1, Some(root_for(3))));
        let r2 = validate_poawx_block_receipts(&block2, 2, Some(&block1));
        assert!(r2.is_ok(), "valid parent-root reveal: {:?}", r2);

        // (12) parent has no precommit_root => reject.
        let block1_nr = build(1, &parent_hash, &mk_ext(1, &parent_hash, None));
        let h1nr = block1_nr.header.hash_for_height(1);
        let block2_nr = build(2, &h1nr, &mk_ext(2, &h1nr, Some(root_for(3))));
        assert!(
            validate_poawx_block_receipts(&block2_nr, 2, Some(&block1_nr)).is_err(),
            "missing parent root rejects"
        );

        // (13) parent commits the wrong root => reject.
        let block1_w = build(
            1,
            &parent_hash,
            &mk_ext(1, &parent_hash, Some(root_for(99))),
        );
        let h1w = block1_w.header.hash_for_height(1);
        let block2_w = build(2, &h1w, &mk_ext(2, &h1w, Some(root_for(3))));
        assert!(
            validate_poawx_block_receipts(&block2_w, 2, Some(&block1_w)).is_err(),
            "wrong parent root rejects"
        );

        // (17) reveal with a commitment that doesn't match secret/nonce => reject
        // (fairness still passes; precommit commitment check fails).
        let mut ext2_mut = mk_ext(2, &h1, Some(root_for(3)));
        ext2_mut.compute_claim.commitment_hash = Some([0xEEu8; 32]);
        let block2_mut = build(2, &h1, &ext2_mut);
        assert!(
            validate_poawx_block_receipts(&block2_mut, 2, Some(&block1)).is_err(),
            "mutated commitment rejects"
        );

        // block missing its OWN precommit_root after activation => reject.
        let block2_noown = build(2, &h1, &mk_ext(2, &h1, None));
        assert!(
            validate_poawx_block_receipts(&block2_noown, 2, Some(&block1)).is_err(),
            "missing own precommit_root rejects"
        );

        // (18) mainnet hard-off.
        std::env::set_var("IRIUM_NETWORK", "mainnet");
        assert!(!hidden_precommit_active(2), "mainnet hard-off");
        std::env::set_var("IRIUM_NETWORK", "testnet");

        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_MODE");
        std::env::remove_var("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS");
        std::env::remove_var("IRIUM_POAWX_MULTI_ROLE_REWARD_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_FAIRNESS_MATRIX_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_HIDDEN_PRECOMMIT_ACTIVATION_HEIGHT");
    }

    #[test]
    fn phase13b_irx1_root_mismatch_rejected() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_POAWX_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_MODE", "active");
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS", "1");
        let sk = test_signing_key();
        let parent = phase13b_parent_block();
        let parent_hash = parent.header.hash_for_height(0);
        let height = 1u64;
        let receipt = make_test_receipt(height, &sk, parent_hash, 1);
        let mut block = make_valid_poawx_block(parent_hash, height, receipt, true);
        // Corrupt the irx1 root in the coinbase OP_RETURN output.
        let coinbase = &mut block.transactions[0];
        if let Some(irx1_out) = coinbase
            .outputs
            .iter_mut()
            .find(|o| o.script_pubkey.len() == 38)
        {
            irx1_out.script_pubkey[10] ^= 0xff;
        }
        let result = validate_poawx_block_receipts(&block, height, Some(&parent));
        assert!(result.is_err(), "irx1 root mismatch must be rejected");
        assert!(
            result.unwrap_err().contains("mismatch"),
            "error must mention mismatch"
        );
        std::env::remove_var("IRIUM_POAWX_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_MODE");
        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS");
    }

    #[test]
    fn phase13b_wrong_commitment_nonce_rejected() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_POAWX_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_MODE", "active");
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS", "1");
        let sk = test_signing_key();
        let parent = phase13b_parent_block();
        let parent_hash = parent.header.hash_for_height(0);
        let height = 1u64;
        let mut receipt = make_test_receipt(height, &sk, parent_hash, 1);
        // Corrupt nonce byte in receipt; rebuild irx1 root to match.
        receipt.commitment_nonce[0] ^= 0xff;
        let irx1_root = crate::poawx::irx1_root_from_block_receipts(&[receipt.clone()]);
        let mut irx1_script = vec![0x6a, 0x24u8];
        irx1_script.extend_from_slice(b"irx1");
        irx1_script.extend_from_slice(&irx1_root);
        let base_reward = block_reward(height);
        let worker_due = base_reward * 100 / 1000;
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: [0u8; 32],
                prev_index: 0xffff_ffff,
                script_sig: vec![0x01, 0x00],
                sequence: 0xffff_ffff,
            }],
            outputs: vec![
                TxOutput {
                    value: base_reward - worker_due,
                    script_pubkey: vec![0x51],
                },
                TxOutput {
                    value: worker_due,
                    script_pubkey: p2pkh_script(&receipt.worker_pkh),
                },
                TxOutput {
                    value: 0,
                    script_pubkey: irx1_script,
                },
            ],
            locktime: 0,
        };
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_hash: parent_hash,
                merkle_root: [0u8; 32],
                time: 0,
                bits: 0x207fffff,
                nonce: 0,
            },
            transactions: vec![coinbase],
            auxpow: None,
            poawx_receipts: Some(vec![receipt]),
        };
        let result = validate_poawx_block_receipts(&block, height, Some(&parent));
        assert!(result.is_err(), "wrong nonce must be rejected");
        assert!(
            result.unwrap_err().contains("nonce"),
            "error must mention nonce"
        );
        std::env::remove_var("IRIUM_POAWX_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_MODE");
        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS");
    }

    #[test]
    fn phase13b_bad_worker_sig_rejected() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_POAWX_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_MODE", "active");
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS", "1");
        let sk = test_signing_key();
        let parent = phase13b_parent_block();
        let parent_hash = parent.header.hash_for_height(0);
        let height = 1u64;
        let mut receipt = make_test_receipt(height, &sk, parent_hash, 1);
        // Flip two bytes of the signature — almost certain to produce invalid sig.
        receipt.worker_sig[0] ^= 0xff;
        receipt.worker_sig[32] ^= 0xff;
        // Rebuild block with matching irx1 root.
        let block = make_valid_poawx_block(parent_hash, height, receipt, true);
        let result = validate_poawx_block_receipts(&block, height, Some(&parent));
        assert!(result.is_err(), "corrupted sig must be rejected");
        std::env::remove_var("IRIUM_POAWX_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_MODE");
        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS");
    }

    #[test]
    fn phase13b_spoofed_pkh_rejected() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_POAWX_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_MODE", "active");
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS", "1");
        let sk = test_signing_key();
        let parent = phase13b_parent_block();
        let parent_hash = parent.header.hash_for_height(0);
        let height = 1u64;
        let mut receipt = make_test_receipt(height, &sk, parent_hash, 1);
        // Replace worker_pkh with a value that doesn't match worker_pubkey.
        receipt.worker_pkh[0] ^= 0xff;
        // Rebuild block with matching irx1 root (root uses binary fields).
        let block = make_valid_poawx_block(parent_hash, height, receipt, true);
        let result = validate_poawx_block_receipts(&block, height, Some(&parent));
        assert!(result.is_err(), "spoofed pkh must be rejected");
        assert!(
            result.unwrap_err().contains("mismatch"),
            "error must mention mismatch"
        );
        std::env::remove_var("IRIUM_POAWX_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_MODE");
        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS");
    }

    #[test]
    fn phase13b_insufficient_puzzle_difficulty_rejected() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_POAWX_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_MODE", "active");
        std::env::set_var("IRIUM_NETWORK", "testnet");
        let sk = test_signing_key();
        let parent = phase13b_parent_block();
        let parent_hash = parent.header.hash_for_height(0);
        let height = 1u64;
        // Build receipt satisfying only 1 leading zero bit.
        std::env::set_var("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS", "1");
        let receipt = make_test_receipt(height, &sk, parent_hash, 1);
        // Require 20 bits — near-zero chance the 1-bit solution also satisfies 20 bits.
        std::env::set_var("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS", "20");
        let block = make_valid_poawx_block(parent_hash, height, receipt, true);
        let result = validate_poawx_block_receipts(&block, height, Some(&parent));
        assert!(
            result.is_err(),
            "low-difficulty solution should be rejected at higher difficulty"
        );
        std::env::remove_var("IRIUM_POAWX_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_MODE");
        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS");
    }

    #[test]
    fn phase13b_missing_worker_payout_rejected() {
        let _g = chain_poawx_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_POAWX_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_MODE", "active");
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS", "1");
        let sk = test_signing_key();
        let parent = phase13b_parent_block();
        let parent_hash = parent.header.hash_for_height(0);
        let height = 1u64;
        let receipt = make_test_receipt(height, &sk, parent_hash, 1);
        // payout_ok=false → worker receives 0 (underpaid).
        let block = make_valid_poawx_block(parent_hash, height, receipt, false);
        let result = validate_poawx_block_receipts(&block, height, Some(&parent));
        assert!(result.is_err(), "missing worker payout must be rejected");
        assert!(
            result.unwrap_err().contains("underpaid"),
            "error must mention underpaid"
        );
        std::env::remove_var("IRIUM_POAWX_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_MODE");
        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS");
    }

    #[test]
    fn phase13b_legacy_block_wire_still_parses() {
        // Verify that a block with no receipt section (pre-Phase-13-A wire)
        // still deserializes correctly after Phase 13-B changes.
        let block = make_poawx_test_block(vec![0x51]);
        let bytes = block.serialize_for_height(1);
        let (decoded, used) =
            Block::deserialize_for_height(&bytes, 1).expect("legacy block must still parse");
        assert_eq!(used, bytes.len());
        assert!(decoded.poawx_receipts.is_none());
    }
}
