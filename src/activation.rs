//! ⚠ MAINNET STATUS (reconciled 2026-07-25; authoritative check: `mainnet_gate_truth`): the "mainnet hard-off"
//! wording on the gate helpers below is STALE for any gate whose `MAINNET_*_ACTIVATION_HEIGHT` is `Some` — those
//! are ACTIVE on mainnet at/after that compiled height via `poawx_effective_activation` (which ignores the env
//! on `network_id==0`). Genuinely hard-off ONLY for `None` gates (e.g. mandatory-inclusion, the pool-ticket gate).
use std::env;

/// Mainnet HTLCv1 activation height source-of-truth.
///
/// Set this to `Some(<height>)` only after activation governance is complete.
/// `None` keeps HTLCv1 disabled on mainnet.
pub const MAINNET_HTLCV1_ACTIVATION_HEIGHT: Option<u64> = Some(18677);

/// Mainnet LWMA difficulty activation height source-of-truth.
///
/// Mainnet LWMA has been active since block height 16,462.
/// Historical consensus from that height onward must remain unchanged.
pub const MAINNET_LWMA_ACTIVATION_HEIGHT: Option<u64> = Some(16_462);

/// Mainnet LWMA v2 activation height source-of-truth.
///
/// INACTIVE by default. Set to Some(<height>) only after governance review
/// and explicit approval. When active, switches difficulty to LWMA v2
/// parameters (N=30, clamp=10T) for faster post-collapse recovery.
/// Historical consensus before this height is unaffected.
pub const MAINNET_LWMA_V2_ACTIVATION_HEIGHT: Option<u64> = Some(19_740);

/// Mainnet block-time V2 activation height (T 600s → 120s + halving rescale).
///
/// `None` keeps the chain on the V1 protocol target T=600s and the V1
/// halving interval 210_000. When set to `Some(<height>)`, two coupled
/// changes take effect at that height:
///   1. The LWMA expected-time / solvetime clamp drops to T=120s
///      (`BLOCK_TARGET_INTERVAL_V2`).
///   2. The halving interval rescales from 210_000 to 1_050_000
///      (`HALVING_INTERVAL_V2 = 5 × V1`) to preserve a roughly four-year
///      halving calendar at the new T.
///
/// The two-leg coupling is intentional: changing T without rescaling
/// HALVING_INTERVAL would compress the emission curve 5×; rescaling
/// without changing T is meaningless. Both flip atomically at this
/// height.
///
/// Activated on mainnet at height 24_250. Pre-fork chain history is
/// bit-for-bit unchanged: the `block_target_interval(height)` and
/// `halving_count(height)` accessors in `constants.rs` return V1 values
/// for every `height < 24_250`, and the cumulative `halving_count`
/// formula is continuous across the fork boundary
/// (`halving_count(24_250) == halving_count(24_251)`).
pub const MAINNET_BLOCK_TIME_V2_ACTIVATION_HEIGHT: Option<u64> = Some(24_250);

/// Mainnet AuxPoW merged-mining activation height.
///
/// At this height the chain begins accepting blocks that carry a Namecoin
/// AuxPoW extension (version bit 1<<8). Standard single-hash PoW blocks
/// remain valid after activation.
///
/// Height 26500 is approximately 6 weeks after height 20299 (when this
/// constant was set), giving all known node operators time to upgrade
/// before the first AuxPoW block can appear.
pub const MAINNET_AUXPOW_ACTIVATION_HEIGHT: Option<u64> = Some(24_800);

/// Mainnet Bitcoin SPV header relay activation height (Phase 1).
///
/// `None` keeps the BTC SPV header relay disabled on mainnet. When this is
/// set to `Some(<height>)`, iriumd blocks at or after that height may carry
/// a `BtcHeaderBatch` output (script tag `0xc4`) and the validator will
/// apply such batches into `ChainState.btc_headers`.
///
/// Phase 1 ships disabled. Activation requires a dedicated commit and
/// release per the workflow in docs/htlcv1_activation_commit_workflow.md.
pub const MAINNET_BTC_SPV_RELAY_ACTIVATION_HEIGHT: Option<u64> = Some(23_850);

/// Mainnet anchor for the BTC SPV header relay.
///
/// All four values are zero until the relay is activated on mainnet. They
/// must be set together (a known finalized BTC mainnet block) at the same
/// time as `MAINNET_BTC_SPV_RELAY_ACTIVATION_HEIGHT`.
#[allow(dead_code)] // anchor placeholder; populated by the Phase 1 activation commit
pub const MAINNET_BTC_ANCHOR_HEIGHT: u64 = 880_000;
#[allow(dead_code)] // anchor placeholder; populated by the Phase 1 activation commit
pub const MAINNET_BTC_ANCHOR_HASH: [u8; 32] = [
    // Bitcoin mainnet block 880000 hash in NATURAL byte order
    // (display hex 000000000000000000010b17283c3c400507969a9c2afd1dcf2082ec5cca2880
    // reversed - chain-linkage checks compare to header.prev_hash which is also
    // stored in natural order).
    0x80, 0x28, 0xca, 0x5c, 0xec, 0x82, 0x20, 0xcf, 0x1d, 0xfd, 0x2a, 0x9c, 0x9a, 0x96, 0x07, 0x05,
    0x40, 0x3c, 0x3c, 0x28, 0x17, 0x0b, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
#[allow(dead_code)] // anchor placeholder; populated by the Phase 1 activation commit
pub const MAINNET_BTC_ANCHOR_BITS: u32 = 0x17028c61;
#[allow(dead_code)] // anchor placeholder; populated by the Phase 1 activation commit
pub const MAINNET_BTC_ANCHOR_TIME: u32 = 1_737_337_343;

/// Mainnet Litecoin SPV header relay activation height (Phase B).
///
/// `None` keeps the LTC SPV header relay disabled on mainnet. When set to
/// `Some(<height>)`, iriumd blocks at or after that height may carry an
/// `LtcHeaderBatch` output (script tag `0xc6`) and the validator will
/// apply such batches into `ChainState.ltc_headers`.
///
/// Phase B ships disabled. Activation requires a dedicated commit per the
/// same workflow as Phase 1.
pub const MAINNET_LTC_SPV_RELAY_ACTIVATION_HEIGHT: Option<u64> = Some(24_800);

/// Mainnet anchor for the LTC SPV header relay.
///
/// Litecoin mainnet block 3_106_656 (a 2016-block retarget boundary
/// chosen well-confirmed at pick time). Hash stored here in DISPLAY order
/// for readability; reversed to natural byte order in
/// `LtcAnchor::mainnet()` so it lines up with `prev_hash` chain-linkage
/// fields. These constants take effect only after governance flips
/// `MAINNET_LTC_SPV_RELAY_ACTIVATION_HEIGHT` to `Some(<height>)`.
#[allow(dead_code)] // wired through ChainParams once Phase B callers come online
pub const MAINNET_LTC_ANCHOR_HEIGHT: u64 = 3_106_656;
#[allow(dead_code)]
pub const MAINNET_LTC_ANCHOR_HASH_DISPLAY: [u8; 32] = [
    0x8a, 0x89, 0xd2, 0xe5, 0x23, 0x29, 0xaa, 0xbe, 0x63, 0xfa, 0xbe, 0xb9, 0xd4, 0xcf, 0x73, 0x4d,
    0x8a, 0x44, 0xde, 0x15, 0x85, 0x98, 0xaf, 0xb6, 0x56, 0x0f, 0x20, 0xf8, 0xc9, 0x47, 0xbe, 0x64,
];
#[allow(dead_code)]
pub const MAINNET_LTC_ANCHOR_BITS: u32 = 0x1929_b619;
#[allow(dead_code)]
pub const MAINNET_LTC_ANCHOR_TIME: u32 = 1_778_676_649;

/// Mainnet HtlcLtcSwapV1 activation height (Phase C).
///
/// `None` keeps the LTC-proof claim path disabled on mainnet. When set
/// to `Some(<height>)`, blocks at or after that height may carry
/// HtlcLtcSwapV1 outputs (script tag `0xc7`) and the validator will
/// accept LTC-proof claim witnesses against them.
///
/// Phase C ships disabled. Activation should not precede
/// `MAINNET_LTC_SPV_RELAY_ACTIVATION_HEIGHT`, otherwise no proof would
/// resolve.
pub const MAINNET_HTLC_LTC_SWAP_V1_ACTIVATION_HEIGHT: Option<u64> = Some(24_800);

/// Mainnet LtcSwapOrder activation height (Phase D).
///
/// `None` keeps the LTC on-chain order book disabled on mainnet. When
/// set to `Some(<height>)`, blocks at or after that height may carry
/// LtcSwapOrder outputs (script tag `0xc8`) and the validator will
/// accept Fill / Cancel / ExpireSweep witnesses against them.
///
/// Phase D ships disabled. Sell-direction fills emit `HtlcLtcSwapV1`
/// outputs (Phase C), so this should not be activated before
/// `MAINNET_HTLC_LTC_SWAP_V1_ACTIVATION_HEIGHT` — the fill covenant
/// would otherwise reject every spend.
pub const MAINNET_LTC_SWAP_ORDER_V1_ACTIVATION_HEIGHT: Option<u64> = Some(24_800);

/// Mainnet coinbase header-batch activation (v1.9.62 issue #60).
///
/// At this height and above, blocks may carry BTC/LTC header batches
/// directly in the coinbase tx as zero-value outputs. Before this height,
/// coinbase batch outputs are rejected (pre-v1.9.62 behavior). The same
/// one-per-chain-per-block cap as the regular-tx path is enforced; a block
/// cannot have both a coinbase batch and a regular-tx batch for the same
/// chain. Eliminates the wallet-funded carrier-tx cost entirely.
pub const MAINNET_COINBASE_HEADER_BATCH_ACTIVATION_HEIGHT: Option<u64> = Some(24_800);

/// Mainnet HtlcBtcSwapV1 activation height (Phase 2).
///
/// `None` keeps the BTC-proof claim path disabled on mainnet. When set to
/// `Some(<height>)`, blocks at or after that height may carry HtlcBtcSwapV1
/// outputs (script tag `0xc3`) and the validator will accept BTC-proof
/// claim witnesses against them.
///
/// Phase 2 ships disabled. Activation requires:
/// 1. The BTC SPV relay being active (so headers and merkle proofs can be
///    verified). Setting this height before
///    `MAINNET_BTC_SPV_RELAY_ACTIVATION_HEIGHT` is meaningless because no
///    proofs would resolve.
/// 2. A dedicated activation commit per the workflow in
///    docs/htlcv1_activation_commit_workflow.md.
pub const MAINNET_HTLC_BTC_SWAP_V1_ACTIVATION_HEIGHT: Option<u64> = Some(23_850);

/// Mainnet SwapOrder activation height (Phase 3).
///
/// `None` keeps the on-chain order book disabled on mainnet. When set to
/// `Some(<height>)`, blocks at or after that height may carry SwapOrder
/// outputs (script tag `0xc5`) and the validator will accept Fill /
/// Cancel / ExpireSweep witnesses against them.
///
/// Phase 3 ships disabled. Sell-direction fills emit `HtlcBtcSwapV1`
/// outputs, so this should not be activated before HtlcBtcSwapV1 — the
/// fill covenant would otherwise reject every spend.
pub const MAINNET_SWAP_ORDER_V1_ACTIVATION_HEIGHT: Option<u64> = Some(23_850);

/// Mainnet activation height for accepting bech32 P2WPKH BTC payments in
/// HtlcBtcSwapV1 claim proofs (in addition to the always-accepted legacy
/// P2PKH form).
///
/// `None` keeps the rule at "P2PKH only" — modern bech32 wallets cannot
/// satisfy the BTC payment leg even when they pay to the correct 20-byte
/// pkh, because the consensus check looks only for the 25-byte P2PKH
/// script shape. Setting this to `Some(<height>)` broadens acceptance: a
/// claim whose referenced BTC tx pays the swap.btc_recipient_pkh via the
/// 22-byte P2WPKH form (`OP_0 <0x14> <20-byte pkh>`) ALSO satisfies the
/// payment check from `<height>` onwards.
///
/// This is a consensus-rule relaxation — old nodes will reject claims new
/// nodes accept, so activation requires a coordinated upgrade window per
/// the workflow in docs/htlcv1_activation_commit_workflow.md.
///
/// LTC piggybacks on `htlc_ltc_swap_v1_activation_height`: when LTC swap
/// goes live on mainnet, bech32 LTC P2WPKH payments are accepted from
/// the same block. No separate LTC constant.
pub const MAINNET_BTC_SWAP_BECH32_PAYMENT_ACTIVATION_HEIGHT: Option<u64> = None;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkKind {
    Mainnet,
    Testnet,
    Devnet,
}

impl NetworkKind {
    pub fn from_env_value(v: &str) -> Self {
        match v.trim().to_ascii_lowercase().as_str() {
            "testnet" => Self::Testnet,
            "devnet" | "regtest" | "trial" => Self::Devnet,
            _ => Self::Mainnet,
        }
    }

    /// Phase 18B: stable one-byte network identifier bound into PoAW-X
    /// delegations so a delegation signed for one network cannot be replayed on
    /// another. Mainnet=0, Testnet=1, Devnet=2.
    pub fn id_byte(self) -> u8 {
        match self {
            Self::Mainnet => 0,
            Self::Testnet => 1,
            Self::Devnet => 2,
        }
    }
}

/// Phase 18B: `network_id` byte for the current network (see `NetworkKind::id_byte`).
pub fn network_id_byte() -> u8 {
    network_kind_from_env().id_byte()
}

pub fn network_kind_from_env() -> NetworkKind {
    env::var("IRIUM_NETWORK")
        .map(|v| NetworkKind::from_env_value(&v))
        .unwrap_or(NetworkKind::Mainnet)
}

/// Phase 18B: activation height for mode-1 (delegated) PoAW-X receipts.
/// `None` => delegated receipts are not yet active (mode-1 rejected). Read from
/// `IRIUM_POAWX_DELEGATION_ACTIVATION_HEIGHT`. Testnet/devnet only — mainnet
/// hard-rejects mode-1 regardless of this value.
/// Mainnet PoAW-X consensus activation height. Fixed in consensus code (NOT env /
/// operator configurable). At and after this height, mainnet enforces the full
/// PoAW-X gate set; before it, mainnet is byte-identical to pre-activation.
pub const MAINNET_POAWX_ACTIVATION_HEIGHT: Option<u64> = Some(50_000);

// ══════════════════════════════════════════════════════════════════════════════
//  COMBINED MAINNET ACTIVATION (Phase-2 / v1.9.133) — THE SINGLE DEPLOY KNOB
// ──────────────────────────────────────────────────────────────────────────────
//  ALL of tonight's new consensus features activate at THIS ONE height on mainnet:
//    PoW-demotion, demonstrated-work, V1 rank-length-floor, four-role fan-out
//    (shared-reward), sybil-resistant pool admission (PLA1 + REQUIRED tickets),
//    A1/A2 sortition cap. (N1=59_900, PoAW-X=50_000, delegation=57_920, and every
//    other live gate are UNCHANGED.) V2 reorg safe-halt is always-on runtime code,
//    not height-gated. `None` => every new feature OFF (byte-identical to the
//    deployed 7a74dfc mainnet behaviour). To ACTIVATE: set to `Some(fresh_tip + 15)`
//    at the deploy step and rebuild — this is the ONLY line to edit.
//  COORDINATED HARD FORK: nodes not on this binary reject the new blocks and fork off.
pub const MAINNET_COMBINED_ACTIVATION_HEIGHT: Option<u64> = Some(61_414);
// ══════════════════════════════════════════════════════════════════════════════

// ──────────────────────────────────────────────────────────────────────────────
//  FAIR-DISTRIBUTION ENFORCEMENT ACTIVATION — THE SINGLE PENDING KNOB
// ──────────────────────────────────────────────────────────────────────────────
//  Arms the coupled fair-distribution ENFORCEMENT at ONE height on mainnet: sybil
//  tickets + pool-member admission + mandatory-inclusion. All three route through
//  `pool_ticket_enforced` (poawx_ticket.rs), so they can NEVER be enforce-on/
//  validate-off (the 2026-07-23 halt class). The four-role coinbase SPLIT is already
//  live (MAINNET_COMBINED_ACTIVATION_HEIGHT = 61_414); this makes the payees provably
//  DISTINCT + sybil-costed. The mandatory-inclusion RECORD phase is derived from this
//  height minus MANDATORY_LEAD_WINDOW (see poawx_admission.rs) so the eligible window
//  is populated by the time enforce fires — set ONLY this one value.
//
//  `None` => OFF, byte-identical to the deployed seamless mainnet behaviour (payees
//  ride advisory / self-fill). To ACTIVATE: set to `Some(fresh_tip + safe_margin)`
//  (a few hundred blocks of headroom) and rebuild — this is the ONLY line to edit.
//
//  ⚠️ GATED — do NOT flip until BOTH hold (CLAUDE.md §12):
//    (1) >= 1 genuine INDEPENDENT miner is enrolling on mainnet — a distinct on-chain
//        role payee whose pkh is neither c2fc869e (vps) nor 222a0b48 (eu), AND
//    (2) the producing network_id=0 boundary test passes: a real multi-payee fan-out
//        block VALIDATES at E, a self-stuffed one REJECTS, a sole-producer block is
//        unaffected (no halt).
//  COORDINATED HARD FORK: nodes not on the activation binary reject the new blocks.
pub const MAINNET_FAIR_DISTRIBUTION_ACTIVATION_HEIGHT: Option<u64> = Some(62236u64);

/// Mainnet activation for the BLUEPRINT four-output coinbase: exactly four P2PKH outputs,
/// one distinct participant per role, each the chain's `best_for_role` winner.
///
/// `docs/POAWX.md` specifies four outputs and four distinct participants. The shipped
/// validator instead splits VERIFY's 13% and SUPPORT's 10% across every admitted candidate,
/// so N enrolled workers produce N outputs per role. `chain::four_role_payout_active` gates
/// the correction.
///
/// **ARMED at 64,940** (operator decision, 2026-07-31): tip was 64,920 and stopped, so this
/// is 20 blocks ahead and cannot be reached until mining resumes. Safely ABOVE 64,852–64,864,
/// which carry 6-payee blocks under the legacy rule — arming at or below those would make a
/// node reject its own chain on restart (CLAUDE.md §12).
///
/// ⚠️ BOTH hosts must run a binary carrying this constant BEFORE the chain reaches 64,940.
/// The old rule splits VERIFY/SUPPORT across every admitted candidate; the new rule pays the
/// four drawn holders. A node on the old binary would reject the other's blocks at the
/// boundary, which is a fork, not a degradation.
pub const MAINNET_FOUR_ROLE_PAYOUT_ACTIVATION_HEIGHT: Option<u64> = Some(64_940u64);
// ══════════════════════════════════════════════════════════════════════════════

/// Activation binary (v1.9.127): mainnet activation height for delegated (mode-1)
/// PoAW-X receipts -- the pool paying each miner directly on-chain. `None` => off
/// (pre-activation); `Some(H)` => active at height >= H. COORDINATED HARD FORK: every
/// full node must run this binary before H or it rejects the delegated blocks and forks.
pub const MAINNET_POAWX_DELEGATION_HEIGHT: Option<u64> = Some(57_920);

/// True when mainnet PoAW-X is active at `height` (mainnet network AND height past
/// the fixed activation height). Always false on testnet/devnet.
pub fn poawx_mainnet_active(height: u64) -> bool {
    network_id_byte() == 0 && matches!(MAINNET_POAWX_ACTIVATION_HEIGHT, Some(h) if height >= h)
}

/// Effective per-gate activation height for `network_id`: the fixed mainnet height
/// on mainnet (env ignored), else the supplied testnet/devnet env activation.
/// Every PoAW-X gate routes its activation through this so 50_000 lives in ONE
/// place. Param-driven (takes `network_id`) to preserve race-free gate unit tests.
pub fn poawx_effective_activation(network_id: u8, env_activation: Option<u64>) -> Option<u64> {
    if network_id == 0 {
        MAINNET_POAWX_ACTIVATION_HEIGHT
    } else {
        env_activation
    }
}

/// Whether PoAW-X consensus is active at `height`. Mainnet: the fixed code height,
/// no env. Testnet/devnet: the env master-switch (`IRIUM_POAWX_MODE=active` AND
/// `IRIUM_POAWX_ACTIVATION_HEIGHT` reached). Replaces the per-callsite env + "==
/// Mainnet -> off" cascade in the validator and producer entry points.
pub fn poawx_consensus_active(height: u64) -> bool {
    if network_id_byte() == 0 {
        return matches!(MAINNET_POAWX_ACTIVATION_HEIGHT, Some(h) if height >= h);
    }
    let mode_active = env::var("IRIUM_POAWX_MODE")
        .map(|v| v.trim() == "active")
        .unwrap_or(false);
    if !mode_active {
        return false;
    }
    match env::var("IRIUM_POAWX_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        Some(h) => height >= h,
        None => false,
    }
}

/// Whether the PoAW-X producer/RPC layer should serve (assignment / receipt / template /
/// submit) at `height`. Mainnet: gated by the fixed code activation height. Testnet/devnet:
/// gated only by the `IRIUM_POAWX_MODE` master switch (height-independent), matching the
/// pre-mainnet serving behavior. Distinct from `poawx_consensus_active`, which additionally
/// height-gates devnet *validation* by the env activation height.
pub fn poawx_serving_active(height: u64) -> bool {
    if network_id_byte() == 0 {
        return matches!(MAINNET_POAWX_ACTIVATION_HEIGHT, Some(h) if height >= h);
    }
    env::var("IRIUM_POAWX_MODE")
        .map(|v| v.trim() == "active")
        .unwrap_or(false)
}

/// Mainnet PoAW-X liveness-recovery activation height. Fixed in consensus code.
/// At/after this height, if the chain is GENUINELY stalled (parent older than
/// `proposer_stall_recovery_secs()`, a threshold above MAX_FUTURE_BLOCK_TIME so the
/// gap cannot be forged), the proposer frozen-WINDOW eligibility test is relaxed to
/// any prior on-chain registration. Dormant until a real multi-hour stall.
pub const MAINNET_POAWX_LIVENESS_RECOVERY_ACTIVATION_HEIGHT: Option<u64> = Some(50_000);

/// True when mainnet PoAW-X liveness recovery is active at `height`. Testnet/devnet
/// gate on `IRIUM_POAWX_LIVENESS_RECOVERY_ACTIVATION_HEIGHT`.
pub fn poawx_liveness_recovery_active(height: u64) -> bool {
    if network_id_byte() == 0 {
        return matches!(MAINNET_POAWX_LIVENESS_RECOVERY_ACTIVATION_HEIGHT, Some(h) if height >= h);
    }
    env::var("IRIUM_POAWX_LIVENESS_RECOVERY_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map_or(false, |h| height >= h)
}

pub fn poawx_delegation_activation_height() -> Option<u64> {
    env::var("IRIUM_POAWX_DELEGATION_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// Phase 20: activation height for the multi-role reward split. `None` => not
/// active (existing reward behavior unchanged). Read from
/// `IRIUM_POAWX_MULTI_ROLE_REWARD_ACTIVATION_HEIGHT`. Testnet/devnet only —
/// mainnet hard-rejects the multi-role split regardless of this value (the
/// activation gate in `chain` returns false on mainnet) until an explicit
/// future governance activation path exists.
pub fn poawx_multi_role_reward_activation_height() -> Option<u64> {
    env::var("IRIUM_POAWX_MULTI_ROLE_REWARD_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// Step 2 (devnet build-out): activation height for the §6 "(shared)" multi-payee
/// coinbase fan-out (Other Valid Workers 13% + Finality Committee 10% split across
/// their candidates). `None` => not active. Read from
/// `IRIUM_POAWX_SHARED_REWARD_ACTIVATION_HEIGHT`. Testnet/devnet only — mainnet is
/// hard-off (the `chain::shared_reward_active` gate returns false on mainnet).
pub fn poawx_shared_reward_activation_height() -> Option<u64> {
    env::var("IRIUM_POAWX_SHARED_REWARD_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// Step 3 (devnet build-out): activation height for sybil-resistant fan-out pool
/// admission — every non-winner VERIFY/SUPPORT pool member must carry a valid VRF
/// assignment proof + sybil ticket. `None` => not active. Read from
/// `IRIUM_POAWX_POOL_ADMISSION_ACTIVATION_HEIGHT`. Testnet/devnet only — mainnet
/// hard-off (`chain::pool_admission_enforced` returns false on mainnet).
pub fn poawx_pool_admission_activation_height() -> Option<u64> {
    env::var("IRIUM_POAWX_POOL_ADMISSION_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// A1/A2 fix: activation height for the VRF sortition cap bounding VERIFY/SUPPORT
/// pool + finality-committee size to ~K per role. `None` => not active. Read from
/// `IRIUM_POAWX_POOL_SORTITION_ACTIVATION_HEIGHT`. Testnet/devnet only — mainnet
/// hard-off (`chain::pool_sortition_enforced` returns false on mainnet).
pub fn poawx_pool_sortition_activation_height() -> Option<u64> {
    env::var("IRIUM_POAWX_POOL_SORTITION_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// Phase 20: activation height for the CPU/GPU/ASIC fairness matrix primitives.
/// `None` => not active. Read from `IRIUM_POAWX_FAIRNESS_MATRIX_ACTIVATION_HEIGHT`.
/// Testnet/devnet only — mainnet is hard-off (the `chain` gate returns false on
/// mainnet) until an explicit future governance activation.
pub fn poawx_fairness_matrix_activation_height() -> Option<u64> {
    env::var("IRIUM_POAWX_FAIRNESS_MATRIX_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// Phase 20: activation height for the third-party pool fee. `None` => not active
/// (official 0% only). Read from `IRIUM_POAWX_THIRD_PARTY_FEE_ACTIVATION_HEIGHT`.
/// Testnet/devnet only — mainnet is hard-off (the `chain` gate returns false on
/// mainnet) until an explicit future governance activation.
pub fn poawx_third_party_fee_activation_height() -> Option<u64> {
    env::var("IRIUM_POAWX_THIRD_PARTY_FEE_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// Phase 20 Step 6A: activation height for the hidden role-precommit commitment
/// root. `None` => not active. Read from `IRIUM_POAWX_HIDDEN_PRECOMMIT_ACTIVATION_HEIGHT`.
/// Testnet/devnet only — mainnet is hard-off (the `chain` gate returns false on
/// mainnet) until an explicit future governance activation.
pub fn poawx_hidden_precommit_activation_height() -> Option<u64> {
    env::var("IRIUM_POAWX_HIDDEN_PRECOMMIT_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

pub fn runtime_htlcv1_env_override() -> Option<u64> {
    env::var("IRIUM_HTLCV1_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

pub fn runtime_lwma_env_override() -> Option<u64> {
    env::var("IRIUM_LWMA_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

pub fn runtime_lwma_v2_env_override() -> Option<u64> {
    env::var("IRIUM_LWMA_V2_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

pub fn runtime_auxpow_env_override() -> Option<u64> {
    env::var("IRIUM_AUXPOW_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

pub fn resolved_htlcv1_activation_height(network: NetworkKind) -> Option<u64> {
    match network {
        NetworkKind::Mainnet => MAINNET_HTLCV1_ACTIVATION_HEIGHT,
        NetworkKind::Testnet | NetworkKind::Devnet => runtime_htlcv1_env_override(),
    }
}

pub fn resolved_lwma_activation_height(network: NetworkKind) -> Option<u64> {
    match network {
        NetworkKind::Mainnet => MAINNET_LWMA_ACTIVATION_HEIGHT,
        NetworkKind::Testnet | NetworkKind::Devnet => runtime_lwma_env_override(),
    }
}

pub fn resolved_lwma_v2_activation_height(network: NetworkKind) -> Option<u64> {
    match network {
        NetworkKind::Mainnet => MAINNET_LWMA_V2_ACTIVATION_HEIGHT,
        NetworkKind::Testnet | NetworkKind::Devnet => runtime_lwma_v2_env_override(),
    }
}

/// Non-mainnet-only env override for the standard-header (Fix 2a) activation
/// height. Parsed from IRIUM_STANDARD_HEADER_ACTIVATION_HEIGHT.
pub fn runtime_standard_header_activation_env_override() -> Option<u64> {
    env::var("IRIUM_STANDARD_HEADER_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// Resolve the standard-header (Fix 2a) activation height for `network`.
/// MAINNET is ALWAYS the historical constant and IGNORES any env override, so
/// mainnet header serialization/hashing is permanently byte-stable. Testnet/
/// devnet default to 1 (genesis-preserving: height 0 keeps the legacy header so
/// the fixed devnet/testnet genesis stays valid; every MINED block height >= 1
/// uses Bitcoin-standard natural-merkle headers so standard miners validate) —
/// with an optional env override for tests.
pub fn resolved_standard_header_activation_height(network: NetworkKind) -> u64 {
    resolve_standard_header_activation(network, runtime_standard_header_activation_env_override())
}

/// Pure resolver (no env read) for testability. Mainnet ALWAYS returns the
/// historical constant and ignores `env_override`; testnet/devnet use the
/// override or default to 1 (genesis-preserving).
pub(crate) fn resolve_standard_header_activation(
    network: NetworkKind,
    env_override: Option<u64>,
) -> u64 {
    match network {
        NetworkKind::Mainnet => crate::constants::STANDARD_HEADER_ACTIVATION_HEIGHT,
        // 1 (not 0): genesis (height 0) keeps the legacy header format so the
        // fixed devnet/testnet genesis stays valid; every MINED block (height >= 1)
        // uses the Bitcoin-standard header so standard miners (cpuminer) validate.
        NetworkKind::Testnet | NetworkKind::Devnet => env_override.unwrap_or(1),
    }
}

pub fn resolved_auxpow_activation_height(network: NetworkKind) -> Option<u64> {
    match network {
        NetworkKind::Mainnet => MAINNET_AUXPOW_ACTIVATION_HEIGHT,
        NetworkKind::Testnet | NetworkKind::Devnet => runtime_auxpow_env_override(),
    }
}

/// Devnet/testnet override for the block-time V2 activation height.
/// Read from `IRIUM_BLOCK_TIME_V2_ACTIVATION_HEIGHT`. Ignored on mainnet,
/// which uses `MAINNET_BLOCK_TIME_V2_ACTIVATION_HEIGHT`.
pub fn runtime_block_time_v2_env_override() -> Option<u64> {
    env::var("IRIUM_BLOCK_TIME_V2_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// Resolves the block-time V2 activation height for the running network.
/// Read by `constants.rs::block_target_interval(height)` and
/// `constants.rs::halving_count(height)` so the V1→V2 switch is
/// network-aware without threading ChainParams through every caller of
/// `block_reward(height)`.
pub fn resolved_block_time_v2_activation_height(network: NetworkKind) -> Option<u64> {
    match network {
        NetworkKind::Mainnet => MAINNET_BLOCK_TIME_V2_ACTIVATION_HEIGHT,
        NetworkKind::Testnet | NetworkKind::Devnet => runtime_block_time_v2_env_override(),
    }
}

/// Devnet/testnet override for the BTC SPV header relay activation height.
/// Read from `IRIUM_BTC_SPV_RELAY_ACTIVATION_HEIGHT`. Ignored on mainnet.
#[allow(dead_code)] // wired through ChainParams once Phase 1 callers come online
pub fn runtime_btc_spv_relay_env_override() -> Option<u64> {
    env::var("IRIUM_BTC_SPV_RELAY_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

#[allow(dead_code)] // wired through ChainParams once Phase 1 callers come online
pub fn resolved_btc_spv_relay_activation_height(network: NetworkKind) -> Option<u64> {
    match network {
        NetworkKind::Mainnet => MAINNET_BTC_SPV_RELAY_ACTIVATION_HEIGHT,
        NetworkKind::Testnet | NetworkKind::Devnet => runtime_btc_spv_relay_env_override(),
    }
}

/// Devnet/testnet override for the LTC SPV header relay activation height.
/// Read from `IRIUM_LTC_SPV_RELAY_ACTIVATION_HEIGHT`. Ignored on mainnet.
#[allow(dead_code)] // wired through ChainParams once Phase B callers come online
pub fn runtime_ltc_spv_relay_env_override() -> Option<u64> {
    env::var("IRIUM_LTC_SPV_RELAY_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

#[allow(dead_code)] // wired through ChainParams once Phase B callers come online
pub fn resolved_ltc_spv_relay_activation_height(network: NetworkKind) -> Option<u64> {
    match network {
        NetworkKind::Mainnet => MAINNET_LTC_SPV_RELAY_ACTIVATION_HEIGHT,
        NetworkKind::Testnet | NetworkKind::Devnet => runtime_ltc_spv_relay_env_override(),
    }
}

/// Devnet/testnet override for the HtlcLtcSwapV1 activation height.
/// Read from `IRIUM_HTLC_LTC_SWAP_V1_ACTIVATION_HEIGHT`. Ignored on mainnet.
#[allow(dead_code)] // wired through ChainParams once Phase C callers come online
pub fn runtime_htlc_ltc_swap_v1_env_override() -> Option<u64> {
    env::var("IRIUM_HTLC_LTC_SWAP_V1_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

#[allow(dead_code)] // wired through ChainParams once Phase C callers come online
pub fn resolved_htlc_ltc_swap_v1_activation_height(network: NetworkKind) -> Option<u64> {
    match network {
        NetworkKind::Mainnet => MAINNET_HTLC_LTC_SWAP_V1_ACTIVATION_HEIGHT,
        NetworkKind::Testnet | NetworkKind::Devnet => runtime_htlc_ltc_swap_v1_env_override(),
    }
}

/// Devnet/testnet override for the LtcSwapOrder activation height.
/// Read from `IRIUM_LTC_SWAP_ORDER_V1_ACTIVATION_HEIGHT`. Ignored on mainnet.
#[allow(dead_code)] // wired through ChainParams once Phase D callers come online
pub fn runtime_ltc_swap_order_v1_env_override() -> Option<u64> {
    env::var("IRIUM_LTC_SWAP_ORDER_V1_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

#[allow(dead_code)] // wired through ChainParams once Phase D callers come online
pub fn resolved_ltc_swap_order_v1_activation_height(network: NetworkKind) -> Option<u64> {
    match network {
        NetworkKind::Mainnet => MAINNET_LTC_SWAP_ORDER_V1_ACTIVATION_HEIGHT,
        NetworkKind::Testnet | NetworkKind::Devnet => runtime_ltc_swap_order_v1_env_override(),
    }
}

/// Devnet/testnet override for the HtlcBtcSwapV1 activation height.
/// Read from `IRIUM_HTLC_BTC_SWAP_V1_ACTIVATION_HEIGHT`. Ignored on mainnet.
#[allow(dead_code)] // wired through ChainParams once Phase 2 callers come online
pub fn runtime_htlc_btc_swap_v1_env_override() -> Option<u64> {
    env::var("IRIUM_HTLC_BTC_SWAP_V1_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

#[allow(dead_code)] // wired through ChainParams once Phase 2 callers come online
pub fn resolved_htlc_btc_swap_v1_activation_height(network: NetworkKind) -> Option<u64> {
    match network {
        NetworkKind::Mainnet => MAINNET_HTLC_BTC_SWAP_V1_ACTIVATION_HEIGHT,
        NetworkKind::Testnet | NetworkKind::Devnet => runtime_htlc_btc_swap_v1_env_override(),
    }
}

/// Devnet/testnet override for the SwapOrder activation height.
/// Read from `IRIUM_SWAP_ORDER_V1_ACTIVATION_HEIGHT`. Ignored on mainnet.
#[allow(dead_code)] // wired through ChainParams once Phase 3 callers come online
pub fn runtime_swap_order_v1_env_override() -> Option<u64> {
    env::var("IRIUM_SWAP_ORDER_V1_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

#[allow(dead_code)] // wired through ChainParams once Phase 3 callers come online
pub fn resolved_swap_order_v1_activation_height(network: NetworkKind) -> Option<u64> {
    match network {
        NetworkKind::Mainnet => MAINNET_SWAP_ORDER_V1_ACTIVATION_HEIGHT,
        NetworkKind::Testnet | NetworkKind::Devnet => runtime_swap_order_v1_env_override(),
    }
}

/// Devnet/testnet override for the BTC-swap bech32-payment activation
/// height. Read from `IRIUM_BTC_SWAP_BECH32_PAYMENT_ACTIVATION_HEIGHT`.
/// Ignored on mainnet, which uses
/// `MAINNET_BTC_SWAP_BECH32_PAYMENT_ACTIVATION_HEIGHT`.
#[allow(dead_code)] // wired through ChainParams once the bech32-payment relaxation is consumed
pub fn runtime_btc_swap_bech32_payment_env_override() -> Option<u64> {
    env::var("IRIUM_BTC_SWAP_BECH32_PAYMENT_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

#[allow(dead_code)] // wired through ChainParams once the bech32-payment relaxation is consumed
pub fn resolved_btc_swap_bech32_payment_activation_height(network: NetworkKind) -> Option<u64> {
    match network {
        NetworkKind::Mainnet => MAINNET_BTC_SWAP_BECH32_PAYMENT_ACTIVATION_HEIGHT,
        NetworkKind::Testnet | NetworkKind::Devnet => {
            runtime_btc_swap_bech32_payment_env_override()
        }
    }
}

/// Mainnet MPSOv1 (M-of-N multisig output) activation height.
///
/// Activated at block 20,000. No MPSO outputs exist before this height.
#[allow(dead_code)] // protocol constant: MPSOv1 activation height on mainnet
pub const MAINNET_MPSOV1_ACTIVATION_HEIGHT: Option<u64> = Some(20_000);

#[allow(dead_code)] // env override for testing MPSOv1 activation on non-mainnet networks
pub fn runtime_mpsov1_env_override() -> Option<u64> {
    env::var("IRIUM_MPSOV1_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

#[allow(dead_code)] // public resolver for MPSOv1 activation height; used by wallet and block validators once MPSOv1 ships
pub fn resolved_coinbase_header_batch_activation_height(network: NetworkKind) -> Option<u64> {
    match network {
        NetworkKind::Mainnet => MAINNET_COINBASE_HEADER_BATCH_ACTIVATION_HEIGHT,
        NetworkKind::Devnet | NetworkKind::Testnet => {
            env::var("IRIUM_COINBASE_HEADER_BATCH_ACTIVATION_HEIGHT")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .map(Some)
                .unwrap_or(None)
        }
    }
}

pub fn resolved_mpsov1_activation_height(network: NetworkKind) -> Option<u64> {
    match network {
        NetworkKind::Mainnet => MAINNET_MPSOV1_ACTIVATION_HEIGHT,
        NetworkKind::Testnet | NetworkKind::Devnet => runtime_mpsov1_env_override(),
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

    #[test]
    fn standard_header_resolver_mainnet_ignores_override() {
        let _env = crate::test_env::guard();
        assert_eq!(
            resolve_standard_header_activation(NetworkKind::Mainnet, Some(5)),
            crate::constants::STANDARD_HEADER_ACTIVATION_HEIGHT
        );
        assert_eq!(
            resolve_standard_header_activation(NetworkKind::Mainnet, None),
            crate::constants::STANDARD_HEADER_ACTIVATION_HEIGHT
        );
    }

    #[test]
    fn standard_header_resolver_non_mainnet_default_one_or_override() {
        let _env = crate::test_env::guard();
        assert_eq!(
            resolve_standard_header_activation(NetworkKind::Devnet, None),
            1
        );
        assert_eq!(
            resolve_standard_header_activation(NetworkKind::Testnet, None),
            1
        );
        assert_eq!(
            resolve_standard_header_activation(NetworkKind::Devnet, Some(123)),
            123
        );
        assert_eq!(
            resolve_standard_header_activation(NetworkKind::Testnet, Some(7)),
            7
        );
    }

    #[test]
    fn standard_header_mainnet_ignores_env_var() {
        let _env = crate::test_env::guard();
        let _g = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_STANDARD_HEADER_ACTIVATION_HEIGHT", "9");
        assert_eq!(
            resolved_standard_header_activation_height(NetworkKind::Mainnet),
            crate::constants::STANDARD_HEADER_ACTIVATION_HEIGHT
        );
        assert_eq!(
            resolved_standard_header_activation_height(NetworkKind::Devnet),
            9
        );
        std::env::remove_var("IRIUM_STANDARD_HEADER_ACTIVATION_HEIGHT");
    }

    #[test]
    fn mainnet_ignores_htlc_env_override() {
        let _env = crate::test_env::guard();
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("IRIUM_HTLCV1_ACTIVATION_HEIGHT", "42");
        let resolved = resolved_htlcv1_activation_height(NetworkKind::Mainnet);
        std::env::remove_var("IRIUM_HTLCV1_ACTIVATION_HEIGHT");
        assert_eq!(resolved, MAINNET_HTLCV1_ACTIVATION_HEIGHT);
    }

    #[test]
    fn non_mainnet_uses_htlc_env_override() {
        let _env = crate::test_env::guard();
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("IRIUM_HTLCV1_ACTIVATION_HEIGHT", "42");
        assert_eq!(
            resolved_htlcv1_activation_height(NetworkKind::Devnet),
            Some(42)
        );
        assert_eq!(
            resolved_htlcv1_activation_height(NetworkKind::Testnet),
            Some(42)
        );
        std::env::remove_var("IRIUM_HTLCV1_ACTIVATION_HEIGHT");
    }

    #[test]
    fn mainnet_ignores_lwma_env_override() {
        let _env = crate::test_env::guard();
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("IRIUM_LWMA_ACTIVATION_HEIGHT", "42");
        let resolved = resolved_lwma_activation_height(NetworkKind::Mainnet);
        std::env::remove_var("IRIUM_LWMA_ACTIVATION_HEIGHT");
        assert_eq!(resolved, MAINNET_LWMA_ACTIVATION_HEIGHT);
    }

    #[test]
    fn non_mainnet_uses_lwma_env_override() {
        let _env = crate::test_env::guard();
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("IRIUM_LWMA_ACTIVATION_HEIGHT", "42");
        assert_eq!(
            resolved_lwma_activation_height(NetworkKind::Devnet),
            Some(42)
        );
        assert_eq!(
            resolved_lwma_activation_height(NetworkKind::Testnet),
            Some(42)
        );
        std::env::remove_var("IRIUM_LWMA_ACTIVATION_HEIGHT");
    }

    #[test]
    fn mainnet_lwma_v2_activation_height_is_set() {
        let _env = crate::test_env::guard();
        assert_eq!(
            MAINNET_LWMA_V2_ACTIVATION_HEIGHT,
            Some(19_740),
            "LWMA v2 mainnet activation height must be 19740"
        );
        assert_eq!(
            resolved_lwma_v2_activation_height(NetworkKind::Mainnet),
            Some(19_740),
            "resolved v2 height must be Some(19740) for mainnet"
        );
    }

    #[test]
    fn mainnet_ignores_lwma_v2_env_override() {
        let _env = crate::test_env::guard();
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("IRIUM_LWMA_V2_ACTIVATION_HEIGHT", "99999");
        let resolved = resolved_lwma_v2_activation_height(NetworkKind::Mainnet);
        std::env::remove_var("IRIUM_LWMA_V2_ACTIVATION_HEIGHT");
        assert_eq!(resolved, MAINNET_LWMA_V2_ACTIVATION_HEIGHT);
        assert_eq!(
            resolved,
            Some(19_740),
            "mainnet v2 height must be code-defined 19740, not env override 99999"
        );
    }

    #[test]
    fn non_mainnet_uses_lwma_v2_env_override() {
        let _env = crate::test_env::guard();
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("IRIUM_LWMA_V2_ACTIVATION_HEIGHT", "500");
        assert_eq!(
            resolved_lwma_v2_activation_height(NetworkKind::Devnet),
            Some(500)
        );
        assert_eq!(
            resolved_lwma_v2_activation_height(NetworkKind::Testnet),
            Some(500)
        );
        std::env::remove_var("IRIUM_LWMA_V2_ACTIVATION_HEIGHT");
    }

    #[test]
    fn mainnet_auxpow_activation_height_is_24800() {
        let _env = crate::test_env::guard();
        assert_eq!(
            MAINNET_AUXPOW_ACTIVATION_HEIGHT,
            Some(24_800),
            "AuxPoW mainnet activation height must be 24800"
        );
        assert_eq!(
            resolved_auxpow_activation_height(NetworkKind::Mainnet),
            Some(24_800)
        );
    }

    #[test]
    fn mainnet_ignores_auxpow_env_override() {
        let _env = crate::test_env::guard();
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("IRIUM_AUXPOW_ACTIVATION_HEIGHT", "99999");
        let resolved = resolved_auxpow_activation_height(NetworkKind::Mainnet);
        std::env::remove_var("IRIUM_AUXPOW_ACTIVATION_HEIGHT");
        assert_eq!(resolved, MAINNET_AUXPOW_ACTIVATION_HEIGHT);
    }

    #[test]
    fn non_mainnet_uses_auxpow_env_override() {
        let _env = crate::test_env::guard();
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("IRIUM_AUXPOW_ACTIVATION_HEIGHT", "1000");
        assert_eq!(
            resolved_auxpow_activation_height(NetworkKind::Devnet),
            Some(1000)
        );
        assert_eq!(
            resolved_auxpow_activation_height(NetworkKind::Testnet),
            Some(1000)
        );
        std::env::remove_var("IRIUM_AUXPOW_ACTIVATION_HEIGHT");
    }

    #[test]
    fn mainnet_block_time_v2_activation_height_is_24250() {
        let _env = crate::test_env::guard();
        assert_eq!(
            MAINNET_BLOCK_TIME_V2_ACTIVATION_HEIGHT,
            Some(24_250),
            "Block-time V2 mainnet activation height must be 24250"
        );
        assert_eq!(
            resolved_block_time_v2_activation_height(NetworkKind::Mainnet),
            Some(24_250)
        );
    }

    #[test]
    fn mainnet_ignores_block_time_v2_env_override() {
        let _env = crate::test_env::guard();
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("IRIUM_BLOCK_TIME_V2_ACTIVATION_HEIGHT", "12345");
        let resolved = resolved_block_time_v2_activation_height(NetworkKind::Mainnet);
        std::env::remove_var("IRIUM_BLOCK_TIME_V2_ACTIVATION_HEIGHT");
        assert_eq!(resolved, MAINNET_BLOCK_TIME_V2_ACTIVATION_HEIGHT);
        assert_eq!(
            resolved,
            Some(24_250),
            "mainnet block-time-V2 height must be the code-defined 24250, not the env override 12345"
        );
    }

    #[test]
    fn non_mainnet_uses_block_time_v2_env_override() {
        let _env = crate::test_env::guard();
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("IRIUM_BLOCK_TIME_V2_ACTIVATION_HEIGHT", "75");
        assert_eq!(
            resolved_block_time_v2_activation_height(NetworkKind::Devnet),
            Some(75)
        );
        assert_eq!(
            resolved_block_time_v2_activation_height(NetworkKind::Testnet),
            Some(75)
        );
        std::env::remove_var("IRIUM_BLOCK_TIME_V2_ACTIVATION_HEIGHT");
    }

    #[test]
    fn mainnet_btc_spv_relay_height_is_23850() {
        let _env = crate::test_env::guard();
        assert_eq!(
            MAINNET_BTC_SPV_RELAY_ACTIVATION_HEIGHT,
            Some(23_850),
            "Phase 1 activated on mainnet at height 23850"
        );
        assert_eq!(
            resolved_btc_spv_relay_activation_height(NetworkKind::Mainnet),
            Some(23_850)
        );
    }

    #[test]
    fn mainnet_ignores_btc_spv_env_override() {
        let _env = crate::test_env::guard();
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("IRIUM_BTC_SPV_RELAY_ACTIVATION_HEIGHT", "12345");
        let resolved = resolved_btc_spv_relay_activation_height(NetworkKind::Mainnet);
        std::env::remove_var("IRIUM_BTC_SPV_RELAY_ACTIVATION_HEIGHT");
        assert_eq!(resolved, MAINNET_BTC_SPV_RELAY_ACTIVATION_HEIGHT);
        assert_eq!(resolved, Some(23_850));
    }

    #[test]
    fn non_mainnet_uses_btc_spv_env_override() {
        let _env = crate::test_env::guard();
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("IRIUM_BTC_SPV_RELAY_ACTIVATION_HEIGHT", "50");
        assert_eq!(
            resolved_btc_spv_relay_activation_height(NetworkKind::Devnet),
            Some(50)
        );
        assert_eq!(
            resolved_btc_spv_relay_activation_height(NetworkKind::Testnet),
            Some(50)
        );
        std::env::remove_var("IRIUM_BTC_SPV_RELAY_ACTIVATION_HEIGHT");
    }

    #[test]
    fn mainnet_htlc_btc_swap_v1_height_is_23850() {
        let _env = crate::test_env::guard();
        assert_eq!(
            MAINNET_HTLC_BTC_SWAP_V1_ACTIVATION_HEIGHT,
            Some(23_850),
            "Phase 2 activated on mainnet at height 23850"
        );
        assert_eq!(
            resolved_htlc_btc_swap_v1_activation_height(NetworkKind::Mainnet),
            Some(23_850)
        );
    }

    #[test]
    fn mainnet_ignores_htlc_btc_swap_v1_env_override() {
        let _env = crate::test_env::guard();
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("IRIUM_HTLC_BTC_SWAP_V1_ACTIVATION_HEIGHT", "777");
        let resolved = resolved_htlc_btc_swap_v1_activation_height(NetworkKind::Mainnet);
        std::env::remove_var("IRIUM_HTLC_BTC_SWAP_V1_ACTIVATION_HEIGHT");
        assert_eq!(resolved, MAINNET_HTLC_BTC_SWAP_V1_ACTIVATION_HEIGHT);
        assert_eq!(resolved, Some(23_850));
    }

    #[test]
    fn non_mainnet_uses_htlc_btc_swap_v1_env_override() {
        let _env = crate::test_env::guard();
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("IRIUM_HTLC_BTC_SWAP_V1_ACTIVATION_HEIGHT", "777");
        assert_eq!(
            resolved_htlc_btc_swap_v1_activation_height(NetworkKind::Devnet),
            Some(777)
        );
        assert_eq!(
            resolved_htlc_btc_swap_v1_activation_height(NetworkKind::Testnet),
            Some(777)
        );
        std::env::remove_var("IRIUM_HTLC_BTC_SWAP_V1_ACTIVATION_HEIGHT");
    }

    #[test]
    fn mainnet_swap_order_v1_height_is_23850() {
        let _env = crate::test_env::guard();
        assert_eq!(
            MAINNET_SWAP_ORDER_V1_ACTIVATION_HEIGHT,
            Some(23_850),
            "Phase 3 activated on mainnet at height 23850"
        );
        assert_eq!(
            resolved_swap_order_v1_activation_height(NetworkKind::Mainnet),
            Some(23_850)
        );
    }

    #[test]
    fn mainnet_ignores_swap_order_v1_env_override() {
        let _env = crate::test_env::guard();
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("IRIUM_SWAP_ORDER_V1_ACTIVATION_HEIGHT", "4242");
        let resolved = resolved_swap_order_v1_activation_height(NetworkKind::Mainnet);
        std::env::remove_var("IRIUM_SWAP_ORDER_V1_ACTIVATION_HEIGHT");
        assert_eq!(resolved, MAINNET_SWAP_ORDER_V1_ACTIVATION_HEIGHT);
        assert_eq!(resolved, Some(23_850));
    }

    #[test]
    fn non_mainnet_uses_swap_order_v1_env_override() {
        let _env = crate::test_env::guard();
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("IRIUM_SWAP_ORDER_V1_ACTIVATION_HEIGHT", "111");
        assert_eq!(
            resolved_swap_order_v1_activation_height(NetworkKind::Devnet),
            Some(111)
        );
        assert_eq!(
            resolved_swap_order_v1_activation_height(NetworkKind::Testnet),
            Some(111)
        );
        std::env::remove_var("IRIUM_SWAP_ORDER_V1_ACTIVATION_HEIGHT");
    }

    #[test]
    fn mainnet_ltc_spv_height_activated_at_24800() {
        let _env = crate::test_env::guard();
        assert_eq!(
            MAINNET_LTC_SPV_RELAY_ACTIVATION_HEIGHT,
            Some(24_800),
            "LTC SPV mainnet activation height is set to 24_800"
        );
        assert_eq!(
            resolved_ltc_spv_relay_activation_height(NetworkKind::Mainnet),
            Some(24_800),
        );
    }

    #[test]
    fn mainnet_ignores_ltc_spv_env_override() {
        let _env = crate::test_env::guard();
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("IRIUM_LTC_SPV_RELAY_ACTIVATION_HEIGHT", "5555");
        let resolved = resolved_ltc_spv_relay_activation_height(NetworkKind::Mainnet);
        std::env::remove_var("IRIUM_LTC_SPV_RELAY_ACTIVATION_HEIGHT");
        assert_eq!(resolved, MAINNET_LTC_SPV_RELAY_ACTIVATION_HEIGHT);
        assert_eq!(resolved, Some(24_800));
    }

    #[test]
    fn non_mainnet_uses_ltc_spv_env_override() {
        let _env = crate::test_env::guard();
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("IRIUM_LTC_SPV_RELAY_ACTIVATION_HEIGHT", "77");
        assert_eq!(
            resolved_ltc_spv_relay_activation_height(NetworkKind::Devnet),
            Some(77)
        );
        assert_eq!(
            resolved_ltc_spv_relay_activation_height(NetworkKind::Testnet),
            Some(77)
        );
        std::env::remove_var("IRIUM_LTC_SPV_RELAY_ACTIVATION_HEIGHT");
    }

    #[test]
    fn mainnet_ltc_anchor_constants_have_expected_values() {
        let _env = crate::test_env::guard();
        // Display-order hash (from litecoinspace.org / Litecoin Core RPC).
        // Reversed to natural order in `LtcAnchor::mainnet()`.
        assert_eq!(MAINNET_LTC_ANCHOR_HEIGHT, 3_106_656);
        assert_eq!(MAINNET_LTC_ANCHOR_BITS, 0x1929_b619);
        assert_eq!(MAINNET_LTC_ANCHOR_TIME, 1_778_676_649);
        assert_eq!(MAINNET_LTC_ANCHOR_HASH_DISPLAY[0], 0x8a);
        assert_eq!(MAINNET_LTC_ANCHOR_HASH_DISPLAY[31], 0x64);
    }

    #[test]
    fn mainnet_htlc_ltc_swap_v1_height_activated_at_24800() {
        let _env = crate::test_env::guard();
        assert_eq!(
            MAINNET_HTLC_LTC_SWAP_V1_ACTIVATION_HEIGHT,
            Some(24_800),
            "HtlcLtcSwapV1 mainnet activation height is set to 24_800"
        );
        assert_eq!(
            resolved_htlc_ltc_swap_v1_activation_height(NetworkKind::Mainnet),
            Some(24_800),
        );
    }

    #[test]
    fn mainnet_ignores_htlc_ltc_swap_v1_env_override() {
        let _env = crate::test_env::guard();
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("IRIUM_HTLC_LTC_SWAP_V1_ACTIVATION_HEIGHT", "8888");
        let resolved = resolved_htlc_ltc_swap_v1_activation_height(NetworkKind::Mainnet);
        std::env::remove_var("IRIUM_HTLC_LTC_SWAP_V1_ACTIVATION_HEIGHT");
        assert_eq!(resolved, MAINNET_HTLC_LTC_SWAP_V1_ACTIVATION_HEIGHT);
        assert_eq!(resolved, Some(24_800));
    }

    #[test]
    fn non_mainnet_uses_htlc_ltc_swap_v1_env_override() {
        let _env = crate::test_env::guard();
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("IRIUM_HTLC_LTC_SWAP_V1_ACTIVATION_HEIGHT", "99");
        assert_eq!(
            resolved_htlc_ltc_swap_v1_activation_height(NetworkKind::Devnet),
            Some(99)
        );
        assert_eq!(
            resolved_htlc_ltc_swap_v1_activation_height(NetworkKind::Testnet),
            Some(99)
        );
        std::env::remove_var("IRIUM_HTLC_LTC_SWAP_V1_ACTIVATION_HEIGHT");
    }

    #[test]
    fn mainnet_ltc_swap_order_v1_height_activated_at_24800() {
        let _env = crate::test_env::guard();
        assert_eq!(
            MAINNET_LTC_SWAP_ORDER_V1_ACTIVATION_HEIGHT,
            Some(24_800),
            "LtcSwapOrder mainnet activation height is set to 24_800"
        );
        assert_eq!(
            resolved_ltc_swap_order_v1_activation_height(NetworkKind::Mainnet),
            Some(24_800),
        );
    }

    #[test]
    fn mainnet_ignores_ltc_swap_order_v1_env_override() {
        let _env = crate::test_env::guard();
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("IRIUM_LTC_SWAP_ORDER_V1_ACTIVATION_HEIGHT", "3333");
        let resolved = resolved_ltc_swap_order_v1_activation_height(NetworkKind::Mainnet);
        std::env::remove_var("IRIUM_LTC_SWAP_ORDER_V1_ACTIVATION_HEIGHT");
        assert_eq!(resolved, MAINNET_LTC_SWAP_ORDER_V1_ACTIVATION_HEIGHT);
        assert_eq!(resolved, Some(24_800));
    }

    #[test]
    fn non_mainnet_uses_ltc_swap_order_v1_env_override() {
        let _env = crate::test_env::guard();
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("IRIUM_LTC_SWAP_ORDER_V1_ACTIVATION_HEIGHT", "222");
        assert_eq!(
            resolved_ltc_swap_order_v1_activation_height(NetworkKind::Devnet),
            Some(222)
        );
        assert_eq!(
            resolved_ltc_swap_order_v1_activation_height(NetworkKind::Testnet),
            Some(222)
        );
        std::env::remove_var("IRIUM_LTC_SWAP_ORDER_V1_ACTIVATION_HEIGHT");
    }

    #[test]
    fn mainnet_btc_swap_bech32_payment_is_none_pending_governance() {
        let _env = crate::test_env::guard();
        assert!(
            MAINNET_BTC_SWAP_BECH32_PAYMENT_ACTIVATION_HEIGHT.is_none(),
            "bech32 P2WPKH BTC payment acceptance must stay disabled on mainnet until governance flips this constant"
        );
        assert!(resolved_btc_swap_bech32_payment_activation_height(NetworkKind::Mainnet).is_none());
    }

    #[test]
    fn mainnet_ignores_btc_swap_bech32_payment_env_override() {
        let _env = crate::test_env::guard();
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("IRIUM_BTC_SWAP_BECH32_PAYMENT_ACTIVATION_HEIGHT", "12345");
        let resolved = resolved_btc_swap_bech32_payment_activation_height(NetworkKind::Mainnet);
        std::env::remove_var("IRIUM_BTC_SWAP_BECH32_PAYMENT_ACTIVATION_HEIGHT");
        assert_eq!(resolved, MAINNET_BTC_SWAP_BECH32_PAYMENT_ACTIVATION_HEIGHT);
        assert!(resolved.is_none());
    }

    #[test]
    fn non_mainnet_uses_btc_swap_bech32_payment_env_override() {
        let _env = crate::test_env::guard();
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("IRIUM_BTC_SWAP_BECH32_PAYMENT_ACTIVATION_HEIGHT", "55");
        assert_eq!(
            resolved_btc_swap_bech32_payment_activation_height(NetworkKind::Devnet),
            Some(55)
        );
        assert_eq!(
            resolved_btc_swap_bech32_payment_activation_height(NetworkKind::Testnet),
            Some(55)
        );
        std::env::remove_var("IRIUM_BTC_SWAP_BECH32_PAYMENT_ACTIVATION_HEIGHT");
    }

    /// Batch 1 / D2: the `*_required()` functions hardcode `true` for mainnet, so
    /// enforcement arms with ZERO operator configuration once the height gate is open.
    /// Lives here (not in `mainnet_gate_truth`) because it mutates env and must share
    /// this module's `env_lock`.
    #[test]
    fn poawx_required_flags_are_hardcoded_true_on_mainnet() {
        let _env = crate::test_env::guard();
        let _g = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "mainnet");
        assert!(crate::poawx_dominance::anti_domination_required());
        assert!(crate::poawx_puzzle::puzzle_work_required());
        assert!(crate::poawx_finality::finality_committee_required());
        assert!(crate::poawx_admission::candidate_admission_required());
        assert!(crate::poawx_candidate::candidate_set_required());
        assert!(crate::poawx_penalty::penalty_state_required());
        assert!(crate::poawx_proposer::proposer_vrf_required());
        // Tickets are the one genuine exception: proofs stay off on mainnet.
        assert!(!crate::poawx_ticket::tickets_required());
        std::env::remove_var("IRIUM_NETWORK");
    }

}

/// Mainnet gate truth.
///
/// Every gate that routes through [`poawx_effective_activation`] IGNORES the env on
/// `network_id == 0` and substitutes the compiled `MAINNET_POAWX_ACTIVATION_HEIGHT`
/// (`Some(50_000)`). Mainnet passed that height long ago, so those gates are ACTIVE in
/// production right now.
///
/// This module exists because that was not true of the test suite. Every per-module gate
/// test asserted "mainnet hard-off" while probing heights 1, 5, 10 or 100 — all below
/// 50,000 — so they passed by accident of fixture height and certified the opposite of
/// production behaviour. These tests pin the REAL behaviour at REAL mainnet heights.
///
/// All assertions are param-driven (the network id is passed, not read from env), so this
/// module is race-free and needs no env lock.
#[cfg(test)]
mod mainnet_gate_truth {
    use super::*;

    /// A height comfortably past the mainnet activation, and past the live tip.
    const MAINNET_LIVE: u64 = 60_000;

    #[test]
    fn effective_activation_ignores_env_on_mainnet() {
        let _env = crate::test_env::guard();
        assert_eq!(MAINNET_POAWX_ACTIVATION_HEIGHT, Some(50_000));
        // Whatever the env says, mainnet gets the compiled height.
        for env in [None, Some(1u64), Some(u64::MAX)] {
            assert_eq!(
                poawx_effective_activation(0, env),
                MAINNET_POAWX_ACTIVATION_HEIGHT,
                "mainnet must ignore the env activation ({env:?})"
            );
        }
        // Non-mainnet uses the env value verbatim.
        assert_eq!(poawx_effective_activation(2, Some(7)), Some(7));
        assert_eq!(poawx_effective_activation(2, None), None);
    }

    /// The load-bearing test: every gate routed through `poawx_effective_activation` is ON
    /// at a live mainnet height. If any of these ever flips to `false`, a consensus rule
    /// that mainnet is currently enforcing has been silently disabled.
    #[test]
    fn every_routed_gate_is_on_at_a_live_mainnet_height() {
        let _env = crate::test_env::guard();
        let h = MAINNET_LIVE;
        let gates: [(&str, bool); 10] = [
            ("anti_domination", crate::poawx_dominance::anti_domination_gate(0, None, h)),
            ("puzzle_work", crate::poawx_puzzle::puzzle_work_gate(0, None, h)),
            ("finality_committee", crate::poawx_finality::finality_committee_gate(0, None, h)),
            ("adaptive_mode", crate::poawx_adaptive::adaptive_mode_gate(0, None, h)),
            ("fraud_proof", crate::poawx_challenge::fraud_proof_gate(0, None, h)),
            ("penalty_state", crate::poawx_penalty::penalty_gate(0, None, h)),
            ("multisource_seed", crate::poawx_committed_admission::multisource_seed_gate(0, None, h)),
            ("phase21d", crate::poawx_candidate::poawx_phase21d_gate(0, None, h)),
            ("proposer_vrf", crate::poawx_proposer::proposer_vrf_gate(0, None, h)),
            ("fork_choice_hardening", crate::poawx_proposer::fork_choice_hardening_gate(0, None, h)),
        ];
        let off: Vec<&str> = gates.iter().filter(|(_, v)| !*v).map(|(n, _)| *n).collect();
        assert!(
            off.is_empty(),
            "these gates are ENFORCING on mainnet today but the code says otherwise: {off:?}"
        );
    }

    /// The activation boundary is exactly 50,000 — off below, on at and above.
    #[test]
    fn mainnet_activation_boundary_is_exact() {
        let _env = crate::test_env::guard();
        assert!(!crate::poawx_dominance::anti_domination_gate(0, None, 49_999));
        assert!(crate::poawx_dominance::anti_domination_gate(0, None, 50_000));
        assert!(!crate::poawx_puzzle::puzzle_work_gate(0, None, 49_999));
        assert!(crate::poawx_puzzle::puzzle_work_gate(0, None, 50_000));
        assert!(!crate::poawx_finality::finality_committee_gate(0, None, 49_999));
        assert!(crate::poawx_finality::finality_committee_gate(0, None, 50_000));
        assert!(!crate::poawx_proposer::proposer_vrf_gate(0, None, 49_999));
        assert!(crate::poawx_proposer::proposer_vrf_gate(0, None, 50_000));
    }

    /// CONTRAST with the `poawx_effective_activation`-routed gates: PoW demotion reads its OWN
    /// compiled const, so no ENV can enable or disable it on mainnet. RECONCILED 2026-07-24: that
    /// const is the combined deploy knob (`MAINNET_COMBINED_ACTIVATION_HEIGHT = Some(61_414)`, LIVE
    /// since v1.9.133 2026-07-23) — so demotion is OFF below 61,414 and ON at/after, always
    /// env-independent. (`MAINNET_LIVE` = 60,000 here predates that activation, so demotion is still
    /// off at it; the env-independence invariant is what this pins.)
    #[test]
    fn pow_demotion_reads_its_own_const_env_ignored() {
        let _env = crate::test_env::guard();
        assert_eq!(
            crate::poawx_proposer::MAINNET_POW_DEMOTION_ACTIVATION_HEIGHT,
            MAINNET_COMBINED_ACTIVATION_HEIGHT
        );
        let c = MAINNET_COMBINED_ACTIVATION_HEIGHT.expect("combined knob set");
        // env is IRRELEVANT on mainnet at every height: Some(1) and None agree.
        for h in [0u64, 49_999, 50_000, MAINNET_LIVE, c - 1, c, u64::MAX] {
            assert_eq!(
                crate::poawx_proposer::pow_demotion_gate(0, Some(1), h),
                crate::poawx_proposer::pow_demotion_gate(0, None, h),
                "demotion ignores env at every mainnet height (h={h})"
            );
        }
        // Const boundary: off just below the activation, on at/after it (env irrelevant).
        assert!(!crate::poawx_proposer::pow_demotion_gate(0, None, c - 1));
        assert!(crate::poawx_proposer::pow_demotion_gate(0, None, c));
    }
}
