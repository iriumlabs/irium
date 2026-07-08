use crate::pow::sha256d;
use hex::FromHex;

pub const HTLC_V1_SCRIPT_TAG: u8 = 0xc0;
pub const HTLC_V1_VERSION: u8 = 1;
pub const HTLC_V1_HASHALG_SHA256: u8 = 1;
pub const HTLC_V1_SCRIPT_LEN: usize = 83;

pub const HTLC_WITNESS_CLAIM: u8 = 1;
pub const HTLC_WITNESS_REFUND: u8 = 2;

pub const MPSO_V1_TAG: u8 = 0xc1;
pub const MPSO_V1_MAX_SCRIPT_SIZE: usize = 640;
pub const MPSO_V1_MAX_WITNESS_SIZE: usize = 768;

pub const HTLC_BTC_SWAP_V1_TAG: u8 = 0xc3;
pub const HTLC_BTC_SWAP_V1_VERSION: u8 = 1;
pub const HTLC_BTC_SWAP_V1_SCRIPT_LEN: usize = 87;

/// Witness branch selectors inside the HtlcBtcSwapV1 namespace. These
/// reuse the 0x01/0x02 numeric values that HTLCv1 uses, but they live in
/// a separate parser (`parse_htlc_btc_swap_witness`) invoked only when the
/// output type has already been identified as HtlcBtcSwapV1.
pub const HTLC_BTC_SWAP_WITNESS_CLAIM: u8 = 1;
pub const HTLC_BTC_SWAP_WITNESS_REFUND: u8 = 2;

/// 6-byte ASCII magic prefixing the OP_RETURN binding payload an HtlcBtcSwap
/// payment must carry. Total OP_RETURN payload is `magic || funding_binding`
/// (14 bytes), well inside Bitcoin Core's 80-byte OP_RETURN standardness limit.
pub const BTC_OP_RETURN_BINDING_MAGIC: [u8; 6] = *b"irmswp";
pub const BTC_OP_RETURN_BINDING_LEN: usize = 14;

/// Bounds on `confirmations_required` in an HtlcBtcSwapV1 output. 1 is the
/// loose-trust minimum (one BTC confirmation); 144 is roughly one day at
/// BTC's 10-minute target, more than enough margin for reorg safety.
pub const MIN_HTLC_BTC_SWAP_CONFIRMATIONS: u8 = 1;
pub const MAX_HTLC_BTC_SWAP_CONFIRMATIONS: u8 = 144;

// ---- HtlcLtcSwapV1 (Phase C) — mirrors HtlcBtcSwapV1 with LTC payment side ----

pub const HTLC_LTC_SWAP_V1_TAG: u8 = 0xc7;
pub const HTLC_LTC_SWAP_V1_VERSION: u8 = 1;
pub const HTLC_LTC_SWAP_V1_SCRIPT_LEN: usize = 87;

/// Witness branch selectors inside the HtlcLtcSwapV1 namespace. Mirror
/// HtlcBtcSwapV1's selectors numerically; the parser (`parse_htlc_ltc_swap_witness`)
/// is only invoked once the output type has already been identified as
/// HtlcLtcSwapV1 so there is no clash.
pub const HTLC_LTC_SWAP_WITNESS_CLAIM: u8 = 1;
pub const HTLC_LTC_SWAP_WITNESS_REFUND: u8 = 2;

/// 6-byte ASCII magic prefixing the OP_RETURN binding payload on an
/// HtlcLtcSwap LTC payment. **Distinct from BTC's `irmswp`** so a
/// payment intended for one chain cannot satisfy a claim on the other.
pub const LTC_OP_RETURN_BINDING_MAGIC: [u8; 6] = *b"irmlsw"; // irium-litecoin-swap
pub const LTC_OP_RETURN_BINDING_LEN: usize = 14;

/// Bounds on `confirmations_required` in an HtlcLtcSwapV1 output.
/// 1 is the loose-trust minimum (one LTC confirmation); 144 covers ~6
/// hours at LTC's 2.5-minute target, plenty for reorg safety.
pub const MIN_HTLC_LTC_SWAP_CONFIRMATIONS: u8 = 1;
pub const MAX_HTLC_LTC_SWAP_CONFIRMATIONS: u8 = 144;

// ---- LtcSwapOrder (Phase D) — mirrors SwapOrder with LTC payment side ----

pub const LTC_SWAP_ORDER_V1_TAG: u8 = 0xc8;
pub const LTC_SWAP_ORDER_V1_VERSION: u8 = 1;
pub const LTC_SWAP_ORDER_DIRECTION_SELL: u8 = 0x01;
pub const LTC_SWAP_ORDER_DIRECTION_BUY: u8 = 0x02;
pub const LTC_SWAP_ORDER_SELL_SCRIPT_LEN: usize = 76;
pub const LTC_SWAP_ORDER_BUY_SCRIPT_LEN: usize = 108;

/// Witness branch selectors inside the LtcSwapOrder namespace. Numeric
/// values match the BTC SwapOrder selectors but parser dispatch happens
/// only after the output type has been identified as LtcSwapOrder, so
/// there is no collision with SwapOrder's same-numbered branches.
pub const LTC_SWAP_ORDER_WITNESS_FILL: u8 = 0x01;
pub const LTC_SWAP_ORDER_WITNESS_CANCEL: u8 = 0x02;
pub const LTC_SWAP_ORDER_WITNESS_EXPIRE_SWEEP: u8 = 0x03;

/// Floor on an LtcSwapOrder output's locked value, identical to the BTC
/// SwapOrder floor. Sell-IRM orders lock the full irm_amount and almost
/// always exceed this; buy-IRM orders use a small anti-spam value that
/// must still leave room for `LTC_SWAP_ORDER_MAX_SWEEP_FEE`.
pub const LTC_SWAP_ORDER_MIN_LOCKED_VALUE: u64 = 1100;

/// Maximum gap (in sats) between the LtcSwapOrder UTXO's value and the
/// expire-sweep output's value. Mirrors the BTC SwapOrder ceiling.
pub const LTC_SWAP_ORDER_MAX_SWEEP_FEE: u64 = 1000;

pub const SWAP_ORDER_V1_TAG: u8 = 0xc5;
pub const SWAP_ORDER_V1_VERSION: u8 = 1;
pub const SWAP_ORDER_DIRECTION_SELL: u8 = 0x01;
pub const SWAP_ORDER_DIRECTION_BUY: u8 = 0x02;
pub const SWAP_ORDER_SELL_SCRIPT_LEN: usize = 76;
pub const SWAP_ORDER_BUY_SCRIPT_LEN: usize = 108;

/// Witness branch selectors inside the SwapOrder namespace. Parsed only
/// from inside the SwapOrder match arm of `verify_transaction_signature`
/// via `parse_swap_order_witness`, so the numeric values do not collide
/// with HTLCv1's or HtlcBtcSwapV1's same-numbered branches.
pub const SWAP_ORDER_WITNESS_FILL: u8 = 0x01;
pub const SWAP_ORDER_WITNESS_CANCEL: u8 = 0x02;
pub const SWAP_ORDER_WITNESS_EXPIRE_SWEEP: u8 = 0x03;

/// Floor on a SwapOrder output's locked value. Sell-IRM orders lock the
/// full irm_amount and almost always exceed this; buy-IRM orders use a
/// small anti-spam value and must clear the same floor so an expire-sweep
/// has room for `SWAP_ORDER_MAX_SWEEP_FEE`.
pub const SWAP_ORDER_MIN_LOCKED_VALUE: u64 = 1100;

/// Maximum gap (in sats) between the SwapOrder UTXO's value and the
/// expire-sweep payout to the maker. The gap becomes block-miner tx fee,
/// compensating whoever broadcasts the sweep.
pub const SWAP_ORDER_MAX_SWEEP_FEE: u64 = 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxInput {
    pub prev_txid: [u8; 32],
    pub prev_index: u32,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

impl TxInput {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 32 + 4 + 1 + self.script_sig.len() + 4);
        out.push(self.prev_txid.len() as u8);
        out.extend_from_slice(&self.prev_txid);
        out.extend_from_slice(&self.prev_index.to_le_bytes());
        out.push(self.script_sig.len() as u8);
        out.extend_from_slice(&self.script_sig);
        out.extend_from_slice(&self.sequence.to_le_bytes());
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOutput {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

impl TxOutput {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 3 + self.script_pubkey.len());
        out.extend_from_slice(&self.value.to_le_bytes());
        // Bitcoin-style varint script length. Bug fix: previously u8 cast
        // truncated script_pubkey.len() for outputs longer than 255 bytes
        // (BtcHeaderBatch, large MPSO, etc.), corrupting the serialized tx
        // and breaking signature verification on the block-connect path.
        // Backward-compatible: varint encoding for n < 253 is identical to
        // a single-byte u8, so existing short-script txs serialize identically.
        write_varint(&mut out, self.script_pubkey.len());
        out.extend_from_slice(&self.script_pubkey);
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub version: u32,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub locktime: u32,
}

impl Transaction {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_le_bytes());
        out.push(self.inputs.len() as u8);
        for inp in &self.inputs {
            out.extend_from_slice(&inp.serialize());
        }
        out.push(self.outputs.len() as u8);
        for outp in &self.outputs {
            out.extend_from_slice(&outp.serialize());
        }
        out.extend_from_slice(&self.locktime.to_le_bytes());
        out
    }

    pub fn txid(&self) -> [u8; 32] {
        let ser = self.serialize();
        let mut h = sha256d(&ser);
        h.reverse();
        h
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HtlcV1Output {
    pub expected_hash: [u8; 32],
    pub recipient_pkh: [u8; 20],
    pub refund_pkh: [u8; 20],
    pub timeout_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MpsoV1Output {
    pub flags: u8,
    pub claim_n: u8,
    pub claim_m: u8,
    pub refund_n: u8,
    pub refund_m: u8,
    pub agreement_hash: [u8; 32],
    pub claim_pubkeys: Vec<[u8; 33]>,
    pub refund_pubkeys: Vec<[u8; 33]>,
    pub timeout_height: u64,
    pub optional_hash: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HtlcBtcSwapV1Output {
    pub confirmations_required: u8,
    pub recipient_pkh: [u8; 20],
    pub refund_pkh: [u8; 20],
    pub btc_recipient_pkh: [u8; 20],
    pub btc_amount_sats: u64,
    pub timeout_height: u64,
    pub funding_binding: [u8; 8],
}

/// HtlcLtcSwapV1 output (Phase C). Same layout as HtlcBtcSwapV1, just
/// referencing the LTC payment side. The 8-byte funding_binding is
/// computed identically (`compute_funding_binding` is chain-agnostic),
/// and the LTC OP_RETURN payload uses `LTC_OP_RETURN_BINDING_MAGIC`
/// instead of BTC's magic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HtlcLtcSwapV1Output {
    pub confirmations_required: u8,
    pub recipient_pkh: [u8; 20],
    pub refund_pkh: [u8; 20],
    pub ltc_recipient_pkh: [u8; 20],
    pub ltc_amount_sats: u64,
    pub timeout_height: u64,
    pub funding_binding: [u8; 8],
}

/// SwapOrder lifecycle object: on-chain advertised offer to swap IRM<->BTC.
/// Sell-IRM (`direction=0x01`) outputs lock `irm_amount` for a taker to
/// claim via a covenant-enforced HtlcBtcSwapV1 fill. Buy-IRM
/// (`direction=0x02`) outputs lock anti-spam value and carry the
/// maker-chosen `expected_hash` hashlock commitment in the script tail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapOrderOutput {
    pub direction: u8,
    pub confirmations_required: u8,
    pub irm_amount: u64,
    pub btc_amount_sats: u64,
    pub maker_iriumd_pkh: [u8; 20],
    pub maker_btc_pkh: [u8; 20],
    pub expiry_height: u64,
    pub order_id: [u8; 8],
    /// Some only when `direction == SWAP_ORDER_DIRECTION_BUY`. Consensus
    /// enforces the option-tail relationship via strict script length:
    /// 76 bytes for sell, 108 bytes for buy.
    pub expected_hash: Option<[u8; 32]>,
}

/// LtcSwapOrder lifecycle object (Phase D). Same on-chain shape as
/// `SwapOrderOutput`, just LTC payment side. Sell-IRM fills emit
/// `HtlcLtcSwapV1` outputs (not `HtlcBtcSwapV1`); buy-IRM fills emit
/// HTLCv1 outputs identical to the BTC SwapOrder buy-fill — the IRM
/// hashlock is chain-agnostic and the off-chain LTC HTLC dance is the
/// maker's responsibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LtcSwapOrderOutput {
    pub direction: u8,
    pub confirmations_required: u8,
    pub irm_amount: u64,
    pub ltc_amount_sats: u64,
    pub maker_iriumd_pkh: [u8; 20],
    pub maker_ltc_pkh: [u8; 20],
    pub expiry_height: u64,
    pub order_id: [u8; 8],
    /// Some only when `direction == LTC_SWAP_ORDER_DIRECTION_BUY`.
    /// Consensus enforces the option-tail relationship via strict script
    /// length: 76 bytes for sell, 108 bytes for buy.
    pub expected_hash: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputEncumbrance {
    P2pkh([u8; 20]),
    HtlcV1(HtlcV1Output),
    MpsoV1(MpsoV1Output),
    HtlcBtcSwapV1(HtlcBtcSwapV1Output),
    HtlcLtcSwapV1(HtlcLtcSwapV1Output),
    SwapOrder(SwapOrderOutput),
    LtcSwapOrder(LtcSwapOrderOutput),
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwapOrderWitness {
    /// Sell-IRM fill: taker creates an HtlcBtcSwapV1 in output 0 of the
    /// spending tx. The validator covenant enforces the exact script.
    FillSell {
        sig: Vec<u8>,
        pubkey: Vec<u8>,
        taker_iriumd_pkh: [u8; 20],
        timeout_height: u64,
    },
    /// Buy-IRM fill: taker creates an HTLCv1 in output 0 with the
    /// order's hashlock and the maker as recipient.
    FillBuy {
        sig: Vec<u8>,
        pubkey: Vec<u8>,
        irm_timeout_height: u64,
    },
    /// Maker reclaims the locked value before expiry. No covenant.
    Cancel { sig: Vec<u8>, pubkey: Vec<u8> },
    /// Anyone may sweep an expired order. Covenant: output 0 returns
    /// (locked_value - max_sweep_fee) to the maker via P2PKH.
    ExpireSweep,
}

/// LtcSwapOrder witness branches. Byte-level mirror of `SwapOrderWitness`
/// — selector numbers and field shapes are identical. The sell-fill
/// covenant builds an `HtlcLtcSwapV1` output (not BTC); the buy-fill
/// covenant builds an `HtlcV1` output (chain-agnostic preimage hashlock,
/// same as the BTC SwapOrder buy-fill).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LtcSwapOrderWitness {
    FillSell {
        sig: Vec<u8>,
        pubkey: Vec<u8>,
        taker_iriumd_pkh: [u8; 20],
        timeout_height: u64,
    },
    FillBuy {
        sig: Vec<u8>,
        pubkey: Vec<u8>,
        irm_timeout_height: u64,
    },
    Cancel { sig: Vec<u8>, pubkey: Vec<u8> },
    ExpireSweep,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HtlcBtcSwapWitness {
    Claim {
        sig: Vec<u8>,
        pubkey: Vec<u8>,
        btc_block_hash: [u8; 32],
        btc_merkle_branch: Vec<[u8; 32]>,
        btc_merkle_index: u32,
        btc_tx_raw: Vec<u8>,
    },
    Refund {
        sig: Vec<u8>,
        pubkey: Vec<u8>,
    },
}

/// HtlcLtcSwapV1 witness branches. Mirrors HtlcBtcSwapWitness — the LTC
/// payment proof is structurally identical (sha256d Merkle tree, same
/// branch encoding, same P2PKH-style payment recognition).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HtlcLtcSwapWitness {
    Claim {
        sig: Vec<u8>,
        pubkey: Vec<u8>,
        ltc_block_hash: [u8; 32],
        ltc_merkle_branch: Vec<[u8; 32]>,
        ltc_merkle_index: u32,
        ltc_tx_raw: Vec<u8>,
    },
    Refund {
        sig: Vec<u8>,
        pubkey: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputWitness {
    P2pkh {
        sig: Vec<u8>,
        pubkey: Vec<u8>,
    },
    HtlcClaim {
        sig: Vec<u8>,
        pubkey: Vec<u8>,
        preimage: Vec<u8>,
    },
    HtlcRefund {
        sig: Vec<u8>,
        pubkey: Vec<u8>,
    },
    Unknown,
}

#[allow(dead_code)] // P2PKH script builder; used by wallet and test utilities
pub fn p2pkh_script(pkh: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(25);
    script.push(0x76);
    script.push(0xa9);
    script.push(0x14);
    script.extend_from_slice(pkh);
    script.push(0x88);
    script.push(0xac);
    script
}

pub fn parse_p2pkh_script(script: &[u8]) -> Option<[u8; 20]> {
    if script.len() != 25 {
        return None;
    }
    if script[0] != 0x76 || script[1] != 0xa9 || script[2] != 0x14 {
        return None;
    }
    if script[23] != 0x88 || script[24] != 0xac {
        return None;
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&script[3..23]);
    Some(out)
}

pub fn encode_htlcv1_script(output: &HtlcV1Output) -> Vec<u8> {
    let mut script = Vec::with_capacity(HTLC_V1_SCRIPT_LEN);
    script.push(HTLC_V1_SCRIPT_TAG);
    script.push(HTLC_V1_VERSION);
    script.push(HTLC_V1_HASHALG_SHA256);
    script.extend_from_slice(&output.expected_hash);
    script.extend_from_slice(&output.recipient_pkh);
    script.extend_from_slice(&output.refund_pkh);
    script.extend_from_slice(&output.timeout_height.to_le_bytes());
    script
}

pub fn parse_htlcv1_script(script: &[u8]) -> Option<HtlcV1Output> {
    if script.len() != HTLC_V1_SCRIPT_LEN {
        return None;
    }
    if script[0] != HTLC_V1_SCRIPT_TAG {
        return None;
    }
    if script[1] != HTLC_V1_VERSION {
        return None;
    }
    if script[2] != HTLC_V1_HASHALG_SHA256 {
        return None;
    }
    let mut expected_hash = [0u8; 32];
    expected_hash.copy_from_slice(&script[3..35]);
    let mut recipient_pkh = [0u8; 20];
    recipient_pkh.copy_from_slice(&script[35..55]);
    let mut refund_pkh = [0u8; 20];
    refund_pkh.copy_from_slice(&script[55..75]);
    let mut timeout_bytes = [0u8; 8];
    timeout_bytes.copy_from_slice(&script[75..83]);
    let timeout_height = u64::from_le_bytes(timeout_bytes);
    Some(HtlcV1Output {
        expected_hash,
        recipient_pkh,
        refund_pkh,
        timeout_height,
    })
}

pub fn encode_mpso_script(o: &MpsoV1Output) -> Vec<u8> {
    let secret_gate = o.flags & 0x01 != 0;
    let pubkey_bytes = (o.claim_n as usize + o.refund_n as usize) * 33;
    let total = 48 + pubkey_bytes + if secret_gate { 32 } else { 0 };
    let mut script = Vec::with_capacity(total);
    script.push(MPSO_V1_TAG);
    script.push(0x01);
    script.push(o.flags);
    script.push(0x00);
    script.push(o.claim_n);
    script.push(o.claim_m);
    script.push(o.refund_n);
    script.push(o.refund_m);
    script.extend_from_slice(&o.agreement_hash);
    for pk in &o.claim_pubkeys {
        script.extend_from_slice(pk.as_ref());
    }
    for pk in &o.refund_pubkeys {
        script.extend_from_slice(pk.as_ref());
    }
    script.extend_from_slice(&o.timeout_height.to_le_bytes());
    if let Some(h) = &o.optional_hash {
        script.extend_from_slice(h.as_ref());
    }
    script
}

pub fn parse_mpso_script(script: &[u8]) -> Option<MpsoV1Output> {
    if script.len() < 8 {
        return None;
    }
    if script[0] != MPSO_V1_TAG {
        return None;
    }
    if script[1] != 0x01 {
        return None;
    }
    let flags = script[2];
    if flags & 0xFE != 0 {
        return None;
    }
    if script[3] != 0x00 {
        return None;
    }
    let claim_n = script[4];
    let claim_m = script[5];
    let refund_n = script[6];
    let refund_m = script[7];
    if !(1..=8).contains(&claim_n) {
        return None;
    }
    if claim_m < 1 || claim_m > claim_n {
        return None;
    }
    if !(1..=8).contains(&refund_n) {
        return None;
    }
    if refund_m < 1 || refund_m > refund_n {
        return None;
    }
    let secret_gate = flags & 0x01 != 0;
    let expected_len =
        48 + (claim_n as usize + refund_n as usize) * 33 + if secret_gate { 32 } else { 0 };
    if script.len() != expected_len {
        return None;
    }
    if script.len() > MPSO_V1_MAX_SCRIPT_SIZE {
        return None;
    }
    let mut agreement_hash = [0u8; 32];
    agreement_hash.copy_from_slice(&script[8..40]);
    let mut claim_pubkeys: Vec<[u8; 33]> = Vec::with_capacity(claim_n as usize);
    let mut pos = 40usize;
    for _ in 0..claim_n {
        if script[pos] != 0x02 && script[pos] != 0x03 {
            return None;
        }
        let mut pk = [0u8; 33];
        pk.copy_from_slice(&script[pos..pos + 33]);
        claim_pubkeys.push(pk);
        pos += 33;
    }
    let mut refund_pubkeys: Vec<[u8; 33]> = Vec::with_capacity(refund_n as usize);
    for _ in 0..refund_n {
        if script[pos] != 0x02 && script[pos] != 0x03 {
            return None;
        }
        let mut pk = [0u8; 33];
        pk.copy_from_slice(&script[pos..pos + 33]);
        refund_pubkeys.push(pk);
        pos += 33;
    }
    for i in 0..claim_pubkeys.len() {
        for j in (i + 1)..claim_pubkeys.len() {
            if claim_pubkeys[i] == claim_pubkeys[j] {
                return None;
            }
        }
    }
    for i in 0..refund_pubkeys.len() {
        for j in (i + 1)..refund_pubkeys.len() {
            if refund_pubkeys[i] == refund_pubkeys[j] {
                return None;
            }
        }
    }
    let mut timeout_bytes = [0u8; 8];
    timeout_bytes.copy_from_slice(&script[pos..pos + 8]);
    let timeout_height = u64::from_le_bytes(timeout_bytes);
    pos += 8;
    let optional_hash = if secret_gate {
        let mut h = [0u8; 32];
        h.copy_from_slice(&script[pos..pos + 32]);
        Some(h)
    } else {
        None
    };
    Some(MpsoV1Output {
        flags,
        claim_n,
        claim_m,
        refund_n,
        refund_m,
        agreement_hash,
        claim_pubkeys,
        refund_pubkeys,
        timeout_height,
        optional_hash,
    })
}

pub fn parse_output_encumbrance(script: &[u8]) -> OutputEncumbrance {
    if let Some(pkh) = parse_p2pkh_script(script) {
        return OutputEncumbrance::P2pkh(pkh);
    }
    if let Some(htlc) = parse_htlcv1_script(script) {
        return OutputEncumbrance::HtlcV1(htlc);
    }
    if let Some(mpso) = parse_mpso_script(script) {
        return OutputEncumbrance::MpsoV1(mpso);
    }
    if let Some(swap) = parse_htlc_btc_swap_v1_script(script) {
        return OutputEncumbrance::HtlcBtcSwapV1(swap);
    }
    if let Some(swap) = parse_htlc_ltc_swap_v1_script(script) {
        return OutputEncumbrance::HtlcLtcSwapV1(swap);
    }
    if let Some(order) = parse_swap_order_script(script) {
        return OutputEncumbrance::SwapOrder(order);
    }
    if let Some(order) = parse_ltc_swap_order_script(script) {
        return OutputEncumbrance::LtcSwapOrder(order);
    }
    OutputEncumbrance::Unknown
}

pub fn encode_htlc_btc_swap_v1_script(o: &HtlcBtcSwapV1Output) -> Vec<u8> {
    let mut s = Vec::with_capacity(HTLC_BTC_SWAP_V1_SCRIPT_LEN);
    s.push(HTLC_BTC_SWAP_V1_TAG);
    s.push(HTLC_BTC_SWAP_V1_VERSION);
    s.push(o.confirmations_required);
    s.extend_from_slice(&o.recipient_pkh);
    s.extend_from_slice(&o.refund_pkh);
    s.extend_from_slice(&o.btc_recipient_pkh);
    s.extend_from_slice(&o.btc_amount_sats.to_le_bytes());
    s.extend_from_slice(&o.timeout_height.to_le_bytes());
    s.extend_from_slice(&o.funding_binding);
    s
}

pub fn parse_htlc_btc_swap_v1_script(script: &[u8]) -> Option<HtlcBtcSwapV1Output> {
    if script.len() != HTLC_BTC_SWAP_V1_SCRIPT_LEN {
        return None;
    }
    if script[0] != HTLC_BTC_SWAP_V1_TAG {
        return None;
    }
    if script[1] != HTLC_BTC_SWAP_V1_VERSION {
        return None;
    }
    let confirmations_required = script[2];
    let mut recipient_pkh = [0u8; 20];
    recipient_pkh.copy_from_slice(&script[3..23]);
    let mut refund_pkh = [0u8; 20];
    refund_pkh.copy_from_slice(&script[23..43]);
    let mut btc_recipient_pkh = [0u8; 20];
    btc_recipient_pkh.copy_from_slice(&script[43..63]);
    let mut amount_bytes = [0u8; 8];
    amount_bytes.copy_from_slice(&script[63..71]);
    let btc_amount_sats = u64::from_le_bytes(amount_bytes);
    let mut timeout_bytes = [0u8; 8];
    timeout_bytes.copy_from_slice(&script[71..79]);
    let timeout_height = u64::from_le_bytes(timeout_bytes);
    let mut funding_binding = [0u8; 8];
    funding_binding.copy_from_slice(&script[79..87]);
    Some(HtlcBtcSwapV1Output {
        confirmations_required,
        recipient_pkh,
        refund_pkh,
        btc_recipient_pkh,
        btc_amount_sats,
        timeout_height,
        funding_binding,
    })
}

/// Deterministic binding tying an HtlcBtcSwapV1 output to its funding
/// outpoint. The first 8 bytes of `sha256d(txid || vout_le)` are stored
/// inside the script and must also appear (after the magic prefix) in the
/// BTC payment's OP_RETURN payload.
#[allow(dead_code)] // Phase 5 wallet/RPC path will compute this when funding HtlcBtcSwapV1
pub fn compute_funding_binding(funding_txid: &[u8; 32], vout: u32) -> [u8; 8] {
    let mut buf = [0u8; 36];
    buf[0..32].copy_from_slice(funding_txid);
    buf[32..36].copy_from_slice(&vout.to_le_bytes());
    let h = sha256d(&buf);
    let mut out = [0u8; 8];
    out.copy_from_slice(&h[..8]);
    out
}

#[allow(dead_code)] // Phase 5 RPC + wallet path will emit this witness
pub fn encode_htlc_btc_swap_claim_witness(
    sig: &[u8],
    pubkey: &[u8],
    btc_block_hash: &[u8; 32],
    btc_merkle_branch: &[[u8; 32]],
    btc_merkle_index: u32,
    btc_tx_raw: &[u8],
) -> Option<Vec<u8>> {
    if sig.is_empty() || sig.len() > 255 {
        return None;
    }
    if pubkey.is_empty() || pubkey.len() > 255 {
        return None;
    }
    if btc_merkle_branch.len() > u16::MAX as usize {
        return None;
    }
    if btc_tx_raw.is_empty() {
        return None;
    }
    let tx_len_varint = if btc_tx_raw.len() < 0xfd {
        1
    } else if btc_tx_raw.len() <= 0xffff {
        3
    } else if (btc_tx_raw.len() as u64) <= 0xffff_ffff {
        5
    } else {
        9
    };
    let cap = 1
        + 1
        + sig.len()
        + 1
        + pubkey.len()
        + 32
        + 2
        + btc_merkle_branch.len() * 32
        + 4
        + tx_len_varint
        + btc_tx_raw.len();
    let mut out = Vec::with_capacity(cap);
    out.push(HTLC_BTC_SWAP_WITNESS_CLAIM);
    out.push(sig.len() as u8);
    out.extend_from_slice(sig);
    out.push(pubkey.len() as u8);
    out.extend_from_slice(pubkey);
    out.extend_from_slice(btc_block_hash);
    out.extend_from_slice(&(btc_merkle_branch.len() as u16).to_le_bytes());
    for h in btc_merkle_branch {
        out.extend_from_slice(h);
    }
    out.extend_from_slice(&btc_merkle_index.to_le_bytes());
    write_varint(&mut out, btc_tx_raw.len());
    out.extend_from_slice(btc_tx_raw);
    Some(out)
}

#[allow(dead_code)] // Phase 5 RPC + wallet path will emit this witness
pub fn encode_htlc_btc_swap_refund_witness(sig: &[u8], pubkey: &[u8]) -> Option<Vec<u8>> {
    if sig.is_empty() || sig.len() > 255 || pubkey.is_empty() || pubkey.len() > 255 {
        return None;
    }
    let mut out = Vec::with_capacity(3 + sig.len() + pubkey.len());
    out.push(HTLC_BTC_SWAP_WITNESS_REFUND);
    out.push(sig.len() as u8);
    out.extend_from_slice(sig);
    out.push(pubkey.len() as u8);
    out.extend_from_slice(pubkey);
    Some(out)
}

pub fn write_varint(out: &mut Vec<u8>, n: usize) {
    if n < 0xfd {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if (n as u64) <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&(n as u64).to_le_bytes());
    }
}

pub fn read_varint_at(data: &[u8], offset: &mut usize) -> Option<u64> {
    if *offset >= data.len() {
        return None;
    }
    let first = data[*offset];
    *offset += 1;
    match first {
        0xff => {
            if *offset + 8 > data.len() {
                return None;
            }
            let mut b = [0u8; 8];
            b.copy_from_slice(&data[*offset..*offset + 8]);
            *offset += 8;
            Some(u64::from_le_bytes(b))
        }
        0xfe => {
            if *offset + 4 > data.len() {
                return None;
            }
            let mut b = [0u8; 4];
            b.copy_from_slice(&data[*offset..*offset + 4]);
            *offset += 4;
            Some(u32::from_le_bytes(b) as u64)
        }
        0xfd => {
            if *offset + 2 > data.len() {
                return None;
            }
            let mut b = [0u8; 2];
            b.copy_from_slice(&data[*offset..*offset + 2]);
            *offset += 2;
            Some(u16::from_le_bytes(b) as u64)
        }
        n => Some(n as u64),
    }
}

/// Parse a witness produced by `encode_htlc_btc_swap_claim_witness` or
/// `encode_htlc_btc_swap_refund_witness`. Returns `None` on any structural
/// error. Invoked only from inside the HtlcBtcSwapV1 arm of
/// `verify_transaction_signature`; never substitutes `parse_input_witness`
/// in the existing HTLCv1 / MPSOv1 / P2PKH code paths.
pub fn parse_htlc_btc_swap_witness(script_sig: &[u8]) -> Option<HtlcBtcSwapWitness> {
    if script_sig.is_empty() {
        return None;
    }
    match script_sig[0] {
        HTLC_BTC_SWAP_WITNESS_CLAIM => {
            let mut off: usize = 1;
            let sig_len = *script_sig.get(off)? as usize;
            off += 1;
            if sig_len == 0 || off + sig_len > script_sig.len() {
                return None;
            }
            let sig = script_sig[off..off + sig_len].to_vec();
            off += sig_len;
            let pk_len = *script_sig.get(off)? as usize;
            off += 1;
            if pk_len == 0 || off + pk_len > script_sig.len() {
                return None;
            }
            let pubkey = script_sig[off..off + pk_len].to_vec();
            off += pk_len;
            if off + 32 > script_sig.len() {
                return None;
            }
            let mut btc_block_hash = [0u8; 32];
            btc_block_hash.copy_from_slice(&script_sig[off..off + 32]);
            off += 32;
            if off + 2 > script_sig.len() {
                return None;
            }
            let branch_len =
                u16::from_le_bytes(script_sig[off..off + 2].try_into().ok()?) as usize;
            off += 2;
            if branch_len > 32 {
                // Bitcoin Merkle proofs above depth 32 are nonsensical (would
                // imply > 4 billion txs per block).
                return None;
            }
            if off + branch_len * 32 > script_sig.len() {
                return None;
            }
            let mut btc_merkle_branch: Vec<[u8; 32]> = Vec::with_capacity(branch_len);
            for _ in 0..branch_len {
                let mut h = [0u8; 32];
                h.copy_from_slice(&script_sig[off..off + 32]);
                btc_merkle_branch.push(h);
                off += 32;
            }
            if off + 4 > script_sig.len() {
                return None;
            }
            let btc_merkle_index =
                u32::from_le_bytes(script_sig[off..off + 4].try_into().ok()?);
            off += 4;
            let tx_len = read_varint_at(script_sig, &mut off)? as usize;
            if tx_len == 0 || tx_len > 1_000_000 || off + tx_len != script_sig.len() {
                return None;
            }
            let btc_tx_raw = script_sig[off..off + tx_len].to_vec();
            Some(HtlcBtcSwapWitness::Claim {
                sig,
                pubkey,
                btc_block_hash,
                btc_merkle_branch,
                btc_merkle_index,
                btc_tx_raw,
            })
        }
        HTLC_BTC_SWAP_WITNESS_REFUND => {
            let mut off: usize = 1;
            let sig_len = *script_sig.get(off)? as usize;
            off += 1;
            if sig_len == 0 || off + sig_len > script_sig.len() {
                return None;
            }
            let sig = script_sig[off..off + sig_len].to_vec();
            off += sig_len;
            let pk_len = *script_sig.get(off)? as usize;
            off += 1;
            if pk_len == 0 || off + pk_len != script_sig.len() {
                return None;
            }
            let pubkey = script_sig[off..off + pk_len].to_vec();
            Some(HtlcBtcSwapWitness::Refund { sig, pubkey })
        }
        _ => None,
    }
}

// ---- HtlcLtcSwapV1 script + witness codecs (Phase C) ----
// Byte-level mirror of the HtlcBtcSwap codecs above; the only structural
// difference is the script tag (0xc7 vs 0xc3) and the chain identifier
// in field names. `compute_funding_binding` is shared.

pub fn encode_htlc_ltc_swap_v1_script(o: &HtlcLtcSwapV1Output) -> Vec<u8> {
    let mut s = Vec::with_capacity(HTLC_LTC_SWAP_V1_SCRIPT_LEN);
    s.push(HTLC_LTC_SWAP_V1_TAG);
    s.push(HTLC_LTC_SWAP_V1_VERSION);
    s.push(o.confirmations_required);
    s.extend_from_slice(&o.recipient_pkh);
    s.extend_from_slice(&o.refund_pkh);
    s.extend_from_slice(&o.ltc_recipient_pkh);
    s.extend_from_slice(&o.ltc_amount_sats.to_le_bytes());
    s.extend_from_slice(&o.timeout_height.to_le_bytes());
    s.extend_from_slice(&o.funding_binding);
    s
}

pub fn parse_htlc_ltc_swap_v1_script(script: &[u8]) -> Option<HtlcLtcSwapV1Output> {
    if script.len() != HTLC_LTC_SWAP_V1_SCRIPT_LEN {
        return None;
    }
    if script[0] != HTLC_LTC_SWAP_V1_TAG {
        return None;
    }
    if script[1] != HTLC_LTC_SWAP_V1_VERSION {
        return None;
    }
    let confirmations_required = script[2];
    let mut recipient_pkh = [0u8; 20];
    recipient_pkh.copy_from_slice(&script[3..23]);
    let mut refund_pkh = [0u8; 20];
    refund_pkh.copy_from_slice(&script[23..43]);
    let mut ltc_recipient_pkh = [0u8; 20];
    ltc_recipient_pkh.copy_from_slice(&script[43..63]);
    let mut amount_bytes = [0u8; 8];
    amount_bytes.copy_from_slice(&script[63..71]);
    let ltc_amount_sats = u64::from_le_bytes(amount_bytes);
    let mut timeout_bytes = [0u8; 8];
    timeout_bytes.copy_from_slice(&script[71..79]);
    let timeout_height = u64::from_le_bytes(timeout_bytes);
    let mut funding_binding = [0u8; 8];
    funding_binding.copy_from_slice(&script[79..87]);
    Some(HtlcLtcSwapV1Output {
        confirmations_required,
        recipient_pkh,
        refund_pkh,
        ltc_recipient_pkh,
        ltc_amount_sats,
        timeout_height,
        funding_binding,
    })
}

#[allow(dead_code)] // Phase C RPC + wallet path will emit this witness
pub fn encode_htlc_ltc_swap_claim_witness(
    sig: &[u8],
    pubkey: &[u8],
    ltc_block_hash: &[u8; 32],
    ltc_merkle_branch: &[[u8; 32]],
    ltc_merkle_index: u32,
    ltc_tx_raw: &[u8],
) -> Option<Vec<u8>> {
    if sig.is_empty() || sig.len() > 255 {
        return None;
    }
    if pubkey.is_empty() || pubkey.len() > 255 {
        return None;
    }
    if ltc_merkle_branch.len() > u16::MAX as usize {
        return None;
    }
    if ltc_tx_raw.is_empty() {
        return None;
    }
    let tx_len_varint = if ltc_tx_raw.len() < 0xfd {
        1
    } else if ltc_tx_raw.len() <= 0xffff {
        3
    } else if (ltc_tx_raw.len() as u64) <= 0xffff_ffff {
        5
    } else {
        9
    };
    let cap = 1
        + 1
        + sig.len()
        + 1
        + pubkey.len()
        + 32
        + 2
        + ltc_merkle_branch.len() * 32
        + 4
        + tx_len_varint
        + ltc_tx_raw.len();
    let mut out = Vec::with_capacity(cap);
    out.push(HTLC_LTC_SWAP_WITNESS_CLAIM);
    out.push(sig.len() as u8);
    out.extend_from_slice(sig);
    out.push(pubkey.len() as u8);
    out.extend_from_slice(pubkey);
    out.extend_from_slice(ltc_block_hash);
    out.extend_from_slice(&(ltc_merkle_branch.len() as u16).to_le_bytes());
    for h in ltc_merkle_branch {
        out.extend_from_slice(h);
    }
    out.extend_from_slice(&ltc_merkle_index.to_le_bytes());
    write_varint(&mut out, ltc_tx_raw.len());
    out.extend_from_slice(ltc_tx_raw);
    Some(out)
}

#[allow(dead_code)] // Phase C RPC + wallet path will emit this witness
pub fn encode_htlc_ltc_swap_refund_witness(sig: &[u8], pubkey: &[u8]) -> Option<Vec<u8>> {
    if sig.is_empty() || sig.len() > 255 || pubkey.is_empty() || pubkey.len() > 255 {
        return None;
    }
    let mut out = Vec::with_capacity(3 + sig.len() + pubkey.len());
    out.push(HTLC_LTC_SWAP_WITNESS_REFUND);
    out.push(sig.len() as u8);
    out.extend_from_slice(sig);
    out.push(pubkey.len() as u8);
    out.extend_from_slice(pubkey);
    Some(out)
}

/// Parse the witness of a spend against an HtlcLtcSwapV1 output. Returns
/// `None` for any structural error. Invoked only from inside the
/// HtlcLtcSwapV1 arm of `verify_transaction_signature`; never substitutes
/// for the existing HTLCv1 / HtlcBtcSwapV1 / MPSOv1 / P2PKH parsers.
pub fn parse_htlc_ltc_swap_witness(script_sig: &[u8]) -> Option<HtlcLtcSwapWitness> {
    if script_sig.is_empty() {
        return None;
    }
    match script_sig[0] {
        HTLC_LTC_SWAP_WITNESS_CLAIM => {
            let mut off: usize = 1;
            let sig_len = *script_sig.get(off)? as usize;
            off += 1;
            if sig_len == 0 || off + sig_len > script_sig.len() {
                return None;
            }
            let sig = script_sig[off..off + sig_len].to_vec();
            off += sig_len;
            let pk_len = *script_sig.get(off)? as usize;
            off += 1;
            if pk_len == 0 || off + pk_len > script_sig.len() {
                return None;
            }
            let pubkey = script_sig[off..off + pk_len].to_vec();
            off += pk_len;
            if off + 32 > script_sig.len() {
                return None;
            }
            let mut ltc_block_hash = [0u8; 32];
            ltc_block_hash.copy_from_slice(&script_sig[off..off + 32]);
            off += 32;
            if off + 2 > script_sig.len() {
                return None;
            }
            let branch_len =
                u16::from_le_bytes(script_sig[off..off + 2].try_into().ok()?) as usize;
            off += 2;
            if branch_len > 32 {
                return None;
            }
            if off + branch_len * 32 > script_sig.len() {
                return None;
            }
            let mut ltc_merkle_branch: Vec<[u8; 32]> = Vec::with_capacity(branch_len);
            for _ in 0..branch_len {
                let mut h = [0u8; 32];
                h.copy_from_slice(&script_sig[off..off + 32]);
                ltc_merkle_branch.push(h);
                off += 32;
            }
            if off + 4 > script_sig.len() {
                return None;
            }
            let ltc_merkle_index =
                u32::from_le_bytes(script_sig[off..off + 4].try_into().ok()?);
            off += 4;
            let tx_len = read_varint_at(script_sig, &mut off)? as usize;
            if tx_len == 0 || tx_len > 1_000_000 || off + tx_len != script_sig.len() {
                return None;
            }
            let ltc_tx_raw = script_sig[off..off + tx_len].to_vec();
            Some(HtlcLtcSwapWitness::Claim {
                sig,
                pubkey,
                ltc_block_hash,
                ltc_merkle_branch,
                ltc_merkle_index,
                ltc_tx_raw,
            })
        }
        HTLC_LTC_SWAP_WITNESS_REFUND => {
            let mut off: usize = 1;
            let sig_len = *script_sig.get(off)? as usize;
            off += 1;
            if sig_len == 0 || off + sig_len > script_sig.len() {
                return None;
            }
            let sig = script_sig[off..off + sig_len].to_vec();
            off += sig_len;
            let pk_len = *script_sig.get(off)? as usize;
            off += 1;
            if pk_len == 0 || off + pk_len != script_sig.len() {
                return None;
            }
            let pubkey = script_sig[off..off + pk_len].to_vec();
            Some(HtlcLtcSwapWitness::Refund { sig, pubkey })
        }
        _ => None,
    }
}

pub fn encode_swap_order_script(o: &SwapOrderOutput) -> Vec<u8> {
    let mut s = Vec::with_capacity(SWAP_ORDER_BUY_SCRIPT_LEN);
    s.push(SWAP_ORDER_V1_TAG);
    s.push(SWAP_ORDER_V1_VERSION);
    s.push(o.direction);
    s.push(o.confirmations_required);
    s.extend_from_slice(&o.irm_amount.to_le_bytes());
    s.extend_from_slice(&o.btc_amount_sats.to_le_bytes());
    s.extend_from_slice(&o.maker_iriumd_pkh);
    s.extend_from_slice(&o.maker_btc_pkh);
    s.extend_from_slice(&o.expiry_height.to_le_bytes());
    s.extend_from_slice(&o.order_id);
    if o.direction == SWAP_ORDER_DIRECTION_BUY {
        if let Some(h) = &o.expected_hash {
            s.extend_from_slice(h);
        }
    }
    s
}

pub fn parse_swap_order_script(script: &[u8]) -> Option<SwapOrderOutput> {
    if script.len() != SWAP_ORDER_SELL_SCRIPT_LEN && script.len() != SWAP_ORDER_BUY_SCRIPT_LEN {
        return None;
    }
    if script[0] != SWAP_ORDER_V1_TAG {
        return None;
    }
    if script[1] != SWAP_ORDER_V1_VERSION {
        return None;
    }
    let direction = script[2];
    if direction != SWAP_ORDER_DIRECTION_SELL && direction != SWAP_ORDER_DIRECTION_BUY {
        return None;
    }
    // Sell layout is 76 bytes; buy layout is 76 + 32 hashlock = 108 bytes.
    let expects_hash = direction == SWAP_ORDER_DIRECTION_BUY;
    if expects_hash && script.len() != SWAP_ORDER_BUY_SCRIPT_LEN {
        return None;
    }
    if !expects_hash && script.len() != SWAP_ORDER_SELL_SCRIPT_LEN {
        return None;
    }
    let confirmations_required = script[3];
    let mut amt = [0u8; 8];
    amt.copy_from_slice(&script[4..12]);
    let irm_amount = u64::from_le_bytes(amt);
    amt.copy_from_slice(&script[12..20]);
    let btc_amount_sats = u64::from_le_bytes(amt);
    let mut maker_iriumd_pkh = [0u8; 20];
    maker_iriumd_pkh.copy_from_slice(&script[20..40]);
    let mut maker_btc_pkh = [0u8; 20];
    maker_btc_pkh.copy_from_slice(&script[40..60]);
    amt.copy_from_slice(&script[60..68]);
    let expiry_height = u64::from_le_bytes(amt);
    let mut order_id = [0u8; 8];
    order_id.copy_from_slice(&script[68..76]);
    let expected_hash = if expects_hash {
        let mut h = [0u8; 32];
        h.copy_from_slice(&script[76..108]);
        Some(h)
    } else {
        None
    };
    Some(SwapOrderOutput {
        direction,
        confirmations_required,
        irm_amount,
        btc_amount_sats,
        maker_iriumd_pkh,
        maker_btc_pkh,
        expiry_height,
        order_id,
        expected_hash,
    })
}

#[allow(dead_code)] // Phase 5 wallet/RPC path emits this witness
pub fn encode_swap_order_fill_sell_witness(
    sig: &[u8],
    pubkey: &[u8],
    taker_iriumd_pkh: &[u8; 20],
    timeout_height: u64,
) -> Option<Vec<u8>> {
    if sig.is_empty() || sig.len() > 255 || pubkey.is_empty() || pubkey.len() > 255 {
        return None;
    }
    let mut out = Vec::with_capacity(3 + sig.len() + pubkey.len() + 20 + 8);
    out.push(SWAP_ORDER_WITNESS_FILL);
    out.push(sig.len() as u8);
    out.extend_from_slice(sig);
    out.push(pubkey.len() as u8);
    out.extend_from_slice(pubkey);
    out.extend_from_slice(taker_iriumd_pkh);
    out.extend_from_slice(&timeout_height.to_le_bytes());
    Some(out)
}

#[allow(dead_code)] // Phase 5 wallet/RPC path emits this witness
pub fn encode_swap_order_fill_buy_witness(
    sig: &[u8],
    pubkey: &[u8],
    irm_timeout_height: u64,
) -> Option<Vec<u8>> {
    if sig.is_empty() || sig.len() > 255 || pubkey.is_empty() || pubkey.len() > 255 {
        return None;
    }
    let mut out = Vec::with_capacity(3 + sig.len() + pubkey.len() + 8);
    out.push(SWAP_ORDER_WITNESS_FILL);
    out.push(sig.len() as u8);
    out.extend_from_slice(sig);
    out.push(pubkey.len() as u8);
    out.extend_from_slice(pubkey);
    out.extend_from_slice(&irm_timeout_height.to_le_bytes());
    Some(out)
}

#[allow(dead_code)] // Phase 5 wallet/RPC path emits this witness
pub fn encode_swap_order_cancel_witness(sig: &[u8], pubkey: &[u8]) -> Option<Vec<u8>> {
    if sig.is_empty() || sig.len() > 255 || pubkey.is_empty() || pubkey.len() > 255 {
        return None;
    }
    let mut out = Vec::with_capacity(3 + sig.len() + pubkey.len());
    out.push(SWAP_ORDER_WITNESS_CANCEL);
    out.push(sig.len() as u8);
    out.extend_from_slice(sig);
    out.push(pubkey.len() as u8);
    out.extend_from_slice(pubkey);
    Some(out)
}

#[allow(dead_code)] // Phase 5 wallet/RPC path emits this witness
pub fn encode_swap_order_expire_sweep_witness() -> Vec<u8> {
    vec![SWAP_ORDER_WITNESS_EXPIRE_SWEEP]
}

/// Parse a SwapOrder witness. `direction` from the spending UTXO selects
/// the FillSell vs FillBuy tail shape. Returns `None` on any structural
/// error. Called only from the SwapOrder arm of `verify_transaction_signature`.
pub fn parse_swap_order_witness(script_sig: &[u8], direction: u8) -> Option<SwapOrderWitness> {
    if script_sig.is_empty() {
        return None;
    }
    match script_sig[0] {
        SWAP_ORDER_WITNESS_FILL => {
            let mut off: usize = 1;
            let sig_len = *script_sig.get(off)? as usize;
            off += 1;
            if sig_len == 0 || off + sig_len > script_sig.len() {
                return None;
            }
            let sig = script_sig[off..off + sig_len].to_vec();
            off += sig_len;
            let pk_len = *script_sig.get(off)? as usize;
            off += 1;
            if pk_len == 0 || off + pk_len > script_sig.len() {
                return None;
            }
            let pubkey = script_sig[off..off + pk_len].to_vec();
            off += pk_len;
            match direction {
                SWAP_ORDER_DIRECTION_SELL => {
                    if off + 20 + 8 != script_sig.len() {
                        return None;
                    }
                    let mut taker_iriumd_pkh = [0u8; 20];
                    taker_iriumd_pkh.copy_from_slice(&script_sig[off..off + 20]);
                    off += 20;
                    let mut tb = [0u8; 8];
                    tb.copy_from_slice(&script_sig[off..off + 8]);
                    Some(SwapOrderWitness::FillSell {
                        sig,
                        pubkey,
                        taker_iriumd_pkh,
                        timeout_height: u64::from_le_bytes(tb),
                    })
                }
                SWAP_ORDER_DIRECTION_BUY => {
                    if off + 8 != script_sig.len() {
                        return None;
                    }
                    let mut tb = [0u8; 8];
                    tb.copy_from_slice(&script_sig[off..off + 8]);
                    Some(SwapOrderWitness::FillBuy {
                        sig,
                        pubkey,
                        irm_timeout_height: u64::from_le_bytes(tb),
                    })
                }
                _ => None,
            }
        }
        SWAP_ORDER_WITNESS_CANCEL => {
            let mut off: usize = 1;
            let sig_len = *script_sig.get(off)? as usize;
            off += 1;
            if sig_len == 0 || off + sig_len > script_sig.len() {
                return None;
            }
            let sig = script_sig[off..off + sig_len].to_vec();
            off += sig_len;
            let pk_len = *script_sig.get(off)? as usize;
            off += 1;
            if pk_len == 0 || off + pk_len != script_sig.len() {
                return None;
            }
            let pubkey = script_sig[off..off + pk_len].to_vec();
            Some(SwapOrderWitness::Cancel { sig, pubkey })
        }
        SWAP_ORDER_WITNESS_EXPIRE_SWEEP => {
            if script_sig.len() != 1 {
                return None;
            }
            Some(SwapOrderWitness::ExpireSweep)
        }
        _ => None,
    }
}

// ---- LtcSwapOrder script + witness codecs (Phase D) ----
// Byte-level mirror of the SwapOrder codecs above; the only structural
// differences are the script tag (0xc8 vs 0xc5) and the LTC-side field
// names (ltc_amount_sats, maker_ltc_pkh). Same 76/108 byte sell/buy
// layouts, same 32-byte hashlock tail for buy direction.

pub fn encode_ltc_swap_order_script(o: &LtcSwapOrderOutput) -> Vec<u8> {
    let mut s = Vec::with_capacity(LTC_SWAP_ORDER_BUY_SCRIPT_LEN);
    s.push(LTC_SWAP_ORDER_V1_TAG);
    s.push(LTC_SWAP_ORDER_V1_VERSION);
    s.push(o.direction);
    s.push(o.confirmations_required);
    s.extend_from_slice(&o.irm_amount.to_le_bytes());
    s.extend_from_slice(&o.ltc_amount_sats.to_le_bytes());
    s.extend_from_slice(&o.maker_iriumd_pkh);
    s.extend_from_slice(&o.maker_ltc_pkh);
    s.extend_from_slice(&o.expiry_height.to_le_bytes());
    s.extend_from_slice(&o.order_id);
    if o.direction == LTC_SWAP_ORDER_DIRECTION_BUY {
        if let Some(h) = &o.expected_hash {
            s.extend_from_slice(h);
        }
    }
    s
}

pub fn parse_ltc_swap_order_script(script: &[u8]) -> Option<LtcSwapOrderOutput> {
    if script.len() != LTC_SWAP_ORDER_SELL_SCRIPT_LEN
        && script.len() != LTC_SWAP_ORDER_BUY_SCRIPT_LEN
    {
        return None;
    }
    if script[0] != LTC_SWAP_ORDER_V1_TAG {
        return None;
    }
    if script[1] != LTC_SWAP_ORDER_V1_VERSION {
        return None;
    }
    let direction = script[2];
    if direction != LTC_SWAP_ORDER_DIRECTION_SELL && direction != LTC_SWAP_ORDER_DIRECTION_BUY {
        return None;
    }
    let expects_hash = direction == LTC_SWAP_ORDER_DIRECTION_BUY;
    if expects_hash && script.len() != LTC_SWAP_ORDER_BUY_SCRIPT_LEN {
        return None;
    }
    if !expects_hash && script.len() != LTC_SWAP_ORDER_SELL_SCRIPT_LEN {
        return None;
    }
    let confirmations_required = script[3];
    let mut amt = [0u8; 8];
    amt.copy_from_slice(&script[4..12]);
    let irm_amount = u64::from_le_bytes(amt);
    amt.copy_from_slice(&script[12..20]);
    let ltc_amount_sats = u64::from_le_bytes(amt);
    let mut maker_iriumd_pkh = [0u8; 20];
    maker_iriumd_pkh.copy_from_slice(&script[20..40]);
    let mut maker_ltc_pkh = [0u8; 20];
    maker_ltc_pkh.copy_from_slice(&script[40..60]);
    amt.copy_from_slice(&script[60..68]);
    let expiry_height = u64::from_le_bytes(amt);
    let mut order_id = [0u8; 8];
    order_id.copy_from_slice(&script[68..76]);
    let expected_hash = if expects_hash {
        let mut h = [0u8; 32];
        h.copy_from_slice(&script[76..108]);
        Some(h)
    } else {
        None
    };
    Some(LtcSwapOrderOutput {
        direction,
        confirmations_required,
        irm_amount,
        ltc_amount_sats,
        maker_iriumd_pkh,
        maker_ltc_pkh,
        expiry_height,
        order_id,
        expected_hash,
    })
}

#[allow(dead_code)] // Phase D wallet/RPC path emits this witness
pub fn encode_ltc_swap_order_fill_sell_witness(
    sig: &[u8],
    pubkey: &[u8],
    taker_iriumd_pkh: &[u8; 20],
    timeout_height: u64,
) -> Option<Vec<u8>> {
    if sig.is_empty() || sig.len() > 255 || pubkey.is_empty() || pubkey.len() > 255 {
        return None;
    }
    let mut out = Vec::with_capacity(3 + sig.len() + pubkey.len() + 20 + 8);
    out.push(LTC_SWAP_ORDER_WITNESS_FILL);
    out.push(sig.len() as u8);
    out.extend_from_slice(sig);
    out.push(pubkey.len() as u8);
    out.extend_from_slice(pubkey);
    out.extend_from_slice(taker_iriumd_pkh);
    out.extend_from_slice(&timeout_height.to_le_bytes());
    Some(out)
}

#[allow(dead_code)] // Phase D wallet/RPC path emits this witness
pub fn encode_ltc_swap_order_fill_buy_witness(
    sig: &[u8],
    pubkey: &[u8],
    irm_timeout_height: u64,
) -> Option<Vec<u8>> {
    if sig.is_empty() || sig.len() > 255 || pubkey.is_empty() || pubkey.len() > 255 {
        return None;
    }
    let mut out = Vec::with_capacity(3 + sig.len() + pubkey.len() + 8);
    out.push(LTC_SWAP_ORDER_WITNESS_FILL);
    out.push(sig.len() as u8);
    out.extend_from_slice(sig);
    out.push(pubkey.len() as u8);
    out.extend_from_slice(pubkey);
    out.extend_from_slice(&irm_timeout_height.to_le_bytes());
    Some(out)
}

#[allow(dead_code)] // Phase D wallet/RPC path emits this witness
pub fn encode_ltc_swap_order_cancel_witness(sig: &[u8], pubkey: &[u8]) -> Option<Vec<u8>> {
    if sig.is_empty() || sig.len() > 255 || pubkey.is_empty() || pubkey.len() > 255 {
        return None;
    }
    let mut out = Vec::with_capacity(3 + sig.len() + pubkey.len());
    out.push(LTC_SWAP_ORDER_WITNESS_CANCEL);
    out.push(sig.len() as u8);
    out.extend_from_slice(sig);
    out.push(pubkey.len() as u8);
    out.extend_from_slice(pubkey);
    Some(out)
}

#[allow(dead_code)] // Phase D wallet/RPC path emits this witness
pub fn encode_ltc_swap_order_expire_sweep_witness() -> Vec<u8> {
    vec![LTC_SWAP_ORDER_WITNESS_EXPIRE_SWEEP]
}

/// Parse an LtcSwapOrder witness. `direction` from the spending UTXO
/// selects the FillSell vs FillBuy tail shape. Returns `None` on any
/// structural error. Called only from the LtcSwapOrder arm of
/// `verify_transaction_signature`.
pub fn parse_ltc_swap_order_witness(
    script_sig: &[u8],
    direction: u8,
) -> Option<LtcSwapOrderWitness> {
    if script_sig.is_empty() {
        return None;
    }
    match script_sig[0] {
        LTC_SWAP_ORDER_WITNESS_FILL => {
            let mut off: usize = 1;
            let sig_len = *script_sig.get(off)? as usize;
            off += 1;
            if sig_len == 0 || off + sig_len > script_sig.len() {
                return None;
            }
            let sig = script_sig[off..off + sig_len].to_vec();
            off += sig_len;
            let pk_len = *script_sig.get(off)? as usize;
            off += 1;
            if pk_len == 0 || off + pk_len > script_sig.len() {
                return None;
            }
            let pubkey = script_sig[off..off + pk_len].to_vec();
            off += pk_len;
            match direction {
                LTC_SWAP_ORDER_DIRECTION_SELL => {
                    if off + 20 + 8 != script_sig.len() {
                        return None;
                    }
                    let mut taker_iriumd_pkh = [0u8; 20];
                    taker_iriumd_pkh.copy_from_slice(&script_sig[off..off + 20]);
                    off += 20;
                    let timeout_height =
                        u64::from_le_bytes(script_sig[off..off + 8].try_into().ok()?);
                    Some(LtcSwapOrderWitness::FillSell {
                        sig,
                        pubkey,
                        taker_iriumd_pkh,
                        timeout_height,
                    })
                }
                LTC_SWAP_ORDER_DIRECTION_BUY => {
                    if off + 8 != script_sig.len() {
                        return None;
                    }
                    let irm_timeout_height =
                        u64::from_le_bytes(script_sig[off..off + 8].try_into().ok()?);
                    Some(LtcSwapOrderWitness::FillBuy {
                        sig,
                        pubkey,
                        irm_timeout_height,
                    })
                }
                _ => None,
            }
        }
        LTC_SWAP_ORDER_WITNESS_CANCEL => {
            let mut off: usize = 1;
            let sig_len = *script_sig.get(off)? as usize;
            off += 1;
            if sig_len == 0 || off + sig_len > script_sig.len() {
                return None;
            }
            let sig = script_sig[off..off + sig_len].to_vec();
            off += sig_len;
            let pk_len = *script_sig.get(off)? as usize;
            off += 1;
            if pk_len == 0 || off + pk_len != script_sig.len() {
                return None;
            }
            let pubkey = script_sig[off..off + pk_len].to_vec();
            Some(LtcSwapOrderWitness::Cancel { sig, pubkey })
        }
        LTC_SWAP_ORDER_WITNESS_EXPIRE_SWEEP => {
            if script_sig.len() != 1 {
                return None;
            }
            Some(LtcSwapOrderWitness::ExpireSweep)
        }
        _ => None,
    }
}

fn parse_legacy_p2pkh_witness(script_sig: &[u8]) -> Option<InputWitness> {
    if script_sig.len() < 2 {
        return None;
    }
    let sig_len = script_sig[0] as usize;
    if sig_len == 0 || script_sig.len() < 1 + sig_len + 1 {
        return None;
    }
    let sig = script_sig[1..1 + sig_len].to_vec();
    let pk_len = script_sig[1 + sig_len] as usize;
    let pk_off = 1 + sig_len + 1;
    if pk_len == 0 || script_sig.len() != pk_off + pk_len {
        return None;
    }
    let pubkey = script_sig[pk_off..pk_off + pk_len].to_vec();
    Some(InputWitness::P2pkh { sig, pubkey })
}

#[allow(dead_code)] // HTLCv1 claim witness encoder; used by wallet when spending HTLC outputs
pub fn encode_htlcv1_claim_witness(sig: &[u8], pubkey: &[u8], preimage: &[u8]) -> Option<Vec<u8>> {
    if sig.is_empty()
        || sig.len() > 255
        || pubkey.is_empty()
        || pubkey.len() > 255
        || preimage.is_empty()
        || preimage.len() > 255
    {
        return None;
    }
    let mut out = Vec::with_capacity(4 + sig.len() + pubkey.len() + preimage.len());
    out.push(HTLC_WITNESS_CLAIM);
    out.push(sig.len() as u8);
    out.extend_from_slice(sig);
    out.push(pubkey.len() as u8);
    out.extend_from_slice(pubkey);
    out.push(preimage.len() as u8);
    out.extend_from_slice(preimage);
    Some(out)
}

#[allow(dead_code)] // HTLCv1 refund witness encoder; used by wallet when reclaiming expired HTLCs
pub fn encode_htlcv1_refund_witness(sig: &[u8], pubkey: &[u8]) -> Option<Vec<u8>> {
    if sig.is_empty() || sig.len() > 255 || pubkey.is_empty() || pubkey.len() > 255 {
        return None;
    }
    let mut out = Vec::with_capacity(3 + sig.len() + pubkey.len());
    out.push(HTLC_WITNESS_REFUND);
    out.push(sig.len() as u8);
    out.extend_from_slice(sig);
    out.push(pubkey.len() as u8);
    out.extend_from_slice(pubkey);
    Some(out)
}

#[allow(dead_code)] // MPSO claim witness encoder; used by wallet for M-of-N multisig claim spending
pub fn encode_mpso_claim_witness(
    bitmap: u8,
    sigs: &[Vec<u8>],
    preimage: Option<&[u8]>,
) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    out.push(0x01u8);
    out.push(bitmap);
    for sig in sigs {
        if sig.is_empty() || sig.len() > 255 {
            return None;
        }
        out.push(sig.len() as u8);
        out.extend_from_slice(sig);
    }
    if let Some(pre) = preimage {
        if pre.is_empty() || pre.len() > 64 {
            return None;
        }
        out.push(pre.len() as u8);
        out.extend_from_slice(pre);
    }
    Some(out)
}

#[allow(dead_code)] // MPSO refund witness encoder; used by wallet for M-of-N multisig refund spending
pub fn encode_mpso_refund_witness(bitmap: u8, sigs: &[Vec<u8>]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    out.push(0x02u8);
    out.push(bitmap);
    for sig in sigs {
        if sig.is_empty() || sig.len() > 255 {
            return None;
        }
        out.push(sig.len() as u8);
        out.extend_from_slice(sig);
    }
    Some(out)
}

pub fn parse_input_witness(script_sig: &[u8]) -> InputWitness {
    if script_sig.is_empty() {
        return InputWitness::Unknown;
    }
    match script_sig[0] {
        HTLC_WITNESS_CLAIM => {
            if script_sig.len() < 4 {
                return InputWitness::Unknown;
            }
            let sig_len = script_sig[1] as usize;
            let sig_off = 2;
            let pk_len_off = sig_off + sig_len;
            if sig_len == 0 || pk_len_off >= script_sig.len() {
                return InputWitness::Unknown;
            }
            let sig = script_sig[sig_off..pk_len_off].to_vec();
            let pk_len = script_sig[pk_len_off] as usize;
            let pk_off = pk_len_off + 1;
            let pre_len_off = pk_off + pk_len;
            if pk_len == 0 || pre_len_off >= script_sig.len() {
                return InputWitness::Unknown;
            }
            let pubkey = script_sig[pk_off..pre_len_off].to_vec();
            let pre_len = script_sig[pre_len_off] as usize;
            let pre_off = pre_len_off + 1;
            if pre_len == 0 || pre_off + pre_len != script_sig.len() {
                return InputWitness::Unknown;
            }
            let preimage = script_sig[pre_off..pre_off + pre_len].to_vec();
            InputWitness::HtlcClaim {
                sig,
                pubkey,
                preimage,
            }
        }
        HTLC_WITNESS_REFUND => {
            if script_sig.len() < 3 {
                return InputWitness::Unknown;
            }
            let sig_len = script_sig[1] as usize;
            let sig_off = 2;
            let pk_len_off = sig_off + sig_len;
            if sig_len == 0 || pk_len_off >= script_sig.len() {
                return InputWitness::Unknown;
            }
            let sig = script_sig[sig_off..pk_len_off].to_vec();
            let pk_len = script_sig[pk_len_off] as usize;
            let pk_off = pk_len_off + 1;
            if pk_len == 0 || pk_off + pk_len != script_sig.len() {
                return InputWitness::Unknown;
            }
            let pubkey = script_sig[pk_off..pk_off + pk_len].to_vec();
            InputWitness::HtlcRefund { sig, pubkey }
        }
        _ => parse_legacy_p2pkh_witness(script_sig).unwrap_or(InputWitness::Unknown),
    }
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, hex::FromHexError> {
    Vec::from_hex(s)
}

#[allow(dead_code)]
pub fn decode_full_tx(raw: &[u8]) -> Result<Transaction, String> {
    let mut offset = 0usize;
    let tx = decode_full_tx_at(raw, &mut offset)?;
    if offset != raw.len() {
        return Err("trailing bytes after transaction".to_string());
    }
    Ok(tx)
}

pub fn decode_full_tx_at(raw: &[u8], offset: &mut usize) -> Result<Transaction, String> {
    let read_u8 = |buf: &[u8], off: &mut usize| -> Result<u8, String> {
        if *off >= buf.len() {
            return Err("unexpected EOF".to_string());
        }
        let v = buf[*off];
        *off += 1;
        Ok(v)
    };
    let read_u32 = |buf: &[u8], off: &mut usize| -> Result<u32, String> {
        if *off + 4 > buf.len() {
            return Err("unexpected EOF".to_string());
        }
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&buf[*off..*off + 4]);
        *off += 4;
        Ok(u32::from_le_bytes(bytes))
    };
    let read_u64 = |buf: &[u8], off: &mut usize| -> Result<u64, String> {
        if *off + 8 > buf.len() {
            return Err("unexpected EOF".to_string());
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&buf[*off..*off + 8]);
        *off += 8;
        Ok(u64::from_le_bytes(bytes))
    };
    let read_bytes = |buf: &[u8], off: &mut usize, len: usize| -> Result<Vec<u8>, String> {
        if *off + len > buf.len() {
            return Err("unexpected EOF".to_string());
        }
        let out = buf[*off..*off + len].to_vec();
        *off += len;
        Ok(out)
    };
    let version = read_u32(raw, offset)?;
    let input_count = read_u8(raw, offset)? as usize;
    let mut inputs = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        let txid_len = read_u8(raw, offset)? as usize;
        let prev_txid_bytes = read_bytes(raw, offset, txid_len)?;
        if prev_txid_bytes.len() != 32 {
            return Err("invalid prev_txid length".to_string());
        }
        let mut prev_txid = [0u8; 32];
        prev_txid.copy_from_slice(&prev_txid_bytes);
        let prev_index = read_u32(raw, offset)?;
        let script_len = read_u8(raw, offset)? as usize;
        let script_sig = read_bytes(raw, offset, script_len)?;
        let sequence = read_u32(raw, offset)?;
        inputs.push(TxInput {
            prev_txid,
            prev_index,
            script_sig,
            sequence,
        });
    }
    let output_count = read_u8(raw, offset)? as usize;
    let mut outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        let value = read_u64(raw, offset)?;
        let script_len = read_varint_at(raw, offset)
            .ok_or_else(|| "unexpected EOF reading output script_len varint".to_string())?
            as usize;
        let script_pubkey = read_bytes(raw, offset, script_len)?;
        outputs.push(TxOutput {
            value,
            script_pubkey,
        });
    }
    let locktime = read_u32(raw, offset)?;
    Ok(Transaction {
        version,
        inputs,
        outputs,
        locktime,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn htlc_script_roundtrip() {
        let out = HtlcV1Output {
            expected_hash: [0x11; 32],
            recipient_pkh: [0x22; 20],
            refund_pkh: [0x33; 20],
            timeout_height: 123456,
        };
        let spk = encode_htlcv1_script(&out);
        assert_eq!(spk.len(), HTLC_V1_SCRIPT_LEN);
        let parsed = parse_htlcv1_script(&spk).expect("parse");
        assert_eq!(parsed, out);
    }

    #[test]
    fn htlc_claim_witness_roundtrip() {
        let w = encode_htlcv1_claim_witness(&[1, 2, 3], &[2; 33], &[9; 32]).expect("encode");
        match parse_input_witness(&w) {
            InputWitness::HtlcClaim {
                sig,
                pubkey,
                preimage,
            } => {
                assert_eq!(sig, vec![1, 2, 3]);
                assert_eq!(pubkey.len(), 33);
                assert_eq!(preimage.len(), 32);
            }
            _ => panic!("wrong witness"),
        }
    }

    #[test]
    fn htlc_refund_witness_roundtrip() {
        let w = encode_htlcv1_refund_witness(&[1, 2, 3], &[2; 33]).expect("encode");
        match parse_input_witness(&w) {
            InputWitness::HtlcRefund { sig, pubkey } => {
                assert_eq!(sig, vec![1, 2, 3]);
                assert_eq!(pubkey.len(), 33);
            }
            _ => panic!("wrong witness"),
        }
    }

    fn valid_compressed_pubkey(seed: u8) -> [u8; 33] {
        use k256::ecdsa::SigningKey;
        let mut sk_bytes = [0u8; 32];
        sk_bytes[31] = seed;
        let sk = SigningKey::from_bytes((&sk_bytes).into()).expect("sk");
        let encoded = sk.verifying_key().to_encoded_point(true);
        let bytes = encoded.as_bytes();
        let mut pk = [0u8; 33];
        pk.copy_from_slice(bytes);
        pk
    }

    fn make_mpso(claim_n: u8, claim_m: u8, refund_n: u8, refund_m: u8, flags: u8) -> MpsoV1Output {
        let mut claim_pubkeys = Vec::new();
        for i in 0..claim_n {
            claim_pubkeys.push(valid_compressed_pubkey(i + 1));
        }
        let mut refund_pubkeys = Vec::new();
        for i in 0..refund_n {
            refund_pubkeys.push(valid_compressed_pubkey(i + 1 + claim_n));
        }
        let optional_hash = if flags & 0x01 != 0 {
            Some([0xaau8; 32])
        } else {
            None
        };
        MpsoV1Output {
            flags,
            claim_n,
            claim_m,
            refund_n,
            refund_m,
            agreement_hash: [0x42u8; 32],
            claim_pubkeys,
            refund_pubkeys,
            timeout_height: 1000,
            optional_hash,
        }
    }

    #[test]
    fn mpso_script_roundtrip_no_secret() {
        let o = make_mpso(2, 1, 2, 2, 0x00);
        let script = encode_mpso_script(&o);
        let parsed = parse_mpso_script(&script).expect("parse");
        assert_eq!(parsed, o);
    }

    #[test]
    fn mpso_script_roundtrip_with_secret() {
        let o = make_mpso(2, 2, 1, 1, 0x01);
        let script = encode_mpso_script(&o);
        let parsed = parse_mpso_script(&script).expect("parse");
        assert_eq!(parsed, o);
    }

    #[test]
    fn mpso_script_roundtrip_max_size() {
        let o = make_mpso(8, 8, 8, 8, 0x01);
        let script = encode_mpso_script(&o);
        assert_eq!(script.len(), 608);
        assert!(script.len() <= MPSO_V1_MAX_SCRIPT_SIZE);
        let parsed = parse_mpso_script(&script).expect("parse max-size script");
        assert_eq!(parsed, o);
    }

    #[test]
    fn mpso_script_reject_trailing_byte() {
        let o = make_mpso(2, 1, 1, 1, 0x00);
        let mut script = encode_mpso_script(&o);
        script.push(0x00);
        assert!(parse_mpso_script(&script).is_none());
    }

    #[test]
    fn mpso_script_reject_wrong_tag() {
        let o = make_mpso(1, 1, 1, 1, 0x00);
        let mut script = encode_mpso_script(&o);
        script[0] = 0xc0;
        assert!(parse_mpso_script(&script).is_none());
    }

    #[test]
    fn mpso_script_reject_reserved_flag_bits() {
        let o = make_mpso(1, 1, 1, 1, 0x00);
        let mut script = encode_mpso_script(&o);
        script[2] = 0x02;
        assert!(parse_mpso_script(&script).is_none());
    }

    #[test]
    fn mpso_script_reject_nonzero_reserved_byte() {
        let o = make_mpso(1, 1, 1, 1, 0x00);
        let mut script = encode_mpso_script(&o);
        script[3] = 0x01;
        assert!(parse_mpso_script(&script).is_none());
    }

    #[test]
    fn mpso_script_reject_zero_claim_n() {
        let o = make_mpso(1, 1, 1, 1, 0x00);
        let mut script = encode_mpso_script(&o);
        script[4] = 0;
        assert!(parse_mpso_script(&script).is_none());
    }

    #[test]
    fn mpso_script_reject_claim_m_gt_claim_n() {
        let o = make_mpso(2, 2, 1, 1, 0x00);
        let mut script = encode_mpso_script(&o);
        script[5] = 3;
        assert!(parse_mpso_script(&script).is_none());
    }

    #[test]
    fn mpso_script_reject_refund_m_gt_refund_n() {
        let o = make_mpso(1, 1, 2, 2, 0x00);
        let mut script = encode_mpso_script(&o);
        script[7] = 3;
        assert!(parse_mpso_script(&script).is_none());
    }

    #[test]
    fn mpso_script_reject_duplicate_claim_pubkey() {
        let pk1 = valid_compressed_pubkey(1);
        let rp1 = valid_compressed_pubkey(3);
        let o = MpsoV1Output {
            flags: 0x00,
            claim_n: 2,
            claim_m: 1,
            refund_n: 1,
            refund_m: 1,
            agreement_hash: [0x42u8; 32],
            claim_pubkeys: vec![pk1, pk1],
            refund_pubkeys: vec![rp1],
            timeout_height: 1000,
            optional_hash: None,
        };
        let script = encode_mpso_script(&o);
        assert!(parse_mpso_script(&script).is_none());
    }

    #[test]
    fn mpso_script_reject_duplicate_refund_pubkey() {
        let cp1 = valid_compressed_pubkey(1);
        let rp1 = valid_compressed_pubkey(3);
        let o = MpsoV1Output {
            flags: 0x00,
            claim_n: 1,
            claim_m: 1,
            refund_n: 2,
            refund_m: 1,
            agreement_hash: [0x42u8; 32],
            claim_pubkeys: vec![cp1],
            refund_pubkeys: vec![rp1, rp1],
            timeout_height: 1000,
            optional_hash: None,
        };
        let script = encode_mpso_script(&o);
        assert!(parse_mpso_script(&script).is_none());
    }

    fn sample_swap() -> HtlcBtcSwapV1Output {
        HtlcBtcSwapV1Output {
            confirmations_required: 6,
            recipient_pkh: [0x11; 20],
            refund_pkh: [0x22; 20],
            btc_recipient_pkh: [0x33; 20],
            btc_amount_sats: 5_000,
            timeout_height: 250_000,
            funding_binding: [0xab; 8],
        }
    }

    #[test]
    fn htlc_btc_swap_v1_script_is_87_bytes_and_roundtrips() {
        let o = sample_swap();
        let s = encode_htlc_btc_swap_v1_script(&o);
        assert_eq!(s.len(), HTLC_BTC_SWAP_V1_SCRIPT_LEN);
        assert_eq!(s[0], HTLC_BTC_SWAP_V1_TAG);
        assert_eq!(s[1], HTLC_BTC_SWAP_V1_VERSION);
        let parsed = parse_htlc_btc_swap_v1_script(&s).expect("parse");
        assert_eq!(parsed, o);
    }

    #[test]
    fn htlc_btc_swap_v1_parse_rejects_wrong_size() {
        let o = sample_swap();
        let mut s = encode_htlc_btc_swap_v1_script(&o);
        s.push(0); // 88 bytes
        assert!(parse_htlc_btc_swap_v1_script(&s).is_none());
        assert!(parse_htlc_btc_swap_v1_script(&s[..86]).is_none());
    }

    #[test]
    fn htlc_btc_swap_v1_parse_rejects_wrong_tag() {
        let o = sample_swap();
        let mut s = encode_htlc_btc_swap_v1_script(&o);
        s[0] = 0xc0;
        assert!(parse_htlc_btc_swap_v1_script(&s).is_none());
    }

    #[test]
    fn htlc_btc_swap_v1_parse_rejects_wrong_version() {
        let o = sample_swap();
        let mut s = encode_htlc_btc_swap_v1_script(&o);
        s[1] = 0xff;
        assert!(parse_htlc_btc_swap_v1_script(&s).is_none());
    }

    #[test]
    fn output_encumbrance_recognises_htlc_btc_swap_v1() {
        let o = sample_swap();
        let s = encode_htlc_btc_swap_v1_script(&o);
        match parse_output_encumbrance(&s) {
            OutputEncumbrance::HtlcBtcSwapV1(parsed) => assert_eq!(parsed, o),
            _ => panic!("expected HtlcBtcSwapV1"),
        }
    }

    #[test]
    fn output_encumbrance_does_not_mistake_htlcv1_for_swap() {
        // HTLCv1 is 83 bytes; with the 0xc0 tag it must not parse as HtlcBtcSwapV1.
        let htlc = HtlcV1Output {
            expected_hash: [0; 32],
            recipient_pkh: [0; 20],
            refund_pkh: [0; 20],
            timeout_height: 100,
        };
        let s = encode_htlcv1_script(&htlc);
        match parse_output_encumbrance(&s) {
            OutputEncumbrance::HtlcV1(_) => {}
            other => panic!("HTLCv1 must still parse as HtlcV1, got {:?}", other),
        }
    }

    #[test]
    fn compute_funding_binding_is_deterministic_and_input_sensitive() {
        let a = compute_funding_binding(&[0xaa; 32], 0);
        let b = compute_funding_binding(&[0xaa; 32], 0);
        let c = compute_funding_binding(&[0xaa; 32], 1);
        let d = compute_funding_binding(&[0xbb; 32], 0);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    #[test]
    fn htlc_btc_swap_claim_witness_roundtrip() {
        let block_hash = [0x99u8; 32];
        let branch = vec![[0x11u8; 32], [0x22u8; 32], [0x33u8; 32]];
        let tx_raw = vec![0xde, 0xad, 0xbe, 0xef];
        let w = encode_htlc_btc_swap_claim_witness(
            &[1, 2, 3],
            &[0x02; 33],
            &block_hash,
            &branch,
            7,
            &tx_raw,
        )
        .expect("encode");
        match parse_htlc_btc_swap_witness(&w).expect("parse") {
            HtlcBtcSwapWitness::Claim {
                sig,
                pubkey,
                btc_block_hash,
                btc_merkle_branch,
                btc_merkle_index,
                btc_tx_raw,
            } => {
                assert_eq!(sig, vec![1, 2, 3]);
                assert_eq!(pubkey.len(), 33);
                assert_eq!(btc_block_hash, block_hash);
                assert_eq!(btc_merkle_branch, branch);
                assert_eq!(btc_merkle_index, 7);
                assert_eq!(btc_tx_raw, tx_raw);
            }
            _ => panic!("expected Claim variant"),
        }
    }

    #[test]
    fn htlc_btc_swap_refund_witness_roundtrip() {
        let w = encode_htlc_btc_swap_refund_witness(&[9, 9], &[0x02; 33]).expect("encode");
        match parse_htlc_btc_swap_witness(&w).expect("parse") {
            HtlcBtcSwapWitness::Refund { sig, pubkey } => {
                assert_eq!(sig, vec![9, 9]);
                assert_eq!(pubkey.len(), 33);
            }
            _ => panic!("expected Refund variant"),
        }
    }

    #[test]
    fn htlc_btc_swap_witness_rejects_unknown_selector() {
        assert!(parse_htlc_btc_swap_witness(&[0x05, 0, 0, 0]).is_none());
        assert!(parse_htlc_btc_swap_witness(&[]).is_none());
    }

    #[test]
    fn htlc_btc_swap_witness_rejects_branch_too_deep() {
        let mut w = vec![HTLC_BTC_SWAP_WITNESS_CLAIM, 1, 0x42, 1, 0x02];
        w.extend_from_slice(&[0xaa; 32]); // btc_block_hash
        w.extend_from_slice(&33u16.to_le_bytes()); // branch_len = 33 > 32
        w.extend_from_slice(&[0u8; 33 * 32]);
        w.extend_from_slice(&0u32.to_le_bytes());
        w.push(1);
        w.push(0xff);
        assert!(parse_htlc_btc_swap_witness(&w).is_none());
    }

    #[test]
    fn htlc_btc_swap_witness_rejects_trailing_bytes() {
        let w = encode_htlc_btc_swap_refund_witness(&[1], &[0x02; 33]).expect("encode");
        let mut bad = w.clone();
        bad.push(0xff);
        assert!(parse_htlc_btc_swap_witness(&bad).is_none());
    }

    fn sample_swap_order(direction: u8) -> SwapOrderOutput {
        SwapOrderOutput {
            direction,
            confirmations_required: 6,
            irm_amount: 100_000_000,
            btc_amount_sats: 5_000,
            maker_iriumd_pkh: [0x11; 20],
            maker_btc_pkh: [0x22; 20],
            expiry_height: 250_000,
            order_id: [0xa; 8],
            expected_hash: if direction == SWAP_ORDER_DIRECTION_BUY {
                Some([0xcc; 32])
            } else {
                None
            },
        }
    }

    #[test]
    fn swap_order_sell_script_is_76_bytes_and_roundtrips() {
        let o = sample_swap_order(SWAP_ORDER_DIRECTION_SELL);
        let s = encode_swap_order_script(&o);
        assert_eq!(s.len(), SWAP_ORDER_SELL_SCRIPT_LEN);
        assert_eq!(s[0], SWAP_ORDER_V1_TAG);
        assert_eq!(s[1], SWAP_ORDER_V1_VERSION);
        assert_eq!(s[2], SWAP_ORDER_DIRECTION_SELL);
        let parsed = parse_swap_order_script(&s).expect("parse");
        assert_eq!(parsed, o);
    }

    #[test]
    fn swap_order_buy_script_is_108_bytes_and_roundtrips() {
        let o = sample_swap_order(SWAP_ORDER_DIRECTION_BUY);
        let s = encode_swap_order_script(&o);
        assert_eq!(s.len(), SWAP_ORDER_BUY_SCRIPT_LEN);
        assert_eq!(s[2], SWAP_ORDER_DIRECTION_BUY);
        let parsed = parse_swap_order_script(&s).expect("parse");
        assert_eq!(parsed, o);
        assert!(parsed.expected_hash.is_some());
    }

    #[test]
    fn swap_order_parse_rejects_wrong_tag() {
        let o = sample_swap_order(SWAP_ORDER_DIRECTION_SELL);
        let mut s = encode_swap_order_script(&o);
        s[0] = 0xc0;
        assert!(parse_swap_order_script(&s).is_none());
    }

    #[test]
    fn swap_order_parse_rejects_wrong_version() {
        let o = sample_swap_order(SWAP_ORDER_DIRECTION_SELL);
        let mut s = encode_swap_order_script(&o);
        s[1] = 0xff;
        assert!(parse_swap_order_script(&s).is_none());
    }

    #[test]
    fn swap_order_parse_rejects_invalid_direction() {
        let o = sample_swap_order(SWAP_ORDER_DIRECTION_SELL);
        let mut s = encode_swap_order_script(&o);
        s[2] = 0x05; // not SELL or BUY
        assert!(parse_swap_order_script(&s).is_none());
    }

    #[test]
    fn swap_order_parse_rejects_size_direction_mismatch() {
        // Sell at 108 bytes -> invalid (sell expects exactly 76)
        let mut s = encode_swap_order_script(&sample_swap_order(SWAP_ORDER_DIRECTION_SELL));
        s.extend_from_slice(&[0u8; 32]);
        assert!(parse_swap_order_script(&s).is_none());
        // Buy at 76 bytes -> invalid (buy expects exactly 108)
        let mut s2 = encode_swap_order_script(&sample_swap_order(SWAP_ORDER_DIRECTION_BUY));
        s2.truncate(SWAP_ORDER_SELL_SCRIPT_LEN);
        assert!(parse_swap_order_script(&s2).is_none());
    }

    #[test]
    fn output_encumbrance_recognises_swap_order_sell_and_buy() {
        let sell = encode_swap_order_script(&sample_swap_order(SWAP_ORDER_DIRECTION_SELL));
        let buy = encode_swap_order_script(&sample_swap_order(SWAP_ORDER_DIRECTION_BUY));
        match parse_output_encumbrance(&sell) {
            OutputEncumbrance::SwapOrder(o) => assert_eq!(o.direction, SWAP_ORDER_DIRECTION_SELL),
            other => panic!("expected SwapOrder sell, got {:?}", other),
        }
        match parse_output_encumbrance(&buy) {
            OutputEncumbrance::SwapOrder(o) => assert_eq!(o.direction, SWAP_ORDER_DIRECTION_BUY),
            other => panic!("expected SwapOrder buy, got {:?}", other),
        }
    }

    #[test]
    fn output_encumbrance_does_not_mistake_other_types_for_swap_order() {
        let htlc = HtlcV1Output {
            expected_hash: [0; 32],
            recipient_pkh: [0; 20],
            refund_pkh: [0; 20],
            timeout_height: 100,
        };
        let s = encode_htlcv1_script(&htlc);
        assert!(matches!(
            parse_output_encumbrance(&s),
            OutputEncumbrance::HtlcV1(_)
        ));
    }

    #[test]
    fn swap_order_fill_sell_witness_roundtrip() {
        let w = encode_swap_order_fill_sell_witness(&[1, 2, 3], &[0x02; 33], &[0x44; 20], 100_500)
            .expect("encode");
        match parse_swap_order_witness(&w, SWAP_ORDER_DIRECTION_SELL).expect("parse") {
            SwapOrderWitness::FillSell {
                sig,
                pubkey,
                taker_iriumd_pkh,
                timeout_height,
            } => {
                assert_eq!(sig, vec![1, 2, 3]);
                assert_eq!(pubkey.len(), 33);
                assert_eq!(taker_iriumd_pkh, [0x44u8; 20]);
                assert_eq!(timeout_height, 100_500);
            }
            other => panic!("expected FillSell, got {:?}", other),
        }
    }

    #[test]
    fn swap_order_fill_buy_witness_roundtrip() {
        let w =
            encode_swap_order_fill_buy_witness(&[9, 9], &[0x02; 33], 222_222).expect("encode");
        match parse_swap_order_witness(&w, SWAP_ORDER_DIRECTION_BUY).expect("parse") {
            SwapOrderWitness::FillBuy {
                sig,
                pubkey,
                irm_timeout_height,
            } => {
                assert_eq!(sig, vec![9, 9]);
                assert_eq!(pubkey.len(), 33);
                assert_eq!(irm_timeout_height, 222_222);
            }
            other => panic!("expected FillBuy, got {:?}", other),
        }
    }

    #[test]
    fn swap_order_cancel_witness_roundtrip() {
        let w = encode_swap_order_cancel_witness(&[7, 7, 7], &[0x03; 33]).expect("encode");
        match parse_swap_order_witness(&w, SWAP_ORDER_DIRECTION_SELL).expect("parse") {
            SwapOrderWitness::Cancel { sig, pubkey } => {
                assert_eq!(sig, vec![7, 7, 7]);
                assert_eq!(pubkey.len(), 33);
            }
            other => panic!("expected Cancel, got {:?}", other),
        }
    }

    #[test]
    fn swap_order_expire_sweep_witness_is_single_byte() {
        let w = encode_swap_order_expire_sweep_witness();
        assert_eq!(w, vec![SWAP_ORDER_WITNESS_EXPIRE_SWEEP]);
        assert!(matches!(
            parse_swap_order_witness(&w, SWAP_ORDER_DIRECTION_SELL),
            Some(SwapOrderWitness::ExpireSweep)
        ));
    }

    #[test]
    fn swap_order_witness_rejects_unknown_selector() {
        assert!(parse_swap_order_witness(&[0x05, 0, 0], SWAP_ORDER_DIRECTION_SELL).is_none());
        assert!(parse_swap_order_witness(&[], SWAP_ORDER_DIRECTION_SELL).is_none());
    }

    #[test]
    fn swap_order_fill_witness_with_wrong_direction_rejected() {
        // Encode a SELL-tail Fill witness, then try to parse it as BUY.
        let w = encode_swap_order_fill_sell_witness(&[1, 2], &[0x02; 33], &[0u8; 20], 100)
            .expect("encode");
        assert!(parse_swap_order_witness(&w, SWAP_ORDER_DIRECTION_BUY).is_none());
        // And vice versa.
        let w2 = encode_swap_order_fill_buy_witness(&[1], &[0x02; 33], 999).expect("encode");
        assert!(parse_swap_order_witness(&w2, SWAP_ORDER_DIRECTION_SELL).is_none());
    }

    #[test]
    fn swap_order_expire_sweep_witness_rejects_trailing_bytes() {
        assert!(parse_swap_order_witness(
            &[SWAP_ORDER_WITNESS_EXPIRE_SWEEP, 0xff],
            SWAP_ORDER_DIRECTION_SELL
        )
        .is_none());
    }

    #[test]
    fn mpso_script_allow_claim_refund_overlap() {
        // Overlapping claim/refund keys are intentionally allowed for symmetric multisig escrow,
        // where the same M-of-N signers control both the claim path (before timeout)
        // and the refund path (after timeout).
        let shared = valid_compressed_pubkey(1);
        let cp2 = valid_compressed_pubkey(2);
        let o = MpsoV1Output {
            flags: 0x00,
            claim_n: 2,
            claim_m: 1,
            refund_n: 1,
            refund_m: 1,
            agreement_hash: [0x42u8; 32],
            claim_pubkeys: vec![cp2, shared],
            refund_pubkeys: vec![shared],
            timeout_height: 1000,
            optional_hash: None,
        };
        let script = encode_mpso_script(&o);
        assert!(parse_mpso_script(&script).is_some());
    }

    // ---- HtlcLtcSwapV1 tests (Phase C) ----

    fn sample_ltc_swap() -> HtlcLtcSwapV1Output {
        HtlcLtcSwapV1Output {
            confirmations_required: 6,
            recipient_pkh: [0x11u8; 20],
            refund_pkh: [0x22u8; 20],
            ltc_recipient_pkh: [0x33u8; 20],
            ltc_amount_sats: 100_000,
            timeout_height: 250_000,
            funding_binding: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02],
        }
    }

    #[test]
    fn htlc_ltc_swap_v1_script_roundtrip() {
        let o = sample_ltc_swap();
        let s = encode_htlc_ltc_swap_v1_script(&o);
        assert_eq!(s.len(), HTLC_LTC_SWAP_V1_SCRIPT_LEN);
        assert_eq!(s[0], HTLC_LTC_SWAP_V1_TAG);
        assert_eq!(s[1], HTLC_LTC_SWAP_V1_VERSION);
        let parsed = parse_htlc_ltc_swap_v1_script(&s).expect("parse");
        assert_eq!(parsed, o);
    }

    #[test]
    fn htlc_ltc_swap_v1_dispatch_through_output_encumbrance() {
        let o = sample_ltc_swap();
        let s = encode_htlc_ltc_swap_v1_script(&o);
        match parse_output_encumbrance(&s) {
            OutputEncumbrance::HtlcLtcSwapV1(parsed) => assert_eq!(parsed, o),
            _ => panic!("expected HtlcLtcSwapV1"),
        }
    }

    #[test]
    fn htlc_ltc_swap_v1_rejects_wrong_tag() {
        let mut s = encode_htlc_ltc_swap_v1_script(&sample_ltc_swap());
        s[0] = HTLC_BTC_SWAP_V1_TAG;
        assert!(parse_htlc_ltc_swap_v1_script(&s).is_none());
    }

    #[test]
    fn htlc_ltc_swap_v1_rejects_wrong_length() {
        let mut s = encode_htlc_ltc_swap_v1_script(&sample_ltc_swap());
        s.push(0);
        assert!(parse_htlc_ltc_swap_v1_script(&s).is_none());
    }

    #[test]
    fn htlc_ltc_swap_claim_witness_roundtrip() {
        let sig = vec![0x30, 0x44, 0x02];
        let pubkey = vec![0x02; 33];
        let block_hash = [0x77u8; 32];
        let branch = vec![[0x11u8; 32], [0x22u8; 32]];
        let tx_raw = vec![0xab, 0xcd, 0xef];
        let w = encode_htlc_ltc_swap_claim_witness(&sig, &pubkey, &block_hash, &branch, 7, &tx_raw)
            .expect("encode");
        match parse_htlc_ltc_swap_witness(&w).expect("parse") {
            HtlcLtcSwapWitness::Claim {
                sig: s,
                pubkey: pk,
                ltc_block_hash,
                ltc_merkle_branch,
                ltc_merkle_index,
                ltc_tx_raw,
            } => {
                assert_eq!(s, sig);
                assert_eq!(pk, pubkey);
                assert_eq!(ltc_block_hash, block_hash);
                assert_eq!(ltc_merkle_branch, branch);
                assert_eq!(ltc_merkle_index, 7);
                assert_eq!(ltc_tx_raw, tx_raw);
            }
            _ => panic!("expected Claim"),
        }
    }

    #[test]
    fn htlc_ltc_swap_refund_witness_roundtrip() {
        let sig = vec![0x30, 0x44];
        let pubkey = vec![0x03; 33];
        let w = encode_htlc_ltc_swap_refund_witness(&sig, &pubkey).expect("encode");
        match parse_htlc_ltc_swap_witness(&w).expect("parse") {
            HtlcLtcSwapWitness::Refund { sig: s, pubkey: pk } => {
                assert_eq!(s, sig);
                assert_eq!(pk, pubkey);
            }
            _ => panic!("expected Refund"),
        }
    }

    #[test]
    fn htlc_ltc_swap_witness_rejects_unknown_selector() {
        let mut w = vec![0xff, 1, 0x42, 1, 0x02];
        w.extend_from_slice(&[0u8; 32]);
        w.extend_from_slice(&0u16.to_le_bytes());
        w.extend_from_slice(&0u32.to_le_bytes());
        w.push(1);
        w.push(0xab);
        assert!(parse_htlc_ltc_swap_witness(&w).is_none());
    }

    #[test]
    fn ltc_op_return_binding_magic_distinct_from_btc() {
        assert_ne!(LTC_OP_RETURN_BINDING_MAGIC, BTC_OP_RETURN_BINDING_MAGIC);
        assert_eq!(LTC_OP_RETURN_BINDING_LEN, 14);
        assert_eq!(LTC_OP_RETURN_BINDING_MAGIC.len(), 6);
    }

    // ---- LtcSwapOrder tests (Phase D) ----

    fn sample_ltc_swap_order(direction: u8) -> LtcSwapOrderOutput {
        LtcSwapOrderOutput {
            direction,
            confirmations_required: 6,
            irm_amount: 100_000_000,
            ltc_amount_sats: 50_000,
            maker_iriumd_pkh: [0xa1u8; 20],
            maker_ltc_pkh: [0xb2u8; 20],
            expiry_height: 250_000,
            order_id: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            expected_hash: if direction == LTC_SWAP_ORDER_DIRECTION_BUY {
                Some([0xcc; 32])
            } else {
                None
            },
        }
    }

    #[test]
    fn ltc_swap_order_sell_script_roundtrip() {
        let o = sample_ltc_swap_order(LTC_SWAP_ORDER_DIRECTION_SELL);
        let s = encode_ltc_swap_order_script(&o);
        assert_eq!(s.len(), LTC_SWAP_ORDER_SELL_SCRIPT_LEN);
        assert_eq!(s[0], LTC_SWAP_ORDER_V1_TAG);
        assert_eq!(s[1], LTC_SWAP_ORDER_V1_VERSION);
        let parsed = parse_ltc_swap_order_script(&s).expect("parse");
        assert_eq!(parsed, o);
    }

    #[test]
    fn ltc_swap_order_buy_script_roundtrip() {
        let o = sample_ltc_swap_order(LTC_SWAP_ORDER_DIRECTION_BUY);
        let s = encode_ltc_swap_order_script(&o);
        assert_eq!(s.len(), LTC_SWAP_ORDER_BUY_SCRIPT_LEN);
        let parsed = parse_ltc_swap_order_script(&s).expect("parse");
        assert_eq!(parsed, o);
    }

    #[test]
    fn ltc_swap_order_dispatches_through_output_encumbrance() {
        let sell = encode_ltc_swap_order_script(&sample_ltc_swap_order(
            LTC_SWAP_ORDER_DIRECTION_SELL,
        ));
        let buy = encode_ltc_swap_order_script(&sample_ltc_swap_order(
            LTC_SWAP_ORDER_DIRECTION_BUY,
        ));
        match parse_output_encumbrance(&sell) {
            OutputEncumbrance::LtcSwapOrder(o) => {
                assert_eq!(o.direction, LTC_SWAP_ORDER_DIRECTION_SELL)
            }
            _ => panic!("expected LtcSwapOrder sell"),
        }
        match parse_output_encumbrance(&buy) {
            OutputEncumbrance::LtcSwapOrder(o) => {
                assert_eq!(o.direction, LTC_SWAP_ORDER_DIRECTION_BUY)
            }
            _ => panic!("expected LtcSwapOrder buy"),
        }
    }

    #[test]
    fn ltc_swap_order_rejects_wrong_tag() {
        let mut s = encode_ltc_swap_order_script(&sample_ltc_swap_order(
            LTC_SWAP_ORDER_DIRECTION_SELL,
        ));
        s[0] = SWAP_ORDER_V1_TAG;
        assert!(parse_ltc_swap_order_script(&s).is_none());
    }

    #[test]
    fn ltc_swap_order_rejects_wrong_direction() {
        let mut s = encode_ltc_swap_order_script(&sample_ltc_swap_order(
            LTC_SWAP_ORDER_DIRECTION_SELL,
        ));
        s[2] = 0x07;
        assert!(parse_ltc_swap_order_script(&s).is_none());
    }

    #[test]
    fn ltc_swap_order_rejects_sell_with_hash_tail() {
        let o = sample_ltc_swap_order(LTC_SWAP_ORDER_DIRECTION_SELL);
        let mut s = encode_ltc_swap_order_script(&o);
        s.extend_from_slice(&[0xdd; 32]);
        assert!(parse_ltc_swap_order_script(&s).is_none());
    }

    #[test]
    fn ltc_swap_order_rejects_buy_without_hash_tail() {
        let mut o = sample_ltc_swap_order(LTC_SWAP_ORDER_DIRECTION_BUY);
        o.expected_hash = None;
        let s = encode_ltc_swap_order_script(&o);
        // Encoder still emits 76 bytes when expected_hash is None even with
        // direction=BUY; parser must reject the length/direction mismatch.
        assert_eq!(s.len(), LTC_SWAP_ORDER_SELL_SCRIPT_LEN);
        assert!(parse_ltc_swap_order_script(&s).is_none());
    }

    #[test]
    fn ltc_swap_order_fill_sell_witness_roundtrip() {
        let sig = vec![0x30, 0x44];
        let pubkey = vec![0x02; 33];
        let taker_pkh = [0x11u8; 20];
        let w = encode_ltc_swap_order_fill_sell_witness(&sig, &pubkey, &taker_pkh, 99_999)
            .expect("encode");
        match parse_ltc_swap_order_witness(&w, LTC_SWAP_ORDER_DIRECTION_SELL).expect("parse") {
            LtcSwapOrderWitness::FillSell {
                sig: s,
                pubkey: pk,
                taker_iriumd_pkh,
                timeout_height,
            } => {
                assert_eq!(s, sig);
                assert_eq!(pk, pubkey);
                assert_eq!(taker_iriumd_pkh, taker_pkh);
                assert_eq!(timeout_height, 99_999);
            }
            _ => panic!("expected FillSell"),
        }
    }

    #[test]
    fn ltc_swap_order_fill_buy_witness_roundtrip() {
        let sig = vec![0x30, 0x44];
        let pubkey = vec![0x02; 33];
        let w = encode_ltc_swap_order_fill_buy_witness(&sig, &pubkey, 42_424).expect("encode");
        match parse_ltc_swap_order_witness(&w, LTC_SWAP_ORDER_DIRECTION_BUY).expect("parse") {
            LtcSwapOrderWitness::FillBuy {
                sig: s,
                pubkey: pk,
                irm_timeout_height,
            } => {
                assert_eq!(s, sig);
                assert_eq!(pk, pubkey);
                assert_eq!(irm_timeout_height, 42_424);
            }
            _ => panic!("expected FillBuy"),
        }
    }

    #[test]
    fn ltc_swap_order_cancel_witness_roundtrip() {
        let sig = vec![0x30, 0x44];
        let pubkey = vec![0x03; 33];
        let w = encode_ltc_swap_order_cancel_witness(&sig, &pubkey).expect("encode");
        match parse_ltc_swap_order_witness(&w, LTC_SWAP_ORDER_DIRECTION_SELL).expect("parse") {
            LtcSwapOrderWitness::Cancel { sig: s, pubkey: pk } => {
                assert_eq!(s, sig);
                assert_eq!(pk, pubkey);
            }
            _ => panic!("expected Cancel"),
        }
    }

    #[test]
    fn ltc_swap_order_expire_sweep_witness_is_single_byte() {
        let w = encode_ltc_swap_order_expire_sweep_witness();
        assert_eq!(w, vec![LTC_SWAP_ORDER_WITNESS_EXPIRE_SWEEP]);
        assert!(matches!(
            parse_ltc_swap_order_witness(&w, LTC_SWAP_ORDER_DIRECTION_SELL),
            Some(LtcSwapOrderWitness::ExpireSweep)
        ));
    }

    #[test]
    fn ltc_swap_order_witness_rejects_unknown_selector() {
        let w = vec![0xff, 0, 0, 0];
        assert!(parse_ltc_swap_order_witness(&w, LTC_SWAP_ORDER_DIRECTION_SELL).is_none());
    }
}
