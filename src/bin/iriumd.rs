// Crate-level lint allows: see src/lib.rs for the rationale. The
// iriumd binary inherits its own allow list because the lib-level
// attributes don't apply to bin targets.
#![allow(clippy::all)]
#![allow(unused_must_use)]
#![allow(clippy::manual_clamp)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]
#![allow(clippy::manual_is_multiple_of)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::if_same_then_else)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::manual_unwrap_or_default)]
#![allow(clippy::while_let_loop)]
#![allow(clippy::empty_line_after_doc_comments)]
#![allow(clippy::empty_line_after_outer_attr)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::len_without_is_empty)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::manual_range_contains)]
#![allow(clippy::new_without_default)]
#![allow(clippy::derivable_impls)]
#![allow(clippy::single_char_add_str)]
#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::len_zero)]
#![allow(clippy::redundant_clone)]
#![allow(clippy::redundant_pattern_matching)]
#![allow(clippy::needless_return)]
#![allow(clippy::useless_vec)]
#![allow(clippy::single_match)]
#![allow(clippy::format_in_format_args)]
#![allow(clippy::let_and_return)]
#![allow(clippy::question_mark)]
#![allow(clippy::redundant_closure)]
#![allow(clippy::collapsible_else_if)]
#![allow(clippy::collapsible_match)]
#![allow(clippy::manual_strip)]
#![allow(clippy::needless_borrow)]
#![allow(clippy::single_char_pattern)]
#![allow(clippy::useless_conversion)]
#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use std::sync::{
    atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering},
    Arc, Mutex, OnceLock,
};
use std::{env, fs};

use axum::{
    extract::{ConnectInfo, DefaultBodyLimit, Json as AxumJson, Path as AxumPath, Query, State},
    http::{
        header::{AUTHORIZATION, CONTENT_TYPE},
        HeaderMap, HeaderValue, Method, StatusCode,
    },
    routing::{get, post},
    Json, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use chrono::Utc;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower_http::cors::{Any, CorsLayer};

use get_if_addrs::get_if_addrs;
use subtle::ConstantTimeEq;
use irium_node_rs::activation::{
    network_kind_from_env, resolved_htlcv1_activation_height, resolved_lwma_activation_height,
    resolved_lwma_v2_activation_height, resolved_mpsov1_activation_height,
    runtime_htlcv1_env_override, runtime_lwma_env_override,
    NetworkKind,
};
use irium_node_rs::anchors::AnchorManager;
use irium_node_rs::block::{Block, BlockHeader};
use irium_node_rs::chain::{
    block_from_locked, ChainParams, ChainState, HeaderWork, LwmaParams, OutPoint,
};
use irium_node_rs::constants::{block_reward, coinbase_maturity, MTP_ACTIVATION_HEIGHT};
use irium_node_rs::genesis::load_locked_genesis;
use irium_node_rs::mempool::{evict_invalid_mempool_entries, MempoolManager, MempoolPriority};
use irium_node_rs::network::SeedlistManager;
use irium_node_rs::network_era::network_era;
use irium_node_rs::p2p::P2PNode;
use irium_node_rs::pow::{meets_target, sha256d, Target};
use irium_node_rs::rate_limiter::RateLimiter;
use irium_node_rs::reputation::ReputationManager;
use irium_node_rs::settlement::{
    agreement_short_hash_from_full, basic_otc_escrow_template, build_agreement_activity_timeline,
    build_agreement_anchor_output, build_agreement_audit_record, build_funding_legs,
    build_reputation_event_output, compute_agreement_hash_hex, contractor_milestone_template,
    derive_lifecycle, discover_agreement_funding_leg_candidates, evaluate_policy,
    extract_agreement_funding_leg_refs_from_tx, parse_agreement_anchor, parse_reputation_event,
    policy_template_to_json, preorder_deposit_template, verify_agreement_bundle,
    AgreementActivityEvent, AgreementAnchor, AgreementAnchorRole, AgreementAuditFundingLegRecord,
    AgreementAuditRecord, AgreementBundle, AgreementFundingLegRef, AgreementLifecycleView,
    AgreementLinkedTx, AgreementMilestoneStatus, AgreementObject, AgreementSignatureEnvelope,
    AgreementSummary, AgreementTemplateType, DisputeEvidence, DisputeRaise, DisputeResolution,
    EscrowReceiptDisputeRef, EscrowReceiptProofRef, HoldbackEvaluationResult,
    MilestoneEvaluationResult, MilestoneSpec, PolicyOutcome, PolicyStore, ProofPolicy, ProofStore,
    ReputationEvent, ReputationEventKind, RequirementThresholdResult, ResolverRegistration,
    SettlementProof, TemplateAttestor, TxidWithHeight, AGREEMENT_SIGNATURE_TYPE_SECP256K1,
    DisputeReResolverNomination,
    dispute_evidence_canonical_bytes, dispute_raise_canonical_bytes,
    dispute_reresolve_canonical_bytes, dispute_resolution_canonical_bytes,
    resolver_registration_canonical_bytes,
};
use k256::ecdsa::VerifyingKey;
use irium_node_rs::storage;
use irium_node_rs::tx::{
    compute_funding_binding, decode_full_tx, encode_htlc_btc_swap_claim_witness,
    encode_htlc_btc_swap_refund_witness, encode_htlc_btc_swap_v1_script,
    encode_htlc_ltc_swap_claim_witness, encode_htlc_ltc_swap_refund_witness,
    encode_htlc_ltc_swap_v1_script, encode_ltc_swap_order_cancel_witness,
    encode_ltc_swap_order_expire_sweep_witness,
    encode_ltc_swap_order_fill_buy_witness, encode_ltc_swap_order_fill_sell_witness,
    encode_ltc_swap_order_script, parse_htlc_ltc_swap_v1_script,
    parse_ltc_swap_order_script,
    HtlcLtcSwapV1Output, LtcSwapOrderOutput,
    LTC_SWAP_ORDER_DIRECTION_BUY, LTC_SWAP_ORDER_DIRECTION_SELL,
    LTC_SWAP_ORDER_MAX_SWEEP_FEE, LTC_SWAP_ORDER_MIN_LOCKED_VALUE,
    MAX_HTLC_LTC_SWAP_CONFIRMATIONS, MIN_HTLC_LTC_SWAP_CONFIRMATIONS,
    encode_htlcv1_claim_witness, encode_htlcv1_refund_witness, encode_htlcv1_script,
    encode_swap_order_cancel_witness, encode_swap_order_expire_sweep_witness,
    encode_swap_order_fill_buy_witness, encode_swap_order_fill_sell_witness,
    encode_swap_order_script, parse_htlc_btc_swap_v1_script, parse_htlcv1_script,
    parse_output_encumbrance, parse_swap_order_script, HtlcBtcSwapV1Output, HtlcV1Output,
    OutputEncumbrance, SwapOrderOutput, Transaction, TxInput, TxOutput,
    MAX_HTLC_BTC_SWAP_CONFIRMATIONS, MIN_HTLC_BTC_SWAP_CONFIRMATIONS,
    SWAP_ORDER_DIRECTION_BUY, SWAP_ORDER_DIRECTION_SELL, SWAP_ORDER_MAX_SWEEP_FEE,
    SWAP_ORDER_MIN_LOCKED_VALUE,
};
use irium_node_rs::btc_spv::{
    apply_btc_header_batch, encode_btc_header_batch, parse_btc_header_batch,
    resolve_btc_spv_params, BtcAnchor, BtcHeader, BtcHeaderEntry, BTC_HEADER_BYTES,
    MAX_BTC_HEADERS_PER_BATCH,
};
use irium_node_rs::ltc_spv::{
    encode_ltc_header_batch, parse_ltc_header_batch, LtcAnchor, LtcHeader, LtcHeaderEntry,
    LTC_HEADER_BYTES, MAX_LTC_HEADERS_PER_BATCH,
};
use irium_node_rs::wallet_store::{WalletKey, WalletManager, WalletMode};
use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::IntoResponse;
// futures_util stream/sink imports removed (unused)
use tokio::sync::broadcast;
use std::convert::Infallible;

const WS_BROADCAST_CAPACITY: usize = 1024;
type EventTx = broadcast::Sender<std::sync::Arc<String>>;

const IRIUM_P2PKH_VERSION: u8 = 0x39;
const MAX_SUBMIT_BLOCK_TXS: usize = 10_000;
#[derive(Clone)]
struct AppState {
    chain: Arc<Mutex<ChainState>>,
    genesis_hash: String,
    mempool: Arc<Mutex<MempoolManager>>,
    wallet: Arc<Mutex<WalletManager>>,
    anchors: Option<AnchorManager>,
    p2p: Option<P2PNode>,
    limiter: Arc<Mutex<RateLimiter>>,
    status_height_cache: Arc<AtomicU64>,
    status_peer_count_cache: Arc<AtomicUsize>,
    status_sybil_cache: Arc<AtomicU8>,
    status_persisted_height_cache: Arc<AtomicU64>,
    status_persist_queue_cache: Arc<AtomicUsize>,
    status_persisted_contiguous_cache: Arc<AtomicU64>,
    status_persisted_max_on_disk_cache: Arc<AtomicU64>,
    status_quarantine_count_cache: Arc<AtomicU64>,
    status_persisted_window_tip_cache: Arc<AtomicU64>,
    status_missing_persisted_in_window_cache: Arc<AtomicU64>,
    status_missing_or_mismatch_in_window_cache: Arc<AtomicU64>,
    status_expected_hash_coverage_in_window_cache: Arc<AtomicU64>,
    status_expected_hash_window_span_cache: Arc<AtomicU64>,
    status_best_header_hash_cache: Arc<Mutex<String>>,
    proof_store: Arc<Mutex<ProofStore>>,
    policy_store: Arc<Mutex<PolicyStore>>,
    event_tx: EventTx,
    /// Maps proof_id → chain tip height at submission time (Phase 7 finality tracking).
    proof_heights: Arc<Mutex<std::collections::HashMap<String, u64>>>,
    /// Dispute index keyed by agreement_hash hex (Stage 3.2).
    disputes_index: Arc<Mutex<std::collections::HashMap<String, DisputeState>>>,
    /// Resolver registration index keyed by resolver_address (Stage 3.2).
    resolvers_index: Arc<Mutex<std::collections::HashMap<String, ResolverRegistrationRecord>>>,
    /// v1.9.61: latest BTC header batch cached for direct block-template
    /// injection. Populated by run_btc_header_sync_cycle; consumed by
    /// build_template_btc_batch inside getblocktemplate.
    btc_template_headers_cache: Arc<Mutex<Option<CachedHeaderBatchForTemplate>>>,
    /// v1.9.61: same as above for LTC.
    ltc_template_headers_cache: Arc<Mutex<Option<CachedHeaderBatchForTemplate>>>,
}

const DISPUTE_RESOLVER_RESPONSE_WINDOW: u64 = 288; // blocks
const MINER_RECENCY_WINDOW: u64 = 2016;            // blocks
const DISPUTE_ANCHOR_FEE_PER_BYTE: u64 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DisputeState {
    raise: DisputeRaise,
    raise_anchor_txid: Option<String>,
    raise_anchored_at_height: Option<u64>,
    evidence: Vec<DisputeEvidenceRecord>,
    resolution: Option<DisputeResolution>,
    resolution_anchor_txid: Option<String>,
    resolution_anchored_at_height: Option<u64>,
    escalated_to_fallback: bool,
    escalated_at_height: Option<u64>,
    #[serde(default)]
    reresolve_nomination: Option<DisputeReResolverNomination>,
}

impl DisputeState {
    fn is_open(&self) -> bool {
        self.resolution.is_none()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DisputeEvidenceRecord {
    evidence: DisputeEvidence,
    anchor_txid: Option<String>,
    anchored_at_height: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResolverRegistrationRecord {
    registration: ResolverRegistration,
    anchor_txid: Option<String>,
    anchored_at_height: Option<u64>,
}

fn proof_finality_depth() -> u64 {
    std::env::var("IRIUM_PROOF_FINALITY_DEPTH")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(6)
}

fn emit_event(tx: &EventTx, event_type: &str, data: serde_json::Value) {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let json = serde_json::json!({
        "type": event_type,
        "ts": ts,
        "data": data,
    })
    .to_string();
    let _ = tx.send(std::sync::Arc::new(json));
}

fn ws_event_matches(event_type: &str, subscribed: &HashSet<String>) -> bool {
    if subscribed.contains(event_type) {
        return true;
    }
    for pattern in subscribed {
        if pattern == "*" {
            return true;
        }
        if let Some(prefix) = pattern.strip_suffix(".*") {
            if event_type.starts_with(&format!("{}.", prefix)) {
                return true;
            }
        }
    }
    false
}

fn ws_is_public_event(event_type: &str) -> bool {
    matches!(
        event_type,
        "block.new"
            | "offer.created"
            | "agreement.proof_reorged"
            | "dispute.raised"
            | "dispute.evidence_submitted"
            | "dispute.resolved"
            | "dispute.escalated"
            | "dispute.raise_anchored"
            | "dispute.resolve_anchored"
            | "dispute.reresolved"
            | "resolver.registered"
    )
}

async fn ws_handle_socket(mut socket: WebSocket, state: AppState, is_public_conn: bool) {
    let mut rx = state.event_tx.subscribe();
    let mut subscribed: HashSet<String> = HashSet::new();
    let mut agreement_filter: Option<String> = None;
    let mut has_subscribed = false;

    loop {
        tokio::select! {
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) {
                            if val.get("action").and_then(|a| a.as_str()) == Some("subscribe") {
                                if let Some(events) = val.get("events").and_then(|e| e.as_array()) {
                                    subscribed.clear();
                                    for ev in events {
                                        if let Some(s) = ev.as_str() {
                                            subscribed.insert(s.to_string());
                                        }
                                    }
                                    has_subscribed = true;
                                }
                                if let Some(filter) = val.get("filter")
                                    .and_then(|f| f.get("agreement_hash"))
                                    .and_then(|h| h.as_str()) {
                                    agreement_filter = Some(filter.to_string());
                                }
                                let ack = serde_json::json!({
                                    "type": "subscribed",
                                    "events": subscribed.iter().collect::<Vec<_>>()
                                });
                                if socket.send(Message::Text(ack.to_string())).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => return,
                    Some(Ok(Message::Ping(data))) => {
                        let _ = socket.send(Message::Pong(data)).await;
                    }
                    _ => {}
                }
            }
            event_result = rx.recv() => {
                match event_result {
                    Ok(json_arc) => {
                        if has_subscribed && !subscribed.is_empty() {
                            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json_arc) {
                                let et = val.get("type").and_then(|t| t.as_str()).unwrap_or("");
                                if !ws_event_matches(et, &subscribed) {
                                    continue;
                                }
                                if is_public_conn && !ws_is_public_event(et) {
                                    continue;
                                }
                                if let Some(ref af) = agreement_filter {
                                    let ah = val.get("data")
                                        .and_then(|d| d.get("agreement_hash"))
                                        .and_then(|h| h.as_str());
                                    if ah != Some(af.as_str()) {
                                        continue;
                                    }
                                }
                            }
                        } else if is_public_conn {
                            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json_arc) {
                                let et = val.get("type").and_then(|t| t.as_str()).unwrap_or("");
                                if !ws_is_public_event(et) {
                                    continue;
                                }
                            }
                        }
                        if socket.send(Message::Text((*json_arc).clone())).await.is_err() {
                            return;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        let warn = serde_json::json!({"type":"warn","msg":format!("lagged, {} events dropped",n)});
                        let _ = socket.send(Message::Text(warn.to_string())).await;
                    }
                    Err(_) => return,
                }
            }
        }
    }
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(_addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    let ws_public = std::env::var("IRIUM_WS_PUBLIC")
        .map(|v| v.trim().to_lowercase() == "true")
        .unwrap_or(false);
    let token_required = std::env::var("IRIUM_RPC_TOKEN")
        .map(|t| !t.trim().is_empty())
        .unwrap_or(false);
    if token_required && !ws_public
        && require_rpc_auth(&headers).is_err() {
            return (StatusCode::UNAUTHORIZED, "Bearer token required").into_response();
        }
    let is_public_conn = ws_public && require_rpc_auth(&headers).is_err();
    ws.on_upgrade(move |socket| ws_handle_socket(socket, state, is_public_conn))
}

async fn sse_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(_addr): ConnectInfo<SocketAddr>,
) -> Result<Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>>, StatusCode> {
    let ws_public = std::env::var("IRIUM_WS_PUBLIC")
        .map(|v| v.trim().to_lowercase() == "true")
        .unwrap_or(false);
    let token_required = std::env::var("IRIUM_RPC_TOKEN")
        .map(|t| !t.trim().is_empty())
        .unwrap_or(false);
    if token_required && !ws_public {
        require_rpc_auth(&headers)?;
    }
    let is_public_conn = ws_public && require_rpc_auth(&headers).is_err();
    let rx = state.event_tx.subscribe();
    let stream = futures_util::stream::unfold(
        (rx, is_public_conn),
        |(mut rx, is_pub)| async move {
            loop {
                match rx.recv().await {
                    Ok(json_arc) => {
                        if is_pub {
                            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json_arc) {
                                let et = val.get("type").and_then(|t| t.as_str()).unwrap_or("");
                                if !ws_is_public_event(et) {
                                    continue;
                                }
                            }
                        }
                        let ev = Event::default().data((*json_arc).clone());
                        return Some((Ok::<Event, Infallible>(ev), (rx, is_pub)));
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => return None,
                }
            }
        },
    );
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}


#[derive(Serialize)]
struct PeerInfo {
    multiaddr: String,
    agent: Option<String>,
    source: Option<String>,
    height: Option<u64>,
    last_seen: f64,
    dialable: bool,
    last_successful_handshake: Option<f64>,
}

#[derive(Serialize)]
struct PeersResponse {
    peers: Vec<PeerInfo>,
}

#[derive(Serialize)]
struct BestHeaderTipResponse {
    height: u64,
    hash: String,
}

/// The only currency the IRIUM settlement layer recognises. Consensus
/// enforces this via the `network_marker == "IRIUM"` check in
/// `AgreementObject::validate()`; this constant gives the HTTP surface
/// a single source of truth and lets wallet clients gate their UI on
/// `currency == "IRM"` without parsing the agreement JSON.
const SETTLEMENT_CURRENCY: &str = "IRM";

#[derive(Serialize)]
struct StatusResponse {
    height: u64,
    genesis_hash: String,
    network_era: String,
    network_era_description: String,
    network_era_tagline: Option<String>,
    early_participation_signal: bool,
    anchors_digest: Option<String>,
    peer_count: usize,
    anchor_loaded: bool,
    node_id: Option<String>,
    sybil_difficulty: Option<u8>,
    best_header_tip: BestHeaderTipResponse,
    persisted_height: u64,
    persist_queue_len: usize,
    persisted_contiguous_height: u64,
    persisted_max_height_on_disk: u64,
    quarantine_count: u64,
    persisted_window_tip: u64,
    missing_persisted_in_window: u64,
    missing_or_mismatch_in_window: u64,
    expected_hash_coverage_in_window: u64,
    expected_hash_window_span: u64,
    gap_healer_active: bool,
    gap_healer_last_progress_ts: u64,
    gap_healer_last_filled_height: Option<u64>,
    gap_healer_pending_count: u64,
    /// Current minimum fee rate in satoshis per serialised byte. Equal to
    /// `ceil(mempool.min_fee_per_byte())`, floored at 1 - matches the
    /// default `wallet_send` uses when no `fee_per_byte` override or
    /// `fee_mode` is supplied. Wallets can read this directly without a
    /// second call to `/rpc/fee_estimate`.
    fee_rate_sat_per_byte: u64,
}

#[derive(Serialize)]
struct UtxoResponse {
    value: u64,
    height: u64,
    is_coinbase: bool,
}

#[derive(Deserialize)]
struct NetworkHashrateQuery {
    window: Option<usize>,
}

#[derive(Serialize)]
struct NetworkHashrateResponse {
    tip_height: u64,
    current_network_era: String,
    current_network_era_description: String,
    current_network_era_tagline: Option<String>,
    early_participation_signal: bool,
    difficulty: f64,
    hashrate: Option<f64>,
    avg_block_time: Option<f64>,
    window: usize,
    sample_blocks: usize,
}

#[derive(Serialize)]
struct NetworkStatusResponse {
    height: u64,
    tip_hash: String,
    peer_count: usize,
    difficulty: f64,
    hashrate_estimate: Option<f64>,
    seconds_since_last_block: Option<u64>,
    node_version: &'static str,
}

#[derive(Deserialize)]
struct MiningMetricsQuery {
    window: Option<usize>,
    series: Option<usize>,
}

#[derive(Serialize, Clone)]
struct MiningMetricsPoint {
    height: u64,
    time: u64,
    difficulty: f64,
}

#[derive(Serialize)]
struct MiningMetricsResponse {
    tip_height: u64,
    tip_time: u64,
    current_network_era: String,
    current_network_era_description: String,
    current_network_era_tagline: Option<String>,
    early_participation_signal: bool,

    difficulty: f64,
    hashrate: Option<f64>,
    avg_block_time: Option<f64>,

    window: usize,
    sample_blocks: usize,

    difficulty_1h: Option<f64>,
    difficulty_24h: Option<f64>,
    difficulty_change_1h_pct: Option<f64>,
    difficulty_change_24h_pct: Option<f64>,

    series: Vec<MiningMetricsPoint>,
}

#[derive(Serialize)]
struct BalanceResponse {
    address: String,
    pkh: String,
    balance: u64,
    mined_balance: u64,
    utxo_count: usize,
    mined_blocks: usize,
    height: u64,
}

#[derive(Serialize)]
struct UtxoItem {
    txid: String,
    index: u32,
    value: u64,
    height: u64,
    is_coinbase: bool,
    script_pubkey: String,
}

#[derive(Serialize)]
struct UtxosResponse {
    address: String,
    pkh: String,
    height: u64,
    utxos: Vec<UtxoItem>,
}

// Rich-list response shapes. Surfaced by /rpc/richlist?limit=N. See
// get_richlist for behaviour notes (single chain-lock pass, non-P2PKH
// outputs excluded from entries but counted in total_supply_sats,
// deterministic tie-break by raw PKH).
#[derive(Serialize)]
struct RichlistEntry {
    rank: u32,
    address: String,
    balance_sats: u64,
    balance_irm: f64,
    utxo_count: u32,
    percentage: f64,
}

#[derive(Serialize)]
struct RichlistResponse {
    count: usize,
    total_supply_sats: u64,
    generated_at_height: u64,
    entries: Vec<RichlistEntry>,
}

#[derive(Serialize)]
struct HistoryItem {
    txid: String,
    height: u64,
    received: u64,
    spent: u64,
    net: i64,
    is_coinbase: bool,
}

#[derive(Serialize)]
struct HistoryResponse {
    address: String,
    pkh: String,
    height: u64,
    txs: Vec<HistoryItem>,
}

#[derive(Serialize)]
struct FeeEstimateResponse {
    min_fee_per_byte: f64,
    mempool_size: usize,
}

#[derive(Deserialize)]
struct UtxoQuery {
    txid: String,
    index: u32,
}

#[derive(Deserialize)]
struct BalanceQuery {
    address: String,
}

#[derive(Deserialize)]
struct UtxosQuery {
    address: String,
}

// Rich-list query — limit clamped to [1, 500] inside the handler so a
// malicious caller can't force base58-encoding of the whole address space.
#[derive(Deserialize)]
struct RichlistQuery {
    limit: Option<u32>,
}

#[derive(Deserialize)]
struct BlockQuery {
    height: u64,
}

#[derive(Deserialize)]
struct BlocksQuery {
    from: u64,
    count: u64,
}

#[derive(Deserialize)]
struct BlockHashQuery {
    hash: String,
}

#[derive(Deserialize)]
struct TemplateQuery {
    longpoll: Option<u8>,
    poll_secs: Option<u64>,
    max_txs: Option<usize>,
    min_fee: Option<f64>,
}

#[derive(Deserialize)]
struct SubmitTxRequest {
    tx_hex: String,
}

#[derive(Deserialize)]
struct TxQuery {
    txid: String,
}

#[derive(Serialize)]
struct TxLookupResponse {
    txid: String,
    height: u64,
    index: usize,
    block_hash: String,
    inputs: usize,
    outputs: usize,
    output_value: u64,
    is_coinbase: bool,
    tx_hex: String,
    // Fix C: when the tx is in mempool but not yet in a block, this
    // field is true and `height` / `index` / `block_hash` carry sentinel
    // values (0 / 0 / ""). `#[serde(default)]` keeps backward-compat
    // for any deserializer reading older responses.
    #[serde(default)]
    pending: bool,
}

// Fix D: pending-tx lookup. Returned by /rpc/mempool/by_txid. Slimmer
// than TxLookupResponse because confirmed-only fields are meaningless
// for a tx that's still in mempool.
#[derive(Serialize)]
struct MempoolByTxidResponse {
    txid: String,
    tx_hex: String,
    fee: u64,
    size: usize,
    fee_per_byte: f64,
    added_unix: u64,
    inputs: usize,
    outputs: usize,
    output_value: u64,
}

// Fix D: enumerates outpoints currently pending-spent by mempool
// entries that consume an output owned by the queried address. Wallet
// uses this (Fix A) to subtract pending-spent UTXOs from /rpc/utxos
// before coin selection, avoiding the multi-send race that produced
// ghost-tx symptoms.
#[derive(Serialize)]
struct MempoolSpentByResponse {
    address: String,
    outpoints: Vec<MempoolSpentEntry>,
}

#[derive(Serialize)]
struct MempoolSpentEntry {
    prev_txid: String,
    prev_index: u32,
    claiming_txid: String,
}

#[derive(Serialize)]
struct SubmitTxResponse {
    txid: String,
    accepted: bool,
    // BUG 1 fix: previously every non-2xx response carried an empty body
    // ({txid:"", accepted:false}) so the wallet client surfaced an opaque
    // "submit tx failed: 400 Bad Request" with no detail. The detailed
    // reason was eprintln!()-ed to iriumd's stderr but never wired into
    // the HTTP response. Now populated on every error branch; omitted
    // from the JSON on the success path via skip_serializing_if so
    // existing clients see no change for a successful submit.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

#[derive(Deserialize)]
struct WalletCreateRequest {
    passphrase: String,
    seed_hex: Option<String>,
}

#[derive(Deserialize)]
struct WalletUnlockRequest {
    passphrase: String,
}

#[derive(Deserialize)]
struct WalletSendRequest {
    to_address: String,
    /// Required when `send_max` is false / unset; ignored when `send_max` is true.
    #[serde(default)]
    amount: Option<String>,
    from_address: Option<String>,
    fee_mode: Option<String>,
    fee_per_byte: Option<u64>,
    coin_select: Option<String>,
    /// Sweep every spendable UTXO from `from_address` (or the whole wallet
    /// when `from_address` is None) to `to_address`, minus the fee. The fee
    /// is `size_bytes * fee_per_byte`, floored at 10_000 sats so it always
    /// clears the mempool minimum. `amount` and `coin_select` are ignored.
    #[serde(default)]
    send_max: Option<bool>,
}

#[derive(Deserialize)]
struct WalletImportWifRequest {
    wif: String,
}

#[derive(Deserialize)]
struct WalletImportSeedRequest {
    seed_hex: String,
    force: Option<bool>,
}

#[derive(Deserialize)]
struct WalletExportWifQuery {
    address: String,
}

#[derive(Serialize)]
struct WalletCreateResponse {
    address: String,
    wallet_path: String,
}

#[derive(Serialize)]
struct WalletUnlockResponse {
    addresses: Vec<String>,
    current_address: String,
}

#[derive(Serialize)]
struct WalletAddressesResponse {
    addresses: Vec<String>,
}

#[derive(Serialize)]
struct WalletReceiveResponse {
    address: String,
}

#[derive(Serialize)]
struct WalletLockResponse {
    locked: bool,
}

#[derive(Serialize)]
struct WalletInfoResponse {
    exists: bool,
    mode: WalletMode,
    path: String,
    is_unlocked: bool,
    plaintext_backups: Vec<String>,
}

#[derive(Deserialize)]
struct WalletMigrateRequest {
    passphrase: String,
}

#[derive(Serialize)]
struct WalletMigrateResponse {
    path: String,
    addresses: Vec<String>,
    mode: WalletMode,
}

#[derive(Deserialize)]
struct WalletRecoverRequest {
    /// 64-hex (custom derivation) or 128-hex (BIP32 seed bytes).
    seed_hex: String,
    passphrase: String,
    #[serde(default)]
    allow_overwrite: bool,
}

#[derive(Serialize)]
struct WalletRecoverResponse {
    address: String,
    path: String,
}

#[derive(Serialize)]
struct WalletSendResponse {
    txid: String,
    accepted: bool,
    fee: u64,
    total_input: u64,
    change: u64,
}

#[derive(Deserialize)]
struct CreateHtlcRequest {
    amount: String,
    recipient_address: String,
    refund_address: String,
    secret_hash_hex: String,
    timeout_height: u64,
    fee_per_byte: Option<u64>,
    broadcast: Option<bool>,
}

#[derive(Serialize)]
struct CreateHtlcResponse {
    txid: String,
    accepted: bool,
    raw_tx_hex: String,
    htlc_vout: u32,
    expected_hash: String,
    timeout_height: u64,
    recipient_address: String,
    refund_address: String,
}

#[derive(Deserialize)]
struct DecodeHtlcRequest {
    raw_tx_hex: String,
    vout: Option<u32>,
}

#[derive(Serialize)]
struct DecodeHtlcResponse {
    found: bool,
    vout: Option<u32>,
    output_type: String,
    expected_hash: Option<String>,
    timeout_height: Option<u64>,
    recipient_address: Option<String>,
    refund_address: Option<String>,
}

#[derive(Deserialize)]
struct SpendHtlcRequest {
    funding_txid: String,
    vout: u32,
    destination_address: String,
    fee_per_byte: Option<u64>,
    broadcast: Option<bool>,
    secret_hex: Option<String>,
}

#[derive(Serialize)]
struct SpendHtlcResponse {
    txid: String,
    accepted: bool,
    raw_tx_hex: String,
    fee: u64,
}

#[derive(Deserialize)]
struct InspectHtlcQuery {
    txid: String,
    vout: u32,
}

#[derive(Serialize)]
struct InspectHtlcResponse {
    exists: bool,
    funded: bool,
    unspent: bool,
    spent: bool,
    spend_type: Option<String>,
    claimable_now: bool,
    refundable_now: bool,
    timeout_height: Option<u64>,
    expected_hash: Option<String>,
    recipient_address: Option<String>,
    refund_address: Option<String>,
}

#[derive(Deserialize)]
struct AgreementRequest {
    agreement: AgreementObject,
}

#[derive(Deserialize)]
struct FundAgreementRequest {
    agreement: AgreementObject,
    fee_per_byte: Option<u64>,
    broadcast: Option<bool>,
    /// GROUP G: when set, fund only the named milestone leg. Builds a
    /// single-HTLC funding tx for that milestone instead of the full
    /// agreement. Rejected if the milestone is not in the agreement OR
    /// already has a confirmed Funding anchor on-chain.
    #[serde(default)]
    milestone_id: Option<String>,
}

#[derive(Serialize)]
struct AgreementHashResponse {
    agreement_hash: String,
}

#[derive(Serialize)]
struct AgreementInspectResponse {
    agreement_hash: String,
    summary: AgreementSummary,
    /// Always "IRM". The settlement layer is currency-locked at consensus.
    currency: &'static str,
}

#[derive(Serialize)]
struct AgreementTxsResponse {
    agreement_hash: String,
    txs: Vec<AgreementLinkedTx>,
}

#[derive(Serialize)]
struct AgreementStatusResponse {
    agreement_hash: String,
    lifecycle: AgreementLifecycleView,
    /// Number of blocks since the most recent proof for this agreement was submitted.
    /// None when no proofs exist.
    proof_depth: Option<u64>,
    /// True when proof_depth >= IRIUM_PROOF_FINALITY_DEPTH (default 6).
    proof_final: bool,
    /// True when the lifecycle indicates release eligibility AND proof_final is true.
    release_eligible: bool,
}

#[derive(Serialize)]
struct AgreementMilestonesResponse {
    agreement_hash: String,
    state: String,
    milestones: Vec<AgreementMilestoneStatus>,
}

// GROUP F: GET /rpc/agreementreceipt?agreement_hash=<hex>
// Query params + response shape. iriumd returns only on-chain-derivable
// fields; the wallet enriches with its local AgreementObject (parties,
// template_type, total_amount, per-milestone amounts) and signs the
// final receipt.
#[derive(Deserialize)]
struct AgreementReceiptQuery {
    agreement_hash: String,
}

#[derive(Serialize)]
struct AgreementReceiptResponse {
    agreement_hash: String,
    tip_height: u64,
    /// Best-effort state classification using only on-chain anchors.
    /// Authoritative state (which knows per-milestone target amounts)
    /// is computed wallet-side by overlaying the local AgreementObject.
    final_state_hint: String,
    funding_txids: Vec<TxidWithHeight>,
    release_txids: Vec<TxidWithHeight>,
    refund_txids: Vec<TxidWithHeight>,
    resolved_height: Option<u64>,
    linked_txs: Vec<AgreementLinkedTx>,
    proofs: Vec<EscrowReceiptProofRef>,
    dispute: Option<EscrowReceiptDisputeRef>,
}

#[derive(Deserialize)]
struct AgreementContextRequest {
    agreement: AgreementObject,
    #[serde(default)]
    bundle: Option<AgreementBundle>,
}

#[derive(Serialize, Deserialize, Clone)]
struct AgreementFundingLegCandidateResponse {
    agreement_hash: String,
    funding_txid: String,
    htlc_vout: u32,
    anchor_vout: u32,
    role: AgreementAnchorRole,
    milestone_id: Option<String>,
    amount: u64,
    htlc_backed: bool,
    timeout_height: u64,
    recipient_address: String,
    refund_address: String,
    source_notes: Vec<String>,
    release_eligible: bool,
    release_reasons: Vec<String>,
    refund_eligible: bool,
    refund_reasons: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct AgreementFundingLegsResponse {
    agreement_hash: String,
    selection_required: bool,
    candidates: Vec<AgreementFundingLegCandidateResponse>,
    trust_model_note: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct AgreementTimelineResponse {
    agreement_hash: String,
    lifecycle: AgreementLifecycleView,
    events: Vec<AgreementActivityEvent>,
    trust_model_note: String,
}

#[derive(Deserialize)]
struct VerifyAgreementLinkRequest {
    agreement_hash: String,
    tx_hex: String,
}

#[derive(Serialize)]
struct VerifyAgreementLinkResponse {
    agreement_hash: String,
    matched: bool,
    anchors: Vec<AgreementAnchor>,
}

#[derive(Serialize)]
struct AgreementFundingOutput {
    vout: u32,
    role: AgreementAnchorRole,
    milestone_id: Option<String>,
    amount: u64,
}

#[derive(Serialize)]
struct FundAgreementResponse {
    agreement_hash: String,
    txid: String,
    accepted: bool,
    raw_tx_hex: String,
    outputs: Vec<AgreementFundingOutput>,
    fee: u64,
}

#[derive(Deserialize)]
struct AgreementSpendRequest {
    agreement: AgreementObject,
    funding_txid: String,
    htlc_vout: Option<u32>,
    milestone_id: Option<String>,
    destination_address: Option<String>,
    fee_per_byte: Option<u64>,
    broadcast: Option<bool>,
    secret_hex: Option<String>,
}

#[derive(Serialize)]
struct AgreementSpendEligibilityResponse {
    agreement_hash: String,
    agreement_id: String,
    funding_txid: String,
    htlc_vout: Option<u32>,
    anchor_vout: Option<u32>,
    role: Option<AgreementAnchorRole>,
    milestone_id: Option<String>,
    amount: Option<u64>,
    branch: String,
    htlc_backed: bool,
    funded: bool,
    unspent: bool,
    preimage_required: bool,
    timeout_height: Option<u64>,
    timeout_reached: bool,
    destination_address: Option<String>,
    expected_hash: Option<String>,
    recipient_address: Option<String>,
    refund_address: Option<String>,
    eligible: bool,
    reasons: Vec<String>,
    trust_model_note: String,
}

#[derive(Serialize)]
struct AgreementBuildSpendResponse {
    agreement_hash: String,
    agreement_id: String,
    funding_txid: String,
    htlc_vout: u32,
    role: AgreementAnchorRole,
    milestone_id: Option<String>,
    branch: String,
    destination_address: String,
    txid: String,
    accepted: bool,
    raw_tx_hex: String,
    fee: u64,
    trust_model_note: String,
}

#[derive(Deserialize)]
struct SubmitProofRequest {
    proof: SettlementProof,
}

#[derive(Debug, Serialize)]
struct SubmitProofResponse {
    proof_id: String,
    agreement_hash: String,
    accepted: bool,
    duplicate: bool,
    message: String,
    /// Chain tip height at submit time.
    tip_height: u64,
    /// Expiry height carried in the submitted proof, if any.
    expires_at_height: Option<u64>,
    /// True when tip_height >= expires_at_height at submit time. False when expires_at_height is None.
    expired: bool,
    /// Derived lifecycle status: "active" or "expired". Consistent with listproofs per-proof status.
    status: String,
}

#[derive(Deserialize)]
struct ListPoliciesRequest {
    /// When true, return only policies that are not expired at the current tip height.
    /// Defaults to false (return all policies).
    #[serde(default)]
    active_only: bool,
}

#[derive(Debug, Serialize)]
struct PolicySummary {
    agreement_hash: String,
    policy_id: String,
    required_proofs: usize,
    attestors: usize,
    expires_at_height: Option<u64>,
    expired: bool,
}

#[derive(Debug, Serialize)]
struct ListPoliciesResponse {
    count: usize,
    policies: Vec<PolicySummary>,
    /// Reflects the active_only filter that was applied.
    active_only: bool,
}

#[derive(Deserialize, Default)]
struct ListProofsRequest {
    /// Filter by agreement hash. When absent, all proofs are returned.
    #[serde(default)]
    agreement_hash: Option<String>,
    /// When true, only proofs that are not expired at the current tip are returned.
    #[serde(default)]
    active_only: bool,
    /// Number of proofs to skip before returning results. Default: 0.
    #[serde(default)]
    offset: u32,
    /// Maximum number of proofs to return. When absent, all matching proofs are returned.
    #[serde(default)]
    limit: Option<u32>,
}

fn proof_lifecycle_status(expires_at_height: Option<u64>, tip_height: u64) -> &'static str {
    match expires_at_height {
        None => "active",
        Some(h) if tip_height < h => "active",
        Some(_) => "expired",
    }
}

#[derive(Serialize)]
struct ProofStatusEntry {
    #[serde(flatten)]
    proof: SettlementProof,
    /// Derived lifecycle status: "active" or "expired".
    status: String,
}

#[derive(Serialize)]
struct ListProofsResponse {
    agreement_hash: String,
    /// Chain tip height at the time of the query.
    tip_height: u64,
    /// Echoes the active_only filter from the request.
    active_only: bool,
    /// Total number of proofs that matched the filters before pagination was applied.
    total_count: usize,
    /// Number of proofs returned in this page. Equals proofs.len().
    returned_count: usize,
    /// True when more proofs remain after this page (total_count > offset + returned_count).
    has_more: bool,
    /// Echoes the offset from the request.
    offset: u32,
    /// Echoes the limit from the request. Null when no limit was requested.
    limit: Option<u32>,
    proofs: Vec<ProofStatusEntry>,
}

#[derive(Deserialize)]
struct CheckPolicyRequest {
    agreement: AgreementObject,
    policy: ProofPolicy,
    #[serde(default)]
    proofs: Vec<SettlementProof>,
}

#[derive(Debug, Serialize)]
struct CheckPolicyResponse {
    agreement_hash: String,
    policy_id: String,
    tip_height: u64,
    release_eligible: bool,
    refund_eligible: bool,
    reason: String,
    evaluated_rules: Vec<String>,
    /// Top-level holdback result; absent when no holdback is declared on the policy.
    /// `None` on the milestone path (per-milestone holdbacks are in `milestone_results`).
    #[serde(skip_serializing_if = "Option::is_none")]
    holdback: Option<HoldbackEvaluationResult>,
    /// Per-milestone evaluation results; absent when no milestones are declared.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    milestone_results: Vec<MilestoneEvaluationResult>,
}

#[derive(Deserialize)]
struct EvaluatePolicyRequest {
    agreement: AgreementObject,
}

#[derive(Debug, Serialize)]
struct EvaluatePolicyResponse {
    /// Deterministic classification: "satisfied", "timeout", or "unsatisfied".
    outcome: PolicyOutcome,
    agreement_hash: String,
    policy_found: bool,
    policy_id: Option<String>,
    tip_height: u64,
    /// Total active (non-expired) proofs considered for evaluation.
    proof_count: usize,
    /// Proofs filtered out as expired before evaluation.
    expired_proof_count: usize,
    /// Proofs that passed signature verification and matched the policy.
    matched_proof_count: usize,
    /// IDs of proofs that passed signature verification.
    matched_proof_ids: Vec<String>,
    expired: bool,
    release_eligible: bool,
    refund_eligible: bool,
    reason: String,
    evaluated_rules: Vec<String>,
    /// Per-milestone evaluation results; empty when no milestones declared.
    milestone_results: Vec<MilestoneEvaluationResult>,
    /// Number of milestones with outcome == Satisfied.
    completed_milestone_count: usize,
    /// Total declared milestones.
    total_milestone_count: usize,
    /// Top-level holdback result; None when no holdback configured or milestone path used.
    holdback: Option<HoldbackEvaluationResult>,
    /// Threshold results for requirements with explicit threshold set; empty otherwise.
    threshold_results: Vec<RequirementThresholdResult>,
}

/// A single settlement action derived from policy evaluation.
#[derive(Debug, Serialize)]
struct SettlementAction {
    /// "release" or "refund"
    action: String,
    /// Human-readable recipient label
    recipient_label: String,
    /// Recipient address from the agreement (payer or payee address)
    recipient_address: String,
    /// Basis points of total_amount allocated to this action (10000 = 100%)
    amount_bps: u32,
    /// Absolute amount in satoshis
    amount_sat: u64,
    /// Whether this action can be executed now (vs held/pending)
    executable: bool,
    /// Reason why not executable (None if executable=true)
    hold_reason: Option<String>,
    /// Block height at which this action becomes executable; None if immediately executable.
    #[serde(skip_serializing_if = "Option::is_none")]
    executable_after_height: Option<u64>,
}

#[derive(Debug, Serialize)]
struct BuildSettlementTxResponse {
    agreement_hash: String,
    policy_found: bool,
    tip_height: u64,
    release_eligible: bool,
    refund_eligible: bool,
    outcome: PolicyOutcome,
    reason: String,
    total_amount_sat: u64,
    actions: Vec<SettlementAction>,
}

#[derive(Deserialize)]
struct BuildSettlementTxRequest {
    agreement: AgreementObject,
}

#[derive(Deserialize)]
struct StorePolicyRequest {
    policy: ProofPolicy,
    #[serde(default)]
    replace: bool,
}

#[derive(Debug, Serialize)]
struct StorePolicyResponse {
    policy_id: String,
    agreement_hash: String,
    accepted: bool,
    updated: bool,
    message: String,
}

#[derive(Deserialize)]
struct GetPolicyRequest {
    agreement_hash: String,
}

#[derive(Debug, Serialize)]
struct GetPolicyResponse {
    agreement_hash: String,
    found: bool,
    policy: Option<ProofPolicy>,
    expires_at_height: Option<u64>,
    expired: bool,
}

#[derive(Deserialize)]
struct GetProofRequest {
    /// Unique identifier of the proof to retrieve.
    proof_id: String,
}

#[derive(Serialize)]
struct GetProofResponse {
    proof_id: String,
    /// True when the proof was found in the store.
    found: bool,
    /// Chain tip height at the time of the query.
    tip_height: u64,
    /// Full proof object; null when found=false.
    proof: Option<SettlementProof>,
    /// Expiry height from the proof, if any; null when found=false.
    expires_at_height: Option<u64>,
    /// True when tip_height >= expires_at_height at query time.
    expired: bool,
    /// Derived lifecycle status: "active" or "expired". Empty string when found=false.
    status: String,
}

#[derive(Serialize)]
struct WalletExportWifResponse {
    address: String,
    wif: String,
}

#[derive(Serialize)]
struct WalletImportWifResponse {
    address: String,
}

#[derive(Serialize)]
struct WalletSeedResponse {
    seed_hex: String,
}

#[derive(Serialize)]
struct WalletMnemonicResponse {
    mnemonic: String,
}

#[derive(Serialize)]
struct WalletImportSeedResponse {
    address: String,
}

#[derive(Clone)]
struct WalletUtxo {
    outpoint: OutPoint,
    output: TxOutput,
    height: u64,
    is_coinbase: bool,
    pkh: [u8; 20],
}

/// v1.9.61: cached header-batch fetched by the in-process sync cycle, to
/// be built into a signed carrier tx by getblocktemplate. Only the headers
/// (slow to fetch from mempool.space) are cached; the carrier tx is signed
/// fresh per template request so it always uses the wallet's current UTXO
/// set and never collides with an in-flight user-initiated wallet spend.
#[derive(Clone)]
struct CachedHeaderBatchForTemplate {
    /// Hex-encoded concatenation of 80-byte BTC headers (or 80-byte LTC,
    /// same shape per chain). Passed verbatim to the
    /// chain's submit_*_headers_core.
    headers_hex: String,
    /// Chain's *_tip_height at the moment the headers were fetched. The
    /// helpers refuse to use the cache once the on-chain tip has advanced
    /// past this value — the carrier would extend from the wrong base.
    expected_relay_tip_height: u64,
    /// Wall-clock timestamp at fetch. Cache entries older than 15 minutes
    /// are treated as stale and ignored, forcing the cycle to refresh.
    built_at: std::time::SystemTime,
}

#[derive(Serialize)]
struct TemplateTx {
    hex: String,
    fee: u64,
    relay_addresses: Vec<String>,
}

/// v1.9.62 issue #60: zero-cost coinbase header relay. Each entry is appended
/// by the stratum as an additional output on the coinbase tx after the miner
/// reward output. `value` is always 0 for batch carriers; the script is the
/// batch payload as produced by encode_btc_header_batch / ltc.
#[derive(Serialize)]
struct CoinbaseExtraOutput {
    value: u64,
    script_pubkey_hex: String,
}

#[derive(Serialize)]
struct BlockTemplateResponse {
    height: u64,
    prev_hash: String,
    bits: String,
    target: String,
    time: u32,
    txs: Vec<TemplateTx>,
    total_fees: u64,
    coinbase_value: u64,
    mempool_count: usize,
    /// v1.9.62 issue #60: zero-value outputs the stratum must append to the
    /// coinbase. Empty pre-activation; one entry per chain (BTC/LTC)
    /// post-activation when the cycle has cached fresh headers.
    #[serde(default)]
    coinbase_extra_outputs: Vec<CoinbaseExtraOutput>,
}

#[derive(Deserialize)]
struct SubmitBlockHeader {
    version: u32,
    prev_hash: String,
    merkle_root: String,
    time: u32,
    bits: String,
    nonce: u32,
    hash: String,
}

#[derive(Deserialize)]
struct SubmitBlockRequest {
    height: u64,
    header: SubmitBlockHeader,
    tx_hex: Vec<String>,
    #[serde(default)]
    auxpow_hex: Option<String>,
    #[serde(default)]
    submit_source: Option<String>,
}

#[derive(Deserialize)]
struct NodeConfig {
    /// Optional P2P bind address, e.g. "0.0.0.0:38291".
    #[serde(default)]
    p2p_bind: Option<String>,
    /// Optional list of manual peers, e.g. ["seed.example.org:38291"].
    #[serde(default)]
    p2p_seeds: Vec<String>,
    /// Optional DNS seed hosts.
    #[serde(default)]
    p2p_dns_seeds: Vec<String>,
    /// Optional relay payout address to advertise to peers.
    #[serde(default)]
    relay_address: Option<String>,
    /// Optional self-advertised external endpoint in "host:port" form for
    /// CGNAT/NAT escape — overrides peers' TCP-source-IP inference when set.
    #[serde(default)]
    external_endpoint: Option<String>,
    /// Optional runtime root directory for blocks/state (used by mobile/Termux).
    #[serde(default)]
    data_dir: Option<String>,
}

fn load_node_config_from_env() -> Option<NodeConfig> {
    std::env::var("IRIUM_NODE_CONFIG")
        .ok()
        .and_then(|p| fs::read_to_string(p).ok())
        .and_then(|raw| serde_json::from_str::<NodeConfig>(&raw).ok())
}

fn cors_layer() -> Option<CorsLayer> {
    let raw = env::var("IRIUM_CORS_ORIGINS").ok()?;
    let origins = raw
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    if origins.is_empty() {
        return None;
    }
    let layer = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([AUTHORIZATION, CONTENT_TYPE]);
    if origins.iter().any(|o| *o == "*" || *o == "all") {
        return Some(layer.allow_origin(Any));
    }
    let mut values = Vec::new();
    for origin in origins {
        if let Ok(value) = HeaderValue::from_str(origin) {
            values.push(value);
        }
    }
    if values.is_empty() {
        return None;
    }
    Some(layer.allow_origin(values))
}

fn parse_seed_lines(raw: &str) -> Vec<String> {
    raw.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                None
            } else {
                Some(line.to_string())
            }
        })
        .collect()
}

fn parse_seed_to_socketaddr(seed: &str, default_port: u16) -> Result<std::net::SocketAddr, String> {
    if let Ok(addr) = seed.parse::<std::net::SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(ip) = seed.parse::<std::net::IpAddr>() {
        return format!("{}:{}", ip, default_port)
            .parse::<std::net::SocketAddr>()
            .map_err(|e| e.to_string());
    }
    Err("invalid seed format".to_string())
}
fn local_ip_set(bind: Option<&String>) -> HashSet<IpAddr> {
    let mut ips = HashSet::new();
    if let Some(bind) = bind {
        if let Ok(addr) = bind.parse::<SocketAddr>() {
            ips.insert(addr.ip());
        }
    }
    if let Ok(raw) = env::var("IRIUM_NODE_PUBLIC_IP").or_else(|_| env::var("IRIUM_PUBLIC_IP")) {
        if let Ok(ip) = raw.parse::<IpAddr>() {
            ips.insert(ip);
        }
    }
    if let Ok(ifaces) = get_if_addrs() {
        for iface in ifaces {
            ips.insert(iface.ip());
        }
    }
    // Also query hostname -I so we capture addresses exposed by the OS (e.g., public IPv4 on seeds).
    if let Ok(output) = std::process::Command::new("hostname").arg("-I").output() {
        if output.status.success() {
            if let Ok(list) = String::from_utf8(output.stdout) {
                for part in list.split_whitespace() {
                    if let Ok(ip) = part.parse::<IpAddr>() {
                        ips.insert(ip);
                    }
                }
            }
        }
    }
    // Optional: probe the outbound interface using a user-supplied target.
    if let Ok(target) = env::var("IRIUM_PUBLIC_IP_PROBE_TARGET") {
        if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
            if sock.connect(&target).is_ok() {
                if let Ok(addr) = sock.local_addr() {
                    ips.insert(addr.ip());
                }
            }
        }
    }
    ips.insert(IpAddr::V4(Ipv4Addr::LOCALHOST));
    ips.insert(IpAddr::V6(Ipv6Addr::LOCALHOST));
    ips
}

fn mask_ip(ip: &str) -> String {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            let oct = v4.octets();
            format!("{}.{}.*.*", oct[0], oct[1])
        }
        Ok(IpAddr::V6(v6)) => {
            let seg = v6.segments();
            format!("{:x}:{:x}::*", seg[0], seg[1])
        }
        Err(_) => ip.to_string(),
    }
}

fn mask_seed_label(seed: &str) -> String {
    let (ip, port) = seed.split_once(':').unwrap_or((seed, ""));
    let masked_ip = mask_ip(ip);
    if port.is_empty() {
        masked_ip
    } else {
        format!("{}:{}", masked_ip, port)
    }
}

fn scan_blocks_for_peers(chain: &ChainState, max_blocks: usize) -> (usize, Vec<SocketAddr>) {
    let total = chain.chain.len();
    if total == 0 {
        return (0, Vec::new());
    }
    let start = total.saturating_sub(max_blocks);
    let scan_count = total - start;
    let prefix = b"IRIUM_PEER ";
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for block in &chain.chain[start..] {
        for tx in &block.transactions {
            for output in &tx.outputs {
                let s = &output.script_pubkey;
                if s.len() > 2 && s[0] == 0x6a {
                    let payload = &s[2..];
                    if payload.starts_with(prefix) {
                        if let Ok(addr_str) = std::str::from_utf8(&payload[prefix.len()..]) {
                            let addr_str = addr_str.trim();
                            if let Ok(sa) = addr_str.parse::<SocketAddr>() {
                                if sa.port() != 0 && seen.insert(sa) {
                                    result.push(sa);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    (scan_count, result)
}

fn load_runtime_seeds() -> Vec<String> {
    let path = storage::bootstrap_dir().join("seedlist.runtime");
    std::fs::read_to_string(&path)
        .map(|raw| parse_seed_lines(&raw))
        .unwrap_or_default()
}

// ---- Item 3 (Phase 1 DNS-free bootstrap): peers.custom.json --------------
//
// Operator-curated seed list, kept separate from seedlist.runtime (which is
// the auto-discovered peer cache that gets rewritten every 10 minutes from
// gossip). peers.custom.json is the file a hand-edit will survive: anything
// added via `--add-seed <ip:port>` or appended directly with an editor stays
// authoritative across restarts. Format is a plain JSON array of "ip:port"
// strings to make it both human-editable and easy to share between operators.

/// Path to the operator-curated seed list. Precedence:
/// `IRIUM_DATA_DIR/peers.custom.json` (when the env var is set) →
/// `$HOME/.irium/peers.custom.json` otherwise.
fn custom_seeds_path() -> std::path::PathBuf {
    let data_dir = if let Ok(path) = std::env::var("IRIUM_DATA_DIR") {
        std::path::PathBuf::from(path)
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/".to_string());
        std::path::PathBuf::from(home).join(".irium")
    };
    data_dir.join("peers.custom.json")
}

/// Read operator-curated seeds from `peers.custom.json` (JSON array of
/// `"ip:port"` strings). Returns an empty Vec when the file is absent,
/// unreadable, or contains invalid JSON — an unparseable file is never fatal
/// so a corrupted edit will not block node startup. A warning is logged on
/// parse failure so the operator notices.
fn load_custom_seeds() -> Vec<String> {
    let path = custom_seeds_path();
    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    match serde_json::from_str::<Vec<String>>(&raw) {
        Ok(list) => list
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        Err(e) => {
            eprintln!(
                "[warn] peers.custom.json at {} is not a valid JSON array of \"ip:port\" strings: {}; ignoring",
                path.display(),
                e
            );
            Vec::new()
        }
    }
}

/// Append operator-supplied seed addresses to `peers.custom.json`. Loads the
/// existing list, merges with deduplication, and writes back atomically
/// (tmp file + rename) so a crash mid-write cannot corrupt the file. Silent
/// no-op when `new_seeds` is empty; any I/O failure is logged but never
/// propagated — `--add-seed` is best-effort persistence.
fn append_custom_seeds(new_seeds: &[String]) {
    if new_seeds.is_empty() {
        return;
    }
    let path = custom_seeds_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut existing = load_custom_seeds();
    let mut added = 0usize;
    for seed in new_seeds {
        let trimmed = seed.trim().to_string();
        if trimmed.is_empty() {
            continue;
        }
        if !existing.iter().any(|s| s == &trimmed) {
            existing.push(trimmed);
            added += 1;
        }
    }
    if added == 0 {
        return;
    }
    let json = match serde_json::to_string_pretty(&existing) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[warn] failed to serialize peers.custom.json: {}", e);
            return;
        }
    };
    let tmp_path = path.with_extension("json.tmp");
    if let Err(e) = std::fs::write(&tmp_path, json) {
        eprintln!(
            "[warn] failed to write peers.custom.json tmp file at {}: {}",
            tmp_path.display(),
            e
        );
        return;
    }
    if let Err(e) = std::fs::rename(&tmp_path, &path) {
        eprintln!(
            "[warn] failed to commit peers.custom.json (rename failed): {}",
            e
        );
        let _ = std::fs::remove_file(&tmp_path);
    }
}

fn load_persisted_startup_seeds(
    peers: &[irium_node_rs::network::PeerRecord],
    default_seed_port: u16,
) -> Vec<String> {
    let mut seeds = Vec::new();
    let mut persisted_records: Vec<irium_node_rs::network::PeerRecord> = Vec::new();
    let path = storage::state_dir().join("peers.json");
    if let Ok(raw) = std::fs::read_to_string(&path) {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) {
            if let Some(map) = value.as_object() {
                for (multiaddr, entry) in map {
                    if let Some(obj) = entry.as_object() {
                        let dialable = obj
                            .get("dialable")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        let last_seen =
                            obj.get("last_seen").and_then(|v| v.as_f64()).unwrap_or(0.0);
                        let first_seen = obj
                            .get("first_seen")
                            .and_then(|v| v.as_f64())
                            .unwrap_or(0.0);
                        persisted_records.push(irium_node_rs::network::PeerRecord {
                            multiaddr: multiaddr.clone(),
                            agent: None,
                            source: obj
                                .get("source")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string()),
                            last_seen,
                            first_seen,
                            seen_days: Vec::new(),
                            relay_address: None,
                            last_height: obj.get("last_height").and_then(|v| v.as_u64()),
                            node_id: None,
                            dialable,
                            last_successful_connect: obj
                                .get("last_successful_connect")
                                .and_then(|v| v.as_f64()),
                            last_successful_handshake: obj
                                .get("last_successful_handshake")
                                .and_then(|v| v.as_f64()),
                        });
                    }
                }
            }
        }
    }
    persisted_records.extend_from_slice(peers);
    for peer in persisted_records {
        if !peer.dialable {
            continue;
        }
        let parts: Vec<&str> = peer
            .multiaddr
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();
        if parts.len() < 4 || parts[2] != "tcp" {
            continue;
        }
        let Some(port) = parts[3].parse::<u16>().ok().filter(|port| *port > 0) else {
            continue;
        };
        let seed = format!("{}:{}", parts[1], port);
        if !seeds.iter().any(|existing| existing == &seed) {
            seeds.push(seed);
        }
    }
    for seed in load_runtime_seeds() {
        let normalized = match parse_seed_to_socketaddr(&seed, default_seed_port) {
            Ok(addr) => addr.to_string(),
            Err(_) => seed,
        };
        if !seeds.iter().any(|existing| existing == &normalized) {
            seeds.push(normalized);
        }
    }
    seeds
}

fn load_manual_seeds(node_cfg: Option<&NodeConfig>) -> Vec<String> {
    let mut seeds = node_cfg
        .map(|cfg| cfg.p2p_seeds.clone())
        .unwrap_or_default();
    for env_name in ["IRIUM_ADDNODE", "IRIUM_MANUAL_PEERS"] {
        if let Ok(raw) = std::env::var(env_name) {
            for token in raw.split([',', ' ', '\n', '\t']) {
                let token = token.trim();
                if token.is_empty() {
                    continue;
                }
                if !seeds.iter().any(|s| s == token) {
                    seeds.push(token.to_string());
                }
            }
        }
    }
    seeds
}

fn load_extra_seeds() -> Vec<String> {
    let path = storage::bootstrap_dir().join("seedlist.extra");
    std::fs::read_to_string(&path)
        .map(|raw| parse_seed_lines(&raw))
        .unwrap_or_default()
}

fn load_static_seeds() -> Vec<String> {
    let path = std::path::Path::new("bootstrap/static_peers.txt");
    let mut seeds = std::fs::read_to_string(path)
        .map(|raw| parse_seed_lines(&raw))
        .unwrap_or_default();
    if let Ok(raw) = std::env::var("IRIUM_STATIC_PEERS") {
        for token in raw.split([',', ' ', '\n', '\t']) {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            if !seeds.iter().any(|s| s == token) {
                seeds.push(token.to_string());
            }
        }
    }
    seeds
}

fn load_builtin_fallback_seeds() -> Vec<String> {
    let mut seeds = load_static_seeds();
    for seed in load_extra_seeds() {
        if !seeds.iter().any(|existing| existing == &seed) {
            seeds.push(seed);
        }
    }
    seeds
}

fn load_dns_seed_hosts(node_cfg: Option<&NodeConfig>) -> Vec<String> {
    let mut hosts = node_cfg
        .map(|cfg| cfg.p2p_dns_seeds.clone())
        .unwrap_or_default();
    if let Ok(raw) = std::env::var("IRIUM_DNS_SEEDS") {
        for token in raw.split([',', ' ', '\n', '\t']) {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            if !hosts.iter().any(|host| host == token) {
                hosts.push(token.to_string());
            }
        }
    }
    hosts
}

async fn resolve_dns_seed_addrs(
    hosts: &[String],
    default_seed_port: u16,
    local_ips: &HashSet<IpAddr>,
) -> (Vec<std::net::SocketAddr>, usize) {
    let mut addrs = Vec::new();
    let mut seen = HashSet::new();
    let mut filtered_local = 0usize;
    for host in hosts {
        let host_str = format!("{}:{}", host, default_seed_port);
        let resolved = tokio::task::spawn_blocking(move || {
            use std::net::ToSocketAddrs;
            host_str
                .to_socket_addrs()
                .map(|iter| iter.collect::<Vec<_>>())
        })
        .await;
        match resolved {
            Ok(Ok(iter)) => {
                for addr in iter {
                    if local_ips.contains(&addr.ip()) {
                        filtered_local += 1;
                        continue;
                    }
                    if seen.insert(addr) {
                        addrs.push(addr);
                    }
                }
            }
            Ok(Err(err)) => eprintln!(
                "[warn] bootstrap dns seed {} resolution failed: {}",
                host, err
            ),
            Err(e) => eprintln!(
                "[warn] bootstrap dns seed {} resolution task failed: {}",
                host, e
            ),
        }
    }
    (addrs, filtered_local)
}

#[derive(Clone, Copy)]
struct SeedDialInfo {
    total: usize,
    filtered_local: usize,
    persisted: usize,
    manual: usize,
    fallback: usize,
    dns: usize,
    signed: usize,
}

const BUNDLED_SEEDLIST: &str = include_str!("../../bootstrap/seedlist.txt");
const BUNDLED_SEEDLIST_SIG: &str = include_str!("../../bootstrap/seedlist.txt.sig");

fn ensure_seedlist_in_bootstrap_dir() {
    let dir = storage::bootstrap_dir();
    let _ = fs::create_dir_all(&dir);
    let seed_path = dir.join("seedlist.txt");
    let sig_path = dir.join("seedlist.txt.sig");
    if !seed_path.exists() {
        let _ = fs::write(&seed_path, BUNDLED_SEEDLIST);
    }
    if !sig_path.exists() {
        let _ = fs::write(&sig_path, BUNDLED_SEEDLIST_SIG);
    }
}

fn load_signed_seeds() -> Vec<String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let dir = storage::bootstrap_dir();
    let seed_path = dir.join("seedlist.txt");
    let sig_path = dir.join("seedlist.txt.sig");
    let Ok(seed_data) = std::fs::read_to_string(&seed_path) else {
        eprintln!(
            "[warn] bootstrap signed seedlist missing: {}",
            seed_path.display()
        );
        return Vec::new();
    };

    let sig_principal = std::env::var("IRIUM_SEEDLIST_SIG_PRINCIPAL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "bootstrap-signer".to_string());
    let sig_namespace = std::env::var("IRIUM_SEEDLIST_SIG_NAMESPACE")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "file".to_string());
    let allowed_signers_path = std::env::var("IRIUM_SEEDLIST_ALLOWED_SIGNERS")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| storage::bootstrap_dir().join("trust/allowed_signers"));
    let mut child = match Command::new("ssh-keygen")
        .arg("-Y")
        .arg("verify")
        .arg("-f")
        .arg(&allowed_signers_path)
        .arg("-I")
        .arg(&sig_principal)
        .arg("-n")
        .arg(&sig_namespace)
        .arg("-s")
        .arg(sig_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(err) => {
            eprintln!(
                "[warn] bootstrap signed seed verification unavailable: {}",
                err
            );
            return Vec::new();
        }
    };

    if let Some(stdin) = child.stdin.as_mut() {
        if stdin.write_all(seed_data.as_bytes()).is_err() {
            eprintln!("[warn] bootstrap signed seed verification input failed");
            return Vec::new();
        }
    }
    let status = match child.wait() {
        Ok(s) => s,
        Err(err) => {
            eprintln!("[warn] bootstrap signed seed verification failed: {}", err);
            return Vec::new();
        }
    };
    if status.success() {
        parse_seed_lines(&seed_data)
    } else {
        eprintln!("[warn] bootstrap signed seedlist signature invalid; continuing without it");
        Vec::new()
    }
}

fn build_seed_addrs(
    persisted_seeds: &[String],
    manual_seeds: &[String],
    fallback_seeds: &[String],
    dns_seed_addrs: &[std::net::SocketAddr],
    signed_seeds: &[String],
    default_seed_port: u16,
    local_ips: &HashSet<IpAddr>,
) -> (Vec<std::net::SocketAddr>, SeedDialInfo) {
    let mut seeds: Vec<std::net::SocketAddr> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut filtered_local = 0usize;

    for seed in persisted_seeds
        .iter()
        .chain(fallback_seeds.iter())
        .chain(signed_seeds.iter())
    {
        match parse_seed_to_socketaddr(seed, default_seed_port) {
            Ok(addr) => {
                if local_ips.contains(&addr.ip()) {
                    filtered_local += 1;
                    continue;
                }
                if seen.insert(addr) {
                    seeds.push(addr);
                }
            }
            Err(e) => eprintln!("Invalid P2P seed {}: {}", seed, e),
        }
    }
    for addr in dns_seed_addrs {
        if local_ips.contains(&addr.ip()) {
            filtered_local += 1;
            continue;
        }
        if seen.insert(*addr) {
            seeds.push(*addr);
        }
    }
    for seed in manual_seeds {
        match parse_seed_to_socketaddr(seed, default_seed_port) {
            Ok(addr) => {
                if local_ips.contains(&addr.ip()) {
                    filtered_local += 1;
                    continue;
                }
                if seen.insert(addr) {
                    seeds.push(addr);
                }
            }
            Err(e) => eprintln!("Invalid P2P seed {}: {}", seed, e),
        }
    }

    let mut info = SeedDialInfo {
        total: seeds.len(),
        filtered_local,
        persisted: persisted_seeds.len(),
        manual: manual_seeds.len(),
        fallback: fallback_seeds.len(),
        dns: dns_seed_addrs.len(),
        signed: signed_seeds.len(),
    };

    if seeds.is_empty() && filtered_local > 0 {
        let allow = std::env::var("IRIUM_ALLOW_LOCAL_SEED_FALLBACK")
            .ok()
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false);
        if allow {
            for seed in persisted_seeds
                .iter()
                .chain(fallback_seeds.iter())
                .chain(signed_seeds.iter())
            {
                if let Ok(addr) = parse_seed_to_socketaddr(seed, default_seed_port) {
                    seeds.push(addr);
                    info.total = seeds.len();
                    break;
                }
            }
        }
    }
    let mut rep_mgr = ReputationManager::new();
    seeds.sort_by(|a, b| {
        rep_mgr
            .score_of(&b.to_string())
            .cmp(&rep_mgr.score_of(&a.to_string()))
    });
    (seeds, info)
}

fn json_log_enabled() -> bool {
    static FLAG: OnceLock<bool> = OnceLock::new();
    *FLAG.get_or_init(|| {
        std::env::var("IRIUM_JSON_LOG")
            .ok()
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false)
    })
}

fn dial_log_rate_limit_enabled() -> bool {
    static FLAG: OnceLock<bool> = OnceLock::new();
    *FLAG.get_or_init(|| {
        std::env::var("IRIUM_P2P_DIAL_LOG_RATE_LIMIT")
            .ok()
            .map(|v| v == "0" || v.eq_ignore_ascii_case("false"))
            .map(|disabled| !disabled)
            .unwrap_or(true)
    })
}

fn dial_seed_log_cooldown_secs() -> u64 {
    static VAL: OnceLock<u64> = OnceLock::new();
    *VAL.get_or_init(|| {
        std::env::var("IRIUM_P2P_DIAL_LOG_COOLDOWN_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(|v| v.min(3600))
            .unwrap_or(30)
    })
}

fn dial_seed_log_allowed(kind: u8, ip: IpAddr) -> Option<u64> {
    if !dial_log_rate_limit_enabled() {
        return Some(0);
    }

    let cooldown = dial_seed_log_cooldown_secs();
    if cooldown == 0 {
        return Some(0);
    }

    // kind: 0 = dialing seed, 1 = outbound failed
    static GUARD: OnceLock<Mutex<HashMap<(u8, IpAddr), (Instant, u64)>>> = OnceLock::new();
    let guard = GUARD.get_or_init(|| Mutex::new(HashMap::new()));

    let mut map = guard.lock().unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();
    let entry = map.entry((kind, ip)).or_insert((
        Instant::now() - Duration::from_secs(cooldown.saturating_add(1)),
        0,
    ));

    if now.duration_since(entry.0) < Duration::from_secs(cooldown) {
        entry.1 = entry.1.saturating_add(1);
        return None;
    }

    let suppressed = entry.1;
    entry.0 = now;
    entry.1 = 0;
    Some(suppressed)
}

fn base58_p2pkh_to_hash(addr: &str) -> Option<Vec<u8>> {
    let data = bs58::decode(addr).into_vec().ok()?;
    if data.len() < 25 {
        return None;
    }
    let (body, checksum) = data.split_at(data.len() - 4);
    let first = Sha256::digest(body);
    let second = Sha256::digest(first);
    if &second[0..4] != checksum {
        return None;
    }
    if body.len() < 21 {
        return None;
    }
    let payload = &body[1..];
    if payload.len() != 20 {
        return None;
    }
    Some(payload.to_vec())
}

fn base58_p2pkh_from_hash(pkh: &[u8; 20]) -> String {
    let mut body = Vec::with_capacity(1 + 20);
    body.push(IRIUM_P2PKH_VERSION);
    body.extend_from_slice(pkh);
    let first = Sha256::digest(&body);
    let second = Sha256::digest(first);
    let checksum = &second[0..4];
    let mut full = body;
    full.extend_from_slice(checksum);
    bs58::encode(full).into_string()
}

fn hex_to_32(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s).map_err(|e| e.to_string())?;
    if bytes.len() != 32 {
        return Err("expected 32-byte hex".to_string());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_irm(s: &str) -> Result<u64, String> {
    if s.trim().is_empty() {
        return Err("empty amount".to_string());
    }
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() > 2 {
        return Err("invalid amount".to_string());
    }
    let whole: u64 = parts[0].parse().map_err(|_| "invalid amount".to_string())?;
    let frac = if parts.len() == 2 {
        let frac_str = parts[1];
        if frac_str.len() > 8 {
            return Err("too many decimals".to_string());
        }
        let mut frac_val: u64 = frac_str.parse().map_err(|_| "invalid amount".to_string())?;
        for _ in frac_str.len()..8 {
            frac_val *= 10;
        }
        frac_val
    } else {
        0
    };
    Ok(whole.saturating_mul(100_000_000).saturating_add(frac))
}

fn estimate_tx_size(inputs: usize, outputs: usize) -> u64 {
    10 + inputs as u64 * 148 + outputs as u64 * 34
}

fn p2pkh_script(pkh: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(25);
    script.push(0x76);
    script.push(0xa9);
    script.push(0x14);
    script.extend_from_slice(pkh);
    script.push(0x88);
    script.push(0xac);
    script
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

fn miner_address_from_tx(tx: &Transaction) -> Option<String> {
    let output = tx.outputs.first()?;
    let pkh = p2pkh_hash_from_script(&output.script_pubkey)?;
    Some(base58_p2pkh_from_hash(&pkh))
}

fn miner_address_from_block(block: &Block) -> Option<String> {
    block.transactions.first().and_then(miner_address_from_tx)
}

fn extract_coinbase_tag(script_sig: &[u8]) -> Option<String> {
    // Only works on ASCII text scriptSigs (solo miner format).
    // Pool BIP34 scriptSigs contain binary bytes that fail utf8 decode -> None.
    let text = std::str::from_utf8(script_sig).ok()?;
    // Strip trailing null bytes appended by stratum solo extranonce padding.
    let text = text.trim_end_matches('\0');

    // Text mode: "Block {height}/{tag}"
    if let Some(pos) = text.find('/') {
        let tag = &text[pos + 1..];
        if !tag.is_empty() && tag.len() <= 20 && tag.is_ascii() {
            let t = tag.replace('\0', "");
            if !t.is_empty() { return Some(t); }
        }
    }

    // Stratum solo mode: "Block {height} solo {tag} "
    if let Some(pos) = text.find(" solo ") {
        let after = text[pos + 6..].trim_end();
        if !after.is_empty() && after.len() <= 20 && after.is_ascii() {
            let t = after.replace('\0', "");
            if !t.is_empty() { return Some(t); }
        }
    }

    None
}

fn p2pkh_hash_from_script(script: &[u8]) -> Option<[u8; 20]> {
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

fn miner_blocks_dir() -> PathBuf {
    if let Ok(dir) = env::var("IRIUM_MINER_BLOCKS_DIR") {
        PathBuf::from(dir)
    } else {
        let home = env::var("HOME").unwrap_or_else(|_| "/".to_string());
        PathBuf::from(home).join(".irium/miner/blocks")
    }
}

fn same_dir(a: &PathBuf, b: &PathBuf) -> bool {
    if a == b {
        return true;
    }
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

fn persist_window_size() -> u64 {
    std::env::var("IRIUM_PERSIST_WINDOW")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(|v| v.clamp(128, 200_000))
        .unwrap_or(2000)
}

fn block_height_from_filename(path: &std::path::Path) -> Option<u64> {
    let name = path.file_name()?.to_str()?;
    let stripped = name.strip_prefix("block_")?;
    let num_part = stripped.strip_suffix(".json")?;
    num_part.parse::<u64>().ok()
}

fn path_contains_orphaned_dir(path: &std::path::Path) -> bool {
    path.components().any(|c| {
        c.as_os_str()
            .to_str()
            .map(|s| s.starts_with("orphaned_"))
            .unwrap_or(false)
    })
}

fn quarantine_single_block_file(path: &std::path::Path, reason: &str) -> bool {
    if !path.exists() || path_contains_orphaned_dir(path) {
        return false;
    }
    let Some(parent) = path.parent() else {
        return false;
    };
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let quarantine_dir = parent.join(format!("orphaned_{}", stamp));
    if fs::create_dir_all(&quarantine_dir).is_err() {
        return false;
    }
    let Some(name) = path.file_name() else {
        return false;
    };
    let mut dest = quarantine_dir.join(name);
    if dest.exists() {
        let mut n = 1u32;
        loop {
            let candidate = quarantine_dir.join(format!("{}.dup{}", name.to_string_lossy(), n));
            if !candidate.exists() {
                dest = candidate;
                break;
            }
            n = n.saturating_add(1);
        }
    }
    match fs::rename(path, &dest) {
        Ok(_) => {
            println!(
                "[🧹] Quarantined persisted block file {} (reason: {}; to={})",
                path.display(),
                reason,
                dest.display()
            );
            true
        }
        Err(_) => false,
    }
}

fn parse_persisted_block_file(
    path: &std::path::Path,
    genesis_hash_lc: &str,
) -> Result<(u64, Block), String> {
    let height =
        block_height_from_filename(path).ok_or_else(|| "invalid block file name".to_string())?;

    let md = fs::metadata(path).map_err(|e| format!("metadata read failed: {}", e))?;
    if md.len() == 0 {
        return Err("file is empty".to_string());
    }

    let data = fs::read_to_string(path).map_err(|e| format!("file read failed: {}", e))?;
    let parsed: serde_json::Value =
        serde_json::from_str(&data).map_err(|e| format!("json parse failed: {}", e))?;
    let header_obj = parsed
        .get("header")
        .ok_or_else(|| "missing header".to_string())?;

    let get_hex32 = |key: &str| -> Result<[u8; 32], String> {
        let s = header_obj
            .get(key)
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("missing header.{}", key))?;
        let bytes = hex::decode(s).map_err(|e| format!("bad hex in {}: {}", key, e))?;
        if bytes.len() != 32 {
            return Err(format!("{} must be 32 bytes", key));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    };

    let prev_hash = get_hex32("prev_hash")?;
    let merkle_root = get_hex32("merkle_root")?;
    let version = header_obj
        .get("version")
        .and_then(|v| v.as_u64())
        .unwrap_or(1) as u32;
    let time = header_obj.get("time").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let bits_str = header_obj
        .get("bits")
        .and_then(|v| v.as_str())
        .unwrap_or("1d00ffff");
    let bits = u32::from_str_radix(bits_str, 16).map_err(|e| format!("invalid bits: {}", e))?;
    let nonce = header_obj
        .get("nonce")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    let txs: Vec<Transaction> = match parsed.get("tx_hex").and_then(|v| v.as_array()) {
        Some(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for t in arr {
                let s = t
                    .as_str()
                    .ok_or_else(|| "tx_hex entry is not a string".to_string())?;
                let bytes = hex::decode(s).map_err(|e| format!("invalid tx hex: {}", e))?;
                let tx = decode_compact_tx(&bytes)
                    .map_err(|e| format!("failed to decode compact tx: {}", e))?;
                out.push(tx);
            }
            out
        }
        None => Vec::new(),
    };

    let auxpow = if version & irium_node_rs::auxpow::AUXPOW_VERSION_BIT != 0 {
        parsed.get("auxpow_hex")
            .and_then(|v| v.as_str())
            .and_then(|s| hex::decode(s).ok())
            .and_then(|bytes| {
                let mut off = 0;
                irium_node_rs::auxpow::deserialize(&bytes, &mut off).ok()
            })
    } else {
        None
    };

    let block = Block {
        header: BlockHeader {
            version,
            prev_hash,
            merkle_root,
            time,
            bits,
            nonce,
        },
        transactions: txs,
        auxpow,
    };

    if height == 0 {
        let h = hex::encode(block.header.hash_for_height(0)).to_lowercase();
        if h != genesis_hash_lc {
            return Err("genesis hash mismatch".to_string());
        }
    } else {
        if block.transactions.is_empty() {
            return Err("block has no transactions".to_string());
        }
        if block.merkle_root() != block.header.merkle_root {
            return Err("block merkle root mismatch".to_string());
        }
        if block.header.bits == 0 {
            return Err("header bits is zero".to_string());
        }
        if !meets_target(&block.header.hash_for_height(height), block.header.target()) {
            return Err("header hash does not meet declared target".to_string());
        }
    }

    Ok((height, block))
}

fn collect_block_files_from_dir(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    if !dir.exists() {
        return;
    }
    let mut stack = vec![dir.to_path_buf()];
    while let Some(cur) = stack.pop() {
        let Ok(read_dir) = cur.read_dir() else {
            continue;
        };
        for entry in read_dir.flatten() {
            let path = entry.path();
            if path.is_dir() {
                // v1.9.72: skip orphaned_<ts>/ subdirs at scan time so
                // already-quarantined blocks aren't re-loaded → re-validated
                // → re-quarantined into yet another fresh orphaned_<ts2>/
                // on every startup. Without this gate the orphan directory
                // count grows monotonically every restart, even though the
                // chain on disk is healthy and the v1.9.71 atomic-write fix
                // prevents new partial writes. The orphaned files remain on
                // disk for forensic inspection; storage::ensure_runtime_dirs
                // auto-prunes orphaned_* dirs older than 7 days.
                let name_starts_orphaned = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .map(|s| s.starts_with("orphaned_"))
                    .unwrap_or(false);
                if name_starts_orphaned {
                    continue;
                }
                stack.push(path);
                continue;
            }
            if path.is_file() && block_height_from_filename(&path).is_some() {
                out.push(path);
            }
        }
    }
}

fn discover_persist_mismatch_heights(
    expected: &[(u64, [u8; 32])],
    blocks_dir: &std::path::Path,
    genesis_hash_lc: &str,
    current_contiguous: u64,
) -> (Vec<u64>, u64) {
    let mut out = Vec::new();
    let mut contiguous = current_contiguous;

    for (height, expected_hash) in expected.iter().copied() {
        let path = blocks_dir.join(format!("block_{}.json", height));
        let valid_and_matching = match parse_persisted_block_file(&path, genesis_hash_lc) {
            Ok((parsed_h, block)) => parsed_h == height && block.header.hash_for_height(parsed_h) == expected_hash,
            Err(_) => false,
        };

        if valid_and_matching {
            if height == contiguous.saturating_add(1) {
                contiguous = height;
            }
        } else {
            out.push(height);
        }
    }

    (out, contiguous)
}

#[derive(Default)]
struct PersistWindowStats {
    max_height_on_disk: u64,
    contiguous_from_zero: u64,
    window_tip: u64,
    missing_in_window: u64,
}

fn compute_persist_window_stats(
    all_heights: &std::collections::HashSet<u64>,
    valid_heights: &std::collections::HashSet<u64>,
) -> PersistWindowStats {
    let max_height_on_disk = all_heights.iter().copied().max().unwrap_or(0);
    let mut contiguous = 0u64;
    while valid_heights.contains(&contiguous) {
        contiguous = contiguous.saturating_add(1);
    }
    let contiguous_from_zero = contiguous.saturating_sub(1);
    let window_tip = valid_heights
        .iter()
        .copied()
        .max()
        .unwrap_or(contiguous_from_zero);
    let window = persist_window_size();
    let window_start = window_tip.saturating_sub(window.saturating_sub(1));
    let mut missing = 0u64;
    for h in window_start..=window_tip {
        if !valid_heights.contains(&h) {
            missing = missing.saturating_add(1);
        }
    }
    PersistWindowStats {
        max_height_on_disk,
        contiguous_from_zero,
        window_tip,
        missing_in_window: missing,
    }
}

fn best_chain_hashes_in_window(
    state: &ChainState,
    window_start: u64,
    window_tip: u64,
) -> std::collections::BTreeMap<u64, [u8; 32]> {
    let mut by_height = std::collections::BTreeMap::new();
    if window_start > window_tip {
        return by_height;
    }

    let mut current = state.best_header_hash();
    let mut guard = 0usize;
    let guard_limit = ((window_tip.saturating_sub(window_start) + 1) as usize)
        .saturating_mul(8)
        .saturating_add(8192);

    while current != [0u8; 32] && guard < guard_limit {
        guard = guard.saturating_add(1);

        if let Some(height) = state.heights.get(&current).copied() {
            let mut h = height;
            loop {
                if h < window_start {
                    break;
                }
                if h > window_tip {
                    if h == 0 {
                        break;
                    }
                    h = h.saturating_sub(1);
                    continue;
                }
                if let Some(block) = state.chain.get(h as usize) {
                    by_height.entry(h).or_insert(block.header.hash_for_height(h));
                }
                if h == 0 {
                    break;
                }
                h = h.saturating_sub(1);
            }
            break;
        }

        if let Some(hw) = state.headers.get(&current) {
            let h = hw.height;
            if h >= window_start && h <= window_tip {
                by_height.entry(h).or_insert(current);
            }
            if hw.header.prev_hash == [0u8; 32] {
                break;
            }
            current = hw.header.prev_hash;
            continue;
        }

        break;
    }

    by_height
}

fn rebuild_startup_header_index(
    state: &mut ChainState,
    candidates: &[(u64, std::path::PathBuf, Block)],
    window_start: u64,
    window_tip: u64,
    missing_in_window: u64,
) {
    let mut bootstrap_blocks: Vec<(u64, Block)> =
        candidates.iter().map(|(h, _, b)| (*h, b.clone())).collect();
    bootstrap_blocks.sort_by_key(|(h, _)| *h);

    let mut pending = bootstrap_blocks;
    let mut inserted = 0usize;
    let mut synthetic_roots = 0usize;
    let mut rounds = 0u8;

    while !pending.is_empty() && rounds < 8 {
        rounds = rounds.saturating_add(1);
        let mut progressed = false;
        let mut next_pending: Vec<(u64, Block)> = Vec::new();

        for (h, block) in pending.into_iter() {
            let hash = block.header.hash_for_height(h);
            if state.headers.contains_key(&hash) || state.heights.contains_key(&hash) {
                continue;
            }

            match state.add_header(block.header.clone()) {
                Ok(_) => {
                    inserted = inserted.saturating_add(1);
                    progressed = true;
                }
                Err(e) => {
                    if e.contains("unknown parent") && synthetic_roots == 0 {
                        if !meets_target(&hash, block.header.target()) {
                            eprintln!(
                                "[warn] startup header index skipped invalid PoW header at h={} hash= {}",
                                h,
                                hex::encode(hash)
                            );
                            continue;
                        }
                        let synthetic_work =
                            state.total_work.clone() + BigUint::from(h.saturating_add(1));
                        state.headers.insert(
                            hash,
                            HeaderWork {
                                header: block.header.clone(),
                                height: h,
                                work: synthetic_work,
                            },
                        );
                        state.header_chain.push(hash);
                        inserted = inserted.saturating_add(1);
                        synthetic_roots = synthetic_roots.saturating_add(1);
                        progressed = true;
                    } else {
                        next_pending.push((h, block));
                    }
                }
            }
        }

        pending = next_pending;
        if !progressed {
            break;
        }
    }

    let best_hash = state.best_header_hash();
    let best_linked_persisted_tip = state
        .headers
        .get(&best_hash)
        .map(|hw| hw.height)
        .or_else(|| state.heights.get(&best_hash).copied())
        .unwrap_or_else(|| state.tip_height());

    let mut unlinked_in_window = 0u64;
    for (h, _, block) in candidates.iter() {
        if *h < window_start || *h > window_tip {
            continue;
        }
        let hash = block.header.hash_for_height(*h);
        let linked = state.headers.contains_key(&hash) || state.heights.contains_key(&hash);
        if !linked {
            unlinked_in_window = unlinked_in_window.saturating_add(1);
        }
    }

    println!(
        "[i] startup header index rebuilt: headers_known={} inserted={} synthetic_roots={} best_linked_persisted_tip={}/{} persisted_window_tip={} missing_in_window={} unlinked_in_window={} window=[{}..{}]",
        state.headers.len(),
        inserted,
        synthetic_roots,
        best_linked_persisted_tip,
        hex::encode(best_hash),
        window_tip,
        missing_in_window,
        unlinked_in_window,
        window_start,
        window_tip
    );
    if missing_in_window == 0 && unlinked_in_window > 0 {
        eprintln!(
            "[warn] startup header index has unlinked window headers despite missing_in_window=0 (unlinked_in_window={})",
            unlinked_in_window
        );
    }
    if state.headers.is_empty() {
        eprintln!(
            "[warn] startup header index empty after rebuild (window_tip={} missing_in_window={}); no parsed headers were linkable",
            window_tip,
            missing_in_window
        );
    }
    if missing_in_window == 0 && state.headers.is_empty() {
        eprintln!("[warn] BUG: missing_in_window=0 but headers_known=0 after startup rebuild");
    }
}

fn load_persisted_blocks(state: &mut ChainState, genesis_hash_lc: &str) {
    storage::reset_quarantine_count();
    storage::set_missing_persisted_in_window(0);
    storage::set_missing_or_mismatch_in_window(0);
    storage::set_expected_hash_coverage_in_window(0);
    storage::set_expected_hash_window_span(0);
    storage::set_persisted_window_tip(0);

    let node_dir = storage::blocks_dir();
    let miner_dir = miner_blocks_dir();

    let mut files = Vec::new();
    collect_block_files_from_dir(&node_dir, &mut files);
    if !same_dir(&node_dir, &miner_dir) {
        collect_block_files_from_dir(&miner_dir, &mut files);
    }
    files.sort();
    files.dedup();

    let mut all_heights: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut valid_heights: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut candidates: Vec<(u64, std::path::PathBuf, Block)> = Vec::new();

    for path in files {
        let Some(h) = block_height_from_filename(&path) else {
            continue;
        };
        all_heights.insert(h);
        match parse_persisted_block_file(&path, genesis_hash_lc) {
            Ok((height, block)) => {
                valid_heights.insert(height);
                candidates.push((height, path, block));
            }
            Err(e) => {
                eprintln!("[⚠️] Invalid persisted block {}: {}", path.display(), e);
                if quarantine_single_block_file(&path, &e) {
                    storage::add_quarantine_count(1);
                }
            }
        }
    }

    let stats = compute_persist_window_stats(&all_heights, &valid_heights);
    storage::set_persisted_max_height_on_disk(stats.max_height_on_disk);
    // contiguous_from_zero from file parsing is informational only; authoritative
    // contiguous height is the replay-connected tip set later in startup.
    storage::force_set_persisted_contiguous_height(0);
    storage::set_persisted_window_tip(stats.window_tip);
    storage::set_missing_persisted_in_window(stats.missing_in_window);

    let window = persist_window_size();
    let window_start = stats.window_tip.saturating_sub(window.saturating_sub(1));
    let mut missing_heights = Vec::new();
    for h in window_start..=stats.window_tip {
        if !valid_heights.contains(&h) {
            missing_heights.push(h);
        }
    }

    // Also track missing persisted files before the continuity window.
    // If this backlog is never healed, restarts can resume from a much lower
    // contiguous height even when near-tip files exist.
    let mut historical_missing_heights = Vec::new();
    if stats.contiguous_from_zero.saturating_add(1) < window_start {
        for h in (stats.contiguous_from_zero.saturating_add(1))..window_start {
            if !valid_heights.contains(&h) {
                historical_missing_heights.push(h);
            }
        }
    }

    println!(
        "[i] persist continuity window: tip={} window_start={} missing_in_window={} contiguous_from_zero={} historical_missing_before_window={}",
        stats.window_tip,
        window_start,
        stats.missing_in_window,
        stats.contiguous_from_zero,
        historical_missing_heights.len()
    );
    if stats.missing_in_window > 0 {
        eprintln!(
            "[warn] persist continuity window has gaps near tip (missing_in_window={}); writer may be behind; will backfill",
            stats.missing_in_window
        );
    }

    rebuild_startup_header_index(
        state,
        &candidates,
        window_start,
        stats.window_tip,
        stats.missing_in_window,
    );

    let mut observed_hashes_by_height: std::collections::BTreeMap<u64, Vec<[u8; 32]>> =
        std::collections::BTreeMap::new();
    for (h, _, block) in candidates.iter() {
        if *h < window_start || *h > stats.window_tip {
            continue;
        }
        observed_hashes_by_height
            .entry(*h)
            .or_default()
            .push(block.header.hash_for_height(*h));
    }

    let expected_hashes_by_height =
        best_chain_hashes_in_window(state, window_start, stats.window_tip);
    let expected_hash_coverage_in_window = expected_hashes_by_height.len() as u64;
    let expected_hash_window_span = if window_start <= stats.window_tip {
        stats
            .window_tip
            .saturating_sub(window_start)
            .saturating_add(1)
    } else {
        0
    };
    storage::set_expected_hash_coverage_in_window(expected_hash_coverage_in_window);
    storage::set_expected_hash_window_span(expected_hash_window_span);

    let mut target_heights = historical_missing_heights.clone();

    if expected_hashes_by_height.is_empty() {
        target_heights.extend(missing_heights.iter().copied());
    } else {
        for h in window_start..=stats.window_tip {
            let Some(expected_hash) = expected_hashes_by_height.get(&h) else {
                continue;
            };
            let matched = observed_hashes_by_height
                .get(&h)
                .map(|hashes| hashes.iter().any(|v| v == expected_hash))
                .unwrap_or(false);
            if !matched {
                target_heights.push(h);
            }
        }
    }

    target_heights.sort_unstable();
    target_heights.dedup();

    storage::set_gap_healer_target_heights(&target_heights);
    storage::set_missing_or_mismatch_in_window(target_heights.len() as u64);

    candidates.sort_by_key(|(h, _, _)| *h);
    let mut pending = candidates;
    let mut rounds = 0u32;
    loop {
        rounds = rounds.saturating_add(1);
        let mut progressed = false;
        let mut next_pending: Vec<(u64, std::path::PathBuf, Block)> = Vec::new();

        for (h, path, block) in pending.into_iter() {
            if h == 0 || h <= state.tip_height() {
                continue;
            }
            match state.connect_block(block.clone()) {
                Ok(_) => {
                    progressed = true;
                }
                Err(e) => {
                    let e_lc = e.to_ascii_lowercase();
                    let should_quarantine = e_lc.contains("merkle")
                        || e_lc.contains("proof-of-work")
                        || e_lc.contains("bits mismatch")
                        || e_lc.contains("coinbase")
                        || e_lc.contains("timestamp");
                    if should_quarantine {
                        eprintln!(
                            "[⚠️] Persisted block {} failed validation: {}",
                            path.display(),
                            e
                        );
                        if quarantine_single_block_file(&path, &e) {
                            storage::add_quarantine_count(1);
                        }
                    } else {
                        next_pending.push((h, path, block));
                    }
                }
            }
        }

        pending = next_pending;
        if !progressed || pending.is_empty() || rounds > 4 {
            break;
        }
    }

    if !pending.is_empty() {
        eprintln!(
            "[i] persisted replay deferred {} block files due to missing ancestors; network sync will fill gaps",
            pending.len()
        );
    }

    let tip_height = state.tip_height();
    let tip_hash = hex::encode(state.tip_hash());
    storage::set_persisted_height(tip_height);
    storage::force_set_persisted_contiguous_height(tip_height);
    let queue_len = storage::persist_queue_len();

    println!(
        "[i] Startup source-of-truth: using validated persisted chain data near tip; old historical holes do not force rewind. tip={} hash={}",
        tip_height, tip_hash
    );

    if storage::persisted_max_height_on_disk() > tip_height {
        let gap = storage::persisted_max_height_on_disk().saturating_sub(tip_height);
        if queue_len as u64 >= gap {
            println!(
                "[i] Persisted block gap detected: tip_height={} tip_hash={} highest_persisted_height={} persist_queue_len={}. writer may be behind; will backfill.",
                tip_height,
                tip_hash,
                storage::persisted_max_height_on_disk(),
                queue_len
            );
        } else {
            eprintln!(
                "[warn] Persisted block gap detected: tip_height={} tip_hash={} highest_persisted_height={} persist_queue_len={}. will resync missing continuity from network.",
                tip_height,
                tip_hash,
                storage::persisted_max_height_on_disk(),
                queue_len
            );
        }
    } else {
        println!(
            "[i] Persist continuity OK: tip_height={} tip_hash={} highest_persisted_height={} persist_queue_len={}",
            tip_height,
            tip_hash,
            storage::persisted_max_height_on_disk(),
            queue_len
        );
    }

    if state.height > 1 {
        println!(
            "[↩️] Resumed node height {} from persisted blocks",
            state.height
        );
    }
}

fn dir_is_empty(path: &std::path::Path) -> bool {
    match std::fs::read_dir(path) {
        Ok(mut rd) => rd.next().is_none(),
        Err(_) => true,
    }
}

fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else if ty.is_file() {
            if let Some(parent) = to.parent() {
                std::fs::create_dir_all(parent)?;
            }
            // Do not overwrite any existing new-state files.
            if !to.exists() {
                let _ = std::fs::copy(&from, &to);
            }
        }
    }
    Ok(())
}

fn migrate_legacy_repo_state_dir(state_dir: &std::path::Path) {
    if !dir_is_empty(state_dir) {
        return;
    }

    let mut candidates = Vec::new();
    if let Ok(root) = env::var("IRIUM_REPO_ROOT") {
        candidates.push(PathBuf::from(root).join("state"));
    }
    candidates.push(PathBuf::from("state"));

    for legacy in candidates {
        if legacy.exists() && legacy.is_dir() {
            if let Err(e) = copy_dir_recursive(&legacy, state_dir) {
                eprintln!(
                    "[warn] Legacy state migration failed from {}: {}",
                    legacy.display(),
                    e
                );
            } else {
                println!(
                    "[i] Migrated legacy state from {} -> {}",
                    legacy.display(),
                    state_dir.display()
                );
            }
            break;
        }
    }
}

fn reinit_state_dir(state_dir: &PathBuf, reason: &str) {
    let ts = Utc::now().timestamp();
    if state_dir.exists() && !dir_is_empty(state_dir) {
        let backup = state_dir
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join(format!("state.bad.{ts}"));
        if let Err(e) = fs::rename(state_dir, &backup) {
            eprintln!(
                "[warn] Failed to rename state dir {} -> {}: {}",
                state_dir.display(),
                backup.display(),
                e
            );
        } else {
            println!(
                "[i] State dir reinitialized ({}) -> {}",
                reason,
                backup.display()
            );
        }
    }
    let _ = fs::create_dir_all(state_dir);
}

fn mempool_file() -> PathBuf {
    if let Ok(path) = env::var("IRIUM_MEMPOOL_FILE") {
        PathBuf::from(path)
    } else {
        let path = storage::state_dir().join("mempool/pending.json");
        if !path.exists() {
            let home = env::var("HOME").unwrap_or_else(|_| "/".to_string());
            let legacy = PathBuf::from(home).join(".irium/mempool/pending.json");
            if legacy.exists() {
                if let Some(parent) = path.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                let _ = fs::copy(&legacy, &path);
            }
        }
        path
    }
}

fn rate_limiter() -> RateLimiter {
    let rpm = env::var("IRIUM_RATE_LIMIT_PER_MIN")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(120);
    RateLimiter::new(rpm)
}

fn rpc_body_limit_bytes() -> usize {
    env::var("IRIUM_RPC_BODY_MAX")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(32 * 1024 * 1024)
}

fn require_rpc_auth(headers: &HeaderMap) -> Result<(), StatusCode> {
    let token = match env::var("IRIUM_RPC_TOKEN") {
        Ok(t) if !t.trim().is_empty() => t,
        _ => return Ok(()),
    };
    let expected = format!("Bearer {}", token);
    let provided = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if provided.as_bytes().ct_eq(expected.as_bytes()).into() {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

fn rpc_authorized(headers: &HeaderMap) -> bool {
    let token = match env::var("IRIUM_RPC_TOKEN") {
        Ok(t) if !t.trim().is_empty() => t,
        _ => return false,
    };
    let expected = format!("Bearer {}", token);
    let provided = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    provided.as_bytes().ct_eq(expected.as_bytes()).into()
}

fn check_rate_with_auth(
    state: &AppState,
    addr: &SocketAddr,
    headers: &HeaderMap,
) -> Result<(), StatusCode> {
    if rpc_authorized(headers) {
        return Ok(());
    }
    check_rate(state, addr)
}

fn check_rate(state: &AppState, addr: &SocketAddr) -> Result<(), StatusCode> {
    if addr.ip().is_loopback() {
        return Ok(());
    }
    let mut limiter = state.limiter.lock().unwrap_or_else(|e| e.into_inner());
    if limiter.is_allowed(&addr.ip().to_string()) {
        Ok(())
    } else {
        Err(StatusCode::TOO_MANY_REQUESTS)
    }
}

fn difficulty_from_target(pow_limit: Target, target: Target) -> f64 {
    let max_target = pow_limit.to_target();
    let cur_target = target.to_target();
    let max_f = max_target.to_f64().unwrap_or(0.0);
    let cur_f = cur_target.to_f64().unwrap_or(0.0);
    if cur_f <= 0.0 {
        0.0
    } else {
        max_f / cur_f
    }
}

async fn network_hashrate(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Query(q): Query<NetworkHashrateQuery>,
) -> Result<Json<NetworkHashrateResponse>, StatusCode> {
    check_rate(&state, &addr)?;
    let window = q.window.unwrap_or(120).clamp(1, 2016);
    let (tip_height, difficulty, hashrate, avg_block_time, sample_blocks) = {
        let guard = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let tip_height = guard.tip_height();
        let tip_target = guard
            .chain
            .last()
            .map(|b| b.header.target())
            .unwrap_or_else(|| guard.params.genesis_block.header.target());
        let difficulty = difficulty_from_target(guard.params.pow_limit, tip_target);

        if guard.chain.len() < 2 {
            (tip_height, difficulty, None, None, 0usize)
        } else {
            let end_index = guard.chain.len() - 1;
            let start_index = if guard.chain.len() > window {
                guard.chain.len() - 1 - window
            } else {
                0
            };
            let blocks = end_index.saturating_sub(start_index);
            if blocks == 0 {
                (tip_height, difficulty, None, None, 0usize)
            } else {
                let start_time = guard.chain[start_index].header.time as i64;
                let end_time = guard.chain[end_index].header.time as i64;
                let elapsed = end_time - start_time;
                if elapsed <= 0 {
                    (tip_height, difficulty, None, None, blocks)
                } else {
                    let avg_time = (elapsed as f64) / (blocks as f64);
                    let hashrate = difficulty * 4294967296.0 / avg_time;
                    (
                        tip_height,
                        difficulty,
                        Some(hashrate),
                        Some(avg_time),
                        blocks,
                    )
                }
            }
        }
    };

    let era = network_era(tip_height);

    Ok(Json(NetworkHashrateResponse {
        tip_height,
        current_network_era: era.era_name.to_string(),
        current_network_era_description: era.era_description.to_string(),
        current_network_era_tagline: era.era_tagline.map(str::to_string),
        early_participation_signal: era.early_participation_signal,
        difficulty,
        hashrate,
        avg_block_time,
        window,
        sample_blocks,
    }))
}

async fn network_status(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
) -> Result<Json<NetworkStatusResponse>, StatusCode> {
    check_rate(&state, &addr)?;
    let guard = state.chain.lock().unwrap_or_else(|e| e.into_inner());
    let height = guard.tip_height();
    let tip_hash = guard
        .chain
        .last()
        .map(|b| hex::encode(b.header.hash_for_height(height)))
        .unwrap_or_else(|| "0".repeat(64));
    let tip_target = guard
        .chain
        .last()
        .map(|b| b.header.target())
        .unwrap_or_else(|| guard.params.genesis_block.header.target());
    let difficulty = difficulty_from_target(guard.params.pow_limit, tip_target);

    let (hashrate_estimate, seconds_since_last_block) = if guard.chain.len() >= 2 {
        let end_index = guard.chain.len() - 1;
        let window = 120usize.min(end_index);
        let start_index = end_index - window;
        let start_time = guard.chain[start_index].header.time as i64;
        let end_time = guard.chain[end_index].header.time as i64;
        let elapsed = end_time - start_time;
        let hashrate = if elapsed > 0 {
            let avg_time = (elapsed as f64) / (window as f64);
            Some(difficulty * 4294967296.0 / avg_time)
        } else {
            None
        };
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let secs = now_secs.saturating_sub(end_time as u64);
        (hashrate, Some(secs))
    } else {
        (None, None)
    };
    let peer_count = state.status_peer_count_cache.load(std::sync::atomic::Ordering::Relaxed);
    drop(guard);

    Ok(Json(NetworkStatusResponse {
        height,
        tip_hash,
        peer_count,
        difficulty,
        hashrate_estimate,
        seconds_since_last_block,
        node_version: env!("CARGO_PKG_VERSION"),
    }))
}

async fn mining_metrics(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Query(q): Query<MiningMetricsQuery>,
) -> Result<Json<MiningMetricsResponse>, StatusCode> {
    check_rate(&state, &addr)?;
    let window = q.window.unwrap_or(120).clamp(1, 2016);
    let series_len = q.series.unwrap_or(240).clamp(1, 2016);

    let (
        tip_height,
        tip_time,
        difficulty,
        hashrate,
        avg_block_time,
        sample_blocks,
        diff_1h,
        diff_24h,
        diff_1h_pct,
        diff_24h_pct,
        series,
    ) = {
        let guard = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let tip_height = guard.tip_height();
        let tip_time = guard
            .chain
            .last()
            .map(|b| b.header.time)
            .unwrap_or(guard.params.genesis_block.header.time);

        let tip_target = guard
            .chain
            .last()
            .map(|b| b.header.target())
            .unwrap_or_else(|| guard.params.genesis_block.header.target());
        let difficulty = difficulty_from_target(guard.params.pow_limit, tip_target);

        let (hashrate, avg_block_time, sample_blocks) = if guard.chain.len() < 2 {
            (None, None, 0usize)
        } else {
            let end_index = guard.chain.len() - 1;
            let start_index = if guard.chain.len() > window {
                guard.chain.len() - 1 - window
            } else {
                0
            };
            let blocks = end_index.saturating_sub(start_index);
            if blocks == 0 {
                (None, None, 0usize)
            } else {
                let start_time = guard.chain[start_index].header.time as i64;
                let end_time = guard.chain[end_index].header.time as i64;
                let elapsed = end_time - start_time;
                if elapsed <= 0 {
                    (None, None, blocks)
                } else {
                    let avg_time = (elapsed as f64) / (blocks as f64);
                    let hashrate = difficulty * 4294967296.0 / avg_time;
                    (Some(hashrate), Some(avg_time), blocks)
                }
            }
        };

        let diff_at_age = |age_secs: u64| -> Option<f64> {
            for b in guard.chain.iter().rev() {
                if (tip_time as u64).saturating_sub(b.header.time as u64) >= age_secs {
                    let d = difficulty_from_target(guard.params.pow_limit, b.header.target());
                    return Some(d);
                }
            }
            None
        };

        let diff_1h = diff_at_age(3600);
        let diff_24h = diff_at_age(86400);
        let diff_1h_pct = diff_1h.and_then(|d| {
            if d > 0.0 {
                Some((difficulty - d) / d * 100.0)
            } else {
                None
            }
        });
        let diff_24h_pct = diff_24h.and_then(|d| {
            if d > 0.0 {
                Some((difficulty - d) / d * 100.0)
            } else {
                None
            }
        });

        let mut series = Vec::new();
        if !guard.chain.is_empty() {
            let end_index = guard.chain.len() - 1;
            let start_index = if guard.chain.len() > series_len {
                guard.chain.len() - series_len
            } else {
                0
            };
            let count = end_index + 1 - start_index;
            let step = std::cmp::max(1, count / 120);
            for i in (start_index..=end_index).step_by(step) {
                let b = &guard.chain[i];
                let d = difficulty_from_target(guard.params.pow_limit, b.header.target());
                series.push(MiningMetricsPoint {
                    height: i as u64,
                    time: b.header.time as u64,
                    difficulty: d,
                });
            }
        }

        (
            tip_height,
            tip_time,
            difficulty,
            hashrate,
            avg_block_time,
            sample_blocks,
            diff_1h,
            diff_24h,
            diff_1h_pct,
            diff_24h_pct,
            series,
        )
    };

    let era = network_era(tip_height);

    Ok(Json(MiningMetricsResponse {
        tip_height,
        tip_time: tip_time as u64,
        current_network_era: era.era_name.to_string(),
        current_network_era_description: era.era_description.to_string(),
        current_network_era_tagline: era.era_tagline.map(str::to_string),
        early_participation_signal: era.early_participation_signal,
        difficulty,
        hashrate,
        avg_block_time,
        window,
        sample_blocks,
        difficulty_1h: diff_1h,
        difficulty_24h: diff_24h,
        difficulty_change_1h_pct: diff_1h_pct,
        difficulty_change_24h_pct: diff_24h_pct,
        series,
    }))
}

fn cached_best_header_tip(
    height: u64,
    cached_hash: &str,
    genesis_hash: &str,
) -> BestHeaderTipResponse {
    let hash = if cached_hash.is_empty() {
        if height > 0 {
            genesis_hash.to_string()
        } else {
            String::new()
        }
    } else {
        cached_hash.to_string()
    };
    BestHeaderTipResponse { height, hash }
}

fn compute_best_header_tip_from_chain(
    guard: &ChainState,
    genesis_hash: &str,
) -> BestHeaderTipResponse {
    let h = guard.tip_height();
    let best_hash = guard.best_header_hash();
    let best_height = guard
        .headers
        .get(&best_hash)
        .map(|hw| hw.height)
        .or_else(|| guard.heights.get(&best_hash).copied())
        .unwrap_or(h);
    let best_hash_hex = hex::encode(best_hash);
    if best_height > 0 && best_hash_hex.is_empty() {
        return cached_best_header_tip(best_height, "", genesis_hash);
    }
    BestHeaderTipResponse {
        height: best_height,
        hash: best_hash_hex,
    }
}

async fn status(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
) -> Result<Json<StatusResponse>, StatusCode> {
    check_rate(&state, &addr)?;

    // Keep /status responsive under heavy sync/P2P load by using short timeouts
    // and cached values instead of waiting indefinitely.
    let (peer_count, node_id, sybil_diff) = match state.p2p {
        Some(ref p2p) => {
            let peer_count =
                match tokio::time::timeout(Duration::from_millis(250), p2p.peer_count()).await {
                    Ok(v) => {
                        state.status_peer_count_cache.store(v, Ordering::Relaxed);
                        v
                    }
                    Err(_) => state.status_peer_count_cache.load(Ordering::Relaxed),
                };
            let sybil = match tokio::time::timeout(
                Duration::from_millis(250),
                p2p.current_sybil_difficulty(),
            )
            .await
            {
                Ok(v) => {
                    state.status_sybil_cache.store(v, Ordering::Relaxed);
                    Some(v)
                }
                Err(_) => Some(state.status_sybil_cache.load(Ordering::Relaxed)),
            };
            (peer_count, Some(p2p.node_id_hex()), sybil)
        }
        None => (0, None, None),
    };

    let anchors_digest = state
        .anchors
        .as_ref()
        .map(|a| a.payload_digest().to_string());

    let (height, best_header_tip) = match state.chain.try_lock() {
        Ok(guard) => {
            let h = guard.tip_height();
            state.status_height_cache.store(h, Ordering::Relaxed);
            let best = compute_best_header_tip_from_chain(&guard, &state.genesis_hash);
            if let Ok(mut cached) = state.status_best_header_hash_cache.lock() {
                if !best.hash.is_empty() {
                    *cached = best.hash.clone();
                }
            }
            (h, best)
        }
        Err(_) => {
            let h = state.status_height_cache.load(Ordering::Relaxed);
            let cached_hash = state
                .status_best_header_hash_cache
                .lock()
                .map(|v| v.clone())
                .unwrap_or_default();
            (
                h,
                cached_best_header_tip(h, &cached_hash, &state.genesis_hash),
            )
        }
    };

    let era = network_era(height);

    let persisted_height = storage::persisted_height();
    state
        .status_persisted_height_cache
        .store(persisted_height, Ordering::Relaxed);
    let persist_queue_len = storage::persist_queue_len();
    state
        .status_persist_queue_cache
        .store(persist_queue_len, Ordering::Relaxed);
    let persisted_contiguous_height = storage::persisted_contiguous_height();
    state
        .status_persisted_contiguous_cache
        .store(persisted_contiguous_height, Ordering::Relaxed);
    let persisted_max_height_on_disk = storage::persisted_max_height_on_disk();
    state
        .status_persisted_max_on_disk_cache
        .store(persisted_max_height_on_disk, Ordering::Relaxed);
    let quarantine_count = storage::quarantine_count();
    state
        .status_quarantine_count_cache
        .store(quarantine_count, Ordering::Relaxed);
    let persisted_window_tip = storage::persisted_window_tip();
    state
        .status_persisted_window_tip_cache
        .store(persisted_window_tip, Ordering::Relaxed);
    let missing_persisted_in_window = storage::missing_persisted_in_window();
    state
        .status_missing_persisted_in_window_cache
        .store(missing_persisted_in_window, Ordering::Relaxed);
    let missing_or_mismatch_in_window = storage::missing_or_mismatch_in_window();
    state
        .status_missing_or_mismatch_in_window_cache
        .store(missing_or_mismatch_in_window, Ordering::Relaxed);
    let expected_hash_coverage_in_window = storage::expected_hash_coverage_in_window();
    state
        .status_expected_hash_coverage_in_window_cache
        .store(expected_hash_coverage_in_window, Ordering::Relaxed);
    let expected_hash_window_span = storage::expected_hash_window_span();
    state
        .status_expected_hash_window_span_cache
        .store(expected_hash_window_span, Ordering::Relaxed);
    let gap_healer_active = storage::gap_healer_active();
    let gap_healer_last_progress_ts = storage::gap_healer_last_progress_ts();
    let gap_healer_last_filled_height = storage::gap_healer_last_filled_height();
    let gap_healer_pending_count = storage::gap_healer_pending_count();

    let fee_rate_sat_per_byte = {
        let mempool = state.mempool.lock().unwrap_or_else(|e| e.into_inner());
        let raw = mempool.min_fee_per_byte().ceil() as u64;
        if raw == 0 { 1 } else { raw }
    };

    Ok(Json(StatusResponse {
        height,
        genesis_hash: state.genesis_hash.clone(),
        network_era: era.era_name.to_string(),
        network_era_description: era.era_description.to_string(),
        network_era_tagline: era.era_tagline.map(str::to_string),
        early_participation_signal: era.early_participation_signal,
        anchors_digest,
        peer_count,
        anchor_loaded: state.anchors.is_some(),
        node_id,
        sybil_difficulty: sybil_diff,
        best_header_tip,
        persisted_height,
        persist_queue_len,
        persisted_contiguous_height,
        persisted_max_height_on_disk,
        quarantine_count,
        persisted_window_tip,
        missing_persisted_in_window,
        missing_or_mismatch_in_window,
        expected_hash_coverage_in_window,
        expected_hash_window_span,
        gap_healer_active,
        gap_healer_last_progress_ts,
        gap_healer_last_filled_height,
        gap_healer_pending_count,
        fee_rate_sat_per_byte,
    }))
}

async fn peers(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
) -> Result<Json<PeersResponse>, StatusCode> {
    check_rate(&state, &addr)?;
    if let Some(ref p2p) = state.p2p {
        let list = p2p
            .peers_snapshot()
            .await
            .into_iter()
            .map(|p| PeerInfo {
                multiaddr: p.multiaddr,
                agent: p.agent,
                source: p.source,
                height: p.last_height,
                last_seen: p.last_seen,
                dialable: p.dialable,
                last_successful_handshake: p.last_successful_handshake,
            })
            .collect();
        Ok(Json(PeersResponse { peers: list }))
    } else {
        Ok(Json(PeersResponse { peers: Vec::new() }))
    }
}

async fn metrics(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
) -> Result<String, StatusCode> {
    check_rate(&state, &addr)?;
    let (height, anchor_loaded, tip_hash, anchor_digest) = {
        let g = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let tip_h = g.tip_height();
        let tip_hash = g
            .chain
            .last()
            .map(|b| hex::encode(b.header.hash_for_height(tip_h)))
            .unwrap_or_else(|| state.genesis_hash.clone());
        let digest = state
            .anchors
            .as_ref()
            .map(|a| a.payload_digest().to_string())
            .unwrap_or_default();
        (g.tip_height(), state.anchors.is_some(), tip_hash, digest)
    };
    let era = network_era(height);
    let relay = P2PNode::relay_telemetry_snapshot();
    let (peer_count, node_id_hex, sybil_diff, peer_telemetry) = match state.p2p {
        Some(ref p2p) => {
            let peers = p2p.peer_count().await;
            let node_id = p2p.node_id_hex();
            let diff = p2p.current_sybil_difficulty().await;
            let peer_telemetry = p2p.peer_telemetry_snapshot().await;
            (peers, node_id, diff, peer_telemetry)
        }
        None => (0usize, String::new(), 0u8, Default::default()),
    };
    let seeds = SeedlistManager::new(128).merged_seedlist();
    let mempool_sz = state
        .mempool
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .len();
    Ok(format!(
        "irium_height {}
irium_peers {}
irium_anchor_loaded {}
irium_tip_hash {}
irium_mempool_size {}
irium_anchor_digest {}
irium_node_id {}
irium_sybil_difficulty {}
irium_seed_count {}
irium_early_participation_signal {}
irium_new_tip_announced_count {}
irium_block_announce_peers_count_total {}
irium_block_request_count {}
irium_duplicate_block_suppressed_count {}
irium_avg_block_processing_ms {}
irium_avg_block_announce_delay_ms {}
irium_outbound_dial_attempts_total {}
irium_outbound_dial_success_total {}
irium_outbound_dial_failure_total {}
irium_outbound_dial_failure_timeout_total {}
irium_outbound_dial_failure_refused_total {}
irium_outbound_dial_failure_no_route_total {}
irium_outbound_dial_failure_banned_total {}
irium_outbound_dial_failure_backoff_total {}
irium_outbound_dial_failure_other_total {}
irium_inbound_accepted_total {}
irium_handshake_failures_total {}
irium_temp_bans_total {}
irium_unique_connected_peer_ips {}
irium_attempted_peer_ips {}
irium_banned_peers {}
",
        height,
        peer_count,
        anchor_loaded as u8,
        tip_hash,
        mempool_sz,
        anchor_digest,
        node_id_hex,
        sybil_diff,
        seeds.len(),
        era.early_participation_signal as u8,
        relay.new_tip_announced_count,
        relay.block_announce_peers_count_total,
        relay.block_request_count,
        relay.duplicate_block_suppressed_count,
        relay.avg_block_processing_ms,
        relay.avg_block_announce_delay_ms,
        peer_telemetry.outbound_dial_attempts_total,
        peer_telemetry.outbound_dial_success_total,
        peer_telemetry.outbound_dial_failure_total,
        peer_telemetry.outbound_dial_failure_timeout_total,
        peer_telemetry.outbound_dial_failure_refused_total,
        peer_telemetry.outbound_dial_failure_no_route_total,
        peer_telemetry.outbound_dial_failure_banned_total,
        peer_telemetry.outbound_dial_failure_backoff_total,
        peer_telemetry.outbound_dial_failure_other_total,
        peer_telemetry.inbound_accepted_total,
        peer_telemetry.handshake_failures_total,
        peer_telemetry.temp_bans_total,
        peer_telemetry.unique_connected_peer_ips,
        peer_telemetry.attempted_peer_ips,
        peer_telemetry.banned_peers
    ))
}

async fn get_utxo(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<UtxoQuery>,
) -> Result<Json<UtxoResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    let bytes = match hex::decode(&q.txid) {
        Ok(b) => b,
        Err(_) => return Err(StatusCode::BAD_REQUEST),
    };
    if bytes.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut txid = [0u8; 32];
    txid.copy_from_slice(&bytes);

    let guard = state.chain.lock().unwrap_or_else(|e| e.into_inner());
    let key = OutPoint {
        txid,
        index: q.index,
    };
    if let Some(utxo) = guard.utxos.get(&key) {
        Ok(Json(UtxoResponse {
            value: utxo.output.value,
            height: utxo.height,
            is_coinbase: utxo.is_coinbase,
        }))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn get_balance(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<BalanceQuery>,
) -> Result<Json<BalanceResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    let pkh = base58_p2pkh_to_hash(&q.address).ok_or(StatusCode::BAD_REQUEST)?;
    if pkh.len() != 20 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut pkh_arr = [0u8; 20];
    pkh_arr.copy_from_slice(&pkh);

    let (balance, utxo_count, mined_balance, mined_blocks, height) = {
        let guard = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let mut balance = 0u64;
        let mut utxo_count = 0usize;
        let mut mined_balance = 0u64;
        let mut mined_blocks = 0usize;
        for utxo in guard.utxos.values() {
            if let Some(script_pkh) = p2pkh_hash_from_script(&utxo.output.script_pubkey) {
                if script_pkh == pkh_arr {
                    balance = balance.saturating_add(utxo.output.value);
                    utxo_count += 1;
                    if utxo.is_coinbase {
                        mined_balance = mined_balance.saturating_add(utxo.output.value);
                        mined_blocks += 1;
                    }
                }
            }
        }
        (
            balance,
            utxo_count,
            mined_balance,
            mined_blocks,
            guard.tip_height(),
        )
    };

    Ok(Json(BalanceResponse {
        address: q.address,
        pkh: hex::encode(pkh_arr),
        balance,
        mined_balance,
        utxo_count,
        mined_blocks,
        height,
    }))
}

async fn get_utxos(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<UtxosQuery>,
) -> Result<Json<UtxosResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    let pkh = base58_p2pkh_to_hash(&q.address).ok_or(StatusCode::BAD_REQUEST)?;
    if pkh.len() != 20 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut pkh_arr = [0u8; 20];
    pkh_arr.copy_from_slice(&pkh);

    let (utxos, height) = {
        let guard = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let mut items = Vec::new();
        for (outpoint, utxo) in guard.utxos.iter() {
            if let Some(script_pkh) = p2pkh_hash_from_script(&utxo.output.script_pubkey) {
                if script_pkh == pkh_arr {
                    items.push(UtxoItem {
                        txid: hex::encode(outpoint.txid),
                        index: outpoint.index,
                        value: utxo.output.value,
                        height: utxo.height,
                        is_coinbase: utxo.is_coinbase,
                        script_pubkey: hex::encode(&utxo.output.script_pubkey),
                    });
                }
            }
        }
        (items, guard.tip_height())
    };

    Ok(Json(UtxosResponse {
        address: q.address,
        pkh: hex::encode(pkh_arr),
        height,
        utxos,
    }))
}

// /rpc/richlist?limit=N
//
// Top-N IRM holders, ranked by spendable P2PKH balance. Walks the in-memory
// UTXO set under a single chain-lock so the response is internally
// consistent: total_supply_sats and the per-entry percentages always refer
// to the same height. Non-P2PKH outputs (multisig escrows, OP_RETURN,
// future template scripts) are excluded from the per-address aggregation
// but still count toward total_supply_sats — clients can sanity-check that
// the sum of entry balances is <= total_supply.
//
// Limit defaults to 100, clamped to [1, 500] so a single request can never
// trigger base58-encoding of the whole address space.
async fn get_richlist(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<RichlistQuery>,
) -> Result<Json<RichlistResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;

    let limit = q.limit.unwrap_or(100).clamp(1, 500) as usize;

    // Aggregate balances + UTXO counts + total supply in a single pass.
    let (balances, total_supply, height) = {
        let guard = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let mut acc: HashMap<[u8; 20], (u64, u32)> = HashMap::new();
        let mut total: u64 = 0;
        for utxo in guard.utxos.values() {
            let value = utxo.output.value;
            total = total.saturating_add(value);
            if let Some(pkh) = p2pkh_hash_from_script(&utxo.output.script_pubkey) {
                let entry = acc.entry(pkh).or_insert((0u64, 0u32));
                entry.0 = entry.0.saturating_add(value);
                entry.1 = entry.1.saturating_add(1);
            }
        }
        (acc, total, guard.tip_height())
    };

    // Sort descending by balance; ties broken by raw PKH so output is
    // deterministic across calls (frontend caching, test reproducibility).
    let mut sorted: Vec<([u8; 20], (u64, u32))> = balances.into_iter().collect();
    sorted.sort_by(|a, b| b.1 .0.cmp(&a.1 .0).then_with(|| a.0.cmp(&b.0)));
    sorted.truncate(limit);

    let entries: Vec<RichlistEntry> = sorted
        .into_iter()
        .enumerate()
        .map(|(i, (pkh, (bal, utxos)))| {
            let percentage = if total_supply > 0 {
                (bal as f64) / (total_supply as f64) * 100.0
            } else {
                0.0
            };
            RichlistEntry {
                rank: (i + 1) as u32,
                address: base58_p2pkh_from_hash(&pkh),
                balance_sats: bal,
                balance_irm: (bal as f64) / 100_000_000.0,
                utxo_count: utxos,
                percentage,
            }
        })
        .collect();

    Ok(Json(RichlistResponse {
        count: entries.len(),
        total_supply_sats: total_supply,
        generated_at_height: height,
        entries,
    }))
}

fn agreement_party_address<'a>(
    agreement: &'a AgreementObject,
    party_id: &str,
) -> Result<&'a str, StatusCode> {
    agreement
        .parties
        .iter()
        .find(|p| p.party_id == party_id)
        .map(|p| p.address.as_str())
        .ok_or(StatusCode::BAD_REQUEST)
}

fn agreement_anchor_value(
    agreement: &AgreementObject,
    role: AgreementAnchorRole,
    milestone_id: Option<&str>,
) -> u64 {
    if let Some(mid) = milestone_id {
        if let Some(ms) = agreement.milestones.iter().find(|m| m.milestone_id == mid) {
            return ms.amount;
        }
    }
    match role {
        AgreementAnchorRole::DepositLock | AgreementAnchorRole::CollateralLock => agreement
            .deposit_rule
            .as_ref()
            .map(|r| r.amount)
            .unwrap_or(agreement.total_amount),
        _ => agreement.total_amount,
    }
}

fn scan_agreement_linked_txs(
    chain: &ChainState,
    agreement: &AgreementObject,
    agreement_hash: &str,
) -> Vec<AgreementLinkedTx> {
    let mut txs = Vec::new();
    for (height, block) in chain.chain.iter().enumerate() {
        for tx in &block.transactions {
            let txid = hex::encode(tx.txid());
            for output in &tx.outputs {
                if let Some(anchor) = parse_agreement_anchor(&output.script_pubkey) {
                    if anchor.agreement_hash == agreement_hash {
                        txs.push(AgreementLinkedTx {
                            txid: txid.clone(),
                            role: anchor.role,
                            milestone_id: anchor.milestone_id.clone(),
                            height: Some(height as u64),
                            confirmed: true,
                            value: agreement_anchor_value(
                                agreement,
                                anchor.role,
                                anchor.milestone_id.as_deref(),
                            ),
                        });
                    }
                }
            }
        }
    }
    txs.sort_by(|a, b| {
        b.height
            .cmp(&a.height)
            .then_with(|| a.txid.cmp(&b.txid))
            .then_with(|| a.milestone_id.cmp(&b.milestone_id))
    });
    txs
}

/// GROUP F: hash-only variant of scan_agreement_linked_txs. Used by the
/// GET /rpc/agreementreceipt endpoint, which knows only the agreement
/// hash (the wallet has the full AgreementObject locally). Returns all
/// linked txs anchored to the hash with value=0; the wallet overlays
/// agreement.milestones[].amount and agreement.total_amount to populate
/// values in the final receipt. Sort order matches the AgreementObject
/// variant (height descending, then txid, then milestone_id).
fn scan_linked_txs_by_hash(
    chain: &ChainState,
    agreement_hash: &str,
) -> Vec<AgreementLinkedTx> {
    let mut txs = Vec::new();
    for (height, block) in chain.chain.iter().enumerate() {
        for tx in &block.transactions {
            let txid = hex::encode(tx.txid());
            for output in &tx.outputs {
                if let Some(anchor) = parse_agreement_anchor(&output.script_pubkey) {
                    if anchor.agreement_hash == agreement_hash {
                        txs.push(AgreementLinkedTx {
                            txid: txid.clone(),
                            role: anchor.role,
                            milestone_id: anchor.milestone_id.clone(),
                            height: Some(height as u64),
                            confirmed: true,
                            value: 0,
                        });
                    }
                }
            }
        }
    }
    txs.sort_by(|a, b| {
        b.height
            .cmp(&a.height)
            .then_with(|| a.txid.cmp(&b.txid))
            .then_with(|| a.milestone_id.cmp(&b.milestone_id))
    });
    txs
}

/// LAYER 3: lightweight chain scan answering "has any on-chain tx anchored
/// this agreement hash yet?". Used by the offer-watcher to decide whether
/// to relist a taken-but-unfunded offer once the grace window expires. Only
/// needs the agreement hash (no full AgreementObject), so it's cheap to
/// call from the watcher without keeping agreement files mirrored on the
/// seller's machine.
fn agreement_hash_funded_on_chain(chain: &ChainState, agreement_hash: &str) -> bool {
    for block in &chain.chain {
        for tx in &block.transactions {
            for output in &tx.outputs {
                if let Some(anchor) = parse_agreement_anchor(&output.script_pubkey) {
                    if anchor.agreement_hash == agreement_hash {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn find_confirmed_tx_by_id(chain: &ChainState, txid_hex: &str) -> Result<Transaction, String> {
    let target = hex_to_32(txid_hex.trim()).map_err(|e| format!("invalid funding_txid: {e}"))?;
    for block in &chain.chain {
        for tx in &block.transactions {
            if tx.txid() == target {
                return Ok(tx.clone());
            }
        }
    }
    Err("funding_tx_not_found_on_chain".to_string())
}

fn resolve_agreement_leg_ref(
    chain: &ChainState,
    agreement: &AgreementObject,
    agreement_hash: &str,
    funding_txid: &str,
    htlc_vout: Option<u32>,
    milestone_id: Option<&str>,
) -> Result<AgreementFundingLegRef, String> {
    let tx = find_confirmed_tx_by_id(chain, funding_txid)?;
    let mut refs = extract_agreement_funding_leg_refs_from_tx(&tx, agreement_hash);
    refs.retain(|r| {
        matches!(
            r.role,
            AgreementAnchorRole::Funding
                | AgreementAnchorRole::DepositLock
                | AgreementAnchorRole::OtcSettlement
                | AgreementAnchorRole::MerchantSettlement
        )
    });
    if let Some(vout) = htlc_vout {
        refs.retain(|r| r.htlc_vout == vout);
    }
    if let Some(mid) = milestone_id {
        refs.retain(|r| r.milestone_id.as_deref() == Some(mid));
    }
    if refs.is_empty() {
        return Err("agreement_funding_leg_not_found_or_not_htlc_backed".to_string());
    }
    if refs.len() > 1 {
        return Err("agreement_funding_leg_ambiguous".to_string());
    }
    let resolved = refs.remove(0);
    let expected_amount = if let Some(mid) = resolved.milestone_id.as_deref() {
        agreement
            .milestones
            .iter()
            .find(|m| m.milestone_id == mid)
            .map(|m| m.amount)
            .unwrap_or(agreement.total_amount)
    } else {
        match resolved.role {
            AgreementAnchorRole::DepositLock | AgreementAnchorRole::CollateralLock => agreement
                .deposit_rule
                .as_ref()
                .map(|r| r.amount)
                .unwrap_or(agreement.total_amount),
            _ => agreement.total_amount,
        }
    };
    if resolved.amount != expected_amount {
        return Err("agreement_leg_amount_mismatch".to_string());
    }
    Ok(resolved)
}

fn agreement_observation_trust_note() -> String {
    "Phase 1 agreement funding leg discovery and activity timelines are reconstructed from the supplied canonical agreement object, optional local bundle hints, on-chain anchor observations, and HTLCv1 branch checks. They do not create native consensus agreement state.".to_string()
}

fn verify_agreement_context_bundle(
    agreement: &AgreementObject,
    bundle: Option<&AgreementBundle>,
    agreement_hash: &str,
) -> Result<Option<AgreementBundle>, String> {
    let Some(bundle) = bundle else {
        return Ok(None);
    };
    verify_agreement_bundle(bundle)?;
    if bundle.agreement_hash != agreement_hash {
        return Err("bundle agreement hash does not match supplied agreement".to_string());
    }
    if bundle.agreement != *agreement {
        return Err("bundle agreement object does not match supplied agreement".to_string());
    }
    Ok(Some(bundle.clone()))
}

fn collect_agreement_funding_leg_refs(
    chain: &ChainState,
    agreement: &AgreementObject,
    agreement_hash: &str,
) -> Vec<AgreementFundingLegRef> {
    let linked = scan_agreement_linked_txs(chain, agreement, agreement_hash);
    let mut refs = Vec::new();
    let mut seen = Vec::<String>::new();
    for tx in linked.iter().filter(|tx| {
        matches!(
            tx.role,
            AgreementAnchorRole::Funding
                | AgreementAnchorRole::DepositLock
                | AgreementAnchorRole::OtcSettlement
                | AgreementAnchorRole::MerchantSettlement
        )
    }) {
        if seen.iter().any(|existing| existing == &tx.txid) {
            continue;
        }
        seen.push(tx.txid.clone());
        if let Ok(observed_tx) = find_confirmed_tx_by_id(chain, &tx.txid) {
            refs.extend(extract_agreement_funding_leg_refs_from_tx(
                &observed_tx,
                agreement_hash,
            ));
        }
    }
    refs.sort_by(|a, b| {
        a.milestone_id
            .cmp(&b.milestone_id)
            .then_with(|| a.funding_txid.cmp(&b.funding_txid))
            .then_with(|| a.htlc_vout.cmp(&b.htlc_vout))
    });
    refs
}

fn build_agreement_funding_leg_candidate_views(
    chain: &ChainState,
    agreement: &AgreementObject,
    agreement_hash: &str,
    bundle: Option<&AgreementBundle>,
) -> Result<Vec<AgreementFundingLegCandidateResponse>, String> {
    let linked = scan_agreement_linked_txs(chain, agreement, agreement_hash);
    let refs = collect_agreement_funding_leg_refs(chain, agreement, agreement_hash);
    let candidates = discover_agreement_funding_leg_candidates(
        agreement_hash,
        &linked,
        &refs,
        bundle.map(|b| &b.metadata),
    )?;
    let mut out = Vec::new();
    for candidate in candidates {
        let release_eval = evaluate_agreement_spend_eligibility(
            true,
            chain,
            agreement,
            &AgreementSpendRequest {
                agreement: agreement.clone(),
                funding_txid: candidate.funding_txid.clone(),
                htlc_vout: Some(candidate.htlc_vout),
                milestone_id: candidate.milestone_id.clone(),
                destination_address: None,
                fee_per_byte: None,
                broadcast: Some(false),
                secret_hex: None,
            },
        )?;
        let refund_eval = evaluate_agreement_spend_eligibility(
            false,
            chain,
            agreement,
            &AgreementSpendRequest {
                agreement: agreement.clone(),
                funding_txid: candidate.funding_txid.clone(),
                htlc_vout: Some(candidate.htlc_vout),
                milestone_id: candidate.milestone_id.clone(),
                destination_address: None,
                fee_per_byte: None,
                broadcast: Some(false),
                secret_hex: None,
            },
        )?;
        out.push(AgreementFundingLegCandidateResponse {
            agreement_hash: candidate.agreement_hash,
            funding_txid: candidate.funding_txid,
            htlc_vout: candidate.htlc_vout,
            anchor_vout: candidate.anchor_vout,
            role: candidate.role,
            milestone_id: candidate.milestone_id,
            amount: candidate.amount,
            htlc_backed: candidate.htlc_backed,
            timeout_height: candidate.timeout_height,
            recipient_address: candidate.recipient_address,
            refund_address: candidate.refund_address,
            source_notes: candidate.source_notes,
            release_eligible: release_eval.eligible,
            release_reasons: release_eval.reasons,
            refund_eligible: refund_eval.eligible,
            refund_reasons: refund_eval.reasons,
        });
    }
    Ok(out)
}

fn agreement_spend_trust_note() -> String {
    "Phase 1 agreement release/refund uses existing HTLCv1 spend rules only. Agreement lifecycle, milestone meaning, and settlement context remain metadata/indexed and require off-chain agreement exchange.".to_string()
}

fn evaluate_agreement_spend_eligibility(
    claim: bool,
    chain: &ChainState,
    agreement: &AgreementObject,
    req: &AgreementSpendRequest,
) -> Result<AgreementSpendEligibilityResponse, String> {
    agreement.validate()?;
    let agreement_hash = compute_agreement_hash_hex(agreement)?;
    let leg = resolve_agreement_leg_ref(
        chain,
        agreement,
        &agreement_hash,
        &req.funding_txid,
        req.htlc_vout,
        req.milestone_id.as_deref(),
    )?;
    let outpoint = OutPoint {
        txid: hex_to_32(req.funding_txid.trim())
            .map_err(|e| format!("invalid funding_txid: {e}"))?,
        index: leg.htlc_vout,
    };
    let maybe_utxo = chain.utxos.get(&outpoint).cloned();
    let unspent = maybe_utxo.is_some();
    let tip_height = chain.tip_height();
    let timeout_reached = tip_height >= leg.timeout_height;
    let mut reasons = Vec::new();
    let preimage_required = claim;
    if !unspent {
        reasons.push("funding_leg_already_spent_or_missing".to_string());
    }
    if claim {
        match req.secret_hex.as_deref() {
            Some(secret_hex) => {
                let preimage = hex::decode(secret_hex.trim())
                    .map_err(|_| "secret_hex_invalid_hex".to_string())?;
                let digest = Sha256::digest(&preimage);
                if hex::encode(digest) != leg.expected_hash {
                    reasons.push("secret_hash_mismatch".to_string());
                }
            }
            None => reasons.push("secret_hex_required_for_release".to_string()),
        }
    } else if !timeout_reached {
        reasons.push("refund_timeout_not_reached".to_string());
    }
    let destination_address = req.destination_address.clone().or_else(|| {
        if claim {
            Some(leg.recipient_address.clone())
        } else {
            Some(leg.refund_address.clone())
        }
    });
    let eligible = reasons.is_empty() && destination_address.is_some();
    Ok(AgreementSpendEligibilityResponse {
        agreement_hash,
        agreement_id: agreement.agreement_id.clone(),
        funding_txid: req.funding_txid.clone(),
        htlc_vout: Some(leg.htlc_vout),
        anchor_vout: Some(leg.anchor_vout),
        role: Some(leg.role),
        milestone_id: leg.milestone_id.clone(),
        amount: Some(leg.amount),
        branch: if claim {
            "release".to_string()
        } else {
            "refund".to_string()
        },
        htlc_backed: true,
        funded: true,
        unspent,
        preimage_required,
        timeout_height: Some(leg.timeout_height),
        timeout_reached,
        destination_address,
        expected_hash: Some(leg.expected_hash.clone()),
        recipient_address: Some(leg.recipient_address.clone()),
        refund_address: Some(leg.refund_address.clone()),
        eligible,
        reasons,
        trust_model_note: agreement_spend_trust_note(),
    })
}

fn spend_htlc_from_params(
    claim: bool,
    state: &AppState,
    funding_txid: &str,
    vout: u32,
    destination_address: &str,
    fee_per_byte: Option<u64>,
    broadcast: Option<bool>,
    secret_hex: Option<&str>,
) -> Result<SpendHtlcResponse, StatusCode> {
    spend_htlc_with_optional_payout(
        claim,
        state,
        funding_txid,
        vout,
        destination_address,
        fee_per_byte,
        broadcast,
        secret_hex,
        None,
    )
}

fn spend_htlc_with_optional_payout(
    claim: bool,
    state: &AppState,
    funding_txid: &str,
    vout: u32,
    destination_address: &str,
    fee_per_byte: Option<u64>,
    broadcast: Option<bool>,
    secret_hex: Option<&str>,
    resolver_payout: Option<(String, u64)>,
) -> Result<SpendHtlcResponse, StatusCode> {
    {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let active = chain
            .params
            .htlcv1_activation_height
            .map(|h| chain.height >= h)
            .unwrap_or(false);
        if !active {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    let txid_arr = hex_to_32(funding_txid.trim()).map_err(|_| StatusCode::BAD_REQUEST)?;
    let (funding_out, tip_height) = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let key = OutPoint {
            txid: txid_arr,
            index: vout,
        };
        let utxo = chain
            .utxos
            .get(&key)
            .cloned()
            .ok_or(StatusCode::BAD_REQUEST)?;
        (utxo, chain.tip_height())
    };
    let htlc =
        parse_htlcv1_script(&funding_out.output.script_pubkey).ok_or(StatusCode::BAD_REQUEST)?;
    let signer_pkh = if claim {
        htlc.recipient_pkh
    } else {
        htlc.refund_pkh
    };
    if !claim && tip_height < htlc.timeout_height {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut wallet = state.wallet.lock().unwrap_or_else(|e| e.into_inner());
    let keys = wallet.keys().map_err(|_| StatusCode::BAD_REQUEST)?;
    let mut key: Option<WalletKey> = None;
    for k in keys {
        let b = hex::decode(&k.pkh).map_err(|_| StatusCode::BAD_REQUEST)?;
        if b.len() != 20 {
            continue;
        }
        let mut pkh = [0u8; 20];
        pkh.copy_from_slice(&b);
        if pkh == signer_pkh {
            key = Some(k);
            break;
        }
    }
    let key = key.ok_or(StatusCode::FORBIDDEN)?;
    let dest = base58_p2pkh_to_hash(destination_address).ok_or(StatusCode::BAD_REQUEST)?;
    if dest.len() != 20 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut dest_pkh = [0u8; 20];
    dest_pkh.copy_from_slice(&dest);
    let fee_per_byte = fee_per_byte.unwrap_or(1).max(1);
    let num_outputs = if resolver_payout.is_some() { 2 } else { 1 };
    let fee = estimate_tx_size(1, num_outputs).saturating_mul(fee_per_byte);
    if funding_out.output.value <= fee {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut outputs: Vec<TxOutput> = Vec::with_capacity(num_outputs);
    if let Some((ref resolver_addr, resolver_fee)) = resolver_payout {
        if resolver_fee == 0 {
            return Err(StatusCode::BAD_REQUEST);
        }
        if funding_out.output.value <= resolver_fee.saturating_add(fee) {
            return Err(StatusCode::BAD_REQUEST);
        }
        outputs.push(TxOutput {
            value: funding_out.output.value - fee - resolver_fee,
            script_pubkey: p2pkh_script(&dest_pkh),
        });
        let resolver_pkh_vec = base58_p2pkh_to_hash(resolver_addr)
            .ok_or(StatusCode::BAD_REQUEST)?;
        if resolver_pkh_vec.len() != 20 {
            return Err(StatusCode::BAD_REQUEST);
        }
        let mut resolver_pkh = [0u8; 20];
        resolver_pkh.copy_from_slice(&resolver_pkh_vec);
        outputs.push(TxOutput {
            value: resolver_fee,
            script_pubkey: p2pkh_script(&resolver_pkh),
        });
    } else {
        outputs.push(TxOutput {
            value: funding_out.output.value - fee,
            script_pubkey: p2pkh_script(&dest_pkh),
        });
    }
    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid: txid_arr,
            prev_index: vout,
            script_sig: Vec::new(),
            sequence: 0xffff_fffe,
        }],
        outputs,
        locktime: 0,
    };
    let digest = signature_digest(&tx, 0, &funding_out.output.script_pubkey);
    let priv_bytes = hex::decode(&key.privkey).map_err(|_| StatusCode::BAD_REQUEST)?;
    if priv_bytes.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(&priv_bytes);
    let signing_key =
        SigningKey::from_bytes((&sk_bytes).into()).map_err(|_| StatusCode::BAD_REQUEST)?;
    let sig: Signature = signing_key
        .sign_prehash(&digest)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let sig = sig.normalize_s().unwrap_or(sig);
    let mut sig_bytes = sig.to_der().as_bytes().to_vec();
    sig_bytes.push(0x01);
    let pubkey = signing_key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    tx.inputs[0].script_sig = if claim {
        let secret_hex = secret_hex.ok_or(StatusCode::BAD_REQUEST)?;
        let preimage = hex::decode(secret_hex.trim()).map_err(|_| StatusCode::BAD_REQUEST)?;
        encode_htlcv1_claim_witness(&sig_bytes, &pubkey, &preimage)
            .ok_or(StatusCode::BAD_REQUEST)?
    } else {
        encode_htlcv1_refund_witness(&sig_bytes, &pubkey).ok_or(StatusCode::BAD_REQUEST)?
    };
    let fee_checked = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain
            .calculate_fees(&tx)
            .map_err(|_| StatusCode::BAD_REQUEST)?
    };
    let raw = tx.serialize();
    let txid = tx.txid();
    let txid_hex = hex::encode(txid);
    let mut accepted = false;
    if broadcast.unwrap_or(false) {
        let mut mempool = state.mempool.lock().unwrap_or_else(|e| e.into_inner());
        if !mempool.contains(&txid) {
            accepted = mempool
                .add_transaction(tx, raw.clone(), fee_checked)
                .is_ok();
        }
    }
    Ok(SpendHtlcResponse {
        txid: txid_hex,
        accepted,
        raw_tx_hex: hex::encode(raw),
        fee: fee_checked,
    })
}

#[derive(Deserialize)]
struct AddSeedRequest {
    addr: String,
}

/// POST /rpc/stop — graceful shutdown endpoint. Authenticated via the
/// same Bearer-token mechanism as the other privileged RPCs AND
/// restricted to loopback callers regardless of token validity. Both
/// guards are required because the desktop launcher binds iriumd's
/// RPC to 0.0.0.0:38300 to expose the marketplace feed; a leaked
/// token must not be usable to remote-DoS arbitrary nodes.
///
/// On success the handler kicks off a background task that flushes
/// peers to the runtime database, drains the persist queue (same
/// IRIUM_PERSIST_DRAIN_SECS envelope as the SIGTERM handler, default
/// 15 s, clamped to 20 s), then std::process::exit(0). The HTTP
/// response (202 Accepted) is flushed before the exit so the desktop
/// graceful-shutdown helper can confirm iriumd accepted the request.
async fn stop_handler(
    ConnectInfo(conn): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<Value>), StatusCode> {
    if !conn.ip().is_loopback() {
        return Err(StatusCode::FORBIDDEN);
    }
    require_rpc_auth(&headers)?;

    let persist_drain_secs = std::env::var("IRIUM_PERSIST_DRAIN_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(15)
        .clamp(0, 20);
    let p2p_for_shutdown = state.p2p.clone();

    tokio::spawn(async move {
        if let Some(ref node) = p2p_for_shutdown {
            node.flush_peers_to_runtime().await;
        }
        let ok = storage::drain_persist_queue(Duration::from_secs(persist_drain_secs));
        if ok {
            eprintln!("[i] persist queue drained via /rpc/stop");
        } else {
            eprintln!(
                "[warn] persist queue drain timeout via /rpc/stop; remaining_queue_len={}",
                storage::persist_queue_len()
            );
        }
        std::process::exit(0);
    });

    Ok((
        StatusCode::ACCEPTED,
        Json(json!({
            "status": "draining",
            "drain_secs": persist_drain_secs,
        })),
    ))
}

async fn admin_add_seed(
    ConnectInfo(_conn): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<AddSeedRequest>,
) -> Result<Json<Value>, StatusCode> {
    require_rpc_auth(&headers)?;
    let addr_str = req.addr.trim().to_string();
    if addr_str.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    {
        let runtime_path = storage::bootstrap_dir().join("seedlist.runtime");
        if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(&runtime_path) {
            use std::io::Write;
            let _ = writeln!(file, "{}", addr_str);
        }
    }
    if let Some(ref node) = state.p2p {
        if let Ok(sa) = addr_str.parse::<SocketAddr>() {
            let node_c = node.clone();
            let height = state.chain.lock().unwrap_or_else(|e| e.into_inner()).tip_height();
            tokio::spawn(async move {
                let _ = node_c.connect_and_handshake(sa, height, "Irium-Node").await;
            });
        }
    }
    Ok(Json(json!({ "added": true })))
}

async fn create_agreement(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<AgreementRequest>,
) -> Result<Json<AgreementInspectResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    require_rpc_auth(&headers)?;
    let summary = req
        .agreement
        .summary()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(Json(AgreementInspectResponse {
        agreement_hash: summary.agreement_hash.clone(),
        summary,
        currency: SETTLEMENT_CURRENCY,
    }))
}

async fn inspect_agreement(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<AgreementRequest>,
) -> Result<Json<AgreementInspectResponse>, StatusCode> {
    create_agreement(ConnectInfo(addr), State(state), headers, AxumJson(req)).await
}

async fn compute_agreement_hash_rpc(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<AgreementRequest>,
) -> Result<Json<AgreementHashResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    require_rpc_auth(&headers)?;
    let agreement_hash =
        compute_agreement_hash_hex(&req.agreement).map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(Json(AgreementHashResponse { agreement_hash }))
}

async fn list_agreement_txs(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<AgreementRequest>,
) -> Result<Json<AgreementTxsResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    require_rpc_auth(&headers)?;
    let agreement_hash =
        compute_agreement_hash_hex(&req.agreement).map_err(|_| StatusCode::BAD_REQUEST)?;
    let txs = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        scan_agreement_linked_txs(&chain, &req.agreement, &agreement_hash)
    };
    Ok(Json(AgreementTxsResponse {
        agreement_hash,
        txs,
    }))
}

async fn agreement_funding_legs(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<AgreementContextRequest>,
) -> Result<Json<AgreementFundingLegsResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    require_rpc_auth(&headers)?;
    let agreement_hash =
        compute_agreement_hash_hex(&req.agreement).map_err(|_| StatusCode::BAD_REQUEST)?;
    let bundle =
        verify_agreement_context_bundle(&req.agreement, req.bundle.as_ref(), &agreement_hash)
            .map_err(|_| StatusCode::BAD_REQUEST)?;
    let candidates = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        build_agreement_funding_leg_candidate_views(
            &chain,
            &req.agreement,
            &agreement_hash,
            bundle.as_ref(),
        )
        .map_err(|_| StatusCode::BAD_REQUEST)?
    };
    Ok(Json(AgreementFundingLegsResponse {
        agreement_hash,
        selection_required: candidates.len() != 1,
        candidates,
        trust_model_note: agreement_observation_trust_note(),
    }))
}

async fn agreement_timeline(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<AgreementContextRequest>,
) -> Result<Json<AgreementTimelineResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    require_rpc_auth(&headers)?;
    let agreement_hash =
        compute_agreement_hash_hex(&req.agreement).map_err(|_| StatusCode::BAD_REQUEST)?;
    let bundle =
        verify_agreement_context_bundle(&req.agreement, req.bundle.as_ref(), &agreement_hash)
            .map_err(|_| StatusCode::BAD_REQUEST)?;
    let (lifecycle, events) = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let linked = scan_agreement_linked_txs(&chain, &req.agreement, &agreement_hash);
        let lifecycle = derive_lifecycle(
            &req.agreement,
            &agreement_hash,
            linked.clone(),
            chain.tip_height(),
        );
        let refs = collect_agreement_funding_leg_refs(&chain, &req.agreement, &agreement_hash);
        let candidates = discover_agreement_funding_leg_candidates(
            &agreement_hash,
            &linked,
            &refs,
            bundle.as_ref().map(|b| &b.metadata),
        )
        .map_err(|_| StatusCode::BAD_REQUEST)?;
        let candidate_views = build_agreement_funding_leg_candidate_views(
            &chain,
            &req.agreement,
            &agreement_hash,
            bundle.as_ref(),
        )
        .map_err(|_| StatusCode::BAD_REQUEST)?;
        let mut events = build_agreement_activity_timeline(
            &agreement_hash,
            &lifecycle,
            &linked,
            &candidates,
            bundle.as_ref(),
        );
        for candidate in &candidate_views {
            if candidate.release_eligible {
                events.push(AgreementActivityEvent {
                    event_type: "release_eligible".to_string(),
                    source: irium_node_rs::settlement::AgreementActivitySource::HtlcEligibility,
                    txid: Some(candidate.funding_txid.clone()),
                    height: None,
                    timestamp: None,
                    milestone_id: candidate.milestone_id.clone(),
                    note: Some(
                        "HTLC release branch is currently eligible with the provided default context"
                            .to_string(),
                    ),
                });
            }
            if candidate.refund_eligible {
                events.push(AgreementActivityEvent {
                    event_type: "refund_eligible".to_string(),
                    source: irium_node_rs::settlement::AgreementActivitySource::HtlcEligibility,
                    txid: Some(candidate.funding_txid.clone()),
                    height: None,
                    timestamp: None,
                    milestone_id: candidate.milestone_id.clone(),
                    note: Some(
                        "HTLC refund branch is currently eligible with the observed timeout state"
                            .to_string(),
                    ),
                });
            }
        }
        (lifecycle, events)
    };
    Ok(Json(AgreementTimelineResponse {
        agreement_hash,
        lifecycle,
        events,
        trust_model_note: agreement_observation_trust_note(),
    }))
}

async fn agreement_status(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<AgreementRequest>,
) -> Result<Json<AgreementStatusResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    require_rpc_auth(&headers)?;
    let agreement_hash =
        compute_agreement_hash_hex(&req.agreement).map_err(|_| StatusCode::BAD_REQUEST)?;
    let (lifecycle, tip_height) = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let tip = chain.tip_height();
        let linked = scan_agreement_linked_txs(&chain, &req.agreement, &agreement_hash);
        (derive_lifecycle(&req.agreement, &agreement_hash, linked, tip), tip)
    };
    // Compute proof finality depth for this agreement.
    let finality_depth = proof_finality_depth();
    let (proof_depth, proof_final) = {
        let heights = state.proof_heights.lock().unwrap_or_else(|e| e.into_inner());
        let store = state.proof_store.lock().unwrap_or_else(|e| e.into_inner());
        let proof_ids: Vec<String> = store
            .list_by_agreement(&agreement_hash)
            .into_iter()
            .map(|p| p.proof_id.clone())
            .collect();
        // Find the minimum submitted_at_height across all proofs for this agreement
        // (the shallowest proof needs to reach finality depth first).
        let min_height = proof_ids
            .iter()
            .filter_map(|id| heights.get(id).copied())
            .reduce(u64::min);
        match min_height {
            None => (None, false),
            Some(h) => {
                let depth = tip_height.saturating_sub(h);
                (Some(depth), depth >= finality_depth)
            }
        }
    };
    let release_eligible = proof_final && matches!(
        lifecycle.state,
        irium_node_rs::settlement::AgreementLifecycleState::Funded
            | irium_node_rs::settlement::AgreementLifecycleState::PartiallyReleased
    );
    Ok(Json(AgreementStatusResponse {
        agreement_hash,
        lifecycle,
        proof_depth,
        proof_final,
        release_eligible,
    }))
}

async fn agreement_milestones(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<AgreementRequest>,
) -> Result<Json<AgreementMilestonesResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    require_rpc_auth(&headers)?;
    let agreement_hash =
        compute_agreement_hash_hex(&req.agreement).map_err(|_| StatusCode::BAD_REQUEST)?;
    let lifecycle = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let linked = scan_agreement_linked_txs(&chain, &req.agreement, &agreement_hash);
        derive_lifecycle(&req.agreement, &agreement_hash, linked, chain.tip_height())
    };
    Ok(Json(AgreementMilestonesResponse {
        agreement_hash,
        state: format!("{:?}", lifecycle.state).to_lowercase(),
        milestones: lifecycle.milestones,
    }))
}

// GROUP F: GET /rpc/agreementreceipt?agreement_hash=<hex>
// Returns on-chain-derivable receipt data. The wallet enriches with
// the local AgreementObject (template_type / parties / total_amount /
// per-milestone amounts) and signs before exporting.
async fn agreement_receipt(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<AgreementReceiptQuery>,
) -> Result<Json<AgreementReceiptResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    require_rpc_auth(&headers)?;
    let agreement_hash = q.agreement_hash.trim().to_string();
    if agreement_hash.len() != 64 || !agreement_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let (tip_height, linked_txs) = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let tip = chain.tip_height();
        let linked = scan_linked_txs_by_hash(&chain, &agreement_hash);
        (tip, linked)
    };
    let to_txid_with_height = |t: &AgreementLinkedTx| TxidWithHeight {
        txid: t.txid.clone(),
        height: t.height,
        milestone_id: t.milestone_id.clone(),
        value: t.value,
    };
    let funding_txids: Vec<TxidWithHeight> = linked_txs
        .iter()
        .filter(|t| {
            matches!(
                t.role,
                AgreementAnchorRole::Funding
                    | AgreementAnchorRole::DepositLock
                    | AgreementAnchorRole::OtcSettlement
                    | AgreementAnchorRole::MerchantSettlement
            )
        })
        .map(to_txid_with_height)
        .collect();
    let release_txids: Vec<TxidWithHeight> = linked_txs
        .iter()
        .filter(|t| {
            matches!(
                t.role,
                AgreementAnchorRole::Release | AgreementAnchorRole::MilestoneRelease
            )
        })
        .map(to_txid_with_height)
        .collect();
    let refund_txids: Vec<TxidWithHeight> = linked_txs
        .iter()
        .filter(|t| matches!(t.role, AgreementAnchorRole::Refund))
        .map(to_txid_with_height)
        .collect();
    let resolved_height = release_txids
        .iter()
        .chain(refund_txids.iter())
        .filter_map(|t| t.height)
        .max();
    let final_state_hint = if !refund_txids.is_empty() {
        "refunded".to_string()
    } else if !release_txids.is_empty() {
        "released_or_partial".to_string()
    } else if !funding_txids.is_empty() {
        "funded".to_string()
    } else {
        "proposed".to_string()
    };
    let proofs: Vec<EscrowReceiptProofRef> = {
        let store = state.proof_store.lock().unwrap_or_else(|e| e.into_inner());
        let heights = state.proof_heights.lock().unwrap_or_else(|e| e.into_inner());
        store
            .list_by_agreement(&agreement_hash)
            .into_iter()
            .map(|p| EscrowReceiptProofRef {
                proof_id: p.proof_id.clone(),
                proof_type: p.proof_type.clone(),
                attestation_time: p.attestation_time,
                anchored_at_height: heights.get(&p.proof_id).copied(),
                anchor_txid: None,
            })
            .collect()
    };
    let dispute = {
        let guard = state.disputes_index.lock().unwrap_or_else(|e| e.into_inner());
        guard.get(&agreement_hash).and_then(|d| {
            d.resolution.as_ref().map(|res| EscrowReceiptDisputeRef {
                resolver_address: res.resolver_address.clone(),
                resolver_role: res.resolver_role.clone(),
                outcome: res.outcome.clone(),
                resolved_at_height: res.resolved_at_height,
                message_hash: hex::encode(Sha256::digest(res.message.as_bytes())),
                anchor_txid: d.resolution_anchor_txid.clone(),
            })
        })
    };
    Ok(Json(AgreementReceiptResponse {
        agreement_hash,
        tip_height,
        final_state_hint,
        funding_txids,
        release_txids,
        refund_txids,
        resolved_height,
        linked_txs,
        proofs,
        dispute,
    }))
}

// GROUP H: on-chain reputation event lookup.
// GET /rpc/reputation/:address returns the chain-anchored reputation
// events naming this address, with lifetime + recent counts. The chain
// is authoritative; the wallet's local outcomes file is consulted only
// when this endpoint is unreachable.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct ReputationEventRecord {
    event_kind: String,
    txid: String,
    height: u64,
    /// Full agreement_hash recovered from the carrying tx's agr1
    /// anchor (or from the rep1 event's short hash + chain lookup for
    /// ResolverNonResponse). Empty when unresolvable.
    agreement_hash: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
struct ReputationEventCounts {
    successful_trade: u64,
    dispute_win: u64,
    dispute_loss: u64,
    resolver_non_response: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct ReputationLookupResponse {
    address: String,
    tip_height: u64,
    /// Lifetime counts (since block 0).
    lifetime: ReputationEventCounts,
    /// Counts restricted to the last `recent_window` blocks.
    recent: ReputationEventCounts,
    recent_window: u64,
    events: Vec<ReputationEventRecord>,
}

/// Default recent window matches the wallet's existing
/// ReputationScore "recent" semantics. 4320 blocks ≈ 3 days at the
/// current ~60-second mean block time.
const REPUTATION_RECENT_WINDOW_BLOCKS: u64 = 4320;

/// Walks every confirmed tx on the chain looking for OP_RETURN outputs
/// carrying a rep1: anchor whose address field matches `target`. For
/// each match, recovers the agreement_hash either from a co-located
/// agr1: anchor in the same tx (Q2/Q3 path) or from the rep1 payload's
/// short hash for ResolverNonResponse (Q1 path).
fn scan_reputation_events_for_address(
    chain: &ChainState,
    target: &str,
) -> Vec<ReputationEventRecord> {
    let mut out = Vec::new();
    for (height, block) in chain.chain.iter().enumerate() {
        for tx in &block.transactions {
            // Two-pass: find the rep1 outputs that name `target`, then
            // look for an agr1 output in the same tx for the full
            // agreement_hash. ResolverNonResponse uses the short hash
            // in its own payload and scans the chain for the matching
            // agreement.
            let mut rep_events: Vec<ReputationEvent> = Vec::new();
            let mut agr_hash: Option<String> = None;
            for output in &tx.outputs {
                if let Some(ev) = parse_reputation_event(&output.script_pubkey) {
                    if ev.address == target {
                        rep_events.push(ev);
                    }
                } else if let Some(anchor) = parse_agreement_anchor(&output.script_pubkey) {
                    agr_hash = Some(anchor.agreement_hash.clone());
                }
            }
            if rep_events.is_empty() {
                continue;
            }
            let txid = hex::encode(tx.txid());
            for ev in rep_events {
                let resolved_hash = if let Some(ref h) = agr_hash {
                    h.clone()
                } else if let Some(short) = ev.agreement_short_hash.as_deref() {
                    // Match short_hash prefix against agr1 anchors elsewhere on chain.
                    resolve_agreement_hash_from_short(chain, short).unwrap_or_default()
                } else {
                    String::new()
                };
                out.push(ReputationEventRecord {
                    event_kind: match ev.kind {
                        ReputationEventKind::SuccessfulTrade => "successful_trade".to_string(),
                        ReputationEventKind::DisputeWin => "dispute_win".to_string(),
                        ReputationEventKind::DisputeLoss => "dispute_loss".to_string(),
                        ReputationEventKind::ResolverNonResponse => {
                            "resolver_non_response".to_string()
                        }
                    },
                    txid: txid.clone(),
                    height: height as u64,
                    agreement_hash: resolved_hash,
                });
            }
        }
    }
    out.sort_by(|a, b| b.height.cmp(&a.height).then_with(|| a.txid.cmp(&b.txid)));
    out
}

/// Match a 16-hex-char agreement_short_hash prefix against any agr1:
/// anchor on the chain. Returns the first full match. Used only for
/// ResolverNonResponse events which do not have a co-located agr1
/// anchor in the same tx.
fn resolve_agreement_hash_from_short(chain: &ChainState, short: &str) -> Option<String> {
    for block in &chain.chain {
        for tx in &block.transactions {
            for output in &tx.outputs {
                if let Some(anchor) = parse_agreement_anchor(&output.script_pubkey) {
                    if anchor.agreement_hash.starts_with(short) {
                        return Some(anchor.agreement_hash);
                    }
                }
            }
        }
    }
    None
}

fn count_reputation_events(
    events: &[ReputationEventRecord],
    height_floor: Option<u64>,
) -> ReputationEventCounts {
    let mut c = ReputationEventCounts::default();
    for e in events {
        if let Some(floor) = height_floor {
            if e.height < floor {
                continue;
            }
        }
        match e.event_kind.as_str() {
            "successful_trade" => c.successful_trade += 1,
            "dispute_win" => c.dispute_win += 1,
            "dispute_loss" => c.dispute_loss += 1,
            "resolver_non_response" => c.resolver_non_response += 1,
            _ => {}
        }
    }
    c
}

async fn reputation_lookup(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(address): AxumPath<String>,
) -> Result<Json<ReputationLookupResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    require_rpc_auth(&headers)?;
    if address.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let (tip_height, events) = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let tip = chain.tip_height();
        let evs = scan_reputation_events_for_address(&chain, address.trim());
        (tip, evs)
    };
    let lifetime = count_reputation_events(&events, None);
    let recent_floor = tip_height.saturating_sub(REPUTATION_RECENT_WINDOW_BLOCKS);
    let recent = count_reputation_events(&events, Some(recent_floor));
    Ok(Json(ReputationLookupResponse {
        address,
        tip_height,
        lifetime,
        recent,
        recent_window: REPUTATION_RECENT_WINDOW_BLOCKS,
        events,
    }))
}

async fn verify_agreement_link(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<VerifyAgreementLinkRequest>,
) -> Result<Json<VerifyAgreementLinkResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    require_rpc_auth(&headers)?;
    let raw = hex::decode(req.tx_hex.trim()).map_err(|_| StatusCode::BAD_REQUEST)?;
    let tx = decode_full_tx(&raw).map_err(|_| StatusCode::BAD_REQUEST)?;
    let anchors: Vec<AgreementAnchor> = tx
        .outputs
        .iter()
        .filter_map(|o| parse_agreement_anchor(&o.script_pubkey))
        .filter(|a| a.agreement_hash == req.agreement_hash)
        .collect();
    Ok(Json(VerifyAgreementLinkResponse {
        agreement_hash: req.agreement_hash,
        matched: !anchors.is_empty(),
        anchors,
    }))
}

async fn fund_agreement(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<FundAgreementRequest>,
) -> Result<Json<FundAgreementResponse>, (StatusCode, String)> {
    let bad =
        |reason: &str| -> (StatusCode, String) { (StatusCode::BAD_REQUEST, reason.to_string()) };
    check_rate_with_auth(&state, &addr, &headers)
        .map_err(|sc| (sc, "rate_limit_or_auth_failed".to_string()))?;
    require_rpc_auth(&headers).map_err(|sc| (sc, format!("rpc_auth_failed:{sc}")))?;
    {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let active = chain
            .params
            .htlcv1_activation_height
            .map(|h| chain.height >= h)
            .unwrap_or(false);
        if !active {
            return Err(bad("htlcv1_not_active_at_current_height"));
        }
    }

    req.agreement
        .validate()
        .map_err(|_| bad("agreement_invalid"))?;
    let agreement_hash =
        compute_agreement_hash_hex(&req.agreement).map_err(|_| bad("agreement_hash_failed"))?;
    let payer_addr = agreement_party_address(&req.agreement, &req.agreement.payer)
        .map_err(|_| bad("payer_party_missing"))?;
    let payee_addr = agreement_party_address(&req.agreement, &req.agreement.payee)
        .map_err(|_| bad("payee_party_missing"))?;
    let payer_vec =
        base58_p2pkh_to_hash(payer_addr).ok_or_else(|| bad("payer_address_decode_failed"))?;
    let payee_vec =
        base58_p2pkh_to_hash(payee_addr).ok_or_else(|| bad("payee_address_decode_failed"))?;
    if payer_vec.len() != 20 || payee_vec.len() != 20 {
        return Err(bad("party_address_hash_len_invalid"));
    }
    let mut payer_pkh = [0u8; 20];
    payer_pkh.copy_from_slice(&payer_vec);
    let mut payee_pkh = [0u8; 20];
    payee_pkh.copy_from_slice(&payee_vec);
    let mut legs = build_funding_legs(&req.agreement, payer_pkh, payee_pkh)
        .map_err(|_| bad("build_funding_legs_failed"))?;
    if legs.is_empty() {
        return Err(bad("agreement_has_no_funding_legs"));
    }
    // GROUP G: per-milestone partial funding. When milestone_id is set,
    // filter the built legs to that one milestone, reject if unknown,
    // and reject if a confirmed Funding anchor already exists for that
    // milestone on-chain (Q2: clear double-funding rejection).
    if let Some(target_mid) = req.milestone_id.as_deref() {
        if !req
            .agreement
            .milestones
            .iter()
            .any(|m| m.milestone_id == target_mid)
        {
            return Err(bad("milestone_id_not_found_in_agreement"));
        }
        legs.retain(|l| l.milestone_id.as_deref() == Some(target_mid));
        if legs.is_empty() {
            return Err(bad("milestone_id_has_no_funding_leg"));
        }
        if legs.len() != 1 {
            return Err(bad("milestone_id_matched_multiple_legs"));
        }
        // Already-funded check: walk the chain for a confirmed Funding
        // anchor that matches both agreement_hash and milestone_id.
        let already_funded = {
            let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
            scan_linked_txs_by_hash(&chain, &agreement_hash)
                .iter()
                .any(|t| {
                    t.role == AgreementAnchorRole::Funding
                        && t.milestone_id.as_deref() == Some(target_mid)
                })
        };
        if already_funded {
            return Err(bad("milestone_already_funded"));
        }
    }

    let mut key_map: HashMap<[u8; 20], WalletKey> = HashMap::new();
    {
        let mut wallet = state.wallet.lock().unwrap_or_else(|e| e.into_inner());
        let keys = wallet.keys().map_err(|_| bad("wallet_keys_unavailable"))?;
        for key in keys {
            let bytes = hex::decode(&key.pkh).map_err(|_| bad("wallet_key_pkh_decode_failed"))?;
            if bytes.len() != 20 {
                continue;
            }
            let mut arr = [0u8; 20];
            arr.copy_from_slice(&bytes);
            key_map.insert(arr, key);
        }
    }
    if key_map.is_empty() {
        return Err(bad("wallet_key_map_empty"));
    }

    let (mut utxos, tip_height) = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let mut collected = Vec::new();
        for (outpoint, utxo) in chain.utxos.iter() {
            if let Some(script_pkh) = p2pkh_hash_from_script(&utxo.output.script_pubkey) {
                if key_map.contains_key(&script_pkh) {
                    collected.push(WalletUtxo {
                        outpoint: outpoint.clone(),
                        output: utxo.output.clone(),
                        height: utxo.height,
                        is_coinbase: utxo.is_coinbase,
                        pkh: script_pkh,
                    });
                }
            }
        }
        (collected, chain.tip_height())
    };
    if utxos.is_empty() {
        return Err(bad("wallet_utxo_set_empty"));
    }
    utxos.sort_by(|a, b| b.output.value.cmp(&a.output.value));

    let total_required: u64 = legs.iter().map(|l| l.amount).sum();
    let mut fee_per_byte = req.fee_per_byte.unwrap_or(1).max(1);
    if fee_per_byte == 0 {
        fee_per_byte = 1;
    }

    let mut selected: Vec<WalletUtxo> = Vec::new();
    let mut total = 0u64;
    let mut fee = 0u64;
    let base_outputs = legs.len().saturating_mul(2);
    for utxo in &utxos {
        let confirmations = tip_height.saturating_sub(utxo.height);
        if utxo.is_coinbase && confirmations < coinbase_maturity() {
            continue;
        }
        selected.push(utxo.clone());
        total = total.saturating_add(utxo.output.value);
        fee = estimate_tx_size(selected.len(), base_outputs + 1).saturating_mul(fee_per_byte);
        if total >= total_required.saturating_add(fee) {
            break;
        }
    }
    if total < total_required.saturating_add(fee) {
        return Err(bad("insufficient_spendable_funds_or_immature_coinbase"));
    }

    let inputs: Vec<TxInput> = selected
        .iter()
        .map(|u| TxInput {
            prev_txid: u.outpoint.txid,
            prev_index: u.outpoint.index,
            script_sig: Vec::new(),
            sequence: 0xffff_ffff,
        })
        .collect();

    let mut outputs = Vec::new();
    let mut funding_outputs = Vec::new();
    for leg in &legs {
        let vout = outputs.len() as u32;
        outputs.push(leg.output.clone());
        outputs.push(
            build_agreement_anchor_output(&AgreementAnchor {
                agreement_hash: agreement_hash.clone(),
                role: leg.role,
                milestone_id: leg.milestone_id.clone(),
            })
            .map_err(|_| bad("build_agreement_anchor_failed"))?,
        );
        funding_outputs.push(AgreementFundingOutput {
            vout,
            role: leg.role,
            milestone_id: leg.milestone_id.clone(),
            amount: leg.amount,
        });
    }

    let change_script = selected
        .first()
        .map(|u| p2pkh_script(&u.pkh))
        .ok_or_else(|| bad("change_output_missing_selected_input"))?;
    let mut change = total.saturating_sub(total_required).saturating_sub(fee);
    if change > 0 {
        outputs.push(TxOutput {
            value: change,
            script_pubkey: change_script.clone(),
        });
    }

    let mut tx = Transaction {
        version: 1,
        inputs,
        outputs,
        locktime: 0,
    };
    for _ in 0..2 {
        sign_wallet_inputs(&mut tx, &selected, &key_map)
            .map_err(|_| bad("sign_wallet_inputs_failed"))?;
        let needed_fee = (tx.serialize().len() as u64).saturating_mul(fee_per_byte);
        if needed_fee > fee {
            let extra = needed_fee - fee;
            if change >= extra {
                fee = needed_fee;
                change = change.saturating_sub(extra);
                if let Some(last) = tx.outputs.last_mut() {
                    if p2pkh_hash_from_script(&last.script_pubkey).is_some() {
                        last.value = change;
                    }
                }
                continue;
            } else {
                return Err(bad("fee_recalculation_exceeded_change"));
            }
        }
        break;
    }

    let fee_checked = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain
            .calculate_fees(&tx)
            .map_err(|e| { eprintln!("[fund_agreement] calc_fees_err={}", e); bad("chain_fee_calculation_failed") })?
    };

    let raw = tx.serialize();
    let txid = tx.txid();
    let txid_hex = hex::encode(txid);
    let mut accepted = false;
    if req.broadcast.unwrap_or(false) {
        let mut mempool = state.mempool.lock().unwrap_or_else(|e| e.into_inner());
        if !mempool.contains(&txid) {
            accepted = mempool
                .add_transaction(tx.clone(), raw.clone(), fee_checked)
                .is_ok();
        }
    }

    if accepted {
        emit_event(&state.event_tx, "agreement.funded", serde_json::json!({
            "agreement_hash": agreement_hash,
            "txid": txid_hex,
        }));
    }

    Ok(Json(FundAgreementResponse {
        agreement_hash,
        txid: txid_hex,
        accepted,
        raw_tx_hex: hex::encode(raw),
        outputs: funding_outputs,
        fee: fee_checked,
    }))
}

async fn get_history(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<BalanceQuery>,
) -> Result<Json<HistoryResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    let pkh = base58_p2pkh_to_hash(&q.address).ok_or(StatusCode::BAD_REQUEST)?;
    if pkh.len() != 20 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut pkh_arr = [0u8; 20];
    pkh_arr.copy_from_slice(&pkh);

    let (height, txs) = {
        let guard = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let mut owned: HashMap<OutPoint, u64> = HashMap::new();
        let mut map: HashMap<[u8; 32], HistoryItem> = HashMap::new();

        for (h, block) in guard.chain.iter().enumerate() {
            let height = h as u64;
            for tx in &block.transactions {
                let txid = tx.txid();
                let is_coinbase = tx.inputs.len() == 1
                    && tx.inputs[0].prev_txid == [0u8; 32]
                    && tx.inputs[0].prev_index == 0xffff_ffff;

                let mut received = 0u64;
                let mut spent = 0u64;

                if !is_coinbase {
                    for input in &tx.inputs {
                        let outpoint = OutPoint {
                            txid: input.prev_txid,
                            index: input.prev_index,
                        };
                        if let Some(value) = owned.remove(&outpoint) {
                            spent = spent.saturating_add(value);
                        }
                    }
                }

                for (idx, output) in tx.outputs.iter().enumerate() {
                    if let Some(script_pkh) = p2pkh_hash_from_script(&output.script_pubkey) {
                        if script_pkh == pkh_arr {
                            received = received.saturating_add(output.value);
                            owned.insert(
                                OutPoint {
                                    txid,
                                    index: idx as u32,
                                },
                                output.value,
                            );
                        }
                    }
                }

                if received > 0 || spent > 0 {
                    let entry = map.entry(txid).or_insert(HistoryItem {
                        txid: hex::encode(txid),
                        height,
                        received: 0,
                        spent: 0,
                        net: 0,
                        is_coinbase,
                    });
                    entry.received = entry.received.saturating_add(received);
                    entry.spent = entry.spent.saturating_add(spent);
                    entry.net = entry.received as i64 - entry.spent as i64;
                }
            }
        }

        let mut txs: Vec<HistoryItem> = map.into_values().collect();
        txs.sort_by(|a, b| b.height.cmp(&a.height));
        (guard.tip_height(), txs)
    };

    Ok(Json(HistoryResponse {
        address: q.address,
        pkh: hex::encode(pkh_arr),
        height,
        txs,
    }))
}

async fn get_fee_estimate(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<FeeEstimateResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    let (min_fee_per_byte, mempool_size) = {
        let mempool = state.mempool.lock().unwrap_or_else(|e| e.into_inner());
        (mempool.min_fee_per_byte(), mempool.len())
    };
    Ok(Json(FeeEstimateResponse {
        min_fee_per_byte,
        mempool_size,
    }))
}

fn sign_wallet_inputs(
    tx: &mut Transaction,
    utxos: &[WalletUtxo],
    key_map: &HashMap<[u8; 20], WalletKey>,
) -> Result<(), StatusCode> {
    for (idx, utxo) in utxos.iter().enumerate() {
        let key = key_map.get(&utxo.pkh).ok_or(StatusCode::BAD_REQUEST)?;
        let priv_bytes = hex::decode(&key.privkey).map_err(|_| StatusCode::BAD_REQUEST)?;
        let signing_key = SigningKey::from_bytes(priv_bytes.as_slice().into())
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        let pub_bytes = signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let digest = signature_digest(tx, idx, &utxo.output.script_pubkey);
        let verify_key = signing_key.verifying_key();
        let mut sig_opt: Option<Signature> = None;
        for _ in 0..4 {
            let sig_try: Signature = signing_key
                .sign_prehash(&digest)
                .map_err(|_| StatusCode::BAD_REQUEST)?;
            let sig_try = sig_try.normalize_s().unwrap_or(sig_try);
            if verify_key.verify_prehash(&digest, &sig_try).is_ok() {
                sig_opt = Some(sig_try);
                break;
            }
        }
        let sig = sig_opt.ok_or(StatusCode::BAD_REQUEST)?;
        let mut sig_bytes = sig.to_der().as_bytes().to_vec();
        sig_bytes.push(0x01);

        let mut script = Vec::new();
        script.push(sig_bytes.len() as u8);
        script.extend_from_slice(&sig_bytes);
        script.push(pub_bytes.len() as u8);
        script.extend_from_slice(&pub_bytes);
        tx.inputs[idx].script_sig = script;
    }
    Ok(())
}

async fn wallet_create(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<WalletCreateRequest>,
) -> Result<Json<WalletCreateResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    require_rpc_auth(&headers)?;

    let mut wallet = state.wallet.lock().unwrap_or_else(|e| e.into_inner());
    if wallet.exists() {
        return Err(StatusCode::CONFLICT);
    }
    let key = wallet
        .create_with_seed(&req.passphrase, req.seed_hex.as_deref())
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    Ok(Json(WalletCreateResponse {
        address: key.address,
        wallet_path: wallet.path().display().to_string(),
    }))
}

async fn wallet_unlock(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<WalletUnlockRequest>,
) -> Result<Json<WalletUnlockResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    require_rpc_auth(&headers)?;

    let mut wallet = state.wallet.lock().unwrap_or_else(|e| e.into_inner());
    // Distinguish "wallet needs migration" (file is plaintext, caller
    // must POST /wallet/migrate_to_encrypted first) from "wrong
    // passphrase" so the frontend can route correctly. 409 = state
    // conflict; 400 = bad credentials.
    if let Err(e) = wallet.unlock(&req.passphrase) {
        if e == "wallet_needs_migration" {
            return Err(StatusCode::CONFLICT);
        }
        return Err(StatusCode::BAD_REQUEST);
    }
    let addresses = wallet.addresses().map_err(|_| StatusCode::BAD_REQUEST)?;
    let current = wallet
        .current_address()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    Ok(Json(WalletUnlockResponse {
        addresses,
        current_address: current,
    }))
}

async fn wallet_info(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<WalletInfoResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    require_rpc_auth(&headers)?;

    let wallet = state.wallet.lock().unwrap_or_else(|e| e.into_inner());
    let mode = wallet.mode();
    let exists = !matches!(mode, WalletMode::None);
    let is_unlocked = wallet.is_unlocked();
    let path = wallet.path().display().to_string();
    let plaintext_backups: Vec<String> = wallet
        .plaintext_backups()
        .into_iter()
        .map(|p| p.display().to_string())
        .collect();

    Ok(Json(WalletInfoResponse {
        exists,
        mode,
        path,
        is_unlocked,
        plaintext_backups,
    }))
}

async fn wallet_migrate_to_encrypted(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<WalletMigrateRequest>,
) -> Result<Json<WalletMigrateResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    require_rpc_auth(&headers)?;

    let mut wallet = state.wallet.lock().unwrap_or_else(|e| e.into_inner());
    if let Err(e) = wallet.migrate_to_encrypted(&req.passphrase) {
        if e == "already_encrypted" {
            return Err(StatusCode::CONFLICT);
        }
        return Err(StatusCode::BAD_REQUEST);
    }
    let addresses = wallet.addresses().map_err(|_| StatusCode::BAD_REQUEST)?;
    let path = wallet.path().display().to_string();
    Ok(Json(WalletMigrateResponse {
        path,
        addresses,
        mode: WalletMode::Encrypted,
    }))
}

async fn wallet_recover_from_seed(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<WalletRecoverRequest>,
) -> Result<Json<WalletRecoverResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    require_rpc_auth(&headers)?;

    let mut wallet = state.wallet.lock().unwrap_or_else(|e| e.into_inner());
    let key = match wallet.recover_from_seed(
        &req.seed_hex,
        &req.passphrase,
        req.allow_overwrite,
    ) {
        Ok(k) => k,
        Err(e) => {
            if e == "wallet_exists" {
                return Err(StatusCode::CONFLICT);
            }
            return Err(StatusCode::BAD_REQUEST);
        }
    };
    let path = wallet.path().display().to_string();
    Ok(Json(WalletRecoverResponse {
        address: key.address,
        path,
    }))
}

async fn wallet_lock(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<WalletLockResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    require_rpc_auth(&headers)?;

    let mut wallet = state.wallet.lock().unwrap_or_else(|e| e.into_inner());
    wallet.lock();

    Ok(Json(WalletLockResponse { locked: true }))
}

async fn wallet_addresses(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<WalletAddressesResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    require_rpc_auth(&headers)?;

    let mut wallet = state.wallet.lock().unwrap_or_else(|e| e.into_inner());
    let addresses = wallet.addresses().map_err(|_| StatusCode::BAD_REQUEST)?;

    Ok(Json(WalletAddressesResponse { addresses }))
}

async fn wallet_receive(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<WalletReceiveResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    require_rpc_auth(&headers)?;

    let mut wallet = state.wallet.lock().unwrap_or_else(|e| e.into_inner());
    let address = wallet
        .current_address()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    Ok(Json(WalletReceiveResponse { address }))
}

async fn wallet_new_address(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<WalletReceiveResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    require_rpc_auth(&headers)?;

    let mut wallet = state.wallet.lock().unwrap_or_else(|e| e.into_inner());
    let key = wallet.new_address().map_err(|_| StatusCode::BAD_REQUEST)?;

    Ok(Json(WalletReceiveResponse {
        address: key.address,
    }))
}

async fn wallet_export_wif(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<WalletExportWifQuery>,
) -> Result<Json<WalletExportWifResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    require_rpc_auth(&headers)?;

    let mut wallet = state.wallet.lock().unwrap_or_else(|e| e.into_inner());
    let wif = wallet
        .export_wif(&q.address)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(Json(WalletExportWifResponse {
        address: q.address,
        wif,
    }))
}

async fn wallet_import_wif(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<WalletImportWifRequest>,
) -> Result<Json<WalletImportWifResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    require_rpc_auth(&headers)?;

    let mut wallet = state.wallet.lock().unwrap_or_else(|e| e.into_inner());
    let key = wallet
        .import_wif(&req.wif)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(Json(WalletImportWifResponse {
        address: key.address,
    }))
}

async fn wallet_export_seed(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<WalletSeedResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    require_rpc_auth(&headers)?;

    let mut wallet = state.wallet.lock().unwrap_or_else(|e| e.into_inner());
    let seed_hex = wallet.export_seed().map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(Json(WalletSeedResponse { seed_hex }))
}

/// GET /wallet/export_mnemonic — returns the BIP39 mnemonic stored in the
/// unlocked wallet. Mirrors `wallet_export_seed`: requires the wallet to be
/// unlocked, returns 400 if locked OR if the wallet has no mnemonic (WIF-
/// imported or raw-seed-imported wallets). Used by the desktop wallet's
/// Reveal Recovery Phrase flow on encrypted wallets, which can't reach the
/// plaintext mnemonic field via the CLI's file-direct path.
async fn wallet_export_mnemonic(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<WalletMnemonicResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    require_rpc_auth(&headers)?;

    let mut wallet = state.wallet.lock().unwrap_or_else(|e| e.into_inner());
    let mnemonic = wallet.export_mnemonic().map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(Json(WalletMnemonicResponse { mnemonic }))
}

async fn wallet_import_seed(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<WalletImportSeedRequest>,
) -> Result<Json<WalletImportSeedResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    require_rpc_auth(&headers)?;

    let mut wallet = state.wallet.lock().unwrap_or_else(|e| e.into_inner());
    let key = wallet
        .import_seed(&req.seed_hex, req.force.unwrap_or(false))
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(Json(WalletImportSeedResponse {
        address: key.address,
    }))
}

async fn wallet_send(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<WalletSendRequest>,
) -> Result<Json<WalletSendResponse>, (StatusCode, Json<serde_json::Value>)> {
    // Helpers — surface a typed error body that the desktop wallet's
    // wallet_send command can decode into a friendly user-facing message.
    // The empty-body returns from the previous shape are what made the
    // GUI's "HTTP 400 Bad Request" indistinguishable between "wallet
    // locked", "insufficient funds", and "invalid address" — see issue
    // report and the v1.0.74-era src-tauri wallet_send change for the
    // call-site decode logic.
    let bad = |reason: &str| -> (StatusCode, Json<serde_json::Value>) {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": reason })))
    };
    let denied = |reason: &str| -> (StatusCode, Json<serde_json::Value>) {
        (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": reason })))
    };
    let auth_err = |s: StatusCode| -> (StatusCode, Json<serde_json::Value>) {
        (s, Json(serde_json::json!({})))
    };

    check_rate_with_auth(&state, &addr, &headers).map_err(auth_err)?;
    require_rpc_auth(&headers).map_err(auth_err)?;

    // `amount` is parsed lazily — in send_max mode we ignore the value and
    // compute it from total_inputs - fee after UTXO selection. In normal
    // mode the parse + zero-check happens inside the else branch below.
    let send_max = req.send_max.unwrap_or(false);

    let (keys, change_address) = {
        let mut wallet = state.wallet.lock().unwrap_or_else(|e| e.into_inner());
        let keys = wallet.keys().map_err(|_| bad("wallet_locked"))?;
        let change = if let Some(ref from) = req.from_address {
            from.clone()
        } else {
            wallet
                .current_address()
                .map_err(|_| bad("wallet_locked"))?
        };
        (keys, change)
    };

    if keys.is_empty() {
        return Err(bad("wallet_locked"));
    }

    let mut key_map: HashMap<[u8; 20], WalletKey> = HashMap::new();
    for key in keys {
        let bytes = hex::decode(&key.pkh).map_err(|_| bad("internal_keymap_error"))?;
        if bytes.len() != 20 {
            continue;
        }
        let mut arr = [0u8; 20];
        arr.copy_from_slice(&bytes);
        key_map.insert(arr, key);
    }

    if key_map.is_empty() {
        return Err(bad("wallet_locked"));
    }

    let mut allowed: HashSet<[u8; 20]> = HashSet::new();
    if let Some(ref from_addr) = req.from_address {
        let pkh = base58_p2pkh_to_hash(from_addr).ok_or_else(|| bad("invalid_address"))?;
        if pkh.len() != 20 {
            return Err(bad("invalid_address"));
        }
        let mut arr = [0u8; 20];
        arr.copy_from_slice(&pkh);
        if !key_map.contains_key(&arr) {
            return Err(denied("from_address_not_in_wallet"));
        }
        allowed.insert(arr);
    } else {
        for key in key_map.keys() {
            allowed.insert(*key);
        }
    }

    let change_vec = base58_p2pkh_to_hash(&change_address).ok_or_else(|| bad("invalid_address"))?;
    if change_vec.len() != 20 {
        return Err(bad("invalid_address"));
    }
    let mut change_pkh = [0u8; 20];
    change_pkh.copy_from_slice(&change_vec);
    if !key_map.contains_key(&change_pkh) {
        return Err(denied("change_address_not_in_wallet"));
    }

    let (mut utxos, tip_height) = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let mut collected = Vec::new();
        for (outpoint, utxo) in chain.utxos.iter() {
            if let Some(script_pkh) = p2pkh_hash_from_script(&utxo.output.script_pubkey) {
                if allowed.contains(&script_pkh) {
                    collected.push(WalletUtxo {
                        outpoint: outpoint.clone(),
                        output: utxo.output.clone(),
                        height: utxo.height,
                        is_coinbase: utxo.is_coinbase,
                        pkh: script_pkh,
                    });
                }
            }
        }
        (collected, chain.tip_height())
    };

    if utxos.is_empty() {
        return Err(bad("no_utxos"));
    }

    let coin_select = req.coin_select.as_deref().unwrap_or("largest");
    match coin_select {
        "smallest" => utxos.sort_by_key(|u| u.output.value),
        _ => utxos.sort_by(|a, b| b.output.value.cmp(&a.output.value)),
    }

    let mut fee_per_byte = {
        let mempool = state.mempool.lock().unwrap_or_else(|e| e.into_inner());
        mempool.min_fee_per_byte().ceil() as u64
    };
    if fee_per_byte == 0 {
        fee_per_byte = 1;
    }
    if let Some(override_fee) = req.fee_per_byte {
        if override_fee > 0 {
            fee_per_byte = override_fee;
        }
    } else if let Some(mode) = req.fee_mode.as_deref() {
        match mode.to_lowercase().as_str() {
            "low" => {}
            "normal" => fee_per_byte = fee_per_byte.saturating_mul(2),
            "high" => fee_per_byte = fee_per_byte.saturating_mul(4),
            _ => {}
        }
    }
    if fee_per_byte == 0 {
        fee_per_byte = 1;
    }

    // UTXO selection. In send_max mode we take every spendable UTXO in
    // `allowed`, then derive amount = total - fee with a 1-output tx (no
    // change). In normal mode the existing greedy loop runs unchanged.
    let (selected, total, mut fee, mut amount): (Vec<WalletUtxo>, u64, u64, u64) = if send_max {
        let mut sel: Vec<WalletUtxo> = Vec::new();
        let mut sum = 0u64;
        for utxo in utxos.iter() {
            let confirmations = tip_height.saturating_sub(utxo.height);
            if utxo.is_coinbase && confirmations < coinbase_maturity() {
                continue;
            }
            sel.push(utxo.clone());
            sum = sum.saturating_add(utxo.output.value);
        }
        if sel.is_empty() {
            return Err(bad("no_spendable_utxos"));
        }
        let est_size = estimate_tx_size(sel.len(), 1);
        let est_fee = est_size.saturating_mul(fee_per_byte).max(10_000);
        if sum <= est_fee {
            return Err(bad("insufficient_funds_for_fee"));
        }
        let amt = sum - est_fee;
        (sel, sum, est_fee, amt)
    } else {
        let parsed_amount = {
            let s = req.amount.as_deref().ok_or_else(|| bad("missing_amount"))?;
            let v = parse_irm(s).map_err(|_| bad("invalid_amount"))?;
            if v == 0 {
                return Err(bad("invalid_amount"));
            }
            v
        };
        let mut sel: Vec<WalletUtxo> = Vec::new();
        let mut sum = 0u64;
        let mut f = 0u64;
        for utxo in utxos.iter() {
            let confirmations = tip_height.saturating_sub(utxo.height);
            if utxo.is_coinbase && confirmations < coinbase_maturity() {
                continue;
            }
            sel.push(utxo.clone());
            sum = sum.saturating_add(utxo.output.value);
            let outputs = if sum > parsed_amount { 2 } else { 1 };
            f = estimate_tx_size(sel.len(), outputs).saturating_mul(fee_per_byte);
            if sum >= parsed_amount.saturating_add(f) {
                break;
            }
        }
        if sum < parsed_amount.saturating_add(f) {
            return Err(bad("insufficient_funds"));
        }
        (sel, sum, f, parsed_amount)
    };

    let to_vec = base58_p2pkh_to_hash(&req.to_address).ok_or_else(|| bad("invalid_address"))?;
    if to_vec.len() != 20 {
        return Err(bad("invalid_address"));
    }
    let mut to_pkh = [0u8; 20];
    to_pkh.copy_from_slice(&to_vec);
    let to_script = p2pkh_script(&to_pkh);
    let change_script = p2pkh_script(&change_pkh);

    let mut inputs: Vec<TxInput> = Vec::new();
    for utxo in &selected {
        inputs.push(TxInput {
            prev_txid: utxo.outpoint.txid,
            prev_index: utxo.outpoint.index,
            script_sig: Vec::new(),
            sequence: 0xffff_ffff,
        });
    }

    let mut outputs = vec![TxOutput {
        value: amount,
        script_pubkey: to_script,
    }];

    let mut change = total.saturating_sub(amount).saturating_sub(fee);
    if change > 0 {
        outputs.push(TxOutput {
            value: change,
            script_pubkey: change_script.clone(),
        });
    }

    let mut tx = Transaction {
        version: 1,
        inputs,
        outputs,
        locktime: 0,
    };

    for _ in 0..2 {
        sign_wallet_inputs(&mut tx, &selected, &key_map).map_err(auth_err)?;
        let size = tx.serialize().len() as u64;
        let needed_fee = if send_max {
            size.saturating_mul(fee_per_byte).max(10_000)
        } else {
            size.saturating_mul(fee_per_byte)
        };
        if needed_fee > fee {
            let extra = needed_fee - fee;
            if send_max {
                // No change output to shrink — absorb the extra fee from the
                // recipient output. If even that is insufficient (pathological
                // case where the signed size grew so much that the floored
                // estimate underestimated by more than `amount`), reject.
                if amount > extra {
                    fee = needed_fee;
                    amount -= extra;
                    tx.outputs[0].value = amount;
                    continue;
                } else {
                    return Err(bad("insufficient_funds_for_fee"));
                }
            } else if change >= extra {
                fee = needed_fee;
                change = change.saturating_sub(extra);
                if tx.outputs.len() > 1 {
                    tx.outputs[1].value = change;
                } else if change > 0 {
                    tx.outputs.push(TxOutput {
                        value: change,
                        script_pubkey: change_script.clone(),
                    });
                }
                continue;
            } else {
                return Err(bad("insufficient_funds"));
            }
        }
        break;
    }

    let fee_checked = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain
            .calculate_fees(&tx)
            .map_err(|_| bad("fee_calc_failed"))?
    };

    let raw = tx.serialize();
    let txid = tx.txid();
    let hex_txid = hex::encode(txid);

    let raw_for_broadcast = raw.clone();
    let mut mempool = state.mempool.lock().unwrap_or_else(|e| e.into_inner());
    if mempool.contains(&txid) {
        // Duplicate of a tx already in our local mempool. Drop the lock,
        // re-broadcast in case peers missed the first round, and tell the
        // caller we didn't admit a new entry. Mirrors submit_tx.
        drop(mempool);
        if let Some(p2p) = state.p2p.clone() {
            tokio::spawn(async move {
                if let Err(e) = p2p.broadcast_tx(&raw_for_broadcast).await {
                    eprintln!("wallet_send: rebroadcast_tx failed: {}", e);
                }
            });
        }
        return Ok(Json(WalletSendResponse {
            txid: hex_txid,
            accepted: false,
            fee: fee_checked,
            total_input: total,
            change,
        }));
    }

    if let Err(e) = mempool.add_transaction(tx, raw, fee_checked) {
        // Pre-fix this branch silently set `accepted: false` and returned
        // 200 OK with a real-looking txid, so the desktop wallet reported
        // "success" for txs the local mempool had actually rejected. Now
        // we propagate the rejection so the GUI can show the actual
        // reason (fee floor, dust, input conflict, etc.).
        eprintln!("wallet_send: mempool reject reason={}", e);
        return Err(bad(&format!("mempool_reject:{e}")));
    }
    drop(mempool);

    // Broadcast the freshly admitted tx to peers so mining nodes actually
    // see it. Mirrors submit_tx — pre-fix this call was missing, so wallet
    // sends sat in the local iriumd's mempool forever, never reaching the
    // mainnet nodes, and the GUI showed "success" but the tx never
    // confirmed.
    if let Some(p2p) = state.p2p.clone() {
        tokio::spawn(async move {
            if let Err(e) = p2p.broadcast_tx(&raw_for_broadcast).await {
                eprintln!("wallet_send: broadcast_tx failed: {}", e);
            }
        });
    }

    Ok(Json(WalletSendResponse {
        txid: hex_txid,
        accepted: true,
        fee: fee_checked,
        total_input: total,
        change,
    }))
}

// Phase 4 Part 1 — BTC SPV header relay RPC endpoints. Three endpoints behind
// the `btc_spv_relay_active_at` activation gate; all three return
// SERVICE_UNAVAILABLE pre-activation. Active path: A1 funds + signs a P2PKH
// iriumd tx whose vout 1 is a `BtcHeaderBatch` (tag 0xc4) carrying validated
// BTC headers; A2 reads `ChainState.btc_tip`/`btc_anchor`/`btc_tip_height`
// directly; A3 looks up headers by display-order hash or by canonical height
// in `ChainState.btc_headers`/`btc_heights`. Display-order hashes are
// reverse(natural-order); natural-order is what consensus stores.

#[derive(Debug, Deserialize)]
struct SubmitBtcHeadersRequest {
    headers_hex: String,
    #[serde(default)]
    broadcast: Option<bool>,
    #[serde(default)]
    fee_per_byte: Option<u64>,
}

#[derive(Debug, Serialize)]
struct SubmitBtcHeadersResponse {
    txid: String,
    accepted: bool,
    headers_count: u32,
    new_tip_hash: Option<String>,
    new_tip_height: Option<u64>,
    fee: u64,
    raw_tx_hex: String,
}

#[derive(Debug, Serialize)]
struct BtcRelayTipResponse {
    active: bool,
    anchor_hash: String,
    anchor_height: u64,
    anchor_bits: String,
    anchor_time: u32,
    tip_hash: String,
    tip_height: u64,
    tip_time: u32,
    tip_total_work_hex: String,
}

#[derive(Debug, Deserialize)]
struct BtcHeaderQuery {
    #[serde(default)]
    hash: Option<String>,
    #[serde(default)]
    height: Option<u64>,
}

#[derive(Debug, Serialize)]
struct BtcHeaderResponse {
    found: bool,
    hash: Option<String>,
    height: Option<u64>,
    version: Option<i32>,
    prev_hash: Option<String>,
    merkle_root: Option<String>,
    time: Option<u32>,
    bits: Option<String>,
    nonce: Option<u32>,
    on_canonical_chain: Option<bool>,
}

fn btc_hash_to_display(natural: &[u8; 32]) -> String {
    let mut rev = *natural;
    rev.reverse();
    hex::encode(rev)
}

fn parse_btc_display_hash(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s.trim()).map_err(|e| format!("hex_decode: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut natural = [0u8; 32];
    natural.copy_from_slice(&bytes);
    natural.reverse();
    Ok(natural)
}

/// Core implementation of `/rpc/submitbtcheaders` shared between the HTTP
/// handler and the in-process header-sync background task. Skips auth +
/// rate-limit checks; callers must apply those themselves at the transport
/// boundary. `peer_ip` is propagated to the mempool's per-IP rate
/// accounting; the background task should pass `None`, the HTTP handler
/// passes the caller's source IP.
async fn submit_btc_headers_core(
    state: &AppState,
    req: SubmitBtcHeadersRequest,
    peer_ip: Option<IpAddr>,
) -> Result<SubmitBtcHeadersResponse, (StatusCode, String)> {
    let bad = |reason: &str| -> (StatusCode, String) {
        eprintln!("[submit_btc_headers] reject reason={}", reason);
        (StatusCode::BAD_REQUEST, reason.to_string())
    };

    {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let active = chain
            .params
            .btc_spv
            .as_ref()
            .map(|p| chain.height >= p.activation_height)
            .unwrap_or(false);
        if !active {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "btc_spv_relay_not_active".to_string(),
            ));
        }
    }

    let raw = hex::decode(req.headers_hex.trim())
        .map_err(|_| bad("headers_hex_decode_failed"))?;
    if raw.is_empty() || raw.len() % BTC_HEADER_BYTES != 0 {
        return Err(bad("headers_hex_length_not_multiple_of_80"));
    }
    let header_count = raw.len() / BTC_HEADER_BYTES;
    if header_count == 0 || header_count > MAX_BTC_HEADERS_PER_BATCH as usize {
        return Err(bad("header_count_out_of_range"));
    }
    let mut parsed_headers: Vec<BtcHeader> = Vec::with_capacity(header_count);
    for i in 0..header_count {
        let chunk = &raw[i * BTC_HEADER_BYTES..(i + 1) * BTC_HEADER_BYTES];
        let h = BtcHeader::deserialize(chunk).map_err(|_| bad("btc_header_deserialize_failed"))?;
        parsed_headers.push(h);
    }

    let batch_script = encode_btc_header_batch(&parsed_headers)
        .map_err(|_| bad("encode_btc_header_batch_failed"))?;

    let mut key_map: HashMap<[u8; 20], WalletKey> = HashMap::new();
    {
        let mut wallet = state.wallet.lock().unwrap_or_else(|e| e.into_inner());
        let keys = wallet.keys().map_err(|_| bad("wallet_keys_unavailable"))?;
        for key in keys {
            let bytes = hex::decode(&key.pkh).map_err(|_| bad("wallet_key_pkh_decode_failed"))?;
            if bytes.len() != 20 {
                continue;
            }
            let mut arr = [0u8; 20];
            arr.copy_from_slice(&bytes);
            key_map.insert(arr, key);
        }
    }
    if key_map.is_empty() {
        return Err(bad("wallet_key_map_empty"));
    }

    let (mut utxos, tip_height) = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let mut collected = Vec::new();
        for (outpoint, utxo) in chain.utxos.iter() {
            if let Some(script_pkh) = p2pkh_hash_from_script(&utxo.output.script_pubkey) {
                if key_map.contains_key(&script_pkh) {
                    collected.push(WalletUtxo {
                        outpoint: outpoint.clone(),
                        output: utxo.output.clone(),
                        height: utxo.height,
                        is_coinbase: utxo.is_coinbase,
                        pkh: script_pkh,
                    });
                }
            }
        }
        (collected, chain.tip_height())
    };
    if utxos.is_empty() {
        return Err(bad("wallet_utxo_set_empty"));
    }
    utxos.sort_by(|a, b| b.output.value.cmp(&a.output.value));

    let mut fee_per_byte = req.fee_per_byte.unwrap_or(1).max(1);
    if fee_per_byte == 0 {
        fee_per_byte = 1;
    }

    let mut selected: Vec<WalletUtxo> = Vec::new();
    let mut total: u64 = 0;
    let mut fee: u64 = 0;
    for utxo in utxos.iter() {
        let confirmations = tip_height.saturating_sub(utxo.height);
        if utxo.is_coinbase && confirmations < coinbase_maturity() {
            continue;
        }
        selected.push(utxo.clone());
        total = total.saturating_add(utxo.output.value);
        let base_size = estimate_tx_size(selected.len(), 2);
        fee = base_size
            .saturating_add(batch_script.len() as u64)
            .saturating_mul(fee_per_byte);
        if total >= fee {
            break;
        }
    }
    if total < fee {
        return Err(bad("insufficient_spendable_funds_for_header_batch_fee"));
    }

    let change_pkh = selected
        .first()
        .map(|u| u.pkh)
        .ok_or_else(|| bad("no_change_pkh_available"))?;
    let mut change = total.saturating_sub(fee);

    let inputs: Vec<TxInput> = selected
        .iter()
        .map(|u| TxInput {
            prev_txid: u.outpoint.txid,
            prev_index: u.outpoint.index,
            script_sig: Vec::new(),
            sequence: 0xffff_ffff,
        })
        .collect();

    let outputs = vec![
        TxOutput {
            value: change,
            script_pubkey: p2pkh_script(&change_pkh),
        },
        TxOutput {
            value: 0,
            script_pubkey: batch_script,
        },
    ];

    let mut tx = Transaction {
        version: 1,
        inputs,
        outputs,
        locktime: 0,
    };

    for _ in 0..2 {
        sign_wallet_inputs(&mut tx, &selected, &key_map)
            .map_err(|_| bad("sign_wallet_inputs_failed"))?;
        let needed_fee = (tx.serialize().len() as u64).saturating_mul(fee_per_byte);
        if needed_fee > fee {
            let extra = needed_fee - fee;
            if change >= extra {
                fee = needed_fee;
                change = change.saturating_sub(extra);
                tx.outputs[0].value = change;
                continue;
            } else {
                return Err(bad("fee_recalculation_exceeded_change"));
            }
        }
        break;
    }

    let fee_checked = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain
            .calculate_fees(&tx)
            .map_err(|_| bad("chain_fee_calculation_failed"))?
    };

    let raw_tx = tx.serialize();
    let txid = tx.txid();
    let txid_hex = hex::encode(txid);
    let mut accepted = false;
    if req.broadcast.unwrap_or(true) {
        let mut mempool = state.mempool.lock().unwrap_or_else(|e| e.into_inner());
        if !mempool.contains(&txid) {
            // BtcHeaderBatch carrier tx: ZeroFeeAllowed so a BTC-only
            // buyer can extend the relay before their claim. peer_ip is
            // None for the in-process background task and Some(addr.ip())
            // for HTTP callers; loopback bypasses the rate limit so the
            // local operator and Tauri client are unthrottled.
            match mempool.add_transaction_with_priority(
                tx.clone(),
                raw_tx.clone(),
                fee_checked,
                MempoolPriority::ZeroFeeAllowed,
                peer_ip,
            ) {
                Ok(_) => accepted = true,
                Err(e) => {
                    eprintln!("[submit_btc_headers] mempool_reject reason={}", e);
                }
            }
        }
    }

    Ok(SubmitBtcHeadersResponse {
        txid: txid_hex,
        accepted,
        headers_count: header_count as u32,
        new_tip_hash: None,
        new_tip_height: None,
        fee: fee_checked,
        raw_tx_hex: hex::encode(raw_tx),
    })
}

async fn submit_btc_headers(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers_map: HeaderMap,
    AxumJson(req): AxumJson<SubmitBtcHeadersRequest>,
) -> Result<Json<SubmitBtcHeadersResponse>, (StatusCode, String)> {
    check_rate_with_auth(&state, &addr, &headers_map)
        .map_err(|sc| (sc, "rate_limit_or_auth_failed".to_string()))?;
    require_rpc_auth(&headers_map).map_err(|sc| (sc, format!("rpc_auth_failed:{sc}")))?;
    submit_btc_headers_core(&state, req, Some(addr.ip()))
        .await
        .map(Json)
}

async fn btc_relay_tip(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers_map: HeaderMap,
) -> Result<Json<BtcRelayTipResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers_map)?;
    require_rpc_auth(&headers_map)?;

    let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
    let (active, anchor) = match chain.params.btc_spv.as_ref() {
        Some(p) => (chain.height >= p.activation_height, p.anchor),
        None => (false, BtcAnchor::zero()),
    };

    let (tip_hash_display, tip_height, tip_time, tip_total_work_hex) = match chain.btc_tip {
        Some(h) => {
            let entry = chain.btc_headers.get(&h);
            let time = entry.map(|e| e.header.time).unwrap_or(0);
            let work_hex = entry
                .map(|e| e.total_work.to_str_radix(16))
                .unwrap_or_else(|| "0".to_string());
            (
                btc_hash_to_display(&h),
                chain.btc_tip_height,
                time,
                work_hex,
            )
        }
        None => (
            btc_hash_to_display(&anchor.hash),
            anchor.height,
            anchor.time,
            "0".to_string(),
        ),
    };

    Ok(Json(BtcRelayTipResponse {
        active,
        anchor_hash: btc_hash_to_display(&anchor.hash),
        anchor_height: anchor.height,
        anchor_bits: format!("0x{:08x}", anchor.bits),
        anchor_time: anchor.time,
        tip_hash: tip_hash_display,
        tip_height,
        tip_time,
        tip_total_work_hex,
    }))
}

async fn btc_header(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers_map: HeaderMap,
    Query(q): Query<BtcHeaderQuery>,
) -> Result<Json<BtcHeaderResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers_map)?;
    require_rpc_auth(&headers_map)?;

    if q.hash.is_none() && q.height.is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if q.hash.is_some() && q.height.is_some() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());

    let found: Option<([u8; 32], BtcHeaderEntry, bool)> = if let Some(hash_display) = &q.hash {
        let natural = match parse_btc_display_hash(hash_display) {
            Ok(h) => h,
            Err(_) => return Err(StatusCode::BAD_REQUEST),
        };
        chain.btc_headers.get(&natural).map(|e| {
            let canonical = chain
                .btc_heights
                .get(&natural)
                .copied()
                .map(|h| h <= chain.btc_tip_height)
                .unwrap_or(false);
            (natural, e.clone(), canonical)
        })
    } else if let Some(h) = q.height {
        let mut hit: Option<[u8; 32]> = None;
        for (hash, bh) in chain.btc_heights.iter() {
            if *bh == h {
                hit = Some(*hash);
                break;
            }
        }
        hit.and_then(|hash| {
            chain
                .btc_headers
                .get(&hash)
                .cloned()
                .map(|e| (hash, e, true))
        })
    } else {
        None
    };

    match found {
        Some((hash, entry, canonical)) => Ok(Json(BtcHeaderResponse {
            found: true,
            hash: Some(btc_hash_to_display(&hash)),
            height: Some(entry.height),
            version: Some(entry.header.version),
            prev_hash: Some(btc_hash_to_display(&entry.header.prev_hash)),
            merkle_root: Some(btc_hash_to_display(&entry.header.merkle_root)),
            time: Some(entry.header.time),
            bits: Some(format!("0x{:08x}", entry.header.bits)),
            nonce: Some(entry.header.nonce),
            on_canonical_chain: Some(canonical),
        })),
        None => Ok(Json(BtcHeaderResponse {
            found: false,
            hash: None,
            height: None,
            version: None,
            prev_hash: None,
            merkle_root: None,
            time: None,
            bits: None,
            nonce: None,
            on_canonical_chain: None,
        })),
    }
}

// Phase E.1 — LTC SPV header relay RPC endpoints. Byte-level mirror of the
// BTC SPV trio above; gated on `chain.params.ltc_spv` being `Some` and
// `chain.height >= activation_height`. Sha256d display-order helpers
// (`btc_hash_to_display`, `parse_btc_display_hash`) are reused as-is —
// Litecoin block hashes are sha256d in the same byte order.

#[derive(Debug, Deserialize)]
struct SubmitLtcHeadersRequest {
    headers_hex: String,
    #[serde(default)]
    broadcast: Option<bool>,
    #[serde(default)]
    fee_per_byte: Option<u64>,
}

#[derive(Debug, Serialize)]
struct SubmitLtcHeadersResponse {
    txid: String,
    accepted: bool,
    headers_count: u32,
    new_tip_hash: Option<String>,
    new_tip_height: Option<u64>,
    fee: u64,
    raw_tx_hex: String,
}

#[derive(Debug, Serialize)]
struct LtcRelayTipResponse {
    active: bool,
    anchor_hash: String,
    anchor_height: u64,
    anchor_bits: String,
    anchor_time: u32,
    tip_hash: String,
    tip_height: u64,
    tip_time: u32,
    tip_total_work_hex: String,
}

#[derive(Debug, Deserialize)]
struct LtcHeaderQuery {
    #[serde(default)]
    hash: Option<String>,
    #[serde(default)]
    height: Option<u64>,
}

#[derive(Debug, Serialize)]
struct LtcHeaderResponse {
    found: bool,
    hash: Option<String>,
    height: Option<u64>,
    version: Option<i32>,
    prev_hash: Option<String>,
    merkle_root: Option<String>,
    time: Option<u32>,
    bits: Option<String>,
    nonce: Option<u32>,
    on_canonical_chain: Option<bool>,
}

/// Core implementation of `/rpc/submitltcheaders` — see `submit_btc_headers_core`
/// for the design rationale (auth + rate limit live at the transport layer).
async fn submit_ltc_headers_core(
    state: &AppState,
    req: SubmitLtcHeadersRequest,
) -> Result<SubmitLtcHeadersResponse, (StatusCode, String)> {
    let bad = |reason: &str| -> (StatusCode, String) {
        eprintln!("[submit_ltc_headers] reject reason={}", reason);
        (StatusCode::BAD_REQUEST, reason.to_string())
    };

    {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let active = chain
            .params
            .ltc_spv
            .as_ref()
            .map(|p| chain.height >= p.activation_height)
            .unwrap_or(false);
        if !active {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "ltc_spv_relay_not_active".to_string(),
            ));
        }
    }

    let raw = hex::decode(req.headers_hex.trim())
        .map_err(|_| bad("headers_hex_decode_failed"))?;
    if raw.is_empty() || raw.len() % LTC_HEADER_BYTES != 0 {
        return Err(bad("headers_hex_length_not_multiple_of_80"));
    }
    let header_count = raw.len() / LTC_HEADER_BYTES;
    if header_count == 0 || header_count > MAX_LTC_HEADERS_PER_BATCH as usize {
        return Err(bad("header_count_out_of_range"));
    }
    let mut parsed_headers: Vec<LtcHeader> = Vec::with_capacity(header_count);
    for i in 0..header_count {
        let chunk = &raw[i * LTC_HEADER_BYTES..(i + 1) * LTC_HEADER_BYTES];
        let h = LtcHeader::deserialize(chunk).map_err(|_| bad("ltc_header_deserialize_failed"))?;
        parsed_headers.push(h);
    }

    let batch_script = encode_ltc_header_batch(&parsed_headers)
        .map_err(|_| bad("encode_ltc_header_batch_failed"))?;

    let mut key_map: HashMap<[u8; 20], WalletKey> = HashMap::new();
    {
        let mut wallet = state.wallet.lock().unwrap_or_else(|e| e.into_inner());
        let keys = wallet.keys().map_err(|_| bad("wallet_keys_unavailable"))?;
        for key in keys {
            let bytes = hex::decode(&key.pkh).map_err(|_| bad("wallet_key_pkh_decode_failed"))?;
            if bytes.len() != 20 {
                continue;
            }
            let mut arr = [0u8; 20];
            arr.copy_from_slice(&bytes);
            key_map.insert(arr, key);
        }
    }
    if key_map.is_empty() {
        return Err(bad("wallet_key_map_empty"));
    }

    let (mut utxos, tip_height) = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let mut collected = Vec::new();
        for (outpoint, utxo) in chain.utxos.iter() {
            if let Some(script_pkh) = p2pkh_hash_from_script(&utxo.output.script_pubkey) {
                if key_map.contains_key(&script_pkh) {
                    collected.push(WalletUtxo {
                        outpoint: outpoint.clone(),
                        output: utxo.output.clone(),
                        height: utxo.height,
                        is_coinbase: utxo.is_coinbase,
                        pkh: script_pkh,
                    });
                }
            }
        }
        (collected, chain.tip_height())
    };
    if utxos.is_empty() {
        return Err(bad("wallet_utxo_set_empty"));
    }
    utxos.sort_by(|a, b| b.output.value.cmp(&a.output.value));

    let mut fee_per_byte = req.fee_per_byte.unwrap_or(1).max(1);
    if fee_per_byte == 0 {
        fee_per_byte = 1;
    }

    let mut selected: Vec<WalletUtxo> = Vec::new();
    let mut total: u64 = 0;
    let mut fee: u64 = 0;
    for utxo in utxos.iter() {
        let confirmations = tip_height.saturating_sub(utxo.height);
        if utxo.is_coinbase && confirmations < coinbase_maturity() {
            continue;
        }
        selected.push(utxo.clone());
        total = total.saturating_add(utxo.output.value);
        let base_size = estimate_tx_size(selected.len(), 2);
        fee = base_size
            .saturating_add(batch_script.len() as u64)
            .saturating_mul(fee_per_byte);
        if total >= fee {
            break;
        }
    }
    if total < fee {
        return Err(bad("insufficient_spendable_funds_for_header_batch_fee"));
    }

    let change_pkh = selected
        .first()
        .map(|u| u.pkh)
        .ok_or_else(|| bad("no_change_pkh_available"))?;
    let mut change = total.saturating_sub(fee);

    let inputs: Vec<TxInput> = selected
        .iter()
        .map(|u| TxInput {
            prev_txid: u.outpoint.txid,
            prev_index: u.outpoint.index,
            script_sig: Vec::new(),
            sequence: 0xffff_ffff,
        })
        .collect();

    let outputs = vec![
        TxOutput {
            value: change,
            script_pubkey: p2pkh_script(&change_pkh),
        },
        TxOutput {
            value: 0,
            script_pubkey: batch_script,
        },
    ];

    let mut tx = Transaction {
        version: 1,
        inputs,
        outputs,
        locktime: 0,
    };

    for _ in 0..2 {
        sign_wallet_inputs(&mut tx, &selected, &key_map)
            .map_err(|_| bad("sign_wallet_inputs_failed"))?;
        let needed_fee = (tx.serialize().len() as u64).saturating_mul(fee_per_byte);
        if needed_fee > fee {
            let extra = needed_fee - fee;
            if change >= extra {
                fee = needed_fee;
                change = change.saturating_sub(extra);
                tx.outputs[0].value = change;
                continue;
            } else {
                return Err(bad("fee_recalculation_exceeded_change"));
            }
        }
        break;
    }

    let fee_checked = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain
            .calculate_fees(&tx)
            .map_err(|_| bad("chain_fee_calculation_failed"))?
    };

    let raw_tx = tx.serialize();
    let txid = tx.txid();
    let txid_hex = hex::encode(txid);
    let mut accepted = false;
    if req.broadcast.unwrap_or(true) {
        let mut mempool = state.mempool.lock().unwrap_or_else(|e| e.into_inner());
        if !mempool.contains(&txid) {
            match mempool.add_transaction(tx.clone(), raw_tx.clone(), fee_checked) {
                Ok(_) => accepted = true,
                Err(e) => {
                    eprintln!("[submit_ltc_headers] mempool_reject reason={}", e);
                }
            }
        }
    }

    Ok(SubmitLtcHeadersResponse {
        txid: txid_hex,
        accepted,
        headers_count: header_count as u32,
        new_tip_hash: None,
        new_tip_height: None,
        fee: fee_checked,
        raw_tx_hex: hex::encode(raw_tx),
    })
}

async fn submit_ltc_headers(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers_map: HeaderMap,
    AxumJson(req): AxumJson<SubmitLtcHeadersRequest>,
) -> Result<Json<SubmitLtcHeadersResponse>, (StatusCode, String)> {
    check_rate_with_auth(&state, &addr, &headers_map)
        .map_err(|sc| (sc, "rate_limit_or_auth_failed".to_string()))?;
    require_rpc_auth(&headers_map).map_err(|sc| (sc, format!("rpc_auth_failed:{sc}")))?;
    submit_ltc_headers_core(&state, req).await.map(Json)
}

async fn ltc_relay_tip(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers_map: HeaderMap,
) -> Result<Json<LtcRelayTipResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers_map)?;
    require_rpc_auth(&headers_map)?;

    let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
    let (active, anchor) = match chain.params.ltc_spv.as_ref() {
        Some(p) => (chain.height >= p.activation_height, p.anchor),
        None => (false, LtcAnchor::zero()),
    };

    let (tip_hash_display, tip_height, tip_time, tip_total_work_hex) = match chain.ltc_tip {
        Some(h) => {
            let entry = chain.ltc_headers.get(&h);
            let time = entry.map(|e| e.header.time).unwrap_or(0);
            let work_hex = entry
                .map(|e| e.total_work.to_str_radix(16))
                .unwrap_or_else(|| "0".to_string());
            (
                btc_hash_to_display(&h),
                chain.ltc_tip_height,
                time,
                work_hex,
            )
        }
        None => (
            btc_hash_to_display(&anchor.hash),
            anchor.height,
            anchor.time,
            "0".to_string(),
        ),
    };

    Ok(Json(LtcRelayTipResponse {
        active,
        anchor_hash: btc_hash_to_display(&anchor.hash),
        anchor_height: anchor.height,
        anchor_bits: format!("0x{:08x}", anchor.bits),
        anchor_time: anchor.time,
        tip_hash: tip_hash_display,
        tip_height,
        tip_time,
        tip_total_work_hex,
    }))
}

async fn ltc_header(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers_map: HeaderMap,
    Query(q): Query<LtcHeaderQuery>,
) -> Result<Json<LtcHeaderResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers_map)?;
    require_rpc_auth(&headers_map)?;

    if q.hash.is_none() && q.height.is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if q.hash.is_some() && q.height.is_some() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());

    let found: Option<([u8; 32], LtcHeaderEntry, bool)> = if let Some(hash_display) = &q.hash {
        let natural = match parse_btc_display_hash(hash_display) {
            Ok(h) => h,
            Err(_) => return Err(StatusCode::BAD_REQUEST),
        };
        chain.ltc_headers.get(&natural).map(|e| {
            let canonical = chain
                .ltc_heights
                .get(&natural)
                .copied()
                .map(|h| h <= chain.ltc_tip_height)
                .unwrap_or(false);
            (natural, e.clone(), canonical)
        })
    } else if let Some(h) = q.height {
        let mut hit: Option<[u8; 32]> = None;
        for (hash, bh) in chain.ltc_heights.iter() {
            if *bh == h {
                hit = Some(*hash);
                break;
            }
        }
        hit.and_then(|hash| {
            chain
                .ltc_headers
                .get(&hash)
                .cloned()
                .map(|e| (hash, e, true))
        })
    } else {
        None
    };

    match found {
        Some((hash, entry, canonical)) => Ok(Json(LtcHeaderResponse {
            found: true,
            hash: Some(btc_hash_to_display(&hash)),
            height: Some(entry.height),
            version: Some(entry.header.version),
            prev_hash: Some(btc_hash_to_display(&entry.header.prev_hash)),
            merkle_root: Some(btc_hash_to_display(&entry.header.merkle_root)),
            time: Some(entry.header.time),
            bits: Some(format!("0x{:08x}", entry.header.bits)),
            nonce: Some(entry.header.nonce),
            on_canonical_chain: Some(canonical),
        })),
        None => Ok(Json(LtcHeaderResponse {
            found: false,
            hash: None,
            height: None,
            version: None,
            prev_hash: None,
            merkle_root: None,
            time: None,
            bits: None,
            nonce: None,
            on_canonical_chain: None,
        })),
    }
}

// Phase 4 Part 2 — HtlcBtcSwapV1 RPC endpoints. Four endpoints behind the
// `htlc_btc_swap_v1_activation_height` gate; claim path additionally
// requires the `btc_spv` relay active so header proofs can resolve. All
// four return SERVICE_UNAVAILABLE while the gate is None.

#[derive(Debug, Deserialize)]
struct CreateBtcSwapRequest {
    irm_amount: String,
    btc_amount_sats: u64,
    btc_recipient_address: String,
    recipient_address: String,
    refund_address: String,
    confirmations_required: u8,
    timeout_height: u64,
    #[serde(default)]
    fee_per_byte: Option<u64>,
    #[serde(default)]
    broadcast: Option<bool>,
}

#[derive(Debug, Serialize)]
struct CreateBtcSwapResponse {
    txid: String,
    accepted: bool,
    raw_tx_hex: String,
    swap_vout: u32,
    funding_binding_hex: String,
    btc_op_return_payload_hex: String,
    expected_btc_payment_address: String,
    expected_btc_amount_sats: u64,
    fee: u64,
}

#[derive(Debug, Deserialize)]
struct ClaimBtcSwapRequest {
    funding_txid: String,
    vout: u32,
    destination_address: String,
    btc_block_hash: String,
    btc_tx_hex: String,
    btc_merkle_branch_hex: Vec<String>,
    btc_merkle_index: u32,
    #[serde(default)]
    fee_per_byte: Option<u64>,
    #[serde(default)]
    broadcast: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct RefundBtcSwapRequest {
    funding_txid: String,
    vout: u32,
    destination_address: String,
    #[serde(default)]
    fee_per_byte: Option<u64>,
    #[serde(default)]
    broadcast: Option<bool>,
}

#[derive(Debug, Serialize)]
struct SpendBtcSwapResponse {
    txid: String,
    accepted: bool,
    raw_tx_hex: String,
    fee: u64,
}

#[derive(Debug, Deserialize)]
struct InspectBtcSwapQuery {
    txid: String,
    vout: u32,
}

#[derive(Debug, Serialize)]
struct InspectBtcSwapResponse {
    exists: bool,
    funded: bool,
    unspent: bool,
    spent: bool,
    recipient_address: Option<String>,
    refund_address: Option<String>,
    btc_recipient_pkh_hex: Option<String>,
    btc_amount_sats: Option<u64>,
    confirmations_required: Option<u8>,
    timeout_height: Option<u64>,
    funding_binding_hex: Option<String>,
    claimable_now: bool,
    refundable_now: bool,
}

// Decode a Bitcoin P2PKH address (base58check, mainnet 0x00 or testnet 0x6f
// prefix) into a 20-byte hash. v1 only supports P2PKH — bech32 P2WPKH inputs
// are rejected because consensus only validates P2PKH at the BTC OP_RETURN
// claim path. Mirrors the existing base58_p2pkh_to_hash double-SHA256
// checksum verification used for iriumd addresses.
fn decode_btc_p2pkh_address(addr: &str) -> Option<[u8; 20]> {
    let data = bs58::decode(addr.trim()).into_vec().ok()?;
    if data.len() != 25 {
        return None;
    }
    let (body, checksum) = data.split_at(21);
    let first = Sha256::digest(body);
    let second = Sha256::digest(first);
    if &second[0..4] != checksum {
        return None;
    }
    if body[0] != 0x00 && body[0] != 0x6f {
        return None;
    }
    let mut pkh = [0u8; 20];
    pkh.copy_from_slice(&body[1..]);
    Some(pkh)
}

/// Decode a bech32 P2WPKH BIP173 address into the 20-byte HASH160(pubkey).
///
/// Accepts only:
///   - bech32 variant (not bech32m — bech32m is reserved for witness
///     versions ≥ 1, i.e. Taproot; v1 is intentionally out of scope for the
///     BTC swap claim path).
///   - witness version 0.
///   - a 20-byte program. The same opcode/length form with a 32-byte
///     program encodes P2WSH; we reject it because consensus has no way
///     to recover the inner script hash and match it against a swap's
///     `btc_recipient_pkh` slot.
///   - HRP listed in `expected_hrps`. Used to keep BTC and LTC decoders
///     symmetric: BTC accepts "bc"/"tb"; LTC accepts "ltc"/"tltc".
fn decode_p2wpkh_bech32_for_hrps(addr: &str, expected_hrps: &[&str]) -> Option<[u8; 20]> {
    let (hrp, witver, program) = bech32::segwit::decode(addr.trim()).ok()?;
    if witver.to_u8() != 0 {
        return None;
    }
    let hrp_s = hrp.as_str();
    if !expected_hrps.iter().any(|h| h.eq_ignore_ascii_case(hrp_s)) {
        return None;
    }
    if program.len() != 20 {
        return None;
    }
    let mut pkh = [0u8; 20];
    pkh.copy_from_slice(&program);
    Some(pkh)
}

/// Decode either a legacy P2PKH (base58check) or a bech32 P2WPKH BTC
/// address into the 20-byte HASH160(pubkey).
///
/// Acceptance of bech32 forms here is RPC-layer ingress only — it lets
/// users post / create swaps with their default modern-wallet address.
/// Whether a bech32 BTC payment subsequently satisfies the claim path is
/// gated by `ChainParams.btc_swap_bech32_payment_activation_height` at
/// consensus time. The 20-byte hash returned is identical for both
/// encodings (both encode HASH160(pubkey)), so the on-chain
/// `btc_recipient_pkh` slot is form-agnostic.
fn decode_btc_address(addr: &str) -> Option<[u8; 20]> {
    decode_btc_p2pkh_address(addr).or_else(|| decode_p2wpkh_bech32_for_hrps(addr, &["bc", "tb"]))
}

async fn create_btc_swap(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers_map: HeaderMap,
    AxumJson(req): AxumJson<CreateBtcSwapRequest>,
) -> Result<Json<CreateBtcSwapResponse>, (StatusCode, String)> {
    let bad = |reason: &str| -> (StatusCode, String) {
        eprintln!("[create_btc_swap] reject reason={}", reason);
        (StatusCode::BAD_REQUEST, reason.to_string())
    };

    check_rate_with_auth(&state, &addr, &headers_map)
        .map_err(|sc| (sc, "rate_limit_or_auth_failed".to_string()))?;
    require_rpc_auth(&headers_map).map_err(|sc| (sc, format!("rpc_auth_failed:{sc}")))?;

    {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let active = chain
            .params
            .htlc_btc_swap_v1_activation_height
            .map(|h| chain.height >= h)
            .unwrap_or(false);
        if !active {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "htlc_btc_swap_v1_not_active".to_string(),
            ));
        }
    }

    if req.confirmations_required < MIN_HTLC_BTC_SWAP_CONFIRMATIONS
        || req.confirmations_required > MAX_HTLC_BTC_SWAP_CONFIRMATIONS
    {
        return Err(bad("confirmations_required_out_of_range"));
    }

    let amount = parse_irm(&req.irm_amount).map_err(|_| bad("irm_amount_parse_failed"))?;
    if amount == 0 {
        return Err(bad("irm_amount_zero"));
    }
    if req.btc_amount_sats == 0 {
        return Err(bad("btc_amount_sats_zero"));
    }

    let recipient_vec = base58_p2pkh_to_hash(&req.recipient_address)
        .ok_or_else(|| bad("recipient_address_decode_failed"))?;
    let refund_vec = base58_p2pkh_to_hash(&req.refund_address)
        .ok_or_else(|| bad("refund_address_decode_failed"))?;
    if recipient_vec.len() != 20 || refund_vec.len() != 20 {
        return Err(bad("iriumd_address_hash_len_invalid"));
    }
    let mut recipient_pkh = [0u8; 20];
    recipient_pkh.copy_from_slice(&recipient_vec);
    let mut refund_pkh = [0u8; 20];
    refund_pkh.copy_from_slice(&refund_vec);

    let btc_recipient_pkh = decode_btc_address(&req.btc_recipient_address)
        .ok_or_else(|| bad("btc_recipient_address_must_be_p2pkh_or_bech32_p2wpkh"))?;

    let mut key_map: HashMap<[u8; 20], WalletKey> = HashMap::new();
    {
        let mut wallet = state.wallet.lock().unwrap_or_else(|e| e.into_inner());
        let keys = wallet.keys().map_err(|_| bad("wallet_keys_unavailable"))?;
        for key in keys {
            let bytes = hex::decode(&key.pkh).map_err(|_| bad("wallet_key_pkh_decode_failed"))?;
            if bytes.len() != 20 {
                continue;
            }
            let mut arr = [0u8; 20];
            arr.copy_from_slice(&bytes);
            key_map.insert(arr, key);
        }
    }
    if key_map.is_empty() {
        return Err(bad("wallet_key_map_empty"));
    }

    let (mut utxos, tip_height) = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let mut collected = Vec::new();
        for (outpoint, utxo) in chain.utxos.iter() {
            if let Some(script_pkh) = p2pkh_hash_from_script(&utxo.output.script_pubkey) {
                if key_map.contains_key(&script_pkh) {
                    collected.push(WalletUtxo {
                        outpoint: outpoint.clone(),
                        output: utxo.output.clone(),
                        height: utxo.height,
                        is_coinbase: utxo.is_coinbase,
                        pkh: script_pkh,
                    });
                }
            }
        }
        (collected, chain.tip_height())
    };
    if utxos.is_empty() {
        return Err(bad("wallet_utxo_set_empty"));
    }
    utxos.sort_by(|a, b| b.output.value.cmp(&a.output.value));

    let mut fee_per_byte = req.fee_per_byte.unwrap_or(1).max(1);
    if fee_per_byte == 0 {
        fee_per_byte = 1;
    }

    let mut selected: Vec<WalletUtxo> = Vec::new();
    let mut total = 0u64;
    let mut fee = 0u64;
    for utxo in utxos.iter() {
        let confirmations = tip_height.saturating_sub(utxo.height);
        if utxo.is_coinbase && confirmations < coinbase_maturity() {
            continue;
        }
        selected.push(utxo.clone());
        total = total.saturating_add(utxo.output.value);
        let n_outs = if total > amount { 2 } else { 1 };
        fee = estimate_tx_size(selected.len(), n_outs).saturating_mul(fee_per_byte);
        if total >= amount.saturating_add(fee) {
            break;
        }
    }
    if total < amount.saturating_add(fee) {
        return Err(bad("insufficient_spendable_funds"));
    }

    let first_input = selected
        .first()
        .ok_or_else(|| bad("no_input_for_binding"))?;
    let funding_binding =
        compute_funding_binding(&first_input.outpoint.txid, first_input.outpoint.index);

    let swap = HtlcBtcSwapV1Output {
        confirmations_required: req.confirmations_required,
        recipient_pkh,
        refund_pkh,
        btc_recipient_pkh,
        btc_amount_sats: req.btc_amount_sats,
        timeout_height: req.timeout_height,
        funding_binding,
    };

    let inputs: Vec<TxInput> = selected
        .iter()
        .map(|u| TxInput {
            prev_txid: u.outpoint.txid,
            prev_index: u.outpoint.index,
            script_sig: Vec::new(),
            sequence: 0xffff_ffff,
        })
        .collect();

    let mut outputs = vec![TxOutput {
        value: amount,
        script_pubkey: encode_htlc_btc_swap_v1_script(&swap),
    }];
    let mut change = total.saturating_sub(amount).saturating_sub(fee);
    if change > 0 {
        let change_pkh = selected
            .first()
            .map(|u| u.pkh)
            .ok_or_else(|| bad("no_change_pkh"))?;
        outputs.push(TxOutput {
            value: change,
            script_pubkey: p2pkh_script(&change_pkh),
        });
    }

    let mut tx = Transaction {
        version: 1,
        inputs,
        outputs,
        locktime: 0,
    };

    for _ in 0..2 {
        sign_wallet_inputs(&mut tx, &selected, &key_map)
            .map_err(|_| bad("sign_wallet_inputs_failed"))?;
        let needed_fee = (tx.serialize().len() as u64).saturating_mul(fee_per_byte);
        if needed_fee > fee {
            let extra = needed_fee - fee;
            if change >= extra {
                fee = needed_fee;
                change = change.saturating_sub(extra);
                if tx.outputs.len() > 1 {
                    tx.outputs[1].value = change;
                }
                continue;
            } else {
                return Err(bad("fee_recalculation_exceeded_change"));
            }
        }
        break;
    }

    let fee_checked = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain
            .calculate_fees(&tx)
            .map_err(|_| bad("chain_fee_calculation_failed"))?
    };
    let raw = tx.serialize();
    let txid_arr = tx.txid();
    let txid_hex = hex::encode(txid_arr);
    let mut accepted = false;
    if req.broadcast.unwrap_or(false) {
        let mut mempool = state.mempool.lock().unwrap_or_else(|e| e.into_inner());
        if !mempool.contains(&txid_arr) {
            match mempool.add_transaction(tx.clone(), raw.clone(), fee_checked) {
                Ok(_) => accepted = true,
                Err(e) => eprintln!("[create_btc_swap] mempool_reject reason={}", e),
            }
        }
    }

    let mut op_return_payload = Vec::with_capacity(14);
    op_return_payload.extend_from_slice(b"irmswp");
    op_return_payload.extend_from_slice(&funding_binding);

    Ok(Json(CreateBtcSwapResponse {
        txid: txid_hex,
        accepted,
        raw_tx_hex: hex::encode(raw),
        swap_vout: 0,
        funding_binding_hex: hex::encode(funding_binding),
        btc_op_return_payload_hex: hex::encode(op_return_payload),
        expected_btc_payment_address: req.btc_recipient_address,
        expected_btc_amount_sats: req.btc_amount_sats,
        fee: fee_checked,
    }))
}

async fn claim_btc_swap(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers_map: HeaderMap,
    AxumJson(req): AxumJson<ClaimBtcSwapRequest>,
) -> Result<Json<SpendBtcSwapResponse>, (StatusCode, String)> {
    let bad = |reason: &str| -> (StatusCode, String) {
        eprintln!("[claim_btc_swap] reject reason={}", reason);
        (StatusCode::BAD_REQUEST, reason.to_string())
    };

    check_rate_with_auth(&state, &addr, &headers_map)
        .map_err(|sc| (sc, "rate_limit_or_auth_failed".to_string()))?;
    require_rpc_auth(&headers_map).map_err(|sc| (sc, format!("rpc_auth_failed:{sc}")))?;

    {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let swap_active = chain
            .params
            .htlc_btc_swap_v1_activation_height
            .map(|h| chain.height >= h)
            .unwrap_or(false);
        let spv_active = chain
            .params
            .btc_spv
            .as_ref()
            .map(|p| chain.height >= p.activation_height)
            .unwrap_or(false);
        if !swap_active || !spv_active {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "htlc_btc_swap_or_btc_spv_not_active".to_string(),
            ));
        }
    }

    let txid_arr =
        hex_to_32(req.funding_txid.trim()).map_err(|_| bad("funding_txid_hex_invalid"))?;
    let key = OutPoint {
        txid: txid_arr,
        index: req.vout,
    };

    let funding_out = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain
            .utxos
            .get(&key)
            .cloned()
            .ok_or_else(|| bad("funding_outpoint_unspent_or_unknown"))?
    };

    let swap = parse_htlc_btc_swap_v1_script(&funding_out.output.script_pubkey)
        .ok_or_else(|| bad("funding_output_not_htlc_btc_swap_v1"))?;

    let signer_pkh = swap.recipient_pkh;
    let wallet_key = {
        let mut wallet = state.wallet.lock().unwrap_or_else(|e| e.into_inner());
        let keys = wallet.keys().map_err(|_| bad("wallet_keys_unavailable"))?;
        let mut found: Option<WalletKey> = None;
        for k in keys {
            let b = hex::decode(&k.pkh).map_err(|_| bad("wallet_key_pkh_decode_failed"))?;
            if b.len() != 20 {
                continue;
            }
            let mut pkh = [0u8; 20];
            pkh.copy_from_slice(&b);
            if pkh == signer_pkh {
                found = Some(k);
                break;
            }
        }
        found.ok_or_else(|| bad("recipient_pkh_key_not_in_wallet"))?
    };

    let dest = base58_p2pkh_to_hash(&req.destination_address)
        .ok_or_else(|| bad("destination_address_decode_failed"))?;
    if dest.len() != 20 {
        return Err(bad("destination_pkh_len_invalid"));
    }
    let mut dest_pkh = [0u8; 20];
    dest_pkh.copy_from_slice(&dest);

    let btc_block_hash =
        parse_btc_display_hash(&req.btc_block_hash).map_err(|_| bad("btc_block_hash_invalid"))?;
    let btc_tx_raw =
        hex::decode(req.btc_tx_hex.trim()).map_err(|_| bad("btc_tx_hex_invalid"))?;
    if btc_tx_raw.is_empty() {
        return Err(bad("btc_tx_hex_empty"));
    }
    let mut branch: Vec<[u8; 32]> = Vec::with_capacity(req.btc_merkle_branch_hex.len());
    for s in &req.btc_merkle_branch_hex {
        let h = parse_btc_display_hash(s).map_err(|_| bad("merkle_branch_node_invalid"))?;
        branch.push(h);
    }

    let fee_per_byte = req.fee_per_byte.unwrap_or(1).max(1);
    let mut fee = estimate_tx_size(1, 1).saturating_mul(fee_per_byte);
    if funding_out.output.value <= fee {
        return Err(bad("funding_value_le_fee"));
    }
    let mut payout = funding_out.output.value - fee;

    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid: txid_arr,
            prev_index: req.vout,
            script_sig: Vec::new(),
            sequence: 0xffff_fffe,
        }],
        outputs: vec![TxOutput {
            value: payout,
            script_pubkey: p2pkh_script(&dest_pkh),
        }],
        locktime: 0,
    };

    let priv_bytes =
        hex::decode(&wallet_key.privkey).map_err(|_| bad("privkey_decode_failed"))?;
    if priv_bytes.len() != 32 {
        return Err(bad("privkey_len_invalid"));
    }
    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(&priv_bytes);
    let signing_key = SigningKey::from_bytes((&sk_bytes).into())
        .map_err(|_| bad("signing_key_init_failed"))?;
    let pubkey = signing_key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();

    // 2-pass fee recalc: estimate_tx_size(1,1) returns 192 bytes, but the
    // real claim witness (sig + pubkey + btc_block_hash + merkle branch +
    // raw BTC tx) pushes the actual tx to ~810 bytes. Without this loop the
    // computed fee is ~0.24 sat/B and mempool admission fails at
    // min_fee_per_byte=100.0. Same pattern as submit_btc_headers.
    for _ in 0..2 {
        let digest = signature_digest(&tx, 0, &funding_out.output.script_pubkey);
        let sig: Signature = signing_key
            .sign_prehash(&digest)
            .map_err(|_| bad("sig_prehash_failed"))?;
        let sig = sig.normalize_s().unwrap_or(sig);
        let mut sig_bytes = sig.to_der().as_bytes().to_vec();
        sig_bytes.push(0x01);
        let witness = encode_htlc_btc_swap_claim_witness(
            &sig_bytes,
            &pubkey,
            &btc_block_hash,
            &branch,
            req.btc_merkle_index,
            &btc_tx_raw,
        )
        .ok_or_else(|| bad("encode_claim_witness_failed"))?;
        tx.inputs[0].script_sig = witness;

        let needed_fee = (tx.serialize().len() as u64).saturating_mul(fee_per_byte);
        if needed_fee > fee {
            let extra = needed_fee - fee;
            if payout > extra {
                fee = needed_fee;
                payout -= extra;
                tx.outputs[0].value = payout;
                continue;
            } else {
                return Err(bad("fee_recalculation_exceeded_payout"));
            }
        }
        break;
    }

    let fee_checked = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain
            .calculate_fees(&tx)
            .map_err(|_| bad("calculate_fees_failed"))?
    };
    let raw = tx.serialize();
    let txid_out = tx.txid();
    let mut accepted = false;
    if req.broadcast.unwrap_or(false) {
        let mut mempool = state.mempool.lock().unwrap_or_else(|e| e.into_inner());
        if !mempool.contains(&txid_out) {
            // HtlcBtcSwapV1 BTC-proof claim: ZeroFeeAllowed so a buyer
            // with no IRM can receive the full swap value with zero
            // network deduction.
            accepted = mempool
                .add_transaction_with_priority(
                    tx,
                    raw.clone(),
                    fee_checked,
                    MempoolPriority::ZeroFeeAllowed,
                    Some(addr.ip()),
                )
                .is_ok();
        }
    }

    // Gap A (NAT broadcast): admitting to local mempool alone relies on
    // the 60s rebroadcast timer to reach peers, which delays order/fill
    // visibility up to a minute on NAT-bound nodes. Push the tx to all
    // currently-connected peers immediately so they see it the moment we
    // accept it. Best-effort; the rebroadcast timer still covers failures.
    if accepted {
        if let Some(ref p2p) = state.p2p {
            let p = p2p.clone();
            let r = raw.clone();
            tokio::spawn(async move {
                if let Err(e) = p.broadcast_tx(&r).await {
                    eprintln!("[swap-broadcast/claim_btc_swap] error: {e}");
                }
            });
        }
    }
    Ok(Json(SpendBtcSwapResponse {
        txid: hex::encode(txid_out),
        accepted,
        raw_tx_hex: hex::encode(raw),
        fee: fee_checked,
    }))
}

async fn refund_btc_swap(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers_map: HeaderMap,
    AxumJson(req): AxumJson<RefundBtcSwapRequest>,
) -> Result<Json<SpendBtcSwapResponse>, (StatusCode, String)> {
    let bad = |reason: &str| -> (StatusCode, String) {
        eprintln!("[refund_btc_swap] reject reason={}", reason);
        (StatusCode::BAD_REQUEST, reason.to_string())
    };

    check_rate_with_auth(&state, &addr, &headers_map)
        .map_err(|sc| (sc, "rate_limit_or_auth_failed".to_string()))?;
    require_rpc_auth(&headers_map).map_err(|sc| (sc, format!("rpc_auth_failed:{sc}")))?;

    {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let active = chain
            .params
            .htlc_btc_swap_v1_activation_height
            .map(|h| chain.height >= h)
            .unwrap_or(false);
        if !active {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "htlc_btc_swap_v1_not_active".to_string(),
            ));
        }
    }

    let txid_arr =
        hex_to_32(req.funding_txid.trim()).map_err(|_| bad("funding_txid_hex_invalid"))?;
    let key = OutPoint {
        txid: txid_arr,
        index: req.vout,
    };

    let (funding_out, tip_height) = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let utxo = chain
            .utxos
            .get(&key)
            .cloned()
            .ok_or_else(|| bad("funding_outpoint_unspent_or_unknown"))?;
        (utxo, chain.tip_height())
    };

    let swap = parse_htlc_btc_swap_v1_script(&funding_out.output.script_pubkey)
        .ok_or_else(|| bad("funding_output_not_htlc_btc_swap_v1"))?;
    if tip_height < swap.timeout_height {
        return Err(bad("timeout_not_reached"));
    }

    let signer_pkh = swap.refund_pkh;
    let wallet_key = {
        let mut wallet = state.wallet.lock().unwrap_or_else(|e| e.into_inner());
        let keys = wallet.keys().map_err(|_| bad("wallet_keys_unavailable"))?;
        let mut found: Option<WalletKey> = None;
        for k in keys {
            let b = hex::decode(&k.pkh).map_err(|_| bad("wallet_key_pkh_decode_failed"))?;
            if b.len() != 20 {
                continue;
            }
            let mut pkh = [0u8; 20];
            pkh.copy_from_slice(&b);
            if pkh == signer_pkh {
                found = Some(k);
                break;
            }
        }
        found.ok_or_else(|| bad("refund_pkh_key_not_in_wallet"))?
    };

    let dest = base58_p2pkh_to_hash(&req.destination_address)
        .ok_or_else(|| bad("destination_address_decode_failed"))?;
    if dest.len() != 20 {
        return Err(bad("destination_pkh_len_invalid"));
    }
    let mut dest_pkh = [0u8; 20];
    dest_pkh.copy_from_slice(&dest);

    let fee_per_byte = req.fee_per_byte.unwrap_or(1).max(1);
    let mut fee = estimate_tx_size(1, 1).saturating_mul(fee_per_byte);
    if funding_out.output.value <= fee {
        return Err(bad("funding_value_le_fee"));
    }
    let mut payout = funding_out.output.value - fee;

    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid: txid_arr,
            prev_index: req.vout,
            script_sig: Vec::new(),
            sequence: 0xffff_fffe,
        }],
        outputs: vec![TxOutput {
            value: payout,
            script_pubkey: p2pkh_script(&dest_pkh),
        }],
        locktime: 0,
    };

    let priv_bytes =
        hex::decode(&wallet_key.privkey).map_err(|_| bad("privkey_decode_failed"))?;
    if priv_bytes.len() != 32 {
        return Err(bad("privkey_len_invalid"));
    }
    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(&priv_bytes);
    let signing_key = SigningKey::from_bytes((&sk_bytes).into())
        .map_err(|_| bad("signing_key_init_failed"))?;
    let pubkey = signing_key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();

    // 2-pass fee recalc: refund witness pushes tx above the
    // estimate_tx_size(1,1) baseline. Same pattern as claim_btc_swap fix
    // (1d9519f) and claim_ltc_swap fix (58ca801).
    for _ in 0..2 {
        let digest = signature_digest(&tx, 0, &funding_out.output.script_pubkey);
        let sig: Signature = signing_key
            .sign_prehash(&digest)
            .map_err(|_| bad("sig_prehash_failed"))?;
        let sig = sig.normalize_s().unwrap_or(sig);
        let mut sig_bytes = sig.to_der().as_bytes().to_vec();
        sig_bytes.push(0x01);

        let witness = encode_htlc_btc_swap_refund_witness(&sig_bytes, &pubkey)
            .ok_or_else(|| bad("encode_refund_witness_failed"))?;
        tx.inputs[0].script_sig = witness;

        let needed_fee = (tx.serialize().len() as u64).saturating_mul(fee_per_byte);
        if needed_fee > fee {
            let extra = needed_fee - fee;
            if payout > extra {
                fee = needed_fee;
                payout -= extra;
                tx.outputs[0].value = payout;
                continue;
            } else {
                return Err(bad("fee_recalculation_exceeded_payout"));
            }
        }
        break;
    }

    let fee_checked = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain
            .calculate_fees(&tx)
            .map_err(|_| bad("calculate_fees_failed"))?
    };
    let raw = tx.serialize();
    let txid_out = tx.txid();
    let mut accepted = false;
    if req.broadcast.unwrap_or(false) {
        let mut mempool = state.mempool.lock().unwrap_or_else(|e| e.into_inner());
        if !mempool.contains(&txid_out) {
            accepted = mempool
                .add_transaction(tx, raw.clone(), fee_checked)
                .is_ok();
        }
    }

    // Gap A (NAT broadcast): admitting to local mempool alone relies on
    // the 60s rebroadcast timer to reach peers, which delays order/fill
    // visibility up to a minute on NAT-bound nodes. Push the tx to all
    // currently-connected peers immediately so they see it the moment we
    // accept it. Best-effort; the rebroadcast timer still covers failures.
    if accepted {
        if let Some(ref p2p) = state.p2p {
            let p = p2p.clone();
            let r = raw.clone();
            tokio::spawn(async move {
                if let Err(e) = p.broadcast_tx(&r).await {
                    eprintln!("[swap-broadcast/refund_btc_swap] error: {e}");
                }
            });
        }
    }
    Ok(Json(SpendBtcSwapResponse {
        txid: hex::encode(txid_out),
        accepted,
        raw_tx_hex: hex::encode(raw),
        fee: fee_checked,
    }))
}

async fn inspect_btc_swap(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers_map: HeaderMap,
    Query(q): Query<InspectBtcSwapQuery>,
) -> Result<Json<InspectBtcSwapResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers_map)?;
    require_rpc_auth(&headers_map)?;

    let txid = hex_to_32(q.txid.trim()).map_err(|_| StatusCode::BAD_REQUEST)?;
    let key = OutPoint {
        txid,
        index: q.vout,
    };

    let (tip_height, maybe_utxo, swap_active, spv_active) = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let utxo = chain.utxos.get(&key).cloned();
        let swap_active = chain
            .params
            .htlc_btc_swap_v1_activation_height
            .map(|h| chain.height >= h)
            .unwrap_or(false);
        let spv_active = chain
            .params
            .btc_spv
            .as_ref()
            .map(|p| chain.height >= p.activation_height)
            .unwrap_or(false);
        (chain.tip_height(), utxo, swap_active, spv_active)
    };

    let Some(utxo) = maybe_utxo else {
        return Ok(Json(InspectBtcSwapResponse {
            exists: false,
            funded: false,
            unspent: false,
            spent: true,
            recipient_address: None,
            refund_address: None,
            btc_recipient_pkh_hex: None,
            btc_amount_sats: None,
            confirmations_required: None,
            timeout_height: None,
            funding_binding_hex: None,
            claimable_now: false,
            refundable_now: false,
        }));
    };

    let swap = match parse_htlc_btc_swap_v1_script(&utxo.output.script_pubkey) {
        Some(v) => v,
        None => {
            return Ok(Json(InspectBtcSwapResponse {
                exists: false,
                funded: false,
                unspent: false,
                spent: false,
                recipient_address: None,
                refund_address: None,
                btc_recipient_pkh_hex: None,
                btc_amount_sats: None,
                confirmations_required: None,
                timeout_height: None,
                funding_binding_hex: None,
                claimable_now: false,
                refundable_now: false,
            }))
        }
    };

    Ok(Json(InspectBtcSwapResponse {
        exists: true,
        funded: true,
        unspent: true,
        spent: false,
        recipient_address: Some(base58_p2pkh_from_hash(&swap.recipient_pkh)),
        refund_address: Some(base58_p2pkh_from_hash(&swap.refund_pkh)),
        btc_recipient_pkh_hex: Some(hex::encode(swap.btc_recipient_pkh)),
        btc_amount_sats: Some(swap.btc_amount_sats),
        confirmations_required: Some(swap.confirmations_required),
        timeout_height: Some(swap.timeout_height),
        funding_binding_hex: Some(hex::encode(swap.funding_binding)),
        claimable_now: swap_active && spv_active,
        refundable_now: tip_height >= swap.timeout_height,
    }))
}

// Phase C — HtlcLtcSwapV1 RPC endpoints. Byte-level mirror of the BTC
// swap RPCs above, gated on `htlc_ltc_swap_v1_activation_height` (and
// additionally on `ltc_spv` for the claim path so LTC header proofs can
// resolve). All four return SERVICE_UNAVAILABLE while the gate is None.

#[derive(Debug, Deserialize)]
struct CreateLtcSwapRequest {
    irm_amount: String,
    ltc_amount_sats: u64,
    ltc_recipient_address: String,
    recipient_address: String,
    refund_address: String,
    confirmations_required: u8,
    timeout_height: u64,
    #[serde(default)]
    fee_per_byte: Option<u64>,
    #[serde(default)]
    broadcast: Option<bool>,
}

#[derive(Debug, Serialize)]
struct CreateLtcSwapResponse {
    txid: String,
    accepted: bool,
    raw_tx_hex: String,
    swap_vout: u32,
    funding_binding_hex: String,
    ltc_op_return_payload_hex: String,
    expected_ltc_payment_address: String,
    expected_ltc_amount_sats: u64,
    fee: u64,
}

#[derive(Debug, Deserialize)]
struct ClaimLtcSwapRequest {
    funding_txid: String,
    vout: u32,
    destination_address: String,
    ltc_block_hash: String,
    ltc_tx_hex: String,
    ltc_merkle_branch_hex: Vec<String>,
    ltc_merkle_index: u32,
    #[serde(default)]
    fee_per_byte: Option<u64>,
    #[serde(default)]
    broadcast: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct RefundLtcSwapRequest {
    funding_txid: String,
    vout: u32,
    destination_address: String,
    #[serde(default)]
    fee_per_byte: Option<u64>,
    #[serde(default)]
    broadcast: Option<bool>,
}

#[derive(Debug, Serialize)]
struct SpendLtcSwapResponse {
    txid: String,
    accepted: bool,
    raw_tx_hex: String,
    fee: u64,
}

#[derive(Debug, Deserialize)]
struct InspectLtcSwapQuery {
    txid: String,
    vout: u32,
}

#[derive(Debug, Serialize)]
struct InspectLtcSwapResponse {
    exists: bool,
    funded: bool,
    unspent: bool,
    spent: bool,
    recipient_address: Option<String>,
    refund_address: Option<String>,
    ltc_recipient_pkh_hex: Option<String>,
    ltc_amount_sats: Option<u64>,
    confirmations_required: Option<u8>,
    timeout_height: Option<u64>,
    funding_binding_hex: Option<String>,
    claimable_now: bool,
    refundable_now: bool,
}

/// Decode a Litecoin P2PKH address (base58check; mainnet prefix `0x30`,
/// testnet prefix `0x6f`) into a 20-byte hash. v1 only supports P2PKH —
/// bech32 (ltc1...) inputs are rejected because consensus only validates
/// P2PKH at the LTC OP_RETURN claim path. Structurally identical to
/// `decode_btc_p2pkh_address`, just different prefix byte.
fn decode_ltc_p2pkh_address(addr: &str) -> Option<[u8; 20]> {
    let data = bs58::decode(addr.trim()).into_vec().ok()?;
    if data.len() != 25 {
        return None;
    }
    let (body, checksum) = data.split_at(21);
    let first = Sha256::digest(body);
    let second = Sha256::digest(first);
    if &second[0..4] != checksum {
        return None;
    }
    if body[0] != 0x30 && body[0] != 0x6f {
        return None;
    }
    let mut pkh = [0u8; 20];
    pkh.copy_from_slice(&body[1..]);
    Some(pkh)
}

/// Decode either a legacy P2PKH (base58check) or a bech32 P2WPKH LTC
/// address into the 20-byte HASH160(pubkey). LTC bech32 acceptance has
/// no separate consensus gate: the LTC swap claim arm itself ships
/// disabled today (`htlc_ltc_swap_v1_active`), and the initial mainnet
/// activation will land with bech32 acceptance on day one. Mirrors
/// `decode_btc_address` but uses the "ltc"/"tltc" HRP set.
fn decode_ltc_address(addr: &str) -> Option<[u8; 20]> {
    decode_ltc_p2pkh_address(addr).or_else(|| decode_p2wpkh_bech32_for_hrps(addr, &["ltc", "tltc"]))
}

async fn create_ltc_swap(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers_map: HeaderMap,
    AxumJson(req): AxumJson<CreateLtcSwapRequest>,
) -> Result<Json<CreateLtcSwapResponse>, (StatusCode, String)> {
    let bad = |reason: &str| -> (StatusCode, String) {
        eprintln!("[create_ltc_swap] reject reason={}", reason);
        (StatusCode::BAD_REQUEST, reason.to_string())
    };

    check_rate_with_auth(&state, &addr, &headers_map)
        .map_err(|sc| (sc, "rate_limit_or_auth_failed".to_string()))?;
    require_rpc_auth(&headers_map).map_err(|sc| (sc, format!("rpc_auth_failed:{sc}")))?;

    {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let active = chain
            .params
            .htlc_ltc_swap_v1_activation_height
            .map(|h| chain.height >= h)
            .unwrap_or(false);
        if !active {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "htlc_ltc_swap_v1_not_active".to_string(),
            ));
        }
    }

    if req.confirmations_required < MIN_HTLC_LTC_SWAP_CONFIRMATIONS
        || req.confirmations_required > MAX_HTLC_LTC_SWAP_CONFIRMATIONS
    {
        return Err(bad("confirmations_required_out_of_range"));
    }

    let amount = parse_irm(&req.irm_amount).map_err(|_| bad("irm_amount_parse_failed"))?;
    if amount == 0 {
        return Err(bad("irm_amount_zero"));
    }
    if req.ltc_amount_sats == 0 {
        return Err(bad("ltc_amount_sats_zero"));
    }

    let recipient_vec = base58_p2pkh_to_hash(&req.recipient_address)
        .ok_or_else(|| bad("recipient_address_decode_failed"))?;
    let refund_vec = base58_p2pkh_to_hash(&req.refund_address)
        .ok_or_else(|| bad("refund_address_decode_failed"))?;
    if recipient_vec.len() != 20 || refund_vec.len() != 20 {
        return Err(bad("iriumd_address_hash_len_invalid"));
    }
    let mut recipient_pkh = [0u8; 20];
    recipient_pkh.copy_from_slice(&recipient_vec);
    let mut refund_pkh = [0u8; 20];
    refund_pkh.copy_from_slice(&refund_vec);

    let ltc_recipient_pkh = decode_ltc_address(&req.ltc_recipient_address)
        .ok_or_else(|| bad("ltc_recipient_address_must_be_p2pkh_or_bech32_p2wpkh"))?;

    let mut key_map: HashMap<[u8; 20], WalletKey> = HashMap::new();
    {
        let mut wallet = state.wallet.lock().unwrap_or_else(|e| e.into_inner());
        let keys = wallet.keys().map_err(|_| bad("wallet_keys_unavailable"))?;
        for key in keys {
            let bytes = hex::decode(&key.pkh).map_err(|_| bad("wallet_key_pkh_decode_failed"))?;
            if bytes.len() != 20 {
                continue;
            }
            let mut arr = [0u8; 20];
            arr.copy_from_slice(&bytes);
            key_map.insert(arr, key);
        }
    }
    if key_map.is_empty() {
        return Err(bad("wallet_key_map_empty"));
    }

    let (mut utxos, tip_height) = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let mut collected = Vec::new();
        for (outpoint, utxo) in chain.utxos.iter() {
            if let Some(script_pkh) = p2pkh_hash_from_script(&utxo.output.script_pubkey) {
                if key_map.contains_key(&script_pkh) {
                    collected.push(WalletUtxo {
                        outpoint: outpoint.clone(),
                        output: utxo.output.clone(),
                        height: utxo.height,
                        is_coinbase: utxo.is_coinbase,
                        pkh: script_pkh,
                    });
                }
            }
        }
        (collected, chain.tip_height())
    };
    if utxos.is_empty() {
        return Err(bad("wallet_utxo_set_empty"));
    }
    utxos.sort_by(|a, b| b.output.value.cmp(&a.output.value));

    let mut fee_per_byte = req.fee_per_byte.unwrap_or(1).max(1);
    if fee_per_byte == 0 {
        fee_per_byte = 1;
    }

    let mut selected: Vec<WalletUtxo> = Vec::new();
    let mut total = 0u64;
    let mut fee = 0u64;
    for utxo in utxos.iter() {
        let confirmations = tip_height.saturating_sub(utxo.height);
        if utxo.is_coinbase && confirmations < coinbase_maturity() {
            continue;
        }
        selected.push(utxo.clone());
        total = total.saturating_add(utxo.output.value);
        let n_outs = if total > amount { 2 } else { 1 };
        fee = estimate_tx_size(selected.len(), n_outs).saturating_mul(fee_per_byte);
        if total >= amount.saturating_add(fee) {
            break;
        }
    }
    if total < amount.saturating_add(fee) {
        return Err(bad("insufficient_spendable_funds"));
    }

    let first_input = selected
        .first()
        .ok_or_else(|| bad("no_input_for_binding"))?;
    let funding_binding =
        compute_funding_binding(&first_input.outpoint.txid, first_input.outpoint.index);

    let swap = HtlcLtcSwapV1Output {
        confirmations_required: req.confirmations_required,
        recipient_pkh,
        refund_pkh,
        ltc_recipient_pkh,
        ltc_amount_sats: req.ltc_amount_sats,
        timeout_height: req.timeout_height,
        funding_binding,
    };

    let inputs: Vec<TxInput> = selected
        .iter()
        .map(|u| TxInput {
            prev_txid: u.outpoint.txid,
            prev_index: u.outpoint.index,
            script_sig: Vec::new(),
            sequence: 0xffff_ffff,
        })
        .collect();

    let mut outputs = vec![TxOutput {
        value: amount,
        script_pubkey: encode_htlc_ltc_swap_v1_script(&swap),
    }];
    let mut change = total.saturating_sub(amount).saturating_sub(fee);
    if change > 0 {
        let change_pkh = selected
            .first()
            .map(|u| u.pkh)
            .ok_or_else(|| bad("no_change_pkh"))?;
        outputs.push(TxOutput {
            value: change,
            script_pubkey: p2pkh_script(&change_pkh),
        });
    }

    let mut tx = Transaction {
        version: 1,
        inputs,
        outputs,
        locktime: 0,
    };

    for _ in 0..2 {
        sign_wallet_inputs(&mut tx, &selected, &key_map)
            .map_err(|_| bad("sign_wallet_inputs_failed"))?;
        let needed_fee = (tx.serialize().len() as u64).saturating_mul(fee_per_byte);
        if needed_fee > fee {
            let extra = needed_fee - fee;
            if change >= extra {
                fee = needed_fee;
                change = change.saturating_sub(extra);
                if tx.outputs.len() > 1 {
                    tx.outputs[1].value = change;
                }
                continue;
            } else {
                return Err(bad("fee_recalculation_exceeded_change"));
            }
        }
        break;
    }

    let fee_checked = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain
            .calculate_fees(&tx)
            .map_err(|_| bad("chain_fee_calculation_failed"))?
    };
    let raw = tx.serialize();
    let txid_arr = tx.txid();
    let txid_hex = hex::encode(txid_arr);
    let mut accepted = false;
    if req.broadcast.unwrap_or(false) {
        let mut mempool = state.mempool.lock().unwrap_or_else(|e| e.into_inner());
        if !mempool.contains(&txid_arr) {
            match mempool.add_transaction(tx.clone(), raw.clone(), fee_checked) {
                Ok(_) => accepted = true,
                Err(e) => eprintln!("[create_ltc_swap] mempool_reject reason={}", e),
            }
        }
    }

    let mut op_return_payload = Vec::with_capacity(14);
    op_return_payload.extend_from_slice(b"irmlsw");
    op_return_payload.extend_from_slice(&funding_binding);

    Ok(Json(CreateLtcSwapResponse {
        txid: txid_hex,
        accepted,
        raw_tx_hex: hex::encode(raw),
        swap_vout: 0,
        funding_binding_hex: hex::encode(funding_binding),
        ltc_op_return_payload_hex: hex::encode(op_return_payload),
        expected_ltc_payment_address: req.ltc_recipient_address,
        expected_ltc_amount_sats: req.ltc_amount_sats,
        fee: fee_checked,
    }))
}

async fn claim_ltc_swap(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers_map: HeaderMap,
    AxumJson(req): AxumJson<ClaimLtcSwapRequest>,
) -> Result<Json<SpendLtcSwapResponse>, (StatusCode, String)> {
    let bad = |reason: &str| -> (StatusCode, String) {
        eprintln!("[claim_ltc_swap] reject reason={}", reason);
        (StatusCode::BAD_REQUEST, reason.to_string())
    };

    check_rate_with_auth(&state, &addr, &headers_map)
        .map_err(|sc| (sc, "rate_limit_or_auth_failed".to_string()))?;
    require_rpc_auth(&headers_map).map_err(|sc| (sc, format!("rpc_auth_failed:{sc}")))?;

    {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let swap_active = chain
            .params
            .htlc_ltc_swap_v1_activation_height
            .map(|h| chain.height >= h)
            .unwrap_or(false);
        let spv_active = chain
            .params
            .ltc_spv
            .as_ref()
            .map(|p| chain.height >= p.activation_height)
            .unwrap_or(false);
        if !swap_active || !spv_active {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "htlc_ltc_swap_or_ltc_spv_not_active".to_string(),
            ));
        }
    }

    let txid_arr =
        hex_to_32(req.funding_txid.trim()).map_err(|_| bad("funding_txid_hex_invalid"))?;
    let key = OutPoint {
        txid: txid_arr,
        index: req.vout,
    };

    let funding_out = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain
            .utxos
            .get(&key)
            .cloned()
            .ok_or_else(|| bad("funding_outpoint_unspent_or_unknown"))?
    };

    let swap = parse_htlc_ltc_swap_v1_script(&funding_out.output.script_pubkey)
        .ok_or_else(|| bad("funding_output_not_htlc_ltc_swap_v1"))?;

    let signer_pkh = swap.recipient_pkh;
    let wallet_key = {
        let mut wallet = state.wallet.lock().unwrap_or_else(|e| e.into_inner());
        let keys = wallet.keys().map_err(|_| bad("wallet_keys_unavailable"))?;
        let mut found: Option<WalletKey> = None;
        for k in keys {
            let b = hex::decode(&k.pkh).map_err(|_| bad("wallet_key_pkh_decode_failed"))?;
            if b.len() != 20 {
                continue;
            }
            let mut pkh = [0u8; 20];
            pkh.copy_from_slice(&b);
            if pkh == signer_pkh {
                found = Some(k);
                break;
            }
        }
        found.ok_or_else(|| bad("recipient_pkh_key_not_in_wallet"))?
    };

    let dest = base58_p2pkh_to_hash(&req.destination_address)
        .ok_or_else(|| bad("destination_address_decode_failed"))?;
    if dest.len() != 20 {
        return Err(bad("destination_pkh_len_invalid"));
    }
    let mut dest_pkh = [0u8; 20];
    dest_pkh.copy_from_slice(&dest);

    let ltc_block_hash =
        parse_btc_display_hash(&req.ltc_block_hash).map_err(|_| bad("ltc_block_hash_invalid"))?;
    let ltc_tx_raw =
        hex::decode(req.ltc_tx_hex.trim()).map_err(|_| bad("ltc_tx_hex_invalid"))?;
    if ltc_tx_raw.is_empty() {
        return Err(bad("ltc_tx_hex_empty"));
    }
    let mut branch: Vec<[u8; 32]> = Vec::with_capacity(req.ltc_merkle_branch_hex.len());
    for s in &req.ltc_merkle_branch_hex {
        let h = parse_btc_display_hash(s).map_err(|_| bad("merkle_branch_node_invalid"))?;
        branch.push(h);
    }

    let fee_per_byte = req.fee_per_byte.unwrap_or(1).max(1);
    let mut fee = estimate_tx_size(1, 1).saturating_mul(fee_per_byte);
    if funding_out.output.value <= fee {
        return Err(bad("funding_value_le_fee"));
    }
    let mut payout = funding_out.output.value - fee;

    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid: txid_arr,
            prev_index: req.vout,
            script_sig: Vec::new(),
            sequence: 0xffff_fffe,
        }],
        outputs: vec![TxOutput {
            value: payout,
            script_pubkey: p2pkh_script(&dest_pkh),
        }],
        locktime: 0,
    };

    let priv_bytes =
        hex::decode(&wallet_key.privkey).map_err(|_| bad("privkey_decode_failed"))?;
    if priv_bytes.len() != 32 {
        return Err(bad("privkey_len_invalid"));
    }
    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(&priv_bytes);
    let signing_key = SigningKey::from_bytes((&sk_bytes).into())
        .map_err(|_| bad("signing_key_init_failed"))?;
    let pubkey = signing_key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();

    // 2-pass fee recalc: estimate_tx_size(1,1) returns 192 bytes, but the
    // real claim witness (sig + pubkey + ltc_block_hash + merkle branch +
    // raw LTC tx) pushes the actual tx well above that. Without this loop
    // the computed fee falls below the 1.0 sat/B mempool floor and
    // add_transaction rejects with "Fee per byte below minimum policy".
    // Same pattern as claim_btc_swap fix in 1d9519f.
    for _ in 0..2 {
        let digest = signature_digest(&tx, 0, &funding_out.output.script_pubkey);
        let sig: Signature = signing_key
            .sign_prehash(&digest)
            .map_err(|_| bad("sig_prehash_failed"))?;
        let sig = sig.normalize_s().unwrap_or(sig);
        let mut sig_bytes = sig.to_der().as_bytes().to_vec();
        sig_bytes.push(0x01);
        let witness = encode_htlc_ltc_swap_claim_witness(
            &sig_bytes,
            &pubkey,
            &ltc_block_hash,
            &branch,
            req.ltc_merkle_index,
            &ltc_tx_raw,
        )
        .ok_or_else(|| bad("encode_claim_witness_failed"))?;
        tx.inputs[0].script_sig = witness;

        let needed_fee = (tx.serialize().len() as u64).saturating_mul(fee_per_byte);
        if needed_fee > fee {
            let extra = needed_fee - fee;
            if payout > extra {
                fee = needed_fee;
                payout -= extra;
                tx.outputs[0].value = payout;
                continue;
            } else {
                return Err(bad("fee_recalculation_exceeded_payout"));
            }
        }
        break;
    }

    let fee_checked = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain
            .calculate_fees(&tx)
            .map_err(|_| bad("calculate_fees_failed"))?
    };
    let raw = tx.serialize();
    let txid_out = tx.txid();
    let mut accepted = false;
    if req.broadcast.unwrap_or(false) {
        let mut mempool = state.mempool.lock().unwrap_or_else(|e| e.into_inner());
        if !mempool.contains(&txid_out) {
            accepted = mempool
                .add_transaction(tx, raw.clone(), fee_checked)
                .is_ok();
        }
    }

    // Gap A (NAT broadcast): admitting to local mempool alone relies on
    // the 60s rebroadcast timer to reach peers, which delays order/fill
    // visibility up to a minute on NAT-bound nodes. Push the tx to all
    // currently-connected peers immediately so they see it the moment we
    // accept it. Best-effort; the rebroadcast timer still covers failures.
    if accepted {
        if let Some(ref p2p) = state.p2p {
            let p = p2p.clone();
            let r = raw.clone();
            tokio::spawn(async move {
                if let Err(e) = p.broadcast_tx(&r).await {
                    eprintln!("[swap-broadcast/claim_ltc_swap] error: {e}");
                }
            });
        }
    }
    Ok(Json(SpendLtcSwapResponse {
        txid: hex::encode(txid_out),
        accepted,
        raw_tx_hex: hex::encode(raw),
        fee: fee_checked,
    }))
}

async fn refund_ltc_swap(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers_map: HeaderMap,
    AxumJson(req): AxumJson<RefundLtcSwapRequest>,
) -> Result<Json<SpendLtcSwapResponse>, (StatusCode, String)> {
    let bad = |reason: &str| -> (StatusCode, String) {
        eprintln!("[refund_ltc_swap] reject reason={}", reason);
        (StatusCode::BAD_REQUEST, reason.to_string())
    };

    check_rate_with_auth(&state, &addr, &headers_map)
        .map_err(|sc| (sc, "rate_limit_or_auth_failed".to_string()))?;
    require_rpc_auth(&headers_map).map_err(|sc| (sc, format!("rpc_auth_failed:{sc}")))?;

    {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let active = chain
            .params
            .htlc_ltc_swap_v1_activation_height
            .map(|h| chain.height >= h)
            .unwrap_or(false);
        if !active {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "htlc_ltc_swap_v1_not_active".to_string(),
            ));
        }
    }

    let txid_arr =
        hex_to_32(req.funding_txid.trim()).map_err(|_| bad("funding_txid_hex_invalid"))?;
    let key = OutPoint {
        txid: txid_arr,
        index: req.vout,
    };

    let (funding_out, tip_height) = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let utxo = chain
            .utxos
            .get(&key)
            .cloned()
            .ok_or_else(|| bad("funding_outpoint_unspent_or_unknown"))?;
        (utxo, chain.tip_height())
    };

    let swap = parse_htlc_ltc_swap_v1_script(&funding_out.output.script_pubkey)
        .ok_or_else(|| bad("funding_output_not_htlc_ltc_swap_v1"))?;
    if tip_height < swap.timeout_height {
        return Err(bad("timeout_not_reached"));
    }

    let signer_pkh = swap.refund_pkh;
    let wallet_key = {
        let mut wallet = state.wallet.lock().unwrap_or_else(|e| e.into_inner());
        let keys = wallet.keys().map_err(|_| bad("wallet_keys_unavailable"))?;
        let mut found: Option<WalletKey> = None;
        for k in keys {
            let b = hex::decode(&k.pkh).map_err(|_| bad("wallet_key_pkh_decode_failed"))?;
            if b.len() != 20 {
                continue;
            }
            let mut pkh = [0u8; 20];
            pkh.copy_from_slice(&b);
            if pkh == signer_pkh {
                found = Some(k);
                break;
            }
        }
        found.ok_or_else(|| bad("refund_pkh_key_not_in_wallet"))?
    };

    let dest = base58_p2pkh_to_hash(&req.destination_address)
        .ok_or_else(|| bad("destination_address_decode_failed"))?;
    if dest.len() != 20 {
        return Err(bad("destination_pkh_len_invalid"));
    }
    let mut dest_pkh = [0u8; 20];
    dest_pkh.copy_from_slice(&dest);

    let fee_per_byte = req.fee_per_byte.unwrap_or(1).max(1);
    let mut fee = estimate_tx_size(1, 1).saturating_mul(fee_per_byte);
    if funding_out.output.value <= fee {
        return Err(bad("funding_value_le_fee"));
    }
    let mut payout = funding_out.output.value - fee;

    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid: txid_arr,
            prev_index: req.vout,
            script_sig: Vec::new(),
            sequence: 0xffff_fffe,
        }],
        outputs: vec![TxOutput {
            value: payout,
            script_pubkey: p2pkh_script(&dest_pkh),
        }],
        locktime: 0,
    };

    let priv_bytes =
        hex::decode(&wallet_key.privkey).map_err(|_| bad("privkey_decode_failed"))?;
    if priv_bytes.len() != 32 {
        return Err(bad("privkey_len_invalid"));
    }
    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(&priv_bytes);
    let signing_key = SigningKey::from_bytes((&sk_bytes).into())
        .map_err(|_| bad("signing_key_init_failed"))?;
    let pubkey = signing_key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();

    for _ in 0..2 {
        let digest = signature_digest(&tx, 0, &funding_out.output.script_pubkey);
        let sig: Signature = signing_key
            .sign_prehash(&digest)
            .map_err(|_| bad("sig_prehash_failed"))?;
        let sig = sig.normalize_s().unwrap_or(sig);
        let mut sig_bytes = sig.to_der().as_bytes().to_vec();
        sig_bytes.push(0x01);

        let witness = encode_htlc_ltc_swap_refund_witness(&sig_bytes, &pubkey)
            .ok_or_else(|| bad("encode_refund_witness_failed"))?;
        tx.inputs[0].script_sig = witness;

        let needed_fee = (tx.serialize().len() as u64).saturating_mul(fee_per_byte);
        if needed_fee > fee {
            let extra = needed_fee - fee;
            if payout > extra {
                fee = needed_fee;
                payout -= extra;
                tx.outputs[0].value = payout;
                continue;
            } else {
                return Err(bad("fee_recalculation_exceeded_payout"));
            }
        }
        break;
    }

    let fee_checked = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain
            .calculate_fees(&tx)
            .map_err(|_| bad("calculate_fees_failed"))?
    };
    let raw = tx.serialize();
    let txid_out = tx.txid();
    let mut accepted = false;
    if req.broadcast.unwrap_or(false) {
        let mut mempool = state.mempool.lock().unwrap_or_else(|e| e.into_inner());
        if !mempool.contains(&txid_out) {
            accepted = mempool
                .add_transaction(tx, raw.clone(), fee_checked)
                .is_ok();
        }
    }

    // Gap A (NAT broadcast): admitting to local mempool alone relies on
    // the 60s rebroadcast timer to reach peers, which delays order/fill
    // visibility up to a minute on NAT-bound nodes. Push the tx to all
    // currently-connected peers immediately so they see it the moment we
    // accept it. Best-effort; the rebroadcast timer still covers failures.
    if accepted {
        if let Some(ref p2p) = state.p2p {
            let p = p2p.clone();
            let r = raw.clone();
            tokio::spawn(async move {
                if let Err(e) = p.broadcast_tx(&r).await {
                    eprintln!("[swap-broadcast/refund_ltc_swap] error: {e}");
                }
            });
        }
    }
    Ok(Json(SpendLtcSwapResponse {
        txid: hex::encode(txid_out),
        accepted,
        raw_tx_hex: hex::encode(raw),
        fee: fee_checked,
    }))
}

async fn inspect_ltc_swap(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers_map: HeaderMap,
    Query(q): Query<InspectLtcSwapQuery>,
) -> Result<Json<InspectLtcSwapResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers_map)?;
    require_rpc_auth(&headers_map)?;

    let txid = hex_to_32(q.txid.trim()).map_err(|_| StatusCode::BAD_REQUEST)?;
    let key = OutPoint {
        txid,
        index: q.vout,
    };

    let (tip_height, maybe_utxo, swap_active, spv_active) = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let utxo = chain.utxos.get(&key).cloned();
        let swap_active = chain
            .params
            .htlc_ltc_swap_v1_activation_height
            .map(|h| chain.height >= h)
            .unwrap_or(false);
        let spv_active = chain
            .params
            .ltc_spv
            .as_ref()
            .map(|p| chain.height >= p.activation_height)
            .unwrap_or(false);
        (chain.tip_height(), utxo, swap_active, spv_active)
    };

    let Some(utxo) = maybe_utxo else {
        return Ok(Json(InspectLtcSwapResponse {
            exists: false,
            funded: false,
            unspent: false,
            spent: true,
            recipient_address: None,
            refund_address: None,
            ltc_recipient_pkh_hex: None,
            ltc_amount_sats: None,
            confirmations_required: None,
            timeout_height: None,
            funding_binding_hex: None,
            claimable_now: false,
            refundable_now: false,
        }));
    };

    let swap = match parse_htlc_ltc_swap_v1_script(&utxo.output.script_pubkey) {
        Some(v) => v,
        None => {
            return Ok(Json(InspectLtcSwapResponse {
                exists: false,
                funded: false,
                unspent: false,
                spent: false,
                recipient_address: None,
                refund_address: None,
                ltc_recipient_pkh_hex: None,
                ltc_amount_sats: None,
                confirmations_required: None,
                timeout_height: None,
                funding_binding_hex: None,
                claimable_now: false,
                refundable_now: false,
            }))
        }
    };

    Ok(Json(InspectLtcSwapResponse {
        exists: true,
        funded: true,
        unspent: true,
        spent: false,
        recipient_address: Some(base58_p2pkh_from_hash(&swap.recipient_pkh)),
        refund_address: Some(base58_p2pkh_from_hash(&swap.refund_pkh)),
        ltc_recipient_pkh_hex: Some(hex::encode(swap.ltc_recipient_pkh)),
        ltc_amount_sats: Some(swap.ltc_amount_sats),
        confirmations_required: Some(swap.confirmations_required),
        timeout_height: Some(swap.timeout_height),
        funding_binding_hex: Some(hex::encode(swap.funding_binding)),
        claimable_now: swap_active && spv_active,
        refundable_now: tip_height >= swap.timeout_height,
    }))
}


// Phase 4 Part 3 — SwapOrder RPC endpoints. Six endpoints behind the
// `swap_order_v1_activation_height` gate. C5 sell-direction fills create
// HtlcBtcSwapV1 outputs (so swap_order_v1 + htlc_btc_swap_v1 should
// activate together); C5 buy-direction fills create HTLCv1 outputs (so
// htlcv1 must also be active for buy fills to validate post-activation).
//
// listswaporders (C2) scans ChainState.utxos because there is no indexed
// open_orders map yet; this is O(n_utxos) per call. A future Part 3.5 can
// add the index without breaking the API.
//
// C5 sell covenant note: consensus enforces
// funding_binding == compute_funding_binding(spending_tx.txid(), 0) for
// the new HtlcBtcSwapV1 at vout 0. The binding lives inside vout 0's
// script, so changing it changes the txid, making the constraint
// self-referential. The wallet sets binding deterministically from the
// order outpoint (compute_funding_binding(order.txid, order.vout)); this
// will fail the covenant check post-activation. Documented as a Part 3.5
// follow-up requiring a consensus rule change before sell fills can ship.

#[derive(Debug, Deserialize)]
struct PostSwapOrderRequest {
    direction: String,
    irm_amount: String,
    btc_amount_sats: u64,
    maker_iriumd_address: String,
    maker_btc_address: String,
    confirmations_required: u8,
    expiry_blocks_from_now: u64,
    #[serde(default)]
    expected_hash_hex: Option<String>,
    #[serde(default)]
    fee_per_byte: Option<u64>,
    #[serde(default)]
    broadcast: Option<bool>,
}

#[derive(Debug, Serialize)]
struct OutPointJson {
    txid: String,
    vout: u32,
}

#[derive(Debug, Serialize)]
struct PostSwapOrderResponse {
    txid: String,
    accepted: bool,
    raw_tx_hex: String,
    order_outpoint: OutPointJson,
    order_id_hex: String,
    expiry_height: u64,
    fee: u64,
}

#[derive(Debug, Deserialize)]
struct ListSwapOrdersQuery {
    #[serde(default)]
    direction: Option<String>,
    #[serde(default)]
    min_irm: Option<u64>,
    #[serde(default)]
    max_irm: Option<u64>,
    #[serde(default)]
    min_btc: Option<u64>,
    #[serde(default)]
    max_btc: Option<u64>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
    #[serde(default)]
    sort: Option<String>,
}

#[derive(Debug, Serialize)]
struct SwapOrderJson {
    outpoint: OutPointJson,
    order_id_hex: String,
    direction: String,
    irm_amount: u64,
    btc_amount_sats: u64,
    implied_btc_per_irm_sats: f64,
    maker_iriumd_address: String,
    maker_btc_pkh_hex: String,
    confirmations_required: u8,
    expiry_height: u64,
    locked_value: u64,
    expected_hash_hex: Option<String>,
}

#[derive(Debug, Serialize)]
struct ListSwapOrdersResponse {
    orders: Vec<SwapOrderJson>,
    total_open: usize,
}

#[derive(Debug, Deserialize)]
struct GetSwapOrderQuery {
    txid: String,
    vout: u32,
}

#[derive(Debug, Serialize)]
struct GetSwapOrderResponse {
    found: bool,
    order: Option<SwapOrderJson>,
    status: String,
}

#[derive(Debug, Deserialize)]
struct CancelSwapOrderRequest {
    order_txid: String,
    order_vout: u32,
    destination_address: String,
    #[serde(default)]
    fee_per_byte: Option<u64>,
    #[serde(default)]
    broadcast: Option<bool>,
}

#[derive(Debug, Serialize)]
struct SwapSpendResponse {
    txid: String,
    accepted: bool,
    raw_tx_hex: String,
    fee: u64,
}

#[derive(Debug, Deserialize)]
struct FillSwapOrderRequest {
    order_txid: String,
    order_vout: u32,
    taker_iriumd_address: String,
    #[serde(default)]
    taker_btc_address: Option<String>,
    timeout_blocks_from_now: u64,
    #[serde(default)]
    fee_per_byte: Option<u64>,
    #[serde(default)]
    broadcast: Option<bool>,
}

#[derive(Debug, Serialize)]
struct FillSwapOrderResponse {
    txid: String,
    accepted: bool,
    raw_tx_hex: String,
    new_outpoint: OutPointJson,
    direction: String,
    fee: u64,
}

#[derive(Debug, Deserialize)]
struct SweepExpiredOrderRequest {
    order_txid: String,
    order_vout: u32,
    #[serde(default)]
    fee_per_byte: Option<u64>,
    #[serde(default)]
    broadcast: Option<bool>,
}

// Deterministic 8-byte order identifier from the order body fields
// (everything except the order_id slot itself). Used so callers can
// recognise an order across reads without keying on the funding outpoint.
fn compute_swap_order_id(o: &SwapOrderOutput) -> [u8; 8] {
    let mut hasher = Sha256::new();
    hasher.update([o.direction, o.confirmations_required]);
    hasher.update(o.irm_amount.to_le_bytes());
    hasher.update(o.btc_amount_sats.to_le_bytes());
    hasher.update(o.maker_iriumd_pkh);
    hasher.update(o.maker_btc_pkh);
    hasher.update(o.expiry_height.to_le_bytes());
    if let Some(h) = &o.expected_hash {
        hasher.update(h);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

fn swap_direction_label(direction: u8) -> &'static str {
    match direction {
        SWAP_ORDER_DIRECTION_SELL => "sell_irm",
        SWAP_ORDER_DIRECTION_BUY => "buy_irm",
        _ => "unknown",
    }
}

fn parse_swap_direction(s: &str) -> Option<u8> {
    match s.trim().to_ascii_lowercase().as_str() {
        "sell_irm" | "sell" => Some(SWAP_ORDER_DIRECTION_SELL),
        "buy_irm" | "buy" => Some(SWAP_ORDER_DIRECTION_BUY),
        _ => None,
    }
}

async fn post_swap_order(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers_map: HeaderMap,
    AxumJson(req): AxumJson<PostSwapOrderRequest>,
) -> Result<Json<PostSwapOrderResponse>, (StatusCode, String)> {
    let bad = |reason: &str| -> (StatusCode, String) {
        eprintln!("[post_swap_order] reject reason={}", reason);
        (StatusCode::BAD_REQUEST, reason.to_string())
    };

    check_rate_with_auth(&state, &addr, &headers_map)
        .map_err(|sc| (sc, "rate_limit_or_auth_failed".to_string()))?;
    require_rpc_auth(&headers_map).map_err(|sc| (sc, format!("rpc_auth_failed:{sc}")))?;

    let tip_height_before = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let active = chain
            .params
            .swap_order_v1_activation_height
            .map(|h| chain.height >= h)
            .unwrap_or(false);
        if !active {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "swap_order_v1_not_active".to_string(),
            ));
        }
        chain.tip_height()
    };

    let direction =
        parse_swap_direction(&req.direction).ok_or_else(|| bad("direction_invalid"))?;
    let irm_amount = parse_irm(&req.irm_amount).map_err(|_| bad("irm_amount_parse_failed"))?;
    if irm_amount == 0 {
        return Err(bad("irm_amount_zero"));
    }
    if req.btc_amount_sats == 0 {
        return Err(bad("btc_amount_sats_zero"));
    }
    if req.confirmations_required < MIN_HTLC_BTC_SWAP_CONFIRMATIONS
        || req.confirmations_required > MAX_HTLC_BTC_SWAP_CONFIRMATIONS
    {
        return Err(bad("confirmations_required_out_of_range"));
    }
    if req.expiry_blocks_from_now == 0 {
        return Err(bad("expiry_blocks_from_now_zero"));
    }
    let expiry_height = tip_height_before.saturating_add(req.expiry_blocks_from_now);

    let maker_iriumd_vec = base58_p2pkh_to_hash(&req.maker_iriumd_address)
        .ok_or_else(|| bad("maker_iriumd_address_decode_failed"))?;
    if maker_iriumd_vec.len() != 20 {
        return Err(bad("maker_iriumd_pkh_len_invalid"));
    }
    let mut maker_iriumd_pkh = [0u8; 20];
    maker_iriumd_pkh.copy_from_slice(&maker_iriumd_vec);

    let maker_btc_pkh = decode_btc_address(&req.maker_btc_address)
        .ok_or_else(|| bad("maker_btc_address_must_be_p2pkh_or_bech32_p2wpkh"))?;

    let expected_hash = if direction == SWAP_ORDER_DIRECTION_BUY {
        let h_hex = req
            .expected_hash_hex
            .as_deref()
            .ok_or_else(|| bad("expected_hash_hex_required_for_buy_irm"))?;
        let bytes = hex::decode(h_hex.trim()).map_err(|_| bad("expected_hash_hex_invalid"))?;
        if bytes.len() != 32 {
            return Err(bad("expected_hash_len_invalid"));
        }
        let mut h = [0u8; 32];
        h.copy_from_slice(&bytes);
        Some(h)
    } else {
        None
    };

    let mut order = SwapOrderOutput {
        direction,
        confirmations_required: req.confirmations_required,
        irm_amount,
        btc_amount_sats: req.btc_amount_sats,
        maker_iriumd_pkh,
        maker_btc_pkh,
        expiry_height,
        order_id: [0u8; 8],
        expected_hash,
    };
    order.order_id = compute_swap_order_id(&order);

    let order_script = encode_swap_order_script(&order);
    let order_value = if direction == SWAP_ORDER_DIRECTION_SELL {
        irm_amount
    } else {
        SWAP_ORDER_MIN_LOCKED_VALUE
    };

    let mut key_map: HashMap<[u8; 20], WalletKey> = HashMap::new();
    {
        let mut wallet = state.wallet.lock().unwrap_or_else(|e| e.into_inner());
        let keys = wallet.keys().map_err(|_| bad("wallet_keys_unavailable"))?;
        for key in keys {
            let bytes = hex::decode(&key.pkh).map_err(|_| bad("wallet_key_pkh_decode_failed"))?;
            if bytes.len() != 20 {
                continue;
            }
            let mut arr = [0u8; 20];
            arr.copy_from_slice(&bytes);
            key_map.insert(arr, key);
        }
    }
    if key_map.is_empty() {
        return Err(bad("wallet_key_map_empty"));
    }

    let (mut utxos, tip_height) = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let mut collected = Vec::new();
        for (outpoint, utxo) in chain.utxos.iter() {
            if let Some(script_pkh) = p2pkh_hash_from_script(&utxo.output.script_pubkey) {
                if key_map.contains_key(&script_pkh) {
                    collected.push(WalletUtxo {
                        outpoint: outpoint.clone(),
                        output: utxo.output.clone(),
                        height: utxo.height,
                        is_coinbase: utxo.is_coinbase,
                        pkh: script_pkh,
                    });
                }
            }
        }
        (collected, chain.tip_height())
    };
    if utxos.is_empty() {
        return Err(bad("wallet_utxo_set_empty"));
    }
    utxos.sort_by(|a, b| b.output.value.cmp(&a.output.value));

    let mut fee_per_byte = req.fee_per_byte.unwrap_or(1).max(1);
    if fee_per_byte == 0 {
        fee_per_byte = 1;
    }

    let mut selected: Vec<WalletUtxo> = Vec::new();
    let mut total = 0u64;
    let mut fee = 0u64;
    for utxo in utxos.iter() {
        let confirmations = tip_height.saturating_sub(utxo.height);
        if utxo.is_coinbase && confirmations < coinbase_maturity() {
            continue;
        }
        selected.push(utxo.clone());
        total = total.saturating_add(utxo.output.value);
        let n_outs = if total > order_value { 2 } else { 1 };
        fee = estimate_tx_size(selected.len(), n_outs)
            .saturating_add(order_script.len() as u64)
            .saturating_mul(fee_per_byte);
        if total >= order_value.saturating_add(fee) {
            break;
        }
    }
    if total < order_value.saturating_add(fee) {
        return Err(bad("insufficient_spendable_funds"));
    }

    let inputs: Vec<TxInput> = selected
        .iter()
        .map(|u| TxInput {
            prev_txid: u.outpoint.txid,
            prev_index: u.outpoint.index,
            script_sig: Vec::new(),
            sequence: 0xffff_ffff,
        })
        .collect();

    let mut outputs = vec![TxOutput {
        value: order_value,
        script_pubkey: order_script,
    }];
    let mut change = total.saturating_sub(order_value).saturating_sub(fee);
    if change > 0 {
        let change_pkh = selected
            .first()
            .map(|u| u.pkh)
            .ok_or_else(|| bad("no_change_pkh"))?;
        outputs.push(TxOutput {
            value: change,
            script_pubkey: p2pkh_script(&change_pkh),
        });
    }

    let mut tx = Transaction {
        version: 1,
        inputs,
        outputs,
        locktime: 0,
    };

    for _ in 0..2 {
        sign_wallet_inputs(&mut tx, &selected, &key_map)
            .map_err(|_| bad("sign_wallet_inputs_failed"))?;
        let needed_fee = (tx.serialize().len() as u64).saturating_mul(fee_per_byte);
        if needed_fee > fee {
            let extra = needed_fee - fee;
            if change >= extra {
                fee = needed_fee;
                change = change.saturating_sub(extra);
                if tx.outputs.len() > 1 {
                    tx.outputs[1].value = change;
                }
                continue;
            } else {
                return Err(bad("fee_recalculation_exceeded_change"));
            }
        }
        break;
    }

    let fee_checked = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain
            .calculate_fees(&tx)
            .map_err(|_| bad("chain_fee_calculation_failed"))?
    };
    let raw = tx.serialize();
    let txid_arr = tx.txid();
    let txid_hex = hex::encode(txid_arr);
    let mut accepted = false;
    if req.broadcast.unwrap_or(false) {
        let mut mempool = state.mempool.lock().unwrap_or_else(|e| e.into_inner());
        if !mempool.contains(&txid_arr) {
            match mempool.add_transaction(tx.clone(), raw.clone(), fee_checked) {
                Ok(_) => accepted = true,
                Err(e) => eprintln!("[post_swap_order] mempool_reject reason={}", e),
            }
        }
    }

    // Gap A (NAT broadcast): admitting to local mempool alone relies on
    // the 60s rebroadcast timer to reach peers, which delays order/fill
    // visibility up to a minute on NAT-bound nodes. Push the tx to all
    // currently-connected peers immediately so they see it the moment we
    // accept it. Best-effort; the rebroadcast timer still covers failures.
    if accepted {
        if let Some(ref p2p) = state.p2p {
            let p = p2p.clone();
            let r = raw.clone();
            tokio::spawn(async move {
                if let Err(e) = p.broadcast_tx(&r).await {
                    eprintln!("[swap-broadcast/post_swap_order] error: {e}");
                }
            });
        }
    }

    Ok(Json(PostSwapOrderResponse {
        txid: txid_hex.clone(),
        accepted,
        raw_tx_hex: hex::encode(raw),
        order_outpoint: OutPointJson {
            txid: txid_hex,
            vout: 0,
        },
        order_id_hex: hex::encode(order.order_id),
        expiry_height,
        fee: fee_checked,
    }))
}

async fn list_swap_orders(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers_map: HeaderMap,
    Query(q): Query<ListSwapOrdersQuery>,
) -> Result<Json<ListSwapOrdersResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers_map)?;
    require_rpc_auth(&headers_map)?;

    let direction_filter = match q.direction.as_deref() {
        None | Some("both") => None,
        Some(s) => match parse_swap_direction(s) {
            Some(d) => Some(d),
            None => return Err(StatusCode::BAD_REQUEST),
        },
    };
    let limit = q.limit.unwrap_or(100).min(1000);
    let offset = q.offset.unwrap_or(0);
    let sort = q.sort.as_deref().unwrap_or("recent");

    let mut all: Vec<SwapOrderJson> = Vec::new();
    {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        for (outpoint, utxo) in chain.utxos.iter() {
            let order = match parse_swap_order_script(&utxo.output.script_pubkey) {
                Some(o) => o,
                None => continue,
            };
            if let Some(d) = direction_filter {
                if order.direction != d {
                    continue;
                }
            }
            if let Some(min) = q.min_irm {
                if order.irm_amount < min {
                    continue;
                }
            }
            if let Some(max) = q.max_irm {
                if order.irm_amount > max {
                    continue;
                }
            }
            if let Some(min) = q.min_btc {
                if order.btc_amount_sats < min {
                    continue;
                }
            }
            if let Some(max) = q.max_btc {
                if order.btc_amount_sats > max {
                    continue;
                }
            }
            let implied = if order.irm_amount > 0 {
                order.btc_amount_sats as f64 / order.irm_amount as f64
            } else {
                0.0
            };
            all.push(SwapOrderJson {
                outpoint: OutPointJson {
                    txid: hex::encode(outpoint.txid),
                    vout: outpoint.index,
                },
                order_id_hex: hex::encode(order.order_id),
                direction: swap_direction_label(order.direction).to_string(),
                irm_amount: order.irm_amount,
                btc_amount_sats: order.btc_amount_sats,
                implied_btc_per_irm_sats: implied,
                maker_iriumd_address: base58_p2pkh_from_hash(&order.maker_iriumd_pkh),
                maker_btc_pkh_hex: hex::encode(order.maker_btc_pkh),
                confirmations_required: order.confirmations_required,
                expiry_height: order.expiry_height,
                locked_value: utxo.output.value,
                expected_hash_hex: order.expected_hash.map(hex::encode),
            });
        }
    }

    let total_open = all.len();
    match sort {
        "price_asc" => all.sort_by(|a, b| {
            a.implied_btc_per_irm_sats
                .partial_cmp(&b.implied_btc_per_irm_sats)
                .unwrap_or(std::cmp::Ordering::Equal)
        }),
        "price_desc" => all.sort_by(|a, b| {
            b.implied_btc_per_irm_sats
                .partial_cmp(&a.implied_btc_per_irm_sats)
                .unwrap_or(std::cmp::Ordering::Equal)
        }),
        _ => all.sort_by(|a, b| b.expiry_height.cmp(&a.expiry_height)),
    }

    let page: Vec<SwapOrderJson> = all.into_iter().skip(offset).take(limit).collect();
    Ok(Json(ListSwapOrdersResponse {
        orders: page,
        total_open,
    }))
}

async fn get_swap_order(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers_map: HeaderMap,
    Query(q): Query<GetSwapOrderQuery>,
) -> Result<Json<GetSwapOrderResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers_map)?;
    require_rpc_auth(&headers_map)?;

    let txid = hex_to_32(q.txid.trim()).map_err(|_| StatusCode::BAD_REQUEST)?;
    let key = OutPoint {
        txid,
        index: q.vout,
    };

    let (tip_height, maybe_utxo) = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        (chain.tip_height(), chain.utxos.get(&key).cloned())
    };

    let Some(utxo) = maybe_utxo else {
        return Ok(Json(GetSwapOrderResponse {
            found: false,
            order: None,
            status: "closed".to_string(),
        }));
    };

    let order = match parse_swap_order_script(&utxo.output.script_pubkey) {
        Some(o) => o,
        None => {
            return Ok(Json(GetSwapOrderResponse {
                found: false,
                order: None,
                status: "not_a_swap_order".to_string(),
            }));
        }
    };

    let implied = if order.irm_amount > 0 {
        order.btc_amount_sats as f64 / order.irm_amount as f64
    } else {
        0.0
    };
    let status = if tip_height >= order.expiry_height {
        "expired"
    } else {
        "open"
    };
    Ok(Json(GetSwapOrderResponse {
        found: true,
        order: Some(SwapOrderJson {
            outpoint: OutPointJson {
                txid: hex::encode(key.txid),
                vout: key.index,
            },
            order_id_hex: hex::encode(order.order_id),
            direction: swap_direction_label(order.direction).to_string(),
            irm_amount: order.irm_amount,
            btc_amount_sats: order.btc_amount_sats,
            implied_btc_per_irm_sats: implied,
            maker_iriumd_address: base58_p2pkh_from_hash(&order.maker_iriumd_pkh),
            maker_btc_pkh_hex: hex::encode(order.maker_btc_pkh),
            confirmations_required: order.confirmations_required,
            expiry_height: order.expiry_height,
            locked_value: utxo.output.value,
            expected_hash_hex: order.expected_hash.map(hex::encode),
        }),
        status: status.to_string(),
    }))
}

async fn cancel_swap_order(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers_map: HeaderMap,
    AxumJson(req): AxumJson<CancelSwapOrderRequest>,
) -> Result<Json<SwapSpendResponse>, (StatusCode, String)> {
    let bad = |reason: &str| -> (StatusCode, String) {
        eprintln!("[cancel_swap_order] reject reason={}", reason);
        (StatusCode::BAD_REQUEST, reason.to_string())
    };

    check_rate_with_auth(&state, &addr, &headers_map)
        .map_err(|sc| (sc, "rate_limit_or_auth_failed".to_string()))?;
    require_rpc_auth(&headers_map).map_err(|sc| (sc, format!("rpc_auth_failed:{sc}")))?;

    {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let active = chain
            .params
            .swap_order_v1_activation_height
            .map(|h| chain.height >= h)
            .unwrap_or(false);
        if !active {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "swap_order_v1_not_active".to_string(),
            ));
        }
    }

    let txid_arr =
        hex_to_32(req.order_txid.trim()).map_err(|_| bad("order_txid_hex_invalid"))?;
    let key = OutPoint {
        txid: txid_arr,
        index: req.order_vout,
    };

    let (funding_out, tip_height) = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let utxo = chain
            .utxos
            .get(&key)
            .cloned()
            .ok_or_else(|| bad("order_outpoint_unspent_or_unknown"))?;
        (utxo, chain.tip_height())
    };

    let order = parse_swap_order_script(&funding_out.output.script_pubkey)
        .ok_or_else(|| bad("funding_output_not_swap_order"))?;
    if tip_height >= order.expiry_height {
        return Err(bad("order_already_expired_use_sweepexpiredorder"));
    }

    let signer_pkh = order.maker_iriumd_pkh;
    let wallet_key = {
        let mut wallet = state.wallet.lock().unwrap_or_else(|e| e.into_inner());
        let keys = wallet.keys().map_err(|_| bad("wallet_keys_unavailable"))?;
        let mut found: Option<WalletKey> = None;
        for k in keys {
            let b = hex::decode(&k.pkh).map_err(|_| bad("wallet_key_pkh_decode_failed"))?;
            if b.len() != 20 {
                continue;
            }
            let mut pkh = [0u8; 20];
            pkh.copy_from_slice(&b);
            if pkh == signer_pkh {
                found = Some(k);
                break;
            }
        }
        found.ok_or_else(|| bad("maker_iriumd_pkh_key_not_in_wallet"))?
    };

    let dest = base58_p2pkh_to_hash(&req.destination_address)
        .ok_or_else(|| bad("destination_address_decode_failed"))?;
    if dest.len() != 20 {
        return Err(bad("destination_pkh_len_invalid"));
    }
    let mut dest_pkh = [0u8; 20];
    dest_pkh.copy_from_slice(&dest);

    let fee_per_byte = req.fee_per_byte.unwrap_or(1).max(1);
    let mut fee = estimate_tx_size(1, 1).saturating_mul(fee_per_byte);
    if funding_out.output.value <= fee {
        return Err(bad("funding_value_le_fee"));
    }
    let mut payout = funding_out.output.value - fee;

    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid: txid_arr,
            prev_index: req.order_vout,
            script_sig: Vec::new(),
            sequence: 0xffff_fffe,
        }],
        outputs: vec![TxOutput {
            value: payout,
            script_pubkey: p2pkh_script(&dest_pkh),
        }],
        locktime: 0,
    };

    let scriptcode = encode_swap_order_script(&order);
    let priv_bytes =
        hex::decode(&wallet_key.privkey).map_err(|_| bad("privkey_decode_failed"))?;
    if priv_bytes.len() != 32 {
        return Err(bad("privkey_len_invalid"));
    }
    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(&priv_bytes);
    let signing_key = SigningKey::from_bytes((&sk_bytes).into())
        .map_err(|_| bad("signing_key_init_failed"))?;
    let pubkey = signing_key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();

    for _ in 0..2 {
        let digest = signature_digest(&tx, 0, &scriptcode);
        let sig: Signature = signing_key
            .sign_prehash(&digest)
            .map_err(|_| bad("sig_prehash_failed"))?;
        let sig = sig.normalize_s().unwrap_or(sig);
        let mut sig_bytes = sig.to_der().as_bytes().to_vec();
        sig_bytes.push(0x01);

        let witness = encode_swap_order_cancel_witness(&sig_bytes, &pubkey)
            .ok_or_else(|| bad("encode_cancel_witness_failed"))?;
        tx.inputs[0].script_sig = witness;

        let needed_fee = (tx.serialize().len() as u64).saturating_mul(fee_per_byte);
        if needed_fee > fee {
            let extra = needed_fee - fee;
            if payout > extra {
                fee = needed_fee;
                payout -= extra;
                tx.outputs[0].value = payout;
                continue;
            } else {
                return Err(bad("fee_recalculation_exceeded_payout"));
            }
        }
        break;
    }

    let fee_checked = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain
            .calculate_fees(&tx)
            .map_err(|_| bad("calculate_fees_failed"))?
    };
    let raw = tx.serialize();
    let txid_out = tx.txid();
    let mut accepted = false;
    if req.broadcast.unwrap_or(false) {
        let mut mempool = state.mempool.lock().unwrap_or_else(|e| e.into_inner());
        if !mempool.contains(&txid_out) {
            accepted = mempool
                .add_transaction(tx, raw.clone(), fee_checked)
                .is_ok();
        }
    }

    // Gap A (NAT broadcast): admitting to local mempool alone relies on
    // the 60s rebroadcast timer to reach peers, which delays order/fill
    // visibility up to a minute on NAT-bound nodes. Push the tx to all
    // currently-connected peers immediately so they see it the moment we
    // accept it. Best-effort; the rebroadcast timer still covers failures.
    if accepted {
        if let Some(ref p2p) = state.p2p {
            let p = p2p.clone();
            let r = raw.clone();
            tokio::spawn(async move {
                if let Err(e) = p.broadcast_tx(&r).await {
                    eprintln!("[swap-broadcast/cancel_swap_order] error: {e}");
                }
            });
        }
    }
    Ok(Json(SwapSpendResponse {
        txid: hex::encode(txid_out),
        accepted,
        raw_tx_hex: hex::encode(raw),
        fee: fee_checked,
    }))
}

async fn fill_swap_order(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers_map: HeaderMap,
    AxumJson(req): AxumJson<FillSwapOrderRequest>,
) -> Result<Json<FillSwapOrderResponse>, (StatusCode, String)> {
    let bad = |reason: &str| -> (StatusCode, String) {
        eprintln!("[fill_swap_order] reject reason={}", reason);
        (StatusCode::BAD_REQUEST, reason.to_string())
    };

    check_rate_with_auth(&state, &addr, &headers_map)
        .map_err(|sc| (sc, "rate_limit_or_auth_failed".to_string()))?;
    require_rpc_auth(&headers_map).map_err(|sc| (sc, format!("rpc_auth_failed:{sc}")))?;

    {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let active = chain
            .params
            .swap_order_v1_activation_height
            .map(|h| chain.height >= h)
            .unwrap_or(false);
        if !active {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "swap_order_v1_not_active".to_string(),
            ));
        }
    }

    let _ = req.taker_btc_address;

    let txid_arr =
        hex_to_32(req.order_txid.trim()).map_err(|_| bad("order_txid_hex_invalid"))?;
    let key = OutPoint {
        txid: txid_arr,
        index: req.order_vout,
    };

    let (funding_out, tip_height) = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let utxo = chain
            .utxos
            .get(&key)
            .cloned()
            .ok_or_else(|| bad("order_outpoint_unspent_or_unknown"))?;
        (utxo, chain.tip_height())
    };

    let order = parse_swap_order_script(&funding_out.output.script_pubkey)
        .ok_or_else(|| bad("funding_output_not_swap_order"))?;
    if tip_height > order.expiry_height {
        return Err(bad("order_expired"));
    }
    if req.timeout_blocks_from_now == 0 {
        return Err(bad("timeout_blocks_from_now_zero"));
    }
    let timeout_height = tip_height.saturating_add(req.timeout_blocks_from_now);

    let taker_iriumd_vec = base58_p2pkh_to_hash(&req.taker_iriumd_address)
        .ok_or_else(|| bad("taker_iriumd_address_decode_failed"))?;
    if taker_iriumd_vec.len() != 20 {
        return Err(bad("taker_iriumd_pkh_len_invalid"));
    }
    let mut taker_iriumd_pkh = [0u8; 20];
    taker_iriumd_pkh.copy_from_slice(&taker_iriumd_vec);

    let wallet_key = {
        let mut wallet = state.wallet.lock().unwrap_or_else(|e| e.into_inner());
        let keys = wallet.keys().map_err(|_| bad("wallet_keys_unavailable"))?;
        let mut found: Option<WalletKey> = None;
        for k in keys {
            let b = hex::decode(&k.pkh).map_err(|_| bad("wallet_key_pkh_decode_failed"))?;
            if b.len() != 20 {
                continue;
            }
            let mut pkh = [0u8; 20];
            pkh.copy_from_slice(&b);
            if pkh == taker_iriumd_pkh {
                found = Some(k);
                break;
            }
        }
        found.ok_or_else(|| bad("taker_iriumd_pkh_key_not_in_wallet"))?
    };

    let priv_bytes =
        hex::decode(&wallet_key.privkey).map_err(|_| bad("privkey_decode_failed"))?;
    if priv_bytes.len() != 32 {
        return Err(bad("privkey_len_invalid"));
    }
    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(&priv_bytes);
    let signing_key = SigningKey::from_bytes((&sk_bytes).into())
        .map_err(|_| bad("signing_key_init_failed"))?;
    let pubkey = signing_key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();

    // Build the spending tx's vout 0 — covenant-enforced by consensus.
    let covenant_output = match order.direction {
        SWAP_ORDER_DIRECTION_SELL => {
            // Sell-direction: consensus expects funding_binding =
            // compute_funding_binding(spending_tx.txid(), 0). Since the
            // binding lives inside vout 0's script, that constraint is
            // self-referential and not satisfiable by a single-shot wallet
            // construction. Best-effort: bind to the order outpoint so the
            // value is at least deterministic. Documented Part 3.5 follow-up.
            let funding_binding = compute_funding_binding(&txid_arr, req.order_vout);
            let swap = HtlcBtcSwapV1Output {
                confirmations_required: order.confirmations_required,
                recipient_pkh: taker_iriumd_pkh,
                refund_pkh: order.maker_iriumd_pkh,
                btc_recipient_pkh: order.maker_btc_pkh,
                btc_amount_sats: order.btc_amount_sats,
                timeout_height,
                funding_binding,
            };
            TxOutput {
                value: order.irm_amount,
                script_pubkey: encode_htlc_btc_swap_v1_script(&swap),
            }
        }
        SWAP_ORDER_DIRECTION_BUY => {
            let expected_hash = order
                .expected_hash
                .ok_or_else(|| bad("buy_order_missing_expected_hash"))?;
            let sha = Sha256::digest(&pubkey);
            let rip = ripemd::Ripemd160::digest(sha);
            let mut taker_refund_pkh = [0u8; 20];
            taker_refund_pkh.copy_from_slice(&rip);
            let htlc = HtlcV1Output {
                expected_hash,
                recipient_pkh: order.maker_iriumd_pkh,
                refund_pkh: taker_refund_pkh,
                timeout_height,
            };
            TxOutput {
                value: order.irm_amount,
                script_pubkey: encode_htlcv1_script(&htlc),
            }
        }
        _ => return Err(bad("order_direction_unknown")),
    };

    let fee_per_byte = req.fee_per_byte.unwrap_or(1).max(1);
    let mut fee = estimate_tx_size(1, 1).saturating_mul(fee_per_byte);
    if funding_out.output.value <= fee.saturating_add(order.irm_amount).saturating_sub(funding_out.output.value)
        && order.direction == SWAP_ORDER_DIRECTION_SELL
        && funding_out.output.value < order.irm_amount
    {
        return Err(bad("order_value_below_required_irm_amount"));
    }

    // Sell: order UTXO already holds irm_amount, no extra funding needed.
    // Buy: order UTXO holds anti-spam value only; taker must add wallet
    // inputs for irm_amount + fee. Both directions need fee coverage.
    let mut inputs: Vec<TxInput> = vec![TxInput {
        prev_txid: txid_arr,
        prev_index: req.order_vout,
        script_sig: Vec::new(),
        sequence: 0xffff_fffe,
    }];
    let mut outputs = vec![covenant_output];

    let mut extra_inputs: Vec<WalletUtxo> = Vec::new();
    let mut extra_total = 0u64;
    if order.direction == SWAP_ORDER_DIRECTION_BUY
        || funding_out.output.value < order.irm_amount.saturating_add(fee)
    {
        let needed = order
            .irm_amount
            .saturating_add(fee)
            .saturating_sub(funding_out.output.value);
        let mut wallet_utxos = {
            let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
            let mut collected = Vec::new();
            for (out, ut) in chain.utxos.iter() {
                if let Some(pkh) = p2pkh_hash_from_script(&ut.output.script_pubkey) {
                    if pkh == taker_iriumd_pkh {
                        collected.push(WalletUtxo {
                            outpoint: out.clone(),
                            output: ut.output.clone(),
                            height: ut.height,
                            is_coinbase: ut.is_coinbase,
                            pkh,
                        });
                    }
                }
            }
            collected
        };
        wallet_utxos.sort_by(|a, b| b.output.value.cmp(&a.output.value));
        for u in wallet_utxos.iter() {
            if u.is_coinbase
                && tip_height.saturating_sub(u.height) < coinbase_maturity()
            {
                continue;
            }
            extra_inputs.push(u.clone());
            extra_total = extra_total.saturating_add(u.output.value);
            inputs.push(TxInput {
                prev_txid: u.outpoint.txid,
                prev_index: u.outpoint.index,
                script_sig: Vec::new(),
                sequence: 0xffff_ffff,
            });
            if extra_total >= needed {
                break;
            }
        }
        if extra_total < needed {
            return Err(bad("insufficient_taker_funds_to_fill_order"));
        }
        let change = funding_out
            .output
            .value
            .saturating_add(extra_total)
            .saturating_sub(order.irm_amount)
            .saturating_sub(fee);
        if change > 0 {
            outputs.push(TxOutput {
                value: change,
                script_pubkey: p2pkh_script(&taker_iriumd_pkh),
            });
        }
    }

    let mut tx = Transaction {
        version: 1,
        inputs,
        outputs,
        locktime: 0,
    };

    let scriptcode_order = encode_swap_order_script(&order);

    // 2-pass fee recalc: estimate_tx_size(1,1) under-counts the order fill
    // witness (sig + pubkey + taker_pkh + timeout) and any extra P2PKH
    // wallet inputs. Without this loop a 1-input/1-output sell fill at
    // fee_per_byte=1 produces ~0.66 sat/B and mempool admission fails at
    // min_fee_per_byte=100.0. Same pattern as submit_btc_headers.
    for _ in 0..2 {
        let digest_order = signature_digest(&tx, 0, &scriptcode_order);
        let order_sig: Signature = signing_key
            .sign_prehash(&digest_order)
            .map_err(|_| bad("sig_prehash_failed"))?;
        let order_sig = order_sig.normalize_s().unwrap_or(order_sig);
        let mut order_sig_bytes = order_sig.to_der().as_bytes().to_vec();
        order_sig_bytes.push(0x01);

        let witness = match order.direction {
            SWAP_ORDER_DIRECTION_SELL => encode_swap_order_fill_sell_witness(
                &order_sig_bytes,
                &pubkey,
                &taker_iriumd_pkh,
                timeout_height,
            )
            .ok_or_else(|| bad("encode_fill_sell_witness_failed"))?,
            SWAP_ORDER_DIRECTION_BUY => encode_swap_order_fill_buy_witness(
                &order_sig_bytes,
                &pubkey,
                timeout_height,
            )
            .ok_or_else(|| bad("encode_fill_buy_witness_failed"))?,
            _ => return Err(bad("order_direction_unknown")),
        };
        tx.inputs[0].script_sig = witness;

        if !extra_inputs.is_empty() {
            let mut key_map: HashMap<[u8; 20], WalletKey> = HashMap::new();
            key_map.insert(taker_iriumd_pkh, wallet_key.clone());
            sign_wallet_inputs(&mut tx, &extra_inputs, &key_map)
                .map_err(|_| bad("sign_extra_inputs_failed"))?;
        }

        let needed_fee = (tx.serialize().len() as u64).saturating_mul(fee_per_byte);
        if needed_fee > fee {
            let extra = needed_fee - fee;
            // Reduce change (always the last output when there is one) to
            // absorb the shortfall. Covenant output 0 is fixed by spec; we
            // cannot touch it. If no change exists or change can't cover
            // the delta, reject — caller can retry with a higher
            // fee_per_byte or pre-funded inputs.
            if tx.outputs.len() > 1 {
                let change_idx = tx.outputs.len() - 1;
                if tx.outputs[change_idx].value > extra {
                    fee = needed_fee;
                    tx.outputs[change_idx].value -= extra;
                    continue;
                } else {
                    return Err(bad("fee_recalculation_exceeded_change"));
                }
            } else {
                return Err(bad("fee_recalculation_no_change_to_reduce"));
            }
        }
        break;
    }

    let fee_checked = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain
            .calculate_fees(&tx)
            .map_err(|_| bad("calculate_fees_failed"))?
    };
    let raw = tx.serialize();
    let txid_out = tx.txid();
    let mut accepted = false;
    if req.broadcast.unwrap_or(false) {
        let mut mempool = state.mempool.lock().unwrap_or_else(|e| e.into_inner());
        if !mempool.contains(&txid_out) {
            // sell_irm fill is the BTC-buyer covenant tx: ZeroFeeAllowed
            // so the taker (who has no IRM) can fill at zero fee. buy_irm
            // fillers DO have IRM (they're providing the IRM side) so
            // their fills remain Standard.
            let priority = if order.direction == SWAP_ORDER_DIRECTION_SELL {
                MempoolPriority::ZeroFeeAllowed
            } else {
                MempoolPriority::Standard
            };
            accepted = mempool
                .add_transaction_with_priority(
                    tx,
                    raw.clone(),
                    fee_checked,
                    priority,
                    Some(addr.ip()),
                )
                .is_ok();
        }
    }

    // Gap A (NAT broadcast): admitting to local mempool alone relies on
    // the 60s rebroadcast timer to reach peers, which delays order/fill
    // visibility up to a minute on NAT-bound nodes. Push the tx to all
    // currently-connected peers immediately so they see it the moment we
    // accept it. Best-effort; the rebroadcast timer still covers failures.
    if accepted {
        if let Some(ref p2p) = state.p2p {
            let p = p2p.clone();
            let r = raw.clone();
            tokio::spawn(async move {
                if let Err(e) = p.broadcast_tx(&r).await {
                    eprintln!("[swap-broadcast/fill_swap_order] error: {e}");
                }
            });
        }
    }

    Ok(Json(FillSwapOrderResponse {
        txid: hex::encode(txid_out),
        accepted,
        raw_tx_hex: hex::encode(raw),
        new_outpoint: OutPointJson {
            txid: hex::encode(txid_out),
            vout: 0,
        },
        direction: swap_direction_label(order.direction).to_string(),
        fee: fee_checked,
    }))
}

async fn sweep_expired_order(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers_map: HeaderMap,
    AxumJson(req): AxumJson<SweepExpiredOrderRequest>,
) -> Result<Json<SwapSpendResponse>, (StatusCode, String)> {
    let bad = |reason: &str| -> (StatusCode, String) {
        eprintln!("[sweep_expired_order] reject reason={}", reason);
        (StatusCode::BAD_REQUEST, reason.to_string())
    };

    check_rate_with_auth(&state, &addr, &headers_map)
        .map_err(|sc| (sc, "rate_limit_or_auth_failed".to_string()))?;
    require_rpc_auth(&headers_map).map_err(|sc| (sc, format!("rpc_auth_failed:{sc}")))?;

    {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let active = chain
            .params
            .swap_order_v1_activation_height
            .map(|h| chain.height >= h)
            .unwrap_or(false);
        if !active {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "swap_order_v1_not_active".to_string(),
            ));
        }
    }

    let txid_arr =
        hex_to_32(req.order_txid.trim()).map_err(|_| bad("order_txid_hex_invalid"))?;
    let key = OutPoint {
        txid: txid_arr,
        index: req.order_vout,
    };

    let (funding_out, tip_height) = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let utxo = chain
            .utxos
            .get(&key)
            .cloned()
            .ok_or_else(|| bad("order_outpoint_unspent_or_unknown"))?;
        (utxo, chain.tip_height())
    };

    let order = parse_swap_order_script(&funding_out.output.script_pubkey)
        .ok_or_else(|| bad("funding_output_not_swap_order"))?;
    if tip_height < order.expiry_height {
        return Err(bad("expiry_height_not_reached"));
    }

    let utxo_value = funding_out.output.value;
    let minimum_payout = utxo_value.saturating_sub(SWAP_ORDER_MAX_SWEEP_FEE);
    let fee_per_byte = req.fee_per_byte.unwrap_or(1).max(1);
    let est_fee = estimate_tx_size(1, 1).saturating_mul(fee_per_byte);
    let mut payout = if utxo_value >= est_fee.saturating_add(minimum_payout) {
        utxo_value - est_fee
    } else {
        minimum_payout
    };
    if payout < minimum_payout {
        return Err(bad("payout_below_consensus_minimum"));
    }

    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid: txid_arr,
            prev_index: req.order_vout,
            script_sig: encode_swap_order_expire_sweep_witness(),
            sequence: 0xffff_fffe,
        }],
        outputs: vec![TxOutput {
            value: payout,
            script_pubkey: p2pkh_script(&order.maker_iriumd_pkh),
        }],
        locktime: 0,
    };

    // Fee recalc against the actual serialized size. The 1-byte
    // expire-sweep witness is constant so a single pass suffices;
    // we only need to absorb the delta between estimate_tx_size(1,1)
    // and the real tx into the single payout output, subject to the
    // consensus minimum_payout floor.
    let needed_fee = (tx.serialize().len() as u64).saturating_mul(fee_per_byte);
    if needed_fee > est_fee {
        let extra = needed_fee - est_fee;
        if payout >= minimum_payout.saturating_add(extra) {
            payout -= extra;
            tx.outputs[0].value = payout;
        } else {
            return Err(bad("fee_recalculation_exceeded_payout_floor"));
        }
    }

    let fee_checked = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain
            .calculate_fees(&tx)
            .map_err(|_| bad("calculate_fees_failed"))?
    };
    let raw = tx.serialize();
    let txid_out = tx.txid();
    let mut accepted = false;
    if req.broadcast.unwrap_or(false) {
        let mut mempool = state.mempool.lock().unwrap_or_else(|e| e.into_inner());
        if !mempool.contains(&txid_out) {
            accepted = mempool
                .add_transaction(tx.clone(), raw.clone(), fee_checked)
                .is_ok();
        }
    }

    // Gap A (NAT broadcast): admitting to local mempool alone relies on
    // the 60s rebroadcast timer to reach peers, which delays order/fill
    // visibility up to a minute on NAT-bound nodes. Push the tx to all
    // currently-connected peers immediately so they see it the moment we
    // accept it. Best-effort; the rebroadcast timer still covers failures.
    if accepted {
        if let Some(ref p2p) = state.p2p {
            let p = p2p.clone();
            let r = raw.clone();
            tokio::spawn(async move {
                if let Err(e) = p.broadcast_tx(&r).await {
                    eprintln!("[swap-broadcast/sweep_expired_order] error: {e}");
                }
            });
        }
    }
    Ok(Json(SwapSpendResponse {
        txid: hex::encode(txid_out),
        accepted,
        raw_tx_hex: hex::encode(raw),
        fee: fee_checked,
    }))
}

async fn sweep_ltc_expired_order(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers_map: HeaderMap,
    AxumJson(req): AxumJson<SweepExpiredOrderRequest>,
) -> Result<Json<SwapSpendResponse>, (StatusCode, String)> {
    let bad = |reason: &str| -> (StatusCode, String) {
        eprintln!("[sweep_ltc_expired_order] reject reason={}", reason);
        (StatusCode::BAD_REQUEST, reason.to_string())
    };

    check_rate_with_auth(&state, &addr, &headers_map)
        .map_err(|sc| (sc, "rate_limit_or_auth_failed".to_string()))?;
    require_rpc_auth(&headers_map).map_err(|sc| (sc, format!("rpc_auth_failed:{sc}")))?;

    {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let active = chain
            .params
            .ltc_swap_order_v1_activation_height
            .map(|h| chain.height >= h)
            .unwrap_or(false);
        if !active {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "ltc_swap_order_v1_not_active".to_string(),
            ));
        }
    }

    let txid_arr =
        hex_to_32(req.order_txid.trim()).map_err(|_| bad("order_txid_hex_invalid"))?;
    let key = OutPoint {
        txid: txid_arr,
        index: req.order_vout,
    };

    let (funding_out, tip_height) = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let utxo = chain
            .utxos
            .get(&key)
            .cloned()
            .ok_or_else(|| bad("order_outpoint_unspent_or_unknown"))?;
        (utxo, chain.tip_height())
    };

    let order = parse_ltc_swap_order_script(&funding_out.output.script_pubkey)
        .ok_or_else(|| bad("funding_output_not_ltc_swap_order"))?;
    if tip_height < order.expiry_height {
        return Err(bad("expiry_height_not_reached"));
    }

    let utxo_value = funding_out.output.value;
    let minimum_payout = utxo_value.saturating_sub(LTC_SWAP_ORDER_MAX_SWEEP_FEE);
    let fee_per_byte = req.fee_per_byte.unwrap_or(1).max(1);
    let est_fee = estimate_tx_size(1, 1).saturating_mul(fee_per_byte);
    let mut payout = if utxo_value >= est_fee.saturating_add(minimum_payout) {
        utxo_value - est_fee
    } else {
        minimum_payout
    };
    if payout < minimum_payout {
        return Err(bad("payout_below_consensus_minimum"));
    }

    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid: txid_arr,
            prev_index: req.order_vout,
            script_sig: encode_ltc_swap_order_expire_sweep_witness(),
            sequence: 0xffff_fffe,
        }],
        outputs: vec![TxOutput {
            value: payout,
            script_pubkey: p2pkh_script(&order.maker_iriumd_pkh),
        }],
        locktime: 0,
    };

    // Fee recalc against the actual serialized size. The 1-byte
    // expire-sweep witness is constant so a single pass suffices.
    let needed_fee = (tx.serialize().len() as u64).saturating_mul(fee_per_byte);
    if needed_fee > est_fee {
        let extra = needed_fee - est_fee;
        if payout >= minimum_payout.saturating_add(extra) {
            payout -= extra;
            tx.outputs[0].value = payout;
        } else {
            return Err(bad("fee_recalculation_exceeded_payout_floor"));
        }
    }

    let fee_checked = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain
            .calculate_fees(&tx)
            .map_err(|_| bad("calculate_fees_failed"))?
    };
    let raw = tx.serialize();
    let txid_out = tx.txid();
    let mut accepted = false;
    if req.broadcast.unwrap_or(false) {
        let mut mempool = state.mempool.lock().unwrap_or_else(|e| e.into_inner());
        if !mempool.contains(&txid_out) {
            accepted = mempool
                .add_transaction(tx.clone(), raw.clone(), fee_checked)
                .is_ok();
        }
    }

    // Gap A (NAT broadcast): admitting to local mempool alone relies on
    // the 60s rebroadcast timer to reach peers, which delays order/fill
    // visibility up to a minute on NAT-bound nodes. Push the tx to all
    // currently-connected peers immediately so they see it the moment we
    // accept it. Best-effort; the rebroadcast timer still covers failures.
    if accepted {
        if let Some(ref p2p) = state.p2p {
            let p = p2p.clone();
            let r = raw.clone();
            tokio::spawn(async move {
                if let Err(e) = p.broadcast_tx(&r).await {
                    eprintln!("[swap-broadcast/sweep_ltc_expired_order] error: {e}");
                }
            });
        }
    }
    Ok(Json(SwapSpendResponse {
        txid: hex::encode(txid_out),
        accepted,
        raw_tx_hex: hex::encode(raw),
        fee: fee_checked,
    }))
}

// ---- Phase D — LtcSwapOrder RPC endpoints. Byte-level mirror of the
// BTC SwapOrder RPCs above, gated on `ltc_swap_order_v1_activation_height`.
// Sell-direction fills emit `HtlcLtcSwapV1` outputs (Phase C); buy-direction
// fills emit `HTLCv1` outputs identical to the BTC SwapOrder buy-fill since
// the IRM hashlock is chain-agnostic.

#[derive(Debug, Deserialize)]
struct PostLtcSwapOrderRequest {
    direction: String,
    irm_amount: String,
    ltc_amount_sats: u64,
    maker_iriumd_address: String,
    maker_ltc_address: String,
    confirmations_required: u8,
    expiry_blocks_from_now: u64,
    #[serde(default)]
    expected_hash_hex: Option<String>,
    #[serde(default)]
    fee_per_byte: Option<u64>,
    #[serde(default)]
    broadcast: Option<bool>,
}

#[derive(Debug, Serialize)]
struct PostLtcSwapOrderResponse {
    txid: String,
    accepted: bool,
    raw_tx_hex: String,
    order_outpoint: OutPointJson,
    order_id_hex: String,
    expiry_height: u64,
    fee: u64,
}

#[derive(Debug, Deserialize)]
struct ListLtcSwapOrdersQuery {
    #[serde(default)]
    direction: Option<String>,
    #[serde(default)]
    min_irm: Option<u64>,
    #[serde(default)]
    max_irm: Option<u64>,
    #[serde(default)]
    min_ltc: Option<u64>,
    #[serde(default)]
    max_ltc: Option<u64>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
    #[serde(default)]
    sort: Option<String>,
}

#[derive(Debug, Serialize)]
struct LtcSwapOrderJson {
    outpoint: OutPointJson,
    order_id_hex: String,
    direction: String,
    irm_amount: u64,
    ltc_amount_sats: u64,
    implied_ltc_per_irm_sats: f64,
    maker_iriumd_address: String,
    maker_ltc_pkh_hex: String,
    confirmations_required: u8,
    expiry_height: u64,
    locked_value: u64,
    expected_hash_hex: Option<String>,
}

#[derive(Debug, Serialize)]
struct ListLtcSwapOrdersResponse {
    orders: Vec<LtcSwapOrderJson>,
    total_open: usize,
}

#[derive(Debug, Deserialize)]
struct GetLtcSwapOrderQuery {
    txid: String,
    vout: u32,
}

#[derive(Debug, Serialize)]
struct GetLtcSwapOrderResponse {
    found: bool,
    order: Option<LtcSwapOrderJson>,
    status: String,
}

#[derive(Debug, Deserialize)]
struct CancelLtcSwapOrderRequest {
    order_txid: String,
    order_vout: u32,
    destination_address: String,
    #[serde(default)]
    fee_per_byte: Option<u64>,
    #[serde(default)]
    broadcast: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct FillLtcSwapOrderRequest {
    order_txid: String,
    order_vout: u32,
    taker_iriumd_address: String,
    #[serde(default)]
    taker_ltc_address: Option<String>,
    timeout_blocks_from_now: u64,
    #[serde(default)]
    fee_per_byte: Option<u64>,
    #[serde(default)]
    broadcast: Option<bool>,
}

#[derive(Debug, Serialize)]
struct FillLtcSwapOrderResponse {
    txid: String,
    accepted: bool,
    raw_tx_hex: String,
    new_outpoint: OutPointJson,
    direction: String,
    fee: u64,
}

fn compute_ltc_swap_order_id(o: &LtcSwapOrderOutput) -> [u8; 8] {
    let mut hasher = Sha256::new();
    hasher.update([o.direction, o.confirmations_required]);
    hasher.update(o.irm_amount.to_le_bytes());
    hasher.update(o.ltc_amount_sats.to_le_bytes());
    hasher.update(o.maker_iriumd_pkh);
    hasher.update(o.maker_ltc_pkh);
    hasher.update(o.expiry_height.to_le_bytes());
    if let Some(h) = &o.expected_hash {
        hasher.update(h);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

fn ltc_swap_direction_label(direction: u8) -> &'static str {
    match direction {
        LTC_SWAP_ORDER_DIRECTION_SELL => "sell_irm",
        LTC_SWAP_ORDER_DIRECTION_BUY => "buy_irm",
        _ => "unknown",
    }
}

fn parse_ltc_swap_direction(s: &str) -> Option<u8> {
    match s.trim().to_ascii_lowercase().as_str() {
        "sell_irm" | "sell" => Some(LTC_SWAP_ORDER_DIRECTION_SELL),
        "buy_irm" | "buy" => Some(LTC_SWAP_ORDER_DIRECTION_BUY),
        _ => None,
    }
}

async fn post_ltc_swap_order(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers_map: HeaderMap,
    AxumJson(req): AxumJson<PostLtcSwapOrderRequest>,
) -> Result<Json<PostLtcSwapOrderResponse>, (StatusCode, String)> {
    let bad = |reason: &str| -> (StatusCode, String) {
        eprintln!("[post_ltc_swap_order] reject reason={}", reason);
        (StatusCode::BAD_REQUEST, reason.to_string())
    };

    check_rate_with_auth(&state, &addr, &headers_map)
        .map_err(|sc| (sc, "rate_limit_or_auth_failed".to_string()))?;
    require_rpc_auth(&headers_map).map_err(|sc| (sc, format!("rpc_auth_failed:{sc}")))?;

    let tip_height_before = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let active = chain
            .params
            .ltc_swap_order_v1_activation_height
            .map(|h| chain.height >= h)
            .unwrap_or(false);
        if !active {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "ltc_swap_order_v1_not_active".to_string(),
            ));
        }
        chain.tip_height()
    };

    let direction =
        parse_ltc_swap_direction(&req.direction).ok_or_else(|| bad("direction_invalid"))?;
    let irm_amount = parse_irm(&req.irm_amount).map_err(|_| bad("irm_amount_parse_failed"))?;
    if irm_amount == 0 {
        return Err(bad("irm_amount_zero"));
    }
    if req.ltc_amount_sats == 0 {
        return Err(bad("ltc_amount_sats_zero"));
    }
    if req.confirmations_required < MIN_HTLC_LTC_SWAP_CONFIRMATIONS
        || req.confirmations_required > MAX_HTLC_LTC_SWAP_CONFIRMATIONS
    {
        return Err(bad("confirmations_required_out_of_range"));
    }
    if req.expiry_blocks_from_now == 0 {
        return Err(bad("expiry_blocks_from_now_zero"));
    }
    let expiry_height = tip_height_before.saturating_add(req.expiry_blocks_from_now);

    let maker_iriumd_vec = base58_p2pkh_to_hash(&req.maker_iriumd_address)
        .ok_or_else(|| bad("maker_iriumd_address_decode_failed"))?;
    if maker_iriumd_vec.len() != 20 {
        return Err(bad("maker_iriumd_pkh_len_invalid"));
    }
    let mut maker_iriumd_pkh = [0u8; 20];
    maker_iriumd_pkh.copy_from_slice(&maker_iriumd_vec);

    let maker_ltc_pkh = decode_ltc_address(&req.maker_ltc_address)
        .ok_or_else(|| bad("maker_ltc_address_must_be_p2pkh_or_bech32_p2wpkh"))?;

    let expected_hash = if direction == LTC_SWAP_ORDER_DIRECTION_BUY {
        let h_hex = req
            .expected_hash_hex
            .as_deref()
            .ok_or_else(|| bad("expected_hash_hex_required_for_buy_irm"))?;
        let bytes = hex::decode(h_hex.trim()).map_err(|_| bad("expected_hash_hex_invalid"))?;
        if bytes.len() != 32 {
            return Err(bad("expected_hash_len_invalid"));
        }
        let mut h = [0u8; 32];
        h.copy_from_slice(&bytes);
        Some(h)
    } else {
        None
    };

    let mut order = LtcSwapOrderOutput {
        direction,
        confirmations_required: req.confirmations_required,
        irm_amount,
        ltc_amount_sats: req.ltc_amount_sats,
        maker_iriumd_pkh,
        maker_ltc_pkh,
        expiry_height,
        order_id: [0u8; 8],
        expected_hash,
    };
    order.order_id = compute_ltc_swap_order_id(&order);

    let order_script = encode_ltc_swap_order_script(&order);
    let order_value = if direction == LTC_SWAP_ORDER_DIRECTION_SELL {
        irm_amount
    } else {
        LTC_SWAP_ORDER_MIN_LOCKED_VALUE
    };

    let mut key_map: HashMap<[u8; 20], WalletKey> = HashMap::new();
    {
        let mut wallet = state.wallet.lock().unwrap_or_else(|e| e.into_inner());
        let keys = wallet.keys().map_err(|_| bad("wallet_keys_unavailable"))?;
        for key in keys {
            let bytes = hex::decode(&key.pkh).map_err(|_| bad("wallet_key_pkh_decode_failed"))?;
            if bytes.len() != 20 {
                continue;
            }
            let mut arr = [0u8; 20];
            arr.copy_from_slice(&bytes);
            key_map.insert(arr, key);
        }
    }
    if key_map.is_empty() {
        return Err(bad("wallet_key_map_empty"));
    }

    let (mut utxos, tip_height) = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let mut collected = Vec::new();
        for (outpoint, utxo) in chain.utxos.iter() {
            if let Some(script_pkh) = p2pkh_hash_from_script(&utxo.output.script_pubkey) {
                if key_map.contains_key(&script_pkh) {
                    collected.push(WalletUtxo {
                        outpoint: outpoint.clone(),
                        output: utxo.output.clone(),
                        height: utxo.height,
                        is_coinbase: utxo.is_coinbase,
                        pkh: script_pkh,
                    });
                }
            }
        }
        (collected, chain.tip_height())
    };
    if utxos.is_empty() {
        return Err(bad("wallet_utxo_set_empty"));
    }
    utxos.sort_by(|a, b| b.output.value.cmp(&a.output.value));

    let mut fee_per_byte = req.fee_per_byte.unwrap_or(1).max(1);
    if fee_per_byte == 0 {
        fee_per_byte = 1;
    }

    let mut selected: Vec<WalletUtxo> = Vec::new();
    let mut total = 0u64;
    let mut fee = 0u64;
    for utxo in utxos.iter() {
        let confirmations = tip_height.saturating_sub(utxo.height);
        if utxo.is_coinbase && confirmations < coinbase_maturity() {
            continue;
        }
        selected.push(utxo.clone());
        total = total.saturating_add(utxo.output.value);
        let n_outs = if total > order_value { 2 } else { 1 };
        fee = estimate_tx_size(selected.len(), n_outs)
            .saturating_add(order_script.len() as u64)
            .saturating_mul(fee_per_byte);
        if total >= order_value.saturating_add(fee) {
            break;
        }
    }
    if total < order_value.saturating_add(fee) {
        return Err(bad("insufficient_spendable_funds"));
    }

    let inputs: Vec<TxInput> = selected
        .iter()
        .map(|u| TxInput {
            prev_txid: u.outpoint.txid,
            prev_index: u.outpoint.index,
            script_sig: Vec::new(),
            sequence: 0xffff_ffff,
        })
        .collect();

    let mut outputs = vec![TxOutput {
        value: order_value,
        script_pubkey: order_script,
    }];
    let mut change = total.saturating_sub(order_value).saturating_sub(fee);
    if change > 0 {
        let change_pkh = selected
            .first()
            .map(|u| u.pkh)
            .ok_or_else(|| bad("no_change_pkh"))?;
        outputs.push(TxOutput {
            value: change,
            script_pubkey: p2pkh_script(&change_pkh),
        });
    }

    let mut tx = Transaction {
        version: 1,
        inputs,
        outputs,
        locktime: 0,
    };

    for _ in 0..2 {
        sign_wallet_inputs(&mut tx, &selected, &key_map)
            .map_err(|_| bad("sign_wallet_inputs_failed"))?;
        let needed_fee = (tx.serialize().len() as u64).saturating_mul(fee_per_byte);
        if needed_fee > fee {
            let extra = needed_fee - fee;
            if change >= extra {
                fee = needed_fee;
                change = change.saturating_sub(extra);
                if tx.outputs.len() > 1 {
                    tx.outputs[1].value = change;
                }
                continue;
            } else {
                return Err(bad("fee_recalculation_exceeded_change"));
            }
        }
        break;
    }

    let fee_checked = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain
            .calculate_fees(&tx)
            .map_err(|_| bad("chain_fee_calculation_failed"))?
    };
    let raw = tx.serialize();
    let txid_arr = tx.txid();
    let txid_hex = hex::encode(txid_arr);
    let mut accepted = false;
    if req.broadcast.unwrap_or(false) {
        let mut mempool = state.mempool.lock().unwrap_or_else(|e| e.into_inner());
        if !mempool.contains(&txid_arr) {
            match mempool.add_transaction(tx.clone(), raw.clone(), fee_checked) {
                Ok(_) => accepted = true,
                Err(e) => eprintln!("[post_ltc_swap_order] mempool_reject reason={}", e),
            }
        }
    }

    // Gap A (NAT broadcast): admitting to local mempool alone relies on
    // the 60s rebroadcast timer to reach peers, which delays order/fill
    // visibility up to a minute on NAT-bound nodes. Push the tx to all
    // currently-connected peers immediately so they see it the moment we
    // accept it. Best-effort; the rebroadcast timer still covers failures.
    if accepted {
        if let Some(ref p2p) = state.p2p {
            let p = p2p.clone();
            let r = raw.clone();
            tokio::spawn(async move {
                if let Err(e) = p.broadcast_tx(&r).await {
                    eprintln!("[swap-broadcast/post_ltc_swap_order] error: {e}");
                }
            });
        }
    }

    Ok(Json(PostLtcSwapOrderResponse {
        txid: txid_hex.clone(),
        accepted,
        raw_tx_hex: hex::encode(raw),
        order_outpoint: OutPointJson {
            txid: txid_hex,
            vout: 0,
        },
        order_id_hex: hex::encode(order.order_id),
        expiry_height,
        fee: fee_checked,
    }))
}

async fn list_ltc_swap_orders(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers_map: HeaderMap,
    Query(q): Query<ListLtcSwapOrdersQuery>,
) -> Result<Json<ListLtcSwapOrdersResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers_map)?;
    require_rpc_auth(&headers_map)?;

    let direction_filter = match q.direction.as_deref() {
        None | Some("both") => None,
        Some(s) => match parse_ltc_swap_direction(s) {
            Some(d) => Some(d),
            None => return Err(StatusCode::BAD_REQUEST),
        },
    };
    let limit = q.limit.unwrap_or(100).min(1000);
    let offset = q.offset.unwrap_or(0);
    let sort = q.sort.as_deref().unwrap_or("recent");

    let mut all: Vec<LtcSwapOrderJson> = Vec::new();
    {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        for (outpoint, utxo) in chain.utxos.iter() {
            let order = match parse_ltc_swap_order_script(&utxo.output.script_pubkey) {
                Some(o) => o,
                None => continue,
            };
            if let Some(d) = direction_filter {
                if order.direction != d {
                    continue;
                }
            }
            if let Some(min) = q.min_irm {
                if order.irm_amount < min {
                    continue;
                }
            }
            if let Some(max) = q.max_irm {
                if order.irm_amount > max {
                    continue;
                }
            }
            if let Some(min) = q.min_ltc {
                if order.ltc_amount_sats < min {
                    continue;
                }
            }
            if let Some(max) = q.max_ltc {
                if order.ltc_amount_sats > max {
                    continue;
                }
            }
            let implied = if order.irm_amount > 0 {
                order.ltc_amount_sats as f64 / order.irm_amount as f64
            } else {
                0.0
            };
            all.push(LtcSwapOrderJson {
                outpoint: OutPointJson {
                    txid: hex::encode(outpoint.txid),
                    vout: outpoint.index,
                },
                order_id_hex: hex::encode(order.order_id),
                direction: ltc_swap_direction_label(order.direction).to_string(),
                irm_amount: order.irm_amount,
                ltc_amount_sats: order.ltc_amount_sats,
                implied_ltc_per_irm_sats: implied,
                maker_iriumd_address: base58_p2pkh_from_hash(&order.maker_iriumd_pkh),
                maker_ltc_pkh_hex: hex::encode(order.maker_ltc_pkh),
                confirmations_required: order.confirmations_required,
                expiry_height: order.expiry_height,
                locked_value: utxo.output.value,
                expected_hash_hex: order.expected_hash.map(hex::encode),
            });
        }
    }

    let total_open = all.len();
    match sort {
        "price_asc" => all.sort_by(|a, b| {
            a.implied_ltc_per_irm_sats
                .partial_cmp(&b.implied_ltc_per_irm_sats)
                .unwrap_or(std::cmp::Ordering::Equal)
        }),
        "price_desc" => all.sort_by(|a, b| {
            b.implied_ltc_per_irm_sats
                .partial_cmp(&a.implied_ltc_per_irm_sats)
                .unwrap_or(std::cmp::Ordering::Equal)
        }),
        _ => all.sort_by(|a, b| b.expiry_height.cmp(&a.expiry_height)),
    }

    let page: Vec<LtcSwapOrderJson> = all.into_iter().skip(offset).take(limit).collect();
    Ok(Json(ListLtcSwapOrdersResponse {
        orders: page,
        total_open,
    }))
}

async fn get_ltc_swap_order(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers_map: HeaderMap,
    Query(q): Query<GetLtcSwapOrderQuery>,
) -> Result<Json<GetLtcSwapOrderResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers_map)?;
    require_rpc_auth(&headers_map)?;

    let txid = hex_to_32(q.txid.trim()).map_err(|_| StatusCode::BAD_REQUEST)?;
    let key = OutPoint {
        txid,
        index: q.vout,
    };

    let (tip_height, maybe_utxo) = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        (chain.tip_height(), chain.utxos.get(&key).cloned())
    };

    let Some(utxo) = maybe_utxo else {
        return Ok(Json(GetLtcSwapOrderResponse {
            found: false,
            order: None,
            status: "closed".to_string(),
        }));
    };

    let order = match parse_ltc_swap_order_script(&utxo.output.script_pubkey) {
        Some(o) => o,
        None => {
            return Ok(Json(GetLtcSwapOrderResponse {
                found: false,
                order: None,
                status: "not_a_ltc_swap_order".to_string(),
            }));
        }
    };

    let implied = if order.irm_amount > 0 {
        order.ltc_amount_sats as f64 / order.irm_amount as f64
    } else {
        0.0
    };
    let status = if tip_height >= order.expiry_height {
        "expired"
    } else {
        "open"
    };
    Ok(Json(GetLtcSwapOrderResponse {
        found: true,
        order: Some(LtcSwapOrderJson {
            outpoint: OutPointJson {
                txid: hex::encode(key.txid),
                vout: key.index,
            },
            order_id_hex: hex::encode(order.order_id),
            direction: ltc_swap_direction_label(order.direction).to_string(),
            irm_amount: order.irm_amount,
            ltc_amount_sats: order.ltc_amount_sats,
            implied_ltc_per_irm_sats: implied,
            maker_iriumd_address: base58_p2pkh_from_hash(&order.maker_iriumd_pkh),
            maker_ltc_pkh_hex: hex::encode(order.maker_ltc_pkh),
            confirmations_required: order.confirmations_required,
            expiry_height: order.expiry_height,
            locked_value: utxo.output.value,
            expected_hash_hex: order.expected_hash.map(hex::encode),
        }),
        status: status.to_string(),
    }))
}

async fn cancel_ltc_swap_order(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers_map: HeaderMap,
    AxumJson(req): AxumJson<CancelLtcSwapOrderRequest>,
) -> Result<Json<SwapSpendResponse>, (StatusCode, String)> {
    let bad = |reason: &str| -> (StatusCode, String) {
        eprintln!("[cancel_ltc_swap_order] reject reason={}", reason);
        (StatusCode::BAD_REQUEST, reason.to_string())
    };

    check_rate_with_auth(&state, &addr, &headers_map)
        .map_err(|sc| (sc, "rate_limit_or_auth_failed".to_string()))?;
    require_rpc_auth(&headers_map).map_err(|sc| (sc, format!("rpc_auth_failed:{sc}")))?;

    {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let active = chain
            .params
            .ltc_swap_order_v1_activation_height
            .map(|h| chain.height >= h)
            .unwrap_or(false);
        if !active {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "ltc_swap_order_v1_not_active".to_string(),
            ));
        }
    }

    let txid_arr =
        hex_to_32(req.order_txid.trim()).map_err(|_| bad("order_txid_hex_invalid"))?;
    let key = OutPoint {
        txid: txid_arr,
        index: req.order_vout,
    };

    let (funding_out, tip_height) = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let utxo = chain
            .utxos
            .get(&key)
            .cloned()
            .ok_or_else(|| bad("order_outpoint_unspent_or_unknown"))?;
        (utxo, chain.tip_height())
    };

    let order = parse_ltc_swap_order_script(&funding_out.output.script_pubkey)
        .ok_or_else(|| bad("funding_output_not_ltc_swap_order"))?;
    if tip_height >= order.expiry_height {
        return Err(bad("order_already_expired"));
    }

    let signer_pkh = order.maker_iriumd_pkh;
    let wallet_key = {
        let mut wallet = state.wallet.lock().unwrap_or_else(|e| e.into_inner());
        let keys = wallet.keys().map_err(|_| bad("wallet_keys_unavailable"))?;
        let mut found: Option<WalletKey> = None;
        for k in keys {
            let b = hex::decode(&k.pkh).map_err(|_| bad("wallet_key_pkh_decode_failed"))?;
            if b.len() != 20 {
                continue;
            }
            let mut pkh = [0u8; 20];
            pkh.copy_from_slice(&b);
            if pkh == signer_pkh {
                found = Some(k);
                break;
            }
        }
        found.ok_or_else(|| bad("maker_iriumd_pkh_key_not_in_wallet"))?
    };

    let dest = base58_p2pkh_to_hash(&req.destination_address)
        .ok_or_else(|| bad("destination_address_decode_failed"))?;
    if dest.len() != 20 {
        return Err(bad("destination_pkh_len_invalid"));
    }
    let mut dest_pkh = [0u8; 20];
    dest_pkh.copy_from_slice(&dest);

    let fee_per_byte = req.fee_per_byte.unwrap_or(1).max(1);
    let mut fee = estimate_tx_size(1, 1).saturating_mul(fee_per_byte);
    if funding_out.output.value <= fee {
        return Err(bad("funding_value_le_fee"));
    }
    let mut payout = funding_out.output.value - fee;

    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid: txid_arr,
            prev_index: req.order_vout,
            script_sig: Vec::new(),
            sequence: 0xffff_fffe,
        }],
        outputs: vec![TxOutput {
            value: payout,
            script_pubkey: p2pkh_script(&dest_pkh),
        }],
        locktime: 0,
    };

    let scriptcode = encode_ltc_swap_order_script(&order);
    let priv_bytes =
        hex::decode(&wallet_key.privkey).map_err(|_| bad("privkey_decode_failed"))?;
    if priv_bytes.len() != 32 {
        return Err(bad("privkey_len_invalid"));
    }
    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(&priv_bytes);
    let signing_key = SigningKey::from_bytes((&sk_bytes).into())
        .map_err(|_| bad("signing_key_init_failed"))?;
    let pubkey = signing_key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();

    for _ in 0..2 {
        let digest = signature_digest(&tx, 0, &scriptcode);
        let sig: Signature = signing_key
            .sign_prehash(&digest)
            .map_err(|_| bad("sig_prehash_failed"))?;
        let sig = sig.normalize_s().unwrap_or(sig);
        let mut sig_bytes = sig.to_der().as_bytes().to_vec();
        sig_bytes.push(0x01);

        let witness = encode_ltc_swap_order_cancel_witness(&sig_bytes, &pubkey)
            .ok_or_else(|| bad("encode_cancel_witness_failed"))?;
        tx.inputs[0].script_sig = witness;

        let needed_fee = (tx.serialize().len() as u64).saturating_mul(fee_per_byte);
        if needed_fee > fee {
            let extra = needed_fee - fee;
            if payout > extra {
                fee = needed_fee;
                payout -= extra;
                tx.outputs[0].value = payout;
                continue;
            } else {
                return Err(bad("fee_recalculation_exceeded_payout"));
            }
        }
        break;
    }

    let fee_checked = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain
            .calculate_fees(&tx)
            .map_err(|_| bad("calculate_fees_failed"))?
    };
    let raw = tx.serialize();
    let txid_out = tx.txid();
    let mut accepted = false;
    if req.broadcast.unwrap_or(false) {
        let mut mempool = state.mempool.lock().unwrap_or_else(|e| e.into_inner());
        if !mempool.contains(&txid_out) {
            accepted = mempool
                .add_transaction(tx, raw.clone(), fee_checked)
                .is_ok();
        }
    }

    // Gap A (NAT broadcast): admitting to local mempool alone relies on
    // the 60s rebroadcast timer to reach peers, which delays order/fill
    // visibility up to a minute on NAT-bound nodes. Push the tx to all
    // currently-connected peers immediately so they see it the moment we
    // accept it. Best-effort; the rebroadcast timer still covers failures.
    if accepted {
        if let Some(ref p2p) = state.p2p {
            let p = p2p.clone();
            let r = raw.clone();
            tokio::spawn(async move {
                if let Err(e) = p.broadcast_tx(&r).await {
                    eprintln!("[swap-broadcast/cancel_ltc_swap_order] error: {e}");
                }
            });
        }
    }
    Ok(Json(SwapSpendResponse {
        txid: hex::encode(txid_out),
        accepted,
        raw_tx_hex: hex::encode(raw),
        fee: fee_checked,
    }))
}

async fn fill_ltc_swap_order(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers_map: HeaderMap,
    AxumJson(req): AxumJson<FillLtcSwapOrderRequest>,
) -> Result<Json<FillLtcSwapOrderResponse>, (StatusCode, String)> {
    let bad = |reason: &str| -> (StatusCode, String) {
        eprintln!("[fill_ltc_swap_order] reject reason={}", reason);
        (StatusCode::BAD_REQUEST, reason.to_string())
    };

    check_rate_with_auth(&state, &addr, &headers_map)
        .map_err(|sc| (sc, "rate_limit_or_auth_failed".to_string()))?;
    require_rpc_auth(&headers_map).map_err(|sc| (sc, format!("rpc_auth_failed:{sc}")))?;

    {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let active = chain
            .params
            .ltc_swap_order_v1_activation_height
            .map(|h| chain.height >= h)
            .unwrap_or(false);
        if !active {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "ltc_swap_order_v1_not_active".to_string(),
            ));
        }
    }

    let _ = req.taker_ltc_address;

    let txid_arr =
        hex_to_32(req.order_txid.trim()).map_err(|_| bad("order_txid_hex_invalid"))?;
    let key = OutPoint {
        txid: txid_arr,
        index: req.order_vout,
    };

    let (funding_out, tip_height) = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let utxo = chain
            .utxos
            .get(&key)
            .cloned()
            .ok_or_else(|| bad("order_outpoint_unspent_or_unknown"))?;
        (utxo, chain.tip_height())
    };

    let order = parse_ltc_swap_order_script(&funding_out.output.script_pubkey)
        .ok_or_else(|| bad("funding_output_not_ltc_swap_order"))?;
    if tip_height > order.expiry_height {
        return Err(bad("order_expired"));
    }
    if req.timeout_blocks_from_now == 0 {
        return Err(bad("timeout_blocks_from_now_zero"));
    }
    let timeout_height = tip_height.saturating_add(req.timeout_blocks_from_now);

    let taker_iriumd_vec = base58_p2pkh_to_hash(&req.taker_iriumd_address)
        .ok_or_else(|| bad("taker_iriumd_address_decode_failed"))?;
    if taker_iriumd_vec.len() != 20 {
        return Err(bad("taker_iriumd_pkh_len_invalid"));
    }
    let mut taker_iriumd_pkh = [0u8; 20];
    taker_iriumd_pkh.copy_from_slice(&taker_iriumd_vec);

    let wallet_key = {
        let mut wallet = state.wallet.lock().unwrap_or_else(|e| e.into_inner());
        let keys = wallet.keys().map_err(|_| bad("wallet_keys_unavailable"))?;
        let mut found: Option<WalletKey> = None;
        for k in keys {
            let b = hex::decode(&k.pkh).map_err(|_| bad("wallet_key_pkh_decode_failed"))?;
            if b.len() != 20 {
                continue;
            }
            let mut pkh = [0u8; 20];
            pkh.copy_from_slice(&b);
            if pkh == taker_iriumd_pkh {
                found = Some(k);
                break;
            }
        }
        found.ok_or_else(|| bad("taker_iriumd_pkh_key_not_in_wallet"))?
    };

    let priv_bytes =
        hex::decode(&wallet_key.privkey).map_err(|_| bad("privkey_decode_failed"))?;
    if priv_bytes.len() != 32 {
        return Err(bad("privkey_len_invalid"));
    }
    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(&priv_bytes);
    let signing_key = SigningKey::from_bytes((&sk_bytes).into())
        .map_err(|_| bad("signing_key_init_failed"))?;
    let pubkey = signing_key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();

    let covenant_output = match order.direction {
        LTC_SWAP_ORDER_DIRECTION_SELL => {
            let funding_binding = compute_funding_binding(&txid_arr, req.order_vout);
            let swap = HtlcLtcSwapV1Output {
                confirmations_required: order.confirmations_required,
                recipient_pkh: taker_iriumd_pkh,
                refund_pkh: order.maker_iriumd_pkh,
                ltc_recipient_pkh: order.maker_ltc_pkh,
                ltc_amount_sats: order.ltc_amount_sats,
                timeout_height,
                funding_binding,
            };
            TxOutput {
                value: order.irm_amount,
                script_pubkey: encode_htlc_ltc_swap_v1_script(&swap),
            }
        }
        LTC_SWAP_ORDER_DIRECTION_BUY => {
            let expected_hash = order
                .expected_hash
                .ok_or_else(|| bad("buy_order_missing_expected_hash"))?;
            let sha = Sha256::digest(&pubkey);
            let rip = ripemd::Ripemd160::digest(sha);
            let mut taker_refund_pkh = [0u8; 20];
            taker_refund_pkh.copy_from_slice(&rip);
            let htlc = HtlcV1Output {
                expected_hash,
                recipient_pkh: order.maker_iriumd_pkh,
                refund_pkh: taker_refund_pkh,
                timeout_height,
            };
            TxOutput {
                value: order.irm_amount,
                script_pubkey: encode_htlcv1_script(&htlc),
            }
        }
        _ => return Err(bad("order_direction_unknown")),
    };

    let fee_per_byte = req.fee_per_byte.unwrap_or(1).max(1);
    let mut fee = estimate_tx_size(1, 1).saturating_mul(fee_per_byte);
    if order.direction == LTC_SWAP_ORDER_DIRECTION_SELL
        && funding_out.output.value < order.irm_amount
    {
        return Err(bad("order_value_below_required_irm_amount"));
    }

    let mut inputs: Vec<TxInput> = vec![TxInput {
        prev_txid: txid_arr,
        prev_index: req.order_vout,
        script_sig: Vec::new(),
        sequence: 0xffff_fffe,
    }];
    let mut outputs = vec![covenant_output];

    let mut extra_inputs: Vec<WalletUtxo> = Vec::new();
    let mut extra_total = 0u64;
    if order.direction == LTC_SWAP_ORDER_DIRECTION_BUY
        || funding_out.output.value < order.irm_amount.saturating_add(fee)
    {
        let needed = order
            .irm_amount
            .saturating_add(fee)
            .saturating_sub(funding_out.output.value);
        let mut wallet_utxos = {
            let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
            let mut collected = Vec::new();
            for (out, ut) in chain.utxos.iter() {
                if let Some(pkh) = p2pkh_hash_from_script(&ut.output.script_pubkey) {
                    if pkh == taker_iriumd_pkh {
                        collected.push(WalletUtxo {
                            outpoint: out.clone(),
                            output: ut.output.clone(),
                            height: ut.height,
                            is_coinbase: ut.is_coinbase,
                            pkh,
                        });
                    }
                }
            }
            collected
        };
        wallet_utxos.sort_by(|a, b| b.output.value.cmp(&a.output.value));
        for u in wallet_utxos.iter() {
            if u.is_coinbase
                && tip_height.saturating_sub(u.height) < coinbase_maturity()
            {
                continue;
            }
            extra_inputs.push(u.clone());
            extra_total = extra_total.saturating_add(u.output.value);
            inputs.push(TxInput {
                prev_txid: u.outpoint.txid,
                prev_index: u.outpoint.index,
                script_sig: Vec::new(),
                sequence: 0xffff_ffff,
            });
            if extra_total >= needed {
                break;
            }
        }
        if extra_total < needed {
            return Err(bad("insufficient_taker_funds_to_fill_order"));
        }
        let change = funding_out
            .output
            .value
            .saturating_add(extra_total)
            .saturating_sub(order.irm_amount)
            .saturating_sub(fee);
        if change > 0 {
            outputs.push(TxOutput {
                value: change,
                script_pubkey: p2pkh_script(&taker_iriumd_pkh),
            });
        }
    }

    let mut tx = Transaction {
        version: 1,
        inputs,
        outputs,
        locktime: 0,
    };

    let scriptcode_order = encode_ltc_swap_order_script(&order);

    // 2-pass fee recalc: estimate_tx_size(1,1) under-counts the order
    // fill witness (sig + pubkey + taker_pkh + timeout) and any extra
    // P2PKH wallet inputs. Without this loop a 1-input/1-output sell
    // fill at fee_per_byte=1 produces ~0.66 sat/B and mempool admission
    // fails at min_fee_per_byte=100.0. Same pattern as fill_swap_order
    // fix in 1d9519f.
    for _ in 0..2 {
        let digest_order = signature_digest(&tx, 0, &scriptcode_order);
        let order_sig: Signature = signing_key
            .sign_prehash(&digest_order)
            .map_err(|_| bad("sig_prehash_failed"))?;
        let order_sig = order_sig.normalize_s().unwrap_or(order_sig);
        let mut order_sig_bytes = order_sig.to_der().as_bytes().to_vec();
        order_sig_bytes.push(0x01);

        let witness = match order.direction {
            LTC_SWAP_ORDER_DIRECTION_SELL => encode_ltc_swap_order_fill_sell_witness(
                &order_sig_bytes,
                &pubkey,
                &taker_iriumd_pkh,
                timeout_height,
            )
            .ok_or_else(|| bad("encode_fill_sell_witness_failed"))?,
            LTC_SWAP_ORDER_DIRECTION_BUY => encode_ltc_swap_order_fill_buy_witness(
                &order_sig_bytes,
                &pubkey,
                timeout_height,
            )
            .ok_or_else(|| bad("encode_fill_buy_witness_failed"))?,
            _ => return Err(bad("order_direction_unknown")),
        };
        tx.inputs[0].script_sig = witness;

        if !extra_inputs.is_empty() {
            let mut key_map: HashMap<[u8; 20], WalletKey> = HashMap::new();
            key_map.insert(taker_iriumd_pkh, wallet_key.clone());
            sign_wallet_inputs(&mut tx, &extra_inputs, &key_map)
                .map_err(|_| bad("sign_extra_inputs_failed"))?;
        }

        let needed_fee = (tx.serialize().len() as u64).saturating_mul(fee_per_byte);
        if needed_fee > fee {
            let extra = needed_fee - fee;
            // Reduce change (always the last output when there is one) to
            // absorb the shortfall. Covenant output 0 is fixed by spec; we
            // cannot touch it. If no change exists or change can't cover
            // the delta, reject \xe2\x80\x94 caller can retry with a higher
            // fee_per_byte or pre-funded inputs.
            if tx.outputs.len() > 1 {
                let change_idx = tx.outputs.len() - 1;
                if tx.outputs[change_idx].value > extra {
                    fee = needed_fee;
                    tx.outputs[change_idx].value -= extra;
                    continue;
                } else {
                    return Err(bad("fee_recalculation_exceeded_change"));
                }
            } else {
                return Err(bad("fee_recalculation_no_change_to_reduce"));
            }
        }
        break;
    }

    let fee_checked = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain
            .calculate_fees(&tx)
            .map_err(|_| bad("calculate_fees_failed"))?
    };
    let raw = tx.serialize();
    let txid_out = tx.txid();
    let mut accepted = false;
    if req.broadcast.unwrap_or(false) {
        let mut mempool = state.mempool.lock().unwrap_or_else(|e| e.into_inner());
        if !mempool.contains(&txid_out) {
            accepted = mempool
                .add_transaction(tx, raw.clone(), fee_checked)
                .is_ok();
        }
    }

    // Gap A (NAT broadcast): admitting to local mempool alone relies on
    // the 60s rebroadcast timer to reach peers, which delays order/fill
    // visibility up to a minute on NAT-bound nodes. Push the tx to all
    // currently-connected peers immediately so they see it the moment we
    // accept it. Best-effort; the rebroadcast timer still covers failures.
    if accepted {
        if let Some(ref p2p) = state.p2p {
            let p = p2p.clone();
            let r = raw.clone();
            tokio::spawn(async move {
                if let Err(e) = p.broadcast_tx(&r).await {
                    eprintln!("[swap-broadcast/fill_ltc_swap_order] error: {e}");
                }
            });
        }
    }

    Ok(Json(FillLtcSwapOrderResponse {
        txid: hex::encode(txid_out),
        accepted,
        raw_tx_hex: hex::encode(raw),
        new_outpoint: OutPointJson {
            txid: hex::encode(txid_out),
            vout: 0,
        },
        direction: ltc_swap_direction_label(order.direction).to_string(),
        fee: fee_checked,
    }))
}


async fn create_htlc(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<CreateHtlcRequest>,
) -> Result<Json<CreateHtlcResponse>, (StatusCode, String)> {
    let bad = |reason: &str| -> (StatusCode, String) {
        eprintln!("[create_htlc] reject reason={}", reason);
        (StatusCode::BAD_REQUEST, reason.to_string())
    };

    check_rate_with_auth(&state, &addr, &headers)
        .map_err(|sc| (sc, "rate_limit_or_auth_failed".to_string()))?;
    require_rpc_auth(&headers).map_err(|sc| (sc, format!("rpc_auth_failed:{sc}")))?;
    {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let active = chain
            .params
            .htlcv1_activation_height
            .map(|h| chain.height >= h)
            .unwrap_or(false);
        if !active {
            return Err(bad("htlcv1_not_active_at_current_height"));
        }
    }

    let amount = parse_irm(&req.amount).map_err(|_| bad("amount_parse_failed"))?;
    if amount == 0 {
        return Err(bad("amount_zero"));
    }

    let recipient_vec = base58_p2pkh_to_hash(&req.recipient_address)
        .ok_or_else(|| bad("recipient_address_decode_failed"))?;
    let refund_vec = base58_p2pkh_to_hash(&req.refund_address)
        .ok_or_else(|| bad("refund_address_decode_failed"))?;
    if recipient_vec.len() != 20 || refund_vec.len() != 20 {
        return Err(bad("address_hash_len_invalid"));
    }
    let mut recipient_pkh = [0u8; 20];
    recipient_pkh.copy_from_slice(&recipient_vec);
    let mut refund_pkh = [0u8; 20];
    refund_pkh.copy_from_slice(&refund_vec);

    let hash_bytes = hex::decode(req.secret_hash_hex.trim())
        .map_err(|_| bad("secret_hash_hex_decode_failed"))?;
    if hash_bytes.len() != 32 {
        return Err(bad("secret_hash_len_invalid"));
    }
    let mut expected_hash = [0u8; 32];
    expected_hash.copy_from_slice(&hash_bytes);

    let mut key_map: HashMap<[u8; 20], WalletKey> = HashMap::new();
    {
        let mut wallet = state.wallet.lock().unwrap_or_else(|e| e.into_inner());
        let keys = wallet.keys().map_err(|_| bad("wallet_keys_unavailable"))?;
        for key in keys {
            let bytes = hex::decode(&key.pkh).map_err(|_| bad("wallet_key_pkh_decode_failed"))?;
            if bytes.len() != 20 {
                continue;
            }
            let mut arr = [0u8; 20];
            arr.copy_from_slice(&bytes);
            key_map.insert(arr, key);
        }
    }
    if key_map.is_empty() {
        return Err(bad("wallet_key_map_empty"));
    }

    let (mut utxos, tip_height) = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let mut collected = Vec::new();
        for (outpoint, utxo) in chain.utxos.iter() {
            if let Some(script_pkh) = p2pkh_hash_from_script(&utxo.output.script_pubkey) {
                if key_map.contains_key(&script_pkh) {
                    collected.push(WalletUtxo {
                        outpoint: outpoint.clone(),
                        output: utxo.output.clone(),
                        height: utxo.height,
                        is_coinbase: utxo.is_coinbase,
                        pkh: script_pkh,
                    });
                }
            }
        }
        (collected, chain.tip_height())
    };

    if utxos.is_empty() {
        return Err(bad("wallet_utxo_set_empty"));
    }

    utxos.sort_by(|a, b| b.output.value.cmp(&a.output.value));

    let mut fee_per_byte = req.fee_per_byte.unwrap_or(1).max(1);
    if fee_per_byte == 0 {
        fee_per_byte = 1;
    }

    let mut selected: Vec<WalletUtxo> = Vec::new();
    let mut total = 0u64;
    let mut fee = 0u64;
    for utxo in utxos.iter() {
        let confirmations = tip_height.saturating_sub(utxo.height);
        if utxo.is_coinbase && confirmations < coinbase_maturity() {
            continue;
        }
        selected.push(utxo.clone());
        total = total.saturating_add(utxo.output.value);
        let outputs = if total > amount { 2 } else { 1 };
        fee = estimate_tx_size(selected.len(), outputs).saturating_mul(fee_per_byte);
        if total >= amount.saturating_add(fee) {
            break;
        }
    }

    if total < amount.saturating_add(fee) {
        return Err(bad("insufficient_spendable_funds_or_immature_coinbase"));
    }

    let htlc = HtlcV1Output {
        expected_hash,
        recipient_pkh,
        refund_pkh,
        timeout_height: req.timeout_height,
    };

    let inputs: Vec<TxInput> = selected
        .iter()
        .map(|u| TxInput {
            prev_txid: u.outpoint.txid,
            prev_index: u.outpoint.index,
            script_sig: Vec::new(),
            sequence: 0xffff_ffff,
        })
        .collect();

    let mut outputs = vec![TxOutput {
        value: amount,
        script_pubkey: encode_htlcv1_script(&htlc),
    }];

    let mut change = total.saturating_sub(amount).saturating_sub(fee);
    if change > 0 {
        let change_pkh = selected
            .first()
            .map(|u| u.pkh)
            .ok_or_else(|| bad("change_output_missing_selected_input"))?;
        outputs.push(TxOutput {
            value: change,
            script_pubkey: p2pkh_script(&change_pkh),
        });
    }

    let mut tx = Transaction {
        version: 1,
        inputs,
        outputs,
        locktime: 0,
    };

    for _ in 0..2 {
        sign_wallet_inputs(&mut tx, &selected, &key_map)
            .map_err(|_| bad("sign_wallet_inputs_failed"))?;
        let needed_fee = (tx.serialize().len() as u64).saturating_mul(fee_per_byte);
        if needed_fee > fee {
            let extra = needed_fee - fee;
            if change >= extra {
                fee = needed_fee;
                change = change.saturating_sub(extra);
                if tx.outputs.len() > 1 {
                    tx.outputs[1].value = change;
                }
                continue;
            } else {
                return Err(bad("fee_recalculation_exceeded_change"));
            }
        }
        break;
    }

    let fee_checked = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain
            .calculate_fees(&tx)
            .map_err(|_| bad("chain_fee_calculation_failed"))?
    };

    let raw = tx.serialize();
    let txid = tx.txid();
    let txid_hex = hex::encode(txid);
    let mut accepted = false;

    if req.broadcast.unwrap_or(false) {
        let mut mempool = state.mempool.lock().unwrap_or_else(|e| e.into_inner());
        if !mempool.contains(&txid) {
            match mempool.add_transaction(tx.clone(), raw.clone(), fee_checked) {
                Ok(_) => accepted = true,
                Err(e) => {
                    eprintln!("[create_htlc] mempool_reject reason={}", e);
                    accepted = false;
                }
            }
        }
    }

    Ok(Json(CreateHtlcResponse {
        txid: txid_hex,
        accepted,
        raw_tx_hex: hex::encode(raw),
        htlc_vout: 0,
        expected_hash: hex::encode(expected_hash),
        timeout_height: req.timeout_height,
        recipient_address: req.recipient_address,
        refund_address: req.refund_address,
    }))
}

async fn decode_htlc(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<DecodeHtlcRequest>,
) -> Result<Json<DecodeHtlcResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    require_rpc_auth(&headers)?;

    let raw = hex::decode(req.raw_tx_hex.trim()).map_err(|_| StatusCode::BAD_REQUEST)?;
    let tx = decode_full_tx(&raw).map_err(|_| StatusCode::BAD_REQUEST)?;

    if tx.outputs.is_empty() {
        return Ok(Json(DecodeHtlcResponse {
            found: false,
            vout: None,
            output_type: "none".to_string(),
            expected_hash: None,
            timeout_height: None,
            recipient_address: None,
            refund_address: None,
        }));
    }

    let idx = req.vout.unwrap_or(0) as usize;
    if idx >= tx.outputs.len() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let out = &tx.outputs[idx];
    match parse_output_encumbrance(&out.script_pubkey) {
        OutputEncumbrance::HtlcV1(htlc) => Ok(Json(DecodeHtlcResponse {
            found: true,
            vout: Some(idx as u32),
            output_type: "htlcv1".to_string(),
            expected_hash: Some(hex::encode(htlc.expected_hash)),
            timeout_height: Some(htlc.timeout_height),
            recipient_address: Some(base58_p2pkh_from_hash(&htlc.recipient_pkh)),
            refund_address: Some(base58_p2pkh_from_hash(&htlc.refund_pkh)),
        })),
        OutputEncumbrance::P2pkh(_) => Ok(Json(DecodeHtlcResponse {
            found: false,
            vout: Some(idx as u32),
            output_type: "p2pkh".to_string(),
            expected_hash: None,
            timeout_height: None,
            recipient_address: None,
            refund_address: None,
        })),
        OutputEncumbrance::MpsoV1(_) | OutputEncumbrance::HtlcBtcSwapV1(_) | OutputEncumbrance::HtlcLtcSwapV1(_) | OutputEncumbrance::SwapOrder(_) | OutputEncumbrance::LtcSwapOrder(_) | OutputEncumbrance::Unknown => Ok(Json(DecodeHtlcResponse {
            found: false,
            vout: Some(idx as u32),
            output_type: "unknown".to_string(),
            expected_hash: None,
            timeout_height: None,
            recipient_address: None,
            refund_address: None,
        })),
    }
}

async fn claim_htlc(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<SpendHtlcRequest>,
) -> Result<Json<SpendHtlcResponse>, StatusCode> {
    spend_htlc_internal(true, addr, state, headers, req).await
}

async fn refund_htlc(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<SpendHtlcRequest>,
) -> Result<Json<SpendHtlcResponse>, StatusCode> {
    spend_htlc_internal(false, addr, state, headers, req).await
}

async fn agreement_audit(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<AgreementContextRequest>,
) -> Result<Json<AgreementAuditRecord>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    require_rpc_auth(&headers)?;
    let agreement_hash =
        compute_agreement_hash_hex(&req.agreement).map_err(|_| StatusCode::BAD_REQUEST)?;
    let bundle =
        verify_agreement_context_bundle(&req.agreement, req.bundle.as_ref(), &agreement_hash)
            .map_err(|_| StatusCode::BAD_REQUEST)?;
    let record = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let linked = scan_agreement_linked_txs(&chain, &req.agreement, &agreement_hash);
        let lifecycle = derive_lifecycle(
            &req.agreement,
            &agreement_hash,
            linked.clone(),
            chain.tip_height(),
        );
        let refs = collect_agreement_funding_leg_refs(&chain, &req.agreement, &agreement_hash);
        let candidates = discover_agreement_funding_leg_candidates(
            &agreement_hash,
            &linked,
            &refs,
            bundle.as_ref().map(|b| &b.metadata),
        )
        .map_err(|_| StatusCode::BAD_REQUEST)?;
        let candidate_views = build_agreement_funding_leg_candidate_views(
            &chain,
            &req.agreement,
            &agreement_hash,
            bundle.as_ref(),
        )
        .map_err(|_| StatusCode::BAD_REQUEST)?;
        let mut events = build_agreement_activity_timeline(
            &agreement_hash,
            &lifecycle,
            &linked,
            &candidates,
            bundle.as_ref(),
        );
        for candidate in &candidate_views {
            if candidate.release_eligible {
                events.push(AgreementActivityEvent {
                    event_type: "release_eligible".to_string(),
                    source: irium_node_rs::settlement::AgreementActivitySource::HtlcEligibility,
                    txid: Some(candidate.funding_txid.clone()),
                    height: None,
                    timestamp: None,
                    milestone_id: candidate.milestone_id.clone(),
                    note: Some(
                        "HTLC release branch is currently eligible with the provided default context"
                            .to_string(),
                    ),
                });
            }
            if candidate.refund_eligible {
                events.push(AgreementActivityEvent {
                    event_type: "refund_eligible".to_string(),
                    source: irium_node_rs::settlement::AgreementActivitySource::HtlcEligibility,
                    txid: Some(candidate.funding_txid.clone()),
                    height: None,
                    timestamp: None,
                    milestone_id: candidate.milestone_id.clone(),
                    note: Some(
                        "HTLC refund branch is currently eligible with the observed timeout state"
                            .to_string(),
                    ),
                });
            }
        }
        let funding_legs = candidate_views
            .iter()
            .map(|candidate| AgreementAuditFundingLegRecord {
                funding_txid: candidate.funding_txid.clone(),
                htlc_vout: candidate.htlc_vout,
                anchor_vout: candidate.anchor_vout,
                role: candidate.role,
                milestone_id: candidate.milestone_id.clone(),
                amount: candidate.amount,
                htlc_backed: candidate.htlc_backed,
                timeout_height: candidate.timeout_height,
                recipient_address: candidate.recipient_address.clone(),
                refund_address: candidate.refund_address.clone(),
                source_notes: candidate.source_notes.clone(),
                release_eligible: Some(candidate.release_eligible),
                release_reasons: candidate.release_reasons.clone(),
                refund_eligible: Some(candidate.refund_eligible),
                refund_reasons: candidate.refund_reasons.clone(),
            })
            .collect::<Vec<_>>();
        let selected_leg = if funding_legs.len() == 1 {
            funding_legs.first()
        } else {
            None
        };
        build_agreement_audit_record(
            &req.agreement,
            &agreement_hash,
            bundle.as_ref(),
            &lifecycle,
            &linked,
            &funding_legs,
            selected_leg,
            &events,
            Utc::now().timestamp().max(0) as u64,
            "iriumd_rpc",
        )
    };
    Ok(Json(record))
}

async fn agreement_release_eligibility(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<AgreementSpendRequest>,
) -> Result<Json<AgreementSpendEligibilityResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    require_rpc_auth(&headers)?;
    let mut resp = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        evaluate_agreement_spend_eligibility(true, &chain, &req.agreement, &req)
            .map_err(|_| StatusCode::BAD_REQUEST)?
    };
    apply_dispute_status_to_eligibility(&state, &req.agreement, true, &mut resp);
    if resp.eligible {
        if let Ok(ah) = compute_agreement_hash_hex(&req.agreement) {
            emit_event(&state.event_tx, "agreement.satisfied", serde_json::json!({
                "agreement_hash": ah,
            }));
        }
    }
    Ok(Json(resp))
}

async fn agreement_refund_eligibility(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<AgreementSpendRequest>,
) -> Result<Json<AgreementSpendEligibilityResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    require_rpc_auth(&headers)?;
    let mut resp = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        evaluate_agreement_spend_eligibility(false, &chain, &req.agreement, &req)
            .map_err(|_| StatusCode::BAD_REQUEST)?
    };
    apply_dispute_status_to_eligibility(&state, &req.agreement, false, &mut resp);
    if resp.eligible {
        if let Ok(ah) = compute_agreement_hash_hex(&req.agreement) {
            emit_event(&state.event_tx, "agreement.timeout", serde_json::json!({
                "agreement_hash": ah,
            }));
        }
    }
    Ok(Json(resp))
}

async fn submit_proof_rpc(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<SubmitProofRequest>,
) -> Result<Json<SubmitProofResponse>, (StatusCode, String)> {
    let bad = |reason: &str| (StatusCode::BAD_REQUEST, reason.to_string());
    check_rate_with_auth(&state, &addr, &headers)
        .map_err(|sc| (sc, format!("rate_limit_or_auth_failed:{sc}")))?;
    require_rpc_auth(&headers).map_err(|sc| (sc, format!("rpc_auth_failed:{sc}")))?;
    let tip_height = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain.tip_height()
    };
    let expires_at_height = req.proof.expires_at_height;
    let expired = match expires_at_height {
        None => false,
        Some(h) => tip_height >= h,
    };
    let proof_for_gossip = req.proof.clone();
    // Phase 7: record submission height for finality tracking before consuming req.proof.
    {
        let mut heights = state.proof_heights.lock().unwrap_or_else(|e| e.into_inner());
        heights.insert(proof_for_gossip.proof_id.clone(), tip_height);
    }
    let mut store = state.proof_store.lock().unwrap_or_else(|e| e.into_inner());
    let outcome = store.submit(req.proof).map_err(|e| bad(&e))?;
    if outcome.accepted {
        emit_event(&state.event_tx, "agreement.proof_submitted", serde_json::json!({
            "agreement_hash": outcome.agreement_hash,
            "proof_id": outcome.proof_id,
        }));
        if let Some(ref node) = state.p2p {
            if let Ok(json) = serde_json::to_string(&proof_for_gossip) {
                let node = node.clone();
                tokio::spawn(async move { node.broadcast_proof(&json).await; });
            }
        }
    }
    let status = proof_lifecycle_status(expires_at_height, tip_height).to_string();
    Ok(Json(SubmitProofResponse {
        proof_id: outcome.proof_id,
        agreement_hash: outcome.agreement_hash,
        accepted: outcome.accepted,
        duplicate: outcome.duplicate,
        message: outcome.message,
        tip_height,
        expires_at_height,
        expired,
        status,
    }))
}

async fn list_policies_rpc(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<ListPoliciesRequest>,
) -> Result<Json<ListPoliciesResponse>, (StatusCode, String)> {
    check_rate_with_auth(&state, &addr, &headers)
        .map_err(|sc| (sc, format!("rate_limit_or_auth_failed:{sc}")))?;
    require_rpc_auth(&headers).map_err(|sc| (sc, format!("rpc_auth_failed:{sc}")))?;
    let active_only = req.active_only;
    let tip_height = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain.tip_height()
    };
    let policies = {
        let store = state.policy_store.lock().unwrap_or_else(|e| e.into_inner());
        store
            .list_all()
            .into_iter()
            .filter_map(|p| {
                let expired = p.expires_at_height.is_some_and(|h| tip_height >= h);
                if active_only && expired {
                    return None;
                }
                Some(PolicySummary {
                    agreement_hash: p.agreement_hash.clone(),
                    policy_id: p.policy_id.clone(),
                    required_proofs: p.required_proofs.len(),
                    attestors: p.attestors.len(),
                    expires_at_height: p.expires_at_height,
                    expired,
                })
            })
            .collect::<Vec<_>>()
    };
    let count = policies.len();
    Ok(Json(ListPoliciesResponse {
        count,
        policies,
        active_only,
    }))
}

async fn list_proofs_rpc(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<ListProofsRequest>,
) -> Result<Json<ListProofsResponse>, (StatusCode, String)> {
    check_rate_with_auth(&state, &addr, &headers)
        .map_err(|sc| (sc, format!("rate_limit_or_auth_failed:{sc}")))?;
    require_rpc_auth(&headers).map_err(|sc| (sc, format!("rpc_auth_failed:{sc}")))?;
    let tip_height = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain.tip_height()
    };
    let store = state.proof_store.lock().unwrap_or_else(|e| e.into_inner());
    let (filter_hash, mut proofs): (String, Vec<SettlementProof>) =
        match req.agreement_hash.as_deref() {
            Some(h) => (
                h.to_string(),
                store.list_by_agreement(h).into_iter().cloned().collect(),
            ),
            None => (
                "*".to_string(),
                store.list_all().into_iter().cloned().collect(),
            ),
        };
    if req.active_only {
        proofs.retain(|p| match p.expires_at_height {
            None => true,
            Some(h) => tip_height < h,
        });
    }
    let total_count = proofs.len();
    // Apply pagination: offset first, then limit.
    let offset_usize = req.offset as usize;
    let paged: Vec<SettlementProof> = proofs.into_iter().skip(offset_usize).collect();
    let paged: Vec<SettlementProof> = if let Some(lim) = req.limit {
        paged.into_iter().take(lim as usize).collect()
    } else {
        paged
    };
    let returned_count = paged.len();
    let has_more = total_count > req.offset as usize + returned_count;
    let entries: Vec<ProofStatusEntry> = paged
        .into_iter()
        .map(|p| {
            let status = proof_lifecycle_status(p.expires_at_height, tip_height).to_string();
            ProofStatusEntry { proof: p, status }
        })
        .collect();
    Ok(Json(ListProofsResponse {
        agreement_hash: filter_hash,
        tip_height,
        active_only: req.active_only,
        total_count,
        returned_count,
        has_more,
        offset: req.offset,
        limit: req.limit,
        proofs: entries,
    }))
}

// Phase 3: template builder types
#[derive(Deserialize)]
struct TemplateAttestorInput {
    attestor_id: String,
    pubkey_hex: String,
    display_name: Option<String>,
}
#[derive(Deserialize)]
struct MilestoneSpecInput {
    milestone_id: String,
    label: Option<String>,
    proof_type: String,
    deadline_height: Option<u64>,
    holdback_bps: Option<u32>,
    holdback_release_height: Option<u64>,
}
#[derive(Deserialize)]
struct BuildContractorTemplateRequest {
    policy_id: String,
    agreement_hash: String,
    attestors: Vec<TemplateAttestorInput>,
    milestones: Vec<MilestoneSpecInput>,
    notes: Option<String>,
}
#[derive(Deserialize)]
struct BuildPreorderTemplateRequest {
    policy_id: String,
    agreement_hash: String,
    attestors: Vec<TemplateAttestorInput>,
    delivery_proof_type: String,
    refund_deadline_height: u64,
    holdback_bps: Option<u32>,
    holdback_release_height: Option<u64>,
    notes: Option<String>,
}
#[derive(Deserialize)]
struct BuildOtcTemplateRequest {
    policy_id: String,
    agreement_hash: String,
    attestors: Vec<TemplateAttestorInput>,
    release_proof_type: String,
    refund_deadline_height: u64,
    threshold: Option<u32>,
    notes: Option<String>,
}
/// Response for all three template builder endpoints.
#[derive(Debug, Serialize)]
struct BuildTemplateResponse {
    /// Fully-constructed ProofPolicy ready for /rpc/storepolicy.
    policy: ProofPolicy,
    /// Pretty-printed JSON of the policy.
    policy_json: String,
    /// Human-readable summary of policy enforcement rules.
    summary: String,
    requirement_count: usize,
    attestor_count: usize,
    /// 0 for preorder/OTC templates.
    milestone_count: usize,
    has_holdback: bool,
    has_timeout_rules: bool,
}
fn input_to_template_attestor(a: &TemplateAttestorInput) -> TemplateAttestor {
    TemplateAttestor {
        attestor_id: a.attestor_id.clone(),
        pubkey_hex: a.pubkey_hex.clone(),
        display_name: a.display_name.clone(),
    }
}
fn input_to_milestone_spec(m: &MilestoneSpecInput) -> MilestoneSpec {
    MilestoneSpec {
        milestone_id: m.milestone_id.clone(),
        label: m.label.clone(),
        proof_type: m.proof_type.clone(),
        deadline_height: m.deadline_height,
        holdback_bps: m.holdback_bps,
        holdback_release_height: m.holdback_release_height,
    }
}
fn build_template_summary_contractor(policy: &ProofPolicy, milestone_count: usize) -> String {
    let ids: Vec<&str> = policy
        .attestors
        .iter()
        .map(|a| a.attestor_id.as_str())
        .collect();
    let hb = if policy.milestones.iter().any(|m| m.holdback.is_some()) {
        ", holdback on milestone(s)"
    } else {
        ""
    };
    format!(
        "Contractor milestone policy {pol}: {ms} milestone(s), {att} attestor(s) [{ids}], {dl} timeout rule(s){hb}.",
        pol = policy.policy_id,
        ms = milestone_count,
        att = ids.len(),
        ids = ids.join(", "),
        dl = policy.no_response_rules.len(),
        hb = hb,
    )
}
fn build_template_summary_preorder(policy: &ProofPolicy) -> String {
    let ids: Vec<&str> = policy
        .attestors
        .iter()
        .map(|a| a.attestor_id.as_str())
        .collect();
    let pt = policy
        .required_proofs
        .first()
        .map(|r| r.proof_type.as_str())
        .unwrap_or("?");
    let dl = policy
        .no_response_rules
        .first()
        .map(|r| r.deadline_height)
        .unwrap_or(0);
    let hb = match &policy.holdback {
        Some(h) => format!(", {}bps holdback", h.holdback_bps),
        None => String::new(),
    };
    format!(
        "Preorder deposit policy {pol}: release on {pt} proof from [{ids}], refund at height {dl}{hb}.",
        pol = policy.policy_id,
        pt = pt,
        ids = ids.join(", "),
        dl = dl,
        hb = hb,
    )
}
fn build_template_summary_otc(policy: &ProofPolicy) -> String {
    let ids: Vec<&str> = policy
        .attestors
        .iter()
        .map(|a| a.attestor_id.as_str())
        .collect();
    let pt = policy
        .required_proofs
        .first()
        .map(|r| r.proof_type.as_str())
        .unwrap_or("?");
    let thr = policy
        .required_proofs
        .first()
        .and_then(|r| r.threshold)
        .unwrap_or(1);
    let dl = policy
        .no_response_rules
        .first()
        .map(|r| r.deadline_height)
        .unwrap_or(0);
    format!(
        "OTC escrow policy {pol}: {thr}-of-{tot} release on {pt} proof from [{ids}], refund at height {dl}.",
        pol = policy.policy_id,
        thr = thr,
        tot = ids.len(),
        pt = pt,
        ids = ids.join(", "),
        dl = dl,
    )
}
async fn build_contractor_template_rpc(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<BuildContractorTemplateRequest>,
) -> Result<Json<BuildTemplateResponse>, (StatusCode, String)> {
    let bad = |reason: &str| (StatusCode::BAD_REQUEST, reason.to_string());
    check_rate_with_auth(&state, &addr, &headers)
        .map_err(|sc| (sc, format!("rate_limit_or_auth_failed:{sc}")))?;
    require_rpc_auth(&headers).map_err(|sc| (sc, format!("rpc_auth_failed:{sc}")))?;
    let attestors: Vec<TemplateAttestor> = req
        .attestors
        .iter()
        .map(input_to_template_attestor)
        .collect();
    let milestones: Vec<MilestoneSpec> =
        req.milestones.iter().map(input_to_milestone_spec).collect();
    let milestone_count = milestones.len();
    let policy = contractor_milestone_template(
        &req.policy_id,
        &req.agreement_hash,
        &attestors,
        &milestones,
        req.notes,
    )
    .map_err(|e| bad(&e))?;
    let policy_json = policy_template_to_json(&policy).map_err(|e| bad(&e))?;
    let summary = build_template_summary_contractor(&policy, milestone_count);
    let requirement_count = policy.required_proofs.len();
    let attestor_count = policy.attestors.len();
    let has_holdback = policy.milestones.iter().any(|m| m.holdback.is_some());
    let has_timeout_rules = !policy.no_response_rules.is_empty();
    Ok(Json(BuildTemplateResponse {
        policy,
        policy_json,
        summary,
        requirement_count,
        attestor_count,
        milestone_count,
        has_holdback,
        has_timeout_rules,
    }))
}
async fn build_preorder_template_rpc(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<BuildPreorderTemplateRequest>,
) -> Result<Json<BuildTemplateResponse>, (StatusCode, String)> {
    let bad = |reason: &str| (StatusCode::BAD_REQUEST, reason.to_string());
    check_rate_with_auth(&state, &addr, &headers)
        .map_err(|sc| (sc, format!("rate_limit_or_auth_failed:{sc}")))?;
    require_rpc_auth(&headers).map_err(|sc| (sc, format!("rpc_auth_failed:{sc}")))?;
    let attestors: Vec<TemplateAttestor> = req
        .attestors
        .iter()
        .map(input_to_template_attestor)
        .collect();
    let policy = preorder_deposit_template(
        &req.policy_id,
        &req.agreement_hash,
        &attestors,
        &req.delivery_proof_type,
        req.refund_deadline_height,
        req.holdback_bps,
        req.holdback_release_height,
        req.notes,
    )
    .map_err(|e| bad(&e))?;
    let policy_json = policy_template_to_json(&policy).map_err(|e| bad(&e))?;
    let summary = build_template_summary_preorder(&policy);
    let requirement_count = policy.required_proofs.len();
    let attestor_count = policy.attestors.len();
    let has_holdback = policy.holdback.is_some();
    let has_timeout_rules = !policy.no_response_rules.is_empty();
    Ok(Json(BuildTemplateResponse {
        policy,
        policy_json,
        summary,
        requirement_count,
        attestor_count,
        milestone_count: 0,
        has_holdback,
        has_timeout_rules,
    }))
}
async fn build_otc_template_rpc(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<BuildOtcTemplateRequest>,
) -> Result<Json<BuildTemplateResponse>, (StatusCode, String)> {
    let bad = |reason: &str| (StatusCode::BAD_REQUEST, reason.to_string());
    check_rate_with_auth(&state, &addr, &headers)
        .map_err(|sc| (sc, format!("rate_limit_or_auth_failed:{sc}")))?;
    require_rpc_auth(&headers).map_err(|sc| (sc, format!("rpc_auth_failed:{sc}")))?;
    let attestors: Vec<TemplateAttestor> = req
        .attestors
        .iter()
        .map(input_to_template_attestor)
        .collect();
    let policy = basic_otc_escrow_template(
        &req.policy_id,
        &req.agreement_hash,
        &attestors,
        &req.release_proof_type,
        req.refund_deadline_height,
        req.threshold,
        req.notes,
    )
    .map_err(|e| bad(&e))?;
    let policy_json = policy_template_to_json(&policy).map_err(|e| bad(&e))?;
    let summary = build_template_summary_otc(&policy);
    let requirement_count = policy.required_proofs.len();
    let attestor_count = policy.attestors.len();
    let has_timeout_rules = !policy.no_response_rules.is_empty();
    Ok(Json(BuildTemplateResponse {
        policy,
        policy_json,
        summary,
        requirement_count,
        attestor_count,
        milestone_count: 0,
        has_holdback: false,
        has_timeout_rules,
    }))
}
async fn store_policy_rpc(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<StorePolicyRequest>,
) -> Result<Json<StorePolicyResponse>, (StatusCode, String)> {
    let bad = |reason: &str| (StatusCode::BAD_REQUEST, reason.to_string());
    check_rate_with_auth(&state, &addr, &headers)
        .map_err(|sc| (sc, format!("rate_limit_or_auth_failed:{sc}")))?;
    require_rpc_auth(&headers).map_err(|sc| (sc, format!("rpc_auth_failed:{sc}")))?;
    let mut store = state.policy_store.lock().unwrap_or_else(|e| e.into_inner());
    let outcome = store.store(req.policy, req.replace).map_err(|e| bad(&e))?;
    Ok(Json(StorePolicyResponse {
        policy_id: outcome.policy_id,
        agreement_hash: outcome.agreement_hash,
        accepted: outcome.accepted,
        updated: outcome.updated,
        message: outcome.message,
    }))
}

async fn get_proof_rpc(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<GetProofRequest>,
) -> Result<Json<GetProofResponse>, (StatusCode, String)> {
    check_rate_with_auth(&state, &addr, &headers)
        .map_err(|sc| (sc, format!("rate_limit_or_auth_failed:{sc}")))?;
    require_rpc_auth(&headers).map_err(|sc| (sc, format!("rpc_auth_failed:{sc}")))?;
    let tip_height = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain.tip_height()
    };
    let store = state.proof_store.lock().unwrap_or_else(|e| e.into_inner());
    let proof = store.get_by_id(&req.proof_id).cloned();
    let found = proof.is_some();
    let expires_at_height = proof.as_ref().and_then(|p| p.expires_at_height);
    let expired = match expires_at_height {
        None => false,
        Some(h) => tip_height >= h,
    };
    let status = if found {
        proof_lifecycle_status(expires_at_height, tip_height).to_string()
    } else {
        String::new()
    };
    Ok(Json(GetProofResponse {
        proof_id: req.proof_id,
        found,
        tip_height,
        proof,
        expires_at_height,
        expired,
        status,
    }))
}

async fn get_policy_rpc(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<GetPolicyRequest>,
) -> Result<Json<GetPolicyResponse>, (StatusCode, String)> {
    check_rate_with_auth(&state, &addr, &headers)
        .map_err(|sc| (sc, format!("rate_limit_or_auth_failed:{sc}")))?;
    require_rpc_auth(&headers).map_err(|sc| (sc, format!("rpc_auth_failed:{sc}")))?;
    let tip_height = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain.tip_height()
    };
    let store = state.policy_store.lock().unwrap_or_else(|e| e.into_inner());
    let policy = store.get(&req.agreement_hash).cloned();
    let found = policy.is_some();
    let expires_at_height = policy.as_ref().and_then(|p| p.expires_at_height);
    let expired = expires_at_height.is_some_and(|h| tip_height >= h);
    Ok(Json(GetPolicyResponse {
        agreement_hash: req.agreement_hash,
        found,
        policy,
        expires_at_height,
        expired,
    }))
}

async fn evaluate_policy_rpc(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<EvaluatePolicyRequest>,
) -> Result<Json<EvaluatePolicyResponse>, (StatusCode, String)> {
    let bad = |reason: &str| (StatusCode::BAD_REQUEST, reason.to_string());
    check_rate_with_auth(&state, &addr, &headers)
        .map_err(|sc| (sc, format!("rate_limit_or_auth_failed:{sc}")))?;
    require_rpc_auth(&headers).map_err(|sc| (sc, format!("rpc_auth_failed:{sc}")))?;
    let tip_height = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain.tip_height()
    };
    let agreement_hash = compute_agreement_hash_hex(&req.agreement)
        .map_err(|e| bad(&format!("agreement_hash_failed:{e}")))?;
    let policy = {
        let store = state.policy_store.lock().unwrap_or_else(|e| e.into_inner());
        store.get(&agreement_hash).cloned()
    };
    let policy = match policy {
        None => {
            return Ok(Json(EvaluatePolicyResponse {
                outcome: PolicyOutcome::Unsatisfied,
                agreement_hash,
                policy_found: false,
                policy_id: None,
                tip_height,
                proof_count: 0,
                expired_proof_count: 0,
                matched_proof_count: 0,
                matched_proof_ids: Vec::new(),
                expired: false,
                release_eligible: false,
                refund_eligible: false,
                reason: "no policy stored for this agreement".to_string(),
                evaluated_rules: Vec::new(),
                milestone_results: vec![],
                completed_milestone_count: 0,
                total_milestone_count: 0,
                holdback: None,
                threshold_results: vec![],
            }));
        }
        Some(p) => p,
    };
    let all_stored_proofs = {
        let store = state.proof_store.lock().unwrap_or_else(|e| e.into_inner());
        store
            .list_by_agreement(&agreement_hash)
            .into_iter()
            .cloned()
            .collect::<Vec<_>>()
    };
    // Filter out proofs whose expiry height has been reached.
    // Expired proofs are skipped in stored evaluation; they are noted in evaluated_rules.
    let mut expiry_rules: Vec<String> = Vec::new();
    let active_proofs: Vec<SettlementProof> = all_stored_proofs
        .into_iter()
        .filter(|p| {
            if let Some(h) = p.expires_at_height {
                if tip_height >= h {
                    expiry_rules.push(format!(
                        "proof '{}' skipped: expired at height {} (tip {})",
                        p.proof_id, h, tip_height
                    ));
                    return false;
                }
            }
            true
        })
        .collect();
    let proof_count = active_proofs.len();
    let expiry_rule_count = expiry_rules.len();
    // Policy expiry check: treat expired policy as inactive.
    if let Some(expires) = policy.expires_at_height {
        if tip_height >= expires {
            return Ok(Json(EvaluatePolicyResponse {
                outcome: PolicyOutcome::Unsatisfied,
                agreement_hash,
                policy_found: true,
                policy_id: Some(policy.policy_id.clone()),
                tip_height,
                proof_count,
                expired_proof_count: expiry_rules.len(),
                matched_proof_count: 0,
                matched_proof_ids: Vec::new(),
                expired: true,
                release_eligible: false,
                refund_eligible: false,
                reason: format!("policy expired at height {}", expires),
                evaluated_rules: expiry_rules,
                milestone_results: vec![],
                completed_milestone_count: 0,
                total_milestone_count: 0,
                holdback: None,
                threshold_results: vec![],
            }));
        }
    }
    let policy_id = policy.policy_id.clone();
    let result = evaluate_policy(&req.agreement, &policy, &active_proofs, tip_height)
        .map_err(|e| bad(&format!("policy_eval_failed:{e}")))?;
    let mut all_rules = expiry_rules;
    all_rules.extend(result.evaluated_rules);
    let matched_proof_count = result.matched_proof_ids.len();
    let matched_proof_ids = result.matched_proof_ids;
    let completed_milestone_count = result.completed_milestone_count;
    let total_milestone_count = result.total_milestone_count;
    let milestone_results = result.milestone_results;
    let holdback = result.holdback;
    let threshold_results = result.threshold_results;
    Ok(Json(EvaluatePolicyResponse {
        outcome: result.outcome,
        agreement_hash,
        policy_found: true,
        policy_id: Some(policy_id),
        tip_height,
        proof_count,
        expired_proof_count: expiry_rule_count,
        matched_proof_count,
        matched_proof_ids,
        expired: false,
        release_eligible: result.release_eligible,
        refund_eligible: result.refund_eligible,
        reason: result.reason,
        evaluated_rules: all_rules,
        milestone_results,
        completed_milestone_count,
        total_milestone_count,
        holdback,
        threshold_results,
    }))
}

async fn build_settlement_tx_rpc(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<BuildSettlementTxRequest>,
) -> Result<Json<BuildSettlementTxResponse>, (StatusCode, String)> {
    let bad = |reason: &str| (StatusCode::BAD_REQUEST, reason.to_string());
    check_rate_with_auth(&state, &addr, &headers)
        .map_err(|sc| (sc, format!("rate_limit_or_auth_failed:{sc}")))?;
    require_rpc_auth(&headers).map_err(|sc| (sc, format!("rpc_auth_failed:{sc}")))?;

    let tip_height = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain.tip_height()
    };
    let agreement_hash = compute_agreement_hash_hex(&req.agreement)
        .map_err(|e| bad(&format!("agreement_hash_failed:{e}")))?;

    let policy = {
        let store = state.policy_store.lock().unwrap_or_else(|e| e.into_inner());
        store.get(&agreement_hash).cloned()
    };
    let policy = match policy {
        None => {
            return Ok(Json(BuildSettlementTxResponse {
                agreement_hash,
                policy_found: false,
                tip_height,
                release_eligible: false,
                refund_eligible: false,
                outcome: PolicyOutcome::Unsatisfied,
                reason: "no policy stored for this agreement".to_string(),
                total_amount_sat: req.agreement.total_amount,
                actions: vec![],
            }));
        }
        Some(p) => p,
    };

    let all_stored_proofs = {
        let store = state.proof_store.lock().unwrap_or_else(|e| e.into_inner());
        store
            .list_by_agreement(&agreement_hash)
            .into_iter()
            .cloned()
            .collect::<Vec<_>>()
    };
    let active_proofs: Vec<SettlementProof> = all_stored_proofs
        .into_iter()
        .filter(|p| p.expires_at_height.map(|h| tip_height < h).unwrap_or(true))
        .collect();

    let result = evaluate_policy(&req.agreement, &policy, &active_proofs, tip_height)
        .map_err(|e| bad(&format!("policy_eval_failed:{e}")))?;

    let total_sat = req.agreement.total_amount;

    // Resolve payer/payee addresses from the agreement parties list.
    let payer_id: &str = &req.agreement.payer;
    let payee_id: &str = &req.agreement.payee;
    let payer_addr = req
        .agreement
        .parties
        .iter()
        .find(|p| p.party_id == payer_id)
        .map(|p| p.address.clone())
        .unwrap_or_else(|| payer_id.to_string());
    let payee_addr = req
        .agreement
        .parties
        .iter()
        .find(|p| p.party_id == payee_id)
        .map(|p| p.address.clone())
        .unwrap_or_else(|| payee_id.to_string());

    let mut actions: Vec<SettlementAction> = Vec::new();

    if result.release_eligible {
        // Check for top-level holdback split.
        if let Some(ref hb) = result.holdback {
            let immediate_bps = hb.immediate_release_bps;
            let held_bps = hb.holdback_bps;
            let immediate_sat = (total_sat as u128 * immediate_bps as u128 / 10000) as u64;
            let held_sat = (total_sat as u128 * held_bps as u128 / 10000) as u64;

            // Immediate portion to payee
            actions.push(SettlementAction {
                action: "release".to_string(),
                recipient_label: "payee (immediate)".to_string(),
                recipient_address: payee_addr.clone(),
                amount_bps: immediate_bps,
                amount_sat: immediate_sat,
                executable: true,
                hold_reason: None,
                executable_after_height: None,
            });

            // Held portion
            if held_bps > 0 {
                let (exec, hold_reason) = if hb.holdback_released {
                    (true, None)
                } else {
                    (false, Some(hb.holdback_reason.clone()))
                };
                actions.push(SettlementAction {
                    action: "release".to_string(),
                    recipient_label: "payee (holdback)".to_string(),
                    recipient_address: payee_addr.clone(),
                    amount_bps: held_bps,
                    amount_sat: held_sat,
                    executable: exec,
                    hold_reason,
                    executable_after_height: if exec { None } else { hb.deadline_height },
                });
            }
        } else {
            // Simple full release
            actions.push(SettlementAction {
                action: "release".to_string(),
                recipient_label: "payee".to_string(),
                recipient_address: payee_addr,
                amount_bps: 10000,
                amount_sat: total_sat,
                executable: true,
                hold_reason: None,
                executable_after_height: None,
            });
        }
    } else if result.refund_eligible {
        // Full refund to payer
        actions.push(SettlementAction {
            action: "refund".to_string(),
            recipient_label: "payer".to_string(),
            recipient_address: payer_addr,
            amount_bps: 10000,
            amount_sat: total_sat,
            executable: true,
            hold_reason: None,
            executable_after_height: None,
        });
    }
    // If neither eligible, actions list is empty — funds stay locked.

    Ok(Json(BuildSettlementTxResponse {
        agreement_hash,
        policy_found: true,
        tip_height,
        release_eligible: result.release_eligible,
        refund_eligible: result.refund_eligible,
        outcome: result.outcome,
        reason: result.reason,
        total_amount_sat: total_sat,
        actions,
    }))
}

async fn check_policy_rpc(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<CheckPolicyRequest>,
) -> Result<Json<CheckPolicyResponse>, (StatusCode, String)> {
    let bad = |reason: &str| (StatusCode::BAD_REQUEST, reason.to_string());
    check_rate_with_auth(&state, &addr, &headers)
        .map_err(|sc| (sc, format!("rate_limit_or_auth_failed:{sc}")))?;
    require_rpc_auth(&headers).map_err(|sc| (sc, format!("rpc_auth_failed:{sc}")))?;
    let tip_height = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain.tip_height()
    };
    let agreement_hash = compute_agreement_hash_hex(&req.agreement)
        .map_err(|e| bad(&format!("agreement_hash_failed:{e}")))?;
    let result = evaluate_policy(&req.agreement, &req.policy, &req.proofs, tip_height)
        .map_err(|e| bad(&format!("policy_eval_failed:{e}")))?;
    Ok(Json(CheckPolicyResponse {
        agreement_hash,
        policy_id: req.policy.policy_id.clone(),
        tip_height,
        release_eligible: result.release_eligible,
        refund_eligible: result.refund_eligible,
        reason: result.reason,
        evaluated_rules: result.evaluated_rules,
        holdback: result.holdback,
        milestone_results: result.milestone_results,
    }))
}

async fn build_agreement_release(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<AgreementSpendRequest>,
) -> Result<Json<AgreementBuildSpendResponse>, (StatusCode, String)> {
    build_agreement_spend_internal(true, addr, state, headers, req).await
}
async fn build_agreement_refund(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<AgreementSpendRequest>,
) -> Result<Json<AgreementBuildSpendResponse>, (StatusCode, String)> {
    build_agreement_spend_internal(false, addr, state, headers, req).await
}

async fn build_agreement_spend_internal(
    claim: bool,
    addr: SocketAddr,
    state: AppState,
    headers: HeaderMap,
    req: AgreementSpendRequest,
) -> Result<Json<AgreementBuildSpendResponse>, (StatusCode, String)> {
    let bad =
        |reason: &str| -> (StatusCode, String) { (StatusCode::BAD_REQUEST, reason.to_string()) };
    check_rate_with_auth(&state, &addr, &headers)
        .map_err(|sc| (sc, format!("rate_limit_or_auth_failed:{sc}")))?;
    require_rpc_auth(&headers).map_err(|sc| (sc, format!("rpc_auth_failed:{sc}")))?;
    let mut eligibility = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        evaluate_agreement_spend_eligibility(claim, &chain, &req.agreement, &req)
            .map_err(|e| bad(&e))?
    };
    apply_dispute_status_to_eligibility(&state, &req.agreement, claim, &mut eligibility);
    if !eligibility.eligible {
        return Err(bad(&format!(
            "ineligible:{}",
            eligibility.reasons.join(",")
        )));
    }
    let dest = eligibility
        .destination_address
        .clone()
        .ok_or_else(|| bad("destination_address_missing"))?;
    // Stage 3.4.1: if a resolved dispute matches this branch, pay the
    // resolver out of the spend tx according to the agreement's resolver
    // fee fields.
    let resolver_payout: Option<(String, u64)> = {
        let agreement_hash = compute_agreement_hash_hex(&req.agreement)
            .map_err(|_| bad("agreement_hash_failed"))?;
        let dispute_state = state
            .disputes_index
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&agreement_hash)
            .cloned();
        if let Some(d) = dispute_state {
            if let Some(ref resolution) = d.resolution {
                let role = resolution.resolver_role.as_str();
                let (addr, fee) = match role {
                    "primary" => (
                        req.agreement.primary_resolver.clone(),
                        req.agreement.primary_resolver_fee,
                    ),
                    "fallback" => (
                        req.agreement.fallback_resolver.clone(),
                        req.agreement.fallback_resolver_fee,
                    ),
                    _ => (None, None),
                };
                match (addr, fee) {
                    (Some(a), Some(f)) if f > 0 => Some((a, f)),
                    _ => None,
                }
            } else {
                None
            }
        } else {
            None
        }
    };
    let spend = spend_htlc_with_optional_payout(
        claim,
        &state,
        &req.funding_txid,
        eligibility
            .htlc_vout
            .ok_or_else(|| bad("htlc_vout_missing"))?,
        &dest,
        req.fee_per_byte,
        req.broadcast,
        req.secret_hex.as_deref(),
        resolver_payout,
    )
    .map_err(|_| bad("build_htlc_spend_failed"))?;

    // GROUP H follow-up: on a broadcast release, kick off a separate
    // best-effort Release anchor tx that carries rep1:s outputs for both
    // parties. This pins the trade success on-chain without altering the
    // HTLC spend tx itself. Failures here do NOT undo the release - the
    // chain truth is the HTLC spend; the rep1 anchor is purely metadata.
    if claim && spend.accepted {
        let agreement_hash_for_rep = eligibility.agreement_hash.clone();
        let payer_address = req
            .agreement
            .parties
            .iter()
            .find(|p| p.party_id == req.agreement.payer)
            .map(|p| p.address.clone())
            .unwrap_or_default();
        let payee_address = req
            .agreement
            .parties
            .iter()
            .find(|p| p.party_id == req.agreement.payee)
            .map(|p| p.address.clone())
            .unwrap_or_default();
        let mut rep_outputs: Vec<TxOutput> = Vec::new();
        if !payer_address.is_empty() {
            if let Ok(out) = build_reputation_event_output(&ReputationEvent {
                kind: ReputationEventKind::SuccessfulTrade,
                address: payer_address,
                agreement_short_hash: None,
            }) {
                rep_outputs.push(out);
            }
        }
        if !payee_address.is_empty() {
            if let Ok(out) = build_reputation_event_output(&ReputationEvent {
                kind: ReputationEventKind::SuccessfulTrade,
                address: payee_address,
                agreement_short_hash: None,
            }) {
                rep_outputs.push(out);
            }
        }
        if !rep_outputs.is_empty() {
            let release_role = match eligibility.role {
                Some(AgreementAnchorRole::MilestoneRelease) => AgreementAnchorRole::MilestoneRelease,
                _ => AgreementAnchorRole::Release,
            };
            if let Err(e) = build_and_broadcast_anchor_tx(
                &state,
                &agreement_hash_for_rep,
                release_role,
                rep_outputs,
            ) {
                eprintln!(
                    "[group_h] best-effort release anchor + rep1:s broadcast failed for {}: {}",
                    agreement_hash_for_rep, e
                );
            }
        }
    }

    Ok(Json(AgreementBuildSpendResponse {
        agreement_hash: eligibility.agreement_hash,
        agreement_id: req.agreement.agreement_id,
        funding_txid: req.funding_txid,
        htlc_vout: eligibility.htlc_vout.unwrap_or(0),
        role: eligibility.role.unwrap_or(AgreementAnchorRole::Funding),
        milestone_id: eligibility.milestone_id,
        branch: if claim {
            "release".to_string()
        } else {
            "refund".to_string()
        },
        destination_address: dest,
        txid: spend.txid,
        accepted: spend.accepted,
        raw_tx_hex: spend.raw_tx_hex,
        fee: spend.fee,
        trust_model_note: agreement_spend_trust_note(),
    }))
}

async fn spend_htlc_internal(
    claim: bool,
    addr: SocketAddr,
    state: AppState,
    headers: HeaderMap,
    req: SpendHtlcRequest,
) -> Result<Json<SpendHtlcResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    require_rpc_auth(&headers)?;
    let resp = spend_htlc_from_params(
        claim,
        &state,
        &req.funding_txid,
        req.vout,
        &req.destination_address,
        req.fee_per_byte,
        req.broadcast,
        req.secret_hex.as_deref(),
    )?;
    Ok(Json(resp))
}

async fn inspect_htlc(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<InspectHtlcQuery>,
) -> Result<Json<InspectHtlcResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    require_rpc_auth(&headers)?;

    let txid = hex_to_32(q.txid.trim()).map_err(|_| StatusCode::BAD_REQUEST)?;
    let key = OutPoint {
        txid,
        index: q.vout,
    };

    let (tip_height, maybe_utxo) = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        (chain.tip_height(), chain.utxos.get(&key).cloned())
    };

    let Some(utxo) = maybe_utxo else {
        return Ok(Json(InspectHtlcResponse {
            exists: false,
            funded: false,
            unspent: false,
            spent: true,
            spend_type: None,
            claimable_now: false,
            refundable_now: false,
            timeout_height: None,
            expected_hash: None,
            recipient_address: None,
            refund_address: None,
        }));
    };

    let htlc = match parse_htlcv1_script(&utxo.output.script_pubkey) {
        Some(v) => v,
        None => {
            return Ok(Json(InspectHtlcResponse {
                exists: false,
                funded: false,
                unspent: false,
                spent: false,
                spend_type: None,
                claimable_now: false,
                refundable_now: false,
                timeout_height: None,
                expected_hash: None,
                recipient_address: None,
                refund_address: None,
            }))
        }
    };

    Ok(Json(InspectHtlcResponse {
        exists: true,
        funded: true,
        unspent: true,
        spent: false,
        spend_type: None,
        claimable_now: true,
        refundable_now: tip_height >= htlc.timeout_height,
        timeout_height: Some(htlc.timeout_height),
        expected_hash: Some(hex::encode(htlc.expected_hash)),
        recipient_address: Some(base58_p2pkh_from_hash(&htlc.recipient_pkh)),
        refund_address: Some(base58_p2pkh_from_hash(&htlc.refund_pkh)),
    }))
}

async fn get_block_template(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TemplateQuery>,
) -> Result<Json<BlockTemplateResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    require_rpc_auth(&headers)?;

    let longpoll = q.longpoll.unwrap_or(0) == 1;
    let poll_secs = q.poll_secs.unwrap_or(25).max(1).min(120);
    let max_txs = q.max_txs;
    let min_fee = q.min_fee;

    if longpoll {
        let last_tip = {
            let guard = state.chain.lock().unwrap_or_else(|e| e.into_inner());
            let tip_h = guard.tip_height();
            guard
                .chain
                .last()
                .map(|b| hex::encode(b.header.hash_for_height(tip_h)))
                .unwrap_or_else(|| state.genesis_hash.clone())
        };
        let last_mempool = state
            .mempool
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len();

        let start = std::time::Instant::now();
        while start.elapsed().as_secs() < poll_secs {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let current_tip = {
                let guard = state.chain.lock().unwrap_or_else(|e| e.into_inner());
                let tip_h = guard.tip_height();
                guard
                    .chain
                    .last()
                    .map(|b| hex::encode(b.header.hash_for_height(tip_h)))
                    .unwrap_or_else(|| state.genesis_hash.clone())
            };
            let current_mempool = state
                .mempool
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len();
            if current_tip != last_tip || current_mempool != last_mempool {
                break;
            }
        }
    }

    let (height, prev_hash, bits, target, time) = {
        let guard = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let tip = guard.chain.last();
        let tip_h = guard.tip_height();
        let prev_hash = tip
            .map(|b| hex::encode(b.header.hash_for_height(tip_h)))
            .unwrap_or_else(|| "00".repeat(32));
        let height = guard.height;
        let target = guard.target_for_height(height);
        let bits = target.bits;
        let prev_time = tip.map(|b| b.header.time).unwrap_or(0);
        let now = Utc::now().timestamp() as u32;
        let time = if height >= MTP_ACTIVATION_HEIGHT {
            let mtp = guard.median_time_past();
            now.max(mtp.saturating_add(1))
        } else {
            now.max(prev_time.saturating_add(1))
        };
        (height, prev_hash, bits, target_hex(bits), time)
    };

    let mut mempool_entries = state
        .mempool
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .ordered_entries();
    if let Some(min_fee) = min_fee {
        mempool_entries.retain(|e| e.fee_per_byte >= min_fee);
    }
    if let Some(max) = max_txs {
        if mempool_entries.len() > max {
            mempool_entries.truncate(max);
        }
    }
    // Remove conflicting TXs: keep the highest-fee TX for each spent outpoint.
    // ordered_entries() is sorted fee_per_byte desc so first claimer wins.
    {
        let mut claimed: HashSet<([u8; 32], u32)> = HashSet::new();
        mempool_entries.retain(|e| {
            let conflicts = e.tx.inputs.iter().any(|inp| {
                claimed.contains(&(inp.prev_txid, inp.prev_index))
            });
            if conflicts {
                return false;
            }
            for inp in &e.tx.inputs {
                claimed.insert((inp.prev_txid, inp.prev_index));
            }
            true
        });
    }
    // Consensus enforces at-most-one of each header-batch carrier per block
    // (chain.rs: 'block contains more than one {Btc,Ltc}HeaderBatch
    // output'). The mempool can hold many in transit when peers re-gossip
    // stale carriers after an iriumd restart, so the template builder must
    // filter — otherwise the pool stuffs all of them into a block and
    // submit_block rejects, stalling production network-wide. Keep the
    // highest-fee carrier of each chain (ordered_entries is fee-per-byte
    // desc) and drop the rest. Additionally, exclude any carrier whose first
    // header does not connect to the current relay tip — such stale carriers
    // (e.g. re-gossiped from pre-restart state) cause connect_block_failed.
    let (btc_relay_tip, ltc_relay_tip) = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        (chain.btc_tip, chain.ltc_tip)
    };
    {
        let mut btc_seen = false;
        let mut ltc_seen = false;
        mempool_entries.retain(|e| {
            let mut has_btc = false;
            let mut has_ltc = false;
            let mut is_btc_carrier = false;
            let mut is_ltc_carrier = false;
            for out in &e.tx.outputs {
                if let Ok(headers) = parse_btc_header_batch(&out.script_pubkey) {
                    is_btc_carrier = true;
                    if headers.first()
                        .and_then(|h| btc_relay_tip.map(|t| t == h.prev_hash))
                        .unwrap_or(false)
                    {
                        has_btc = true;
                    }
                }
                if let Ok(headers) = parse_ltc_header_batch(&out.script_pubkey) {
                    is_ltc_carrier = true;
                    if headers.first()
                        .and_then(|h| ltc_relay_tip.map(|t| t == h.prev_hash))
                        .unwrap_or(false)
                    {
                        has_ltc = true;
                    }
                }
            }
            if is_btc_carrier && !has_btc {
                return false;
            }
            if is_ltc_carrier && !has_ltc {
                return false;
            }
            if has_btc && btc_seen {
                return false;
            }
            if has_ltc && ltc_seen {
                return false;
            }
            if has_btc {
                btc_seen = true;
            }
            if has_ltc {
                ltc_seen = true;
            }
            true
        });
    }
    let mempool_count = mempool_entries.len();
    let mut total_fees = 0u64;
    let txs = mempool_entries
        .into_iter()
        .map(|entry| {
            total_fees = total_fees.saturating_add(entry.fee);
            TemplateTx {
                hex: hex::encode(entry.raw),
                fee: entry.fee,
                relay_addresses: entry.relay_addresses,
            }
        })
        .collect();

    let coinbase_value = block_reward(height).saturating_add(total_fees);

    // v1.9.62 issue #60: build coinbase extra outputs from the cycle's
    // cached headers if the coinbase batch activation height has been
    // reached. Zero-cost: no wallet access, no UTXOs, no signing — just
    // pure header data the stratum appends to the coinbase as
    // additional value=0 outputs.
    let coinbase_extra_outputs = {
        let coinbase_batch_active = {
            let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
            chain
                .params
                .coinbase_header_batch_activation_height
                .map(|h| height >= h)
                .unwrap_or(false)
        };
        if coinbase_batch_active {
            const COINBASE_BATCH_CACHE_TTL_SECS: u64 = 900;
            let mut out: Vec<CoinbaseExtraOutput> = Vec::new();
            // BTC
            let btc_cached = state
                .btc_template_headers_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            if let Some(c) = btc_cached {
                // v1.9.63: freshness is age-only. Removed the strict
                // expected_relay_tip_height == chain.btc_tip_height
                // check that was wedging injection after the first
                // post-activation block (cycle stored relay_tip=X,
                // apply moved chain to X+144, all subsequent template
                // requests saw mismatch and skipped until next cycle
                // 10min later). apply_btc_header_batch is robust:
                // entirely-known headers no-op via v1.9.52 idempotency;
                // partially-applied or disconnected fail-fast for that
                // single block, the cycle re-fetches on the next tick.
                let fresh = c
                    .built_at
                    .elapsed()
                    .map(|d| d.as_secs() <= COINBASE_BATCH_CACHE_TTL_SECS)
                    .unwrap_or(false);
                if fresh {
                    if let Ok(raw) = hex::decode(c.headers_hex.trim()) {
                        if !raw.is_empty() && raw.len() % BTC_HEADER_BYTES == 0 {
                            let mut headers: Vec<BtcHeader> = Vec::new();
                            let mut ok = true;
                            for chunk in raw.chunks(BTC_HEADER_BYTES) {
                                match BtcHeader::deserialize(chunk) {
                                    Ok(h) => headers.push(h),
                                    Err(_) => {
                                        ok = false;
                                        break;
                                    }
                                }
                            }
                            if ok {
                                headers.truncate(25);
                                if let Ok(script) = encode_btc_header_batch(&headers) {
                                    out.push(CoinbaseExtraOutput {
                                        value: 0,
                                        script_pubkey_hex: hex::encode(script),
                                    });
                                }
                            }
                        }
                    }
                }
            }
            // LTC — v1.9.63: re-enabled after the cycle started flooring
            // start at max(relay_tip, anchor.height) + 1 (see
            // run_ltc_header_sync_cycle); cached LTC headers now connect
            // from the mainnet anchor on cold start. Freshness check is
            // age-only (same relaxation as BTC above).
            let ltc_cached = state
                .ltc_template_headers_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            if let Some(c) = ltc_cached {
                let fresh = c
                    .built_at
                    .elapsed()
                    .map(|d| d.as_secs() <= COINBASE_BATCH_CACHE_TTL_SECS)
                    .unwrap_or(false);
                // v1.9.64: LTC needs strict tip match because apply_ltc_header_batch
                // lacks the v1.9.52-style idempotency that BTC has — re-applying
                // an already-known batch hard-rejects with "header X already known
                // in chain state" and the whole block fails.
                let live = {
                    let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
                    chain.ltc_tip_height
                };
                if fresh && live == c.expected_relay_tip_height {
                    if let Ok(raw) = hex::decode(c.headers_hex.trim()) {
                        if !raw.is_empty() && raw.len() % LTC_HEADER_BYTES == 0 {
                            let mut headers: Vec<LtcHeader> = Vec::new();
                            let mut ok = true;
                            for chunk in raw.chunks(LTC_HEADER_BYTES) {
                                match LtcHeader::deserialize(chunk) {
                                    Ok(h) => headers.push(h),
                                    Err(_) => {
                                        ok = false;
                                        break;
                                    }
                                }
                            }
                            if ok {
                                headers.truncate(25);
                                if let Ok(script) = encode_ltc_header_batch(&headers) {
                                    out.push(CoinbaseExtraOutput {
                                        value: 0,
                                        script_pubkey_hex: hex::encode(script),
                                    });
                                }
                            }
                        }
                    }
                }
            }
            out
        } else {
            Vec::new()
        }
    };

    Ok(Json(BlockTemplateResponse {
        height,
        prev_hash,
        bits: format!("{:08x}", bits),
        target,
        time,
        txs,
        total_fees,
        coinbase_value,
        mempool_count,
        coinbase_extra_outputs,
    }))
}

fn block_json_for(height: u64, block: &Block) -> Value {
    let header = &block.header;
    serde_json::json!({
        "height": height,
        "header": {
            "version": header.version,
            "prev_hash": hex::encode(header.prev_hash),
            "merkle_root": hex::encode(header.merkle_root),
            "time": header.time,
            "bits": format!("{:08x}", header.bits),
            "nonce": header.nonce,
            "hash": hex::encode(header.hash_for_height(height)),
        },
        "tx_hex": block.transactions.iter().map(|tx| hex::encode(tx.serialize())).collect::<Vec<_>>(),
        "auxpow_hex": block.auxpow.as_ref().map(|ap| hex::encode(irium_node_rs::auxpow::serialize(ap))),
        "miner_address": miner_address_from_block(block),
        "submit_source": storage::read_block_submit_source(height),
        "coinbase_tag": block.transactions.first()
            .and_then(|tx| tx.inputs.first())
            .and_then(|inp| extract_coinbase_tag(&inp.script_sig)),
    })
}
async fn get_block(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<BlockQuery>,
) -> Result<Json<Value>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    let guard = state.chain.lock().unwrap_or_else(|e| e.into_inner());
    let idx = q.height as usize;
    if idx >= guard.chain.len() {
        return Err(StatusCode::NOT_FOUND);
    }
    let block = &guard.chain[idx];
    Ok(Json(block_json_for(q.height, block)))
}

async fn get_blocks(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<BlocksQuery>,
) -> Result<Json<Value>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    // Cap at 500 blocks per request to bound response size and chain-lock duration.
    let count = q.count.min(500);
    if count == 0 {
        return Ok(Json(serde_json::json!({"from": q.from, "count": 0, "blocks": []})));
    }
    let guard = state.chain.lock().unwrap_or_else(|e| e.into_inner());
    let start = q.from as usize;
    if start >= guard.chain.len() {
        return Err(StatusCode::NOT_FOUND);
    }
    let end = (start + count as usize).min(guard.chain.len());
    let mut out = Vec::with_capacity(end - start);
    for h in start..end {
        out.push(block_json_for(h as u64, &guard.chain[h]));
    }
    Ok(Json(serde_json::json!({
        "from": q.from,
        "count": out.len(),
        "blocks": out,
    })))
}

async fn get_block_by_hash(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<BlockHashQuery>,
) -> Result<Json<Value>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    let bytes = hex::decode(&q.hash).map_err(|_| StatusCode::BAD_REQUEST)?;
    if bytes.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut target = [0u8; 32];
    target.copy_from_slice(&bytes);

    let guard = state.chain.lock().unwrap_or_else(|e| e.into_inner());
    let height = match guard.heights.get(&target) {
        Some(h) => *h,
        None => return Err(StatusCode::NOT_FOUND),
    };
    let block = guard
        .block_store
        .get(&target)
        .or_else(|| guard.chain.get(height as usize))
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(block_json_for(height, block)))
}

async fn get_tx(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TxQuery>,
) -> Result<Json<TxLookupResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    let bytes = hex::decode(&q.txid).map_err(|_| StatusCode::BAD_REQUEST)?;
    if bytes.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut target = [0u8; 32];
    target.copy_from_slice(&bytes);

    let guard = state.chain.lock().unwrap_or_else(|e| e.into_inner());
    for (height, block) in guard.chain.iter().enumerate() {
        for (idx, tx) in block.transactions.iter().enumerate() {
            if tx.txid() == target {
                let output_value: u64 = tx.outputs.iter().map(|o| o.value).sum();
                let is_coinbase = tx.inputs.len() == 1 && tx.inputs[0].prev_txid == [0u8; 32];
                let response = TxLookupResponse {
                    txid: hex::encode(target),
                    height: height as u64,
                    index: idx,
                    block_hash: hex::encode(block.header.hash_for_height(height as u64)),
                    inputs: tx.inputs.len(),
                    outputs: tx.outputs.len(),
                    output_value,
                    is_coinbase,
                    tx_hex: hex::encode(tx.serialize()),
                    pending: false,
                };
                return Ok(Json(response));
            }
        }
    }
    // Fix C: chain miss — fall back to mempool. Without this, every
    // pending tx looked like a "ghost" to the wallet (printed-txid then
    // /rpc/tx 404 forever) because /rpc/tx only walked the confirmed
    // chain. Returning pending=true with sentinel height/index/block_hash
    // disambiguates "in mempool waiting" from "actually unknown / rejected".
    drop(guard);
    let mempool = state.mempool.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(entry) = mempool.entry(&target) {
        let output_value: u64 = entry.tx.outputs.iter().map(|o| o.value).sum();
        let is_coinbase = entry.tx.inputs.len() == 1 && entry.tx.inputs[0].prev_txid == [0u8; 32];
        let response = TxLookupResponse {
            txid: hex::encode(target),
            height: 0,
            index: 0,
            block_hash: String::new(),
            inputs: entry.tx.inputs.len(),
            outputs: entry.tx.outputs.len(),
            output_value,
            is_coinbase,
            tx_hex: hex::encode(&entry.raw),
            pending: true,
        };
        return Ok(Json(response));
    }
    Err(StatusCode::NOT_FOUND)
}

fn decode_compact_tx(raw: &[u8]) -> Result<Transaction, String> {
    let mut offset = 0usize;

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

    let version = read_u32(raw, &mut offset)?;
    let input_count = read_u8(raw, &mut offset)? as usize;
    let mut inputs = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        let prev_len = read_u8(raw, &mut offset)? as usize;
        let prev_txid_bytes = read_bytes(raw, &mut offset, prev_len)?;
        let mut prev_txid = [0u8; 32];
        if prev_txid_bytes.len() == 32 {
            prev_txid.copy_from_slice(&prev_txid_bytes);
        } else {
            let start = 32 - prev_txid_bytes.len();
            prev_txid[start..].copy_from_slice(&prev_txid_bytes);
        }
        let prev_index = read_u32(raw, &mut offset)?;
        let script_sig_len = read_u8(raw, &mut offset)? as usize;
        let script_sig = read_bytes(raw, &mut offset, script_sig_len)?;
        let sequence = read_u32(raw, &mut offset)?;
        inputs.push(TxInput {
            prev_txid,
            prev_index,
            script_sig,
            sequence,
        });
    }

    let output_count = read_u8(raw, &mut offset)? as usize;
    let mut outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        let value = read_u64(raw, &mut offset)?;
        // v1.9.73: read script_len as varint to match TxOutput::serialize
        // (which switched to varint to support outputs > 252 bytes such as
        // BtcHeaderBatch / LtcHeaderBatch / large MPSO
        // covenants). Previously this single-byte read produced a garbage
        // tx for any output whose script_pubkey was > 252 bytes — the
        // recomputed txid then differed from the original, the merkle
        // tree differed, and parse_persisted_block_file rejected the
        // file with "block merkle root mismatch" on every startup.
        // chain.rs:3337 (the permissive decoder) already does this read.
        let script_len = irium_node_rs::tx::read_varint_at(raw, &mut offset)
            .ok_or_else(|| "varint EOF".to_string())? as usize;
        let script_pubkey = read_bytes(raw, &mut offset, script_len)?;
        outputs.push(TxOutput {
            value,
            script_pubkey,
        });
    }

    let locktime = read_u32(raw, &mut offset)?;

    Ok(Transaction {
        version,
        inputs,
        outputs,
        locktime,
    })
}

fn target_hex(bits: u32) -> String {
    let target = Target { bits }.to_target();
    let mut bytes = target.to_bytes_be();
    if bytes.len() < 32 {
        let mut padded = vec![0u8; 32 - bytes.len()];
        padded.extend_from_slice(&bytes);
        bytes = padded;
    }
    hex::encode(bytes)
}

fn parse_header_bits(bits_str: &str) -> Result<u32, String> {
    let trimmed = bits_str.trim_start_matches("0x");
    u32::from_str_radix(trimmed, 16).map_err(|e| format!("invalid bits field: {e}"))
}

async fn submit_block(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<SubmitBlockRequest>,
) -> Result<Json<Value>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    require_rpc_auth(&headers)?;
    // Rebuild header from JSON.
    let header = &req.header;

    let prev_bytes = hex::decode(&header.prev_hash).map_err(|_| StatusCode::BAD_REQUEST)?;
    let merkle_bytes = hex::decode(&header.merkle_root).map_err(|_| StatusCode::BAD_REQUEST)?;
    let hash_bytes = hex::decode(&header.hash).map_err(|_| StatusCode::BAD_REQUEST)?;
    if prev_bytes.len() != 32 || merkle_bytes.len() != 32 || hash_bytes.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let bits = parse_header_bits(&header.bits).map_err(|_| StatusCode::BAD_REQUEST)?;

    let mut prev_hash = [0u8; 32];
    prev_hash.copy_from_slice(&prev_bytes);
    let mut merkle_root = [0u8; 32];
    merkle_root.copy_from_slice(&merkle_bytes);

    let block_header = BlockHeader {
        version: header.version,
        prev_hash,
        merkle_root,
        time: header.time,
        bits,
        nonce: header.nonce,
    };

    // Sanity-check header hash matches payload.
    // Fix 2a Step B completion: use height-aware hash. Pre-fork
    // (h < STANDARD_HEADER_ACTIVATION_HEIGHT) this is byte-identical
    // to legacy hash() per the pinning test
    // serialize_for_height_matches_legacy_for_all_pre_fork_heights.
    // Post-fork the merkle byte order matches the rest of the chain
    // validation path (Block::merkle_root native order + ASIC wire),
    // closing the inconsistency that caused submit_block to reject
    // valid pool blocks with "merkle root mismatch" in connect_block.
    let derived_hash = block_header.hash_for_height(req.height);
    if derived_hash[..] != hash_bytes[..] {
        eprintln!(
            "[submit_block] reject branch=hash_mismatch derived={} provided={}",
            hex::encode(derived_hash),
            hex::encode(&hash_bytes)
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    if req.tx_hex.is_empty() || req.tx_hex.len() > MAX_SUBMIT_BLOCK_TXS {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    // Decode full transactions from hex payload.
    let mut txs: Vec<Transaction> = Vec::new();
    for tx_hex in &req.tx_hex {
        let raw = hex::decode(tx_hex).map_err(|_| StatusCode::BAD_REQUEST)?;
        let tx = decode_full_tx(&raw).map_err(|_| StatusCode::BAD_REQUEST)?;
        txs.push(tx);
    }

    let auxpow = if block_header.version & irium_node_rs::auxpow::AUXPOW_VERSION_BIT != 0 {
        let hex_str = req.auxpow_hex.as_deref().ok_or_else(|| {
            eprintln!("[submit_block] AuxPoW block missing auxpow_hex");
            StatusCode::BAD_REQUEST
        })?;
        let bytes = hex::decode(hex_str).map_err(|_| StatusCode::BAD_REQUEST)?;
        let mut off = 0usize;
        let ap = irium_node_rs::auxpow::deserialize(&bytes, &mut off).map_err(|e| {
            eprintln!("[submit_block] auxpow decode error: {e}");
            StatusCode::BAD_REQUEST
        })?;
        Some(ap)
    } else {
        None
    };

    let block = Block {
        header: block_header,
        transactions: txs,
        auxpow,
    };

    // Apply to chain state under lock, enforcing consensus rules.
    let (new_height, new_tip_hash) = {
        let mut chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());

        // Height must match the next expected block height.
        if req.height != chain.height {
            eprintln!(
                "[submit_block] reject branch=height_mismatch req_height={} chain_height={}",
                req.height, chain.height
            );
            return Err(StatusCode::BAD_REQUEST);
        }

        if let Err(e) = chain.connect_block(block.clone()) {
            eprintln!(
                "[submit_block] reject branch=connect_block_failed err={}",
                e
            );
            return Err(StatusCode::BAD_REQUEST);
        }

        // Two-pass mempool cleanup while the chain lock is still held so the
        // post-block UTXO set is what validate_transaction sees:
        //   1) drop transactions included in this block by txid match
        //   2) drop transactions that conflict with the new block's UTXOs
        //      (double-spends), which a plain txid match never catches.
        {
            let mut mempool = state.mempool.lock().unwrap_or_else(|e| e.into_inner());
            for tx in block.transactions.iter().skip(1) {
                mempool.remove(&tx.txid());
            }
            evict_invalid_mempool_entries(&chain, &mut mempool);
        }

        let new_tip_h = chain.tip_height();
        let tip_hash = block.header.hash_for_height(new_tip_h);
        (new_tip_h, hex::encode(tip_hash))
    };

    // If anchors are loaded, enforce anchor consistency on the new tip.
    if let Some(ref anchors) = state.anchors {
        if !anchors.is_chain_valid(new_height, &new_tip_hash) {
            eprintln!(
                "[submit_block] reject branch=anchor_reject height={} tip={}",
                new_height, new_tip_hash
            );
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    // Persist JSON representation alongside miner-written blocks.
    if let Err(_e) = storage::write_block_json(req.height, &block) {
        // The block is already in memory; surface a server error if disk write fails.
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    if let Err(_e) =
        storage::write_block_json_with_source(req.height, &block, req.submit_source.as_deref())
    {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // Broadcast the newly accepted block over P2P if enabled.
    if let Some(ref p2p) = state.p2p {
        let mut bytes = Vec::new();
        // Serialize header + transactions using the canonical Rust format.
        //
        // For now we reuse Transaction::serialize() and BlockHeader::serialize()
        // and simply concatenate them; remote peers can interpret this as needed.
        bytes.extend_from_slice(&block.header.serialize_for_height(new_height));
        for tx in &block.transactions {
            bytes.extend_from_slice(&tx.serialize());
        }
        if let Err(e) = p2p.broadcast_block(&bytes).await {
            eprintln!("Failed to broadcast accepted block over P2P: {}", e);
        }
    }

    emit_event(&state.event_tx, "block.new", serde_json::json!({
        "height": new_height,
        "hash": new_tip_hash,
    }));

    Ok(Json(json!({
        "accepted": true,
        "height": req.height,
        "hash": header.hash,
    })))
}

async fn submit_tx(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<SubmitTxRequest>,
) -> Result<Json<SubmitTxResponse>, (StatusCode, Json<SubmitTxResponse>)> {
    // BUG 1 fix: thread a contextual reason through every error path so the
    // wallet client surfaces the actual rejection cause instead of a bare
    // status code. Empty txid on these paths because we either couldn't
    // decode the tx or didn't accept it.
    let empty_err = |sc: StatusCode, reason: &str| -> (StatusCode, Json<SubmitTxResponse>) {
        (sc, Json(SubmitTxResponse {
            txid: String::new(),
            accepted: false,
            reason: Some(reason.to_string()),
        }))
    };
    check_rate_with_auth(&state, &addr, &headers)
        .map_err(|sc| empty_err(sc, "Rate limit or authentication check failed"))?;
    require_rpc_auth(&headers)
        .map_err(|sc| empty_err(sc, "RPC authentication required"))?;
    let bytes = match hex::decode(&req.tx_hex) {
        Ok(b) => b,
        Err(_) => return Err(empty_err(StatusCode::BAD_REQUEST, "Invalid transaction hex")),
    };
    // A compact wallet tx payload may be ambiguously parseable by the full decoder.
    // Try both decoders and select the candidate that passes fee/signature checks.
    let mut candidates: Vec<(&'static str, Transaction)> = Vec::new();
    if let Ok(tx) = decode_compact_tx(&bytes) {
        candidates.push(("compact", tx));
    }
    if let Ok(tx) = decode_full_tx(&bytes) {
        candidates.push(("full", tx));
    }
    if candidates.is_empty() {
        eprintln!("submit_tx decode failed: no valid decoder for payload");
        return Err(empty_err(StatusCode::BAD_REQUEST, "Transaction decode failed"));
    }

    let (tx, fee) = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let mut last_err: Option<String> = None;
        let mut selected: Option<(Transaction, u64)> = None;

        for (kind, cand) in candidates.into_iter() {
            if cand.inputs.is_empty() || cand.outputs.is_empty() {
                last_err = Some(format!("{} decode yielded empty tx", kind));
                continue;
            }
            match chain.calculate_fees(&cand) {
                Ok(f) => {
                    selected = Some((cand, f));
                    break;
                }
                Err(e) => {
                    last_err = Some(format!("{} decode: {}", kind, e));
                }
            }
        }

        match selected {
            Some(v) => v,
            None => {
                let detail = last_err.unwrap_or_else(|| "no valid decoded transaction".to_string());
                eprintln!("submit_tx fee validation failed: {}", detail);
                return Err(empty_err(
                    StatusCode::BAD_REQUEST,
                    &format!("Fee validation failed: {}", detail),
                ));
            }
        }
    };

    let txid = tx.txid();

    let mut mempool = state.mempool.lock().unwrap_or_else(|e| e.into_inner());
    let hex_txid = hex::encode(txid);
    if mempool.contains(&txid) {
        drop(mempool);
        if let Some(p2p) = state.p2p.clone() {
            let raw_bytes = bytes;
            tokio::spawn(async move {
                if let Err(e) = p2p.broadcast_tx(&raw_bytes).await {
                    eprintln!("submit_tx rebroadcast failed: {}", e);
                }
            });
        }
        return Err((StatusCode::CONFLICT, Json(SubmitTxResponse {
            txid: hex_txid,
            accepted: false,
            reason: Some("Transaction already in mempool".to_string()),
        })));
    }

    // Fix B: input-conflict check. Prior to this, two txs that spent
    // the same UTXO would BOTH be admitted to mempool (the only
    // existing check was "same txid"), then get_block_template's
    // conflict-removal retain loop would silently drop the later one
    // at template build — producing the ghost-tx pattern where the
    // wallet printed a txid + exit 0 but the tx never confirmed.
    // Surfacing the conflict at submit-time gives the wallet (and the
    // user) an actionable 422 with the conflicting txid in the reason.
    for input in &tx.inputs {
        let outpoint = (input.prev_txid, input.prev_index);
        if let Some(existing) = mempool.find_conflicting(&outpoint) {
            let reason = format!(
                "Input outpoint {}:{} already claimed by mempool tx {}",
                hex::encode(input.prev_txid),
                input.prev_index,
                hex::encode(existing),
            );
            return Err((StatusCode::UNPROCESSABLE_ENTITY, Json(SubmitTxResponse {
                txid: hex_txid,
                accepted: false,
                reason: Some(reason),
            })));
        }
    }

    let raw = bytes;
    let raw_for_broadcast = raw.clone();
    if let Err(e) = mempool.add_transaction(tx, raw, fee) {
        let mempool_err = format!("Failed to add to mempool: {}", e);
        eprintln!("{}", mempool_err);
        return Err((StatusCode::UNPROCESSABLE_ENTITY, Json(SubmitTxResponse {
            txid: hex_txid,
            accepted: false,
            reason: Some(mempool_err),
        })));
    }
    drop(mempool);

    if let Some(p2p) = state.p2p.clone() {
        tokio::spawn(async move {
            if let Err(e) = p2p.broadcast_tx(&raw_for_broadcast).await {
                eprintln!("submit_tx: broadcast_tx failed: {}", e);
            }
        });
    }

    Ok(Json(SubmitTxResponse {
        txid: hex_txid,
        accepted: true,
        reason: None,
    }))
}

// Fix D: pending-tx lookup. Returns the raw mempool entry for a txid
// that's in mempool but not yet on chain. Public (rate-limited but no
// strict auth) — same policy as /rpc/utxos and /rpc/tx.
async fn mempool_by_txid(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TxQuery>,
) -> Result<Json<MempoolByTxidResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;

    let bytes = hex::decode(&q.txid).map_err(|_| StatusCode::BAD_REQUEST)?;
    if bytes.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut target = [0u8; 32];
    target.copy_from_slice(&bytes);

    let mempool = state.mempool.lock().unwrap_or_else(|e| e.into_inner());
    let entry = match mempool.entry(&target) {
        Some(e) => e,
        None => return Err(StatusCode::NOT_FOUND),
    };
    let output_value: u64 = entry.tx.outputs.iter().map(|o| o.value).sum();
    Ok(Json(MempoolByTxidResponse {
        txid: hex::encode(target),
        tx_hex: hex::encode(&entry.raw),
        fee: entry.fee,
        size: entry.size,
        fee_per_byte: entry.fee_per_byte,
        added_unix: entry.added,
        inputs: entry.tx.inputs.len(),
        outputs: entry.tx.outputs.len(),
        output_value,
    }))
}

// Fix D: outpoints pending-spent by mempool, filtered to those whose
// UTXO belongs to the queried address. Required by the wallet's
// pending-UTXO awareness (Fix A) — wallet calls this before coin
// selection to subtract outpoints already committed to an unconfirmed
// tx, preventing the multi-send race that produced ghost-tx symptoms.
//
// Implementation: iterates the (small) mempool, looks up each input's
// UTXO in chain.utxos, and includes outpoints whose script_pubkey
// matches p2pkh(address). Linear scan is acceptable because mempool
// size is bounded and this endpoint is hit at most once per send.
async fn mempool_spent_by(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<BalanceQuery>,
) -> Result<Json<MempoolSpentByResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;

    let pkh_vec = base58_p2pkh_to_hash(&q.address).ok_or(StatusCode::BAD_REQUEST)?;
    if pkh_vec.len() != 20 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut pkh_arr = [0u8; 20];
    pkh_arr.copy_from_slice(&pkh_vec);
    let target_script = p2pkh_script(&pkh_arr);

    let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
    let mempool = state.mempool.lock().unwrap_or_else(|e| e.into_inner());

    let mut outpoints: Vec<MempoolSpentEntry> = Vec::new();
    for (claiming_txid, entry) in mempool.iter_entries() {
        for input in &entry.tx.inputs {
            let op = OutPoint {
                txid: input.prev_txid,
                index: input.prev_index,
            };
            if let Some(utxo) = chain.utxos.get(&op) {
                if utxo.output.script_pubkey == target_script {
                    outpoints.push(MempoolSpentEntry {
                        prev_txid: hex::encode(input.prev_txid),
                        prev_index: input.prev_index,
                        claiming_txid: hex::encode(claiming_txid),
                    });
                }
            }
        }
    }

    Ok(Json(MempoolSpentByResponse {
        address: q.address.clone(),
        outpoints,
    }))
}

// =====================================================================
// In-process header sync background tasks (replacing the standalone
// `src/bin/{btc,ltc}-header-sync.rs` binaries + their systemd
// timers). One tokio task per chain, spawned from main() once the
// corresponding `resolved_*_spv_relay_activation_height(network)`
// returns `Some(_)`. Each task loops forever:
//   1. Read relay tip + activation gate directly from ChainState
//      (in-process, no HTTP, no auth).
//   2. Fetch external-chain tip via the async helpers in
//      `irium_node_rs::header_sync::{btc,ltc}`.
//   3. Compute target = net_tip - SAFETY_LAG; bail if up to date.
//   4. Fetch the [relay_tip+1 ..= target] header range (max 144).
//   5. Call the corresponding `submit_*_headers_core` directly.
//   6. Sleep CYCLE_PERIOD_SECS (600 s) and repeat. First cycle runs
//      immediately at startup — no initial 600 s wait.
// =====================================================================

use irium_node_rs::header_sync;

/// Periodic background task: re-broadcasts every unconfirmed transaction in
/// the local mempool to all currently-connected peers every 60 seconds.
/// Fixes the case where a tx was created while no peers were connected; the
/// next tick will catch it once peers reconnect. Best-effort: errors are
/// logged but do not abort the loop.
fn spawn_mempool_rebroadcast(state: AppState) {
    let p2p = match state.p2p.clone() {
        Some(n) => n,
        None => {
            eprintln!("[mempool-rebroadcast] P2P is disabled; not spawning");
            return;
        }
    };
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            let raw_txs: Vec<Vec<u8>> = {
                let mempool = state.mempool.lock().unwrap_or_else(|e| e.into_inner());
                mempool.iter_entries().map(|(_, entry)| entry.raw.clone()).collect()
            };
            if raw_txs.is_empty() {
                continue;
            }
            eprintln!("[mempool-rebroadcast] rebroadcasting {} mempool tx(s)", raw_txs.len());
            for raw in &raw_txs {
                if let Err(e) = p2p.broadcast_tx(raw).await {
                    eprintln!("[mempool-rebroadcast] broadcast_tx error: {e}");
                }
            }
        }
    });
}

/// Module-scope helper used by both `spawn_offer_rebroadcast` and the in-main
/// offer handlers. Resolves the local offers feed directory in this precedence:
/// `IRIUM_OFFERS_DIR` env var > `IRIUM_DATA_DIR/offers` > `$HOME/.irium/offers`.
fn offers_feed_dir() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("IRIUM_OFFERS_DIR") {
        return std::path::PathBuf::from(path);
    }
    let data_dir = if let Ok(path) = std::env::var("IRIUM_DATA_DIR") {
        std::path::PathBuf::from(path)
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/".to_string());
        std::path::PathBuf::from(home).join(".irium")
    };
    data_dir.join("offers")
}

/// Periodic background task: re-broadcasts all locally-stored open offers to
/// currently-connected peers every 120 seconds. Unlike the session-scoped
/// offer watcher (which suppresses re-announcement after the first broadcast),
/// this timer re-announces unconditionally, covering peers that joined after
/// initial creation.
fn spawn_offer_rebroadcast(state: AppState) {
    let p2p = match state.p2p.clone() {
        Some(n) => n,
        None => {
            eprintln!("[offer-rebroadcast] P2P is disabled; not spawning");
            return;
        }
    };
    tokio::spawn(async move {
        // Initial warmup so the first re-broadcast lands AFTER outbound
        // peer dial has had a chance to complete on freshly-started NAT
        // nodes. Without this the first rebroadcast happens 120 s in,
        // which used to be the only catch when the 5 s offer-watcher
        // wasted its single shot against zero peers at T=5 s.
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        loop {
            let dir = offers_feed_dir();
            let entries = match std::fs::read_dir(&dir) {
                Ok(e) => e,
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_secs(120)).await;
                    continue;
                }
            };
            let mut to_broadcast: Vec<String> = Vec::new();
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.extension().map(|e| e == "json").unwrap_or(false) { continue; }
                let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if !filename.starts_with("offer-") || !filename.ends_with(".json") { continue; }
                let data = match std::fs::read_to_string(&path) {
                    Ok(d) => d,
                    Err(_) => continue,
                };
                let status = serde_json::from_str::<serde_json::Value>(&data)
                    .ok()
                    .and_then(|v| v.get("status").and_then(|s| s.as_str()).map(|s| s.to_string()));
                if status.as_deref() != Some("open") { continue; }
                to_broadcast.push(data);
            }
            if !to_broadcast.is_empty() {
                eprintln!("[offer-rebroadcast] rebroadcasting {} open offer(s)", to_broadcast.len());
                for json in &to_broadcast {
                    p2p.broadcast_offer(json).await;
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(120)).await;
        }
    });
}

/// HTTP shape returned by mempool.space `/api/v1/blocks/{height}` for each
/// block in the descending 15-item page. Only the fields we need are
/// declared; the rest are ignored by serde.
#[derive(serde::Deserialize)]
struct MempoolSpaceBlock {
    id: String,
    height: u64,
    version: i32,
    timestamp: u32,
    bits: u32,
    nonce: u32,
    merkle_root: String,
    previousblockhash: Option<String>,
}

fn reconstruct_btc_header_from_mempool_space(b: &MempoolSpaceBlock) -> Result<BtcHeader, String> {
    let prev = b.previousblockhash.as_deref().unwrap_or("");
    let prev_bytes = hex::decode(prev)
        .map_err(|e| format!("prev_hash hex decode at h={}: {}", b.height, e))?;
    if prev_bytes.len() != 32 {
        return Err(format!("prev_hash len {} != 32 at h={}", prev_bytes.len(), b.height));
    }
    let mut prev_hash = [0u8; 32];
    prev_hash.copy_from_slice(&prev_bytes);
    // mempool.space returns display-order hex; convert to natural order for
    // the BtcHeader struct, which is the on-wire byte order used by sha256d.
    prev_hash.reverse();

    let merkle = hex::decode(&b.merkle_root)
        .map_err(|e| format!("merkle hex decode at h={}: {}", b.height, e))?;
    if merkle.len() != 32 {
        return Err(format!("merkle len {} != 32 at h={}", merkle.len(), b.height));
    }
    let mut merkle_root = [0u8; 32];
    merkle_root.copy_from_slice(&merkle);
    merkle_root.reverse();

    Ok(BtcHeader {
        version: b.version,
        prev_hash,
        merkle_root,
        time: b.timestamp,
        bits: b.bits,
        nonce: b.nonce,
    })
}

/// Fetch BTC headers covering `start..=end` (inclusive heights) from
/// mempool.space's `/api/v1/blocks/{height}` endpoint, which returns 15
/// blocks at a time descending from the given height. We page downward
/// until the requested range is fully covered, then return the headers in
/// ascending height order (the order apply_btc_header_batch expects).
async fn fetch_btc_headers_from_mempool_space(
    client: &reqwest::Client,
    start: u64,
    end: u64,
) -> Result<Vec<BtcHeader>, String> {
    use std::collections::BTreeMap;
    if start > end {
        return Err(format!("fetch range start={} > end={}", start, end));
    }
    let mut by_height: BTreeMap<u64, BtcHeader> = BTreeMap::new();
    let mut fetch_from = end;
    let max_pages = ((end - start) / 15) + 4;
    let mut page = 0u64;
    loop {
        if page > max_pages {
            return Err(format!(
                "exceeded max pages ({}) fetching {}..{}",
                max_pages, start, end
            ));
        }
        page += 1;
        let url = format!("https://mempool.space/api/v1/blocks/{}", fetch_from);
        let resp = client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("http error {}: {}", url, e))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(format!("http {} from {}", status, url));
        }
        let blocks: Vec<MempoolSpaceBlock> = resp
            .json()
            .await
            .map_err(|e| format!("json parse {}: {}", url, e))?;
        if blocks.is_empty() {
            return Err(format!("empty blocks array from {}", url));
        }
        let mut min_h = u64::MAX;
        for b in blocks.iter() {
            if b.height >= start && b.height <= end {
                let h = reconstruct_btc_header_from_mempool_space(b)?;
                by_height.insert(b.height, h);
            }
            if b.height < min_h {
                min_h = b.height;
            }
        }
        if (by_height.len() as u64) >= (end - start + 1) {
            break;
        }
        if min_h == 0 || min_h <= start {
            break;
        }
        fetch_from = min_h - 1;
        // Be nice to mempool.space — small pause between paginated calls.
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;
    }
    let got = by_height.len() as u64;
    let want = end - start + 1;
    if got < want {
        return Err(format!(
            "got {} headers, wanted {} for {}..{}",
            got, want, start, end
        ));
    }
    Ok(by_height.into_values().collect())
}

/// On fresh mainnet nodes (or any time the local BTC header chain is far
/// behind the network), fetch BTC headers from mempool.space and validate
/// them via the existing apply_btc_header_batch path. Runs synchronously
/// in main() BEFORE maybe_spawn_btc_header_sync and BEFORE the HTTP server
/// accepts connections, so there is no concurrent writer on
/// chain.btc_headers during bootstrap.
///
/// Without this step, fresh installs cannot apply Irium blocks containing
/// BtcHeaderBatch transactions whose first header references a BTC block
/// that is not the hardcoded anchor — every block from h=24,477 onward
/// fails validation with "first header does not connect to known chain".
///
/// Idempotent: on subsequent restarts where btc_tip_height is already past
/// the target, the function is a no-op (it computes start_height from
/// existing btc_tip_height + 1, sees it is at or past the target, and
/// returns). When iriumd's chain state is re-derived from blocks (and so
/// btc_headers is rebuilt from scratch), this bootstrap runs again — the
/// v1.9.52 apply_btc_header_batch idempotency fix means subsequent block
/// replays that re-apply the same headers are no-ops, not rejections.
///
/// On any HTTP / parse / validation error the function logs a warning and
/// returns Ok(()) — iriumd still starts, and btc-header-sync.timer or a
/// subsequent restart can complete the bootstrap later.
async fn maybe_bootstrap_btc_headers(
    state: AppState,
    network: NetworkKind,
) -> Result<(), String> {
    if !matches!(network, NetworkKind::Mainnet) {
        return Ok(());
    }
    if env::var("IRIUM_SKIP_BTC_BOOTSTRAP").ok().as_deref() == Some("1") {
        eprintln!("[btc-bootstrap] skipped via IRIUM_SKIP_BTC_BOOTSTRAP=1");
        return Ok(());
    }

    // Resolve the anchor directly from the network constants rather than
    // going through ChainState::btc_anchor (private). Mirrors the value
    // chain.rs threads into apply_btc_header_batch at block apply time.
    let anchor = match resolve_btc_spv_params(network) {
        Some(p) => p.anchor,
        None => {
            eprintln!("[btc-bootstrap] btc_spv params unresolved on {:?} — skipping", network);
            return Ok(());
        }
    };
    if anchor.is_zero() {
        eprintln!("[btc-bootstrap] anchor not configured on mainnet — skipping");
        return Ok(());
    }
    let existing_tip = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain.btc_tip_height
    };

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("iriumd-btc-bootstrap/1.9.54")
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[btc-bootstrap] http client build failed: {} — skipping", e);
            return Ok(());
        }
    };

    let tip_url = "https://mempool.space/api/blocks/tip/height";
    let btc_tip: u64 = match client.get(tip_url).send().await {
        Ok(resp) => match resp.text().await {
            Ok(s) => match s.trim().parse() {
                Ok(n) => n,
                Err(e) => {
                    eprintln!(
                        "[btc-bootstrap] could not parse tip {:?}: {} — skipping",
                        s, e
                    );
                    return Ok(());
                }
            },
            Err(e) => {
                eprintln!("[btc-bootstrap] tip body read failed: {} — skipping", e);
                return Ok(());
            }
        },
        Err(e) => {
            eprintln!(
                "[btc-bootstrap] could not reach mempool.space ({}): {} — skipping; btc-header-sync.timer can fill the gap later",
                tip_url, e
            );
            return Ok(());
        }
    };

    // 12-block safety margin against mempool.space serving a header that
    // ends up reorged out of the canonical chain by the time we apply it.
    let target_height = btc_tip.saturating_sub(12);
    let start_height = if existing_tip == 0 {
        anchor.height + 1
    } else {
        existing_tip + 1
    };
    if start_height > target_height {
        eprintln!(
            "[btc-bootstrap] already at h={} (target {}), nothing to bootstrap",
            existing_tip, target_height
        );
        return Ok(());
    }

    eprintln!(
        "[btc-bootstrap] mainnet bootstrap from {} to {} ({} headers) — mempool.space",
        start_height,
        target_height,
        target_height - start_height + 1,
    );

    let chunk_size: u64 = 2016;
    let mut h = start_height;
    while h <= target_height {
        let chunk_end = (h + chunk_size - 1).min(target_height);
        eprintln!(
            "[btc-bootstrap] fetching headers {}..{}",
            h, chunk_end
        );
        let headers =
            match fetch_btc_headers_from_mempool_space(&client, h, chunk_end).await {
                Ok(hs) => hs,
                Err(e) => {
                    eprintln!(
                        "[btc-bootstrap] fetch {}..{} failed: {} — aborting bootstrap",
                        h, chunk_end, e
                    );
                    return Ok(());
                }
            };

        // Apply via the existing validator. iriumd_block_time is used only
        // for the "header.time > iriumd_block_time + 2h" future-time guard;
        // we are populating historical headers so use the current wall
        // clock as the upper bound.
        let iriumd_block_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(u32::MAX - 7200);

        let apply_result = {
            let mut chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
            // Splitting borrows on fields of a MutexGuard requires going
            // through an explicit `&mut *chain` reborrow first; otherwise
            // the compiler tracks each .field access as a fresh borrow of
            // the whole guard and rejects multiple mutable accesses.
            let cs = &mut *chain;
            apply_btc_header_batch(
                headers,
                iriumd_block_time,
                &mut cs.btc_headers,
                &mut cs.btc_heights,
                &mut cs.btc_tip,
                &mut cs.btc_tip_height,
                &anchor,
            )
        };

        match apply_result {
            Ok(update) => {
                eprintln!(
                    "[btc-bootstrap] applied {} headers ({}..{}); btc_tip_height={}",
                    update.headers_added.len(),
                    h,
                    chunk_end,
                    chunk_end
                );
            }
            Err(e) => {
                eprintln!(
                    "[btc-bootstrap] apply {}..{} failed: {} — aborting bootstrap",
                    h, chunk_end, e
                );
                return Ok(());
            }
        }

        h = chunk_end + 1;
        // Small pause so the rate guard on mempool.space stays happy.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    eprintln!(
        "[btc-bootstrap] complete. btc_tip_height now at {}",
        target_height
    );
    Ok(())
}

/// Resolve `<IRIUM_DATA_DIR>/{label}_header_sync_last.txt` (or
/// `$HOME/.irium/...` if the env var is unset). The wrapper script
/// /usr/local/bin/btc-header-sync-wrapper reads this file's unix
/// timestamp and exits 0 (skipping the fallback fetch) if it is less
/// than 600s old. So updating the file with the current time is how the
/// internal cycle tells the external timer "primary is healthy — stand
/// down."
fn header_sync_last_file_path(label: &str) -> std::path::PathBuf {
    let data_dir = env::var("IRIUM_DATA_DIR").unwrap_or_else(|_| {
        let home = env::var("HOME").unwrap_or_else(|_| "/".to_string());
        format!("{}/.irium", home)
    });
    std::path::Path::new(&data_dir).join(format!("{}_header_sync_last.txt", label))
}

/// Write current unix seconds into <data_dir>/{label}_header_sync_last.txt.
/// Best-effort: write errors are logged but not propagated — the worst
/// case is the fallback timer runs a redundant fetch, which is fine.
fn header_sync_touch_last_file(label: &str) {
    let path = header_sync_last_file_path(label);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if let Err(e) = std::fs::write(&path, format!("{}\n", now)) {
        eprintln!(
            "[header-sync/{}] failed to write {}: {} (fallback timer will run unnecessarily)",
            label,
            path.display(),
            e
        );
    }
}

/// Random 0-30s startup delay (v1.9.60) so simultaneous deploys across
/// the network don't have every node firing its very first header-sync
/// cycle within the same wall-clock second. Seeds purely off the current
/// nanosecond, so no `rand` crate dependency is needed and each node
/// gets a distinct value naturally. After the jitter, the steady-state
/// 600s loop period takes over and individual schedule drift keeps
/// nodes desynchronised on its own.
fn header_sync_startup_jitter_secs() -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    nanos % 31
}

/// True iff the mempool contains a tx whose outputs include a script
/// that the supplied parser recognises (i.e. a pending unconfirmed
/// BtcHeaderBatch / LtcHeaderBatch carrier tx). When
/// true, the cycle skips submitting another batch: with the same
/// wallet inputs and same headers, the resulting tx is byte-identical
/// to the pending one, which the mempool rejects as a duplicate and
/// block-template builders can then race the two against each other —
/// the v1.9.55 → v1.9.56 production stall was a textbook example.
fn mempool_has_pending_header_batch<F>(state: &AppState, output_is_batch: F) -> bool
where
    F: Fn(&[u8]) -> bool,
{
    let mempool = state.mempool.lock().unwrap_or_else(|e| e.into_inner());
    let found = mempool.iter_entries().any(|(_txid, entry)| {
        entry
            .tx
            .outputs
            .iter()
            .any(|out| output_is_batch(&out.script_pubkey))
    });
    found
}

fn maybe_spawn_btc_header_sync(state: AppState, network: NetworkKind) {
    let act_height = match irium_node_rs::activation::resolved_btc_spv_relay_activation_height(network) {
        Some(h) => h,
        None => {
            eprintln!(
                "[header-sync/btc] activation gate is None on {:?}; not spawning",
                network
            );
            return;
        }
    };
    tokio::spawn(async move {
        let client = match reqwest::Client::builder()
            .user_agent("iriumd-btc-header-sync/1.0")
            .timeout(std::time::Duration::from_secs(
                header_sync::common::HTTP_TIMEOUT_SECS,
            ))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[header-sync/btc] failed to build http client: {e}; thread exiting");
                return;
            }
        };
        // FIX 2 (v1.9.60): random 0-30s startup jitter so simultaneous
        // network-wide restarts don't have every node firing cycle 0 at
        // the same wall-clock second. After this, the 600s loop period
        // drift keeps nodes naturally desynchronised.
        let jitter = header_sync_startup_jitter_secs();
        eprintln!("[header-sync/btc] startup jitter {jitter}s");
        tokio::time::sleep(std::time::Duration::from_secs(jitter)).await;
        loop {
            match run_btc_header_sync_cycle(&state, &client, act_height).await {
                Ok(outcome) => {
                    eprintln!("[header-sync/btc] cycle ok: {outcome}");
                }
                Err(e) => {
                    eprintln!("[header-sync/btc] cycle error: {e}");
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(
                header_sync::common::CYCLE_PERIOD_SECS,
            ))
            .await;
        }
    });
}

fn maybe_spawn_ltc_header_sync(state: AppState, network: NetworkKind) {
    let act_height = match irium_node_rs::activation::resolved_ltc_spv_relay_activation_height(network) {
        Some(h) => h,
        None => {
            eprintln!(
                "[header-sync/ltc] activation gate is None on {:?}; not spawning",
                network
            );
            return;
        }
    };
    let source = match header_sync::common::Source::from_env("IRIUM_LTC_HEADER_SYNC_SOURCE") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[header-sync/ltc] source detection failed: {e}; thread exiting");
            return;
        }
    };
    tokio::spawn(async move {
        let client = match reqwest::Client::builder()
            .user_agent("iriumd-ltc-header-sync/1.0")
            .timeout(std::time::Duration::from_secs(
                header_sync::common::HTTP_TIMEOUT_SECS,
            ))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[header-sync/ltc] failed to build http client: {e}; thread exiting");
                return;
            }
        };
        let jitter = header_sync_startup_jitter_secs();
        eprintln!("[header-sync/ltc] startup jitter {jitter}s");
        tokio::time::sleep(std::time::Duration::from_secs(jitter)).await;
        loop {
            match run_ltc_header_sync_cycle(&state, &client, act_height, source).await {
                Ok(outcome) => {
                    eprintln!("[header-sync/ltc] cycle ok: {outcome}");
                }
                Err(e) => {
                    eprintln!("[header-sync/ltc] cycle error: {e}");
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(
                header_sync::common::CYCLE_PERIOD_SECS,
            ))
            .await;
        }
    });
}

async fn run_btc_header_sync_cycle(
    state: &AppState,
    client: &reqwest::Client,
    act_height: u64,
) -> Result<String, String> {
    let (relay_tip, gate_open) = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let open = chain.height >= act_height;
        (chain.btc_tip_height, open)
    };
    if !gate_open {
        return Ok("gate_closed".to_string());
    }
    // v1.9.67 Issue #60 phase 2: native BTC P2P. No mempool.space HTTP.
    let tip_hash = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain.btc_tip.unwrap_or_else(|| {
            chain
                .params
                .btc_spv
                .as_ref()
                .map(|p| p.anchor.hash)
                .unwrap_or([0u8; 32])
        })
    };
    let raw_headers = irium_node_rs::btc_p2p::fetch_headers(tip_hash)
        .await
        .map_err(|e| format!("p2p fetch: {e}"))?;
    // v1.9.70: cap BTC batch to 144 headers (~11.5 KB encoded) for the
    // same reason — a 2000-header P2P response
    // produces a 160 KB coinbase OP_RETURN that stalls local mining.
    let raw_headers: Vec<[u8; 80]> = raw_headers.into_iter().take(144).collect();
    if raw_headers.is_empty() {
        header_sync_touch_last_file("btc");
        return Ok("p2p_up_to_date".to_string());
    }
    let count = raw_headers.len();
    let headers_hex: String = raw_headers.iter().map(hex::encode).collect();
    let live_relay_tip = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain.btc_tip_height
    };
    {
        let mut cache = state
            .btc_template_headers_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *cache = Some(CachedHeaderBatchForTemplate {
            headers_hex,
            expected_relay_tip_height: live_relay_tip,
            built_at: std::time::SystemTime::now(),
        });
    }
    header_sync_touch_last_file("btc");
    return Ok(format!(
        "p2p_cached_headers count={count} relay_tip={live_relay_tip}"
    ));

    // ----- dead post-v1.9.67 code below; kept inside `#[allow]` block ----
    #[allow(unreachable_code, unused_variables, unused_assignments)]
    {
    // v1.9.61: this cycle has NO mempool side effects. It only fetches
    // headers from mempool.space and caches them. getblocktemplate builds
    // a fresh signed carrier per template request using current wallet
    // UTXOs, and the carrier rides into a mined block directly without
    // ever entering the mempool. The previous mempool guard (v1.9.57)
    // is therefore not relevant here anymore and is removed; the v1.9.58
    // template carrier cap and v1.9.59 admission dedup still protect
    // against peer-submitted carriers (e.g. via /rpc/submitbtcheaders).
    let btc_net_tip = header_sync::btc::fetch_btc_net_tip(client).await?;
    if btc_net_tip <= header_sync::common::SAFETY_LAG {
        return Err(format!(
            "btc network tip {btc_net_tip} <= safety lag {}; refusing to fetch",
            header_sync::common::SAFETY_LAG
        ));
    }
    let target = btc_net_tip - header_sync::common::SAFETY_LAG;
    if relay_tip >= target {
        header_sync_touch_last_file("btc");
        return Ok(format!(
            "up_to_date relay_tip={relay_tip} btc_net={btc_net_tip} target={target}"
        ));
    }
    // FIX 2 (v1.9.63): floor at anchor.height on cold start. ChainState
    // initialises btc_tip_height to 0 even when btc_spv is configured;
    // fetching from height 1 would produce headers that do not connect
    // to the anchor (LTC hit this hard at v1.9.62 activation; apply
    // BTC the same protection for consistency even though v1.9.55
    // bootstrap usually beats the cycle to it).
    let anchor_height = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain
            .params
            .btc_spv
            .as_ref()
            .map(|p| p.anchor.height)
            .unwrap_or(0)
    };
    let effective_relay_tip = std::cmp::max(relay_tip, anchor_height);
    let start = effective_relay_tip + 1;
    let end = std::cmp::min(start + header_sync::common::BATCH_SIZE - 1, target);
    let headers_hex = header_sync::btc::fetch_btc_headers(client, start, end).await?;
    let live_relay_tip = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain.btc_tip_height
    };
    if live_relay_tip >= end {
        header_sync_touch_last_file("btc");
        return Ok(format!(
            "stand_down: chain advanced from {relay_tip} to {live_relay_tip} during fetch (planned end {end})"
        ));
    }
    {
        let mut cache = state
            .btc_template_headers_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *cache = Some(CachedHeaderBatchForTemplate {
            headers_hex,
            expected_relay_tip_height: live_relay_tip,
            built_at: std::time::SystemTime::now(),
        });
    }
    header_sync_touch_last_file("btc");
    Ok(format!(
        "cached_headers start={start} end={end} relay_tip={live_relay_tip}"
    ))
    } // closes #[allow] block
}

async fn run_ltc_header_sync_cycle(
    state: &AppState,
    client: &reqwest::Client,
    act_height: u64,
    source: header_sync::common::Source,
) -> Result<String, String> {
    let (relay_tip, gate_open) = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let open = chain.height >= act_height;
        (chain.ltc_tip_height, open)
    };
    if !gate_open {
        return Ok("gate_closed".to_string());
    }
    // v1.9.67 Issue #60 phase 3: native LTC P2P for mainnet. Regtest
    // (iriumd-devnet) still goes through the existing litecoind RPC
    // path for integration test rigs.
    if source == header_sync::common::Source::Mainnet {
        let tip_hash = {
            let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
            chain.ltc_tip.unwrap_or_else(|| {
                chain
                    .params
                    .ltc_spv
                    .as_ref()
                    .map(|p| p.anchor.hash)
                    .unwrap_or([0u8; 32])
            })
        };
        let raw_headers = irium_node_rs::ltc_p2p::fetch_headers(tip_hash)
            .await
            .map_err(|e| format!("p2p fetch: {e}"))?;
        // v1.9.70: cap LTC batch to 144 headers — see BTC comment above.
        let raw_headers: Vec<[u8; 80]> = raw_headers.into_iter().take(144).collect();
        if raw_headers.is_empty() {
            header_sync_touch_last_file("ltc");
            return Ok("p2p_up_to_date".to_string());
        }
        let count = raw_headers.len();
        let headers_hex: String = raw_headers.iter().map(hex::encode).collect();
        let live_relay_tip = {
            let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
            chain.ltc_tip_height
        };
        {
            let mut cache = state
                .ltc_template_headers_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *cache = Some(CachedHeaderBatchForTemplate {
                headers_hex,
                expected_relay_tip_height: live_relay_tip,
                built_at: std::time::SystemTime::now(),
            });
        }
        header_sync_touch_last_file("ltc");
        return Ok(format!(
            "p2p_cached_headers count={count} relay_tip={live_relay_tip}"
        ));
    }

    // Regtest path (unchanged from pre-v1.9.67): litecoind JSON-RPC.
    let relay_tip = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain.ltc_tip_height
    };
    let ltc_net_tip = header_sync::ltc::fetch_ltc_net_tip(client, source).await?;
    if source == header_sync::common::Source::Mainnet
        && ltc_net_tip <= header_sync::common::SAFETY_LAG
    {
        return Err(format!(
            "ltc network tip {ltc_net_tip} <= safety lag {}; refusing to submit",
            header_sync::common::SAFETY_LAG
        ));
    }
    let target = match source {
        header_sync::common::Source::Mainnet => ltc_net_tip - header_sync::common::SAFETY_LAG,
        header_sync::common::Source::Regtest => ltc_net_tip,
    };
    if relay_tip >= target {
        header_sync_touch_last_file("ltc");
        return Ok(format!(
            "up_to_date relay_tip={relay_tip} ltc_net={ltc_net_tip} target={target} source={source:?}"
        ));
    }
    // FIX 2 (v1.9.63): floor at anchor.height on cold start.
    let anchor_height = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain
            .params
            .ltc_spv
            .as_ref()
            .map(|p| p.anchor.height)
            .unwrap_or(0)
    };
    let effective_relay_tip = std::cmp::max(relay_tip, anchor_height);
    let start = effective_relay_tip + 1;
    let end = std::cmp::min(start + header_sync::common::BATCH_SIZE - 1, target);
    let headers_hex =
        header_sync::ltc::fetch_ltc_headers(client, source, start, end).await?;
    let live_relay_tip = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain.ltc_tip_height
    };
    if live_relay_tip >= end {
        header_sync_touch_last_file("ltc");
        return Ok(format!(
            "stand_down: chain advanced from {relay_tip} to {live_relay_tip} during fetch (planned end {end})"
        ));
    }
    {
        let mut cache = state
            .ltc_template_headers_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *cache = Some(CachedHeaderBatchForTemplate {
            headers_hex,
            expected_relay_tip_height: live_relay_tip,
            built_at: std::time::SystemTime::now(),
        });
    }
    header_sync_touch_last_file("ltc");
    Ok(format!(
        "cached_headers start={start} end={end} relay_tip={live_relay_tip} source={source:?}"
    ))
}

#[tokio::main(flavor = "multi_thread", worker_threads = 8)]
async fn main() {
    // Added to allow --version to be displayed
    let args: Vec<String> = std::env::args().collect();
    if args.contains(&"--version".to_string()) || args.contains(&"-V".to_string()) {
        println!("iriumd version {}", env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }
    // -----------------------
    // Install ring as the default rustls crypto provider before any TLS code runs.
    // When both ring and aws-lc-rs appear in the dep tree, rustls 0.23 panics
    // unless install_default() is called explicitly (e.g. on nodes using TLS RPC).
    let _ = rustls::crypto::ring::default_provider().install_default();
    // Load config first so data_dir can influence runtime path selection.
    let node_cfg: Option<NodeConfig> = load_node_config_from_env();
    if let Some(data_dir) = node_cfg
        .as_ref()
        .and_then(|cfg| cfg.data_dir.as_ref())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        if std::env::var_os("IRIUM_DATA_DIR").is_none() {
            std::env::set_var("IRIUM_DATA_DIR", data_dir);
            println!("Using config data_dir via IRIUM_DATA_DIR={}", data_dir);
        }
    }

    let (blocks_dir, state_dir) = storage::ensure_runtime_dirs().unwrap_or_else(|e| {
        eprintln!("Failed to init runtime dirs: {e}");
        std::process::exit(1);
    });
    migrate_legacy_repo_state_dir(&state_dir);
    println!("Using blocks dir: {}", blocks_dir.display());
    println!("Using state dir: {}", state_dir.display());
    println!(
        "To resync, delete ONLY state dir: {} (keep blocks dir: {})",
        state_dir.display(),
        blocks_dir.display()
    );
    storage::init_persist_writer();
    // Initialize chain state with locked genesis.
    let locked = load_locked_genesis().expect("load locked genesis");
    let genesis_hash = locked.header.hash.clone();
    let genesis_hash_lc = genesis_hash.to_lowercase();
    let genesis_block = match block_from_locked(&locked) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Failed to build genesis block from locked config: {e}");
            std::process::exit(1);
        }
    };

    // Ensure genesis (block 0) exists and matches the locked genesis.
    // If a persisted genesis is corrupt/mismatched, quarantine it and reset volatile state.
    let mut load_persisted = true;
    let block0_path = blocks_dir.join("block_0.json");
    if block0_path.exists() {
        let mut bad = false;
        match fs::read_to_string(&block0_path) {
            Ok(raw) => match serde_json::from_str::<Value>(&raw) {
                Ok(v) => {
                    let file_hash = v
                        .get("header")
                        .and_then(|h| h.get("hash"))
                        .and_then(|h| h.as_str())
                        .unwrap_or("");
                    if file_hash.to_lowercase() != genesis_hash_lc {
                        bad = true;
                    }
                }
                Err(_) => bad = true,
            },
            Err(_) => bad = true,
        }
        if bad {
            eprintln!(
                "[error] Genesis block file (block_0.json) is corrupt or mismatched at {}",
                block0_path.display()
            );
            let ts = Utc::now().timestamp();
            let quarantine = blocks_dir.join(format!("block_0.bad.{ts}.json"));
            let _ = fs::rename(&block0_path, &quarantine);
            eprintln!(
                "[error] Quarantined bad genesis to {}. Reinitializing state dir and resyncing headers from genesis.",
                quarantine.display()
            );
            reinit_state_dir(&state_dir, "genesis mismatch");
            load_persisted = false;
        }
    }
    if !block0_path.exists() {
        if let Err(e) = storage::write_block_json(0, &genesis_block) {
            eprintln!(
                "[warn] Failed to write genesis block_0.json to {}: {}",
                block0_path.display(),
                e
            );
        }
    }

    let pow_limit = Target { bits: 0x1d00_ffff };
    let network = network_kind_from_env();
    let env_override = runtime_htlcv1_env_override();
    let lwma_env_override = runtime_lwma_env_override();
    let htlc_activation = resolved_htlcv1_activation_height(network);
    let lwma_activation = resolved_lwma_activation_height(network);
    match (network, htlc_activation) {
        (NetworkKind::Mainnet, Some(_)) => {
            // Already activated on mainnet; no startup message needed.
        }
        (NetworkKind::Mainnet, None) => {
            // Not configured for mainnet.
        }
        (_, Some(h)) => println!("HTLCv1 non-mainnet activation height from env: {}", h),
        (_, None) => println!("HTLCv1 non-mainnet activation unset (env not provided)"),
    }
    match (network, lwma_activation) {
        (NetworkKind::Mainnet, Some(_)) => {
            // Already active on mainnet; no startup message needed.
        }
        (NetworkKind::Mainnet, None) => {
            // Not configured for mainnet.
        }
        (_, Some(h)) => println!("LWMA non-mainnet activation height from env: {}", h),
        (_, None) => println!("LWMA non-mainnet activation unset (env not provided)"),
    }
    if network == NetworkKind::Mainnet && env_override.is_some() {
        eprintln!("[warn] Ignoring IRIUM_HTLCV1_ACTIVATION_HEIGHT on mainnet; activation source is code-defined");
    }
    if network == NetworkKind::Mainnet && lwma_env_override.is_some() {
        eprintln!("[warn] Ignoring IRIUM_LWMA_ACTIVATION_HEIGHT on mainnet; activation source is code-defined");
    }
    let lwma_v2_activation = resolved_lwma_v2_activation_height(network);
    match (network, lwma_v2_activation) {
        (NetworkKind::Mainnet, Some(_)) => {
            // Already activated on mainnet; no startup message needed.
        }
        (NetworkKind::Mainnet, None) => {
            // Not configured for mainnet.
        }
        (_, Some(h)) => println!("LWMA v2 non-mainnet activation height from env: {}", h),
        (_, None) => println!("LWMA v2 non-mainnet activation unset (env not provided)"),
    }
    if network == NetworkKind::Mainnet && std::env::var("IRIUM_LWMA_V2_ACTIVATION_HEIGHT").is_ok() {
        eprintln!("[warn] Ignoring IRIUM_LWMA_V2_ACTIVATION_HEIGHT on mainnet; activation source is code-defined");
    }
    let params = ChainParams {
        genesis_block: genesis_block.clone(),
        pow_limit,
        htlcv1_activation_height: htlc_activation,
        mpsov1_activation_height: resolved_mpsov1_activation_height(network),
        lwma: LwmaParams::new(lwma_activation, pow_limit),
        lwma_v2: lwma_v2_activation.map(|h| LwmaParams::new_v2(Some(h), pow_limit)),
        auxpow_activation_height: irium_node_rs::activation::resolved_auxpow_activation_height(network),
            btc_spv: irium_node_rs::btc_spv::resolve_btc_spv_params(network),
            ltc_spv: irium_node_rs::ltc_spv::resolve_ltc_spv_params(network),
            htlc_btc_swap_v1_activation_height:
                irium_node_rs::activation::resolved_htlc_btc_swap_v1_activation_height(network),
            btc_swap_bech32_payment_activation_height:
                irium_node_rs::activation::resolved_btc_swap_bech32_payment_activation_height(network),
            htlc_ltc_swap_v1_activation_height:
                irium_node_rs::activation::resolved_htlc_ltc_swap_v1_activation_height(network),
            swap_order_v1_activation_height:
                irium_node_rs::activation::resolved_swap_order_v1_activation_height(network),
            ltc_swap_order_v1_activation_height:
                irium_node_rs::activation::resolved_ltc_swap_order_v1_activation_height(network),
            coinbase_header_batch_activation_height:
                irium_node_rs::activation::resolved_coinbase_header_batch_activation_height(network),
    };
    let mut state = ChainState::new(params);
    if load_persisted {
        load_persisted_blocks(&mut state, &genesis_hash_lc);
    }
    let shared_state = Arc::new(Mutex::new(state));
    {
        let guard = shared_state.lock().unwrap_or_else(|e| e.into_inner());
        let era = network_era(guard.tip_height());
        println!(
            "[Irium] Network Era: {} — {}",
            era.era_name, era.era_description
        );
    }
    let mempool = Arc::new(Mutex::new(MempoolManager::new(mempool_file(), 1000, 100.0, 10_000)));
    let limiter = Arc::new(Mutex::new(rate_limiter()));
    let wallet = Arc::new(Mutex::new(
        WalletManager::new(WalletManager::default_path()),
    ));

    // Attempt to load anchors from the repo root if present. On mainnet,
    // the anchors file is shipped and verified out-of-band.
    let anchors = match AnchorManager::from_default_repo_root(PathBuf::from(".")) {
        Ok(a) => Some(a),
        Err(e) => {
            eprintln!("Failed to load anchors: {}", e);
            std::process::exit(1);
        }
    };
    if let Some(a) = anchors.clone() {
        let mut guard = shared_state.lock().unwrap_or_else(|e| e.into_inner());
        guard.set_anchors(a);
    }

    // Enforce anchor consistency if anchors are present
    if let Some(ref a) = anchors {
        if let Some(latest) = a.get_latest_anchor() {
            let expected = latest.hash.to_lowercase();
            let tip_hash = genesis_hash.to_lowercase();
            if latest.height <= 1 && expected != tip_hash {
                eprintln!(
                    "Anchors mismatch: latest anchor hash {} != genesis hash {}",
                    expected, tip_hash
                );
                std::process::exit(1);
            }
        }
    }

    // Validate anchors against genesis if available.
    if let Some(ref a) = anchors {
        if let Some(latest) = a.get_latest_anchor() {
            if latest.height <= 1 && latest.hash.to_lowercase() != genesis_hash.to_lowercase() {
                eprintln!(
                    "Anchors mismatch: latest anchor hash {} != genesis hash {}",
                    latest.hash, genesis_hash
                );
                std::process::exit(1);
            }
        }
    }

    let agent_string =
        std::env::var("IRIUM_NODE_AGENT").unwrap_or_else(|_| "Irium-Node".to_string());
    let relay_address = node_cfg
        .as_ref()
        .and_then(|c| c.relay_address.clone())
        .or_else(|| std::env::var("IRIUM_RELAY_ADDRESS").ok());
    let marketplace_feed_url: Option<String> = std::env::var("IRIUM_MARKETPLACE_FEED_URL").ok();
    // Self-advertised external "host:port" for CGNAT/NAT escape. When set
    // and globally routable, peers prefer this over TCP-source-IP inference
    // when recording us as dialable. The GUI populates it via UPnP IGD or
    // a public IP-echo service before spawning iriumd; manual operators can
    // set it directly via env or node config.
    let external_endpoint: Option<String> = node_cfg
        .as_ref()
        .and_then(|c| c.external_endpoint.clone())
        .or_else(|| std::env::var("IRIUM_EXTERNAL_ENDPOINT").ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    // Set up P2P node if configured via IRIUM_P2P_BIND env var or node config.
    let p2p_bind_str: Option<String> = std::env::var("IRIUM_P2P_BIND").ok()
        .or_else(|| node_cfg.as_ref().and_then(|cfg| cfg.p2p_bind.clone()));
    let p2p: Option<P2PNode> = if let Some(bind) = p2p_bind_str {
        match bind.parse::<SocketAddr>() {
            Ok(addr) => {
                let node = P2PNode::new(
                    addr,
                    agent_string.clone(),
                    Some(shared_state.clone()),
                    Some(mempool.clone()),
                    relay_address.clone(),
                    marketplace_feed_url.clone(),
                    external_endpoint.clone(),
                );
                // Start listener in the background.
                if let Err(e) = node.start().await {
                    eprintln!("Failed to start P2P listener on {}: {}", addr, e);
                    None
                } else {
                    Some(node)
                }
            }
            Err(e) => {
                eprintln!("Invalid P2P bind address {}: {}", bind, e);
                None
            }
        }
    } else {
        None
    };

    // Build seed list: merge config, signed, and runtime seeds; filter locals.
    // Derive default seed port from the configured P2P bind address; 0 = no default.
    let default_seed_port: u16 = std::env::var("IRIUM_P2P_SEED_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .or_else(|| {
            std::env::var("IRIUM_P2P_BIND").ok()
                .or_else(|| node_cfg.as_ref().and_then(|cfg| cfg.p2p_bind.clone()))
                .as_deref()
                .and_then(|b| b.split(':').next_back())
                .and_then(|p| p.parse().ok())
        })
        .unwrap_or(0);

    ensure_seedlist_in_bootstrap_dir();
    let add_seed_args: Vec<String> = {
        let args: Vec<String> = std::env::args().collect();
        args.windows(2)
            .filter(|w| w[0] == "--add-seed")
            .map(|w| w[1].clone())
            .collect()
    };
    // Item 3 Option B: persist --add-seed args to peers.custom.json (NOT to
    // seedlist.runtime). This keeps the operator-curated list distinct from
    // the auto-discovered peer cache so a hand-edit survives across the
    // periodic seedlist.runtime rewrites that p2p does every 10 min.
    if !add_seed_args.is_empty() {
        append_custom_seeds(&add_seed_args);
    }
    let mut manual_seeds = load_manual_seeds(node_cfg.as_ref());
    // Load operator-curated seeds (peers.custom.json from previous runs plus
    // anything we just appended above) into the manual-seed pool so they get
    // dialed on every start.
    for addr in load_custom_seeds() {
        if !manual_seeds.iter().any(|s| s == &addr) {
            manual_seeds.push(addr);
        }
    }
    // Phase 3: cold-start blockchain peer scan
    if load_runtime_seeds().len() < 5 {
        let (scanned, block_peers) = {
            let guard = shared_state.lock().unwrap_or_else(|e| e.into_inner());
            scan_blocks_for_peers(&guard, 2016)
        };
        let m = block_peers.len();
        eprintln!("[bootstrap] scanned {} blocks, found {} peer announcements", scanned, m);
        if m == 0 {
            eprintln!("[bootstrap] no peer announcements found in chain yet — falling back to signed seedlist");
        } else {
            let runtime_path = storage::bootstrap_dir().join("seedlist.runtime");
            if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(&runtime_path) {
                use std::io::Write;
                for addr in &block_peers {
                    let _ = writeln!(file, "{}", addr);
                }
            }
            for addr in &block_peers {
                let addr_str = addr.to_string();
                if !manual_seeds.iter().any(|s| s == &addr_str) {
                    manual_seeds.push(addr_str);
                }
            }
        }
    }
    let fallback_seeds = load_builtin_fallback_seeds();
    let dns_seed_hosts = load_dns_seed_hosts(node_cfg.as_ref());
    let signed_seeds = if load_runtime_seeds().len() >= 5 {
        Vec::new()
    } else {
        load_signed_seeds()
    };
    let p2p_bind_for_local = std::env::var("IRIUM_P2P_BIND").ok()
        .or_else(|| node_cfg.as_ref().and_then(|cfg| cfg.p2p_bind.clone()));
    let local_ips = local_ip_set(p2p_bind_for_local.as_ref());

    let startup_missing_window = storage::missing_persisted_in_window();

    // Connect to seed peers using a basic handshake and keep retrying in background.
    if let Some(node) = p2p.clone() {
        let manual_seeds = manual_seeds.clone();
        let fallback_seeds = fallback_seeds.clone();
        let dns_seed_hosts = dns_seed_hosts.clone();
        let signed_seeds = signed_seeds.clone();
        let local_ips = local_ips.clone();
        let agent_clone = agent_string.clone();
        let shared_clone = shared_state.clone();
        tokio::spawn(async move {
            let node = node;
            let mut no_seed_logged = false;
            let mut bootstrap_logged = false;

            loop {
                let persisted_peers = node.peers_snapshot().await;
                let persisted_seeds =
                    load_persisted_startup_seeds(&persisted_peers, default_seed_port);
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    node.connect_known_peers(5),
                )
                .await;
                let (dns_seed_addrs, dns_filtered_local) =
                    resolve_dns_seed_addrs(&dns_seed_hosts, default_seed_port, &local_ips).await;
                let (seeds, mut seed_info) = build_seed_addrs(
                    &persisted_seeds,
                    &manual_seeds,
                    &fallback_seeds,
                    &dns_seed_addrs,
                    &signed_seeds,
                    default_seed_port,
                    &local_ips,
                );
                seed_info.filtered_local += dns_filtered_local;
                if !bootstrap_logged {
                    eprintln!(
                        "[{}] [bootstrap] persisted={} manual={} fallback={} dns_hosts={} dns_addrs={} signed={} filtered_local={}",
                        Utc::now().format("%H:%M:%S"),
                        seed_info.persisted,
                        seed_info.manual,
                        seed_info.fallback,
                        dns_seed_hosts.len(),
                        seed_info.dns,
                        seed_info.signed,
                        seed_info.filtered_local,
                    );
                    bootstrap_logged = true;
                }
                if seeds.is_empty() {
                    if !no_seed_logged {
                        if seed_info.filtered_local > 0 {
                            // All configured bootstrap targets resolved to local addresses.
                        } else {
                            println!(
                                "[{}] no bootstrap seeds resolved; continuing with persisted peers and inbound discovery",
                                Utc::now().format("%H:%M:%S")
                            );
                        }
                        no_seed_logged = true;
                    }
                    let cur_peers = node.peer_count().await;
                    tokio::time::sleep(if cur_peers < 2 { std::time::Duration::from_secs(5) } else { std::time::Duration::from_secs(30) }).await;
                    continue;
                }
                no_seed_logged = false;

                // Dedup seeds to avoid churn when the seed list contains duplicates.
                let mut seeds_seen: std::collections::HashSet<std::net::SocketAddr> =
                    std::collections::HashSet::new();
                let mut seeds_ip_seen: std::collections::HashSet<std::net::IpAddr> =
                    std::collections::HashSet::new();

                let height = {
                    let chain = shared_clone.lock().unwrap_or_else(|e| e.into_inner());
                    chain.tip_height()
                };
                let mut seeds_to_dial: Vec<std::net::SocketAddr> = Vec::new();
                for addr in &seeds {
                    if !seeds_seen.insert(*addr) {
                        continue;
                    }
                    if !seeds_ip_seen.insert(addr.ip()) {
                        continue;
                    }
                    if node.is_connected(addr).await {
                        continue;
                    }
                    if node.is_self_ip(addr.ip()).await {
                        continue;
                    }
                    if node.is_ip_connected(addr.ip()).await {
                        continue;
                    }
                    if !node.outbound_dial_allowed(addr).await {
                        continue;
                    }
                    seeds_to_dial.push(*addr);
                }

                // Dial all eligible seeds in parallel so a slow/timed-out seed
                // does not delay connections to the others.
                let mut join_set = tokio::task::JoinSet::new();
                for addr in seeds_to_dial {
                    let node_c = node.clone();
                    let agent_c = agent_clone.clone();
                    join_set.spawn(async move {
                        if let Some(suppressed) = dial_seed_log_allowed(0, addr.ip()) {
                            let mut line = format!(
                                "[{}] dialing seed {} (h={})",
                                Utc::now().format("%H:%M:%S"),
                                addr,
                                height
                            );
                            if suppressed > 0 {
                                line.push_str(&format!(" (suppressed {} repeats)", suppressed));
                            }
                            println!("{}", line);
                        }
                        if let Err(e) = node_c.connect_and_handshake(addr, height, &agent_c).await {
                            let msg = e.to_string();
                            if !msg.contains("dial backoff") && !msg.contains("dial in progress") {
                                if let Some(suppressed) = dial_seed_log_allowed(1, addr.ip()) {
                                    let mut line = format!(
                                        "[{}] outbound {} failed: {}",
                                        Utc::now().format("%H:%M:%S"),
                                        addr,
                                        msg
                                    );
                                    if suppressed > 0 {
                                        line.push_str(&format!(" (suppressed {} repeats)", suppressed));
                                    }
                                    eprintln!("{}", line);
                                }
                            }
                        }
                    });
                }
                while join_set.join_next().await.is_some() {}

                // Adaptive wait: reconnect faster when low on peers.
                let cur_peers = node.peer_count().await;
                tokio::time::sleep(if cur_peers < 2 { std::time::Duration::from_secs(5) } else { std::time::Duration::from_secs(30) }).await;
            }
        });
    }

    if startup_missing_window > 0 {
        if let Some(node) = p2p.clone() {
            let shared_for_gap = shared_state.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let start_hash = {
                    let guard = shared_for_gap.lock().unwrap_or_else(|e| e.into_inner());
                    guard.tip_hash()
                };
                eprintln!(
                    "[i] persist gap healer: requesting network sync burst for missing persisted window blocks (missing_in_window={})",
                    startup_missing_window
                );
                let _ = node.force_sync_burst_from_tip(start_hash).await;
            });
        }
    }

    let status_height_cache = Arc::new(AtomicU64::new({
        let g = shared_state.lock().unwrap_or_else(|e| e.into_inner());
        g.tip_height()
    }));
    let status_peer_count_cache = Arc::new(AtomicUsize::new(0));
    let status_sybil_cache = Arc::new(AtomicU8::new(0));
    let status_persisted_height_cache = Arc::new(AtomicU64::new(storage::persisted_height()));
    let status_persist_queue_cache = Arc::new(AtomicUsize::new(storage::persist_queue_len()));
    let status_persisted_contiguous_cache =
        Arc::new(AtomicU64::new(storage::persisted_contiguous_height()));
    let status_persisted_max_on_disk_cache =
        Arc::new(AtomicU64::new(storage::persisted_max_height_on_disk()));
    let status_quarantine_count_cache = Arc::new(AtomicU64::new(storage::quarantine_count()));
    let status_persisted_window_tip_cache =
        Arc::new(AtomicU64::new(storage::persisted_window_tip()));
    let status_missing_persisted_in_window_cache =
        Arc::new(AtomicU64::new(storage::missing_persisted_in_window()));
    let status_missing_or_mismatch_in_window_cache =
        Arc::new(AtomicU64::new(storage::missing_or_mismatch_in_window()));
    let status_expected_hash_coverage_in_window_cache =
        Arc::new(AtomicU64::new(storage::expected_hash_coverage_in_window()));
    let status_expected_hash_window_span_cache =
        Arc::new(AtomicU64::new(storage::expected_hash_window_span()));
    let status_best_header_hash_cache = Arc::new(Mutex::new({
        let g = shared_state.lock().unwrap_or_else(|e| e.into_inner());
        let best = compute_best_header_tip_from_chain(&g, &genesis_hash);
        best.hash
    }));

    // Periodic heartbeat logging to surface peers and seedlist.
    if let Some(ref node) = p2p {
        let node_clone = node.clone();
        let chain_clone = shared_state.clone();
        let mempool_clone = mempool.clone();
        let genesis_hex = genesis_hash.clone();
        let status_height = status_height_cache.clone();
        let status_peer_count = status_peer_count_cache.clone();
        let status_sybil = status_sybil_cache.clone();
        tokio::spawn(async move {
            let seed_mgr = SeedlistManager::new(128);
            let mut hb_ticks: u64 = 0;
            let mut maintenance_ticks: u64 = 0;
            let mut last_progress_height: u64 = 0;
            let mut stalled_ticks: u32 = 0;
            let mut last_tip_hash: String = genesis_hex.clone();
            let mut last_tip_bytes: [u8; 32] = [0u8; 32];
            let mut last_best_header_height: u64 = 0;
            let mut last_sync_burst_at: Option<std::time::Instant> = None;
            let mut last_mempool_size: usize = 0;
            let mut last_peer_summary = None;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                let peers = tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    node_clone.peers_snapshot(),
                )
                .await
                .unwrap_or_default();
                let current_peer_count = tokio::time::timeout(
                    std::time::Duration::from_millis(250),
                    node_clone.peer_count(),
                )
                .await
                .unwrap_or(peers.len());
                maintenance_ticks = maintenance_ticks.wrapping_add(1);
                // Emergency reconnect when 0 peers; also routine reconnect every 30s.
                if current_peer_count == 0 || maintenance_ticks.is_multiple_of(6) {
                    let maintenance_node = node_clone.clone();
                    tokio::spawn(async move {
                        let _ = tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            maintenance_node.refresh_seedlist(),
                        )
                        .await;
                        let _ = tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            maintenance_node.connect_known_peers(5),
                        )
                        .await;
                    });
                }
                let seeds = seed_mgr.merged_seedlist();

                let mut peer_ips = std::collections::HashSet::new();
                let mut peer_list: Vec<String> = Vec::new();
                for p in peers.iter() {
                    let parts: Vec<&str> = p.multiaddr.split("/").collect();
                    if parts.len() >= 5 {
                        let ip = parts[2];
                        if peer_ips.insert(ip.to_string()) {
                            let label = p.agent.clone().unwrap_or_else(|| "peer".to_string());
                            peer_list.push(label);
                        }
                    } else if peer_ips.insert(p.multiaddr.clone()) {
                        let label = p.agent.clone().unwrap_or_else(|| "peer".to_string());
                        peer_list.push(label);
                    }
                }
                if peer_list.is_empty() {
                    peer_list.push("-".to_string());
                }

                let best_peer_height = peers.iter().filter_map(|p| p.last_height).max();

                let mut seed_ips = std::collections::HashSet::new();
                let mut seed_list: Vec<String> = Vec::new();
                for s in seeds.iter() {
                    let parts: Vec<&str> = s.split('/').collect();
                    if parts.len() >= 5 {
                        let ip = parts[2];
                        if seed_ips.insert(ip.to_string()) {
                            seed_list.push(mask_seed_label(ip));
                        }
                    } else if seed_ips.insert(s.clone()) {
                        seed_list.push(mask_seed_label(s));
                    }
                }
                if seed_list.is_empty() {
                    seed_list.push("-".to_string());
                }

                let (local_height, tip_hash, tip_bytes, best_header_height) =
                    match chain_clone.try_lock() {
                        Ok(g) => {
                            let local_height = g.tip_height();
                            let tip_bytes =
                                g.chain.last().map(|b| b.header.hash_for_height(local_height)).unwrap_or([0u8; 32]);
                            let tip = hex::encode(tip_bytes);
                            let best_hash = g.best_header_hash();
                            let best_header_height = g
                                .headers
                                .get(&best_hash)
                                .map(|hw| hw.height)
                                .or_else(|| g.heights.get(&best_hash).copied())
                                .unwrap_or(local_height)
                                .max(local_height);
                            (local_height, tip, tip_bytes, best_header_height)
                        }
                        Err(_) => (
                            status_height.load(Ordering::Relaxed),
                            last_tip_hash.clone(),
                            last_tip_bytes,
                            last_best_header_height.max(status_height.load(Ordering::Relaxed)),
                        ),
                    };
                last_tip_hash = tip_hash.clone();
                last_tip_bytes = tip_bytes;
                last_best_header_height = best_header_height;

                let mempool_size = match mempool_clone.try_lock() {
                    Ok(g) => g.len(),
                    Err(_) => last_mempool_size,
                };
                last_mempool_size = mempool_size;

                status_height.store(local_height, Ordering::Relaxed);
                status_peer_count.store(current_peer_count, Ordering::Relaxed);
                let sybil_now = match tokio::time::timeout(
                    std::time::Duration::from_millis(250),
                    node_clone.current_sybil_difficulty(),
                )
                .await
                {
                    Ok(v) => v,
                    Err(_) => status_sybil.load(Ordering::Relaxed),
                };
                status_sybil.store(sybil_now, Ordering::Relaxed);

                let next_height = local_height.saturating_add(1);
                let peer_height = best_peer_height.unwrap_or(0);
                let sync_target_height = best_header_height.max(local_height);
                // Keep local height authoritative for validation, but expose the
                // best known header height separately in heartbeat logs so sync
                // lag is visible instead of being flattened into local height.
                let chain_height = sync_target_height;

                hb_ticks = hb_ticks.wrapping_add(1);

                let dbg = node_clone.sync_debug_snapshot().await;
                let peer_dbg = node_clone.peer_telemetry_snapshot().await;
                let seed_count = seeds.len();

                // Use validated best-header progress for sync decisions (peer-advertised
                // heights are untrusted and can cause false stall churn). When best_header
                // is genuinely above local we trigger a fast sync burst.
                //
                // Background: the self-perpetuating-tip stall observed on irium-eu after
                // the v1.9.14 deploy (local stuck at 21549 while the network was at 21833)
                // had two root causes:
                //   1. trusted_remote_height (p2p.rs) capped every peer-advertised height
                //      to `best_h.max(local_h)`, so on a fresh restart with
                //      `best_h == local_h` every peer was stored at exactly local_h —
                //      `best_peer_height` could never exceed local_height. (Fixed in p2p.rs:
                //      the cap is only applied when best_h is strictly above local_h.)
                //   2. The `behind` check below uses `sync_target_height`, which is derived
                //      only from our own validated headers — so if we never get headers
                //      above local, `behind` is permanently false and no burst fires.
                // The periodic probe below is the escape hatch for case (2): every ~60s
                // (12 * 5s heartbeats) it forces a sync burst regardless of `behind`,
                // using our current tip as the locator. If peers really do have higher
                // headers, the burst pulls them in and `sync_target_height` advances
                // normally; if they don't, the burst is a cheap no-op.
                let behind = sync_target_height >= local_height.saturating_add(3);
                let header_only_stall = dbg.sync_requests > 0 && dbg.getblocks_inflight == 0;
                let need_sync_burst = behind && (dbg.getblocks_inflight == 0 || header_only_stall);
                // Periodic unconditional probe — fires roughly every 60 seconds even when
                // `behind == false`. Without this, any future regression that pins
                // `best_peer == local` (cap bug, handshake bug, network partition that
                // dissolves with the rest of the chain ahead, etc.) would silently strand
                // the node at its current tip until manual intervention.
                let periodic_probe = hb_ticks > 0 && hb_ticks.is_multiple_of(12);
                if need_sync_burst || periodic_probe {
                    let min_gap = if need_sync_burst {
                        std::time::Duration::from_secs(10)
                    } else {
                        std::time::Duration::from_secs(50)
                    };
                    let burst_ok = last_sync_burst_at
                        .map(|t| t.elapsed() >= min_gap)
                        .unwrap_or(true);
                    if burst_ok {
                        let burst_node = node_clone.clone();
                        let start = tip_bytes;
                        tokio::spawn(async move {
                            let _ = burst_node.force_sync_burst_from_tip(start).await;
                        });
                        last_sync_burst_at = Some(std::time::Instant::now());
                    }
                }

                // Periodic sync status line to diagnose stalls quickly.
                if hb_ticks.is_multiple_of(6) {
                    let ahead = sync_target_height.saturating_sub(local_height);
                    eprintln!(
                        "[{}] [🔁 sync] status local={} best_header={} best_peer={} ahead={} peers={} inflight(getheaders)={} inflight(getblocks)={} handshake_failures={}",
                        Utc::now().format("%H:%M:%S"),
                        local_height,
                        sync_target_height,
                        peer_height,
                        ahead,
                        current_peer_count,
                        dbg.sync_requests,
                        dbg.getblocks_inflight,
                        dbg.handshake_failures
                    );
                }

                if hb_ticks.is_multiple_of(12) {
                    let prev = last_peer_summary.unwrap_or(peer_dbg);
                    let delta_attempts = peer_dbg
                        .outbound_dial_attempts_total
                        .saturating_sub(prev.outbound_dial_attempts_total);
                    let delta_success = peer_dbg
                        .outbound_dial_success_total
                        .saturating_sub(prev.outbound_dial_success_total);
                    let delta_fail = peer_dbg
                        .outbound_dial_failure_total
                        .saturating_sub(prev.outbound_dial_failure_total);
                    let delta_timeout = peer_dbg
                        .outbound_dial_failure_timeout_total
                        .saturating_sub(prev.outbound_dial_failure_timeout_total);
                    let delta_refused = peer_dbg
                        .outbound_dial_failure_refused_total
                        .saturating_sub(prev.outbound_dial_failure_refused_total);
                    let delta_no_route = peer_dbg
                        .outbound_dial_failure_no_route_total
                        .saturating_sub(prev.outbound_dial_failure_no_route_total);
                    let delta_banned = peer_dbg
                        .outbound_dial_failure_banned_total
                        .saturating_sub(prev.outbound_dial_failure_banned_total);
                    let delta_other = peer_dbg
                        .outbound_dial_failure_other_total
                        .saturating_sub(prev.outbound_dial_failure_other_total);
                    let delta_handshake = peer_dbg
                        .handshake_failures_total
                        .saturating_sub(prev.handshake_failures_total);
                    let delta_temp_bans = peer_dbg
                        .temp_bans_total
                        .saturating_sub(prev.temp_bans_total);
                    let delta_inbound = peer_dbg
                        .inbound_accepted_total
                        .saturating_sub(prev.inbound_accepted_total);
                    eprintln!(
                        "[{}] [peer_mgr] summary peers={} unique_ips={} attempted={} outbound_attempts={} success={} failure={} timeout={} refused={} no_route={} banned={} other={} inbound_accepted={} handshake_failures={} temp_bans={} banned_peers={} seedlist={}",
                        Utc::now().format("%H:%M:%S"),
                        current_peer_count,
                        peer_dbg.unique_connected_peer_ips,
                        peer_dbg.attempted_peer_ips,
                        delta_attempts,
                        delta_success,
                        delta_fail,
                        delta_timeout,
                        delta_refused,
                        delta_no_route,
                        delta_banned,
                        delta_other,
                        delta_inbound,
                        delta_handshake,
                        delta_temp_bans,
                        peer_dbg.banned_peers,
                        seed_count,
                    );
                    last_peer_summary = Some(peer_dbg);
                }

                // If we're behind OR stuck in header-only mode and not making progress, clear
                // throttles and reconnect peers to kick block body sync.
                if behind || header_only_stall {
                    if local_height == last_progress_height {
                        stalled_ticks = stalled_ticks.saturating_add(1);
                    } else {
                        last_progress_height = local_height;
                        stalled_ticks = 0;
                    }

                    if stalled_ticks >= 6 {
                        eprintln!(
                            "[{}] [🔁 sync] WARN stalled (local={}, best_header={}, best_peer={}, headers_inflight={}, getblocks_inflight={}); clearing sync throttles and reconnecting",
                            Utc::now().format("%H:%M:%S"),
                            local_height,
                            sync_target_height,
                            peer_height,
                            dbg.sync_requests,
                            dbg.getblocks_inflight
                        );
                        let stalled_node = node_clone.clone();
                        tokio::spawn(async move {
                            stalled_node.clear_sync_throttles().await;
                            stalled_node.clear_transient_headers().await;
                            let _ = tokio::time::timeout(
                                std::time::Duration::from_secs(5),
                                stalled_node.connect_known_peers(5),
                            )
                            .await;
                        });
                        stalled_ticks = 0;
                    }
                } else {
                    last_progress_height = local_height;
                    stalled_ticks = 0;
                }

                let peer_sample = peer_list
                    .iter()
                    .take(5)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ");
                let seed_count = seed_list.len();

                if json_log_enabled() {
                    eprintln!(
                        "{}",
                        json!({
                            "ts": Utc::now().format("%H:%M:%S").to_string(),
                            "level": "info",
                            "event": "heartbeat",
                            "height": local_height,
                            "local_height": local_height,
                            "chain_height": chain_height,
                            "peer_height": peer_height,
                            "next_height": next_height,
                            "peers": current_peer_count,
                            "peer_sample": peer_sample,
                            "seed_count": seed_count,
                            "agent": std::env::var("IRIUM_NODE_AGENT").unwrap_or_else(|_| "Irium-Node".to_string()),
                            "tip": tip_hash,
                            "mempool": mempool_size,
                        })
                    );
                } else {
                    let short_tip = tip_hash.chars().take(12).collect::<String>();
                    eprintln!(
                        "[{}] ❤️ heartbeat Irium best height={} 🏠 local height={} 🧱 next height={} ⛏ tip={} 👥 peers={} 🌱 seedlist={} 🧺 mempool={}",
                        Utc::now().format("%H:%M:%S"),
                        chain_height,
                        local_height,
                        next_height,
                        short_tip,
                        current_peer_count,
                        seed_count,
                        mempool_size
                    );
                }
            }
        });
    }

    {
        let chain_for_gap_healer = shared_state.clone();
        let p2p_for_gap_healer = p2p.clone();
        let genesis_hash_for_gap_healer = genesis_hash_lc.clone();
        tokio::spawn(async move {
            let interval_secs = std::env::var("IRIUM_GAP_HEALER_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(30)
                .clamp(10, 600);
            let batch_size = std::env::var("IRIUM_GAP_HEALER_BATCH")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(100)
                .clamp(1, 500);

            loop {
                tokio::time::sleep(Duration::from_secs(interval_secs)).await;

                let mut pending = storage::gap_healer_pending_count();
                if pending == 0 {
                    // Opportunistically scan the next segment above contiguous persisted
                    // height and queue missing/mismatched files for repair.
                    let expected_segment = {
                        let guard = chain_for_gap_healer
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        let tip = guard.tip_height();
                        let start = storage::persisted_contiguous_height().saturating_add(1);
                        if start > tip {
                            Vec::new()
                        } else {
                            let end = (start.saturating_add(799)).min(tip);
                            let mut v =
                                Vec::with_capacity((end.saturating_sub(start) + 1) as usize);
                            for h in start..=end {
                                if let Some(block) = guard.chain.get(h as usize) {
                                    v.push((h, block.header.hash_for_height(h)));
                                }
                            }
                            v
                        }
                    };

                    if !expected_segment.is_empty() {
                        let blocks_dir = storage::blocks_dir();
                        let current_contiguous = storage::persisted_contiguous_height();
                        let (discovered, contiguous_end) = discover_persist_mismatch_heights(
                            &expected_segment,
                            &blocks_dir,
                            &genesis_hash_for_gap_healer,
                            current_contiguous,
                        );

                        if contiguous_end > current_contiguous {
                            storage::force_set_persisted_contiguous_height(contiguous_end);
                        }

                        if !discovered.is_empty() {
                            storage::set_gap_healer_target_heights(&discovered);
                            pending = storage::gap_healer_pending_count();
                            eprintln!(
                                "[i] gap healer discovered backlog: queued={} contiguous={} tip={}",
                                pending,
                                storage::persisted_contiguous_height(),
                                expected_segment.last().map(|(h, _)| *h).unwrap_or(0)
                            );
                        }
                    }
                }

                if pending == 0 {
                    storage::set_gap_healer_active(false);
                    continue;
                }
                storage::set_gap_healer_active(true);

                let adaptive_batch = if pending > 5_000 {
                    batch_size.max(300)
                } else if pending > 2_000 {
                    batch_size.max(200)
                } else if pending > 500 {
                    batch_size.max(120)
                } else {
                    batch_size
                };
                let batch = storage::gap_healer_batch(adaptive_batch);
                if batch.is_empty() {
                    continue;
                }

                let (tip_height, tip_bytes) = {
                    let guard = chain_for_gap_healer
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    let th = guard.tip_height();
                    let tip_bytes = guard
                        .chain
                        .last()
                        .map(|b| b.header.hash_for_height(th))
                        .unwrap_or([0u8; 32]);
                    (th, tip_bytes)
                };

                let mut filled: usize = 0;
                for h in batch.iter().copied() {
                    if h > tip_height {
                        continue;
                    }

                    let block_opt = {
                        let guard = chain_for_gap_healer
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        guard.chain.get(h as usize).cloned()
                    };

                    let Some(block) = block_opt else {
                        continue;
                    };

                    match storage::write_block_json(h, &block) {
                        Ok(_) => {
                            if storage::gap_healer_mark_filled(h) {
                                filled = filled.saturating_add(1);
                                // Per-height progress logs are intentionally suppressed to avoid
                                // flooding journals during large backfills; batch summary is logged below.
                            }
                        }
                        Err(e) => {
                            eprintln!("[warn] gap healer persist failed for height {}: {}", h, e);
                        }
                    }
                }

                let remaining = storage::gap_healer_pending_count();
                eprintln!(
                    "[i] gap healer batch: requested={} filled={} remaining={}",
                    batch.len(),
                    filled,
                    remaining
                );

                if filled == 0 {
                    if let Some(node) = p2p_for_gap_healer.clone() {
                        let _ = node.force_sync_burst_from_tip(tip_bytes).await;
                    }
                }
            }
        });
    }
    let (event_tx, _) = broadcast::channel::<std::sync::Arc<String>>(WS_BROADCAST_CAPACITY);

    let app_state = AppState {
        chain: shared_state.clone(),
        genesis_hash: genesis_hash.clone(),
        mempool: mempool.clone(),
        wallet: wallet.clone(),
        anchors,
        p2p,
        limiter: limiter.clone(),
        status_height_cache,
        status_peer_count_cache,
        status_sybil_cache,
        status_persisted_height_cache,
        status_persist_queue_cache,
        status_persisted_contiguous_cache,
        status_persisted_max_on_disk_cache,
        status_quarantine_count_cache,
        status_persisted_window_tip_cache,
        status_missing_persisted_in_window_cache,
        status_missing_or_mismatch_in_window_cache,
        status_expected_hash_coverage_in_window_cache,
        status_expected_hash_window_span_cache,
        status_best_header_hash_cache,
        proof_store: Arc::new(Mutex::new(ProofStore::new(
            storage::state_dir().join("proofs.json"),
        ))),
        policy_store: Arc::new(Mutex::new(PolicyStore::new(
            storage::state_dir().join("policies.json"),
        ))),
        event_tx: event_tx.clone(),
        proof_heights: Arc::new(Mutex::new(std::collections::HashMap::new())),
        disputes_index: Arc::new(Mutex::new(load_all_disputes_at_startup())),
        resolvers_index: Arc::new(Mutex::new(load_all_resolvers_at_startup())),
        btc_template_headers_cache: Arc::new(Mutex::new(None)),
        ltc_template_headers_cache: Arc::new(Mutex::new(None)),
    };

    // Spawn the in-process header-sync background tasks. Each one no-ops
    // (and logs once) when the corresponding `resolved_*_spv_relay_activation_height`
    // is `None` on the running network — so devnet / dev nodes pay nothing
    // for chains they haven't enabled. Replaces the standalone
    // src/bin/{btc,ltc}-header-sync.rs binaries + systemd timers.
    // v1.9.54: pre-seed BTC headers from mempool.space on fresh installs so
    // Irium blocks that carry a BtcHeaderBatch tx whose first header references
    // a BTC block past the anchor can be applied. Runs as a tokio::spawn task
    // so iriumd's HTTP server and P2P stack come up immediately — fetching
    // 70k+ headers can take 15+ minutes against historical mempool.space data
    // and there is no reason to block RPC during that time. Blocks that arrive
    // before bootstrap completes and reference an un-fetched BTC header will
    // fail validation and be re-requested from peers; the v1.9.52 idempotency
    // fix makes the eventual re-application a no-op.
    {
        let s = app_state.clone();
        tokio::spawn(async move {
            if let Err(e) = maybe_bootstrap_btc_headers(s, network).await {
                eprintln!("[btc-bootstrap] returned error: {}", e);
            }
        });
    }

    maybe_spawn_btc_header_sync(app_state.clone(), network);
    maybe_spawn_ltc_header_sync(app_state.clone(), network);
    spawn_mempool_rebroadcast(app_state.clone());
    spawn_offer_rebroadcast(app_state.clone());

    // Background task: emit block.new events when chain height advances.
    {
        let block_event_tx = event_tx.clone();
        let block_chain = app_state.chain.clone();
        let reorg_proof_heights = app_state.proof_heights.clone();
        let reorg_proof_store = app_state.proof_store.clone();
        let block_disputes = app_state.disputes_index.clone();
        let block_resolvers = app_state.resolvers_index.clone();
        let block_p2p = app_state.p2p.clone();
        tokio::spawn(async move {
            let mut last_known_height: u64 = 0;
            let mut last_known_hash = String::new();
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                let (h, hash) = {
                    let g = block_chain.lock().unwrap_or_else(|e| e.into_inner());
                    let height = g.tip_height();
                    let hash = g.chain.last().map(|b| hex::encode(b.header.hash_for_height(height))).unwrap_or_default();
                    (height, hash)
                };
                if h < last_known_height && last_known_height > 0 {
                    // Reorg detected: tip rewound. Emit proof_reorged for any proof
                    // submitted at a height now above the new tip.
                    let reorged_agreements = {
                        let heights = reorg_proof_heights.lock().unwrap_or_else(|e| e.into_inner());
                        let store = reorg_proof_store.lock().unwrap_or_else(|e| e.into_inner());
                        let mut agreements: std::collections::HashSet<String> = Default::default();
                        for (proof_id, &submitted_at) in heights.iter() {
                            if submitted_at > h {
                                // This proof was submitted at a height that is now reorganized.
                                if let Some(proof) = store.list_all().into_iter().find(|p| p.proof_id == *proof_id) {
                                    agreements.insert(proof.agreement_hash.clone());
                                }
                            }
                        }
                        agreements
                    };
                    for agreement_hash in reorged_agreements {
                        emit_event(&block_event_tx, "agreement.proof_reorged", serde_json::json!({
                            "agreement_hash": agreement_hash,
                            "reorg_tip": h,
                            "previous_tip": last_known_height,
                            "note": "One or more proofs for this agreement were submitted at a height that has been reorganized. Resubmit the proof once the chain stabilizes.",
                        }));
                    }
                }
                if h > last_known_height || (h == last_known_height && hash != last_known_hash && !hash.is_empty()) {
                    if last_known_height > 0 {
                        emit_event(&block_event_tx, "block.new", serde_json::json!({
                            "height": h,
                            "hash": hash,
                        }));
                        // Stage 3.2: scan newly-confirmed blocks for dispute/resolver anchor OP_RETURNs.
                        scan_new_blocks_for_dispute_anchors(
                            &block_chain,
                            &block_disputes,
                            &block_resolvers,
                            &block_event_tx,
                            last_known_height,
                            h,
                        );
                    }
                    last_known_height = h;
                    last_known_hash = hash;
                }
                // Stage 3.2 + 3.3.1: escalation tick — disputes whose primary resolver missed window go to fallback.
                escalation_tick(&block_disputes, &block_event_tx, &block_p2p, h).await;
            }
        });
    }

    // LAYER 1 receive-side: drain P2P OfferTakeNotification inbox and
    // mutate matching local offer files. Runs on a 2 s cadence — quicker
    // than the 5 s fs-watcher because the take-broadcast latency directly
    // determines how long peers can race to take an already-taken offer.
    if let Some(ref take_p2p) = app_state.p2p {
        let drain_node = take_p2p.clone();
        let drain_event_tx = event_tx.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                for json in drain_node.drain_offer_take_notifications().await {
                    if let Err(e) = process_received_offer_take(&json, &drain_event_tx) {
                        eprintln!("[offer-take] {}", e);
                    }
                }
            }
        });
    }

    // Phase 1A+1B: drain incoming OfferBroadcast payloads and write each
    // to ~/.irium/offers/offer-<offer_id>.json so /offers/feed serves it
    // locally. The p2p layer has already done dedup + rate limit + size
    // check + parse validation (offer_id, status==open) and re-broadcast
    // to its other peers, so this drainer's only job is durable persistence.
    // We do NOT overwrite an existing offer file - if the local node is
    // the offer's seller, the locally-created file is authoritative; if a
    // duplicate ID arrives from a different seller it's dropped here to
    // avoid the gossip layer rewriting our own offers. 2 s cadence mirrors
    // the offer-take drainer above.
    if let Some(ref broadcast_p2p) = app_state.p2p {
        let drain_node = broadcast_p2p.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                let offers_dir = offers_feed_dir();
                if !offers_dir.exists() {
                    if let Err(e) = std::fs::create_dir_all(&offers_dir) {
                        eprintln!("[offer-broadcast] create_dir_all {}: {}", offers_dir.display(), e);
                        continue;
                    }
                }
                for json in drain_node.drain_offer_broadcasts().await {
                    let val: serde_json::Value = match serde_json::from_str(&json) {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!("[offer-broadcast] drop unparseable: {}", e);
                            continue;
                        }
                    };
                    let id = match val.get("offer_id").and_then(|v| v.as_str()) {
                        Some(s) if !s.is_empty() => s.to_string(),
                        _ => {
                            eprintln!("[offer-broadcast] drop missing offer_id");
                            continue;
                        }
                    };
                    if id.len() > 128 || id.is_empty()
                        || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                    {
                        eprintln!("[offer-broadcast] drop unsafe offer_id: {}", id);
                        continue;
                    }
                    let path = offers_dir.join(format!("offer-{}.json", id));
                    if path.exists() {
                        continue;
                    }
                    if let Err(e) = std::fs::write(&path, &json) {
                        eprintln!("[offer-broadcast] write {}: {}", path.display(), e);
                    }
                }
            }
        });
    }

    // Stage 3.3.1: drain dispute P2P inboxes and apply to local indexes.
    if let Some(ref dispute_p2p) = app_state.p2p {
        let drain_node = dispute_p2p.clone();
        let drain_disputes = app_state.disputes_index.clone();
        let drain_event_tx = event_tx.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                for json in drain_node.drain_dispute_raised_notifications().await {
                    process_received_dispute_raise(&json, &drain_disputes, &drain_event_tx);
                }
                for json in drain_node.drain_dispute_evidence_notifications().await {
                    process_received_dispute_evidence(&json, &drain_disputes, &drain_event_tx);
                }
                for json in drain_node.drain_dispute_resolved_notifications().await {
                    process_received_dispute_resolved(&json, &drain_disputes, &drain_event_tx);
                }
                for json in drain_node.drain_dispute_escalated_notifications().await {
                    process_received_dispute_escalated(&json, &drain_disputes, &drain_event_tx);
                }
            }
        });
    }

    // Background task: drain P2P proof gossip inbox and submit locally.
    if let Some(ref gossip_p2p) = app_state.p2p {
        let drain_node = gossip_p2p.clone();
        let drain_proof_store = app_state.proof_store.clone();
        let drain_event_tx = event_tx.clone();
        let drain_heights = app_state.proof_heights.clone();
        let drain_chain_for_gossip = app_state.chain.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                let proofs = drain_node.drain_proof_gossip().await;
                if proofs.is_empty() {
                    continue;
                }
                let gossip_tip_height = {
                    let g = drain_chain_for_gossip.lock().unwrap_or_else(|e| e.into_inner());
                    g.tip_height()
                };
                let mut store = drain_proof_store.lock().unwrap_or_else(|e| e.into_inner());
                for json in proofs {
                    if let Ok(proof) = serde_json::from_str::<SettlementProof>(&json) {
                        let ah_for_evt = proof.agreement_hash.clone();
                        let pid_for_evt = proof.proof_id.clone();
                        if let Ok(outcome) = store.submit(proof) {
                            if outcome.accepted {
                                // Phase 7: record gossip proof receipt height.
                                {
                                    let mut heights = drain_heights.lock().unwrap_or_else(|e| e.into_inner());
                                    heights.insert(pid_for_evt.clone(), gossip_tip_height);
                                }
                                emit_event(&drain_event_tx, "proof.gossip_received", serde_json::json!({
                                    "agreement_hash": ah_for_evt,
                                    "proof_id": pid_for_evt,
                                }));
                                let rebroadcast = drain_node.clone();
                                let j = json.clone();
                                tokio::spawn(async move {
                                    rebroadcast.broadcast_proof(&j).await;
                                });
                            }
                        }
                    }
                }
            }
        });
    }

    // Background task: detect peer connect/disconnect events.
    {
        let peer_event_tx = event_tx.clone();
        let peer_p2p = app_state.p2p.clone();
        tokio::spawn(async move {
            let mut known_peers: HashSet<String> = HashSet::new();
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                if let Some(ref node) = peer_p2p {
                    let current = node.peers_snapshot().await;
                    let current_set: HashSet<String> =
                        current.iter().map(|p| p.multiaddr.clone()).collect();
                    for addr in current_set.difference(&known_peers) {
                        emit_event(&peer_event_tx, "peer.connected", serde_json::json!({
                            "multiaddr": addr,
                        }));
                    }
                    for addr in known_peers.difference(&current_set) {
                        emit_event(&peer_event_tx, "peer.disconnected", serde_json::json!({
                            "multiaddr": addr,
                        }));
                    }
                    known_peers = current_set;
                }
            }
        });
    }

    // Background task: detect new/taken offers from local offer store.
    // Also drives LAYER 2 (open→expired when chain tip passes
    // timeout_height) and LAYER 3 (taken→open auto-relist when the buyer
    // never anchors the agreement on-chain within the grace window).
    {
        let offer_event_tx = event_tx.clone();
        let watcher_chain = app_state.chain.clone();
        // Phase 1A+1B: clone the P2P handle so the watcher can announce
        // newly-created local offers to peers. None when P2P is disabled.
        let watcher_p2p = app_state.p2p.clone();
        // LAYER 3 grace window in blocks. Default 144 (≈ a day at 10-min
        // blocks; about 2.4 hours at 60 s blocks). Operators can override
        // via IRIUM_OFFER_RELIST_GRACE_BLOCKS.
        let relist_grace_blocks: u64 = std::env::var("IRIUM_OFFER_RELIST_GRACE_BLOCKS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(144);
        tokio::spawn(async move {
            let mut seen: HashMap<String, String> = HashMap::new();
            // Phase 1A+1B: tracks which local offer IDs we have already
            // announced via P2P gossip during THIS iriumd session. On
            // restart it's empty, so all open offers re-broadcast — the
            // gossip LRU on every peer absorbs the duplicates (one tick
            // of network noise, then quiet again).
            let mut broadcast_announced: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                let dir = offers_feed_dir();
                if !dir.exists() { continue; }
                let Ok(entries) = std::fs::read_dir(&dir) else { continue };
                let tip_height: u64 = watcher_chain
                    .lock()
                    .map(|g| g.tip_height())
                    .unwrap_or(0);
                // Phase 1A+1B: collect open offers we have not yet announced.
                // We queue here and broadcast outside the per-file loop so
                // no async I/O happens while iterating fs entries.
                let mut to_broadcast: Vec<(String, String)> = Vec::new();
                for entry in entries.flatten() {
                    let path = entry.path();
                    if !path.extension().map(|e| e == "json").unwrap_or(false) {
                        continue;
                    }
                    let Ok(data) = std::fs::read_to_string(&path) else { continue };
                    let Ok(val) = serde_json::from_str::<serde_json::Value>(&data) else { continue };
                    let id = val.get("offer_id")
                        .and_then(|v| v.as_str()).unwrap_or_default().to_string();
                    if id.is_empty() { continue; }
                    let mut status = val.get("status")
                        .and_then(|s| s.as_str()).unwrap_or("open").to_string();
                    let timeout_height = val.get("timeout_height").and_then(|v| v.as_u64());
                    let taken_at_height = val.get("taken_at_height").and_then(|v| v.as_u64());
                    let agreement_hash = val.get("agreement_hash")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    // LAYER 2: persist open→expired transition to disk so
                    // the offer never gets re-served in /offers/feed.
                    if status == "open" {
                        if let Some(th) = timeout_height {
                            if tip_height >= th {
                                if let Ok(mut new_val) = serde_json::from_str::<serde_json::Value>(&data) {
                                    if let Some(obj) = new_val.as_object_mut() {
                                        obj.insert("status".to_string(), serde_json::json!("expired"));
                                    }
                                    if let Ok(serialized) = serde_json::to_string_pretty(&new_val) {
                                        let _ = std::fs::write(&path, serialized);
                                    }
                                }
                                status = "expired".to_string();
                            }
                        }
                    }

                    // LAYER 3: persist taken→open relist if the buyer hasn't
                    // anchored the agreement on-chain within the grace window.
                    // Chain-aware check via agreement_hash_funded_on_chain so
                    // a slow-funding buyer (already on-chain) is not falsely
                    // relisted. Only fires when taken_at_height is present —
                    // offers taken before v1.9.24 lack the field and are
                    // skipped (operator can relist manually).
                    if status == "taken" {
                        if let (Some(tah), Some(ref ah)) = (taken_at_height, &agreement_hash) {
                            if tip_height > tah + relist_grace_blocks {
                                let funded = watcher_chain
                                    .lock()
                                    .map(|g| agreement_hash_funded_on_chain(&g, ah))
                                    .unwrap_or(false);
                                if !funded {
                                    let previous_buyer = val.get("buyer_address")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .to_string();
                                    if let Ok(mut new_val) = serde_json::from_str::<serde_json::Value>(&data) {
                                        if let Some(obj) = new_val.as_object_mut() {
                                            obj.insert("status".to_string(), serde_json::json!("open"));
                                            obj.remove("agreement_id");
                                            obj.remove("agreement_hash");
                                            obj.remove("buyer_address");
                                            obj.remove("taken_at");
                                            obj.remove("taken_at_height");
                                        }
                                        if let Ok(serialized) = serde_json::to_string_pretty(&new_val) {
                                            let _ = std::fs::write(&path, serialized);
                                        }
                                    }
                                    emit_event(&offer_event_tx, "offer.relisted", serde_json::json!({
                                        "offer_id": id,
                                        "previous_buyer_address": previous_buyer,
                                    }));
                                    status = "open".to_string();
                                }
                            }
                        }
                    }

                    let prev = seen.get(&id).cloned();
                    if prev.is_none() && status == "open" {
                        emit_event(&offer_event_tx, "offer.created", serde_json::json!({
                            "offer_id": id,
                        }));
                    } else if prev.as_deref() == Some("open") && status == "taken" {
                        emit_event(&offer_event_tx, "offer.taken", serde_json::json!({
                            "offer_id": id,
                        }));
                    } else if prev.as_deref() == Some("open") && status == "expired" {
                        emit_event(&offer_event_tx, "offer.expired", serde_json::json!({
                            "offer_id": id,
                        }));
                    }
                    // Phase 1A+1B: queue OPEN offers we have not yet
                    // announced this session. Status was potentially
                    // mutated by LAYER 2 (open→expired) or LAYER 3
                    // (taken→open relist) above, so this check after the
                    // transitions catches relists too.
                    if status == "open" && !broadcast_announced.contains(&id) {
                        to_broadcast.push((id.clone(), data.clone()));
                    }
                    seen.insert(id, status);
                }
                // Phase 1A+1B: emit broadcasts outside the fs-iteration
                // loop. Mark each as announced only after broadcast_offer
                // returns so a panic/early-return doesn't leave us in a
                // half-announced state that would skip retry next tick.
                //
                // Startup-race fix: also gate `announced` on peers > 0. On
                // freshly-started NAT iriumd, peer dial takes 10-30 s; the
                // 5 s watcher used to fire against zero peers, mark the
                // offer announced for the session, and leave us waiting
                // for the 120 s rebroadcast loop. Retrying every 5 s until
                // at least one peer is up costs essentially nothing and
                // closes that gap entirely.
                if let Some(ref p2p) = watcher_p2p {
                    let peer_count = p2p.peers_snapshot().await.len();
                    for (id, json) in to_broadcast {
                        p2p.broadcast_offer(&json).await;
                        if peer_count > 0 {
                            broadcast_announced.insert(id);
                        }
                    }
                }
            }
        });
    }

    let persist_drain_secs = std::env::var("IRIUM_PERSIST_DRAIN_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(15)
        .clamp(0, 20);
    if persist_drain_secs > 0 {
        #[cfg(unix)]
        {
            let p2p_for_shutdown = app_state.p2p.clone();
            tokio::spawn(async move {
                use tokio::signal::unix::{signal, SignalKind};
                let mut sigterm = match signal(SignalKind::terminate()) {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let _ = sigterm.recv().await;
                if let Some(ref node) = p2p_for_shutdown {
                    node.flush_peers_to_runtime().await;
                }
                let ok = storage::drain_persist_queue(Duration::from_secs(persist_drain_secs));
                if ok {
                    eprintln!("[i] persist queue drained on shutdown");
                } else {
                    eprintln!(
                        "[warn] persist queue drain timeout on shutdown; remaining_queue_len={}",
                        storage::persist_queue_len()
                    );
                }
                // Issue #66 — installing a custom SIGTERM handler via
                // tokio::signal::unix::signal suppresses the kernel's
                // default exit-on-SIGTERM behavior. Without an explicit
                // exit here, the runtime stays alive via the 30+ spawned
                // background tasks (offer drainers, dispute drainers,
                // gossip, header sync, ...) and systemd SIGKILLs after
                // TimeoutStopSec, losing in-memory state accumulated
                // between drain completion and SIGKILL. Matches the
                // /rpc/stop and Windows ctrl_c handlers (which already
                // exit explicitly).
                std::process::exit(0);
            });
        }

        // Windows ctrl_c handler — defense-in-depth for users running
        // iriumd standalone from a console window (the path on which
        // tokio's ctrl_c() actually fires). The Tauri-sidecar case has
        // no console attached (CREATE_NO_WINDOW) and uses POST /rpc/stop
        // instead. Mirrors the Unix block above except for the explicit
        // std::process::exit after drain — Windows ctrl_c does not
        // implicitly terminate the process the way the default SIGTERM
        // action does on Unix.
        #[cfg(windows)]
        {
            let p2p_for_shutdown = app_state.p2p.clone();
            tokio::spawn(async move {
                if tokio::signal::ctrl_c().await.is_err() {
                    return;
                }
                if let Some(ref node) = p2p_for_shutdown {
                    node.flush_peers_to_runtime().await;
                }
                let ok = storage::drain_persist_queue(Duration::from_secs(persist_drain_secs));
                if ok {
                    eprintln!("[i] persist queue drained on shutdown (Windows ctrl_c)");
                } else {
                    eprintln!(
                        "[warn] persist queue drain timeout on shutdown (Windows ctrl_c); remaining_queue_len={}",
                        storage::persist_queue_len()
                    );
                }
                std::process::exit(0);
            });
        }
    }


const OFFERS_FEED_DEFAULT_LIMIT: usize = 500;

/// LAYER 1 receive-side: a peer (the buyer) has broadcast an
/// OfferTakeNotification. If the local offers/ dir holds a matching offer
/// whose seller_pubkey matches the payload, mutate it to status="taken"
/// and emit `offer.taken` so the seller's GUI updates in real time.
///
/// Validation is intentionally light for v1 — no cryptographic signature
/// is required. Structural match (offer_id present locally, seller_pubkey
/// match, status=="open") prevents accidental collisions; spoofing remains
/// possible until the security-follow-up adds ed25519 signing (see the
/// MessageType::OfferTakeNotification comment in protocol.rs).
fn process_received_offer_take(payload_json: &str, event_tx: &EventTx) -> Result<(), String> {
    let val: serde_json::Value = serde_json::from_str(payload_json)
        .map_err(|e| format!("offer-take parse: {e}"))?;
    let offer_id = val
        .get("offer_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "offer-take: missing offer_id".to_string())?;
    let buyer_address = val
        .get("buyer_address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "offer-take: missing buyer_address".to_string())?;
    let agreement_id = val
        .get("agreement_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "offer-take: missing agreement_id".to_string())?;
    let agreement_hash = val
        .get("agreement_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "offer-take: missing agreement_hash".to_string())?;
    let taken_at = val.get("taken_at").and_then(|v| v.as_i64()).unwrap_or(0);
    let taken_at_height = val.get("taken_at_height").and_then(|v| v.as_u64());
    let seller_pubkey_claim = val
        .get("seller_pubkey")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let dir = offers_feed_dir();
    let path = dir.join(format!("offer-{}.json", offer_id));
    if !path.exists() {
        // Not our offer — silently ignore. Every connected peer receives
        // the broadcast so most will land here.
        return Ok(());
    }
    let data = std::fs::read_to_string(&path)
        .map_err(|e| format!("read offer {offer_id}: {e}"))?;
    let mut offer: serde_json::Value = serde_json::from_str(&data)
        .map_err(|e| format!("parse offer {offer_id}: {e}"))?;

    // Verify the seller_pubkey claim matches our local offer's seller_pubkey
    // (when both are present). Mismatch → silently ignore (someone else's
    // offer with a colliding id).
    if !seller_pubkey_claim.is_empty() {
        let local_pk = offer.get("seller_pubkey").and_then(|v| v.as_str()).unwrap_or("");
        if !local_pk.is_empty() && local_pk != seller_pubkey_claim {
            return Ok(());
        }
    }

    let cur_status = offer.get("status").and_then(|v| v.as_str()).unwrap_or("open");
    if cur_status != "open" {
        return Ok(()); // already taken / expired / etc.
    }

    if let Some(obj) = offer.as_object_mut() {
        obj.insert("status".to_string(), serde_json::json!("taken"));
        obj.insert("buyer_address".to_string(), serde_json::json!(buyer_address));
        obj.insert("agreement_id".to_string(), serde_json::json!(agreement_id));
        obj.insert("agreement_hash".to_string(), serde_json::json!(agreement_hash));
        obj.insert("taken_at".to_string(), serde_json::json!(taken_at));
        if let Some(h) = taken_at_height {
            obj.insert("taken_at_height".to_string(), serde_json::json!(h));
        }
    }
    let serialized = serde_json::to_string_pretty(&offer)
        .map_err(|e| format!("serialise offer: {e}"))?;
    std::fs::write(&path, serialized)
        .map_err(|e| format!("write offer {offer_id}: {e}"))?;

    // Emit offer.taken immediately so the seller's GUI updates without
    // waiting for the 5 s fs-watcher tick. The watcher's own emit will
    // fire on the next tick too (idempotent on the GUI side — both
    // events trigger the same silent reload).
    emit_event(event_tx, "offer.taken", serde_json::json!({
        "offer_id": offer_id,
        "buyer_address": buyer_address,
        "via": "p2p",
    }));
    Ok(())
}

fn offers_feed_limit() -> usize {
    std::env::var("IRIUM_OFFERS_FEED_LIMIT")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(OFFERS_FEED_DEFAULT_LIMIT)
}

async fn offers_feed(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    check_rate(&state, &addr)?;
    let dir = offers_feed_dir();
    let limit = offers_feed_limit();
    // LAYER 2: hide offers whose timeout_height has been reached by the
    // current chain tip. The 5 s offer-watcher background task is the one
    // that permanently flips status="open" → "expired" on disk; this filter
    // is a fast-path so we never serve an expired offer to a peer even in
    // the short window between expiry and the next watcher tick.
    let current_tip: u64 = state
        .chain
        .lock()
        .map(|guard| guard.tip_height())
        .unwrap_or(0);
    let mut offers: Vec<serde_json::Value> = Vec::new();
    if dir.exists() {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e == "json").unwrap_or(false) {
                    if let Ok(data) = std::fs::read_to_string(&path) {
                        if let Ok(mut val) =
                            serde_json::from_str::<serde_json::Value>(&data)
                        {
                            if val.get("status").and_then(|s| s.as_str()) != Some("open") {
                                continue;
                            }
                            // LAYER 2 expiry: skip if chain tip past timeout_height.
                            if let Some(th) = val.get("timeout_height").and_then(|v| v.as_u64()) {
                                if current_tip >= th {
                                    continue;
                                }
                            }
                            if let Some(obj) = val.as_object_mut() {
                                obj.remove("source");
                                obj.remove("agreement_id");
                                obj.remove("agreement_hash");
                                obj.remove("buyer_address");
                                obj.remove("taken_at");
                            }
                            offers.push(val);
                        }
                    }
                }
            }
        }
    }
    offers.sort_by(|a, b| {
        let ta = a.get("created_at").and_then(|v| v.as_u64()).unwrap_or(0);
        let tb = b.get("created_at").and_then(|v| v.as_u64()).unwrap_or(0);
        tb.cmp(&ta)
    });
    if offers.len() > limit {
        offers.truncate(limit);
    }
    let exported_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Ok(Json(serde_json::json!({
        "version": "1",
        "exported_at": exported_at,
        "count": offers.len(),
        "offers": offers,
    })))
}

/// LAYER 1 send-side RPC. The wallet binary calls this after `offer-take`
/// has saved its local agreement; iriumd then broadcasts the take to all
/// peers via MessageType::OfferTakeNotification. Gated behind
/// require_rpc_auth so only the local wallet (which shares
/// IRIUM_RPC_TOKEN) can broadcast — prevents a random LAN client from
/// spoof-taking other people's offers.
#[derive(Debug, serde::Deserialize)]
struct BroadcastOfferTakeRequest {
    /// JSON-encoded payload {offer_id, buyer_address, agreement_id,
    /// agreement_hash, taken_at, taken_at_height?, seller_pubkey}.
    payload_json: String,
}

async fn broadcast_offer_take_rpc(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<BroadcastOfferTakeRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    require_rpc_auth(&headers)?;
    if let Some(ref p2p) = state.p2p {
        p2p.broadcast_offer_take(&req.payload_json).await;
        Ok(Json(serde_json::json!({"ok": true})))
    } else {
        // No P2P node configured — broadcast is a no-op but we still
        // return ok so the wallet's best-effort send doesn't error.
        Ok(Json(serde_json::json!({"ok": false, "reason": "p2p_disabled"})))
    }
}


// --- Explorer endpoints (public, no auth, CORS * always on) -------------------

fn explorer_agreements_dir() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("IRIUM_AGREEMENT_BUNDLES_DIR") {
        return std::path::PathBuf::from(p).join("raw");
    }
    if let Ok(p) = std::env::var("IRIUM_DATA_DIR") {
        return std::path::PathBuf::from(p).join("agreements").join("raw");
    }
    // state_dir is {data_dir}/state/ so parent is {data_dir}
    irium_node_rs::storage::state_dir()
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
        .join("agreements")
        .join("raw")
}

fn explorer_cors_headers() -> HeaderMap {
    let mut map = HeaderMap::new();
    map.insert("Access-Control-Allow-Origin", HeaderValue::from_static("*"));
    map.insert("Access-Control-Allow-Methods", HeaderValue::from_static("GET, OPTIONS"));
    map
}

#[derive(Deserialize)]
struct ExplorerPageQuery {
    #[serde(default = "explorer_default_page")]
    page: usize,
    #[serde(default = "explorer_default_limit")]
    limit: usize,
}
fn explorer_default_page() -> usize { 1 }
fn explorer_default_limit() -> usize { 20 }

#[derive(Deserialize)]
struct ExplorerProofsQuery {
    #[serde(default = "explorer_default_page")]
    page: usize,
    #[serde(default = "explorer_default_limit")]
    limit: usize,
    agreement_hash: Option<String>,
}

#[derive(Serialize)]
struct ExplorerAgreementSummary {
    hash: String,
    agreement_id: String,
    template_type: String,
    total_amount: u64,
    creation_time: u64,
    parties: Vec<serde_json::Value>,
}

#[derive(Serialize)]
struct ExplorerAgreementsResponse {
    agreements: Vec<ExplorerAgreementSummary>,
    total: usize,
    page: usize,
    limit: usize,
}

#[derive(Serialize)]
struct ExplorerProofEntry {
    proof_id: String,
    proof_type: String,
    agreement_hash: String,
    attested_by: String,
    attestation_time: u64,
    status: String,
}

#[derive(Serialize)]
struct ExplorerProofsResponse {
    proofs: Vec<ExplorerProofEntry>,
    total: usize,
    page: usize,
    limit: usize,
}

#[derive(Serialize)]
struct ExplorerReputationResponse {
    pubkey: String,
    total_agreements_as_seller: usize,
    proofs_submitted: usize,
    note: String,
}

#[derive(Serialize)]
struct ExplorerStatsResponse {
    chain_height: u64,
    total_agreements: usize,
    total_proofs: usize,
    peer_count: usize,
    proof_types: std::collections::HashMap<String, usize>,
}

#[derive(Serialize)]
struct ExplorerAgreementDetailResponse {
    hash: String,
    agreement: serde_json::Value,
    lifecycle: AgreementLifecycleView,
    proofs: Vec<ExplorerProofEntry>,
}

async fn explorer_agreements(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Query(q): Query<ExplorerPageQuery>,
) -> impl axum::response::IntoResponse {
    check_rate(&state, &addr).unwrap_or(());
    let dir = explorer_agreements_dir();
    let mut entries: Vec<(u64, ExplorerAgreementSummary)> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for entry in rd.flatten() {
            let path = entry.path();
            if !path.extension().map(|e| e == "json").unwrap_or(false) { continue; }
            let hash = match path.file_stem().and_then(|s| s.to_str()) {
                Some(h) => h.to_string(),
                None => continue,
            };
            let Ok(data) = std::fs::read_to_string(&path) else { continue };
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&data) else { continue };
            let agreement_id = v.get("agreement_id").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let template_type = v.get("template_type").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let total_amount = v.get("total_amount").and_then(|x| x.as_u64()).unwrap_or(0);
            let creation_time = v.get("creation_time").and_then(|x| x.as_u64()).unwrap_or(0);
            let parties: Vec<serde_json::Value> = v.get("parties")
                .and_then(|x| x.as_array())
                .map(|arr| arr.iter().map(|p| serde_json::json!({
                    "role": p.get("role").and_then(|r| r.as_str()).unwrap_or(""),
                    "display_name": p.get("display_name").and_then(|r| r.as_str()).unwrap_or(""),
                    "address": p.get("address").and_then(|r| r.as_str()).unwrap_or(""),
                })).collect())
                .unwrap_or_default();
            entries.push((creation_time, ExplorerAgreementSummary {
                hash, agreement_id, template_type, total_amount, creation_time, parties,
            }));
        }
    }
    entries.sort_by(|a, b| b.0.cmp(&a.0));
    let total = entries.len();
    let limit = q.limit.clamp(1, 100);
    let page = q.page.max(1);
    let skip = (page - 1) * limit;
    let agreements: Vec<ExplorerAgreementSummary> = entries.into_iter()
        .skip(skip).take(limit).map(|(_, s)| s).collect();
    (explorer_cors_headers(), Json(ExplorerAgreementsResponse { agreements, total, page, limit }))
}

async fn explorer_agreement_detail(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    AxumPath(hash): AxumPath<String>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    check_rate(&state, &addr).unwrap_or(());
    let hash = hash.to_lowercase();
    let dir = explorer_agreements_dir();
    let path = dir.join(format!("{}.json", hash));
    let Ok(data) = std::fs::read_to_string(&path) else {
        return (explorer_cors_headers(), Json(serde_json::json!({"error": "agreement not found"}))).into_response();
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&data) else {
        return (explorer_cors_headers(), Json(serde_json::json!({"error": "parse error"}))).into_response();
    };
    let agreement: irium_node_rs::settlement::AgreementObject = match serde_json::from_value(v.clone()) {
        Ok(a) => a,
        Err(_) => return (explorer_cors_headers(), Json(serde_json::json!({"error": "invalid agreement"}))).into_response(),
    };
    let lifecycle = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let linked = scan_agreement_linked_txs(&chain, &agreement, &hash);
        let tip = chain.tip_height();
        irium_node_rs::settlement::derive_lifecycle(&agreement, &hash, linked, tip)
    };
    let tip_height = state.status_height_cache.load(std::sync::atomic::Ordering::Relaxed);
    let store = state.proof_store.lock().unwrap_or_else(|e| e.into_inner());
    let proofs: Vec<ExplorerProofEntry> = store.list_by_agreement(&hash).into_iter().map(|p| {
        ExplorerProofEntry {
            proof_id: p.proof_id.clone(),
            proof_type: p.proof_type.clone(),
            agreement_hash: p.agreement_hash.clone(),
            attested_by: p.attested_by.clone(),
            attestation_time: p.attestation_time,
            status: proof_lifecycle_status(p.expires_at_height, tip_height).to_string(),
        }
    }).collect();
    (explorer_cors_headers(), Json(ExplorerAgreementDetailResponse { hash, agreement: v, lifecycle, proofs })).into_response()
}

async fn explorer_proofs(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Query(q): Query<ExplorerProofsQuery>,
) -> impl axum::response::IntoResponse {
    check_rate(&state, &addr).unwrap_or(());
    let tip_height = state.status_height_cache.load(std::sync::atomic::Ordering::Relaxed);
    let store = state.proof_store.lock().unwrap_or_else(|e| e.into_inner());
    let all: Vec<ExplorerProofEntry> = match q.agreement_hash.as_deref() {
        Some(h) => store.list_by_agreement(h).into_iter().map(|p| ExplorerProofEntry {
            proof_id: p.proof_id.clone(), proof_type: p.proof_type.clone(),
            agreement_hash: p.agreement_hash.clone(), attested_by: p.attested_by.clone(),
            attestation_time: p.attestation_time,
            status: proof_lifecycle_status(p.expires_at_height, tip_height).to_string(),
        }).collect(),
        None => store.list_all().into_iter().map(|p| ExplorerProofEntry {
            proof_id: p.proof_id.clone(), proof_type: p.proof_type.clone(),
            agreement_hash: p.agreement_hash.clone(), attested_by: p.attested_by.clone(),
            attestation_time: p.attestation_time,
            status: proof_lifecycle_status(p.expires_at_height, tip_height).to_string(),
        }).collect(),
    };
    let total = all.len();
    let limit = q.limit.clamp(1, 100);
    let page = q.page.max(1);
    let skip = (page - 1) * limit;
    let proofs: Vec<ExplorerProofEntry> = all.into_iter().skip(skip).take(limit).collect();
    (explorer_cors_headers(), Json(ExplorerProofsResponse { proofs, total, page, limit }))
}

async fn explorer_reputation(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    AxumPath(pubkey): AxumPath<String>,
) -> impl axum::response::IntoResponse {
    check_rate(&state, &addr).unwrap_or(());
    let dir = explorer_agreements_dir();
    let mut total_seller: usize = 0;
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for entry in rd.flatten() {
            let path = entry.path();
            if !path.extension().map(|e| e == "json").unwrap_or(false) { continue; }
            let Ok(data) = std::fs::read_to_string(&path) else { continue };
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&data) else { continue };
            if let Some(parties) = v.get("parties").and_then(|p| p.as_array()) {
                for party in parties {
                    let role = party.get("role").and_then(|r| r.as_str()).unwrap_or("");
                    let addr = party.get("address").and_then(|a| a.as_str()).unwrap_or("");
                    if (role == "seller" || role == "payee") && addr == pubkey.as_str() {
                        total_seller += 1;
                        break;
                    }
                }
            }
        }
    }
    let store = state.proof_store.lock().unwrap_or_else(|e| e.into_inner());
    let proofs_submitted = store.list_all().into_iter()
        .filter(|p| p.attested_by == pubkey)
        .count();
    (explorer_cors_headers(), Json(ExplorerReputationResponse {
        pubkey,
        total_agreements_as_seller: total_seller,
        proofs_submitted,
        note: "Reputation derived from locally stored agreement and proof data on this node.".to_string(),
    }))
}

async fn explorer_stats(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
) -> impl axum::response::IntoResponse {
    check_rate(&state, &addr).unwrap_or(());
    let chain_height = state.status_height_cache.load(std::sync::atomic::Ordering::Relaxed);
    let peer_count = state.status_peer_count_cache.load(std::sync::atomic::Ordering::Relaxed);
    let dir = explorer_agreements_dir();
    let total_agreements = std::fs::read_dir(&dir)
        .map(|rd| rd.flatten().filter(|e| {
            e.path().extension().map(|ex| ex == "json").unwrap_or(false)
        }).count())
        .unwrap_or(0);
    let store = state.proof_store.lock().unwrap_or_else(|e| e.into_inner());
    let total_proofs = store.count();
    let mut proof_types: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for p in store.list_all() {
        *proof_types.entry(p.proof_type.clone()).or_insert(0) += 1;
    }
    (explorer_cors_headers(), Json(ExplorerStatsResponse {
        chain_height, total_agreements, total_proofs, peer_count, proof_types,
    }))
}

    let mut app = Router::new()
        .route("/status", get(status))
        .route("/peers", get(peers))
        .route("/metrics", get(metrics))
        .route("/rpc/network_hashrate", get(network_hashrate))
        .route("/network-status", get(network_status))
        .route("/rpc/mining_metrics", get(mining_metrics))
        .route("/rpc/balance", get(get_balance))
        .route("/rpc/utxos", get(get_utxos))
        .route("/rpc/richlist", get(get_richlist))
        .route("/rpc/history", get(get_history))
        .route("/rpc/fee_estimate", get(get_fee_estimate))
        .route("/rpc/utxo", get(get_utxo))
        .route("/rpc/getblocktemplate", get(get_block_template))
        .route("/rpc/block", get(get_block))
        .route("/rpc/blocks", get(get_blocks))
        .route("/rpc/block_by_hash", get(get_block_by_hash))
        .route("/rpc/tx", get(get_tx))
        .route("/rpc/submit_block", post(submit_block))
        .route("/rpc/submit_tx", post(submit_tx))
        // Fix D: pending-tx introspection + per-address pending-spent
        // outpoints. Both are public (rate-limited only) so the wallet's
        // Fix A coin-selection check can call /rpc/mempool/spent_by
        // without an auth token, matching the policy of /rpc/utxos.
        .route("/rpc/mempool/by_txid", get(mempool_by_txid))
        .route("/rpc/mempool/spent_by", get(mempool_spent_by))
        .route("/rpc/createagreement", post(create_agreement))
        .route("/rpc/inspectagreement", post(inspect_agreement))
        .route(
            "/rpc/computeagreementhash",
            post(compute_agreement_hash_rpc),
        )
        .route("/rpc/fundagreement", post(fund_agreement))
        .route("/rpc/raisedispute", post(raise_dispute))
        .route("/rpc/disputeevidence", post(submit_dispute_evidence))
        .route("/rpc/resolvedispute", post(resolve_dispute))
        .route("/rpc/registerresolver", post(register_resolver))
        .route("/rpc/disputestate", get(get_dispute_state))
        .route("/rpc/reresolveagreement", post(reresolve_agreement))
        .route("/resolvers/list", get(resolvers_list))
        .route("/rpc/listagreementtxs", post(list_agreement_txs))
        .route("/rpc/agreementfundinglegs", post(agreement_funding_legs))
        .route("/rpc/agreementtimeline", post(agreement_timeline))
        .route("/rpc/agreementaudit", post(agreement_audit))
        .route("/rpc/agreementstatus", post(agreement_status))
        .route("/rpc/agreementmilestones", post(agreement_milestones))
        .route("/rpc/agreementreceipt", get(agreement_receipt))
        .route("/rpc/reputation/:address", get(reputation_lookup))
        .route(
            "/rpc/broadcastreputationnonresponse",
            post(broadcast_reputation_non_response),
        )
        .route("/rpc/verifyagreementlink", post(verify_agreement_link))
        .route(
            "/rpc/agreementreleaseeligibility",
            post(agreement_release_eligibility),
        )
        .route(
            "/rpc/agreementrefundeligibility",
            post(agreement_refund_eligibility),
        )
        .route("/rpc/buildagreementrelease", post(build_agreement_release))
        .route("/rpc/buildagreementrefund", post(build_agreement_refund))
        .route(
            "/rpc/buildcontractortemplate",
            post(build_contractor_template_rpc),
        )
        .route(
            "/rpc/buildpreordertemplate",
            post(build_preorder_template_rpc),
        )
        .route("/rpc/buildotctemplate", post(build_otc_template_rpc))
        .route("/rpc/checkpolicy", post(check_policy_rpc))
        .route("/rpc/submitproof", post(submit_proof_rpc))
        .route("/rpc/listproofs", post(list_proofs_rpc))
        .route("/rpc/getproof", post(get_proof_rpc))
        .route("/rpc/storepolicy", post(store_policy_rpc))
        .route("/rpc/getpolicy", post(get_policy_rpc))
        .route("/rpc/evaluatepolicy", post(evaluate_policy_rpc))
        .route("/rpc/buildsettlementtx", post(build_settlement_tx_rpc))
        .route("/rpc/listpolicies", post(list_policies_rpc))
        .route("/rpc/createhtlc", post(create_htlc))
        .route("/rpc/decodehtlc", post(decode_htlc))
        .route("/rpc/claimhtlc", post(claim_htlc))
        .route("/rpc/refundhtlc", post(refund_htlc))
        .route("/rpc/inspecthtlc", get(inspect_htlc))
        .route("/rpc/submitbtcheaders", post(submit_btc_headers))
        .route("/rpc/btcrelaytip", get(btc_relay_tip))
        .route("/rpc/btcheader", get(btc_header))
        .route("/rpc/submitltcheaders", post(submit_ltc_headers))
        .route("/rpc/ltcrelaytip", get(ltc_relay_tip))
        .route("/rpc/ltcheader", get(ltc_header))
        .route("/rpc/createbtcswap", post(create_btc_swap))
        .route("/rpc/claimbtcswap", post(claim_btc_swap))
        .route("/rpc/refundbtcswap", post(refund_btc_swap))
        .route("/rpc/inspectbtcswap", get(inspect_btc_swap))
        .route("/rpc/createltcswap", post(create_ltc_swap))
        .route("/rpc/claimltcswap", post(claim_ltc_swap))
        .route("/rpc/refundltcswap", post(refund_ltc_swap))
        .route("/rpc/inspectltcswap", get(inspect_ltc_swap))
        .route("/rpc/postswaporder", post(post_swap_order))
        .route("/rpc/listswaporders", get(list_swap_orders))
        .route("/rpc/getswaporder", get(get_swap_order))
        .route("/rpc/cancelswaporder", post(cancel_swap_order))
        .route("/rpc/fillswaporder", post(fill_swap_order))
        .route("/rpc/postltcswaporder", post(post_ltc_swap_order))
        .route("/rpc/listltcswaporders", get(list_ltc_swap_orders))
        .route("/rpc/getltcswaporder", get(get_ltc_swap_order))
        .route("/rpc/cancelltcswaporder", post(cancel_ltc_swap_order))
        .route("/rpc/fillltcswaporder", post(fill_ltc_swap_order))
        .route("/rpc/sweepltcexpiredorder", post(sweep_ltc_expired_order))
        .route("/rpc/sweepexpiredorder", post(sweep_expired_order))
        .route("/wallet/create", post(wallet_create))
        .route("/wallet/unlock", post(wallet_unlock))
        .route("/wallet/lock", post(wallet_lock))
        .route("/wallet/info", get(wallet_info))
        .route("/wallet/migrate_to_encrypted", post(wallet_migrate_to_encrypted))
        .route("/wallet/recover_from_seed", post(wallet_recover_from_seed))
        .route("/wallet/addresses", get(wallet_addresses))
        .route("/wallet/receive", get(wallet_receive))
        .route("/wallet/new_address", post(wallet_new_address))
        .route("/wallet/export_wif", get(wallet_export_wif))
        .route("/wallet/import_wif", post(wallet_import_wif))
        .route("/wallet/export_seed", get(wallet_export_seed))
        .route("/wallet/export_mnemonic", get(wallet_export_mnemonic))
        .route("/wallet/import_seed", post(wallet_import_seed))
        .route("/wallet/send", post(wallet_send))
        .route("/explorer/agreements", get(explorer_agreements))
        .route("/explorer/agreement/:hash", get(explorer_agreement_detail))
        .route("/explorer/proofs", get(explorer_proofs))
        .route("/explorer/reputation/:pubkey", get(explorer_reputation))
        .route("/explorer/stats", get(explorer_stats))
        .route("/offers/feed", get(offers_feed))
        .route("/rpc/broadcast_offer_take", post(broadcast_offer_take_rpc))
        .route("/ws", get(ws_handler))
        .route("/events", get(sse_handler))
        .route("/rpc/stop", post(stop_handler))
        .route("/admin/add-seed", post(admin_add_seed))
        .layer(DefaultBodyLimit::max(rpc_body_limit_bytes()))
        .with_state(app_state.clone());

    if let Some(cors) = cors_layer() {
        app = app.layer(cors);
    }

    let app = app.into_make_service_with_connect_info::<SocketAddr>();

    let status_host =
        std::env::var("IRIUM_STATUS_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let status_port: u16 = std::env::var("IRIUM_STATUS_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080); // default 8080 if IRIUM_STATUS_PORT not set
    let status_addr: SocketAddr = format!("{}:{}", status_host, status_port)
        .parse()
        .expect("valid status bind address");

    let status_app = Router::new()
        .route("/status", get(status))
        .with_state(app_state.clone())
        .into_make_service_with_connect_info::<SocketAddr>();

    tokio::spawn(async move {
        match tokio::net::TcpListener::bind(status_addr).await {
            Ok(listener) => {
                if let Err(e) = axum::serve(listener, status_app).await {
                    eprintln!("[warn] HTTP status server exited: {}", e);
                }
            }
            Err(e) => {
                eprintln!(
                    "[warn] failed to bind HTTP status listener on {}: {}",
                    status_addr, e
                );
            }
        }
    });

    let host = std::env::var("IRIUM_NODE_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port: u16 = std::env::var("IRIUM_NODE_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(38300); // default 38300 if IRIUM_NODE_PORT not set

    let addr: SocketAddr = format!("{}:{}", host, port)
        .parse()
        .expect("valid bind address");

    println!("[i] RPC status: http://{}:{}/status", host, port);
    println!(
        "[i] HTTP status: http://{}:{}/status",
        status_host, status_port
    );
    println!("[i] WebSocket: ws://{}:{}/ws  SSE: http://{}:{}/events", host, port, host, port);
    println!("[i] Explorer: http://{}:{}/explorer/stats | /explorer/agreements | /explorer/proofs", host, port);
    println!("[i] Proof finality depth: {} blocks (IRIUM_PROOF_FINALITY_DEPTH)", proof_finality_depth());

    let tls_cert = std::env::var("IRIUM_TLS_CERT").ok();
    let tls_key = std::env::var("IRIUM_TLS_KEY").ok();
    if let (Some(cert_path), Some(key_path)) = (tls_cert, tls_key) {
        let config = RustlsConfig::from_pem_file(cert_path, key_path)
            .await
            .expect("failed to load TLS cert/key");
        if json_log_enabled() {
            println!(
                "{}",
                json!({"ts": Utc::now().format("%H:%M:%S").to_string(), "level": "info", "event": "http_listen", "host": host, "port": port, "scheme": "https"})
            );
        } else {
            println!(
                "Irium Rust node HTTPS listening on https://{}:{}",
                host, port
            );
        }
        axum_server::bind_rustls(addr, config)
            .serve(app)
            .await
            .expect("server error");
    } else {
        if json_log_enabled() {
            println!(
                "{}",
                json!({"ts": Utc::now().format("%H:%M:%S").to_string(), "level": "info", "event": "http_listen", "host": host, "port": port, "scheme": "http"})
            );
        } else {
            println!("Irium Rust node HTTP listening on http://{}:{}", host, port);
        }

        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .expect("bind failed");

        axum::serve(listener, app).await.expect("server error");
    }
}

#[cfg(test)]
mod tests {
    use irium_node_rs::settlement::TypedProofPayload;
    use super::*;
    use axum::extract::{ConnectInfo, Query, State};
    use axum::http::HeaderMap;
    use axum::Json;
    use irium_node_rs::chain::{block_from_locked, ChainParams, ChainState, OutPoint, UtxoEntry};
    use irium_node_rs::genesis::load_locked_genesis;
    use irium_node_rs::mempool::MempoolManager;
    use irium_node_rs::settlement::{
        settlement_proof_payload_bytes, AgreementDeadlines, AgreementMilestone, AgreementObject,
        AgreementParty, AgreementRefundCondition, AgreementReleaseCondition, AgreementTemplateType,
        ApprovedAttestor, HoldbackOutcome, NoResponseRule, NoResponseTrigger, PolicyHoldback,
        PolicyMilestone, ProofPolicy, ProofRequirement, ProofResolution, ProofSignatureEnvelope,
        SettlementProof, AGREEMENT_SIGNATURE_TYPE_SECP256K1, PROOF_POLICY_SCHEMA_ID,
        SETTLEMENT_PROOF_SCHEMA_ID,
    };
    use irium_node_rs::wallet_store::WalletManager;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_socket() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 38000)
    }

    static TEST_PATH_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_path(prefix: &str, ext: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let seq = TEST_PATH_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "{}_{}_{}_{}.{}",
            prefix,
            std::process::id(),
            nanos,
            seq,
            ext
        ))
    }

    fn create_test_state(activation: Option<u64>) -> (AppState, String, String, String) {
        std::env::remove_var("IRIUM_RPC_TOKEN");

        let locked = load_locked_genesis().expect("locked genesis");
        let genesis_block = block_from_locked(&locked).expect("genesis block");
        let pow_limit = genesis_block.header.target();
        let params = ChainParams {
            pow_limit,
            genesis_block,
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
        let chain = Arc::new(Mutex::new(ChainState::new(params)));

        let mempool_path = unique_path("irium_htlc_mempool", "json");
        let mempool = Arc::new(Mutex::new(MempoolManager::new(mempool_path, 1024, 0.0, 0)));

        let wallet_path = unique_path("irium_htlc_wallet", "json");
        let wallet = Arc::new(Mutex::new(WalletManager::new(wallet_path)));

        let (sender, recipient, refund) = {
            let mut w = wallet.lock().unwrap_or_else(|e| e.into_inner());
            let sender = w
                .create_with_seed(
                    "test-pass",
                    Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
                )
                .expect("wallet create")
                .address;
            let recipient = w.new_address().expect("recipient address").address;
            let refund = w.new_address().expect("refund address").address;
            (sender, recipient, refund)
        };

        let state = AppState {
            chain,
            genesis_hash: "00".repeat(32),
            mempool,
            wallet,
            anchors: None,
            p2p: None,
            limiter: Arc::new(Mutex::new(rate_limiter())),
            status_height_cache: Arc::new(AtomicU64::new(0)),
            status_peer_count_cache: Arc::new(AtomicUsize::new(0)),
            status_sybil_cache: Arc::new(AtomicU8::new(0)),
            status_persisted_height_cache: Arc::new(AtomicU64::new(0)),
            status_persist_queue_cache: Arc::new(AtomicUsize::new(0)),
            status_persisted_contiguous_cache: Arc::new(AtomicU64::new(0)),
            status_persisted_max_on_disk_cache: Arc::new(AtomicU64::new(0)),
            status_quarantine_count_cache: Arc::new(AtomicU64::new(0)),
            status_persisted_window_tip_cache: Arc::new(AtomicU64::new(0)),
            status_missing_persisted_in_window_cache: Arc::new(AtomicU64::new(0)),
            status_missing_or_mismatch_in_window_cache: Arc::new(AtomicU64::new(0)),
            status_expected_hash_coverage_in_window_cache: Arc::new(AtomicU64::new(0)),
            status_expected_hash_window_span_cache: Arc::new(AtomicU64::new(0)),
            status_best_header_hash_cache: Arc::new(Mutex::new(String::new())),
            proof_store: Arc::new(Mutex::new(ProofStore::new(unique_path(
                "irium_proofs",
                "json",
            )))),
            policy_store: Arc::new(Mutex::new(PolicyStore::new(unique_path(
                "irium_policies",
                "json",
            )))),
            event_tx: tokio::sync::broadcast::channel::<std::sync::Arc<String>>(WS_BROADCAST_CAPACITY).0,
            proof_heights: Arc::new(Mutex::new(std::collections::HashMap::new())),
            disputes_index: Arc::new(Mutex::new(std::collections::HashMap::new())),
            resolvers_index: Arc::new(Mutex::new(std::collections::HashMap::new())),
            btc_template_headers_cache: Arc::new(Mutex::new(None)),
            ltc_template_headers_cache: Arc::new(Mutex::new(None)),
            };

        (state, sender, recipient, refund)
    }

    fn add_wallet_utxo(state: &AppState, address: &str, value: u64) {
        let pkh = base58_p2pkh_to_hash(address).expect("address decode");
        let mut pkh20 = [0u8; 20];
        pkh20.copy_from_slice(&pkh);
        let mut chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let tip = chain.tip_height();
        chain.utxos.insert(
            OutPoint {
                txid: [0x55; 32],
                index: 0,
            },
            UtxoEntry {
                output: TxOutput {
                    value,
                    script_pubkey: p2pkh_script(&pkh20),
                },
                height: tip,
                is_coinbase: false,
            },
        );
    }

    fn apply_tx_to_chain_for_test(state: &AppState, tx: &Transaction) {
        let mut chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        for input in &tx.inputs {
            let _ = chain.utxos.remove(&OutPoint {
                txid: input.prev_txid,
                index: input.prev_index,
            });
        }
        let txid = tx.txid();
        let h = chain.tip_height();
        for (idx, out) in tx.outputs.iter().cloned().enumerate() {
            chain.utxos.insert(
                OutPoint {
                    txid,
                    index: idx as u32,
                },
                UtxoEntry {
                    output: out,
                    height: h,
                    is_coinbase: false,
                },
            );
        }
    }

    fn htlc_create_request(
        recipient: &str,
        refund: &str,
        secret_hash_hex: String,
        timeout_height: u64,
    ) -> CreateHtlcRequest {
        CreateHtlcRequest {
            amount: "5.00000000".to_string(),
            recipient_address: recipient.to_string(),
            refund_address: refund.to_string(),
            secret_hash_hex,
            timeout_height,
            fee_per_byte: Some(1),
            broadcast: Some(false),
        }
    }

    #[tokio::test]
    async fn rpc_createhtlc_rejected_before_activation() {
        let (state, sender, recipient, refund) = create_test_state(Some(50));
        add_wallet_utxo(&state, &sender, 20_000_000_000);

        {
            let mut chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
            chain.height = 49;
        }

        let req = htlc_create_request(&recipient, &refund, "11".repeat(32), 100);
        let res = create_htlc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(req),
        )
        .await;

        assert!(matches!(res, Err((StatusCode::BAD_REQUEST, _))));
    }

    #[tokio::test]
    async fn template_includes_htlc_at_activation_boundary() {
        let (state, sender, recipient, refund) = create_test_state(Some(50));
        add_wallet_utxo(&state, &sender, 20_000_000_000);

        {
            let mut chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
            chain.height = 50; // candidate block height == activation height
        }

        let create = create_htlc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(CreateHtlcRequest {
                amount: "5.00000000".to_string(),
                recipient_address: recipient,
                refund_address: refund,
                secret_hash_hex: "33".repeat(32),
                timeout_height: 120,
                fee_per_byte: Some(1),
                broadcast: Some(true),
            }),
        )
        .await
        .expect("createhtlc")
        .0;

        let tpl = get_block_template(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Query(TemplateQuery {
                longpoll: None,
                poll_secs: None,
                max_txs: None,
                min_fee: None,
            }),
        )
        .await
        .expect("template")
        .0;

        assert!(
            tpl.txs.iter().any(|t| t.hex == create.raw_tx_hex),
            "HTLC tx should be in template at activation height"
        );

        {
            let mut chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
            chain.height = 51; // activation + 1 should also include
        }

        let tpl_after = get_block_template(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Query(TemplateQuery {
                longpoll: None,
                poll_secs: None,
                max_txs: None,
                min_fee: None,
            }),
        )
        .await
        .expect("template after")
        .0;

        assert!(
            tpl_after.txs.iter().any(|t| t.hex == create.raw_tx_hex),
            "HTLC tx should remain template-eligible after activation"
        );
    }

    #[tokio::test]
    async fn rpc_create_decode_inspect_and_claim_flow() {
        let (state, sender, recipient, refund) = create_test_state(Some(0));
        add_wallet_utxo(&state, &sender, 20_000_000_000);

        let secret = b"swap-secret";
        let secret_hash_hex = hex::encode(Sha256::digest(secret));

        let create = create_htlc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(htlc_create_request(
                &recipient,
                &refund,
                secret_hash_hex.clone(),
                10,
            )),
        )
        .await
        .expect("createhtlc")
        .0;

        let decode = decode_htlc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(DecodeHtlcRequest {
                raw_tx_hex: create.raw_tx_hex.clone(),
                vout: Some(0),
            }),
        )
        .await
        .expect("decodehtlc")
        .0;

        assert!(decode.found);
        assert_eq!(decode.output_type, "htlcv1");
        assert_eq!(
            decode.expected_hash.as_deref(),
            Some(secret_hash_hex.as_str())
        );

        let funding_tx =
            decode_full_tx(&hex::decode(&create.raw_tx_hex).expect("hex")).expect("tx decode");
        apply_tx_to_chain_for_test(&state, &funding_tx);

        let inspect_funded = inspect_htlc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Query(InspectHtlcQuery {
                txid: create.txid.clone(),
                vout: 0,
            }),
        )
        .await
        .expect("inspect funded")
        .0;

        assert!(inspect_funded.exists);
        assert!(inspect_funded.unspent);

        let claim = claim_htlc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SpendHtlcRequest {
                funding_txid: create.txid.clone(),
                vout: 0,
                destination_address: recipient.clone(),
                fee_per_byte: Some(1),
                broadcast: Some(false),
                secret_hex: Some(hex::encode(secret)),
            }),
        )
        .await
        .expect("claim")
        .0;

        let claim_tx =
            decode_full_tx(&hex::decode(&claim.raw_tx_hex).expect("hex")).expect("claim decode");
        apply_tx_to_chain_for_test(&state, &claim_tx);

        let inspect_spent = inspect_htlc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Query(InspectHtlcQuery {
                txid: create.txid,
                vout: 0,
            }),
        )
        .await
        .expect("inspect spent")
        .0;

        assert!(!inspect_spent.exists);
        assert!(inspect_spent.spent);
    }

    #[tokio::test]
    async fn rpc_claim_wrong_preimage_rejected() {
        let (state, sender, recipient, refund) = create_test_state(Some(0));
        add_wallet_utxo(&state, &sender, 20_000_000_000);
        {
            let mut chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
            chain.height = 19;
        }

        let secret_hash_hex = hex::encode(Sha256::digest(b"right-secret"));
        let create = create_htlc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(htlc_create_request(
                &recipient,
                &refund,
                secret_hash_hex,
                40,
            )),
        )
        .await
        .expect("createhtlc")
        .0;

        let funding_tx =
            decode_full_tx(&hex::decode(&create.raw_tx_hex).expect("hex")).expect("tx decode");
        apply_tx_to_chain_for_test(&state, &funding_tx);

        let wrong = claim_htlc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(SpendHtlcRequest {
                funding_txid: create.txid,
                vout: 0,
                destination_address: recipient,
                fee_per_byte: Some(1),
                broadcast: Some(true),
                secret_hex: Some(hex::encode("wrong-secret")),
            }),
        )
        .await;

        assert!(matches!(wrong, Err(StatusCode::BAD_REQUEST)));
    }

    #[tokio::test]
    async fn rpc_refund_before_and_after_timeout() {
        let (state, sender, recipient, refund) = create_test_state(Some(0));
        add_wallet_utxo(&state, &sender, 20_000_000_000);

        let timeout = 20u64;
        {
            let mut chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
            chain.height = 19;
        }

        let create = create_htlc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(htlc_create_request(
                &recipient,
                &refund,
                "22".repeat(32),
                timeout,
            )),
        )
        .await
        .expect("createhtlc")
        .0;

        let funding_tx =
            decode_full_tx(&hex::decode(&create.raw_tx_hex).expect("hex")).expect("tx decode");
        apply_tx_to_chain_for_test(&state, &funding_tx);

        let early = refund_htlc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SpendHtlcRequest {
                funding_txid: create.txid.clone(),
                vout: 0,
                destination_address: refund.clone(),
                fee_per_byte: Some(1),
                broadcast: Some(false),
                secret_hex: None,
            }),
        )
        .await;
        assert!(matches!(early, Err(StatusCode::BAD_REQUEST)));

        {
            let mut chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
            chain.height = timeout + 1;
        }

        let late = refund_htlc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(SpendHtlcRequest {
                funding_txid: create.txid,
                vout: 0,
                destination_address: refund,
                fee_per_byte: Some(1),
                broadcast: Some(false),
                secret_hex: None,
            }),
        )
        .await;

        assert!(late.is_ok());
    }

    #[tokio::test]
    async fn rpc_decodehtlc_reports_non_htlc_output() {
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: [0u8; 32],
                prev_index: 0,
                script_sig: vec![],
                sequence: 0xffff_ffff,
            }],
            outputs: vec![TxOutput {
                value: 1,
                script_pubkey: p2pkh_script(&[1u8; 20]),
            }],
            locktime: 0,
        };
        tx.inputs[0].script_sig = vec![1, 0, 1, 2];

        let (state, _, _, _) = create_test_state(None);
        let decode = decode_htlc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(DecodeHtlcRequest {
                raw_tx_hex: hex::encode(tx.serialize()),
                vout: Some(0),
            }),
        )
        .await
        .expect("decode")
        .0;

        assert!(!decode.found);
        assert_eq!(decode.output_type, "p2pkh");
    }

    fn confirm_tx_for_agreement_scan(state: &AppState, tx: &Transaction) {
        let mut chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(block) = chain.chain.last_mut() {
            block.transactions.push(tx.clone());
        }
    }

    fn sample_agreement_for_test(
        payer_address: &str,
        payee_address: &str,
        secret_hash_hex: String,
        timeout_height: u64,
    ) -> AgreementObject {
        AgreementObject {
            schema_id: Some(irium_node_rs::settlement::AGREEMENT_SCHEMA_ID_V1.to_string()),
            agreement_id: "agr-node-1".to_string(),
            version: 1,
            template_type: AgreementTemplateType::SimpleReleaseRefund,
            parties: vec![
                AgreementParty {
                    party_id: "payer".to_string(),
                    display_name: "Payer".to_string(),
                    address: payer_address.to_string(),
                    role: Some("payer".to_string()),
                },
                AgreementParty {
                    party_id: "payee".to_string(),
                    display_name: "Payee".to_string(),
                    address: payee_address.to_string(),
                    role: Some("payee".to_string()),
                },
            ],
            payer: "payer".to_string(),
            payee: "payee".to_string(),
            mediator_reference: None,
            total_amount: 500_000_000,
            network_marker: "IRIUM".to_string(),
            creation_time: 1_700_000_000,
            deadlines: AgreementDeadlines {
                settlement_deadline: Some(timeout_height.saturating_sub(10)),
                refund_deadline: Some(timeout_height),
                dispute_window: None,
            },
            release_conditions: vec![AgreementReleaseCondition {
                mode: "secret_preimage".to_string(),
                secret_hash_hex: Some(secret_hash_hex),
                release_authorizer: Some("payer".to_string()),
                notes: None,
            }],
            refund_conditions: vec![AgreementRefundCondition {
                refund_address: payer_address.to_string(),
                timeout_height,
                notes: None,
            }],
            milestones: vec![],
            deposit_rule: None,
            proof_policy_reference: Some("phase2-placeholder".to_string()),
            document_hash: "22".repeat(32),
            metadata_hash: None,
            invoice_reference: None,
            external_reference: None,
            disputed_metadata_only: false,
            primary_resolver: None,
            fallback_resolver: None,
            primary_resolver_fee: None,
            fallback_resolver_fee: None,
            asset_reference: None,
            payment_reference: None,
            purpose_reference: None,
            release_summary: Some("Release when the payer reveals the preimage".to_string()),
            refund_summary: Some("Refund after timeout to the payer".to_string()),
            attestor_reference: None,
            resolver_reference: None,
            notes: Some("fixture".to_string()),
        }
    }

    fn milestone_agreement_for_test(
        payer_address: &str,
        payee_address: &str,
        timeout_height: u64,
    ) -> (AgreementObject, Vec<Vec<u8>>) {
        let s1 = b"milestone-one".to_vec();
        let s2 = b"milestone-two".to_vec();
        let agreement = AgreementObject {
            schema_id: Some(irium_node_rs::settlement::AGREEMENT_SCHEMA_ID_V1.to_string()),
            agreement_id: "agr-node-ms".to_string(),
            version: 1,
            template_type: AgreementTemplateType::MilestoneSettlement,
            parties: vec![
                AgreementParty {
                    party_id: "payer".to_string(),
                    display_name: "Payer".to_string(),
                    address: payer_address.to_string(),
                    role: Some("payer".to_string()),
                },
                AgreementParty {
                    party_id: "payee".to_string(),
                    display_name: "Payee".to_string(),
                    address: payee_address.to_string(),
                    role: Some("payee".to_string()),
                },
            ],
            payer: "payer".to_string(),
            payee: "payee".to_string(),
            mediator_reference: None,
            total_amount: 700_000_000,
            network_marker: "IRIUM".to_string(),
            creation_time: 1_700_000_000,
            deadlines: AgreementDeadlines {
                settlement_deadline: Some(timeout_height.saturating_sub(10)),
                refund_deadline: Some(timeout_height),
                dispute_window: None,
            },
            release_conditions: vec![AgreementReleaseCondition {
                mode: "secret_preimage".to_string(),
                secret_hash_hex: Some(hex::encode(Sha256::digest(&s1))),
                release_authorizer: Some("payer".to_string()),
                notes: None,
            }],
            refund_conditions: vec![AgreementRefundCondition {
                refund_address: payer_address.to_string(),
                timeout_height,
                notes: None,
            }],
            milestones: vec![
                AgreementMilestone {
                    milestone_id: "ms1".to_string(),
                    title: "Kickoff".to_string(),
                    amount: 300_000_000,
                    recipient_address: payee_address.to_string(),
                    refund_address: payer_address.to_string(),
                    secret_hash_hex: hex::encode(Sha256::digest(&s1)),
                    timeout_height,
                    metadata_hash: None,
                },
                AgreementMilestone {
                    milestone_id: "ms2".to_string(),
                    title: "Delivery".to_string(),
                    amount: 400_000_000,
                    recipient_address: payee_address.to_string(),
                    refund_address: payer_address.to_string(),
                    secret_hash_hex: hex::encode(Sha256::digest(&s2)),
                    timeout_height: timeout_height + 5,
                    metadata_hash: None,
                },
            ],
            deposit_rule: None,
            proof_policy_reference: Some("phase2-placeholder".to_string()),
            document_hash: "22".repeat(32),
            metadata_hash: None,
            invoice_reference: None,
            external_reference: None,
            disputed_metadata_only: false,
            primary_resolver: None,
            fallback_resolver: None,
            primary_resolver_fee: None,
            fallback_resolver_fee: None,
            asset_reference: None,
            payment_reference: None,
            purpose_reference: None,
            release_summary: Some("Milestone releases remain off-chain coordination unless a specific HTLC branch is exercised".to_string()),
            refund_summary: Some("Refund each milestone after its timeout back to the payer".to_string()),
            attestor_reference: None,
            resolver_reference: None,
            notes: Some("fixture".to_string()),
        };
        (agreement, vec![s1, s2])
    }

    async fn fund_agreement_for_test(
        state: AppState,
        agreement: AgreementObject,
    ) -> FundAgreementResponse {
        fund_agreement(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(FundAgreementRequest {
                agreement,
                fee_per_byte: Some(1),
                broadcast: Some(false),
                milestone_id: None,
            }),
        )
        .await
        .expect("fund agreement")
        .0
    }

    #[tokio::test]
    async fn agreement_release_eligibility_when_preimage_available() {
        let (state, sender, recipient, _) = create_test_state(Some(0));
        add_wallet_utxo(&state, &sender, 20_000_000_000);
        let (agreement, secrets) = milestone_agreement_for_test(&sender, &recipient, 120);
        let funded = fund_agreement_for_test(state.clone(), agreement.clone()).await;
        let funding_tx = decode_full_tx(&hex::decode(&funded.raw_tx_hex).unwrap()).unwrap();
        apply_tx_to_chain_for_test(&state, &funding_tx);
        confirm_tx_for_agreement_scan(&state, &funding_tx);
        let target = funded
            .outputs
            .iter()
            .find(|o| o.milestone_id.as_deref() == Some("ms1"))
            .expect("ms1 output")
            .vout;
        let resp = agreement_release_eligibility(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(AgreementSpendRequest {
                agreement,
                funding_txid: funded.txid,
                htlc_vout: Some(target),
                milestone_id: Some("ms1".to_string()),
                destination_address: Some(recipient),
                fee_per_byte: None,
                broadcast: Some(false),
                secret_hex: Some(hex::encode(&secrets[0])),
            }),
        )
        .await
        .expect("eligibility")
        .0;
        assert!(resp.eligible);
        assert!(resp.preimage_required);
        assert_eq!(resp.branch, "release");
    }

    #[tokio::test]
    async fn agreement_release_ineligible_without_required_preimage() {
        let (state, sender, recipient, _) = create_test_state(Some(0));
        add_wallet_utxo(&state, &sender, 20_000_000_000);
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 120);
        let funded = fund_agreement_for_test(state.clone(), agreement.clone()).await;
        let funding_tx = decode_full_tx(&hex::decode(&funded.raw_tx_hex).unwrap()).unwrap();
        apply_tx_to_chain_for_test(&state, &funding_tx);
        confirm_tx_for_agreement_scan(&state, &funding_tx);
        let target = funded
            .outputs
            .iter()
            .find(|o| o.milestone_id.as_deref() == Some("ms1"))
            .expect("ms1 output")
            .vout;
        let resp = agreement_release_eligibility(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(AgreementSpendRequest {
                agreement,
                funding_txid: funded.txid,
                htlc_vout: Some(target),
                milestone_id: Some("ms1".to_string()),
                destination_address: Some(recipient),
                fee_per_byte: None,
                broadcast: Some(false),
                secret_hex: None,
            }),
        )
        .await
        .expect("eligibility")
        .0;
        assert!(!resp.eligible);
        assert!(resp
            .reasons
            .iter()
            .any(|r| r == "secret_hex_required_for_release"));
    }

    #[tokio::test]
    async fn agreement_refund_eligibility_when_timeout_matured() {
        let (state, sender, recipient, _) = create_test_state(Some(0));
        add_wallet_utxo(&state, &sender, 20_000_000_000);
        {
            let mut chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
            chain.height = 140;
        }
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 120);
        let funded = fund_agreement_for_test(state.clone(), agreement.clone()).await;
        let funding_tx = decode_full_tx(&hex::decode(&funded.raw_tx_hex).unwrap()).unwrap();
        apply_tx_to_chain_for_test(&state, &funding_tx);
        confirm_tx_for_agreement_scan(&state, &funding_tx);
        let target = funded
            .outputs
            .iter()
            .find(|o| o.milestone_id.as_deref() == Some("ms1"))
            .expect("ms1 output")
            .vout;
        let resp = agreement_refund_eligibility(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(AgreementSpendRequest {
                agreement,
                funding_txid: funded.txid,
                htlc_vout: Some(target),
                milestone_id: Some("ms1".to_string()),
                destination_address: Some(sender),
                fee_per_byte: None,
                broadcast: Some(false),
                secret_hex: None,
            }),
        )
        .await
        .expect("eligibility")
        .0;
        assert!(resp.eligible);
        assert!(resp.timeout_reached);
        assert_eq!(resp.branch, "refund");
    }

    #[tokio::test]
    async fn agreement_refund_ineligible_before_timeout() {
        let (state, sender, recipient, _) = create_test_state(Some(0));
        add_wallet_utxo(&state, &sender, 20_000_000_000);
        {
            let mut chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
            chain.height = 100;
        }
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 120);
        let funded = fund_agreement_for_test(state.clone(), agreement.clone()).await;
        let funding_tx = decode_full_tx(&hex::decode(&funded.raw_tx_hex).unwrap()).unwrap();
        apply_tx_to_chain_for_test(&state, &funding_tx);
        confirm_tx_for_agreement_scan(&state, &funding_tx);
        let target = funded
            .outputs
            .iter()
            .find(|o| o.milestone_id.as_deref() == Some("ms1"))
            .expect("ms1 output")
            .vout;
        let resp = agreement_refund_eligibility(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(AgreementSpendRequest {
                agreement,
                funding_txid: funded.txid,
                htlc_vout: Some(target),
                milestone_id: Some("ms1".to_string()),
                destination_address: Some(sender),
                fee_per_byte: None,
                broadcast: Some(false),
                secret_hex: None,
            }),
        )
        .await
        .expect("eligibility")
        .0;
        assert!(!resp.eligible);
        assert!(resp
            .reasons
            .iter()
            .any(|r| r == "refund_timeout_not_reached"));
    }

    #[tokio::test]
    async fn agreement_release_rejects_non_htlc_backed_funding_path() {
        let (state, sender, recipient, _) = create_test_state(Some(0));
        let plain_tx = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOutput {
                value: 5_000_000,
                script_pubkey: p2pkh_script(&[9u8; 20]),
            }],
            locktime: 0,
        };
        confirm_tx_for_agreement_scan(&state, &plain_tx);
        let agreement =
            sample_agreement_for_test(&sender, &recipient, hex::encode(Sha256::digest(b"x")), 120);
        let res = agreement_release_eligibility(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(AgreementSpendRequest {
                agreement,
                funding_txid: hex::encode(plain_tx.txid()),
                htlc_vout: Some(0),
                milestone_id: None,
                destination_address: Some(sender),
                fee_per_byte: None,
                broadcast: Some(false),
                secret_hex: Some(hex::encode(b"x")),
            }),
        )
        .await;
        assert!(matches!(res, Err(StatusCode::BAD_REQUEST)));
    }

    #[tokio::test]
    async fn agreement_release_eligibility_resolves_requested_milestone_leg() {
        let (state, sender, recipient, _) = create_test_state(Some(0));
        add_wallet_utxo(&state, &sender, 30_000_000_000);
        let (agreement, secrets) = milestone_agreement_for_test(&sender, &recipient, 140);
        let funded = fund_agreement_for_test(state.clone(), agreement.clone()).await;
        let funding_tx = decode_full_tx(&hex::decode(&funded.raw_tx_hex).unwrap()).unwrap();
        apply_tx_to_chain_for_test(&state, &funding_tx);
        confirm_tx_for_agreement_scan(&state, &funding_tx);
        let target = funded
            .outputs
            .iter()
            .find(|o| o.milestone_id.as_deref() == Some("ms2"))
            .expect("ms2 output")
            .vout;
        let resp = agreement_release_eligibility(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(AgreementSpendRequest {
                agreement,
                funding_txid: funded.txid,
                htlc_vout: Some(target),
                milestone_id: Some("ms2".to_string()),
                destination_address: Some(recipient),
                fee_per_byte: None,
                broadcast: Some(false),
                secret_hex: Some(hex::encode(&secrets[1])),
            }),
        )
        .await
        .expect("eligibility")
        .0;
        assert!(resp.eligible);
        assert_eq!(resp.milestone_id.as_deref(), Some("ms2"));
        assert_eq!(resp.htlc_vout, Some(target));
    }

    #[test]
    fn status_best_header_tip_hash_non_empty_when_height_positive() {
        let locked = load_locked_genesis().expect("locked genesis");
        let genesis_block = block_from_locked(&locked).expect("genesis block");
        let pow_limit = genesis_block.header.target();
        let params = ChainParams {
            pow_limit,
            genesis_block,
            htlcv1_activation_height: None,
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
        let chain = ChainState::new(params);
        let genesis_hash = hex::encode(chain.tip_hash());

        let tip = compute_best_header_tip_from_chain(&chain, &genesis_hash);
        assert!(!tip.hash.is_empty(), "best header hash should not be empty");

        let fallback = cached_best_header_tip(1, "", &genesis_hash);
        assert!(
            !fallback.hash.is_empty(),
            "fallback best_header_tip.hash must not be empty when height > 0"
        );
        assert_eq!(fallback.height, 1);
    }

    // ---- Phase 2 RPC tests ----

    fn make_rpc_policy(agreement_hash: &str, pubkey_hex: &str) -> ProofPolicy {
        ProofPolicy {
            policy_id: "rpc-pol-001".to_string(),
            schema_id: PROOF_POLICY_SCHEMA_ID.to_string(),
            agreement_hash: agreement_hash.to_string(),
            required_proofs: vec![ProofRequirement {
                requirement_id: "req-rpc-001".to_string(),
                proof_type: "delivery_confirmation".to_string(),
                required_by: None,
                required_attestor_ids: vec!["rpc-attestor".to_string()],
                resolution: ProofResolution::Release,
                milestone_id: None,
                threshold: None,
            }],
            no_response_rules: vec![],
            attestors: vec![ApprovedAttestor {
                attestor_id: "rpc-attestor".to_string(),
                pubkey_hex: pubkey_hex.to_string(),
                display_name: None,
                domain: None,
            }],
            notes: None,
            expires_at_height: None,
            milestones: vec![],
            holdback: None,
        }
    }

    #[allow(dead_code)] // test helper; used by test setup utilities
    fn make_test_agreement(agreement_hash_hint: &str) -> AgreementObject {
        let addr = "iRLeMFpzwVhvDBkfXFqMFLhAUoTQVuSmma".to_string();
        AgreementObject {
            schema_id: Some(irium_node_rs::settlement::AGREEMENT_SCHEMA_ID_V1.to_string()),
            agreement_id: agreement_hash_hint.to_string(),
            version: 1,
            template_type: AgreementTemplateType::SimpleReleaseRefund,
            parties: vec![
                AgreementParty {
                    party_id: "alice".to_string(),
                    display_name: "Alice".to_string(),
                    address: addr.clone(),
                    role: Some("payer".to_string()),
                },
                AgreementParty {
                    party_id: "bob".to_string(),
                    display_name: "Bob".to_string(),
                    address: addr.clone(),
                    role: Some("payee".to_string()),
                },
            ],
            payer: "alice".to_string(),
            payee: "bob".to_string(),
            mediator_reference: None,
            total_amount: 5_000_000_000,
            network_marker: "IRIUM".to_string(),
            creation_time: 1_700_000_000,
            deadlines: AgreementDeadlines {
                settlement_deadline: None,
                refund_deadline: None,
                dispute_window: None,
            },
            release_conditions: vec![AgreementReleaseCondition {
                mode: "attestor_release".to_string(),
                secret_hash_hex: None,
                release_authorizer: None,
                notes: None,
            }],
            refund_conditions: vec![AgreementRefundCondition {
                refund_address: addr,
                timeout_height: 9999,
                notes: None,
            }],
            milestones: vec![],
            deposit_rule: None,
            proof_policy_reference: None,
            document_hash: "ab".repeat(32),
            metadata_hash: None,
            invoice_reference: None,
            external_reference: None,
            disputed_metadata_only: false,
            primary_resolver: None,
            fallback_resolver: None,
            primary_resolver_fee: None,
            fallback_resolver_fee: None,
            asset_reference: None,
            payment_reference: None,
            purpose_reference: None,
            release_summary: None,
            refund_summary: None,
            attestor_reference: None,
            resolver_reference: None,
            notes: None,
        }
    }

    fn rpc_signing_key() -> SigningKey {
        SigningKey::from_bytes((&[11u8; 32]).into()).expect("static signing key")
    }

    fn rpc_pubkey_hex(sk: &SigningKey) -> String {
        hex::encode(sk.verifying_key().to_encoded_point(false).as_bytes())
    }

    fn sign_rpc_proof(proof: &SettlementProof, sk: &SigningKey) -> ProofSignatureEnvelope {
        use sha2::{Digest, Sha256};
        let payload = settlement_proof_payload_bytes(proof).unwrap();
        let digest = Sha256::digest(&payload);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&digest);
        let sig: k256::ecdsa::Signature = sk.sign_prehash(&arr).unwrap();
        ProofSignatureEnvelope {
            signature_type: AGREEMENT_SIGNATURE_TYPE_SECP256K1.to_string(),
            pubkey_hex: rpc_pubkey_hex(sk),
            signature_hex: hex::encode(sig.to_bytes()),
            payload_hash: hex::encode(digest),
        }
    }

    fn make_rpc_proof(agreement_hash: &str, sk: &SigningKey) -> SettlementProof {
        let mut proof = SettlementProof {
            proof_id: "rpc-prf-001".to_string(),
            schema_id: SETTLEMENT_PROOF_SCHEMA_ID.to_string(),
            proof_type: "delivery_confirmation".to_string(),
            agreement_hash: agreement_hash.to_string(),
            milestone_id: None,
            attested_by: "rpc-attestor".to_string(),
            attestation_time: 1_700_000_000,
            evidence_hash: None,
            evidence_summary: Some("rpc test delivery".to_string()),
            signature: ProofSignatureEnvelope {
                signature_type: AGREEMENT_SIGNATURE_TYPE_SECP256K1.to_string(),
                pubkey_hex: rpc_pubkey_hex(sk),
                signature_hex: String::new(),
                payload_hash: String::new(),
            },
            expires_at_height: None,
            typed_payload: None,
        };
        proof.signature = sign_rpc_proof(&proof, sk);
        proof
    }

    #[tokio::test]
    async fn check_policy_returns_release_eligible_when_requirements_met() {
        use irium_node_rs::settlement::agreement_canonical_bytes;
        let (state, sender, recipient, _) = create_test_state(Some(0));
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);

        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));

        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);
        let policy = make_rpc_policy(&agreement_hash, &pubkey_hex);
        let proof = make_rpc_proof(&agreement_hash, &sk);

        let req = CheckPolicyRequest {
            agreement,
            policy,
            proofs: vec![proof],
        };

        let resp = check_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(req),
        )
        .await
        .expect("check_policy_rpc must succeed")
        .0;

        assert!(
            resp.release_eligible,
            "valid proof must yield release_eligible"
        );
        assert!(!resp.refund_eligible);
        assert_eq!(resp.policy_id, "rpc-pol-001");
        assert_eq!(resp.agreement_hash, agreement_hash);
    }

    #[tokio::test]
    async fn check_policy_rejects_agreement_hash_mismatch() {
        let (state, sender, recipient, _) = create_test_state(Some(0));
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);

        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);
        // policy references a wrong hash
        let policy = make_rpc_policy("deadbeef_wrong", &pubkey_hex);

        let req = CheckPolicyRequest {
            agreement,
            policy,
            proofs: vec![],
        };

        let result = check_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(req),
        )
        .await;

        assert!(result.is_err(), "mismatched hash must return error");
        let (status, body) = result.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("policy_eval_failed"), "got: {body}");
    }

    #[tokio::test]
    async fn check_policy_no_proofs_with_no_response_rule_at_tip() {
        use irium_node_rs::settlement::agreement_canonical_bytes;
        let (state, sender, recipient, _) = create_test_state(Some(0));
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);

        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));

        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);
        let mut policy = make_rpc_policy(&agreement_hash, &pubkey_hex);
        // deadline at height 0, so tip (0) >= deadline (0) → triggers immediately
        policy.no_response_rules.push(NoResponseRule {
            rule_id: "rpc-rule-refund-0".to_string(),
            deadline_height: 0,
            trigger: NoResponseTrigger::FundedAndNoRelease,
            resolution: ProofResolution::Refund,
            milestone_id: None,
            notes: None,
        });
        // remove required proofs so the only path is no-response
        policy.required_proofs.clear();

        let req = CheckPolicyRequest {
            agreement,
            policy,
            proofs: vec![],
        };

        let resp = check_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(req),
        )
        .await
        .expect("check_policy_rpc must succeed")
        .0;

        assert!(
            resp.refund_eligible,
            "no-response rule must yield refund_eligible"
        );
        assert!(!resp.release_eligible);
        assert!(
            resp.reason.contains("rpc-rule-refund-0"),
            "reason must mention rule: {}",
            resp.reason
        );
    }

    // ---- Phase 2 proof store RPC tests ----

    fn make_signed_proof_for_rpc(
        agreement_hash: &str,
        signing_key: &SigningKey,
    ) -> SettlementProof {
        use irium_node_rs::settlement::{
            settlement_proof_payload_bytes, AGREEMENT_SIGNATURE_TYPE_SECP256K1,
            SETTLEMENT_PROOF_SCHEMA_ID,
        };
        let pubkey_hex = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let mut proof = SettlementProof {
            proof_id: "rpc-store-prf-001".to_string(),
            schema_id: SETTLEMENT_PROOF_SCHEMA_ID.to_string(),
            proof_type: "delivery_confirmation".to_string(),
            agreement_hash: agreement_hash.to_string(),
            milestone_id: None,
            attested_by: "att-node-test".to_string(),
            attestation_time: 1_700_200_000,
            evidence_hash: None,
            evidence_summary: Some("rpc store test".to_string()),
            signature: ProofSignatureEnvelope {
                signature_type: AGREEMENT_SIGNATURE_TYPE_SECP256K1.to_string(),
                pubkey_hex: pubkey_hex.clone(),
                signature_hex: String::new(),
                payload_hash: String::new(),
            },
            expires_at_height: None,
            typed_payload: None,
        };
        let payload = settlement_proof_payload_bytes(&proof).unwrap();
        let digest = sha2::Sha256::digest(&payload);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&digest);
        let sig: k256::ecdsa::Signature = signing_key.sign_prehash(&arr).unwrap();
        proof.signature.signature_hex = hex::encode(sig.to_bytes());
        proof.signature.payload_hash = hex::encode(digest);
        proof
    }

    /// Variant of make_signed_proof_for_rpc with configurable proof_id and attestation_time.
    fn make_proof_with_time(
        proof_id: &str,
        agreement_hash: &str,
        attestation_time: u64,
        signing_key: &SigningKey,
    ) -> SettlementProof {
        use irium_node_rs::settlement::{
            settlement_proof_payload_bytes, AGREEMENT_SIGNATURE_TYPE_SECP256K1,
            SETTLEMENT_PROOF_SCHEMA_ID,
        };
        let pubkey_hex = hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let mut proof = SettlementProof {
            proof_id: proof_id.to_string(),
            schema_id: SETTLEMENT_PROOF_SCHEMA_ID.to_string(),
            proof_type: "delivery_confirmation".to_string(),
            agreement_hash: agreement_hash.to_string(),
            milestone_id: None,
            attested_by: "att-order-test".to_string(),
            attestation_time,
            evidence_hash: None,
            evidence_summary: Some("ordering test proof".to_string()),
            signature: ProofSignatureEnvelope {
                signature_type: AGREEMENT_SIGNATURE_TYPE_SECP256K1.to_string(),
                pubkey_hex: pubkey_hex.clone(),
                signature_hex: String::new(),
                payload_hash: String::new(),
            },
            expires_at_height: None,
            typed_payload: None,
        };
        let payload = settlement_proof_payload_bytes(&proof).unwrap();
        let digest = sha2::Sha256::digest(&payload);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&digest);
        let sig: k256::ecdsa::Signature = signing_key.sign_prehash(&arr).unwrap();
        proof.signature.signature_hex = hex::encode(sig.to_bytes());
        proof.signature.payload_hash = hex::encode(digest);
        proof
    }

    #[tokio::test]
    async fn list_proofs_rpc_ordering_by_attestation_time() {
        // Proofs submitted in reverse time order must be listed oldest-first.
        let (state, _, _, _) = create_test_state(Some(0));
        let sk1 = SigningKey::from_bytes((&[60u8; 32]).into()).unwrap();
        let sk2 = SigningKey::from_bytes((&[61u8; 32]).into()).unwrap();
        let sk3 = SigningKey::from_bytes((&[62u8; 32]).into()).unwrap();
        let p_late = make_proof_with_time("prf-ord-c", "hash-ord", 3_000, &sk3);
        let p_mid = make_proof_with_time("prf-ord-b", "hash-ord", 2_000, &sk2);
        let p_early = make_proof_with_time("prf-ord-a", "hash-ord", 1_000, &sk1);
        for p in [p_late, p_mid, p_early] {
            let _ = submit_proof_rpc(
                ConnectInfo(test_socket()),
                State(state.clone()),
                HeaderMap::new(),
                Json(SubmitProofRequest { proof: p }),
            )
            .await
            .expect("submit");
        }
        let resp = list_proofs_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(ListProofsRequest {
                agreement_hash: None,
                active_only: false,
                ..Default::default()
            }),
        )
        .await
        .expect("list")
        .0;
        assert_eq!(resp.proofs.len(), 3);
        assert_eq!(
            resp.proofs[0].proof.attestation_time, 1_000,
            "oldest must be first"
        );
        assert_eq!(resp.proofs[1].proof.attestation_time, 2_000);
        assert_eq!(
            resp.proofs[2].proof.attestation_time, 3_000,
            "latest must be last"
        );
    }

    #[tokio::test]
    async fn list_proofs_rpc_ordering_tie_break_by_proof_id() {
        // Two proofs with identical attestation_time must be sorted by proof_id ascending.
        let (state, _, _, _) = create_test_state(Some(0));
        let sk1 = SigningKey::from_bytes((&[63u8; 32]).into()).unwrap();
        let sk2 = SigningKey::from_bytes((&[64u8; 32]).into()).unwrap();
        let p_zzz = make_proof_with_time("prf-tie-zzz", "hash-tie", 5_000, &sk1);
        let p_aaa = make_proof_with_time("prf-tie-aaa", "hash-tie", 5_000, &sk2);
        for p in [p_zzz, p_aaa] {
            let _ = submit_proof_rpc(
                ConnectInfo(test_socket()),
                State(state.clone()),
                HeaderMap::new(),
                Json(SubmitProofRequest { proof: p }),
            )
            .await
            .expect("submit");
        }
        let resp = list_proofs_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(ListProofsRequest {
                agreement_hash: Some("hash-tie".to_string()),
                active_only: false,
                ..Default::default()
            }),
        )
        .await
        .expect("list")
        .0;
        assert_eq!(resp.proofs.len(), 2);
        assert_eq!(
            resp.proofs[0].proof.proof_id, "prf-tie-aaa",
            "earlier proof_id must come first on tie"
        );
        assert_eq!(resp.proofs[1].proof.proof_id, "prf-tie-zzz");
    }

    #[tokio::test]
    async fn list_proofs_rpc_ordering_agreement_scoped() {
        // Agreement-scoped listing must also respect attestation_time order.
        let (state, _, _, _) = create_test_state(Some(0));
        let sk1 = SigningKey::from_bytes((&[65u8; 32]).into()).unwrap();
        let sk2 = SigningKey::from_bytes((&[66u8; 32]).into()).unwrap();
        let sk3 = SigningKey::from_bytes((&[67u8; 32]).into()).unwrap();
        let pa2 = make_proof_with_time("prf-sc-a2", "hash-scope-a", 2_000, &sk2);
        let pa1 = make_proof_with_time("prf-sc-a1", "hash-scope-a", 1_000, &sk1);
        let pb1 = make_proof_with_time("prf-sc-b1", "hash-scope-b", 500, &sk3);
        for p in [pa2, pb1, pa1] {
            let _ = submit_proof_rpc(
                ConnectInfo(test_socket()),
                State(state.clone()),
                HeaderMap::new(),
                Json(SubmitProofRequest { proof: p }),
            )
            .await
            .expect("submit");
        }
        let resp = list_proofs_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(ListProofsRequest {
                agreement_hash: Some("hash-scope-a".to_string()),
                active_only: false,
                ..Default::default()
            }),
        )
        .await
        .expect("list")
        .0;
        assert_eq!(
            resp.proofs.len(),
            2,
            "scoped query must not include other agreement proofs"
        );
        assert_eq!(
            resp.proofs[0].proof.attestation_time, 1_000,
            "oldest scoped proof must be first"
        );
        assert_eq!(resp.proofs[1].proof.attestation_time, 2_000);
    }

    #[tokio::test]
    async fn list_proofs_rpc_ordering_preserved_with_active_only() {
        // active_only filter must not disturb the attestation_time ordering of surviving proofs.
        // Chain tip is always 0 in tests; expires_at_height=Some(0) => expired (0 >= 0),
        // expires_at_height=Some(1) => active (0 < 1).
        let (state, _, _, _) = create_test_state(Some(0));
        let sk1 = SigningKey::from_bytes((&[68u8; 32]).into()).unwrap();
        let sk2 = SigningKey::from_bytes((&[69u8; 32]).into()).unwrap();
        let sk3 = SigningKey::from_bytes((&[70u8; 32]).into()).unwrap();
        let sk4 = SigningKey::from_bytes((&[71u8; 32]).into()).unwrap();
        let p1 = make_proof_with_time("prf-ao-1", "hash-ao", 1_000, &sk1); // no expiry -> active
        let mut p2 = make_proof_with_time("prf-ao-2", "hash-ao", 2_000, &sk2);
        p2.expires_at_height = Some(0); // tip=0 >= 0 -> expired, filtered out
        let mut p3 = make_proof_with_time("prf-ao-3", "hash-ao", 3_000, &sk3);
        p3.expires_at_height = Some(1); // tip=0 < 1 -> active
        let mut p4 = make_proof_with_time("prf-ao-4", "hash-ao", 4_000, &sk4);
        p4.expires_at_height = Some(0); // tip=0 >= 0 -> expired, filtered out
        for p in [p1, p2, p3, p4] {
            let _ = submit_proof_rpc(
                ConnectInfo(test_socket()),
                State(state.clone()),
                HeaderMap::new(),
                Json(SubmitProofRequest { proof: p }),
            )
            .await
            .expect("submit");
        }
        let resp = list_proofs_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(ListProofsRequest {
                agreement_hash: None,
                active_only: true,
                ..Default::default()
            }),
        )
        .await
        .expect("list")
        .0;
        assert_eq!(resp.proofs.len(), 2, "only 2 active proofs must survive");
        assert_eq!(
            resp.proofs[0].proof.attestation_time, 1_000,
            "surviving proofs must remain time-ordered"
        );
        assert_eq!(resp.proofs[1].proof.attestation_time, 3_000);
        assert_eq!(resp.proofs[0].status, "active");
        assert_eq!(resp.proofs[1].status, "active");
    }

    #[tokio::test]
    async fn submit_proof_rpc_rejects_invalid_typed_payload() {
        use irium_node_rs::settlement::{
            settlement_proof_payload_bytes, AGREEMENT_SIGNATURE_TYPE_SECP256K1,
            SETTLEMENT_PROOF_SCHEMA_ID,
        };
        let (state, sender, recipient, _) = create_test_state(Some(0));
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
        use irium_node_rs::settlement::agreement_canonical_bytes;
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));
        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);
        let mut proof = SettlementProof {
            proof_id: "prf-typed-rpc-bad".to_string(),
            schema_id: SETTLEMENT_PROOF_SCHEMA_ID.to_string(),
            proof_type: "delivery_confirmation".to_string(),
            agreement_hash: agreement_hash.clone(),
            milestone_id: None,
            attested_by: "rpc-attestor".to_string(),
            attestation_time: 1_700_999_999,
            evidence_hash: None,
            evidence_summary: None,
            signature: ProofSignatureEnvelope {
                signature_type: AGREEMENT_SIGNATURE_TYPE_SECP256K1.to_string(),
                pubkey_hex: pubkey_hex.clone(),
                signature_hex: String::new(),
                payload_hash: String::new(),
            },
            expires_at_height: None,
            typed_payload: Some(TypedProofPayload {
                proof_kind: String::new(), // invalid: empty
                content_hash: None,
                reference_id: None,
                attributes: None,
            }),
        };
        let payload = settlement_proof_payload_bytes(&proof).unwrap();
        let digest = sha2::Sha256::digest(&payload);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&digest);
        let sig: k256::ecdsa::Signature = sk.sign_prehash(&arr).unwrap();
        proof.signature.signature_hex = hex::encode(sig.to_bytes());
        proof.signature.payload_hash = hex::encode(digest);
        let result = submit_proof_rpc(
            ConnectInfo("127.0.0.1:0".parse().unwrap()),
            State(state),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof }),
        )
        .await;
        assert!(result.is_err(), "empty proof_kind must be rejected by RPC");
        let (status, msg) = result.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(msg.contains("proof_kind"), "got: {msg}");
    }

    #[tokio::test]
    async fn submit_proof_rpc_accepts_valid_proof() {
        let (state, _, _, _) = create_test_state(Some(0));
        let sk = SigningKey::from_bytes((&[17u8; 32]).into()).unwrap();
        let proof = make_signed_proof_for_rpc("cafecafe", &sk);
        let resp = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof }),
        )
        .await
        .expect("submit must succeed")
        .0;
        assert!(resp.accepted);
        assert!(!resp.duplicate);
        assert_eq!(resp.proof_id, "rpc-store-prf-001");
        assert_eq!(resp.tip_height, 0);
        assert!(resp.expires_at_height.is_none());
        assert!(!resp.expired);
    }

    #[tokio::test]
    async fn submit_proof_rpc_rejects_invalid_signature() {
        let (state, _, _, _) = create_test_state(Some(0));
        let sk = SigningKey::from_bytes((&[17u8; 32]).into()).unwrap();
        let mut proof = make_signed_proof_for_rpc("cafecafe", &sk);
        proof.signature.signature_hex = "00".repeat(64);
        let result = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof }),
        )
        .await;
        assert!(result.is_err());
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn submit_proof_rpc_deduplicates() {
        let (state, _, _, _) = create_test_state(Some(0));
        let sk = SigningKey::from_bytes((&[17u8; 32]).into()).unwrap();
        let proof = make_signed_proof_for_rpc("cafecafe", &sk);
        let _ = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest {
                proof: proof.clone(),
            }),
        )
        .await
        .expect("first submit")
        .0;
        let second = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof }),
        )
        .await
        .expect("second submit")
        .0;
        assert!(!second.accepted);
        assert!(second.duplicate);
        assert_eq!(second.tip_height, 0);
        assert!(second.expires_at_height.is_none());
        assert!(!second.expired);
    }

    #[tokio::test]
    async fn list_proofs_rpc_returns_submitted_proofs() {
        let (state, _, _, _) = create_test_state(Some(0));
        let sk = SigningKey::from_bytes((&[17u8; 32]).into()).unwrap();
        let proof = make_signed_proof_for_rpc("listtest", &sk);
        let _ = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof }),
        )
        .await
        .expect("submit");
        let list_resp = list_proofs_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(ListProofsRequest {
                agreement_hash: Some("listtest".to_string()),
                active_only: false,
                ..Default::default()
            }),
        )
        .await
        .expect("list")
        .0;
        assert_eq!(list_resp.returned_count, 1);
        assert_eq!(list_resp.proofs[0].proof.proof_id, "rpc-store-prf-001");
    }

    #[tokio::test]
    async fn store_policy_rpc_accepts_valid_policy() {
        let (state, _, _, _) = create_test_state(Some(0));
        let policy = make_rpc_policy("storepol-hash", "pk-abc");
        let resp = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy,
                replace: false,
            }),
        )
        .await
        .expect("must accept")
        .0;
        assert!(resp.accepted);
        assert!(!resp.updated);
        assert_eq!(resp.agreement_hash, "storepol-hash");
        assert!(resp.message.contains("accepted"), "got: {}", resp.message);
    }

    #[tokio::test]
    async fn store_policy_rpc_rejects_empty_agreement_hash() {
        let (state, _, _, _) = create_test_state(Some(0));
        let mut policy = make_rpc_policy("", "pk");
        policy.agreement_hash = "".to_string();
        let result = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy,
                replace: false,
            }),
        )
        .await;
        assert!(result.is_err(), "must reject empty agreement_hash");
    }

    #[tokio::test]
    async fn store_policy_rpc_rejects_empty_milestone_id() {
        let (state, _, _, _) = create_test_state(Some(0));
        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);
        let mut policy = make_rpc_policy("hash-ms-empty-id", &pubkey_hex);
        policy.milestones = vec![PolicyMilestone {
            milestone_id: "".to_string(),
            label: None,
            holdback: None,
        }];
        let result = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy,
                replace: false,
            }),
        )
        .await;
        assert!(result.is_err(), "must reject empty milestone_id");
    }

    #[tokio::test]
    async fn store_policy_rpc_rejects_duplicate_milestone_id() {
        let (state, _, _, _) = create_test_state(Some(0));
        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);
        let mut policy = make_rpc_policy("hash-ms-dup-id", &pubkey_hex);
        policy.milestones = vec![
            PolicyMilestone {
                milestone_id: "ms-dup".to_string(),
                label: None,
                holdback: None,
            },
            PolicyMilestone {
                milestone_id: "ms-dup".to_string(),
                label: None,
                holdback: None,
            },
        ];
        let result = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy,
                replace: false,
            }),
        )
        .await;
        assert!(result.is_err(), "must reject duplicate milestone_id");
    }

    #[tokio::test]
    async fn get_policy_rpc_returns_stored_policy() {
        let (state, _, _, _) = create_test_state(Some(0));
        let policy = make_rpc_policy("getpol-hash-001", "pk-get");
        let _ = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy: policy.clone(),
                replace: false,
            }),
        )
        .await
        .expect("store must succeed");
        let resp = get_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(GetPolicyRequest {
                agreement_hash: "getpol-hash-001".to_string(),
            }),
        )
        .await
        .expect("get must succeed")
        .0;
        assert!(resp.found);
        assert_eq!(resp.policy.as_ref().unwrap().policy_id, policy.policy_id);
        assert_eq!(
            resp.policy.as_ref().unwrap().agreement_hash,
            "getpol-hash-001"
        );
    }

    #[tokio::test]
    async fn get_policy_rpc_returns_not_found_for_missing() {
        let (state, _, _, _) = create_test_state(Some(0));
        let resp = get_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(GetPolicyRequest {
                agreement_hash: "nosuchpolicy".to_string(),
            }),
        )
        .await
        .expect("get must not error")
        .0;
        assert!(!resp.found);
        assert!(resp.policy.is_none());
    }

    #[tokio::test]
    async fn evaluate_policy_rpc_success_with_stored_policy_and_proof() {
        use irium_node_rs::settlement::agreement_canonical_bytes;
        let (state, sender, recipient, _) = create_test_state(Some(0));
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));

        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);

        // Store policy
        let policy = make_rpc_policy(&agreement_hash, &pubkey_hex);
        let _ = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy,
                replace: false,
            }),
        )
        .await
        .expect("store policy");

        // Store proof (attested_by matches rpc-attestor in policy)
        let proof = make_rpc_proof(&agreement_hash, &sk);
        let _ = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof }),
        )
        .await
        .expect("submit proof");

        // Evaluate using stored artifacts
        let resp = evaluate_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(EvaluatePolicyRequest { agreement }),
        )
        .await
        .expect("evaluate must succeed")
        .0;

        assert!(resp.policy_found);
        assert_eq!(resp.policy_id.as_deref(), Some("rpc-pol-001"));
        assert_eq!(resp.proof_count, 1);
        assert!(
            resp.release_eligible,
            "expected release eligible; reason: {}",
            resp.reason
        );
        assert!(!resp.refund_eligible);
        assert!(
            resp.evaluated_rules
                .iter()
                .any(|r| r.contains("verified ok")),
            "got rules: {:?}",
            resp.evaluated_rules
        );
    }

    #[tokio::test]
    async fn evaluate_policy_rpc_missing_policy_returns_not_found() {
        let (state, sender, recipient, _) = create_test_state(Some(0));
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);

        let resp = evaluate_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(EvaluatePolicyRequest { agreement }),
        )
        .await
        .expect("evaluate must not error")
        .0;

        assert!(!resp.policy_found);
        assert!(resp.policy_id.is_none());
        assert_eq!(resp.proof_count, 0);
        assert!(!resp.release_eligible);
        assert!(!resp.refund_eligible);
        assert!(
            resp.reason.contains("no policy stored"),
            "got reason: {}",
            resp.reason
        );
    }

    #[tokio::test]
    async fn evaluate_policy_rpc_no_proofs_not_eligible() {
        use irium_node_rs::settlement::agreement_canonical_bytes;
        let (state, sender, recipient, _) = create_test_state(Some(0));
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));

        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);
        let policy = make_rpc_policy(&agreement_hash, &pubkey_hex);
        let _ = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy,
                replace: false,
            }),
        )
        .await
        .expect("store policy");

        let resp = evaluate_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(EvaluatePolicyRequest { agreement }),
        )
        .await
        .expect("evaluate must not error")
        .0;

        assert!(resp.policy_found);
        assert_eq!(resp.proof_count, 0);
        assert!(!resp.release_eligible);
    }

    #[tokio::test]
    async fn evaluate_policy_rpc_cross_agreement_proof_not_fetched() {
        use irium_node_rs::settlement::agreement_canonical_bytes;
        let (state, sender, recipient, _) = create_test_state(Some(0));
        let (agreement_b, _) = milestone_agreement_for_test(&sender, &recipient, 200);
        let bytes_b = agreement_canonical_bytes(&agreement_b).unwrap();
        let hash_b = hex::encode(Sha256::digest(&bytes_b));

        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);

        let policy_b = make_rpc_policy(&hash_b, &pubkey_hex);
        let _ = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy: policy_b,
                replace: false,
            }),
        )
        .await
        .expect("store policy b");

        // Proof stored for a different hash
        let proof_for_a = make_rpc_proof(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &sk,
        );
        let _ = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof: proof_for_a }),
        )
        .await
        .expect("submit proof for a");

        let resp = evaluate_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(EvaluatePolicyRequest {
                agreement: agreement_b,
            }),
        )
        .await
        .expect("evaluate must not error")
        .0;

        assert!(resp.policy_found);
        assert_eq!(resp.proof_count, 0, "proof for A must not be fetched for B");
        assert_eq!(resp.expired_proof_count, 0);
        assert_eq!(resp.matched_proof_count, 0);
        assert!(resp.matched_proof_ids.is_empty());
        assert!(!resp.release_eligible);
    }

    #[tokio::test]
    async fn evaluate_policy_rpc_enrichment_satisfied_by_active_proof() {
        use irium_node_rs::settlement::agreement_canonical_bytes;
        let (state, sender, recipient, _) = create_test_state(Some(0));
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));
        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);
        let policy = make_rpc_policy(&agreement_hash, &pubkey_hex);
        let _ = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy,
                replace: false,
            }),
        )
        .await
        .expect("store policy");
        let proof = make_rpc_proof(&agreement_hash, &sk);
        let _ = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof }),
        )
        .await
        .expect("submit proof");
        let resp = evaluate_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(EvaluatePolicyRequest { agreement }),
        )
        .await
        .expect("evaluate")
        .0;
        assert_eq!(resp.proof_count, 1);
        assert_eq!(resp.expired_proof_count, 0, "proof is active");
        assert_eq!(resp.matched_proof_count, 1, "one proof verified ok");
        assert_eq!(resp.matched_proof_ids.len(), 1);
        assert!(resp.release_eligible);
    }

    #[tokio::test]
    async fn evaluate_policy_rpc_enrichment_expired_proof_excluded() {
        use irium_node_rs::settlement::agreement_canonical_bytes;
        let (state, sender, recipient, _) = create_test_state(Some(0));
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));
        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);
        let policy = make_rpc_policy(&agreement_hash, &pubkey_hex);
        let _ = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy,
                replace: false,
            }),
        )
        .await
        .expect("store policy");
        let mut proof = make_rpc_proof(&agreement_hash, &sk);
        proof.expires_at_height = Some(0);
        let _ = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof }),
        )
        .await
        .expect("submit proof");
        let resp = evaluate_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(EvaluatePolicyRequest { agreement }),
        )
        .await
        .expect("evaluate")
        .0;
        assert_eq!(resp.proof_count, 0, "expired proof not in active count");
        assert_eq!(resp.expired_proof_count, 1, "one proof filtered as expired");
        assert_eq!(resp.matched_proof_count, 0);
        assert!(resp.matched_proof_ids.is_empty());
        assert!(!resp.release_eligible);
    }

    #[tokio::test]
    async fn evaluate_policy_rpc_enrichment_mixed_active_and_expired() {
        use irium_node_rs::settlement::agreement_canonical_bytes;
        let (state, sender, recipient, _) = create_test_state(Some(0));
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));
        let sk = rpc_signing_key();
        let sk2 = SigningKey::from_bytes((&[77u8; 32]).into()).unwrap();
        let pubkey_hex = rpc_pubkey_hex(&sk);
        let policy = make_rpc_policy(&agreement_hash, &pubkey_hex);
        let _ = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy,
                replace: false,
            }),
        )
        .await
        .expect("store policy");
        let active_proof = make_rpc_proof(&agreement_hash, &sk);
        let _ = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest {
                proof: active_proof,
            }),
        )
        .await
        .expect("submit active");
        let mut expired_proof = make_proof_with_time("prf-expired-mix", &agreement_hash, 500, &sk2);
        expired_proof.expires_at_height = Some(0);
        let _ = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest {
                proof: expired_proof,
            }),
        )
        .await
        .expect("submit expired");
        let resp = evaluate_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(EvaluatePolicyRequest { agreement }),
        )
        .await
        .expect("evaluate")
        .0;
        assert_eq!(resp.proof_count, 1, "only active proof in proof_count");
        assert_eq!(resp.expired_proof_count, 1, "one expired");
        assert_eq!(resp.matched_proof_count, 1, "active proof verified ok");
        assert_eq!(resp.matched_proof_ids.len(), 1);
        assert!(resp.release_eligible);
    }

    #[tokio::test]
    async fn evaluate_policy_rpc_enrichment_empty_proof_set() {
        use irium_node_rs::settlement::agreement_canonical_bytes;
        let (state, sender, recipient, _) = create_test_state(Some(0));
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));
        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);
        let policy = make_rpc_policy(&agreement_hash, &pubkey_hex);
        let _ = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy,
                replace: false,
            }),
        )
        .await
        .expect("store policy");
        let resp = evaluate_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(EvaluatePolicyRequest { agreement }),
        )
        .await
        .expect("evaluate")
        .0;
        assert_eq!(resp.proof_count, 0);
        assert_eq!(resp.expired_proof_count, 0);
        assert_eq!(resp.matched_proof_count, 0);
        assert!(resp.matched_proof_ids.is_empty());
        assert!(!resp.release_eligible);
    }

    // ---- outcome field tests ----

    #[tokio::test]
    async fn evaluate_policy_rpc_outcome_satisfied() {
        // Valid proof matches policy -> outcome "satisfied".
        use irium_node_rs::settlement::agreement_canonical_bytes;
        let (state, sender, recipient, _) = create_test_state(Some(0));
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));
        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);
        let policy = make_rpc_policy(&agreement_hash, &pubkey_hex);
        let _ = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy,
                replace: false,
            }),
        )
        .await
        .expect("store policy");
        let proof = make_rpc_proof(&agreement_hash, &sk);
        let _ = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof }),
        )
        .await
        .expect("submit proof");
        let resp = evaluate_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(EvaluatePolicyRequest { agreement }),
        )
        .await
        .expect("evaluate")
        .0;
        assert_eq!(resp.outcome, PolicyOutcome::Satisfied);
        assert!(resp.release_eligible);
        assert!(!resp.refund_eligible);
    }

    #[tokio::test]
    async fn evaluate_policy_rpc_outcome_unsatisfied_missing_proofs() {
        // No proofs submitted, no deadline elapsed -> outcome "unsatisfied".
        use irium_node_rs::settlement::agreement_canonical_bytes;
        let (state, sender, recipient, _) = create_test_state(Some(0));
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));
        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);
        let policy = make_rpc_policy(&agreement_hash, &pubkey_hex);
        let _ = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy,
                replace: false,
            }),
        )
        .await
        .expect("store policy");
        let resp = evaluate_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(EvaluatePolicyRequest { agreement }),
        )
        .await
        .expect("evaluate")
        .0;
        assert_eq!(resp.outcome, PolicyOutcome::Unsatisfied);
        assert!(!resp.release_eligible);
        assert!(!resp.refund_eligible);
    }

    #[tokio::test]
    async fn evaluate_policy_rpc_outcome_unsatisfied_expired_proofs_only() {
        // Only expired proofs remain -> active proof_count=0, outcome "unsatisfied".
        use irium_node_rs::settlement::agreement_canonical_bytes;
        let (state, sender, recipient, _) = create_test_state(Some(0));
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));
        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);
        let policy = make_rpc_policy(&agreement_hash, &pubkey_hex);
        let _ = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy,
                replace: false,
            }),
        )
        .await
        .expect("store policy");
        let mut proof = make_proof_with_time("prf-exp-out", &agreement_hash, 1_000, &sk);
        proof.expires_at_height = Some(5);
        let _ = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof }),
        )
        .await
        .expect("submit expired proof");
        // Advance chain past expiry
        {
            let mut chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
            chain.height = 10;
        }
        let resp = evaluate_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(EvaluatePolicyRequest { agreement }),
        )
        .await
        .expect("evaluate")
        .0;
        assert_eq!(resp.outcome, PolicyOutcome::Unsatisfied);
        assert_eq!(resp.proof_count, 0, "expired proof must be excluded");
        assert_eq!(resp.expired_proof_count, 1);
        assert!(!resp.release_eligible);
    }

    #[tokio::test]
    async fn evaluate_policy_rpc_outcome_timeout_no_response_rule() {
        // No-response rule deadline elapsed with no release -> outcome "timeout".
        use irium_node_rs::settlement::agreement_canonical_bytes;
        let (state, sender, recipient, _) = create_test_state(Some(0));
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));
        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);
        let mut policy = make_rpc_policy(&agreement_hash, &pubkey_hex);
        policy.no_response_rules.push(NoResponseRule {
            rule_id: "rule-timeout-50".to_string(),
            deadline_height: 50,
            trigger: NoResponseTrigger::FundedAndNoRelease,
            resolution: ProofResolution::Refund,
            milestone_id: None,
            notes: None,
        });
        let _ = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy,
                replace: false,
            }),
        )
        .await
        .expect("store policy");
        // tip_height() = chain.height - 1; set to 51 so tip=50 meets deadline 50.
        {
            let mut chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
            chain.height = 51;
        }
        let resp = evaluate_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(EvaluatePolicyRequest { agreement }),
        )
        .await
        .expect("evaluate")
        .0;
        assert_eq!(resp.outcome, PolicyOutcome::Timeout);
        assert!(resp.refund_eligible);
        assert!(!resp.release_eligible);
    }

    #[tokio::test]
    async fn evaluate_policy_rpc_outcome_timeout_required_by_deadline() {
        // Refund required_by deadline elapsed with no proof -> outcome "timeout".
        use irium_node_rs::settlement::agreement_canonical_bytes;
        let (state, sender, recipient, _) = create_test_state(Some(0));
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));
        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);
        let mut policy = make_rpc_policy(&agreement_hash, &pubkey_hex);
        policy.required_proofs = vec![ProofRequirement {
            requirement_id: "req-refund-dl".to_string(),
            proof_type: "delivery_confirmation".to_string(),
            required_by: Some(75),
            required_attestor_ids: vec!["rpc-attestor".to_string()],
            resolution: ProofResolution::Refund,
            milestone_id: None,
            threshold: None,
        }];
        let _ = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy,
                replace: false,
            }),
        )
        .await
        .expect("store policy");
        // tip_height() = chain.height - 1; set to 76 so tip=75 meets deadline 75.
        {
            let mut chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
            chain.height = 76;
        }
        let resp = evaluate_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(EvaluatePolicyRequest { agreement }),
        )
        .await
        .expect("evaluate")
        .0;
        assert_eq!(resp.outcome, PolicyOutcome::Timeout);
        assert!(resp.refund_eligible);
        assert!(!resp.release_eligible);
    }

    #[tokio::test]
    async fn evaluate_policy_rpc_outcome_satisfied_when_no_response_deadline_also_elapsed() {
        // Proofs satisfy release AND no-response deadline has elapsed.
        // Satisfied must take priority; outcome must be Satisfied.
        use irium_node_rs::settlement::agreement_canonical_bytes;
        let (state, sender, recipient, _) = create_test_state(Some(0));
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));
        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);
        let mut policy = make_rpc_policy(&agreement_hash, &pubkey_hex);
        policy.no_response_rules.push(NoResponseRule {
            rule_id: "rule-refund-suppress".to_string(),
            deadline_height: 10,
            trigger: NoResponseTrigger::FundedAndNoRelease,
            resolution: ProofResolution::Refund,
            milestone_id: None,
            notes: None,
        });
        let _ = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy,
                replace: false,
            }),
        )
        .await
        .expect("store policy");
        // The proof must have attestation_time <= the refund deadline (10) to be
        // considered timely by the late-proof guard in evaluate_policy.
        let mut proof = make_rpc_proof(&agreement_hash, &sk);
        proof.attestation_time = 5;
        proof.signature = sign_rpc_proof(&proof, &sk);
        let _ = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof }),
        )
        .await
        .expect("submit proof");
        {
            let mut chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
            chain.height = 100;
        }
        let resp = evaluate_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(EvaluatePolicyRequest { agreement }),
        )
        .await
        .expect("evaluate")
        .0;
        assert_eq!(resp.outcome, PolicyOutcome::Satisfied);
        assert!(resp.release_eligible);
        assert!(!resp.refund_eligible);
    }

    #[tokio::test]
    async fn evaluate_policy_rpc_outcome_unsatisfied_no_policy() {
        // No policy stored for the agreement -> outcome "unsatisfied".
        let (state, sender, recipient, _) = create_test_state(Some(0));
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
        let resp = evaluate_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(EvaluatePolicyRequest { agreement }),
        )
        .await
        .expect("evaluate")
        .0;
        assert_eq!(resp.outcome, PolicyOutcome::Unsatisfied);
        assert!(!resp.policy_found);
        assert!(!resp.release_eligible);
    }

    // ---- milestone rpc tests ----

    fn make_rpc_policy_with_milestones(
        agreement_hash: &str,
        pubkey_hex: &str,
        milestones: &[&str],
    ) -> ProofPolicy {
        let ms_decls: Vec<PolicyMilestone> = milestones
            .iter()
            .map(|id| PolicyMilestone {
                milestone_id: id.to_string(),
                label: None,
                holdback: None,
            })
            .collect();
        let reqs: Vec<ProofRequirement> = milestones
            .iter()
            .map(|id| ProofRequirement {
                requirement_id: format!("req-{}", id),
                proof_type: format!("proof_type_{}", id),
                required_by: None,
                required_attestor_ids: vec!["rpc-attestor".to_string()],
                resolution: ProofResolution::MilestoneRelease,
                milestone_id: Some(id.to_string()),
                threshold: None,
            })
            .collect();
        ProofPolicy {
            policy_id: "pol-ms-rpc".to_string(),
            schema_id: PROOF_POLICY_SCHEMA_ID.to_string(),
            agreement_hash: agreement_hash.to_string(),
            required_proofs: reqs,
            no_response_rules: vec![],
            attestors: vec![ApprovedAttestor {
                attestor_id: "rpc-attestor".to_string(),
                pubkey_hex: pubkey_hex.to_string(),
                display_name: None,
                domain: None,
            }],
            notes: None,
            expires_at_height: None,
            milestones: ms_decls,
            holdback: None,
        }
    }

    fn make_rpc_milestone_proof(
        agreement_hash: &str,
        milestone_id: &str,
        sk: &SigningKey,
    ) -> SettlementProof {
        let pubkey_hex = rpc_pubkey_hex(sk);
        let mut proof = SettlementProof {
            proof_id: format!("prf-ms-{}", milestone_id),
            schema_id: SETTLEMENT_PROOF_SCHEMA_ID.to_string(),
            proof_type: format!("proof_type_{}", milestone_id),
            agreement_hash: agreement_hash.to_string(),
            milestone_id: Some(milestone_id.to_string()),
            attested_by: "rpc-attestor".to_string(),
            attestation_time: 1_700_000_000,
            evidence_hash: None,
            evidence_summary: None,
            signature: ProofSignatureEnvelope {
                signature_type: AGREEMENT_SIGNATURE_TYPE_SECP256K1.to_string(),
                pubkey_hex: pubkey_hex.clone(),
                signature_hex: String::new(),
                payload_hash: String::new(),
            },
            expires_at_height: None,
            typed_payload: None,
        };
        let payload_bytes =
            irium_node_rs::settlement::settlement_proof_payload_bytes(&proof).unwrap();
        let digest = Sha256::digest(&payload_bytes);
        let mut digest_arr = [0u8; 32];
        digest_arr.copy_from_slice(&digest);
        let sig: k256::ecdsa::Signature = sk.sign_prehash(&digest_arr).unwrap();
        proof.signature = ProofSignatureEnvelope {
            signature_type: AGREEMENT_SIGNATURE_TYPE_SECP256K1.to_string(),
            pubkey_hex,
            signature_hex: hex::encode(sig.to_bytes()),
            payload_hash: hex::encode(digest),
        };
        proof
    }

    #[tokio::test]
    async fn evaluate_policy_rpc_milestone_all_satisfied() {
        // Two milestones; both proofs submitted -> overall Satisfied, completed=2.
        use irium_node_rs::settlement::agreement_canonical_bytes;
        let (state, sender, recipient, _) = create_test_state(Some(0));
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));
        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);
        let policy =
            make_rpc_policy_with_milestones(&agreement_hash, &pubkey_hex, &["ms-a", "ms-b"]);
        let _ = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy,
                replace: false,
            }),
        )
        .await
        .expect("store policy");
        let proof_a = make_rpc_milestone_proof(&agreement_hash, "ms-a", &sk);
        let proof_b = make_rpc_milestone_proof(&agreement_hash, "ms-b", &sk);
        let _ = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof: proof_a }),
        )
        .await
        .expect("submit proof a");
        let _ = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof: proof_b }),
        )
        .await
        .expect("submit proof b");
        let resp = evaluate_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(EvaluatePolicyRequest { agreement }),
        )
        .await
        .expect("evaluate")
        .0;
        assert_eq!(resp.outcome, PolicyOutcome::Satisfied);
        assert!(resp.release_eligible);
        assert_eq!(resp.total_milestone_count, 2);
        assert_eq!(resp.completed_milestone_count, 2);
    }

    #[tokio::test]
    async fn evaluate_policy_rpc_milestone_partial_unsatisfied() {
        // Two milestones; only ms-a proof submitted -> 1/2 satisfied -> Unsatisfied.
        use irium_node_rs::settlement::agreement_canonical_bytes;
        let (state, sender, recipient, _) = create_test_state(Some(0));
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));
        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);
        let policy =
            make_rpc_policy_with_milestones(&agreement_hash, &pubkey_hex, &["ms-a", "ms-b"]);
        let _ = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy,
                replace: false,
            }),
        )
        .await
        .expect("store policy");
        let proof_a = make_rpc_milestone_proof(&agreement_hash, "ms-a", &sk);
        let _ = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof: proof_a }),
        )
        .await
        .expect("submit proof a");
        let resp = evaluate_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(EvaluatePolicyRequest { agreement }),
        )
        .await
        .expect("evaluate")
        .0;
        assert_eq!(resp.outcome, PolicyOutcome::Unsatisfied);
        assert!(!resp.release_eligible);
        assert_eq!(resp.total_milestone_count, 2);
        assert_eq!(resp.completed_milestone_count, 1);
        assert_eq!(resp.milestone_results[0].milestone_id, "ms-a");
        assert_eq!(resp.milestone_results[0].outcome, PolicyOutcome::Satisfied);
        assert_eq!(resp.milestone_results[1].milestone_id, "ms-b");
        assert_eq!(
            resp.milestone_results[1].outcome,
            PolicyOutcome::Unsatisfied
        );
    }

    #[tokio::test]
    async fn evaluate_policy_rpc_milestone_timeout() {
        // ms-b has a no_response_rule; deadline elapsed -> overall Timeout.
        use irium_node_rs::settlement::agreement_canonical_bytes;
        let (state, sender, recipient, _) = create_test_state(Some(0));
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));
        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);
        let mut policy =
            make_rpc_policy_with_milestones(&agreement_hash, &pubkey_hex, &["ms-a", "ms-b"]);
        policy.no_response_rules.push(NoResponseRule {
            rule_id: "rule-ms-b-dl".to_string(),
            deadline_height: 50,
            trigger: NoResponseTrigger::FundedAndNoRelease,
            resolution: ProofResolution::Refund,
            milestone_id: Some("ms-b".to_string()),
            notes: None,
        });
        let _ = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy,
                replace: false,
            }),
        )
        .await
        .expect("store policy");
        // Advance chain past deadline (tip_height = chain.height - 1; need tip >= 50 -> height = 51)
        {
            let mut chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
            chain.height = 51;
        }
        let resp = evaluate_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(EvaluatePolicyRequest { agreement }),
        )
        .await
        .expect("evaluate")
        .0;
        assert_eq!(resp.outcome, PolicyOutcome::Timeout);
        assert!(resp.refund_eligible);
        assert_eq!(resp.total_milestone_count, 2);
        let ms_b = resp
            .milestone_results
            .iter()
            .find(|r| r.milestone_id == "ms-b")
            .unwrap();
        assert_eq!(ms_b.outcome, PolicyOutcome::Timeout);
    }

    #[tokio::test]
    async fn evaluate_policy_rpc_no_milestone_has_empty_milestone_results() {
        // Policy without milestones: milestone_results must be empty.
        use irium_node_rs::settlement::agreement_canonical_bytes;
        let (state, sender, recipient, _) = create_test_state(Some(0));
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));
        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);
        let policy = make_rpc_policy(&agreement_hash, &pubkey_hex);
        let _ = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy,
                replace: false,
            }),
        )
        .await
        .expect("store policy");
        let proof = make_rpc_proof(&agreement_hash, &sk);
        let _ = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof }),
        )
        .await
        .expect("submit proof");
        let resp = evaluate_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(EvaluatePolicyRequest { agreement }),
        )
        .await
        .expect("evaluate")
        .0;
        assert_eq!(resp.outcome, PolicyOutcome::Satisfied);
        assert!(resp.milestone_results.is_empty());
        assert_eq!(resp.total_milestone_count, 0);
        assert_eq!(resp.completed_milestone_count, 0);
    }

    #[tokio::test]
    async fn list_policies_rpc_empty_returns_count_zero() {
        let (state, _, _, _) = create_test_state(Some(0));
        let resp = list_policies_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(ListPoliciesRequest { active_only: false }),
        )
        .await
        .expect("list must succeed")
        .0;
        assert_eq!(resp.count, 0);
        assert!(resp.policies.is_empty());
    }

    #[tokio::test]
    async fn list_policies_rpc_returns_stored_policies() {
        use irium_node_rs::settlement::agreement_canonical_bytes;
        let (state, sender, recipient, _) = create_test_state(Some(0));
        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);

        // Store two policies with different agreement hashes
        let (agreement_a, _) = milestone_agreement_for_test(&sender, &recipient, 200);
        let bytes_a = agreement_canonical_bytes(&agreement_a).unwrap();
        let hash_a = hex::encode(Sha256::digest(&bytes_a));

        let (agreement_b, _) = milestone_agreement_for_test(&sender, &recipient, 300);
        let bytes_b = agreement_canonical_bytes(&agreement_b).unwrap();
        let hash_b = hex::encode(Sha256::digest(&bytes_b));

        let policy_a = make_rpc_policy(&hash_a, &pubkey_hex);
        let _ = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy: policy_a,
                replace: false,
            }),
        )
        .await
        .expect("store policy a");

        let policy_b = make_rpc_policy(&hash_b, &pubkey_hex);
        let _ = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy: policy_b,
                replace: false,
            }),
        )
        .await
        .expect("store policy b");

        let resp = list_policies_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(ListPoliciesRequest { active_only: false }),
        )
        .await
        .expect("list must succeed")
        .0;

        assert_eq!(resp.count, 2);
        assert_eq!(resp.policies.len(), 2);
        // Sorted by agreement_hash
        assert!(resp.policies[0].agreement_hash <= resp.policies[1].agreement_hash);
        for p in &resp.policies {
            assert_eq!(p.policy_id, "rpc-pol-001");
            assert_eq!(p.required_proofs, 1);
            assert_eq!(p.attestors, 1);
        }
    }

    #[tokio::test]
    async fn list_policies_rpc_summary_fields_match_stored_policy() {
        use irium_node_rs::settlement::agreement_canonical_bytes;
        let (state, sender, recipient, _) = create_test_state(Some(0));
        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));
        let policy = make_rpc_policy(&agreement_hash, &pubkey_hex);
        let _ = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy,
                replace: false,
            }),
        )
        .await
        .expect("store policy");

        let resp = list_policies_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(ListPoliciesRequest { active_only: false }),
        )
        .await
        .expect("list must succeed")
        .0;

        assert_eq!(resp.count, 1);
        let summary = &resp.policies[0];
        assert_eq!(summary.agreement_hash, agreement_hash);
        assert_eq!(summary.policy_id, "rpc-pol-001");
        assert_eq!(summary.required_proofs, 1);
        assert_eq!(summary.attestors, 1);
    }

    #[tokio::test]
    async fn evaluate_policy_rpc_refund_when_required_by_deadline_passed() {
        use irium_node_rs::settlement::agreement_canonical_bytes;
        let (state, sender, recipient, _) = create_test_state(Some(0));
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));

        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);

        // Build a policy with a refund requirement that expires at height 100
        let mut policy = make_rpc_policy(&agreement_hash, &pubkey_hex);
        policy.required_proofs = vec![irium_node_rs::settlement::ProofRequirement {
            requirement_id: "req-refund-100".to_string(),
            proof_type: "delivery_confirmation".to_string(),
            required_by: Some(100),
            required_attestor_ids: vec!["rpc-attestor".to_string()],
            resolution: irium_node_rs::settlement::ProofResolution::Refund,
            milestone_id: None,
            threshold: None,
        }];
        let _ = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy,
                replace: false,
            }),
        )
        .await
        .expect("store policy");

        // Advance chain past the deadline
        {
            let mut chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
            chain.height = 150;
        }

        // No proof submitted — refund deadline has passed
        let resp = evaluate_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(EvaluatePolicyRequest { agreement }),
        )
        .await
        .expect("evaluate must not error")
        .0;

        assert!(resp.policy_found);
        assert_eq!(resp.proof_count, 0);
        assert!(
            resp.refund_eligible,
            "refund must be triggered by required_by deadline"
        );
        assert!(!resp.release_eligible);
        assert!(
            resp.evaluated_rules
                .iter()
                .any(|r| r.contains("refund deadline") && r.contains("no satisfying proof")),
            "evaluated_rules must record the deadline miss; got: {:?}",
            resp.evaluated_rules
        );
    }

    #[tokio::test]
    async fn evaluate_policy_rpc_no_response_rule_suppressed_by_release() {
        use irium_node_rs::settlement::agreement_canonical_bytes;
        let (state, sender, recipient, _) = create_test_state(Some(0));
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));

        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);

        // Policy with release requirement + no-response refund rule at height 10
        let mut policy = make_rpc_policy(&agreement_hash, &pubkey_hex);
        policy
            .no_response_rules
            .push(irium_node_rs::settlement::NoResponseRule {
                rule_id: "rule-refund-10".to_string(),
                deadline_height: 10,
                trigger: irium_node_rs::settlement::NoResponseTrigger::FundedAndNoRelease,
                resolution: irium_node_rs::settlement::ProofResolution::Refund,
                milestone_id: None,
                notes: None,
            });
        let _ = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy,
                replace: false,
            }),
        )
        .await
        .expect("store policy");

        // Submit a valid proof with attestation_time before the refund deadline (10).
        // The late-proof guard in evaluate_policy filters proofs with
        // attestation_time > refund_deadline; we need attestation_time <= 10 here.
        let mut proof = make_rpc_proof(&agreement_hash, &sk);
        proof.attestation_time = 5;
        proof.signature = sign_rpc_proof(&proof, &sk);
        let _ = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof }),
        )
        .await
        .expect("submit proof");

        // Advance chain past the no-response rule deadline
        {
            let mut chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
            chain.height = 100;
        }

        let resp = evaluate_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(EvaluatePolicyRequest { agreement }),
        )
        .await
        .expect("evaluate must not error")
        .0;

        assert!(resp.policy_found);
        assert_eq!(resp.proof_count, 1);
        assert!(
            resp.release_eligible,
            "release must be granted; no-response rule must be suppressed"
        );
        assert!(!resp.refund_eligible);
    }

    #[tokio::test]
    async fn store_policy_rpc_rejects_overwrite_without_replace() {
        let (state, _, _, _) = create_test_state(Some(0));
        let policy_a = make_rpc_policy("overwrite-hash-01", "pk-a");
        let _ = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy: policy_a,
                replace: false,
            }),
        )
        .await
        .expect("first store");

        // Different policy_id, same agreement_hash, replace=false => rejected
        let mut policy_b = make_rpc_policy("overwrite-hash-01", "pk-a");
        policy_b.policy_id = "pol-rpc-002".to_string();
        let resp = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy: policy_b,
                replace: false,
            }),
        )
        .await
        .expect("must not error")
        .0;
        assert!(!resp.accepted, "must reject overwrite without replace flag");
        assert!(!resp.updated);
        assert!(
            resp.message.contains("already exists") && resp.message.contains("--replace"),
            "message must explain --replace; got: {}",
            resp.message
        );
    }

    #[tokio::test]
    async fn store_policy_rpc_replaces_with_flag() {
        let (state, _, _, _) = create_test_state(Some(0));
        let policy_a = make_rpc_policy("overwrite-hash-02", "pk-b");
        let _ = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy: policy_a,
                replace: false,
            }),
        )
        .await
        .expect("first store");

        // Different policy_id, replace=true => accepted + updated
        let mut policy_b = make_rpc_policy("overwrite-hash-02", "pk-b");
        policy_b.policy_id = "pol-rpc-003".to_string();
        let resp = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy: policy_b,
                replace: true,
            }),
        )
        .await
        .expect("must not error")
        .0;
        assert!(resp.accepted, "must accept with replace=true");
        assert!(resp.updated, "must be marked updated");
        assert!(
            resp.message.contains("replaced"),
            "message must say replaced; got: {}",
            resp.message
        );
    }

    #[tokio::test]
    async fn evaluate_policy_rpc_before_expiry_is_active() {
        use irium_node_rs::settlement::agreement_canonical_bytes;
        let (state, sender, recipient, _) = create_test_state(Some(0));
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));
        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);
        let mut policy = make_rpc_policy(&agreement_hash, &pubkey_hex);
        policy.expires_at_height = Some(1); // tip=0 < 1 -> not expired
        let _ = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy,
                replace: false,
            }),
        )
        .await
        .expect("store must succeed");
        let resp = evaluate_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(EvaluatePolicyRequest { agreement }),
        )
        .await
        .expect("must succeed")
        .0;
        assert!(resp.policy_found);
        assert!(!resp.expired, "must not be expired when tip < expiry");
        assert!(!resp.reason.contains("expired"), "reason: {}", resp.reason);
    }

    #[tokio::test]
    async fn evaluate_policy_rpc_at_expiry_height_returns_expired() {
        use irium_node_rs::settlement::agreement_canonical_bytes;
        let (state, sender, recipient, _) = create_test_state(Some(5));
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));
        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);
        let mut policy = make_rpc_policy(&agreement_hash, &pubkey_hex);
        policy.expires_at_height = Some(0); // tip=0 >= 0 -> expired
        let _ = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy,
                replace: false,
            }),
        )
        .await
        .expect("store must succeed");
        let resp = evaluate_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(EvaluatePolicyRequest { agreement }),
        )
        .await
        .expect("must succeed")
        .0;
        assert!(resp.policy_found);
        assert!(resp.expired, "must be expired at expiry height");
        assert!(!resp.release_eligible);
        assert!(!resp.refund_eligible);
        assert!(
            resp.reason.contains("expired") && resp.reason.contains("0"),
            "reason must name expiry height; got: {}",
            resp.reason
        );
    }

    #[tokio::test]
    async fn evaluate_policy_rpc_past_expiry_returns_expired() {
        use irium_node_rs::settlement::agreement_canonical_bytes;
        let (state, sender, recipient, _) = create_test_state(Some(10));
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));
        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);
        let mut policy = make_rpc_policy(&agreement_hash, &pubkey_hex);
        policy.expires_at_height = Some(0); // tip=0 >= 0 -> expired
        let _ = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy,
                replace: false,
            }),
        )
        .await
        .expect("store must succeed");
        let resp = evaluate_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(EvaluatePolicyRequest { agreement }),
        )
        .await
        .expect("must succeed")
        .0;
        assert!(resp.expired);
        assert!(!resp.release_eligible);
        assert!(!resp.refund_eligible);
    }

    #[tokio::test]
    async fn get_policy_rpc_shows_expiry_fields() {
        let (state, _, _, _) = create_test_state(Some(0));
        let mut policy = make_rpc_policy("exp-get-hash-01", "pk-get-exp");
        policy.expires_at_height = Some(50);
        let _ = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy,
                replace: false,
            }),
        )
        .await
        .expect("store must succeed");
        let resp = get_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(GetPolicyRequest {
                agreement_hash: "exp-get-hash-01".to_string(),
            }),
        )
        .await
        .expect("get must succeed")
        .0;
        assert!(resp.found);
        assert_eq!(resp.expires_at_height, Some(50));
        assert!(!resp.expired, "tip=0, expires=50: must not be expired");
    }

    #[tokio::test]
    async fn get_policy_rpc_marks_expired_when_past_height() {
        let (state, _, _, _) = create_test_state(Some(100));
        let mut policy = make_rpc_policy("exp-get-hash-02", "pk-get-exp2");
        policy.expires_at_height = Some(0); // tip=0 >= 0 -> expired
        let _ = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy,
                replace: false,
            }),
        )
        .await
        .expect("store must succeed");
        let resp = get_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(GetPolicyRequest {
                agreement_hash: "exp-get-hash-02".to_string(),
            }),
        )
        .await
        .expect("get must succeed")
        .0;
        assert!(resp.found);
        assert_eq!(resp.expires_at_height, Some(0));
        assert!(resp.expired, "tip=0, expires=0: must be expired");
    }

    #[tokio::test]
    async fn list_policies_rpc_shows_expiry_and_expired_flag() {
        let (state, _, _, _) = create_test_state(Some(20));
        let mut active = make_rpc_policy("list-exp-active", "pk-la");
        active.expires_at_height = Some(1); // tip=0 < 1 -> not expired
        let mut expired_p = make_rpc_policy("list-exp-past", "pk-le");
        expired_p.expires_at_height = Some(0); // tip=0 >= 0 -> expired
        let no_expiry = make_rpc_policy("list-exp-none", "pk-ln");
        for p in [active, expired_p, no_expiry] {
            let _ = store_policy_rpc(
                ConnectInfo(test_socket()),
                State(state.clone()),
                HeaderMap::new(),
                Json(StorePolicyRequest {
                    policy: p,
                    replace: false,
                }),
            )
            .await
            .expect("store must succeed");
        }
        let resp = list_policies_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(ListPoliciesRequest { active_only: false }),
        )
        .await
        .expect("list must succeed")
        .0;
        assert_eq!(resp.count, 3);
        for p in &resp.policies {
            match p.agreement_hash.as_str() {
                "list-exp-active" => {
                    assert_eq!(p.expires_at_height, Some(1));
                    assert!(!p.expired, "tip=0, expires=1: not expired");
                }
                "list-exp-past" => {
                    assert_eq!(p.expires_at_height, Some(0));
                    assert!(p.expired, "tip=0, expires=0: expired");
                }
                "list-exp-none" => {
                    assert_eq!(p.expires_at_height, None);
                    assert!(!p.expired, "no expiry: never expired");
                }
                other => panic!("unexpected hash: {other}"),
            }
        }
    }

    #[tokio::test]
    async fn check_policy_rpc_ignores_expiry_on_manual_check() {
        use irium_node_rs::settlement::agreement_canonical_bytes;
        // check_policy (manual) does not enforce expiry; the user supplies the policy explicitly
        let (state, sender, recipient, _) = create_test_state(Some(999));
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));
        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);
        let mut policy = make_rpc_policy(&agreement_hash, &pubkey_hex);
        policy.expires_at_height = Some(1); // expired at height 999
        let resp = check_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(CheckPolicyRequest {
                agreement,
                policy,
                proofs: Vec::new(),
            }),
        )
        .await
        .expect("check must succeed")
        .0;
        assert!(
            !resp.reason.contains("expired"),
            "check_policy must not enforce expiry; reason: {}",
            resp.reason
        );
    }
    #[tokio::test]
    async fn check_policy_no_holdback_field_absent() {
        use irium_node_rs::settlement::agreement_canonical_bytes;
        let (state, sender, recipient, _) = create_test_state(Some(0));
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));
        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);
        let policy = make_rpc_policy(&agreement_hash, &pubkey_hex);
        let proof = make_rpc_proof(&agreement_hash, &sk);
        let req = CheckPolicyRequest {
            agreement,
            policy,
            proofs: vec![proof],
        };
        let resp = check_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(req),
        )
        .await
        .expect("must succeed")
        .0;
        assert!(
            resp.holdback.is_none(),
            "no holdback on policy => holdback field absent"
        );
        assert!(resp.milestone_results.is_empty());
    }

    #[tokio::test]
    async fn check_policy_holdback_held_when_future_deadline() {
        use irium_node_rs::settlement::agreement_canonical_bytes;
        let (state, sender, recipient, _) = create_test_state(Some(0));
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));
        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);
        let mut policy = make_rpc_policy(&agreement_hash, &pubkey_hex);
        // Holdback: 10% held until height 999999 (far future at tip=0)
        policy.holdback = Some(PolicyHoldback {
            holdback_bps: 1000,
            release_requirement_id: None,
            deadline_height: Some(999999),
        });
        let proof = make_rpc_proof(&agreement_hash, &sk);
        let req = CheckPolicyRequest {
            agreement,
            policy,
            proofs: vec![proof],
        };
        let resp = check_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(req),
        )
        .await
        .expect("must succeed")
        .0;
        assert!(resp.release_eligible, "base must be satisfied");
        let hb = resp.holdback.expect("holdback field must be present");
        assert_eq!(hb.holdback_outcome, HoldbackOutcome::Held);
        assert_eq!(hb.holdback_bps, 1000);
        assert_eq!(hb.immediate_release_bps, 9000);
        assert!(!hb.holdback_released);
        assert!(hb.holdback_present);
    }

    #[tokio::test]
    async fn check_policy_holdback_released_when_deadline_passed() {
        use irium_node_rs::settlement::agreement_canonical_bytes;
        // tip_height=0 >= deadline_height=0 => released
        let (state, sender, recipient, _) = create_test_state(Some(0));
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));
        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);
        let mut policy = make_rpc_policy(&agreement_hash, &pubkey_hex);
        policy.holdback = Some(PolicyHoldback {
            holdback_bps: 500,
            release_requirement_id: None,
            deadline_height: Some(0), // deadline at height 0, tip=0 => passed
        });
        let proof = make_rpc_proof(&agreement_hash, &sk);
        let req = CheckPolicyRequest {
            agreement,
            policy,
            proofs: vec![proof],
        };
        let resp = check_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(req),
        )
        .await
        .expect("must succeed")
        .0;
        assert!(resp.release_eligible);
        let hb = resp.holdback.expect("holdback field must be present");
        assert_eq!(hb.holdback_outcome, HoldbackOutcome::Released);
        assert_eq!(hb.holdback_bps, 500);
        assert_eq!(hb.immediate_release_bps, 10000);
        assert!(hb.holdback_released);
    }

    #[tokio::test]
    async fn list_policies_rpc_active_only_excludes_expired() {
        let (state, _, _, _) = create_test_state(Some(0));
        // active: tip=0 < 1, not expired
        let mut active = make_rpc_policy("ao-active", "pk-ao-a");
        active.expires_at_height = Some(1);
        // expired: tip=0 >= 0, expired
        let mut expired_p = make_rpc_policy("ao-expired", "pk-ao-e");
        expired_p.expires_at_height = Some(0);
        // no expiry: always active
        let no_exp = make_rpc_policy("ao-none", "pk-ao-n");
        for p in [active, expired_p, no_exp] {
            let _ = store_policy_rpc(
                ConnectInfo(test_socket()),
                State(state.clone()),
                HeaderMap::new(),
                Json(StorePolicyRequest {
                    policy: p,
                    replace: false,
                }),
            )
            .await
            .expect("store must succeed");
        }
        let resp = list_policies_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(ListPoliciesRequest { active_only: true }),
        )
        .await
        .expect("list must succeed")
        .0;
        // 2 active (ao-active with expiry=1, ao-none with no expiry); ao-expired excluded
        assert_eq!(
            resp.count, 2,
            "active_only must exclude expired; got count={}",
            resp.count
        );
        assert!(
            resp.active_only,
            "active_only must be reflected in response"
        );
        let hashes: Vec<_> = resp
            .policies
            .iter()
            .map(|p| p.agreement_hash.as_str())
            .collect();
        assert!(hashes.contains(&"ao-active"), "ao-active must be present");
        assert!(hashes.contains(&"ao-none"), "ao-none must be present");
        assert!(
            !hashes.contains(&"ao-expired"),
            "ao-expired must be excluded"
        );
        for p in &resp.policies {
            assert!(
                !p.expired,
                "active_only result must not contain expired policies"
            );
        }
    }

    #[tokio::test]
    async fn list_policies_rpc_default_includes_all() {
        let (state, _, _, _) = create_test_state(Some(0));
        let mut active = make_rpc_policy("def-active", "pk-def-a");
        active.expires_at_height = Some(1);
        let mut expired_p = make_rpc_policy("def-expired", "pk-def-e");
        expired_p.expires_at_height = Some(0);
        for p in [active, expired_p] {
            let _ = store_policy_rpc(
                ConnectInfo(test_socket()),
                State(state.clone()),
                HeaderMap::new(),
                Json(StorePolicyRequest {
                    policy: p,
                    replace: false,
                }),
            )
            .await
            .expect("store must succeed");
        }
        let resp = list_policies_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(ListPoliciesRequest { active_only: false }),
        )
        .await
        .expect("list must succeed")
        .0;
        assert_eq!(
            resp.count, 2,
            "default must include all policies; got count={}",
            resp.count
        );
        assert!(!resp.active_only, "active_only must be false in response");
    }

    #[tokio::test]
    async fn list_policies_rpc_active_only_empty_when_all_expired() {
        let (state, _, _, _) = create_test_state(Some(0));
        let mut p1 = make_rpc_policy("allexp-1", "pk-ae-1");
        p1.expires_at_height = Some(0);
        let mut p2 = make_rpc_policy("allexp-2", "pk-ae-2");
        p2.expires_at_height = Some(0);
        for p in [p1, p2] {
            let _ = store_policy_rpc(
                ConnectInfo(test_socket()),
                State(state.clone()),
                HeaderMap::new(),
                Json(StorePolicyRequest {
                    policy: p,
                    replace: false,
                }),
            )
            .await
            .expect("store must succeed");
        }
        let resp = list_policies_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(ListPoliciesRequest { active_only: true }),
        )
        .await
        .expect("list must succeed")
        .0;
        assert_eq!(resp.count, 0, "active_only must be empty when all expired");
        assert!(resp.active_only);
    }

    #[tokio::test]
    async fn list_policies_rpc_active_only_keeps_no_expiry_policies() {
        let (state, _, _, _) = create_test_state(Some(0));
        let no_exp1 = make_rpc_policy("noexp-1", "pk-ne-1");
        let no_exp2 = make_rpc_policy("noexp-2", "pk-ne-2");
        for p in [no_exp1, no_exp2] {
            let _ = store_policy_rpc(
                ConnectInfo(test_socket()),
                State(state.clone()),
                HeaderMap::new(),
                Json(StorePolicyRequest {
                    policy: p,
                    replace: false,
                }),
            )
            .await
            .expect("store must succeed");
        }
        let resp = list_policies_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(ListPoliciesRequest { active_only: true }),
        )
        .await
        .expect("list must succeed")
        .0;
        assert_eq!(resp.count, 2, "active_only must keep no-expiry policies");
    }

    #[tokio::test]
    async fn list_proofs_rpc_all_returns_every_proof() {
        let (state, _, _, _) = create_test_state(Some(0));
        let sk = SigningKey::from_bytes((&[19u8; 32]).into()).unwrap();
        // Submit one proof; make_signed_proof_for_rpc hardcodes proof_id so only one unique proof.
        let proof_a = make_signed_proof_for_rpc("hash-aaa", &sk);
        let _ = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof: proof_a }),
        )
        .await
        .expect("submit");
        // List all without filter: must return the proof with agreement_hash="*"
        let resp = list_proofs_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(ListProofsRequest {
                agreement_hash: None,
                active_only: false,
                ..Default::default()
            }),
        )
        .await
        .expect("list all must succeed")
        .0;
        assert_eq!(
            resp.returned_count, 1,
            "must return the stored proof; got count={}",
            resp.returned_count
        );
        assert_eq!(
            resp.agreement_hash, "*",
            "agreement_hash must be * for global list"
        );
        assert_eq!(
            resp.proofs[0].proof.agreement_hash, "hash-aaa",
            "proof must carry its own agreement_hash"
        );
    }

    #[tokio::test]
    async fn list_proofs_rpc_filter_still_works_with_some() {
        let (state, _, _, _) = create_test_state(Some(0));
        let sk = SigningKey::from_bytes((&[21u8; 32]).into()).unwrap();
        // Submit one proof for hash-filter-a.
        let proof_a = make_signed_proof_for_rpc("hash-filter-a", &sk);
        let _ = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof: proof_a }),
        )
        .await
        .expect("submit");
        // Filter by hash-filter-a: must return 1 proof.
        let resp_a = list_proofs_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(ListProofsRequest {
                agreement_hash: Some("hash-filter-a".to_string()),
                active_only: false,
                ..Default::default()
            }),
        )
        .await
        .expect("filtered list must succeed")
        .0;
        assert_eq!(
            resp_a.returned_count, 1,
            "filter must return only matching proof"
        );
        assert_eq!(resp_a.agreement_hash, "hash-filter-a");
        assert_eq!(resp_a.proofs[0].proof.agreement_hash, "hash-filter-a");
        // Filter by hash-filter-b: no proofs stored under that hash.
        let resp_b = list_proofs_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(ListProofsRequest {
                agreement_hash: Some("hash-filter-b".to_string()),
                active_only: false,
                ..Default::default()
            }),
        )
        .await
        .expect("filter-b list must succeed")
        .0;
        assert_eq!(resp_b.returned_count, 0, "filter-b must return no proofs");
        assert_eq!(resp_b.agreement_hash, "hash-filter-b");
    }

    #[tokio::test]
    async fn list_proofs_rpc_all_empty_store_returns_zero() {
        let (state, _, _, _) = create_test_state(Some(0));
        let resp = list_proofs_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(ListProofsRequest {
                agreement_hash: None,
                active_only: false,
                ..Default::default()
            }),
        )
        .await
        .expect("empty all list must succeed")
        .0;
        assert_eq!(resp.returned_count, 0);
        assert_eq!(resp.agreement_hash, "*");
        assert_eq!(resp.tip_height, 0, "test node starts at height 0");
    }

    #[tokio::test]
    async fn list_proofs_rpc_includes_tip_height() {
        // Test state always starts at height 0; verify tip_height is present in the response.
        let (state, _, _, _) = create_test_state(Some(0));
        let sk = SigningKey::from_bytes((&[23u8; 32]).into()).unwrap();
        let proof = make_signed_proof_for_rpc("th-test", &sk);
        let _ = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof }),
        )
        .await
        .expect("submit");
        let resp = list_proofs_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(ListProofsRequest {
                agreement_hash: None,
                active_only: false,
                ..Default::default()
            }),
        )
        .await
        .expect("list")
        .0;
        // Test chain starts at genesis (height 0); tip_height field must be present.
        assert_eq!(
            resp.tip_height, 0,
            "tip_height must reflect chain genesis height"
        );
        assert_eq!(resp.returned_count, 1);
    }

    #[tokio::test]
    async fn list_proofs_rpc_proof_carries_expiry_field() {
        let (state, _, _, _) = create_test_state(Some(0));
        let sk = SigningKey::from_bytes((&[24u8; 32]).into()).unwrap();
        // Build a proof with expires_at_height set.
        let mut proof = make_signed_proof_for_rpc("exp-carry-hash", &sk);
        proof.expires_at_height = Some(500);
        let _ = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof }),
        )
        .await
        .expect("submit");
        let resp = list_proofs_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(ListProofsRequest {
                agreement_hash: None,
                active_only: false,
                ..Default::default()
            }),
        )
        .await
        .expect("list")
        .0;
        assert_eq!(
            resp.proofs[0].proof.expires_at_height,
            Some(500),
            "expires_at_height must be returned in listing"
        );
    }

    #[tokio::test]
    async fn evaluate_policy_rpc_skips_expired_proof() {
        // Test chain starts at genesis (height 0). Use expires_at_height=0 so that
        // tip_height(0) >= 0 is true: proof is immediately expired.
        let (state, sender, recipient, _) = create_test_state(Some(0));
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
        use irium_node_rs::settlement::agreement_canonical_bytes;
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));
        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);
        let policy = make_rpc_policy(&agreement_hash, &pubkey_hex);
        let _ = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy,
                replace: false,
            }),
        )
        .await
        .expect("store policy");
        // expires_at_height=0, tip=0 => 0 >= 0 => expired immediately.
        let mut proof = make_rpc_proof(&agreement_hash, &sk);
        proof.expires_at_height = Some(0);
        let _ = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof }),
        )
        .await
        .expect("submit expired proof");
        // evaluate_policy_rpc must find 0 active proofs (the one stored is expired).
        let resp = evaluate_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(EvaluatePolicyRequest { agreement }),
        )
        .await
        .expect("evaluate")
        .0;
        assert!(resp.policy_found);
        assert!(!resp.expired, "policy itself is not expired");
        assert_eq!(
            resp.proof_count, 0,
            "expired proof must not count as active"
        );
        assert!(
            !resp.release_eligible,
            "must not be release eligible without active proof"
        );
        let skipped = resp
            .evaluated_rules
            .iter()
            .any(|r| r.contains("skipped: expired"));
        assert!(
            skipped,
            "evaluated_rules must note the skipped proof; got: {:?}",
            resp.evaluated_rules
        );
    }

    #[tokio::test]
    async fn evaluate_policy_rpc_uses_active_proof_before_expiry() {
        // Test chain starts at genesis (height 0). Use expires_at_height=1 so that
        // tip_height(0) < 1 is true: proof is not yet expired.
        let (state, sender, recipient, _) = create_test_state(Some(0));
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
        use irium_node_rs::settlement::agreement_canonical_bytes;
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));
        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);
        let policy = make_rpc_policy(&agreement_hash, &pubkey_hex);
        let _ = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy,
                replace: false,
            }),
        )
        .await
        .expect("store policy");
        // expires_at_height=1, tip=0 => 0 < 1 => not expired, proof is active.
        let mut proof = make_rpc_proof(&agreement_hash, &sk);
        proof.expires_at_height = Some(1);
        let _ = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof }),
        )
        .await
        .expect("submit active proof");
        let resp = evaluate_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(EvaluatePolicyRequest { agreement }),
        )
        .await
        .expect("evaluate")
        .0;
        assert!(resp.policy_found);
        assert!(!resp.expired);
        assert_eq!(
            resp.proof_count, 1,
            "non-expired proof must be counted as active"
        );
        assert!(
            resp.release_eligible,
            "must be release eligible with active proof"
        );
    }

    #[tokio::test]
    async fn list_proofs_rpc_active_only_excludes_expired() {
        // tip=0; one expired proof submitted; active_only=true must return count=0.
        let (state, _, _, _) = create_test_state(Some(0));
        let sk = SigningKey::from_bytes((&[24u8; 32]).into()).unwrap();
        let mut expired_proof = make_signed_proof_for_rpc("ao-expired", &sk);
        expired_proof.expires_at_height = Some(0);
        let _ = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest {
                proof: expired_proof,
            }),
        )
        .await
        .expect("submit expired");
        let resp = list_proofs_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(ListProofsRequest {
                agreement_hash: None,
                active_only: true,
                ..Default::default()
            }),
        )
        .await
        .expect("list active_only")
        .0;
        assert!(resp.active_only, "active_only must be echoed true");
        assert_eq!(
            resp.returned_count, 0,
            "expired proof must be excluded when active_only=true"
        );
    }

    #[tokio::test]
    async fn list_proofs_rpc_active_only_keeps_non_expiring_proofs() {
        // tip=0; proof with expires_at_height=None must be included by active_only=true.
        let (state, _, _, _) = create_test_state(Some(0));
        let sk = SigningKey::from_bytes((&[26u8; 32]).into()).unwrap();
        let proof = make_signed_proof_for_rpc("ao-no-expiry", &sk);
        let _ = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof }),
        )
        .await
        .expect("submit no-expiry proof");
        let resp = list_proofs_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(ListProofsRequest {
                agreement_hash: None,
                active_only: true,
                ..Default::default()
            }),
        )
        .await
        .expect("list active_only")
        .0;
        assert!(resp.active_only);
        assert_eq!(
            resp.returned_count, 1,
            "non-expiring proof must be included when active_only=true"
        );
    }

    #[tokio::test]
    async fn list_proofs_rpc_active_only_false_includes_expired() {
        // Default: active_only=false includes expired proofs unchanged.
        let (state, _, _, _) = create_test_state(Some(0));
        let sk = SigningKey::from_bytes((&[27u8; 32]).into()).unwrap();
        let mut proof = make_signed_proof_for_rpc("ao-default", &sk);
        proof.expires_at_height = Some(0);
        let _ = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof }),
        )
        .await
        .expect("submit expired proof");
        let resp = list_proofs_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(ListProofsRequest {
                agreement_hash: None,
                active_only: false,
                ..Default::default()
            }),
        )
        .await
        .expect("list default")
        .0;
        assert!(!resp.active_only);
        assert_eq!(
            resp.returned_count, 1,
            "expired proof must still be included when active_only=false"
        );
    }

    #[tokio::test]
    async fn submit_proof_rpc_non_expiring_response() {
        // Proof with no expires_at_height: response must show expires_at_height=None, expired=false.
        let (state, _, _, _) = create_test_state(Some(0));
        let sk = SigningKey::from_bytes((&[28u8; 32]).into()).unwrap();
        let proof = make_signed_proof_for_rpc("ne-resp-test", &sk);
        let resp = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof }),
        )
        .await
        .expect("submit")
        .0;
        assert!(resp.accepted);
        assert_eq!(resp.tip_height, 0);
        assert!(resp.expires_at_height.is_none(), "no expiry must be None");
        assert!(!resp.expired, "non-expiring proof must not be expired");
        assert_eq!(
            resp.status, "active",
            "non-expiring proof must have status=active"
        );
    }

    #[tokio::test]
    async fn submit_proof_rpc_future_expiry_response() {
        // Proof with expires_at_height=1 at tip=0: 0 < 1, not expired.
        let (state, _, _, _) = create_test_state(Some(0));
        let sk = SigningKey::from_bytes((&[29u8; 32]).into()).unwrap();
        let mut proof = make_signed_proof_for_rpc("fe-resp-test", &sk);
        proof.expires_at_height = Some(1);
        let resp = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof }),
        )
        .await
        .expect("submit")
        .0;
        assert!(resp.accepted);
        assert_eq!(resp.tip_height, 0);
        assert_eq!(resp.expires_at_height, Some(1));
        assert!(
            !resp.expired,
            "expires_at_height=1 at tip=0 must not be expired"
        );
        assert_eq!(
            resp.status, "active",
            "expires_at_height=1 at tip=0 must have status=active"
        );
    }

    #[tokio::test]
    async fn submit_proof_rpc_already_expired_response() {
        // Proof with expires_at_height=0 at tip=0: 0 >= 0, expired immediately.
        // Submission still succeeds (expiry is not an acceptance criterion).
        let (state, _, _, _) = create_test_state(Some(0));
        let sk = SigningKey::from_bytes((&[30u8; 32]).into()).unwrap();
        let mut proof = make_signed_proof_for_rpc("ae-resp-test", &sk);
        proof.expires_at_height = Some(0);
        let resp = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof }),
        )
        .await
        .expect("submit expired proof")
        .0;
        assert!(
            resp.accepted,
            "expired proof must still be accepted for storage"
        );
        assert_eq!(resp.tip_height, 0);
        assert_eq!(resp.expires_at_height, Some(0));
        assert!(
            resp.expired,
            "tip=0 >= expires_at_height=0 must be reported as expired"
        );
        assert_eq!(
            resp.status, "expired",
            "tip=0 >= expires_at_height=0 must have status=expired"
        );
    }

    #[tokio::test]
    async fn submit_proof_rpc_duplicate_carries_lifecycle_fields() {
        // Duplicate response must also carry tip_height, expires_at_height, expired.
        let (state, _, _, _) = create_test_state(Some(0));
        let sk = SigningKey::from_bytes((&[31u8; 32]).into()).unwrap();
        let mut proof = make_signed_proof_for_rpc("dup-lc-test", &sk);
        proof.expires_at_height = Some(0);
        let _ = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest {
                proof: proof.clone(),
            }),
        )
        .await
        .expect("first submit");
        let dup = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof }),
        )
        .await
        .expect("duplicate submit")
        .0;
        assert!(!dup.accepted);
        assert!(dup.duplicate);
        assert_eq!(dup.tip_height, 0);
        assert_eq!(dup.expires_at_height, Some(0));
        assert!(
            dup.expired,
            "lifecycle fields must be present even on duplicate response"
        );
        assert_eq!(
            dup.status, "expired",
            "status must be present on duplicate response"
        );
    }

    #[tokio::test]
    async fn list_proofs_rpc_status_non_expiring_is_active() {
        let (state, _, _, _) = create_test_state(Some(0));
        let sk = SigningKey::from_bytes((&[32u8; 32]).into()).unwrap();
        let proof = make_signed_proof_for_rpc("st-ne", &sk);
        let _ = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof }),
        )
        .await
        .expect("submit");
        let resp = list_proofs_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(ListProofsRequest {
                agreement_hash: None,
                active_only: false,
                ..Default::default()
            }),
        )
        .await
        .expect("list")
        .0;
        assert_eq!(
            resp.proofs[0].status, "active",
            "non-expiring proof must have status=active"
        );
    }

    #[tokio::test]
    async fn list_proofs_rpc_status_future_expiry_is_active() {
        let (state, _, _, _) = create_test_state(Some(0));
        let sk = SigningKey::from_bytes((&[33u8; 32]).into()).unwrap();
        let mut proof = make_signed_proof_for_rpc("st-fe", &sk);
        proof.expires_at_height = Some(1000);
        let _ = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof }),
        )
        .await
        .expect("submit");
        let resp = list_proofs_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(ListProofsRequest {
                agreement_hash: None,
                active_only: false,
                ..Default::default()
            }),
        )
        .await
        .expect("list")
        .0;
        assert_eq!(
            resp.proofs[0].status, "active",
            "expires_at_height=1000 at tip=0 must be active"
        );
    }

    #[tokio::test]
    async fn list_proofs_rpc_status_already_expired_is_expired() {
        let (state, _, _, _) = create_test_state(Some(0));
        let sk = SigningKey::from_bytes((&[34u8; 32]).into()).unwrap();
        let mut proof = make_signed_proof_for_rpc("st-ae", &sk);
        proof.expires_at_height = Some(0);
        let _ = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof }),
        )
        .await
        .expect("submit");
        let resp = list_proofs_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(ListProofsRequest {
                agreement_hash: None,
                active_only: false,
                ..Default::default()
            }),
        )
        .await
        .expect("list")
        .0;
        assert_eq!(
            resp.proofs[0].status, "expired",
            "expires_at_height=0 at tip=0 must be expired"
        );
    }

    #[test]
    fn proof_lifecycle_status_boundary_equal_is_expired() {
        assert_eq!(proof_lifecycle_status(Some(5), 5), "expired");
    }

    #[test]
    fn proof_lifecycle_status_boundary_one_before_is_active() {
        assert_eq!(proof_lifecycle_status(Some(5), 4), "active");
    }

    #[tokio::test]
    async fn submit_status_matches_list_status_active() {
        // Submit a non-expiring proof; list it back; submit.status must equal list entry status.
        let (state, _, _, _) = create_test_state(Some(0));
        let sk = SigningKey::from_bytes((&[35u8; 32]).into()).unwrap();
        let proof = make_signed_proof_for_rpc("sl-ne", &sk);
        let sub = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof }),
        )
        .await
        .expect("submit")
        .0;
        let list = list_proofs_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(ListProofsRequest {
                agreement_hash: None,
                active_only: false,
                ..Default::default()
            }),
        )
        .await
        .expect("list")
        .0;
        assert_eq!(sub.status, "active");
        assert_eq!(
            list.proofs[0].status, sub.status,
            "submit status must match list status for same proof"
        );
    }

    #[tokio::test]
    async fn submit_status_matches_list_status_expired() {
        // Submit a proof already expired at tip=0; list it; statuses must agree.
        let (state, _, _, _) = create_test_state(Some(0));
        let sk = SigningKey::from_bytes((&[36u8; 32]).into()).unwrap();
        let mut proof = make_signed_proof_for_rpc("sl-ae", &sk);
        proof.expires_at_height = Some(0);
        let sub = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof }),
        )
        .await
        .expect("submit")
        .0;
        let list = list_proofs_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(ListProofsRequest {
                agreement_hash: None,
                active_only: false,
                ..Default::default()
            }),
        )
        .await
        .expect("list")
        .0;
        assert_eq!(sub.status, "expired");
        assert_eq!(
            list.proofs[0].status, sub.status,
            "submit status must match list status for expired proof"
        );
    }

    #[tokio::test]
    async fn submit_status_consistent_with_expired_bool() {
        // Invariant: (status=="expired") == expired for all submit responses.
        let (state, _, _, _) = create_test_state(Some(0));
        let sk = SigningKey::from_bytes((&[37u8; 32]).into()).unwrap();
        // Case A: no expiry -> expired=false, status=active.
        let proof_a = make_signed_proof_for_rpc("sl-inv-a", &sk);
        let resp_a = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof: proof_a }),
        )
        .await
        .expect("submit a")
        .0;
        assert_eq!(
            resp_a.expired,
            resp_a.status == "expired",
            "expired bool must agree with status field (case a)"
        );
        // Case B: expires_at_height=0 at tip=0 -> expired=true, status=expired.
        let sk2 = SigningKey::from_bytes((&[38u8; 32]).into()).unwrap();
        let mut proof_b = make_signed_proof_for_rpc("sl-inv-b", &sk2);
        proof_b.expires_at_height = Some(0);
        let resp_b = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof: proof_b }),
        )
        .await
        .expect("submit b")
        .0;
        assert_eq!(
            resp_b.expired,
            resp_b.status == "expired",
            "expired bool must agree with status field (case b)"
        );
    }

    #[tokio::test]
    async fn get_proof_rpc_found_active() {
        // Submit a non-expiring proof; get it by proof_id; must be found with status=active.
        let (state, _, _, _) = create_test_state(Some(0));
        let sk = SigningKey::from_bytes((&[40u8; 32]).into()).unwrap();
        let proof = make_signed_proof_for_rpc("gp-active", &sk);
        let submitted = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof }),
        )
        .await
        .expect("submit")
        .0;
        let resp = get_proof_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(GetProofRequest {
                proof_id: submitted.proof_id.clone(),
            }),
        )
        .await
        .expect("get")
        .0;
        assert!(resp.found, "proof must be found");
        assert_eq!(resp.proof_id, submitted.proof_id);
        assert!(resp.proof.is_some(), "proof field must be populated");
        assert_eq!(
            resp.status, "active",
            "non-expiring proof must have status=active"
        );
        assert!(!resp.expired, "non-expiring proof must not be expired");
        assert_eq!(resp.tip_height, 0);
    }

    #[tokio::test]
    async fn get_proof_rpc_found_expired() {
        // Submit a proof already expired at tip=0; get it; must be found with status=expired.
        let (state, _, _, _) = create_test_state(Some(0));
        let sk = SigningKey::from_bytes((&[41u8; 32]).into()).unwrap();
        let mut proof = make_signed_proof_for_rpc("gp-expired", &sk);
        proof.expires_at_height = Some(0);
        let submitted = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof }),
        )
        .await
        .expect("submit")
        .0;
        let resp = get_proof_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(GetProofRequest {
                proof_id: submitted.proof_id.clone(),
            }),
        )
        .await
        .expect("get")
        .0;
        assert!(resp.found, "expired proof must still be found");
        assert_eq!(
            resp.status, "expired",
            "tip=0 >= expires_at_height=0 must be expired"
        );
        assert!(resp.expired);
        assert_eq!(resp.expires_at_height, Some(0));
    }

    #[tokio::test]
    async fn get_proof_rpc_not_found() {
        // Request a proof that was never submitted; must return found=false with empty status.
        let (state, _, _, _) = create_test_state(Some(0));
        let resp = get_proof_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(GetProofRequest {
                proof_id: "nonexistent-proof-id".to_string(),
            }),
        )
        .await
        .expect("get")
        .0;
        assert!(!resp.found, "unknown proof_id must return found=false");
        assert!(resp.proof.is_none(), "proof must be null when not found");
        assert!(
            resp.status.is_empty(),
            "status must be empty when not found"
        );
        assert!(!resp.expired);
    }

    #[tokio::test]
    async fn get_proof_rpc_status_consistent_with_expired_bool() {
        // Invariant: (status=="expired") == expired for getproof responses.
        let (state, _, _, _) = create_test_state(Some(0));
        let sk = SigningKey::from_bytes((&[42u8; 32]).into()).unwrap();
        // Submit expired proof.
        let mut proof = make_signed_proof_for_rpc("gp-inv", &sk);
        proof.expires_at_height = Some(0);
        let sub = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof }),
        )
        .await
        .expect("submit")
        .0;
        let get = get_proof_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(GetProofRequest {
                proof_id: sub.proof_id,
            }),
        )
        .await
        .expect("get")
        .0;
        assert_eq!(
            get.expired,
            get.status == "expired",
            "(status==expired) must equal expired bool"
        );
    }

    #[tokio::test]
    async fn get_proof_rpc_status_matches_list_status() {
        // Consistency: getproof status must equal listproofs per-proof status for the same proof.
        let (state, _, _, _) = create_test_state(Some(0));
        let sk = SigningKey::from_bytes((&[43u8; 32]).into()).unwrap();
        let mut proof = make_signed_proof_for_rpc("gp-cons", &sk);
        proof.expires_at_height = Some(0); // expired at tip=0
        let sub = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof }),
        )
        .await
        .expect("submit")
        .0;
        let get = get_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(GetProofRequest {
                proof_id: sub.proof_id,
            }),
        )
        .await
        .expect("get")
        .0;
        let list = list_proofs_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(ListProofsRequest {
                agreement_hash: None,
                active_only: false,
                ..Default::default()
            }),
        )
        .await
        .expect("list")
        .0;
        assert_eq!(
            get.status, list.proofs[0].status,
            "getproof status must match listproofs status for the same proof"
        );
    }

    // ---- Pagination tests ----

    #[tokio::test]
    async fn list_proofs_rpc_pagination_limit_only() {
        // limit=3 on 5 proofs must return first 3 in time order.
        let (state, _, _, _) = create_test_state(Some(0));
        let keys: Vec<_> = (72u8..77)
            .map(|b| SigningKey::from_bytes((&[b; 32]).into()).unwrap())
            .collect();
        for (i, sk) in keys.iter().enumerate() {
            let p = make_proof_with_time(
                &format!("prf-lim-{}", i),
                "hash-lim",
                (i as u64 + 1) * 1000,
                sk,
            );
            let _ = submit_proof_rpc(
                ConnectInfo(test_socket()),
                State(state.clone()),
                HeaderMap::new(),
                Json(SubmitProofRequest { proof: p }),
            )
            .await
            .expect("submit");
        }
        let resp = list_proofs_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(ListProofsRequest {
                limit: Some(3),
                ..Default::default()
            }),
        )
        .await
        .expect("list")
        .0;
        assert_eq!(
            resp.total_count, 5,
            "total_count must reflect unsliced count"
        );
        assert_eq!(resp.returned_count, 3, "count must reflect page size");
        assert!(resp.has_more, "3 of 5 returned at offset 0, more remain");
        assert_eq!(resp.proofs.len(), 3);
        assert_eq!(resp.offset, 0);
        assert_eq!(resp.limit, Some(3));
        assert_eq!(
            resp.proofs[0].proof.attestation_time, 1_000,
            "first page must start from oldest"
        );
        assert_eq!(resp.proofs[2].proof.attestation_time, 3_000);
    }

    #[tokio::test]
    async fn list_proofs_rpc_pagination_offset_only() {
        // offset=2 on 5 proofs must skip first 2 and return the rest.
        let (state, _, _, _) = create_test_state(Some(0));
        let keys: Vec<_> = (77u8..82)
            .map(|b| SigningKey::from_bytes((&[b; 32]).into()).unwrap())
            .collect();
        for (i, sk) in keys.iter().enumerate() {
            let p = make_proof_with_time(
                &format!("prf-off-{}", i),
                "hash-off",
                (i as u64 + 1) * 1000,
                sk,
            );
            let _ = submit_proof_rpc(
                ConnectInfo(test_socket()),
                State(state.clone()),
                HeaderMap::new(),
                Json(SubmitProofRequest { proof: p }),
            )
            .await
            .expect("submit");
        }
        let resp = list_proofs_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(ListProofsRequest {
                offset: 2,
                ..Default::default()
            }),
        )
        .await
        .expect("list")
        .0;
        assert_eq!(resp.total_count, 5);
        assert_eq!(resp.returned_count, 3, "5 proofs minus offset 2 = 3");
        assert!(!resp.has_more, "all remaining proofs returned");
        assert_eq!(resp.proofs.len(), 3);
        assert_eq!(resp.offset, 2);
        assert_eq!(resp.limit, None);
        assert_eq!(
            resp.proofs[0].proof.attestation_time, 3_000,
            "offset 2 must skip first two"
        );
        assert_eq!(resp.proofs[2].proof.attestation_time, 5_000);
    }

    #[tokio::test]
    async fn list_proofs_rpc_pagination_limit_and_offset() {
        // offset=1, limit=2 on 5 proofs must return proofs at index 1 and 2.
        let (state, _, _, _) = create_test_state(Some(0));
        let keys: Vec<_> = (82u8..87)
            .map(|b| SigningKey::from_bytes((&[b; 32]).into()).unwrap())
            .collect();
        for (i, sk) in keys.iter().enumerate() {
            let p = make_proof_with_time(
                &format!("prf-lo-{}", i),
                "hash-lo",
                (i as u64 + 1) * 1000,
                sk,
            );
            let _ = submit_proof_rpc(
                ConnectInfo(test_socket()),
                State(state.clone()),
                HeaderMap::new(),
                Json(SubmitProofRequest { proof: p }),
            )
            .await
            .expect("submit");
        }
        let resp = list_proofs_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(ListProofsRequest {
                offset: 1,
                limit: Some(2),
                ..Default::default()
            }),
        )
        .await
        .expect("list")
        .0;
        assert_eq!(resp.total_count, 5);
        assert_eq!(resp.returned_count, 2);
        assert!(resp.has_more, "5 > offset(1)+returned(2)");
        assert_eq!(resp.proofs.len(), 2);
        assert_eq!(
            resp.proofs[0].proof.attestation_time, 2_000,
            "offset=1 skips index 0, starts at index 1"
        );
        assert_eq!(
            resp.proofs[1].proof.attestation_time, 3_000,
            "limit=2 stops after index 2"
        );
    }

    #[tokio::test]
    async fn list_proofs_rpc_pagination_offset_beyond_length() {
        // offset beyond list length must return empty proofs but total_count reflects full size.
        let (state, _, _, _) = create_test_state(Some(0));
        let keys: Vec<_> = (87u8..90)
            .map(|b| SigningKey::from_bytes((&[b; 32]).into()).unwrap())
            .collect();
        for (i, sk) in keys.iter().enumerate() {
            let p = make_proof_with_time(
                &format!("prf-oob-{}", i),
                "hash-oob",
                (i as u64 + 1) * 1000,
                sk,
            );
            let _ = submit_proof_rpc(
                ConnectInfo(test_socket()),
                State(state.clone()),
                HeaderMap::new(),
                Json(SubmitProofRequest { proof: p }),
            )
            .await
            .expect("submit");
        }
        let resp = list_proofs_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(ListProofsRequest {
                offset: 100,
                ..Default::default()
            }),
        )
        .await
        .expect("list")
        .0;
        assert_eq!(resp.total_count, 3, "total_count must equal full list");
        assert_eq!(resp.returned_count, 0, "no proofs when offset > total");
        assert!(!resp.has_more, "empty page, nothing more");
        assert!(resp.proofs.is_empty());
    }

    #[tokio::test]
    async fn list_proofs_rpc_pagination_limit_larger_than_list() {
        // limit larger than total proofs must return all proofs without error.
        let (state, _, _, _) = create_test_state(Some(0));
        let keys: Vec<_> = (90u8..93)
            .map(|b| SigningKey::from_bytes((&[b; 32]).into()).unwrap())
            .collect();
        for (i, sk) in keys.iter().enumerate() {
            let p = make_proof_with_time(
                &format!("prf-big-{}", i),
                "hash-big",
                (i as u64 + 1) * 1000,
                sk,
            );
            let _ = submit_proof_rpc(
                ConnectInfo(test_socket()),
                State(state.clone()),
                HeaderMap::new(),
                Json(SubmitProofRequest { proof: p }),
            )
            .await
            .expect("submit");
        }
        let resp = list_proofs_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(ListProofsRequest {
                limit: Some(999),
                ..Default::default()
            }),
        )
        .await
        .expect("list")
        .0;
        assert_eq!(resp.total_count, 3);
        assert_eq!(
            resp.returned_count, 3,
            "limit > total must return all proofs"
        );
        assert!(!resp.has_more, "all proofs returned, nothing more");
        assert_eq!(resp.proofs.len(), 3);
    }

    #[tokio::test]
    async fn list_proofs_rpc_pagination_with_active_only() {
        // active_only filter applies before pagination; total_count reflects post-filter count.
        let (state, _, _, _) = create_test_state(Some(0));
        let sk1 = SigningKey::from_bytes((&[93u8; 32]).into()).unwrap();
        let sk2 = SigningKey::from_bytes((&[94u8; 32]).into()).unwrap();
        let sk3 = SigningKey::from_bytes((&[95u8; 32]).into()).unwrap();
        let sk4 = SigningKey::from_bytes((&[96u8; 32]).into()).unwrap();
        let p1 = make_proof_with_time("prf-aop-1", "hash-aop", 1_000, &sk1); // active
        let mut p2 = make_proof_with_time("prf-aop-2", "hash-aop", 2_000, &sk2);
        p2.expires_at_height = Some(0); // expired
        let p3 = make_proof_with_time("prf-aop-3", "hash-aop", 3_000, &sk3); // active
        let p4 = make_proof_with_time("prf-aop-4", "hash-aop", 4_000, &sk4); // active
        for p in [p1, p2, p3, p4] {
            let _ = submit_proof_rpc(
                ConnectInfo(test_socket()),
                State(state.clone()),
                HeaderMap::new(),
                Json(SubmitProofRequest { proof: p }),
            )
            .await
            .expect("submit");
        }
        // active_only=true leaves 3; limit=2 must page those 3
        let resp = list_proofs_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(ListProofsRequest {
                active_only: true,
                limit: Some(2),
                ..Default::default()
            }),
        )
        .await
        .expect("list")
        .0;
        assert_eq!(
            resp.total_count, 3,
            "total_count must be post-filter pre-pagination"
        );
        assert_eq!(resp.returned_count, 2, "limit=2 must cap page");
        assert!(resp.has_more, "3 active proofs paged at 2, one remains");
        assert_eq!(resp.proofs[0].proof.attestation_time, 1_000);
        assert_eq!(resp.proofs[1].proof.attestation_time, 3_000);
        assert_eq!(resp.proofs[0].status, "active");
    }

    #[tokio::test]
    async fn list_proofs_rpc_pagination_with_agreement_hash() {
        // agreement_hash scoping applies before pagination.
        let (state, _, _, _) = create_test_state(Some(0));
        let keys: Vec<_> = (97u8..103)
            .map(|b| SigningKey::from_bytes((&[b; 32]).into()).unwrap())
            .collect();
        // 4 proofs for hash-pg-a, 2 for hash-pg-b
        for (i, sk) in keys[..4].iter().enumerate() {
            let p = make_proof_with_time(
                &format!("prf-pga-{}", i),
                "hash-pg-a",
                (i as u64 + 1) * 1000,
                sk,
            );
            let _ = submit_proof_rpc(
                ConnectInfo(test_socket()),
                State(state.clone()),
                HeaderMap::new(),
                Json(SubmitProofRequest { proof: p }),
            )
            .await
            .expect("submit");
        }
        for (i, sk) in keys[4..].iter().enumerate() {
            let p = make_proof_with_time(
                &format!("prf-pgb-{}", i),
                "hash-pg-b",
                (i as u64 + 1) * 1000,
                sk,
            );
            let _ = submit_proof_rpc(
                ConnectInfo(test_socket()),
                State(state.clone()),
                HeaderMap::new(),
                Json(SubmitProofRequest { proof: p }),
            )
            .await
            .expect("submit");
        }
        let resp = list_proofs_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(ListProofsRequest {
                agreement_hash: Some("hash-pg-a".to_string()),
                offset: 1,
                limit: Some(2),
                ..Default::default()
            }),
        )
        .await
        .expect("list")
        .0;
        assert_eq!(resp.total_count, 4, "scoped to hash-pg-a only");
        assert_eq!(resp.returned_count, 2);
        assert!(
            resp.has_more,
            "4 scoped proofs, offset=1+returned=2, one more at index 3"
        );
        assert_eq!(
            resp.proofs[0].proof.attestation_time, 2_000,
            "offset=1 skips first"
        );
        assert_eq!(resp.proofs[1].proof.attestation_time, 3_000);
    }

    #[tokio::test]
    async fn list_proofs_rpc_has_more_false_on_last_page() {
        // Last page: offset + returned_count == total_count => has_more false.
        let (state, _, _, _) = create_test_state(Some(0));
        let keys: Vec<_> = (103u8..107)
            .map(|b| SigningKey::from_bytes((&[b; 32]).into()).unwrap())
            .collect();
        for (i, sk) in keys.iter().enumerate() {
            let p = make_proof_with_time(
                &format!("prf-lp-{}", i),
                "hash-lp",
                (i as u64 + 1) * 1000,
                sk,
            );
            let _ = submit_proof_rpc(
                ConnectInfo(test_socket()),
                State(state.clone()),
                HeaderMap::new(),
                Json(SubmitProofRequest { proof: p }),
            )
            .await
            .expect("submit");
        }
        let resp = list_proofs_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(ListProofsRequest {
                offset: 2,
                limit: Some(2),
                ..Default::default()
            }),
        )
        .await
        .expect("list")
        .0;
        assert_eq!(resp.total_count, 4);
        assert_eq!(resp.returned_count, 2);
        assert!(!resp.has_more, "offset(2)+returned(2)==total(4), last page");
    }

    #[tokio::test]
    async fn list_proofs_rpc_has_more_false_no_limit_full_result() {
        // No limit: all proofs returned => has_more always false.
        let (state, _, _, _) = create_test_state(Some(0));
        let keys: Vec<_> = (107u8..110)
            .map(|b| SigningKey::from_bytes((&[b; 32]).into()).unwrap())
            .collect();
        for (i, sk) in keys.iter().enumerate() {
            let p = make_proof_with_time(
                &format!("prf-nolim-{}", i),
                "hash-nolim",
                (i as u64 + 1) * 1000,
                sk,
            );
            let _ = submit_proof_rpc(
                ConnectInfo(test_socket()),
                State(state.clone()),
                HeaderMap::new(),
                Json(SubmitProofRequest { proof: p }),
            )
            .await
            .expect("submit");
        }
        let resp = list_proofs_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(ListProofsRequest {
                ..Default::default()
            }),
        )
        .await
        .expect("list")
        .0;
        assert_eq!(resp.total_count, 3);
        assert_eq!(resp.returned_count, 3);
        assert!(!resp.has_more, "no limit means all results returned");
    }

    // ---- Integration audit tests ----
    // These tests exercise multiple surfaces in sequence to validate
    // cross-surface invariants across the full Phase 2 proof-automation stack.

    #[tokio::test]
    async fn integration_submit_list_get_evaluate_full_flow() {
        // Full 4-step chain: submit -> listproofs -> getproof -> evaluatepolicy.
        // Verifies every surface returns consistent data for the same proof.
        use irium_node_rs::settlement::agreement_canonical_bytes;
        let (state, sender, recipient, _) = create_test_state(Some(0));
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));
        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);

        // 1. Submit proof
        let proof = make_rpc_proof(&agreement_hash, &sk);
        let proof_id = proof.proof_id.clone();
        let sub = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof }),
        )
        .await
        .expect("submit")
        .0;
        assert!(sub.accepted, "proof must be accepted");
        assert_eq!(sub.status, "active", "fresh proof must be active");
        assert!(!sub.expired);

        // 2. listproofs - verify proof appears with consistent lifecycle data
        let list = list_proofs_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(ListProofsRequest {
                agreement_hash: Some(agreement_hash.clone()),
                active_only: false,
                ..Default::default()
            }),
        )
        .await
        .expect("list")
        .0;
        assert_eq!(list.returned_count, 1);
        assert_eq!(list.total_count, 1);
        assert!(
            !list.has_more,
            "single proof, no pagination, must not have more"
        );
        assert_eq!(list.proofs[0].proof.proof_id, proof_id);
        assert_eq!(
            list.proofs[0].status, sub.status,
            "list status must match submit status"
        );
        assert_eq!(list.proofs[0].status, "active");

        // 3. getproof - verify individual retrieval is consistent with list
        let get = get_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(GetProofRequest {
                proof_id: proof_id.clone(),
            }),
        )
        .await
        .expect("get")
        .0;
        assert!(get.found, "submitted proof must be found by proof_id");
        assert_eq!(
            get.status, sub.status,
            "getproof status must match submit status"
        );
        assert_eq!(
            get.status, list.proofs[0].status,
            "getproof status must match listproofs status"
        );
        assert_eq!(
            get.expired, sub.expired,
            "getproof expired must match submit expired"
        );
        assert!(get.proof.is_some(), "proof body must be present");
        assert_eq!(get.proof.unwrap().proof_id, proof_id);

        // 4. evaluatepolicy - store policy and evaluate; must reflect proof as matched
        let policy = make_rpc_policy(&agreement_hash, &pubkey_hex);
        let _ = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy,
                replace: false,
            }),
        )
        .await
        .expect("store policy");
        let eval = evaluate_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(EvaluatePolicyRequest { agreement }),
        )
        .await
        .expect("evaluate")
        .0;
        assert_eq!(eval.outcome, PolicyOutcome::Satisfied);
        assert!(eval.release_eligible);
        assert!(!eval.refund_eligible);
        assert_eq!(eval.proof_count, 1, "active proof must be counted");
        assert_eq!(eval.expired_proof_count, 0);
        assert_eq!(eval.matched_proof_count, 1);
        assert_eq!(
            eval.matched_proof_ids,
            vec![proof_id],
            "matched_proof_ids must contain the same proof_id seen in list/get"
        );
    }

    #[tokio::test]
    async fn integration_expired_proof_visible_in_get_excluded_from_evaluate() {
        // Invariant: a proof that getproof reports as expired must be excluded from
        // evaluatepolicy's active proof set (proof_count=0, expired_proof_count=1).
        // listproofs active_only=true must also return zero proofs for the same agreement.
        use irium_node_rs::settlement::agreement_canonical_bytes;
        let (state, sender, recipient, _) = create_test_state(Some(0));
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));
        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);

        // Submit proof expired at tip=0 (expires_at_height=0, tip_height()=0)
        let mut rpc_proof = make_rpc_proof(&agreement_hash, &sk);
        rpc_proof.expires_at_height = Some(0);
        let proof_id = rpc_proof.proof_id.clone();
        let _ = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof: rpc_proof }),
        )
        .await
        .expect("submit expired");

        // getproof: expired proof must be findable but flagged expired
        let get = get_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(GetProofRequest {
                proof_id: proof_id.clone(),
            }),
        )
        .await
        .expect("get")
        .0;
        assert!(
            get.found,
            "expired proof must still be findable via getproof"
        );
        assert_eq!(get.status, "expired", "getproof must report status=expired");
        assert!(get.expired, "getproof expired bool must be true");

        // listproofs active_only=false: proof appears with status=expired
        let list_all = list_proofs_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(ListProofsRequest {
                agreement_hash: Some(agreement_hash.clone()),
                active_only: false,
                ..Default::default()
            }),
        )
        .await
        .expect("list all")
        .0;
        assert_eq!(
            list_all.returned_count, 1,
            "expired proof must appear in full list"
        );
        assert_eq!(list_all.proofs[0].status, "expired");
        assert_eq!(
            list_all.proofs[0].status, get.status,
            "listproofs and getproof must agree on status"
        );

        // listproofs active_only=true: expired proof must be excluded
        let list_active = list_proofs_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(ListProofsRequest {
                agreement_hash: Some(agreement_hash.clone()),
                active_only: true,
                ..Default::default()
            }),
        )
        .await
        .expect("list active")
        .0;
        assert_eq!(
            list_active.returned_count, 0,
            "active_only must exclude expired proof"
        );
        assert_eq!(list_active.total_count, 0);
        assert!(!list_active.has_more);

        // evaluatepolicy: same exclusion must apply — proof_count=0
        let policy = make_rpc_policy(&agreement_hash, &pubkey_hex);
        let _ = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy,
                replace: false,
            }),
        )
        .await
        .expect("store policy");
        let eval = evaluate_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(EvaluatePolicyRequest { agreement }),
        )
        .await
        .expect("evaluate")
        .0;
        assert_eq!(
            eval.proof_count, 0,
            "evaluatepolicy must apply the same expiry exclusion as active_only; got {}",
            eval.proof_count
        );
        assert_eq!(
            eval.expired_proof_count, 1,
            "expired proof must be counted in expired_proof_count"
        );
        assert_eq!(eval.outcome, PolicyOutcome::Unsatisfied);
        assert!(!eval.release_eligible);
    }

    #[tokio::test]
    async fn integration_outcome_invariant_coherence() {
        // Invariant audit: outcome field must be coherent with release_eligible and refund_eligible.
        // satisfied  -> release_eligible=true,  refund_eligible=false
        // unsatisfied -> release_eligible=false, refund_eligible=false
        // timeout    -> refund_eligible=true (when rule resolution=Refund), release_eligible=false
        use irium_node_rs::settlement::agreement_canonical_bytes;

        // Case A: satisfied
        {
            let (state, sender, recipient, _) = create_test_state(Some(0));
            let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
            let bytes = agreement_canonical_bytes(&agreement).unwrap();
            let agreement_hash = hex::encode(Sha256::digest(&bytes));
            let sk = rpc_signing_key();
            let pubkey_hex = rpc_pubkey_hex(&sk);
            let proof = make_rpc_proof(&agreement_hash, &sk);
            let _ = submit_proof_rpc(
                ConnectInfo(test_socket()),
                State(state.clone()),
                HeaderMap::new(),
                Json(SubmitProofRequest { proof }),
            )
            .await
            .expect("submit");
            let _ = store_policy_rpc(
                ConnectInfo(test_socket()),
                State(state.clone()),
                HeaderMap::new(),
                Json(StorePolicyRequest {
                    policy: make_rpc_policy(&agreement_hash, &pubkey_hex),
                    replace: false,
                }),
            )
            .await
            .expect("store");
            let eval = evaluate_policy_rpc(
                ConnectInfo(test_socket()),
                State(state),
                HeaderMap::new(),
                Json(EvaluatePolicyRequest { agreement }),
            )
            .await
            .expect("evaluate")
            .0;
            assert_eq!(eval.outcome, PolicyOutcome::Satisfied, "case A: satisfied");
            assert!(
                eval.release_eligible,
                "satisfied must imply release_eligible"
            );
            assert!(
                !eval.refund_eligible,
                "satisfied must not imply refund_eligible"
            );
        }

        // Case B: unsatisfied (no proofs)
        {
            let (state, sender, recipient, _) = create_test_state(Some(0));
            let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
            let bytes = agreement_canonical_bytes(&agreement).unwrap();
            let agreement_hash = hex::encode(Sha256::digest(&bytes));
            let sk = rpc_signing_key();
            let pubkey_hex = rpc_pubkey_hex(&sk);
            let _ = store_policy_rpc(
                ConnectInfo(test_socket()),
                State(state.clone()),
                HeaderMap::new(),
                Json(StorePolicyRequest {
                    policy: make_rpc_policy(&agreement_hash, &pubkey_hex),
                    replace: false,
                }),
            )
            .await
            .expect("store");
            let eval = evaluate_policy_rpc(
                ConnectInfo(test_socket()),
                State(state),
                HeaderMap::new(),
                Json(EvaluatePolicyRequest { agreement }),
            )
            .await
            .expect("evaluate")
            .0;
            assert_eq!(
                eval.outcome,
                PolicyOutcome::Unsatisfied,
                "case B: unsatisfied"
            );
            assert!(
                !eval.release_eligible,
                "unsatisfied must not imply release_eligible"
            );
            assert!(
                !eval.refund_eligible,
                "unsatisfied must not imply refund_eligible"
            );
        }

        // Case C: timeout via no-response rule
        {
            let (state, sender, recipient, _) = create_test_state(Some(0));
            let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
            let bytes = agreement_canonical_bytes(&agreement).unwrap();
            let agreement_hash = hex::encode(Sha256::digest(&bytes));
            let sk = rpc_signing_key();
            let pubkey_hex = rpc_pubkey_hex(&sk);
            let mut policy = make_rpc_policy(&agreement_hash, &pubkey_hex);
            policy.no_response_rules.push(NoResponseRule {
                rule_id: "rule-inv-c".to_string(),
                deadline_height: 10,
                trigger: NoResponseTrigger::FundedAndNoRelease,
                resolution: ProofResolution::Refund,
                milestone_id: None,
                notes: None,
            });
            let _ = store_policy_rpc(
                ConnectInfo(test_socket()),
                State(state.clone()),
                HeaderMap::new(),
                Json(StorePolicyRequest {
                    policy,
                    replace: false,
                }),
            )
            .await
            .expect("store");
            // tip_height() = chain.height - 1; set height=11 so tip=10 >= deadline 10
            {
                let mut chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
                chain.height = 11;
            }
            let eval = evaluate_policy_rpc(
                ConnectInfo(test_socket()),
                State(state),
                HeaderMap::new(),
                Json(EvaluatePolicyRequest { agreement }),
            )
            .await
            .expect("evaluate")
            .0;
            assert_eq!(eval.outcome, PolicyOutcome::Timeout, "case C: timeout");
            assert!(
                eval.refund_eligible,
                "timeout (refund resolution) must imply refund_eligible"
            );
            assert!(
                !eval.release_eligible,
                "timeout must not imply release_eligible when resolution=Refund"
            );
        }
    }

    #[tokio::test]
    async fn integration_active_only_pagination_two_page_traversal() {
        // 5 proofs: 3 active, 2 expired.
        // Page 1: active_only=true, limit=2 -> returned=2, has_more=true.
        // Page 2: active_only=true, limit=2, offset=2 -> returned=1, has_more=false.
        // Ordering must be preserved across both pages (attestation_time ascending).
        let (state, _, _, _) = create_test_state(Some(0));
        let sk1 = SigningKey::from_bytes((&[110u8; 32]).into()).unwrap();
        let sk2 = SigningKey::from_bytes((&[111u8; 32]).into()).unwrap();
        let sk3 = SigningKey::from_bytes((&[112u8; 32]).into()).unwrap();
        let sk4 = SigningKey::from_bytes((&[113u8; 32]).into()).unwrap();
        let sk5 = SigningKey::from_bytes((&[114u8; 32]).into()).unwrap();
        // Times: 1000(active), 2000(expired), 3000(active), 4000(expired), 5000(active)
        let p1 = make_proof_with_time("prf-tt-1", "hash-tt", 1_000, &sk1);
        let mut p2 = make_proof_with_time("prf-tt-2", "hash-tt", 2_000, &sk2);
        p2.expires_at_height = Some(0);
        let p3 = make_proof_with_time("prf-tt-3", "hash-tt", 3_000, &sk3);
        let mut p4 = make_proof_with_time("prf-tt-4", "hash-tt", 4_000, &sk4);
        p4.expires_at_height = Some(0);
        let p5 = make_proof_with_time("prf-tt-5", "hash-tt", 5_000, &sk5);
        for p in [p1, p2, p3, p4, p5] {
            let _ = submit_proof_rpc(
                ConnectInfo(test_socket()),
                State(state.clone()),
                HeaderMap::new(),
                Json(SubmitProofRequest { proof: p }),
            )
            .await
            .expect("submit");
        }

        // Page 1
        let page1 = list_proofs_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(ListProofsRequest {
                agreement_hash: Some("hash-tt".to_string()),
                active_only: true,
                limit: Some(2),
                offset: 0,
                ..Default::default()
            }),
        )
        .await
        .expect("list page1")
        .0;
        assert_eq!(page1.total_count, 3, "3 active proofs after expiry filter");
        assert_eq!(page1.returned_count, 2);
        assert!(page1.has_more, "1 more active proof on page 2");
        assert_eq!(
            page1.proofs[0].proof.attestation_time, 1_000,
            "page1[0] must be oldest active"
        );
        assert_eq!(
            page1.proofs[1].proof.attestation_time, 3_000,
            "page1[1] must skip expired at 2000"
        );
        assert_eq!(page1.proofs[0].status, "active");
        assert_eq!(page1.proofs[1].status, "active");

        // Page 2
        let page2 = list_proofs_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(ListProofsRequest {
                agreement_hash: Some("hash-tt".to_string()),
                active_only: true,
                limit: Some(2),
                offset: 2,
                ..Default::default()
            }),
        )
        .await
        .expect("list page2")
        .0;
        assert_eq!(page2.total_count, 3, "total_count must be same as page1");
        assert_eq!(
            page2.returned_count, 1,
            "only 1 active proof remains at offset=2"
        );
        assert!(!page2.has_more, "last page must have has_more=false");
        assert_eq!(
            page2.proofs[0].proof.attestation_time, 5_000,
            "page2 must contain the last active proof"
        );
        assert_eq!(page2.proofs[0].status, "active");
    }

    #[tokio::test]
    async fn integration_evaluate_active_count_matches_listproofs_active_only() {
        // Cross-surface invariant: evaluatepolicy.proof_count must equal the
        // total_count returned by listproofs with active_only=true for the same agreement.
        // Both surfaces must apply the same expiry rule.
        use irium_node_rs::settlement::agreement_canonical_bytes;
        let (state, sender, recipient, _) = create_test_state(Some(0));
        let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
        let bytes = agreement_canonical_bytes(&agreement).unwrap();
        let agreement_hash = hex::encode(Sha256::digest(&bytes));
        let sk = rpc_signing_key();
        let pubkey_hex = rpc_pubkey_hex(&sk);

        // Submit 2 active + 2 expired proofs for this agreement
        let sk2 = SigningKey::from_bytes((&[115u8; 32]).into()).unwrap();
        let sk3 = SigningKey::from_bytes((&[116u8; 32]).into()).unwrap();
        let sk4 = SigningKey::from_bytes((&[117u8; 32]).into()).unwrap();
        let active1 = make_rpc_proof(&agreement_hash, &sk);
        let _ = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof: active1 }),
        )
        .await
        .expect("submit active1");
        let mut expired1 = make_proof_with_time("prf-cross-exp1", &agreement_hash, 2_000, &sk2);
        expired1.expires_at_height = Some(0);
        let _ = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof: expired1 }),
        )
        .await
        .expect("submit expired1");
        let mut expired2 = make_proof_with_time("prf-cross-exp2", &agreement_hash, 3_000, &sk3);
        expired2.expires_at_height = Some(0);
        let _ = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof: expired2 }),
        )
        .await
        .expect("submit expired2");
        let active2 = make_proof_with_time("prf-cross-act2", &agreement_hash, 4_000, &sk4);
        let _ = submit_proof_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(SubmitProofRequest { proof: active2 }),
        )
        .await
        .expect("submit active2");

        // listproofs active_only=true: should return total_count=1
        // (only the rpc-proof is active AND matches the rpc-attestor policy requirement)
        // For the count check we use the raw active filter regardless of policy matching:
        let list_active = list_proofs_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(ListProofsRequest {
                agreement_hash: Some(agreement_hash.clone()),
                active_only: true,
                ..Default::default()
            }),
        )
        .await
        .expect("list active")
        .0;
        // active1 (rpc-proof, no expiry) + active2 (prf-cross-act2, no expiry) = 2 active
        assert_eq!(list_active.total_count, 2, "2 active proofs expected");

        // evaluatepolicy: proof_count must equal listproofs active total_count
        let _ = store_policy_rpc(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Json(StorePolicyRequest {
                policy: make_rpc_policy(&agreement_hash, &pubkey_hex),
                replace: false,
            }),
        )
        .await
        .expect("store");
        let eval = evaluate_policy_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Json(EvaluatePolicyRequest { agreement }),
        )
        .await
        .expect("evaluate")
        .0;
        assert_eq!(eval.proof_count, list_active.total_count,
            "evaluatepolicy proof_count must equal listproofs active_only total_count: expected {} got {}",
            list_active.total_count, eval.proof_count);
        assert_eq!(
            eval.expired_proof_count, 2,
            "2 expired proofs must be noted"
        );
    }

    #[tokio::test]
    async fn integration_deadline_at_exact_boundary_height() {
        // Boundary audit: a no-response rule fires exactly at deadline_height.
        // tip_height() == deadline_height must trigger Timeout (>= is the check).
        // tip_height() == deadline_height - 1 must NOT trigger (remain Unsatisfied).
        use irium_node_rs::settlement::agreement_canonical_bytes;

        let deadline = 25u64;

        // Sub-case 1: tip_height exactly at deadline -> Timeout
        {
            let (state, sender, recipient, _) = create_test_state(Some(0));
            let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
            let bytes = agreement_canonical_bytes(&agreement).unwrap();
            let agreement_hash = hex::encode(Sha256::digest(&bytes));
            let sk = rpc_signing_key();
            let pubkey_hex = rpc_pubkey_hex(&sk);
            let mut policy = make_rpc_policy(&agreement_hash, &pubkey_hex);
            policy.no_response_rules.push(NoResponseRule {
                rule_id: "rule-bnd-at".to_string(),
                deadline_height: deadline,
                trigger: NoResponseTrigger::FundedAndNoRelease,
                resolution: ProofResolution::Refund,
                milestone_id: None,
                notes: None,
            });
            let _ = store_policy_rpc(
                ConnectInfo(test_socket()),
                State(state.clone()),
                HeaderMap::new(),
                Json(StorePolicyRequest {
                    policy,
                    replace: false,
                }),
            )
            .await
            .expect("store");
            // tip_height() = chain.height - 1; set height = deadline + 1 so tip == deadline
            {
                let mut chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
                chain.height = deadline + 1;
            }
            let eval = evaluate_policy_rpc(
                ConnectInfo(test_socket()),
                State(state),
                HeaderMap::new(),
                Json(EvaluatePolicyRequest { agreement }),
            )
            .await
            .expect("evaluate")
            .0;
            assert_eq!(
                eval.outcome,
                PolicyOutcome::Timeout,
                "tip_height==deadline must trigger Timeout; reason: {}",
                eval.reason
            );
        }

        // Sub-case 2: tip_height one before deadline -> Unsatisfied
        {
            let (state, sender, recipient, _) = create_test_state(Some(0));
            let (agreement, _) = milestone_agreement_for_test(&sender, &recipient, 200);
            let bytes = agreement_canonical_bytes(&agreement).unwrap();
            let agreement_hash = hex::encode(Sha256::digest(&bytes));
            let sk = rpc_signing_key();
            let pubkey_hex = rpc_pubkey_hex(&sk);
            let mut policy = make_rpc_policy(&agreement_hash, &pubkey_hex);
            policy.no_response_rules.push(NoResponseRule {
                rule_id: "rule-bnd-before".to_string(),
                deadline_height: deadline,
                trigger: NoResponseTrigger::FundedAndNoRelease,
                resolution: ProofResolution::Refund,
                milestone_id: None,
                notes: None,
            });
            let _ = store_policy_rpc(
                ConnectInfo(test_socket()),
                State(state.clone()),
                HeaderMap::new(),
                Json(StorePolicyRequest {
                    policy,
                    replace: false,
                }),
            )
            .await
            .expect("store");
            // tip_height() = deadline - 1 (one before): height = deadline (height-1 = deadline-1)
            {
                let mut chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
                chain.height = deadline;
            }
            let eval = evaluate_policy_rpc(
                ConnectInfo(test_socket()),
                State(state),
                HeaderMap::new(),
                Json(EvaluatePolicyRequest { agreement }),
            )
            .await
            .expect("evaluate")
            .0;
            assert_eq!(
                eval.outcome,
                PolicyOutcome::Unsatisfied,
                "tip_height==deadline-1 must NOT trigger; got: {}",
                eval.reason
            );
            assert!(!eval.refund_eligible);
        }
    }

    // ── Phase 3: template builder RPC tests ──────────────────────────────────

    #[tokio::test]
    async fn build_contractor_template_rpc_returns_policy_and_summary() {
        let (state, _, _, _) = create_test_state(None);
        let req = BuildContractorTemplateRequest {
            policy_id: "pol-contractor-1".to_string(),
            agreement_hash: "aa".repeat(32),
            attestors: vec![TemplateAttestorInput {
                attestor_id: "att-site".to_string(),
                pubkey_hex: "03".to_string() + &"ab".repeat(32),
                display_name: Some("Site Inspector".to_string()),
            }],
            milestones: vec![
                MilestoneSpecInput {
                    milestone_id: "ms-foundation".to_string(),
                    label: Some("Foundation".to_string()),
                    proof_type: "foundation_complete".to_string(),
                    deadline_height: Some(500_000),
                    holdback_bps: None,
                    holdback_release_height: None,
                },
                MilestoneSpecInput {
                    milestone_id: "ms-framing".to_string(),
                    label: Some("Framing".to_string()),
                    proof_type: "framing_complete".to_string(),
                    deadline_height: None,
                    holdback_bps: None,
                    holdback_release_height: None,
                },
            ],
            notes: None,
        };
        let resp = build_contractor_template_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            AxumJson(req),
        )
        .await
        .expect("build_contractor_template_rpc should succeed")
        .0;
        assert_eq!(resp.milestone_count, 2);
        assert_eq!(resp.requirement_count, 2);
        assert_eq!(resp.attestor_count, 1);
        assert!(
            resp.has_timeout_rules,
            "foundation milestone has a deadline"
        );
        assert!(!resp.has_holdback);
        assert!(
            resp.summary.contains("pol-contractor-1"),
            "summary contains policy_id"
        );
        assert!(!resp.policy_json.is_empty(), "policy_json must be present");
        // policy_json must be valid JSON
        let v: serde_json::Value =
            serde_json::from_str(&resp.policy_json).expect("policy_json is valid JSON");
        assert_eq!(v["policy_id"], "pol-contractor-1");
    }

    #[tokio::test]
    async fn build_contractor_template_rpc_rejects_empty_milestones() {
        let (state, _, _, _) = create_test_state(None);
        let req = BuildContractorTemplateRequest {
            policy_id: "pol-c-2".to_string(),
            agreement_hash: "bb".repeat(32),
            attestors: vec![TemplateAttestorInput {
                attestor_id: "att-1".to_string(),
                pubkey_hex: "03".to_string() + &"cd".repeat(32),
                display_name: None,
            }],
            milestones: vec![],
            notes: None,
        };
        let result = build_contractor_template_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            AxumJson(req),
        )
        .await;
        assert!(result.is_err(), "empty milestones must be rejected");
        let (status, _msg) = result.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn build_preorder_template_rpc_returns_policy_and_summary() {
        let (state, _, _, _) = create_test_state(None);
        let req = BuildPreorderTemplateRequest {
            policy_id: "pol-preorder-1".to_string(),
            agreement_hash: "cc".repeat(32),
            attestors: vec![TemplateAttestorInput {
                attestor_id: "att-warehouse".to_string(),
                pubkey_hex: "03".to_string() + &"ef".repeat(32),
                display_name: None,
            }],
            delivery_proof_type: "shipment_delivered".to_string(),
            refund_deadline_height: 900_000,
            holdback_bps: None,
            holdback_release_height: None,
            notes: None,
        };
        let resp = build_preorder_template_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            AxumJson(req),
        )
        .await
        .expect("build_preorder_template_rpc should succeed")
        .0;
        assert_eq!(resp.requirement_count, 1);
        assert_eq!(resp.attestor_count, 1);
        assert_eq!(resp.milestone_count, 0);
        assert!(resp.has_timeout_rules);
        assert!(!resp.has_holdback);
        assert!(resp.summary.contains("pol-preorder-1"));
        let v: serde_json::Value = serde_json::from_str(&resp.policy_json).unwrap();
        assert_eq!(v["policy_id"], "pol-preorder-1");
    }

    #[tokio::test]
    async fn build_preorder_template_rpc_rejects_empty_attestors() {
        let (state, _, _, _) = create_test_state(None);
        let req = BuildPreorderTemplateRequest {
            policy_id: "pol-p-empty".to_string(),
            agreement_hash: "dd".repeat(32),
            attestors: vec![],
            delivery_proof_type: "proof".to_string(),
            refund_deadline_height: 1_000,
            holdback_bps: None,
            holdback_release_height: None,
            notes: None,
        };
        let result = build_preorder_template_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            AxumJson(req),
        )
        .await;
        assert!(result.is_err());
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn build_otc_template_rpc_single_attestor_default_threshold() {
        let (state, _, _, _) = create_test_state(None);
        let req = BuildOtcTemplateRequest {
            policy_id: "pol-otc-1".to_string(),
            agreement_hash: "ee".repeat(32),
            attestors: vec![TemplateAttestorInput {
                attestor_id: "att-arb".to_string(),
                pubkey_hex: "03".to_string() + &"12".repeat(32),
                display_name: None,
            }],
            release_proof_type: "otc_trade_confirmed".to_string(),
            refund_deadline_height: 800_000,
            threshold: None,
            notes: None,
        };
        let resp = build_otc_template_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            AxumJson(req),
        )
        .await
        .expect("build_otc_template_rpc should succeed")
        .0;
        assert_eq!(resp.requirement_count, 1);
        assert_eq!(resp.attestor_count, 1);
        assert_eq!(resp.milestone_count, 0);
        assert!(!resp.has_holdback);
        assert!(resp.has_timeout_rules);
        assert!(resp.summary.contains("pol-otc-1"));
        // single attestor => no threshold field in JSON
        let v: serde_json::Value = serde_json::from_str(&resp.policy_json).unwrap();
        assert!(
            v["required_proofs"][0]["threshold"].is_null(),
            "single-attestor path must not set threshold"
        );
    }

    #[tokio::test]
    async fn build_otc_template_rpc_multi_attestor_threshold() {
        let (state, _, _, _) = create_test_state(None);
        let req = BuildOtcTemplateRequest {
            policy_id: "pol-otc-multi".to_string(),
            agreement_hash: "ff".repeat(32),
            attestors: vec![
                TemplateAttestorInput {
                    attestor_id: "att-a".to_string(),
                    pubkey_hex: "03".to_string() + &"aa".repeat(32),
                    display_name: None,
                },
                TemplateAttestorInput {
                    attestor_id: "att-b".to_string(),
                    pubkey_hex: "03".to_string() + &"bb".repeat(32),
                    display_name: None,
                },
                TemplateAttestorInput {
                    attestor_id: "att-c".to_string(),
                    pubkey_hex: "03".to_string() + &"cc".repeat(32),
                    display_name: None,
                },
            ],
            release_proof_type: "otc_trade_confirmed".to_string(),
            refund_deadline_height: 900_000,
            threshold: Some(2),
            notes: None,
        };
        let resp = build_otc_template_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            AxumJson(req),
        )
        .await
        .expect("build_otc_template_rpc 2-of-3 should succeed")
        .0;
        assert_eq!(resp.attestor_count, 3);
        let v: serde_json::Value = serde_json::from_str(&resp.policy_json).unwrap();
        assert_eq!(
            v["required_proofs"][0]["threshold"], 2,
            "2-of-3 must set threshold=2"
        );
        assert!(
            resp.summary.contains("2-of-3") || resp.summary.contains("2-of"),
            "summary describes threshold"
        );
    }

    #[tokio::test]
    async fn build_otc_template_rpc_rejects_threshold_exceeds_attestors() {
        let (state, _, _, _) = create_test_state(None);
        let req = BuildOtcTemplateRequest {
            policy_id: "pol-otc-bad".to_string(),
            agreement_hash: "1a".repeat(32),
            attestors: vec![TemplateAttestorInput {
                attestor_id: "att-only".to_string(),
                pubkey_hex: "03".to_string() + &"11".repeat(32),
                display_name: None,
            }],
            release_proof_type: "proof".to_string(),
            refund_deadline_height: 1000,
            threshold: Some(3),
            notes: None,
        };
        let result = build_otc_template_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            AxumJson(req),
        )
        .await;
        assert!(result.is_err());
        let (status, msg) = result.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            msg.contains("threshold"),
            "error must mention threshold; got: {msg}"
        );
    }

    // Phase 3 audit: empty policy_id is rejected at the template layer
    #[tokio::test]
    async fn build_contractor_template_rpc_rejects_empty_policy_id() {
        let (state, _, _, _) = create_test_state(None);
        let req = BuildContractorTemplateRequest {
            policy_id: "".to_string(),
            agreement_hash: "aa".repeat(32),
            attestors: vec![TemplateAttestorInput {
                attestor_id: "att".to_string(),
                pubkey_hex: "03".to_string() + &"ab".repeat(32),
                display_name: None,
            }],
            milestones: vec![MilestoneSpecInput {
                milestone_id: "ms-1".to_string(),
                label: None,
                proof_type: "delivery".to_string(),
                deadline_height: None,
                holdback_bps: None,
                holdback_release_height: None,
            }],
            notes: None,
        };
        let result = build_contractor_template_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            AxumJson(req),
        )
        .await;
        assert!(result.is_err());
        let (status, msg) = result.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(msg.contains("policy_id must not be empty"), "got: {msg}");
    }

    #[tokio::test]
    async fn build_contractor_template_rpc_rejects_empty_proof_type() {
        let (state, _, _, _) = create_test_state(None);
        let req = BuildContractorTemplateRequest {
            policy_id: "pol-empty-pt".to_string(),
            agreement_hash: "bb".repeat(32),
            attestors: vec![TemplateAttestorInput {
                attestor_id: "att".to_string(),
                pubkey_hex: "03".to_string() + &"cd".repeat(32),
                display_name: None,
            }],
            milestones: vec![MilestoneSpecInput {
                milestone_id: "ms-1".to_string(),
                label: None,
                proof_type: "".to_string(),
                deadline_height: None,
                holdback_bps: None,
                holdback_release_height: None,
            }],
            notes: None,
        };
        let result = build_contractor_template_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            AxumJson(req),
        )
        .await;
        assert!(result.is_err());
        let (status, msg) = result.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(msg.contains("proof_type must not be empty"), "got: {msg}");
    }

    #[tokio::test]
    async fn build_preorder_template_rpc_rejects_empty_delivery_proof_type() {
        let (state, _, _, _) = create_test_state(None);
        let req = BuildPreorderTemplateRequest {
            policy_id: "pol-empty-dpt".to_string(),
            agreement_hash: "cc".repeat(32),
            attestors: vec![TemplateAttestorInput {
                attestor_id: "att".to_string(),
                pubkey_hex: "03".to_string() + &"ef".repeat(32),
                display_name: None,
            }],
            delivery_proof_type: "".to_string(),
            refund_deadline_height: 100_000,
            holdback_bps: None,
            holdback_release_height: None,
            notes: None,
        };
        let result = build_preorder_template_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            AxumJson(req),
        )
        .await;
        assert!(result.is_err());
        let (status, msg) = result.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            msg.contains("delivery_proof_type must not be empty"),
            "got: {msg}"
        );
    }

    #[tokio::test]
    async fn build_otc_template_rpc_rejects_threshold_zero() {
        let (state, _, _, _) = create_test_state(None);
        let req = BuildOtcTemplateRequest {
            policy_id: "pol-thr0".to_string(),
            agreement_hash: "dd".repeat(32),
            attestors: vec![TemplateAttestorInput {
                attestor_id: "att".to_string(),
                pubkey_hex: "03".to_string() + &"12".repeat(32),
                display_name: None,
            }],
            release_proof_type: "trade".to_string(),
            refund_deadline_height: 500_000,
            threshold: Some(0),
            notes: None,
        };
        let result = build_otc_template_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            AxumJson(req),
        )
        .await;
        assert!(result.is_err());
        let (status, msg) = result.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(msg.contains("threshold must be >= 1"), "got: {msg}");
    }

    // milestone_count in response is derived from policy, not caller input
    #[tokio::test]
    async fn build_contractor_template_milestone_count_matches_policy() {
        let (state, _, _, _) = create_test_state(None);
        let req = BuildContractorTemplateRequest {
            policy_id: "pol-ms-count".to_string(),
            agreement_hash: "ee".repeat(32),
            attestors: vec![TemplateAttestorInput {
                attestor_id: "att".to_string(),
                pubkey_hex: "03".to_string() + &"ab".repeat(32),
                display_name: None,
            }],
            milestones: vec![
                MilestoneSpecInput {
                    milestone_id: "ms-a".to_string(),
                    label: None,
                    proof_type: "pa".to_string(),
                    deadline_height: None,
                    holdback_bps: None,
                    holdback_release_height: None,
                },
                MilestoneSpecInput {
                    milestone_id: "ms-b".to_string(),
                    label: None,
                    proof_type: "pb".to_string(),
                    deadline_height: None,
                    holdback_bps: None,
                    holdback_release_height: None,
                },
                MilestoneSpecInput {
                    milestone_id: "ms-c".to_string(),
                    label: None,
                    proof_type: "pc".to_string(),
                    deadline_height: None,
                    holdback_bps: None,
                    holdback_release_height: None,
                },
            ],
            notes: None,
        };
        let resp = build_contractor_template_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            AxumJson(req),
        )
        .await
        .expect("should succeed")
        .0;
        // milestone_count in response must match actual policy.milestones.len()
        assert_eq!(
            resp.milestone_count,
            resp.policy.milestones.len(),
            "milestone_count must be derived from policy, not caller input"
        );
        assert_eq!(resp.milestone_count, 3);
        assert_eq!(resp.requirement_count, resp.policy.required_proofs.len());
    }

    // summary attestor list must reflect the policy's attestors
    #[tokio::test]
    async fn build_otc_summary_reflects_policy_attestors() {
        let (state, _, _, _) = create_test_state(None);
        let req = BuildOtcTemplateRequest {
            policy_id: "pol-summary-check".to_string(),
            agreement_hash: "ff".repeat(32),
            attestors: vec![
                TemplateAttestorInput {
                    attestor_id: "arbitrator-alpha".to_string(),
                    pubkey_hex: "03".to_string() + &"aa".repeat(32),
                    display_name: None,
                },
                TemplateAttestorInput {
                    attestor_id: "arbitrator-beta".to_string(),
                    pubkey_hex: "03".to_string() + &"bb".repeat(32),
                    display_name: None,
                },
            ],
            release_proof_type: "trade_confirmed".to_string(),
            refund_deadline_height: 1_000_000,
            threshold: Some(2),
            notes: None,
        };
        let resp = build_otc_template_rpc(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            AxumJson(req),
        )
        .await
        .expect("should succeed")
        .0;
        assert!(
            resp.summary.contains("arbitrator-alpha"),
            "summary must list attestor ids: {}",
            resp.summary
        );
        assert!(
            resp.summary.contains("arbitrator-beta"),
            "summary must list attestor ids: {}",
            resp.summary
        );
        assert_eq!(resp.attestor_count, 2);
        assert_eq!(resp.attestor_count, resp.policy.attestors.len());
    }

    // ─── Rich-list ──────────────────────────────────────────────────────
    //
    // Mocks 5 P2PKH UTXOs across 3 addresses plus 1 non-P2PKH output:
    //   sender    15 IRM  (10 + 5)         — rank 1, 2 UTXOs
    //   recipient  5 IRM  (3 + 2)          — rank 2, 2 UTXOs
    //   refund     1 IRM  (1)              — rank 3, 1 UTXO
    //   non-P2PKH  4 IRM  (script len=1)   — excluded from entries,
    //                                        counted in total_supply_sats
    // Total supply: 25 IRM. Per-entry percentages: 60% / 20% / 4% = 84%.
    // The remaining 16% is the non-P2PKH bucket and is intentionally not
    // surfaced as an "entry" (no single owning address for that script).
    fn insert_utxo(state: &AppState, txid_byte: u8, index: u32, value: u64, script_pubkey: Vec<u8>) {
        let mut chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let tip = chain.tip_height();
        chain.utxos.insert(
            OutPoint { txid: [txid_byte; 32], index },
            UtxoEntry {
                output: TxOutput { value, script_pubkey },
                height: tip,
                is_coinbase: false,
            },
        );
    }

    #[tokio::test]
    async fn rpc_richlist_ranks_and_excludes_non_p2pkh() {
        let (state, sender, recipient, refund) = create_test_state(None);

        // Genesis state carries premine UTXOs from the locked genesis block;
        // strip them so this test asserts against only the UTXOs it injects.
        {
            let mut chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
            chain.utxos.clear();
        }

        // P2PKH helper: build the script bytes from the address's PKH so
        // the test mirrors what real iriumd-side encoding produces.
        let p2pkh = |addr: &str| -> Vec<u8> {
            let pkh = base58_p2pkh_to_hash(addr).expect("addr decode");
            let mut pkh20 = [0u8; 20];
            pkh20.copy_from_slice(&pkh);
            p2pkh_script(&pkh20)
        };

        // 5 P2PKH UTXOs + 1 non-P2PKH output.
        insert_utxo(&state, 0x01, 0, 10_00_000_000, p2pkh(&sender));    // 10 IRM
        insert_utxo(&state, 0x02, 0,  5_00_000_000, p2pkh(&sender));    //  5 IRM
        insert_utxo(&state, 0x03, 0,  3_00_000_000, p2pkh(&recipient)); //  3 IRM
        insert_utxo(&state, 0x04, 0,  2_00_000_000, p2pkh(&recipient)); //  2 IRM
        insert_utxo(&state, 0x05, 0,  1_00_000_000, p2pkh(&refund));    //  1 IRM
        // Non-P2PKH: 1-byte script will fail p2pkh_hash_from_script's len==25 gate.
        insert_utxo(&state, 0x06, 0,  4_00_000_000, vec![0x00]);        //  4 IRM

        let resp = get_richlist(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            Query(RichlistQuery { limit: Some(100) }),
        )
        .await
        .expect("richlist call should succeed")
        .0;

        // total_supply_sats includes ALL outputs (P2PKH + non-P2PKH).
        assert_eq!(resp.total_supply_sats, 25_00_000_000, "total supply must include non-P2PKH outputs");

        // entries excludes the non-P2PKH output → exactly 3 addresses.
        assert_eq!(resp.count, 3);
        assert_eq!(resp.entries.len(), 3);

        // Ranking: highest balance first.
        assert_eq!(resp.entries[0].rank, 1);
        assert_eq!(resp.entries[0].address, sender);
        assert_eq!(resp.entries[0].balance_sats, 15_00_000_000);
        assert!((resp.entries[0].balance_irm - 15.0).abs() < 1e-9);
        assert_eq!(resp.entries[0].utxo_count, 2);

        assert_eq!(resp.entries[1].rank, 2);
        assert_eq!(resp.entries[1].address, recipient);
        assert_eq!(resp.entries[1].balance_sats, 5_00_000_000);
        assert_eq!(resp.entries[1].utxo_count, 2);

        assert_eq!(resp.entries[2].rank, 3);
        assert_eq!(resp.entries[2].address, refund);
        assert_eq!(resp.entries[2].balance_sats, 1_00_000_000);
        assert_eq!(resp.entries[2].utxo_count, 1);

        // Percentages match the balance-to-total ratio and never exceed 100.
        let pct_sum: f64 = resp.entries.iter().map(|e| e.percentage).sum();
        assert!(pct_sum <= 100.0 + 1e-9, "percentages must sum to ≤ 100, got {}", pct_sum);
        // The non-P2PKH 4 IRM is the 16% gap — entry percentages should sum to 84%.
        assert!((pct_sum - 84.0).abs() < 0.01, "expected ≈84% sum, got {}", pct_sum);

        // Sanity-check the rank-1 percentage matches 15/25 = 60%.
        assert!((resp.entries[0].percentage - 60.0).abs() < 0.01);

        // generated_at_height equals the chain's tip — for the freshly-built
        // test state with no blocks applied, that's 0.
        assert_eq!(resp.generated_at_height, 0);
    }

    // ========================================================================
    // Stage 3.2.1: Dispute & resolver handler tests
    // ========================================================================

    fn s32_test_sk(seed: u8) -> SigningKey {
        SigningKey::from_bytes((&[seed; 32]).into()).expect("test sk")
    }

    fn s32_test_addr(sk: &SigningKey) -> String {
        let pk = sk
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let sha = Sha256::digest(&pk);
        let rip = ripemd::Ripemd160::digest(sha);
        let mut pkh = [0u8; 20];
        pkh.copy_from_slice(&rip);
        base58_p2pkh_from_hash(&pkh)
    }

    fn s32_signing_envelope(sk: &SigningKey, agreement_hash: &str) -> AgreementSignatureEnvelope {
        let pk = sk
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        AgreementSignatureEnvelope {
            version: 1,
            target_type: irium_node_rs::settlement::AgreementSignatureTargetType::Agreement,
            target_hash: agreement_hash.to_string(),
            signer_public_key: hex::encode(&pk),
            signer_address: Some(s32_test_addr(sk)),
            signature_type: AGREEMENT_SIGNATURE_TYPE_SECP256K1.to_string(),
            timestamp: Some(1_700_000_000),
            signer_role: None,
            signature: String::new(),
        }
    }

    fn s32_sign_raise(d: &mut DisputeRaise, sk: &SigningKey) {
        d.signature = s32_signing_envelope(sk, &d.agreement_hash);
        let bytes = dispute_raise_canonical_bytes(d).expect("canonical");
        let digest = Sha256::digest(&bytes);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&digest);
        let sig: Signature = sk.sign_prehash(&arr).expect("sign");
        let sig = sig.normalize_s().unwrap_or(sig);
        d.signature.signature = hex::encode(sig.to_bytes());
    }

    fn s32_sign_evidence(d: &mut DisputeEvidence, sk: &SigningKey) {
        d.signature = s32_signing_envelope(sk, &d.agreement_hash);
        let bytes = dispute_evidence_canonical_bytes(d).expect("canonical");
        let digest = Sha256::digest(&bytes);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&digest);
        let sig: Signature = sk.sign_prehash(&arr).expect("sign");
        let sig = sig.normalize_s().unwrap_or(sig);
        d.signature.signature = hex::encode(sig.to_bytes());
    }

    fn s32_sign_resolution(d: &mut DisputeResolution, sk: &SigningKey) {
        d.signature = s32_signing_envelope(sk, &d.agreement_hash);
        let bytes = dispute_resolution_canonical_bytes(d).expect("canonical");
        let digest = Sha256::digest(&bytes);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&digest);
        let sig: Signature = sk.sign_prehash(&arr).expect("sign");
        let sig = sig.normalize_s().unwrap_or(sig);
        d.signature.signature = hex::encode(sig.to_bytes());
    }

    fn s32_sign_registration(r: &mut ResolverRegistration, sk: &SigningKey) {
        r.signature = s32_signing_envelope(sk, "");
        let bytes = resolver_registration_canonical_bytes(r).expect("canonical");
        let digest = Sha256::digest(&bytes);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&digest);
        let sig: Signature = sk.sign_prehash(&arr).expect("sign");
        let sig = sig.normalize_s().unwrap_or(sig);
        r.signature.signature = hex::encode(sig.to_bytes());
    }

    fn s32_otc_with_resolver(buyer: &str, seller: &str, primary_resolver: Option<&str>) -> AgreementObject {
        let buyer_party = irium_node_rs::settlement::AgreementParty {
            party_id: "buyer".to_string(),
            display_name: "Buyer".to_string(),
            address: buyer.to_string(),
            role: Some("buyer".to_string()),
        };
        let seller_party = irium_node_rs::settlement::AgreementParty {
            party_id: "seller".to_string(),
            display_name: "Seller".to_string(),
            address: seller.to_string(),
            role: Some("seller".to_string()),
        };
        let mut a = irium_node_rs::settlement::build_otc_agreement(
            "otc-3-2-1".to_string(),
            1_700_000_000,
            buyer_party,
            seller_party,
            500_000_000,
            "IRM".to_string(),
            "off-chain".to_string(),
            120,
            "ab".repeat(32),
            "cd".repeat(32),
            None,
            None,
        )
        .expect("build_otc");
        if let Some(addr) = primary_resolver {
            a.primary_resolver = Some(addr.to_string());
            a.primary_resolver_fee = Some(1_000_000);
        }
        a
    }

    fn s32_make_raise(agreement: &AgreementObject, raising_party: &str, sk: &SigningKey) -> DisputeRaise {
        let agreement_hash = compute_agreement_hash_hex(agreement).expect("hash");
        let mut d = DisputeRaise {
            version: irium_node_rs::settlement::DISPUTE_RAISE_VERSION,
            schema_id: Some(irium_node_rs::settlement::DISPUTE_RAISE_SCHEMA_ID.to_string()),
            agreement_hash,
            raising_party: raising_party.to_string(),
            raised_at_height: 100,
            raised_at_unix: 1_700_000_500,
            reason: "buyer paid but seller refused release".to_string(),
            initial_evidence_hash: "bb".repeat(32),
            signature: s32_signing_envelope(sk, ""),
        };
        s32_sign_raise(&mut d, sk);
        d
    }

    fn s32_make_evidence(agreement: &AgreementObject, submitter: &str, sk: &SigningKey) -> DisputeEvidence {
        let agreement_hash = compute_agreement_hash_hex(agreement).expect("hash");
        let mut d = DisputeEvidence {
            version: irium_node_rs::settlement::DISPUTE_EVIDENCE_VERSION,
            schema_id: Some(irium_node_rs::settlement::DISPUTE_EVIDENCE_SCHEMA_ID.to_string()),
            agreement_hash,
            submitter_party: submitter.to_string(),
            submitted_at_height: 110,
            evidence_type: "payment_proof".to_string(),
            evidence_payload: "BASE64DATA".to_string(),
            evidence_hash: "cc".repeat(32),
            message: None,
            signature: s32_signing_envelope(sk, ""),
        };
        s32_sign_evidence(&mut d, sk);
        d
    }

    fn s32_make_resolution(
        agreement: &AgreementObject,
        role: &str,
        sk: &SigningKey,
        outcome: &str,
    ) -> DisputeResolution {
        let agreement_hash = compute_agreement_hash_hex(agreement).expect("hash");
        let mut d = DisputeResolution {
            version: irium_node_rs::settlement::DISPUTE_RESOLUTION_VERSION,
            schema_id: Some(irium_node_rs::settlement::DISPUTE_RESOLUTION_SCHEMA_ID.to_string()),
            agreement_hash,
            resolver_address: s32_test_addr(sk),
            resolver_role: role.to_string(),
            outcome: outcome.to_string(),
            resolved_at_height: 200,
            message: "resolved by primary".to_string(),
            signature: s32_signing_envelope(sk, ""),
        };
        s32_sign_resolution(&mut d, sk);
        d
    }

    fn s32_make_registration(sk: &SigningKey, fee_bps: Option<u32>) -> ResolverRegistration {
        let mut r = ResolverRegistration {
            version: irium_node_rs::settlement::RESOLVER_REGISTRATION_VERSION,
            schema_id: Some(irium_node_rs::settlement::RESOLVER_REGISTRATION_SCHEMA_ID.to_string()),
            resolver_address: s32_test_addr(sk),
            registered_at_height: 10,
            display_name: Some("Test Resolver".to_string()),
            bio: None,
            fee_bps_self_quoted: fee_bps,
            signature: s32_signing_envelope(sk, ""),
        };
        s32_sign_registration(&mut r, sk);
        r
    }

    fn s32_add_wallet_utxos_multi(state: &AppState, address: &str, count: usize, value_each: u64) {
        let pkh_vec = base58_p2pkh_to_hash(address).expect("addr decode");
        let mut pkh20 = [0u8; 20];
        pkh20.copy_from_slice(&pkh_vec);
        let mut chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let tip = chain.tip_height();
        for i in 0..count {
            let mut txid = [0xAAu8; 32];
            txid[31] = i as u8;
            chain.utxos.insert(
                OutPoint {
                    txid,
                    index: 0,
                },
                UtxoEntry {
                    output: TxOutput {
                        value: value_each,
                        script_pubkey: p2pkh_script(&pkh20),
                    },
                    height: tip,
                    is_coinbase: false,
                },
            );
        }
    }

    fn s32_stub_eligibility(
        agreement_hash: &str,
        agreement_id: &str,
        eligible: bool,
        branch: &str,
    ) -> AgreementSpendEligibilityResponse {
        AgreementSpendEligibilityResponse {
            agreement_hash: agreement_hash.to_string(),
            agreement_id: agreement_id.to_string(),
            funding_txid: "ff".repeat(32),
            htlc_vout: Some(0),
            anchor_vout: Some(1),
            role: Some(AgreementAnchorRole::Funding),
            milestone_id: None,
            amount: Some(100),
            branch: branch.to_string(),
            htlc_backed: true,
            funded: true,
            unspent: true,
            preimage_required: branch == "release",
            timeout_height: Some(120),
            timeout_reached: branch == "refund",
            destination_address: Some("Qdest".to_string()),
            expected_hash: Some("11".repeat(32)),
            recipient_address: Some("Qrcpt".to_string()),
            refund_address: Some("Qrfd".to_string()),
            eligible,
            reasons: Vec::new(),
            trust_model_note: String::new(),
        }
    }

    // ---- Direct-helper unit tests (no RPC, no wallet) ----

    #[test]
    fn s32_eligibility_hook_blocks_release_when_open() {
        let (state, _, _, _) = create_test_state(Some(0));
        let buyer = s32_test_sk(11);
        let seller = s32_test_sk(12);
        let buyer_addr = s32_test_addr(&buyer);
        let seller_addr = s32_test_addr(&seller);
        let agreement = s32_otc_with_resolver(&buyer_addr, &seller_addr, None);
        let agreement_hash = compute_agreement_hash_hex(&agreement).unwrap();
        let raise = s32_make_raise(&agreement, "buyer", &buyer);
        let dstate = DisputeState {
            raise,
            raise_anchor_txid: None,
            raise_anchored_at_height: None,
            evidence: Vec::new(),
            resolution: None,
            resolution_anchor_txid: None,
            resolution_anchored_at_height: None,
            escalated_to_fallback: false,
            escalated_at_height: None,
        reresolve_nomination: None,
        };
        {
            let mut guard = state.disputes_index.lock().unwrap();
            guard.insert(agreement_hash.clone(), dstate);
        }
        let mut resp = s32_stub_eligibility(&agreement_hash, &agreement.agreement_id, true, "release");
        apply_dispute_status_to_eligibility(&state, &agreement, true, &mut resp);
        assert!(!resp.eligible);
        assert!(resp.reasons.iter().any(|r| r == "dispute_open"));
    }

    #[test]
    fn s32_eligibility_hook_blocks_refund_when_open() {
        let (state, _, _, _) = create_test_state(Some(0));
        let buyer = s32_test_sk(13);
        let seller = s32_test_sk(14);
        let buyer_addr = s32_test_addr(&buyer);
        let seller_addr = s32_test_addr(&seller);
        let agreement = s32_otc_with_resolver(&buyer_addr, &seller_addr, None);
        let agreement_hash = compute_agreement_hash_hex(&agreement).unwrap();
        let raise = s32_make_raise(&agreement, "seller", &seller);
        let dstate = DisputeState {
            raise,
            raise_anchor_txid: None,
            raise_anchored_at_height: None,
            evidence: Vec::new(),
            resolution: None,
            resolution_anchor_txid: None,
            resolution_anchored_at_height: None,
            escalated_to_fallback: false,
            escalated_at_height: None,
        reresolve_nomination: None,
        };
        {
            let mut guard = state.disputes_index.lock().unwrap();
            guard.insert(agreement_hash.clone(), dstate);
        }
        let mut resp = s32_stub_eligibility(&agreement_hash, &agreement.agreement_id, true, "refund");
        apply_dispute_status_to_eligibility(&state, &agreement, false, &mut resp);
        assert!(!resp.eligible);
        assert!(resp.reasons.iter().any(|r| r == "dispute_open"));
    }

    #[test]
    fn s32_eligibility_hook_resolved_release_blocks_refund_branch() {
        let (state, _, _, _) = create_test_state(Some(0));
        let buyer = s32_test_sk(15);
        let seller = s32_test_sk(16);
        let resolver = s32_test_sk(17);
        let buyer_addr = s32_test_addr(&buyer);
        let seller_addr = s32_test_addr(&seller);
        let resolver_addr = s32_test_addr(&resolver);
        let agreement = s32_otc_with_resolver(&buyer_addr, &seller_addr, Some(&resolver_addr));
        let agreement_hash = compute_agreement_hash_hex(&agreement).unwrap();
        let raise = s32_make_raise(&agreement, "buyer", &buyer);
        let resolution = s32_make_resolution(&agreement, "primary", &resolver, "release");
        let dstate = DisputeState {
            raise,
            raise_anchor_txid: Some("aa".repeat(32)),
            raise_anchored_at_height: Some(10),
            evidence: Vec::new(),
            resolution: Some(resolution),
            resolution_anchor_txid: Some("bb".repeat(32)),
            resolution_anchored_at_height: Some(20),
            escalated_to_fallback: false,
            escalated_at_height: None,
        reresolve_nomination: None,
        };
        {
            let mut guard = state.disputes_index.lock().unwrap();
            guard.insert(agreement_hash.clone(), dstate);
        }
        // Release branch should pass (no dispute block).
        let mut release_resp = s32_stub_eligibility(&agreement_hash, &agreement.agreement_id, true, "release");
        apply_dispute_status_to_eligibility(&state, &agreement, true, &mut release_resp);
        assert!(release_resp.eligible);
        // Refund branch should be blocked.
        let mut refund_resp = s32_stub_eligibility(&agreement_hash, &agreement.agreement_id, true, "refund");
        apply_dispute_status_to_eligibility(&state, &agreement, false, &mut refund_resp);
        assert!(!refund_resp.eligible);
        assert!(refund_resp.reasons.iter().any(|r| r == "dispute_resolution_blocks_branch"));
    }

    #[test]
    fn s32_eligibility_hook_resolved_refund_blocks_release_branch() {
        let (state, _, _, _) = create_test_state(Some(0));
        let buyer = s32_test_sk(18);
        let seller = s32_test_sk(19);
        let resolver = s32_test_sk(20);
        let buyer_addr = s32_test_addr(&buyer);
        let seller_addr = s32_test_addr(&seller);
        let resolver_addr = s32_test_addr(&resolver);
        let agreement = s32_otc_with_resolver(&buyer_addr, &seller_addr, Some(&resolver_addr));
        let agreement_hash = compute_agreement_hash_hex(&agreement).unwrap();
        let raise = s32_make_raise(&agreement, "seller", &seller);
        let resolution = s32_make_resolution(&agreement, "primary", &resolver, "refund");
        let dstate = DisputeState {
            raise,
            raise_anchor_txid: Some("aa".repeat(32)),
            raise_anchored_at_height: Some(10),
            evidence: Vec::new(),
            resolution: Some(resolution),
            resolution_anchor_txid: Some("bb".repeat(32)),
            resolution_anchored_at_height: Some(20),
            escalated_to_fallback: false,
            escalated_at_height: None,
        reresolve_nomination: None,
        };
        {
            let mut guard = state.disputes_index.lock().unwrap();
            guard.insert(agreement_hash.clone(), dstate);
        }
        let mut refund_resp = s32_stub_eligibility(&agreement_hash, &agreement.agreement_id, true, "refund");
        apply_dispute_status_to_eligibility(&state, &agreement, false, &mut refund_resp);
        assert!(refund_resp.eligible);
        let mut release_resp = s32_stub_eligibility(&agreement_hash, &agreement.agreement_id, true, "release");
        apply_dispute_status_to_eligibility(&state, &agreement, true, &mut release_resp);
        assert!(!release_resp.eligible);
        assert!(release_resp.reasons.iter().any(|r| r == "dispute_resolution_blocks_branch"));
    }

    #[tokio::test]
    async fn s32_escalation_tick_marks_fallback_after_window() {
        let (state, _, _, _) = create_test_state(Some(0));
        let buyer = s32_test_sk(21);
        let seller = s32_test_sk(22);
        let buyer_addr = s32_test_addr(&buyer);
        let seller_addr = s32_test_addr(&seller);
        let agreement = s32_otc_with_resolver(&buyer_addr, &seller_addr, None);
        let agreement_hash = compute_agreement_hash_hex(&agreement).unwrap();
        let raise = s32_make_raise(&agreement, "buyer", &buyer);
        let dstate = DisputeState {
            raise,
            raise_anchor_txid: Some("aa".repeat(32)),
            raise_anchored_at_height: Some(10),
            evidence: Vec::new(),
            resolution: None,
            resolution_anchor_txid: None,
            resolution_anchored_at_height: None,
            escalated_to_fallback: false,
            escalated_at_height: None,
        reresolve_nomination: None,
        };
        {
            let mut guard = state.disputes_index.lock().unwrap();
            guard.insert(agreement_hash.clone(), dstate);
        }
        // Tip exactly 288 blocks past raise → triggers escalation.
        escalation_tick(&state.disputes_index, &state.event_tx, &None, 10 + 288).await;
        let guard = state.disputes_index.lock().unwrap();
        let d = guard.get(&agreement_hash).expect("present");
        assert!(d.escalated_to_fallback);
        assert_eq!(d.escalated_at_height, Some(298));
    }

    #[tokio::test]
    async fn s32_escalation_tick_no_escalation_within_window() {
        let (state, _, _, _) = create_test_state(Some(0));
        let buyer = s32_test_sk(23);
        let seller = s32_test_sk(24);
        let buyer_addr = s32_test_addr(&buyer);
        let seller_addr = s32_test_addr(&seller);
        let agreement = s32_otc_with_resolver(&buyer_addr, &seller_addr, None);
        let agreement_hash = compute_agreement_hash_hex(&agreement).unwrap();
        let raise = s32_make_raise(&agreement, "buyer", &buyer);
        let dstate = DisputeState {
            raise,
            raise_anchor_txid: Some("aa".repeat(32)),
            raise_anchored_at_height: Some(10),
            evidence: Vec::new(),
            resolution: None,
            resolution_anchor_txid: None,
            resolution_anchored_at_height: None,
            escalated_to_fallback: false,
            escalated_at_height: None,
        reresolve_nomination: None,
        };
        {
            let mut guard = state.disputes_index.lock().unwrap();
            guard.insert(agreement_hash.clone(), dstate);
        }
        // Tip only 200 blocks past raise — under 288 → no escalation.
        escalation_tick(&state.disputes_index, &state.event_tx, &None, 210).await;
        let guard = state.disputes_index.lock().unwrap();
        let d = guard.get(&agreement_hash).expect("present");
        assert!(!d.escalated_to_fallback);
    }

    #[tokio::test]
    async fn s32_resolvers_list_paginates() {
        let (state, _, _, _) = create_test_state(Some(0));
        for i in 0..3u8 {
            let sk = s32_test_sk(40 + i);
            let mut reg = s32_make_registration(&sk, Some(100 * (i as u32 + 1)));
            reg.registered_at_height = 1000 + i as u64;
            let rec = ResolverRegistrationRecord {
                registration: reg,
                anchor_txid: Some(format!("{:0>64}", i)),
                anchored_at_height: Some(1000 + i as u64),
            };
            let mut guard = state.resolvers_index.lock().unwrap();
            guard.insert(rec.registration.resolver_address.clone(), rec);
        }
        let resp1 = resolvers_list(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Query(ResolversListQuery {
                limit: Some(2),
                cursor: None,
            }),
        )
        .await
        .expect("list1")
        .0;
        assert_eq!(resp1.resolvers.len(), 2);
        assert!(resp1.next_cursor.is_some());
        let cursor = resp1.next_cursor.clone().unwrap();
        let resp2 = resolvers_list(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            Query(ResolversListQuery {
                limit: Some(2),
                cursor: Some(cursor),
            }),
        )
        .await
        .expect("list2")
        .0;
        assert_eq!(resp2.resolvers.len(), 1);
        assert!(resp2.next_cursor.is_none());
    }

    // ---- Full-handler RPC tests (real wallet + UTXOs) ----

    #[tokio::test]
    async fn s32_raise_dispute_happy_path() {
        let (state, sender, _, _) = create_test_state(Some(0));
        s32_add_wallet_utxos_multi(&state, &sender, 3, 100_000_000);
        let buyer = s32_test_sk(50);
        let seller = s32_test_sk(51);
        let buyer_addr = s32_test_addr(&buyer);
        let seller_addr = s32_test_addr(&seller);
        let agreement = s32_otc_with_resolver(&buyer_addr, &seller_addr, None);
        let dispute = s32_make_raise(&agreement, "buyer", &buyer);
        let agreement_hash = dispute.agreement_hash.clone();
        let resp = raise_dispute(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            AxumJson(RaiseDisputeRequest {
                dispute,
                agreement: agreement.clone(),
            }),
        )
        .await
        .expect("raise_dispute")
        .0;
        assert_eq!(resp.agreement_hash, agreement_hash);
        assert!(!resp.anchor_txid.is_empty());
        let guard = state.disputes_index.lock().unwrap();
        let d = guard.get(&agreement_hash).expect("present");
        assert!(d.is_open());
        assert_eq!(d.raise.raising_party, "buyer");
    }

    #[tokio::test]
    async fn s32_raise_dispute_rejects_invalid_signature() {
        let (state, sender, _, _) = create_test_state(Some(0));
        s32_add_wallet_utxos_multi(&state, &sender, 3, 100_000_000);
        let buyer = s32_test_sk(52);
        let wrong = s32_test_sk(53);
        let seller = s32_test_sk(54);
        let buyer_addr = s32_test_addr(&buyer);
        let seller_addr = s32_test_addr(&seller);
        let agreement = s32_otc_with_resolver(&buyer_addr, &seller_addr, None);
        // Sign with the WRONG key.
        let dispute = s32_make_raise(&agreement, "buyer", &wrong);
        let result = raise_dispute(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            AxumJson(RaiseDisputeRequest {
                dispute,
                agreement,
            }),
        )
        .await;
        let (status, msg) = result.expect_err("should reject");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(msg.contains("signature"), "got: {msg}");
    }

    #[tokio::test]
    async fn s32_raise_dispute_rejects_non_party_raiser() {
        let (state, sender, _, _) = create_test_state(Some(0));
        s32_add_wallet_utxos_multi(&state, &sender, 3, 100_000_000);
        let buyer = s32_test_sk(55);
        let seller = s32_test_sk(56);
        let buyer_addr = s32_test_addr(&buyer);
        let seller_addr = s32_test_addr(&seller);
        let agreement = s32_otc_with_resolver(&buyer_addr, &seller_addr, None);
        // raising_party set to non-existent id "other".
        let dispute = s32_make_raise(&agreement, "other", &buyer);
        let result = raise_dispute(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            AxumJson(RaiseDisputeRequest {
                dispute,
                agreement,
            }),
        )
        .await;
        let (status, msg) = result.expect_err("should reject");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(msg.contains("raising_party_not_in_agreement"), "got: {msg}");
    }

    #[tokio::test]
    async fn s32_raise_dispute_rejects_deposit_template() {
        let (state, sender, _, _) = create_test_state(Some(0));
        s32_add_wallet_utxos_multi(&state, &sender, 3, 100_000_000);
        let payer = s32_test_sk(57);
        let payee = s32_test_sk(58);
        let payer_addr = s32_test_addr(&payer);
        let payee_addr = s32_test_addr(&payee);
        let payer_party = irium_node_rs::settlement::AgreementParty {
            party_id: "payer".to_string(),
            display_name: "Payer".to_string(),
            address: payer_addr.clone(),
            role: Some("payer".to_string()),
        };
        let payee_party = irium_node_rs::settlement::AgreementParty {
            party_id: "payee".to_string(),
            display_name: "Payee".to_string(),
            address: payee_addr.clone(),
            role: Some("payee".to_string()),
        };
        let agreement = irium_node_rs::settlement::build_deposit_agreement(
            "dep-3-2-1".to_string(),
            1_700_000_000,
            payer_party,
            payee_party,
            500_000_000,
            "purpose".to_string(),
            "refundable".to_string(),
            120,
            "ab".repeat(32),
            "cd".repeat(32),
            None,
            None,
        )
        .expect("build_deposit");
        let dispute = s32_make_raise(&agreement, "payer", &payer);
        let result = raise_dispute(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            AxumJson(RaiseDisputeRequest {
                dispute,
                agreement,
            }),
        )
        .await;
        let (status, msg) = result.expect_err("should reject");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(msg.contains("dispute_template_not_eligible"), "got: {msg}");
    }

    #[tokio::test]
    async fn s32_raise_dispute_rejects_duplicate() {
        let (state, sender, _, _) = create_test_state(Some(0));
        s32_add_wallet_utxos_multi(&state, &sender, 3, 100_000_000);
        let buyer = s32_test_sk(59);
        let seller = s32_test_sk(60);
        let buyer_addr = s32_test_addr(&buyer);
        let seller_addr = s32_test_addr(&seller);
        let agreement = s32_otc_with_resolver(&buyer_addr, &seller_addr, None);
        let dispute1 = s32_make_raise(&agreement, "buyer", &buyer);
        raise_dispute(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            AxumJson(RaiseDisputeRequest {
                dispute: dispute1,
                agreement: agreement.clone(),
            }),
        )
        .await
        .expect("first raise");
        let dispute2 = s32_make_raise(&agreement, "seller", &seller);
        let result = raise_dispute(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            AxumJson(RaiseDisputeRequest {
                dispute: dispute2,
                agreement,
            }),
        )
        .await;
        let (status, msg) = result.expect_err("should reject duplicate");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(msg.contains("dispute_already_open"), "got: {msg}");
    }

    #[tokio::test]
    async fn s32_dispute_evidence_appends_to_open_dispute() {
        let (state, sender, _, _) = create_test_state(Some(0));
        s32_add_wallet_utxos_multi(&state, &sender, 5, 100_000_000);
        let buyer = s32_test_sk(61);
        let seller = s32_test_sk(62);
        let buyer_addr = s32_test_addr(&buyer);
        let seller_addr = s32_test_addr(&seller);
        let agreement = s32_otc_with_resolver(&buyer_addr, &seller_addr, None);
        let dispute = s32_make_raise(&agreement, "buyer", &buyer);
        raise_dispute(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            AxumJson(RaiseDisputeRequest {
                dispute,
                agreement: agreement.clone(),
            }),
        )
        .await
        .expect("raise");
        let evidence = s32_make_evidence(&agreement, "seller", &seller);
        let agreement_hash = evidence.agreement_hash.clone();
        let resp = submit_dispute_evidence(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            AxumJson(SubmitDisputeEvidenceRequest {
                evidence,
                agreement,
            }),
        )
        .await
        .expect("evidence")
        .0;
        assert!(!resp.anchor_txid.is_empty());
        let guard = state.disputes_index.lock().unwrap();
        let d = guard.get(&agreement_hash).expect("present");
        assert_eq!(d.evidence.len(), 1);
        assert_eq!(d.evidence[0].evidence.submitter_party, "seller");
    }

    #[tokio::test]
    async fn s32_dispute_evidence_rejects_when_no_open_dispute() {
        let (state, sender, _, _) = create_test_state(Some(0));
        s32_add_wallet_utxos_multi(&state, &sender, 3, 100_000_000);
        let buyer = s32_test_sk(63);
        let seller = s32_test_sk(64);
        let buyer_addr = s32_test_addr(&buyer);
        let seller_addr = s32_test_addr(&seller);
        let agreement = s32_otc_with_resolver(&buyer_addr, &seller_addr, None);
        let evidence = s32_make_evidence(&agreement, "buyer", &buyer);
        let result = submit_dispute_evidence(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            AxumJson(SubmitDisputeEvidenceRequest {
                evidence,
                agreement,
            }),
        )
        .await;
        let (status, msg) = result.expect_err("should reject");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(msg.contains("no_open_dispute"), "got: {msg}");
    }

    #[tokio::test]
    async fn s32_resolve_dispute_primary_release_recorded() {
        let (state, sender, _, _) = create_test_state(Some(0));
        s32_add_wallet_utxos_multi(&state, &sender, 5, 100_000_000);
        let buyer = s32_test_sk(65);
        let seller = s32_test_sk(66);
        let resolver = s32_test_sk(67);
        let buyer_addr = s32_test_addr(&buyer);
        let seller_addr = s32_test_addr(&seller);
        let resolver_addr = s32_test_addr(&resolver);
        let agreement = s32_otc_with_resolver(&buyer_addr, &seller_addr, Some(&resolver_addr));
        let dispute = s32_make_raise(&agreement, "buyer", &buyer);
        raise_dispute(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            AxumJson(RaiseDisputeRequest {
                dispute,
                agreement: agreement.clone(),
            }),
        )
        .await
        .expect("raise");
        let resolution = s32_make_resolution(&agreement, "primary", &resolver, "release");
        let agreement_hash = resolution.agreement_hash.clone();
        let resp = resolve_dispute(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            AxumJson(ResolveDisputeRequest {
                resolution,
                agreement,
            }),
        )
        .await
        .expect("resolve")
        .0;
        assert_eq!(resp.outcome, "release");
        assert_eq!(resp.resolver_role, "primary");
        let guard = state.disputes_index.lock().unwrap();
        let d = guard.get(&agreement_hash).expect("present");
        assert!(!d.is_open());
        assert_eq!(d.resolution.as_ref().unwrap().outcome, "release");
    }

    #[tokio::test]
    async fn s32_resolve_dispute_rejects_unknown_resolver() {
        let (state, sender, _, _) = create_test_state(Some(0));
        s32_add_wallet_utxos_multi(&state, &sender, 5, 100_000_000);
        let buyer = s32_test_sk(68);
        let seller = s32_test_sk(69);
        let resolver = s32_test_sk(70);
        let attacker = s32_test_sk(71);
        let buyer_addr = s32_test_addr(&buyer);
        let seller_addr = s32_test_addr(&seller);
        let resolver_addr = s32_test_addr(&resolver);
        let agreement = s32_otc_with_resolver(&buyer_addr, &seller_addr, Some(&resolver_addr));
        let dispute = s32_make_raise(&agreement, "buyer", &buyer);
        raise_dispute(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            AxumJson(RaiseDisputeRequest {
                dispute,
                agreement: agreement.clone(),
            }),
        )
        .await
        .expect("raise");
        // Build resolution signed by attacker (not the named resolver).
        let resolution = s32_make_resolution(&agreement, "primary", &attacker, "release");
        let result = resolve_dispute(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            AxumJson(ResolveDisputeRequest {
                resolution,
                agreement,
            }),
        )
        .await;
        let (status, msg) = result.expect_err("should reject");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(msg.contains("resolver_address_mismatch"), "got: {msg}");
    }

    #[tokio::test]
    async fn s32_resolve_dispute_rejects_fallback_before_escalation() {
        let (state, sender, _, _) = create_test_state(Some(0));
        s32_add_wallet_utxos_multi(&state, &sender, 5, 100_000_000);
        let buyer = s32_test_sk(72);
        let seller = s32_test_sk(73);
        let primary = s32_test_sk(74);
        let fallback = s32_test_sk(75);
        let buyer_addr = s32_test_addr(&buyer);
        let seller_addr = s32_test_addr(&seller);
        let primary_addr = s32_test_addr(&primary);
        let fallback_addr = s32_test_addr(&fallback);
        let mut agreement = s32_otc_with_resolver(&buyer_addr, &seller_addr, Some(&primary_addr));
        agreement.fallback_resolver = Some(fallback_addr.clone());
        agreement.fallback_resolver_fee = Some(500_000);
        let dispute = s32_make_raise(&agreement, "buyer", &buyer);
        raise_dispute(
            ConnectInfo(test_socket()),
            State(state.clone()),
            HeaderMap::new(),
            AxumJson(RaiseDisputeRequest {
                dispute,
                agreement: agreement.clone(),
            }),
        )
        .await
        .expect("raise");
        // Fallback tries to resolve without escalation having occurred.
        let resolution = s32_make_resolution(&agreement, "fallback", &fallback, "release");
        let result = resolve_dispute(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            AxumJson(ResolveDisputeRequest {
                resolution,
                agreement,
            }),
        )
        .await;
        let (status, msg) = result.expect_err("should reject");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(msg.contains("fallback_not_yet_escalated"), "got: {msg}");
    }

    #[tokio::test]
    async fn s32_register_resolver_rejects_non_miner() {
        let (state, sender, _, _) = create_test_state(Some(0));
        s32_add_wallet_utxos_multi(&state, &sender, 3, 100_000_000);
        // chain.chain is empty in tests → no coinbase → not a recent miner.
        let resolver = s32_test_sk(80);
        let registration = s32_make_registration(&resolver, Some(500));
        let result = register_resolver(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            AxumJson(RegisterResolverRequest { registration }),
        )
        .await;
        let (status, msg) = result.expect_err("should reject");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(msg.contains("resolver_not_recent_miner"), "got: {msg}");
    }

    /// Regression for the size-estimator bug fixed in claim_btc_swap and
    /// fill_swap_order. Before the 2-pass recalc, those handlers computed
    /// fee = estimate_tx_size(1, 1) * fee_per_byte = 192 sats at fpb=1,
    /// but the actual serialized tx — with the heavy claim or fill
    /// witness — is several times larger. The handler-produced tx was
    /// then rejected by the production mempool (min_fee_per_byte=100.0).
    /// This test asserts the property the fix delivers: a tx whose
    /// declared fee equals serialize().len() * 1 IS admitted.
    #[test]
    fn mempool_admits_claim_shaped_tx_when_fee_matches_serialized_size() {
        // Mimic a real claim_btc_swap output: one input carrying the
        // ~720-byte claim witness, one P2PKH output. Concrete witness
        // bytes don't need to be meaningful — only the size matters for
        // mempool admission. (Consensus validation isn't exercised here;
        // mempool admission is governed by raw fee/size ratio.)
        let witness = vec![0u8; 720];
        let tx = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: [0xa1u8; 32],
                prev_index: 0,
                script_sig: witness,
                sequence: 0xffff_fffe,
            }],
            outputs: vec![TxOutput {
                value: 100_000,
                script_pubkey: p2pkh_script(&[0u8; 20]),
            }],
            locktime: 0,
        };
        let raw = tx.serialize();
        let size = raw.len() as u64;

        let path = unique_path("mempool_claim_admit", "json");
        let mut mempool = MempoolManager::new(path.clone(), 100, 1.0, 0);

        // Correct fee = size * 1 satisfies min_fee_per_byte=1.0.
        let res = mempool.add_transaction(tx.clone(), raw.clone(), size);
        assert!(
            res.is_ok(),
            "expected admission at correct fee={} for size={}: {:?}",
            size,
            size,
            res
        );

        let _ = std::fs::remove_file(path);
    }

    /// Regression — confirms the bug shape. Before the 2-pass fix, the
    /// handlers passed estimate_tx_size(1, 1) (= 192 sats at fpb=1) as
    /// the fee for a tx whose real size is much larger. Mempool then
    /// rejects the tx because fee/size < min_fee_per_byte. This test
    /// makes that rejection explicit so a future regression that
    /// reintroduces the estimator-only path will fail loudly.
    #[test]
    fn mempool_rejects_claim_shaped_tx_at_buggy_estimate_only_fee() {
        let witness = vec![0u8; 720];
        let tx = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: [0xa2u8; 32], // distinct so the prior test's
                prev_index: 0,           // entry doesn't collide
                script_sig: witness,
                sequence: 0xffff_fffe,
            }],
            outputs: vec![TxOutput {
                value: 100_000,
                script_pubkey: p2pkh_script(&[0u8; 20]),
            }],
            locktime: 0,
        };
        let raw = tx.serialize();
        let real_size = raw.len() as u64;

        // The buggy fee the handlers used before the fix.
        let buggy_fee = estimate_tx_size(1, 1);
        assert!(
            buggy_fee < real_size,
            "test inputs are not representative: estimate {} should be \
             much less than actual {}",
            buggy_fee,
            real_size
        );

        let path = unique_path("mempool_claim_reject", "json");
        let mut mempool = MempoolManager::new(path.clone(), 100, 1.0, 0);

        let res = mempool.add_transaction(tx.clone(), raw.clone(), buggy_fee);
        assert!(
            res.is_err(),
            "expected rejection at buggy fee={} on size={} tx",
            buggy_fee,
            real_size
        );

        let _ = std::fs::remove_file(path);
    }

    // ============================================================================
    // Unified wallet RPC tests (Commit 1)
    // ============================================================================

    /// Construct a minimal AppState whose wallet manager points at a
    /// caller-supplied path. Skips the full chain/mempool setup that
    /// `create_test_state` does; these wallet tests only exercise the
    /// wallet-side handlers.
    fn make_wallet_app_state(wallet_path: PathBuf) -> AppState {
        // Bare minimum chain (needed because AppState requires it).
        let locked = load_locked_genesis().expect("genesis");
        let block = block_from_locked(&locked).expect("block_from_locked");
        let params = ChainParams {
            genesis_block: block,
            pow_limit: irium_node_rs::pow::Target { bits: 0x1d00_ffff },
            htlcv1_activation_height: None,
            mpsov1_activation_height: None,
            lwma: irium_node_rs::chain::LwmaParams::new(
                None,
                irium_node_rs::pow::Target { bits: 0x1d00_ffff },
            ),
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
        let chain = Arc::new(Mutex::new(ChainState::new(params)));
        let mempool_path = unique_path("irium_wallet_test_mempool", "json");
        let mempool = Arc::new(Mutex::new(MempoolManager::new(mempool_path, 256, 0.0, 0)));
        let wallet = Arc::new(Mutex::new(WalletManager::new(wallet_path)));

        AppState {
            chain,
            genesis_hash: "00".repeat(32),
            mempool,
            wallet,
            anchors: None,
            p2p: None,
            limiter: Arc::new(Mutex::new(rate_limiter())),
            status_height_cache: Arc::new(AtomicU64::new(0)),
            status_peer_count_cache: Arc::new(AtomicUsize::new(0)),
            status_sybil_cache: Arc::new(AtomicU8::new(0)),
            status_persisted_height_cache: Arc::new(AtomicU64::new(0)),
            status_persist_queue_cache: Arc::new(AtomicUsize::new(0)),
            status_persisted_contiguous_cache: Arc::new(AtomicU64::new(0)),
            status_persisted_max_on_disk_cache: Arc::new(AtomicU64::new(0)),
            status_quarantine_count_cache: Arc::new(AtomicU64::new(0)),
            status_persisted_window_tip_cache: Arc::new(AtomicU64::new(0)),
            status_missing_persisted_in_window_cache: Arc::new(AtomicU64::new(0)),
            status_missing_or_mismatch_in_window_cache: Arc::new(AtomicU64::new(0)),
            status_expected_hash_coverage_in_window_cache: Arc::new(AtomicU64::new(0)),
            status_expected_hash_window_span_cache: Arc::new(AtomicU64::new(0)),
            status_best_header_hash_cache: Arc::new(Mutex::new(String::new())),
            proof_store: Arc::new(Mutex::new(ProofStore::new(unique_path(
                "irium_proofs_wallet",
                "json",
            )))),
            policy_store: Arc::new(Mutex::new(PolicyStore::new(unique_path(
                "irium_policies_wallet",
                "json",
            )))),
            event_tx: tokio::sync::broadcast::channel::<std::sync::Arc<String>>(
                WS_BROADCAST_CAPACITY,
            )
            .0,
            proof_heights: Arc::new(Mutex::new(std::collections::HashMap::new())),
            disputes_index: Arc::new(Mutex::new(std::collections::HashMap::new())),
            resolvers_index: Arc::new(Mutex::new(std::collections::HashMap::new())),
            btc_template_headers_cache: Arc::new(Mutex::new(None)),
            ltc_template_headers_cache: Arc::new(Mutex::new(None)),
            }
    }

    /// Empty headers; with IRIUM_RPC_TOKEN unset (which
    /// `ensure_rpc_token_env` enforces) the require_rpc_auth path
    /// short-circuits to Ok and these tests don't need to fabricate
    /// a Bearer token. Matches the convention used by the
    /// dispute/proof RPC tests in this same file via
    /// `create_test_state`.
    fn auth_headers() -> HeaderMap {
        HeaderMap::new()
    }

    fn ensure_rpc_token_env() {
        std::env::remove_var("IRIUM_RPC_TOKEN");
    }

    fn write_legacy_plaintext_at(path: &PathBuf) {
        let plain_json = serde_json::json!({
            "version": 1,
            "seed_hex": null,
            "bip32_seed": "01".repeat(64),
            "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "next_index": 1,
            "keys": [],
        });
        std::fs::write(path, serde_json::to_string_pretty(&plain_json).unwrap()).unwrap();
    }

    #[tokio::test]
    async fn wallet_info_reports_none_when_no_file() {
        ensure_rpc_token_env();
        let path = unique_path("walletinfo_none", "json");
        let state = make_wallet_app_state(path.clone());
        let resp = wallet_info(
            ConnectInfo(test_socket()),
            State(state),
            auth_headers(),
        )
        .await
        .expect("Ok");
        let body = resp.0;
        assert!(!body.exists);
        assert_eq!(body.mode, WalletMode::None);
        assert!(!body.is_unlocked);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn wallet_info_reports_plaintext_when_legacy_file_present() {
        ensure_rpc_token_env();
        let path = unique_path("walletinfo_plain", "json");
        write_legacy_plaintext_at(&path);
        let state = make_wallet_app_state(path.clone());
        let resp = wallet_info(
            ConnectInfo(test_socket()),
            State(state),
            auth_headers(),
        )
        .await
        .expect("Ok");
        assert!(resp.0.exists);
        assert_eq!(resp.0.mode, WalletMode::Plaintext);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn wallet_info_reports_encrypted_after_create() {
        ensure_rpc_token_env();
        let path = unique_path("walletinfo_enc", "json");
        let state = make_wallet_app_state(path.clone());
        // Use create_with_seed directly on the wallet to set up state.
        {
            let mut w = state.wallet.lock().unwrap_or_else(|e| e.into_inner());
            w.create_with_seed("p", None).expect("create");
        }
        let resp = wallet_info(
            ConnectInfo(test_socket()),
            State(state),
            auth_headers(),
        )
        .await
        .expect("Ok");
        assert_eq!(resp.0.mode, WalletMode::Encrypted);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn wallet_unlock_returns_409_on_plaintext_file() {
        ensure_rpc_token_env();
        let path = unique_path("walletunlock_plain", "json");
        write_legacy_plaintext_at(&path);
        let state = make_wallet_app_state(path.clone());
        let result = wallet_unlock(
            ConnectInfo(test_socket()),
            State(state),
            auth_headers(),
            AxumJson(WalletUnlockRequest {
                passphrase: "irrelevant".to_string(),
            }),
        )
        .await;
        let status = result.err().expect("must error");
        assert_eq!(status, StatusCode::CONFLICT);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn wallet_migrate_to_encrypted_succeeds_on_plaintext() {
        ensure_rpc_token_env();
        let path = unique_path("walletmigrate_ok", "json");
        write_legacy_plaintext_at(&path);
        let state = make_wallet_app_state(path.clone());
        let resp = wallet_migrate_to_encrypted(
            ConnectInfo(test_socket()),
            State(state.clone()),
            auth_headers(),
            AxumJson(WalletMigrateRequest {
                passphrase: "new-pass".to_string(),
            }),
        )
        .await
        .expect("Ok");
        assert_eq!(resp.0.mode, WalletMode::Encrypted);
        // wallet_info should now report encrypted+unlocked
        let info = wallet_info(
            ConnectInfo(test_socket()),
            State(state.clone()),
            auth_headers(),
        )
        .await
        .expect("Ok");
        assert_eq!(info.0.mode, WalletMode::Encrypted);
        assert!(info.0.is_unlocked);
        let _ = std::fs::remove_file(&path);
        // Cleanup the backup
        let parent = path.parent().unwrap();
        if let Ok(dir) = std::fs::read_dir(parent) {
            for e in dir.flatten() {
                let n = e.file_name().to_string_lossy().to_string();
                if n.contains(".plaintext.bak.") {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
    }

    #[tokio::test]
    async fn wallet_migrate_to_encrypted_returns_409_on_already_encrypted() {
        ensure_rpc_token_env();
        let path = unique_path("walletmigrate_conflict", "json");
        let state = make_wallet_app_state(path.clone());
        {
            let mut w = state.wallet.lock().unwrap_or_else(|e| e.into_inner());
            w.create_with_seed("first", None).expect("create");
        }
        let result = wallet_migrate_to_encrypted(
            ConnectInfo(test_socket()),
            State(state),
            auth_headers(),
            AxumJson(WalletMigrateRequest {
                passphrase: "second".to_string(),
            }),
        )
        .await;
        assert_eq!(result.err().unwrap(), StatusCode::CONFLICT);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn wallet_recover_from_seed_succeeds_when_no_wallet_exists() {
        ensure_rpc_token_env();
        let path = unique_path("walletrecover_ok", "json");
        let state = make_wallet_app_state(path.clone());
        let resp = wallet_recover_from_seed(
            ConnectInfo(test_socket()),
            State(state),
            auth_headers(),
            AxumJson(WalletRecoverRequest {
                seed_hex: "ab".repeat(32),
                passphrase: "p".to_string(),
                allow_overwrite: false,
            }),
        )
        .await
        .expect("Ok");
        assert!(!resp.0.address.is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn wallet_recover_from_seed_returns_409_when_wallet_exists_without_overwrite() {
        ensure_rpc_token_env();
        let path = unique_path("walletrecover_conflict", "json");
        let state = make_wallet_app_state(path.clone());
        {
            let mut w = state.wallet.lock().unwrap_or_else(|e| e.into_inner());
            w.create_with_seed("first", None).expect("create");
        }
        let result = wallet_recover_from_seed(
            ConnectInfo(test_socket()),
            State(state),
            auth_headers(),
            AxumJson(WalletRecoverRequest {
                seed_hex: "cd".repeat(32),
                passphrase: "second".to_string(),
                allow_overwrite: false,
            }),
        )
        .await;
        assert_eq!(result.err().unwrap(), StatusCode::CONFLICT);
        let _ = std::fs::remove_file(&path);
    }

    // wallet_send send_max tests. Each one builds a fresh AppState via
    // create_test_state, parks a single UTXO on the sender address, then
    // exercises wallet_send with send_max in various shapes.

    #[tokio::test]
    async fn wallet_send_send_max_drains_address_with_floored_fee() {
        std::env::remove_var("IRIUM_RPC_TOKEN");
        let (state, sender, recipient, _refund) = create_test_state(None);
        // 1 IRM = 100_000_000 sats. With one input + one output the size
        // estimate is 10 + 148 + 34 = 192 bytes; at fee_per_byte=1 the raw
        // fee (192 sat) is below the 10_000 sat floor, so fee must be 10_000.
        add_wallet_utxo(&state, &sender, 100_000_000);

        let req = WalletSendRequest {
            to_address: recipient.clone(),
            amount: None,
            from_address: Some(sender.clone()),
            fee_mode: None,
            fee_per_byte: Some(1),
            coin_select: None,
            send_max: Some(true),
        };
        let resp = wallet_send(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            AxumJson(req),
        )
        .await
        .expect("wallet_send")
        .0;

        assert!(resp.accepted);
        assert_eq!(resp.fee, 10_000);
        assert_eq!(resp.total_input, 100_000_000);
        assert_eq!(resp.change, 0);
    }

    #[tokio::test]
    async fn wallet_send_send_max_uses_actual_fee_when_above_floor() {
        std::env::remove_var("IRIUM_RPC_TOKEN");
        let (state, sender, recipient, _refund) = create_test_state(None);
        add_wallet_utxo(&state, &sender, 100_000_000);

        // fee_per_byte=100 → at least 100 * 192 = 19_200 sat, comfortably
        // above the 10_000 sat floor. The 2-pass loop may bump this if the
        // actual signed size differs, so we assert >= 19_200 not ==.
        let req = WalletSendRequest {
            to_address: recipient.clone(),
            amount: None,
            from_address: Some(sender.clone()),
            fee_mode: None,
            fee_per_byte: Some(100),
            coin_select: None,
            send_max: Some(true),
        };
        let resp = wallet_send(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            AxumJson(req),
        )
        .await
        .expect("wallet_send")
        .0;

        assert!(resp.accepted);
        assert!(resp.fee >= 19_200, "fee {} should clear raw estimate", resp.fee);
        assert_eq!(resp.total_input, 100_000_000);
        assert_eq!(resp.change, 0);
        // amount = total - fee; no change output.
        assert!(resp.fee <= 100_000_000);
    }

    #[tokio::test]
    async fn wallet_send_send_max_rejects_when_balance_below_fee_floor() {
        std::env::remove_var("IRIUM_RPC_TOKEN");
        let (state, sender, recipient, _refund) = create_test_state(None);
        // 5 000 sats is below the 10 000 sat send_max fee floor.
        add_wallet_utxo(&state, &sender, 5_000);

        let req = WalletSendRequest {
            to_address: recipient.clone(),
            amount: None,
            from_address: Some(sender.clone()),
            fee_mode: None,
            fee_per_byte: Some(1),
            coin_select: None,
            send_max: Some(true),
        };
        let result = wallet_send(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            AxumJson(req),
        )
        .await;

        let err = result.err().expect("expected error");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        let body = err.1.0;
        assert_eq!(body.get("error").and_then(|v| v.as_str()), Some("insufficient_funds_for_fee"));
    }

    #[tokio::test]
    async fn wallet_send_send_max_returns_no_spendable_utxos_when_empty() {
        std::env::remove_var("IRIUM_RPC_TOKEN");
        let (state, sender, recipient, _refund) = create_test_state(None);
        // Intentionally no UTXOs added.

        let req = WalletSendRequest {
            to_address: recipient.clone(),
            amount: None,
            from_address: Some(sender.clone()),
            fee_mode: None,
            fee_per_byte: Some(1),
            coin_select: None,
            send_max: Some(true),
        };
        let result = wallet_send(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            AxumJson(req),
        )
        .await;

        let err = result.err().expect("expected error");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        let body = err.1.0;
        // wallet_send rejects at the empty-UTXO step before reaching the
        // send_max branch when from_address has nothing in chain.utxos.
        let reason = body.get("error").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            reason == "no_utxos" || reason == "no_spendable_utxos",
            "unexpected error: {}",
            reason
        );
    }

    #[tokio::test]
    async fn wallet_send_without_send_max_requires_amount() {
        std::env::remove_var("IRIUM_RPC_TOKEN");
        let (state, sender, recipient, _refund) = create_test_state(None);
        add_wallet_utxo(&state, &sender, 100_000_000);

        let req = WalletSendRequest {
            to_address: recipient.clone(),
            amount: None,
            from_address: Some(sender.clone()),
            fee_mode: None,
            fee_per_byte: Some(1),
            coin_select: None,
            send_max: None,
        };
        let result = wallet_send(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            AxumJson(req),
        )
        .await;

        let err = result.err().expect("expected error");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        let body = err.1.0;
        assert_eq!(body.get("error").and_then(|v| v.as_str()), Some("missing_amount"));
    }

    #[tokio::test]
    async fn wallet_send_without_send_max_preserves_existing_behaviour() {
        std::env::remove_var("IRIUM_RPC_TOKEN");
        let (state, sender, recipient, _refund) = create_test_state(None);
        // 1 IRM available; send 0.5 IRM and expect change > 0.
        add_wallet_utxo(&state, &sender, 100_000_000);

        let req = WalletSendRequest {
            to_address: recipient.clone(),
            amount: Some("0.50000000".to_string()),
            from_address: Some(sender.clone()),
            fee_mode: None,
            fee_per_byte: Some(1),
            coin_select: None,
            send_max: None,
        };
        let resp = wallet_send(
            ConnectInfo(test_socket()),
            State(state),
            HeaderMap::new(),
            AxumJson(req),
        )
        .await
        .expect("wallet_send")
        .0;

        assert!(resp.accepted);
        assert_eq!(resp.total_input, 100_000_000);
        // Change goes back to sender (it's the change_address when from_address is set).
        assert!(resp.change > 0, "expected change output, got {}", resp.change);
        // Standard fee_per_byte=1 with no floor: tiny fee (~250 sat range).
        assert!(resp.fee < 10_000, "non-send_max fee should not be floored: {}", resp.fee);
    }
}


// ============================================================================
// Stage 3.2: Dispute and Resolver System
// ============================================================================

fn iriumd_disputes_dir() -> std::path::PathBuf {
    storage::state_dir().join("iriumd_disputes")
}

fn iriumd_resolvers_dir() -> std::path::PathBuf {
    storage::state_dir().join("iriumd_resolvers")
}

fn dispute_state_path(agreement_hash: &str) -> std::path::PathBuf {
    iriumd_disputes_dir().join(format!("{}.json", agreement_hash))
}

fn resolver_record_path(addr: &str) -> std::path::PathBuf {
    iriumd_resolvers_dir().join(format!("{}.json", addr))
}

fn save_json_atomic<T: Serialize>(path: &std::path::Path, value: &T) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create dir {}: {}", parent.display(), e))?;
    }
    let pid = std::process::id();
    let tmp = path.with_extension(format!("json.tmp.{}", pid));
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| format!("serialize: {}", e))?;
    std::fs::write(&tmp, &bytes).map_err(|e| format!("write tmp: {}", e))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("rename: {}", e))?;
    Ok(())
}

fn save_dispute_state(state: &DisputeState) -> Result<(), String> {
    let path = dispute_state_path(&state.raise.agreement_hash);
    save_json_atomic(&path, state)
}

fn save_resolver_record(rec: &ResolverRegistrationRecord) -> Result<(), String> {
    let path = resolver_record_path(&rec.registration.resolver_address);
    save_json_atomic(&path, rec)
}

fn load_all_disputes_at_startup() -> std::collections::HashMap<String, DisputeState> {
    let dir = iriumd_disputes_dir();
    let mut out = std::collections::HashMap::new();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("[disputes] failed to read {}: {}", path.display(), e);
                continue;
            }
        };
        match serde_json::from_slice::<DisputeState>(&bytes) {
            Ok(state) => {
                out.insert(state.raise.agreement_hash.clone(), state);
            }
            Err(e) => {
                eprintln!("[disputes] failed to parse {}: {}", path.display(), e);
            }
        }
    }
    out
}

fn load_all_resolvers_at_startup() -> std::collections::HashMap<String, ResolverRegistrationRecord>
{
    let dir = iriumd_resolvers_dir();
    let mut out = std::collections::HashMap::new();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if let Ok(rec) = serde_json::from_slice::<ResolverRegistrationRecord>(&bytes) {
            out.insert(rec.registration.resolver_address.clone(), rec);
        }
    }
    out
}

fn address_is_recent_miner(chain: &ChainState, address: &str) -> bool {
    let Some(pkh_vec) = base58_p2pkh_to_hash(address) else {
        return false;
    };
    if pkh_vec.len() != 20 {
        return false;
    }
    let mut target = [0u8; 20];
    target.copy_from_slice(&pkh_vec);
    let tip = chain.tip_height();
    let start = tip.saturating_sub(MINER_RECENCY_WINDOW);
    for h in start..=tip {
        let Some(block) = chain.chain.get(h as usize) else {
            continue;
        };
        let Some(coinbase) = block.transactions.first() else {
            continue;
        };
        for out in &coinbase.outputs {
            if let Some(out_pkh) = p2pkh_hash_from_script(&out.script_pubkey) {
                if out_pkh == target {
                    return true;
                }
            }
        }
    }
    false
}

/// Apply dispute status to an eligibility response. If a dispute is open,
/// mark not-eligible with reason "dispute_open". If a dispute is resolved,
/// block the branch that does not match the resolved outcome with reason
/// "dispute_resolution_blocks_branch".
fn apply_dispute_status_to_eligibility(
    state: &AppState,
    agreement: &AgreementObject,
    claim: bool,
    resp: &mut AgreementSpendEligibilityResponse,
) {
    let Ok(agreement_hash) = compute_agreement_hash_hex(agreement) else {
        return;
    };
    let dispute = {
        let guard = state.disputes_index.lock().unwrap_or_else(|e| e.into_inner());
        guard.get(&agreement_hash).cloned()
    };
    let Some(d) = dispute else {
        return;
    };
    if d.is_open() {
        resp.eligible = false;
        if !resp.reasons.iter().any(|r| r == "dispute_open") {
            resp.reasons.push("dispute_open".to_string());
        }
        return;
    }
    if let Some(ref resolution) = d.resolution {
        let want_release = resolution.outcome == "release";
        let want_refund = resolution.outcome == "refund";
        let branch_allowed = (claim && want_release) || (!claim && want_refund);
        if !branch_allowed {
            resp.eligible = false;
            if !resp
                .reasons
                .iter()
                .any(|r| r == "dispute_resolution_blocks_branch")
            {
                resp.reasons
                    .push("dispute_resolution_blocks_branch".to_string());
            }
        }
    }
}

/// Build, sign, and (optionally) broadcast a transaction that anchors the
/// supplied agreement hash on chain via an OP_RETURN output. Returns the txid
/// hex on success. Mirrors fund_agreement's wallet+utxo+sign+broadcast path.
///
/// GROUP H follow-up: `extra_op_returns` carries additional OP_RETURN outputs
/// (e.g. rep1:s / rep1:w / rep1:l reputation events) that ride alongside the
/// primary agr1: anchor in the same tx. Fee estimate, output count, and the
/// signature digest all include them. Pass `Vec::new()` for the legacy 2-output
/// behaviour (agr1 + change only).
fn build_and_broadcast_anchor_tx(
    state: &AppState,
    agreement_hash: &str,
    role: AgreementAnchorRole,
    extra_op_returns: Vec<TxOutput>,
) -> Result<String, String> {
    let anchor_output = build_agreement_anchor_output(&AgreementAnchor {
        agreement_hash: agreement_hash.to_string(),
        role,
        milestone_id: None,
    })
    .map_err(|e| format!("anchor_payload: {}", e))?;

    let mut key_map: HashMap<[u8; 20], WalletKey> = HashMap::new();
    {
        let mut wallet = state.wallet.lock().unwrap_or_else(|e| e.into_inner());
        let keys = wallet
            .keys()
            .map_err(|_| "wallet_keys_unavailable".to_string())?;
        for key in keys {
            let bytes = hex::decode(&key.pkh).map_err(|_| "wallet_key_pkh_decode_failed".to_string())?;
            if bytes.len() != 20 {
                continue;
            }
            let mut arr = [0u8; 20];
            arr.copy_from_slice(&bytes);
            key_map.insert(arr, key);
        }
    }
    if key_map.is_empty() {
        return Err("wallet_key_map_empty".to_string());
    }

    let (mut utxos, tip_height) = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let mut collected = Vec::new();
        for (outpoint, utxo) in chain.utxos.iter() {
            if let Some(script_pkh) = p2pkh_hash_from_script(&utxo.output.script_pubkey) {
                if key_map.contains_key(&script_pkh) {
                    collected.push(WalletUtxo {
                        outpoint: outpoint.clone(),
                        output: utxo.output.clone(),
                        height: utxo.height,
                        is_coinbase: utxo.is_coinbase,
                        pkh: script_pkh,
                    });
                }
            }
        }
        (collected, chain.tip_height())
    };
    if utxos.is_empty() {
        return Err("wallet_utxo_set_empty".to_string());
    }
    utxos.sort_by(|a, b| a.output.value.cmp(&b.output.value));

    let fee_per_byte = DISPUTE_ANCHOR_FEE_PER_BYTE;
    // Tx layout: 1 input + (1 agr1 anchor + N rep1 extras + 1 change) outputs.
    let num_outputs = 2 + extra_op_returns.len();
    let estimated_fee = estimate_tx_size(1, num_outputs).saturating_mul(fee_per_byte);

    let mut chosen: Option<WalletUtxo> = None;
    for utxo in &utxos {
        let confirmations = tip_height.saturating_sub(utxo.height);
        if utxo.is_coinbase && confirmations < coinbase_maturity() {
            continue;
        }
        if utxo.output.value > estimated_fee {
            chosen = Some(utxo.clone());
            break;
        }
    }
    let utxo = chosen.ok_or_else(|| "insufficient_spendable_funds_or_immature_coinbase".to_string())?;

    let change_value = utxo.output.value.saturating_sub(estimated_fee);
    let mut outputs = vec![anchor_output];
    for extra in extra_op_returns {
        outputs.push(extra);
    }
    outputs.push(TxOutput {
        value: change_value,
        script_pubkey: p2pkh_script(&utxo.pkh),
    });

    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid: utxo.outpoint.txid,
            prev_index: utxo.outpoint.index,
            script_sig: Vec::new(),
            sequence: 0xffff_ffff,
        }],
        outputs,
        locktime: 0,
    };

    // Sign the input.
    let priv_bytes = hex::decode(&utxo.pkh_key_priv(&key_map)?)
        .map_err(|_| "wallet_priv_decode".to_string())?;
    if priv_bytes.len() != 32 {
        return Err("wallet_priv_len".to_string());
    }
    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(&priv_bytes);
    let signing_key =
        SigningKey::from_bytes((&sk_arr).into()).map_err(|_| "signing_key".to_string())?;
    let pubkey_bytes = signing_key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    let scriptcode = p2pkh_script(&utxo.pkh);
    let digest = signature_digest(&tx, 0, &scriptcode);
    let sig: Signature = signing_key
        .sign_prehash(&digest)
        .map_err(|_| "sign_prehash".to_string())?;
    let sig = sig.normalize_s().unwrap_or(sig);
    let mut sig_bytes = sig.to_der().as_bytes().to_vec();
    sig_bytes.push(0x01);
    let mut script_sig: Vec<u8> = Vec::with_capacity(2 + sig_bytes.len() + pubkey_bytes.len());
    script_sig.push(sig_bytes.len() as u8);
    script_sig.extend_from_slice(&sig_bytes);
    script_sig.push(pubkey_bytes.len() as u8);
    script_sig.extend_from_slice(&pubkey_bytes);
    tx.inputs[0].script_sig = script_sig;

    // Validate fee then submit to mempool.
    let raw = tx.serialize();
    let txid = tx.txid();
    let txid_hex = hex::encode(txid);
    let fee = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain
            .calculate_fees(&tx)
            .map_err(|e| format!("fee_validate: {}", e))?
    };
    {
        let mut mp = state.mempool.lock().unwrap_or_else(|e| e.into_inner());
        let _ = mp.add_transaction(tx.clone(), raw.clone(), fee);
    }
    // Best-effort P2P broadcast.
    if let Some(ref node) = state.p2p {
        let node = node.clone();
        let raw_bytes = raw.clone();
        tokio::spawn(async move {
            let _ = node.broadcast_tx(&raw_bytes).await;
        });
    }
    Ok(txid_hex)
}

/// GROUP H follow-up: build, sign, and broadcast a standalone reputation-
/// event tx. No agr1 anchor; the rep1 outputs (typically just one rep1:n)
/// are the only OP_RETURN outputs. Used by the resolver_non_response flow
/// where the carrying tx is a pure reputation event, not part of a
/// release / refund / disputeresolve flow.
fn build_and_broadcast_rep_event_tx(
    state: &AppState,
    rep_outputs: Vec<TxOutput>,
) -> Result<String, String> {
    if rep_outputs.is_empty() {
        return Err("rep_outputs_empty".to_string());
    }
    let mut key_map: HashMap<[u8; 20], WalletKey> = HashMap::new();
    {
        let mut wallet = state.wallet.lock().unwrap_or_else(|e| e.into_inner());
        let keys = wallet
            .keys()
            .map_err(|_| "wallet_keys_unavailable".to_string())?;
        for key in keys {
            let bytes = hex::decode(&key.pkh)
                .map_err(|_| "wallet_key_pkh_decode_failed".to_string())?;
            if bytes.len() != 20 {
                continue;
            }
            let mut arr = [0u8; 20];
            arr.copy_from_slice(&bytes);
            key_map.insert(arr, key);
        }
    }
    if key_map.is_empty() {
        return Err("wallet_key_map_empty".to_string());
    }
    let (mut utxos, tip_height) = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        let mut collected = Vec::new();
        for (outpoint, utxo) in chain.utxos.iter() {
            if let Some(script_pkh) = p2pkh_hash_from_script(&utxo.output.script_pubkey) {
                if key_map.contains_key(&script_pkh) {
                    collected.push(WalletUtxo {
                        outpoint: outpoint.clone(),
                        output: utxo.output.clone(),
                        height: utxo.height,
                        is_coinbase: utxo.is_coinbase,
                        pkh: script_pkh,
                    });
                }
            }
        }
        (collected, chain.tip_height())
    };
    if utxos.is_empty() {
        return Err("wallet_utxo_set_empty".to_string());
    }
    utxos.sort_by(|a, b| a.output.value.cmp(&b.output.value));
    let fee_per_byte = DISPUTE_ANCHOR_FEE_PER_BYTE;
    let num_outputs = rep_outputs.len() + 1; // rep + change
    let estimated_fee = estimate_tx_size(1, num_outputs).saturating_mul(fee_per_byte);
    let mut chosen: Option<WalletUtxo> = None;
    for utxo in &utxos {
        let confirmations = tip_height.saturating_sub(utxo.height);
        if utxo.is_coinbase && confirmations < coinbase_maturity() {
            continue;
        }
        if utxo.output.value > estimated_fee {
            chosen = Some(utxo.clone());
            break;
        }
    }
    let utxo = chosen
        .ok_or_else(|| "insufficient_spendable_funds_or_immature_coinbase".to_string())?;
    let change_value = utxo.output.value.saturating_sub(estimated_fee);
    let mut outputs = rep_outputs;
    outputs.push(TxOutput {
        value: change_value,
        script_pubkey: p2pkh_script(&utxo.pkh),
    });
    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid: utxo.outpoint.txid,
            prev_index: utxo.outpoint.index,
            script_sig: Vec::new(),
            sequence: 0xffff_ffff,
        }],
        outputs,
        locktime: 0,
    };
    let priv_bytes = hex::decode(&utxo.pkh_key_priv(&key_map)?)
        .map_err(|_| "wallet_priv_decode".to_string())?;
    if priv_bytes.len() != 32 {
        return Err("wallet_priv_len".to_string());
    }
    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(&priv_bytes);
    let signing_key =
        SigningKey::from_bytes((&sk_arr).into()).map_err(|_| "signing_key".to_string())?;
    let pubkey_bytes = signing_key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    let scriptcode = p2pkh_script(&utxo.pkh);
    let digest = signature_digest(&tx, 0, &scriptcode);
    let sig: Signature = signing_key
        .sign_prehash(&digest)
        .map_err(|_| "sign_prehash".to_string())?;
    let sig = sig.normalize_s().unwrap_or(sig);
    let mut sig_bytes = sig.to_der().as_bytes().to_vec();
    sig_bytes.push(0x01);
    let mut script_sig: Vec<u8> = Vec::with_capacity(2 + sig_bytes.len() + pubkey_bytes.len());
    script_sig.push(sig_bytes.len() as u8);
    script_sig.extend_from_slice(&sig_bytes);
    script_sig.push(pubkey_bytes.len() as u8);
    script_sig.extend_from_slice(&pubkey_bytes);
    tx.inputs[0].script_sig = script_sig;
    let raw = tx.serialize();
    let txid = tx.txid();
    let txid_hex = hex::encode(txid);
    let fee = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain
            .calculate_fees(&tx)
            .map_err(|e| format!("fee_validate: {}", e))?
    };
    {
        let mut mp = state.mempool.lock().unwrap_or_else(|e| e.into_inner());
        let _ = mp.add_transaction(tx.clone(), raw.clone(), fee);
    }
    if let Some(ref node) = state.p2p {
        let node = node.clone();
        let raw_bytes = raw.clone();
        tokio::spawn(async move {
            let _ = node.broadcast_tx(&raw_bytes).await;
        });
    }
    Ok(txid_hex)
}

trait WalletKeyPrivLookup {
    fn pkh_key_priv(&self, key_map: &HashMap<[u8; 20], WalletKey>) -> Result<String, String>;
}

impl WalletKeyPrivLookup for WalletUtxo {
    fn pkh_key_priv(&self, key_map: &HashMap<[u8; 20], WalletKey>) -> Result<String, String> {
        key_map
            .get(&self.pkh)
            .map(|k| k.privkey.clone())
            .ok_or_else(|| "wallet_key_for_pkh_missing".to_string())
    }
}

/// Compute the payload hash for a DisputeRaise signature. The signature field
/// is zeroed for the hash so signers can compute the same digest before
/// embedding their signature.
fn dispute_raise_payload_hash(d: &DisputeRaise) -> Result<[u8; 32], String> {
    let mut tmp = d.clone();
    tmp.signature.signature = String::new();
    let bytes = dispute_raise_canonical_bytes(&tmp)?;
    let h = Sha256::digest(&bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h);
    Ok(out)
}

fn dispute_evidence_payload_hash(d: &DisputeEvidence) -> Result<[u8; 32], String> {
    let mut tmp = d.clone();
    tmp.signature.signature = String::new();
    let bytes = dispute_evidence_canonical_bytes(&tmp)?;
    let h = Sha256::digest(&bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h);
    Ok(out)
}

fn dispute_resolution_payload_hash(d: &DisputeResolution) -> Result<[u8; 32], String> {
    let mut tmp = d.clone();
    tmp.signature.signature = String::new();
    let bytes = dispute_resolution_canonical_bytes(&tmp)?;
    let h = Sha256::digest(&bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h);
    Ok(out)
}

fn resolver_registration_payload_hash(r: &ResolverRegistration) -> Result<[u8; 32], String> {
    let mut tmp = r.clone();
    tmp.signature.signature = String::new();
    let bytes = resolver_registration_canonical_bytes(&tmp)?;
    let h = Sha256::digest(&bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h);
    Ok(out)
}

fn verify_envelope_signature(
    envelope: &AgreementSignatureEnvelope,
    digest: &[u8; 32],
    expected_address: &str,
) -> Result<(), String> {
    if envelope.signature_type != AGREEMENT_SIGNATURE_TYPE_SECP256K1 {
        return Err(format!(
            "unsupported signature type: {}",
            envelope.signature_type
        ));
    }
    if envelope
        .signer_address
        .as_deref()
        .map(|s| s != expected_address)
        .unwrap_or(true)
    {
        return Err("signer_address_mismatch".to_string());
    }
    let pubkey_bytes = hex::decode(&envelope.signer_public_key)
        .map_err(|_| "signer_public_key_decode".to_string())?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&pubkey_bytes)
        .map_err(|_| "signer_public_key_invalid".to_string())?;
    // Verify pubkey produces the expected address.
    let mut sha = Sha256::new();
    sha.update(&pubkey_bytes);
    let sha_out = sha.finalize();
    let rip = ripemd::Ripemd160::digest(sha_out);
    let mut pkh = [0u8; 20];
    pkh.copy_from_slice(&rip);
    let derived_address = base58_p2pkh_from_hash(&pkh);
    if derived_address != expected_address {
        return Err("pubkey_does_not_match_signer_address".to_string());
    }
    let sig_bytes =
        hex::decode(&envelope.signature).map_err(|_| "signature_decode".to_string())?;
    let parsed = Signature::from_slice(&sig_bytes)
        .map_err(|_| "signature_format".to_string())?;
    verifying_key
        .verify_prehash(digest, &parsed)
        .map_err(|_| "signature_verify_failed".to_string())?;
    Ok(())
}

// ---------- Request/response types ----------

#[derive(Debug, Deserialize)]
struct RaiseDisputeRequest {
    dispute: DisputeRaise,
    agreement: AgreementObject,
}

#[derive(Debug, Serialize)]
struct RaiseDisputeResponse {
    agreement_hash: String,
    anchor_txid: String,
}

#[derive(Debug, Deserialize)]
struct SubmitDisputeEvidenceRequest {
    evidence: DisputeEvidence,
    agreement: AgreementObject,
}

#[derive(Debug, Serialize)]
struct SubmitDisputeEvidenceResponse {
    evidence_hash: String,
    anchor_txid: String,
}

#[derive(Debug, Deserialize)]
struct ResolveDisputeRequest {
    resolution: DisputeResolution,
    agreement: AgreementObject,
}

#[derive(Debug, Serialize)]
struct ResolveDisputeResponse {
    anchor_txid: String,
    outcome: String,
    resolver_role: String,
}

// GROUP H follow-up: payload for the resolver-non-response indictment.
// Any party can submit. iriumd verifies the dispute exists, is still
// open (no resolution anchored), and the resolver's response window
// (DISPUTE_RESOLVER_RESPONSE_WINDOW blocks past the raise anchor)
// has elapsed.
#[derive(Debug, Deserialize)]
struct BroadcastReputationNonResponseRequest {
    resolver_address: String,
    agreement_hash: String,
}

#[derive(Debug, Serialize)]
struct BroadcastReputationNonResponseResponse {
    anchor_txid: String,
    resolver_address: String,
    agreement_hash: String,
}

#[derive(Debug, Deserialize)]
struct RegisterResolverRequest {
    registration: ResolverRegistration,
}

#[derive(Debug, Serialize)]
struct RegisterResolverResponse {
    resolver_address: String,
    anchor_txid: String,
}

#[derive(Debug, Deserialize)]
struct ResolversListQuery {
    limit: Option<usize>,
    cursor: Option<String>,
}

#[derive(Debug, Serialize)]
struct ResolversListEntry {
    resolver_address: String,
    registered_at_height: u64,
    display_name: Option<String>,
    fee_bps_self_quoted: Option<u32>,
    anchor_txid: Option<String>,
    anchored_at_height: Option<u64>,
}

#[derive(Debug, Serialize)]
struct ResolversListResponse {
    resolvers: Vec<ResolversListEntry>,
    next_cursor: Option<String>,
}

// ---------- Handlers ----------

async fn raise_dispute(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<RaiseDisputeRequest>,
) -> Result<Json<RaiseDisputeResponse>, (StatusCode, String)> {
    let bad =
        |reason: &str| -> (StatusCode, String) { (StatusCode::BAD_REQUEST, reason.to_string()) };
    check_rate_with_auth(&state, &addr, &headers)
        .map_err(|sc| (sc, format!("rate_limit_or_auth_failed:{sc}")))?;
    require_rpc_auth(&headers).map_err(|sc| (sc, format!("rpc_auth_failed:{sc}")))?;
    req.dispute.validate().map_err(|e| bad(&e))?;
    req.agreement.validate().map_err(|e| bad(&e))?;
    let agreement_hash =
        compute_agreement_hash_hex(&req.agreement).map_err(|_| bad("agreement_hash_failed"))?;
    if agreement_hash != req.dispute.agreement_hash {
        return Err(bad("dispute_agreement_hash_mismatch"));
    }
    let dispute_eligible = matches!(
        req.agreement.template_type,
        AgreementTemplateType::OtcSettlement
            | AgreementTemplateType::MilestoneSettlement
            | AgreementTemplateType::ContractorMilestone
    );
    if !dispute_eligible {
        return Err(bad("dispute_template_not_eligible"));
    }
    let party = req
        .agreement
        .parties
        .iter()
        .find(|p| p.party_id == req.dispute.raising_party)
        .ok_or_else(|| bad("raising_party_not_in_agreement"))?;
    let digest =
        dispute_raise_payload_hash(&req.dispute).map_err(|e| bad(&format!("payload_hash:{e}")))?;
    verify_envelope_signature(&req.dispute.signature, &digest, &party.address)
        .map_err(|e| bad(&format!("signature:{e}")))?;
    {
        let guard = state.disputes_index.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = guard.get(&agreement_hash) {
            if existing.is_open() {
                return Err(bad("dispute_already_open"));
            }
        }
    }
    let anchor_txid =
        build_and_broadcast_anchor_tx(
            &state,
            &agreement_hash,
            AgreementAnchorRole::DisputeRaise,
            Vec::new(),
        )
        .map_err(|e| bad(&format!("anchor_tx:{e}")))?;
    let new_state = DisputeState {
        raise: req.dispute.clone(),
        raise_anchor_txid: Some(anchor_txid.clone()),
        raise_anchored_at_height: None,
        evidence: Vec::new(),
        resolution: None,
        resolution_anchor_txid: None,
        resolution_anchored_at_height: None,
        escalated_to_fallback: false,
        escalated_at_height: None,
    reresolve_nomination: None,
    };
    save_dispute_state(&new_state).map_err(|e| bad(&format!("persist:{e}")))?;
    {
        let mut guard = state.disputes_index.lock().unwrap_or_else(|e| e.into_inner());
        guard.insert(agreement_hash.clone(), new_state);
    }
    emit_event(
        &state.event_tx,
        "dispute.raised",
        serde_json::json!({
            "agreement_hash": agreement_hash,
            "raising_party": req.dispute.raising_party,
            "anchor_txid": anchor_txid,
        }),
    );
    if let Some(ref node) = state.p2p {
        if let Ok(json) = serde_json::to_string(&req.dispute) {
            let node = node.clone();
            tokio::spawn(async move {
                node.broadcast_dispute_raised(&json).await;
            });
        }
    }
    Ok(Json(RaiseDisputeResponse {
        agreement_hash,
        anchor_txid,
    }))
}

async fn submit_dispute_evidence(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<SubmitDisputeEvidenceRequest>,
) -> Result<Json<SubmitDisputeEvidenceResponse>, (StatusCode, String)> {
    let bad =
        |reason: &str| -> (StatusCode, String) { (StatusCode::BAD_REQUEST, reason.to_string()) };
    check_rate_with_auth(&state, &addr, &headers)
        .map_err(|sc| (sc, format!("rate_limit_or_auth_failed:{sc}")))?;
    require_rpc_auth(&headers).map_err(|sc| (sc, format!("rpc_auth_failed:{sc}")))?;
    req.evidence.validate().map_err(|e| bad(&e))?;
    req.agreement.validate().map_err(|e| bad(&e))?;
    let agreement_hash =
        compute_agreement_hash_hex(&req.agreement).map_err(|_| bad("agreement_hash_failed"))?;
    if agreement_hash != req.evidence.agreement_hash {
        return Err(bad("evidence_agreement_hash_mismatch"));
    }
    let party = req
        .agreement
        .parties
        .iter()
        .find(|p| p.party_id == req.evidence.submitter_party)
        .ok_or_else(|| bad("submitter_party_not_in_agreement"))?;
    let digest = dispute_evidence_payload_hash(&req.evidence)
        .map_err(|e| bad(&format!("payload_hash:{e}")))?;
    verify_envelope_signature(&req.evidence.signature, &digest, &party.address)
        .map_err(|e| bad(&format!("signature:{e}")))?;
    {
        let guard = state.disputes_index.lock().unwrap_or_else(|e| e.into_inner());
        let d = guard.get(&agreement_hash).ok_or_else(|| bad("no_open_dispute"))?;
        if !d.is_open() {
            return Err(bad("dispute_already_resolved"));
        }
    }
    let anchor_txid = build_and_broadcast_anchor_tx(
        &state,
        &agreement_hash,
        AgreementAnchorRole::DisputeEvidence,
        Vec::new(),
    )
    .map_err(|e| bad(&format!("anchor_tx:{e}")))?;
    let evidence_hash = req.evidence.evidence_hash.clone();
    let evidence_record = DisputeEvidenceRecord {
        evidence: req.evidence,
        anchor_txid: Some(anchor_txid.clone()),
        anchored_at_height: None,
    };
    let snapshot = {
        let mut guard = state.disputes_index.lock().unwrap_or_else(|e| e.into_inner());
        let d = guard.get_mut(&agreement_hash).ok_or_else(|| bad("no_open_dispute"))?;
        d.evidence.push(evidence_record);
        d.clone()
    };
    save_dispute_state(&snapshot).map_err(|e| bad(&format!("persist:{e}")))?;
    emit_event(
        &state.event_tx,
        "dispute.evidence_submitted",
        serde_json::json!({
            "agreement_hash": agreement_hash,
            "evidence_hash": evidence_hash,
            "anchor_txid": anchor_txid,
        }),
    );
    if let Some(ref node) = state.p2p {
        let evidence_clone = {
            let guard = state.disputes_index.lock().unwrap_or_else(|e| e.into_inner());
            guard
                .get(&agreement_hash)
                .and_then(|d| d.evidence.last().map(|r| r.evidence.clone()))
        };
        if let Some(ev) = evidence_clone {
            if let Ok(json) = serde_json::to_string(&ev) {
                let node = node.clone();
                tokio::spawn(async move {
                    node.broadcast_dispute_evidence(&json).await;
                });
            }
        }
    }
    Ok(Json(SubmitDisputeEvidenceResponse {
        evidence_hash,
        anchor_txid,
    }))
}

async fn resolve_dispute(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<ResolveDisputeRequest>,
) -> Result<Json<ResolveDisputeResponse>, (StatusCode, String)> {
    let bad =
        |reason: &str| -> (StatusCode, String) { (StatusCode::BAD_REQUEST, reason.to_string()) };
    check_rate_with_auth(&state, &addr, &headers)
        .map_err(|sc| (sc, format!("rate_limit_or_auth_failed:{sc}")))?;
    require_rpc_auth(&headers).map_err(|sc| (sc, format!("rpc_auth_failed:{sc}")))?;
    req.resolution.validate().map_err(|e| bad(&e))?;
    req.agreement.validate().map_err(|e| bad(&e))?;
    let agreement_hash =
        compute_agreement_hash_hex(&req.agreement).map_err(|_| bad("agreement_hash_failed"))?;
    if agreement_hash != req.resolution.agreement_hash {
        return Err(bad("resolution_agreement_hash_mismatch"));
    }
    let role = req.resolution.resolver_role.as_str();
    let (agreement_primary, agreement_fallback) = (
        req.agreement.primary_resolver.clone(),
        req.agreement.fallback_resolver.clone(),
    );
    // Stage 3.4.1: a co-signed reresolve nomination overrides the
    // agreement's named resolvers for this dispute.
    let agreement_hash_for_role = compute_agreement_hash_hex(&req.agreement)
        .map_err(|_| bad("agreement_hash_failed"))?;
    let (effective_primary, effective_fallback) = {
        let guard = state.disputes_index.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(d) = guard.get(&agreement_hash_for_role) {
            if let Some(ref nom) = d.reresolve_nomination {
                (
                    Some(nom.new_primary_resolver.clone()),
                    nom.new_fallback_resolver.clone(),
                )
            } else {
                (agreement_primary.clone(), agreement_fallback.clone())
            }
        } else {
            (agreement_primary.clone(), agreement_fallback.clone())
        }
    };
    let expected_address = match role {
        "primary" => effective_primary
            .ok_or_else(|| bad("agreement_has_no_primary_resolver"))?,
        "fallback" => effective_fallback
            .ok_or_else(|| bad("agreement_has_no_fallback_resolver"))?,
        _ => return Err(bad("invalid_resolver_role")),
    };
    if expected_address != req.resolution.resolver_address {
        return Err(bad("resolver_address_mismatch"));
    }
    let digest = dispute_resolution_payload_hash(&req.resolution)
        .map_err(|e| bad(&format!("payload_hash:{e}")))?;
    verify_envelope_signature(&req.resolution.signature, &digest, &expected_address)
        .map_err(|e| bad(&format!("signature:{e}")))?;
    {
        let guard = state.disputes_index.lock().unwrap_or_else(|e| e.into_inner());
        let d = guard
            .get(&agreement_hash)
            .ok_or_else(|| bad("no_open_dispute"))?;
        if !d.is_open() {
            return Err(bad("dispute_already_resolved"));
        }
        if role == "fallback" && !d.escalated_to_fallback {
            return Err(bad("fallback_not_yet_escalated"));
        }
    }
    // GROUP H follow-up: embed rep1:w + rep1:l reputation events alongside
    // the agr1:x DisputeResolve anchor in the same tx. The resolver knows
    // both parties' addresses from the agreement; the winner is the party
    // who receives funds per outcome ("release" -> payee wins;
    // "refund" -> payer wins).
    let payer_address = req
        .agreement
        .parties
        .iter()
        .find(|p| p.party_id == req.agreement.payer)
        .map(|p| p.address.clone())
        .unwrap_or_default();
    let payee_address = req
        .agreement
        .parties
        .iter()
        .find(|p| p.party_id == req.agreement.payee)
        .map(|p| p.address.clone())
        .unwrap_or_default();
    let (winner_addr, loser_addr) = match req.resolution.outcome.as_str() {
        "release" => (payee_address.clone(), payer_address.clone()),
        "refund" => (payer_address.clone(), payee_address.clone()),
        _ => (String::new(), String::new()),
    };
    let mut rep_outputs: Vec<TxOutput> = Vec::new();
    if !winner_addr.is_empty() {
        if let Ok(out) = build_reputation_event_output(&ReputationEvent {
            kind: ReputationEventKind::DisputeWin,
            address: winner_addr,
            agreement_short_hash: None,
        }) {
            rep_outputs.push(out);
        }
    }
    if !loser_addr.is_empty() {
        if let Ok(out) = build_reputation_event_output(&ReputationEvent {
            kind: ReputationEventKind::DisputeLoss,
            address: loser_addr,
            agreement_short_hash: None,
        }) {
            rep_outputs.push(out);
        }
    }
    let anchor_txid = build_and_broadcast_anchor_tx(
        &state,
        &agreement_hash,
        AgreementAnchorRole::DisputeResolve,
        rep_outputs,
    )
    .map_err(|e| bad(&format!("anchor_tx:{e}")))?;
    let outcome = req.resolution.outcome.clone();
    let resolver_role = req.resolution.resolver_role.clone();
    let snapshot = {
        let mut guard = state.disputes_index.lock().unwrap_or_else(|e| e.into_inner());
        let d = guard.get_mut(&agreement_hash).ok_or_else(|| bad("no_open_dispute"))?;
        d.resolution = Some(req.resolution);
        d.resolution_anchor_txid = Some(anchor_txid.clone());
        d.clone()
    };
    save_dispute_state(&snapshot).map_err(|e| bad(&format!("persist:{e}")))?;
    emit_event(
        &state.event_tx,
        "dispute.resolved",
        serde_json::json!({
            "agreement_hash": agreement_hash,
            "outcome": outcome,
            "resolver_role": resolver_role,
            "anchor_txid": anchor_txid,
        }),
    );
    if let Some(ref node) = state.p2p {
        if let Some(resolution_clone) = snapshot.resolution.clone() {
            if let Ok(json) = serde_json::to_string(&resolution_clone) {
                let node = node.clone();
                tokio::spawn(async move {
                    node.broadcast_dispute_resolved(&json).await;
                });
            }
        }
    }
    Ok(Json(ResolveDisputeResponse {
        anchor_txid,
        outcome,
        resolver_role,
    }))
}

async fn register_resolver(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<RegisterResolverRequest>,
) -> Result<Json<RegisterResolverResponse>, (StatusCode, String)> {
    let bad =
        |reason: &str| -> (StatusCode, String) { (StatusCode::BAD_REQUEST, reason.to_string()) };
    check_rate_with_auth(&state, &addr, &headers)
        .map_err(|sc| (sc, format!("rate_limit_or_auth_failed:{sc}")))?;
    require_rpc_auth(&headers).map_err(|sc| (sc, format!("rpc_auth_failed:{sc}")))?;
    req.registration.validate().map_err(|e| bad(&e))?;
    let digest = resolver_registration_payload_hash(&req.registration)
        .map_err(|e| bad(&format!("payload_hash:{e}")))?;
    verify_envelope_signature(
        &req.registration.signature,
        &digest,
        &req.registration.resolver_address,
    )
    .map_err(|e| bad(&format!("signature:{e}")))?;
    {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        if !address_is_recent_miner(&chain, &req.registration.resolver_address) {
            return Err(bad("resolver_not_recent_miner"));
        }
    }
    let resolver_address = req.registration.resolver_address.clone();
    let anchor_txid = build_and_broadcast_anchor_tx(
        &state,
        &resolver_address,
        AgreementAnchorRole::ResolverRegister,
        Vec::new(),
    )
    .map_err(|e| bad(&format!("anchor_tx:{e}")))?;
    let record = ResolverRegistrationRecord {
        registration: req.registration,
        anchor_txid: Some(anchor_txid.clone()),
        anchored_at_height: None,
    };
    save_resolver_record(&record).map_err(|e| bad(&format!("persist:{e}")))?;
    {
        let mut guard = state.resolvers_index.lock().unwrap_or_else(|e| e.into_inner());
        guard.insert(resolver_address.clone(), record);
    }
    emit_event(
        &state.event_tx,
        "resolver.registered",
        serde_json::json!({
            "resolver_address": resolver_address,
            "anchor_txid": anchor_txid,
        }),
    );
    Ok(Json(RegisterResolverResponse {
        resolver_address,
        anchor_txid,
    }))
}

// GROUP H follow-up: broadcast a standalone rep1:n indictment of a
// resolver who missed the response window for an open dispute. Any
// caller can submit; iriumd validates the dispute exists, has not been
// resolved, and the resolver's response window has elapsed (raise
// height + DISPUTE_RESOLVER_RESPONSE_WINDOW blocks). The named
// resolver must match the dispute's currently effective resolver
// (primary, or fallback if escalated, or the reresolve nominee).
async fn broadcast_reputation_non_response(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<BroadcastReputationNonResponseRequest>,
) -> Result<Json<BroadcastReputationNonResponseResponse>, (StatusCode, String)> {
    let bad =
        |reason: &str| -> (StatusCode, String) { (StatusCode::BAD_REQUEST, reason.to_string()) };
    check_rate_with_auth(&state, &addr, &headers)
        .map_err(|sc| (sc, format!("rate_limit_or_auth_failed:{sc}")))?;
    require_rpc_auth(&headers).map_err(|sc| (sc, format!("rpc_auth_failed:{sc}")))?;
    if req.resolver_address.trim().is_empty() {
        return Err(bad("resolver_address_empty"));
    }
    if req.agreement_hash.len() != 64
        || !req.agreement_hash.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(bad("agreement_hash_invalid"));
    }
    // Look up the dispute and validate state.
    let (raise_height, is_open) = {
        let guard = state.disputes_index.lock().unwrap_or_else(|e| e.into_inner());
        let d = guard
            .get(&req.agreement_hash)
            .ok_or_else(|| bad("dispute_not_found"))?;
        let raise_h = d
            .raise_anchored_at_height
            .ok_or_else(|| bad("dispute_raise_not_anchored"))?;
        (raise_h, d.is_open())
    };
    if !is_open {
        return Err(bad("dispute_already_resolved"));
    }
    // Window check.
    let tip_height = {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        chain.tip_height()
    };
    let deadline = raise_height.saturating_add(DISPUTE_RESOLVER_RESPONSE_WINDOW);
    if tip_height < deadline {
        return Err(bad("response_window_not_elapsed"));
    }
    // Build rep1:n event.
    let short = agreement_short_hash_from_full(&req.agreement_hash)
        .map_err(|_| bad("agreement_short_hash_failed"))?;
    let rep_output = build_reputation_event_output(&ReputationEvent {
        kind: ReputationEventKind::ResolverNonResponse,
        address: req.resolver_address.clone(),
        agreement_short_hash: Some(short),
    })
    .map_err(|e| bad(&format!("rep1_payload:{e}")))?;
    let anchor_txid = build_and_broadcast_rep_event_tx(&state, vec![rep_output])
        .map_err(|e| bad(&format!("anchor_tx:{e}")))?;
    Ok(Json(BroadcastReputationNonResponseResponse {
        anchor_txid,
        resolver_address: req.resolver_address,
        agreement_hash: req.agreement_hash,
    }))
}

async fn resolvers_list(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ResolversListQuery>,
) -> Result<Json<ResolversListResponse>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    let limit = query.limit.unwrap_or(50).min(500);
    let resolvers: Vec<ResolverRegistrationRecord> = {
        let guard = state.resolvers_index.lock().unwrap_or_else(|e| e.into_inner());
        guard.values().cloned().collect()
    };
    let mut sorted = resolvers;
    sorted.sort_by(|a, b| {
        b.registration
            .registered_at_height
            .cmp(&a.registration.registered_at_height)
            .then_with(|| {
                a.registration
                    .resolver_address
                    .cmp(&b.registration.resolver_address)
            })
    });
    let start = match query.cursor {
        Some(cursor) => sorted
            .iter()
            .position(|r| r.registration.resolver_address == cursor)
            .map(|i| i + 1)
            .unwrap_or(0),
        None => 0,
    };
    let page: Vec<&ResolverRegistrationRecord> = sorted.iter().skip(start).take(limit).collect();
    let next_cursor = if start + page.len() < sorted.len() {
        page.last()
            .map(|r| r.registration.resolver_address.clone())
    } else {
        None
    };
    let entries: Vec<ResolversListEntry> = page
        .iter()
        .map(|r| ResolversListEntry {
            resolver_address: r.registration.resolver_address.clone(),
            registered_at_height: r.registration.registered_at_height,
            display_name: r.registration.display_name.clone(),
            fee_bps_self_quoted: r.registration.fee_bps_self_quoted,
            anchor_txid: r.anchor_txid.clone(),
            anchored_at_height: r.anchored_at_height,
        })
        .collect();
    Ok(Json(ResolversListResponse {
        resolvers: entries,
        next_cursor,
    }))
}


// Stage 3.2: scan newly-confirmed blocks for dispute/resolver anchor OP_RETURNs.
fn scan_new_blocks_for_dispute_anchors(
    chain_handle: &Arc<Mutex<ChainState>>,
    disputes: &Arc<Mutex<std::collections::HashMap<String, DisputeState>>>,
    resolvers: &Arc<Mutex<std::collections::HashMap<String, ResolverRegistrationRecord>>>,
    event_tx: &EventTx,
    from_height_exclusive: u64,
    to_height_inclusive: u64,
) {
    let snapshot: Vec<(u64, Vec<Transaction>)> = {
        let g = chain_handle.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = Vec::new();
        let start = from_height_exclusive.saturating_add(1) as usize;
        let end = (to_height_inclusive as usize).min(g.chain.len().saturating_sub(1));
        if start > end {
            return;
        }
        for h in start..=end {
            if let Some(b) = g.chain.get(h) {
                out.push((h as u64, b.transactions.clone()));
            }
        }
        out
    };
    for (height, txs) in snapshot {
        for tx in &txs {
            let txid_hex = hex::encode(tx.txid());
            for out in &tx.outputs {
                let Some(anchor) = parse_agreement_anchor(&out.script_pubkey) else {
                    continue;
                };
                match anchor.role {
                    AgreementAnchorRole::DisputeRaise => {
                        let mut snapshot_to_persist: Option<DisputeState> = None;
                        {
                            let mut guard = disputes.lock().unwrap_or_else(|e| e.into_inner());
                            if let Some(d) = guard.get_mut(&anchor.agreement_hash) {
                                if d.raise_anchored_at_height.is_none() {
                                    d.raise_anchored_at_height = Some(height);
                                    d.raise_anchor_txid = Some(txid_hex.clone());
                                    snapshot_to_persist = Some(d.clone());
                                }
                            }
                        }
                        if let Some(snap) = snapshot_to_persist {
                            let _ = save_dispute_state(&snap);
                            emit_event(
                                event_tx,
                                "dispute.raise_anchored",
                                serde_json::json!({
                                    "agreement_hash": anchor.agreement_hash,
                                    "anchor_txid": txid_hex,
                                    "anchored_at_height": height,
                                }),
                            );
                        }
                    }
                    AgreementAnchorRole::DisputeEvidence => {
                        let mut snapshot_to_persist: Option<DisputeState> = None;
                        {
                            let mut guard = disputes.lock().unwrap_or_else(|e| e.into_inner());
                            if let Some(d) = guard.get_mut(&anchor.agreement_hash) {
                                for rec in d.evidence.iter_mut() {
                                    if rec.anchor_txid.as_deref() == Some(&txid_hex)
                                        && rec.anchored_at_height.is_none()
                                    {
                                        rec.anchored_at_height = Some(height);
                                        snapshot_to_persist = Some(d.clone());
                                        break;
                                    }
                                }
                            }
                        }
                        if let Some(snap) = snapshot_to_persist {
                            let _ = save_dispute_state(&snap);
                        }
                    }
                    AgreementAnchorRole::DisputeResolve => {
                        let mut snapshot_to_persist: Option<DisputeState> = None;
                        {
                            let mut guard = disputes.lock().unwrap_or_else(|e| e.into_inner());
                            if let Some(d) = guard.get_mut(&anchor.agreement_hash) {
                                if d.resolution_anchored_at_height.is_none() {
                                    d.resolution_anchored_at_height = Some(height);
                                    d.resolution_anchor_txid = Some(txid_hex.clone());
                                    snapshot_to_persist = Some(d.clone());
                                }
                            }
                        }
                        if let Some(snap) = snapshot_to_persist {
                            let _ = save_dispute_state(&snap);
                            emit_event(
                                event_tx,
                                "dispute.resolve_anchored",
                                serde_json::json!({
                                    "agreement_hash": anchor.agreement_hash,
                                    "anchor_txid": txid_hex,
                                    "anchored_at_height": height,
                                }),
                            );
                        }
                    }
                    AgreementAnchorRole::ResolverRegister => {
                        let mut snapshot_to_persist: Option<ResolverRegistrationRecord> = None;
                        {
                            let mut guard = resolvers.lock().unwrap_or_else(|e| e.into_inner());
                            for rec in guard.values_mut() {
                                if rec.anchor_txid.as_deref() == Some(&txid_hex)
                                    && rec.anchored_at_height.is_none()
                                {
                                    rec.anchored_at_height = Some(height);
                                    snapshot_to_persist = Some(rec.clone());
                                    break;
                                }
                            }
                        }
                        if let Some(snap) = snapshot_to_persist {
                            let _ = save_resolver_record(&snap);
                        }
                    }
                    // GROUP C: release-role anchors confirming on-chain emit
                    // `agreement.auto_released` so subscribed clients (the
                    // Tauri GUI, the wallet watcher) hear that the
                    // agreement has settled. The same event fires whether
                    // the release was triggered manually or by `irium-wallet
                    // watch --auto-release`; the wallet-side dedupe HashSet
                    // makes repeat events idempotent.
                    AgreementAnchorRole::OtcSettlement
                    | AgreementAnchorRole::MerchantSettlement => {
                        emit_event(
                            event_tx,
                            "agreement.auto_released",
                            serde_json::json!({
                                "agreement_hash": anchor.agreement_hash,
                                "anchor_txid": txid_hex,
                                "anchored_at_height": height,
                                "role": format!("{:?}", anchor.role),
                            }),
                        );
                    }
                    _ => {}
                }
            }
        }
    }
}

// Stage 3.2 + 3.3.1: per-tick escalation check, optionally broadcasting via P2P.
async fn escalation_tick(
    disputes: &Arc<Mutex<std::collections::HashMap<String, DisputeState>>>,
    event_tx: &EventTx,
    p2p: &Option<P2PNode>,
    tip_height: u64,
) {
    let mut to_escalate: Vec<String> = Vec::new();
    {
        let guard = disputes.lock().unwrap_or_else(|e| e.into_inner());
        for (hash, d) in guard.iter() {
            if d.is_open()
                && !d.escalated_to_fallback
                && d.raise_anchored_at_height
                    .map(|h| tip_height >= h.saturating_add(DISPUTE_RESOLVER_RESPONSE_WINDOW))
                    .unwrap_or(false)
            {
                to_escalate.push(hash.clone());
            }
        }
    }
    for hash in to_escalate {
        let snapshot = {
            let mut guard = disputes.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(d) = guard.get_mut(&hash) {
                d.escalated_to_fallback = true;
                d.escalated_at_height = Some(tip_height);
                Some(d.clone())
            } else {
                None
            }
        };
        if let Some(snap) = snapshot {
            let _ = save_dispute_state(&snap);
            emit_event(
                event_tx,
                "dispute.escalated",
                serde_json::json!({
                    "agreement_hash": hash,
                    "escalated_at_height": tip_height,
                }),
            );
            if let Some(ref node) = p2p {
                let body = serde_json::json!({
                    "agreement_hash": hash,
                    "escalated_at_height": tip_height,
                });
                if let Ok(json) = serde_json::to_string(&body) {
                    node.broadcast_dispute_escalated(&json).await;
                }
            }
        }
    }
}


// ============================================================================
// Stage 3.3.1: P2P dispute notification drain — apply incoming peer broadcasts
// to the local disputes_index. The drain task runs every 5 s and consumes the
// four dispute inboxes populated by the P2P receive arms in p2p.rs.
//
// Signature on the inbound payload is still verified (the signer must own the
// pubkey that derives to signer_address), but we cannot enforce party-of-
// agreement membership here because we do not necessarily have the underlying
// agreement object locally. That check fires when a local user later attempts
// to act on the dispute via the wallet (which DOES have the agreement).
// ============================================================================

fn process_received_dispute_raise(
    json: &str,
    disputes: &Arc<Mutex<std::collections::HashMap<String, DisputeState>>>,
    event_tx: &EventTx,
) {
    let d: DisputeRaise = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[dispute-raise drain] parse error: {}", e);
            return;
        }
    };
    if let Err(e) = d.validate() {
        eprintln!("[dispute-raise drain] invalid: {}", e);
        return;
    }
    let signer_addr = match d.signature.signer_address.as_deref() {
        Some(a) => a.to_string(),
        None => {
            eprintln!("[dispute-raise drain] missing signer_address");
            return;
        }
    };
    let digest = match dispute_raise_payload_hash(&d) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("[dispute-raise drain] payload hash: {}", e);
            return;
        }
    };
    if let Err(e) = verify_envelope_signature(&d.signature, &digest, &signer_addr) {
        eprintln!("[dispute-raise drain] sig verify failed: {}", e);
        return;
    }
    let agreement_hash = d.agreement_hash.clone();
    let already_have = {
        let guard = disputes.lock().unwrap_or_else(|e| e.into_inner());
        guard.contains_key(&agreement_hash)
    };
    if already_have {
        return;
    }
    let new_state = DisputeState {
        raise: d,
        raise_anchor_txid: None,
        raise_anchored_at_height: None,
        evidence: Vec::new(),
        resolution: None,
        resolution_anchor_txid: None,
        resolution_anchored_at_height: None,
        escalated_to_fallback: false,
        escalated_at_height: None,
    reresolve_nomination: None,
    };
    let _ = save_dispute_state(&new_state);
    {
        let mut guard = disputes.lock().unwrap_or_else(|e| e.into_inner());
        guard.insert(agreement_hash.clone(), new_state);
    }
    emit_event(
        event_tx,
        "dispute.raised",
        serde_json::json!({
            "agreement_hash": agreement_hash,
            "source": "p2p",
        }),
    );
}

fn process_received_dispute_evidence(
    json: &str,
    disputes: &Arc<Mutex<std::collections::HashMap<String, DisputeState>>>,
    event_tx: &EventTx,
) {
    let e: DisputeEvidence = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("[dispute-evidence drain] parse: {}", err);
            return;
        }
    };
    if let Err(err) = e.validate() {
        eprintln!("[dispute-evidence drain] invalid: {}", err);
        return;
    }
    let signer_addr = match e.signature.signer_address.as_deref() {
        Some(a) => a.to_string(),
        None => return,
    };
    let digest = match dispute_evidence_payload_hash(&e) {
        Ok(h) => h,
        Err(_) => return,
    };
    if verify_envelope_signature(&e.signature, &digest, &signer_addr).is_err() {
        return;
    }
    let agreement_hash = e.agreement_hash.clone();
    let evidence_hash = e.evidence_hash.clone();
    let mut snapshot: Option<DisputeState> = None;
    {
        let mut guard = disputes.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(d) = guard.get_mut(&agreement_hash) {
            if d.is_open()
                && !d.evidence.iter().any(|r| r.evidence.evidence_hash == evidence_hash)
            {
                d.evidence.push(DisputeEvidenceRecord {
                    evidence: e,
                    anchor_txid: None,
                    anchored_at_height: None,
                });
                snapshot = Some(d.clone());
            }
        }
    }
    if let Some(snap) = snapshot {
        let _ = save_dispute_state(&snap);
        emit_event(
            event_tx,
            "dispute.evidence_submitted",
            serde_json::json!({
                "agreement_hash": agreement_hash,
                "evidence_hash": evidence_hash,
                "source": "p2p",
            }),
        );
    }
}

fn process_received_dispute_resolved(
    json: &str,
    disputes: &Arc<Mutex<std::collections::HashMap<String, DisputeState>>>,
    event_tx: &EventTx,
) {
    let r: DisputeResolution = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("[dispute-resolved drain] parse: {}", err);
            return;
        }
    };
    if let Err(err) = r.validate() {
        eprintln!("[dispute-resolved drain] invalid: {}", err);
        return;
    }
    let signer_addr = match r.signature.signer_address.as_deref() {
        Some(a) => a.to_string(),
        None => return,
    };
    let digest = match dispute_resolution_payload_hash(&r) {
        Ok(h) => h,
        Err(_) => return,
    };
    if verify_envelope_signature(&r.signature, &digest, &signer_addr).is_err() {
        return;
    }
    let agreement_hash = r.agreement_hash.clone();
    let outcome = r.outcome.clone();
    let resolver_role = r.resolver_role.clone();
    let mut snapshot: Option<DisputeState> = None;
    {
        let mut guard = disputes.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(d) = guard.get_mut(&agreement_hash) {
            if d.is_open() {
                d.resolution = Some(r);
                snapshot = Some(d.clone());
            }
        }
    }
    if let Some(snap) = snapshot {
        let _ = save_dispute_state(&snap);
        emit_event(
            event_tx,
            "dispute.resolved",
            serde_json::json!({
                "agreement_hash": agreement_hash,
                "outcome": outcome,
                "resolver_role": resolver_role,
                "source": "p2p",
            }),
        );
    }
}

fn process_received_dispute_escalated(
    json: &str,
    disputes: &Arc<Mutex<std::collections::HashMap<String, DisputeState>>>,
    event_tx: &EventTx,
) {
    let v: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return,
    };
    let agreement_hash = match v.get("agreement_hash").and_then(|x| x.as_str()) {
        Some(h) => h.to_string(),
        None => return,
    };
    let escalated_at = v
        .get("escalated_at_height")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let mut snapshot: Option<DisputeState> = None;
    {
        let mut guard = disputes.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(d) = guard.get_mut(&agreement_hash) {
            if d.is_open() && !d.escalated_to_fallback {
                d.escalated_to_fallback = true;
                d.escalated_at_height = Some(escalated_at);
                snapshot = Some(d.clone());
            }
        }
    }
    if let Some(snap) = snapshot {
        let _ = save_dispute_state(&snap);
        emit_event(
            event_tx,
            "dispute.escalated",
            serde_json::json!({
                "agreement_hash": agreement_hash,
                "escalated_at_height": escalated_at,
                "source": "p2p",
            }),
        );
    }
}


// ============================================================================
// Stage 3.4.1: dispute-show + dispute-reresolve handlers
// ============================================================================

#[derive(Deserialize)]
struct DisputeStateQuery {
    agreement_hash: String,
}

#[derive(Serialize)]
struct DisputeStateRpcResp {
    found: bool,
    state: Option<DisputeState>,
}

async fn get_dispute_state(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<DisputeStateQuery>,
) -> Result<Json<DisputeStateRpcResp>, StatusCode> {
    check_rate_with_auth(&state, &addr, &headers)?;
    require_rpc_auth(&headers)?;
    let s = {
        let guard = state.disputes_index.lock().unwrap_or_else(|e| e.into_inner());
        guard.get(&q.agreement_hash).cloned()
    };
    Ok(Json(DisputeStateRpcResp {
        found: s.is_some(),
        state: s,
    }))
}

#[derive(Deserialize)]
struct ReResolveAgreementRequest {
    nomination: DisputeReResolverNomination,
    agreement: AgreementObject,
}

#[derive(Serialize)]
struct ReResolveAgreementResponse {
    agreement_hash: String,
    new_primary_resolver: String,
    new_fallback_resolver: Option<String>,
}

fn dispute_reresolve_payload_hash(
    n: &DisputeReResolverNomination,
) -> Result<[u8; 32], String> {
    let mut tmp = n.clone();
    tmp.party_a_signature.signature = String::new();
    tmp.party_b_signature.signature = String::new();
    let bytes = dispute_reresolve_canonical_bytes(&tmp)?;
    let h = Sha256::digest(&bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h);
    Ok(out)
}

async fn reresolve_agreement(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumJson(req): AxumJson<ReResolveAgreementRequest>,
) -> Result<Json<ReResolveAgreementResponse>, (StatusCode, String)> {
    let bad =
        |reason: &str| -> (StatusCode, String) { (StatusCode::BAD_REQUEST, reason.to_string()) };
    check_rate_with_auth(&state, &addr, &headers)
        .map_err(|sc| (sc, format!("rate_limit_or_auth_failed:{sc}")))?;
    require_rpc_auth(&headers).map_err(|sc| (sc, format!("rpc_auth_failed:{sc}")))?;
    req.nomination.validate().map_err(|e| bad(&e))?;
    req.agreement.validate().map_err(|e| bad(&e))?;
    let agreement_hash =
        compute_agreement_hash_hex(&req.agreement).map_err(|_| bad("agreement_hash_failed"))?;
    if agreement_hash != req.nomination.agreement_hash {
        return Err(bad("reresolve_agreement_hash_mismatch"));
    }
    if req.agreement.parties.len() < 2 {
        return Err(bad("agreement_must_have_two_parties"));
    }
    let party_a_addr = req.agreement.parties[0].address.clone();
    let party_b_addr = req.agreement.parties[1].address.clone();
    let digest = dispute_reresolve_payload_hash(&req.nomination)
        .map_err(|e| bad(&format!("payload_hash:{e}")))?;
    // Both signatures must come from the two named parties (in either order).
    let sa_addr = req
        .nomination
        .party_a_signature
        .signer_address
        .clone()
        .ok_or_else(|| bad("party_a_signature_missing_address"))?;
    let sb_addr = req
        .nomination
        .party_b_signature
        .signer_address
        .clone()
        .ok_or_else(|| bad("party_b_signature_missing_address"))?;
    let pairs = vec![
        (party_a_addr.clone(), party_b_addr.clone()),
        (party_b_addr.clone(), party_a_addr.clone()),
    ];
    let mut pair_valid = false;
    for (a, b) in pairs {
        if sa_addr == a && sb_addr == b
            && verify_envelope_signature(&req.nomination.party_a_signature, &digest, &a).is_ok()
                && verify_envelope_signature(&req.nomination.party_b_signature, &digest, &b)
                    .is_ok()
            {
                pair_valid = true;
                break;
            }
    }
    if !pair_valid {
        return Err(bad("co_signatures_invalid"));
    }
    // Miner-recency check on the new resolvers.
    {
        let chain = state.chain.lock().unwrap_or_else(|e| e.into_inner());
        if !address_is_recent_miner(&chain, &req.nomination.new_primary_resolver) {
            return Err(bad("new_primary_resolver_not_recent_miner"));
        }
        if let Some(ref fb) = req.nomination.new_fallback_resolver {
            if !address_is_recent_miner(&chain, fb) {
                return Err(bad("new_fallback_resolver_not_recent_miner"));
            }
        }
    }
    let new_primary = req.nomination.new_primary_resolver.clone();
    let new_fallback = req.nomination.new_fallback_resolver.clone();
    let snapshot: Option<DisputeState> = {
        let mut guard = state.disputes_index.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(d) = guard.get_mut(&agreement_hash) {
            if !d.is_open() {
                return Err(bad("dispute_already_resolved"));
            }
            d.reresolve_nomination = Some(req.nomination);
            // Reset escalation: the fallback designation now belongs to a
            // new resolver who has not had a chance to respond yet.
            d.escalated_to_fallback = false;
            d.escalated_at_height = None;
            Some(d.clone())
        } else {
            return Err(bad("no_open_dispute"));
        }
    };
    if let Some(snap) = snapshot {
        let _ = save_dispute_state(&snap);
        emit_event(
            &state.event_tx,
            "dispute.reresolved",
            serde_json::json!({
                "agreement_hash": agreement_hash,
                "new_primary_resolver": new_primary,
                "new_fallback_resolver": new_fallback,
            }),
        );
    }
    Ok(Json(ReResolveAgreementResponse {
        agreement_hash,
        new_primary_resolver: new_primary,
        new_fallback_resolver: new_fallback,
    }))
}
