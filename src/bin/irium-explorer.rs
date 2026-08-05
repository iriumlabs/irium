use std::collections::{HashMap, HashSet};
use std::env;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    extract::{ConnectInfo, Form, Path, Query, RawQuery, State},
    http::{
        header::{AUTHORIZATION, CONTENT_DISPOSITION, CONTENT_TYPE},
        HeaderMap, HeaderValue, StatusCode,
    },
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use irium_node_rs::constants::{block_reward, COINBASE_MATURITY};
use irium_node_rs::rate_limiter::RateLimiter;
use irium_node_rs::settlement::{
    build_agreement_artifact_authenticity_verification, build_agreement_artifact_verification,
    build_agreement_share_package_verification, build_agreement_statement, build_deposit_agreement,
    build_milestone_agreement, build_otc_agreement, build_simple_settlement_agreement,
    compute_agreement_bundle_hash_hex, compute_agreement_hash_hex, inspect_agreement_signature,
    parse_agreement_anchor, render_agreement_audit_csv, summarize_agreement_authenticity,
    validate_agreement_signature_envelope, verify_agreement_bundle, verify_agreement_share_package,
    verify_bundle_signatures, AgreementArtifactVerificationResult, AgreementAuditRecord,
    AgreementBundle, AgreementMilestone, AgreementObject, AgreementParty, AgreementSharePackage,
    AgreementSharePackageVerificationResult, AgreementSignatureEnvelope,
    AgreementSignatureVerification, AgreementStatement,
};
use irium_node_rs::tx::decode_full_tx;
use reqwest::Client;
use sha2::{Digest, Sha256};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::RwLock;
use tokio::time::Instant;

#[derive(Clone)]
struct AppState {
    client: Client,
    node_base: String,
    limiter: Arc<Mutex<RateLimiter>>,
    api_token: Option<String>,
    rpc_token: Option<String>,
    miners_cache: Arc<RwLock<MinersCache>>,
    stratum_metrics_url: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct MinersCache {
    active_miners: Option<u64>,
    window_blocks: u64,
    as_of_height: u64,
    updated_at_unix: u64,
    last_error: Option<String>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

#[derive(Deserialize)]
struct UtxoQuery {
    txid: String,
    index: u32,
}

#[derive(Deserialize)]
struct BlocksQuery {
    limit: Option<usize>,
    start: Option<u64>,
}

#[derive(Deserialize)]
struct MiningQuery {
    window: Option<usize>,
    series: Option<usize>,
}

#[derive(Deserialize)]
struct PoolQuery {
    limit: Option<usize>,
    window: Option<u64>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct AgreementHtmlForm {
    agreement_json: String,
    audit_json: Option<String>,
    statement_json: Option<String>,
    share_package_json: Option<String>,
    signature_json: Option<String>,
    agreement_signature_json: Option<String>,
    bundle_signature_json: Option<String>,
    funding_txid: Option<String>,
    htlc_vout: Option<u32>,
    milestone_id: Option<String>,
    destination_address: Option<String>,
    secret_hex: Option<String>,
    agreement_hash: Option<String>,
    lookup_txid: Option<String>,
}

#[derive(Deserialize, Default)]
struct AgreementTemplateForm {
    agreement_id: String,
    creation_time: String,
    party_a: Option<String>,
    party_b: Option<String>,
    buyer: Option<String>,
    seller: Option<String>,
    payer: Option<String>,
    payee: Option<String>,
    amount: Option<String>,
    asset_reference: Option<String>,
    payment_reference: Option<String>,
    purpose_reference: Option<String>,
    release_summary: Option<String>,
    refund_summary: Option<String>,
    settlement_deadline: Option<String>,
    refund_timeout: Option<String>,
    refund_deadline: Option<String>,
    secret_hash: Option<String>,
    document_hash: String,
    metadata_hash: Option<String>,
    notes: Option<String>,
    milestones_text: Option<String>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
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
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

fn build_client(node_base: &str) -> Result<Client, String> {
    let mut builder = Client::builder().timeout(Duration::from_secs(10));
    if let Ok(path) = env::var("IRIUM_RPC_CA") {
        let pem = std::fs::read(&path).map_err(|e| format!("read CA {path}: {e}"))?;
        let cert =
            reqwest::Certificate::from_pem(&pem).map_err(|e| format!("invalid CA {path}: {e}"))?;
        builder = builder.add_root_certificate(cert);
    }
    let insecure = env::var("IRIUM_RPC_INSECURE")
        .ok()
        .map(|v| {
            let v = v.to_lowercase();
            v == "1" || v == "true" || v == "yes"
        })
        .unwrap_or(false);
    if insecure {
        let url = reqwest::Url::parse(node_base)
            .map_err(|e| format!("invalid RPC URL {node_base}: {e}"))?;
        if url.scheme() != "https" {
            eprintln!("[warn] IRIUM_RPC_INSECURE=1 has no effect on non-HTTPS RPC URL");
        } else {
            let host = url
                .host_str()
                .ok_or_else(|| "RPC URL missing host".to_string())?;
            if !is_loopback_host(host) {
                return Err(format!(
                    "Refusing to disable TLS verification for non-local RPC host {host}; set IRIUM_RPC_CA instead"
                ));
            }
            eprintln!("[warn] IRIUM_RPC_INSECURE=1: TLS verification disabled for https://{host}");
            builder = builder.danger_accept_invalid_certs(true);
        }
    }
    builder.build().map_err(|e| format!("build client: {e}"))
}

fn api_authorized(headers: &HeaderMap, token: &Option<String>) -> bool {
    let token = match token {
        Some(t) if !t.is_empty() => t,
        _ => return true,
    };
    let expected = format!("Bearer {}", token);
    let header = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok());
    header == Some(expected.as_str())
}

fn check_rate(state: &AppState, addr: &SocketAddr, headers: &HeaderMap) -> Result<(), StatusCode> {
    if api_authorized(headers, &state.api_token) {
        return Ok(());
    }
    let mut limiter = state.limiter.lock().unwrap_or_else(|e| e.into_inner());
    if limiter.is_allowed(&addr.ip().to_string()) {
        Ok(())
    } else {
        Err(StatusCode::TOO_MANY_REQUESTS)
    }
}

fn map_status(status: reqwest::StatusCode) -> StatusCode {
    StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY)
}

fn node_url(base: &str, path: &str) -> String {
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

fn value_f64(v: Option<&Value>) -> Option<f64> {
    match v {
        Some(Value::Number(n)) => n.as_f64(),
        Some(Value::String(s)) => s.parse::<f64>().ok(),
        _ => None,
    }
}

fn reward_irm_for_height(height: u64) -> f64 {
    (block_reward(height) as f64) / 100_000_000.0
}

#[derive(Debug, Clone)]
struct MinedBlockEntry {
    miner: String,
    time: u64,
    hash: String,
    source: Option<String>,
    // The ACTUAL coinbase P2PKH payees + amounts (sats), decoded from the block's
    // coinbase tx. Shows the PoAW-X reward split (proposer 55% + worker roles
    // 22/13/10 to distinct workers) instead of just the proposer + the full subsidy.
    payees: Vec<(String, u64)>,
}

const IRIUM_P2PKH_VERSION: u8 = 0x39;

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

/// Derive the miner address from a proxied node block's coinbase by scanning for
/// the FIRST P2PKH output. Post-PoAW-X-activation the coinbase output[0] is an
/// irx1 OP_RETURN (the payee moved to a later output), so the node's own
/// `outputs.first()` derivation yields null. Display-only; no consensus effect.
fn derive_miner_address_from_block_json(block: &Value) -> Option<String> {
    let cb_hex = block.get("tx_hex")?.as_array()?.first()?.as_str()?;
    let raw = hex::decode(cb_hex.trim()).ok()?;
    let tx = decode_full_tx(&raw).ok()?;
    let pkh = tx
        .outputs
        .iter()
        .find_map(|o| p2pkh_hash_from_script(&o.script_pubkey))?;
    Some(base58_p2pkh_from_hash(&pkh))
}

/// If a proxied block lacks a usable miner_address, fill it in from the coinbase
/// (first P2PKH). Mutates in place; never alters any other field or the response
/// shape. Display-only; zero consensus effect.
fn enrich_miner_address(block: &mut Value) {
    let missing = block
        .get("miner_address")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().is_empty() || s == "N/A")
        .unwrap_or(true);
    if !missing {
        return;
    }
    if let Some(addr) = derive_miner_address_from_block_json(block) {
        if let Some(obj) = block.as_object_mut() {
            obj.insert("miner_address".to_string(), Value::String(addr));
        }
    }
}

async fn load_block_entry(state: &AppState, height: u64) -> Option<MinedBlockEntry> {
    let path = format!("/rpc/block?height={}", height);
    let mut block = proxy_value(state, &path).await.ok()?;
    enrich_miner_address(&mut block);

    let miner = block
        .get("miner_address")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .unwrap_or("N/A")
        .to_string();
    let time = block
        .get("header")
        .and_then(|hh| hh.get("time"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let hash = block
        .get("header")
        .and_then(|hh| hh.get("hash"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let source = block
        .get("submit_source")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Decode the coinbase's real P2PKH payees + amounts so the reward SPLIT is shown,
    // not just the proposer + the height-based full subsidy.
    let payees = block_coinbase_payees(&block);

    Some(MinedBlockEntry {
        miner,
        time,
        hash,
        source,
        payees,
    })
}

async fn proxy_json(state: &AppState, path: &str) -> Result<Json<Value>, StatusCode> {
    let url = node_url(&state.node_base, path);
    let mut req = state.client.get(url);
    if let Some(token) = &state.rpc_token {
        if !token.is_empty() {
            req = req.bearer_auth(token);
        }
    }
    let resp = req.send().await.map_err(|_| StatusCode::BAD_GATEWAY)?;
    if !resp.status().is_success() {
        return Err(map_status(resp.status()));
    }
    let payload = resp
        .json::<Value>()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    Ok(Json(payload))
}

async fn proxy_value(state: &AppState, path: &str) -> Result<Value, StatusCode> {
    let Json(payload) = proxy_json(state, path).await?;
    Ok(payload)
}

async fn proxy_post_json(
    state: &AppState,
    path: &str,
    payload: Value,
) -> Result<Value, StatusCode> {
    let url = node_url(&state.node_base, path);
    let mut req = state.client.post(url).json(&payload);
    if let Some(token) = &state.rpc_token {
        if !token.is_empty() {
            req = req.bearer_auth(token);
        }
    }
    let resp = req.send().await.map_err(|_| StatusCode::BAD_GATEWAY)?;
    if !resp.status().is_success() {
        return Err(map_status(resp.status()));
    }
    resp.json::<Value>()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)
}

fn settlement_surface(rpc: &str, payload: Value) -> Json<Value> {
    Json(json!({
        "surface": "phase1_settlement",
        "rpc": rpc,
        "consensus_enforced": [
            "standard transaction validity",
            "op_return anchor visibility"
        ],
        "htlc_enforced": [
            "existing HTLCv1 preimage-release and timeout-refund rules only when the agreement funding output uses HTLCv1"
        ],
        "metadata_indexed": [
            "agreement object",
            "milestones and milestone progress",
            "lifecycle reconstruction",
            "mediator references",
            "document and metadata hashes"
        ],
        "off_chain_required": [
            "agreement exchange",
            "milestone completion interpretation",
            "release coordination unless encoded by HTLC preimage"
        ],
        "data": payload
    }))
}

async fn settlement_proxy(
    state: &AppState,
    rpc_path: &str,
    rpc_name: &str,
    payload: Value,
) -> Result<Json<Value>, StatusCode> {
    let forwarded = proxy_post_json(state, rpc_path, payload).await?;
    Ok(settlement_surface(rpc_name, forwarded))
}

fn html_escape(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn parse_party_form_value(value: &str) -> Result<AgreementParty, String> {
    let parts: Vec<&str> = value.split('|').collect();
    if parts.len() < 3 || parts.len() > 4 {
        return Err("party value must be party_id|display_name|address|role(optional)".to_string());
    }
    Ok(AgreementParty {
        party_id: parts[0].trim().to_string(),
        display_name: parts[1].trim().to_string(),
        address: parts[2].trim().to_string(),
        role: parts
            .get(3)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty()),
    })
}

fn parse_required_hex_hash(value: &str, label: &str) -> Result<String, String> {
    let value = value.trim();
    if value.len() != 64 || hex::decode(value).is_err() {
        return Err(format!("{label} must be 32-byte hex"));
    }
    Ok(value.to_string())
}

fn parse_optional_hex_hash(value: Option<&String>, label: &str) -> Result<Option<String>, String> {
    match value {
        Some(value) if !value.trim().is_empty() => Ok(Some(parse_required_hex_hash(value, label)?)),
        _ => Ok(None),
    }
}

fn parse_milestone_form_lines(
    raw: &str,
    payee: &AgreementParty,
    payer: &AgreementParty,
) -> Result<Vec<AgreementMilestone>, String> {
    let mut milestones = Vec::new();
    for line in raw.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() != 5 && parts.len() != 6 {
            return Err("milestone line must be id|title|amount_irm|timeout_height|secret_hash_hex|deliverable_hash(optional)".to_string());
        }
        let amount = parts[2]
            .parse::<f64>()
            .ok()
            .filter(|&f| f.is_finite())
            .ok_or_else(|| "invalid milestone amount".to_string())?;
        let atoms = (amount * 100_000_000.0).round() as u64;
        let timeout_height = parts[3]
            .parse::<u64>()
            .map_err(|_| "invalid milestone timeout_height".to_string())?;
        let secret_hash_hex = parse_required_hex_hash(parts[4], "milestone secret_hash_hex")?;
        let metadata_hash = if let Some(value) = parts.get(5) {
            Some(parse_required_hex_hash(
                value,
                "milestone deliverable hash",
            )?)
        } else {
            None
        };
        milestones.push(AgreementMilestone {
            milestone_id: parts[0].trim().to_string(),
            title: parts[1].trim().to_string(),
            amount: atoms,
            recipient_address: payee.address.clone(),
            refund_address: payer.address.clone(),
            secret_hash_hex,
            timeout_height,
            metadata_hash,
        });
    }
    Ok(milestones)
}

fn agreement_template_markup() -> String {
    [
        r#"<section><h2>Template Creation Helpers</h2><p>Create canonical Phase 1.5 agreement JSON locally in your browser session. These forms derive off-chain agreement artifacts only. They do not create native consensus agreement state.</p></section>"#,
        r#"<section><h3>Simple settlement</h3><form method="post" action="/agreement/create/simple-settlement/view"><div class="grid"><label>Agreement ID<input name="agreement_id" /></label><label>Creation time<input name="creation_time" /></label><label>Party A<input name="party_a" placeholder="id|Display|Qaddr|role" /></label><label>Party B<input name="party_b" placeholder="id|Display|Qaddr|role" /></label><label>Amount IRIUM<input name="amount" /></label><label>Settlement deadline<input name="settlement_deadline" /></label><label>Refund timeout height<input name="refund_timeout" /></label><label>Secret hash<input name="secret_hash" /></label><label>Document hash<input name="document_hash" /></label><label>Metadata hash<input name="metadata_hash" /></label><label>Release summary<input name="release_summary" /></label><label>Refund summary<input name="refund_summary" /></label><label>Notes<input name="notes" /></label></div><div class="actions"><button type="submit">Create simple settlement</button></div></form></section>"#,
        r#"<section><h3>OTC settlement</h3><form method="post" action="/agreement/create/otc/view"><div class="grid"><label>Agreement ID<input name="agreement_id" /></label><label>Creation time<input name="creation_time" /></label><label>Buyer<input name="buyer" placeholder="id|Display|Qaddr|role" /></label><label>Seller<input name="seller" placeholder="id|Display|Qaddr|role" /></label><label>Amount IRIUM<input name="amount" /></label><label>Asset reference<input name="asset_reference" /></label><label>Payment reference<input name="payment_reference" /></label><label>Refund timeout height<input name="refund_timeout" /></label><label>Secret hash<input name="secret_hash" /></label><label>Document hash<input name="document_hash" /></label><label>Metadata hash<input name="metadata_hash" /></label><label>Notes<input name="notes" /></label></div><div class="actions"><button type="submit">Create OTC agreement</button></div></form></section>"#,
        r#"<section><h3>Deposit settlement</h3><form method="post" action="/agreement/create/deposit/view"><div class="grid"><label>Agreement ID<input name="agreement_id" /></label><label>Creation time<input name="creation_time" /></label><label>Payer<input name="payer" placeholder="id|Display|Qaddr|role" /></label><label>Payee<input name="payee" placeholder="id|Display|Qaddr|role" /></label><label>Amount IRIUM<input name="amount" /></label><label>Purpose reference<input name="purpose_reference" /></label><label>Refund summary<input name="refund_summary" /></label><label>Refund timeout height<input name="refund_timeout" /></label><label>Secret hash<input name="secret_hash" /></label><label>Document hash<input name="document_hash" /></label><label>Metadata hash<input name="metadata_hash" /></label><label>Notes<input name="notes" /></label></div><div class="actions"><button type="submit">Create deposit agreement</button></div></form></section>"#,
        r#"<section><h3>Milestone settlement</h3><form method="post" action="/agreement/create/milestone/view"><div class="grid"><label>Agreement ID<input name="agreement_id" /></label><label>Creation time<input name="creation_time" /></label><label>Payer<input name="payer" placeholder="id|Display|Qaddr|role" /></label><label>Payee<input name="payee" placeholder="id|Display|Qaddr|role" /></label><label>Refund deadline<input name="refund_deadline" /></label><label>Document hash<input name="document_hash" /></label><label>Metadata hash<input name="metadata_hash" /></label><label>Notes<input name="notes" /></label></div><label>Milestones<textarea name="milestones_text" rows="6" placeholder="id|title|amount_irm|timeout_height|secret_hash_hex|deliverable_hash(optional)"></textarea></label><div class="actions"><button type="submit">Create milestone agreement</button></div></form></section>"#,
    ].join("")
}

fn agreement_form_markup(prefill: &str) -> String {
    format!(
        r#"<section><h1>Phase 1 Agreement Views</h1><p>Paste the canonical agreement JSON or an exported agreement bundle JSON. If a bundle is supplied, the contained canonical agreement object is used after hash verification. These views combine on-chain observations, HTLCv1 branch rules, and metadata-derived agreement context. They do not create native consensus settlement state.</p><form method="post" action="/agreement/inspect/view"><label>Agreement or bundle JSON</label><textarea name="agreement_json" rows="18">{}</textarea><div class="grid"><label>Funding txid<input name="funding_txid" /></label><label>HTLC vout<input name="htlc_vout" type="number" min="0" /></label><label>Milestone ID<input name="milestone_id" /></label><label>Destination address<input name="destination_address" /></label><label>Release secret hex<input name="secret_hex" /></label></div><label>Detached agreement signature JSON (optional)</label><textarea name="agreement_signature_json" rows="6"></textarea><label>Detached bundle signature JSON (optional)</label><textarea name="bundle_signature_json" rows="6"></textarea><div class="actions"><button type="submit">Inspect</button><button type="submit" formaction="/agreement/status/view">Status</button><button type="submit" formaction="/agreement/milestones/view">Milestones</button><button type="submit" formaction="/agreement/txs/view">Transactions</button><button type="submit" formaction="/agreement/funding-legs/view">Funding Legs</button><button type="submit" formaction="/agreement/timeline/view">Timeline</button><button type="submit" formaction="/agreement/audit/view">Audit</button><button type="submit" formaction="/agreement/statement/view">Statement</button><button type="submit" formaction="/agreement/release-eligibility/view">Release Eligibility</button><button type="submit" formaction="/agreement/refund-eligibility/view">Refund Eligibility</button></div></form></section>"#,
        html_escape(prefill)
    )
}

fn agreement_lookup_markup() -> String {
    r#"<section><h2>Lookup by hash or txid</h2><p>Use this when you have a linked transaction id or an agreement hash but not the full agreement JSON. Txid lookup can discover on-chain agreement anchors. Full lifecycle and milestone reconstruction still requires the canonical agreement object or an exported agreement bundle.</p><form method="post" action="/agreement/lookup/view"><div class="grid"><label>Agreement hash<input name="agreement_hash" /></label><label>Linked txid or funding txid<input name="lookup_txid" /></label></div><div class="actions"><button type="submit">Lookup</button></div></form></section>"#.to_string()
}

fn agreement_verification_markup() -> String {
    r#"<section><h2>Verify shared artifacts</h2><p>Paste the canonical agreement JSON or exported bundle JSON, plus any shared audit or statement JSON. Verification is derived from supplied artifacts plus observed chain activity. It does not create native agreement state and it cannot recover full agreement terms from chain data alone.</p><form method="post" action="/agreement/verify-artifacts/view"><label>Agreement or bundle JSON (optional but recommended)</label><textarea name="agreement_json" rows="12"></textarea><label>Audit JSON (optional)</label><textarea name="audit_json" rows="12"></textarea><label>Statement JSON (optional)</label><textarea name="statement_json" rows="10"></textarea><label>Detached agreement signature JSON (optional)</label><textarea name="agreement_signature_json" rows="8"></textarea><label>Detached bundle signature JSON (optional)</label><textarea name="bundle_signature_json" rows="8"></textarea><div class="actions"><button type="submit">Verify artifacts</button></div></form></section>"#.to_string()
}

fn agreement_share_package_markup() -> String {
    r#"<section><h2>Verify a shared handoff package</h2><p>Paste a share-package JSON artifact when a counterparty sends a compact handoff package containing agreement, bundle, statement, audit, or detached signatures. The package itself is only a transport convenience. Verification still checks the included canonical hashes, signatures, and derived artifact consistency. It does not create native agreement state or settlement enforcement.</p><form method="post" action="/agreement/share-package/verify/view"><label>Share-package JSON</label><textarea name="share_package_json" rows="14"></textarea><div class="actions"><button type="submit">Verify share package</button></div></form></section>"#.to_string()
}

fn agreement_signature_markup() -> String {
    r#"<section><h2>Verify signatures</h2><p>Paste canonical agreement JSON or bundle JSON plus detached signature JSON when available. Explorer verification checks authenticity only. It does not prove the agreement is true or enforce settlement on-chain.</p><form method="post" action="/agreement/verify-signature/view"><label>Agreement or bundle JSON</label><textarea name="agreement_json" rows="12"></textarea><label>Signature JSON (optional for detached verification; embedded bundle signatures are checked automatically)</label><textarea name="signature_json" rows="10"></textarea><div class="actions"><button type="submit">Verify signatures</button></div></form></section>"#.to_string()
}

fn agreement_wallet_handoff_markup() -> String {
    [
        r#"<section><h2>Wallet-side intake and housekeeping</h2><p>Explorer pages verify and inspect supplied agreement artifacts, but local receipt import, archive, prune, and exact remove remain wallet-side operations only. Use the wallet when you want to persist a verified handoff package locally.</p>"#,
        r#"<ul><li><code>irium-wallet agreement-share-package-import package.json --import agreement --import bundle</code></li><li><code>irium-wallet agreement-local-store-list --include-archived</code></li><li><code>irium-wallet agreement-share-package-archive &lt;receipt-id&gt;</code></li><li><code>irium-wallet agreement-share-package-prune --dry-run --include-archived --older-than 30</code></li></ul></section>"#,
    ]
    .join("")
}

fn trust_boundary_markup() -> String {
    [
        "<section><h2>Trust Boundaries</h2><ul>",
        "<li><strong>Consensus-enforced:</strong> standard transaction validity and OP_RETURN anchor visibility only.</li>",
        "<li><strong>HTLC-enforced:</strong> existing HTLCv1 preimage release and timeout refund branches when the agreement funding leg actually uses HTLCv1.</li>",
        "<li><strong>Metadata / indexed context:</strong> agreement object, lifecycle reconstruction, milestone meaning, mediator references, and document or metadata hashes.</li>",
        "<li><strong>Off-chain required:</strong> agreement exchange, release coordination, and milestone interpretation unless already expressed by HTLCv1 branch data.</li>",
        "</ul></section>",
    ]
    .join("")
}

fn layout_html(title: &str, body: String) -> String {
    format!(
        r#"<!doctype html><html><head><meta charset="utf-8"><title>{}</title><style>body{{font-family:ui-sans-serif,system-ui,sans-serif;max-width:980px;margin:2rem auto;padding:0 1rem;line-height:1.45}}textarea{{width:100%;font-family:ui-monospace,monospace}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ddd;padding:.45rem;text-align:left;vertical-align:top}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:.75rem;margin:.75rem 0}}label{{display:flex;flex-direction:column;gap:.25rem}}.actions{{display:flex;flex-wrap:wrap;gap:.5rem;margin-top:.75rem}}.notice{{background:#f6f6f6;border:1px solid #ddd;padding:.75rem;margin:1rem 0}}code,pre{{background:#f6f6f6;padding:.1rem .25rem}}pre{{padding:.75rem;overflow:auto}}</style></head><body><nav><a href="/agreement">Agreement tools</a></nav>{}</body></html>"#,
        html_escape(title),
        body,
    )
}

fn html_page(title: &str, body: String) -> Html<String> {
    Html(layout_html(title, body))
}

fn html_error(status: StatusCode, title: &str, message: &str) -> Response {
    (
        status,
        html_page(
            title,
            format!(
                r#"<div class="notice"><strong>{}</strong><p>{}</p></div>{}{}"#,
                html_escape(title),
                html_escape(message),
                trust_boundary_markup(),
                agreement_form_markup("")
            ),
        ),
    )
        .into_response()
}

fn parse_agreement_context_form(
    form: &AgreementHtmlForm,
) -> Result<(AgreementObject, Option<AgreementBundle>), String> {
    let raw = form.agreement_json.trim();
    if raw.is_empty() {
        return Err("agreement json or bundle json is required".to_string());
    }
    if let Ok(agreement) = serde_json::from_str::<AgreementObject>(raw) {
        agreement.validate()?;
        return Ok((agreement, None));
    }
    let bundle: AgreementBundle =
        serde_json::from_str(raw).map_err(|e| format!("invalid agreement or bundle json: {e}"))?;
    verify_agreement_bundle(&bundle)?;
    Ok((bundle.agreement.clone(), Some(bundle)))
}

fn parse_agreement_form(form: &AgreementHtmlForm) -> Result<AgreementObject, String> {
    parse_agreement_context_form(form).map(|(agreement, _bundle)| agreement)
}

fn agreement_context_payload(form: &AgreementHtmlForm) -> Result<Value, String> {
    let (agreement, bundle) = parse_agreement_context_form(form)?;
    Ok(json!({"agreement": agreement, "bundle": bundle}))
}

fn parse_optional_agreement_context_form(
    form: &AgreementHtmlForm,
) -> Result<(Option<AgreementObject>, Option<AgreementBundle>), String> {
    if form.agreement_json.trim().is_empty() {
        return Ok((None, None));
    }
    let (agreement, bundle) = parse_agreement_context_form(form)?;
    Ok((Some(agreement), bundle))
}

fn parse_optional_audit_form(
    form: &AgreementHtmlForm,
) -> Result<Option<AgreementAuditRecord>, String> {
    let raw = form.audit_json.as_deref().unwrap_or("").trim();
    if raw.is_empty() {
        return Ok(None);
    }
    serde_json::from_str(raw)
        .map(Some)
        .map_err(|e| format!("invalid audit json: {e}"))
}

fn parse_optional_statement_form(
    form: &AgreementHtmlForm,
) -> Result<Option<AgreementStatement>, String> {
    let raw = form.statement_json.as_deref().unwrap_or("").trim();
    if raw.is_empty() {
        return Ok(None);
    }
    serde_json::from_str(raw)
        .map(Some)
        .map_err(|e| format!("invalid statement json: {e}"))
}

fn parse_signature_json(
    raw: &str,
    label: &str,
) -> Result<Option<AgreementSignatureEnvelope>, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let signature: AgreementSignatureEnvelope =
        serde_json::from_str(raw).map_err(|e| format!("invalid {} json: {e}", label))?;
    validate_agreement_signature_envelope(&signature)?;
    Ok(Some(signature))
}

fn parse_optional_signature_form(
    form: &AgreementHtmlForm,
) -> Result<Option<AgreementSignatureEnvelope>, String> {
    parse_signature_json(form.signature_json.as_deref().unwrap_or(""), "signature")
}

fn parse_optional_agreement_signature_form(
    form: &AgreementHtmlForm,
) -> Result<Option<AgreementSignatureEnvelope>, String> {
    parse_signature_json(
        form.agreement_signature_json.as_deref().unwrap_or(""),
        "agreement signature",
    )
}

fn parse_optional_bundle_signature_form(
    form: &AgreementHtmlForm,
) -> Result<Option<AgreementSignatureEnvelope>, String> {
    parse_signature_json(
        form.bundle_signature_json.as_deref().unwrap_or(""),
        "bundle signature",
    )
}

fn parse_optional_share_package_form(
    form: &AgreementHtmlForm,
) -> Result<Option<AgreementSharePackage>, String> {
    let raw = form.share_package_json.as_deref().unwrap_or("").trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let package: AgreementSharePackage =
        serde_json::from_str(raw).map_err(|e| format!("invalid share-package json: {e}"))?;
    verify_agreement_share_package(&package)?;
    Ok(Some(package))
}

fn attach_authenticity_to_audit(
    record: &mut AgreementAuditRecord,
    agreement: &AgreementObject,
    bundle: Option<&AgreementBundle>,
    detached_agreement_signatures: &[AgreementSignatureEnvelope],
    detached_bundle_signatures: &[AgreementSignatureEnvelope],
) {
    record.authenticity = build_agreement_artifact_authenticity_verification(
        Some(agreement),
        bundle,
        detached_agreement_signatures,
        detached_bundle_signatures,
    )
    .as_ref()
    .map(summarize_agreement_authenticity);
}

fn agreement_navigation_markup() -> String {
    r#"<section><h2>Related views</h2><p><a href="/agreement">Agreement tools</a> keeps the agreement JSON form and the txid/hash lookup form in one place. Use the buttons below each view to move between inspect, status, milestones, transaction history, statement, audit, and HTLC eligibility checks.</p></section>"#.to_string()
}

fn bundle_context_markup(bundle: Option<&AgreementBundle>) -> String {
    let Some(bundle) = bundle else {
        return String::new();
    };
    let bundle_hash =
        compute_agreement_bundle_hash_hex(bundle).unwrap_or_else(|_| "unavailable".to_string());
    let signature_markup = if bundle.signatures.is_empty() {
        "<p><strong>Embedded signatures:</strong> none</p>".to_string()
    } else {
        let items = verify_bundle_signatures(bundle)
            .into_iter()
            .map(|item| {
                format!(
                    "<li><strong>{}</strong> signer {} role {} target {} note {}</li>",
                    if item.valid { "valid" } else { "invalid" },
                    html_escape(
                        item.signer_address
                            .as_deref()
                            .unwrap_or(item.signer_public_key.as_str())
                    ),
                    html_escape(item.signer_role.as_deref().unwrap_or("unspecified")),
                    html_escape(&item.target_hash),
                    html_escape(&item.authenticity_note),
                )
            })
            .collect::<Vec<_>>()
            .join("");
        format!(
            "<p><strong>Embedded signatures:</strong> {}</p><ul>{}</ul>",
            bundle.signatures.len(),
            items
        )
    };
    format!(
        "<section><h2>Bundle context</h2><p class='notice'>Bundle JSON is an off-chain export artifact. It is useful for self-custodial exchange and re-verification, but it is not native consensus state.</p><p><strong>Bundle schema:</strong> <code>{}</code></p><p><strong>Bundle hash:</strong> <code>{}</code></p><p><strong>Embedded audit:</strong> {}</p><p><strong>Embedded statement:</strong> {}</p>{}<p><strong>Copy hashes:</strong> agreement <code>{}</code> | bundle <code>{}</code></p></section>",
        html_escape(bundle.bundle_schema_id.as_deref().unwrap_or("legacy_unlabeled")),
        html_escape(&bundle_hash),
        bundle.artifacts.audit.is_some(),
        bundle.artifacts.statement.is_some(),
        signature_markup,
        html_escape(&bundle.agreement_hash),
        html_escape(&bundle_hash),
    )
}

fn agreement_header_markup(agreement: &AgreementObject, agreement_hash: &str) -> String {
    let milestones = if agreement.milestones.is_empty() {
        "<p><strong>Milestones:</strong> none</p>".to_string()
    } else {
        let rows = agreement
            .milestones
            .iter()
            .map(|m| {
                format!(
                    "<li><code>{}</code> {} amount {} timeout {}</li>",
                    html_escape(&m.milestone_id),
                    html_escape(&m.title),
                    m.amount,
                    m.timeout_height
                )
            })
            .collect::<Vec<_>>()
            .join("");
        format!("<p><strong>Milestones:</strong></p><ul>{}</ul>", rows)
    };
    let template_type_escaped = html_escape(&format!("{:?}", agreement.template_type));
    let settlement_deadline_escaped = agreement
        .deadlines
        .settlement_deadline
        .map_or_else(|| "none".to_string(), |v| v.to_string());
    let refund_deadline_escaped = agreement
        .deadlines
        .refund_deadline
        .map_or_else(|| "none".to_string(), |v| v.to_string());
    format!(
        "<section><h1>Agreement {}</h1><p><strong>Agreement hash:</strong> <code>{}</code></p><p><strong>Schema:</strong> <code>{}</code></p><p><strong>Version:</strong> {}</p><p><strong>Template:</strong> {}</p><p><strong>Payer:</strong> {}</p><p><strong>Payee:</strong> {}</p><p><strong>Total amount:</strong> {}</p><p><strong>Document hash:</strong> <code>{}</code></p><p><strong>Metadata hash:</strong> {}</p><p><strong>Settlement deadline:</strong> {}</p><p><strong>Refund deadline:</strong> {}</p>{}</section>",
        html_escape(&agreement.agreement_id),
        html_escape(agreement_hash),
        html_escape(agreement.schema_id.as_deref().unwrap_or("legacy_unlabeled")),
        agreement.version,
        template_type_escaped,
        html_escape(&agreement.payer),
        html_escape(&agreement.payee),
        agreement.total_amount,
        html_escape(&agreement.document_hash),
        html_escape(agreement.metadata_hash.as_deref().unwrap_or("none")),
        settlement_deadline_escaped,
        refund_deadline_escaped,
        milestones,
    )
}

fn render_created_agreement_page(title: &str, agreement: &AgreementObject) -> Html<String> {
    let agreement_hash =
        compute_agreement_hash_hex(agreement).unwrap_or_else(|_| "unavailable".to_string());
    let canonical_json =
        serde_json::to_string_pretty(agreement).unwrap_or_else(|_| "{}".to_string());
    html_page(
        title,
        format!(
            "{}<section><h2>Generated canonical agreement JSON</h2><p class=notice>This agreement JSON is a derived off-chain Phase 1.5 artifact. Canonical agreement JSON remains the source of truth for agreement terms; chain data alone cannot recover it.</p><p><strong>Agreement hash:</strong> <code>{}</code></p><pre>{}</pre></section>{}",
            agreement_header_markup(agreement, &agreement_hash),
            html_escape(&agreement_hash),
            html_escape(&canonical_json),
            agreement_form_markup(&canonical_json),
        ),
    )
}

fn build_simple_agreement_from_form(
    form: &AgreementTemplateForm,
) -> Result<AgreementObject, String> {
    build_simple_settlement_agreement(
        form.agreement_id.trim().to_string(),
        form.creation_time
            .trim()
            .parse::<u64>()
            .map_err(|_| "invalid creation_time".to_string())?,
        parse_party_form_value(form.party_a.as_deref().unwrap_or(""))?,
        parse_party_form_value(form.party_b.as_deref().unwrap_or(""))?,
        ((form
            .amount
            .as_deref()
            .unwrap_or("0")
            .parse::<f64>()
            .map_err(|_| "invalid amount".to_string())?
            * 100_000_000.0)
            .round()) as u64,
        form.settlement_deadline
            .as_deref()
            .filter(|v| !v.is_empty())
            .map(|v| {
                v.parse::<u64>()
                    .map_err(|_| "invalid settlement_deadline".to_string())
            })
            .transpose()?,
        form.refund_timeout
            .as_deref()
            .unwrap_or("0")
            .parse::<u64>()
            .map_err(|_| "invalid refund_timeout".to_string())?,
        parse_required_hex_hash(form.secret_hash.as_deref().unwrap_or(""), "secret_hash")?,
        parse_required_hex_hash(&form.document_hash, "document_hash")?,
        parse_optional_hex_hash(form.metadata_hash.as_ref(), "metadata_hash")?,
        form.release_summary
            .clone()
            .filter(|v| !v.trim().is_empty()),
        form.refund_summary.clone().filter(|v| !v.trim().is_empty()),
        form.notes.clone().filter(|v| !v.trim().is_empty()),
    )
}

fn build_otc_agreement_from_form(form: &AgreementTemplateForm) -> Result<AgreementObject, String> {
    build_otc_agreement(
        form.agreement_id.trim().to_string(),
        form.creation_time
            .trim()
            .parse::<u64>()
            .map_err(|_| "invalid creation_time".to_string())?,
        parse_party_form_value(form.buyer.as_deref().unwrap_or(""))?,
        parse_party_form_value(form.seller.as_deref().unwrap_or(""))?,
        ((form
            .amount
            .as_deref()
            .unwrap_or("0")
            .parse::<f64>()
            .map_err(|_| "invalid amount".to_string())?
            * 100_000_000.0)
            .round()) as u64,
        form.asset_reference
            .clone()
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| "asset_reference required".to_string())?,
        form.payment_reference
            .clone()
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| "payment_reference required".to_string())?,
        form.refund_timeout
            .as_deref()
            .unwrap_or("0")
            .parse::<u64>()
            .map_err(|_| "invalid refund_timeout".to_string())?,
        parse_required_hex_hash(form.secret_hash.as_deref().unwrap_or(""), "secret_hash")?,
        parse_required_hex_hash(&form.document_hash, "document_hash")?,
        parse_optional_hex_hash(form.metadata_hash.as_ref(), "metadata_hash")?,
        form.notes.clone().filter(|v| !v.trim().is_empty()),
    )
}

fn build_deposit_agreement_from_form(
    form: &AgreementTemplateForm,
) -> Result<AgreementObject, String> {
    build_deposit_agreement(
        form.agreement_id.trim().to_string(),
        form.creation_time
            .trim()
            .parse::<u64>()
            .map_err(|_| "invalid creation_time".to_string())?,
        parse_party_form_value(form.payer.as_deref().unwrap_or(""))?,
        parse_party_form_value(form.payee.as_deref().unwrap_or(""))?,
        ((form
            .amount
            .as_deref()
            .unwrap_or("0")
            .parse::<f64>()
            .map_err(|_| "invalid amount".to_string())?
            * 100_000_000.0)
            .round()) as u64,
        form.purpose_reference
            .clone()
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| "purpose_reference required".to_string())?,
        form.refund_summary
            .clone()
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| "refund_summary required".to_string())?,
        form.refund_timeout
            .as_deref()
            .unwrap_or("0")
            .parse::<u64>()
            .map_err(|_| "invalid refund_timeout".to_string())?,
        parse_required_hex_hash(form.secret_hash.as_deref().unwrap_or(""), "secret_hash")?,
        parse_required_hex_hash(&form.document_hash, "document_hash")?,
        parse_optional_hex_hash(form.metadata_hash.as_ref(), "metadata_hash")?,
        form.notes.clone().filter(|v| !v.trim().is_empty()),
    )
}

fn build_milestone_agreement_from_form(
    form: &AgreementTemplateForm,
) -> Result<AgreementObject, String> {
    let payer = parse_party_form_value(form.payer.as_deref().unwrap_or(""))?;
    let payee = parse_party_form_value(form.payee.as_deref().unwrap_or(""))?;
    let milestones = parse_milestone_form_lines(
        form.milestones_text.as_deref().unwrap_or(""),
        &payee,
        &payer,
    )?;
    build_milestone_agreement(
        form.agreement_id.trim().to_string(),
        form.creation_time
            .trim()
            .parse::<u64>()
            .map_err(|_| "invalid creation_time".to_string())?,
        payer,
        payee,
        milestones,
        form.refund_deadline
            .as_deref()
            .unwrap_or("0")
            .parse::<u64>()
            .map_err(|_| "invalid refund_deadline".to_string())?,
        parse_required_hex_hash(&form.document_hash, "document_hash")?,
        parse_optional_hex_hash(form.metadata_hash.as_ref(), "metadata_hash")?,
        form.notes.clone().filter(|v| !v.trim().is_empty()),
    )
}

async fn agreement_index_html() -> Html<String> {
    html_page(
        "Agreement tools",
        format!(
            "{}{}{}{}{}{}{}{}",
            agreement_template_markup(),
            agreement_form_markup(""),
            agreement_lookup_markup(),
            agreement_verification_markup(),
            agreement_share_package_markup(),
            agreement_signature_markup(),
            agreement_wallet_handoff_markup(),
            trust_boundary_markup()
        ),
    )
}

async fn agreement_create_simple_view(
    Form(form): Form<AgreementTemplateForm>,
) -> impl IntoResponse {
    match build_simple_agreement_from_form(&form) {
        Ok(agreement) => {
            render_created_agreement_page("Simple settlement", &agreement).into_response()
        }
        Err(message) => html_error(
            StatusCode::BAD_REQUEST,
            "Create simple settlement",
            &message,
        ),
    }
}

async fn agreement_create_otc_view(Form(form): Form<AgreementTemplateForm>) -> impl IntoResponse {
    match build_otc_agreement_from_form(&form) {
        Ok(agreement) => {
            render_created_agreement_page("OTC settlement", &agreement).into_response()
        }
        Err(message) => html_error(StatusCode::BAD_REQUEST, "Create OTC agreement", &message),
    }
}

async fn agreement_create_deposit_view(
    Form(form): Form<AgreementTemplateForm>,
) -> impl IntoResponse {
    match build_deposit_agreement_from_form(&form) {
        Ok(agreement) => {
            render_created_agreement_page("Deposit settlement", &agreement).into_response()
        }
        Err(message) => html_error(
            StatusCode::BAD_REQUEST,
            "Create deposit agreement",
            &message,
        ),
    }
}

async fn agreement_create_milestone_view(
    Form(form): Form<AgreementTemplateForm>,
) -> impl IntoResponse {
    match build_milestone_agreement_from_form(&form) {
        Ok(agreement) => {
            render_created_agreement_page("Milestone settlement", &agreement).into_response()
        }
        Err(message) => html_error(
            StatusCode::BAD_REQUEST,
            "Create milestone agreement",
            &message,
        ),
    }
}

async fn agreement_release_eligibility_api(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;
    settlement_proxy(
        &state,
        "/rpc/agreementreleaseeligibility",
        "agreementreleaseeligibility",
        payload,
    )
    .await
}

async fn agreement_refund_eligibility_api(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;
    settlement_proxy(
        &state,
        "/rpc/agreementrefundeligibility",
        "agreementrefundeligibility",
        payload,
    )
    .await
}

async fn agreement_funding_legs_api(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;
    settlement_proxy(
        &state,
        "/rpc/agreementfundinglegs",
        "agreementfundinglegs",
        payload,
    )
    .await
}

async fn agreement_timeline_api(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;
    settlement_proxy(
        &state,
        "/rpc/agreementtimeline",
        "agreementtimeline",
        payload,
    )
    .await
}

async fn agreement_audit_api(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;
    settlement_proxy(&state, "/rpc/agreementaudit", "agreementaudit", payload).await
}

fn audit_download_filename(agreement_id: &str, ext: &str) -> String {
    let safe_id: String = agreement_id
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect();
    format!("agreement-audit-{}.{}", safe_id, ext)
}

fn agreement_audit_download_markup(prefill: &str) -> String {
    format!(
        r#"<div class="actions"><form method="post" action="/agreement/audit/download.json"><textarea name="agreement_json" hidden>{}</textarea><button type="submit">Download audit JSON</button></form><form method="post" action="/agreement/audit/download.csv"><textarea name="agreement_json" hidden>{}</textarea><button type="submit">Download audit CSV</button></form></div>"#,
        html_escape(prefill),
        html_escape(prefill)
    )
}

fn agreement_statement_download_markup(prefill: &str) -> String {
    format!(
        r#"<div class="actions"><form method="post" action="/agreement/statement/view"><textarea name="agreement_json" hidden>{}</textarea><button type="submit">Statement view</button></form><form method="post" action="/agreement/statement/download.json"><textarea name="agreement_json" hidden>{}</textarea><button type="submit">Download statement JSON</button></form></div>"#,
        html_escape(prefill),
        html_escape(prefill)
    )
}

fn render_statement_section(statement: &AgreementStatement) -> String {
    let references = if statement.references.linked_txids.is_empty() {
        "<p><strong>Linked txids:</strong> none observed</p>".to_string()
    } else {
        format!(
            "<p><strong>Linked txids:</strong> {}</p>",
            html_escape(&statement.references.linked_txids.join(" | "))
        )
    };
    let ambiguity = statement
        .observed
        .ambiguity_warning
        .as_ref()
        .map(|warning| {
            format!(
                "<p><strong>Ambiguity warning:</strong> {}</p>",
                html_escape(warning)
            )
        })
        .unwrap_or_default();
    format!(
        r#"<section><h2>Derived settlement statement</h2><p><strong>Generated at:</strong> {}</p><p class="notice">This statement is derived from supplied agreement or bundle data plus observed chain activity. It is a printable/shareable Phase 1 report artifact, not native consensus contract state.</p><h3>Commercial summary</h3><p><strong>Total amount:</strong> {}</p><p><strong>Milestones:</strong> {}</p><p><strong>Settlement deadline:</strong> {}</p><p><strong>Refund deadline:</strong> {}</p><p><strong>Release path:</strong> {}</p><p><strong>Refund path:</strong> {}</p><h3>Observed settlement summary</h3><p><strong>Funding observed:</strong> {}</p><p><strong>Release observed:</strong> {}</p><p><strong>Refund observed:</strong> {}</p>{}<h3>Derived status summary</h3><p><strong>Derived status:</strong> {}</p><p><strong>Notice:</strong> {}</p>{}<h3>Trust boundaries</h3><ul><li><strong>Consensus-visible:</strong> {}</li><li><strong>HTLC-enforced:</strong> {}</li><li><strong>Derived/indexed:</strong> {}</li><li><strong>Local/off-chain:</strong> {}</li></ul><h3>References</h3>{}<p><strong>Canonical source of truth:</strong> {}</p></section>"#,
        statement.metadata.generated_at,
        statement.commercial.total_amount,
        html_escape(&statement.commercial.milestone_summary),
        statement
            .commercial
            .settlement_deadline
            .map(|v| v.to_string())
            .unwrap_or_else(|| "not specified".to_string()),
        statement
            .commercial
            .refund_deadline
            .map(|v| v.to_string())
            .unwrap_or_else(|| "not specified".to_string()),
        html_escape(&statement.commercial.release_path_summary),
        html_escape(&statement.commercial.refund_path_summary),
        statement.observed.funding_observed,
        statement.observed.release_observed,
        statement.observed.refund_observed,
        ambiguity,
        html_escape(&statement.derived.derived_state_label),
        html_escape(&statement.derived.note),
        statement.authenticity.as_ref().map(|authenticity| format!("<h3>Authenticity</h3><p><strong>Summary:</strong> {}</p><p><strong>Valid:</strong> {} <strong>Invalid:</strong> {} <strong>Unverifiable:</strong> {}</p><p class='notice'>{}</p>", html_escape(&authenticity.compact_summary), authenticity.valid_signatures, authenticity.invalid_signatures, authenticity.unverifiable_signatures, html_escape(&authenticity.authenticity_notice))).unwrap_or_default(),
        html_escape(&statement.trust_notice.consensus_visible.join(" | ")),
        html_escape(&statement.trust_notice.htlc_enforced.join(" | ")),
        html_escape(&statement.trust_notice.derived_indexed.join(" | ")),
        html_escape(&statement.trust_notice.local_off_chain.join(" | ")),
        references,
        html_escape(&statement.references.canonical_agreement_notice),
    )
}

fn verification_list_markup(items: &[String], empty: &str) -> String {
    if items.is_empty() {
        format!("<li>{}</li>", html_escape(empty))
    } else {
        items
            .iter()
            .map(|item| format!("<li>{}</li>", html_escape(item)))
            .collect::<Vec<_>>()
            .join("")
    }
}

fn render_share_package_verification_section(
    result: &AgreementSharePackageVerificationResult,
) -> String {
    let package = &result.package;
    let notices = if result.informational_notices.is_empty() {
        "<li>none</li>".to_string()
    } else {
        result
            .informational_notices
            .iter()
            .map(|notice| format!("<li>{}</li>", html_escape(notice)))
            .collect::<Vec<_>>()
            .join("")
    };
    let included = if package.included_artifact_types.is_empty() {
        "none".to_string()
    } else {
        package.included_artifact_types.join(", ")
    };
    let omitted = if package.omitted_artifact_types.is_empty() {
        "none".to_string()
    } else {
        package.omitted_artifact_types.join(", ")
    };
    format!(
        "<section><h2>Share package summary</h2><p class='notice'>{}</p><p><strong>Package profile:</strong> {}</p><p><strong>Included artifacts:</strong> {}</p><p><strong>Omitted artifacts:</strong> {}</p><p class='notice'>{}</p><p><strong>Agreement present:</strong> {}</p><p><strong>Bundle present:</strong> {}</p><p><strong>Audit present:</strong> {}</p><p><strong>Statement present:</strong> {}</p><p><strong>Detached agreement signatures:</strong> {}</p><p><strong>Detached bundle signatures:</strong> {}</p><p><strong>Canonical agreement id:</strong> {}</p><p><strong>Canonical agreement hash:</strong> <code>{}</code></p><p><strong>Bundle hash:</strong> <code>{}</code></p><p class='notice'>{}</p><h3>Package notices</h3><ul>{}</ul></section>{}",
        html_escape(&result.metadata.derived_notice),
        html_escape(&package.package_profile),
        html_escape(&included),
        html_escape(&omitted),
        html_escape(&package.verification_notice),
        package.agreement_present,
        package.bundle_present,
        package.audit_present,
        package.statement_present,
        package.detached_agreement_signature_count,
        package.detached_bundle_signature_count,
        html_escape(package.canonical_agreement_id.as_deref().unwrap_or("unavailable")),
        html_escape(package.canonical_agreement_hash.as_deref().unwrap_or("unavailable")),
        html_escape(package.bundle_hash.as_deref().unwrap_or("unavailable")),
        html_escape(&package.informational_notice),
        notices,
        render_artifact_verification_section(&result.artifact_verification),
    )
}

fn render_artifact_verification_section(result: &AgreementArtifactVerificationResult) -> String {
    let mut mismatches = result.canonical_verification.mismatches.clone();
    mismatches.extend(result.artifact_consistency.warnings.clone());
    let mut unverifiable = result.canonical_verification.warnings.clone();
    unverifiable.extend(result.chain_verification.warnings.clone());
    unverifiable.extend(result.derived_verification.warnings.clone());
    unverifiable.extend(result.trust_summary.unverifiable_from_chain_alone.clone());
    let checked_txids = if result.chain_verification.checked_txids.is_empty() {
        "none".to_string()
    } else {
        html_escape(&result.chain_verification.checked_txids.join(" | "))
    };
    let authenticity = result.authenticity.as_ref().map(|authenticity| {
        format!(
            "<h3>Authenticity</h3><p><strong>Detached agreement signatures:</strong> {}</p><p><strong>Detached bundle signatures:</strong> {}</p><p><strong>Embedded bundle signatures:</strong> {}</p><p><strong>Valid:</strong> {} <strong>Invalid:</strong> {} <strong>Unverifiable:</strong> {}</p><p class='notice'>{}</p><ul>{}</ul>",
            authenticity.detached_agreement_signatures_supplied,
            authenticity.detached_bundle_signatures_supplied,
            authenticity.embedded_bundle_signatures_supplied,
            authenticity.valid_signatures,
            authenticity.invalid_signatures,
            authenticity.unverifiable_signatures,
            html_escape(&authenticity.authenticity_notice),
            if authenticity.signer_summaries.is_empty() {
                "<li>none</li>".to_string()
            } else {
                authenticity
                    .signer_summaries
                    .iter()
                    .map(|item| format!("<li>{}</li>", html_escape(item)))
                    .collect::<Vec<_>>()
                    .join("")
            }
        )
    }).unwrap_or_default();
    format!(
        r#"<section><h2>Artifact verification</h2><p><strong>Generated at:</strong> {}</p><p class="notice">This verification result is derived from supplied artifacts plus observed chain activity. It is not native consensus contract state, and it cannot recover full agreement terms from chain data alone.</p><h3>Input summary</h3><p><strong>Supplied artifacts:</strong> {}</p><p><strong>Canonical agreement present:</strong> {}</p><p><strong>Extracted from bundle:</strong> {}</p><h3>Verified matches</h3><ul>{}</ul><h3>Mismatches</h3><ul>{}</ul>{}<h3>Chain-observed checks</h3><p><strong>Linked tx references found:</strong> {}</p><p><strong>Anchor observations found:</strong> {}</p><p><strong>Checked txids:</strong> {}</p><h3>Unverifiable or limited</h3><ul>{}</ul><h3>Trust boundaries</h3><ul><li><strong>Consensus-visible:</strong> {}</li><li><strong>HTLC-enforced:</strong> {}</li><li><strong>Derived/indexed:</strong> {}</li><li><strong>Local/off-chain:</strong> {}</li><li><strong>Not verifiable from chain alone:</strong> {}</li></ul></section>"#,
        result.metadata.generated_at,
        html_escape(&result.input_summary.supplied_artifact_types.join(" | ")),
        result.input_summary.canonical_agreement_present,
        result.input_summary.extracted_from_bundle,
        verification_list_markup(
            &result.canonical_verification.matches,
            "No direct canonical matches were proven from the supplied artifacts."
        ),
        verification_list_markup(
            &mismatches,
            "No mismatches detected in the supplied artifacts."
        ),
        authenticity,
        result.chain_verification.linked_tx_references_found,
        result.chain_verification.anchor_observations_found,
        checked_txids,
        verification_list_markup(
            &unverifiable,
            "No additional chain-verification limitations were recorded."
        ),
        html_escape(&result.trust_summary.consensus_visible.join(" | ")),
        html_escape(&result.trust_summary.htlc_enforced.join(" | ")),
        html_escape(&result.trust_summary.derived_indexed.join(" | ")),
        html_escape(&result.trust_summary.local_artifact_only.join(" | ")),
        html_escape(
            &result
                .trust_summary
                .unverifiable_from_chain_alone
                .join(" | ")
        ),
    )
}

async fn derive_artifact_verification(
    state: &AppState,
    agreement: Option<&AgreementObject>,
    bundle: Option<&AgreementBundle>,
    supplied_audit: Option<&AgreementAuditRecord>,
    supplied_statement: Option<&AgreementStatement>,
    detached_agreement_signature: Option<&AgreementSignatureEnvelope>,
    detached_bundle_signature: Option<&AgreementSignatureEnvelope>,
) -> AgreementArtifactVerificationResult {
    let recomputed_audit =
        if let Some(agreement_ref) = agreement.or_else(|| bundle.as_ref().map(|b| &b.agreement)) {
            proxy_post_json(
                state,
                "/rpc/agreementaudit",
                json!({"agreement": agreement_ref, "bundle": bundle}),
            )
            .await
            .ok()
            .and_then(|value| serde_json::from_value::<AgreementAuditRecord>(value).ok())
        } else {
            None
        };
    let detached_agreement_signatures = detached_agreement_signature
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();
    let detached_bundle_signatures = detached_bundle_signature
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();
    build_agreement_artifact_verification(
        agreement,
        bundle,
        supplied_audit,
        supplied_statement,
        &detached_agreement_signatures,
        &detached_bundle_signatures,
        recomputed_audit.as_ref(),
        now_unix(),
    )
}

async fn derive_share_package_verification(
    state: &AppState,
    package: &AgreementSharePackage,
) -> Result<AgreementSharePackageVerificationResult, String> {
    let recomputed_audit = if let Some(agreement_ref) = package
        .agreement
        .as_ref()
        .or_else(|| package.bundle.as_ref().map(|bundle| &bundle.agreement))
    {
        proxy_post_json(
            state,
            "/rpc/agreementaudit",
            json!({"agreement": agreement_ref, "bundle": package.bundle.as_ref()}),
        )
        .await
        .ok()
        .and_then(|value| serde_json::from_value::<AgreementAuditRecord>(value).ok())
    } else {
        None
    };
    build_agreement_share_package_verification(package, recomputed_audit.as_ref(), now_unix())
}

async fn agreement_verify_artifacts_api(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;
    let agreement = payload
        .get("agreement")
        .cloned()
        .map(serde_json::from_value::<AgreementObject>)
        .transpose()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if let Some(agreement_ref) = agreement.as_ref() {
        agreement_ref
            .validate()
            .map_err(|_| StatusCode::BAD_REQUEST)?;
    }
    let bundle = payload
        .get("bundle")
        .cloned()
        .map(serde_json::from_value::<AgreementBundle>)
        .transpose()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if let Some(bundle_ref) = bundle.as_ref() {
        verify_agreement_bundle(bundle_ref).map_err(|_| StatusCode::BAD_REQUEST)?;
    }
    let audit = payload
        .get("audit")
        .cloned()
        .map(serde_json::from_value::<AgreementAuditRecord>)
        .transpose()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let statement = payload
        .get("statement")
        .cloned()
        .map(serde_json::from_value::<AgreementStatement>)
        .transpose()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if agreement.is_none() && bundle.is_none() && audit.is_none() && statement.is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let agreement_signature = payload
        .get("agreement_signature")
        .cloned()
        .map(serde_json::from_value::<AgreementSignatureEnvelope>)
        .transpose()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if let Some(signature_ref) = agreement_signature.as_ref() {
        validate_agreement_signature_envelope(signature_ref)
            .map_err(|_| StatusCode::BAD_REQUEST)?;
    }
    let bundle_signature = payload
        .get("bundle_signature")
        .cloned()
        .map(serde_json::from_value::<AgreementSignatureEnvelope>)
        .transpose()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if let Some(signature_ref) = bundle_signature.as_ref() {
        validate_agreement_signature_envelope(signature_ref)
            .map_err(|_| StatusCode::BAD_REQUEST)?;
    }
    let result = derive_artifact_verification(
        &state,
        agreement.as_ref(),
        bundle.as_ref(),
        audit.as_ref(),
        statement.as_ref(),
        agreement_signature.as_ref(),
        bundle_signature.as_ref(),
    )
    .await;
    Ok(settlement_surface(
        "agreementverifyartifacts",
        serde_json::to_value(&result).unwrap_or(Value::Null),
    ))
}

async fn agreement_share_package_verify_api(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;
    let package = payload
        .get("share_package")
        .cloned()
        .map(serde_json::from_value::<AgreementSharePackage>)
        .transpose()
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .ok_or(StatusCode::BAD_REQUEST)?;
    verify_agreement_share_package(&package).map_err(|_| StatusCode::BAD_REQUEST)?;
    let result = derive_share_package_verification(&state, &package)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(Json(serde_json::to_value(&result).unwrap_or(Value::Null)))
}

async fn agreement_share_package_verify_view(
    ConnectInfo(_addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Form(form): Form<AgreementHtmlForm>,
) -> Response {
    let package = match parse_optional_share_package_form(&form) {
        Ok(Some(v)) => v,
        Ok(None) => {
            return html_error(
                StatusCode::BAD_REQUEST,
                "Missing share package",
                "Paste a share-package JSON artifact to verify the handoff contents.",
            )
        }
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid share package", &e),
    };
    let result = match derive_share_package_verification(&state, &package).await {
        Ok(v) => v,
        Err(e) => {
            return html_error(
                StatusCode::BAD_GATEWAY,
                "Share package verification unavailable",
                &e,
            )
        }
    };
    let header = if let Some(agreement_ref) = package
        .agreement
        .as_ref()
        .or_else(|| package.bundle.as_ref().map(|bundle| &bundle.agreement))
    {
        let agreement_hash = compute_agreement_hash_hex(agreement_ref).unwrap_or_default();
        agreement_header_markup(agreement_ref, &agreement_hash)
    } else {
        "<section><h1>Share package verification</h1><p class='notice'>No canonical agreement JSON was included. Package verification is limited to the supplied artifact identities and signature target checks.</p></section>".to_string()
    };
    html_page(
        "Agreement share package verification",
        format!(
            "{}{}{}{}{}{}",
            header,
            render_share_package_verification_section(&result),
            agreement_navigation_markup(),
            trust_boundary_markup(),
            agreement_verification_markup(),
            agreement_share_package_markup(),
        ),
    )
    .into_response()
}

async fn agreement_verify_artifacts_view(
    ConnectInfo(_addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Form(form): Form<AgreementHtmlForm>,
) -> Response {
    let (agreement, bundle) = match parse_optional_agreement_context_form(&form) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid agreement or bundle", &e),
    };
    let supplied_audit = match parse_optional_audit_form(&form) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid audit artifact", &e),
    };
    let supplied_statement = match parse_optional_statement_form(&form) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid statement artifact", &e),
    };
    let detached_agreement_signature = match parse_optional_agreement_signature_form(&form) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid agreement signature", &e),
    };
    let detached_bundle_signature = match parse_optional_bundle_signature_form(&form) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid bundle signature", &e),
    };
    if agreement.is_none()
        && bundle.is_none()
        && supplied_audit.is_none()
        && supplied_statement.is_none()
        && detached_agreement_signature.is_none()
        && detached_bundle_signature.is_none()
    {
        return html_error(
            StatusCode::BAD_REQUEST,
            "Missing artifacts",
            "Supply at least one canonical agreement, bundle, audit, or statement artifact.",
        );
    }
    let result = derive_artifact_verification(
        &state,
        agreement.as_ref(),
        bundle.as_ref(),
        supplied_audit.as_ref(),
        supplied_statement.as_ref(),
        detached_agreement_signature.as_ref(),
        detached_bundle_signature.as_ref(),
    )
    .await;
    let header = if let Some(agreement_ref) = agreement
        .as_ref()
        .or_else(|| bundle.as_ref().map(|b| &b.agreement))
    {
        let agreement_hash = compute_agreement_hash_hex(agreement_ref).unwrap_or_default();
        agreement_header_markup(agreement_ref, &agreement_hash)
    } else {
        "<section><h1>Artifact verification</h1><p class=\"notice\">No canonical agreement JSON was supplied. Verification is limited to artifact identity and consistency checks.</p></section>".to_string()
    };
    html_page(
        "Agreement artifact verification",
        format!(
            "{}{}{}{}{}{}",
            header,
            render_artifact_verification_section(&result),
            agreement_navigation_markup(),
            trust_boundary_markup(),
            agreement_verification_markup(),
            agreement_lookup_markup(),
        ),
    )
    .into_response()
}

fn render_signature_verification_block(
    detached: Option<&AgreementSignatureVerification>,
    embedded: &[AgreementSignatureVerification],
) -> String {
    let detached_markup = detached
        .map(|item| {
            format!(
                "<section><h2>Detached signature</h2><p><strong>Validity:</strong> {}</p><p><strong>Signer:</strong> {}</p><p><strong>Role:</strong> {}</p><p><strong>Target hash:</strong> <code>{}</code></p><p><strong>Expected target match:</strong> {}</p><p class='notice'>{}</p><ul>{}</ul></section>",
                item.valid,
                html_escape(item.signer_address.as_deref().unwrap_or(item.signer_public_key.as_str())),
                html_escape(item.signer_role.as_deref().unwrap_or("unspecified")),
                html_escape(&item.target_hash),
                item.matches_expected_target,
                html_escape(&item.authenticity_note),
                if item.warnings.is_empty() {
                    "<li>none</li>".to_string()
                } else {
                    item.warnings
                        .iter()
                        .map(|warning| format!("<li>{}</li>", html_escape(warning)))
                        .collect::<Vec<_>>()
                        .join("")
                }
            )
        })
        .unwrap_or_default();
    let embedded_markup = if embedded.is_empty() {
        "<section><h2>Embedded bundle signatures</h2><p>No embedded signatures were supplied in the bundle.</p></section>".to_string()
    } else {
        let rows = embedded
            .iter()
            .map(|item| {
                format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>",
                    item.valid,
                    html_escape(
                        item.signer_address
                            .as_deref()
                            .unwrap_or(item.signer_public_key.as_str())
                    ),
                    html_escape(item.signer_role.as_deref().unwrap_or("unspecified")),
                    item.matches_expected_target,
                    html_escape(&item.target_hash),
                )
            })
            .collect::<Vec<_>>()
            .join("");
        format!(
            "<section><h2>Embedded bundle signatures</h2><p class='notice'>Embedded signatures are checked offline against the supplied bundle hash. Validity proves authenticity only, not correctness or enforceability.</p><table><thead><tr><th>Valid</th><th>Signer</th><th>Role</th><th>Target match</th><th>Target hash</th></tr></thead><tbody>{}</tbody></table></section>",
            rows
        )
    };
    format!("{}{}", detached_markup, embedded_markup)
}

async fn agreement_verify_signature_api(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;
    let agreement = payload
        .get("agreement")
        .cloned()
        .map(serde_json::from_value::<AgreementObject>)
        .transpose()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if let Some(agreement_ref) = agreement.as_ref() {
        agreement_ref
            .validate()
            .map_err(|_| StatusCode::BAD_REQUEST)?;
    }
    let bundle = payload
        .get("bundle")
        .cloned()
        .map(serde_json::from_value::<AgreementBundle>)
        .transpose()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if let Some(bundle_ref) = bundle.as_ref() {
        verify_agreement_bundle(bundle_ref).map_err(|_| StatusCode::BAD_REQUEST)?;
    }
    let signature = payload
        .get("signature")
        .cloned()
        .map(serde_json::from_value::<AgreementSignatureEnvelope>)
        .transpose()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if agreement.is_none() && bundle.is_none() && signature.is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let agreement_hash = if let Some(agreement_ref) = agreement.as_ref() {
        Some(compute_agreement_hash_hex(agreement_ref).map_err(|_| StatusCode::BAD_REQUEST)?)
    } else {
        bundle
            .as_ref()
            .map(|bundle_ref| bundle_ref.agreement_hash.clone())
    };
    let bundle_hash = bundle
        .as_ref()
        .map(compute_agreement_bundle_hash_hex)
        .transpose()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let detached = signature.as_ref().map(|sig| {
        serde_json::to_value(inspect_agreement_signature(
            sig,
            agreement_hash.as_deref(),
            bundle_hash.as_deref(),
        ))
        .unwrap_or(Value::Null)
    });
    let embedded = bundle
        .as_ref()
        .map(|bundle_ref| {
            serde_json::to_value(verify_bundle_signatures(bundle_ref)).unwrap_or(Value::Null)
        })
        .unwrap_or_else(|| json!([]));
    Ok(Json(json!({
        "agreement_hash": agreement_hash,
        "bundle_hash": bundle_hash,
        "detached_signature": detached,
        "embedded_signatures": embedded,
        "authenticity_notice": "Valid signatures prove authorship or intent only. They do not prove the agreement is true or enforce settlement on-chain.",
    })))
}

async fn agreement_verify_signature_view(
    ConnectInfo(_addr): ConnectInfo<SocketAddr>,
    State(_state): State<AppState>,
    Form(form): Form<AgreementHtmlForm>,
) -> Response {
    let (agreement, bundle) = match parse_optional_agreement_context_form(&form) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid agreement or bundle", &e),
    };
    let signature = match parse_optional_signature_form(&form) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid signature", &e),
    };
    if agreement.is_none() && bundle.is_none() && signature.is_none() {
        return html_error(
            StatusCode::BAD_REQUEST,
            "Missing signature artifacts",
            "Supply a canonical agreement or bundle, plus detached signature JSON when needed.",
        );
    }
    let agreement_hash = if let Some(agreement_ref) = agreement.as_ref() {
        match compute_agreement_hash_hex(agreement_ref) {
            Ok(v) => Some(v),
            Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid agreement", &e),
        }
    } else {
        bundle
            .as_ref()
            .map(|bundle_ref| bundle_ref.agreement_hash.clone())
    };
    let bundle_hash = match bundle
        .as_ref()
        .map(compute_agreement_bundle_hash_hex)
        .transpose()
    {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid bundle", &e),
    };
    let detached = signature.as_ref().map(|sig| {
        inspect_agreement_signature(sig, agreement_hash.as_deref(), bundle_hash.as_deref())
    });
    let embedded = bundle
        .as_ref()
        .map(verify_bundle_signatures)
        .unwrap_or_default();
    let header = if let Some(agreement_ref) = agreement
        .as_ref()
        .or_else(|| bundle.as_ref().map(|b| &b.agreement))
    {
        agreement_header_markup(agreement_ref, agreement_hash.as_deref().unwrap_or_default())
    } else {
        "<section><h1>Signature verification</h1><p class='notice'>No canonical agreement JSON was supplied. Verification is limited to the supplied signature target hashes and any embedded bundle signatures.</p></section>".to_string()
    };
    html_page(
        "Agreement signature verification",
        format!(
            "{}{}{}{}{}{}{}",
            header,
            bundle_context_markup(bundle.as_ref()),
            render_signature_verification_block(detached.as_ref(), &embedded),
            agreement_navigation_markup(),
            trust_boundary_markup(),
            agreement_signature_markup(),
            agreement_form_markup(&form.agreement_json),
        ),
    )
    .into_response()
}

async fn agreement_statement_api(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;
    let audit_payload = proxy_post_json(&state, "/rpc/agreementaudit", payload).await?;
    let record: AgreementAuditRecord =
        serde_json::from_value(audit_payload).map_err(|_| StatusCode::BAD_GATEWAY)?;
    Ok(Json(
        serde_json::to_value(build_agreement_statement(&record)).unwrap_or_default(),
    ))
}

async fn agreement_statement_download_json(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AgreementHtmlForm>,
) -> Response {
    if let Err(status) = check_rate(&state, &addr, &headers) {
        return html_error(
            status,
            "Rate limit",
            "Request rejected by explorer rate limit",
        );
    }
    let payload = match agreement_context_payload(&form) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid agreement", &e),
    };
    let (agreement, _bundle) = match parse_agreement_context_form(&form) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid agreement", &e),
    };
    let audit_payload = match proxy_post_json(&state, "/rpc/agreementaudit", payload).await {
        Ok(v) => v,
        Err(status) => {
            return html_error(
                status,
                "Agreement statement unavailable",
                "Node RPC agreementaudit failed",
            )
        }
    };
    let mut record: AgreementAuditRecord = match serde_json::from_value(audit_payload) {
        Ok(v) => v,
        Err(e) => {
            return html_error(
                StatusCode::BAD_GATEWAY,
                "Agreement statement unavailable",
                &format!("invalid audit payload: {e}"),
            )
        }
    };
    let detached_agreement_signature = match parse_optional_agreement_signature_form(&form) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid agreement signature", &e),
    };
    let detached_bundle_signature = match parse_optional_bundle_signature_form(&form) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid bundle signature", &e),
    };
    let (_, bundle) = match parse_agreement_context_form(&form) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid agreement", &e),
    };
    let detached_agreement_signatures =
        detached_agreement_signature.into_iter().collect::<Vec<_>>();
    let detached_bundle_signatures = detached_bundle_signature.into_iter().collect::<Vec<_>>();
    attach_authenticity_to_audit(
        &mut record,
        &agreement,
        bundle.as_ref(),
        &detached_agreement_signatures,
        &detached_bundle_signatures,
    );
    let statement = build_agreement_statement(&record);
    let rendered = match serde_json::to_string_pretty(&statement) {
        Ok(v) => v,
        Err(e) => {
            return html_error(
                StatusCode::BAD_GATEWAY,
                "Agreement statement unavailable",
                &format!("invalid statement payload: {e}"),
            )
        }
    };
    let filename = audit_download_filename(&agreement.agreement_id, "statement.json");
    let mut resp = rendered.into_response();
    resp.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    let disposition = format!("attachment; filename=\"{}\"", filename);
    if let Ok(value) = HeaderValue::from_str(&disposition) {
        resp.headers_mut().insert(CONTENT_DISPOSITION, value);
    }
    resp
}

async fn agreement_audit_download_json(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AgreementHtmlForm>,
) -> Response {
    if let Err(status) = check_rate(&state, &addr, &headers) {
        return html_error(
            status,
            "Rate limit",
            "Request rejected by explorer rate limit",
        );
    }
    let payload = match agreement_context_payload(&form) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid agreement", &e),
    };
    let (agreement, _bundle) = match parse_agreement_context_form(&form) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid agreement", &e),
    };
    let audit_payload = match proxy_post_json(&state, "/rpc/agreementaudit", payload).await {
        Ok(v) => v,
        Err(status) => {
            return html_error(
                status,
                "Agreement audit unavailable",
                "Node RPC agreementaudit failed",
            )
        }
    };
    let rendered = match serde_json::to_string_pretty(&audit_payload) {
        Ok(v) => v,
        Err(e) => {
            return html_error(
                StatusCode::BAD_GATEWAY,
                "Agreement audit unavailable",
                &format!("invalid audit payload: {e}"),
            )
        }
    };
    let filename = audit_download_filename(&agreement.agreement_id, "json");
    let mut resp = rendered.into_response();
    resp.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    let disposition = format!("attachment; filename=\"{}\"", filename);
    if let Ok(value) = HeaderValue::from_str(&disposition) {
        resp.headers_mut().insert(CONTENT_DISPOSITION, value);
    }
    resp
}

async fn agreement_audit_download_csv(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AgreementHtmlForm>,
) -> Response {
    if let Err(status) = check_rate(&state, &addr, &headers) {
        return html_error(
            status,
            "Rate limit",
            "Request rejected by explorer rate limit",
        );
    }
    let payload = match agreement_context_payload(&form) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid agreement", &e),
    };
    let (agreement, _bundle) = match parse_agreement_context_form(&form) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid agreement", &e),
    };
    let audit_payload = match proxy_post_json(&state, "/rpc/agreementaudit", payload).await {
        Ok(v) => v,
        Err(status) => {
            return html_error(
                status,
                "Agreement audit unavailable",
                "Node RPC agreementaudit failed",
            )
        }
    };
    let record: AgreementAuditRecord = match serde_json::from_value(audit_payload) {
        Ok(v) => v,
        Err(e) => {
            return html_error(
                StatusCode::BAD_GATEWAY,
                "Agreement audit unavailable",
                &format!("invalid audit payload: {e}"),
            )
        }
    };
    let rendered = render_agreement_audit_csv(&record);
    let filename = audit_download_filename(&agreement.agreement_id, "csv");
    let mut resp = rendered.into_response();
    resp.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    let disposition = format!("attachment; filename=\"{}\"", filename);
    if let Ok(value) = HeaderValue::from_str(&disposition) {
        resp.headers_mut().insert(CONTENT_DISPOSITION, value);
    }
    resp
}

fn agreement_lookup_response(
    tx: &TxLookupResponse,
    anchors: Vec<Value>,
    agreement_hash: Option<&str>,
) -> Value {
    let matched = agreement_hash
        .map(|h| {
            anchors
                .iter()
                .any(|a| a.get("agreement_hash").and_then(|v| v.as_str()) == Some(h))
        })
        .unwrap_or(false);
    json!({
        "lookup_mode": "txid_anchor_scan",
        "txid": tx.txid,
        "height": tx.height,
        "block_hash": tx.block_hash,
        "agreement_hash": agreement_hash,
        "tx_found": true,
        "matched": matched,
        "anchors": anchors,
        "limitation": if agreement_hash.is_some() {
            "Txid lookup can confirm anchor presence for the supplied agreement hash, but full lifecycle and milestone reconstruction still requires the canonical agreement JSON or an exported agreement bundle."
        } else {
            "Txid lookup can only discover anchor hashes and roles from on-chain OP_RETURN data. It cannot recover the full agreement object, a saved bundle, or metadata-derived lifecycle by itself."
        }
    })
}

async fn lookup_tx_anchors(
    state: &AppState,
    txid: &str,
) -> Result<(TxLookupResponse, Vec<Value>), StatusCode> {
    let tx_value = proxy_value(state, &format!("/rpc/tx?txid={}", txid)).await?;
    let tx: TxLookupResponse =
        serde_json::from_value(tx_value).map_err(|_| StatusCode::BAD_GATEWAY)?;
    let raw = hex::decode(tx.tx_hex.trim()).map_err(|_| StatusCode::BAD_GATEWAY)?;
    let parsed = decode_full_tx(&raw).map_err(|_| StatusCode::BAD_GATEWAY)?;
    let anchors = parsed
        .outputs
        .iter()
        .enumerate()
        .filter_map(|(vout, out)| {
            parse_agreement_anchor(&out.script_pubkey).map(|anchor| {
                json!({
                    "agreement_hash": anchor.agreement_hash,
                    "role": anchor.role.short_code(),
                    "milestone_id": anchor.milestone_id,
                    "vout": vout,
                })
            })
        })
        .collect::<Vec<_>>();
    Ok((tx, anchors))
}

async fn agreement_lookup_api(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AgreementHtmlForm>,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;
    let txid = form
        .lookup_txid
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let agreement_hash = form
        .agreement_hash
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let (tx, anchors) = lookup_tx_anchors(&state, txid).await?;
    Ok(Json(
        settlement_surface(
            "agreementlookup",
            agreement_lookup_response(&tx, anchors, agreement_hash),
        )
        .0,
    ))
}

async fn agreement_inspect_view(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AgreementHtmlForm>,
) -> Response {
    if let Err(status) = check_rate(&state, &addr, &headers) {
        return html_error(
            status,
            "Rate limit",
            "Request rejected by explorer rate limit",
        );
    }
    let (agreement, bundle) = match parse_agreement_context_form(&form) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid agreement", &e),
    };
    let agreement_hash = match compute_agreement_hash_hex(&agreement) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Agreement hash failed", &e),
    };
    let payload = json!({"agreement": agreement.clone()});
    let inspect = match proxy_post_json(&state, "/rpc/inspectagreement", payload).await {
        Ok(v) => v,
        Err(status) => {
            return html_error(status, "Inspect failed", "Node RPC inspectagreement failed")
        }
    };
    let summary = inspect.get("summary").cloned().unwrap_or(Value::Null);
    html_page(
        "Agreement inspect",
        format!(
            "{}{}<section><h2>Inspection</h2><pre>{}</pre></section>{}{}{}{}",
            agreement_header_markup(&agreement, &agreement_hash),
            bundle_context_markup(bundle.as_ref()),
            html_escape(&serde_json::to_string_pretty(&summary).unwrap_or_default()),
            agreement_navigation_markup(),
            trust_boundary_markup(),
            agreement_form_markup(&form.agreement_json),
            agreement_lookup_markup(),
        ),
    )
    .into_response()
}

async fn agreement_status_view(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AgreementHtmlForm>,
) -> Response {
    if let Err(status) = check_rate(&state, &addr, &headers) {
        return html_error(
            status,
            "Rate limit",
            "Request rejected by explorer rate limit",
        );
    }
    let agreement = match parse_agreement_form(&form) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid agreement", &e),
    };
    let agreement_hash = match compute_agreement_hash_hex(&agreement) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Agreement hash failed", &e),
    };
    let payload = json!({"agreement": agreement.clone()});
    let status_payload = match proxy_post_json(&state, "/rpc/agreementstatus", payload).await {
        Ok(v) => v,
        Err(status) => {
            return html_error(status, "Status failed", "Node RPC agreementstatus failed")
        }
    };
    let lifecycle = status_payload
        .get("lifecycle")
        .cloned()
        .unwrap_or(Value::Null);
    html_page(
        "Agreement status",
        format!(
            r#"{}<section><h2>Status</h2><p><strong>State:</strong> {}</p><p><strong>Funded amount:</strong> {}</p><p><strong>Released amount:</strong> {}</p><p><strong>Refunded amount:</strong> {}</p><p class="notice">This lifecycle is reconstructed software state. It is not native consensus settlement state.</p><pre>{}</pre></section>{}{}{}{}"#,
            agreement_header_markup(&agreement, &agreement_hash),
            html_escape(lifecycle.get("state").and_then(|v| v.as_str()).unwrap_or("unknown")),
            lifecycle.get("funded_amount").and_then(|v| v.as_u64()).unwrap_or(0),
            lifecycle.get("released_amount").and_then(|v| v.as_u64()).unwrap_or(0),
            lifecycle.get("refunded_amount").and_then(|v| v.as_u64()).unwrap_or(0),
            html_escape(&serde_json::to_string_pretty(&lifecycle).unwrap_or_default()),
            agreement_navigation_markup(),
            trust_boundary_markup(),
            agreement_form_markup(&form.agreement_json),
            agreement_lookup_markup(),
        ),
    ).into_response()
}

async fn agreement_milestones_view(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AgreementHtmlForm>,
) -> Response {
    if let Err(status) = check_rate(&state, &addr, &headers) {
        return html_error(
            status,
            "Rate limit",
            "Request rejected by explorer rate limit",
        );
    }
    let agreement = match parse_agreement_form(&form) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid agreement", &e),
    };
    let agreement_hash = match compute_agreement_hash_hex(&agreement) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Agreement hash failed", &e),
    };
    let payload = json!({"agreement": agreement.clone()});
    let milestones_payload =
        match proxy_post_json(&state, "/rpc/agreementmilestones", payload).await {
            Ok(v) => v,
            Err(status) => {
                return html_error(
                    status,
                    "Milestones failed",
                    "Node RPC agreementmilestones failed",
                )
            }
        };
    let rows = milestones_payload
        .get("milestones")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let table_rows = if rows.is_empty() {
        r#"<tr><td colspan="6">No milestones defined for this agreement.</td></tr>"#.to_string()
    } else {
        rows.into_iter().map(|row| format!("<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>", html_escape(row.get("milestone_id").and_then(|v| v.as_str()).unwrap_or("")), html_escape(row.get("title").and_then(|v| v.as_str()).unwrap_or("")), row.get("amount").and_then(|v| v.as_u64()).unwrap_or(0), row.get("funded").and_then(|v| v.as_bool()).unwrap_or(false), row.get("released").and_then(|v| v.as_bool()).unwrap_or(false), row.get("refunded").and_then(|v| v.as_bool()).unwrap_or(false))).collect::<Vec<_>>().join("")
    };
    html_page(
        "Agreement milestones",
        format!(
            r#"{}<section><h2>Milestones</h2><table><thead><tr><th>ID</th><th>Title</th><th>Amount</th><th>Funded</th><th>Released</th><th>Refunded</th></tr></thead><tbody>{}</tbody></table><p class="notice">Milestone progress is metadata/indexed interpretation on top of linked transactions.</p></section>{}{}{}{}"#,
            agreement_header_markup(&agreement, &agreement_hash),
            table_rows,
            agreement_navigation_markup(),
            trust_boundary_markup(),
            agreement_form_markup(&form.agreement_json),
            agreement_lookup_markup(),
        ),
    ).into_response()
}

async fn agreement_txs_view(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AgreementHtmlForm>,
) -> Response {
    if let Err(status) = check_rate(&state, &addr, &headers) {
        return html_error(
            status,
            "Rate limit",
            "Request rejected by explorer rate limit",
        );
    }
    let agreement = match parse_agreement_form(&form) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid agreement", &e),
    };
    let agreement_hash = match compute_agreement_hash_hex(&agreement) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Agreement hash failed", &e),
    };
    let payload = json!({"agreement": agreement.clone()});
    let txs_payload = match proxy_post_json(&state, "/rpc/listagreementtxs", payload).await {
        Ok(v) => v,
        Err(status) => {
            return html_error(
                status,
                "Transaction history failed",
                "Node RPC listagreementtxs failed",
            )
        }
    };
    let rows = txs_payload
        .get("txs")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let table_rows = if rows.is_empty() {
        r#"<tr><td colspan="6">No linked transactions found for this agreement.</td></tr>"#
            .to_string()
    } else {
        rows.into_iter().map(|row| format!("<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>", html_escape(row.get("txid").and_then(|v| v.as_str()).unwrap_or("")), html_escape(row.get("role").and_then(|v| v.as_str()).unwrap_or("")), html_escape(row.get("milestone_id").and_then(|v| v.as_str()).unwrap_or("")), row.get("value").and_then(|v| v.as_u64()).unwrap_or(0), row.get("height").map(|v| html_escape(&v.to_string())).unwrap_or_else(|| "-".to_string()), row.get("confirmed").and_then(|v| v.as_bool()).unwrap_or(false))).collect::<Vec<_>>().join("")
    };
    html_page(
        "Agreement transactions",
        format!(
            "{}<section><h2>Linked transactions</h2><table><thead><tr><th>Txid</th><th>Role</th><th>Milestone</th><th>Value</th><th>Height</th><th>Confirmed</th></tr></thead><tbody>{}</tbody></table></section>{}{}{}{}",
            agreement_header_markup(&agreement, &agreement_hash),
            table_rows,
            agreement_navigation_markup(),
            trust_boundary_markup(),
            agreement_form_markup(&form.agreement_json),
            agreement_lookup_markup(),
        ),
    ).into_response()
}

async fn agreement_funding_legs_view(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AgreementHtmlForm>,
) -> Response {
    if let Err(status) = check_rate(&state, &addr, &headers) {
        return html_error(
            status,
            "Rate limit",
            "Request rejected by explorer rate limit",
        );
    }
    let agreement = match parse_agreement_form(&form) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid agreement", &e),
    };
    let agreement_hash = match compute_agreement_hash_hex(&agreement) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Agreement hash failed", &e),
    };
    let payload = match agreement_context_payload(&form) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid agreement", &e),
    };
    let funding_payload = match proxy_post_json(&state, "/rpc/agreementfundinglegs", payload).await
    {
        Ok(v) => v,
        Err(status) => {
            return html_error(
                status,
                "Funding leg discovery failed",
                "Node RPC agreementfundinglegs failed",
            )
        }
    };
    let rows = funding_payload
        .get("candidates")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let table_rows = if rows.is_empty() {
        r#"<tr><td colspan="8">No HTLC-backed funding leg candidates were discovered from the observed agreement anchors. Provide a funding txid manually if you already know the leg, or ensure the canonical agreement and linked anchor observations line up.</td></tr>"#.to_string()
    } else {
        rows.into_iter().map(|row| format!("<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>", html_escape(row.get("funding_txid").and_then(|v| v.as_str()).unwrap_or("")), row.get("htlc_vout").map(|v| html_escape(&v.to_string())).unwrap_or_else(|| "-".to_string()), html_escape(row.get("role").and_then(|v| v.as_str()).unwrap_or("")), html_escape(row.get("milestone_id").and_then(|v| v.as_str()).unwrap_or("")), row.get("amount").map(|v| html_escape(&v.to_string())).unwrap_or_else(|| "-".to_string()), row.get("release_eligible").map(|v| html_escape(&v.to_string())).unwrap_or_else(|| "false".to_string()), row.get("refund_eligible").map(|v| html_escape(&v.to_string())).unwrap_or_else(|| "false".to_string()), html_escape(&row.get("source_notes").and_then(|v| serde_json::to_string(v).ok()).unwrap_or_default()))).collect::<Vec<_>>().join("")
    };
    html_page(
        "Agreement funding legs",
        format!(
            r#"{}<section><h2>Funding leg discovery</h2><table><thead><tr><th>Funding txid</th><th>HTLC vout</th><th>Role</th><th>Milestone</th><th>Amount</th><th>Release eligible</th><th>Refund eligible</th><th>Source notes</th></tr></thead><tbody>{}</tbody></table><p class="notice">These are discovered convenience candidates derived from the supplied agreement/bundle plus observed anchors. They are not native agreement UTXO state, and explicit operator selection is still required when multiple candidates exist.</p><pre>{}</pre></section>{}{}{}{}"#,
            agreement_header_markup(&agreement, &agreement_hash),
            table_rows,
            html_escape(&serde_json::to_string_pretty(&funding_payload).unwrap_or_default()),
            agreement_navigation_markup(),
            trust_boundary_markup(),
            agreement_form_markup(&form.agreement_json),
            agreement_lookup_markup(),
        ),
    ).into_response()
}

async fn agreement_timeline_view(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AgreementHtmlForm>,
) -> Response {
    if let Err(status) = check_rate(&state, &addr, &headers) {
        return html_error(
            status,
            "Rate limit",
            "Request rejected by explorer rate limit",
        );
    }
    let agreement = match parse_agreement_form(&form) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid agreement", &e),
    };
    let agreement_hash = match compute_agreement_hash_hex(&agreement) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Agreement hash failed", &e),
    };
    let payload = match agreement_context_payload(&form) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid agreement", &e),
    };
    let timeline_payload = match proxy_post_json(&state, "/rpc/agreementtimeline", payload).await {
        Ok(v) => v,
        Err(status) => {
            return html_error(
                status,
                "Timeline failed",
                "Node RPC agreementtimeline failed",
            )
        }
    };
    let rows = timeline_payload
        .get("events")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let table_rows = if rows.is_empty() {
        r#"<tr><td colspan="7">No derived agreement events were produced for this context.</td></tr>"#.to_string()
    } else {
        rows.into_iter().map(|row| format!("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>", html_escape(row.get("event_type").and_then(|v| v.as_str()).unwrap_or("")), html_escape(row.get("source").and_then(|v| v.as_str()).unwrap_or("")), row.get("height").map(|v| html_escape(&v.to_string())).unwrap_or_else(|| "-".to_string()), row.get("timestamp").map(|v| html_escape(&v.to_string())).unwrap_or_else(|| "-".to_string()), html_escape(row.get("txid").and_then(|v| v.as_str()).unwrap_or("")), html_escape(row.get("milestone_id").and_then(|v| v.as_str()).unwrap_or("")), html_escape(row.get("note").and_then(|v| v.as_str()).unwrap_or("")))).collect::<Vec<_>>().join("")
    };
    html_page(
        "Agreement timeline",
        format!(
            r#"{}<section><h2>Reconstructed activity timeline</h2><table><thead><tr><th>Event</th><th>Source</th><th>Height</th><th>Timestamp</th><th>Txid</th><th>Milestone</th><th>Note</th></tr></thead><tbody>{}</tbody></table><p class="notice">This timeline is reconstructed software history from the supplied agreement or bundle plus chain observation. It is not consensus-native agreement state and does not imply subjective settlement finality.</p><pre>{}</pre></section>{}{}{}{}"#,
            agreement_header_markup(&agreement, &agreement_hash),
            table_rows,
            html_escape(&serde_json::to_string_pretty(&timeline_payload).unwrap_or_default()),
            agreement_navigation_markup(),
            trust_boundary_markup(),
            agreement_form_markup(&form.agreement_json),
            agreement_lookup_markup(),
        ),
    ).into_response()
}

async fn agreement_audit_view(
    ConnectInfo(_addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Form(form): Form<AgreementHtmlForm>,
) -> Response {
    let payload = match agreement_context_payload(&form) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid agreement", &e),
    };
    let agreement = match parse_agreement_form(&form) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid agreement", &e),
    };
    let agreement_hash = match compute_agreement_hash_hex(&agreement) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid agreement", &e),
    };
    let audit_payload = match proxy_post_json(&state, "/rpc/agreementaudit", payload).await {
        Ok(v) => v,
        Err(status) => {
            return html_error(
                status,
                "Agreement audit unavailable",
                "Node RPC agreementaudit failed",
            )
        }
    };
    let mut record: AgreementAuditRecord = match serde_json::from_value(audit_payload.clone()) {
        Ok(v) => v,
        Err(e) => {
            return html_error(
                StatusCode::BAD_GATEWAY,
                "Agreement audit unavailable",
                &format!("invalid audit payload: {e}"),
            )
        }
    };
    let detached_agreement_signature = match parse_optional_agreement_signature_form(&form) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid agreement signature", &e),
    };
    let detached_bundle_signature = match parse_optional_bundle_signature_form(&form) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid bundle signature", &e),
    };
    let (_, bundle) = match parse_agreement_context_form(&form) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid agreement", &e),
    };
    let detached_agreement_signatures =
        detached_agreement_signature.into_iter().collect::<Vec<_>>();
    let detached_bundle_signatures = detached_bundle_signature.into_iter().collect::<Vec<_>>();
    attach_authenticity_to_audit(
        &mut record,
        &agreement,
        bundle.as_ref(),
        &detached_agreement_signatures,
        &detached_bundle_signatures,
    );
    let authenticity_markup = record.authenticity.as_ref().map(|authenticity| format!("<h3>Authenticity</h3><p><strong>Detached agreement signatures:</strong> {}</p><p><strong>Detached bundle signatures:</strong> {}</p><p><strong>Embedded bundle signatures:</strong> {}</p><p><strong>Valid:</strong> {} <strong>Invalid:</strong> {} <strong>Unverifiable:</strong> {}</p><p class='notice'>{}</p>", authenticity.detached_agreement_signatures_supplied, authenticity.detached_bundle_signatures_supplied, authenticity.embedded_bundle_signatures_supplied, authenticity.valid_signatures, authenticity.invalid_signatures, authenticity.unverifiable_signatures, html_escape(&authenticity.authenticity_notice))).unwrap_or_default();
    let selected_leg = record
        .funding_legs
        .selected_leg
        .as_ref()
        .map(|leg| {
            format!(
                "<p><strong>Selected leg:</strong> <code>{}</code> vout {} milestone {}</p>",
                html_escape(&leg.funding_txid),
                leg.htlc_vout,
                html_escape(leg.milestone_id.as_deref().unwrap_or("-"))
            )
        })
        .unwrap_or_default();
    let html = format!(
        r#"{}<section><h2>Agreement audit record</h2><p><strong>Derived state:</strong> {}</p><p><strong>Generated at:</strong> {}</p><p><strong>Bundle used:</strong> {}</p><p><strong>Linked tx count:</strong> {}</p><p><strong>Funding-leg candidates:</strong> {}</p>{}<p class="notice">This audit record is derived from the supplied agreement or bundle plus observed chain activity. It is useful for OTC, contractor, and merchant settlement review, but it is not native consensus contract state.</p>{}{}{}<h3>Trust boundaries</h3><ul><li><strong>Consensus:</strong> {}</li><li><strong>HTLC:</strong> {}</li><li><strong>Derived:</strong> {}</li><li><strong>Local bundle:</strong> {}</li><li><strong>Off-chain required:</strong> {}</li></ul><pre>{}</pre></section>{}{}{}{}{}"#,
        agreement_header_markup(&agreement, &agreement_hash),
        html_escape(&record.settlement_state.derived_state_label),
        record.metadata.generated_at,
        record.local_bundle.bundle_used,
        record.chain_observed.linked_transaction_count,
        record.funding_legs.candidate_count,
        selected_leg,
        agreement_statement_download_markup(&form.agreement_json),
        agreement_audit_download_markup(&form.agreement_json),
        authenticity_markup,
        html_escape(&record.trust_boundaries.consensus_enforced.join(" | ")),
        html_escape(&record.trust_boundaries.htlc_enforced.join(" | ")),
        html_escape(&record.trust_boundaries.metadata_indexed.join(" | ")),
        html_escape(&record.trust_boundaries.local_bundle_only.join(" | ")),
        html_escape(&record.trust_boundaries.off_chain_required.join(" | ")),
        html_escape(&serde_json::to_string_pretty(&audit_payload).unwrap_or_default()),
        agreement_navigation_markup(),
        trust_boundary_markup(),
        agreement_form_markup(&form.agreement_json),
        agreement_verification_markup(),
        agreement_lookup_markup(),
    );
    html_page("Agreement audit", html).into_response()
}

async fn agreement_statement_view(
    ConnectInfo(_addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Form(form): Form<AgreementHtmlForm>,
) -> Response {
    let payload = match agreement_context_payload(&form) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid agreement", &e),
    };
    let agreement = match parse_agreement_form(&form) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid agreement", &e),
    };
    let agreement_hash = match compute_agreement_hash_hex(&agreement) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid agreement", &e),
    };
    let audit_payload = match proxy_post_json(&state, "/rpc/agreementaudit", payload).await {
        Ok(v) => v,
        Err(status) => {
            return html_error(
                status,
                "Agreement statement unavailable",
                "Node RPC agreementaudit failed",
            )
        }
    };
    let record: AgreementAuditRecord = match serde_json::from_value(audit_payload) {
        Ok(v) => v,
        Err(e) => {
            return html_error(
                StatusCode::BAD_GATEWAY,
                "Agreement statement unavailable",
                &format!("invalid audit payload: {e}"),
            )
        }
    };
    let statement = build_agreement_statement(&record);
    let html = format!(
        r#"{}{}{}{}{}{}"#,
        agreement_header_markup(&agreement, &agreement_hash),
        render_statement_section(&statement),
        agreement_statement_download_markup(&form.agreement_json),
        agreement_navigation_markup(),
        trust_boundary_markup(),
        agreement_form_markup(&form.agreement_json),
    );
    html_page(
        "Agreement statement",
        format!(
            "{}{}{}",
            html,
            agreement_verification_markup(),
            agreement_lookup_markup()
        ),
    )
    .into_response()
}

async fn agreement_release_eligibility_view(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AgreementHtmlForm>,
) -> Response {
    if let Err(status) = check_rate(&state, &addr, &headers) {
        return html_error(
            status,
            "Rate limit",
            "Request rejected by explorer rate limit",
        );
    }
    let agreement = match parse_agreement_form(&form) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid agreement", &e),
    };
    let agreement_hash = match compute_agreement_hash_hex(&agreement) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Agreement hash failed", &e),
    };
    let funding_txid = match form.funding_txid.clone() {
        Some(v) if !v.trim().is_empty() => v,
        _ => {
            return html_error(
                StatusCode::BAD_REQUEST,
                "Missing funding txid",
                "Release eligibility requires a funding txid",
            )
        }
    };
    let payload = json!({"agreement": agreement.clone(), "funding_txid": funding_txid, "htlc_vout": form.htlc_vout, "milestone_id": form.milestone_id, "destination_address": form.destination_address, "secret_hex": form.secret_hex, "broadcast": false});
    let eligibility =
        match proxy_post_json(&state, "/rpc/agreementreleaseeligibility", payload).await {
            Ok(v) => v,
            Err(status) => {
                return html_error(
                    status,
                    "Release eligibility failed",
                    "Node RPC agreementreleaseeligibility failed",
                )
            }
        };
    html_page(
        "Agreement release eligibility",
        format!(
            r#"{}<section><h2>Release eligibility</h2><pre>{}</pre><p class="notice">Release is only available when the linked funding leg is HTLC-backed and the required preimage or destination conditions are satisfied.</p></section>{}{}{}{}"#,
            agreement_header_markup(&agreement, &agreement_hash),
            html_escape(&serde_json::to_string_pretty(&eligibility).unwrap_or_default()),
            agreement_navigation_markup(),
            trust_boundary_markup(),
            agreement_form_markup(&form.agreement_json),
            agreement_lookup_markup(),
        ),
    ).into_response()
}

async fn agreement_refund_eligibility_view(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AgreementHtmlForm>,
) -> Response {
    if let Err(status) = check_rate(&state, &addr, &headers) {
        return html_error(
            status,
            "Rate limit",
            "Request rejected by explorer rate limit",
        );
    }
    let agreement = match parse_agreement_form(&form) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Invalid agreement", &e),
    };
    let agreement_hash = match compute_agreement_hash_hex(&agreement) {
        Ok(v) => v,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, "Agreement hash failed", &e),
    };
    let funding_txid = match form.funding_txid.clone() {
        Some(v) if !v.trim().is_empty() => v,
        _ => {
            return html_error(
                StatusCode::BAD_REQUEST,
                "Missing funding txid",
                "Refund eligibility requires a funding txid",
            )
        }
    };
    let payload = json!({"agreement": agreement.clone(), "funding_txid": funding_txid, "htlc_vout": form.htlc_vout, "milestone_id": form.milestone_id, "destination_address": form.destination_address, "broadcast": false});
    let eligibility =
        match proxy_post_json(&state, "/rpc/agreementrefundeligibility", payload).await {
            Ok(v) => v,
            Err(status) => {
                return html_error(
                    status,
                    "Refund eligibility failed",
                    "Node RPC agreementrefundeligibility failed",
                )
            }
        };
    html_page(
        "Agreement refund eligibility",
        format!(
            r#"{}<section><h2>Refund eligibility</h2><pre>{}</pre><p class="notice">Refund remains a user-built HTLC timeout spend. It is not automatic settlement execution.</p></section>{}{}{}{}"#,
            agreement_header_markup(&agreement, &agreement_hash),
            html_escape(&serde_json::to_string_pretty(&eligibility).unwrap_or_default()),
            agreement_navigation_markup(),
            trust_boundary_markup(),
            agreement_form_markup(&form.agreement_json),
            agreement_lookup_markup(),
        ),
    ).into_response()
}

async fn agreement_lookup_view(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AgreementHtmlForm>,
) -> Response {
    if let Err(status) = check_rate(&state, &addr, &headers) {
        return html_error(
            status,
            "Rate limit",
            "Request rejected by explorer rate limit",
        );
    }
    let txid = match form
        .lookup_txid
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(v) => v,
        None => {
            return html_error(
                StatusCode::BAD_REQUEST,
                "Missing txid",
                "Lookup requires a linked transaction id or funding transaction id.",
            )
        }
    };
    let agreement_hash = form
        .agreement_hash
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let (tx, anchors) = match lookup_tx_anchors(&state, txid).await {
        Ok(v) => v,
        Err(StatusCode::NOT_FOUND) => return html_error(StatusCode::NOT_FOUND, "Transaction not found", "The supplied txid was not found in explorer-backed node data. Txid-only lookup cannot recover agreement metadata without an indexed transaction."),
        Err(status) => return html_error(status, "Lookup failed", "Explorer could not inspect the linked transaction for agreement anchors."),
    };
    let matched = agreement_hash
        .map(|h| {
            anchors
                .iter()
                .any(|a| a.get("agreement_hash").and_then(|v| v.as_str()) == Some(h))
        })
        .unwrap_or(false);
    let rows = if anchors.is_empty() {
        r#"<tr><td colspan="4">No agreement anchors were discovered in this transaction. Explorer lookup cannot reconstruct an agreement from txid-only input when the transaction does not carry a settlement anchor.</td></tr>"#.to_string()
    } else {
        anchors
            .iter()
            .map(|row| {
                format!(
                    "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    html_escape(
                        row.get("agreement_hash")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                    ),
                    html_escape(row.get("role").and_then(|v| v.as_str()).unwrap_or("")),
                    html_escape(
                        row.get("milestone_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                    ),
                    row.get("vout").and_then(|v| v.as_u64()).unwrap_or(0),
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };
    let summary = if let Some(hash) = agreement_hash {
        format!("<p><strong>Requested agreement hash:</strong> <code>{}</code></p><p><strong>Anchor match in tx:</strong> {}</p>", html_escape(hash), matched)
    } else {
        "<p><strong>Requested agreement hash:</strong> none supplied. This lookup can discover anchor hashes, but not reconstruct the full agreement object.</p>".to_string()
    };
    html_page(
        "Agreement lookup",
        format!(
            r#"<section><h1>Agreement lookup</h1><p><strong>Txid:</strong> <code>{}</code></p><p><strong>Block hash:</strong> <code>{}</code></p><p><strong>Height:</strong> {}</p>{}<table><thead><tr><th>Agreement hash</th><th>Role</th><th>Milestone</th><th>Vout</th></tr></thead><tbody>{}</tbody></table><p class="notice">Txid lookup is limited to on-chain anchor discovery. Full agreement lifecycle, milestone meaning, and off-chain metadata still require the canonical agreement JSON.</p><p><a href="/tx/{}">Open raw transaction view</a></p></section>{}{}{}"#,
            html_escape(&tx.txid),
            html_escape(&tx.block_hash),
            tx.height,
            summary,
            rows,
            html_escape(&tx.txid),
            agreement_navigation_markup(),
            agreement_lookup_markup(),
            trust_boundary_markup(),
        ),
    ).into_response()
}

async fn fetch_stratum_metrics(state: &AppState) -> Option<Value> {
    let base = state.stratum_metrics_url.as_ref()?;
    let url = node_url(base, "/metrics");
    let resp = state.client.get(url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json::<Value>().await.ok()
}

async fn proxy_text(state: &AppState, path: &str) -> Result<Response, StatusCode> {
    let url = node_url(&state.node_base, path);
    let mut req = state.client.get(url);
    if let Some(token) = &state.rpc_token {
        if !token.is_empty() {
            req = req.bearer_auth(token);
        }
    }
    let resp = req.send().await.map_err(|_| StatusCode::BAD_GATEWAY)?;
    if !resp.status().is_success() {
        return Err(map_status(resp.status()));
    }
    let body = resp.text().await.map_err(|_| StatusCode::BAD_GATEWAY)?;
    Ok(body.into_response())
}

async fn refresh_active_miners_once(
    state: &AppState,
    window_blocks: u64,
) -> Result<MinersCache, String> {
    let status = proxy_value(state, "/status")
        .await
        .map_err(|e| format!("status: {e}"))?;
    let height = status.get("height").and_then(|v| v.as_u64()).unwrap_or(0);

    let window_blocks = window_blocks.max(1);
    let start = height.saturating_sub(window_blocks.saturating_sub(1));

    let mut miners = HashSet::new();
    let mut ok_blocks = 0u64;

    for h in start..=height {
        let path = format!("/rpc/block?height={}", h);
        match proxy_value(state, &path).await {
            Ok(mut block) => {
                ok_blocks += 1;
                enrich_miner_address(&mut block);
                let addr = block
                    .get("miner_address")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .unwrap_or("");
                if !addr.is_empty() && addr != "N/A" {
                    miners.insert(addr.to_string());
                }
            }
            Err(_) => {
                // Keep going; this is best-effort.
                continue;
            }
        }
    }

    Ok(MinersCache {
        active_miners: Some(miners.len() as u64),
        window_blocks: ok_blocks.max(1),
        as_of_height: height,
        updated_at_unix: now_unix(),
        last_error: None,
    })
}

async fn miners_refresher_task(state: AppState, window_blocks: u64, interval: Duration) {
    loop {
        match refresh_active_miners_once(&state, window_blocks).await {
            Ok(cache) => {
                let mut w = state.miners_cache.write().await;
                *w = cache;
            }
            Err(e) => {
                let mut w = state.miners_cache.write().await;
                w.updated_at_unix = now_unix();
                w.last_error = Some(e);
            }
        }
        tokio::time::sleep(interval).await;
    }
}

async fn status(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;
    proxy_json(&state, "/status").await
}

async fn peers(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;
    proxy_json(&state, "/peers").await
}

async fn metrics(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    check_rate(&state, &addr, &headers)?;
    proxy_text(&state, "/metrics").await
}

async fn stats(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;

    let status = proxy_value(&state, "/status").await?;
    let height = status.get("height").and_then(|v| v.as_u64()).unwrap_or(0);
    let peer_count = status.get("peer_count").and_then(|v| v.as_u64());

    // Supply calculation is deterministic; keep existing behavior.
    let mut total = 0u64;
    for h in 1..=height {
        total = total.saturating_add(block_reward(h));
    }

    let miners = state.miners_cache.read().await.clone();

    let payload = json!({
        "height": height,
        "total_blocks": height,
        "total": height,
        "supply_irm": (total as f64) / 100_000_000.0,
        "genesis_hash": status.get("genesis_hash"),

        // Live peers
        "peer_count": peer_count,
        "peers_connected": peer_count,

        // Approx miners: unique miner addresses observed in a rolling recent window.
        "active_miners": miners.active_miners,
        "active_miners_window_blocks": miners.window_blocks,
        "active_miners_as_of_height": miners.as_of_height,
        "active_miners_updated_at": miners.updated_at_unix,
        "active_miners_last_error": miners.last_error,
    });

    Ok(Json(payload))
}

async fn blocks(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<BlocksQuery>,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;
    let status = proxy_value(&state, "/status").await?;
    let height = status.get("height").and_then(|v| v.as_u64()).unwrap_or(0);
    let limit = q.limit.unwrap_or(50).min(200);
    let start = q.start.unwrap_or(height).min(height);
    let mut blocks = Vec::new();
    let mut h = start as i64;
    while h >= 0 && blocks.len() < limit {
        let path = format!("/rpc/block?height={}", h);
        if let Ok(mut block) = proxy_value(&state, &path).await {
            // Both, for parity with /rpc/blocks: miner_address must come from the first
            // P2PKH coinbase output, and the payees expose the full role split so a list
            // never reduces a four-worker block to "one miner, 50 IRM".
            enrich_miner_address(&mut block);
            attach_coinbase_payees(&mut block, h.max(0) as u64);
            blocks.push(block);
        }
        h -= 1;
    }
    let payload = json!({
        "height": height,
        "total_blocks": height,
        "total": height,
        "blocks": blocks,
    });
    Ok(Json(payload))
}

/// Scan a coinbase tx's raw bytes for its P2PKH outputs -> (base58 address, sats).
/// Uses the fixed P2PKH output pattern (`<8B value LE> 19 76a914 <20B pkh> 88ac`) rather
/// than a full tx parse -- coinbase outputs are all P2PKH or OP_RETURN, so this is exact
/// and avoids depending on a tx deserializer the lib doesn't expose.
fn decode_coinbase_payees(raw: &[u8]) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    let mut i = 8usize; // need 8 value bytes before the script-length byte
    while i + 26 <= raw.len() {
        if raw[i] == 0x19
            && raw[i + 1] == 0x76
            && raw[i + 2] == 0xa9
            && raw[i + 3] == 0x14
            && raw[i + 24] == 0x88
            && raw[i + 25] == 0xac
        {
            let val = u64::from_le_bytes(raw[i - 8..i].try_into().unwrap());
            let mut pkh = [0u8; 20];
            pkh.copy_from_slice(&raw[i + 4..i + 24]);
            out.push((irium_node_rs::storage::base58_p2pkh_from_hash(&pkh), val));
            i += 26;
        } else {
            i += 1;
        }
    }
    out
}

/// Coinbase payees of a block JSON as (address, sats), decoded from tx_hex[0].
fn block_coinbase_payees(block: &Value) -> Vec<(String, u64)> {
    let cb_hex = block
        .get("tx_hex")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .or_else(|| block.get("tx_hex").and_then(|v| v.as_str()));
    match cb_hex.and_then(|h| hex::decode(h.trim()).ok()) {
        Some(raw) => decode_coinbase_payees(&raw),
        None => Vec::new(),
    }
}

/// Attach `coinbase_payees` (address / amount_irm / share_pct) to a block JSON so
/// consumers see the PoAW-X reward SPLIT (proposer 55% + worker roles 22/13/10 to
/// distinct workers) rather than just the proposer + the full height-based subsidy.
fn attach_coinbase_payees(block: &mut Value, height: u64) {
    let total_sats = reward_irm_for_height(height) * 1e8;
    let payees: Vec<Value> = block_coinbase_payees(block)
        .into_iter()
        .map(|(addr, sats)| {
            json!({
                "address": addr,
                "amount_irm": (sats as f64) / 1e8,
                "share_pct": if total_sats > 0.0 {
                    ((sats as f64) / total_sats * 100.0 * 10.0).round() / 10.0
                } else { 0.0 },
            })
        })
        .collect();
    if let Some(obj) = block.as_object_mut() {
        obj.insert("coinbase_payee_count".into(), json!(payees.len()));
        obj.insert("coinbase_payees".into(), json!(payees));
    }
}

async fn block(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(height): Path<u64>,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;
    let mut v = proxy_value(&state, &format!("/rpc/block?height={}", height)).await?;
    // Both enrichments are wanted: miner_address must be derived from the first P2PKH
    // coinbase output (post-activation the payee moved behind an irx1 OP_RETURN), and the
    // payees expose the full role split rather than just the proposer.
    enrich_miner_address(&mut v);
    attach_coinbase_payees(&mut v, height);
    Ok(Json(v))
}

async fn blockhash(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(hash): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;
    let mut b = proxy_value(&state, &format!("/rpc/block_by_hash?hash={}", hash)).await?;
    enrich_miner_address(&mut b);
    Ok(Json(b))
}

// Enriched pass-throughs for the node's RAW /rpc block endpoints. The irium.org
// static explorer's detail modal fetches `/rpc/blocks?from=H&count=1` and
// `/rpc/block_by_hash?hash=..`, which proxy straight to the node (null
// miner_address). These mirror the node response verbatim and only fill in the
// derived first-P2PKH miner_address. Display-only; zero consensus effect.

async fn rpc_blocks_enriched(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(q): RawQuery,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;
    let path = match q {
        Some(q) if !q.is_empty() => format!("/rpc/blocks?{}", q),
        _ => "/rpc/blocks".to_string(),
    };
    let mut v = proxy_value(&state, &path).await?;
    if let Some(arr) = v.get_mut("blocks").and_then(|b| b.as_array_mut()) {
        for b in arr.iter_mut() {
            enrich_miner_address(b);
            // Attach the coinbase payees so consumers can show the PoAW-X reward SPLIT
            // (proposer 55% + compute/verify/support 22/13/10 to distinct workers) rather
            // than just the proposer and a flat subsidy. This is the endpoint the public
            // explorer page at irium.org/explorer/ actually reads.
            let height = b.get("height").and_then(|h| h.as_u64()).unwrap_or(0);
            attach_coinbase_payees(b, height);
        }
    }
    Ok(Json(v))
}

async fn rpc_block_by_hash_enriched(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(q): RawQuery,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;
    let path = match q {
        Some(q) if !q.is_empty() => format!("/rpc/block_by_hash?{}", q),
        _ => "/rpc/block_by_hash".to_string(),
    };
    let mut v = proxy_value(&state, &path).await?;
    enrich_miner_address(&mut v);
    Ok(Json(v))
}

async fn tx(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(txid): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;
    proxy_json(&state, &format!("/rpc/tx?txid={}", txid)).await
}

async fn address(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(address): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;
    let balance = proxy_value(&state, &format!("/rpc/balance?address={}", address)).await?;
    let utxos = proxy_value(&state, &format!("/rpc/utxos?address={}", address)).await?;
    let history = proxy_value(&state, &format!("/rpc/history?address={}", address)).await?;
    let payload = json!({
        "address": address,
        "balance": balance,
        "utxos": utxos,
        "history": history,
    });
    Ok(Json(payload))
}

async fn utxo(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<UtxoQuery>,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;
    proxy_json(
        &state,
        &format!("/rpc/utxo?txid={}&index={}", q.txid, q.index),
    )
    .await
}

async fn mining(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<MiningQuery>,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;
    let mut path = String::from("/rpc/mining_metrics");
    let mut first = true;
    if let Some(w) = q.window {
        path.push_str(if first { "?window=" } else { "&window=" });
        path.push_str(&w.to_string());
        first = false;
    }
    if let Some(n) = q.series {
        path.push_str(if first { "?series=" } else { "&series=" });
        path.push_str(&n.to_string());
    }
    proxy_json(&state, &path).await
}

async fn agreement_create(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;
    settlement_proxy(&state, "/rpc/createagreement", "createagreement", payload).await
}

async fn agreement_inspect(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;
    settlement_proxy(&state, "/rpc/inspectagreement", "inspectagreement", payload).await
}

async fn agreement_hash(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;
    settlement_proxy(
        &state,
        "/rpc/computeagreementhash",
        "computeagreementhash",
        payload,
    )
    .await
}

async fn agreement_fund(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;
    settlement_proxy(&state, "/rpc/fundagreement", "fundagreement", payload).await
}

async fn agreement_status_api(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;
    settlement_proxy(&state, "/rpc/agreementstatus", "agreementstatus", payload).await
}

async fn agreement_milestones_api(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;
    settlement_proxy(
        &state,
        "/rpc/agreementmilestones",
        "agreementmilestones",
        payload,
    )
    .await
}

async fn agreement_txs_api(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;
    settlement_proxy(&state, "/rpc/listagreementtxs", "listagreementtxs", payload).await
}

async fn agreement_verify_link_api(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;
    settlement_proxy(
        &state,
        "/rpc/verifyagreementlink",
        "verifyagreementlink",
        payload,
    )
    .await
}

/// The public Stratum pool was retired on 2026-08-05. These endpoints used to derive
/// their figures by scanning recent CHAIN blocks and relabelling their producers as
/// "pool workers", inventing an `estimated_hashrate` from blocks that are won by VRF
/// sortition against a fixed floor -- so the numbers measured luck, not hashrate, and
/// the addresses were the network's own producers, not pool miners. Rather than keep a
/// corrected version of a meaningless number, every pool endpoint now returns an honest
/// retirement payload. The `workers`/`workers_online` keys are retained (empty/zero) so
/// existing integrations degrade to "nothing here" instead of crashing on a missing field.
fn retired_pool_payload() -> Value {
    json!({
        "retired": true,
        "retired_at": "2026-08-05",
        "reason": "The Irium Stratum pool is retired. Block producers are selected by VRF \
sortition over registered keys, not by hashrate, so pooling has no effect on selection.",
        "see": "https://irium.org/pool/",
        "workers_online": 0,
        "workers": [],
        "payouts": [],
        "blocks_accepted": 0,
        "healthy": false
    })
}


async fn pool_stats(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(_q): Query<PoolQuery>,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;

    // Pool retired 2026-08-05 -- see retired_pool_payload().
    return Ok(Json(retired_pool_payload()));

    let status = proxy_value(&state, "/status").await?;
    let mining = proxy_value(&state, "/rpc/mining_metrics").await?;
    let miners = state.miners_cache.read().await.clone();

    let sample_window = q.window.unwrap_or(miners.window_blocks.max(1));
    let stratum_metrics = fetch_stratum_metrics(&state).await;

    let active_tcp_sessions = stratum_metrics
        .as_ref()
        .and_then(|m| m.get("active_tcp_sessions"))
        .cloned()
        .unwrap_or(Value::Null);
    let accepted_shares = stratum_metrics
        .as_ref()
        .and_then(|m| m.get("accepted_shares"))
        .cloned()
        .unwrap_or(Value::Null);
    let rejected_shares = stratum_metrics
        .as_ref()
        .and_then(|m| m.get("rejected_shares"))
        .cloned()
        .unwrap_or(Value::Null);
    let mut chain_pool_blocks = 0u64;
    let mut h = status.get("height").and_then(|v| v.as_u64()).unwrap_or(0) as i64;
    let mut scanned = 0u64;
    while h >= 0 && scanned < sample_window {
        let height = h as u64;
        if let Some(entry) = load_block_entry(&state, height).await {
            scanned += 1;
            if entry.source.as_deref() == Some("pool_stratum") {
                chain_pool_blocks = chain_pool_blocks.saturating_add(1);
            }
        }
        h -= 1;
    }

    let blocks_accepted = stratum_metrics
        .as_ref()
        .and_then(|m| m.get("blocks_accepted"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let blocks_accepted = if blocks_accepted > 0 {
        blocks_accepted
    } else {
        chain_pool_blocks
    };
    let candidates_detected = stratum_metrics
        .as_ref()
        .and_then(|m| m.get("candidates_detected"))
        .cloned()
        .unwrap_or(Value::Null);
    let candidates_submitted = stratum_metrics
        .as_ref()
        .and_then(|m| m.get("candidates_submitted"))
        .cloned()
        .unwrap_or(Value::Null);
    let rejected_stale = stratum_metrics
        .as_ref()
        .and_then(|m| m.get("rejected_stale"))
        .cloned()
        .unwrap_or(Value::Null);
    let rejected_low_difficulty = stratum_metrics
        .as_ref()
        .and_then(|m| m.get("rejected_low_difficulty"))
        .cloned()
        .unwrap_or(Value::Null);
    let rejected_invalid = stratum_metrics
        .as_ref()
        .and_then(|m| m.get("rejected_invalid"))
        .cloned()
        .unwrap_or(Value::Null);
    let rejected_duplicate = stratum_metrics
        .as_ref()
        .and_then(|m| m.get("rejected_duplicate"))
        .cloned()
        .unwrap_or(Value::Null);
    let last_share_accepted_at = stratum_metrics
        .as_ref()
        .and_then(|m| m.get("last_share_accepted_at"))
        .cloned()
        .unwrap_or(Value::Null);
    let last_share_rejected_at = stratum_metrics
        .as_ref()
        .and_then(|m| m.get("last_share_rejected_at"))
        .cloned()
        .unwrap_or(Value::Null);

    let payload = json!({
        "backend_connected": true,
        "stratum_metrics_connected": stratum_metrics.is_some(),
        "source": "explorer-chain-derived+stratum",
        "payout_model": "solo",
        "workers_online": active_tcp_sessions,
        "active_tcp_sessions": active_tcp_sessions,
        "chain_active_miners_window": miners.active_miners,
        "chain_active_miners_window_blocks": miners.window_blocks,
        "chain_active_miners_as_of_height": miners.as_of_height,
        "chain_active_miners_updated_at": miners.updated_at_unix,
        "accepted_shares": accepted_shares,
        "rejected_shares": rejected_shares,
        "blocks_accepted": blocks_accepted,
        "pool_blocks_accepted_chain_attributed": chain_pool_blocks,
        "candidates_detected": candidates_detected,
        "candidates_submitted": candidates_submitted,
        "rejected_stale": rejected_stale,
        "rejected_low_difficulty": rejected_low_difficulty,
        "rejected_invalid": rejected_invalid,
        "rejected_duplicate": rejected_duplicate,
        "last_share_accepted_at": last_share_accepted_at,
        "last_share_rejected_at": last_share_rejected_at,
        "stale_shares": Value::Null,
        "round_luck": Value::Null,
        "round_effort": Value::Null,
        "pool_hashrate": mining.get("hashrate"),
        "difficulty": mining.get("difficulty"),
        "network_height": status.get("height"),
        "sample_window_blocks": sample_window,
    });

    Ok(Json(payload))
}

async fn pool_payouts(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(_q): Query<PoolQuery>,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;

    // Pool retired 2026-08-05 -- see retired_pool_payload().
    return Ok(Json(retired_pool_payload()));

    let status = proxy_value(&state, "/status").await?;
    let chain_height = status.get("height").and_then(|v| v.as_u64()).unwrap_or(0);
    let limit = q.limit.unwrap_or(100).min(500);

    let mut payouts = Vec::new();
    let mut h = chain_height as i64;
    while h >= 0 && payouts.len() < limit {
        let height = h as u64;
        if let Some(entry) = load_block_entry(&state, height).await {
            let confirmations = chain_height.saturating_sub(height).saturating_add(1);
            let mature = confirmations >= COINBASE_MATURITY;
            let maturity_remaining = COINBASE_MATURITY.saturating_sub(confirmations);

            // The actual coinbase split: distinct payees + their IRM shares + %.
            let total_sats = reward_irm_for_height(height) * 1e8;
            let payees_json: Vec<Value> = entry
                .payees
                .iter()
                .map(|(addr, sats)| {
                    json!({
                        "address": addr,
                        "amount_irm": (*sats as f64) / 1e8,
                        "share_pct": if total_sats > 0.0 {
                            ((*sats as f64) / total_sats * 100.0 * 10.0).round() / 10.0
                        } else { 0.0 },
                    })
                })
                .collect();
            payouts.push(json!({
                "height": height,
                "address": entry.miner,
                "reward_irm": reward_irm_for_height(height),
                "payees": payees_json,
                "payee_count": entry.payees.len(),
                "time": entry.time,
                "hash": entry.hash,
                "status": "on_chain",
                "source": entry.source.clone().unwrap_or_else(|| "unknown".to_string()),
                "confirmations": confirmations,
                "coinbase_maturity": COINBASE_MATURITY,
                "mature": mature,
                "maturity_remaining": maturity_remaining
            }));
        }
        h -= 1;
    }

    Ok(Json(json!({
        "height": chain_height,
        "count": payouts.len(),
        "coinbase_maturity": COINBASE_MATURITY,
        "payouts": payouts
    })))
}

async fn pool_workers(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(_q): Query<PoolQuery>,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;

    // Pool retired 2026-08-05 -- see retired_pool_payload().
    return Ok(Json(retired_pool_payload()));

    let status = proxy_value(&state, "/status").await?;
    let chain_height = status.get("height").and_then(|v| v.as_u64()).unwrap_or(0);

    let window = q.window.unwrap_or(288).clamp(32, 5000);
    let limit = q.limit.unwrap_or(50).min(500);
    let start = chain_height.saturating_sub(window.saturating_sub(1));

    let mining = proxy_value(&state, "/rpc/mining_metrics").await.ok();
    let network_hashrate = value_f64(mining.as_ref().and_then(|m| m.get("hashrate")));

    let mut by_addr: HashMap<String, u64> = HashMap::new();
    let mut scanned_blocks = 0u64;
    for h in (start..=chain_height).rev() {
        let Some(entry) = load_block_entry(&state, h).await else {
            continue;
        };
        scanned_blocks = scanned_blocks.saturating_add(1);
        if entry.miner.is_empty() || entry.miner == "N/A" {
            continue;
        }
        *by_addr.entry(entry.miner).or_insert(0) += 1;
    }

    let total_found: u64 = by_addr.values().copied().sum();
    let mut rows: Vec<(String, u64)> = by_addr.into_iter().collect();
    rows.sort_by_key(|b| std::cmp::Reverse(b.1));

    let workers: Vec<Value> = rows
        .into_iter()
        .take(limit)
        .map(|(address, blocks_found)| {
            let share = if total_found > 0 {
                (blocks_found as f64) / (total_found as f64)
            } else {
                0.0
            };
            let est_hashrate = network_hashrate.map(|h| h * share);
            json!({
                "address": address,
                "blocks_found": blocks_found,
                "share_pct": share * 100.0,
                "estimated_hashrate_hs": est_hashrate,
            })
        })
        .collect();

    Ok(Json(json!({
        "height": chain_height,
        "window_scanned": window,
        "scanned_blocks": scanned_blocks,
        "workers_online": workers.len(),
        "total_found_blocks": total_found,
        "network_hashrate_hs": network_hashrate,
        "workers": workers
    })))
}

async fn pool_distribution(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PoolQuery>,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;

    let status = proxy_value(&state, "/status").await?;
    let chain_height = status.get("height").and_then(|v| v.as_u64()).unwrap_or(0);

    let window = q.window.unwrap_or(4000).clamp(200, 20000);
    let limit = q.limit.unwrap_or(100).min(1000);
    let start = chain_height.saturating_sub(window.saturating_sub(1));

    let mining = proxy_value(&state, "/rpc/mining_metrics").await.ok();
    let network_hashrate = value_f64(mining.as_ref().and_then(|m| m.get("hashrate")));

    let mut by_addr: HashMap<String, u64> = HashMap::new();
    let mut scanned_blocks = 0u64;
    for h in (start..=chain_height).rev() {
        let Some(entry) = load_block_entry(&state, h).await else {
            continue;
        };
        scanned_blocks = scanned_blocks.saturating_add(1);
        if entry.miner.is_empty() || entry.miner == "N/A" {
            continue;
        }
        *by_addr.entry(entry.miner).or_insert(0) += 1;
    }

    let total_found: u64 = by_addr.values().copied().sum();
    let mut rows: Vec<(String, u64)> = by_addr.into_iter().collect();
    rows.sort_by_key(|b| std::cmp::Reverse(b.1));

    let unique_addresses = rows.len() as u64;

    let top1_share_pct = rows
        .first()
        .map(|(_, c)| {
            if total_found > 0 {
                (*c as f64) * 100.0 / (total_found as f64)
            } else {
                0.0
            }
        })
        .unwrap_or(0.0);
    let top5_total: u64 = rows.iter().take(5).map(|(_, c)| *c).sum();
    let top5_share_pct = if total_found > 0 {
        (top5_total as f64) * 100.0 / (total_found as f64)
    } else {
        0.0
    };

    let distribution: Vec<Value> = rows
        .into_iter()
        .take(limit)
        .enumerate()
        .map(|(i, (address, blocks_found))| {
            let share = if total_found > 0 {
                (blocks_found as f64) / (total_found as f64)
            } else {
                0.0
            };
            let est_hashrate = network_hashrate.map(|h| h * share);
            json!({
                "rank": i + 1,
                "address": address,
                "blocks_found": blocks_found,
                "share_pct": share * 100.0,
                "estimated_hashrate_hs": est_hashrate,
            })
        })
        .collect();

    Ok(Json(json!({
        "height": chain_height,
        "window_scanned": window,
        "scanned_blocks": scanned_blocks,
        "total_found_blocks": total_found,
        "unique_addresses": unique_addresses,
        "network_hashrate_hs": network_hashrate,
        "top1_share_pct": top1_share_pct,
        "top5_share_pct": top5_share_pct,
        "distribution": distribution,
    })))
}

async fn pool_health(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;

    // Pool retired 2026-08-05 -- see retired_pool_payload().
    return Ok(Json(retired_pool_payload()));

    let mut issues: Vec<String> = Vec::new();
    let mut backend_connected = true;

    let t_status = Instant::now();
    let status = match proxy_value(&state, "/status").await {
        Ok(v) => v,
        Err(e) => {
            backend_connected = false;
            issues.push(format!("status fetch failed: {e}"));
            Value::Null
        }
    };
    let status_latency_ms = t_status.elapsed().as_millis() as u64;

    let t_mining = Instant::now();
    let mining = match proxy_value(&state, "/rpc/mining_metrics").await {
        Ok(v) => v,
        Err(e) => {
            backend_connected = false;
            issues.push(format!("mining_metrics fetch failed: {e}"));
            Value::Null
        }
    };
    let mining_latency_ms = t_mining.elapsed().as_millis() as u64;

    let chain_height = status.get("height").and_then(|v| v.as_u64()).unwrap_or(0);
    let peers = status
        .get("peer_count")
        .and_then(|v| v.as_u64())
        .or_else(|| status.get("peers_connected").and_then(|v| v.as_u64()));

    let tip_time = if chain_height > 0 {
        load_block_entry(&state, chain_height).await.map(|b| b.time)
    } else {
        None
    };
    let freshness_secs = tip_time.map(|t| now_unix().saturating_sub(t));

    // Dynamic freshness policy: based on observed block cadence, clamped to sane bounds.
    let avg_block_time = value_f64(mining.get("avg_block_time")).unwrap_or(600.0);
    let freshness_threshold_secs = ((avg_block_time * 6.0).round() as u64).clamp(1800, 21600);
    let chain_fresh = freshness_secs
        .map(|s| s <= freshness_threshold_secs)
        .unwrap_or(false);
    let freshness_state = if chain_fresh { "fresh" } else { "stale" };

    // `healthy` now reflects API/backend availability. Chain freshness is reported separately.
    let api_healthy = backend_connected;
    let healthy = api_healthy;

    Ok(Json(json!({
        "healthy": healthy,
        "api_healthy": api_healthy,
        "chain_fresh": chain_fresh,
        "freshness_state": freshness_state,
        "freshness_threshold_secs": freshness_threshold_secs,
        "backend_connected": backend_connected,
        "height": chain_height,
        "peers_connected": peers,
        "difficulty": mining.get("difficulty"),
        "network_hashrate_hs": mining.get("hashrate"),
        "avg_block_time": mining.get("avg_block_time"),
        "tip_time": tip_time,
        "freshness_secs": freshness_secs,
        "latency_ms": {
            "status": status_latency_ms,
            "mining": mining_latency_ms,
            "total": status_latency_ms.saturating_add(mining_latency_ms)
        },
        "issues": issues,
        "updated_at": now_unix()
    })))
}

async fn pool_account(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(address): Path<String>,
    Query(q): Query<PoolQuery>,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;

    let status = proxy_value(&state, "/status").await?;
    let chain_height = status.get("height").and_then(|v| v.as_u64()).unwrap_or(0);

    let window = q.window.unwrap_or(4000).clamp(100, 20000);
    let limit = q.limit.unwrap_or(200).min(1000);

    let mining = proxy_value(&state, "/rpc/mining_metrics").await.ok();
    let network_hashrate_hs = value_f64(mining.as_ref().and_then(|m| m.get("hashrate")));

    let start = chain_height.saturating_sub(window.saturating_sub(1));
    let mut found = Vec::new();
    let mut total = 0.0f64;
    let mut mature_total = 0.0f64;

    for h in (start..=chain_height).rev() {
        if found.len() >= limit {
            break;
        }
        let Some(entry) = load_block_entry(&state, h).await else {
            continue;
        };
        if entry.miner != address {
            continue;
        }

        let reward = reward_irm_for_height(h);
        total += reward;

        let confirmations = chain_height.saturating_sub(h).saturating_add(1);
        let mature = confirmations >= COINBASE_MATURITY;
        if mature {
            mature_total += reward;
        }

        found.push(json!({
            "height": h,
            "time": entry.time,
            "hash": entry.hash,
            "reward_irm": reward,
            "status": "on_chain",
            "source": entry.source.clone().unwrap_or_else(|| "unknown".to_string()),
            "confirmations": confirmations,
            "coinbase_maturity": COINBASE_MATURITY,
            "mature": mature,
            "maturity_remaining": COINBASE_MATURITY.saturating_sub(confirmations)
        }));
    }

    let pending_total = (total - mature_total).max(0.0);
    let found_count = found.len() as u64;
    let share_window = if window > 0 {
        (found_count as f64) / (window as f64)
    } else {
        0.0
    };
    let estimated_hashrate_hs = network_hashrate_hs.map(|h| h * share_window);

    let last = found.first().cloned();

    Ok(Json(json!({
        "address": address,
        "window_scanned": window,
        "blocks_found": found_count,
        "total_rewards_irm": total,
        "pending_balance_irm": pending_total,
        "paid_total_irm": mature_total,
        "payout_model": "solo",
        "coinbase_maturity": COINBASE_MATURITY,
        "estimated_hashrate_hs": estimated_hashrate_hs,
        "network_hashrate_hs": network_hashrate_hs,
        "window_share_pct": share_window * 100.0,
        "last_found": last,
        "records": found
    })))
}

fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(status))
        .route("/status", get(status))
        .route("/api/status", get(status))
        .route("/stats", get(stats))
        .route("/api/stats", get(stats))
        .route("/blocks", get(blocks))
        .route("/api/blocks", get(blocks))
        .route("/peers", get(peers))
        .route("/api/peers", get(peers))
        .route("/metrics", get(metrics))
        .route("/api/metrics", get(metrics))
        .route("/block/:height", get(block))
        .route("/api/block/:height", get(block))
        .route("/blockhash/:hash", get(blockhash))
        .route("/api/blockhash/:hash", get(blockhash))
        .route("/rpc/blocks", get(rpc_blocks_enriched))
        .route("/rpc/block_by_hash", get(rpc_block_by_hash_enriched))
        .route("/tx/:txid", get(tx))
        .route("/api/tx/:txid", get(tx))
        .route("/address/:address", get(address))
        .route("/api/address/:address", get(address))
        .route("/utxo", get(utxo))
        .route("/api/utxo", get(utxo))
        .route("/mining", get(mining))
        .route("/api/mining", get(mining))
        .route("/pool/stats", get(pool_stats))
        .route("/api/pool/stats", get(pool_stats))
        .route("/pool/payouts", get(pool_payouts))
        .route("/api/pool/payouts", get(pool_payouts))
        .route("/pool/workers", get(pool_workers))
        .route("/api/pool/workers", get(pool_workers))
        .route("/pool/distribution", get(pool_distribution))
        .route("/api/pool/distribution", get(pool_distribution))
        .route("/pool/health", get(pool_health))
        .route("/api/pool/health", get(pool_health))
        .route("/pool/account/:address", get(pool_account))
        .route("/api/pool/account/:address", get(pool_account))
        .route("/agreement", get(agreement_index_html))
        .route("/agreement/create", post(agreement_create))
        .route("/api/agreement/create", post(agreement_create))
        .route("/agreement/inspect", post(agreement_inspect))
        .route("/api/agreement/inspect", post(agreement_inspect))
        .route("/agreement/hash", post(agreement_hash))
        .route("/api/agreement/hash", post(agreement_hash))
        .route("/agreement/fund", post(agreement_fund))
        .route("/api/agreement/fund", post(agreement_fund))
        .route("/agreement/status", post(agreement_status_api))
        .route("/api/agreement/status", post(agreement_status_api))
        .route(
            "/agreement/release-eligibility",
            post(agreement_release_eligibility_api),
        )
        .route(
            "/api/agreement/release-eligibility",
            post(agreement_release_eligibility_api),
        )
        .route(
            "/agreement/refund-eligibility",
            post(agreement_refund_eligibility_api),
        )
        .route(
            "/api/agreement/refund-eligibility",
            post(agreement_refund_eligibility_api),
        )
        .route("/agreement/funding-legs", post(agreement_funding_legs_api))
        .route(
            "/api/agreement/funding-legs",
            post(agreement_funding_legs_api),
        )
        .route("/agreement/timeline", post(agreement_timeline_api))
        .route("/api/agreement/timeline", post(agreement_timeline_api))
        .route("/agreement/audit", post(agreement_audit_api))
        .route("/api/agreement/audit", post(agreement_audit_api))
        .route("/agreement/statement", post(agreement_statement_api))
        .route("/api/agreement/statement", post(agreement_statement_api))
        .route(
            "/agreement/verify-signature",
            post(agreement_verify_signature_api),
        )
        .route(
            "/api/agreement/verify-signature",
            post(agreement_verify_signature_api),
        )
        .route(
            "/agreement/verify-artifacts",
            post(agreement_verify_artifacts_api),
        )
        .route(
            "/api/agreement/verify-artifacts",
            post(agreement_verify_artifacts_api),
        )
        .route(
            "/agreement/share-package/verify",
            post(agreement_share_package_verify_api),
        )
        .route(
            "/api/agreement/share-package/verify",
            post(agreement_share_package_verify_api),
        )
        .route(
            "/agreement/audit/download.json",
            post(agreement_audit_download_json),
        )
        .route(
            "/agreement/audit/download.csv",
            post(agreement_audit_download_csv),
        )
        .route(
            "/agreement/statement/download.json",
            post(agreement_statement_download_json),
        )
        .route(
            "/agreement/create/simple-settlement/view",
            post(agreement_create_simple_view),
        )
        .route(
            "/agreement/create/otc/view",
            post(agreement_create_otc_view),
        )
        .route(
            "/agreement/create/deposit/view",
            post(agreement_create_deposit_view),
        )
        .route(
            "/agreement/create/milestone/view",
            post(agreement_create_milestone_view),
        )
        .route("/agreement/lookup", post(agreement_lookup_api))
        .route("/api/agreement/lookup", post(agreement_lookup_api))
        .route("/agreement/milestones", post(agreement_milestones_api))
        .route("/api/agreement/milestones", post(agreement_milestones_api))
        .route("/agreement/txs", post(agreement_txs_api))
        .route("/api/agreement/txs", post(agreement_txs_api))
        .route("/agreement/verify-link", post(agreement_verify_link_api))
        .route(
            "/api/agreement/verify-link",
            post(agreement_verify_link_api),
        )
        .route("/agreement/inspect/view", post(agreement_inspect_view))
        .route("/agreement/status/view", post(agreement_status_view))
        .route(
            "/agreement/milestones/view",
            post(agreement_milestones_view),
        )
        .route("/agreement/txs/view", post(agreement_txs_view))
        .route(
            "/agreement/funding-legs/view",
            post(agreement_funding_legs_view),
        )
        .route("/agreement/timeline/view", post(agreement_timeline_view))
        .route("/agreement/audit/view", post(agreement_audit_view))
        .route(
            "/agreement/verify-signature/view",
            post(agreement_verify_signature_view),
        )
        .route(
            "/agreement/verify-artifacts/view",
            post(agreement_verify_artifacts_view),
        )
        .route(
            "/agreement/share-package/verify/view",
            post(agreement_share_package_verify_view),
        )
        .route("/agreement/statement/view", post(agreement_statement_view))
        .route(
            "/agreement/release-eligibility/view",
            post(agreement_release_eligibility_view),
        )
        .route(
            "/agreement/refund-eligibility/view",
            post(agreement_refund_eligibility_view),
        )
        .route("/agreement/lookup/view", post(agreement_lookup_view))
        .with_state(state)
}

#[tokio::main]
async fn main() {
    let node_base =
        env::var("IRIUM_NODE_RPC").unwrap_or_else(|_| "https://127.0.0.1:38300".to_string());
    let client = match build_client(&node_base) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to init HTTP client: {e}");
            std::process::exit(1);
        }
    };
    let api_token = env::var("IRIUM_EXPLORER_TOKEN").ok();
    let rpc_token = env::var("IRIUM_RPC_TOKEN").ok();
    let rate = env::var("IRIUM_EXPLORER_RATE_LIMIT_PER_MIN")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(120);

    let miners_window_blocks = env::var("IRIUM_EXPLORER_MINERS_WINDOW_BLOCKS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(144);
    let miners_refresh_secs = env::var("IRIUM_EXPLORER_MINERS_REFRESH_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(15);

    let stratum_metrics_url = env::var("IRIUM_STRATUM_TELEMETRY_URL")
        .ok()
        .map(|v| v.trim_end_matches('/').to_string())
        .filter(|v| !v.is_empty());

    let state = AppState {
        client,
        node_base: node_base.trim_end_matches('/').to_string(),
        limiter: Arc::new(Mutex::new(RateLimiter::new(rate))),
        api_token,
        rpc_token,
        miners_cache: Arc::new(RwLock::new(MinersCache {
            window_blocks: miners_window_blocks,
            ..Default::default()
        })),
        stratum_metrics_url,
    };

    // Background refresh for "active miners" estimate.
    tokio::spawn(miners_refresher_task(
        state.clone(),
        miners_window_blocks,
        Duration::from_secs(miners_refresh_secs.max(3)),
    ));

    let app = build_app(state).into_make_service_with_connect_info::<SocketAddr>();

    let host = env::var("IRIUM_EXPLORER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port: u16 = env::var("IRIUM_EXPLORER_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| {
            eprintln!("Error: IRIUM_EXPLORER_PORT must be set");
            std::process::exit(1);
        });
    let addr: SocketAddr = format!("{}:{}", host, port)
        .parse()
        .expect("valid bind address");

    println!(
        "Irium explorer API listening on http://{}:{} (node rpc {})",
        host, port, node_base
    );

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind failed");
    axum::serve(listener, app).await.expect("server error");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
        routing::post,
        Router,
    };
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::SigningKey;
    use tower::ServiceExt;

    #[test]
    fn settlement_surface_labels_boundaries() {
        let wrapped = settlement_surface("agreementstatus", json!({"agreement_hash": "aa"})).0;
        assert_eq!(wrapped["surface"], "phase1_settlement");
        assert_eq!(wrapped["rpc"], "agreementstatus");
        assert!(!wrapped["htlc_enforced"].as_array().unwrap().is_empty());
        assert!(!wrapped["metadata_indexed"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn agreement_status_route_proxies_and_wraps_response() {
        let upstream = Router::new().route(
            "/rpc/agreementstatus",
            post(|| async {
                Json(json!({
                    "agreement_hash": "aa",
                    "lifecycle": {"state": "funded"}
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });

        let state = AppState {
            client: Client::builder().build().unwrap(),
            node_base: format!("http://{}", addr),
            limiter: Arc::new(Mutex::new(RateLimiter::new(120))),
            api_token: None,
            rpc_token: None,
            miners_cache: Arc::new(RwLock::new(MinersCache::default())),
            stratum_metrics_url: None,
        };

        let req = Request::builder()
            .method("POST")
            .uri("/api/agreement/status")
            .header("content-type", "application/json")
            .extension(ConnectInfo(
                "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            ))
            .body(Body::from(r#"{"agreement":{"agreement_id":"x"}}"#))
            .unwrap();
        let resp = build_app(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["surface"], "phase1_settlement");
        assert_eq!(value["rpc"], "agreementstatus");
        assert_eq!(value["data"]["agreement_hash"], "aa");
    }

    fn sample_agreement_json() -> String {
        serde_json::to_string(&json!({
            "agreement_id": "agr-html-1",
            "version": 1,
            "template_type": "simple_release_refund",
            "parties": [
                {"party_id": "payer", "display_name": "Payer", "address": "Qpayer", "role": "payer"},
                {"party_id": "payee", "display_name": "Payee", "address": "Qpayee", "role": "payee"}
            ],
            "payer": "payer",
            "payee": "payee",
            "total_amount": 50000000,
            "network_marker": "IRIUM",
            "creation_time": 1700000000,
            "deadlines": {"settlement_deadline": 100, "refund_deadline": 120},
            "release_conditions": [{"mode": "secret_preimage", "secret_hash_hex": "1111111111111111111111111111111111111111111111111111111111111111", "release_authorizer": "payer"}],
            "refund_conditions": [{"refund_address": "Qpayer", "timeout_height": 120}],
            "document_hash": "2222222222222222222222222222222222222222222222222222222222222222"
        })).unwrap()
    }

    fn sample_bundle_json() -> String {
        serde_json::to_string(&json!({
            "version": 1,
            "agreement_id": "agr-html-1",
            "agreement_hash": irium_node_rs::settlement::compute_agreement_hash_hex(&serde_json::from_str::<AgreementObject>(&sample_agreement_json()).unwrap()).unwrap(),
            "agreement": serde_json::from_str::<Value>(&sample_agreement_json()).unwrap(),
            "metadata": {"saved_at": 1710000000, "source_label": "test"}
        })).unwrap()
    }

    fn sample_audit_json() -> String {
        serde_json::to_string(&json!({
            "metadata": {"version": 1, "generated_at": 1710000123u64, "generator_surface": "iriumd_rpc", "trust_model_summary": "derived only"},
            "agreement": {"agreement_id": "agr-html-1", "agreement_hash": irium_node_rs::settlement::compute_agreement_hash_hex(&serde_json::from_str::<AgreementObject>(&sample_agreement_json()).unwrap()).unwrap(), "template_type": "simple_release_refund", "network_marker": "IRIUM", "payer": "payer", "payee": "payee", "parties": [], "total_amount": 50000000, "milestone_count": 0, "milestones": [], "settlement_deadline": 100, "refund_deadline": 120, "dispute_window": null, "document_hash": "2222222222222222222222222222222222222222222222222222222222222222", "metadata_hash": null, "invoice_reference": null, "external_reference": null},
            "local_bundle": {"bundle_used": true, "verification_ok": true, "saved_at": 1710000000u64, "source_label": "wallet-test", "note": null, "linked_funding_txids": ["bb"], "milestone_hints": [], "local_only_notice": "local only"},
            "chain_observed": {"linked_transactions": [{"txid": "bb", "role": "funding", "milestone_id": null, "height": 12, "confirmed": true, "value": 50000000}], "linked_transaction_count": 1, "anchor_observation_notice": "chain observed"},
            "funding_legs": {"candidate_count": 1, "selection_required": false, "selected_leg": null, "ambiguity_warning": null, "candidates": [], "notice": "derived only"},
            "timeline": {"reconstructed": true, "event_count": 1, "events": [], "notice": "timeline"},
            "settlement_state": {"lifecycle_state": "funded", "derived_state_label": "funded", "selection_required": false, "funded_amount": 50000000, "released_amount": 0, "refunded_amount": 0, "summary_note": "derived state"},
            "trust_boundaries": {"consensus_enforced": ["anchor visibility"], "htlc_enforced": ["htlc branch"], "metadata_indexed": ["timeline"], "local_bundle_only": ["bundle label"], "off_chain_required": ["agreement exchange"]}
        })).unwrap()
    }

    fn sample_statement_json() -> String {
        serde_json::to_string(&json!({
            "metadata": {"version": 1, "generated_at": 1710000123u64, "derived_notice": "derived only"},
            "identity": {"agreement_id": "agr-html-1", "agreement_hash": irium_node_rs::settlement::compute_agreement_hash_hex(&serde_json::from_str::<AgreementObject>(&sample_agreement_json()).unwrap()).unwrap(), "template_type": "simple_release_refund"},
            "counterparties": {"payer": "payer", "payee": "payee", "parties_summary": ["payer:Qpayer", "payee:Qpayee"]},
            "commercial": {"total_amount": 50000000, "milestone_summary": "no milestones", "settlement_deadline": 100, "refund_deadline": 120, "release_path_summary": "HTLC-backed release path", "refund_path_summary": "HTLC-backed refund path"},
            "observed": {"funding_observed": true, "release_observed": false, "refund_observed": false, "ambiguity_warning": null, "linked_txids": ["bb"]},
            "derived": {"derived_state_label": "funded", "funded_amount": 50000000, "released_amount": 0, "refunded_amount": 0, "note": "derived only"},
            "trust_notice": {"consensus_visible": ["anchor visibility"], "htlc_enforced": ["htlc branch"], "derived_indexed": ["timeline"], "local_off_chain": ["agreement exchange"], "canonical_notice": "canonical agreement json remains the source of truth"},
            "references": {"linked_txids": ["bb"], "selected_funding_txid": null, "canonical_agreement_notice": "canonical agreement json remains the source of truth"}
        })).unwrap()
    }

    fn sample_share_package_json() -> String {
        serde_json::to_string_pretty(&json!({
            "version": 1,
            "package_schema_id": "irium.phase1.share_package.v1",
            "created_at": 1710000400u64,
            "sender_label": "counterparty-a",
            "package_note": "handoff",
            "included_artifact_types": ["agreement", "bundle", "statement", "agreement_signatures"],
            "trust_notice": "Share package contents are supplied artifacts. Authenticity still depends on canonical hashes, signature checks, and derived verification. Derived statement or audit content remains informational and not native consensus contract state.",
            "agreement": serde_json::from_str::<Value>(&sample_agreement_json()).unwrap(),
            "bundle": serde_json::from_str::<Value>(&sample_bundle_json()).unwrap(),
            "statement": serde_json::from_str::<Value>(&sample_statement_json()).unwrap(),
            "detached_agreement_signatures": [serde_json::from_str::<Value>(&sample_signature_json()).unwrap()],
            "detached_bundle_signatures": []
        })).unwrap()
    }

    fn sample_signature_json() -> String {
        let agreement: AgreementObject = serde_json::from_str(&sample_agreement_json()).unwrap();
        let agreement_hash = compute_agreement_hash_hex(&agreement).unwrap();
        let signing_key = SigningKey::from_bytes((&[9u8; 32]).into()).unwrap();
        let mut envelope = AgreementSignatureEnvelope {
            version: irium_node_rs::settlement::AGREEMENT_SIGNATURE_VERSION,
            target_type: irium_node_rs::settlement::AgreementSignatureTargetType::Agreement,
            target_hash: agreement_hash,
            signer_public_key: hex::encode(
                signing_key
                    .verifying_key()
                    .to_encoded_point(true)
                    .as_bytes(),
            ),
            signer_address: Some("Qsigview".to_string()),
            signature_type: irium_node_rs::settlement::AGREEMENT_SIGNATURE_TYPE_SECP256K1
                .to_string(),
            timestamp: Some(1_710_000_777),
            signer_role: Some("buyer".to_string()),
            signature: String::new(),
        };
        let digest =
            irium_node_rs::settlement::compute_agreement_signature_payload_hash(&envelope).unwrap();
        let signature: k256::ecdsa::Signature = signing_key.sign_prehash(&digest).unwrap();
        envelope.signature = hex::encode(signature.to_bytes());
        serde_json::to_string(&envelope).unwrap()
    }

    fn sample_signed_bundle_json() -> String {
        let mut bundle: AgreementBundle = serde_json::from_str(&sample_bundle_json()).unwrap();
        let bundle_hash = compute_agreement_bundle_hash_hex(&bundle).unwrap();
        let signing_key = SigningKey::from_bytes((&[10u8; 32]).into()).unwrap();
        let mut envelope = AgreementSignatureEnvelope {
            version: irium_node_rs::settlement::AGREEMENT_SIGNATURE_VERSION,
            target_type: irium_node_rs::settlement::AgreementSignatureTargetType::Bundle,
            target_hash: bundle_hash,
            signer_public_key: hex::encode(
                signing_key
                    .verifying_key()
                    .to_encoded_point(true)
                    .as_bytes(),
            ),
            signer_address: Some("Qbundleview".to_string()),
            signature_type: irium_node_rs::settlement::AGREEMENT_SIGNATURE_TYPE_SECP256K1
                .to_string(),
            timestamp: Some(1_710_000_778),
            signer_role: Some("seller".to_string()),
            signature: String::new(),
        };
        let digest =
            irium_node_rs::settlement::compute_agreement_signature_payload_hash(&envelope).unwrap();
        let signature: k256::ecdsa::Signature = signing_key.sign_prehash(&digest).unwrap();
        envelope.signature = hex::encode(signature.to_bytes());
        bundle.signatures.push(envelope);
        serde_json::to_string(&bundle).unwrap()
    }

    fn form_body(fields: &[(&str, &str)]) -> String {
        fn enc(s: &str) -> String {
            s.bytes()
                .map(|b| match b {
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                        (b as char).to_string()
                    }
                    b' ' => "+".to_string(),
                    _ => format!("%{:02X}", b),
                })
                .collect::<String>()
        }
        fields
            .iter()
            .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
            .collect::<Vec<_>>()
            .join("&")
    }

    fn test_state(node_base: String) -> AppState {
        AppState {
            client: Client::builder().build().unwrap(),
            node_base,
            limiter: Arc::new(Mutex::new(RateLimiter::new(120))),
            api_token: None,
            rpc_token: None,
            miners_cache: Arc::new(RwLock::new(MinersCache::default())),
            stratum_metrics_url: None,
        }
    }

    fn sample_tx_lookup_json() -> Value {
        use irium_node_rs::settlement::{
            build_agreement_anchor_output, AgreementAnchor, AgreementAnchorRole,
        };
        use irium_node_rs::tx::{Transaction, TxInput, TxOutput};

        let anchor = build_agreement_anchor_output(&AgreementAnchor {
            agreement_hash: "aa".repeat(32),
            role: AgreementAnchorRole::Funding,
            milestone_id: None,
        })
        .unwrap();
        let tx = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: [1u8; 32],
                prev_index: 0,
                script_sig: vec![1],
                sequence: 0xffff_ffff,
            }],
            outputs: vec![
                TxOutput {
                    value: 50_000_000,
                    script_pubkey: vec![0x51],
                },
                anchor,
            ],
            locktime: 0,
        };
        json!({
            "txid": hex::encode(tx.txid()),
            "height": 12,
            "index": 0,
            "block_hash": "bb",
            "inputs": 1,
            "outputs": 2,
            "output_value": 50000000,
            "is_coinbase": false,
            "tx_hex": hex::encode(tx.serialize())
        })
    }

    #[tokio::test]
    async fn agreement_create_simple_view_renders_generated_json() {
        let req = Request::builder()
            .method("POST")
            .uri("/agreement/create/simple-settlement/view")
            .header("content-type", "application/x-www-form-urlencoded")
            .extension(ConnectInfo(
                "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            ))
            .body(Body::from(form_body(&[
                ("agreement_id", "agr-create-1"),
                ("creation_time", "1700000000"),
                ("party_a", "payer|Payer|Qpayer|payer"),
                ("party_b", "payee|Payee|Qpayee|payee"),
                ("amount", "0.5"),
                ("settlement_deadline", "100"),
                ("refund_timeout", "120"),
                ("secret_hash", &"11".repeat(32)),
                ("document_hash", &"22".repeat(32)),
                ("release_summary", "Release after payer confirms"),
                ("refund_summary", "Refund after timeout"),
            ])))
            .unwrap();
        let resp = build_app(test_state("http://127.0.0.1:1".to_string()))
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Generated canonical agreement JSON"));
        assert!(html.contains("agr-create-1"));
        assert!(html.contains("irium.phase1.canonical.v1"));
    }

    #[tokio::test]
    async fn agreement_inspect_view_renders_bundle_context() {
        let upstream = Router::new().route(
            "/rpc/inspectagreement",
            post(|| async { Json(json!({"summary": {"ok": true, "source": "node"}})) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });
        let req = Request::builder()
            .method("POST")
            .uri("/agreement/inspect/view")
            .header("content-type", "application/x-www-form-urlencoded")
            .extension(ConnectInfo(
                "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            ))
            .body(Body::from(form_body(&[(
                "agreement_json",
                &sample_bundle_json(),
            )])))
            .unwrap();
        let resp = build_app(test_state(format!("http://{}", addr)))
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Bundle context"));
        assert!(html.contains("Bundle hash"));
        assert!(html.contains("Copy hashes"));
    }

    #[tokio::test]
    async fn agreement_html_index_renders_form() {
        let state = test_state("http://127.0.0.1:1".to_string());
        let req = Request::builder()
            .method("GET")
            .uri("/agreement")
            .extension(ConnectInfo(
                "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            ))
            .body(Body::empty())
            .unwrap();
        let resp = build_app(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Phase 1 Agreement Views"));
        assert!(html.contains("Release Eligibility"));
        assert!(html.contains("Verify a shared handoff package"));
        assert!(html.contains("Wallet-side intake and housekeeping"));
        assert!(html.contains("agreement-local-store-list --include-archived"));
    }

    #[tokio::test]
    async fn agreement_status_html_view_renders_trust_boundaries() {
        let upstream = Router::new().route(
            "/rpc/agreementstatus",
            post(|| async {
                Json(json!({
                    "agreement_hash": "aa",
                    "lifecycle": {"state": "funded", "funded_amount": 50000000, "released_amount": 0, "refunded_amount": 0}
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });
        let req = Request::builder()
            .method("POST")
            .uri("/agreement/status/view")
            .header("content-type", "application/x-www-form-urlencoded")
            .extension(ConnectInfo(
                "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            ))
            .body(Body::from(form_body(&[(
                "agreement_json",
                &sample_agreement_json(),
            )])))
            .unwrap();
        let resp = build_app(test_state(format!("http://{}", addr)))
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("State:"));
        assert!(html.contains("Consensus-enforced"));
        assert!(html.contains("not native consensus settlement state"));
    }

    #[tokio::test]
    async fn agreement_milestones_html_view_renders_rows() {
        let upstream = Router::new().route(
            "/rpc/agreementmilestones",
            post(|| async {
                Json(json!({
                    "agreement_hash": "aa",
                    "state": "funded",
                    "milestones": [{"milestone_id": "ms1", "title": "Kickoff", "amount": 25000000, "funded": true, "released": false, "refunded": false}]
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });
        let req = Request::builder()
            .method("POST")
            .uri("/agreement/milestones/view")
            .header("content-type", "application/x-www-form-urlencoded")
            .extension(ConnectInfo(
                "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            ))
            .body(Body::from(form_body(&[(
                "agreement_json",
                &sample_agreement_json(),
            )])))
            .unwrap();
        let resp = build_app(test_state(format!("http://{}", addr)))
            .oneshot(req)
            .await
            .unwrap();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Kickoff"));
        assert!(html.contains("metadata/indexed interpretation"));
    }

    #[tokio::test]
    async fn agreement_txs_html_view_renders_linked_tx_info() {
        let upstream = Router::new().route(
            "/rpc/listagreementtxs",
            post(|| async {
                Json(json!({
                    "agreement_hash": "aa",
                    "txs": [{"txid": "bb", "role": "funding", "milestone_id": null, "height": 12, "confirmed": true, "value": 50000000}]
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });
        let req = Request::builder()
            .method("POST")
            .uri("/agreement/txs/view")
            .header("content-type", "application/x-www-form-urlencoded")
            .extension(ConnectInfo(
                "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            ))
            .body(Body::from(form_body(&[(
                "agreement_json",
                &sample_agreement_json(),
            )])))
            .unwrap();
        let resp = build_app(test_state(format!("http://{}", addr)))
            .oneshot(req)
            .await
            .unwrap();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("bb"));
        assert!(html.contains("funding"));
    }

    #[tokio::test]
    async fn agreement_html_error_state_renders_safely() {
        let req = Request::builder()
            .method("POST")
            .uri("/agreement/status/view")
            .header("content-type", "application/x-www-form-urlencoded")
            .extension(ConnectInfo(
                "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            ))
            .body(Body::from("agreement_json=%7Bbad"))
            .unwrap();
        let resp = build_app(test_state("http://127.0.0.1:1".to_string()))
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Invalid agreement"));
        assert!(html.contains("Trust Boundaries"));
    }

    #[tokio::test]
    async fn agreement_lookup_index_renders_input_modes() {
        let state = test_state("http://127.0.0.1:1".to_string());
        let req = Request::builder()
            .method("GET")
            .uri("/agreement")
            .extension(ConnectInfo(
                "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            ))
            .body(Body::empty())
            .unwrap();
        let resp = build_app(state).oneshot(req).await.unwrap();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Lookup by hash or txid"));
        assert!(html.contains("Linked txid or funding txid"));
    }

    #[tokio::test]
    async fn agreement_funding_legs_view_renders_candidates() {
        let upstream = Router::new().route(
            "/rpc/agreementfundinglegs",
            post(|| async {
                Json(json!({
                    "agreement_hash": "aa",
                    "selection_required": false,
                    "candidates": [{"funding_txid": "bb", "htlc_vout": 0, "role": "funding", "milestone_id": null, "amount": 50000000, "release_eligible": false, "refund_eligible": true, "source_notes": ["direct_anchor_match"]}],
                    "trust_model_note": "derived only"
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });
        let req = Request::builder()
            .method("POST")
            .uri("/agreement/funding-legs/view")
            .header("content-type", "application/x-www-form-urlencoded")
            .extension(ConnectInfo(
                "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            ))
            .body(Body::from(form_body(&[(
                "agreement_json",
                &sample_agreement_json(),
            )])))
            .unwrap();
        let resp = build_app(test_state(format!("http://{}", addr)))
            .oneshot(req)
            .await
            .unwrap();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Funding leg discovery"));
        assert!(html.contains("bb"));
        assert!(html.contains("not native agreement UTXO state"));
    }

    #[tokio::test]
    async fn agreement_timeline_view_renders_events() {
        let upstream = Router::new().route(
            "/rpc/agreementtimeline",
            post(|| async {
                Json(json!({
                    "agreement_hash": "aa",
                    "lifecycle": {"state": "funded", "funded_amount": 50000000, "released_amount": 0, "refunded_amount": 0},
                    "events": [{"event_type": "funding_tx_observed", "source": "chain_observed", "height": 12, "timestamp": null, "txid": "bb", "milestone_id": null, "note": "linked tx"}],
                    "trust_model_note": "derived only"
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });
        let req = Request::builder()
            .method("POST")
            .uri("/agreement/timeline/view")
            .header("content-type", "application/x-www-form-urlencoded")
            .extension(ConnectInfo(
                "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            ))
            .body(Body::from(form_body(&[(
                "agreement_json",
                &sample_agreement_json(),
            )])))
            .unwrap();
        let resp = build_app(test_state(format!("http://{}", addr)))
            .oneshot(req)
            .await
            .unwrap();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Reconstructed activity timeline"));
        assert!(html.contains("funding_tx_observed"));
        assert!(html.contains("not consensus-native agreement state"));
    }

    #[tokio::test]
    async fn agreement_lookup_view_resolves_txid_anchor_path() {
        let tx_payload = sample_tx_lookup_json();
        let upstream = Router::new().route(
            "/rpc/tx",
            get(move || {
                let tx_payload = tx_payload.clone();
                async move { Json(tx_payload) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });
        let req = Request::builder()
            .method("POST")
            .uri("/agreement/lookup/view")
            .header("content-type", "application/x-www-form-urlencoded")
            .extension(ConnectInfo(
                "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            ))
            .body(Body::from(form_body(&[
                ("agreement_json", ""),
                ("lookup_txid", &"11".repeat(32)),
                ("agreement_hash", &"aa".repeat(32)),
            ])))
            .unwrap();
        let resp = build_app(test_state(format!("http://{}", addr)))
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Anchor match in tx"));
        assert!(html.contains("Open raw transaction view"));
        assert!(html.contains("aa"));
    }

    #[tokio::test]
    async fn agreement_lookup_missing_txid_renders_safe_error() {
        let req = Request::builder()
            .method("POST")
            .uri("/agreement/lookup/view")
            .header("content-type", "application/x-www-form-urlencoded")
            .extension(ConnectInfo(
                "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            ))
            .body(Body::from(form_body(&[
                ("agreement_json", ""),
                ("agreement_hash", &"aa".repeat(32)),
            ])))
            .unwrap();
        let resp = build_app(test_state("http://127.0.0.1:1".to_string()))
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Missing txid"));
        assert!(html.contains("Trust Boundaries"));
    }

    #[test]
    fn parse_agreement_form_accepts_bundle_json() {
        let form = AgreementHtmlForm {
            agreement_json: sample_bundle_json(),
            audit_json: None,
            statement_json: None,
            share_package_json: None,
            signature_json: None,
            agreement_signature_json: None,
            bundle_signature_json: None,
            funding_txid: None,
            htlc_vout: None,
            milestone_id: None,
            destination_address: None,
            secret_hex: None,
            agreement_hash: None,
            lookup_txid: None,
        };
        let agreement = parse_agreement_form(&form).unwrap();
        assert_eq!(agreement.agreement_id, "agr-html-1");
    }

    #[tokio::test]
    async fn agreement_audit_view_renders_sections() {
        let upstream = Router::new().route(
            "/rpc/agreementaudit",
            post(|| async {
                Json(json!({
                    "metadata": {"version": 1, "generated_at": 1710000123u64, "generator_surface": "iriumd_rpc", "trust_model_summary": "derived only"},
                    "agreement": {"agreement_id": "agr-explorer-1", "agreement_hash": "aa", "template_type": "simple_release_refund", "network_marker": "IRIUM", "payer": "Qpayer", "payee": "Qpayee", "parties": [], "total_amount": 50000000, "milestone_count": 0, "milestones": [], "settlement_deadline": 100, "refund_deadline": 120, "dispute_window": null, "document_hash": "11", "metadata_hash": null, "invoice_reference": null, "external_reference": null},
                    "local_bundle": {"bundle_used": true, "verification_ok": true, "saved_at": 1710000000u64, "source_label": "wallet-test", "note": null, "linked_funding_txids": ["bb"], "milestone_hints": [], "local_only_notice": "local only"},
                    "chain_observed": {"linked_transactions": [], "linked_transaction_count": 1, "anchor_observation_notice": "chain observed"},
                    "funding_legs": {"candidate_count": 1, "selection_required": false, "selected_leg": {"funding_txid": "bb", "htlc_vout": 0, "anchor_vout": 1, "role": "funding", "milestone_id": null, "amount": 50000000, "htlc_backed": true, "timeout_height": 120, "recipient_address": "Qpayee", "refund_address": "Qpayer", "source_notes": ["direct_anchor_match"], "release_eligible": false, "release_reasons": [], "refund_eligible": true, "refund_reasons": []}, "ambiguity_warning": null, "candidates": [], "notice": "derived only"},
                    "timeline": {"reconstructed": true, "event_count": 1, "events": [{"event_type": "funding_tx_observed", "source": "chain_observed", "txid": "bb", "height": 12, "timestamp": null, "milestone_id": null, "note": "linked tx"}], "notice": "timeline"},
                    "settlement_state": {"lifecycle_state": "funded", "derived_state_label": "funded", "selection_required": false, "funded_amount": 50000000, "released_amount": 0, "refunded_amount": 0, "summary_note": "derived state"},
                    "trust_boundaries": {"consensus_enforced": ["anchor visibility"], "htlc_enforced": ["htlc branch"], "metadata_indexed": ["timeline"], "local_bundle_only": ["bundle label"], "off_chain_required": ["agreement exchange"]}
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });
        let req = Request::builder()
            .method("POST")
            .uri("/agreement/audit/view")
            .header("content-type", "application/x-www-form-urlencoded")
            .extension(ConnectInfo(
                "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            ))
            .body(Body::from(form_body(&[(
                "agreement_json",
                &sample_agreement_json(),
            )])))
            .unwrap();
        let resp = build_app(test_state(format!("http://{}", addr)))
            .oneshot(req)
            .await
            .unwrap();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Agreement audit record"));
        assert!(html.contains("Derived state"));
        assert!(html.contains("Download audit JSON"));
        assert!(html.contains("Download audit CSV"));
        assert!(html.contains("not native consensus contract state"));
    }

    #[tokio::test]
    async fn agreement_audit_download_json_returns_attachment() {
        let upstream = Router::new().route(
            "/rpc/agreementaudit",
            post(|| async {
                Json(json!({
                    "metadata": {"version": 1, "generated_at": 1710000123u64, "generator_surface": "iriumd_rpc", "trust_model_summary": "derived only"},
                    "agreement": {"agreement_id": "agr-explorer-1", "agreement_hash": "aa", "template_type": "simple_release_refund", "network_marker": "IRIUM", "payer": "Qpayer", "payee": "Qpayee", "parties": [], "total_amount": 50000000, "milestone_count": 0, "milestones": [], "settlement_deadline": 100, "refund_deadline": 120, "dispute_window": null, "document_hash": "11", "metadata_hash": null, "invoice_reference": null, "external_reference": null},
                    "local_bundle": {"bundle_used": true, "verification_ok": true, "saved_at": 1710000000u64, "source_label": "wallet-test", "note": null, "linked_funding_txids": ["bb"], "milestone_hints": [], "local_only_notice": "local only"},
                    "chain_observed": {"linked_transactions": [], "linked_transaction_count": 1, "anchor_observation_notice": "chain observed"},
                    "funding_legs": {"candidate_count": 1, "selection_required": false, "selected_leg": null, "ambiguity_warning": null, "candidates": [], "notice": "derived only"},
                    "timeline": {"reconstructed": true, "event_count": 1, "events": [], "notice": "timeline"},
                    "settlement_state": {"lifecycle_state": "funded", "derived_state_label": "funded", "selection_required": false, "funded_amount": 50000000, "released_amount": 0, "refunded_amount": 0, "summary_note": "derived state"},
                    "trust_boundaries": {"consensus_enforced": ["anchor visibility"], "htlc_enforced": ["htlc branch"], "metadata_indexed": ["timeline"], "local_bundle_only": ["bundle label"], "off_chain_required": ["agreement exchange"]}
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });
        let req = Request::builder()
            .method("POST")
            .uri("/agreement/audit/download.json")
            .header("content-type", "application/x-www-form-urlencoded")
            .extension(ConnectInfo(
                "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            ))
            .body(Body::from(form_body(&[(
                "agreement_json",
                &sample_agreement_json(),
            )])))
            .unwrap();
        let resp = build_app(test_state(format!("http://{}", addr)))
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/json"
        );
        assert!(resp
            .headers()
            .get("content-disposition")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("agreement-audit-agr-html-1.json"));
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let rendered = String::from_utf8(body.to_vec()).unwrap();
        assert!(rendered.contains("trust_boundaries"));
    }

    #[tokio::test]
    async fn agreement_audit_download_csv_returns_attachment() {
        let upstream = Router::new().route(
            "/rpc/agreementaudit",
            post(|| async {
                Json(json!({
                    "metadata": {"version": 1, "generated_at": 1710000123u64, "generator_surface": "iriumd_rpc", "trust_model_summary": "derived only"},
                    "agreement": {"agreement_id": "agr-explorer-1", "agreement_hash": "aa", "template_type": "simple_release_refund", "network_marker": "IRIUM", "payer": "Qpayer", "payee": "Qpayee", "parties": [], "total_amount": 50000000, "milestone_count": 0, "milestones": [], "settlement_deadline": 100, "refund_deadline": 120, "dispute_window": null, "document_hash": "11", "metadata_hash": null, "invoice_reference": null, "external_reference": null},
                    "local_bundle": {"bundle_used": true, "verification_ok": true, "saved_at": 1710000000u64, "source_label": "wallet-test", "note": null, "linked_funding_txids": ["bb"], "milestone_hints": [], "local_only_notice": "local only"},
                    "chain_observed": {"linked_transactions": [], "linked_transaction_count": 1, "anchor_observation_notice": "chain observed"},
                    "funding_legs": {"candidate_count": 1, "selection_required": false, "selected_leg": null, "ambiguity_warning": null, "candidates": [], "notice": "derived only"},
                    "timeline": {"reconstructed": true, "event_count": 1, "events": [{"event_type": "funding_tx_observed", "source": "chain_observed", "txid": "bb", "height": 12, "timestamp": null, "milestone_id": null, "note": "linked tx"}], "notice": "timeline"},
                    "settlement_state": {"lifecycle_state": "funded", "derived_state_label": "funded", "selection_required": false, "funded_amount": 50000000, "released_amount": 0, "refunded_amount": 0, "summary_note": "derived state"},
                    "trust_boundaries": {"consensus_enforced": ["anchor visibility"], "htlc_enforced": ["htlc branch"], "metadata_indexed": ["timeline"], "local_bundle_only": ["bundle label"], "off_chain_required": ["agreement exchange"]}
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });
        let req = Request::builder()
            .method("POST")
            .uri("/agreement/audit/download.csv")
            .header("content-type", "application/x-www-form-urlencoded")
            .extension(ConnectInfo(
                "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            ))
            .body(Body::from(form_body(&[(
                "agreement_json",
                &sample_agreement_json(),
            )])))
            .unwrap();
        let resp = build_app(test_state(format!("http://{}", addr)))
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "text/csv; charset=utf-8"
        );
        assert!(resp
            .headers()
            .get("content-disposition")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("agreement-audit-agr-html-1.csv"));
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let rendered = String::from_utf8(body.to_vec()).unwrap();
        assert!(rendered.contains("\"record_version\""));
        assert!(rendered.contains("\"csv_schema\""));
        assert!(rendered.contains("timeline_event"));
        assert!(rendered.contains("derived_indexed"));
    }

    #[tokio::test]
    async fn agreement_statement_view_renders_sections() {
        let upstream = Router::new().route(
            "/rpc/agreementaudit",
            post(|| async {
                Json(json!({
                    "metadata": {"version": 1, "generated_at": 1710000123u64, "generator_surface": "iriumd_rpc", "trust_model_summary": "derived only"},
                    "agreement": {"agreement_id": "agr-explorer-1", "agreement_hash": "aa", "template_type": "simple_release_refund", "network_marker": "IRIUM", "payer": "Qpayer", "payee": "Qpayee", "parties": [], "total_amount": 50000000, "milestone_count": 0, "milestones": [], "settlement_deadline": 100, "refund_deadline": 120, "dispute_window": null, "document_hash": "11", "metadata_hash": null, "invoice_reference": null, "external_reference": null},
                    "local_bundle": {"bundle_used": true, "verification_ok": true, "saved_at": 1710000000u64, "source_label": "wallet-test", "note": null, "linked_funding_txids": ["bb"], "milestone_hints": [], "local_only_notice": "local only"},
                    "chain_observed": {"linked_transactions": [], "linked_transaction_count": 1, "anchor_observation_notice": "chain observed"},
                    "funding_legs": {"candidate_count": 1, "selection_required": false, "selected_leg": {"funding_txid": "bb", "htlc_vout": 0, "anchor_vout": 1, "role": "funding", "milestone_id": null, "amount": 50000000, "htlc_backed": true, "timeout_height": 120, "recipient_address": "Qpayee", "refund_address": "Qpayer", "source_notes": ["direct_anchor_match"], "release_eligible": false, "release_reasons": [], "refund_eligible": true, "refund_reasons": []}, "ambiguity_warning": null, "candidates": [], "notice": "derived only"},
                    "timeline": {"reconstructed": true, "event_count": 1, "events": [{"event_type": "funding_tx_observed", "source": "chain_observed", "txid": "bb", "height": 12, "timestamp": null, "milestone_id": null, "note": "linked tx"}], "notice": "timeline"},
                    "settlement_state": {"lifecycle_state": "funded", "derived_state_label": "funded", "selection_required": false, "funded_amount": 50000000, "released_amount": 0, "refunded_amount": 0, "summary_note": "derived state"},
                    "trust_boundaries": {"consensus_enforced": ["anchor visibility"], "htlc_enforced": ["htlc branch"], "metadata_indexed": ["timeline"], "local_bundle_only": ["bundle label"], "off_chain_required": ["agreement exchange"]}
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });
        let req = Request::builder()
            .method("POST")
            .uri("/agreement/statement/view")
            .header("content-type", "application/x-www-form-urlencoded")
            .extension(ConnectInfo(
                "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            ))
            .body(Body::from(form_body(&[(
                "agreement_json",
                &sample_agreement_json(),
            )])))
            .unwrap();
        let resp = build_app(test_state(format!("http://{}", addr)))
            .oneshot(req)
            .await
            .unwrap();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Derived settlement statement"));
        assert!(
            html.contains("Printable/shareable Phase 1 report artifact")
                || html.contains("printable/shareable Phase 1 report artifact")
        );
        assert!(html.contains("Statement view"));
        assert!(html.contains("Download statement JSON"));
        assert!(html.contains("not native consensus contract state"));
    }

    #[tokio::test]
    async fn agreement_verify_artifacts_view_renders_sections() {
        let upstream = Router::new().route(
            "/rpc/agreementaudit",
            post(|| async {
                Json(json!({
                    "metadata": {"version": 1, "generated_at": 1710000123u64, "generator_surface": "iriumd_rpc", "trust_model_summary": "derived only"},
                    "agreement": {"agreement_id": "agr-explorer-1", "agreement_hash": "aa", "template_type": "simple_release_refund", "network_marker": "IRIUM", "payer": "Qpayer", "payee": "Qpayee", "parties": [], "total_amount": 50000000, "milestone_count": 0, "milestones": [], "settlement_deadline": 100, "refund_deadline": 120, "dispute_window": null, "document_hash": "11", "metadata_hash": null, "invoice_reference": null, "external_reference": null},
                    "local_bundle": {"bundle_used": true, "verification_ok": true, "saved_at": 1710000000u64, "source_label": "wallet-test", "note": null, "linked_funding_txids": ["bb"], "milestone_hints": [], "local_only_notice": "local only"},
                    "chain_observed": {"linked_transactions": [{"txid": "bb", "role": "funding", "milestone_id": null, "height": 12, "confirmed": true, "value": 50000000}], "linked_transaction_count": 1, "anchor_observation_notice": "chain observed"},
                    "funding_legs": {"candidate_count": 1, "selection_required": false, "selected_leg": null, "ambiguity_warning": null, "candidates": [], "notice": "derived only"},
                    "timeline": {"reconstructed": true, "event_count": 1, "events": [], "notice": "timeline"},
                    "settlement_state": {"lifecycle_state": "funded", "derived_state_label": "funded", "selection_required": false, "funded_amount": 50000000, "released_amount": 0, "refunded_amount": 0, "summary_note": "derived state"},
                    "trust_boundaries": {"consensus_enforced": ["anchor visibility"], "htlc_enforced": ["htlc branch"], "metadata_indexed": ["timeline"], "local_bundle_only": ["bundle label"], "off_chain_required": ["agreement exchange"]}
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });
        let req = Request::builder()
            .method("POST")
            .uri("/agreement/verify-artifacts/view")
            .header("content-type", "application/x-www-form-urlencoded")
            .extension(ConnectInfo(
                "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            ))
            .body(Body::from(form_body(&[
                ("agreement_json", &sample_agreement_json()),
                ("audit_json", &sample_audit_json()),
                ("statement_json", &sample_statement_json()),
            ])))
            .unwrap();
        let resp = build_app(test_state(format!("http://{}", addr)))
            .oneshot(req)
            .await
            .unwrap();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Artifact verification"));
        assert!(html.contains("Verified matches"));
        assert!(html.contains("Unverifiable or limited"));
        assert!(html.contains("not native consensus contract state"));
    }

    #[tokio::test]
    async fn agreement_verify_artifacts_view_reports_missing_inputs() {
        let req = Request::builder()
            .method("POST")
            .uri("/agreement/verify-artifacts/view")
            .header("content-type", "application/x-www-form-urlencoded")
            .extension(ConnectInfo(
                "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            ))
            .body(Body::from(form_body(&[("agreement_json", "")])))
            .unwrap();
        let resp = build_app(test_state("http://127.0.0.1:1".to_string()))
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Missing artifacts"));
        assert!(html.contains("Trust Boundaries"));
    }

    #[tokio::test]
    async fn agreement_statement_download_json_returns_attachment() {
        let upstream = Router::new().route(
            "/rpc/agreementaudit",
            post(|| async {
                Json(json!({
                    "metadata": {"version": 1, "generated_at": 1710000123u64, "generator_surface": "iriumd_rpc", "trust_model_summary": "derived only"},
                    "agreement": {"agreement_id": "agr-explorer-1", "agreement_hash": "aa", "template_type": "simple_release_refund", "network_marker": "IRIUM", "payer": "Qpayer", "payee": "Qpayee", "parties": [], "total_amount": 50000000, "milestone_count": 0, "milestones": [], "settlement_deadline": 100, "refund_deadline": 120, "dispute_window": null, "document_hash": "11", "metadata_hash": null, "invoice_reference": null, "external_reference": null},
                    "local_bundle": {"bundle_used": true, "verification_ok": true, "saved_at": 1710000000u64, "source_label": "wallet-test", "note": null, "linked_funding_txids": ["bb"], "milestone_hints": [], "local_only_notice": "local only"},
                    "chain_observed": {"linked_transactions": [], "linked_transaction_count": 1, "anchor_observation_notice": "chain observed"},
                    "funding_legs": {"candidate_count": 1, "selection_required": false, "selected_leg": null, "ambiguity_warning": null, "candidates": [], "notice": "derived only"},
                    "timeline": {"reconstructed": true, "event_count": 1, "events": [], "notice": "timeline"},
                    "settlement_state": {"lifecycle_state": "funded", "derived_state_label": "funded", "selection_required": false, "funded_amount": 50000000, "released_amount": 0, "refunded_amount": 0, "summary_note": "derived state"},
                    "trust_boundaries": {"consensus_enforced": ["anchor visibility"], "htlc_enforced": ["htlc branch"], "metadata_indexed": ["timeline"], "local_bundle_only": ["bundle label"], "off_chain_required": ["agreement exchange"]}
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });
        let req = Request::builder()
            .method("POST")
            .uri("/agreement/statement/download.json")
            .header("content-type", "application/x-www-form-urlencoded")
            .extension(ConnectInfo(
                "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            ))
            .body(Body::from(form_body(&[(
                "agreement_json",
                &sample_agreement_json(),
            )])))
            .unwrap();
        let resp = build_app(test_state(format!("http://{}", addr)))
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/json"
        );
        assert!(resp
            .headers()
            .get("content-disposition")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("agreement-audit-agr-html-1.statement.json"));
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let rendered = String::from_utf8(body.to_vec()).unwrap();
        assert!(rendered.contains("derived_notice"));
        assert!(rendered.contains("canonical_agreement_notice"));
    }
    #[tokio::test]
    async fn agreement_verify_signature_view_renders_detached_and_embedded_results() {
        let req = Request::builder()
            .method("POST")
            .uri("/agreement/verify-signature/view")
            .header("content-type", "application/x-www-form-urlencoded")
            .extension(ConnectInfo(
                "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            ))
            .body(Body::from(form_body(&[
                ("agreement_json", &sample_signed_bundle_json()),
                ("signature_json", &sample_signature_json()),
            ])))
            .unwrap();
        let resp = build_app(test_state("http://127.0.0.1:1".to_string()))
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Detached signature"));
        assert!(html.contains("Embedded bundle signatures"));
        assert!(html.contains("Qsigview"));
        assert!(html.contains("authenticity only"));
    }
    #[tokio::test]
    async fn agreement_share_package_verify_view_renders_sections() {
        let upstream = Router::new().route(
            "/rpc/agreementaudit",
            post(|| async {
                Json(json!({
                    "metadata": {"version": 1, "generated_at": 1710000123u64, "generator_surface": "iriumd_rpc", "trust_model_summary": "derived only"},
                    "agreement": {"agreement_id": "agr-html-1", "agreement_hash": "8e3637f53ee6b1af34970958d0252285b6e97b996462d0b11f8c8bf5ffc4a434", "template_type": "simple_release_refund", "network_marker": "IRIUM", "payer": "Qpayer", "payee": "Qpayee", "parties": [], "total_amount": 150000000, "milestone_count": 0, "milestones": [], "settlement_deadline": 120, "refund_deadline": 240, "dispute_window": null, "document_hash": "11", "metadata_hash": null, "invoice_reference": null, "external_reference": null},
                    "local_bundle": {"bundle_used": true, "verification_ok": true, "saved_at": 1710000000u64, "source_label": "wallet-test", "note": null, "linked_funding_txids": ["bb"], "milestone_hints": [], "local_only_notice": "local only"},
                    "chain_observed": {"linked_transactions": [{"txid": "bb", "role": "funding", "milestone_id": null, "height": 12, "confirmed": true, "value": 150000000}], "linked_transaction_count": 1, "anchor_observation_notice": "chain observed"},
                    "funding_legs": {"candidate_count": 1, "selection_required": false, "selected_leg": null, "ambiguity_warning": null, "candidates": [], "notice": "derived only"},
                    "timeline": {"reconstructed": true, "event_count": 1, "events": [], "notice": "timeline"},
                    "settlement_state": {"lifecycle_state": "funded", "derived_state_label": "funded", "selection_required": false, "funded_amount": 150000000, "released_amount": 0, "refunded_amount": 0, "summary_note": "derived state"},
                    "trust_boundaries": {"consensus_enforced": ["anchor visibility"], "htlc_enforced": ["htlc branch"], "metadata_indexed": ["timeline"], "local_bundle_only": ["bundle label"], "off_chain_required": ["agreement exchange"]}
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });
        let req = Request::builder()
            .method("POST")
            .uri("/agreement/share-package/verify/view")
            .header("content-type", "application/x-www-form-urlencoded")
            .extension(ConnectInfo(
                "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            ))
            .body(Body::from(form_body(&[(
                "share_package_json",
                &sample_share_package_json(),
            )])))
            .unwrap();
        let resp = build_app(test_state(format!("http://{}", addr)))
            .oneshot(req)
            .await
            .unwrap();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Share package summary"));
        assert!(html.contains("Package profile"));
        assert!(html.contains("full_informational_package"));
        assert!(html.contains("Omitted artifacts"));
        assert!(html.contains("Package notices"));
        assert!(html.contains("Verified matches"));
        assert!(
            html.contains("native agreement state")
                || html.contains("not native consensus contract state")
        );
    }

    #[tokio::test]
    async fn agreement_share_package_verify_view_reports_missing_input() {
        let req = Request::builder()
            .method("POST")
            .uri("/agreement/share-package/verify/view")
            .header("content-type", "application/x-www-form-urlencoded")
            .extension(ConnectInfo(
                "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            ))
            .body(Body::from(form_body(&[("share_package_json", "")])))
            .unwrap();
        let resp = build_app(test_state("http://127.0.0.1:1".to_string()))
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Missing share package"));
    }

    #[test]
    fn artifact_verification_section_renders_authenticity_summary() {
        let result = AgreementArtifactVerificationResult {
            metadata: irium_node_rs::settlement::AgreementArtifactVerificationMetadata {
                version: 1,
                generated_at: 1,
                derived_notice: "derived".to_string(),
            },
            input_summary: irium_node_rs::settlement::AgreementArtifactVerificationInputSummary {
                supplied_artifact_types: vec![
                    "agreement".to_string(),
                    "agreement_signature".to_string(),
                ],
                canonical_agreement_present: true,
                extracted_from_bundle: false,
                claimed_agreement_id: vec!["agr-test".to_string()],
                claimed_agreement_hash: vec!["aa".repeat(32)],
            },
            canonical_verification:
                irium_node_rs::settlement::AgreementArtifactCanonicalVerification {
                    canonical_agreement_present: true,
                    computed_agreement_hash: Some("aa".repeat(32)),
                    computed_agreement_id: Some("agr-test".to_string()),
                    bundle_hash_match: None,
                    audit_identity_match: None,
                    statement_identity_match: None,
                    matches: vec![
                        "Agreement signature target matched canonical agreement hash".to_string(),
                    ],
                    mismatches: vec![],
                    warnings: vec![],
                },
            artifact_consistency:
                irium_node_rs::settlement::AgreementArtifactConsistencyVerification {
                    bundle_matches_canonical: None,
                    audit_matches_canonical: None,
                    statement_matches_canonical: None,
                    warnings: vec![],
                },
            chain_verification: irium_node_rs::settlement::AgreementArtifactChainVerification {
                linked_tx_references_found: false,
                anchor_observations_found: false,
                checked_txids: vec![],
                audit_chain_match: None,
                statement_chain_match: None,
                warnings: vec![],
            },
            derived_verification: irium_node_rs::settlement::AgreementArtifactDerivedVerification {
                audit_derived_match: None,
                statement_derived_match: None,
                warnings: vec![],
            },
            authenticity: Some(
                irium_node_rs::settlement::AgreementArtifactAuthenticityVerification {
                    detached_agreement_signatures_supplied: 1,
                    detached_bundle_signatures_supplied: 0,
                    embedded_bundle_signatures_supplied: 0,
                    valid_signatures: 0,
                    invalid_signatures: 1,
                    unverifiable_signatures: 0,
                    signer_summaries: vec![
                        "agreement Qauth role buyer target aa status invalid".to_string()
                    ],
                    verifications: vec![],
                    warnings: vec![
                        "signature target hash did not match the supplied artifact".to_string()
                    ],
                    authenticity_notice: "Signature validity is authenticity only".to_string(),
                },
            ),
            trust_summary: irium_node_rs::settlement::AgreementArtifactVerificationTrustSummary {
                consensus_visible: vec!["anchors".to_string()],
                htlc_enforced: vec!["htlc".to_string()],
                derived_indexed: vec!["timeline".to_string()],
                local_artifact_only: vec!["bundle".to_string()],
                unverifiable_from_chain_alone: vec!["full agreement terms".to_string()],
            },
        };
        let html = render_artifact_verification_section(&result);
        assert!(html.contains("Authenticity"));
        assert!(html.contains("Detached agreement signatures"));
        assert!(html.contains("Signature validity is authenticity only"));
    }
}
