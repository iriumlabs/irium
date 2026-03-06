use std::collections::{HashMap, HashSet};
use std::env;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use irium_node_rs::constants::{block_reward, COINBASE_MATURITY};
use irium_node_rs::rate_limiter::RateLimiter;
use reqwest::Client;
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
}

async fn load_block_entry(state: &AppState, height: u64) -> Option<MinedBlockEntry> {
    let path = format!("/rpc/block?height={}", height);
    let block = proxy_value(state, &path).await.ok()?;

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

    Some(MinedBlockEntry {
        miner,
        time,
        hash,
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
            Ok(block) => {
                ok_blocks += 1;
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
        if let Ok(block) = proxy_value(&state, &path).await {
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

async fn block(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(height): Path<u64>,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;
    proxy_json(&state, &format!("/rpc/block?height={}", height)).await
}

async fn blockhash(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(hash): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;
    proxy_json(&state, &format!("/rpc/block_by_hash?hash={}", hash)).await
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


async fn pool_stats(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PoolQuery>,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;

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
    let blocks_accepted = stratum_metrics
        .as_ref()
        .and_then(|m| m.get("blocks_accepted"))
        .cloned()
        .unwrap_or(Value::Null);
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
        "workers_online": miners.active_miners,
        "active_miners_window_blocks": miners.window_blocks,
        "active_miners_as_of_height": miners.as_of_height,
        "active_miners_updated_at": miners.updated_at_unix,
        "active_tcp_sessions": active_tcp_sessions,
        "accepted_shares": accepted_shares,
        "rejected_shares": rejected_shares,
        "blocks_accepted": blocks_accepted,
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
    Query(q): Query<PoolQuery>,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;

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

            payouts.push(json!({
                "height": height,
                "address": entry.miner,
                "reward_irm": reward_irm_for_height(height),
                "time": entry.time,
                "hash": entry.hash,
                "status": "on_chain",
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
    Query(q): Query<PoolQuery>,
) -> Result<Json<Value>, StatusCode> {
    check_rate(&state, &addr, &headers)?;

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
    rows.sort_by(|a, b| b.1.cmp(&a.1));

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
    rows.sort_by(|a, b| b.1.cmp(&a.1));

    let unique_addresses = rows.len() as u64;

    let top1_share_pct = rows
        .first()
        .map(|(_, c)| if total_found > 0 { (*c as f64) * 100.0 / (total_found as f64) } else { 0.0 })
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

    let app = Router::new()
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
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();

    let host = env::var("IRIUM_EXPLORER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port: u16 = env::var("IRIUM_EXPLORER_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(38310);
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
