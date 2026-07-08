//! LTC public-API + regtest fetch logic for the in-process header
//! sync task. Mirrors `src/bin/ltc-header-sync.rs` but async.

use std::env;
use std::time::Duration;

use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};

use super::common::{
    Source, PER_HEADER_RETRIES, POLITE_SLEEP_MS, RETRY_SLEEP_MS,
};

const DEFAULT_LTC_RPC_URL: &str = "http://127.0.0.1:19443";
const DEFAULT_LTC_RPC_USER: &str = "iriumtest";
const DEFAULT_LTC_RPC_PASSWORD: &str = "iriumtest";

const MAINNET_APIS: &[&str] = &["https://litecoinspace.org/api"];

pub async fn fetch_ltc_net_tip(client: &Client, source: Source) -> Result<u64, String> {
    match source {
        Source::Regtest => regtest_get_block_count(client).await,
        Source::Mainnet => mainnet_get_tip_height(client).await,
    }
}

pub async fn fetch_ltc_headers(
    client: &Client,
    source: Source,
    start: u64,
    end: u64,
) -> Result<String, String> {
    match source {
        Source::Regtest => regtest_fetch_headers(client, start, end).await,
        Source::Mainnet => mainnet_fetch_headers(client, start, end).await,
    }
}

// -------- Regtest source (litecoind JSON-RPC) --------

#[derive(Deserialize)]
struct LitecoindRpcResp<T> {
    result: Option<T>,
    error: Option<Value>,
}

async fn litecoind_rpc<T: for<'de> serde::Deserialize<'de>>(
    client: &Client,
    method: &str,
    params: Value,
) -> Result<T, String> {
    let url = env::var("LTC_RPC_URL").unwrap_or_else(|_| DEFAULT_LTC_RPC_URL.to_string());
    let user = env::var("LTC_RPC_USER").unwrap_or_else(|_| DEFAULT_LTC_RPC_USER.to_string());
    let password =
        env::var("LTC_RPC_PASSWORD").unwrap_or_else(|_| DEFAULT_LTC_RPC_PASSWORD.to_string());

    let body = json!({
        "jsonrpc": "1.0",
        "id": "iriumd-ltc-header-sync",
        "method": method,
        "params": params,
    });
    let resp = client
        .post(&url)
        .basic_auth(user, Some(password))
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("litecoind {method} request failed: {e}"))?;
    let status = resp.status();
    let raw = resp
        .text()
        .await
        .map_err(|e| format!("litecoind {method} body read failed: {e}"))?;
    if !status.is_success() {
        return Err(format!(
            "litecoind {method} returned HTTP {status}; body: {raw}"
        ));
    }
    let parsed: LitecoindRpcResp<T> = serde_json::from_str(&raw)
        .map_err(|e| format!("litecoind {method} decode failed: {e}; raw: {raw}"))?;
    if let Some(err) = parsed.error {
        if !err.is_null() {
            return Err(format!("litecoind {method} returned error: {err}"));
        }
    }
    parsed
        .result
        .ok_or_else(|| format!("litecoind {method} returned no result"))
}

async fn regtest_get_block_count(client: &Client) -> Result<u64, String> {
    litecoind_rpc::<u64>(client, "getblockcount", json!([])).await
}

async fn regtest_fetch_headers(
    client: &Client,
    start: u64,
    end: u64,
) -> Result<String, String> {
    let mut hex_out = String::with_capacity(((end - start + 1) * 160) as usize);
    for height in start..=end {
        let hash =
            litecoind_rpc::<String>(client, "getblockhash", json!([height])).await?;
        let header_hex =
            litecoind_rpc::<String>(client, "getblockheader", json!([hash, false])).await?;
        if header_hex.len() != 160 {
            return Err(format!(
                "litecoind getblockheader at h={height} returned hex length {} (expected 160)",
                header_hex.len()
            ));
        }
        hex_out.push_str(&header_hex);
    }
    Ok(hex_out)
}

// -------- Mainnet source (public LTC API) --------

async fn mainnet_get_tip_height(client: &Client) -> Result<u64, String> {
    let mut last_err = String::new();
    for api in MAINNET_APIS {
        let url = format!("{api}/blocks/tip/height");
        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => match resp.text().await {
                Ok(t) => match t.trim().parse::<u64>() {
                    Ok(h) => return Ok(h),
                    Err(e) => last_err = format!("{api} returned non-numeric tip: {e}"),
                },
                Err(e) => last_err = format!("{api} body read failed: {e}"),
            },
            Ok(resp) => last_err = format!("{api} returned HTTP {}", resp.status()),
            Err(e) => last_err = format!("{api} request failed: {e}"),
        }
    }
    Err(format!(
        "all public LTC APIs failed for tip-height probe; last error: {last_err}"
    ))
}

async fn mainnet_fetch_headers(
    client: &Client,
    start: u64,
    end: u64,
) -> Result<String, String> {
    let api = mainnet_pick_api(client).await?;
    let mut hex_out = String::with_capacity(((end - start + 1) * 160) as usize);
    for height in start..=end {
        let hash = mainnet_fetch_height_to_hash(client, api, height).await?;
        let header_hex = mainnet_fetch_block_header(client, api, &hash).await?;
        if header_hex.len() != 160 {
            return Err(format!(
                "header for height {height} has hex length {} (expected 160)",
                header_hex.len()
            ));
        }
        hex_out.push_str(&header_hex);
        tokio::time::sleep(Duration::from_millis(POLITE_SLEEP_MS)).await;
    }
    Ok(hex_out)
}

async fn mainnet_pick_api(client: &Client) -> Result<&'static str, String> {
    let mut last_err = String::new();
    for api in MAINNET_APIS {
        let url = format!("{api}/blocks/tip/height");
        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => return Ok(api),
            Ok(resp) => last_err = format!("{api} returned HTTP {}", resp.status()),
            Err(e) => last_err = format!("{api} request failed: {e}"),
        }
    }
    Err(format!(
        "no public LTC API responding for fetch loop; last error: {last_err}"
    ))
}

async fn mainnet_fetch_height_to_hash(
    client: &Client,
    api: &str,
    height: u64,
) -> Result<String, String> {
    let url = format!("{api}/block-height/{height}");
    let mut last_err = String::new();
    for attempt in 0..PER_HEADER_RETRIES {
        let result: Result<String, String> = async {
            let resp = client
                .get(&url)
                .send()
                .await
                .map_err(|e| format!("block-height {height} request failed: {e}"))?;
            if !resp.status().is_success() {
                return Err(format!(
                    "block-height {height} returned HTTP {}",
                    resp.status()
                ));
            }
            let h = resp
                .text()
                .await
                .map_err(|e| format!("block-height {height} body read failed: {e}"))?;
            let trimmed = h.trim();
            if trimmed.len() != 64 || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(format!(
                    "block-height {height} returned malformed hash: {trimmed:?}"
                ));
            }
            Ok(trimmed.to_string())
        }
        .await;
        match result {
            Ok(v) => return Ok(v),
            Err(e) => {
                last_err = e;
                if attempt + 1 < PER_HEADER_RETRIES {
                    tokio::time::sleep(Duration::from_millis(RETRY_SLEEP_MS)).await;
                }
            }
        }
    }
    Err(format!(
        "exhausted {PER_HEADER_RETRIES} attempts; last error: {last_err}"
    ))
}

async fn mainnet_fetch_block_header(
    client: &Client,
    api: &str,
    hash: &str,
) -> Result<String, String> {
    let url = format!("{api}/block/{hash}/header");
    let mut last_err = String::new();
    for attempt in 0..PER_HEADER_RETRIES {
        let result: Result<String, String> = async {
            let resp = client
                .get(&url)
                .send()
                .await
                .map_err(|e| format!("block/{hash}/header request failed: {e}"))?;
            if !resp.status().is_success() {
                return Err(format!(
                    "block/{hash}/header returned HTTP {}",
                    resp.status()
                ));
            }
            let h = resp
                .text()
                .await
                .map_err(|e| format!("block/{hash}/header body read failed: {e}"))?;
            Ok(h.trim().to_string())
        }
        .await;
        match result {
            Ok(v) => return Ok(v),
            Err(e) => {
                last_err = e;
                if attempt + 1 < PER_HEADER_RETRIES {
                    tokio::time::sleep(Duration::from_millis(RETRY_SLEEP_MS)).await;
                }
            }
        }
    }
    Err(format!(
        "exhausted {PER_HEADER_RETRIES} attempts; last error: {last_err}"
    ))
}
