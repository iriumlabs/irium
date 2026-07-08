//! BTC public-API fetch logic for the in-process header sync task.
//!
//! Mirrors `src/bin/btc-header-sync.rs` (mempool.space primary,
//! blockstream.info fallback) but uses async reqwest so the cycle
//! runs cleanly on the iriumd tokio runtime.

use std::time::Duration;

use reqwest::Client;

use super::common::{PER_HEADER_RETRIES, POLITE_SLEEP_MS, RETRY_SLEEP_MS};

/// API endpoints we try, in order. mempool.space is primary; if it
/// returns non-2xx or times out on the tip-height probe we fail over
/// to blockstream.info for the rest of the cycle.
const APIS: &[&str] = &[
    "https://mempool.space/api",
    "https://blockstream.info/api",
];

/// Queries each API in turn for the current BTC mainnet tip height.
/// Returns the first successful response.
pub async fn fetch_btc_net_tip(client: &Client) -> Result<u64, String> {
    let mut last_err = String::new();
    for api in APIS {
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
        "all public BTC APIs failed for tip-height probe; last error: {last_err}"
    ))
}

/// Fetches concatenated header hex for the inclusive height range
/// `[start, end]`. Picks an API once (whichever succeeds at the
/// tip-height probe) and stays on it for the whole batch so per-call
/// error attribution is unambiguous.
pub async fn fetch_btc_headers(
    client: &Client,
    start: u64,
    end: u64,
) -> Result<String, String> {
    let api = pick_working_api(client).await?;
    let mut hex_out = String::with_capacity(((end - start + 1) * 160) as usize);

    for height in start..=end {
        let hash = fetch_height_to_hash(client, api, height).await?;
        let header_hex = fetch_block_header(client, api, &hash).await?;
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

async fn pick_working_api(client: &Client) -> Result<&'static str, String> {
    let mut last_err = String::new();
    for api in APIS {
        let url = format!("{api}/blocks/tip/height");
        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => return Ok(api),
            Ok(resp) => last_err = format!("{api} returned HTTP {}", resp.status()),
            Err(e) => last_err = format!("{api} request failed: {e}"),
        }
    }
    Err(format!(
        "no public BTC API responding for fetch loop; last error: {last_err}"
    ))
}

async fn fetch_height_to_hash(
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

async fn fetch_block_header(
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
