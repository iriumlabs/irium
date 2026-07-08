//! BTC header sync — periodic relay top-up.
//!
//! DEPRECATED in v1.9.48: header sync is now an internal iriumd
//! background tokio task (see `src/header_sync/` and the
//! `maybe_spawn_btc_header_sync` / `run_btc_header_sync_cycle`
//! helpers in `src/bin/iriumd.rs`). New deployments rely on the
//! integrated runner; this standalone binary is retained as a fallback
//! for operators who can't immediately upgrade, and for one-shot manual
//! top-ups during devnet testing. It will be removed in a later release
//! once all production deployments have migrated.
//!
//! One-shot binary intended to run under a systemd timer every 10 minutes.
//! Reads the current iriumd BTC SPV relay tip, fetches new Bitcoin headers
//! from a public API (mempool.space primary, blockstream.info fallback),
//! and submits them via `/rpc/submitbtcheaders`.
//!
//! Design constraints (locked by spec at time of writing):
//!   - 10-minute interval (managed by the timer, not in-process).
//!   - 3-block safety lag — never submit headers within 3 blocks of the
//!     network tip, to avoid pushing soon-to-be-orphaned headers.
//!   - 144-header batch cap per cycle (24 h worth of BTC blocks).
//!   - 3 retries per single-header fetch before failing the whole batch.
//!     A failed batch exits non-zero; the next timer tick retries from
//!     the same relay tip, so partial work never leaks into state.
//!   - No API key required; both APIs are free.
//!
//! Exit codes:
//!   0  — success, or relay gate closed, or already up-to-date
//!   1  — any failure (relay RPC, API, header validation, submit refusal)
//!
//! Concurrency: systemd `Type=oneshot` + `OnUnitInactiveSec` guarantees no
//! overlap; no in-process flock needed.

use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use chrono::Utc;
use reqwest::blocking::Client;
use serde::Deserialize;
use serde_json::json;

const DEFAULT_RPC_URL: &str = "http://127.0.0.1:38300";
const DEFAULT_LOG_PATH: &str = "/home/irium/btc_header_sync.log";
const USER_AGENT: &str = "irium-btc-header-sync/1.0";

/// Number of blocks to stay behind the public Bitcoin tip. 3 blocks
/// keeps the relay clear of near-tip reorgs without making submitted
/// headers stale by HTLC-claim time (HTLC claims require ≥6 confs,
/// so 3 blocks of headroom still leaves a wide useful window).
const SAFETY_LAG: u64 = 3;

/// Maximum headers submitted in a single cycle. 144 ≈ 24 h of BTC
/// blocks at 10-minute target spacing; chosen to recover from short
/// outages in one cycle while keeping the per-cycle bandwidth and
/// per-block validation budget small.
const BATCH_SIZE: u64 = 144;

/// Number of retry attempts for a single header-fetch call before
/// giving up on the whole batch. Each retry sleeps `RETRY_SLEEP_MS`
/// to back off against transient API issues.
const PER_HEADER_RETRIES: u32 = 3;
const RETRY_SLEEP_MS: u64 = 500;

/// Throttle between sequential public-API requests, to be polite to
/// mempool.space / blockstream.info even though their published
/// rate limits comfortably accommodate higher rates.
const POLITE_SLEEP_MS: u64 = 50;

/// HTTP client timeout for any single request — covers iriumd RPC and
/// public API calls. Large enough for a slow upstream batch validation
/// (header submit) but short enough that a hung mempool.space request
/// fails fast within one cycle.
const HTTP_TIMEOUT_SECS: u64 = 30;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log_line("ERROR", &e.to_string());
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let token =
        env::var("IRIUMD_RPC_TOKEN").map_err(|_| "IRIUMD_RPC_TOKEN env var missing".to_string())?;
    if token.trim().is_empty() {
        return Err("IRIUMD_RPC_TOKEN is empty".into());
    }
    let rpc_url =
        env::var("IRIUMD_RPC_URL").unwrap_or_else(|_| DEFAULT_RPC_URL.to_string());

    let client = Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;

    let relay = get_relay_tip(&client, &rpc_url, &token)?;
    if !relay.active {
        log_line(
            "INFO",
            "relay gate closed (btcrelaytip.active=false); skipping cycle",
        );
        return Ok(());
    }
    let relay_tip = relay.tip_height;

    let btc_net_tip = get_btc_net_tip(&client)?;
    if btc_net_tip <= SAFETY_LAG {
        return Err(format!(
            "btc network tip {btc_net_tip} <= safety lag {SAFETY_LAG}; refusing to submit"
        ));
    }
    let target = btc_net_tip - SAFETY_LAG;

    if relay_tip >= target {
        log_line(
            "INFO",
            &format!(
                "up to date — relay tip={relay_tip}, btc net={btc_net_tip}, target={target}"
            ),
        );
        return Ok(());
    }

    let start = relay_tip + 1;
    let end = std::cmp::min(start + BATCH_SIZE - 1, target);
    let count = end - start + 1;
    log_line(
        "INFO",
        &format!(
            "relay tip={relay_tip}, btc net={btc_net_tip}, target={target}, \
             submitting {count} headers [{start}..{end}]"
        ),
    );

    let headers_hex = fetch_headers(&client, start, end)?;

    let submitted = submit_headers(&client, &rpc_url, &token, &headers_hex)?;
    log_line(
        "INFO",
        &format!(
            "accepted=true headers_count={} new_tip_height={} txid={}",
            submitted.headers_count,
            submitted
                .new_tip_height
                .map(|h| h.to_string())
                .unwrap_or_else(|| "pending".to_string()),
            submitted.txid
        ),
    );

    Ok(())
}

// -------- iriumd RPC --------

#[derive(Deserialize)]
struct RelayTip {
    active: bool,
    tip_height: u64,
}

fn get_relay_tip(client: &Client, rpc_url: &str, token: &str) -> Result<RelayTip, String> {
    let url = format!("{rpc_url}/rpc/btcrelaytip");
    let resp = client
        .get(&url)
        .bearer_auth(token)
        .send()
        .map_err(|e| format!("btcrelaytip request failed: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().unwrap_or_default();
        return Err(format!(
            "btcrelaytip returned HTTP {status}; body: {body}"
        ));
    }
    resp.json::<RelayTip>()
        .map_err(|e| format!("btcrelaytip decode failed: {e}"))
}

#[derive(Deserialize)]
struct SubmitResp {
    accepted: bool,
    txid: String,
    headers_count: u64,
    // iriumd returns null until the carrier tx is mined into a block and
    // the BtcHeaderBatch is applied to chain state. Pending submissions
    // therefore have new_tip_height=None; only confirmed batches see a
    // u64 here.
    #[serde(default)]
    new_tip_height: Option<u64>,
}

fn submit_headers(
    client: &Client,
    rpc_url: &str,
    token: &str,
    headers_hex: &str,
) -> Result<SubmitResp, String> {
    let url = format!("{rpc_url}/rpc/submitbtcheaders");
    // Read fee_per_byte from env with a default of 100 sat/byte to stay at
    // or above the current mainnet mempool floor. Hardcoded `1` predated
    // the floor bump in v1.9.42 and caused every submission to be rejected.
    let fee_per_byte: u64 = env::var("BTC_HEADER_SYNC_FEE_PER_BYTE")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(100);
    let body = json!({
        "headers_hex": headers_hex,
        "broadcast": true,
        "fee_per_byte": fee_per_byte
    });
    let resp = client
        .post(&url)
        .bearer_auth(token)
        .json(&body)
        .send()
        .map_err(|e| format!("submitbtcheaders request failed: {e}"))?;
    let status = resp.status();
    let raw = resp
        .text()
        .map_err(|e| format!("submitbtcheaders body read failed: {e}"))?;
    if !status.is_success() {
        return Err(format!(
            "submitbtcheaders returned HTTP {status}; body: {raw}"
        ));
    }
    let parsed: SubmitResp = serde_json::from_str(&raw)
        .map_err(|e| format!("submitbtcheaders decode failed: {e}; raw: {raw}"))?;
    if !parsed.accepted {
        return Err(format!("submitbtcheaders accepted=false; raw: {raw}"));
    }
    Ok(parsed)
}

// -------- public BTC APIs --------

/// API endpoints we try, in order. mempool.space is primary; if it
/// returns non-2xx or times out on the tip-height probe we fail over
/// to blockstream.info for the rest of the cycle.
const APIS: &[&str] = &[
    "https://mempool.space/api",
    "https://blockstream.info/api",
];

fn get_btc_net_tip(client: &Client) -> Result<u64, String> {
    let mut last_err = String::new();
    for api in APIS {
        let url = format!("{api}/blocks/tip/height");
        match client.get(&url).send() {
            Ok(resp) if resp.status().is_success() => match resp.text() {
                Ok(t) => match t.trim().parse::<u64>() {
                    Ok(h) => return Ok(h),
                    Err(e) => last_err = format!("{api} returned non-numeric tip: {e}"),
                },
                Err(e) => last_err = format!("{api} body read failed: {e}"),
            },
            Ok(resp) => {
                last_err = format!("{api} returned HTTP {}", resp.status());
            }
            Err(e) => last_err = format!("{api} request failed: {e}"),
        }
    }
    Err(format!(
        "all public BTC APIs failed for tip-height probe; last error: {last_err}"
    ))
}

fn fetch_headers(client: &Client, start: u64, end: u64) -> Result<String, String> {
    // Pick the API that succeeded for the tip probe and use it for the
    // whole batch — switching mid-batch would make per-call error
    // attribution confusing.
    let api = pick_working_api(client)?;
    let mut hex_out = String::with_capacity(((end - start + 1) * 160) as usize);

    for height in start..=end {
        let hash = fetch_height_to_hash(client, api, height)?;
        let header_hex = fetch_block_header(client, api, &hash)?;
        if header_hex.len() != 160 {
            return Err(format!(
                "header for height {height} has hex length {} (expected 160)",
                header_hex.len()
            ));
        }
        hex_out.push_str(&header_hex);
        thread::sleep(Duration::from_millis(POLITE_SLEEP_MS));
    }
    Ok(hex_out)
}

fn pick_working_api(client: &Client) -> Result<&'static str, String> {
    let mut last_err = String::new();
    for api in APIS {
        let url = format!("{api}/blocks/tip/height");
        match client.get(&url).send() {
            Ok(resp) if resp.status().is_success() => return Ok(api),
            Ok(resp) => last_err = format!("{api} returned HTTP {}", resp.status()),
            Err(e) => last_err = format!("{api} request failed: {e}"),
        }
    }
    Err(format!(
        "no public BTC API responding for fetch loop; last error: {last_err}"
    ))
}

fn fetch_height_to_hash(client: &Client, api: &str, height: u64) -> Result<String, String> {
    let url = format!("{api}/block-height/{height}");
    retry(PER_HEADER_RETRIES, || {
        let resp = client
            .get(&url)
            .send()
            .map_err(|e| format!("block-height {height} request failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!(
                "block-height {height} returned HTTP {}",
                resp.status()
            ));
        }
        let h = resp
            .text()
            .map_err(|e| format!("block-height {height} body read failed: {e}"))?;
        let trimmed = h.trim();
        if trimmed.len() != 64 || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!(
                "block-height {height} returned malformed hash: {trimmed:?}"
            ));
        }
        Ok(trimmed.to_string())
    })
}

fn fetch_block_header(client: &Client, api: &str, hash: &str) -> Result<String, String> {
    let url = format!("{api}/block/{hash}/header");
    retry(PER_HEADER_RETRIES, || {
        let resp = client
            .get(&url)
            .send()
            .map_err(|e| format!("block/{hash}/header request failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!(
                "block/{hash}/header returned HTTP {}",
                resp.status()
            ));
        }
        let h = resp
            .text()
            .map_err(|e| format!("block/{hash}/header body read failed: {e}"))?;
        Ok(h.trim().to_string())
    })
}

fn retry<T, F: FnMut() -> Result<T, String>>(attempts: u32, mut f: F) -> Result<T, String> {
    let mut last_err = String::new();
    for attempt in 0..attempts {
        match f() {
            Ok(v) => return Ok(v),
            Err(e) => {
                last_err = e;
                if attempt + 1 < attempts {
                    thread::sleep(Duration::from_millis(RETRY_SLEEP_MS));
                }
            }
        }
    }
    Err(format!(
        "exhausted {attempts} attempts; last error: {last_err}"
    ))
}

// -------- logging --------

fn log_line(level: &str, message: &str) {
    let ts = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let line = format!("{ts} [{level}] {message}");
    eprintln!("{line}");
    let path = env::var("BTC_HEADER_SYNC_LOG").unwrap_or_else(|_| DEFAULT_LOG_PATH.to_string());
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "{line}");
    }
}
