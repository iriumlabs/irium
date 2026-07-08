//! LTC header sync — periodic relay top-up.
//!
//! DEPRECATED in v1.9.48: header sync is now an internal iriumd
//! background tokio task (see `src/header_sync/` and the
//! `maybe_spawn_ltc_header_sync` / `run_ltc_header_sync_cycle`
//! helpers in `src/bin/iriumd.rs`). New deployments rely on the
//! integrated runner; this standalone binary is retained as a fallback
//! and for one-shot manual top-ups during devnet testing. It will be
//! removed in a later release once all production deployments have
//! migrated.
//!
//! One-shot binary intended to run under a systemd timer every 10 minutes
//! once activated, OR invoked directly during devnet end-to-end testing.
//! Reads the current iriumd LTC SPV relay tip, fetches new Litecoin
//! headers from a configurable source, and submits them via
//! `/rpc/submitltcheaders`.
//!
//! Mirrors `btc-header-sync.rs` byte-for-byte where the structure
//! coincides; differs only in:
//!   - Endpoint: `/rpc/ltcrelaytip` and `/rpc/submitltcheaders`
//!   - Cap: 144 headers per batch (matches iriumd
//!     `MAX_LTC_HEADERS_PER_BATCH`; happens to equal BTC's pragmatic
//!     batch cap too).
//!   - Source dispatch: `IRIUM_LTC_HEADER_SYNC_SOURCE` selects between
//!     `regtest` (queries a local litecoind via JSON-RPC for
//!     reproducible devnet testing) and `mainnet` (queries a public
//!     Litecoin block-explorer API, mirroring btc-header-sync's
//!     mempool.space / blockstream.info dual-API path).
//!
//! Design constraints — same as btc-header-sync:
//!   - 3-block safety lag (LTC mainnet) so we never submit headers
//!     within 3 blocks of the network tip.
//!   - 144-header batch cap per cycle.
//!   - 3 retries per single header-fetch before failing the whole batch.
//!   - No API key required for the mainnet path.
//!
//! Env vars:
//!   IRIUMD_RPC_TOKEN              required
//!   IRIUMD_RPC_URL                default http://127.0.0.1:38300
//!   IRIUM_LTC_HEADER_SYNC_SOURCE  "regtest" | "mainnet" (default "mainnet")
//!
//!   LTC_RPC_URL                   regtest only, default http://127.0.0.1:19443
//!   LTC_RPC_USER                  regtest only, default iriumtest
//!   LTC_RPC_PASSWORD              regtest only, default iriumtest
//!
//!   LTC_HEADER_SYNC_LOG           default /home/irium/ltc_header_sync.log
//!
//! Exit codes:
//!   0  — success, or relay gate closed, or already up-to-date
//!   1  — any failure
//!
//! Concurrency: systemd `Type=oneshot` + `OnUnitInactiveSec` guarantees
//! no overlap; no in-process flock needed.

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
const DEFAULT_LOG_PATH: &str = "/home/irium/ltc_header_sync.log";
const USER_AGENT: &str = "irium-ltc-header-sync/1.0";

const DEFAULT_LTC_RPC_URL: &str = "http://127.0.0.1:19443";
const DEFAULT_LTC_RPC_USER: &str = "iriumtest";
const DEFAULT_LTC_RPC_PASSWORD: &str = "iriumtest";

/// Number of blocks to stay behind the public Litecoin tip in mainnet
/// mode. Same rationale as the BTC binary — keeps the relay clear of
/// near-tip reorgs without making submitted headers stale.
const SAFETY_LAG: u64 = 3;

/// Maximum headers submitted in a single cycle. Matches iriumd's
/// `MAX_LTC_HEADERS_PER_BATCH`. At LTC's 2.5-minute target spacing 144
/// headers ≈ 6 hours; on regtest (no real spacing) the cap is just a
/// validation budget guard.
const BATCH_SIZE: u64 = 144;

const PER_HEADER_RETRIES: u32 = 3;
const RETRY_SLEEP_MS: u64 = 500;

const POLITE_SLEEP_MS: u64 = 50;

const HTTP_TIMEOUT_SECS: u64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    Regtest,
    Mainnet,
}

impl Source {
    fn from_env() -> Result<Self, String> {
        let raw = env::var("IRIUM_LTC_HEADER_SYNC_SOURCE")
            .unwrap_or_else(|_| "mainnet".to_string());
        match raw.trim().to_lowercase().as_str() {
            "regtest" => Ok(Source::Regtest),
            "mainnet" => Ok(Source::Mainnet),
            other => Err(format!(
                "IRIUM_LTC_HEADER_SYNC_SOURCE must be 'regtest' or 'mainnet'; got {other:?}"
            )),
        }
    }
}

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

    let source = Source::from_env()?;

    let client = Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;

    let relay = get_relay_tip(&client, &rpc_url, &token)?;
    if !relay.active {
        log_line(
            "INFO",
            "relay gate closed (ltcrelaytip.active=false); skipping cycle",
        );
        return Ok(());
    }
    let relay_tip = relay.tip_height;

    let ltc_net_tip = get_ltc_net_tip(&client, source)?;
    if source == Source::Mainnet && ltc_net_tip <= SAFETY_LAG {
        return Err(format!(
            "ltc network tip {ltc_net_tip} <= safety lag {SAFETY_LAG}; refusing to submit"
        ));
    }
    // On regtest a 3-block safety lag is unhelpful — the operator
    // controls block production deterministically and wants every mined
    // block to be relayable immediately. Skip the lag in regtest mode.
    let target = match source {
        Source::Mainnet => ltc_net_tip - SAFETY_LAG,
        Source::Regtest => ltc_net_tip,
    };

    if relay_tip >= target {
        log_line(
            "INFO",
            &format!(
                "up to date — relay tip={relay_tip}, ltc net={ltc_net_tip}, target={target}"
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
            "source={source:?}, relay tip={relay_tip}, ltc net={ltc_net_tip}, \
             target={target}, submitting {count} headers [{start}..{end}]"
        ),
    );

    let headers_hex = fetch_headers(&client, source, start, end)?;

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
    let url = format!("{rpc_url}/rpc/ltcrelaytip");
    let resp = client
        .get(&url)
        .bearer_auth(token)
        .send()
        .map_err(|e| format!("ltcrelaytip request failed: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().unwrap_or_default();
        return Err(format!("ltcrelaytip returned HTTP {status}; body: {body}"));
    }
    resp.json::<RelayTip>()
        .map_err(|e| format!("ltcrelaytip decode failed: {e}"))
}

#[derive(Deserialize)]
struct SubmitResp {
    accepted: bool,
    txid: String,
    headers_count: u64,
    // iriumd returns null until the carrier tx is mined into a block and
    // the LtcHeaderBatch is applied to chain state. Same shape as the
    // BTC submit response — pending submissions have new_tip_height=None.
    #[serde(default)]
    new_tip_height: Option<u64>,
}

fn submit_headers(
    client: &Client,
    rpc_url: &str,
    token: &str,
    headers_hex: &str,
) -> Result<SubmitResp, String> {
    let url = format!("{rpc_url}/rpc/submitltcheaders");
    // Read fee_per_byte from env with a default of 100 sat/byte to stay at
    // or above the current mainnet mempool floor. Hardcoded `1` predated
    // the floor bump in v1.9.42 and caused every submission to be rejected.
    let fee_per_byte: u64 = env::var("LTC_HEADER_SYNC_FEE_PER_BYTE")
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
        .map_err(|e| format!("submitltcheaders request failed: {e}"))?;
    let status = resp.status();
    let raw = resp
        .text()
        .map_err(|e| format!("submitltcheaders body read failed: {e}"))?;
    if !status.is_success() {
        return Err(format!(
            "submitltcheaders returned HTTP {status}; body: {raw}"
        ));
    }
    let parsed: SubmitResp = serde_json::from_str(&raw)
        .map_err(|e| format!("submitltcheaders decode failed: {e}; raw: {raw}"))?;
    if !parsed.accepted {
        return Err(format!("submitltcheaders accepted=false; raw: {raw}"));
    }
    Ok(parsed)
}

// -------- LTC source dispatch --------

fn get_ltc_net_tip(client: &Client, source: Source) -> Result<u64, String> {
    match source {
        Source::Regtest => regtest_get_block_count(client),
        Source::Mainnet => mainnet_get_tip_height(client),
    }
}

fn fetch_headers(
    client: &Client,
    source: Source,
    start: u64,
    end: u64,
) -> Result<String, String> {
    match source {
        Source::Regtest => regtest_fetch_headers(client, start, end),
        Source::Mainnet => mainnet_fetch_headers(client, start, end),
    }
}

// -------- Regtest source (litecoind JSON-RPC) --------

#[derive(Deserialize)]
struct LitecoindRpcResp<T> {
    result: Option<T>,
    error: Option<serde_json::Value>,
}

fn litecoind_rpc<T: for<'de> serde::Deserialize<'de>>(
    client: &Client,
    method: &str,
    params: serde_json::Value,
) -> Result<T, String> {
    let url =
        env::var("LTC_RPC_URL").unwrap_or_else(|_| DEFAULT_LTC_RPC_URL.to_string());
    let user =
        env::var("LTC_RPC_USER").unwrap_or_else(|_| DEFAULT_LTC_RPC_USER.to_string());
    let password = env::var("LTC_RPC_PASSWORD")
        .unwrap_or_else(|_| DEFAULT_LTC_RPC_PASSWORD.to_string());

    let body = json!({
        "jsonrpc": "1.0",
        "id": "ltc-header-sync",
        "method": method,
        "params": params,
    });
    let resp = client
        .post(&url)
        .basic_auth(user, Some(password))
        .json(&body)
        .send()
        .map_err(|e| format!("litecoind {method} request failed: {e}"))?;
    let status = resp.status();
    let raw = resp
        .text()
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

fn regtest_get_block_count(client: &Client) -> Result<u64, String> {
    litecoind_rpc::<u64>(client, "getblockcount", json!([]))
}

fn regtest_fetch_headers(client: &Client, start: u64, end: u64) -> Result<String, String> {
    let mut hex_out = String::with_capacity(((end - start + 1) * 160) as usize);
    for height in start..=end {
        let hash = litecoind_rpc::<String>(client, "getblockhash", json!([height]))?;
        // getblockheader with verbose=false returns the 160-char hex
        // serialized 80-byte header.
        let header_hex =
            litecoind_rpc::<String>(client, "getblockheader", json!([hash, false]))?;
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

/// Public Litecoin block-explorer APIs. litecoinspace.org is the
/// canonical mempool.space-style public API for LTC and serves the
/// same `/blocks/tip/height`, `/block-height/{h}`, and
/// `/block/{hash}/header` endpoints. We list a single primary; if a
/// secondary mempool.space-compatible LTC mirror appears it can be
/// appended here without code change.
const MAINNET_APIS: &[&str] = &["https://litecoinspace.org/api"];

fn mainnet_get_tip_height(client: &Client) -> Result<u64, String> {
    let mut last_err = String::new();
    for api in MAINNET_APIS {
        let url = format!("{api}/blocks/tip/height");
        match client.get(&url).send() {
            Ok(resp) if resp.status().is_success() => match resp.text() {
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

fn mainnet_fetch_headers(
    client: &Client,
    start: u64,
    end: u64,
) -> Result<String, String> {
    let api = mainnet_pick_api(client)?;
    let mut hex_out = String::with_capacity(((end - start + 1) * 160) as usize);

    for height in start..=end {
        let hash = mainnet_fetch_height_to_hash(client, api, height)?;
        let header_hex = mainnet_fetch_block_header(client, api, &hash)?;
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

fn mainnet_pick_api(client: &Client) -> Result<&'static str, String> {
    let mut last_err = String::new();
    for api in MAINNET_APIS {
        let url = format!("{api}/blocks/tip/height");
        match client.get(&url).send() {
            Ok(resp) if resp.status().is_success() => return Ok(api),
            Ok(resp) => last_err = format!("{api} returned HTTP {}", resp.status()),
            Err(e) => last_err = format!("{api} request failed: {e}"),
        }
    }
    Err(format!(
        "no public LTC API responding for fetch loop; last error: {last_err}"
    ))
}

fn mainnet_fetch_height_to_hash(
    client: &Client,
    api: &str,
    height: u64,
) -> Result<String, String> {
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

fn mainnet_fetch_block_header(
    client: &Client,
    api: &str,
    hash: &str,
) -> Result<String, String> {
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

// -------- retry --------

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
    let path =
        env::var("LTC_HEADER_SYNC_LOG").unwrap_or_else(|_| DEFAULT_LOG_PATH.to_string());
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "{line}");
    }
}
