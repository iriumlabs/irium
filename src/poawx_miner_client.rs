//! Shared PoAW-X miner RPC client helpers (Stage G0 extraction).
//!
//! Moved verbatim out of `src/bin/irium-miner.rs` so both the CPU miner
//! (`irium-miner`) and the GPU miner (`irium-miner-gpu`, Stage G1) can share the
//! same node-RPC plumbing, block-template fetch, and PoAW-X candidate /
//! registration / submit client calls. Pure code move: no logic changed. Struct
//! fields are `pub` so the binaries can read them across the crate boundary.

use reqwest::blocking::Client;
use reqwest::Certificate;
use reqwest::StatusCode;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use std::{env, fs};

use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
pub struct TemplateTx {
    pub hex: String,
    pub fee: Option<u64>,
    pub relay_addresses: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub struct BlockTemplate {
    pub height: u64,
    pub prev_hash: String,
    pub bits: String,
    pub time: u32,
    pub txs: Vec<TemplateTx>,
    /// Node-authoritative PoAW-X serving state for this height ("active" /
    /// "disabled"). `None` from older nodes that do not send the field. Once
    /// "active", legacy plain-PoW submissions are rejected by the node (405),
    /// so solo miners must take the PoAW-X path.
    #[serde(default)]
    pub poawx_mode: Option<String>,
    #[serde(default)]
    pub poawx_hidden_precommit_active: Option<bool>,
    #[serde(default)]
    pub poawx_audit_hardening_active: Option<bool>,
    #[serde(default)]
    pub poawx_tickets_active: Option<bool>,
    #[serde(default)]
    pub poawx_multisource_seed_active: Option<bool>,
    #[serde(default)]
    pub poawx_penalty_state_active: Option<bool>,
    #[serde(default)]
    pub poawx_puzzle_anchor_bits: Option<u32>,
    #[serde(default)]
    pub poawx_effective_sybil_bits: Option<u32>,
    // Phase 31 proposer-VRF fields (None on older nodes => proposer mining off).
    #[serde(default)]
    pub poawx_proposer_vrf_active: Option<bool>,
    #[serde(default)]
    pub poawx_proposer_seed: Option<String>,
    #[serde(default)]
    pub poawx_proposer_eligible_count: Option<u64>,
    #[serde(default)]
    pub poawx_proposer_round_interval: Option<u64>,
    #[serde(default)]
    pub poawx_proposer_freeze_height: Option<u64>,
    #[serde(default)]
    pub poawx_proposer_max_allowed_round: Option<u32>,
    /// Earliest header time this block may carry, or 0/None when the minimum-spacing
    /// gate is inactive (or the node predates the field). The miner waits for it so
    /// timestamps track wall clock rather than drifting ahead of it.
    #[serde(default)]
    pub poawx_min_block_time: Option<u32>,
    // Phase 31R proposer-registration fields (None on older nodes).
    #[serde(default)]
    pub poawx_reg_active: Option<bool>,
    #[serde(default)]
    pub poawx_reg_anchor_height: Option<u64>,
    #[serde(default)]
    pub poawx_reg_anchor_hash: Option<String>,
    #[serde(default)]
    pub poawx_reg_required_sybil_bits: Option<u32>,
    #[serde(default)]
    pub poawx_reg_activations: Option<Vec<String>>,
    #[serde(default)]
    pub poawx_reg_announces: Option<Vec<String>>,
}

pub type PoawxParentInfo = (Option<[u8; 32]>, ([u8; 32], [u8; 32]));

pub fn rpc_token() -> Option<String> {
    env::var("IRIUM_RPC_TOKEN")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

pub fn rpc_status_error(prefix: &str, status: StatusCode) -> String {
    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        format!("{}: HTTP {} (check IRIUM_RPC_TOKEN)", prefix, status)
    } else {
        format!("{}: HTTP {}", prefix, status)
    }
}

pub fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

pub fn rpc_client() -> Result<Client, String> {
    let mut builder = Client::builder().timeout(Duration::from_secs(5));
    if let Ok(path) = env::var("IRIUM_RPC_CA") {
        let pem = fs::read(&path).map_err(|e| format!("read CA {path}: {e}"))?;
        let cert = Certificate::from_pem(&pem).map_err(|e| format!("invalid CA {path}: {e}"))?;
        builder = builder.add_root_certificate(cert);
    }
    let insecure = env::var("IRIUM_RPC_INSECURE")
        .ok()
        .map(|v| {
            let v = v.to_lowercase();
            v == "1" || v == "true" || v == "yes"
        })
        .unwrap_or(false);
    let strict = env::var("IRIUM_RPC_STRICT")
        .ok()
        .map(|v| {
            let v = v.to_lowercase();
            v == "1" || v == "true" || v == "yes"
        })
        .unwrap_or(false);
    let base = node_rpc_base();
    let mut allow_insecure = false;
    if !strict && insecure {
        let url = reqwest::Url::parse(&base).map_err(|e| format!("invalid RPC URL {base}: {e}"))?;
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
            allow_insecure = true;
        }
    }
    if allow_insecure {
        builder = builder.danger_accept_invalid_certs(true);
    }
    builder.build().map_err(|e| format!("build client: {e}"))
}

pub fn node_rpc_base() -> String {
    env::var("IRIUM_NODE_RPC").unwrap_or_else(|_| "https://127.0.0.1:38300".to_string())
}

pub fn is_tls_mismatch(err: &str) -> bool {
    let lower = err.to_lowercase();
    lower.contains("invalid http version")
}

pub fn is_https_scheme_mismatch(err: &str) -> bool {
    let lower = err.to_lowercase();
    lower.contains("wrong version number")
        || lower.contains("first record does not look like a tls handshake")
        || lower.contains("received http/0.9 when not allowed")
        || lower.contains("invalid http version")
        || lower.contains("tls handshake")
        || lower.contains("unexpected eof while reading")
}

pub fn with_rpc_base<T, F>(f: F) -> Result<T, String>
where
    F: Fn(&str) -> Result<T, String>,
{
    fn should_log_https_fallback() -> bool {
        static LAST_LOG: OnceLock<Mutex<Option<Instant>>> = OnceLock::new();
        let lock = LAST_LOG.get_or_init(|| Mutex::new(None));
        if let Ok(mut guard) = lock.lock() {
            let now = Instant::now();
            let allow = guard
                .as_ref()
                .map(|t| now.duration_since(*t) >= Duration::from_secs(60))
                .unwrap_or(true);
            if allow {
                *guard = Some(now);
            }
            allow
        } else {
            true
        }
    }

    let base = node_rpc_base();
    match f(&base) {
        Ok(v) => Ok(v),
        Err(e) => {
            if base.starts_with("https://") && is_https_scheme_mismatch(&e) {
                let http = base.replacen("https://", "http://", 1);
                if let Ok(v) = f(&http) {
                    env::set_var("IRIUM_NODE_RPC", &http);
                    if should_log_https_fallback() {
                        eprintln!("[warn] RPC scheme mismatch; switching to {http}");
                    }
                    return Ok(v);
                }
            }
            if base.starts_with("http://") && is_tls_mismatch(&e) {
                let https = base.replacen("http://", "https://", 1);
                if let Ok(v) = f(&https) {
                    env::set_var("IRIUM_NODE_RPC", &https);
                    eprintln!("[warn] RPC scheme mismatch; switching to {https}");
                    return Ok(v);
                }
            }
            Err(e)
        }
    }
}

pub fn gbt_query_params(longpoll: bool) -> Vec<(String, String)> {
    let mut params = Vec::new();
    if longpoll {
        params.push(("longpoll".to_string(), "1".to_string()));
    }
    if let Ok(v) = env::var("IRIUM_GBT_LONGPOLL_SECS") {
        params.push(("poll_secs".to_string(), v));
    }
    if let Ok(v) = env::var("IRIUM_GBT_MAX_TXS") {
        params.push(("max_txs".to_string(), v));
    }
    if let Ok(v) = env::var("IRIUM_GBT_MIN_FEE") {
        params.push(("min_fee".to_string(), v));
    }
    params
}

pub fn fetch_block_template(client: &Client, longpoll: bool) -> Result<BlockTemplate, String> {
    with_rpc_base(|base| fetch_block_template_with_base(client, base, longpoll))
}

pub fn fetch_block_template_with_base(
    client: &Client,
    base: &str,
    longpoll: bool,
) -> Result<BlockTemplate, String> {
    let url = format!("{}/rpc/getblocktemplate", base.trim_end_matches("/"));
    let mut req = client.get(url).query(&gbt_query_params(longpoll));
    if let Some(token) = rpc_token() {
        req = req.bearer_auth(token);
    }
    let resp = req.send().map_err(|e| format!("template failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(rpc_status_error("template failed", resp.status()));
    }
    resp.json().map_err(|e| format!("template parse: {e}"))
}

pub fn poawx_miner_secret() -> Result<[u8; 32], String> {
    let hexs = env::var("IRIUM_POAWX_MINER_SECRET_HEX").map_err(|_| {
        "solo PoAW-X mining requires IRIUM_POAWX_MINER_SECRET_HEX (64 hex chars)".to_string()
    })?;
    let bytes =
        hex::decode(hexs.trim()).map_err(|e| format!("bad IRIUM_POAWX_MINER_SECRET_HEX: {e}"))?;
    if bytes.len() != 32 {
        return Err("IRIUM_POAWX_MINER_SECRET_HEX must be 32 bytes (64 hex chars)".to_string());
    }
    let mut o = [0u8; 32];
    o.copy_from_slice(&bytes);
    Ok(o)
}

pub fn poawx_decode_hash32(s: &str) -> Result<[u8; 32], String> {
    let b = hex::decode(s.trim()).map_err(|e| format!("bad hash hex: {e}"))?;
    if b.len() != 32 {
        return Err(format!("hash must be 32 bytes, got {}", b.len()));
    }
    let mut o = [0u8; 32];
    o.copy_from_slice(&b);
    Ok(o)
}

pub fn poawx_receipt_difficulty_bits() -> u32 {
    if crate::activation::network_id_byte() == 0 {
        return 20; // mainnet configured puzzle difficulty (bits)
    }
    env::var("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(4)
}

/// Seconds the solo --poawx miner waits between block-production attempts.
/// `IRIUM_POAWX_MINER_INTERVAL_SECS` (devnet/testnet only); default 2 (unchanged
/// legacy cadence). Raising it (e.g. 30) slows block production so remote testnet
/// nodes can stay synced via gossip. Clamped to a minimum of 1s.
pub fn poawx_miner_interval_secs() -> u64 {
    env::var("IRIUM_POAWX_MINER_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(2)
        .max(1)
}

/// Build the `/rpc/submit_block_extended` JSON request from a built proof (public
/// block data only; no secret key material). Mirrors the live-proof harness shape.
pub fn build_poawx_submit_request(
    proof: &crate::poawx_mining_harness::AllGatesProof,
) -> Result<serde_json::Value, String> {
    let block = &proof.block;
    if block.transactions.is_empty() {
        return Err("missing coinbase in built block".to_string());
    }
    let receipt = block
        .poawx_receipts
        .as_ref()
        .and_then(|r| r.first())
        .ok_or("missing receipt in built block")?;
    let ext_hex = receipt
        .phase20_ext
        .as_ref()
        .map(|e: &crate::poawx::Phase20ReceiptExt| hex::encode(e.serialize()))
        .unwrap_or_default();
    let header = &block.header;
    Ok(json!({
        "height": proof.height,
        "header": {
            "version": header.version,
            "prev_hash": hex::encode(header.prev_hash),
            "merkle_root": hex::encode(header.merkle_root),
            "time": header.time,
            "bits": format!("{:08x}", header.bits),
            "nonce": header.nonce,
            "hash": hex::encode(proof.block_hash),
        },
        // EVERY transaction, not just the coinbase. The node rebuilds the block from this
        // list and checks it against `header.merkle_root`; sending a subset while the header
        // commits to the full set is an unconditional merkle mismatch. That is exactly what
        // happened on 2026-07-30: v1.9.161 started carrying mempool transactions in
        // `block.transactions` (so the root covered 17 txs) while this line still shipped
        // one, and every submit came back `HTTP 400` with an EMPTY body — empty because the
        // handler returns a bare `Err(StatusCode)`, so there was no message to read and the
        // cause looked like an encoding fault for a day. Both hosts were blocked at once and
        // mainnet stalled ~14 minutes.
        //
        // Coinbase-only blocks are unaffected: a one-element list is what this produced
        // before, byte for byte.
        "tx_hex": block
            .transactions
            .iter()
            .map(|tx| hex::encode(tx.serialize()))
            .collect::<Vec<String>>(),
        "submit_source": "irium-miner-poawx",
        "poawx_receipts": [{
            "height": receipt.height,
            "lane": (receipt.lane as char).to_string(),
            "worker_pkh": hex::encode(receipt.worker_pkh),
            "solution": hex::encode(receipt.solution),
            "commitment_nonce": hex::encode(receipt.commitment_nonce),
            "worker_pubkey": hex::encode(receipt.worker_pubkey),
            "worker_sig": hex::encode(receipt.worker_sig),
            "phase20_ext": ext_hex,
        }],
        "poawx_receipts_root": hex::encode(proof.irx1_root),
    }))
}

/// Fetch the parent (H-1) block prev_hash PLUS its PoAW-X multi-source seed
/// components (finality-proof digest, precommit root). For height <= 1 the parent is
/// genesis: prev_hash None and zero components. The components feed the multi-source
/// assignment seed so blocks at height >= 2 validate once that gate is active.
pub fn poawx_fetch_parent_info(client: &Client, height: u64) -> Result<PoawxParentInfo, String> {
    if height <= 1 {
        return Ok((None, ([0u8; 32], [0u8; 32])));
    }
    with_rpc_base(|base| {
        let url = format!("{}/rpc/block?height={}", base.trim_end_matches('/'), height - 1);
        let mut req = client.get(&url);
        if let Some(token) = rpc_token() {
            req = req.bearer_auth(token);
        }
        let resp = req.send().map_err(|e| format!("get parent block: {e}"))?;
        if !resp.status().is_success() {
            return Err(rpc_status_error("get parent block", resp.status()));
        }
        let v: serde_json::Value = resp.json().map_err(|e| format!("parent parse: {e}"))?;
        let prev = v
            .get("header")
            .and_then(|h| h.get("prev_hash"))
            .and_then(|x| x.as_str())
            .ok_or("parent block missing header.prev_hash")?;
        let comp = |key: &str| -> Result<[u8; 32], String> {
            match v.get(key).and_then(|x| x.as_str()) {
                Some(s) => poawx_decode_hash32(s),
                None => Ok([0u8; 32]),
            }
        };
        let fin = comp("poawx_finality_digest")?;
        let pre = comp("poawx_precommit_root")?;
        Ok((Some(poawx_decode_hash32(prev)?), (fin, pre)))
    })
}

pub fn poawx_fetch_dominance(
    client: &Client,
) -> Result<crate::poawx_dominance::PersistentDominance, String> {
    with_rpc_base(|base| {
        let url = format!("{}/rpc/poawx_dominance", base.trim_end_matches('/'));
        let mut req = client.get(&url);
        if let Some(token) = rpc_token() {
            req = req.bearer_auth(token);
        }
        let resp = req.send().map_err(|e| format!("get dominance: {e}"))?;
        if !resp.status().is_success() {
            return Err(rpc_status_error("get dominance", resp.status()));
        }
        let v: serde_json::Value = resp.json().map_err(|e| format!("dominance parse: {e}"))?;
        let hexs = v
            .get("hex")
            .and_then(|x| x.as_str())
            .ok_or("dominance response missing hex")?;
        let bytes = hex::decode(hexs.trim()).map_err(|e| format!("dominance hex decode: {e}"))?;
        crate::poawx_dominance::PersistentDominance::from_bytes(&bytes)
    })
}

pub fn poawx_post_admission(client: &Client, adm: &[u8]) -> Result<(), String> {
    with_rpc_base(|base| {
        let url = format!("{}/poawx/candidate-admission", base.trim_end_matches('/'));
        let mut req = client
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            .body(adm.to_vec());
        if let Some(token) = rpc_token() {
            req = req.bearer_auth(token);
        }
        let resp = req.send().map_err(|e| format!("post admission: {e}"))?;
        if !resp.status().is_success() {
            return Err(rpc_status_error("post admission", resp.status()));
        }
        Ok(())
    })
}

pub fn poawx_submit_registration(client: &Client, reg: &[u8]) -> Result<(), String> {
    with_rpc_base(|base| {
        let url = format!("{}/poawx/registration", base.trim_end_matches('/'));
        let mut req = client
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            .body(reg.to_vec());
        if let Some(token) = rpc_token() {
            req = req.bearer_auth(token);
        }
        let resp = req.send().map_err(|e| format!("post registration: {e}"))?;
        if !resp.status().is_success() {
            return Err(rpc_status_error("post registration", resp.status()));
        }
        Ok(())
    })
}

pub fn poawx_submit_extended(client: &Client, req_body: &serde_json::Value) -> Result<(), String> {
    with_rpc_base(|base| {
        let url = format!("{}/rpc/submit_block_extended", base.trim_end_matches('/'));
        let mut req = client.post(&url).json(req_body);
        if let Some(token) = rpc_token() {
            req = req.bearer_auth(token);
        }
        let resp = req.send().map_err(|e| format!("submit_block_extended: {e}"))?;
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        if !status.is_success() {
            return Err(format!("submit_block_extended rejected: HTTP {status} body={body}"));
        }
        Ok(())
    })
}

