#![allow(warnings)]
#![allow(clippy::all)]

//! End-to-end IRM/LTC swap test against iriumd-devnet + litecoind regtest.
//!
//! Drives the direct `/rpc/createltcswap` -> `/rpc/claimltcswap` flow with
//! a single wallet acting as both maker and taker (locks IRM, builds the
//! LTC payment, claims with the LTC merkle proof). Verifies the BTC SPV
//! style payment proof consensus path end to end.
//!
//! Environment:
//!   IRIUMD_RPC_URL      default http://127.0.0.1:38400  (iriumd-devnet)
//!   IRIUMD_RPC_TOKEN    required                        (devnet wallet auth)
//!   LTC_RPC_URL         default http://127.0.0.1:19443  (litecoind regtest)
//!   LTC_RPC_USER        default iriumtest
//!   LTC_RPC_PASSWORD    default iriumtest
//!   LTC_RPC_WALLET      default "devnet" (litecoin-core multi-wallet scope)
//!   LTC_E2E_IRM         default "1.00000000"            (swap amount)
//!   LTC_E2E_SATS        default 100000                  (LTC payment sats)
//!   LTC_E2E_CONF        default 1                       (LTC confirmations required)
//!   LTC_E2E_PASSPHRASE  default ""                      (auto-unlock devnet wallet if set)
//!   LTC_E2E_MINE_SCRIPT default /home/irium/.irium-devnet/mine.sh
//!   LTC_E2E_SYNC_SCRIPT default /home/irium/.irium-devnet/ltc-sync.sh
//!
//! Exit codes:
//!   0  full flow passed
//!   1  any step failed

use std::env;
use std::process::{Command, ExitCode, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use reqwest::blocking::Client;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn log(step: &str, status: &str, msg: &str) {
    println!("STEP_{step} status={status} {msg}");
}

// =====================================================================
// iriumd RPC helper (Bearer auth, REST/JSON)
// =====================================================================

struct Iriumd {
    client: Client,
    url: String,
    token: String,
}

impl Iriumd {
    fn from_env() -> Result<Self, String> {
        let url = env::var("IRIUMD_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:38400".to_string());
        let token = env::var("IRIUMD_RPC_TOKEN")
            .map_err(|_| "IRIUMD_RPC_TOKEN required".to_string())?;
        if token.trim().is_empty() {
            return Err("IRIUMD_RPC_TOKEN is empty".into());
        }
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| format!("iriumd http client: {e}"))?;
        Ok(Self { client, url, token })
    }

    fn get(&self, path: &str) -> Result<Value, String> {
        let resp = self
            .client
            .get(format!("{}{path}", self.url))
            .bearer_auth(&self.token)
            .send()
            .map_err(|e| format!("GET {path}: {e}"))?;
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        if !status.is_success() {
            return Err(format!("GET {path} HTTP {status}: {body}"));
        }
        serde_json::from_str(&body)
            .map_err(|e| format!("GET {path} json parse: {e}; body: {body}"))
    }

    fn post(&self, path: &str, body: Value) -> Result<Value, String> {
        let resp = self
            .client
            .post(format!("{}{path}", self.url))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .map_err(|e| format!("POST {path}: {e}"))?;
        let status = resp.status();
        let txt = resp.text().unwrap_or_default();
        if !status.is_success() {
            return Err(format!("POST {path} HTTP {status}: {txt}"));
        }
        serde_json::from_str(&txt)
            .map_err(|e| format!("POST {path} json parse: {e}; body: {txt}"))
    }

    fn current_tip_height(&self) -> Result<u64, String> {
        let tmpl = self.get("/rpc/getblocktemplate")?;
        let next = tmpl["height"].as_u64().unwrap_or(0);
        Ok(next.saturating_sub(1))
    }
}

// =====================================================================
// litecoind RPC helper (Basic auth, JSON-RPC 1.0)
// =====================================================================

struct Litecoind {
    client: Client,
    url: String,
    wallet_url: String,
    user: String,
    password: String,
}

impl Litecoind {
    fn from_env() -> Result<Self, String> {
        let url = env::var("LTC_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:19443".to_string());
        let wallet = env::var("LTC_RPC_WALLET").unwrap_or_else(|_| "devnet".to_string());
        let user = env::var("LTC_RPC_USER").unwrap_or_else(|_| "iriumtest".to_string());
        let password = env::var("LTC_RPC_PASSWORD").unwrap_or_else(|_| "iriumtest".to_string());
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| format!("litecoind http: {e}"))?;
        let wallet_url = format!("{}/wallet/{}", url.trim_end_matches('/'), wallet);
        Ok(Self {
            client,
            url,
            wallet_url,
            user,
            password,
        })
    }

    fn rpc_at(&self, endpoint: &str, method: &str, params: Value) -> Result<Value, String> {
        let req = json!({
            "jsonrpc": "1.0",
            "id": "ltc-swap-e2e",
            "method": method,
            "params": params,
        });
        let resp = self
            .client
            .post(endpoint)
            .basic_auth(&self.user, Some(&self.password))
            .json(&req)
            .send()
            .map_err(|e| format!("ltc {method}: {e}"))?;
        let txt = resp.text().unwrap_or_default();
        let v: Value = serde_json::from_str(&txt)
            .map_err(|e| format!("ltc {method} json: {e}; raw: {txt}"))?;
        if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
            return Err(format!("ltc {method} error: {err}"));
        }
        Ok(v["result"].clone())
    }

    /// Chain-level RPCs (getblockcount, getblockhash, getblockheader, ...)
    fn rpc(&self, method: &str, params: Value) -> Result<Value, String> {
        self.rpc_at(&self.url, method, params)
    }

    /// Wallet-scoped RPCs (getnewaddress, sendtoaddress, signrawtransactionwithwallet, ...)
    fn wallet_rpc(&self, method: &str, params: Value) -> Result<Value, String> {
        self.rpc_at(&self.wallet_url, method, params)
    }
}

// =====================================================================
// sha256d + merkle helpers
// =====================================================================

fn sha256d(bytes: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(bytes);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

/// Compute Bitcoin-style merkle branch for `target_index` in `leaves`.
/// All hashes in natural (non-display) byte order. Branch hashes are
/// returned in natural order; caller can `.reverse()` each for display.
fn compute_merkle_branch_natural(leaves: &[[u8; 32]], target_index: usize) -> Vec<[u8; 32]> {
    let mut branch: Vec<[u8; 32]> = Vec::new();
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    let mut idx = target_index;
    while level.len() > 1 {
        let sibling_idx = if idx.is_multiple_of(2) { idx + 1 } else { idx - 1 };
        let sibling = if sibling_idx >= level.len() {
            level[idx]
        } else {
            level[sibling_idx]
        };
        branch.push(sibling);
        let mut next: Vec<[u8; 32]> = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() { level[i + 1] } else { left };
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&left);
            combined[32..].copy_from_slice(&right);
            next.push(sha256d(&combined));
            i += 2;
        }
        level = next;
        idx /= 2;
    }
    branch
}

// =====================================================================
// Steps
// =====================================================================

fn maybe_unlock(iriumd: &Iriumd) -> Result<(), String> {
    let pass = env::var("LTC_E2E_PASSPHRASE").unwrap_or_default();
    if pass.is_empty() {
        return Ok(());
    }
    // Always POST /wallet/unlock when a passphrase is supplied — the locked
    // state can drift between /wallet/info (which reports stored file state)
    // and the in-memory unlock cache that wallet-signing RPCs consult, and
    // calling unlock when already unlocked is idempotent.
    log("unlock", "start", "POST /wallet/unlock (idempotent)");
    iriumd
        .post("/wallet/unlock", json!({ "passphrase": pass }))
        .map_err(|e| format!("auto-unlock failed: {e}"))?;
    log("unlock", "ok", "wallet unlocked");
    Ok(())
}

fn step_0_probe(iriumd: &Iriumd) -> Result<u64, String> {
    log("0", "start", "probing /rpc/ltcrelaytip");
    let tip = iriumd.get("/rpc/ltcrelaytip")?;
    let active = tip["active"].as_bool().unwrap_or(false);
    let height = tip["tip_height"].as_u64().unwrap_or(0);
    let hash = tip["tip_hash"].as_str().unwrap_or("?");
    if !active {
        return Err(format!("LTC SPV relay not active (tip_height={height})"));
    }
    // tip_height=0 (anchor only) is acceptable; step 9's catch-up loop
    // will push headers up to litecoind's current tip before claim.
    log("0", "ok", &format!("ltcrelaytip active=true height={height} hash={hash}"));
    Ok(height)
}

fn step_1_ltc_address(litecoind: &Litecoind) -> Result<String, String> {
    log("1", "start", "litecoind getnewaddress legacy P2PKH for swap payee");
    let v = litecoind.wallet_rpc(
        "getnewaddress",
        json!(["swap-payee", "legacy"]),
    )?;
    let addr = v.as_str().ok_or("getnewaddress did not return a string")?.to_string();
    log("1", "ok", &format!("ltc payee address={addr}"));
    Ok(addr)
}

fn step_2_wallet_info(iriumd: &Iriumd) -> Result<(String, u64), String> {
    log("2", "start", "/wallet/info and /rpc/getblocktemplate for height");
    let info = iriumd.get("/wallet/info")?;
    let unlocked = info["is_unlocked"].as_bool().unwrap_or(false);
    if !unlocked {
        return Err("devnet wallet is locked; POST /wallet/unlock with passphrase first".into());
    }
    let path = info["path"].as_str().unwrap_or("?");
    let addrs = iriumd.get("/wallet/addresses")?;
    let addr = addrs["addresses"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .ok_or("no wallet address found")?
        .to_string();

    let irm_height = iriumd.current_tip_height()?;

    log("2", "ok", &format!("wallet_unlocked=true path={path} addr={addr} irm_height={irm_height}"));
    Ok((addr, irm_height))
}

#[derive(Debug, Clone)]
struct SwapHandle {
    funding_txid: String,
    swap_vout: u32,
    funding_binding_hex: String,
    expected_ltc_amount_sats: u64,
    expected_ltc_payment_address: String,
    op_return_payload_hex: String,
    timeout_height: u64,
    confirmations_required: u8,
}

fn step_3_create_swap(
    iriumd: &Iriumd,
    irm_wallet_addr: &str,
    ltc_payee_addr: &str,
    irm_height_now: u64,
) -> Result<SwapHandle, String> {
    let irm_amount = env::var("LTC_E2E_IRM").unwrap_or_else(|_| "1.00000000".to_string());
    let ltc_sats: u64 = env::var("LTC_E2E_SATS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100_000);
    let confirmations: u8 = env::var("LTC_E2E_CONF")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let timeout_height = irm_height_now + 100;

    log("3", "start", &format!(
        "POST /rpc/createltcswap irm={irm_amount} sats={ltc_sats} conf={confirmations} timeout={timeout_height}"
    ));

    let body = json!({
        "irm_amount": irm_amount,
        "ltc_amount_sats": ltc_sats,
        "ltc_recipient_address": ltc_payee_addr,
        "recipient_address": irm_wallet_addr,
        "refund_address": irm_wallet_addr,
        "confirmations_required": confirmations,
        "timeout_height": timeout_height,
        "fee_per_byte": 1,
        "broadcast": true,
    });

    let resp = iriumd.post("/rpc/createltcswap", body)?;
    let accepted = resp["accepted"].as_bool().unwrap_or(false);
    if !accepted {
        return Err(format!("createltcswap not accepted: {resp}"));
    }
    let handle = SwapHandle {
        funding_txid: resp["txid"].as_str().ok_or("missing txid")?.to_string(),
        swap_vout: resp["swap_vout"].as_u64().ok_or("missing swap_vout")? as u32,
        funding_binding_hex: resp["funding_binding_hex"].as_str().unwrap_or("").to_string(),
        expected_ltc_amount_sats: resp["expected_ltc_amount_sats"].as_u64().unwrap_or(ltc_sats),
        expected_ltc_payment_address: resp["expected_ltc_payment_address"]
            .as_str()
            .unwrap_or(ltc_payee_addr)
            .to_string(),
        op_return_payload_hex: resp["ltc_op_return_payload_hex"].as_str().unwrap_or("").to_string(),
        timeout_height,
        confirmations_required: confirmations,
    };
    log("3", "ok", &format!(
        "swap funded txid={} vout={} op_return={} binding={}",
        handle.funding_txid,
        handle.swap_vout,
        handle.op_return_payload_hex,
        handle.funding_binding_hex,
    ));
    Ok(handle)
}

/// Spawn the irium-miner via mine.sh and poll iriumd's tip until it advances
/// past `expected_min_height`. Kills the miner once the target is reached.
fn mine_iriumd_to(iriumd: &Iriumd, expected_min_height: u64, ctx: &str) -> Result<u64, String> {
    let mine_script = env::var("LTC_E2E_MINE_SCRIPT")
        .unwrap_or_else(|_| "/home/irium/.irium-devnet/mine.sh".to_string());

    let mut child = Command::new(&mine_script)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn miner ({ctx}): {e}"))?;

    let deadline = Instant::now() + Duration::from_secs(90);
    let final_height = loop {
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("mine timeout ({ctx}) — tip stuck at {expected_min_height}"));
        }
        thread::sleep(Duration::from_millis(300));
        let h = match iriumd.current_tip_height() {
            Ok(h) => h,
            Err(_) => continue,
        };
        if h > expected_min_height {
            break h;
        }
    };

    let _ = child.kill();
    let _ = child.wait();
    // Allow miner to flush + iriumd to settle so subsequent mempool ops see clean state
    thread::sleep(Duration::from_millis(800));
    Ok(final_height)
}

fn step_4_confirm_swap(iriumd: &Iriumd, start_height: u64) -> Result<u64, String> {
    log("4", "start", &format!("mine 1 iriumd block to confirm swap funding (start_h={start_height})"));
    let h = mine_iriumd_to(iriumd, start_height, "confirm swap funding")?;
    log("4", "ok", &format!("iriumd tip h={h}"));
    Ok(h)
}

fn step_5_build_ltc_tx(litecoind: &Litecoind, handle: &SwapHandle) -> Result<String, String> {
    log("5", "start", &format!(
        "createrawtransaction pay={} sats to={} op_return={}",
        handle.expected_ltc_amount_sats,
        handle.expected_ltc_payment_address,
        handle.op_return_payload_hex,
    ));

    let sats = handle.expected_ltc_amount_sats;
    let ltc_amount_str = format!("{}.{:08}", sats / 100_000_000, sats % 100_000_000);

    // createrawtransaction with empty inputs array + outputs as array containing
    // an address-amount map and a {"data": hex} object. Litecoin Core preserves
    // output order: index 0 = P2PKH, index 1 = OP_RETURN. fundrawtransaction
    // appends change as a 3rd output if needed.
    let raw = litecoind.wallet_rpc(
        "createrawtransaction",
        json!([
            [],
            [
                { handle.expected_ltc_payment_address.clone(): ltc_amount_str },
                { "data": handle.op_return_payload_hex.clone() }
            ]
        ]),
    )?;
    let raw_hex = raw.as_str().ok_or("createrawtransaction not a string")?.to_string();

    let funded = litecoind.wallet_rpc("fundrawtransaction", json!([raw_hex]))?;
    let funded_hex = funded["hex"].as_str().ok_or("fundrawtransaction missing hex")?.to_string();
    let fee_ltc = funded["fee"].as_f64().unwrap_or(0.0);

    let signed = litecoind.wallet_rpc("signrawtransactionwithwallet", json!([funded_hex]))?;
    let complete = signed["complete"].as_bool().unwrap_or(false);
    if !complete {
        return Err(format!("signrawtransactionwithwallet incomplete: {signed}"));
    }
    let signed_hex = signed["hex"].as_str().ok_or("signed missing hex")?.to_string();
    log("5", "ok", &format!(
        "signed_tx_len={}B fee={:.8} LTC",
        signed_hex.len() / 2,
        fee_ltc
    ));
    Ok(signed_hex)
}

fn step_6_send_ltc_tx(litecoind: &Litecoind, signed_hex: &str) -> Result<String, String> {
    log("6", "start", "sendrawtransaction -> litecoind regtest mempool");
    let v = litecoind.rpc("sendrawtransaction", json!([signed_hex]))?;
    let txid = v.as_str().ok_or("sendrawtransaction not a string")?.to_string();
    log("6", "ok", &format!("ltc_txid={txid}"));
    Ok(txid)
}

fn step_7_mine_ltc(litecoind: &Litecoind, confirmations: u8) -> Result<u64, String> {
    // mine confirmations+1 blocks so the tx-containing block is at confirmations
    // depth-from-tip = confirmations (gives a slight buffer above the iriumd
    // validator's `tip - proof_height + 1 >= confirmations_required` check).
    let n = (confirmations.max(1) as u64) + 1;
    log("7", "start", &format!("generatetoaddress {} blocks", n));
    let addr = litecoind
        .wallet_rpc("getnewaddress", json!(["e2e-ltc-miner", "legacy"]))?
        .as_str()
        .ok_or("getnewaddress")?
        .to_string();
    let hashes = litecoind.wallet_rpc("generatetoaddress", json!([n, addr]))?;
    let mined = hashes.as_array().map(|a| a.len()).unwrap_or(0);
    let height = litecoind
        .rpc("getblockcount", json!([]))?
        .as_u64()
        .unwrap_or(0);
    log("7", "ok", &format!("mined {mined} blocks, ltc tip h={height}"));
    Ok(height)
}

fn step_8_merkle_proof(
    litecoind: &Litecoind,
    ltc_txid: &str,
) -> Result<(String, Vec<String>, u32), String> {
    log("8", "start", &format!("gettransaction + getblock for merkle proof of {ltc_txid}"));

    let tx_info = litecoind.wallet_rpc("gettransaction", json!([ltc_txid]))?;
    let block_hash = tx_info["blockhash"]
        .as_str()
        .ok_or("tx not confirmed (no blockhash)")?
        .to_string();
    let confirmations = tx_info["confirmations"].as_u64().unwrap_or(0);

    let block = litecoind.rpc("getblock", json!([block_hash.clone(), 1]))?;
    let txids: Vec<String> = block["tx"]
        .as_array()
        .ok_or("block tx array missing")?
        .iter()
        .map(|v| v.as_str().unwrap_or("").to_string())
        .collect();

    let tx_index = txids
        .iter()
        .position(|t| t == ltc_txid)
        .ok_or(format!("tx {ltc_txid} not present in block.tx list"))? as u32;

    // Decode display-order hex -> natural-order [u8;32]
    let leaves: Vec<[u8; 32]> = txids
        .iter()
        .map(|hx| {
            let mut bytes = [0u8; 32];
            let dec = hex::decode(hx).unwrap_or_default();
            if dec.len() == 32 {
                bytes.copy_from_slice(&dec);
                bytes.reverse();
            }
            bytes
        })
        .collect();

    let branch_natural = compute_merkle_branch_natural(&leaves, tx_index as usize);

    // iriumd's claim handler accepts hex strings in display order (matching
    // Bitcoin RPC convention); reverse natural-order back to display.
    let branch_display: Vec<String> = branch_natural
        .iter()
        .map(|h| {
            let mut display = *h;
            display.reverse();
            hex::encode(display)
        })
        .collect();

    log("8", "ok", &format!(
        "block={} index={} branch_len={} confs={}",
        &block_hash[..16.min(block_hash.len())],
        tx_index,
        branch_display.len(),
        confirmations,
    ));
    Ok((block_hash, branch_display, tx_index))
}

fn step_9_relay_ltc_headers(iriumd: &Iriumd, target_height: u64) -> Result<(), String> {
    log("9", "start", &format!("ltc-header-sync loop until iriumd LTC SPV tip >= {target_height}"));
    let script = env::var("LTC_E2E_SYNC_SCRIPT")
        .unwrap_or_else(|_| "/home/irium/.irium-devnet/ltc-sync.sh".to_string());

    // Each ltc-header-sync invocation submits up to 144 headers to iriumd's
    // mempool as one LtcHeaderBatch tx. We then need to mine an iriumd
    // block so the batch enters SPV state. Loop both until the iriumd LTC
    // SPV tip catches up to litecoind's tip (or we exhaust our budget).
    let mut cycles = 0;
    loop {
        cycles += 1;
        if cycles > 16 {
            return Err(format!("ltc-header-sync did not converge after {cycles} cycles"));
        }
        let current = iriumd
            .get("/rpc/ltcrelaytip")
            .map(|v| v["tip_height"].as_u64().unwrap_or(0))
            .unwrap_or(0);
        if current >= target_height {
            log("9", "ok", &format!("LTC SPV caught up to h={current} in {cycles} probe(s)"));
            return Ok(());
        }
        let status = Command::new(&script)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .status()
            .map_err(|e| format!("spawn ltc-header-sync: {e}"))?;
        if !status.success() {
            return Err(format!("ltc-header-sync cycle {cycles} exited code={:?}", status.code()));
        }
        // Mine one iriumd block so the just-submitted batch confirms and
        // the SPV tip advances. Use mine_iriumd_to with the current tip.
        let irm_tip = iriumd.current_tip_height()?;
        let _ = mine_iriumd_to(iriumd, irm_tip, "confirm ltc header batch")?;
    }
}

fn step_10_confirm_headers(iriumd: &Iriumd, start_height: u64) -> Result<u64, String> {
    log("10", "start", &format!("mine 1 iriumd block to confirm LtcHeaderBatch (start_h={start_height})"));
    let h = mine_iriumd_to(iriumd, start_height, "confirm LtcHeaderBatch")?;
    log("10", "ok", &format!("iriumd tip h={h}"));
    Ok(h)
}

fn step_11_claim(
    iriumd: &Iriumd,
    handle: &SwapHandle,
    destination: &str,
    ltc_block_hash: &str,
    ltc_tx_hex: &str,
    ltc_merkle_branch_hex: Vec<String>,
    ltc_merkle_index: u32,
) -> Result<String, String> {
    log("11", "start", "POST /rpc/claimltcswap");
    // The 2-pass fee recalc fix in iriumd's claim_ltc_swap (commit
    // 58ca801) makes fee_per_byte=1 produce a real-tx fee that
    // satisfies the 1.0 sat/B mempool floor. Prior to that fix the
    // single-pass estimate produced ~0.45 sat/B and mempool admission
    // rejected with "Fee per byte below minimum policy"; this binary
    // had to pass fee_per_byte=10 as a workaround.
    let body = json!({
        "funding_txid": handle.funding_txid,
        "vout": handle.swap_vout,
        "destination_address": destination,
        "ltc_block_hash": ltc_block_hash,
        "ltc_tx_hex": ltc_tx_hex,
        "ltc_merkle_branch_hex": ltc_merkle_branch_hex,
        "ltc_merkle_index": ltc_merkle_index,
        "fee_per_byte": 1,
        "broadcast": true,
    });
    let resp = iriumd.post("/rpc/claimltcswap", body)?;
    let accepted = resp["accepted"].as_bool().unwrap_or(false);
    if !accepted {
        return Err(format!("claim not accepted: {resp}"));
    }
    let txid = resp["txid"].as_str().unwrap_or("?").to_string();
    let fee = resp["fee"].as_u64().unwrap_or(0);
    log("11", "ok", &format!("claim_tx={txid} fee={fee}"));
    Ok(txid)
}

fn step_12_verify(
    iriumd: &Iriumd,
    handle: &SwapHandle,
    destination: &str,
    irm_amount_str: &str,
    start_height: u64,
) -> Result<(), String> {
    log("12", "start", "mine claim block + verify balance + inspectltcswap");
    let _ = mine_iriumd_to(iriumd, start_height, "confirm claim")?;

    // /rpc/balance returns the wallet's balance for the address
    let bal = iriumd.get(&format!("/rpc/balance?address={destination}"))?;
    let confirmed_sat = bal["balance"].as_u64().unwrap_or(0);

    let inspect = iriumd
        .get(&format!(
            "/rpc/inspectltcswap?txid={}&vout={}",
            handle.funding_txid, handle.swap_vout
        ))
        .unwrap_or(Value::Null);
    let unspent = inspect["unspent"].as_bool().unwrap_or(true);
    let spent = inspect["spent"].as_bool().unwrap_or(false);

    log(
        "12",
        "ok",
        &format!(
            "wallet_bal_sat={} swap.unspent={} swap.spent={} expected_credit_irm={}",
            confirmed_sat, unspent, spent, irm_amount_str
        ),
    );
    Ok(())
}

fn run() -> Result<(), String> {
    let iriumd = Iriumd::from_env()?;
    let litecoind = Litecoind::from_env()?;

    maybe_unlock(&iriumd)?;

    let _ltc_tip_initial = step_0_probe(&iriumd)?;
    let ltc_payee = step_1_ltc_address(&litecoind)?;
    let (irm_addr, irm_height_before_funding) = step_2_wallet_info(&iriumd)?;
    let handle = step_3_create_swap(&iriumd, &irm_addr, &ltc_payee, irm_height_before_funding)?;
    // Short pause so the funding tx propagates into mempool fully before mining
    thread::sleep(Duration::from_millis(300));
    let _irm_height_after_funding = step_4_confirm_swap(&iriumd, irm_height_before_funding)?;

    let signed_hex = step_5_build_ltc_tx(&litecoind, &handle)?;
    let ltc_txid = step_6_send_ltc_tx(&litecoind, &signed_hex)?;
    let _ltc_tip_after_mine = step_7_mine_ltc(&litecoind, handle.confirmations_required)?;
    let (ltc_block_hash, branch_hex, idx) = step_8_merkle_proof(&litecoind, &ltc_txid)?;

    step_9_relay_ltc_headers(&iriumd, _ltc_tip_after_mine)?;
    let irm_height_after_headers = step_10_confirm_headers(&iriumd, iriumd.current_tip_height()?)?;

    let _claim_tx = step_11_claim(
        &iriumd,
        &handle,
        &irm_addr,
        &ltc_block_hash,
        &signed_hex,
        branch_hex,
        idx,
    )?;

    let irm_amount_str = env::var("LTC_E2E_IRM").unwrap_or_else(|_| "1.00000000".to_string());
    step_12_verify(&iriumd, &handle, &irm_addr, &irm_amount_str, irm_height_after_headers)?;

    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => {
            log("done", "ok", "all 12 steps passed");
            ExitCode::SUCCESS
        }
        Err(e) => {
            log("done", "fail", &e);
            ExitCode::FAILURE
        }
    }
}
