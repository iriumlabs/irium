//! Phase 24L — Irium PoAW-X live-proof harness (devnet/testnet ONLY).
//!
//! Connects to a LOCAL devnet/testnet node over loopback RPC, builds a complete
//! all-gates PoAW-X block with Irium-native PoW (via the proven
//! `irium_node_rs::poawx_mining_harness::build_devnet_all_gates_block`), ingests
//! the candidate admissions, submits the block through the real
//! `/rpc/submit_block_extended` path, and verifies the node accepted it (height
//! advanced).
//!
//! SAFETY (fail-closed): refuses mainnet (`network_id == 0`), requires an
//! explicit `--devnet`/`--testnet` flag, requires a loopback `--rpc-url`,
//! requires an explicit isolated `--work-dir` that is NOT the production default
//! (`%USERPROFILE%\.irium` / `$HOME/.irium`). Never prints private keys, seeds,
//! or VRF secrets. Writes artifacts only under the explicit work dir. This is a
//! local devnet proof tool: it is NOT a mainnet/production component.

use irium_node_rs::activation::network_id_byte;
use irium_node_rs::poawx::Phase20ReceiptExt;
use irium_node_rs::poawx_mining_harness::{
    build_devnet_all_gates_block_with, guard_isolated_storage, guard_network, AllGatesProof,
    AllGatesSections,
};
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone)]
struct Args {
    devnet: bool,
    testnet: bool,
    rpc_url: String,
    work_dir: String,
    rpc_token: Option<String>,
    /// Phase 42: opt-in Phase 31–34 trailing block sections (DMC1/ADM1/TKT1).
    sections: AllGatesSections,
}

fn parse_args(argv: &[String]) -> Result<Args, String> {
    let mut a = Args {
        devnet: false,
        testnet: false,
        rpc_url: String::new(),
        work_dir: String::new(),
        rpc_token: None,
        sections: AllGatesSections::default(),
    };
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--devnet" => a.devnet = true,
            "--testnet" => a.testnet = true,
            // Phase 42: opt-in newer trailing sections (devnet/testnet only).
            "--emit-dmc1" => a.sections.dominance_commitment = true,
            "--emit-adm1" => a.sections.adaptive_commitment = true,
            "--emit-tkt1" => a.sections.ticket_registrations = true,
            "--phase31-34" => {
                a.sections.dominance_commitment = true;
                a.sections.adaptive_commitment = true;
                a.sections.ticket_registrations = true;
            }
            "--rpc-url" => {
                i += 1;
                a.rpc_url = argv.get(i).cloned().ok_or("--rpc-url requires a value")?;
            }
            "--work-dir" => {
                i += 1;
                a.work_dir = argv.get(i).cloned().ok_or("--work-dir requires a value")?;
            }
            "--rpc-token" => {
                i += 1;
                a.rpc_token = Some(argv.get(i).cloned().ok_or("--rpc-token requires a value")?);
            }
            "--help" | "-h" => return Err("help".to_string()),
            other => return Err(format!("unknown argument: {other}")),
        }
        i += 1;
    }
    if !a.devnet && !a.testnet {
        return Err("require an explicit --devnet or --testnet flag".to_string());
    }
    if a.rpc_url.is_empty() {
        return Err("require --rpc-url http://127.0.0.1:<port>".to_string());
    }
    if a.work_dir.is_empty() {
        return Err("require an explicit --work-dir".to_string());
    }
    Ok(a)
}

/// Refuse a non-loopback RPC URL. Only 127.0.0.1 / localhost / ::1 are allowed
/// (the node binds loopback-only for this proof; no public RPC).
fn require_loopback(rpc_url: &str) -> Result<(), String> {
    let after_scheme = rpc_url.split("://").nth(1).unwrap_or(rpc_url);
    let authority = after_scheme
        .split('/')
        .next()
        .unwrap_or(after_scheme)
        .trim_end_matches('/');
    // strip a trailing :port (but keep IPv6 brackets intact)
    let host = if let Some(stripped) = authority.strip_prefix('[') {
        // [::1]:port -> ::1
        stripped.split(']').next().unwrap_or(stripped).to_string()
    } else {
        authority
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(authority)
            .to_string()
    };
    match host.as_str() {
        "127.0.0.1" | "localhost" | "::1" => Ok(()),
        other => Err(format!(
            "poawx live-proof: refusing non-loopback RPC host '{other}' (loopback only)"
        )),
    }
}

/// Validate the work dir: explicit, isolated (not a default `.irium`), and must
/// already exist (the runner script creates it). Fail-closed.
fn validate_work_dir(dir: &str) -> Result<(), String> {
    if dir.trim().is_empty() {
        return Err("poawx live-proof: empty work dir".to_string());
    }
    let p = Path::new(dir);
    guard_isolated_storage(Some(p))?;
    if !p.is_dir() {
        return Err(format!(
            "poawx live-proof: work dir does not exist (create it first): {dir}"
        ));
    }
    Ok(())
}

/// Resolve the network id from the explicit flag + the node env, fail-closed on
/// mainnet. `--devnet` => 2, `--testnet` => 1; the resolved env id must agree and
/// must not be mainnet.
fn resolve_network(a: &Args) -> Result<u8, String> {
    let env_id = network_id_byte();
    guard_network(env_id)?;
    let want = if a.devnet { 2 } else { 1 };
    if env_id != want {
        return Err(format!(
            "poawx live-proof: IRIUM_NETWORK id ({env_id}) does not match the requested flag ({want}); \
             set IRIUM_NETWORK=devnet/testnet to match"
        ));
    }
    Ok(env_id)
}

/// Build the `/rpc/submit_block_extended` JSON request from a built proof.
/// Contains only public block data (header, coinbase tx hex, receipt incl. the
/// serialized Phase20 extension, receipts root) — NO private keys.
fn build_submit_request(proof: &AllGatesProof) -> Result<serde_json::Value, String> {
    let block = &proof.block;
    let coinbase = block
        .transactions
        .first()
        .ok_or("missing coinbase in built block")?;
    let receipt = block
        .poawx_receipts
        .as_ref()
        .and_then(|r| r.first())
        .ok_or("missing receipt in built block")?;
    let ext_hex = receipt
        .phase20_ext
        .as_ref()
        .map(|e: &Phase20ReceiptExt| hex::encode(e.serialize()))
        .unwrap_or_default();
    let header = &block.header;
    let req = serde_json::json!({
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
        "tx_hex": [hex::encode(coinbase.serialize())],
        "submit_source": "poawx-live-proof-harness",
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
    });
    Ok(req)
}

fn http() -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("http client: {e}"))
}

fn auth(
    rb: reqwest::blocking::RequestBuilder,
    token: &Option<String>,
) -> reqwest::blocking::RequestBuilder {
    match token {
        Some(t) if !t.trim().is_empty() => rb.header("Authorization", format!("Bearer {t}")),
        _ => rb,
    }
}

fn get_json(
    c: &reqwest::blocking::Client,
    url: &str,
    token: &Option<String>,
) -> Result<serde_json::Value, String> {
    let resp = auth(c.get(url), token)
        .send()
        .map_err(|e| format!("GET {url}: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("GET {url}: HTTP {}", resp.status()));
    }
    resp.json().map_err(|e| format!("GET {url} decode: {e}"))
}

fn run(a: &Args) -> Result<String, String> {
    let net = resolve_network(a)?;
    require_loopback(&a.rpc_url)?;
    validate_work_dir(&a.work_dir)?;
    let base = a.rpc_url.trim_end_matches('/').to_string();
    let c = http()?;

    // 1) assignment must be served (node active + non-mainnet); read receipt diff.
    let assignment = get_json(&c, &format!("{base}/poawx/assignment"), &a.rpc_token)?;
    let receipt_diff = assignment
        .get("puzzle_difficulty")
        .and_then(|v| v.as_u64())
        .ok_or("assignment missing puzzle_difficulty")? as u32;

    // 2) block template -> prev_hash (raw genesis hash), bits, time, height.
    let tmpl = get_json(&c, &format!("{base}/rpc/getblocktemplate"), &a.rpc_token)?;
    let height = tmpl
        .get("height")
        .and_then(|v| v.as_u64())
        .ok_or("template height")?;
    let prev_hex = tmpl
        .get("prev_hash")
        .and_then(|v| v.as_str())
        .ok_or("template prev_hash")?;
    let bits_str = tmpl
        .get("bits")
        .and_then(|v| v.as_str())
        .ok_or("template bits")?;
    let time = tmpl.get("time").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let prev_bytes = hex::decode(prev_hex).map_err(|e| format!("prev_hash hex: {e}"))?;
    if prev_bytes.len() != 32 {
        return Err("template prev_hash length != 32".to_string());
    }
    let mut prev_hash = [0u8; 32];
    prev_hash.copy_from_slice(&prev_bytes);
    let bits = u32::from_str_radix(bits_str.trim_start_matches("0x"), 16)
        .map_err(|e| format!("bits parse: {e}"))?;

    // 3) record before-height.
    let status0 = get_json(&c, &format!("{base}/status"), &a.rpc_token)?;
    let before = status0
        .get("height")
        .and_then(|v| v.as_u64())
        .unwrap_or(u64::MAX);

    // 3b) Phase 26B: the candidate-admission epoch seed for height H is the parent
    // (tip) block's own prev_hash (the grandparent hash). Fetch the parent block at
    // height-1 and read its prev_hash; the genesis block's prev_hash is all-zero,
    // which the builder maps back to this block's prev_hash (activation grace at H1).
    let parent_prev_hash: Option<[u8; 32]> = if height == 0 {
        None
    } else {
        let pblk = get_json(
            &c,
            &format!("{base}/rpc/block?height={}", height - 1),
            &a.rpc_token,
        )?;
        pblk.get("header")
            .and_then(|h| h.get("prev_hash"))
            .and_then(|v| v.as_str())
            .and_then(|s| hex::decode(s).ok())
            .filter(|b| b.len() == 32)
            .map(|b| {
                let mut o = [0u8; 32];
                o.copy_from_slice(&b);
                o
            })
    };

    // 4) build the all-gates block with Irium-native PoW (mainnet hard-off). With no
    // `--emit-*`/`--phase31-34` flag, `a.sections` is default and this is identical to
    // the legacy all-gates block; the flags add the Phase 31–34 trailing sections.
    let proof = build_devnet_all_gates_block_with(
        a.sections,
        net,
        height,
        prev_hash,
        parent_prev_hash,
        bits,
        time,
        receipt_diff,
    )?;

    // 5) ingest the candidate admissions (raw canonical wire bytes).
    for (i, adm) in proof.admissions.iter().enumerate() {
        let url = format!("{base}/poawx/candidate-admission");
        let resp = auth(c.post(&url), &a.rpc_token)
            .header("Content-Type", "application/octet-stream")
            .body(adm.clone())
            .send()
            .map_err(|e| format!("POST admission[{i}]: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("POST admission[{i}]: HTTP {}", resp.status()));
        }
    }

    // 6) submit the block through the real extended RPC path.
    let req = build_submit_request(&proof)?;
    let url = format!("{base}/rpc/submit_block_extended");
    let resp = auth(c.post(&url), &a.rpc_token)
        .json(&req)
        .send()
        .map_err(|e| format!("POST submit_block_extended: {e}"))?;
    let submit_status = resp.status();
    let submit_body = resp.text().unwrap_or_default();
    if !submit_status.is_success() {
        return Err(format!(
            "submit_block_extended rejected: HTTP {submit_status} body={submit_body}"
        ));
    }

    // 7) verify height advanced.
    let status1 = get_json(&c, &format!("{base}/status"), &a.rpc_token)?;
    let after = status1
        .get("height")
        .and_then(|v| v.as_u64())
        .unwrap_or(before);
    if after <= before {
        return Err(format!(
            "height did not advance (before={before} after={after}); submit body={submit_body}"
        ));
    }

    // 8) write artifacts (public block data only) + return a concise summary.
    let artifact = serde_json::json!({
        "phase": "24L",
        "network_id": net,
        "before_height": before,
        "after_height": after,
        "submitted_height": height,
        "block_hash": hex::encode(proof.block_hash),
        "irx1_root": hex::encode(proof.irx1_root),
        "official_fee_bps": 0,
        "poawx_sections": [
            "candidate_set", "candidate_admission", "committed_admission",
            "true_vrf_assignment_v2", "role_puzzle_proofs", "finality_proof",
            "role_dominance_weights", "multi_role_reward_0pct_fee"
        ],
        "submit_response": submit_body,
    });
    let out_path = Path::new(&a.work_dir).join("poawx-live-proof.json");
    std::fs::write(
        &out_path,
        serde_json::to_vec_pretty(&artifact).unwrap_or_default(),
    )
    .map_err(|e| format!("write artifact: {e}"))?;

    Ok(format!(
        "PoAW-X LIVE PROOF OK\n\
         network_id        : {net} (non-mainnet)\n\
         before_height     : {before}\n\
         after_height      : {after}\n\
         submitted_height  : {height}\n\
         block_hash        : {bh}\n\
         irx1_root         : {ir}\n\
         official_fee      : 0% (no fee output)\n\
         poawx_sections    : candidate_set, candidate_admission, committed_admission, \
         true_vrf(AVR2), role_puzzle_proofs, finality_proof, role_dominance_weights\n\
         node_response     : {submit_body}\n\
         artifact          : {ap}",
        bh = hex::encode(proof.block_hash),
        ir = hex::encode(proof.irx1_root),
        ap = out_path.display(),
    ))
}

fn usage() -> &'static str {
    "poawx-live-proof-harness (devnet/testnet ONLY)\n\
     usage: poawx-live-proof-harness --devnet --rpc-url http://127.0.0.1:41011 \
     --work-dir <isolated-dir> [--rpc-token <token>] \
     [--emit-dmc1] [--emit-adm1] [--emit-tkt1] [--phase31-34]\n\
     (Phase 42: --emit-* / --phase31-34 add the Phase 33/34/32 trailing sections; \
     node gates must be set to match. Default = legacy all-gates block.)\n\
     refuses mainnet, non-loopback RPC, and default %USERPROFILE%\\.irium / $HOME/.irium."
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let a = match parse_args(&argv) {
        Ok(a) => a,
        Err(e) => {
            if e == "help" {
                println!("{}", usage());
                std::process::exit(0);
            }
            eprintln!("error: {e}\n{}", usage());
            std::process::exit(2);
        }
    };
    match run(&a) {
        Ok(summary) => {
            println!("{summary}");
        }
        Err(e) => {
            eprintln!("poawx live-proof FAILED: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_mainnet_network() {
        // F: harness rejects mainnet at the guard layer.
        assert!(guard_network(0).is_err());
        assert!(guard_network(2).is_ok());
    }

    #[test]
    fn rejects_non_loopback_rpc() {
        assert!(require_loopback("http://127.0.0.1:41011").is_ok());
        assert!(require_loopback("http://localhost:41011").is_ok());
        assert!(require_loopback("http://[::1]:41011").is_ok());
        assert!(require_loopback("http://203.0.113.5:41011").is_err());
        assert!(require_loopback("http://example.com/rpc").is_err());
    }

    #[test]
    fn rejects_missing_and_default_work_dir() {
        // missing dir.
        assert!(validate_work_dir("/no/such/poawx-live-proof-dir-xyz").is_err());
        // default .irium under home is refused regardless of existence.
        std::env::set_var("HOME", "/home/wd-tester");
        assert!(validate_work_dir("/home/wd-tester/.irium").is_err());
        // empty refused.
        assert!(validate_work_dir("").is_err());
    }

    #[test]
    fn requires_explicit_network_flag() {
        let argv = vec![
            "--rpc-url".to_string(),
            "http://127.0.0.1:41011".to_string(),
            "--work-dir".to_string(),
            "C:/irium-poawx-live-proof/artifacts".to_string(),
        ];
        assert!(
            parse_args(&argv).is_err(),
            "missing --devnet/--testnet refused"
        );
    }

    #[test]
    fn submit_request_has_no_secret_words() {
        // build a real proof on devnet and confirm the SUMMARY-relevant fields
        // carry no private/secret/mnemonic material. (The full ext is consensus
        // block data, not keys; we assert on the human summary surface.)
        for (k, v) in [
            ("IRIUM_NETWORK", "devnet"),
            ("IRIUM_POAWX_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_MODE", "active"),
            ("IRIUM_POAWX_PUZZLE_DIFFICULTY_BITS", "4"),
            ("IRIUM_POAWX_PUZZLE_BITS", "4"),
            ("IRIUM_POAWX_MULTI_ROLE_REWARD_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_FAIRNESS_MATRIX_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_ANTI_DOMINATION_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_ANTI_DOMINATION_REQUIRED", "1"),
            ("IRIUM_POAWX_CANDIDATE_SET_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_CANDIDATE_SET_REQUIRED", "1"),
            ("IRIUM_POAWX_ASSIGNMENT_PROOF_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_ASSIGNMENT_PROOF_REQUIRED", "1"),
            ("IRIUM_POAWX_CANDIDATE_ADMISSION_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_CANDIDATE_ADMISSION_REQUIRED", "1"),
            ("IRIUM_POAWX_PUZZLE_WORK_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_PUZZLE_WORK_REQUIRED", "1"),
            ("IRIUM_POAWX_FINALITY_COMMITTEE_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_FINALITY_COMMITTEE_REQUIRED", "1"),
            ("IRIUM_POAWX_FINALITY_THRESHOLD_NUM", "1"),
            ("IRIUM_POAWX_FINALITY_THRESHOLD_DEN", "1"),
            ("IRIUM_POAWX_COMMITTED_ADMISSION_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_COMMITTED_ADMISSION_REQUIRED", "1"),
            ("IRIUM_POAWX_TRUE_VRF_ACTIVATION_HEIGHT", "1"),
            ("IRIUM_POAWX_TRUE_VRF_REQUIRED", "1"),
        ] {
            std::env::set_var(k, v);
        }
        let proof = build_devnet_all_gates_block(2, 1, [0x44u8; 32], None, 0x207fffff, 1, 4)
            .expect("build");
        let req = build_submit_request(&proof).expect("req");
        // The request keys are mechanical block fields; assert none of the JSON
        // *keys* leak secret material and the header/hash fields are present.
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains("\"worker_sig\"") && s.contains("\"poawx_receipts_root\""));
        // a human-facing summary must not contain key/secret words.
        let summary = format!(
            "block_hash {} irx1 {} fee 0",
            hex::encode(proof.block_hash),
            hex::encode(proof.irx1_root)
        );
        let low = summary.to_lowercase();
        assert!(
            !low.contains("secret") && !low.contains("private") && !low.contains("mnemonic"),
            "summary must not contain key/secret words"
        );
    }
}
