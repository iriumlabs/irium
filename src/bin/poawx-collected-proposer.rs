//! DEV/TEST-ONLY multi-party proposer: assembles a block from the node's COLLECTED role
//! bundles (fetched over HTTP from `/poawx/collected-bundles`) using ONLY its own
//! proposer key. It never sees or holds any worker's private key — it consumes only the
//! public bundles the workers submitted over the real `/poawx/role-bundle` endpoint. This
//! turns the C3 "assembly from collected artifacts only" property into a real, separate
//! process. Off mainnet / isolated devnet only.
//!
//! Env: IRIUM_POAWX_MINER_SECRET_HEX (the PROPOSER's payout/VRF key), IRIUM_NODE_RPC,
//!      IRIUM_RPC_TOKEN, IRIUM_NETWORK=devnet.
use irium_node_rs::poawx::{
    ROLE_COMPUTE_CONTRIBUTOR, ROLE_SUPPORT_CONTRIBUTOR, ROLE_VERIFY_CONTRIBUTOR,
};
use irium_node_rs::poawx_miner_client::{
    build_poawx_submit_request, fetch_block_template, poawx_decode_hash32, poawx_fetch_dominance,
    poawx_fetch_parent_info, poawx_miner_secret, poawx_receipt_difficulty_bits,
    poawx_submit_extended, rpc_client,
};
use irium_node_rs::poawx_mining_harness::{build_collected_poawx_block_with_parent, CollectedArtifacts};
use irium_node_rs::poawx_role_bundle::RoleBundleV1;
use std::{thread, time::Duration};

fn fetch_collected(
    http: &reqwest::blocking::Client,
    base: &str,
    token: &str,
) -> Result<CollectedArtifacts, String> {
    let v: serde_json::Value = http
        .get(format!("{base}/poawx/collected-bundles"))
        .bearer_auth(token)
        .send()
        .map_err(|e| format!("collected get: {e}"))?
        .json()
        .map_err(|e| format!("collected json: {e}"))?;
    let mut c = CollectedArtifacts {
        compute: None,
        verify: None,
        support: None,
            all: Vec::new(),
    };
    if let Some(arr) = v.get("bundles").and_then(|x| x.as_array()) {
        for b in arr {
            // NOTE: from_json parses PUBLIC bundle data only — no private keys involved.
            let rb = RoleBundleV1::from_json(&b.to_string())?;
            match rb.role_id {
                ROLE_COMPUTE_CONTRIBUTOR => c.compute = Some(rb),
                ROLE_VERIFY_CONTRIBUTOR => c.verify = Some(rb),
                ROLE_SUPPORT_CONTRIBUTOR => c.support = Some(rb),
                _ => {}
            }
        }
    }
    Ok(c)
}

fn main() -> Result<(), String> {
    let net = irium_node_rs::activation::network_id_byte();
    if net == 0 {
        return Err("refusing to run on mainnet (network_id == 0)".into());
    }
    // The ONLY private key this process ever holds is the proposer's own.
    let secret = poawx_miner_secret()?;
    let client = rpc_client()?;
    let base = std::env::var("IRIUM_NODE_RPC").unwrap_or_else(|_| "http://127.0.0.1:38500".into());
    let token = std::env::var("IRIUM_RPC_TOKEN").unwrap_or_default();
    let http = reqwest::blocking::Client::new();
    let diff = poawx_receipt_difficulty_bits();
    println!("[proposer] collected-block proposer started (net={net}); assembles ONLY from collected bundles + its own key");

    loop {
        let tmpl = match fetch_block_template(&client, false) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("[proposer] template: {e}");
                thread::sleep(Duration::from_secs(2));
                continue;
            }
        };
        let height = tmpl.height;
        let prev_hash = match poawx_decode_hash32(&tmpl.prev_hash) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("[proposer] prev_hash: {e}");
                thread::sleep(Duration::from_secs(2));
                continue;
            }
        };
        let bits = match u32::from_str_radix(tmpl.bits.trim_start_matches("0x"), 16) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("[proposer] bits: {e}");
                thread::sleep(Duration::from_secs(2));
                continue;
            }
        };
        let time = tmpl.time;

        let collected = match fetch_collected(&http, &base, &token) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[proposer] {e}");
                thread::sleep(Duration::from_secs(2));
                continue;
            }
        };
        let have = collected.compute.is_some() as u8
            + collected.verify.is_some() as u8
            + collected.support.is_some() as u8;
        if have < 3 {
            println!("[proposer] height={height}: waiting for workers ({have}/3 collected)");
            thread::sleep(Duration::from_secs(2));
            continue;
        }

        let (parent_prev_hash, parent_seed_components) = match poawx_fetch_parent_info(&client, height)
        {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[proposer] parent info: {e}");
                thread::sleep(Duration::from_secs(2));
                continue;
            }
        };
        let dominance = match poawx_fetch_dominance(&client) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("[proposer] dominance: {e}");
                thread::sleep(Duration::from_secs(2));
                continue;
            }
        };

        let proof = match build_collected_poawx_block_with_parent(
            &secret,
            collected,
            net,
            height,
            prev_hash,
            parent_prev_hash,
            bits,
            time,
            diff,
            parent_seed_components,
            Some(&dominance),
        ) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[proposer] build_collected failed at {height}: {e}");
                thread::sleep(Duration::from_secs(2));
                continue;
            }
        };
        let req = match build_poawx_submit_request(&proof) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[proposer] submit build: {e}");
                continue;
            }
        };
        match poawx_submit_extended(&client, &req) {
            Ok(()) => println!("[proposer] SUBMITTED collected block height={height} (proposer + 3 independent workers)"),
            Err(e) => eprintln!("[proposer] submit failed at {height}: {e}"),
        }
        thread::sleep(Duration::from_secs(2));
    }
}
