use chrono::{SecondsFormat, Utc};
use irium_node_rs::block::{Block, BlockHeader};
use irium_node_rs::chain::decode_compact_tx;
use irium_node_rs::genesis::{load_locked_genesis, repo_root};
use irium_node_rs::pow::meets_target;
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize)]
struct GenesisHeaderOut {
    version: u32,
    prev_hash: String,
    merkle_root: String,
    time: u64,
    bits: String,
    nonce: u32,
    hash: String,
}

#[derive(Debug, Serialize)]
struct LockedGenesisOut {
    height: u64,
    header: GenesisHeaderOut,
    transactions: Vec<String>,
}

fn expand_home(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(path)
}

fn read_pubkey(key_path: &Path) -> Result<String, Box<dyn Error>> {
    let mut pub_path = PathBuf::from(key_path);
    pub_path.set_extension("pub");
    let raw = fs::read_to_string(&pub_path)?;
    Ok(raw.trim().to_string())
}

fn sign_payload(
    payload: &[u8],
    key_path: &Path,
    identity: &str,
    namespace: &str,
) -> Result<String, Box<dyn Error>> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut payload_path = std::env::temp_dir();
    payload_path.push(format!("irium-anchor-payload-{}.json", nanos));
    fs::write(&payload_path, payload)?;

    let status = Command::new("ssh-keygen")
        .arg("-Y")
        .arg("sign")
        .arg("-f")
        .arg(key_path)
        .arg("-I")
        .arg(identity)
        .arg("-n")
        .arg(namespace)
        .arg(&payload_path)
        .status()?;
    if !status.success() {
        return Err("ssh-keygen sign failed".into());
    }

    let sig_path = payload_path.with_extension("json.sig");
    let sig_raw = fs::read_to_string(&sig_path)?;
    let mut lines = Vec::new();
    for line in sig_raw.lines() {
        let line = line.trim();
        if line.starts_with("-----") || line.is_empty() {
            continue;
        }
        lines.push(line);
    }

    let _ = fs::remove_file(&payload_path);
    let _ = fs::remove_file(&sig_path);

    if lines.is_empty() {
        return Err("empty ssh signature".into());
    }
    Ok(lines.join(""))
}

fn main() -> Result<(), Box<dyn Error>> {
    let repo_root = repo_root();
    let locked_path = repo_root.join("configs").join("genesis-locked.json");
    let genesis_path = repo_root.join("configs").join("genesis.json");
    let anchors_path = repo_root.join("bootstrap").join("anchors.json");

    let locked = load_locked_genesis()?;
    let bits_str = locked.header.bits.trim().trim_start_matches("0x");
    let bits = u32::from_str_radix(bits_str, 16)?;

    let mut txs = Vec::new();
    for tx_hex in &locked.transactions {
        let raw = irium_node_rs::tx::decode_hex(tx_hex)?;
        txs.push(decode_compact_tx(&raw));
    }

    let merkle_bytes = hex::decode(&locked.header.merkle_root)?;
    if merkle_bytes.len() != 32 {
        return Err("locked genesis merkle root length mismatch".into());
    }
    let mut merkle = [0u8; 32];
    merkle.copy_from_slice(&merkle_bytes);

    let mut block = Block {
        header: BlockHeader {
            version: locked.header.version,
            prev_hash: [0u8; 32],
            merkle_root: merkle,
            time: Utc::now().timestamp() as u32,
            bits,
            nonce: 0,
        },
        transactions: txs.clone(),
        auxpow: None,
    };

    let target = block.header.target();
    let mut nonce: u32 = 0;
    loop {
        block.header.nonce = nonce;
        let hash = block.header.hash_for_height(0);
        if meets_target(&hash, target) {
            let hash_hex = hex::encode(hash);
            let merkle_hex = hex::encode(merkle);
            let prev_hex = "0000000000000000000000000000000000000000000000000000000000000000";
            let timestamp = block.header.time as u64;
            let bits_out = format!("{:08x}", bits);

            let locked_out = LockedGenesisOut {
                height: 0,
                header: GenesisHeaderOut {
                    version: locked.header.version,
                    prev_hash: prev_hex.to_string(),
                    merkle_root: merkle_hex.clone(),
                    time: timestamp,
                    bits: bits_out.clone(),
                    nonce,
                    hash: hash_hex.clone(),
                },
                transactions: locked.transactions.clone(),
            };
            fs::write(&locked_path, serde_json::to_string_pretty(&locked_out)?)?;

            let mut genesis_value: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&genesis_path)?)?;
            genesis_value["timestamp"] = json!(timestamp);
            genesis_value["time"] = json!(timestamp);
            genesis_value["bits"] = json!(bits_out.clone());
            genesis_value["nonce"] = json!(nonce);
            genesis_value["hash"] = json!(hash_hex.clone());
            genesis_value["merkle_root"] = json!(merkle_hex.clone());
            fs::write(&genesis_path, serde_json::to_string_pretty(&genesis_value)?)?;

            let anchor_time = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
            let mut anchor_map = BTreeMap::new();
            anchor_map.insert("network".to_string(), json!("mainnet"));
            anchor_map.insert(
                "description".to_string(),
                json!("Irium blockchain checkpoint anchors for eclipse protection"),
            );
            anchor_map.insert("trusted_signers".to_string(), json!(["iriumlabs"]));
            anchor_map.insert(
                "anchors".to_string(),
                json!([{
                    "height": 0,
                    "hash": hash_hex,
                    "timestamp": timestamp,
                    "prev_hash": prev_hex,
                    "merkle_root": merkle_hex,
                    "description": "Genesis block - Mainnet launch"
                }]),
            );
            anchor_map.insert("last_updated".to_string(), json!(anchor_time.clone()));

            let canonical = serde_json::to_vec(&serde_json::Value::Object(
                anchor_map
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
            ))?;

            let key_path = std::env::var("IRIUM_ANCHOR_SIGN_KEY")
                .unwrap_or_else(|_| "~/.ssh/id_ed25519".to_string());
            let key_path = expand_home(&key_path);
            let signature = sign_payload(&canonical, &key_path, "iriumlabs", "irium-anchor")?;
            let public_key = read_pubkey(&key_path)?;
            let signed_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);

            let mut full_map = anchor_map;
            full_map.insert(
                "signatures".to_string(),
                json!([{
                    "signer": "iriumlabs",
                    "public_key": public_key,
                    "namespace": "irium-anchor",
                    "algorithm": "ssh-ed25519",
                    "signature": signature,
                    "signed_at": signed_at
                }]),
            );

            fs::write(
                &anchors_path,
                serde_json::to_string_pretty(&serde_json::Value::Object(
                    full_map.into_iter().collect(),
                ))?,
            )?;

            println!("Genesis hash: {}", locked_out.header.hash);
            println!("Genesis merkle: {}", locked_out.header.merkle_root);
            println!("Genesis time: {}", locked_out.header.time);
            println!("Genesis bits: {}", locked_out.header.bits);
            println!("Genesis nonce: {}", locked_out.header.nonce);
            return Ok(());
        }
        nonce = nonce.wrapping_add(1);
        if nonce == 0 {
            block.header.time = block.header.time.saturating_add(1);
        }
    }
}
