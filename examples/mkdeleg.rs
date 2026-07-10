//! Stage D Step 5 prover tooling: build a miner-signed Delegation v2 for the
//! delegated (mode-1) miner. Deterministic, distinct keys per miner index so the
//! rig test can drive several miners. Prints shell-sourceable KEY=VALUE lines.
//! Usage: cargo run --release --example mkdeleg -- <miner_idx> <net_id> [expiry]
use irium_node_rs::poawx::Delegation;
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

fn pubkey33(sk: &SigningKey) -> [u8; 33] {
    let enc = VerifyingKey::from(sk).to_encoded_point(true);
    let mut o = [0u8; 33];
    o.copy_from_slice(enc.as_bytes());
    o
}
fn pkh(pk: &[u8; 33]) -> [u8; 20] {
    let mut o = [0u8; 20];
    o.copy_from_slice(&Ripemd160::digest(Sha256::digest(pk)));
    o
}
fn secret(idx: u8, tag: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0] = idx;
    s[1] = tag;
    s[31] = 1;
    s
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let idx: u8 = a.get(1).and_then(|s| s.parse().ok()).unwrap_or(1);
    let net: u8 = a.get(2).and_then(|s| s.parse().ok()).unwrap_or(2);
    let expiry: u64 = a.get(3).and_then(|s| s.parse().ok()).unwrap_or(1_000_000);
    let (custodial, delegate, payout) = (secret(idx, 0xC0), secret(idx, 0xDE), secret(idx, 0x9A));
    let custodial_pub = pubkey33(&SigningKey::from_bytes((&custodial).into()).unwrap());
    let delegate_pub = pubkey33(&SigningKey::from_bytes((&delegate).into()).unwrap());
    let payout_sk = SigningKey::from_bytes((&payout).into()).unwrap();
    let payout_pub = pubkey33(&payout_sk);
    let mut nonce = [0u8; 32];
    nonce[0] = idx;
    nonce[1] = 0xAA;
    let mut d = Delegation {
        deleg_version: 2,
        network_id: net,
        miner_pubkey: payout_pub,
        pool_pubkey: delegate_pub,
        worker_tag: [0u8; 32],
        expiry_height: expiry,
        fee_bps: 0,
        fee_pkh: [0u8; 20],
        deleg_nonce: nonce,
        proposer_pubkey: custodial_pub,
        delegation_sig: [0u8; 64],
    };
    let sig: Signature = payout_sk.sign_prehash(&d.message_hash()).unwrap();
    d.delegation_sig.copy_from_slice(&sig.to_bytes());
    d.verify_signature().expect("self-verify");
    println!("MINER_IDX={idx}");
    println!("IRIUM_POAWX_PROPOSER_SECRET_HEX={}", hex::encode(custodial));
    println!("IRIUM_POAWX_DELEGATE_SECRET_HEX={}", hex::encode(delegate));
    println!("PAYOUT_SECRET_HEX={}", hex::encode(payout));
    println!("IRIUM_POAWX_DELEGATION_HEX={}", hex::encode(d.serialize()));
    println!("PAYOUT_PKH={}", hex::encode(pkh(&payout_pub)));
    println!("DELEGATE_PKH={}", hex::encode(pkh(&delegate_pub)));
    println!("CUSTODIAL_PUBKEY={}", hex::encode(custodial_pub));
}
