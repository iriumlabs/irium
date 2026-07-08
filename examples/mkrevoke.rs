//! Stage D Step 5 Milestone F: build a miner-signed DelegationRevocationV1 for the
//! delegated miner at index <idx> (payout key signs over its deleg_nonce).
//! Usage: cargo run --release --example mkrevoke -- <miner_idx> <net_id>
use irium_node_rs::poawx::DelegationRevocationV1;
fn secret(idx: u8, tag: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0] = idx;
    s[1] = tag;
    s[31] = 1;
    s
}
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let idx: u8 = a.get(1).and_then(|s| s.parse().ok()).unwrap_or(2);
    let net: u8 = a.get(2).and_then(|s| s.parse().ok()).unwrap_or(2);
    let payout = secret(idx, 0x9A);
    let mut nonce = [0u8; 32];
    nonce[0] = idx;
    nonce[1] = 0xAA;
    let rec = DelegationRevocationV1::build_signed(&payout, net, nonce).expect("build");
    rec.validate(net).expect("validate");
    println!("MINER_IDX={idx}");
    println!("IRIUM_POAWX_REVOKE_HEX={}", hex::encode(rec.serialize()));
}
