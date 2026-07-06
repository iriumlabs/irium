use crate::pow::sha256d;
use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};

pub fn parse_address_to_pkh(addr: &str) -> Result<[u8; 20]> {
    let decoded = bs58::decode(addr).into_vec().map_err(|e| anyhow!("base58 decode: {e}"))?;
    if decoded.len() != 25 {
        return Err(anyhow!("invalid address length"));
    }
    let (payload, checksum) = decoded.split_at(21);
    let check = sha256d(payload);
    if checksum != &check[..4] {
        return Err(anyhow!("address checksum mismatch"));
    }
    let mut pkh = [0u8; 20];
    pkh.copy_from_slice(&payload[1..]);
    Ok(pkh)
}

fn put_varint(v: usize, out: &mut Vec<u8>) {
    if v < 0xfd {
        out.push(v as u8);
    } else if v <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(v as u16).to_le_bytes());
    } else if v <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(v as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&(v as u64).to_le_bytes());
    }
}

fn p2pkh_script(pkh: &[u8; 20]) -> Vec<u8> {

    let mut s = Vec::with_capacity(25);
    s.push(0x76);
    s.push(0xa9);
    s.push(0x14);
    s.extend_from_slice(pkh);
    s.push(0x88);
    s.push(0xac);
    s
}


fn encode_bip34_height(height: u64) -> Vec<u8> {
    let mut n = height;
    let mut raw = Vec::new();
    while n > 0 {
        raw.push((n & 0xff) as u8);
        n >>= 8;
    }
    if raw.is_empty() {
        raw.push(0);
    }
    if raw.last().copied().unwrap_or(0) & 0x80 != 0 {
        raw.push(0);
    }
    let mut out = Vec::with_capacity(raw.len() + 1);
    out.push(raw.len() as u8);
    out.extend_from_slice(&raw);
    out
}

pub fn build_coinbase_tx(
    height: u64,
    reward: u64,
    pkh: &[u8; 20],
    extranonce: &[u8],
    bip34_height: bool,
    extras: &[(u64, Vec<u8>)],
) -> Vec<u8> {
    let mut tx = Vec::with_capacity(200 + extras.iter().map(|(_, s)| s.len() + 16).sum::<usize>());
    tx.extend_from_slice(&1u32.to_le_bytes());
    put_varint(1, &mut tx);
    // Fix F: iriumd's tx format prefixes prev_txid with a 1-byte length (=32),
    // unlike Bitcoin. Missing this byte caused submit_block to silent-400
    // (decode_full_tx_at: "invalid prev_txid length") for every pool block.
    tx.push(32u8);
    tx.extend_from_slice(&[0u8; 32]);
    tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());

    let mut script_sig = if bip34_height {
        let mut s = encode_bip34_height(height);
        s.extend_from_slice(b"Irium");
        s
    } else {
        format!("Irium {height}").into_bytes()
    };
    script_sig.extend_from_slice(extranonce);
    put_varint(script_sig.len(), &mut tx);
    tx.extend_from_slice(&script_sig);

    tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    // v1.9.62 issue #60: extras are zero-value BTC/LTC/DOGE header-batch
    // outputs that ride in the coinbase post-activation. They cost nothing
    // (coinbase has no inputs) and chain.rs accepts them at value=0 with a
    // one-per-chain cap.
    put_varint(1 + extras.len(), &mut tx);
    tx.extend_from_slice(&reward.to_le_bytes());

    let spk = p2pkh_script(pkh);
    put_varint(spk.len(), &mut tx);
    tx.extend_from_slice(&spk);
    for (value, script) in extras {
        tx.extend_from_slice(&value.to_le_bytes());
        put_varint(script.len(), &mut tx);
        tx.extend_from_slice(script);
    }
    tx.extend_from_slice(&0u32.to_le_bytes());
    tx
}

pub fn coinbase_prefix_suffix(
    height: u64,
    reward: u64,
    pkh: &[u8; 20],
    bip34_height: bool,
    extras: &[(u64, Vec<u8>)],
) -> (Vec<u8>, Vec<u8>) {
    // Use a unique non-zero marker so we only split at the extranonce location,
    // not at zero-filled fields like prevout hash/index in coinbase tx.
    // Marker length must match total extranonce payload length (4+4=8 bytes).
    let marker: [u8; 8] = [0xfa, 0xce, 0xb0, 0x0c, 0x1c, 0xab, 0xad, 0x1d];
    let full = build_coinbase_tx(height, reward, pkh, &marker, bip34_height, extras);
    let pos = full
        .windows(marker.len())
        .position(|w| w == marker)
        .unwrap_or(full.len());
    (full[..pos].to_vec(), full[pos + marker.len()..].to_vec())
}

fn parse_worker_pkh_hex(hex_str: &str) -> Option<[u8; 20]> {
    let bytes = hex::decode(hex_str.trim()).ok()?;
    if bytes.len() != 20 {
        return None;
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn poawx_role_payouts(
    height: u64,
    receipts: &[crate::template::PoawxPendingReceipt],
) -> Vec<([u8; 20], u64)> {
    let Some(receipt) = receipts.first() else {
        return Vec::new();
    };
    let Some(primary_pkh) = parse_worker_pkh_hex(&receipt.worker_pkh) else {
        return Vec::new();
    };
    let total_reward = irium_node_rs::constants::block_reward(height);
    let Ok(ext_bytes) = hex::decode(receipt.phase20_ext.trim()) else {
        return vec![(primary_pkh, total_reward)];
    };
    let Ok(ext) = irium_node_rs::poawx::Phase20ReceiptExt::deserialize(&ext_bytes) else {
        return vec![(primary_pkh, total_reward)];
    };

    let amounts = irium_node_rs::poawx::multi_role_amounts(total_reward);
    let (primary_net, fee_out) = if ext.fee_bps > 0 {
        let (net, fee) = irium_node_rs::poawx::apply_fee(amounts[0], ext.fee_bps);
        (net, Some((ext.fee_pkh, fee)))
    } else {
        (amounts[0], None)
    };

    let mut payouts = Vec::with_capacity(5);
    payouts.push((primary_pkh, primary_net));
    payouts.push((ext.role_reward.compute_contributor_pkh, amounts[1]));
    payouts.push((ext.role_reward.verify_contributor_pkh, amounts[2]));
    payouts.push((ext.role_reward.support_contributor_pkh, amounts[3]));
    if let Some(fee) = fee_out {
        payouts.push(fee);
    }
    payouts
}

pub fn build_poawx_coinbase_tx(
    height: u64,
    reward: u64,
    _pool_pkh: &[u8; 20],
    extranonce: &[u8],
    bip34_height: bool,
    extras: &[(u64, Vec<u8>)],
    receipts: &[crate::template::PoawxPendingReceipt],
) -> Vec<u8> {
    let role_payouts = poawx_role_payouts(height, receipts);

    let mut tx = Vec::with_capacity(
        240 + extras.iter().map(|(_, s)| s.len() + 16).sum::<usize>() + role_payouts.len() * 34,
    );
    tx.extend_from_slice(&1u32.to_le_bytes());
    put_varint(1, &mut tx);
    tx.push(32u8);
    tx.extend_from_slice(&[0u8; 32]);
    tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());

    let mut script_sig = if bip34_height {
        let mut s = encode_bip34_height(height);
        s.extend_from_slice(b"Irium");
        s
    } else {
        format!("Irium {height}").into_bytes()
    };
    script_sig.extend_from_slice(extranonce);
    put_varint(script_sig.len(), &mut tx);
    tx.extend_from_slice(&script_sig);
    tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());

    put_varint(role_payouts.len() + extras.len(), &mut tx);

    for (role_pkh, value) in role_payouts {
        tx.extend_from_slice(&value.to_le_bytes());
        let role_spk = p2pkh_script(&role_pkh);
        put_varint(role_spk.len(), &mut tx);
        tx.extend_from_slice(&role_spk);
    }

    for (value, script) in extras {
        tx.extend_from_slice(&value.to_le_bytes());
        put_varint(script.len(), &mut tx);
        tx.extend_from_slice(script);
    }
    tx.extend_from_slice(&0u32.to_le_bytes());
    tx
}

pub fn poawx_coinbase_prefix_suffix(
    height: u64,
    reward: u64,
    pool_pkh: &[u8; 20],
    bip34_height: bool,
    extras: &[(u64, Vec<u8>)],
    receipts: &[crate::template::PoawxPendingReceipt],
) -> (Vec<u8>, Vec<u8>) {
    let marker: [u8; 8] = [0xfa, 0xce, 0xb0, 0x0c, 0x1c, 0xab, 0xad, 0x1d];
    let full = build_poawx_coinbase_tx(
        height,
        reward,
        pool_pkh,
        &marker,
        bip34_height,
        extras,
        receipts,
    );
    let pos = full
        .windows(marker.len())
        .position(|w| w == marker)
        .unwrap_or(full.len());
    (full[..pos].to_vec(), full[pos + marker.len()..].to_vec())
}

// Solo-mode coinbase: two outputs in a single transaction.
//   output 0: worker reward = reward * (10_000 - fee_bps) / 10_000  to worker_pkh
//   output 1: pool fee      = reward - worker_reward                to pool_pkh
// fee_bps is capped at 10_000 (100%). A 0 fee still emits two outputs so the
// hash/wire format stays consistent across the solo path; operators who want
// zero fee should run a separate non-pool node, not solo mode with bps=0.
pub fn build_solo_coinbase_tx(
    height: u64,
    reward: u64,
    worker_pkh: &[u8; 20],
    pool_pkh: &[u8; 20],
    fee_bps: u64,
    extranonce: &[u8],
    bip34_height: bool,
) -> Vec<u8> {
    let fee_bps_capped = fee_bps.min(10_000);
    let pool_fee = reward * fee_bps_capped / 10_000;
    let worker_reward = reward.saturating_sub(pool_fee);

    let mut tx = Vec::with_capacity(260);
    tx.extend_from_slice(&1u32.to_le_bytes());
    put_varint(1, &mut tx);
    tx.push(32u8);
    tx.extend_from_slice(&[0u8; 32]);
    tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());

    let mut script_sig = if bip34_height {
        let mut s = encode_bip34_height(height);
        s.extend_from_slice(b"Irium");
        s
    } else {
        format!("Irium {height}").into_bytes()
    };
    script_sig.extend_from_slice(extranonce);
    put_varint(script_sig.len(), &mut tx);
    tx.extend_from_slice(&script_sig);
    tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());

    put_varint(2, &mut tx);

    tx.extend_from_slice(&worker_reward.to_le_bytes());
    let worker_spk = p2pkh_script(worker_pkh);
    put_varint(worker_spk.len(), &mut tx);
    tx.extend_from_slice(&worker_spk);

    tx.extend_from_slice(&pool_fee.to_le_bytes());
    let pool_spk = p2pkh_script(pool_pkh);
    put_varint(pool_spk.len(), &mut tx);
    tx.extend_from_slice(&pool_spk);

    tx.extend_from_slice(&0u32.to_le_bytes());
    tx
}

pub fn solo_coinbase_prefix_suffix(
    height: u64,
    reward: u64,
    worker_pkh: &[u8; 20],
    pool_pkh: &[u8; 20],
    fee_bps: u64,
    bip34_height: bool,
) -> (Vec<u8>, Vec<u8>) {
    let marker: [u8; 8] = [0xfa, 0xce, 0xb0, 0x0c, 0x1c, 0xab, 0xad, 0x1d];
    let full = build_solo_coinbase_tx(height, reward, worker_pkh, pool_pkh, fee_bps, &marker, bip34_height);
    let pos = full
        .windows(marker.len())
        .position(|w| w == marker)
        .unwrap_or(full.len());
    (full[..pos].to_vec(), full[pos + marker.len()..].to_vec())
}

pub fn build_merkle_branches(template_tx_hex: &[String]) -> Result<Vec<[u8; 32]>> {
    let mut level: Vec<[u8; 32]> = Vec::with_capacity(template_tx_hex.len() + 1);
    level.push([0u8; 32]);
    for h in template_tx_hex {
        let raw = hex::decode(h).map_err(|e| anyhow!("template tx decode: {e}"))?;
        level.push(sha256d(&raw));
    }
    let mut branches = Vec::new();
    let mut idx = 0usize;
    while level.len() > 1 {
        let sibling = if idx % 2 == 0 {
            if idx + 1 < level.len() { level[idx + 1] } else { level[idx] }
        } else {
            level[idx - 1]
        };
        branches.push(sibling);

        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        for pair in level.chunks(2) {
            let left = pair[0];
            let right = if pair.len() == 2 { pair[1] } else { pair[0] };
            let mut data = Vec::with_capacity(64);
            data.extend_from_slice(&left);
            data.extend_from_slice(&right);
            next.push(sha256d(&data));
        }
        idx /= 2;
        level = next;
    }
    Ok(branches)
}

pub fn merkle_root_from_coinbase(coinbase_hash: [u8; 32], branches: &[[u8; 32]]) -> [u8; 32] {
    let mut root = coinbase_hash;
    for b in branches {
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&root);
        data.extend_from_slice(b);
        root = sha256d(&data);
    }
    root
}

pub fn parse_hex32(s: &str) -> Result<[u8; 32]> {
    let b = hex::decode(s).map_err(|e| anyhow!("hex decode: {e}"))?;
    if b.len() != 32 {
        return Err(anyhow!("expected 32 bytes"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    Ok(out)
}

pub fn parse_u32_hex(s: &str) -> Result<u32> {
    let t = s.trim_start_matches("0x");
    Ok(u32::from_str_radix(t, 16).map_err(|e| anyhow!("hex parse: {e}"))?)
}

pub fn header_bytes(version: u32, prev_hash: [u8; 32], merkle_root: [u8; 32], ntime: u32, nbits: u32, nonce: u32) -> [u8; 80] {
    let mut h = [0u8; 80];
    h[0..4].copy_from_slice(&version.to_le_bytes());
    h[4..36].copy_from_slice(&prev_hash);
    h[36..68].copy_from_slice(&merkle_root);
    h[68..72].copy_from_slice(&ntime.to_le_bytes());
    h[72..76].copy_from_slice(&nbits.to_le_bytes());
    h[76..80].copy_from_slice(&nonce.to_le_bytes());
    h
}


pub fn build_irx1_commitment_script(root: &[u8; 32]) -> Vec<u8> {
    let mut script = Vec::with_capacity(38);
    script.push(0x6a);
    script.push(0x24);
    script.extend_from_slice(b"irx1");
    script.extend_from_slice(root);
    script
}

pub fn compute_receipts_root_from_pending(receipts: &[crate::template::PoawxPendingReceipt]) -> [u8; 32] {
    let audit_active = receipts.first().map(|r| r.height >= 50_000).unwrap_or(false);
    let phase20_active = audit_active;
    if audit_active {
        let mut inners: Vec<[u8; 32]> = receipts.iter().map(|r| {
            let mut inner = Sha256::new();
            let lane_byte = r.lane.bytes().next().unwrap_or(b'A');
            inner.update(r.height.to_le_bytes());
            inner.update([lane_byte]);
            inner.update(hex::decode(&r.worker_pkh).unwrap_or_default());
            inner.update(hex::decode(&r.worker_pubkey).unwrap_or_default());
            inner.update(hex::decode(&r.worker_sig).unwrap_or_default());
            inner.update(hex::decode(&r.solution).unwrap_or_default());
            inner.update(hex::decode(&r.commitment_nonce).unwrap_or_default());
            if !r.delegation.is_empty() {
                if let Ok(b) = hex::decode(&r.delegation) {
                    let mut dh = Sha256::new();
                    dh.update(&b);
                    let dd: [u8; 32] = dh.finalize().into();
                    inner.update(dd);
                }
            }
            if phase20_active && !r.phase20_ext.is_empty() {
                if let Ok(b) = hex::decode(&r.phase20_ext) {
                    let mut eh = Sha256::new();
                    eh.update(&b);
                    let ed: [u8; 32] = eh.finalize().into();
                    inner.update(ed);
                }
            }
            inner.finalize().into()
        }).collect();
        inners.sort_unstable();
        let mut outer = Sha256::new();
        for h in &inners {
            outer.update(h);
        }
        return outer.finalize().into();
    }

    let mut sorted: Vec<&crate::template::PoawxPendingReceipt> = receipts.iter().collect();
    sorted.sort_unstable_by(|a, b| {
        a.height.cmp(&b.height)
            .then_with(|| a.lane.bytes().next().unwrap_or(b'A').cmp(&b.lane.bytes().next().unwrap_or(b'A')))
            .then_with(|| a.worker_pkh.as_bytes().cmp(b.worker_pkh.as_bytes()))
            .then_with(|| a.commitment_nonce.as_bytes().cmp(b.commitment_nonce.as_bytes()))
    });
    let mut outer = Sha256::new();
    for r in sorted {
        let mut inner = Sha256::new();
        inner.update(r.height.to_le_bytes());
        inner.update([r.lane.bytes().next().unwrap_or(b'A')]);
        inner.update(hex::decode(&r.worker_pkh).unwrap_or_default());
        inner.update(hex::decode(&r.solution).unwrap_or_default());
        inner.update(hex::decode(&r.commitment_nonce).unwrap_or_default());
        if !r.delegation.is_empty() {
            if let Ok(b) = hex::decode(&r.delegation) {
                let mut dh = Sha256::new();
                dh.update(&b);
                let dd: [u8; 32] = dh.finalize().into();
                inner.update(dd);
            }
        }
        if phase20_active && !r.phase20_ext.is_empty() {
            if let Ok(b) = hex::decode(&r.phase20_ext) {
                let mut eh = Sha256::new();
                eh.update(&b);
                let ed: [u8; 32] = eh.finalize().into();
                inner.update(ed);
            }
        }
        outer.update(inner.finalize());
    }
    outer.finalize().into()
}
