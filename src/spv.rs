use crate::block::BlockHeader;
use crate::pow::{header_hash, meets_target, Target};
use num_bigint::BigUint;
use num_traits::Zero;
use std::collections::HashSet;

/// A header-only view of the chain suitable for SPV-style clients.
#[derive(Debug)]
pub struct HeaderChain {
    pub headers: Vec<BlockHeader>,
}

impl HeaderChain {
    pub fn new(genesis: BlockHeader) -> HeaderChain {
        HeaderChain {
            headers: vec![genesis],
        }
    }

    pub fn height(&self) -> u64 {
        self.headers.len() as u64 - 1
    }

    /// Append a new header, verifying basic PoW and linkage.
    pub fn append(&mut self, header: BlockHeader, target: Target) -> Result<(), String> {
        let prev = self
            .headers
            .last()
            .ok_or_else(|| "header chain is empty".to_string())?;
        if header.prev_hash != prev.hash() {
            return Err("Header does not extend current tip".to_string());
        }
        let hash = header.hash();
        if !crate::pow::meets_target(&hash, target) {
            return Err("Header does not satisfy target".to_string());
        }
        self.headers.push(header);
        Ok(())
    }
}

/// Verify a merkle proof for a transaction ID against a known merkle root.
///
/// `txid` and all hashes are big-endian.
pub fn verify_merkle_proof(
    txid: &[u8; 32],
    merkle_root: &[u8; 32],
    mut proof: Vec<[u8; 32]>,
    mut index: usize,
) -> bool {
    let mut current = *txid;
    for sibling in proof.drain(..) {
        let (left, right) = if index.is_multiple_of(2) {
            (current, sibling)
        } else {
            (sibling, current)
        };
        let h = header_hash(&[&left, &right]);
        current = h;
        index /= 2;
    }
    &current == merkle_root
}

/// Compute the NiPoPoW level of a header (mu), based on its PoW target.
/// Level mu is the largest integer such that hash <= target / 2^mu.
pub fn header_level(header: &BlockHeader) -> u32 {
    let target = Target { bits: header.bits }.to_target();
    let hash = BigUint::from_bytes_be(&header.hash());
    if hash > target {
        return 0;
    }
    let mut level: u32 = 0;
    let mut cur = target;
    while !cur.is_zero() && hash <= cur {
        level = level.saturating_add(1);
        cur >>= 1u32;
    }
    level.saturating_sub(1)
}

/// Verify a contiguous header chain (prev_hash linkage + PoW).
pub fn verify_header_chain(headers: &[BlockHeader]) -> Result<(), String> {
    if headers.is_empty() {
        return Err("header chain is empty".to_string());
    }
    for (idx, header) in headers.iter().enumerate() {
        let target = Target { bits: header.bits };
        if !meets_target(&header.hash(), target) {
            return Err(format!("header {} fails PoW", idx));
        }
        if idx > 0 {
            let prev = &headers[idx - 1];
            if header.prev_hash != prev.hash() {
                return Err(format!("header {} does not link to previous", idx));
            }
        }
    }
    Ok(())
}

/// Compute superchain counts |C_mu| for all mu.
pub fn nipopow_counts(levels: &[u32]) -> Vec<usize> {
    let max = levels.iter().copied().max().unwrap_or(0) as usize;
    let mut exact = vec![0usize; max + 1];
    for lvl in levels {
        let idx = *lvl as usize;
        exact[idx] = exact[idx].saturating_add(1);
    }
    let mut counts = vec![0usize; max + 1];
    let mut running = 0usize;
    for mu in (0..=max).rev() {
        running = running.saturating_add(exact[mu]);
        counts[mu] = running;
    }
    counts
}

/// Return the highest mu such that |C_mu| >= m.
pub fn nipopow_best_level(counts: &[usize], m: usize) -> u32 {
    let mut best = 0u32;
    for (mu, cnt) in counts.iter().enumerate() {
        if *cnt >= m {
            best = mu as u32;
        }
    }
    best
}

/// Compare two header chains using NiPoPoW superchain counts.
pub fn nipopow_compare_counts(a: &[usize], b: &[usize], m: usize) -> std::cmp::Ordering {
    let max = std::cmp::max(a.len(), b.len()).saturating_sub(1);
    for mu in (0..=max).rev() {
        let ac = a.get(mu).copied().unwrap_or(0);
        let bc = b.get(mu).copied().unwrap_or(0);
        if (ac >= m || bc >= m)
            && ac != bc {
                return ac.cmp(&bc);
            }
    }
    std::cmp::Ordering::Equal
}

#[derive(Debug, Clone)]
pub struct NipopowProof {
    pub m: usize,
    pub k: usize,
    pub pi: Vec<BlockHeader>,
    pub chi: Vec<BlockHeader>,
}

pub fn nipopow_prove(headers: &[BlockHeader], m: usize, k: usize) -> Result<NipopowProof, String> {
    if headers.is_empty() {
        return Err("cannot prove empty header set".to_string());
    }
    let m = m.max(1);
    let k = k.max(1).min(headers.len());
    let suffix_start = headers.len().saturating_sub(k);

    if suffix_start == 0 {
        return Ok(NipopowProof {
            m,
            k,
            pi: Vec::new(),
            chi: headers.to_vec(),
        });
    }

    let mut include = vec![false; headers.len()];
    include[0] = true;
    let mut end = suffix_start.saturating_sub(1);
    include[end] = true;

    let max_level = headers
        .iter()
        .take(end + 1)
        .map(header_level)
        .max()
        .unwrap_or(0);

    for mu in (0..=max_level).rev() {
        let mut super_idxs = Vec::new();
        for i in 0..=end {
            if header_level(&headers[i]) >= mu {
                super_idxs.push(i);
            }
        }
        if super_idxs.len() >= m {
            let anchor_idx = super_idxs[super_idxs.len() - m];
            for idx in super_idxs {
                if idx <= anchor_idx {
                    include[idx] = true;
                } else {
                    break;
                }
            }
            end = anchor_idx;
            include[end] = true;
            if end == 0 {
                break;
            }
        }
    }

    let mut pi = Vec::new();
    for (idx, header) in headers.iter().enumerate().take(suffix_start) {
        if include[idx] {
            pi.push(header.clone());
        }
    }

    let chi = headers[suffix_start..].to_vec();
    Ok(NipopowProof { m, k, pi, chi })
}

pub fn nipopow_verify(proof: &NipopowProof) -> Result<(), String> {
    if proof.chi.is_empty() {
        return Err("chi is empty".to_string());
    }
    if proof.m == 0 || proof.k == 0 {
        return Err("invalid proof parameters".to_string());
    }

    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    for (idx, header) in proof.pi.iter().enumerate() {
        let target = Target { bits: header.bits };
        if !meets_target(&header.hash(), target) {
            return Err(format!("pi header {} fails PoW", idx));
        }
        if idx == 0 && header.prev_hash != [0u8; 32] {
            return Err("pi must start at genesis".to_string());
        }
        let hash = header.hash();
        if !seen.insert(hash) {
            return Err("duplicate header in pi".to_string());
        }
    }

    for (idx, header) in proof.chi.iter().enumerate() {
        let target = Target { bits: header.bits };
        if !meets_target(&header.hash(), target) {
            return Err(format!("chi header {} fails PoW", idx));
        }
        if idx == 0 {
            if proof.pi.is_empty() {
                if header.prev_hash != [0u8; 32] {
                    return Err("chi must start at genesis when pi is empty".to_string());
                }
            } else {
                let expected = proof
                    .pi
                    .last()
                    .ok_or_else(|| "pi is empty".to_string())?
                    .hash();
                if header.prev_hash != expected {
                    return Err("chi does not connect to pi".to_string());
                }
            }
        } else if header.prev_hash != proof.chi[idx - 1].hash() {
            return Err(format!("chi header {} does not link to previous", idx));
        }
    }

    Ok(())
}

pub fn nipopow_proof_chain(proof: &NipopowProof) -> Vec<BlockHeader> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for header in proof.pi.iter().chain(proof.chi.iter()) {
        let hash = header.hash();
        if seen.insert(hash) {
            out.push(header.clone());
        }
    }
    out
}

pub fn nipopow_proof_counts(proof: &NipopowProof) -> Vec<usize> {
    let chain = nipopow_proof_chain(proof);
    let levels: Vec<u32> = chain.iter().map(header_level).collect();
    nipopow_counts(&levels)
}

pub fn nipopow_compare_proofs(a: &NipopowProof, b: &NipopowProof, m: usize) -> std::cmp::Ordering {
    let counts_a = nipopow_proof_counts(a);
    let counts_b = nipopow_proof_counts(b);
    nipopow_compare_counts(&counts_a, &counts_b, m)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mine_header(prev_hash: [u8; 32], time: u32, bits: u32, nonce_start: u32) -> BlockHeader {
        let mut nonce = nonce_start;
        loop {
            let header = BlockHeader {
                version: 1,
                prev_hash,
                merkle_root: [0u8; 32],
                time,
                bits,
                nonce,
            };
            if meets_target(&header.hash(), Target { bits }) {
                return header;
            }
            nonce = nonce.wrapping_add(1);
        }
    }

    fn mine_chain(len: usize) -> Vec<BlockHeader> {
        let bits = 0x207fffff;
        let mut headers = Vec::with_capacity(len);
        let genesis = mine_header([0u8; 32], 1, bits, 0);
        headers.push(genesis);
        for height in 1..len {
            let prev = headers[height - 1].hash();
            let header = mine_header(prev, (height + 1) as u32, bits, height as u32);
            headers.push(header);
        }
        headers
    }

    #[test]
    fn nipopow_proof_roundtrip() {
        let headers = mine_chain(40);
        let proof = nipopow_prove(&headers, 5, 8).expect("proof");
        nipopow_verify(&proof).expect("verify");
        let counts = nipopow_proof_counts(&proof);
        assert!(!counts.is_empty());
        let cmp = nipopow_compare_proofs(&proof, &proof, 5);
        assert_eq!(cmp, std::cmp::Ordering::Equal);
    }
}
