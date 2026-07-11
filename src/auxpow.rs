use crate::pow::{meets_target, sha256d, Target};

pub const AUXPOW_VERSION_BIT: u32 = 1 << 8;
pub const AUXPOW_COMMIT_MAGIC: [u8; 4] = [0xfa, 0xbe, 0x6d, 0x6d];
pub const MAX_BRANCH_DEPTH: usize = 20;

/// AuxPoW extension attached to a block when `version & AUXPOW_VERSION_BIT` is set.
///
/// Wire layout (after the 80-byte standard header):
///   coinbase_txn      varint-prefixed raw Bitcoin coinbase transaction
///   parent_hash       32 bytes (informational; recomputable from parent_header)
///   coinbase_branch   varint count + count*32 bytes + 4-byte LE index
///   blockchain_branch varint count + count*32 bytes + 4-byte LE index
///   parent_header     80 bytes raw Bitcoin block header
#[derive(Debug, Clone)]
pub struct AuxPoW {
    pub coinbase_txn: Vec<u8>,
    pub parent_hash: [u8; 32],
    pub coinbase_branch: Vec<[u8; 32]>,
    pub coinbase_branch_index: u32,
    pub blockchain_branch: Vec<[u8; 32]>,
    pub blockchain_branch_index: u32,
    pub parent_header: [u8; 80],
}

/// Validate an AuxPoW proof for the given aux (Irium) block header bytes and target.
///
/// `aux_header_bytes` must be the serialized 80-byte Irium block header
/// (`BlockHeader::serialize()`).
///
/// PR-2 of issue #68 refactored this function into a thin wrapper around
/// `validate_with_parent_hash` so that other chains (DOGE) with a
/// non-sha256d parent PoW (Scrypt) can reuse the merge-mining merkle
/// and commitment validation logic without duplication. Behavior is
/// identical to the pre-refactor implementation: parent PoW is sha256d
/// (Bitcoin/IRIUM family) and checked against `target`.
pub fn validate(ap: &AuxPoW, aux_header_bytes: &[u8], target: Target) -> Result<(), String> {
    validate_with_parent_hash(ap, aux_header_bytes, target, |header| {
        // sha256d returns natural order; meets_target expects display
        // (big-endian) order.
        let mut parent_hash_display = sha256d(header);
        parent_hash_display.reverse();
        meets_target(&parent_hash_display, target)
    })
}

/// Validate an AuxPoW proof with a caller-supplied parent-PoW predicate.
///
/// This is the parent-hash-function-agnostic core of AuxPoW validation.
/// The closure `parent_pow` is invoked with the 80-byte parent block
/// header and must return whether that parent's PoW meets the chain's
/// difficulty target.
///
/// Use cases:
///   * IRIUM's own merge-mining (parent uses sha256d) — the existing
///     `validate()` wraps this with the sha256d + meets_target check.
///   * DOGE SPV AuxPoW (parent is LTC using Scrypt) — callers pass a
///     closure that runs Scrypt on the parent header and checks it
///     against the DOGE target. This is the post-371,337 DOGE SPV
///     validator path; lands in a later PR.
///
/// `target` is preserved in the signature for diagnostic error context
/// and forward API symmetry; the closure is the authoritative PoW check.
/// (Issue #68 PR-2)
pub fn validate_with_parent_hash<F>(
    ap: &AuxPoW,
    aux_header_bytes: &[u8],
    target: Target,
    parent_pow: F,
) -> Result<(), String>
where
    F: Fn(&[u8; 80]) -> bool,
{
    if aux_header_bytes.len() != 80 {
        return Err("aux block header must be exactly 80 bytes".to_string());
    }
    if ap.coinbase_branch.len() > MAX_BRANCH_DEPTH {
        return Err("coinbase branch depth exceeds maximum".to_string());
    }
    if ap.blockchain_branch.len() > MAX_BRANCH_DEPTH {
        return Err("blockchain branch depth exceeds maximum".to_string());
    }

    let aux_hash = sha256d(aux_header_bytes);
    let (committed_root, chain_count) = find_commitment(&ap.coinbase_txn)?;

    if chain_count == 0 {
        return Err("chain count in commitment is zero".to_string());
    }

    if chain_count == 1 {
        // AuxPoW spec: coinbase stores the merkle root as a little-endian
        // uint256 (display / reversed byte order). Bitcoin Core's
        // ComputeAuxpowRootHash reverses the computed value before compare.
        let mut aux_hash_committed = aux_hash;
        aux_hash_committed.reverse();
        if committed_root != aux_hash_committed {
            return Err("coinbase commitment does not match aux block hash".to_string());
        }
    } else {
        if ap.blockchain_branch_index >= chain_count {
            return Err("blockchain branch index exceeds chain count".to_string());
        }
        let mut computed_root =
            compute_merkle_root(&aux_hash, &ap.blockchain_branch, ap.blockchain_branch_index);
        // AuxPoW spec: see comment above. Reverse computed_root to match
        // the little-endian uint256 stored in the coinbase commitment.
        computed_root.reverse();
        if computed_root != committed_root {
            return Err("blockchain Merkle branch does not match commitment root".to_string());
        }
    }

    let coinbase_txid = sha256d(&ap.coinbase_txn);
    let mut parent_merkle_root = [0u8; 32];
    parent_merkle_root.copy_from_slice(&ap.parent_header[36..68]);

    let computed_tx_root = compute_merkle_root(
        &coinbase_txid,
        &ap.coinbase_branch,
        ap.coinbase_branch_index,
    );
    if computed_tx_root != parent_merkle_root {
        return Err("coinbase Merkle branch does not match parent block merkle root".to_string());
    }

    if !parent_pow(&ap.parent_header) {
        return Err(format!(
            "parent block hash does not meet target (bits=0x{:08x})",
            target.bits,
        ));
    }

    Ok(())
}

/// Scan raw coinbase transaction bytes for the merged-mining commitment.
///
/// Returns `(committed_root, chain_count)`.
pub fn find_commitment(coinbase: &[u8]) -> Result<([u8; 32], u32), String> {
    // Minimum: magic(4) + hash(32) + count(4) = 40 bytes
    if coinbase.len() < 40 {
        return Err("coinbase too short to contain a commitment".to_string());
    }
    let limit = coinbase.len() - 39;
    for i in 0..limit {
        if coinbase[i..i + 4] == AUXPOW_COMMIT_MAGIC {
            let hash_start = i + 4;
            let count_start = hash_start + 32;
            if count_start + 4 > coinbase.len() {
                continue;
            }
            let mut committed_root = [0u8; 32];
            committed_root.copy_from_slice(&coinbase[hash_start..hash_start + 32]);
            let mut count_bytes = [0u8; 4];
            count_bytes.copy_from_slice(&coinbase[count_start..count_start + 4]);
            let chain_count = u32::from_le_bytes(count_bytes);
            return Ok((committed_root, chain_count));
        }
    }
    Err("merged-mining commitment not found in coinbase".to_string())
}

/// Compute the Merkle root from a leaf, branch hashes, and leaf index.
///
/// Standard Bitcoin Merkle traversal: index bit 0 set → leaf is right child.
pub fn compute_merkle_root(leaf: &[u8; 32], branch: &[[u8; 32]], index: u32) -> [u8; 32] {
    let mut current = *leaf;
    let mut idx = index;
    for sibling in branch {
        let mut buf = [0u8; 64];
        if idx & 1 == 0 {
            buf[..32].copy_from_slice(&current);
            buf[32..].copy_from_slice(sibling);
        } else {
            buf[..32].copy_from_slice(sibling);
            buf[32..].copy_from_slice(&current);
        }
        current = sha256d(&buf);
        idx >>= 1;
    }
    current
}

/// Build a 44-byte merged-mining commitment for embedding in a Bitcoin coinbase.
///
/// `aux_hash` is sha256d(block_header.serialize()) — natural order. This
/// function reverses it to little-endian (display) order before embedding,
/// matching the AuxPoW spec convention used by Bitcoin Core and DOGE Core
/// (the committed merkle root is stored as a little-endian uint256).
#[allow(dead_code)] // merged-mining commitment builder; used by mining infrastructure when merge mining is enabled
pub fn build_commitment(aux_hash: &[u8; 32], chain_count: u32, nonce: u32) -> [u8; 44] {
    let mut out = [0u8; 44];
    out[..4].copy_from_slice(&AUXPOW_COMMIT_MAGIC);
    let mut aux_hash_rev = *aux_hash;
    aux_hash_rev.reverse();
    out[4..36].copy_from_slice(&aux_hash_rev);
    out[36..40].copy_from_slice(&chain_count.to_le_bytes());
    out[40..44].copy_from_slice(&nonce.to_le_bytes());
    out
}

fn write_varint(out: &mut Vec<u8>, n: usize) {
    if n < 0xfd {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&(n as u64).to_le_bytes());
    }
}

fn read_varint(data: &[u8], offset: &mut usize) -> Result<usize, String> {
    if *offset >= data.len() {
        return Err("unexpected EOF reading varint".to_string());
    }
    let first = data[*offset];
    *offset += 1;
    match first {
        0xff => {
            if *offset + 8 > data.len() {
                return Err("unexpected EOF reading 8-byte varint".to_string());
            }
            let mut b = [0u8; 8];
            b.copy_from_slice(&data[*offset..*offset + 8]);
            *offset += 8;
            Ok(u64::from_le_bytes(b) as usize)
        }
        0xfe => {
            if *offset + 4 > data.len() {
                return Err("unexpected EOF reading 4-byte varint".to_string());
            }
            let mut b = [0u8; 4];
            b.copy_from_slice(&data[*offset..*offset + 4]);
            *offset += 4;
            Ok(u32::from_le_bytes(b) as usize)
        }
        0xfd => {
            if *offset + 2 > data.len() {
                return Err("unexpected EOF reading 2-byte varint".to_string());
            }
            let mut b = [0u8; 2];
            b.copy_from_slice(&data[*offset..*offset + 2]);
            *offset += 2;
            Ok(u16::from_le_bytes(b) as usize)
        }
        n => Ok(n as usize),
    }
}

/// Serialize an AuxPoW extension to wire bytes (follows the 80-byte standard header).
pub fn serialize(ap: &AuxPoW) -> Vec<u8> {
    let mut out = Vec::new();
    write_varint(&mut out, ap.coinbase_txn.len());
    out.extend_from_slice(&ap.coinbase_txn);
    out.extend_from_slice(&ap.parent_hash);
    write_varint(&mut out, ap.coinbase_branch.len());
    for h in &ap.coinbase_branch {
        out.extend_from_slice(h);
    }
    out.extend_from_slice(&ap.coinbase_branch_index.to_le_bytes());
    write_varint(&mut out, ap.blockchain_branch.len());
    for h in &ap.blockchain_branch {
        out.extend_from_slice(h);
    }
    out.extend_from_slice(&ap.blockchain_branch_index.to_le_bytes());
    out.extend_from_slice(&ap.parent_header);
    out
}

/// Deserialize an AuxPoW extension from `data` starting at `offset`.
/// Advances `offset` past the consumed bytes.
pub fn deserialize(data: &[u8], offset: &mut usize) -> Result<AuxPoW, String> {
    let coinbase_len = read_varint(data, offset)?;
    if coinbase_len > 1_000_000 {
        return Err("coinbase transaction too large".to_string());
    }
    if *offset + coinbase_len > data.len() {
        return Err("unexpected EOF reading coinbase txn".to_string());
    }
    let coinbase_txn = data[*offset..*offset + coinbase_len].to_vec();
    *offset += coinbase_len;

    if *offset + 32 > data.len() {
        return Err("unexpected EOF reading parent_hash".to_string());
    }
    let mut parent_hash = [0u8; 32];
    parent_hash.copy_from_slice(&data[*offset..*offset + 32]);
    *offset += 32;

    let cb_count = read_varint(data, offset)?;
    if cb_count > MAX_BRANCH_DEPTH {
        return Err("coinbase branch depth exceeds maximum".to_string());
    }
    let mut coinbase_branch = Vec::with_capacity(cb_count);
    for _ in 0..cb_count {
        if *offset + 32 > data.len() {
            return Err("unexpected EOF reading coinbase branch hash".to_string());
        }
        let mut h = [0u8; 32];
        h.copy_from_slice(&data[*offset..*offset + 32]);
        *offset += 32;
        coinbase_branch.push(h);
    }
    if *offset + 4 > data.len() {
        return Err("unexpected EOF reading coinbase_branch_index".to_string());
    }
    let coinbase_branch_index = u32::from_le_bytes(data[*offset..*offset + 4].try_into().unwrap());
    *offset += 4;

    let bc_count = read_varint(data, offset)?;
    if bc_count > MAX_BRANCH_DEPTH {
        return Err("blockchain branch depth exceeds maximum".to_string());
    }
    let mut blockchain_branch = Vec::with_capacity(bc_count);
    for _ in 0..bc_count {
        if *offset + 32 > data.len() {
            return Err("unexpected EOF reading blockchain branch hash".to_string());
        }
        let mut h = [0u8; 32];
        h.copy_from_slice(&data[*offset..*offset + 32]);
        *offset += 32;
        blockchain_branch.push(h);
    }
    if *offset + 4 > data.len() {
        return Err("unexpected EOF reading blockchain_branch_index".to_string());
    }
    let blockchain_branch_index =
        u32::from_le_bytes(data[*offset..*offset + 4].try_into().unwrap());
    *offset += 4;

    if *offset + 80 > data.len() {
        return Err("unexpected EOF reading parent_header".to_string());
    }
    let mut parent_header = [0u8; 80];
    parent_header.copy_from_slice(&data[*offset..*offset + 80]);
    *offset += 80;

    Ok(AuxPoW {
        coinbase_txn,
        parent_hash,
        coinbase_branch,
        coinbase_branch_index,
        blockchain_branch,
        blockchain_branch_index,
        parent_header,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUX_NONCE_DEFAULT: u32 = 0;
    const AUX_NONCE_VARIED: u32 = 99;
    const AUX_CHAIN_COUNT_SINGLE: u32 = 1;
    const AUX_CHAIN_COUNT_MULTI: u32 = 3;

    /// Nonce used in synthetic AuxPoW test fixtures. The value 0 is
    /// intentional — these tests exercise the validator logic with a
    /// known-good commitment, not a real mining nonce.
    /// CodeQL suppress: rust/hard-coded-cryptographic-value
    const TEST_AUXPOW_NONCE: u32 = 0;

    fn make_coinbase(aux_hash: &[u8; 32], chain_count: u32) -> Vec<u8> {
        build_commitment(aux_hash, chain_count, AUX_NONCE_DEFAULT).to_vec()
    }

    #[test]
    fn build_commitment_format() {
        let h = [0x42u8; 32];
        let c = build_commitment(&h, AUX_CHAIN_COUNT_SINGLE, AUX_NONCE_VARIED);
        assert_eq!(&c[..4], &AUXPOW_COMMIT_MAGIC);
        assert_eq!(&c[4..36], &h);
        assert_eq!(&c[36..40], &AUX_CHAIN_COUNT_SINGLE.to_le_bytes());
        assert_eq!(&c[40..44], &AUX_NONCE_VARIED.to_le_bytes());
    }

    #[test]
    fn find_commitment_success() {
        let h = [0xabu8; 32];
        let cb = make_coinbase(&h, AUX_CHAIN_COUNT_MULTI);
        let (root, count) = find_commitment(&cb).unwrap();
        assert_eq!(root, h);
        assert_eq!(count, AUX_CHAIN_COUNT_MULTI);
    }

    #[test]
    fn find_commitment_embedded_in_larger_coinbase() {
        let h = [0x77u8; 32];
        let commitment = build_commitment(&h, AUX_CHAIN_COUNT_SINGLE, AUX_NONCE_DEFAULT);
        let mut cb = vec![0u8; 10];
        cb.extend_from_slice(&commitment);
        cb.extend_from_slice(&[0u8; 5]);
        let (root, count) = find_commitment(&cb).unwrap();
        assert_eq!(root, h);
        assert_eq!(count, AUX_CHAIN_COUNT_SINGLE);
    }

    #[test]
    fn find_commitment_not_found() {
        assert!(find_commitment(&[0u8; 50]).is_err());
    }

    #[test]
    fn find_commitment_too_short() {
        assert!(find_commitment(&[0u8; 30]).is_err());
    }

    #[test]
    fn compute_merkle_root_empty_branch_returns_leaf() {
        let leaf = [0x11u8; 32];
        assert_eq!(compute_merkle_root(&leaf, &[], 0), leaf);
    }

    #[test]
    fn compute_merkle_root_left_child() {
        let leaf = [0x11u8; 32];
        let sibling = [0x22u8; 32];
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&leaf);
        buf[32..].copy_from_slice(&sibling);
        let expected = sha256d(&buf);
        assert_eq!(compute_merkle_root(&leaf, &[sibling], 0), expected);
    }

    #[test]
    fn compute_merkle_root_right_child() {
        let leaf = [0x11u8; 32];
        let sibling = [0x22u8; 32];
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&sibling);
        buf[32..].copy_from_slice(&leaf);
        let expected = sha256d(&buf);
        assert_eq!(compute_merkle_root(&leaf, &[sibling], 1), expected);
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let ap = AuxPoW {
            coinbase_txn: vec![0x01, 0x02, 0x03],
            parent_hash: [0x55u8; 32],
            coinbase_branch: vec![[0xaau8; 32], [0xbbu8; 32]],
            coinbase_branch_index: 0,
            blockchain_branch: vec![],
            blockchain_branch_index: 0,
            parent_header: [0u8; 80],
        };
        let bytes = serialize(&ap);
        let mut off = 0;
        let dec = deserialize(&bytes, &mut off).unwrap();
        assert_eq!(off, bytes.len());
        assert_eq!(dec.coinbase_txn, ap.coinbase_txn);
        assert_eq!(dec.parent_hash, ap.parent_hash);
        assert_eq!(dec.coinbase_branch, ap.coinbase_branch);
        assert_eq!(dec.coinbase_branch_index, 0);
        assert_eq!(dec.blockchain_branch.len(), 0);
        assert_eq!(dec.blockchain_branch_index, 0);
    }

    #[test]
    fn validate_rejects_too_short_header() {
        let ap = AuxPoW {
            coinbase_txn: vec![0u8; 50],
            parent_hash: [0u8; 32],
            coinbase_branch: vec![],
            coinbase_branch_index: 0,
            blockchain_branch: vec![],
            blockchain_branch_index: 0,
            parent_header: [0u8; 80],
        };
        assert!(validate(&ap, &[0u8; 40], Target { bits: 0x207fffff }).is_err());
    }

    #[test]
    fn validate_rejects_missing_commitment() {
        let ap = AuxPoW {
            coinbase_txn: vec![0u8; 50],
            parent_hash: [0u8; 32],
            coinbase_branch: vec![],
            coinbase_branch_index: 0,
            blockchain_branch: vec![],
            blockchain_branch_index: 0,
            parent_header: [0u8; 80],
        };
        assert!(validate(&ap, &[0u8; 80], Target { bits: 0x207fffff }).is_err());
    }

    #[test]
    fn validate_rejects_wrong_commitment() {
        let header = [0u8; 80];
        let wrong_hash = [0xffu8; 32];
        let ap = AuxPoW {
            coinbase_txn: make_coinbase(&wrong_hash, 1),
            parent_hash: [0u8; 32],
            coinbase_branch: vec![],
            coinbase_branch_index: 0,
            blockchain_branch: vec![],
            blockchain_branch_index: 0,
            parent_header: [0u8; 80],
        };
        // sha256d([0u8;80]) != [0xff;32], so commitment check fails.
        assert!(validate(&ap, &header, Target { bits: 0x207fffff }).is_err());
    }

    #[test]
    fn validate_rejects_excessive_coinbase_branch() {
        let ap = AuxPoW {
            coinbase_txn: vec![0u8; 50],
            parent_hash: [0u8; 32],
            coinbase_branch: vec![[0u8; 32]; MAX_BRANCH_DEPTH + 1],
            coinbase_branch_index: 0,
            blockchain_branch: vec![],
            blockchain_branch_index: 0,
            parent_header: [0u8; 80],
        };
        assert!(validate(&ap, &[0u8; 80], Target { bits: 0x207fffff }).is_err());
    }

    /// PR-2 of issue #68: validate the IRIUM merge-mine path end-to-end
    /// through the refactored `validate()` (which now wraps
    /// `validate_with_parent_hash` with the sha256d closure). Constructs
    /// a synthetic but structurally valid AuxPoW and asserts Ok. Anything
    /// breaking here would indicate a behavior regression from the
    /// pre-refactor `validate()`. Pairs with the existing
    /// `validate_rejects_*` tests covering negative paths.
    ///
    /// Note: 0x207fffff (max compact target) only accepts ~50% of random
    /// hashes (top byte ≤ 0x7f after byte reversal), so we brute-force
    /// the parent_header nonce to find one whose sha256d meets the
    /// target. Practice mirrors what a real miner does — a few
    /// iterations on average — but with an upper bound for safety.
    #[test]
    fn validate_passes_for_synthetic_valid_irium_auxpow() {
        let target = Target { bits: 0x207fffff };
        let aux_header = [0u8; 80];
        let aux_hash = sha256d(&aux_header);
        // Coinbase = just the 44-byte merge-mining commitment. With
        // chain_count=1, the validator skips the blockchain_branch
        // merkle check (commitment hash == aux_hash directly).
        // CodeQL suppress: rust/hard-coded-cryptographic-value
        // TEST_AUXPOW_NONCE is a synthetic fixture nonce, not a real secret.
        let coinbase_txn = build_commitment(&aux_hash, 1, TEST_AUXPOW_NONCE).to_vec();
        let coinbase_txid = sha256d(&coinbase_txn);
        // Empty coinbase_branch → coinbase_txid IS the parent's merkle
        // root (coinbase is the only transaction in the parent block).
        let mut parent_header = [0u8; 80];
        parent_header[36..68].copy_from_slice(&coinbase_txid);

        // Brute-force the parent_header nonce until its sha256d (reversed
        // to display order) meets the target. ~50% acceptance rate per
        // attempt, so we expect this to terminate quickly.
        let mut found = false;
        for nonce in 0u32..10_000 {
            parent_header[76..80].copy_from_slice(&nonce.to_le_bytes());
            let mut h = sha256d(&parent_header);
            h.reverse();
            if meets_target(&h, target) {
                found = true;
                break;
            }
        }
        assert!(
            found,
            "could not find a valid parent_header nonce in 10_000 tries"
        );

        let ap = AuxPoW {
            coinbase_txn,
            parent_hash: sha256d(&parent_header),
            coinbase_branch: vec![],
            coinbase_branch_index: 0,
            blockchain_branch: vec![],
            blockchain_branch_index: 0,
            parent_header,
        };
        let result = validate(&ap, &aux_header, target);
        assert!(
            result.is_ok(),
            "refactored validate() rejected a synthetic valid IRIUM AuxPoW: {:?}",
            result,
        );
    }

    /// PR-2 of issue #68: confirm `validate_with_parent_hash` honors the
    /// caller-supplied parent-PoW closure. Same synthetic AuxPoW as the
    /// positive test above; here we force the closure to reject and
    /// assert the function returns the expected parent-pow error — this
    /// proves the closure is actually on the validation path (and not
    /// silently bypassed).
    #[test]
    fn validate_with_parent_hash_closure_is_authoritative() {
        let aux_header = [0u8; 80];
        let aux_hash = sha256d(&aux_header);
        // CodeQL suppress: rust/hard-coded-cryptographic-value
        // TEST_AUXPOW_NONCE is a synthetic fixture nonce, not a real secret.
        let coinbase_txn = build_commitment(&aux_hash, 1, TEST_AUXPOW_NONCE).to_vec();
        let coinbase_txid = sha256d(&coinbase_txn);
        let mut parent_header = [0u8; 80];
        parent_header[36..68].copy_from_slice(&coinbase_txid);
        let ap = AuxPoW {
            coinbase_txn,
            parent_hash: sha256d(&parent_header),
            coinbase_branch: vec![],
            coinbase_branch_index: 0,
            blockchain_branch: vec![],
            blockchain_branch_index: 0,
            parent_header,
        };

        // Closure returns true → Ok
        let ok = validate_with_parent_hash(&ap, &aux_header, Target { bits: 0x207fffff }, |_| true);
        assert!(ok.is_ok(), "closure-true path rejected: {:?}", ok);

        // Closure returns false → Err on parent PoW with bits in message
        let err =
            validate_with_parent_hash(&ap, &aux_header, Target { bits: 0x207fffff }, |_| false);
        assert!(err.is_err(), "closure-false path accepted");
        let msg = err.unwrap_err();
        assert!(
            msg.contains("does not meet target"),
            "expected parent-pow error, got: {}",
            msg,
        );
        assert!(
            msg.contains("207fffff"),
            "expected bits in error context, got: {}",
            msg,
        );
    }
}
