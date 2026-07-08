#![allow(dead_code)]
use crate::auxpow::AuxPoW;
use crate::pow::{header_hash, Target};
use crate::tx::Transaction;

#[derive(Debug, Clone)]
pub struct BlockHeader {
    pub version: u32,
    pub prev_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
}

impl BlockHeader {
    #[allow(dead_code)]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(80);
        out.extend_from_slice(&self.version.to_le_bytes());
        let mut prev = self.prev_hash;
        prev.reverse();
        out.extend_from_slice(&prev);
        let mut merkle = self.merkle_root;
        merkle.reverse();
        out.extend_from_slice(&merkle);
        out.extend_from_slice(&self.time.to_le_bytes());
        out.extend_from_slice(&self.bits.to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out
    }

    pub fn hash(&self) -> [u8; 32] {
        let ser = self.serialize();
        let mut h = header_hash(&[&ser]);
        h.reverse();
        h
    }

    pub fn target(&self) -> Target {
        Target { bits: self.bits }
    }

    /// Deserialize a header from the 80-byte compact encoding.
    #[allow(dead_code)]
    pub fn deserialize(raw: &[u8]) -> Result<(Self, usize), String> {
        if raw.len() < 80 {
            return Err("header too short".to_string());
        }
        let mut offset = 0usize;
        let read_u32 = |buf: &[u8], off: &mut usize| -> Result<u32, String> {
            if *off + 4 > buf.len() {
                return Err("unexpected EOF".to_string());
            }
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&buf[*off..*off + 4]);
            *off += 4;
            Ok(u32::from_le_bytes(bytes))
        };

        let version = read_u32(raw, &mut offset)?;
        let mut prev_hash = [0u8; 32];
        prev_hash.copy_from_slice(&raw[offset..offset + 32]);
        prev_hash.reverse();
        offset += 32;
        let mut merkle_root = [0u8; 32];
        merkle_root.copy_from_slice(&raw[offset..offset + 32]);
        merkle_root.reverse();
        offset += 32;
        let time = read_u32(raw, &mut offset)?;
        let bits = read_u32(raw, &mut offset)?;
        let nonce = read_u32(raw, &mut offset)?;

        Ok((
            BlockHeader {
                version,
                prev_hash,
                merkle_root,
                time,
                bits,
                nonce,
            },
            offset,
        ))
    }

    /// Serialize the 80-byte header using the byte-order convention valid at
    /// `height`. Pre-`STANDARD_HEADER_ACTIVATION_HEIGHT` reverses BOTH
    /// prev_hash and merkle_root before writing (iriumd historical). At/post
    /// activation only prev_hash is reversed; merkle_root is written natural,
    /// matching Bitcoin standard wire format. See constants.rs for the
    /// rationale and Fix 2a migration plan.
    #[allow(dead_code)]
    pub fn serialize_for_height(&self, height: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(80);
        out.extend_from_slice(&self.version.to_le_bytes());
        let mut prev = self.prev_hash;
        prev.reverse();
        out.extend_from_slice(&prev);
        let mut merkle = self.merkle_root;
        if height < crate::constants::STANDARD_HEADER_ACTIVATION_HEIGHT {
            merkle.reverse();
        }
        out.extend_from_slice(&merkle);
        out.extend_from_slice(&self.time.to_le_bytes());
        out.extend_from_slice(&self.bits.to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out
    }

    /// Hash the 80-byte header using the byte-order convention valid at
    /// `height`. Returns display-order bytes (Bitcoin convention for block
    /// hashes shown to users / used in prev_hash fields of subsequent blocks).
    #[allow(dead_code)]
    pub fn hash_for_height(&self, height: u64) -> [u8; 32] {
        let ser = self.serialize_for_height(height);
        let mut h = header_hash(&[&ser]);
        h.reverse();
        h
    }

    /// Read the prev_hash field from raw 80-byte header bytes WITHOUT knowing
    /// the block's height. Safe because the prev_hash byte-order convention is
    /// the SAME pre and post fork (wire = natural order, stored = display order
    /// which is `reverse(wire)`). Used by P2P sync to look up the parent block
    /// in the chain and derive the height before doing a full height-aware
    /// deserialize of the rest of the header.
    #[allow(dead_code)]
    pub fn peek_prev_hash(raw: &[u8]) -> Result<[u8; 32], String> {
        if raw.len() < 36 {
            return Err("header too short to peek prev_hash".to_string());
        }
        let mut prev = [0u8; 32];
        prev.copy_from_slice(&raw[4..36]);
        prev.reverse();
        Ok(prev)
    }

    /// Deserialize a header from the 80-byte compact encoding using the
    /// byte-order convention valid at `height`. Mirror of
    /// `serialize_for_height`: pre-activation reverses both prev_hash and
    /// merkle_root after reading; at/post-activation only prev_hash is reversed.
    #[allow(dead_code)]
    pub fn deserialize_for_height(raw: &[u8], height: u64) -> Result<(Self, usize), String> {
        if raw.len() < 80 {
            return Err("header too short".to_string());
        }
        let mut offset = 0usize;
        let read_u32 = |buf: &[u8], off: &mut usize| -> Result<u32, String> {
            if *off + 4 > buf.len() {
                return Err("unexpected EOF".to_string());
            }
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&buf[*off..*off + 4]);
            *off += 4;
            Ok(u32::from_le_bytes(bytes))
        };

        let version = read_u32(raw, &mut offset)?;
        let mut prev_hash = [0u8; 32];
        prev_hash.copy_from_slice(&raw[offset..offset + 32]);
        prev_hash.reverse();
        offset += 32;
        let mut merkle_root = [0u8; 32];
        merkle_root.copy_from_slice(&raw[offset..offset + 32]);
        if height < crate::constants::STANDARD_HEADER_ACTIVATION_HEIGHT {
            merkle_root.reverse();
        }
        offset += 32;
        let time = read_u32(raw, &mut offset)?;
        let bits = read_u32(raw, &mut offset)?;
        let nonce = read_u32(raw, &mut offset)?;

        Ok((
            BlockHeader {
                version,
                prev_hash,
                merkle_root,
                time,
                bits,
                nonce,
            },
            offset,
        ))
    }
}

#[derive(Debug, Clone)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
    /// AuxPoW extension present when `header.version & AUXPOW_VERSION_BIT` is set.
    pub auxpow: Option<AuxPoW>,
}

impl Block {
    pub fn merkle_root(&self) -> [u8; 32] {
        if self.transactions.is_empty() {
            return [0u8; 32];
        }
        let mut leaves: Vec<[u8; 32]> = self
            .transactions
            .iter()
            .map(|tx| tx.txid())
            .map(|mut h| {
                h.reverse();
                h
            })
            .collect();
        if leaves.is_empty() { return [0u8; 32]; }
        while leaves.len() > 1 {
            if leaves.len() % 2 == 1 {
                let last = leaves[leaves.len() - 1]; // safe: len > 1 by while guard
                leaves.push(last);
            }
            let mut next = Vec::with_capacity(leaves.len() / 2);
            for pair in leaves.chunks(2) {
                let h = header_hash(&[&pair[0], &pair[1]]);
                next.push(h);
            }
            leaves = next;
        }
        leaves[0]
    }

    /// Deserialize a block: 80-byte header + optional AuxPoW + transactions.
    #[allow(dead_code)]
    pub fn deserialize(raw: &[u8]) -> Result<(Self, usize), String> {
        let (header, mut offset) = BlockHeader::deserialize(raw)?;

        let auxpow = if header.version & crate::auxpow::AUXPOW_VERSION_BIT != 0 {
            Some(crate::auxpow::deserialize(raw, &mut offset)?)
        } else {
            None
        };

        let mut txs = Vec::new();
        while offset < raw.len() {
            let tx = crate::tx::decode_full_tx_at(raw, &mut offset)?;
            txs.push(tx);
        }

        Ok((
            Block {
                header,
                transactions: txs,
                auxpow,
            },
            offset,
        ))
    }

    /// Serialize the block: 80-byte header + optional AuxPoW + transactions.
    #[allow(dead_code)]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = self.header.serialize();
        if let Some(ap) = &self.auxpow {
            out.extend_from_slice(&crate::auxpow::serialize(ap));
        }
        for tx in &self.transactions {
            out.extend_from_slice(&tx.serialize());
        }
        out
    }

    /// Deserialize a block using the byte-order convention valid at `height`.
    /// Mirror of `BlockHeader::deserialize_for_height` — only the 80-byte
    /// header parsing depends on height; the AuxPoW and transaction sections
    /// are byte-for-byte invariant across the fork.
    #[allow(dead_code)]
    pub fn deserialize_for_height(raw: &[u8], height: u64) -> Result<(Self, usize), String> {
        let (header, mut offset) = BlockHeader::deserialize_for_height(raw, height)?;

        let auxpow_active = crate::activation::MAINNET_AUXPOW_ACTIVATION_HEIGHT
            .map(|activation_height| height >= activation_height)
            .unwrap_or(false);
        let auxpow = if header.version & crate::auxpow::AUXPOW_VERSION_BIT != 0 && auxpow_active {
            Some(crate::auxpow::deserialize(raw, &mut offset)?)
        } else {
            None
        };

        let mut txs = Vec::new();
        while offset < raw.len() {
            let tx = crate::tx::decode_full_tx_at(raw, &mut offset)?;
            txs.push(tx);
        }

        Ok((
            Block {
                header,
                transactions: txs,
                auxpow,
            },
            offset,
        ))
    }

    /// Serialize the block using the byte-order convention valid at `height`.
    /// Header bytes vary per `serialize_for_height`; tx and AuxPoW sections
    /// are unchanged across the fork.
    #[allow(dead_code)]
    pub fn serialize_for_height(&self, height: u64) -> Vec<u8> {
        let mut out = self.header.serialize_for_height(height);
        if let Some(ap) = &self.auxpow {
            out.extend_from_slice(&crate::auxpow::serialize(ap));
        }
        for tx in &self.transactions {
            out.extend_from_slice(&tx.serialize());
        }
        out
    }
}

#[cfg(test)]
mod fix2a_boundary_tests {
    //! Fix 2a hard-fork boundary tests for BlockHeader::*_for_height.
    //!
    //! The fork at STANDARD_HEADER_ACTIVATION_HEIGHT (= 22_888) flips the
    //! merkle byte-order convention in the 80-byte wire header. Below the
    //! activation height the merkle_root field is reversed before writing
    //! (legacy iriumd convention); at and above the activation height it is
    //! written natural-order (Bitcoin standard). The prev_hash convention
    //! does NOT change at the fork.
    //!
    //! These tests pin the boundary behavior at heights 22_887 / 22_888 /
    //! 22_889 and verify byte equivalence with the legacy serialize() for
    //! all pre-fork heights.
    use super::*;
    use crate::constants::STANDARD_HEADER_ACTIVATION_HEIGHT;

    fn sample_header() -> BlockHeader {
        // Non-palindromic prev/merkle so byte-reversal differences are visible.
        let mut prev = [0u8; 32];
        for (i, b) in prev.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        let mut merkle = [0u8; 32];
        for (i, b) in merkle.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(13).wrapping_add(17);
        }
        BlockHeader {
            version: 1,
            prev_hash: prev,
            merkle_root: merkle,
            time: 0x6a0e_d4c0,
            bits: 0x1b00_ffff,
            nonce: 0xdead_beef,
        }
    }

    /// Sanity: the activation height constant is the expected value.
    #[test]
    fn activation_height_is_23_500() {
        assert_eq!(STANDARD_HEADER_ACTIVATION_HEIGHT, 22_888);
    }

    /// For every pre-fork height (0, 1, 100, … 22_887) the new
    /// serialize_for_height returns the SAME bytes as the legacy serialize().
    /// This is the central invariant: no existing chain state can become
    /// invalid because of this commit.
    #[test]
    fn serialize_for_height_matches_legacy_for_all_pre_fork_heights() {
        let h = sample_header();
        let legacy = h.serialize();
        for height in [0u64, 1, 99, 1_000, 10_000, 22_500, 22_887] {
            assert_eq!(
                h.serialize_for_height(height),
                legacy,
                "pre-fork height {height} must produce legacy bytes",
            );
        }
    }

    /// At and above activation, the bytes DIFFER from legacy specifically at
    /// the merkle_root window [36..68]. Other regions are unchanged.
    #[test]
    fn serialize_for_height_diverges_at_activation_in_merkle_only() {
        let h = sample_header();
        let legacy = h.serialize();
        let post = h.serialize_for_height(STANDARD_HEADER_ACTIVATION_HEIGHT);

        // Version + prev_hash + time + bits + nonce regions are identical.
        assert_eq!(&legacy[0..4], &post[0..4], "version unchanged");
        assert_eq!(&legacy[4..36], &post[4..36], "prev_hash unchanged");
        assert_eq!(&legacy[68..72], &post[68..72], "time unchanged");
        assert_eq!(&legacy[72..76], &post[72..76], "bits unchanged");
        assert_eq!(&legacy[76..80], &post[76..80], "nonce unchanged");

        // Merkle window IS different.
        assert_ne!(&legacy[36..68], &post[36..68], "merkle must differ");

        // Specifically: post-fork bytes equal the stored merkle_root as-is;
        // pre-fork bytes are the reverse.
        assert_eq!(&post[36..68], &h.merkle_root[..]);
        let mut expected_legacy_merkle = h.merkle_root;
        expected_legacy_merkle.reverse();
        assert_eq!(&legacy[36..68], &expected_legacy_merkle[..]);
    }

    /// 22_887 stays pre-fork, 22_888 flips post-fork, 22_889 stays post-fork.
    #[test]
    fn boundary_23499_23500_23501() {
        let h = sample_header();
        let pre = h.serialize_for_height(22_887);
        let act = h.serialize_for_height(22_888);
        let post = h.serialize_for_height(22_889);

        assert_eq!(pre, h.serialize(), "22887 = legacy");
        assert_ne!(act, pre, "22888 differs from 22887");
        assert_eq!(act, post, "22888 = 22889 (both post-fork)");
    }

    /// Round-trip: serialize_for_height(h) -> deserialize_for_height(_, h)
    /// reconstructs the original struct exactly, on both fork sides.
    #[test]
    fn serialize_deserialize_roundtrip_both_sides() {
        let h = sample_header();
        for height in [0u64, 22_400, 22_887, 22_888, 22_889, 1_000_000] {
            let bytes = h.serialize_for_height(height);
            assert_eq!(bytes.len(), 80);
            let (parsed, consumed) =
                BlockHeader::deserialize_for_height(&bytes, height).expect("decode");
            assert_eq!(consumed, 80);
            assert_eq!(parsed.version, h.version, "@h={height} version");
            assert_eq!(parsed.prev_hash, h.prev_hash, "@h={height} prev_hash");
            assert_eq!(parsed.merkle_root, h.merkle_root, "@h={height} merkle_root");
            assert_eq!(parsed.time, h.time, "@h={height} time");
            assert_eq!(parsed.bits, h.bits, "@h={height} bits");
            assert_eq!(parsed.nonce, h.nonce, "@h={height} nonce");
        }
    }

    /// hash_for_height pre-fork == legacy hash().
    /// hash_for_height post-fork differs (different bytes hashed, different sha256d).
    #[test]
    fn hash_for_height_pre_matches_legacy_post_differs() {
        let h = sample_header();
        let legacy_hash = h.hash();
        let pre_hash = h.hash_for_height(22_887);
        let post_hash = h.hash_for_height(22_888);

        assert_eq!(pre_hash, legacy_hash, "pre-fork hash must match legacy hash()");
        assert_ne!(post_hash, legacy_hash, "post-fork hash must differ from legacy");
        assert_ne!(post_hash, pre_hash, "post-fork hash must differ from pre-fork hash");
    }

    /// peek_prev_hash reads bytes [4..36] reversed regardless of fork side.
    /// This is fork-invariant: the prev_hash byte-order convention is the
    /// same pre and post fork.
    #[test]
    fn peek_prev_hash_is_fork_invariant() {
        let h = sample_header();
        let pre = h.serialize_for_height(22_887);
        let post = h.serialize_for_height(22_888);

        let peeked_pre = BlockHeader::peek_prev_hash(&pre).expect("peek pre");
        let peeked_post = BlockHeader::peek_prev_hash(&post).expect("peek post");

        assert_eq!(peeked_pre, h.prev_hash, "peek pre returns stored prev_hash");
        assert_eq!(peeked_post, h.prev_hash, "peek post returns same prev_hash");
        assert_eq!(peeked_pre, peeked_post, "peek is fork-invariant");
    }

    /// peek_prev_hash rejects truncated buffers without panicking.
    #[test]
    fn peek_prev_hash_rejects_short_input() {
        assert!(BlockHeader::peek_prev_hash(&[0u8; 0]).is_err());
        assert!(BlockHeader::peek_prev_hash(&[0u8; 35]).is_err());
        // exactly 36 bytes is enough to read the prev_hash field
        assert!(BlockHeader::peek_prev_hash(&[0u8; 36]).is_ok());
    }

    /// Cross-fork chain link: block at height 22_888 stores its parent's
    /// hash_for_height(22_887). This must round-trip through the chain so
    /// the new block can look up its parent using peek_prev_hash on its
    /// own wire bytes.
    #[test]
    fn cross_fork_chain_link_resolves_parent() {
        let parent = sample_header();
        let parent_hash_at_23499 = parent.hash_for_height(22_887);

        // The new block at height 22_888 stores parent_hash_at_23499 as its prev_hash.
        let mut child = sample_header();
        child.prev_hash = parent_hash_at_23499;
        child.nonce = child.nonce.wrapping_add(1);

        // Serialize the child with post-fork rules.
        let child_bytes = child.serialize_for_height(22_888);
        // A receiver peeks prev_hash from the wire (fork-invariant peek).
        let recovered_parent_hash = BlockHeader::peek_prev_hash(&child_bytes).expect("peek");

        assert_eq!(
            recovered_parent_hash, parent_hash_at_23499,
            "peek must recover the parent's pre-fork hash from the post-fork child bytes",
        );
    }

    /// Block::serialize_for_height composes header bytes correctly with no
    /// AuxPoW and no transactions (degenerate but covers the helper).
    #[test]
    fn block_serialize_for_height_header_only_no_txs_no_auxpow() {
        let header = sample_header();
        let block = Block {
            header: header.clone(),
            transactions: vec![],
            auxpow: None,
        };
        for height in [0u64, 22_887, 22_888] {
            assert_eq!(
                block.serialize_for_height(height),
                header.serialize_for_height(height),
                "Block::serialize_for_height({height}) prefix must equal header.serialize_for_height({height})",
            );
        }
    }
}
