#![allow(dead_code)]
use crate::auxpow::AuxPoW;
use crate::pow::{header_hash, Target};
use crate::tx::Transaction;

static RESOLVED_STD_HEADER_ACTIVATION: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

/// Set the process-wide resolved standard-header (Fix 2a) activation height.
/// Call once at binary startup with the network-resolved value (first set wins).
pub fn set_standard_header_activation_height(height: u64) {
    let _ = RESOLVED_STD_HEADER_ACTIVATION.set(height);
}

/// Process-wide resolved standard-header activation height. Defaults to the
/// mainnet historical constant when unset (unit tests / binaries that do not
/// wire it), keeping mainnet/default serialization byte-stable.
pub fn standard_header_activation_height() -> u64 {
    *RESOLVED_STD_HEADER_ACTIVATION
        .get()
        .unwrap_or(&crate::constants::STANDARD_HEADER_ACTIVATION_HEIGHT)
}

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
        self.serialize_with_activation(height, standard_header_activation_height())
    }

    /// As `serialize_for_height` but with an explicit standard-header activation
    /// height (testable; the public method delegates with the resolved value).
    pub fn serialize_with_activation(&self, height: u64, std_header_activation: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(80);
        out.extend_from_slice(&self.version.to_le_bytes());
        let mut prev = self.prev_hash;
        prev.reverse();
        out.extend_from_slice(&prev);
        let mut merkle = self.merkle_root;
        if height < std_header_activation {
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
        Self::deserialize_with_activation(raw, height, standard_header_activation_height())
    }

    /// As `deserialize_for_height` but with an explicit standard-header
    /// activation height (testable; the public method delegates).
    pub fn deserialize_with_activation(
        raw: &[u8],
        height: u64,
        std_header_activation: u64,
    ) -> Result<(Self, usize), String> {
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
        if height < std_header_activation {
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
    /// PoAW-X receipts carried in the block wire/storage format (Phase 13-A).
    /// `None` for legacy and mainnet blocks.
    pub poawx_receipts: Option<Vec<crate::poawx::PoawxBlockReceipt>>,
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
        if leaves.is_empty() {
            return [0u8; 32];
        }
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

    /// Phase 18B: serialize the PoAW-X receipt section. A pure mode-0 receipt
    /// set uses the v1 magic and the fixed 166-byte element encoding —
    /// byte-for-byte identical to the Phase 13-A format. Only when at least one
    /// mode-1 (delegated) receipt is present is the v2 magic / per-element
    /// self-describing encoding used.
    fn serialize_receipt_section(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(receipts) = &self.poawx_receipts {
            if !receipts.is_empty() {
                let has_phase20 = receipts.iter().any(|r| r.phase20_ext.is_some());
                let has_mode1 = receipts.iter().any(|r| r.delegation.is_some());
                if has_phase20 {
                    // Phase 20: present-only v3 section (v1/v2 byte-identical when no ext).
                    out.extend_from_slice(crate::poawx::POAWX_RECEIPT_SECTION_MAGIC_V3);
                    out.push(receipts.len() as u8);
                    for r in receipts {
                        out.extend_from_slice(&r.serialize_v3());
                    }
                } else if has_mode1 {
                    out.extend_from_slice(crate::poawx::POAWX_RECEIPT_SECTION_MAGIC_V2);
                    out.push(receipts.len() as u8);
                    for r in receipts {
                        out.extend_from_slice(&r.serialize_v2());
                    }
                } else {
                    out.extend_from_slice(crate::poawx::POAWX_RECEIPT_SECTION_MAGIC);
                    out.push(receipts.len() as u8);
                    for r in receipts {
                        out.extend_from_slice(&r.serialize());
                    }
                }
            }
        }
        out
    }

    /// Phase 18B: if a v1 or v2 receipt-section magic begins at `*offset`, parse
    /// the section, advance `*offset` past it, and return the receipts. Returns
    /// `Ok(None)` when the bytes at `*offset` are not a receipt section (so the
    /// caller continues parsing transactions). v1 uses the fixed 166-byte loop
    /// (identical to Phase 13-A); v2 uses the self-describing element parser.
    fn try_parse_receipt_section(
        raw: &[u8],
        offset: &mut usize,
    ) -> Result<Option<Vec<crate::poawx::PoawxBlockReceipt>>, String> {
        if raw.len() - *offset < 8 {
            return Ok(None);
        }
        let magic = &raw[*offset..*offset + 8];
        let is_v1 = magic == crate::poawx::POAWX_RECEIPT_SECTION_MAGIC;
        let is_v2 = magic == crate::poawx::POAWX_RECEIPT_SECTION_MAGIC_V2;
        let is_v3 = magic == crate::poawx::POAWX_RECEIPT_SECTION_MAGIC_V3;
        if !is_v1 && !is_v2 && !is_v3 {
            return Ok(None);
        }
        let mut off = *offset + 8;
        if off >= raw.len() {
            return Err("receipt section: missing count byte".to_string());
        }
        let count = raw[off] as usize;
        off += 1;
        let mut receipts = Vec::with_capacity(count);
        for _ in 0..count {
            if is_v1 {
                if raw.len() - off < crate::poawx::PoawxBlockReceipt::WIRE_SIZE {
                    return Err("receipt section truncated".to_string());
                }
                receipts.push(crate::poawx::PoawxBlockReceipt::deserialize(&raw[off..])?);
                off += crate::poawx::PoawxBlockReceipt::WIRE_SIZE;
            } else if is_v2 {
                let (r, used) = crate::poawx::PoawxBlockReceipt::deserialize_v2(&raw[off..])?;
                receipts.push(r);
                off += used;
            } else {
                // v3 (Phase 20): v2 element + optional length-prefixed extension.
                let (r, used) = crate::poawx::PoawxBlockReceipt::deserialize_v3(&raw[off..])?;
                receipts.push(r);
                off += used;
            }
        }
        *offset = off;
        Ok(Some(receipts))
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
        let mut poawx_receipts: Option<Vec<crate::poawx::PoawxBlockReceipt>> = None;
        while offset < raw.len() {
            if let Some(receipts) = Self::try_parse_receipt_section(raw, &mut offset)? {
                poawx_receipts = Some(receipts);
                break;
            }
            let tx = crate::tx::decode_full_tx_at(raw, &mut offset)?;
            txs.push(tx);
        }

        Ok((
            Block {
                header,
                transactions: txs,
                auxpow,
                poawx_receipts,
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
        out.extend_from_slice(&self.serialize_receipt_section());
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
        let mut poawx_receipts: Option<Vec<crate::poawx::PoawxBlockReceipt>> = None;
        while offset < raw.len() {
            if let Some(receipts) = Self::try_parse_receipt_section(raw, &mut offset)? {
                poawx_receipts = Some(receipts);
                break;
            }
            let tx = crate::tx::decode_full_tx_at(raw, &mut offset)?;
            txs.push(tx);
        }

        Ok((
            Block {
                header,
                transactions: txs,
                auxpow,
                poawx_receipts,
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
        out.extend_from_slice(&self.serialize_receipt_section());
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

    /// Devnet/testnet (activation=0): even height 1 uses the natural merkle
    /// layout (Bitcoin-standard), so standard cpuminers validate from genesis.
    #[test]
    fn devnet_activation_zero_uses_natural_merkle_from_genesis() {
        let h = sample_header();
        let dev = h.serialize_with_activation(1, 0);
        let pre = h.serialize_with_activation(1, STANDARD_HEADER_ACTIVATION_HEIGHT);
        assert_eq!(
            &dev[36..68],
            &h.merkle_root[..],
            "devnet height 1 = natural merkle"
        );
        let mut rev = h.merkle_root;
        rev.reverse();
        assert_eq!(
            &pre[36..68],
            &rev[..],
            "mainnet pre-fork height 1 = reversed merkle"
        );
        assert_ne!(dev, pre);
    }

    /// Round-trip at devnet height 1 with activation=0.
    #[test]
    fn devnet_serialize_deserialize_roundtrip_height_1() {
        let h = sample_header();
        let ser = h.serialize_with_activation(1, 0);
        let (back, n) = BlockHeader::deserialize_with_activation(&ser, 1, 0).unwrap();
        assert_eq!(n, 80);
        assert_eq!(back.merkle_root, h.merkle_root);
        assert_eq!(back.prev_hash, h.prev_hash);
        assert_eq!(back.version, h.version);
        assert_eq!(back.time, h.time);
        assert_eq!(back.bits, h.bits);
        assert_eq!(back.nonce, h.nonce);
    }

    /// Mainnet regression: explicit activation=22888 preserves pre/post-fork
    /// behavior, and the default serialize_for_height (global unset in tests)
    /// resolves to 22888 — byte-identical to the historical const path.
    #[test]
    fn mainnet_serialization_byte_stable() {
        let h = sample_header();
        let mut rev = h.merkle_root;
        rev.reverse();
        assert_eq!(
            &h.serialize_with_activation(100, STANDARD_HEADER_ACTIVATION_HEIGHT)[36..68],
            &rev[..]
        );
        assert_eq!(
            &h.serialize_with_activation(
                STANDARD_HEADER_ACTIVATION_HEIGHT,
                STANDARD_HEADER_ACTIVATION_HEIGHT
            )[36..68],
            &h.merkle_root[..]
        );
        // Default (global unset) must equal explicit mainnet const.
        assert_eq!(
            h.serialize_for_height(100),
            h.serialize_with_activation(100, STANDARD_HEADER_ACTIVATION_HEIGHT)
        );
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

        assert_eq!(
            pre_hash, legacy_hash,
            "pre-fork hash must match legacy hash()"
        );
        assert_ne!(
            post_hash, legacy_hash,
            "post-fork hash must differ from legacy"
        );
        assert_ne!(
            post_hash, pre_hash,
            "post-fork hash must differ from pre-fork hash"
        );
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
            poawx_receipts: None,
        };
        for height in [0u64, 22_887, 22_888] {
            assert_eq!(
                block.serialize_for_height(height),
                header.serialize_for_height(height),
                "Block::serialize_for_height({height}) prefix must equal header.serialize_for_height({height})",
            );
        }
    }

    // ── Phase 13-A: block wire receipt encoding tests ────────────────────

    fn make_receipt(height: u64) -> crate::poawx::PoawxBlockReceipt {
        crate::poawx::PoawxBlockReceipt {
            height,
            lane: b'L',
            worker_pkh: [0xaau8; 20],
            worker_pubkey: [0xbbu8; 33],
            worker_sig: [0xccu8; 64],
            solution: [0xddu8; 8],
            commitment_nonce: [0xeeu8; 32],
            delegation: None,
            phase20_ext: None,
        }
    }

    fn make_block_with_receipts(height: u64) -> Block {
        Block {
            header: sample_header(),
            transactions: vec![],
            auxpow: None,
            poawx_receipts: Some(vec![make_receipt(height)]),
        }
    }

    #[test]
    fn phase13a_block_with_receipts_serialize_deserialize_roundtrip() {
        let block = make_block_with_receipts(7);
        let bytes = block.serialize_for_height(1);
        let (decoded, used) =
            Block::deserialize_for_height(&bytes, 1).expect("deserialize_for_height must succeed");
        assert_eq!(used, bytes.len(), "all bytes consumed");
        let receipts = decoded.poawx_receipts.expect("receipts present");
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0], make_receipt(7));
        assert_eq!(receipts[0].lane, b'L');
    }

    #[test]
    fn phase13a_block_without_receipts_no_magic_appended() {
        // A block with poawx_receipts=None must produce bytes identical to
        // a pre-Phase-13-A serialization (no POAWX_RECEIPT_SECTION_MAGIC).
        let block = Block {
            header: sample_header(),
            transactions: vec![],
            auxpow: None,
            poawx_receipts: None,
        };
        let bytes = block.serialize_for_height(1);
        let magic = crate::poawx::POAWX_RECEIPT_SECTION_MAGIC;
        // Confirm magic does NOT appear in the output.
        let contains_magic = bytes.windows(8).any(|w| w == magic);
        assert!(
            !contains_magic,
            "blocks without receipts must not contain POAWX_RECEIPT_SECTION_MAGIC"
        );
        // And bytes must equal header-only serialization.
        assert_eq!(bytes, block.header.serialize_for_height(1));
    }

    #[test]
    fn phase13a_block_empty_receipts_vec_no_magic() {
        // Some([]) must also produce no magic (empty receipt list is treated as absent).
        let block = Block {
            header: sample_header(),
            transactions: vec![],
            auxpow: None,
            poawx_receipts: Some(vec![]),
        };
        let bytes = block.serialize_for_height(1);
        let magic = crate::poawx::POAWX_RECEIPT_SECTION_MAGIC;
        let contains_magic = bytes.windows(8).any(|w| w == magic);
        assert!(
            !contains_magic,
            "empty receipt list must produce no magic bytes"
        );
    }

    #[test]
    fn phase13a_truncated_receipt_section_rejected() {
        // Build valid bytes then corrupt the count byte to claim more receipts.
        let block = make_block_with_receipts(5);
        let valid_bytes = block.serialize_for_height(1);
        // Truncate by removing the last 10 bytes — now the receipt body is incomplete.
        let truncated = &valid_bytes[..valid_bytes.len() - 10];
        let result = Block::deserialize_for_height(truncated, 1);
        assert!(
            result.is_err(),
            "truncated receipt section must cause deserialize_for_height to fail"
        );
    }

    #[test]
    fn phase13a_receipts_count_byte_correct() {
        // Encode 3 receipts and confirm the count byte in the wire bytes is 3.
        let receipts: Vec<_> = (0..3).map(make_receipt).collect();
        let block = Block {
            header: sample_header(),
            transactions: vec![],
            auxpow: None,
            poawx_receipts: Some(receipts),
        };
        let bytes = block.serialize_for_height(1);
        // Find magic position.
        let magic = crate::poawx::POAWX_RECEIPT_SECTION_MAGIC;
        let magic_pos = bytes
            .windows(8)
            .position(|w| w == magic)
            .expect("magic must be present");
        let count_byte = bytes[magic_pos + 8];
        assert_eq!(count_byte, 3, "count byte must be 3 for 3 receipts");
        // And the total length must be header + magic(8) + count(1) + 3*166.
        let expected_len = 80 + 8 + 1 + 3 * crate::poawx::PoawxBlockReceipt::WIRE_SIZE;
        assert_eq!(bytes.len(), expected_len);
    }

    // ── Phase 18B: v2 (delegated) receipt-section wire tests ──────────────

    fn signed_delegation() -> crate::poawx::Delegation {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        let sk = k256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
        let vk = k256::ecdsa::VerifyingKey::from(&sk);
        let enc = vk.to_encoded_point(true);
        let mut miner_pubkey = [0u8; 33];
        miner_pubkey.copy_from_slice(enc.as_bytes());
        let mut d = crate::poawx::Delegation {
            deleg_version: crate::poawx::Delegation::VERSION,
            network_id: 1,
            miner_pubkey,
            pool_pubkey: [0x02u8; 33],
            worker_tag: [0xaau8; 32],
            expiry_height: 1000,
            fee_bps: 0,
            fee_pkh: [0u8; 20],
            deleg_nonce: [0x77u8; 32],
            delegation_sig: [0u8; 64],
        };
        let sig: k256::ecdsa::Signature = sk.sign_prehash(&d.message_hash()).unwrap();
        d.delegation_sig.copy_from_slice(&sig.to_bytes());
        d
    }

    fn make_mode1_receipt(height: u64) -> crate::poawx::PoawxBlockReceipt {
        let mut r = make_receipt(height);
        r.delegation = Some(signed_delegation());
        r
    }

    #[test]
    fn phase18b_mode0_block_uses_v1_magic_byte_identical() {
        let block = make_block_with_receipts(7);
        let bytes = block.serialize_for_height(1);
        let v1 = crate::poawx::POAWX_RECEIPT_SECTION_MAGIC;
        let v2 = crate::poawx::POAWX_RECEIPT_SECTION_MAGIC_V2;
        assert!(
            bytes.windows(8).any(|w| w == v1),
            "mode-0 must use v1 magic"
        );
        assert!(
            !bytes.windows(8).any(|w| w == v2),
            "mode-0 must NOT use v2 magic"
        );
        let expected_len = 80 + 8 + 1 + crate::poawx::PoawxBlockReceipt::WIRE_SIZE;
        assert_eq!(bytes.len(), expected_len, "Phase 13-A layout unchanged");
    }

    #[test]
    fn phase18b_mode1_block_uses_v2_magic_and_roundtrips() {
        let block = Block {
            header: sample_header(),
            transactions: vec![],
            auxpow: None,
            poawx_receipts: Some(vec![make_mode1_receipt(7)]),
        };
        let bytes = block.serialize_for_height(1);
        let v1 = crate::poawx::POAWX_RECEIPT_SECTION_MAGIC;
        let v2 = crate::poawx::POAWX_RECEIPT_SECTION_MAGIC_V2;
        assert!(
            bytes.windows(8).any(|w| w == v2),
            "mode-1 must use v2 magic"
        );
        assert!(
            !bytes.windows(8).any(|w| w == v1),
            "mode-1 must NOT use v1 magic"
        );
        let expected_len = 80
            + 8
            + 1
            + 1
            + crate::poawx::PoawxBlockReceipt::WIRE_SIZE
            + crate::poawx::Delegation::WIRE_SIZE;
        assert_eq!(bytes.len(), expected_len);
        let (decoded, used) = Block::deserialize_for_height(&bytes, 1).expect("decode");
        assert_eq!(used, bytes.len());
        let receipts = decoded.poawx_receipts.expect("receipts present");
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0], make_mode1_receipt(7));
        assert!(receipts[0].delegation.is_some());
    }

    #[test]
    fn phase18b_v2_mixed_block_roundtrips() {
        let block = Block {
            header: sample_header(),
            transactions: vec![],
            auxpow: None,
            poawx_receipts: Some(vec![make_receipt(1), make_mode1_receipt(2)]),
        };
        let bytes = block.serialize_for_height(1);
        let v2 = crate::poawx::POAWX_RECEIPT_SECTION_MAGIC_V2;
        assert!(bytes.windows(8).any(|w| w == v2));
        let (decoded, used) = Block::deserialize_for_height(&bytes, 1).expect("decode");
        assert_eq!(used, bytes.len());
        let receipts = decoded.poawx_receipts.expect("receipts");
        assert_eq!(receipts.len(), 2);
        assert!(receipts[0].delegation.is_none());
        assert!(receipts[1].delegation.is_some());
    }

    #[test]
    fn phase18b_v2_truncated_delegation_rejected() {
        let block = Block {
            header: sample_header(),
            transactions: vec![],
            auxpow: None,
            poawx_receipts: Some(vec![make_mode1_receipt(5)]),
        };
        let valid = block.serialize_for_height(1);
        let truncated = &valid[..valid.len() - 10];
        assert!(Block::deserialize_for_height(truncated, 1).is_err());
    }

    #[test]
    fn phase20_v3_block_with_extension_roundtrips_and_old_blocks_unaffected() {
        // A receipt carrying a Phase20ReceiptExt makes the block use the v3 magic
        // and round-trips through the block wire (the P2P / binary-persist path).
        let claim = |role_id: u8| crate::poawx::PoawxRoleClaim {
            role_id,
            lane_id: 0,
            solver_pkh: [role_id; 20],
            nonce: [1u8; 32],
            secret: [2u8; 32],
            claim_digest: [3u8; 32],
            commitment_hash: None,
        };
        let ext = crate::poawx::Phase20ReceiptExt {
            role_reward: crate::poawx::RoleReward {
                compute_contributor_pkh: [0xC1u8; 20],
                verify_contributor_pkh: [0xC2u8; 20],
                support_contributor_pkh: [0xC3u8; 20],
            },
            compute_claim: claim(1),
            verify_claim: claim(2),
            support_claim: claim(3),
            fee_bps: 0,
            fee_pkh: [0u8; 20],
            precommit_root: None,
            role_ticket_proofs: None,
            role_dominance_weights: None,
            candidate_set: None,
            role_puzzle_proofs: None,
            finality_proof: None,
            committed_admission: None,
            role_assignment_v2: None,
            double_sign_evidence: None,
        };
        let mut r = make_receipt(7);
        r.phase20_ext = Some(ext);
        let block = Block {
            header: sample_header(),
            transactions: vec![],
            auxpow: None,
            poawx_receipts: Some(vec![r.clone()]),
        };
        let bytes = block.serialize_for_height(1);
        let v1 = crate::poawx::POAWX_RECEIPT_SECTION_MAGIC;
        let v2 = crate::poawx::POAWX_RECEIPT_SECTION_MAGIC_V2;
        let v3 = crate::poawx::POAWX_RECEIPT_SECTION_MAGIC_V3;
        assert!(
            bytes.windows(8).any(|w| w == v3),
            "ext block must use v3 magic"
        );
        assert!(!bytes.windows(8).any(|w| w == v1), "must NOT use v1 magic");
        assert!(!bytes.windows(8).any(|w| w == v2), "must NOT use v2 magic");
        let (decoded, used) = Block::deserialize_for_height(&bytes, 1).expect("decode v3");
        assert_eq!(used, bytes.len());
        let receipts = decoded.poawx_receipts.expect("receipts");
        assert_eq!(receipts.len(), 1);
        assert_eq!(
            receipts[0], r,
            "phase20_ext receipt round-trips byte-for-byte"
        );
        assert!(receipts[0].phase20_ext.is_some());

        // An old block (no extension) is byte-identical to before — no v3 magic.
        let old = Block {
            header: sample_header(),
            transactions: vec![],
            auxpow: None,
            poawx_receipts: Some(vec![make_receipt(7)]),
        };
        let old_bytes = old.serialize_for_height(1);
        assert!(
            !old_bytes.windows(8).any(|w| w == v3),
            "no-ext block must NOT use v3 magic"
        );
        assert!(
            old_bytes.windows(8).any(|w| w == v1),
            "no-ext mode-0 block uses v1 magic"
        );
    }
}
