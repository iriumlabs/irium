use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::btc_spv::parse_btc_header_batch;
use crate::chain::ChainState;
use crate::ltc_spv::parse_ltc_header_batch;
use crate::tx::{decode_full_tx, Transaction};

/// Per-IP minimum interval between successive `ZeroFeeAllowed` admissions.
/// Buyer-side BTC swap operations (header relay, claim, sell-direction
/// fill) bypass `min_fee_per_byte` but must space themselves out so that
/// a single source IP cannot flood the exempt class. Loopback addresses
/// (127.0.0.1, ::1) bypass this gate so the local operator and Tauri
/// client can act unthrottled.
pub const HEADER_RELAY_PER_IP_INTERVAL_SECS: u64 = 600;

/// Mempool admission class. `ZeroFeeAllowed` covers the three buyer-side
/// shapes that a BTC-only wallet has to broadcast and cannot fund from
/// its own IRM balance: BTC/LTC `*HeaderBatch` carriers, HtlcBtcSwap
/// claim spends (witness selector `0x01`), and sell-direction SwapOrder
/// fills (witness selector `0x01`). The class is exempt from
/// `min_fee_per_byte` and is the first to be evicted when the mempool
/// reaches capacity — paying transactions can never be displaced by a
/// zero-fee one. Every other tx is `Standard` and follows the original
/// fee policy unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MempoolPriority {
    ZeroFeeAllowed,
    Standard,
}

impl MempoolPriority {
    /// Numeric rank used as the primary key in the eviction comparator.
    /// Lower is evicted first.
    fn rank(&self) -> u8 {
        match self {
            Self::ZeroFeeAllowed => 0,
            Self::Standard => 1,
        }
    }

    fn as_disk_str(&self) -> &'static str {
        match self {
            Self::ZeroFeeAllowed => "zero_fee_allowed",
            Self::Standard => "standard",
        }
    }

    fn from_disk_str(s: &str) -> Option<Self> {
        match s {
            "zero_fee_allowed" => Some(Self::ZeroFeeAllowed),
            "standard" => Some(Self::Standard),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MempoolEntry {
    pub tx: Transaction,
    pub raw: Vec<u8>,
    pub fee: u64,
    pub size: usize,
    pub fee_per_byte: f64,
    pub added: u64,
    pub relays: Vec<String>,
    pub relay_addresses: Vec<String>,
    pub priority: MempoolPriority,
}

#[derive(Debug, Clone)]
pub struct AddOutcome {
    pub txid: [u8; 32],
    pub evicted: Option<[u8; 32]>,
}

#[derive(Serialize, Deserialize)]
struct DiskEntry {
    hex: String,
    fee: Option<u64>,
    size: Option<usize>,
    fee_per_byte: Option<f64>,
    added: Option<u64>,
    txid: Option<String>,
    relays: Option<Vec<String>>,
    relay_addresses: Option<Vec<String>>,
    /// Stored as the string returned by `MempoolPriority::as_disk_str`.
    /// `None` on legacy on-disk entries that pre-date the priority field;
    /// those entries load as `Standard` so they keep their original
    /// admission semantics.
    priority: Option<String>,
}

pub struct MempoolManager {
    entries: HashMap<[u8; 32], MempoolEntry>,
    path: PathBuf,
    max_entries: usize,
    min_fee_per_byte: f64,
    /// Absolute per-tx fee floor in satoshis. Standard-priority txs
    /// must pay at least this much in total fee in addition to
    /// clearing `min_fee_per_byte`. `ZeroFeeAllowed` bypasses both
    /// floors. `0` disables the floor (used in tests).
    min_total_fee: u64,
    /// Last admission time per source IP for `ZeroFeeAllowed` entries.
    /// In-memory only by design — an iriumd restart re-opens the rate
    /// window. The attacker model here is network spam, and a restart
    /// is a costly operation an attacker cannot trigger remotely.
    header_relay_last_seen: HashMap<IpAddr, SystemTime>,
}

impl MempoolManager {
    pub fn new(
        path: PathBuf,
        max_entries: usize,
        min_fee_per_byte: f64,
        min_total_fee: u64,
    ) -> MempoolManager {
        let mut mgr = MempoolManager {
            entries: HashMap::new(),
            path,
            max_entries,
            min_fee_per_byte,
            min_total_fee,
            header_relay_last_seen: HashMap::new(),
        };
        mgr.load_from_disk();
        mgr
    }

    fn load_from_disk(&mut self) {
        let data = match fs::read_to_string(&self.path) {
            Ok(d) => d,
            Err(_) => return,
        };
        let parsed: Vec<DiskEntry> = match serde_json::from_str(&data) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Failed to parse mempool file {}: {e}", self.path.display());
                return;
            }
        };

        for entry in parsed {
            let raw = match hex::decode(&entry.hex) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("Invalid tx hex in mempool: {e}");
                    continue;
                }
            };
            let tx = match decode_full_tx(&raw) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Invalid mempool tx decode: {e}");
                    continue;
                }
            };
            let txid = tx.txid();
            let size = entry.size.unwrap_or(raw.len());
            let fee = entry.fee.unwrap_or(0);
            let fpb = entry.fee_per_byte.unwrap_or_else(|| {
                if size > 0 {
                    fee as f64 / size as f64
                } else {
                    0.0
                }
            });
            let added = entry.added.unwrap_or_else(now_secs);
            let relays = entry.relays.unwrap_or_default();
            let relay_addresses = entry.relay_addresses.unwrap_or_default();
            let priority = entry
                .priority
                .as_deref()
                .and_then(MempoolPriority::from_disk_str)
                .unwrap_or(MempoolPriority::Standard);
            self.entries.insert(
                txid,
                MempoolEntry {
                    tx,
                    raw,
                    fee,
                    size,
                    fee_per_byte: fpb,
                    added,
                    relays,
                    relay_addresses,
                    priority,
                },
            );
        }
    }

    fn persist(&self) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let mut disk_entries: Vec<DiskEntry> = Vec::with_capacity(self.entries.len());
        for (txid, entry) in self.entries.iter() {
            disk_entries.push(DiskEntry {
                hex: hex::encode(&entry.raw),
                fee: Some(entry.fee),
                size: Some(entry.size),
                fee_per_byte: Some(entry.fee_per_byte),
                added: Some(entry.added),
                txid: Some(hex::encode(txid)),
                relays: Some(entry.relays.clone()),
                relay_addresses: Some(entry.relay_addresses.clone()),
                priority: Some(entry.priority.as_disk_str().to_string()),
            });
        }
        let json = serde_json::to_string_pretty(&disk_entries).map_err(|e| e.to_string())?;
        fs::write(&self.path, json).map_err(|e| e.to_string())
    }

    /// Convenience wrapper that classifies the tx as `Standard` and
    /// preserves the original fee policy. Existing call sites that don't
    /// distinguish the buyer-side exemption keep using this path
    /// unchanged. Buyer-side handlers and the P2P relay path call
    /// [`add_transaction_with_priority`] directly.
    pub fn add_transaction(
        &mut self,
        tx: Transaction,
        raw: Vec<u8>,
        fee: u64,
    ) -> Result<AddOutcome, String> {
        self.add_transaction_with_priority(tx, raw, fee, MempoolPriority::Standard, None)
    }

    /// Full-control admission. `priority` is determined by the caller —
    /// handlers know the shape of the tx they built; the P2P ingress
    /// path classifies incoming peer txs via
    /// `crate::chain::classify_tx_priority`. `peer_ip` is the source IP
    /// for rate-limiting `ZeroFeeAllowed` admissions; loopback
    /// (127.0.0.1, ::1) bypasses the rate limit so local operator
    /// scripts and the Tauri client are unthrottled.
    pub fn add_transaction_with_priority(
        &mut self,
        tx: Transaction,
        raw: Vec<u8>,
        fee: u64,
        priority: MempoolPriority,
        peer_ip: Option<IpAddr>,
    ) -> Result<AddOutcome, String> {
        let txid = tx.txid();
        if self.entries.contains_key(&txid) {
            return Err("Transaction already in mempool".to_string());
        }

        // Per-chain header-batch dedup. Consensus caps each
        // {Btc,Ltc}HeaderBatch carrier at one per block (chain.rs).
        // The mempool can hold many in transit when peers re-gossip
        // stale carriers after an iriumd restart — each cycle of the
        // wallet-funded carrier-tx builder uses different UTXOs, so
        // multiple distinct txids can carry the same chain's batch and
        // the existing same-txid dedup above does not catch them.
        // Reject incoming carriers when a same-chain carrier is
        // already pending. The existing carrier confirms (or ages
        // out) before the next one is accepted, mirroring the
        // consensus cap one level earlier in the pipeline.
        let new_has_btc = tx
            .outputs
            .iter()
            .any(|o| parse_btc_header_batch(&o.script_pubkey).is_ok());
        let new_has_ltc = tx
            .outputs
            .iter()
            .any(|o| parse_ltc_header_batch(&o.script_pubkey).is_ok());
        if new_has_btc || new_has_ltc {
            for entry in self.entries.values() {
                if new_has_btc
                    && entry
                        .tx
                        .outputs
                        .iter()
                        .any(|o| parse_btc_header_batch(&o.script_pubkey).is_ok())
                {
                    return Err("duplicate_btc_header_batch_pending".to_string());
                }
                if new_has_ltc
                    && entry
                        .tx
                        .outputs
                        .iter()
                        .any(|o| parse_ltc_header_batch(&o.script_pubkey).is_ok())
                {
                    return Err("duplicate_ltc_header_batch_pending".to_string());
                }
            }
        }

        if priority == MempoolPriority::ZeroFeeAllowed {
            if let Some(ip) = peer_ip {
                if !ip.is_loopback() {
                    let now = SystemTime::now();
                    self.gc_header_relay_rate_table(now);
                    if let Some(prev) = self.header_relay_last_seen.get(&ip).copied() {
                        let elapsed_under_limit = now
                            .duration_since(prev)
                            .map(|d| d.as_secs() < HEADER_RELAY_PER_IP_INTERVAL_SECS)
                            .unwrap_or(false);
                        if elapsed_under_limit {
                            return Err("header_relay_rate_limit_per_ip".to_string());
                        }
                    }
                }
            }
        }

        let size = raw.len();
        let fee_per_byte = if size > 0 {
            fee as f64 / size as f64
        } else {
            0.0
        };

        // Standard txs must clear the configured floor. ZeroFeeAllowed
        // bypasses it — the eviction policy below ensures they cannot
        // displace any paying tx, which is what makes the bypass safe.
        if priority == MempoolPriority::Standard && fee_per_byte < self.min_fee_per_byte {
            return Err("Fee per byte below minimum policy".to_string());
        }
        // Absolute per-tx fee floor. Symmetric with the per-byte check
        // above: Standard priority enforces, ZeroFeeAllowed bypasses.
        if priority == MempoolPriority::Standard && fee < self.min_total_fee {
            return Err("Fee below minimum total policy".to_string());
        }

        let mut evicted = None;
        if self.entries.len() >= self.max_entries {
            match self.pick_eviction_target(priority, fee_per_byte) {
                Some(t) => evicted = Some(t),
                None => return Err("Mempool full and fee/priority too low".to_string()),
            }
        }
        if let Some(e) = evicted {
            self.entries.remove(&e);
        }

        let entry = MempoolEntry {
            tx,
            raw,
            fee,
            size,
            fee_per_byte,
            added: now_secs(),
            relays: Vec::new(),
            relay_addresses: Vec::new(),
            priority,
        };
        self.entries.insert(txid, entry);
        self.persist()?;

        // Record the rate-limit clock only after a successful admission
        // so a failed insert doesn't lock the IP out for the next 600s.
        if priority == MempoolPriority::ZeroFeeAllowed {
            if let Some(ip) = peer_ip {
                if !ip.is_loopback() {
                    self.header_relay_last_seen.insert(ip, SystemTime::now());
                }
            }
        }

        Ok(AddOutcome { txid, evicted })
    }

    /// Pick the entry to evict. Lexicographic comparison on
    /// (priority rank, fee_per_byte). A `Standard` tx (rank 1) always
    /// outranks a `ZeroFeeAllowed` tx (rank 0) regardless of fpb — that
    /// is the buyer-side exemption's structural guarantee. Within the
    /// same class, lower fpb evicts first. Strict-greater comparison
    /// — ties keep the older entry.
    fn pick_eviction_target(
        &self,
        incoming_priority: MempoolPriority,
        incoming_fpb: f64,
    ) -> Option<[u8; 32]> {
        let (lowest_txid, lowest_entry) = self
            .entries
            .iter()
            .min_by(|(_, a), (_, b)| {
                a.priority
                    .rank()
                    .cmp(&b.priority.rank())
                    .then(a.fee_per_byte.total_cmp(&b.fee_per_byte))
            })?;
        let incoming_rank = incoming_priority.rank();
        let lowest_rank = lowest_entry.priority.rank();
        if incoming_rank > lowest_rank
            || (incoming_rank == lowest_rank && incoming_fpb > lowest_entry.fee_per_byte)
        {
            Some(*lowest_txid)
        } else {
            None
        }
    }

    fn gc_header_relay_rate_table(&mut self, now: SystemTime) {
        let interval = Duration::from_secs(HEADER_RELAY_PER_IP_INTERVAL_SECS);
        self.header_relay_last_seen.retain(|_, t| {
            now.duration_since(*t).map(|d| d < interval).unwrap_or(false)
        });
    }

    pub fn record_relay(&mut self, txid: &[u8; 32], peer: String) {
        if let Some(entry) = self.entries.get_mut(txid) {
            if !entry.relays.contains(&peer) {
                entry.relays.push(peer);
                let _ = self.persist();
            }
        }
    }

    pub fn record_relay_address(&mut self, txid: &[u8; 32], address: String) {
        if let Some(entry) = self.entries.get_mut(txid) {
            if !entry.relay_addresses.contains(&address) {
                entry.relay_addresses.push(address);
                let _ = self.persist();
            }
        }
    }

    pub fn remove(&mut self, txid: &[u8; 32]) -> bool {
        let removed = self.entries.remove(txid).is_some();
        if removed {
            let _ = self.persist();
        }
        removed
    }

    pub fn contains(&self, txid: &[u8; 32]) -> bool {
        self.entries.contains_key(txid)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn min_fee_per_byte(&self) -> f64 {
        self.min_fee_per_byte
    }

    pub fn min_total_fee(&self) -> u64 {
        self.min_total_fee
    }

    pub fn ordered_transactions(&self) -> Vec<Transaction> {
        let mut vec: Vec<&MempoolEntry> = self.entries.values().collect();
        vec.sort_by(|a, b| {
            b.fee_per_byte
                .partial_cmp(&a.fee_per_byte)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        vec.into_iter().map(|e| e.tx.clone()).collect()
    }

    pub fn ordered_entries(&self) -> Vec<MempoolEntry> {
        let mut vec: Vec<MempoolEntry> = self.entries.values().cloned().collect();
        vec.sort_by(|a, b| {
            b.fee_per_byte
                .partial_cmp(&a.fee_per_byte)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        vec
    }

    pub fn txids_hex(&self) -> Vec<String> {
        self.entries.keys().map(hex::encode).collect()
    }

    pub fn raw_tx(&self, txid: &[u8; 32]) -> Option<Vec<u8>> {
        self.entries.get(txid).map(|e| e.raw.clone())
    }

    /// Get a borrowed reference to the full mempool entry for a given txid.
    /// Used by /rpc/tx's mempool fallback (Fix C) so the wallet can
    /// distinguish "in mempool waiting" from "rejected / lost" — prior to
    /// this, /rpc/tx only checked the on-chain Vec and returned 404 for
    /// every pending tx, which produced the ghost-tx misdiagnosis.
    pub fn entry(&self, txid: &[u8; 32]) -> Option<&MempoolEntry> {
        self.entries.get(txid)
    }

    /// Find an existing mempool entry that already claims `outpoint`
    /// (prev_txid, prev_index) as one of its inputs. Returns the
    /// conflicting tx's txid if any. Used by submit_tx (Fix B) to
    /// surface input-conflict at submission time instead of silently
    /// admitting both and letting get_block_template's conflict-removal
    /// retain loop drop the later submission. Linear scan because
    /// indexing every outpoint would double the mempool's memory cost
    /// for a check that fires once per inbound tx — N is small (max
    /// `max_entries`) and the wins from O(1) lookup don't pay back.
    pub fn find_conflicting(&self, outpoint: &([u8; 32], u32)) -> Option<[u8; 32]> {
        for (txid, entry) in &self.entries {
            for input in &entry.tx.inputs {
                if (input.prev_txid, input.prev_index) == *outpoint {
                    return Some(*txid);
                }
            }
        }
        None
    }

    /// Iterate all entries (read-only borrow). Used by
    /// /rpc/mempool/spent_by (Fix D) to enumerate every outpoint
    /// currently pending-spent by some mempool entry, so the wallet
    /// can subtract those from /rpc/utxos before coin selection
    /// (Fix A) and avoid re-selecting an outpoint that's already
    /// committed to an unconfirmed tx.
    pub fn iter_entries(&self) -> impl Iterator<Item = (&[u8; 32], &MempoolEntry)> {
        self.entries.iter()
    }

    pub fn relays_for(&self, txid: &[u8; 32]) -> Vec<String> {
        self.entries
            .get(txid)
            .map(|e| e.relays.clone())
            .unwrap_or_default()
    }

    pub fn relay_addresses_for(&self, txid: &[u8; 32]) -> Vec<String> {
        self.entries
            .get(txid)
            .map(|e| e.relay_addresses.clone())
            .unwrap_or_default()
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// After a block has been connected, drop any mempool transactions that no
/// longer validate against the chain (e.g. their inputs were spent by the
/// new block — a double-spend conflict — or their signatures became invalid
/// after a reorg). Returns the number of evictions.
///
/// The caller must already hold the chain lock so the validation result
/// reflects the post-block UTXO set. Mempool eviction is recorded to
/// `pending.json` via `remove`'s persist hook.
pub fn evict_invalid_mempool_entries(
    chain: &ChainState,
    mempool: &mut MempoolManager,
) -> usize {
    let candidates = mempool.ordered_transactions();
    let mut evicted = 0;
    for tx in &candidates {
        if let Err(reason) = chain.validate_transaction(tx) {
            let txid = tx.txid();
            if mempool.remove(&txid) {
                evicted += 1;
                eprintln!(
                    "[mempool] evicted {} after block connect: {}",
                    hex::encode(txid),
                    reason
                );
            }
        }
    }
    evicted
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn tmp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "mempool_test_{}_{}_{}",
            name,
            std::process::id(),
            now_secs()
        ));
        p
    }

    fn dummy_tx(value: u64) -> Transaction {
        let input = crate::tx::TxInput {
            prev_txid: [1u8; 32],
            prev_index: 0,
            script_sig: vec![0u8; 1],
            sequence: 0xffff_fffe,
        };
        let output = crate::tx::TxOutput {
            value,
            script_pubkey: vec![0u8],
        };
        Transaction {
            version: 1,
            inputs: vec![input],
            outputs: vec![output],
            locktime: 0,
        }
    }

    /// Make a dummy tx whose first-input prev_txid is `tag` so the txid
    /// differs between calls in the same test (avoids "already in
    /// mempool" duplicate-detection collisions).
    fn dummy_tx_tagged(tag: u8, value: u64) -> Transaction {
        let input = crate::tx::TxInput {
            prev_txid: [tag; 32],
            prev_index: 0,
            script_sig: vec![tag],
            sequence: 0xffff_fffe,
        };
        let output = crate::tx::TxOutput {
            value,
            script_pubkey: vec![0u8],
        };
        Transaction {
            version: 1,
            inputs: vec![input],
            outputs: vec![output],
            locktime: 0,
        }
    }

    #[test]
    fn adds_and_evicts_by_fee() {
        let path = tmp_path("evict");
        let mut mgr = MempoolManager::new(path.clone(), 1, 0.0, 0);

        let tx_low = dummy_tx(10);
        let raw_low = tx_low.serialize();
        let _ = mgr.add_transaction(tx_low.clone(), raw_low, 1).unwrap();
        assert_eq!(mgr.len(), 1);

        let tx_high = dummy_tx(20);
        let raw_high = tx_high.serialize();
        let res = mgr.add_transaction(tx_high.clone(), raw_high, 100);
        assert!(res.is_ok());
        assert_eq!(mgr.len(), 1);
        assert!(mgr.contains(&tx_high.txid()));
        assert!(!mgr.contains(&tx_low.txid()));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn records_relay_and_address() {
        let path = tmp_path("relay");
        let mut mgr = MempoolManager::new(path.clone(), 10, 0.0, 0);
        let tx = dummy_tx(5);
        let raw = tx.serialize();
        let txid = tx.txid();
        mgr.add_transaction(tx.clone(), raw, 1).unwrap();
        mgr.record_relay(&txid, "peer1".to_string());
        mgr.record_relay_address(&txid, "aa".to_string());

        let entry = mgr.entries.get(&txid).unwrap();
        assert!(entry.relays.contains(&"peer1".to_string()));
        assert!(entry.relay_addresses.contains(&"aa".to_string()));

        let _ = std::fs::remove_file(path);
    }

    /// ZeroFeeAllowed must be admitted with fee=0 even under the
    /// production min_fee_per_byte=1.0 policy. This is the BTC-buyer
    /// path's structural requirement.
    #[test]
    fn zero_fee_admitted_when_priority_is_zero_fee_allowed() {
        let path = tmp_path("zfa_admit");
        let mut mgr = MempoolManager::new(path.clone(), 10, 1.0, 0);
        let tx = dummy_tx_tagged(0xaa, 100);
        let raw = tx.serialize();

        let res = mgr.add_transaction_with_priority(
            tx.clone(),
            raw,
            0,
            MempoolPriority::ZeroFeeAllowed,
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))),
        );
        assert!(res.is_ok(), "zero-fee zfa should be admitted: {:?}", res);
        assert_eq!(mgr.len(), 1);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn standard_still_rejected_below_min_fee() {
        let path = tmp_path("std_min");
        let mut mgr = MempoolManager::new(path.clone(), 10, 1.0, 0);
        let tx = dummy_tx_tagged(0xbb, 100);
        let raw = tx.serialize();
        let res = mgr.add_transaction(tx.clone(), raw, 1);
        assert!(res.is_err(), "underpaid standard tx must reject");

        let _ = std::fs::remove_file(path);
    }

    /// Capacity full of Standard txs. A new ZeroFeeAllowed cannot
    /// displace any of them — the buyer-side exemption can never push
    /// out a paying tx.
    #[test]
    fn zero_fee_cannot_evict_standard_when_full() {
        let path = tmp_path("zfa_no_evict");
        let mut mgr = MempoolManager::new(path.clone(), 1, 0.0, 0);

        let std_tx = dummy_tx_tagged(0x10, 100);
        let std_raw = std_tx.serialize();
        mgr.add_transaction(std_tx.clone(), std_raw, 50).unwrap();
        assert_eq!(mgr.len(), 1);

        let zfa_tx = dummy_tx_tagged(0x11, 200);
        let zfa_raw = zfa_tx.serialize();
        let res = mgr.add_transaction_with_priority(
            zfa_tx.clone(),
            zfa_raw,
            0,
            MempoolPriority::ZeroFeeAllowed,
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 6))),
        );
        assert!(res.is_err(), "zfa must not displace standard: {:?}", res);
        assert!(mgr.contains(&std_tx.txid()));
        assert!(!mgr.contains(&zfa_tx.txid()));

        let _ = std::fs::remove_file(path);
    }

    /// Capacity full of ZeroFeeAllowed txs. An incoming Standard tx of
    /// ANY positive fee evicts the lowest-priority entry — that's how
    /// the user-facing fee floor stays load-bearing.
    #[test]
    fn standard_evicts_zero_fee_regardless_of_fee() {
        let path = tmp_path("std_evicts_zfa");
        let mut mgr = MempoolManager::new(path.clone(), 1, 0.0, 0);

        let zfa_tx = dummy_tx_tagged(0x20, 100);
        let zfa_raw = zfa_tx.serialize();
        mgr.add_transaction_with_priority(
            zfa_tx.clone(),
            zfa_raw,
            0,
            MempoolPriority::ZeroFeeAllowed,
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
        )
        .unwrap();

        let std_tx = dummy_tx_tagged(0x21, 100);
        let std_raw = std_tx.serialize();
        let res = mgr.add_transaction(std_tx.clone(), std_raw, 50);
        assert!(res.is_ok(), "standard must evict zfa: {:?}", res);
        let outcome = res.unwrap();
        assert_eq!(outcome.evicted, Some(zfa_tx.txid()));
        assert!(mgr.contains(&std_tx.txid()));
        assert!(!mgr.contains(&zfa_tx.txid()));

        let _ = std::fs::remove_file(path);
    }

    /// Two consecutive ZeroFeeAllowed admissions from the SAME non-loopback
    /// IP within the 600s window: the second must be rate-limited.
    /// A different IP succeeds; a loopback IP succeeds even back-to-back.
    #[test]
    fn rate_limit_per_ip_with_loopback_exempt() {
        let path = tmp_path("rate_limit");
        let mut mgr = MempoolManager::new(path.clone(), 100, 1.0, 0);

        let peer_a = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
        let peer_b = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 11));
        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);

        // First admission from peer_a succeeds.
        let tx1 = dummy_tx_tagged(0x30, 1);
        let raw1 = tx1.serialize();
        mgr.add_transaction_with_priority(
            tx1.clone(),
            raw1,
            0,
            MempoolPriority::ZeroFeeAllowed,
            Some(peer_a),
        )
        .unwrap();

        // Second admission from peer_a within window -> rate-limited.
        let tx2 = dummy_tx_tagged(0x31, 1);
        let raw2 = tx2.serialize();
        let res2 = mgr.add_transaction_with_priority(
            tx2.clone(),
            raw2,
            0,
            MempoolPriority::ZeroFeeAllowed,
            Some(peer_a),
        );
        assert!(res2.is_err(), "second zfa from same IP must be rate-limited");
        assert!(res2
            .as_ref()
            .err()
            .map(|e| e.contains("header_relay_rate_limit_per_ip"))
            .unwrap_or(false));

        // Different IP succeeds.
        let tx3 = dummy_tx_tagged(0x32, 1);
        let raw3 = tx3.serialize();
        let res3 = mgr.add_transaction_with_priority(
            tx3.clone(),
            raw3,
            0,
            MempoolPriority::ZeroFeeAllowed,
            Some(peer_b),
        );
        assert!(res3.is_ok(), "different IP must succeed: {:?}", res3);

        // Loopback exempted from rate limit even back-to-back.
        let tx4 = dummy_tx_tagged(0x40, 1);
        let raw4 = tx4.serialize();
        mgr.add_transaction_with_priority(
            tx4.clone(),
            raw4,
            0,
            MempoolPriority::ZeroFeeAllowed,
            Some(loopback),
        )
        .unwrap();
        let tx5 = dummy_tx_tagged(0x41, 1);
        let raw5 = tx5.serialize();
        let res5 = mgr.add_transaction_with_priority(
            tx5.clone(),
            raw5,
            0,
            MempoolPriority::ZeroFeeAllowed,
            Some(loopback),
        );
        assert!(res5.is_ok(), "loopback must not be rate-limited: {:?}", res5);

        let _ = std::fs::remove_file(path);
    }
}
