//! Phase 18B step-2: non-custodial one-time PoAW-X delegation registration.
//!
//! This module is a STRATUM-LOCAL mirror of the consensus `Delegation` wire
//! format (defined in `irium_node_rs::poawx`). The stratum intentionally does
//! NOT depend on the full node crate in production (see `block.rs`, which
//! likewise mirrors the receipt-root algorithm); `irium-node-rs` is a
//! dev-dependency used only by the parity tests in this file, which assert the
//! mirror stays byte-identical to the canonical type. Any drift fails tests.
//!
//! The pool delegate key here is a signer-only identity: it signs delegated
//! receipt challenges (step 4). It is NEVER a payout identity and never appears
//! in a coinbase. The delegation registry stores public material only — no
//! private keys.
//!
//! Some items (e.g. `DelegateKey::secret`, `DelegationStore::all_active` /
//! `prune_expired`, `Delegation::digest`) are foundation consumed by the
//! step-4 receipt producer and are intentionally not yet called in production.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

/// Domain separator — MUST equal `irium_node_rs::poawx::DOMAIN_DELEG`.
pub const DELEG_DOMAIN: &[u8] = b"irium.poawx.delegation.v1";

// ── Stratum-local mirror of the consensus Delegation (226-byte wire) ─────────

#[derive(Debug, Clone, PartialEq)]
pub struct Delegation {
    pub deleg_version: u8,
    pub network_id: u8,
    pub miner_pubkey: [u8; 33],
    pub pool_pubkey: [u8; 33],
    pub worker_tag: [u8; 32],
    pub expiry_height: u64,
    pub fee_bps: u16,
    pub fee_pkh: [u8; 20],
    pub deleg_nonce: [u8; 32],
    /// v2 only: mirror of the consensus proposer key (see node `Delegation`).
    pub proposer_pubkey: [u8; 33],
    pub delegation_sig: [u8; 64],
}

impl Delegation {
    pub const VERSION: u8 = 2;
    pub const WIRE_SIZE_V1: usize = 1 + 1 + 33 + 33 + 32 + 8 + 2 + 20 + 32 + 64; // 226
    pub const WIRE_SIZE_V2: usize = Self::WIRE_SIZE_V1 + 33; // 259
    pub const WIRE_SIZE: usize = Self::WIRE_SIZE_V2; // "current" = v2

    pub fn wire_len(&self) -> usize {
        if self.deleg_version >= 2 {
            Self::WIRE_SIZE_V2
        } else {
            Self::WIRE_SIZE_V1
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::WIRE_SIZE);
        out.push(self.deleg_version);
        out.push(self.network_id);
        out.extend_from_slice(&self.miner_pubkey);
        out.extend_from_slice(&self.pool_pubkey);
        out.extend_from_slice(&self.worker_tag);
        out.extend_from_slice(&self.expiry_height.to_le_bytes());
        out.extend_from_slice(&self.fee_bps.to_le_bytes());
        out.extend_from_slice(&self.fee_pkh);
        out.extend_from_slice(&self.deleg_nonce);
        if self.deleg_version >= 2 {
            out.extend_from_slice(&self.proposer_pubkey);
        }
        out.extend_from_slice(&self.delegation_sig);
        out
    }

    pub fn deserialize(raw: &[u8]) -> Result<Self, String> {
        if raw.len() < Self::WIRE_SIZE_V1 {
            return Err(format!(
                "delegation too short: {} < {}",
                raw.len(),
                Self::WIRE_SIZE_V1
            ));
        }
        let mut off = 0usize;
        let deleg_version = raw[off];
        off += 1;
        let expected = if deleg_version >= 2 {
            Self::WIRE_SIZE_V2
        } else {
            Self::WIRE_SIZE_V1
        };
        if raw.len() < expected {
            return Err(format!(
                "delegation too short: {} < {} (v{})",
                raw.len(),
                expected,
                deleg_version
            ));
        }
        let network_id = raw[off];
        off += 1;
        let mut miner_pubkey = [0u8; 33];
        miner_pubkey.copy_from_slice(&raw[off..off + 33]);
        off += 33;
        let mut pool_pubkey = [0u8; 33];
        pool_pubkey.copy_from_slice(&raw[off..off + 33]);
        off += 33;
        let mut worker_tag = [0u8; 32];
        worker_tag.copy_from_slice(&raw[off..off + 32]);
        off += 32;
        let expiry_height =
            u64::from_le_bytes(raw[off..off + 8].try_into().expect("slice len checked"));
        off += 8;
        let fee_bps = u16::from_le_bytes(raw[off..off + 2].try_into().expect("slice len checked"));
        off += 2;
        let mut fee_pkh = [0u8; 20];
        fee_pkh.copy_from_slice(&raw[off..off + 20]);
        off += 20;
        let mut deleg_nonce = [0u8; 32];
        deleg_nonce.copy_from_slice(&raw[off..off + 32]);
        off += 32;
        let mut proposer_pubkey = [0u8; 33];
        if deleg_version >= 2 {
            proposer_pubkey.copy_from_slice(&raw[off..off + 33]);
            off += 33;
        }
        let mut delegation_sig = [0u8; 64];
        delegation_sig.copy_from_slice(&raw[off..off + 64]);
        Ok(Self {
            deleg_version,
            network_id,
            miner_pubkey,
            pool_pubkey,
            worker_tag,
            expiry_height,
            fee_bps,
            fee_pkh,
            deleg_nonce,
            proposer_pubkey,
            delegation_sig,
        })
    }

    /// SHA256 over the domain + all fields EXCEPT the signature.
    pub fn message_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(DELEG_DOMAIN);
        h.update([self.deleg_version]);
        h.update([self.network_id]);
        h.update(self.miner_pubkey);
        h.update(self.pool_pubkey);
        h.update(self.worker_tag);
        h.update(self.expiry_height.to_le_bytes());
        h.update(self.fee_bps.to_le_bytes());
        h.update(self.fee_pkh);
        h.update(self.deleg_nonce);
        if self.deleg_version >= 2 {
            h.update(self.proposer_pubkey);
        }
        h.finalize().into()
    }

    /// SHA256 over the full 226-byte serialization (including the signature).
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.serialize());
        h.finalize().into()
    }

    /// HASH160(miner_pubkey) — the miner pkh / payout identity.
    pub fn miner_pkh(&self) -> [u8; 20] {
        let sha = Sha256::digest(self.miner_pubkey);
        let rip = ripemd::Ripemd160::digest(sha);
        let mut pkh = [0u8; 20];
        pkh.copy_from_slice(&rip);
        pkh
    }

    /// Verify the miner's delegation signature over `message_hash()`.
    pub fn verify_signature(&self) -> Result<(), &'static str> {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        use k256::ecdsa::{Signature, VerifyingKey};
        let vk = VerifyingKey::from_sec1_bytes(&self.miner_pubkey)
            .map_err(|_| "delegation: invalid miner_pubkey")?;
        let sig = Signature::from_slice(&self.delegation_sig)
            .map_err(|_| "delegation: malformed delegation_sig")?;
        vk.verify_prehash(&self.message_hash(), &sig)
            .map_err(|_| "delegation: signature verification failed")
    }
}

/// worker_tag = SHA256(worker) for a named worker, or all-zero when unscoped.
pub fn worker_tag(worker: &str) -> [u8; 32] {
    if worker.is_empty() {
        return [0u8; 32];
    }
    let mut h = Sha256::new();
    h.update(worker.as_bytes());
    h.finalize().into()
}

/// network_id mirror of `irium_node_rs::activation::NetworkKind::id_byte`:
/// Mainnet=0, Testnet=1, Devnet=2. Read from `IRIUM_NETWORK`.
pub fn network_id_from_env() -> u8 {
    match env::var("IRIUM_NETWORK")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "testnet" => 1,
        "devnet" | "regtest" | "trial" => 2,
        _ => 0, // mainnet / unset
    }
}

// ── Pool delegate key (signer-only; NOT a payout identity) ───────────────────

pub struct DelegateKey {
    secret: [u8; 32],
    pubkey: [u8; 33],
}

impl DelegateKey {
    /// Load the delegate key from `path`, or generate one if absent and
    /// `allow_generate` is true. Generation is only permitted in non-mainnet
    /// contexts (caller passes `allow_generate=false` on mainnet). The private
    /// key is written with 0600 permissions where supported and never logged.
    pub fn load_or_generate(path: &Path, allow_generate: bool) -> Result<Self, String> {
        if path.exists() {
            let hex_str = std::fs::read_to_string(path)
                .map_err(|e| format!("read delegate key {}: {e}", path.display()))?;
            let bytes = hex::decode(hex_str.trim())
                .map_err(|_| "delegate key file: invalid hex".to_string())?;
            if bytes.len() != 32 {
                return Err("delegate key file: expected 32 bytes".to_string());
            }
            let mut secret = [0u8; 32];
            secret.copy_from_slice(&bytes);
            let pubkey = pubkey_from_secret(&secret)?;
            Ok(Self { secret, pubkey })
        } else {
            if !allow_generate {
                return Err("delegate key missing and generation not allowed".to_string());
            }
            let secret = random_valid_secret()?;
            let pubkey = pubkey_from_secret(&secret)?;
            write_secret_file(path, &secret)?;
            Ok(Self { secret, pubkey })
        }
    }

    pub fn pubkey(&self) -> [u8; 33] {
        self.pubkey
    }
    pub fn pubkey_hex(&self) -> String {
        hex::encode(self.pubkey)
    }
    /// Signer-only secret, used to sign delegated receipt challenges in step 4.
    /// Never serialized into the delegation registry, never logged.
    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    /// Sign the per-height receipt challenge `SHA256(solution‖commitment_nonce‖
    /// height_le8)` with the delegate key. This is the signer signature embedded
    /// in a mode-1 receipt (`worker_sig`); the consensus verifies it against the
    /// delegate pubkey, which the miner authorized via the delegation.
    pub fn sign_challenge(
        &self,
        solution: &[u8],
        commitment_nonce: &[u8; 32],
        height: u64,
    ) -> [u8; 64] {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        use k256::ecdsa::{Signature, SigningKey};
        let sk = SigningKey::from_slice(&self.secret).expect("delegate secret validated at load");
        let challenge: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(solution);
            h.update(commitment_nonce);
            h.update(height.to_le_bytes());
            h.finalize().into()
        };
        let sig: Signature = sk.sign_prehash(&challenge).expect("sign challenge");
        let mut out = [0u8; 64];
        out.copy_from_slice(&sig.to_bytes());
        out
    }
}

fn pubkey_from_secret(secret: &[u8; 32]) -> Result<[u8; 33], String> {
    use k256::ecdsa::{SigningKey, VerifyingKey};
    let sk = SigningKey::from_slice(secret).map_err(|e| format!("invalid delegate secret: {e}"))?;
    let vk = VerifyingKey::from(&sk);
    let enc = vk.to_encoded_point(true);
    let mut pk = [0u8; 33];
    pk.copy_from_slice(enc.as_bytes());
    Ok(pk)
}

fn random_valid_secret() -> Result<[u8; 32], String> {
    use k256::ecdsa::SigningKey;
    use rand_core::{OsRng, RngCore};
    for _ in 0..64 {
        let mut b = [0u8; 32];
        OsRng.fill_bytes(&mut b);
        if SigningKey::from_slice(&b).is_ok() {
            return Ok(b);
        }
    }
    Err("failed to generate a valid delegate secret".to_string())
}

fn write_secret_file(path: &Path, secret: &[u8; 32]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create dir {}: {e}", parent.display()))?;
    }
    std::fs::write(path, hex::encode(secret))
        .map_err(|e| format!("write delegate key {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

// ── Delegation registry (no private keys) ────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StoredDelegation {
    /// Canonical 226-byte `Delegation::serialize()` hex — public material only.
    pub delegation_hex: String,
    pub miner_pkh: String,
    pub worker: String,
    pub network_id: u8,
    pub expiry_height: u64,
    pub fee_bps: u16,
    /// Phase 20 Step 4: hex of the third-party `fee_pkh` when `fee_bps > 0`; empty
    /// for OFFICIAL fee-0. `#[serde(default)]` keeps official records unchanged and
    /// backward-compatible on reload.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fee_pkh: String,
    pub status: String,
    pub received_at_unix: u64,
}

pub fn deleg_key(miner_pkh_hex: &str, worker: &str) -> String {
    format!("{}.{}", miner_pkh_hex, worker)
}

pub trait DelegationStore: Send + Sync {
    fn get(&self, miner_pkh_hex: &str, worker: &str) -> Option<StoredDelegation>;
    fn put(&self, rec: StoredDelegation) -> Result<(), String>;
    fn all_active(&self, tip_height: u64) -> Vec<StoredDelegation>;
    fn prune_expired(&self, tip_height: u64) -> usize;
}

#[derive(Serialize, Deserialize, Default)]
struct DelegFile {
    version: u32,
    delegations: BTreeMap<String, StoredDelegation>,
}

pub struct JsonDelegationStore {
    path: PathBuf,
    inner: Mutex<BTreeMap<String, StoredDelegation>>,
}

impl JsonDelegationStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, String> {
        let path = path.into();
        let map = if path.exists() {
            let raw = std::fs::read_to_string(&path)
                .map_err(|e| format!("read delegations {}: {e}", path.display()))?;
            let file: DelegFile = serde_json::from_str(&raw).unwrap_or_default();
            file.delegations
        } else {
            BTreeMap::new()
        };
        Ok(Self {
            path,
            inner: Mutex::new(map),
        })
    }

    fn flush(&self, map: &BTreeMap<String, StoredDelegation>) -> Result<(), String> {
        let file = DelegFile {
            version: 1,
            delegations: map.clone(),
        };
        let json = serde_json::to_string_pretty(&file)
            .map_err(|e| format!("serialize delegations: {e}"))?;
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, json).map_err(|e| format!("write delegations tmp: {e}"))?;
        std::fs::rename(&tmp, &self.path).map_err(|e| format!("rename delegations: {e}"))?;
        Ok(())
    }
}

impl DelegationStore for JsonDelegationStore {
    fn get(&self, miner_pkh_hex: &str, worker: &str) -> Option<StoredDelegation> {
        let map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        map.get(&deleg_key(miner_pkh_hex, worker)).cloned()
    }

    fn put(&self, rec: StoredDelegation) -> Result<(), String> {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        map.insert(deleg_key(&rec.miner_pkh, &rec.worker), rec);
        self.flush(&map)
    }

    fn all_active(&self, tip_height: u64) -> Vec<StoredDelegation> {
        let map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        map.values()
            .filter(|r| r.status == "active" && r.expiry_height > tip_height)
            .cloned()
            .collect()
    }

    fn prune_expired(&self, tip_height: u64) -> usize {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let before = map.len();
        map.retain(|_, r| r.expiry_height > tip_height);
        let removed = before - map.len();
        if removed > 0 {
            let _ = self.flush(&map);
        }
        removed
    }
}

// ── Pool-identity + verify-and-store core (pure, unit-tested) ─────────────────

/// Pool identity JSON. `fee` is the pool's configured third-party fee terms, or
/// None for OFFICIAL fee-0. Official advertises `fee_bps:0` and no `fee_pkh`
/// (byte-identical to before). Third-party advertises the exact `fee_bps` +
/// `fee_pkh` the miner must sign into the delegation.
pub fn pool_identity_json(
    pool_pubkey_hex: &str,
    network_id: u8,
    fee: Option<(u16, [u8; 20])>,
) -> serde_json::Value {
    let mut v = serde_json::json!({
        "pool_pubkey": pool_pubkey_hex,
        "network_id": network_id,
        "fee_bps": fee.map(|(b, _)| b).unwrap_or(0),
        "deleg_version": Delegation::VERSION,
        "domain": String::from_utf8_lossy(DELEG_DOMAIN),
    });
    if let Some((bps, pkh)) = fee {
        if bps > 0 {
            v["fee_pkh"] = serde_json::Value::String(hex::encode(pkh));
        }
    }
    v
}

#[derive(Debug, PartialEq)]
pub enum DelegError {
    Mainnet,
    BadHex,
    BadFormat,
    BadSignature,
    MinerPkhMismatch,
    WorkerTagMismatch,
    NetworkMismatch,
    PoolPubkeyMismatch,
    NonZeroFee,
    /// Third-party mode: delegation fee terms do not match the pool's configured
    /// terms (fee_bps mismatch, over cap, or config invalid).
    FeeMismatch,
    /// Third-party mode: delegation fee_pkh does not match the pool's fee_pkh.
    FeePkhMismatch,
    Expired,
    Storage(String),
}

impl DelegError {
    pub fn http_status(&self) -> (u16, &'static str) {
        match self {
            DelegError::Mainnet => (503, "Service Unavailable"),
            DelegError::Expired => (409, "Conflict"),
            DelegError::Storage(_) => (500, "Internal Server Error"),
            _ => (400, "Bad Request"),
        }
    }
    pub fn reason(&self) -> String {
        match self {
            DelegError::Mainnet => "delegation registration unavailable on mainnet".into(),
            DelegError::BadHex => "delegation: invalid hex".into(),
            DelegError::BadFormat => "delegation: malformed wire format".into(),
            DelegError::BadSignature => "delegation: signature verification failed".into(),
            DelegError::MinerPkhMismatch => {
                "delegation: miner_pkh does not match miner_pubkey".into()
            }
            DelegError::WorkerTagMismatch => "delegation: worker_tag does not match worker".into(),
            DelegError::NetworkMismatch => "delegation: network_id mismatch".into(),
            DelegError::PoolPubkeyMismatch => "delegation: pool_pubkey is not this pool".into(),
            DelegError::NonZeroFee => "delegation: fee_bps must be 0 (official pool is 0%)".into(),
            DelegError::FeeMismatch => {
                "delegation: fee_bps does not match pool third-party fee terms".into()
            }
            DelegError::FeePkhMismatch => {
                "delegation: fee_pkh does not match pool third-party fee terms".into()
            }
            DelegError::Expired => "delegation: expiry_height must be in the future".into(),
            DelegError::Storage(e) => format!("delegation: storage error: {e}"),
        }
    }
}

/// Verify a submitted delegation and persist it. Pure (tip + now passed in) so
/// it is fully unit-testable without HTTP or RPC.
#[allow(clippy::too_many_arguments)]
pub fn verify_and_store(
    store: &dyn DelegationStore,
    delegation_hex: &str,
    worker: &str,
    expected_miner_pkh_hex: &str,
    pool_pubkey: &[u8; 33],
    network_id: u8,
    tip_height: u64,
    now_unix: u64,
    expected_fee: Option<(u16, [u8; 20])>,
) -> Result<StoredDelegation, DelegError> {
    if network_id == 0 {
        return Err(DelegError::Mainnet);
    }
    let bytes = hex::decode(delegation_hex).map_err(|_| DelegError::BadHex)?;
    let d = Delegation::deserialize(&bytes).map_err(|_| DelegError::BadFormat)?;

    if d.network_id != network_id {
        return Err(DelegError::NetworkMismatch);
    }
    if &d.pool_pubkey != pool_pubkey {
        return Err(DelegError::PoolPubkeyMismatch);
    }
    // Fee policy. OFFICIAL (expected_fee None): fee_bps MUST be 0 and fee_pkh zero.
    // THIRD-PARTY (Some): the signed delegation's fee terms MUST equal the pool's
    // configured terms (cap-checked). The signature covers fee_bps + fee_pkh, so a
    // post-signing mutation is caught below as BadSignature.
    match expected_fee {
        None => {
            if d.fee_bps != 0 {
                return Err(DelegError::NonZeroFee);
            }
            if d.fee_pkh != [0u8; 20] {
                return Err(DelegError::NonZeroFee);
            }
        }
        Some((efb, efp)) => {
            if efb == 0 || efb > THIRD_PARTY_FEE_CAP_BPS || efp == [0u8; 20] {
                // Pool config invalid -> never accept a fee.
                return Err(DelegError::FeeMismatch);
            }
            if d.fee_bps != efb {
                return Err(DelegError::FeeMismatch);
            }
            if d.fee_pkh != efp {
                return Err(DelegError::FeePkhMismatch);
            }
        }
    }
    if d.worker_tag != worker_tag(worker) {
        return Err(DelegError::WorkerTagMismatch);
    }
    d.verify_signature().map_err(|_| DelegError::BadSignature)?;

    let miner_pkh = d.miner_pkh();
    let miner_pkh_hex = hex::encode(miner_pkh);
    if !expected_miner_pkh_hex.is_empty()
        && expected_miner_pkh_hex.to_ascii_lowercase() != miner_pkh_hex
    {
        return Err(DelegError::MinerPkhMismatch);
    }
    if d.expiry_height <= tip_height {
        return Err(DelegError::Expired);
    }

    let rec = StoredDelegation {
        delegation_hex: delegation_hex.to_ascii_lowercase(),
        miner_pkh: miner_pkh_hex,
        worker: worker.to_string(),
        network_id: d.network_id,
        expiry_height: d.expiry_height,
        fee_bps: d.fee_bps,
        fee_pkh: if d.fee_bps > 0 {
            hex::encode(d.fee_pkh)
        } else {
            String::new()
        },
        status: "active".to_string(),
        received_at_unix: now_unix,
    };
    store.put(rec.clone()).map_err(DelegError::Storage)?;
    Ok(rec)
}

// ── Mode-1 receipt production (pure; pool-side) ──────────────────────────────

/// Expected CPU lane first byte (assignment lane is "cpu").
pub const EXPECTED_LANE_FIRST: u8 = b'c';

/// Decoded, validated per-block assignment context the pool uses to produce a
/// mode-1 receipt for `block_height` (= tip + 1).
#[derive(Debug, Clone)]
pub struct AssignmentContext {
    pub block_height: u64,
    pub seed: [u8; 32],
    pub commitment_nonce: [u8; 32],
    pub difficulty: u32,
    pub lane: String,
}

fn decode33(s: &str) -> Option<[u8; 33]> {
    let b = hex::decode(s.trim()).ok()?;
    if b.len() != 33 {
        return None;
    }
    let mut o = [0u8; 33];
    o.copy_from_slice(&b);
    Some(o)
}
fn decode32(s: &str) -> Option<[u8; 32]> {
    let b = hex::decode(s).ok()?;
    if b.len() != 32 {
        return None;
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&b);
    Some(a)
}

/// Convert the node assignment DTO into an `AssignmentContext` for `job_height`,
/// applying the fail-closed checks: the assignment must be for the tip the job
/// builds on (`assignment.height + 1 == job_height`) and the CPU lane.
pub fn assignment_context_from_dto(
    dto: &crate::template::PoawxAssignment,
    job_height: u64,
) -> Option<AssignmentContext> {
    if dto.height.checked_add(1) != Some(job_height) {
        return None; // assignment not for this job's parent tip
    }
    let lane_first = dto.lane.bytes().next()?;
    if lane_first != EXPECTED_LANE_FIRST {
        return None; // unexpected lane
    }
    Some(AssignmentContext {
        block_height: job_height,
        seed: decode32(&dto.seed)?,
        commitment_nonce: decode32(&dto.commitment_nonce)?,
        difficulty: dto.puzzle_difficulty,
        lane: dto.lane.clone(),
    })
}

fn count_leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut bits = 0u32;
    for &b in hash.iter() {
        let z = b.leading_zeros();
        bits += z;
        if z < 8 {
            break;
        }
    }
    bits
}

/// Grind an 8-byte solution so `sha256d(seed‖nonce‖solution)` has at least
/// `difficulty` leading zero bits. Bounded; returns None if not found (fail-closed).
fn grind_solution(seed: &[u8; 32], nonce: &[u8; 32], difficulty: u32) -> Option<[u8; 8]> {
    let mut input = [0u8; 72];
    input[..32].copy_from_slice(seed);
    input[32..64].copy_from_slice(nonce);
    for n in 0u64..50_000_000 {
        let sol = n.to_le_bytes();
        input[64..].copy_from_slice(&sol);
        let hash = crate::pow::sha256d(&input);
        if count_leading_zero_bits(&hash) >= difficulty {
            return Some(sol);
        }
    }
    None
}

/// Phase 18C: gated producer trace. Logs reason codes + short prefixes only;
/// never secrets/tokens/full delegation hex/full signatures.
pub fn producer_trace_enabled() -> bool {
    env::var("IRIUM_POAWX_PRODUCER_TRACE")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}

fn pfx(bytes: &[u8]) -> String {
    hex::encode(&bytes[..bytes.len().min(4)])
}

/// Produce a mode-1 (delegated) pending receipt for `miner_pkh`/`worker`, or
/// `None` if no valid delegation applies (fail-closed: missing/expired/wrong
/// network/non-zero fee/wrong pool key/wrong worker tag/grind failure). Pure:
/// the assignment is supplied by the caller (fetched from `/poawx/assignment`).
pub fn build_mode1_pending_receipt(
    store: &dyn DelegationStore,
    key: &DelegateKey,
    network_id: u8,
    miner_pkh: [u8; 20],
    worker: &str,
    ctx: &AssignmentContext,
) -> Option<crate::template::PoawxPendingReceipt> {
    let trace = producer_trace_enabled();
    let miner_pkh_hex = hex::encode(miner_pkh);
    macro_rules! deny {
        ($reason:expr) => {{
            if trace {
                info!(
                    "[poawx-trace] build_mode1 deny reason={} miner_pkh={} worker={} key={} net={} block_h={}",
                    $reason, pfx(&miner_pkh), worker, deleg_key(&miner_pkh_hex, worker), network_id, ctx.block_height
                );
            }
            return None;
        }};
    }
    let rec = match store.get(&miner_pkh_hex, worker) {
        Some(r) => r,
        None => deny!("delegation_missing"),
    };
    if trace {
        info!(
            "[poawx-trace] build_mode1 found rec net={} fee_bps={} expiry={}",
            rec.network_id, rec.fee_bps, rec.expiry_height
        );
    }
    if rec.network_id != network_id {
        deny!("rec_network_mismatch");
    }
    // Phase 20 Step 4: a nonzero fee is allowed only in explicit third-party mode
    // with the fee gate active (mainnet hard-off). The registry already verified
    // the fee terms match the pool config; the node re-validates authoritatively.
    let third_party_fee_ok =
        third_party_fee_active(ctx.block_height) && third_party_pool_mode_enabled();
    if rec.fee_bps != 0 && !third_party_fee_ok {
        deny!("rec_nonzero_fee");
    }
    if rec.expiry_height < ctx.block_height {
        deny!("expired");
    }
    let dbytes = match hex::decode(&rec.delegation_hex) {
        Ok(b) => b,
        Err(_) => deny!("delegation_hex_bad"),
    };
    let d = match Delegation::deserialize(&dbytes) {
        Ok(d) => d,
        Err(_) => deny!("delegation_decode_bad"),
    };
    if d.pool_pubkey != key.pubkey() {
        if trace {
            info!(
                "[poawx-trace] pool_pubkey mismatch deleg={} key={}",
                pfx(&d.pool_pubkey),
                pfx(&key.pubkey())
            );
        }
        deny!("pool_pubkey_mismatch");
    }
    if d.miner_pkh() != miner_pkh {
        deny!("miner_pkh_mismatch");
    }
    if d.network_id != network_id {
        deny!("deleg_network_mismatch");
    }
    if d.fee_bps != 0 && !third_party_fee_ok {
        deny!("deleg_nonzero_fee");
    }
    if d.fee_bps > THIRD_PARTY_FEE_CAP_BPS {
        deny!("deleg_fee_over_cap");
    }
    if d.worker_tag != worker_tag(worker) {
        deny!("worker_tag_mismatch");
    }
    let solution = match grind_solution(&ctx.seed, &ctx.commitment_nonce, ctx.difficulty) {
        Some(s) => s,
        None => deny!("grind_failed"),
    };
    let signer_sig = key.sign_challenge(&solution, &ctx.commitment_nonce, ctx.block_height);
    let receipt = crate::template::PoawxPendingReceipt {
        height: ctx.block_height,
        lane: ctx.lane.clone(),
        worker_pkh: miner_pkh_hex,
        solution: hex::encode(solution),
        commitment_nonce: hex::encode(ctx.commitment_nonce),
        worker_pubkey: key.pubkey_hex(),
        worker_sig: hex::encode(signer_sig),
        delegation: rec.delegation_hex.clone(),
        // Phase 20: base mode-1 receipt carries no extension here; the pool's
        // production path (stratum) attaches a synthetic Phase20ReceiptExt after
        // activation. Empty => legacy/pre-activation (byte-identical submit JSON).
        phase20_ext: String::new(),
    };
    if trace {
        info!(
            "[poawx-trace] build_mode1 OK block_h={} lane={} sol_grinded=true delegation_present=true",
            ctx.block_height, ctx.lane
        );
    }
    Some(receipt)
}

/// Fetch the node's `/poawx/assignment` (single source of truth for the
/// deterministic puzzle context). Returns None on any error (fail-closed).
pub async fn fetch_assignment(
    rpc_base: &str,
    rpc_token: &str,
) -> Option<crate::template::PoawxAssignment> {
    let client = reqwest::Client::builder().build().ok()?;
    let url = format!("{}/poawx/assignment", rpc_base.trim_end_matches('/'));
    let resp = client.get(&url).bearer_auth(rpc_token).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json::<crate::template::PoawxAssignment>().await.ok()
}

// ── Phase 20: production primitives (testnet/devnet mirror of node consensus) ─
//
// STRATUM-LOCAL mirror of the Phase 20 consensus primitives in
// `irium_node_rs::poawx` (multi-role reward split + fairness role claims +
// production receipt extension). Mirrored byte-for-byte; the parity tests below
// assert equality against the dev-dep node lib so any drift fails. Production
// here is OFFICIAL fee-0 only (fee_bps=0 / fee_pkh=0). Mainnet is hard-off.
// The role-claim *source* used by pool production is the gated SYNTHETIC builder
// (testnet/devnet-only, for production-wiring validation) — NOT a live
// hidden-precommit protocol (which remains pending; see design-gap docs).

pub const MULTI_ROLE_PRIMARY_BPS: u64 = 5500;
pub const MULTI_ROLE_COMPUTE_BPS: u64 = 2200;
pub const MULTI_ROLE_VERIFY_BPS: u64 = 1300;
pub const MULTI_ROLE_SUPPORT_BPS: u64 = 1000;

pub const ROLE_COMPUTE_CONTRIBUTOR: u8 = 1;
pub const ROLE_VERIFY_CONTRIBUTOR: u8 = 2;
pub const ROLE_SUPPORT_CONTRIBUTOR: u8 = 3;

pub const LANE_CPU_FRIENDLY: u8 = 0;
pub const LANE_GPU_PARALLEL: u8 = 1;
pub const LANE_ASIC_STREAMING: u8 = 2;

pub const FAIRNESS_DOMAIN_V1: &[u8] = b"IRIUM_POAWX_FAIRNESS_V1";
pub const ROLE_CLAIM_DOMAIN_V1: &[u8] = b"IRIUM_POAWX_ROLE_CLAIM_V1";
pub const FAIRNESS_CPU_UPPER: u32 = 3400;
pub const FAIRNESS_GPU_UPPER: u32 = 6700;
pub const PHASE20_EXT_VERSION: u8 = 1;
/// Mirror of `irium_node_rs::poawx::THIRD_PARTY_FEE_CAP_BPS` (2.00%).
pub const THIRD_PARTY_FEE_CAP_BPS: u16 = 200;

/// Mirror of `irium_node_rs::poawx::multi_role_amounts`: split `total` into
/// `[primary, compute, verify, support]` (floor; remainder → PRIMARY; exact sum).
pub fn multi_role_amounts(total: u64) -> [u64; 4] {
    let bps = |b: u64| -> u64 { ((total as u128 * b as u128) / 10_000u128) as u64 };
    let compute = bps(MULTI_ROLE_COMPUTE_BPS);
    let verify = bps(MULTI_ROLE_VERIFY_BPS);
    let support = bps(MULTI_ROLE_SUPPORT_BPS);
    let primary_floor = bps(MULTI_ROLE_PRIMARY_BPS);
    let remainder = total - primary_floor - compute - verify - support;
    [primary_floor + remainder, compute, verify, support]
}

/// Mirror of `irium_node_rs::poawx::apply_fee`: split a PRIMARY gross into
/// `(net, fee)` where `fee = floor(gross * fee_bps / 10000)` (miner keeps the
/// remainder). Only PRIMARY is fee-taxed; compute/verify/support are untouched.
pub fn apply_fee(gross: u64, fee_bps: u16) -> (u64, u64) {
    let fee = ((gross as u128 * fee_bps as u128) / 10_000u128) as u64;
    (gross - fee, fee)
}

/// Mirror of `irium_node_rs::chain::third_party_pool_mode_enabled`: explicit
/// third-party opt-in (`IRIUM_POAWX_THIRD_PARTY_POOL_MODE=1`). Mainnet hard-off.
pub fn third_party_pool_mode_enabled() -> bool {
    if network_id_from_env() == 0 {
        return false; // mainnet
    }
    env::var("IRIUM_POAWX_THIRD_PARTY_POOL_MODE")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}

/// Mirror of `irium_node_rs::chain::third_party_fee_active`: fee activation height
/// reached. Mainnet hard-off.
pub fn third_party_fee_active(height: u64) -> bool {
    if network_id_from_env() == 0 {
        return false; // mainnet
    }
    activation_height_reached("IRIUM_POAWX_THIRD_PARTY_FEE_ACTIVATION_HEIGHT", height)
}

/// The pool's configured third-party fee terms, or None for OFFICIAL fee-0.
/// `Some((fee_bps, fee_pkh))` ONLY when: not mainnet, explicit third-party mode is
/// enabled, `IRIUM_POAWX_THIRD_PARTY_FEE_BPS` is in 1..=200, and
/// `IRIUM_POAWX_THIRD_PARTY_FEE_PKH` is a valid non-zero 20-byte hex. Any invalid
/// or partial config fails closed to None (official 0%) with a warning — the pool
/// never advertises/charges an unvalidated fee. Used by both the pool identity and
/// (with the activation gate) the registry + production path.
pub fn pool_third_party_fee_terms() -> Option<(u16, [u8; 20])> {
    if !third_party_pool_mode_enabled() {
        return None;
    }
    let bps: u16 = match env::var("IRIUM_POAWX_THIRD_PARTY_FEE_BPS")
        .ok()
        .and_then(|v| v.trim().parse::<u16>().ok())
    {
        Some(b) if b >= 1 && b <= THIRD_PARTY_FEE_CAP_BPS => b,
        Some(b) => {
            warn!("[poawx-deleg] IRIUM_POAWX_THIRD_PARTY_FEE_BPS={b} out of range 1..=200; fee disabled (official 0%)");
            return None;
        }
        None => return None,
    };
    let pkh_hex = match env::var("IRIUM_POAWX_THIRD_PARTY_FEE_PKH") {
        Ok(v) => v.trim().to_ascii_lowercase(),
        Err(_) => {
            warn!("[poawx-deleg] third-party fee_bps set but IRIUM_POAWX_THIRD_PARTY_FEE_PKH missing; fee disabled (official 0%)");
            return None;
        }
    };
    let pkh = match hex::decode(&pkh_hex) {
        Ok(b) if b.len() == 20 => {
            let mut a = [0u8; 20];
            a.copy_from_slice(&b);
            a
        }
        _ => {
            warn!(
                "[poawx-deleg] IRIUM_POAWX_THIRD_PARTY_FEE_PKH invalid (need 40 hex); fee disabled"
            );
            return None;
        }
    };
    if pkh == [0u8; 20] {
        warn!("[poawx-deleg] IRIUM_POAWX_THIRD_PARTY_FEE_PKH is zero; fee disabled");
        return None;
    }
    Some((bps, pkh))
}

/// Extract `(fee_bps, fee_pkh)` from a hex-encoded `Phase20ReceiptExt`. The wire
/// always ends with `fee_bps(2) || fee_pkh(20)`, so they are the last 22 bytes.
/// Returns None on malformed/short input (fail-closed).
pub fn fee_terms_from_ext_hex(ext_hex: &str) -> Option<(u16, [u8; 20])> {
    // Layout: version(1) || role_reward(60) || (len_u16 || claim)×3 || fee_bps(2)
    //         || fee_pkh(20) || [precommit flag(1) + root(32) IFF Some] (trailing).
    // Parse from the FRONT, skipping the three variable-length claims, so the
    // OPTIONAL Step 6A trailing precommit_root is never misread as the fee terms
    // (the old "last 22 bytes" read broke once precommit_root was appended — it
    // parsed 32 bytes of the root hash as a spurious fee, adding a bogus 6th
    // coinbase output that consensus then rejected).
    let b = hex::decode(ext_hex).ok()?;
    if b.len() < 1 + 60 || b[0] != PHASE20_EXT_VERSION {
        return None;
    }
    let mut p = 1 + 60;
    for _ in 0..3 {
        if p + 2 > b.len() {
            return None;
        }
        let len = u16::from_le_bytes(b[p..p + 2].try_into().ok()?) as usize;
        p += 2 + len;
    }
    if p + 22 > b.len() {
        return None;
    }
    let fee_bps = u16::from_le_bytes(b[p..p + 2].try_into().ok()?);
    let mut fee_pkh = [0u8; 20];
    fee_pkh.copy_from_slice(&b[p + 2..p + 22]);
    Some((fee_bps, fee_pkh))
}

/// Mirror of `irium_node_rs::poawx::fairness_assignment_digest`.
pub fn fairness_assignment_digest(
    network_id: u8,
    height: u64,
    prev_hash: &[u8; 32],
    role_id: u8,
    slot_index: u32,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(FAIRNESS_DOMAIN_V1);
    h.update([network_id]);
    h.update(height.to_le_bytes());
    h.update(prev_hash);
    h.update([role_id]);
    h.update(slot_index.to_le_bytes());
    h.finalize().into()
}

/// Mirror of `irium_node_rs::poawx::assign_lane` returning the lane *id* byte
/// (production lanes only; never the dev/test fallback).
pub fn assign_lane_id(
    network_id: u8,
    height: u64,
    prev_hash: &[u8; 32],
    role_id: u8,
    slot_index: u32,
) -> u8 {
    let d = fairness_assignment_digest(network_id, height, prev_hash, role_id, slot_index);
    let v = (u64::from_le_bytes(d[0..8].try_into().expect("len 8")) % 10_000) as u32;
    if v < FAIRNESS_CPU_UPPER {
        LANE_CPU_FRIENDLY
    } else if v < FAIRNESS_GPU_UPPER {
        LANE_GPU_PARALLEL
    } else {
        LANE_ASIC_STREAMING
    }
}

/// Mirror of `irium_node_rs::poawx::role_claim_digest`.
#[allow(clippy::too_many_arguments)]
pub fn role_claim_digest(
    network_id: u8,
    height: u64,
    prev_hash: &[u8; 32],
    role_id: u8,
    lane_id: u8,
    solver_pkh: &[u8; 20],
    nonce: &[u8; 32],
    secret: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ROLE_CLAIM_DOMAIN_V1);
    h.update([network_id]);
    h.update(height.to_le_bytes());
    h.update(prev_hash);
    h.update([role_id]);
    h.update([lane_id]);
    h.update(solver_pkh);
    h.update(nonce);
    h.update(secret);
    h.finalize().into()
}

// ── Phase 20 Step 6A: hidden role-precommit mirror primitives ────────────────
pub const ROLE_PRECOMMIT_DOMAIN_V1: &[u8] = b"IRIUM_POAWX_ROLE_PRECOMMIT_V1";
pub const ROLE_PRECOMMIT_COMMIT_DOMAIN_V1: &[u8] = b"IRIUM_POAWX_ROLE_PRECOMMIT_COMMIT_V1";

/// Mirror of `irium_node_rs::poawx::role_precommit_commitment`.
pub fn role_precommit_commitment(secret: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ROLE_PRECOMMIT_COMMIT_DOMAIN_V1);
    h.update(secret);
    h.update(nonce);
    h.finalize().into()
}

/// Mirror of `irium_node_rs::poawx::role_precommit_leaf`.
pub fn role_precommit_leaf(
    network_id: u8,
    target_height: u64,
    role_id: u8,
    solver_pkh: &[u8; 20],
    commitment_hash: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ROLE_PRECOMMIT_DOMAIN_V1);
    h.update([network_id]);
    h.update(target_height.to_le_bytes());
    h.update([role_id]);
    h.update(solver_pkh);
    h.update(commitment_hash);
    h.finalize().into()
}

/// Mirror of `irium_node_rs::poawx::role_precommit_root` (SHA256 over sorted leaves).
pub fn role_precommit_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    let mut sorted: Vec<[u8; 32]> = leaves.to_vec();
    sorted.sort_unstable();
    let mut h = Sha256::new();
    for l in &sorted {
        h.update(l);
    }
    h.finalize().into()
}

/// Mirror of `irium_node_rs::chain::hidden_precommit_active`: gate on
/// `IRIUM_POAWX_HIDDEN_PRECOMMIT_ACTIVATION_HEIGHT`. Mainnet hard-off.
pub fn hidden_precommit_active(height: u64) -> bool {
    if network_id_from_env() == 0 {
        return false; // mainnet
    }
    activation_height_reached("IRIUM_POAWX_HIDDEN_PRECOMMIT_ACTIVATION_HEIGHT", height)
}

/// Mirror of `irium_node_rs::poawx::RoleReward` (60-byte wire).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleRewardMirror {
    pub compute_contributor_pkh: [u8; 20],
    pub verify_contributor_pkh: [u8; 20],
    pub support_contributor_pkh: [u8; 20],
}

impl RoleRewardMirror {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(60);
        out.extend_from_slice(&self.compute_contributor_pkh);
        out.extend_from_slice(&self.verify_contributor_pkh);
        out.extend_from_slice(&self.support_contributor_pkh);
        out
    }
}

/// Mirror of `irium_node_rs::poawx::PoawxRoleClaim`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoawxRoleClaimMirror {
    pub role_id: u8,
    pub lane_id: u8,
    pub solver_pkh: [u8; 20],
    pub nonce: [u8; 32],
    pub secret: [u8; 32],
    pub claim_digest: [u8; 32],
    pub commitment_hash: Option<[u8; 32]>,
}

impl PoawxRoleClaimMirror {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(118 + 1 + 32);
        out.push(self.role_id);
        out.push(self.lane_id);
        out.extend_from_slice(&self.solver_pkh);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.secret);
        out.extend_from_slice(&self.claim_digest);
        match &self.commitment_hash {
            Some(c) => {
                out.push(1);
                out.extend_from_slice(c);
            }
            None => out.push(0),
        }
        out
    }
}

// ── Phase 21B: stratum-local mirror of the node TicketProof (byte-identical) ──
// MUST match `irium_node_rs::poawx_ticket::TicketProof` byte-for-byte; the parity
// test below asserts equality + node acceptance. Mainnet hard-off via callers.
pub const TICKET_PROOF_DOMAIN: &[u8] = b"IRIUM_POAWX_TICKET_PROOF_V1";
pub const SYBIL_WORK_DOMAIN: &[u8] = b"IRIUM_POAWX_SYBIL_WORK_V1";
pub const TICKET_PROOF_WIRE: usize = 1 + 8 + 1 + 20 + 8 + 8 + 33 + 32 + 32 + 1 + 32; // 176
pub const TICKET_SECTION_MAGIC: &[u8; 4] = b"TPK1";

pub fn mirror_compute_sybil_digest(
    network_id: u8,
    prev_hash: &[u8; 32],
    miner_pkh: &[u8; 20],
    epoch: u64,
    apk: &[u8; 33],
    nonce: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(SYBIL_WORK_DOMAIN);
    h.update([network_id]);
    // Fix B/C parity with the node: bind sybil work to the target block prev_hash.
    h.update(prev_hash);
    h.update(miner_pkh);
    h.update(epoch.to_le_bytes());
    h.update(apk);
    h.update(nonce);
    h.finalize().into()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketProofMirror {
    pub network_id: u8,
    pub target_height: u64,
    pub role_id: u8,
    pub miner_pkh: [u8; 20],
    pub epoch: u64,
    pub expiry_height: u64,
    pub assignment_public_key: [u8; 33],
    pub sybil_work_nonce: [u8; 32],
    pub sybil_work_digest: [u8; 32],
    pub penalty_status: u8,
    pub ticket_digest: [u8; 32],
}

impl TicketProofMirror {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network_id: u8,
        target_height: u64,
        prev_hash: [u8; 32],
        role_id: u8,
        miner_pkh: [u8; 20],
        epoch: u64,
        expiry_height: u64,
        assignment_public_key: [u8; 33],
        sybil_work_nonce: [u8; 32],
        penalty_status: u8,
    ) -> Self {
        let sybil_work_digest = mirror_compute_sybil_digest(
            network_id,
            &prev_hash,
            &miner_pkh,
            epoch,
            &assignment_public_key,
            &sybil_work_nonce,
        );
        let mut h = Sha256::new();
        h.update(TICKET_PROOF_DOMAIN);
        h.update([network_id]);
        h.update(target_height.to_le_bytes());
        h.update([role_id]);
        h.update(miner_pkh);
        h.update(epoch.to_le_bytes());
        h.update(expiry_height.to_le_bytes());
        h.update(assignment_public_key);
        h.update(sybil_work_digest);
        let ticket_digest = h.finalize().into();
        Self {
            network_id,
            target_height,
            role_id,
            miner_pkh,
            epoch,
            expiry_height,
            assignment_public_key,
            sybil_work_nonce,
            sybil_work_digest,
            penalty_status,
            ticket_digest,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(TICKET_PROOF_WIRE);
        out.push(self.network_id);
        out.extend_from_slice(&self.target_height.to_le_bytes());
        out.push(self.role_id);
        out.extend_from_slice(&self.miner_pkh);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.expiry_height.to_le_bytes());
        out.extend_from_slice(&self.assignment_public_key);
        out.extend_from_slice(&self.sybil_work_nonce);
        out.extend_from_slice(&self.sybil_work_digest);
        out.push(self.penalty_status);
        out.extend_from_slice(&self.ticket_digest);
        out
    }

    pub fn deserialize(raw: &[u8]) -> Result<Self, String> {
        if raw.len() != TICKET_PROOF_WIRE {
            return Err(format!(
                "ticket proof mirror: wrong length {} (want {})",
                raw.len(),
                TICKET_PROOF_WIRE
            ));
        }
        let mut o = 0usize;
        let network_id = raw[o];
        o += 1;
        let target_height = u64::from_le_bytes(raw[o..o + 8].try_into().unwrap());
        o += 8;
        let role_id = raw[o];
        o += 1;
        let mut miner_pkh = [0u8; 20];
        miner_pkh.copy_from_slice(&raw[o..o + 20]);
        o += 20;
        let epoch = u64::from_le_bytes(raw[o..o + 8].try_into().unwrap());
        o += 8;
        let expiry_height = u64::from_le_bytes(raw[o..o + 8].try_into().unwrap());
        o += 8;
        let mut assignment_public_key = [0u8; 33];
        assignment_public_key.copy_from_slice(&raw[o..o + 33]);
        o += 33;
        let mut sybil_work_nonce = [0u8; 32];
        sybil_work_nonce.copy_from_slice(&raw[o..o + 32]);
        o += 32;
        let mut sybil_work_digest = [0u8; 32];
        sybil_work_digest.copy_from_slice(&raw[o..o + 32]);
        o += 32;
        let penalty_status = raw[o];
        o += 1;
        let mut ticket_digest = [0u8; 32];
        ticket_digest.copy_from_slice(&raw[o..o + 32]);
        Ok(Self {
            network_id,
            target_height,
            role_id,
            miner_pkh,
            epoch,
            expiry_height,
            assignment_public_key,
            sybil_work_nonce,
            sybil_work_digest,
            penalty_status,
            ticket_digest,
        })
    }
}

/// Phase 22D: opaque mirror of `irium_node_rs::poawx_candidate::AssignmentProofV2`
/// (a true secp256k1 RFC 9381 ECVRF proof). The pool does NOT verify the VRF (no
/// `vrf_fun` dependency here) -- it mirrors the 273-byte wire byte-for-byte so it can
/// bundle miner-produced proofs into the produced ext; the NODE is authoritative and
/// re-verifies. The parity test below asserts byte-equality vs the canonical type.
pub const VRF_PROOF_WIRE: usize = 81;
pub const ASSIGNMENT_PROOF_V2_WIRE: usize =
    1 + 1 + 8 + 1 + 20 + 33 + 32 + 32 + 32 + VRF_PROOF_WIRE + 32; // 273
pub const ASSIGNMENT_V2_SECTION_MAGIC: &[u8; 4] = b"AVR2";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignmentProofV2Mirror {
    pub version: u8,
    pub network_id: u8,
    pub target_height: u64,
    pub role_id: u8,
    pub solver_pkh: [u8; 20],
    pub assignment_public_key: [u8; 33],
    pub ticket_digest: [u8; 32],
    pub seed: [u8; 32],
    pub vrf_output: [u8; 32],
    pub vrf_proof: [u8; VRF_PROOF_WIRE],
    pub digest: [u8; 32],
}

impl AssignmentProofV2Mirror {
    pub fn serialize(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(ASSIGNMENT_PROOF_V2_WIRE);
        o.push(self.version);
        o.push(self.network_id);
        o.extend_from_slice(&self.target_height.to_le_bytes());
        o.push(self.role_id);
        o.extend_from_slice(&self.solver_pkh);
        o.extend_from_slice(&self.assignment_public_key);
        o.extend_from_slice(&self.ticket_digest);
        o.extend_from_slice(&self.seed);
        o.extend_from_slice(&self.vrf_output);
        o.extend_from_slice(&self.vrf_proof);
        o.extend_from_slice(&self.digest);
        o
    }

    pub fn deserialize(raw: &[u8]) -> Result<Self, String> {
        if raw.len() != ASSIGNMENT_PROOF_V2_WIRE {
            return Err("assignment v2 mirror: bad length".to_string());
        }
        let mut p = 0usize;
        let take = |p: &mut usize, n: usize| -> Vec<u8> {
            let v = raw[*p..*p + n].to_vec();
            *p += n;
            v
        };
        let version = raw[p];
        p += 1;
        let network_id = raw[p];
        p += 1;
        let mut h8 = [0u8; 8];
        h8.copy_from_slice(&take(&mut p, 8));
        let target_height = u64::from_le_bytes(h8);
        let role_id = raw[p];
        p += 1;
        let mut solver_pkh = [0u8; 20];
        solver_pkh.copy_from_slice(&take(&mut p, 20));
        let mut assignment_public_key = [0u8; 33];
        assignment_public_key.copy_from_slice(&take(&mut p, 33));
        let mut ticket_digest = [0u8; 32];
        ticket_digest.copy_from_slice(&take(&mut p, 32));
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&take(&mut p, 32));
        let mut vrf_output = [0u8; 32];
        vrf_output.copy_from_slice(&take(&mut p, 32));
        let mut vrf_proof = [0u8; VRF_PROOF_WIRE];
        vrf_proof.copy_from_slice(&take(&mut p, VRF_PROOF_WIRE));
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&take(&mut p, 32));
        Ok(Self {
            version,
            network_id,
            target_height,
            role_id,
            solver_pkh,
            assignment_public_key,
            ticket_digest,
            seed,
            vrf_output,
            vrf_proof,
            digest,
        })
    }
}

/// Pool-side true-VRF enforcement gate (mirror node `true_vrf_enforced`): active
/// height + required flag, mainnet hard-off. When on, the pool will only emit a
/// production ext if it carries miner-produced V2 proofs (else it fails closed --
/// the pool holds no VRF secret and never fabricates proofs).
pub fn pool_true_vrf_enforced(height: u64) -> bool {
    if network_id_from_env() == 0 {
        return false; // mainnet
    }
    let active = match env::var("IRIUM_POAWX_TRUE_VRF_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        Some(h) => height >= h,
        None => false,
    };
    let required = env::var("IRIUM_POAWX_TRUE_VRF_REQUIRED")
        .map(|v| v.trim() == "1")
        .unwrap_or(false);
    active && required
}

/// Attach miner-produced V2 proofs [compute, verify, support] to a produced ext.
/// The pool bundles only; the node re-verifies every proof.
pub fn attach_true_vrf_section(
    ext: &mut Phase20ReceiptExtMirror,
    proofs: [AssignmentProofV2Mirror; 3],
) {
    ext.role_assignment_v2 = Some(proofs);
}

/// Mirror of `irium_node_rs::poawx::Phase20ReceiptExt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Phase20ReceiptExtMirror {
    pub role_reward: RoleRewardMirror,
    pub compute_claim: PoawxRoleClaimMirror,
    pub verify_claim: PoawxRoleClaimMirror,
    pub support_claim: PoawxRoleClaimMirror,
    pub fee_bps: u16,
    pub fee_pkh: [u8; 20],
    /// Step 6A: optional hidden-precommit root committing the next block's leaves
    /// (trailing-optional; None => byte-identical to pre-6A).
    pub precommit_root: Option<[u8; 32]>,
    /// Phase 21B: optional per-role ticket proofs (trailing section; None =>
    /// byte-identical to pre-21B). Attached when the pool ticket gate is enabled.
    pub role_ticket_proofs: Option<[TicketProofMirror; 3]>,
    /// Phase 21C: optional per-role dominance weights (trailing DOM1
    /// section; None => byte-identical to pre-21C). Attached when
    /// `pool_anti_domination_enforced(height)`.
    pub role_dominance_weights: Option<[u64; 4]>,
    /// Phase 21D: optional candidate set (trailing CND1 section; None =>
    /// byte-identical to pre-21D).
    pub candidate_set: Option<CandidateSetMirror>,
    /// Phase 21F: optional per-role puzzle solutions (trailing PZL1 section;
    /// None => byte-identical to pre-21F).
    pub role_puzzle_proofs: Option<[PuzzleSolutionMirror; 3]>,
    /// Phase 21H: optional bundled finality proof (trailing FIN1 section;
    /// None => byte-identical to pre-21H).
    pub finality_proof: Option<FinalityProofMirror>,
    /// Phase 22A: optional committed admission for the next height (CAC1
    /// section; None => byte-identical to pre-22A).
    pub committed_admission: Option<AdmissionCommitmentMirror>,
    /// Phase 22D: optional per-role true-VRF assignment proofs [compute, verify,
    /// support] (trailing AVR2 section; None => byte-identical to pre-22D).
    pub role_assignment_v2: Option<[AssignmentProofV2Mirror; 3]>,
}

impl Phase20ReceiptExtMirror {
    /// Wire: version(1) || role_reward(60) || (len_u16 || claim)×3 || fee_bps(2) ||
    /// fee_pkh(20) || [precommit flag(1) + root(32) IFF Some] (trailing optional).
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(PHASE20_EXT_VERSION);
        out.extend_from_slice(&self.role_reward.serialize());
        for claim in [&self.compute_claim, &self.verify_claim, &self.support_claim] {
            let b = claim.serialize();
            out.extend_from_slice(&(b.len() as u16).to_le_bytes());
            out.extend_from_slice(&b);
        }
        out.extend_from_slice(&self.fee_bps.to_le_bytes());
        out.extend_from_slice(&self.fee_pkh);
        // Mirror node poawx::Phase20ReceiptExt::serialize EXACTLY: precommit_root
        // (present-only) then the Step 21B trailing ticket section (present-only). A
        // `0` precommit flag is written when tickets are present but precommit is
        // None, so the reader can skip to the ticket magic. Both absent => nothing.
        match &self.precommit_root {
            Some(root) => {
                out.push(1);
                out.extend_from_slice(root);
            }
            None => {
                if self.role_ticket_proofs.is_some()
                    || self.role_dominance_weights.is_some()
                    || self.candidate_set.is_some()
                    || self.role_puzzle_proofs.is_some()
                    || self.finality_proof.is_some()
                    || self.committed_admission.is_some()
                    || self.role_assignment_v2.is_some()
                {
                    out.push(0);
                }
            }
        }
        if let Some(proofs) = &self.role_ticket_proofs {
            out.extend_from_slice(TICKET_SECTION_MAGIC);
            for p in proofs.iter() {
                out.extend_from_slice(&p.serialize());
            }
        }
        // Phase 21C trailing DOM1 dominance-weight section (present-only),
        // byte-identical to node poawx::Phase20ReceiptExt::serialize.
        if let Some(weights) = &self.role_dominance_weights {
            out.extend_from_slice(DOMINANCE_SECTION_MAGIC);
            for w in weights.iter() {
                out.extend_from_slice(&w.to_le_bytes());
            }
        }
        if let Some(cs) = &self.candidate_set {
            let body = cs.serialize();
            out.extend_from_slice(CANDIDATE_SECTION_MAGIC);
            out.extend_from_slice(&(body.len() as u32).to_le_bytes());
            out.extend_from_slice(&body);
        }
        if let Some(sols) = &self.role_puzzle_proofs {
            out.extend_from_slice(PUZZLE_SECTION_MAGIC);
            for sol in sols.iter() {
                out.extend_from_slice(&sol.serialize());
            }
        }
        if let Some(fp) = &self.finality_proof {
            let body = fp.serialize();
            out.extend_from_slice(FINALITY_SECTION_MAGIC);
            out.extend_from_slice(&(body.len() as u32).to_le_bytes());
            out.extend_from_slice(&body);
        }
        if let Some(ca) = &self.committed_admission {
            out.extend_from_slice(COMMITTED_ADMISSION_SECTION_MAGIC);
            out.extend_from_slice(&ca.serialize());
        }
        // Phase 22D trailing AVR2 true-VRF section (present-only); byte-identical to
        // node poawx::Phase20ReceiptExt::serialize when absent.
        if let Some(proofs) = &self.role_assignment_v2 {
            out.extend_from_slice(ASSIGNMENT_V2_SECTION_MAGIC);
            for pr in proofs.iter() {
                out.extend_from_slice(&pr.serialize());
            }
        }
        out
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.serialize());
        h.finalize().into()
    }
}

/// Pool-side ticket enforcement gate (mirrors node `tickets_enforced`): active
/// height + required flag, mainnet hard-off. When on, the pool attaches per-role
/// ticket proofs to the produced Phase 20 ext (else the node fails closed).
pub fn pool_tickets_enforced(height: u64) -> bool {
    if network_id_from_env() == 0 {
        return false;
    }
    let active = match env::var("IRIUM_POAWX_TICKETS_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        Some(h) => height >= h,
        None => false,
    };
    let required = env::var("IRIUM_POAWX_TICKETS_REQUIRED")
        .map(|v| v.trim() == "1")
        .unwrap_or(false);
    active && required
}

/// Build the 3 per-role ticket proofs for a produced ext (compute/verify/support),
/// each bound to that role's solver pkh. Deterministic; clean penalty; expiry a
/// fixed window ahead. Used when `pool_tickets_enforced(height)`.
pub fn build_role_ticket_proofs(
    network_id: u8,
    height: u64,
    prev_hash: &[u8; 32],
    rr: &RoleRewardMirror,
) -> [TicketProofMirror; 3] {
    let epoch = height; // simple per-height epoch (testnet/devnet)
    let expiry = height + 256;
    let apk = [0x02u8; 33];
    let mk = |role_id: u8, pkh: [u8; 20], tag: u8| {
        let mut nonce = [0u8; 32];
        nonce[0] = tag;
        nonce[1] = role_id;
        nonce[2..10].copy_from_slice(&height.to_le_bytes());
        TicketProofMirror::new(
            network_id, height, *prev_hash, role_id, pkh, epoch, expiry, apk, nonce, 0,
        )
    };
    [
        mk(ROLE_COMPUTE_CONTRIBUTOR, rr.compute_contributor_pkh, 1),
        mk(ROLE_VERIFY_CONTRIBUTOR, rr.verify_contributor_pkh, 2),
        mk(ROLE_SUPPORT_CONTRIBUTOR, rr.support_contributor_pkh, 3),
    ]
}

/// Parse an env activation height (`>= h`), mainnet-off handled by the caller.
fn activation_height_reached(var: &str, height: u64) -> bool {
    match env::var(var)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        Some(h) => height >= h,
        None => false,
    }
}

/// Mirror of `irium_node_rs::chain::phase20_production_active`: both multi-role
/// reward AND fairness matrix active for `height`. **Mainnet hard-off**
/// (`network_id_from_env() == 0`). Used to gate pool production + the gated root.
pub fn phase20_production_active(height: u64) -> bool {
    if network_id_from_env() == 0 {
        return false; // mainnet
    }
    activation_height_reached("IRIUM_POAWX_MULTI_ROLE_REWARD_ACTIVATION_HEIGHT", height)
        && activation_height_reached("IRIUM_POAWX_FAIRNESS_MATRIX_ACTIVATION_HEIGHT", height)
}

/// Whether the gated SYNTHETIC role-claim builder is enabled. Testnet/devnet-only
/// (`IRIUM_POAWX_SYNTHETIC_ROLE_CLAIMS=1`), mainnet hard-off, disabled by default.
/// This is for production-wiring validation; it is NOT the live hidden-precommit
/// role-claim protocol (pending).
pub fn synthetic_role_claims_enabled() -> bool {
    if network_id_from_env() == 0 {
        return false; // mainnet
    }
    env::var("IRIUM_POAWX_SYNTHETIC_ROLE_CLAIMS")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}

/// Deterministic per-(role) 32-byte field for reproducible synthetic claims.
fn synth_field(
    tag: &[u8],
    network_id: u8,
    height: u64,
    prev_hash: &[u8; 32],
    role_id: u8,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"IRIUM_POAWX_SYNTHETIC_V1");
    h.update(tag);
    h.update([network_id]);
    h.update(height.to_le_bytes());
    h.update(prev_hash);
    h.update([role_id]);
    h.finalize().into()
}

/// Build a synthetic `Phase20ReceiptExtMirror` for pool production on
/// testnet/devnet. For each role: deterministic nonce/secret, the assigned lane
/// via `assign_lane_id`, a verifying `role_claim_digest`, and a solver pkh chosen
/// deterministically from `workers` (if any) else `primary_pkh` (MVP single-miner).
/// `RoleReward` mirrors the validated solver pkhs. `fee` carries the OPTIONAL
/// third-party fee terms (`Some((fee_bps, fee_pkh))`); `None` => OFFICIAL fee-0.
/// Returns None on mainnet or when synthetic claims are disabled (never fakes).
/// ── Phase 21C: anti-domination dominance weights (pool side) ────────────────
/// Byte-identical mirror of node `poawx_dominance` wire constants + the
/// deterministic fairness math, plus a pool selection helper. PoAW-X is
/// consensus-level: the pool is only one miner interface, so the node remains
/// authoritative and re-validates every attached weight against its persisted
/// state. The pool view is populated operationally from authoritative node state
/// (loopback RPC / block observation); that sync is the remaining operational
/// wiring (global-best candidate selection = Phase 21D). An empty view yields
/// full (base) weights.
pub const DOMINANCE_SECTION_MAGIC: &[u8; 4] = b"DOM1";
pub const DOMINANCE_WEIGHTS_WIRE: usize = 32;
pub const DOMINANCE_BASE_WORK_SCORE: u64 = 1000;

/// Mirror of node `poawx_dominance::fairness_weight`.
pub fn fairness_weight(valid_work_score: u64, recent_reward_share_permille: u32) -> u64 {
    let num = (valid_work_score as u128).saturating_mul(1000);
    let den = 1000u128 + recent_reward_share_permille as u128;
    (num / den) as u64
}

/// Pool-side recent-reward view (recent totals per miner + network total).
#[derive(Debug, Clone, Default)]
pub struct PoolDominanceView {
    recent: BTreeMap<[u8; 20], u64>,
    network_total: u64,
}

impl PoolDominanceView {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn record(&mut self, pkh: [u8; 20], amount: u64) {
        let e = self.recent.entry(pkh).or_insert(0);
        *e = e.saturating_add(amount);
        self.network_total = self.network_total.saturating_add(amount);
    }
    pub fn clear(&mut self) {
        self.recent.clear();
        self.network_total = 0;
    }
    pub fn recent_reward_share_permille(&self, pkh: &[u8; 20]) -> u32 {
        if self.network_total == 0 {
            return 0;
        }
        let mine = *self.recent.get(pkh).unwrap_or(&0) as u128;
        (mine.saturating_mul(1000) / self.network_total as u128).min(1000) as u32
    }
    pub fn weight(&self, base: u64, pkh: &[u8; 20]) -> u64 {
        fairness_weight(base, self.recent_reward_share_permille(pkh))
    }
}

/// Compute the 4 role dominance weights [PRIMARY, COMPUTE, VERIFY, SUPPORT] using
/// the same baseline + formula the node recomputes from its persisted state.
pub fn pool_role_dominance_weights(
    primary_pkh: &[u8; 20],
    rr: &RoleRewardMirror,
    view: &PoolDominanceView,
    base: u64,
) -> [u64; 4] {
    [
        view.weight(base, primary_pkh),
        view.weight(base, &rr.compute_contributor_pkh),
        view.weight(base, &rr.verify_contributor_pkh),
        view.weight(base, &rr.support_contributor_pkh),
    ]
}

/// Select the fairest candidate among collected role candidates: highest fairness
/// weight wins; deterministic tie-break by lower pkh. No hardware-class or
/// pool-ownership assumptions. None for an empty set. (Selecting the GLOBALLY best
/// worker among all possibly-unseen candidates is Phase 21D.)
pub fn select_candidate_by_fairness_weight(
    candidates: &[[u8; 20]],
    view: &PoolDominanceView,
    base: u64,
) -> Option<[u8; 20]> {
    candidates.iter().copied().max_by(|a, b| {
        view.weight(base, a)
            .cmp(&view.weight(base, b))
            .then_with(|| b.cmp(a))
    })
}

/// Pool anti-domination enforcement gate (mirror node `anti_domination_enforced`):
/// activation height + `_REQUIRED=1`, mainnet hard-off.
pub fn pool_anti_domination_enforced(height: u64) -> bool {
    if network_id_from_env() == 0 {
        return false;
    }
    let active = match env::var("IRIUM_POAWX_ANTI_DOMINATION_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        Some(h) => height >= h,
        None => false,
    };
    let required = env::var("IRIUM_POAWX_ANTI_DOMINATION_REQUIRED")
        .map(|v| v.trim() == "1")
        .unwrap_or(false);
    active && required
}

/// Process-global pool dominance view (operationally populated; tests set/clear
/// under p20_env_lock).
pub fn pool_dominance_view() -> &'static std::sync::Mutex<PoolDominanceView> {
    static V: std::sync::OnceLock<std::sync::Mutex<PoolDominanceView>> = std::sync::OnceLock::new();
    V.get_or_init(|| std::sync::Mutex::new(PoolDominanceView::new()))
}

/// Snapshot the global view + compute an ext's role weights (gated attach point).
pub fn pool_dominance_weights_for(primary_pkh: &[u8; 20], rr: &RoleRewardMirror) -> [u64; 4] {
    let v = pool_dominance_view()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    pool_role_dominance_weights(primary_pkh, rr, &v, DOMINANCE_BASE_WORK_SCORE)
}

/// ── Phase 21D: candidate-set + assignment-proof mirror (pool side) ──────────
/// Byte-identical mirror of node `poawx_candidate` (wire + deterministic math).
/// `AssignmentProofV1` is a VRF-style placeholder (no VRF lib); the node
/// re-validates everything, so the pool is one interface, not the owner.
pub const ASSIGNMENT_PROOF_DOMAIN: &[u8] = b"IRIUM_POAWX_ASSIGNMENT_PROOF_V1";
pub const CANDIDATE_SET_DOMAIN: &[u8] = b"IRIUM_POAWX_CANDIDATE_SET_V1";
pub const CANDIDATE_SECTION_MAGIC: &[u8; 4] = b"CND1";
pub const ROLE_CANDIDATE_WIRE: usize = 1 + 20 + 33 + 32 + 1 + 32 + 8 + 8 + 8 + 32; // 175
pub const EFFECTIVE_SCORE_SCALE: u128 = 1_000_000;

pub fn compute_assignment_proof_digest(
    network_id: u8,
    target_height: u64,
    role_id: u8,
    solver_pkh: &[u8; 20],
    assignment_public_key: &[u8; 33],
    ticket_digest: &[u8; 32],
    seed: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ASSIGNMENT_PROOF_DOMAIN);
    h.update([network_id]);
    h.update(target_height.to_le_bytes());
    h.update([role_id]);
    h.update(solver_pkh);
    h.update(assignment_public_key);
    h.update(ticket_digest);
    h.update(seed);
    h.finalize().into()
}

pub fn assignment_score_from_digest(d: &[u8; 32]) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[0..8]);
    u64::from_le_bytes(b)
}

pub fn effective_score(assignment_score: u64, dominance_weight: u64, penalty_weight: u64) -> u64 {
    let v = (assignment_score as u128)
        .saturating_mul(dominance_weight as u128)
        .saturating_mul(penalty_weight as u128)
        / EFFECTIVE_SCORE_SCALE;
    v.min(u64::MAX as u128) as u64
}

/// Mirror of node PenaltyStatus::weight_multiplier_permille.
pub fn penalty_weight_permille(status: u8) -> u64 {
    match status {
        0 | 1 => 1000,
        2 => 500,
        _ => 0,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleCandidateMirror {
    pub role_id: u8,
    pub solver_pkh: [u8; 20],
    pub assignment_public_key: [u8; 33],
    pub ticket_digest: [u8; 32],
    pub penalty_status: u8,
    pub assignment_proof_digest: [u8; 32],
    pub dominance_weight: u64,
    pub penalty_weight: u64,
    pub effective_score: u64,
    pub role_claim_digest: [u8; 32],
}

impl RoleCandidateMirror {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        network_id: u8,
        target_height: u64,
        seed: &[u8; 32],
        role_id: u8,
        solver_pkh: [u8; 20],
        assignment_public_key: [u8; 33],
        ticket_digest: [u8; 32],
        penalty_status: u8,
        dominance_weight: u64,
        role_claim_digest: [u8; 32],
    ) -> Self {
        let assignment_proof_digest = compute_assignment_proof_digest(
            network_id,
            target_height,
            role_id,
            &solver_pkh,
            &assignment_public_key,
            &ticket_digest,
            seed,
        );
        let penalty_weight = penalty_weight_permille(penalty_status);
        let assignment_score = assignment_score_from_digest(&assignment_proof_digest);
        let effective_score = effective_score(assignment_score, dominance_weight, penalty_weight);
        Self {
            role_id,
            solver_pkh,
            assignment_public_key,
            ticket_digest,
            penalty_status,
            assignment_proof_digest,
            dominance_weight,
            penalty_weight,
            effective_score,
            role_claim_digest,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ROLE_CANDIDATE_WIRE);
        out.push(self.role_id);
        out.extend_from_slice(&self.solver_pkh);
        out.extend_from_slice(&self.assignment_public_key);
        out.extend_from_slice(&self.ticket_digest);
        out.push(self.penalty_status);
        out.extend_from_slice(&self.assignment_proof_digest);
        out.extend_from_slice(&self.dominance_weight.to_le_bytes());
        out.extend_from_slice(&self.penalty_weight.to_le_bytes());
        out.extend_from_slice(&self.effective_score.to_le_bytes());
        out.extend_from_slice(&self.role_claim_digest);
        out
    }

    pub fn deserialize(raw: &[u8]) -> Result<Self, String> {
        if raw.len() != ROLE_CANDIDATE_WIRE {
            return Err("role candidate mirror: bad length".to_string());
        }
        let mut p = 0usize;
        let take = |p: &mut usize, n: usize| -> Vec<u8> {
            let v = raw[*p..*p + n].to_vec();
            *p += n;
            v
        };
        let role_id = raw[p];
        p += 1;
        let mut solver_pkh = [0u8; 20];
        solver_pkh.copy_from_slice(&take(&mut p, 20));
        let mut assignment_public_key = [0u8; 33];
        assignment_public_key.copy_from_slice(&take(&mut p, 33));
        let mut ticket_digest = [0u8; 32];
        ticket_digest.copy_from_slice(&take(&mut p, 32));
        let penalty_status = raw[p];
        p += 1;
        let mut assignment_proof_digest = [0u8; 32];
        assignment_proof_digest.copy_from_slice(&take(&mut p, 32));
        let mut w = [0u8; 8];
        w.copy_from_slice(&take(&mut p, 8));
        let dominance_weight = u64::from_le_bytes(w);
        w.copy_from_slice(&take(&mut p, 8));
        let penalty_weight = u64::from_le_bytes(w);
        w.copy_from_slice(&take(&mut p, 8));
        let effective_score = u64::from_le_bytes(w);
        let mut role_claim_digest = [0u8; 32];
        role_claim_digest.copy_from_slice(&take(&mut p, 32));
        Ok(Self {
            role_id,
            solver_pkh,
            assignment_public_key,
            ticket_digest,
            penalty_status,
            assignment_proof_digest,
            dominance_weight,
            penalty_weight,
            effective_score,
            role_claim_digest,
        })
    }

    fn sort_key(&self) -> ([u8; 1], [u8; 20], [u8; 32], [u8; 32]) {
        (
            [self.role_id],
            self.solver_pkh,
            self.ticket_digest,
            self.assignment_proof_digest,
        )
    }
}

fn candidate_better(a: &RoleCandidateMirror, b: &RoleCandidateMirror) -> bool {
    if a.effective_score != b.effective_score {
        return a.effective_score > b.effective_score;
    }
    if a.assignment_proof_digest != b.assignment_proof_digest {
        return a.assignment_proof_digest < b.assignment_proof_digest;
    }
    if a.solver_pkh != b.solver_pkh {
        return a.solver_pkh < b.solver_pkh;
    }
    a.ticket_digest < b.ticket_digest
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateSetMirror {
    pub network_id: u8,
    pub target_height: u64,
    pub seed: [u8; 32],
    pub candidates: Vec<RoleCandidateMirror>,
}

impl CandidateSetMirror {
    pub fn new(network_id: u8, target_height: u64, seed: [u8; 32]) -> Self {
        Self {
            network_id,
            target_height,
            seed,
            candidates: Vec::new(),
        }
    }
    pub fn push(&mut self, c: RoleCandidateMirror) {
        self.candidates.push(c);
    }
    pub fn sort_canonical(&mut self) {
        self.candidates
            .sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(1 + 8 + 32 + 2 + self.candidates.len() * ROLE_CANDIDATE_WIRE);
        out.push(self.network_id);
        out.extend_from_slice(&self.target_height.to_le_bytes());
        out.extend_from_slice(&self.seed);
        out.extend_from_slice(&(self.candidates.len() as u16).to_le_bytes());
        for c in &self.candidates {
            out.extend_from_slice(&c.serialize());
        }
        out
    }
    pub fn root(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(CANDIDATE_SET_DOMAIN);
        h.update(self.serialize());
        h.finalize().into()
    }
    pub fn best_for_role(&self, role_id: u8) -> Option<&RoleCandidateMirror> {
        let mut best: Option<&RoleCandidateMirror> = None;
        for c in self.candidates.iter().filter(|c| c.role_id == role_id) {
            match best {
                None => best = Some(c),
                Some(b) if candidate_better(c, b) => best = Some(c),
                _ => {}
            }
        }
        best
    }
}

/// Pool candidate-set enforcement gate (mirror node `candidate_set_enforced`).
pub fn pool_candidate_set_enforced(height: u64) -> bool {
    if network_id_from_env() == 0 {
        return false;
    }
    let active = match env::var("IRIUM_POAWX_CANDIDATE_SET_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        Some(h) => height >= h,
        None => false,
    };
    let required = env::var("IRIUM_POAWX_CANDIDATE_SET_REQUIRED")
        .map(|v| v.trim() == "1")
        .unwrap_or(false);
    active && required
}

/// Build a canonical candidate set for the produced ext from the selected role
/// solvers: ticket digests come from the per-role ticket proofs, dominance weights
/// from the process-global pool view, penalty Clean. One candidate per selected
/// role (the node validates "selected == best within the included set"; richer
/// multi-candidate admission/gossip is future work). Fails closed by returning the
/// set the node will accept only if it matches the node's persisted state.
pub fn build_pool_candidate_set(
    network_id: u8,
    height: u64,
    prev_hash: &[u8; 32],
    rr: &RoleRewardMirror,
) -> CandidateSetMirror {
    let tickets = build_role_ticket_proofs(network_id, height, prev_hash, rr);
    let view = pool_dominance_view()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let base = DOMINANCE_BASE_WORK_SCORE;
    let mut cs = CandidateSetMirror::new(network_id, height, *prev_hash);
    let roles = [
        (
            ROLE_COMPUTE_CONTRIBUTOR,
            rr.compute_contributor_pkh,
            &tickets[0],
        ),
        (
            ROLE_VERIFY_CONTRIBUTOR,
            rr.verify_contributor_pkh,
            &tickets[1],
        ),
        (
            ROLE_SUPPORT_CONTRIBUTOR,
            rr.support_contributor_pkh,
            &tickets[2],
        ),
    ];
    for (role_id, solver, tk) in roles {
        let dom_w = view.weight(base, &solver);
        cs.push(RoleCandidateMirror::build(
            network_id,
            height,
            prev_hash,
            role_id,
            solver,
            tk.assignment_public_key,
            tk.ticket_digest,
            0,
            dom_w,
            tk.ticket_digest,
        ));
    }
    cs.sort_canonical();
    cs
}

/// ── Phase 21E: candidate-admission (pool side) ──────────────────────────────
/// The pool builds its block candidate set strictly from the node's ADMITTED
/// candidates (fetched via loopback RPC) so it matches what the node validates.
/// The node remains authoritative; the pool is one interface, not the owner.
pub const CANDIDATE_ADMISSION_WIRE: usize = 1 + 1 + 8 + 32 + 175 + 32; // 249
/// Phase 22E: admission wire length with a trailing true-VRF proof appended.
pub const CANDIDATE_ADMISSION_V2_WIRE: usize = CANDIDATE_ADMISSION_WIRE + ASSIGNMENT_PROOF_V2_WIRE;

/// Phase 22E: decode one admission wire (hex) -> (height, seed, role, solver, V2
/// proof) when it carries a trailing true-VRF proof. None on malformed / V1-only.
pub fn decode_admission_v2(
    hexstr: &str,
) -> Option<(u64, [u8; 32], u8, [u8; 20], AssignmentProofV2Mirror)> {
    let bytes = hex::decode(hexstr.trim()).ok()?;
    if bytes.len() != CANDIDATE_ADMISSION_V2_WIRE || bytes[0] != 1 {
        return None;
    }
    let mut hb = [0u8; 8];
    hb.copy_from_slice(&bytes[2..10]);
    let height = u64::from_le_bytes(hb);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes[10..42]);
    let cand = RoleCandidateMirror::deserialize(&bytes[42..42 + 175]).ok()?;
    let proof = AssignmentProofV2Mirror::deserialize(
        &bytes[CANDIDATE_ADMISSION_WIRE..CANDIDATE_ADMISSION_V2_WIRE],
    )
    .ok()?;
    Some((height, seed, cand.role_id, cand.solver_pkh, proof))
}

/// Phase 22E: map (role_id, solver_pkh) -> admitted true-VRF proof for (height,
/// seed). The pool bundles these; it never verifies or fabricates them.
pub fn build_admitted_v2_proofs(
    hexes: &[String],
    height: u64,
    seed: &[u8; 32],
) -> BTreeMap<(u8, [u8; 20]), AssignmentProofV2Mirror> {
    let mut m: BTreeMap<(u8, [u8; 20]), AssignmentProofV2Mirror> = BTreeMap::new();
    for h in hexes {
        if let Some((hh, ss, role, solver, proof)) = decode_admission_v2(h) {
            if hh == height && &ss == seed {
                m.insert((role, solver), proof);
            }
        }
    }
    m
}

/// Phase 22E: build the AVR2 section [compute, verify, support] for a produced ext
/// from the pool admitted cache, using the proofs of the SELECTED candidates. None
/// (fail closed) if any selected role lacks an admitted V2 proof. The pool only
/// bundles miner-supplied proofs; it never signs or generates VRF proofs.
pub fn build_pool_true_vrf_section(
    height: u64,
    seed: &[u8; 32],
    role_reward: &RoleRewardMirror,
) -> Option<[AssignmentProofV2Mirror; 3]> {
    let hexes = pool_admitted_cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&height)
        .cloned()
        .unwrap_or_default();
    let map = build_admitted_v2_proofs(&hexes, height, seed);
    let compute = map
        .get(&(
            ROLE_COMPUTE_CONTRIBUTOR,
            role_reward.compute_contributor_pkh,
        ))?
        .clone();
    let verify = map
        .get(&(ROLE_VERIFY_CONTRIBUTOR, role_reward.verify_contributor_pkh))?
        .clone();
    let support = map
        .get(&(
            ROLE_SUPPORT_CONTRIBUTOR,
            role_reward.support_contributor_pkh,
        ))?
        .clone();
    Some([compute, verify, support])
}

/// Pool candidate-admission enforcement gate (mirror node).
pub fn pool_candidate_admission_enforced(height: u64) -> bool {
    if network_id_from_env() == 0 {
        return false;
    }
    let active = match env::var("IRIUM_POAWX_CANDIDATE_ADMISSION_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        Some(h) => height >= h,
        None => false,
    };
    let required = env::var("IRIUM_POAWX_CANDIDATE_ADMISSION_REQUIRED")
        .map(|v| v.trim() == "1")
        .unwrap_or(false);
    active && required
}

/// Decode one admission wire (hex) -> (height, seed, candidate). None on malformed.
pub fn decode_admission_candidate(hexstr: &str) -> Option<(u64, [u8; 32], RoleCandidateMirror)> {
    let bytes = hex::decode(hexstr.trim()).ok()?;
    if (bytes.len() != CANDIDATE_ADMISSION_WIRE && bytes.len() != CANDIDATE_ADMISSION_V2_WIRE)
        || bytes[0] != 1
    {
        return None;
    }
    let mut hb = [0u8; 8];
    hb.copy_from_slice(&bytes[2..10]);
    let height = u64::from_le_bytes(hb);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes[10..42]);
    let candidate = RoleCandidateMirror::deserialize(&bytes[42..42 + 175]).ok()?;
    Some((height, seed, candidate))
}

/// Build the admitted candidate set for (height, seed) from fetched admission
/// hex strings. None when no admitted candidate matches (caller fails closed).
pub fn build_admitted_candidate_set(
    hexes: &[String],
    network_id: u8,
    height: u64,
    seed: &[u8; 32],
) -> Option<CandidateSetMirror> {
    let mut cs = CandidateSetMirror::new(network_id, height, *seed);
    for h in hexes {
        if let Some((hh, ss, cand)) = decode_admission_candidate(h) {
            if hh == height && &ss == seed {
                cs.push(cand);
            }
        }
    }
    if cs.candidates.is_empty() {
        return None;
    }
    cs.sort_canonical();
    Some(cs)
}

/// Process-global pool cache of fetched admission hexes per height.
pub fn pool_admitted_cache() -> &'static std::sync::Mutex<BTreeMap<u64, Vec<String>>> {
    static C: std::sync::OnceLock<std::sync::Mutex<BTreeMap<u64, Vec<String>>>> =
        std::sync::OnceLock::new();
    C.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
}

/// Build the candidate set for a produced ext from the pool admitted cache.
pub fn build_pool_candidate_set_for_height(
    network_id: u8,
    height: u64,
    seed: &[u8; 32],
) -> Option<CandidateSetMirror> {
    let cache = pool_admitted_cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let hexes = cache.get(&height).cloned().unwrap_or_default();
    drop(cache);
    build_admitted_candidate_set(&hexes, network_id, height, seed)
}

/// Fetch node-admitted candidate admissions for a height (hex; empty on error).
pub async fn fetch_node_candidate_admissions(
    rpc_base: &str,
    rpc_token: &str,
    target_height: u64,
) -> Vec<String> {
    let url = format!(
        "{}/poawx/candidate-admissions?target_height={}",
        rpc_base.trim_end_matches('/'),
        target_height
    );
    let client = match reqwest::Client::builder().build() {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let resp = match client.get(&url).bearer_auth(rpc_token).send().await {
        Ok(r) if r.status().is_success() => r,
        _ => return Vec::new(),
    };
    #[derive(serde::Deserialize)]
    struct Resp {
        admissions: Vec<String>,
    }
    match resp.json::<Resp>().await {
        Ok(r) => r.admissions,
        Err(_) => Vec::new(),
    }
}

/// Refresh the pool admitted cache for a height from the node (best-effort; no-op
/// unless candidate-admission is enforced).
pub async fn refresh_pool_admitted_cache(rpc_base: &str, rpc_token: &str, height: u64) {
    if !pool_candidate_admission_enforced(height) {
        return;
    }
    let hexes = fetch_node_candidate_admissions(rpc_base, rpc_token, height).await;
    let mut cache = pool_admitted_cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    cache.insert(height, hexes);
    // bound memory: keep only recent heights.
    let keep_floor = height.saturating_sub(64);
    cache.retain(|h, _| *h >= keep_floor);
}

/// Phase 21I: fetch node-collected finality votes for a height (hex; empty on error).
pub async fn fetch_node_finality_votes(
    rpc_base: &str,
    rpc_token: &str,
    target_height: u64,
) -> Vec<String> {
    let url = format!(
        "{}/poawx/finality-votes?target_height={}",
        rpc_base.trim_end_matches('/'),
        target_height
    );
    let client = match reqwest::Client::builder().build() {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let resp = match client.get(&url).bearer_auth(rpc_token).send().await {
        Ok(r) if r.status().is_success() => r,
        _ => return Vec::new(),
    };
    #[derive(serde::Deserialize)]
    struct Resp {
        votes: Vec<String>,
    }
    match resp.json::<Resp>().await {
        Ok(r) => r.votes,
        Err(_) => Vec::new(),
    }
}

/// Refresh the pool finality-vote cache for a height from the node (best-effort;
/// no-op unless the finality committee gate is enforced). The pool only fetches
/// member-signed votes; it never signs them and the node re-verifies everything.
pub async fn refresh_pool_finality_votes(rpc_base: &str, rpc_token: &str, height: u64) {
    if !pool_finality_committee_enforced(height) {
        return;
    }
    let hexes = fetch_node_finality_votes(rpc_base, rpc_token, height).await;
    if hexes.is_empty() {
        return;
    }
    let mut cache = pool_finality_vote_cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    cache.insert(height, hexes);
    let keep_floor = height.saturating_sub(64);
    cache.retain(|h, _| *h >= keep_floor);
}

/// ── Phase 21F: assigned puzzle work modes (pool mirror) ─────────────────────
/// Byte-identical mirror of node `poawx_puzzle` so the pool can SOLVE the assigned
/// puzzle for each selected candidate and attach a node-verifiable solution.
/// Assigned-work proofs only; NOT chain PoW. The node re-verifies everything.
pub const PUZZLE_SECTION_MAGIC: &[u8; 4] = b"PZL1";
pub const PUZZLE_SOLUTION_WIRE: usize = 1 + 8 + 32;
const PZ_MODE_DOMAIN: &[u8] = b"IRIUM_POAWX_PUZZLE_MODE_V1";
const PZ_CHALLENGE_DOMAIN: &[u8] = b"IRIUM_POAWX_PUZZLE_CHALLENGE_V1";
const PZ_ANCHOR_DOMAIN: &[u8] = b"IRIUM_POAWX_PUZZLE_ANCHOR_V1";
const PZ_MEM_DOMAIN: &[u8] = b"IRIUM_POAWX_PUZZLE_MEM_V1";
const PZ_PAR_DOMAIN: &[u8] = b"IRIUM_POAWX_PUZZLE_PAR_V1";
const PZ_VERIFY_DOMAIN: &[u8] = b"IRIUM_POAWX_PUZZLE_VERIFY_V1";
const PZ_FINALITY_DOMAIN: &[u8] = b"IRIUM_POAWX_PUZZLE_FINALITY_V1";
const PZ_MAX_MEM_WORDS: u32 = 4096;
const PZ_MAX_LANES: u8 = 16;
const PZ_MAX_ITER: u32 = 4096;
const PZ_MAX_BITS: u8 = 24;
const PZ_SOLVE_CAP: u64 = 1 << 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PuzzleProfileMirror {
    pub anchor_bits: u8,
    pub mem_words: u32,
    pub lanes: u8,
    pub iterations: u32,
}
impl PuzzleProfileMirror {
    fn clamped(self) -> Self {
        Self {
            anchor_bits: self.anchor_bits.min(PZ_MAX_BITS),
            mem_words: self.mem_words.clamp(1, PZ_MAX_MEM_WORDS),
            lanes: self.lanes.clamp(1, PZ_MAX_LANES),
            iterations: self.iterations.min(PZ_MAX_ITER),
        }
    }
    fn serialize(&self) -> [u8; 10] {
        let c = self.clamped();
        let mut o = [0u8; 10];
        o[0] = c.anchor_bits;
        o[1..5].copy_from_slice(&c.mem_words.to_le_bytes());
        o[5] = c.lanes;
        o[6..10].copy_from_slice(&c.iterations.to_le_bytes());
        o
    }
}
pub fn puzzle_default_profile() -> PuzzleProfileMirror {
    let mut p = PuzzleProfileMirror {
        anchor_bits: 8,
        mem_words: 64,
        lanes: 4,
        iterations: 16,
    };
    if let Some(b) = env::var("IRIUM_POAWX_PUZZLE_BITS")
        .ok()
        .and_then(|v| v.trim().parse::<u8>().ok())
    {
        p.anchor_bits = b;
    }
    p.clamped()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PuzzleSolutionMirror {
    pub mode: u8,
    pub nonce: u64,
    pub proof_digest: [u8; 32],
}
impl PuzzleSolutionMirror {
    pub fn serialize(&self) -> [u8; PUZZLE_SOLUTION_WIRE] {
        let mut o = [0u8; PUZZLE_SOLUTION_WIRE];
        o[0] = self.mode;
        o[1..9].copy_from_slice(&self.nonce.to_le_bytes());
        o[9..41].copy_from_slice(&self.proof_digest);
        o
    }

    pub fn deserialize(raw: &[u8]) -> Result<Self, String> {
        if raw.len() != PUZZLE_SOLUTION_WIRE {
            return Err(format!(
                "puzzle solution mirror: wrong length {} (want {})",
                raw.len(),
                PUZZLE_SOLUTION_WIRE
            ));
        }
        let mode = raw[0];
        let nonce = u64::from_le_bytes(raw[1..9].try_into().unwrap());
        let mut proof_digest = [0u8; 32];
        proof_digest.copy_from_slice(&raw[9..41]);
        Ok(Self {
            mode,
            nonce,
            proof_digest,
        })
    }
}

fn pz_leading_zero_bits(d: &[u8; 32]) -> u32 {
    let mut n = 0u32;
    for b in d {
        if *b == 0 {
            n += 8;
        } else {
            n += b.leading_zeros();
            break;
        }
    }
    n
}

#[allow(clippy::too_many_arguments)]
fn pz_assign_mode(
    net: u8,
    h: u64,
    role: u8,
    solver: &[u8; 20],
    ticket: &[u8; 32],
    apd: &[u8; 32],
    seed: &[u8; 32],
) -> u8 {
    let mut hsh = Sha256::new();
    hsh.update(PZ_MODE_DOMAIN);
    hsh.update([net]);
    hsh.update(h.to_le_bytes());
    hsh.update([role]);
    hsh.update(solver);
    hsh.update(ticket);
    hsh.update(apd);
    hsh.update(seed);
    let d: [u8; 32] = hsh.finalize().into();
    d[0] % 5
}

#[allow(clippy::too_many_arguments)]
fn pz_challenge_digest(
    net: u8,
    h: u64,
    role: u8,
    solver: &[u8; 20],
    ticket: &[u8; 32],
    apd: &[u8; 32],
    cand: &[u8; 32],
    seed: &[u8; 32],
    mode: u8,
    profile: &PuzzleProfileMirror,
) -> [u8; 32] {
    let mut hsh = Sha256::new();
    hsh.update(PZ_CHALLENGE_DOMAIN);
    hsh.update([net]);
    hsh.update(h.to_le_bytes());
    hsh.update([role]);
    hsh.update(solver);
    hsh.update(ticket);
    hsh.update(apd);
    hsh.update(cand);
    hsh.update(seed);
    hsh.update([mode]);
    hsh.update(profile.serialize());
    hsh.finalize().into()
}

fn pz_sha256d(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    let a: [u8; 32] = h.finalize().into();
    let mut h2 = Sha256::new();
    h2.update(a);
    h2.finalize().into()
}
fn pz_anchor(cd: &[u8; 32], nonce: u64) -> [u8; 32] {
    pz_sha256d(&[PZ_ANCHOR_DOMAIN, cd, &nonce.to_le_bytes()])
}
fn pz_memory(cd: &[u8; 32], nonce: u64, p: &PuzzleProfileMirror) -> [u8; 32] {
    let p = p.clamped();
    let n = p.mem_words as usize;
    let mut scratch = vec![0u64; n];
    let mut s8 = [0u8; 8];
    s8.copy_from_slice(&cd[0..8]);
    let mut acc = u64::from_le_bytes(s8) ^ nonce;
    for (i, slot) in scratch.iter_mut().enumerate() {
        acc = acc
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407 ^ (i as u64));
        *slot = acc;
    }
    for _ in 0..(p.iterations as usize) {
        let idx = (acc as usize) % n;
        acc = acc.rotate_left(13) ^ scratch[idx].wrapping_mul(0x9E37_79B9_7F4A_7C15);
        scratch[idx] = acc;
    }
    let mut h = Sha256::new();
    h.update(PZ_MEM_DOMAIN);
    h.update(cd);
    h.update(nonce.to_le_bytes());
    h.update(acc.to_le_bytes());
    h.finalize().into()
}
fn pz_parallel(cd: &[u8; 32], nonce: u64, p: &PuzzleProfileMirror) -> [u8; 32] {
    let p = p.clamped();
    let mut h = Sha256::new();
    h.update(PZ_PAR_DOMAIN);
    h.update(cd);
    h.update(nonce.to_le_bytes());
    for lane in 0..p.lanes {
        let mut lh = Sha256::new();
        lh.update(cd);
        lh.update(nonce.to_le_bytes());
        lh.update([lane]);
        let d: [u8; 32] = lh.finalize().into();
        h.update(d);
    }
    h.finalize().into()
}
fn pz_verify_digest(cd: &[u8; 32], cand: &[u8; 32], apd: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(PZ_VERIFY_DOMAIN);
    h.update(cd);
    h.update(cand);
    h.update(apd);
    h.finalize().into()
}
fn pz_finality_digest(cd: &[u8; 32], seed: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(PZ_FINALITY_DOMAIN);
    h.update(cd);
    h.update(seed);
    h.finalize().into()
}

/// Solve the assigned puzzle for one candidate (mirror of node solve_dev).
fn pz_solve_for_candidate(
    net: u8,
    h: u64,
    role: u8,
    cand: &RoleCandidateMirror,
    seed: &[u8; 32],
    profile: &PuzzleProfileMirror,
) -> Option<PuzzleSolutionMirror> {
    let candidate_digest: [u8; 32] = {
        let mut hh = Sha256::new();
        hh.update(cand.serialize());
        hh.finalize().into()
    };
    let mode = pz_assign_mode(
        net,
        h,
        role,
        &cand.solver_pkh,
        &cand.ticket_digest,
        &cand.assignment_proof_digest,
        seed,
    );
    let cd = pz_challenge_digest(
        net,
        h,
        role,
        &cand.solver_pkh,
        &cand.ticket_digest,
        &cand.assignment_proof_digest,
        &candidate_digest,
        seed,
        mode,
        profile,
    );
    match mode {
        3 => Some(PuzzleSolutionMirror {
            mode,
            nonce: 0,
            proof_digest: pz_verify_digest(&cd, &candidate_digest, &cand.assignment_proof_digest),
        }),
        4 => Some(PuzzleSolutionMirror {
            mode,
            nonce: 0,
            proof_digest: pz_finality_digest(&cd, seed),
        }),
        _ => {
            let bits = profile.anchor_bits as u32;
            for nonce in 0..PZ_SOLVE_CAP {
                let out = match mode {
                    0 => pz_anchor(&cd, nonce),
                    1 => pz_memory(&cd, nonce, profile),
                    _ => pz_parallel(&cd, nonce, profile),
                };
                if pz_leading_zero_bits(&out) >= bits {
                    return Some(PuzzleSolutionMirror {
                        mode,
                        nonce,
                        proof_digest: out,
                    });
                }
            }
            None
        }
    }
}

/// Pool puzzle-work enforcement gate (mirror node `puzzle_work_enforced`).
pub fn pool_puzzle_work_enforced(height: u64) -> bool {
    if network_id_from_env() == 0 {
        return false;
    }
    let active = match env::var("IRIUM_POAWX_PUZZLE_WORK_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        Some(h) => height >= h,
        None => false,
    };
    let required = env::var("IRIUM_POAWX_PUZZLE_WORK_REQUIRED")
        .map(|v| v.trim() == "1")
        .unwrap_or(false);
    active && required
}

/// Build the 3 per-role puzzle solutions from the (selected) candidate set. None
/// if any role lacks a candidate or cannot be solved (caller fails closed).
pub fn build_pool_puzzle_proofs(
    network_id: u8,
    height: u64,
    prev_hash: &[u8; 32],
    cs: &CandidateSetMirror,
) -> Option<[PuzzleSolutionMirror; 3]> {
    let profile = puzzle_default_profile();
    let roles = [
        ROLE_COMPUTE_CONTRIBUTOR,
        ROLE_VERIFY_CONTRIBUTOR,
        ROLE_SUPPORT_CONTRIBUTOR,
    ];
    let mut out: Vec<PuzzleSolutionMirror> = Vec::with_capacity(3);
    for role in roles {
        let cand = cs.best_for_role(role)?;
        out.push(pz_solve_for_candidate(
            network_id, height, role, cand, prev_hash, &profile,
        )?);
    }
    Some([out[0], out[1], out[2]])
}

/// ── Phase 21H: finality-committee proof bundling (pool side) ────────────────
/// The pool does NOT sign votes (no member keys) and does NOT verify finality
/// (the node is authoritative). It BUNDLES collected member-signed votes into a
/// byte-identical FinalityProofMirror and attaches it; fail-closed if none. Votes
/// are real member secp256k1 signatures collected out-of-band / via RPC.
pub const FINALITY_SECTION_MAGIC: &[u8; 4] = b"FIN1";
pub const FINALITY_VOTE_WIRE: usize = 1 + 1 + 8 + 32 + 32 + 8 + 20 + 33 + 32 + 1 + 64; // 232
const FIN_VOTE_MEMBER_PKH_OFF: usize = 1 + 1 + 8 + 32 + 32 + 8; // 82
const FIN_VOTE_PARENT_OFF: usize = 1 + 1 + 8 + 32; // 42
const FIN_VOTE_EPOCH_OFF: usize = 1 + 1 + 8 + 32 + 32; // 74
const FIN_VOTE_HEIGHT_OFF: usize = 2;
const FIN_VOTE_BLOCK_OFF: usize = 10;

/// Pool finality-committee enforcement gate (mirror node).
pub fn pool_finality_committee_enforced(height: u64) -> bool {
    if network_id_from_env() == 0 {
        return false;
    }
    let active = match env::var("IRIUM_POAWX_FINALITY_COMMITTEE_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        Some(h) => height >= h,
        None => false,
    };
    let required = env::var("IRIUM_POAWX_FINALITY_COMMITTEE_REQUIRED")
        .map(|v| v.trim() == "1")
        .unwrap_or(false);
    active && required
}

/// Mirror of node finality threshold (num, den), default 1/1.
pub fn pool_finality_threshold() -> (u16, u16) {
    let num = env::var("IRIUM_POAWX_FINALITY_THRESHOLD_NUM")
        .ok()
        .and_then(|v| v.trim().parse::<u16>().ok())
        .filter(|n| *n >= 1)
        .unwrap_or(1);
    let den = env::var("IRIUM_POAWX_FINALITY_THRESHOLD_DEN")
        .ok()
        .and_then(|v| v.trim().parse::<u16>().ok())
        .filter(|d| *d >= 1)
        .unwrap_or(1);
    (num, den)
}

/// A bundled finality proof (byte-identical to node FinalityProofV1 wire). Votes
/// are stored as raw 232-byte records (sorted canonical by member_pkh, deduped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalityProofMirror {
    pub network_id: u8,
    pub target_height: u64,
    pub block_hash: [u8; 32],
    pub parent_hash: [u8; 32],
    pub committee_epoch: u64,
    pub threshold_num: u16,
    pub threshold_den: u16,
    votes: Vec<[u8; FINALITY_VOTE_WIRE]>,
}

impl FinalityProofMirror {
    pub fn vote_count(&self) -> usize {
        self.votes.len()
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(88 + self.votes.len() * FINALITY_VOTE_WIRE);
        o.push(1u8); // version
        o.push(self.network_id);
        o.extend_from_slice(&self.target_height.to_le_bytes());
        o.extend_from_slice(&self.block_hash);
        o.extend_from_slice(&self.parent_hash);
        o.extend_from_slice(&self.committee_epoch.to_le_bytes());
        o.extend_from_slice(&self.threshold_num.to_le_bytes());
        o.extend_from_slice(&self.threshold_den.to_le_bytes());
        o.extend_from_slice(&(self.votes.len() as u16).to_le_bytes());
        for v in &self.votes {
            o.extend_from_slice(v);
        }
        o
    }
}

/// Process-global pool finality-vote cache: hex vote records keyed by height.
pub fn pool_finality_vote_cache() -> &'static std::sync::Mutex<BTreeMap<u64, Vec<String>>> {
    static C: std::sync::OnceLock<std::sync::Mutex<BTreeMap<u64, Vec<String>>>> =
        std::sync::OnceLock::new();
    C.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
}

/// Bundle collected member votes for (height, block_hash) into a canonical proof.
/// None if no matching vote (caller fails closed; the node enforces the threshold).
pub fn build_pool_finality_proof(
    network_id: u8,
    height: u64,
    block_hash: &[u8; 32],
    num: u16,
    den: u16,
) -> Option<FinalityProofMirror> {
    let cache = pool_finality_vote_cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let hexes = cache.get(&height).cloned().unwrap_or_default();
    drop(cache);
    let mut by_member: BTreeMap<[u8; 20], [u8; FINALITY_VOTE_WIRE]> = BTreeMap::new();
    let mut parent_hash = [0u8; 32];
    let mut committee_epoch = 0u64;
    let mut have_any = false;
    for hx in &hexes {
        let bytes = match hex::decode(hx.trim()) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if bytes.len() != FINALITY_VOTE_WIRE || bytes[0] != 1 || bytes[1] != network_id {
            continue;
        }
        let mut h8 = [0u8; 8];
        h8.copy_from_slice(&bytes[FIN_VOTE_HEIGHT_OFF..FIN_VOTE_HEIGHT_OFF + 8]);
        if u64::from_le_bytes(h8) != height {
            continue;
        }
        if &bytes[FIN_VOTE_BLOCK_OFF..FIN_VOTE_BLOCK_OFF + 32] != block_hash {
            continue;
        }
        let mut rec = [0u8; FINALITY_VOTE_WIRE];
        rec.copy_from_slice(&bytes);
        let mut pkh = [0u8; 20];
        pkh.copy_from_slice(&bytes[FIN_VOTE_MEMBER_PKH_OFF..FIN_VOTE_MEMBER_PKH_OFF + 20]);
        if !have_any {
            parent_hash.copy_from_slice(&bytes[FIN_VOTE_PARENT_OFF..FIN_VOTE_PARENT_OFF + 32]);
            h8.copy_from_slice(&bytes[FIN_VOTE_EPOCH_OFF..FIN_VOTE_EPOCH_OFF + 8]);
            committee_epoch = u64::from_le_bytes(h8);
            have_any = true;
        }
        by_member.entry(pkh).or_insert(rec); // dedup by member; BTreeMap => sorted
    }
    if by_member.is_empty() {
        return None;
    }
    Some(FinalityProofMirror {
        network_id,
        target_height: height,
        block_hash: *block_hash,
        parent_hash,
        committee_epoch,
        threshold_num: num,
        threshold_den: den,
        votes: by_member.into_values().collect(),
    })
}

/// ── Phase 22A: chain-committed admission (pool mirror) ──────────────────────
/// Byte-identical mirror of node AdmissionCommitmentV1 so the pool can build the
/// committed-admission root the node validates. The pool builds it from its admitted
/// cache (21E); the node re-validates everything.
pub const COMMITTED_ADMISSION_SECTION_MAGIC: &[u8; 4] = b"CAC1";
pub const ADMISSION_COMMITMENT_WIRE: usize = 1 + 1 + 8 + 8 + 32 + 32 + 2 + 8 + 32; // 124
const COMMITMENT_DOMAIN: &[u8] = b"IRIUM_POAWX_ADMISSION_COMMITMENT_V1";
pub const DEFAULT_COMMITTED_ADMISSION_WINDOW: u64 = 64;

pub fn committed_admission_window() -> u64 {
    env::var("IRIUM_POAWX_COMMITTED_ADMISSION_WINDOW")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|w| *w >= 1)
        .unwrap_or(DEFAULT_COMMITTED_ADMISSION_WINDOW)
}

/// Pool committed-admission enforcement gate (mirror node).
pub fn pool_committed_admission_enforced(height: u64) -> bool {
    if network_id_from_env() == 0 {
        return false;
    }
    let active = match env::var("IRIUM_POAWX_COMMITTED_ADMISSION_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        Some(h) => height >= h,
        None => false,
    };
    let required = env::var("IRIUM_POAWX_COMMITTED_ADMISSION_REQUIRED")
        .map(|v| v.trim() == "1")
        .unwrap_or(false);
    active && required
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionCommitmentMirror {
    pub network_id: u8,
    pub target_height: u64,
    pub commit_height: u64,
    pub seed: [u8; 32],
    pub candidate_admission_root: [u8; 32],
    pub candidate_count: u16,
    pub window_id: u64,
    pub digest: [u8; 32],
}

impl AdmissionCommitmentMirror {
    pub fn from_candidate_set(cs: &CandidateSetMirror, commit_height: u64) -> Self {
        let network_id = cs.network_id;
        let target_height = cs.target_height;
        let seed = cs.seed;
        let candidate_admission_root = cs.root();
        let candidate_count = cs.candidates.len().min(u16::MAX as usize) as u16;
        let window_id = target_height / committed_admission_window();
        let mut h = Sha256::new();
        h.update(COMMITMENT_DOMAIN);
        h.update([1u8]); // version
        h.update([network_id]);
        h.update(target_height.to_le_bytes());
        h.update(commit_height.to_le_bytes());
        h.update(seed);
        h.update(candidate_admission_root);
        h.update(candidate_count.to_le_bytes());
        h.update(window_id.to_le_bytes());
        let digest: [u8; 32] = h.finalize().into();
        Self {
            network_id,
            target_height,
            commit_height,
            seed,
            candidate_admission_root,
            candidate_count,
            window_id,
            digest,
        }
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(ADMISSION_COMMITMENT_WIRE);
        o.push(1u8); // version
        o.push(self.network_id);
        o.extend_from_slice(&self.target_height.to_le_bytes());
        o.extend_from_slice(&self.commit_height.to_le_bytes());
        o.extend_from_slice(&self.seed);
        o.extend_from_slice(&self.candidate_admission_root);
        o.extend_from_slice(&self.candidate_count.to_le_bytes());
        o.extend_from_slice(&self.window_id.to_le_bytes());
        o.extend_from_slice(&self.digest);
        o
    }
}

/// Build the committed admission for `target` (= commit_height+1) from the pool
/// admitted cache (21E), freeze seed = `seed`. None if no admitted candidates
/// (caller fails closed).
pub fn build_pool_committed_admission(
    network_id: u8,
    target: u64,
    seed: &[u8; 32],
) -> Option<AdmissionCommitmentMirror> {
    let cs = build_admitted_candidate_set(
        &pool_admitted_cache()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&target)
            .cloned()
            .unwrap_or_default(),
        network_id,
        target,
        seed,
    )?;
    Some(AdmissionCommitmentMirror::from_candidate_set(
        &cs,
        target.saturating_sub(1),
    ))
}

/// Phase 24H: derive role_reward solvers from the node-validated admitted candidate
/// set (best candidate per role), so the pool keys role rewards + the per-role V2
/// proofs (looked up by role_reward.solver) to the actual admitted miners instead of
/// the pool primary_pkh. None (fail closed) if any role has no admitted candidate.
/// The pool holds no miner secret.
pub fn pool_role_reward_from_admitted(
    network_id: u8,
    height: u64,
    prev_hash: &[u8; 32],
) -> Option<RoleRewardMirror> {
    let cs = build_pool_candidate_set_for_height(network_id, height, prev_hash)?;
    Some(RoleRewardMirror {
        compute_contributor_pkh: cs.best_for_role(ROLE_COMPUTE_CONTRIBUTOR)?.solver_pkh,
        verify_contributor_pkh: cs.best_for_role(ROLE_VERIFY_CONTRIBUTOR)?.solver_pkh,
        support_contributor_pkh: cs.best_for_role(ROLE_SUPPORT_CONTRIBUTOR)?.solver_pkh,
    })
}

pub fn build_synthetic_phase20_ext(
    network_id: u8,
    height: u64,
    prev_hash: &[u8; 32],
    primary_pkh: &[u8; 20],
    workers: &[[u8; 20]],
    fee: Option<(u16, [u8; 20])>,
) -> Option<Phase20ReceiptExtMirror> {
    if network_id == 0 || !synthetic_role_claims_enabled() {
        return None;
    }
    // Fee terms: official (None) => 0/zero; third-party => only when valid (cap +
    // nonzero pkh), else fail closed to official 0%.
    let (fee_bps, fee_pkh) = match fee {
        Some((b, p)) if b >= 1 && b <= THIRD_PARTY_FEE_CAP_BPS && p != [0u8; 20] => (b, p),
        _ => (0u16, [0u8; 20]),
    };
    // Step 6A: when hidden-precommit is active, derive secret/nonce WITHOUT prev_hash
    // (so block H-1 can compute block H's commitments) and set commitment_hash; the
    // claim still binds prev_hash via claim_digest. When inactive, keep the prior
    // prev-hash-derived secret/nonce + no commitment (Steps 5A/5B unchanged).
    // Phase 24H: under all-gates candidate admission, the per-role solvers (and thus
    // role_reward + the per-role V2 lookup) are derived from the node-validated
    // admitted candidate set, NOT the pool primary_pkh. Fail closed if any role lacks
    // an admitted candidate.
    let admitted_cs = if pool_candidate_admission_enforced(height) {
        Some(build_pool_candidate_set_for_height(
            network_id, height, prev_hash,
        )?)
    } else {
        None
    };
    let solvers: [[u8; 20]; 3] = match &admitted_cs {
        Some(cs) => [
            match cs.best_for_role(ROLE_COMPUTE_CONTRIBUTOR) {
                Some(c) => c.solver_pkh,
                None => return None,
            },
            match cs.best_for_role(ROLE_VERIFY_CONTRIBUTOR) {
                Some(c) => c.solver_pkh,
                None => return None,
            },
            match cs.best_for_role(ROLE_SUPPORT_CONTRIBUTOR) {
                Some(c) => c.solver_pkh,
                None => return None,
            },
        ],
        None => [
            synth_role_solver(primary_pkh, workers, 0),
            synth_role_solver(primary_pkh, workers, 1),
            synth_role_solver(primary_pkh, workers, 2),
        ],
    };
    let hp = hidden_precommit_active(height);
    let mk = |role_id: u8, idx: usize| -> PoawxRoleClaimMirror {
        let lane_id = assign_lane_id(network_id, height, prev_hash, role_id, 0);
        let solver = solvers[idx];
        let (secret, nonce) = if hp {
            synth_role_secret_nonce(network_id, height, role_id)
        } else {
            (
                synth_field(b"secret", network_id, height, prev_hash, role_id),
                synth_field(b"nonce", network_id, height, prev_hash, role_id),
            )
        };
        let claim_digest = role_claim_digest(
            network_id, height, prev_hash, role_id, lane_id, &solver, &nonce, &secret,
        );
        let commitment_hash = if hp {
            Some(role_precommit_commitment(&secret, &nonce))
        } else {
            None
        };
        PoawxRoleClaimMirror {
            role_id,
            lane_id,
            solver_pkh: solver,
            nonce,
            secret,
            claim_digest,
            commitment_hash,
        }
    };
    let compute_claim = mk(ROLE_COMPUTE_CONTRIBUTOR, 0);
    let verify_claim = mk(ROLE_VERIFY_CONTRIBUTOR, 1);
    let support_claim = mk(ROLE_SUPPORT_CONTRIBUTOR, 2);
    // Commit the NEXT block's leaves (this block H commits height H+1).
    let precommit_root = if hp {
        Some(synthetic_precommit_root(
            network_id,
            height + 1,
            primary_pkh,
            workers,
        ))
    } else {
        None
    };
    let role_reward = RoleRewardMirror {
        compute_contributor_pkh: compute_claim.solver_pkh,
        verify_contributor_pkh: verify_claim.solver_pkh,
        support_contributor_pkh: support_claim.solver_pkh,
    };
    // Phase 21B: attach per-role ticket proofs when the pool ticket gate is on
    // (else the node fails closed). Off => None (byte-identical to pre-21B).
    let role_ticket_proofs = if pool_tickets_enforced(height) {
        Some(build_role_ticket_proofs(network_id, height, prev_hash, &role_reward))
    } else {
        None
    };
    // Phase 21C: attach per-role dominance weights when enforcement is on
    // (else the node fails closed). Off => None (byte-identical to pre-21C).
    let role_dominance_weights = if pool_anti_domination_enforced(height) {
        Some(pool_dominance_weights_for(primary_pkh, &role_reward))
    } else {
        None
    };
    // Phase 21D: attach the candidate set when enforcement is on (else None =>
    // byte-identical; node fails closed when required).
    let candidate_set = if pool_candidate_admission_enforced(height) {
        // Phase 21E: build strictly from node-ADMITTED candidates; fail closed
        // if the admitted cache is unavailable/empty (no fake set produced).
        match build_pool_candidate_set_for_height(network_id, height, prev_hash) {
            Some(cs) => Some(cs),
            None => return None,
        }
    } else if pool_candidate_set_enforced(height) {
        Some(build_pool_candidate_set(
            network_id,
            height,
            prev_hash,
            &role_reward,
        ))
    } else {
        None
    };
    // Phase 21F: solve + attach per-role puzzle proofs when enforced; fail
    // closed (no ext) if the candidate set/solution is unavailable.
    let role_puzzle_proofs = if pool_puzzle_work_enforced(height) {
        match candidate_set
            .as_ref()
            .and_then(|cs| build_pool_puzzle_proofs(network_id, height, prev_hash, cs))
        {
            Some(p) => Some(p),
            None => return None,
        }
    } else {
        None
    };
    // Phase 21H: bundle + attach the finality proof when enforced; fail closed
    // (no ext) if no collected committee votes are available.
    let finality_proof = if pool_finality_committee_enforced(height) {
        let (fnum, fden) = pool_finality_threshold();
        match build_pool_finality_proof(network_id, height, prev_hash, fnum, fden) {
            Some(p) => Some(p),
            None => return None,
        }
    } else {
        None
    };
    // Phase 22A: commit the NEXT height's admitted set (from the admitted cache)
    // when enforced; fail closed (no ext) if it cannot be built.
    let committed_admission = if pool_committed_admission_enforced(height) {
        match build_pool_committed_admission(network_id, height + 1, prev_hash) {
            Some(c) => Some(c),
            None => return None,
        }
    } else {
        None
    };
    // Phase 22E: under true-VRF enforcement, bundle the SELECTED candidates'
    // miner-supplied proofs from the admitted cache; fail closed if any is missing.
    let role_assignment_v2 = if pool_true_vrf_enforced(height) {
        match build_pool_true_vrf_section(height, prev_hash, &role_reward) {
            Some(p) => Some(p),
            None => return None,
        }
    } else {
        None
    };
    Some(Phase20ReceiptExtMirror {
        role_reward,
        compute_claim,
        verify_claim,
        support_claim,
        fee_bps,
        fee_pkh,
        precommit_root,
        role_ticket_proofs,
        role_dominance_weights,
        candidate_set,
        role_puzzle_proofs,
        finality_proof,
        committed_admission,
        role_assignment_v2,
    })
}

/// Deterministic synthetic secret/nonce for (net, height, role) — prev-hash-free so
/// a precommit built at block H-1 and the reveal at block H agree. Testnet/devnet.
fn synth_role_secret_nonce(network_id: u8, height: u64, role_id: u8) -> ([u8; 32], [u8; 32]) {
    let mk = |tag: &[u8]| -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"IRIUM_POAWX_SYNTHETIC_HP_V1");
        h.update(tag);
        h.update([network_id]);
        h.update(height.to_le_bytes());
        h.update([role_id]);
        h.finalize().into()
    };
    (mk(b"secret"), mk(b"nonce"))
}

/// Deterministic synthetic solver pkh for role index `idx`.
fn synth_role_solver(primary_pkh: &[u8; 20], workers: &[[u8; 20]], idx: usize) -> [u8; 20] {
    if workers.is_empty() {
        *primary_pkh
    } else {
        workers[idx % workers.len()]
    }
}

/// Synthetic hidden-precommit root committing `target_height`'s 3 role-claim leaves
/// (matches what the reveal at `target_height` reconstructs).
pub fn synthetic_precommit_root(
    network_id: u8,
    target_height: u64,
    primary_pkh: &[u8; 20],
    workers: &[[u8; 20]],
) -> [u8; 32] {
    let roles = [
        ROLE_COMPUTE_CONTRIBUTOR,
        ROLE_VERIFY_CONTRIBUTOR,
        ROLE_SUPPORT_CONTRIBUTOR,
    ];
    let leaves: Vec<[u8; 32]> = roles
        .iter()
        .enumerate()
        .map(|(i, &role)| {
            let (s, n) = synth_role_secret_nonce(network_id, target_height, role);
            let c = role_precommit_commitment(&s, &n);
            let solver = synth_role_solver(primary_pkh, workers, i);
            role_precommit_leaf(network_id, target_height, role, &solver, &c)
        })
        .collect();
    role_precommit_root(&leaves)
}

/// Extract the three RoleReward pkhs from a hex-encoded `Phase20ReceiptExt`
/// (`version(1) || role_reward(60) || …`). Used by the coinbase builder without
/// a full deserialize. Returns None on malformed/short input (fail-closed).
pub fn role_reward_pkhs_from_ext_hex(ext_hex: &str) -> Option<([u8; 20], [u8; 20], [u8; 20])> {
    let b = hex::decode(ext_hex).ok()?;
    if b.len() < 1 + 60 || b[0] != PHASE20_EXT_VERSION {
        return None;
    }
    let mut c = [0u8; 20];
    let mut v = [0u8; 20];
    let mut s = [0u8; 20];
    c.copy_from_slice(&b[1..21]);
    v.copy_from_slice(&b[21..41]);
    s.copy_from_slice(&b[41..61]);
    Some((c, v, s))
}

// ── Phase 20 Step 6B: local/testnet role precommit + reveal collection ───────
//
// Real (non-synthetic) role data for Phase 20 production. A miner submits a
// PRECOMMIT before the target height (hides secret/nonce via commitment_hash) and
// a REVEAL at the target height (carries secret/nonce + claim fields). The pool
// collects them in a height-keyed store, selects exactly one canonical reveal per
// role (COMPUTE/VERIFY/SUPPORT), and produces the Phase 20 ext from them. Uses the
// Step 6A primitives (one hashing model). Loopback-only, testnet/devnet-gated,
// mainnet hard-off. NOT public networking — submissions arrive on the existing
// loopback delegation server, operator-mediated like the delegation flow.

/// Window (in heights) beyond which stale precommits/reveals are pruned.
pub const ROLE_PROTOCOL_HEIGHT_WINDOW: u64 = 64;

/// Whether the local/testnet role precommit+reveal protocol is enabled
/// (`IRIUM_POAWX_ROLE_PROTOCOL_ENABLED=1`). Mainnet hard-off; default off.
pub fn role_protocol_enabled() -> bool {
    if network_id_from_env() == 0 {
        return false; // mainnet
    }
    env::var("IRIUM_POAWX_ROLE_PROTOCOL_ENABLED")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}

fn decode20(s: &str) -> Option<[u8; 20]> {
    let b = hex::decode(s.trim()).ok()?;
    if b.len() != 20 {
        return None;
    }
    let mut a = [0u8; 20];
    a.copy_from_slice(&b);
    Some(a)
}

fn is_production_role(role_id: u8) -> bool {
    matches!(
        role_id,
        ROLE_COMPUTE_CONTRIBUTOR | ROLE_VERIFY_CONTRIBUTOR | ROLE_SUPPORT_CONTRIBUTOR
    )
}

/// Role precommit wire DTO (loopback JSON). HIDES secret/nonce — only the
/// `commitment_hash` is carried. `worker` is optional identity metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolePrecommitDto {
    pub network_id: u8,
    pub target_height: u64,
    pub role_id: u8,
    pub solver_pkh: String,
    pub commitment_hash: String,
    #[serde(default)]
    pub worker: String,
}

/// Role reveal wire DTO (loopback JSON). Carries secret/nonce + the claim fields
/// `validate_role_claim` needs; the secret/nonce reconstruct `commitment_hash`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleRevealDto {
    pub network_id: u8,
    pub target_height: u64,
    pub role_id: u8,
    pub lane_id: u8,
    pub solver_pkh: String,
    pub secret: String,
    pub nonce: String,
    pub commitment_hash: String,
    pub claim_digest: String,
    /// Phase 3 payout-bound role-work bundle (optional; empty => legacy claim-only).
    #[serde(default)]
    pub assignment_public_key: String,
    #[serde(default)]
    pub assignment_proof: String,
    #[serde(default)]
    pub ticket_proof: String,
    #[serde(default)]
    pub puzzle_solution: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedPrecommit {
    pub network_id: u8,
    pub target_height: u64,
    pub role_id: u8,
    pub solver_pkh: [u8; 20],
    pub commitment_hash: [u8; 32],
}

impl ValidatedPrecommit {
    pub fn leaf(&self) -> [u8; 32] {
        role_precommit_leaf(
            self.network_id,
            self.target_height,
            self.role_id,
            &self.solver_pkh,
            &self.commitment_hash,
        )
    }
}

#[derive(Debug, Clone)]
pub struct ValidatedReveal {
    pub network_id: u8,
    pub target_height: u64,
    pub claim: PoawxRoleClaimMirror,
    /// Phase 3: the participant's payout-bound role-work proofs. `assignment_public_key`
    /// is Some iff a bundle was supplied AND hash160(it) == claim.solver_pkh was verified
    /// on ingest (the Phase 1 structural binding). The node verifies the full ECVRF at
    /// connect_block; the pool only enforces the hash binding + carries the proofs.
    pub assignment_public_key: Option<[u8; 33]>,
    pub assignment_proof: Vec<u8>,
    pub ticket_proof: Vec<u8>,
    pub puzzle_solution: Vec<u8>,
}

impl RolePrecommitDto {
    /// Validate a precommit against the expected network. Checks role id, hex
    /// fields, and network. Does NOT (cannot) see the secret/nonce.
    pub fn validate(&self, expected_network: u8) -> Result<ValidatedPrecommit, String> {
        if expected_network == 0 {
            return Err("role precommit: mainnet hard-off".to_string());
        }
        if self.network_id != expected_network {
            return Err("role precommit: network_id mismatch".to_string());
        }
        if !is_production_role(self.role_id) {
            return Err(format!("role precommit: bad role_id {}", self.role_id));
        }
        let solver_pkh = decode20(&self.solver_pkh).ok_or("role precommit: bad solver_pkh")?;
        let commitment_hash =
            decode32(&self.commitment_hash).ok_or("role precommit: bad commitment_hash")?;
        Ok(ValidatedPrecommit {
            network_id: self.network_id,
            target_height: self.target_height,
            role_id: self.role_id,
            solver_pkh,
            commitment_hash,
        })
    }
}

impl RoleRevealDto {
    /// Validate a reveal: hex fields, role, network, AND the commitment binding —
    /// `commitment_hash == role_precommit_commitment(secret,nonce)` — so a mutated
    /// secret/nonce fails closed. Produces a `PoawxRoleClaimMirror`.
    pub fn validate(&self, expected_network: u8) -> Result<ValidatedReveal, String> {
        if expected_network == 0 {
            return Err("role reveal: mainnet hard-off".to_string());
        }
        if self.network_id != expected_network {
            return Err("role reveal: network_id mismatch".to_string());
        }
        if !is_production_role(self.role_id) {
            return Err(format!("role reveal: bad role_id {}", self.role_id));
        }
        let solver_pkh = decode20(&self.solver_pkh).ok_or("role reveal: bad solver_pkh")?;
        let secret = decode32(&self.secret).ok_or("role reveal: bad secret")?;
        let nonce = decode32(&self.nonce).ok_or("role reveal: bad nonce")?;
        let commitment_hash =
            decode32(&self.commitment_hash).ok_or("role reveal: bad commitment_hash")?;
        let claim_digest = decode32(&self.claim_digest).ok_or("role reveal: bad claim_digest")?;
        if role_precommit_commitment(&secret, &nonce) != commitment_hash {
            return Err("role reveal: commitment_hash != H(secret||nonce)".to_string());
        }
        // Phase 3: optional payout-bound role-work bundle. Enforce the Phase 1 structural
        // binding at ingest: hash160(assignment_public_key) MUST equal claim.solver_pkh, so
        // a reveal can only attribute a role to the key that will prove it. A distinct
        // participant proving with its own payout key passes; a producer naming an address
        // it does not hold the proving key for is rejected here (the node then verifies the
        // full ECVRF at connect_block).
        let (assignment_public_key, assignment_proof, ticket_proof, puzzle_solution) =
            if self.assignment_public_key.trim().is_empty() {
                (None, Vec::new(), Vec::new(), Vec::new())
            } else {
                let apk =
                    decode33(&self.assignment_public_key).ok_or("role reveal: bad assignment_public_key")?;
                let a_pkh = {
                    let rip = ripemd::Ripemd160::digest(Sha256::digest(apk));
                    let mut o = [0u8; 20];
                    o.copy_from_slice(&rip);
                    o
                };
                if a_pkh != solver_pkh {
                    return Err(
                        "role reveal: assignment_public_key does not hash to solver_pkh (Phase 1 binding)"
                            .to_string(),
                    );
                }
                let ap = hex::decode(self.assignment_proof.trim())
                    .map_err(|_| "role reveal: bad assignment_proof hex".to_string())?;
                let tp = hex::decode(self.ticket_proof.trim())
                    .map_err(|_| "role reveal: bad ticket_proof hex".to_string())?;
                let ps = hex::decode(self.puzzle_solution.trim())
                    .map_err(|_| "role reveal: bad puzzle_solution hex".to_string())?;
                (Some(apk), ap, tp, ps)
            };
        Ok(ValidatedReveal {
            network_id: self.network_id,
            target_height: self.target_height,
            claim: PoawxRoleClaimMirror {
                role_id: self.role_id,
                lane_id: self.lane_id,
                solver_pkh,
                nonce,
                secret,
                claim_digest,
                commitment_hash: Some(commitment_hash),
            },
            assignment_public_key,
            assignment_proof,
            ticket_proof,
            puzzle_solution,
        })
    }
}

/// In-memory, height-keyed store of collected precommits + reveals. Loopback-fed.
#[derive(Default)]
pub struct RoleProtocolStore {
    precommits: Mutex<BTreeMap<(u64, u8, [u8; 20]), ValidatedPrecommit>>,
    reveals: Mutex<BTreeMap<(u64, u8, [u8; 20]), ValidatedReveal>>,
}

impl RoleProtocolStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept a validated precommit. Duplicate (same target/role/solver) with the
    /// SAME commitment is idempotent; with a DIFFERENT commitment is rejected
    /// (deterministic: first-writer-wins, no silent overwrite).
    pub fn add_precommit(&self, p: ValidatedPrecommit) -> Result<(), String> {
        let mut g = self.precommits.lock().unwrap_or_else(|e| e.into_inner());
        let k = (p.target_height, p.role_id, p.solver_pkh);
        match g.get(&k) {
            Some(existing) if existing.commitment_hash != p.commitment_hash => {
                return Err("role precommit: duplicate with different commitment".to_string());
            }
            Some(_) => return Ok(()), // idempotent
            None => {}
        }
        g.insert(k, p);
        Ok(())
    }

    /// Accept a validated reveal — ONLY if a matching precommit (same target/role/
    /// solver and commitment) exists. Duplicate same-claim reveal is idempotent;
    /// a differing duplicate is rejected.
    pub fn add_reveal(&self, r: ValidatedReveal) -> Result<(), String> {
        let k = (r.target_height, r.claim.role_id, r.claim.solver_pkh);
        {
            let pg = self.precommits.lock().unwrap_or_else(|e| e.into_inner());
            match pg.get(&k) {
                Some(pc) if Some(pc.commitment_hash) == r.claim.commitment_hash => {}
                _ => return Err("role reveal: no matching precommit".to_string()),
            }
        }
        let mut g = self.reveals.lock().unwrap_or_else(|e| e.into_inner());
        match g.get(&k) {
            Some(existing) if existing.claim != r.claim => {
                return Err("role reveal: duplicate with different claim".to_string());
            }
            Some(_) => return Ok(()),
            None => {}
        }
        g.insert(k, r);
        Ok(())
    }

    /// Drop precommits/reveals targeting heights at/below `tip - WINDOW`.
    pub fn prune(&self, tip_height: u64) {
        let cutoff = tip_height.saturating_sub(ROLE_PROTOCOL_HEIGHT_WINDOW);
        self.precommits
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|k, _| k.0 > cutoff);
        self.reveals
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|k, _| k.0 > cutoff);
    }

    /// Deterministic one-per-role precommit selection for `target_height`: the
    /// precommit with the smallest (solver_pkh, commitment_hash). None if absent.
    pub fn canonical_precommit(
        &self,
        target_height: u64,
        role_id: u8,
    ) -> Option<ValidatedPrecommit> {
        let g = self.precommits.lock().unwrap_or_else(|e| e.into_inner());
        g.iter()
            .filter(|((t, r, _), _)| *t == target_height && *r == role_id)
            .map(|(_, v)| v.clone())
            .min_by(|a, b| {
                (a.solver_pkh, a.commitment_hash).cmp(&(b.solver_pkh, b.commitment_hash))
            })
    }

    /// The precommit root committing `target_height`'s canonical leaves (one per
    /// role). None unless all three roles have a precommit.
    pub fn precommit_root_for(&self, target_height: u64) -> Option<[u8; 32]> {
        let roles = [
            ROLE_COMPUTE_CONTRIBUTOR,
            ROLE_VERIFY_CONTRIBUTOR,
            ROLE_SUPPORT_CONTRIBUTOR,
        ];
        let mut leaves = Vec::with_capacity(3);
        for r in roles {
            leaves.push(self.canonical_precommit(target_height, r)?.leaf());
        }
        Some(role_precommit_root(&leaves))
    }

    /// Select exactly one valid reveal per role for `target_height`, each matching
    /// that role's canonical precommit. Returns [compute, verify, support] or None
    /// if any role is missing a matching reveal.
    pub fn select_reveals(&self, target_height: u64) -> Option<[ValidatedReveal; 3]> {
        let roles = [
            ROLE_COMPUTE_CONTRIBUTOR,
            ROLE_VERIFY_CONTRIBUTOR,
            ROLE_SUPPORT_CONTRIBUTOR,
        ];
        let mut picked: Vec<ValidatedReveal> = Vec::with_capacity(3);
        for r in roles {
            let pc = self.canonical_precommit(target_height, r)?;
            let g = self.reveals.lock().unwrap_or_else(|e| e.into_inner());
            let rv = g.get(&(target_height, r, pc.solver_pkh)).cloned()?;
            if rv.claim.commitment_hash != Some(pc.commitment_hash) {
                return None;
            }
            picked.push(rv);
        }
        Some([picked[0].clone(), picked[1].clone(), picked[2].clone()])
    }

    /// Phase 3 M2: per role, among the collected BUNDLED reveals (those carrying a
    /// payout-bound assignment proof), select the winner by genuine self-VRF score
    /// (first 8 bytes LE of the assignment proof's vrf_output) -- the un-grindable
    /// competition. The pool admits all valid submissions and simply picks the highest
    /// score; it never assigns a role itself. Returns the 3 winners (compute/verify/
    /// support) or None if any role has no bundled submission.
    pub fn best_bundled_reveals(&self, target_height: u64) -> Option<[ValidatedReveal; 3]> {
        let roles = [
            ROLE_COMPUTE_CONTRIBUTOR,
            ROLE_VERIFY_CONTRIBUTOR,
            ROLE_SUPPORT_CONTRIBUTOR,
        ];
        let g = self.reveals.lock().unwrap_or_else(|e| e.into_inner());
        let mut out: Vec<ValidatedReveal> = Vec::with_capacity(3);
        for r in roles {
            let lo = (target_height, r, [0u8; 20]);
            let hi = (target_height, r, [0xffu8; 20]);
            let mut best: Option<(u64, [u8; 32], ValidatedReveal)> = None;
            for (_k, rv) in g.range(lo..=hi) {
                if rv.assignment_public_key.is_none() {
                    continue; // Phase 1: only payout-bound submissions compete
                }
                let proof = match AssignmentProofV2Mirror::deserialize(&rv.assignment_proof) {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                let mut sb = [0u8; 8];
                sb.copy_from_slice(&proof.vrf_output[0..8]);
                let score = u64::from_le_bytes(sb);
                // highest score wins; deterministic tie-break by full vrf_output then solver.
                let better = match &best {
                    None => true,
                    Some((bs, bo, _)) => {
                        score > *bs || (score == *bs && proof.vrf_output < *bo)
                    }
                };
                if better {
                    best = Some((score, proof.vrf_output, rv.clone()));
                }
            }
            out.push(best?.2);
        }
        Some([out[0].clone(), out[1].clone(), out[2].clone()])
    }
}

/// Build the Phase 20 reveal-side extension at block `height` from COLLECTED role
/// data: claims + RoleReward come from the selected reveals; `precommit_root`
/// commits the NEXT height's collected precommits. Returns None (caller falls back)
/// unless the role protocol is enabled and BOTH this height's reveals and the next
/// height's precommits are present. Mainnet hard-off. `fee` layers the (validated)
/// third-party fee terms; None/invalid => official 0%.
fn pool_hash160(b: &[u8]) -> [u8; 20] {
    let mut o = [0u8; 20];
    o.copy_from_slice(&ripemd::Ripemd160::digest(Sha256::digest(b)));
    o
}

/// Phase 3 M2: build the reveal-side ext from GENUINELY DISTINCT participants' collected
/// role-work bundles. Each role's reward is routed to the winning participant's own
/// solver pkh, and the participant's OWN assignment / ticket / puzzle proofs are attached
/// (not pool-synthesized). The winner per role is chosen by `best_bundled_reveals`
/// (self-VRF competition). The Phase 1 binding (solver_pkh == hash160(assignment_public_key)
/// == the assignment proof's own solver) is re-verified here; the node verifies the full
/// ECVRF at connect_block. Mainnet hard-off.
pub fn build_collected_bundle_ext(
    store: &RoleProtocolStore,
    network_id: u8,
    height: u64,
    fee: Option<(u16, [u8; 20])>,
    prev_hash: &[u8; 32],
) -> Option<Phase20ReceiptExtMirror> {
    let _ = prev_hash;
    if network_id == 0 || !role_protocol_enabled() {
        return None;
    }
    let winners = store.best_bundled_reveals(height)?;
    let next_root = store.precommit_root_for(height + 1)?;
    let mut assigns: Vec<AssignmentProofV2Mirror> = Vec::with_capacity(3);
    let mut tickets: Vec<TicketProofMirror> = Vec::with_capacity(3);
    let mut puzzles: Vec<PuzzleSolutionMirror> = Vec::with_capacity(3);
    for w in &winners {
        let apk = w.assignment_public_key?;
        let a = AssignmentProofV2Mirror::deserialize(&w.assignment_proof).ok()?;
        // Phase 1 binding, re-verified on the collected proof.
        if pool_hash160(&apk) != w.claim.solver_pkh
            || a.solver_pkh != w.claim.solver_pkh
            || a.assignment_public_key != apk
        {
            return None;
        }
        // Phase 4: full attachment -- the participant's own ticket + puzzle proofs.
        let t = TicketProofMirror::deserialize(&w.ticket_proof).ok()?;
        let p = PuzzleSolutionMirror::deserialize(&w.puzzle_solution).ok()?;
        // ticket must bind to the same participant identity as the reward.
        if t.miner_pkh != w.claim.solver_pkh {
            return None;
        }
        assigns.push(a);
        tickets.push(t);
        puzzles.push(p);
    }
    let (fee_bps, fee_pkh) = match fee {
        Some((b, p)) if b >= 1 && b <= THIRD_PARTY_FEE_CAP_BPS && p != [0u8; 20] => (b, p),
        _ => (0u16, [0u8; 20]),
    };
    let role_reward = RoleRewardMirror {
        compute_contributor_pkh: winners[0].claim.solver_pkh,
        verify_contributor_pkh: winners[1].claim.solver_pkh,
        support_contributor_pkh: winners[2].claim.solver_pkh,
    };
    Some(Phase20ReceiptExtMirror {
        role_reward,
        compute_claim: winners[0].claim.clone(),
        verify_claim: winners[1].claim.clone(),
        support_claim: winners[2].claim.clone(),
        fee_bps,
        fee_pkh,
        precommit_root: Some(next_root),
        role_ticket_proofs: Some([tickets[0].clone(), tickets[1].clone(), tickets[2].clone()]),
        role_dominance_weights: None,
        candidate_set: None,
        role_puzzle_proofs: Some([puzzles[0].clone(), puzzles[1].clone(), puzzles[2].clone()]),
        finality_proof: None,
        committed_admission: None,
        role_assignment_v2: Some([assigns[0].clone(), assigns[1].clone(), assigns[2].clone()]),
    })
}

pub fn build_collected_phase20_ext(
    store: &RoleProtocolStore,
    network_id: u8,
    height: u64,
    fee: Option<(u16, [u8; 20])>,
    primary_pkh: &[u8; 20],
    prev_hash: &[u8; 32],
) -> Option<Phase20ReceiptExtMirror> {
    if network_id == 0 || !role_protocol_enabled() {
        return None;
    }
    let reveals = store.select_reveals(height)?;
    let next_root = store.precommit_root_for(height + 1)?;
    let (fee_bps, fee_pkh) = match fee {
        Some((b, p)) if b >= 1 && b <= THIRD_PARTY_FEE_CAP_BPS && p != [0u8; 20] => (b, p),
        _ => (0u16, [0u8; 20]),
    };
    let role_reward = RoleRewardMirror {
        compute_contributor_pkh: reveals[0].claim.solver_pkh,
        verify_contributor_pkh: reveals[1].claim.solver_pkh,
        support_contributor_pkh: reveals[2].claim.solver_pkh,
    };
    // Phase 21B: attach per-role ticket proofs when the pool ticket gate is on.
    let role_ticket_proofs = if pool_tickets_enforced(height) {
        Some(build_role_ticket_proofs(network_id, height, prev_hash, &role_reward))
    } else {
        None
    };
    // Phase 21C: attach per-role dominance weights when enforcement is on
    // (else the node fails closed). Off => None (byte-identical to pre-21C).
    let role_dominance_weights = if pool_anti_domination_enforced(height) {
        Some(pool_dominance_weights_for(primary_pkh, &role_reward))
    } else {
        None
    };
    // Phase 21D: attach the candidate set when enforcement is on (else None =>
    // byte-identical; node fails closed when required).
    let candidate_set = if pool_candidate_admission_enforced(height) {
        // Phase 21E: build strictly from node-ADMITTED candidates; fail closed
        // if the admitted cache is unavailable/empty (no fake set produced).
        match build_pool_candidate_set_for_height(network_id, height, prev_hash) {
            Some(cs) => Some(cs),
            None => return None,
        }
    } else if pool_candidate_set_enforced(height) {
        Some(build_pool_candidate_set(
            network_id,
            height,
            prev_hash,
            &role_reward,
        ))
    } else {
        None
    };
    // Phase 21F: solve + attach per-role puzzle proofs when enforced; fail
    // closed (no ext) if the candidate set/solution is unavailable.
    let role_puzzle_proofs = if pool_puzzle_work_enforced(height) {
        match candidate_set
            .as_ref()
            .and_then(|cs| build_pool_puzzle_proofs(network_id, height, prev_hash, cs))
        {
            Some(p) => Some(p),
            None => return None,
        }
    } else {
        None
    };
    // Phase 21H: bundle + attach the finality proof when enforced; fail closed
    // (no ext) if no collected committee votes are available.
    let finality_proof = if pool_finality_committee_enforced(height) {
        let (fnum, fden) = pool_finality_threshold();
        match build_pool_finality_proof(network_id, height, prev_hash, fnum, fden) {
            Some(p) => Some(p),
            None => return None,
        }
    } else {
        None
    };
    // Phase 22A: commit the NEXT height's admitted set (from the admitted cache)
    // when enforced; fail closed (no ext) if it cannot be built.
    let committed_admission = if pool_committed_admission_enforced(height) {
        match build_pool_committed_admission(network_id, height + 1, prev_hash) {
            Some(c) => Some(c),
            None => return None,
        }
    } else {
        None
    };
    // Phase 22E: bundle SELECTED candidates' miner-supplied proofs; fail closed.
    let role_assignment_v2 = if pool_true_vrf_enforced(height) {
        match build_pool_true_vrf_section(height, prev_hash, &role_reward) {
            Some(p) => Some(p),
            None => return None,
        }
    } else {
        None
    };
    Some(Phase20ReceiptExtMirror {
        role_reward,
        compute_claim: reveals[0].claim.clone(),
        verify_claim: reveals[1].claim.clone(),
        support_claim: reveals[2].claim.clone(),
        fee_bps,
        fee_pkh,
        precommit_root: Some(next_root),
        role_ticket_proofs,
        role_dominance_weights,
        candidate_set,
        role_puzzle_proofs,
        finality_proof,
        committed_admission,
        role_assignment_v2,
    })
}

// ── Step 6C: testnet/devnet role precommit/reveal gossip plumbing ────────────
// Versioned gossip envelopes + a conservative validate→dedupe→store→(maybe)
// rebroadcast engine, reusing the Step 6B DTOs/store/primitives (one model).
// Mainnet hard-off; default off unless IRIUM_POAWX_ROLE_GOSSIP_ENABLED=1 AND the
// Step 6B role protocol is enabled.
//
// SCOPE: this is the payload + validation + in-memory relay layer. The live
// cross-process bridge (node P2P receive → this pool store, and pool → node
// broadcast) is intentionally NOT wired here — the node P2P bus and this store
// live in separate crates/processes joined only by RPC. The node side reserves
// the forward-compatible wire variants (`MessageType::PoawxRolePrecommit`/
// `PoawxRoleReveal`); a future step bridges them to this engine. No public
// ports, no live E2E in this step.

/// Versioned role-gossip envelope version. Receivers reject other versions.
pub const ROLE_GOSSIP_VERSION: u8 = 1;

/// Conservative upper bound on an accepted role-gossip payload (bytes). Anti-flood
/// guard; well above the largest legitimate reveal envelope.
pub const ROLE_GOSSIP_MAX_BYTES: usize = 4096;

/// Soft cap on the dedupe seen-set before it is cleared (the seen-set holds
/// opaque digests with no height, so it is bounded by size rather than pruned by
/// height; the store itself is pruned by height via `RoleProtocolStore::prune`).
pub const ROLE_GOSSIP_SEEN_CAP: usize = 8192;

/// Whether role-gossip ingest is enabled. Requires BOTH the Step 6B role protocol
/// (`IRIUM_POAWX_ROLE_PROTOCOL_ENABLED=1`, mainnet hard-off) AND the gossip opt-in
/// (`IRIUM_POAWX_ROLE_GOSSIP_ENABLED=1`). Default off.
pub fn role_gossip_enabled() -> bool {
    role_protocol_enabled()
        && env::var("IRIUM_POAWX_ROLE_GOSSIP_ENABLED")
            .map(|v| v.trim() == "1")
            .unwrap_or(false)
}

/// Versioned gossip envelope for a role precommit. Inner DTO is the Step 6B
/// `RolePrecommitDto` (hides secret/nonce).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolePrecommitGossip {
    pub gossip_version: u8,
    pub precommit: RolePrecommitDto,
}

/// Versioned gossip envelope for a role reveal. Inner DTO is the Step 6B
/// `RoleRevealDto` (carries secret/nonce + claim fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleRevealGossip {
    pub gossip_version: u8,
    pub reveal: RoleRevealDto,
}

impl RolePrecommitGossip {
    pub fn new(precommit: RolePrecommitDto) -> Self {
        Self {
            gossip_version: ROLE_GOSSIP_VERSION,
            precommit,
        }
    }
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > ROLE_GOSSIP_MAX_BYTES {
            return Err("role gossip: precommit payload too large".to_string());
        }
        let g: RolePrecommitGossip = serde_json::from_slice(bytes)
            .map_err(|e| format!("role gossip: malformed precommit: {e}"))?;
        if g.gossip_version != ROLE_GOSSIP_VERSION {
            return Err(format!(
                "role gossip: unsupported precommit version {}",
                g.gossip_version
            ));
        }
        Ok(g)
    }
}

impl RoleRevealGossip {
    pub fn new(reveal: RoleRevealDto) -> Self {
        Self {
            gossip_version: ROLE_GOSSIP_VERSION,
            reveal,
        }
    }
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > ROLE_GOSSIP_MAX_BYTES {
            return Err("role gossip: reveal payload too large".to_string());
        }
        let g: RoleRevealGossip = serde_json::from_slice(bytes)
            .map_err(|e| format!("role gossip: malformed reveal: {e}"))?;
        if g.gossip_version != ROLE_GOSSIP_VERSION {
            return Err(format!(
                "role gossip: unsupported reveal version {}",
                g.gossip_version
            ));
        }
        Ok(g)
    }
}

/// Stable, mutation-sensitive dedupe digest for a validated reveal. (Precommits
/// dedupe on `ValidatedPrecommit::leaf()`, which already binds net/height/role/
/// solver/commitment.)
fn reveal_gossip_digest(r: &ValidatedReveal) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"IRIUM_POAWX_ROLE_REVEAL_GOSSIP_V1");
    h.update([r.network_id]);
    h.update(r.target_height.to_le_bytes());
    h.update([r.claim.role_id, r.claim.lane_id]);
    h.update(r.claim.solver_pkh);
    h.update(r.claim.nonce);
    h.update(r.claim.secret);
    h.update(r.claim.claim_digest);
    if let Some(c) = r.claim.commitment_hash {
        h.update(c);
    }
    h.finalize().into()
}

/// Outcome of ingesting one gossip payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GossipOutcome {
    /// Valid and newly stored — the caller SHOULD rebroadcast to other peers.
    AcceptedNew,
    /// Valid but already seen — stored once already; do NOT rebroadcast (stops
    /// gossip-flood loops).
    Duplicate,
    /// Invalid / disabled / out-of-window / no-matching-precommit — NOT stored,
    /// NEVER rebroadcast.
    Rejected(String),
}

impl GossipOutcome {
    /// Only a newly-accepted payload is rebroadcast; duplicates and rejects are not.
    pub fn should_rebroadcast(&self) -> bool {
        matches!(self, GossipOutcome::AcceptedNew)
    }
    /// True if the payload is (now or already) in the store.
    pub fn accepted(&self) -> bool {
        matches!(self, GossipOutcome::AcceptedNew | GossipOutcome::Duplicate)
    }
}

/// Conservative role-gossip engine: validate first, dedupe by stable digest, store
/// only if valid and within the height window, never rebroadcast invalid. Holds
/// the seen-digest set separately from the store, so Step 6B store semantics are
/// unchanged.
#[derive(Default)]
pub struct RoleGossipEngine {
    seen: Mutex<std::collections::BTreeSet<[u8; 32]>>,
}

impl RoleGossipEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept `target_height` in `[tip, tip + ROLE_PROTOCOL_HEIGHT_WINDOW]`:
    /// precommits/reveals target the block being built (>= tip), and we bound how
    /// far ahead we accept. Older than `tip` is stale; further than the window is
    /// far-future.
    fn height_in_window(target: u64, tip: u64) -> bool {
        target >= tip && target <= tip.saturating_add(ROLE_PROTOCOL_HEIGHT_WINDOW)
    }

    fn mark_seen(&self, digest: [u8; 32]) {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        if seen.len() >= ROLE_GOSSIP_SEEN_CAP {
            seen.clear();
        }
        seen.insert(digest);
    }

    fn already_seen(&self, digest: &[u8; 32]) -> bool {
        self.seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(digest)
    }

    /// Ingest a role-precommit gossip payload. `expected_network` is the local
    /// network id (0 = mainnet hard-off); `tip` is the current chain tip height.
    pub fn ingest_precommit(
        &self,
        store: &RoleProtocolStore,
        bytes: &[u8],
        expected_network: u8,
        tip: u64,
    ) -> GossipOutcome {
        if expected_network == 0 || !role_gossip_enabled() {
            return GossipOutcome::Rejected("role gossip disabled".to_string());
        }
        let g = match RolePrecommitGossip::decode(bytes) {
            Ok(g) => g,
            Err(e) => return GossipOutcome::Rejected(e),
        };
        let v = match g.precommit.validate(expected_network) {
            Ok(v) => v,
            Err(e) => return GossipOutcome::Rejected(e),
        };
        if !Self::height_in_window(v.target_height, tip) {
            return GossipOutcome::Rejected(format!(
                "role gossip: precommit height {} outside window [{}, {}]",
                v.target_height,
                tip,
                tip.saturating_add(ROLE_PROTOCOL_HEIGHT_WINDOW)
            ));
        }
        let digest = v.leaf();
        if self.already_seen(&digest) {
            return GossipOutcome::Duplicate;
        }
        // store policy (Step 6B): duplicate-different-commitment fails closed.
        if let Err(e) = store.add_precommit(v) {
            return GossipOutcome::Rejected(e);
        }
        self.mark_seen(digest);
        GossipOutcome::AcceptedNew
    }

    /// Ingest a role-reveal gossip payload. A reveal without a matching precommit
    /// is rejected GRACEFULLY per Step 6B store policy (no crash, not stored, not
    /// rebroadcast).
    pub fn ingest_reveal(
        &self,
        store: &RoleProtocolStore,
        bytes: &[u8],
        expected_network: u8,
        tip: u64,
    ) -> GossipOutcome {
        if expected_network == 0 || !role_gossip_enabled() {
            return GossipOutcome::Rejected("role gossip disabled".to_string());
        }
        let g = match RoleRevealGossip::decode(bytes) {
            Ok(g) => g,
            Err(e) => return GossipOutcome::Rejected(e),
        };
        let v = match g.reveal.validate(expected_network) {
            Ok(v) => v,
            Err(e) => return GossipOutcome::Rejected(e),
        };
        if !Self::height_in_window(v.target_height, tip) {
            return GossipOutcome::Rejected(format!(
                "role gossip: reveal height {} outside window [{}, {}]",
                v.target_height,
                tip,
                tip.saturating_add(ROLE_PROTOCOL_HEIGHT_WINDOW)
            ));
        }
        let digest = reveal_gossip_digest(&v);
        if self.already_seen(&digest) {
            return GossipOutcome::Duplicate;
        }
        if let Err(e) = store.add_reveal(v) {
            return GossipOutcome::Rejected(e);
        }
        self.mark_seen(digest);
        GossipOutcome::AcceptedNew
    }

    /// Prune the backing store by height (mirrors the Step 6B window). The seen-set
    /// is size-bounded separately (see `mark_seen`).
    pub fn prune(&self, store: &RoleProtocolStore, tip: u64) {
        store.prune(tip);
    }
}

// ── Step 6D: pool↔node loopback RPC bridge ───────────────────────────────────
// The pool forwards locally-submitted role precommits/reveals to the node's
// loopback role-gossip endpoints (so the node can P2P-broadcast them), and
// fetches node-collected gossip before producing a block. All best-effort:
// failures log/return empty and never crash production. Gated by
// role_gossip_enabled() (mainnet hard-off). Defaults to the pool's existing node
// RPC base; override via IRIUM_POAWX_ROLE_GOSSIP_NODE_RPC.

/// Node RPC base for the role-gossip bridge.
pub fn node_role_gossip_rpc_base(default_rpc_base: &str) -> String {
    env::var("IRIUM_POAWX_ROLE_GOSSIP_NODE_RPC")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| default_rpc_base.to_string())
}

/// Best-effort: POST a validated local precommit (as a gossip envelope) to the
/// node for P2P broadcast. Never panics; ignores transport/HTTP errors.
pub async fn forward_precommit_to_node(rpc_base: &str, rpc_token: &str, dto: &RolePrecommitDto) {
    if !role_gossip_enabled() {
        return;
    }
    let url = format!(
        "{}/poawx/role-gossip/precommit",
        rpc_base.trim_end_matches('/')
    );
    if let Ok(client) = reqwest::Client::builder().build() {
        let body = RolePrecommitGossip::new(dto.clone()).encode();
        let _ = client
            .post(&url)
            .bearer_auth(rpc_token)
            .body(body)
            .send()
            .await;
    }
}

/// Best-effort: POST a validated local reveal (as a gossip envelope) to the node.
pub async fn forward_reveal_to_node(rpc_base: &str, rpc_token: &str, dto: &RoleRevealDto) {
    if !role_gossip_enabled() {
        return;
    }
    let url = format!(
        "{}/poawx/role-gossip/reveal",
        rpc_base.trim_end_matches('/')
    );
    if let Ok(client) = reqwest::Client::builder().build() {
        let body = RoleRevealGossip::new(dto.clone()).encode();
        let _ = client
            .post(&url)
            .bearer_auth(rpc_token)
            .body(body)
            .send()
            .await;
    }
}

#[derive(Deserialize)]
struct NodePrecommitsResp {
    #[serde(default)]
    precommits: Vec<RolePrecommitGossip>,
}
#[derive(Deserialize)]
struct NodeRevealsResp {
    #[serde(default)]
    reveals: Vec<RoleRevealGossip>,
}

/// Fetch node-collected precommits for `target_height` (best-effort, empty on error).
pub async fn fetch_node_precommits(
    rpc_base: &str,
    rpc_token: &str,
    target_height: u64,
) -> Vec<RolePrecommitDto> {
    if !role_gossip_enabled() {
        return Vec::new();
    }
    let url = format!(
        "{}/poawx/role-gossip/precommits?target_height={}",
        rpc_base.trim_end_matches('/'),
        target_height
    );
    let client = match reqwest::Client::builder().build() {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let resp = match client.get(&url).bearer_auth(rpc_token).send().await {
        Ok(r) if r.status().is_success() => r,
        _ => return Vec::new(),
    };
    match resp.json::<NodePrecommitsResp>().await {
        Ok(r) => r.precommits.into_iter().map(|g| g.precommit).collect(),
        Err(_) => Vec::new(),
    }
}

/// Fetch node-collected reveals for `target_height` (best-effort, empty on error).
pub async fn fetch_node_reveals(
    rpc_base: &str,
    rpc_token: &str,
    target_height: u64,
) -> Vec<RoleRevealDto> {
    if !role_gossip_enabled() {
        return Vec::new();
    }
    let url = format!(
        "{}/poawx/role-gossip/reveals?target_height={}",
        rpc_base.trim_end_matches('/'),
        target_height
    );
    let client = match reqwest::Client::builder().build() {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let resp = match client.get(&url).bearer_auth(rpc_token).send().await {
        Ok(r) if r.status().is_success() => r,
        _ => return Vec::new(),
    };
    match resp.json::<NodeRevealsResp>().await {
        Ok(r) => r.reveals.into_iter().map(|g| g.reveal).collect(),
        Err(_) => Vec::new(),
    }
}

/// Fetch node-collected role gossip for the heights needed to produce a block at
/// `height` (precommits for `height` and `height+1`, reveals for `height`) and
/// ingest into the local store. Best-effort; validates each before storing.
pub async fn bridge_fetch_into_store(
    store: &RoleProtocolStore,
    network_id: u8,
    rpc_base: &str,
    rpc_token: &str,
    height: u64,
) {
    if network_id == 0 || !role_gossip_enabled() {
        return;
    }
    let base = node_role_gossip_rpc_base(rpc_base);
    for h in [height, height + 1] {
        for dto in fetch_node_precommits(&base, rpc_token, h).await {
            if let Ok(v) = dto.validate(network_id) {
                let _ = store.add_precommit(v);
            }
        }
    }
    for dto in fetch_node_reveals(&base, rpc_token, height).await {
        if let Ok(v) = dto.validate(network_id) {
            let _ = store.add_reveal(v);
        }
    }
}

// ── HTTP server (raw-TCP, loopback-only by config; opt-in) ───────────────────

fn poawx_state_dir() -> PathBuf {
    env::var("IRIUM_POAWX_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/opt/irium-pool/data"))
}

pub fn delegate_key_path() -> PathBuf {
    env::var("IRIUM_POAWX_DELEGATE_KEY_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| poawx_state_dir().join("poawx_delegate_key.hex"))
}

pub fn delegations_path() -> PathBuf {
    env::var("IRIUM_POAWX_DELEGATIONS_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| poawx_state_dir().join("poawx_delegations.json"))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn is_loopback_bind(bind: &str) -> bool {
    let t = bind.trim();
    t.starts_with("127.0.0.1:") || t.starts_with("localhost:") || t.starts_with("[::1]:")
}

/// Shared PoAW-X producer context: the delegate key + delegation registry +
/// network id, shared via a single `Arc` between the HTTP registration server
/// and the live receipt-producer path so a freshly registered delegation is
/// immediately visible to the mining path. None on mainnet (mode-1 hard-off).
pub struct PoawxProducer {
    pub store: Arc<dyn DelegationStore>,
    pub key: Arc<DelegateKey>,
    pub network_id: u8,
    /// Step 6B: shared role precommit/reveal store (loopback-fed); read by the
    /// receipt-producer path to build collected Phase 20 exts.
    pub role_store: Arc<RoleProtocolStore>,
}

/// Load the producer (delegate key + delegation store). Returns None on mainnet
/// (no key generated, delegation refused) or if the key/store cannot be loaded.
pub fn load_producer() -> Option<PoawxProducer> {
    let network_id = network_id_from_env();
    if network_id == 0 {
        warn!("[poawx-deleg] mainnet context: PoAW-X delegation disabled (mode-1 hard-off)");
        return None;
    }
    let key = match DelegateKey::load_or_generate(&delegate_key_path(), true) {
        Ok(k) => k,
        Err(e) => {
            warn!("[poawx-deleg] delegate key unavailable: {e}");
            return None;
        }
    };
    let store = match JsonDelegationStore::open(delegations_path()) {
        Ok(s) => Arc::new(s) as Arc<dyn DelegationStore>,
        Err(e) => {
            warn!("[poawx-deleg] delegation store unavailable: {e}");
            return None;
        }
    };
    info!(
        "[poawx-deleg] pool_pubkey={} network_id={network_id}",
        key.pubkey_hex()
    );
    Some(PoawxProducer {
        store,
        key: Arc::new(key),
        network_id,
        role_store: Arc::new(RoleProtocolStore::new()),
    })
}

/// Spawn the delegation HTTP server if `IRIUM_POAWX_DELEGATION_BIND` is set.
/// Default = DISABLED (no bind). Refuses any non-loopback bind. The server shares
/// `producer` (store+key) with the receipt-producer path. On mainnet (`producer`
/// None) the endpoints return 503.
pub fn maybe_spawn(producer: Option<Arc<PoawxProducer>>, rpc_base: String, rpc_token: String) {
    let bind = match env::var("IRIUM_POAWX_DELEGATION_BIND")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
    {
        Some(b) => b,
        None => return, // disabled by default
    };
    if !is_loopback_bind(&bind) {
        warn!(
            "[poawx-deleg] refusing non-loopback IRIUM_POAWX_DELEGATION_BIND={bind}; server NOT started"
        );
        return;
    }
    let network_id = network_id_from_env();
    tokio::spawn(async move {
        if let Err(e) = serve(bind, producer, network_id, rpc_base, rpc_token).await {
            warn!("[poawx-deleg] server stopped: {e}");
        }
    });
}

struct ServerCtx {
    network_id: u8,
    /// None on mainnet (delegation disabled → 503).
    producer: Option<Arc<PoawxProducer>>,
    rpc_base: String,
    rpc_token: String,
}

async fn serve(
    bind: String,
    producer: Option<Arc<PoawxProducer>>,
    network_id: u8,
    rpc_base: String,
    rpc_token: String,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&bind).await?;
    info!("[poawx-deleg] listening on http://{bind} (loopback-only, network_id={network_id})");

    let ctx = Arc::new(ServerCtx {
        network_id,
        producer,
        rpc_base,
        rpc_token,
    });

    loop {
        let (stream, _addr) = listener.accept().await?;
        let ctx = Arc::clone(&ctx);
        tokio::spawn(async move {
            let _ = handle_conn(stream, ctx).await;
        });
    }
}

async fn read_request(stream: &mut TcpStream) -> Option<(String, String, Vec<u8>)> {
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 16 * 1024 {
            return None;
        }
    };
    let header_str = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut header_lines = header_str.lines();
    let first = header_lines.next()?;
    let mut parts = first.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();

    let mut content_len = 0usize;
    for l in header_str.lines() {
        let ll = l.to_ascii_lowercase();
        if let Some(v) = ll.strip_prefix("content-length:") {
            content_len = v.trim().parse().unwrap_or(0);
        }
    }
    let mut body = buf[header_end..].to_vec();
    while body.len() < content_len {
        let n = stream.read(&mut tmp).await.ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
        if body.len() > 64 * 1024 {
            break;
        }
    }
    body.truncate(content_len.min(body.len()));
    Some((method, path, body))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

async fn respond(stream: &mut TcpStream, status: u16, reason: &str, body: &serde_json::Value) {
    let body_str = serde_json::to_string(body).unwrap_or_else(|_| "{}".to_string());
    let resp = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body_str.len(),
        body_str
    );
    let _ = stream.write_all(resp.as_bytes()).await;
    let _ = stream.flush().await;
}

async fn fetch_tip_height(rpc_base: &str, rpc_token: &str) -> Option<u64> {
    let tpl =
        crate::template::TemplateClient::new(rpc_base.to_string(), rpc_token.to_string()).ok()?;
    let template = tpl.fetch_template().await.ok()?;
    Some(template.height.saturating_sub(1))
}

async fn handle_conn(mut stream: TcpStream, ctx: Arc<ServerCtx>) {
    let (method, path, body) = match read_request(&mut stream).await {
        Some(t) => t,
        None => return,
    };
    let path_only = path.split('?').next().unwrap_or(&path);

    match (method.as_str(), path_only) {
        ("GET", "/poawx/pool-identity") => match &ctx.producer {
            None => {
                respond(
                    &mut stream,
                    503,
                    "Service Unavailable",
                    &serde_json::json!({"error":"delegation unavailable on mainnet"}),
                )
                .await
            }
            Some(p) => {
                // Advertise the pool's configured third-party fee terms (or fee-0
                // when official / mode off / mainnet).
                let v = pool_identity_json(
                    &p.key.pubkey_hex(),
                    p.network_id,
                    pool_third_party_fee_terms(),
                );
                respond(&mut stream, 200, "OK", &v).await
            }
        },
        ("POST", "/poawx/delegation") => {
            let (key, store) = match &ctx.producer {
                Some(p) => (&p.key, &p.store),
                None => {
                    respond(
                        &mut stream,
                        503,
                        "Service Unavailable",
                        &serde_json::json!({"error":"delegation unavailable on mainnet"}),
                    )
                    .await;
                    return;
                }
            };
            let parsed: serde_json::Value = match serde_json::from_slice(&body) {
                Ok(v) => v,
                Err(_) => {
                    respond(
                        &mut stream,
                        400,
                        "Bad Request",
                        &serde_json::json!({"error":"invalid JSON body"}),
                    )
                    .await;
                    return;
                }
            };
            let delegation_hex = parsed
                .get("delegation")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let worker = parsed.get("worker").and_then(|v| v.as_str()).unwrap_or("");
            let miner_pkh = parsed
                .get("miner_pkh")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let tip = match fetch_tip_height(&ctx.rpc_base, &ctx.rpc_token).await {
                Some(t) => t,
                None => {
                    respond(
                        &mut stream,
                        503,
                        "Service Unavailable",
                        &serde_json::json!({"error":"could not determine chain tip"}),
                    )
                    .await;
                    return;
                }
            };
            // Third-party fee terms accepted only when the fee gate is active at the
            // current tip AND the pool config is valid; otherwise official (None).
            let expected_fee = if third_party_fee_active(tip) {
                pool_third_party_fee_terms()
            } else {
                None
            };
            match verify_and_store(
                store.as_ref(),
                delegation_hex,
                worker,
                miner_pkh,
                &key.pubkey(),
                ctx.network_id,
                tip,
                unix_now(),
                expected_fee,
            ) {
                Ok(rec) => {
                    respond(
                        &mut stream,
                        200,
                        "OK",
                        &serde_json::json!({
                            "status": rec.status,
                            "miner_pkh": rec.miner_pkh,
                            "worker": rec.worker,
                            "expiry_height": rec.expiry_height,
                            "network_id": rec.network_id,
                        }),
                    )
                    .await
                }
                Err(e) => {
                    let (status, reason) = e.http_status();
                    respond(
                        &mut stream,
                        status,
                        reason,
                        &serde_json::json!({"error": e.reason()}),
                    )
                    .await
                }
            }
        }
        // Step 6B: local/testnet role precommit + reveal collection (loopback-only,
        // gated). Mainnet (producer None) => 503; gate off => 403.
        ("POST", "/poawx/role-precommit") | ("POST", "/poawx/role-reveal") => {
            let producer = match &ctx.producer {
                Some(p) => p,
                None => {
                    respond(
                        &mut stream,
                        503,
                        "Service Unavailable",
                        &serde_json::json!({"error":"role protocol unavailable on mainnet"}),
                    )
                    .await;
                    return;
                }
            };
            if !role_protocol_enabled() {
                respond(&mut stream, 403, "Forbidden",
                    &serde_json::json!({"error":"role protocol disabled (set IRIUM_POAWX_ROLE_PROTOCOL_ENABLED=1)"})).await;
                return;
            }
            // Opportunistic pruning of stale heights (best-effort).
            if let Some(tip) = fetch_tip_height(&ctx.rpc_base, &ctx.rpc_token).await {
                producer.role_store.prune(tip);
            }
            let result: Result<&'static str, String> = if path_only == "/poawx/role-precommit" {
                serde_json::from_slice::<RolePrecommitDto>(&body)
                    .map_err(|_| "invalid precommit JSON".to_string())
                    .and_then(|dto| dto.validate(ctx.network_id))
                    .and_then(|v| producer.role_store.add_precommit(v).map(|_| "precommit"))
            } else {
                serde_json::from_slice::<RoleRevealDto>(&body)
                    .map_err(|_| "invalid reveal JSON".to_string())
                    .and_then(|dto| dto.validate(ctx.network_id))
                    .and_then(|v| producer.role_store.add_reveal(v).map(|_| "reveal"))
            };
            match result {
                Ok(kind) => {
                    // Step 6D: best-effort forward to the node's loopback role-gossip
                    // endpoint so it can P2P-broadcast. Local store already succeeded;
                    // a node failure here never affects the local store / response.
                    if role_gossip_enabled() {
                        let base = node_role_gossip_rpc_base(&ctx.rpc_base);
                        if kind == "precommit" {
                            if let Ok(dto) = serde_json::from_slice::<RolePrecommitDto>(&body) {
                                forward_precommit_to_node(&base, &ctx.rpc_token, &dto).await;
                            }
                        } else if let Ok(dto) = serde_json::from_slice::<RoleRevealDto>(&body) {
                            forward_reveal_to_node(&base, &ctx.rpc_token, &dto).await;
                        }
                    }
                    respond(
                        &mut stream,
                        200,
                        "OK",
                        &serde_json::json!({"status":"accepted","kind":kind}),
                    )
                    .await
                }
                Err(e) => {
                    respond(
                        &mut stream,
                        400,
                        "Bad Request",
                        &serde_json::json!({"error": e}),
                    )
                    .await
                }
            }
        }
        _ => {
            respond(
                &mut stream,
                404,
                "Not Found",
                &serde_json::json!({"error":"not found"}),
            )
            .await
        }
    }
}

/// Shared process-wide lock for tests that mutate `IRIUM_NETWORK` / the Phase 20
/// activation env vars (env is global). Exposed `pub(crate)` so the stratum test
/// module can serialize against the same lock.
#[cfg(test)]
pub(crate) fn p20_env_lock() -> &'static std::sync::Mutex<()> {
    static L: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    L.get_or_init(|| std::sync::Mutex::new(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::{Signature, SigningKey, VerifyingKey};

    fn pk33(sk: &SigningKey) -> [u8; 33] {
        let vk = VerifyingKey::from(sk);
        let enc = vk.to_encoded_point(true);
        let mut p = [0u8; 33];
        p.copy_from_slice(enc.as_bytes());
        p
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("irium-deleg-{tag}-{stamp}"))
    }

    /// Build a mirror Delegation signed by `miner` (matches what the wallet
    /// produces via the canonical type — the parity tests below prove this).
    fn mirror_signed(
        miner: &SigningKey,
        pool_pubkey: [u8; 33],
        network_id: u8,
        worker: &str,
        expiry: u64,
        fee_bps: u16,
    ) -> Delegation {
        let mut d = Delegation {
            deleg_version: Delegation::VERSION,
            network_id,
            miner_pubkey: pk33(miner),
            pool_pubkey,
            worker_tag: worker_tag(worker),
            expiry_height: expiry,
            fee_bps,
            fee_pkh: [0u8; 20],
            deleg_nonce: [7u8; 32],
            proposer_pubkey: [0u8; 33],
            delegation_sig: [0u8; 64],
        };
        let sig: Signature = miner.sign_prehash(&d.message_hash()).unwrap();
        d.delegation_sig.copy_from_slice(&sig.to_bytes());
        d
    }

    /// Phase 20 Step 4: build a signed delegation carrying third-party fee terms.
    fn mirror_signed_fee(
        miner: &SigningKey,
        pool_pubkey: [u8; 33],
        network_id: u8,
        worker: &str,
        expiry: u64,
        fee_bps: u16,
        fee_pkh: [u8; 20],
    ) -> Delegation {
        let mut d = Delegation {
            deleg_version: Delegation::VERSION,
            network_id,
            miner_pubkey: pk33(miner),
            pool_pubkey,
            worker_tag: worker_tag(worker),
            expiry_height: expiry,
            fee_bps,
            fee_pkh,
            deleg_nonce: [7u8; 32],
            proposer_pubkey: [0u8; 33],
            delegation_sig: [0u8; 64],
        };
        let sig: Signature = miner.sign_prehash(&d.message_hash()).unwrap();
        d.delegation_sig.copy_from_slice(&sig.to_bytes());
        d
    }

    // ── Mandatory parity tests vs canonical irium_node_rs::poawx::Delegation ──

    #[test]
    fn parity_serialize_message_hash_digest_and_size() {
        let fields = (
            1u8,
            1u8,
            [0x11u8; 33],
            [0x22u8; 33],
            [0x33u8; 32],
            999u64,
            0u16,
            [0u8; 20],
            [0x44u8; 32],
            [0x55u8; 64],
        );
        let canon = irium_node_rs::poawx::Delegation {
            deleg_version: fields.0,
            network_id: fields.1,
            miner_pubkey: fields.2,
            pool_pubkey: fields.3,
            worker_tag: fields.4,
            expiry_height: fields.5,
            fee_bps: fields.6,
            fee_pkh: fields.7,
            deleg_nonce: fields.8,
            proposer_pubkey: [0u8; 33],
            delegation_sig: fields.9,
        };
        let mir = Delegation {
            deleg_version: fields.0,
            network_id: fields.1,
            miner_pubkey: fields.2,
            pool_pubkey: fields.3,
            worker_tag: fields.4,
            expiry_height: fields.5,
            fee_bps: fields.6,
            fee_pkh: fields.7,
            deleg_nonce: fields.8,
            proposer_pubkey: [0u8; 33],
            delegation_sig: fields.9,
        };
        assert_eq!(Delegation::WIRE_SIZE_V1, 226);
        assert_eq!(irium_node_rs::poawx::Delegation::WIRE_SIZE_V1, 226);
        assert_eq!(Delegation::WIRE_SIZE, 259);
        assert_eq!(irium_node_rs::poawx::Delegation::WIRE_SIZE, 259);
        assert_eq!(canon.serialize(), mir.serialize(), "serialize parity");
        assert_eq!(canon.serialize().len(), 226);
        assert_eq!(
            canon.message_hash(),
            mir.message_hash(),
            "message_hash parity"
        );
        assert_eq!(canon.digest(), mir.digest(), "digest parity");
        assert_eq!(
            Delegation::VERSION,
            irium_node_rs::poawx::Delegation::VERSION
        );
        assert_eq!(DELEG_DOMAIN, irium_node_rs::poawx::DOMAIN_DELEG);
    }

    #[test]
    fn parity_mirror_verifies_canonical_signed_and_rejects_tamper() {
        let miner = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let mp = pk33(&miner);
        let mut canon = irium_node_rs::poawx::Delegation {
            deleg_version: 1,
            network_id: 1,
            miner_pubkey: mp,
            pool_pubkey: [0x02u8; 33],
            worker_tag: [0u8; 32],
            expiry_height: 999,
            fee_bps: 0,
            fee_pkh: [0u8; 20],
            deleg_nonce: [4u8; 32],
            proposer_pubkey: [0u8; 33],
            delegation_sig: [0u8; 64],
        };
        let sig: Signature = miner.sign_prehash(&canon.message_hash()).unwrap();
        canon.delegation_sig.copy_from_slice(&sig.to_bytes());

        // Mirror deserializes the canonical bytes and verifies the signature.
        let mir = Delegation::deserialize(&canon.serialize()).unwrap();
        assert!(
            mir.verify_signature().is_ok(),
            "mirror verifies canonical-signed"
        );
        assert_eq!(mir.miner_pkh(), canon.miner_pkh(), "miner_pkh parity");

        // Tampered canonical delegation must be rejected by the mirror.
        let mut tampered = canon.clone();
        tampered.delegation_sig[0] ^= 0xff;
        let mir_bad = Delegation::deserialize(&tampered.serialize()).unwrap();
        assert!(
            mir_bad.verify_signature().is_err(),
            "mirror rejects tampered"
        );
    }

    #[test]
    fn parity_miner_pkh_matches_hash160() {
        let miner = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let mp = pk33(&miner);
        let canon = irium_node_rs::poawx::Delegation {
            deleg_version: 1,
            network_id: 1,
            miner_pubkey: mp,
            pool_pubkey: [0u8; 33],
            worker_tag: [0u8; 32],
            expiry_height: 1,
            fee_bps: 0,
            fee_pkh: [0u8; 20],
            deleg_nonce: [0u8; 32],
            proposer_pubkey: [0u8; 33],
            delegation_sig: [0u8; 64],
        };
        let expected = {
            let sha = Sha256::digest(mp);
            let rip = ripemd::Ripemd160::digest(sha);
            let mut p = [0u8; 20];
            p.copy_from_slice(&rip);
            p
        };
        let mir = Delegation::deserialize(&canon.serialize()).unwrap();
        assert_eq!(mir.miner_pkh(), expected);
        assert_eq!(canon.miner_pkh(), expected);
    }

    // ── Store, key, verify, identity ──

    #[test]
    fn store_put_get_persist_across_reload() {
        let dir = temp_dir("store");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("poawx_delegations.json");
        let rec = StoredDelegation {
            delegation_hex: "ab".repeat(226),
            miner_pkh: "aa".repeat(20),
            worker: "rig1".into(),
            network_id: 1,
            expiry_height: 100,
            fee_bps: 0,
            fee_pkh: String::new(),
            status: "active".into(),
            received_at_unix: 1,
        };
        {
            let s = JsonDelegationStore::open(&path).unwrap();
            s.put(rec.clone()).unwrap();
            assert_eq!(s.get(&rec.miner_pkh, "rig1").unwrap(), rec);
        }
        let s2 = JsonDelegationStore::open(&path).unwrap();
        assert_eq!(
            s2.get(&rec.miner_pkh, "rig1").unwrap(),
            rec,
            "persists across reload"
        );
        // Registry stores no private keys.
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("privkey") && !raw.contains("secret") && !raw.contains("private"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn multi_worker_registry_isolation_and_reload() {
        // Phase 20 (Part D, registry layer): the delegation registry holds many
        // (miner_pkh, worker) entries without cross-contamination; reload preserves
        // all; all_active() honors expiry; no worker can resolve to another's record.
        let dir = temp_dir("multiworker");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("poawx_delegations.json");
        let mk = |pkh: &str, worker: &str, expiry: u64| StoredDelegation {
            delegation_hex: "cd".repeat(226),
            miner_pkh: pkh.to_string(),
            worker: worker.to_string(),
            network_id: 1,
            expiry_height: expiry,
            fee_bps: 0,
            fee_pkh: String::new(),
            status: "active".into(),
            received_at_unix: 1,
        };
        let a = mk(&"aa".repeat(20), "rig1", 100); // miner A / worker rig1
        let b = mk(&"bb".repeat(20), "rig2", 100); // miner B / worker rig2 (different miner+worker)
        let a2 = mk(&"aa".repeat(20), "rig3", 5); // miner A / worker rig3, expires early
        {
            let s = JsonDelegationStore::open(&path).unwrap();
            s.put(a.clone()).unwrap();
            s.put(b.clone()).unwrap();
            s.put(a2.clone()).unwrap();
            // exact (pkh,worker) resolution — no cross-pay collisions:
            assert_eq!(s.get(&a.miner_pkh, "rig1").unwrap(), a);
            assert_eq!(s.get(&b.miner_pkh, "rig2").unwrap(), b);
            assert_eq!(s.get(&a.miner_pkh, "rig3").unwrap(), a2);
            assert!(
                s.get(&b.miner_pkh, "rig1").is_none(),
                "worker rig1 belongs to miner A only"
            );
            assert!(
                s.get(&a.miner_pkh, "rig2").is_none(),
                "worker rig2 belongs to miner B only"
            );
            assert!(
                s.get(&"cc".repeat(20), "rig1").is_none(),
                "unknown miner has no record"
            );
            // all_active(tip=10): a and b active; a2 expired (expiry 5 <= 10).
            let active = s.all_active(10);
            assert_eq!(active.len(), 2, "two active delegations at tip 10");
        }
        // reload preserves every (pkh,worker) entry, including the expired-but-stored a2.
        let s2 = JsonDelegationStore::open(&path).unwrap();
        assert_eq!(s2.get(&a.miner_pkh, "rig1").unwrap(), a);
        assert_eq!(s2.get(&b.miner_pkh, "rig2").unwrap(), b);
        assert_eq!(s2.get(&a.miner_pkh, "rig3").unwrap(), a2);
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("privkey") && !raw.contains("secret") && !raw.contains("private"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_and_store_accepts_valid_and_no_privkey_in_registry() {
        let dir = temp_dir("ok");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("d.json");
        let store = JsonDelegationStore::open(&path).unwrap();
        let pool = SigningKey::from_slice(&[3u8; 32]).unwrap();
        let pool_pub = pk33(&pool);
        let miner = SigningKey::from_slice(&[5u8; 32]).unwrap();
        let d = mirror_signed(&miner, pool_pub, 1, "rig1", 100, 0);
        let miner_pkh_hex = hex::encode(d.miner_pkh());
        let rec = verify_and_store(
            &store,
            &hex::encode(d.serialize()),
            "rig1",
            &miner_pkh_hex,
            &pool_pub,
            1,
            10,
            42,
            None,
        )
        .unwrap();
        assert_eq!(rec.miner_pkh, miner_pkh_hex);
        assert!(store.get(&miner_pkh_hex, "rig1").is_some());
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("privkey") && !raw.contains("secret"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_and_store_rejections() {
        let dir = temp_dir("rej");
        std::fs::create_dir_all(&dir).unwrap();
        let store = JsonDelegationStore::open(dir.join("d.json")).unwrap();
        let pool = SigningKey::from_slice(&[3u8; 32]).unwrap();
        let pool_pub = pk33(&pool);
        let other_pool = pk33(&SigningKey::from_slice(&[4u8; 32]).unwrap());
        let miner = SigningKey::from_slice(&[5u8; 32]).unwrap();
        let hexd = |d: &Delegation| hex::encode(d.serialize());

        // mainnet (network_id 0)
        assert_eq!(
            verify_and_store(
                &store,
                &hexd(&mirror_signed(&miner, pool_pub, 0, "r", 100, 0)),
                "r",
                "",
                &pool_pub,
                0,
                10,
                1,
                None
            ),
            Err(DelegError::Mainnet)
        );
        // network mismatch
        assert_eq!(
            verify_and_store(
                &store,
                &hexd(&mirror_signed(&miner, pool_pub, 2, "r", 100, 0)),
                "r",
                "",
                &pool_pub,
                1,
                10,
                1,
                None
            ),
            Err(DelegError::NetworkMismatch)
        );
        // pool pubkey mismatch
        assert_eq!(
            verify_and_store(
                &store,
                &hexd(&mirror_signed(&miner, other_pool, 1, "r", 100, 0)),
                "r",
                "",
                &pool_pub,
                1,
                10,
                1,
                None
            ),
            Err(DelegError::PoolPubkeyMismatch)
        );
        // fee > 0
        assert_eq!(
            verify_and_store(
                &store,
                &hexd(&mirror_signed(&miner, pool_pub, 1, "r", 100, 100)),
                "r",
                "",
                &pool_pub,
                1,
                10,
                1,
                None
            ),
            Err(DelegError::NonZeroFee)
        );
        // worker_tag mismatch (claimed worker differs from signed tag)
        assert_eq!(
            verify_and_store(
                &store,
                &hexd(&mirror_signed(&miner, pool_pub, 1, "rig1", 100, 0)),
                "rig2",
                "",
                &pool_pub,
                1,
                10,
                1,
                None
            ),
            Err(DelegError::WorkerTagMismatch)
        );
        // bad signature
        let mut bad = mirror_signed(&miner, pool_pub, 1, "r", 100, 0);
        bad.delegation_sig[0] ^= 0xff;
        assert_eq!(
            verify_and_store(&store, &hexd(&bad), "r", "", &pool_pub, 1, 10, 1, None),
            Err(DelegError::BadSignature)
        );
        // miner_pkh mismatch (claim a different pkh)
        assert_eq!(
            verify_and_store(
                &store,
                &hexd(&mirror_signed(&miner, pool_pub, 1, "r", 100, 0)),
                "r",
                &"ff".repeat(20),
                &pool_pub,
                1,
                10,
                1,
                None
            ),
            Err(DelegError::MinerPkhMismatch)
        );
        // expired (expiry <= tip)
        assert_eq!(
            verify_and_store(
                &store,
                &hexd(&mirror_signed(&miner, pool_pub, 1, "r", 10, 0)),
                "r",
                "",
                &pool_pub,
                1,
                10,
                1,
                None
            ),
            Err(DelegError::Expired)
        );
        // bad hex / format
        assert_eq!(
            verify_and_store(&store, "zz", "r", "", &pool_pub, 1, 10, 1, None),
            Err(DelegError::BadHex)
        );
        assert_eq!(
            verify_and_store(&store, "00", "r", "", &pool_pub, 1, 10, 1, None),
            Err(DelegError::BadFormat)
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn delegate_key_generate_reload_and_no_generate_when_absent() {
        let dir = temp_dir("key");
        std::fs::create_dir_all(&dir).unwrap();
        let kp = dir.join("poawx_delegate_key.hex");
        let k1 = DelegateKey::load_or_generate(&kp, true).unwrap();
        let k2 = DelegateKey::load_or_generate(&kp, true).unwrap();
        assert_eq!(k1.pubkey(), k2.pubkey(), "same key across reload");
        // Stored file is the 32-byte secret hex only (64 chars), no JSON/labels.
        let raw = std::fs::read_to_string(&kp).unwrap();
        assert_eq!(raw.trim().len(), 64);
        // Generation disallowed when absent (mainnet path).
        let missing = dir.join("nope.hex");
        assert!(DelegateKey::load_or_generate(&missing, false).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pool_identity_json_shape() {
        let pk = "02".to_string() + &"ab".repeat(32);
        let v = pool_identity_json(&pk, 1, None);
        assert_eq!(v["pool_pubkey"], pk);
        assert_eq!(v["network_id"], 1);
        assert_eq!(v["fee_bps"], 0);
        assert_eq!(v["deleg_version"], Delegation::VERSION);
        assert_eq!(v["domain"], "irium.poawx.delegation.v1");
        assert!(
            v.get("fee_pkh").is_none(),
            "official identity has no fee_pkh"
        );
        // Third-party identity advertises exact fee terms.
        let fp = [0xFEu8; 20];
        let vt = pool_identity_json(&pk, 1, Some((200, fp)));
        assert_eq!(vt["fee_bps"], 200);
        assert_eq!(vt["fee_pkh"], hex::encode(fp));
    }

    #[test]
    fn network_id_mapping_and_loopback_guard() {
        assert!(is_loopback_bind("127.0.0.1:39520"));
        assert!(is_loopback_bind("[::1]:39520"));
        assert!(!is_loopback_bind("0.0.0.0:39520"));
        assert!(!is_loopback_bind("10.0.0.5:39520"));
    }

    // ── Phase 18B step-3: mode-1 receipt production ──

    fn p18b3_assignment_dto(
        tip: u64,
        difficulty: u32,
        lane: &str,
    ) -> crate::template::PoawxAssignment {
        crate::template::PoawxAssignment {
            height: tip,
            seed: hex::encode([0xaau8; 32]),
            commitment_nonce: hex::encode([0xbbu8; 32]),
            puzzle_difficulty: difficulty,
            lane: lane.to_string(),
        }
    }

    /// Generate a delegate key in a temp dir + a store holding a valid delegation
    /// for `miner`/`worker`. Returns (key, store, miner_pkh).
    fn p18b3_setup(
        miner: &SigningKey,
        worker: &str,
        expiry: u64,
        fee_bps: u16,
        network_id: u8,
    ) -> (DelegateKey, JsonDelegationStore, [u8; 20]) {
        let dir = temp_dir("p18b3");
        std::fs::create_dir_all(&dir).unwrap();
        let key = DelegateKey::load_or_generate(&dir.join("k.hex"), true).unwrap();
        let store = JsonDelegationStore::open(dir.join("d.json")).unwrap();
        let d = mirror_signed(miner, key.pubkey(), network_id, worker, expiry, fee_bps);
        let miner_pkh = d.miner_pkh();
        // store via the real registration path (tip 0 so expiry>tip holds).
        verify_and_store(
            &store,
            &hex::encode(d.serialize()),
            worker,
            &hex::encode(miner_pkh),
            &key.pubkey(),
            network_id,
            0,
            1,
            None,
        )
        .expect("store delegation");
        (key, store, miner_pkh)
    }

    #[test]
    fn phase18b3_build_mode1_receipt_and_root_parity() {
        let miner = SigningKey::from_slice(&[5u8; 32]).unwrap();
        let (key, store, miner_pkh) = p18b3_setup(&miner, "rig1", 1000, 0, 1);
        let dto = p18b3_assignment_dto(0, 4, "cpu"); // tip 0 -> block height 1
        let ctx = assignment_context_from_dto(&dto, 1).expect("ctx");
        let rec =
            build_mode1_pending_receipt(&store, &key, 1, miner_pkh, "rig1", &ctx).expect("receipt");
        // Field checks.
        assert_eq!(rec.worker_pkh, hex::encode(miner_pkh), "pays miner pkh");
        assert_eq!(
            rec.worker_pubkey,
            key.pubkey_hex(),
            "signer = pool delegate"
        );
        assert_eq!(rec.height, 1);
        assert_eq!(rec.lane, "cpu");
        assert!(!rec.delegation.is_empty(), "carries embedded delegation");
        // Root parity: pool root == node irx1_root_from_block_receipts.
        let block_rec = irium_node_rs::poawx::PoawxBlockReceipt {
            height: rec.height,
            lane: rec.lane.bytes().next().unwrap(),
            worker_pkh: {
                let mut a = [0u8; 20];
                a.copy_from_slice(&hex::decode(&rec.worker_pkh).unwrap());
                a
            },
            worker_pubkey: {
                let mut a = [0u8; 33];
                a.copy_from_slice(&hex::decode(&rec.worker_pubkey).unwrap());
                a
            },
            worker_sig: {
                let mut a = [0u8; 64];
                a.copy_from_slice(&hex::decode(&rec.worker_sig).unwrap());
                a
            },
            solution: {
                let mut a = [0u8; 8];
                a.copy_from_slice(&hex::decode(&rec.solution).unwrap());
                a
            },
            commitment_nonce: {
                let mut a = [0u8; 32];
                a.copy_from_slice(&hex::decode(&rec.commitment_nonce).unwrap());
                a
            },
            delegation: Some(
                irium_node_rs::poawx::Delegation::deserialize(
                    &hex::decode(&rec.delegation).unwrap(),
                )
                .unwrap(),
            ),
            phase20_ext: None,
        };
        let node_root =
            irium_node_rs::poawx::irx1_root_from_block_receipts(std::slice::from_ref(&block_rec));
        let pool_root =
            crate::block::compute_receipts_root_from_pending(std::slice::from_ref(&rec));
        assert_eq!(
            pool_root, node_root,
            "pool mode-1 root must equal node irx1_root_from_block_receipts"
        );
        // The produced solution actually meets the puzzle difficulty.
        let mut input = [0u8; 72];
        input[..32].copy_from_slice(&ctx.seed);
        input[32..64].copy_from_slice(&ctx.commitment_nonce);
        input[64..].copy_from_slice(&hex::decode(&rec.solution).unwrap());
        assert!(count_leading_zero_bits(&crate::pow::sha256d(&input)) >= ctx.difficulty);
    }

    #[test]
    fn phase18b3_no_delegation_returns_none() {
        let key_dir = temp_dir("p18b3-none");
        std::fs::create_dir_all(&key_dir).unwrap();
        let key = DelegateKey::load_or_generate(&key_dir.join("k.hex"), true).unwrap();
        let store = JsonDelegationStore::open(key_dir.join("d.json")).unwrap();
        let dto = p18b3_assignment_dto(0, 4, "cpu");
        let ctx = assignment_context_from_dto(&dto, 1).unwrap();
        // empty store -> no mode-1 receipt (mode-0 path preserved upstream).
        assert!(build_mode1_pending_receipt(&store, &key, 1, [0x11u8; 20], "rig1", &ctx).is_none());
    }

    #[test]
    fn phase18b3_assignment_height_and_lane_mismatch_fail_closed() {
        // height mismatch: assignment tip 5 but job height 1 -> None
        assert!(assignment_context_from_dto(&p18b3_assignment_dto(5, 4, "cpu"), 1).is_none());
        // correct: tip 0 -> job height 1
        assert!(assignment_context_from_dto(&p18b3_assignment_dto(0, 4, "cpu"), 1).is_some());
        // wrong lane -> None
        assert!(assignment_context_from_dto(&p18b3_assignment_dto(0, 4, "gpu"), 1).is_none());
    }

    #[test]
    fn phase18b3_expired_wrong_worker_wrong_pkh_fail_closed() {
        let miner = SigningKey::from_slice(&[5u8; 32]).unwrap();
        let (key, store, miner_pkh) = p18b3_setup(&miner, "rig1", 5, 0, 1);
        // expired: delegation expiry 5, block height 10 -> None
        let ctx10 = assignment_context_from_dto(&p18b3_assignment_dto(9, 4, "cpu"), 10).unwrap();
        assert!(build_mode1_pending_receipt(&store, &key, 1, miner_pkh, "rig1", &ctx10).is_none());
        // wrong worker (registered rig1, ask rig2) -> None
        let ctx1 = assignment_context_from_dto(&p18b3_assignment_dto(0, 4, "cpu"), 1).unwrap();
        assert!(build_mode1_pending_receipt(&store, &key, 1, miner_pkh, "rig2", &ctx1).is_none());
        // wrong miner pkh -> None
        assert!(
            build_mode1_pending_receipt(&store, &key, 1, [0xffu8; 20], "rig1", &ctx1).is_none()
        );
        // wrong network id (delegation stored for net 1; ask as net 2) -> None
        assert!(build_mode1_pending_receipt(&store, &key, 2, miner_pkh, "rig1", &ctx1).is_none());
    }

    // ── Phase 20 production primitives: parity, gate, synthetic builder ───────

    #[test]
    fn phase20_mirror_wire_parity_vs_node() {
        // RoleReward 60-byte wire parity.
        let rr = RoleRewardMirror {
            compute_contributor_pkh: [0xC1u8; 20],
            verify_contributor_pkh: [0xC2u8; 20],
            support_contributor_pkh: [0xC3u8; 20],
        };
        let node_rr = irium_node_rs::poawx::RoleReward {
            compute_contributor_pkh: [0xC1u8; 20],
            verify_contributor_pkh: [0xC2u8; 20],
            support_contributor_pkh: [0xC3u8; 20],
        };
        assert_eq!(
            rr.serialize(),
            node_rr.serialize(),
            "RoleReward wire parity"
        );

        // multi_role_amounts parity over a range incl. remainder cases.
        for total in [0u64, 1, 7, 999, 5_000_000_000, 5_000_000_001, u64::MAX / 2] {
            assert_eq!(
                multi_role_amounts(total),
                irium_node_rs::poawx::multi_role_amounts(total),
                "multi_role_amounts parity total={total}"
            );
            // exact-sum invariant.
            assert_eq!(multi_role_amounts(total).iter().sum::<u64>(), total);
        }

        // fairness digest / assign_lane / role_claim_digest parity.
        let prev = [0x44u8; 32];
        for role in [
            ROLE_COMPUTE_CONTRIBUTOR,
            ROLE_VERIFY_CONTRIBUTOR,
            ROLE_SUPPORT_CONTRIBUTOR,
        ] {
            assert_eq!(
                fairness_assignment_digest(1, 100, &prev, role, 0),
                irium_node_rs::poawx::fairness_assignment_digest(1, 100, &prev, role, 0)
            );
            assert_eq!(
                assign_lane_id(1, 100, &prev, role, 0),
                irium_node_rs::poawx::assign_lane(1, 100, &prev, role, 0).id()
            );
            assert_eq!(
                role_claim_digest(
                    1,
                    100,
                    &prev,
                    role,
                    0,
                    &[0x07u8; 20],
                    &[1u8; 32],
                    &[2u8; 32]
                ),
                irium_node_rs::poawx::role_claim_digest(
                    1,
                    100,
                    &prev,
                    role,
                    0,
                    &[0x07u8; 20],
                    &[1u8; 32],
                    &[2u8; 32]
                )
            );
        }

        // PoawxRoleClaim + Phase20ReceiptExt wire + digest parity.
        let mk_pool = |role: u8| PoawxRoleClaimMirror {
            role_id: role,
            lane_id: LANE_GPU_PARALLEL,
            solver_pkh: [role; 20],
            nonce: [role; 32],
            secret: [role.wrapping_add(1); 32],
            claim_digest: [role.wrapping_add(2); 32],
            commitment_hash: None,
        };
        let mk_node = |role: u8| irium_node_rs::poawx::PoawxRoleClaim {
            role_id: role,
            lane_id: LANE_GPU_PARALLEL,
            solver_pkh: [role; 20],
            nonce: [role; 32],
            secret: [role.wrapping_add(1); 32],
            claim_digest: [role.wrapping_add(2); 32],
            commitment_hash: None,
        };
        assert_eq!(
            mk_pool(1).serialize(),
            mk_node(1).serialize(),
            "RoleClaim parity"
        );
        let ext = Phase20ReceiptExtMirror {
            role_reward: rr,
            compute_claim: mk_pool(1),
            verify_claim: mk_pool(2),
            support_claim: mk_pool(3),
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
        };
        let node_ext = irium_node_rs::poawx::Phase20ReceiptExt {
            role_reward: node_rr,
            compute_claim: mk_node(1),
            verify_claim: mk_node(2),
            support_claim: mk_node(3),
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
            fraud_proofs: None,
            proposer_assignment: None,
            proposer_registrations: None,
            delegation_revocations: None,
        };
        assert_eq!(
            ext.serialize(),
            node_ext.serialize(),
            "Phase20ReceiptExt wire parity"
        );
        assert_eq!(ext.digest(), node_ext.digest(), "ext digest parity");
        // The node can deserialize the pool's bytes back to the identical type.
        let round = irium_node_rs::poawx::Phase20ReceiptExt::deserialize(&ext.serialize()).unwrap();
        assert_eq!(round, node_ext);
        // RoleReward pkhs extractable from the hex without full deserialize.
        let (c, v, s) = role_reward_pkhs_from_ext_hex(&hex::encode(ext.serialize())).unwrap();
        assert_eq!((c, v, s), ([0xC1u8; 20], [0xC2u8; 20], [0xC3u8; 20]));
    }

    #[test]
    fn phase23a_assignment_v2_mirror_rejects_bad_length() {
        // The opaque mirror enforces the exact 273-byte wire (bounded deserialization).
        assert!(
            AssignmentProofV2Mirror::deserialize(&[0u8; ASSIGNMENT_PROOF_V2_WIRE - 1]).is_err()
        );
        assert!(
            AssignmentProofV2Mirror::deserialize(&[0u8; ASSIGNMENT_PROOF_V2_WIRE + 1]).is_err()
        );
        assert!(AssignmentProofV2Mirror::deserialize(&[]).is_err());
        assert!(AssignmentProofV2Mirror::deserialize(&[0u8; ASSIGNMENT_PROOF_V2_WIRE]).is_ok());
        // decode_admission_v2 rejects a V1-length admission (no trailing proof).
        let v1 = "01".to_string() + &"00".repeat(CANDIDATE_ADMISSION_WIRE - 1);
        assert!(
            decode_admission_v2(&v1).is_none(),
            "V1-length admission has no V2"
        );
    }

    #[test]
    fn phase22e_pool_e2e_bundle_and_failclosed() {
        let _g = p20_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_SYNTHETIC_ROLE_CLAIMS", "1");
        std::env::set_var("IRIUM_POAWX_CANDIDATE_ADMISSION_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_CANDIDATE_ADMISSION_REQUIRED", "1");
        std::env::set_var("IRIUM_POAWX_TRUE_VRF_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_TRUE_VRF_REQUIRED", "1");
        let net = network_id_from_env();
        let height = 5u64;
        let seed = [0x44u8; 32];
        let primary = [0xA0u8; 20];

        // Miner/wallet supplies V2 proofs; build admission wires (node lib) for the 3
        // roles, all solver == primary (matches build_synthetic's role_reward solvers
        // with empty workers).
        let roles = [
            ROLE_COMPUTE_CONTRIBUTOR,
            ROLE_VERIFY_CONTRIBUTOR,
            ROLE_SUPPORT_CONTRIBUTOR,
        ];
        let mk_adm = |secret: u8, role: u8| -> String {
            let proof = irium_node_rs::poawx_candidate::AssignmentProofV2::prove(
                &[secret; 32],
                net,
                height,
                role,
                primary,
                [role; 32],
                seed,
            )
            .unwrap();
            let cand = irium_node_rs::poawx_candidate::RoleCandidate::from_assignment_v2(
                &proof,
                irium_node_rs::poawx_penalty::PenaltyStatus::Clean.id(),
                1000,
                [role; 32],
            );
            let adm = irium_node_rs::poawx_admission::CandidateAdmissionV1::new_with_v2(
                net,
                height,
                seed,
                cand,
                Some(proof),
            );
            hex::encode(adm.serialize())
        };
        let hexes: Vec<String> = roles
            .iter()
            .enumerate()
            .map(|(i, &r)| mk_adm(7 + i as u8, r))
            .collect();

        // (17) pool extracts the admitted V2 proofs.
        let proofs = build_admitted_v2_proofs(&hexes, height, &seed);
        assert_eq!(proofs.len(), 3, "3 admitted V2 proofs extracted");
        // (18) pool builds a candidate set whose digests are the VRF outputs (score
        // derives from the VRF output).
        let cs = build_admitted_candidate_set(&hexes, net, height, &seed).expect("cs");
        assert_eq!(cs.candidates.len(), 3);
        for c in &cs.candidates {
            let p = proofs.get(&(c.role_id, c.solver_pkh)).unwrap();
            assert_eq!(
                c.assignment_proof_digest, p.vrf_output,
                "candidate digest == VRF output"
            );
        }

        // Populate the pool admitted cache (as refresh_pool_admitted_cache would).
        pool_admitted_cache()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(height, hexes.clone());

        let rr = RoleRewardMirror {
            compute_contributor_pkh: primary,
            verify_contributor_pkh: primary,
            support_contributor_pkh: primary,
        };
        // (19) pool builds the AVR2 section for the selected candidates.
        assert!(
            build_pool_true_vrf_section(height, &seed, &rr).is_some(),
            "AVR2 section built"
        );

        // (21) official fee-0 production attaches AVR2; node deserializes the bytes.
        let off = build_synthetic_phase20_ext(net, height, &seed, &primary, &[], None)
            .expect("official ext");
        assert_eq!(off.fee_bps, 0, "official fee-0");
        let v2 = off
            .role_assignment_v2
            .as_ref()
            .expect("AVR2 attached (official)");
        assert_eq!(v2.len(), 3);
        let node_off =
            irium_node_rs::poawx::Phase20ReceiptExt::deserialize(&off.serialize()).unwrap();
        assert!(
            node_off.role_assignment_v2.is_some(),
            "node parses AVR2 (official)"
        );
        // (22) third-party fee production also attaches AVR2 and preserves the fee.
        let tp = build_synthetic_phase20_ext(
            net,
            height,
            &seed,
            &primary,
            &[],
            Some((100, [0xFEu8; 20])),
        )
        .expect("third-party ext");
        assert_eq!(tp.fee_bps, 100, "third-party fee preserved");
        assert!(
            tp.role_assignment_v2.is_some(),
            "AVR2 attached (third-party)"
        );

        // (20) fail-closed: drop one role's proof -> builder emits nothing.
        let missing: Vec<String> = hexes[..2].to_vec();
        pool_admitted_cache()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(height, missing);
        assert!(
            build_pool_true_vrf_section(height, &seed, &rr).is_none(),
            "fail closed (missing proof)"
        );
        assert!(
            build_synthetic_phase20_ext(net, height, &seed, &primary, &[], None).is_none(),
            "synthetic builder fails closed when a selected V2 proof is missing"
        );

        pool_admitted_cache()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_SYNTHETIC_ROLE_CLAIMS");
        std::env::remove_var("IRIUM_POAWX_CANDIDATE_ADMISSION_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_CANDIDATE_ADMISSION_REQUIRED");
        std::env::remove_var("IRIUM_POAWX_TRUE_VRF_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_TRUE_VRF_REQUIRED");
    }

    #[test]
    fn phase24h_role_reward_derived_from_admitted_candidates() {
        let _g = p20_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_SYNTHETIC_ROLE_CLAIMS", "1");
        std::env::set_var("IRIUM_POAWX_CANDIDATE_ADMISSION_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_CANDIDATE_ADMISSION_REQUIRED", "1");
        std::env::set_var("IRIUM_POAWX_TRUE_VRF_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_TRUE_VRF_REQUIRED", "1");
        let net = network_id_from_env();
        let height = 7u64;
        let seed = [0x44u8; 32];
        let primary = [0xA0u8; 20];
        // admitted candidates with DISTINCT solvers per role (none == primary).
        let roles = [
            (ROLE_COMPUTE_CONTRIBUTOR, [0xC1u8; 20], 7u8),
            (ROLE_VERIFY_CONTRIBUTOR, [0xC2u8; 20], 8u8),
            (ROLE_SUPPORT_CONTRIBUTOR, [0xC3u8; 20], 9u8),
        ];
        let hexes: Vec<String> = roles
            .iter()
            .map(|&(role, solver, secret)| {
                let proof = irium_node_rs::poawx_candidate::AssignmentProofV2::prove(
                    &[secret; 32],
                    net,
                    height,
                    role,
                    solver,
                    [role; 32],
                    seed,
                )
                .unwrap();
                let cand = irium_node_rs::poawx_candidate::RoleCandidate::from_assignment_v2(
                    &proof,
                    irium_node_rs::poawx_penalty::PenaltyStatus::Clean.id(),
                    1000,
                    [role; 32],
                );
                let adm = irium_node_rs::poawx_admission::CandidateAdmissionV1::new_with_v2(
                    net,
                    height,
                    seed,
                    cand,
                    Some(proof),
                );
                hex::encode(adm.serialize())
            })
            .collect();
        pool_admitted_cache()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(height, hexes);

        // (1)(2) role_reward solvers come from the admitted candidates, NOT primary_pkh.
        let off = build_synthetic_phase20_ext(net, height, &seed, &primary, &[], None)
            .expect("official ext");
        assert_eq!(off.role_reward.compute_contributor_pkh, [0xC1u8; 20]);
        assert_eq!(off.role_reward.verify_contributor_pkh, [0xC2u8; 20]);
        assert_eq!(off.role_reward.support_contributor_pkh, [0xC3u8; 20]);
        assert_ne!(
            off.role_reward.compute_contributor_pkh, primary,
            "not forced to primary"
        );
        // (6) AVR2 bundled (looked up by the admitted role_reward solvers).
        assert!(
            off.role_assignment_v2.is_some(),
            "AVR2 bundled for admitted solvers"
        );
        // the candidate set + role claims agree with role_reward.
        let cs = off.candidate_set.as_ref().expect("candidate set");
        assert_eq!(
            cs.best_for_role(ROLE_COMPUTE_CONTRIBUTOR)
                .unwrap()
                .solver_pkh,
            [0xC1u8; 20]
        );
        assert_eq!(
            off.compute_claim.solver_pkh, [0xC1u8; 20],
            "claim solver matches role_reward"
        );
        // (3) official fee-0.
        assert_eq!(off.fee_bps, 0);
        assert_eq!(off.fee_pkh, [0u8; 20]);
        // (4) third-party fee: PRIMARY-only fee terms set; role solvers (rewards) unchanged.
        let tp = build_synthetic_phase20_ext(
            net,
            height,
            &seed,
            &primary,
            &[],
            Some((100, [0xFEu8; 20])),
        )
        .expect("third-party ext");
        assert_eq!(tp.fee_bps, 100);
        assert_eq!(tp.fee_pkh, [0xFEu8; 20]);
        assert_eq!(
            tp.role_reward.compute_contributor_pkh, [0xC1u8; 20],
            "role rewards untaxed"
        );
        // (5) fail-closed: drop the SUPPORT admission -> no ext.
        let two: Vec<String> = pool_admitted_cache()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&height)
            .unwrap()[..2]
            .to_vec();
        pool_admitted_cache()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(height, two);
        assert!(
            build_synthetic_phase20_ext(net, height, &seed, &primary, &[], None).is_none(),
            "fail-closed when a role's admitted candidate is missing"
        );
        // helper fail-closed on empty cache.
        pool_admitted_cache()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        assert!(
            pool_role_reward_from_admitted(net, height, &seed).is_none(),
            "helper fail-closed"
        );

        for v in [
            "IRIUM_NETWORK",
            "IRIUM_POAWX_SYNTHETIC_ROLE_CLAIMS",
            "IRIUM_POAWX_CANDIDATE_ADMISSION_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_CANDIDATE_ADMISSION_REQUIRED",
            "IRIUM_POAWX_TRUE_VRF_ACTIVATION_HEIGHT",
            "IRIUM_POAWX_TRUE_VRF_REQUIRED",
        ] {
            std::env::remove_var(v);
        }
    }

    #[test]
    fn phase22d_pool_true_vrf_parity_and_failclosed() {
        // (a) proof-level wire parity vs the canonical node AssignmentProofV2.
        let proof = irium_node_rs::poawx_candidate::AssignmentProofV2::prove(
            &[7u8; 32],
            1,
            10,
            1,
            [0xAAu8; 20],
            [0x11u8; 32],
            [0x22u8; 32],
        )
        .expect("node prove");
        let canon = proof.serialize();
        assert_eq!(canon.len(), ASSIGNMENT_PROOF_V2_WIRE);
        let mir = AssignmentProofV2Mirror::deserialize(&canon).unwrap();
        assert_eq!(mir.serialize(), canon, "mirror re-serialize == node wire");
        let back = irium_node_rs::poawx_candidate::AssignmentProofV2::deserialize(&mir.serialize())
            .unwrap();
        assert_eq!(back, proof, "node round-trips the mirror bytes");
        assert_eq!(
            ASSIGNMENT_V2_SECTION_MAGIC,
            irium_node_rs::poawx_candidate::ASSIGNMENT_V2_SECTION_MAGIC,
            "AVR2 magic parity"
        );

        // (b) ext-with-AVR2 wire + digest parity (3 proofs).
        let mk = |secret: u8, role: u8, solver: [u8; 20]| {
            irium_node_rs::poawx_candidate::AssignmentProofV2::prove(
                &[secret; 32],
                1,
                11,
                role,
                solver,
                [role; 32],
                [0x55u8; 32],
            )
            .unwrap()
        };
        let np = [
            mk(7, 1, [0xC1u8; 20]),
            mk(8, 2, [0xC2u8; 20]),
            mk(9, 3, [0xC3u8; 20]),
        ];
        let mp = [
            AssignmentProofV2Mirror::deserialize(&np[0].serialize()).unwrap(),
            AssignmentProofV2Mirror::deserialize(&np[1].serialize()).unwrap(),
            AssignmentProofV2Mirror::deserialize(&np[2].serialize()).unwrap(),
        ];
        let claim_pool = |role: u8| PoawxRoleClaimMirror {
            role_id: role,
            lane_id: LANE_GPU_PARALLEL,
            solver_pkh: [role; 20],
            nonce: [role; 32],
            secret: [role.wrapping_add(1); 32],
            claim_digest: [role.wrapping_add(2); 32],
            commitment_hash: None,
        };
        let claim_node = |role: u8| irium_node_rs::poawx::PoawxRoleClaim {
            role_id: role,
            lane_id: LANE_GPU_PARALLEL,
            solver_pkh: [role; 20],
            nonce: [role; 32],
            secret: [role.wrapping_add(1); 32],
            claim_digest: [role.wrapping_add(2); 32],
            commitment_hash: None,
        };
        let mut pe = Phase20ReceiptExtMirror {
            role_reward: RoleRewardMirror {
                compute_contributor_pkh: [0xC1u8; 20],
                verify_contributor_pkh: [0xC2u8; 20],
                support_contributor_pkh: [0xC3u8; 20],
            },
            compute_claim: claim_pool(1),
            verify_claim: claim_pool(2),
            support_claim: claim_pool(3),
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
        };
        attach_true_vrf_section(&mut pe, mp);
        let ne = irium_node_rs::poawx::Phase20ReceiptExt {
            role_reward: irium_node_rs::poawx::RoleReward {
                compute_contributor_pkh: [0xC1u8; 20],
                verify_contributor_pkh: [0xC2u8; 20],
                support_contributor_pkh: [0xC3u8; 20],
            },
            compute_claim: claim_node(1),
            verify_claim: claim_node(2),
            support_claim: claim_node(3),
            fee_bps: 0,
            fee_pkh: [0u8; 20],
            precommit_root: None,
            role_ticket_proofs: None,
            role_dominance_weights: None,
            candidate_set: None,
            role_puzzle_proofs: None,
            finality_proof: None,
            committed_admission: None,
            role_assignment_v2: Some([np[0].clone(), np[1].clone(), np[2].clone()]),
            fraud_proofs: None,
            proposer_assignment: None,
            proposer_registrations: None,
            delegation_revocations: None,
        };
        assert_eq!(pe.serialize(), ne.serialize(), "ext AVR2 wire parity");
        assert_eq!(pe.digest(), ne.digest(), "ext AVR2 digest parity");
        assert_eq!(
            irium_node_rs::poawx::Phase20ReceiptExt::deserialize(&pe.serialize()).unwrap(),
            ne,
            "node deserializes pool AVR2 bytes"
        );

        // (c) fail-closed: the synthetic builder emits nothing under V2 enforcement
        // (the pool holds no VRF secret), and mainnet is hard-off.
        let _g = p20_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_SYNTHETIC_ROLE_CLAIMS", "1");
        std::env::set_var("IRIUM_POAWX_MULTI_ROLE_REWARD_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_FAIRNESS_MATRIX_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_TRUE_VRF_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_TRUE_VRF_REQUIRED", "1");
        let net = network_id_from_env();
        assert!(pool_true_vrf_enforced(5), "enforced on testnet");
        assert!(
            build_synthetic_phase20_ext(net, 5, &[0x44u8; 32], &[0xA0u8; 20], &[], None).is_none(),
            "synthetic builder fails closed under true-VRF"
        );
        std::env::set_var("IRIUM_NETWORK", "mainnet");
        assert!(!pool_true_vrf_enforced(5), "mainnet hard-off");
        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_SYNTHETIC_ROLE_CLAIMS");
        std::env::remove_var("IRIUM_POAWX_MULTI_ROLE_REWARD_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_FAIRNESS_MATRIX_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_TRUE_VRF_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_TRUE_VRF_REQUIRED");
    }

    #[test]
    fn phase22a_pool_committed_admission_parity_and_failclosed() {
        let _g = p20_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_COMMITTED_ADMISSION_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_COMMITTED_ADMISSION_REQUIRED", "1");
        std::env::set_var("IRIUM_POAWX_CANDIDATE_ADMISSION_ACTIVATION_HEIGHT", "1");
        let net = network_id_from_env();
        assert!(pool_committed_admission_enforced(5), "enforced on testnet");
        assert!(
            !pool_committed_admission_enforced(0),
            "below activation off"
        );

        let target = 5u64;
        let seed = [0x44u8; 32];
        use irium_node_rs::poawx_admission::CandidateAdmissionV1 as NAV;
        use irium_node_rs::poawx_candidate::RoleCandidate as NRC;
        let mk = |role: u8, solver: [u8; 20], tag: u8| {
            NRC::build(
                net,
                target,
                &seed,
                role,
                solver,
                [0x02u8; 33],
                [tag; 32],
                0,
                1000,
                [tag.wrapping_add(1); 32],
            )
        };
        let cands = [
            mk(1, [0xC1u8; 20], 0x11),
            mk(2, [0xC2u8; 20], 0x12),
            mk(3, [0xC3u8; 20], 0x13),
        ];
        let hexes: Vec<String> = cands
            .iter()
            .map(|c| hex::encode(NAV::new(net, target, seed, c.clone()).serialize()))
            .collect();
        pool_admitted_cache()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(target, hexes.clone());

        // pool builds the committed admission; node validates it + root parity.
        let ca = build_pool_committed_admission(net, target, &seed).expect("commitment");
        let node_ca = irium_node_rs::poawx_committed_admission::AdmissionCommitmentV1::deserialize(
            &ca.serialize(),
        )
        .unwrap();
        assert!(
            node_ca.validate(net, target).is_ok(),
            "node validates pool commitment"
        );
        assert_eq!(node_ca.commit_height, target - 1);
        // node admitted set (same admissions) root == committed root (parity).
        let cache = irium_node_rs::poawx_admission::NodeCandidateAdmissionCache::new();
        cache.set_tip(target);
        for hx in &hexes {
            let _ = cache.ingest_bytes(&hex::decode(hx).unwrap());
        }
        let node_set = cache.admitted_candidate_set(net, target, &seed);
        assert_eq!(
            node_ca.candidate_admission_root,
            node_set.root(),
            "committed root == node admitted set root"
        );
        assert!(
            node_ca.matches_candidate_set(&node_set),
            "commitment matches node set"
        );

        // fail-closed: no admitted candidates => None.
        pool_admitted_cache()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        assert!(
            build_pool_committed_admission(net, target, &seed).is_none(),
            "no admitted candidates => None"
        );

        // mainnet hard-off.
        std::env::set_var("IRIUM_NETWORK", "mainnet");
        assert!(!pool_committed_admission_enforced(5), "mainnet hard-off");

        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_COMMITTED_ADMISSION_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_COMMITTED_ADMISSION_REQUIRED");
        std::env::remove_var("IRIUM_POAWX_CANDIDATE_ADMISSION_ACTIVATION_HEIGHT");
    }

    #[test]
    fn phase21h_pool_finality_proof_parity_and_failclosed() {
        let _g = p20_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_FINALITY_COMMITTEE_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_FINALITY_COMMITTEE_REQUIRED", "1");
        std::env::set_var("IRIUM_POAWX_FINALITY_THRESHOLD_NUM", "1");
        std::env::set_var("IRIUM_POAWX_FINALITY_THRESHOLD_DEN", "1");
        std::env::set_var("IRIUM_POAWX_SYNTHETIC_ROLE_CLAIMS", "1");
        let net = network_id_from_env();
        assert!(pool_finality_committee_enforced(1), "enforced on testnet");

        let h = 5u64;
        let seed = [0x44u8; 32];
        use irium_node_rs::poawx_finality::{
            FinalityProofV1 as NP, FinalityVoteType as NVT, FinalityVoteV1 as NV,
        };
        let member = k256::ecdsa::SigningKey::from_slice(&[0x21u8; 32]).unwrap();
        let vote = NV::signed(
            &member,
            net,
            h,
            seed,
            [0u8; 32],
            0,
            [0x11u8; 32],
            NVT::Commit,
        );
        let member_pkh = vote.member_pkh;
        pool_finality_vote_cache()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(h, vec![hex::encode(vote.serialize())]);

        // pool bundles -> node verifies the bundled proof (parity, 1-of-1).
        let proof = build_pool_finality_proof(net, h, &seed, 1, 1).expect("proof");
        let node_proof = NP::deserialize(&proof.serialize()).unwrap();
        assert!(
            node_proof.validate(net, h, &seed, &[member_pkh]).is_ok(),
            "node accepts pool-bundled finality proof"
        );

        // build_synthetic attaches the finality proof + node reads FIN1.
        let ext = build_synthetic_phase20_ext(net, h, &seed, &[0xA0u8; 20], &[], None)
            .expect("ext with finality proof");
        assert!(ext.finality_proof.is_some(), "finality proof attached");
        let node_ext =
            irium_node_rs::poawx::Phase20ReceiptExt::deserialize(&ext.serialize()).unwrap();
        assert!(node_ext.finality_proof.is_some(), "node reads pool FIN1");

        // fail-closed: no collected votes => None proof => None ext.
        pool_finality_vote_cache()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        assert!(
            build_pool_finality_proof(net, h, &seed, 1, 1).is_none(),
            "no votes => None"
        );
        assert!(
            build_synthetic_phase20_ext(net, h, &seed, &[0xA0u8; 20], &[], None).is_none(),
            "fail closed without collected votes"
        );

        // mainnet hard-off.
        std::env::set_var("IRIUM_NETWORK", "mainnet");
        assert!(!pool_finality_committee_enforced(1), "mainnet hard-off");

        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_FINALITY_COMMITTEE_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_FINALITY_COMMITTEE_REQUIRED");
        std::env::remove_var("IRIUM_POAWX_FINALITY_THRESHOLD_NUM");
        std::env::remove_var("IRIUM_POAWX_FINALITY_THRESHOLD_DEN");
        std::env::remove_var("IRIUM_POAWX_SYNTHETIC_ROLE_CLAIMS");
    }

    #[test]
    fn phase21f_pool_puzzle_proofs_parity_and_failclosed() {
        let _g = p20_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_PUZZLE_WORK_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_PUZZLE_WORK_REQUIRED", "1");
        std::env::set_var("IRIUM_POAWX_PUZZLE_BITS", "4");
        std::env::set_var("IRIUM_POAWX_CANDIDATE_SET_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_CANDIDATE_SET_REQUIRED", "1");
        std::env::set_var("IRIUM_POAWX_SYNTHETIC_ROLE_CLAIMS", "1");
        let net = network_id_from_env();
        assert!(pool_puzzle_work_enforced(1), "enforced on testnet");

        let h = 5u64;
        let seed = [0x44u8; 32];
        let rr = RoleRewardMirror {
            compute_contributor_pkh: [0xC1u8; 20],
            verify_contributor_pkh: [0xC2u8; 20],
            support_contributor_pkh: [0xC3u8; 20],
        };
        let cs = build_pool_candidate_set(net, h, &seed, &rr);
        let proofs = build_pool_puzzle_proofs(net, h, &seed, &cs).expect("proofs");

        // each pool-solved puzzle verifies against the node lib (parity).
        for (i, role) in [
            ROLE_COMPUTE_CONTRIBUTOR,
            ROLE_VERIFY_CONTRIBUTOR,
            ROLE_SUPPORT_CONTRIBUTOR,
        ]
        .iter()
        .enumerate()
        {
            let cand = cs.best_for_role(*role).unwrap();
            let ncand = irium_node_rs::poawx_candidate::RoleCandidate::build(
                net,
                h,
                &seed,
                *role,
                cand.solver_pkh,
                cand.assignment_public_key,
                cand.ticket_digest,
                cand.penalty_status,
                cand.dominance_weight,
                cand.role_claim_digest,
            );
            let cdg: [u8; 32] = {
                let mut hh = Sha256::new();
                hh.update(ncand.serialize());
                hh.finalize().into()
            };
            let nch = irium_node_rs::poawx_puzzle::PuzzleChallengeV1::build(
                net,
                h,
                *role,
                cand.solver_pkh,
                cand.ticket_digest,
                cand.assignment_proof_digest,
                cdg,
                seed,
                irium_node_rs::poawx_puzzle::default_profile(),
            );
            let nsol =
                irium_node_rs::poawx_puzzle::PuzzleSolutionV1::deserialize(&proofs[i].serialize())
                    .unwrap();
            assert!(
                irium_node_rs::poawx_puzzle::verify_solution(&nch, &nsol).is_valid(),
                "node verifies pool puzzle role {}",
                role
            );
        }

        // build_synthetic attaches candidate set + puzzle proofs when enforced.
        let ext = build_synthetic_phase20_ext(net, h, &seed, &[0xA0u8; 20], &[], None)
            .expect("ext with puzzle proofs");
        assert!(ext.candidate_set.is_some());
        assert!(ext.role_puzzle_proofs.is_some(), "puzzle proofs attached");
        let node_ext =
            irium_node_rs::poawx::Phase20ReceiptExt::deserialize(&ext.serialize()).unwrap();
        assert!(
            node_ext.role_puzzle_proofs.is_some(),
            "node reads pool PZL1 section"
        );

        // fail closed: puzzle enforced but no candidate set => None ext.
        std::env::remove_var("IRIUM_POAWX_CANDIDATE_SET_REQUIRED");
        std::env::remove_var("IRIUM_POAWX_CANDIDATE_SET_ACTIVATION_HEIGHT");
        assert!(
            build_synthetic_phase20_ext(net, h, &seed, &[0xA0u8; 20], &[], None).is_none(),
            "fail closed without candidate set"
        );

        // mainnet hard-off.
        std::env::set_var("IRIUM_NETWORK", "mainnet");
        assert!(!pool_puzzle_work_enforced(1), "mainnet hard-off");

        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_PUZZLE_WORK_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_PUZZLE_WORK_REQUIRED");
        std::env::remove_var("IRIUM_POAWX_PUZZLE_BITS");
        std::env::remove_var("IRIUM_POAWX_SYNTHETIC_ROLE_CLAIMS");
    }

    #[test]
    fn phase21e_pool_admitted_candidate_set_parity_and_failclosed() {
        let _g = p20_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_CANDIDATE_ADMISSION_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_CANDIDATE_ADMISSION_REQUIRED", "1");
        std::env::set_var("IRIUM_POAWX_SYNTHETIC_ROLE_CLAIMS", "1");
        let net = network_id_from_env();
        assert!(pool_candidate_admission_enforced(1), "enforced on testnet");

        let h = 5u64;
        let seed = [0x44u8; 32];
        use irium_node_rs::poawx_admission::CandidateAdmissionV1 as NAV;
        use irium_node_rs::poawx_candidate::RoleCandidate as NRC;
        let mk = |role: u8, solver: [u8; 20], tag: u8| {
            NRC::build(
                net,
                h,
                &seed,
                role,
                solver,
                [0x02u8; 33],
                [tag; 32],
                0,
                1000,
                [tag.wrapping_add(1); 32],
            )
        };
        let cands = [
            mk(1, [0xC1u8; 20], 0x11),
            mk(2, [0xC2u8; 20], 0x12),
            mk(3, [0xC3u8; 20], 0x13),
        ];
        let hexes: Vec<String> = cands
            .iter()
            .map(|c| hex::encode(NAV::new(net, h, seed, c.clone()).serialize()))
            .collect();

        // pool builds the admitted set; must byte-match the node admitted set.
        let pool_cs = build_admitted_candidate_set(&hexes, net, h, &seed).expect("set");
        let cache = irium_node_rs::poawx_admission::NodeCandidateAdmissionCache::new();
        cache.set_tip(h);
        for hx in &hexes {
            let _ = cache.ingest_bytes(&hex::decode(hx).unwrap());
        }
        let node_cs = cache.admitted_candidate_set(net, h, &seed);
        assert_eq!(
            pool_cs.serialize(),
            node_cs.serialize(),
            "pool admitted set == node admitted set"
        );

        // decode roundtrip.
        let (dh, ds, dc) = decode_admission_candidate(&hexes[0]).unwrap();
        assert_eq!(dh, h);
        assert_eq!(ds, seed);
        assert_eq!(
            dc.serialize(),
            cands[0].serialize(),
            "candidate decode parity"
        );

        // wrong seed => no admitted candidates => None (fail closed).
        assert!(
            build_admitted_candidate_set(&hexes, net, h, &[0x99u8; 32]).is_none(),
            "wrong seed yields empty -> None"
        );

        // builder fail-closed: admission enforced + empty admitted cache => None ext.
        pool_admitted_cache()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        assert!(
            build_synthetic_phase20_ext(net, h, &seed, &[0xA0u8; 20], &[], None).is_none(),
            "fail closed when admitted cache empty"
        );
        // populate cache => builder attaches the admitted set.
        pool_admitted_cache()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(h, hexes.clone());
        let ext =
            build_synthetic_phase20_ext(net, h, &seed, &[0xA0u8; 20], &[], None).expect("ext");
        assert_eq!(
            ext.candidate_set.as_ref().unwrap().serialize(),
            pool_cs.serialize(),
            "builder attaches the admitted set"
        );

        // mainnet hard-off.
        std::env::set_var("IRIUM_NETWORK", "mainnet");
        assert!(!pool_candidate_admission_enforced(1), "mainnet hard-off");

        pool_admitted_cache()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_CANDIDATE_ADMISSION_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_CANDIDATE_ADMISSION_REQUIRED");
        std::env::remove_var("IRIUM_POAWX_SYNTHETIC_ROLE_CLAIMS");
    }

    #[test]
    fn phase21d_pool_candidate_set_parity() {
        let _g = p20_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_CANDIDATE_SET_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_CANDIDATE_SET_REQUIRED", "1");
        std::env::set_var("IRIUM_POAWX_SYNTHETIC_ROLE_CLAIMS", "1");
        let net = network_id_from_env();
        assert!(pool_candidate_set_enforced(1), "enforced on testnet");
        assert!(!pool_candidate_set_enforced(0), "below activation off");

        let h = 5u64;
        let prev = [0x44u8; 32];
        let (cc, vv, ss) = ([0xC1u8; 20], [0xC2u8; 20], [0xC3u8; 20]);
        let rr = RoleRewardMirror {
            compute_contributor_pkh: cc,
            verify_contributor_pkh: vv,
            support_contributor_pkh: ss,
        };
        let cs = build_pool_candidate_set(net, h, &prev, &rr);
        assert_eq!(cs.candidates.len(), 3);

        // candidate-set wire + root + best_for_role parity with the node lib.
        let node_cs =
            irium_node_rs::poawx_candidate::CandidateSet::deserialize(&cs.serialize()).unwrap();
        assert_eq!(
            node_cs.serialize(),
            cs.serialize(),
            "candidate set wire parity"
        );
        assert_eq!(node_cs.root(), cs.root(), "candidate set root parity");
        for role in [1u8, 2, 3] {
            assert_eq!(
                node_cs.best_for_role(role).unwrap().solver_pkh,
                cs.best_for_role(role).unwrap().solver_pkh,
                "best-for-role parity"
            );
        }
        // assignment-proof digest parity (VRF-style placeholder is recomputable).
        let c0 = &cs.candidates[0];
        let nd = irium_node_rs::poawx_candidate::compute_assignment_proof_digest(
            net,
            h,
            c0.role_id,
            &c0.solver_pkh,
            &c0.assignment_public_key,
            &c0.ticket_digest,
            &prev,
        );
        assert_eq!(
            nd, c0.assignment_proof_digest,
            "assignment proof digest parity"
        );

        // full ext: pool attaches CND1 when enforced; node reads it back.
        let primary = [0xA0u8; 20];
        let ext = build_synthetic_phase20_ext(net, h, &prev, &primary, &[], None).expect("ext");
        assert!(
            ext.candidate_set.is_some(),
            "candidate set attached when enforced"
        );
        let node_ext =
            irium_node_rs::poawx::Phase20ReceiptExt::deserialize(&ext.serialize()).unwrap();
        assert_eq!(
            node_ext.candidate_set.as_ref().unwrap().root(),
            ext.candidate_set.as_ref().unwrap().root(),
            "node reads pool CND1 section"
        );

        // gate off => no candidate set (byte-identical pre-21D).
        std::env::remove_var("IRIUM_POAWX_CANDIDATE_SET_REQUIRED");
        let ext_off = build_synthetic_phase20_ext(net, h, &prev, &primary, &[], None).expect("ext");
        assert!(
            ext_off.candidate_set.is_none(),
            "no candidate set when gate off"
        );
        assert!(
            ext_off
                .serialize()
                .windows(4)
                .all(|w| w != &CANDIDATE_SECTION_MAGIC[..]),
            "no CND1 magic when absent"
        );

        // mainnet hard-off.
        std::env::set_var("IRIUM_NETWORK", "mainnet");
        assert!(!pool_candidate_set_enforced(1), "mainnet hard-off");

        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_CANDIDATE_SET_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_SYNTHETIC_ROLE_CLAIMS");
    }

    #[test]
    fn phase21c_pool_dominance_weights_and_selection() {
        let _g = p20_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_ANTI_DOMINATION_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_ANTI_DOMINATION_REQUIRED", "1");
        let net = network_id_from_env();
        assert!(pool_anti_domination_enforced(1), "enforced on testnet");
        assert!(!pool_anti_domination_enforced(0), "below activation off");

        let h = 5u64;
        let prev = [0x44u8; 32];
        let (cc, vv, ss) = ([0xC1u8; 20], [0xC2u8; 20], [0xC3u8; 20]);
        let primary = [0xA0u8; 20];
        let base = DOMINANCE_BASE_WORK_SCORE;

        let mut view = PoolDominanceView::new();
        view.record(primary, 7_000);
        view.record(cc, 3_000);
        let rr = RoleRewardMirror {
            compute_contributor_pkh: cc,
            verify_contributor_pkh: vv,
            support_contributor_pkh: ss,
        };
        let weights = pool_role_dominance_weights(&primary, &rr, &view, base);
        assert!(weights[0] < base, "primary (heavier) down-weighted");
        assert!(
            weights[1] < base && weights[1] > weights[0],
            "compute lighter than primary"
        );
        assert_eq!(weights[2], base, "fresh verify keeps full weight");

        let mk_claim = |role: u8, solver: [u8; 20]| PoawxRoleClaimMirror {
            role_id: role,
            lane_id: assign_lane_id(net, h, &prev, role, 0),
            solver_pkh: solver,
            nonce: [role; 32],
            secret: [role.wrapping_add(9); 32],
            claim_digest: role_claim_digest(
                net,
                h,
                &prev,
                role,
                assign_lane_id(net, h, &prev, role, 0),
                &solver,
                &[role; 32],
                &[role.wrapping_add(9); 32],
            ),
            commitment_hash: None,
        };
        let ext = Phase20ReceiptExtMirror {
            role_reward: rr.clone(),
            compute_claim: mk_claim(ROLE_COMPUTE_CONTRIBUTOR, cc),
            verify_claim: mk_claim(ROLE_VERIFY_CONTRIBUTOR, vv),
            support_claim: mk_claim(ROLE_SUPPORT_CONTRIBUTOR, ss),
            fee_bps: 0,
            fee_pkh: [0u8; 20],
            precommit_root: None,
            role_ticket_proofs: None,
            role_dominance_weights: Some(weights),
            candidate_set: None,
            role_puzzle_proofs: None,
            finality_proof: None,
            committed_admission: None,
            role_assignment_v2: None,
        };
        // node lib reads the pool DOM1 weights back identically (wire parity).
        let node_ext =
            irium_node_rs::poawx::Phase20ReceiptExt::deserialize(&ext.serialize()).unwrap();
        assert_eq!(
            node_ext.role_dominance_weights,
            Some(weights),
            "node reads pool DOM1 weights"
        );
        // absent => no DOM1 magic (byte-identical to pre-21C).
        let mut ext_off = ext.clone();
        ext_off.role_dominance_weights = None;
        assert!(
            ext_off
                .serialize()
                .windows(4)
                .all(|w| w != &DOMINANCE_SECTION_MAGIC[..]),
            "no DOM1 magic when absent"
        );

        // selection: fairness picks the less-recently-rewarded candidate.
        let light = [0x0Bu8; 20];
        assert_eq!(
            select_candidate_by_fairness_weight(&[primary, light], &view, base),
            Some(light),
            "fairness selects the lighter candidate"
        );
        // deterministic tie-break (equal weights) -> lower pkh.
        let empty = PoolDominanceView::new();
        assert_eq!(
            select_candidate_by_fairness_weight(&[[0x02u8; 20], [0x01u8; 20]], &empty, base),
            Some([0x01u8; 20])
        );

        // mainnet hard-off.
        std::env::set_var("IRIUM_NETWORK", "mainnet");
        assert!(!pool_anti_domination_enforced(1), "mainnet hard-off");

        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_ANTI_DOMINATION_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_ANTI_DOMINATION_REQUIRED");
    }

    #[test]
    fn phase20_gate_mainnet_off_and_heights() {
        let _g = p20_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_MULTI_ROLE_REWARD_ACTIVATION_HEIGHT", "5");
        std::env::remove_var("IRIUM_POAWX_FAIRNESS_MATRIX_ACTIVATION_HEIGHT");
        assert!(!phase20_production_active(10), "needs fairness too");
        std::env::set_var("IRIUM_POAWX_FAIRNESS_MATRIX_ACTIVATION_HEIGHT", "5");
        assert!(!phase20_production_active(4), "below activation");
        assert!(phase20_production_active(5), "both active at height");
        std::env::set_var("IRIUM_NETWORK", "mainnet");
        assert!(!phase20_production_active(10), "mainnet hard-off");
        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_MULTI_ROLE_REWARD_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_FAIRNESS_MATRIX_ACTIVATION_HEIGHT");
    }

    #[test]
    fn phase20_synthetic_disabled_or_mainnet_returns_none() {
        let _g = p20_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let prev = [0x44u8; 32];
        // disabled by default on testnet (no fakes).
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::remove_var("IRIUM_POAWX_SYNTHETIC_ROLE_CLAIMS");
        assert!(
            build_synthetic_phase20_ext(1, 10, &prev, &[0x11u8; 20], &[], None).is_none(),
            "synthetic disabled by default"
        );
        // enabled flag but mainnet (network_id 0 passed) -> None.
        std::env::set_var("IRIUM_POAWX_SYNTHETIC_ROLE_CLAIMS", "1");
        std::env::set_var("IRIUM_NETWORK", "mainnet");
        assert!(
            build_synthetic_phase20_ext(0, 10, &prev, &[0x11u8; 20], &[], None).is_none(),
            "mainnet hard-off"
        );
        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_SYNTHETIC_ROLE_CLAIMS");
    }

    #[test]
    fn phase20_synthetic_builder_valid_and_node_validator_passes() {
        let _g = p20_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_SYNTHETIC_ROLE_CLAIMS", "1");
        let net = 1u8;
        let height = 500u64;
        let prev = [0x55u8; 32];
        let primary = [0xA1u8; 20];
        let total = 5_000_000_001u64;

        let ext =
            build_synthetic_phase20_ext(net, height, &prev, &primary, &[], None).expect("ext");
        // three role claims, expected role ids, solver == primary (MVP single-miner).
        assert_eq!(ext.compute_claim.role_id, ROLE_COMPUTE_CONTRIBUTOR);
        assert_eq!(ext.verify_claim.role_id, ROLE_VERIFY_CONTRIBUTOR);
        assert_eq!(ext.support_claim.role_id, ROLE_SUPPORT_CONTRIBUTOR);
        assert_eq!(
            ext.role_reward.compute_contributor_pkh,
            ext.compute_claim.solver_pkh
        );
        assert_eq!(
            ext.role_reward.verify_contributor_pkh,
            ext.verify_claim.solver_pkh
        );
        assert_eq!(
            ext.role_reward.support_contributor_pkh,
            ext.support_claim.solver_pkh
        );
        assert_eq!(ext.fee_bps, 0, "official fee-0 only");
        assert_eq!(ext.fee_pkh, [0u8; 20]);
        // deterministic / reproducible.
        let ext2 = build_synthetic_phase20_ext(net, height, &prev, &primary, &[], None).unwrap();
        assert_eq!(
            ext.serialize(),
            ext2.serialize(),
            "synthetic builder is deterministic"
        );

        // each claim validates via the node consensus primitive.
        let node_ext =
            irium_node_rs::poawx::Phase20ReceiptExt::deserialize(&ext.serialize()).unwrap();
        for c in [
            &node_ext.compute_claim,
            &node_ext.verify_claim,
            &node_ext.support_claim,
        ] {
            irium_node_rs::poawx::validate_role_claim(c, net, height, &prev, 0)
                .expect("synthetic role claim must validate");
        }

        // Build the canonical pool coinbase outputs and assert the AUTHORITATIVE
        // node validators accept them (item 8). p2pkh = 76 a9 14 <20> 88 ac.
        let amts = multi_role_amounts(total);
        let p2pkh = |pkh: &[u8; 20]| -> Vec<u8> {
            let mut s = vec![0x76u8, 0xa9, 0x14];
            s.extend_from_slice(pkh);
            s.extend_from_slice(&[0x88, 0xac]);
            s
        };
        let irx1 = irium_node_rs::tx::TxOutput {
            value: 0,
            script_pubkey: vec![0x6a, 0x24, b'i', b'r', b'x', b'1'],
        };
        let outs = vec![
            irx1,
            irium_node_rs::tx::TxOutput {
                value: amts[0],
                script_pubkey: p2pkh(&primary),
            },
            irium_node_rs::tx::TxOutput {
                value: amts[1],
                script_pubkey: p2pkh(&node_ext.role_reward.compute_contributor_pkh),
            },
            irium_node_rs::tx::TxOutput {
                value: amts[2],
                script_pubkey: p2pkh(&node_ext.role_reward.verify_contributor_pkh),
            },
            irium_node_rs::tx::TxOutput {
                value: amts[3],
                script_pubkey: p2pkh(&node_ext.role_reward.support_contributor_pkh),
            },
        ];
        irium_node_rs::chain::validate_phase20_production_payout(
            &outs, &primary, total, height, &prev, net, &node_ext, false,
        )
        .expect("node validator must accept the pool-produced fixture");
        irium_node_rs::chain::validate_poawx_coinbase_payout(
            &outs,
            &primary,
            total,
            Some(&node_ext.role_reward),
            None,
        )
        .expect("node coinbase payout must accept the pool-produced fixture");

        // Tamper cases rejected by the node validator.
        let mut bad = outs.clone();
        bad[1].value += 1;
        assert!(
            irium_node_rs::chain::validate_phase20_production_payout(
                &bad, &primary, total, height, &prev, net, &node_ext, false
            )
            .is_err(),
            "wrong amount must reject"
        );
        let mut bad = outs.clone();
        bad.swap(1, 2);
        assert!(
            irium_node_rs::chain::validate_phase20_production_payout(
                &bad, &primary, total, height, &prev, net, &node_ext, false
            )
            .is_err(),
            "wrong order must reject"
        );
        let mut bad = outs.clone();
        bad.push(irium_node_rs::tx::TxOutput {
            value: 1,
            script_pubkey: p2pkh(&[0x9Au8; 20]),
        });
        assert!(
            irium_node_rs::chain::validate_phase20_production_payout(
                &bad, &primary, total, height, &prev, net, &node_ext, false
            )
            .is_err(),
            "hidden extra output must reject"
        );

        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_SYNTHETIC_ROLE_CLAIMS");
    }

    #[test]
    fn phase20_registry_third_party_fee() {
        let dir = temp_dir("tpfee");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("d.json");
        let store = JsonDelegationStore::open(&path).unwrap();
        let pool = SigningKey::from_slice(&[3u8; 32]).unwrap();
        let pool_pub = pk33(&pool);
        let miner = SigningKey::from_slice(&[5u8; 32]).unwrap();
        let fee_pkh = [0xFEu8; 20];
        let expected = Some((150u16, fee_pkh));

        // Official mode (expected_fee None) rejects a nonzero-fee delegation.
        let d_fee = mirror_signed_fee(&miner, pool_pub, 1, "rig1", 100, 150, fee_pkh);
        assert_eq!(
            verify_and_store(
                &store,
                &hex::encode(d_fee.serialize()),
                "rig1",
                "",
                &pool_pub,
                1,
                10,
                1,
                None
            ),
            Err(DelegError::NonZeroFee),
            "official mode rejects nonzero fee"
        );

        // Third-party mode accepts a valid signed fee that matches pool config.
        let rec = verify_and_store(
            &store,
            &hex::encode(d_fee.serialize()),
            "rig1",
            "",
            &pool_pub,
            1,
            10,
            1,
            expected,
        )
        .expect("third-party fee accepted");
        assert_eq!(rec.fee_bps, 150);
        assert_eq!(rec.fee_pkh, hex::encode(fee_pkh));
        // Reload preserves fee_bps + fee_pkh.
        let store2 = JsonDelegationStore::open(&path).unwrap();
        let got = store2.get(&rec.miner_pkh, "rig1").unwrap();
        assert_eq!(got.fee_bps, 150);
        assert_eq!(got.fee_pkh, hex::encode(fee_pkh));

        // fee_bps mismatch vs pool config rejects.
        assert_eq!(
            verify_and_store(
                &store,
                &hex::encode(d_fee.serialize()),
                "rig1",
                "",
                &pool_pub,
                1,
                10,
                1,
                Some((100, fee_pkh))
            ),
            Err(DelegError::FeeMismatch)
        );
        // fee_pkh mismatch rejects.
        assert_eq!(
            verify_and_store(
                &store,
                &hex::encode(d_fee.serialize()),
                "rig1",
                "",
                &pool_pub,
                1,
                10,
                1,
                Some((150, [0xABu8; 20]))
            ),
            Err(DelegError::FeePkhMismatch)
        );
        // Over-cap pool config never accepts a fee.
        let d_over = mirror_signed_fee(&miner, pool_pub, 1, "rig1", 100, 201, fee_pkh);
        assert_eq!(
            verify_and_store(
                &store,
                &hex::encode(d_over.serialize()),
                "rig1",
                "",
                &pool_pub,
                1,
                10,
                1,
                Some((201, fee_pkh))
            ),
            Err(DelegError::FeeMismatch)
        );
        // Post-signing fee mutation breaks the signature.
        let mut tampered = d_fee.clone();
        tampered.fee_bps = 100; // not re-signed
        assert_eq!(
            verify_and_store(
                &store,
                &hex::encode(tampered.serialize()),
                "rig1",
                "",
                &pool_pub,
                1,
                10,
                1,
                Some((100, fee_pkh))
            ),
            Err(DelegError::BadSignature)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn phase20_synthetic_builder_third_party_fee() {
        let _g = p20_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_SYNTHETIC_ROLE_CLAIMS", "1");
        let net = 1u8;
        let height = 500u64;
        let prev = [0x55u8; 32];
        let primary = [0xA1u8; 20];
        let total = 5_000_000_001u64;
        let fee_pkh = [0xFEu8; 20];

        // With fee terms, the ext carries them; without, official 0.
        let ext =
            build_synthetic_phase20_ext(net, height, &prev, &primary, &[], Some((200, fee_pkh)))
                .expect("ext");
        assert_eq!(ext.fee_bps, 200);
        assert_eq!(ext.fee_pkh, fee_pkh);
        // fee terms recoverable from the hex tail.
        assert_eq!(
            fee_terms_from_ext_hex(&hex::encode(ext.serialize())),
            Some((200, fee_pkh))
        );
        // ext digest changes when fee_bps or fee_pkh change.
        let ext0 = build_synthetic_phase20_ext(net, height, &prev, &primary, &[], None).unwrap();
        assert_ne!(ext.digest(), ext0.digest(), "fee changes ext digest");
        let ext_pkh2 = build_synthetic_phase20_ext(
            net,
            height,
            &prev,
            &primary,
            &[],
            Some((200, [0x11u8; 20])),
        )
        .unwrap();
        assert_ne!(
            ext.digest(),
            ext_pkh2.digest(),
            "fee_pkh changes ext digest"
        );

        // The node validator accepts the fee-aware fixture in third-party mode and
        // rejects it without third-party mode.
        let node_ext =
            irium_node_rs::poawx::Phase20ReceiptExt::deserialize(&ext.serialize()).unwrap();
        let amts = multi_role_amounts(total);
        let (pnet, pfee) = apply_fee(amts[0], 200);
        let p2pkh = |pkh: &[u8; 20]| {
            let mut s = vec![0x76u8, 0xa9, 0x14];
            s.extend_from_slice(pkh);
            s.extend_from_slice(&[0x88, 0xac]);
            s
        };
        let outs = vec![
            irium_node_rs::tx::TxOutput {
                value: 0,
                script_pubkey: vec![0x6a, 0x24, b'i', b'r', b'x', b'1'],
            },
            irium_node_rs::tx::TxOutput {
                value: pnet,
                script_pubkey: p2pkh(&primary),
            },
            irium_node_rs::tx::TxOutput {
                value: amts[1],
                script_pubkey: p2pkh(&node_ext.role_reward.compute_contributor_pkh),
            },
            irium_node_rs::tx::TxOutput {
                value: amts[2],
                script_pubkey: p2pkh(&node_ext.role_reward.verify_contributor_pkh),
            },
            irium_node_rs::tx::TxOutput {
                value: amts[3],
                script_pubkey: p2pkh(&node_ext.role_reward.support_contributor_pkh),
            },
            irium_node_rs::tx::TxOutput {
                value: pfee,
                script_pubkey: p2pkh(&fee_pkh),
            },
        ];
        irium_node_rs::chain::validate_phase20_production_payout(
            &outs, &primary, total, height, &prev, net, &node_ext, true,
        )
        .expect("node validator accepts third-party fee fixture");
        assert!(
            irium_node_rs::chain::validate_phase20_production_payout(
                &outs, &primary, total, height, &prev, net, &node_ext, false
            )
            .is_err(),
            "fee rejected without third-party mode"
        );

        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_SYNTHETIC_ROLE_CLAIMS");
    }

    #[test]
    fn phase20_hidden_precommit_synthetic_and_node_parity() {
        let _g = p20_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_SYNTHETIC_ROLE_CLAIMS", "1");
        std::env::set_var("IRIUM_POAWX_MULTI_ROLE_REWARD_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_FAIRNESS_MATRIX_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_HIDDEN_PRECOMMIT_ACTIVATION_HEIGHT", "1");
        let net = 1u8;
        let prev1 = [0x11u8; 32];
        let prev2 = [0x22u8; 32];
        let primary = [0xA1u8; 20];

        // Block H-1 (height 1) ext commits height-2's root; block H (height 2) ext
        // reveals height-2's claims.
        let ext1 = build_synthetic_phase20_ext(net, 1, &prev1, &primary, &[], None).expect("ext1");
        let ext2 = build_synthetic_phase20_ext(net, 2, &prev2, &primary, &[], None).expect("ext2");
        assert!(
            ext1.precommit_root.is_some(),
            "producer commits next-height root"
        );
        assert!(
            ext2.compute_claim.commitment_hash.is_some(),
            "reveal carries commitment"
        );
        // The committed root equals the pool's deterministic height-2 root.
        assert_eq!(
            ext1.precommit_root.unwrap(),
            synthetic_precommit_root(net, 2, &primary, &[])
        );

        // Node-side independent reconstruction: deserialize the reveal via the node
        // lib, reconstruct each leaf (validating the commitment binds secret/nonce),
        // and the sorted root MUST equal the parent's committed root.
        let node_ext2 =
            irium_node_rs::poawx::Phase20ReceiptExt::deserialize(&ext2.serialize()).unwrap();
        let mut leaves = Vec::new();
        for c in [
            &node_ext2.compute_claim,
            &node_ext2.verify_claim,
            &node_ext2.support_claim,
        ] {
            leaves.push(
                irium_node_rs::poawx::role_precommit_leaf_for_claim(c, net, 2)
                    .expect("valid reveal leaf"),
            );
        }
        let node_root = irium_node_rs::poawx::role_precommit_root(&leaves);
        assert_eq!(
            node_root,
            ext1.precommit_root.unwrap(),
            "node-reconstructed reveal root == pool-committed parent root"
        );
        // pool primitive == node primitive.
        assert_eq!(synthetic_precommit_root(net, 2, &primary, &[]), node_root);

        // Mutation: a tampered revealed secret fails the node commitment binding.
        let mut bad = node_ext2.compute_claim.clone();
        bad.secret = [0xFFu8; 32];
        assert!(
            irium_node_rs::poawx::role_precommit_leaf_for_claim(&bad, net, 2).is_err(),
            "mutated reveal rejected by node"
        );

        // Off-path: hidden-precommit inactive => no precommit_root / no commitment
        // (Steps 5A/5B behavior unchanged).
        std::env::remove_var("IRIUM_POAWX_HIDDEN_PRECOMMIT_ACTIVATION_HEIGHT");
        let ext_off = build_synthetic_phase20_ext(net, 2, &prev2, &primary, &[], None).unwrap();
        assert!(ext_off.precommit_root.is_none());
        assert!(ext_off.compute_claim.commitment_hash.is_none());

        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_SYNTHETIC_ROLE_CLAIMS");
        std::env::remove_var("IRIUM_POAWX_MULTI_ROLE_REWARD_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_FAIRNESS_MATRIX_ACTIVATION_HEIGHT");
    }

    // ── Step 6B: role precommit/reveal protocol payloads + store + production ──

    fn mk_precommit_dto(
        net: u8,
        h: u64,
        role: u8,
        solver: [u8; 20],
        secret: [u8; 32],
        nonce: [u8; 32],
    ) -> RolePrecommitDto {
        RolePrecommitDto {
            network_id: net,
            target_height: h,
            role_id: role,
            solver_pkh: hex::encode(solver),
            commitment_hash: hex::encode(role_precommit_commitment(&secret, &nonce)),
            worker: String::new(),
        }
    }
    fn mk_reveal_dto(
        net: u8,
        h: u64,
        prev: &[u8; 32],
        role: u8,
        solver: [u8; 20],
        secret: [u8; 32],
        nonce: [u8; 32],
    ) -> RoleRevealDto {
        let lane = assign_lane_id(net, h, prev, role, 0);
        let cd = role_claim_digest(net, h, prev, role, lane, &solver, &nonce, &secret);
        RoleRevealDto {
            network_id: net,
            target_height: h,
            role_id: role,
            lane_id: lane,
            solver_pkh: hex::encode(solver),
            secret: hex::encode(secret),
            nonce: hex::encode(nonce),
            commitment_hash: hex::encode(role_precommit_commitment(&secret, &nonce)),
            claim_digest: hex::encode(cd),
            assignment_public_key: String::new(),
            assignment_proof: String::new(),
            ticket_proof: String::new(),
            puzzle_solution: String::new(),
        }
    }

    #[test]
    #[ignore] // rig integration test: reads REAL worker bundles from IRIUM_M3_DIR
    fn phase3_m3_real_worker_bundles_collection_and_attribution() {
        // End-to-end with GENUINE Phase-2 worker output: feed real bundles through the
        // actual collection path (validate -> store -> best_bundled_reveals). Confirms the
        // pool collects, validates the Phase-1 payout bindings on real proofs, and
        // attributes each role to its rightful distinct real participant.
        let dir = std::env::var("IRIUM_M3_DIR").unwrap_or_else(|_| "/home/irium/tmp/m3".to_string());
        let load = |name: &str| -> serde_json::Value {
            serde_json::from_str(
                &std::fs::read_to_string(format!("{dir}/{name}.json")).expect("read bundle"),
            )
            .expect("bundle json")
        };
        let pkh_of = |b: &serde_json::Value| -> [u8; 20] {
            let mut o = [0u8; 20];
            o.copy_from_slice(&hex::decode(b["solver_pkh"].as_str().unwrap()).unwrap());
            o
        };
        let score_of = |b: &serde_json::Value| -> u64 {
            let ap = AssignmentProofV2Mirror::deserialize(
                &hex::decode(b["assignment_proof"].as_str().unwrap()).unwrap(),
            )
            .unwrap();
            let mut s = [0u8; 8];
            s.copy_from_slice(&ap.vrf_output[0..8]);
            u64::from_le_bytes(s)
        };
        let feed = |store: &RoleProtocolStore, b: &serde_json::Value| {
            let g = |k: &str| b[k].as_str().unwrap().to_string();
            let claim = &b["claim"];
            let cg = |k: &str| claim[k].as_str().unwrap().to_string();
            let net = b["network_id"].as_u64().unwrap() as u8;
            let h = b["target_height"].as_u64().unwrap();
            let role = b["role_id"].as_u64().unwrap() as u8;
            let pre = RolePrecommitDto {
                network_id: net,
                target_height: h,
                role_id: role,
                solver_pkh: g("solver_pkh"),
                commitment_hash: cg("commitment_hash"),
                worker: String::new(),
            };
            store
                .add_precommit(pre.validate(net).expect("real precommit valid"))
                .expect("add precommit");
            let dto = RoleRevealDto {
                network_id: net,
                target_height: h,
                role_id: role,
                lane_id: claim["lane_id"].as_u64().unwrap() as u8,
                solver_pkh: g("solver_pkh"),
                secret: cg("secret"),
                nonce: cg("nonce"),
                commitment_hash: cg("commitment_hash"),
                claim_digest: cg("claim_digest"),
                assignment_public_key: g("assignment_public_key"),
                assignment_proof: g("assignment_proof"),
                ticket_proof: g("ticket_proof"),
                puzzle_solution: g("puzzle_solution"),
            };
            // validate ENFORCES the Phase 1 binding on the REAL bundle.
            let v = dto.validate(net).expect("real bundle passes the Phase 1 binding");
            assert!(v.assignment_public_key.is_some(), "real bundle carries payout-bound proof");
            store.add_reveal(v).expect("add reveal");
        };
        let (ca, cb, vf, sp) = (load("compute_A"), load("compute_B"), load("verify_1"), load("support_1"));
        let store = RoleProtocolStore::new();
        for x in [&ca, &cb, &vf, &sp] {
            feed(&store, x);
        }
        let h = ca["target_height"].as_u64().unwrap();
        let w = store.best_bundled_reveals(h).expect("collected winners from real bundles");
        // distinct attribution: verify + support go to their own workers
        assert_eq!(w[1].claim.solver_pkh, pkh_of(&vf), "VERIFY attributed to its worker");
        assert_eq!(w[2].claim.solver_pkh, pkh_of(&sp), "SUPPORT attributed to its worker");
        // best_for_role: the COMPUTE winner is the higher-self-VRF-score real competitor
        let (sa, sb) = (score_of(&ca), score_of(&cb));
        let win_score = {
            let ap = AssignmentProofV2Mirror::deserialize(&w[0].assignment_proof).unwrap();
            let mut s = [0u8; 8];
            s.copy_from_slice(&ap.vrf_output[0..8]);
            u64::from_le_bytes(s)
        };
        assert_eq!(win_score, sa.max(sb), "COMPUTE winner has the higher self-VRF score");
        assert!(
            w[0].claim.solver_pkh == pkh_of(&ca) || w[0].claim.solver_pkh == pkh_of(&cb),
            "COMPUTE winner is one of the two real competitors"
        );
        println!(
            "[m3] REAL bundles: compute A={} B={} -> winner score {} pkh {}; verify {}; support {}",
            sa, sb, win_score, hex::encode(w[0].claim.solver_pkh),
            hex::encode(w[1].claim.solver_pkh), hex::encode(w[2].claim.solver_pkh)
        );
    }

    #[test]
    #[ignore] // rig: the SWAPPED live call-site build_collected_bundle_ext produces the compliant ext + fallback
    fn phase4_live_callsite_build_collected_bundle_ext_and_fallback() {
        // Step 2 receipt-producer upgrade (operator-orchestrated). Proves the SWAPPED live
        // call-site -- build_session_poawx_receipts now calls build_collected_bundle_ext
        // (stratum.rs), not build_collected_phase20_ext -- produces the COMPLIANT multi-role
        // payout-split ext from REAL role-worker bundles fed through the SAME ingest-
        // validation the live loopback endpoints use (RoleRevealDto::validate + add_reveal +
        // add_precommit). Each contributor role is attributed to its own DISTINCT participant
        // by best_for_role VRF selection and carries that participant's OWN ticket + puzzle
        // proofs. The automatic fallback (empty store / mainnet net==0 / role-protocol-off ->
        // None) preserves today's exact behavior. SCOPE: the bundles come from the single
        // pool operator's own workers; accepting independent external submissions from
        // separate untrusting participants over the network is Option B (a future project).
        std::env::set_var("IRIUM_NETWORK", "devnet");
        std::env::set_var("IRIUM_POAWX_ROLE_PROTOCOL_ENABLED", "1");
        std::env::set_var("IRIUM_POAWX_CONTRIBUTOR_ROLE_BINDING_ACTIVATION_HEIGHT", "1");
        let net = 2u8;

        let dir = std::env::var("IRIUM_M3_DIR").unwrap_or_else(|_| "/home/irium/tmp/m3".to_string());
        let load = |name: &str| -> serde_json::Value {
            serde_json::from_str(
                &std::fs::read_to_string(format!("{dir}/{name}.json")).expect("read real bundle"),
            )
            .expect("bundle json")
        };
        let pkh_of = |b: &serde_json::Value| -> [u8; 20] {
            let mut o = [0u8; 20];
            o.copy_from_slice(&hex::decode(b["solver_pkh"].as_str().unwrap()).unwrap());
            o
        };
        let score_of = |b: &serde_json::Value| -> u64 {
            let ap = AssignmentProofV2Mirror::deserialize(
                &hex::decode(b["assignment_proof"].as_str().unwrap()).unwrap(),
            )
            .unwrap();
            let mut s = [0u8; 8];
            s.copy_from_slice(&ap.vrf_output[0..8]);
            u64::from_le_bytes(s)
        };
        // Feed a bundle EXACTLY as the live loopback ingest does: validate the precommit +
        // reveal DTOs, then add to the shared store.
        let feed = |store: &RoleProtocolStore, b: &serde_json::Value| {
            let g = |k: &str| b[k].as_str().unwrap().to_string();
            let claim = &b["claim"];
            let cg = |k: &str| claim[k].as_str().unwrap().to_string();
            let h = b["target_height"].as_u64().unwrap();
            let role = b["role_id"].as_u64().unwrap() as u8;
            let pre = RolePrecommitDto {
                network_id: net,
                target_height: h,
                role_id: role,
                solver_pkh: g("solver_pkh"),
                commitment_hash: cg("commitment_hash"),
                worker: String::new(),
            };
            store
                .add_precommit(pre.validate(net).expect("real precommit valid"))
                .expect("add precommit");
            let dto = RoleRevealDto {
                network_id: net,
                target_height: h,
                role_id: role,
                lane_id: claim["lane_id"].as_u64().unwrap() as u8,
                solver_pkh: g("solver_pkh"),
                secret: cg("secret"),
                nonce: cg("nonce"),
                commitment_hash: cg("commitment_hash"),
                claim_digest: cg("claim_digest"),
                assignment_public_key: g("assignment_public_key"),
                assignment_proof: g("assignment_proof"),
                ticket_proof: g("ticket_proof"),
                puzzle_solution: g("puzzle_solution"),
            };
            let v = dto.validate(net).expect("real bundle passes the Phase 1 binding");
            store.add_reveal(v).expect("add reveal");
        };

        let (ca, cb, vf, sp) = (load("compute_A"), load("compute_B"), load("verify_1"), load("support_1"));
        let h = ca["target_height"].as_u64().unwrap();
        let store = RoleProtocolStore::new();
        for x in [&ca, &cb, &vf, &sp] {
            feed(&store, x);
        }
        // The live flow always has the NEXT round's precommits in flight; the compliant
        // builder requires precommit_root_for(h+1) (one precommit per role). Add them.
        let compute_win = if score_of(&cb) >= score_of(&ca) { &cb } else { &ca };
        for (role, b) in [
            (ROLE_COMPUTE_CONTRIBUTOR, compute_win),
            (ROLE_VERIFY_CONTRIBUTOR, &vf),
            (ROLE_SUPPORT_CONTRIBUTOR, &sp),
        ] {
            let pre = RolePrecommitDto {
                network_id: net,
                target_height: h + 1,
                role_id: role,
                solver_pkh: b["solver_pkh"].as_str().unwrap().to_string(),
                commitment_hash: b["claim"]["commitment_hash"].as_str().unwrap().to_string(),
                worker: String::new(),
            };
            store
                .add_precommit(pre.validate(net).expect("next-round precommit valid"))
                .expect("add next-round precommit");
        }

        // ---- COMPLIANT PATH: exactly what the swapped stratum.rs call-site now invokes ----
        let ext = build_collected_bundle_ext(&store, net, h, None, &[0u8; 32])
            .expect("compliant multi-role ext built from real bundles");
        let (cpk, vpk, spk) = (
            ext.role_reward.compute_contributor_pkh,
            ext.role_reward.verify_contributor_pkh,
            ext.role_reward.support_contributor_pkh,
        );
        // three DISTINCT contributor participants, each its own real worker.
        assert_eq!(
            [cpk, vpk, spk].iter().collect::<std::collections::BTreeSet<_>>().len(),
            3,
            "three distinct contributor participants"
        );
        assert_eq!(cpk, pkh_of(compute_win), "COMPUTE attributed to the higher-VRF real competitor (best_for_role)");
        assert_eq!(vpk, pkh_of(&vf), "VERIFY attributed to its real worker");
        assert_eq!(spk, pkh_of(&sp), "SUPPORT attributed to its real worker");
        // the ext carries each participant's OWN ticket + puzzle proofs (compliant, not synthesized).
        assert!(ext.role_ticket_proofs.is_some(), "per-participant ticket proofs attached");
        assert!(ext.role_puzzle_proofs.is_some(), "per-participant puzzle proofs attached");
        assert!(ext.precommit_root.is_some(), "next-round precommit root committed");

        // ---- FALLBACK PARITY (automatic fallback to today's behavior) ----
        // (1) empty store -> None (no collected bundles).
        assert!(
            build_collected_bundle_ext(&RoleProtocolStore::new(), net, h, None, &[0u8; 32]).is_none(),
            "fallback: empty store yields no ext"
        );
        // (2) mainnet (network_id == 0) -> None: mainnet stays byte-identical / untouched.
        assert!(
            build_collected_bundle_ext(&store, 0, h, None, &[0u8; 32]).is_none(),
            "fallback: mainnet (net 0) yields no ext -- mainnet untouched"
        );
        // (3) role protocol disabled -> None.
        std::env::remove_var("IRIUM_POAWX_ROLE_PROTOCOL_ENABLED");
        assert!(
            build_collected_bundle_ext(&store, net, h, None, &[0u8; 32]).is_none(),
            "fallback: role protocol disabled yields no ext"
        );
        std::env::set_var("IRIUM_POAWX_ROLE_PROTOCOL_ENABLED", "1");

        println!(
            "[callsite] build_collected_bundle_ext -> compliant ext: COMPUTE={} VERIFY={} SUPPORT={} (3 distinct); fallbacks (empty/net0/disabled) all None",
            hex::encode(cpk), hex::encode(vpk), hex::encode(spk)
        );

        std::env::remove_var("IRIUM_POAWX_ROLE_PROTOCOL_ENABLED");
        std::env::remove_var("IRIUM_POAWX_CONTRIBUTOR_ROLE_BINDING_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_NETWORK");
    }

    #[test]
    fn phase4_mirror_ticket_puzzle_deserialize_roundtrip() {
        // Phase 4 M2: the new mirror deserializers are exact inverses of serialize.
        let t = TicketProofMirror::new(
            2, 10, [0x33u8; 32], ROLE_COMPUTE_CONTRIBUTOR, [0x44u8; 20], 10, 100_010,
            [0x02u8; 33], [0x55u8; 32], 0,
        );
        assert_eq!(TicketProofMirror::deserialize(&t.serialize()).unwrap(), t);
        assert!(TicketProofMirror::deserialize(&t.serialize()[..175]).is_err());
        let pz = PuzzleSolutionMirror { mode: 3, nonce: 12_345, proof_digest: [0x66u8; 32] };
        assert_eq!(PuzzleSolutionMirror::deserialize(&pz.serialize()).unwrap(), pz);
    }

    #[test]
    fn phase3_m2_distinct_attribution_and_best_for_role() {
        // Distinct participants each win their role; when two compete for one role, the
        // higher genuine self-VRF score wins (best_for_role). Attribution routes to the
        // winning participant. The pool admits all valid submissions and picks the best.
        let net = 2u8;
        let h = 40u64;
        let store = RoleProtocolStore::new();
        let mk = |role: u8, apk: [u8; 33], vrf0: u8| -> [u8; 20] {
            let pkh = {
                let rip = ripemd::Ripemd160::digest(Sha256::digest(apk));
                let mut o = [0u8; 20];
                o.copy_from_slice(&rip);
                o
            };
            let secret = [role ^ vrf0; 32];
            let nonce = [role.wrapping_add(vrf0); 32];
            let commitment = role_precommit_commitment(&secret, &nonce);
            let mut vrf_output = [0u8; 32];
            vrf_output[0] = vrf0;
            let proof = AssignmentProofV2Mirror {
                version: 2,
                network_id: net,
                target_height: h,
                role_id: role,
                solver_pkh: pkh,
                assignment_public_key: apk,
                ticket_digest: [0u8; 32],
                seed: [0u8; 32],
                vrf_output,
                vrf_proof: [0u8; VRF_PROOF_WIRE],
                digest: [0u8; 32],
            };
            store
                .add_precommit(ValidatedPrecommit {
                    network_id: net,
                    target_height: h,
                    role_id: role,
                    solver_pkh: pkh,
                    commitment_hash: commitment,
                })
                .unwrap();
            let dto = RoleRevealDto {
                network_id: net,
                target_height: h,
                role_id: role,
                lane_id: 0,
                solver_pkh: hex::encode(pkh),
                secret: hex::encode(secret),
                nonce: hex::encode(nonce),
                commitment_hash: hex::encode(commitment),
                claim_digest: hex::encode([0u8; 32]),
                assignment_public_key: hex::encode(apk),
                assignment_proof: hex::encode(proof.serialize()),
                ticket_proof: hex::encode([1u8; 4]),
                puzzle_solution: hex::encode([2u8; 4]),
            };
            store.add_reveal(dto.validate(net).unwrap()).unwrap();
            pkh
        };
        // COMPUTE: two competitors -- higher VRF score (0xff) must beat lower (0x10).
        let pkh_hi = mk(ROLE_COMPUTE_CONTRIBUTOR, [0x02u8; 33], 0xff);
        let pkh_lo = mk(ROLE_COMPUTE_CONTRIBUTOR, [0x03u8; 33], 0x10);
        let pkh_v = mk(ROLE_VERIFY_CONTRIBUTOR, [0x04u8; 33], 0x80);
        let pkh_s = mk(ROLE_SUPPORT_CONTRIBUTOR, [0x05u8; 33], 0x80);
        assert_ne!(pkh_hi, pkh_lo);
        let w = store.best_bundled_reveals(h).expect("winners");
        assert_eq!(w[0].claim.solver_pkh, pkh_hi, "COMPUTE winner = higher self-VRF score");
        assert_eq!(w[1].claim.solver_pkh, pkh_v, "VERIFY -> its distinct participant");
        assert_eq!(w[2].claim.solver_pkh, pkh_s, "SUPPORT -> its distinct participant");
        for wr in &w {
            assert!(wr.assignment_public_key.is_some(), "winner carries payout-bound proof");
        }
    }

    #[test]
    fn phase3_reveal_bundle_enforces_payout_binding() {
        // A payout-bound bundle whose assignment_public_key hashes to solver_pkh is
        // accepted and carries the proofs; one that does not is rejected (the Phase 1
        // structural binding, enforced at pool ingest); a legacy claim-only reveal still works.
        let net = 2u8;
        let secret = [0x11u8; 32];
        let nonce = [0x22u8; 32];
        let commitment = role_precommit_commitment(&secret, &nonce);
        let apk = [0x02u8; 33];
        let pkh = {
            let rip = ripemd::Ripemd160::digest(Sha256::digest(apk));
            let mut o = [0u8; 20];
            o.copy_from_slice(&rip);
            o
        };
        let mk = |apk_hex: &str, solver: [u8; 20]| RoleRevealDto {
            network_id: net,
            target_height: 10,
            role_id: ROLE_COMPUTE_CONTRIBUTOR,
            lane_id: 0,
            solver_pkh: hex::encode(solver),
            secret: hex::encode(secret),
            nonce: hex::encode(nonce),
            commitment_hash: hex::encode(commitment),
            claim_digest: hex::encode([0u8; 32]),
            assignment_public_key: apk_hex.to_string(),
            assignment_proof: hex::encode([1u8; 8]),
            ticket_proof: hex::encode([2u8; 8]),
            puzzle_solution: hex::encode([3u8; 8]),
        };
        // matching binding -> accepted, carries the proofs
        let v = mk(&hex::encode(apk), pkh).validate(net).expect("matching bundle accepted");
        assert_eq!(v.assignment_public_key, Some(apk));
        assert_eq!(v.assignment_proof.len(), 8);
        assert_eq!(v.ticket_proof.len(), 8);
        assert_eq!(v.puzzle_solution.len(), 8);
        // mismatched solver (apk does not hash to it) -> rejected with the Phase 1 binding error
        let e = mk(&hex::encode(apk), [0x99u8; 20])
            .validate(net)
            .expect_err("mismatched binding must be rejected");
        assert!(e.contains("Phase 1 binding"), "got: {e}");
        // legacy claim-only (empty bundle) still accepted, no proofs carried
        let mut legacy = mk("", pkh);
        legacy.assignment_proof = String::new();
        legacy.ticket_proof = String::new();
        legacy.puzzle_solution = String::new();
        let lv = legacy.validate(net).expect("legacy claim-only accepted");
        assert!(lv.assignment_public_key.is_none());
    }

    #[test]
    fn phase20_role_protocol_payloads_and_store() {
        let net = 1u8;
        let prev = [0x77u8; 32];
        let roles = [
            ROLE_COMPUTE_CONTRIBUTOR,
            ROLE_VERIFY_CONTRIBUTOR,
            ROLE_SUPPORT_CONTRIBUTOR,
        ];
        let solvers = [[0xA1u8; 20], [0xA2u8; 20], [0xA3u8; 20]];
        let sn = |role: u8| ([role; 32], [role.wrapping_add(100); 32]);

        // --- payloads ---
        let (s, n) = sn(ROLE_COMPUTE_CONTRIBUTOR);
        let pc = mk_precommit_dto(net, 2, ROLE_COMPUTE_CONTRIBUTOR, solvers[0], s, n);
        // precommit hides secret/nonce (DTO has no such fields).
        let pc_json = serde_json::to_string(&pc).unwrap();
        assert!(
            !pc_json.contains(&hex::encode(s)) && !pc_json.contains(&hex::encode(n)),
            "precommit hides secret/nonce"
        );
        // JSON round-trip.
        let pc2: RolePrecommitDto = serde_json::from_str(&pc_json).unwrap();
        assert_eq!(pc2.validate(net).unwrap(), pc.validate(net).unwrap());
        let rv = mk_reveal_dto(net, 2, &prev, ROLE_COMPUTE_CONTRIBUTOR, solvers[0], s, n);
        let rv2: RoleRevealDto =
            serde_json::from_str(&serde_json::to_string(&rv).unwrap()).unwrap();
        // reveal reconstructs commitment_hash from secret/nonce (validate succeeds).
        let vr = rv2.validate(net).unwrap();
        assert_eq!(
            vr.claim.commitment_hash,
            Some(role_precommit_commitment(&s, &n))
        );
        // mutation: a reveal whose commitment doesn't match secret/nonce rejects.
        let mut bad = rv.clone();
        bad.commitment_hash = hex::encode([0xEEu8; 32]);
        assert!(bad.validate(net).is_err(), "mutated commitment rejects");
        let mut bad2 = rv.clone();
        bad2.secret = hex::encode([0x00u8; 32]);
        assert!(bad2.validate(net).is_err(), "mutated secret rejects");
        // wrong network / role rejects.
        assert!(pc.validate(2).is_err(), "wrong network");
        let mut badrole = pc.clone();
        badrole.role_id = 9;
        assert!(badrole.validate(net).is_err(), "bad role");
        // wrong solver hex rejects.
        let mut badsolver = pc.clone();
        badsolver.solver_pkh = "zz".to_string();
        assert!(badsolver.validate(net).is_err(), "bad solver");

        // --- store ---
        let store = RoleProtocolStore::new();
        // accept all 3 roles for height 2 + 3 for height 3 (next).
        for h in [2u64, 3u64] {
            for (i, &role) in roles.iter().enumerate() {
                let (s, n) = sn(role);
                store
                    .add_precommit(
                        mk_precommit_dto(net, h, role, solvers[i], s, n)
                            .validate(net)
                            .unwrap(),
                    )
                    .unwrap();
            }
        }
        // duplicate same-commitment is idempotent; different-commitment rejects.
        let (s0, n0) = sn(ROLE_COMPUTE_CONTRIBUTOR);
        store
            .add_precommit(
                mk_precommit_dto(net, 2, ROLE_COMPUTE_CONTRIBUTOR, solvers[0], s0, n0)
                    .validate(net)
                    .unwrap(),
            )
            .unwrap();
        let mut diff = mk_precommit_dto(net, 2, ROLE_COMPUTE_CONTRIBUTOR, solvers[0], s0, n0);
        diff.commitment_hash = hex::encode([0x01u8; 32]);
        assert!(
            store.add_precommit(diff.validate(net).unwrap()).is_err(),
            "dup different commitment rejects"
        );
        // reveal without precommit rejects (height 2, solver not precommitted).
        let orphan = mk_reveal_dto(
            net,
            2,
            &prev,
            ROLE_COMPUTE_CONTRIBUTOR,
            [0xBBu8; 20],
            s0,
            n0,
        );
        assert!(
            store.add_reveal(orphan.validate(net).unwrap()).is_err(),
            "reveal w/o precommit rejects"
        );
        // valid reveals for height 2 accepted.
        for (i, &role) in roles.iter().enumerate() {
            let (s, n) = sn(role);
            store
                .add_reveal(
                    mk_reveal_dto(net, 2, &prev, role, solvers[i], s, n)
                        .validate(net)
                        .unwrap(),
                )
                .unwrap();
        }
        // selection: one per role; precommit_root deterministic.
        let sel = store.select_reveals(2).expect("3 reveals");
        assert_eq!(sel[0].claim.role_id, ROLE_COMPUTE_CONTRIBUTOR);
        assert_eq!(sel[2].claim.role_id, ROLE_SUPPORT_CONTRIBUTOR);
        let root2 = store.precommit_root_for(2).expect("root2");
        assert_eq!(root2, store.precommit_root_for(2).unwrap(), "deterministic");
        assert!(
            store.precommit_root_for(3).is_some(),
            "next-height root present"
        );
        // prune drops stale (window 64): targeting tip far ahead removes height 2/3.
        store.prune(2 + ROLE_PROTOCOL_HEIGHT_WINDOW + 5);
        assert!(store.precommit_root_for(2).is_none(), "pruned stale");
    }

    #[test]
    fn phase20_role_protocol_collected_production_and_node_parity() {
        let _g = p20_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_ROLE_PROTOCOL_ENABLED", "1");
        std::env::set_var("IRIUM_POAWX_MULTI_ROLE_REWARD_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_FAIRNESS_MATRIX_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_HIDDEN_PRECOMMIT_ACTIVATION_HEIGHT", "1");
        let net = 1u8;
        let prev = [0x55u8; 32];
        let roles = [
            ROLE_COMPUTE_CONTRIBUTOR,
            ROLE_VERIFY_CONTRIBUTOR,
            ROLE_SUPPORT_CONTRIBUTOR,
        ];
        let solvers = [[0xA1u8; 20], [0xA2u8; 20], [0xA3u8; 20]];
        let sn = |role: u8| ([role; 32], [role.wrapping_add(50); 32]);
        let store = RoleProtocolStore::new();
        // precommits+reveals for height 2; precommits for height 3 (next).
        for (i, &role) in roles.iter().enumerate() {
            let (s, n) = sn(role);
            store
                .add_precommit(
                    mk_precommit_dto(net, 2, role, solvers[i], s, n)
                        .validate(net)
                        .unwrap(),
                )
                .unwrap();
            store
                .add_precommit(
                    mk_precommit_dto(net, 3, role, solvers[i], s, n)
                        .validate(net)
                        .unwrap(),
                )
                .unwrap();
            store
                .add_reveal(
                    mk_reveal_dto(net, 2, &prev, role, solvers[i], s, n)
                        .validate(net)
                        .unwrap(),
                )
                .unwrap();
        }
        // COLLECTED production ext for height 2.
        let ext = build_collected_phase20_ext(&store, net, 2, None, &[0x11u8; 20], &[0x33u8; 32])
            .expect("collected ext");
        assert_eq!(
            ext.precommit_root,
            store.precommit_root_for(3),
            "commits next-height root"
        );
        assert_eq!(ext.role_reward.compute_contributor_pkh, solvers[0]);

        // Node parity: each revealed claim validates against fairness + reconstructs
        // a leaf; the sorted root equals the PARENT's committed root (root_for(2)).
        let node_ext =
            irium_node_rs::poawx::Phase20ReceiptExt::deserialize(&ext.serialize()).unwrap();
        let mut leaves = Vec::new();
        for c in [
            &node_ext.compute_claim,
            &node_ext.verify_claim,
            &node_ext.support_claim,
        ] {
            irium_node_rs::poawx::validate_role_claim(c, net, 2, &prev, 0).expect("claim valid");
            leaves.push(
                irium_node_rs::poawx::role_precommit_leaf_for_claim(c, net, 2).expect("leaf"),
            );
        }
        assert_eq!(
            irium_node_rs::poawx::role_precommit_root(&leaves),
            store.precommit_root_for(2).unwrap(),
            "reveal leaves root == parent committed root"
        );

        // missing role reveal => fail closed (None) after activation.
        let store2 = RoleProtocolStore::new();
        for (i, &role) in roles.iter().enumerate().take(2) {
            let (s, n) = sn(role);
            store2
                .add_precommit(
                    mk_precommit_dto(net, 2, role, solvers[i], s, n)
                        .validate(net)
                        .unwrap(),
                )
                .unwrap();
            store2
                .add_reveal(
                    mk_reveal_dto(net, 2, &prev, role, solvers[i], s, n)
                        .validate(net)
                        .unwrap(),
                )
                .unwrap();
        }
        assert!(
            build_collected_phase20_ext(&store2, net, 2, None, &[0x11u8; 20], &[0x33u8; 32])
                .is_none(),
            "missing role => fail closed"
        );

        // off-path: role protocol disabled => None (falls back to synthetic upstream).
        std::env::remove_var("IRIUM_POAWX_ROLE_PROTOCOL_ENABLED");
        assert!(
            build_collected_phase20_ext(&store, net, 2, None, &[0x11u8; 20], &[0x33u8; 32])
                .is_none(),
            "disabled => None"
        );
        // mainnet hard-off.
        assert!(
            build_collected_phase20_ext(&store, 0, 2, None, &[0x11u8; 20], &[0x33u8; 32]).is_none(),
            "mainnet hard-off"
        );
        assert!(!role_protocol_enabled(), "gate off");

        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_MULTI_ROLE_REWARD_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_FAIRNESS_MATRIX_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_HIDDEN_PRECOMMIT_ACTIVATION_HEIGHT");
    }

    // ── Step 6C: role gossip envelopes + engine + in-memory relay ─────────────

    fn enable_role_gossip_env() {
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_ROLE_PROTOCOL_ENABLED", "1");
        std::env::set_var("IRIUM_POAWX_ROLE_GOSSIP_ENABLED", "1");
        std::env::set_var("IRIUM_POAWX_MULTI_ROLE_REWARD_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_FAIRNESS_MATRIX_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_HIDDEN_PRECOMMIT_ACTIVATION_HEIGHT", "1");
    }
    fn clear_role_gossip_env() {
        std::env::remove_var("IRIUM_NETWORK");
        std::env::remove_var("IRIUM_POAWX_ROLE_PROTOCOL_ENABLED");
        std::env::remove_var("IRIUM_POAWX_ROLE_GOSSIP_ENABLED");
        std::env::remove_var("IRIUM_POAWX_SYNTHETIC_ROLE_CLAIMS");
        std::env::remove_var("IRIUM_POAWX_MULTI_ROLE_REWARD_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_FAIRNESS_MATRIX_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_HIDDEN_PRECOMMIT_ACTIVATION_HEIGHT");
    }

    // Tests 1–5: payload encoding (no env needed — pure encode/decode/validate).
    #[test]
    fn phase20_role_gossip_envelope_roundtrip_and_versioning() {
        let net = 1u8;
        let prev = [0x33u8; 32];
        let (s, n) = ([0x11u8; 32], [0x22u8; 32]);
        let solver = [0xC1u8; 20];

        // (1) precommit envelope wire round-trip.
        let pc = mk_precommit_dto(net, 2, ROLE_COMPUTE_CONTRIBUTOR, solver, s, n);
        let pc_bytes = RolePrecommitGossip::new(pc.clone()).encode();
        let pc_dec = RolePrecommitGossip::decode(&pc_bytes).expect("precommit decode");
        assert_eq!(pc_dec.gossip_version, ROLE_GOSSIP_VERSION);
        assert_eq!(
            pc_dec.precommit.validate(net).unwrap(),
            pc.validate(net).unwrap()
        );
        // (3) precommit envelope never carries secret/nonce.
        let pc_str = String::from_utf8(pc_bytes.clone()).unwrap();
        assert!(
            !pc_str.contains(&hex::encode(s)) && !pc_str.contains(&hex::encode(n)),
            "precommit gossip hides secret/nonce"
        );

        // (2) reveal envelope wire round-trip.
        let rv = mk_reveal_dto(net, 2, &prev, ROLE_COMPUTE_CONTRIBUTOR, solver, s, n);
        let rv_bytes = RoleRevealGossip::new(rv.clone()).encode();
        let rv_dec = RoleRevealGossip::decode(&rv_bytes).expect("reveal decode");
        // (4) reveal reconstructs the commitment via validate().
        let vr = rv_dec.reveal.validate(net).unwrap();
        assert_eq!(
            vr.claim.commitment_hash,
            Some(role_precommit_commitment(&s, &n))
        );

        // (5) mutation changes the dedupe digest.
        let d0 = reveal_gossip_digest(&vr);
        let mut rv_mut = rv.clone();
        rv_mut.nonce = hex::encode([0x99u8; 32]);
        rv_mut.commitment_hash = hex::encode(role_precommit_commitment(&s, &[0x99u8; 32]));
        // recompute claim_digest so validate passes but content differs
        let lane = assign_lane_id(net, 2, &prev, ROLE_COMPUTE_CONTRIBUTOR, 0);
        rv_mut.claim_digest = hex::encode(role_claim_digest(
            net,
            2,
            &prev,
            ROLE_COMPUTE_CONTRIBUTOR,
            lane,
            &solver,
            &[0x99u8; 32],
            &s,
        ));
        let vr_mut = rv_mut.validate(net).unwrap();
        assert_ne!(d0, reveal_gossip_digest(&vr_mut), "mutation changes digest");

        // versioning + size + malformed all reject.
        let mut badver = RolePrecommitGossip::new(pc.clone());
        badver.gossip_version = 2;
        assert!(
            RolePrecommitGossip::decode(&badver.encode()).is_err(),
            "bad version rejects"
        );
        assert!(
            RolePrecommitGossip::decode(&vec![b'{'; ROLE_GOSSIP_MAX_BYTES + 1]).is_err(),
            "oversize rejects"
        );
        assert!(
            RolePrecommitGossip::decode(b"not json").is_err()
                && RoleRevealGossip::decode(b"not json").is_err(),
            "malformed rejects"
        );
    }

    // Tests 6–12: validation / window / dedupe (engine ingest; env-gated).
    #[test]
    fn phase20_role_gossip_validation_window_dedupe() {
        let _g = p20_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        enable_role_gossip_env();
        let net = 1u8;
        let prev = [0x44u8; 32];
        let solver = [0xD1u8; 20];
        let (s, n) = ([0x31u8; 32], [0x32u8; 32]);
        let store = RoleProtocolStore::new();
        let eng = RoleGossipEngine::new();

        let pc_bytes = |h: u64, sv: [u8; 20]| {
            RolePrecommitGossip::new(mk_precommit_dto(net, h, ROLE_COMPUTE_CONTRIBUTOR, sv, s, n))
                .encode()
        };

        // (12) valid precommit within window accepted.
        let tip = 1u64;
        assert_eq!(
            eng.ingest_precommit(&store, &pc_bytes(2, solver), net, tip),
            GossipOutcome::AcceptedNew
        );
        // (10) duplicate dedupes (stored once).
        assert_eq!(
            eng.ingest_precommit(&store, &pc_bytes(2, solver), net, tip),
            GossipOutcome::Duplicate
        );
        assert!(store
            .canonical_precommit(2, ROLE_COMPUTE_CONTRIBUTOR)
            .is_some());

        // (6) wrong network rejects (dto net=1, expected_network=2).
        assert!(matches!(
            eng.ingest_precommit(&store, &pc_bytes(2, [0xD2u8; 20]), 2, tip),
            GossipOutcome::Rejected(_)
        ));
        // (7) stale height (< tip) rejects.
        assert!(matches!(
            eng.ingest_precommit(&store, &pc_bytes(0, [0xD3u8; 20]), net, 5),
            GossipOutcome::Rejected(_)
        ));
        // (8) far-future (> tip + window) rejects.
        let far = tip + ROLE_PROTOCOL_HEIGHT_WINDOW + 1;
        assert!(matches!(
            eng.ingest_precommit(&store, &pc_bytes(far, [0xD4u8; 20]), net, tip),
            GossipOutcome::Rejected(_)
        ));
        // (9) malformed rejects.
        assert!(matches!(
            eng.ingest_precommit(&store, b"garbage", net, tip),
            GossipOutcome::Rejected(_)
        ));

        // (11) reveal WITHOUT a matching precommit is rejected gracefully (no crash).
        let orphan = RoleRevealGossip::new(mk_reveal_dto(
            net,
            2,
            &prev,
            ROLE_VERIFY_CONTRIBUTOR,
            [0xEEu8; 20],
            s,
            n,
        ))
        .encode();
        assert!(matches!(
            eng.ingest_reveal(&store, &orphan, net, tip),
            GossipOutcome::Rejected(_)
        ));
        assert!(
            store.select_reveals(2).is_none(),
            "orphan reveal not stored"
        );

        // (12) reveal WITH a matching precommit accepted.
        let rv = RoleRevealGossip::new(mk_reveal_dto(
            net,
            2,
            &prev,
            ROLE_COMPUTE_CONTRIBUTOR,
            solver,
            s,
            n,
        ))
        .encode();
        assert_eq!(
            eng.ingest_reveal(&store, &rv, net, tip),
            GossipOutcome::AcceptedNew
        );

        clear_role_gossip_env();
    }

    // Tests 13–17: in-memory relay (validate→store-once→rebroadcast-only-valid).
    #[test]
    fn phase20_role_gossip_inmemory_relay() {
        let _g = p20_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        enable_role_gossip_env();
        let net = 1u8;
        let prev = [0x66u8; 32];
        let solver = [0xF1u8; 20];
        let (s, n) = ([0x41u8; 32], [0x42u8; 32]);
        let tip = 1u64;

        struct Node {
            store: RoleProtocolStore,
            eng: RoleGossipEngine,
        }
        let nodes: Vec<Node> = (0..3)
            .map(|_| Node {
                store: RoleProtocolStore::new(),
                eng: RoleGossipEngine::new(),
            })
            .collect();

        let pc_bytes = RolePrecommitGossip::new(mk_precommit_dto(
            net,
            2,
            ROLE_COMPUTE_CONTRIBUTOR,
            solver,
            s,
            n,
        ))
        .encode();

        // Flood from node 0. AcceptedNew triggers a rebroadcast to peers; the
        // seen-set dedup makes the flood converge (no infinite loop).
        let mut frontier = vec![0usize];
        let mut relays = 0;
        while let Some(src) = frontier.pop() {
            let out = nodes[src]
                .eng
                .ingest_precommit(&nodes[src].store, &pc_bytes, net, tip);
            if out.should_rebroadcast() {
                relays += 1;
                for (i, _) in nodes.iter().enumerate() {
                    if i != src {
                        frontier.push(i);
                    }
                }
            }
        }
        // (13/14) every node stored exactly once (canonical present), flood converged.
        for nd in &nodes {
            assert!(nd
                .store
                .canonical_precommit(2, ROLE_COMPUTE_CONTRIBUTOR)
                .is_some());
            // re-ingest on the same node is a Duplicate (stored once).
            assert_eq!(
                nd.eng.ingest_precommit(&nd.store, &pc_bytes, net, tip),
                GossipOutcome::Duplicate
            );
        }
        assert!(relays >= 3, "valid precommit relayed across nodes");

        // (15) invalid precommit: not stored, not rebroadcast.
        let nd = &nodes[0];
        let before = nd.store.canonical_precommit(2, ROLE_VERIFY_CONTRIBUTOR);
        let out = nd.eng.ingest_precommit(&nd.store, b"garbage", net, tip);
        assert!(matches!(out, GossipOutcome::Rejected(_)) && !out.should_rebroadcast());
        assert_eq!(
            nd.store.canonical_precommit(2, ROLE_VERIFY_CONTRIBUTOR),
            before
        );

        // (16) valid reveal stores once (after its precommit).
        let rv_bytes = RoleRevealGossip::new(mk_reveal_dto(
            net,
            2,
            &prev,
            ROLE_COMPUTE_CONTRIBUTOR,
            solver,
            s,
            n,
        ))
        .encode();
        assert_eq!(
            nd.eng.ingest_reveal(&nd.store, &rv_bytes, net, tip),
            GossipOutcome::AcceptedNew
        );
        assert_eq!(
            nd.eng.ingest_reveal(&nd.store, &rv_bytes, net, tip),
            GossipOutcome::Duplicate
        );

        // (17) invalid reveal (no precommit on a fresh node): not stored/rebroadcast.
        let fresh = Node {
            store: RoleProtocolStore::new(),
            eng: RoleGossipEngine::new(),
        };
        let out = fresh.eng.ingest_reveal(&fresh.store, &rv_bytes, net, tip);
        assert!(matches!(out, GossipOutcome::Rejected(_)) && !out.should_rebroadcast());
        assert!(fresh.store.select_reveals(2).is_none());

        clear_role_gossip_env();
    }

    // Tests 20–26: production parity from gossip-collected data + fallback + hard-off.
    #[test]
    fn phase20_role_gossip_production_parity() {
        let _g = p20_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        enable_role_gossip_env();
        let net = 1u8;
        let prev = [0x55u8; 32];
        let primary = [0x09u8; 20];
        let roles = [
            ROLE_COMPUTE_CONTRIBUTOR,
            ROLE_VERIFY_CONTRIBUTOR,
            ROLE_SUPPORT_CONTRIBUTOR,
        ];
        let solvers = [[0xA1u8; 20], [0xA2u8; 20], [0xA3u8; 20]];
        let sn = |role: u8| ([role; 32], [role.wrapping_add(70); 32]);
        let store = RoleProtocolStore::new();
        let eng = RoleGossipEngine::new();
        let tip = 1u64;

        // Ingest precommits for height 2 + 3 and reveals for height 2, all via gossip.
        for (i, &role) in roles.iter().enumerate() {
            let (s, n) = sn(role);
            for h in [2u64, 3u64] {
                let pc = RolePrecommitGossip::new(mk_precommit_dto(net, h, role, solvers[i], s, n))
                    .encode();
                assert_eq!(
                    eng.ingest_precommit(&store, &pc, net, tip),
                    GossipOutcome::AcceptedNew
                );
            }
            let rv = RoleRevealGossip::new(mk_reveal_dto(net, 2, &prev, role, solvers[i], s, n))
                .encode();
            assert_eq!(
                eng.ingest_reveal(&store, &rv, net, tip),
                GossipOutcome::AcceptedNew
            );
        }

        // (20) collected gossip precommits build the parent precommit_root.
        let root2 = store.precommit_root_for(2).expect("root2 from gossip");
        // (21) collected gossip reveals build the child ext (official fee-0 / 23).
        let ext = build_collected_phase20_ext(&store, net, 2, None, &[0x11u8; 20], &[0x33u8; 32])
            .expect("collected ext");
        assert_eq!(ext.fee_bps, 0, "official fee-0");
        assert_eq!(ext.precommit_root, store.precommit_root_for(3));
        // (22) node validator accepts the gossip-built fixture.
        let node_ext =
            irium_node_rs::poawx::Phase20ReceiptExt::deserialize(&ext.serialize()).unwrap();
        let mut leaves = Vec::new();
        for c in [
            &node_ext.compute_claim,
            &node_ext.verify_claim,
            &node_ext.support_claim,
        ] {
            irium_node_rs::poawx::validate_role_claim(c, net, 2, &prev, 0).expect("claim valid");
            leaves.push(
                irium_node_rs::poawx::role_precommit_leaf_for_claim(c, net, 2).expect("leaf"),
            );
        }
        assert_eq!(
            irium_node_rs::poawx::role_precommit_root(&leaves),
            root2,
            "gossip reveal leaves root == parent committed root"
        );

        // (24) third-party fee still works from gossip-collected data.
        let fee_pkh = [0x7Fu8; 20];
        let ext_fee = build_collected_phase20_ext(
            &store,
            net,
            2,
            Some((200, fee_pkh)),
            &[0x11u8; 20],
            &[0x33u8; 32],
        )
        .expect("collected fee ext");
        assert_eq!(ext_fee.fee_bps, 200);
        assert_eq!(ext_fee.fee_pkh, fee_pkh);

        // (25) synthetic fallback works ONLY when explicitly enabled.
        assert!(
            build_synthetic_phase20_ext(net, 2, &prev, &primary, &[], None).is_none(),
            "synthetic disabled by default"
        );
        std::env::set_var("IRIUM_POAWX_SYNTHETIC_ROLE_CLAIMS", "1");
        assert!(
            build_synthetic_phase20_ext(net, 2, &prev, &primary, &[], None).is_some(),
            "synthetic enabled => Some"
        );
        std::env::remove_var("IRIUM_POAWX_SYNTHETIC_ROLE_CLAIMS");

        // (26) mainnet hard-off: build returns None and ingest rejects.
        assert!(
            build_collected_phase20_ext(&store, 0, 2, None, &[0x11u8; 20], &[0x33u8; 32]).is_none(),
            "mainnet build None"
        );
        let pc0 = RolePrecommitGossip::new(mk_precommit_dto(
            net,
            2,
            ROLE_COMPUTE_CONTRIBUTOR,
            solvers[0],
            sn(ROLE_COMPUTE_CONTRIBUTOR).0,
            sn(ROLE_COMPUTE_CONTRIBUTOR).1,
        ))
        .encode();
        assert!(matches!(
            eng.ingest_precommit(&store, &pc0, 0, tip),
            GossipOutcome::Rejected(_)
        ));

        clear_role_gossip_env();
    }

    // ── Step 6D: pool↔node loopback RPC bridge ────────────────────────────────

    /// Minimal one-shot HTTP/1.1 mock: serves `body` to the first connection and
    /// returns the raw request bytes (so a POST test can assert the body).
    async fn mock_http_serve_once(body: String) -> (String, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = vec![0u8; 8192];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = buf[..n].to_vec();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.flush().await;
                req
            } else {
                Vec::new()
            }
        });
        (url, handle)
    }

    // (20,21,22,23,24) pool fetches node-stored precommits/reveals over real HTTP,
    // builds the parent root + child ext, and the node validator accepts it.
    #[test]
    fn phase20_role_gossip_bridge_fetch_http_and_production_parity() {
        let _g = p20_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        enable_role_gossip_env();
        let net = 1u8;
        let prev = [0x55u8; 32];
        let roles = [
            ROLE_COMPUTE_CONTRIBUTOR,
            ROLE_VERIFY_CONTRIBUTOR,
            ROLE_SUPPORT_CONTRIBUTOR,
        ];
        let solvers = [[0xA1u8; 20], [0xA2u8; 20], [0xA3u8; 20]];
        let sn = |r: u8| ([r; 32], [r.wrapping_add(70); 32]);
        let store = RoleProtocolStore::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            // node-shaped GET response for precommits @ height 2.
            let pcs: Vec<RolePrecommitGossip> = roles
                .iter()
                .enumerate()
                .map(|(i, &role)| {
                    let (s, n) = sn(role);
                    RolePrecommitGossip::new(mk_precommit_dto(net, 2, role, solvers[i], s, n))
                })
                .collect();
            let body =
                serde_json::json!({"precommits": serde_json::to_value(&pcs).unwrap()}).to_string();
            let (url, h) = mock_http_serve_once(body).await;
            let fetched = fetch_node_precommits(&url, "tok", 2).await;
            let _ = h.await;
            assert_eq!(fetched.len(), 3, "fetched precommits over HTTP");
            for dto in &fetched {
                store.add_precommit(dto.validate(net).unwrap()).unwrap();
            }
            // node-shaped GET response for reveals @ height 2.
            let rvs: Vec<RoleRevealGossip> = roles
                .iter()
                .enumerate()
                .map(|(i, &role)| {
                    let (s, n) = sn(role);
                    RoleRevealGossip::new(mk_reveal_dto(net, 2, &prev, role, solvers[i], s, n))
                })
                .collect();
            let body2 =
                serde_json::json!({"reveals": serde_json::to_value(&rvs).unwrap()}).to_string();
            let (url2, h2) = mock_http_serve_once(body2).await;
            let fr = fetch_node_reveals(&url2, "tok", 2).await;
            let _ = h2.await;
            assert_eq!(fr.len(), 3, "fetched reveals over HTTP");
            for dto in &fr {
                store.add_reveal(dto.validate(net).unwrap()).unwrap();
            }
            // next-height precommits (committed by the child ext's precommit_root).
            for (i, &role) in roles.iter().enumerate() {
                let (s, n) = sn(role);
                store
                    .add_precommit(
                        mk_precommit_dto(net, 3, role, solvers[i], s, n)
                            .validate(net)
                            .unwrap(),
                    )
                    .unwrap();
            }
            // build collected ext from the fetched data; node validator accepts.
            let ext =
                build_collected_phase20_ext(&store, net, 2, None, &[0x11u8; 20], &[0x33u8; 32])
                    .expect("collected from fetched");
            let node_ext =
                irium_node_rs::poawx::Phase20ReceiptExt::deserialize(&ext.serialize()).unwrap();
            let mut leaves = Vec::new();
            for c in [
                &node_ext.compute_claim,
                &node_ext.verify_claim,
                &node_ext.support_claim,
            ] {
                irium_node_rs::poawx::validate_role_claim(c, net, 2, &prev, 0)
                    .expect("claim valid");
                leaves.push(
                    irium_node_rs::poawx::role_precommit_leaf_for_claim(c, net, 2).expect("leaf"),
                );
            }
            assert_eq!(
                irium_node_rs::poawx::role_precommit_root(&leaves),
                store.precommit_root_for(2).unwrap(),
                "fetched leaves root == parent committed root"
            );
            // (24) third-party fee from bridged data.
            let ext_fee = build_collected_phase20_ext(
                &store,
                net,
                2,
                Some((200, [0x7Fu8; 20])),
                &[0x11u8; 20],
                &[0x33u8; 32],
            )
            .expect("fee ext");
            assert_eq!(ext_fee.fee_bps, 200);
        });
        clear_role_gossip_env();
    }

    // (18) pool local submission reaches the node cache: forward POSTs the envelope.
    #[test]
    fn phase20_role_gossip_bridge_forward_http() {
        let _g = p20_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        enable_role_gossip_env();
        let (s, n) = ([0x11u8; 32], [0x12u8; 32]);
        let solver = [0xC1u8; 20];
        let dto = mk_precommit_dto(1, 2, ROLE_COMPUTE_CONTRIBUTOR, solver, s, n);
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (url, h) = mock_http_serve_once("{\"status\":\"accepted\"}".to_string()).await;
            forward_precommit_to_node(&url, "tok", &dto).await;
            let req = h.await.unwrap();
            let s = String::from_utf8_lossy(&req);
            assert!(s.contains("POST"), "is a POST");
            assert!(s.contains("/poawx/role-gossip/precommit"), "to bridge path");
            assert!(s.contains("gossip_version"), "body carries envelope");
            assert!(s.contains(&hex::encode(solver)), "body carries solver pkh");
        });
        clear_role_gossip_env();
    }

    // (19,25,26) error-safety + base override + mainnet hard-off + synthetic gating.
    #[test]
    fn phase20_role_gossip_bridge_error_safe_and_mainnet_off() {
        let _g = p20_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        // base override.
        std::env::set_var("IRIUM_POAWX_ROLE_GOSSIP_NODE_RPC", "http://override:9");
        assert_eq!(
            node_role_gossip_rpc_base("http://default:1"),
            "http://override:9"
        );
        std::env::remove_var("IRIUM_POAWX_ROLE_GOSSIP_NODE_RPC");
        assert_eq!(
            node_role_gossip_rpc_base("http://default:1"),
            "http://default:1"
        );

        enable_role_gossip_env();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            // (19) unreachable node -> empty, no crash.
            assert!(fetch_node_precommits("http://127.0.0.1:1", "t", 2)
                .await
                .is_empty());
            assert!(fetch_node_reveals("http://127.0.0.1:1", "t", 2)
                .await
                .is_empty());
            let dto = mk_precommit_dto(
                1,
                2,
                ROLE_COMPUTE_CONTRIBUTOR,
                [0xA1u8; 20],
                [1u8; 32],
                [2u8; 32],
            );
            forward_precommit_to_node("http://127.0.0.1:1", "t", &dto).await; // must not panic
                                                                              // (26) mainnet hard-off: network 0 -> bridge no-op.
            let store = RoleProtocolStore::new();
            bridge_fetch_into_store(&store, 0, "http://127.0.0.1:1", "t", 2).await;
            assert!(
                store.precommit_root_for(2).is_none(),
                "mainnet bridge no-op"
            );
        });
        // (25) synthetic fallback gating unchanged.
        assert!(
            build_synthetic_phase20_ext(1, 2, &[0x55u8; 32], &[0x09u8; 20], &[], None).is_none(),
            "synthetic off by default"
        );
        std::env::set_var("IRIUM_POAWX_SYNTHETIC_ROLE_CLAIMS", "1");
        assert!(
            build_synthetic_phase20_ext(1, 2, &[0x55u8; 32], &[0x09u8; 20], &[], None).is_some(),
            "synthetic on when enabled"
        );
        std::env::remove_var("IRIUM_POAWX_SYNTHETIC_ROLE_CLAIMS");
        clear_role_gossip_env();
    }

    // Regression (Step 6E live-E2E finding): fee_terms_from_ext_hex must parse the
    // fee from the FRONT, not the last 22 bytes — otherwise the OPTIONAL Step 6A
    // trailing precommit_root is misread as a spurious fee, adding a bogus 6th
    // coinbase output that consensus rejects ("expected 4 payout outputs, found 5").
    #[test]
    fn phase20_fee_terms_from_ext_hex_ignores_trailing_precommit_root() {
        let claim = PoawxRoleClaimMirror {
            role_id: ROLE_COMPUTE_CONTRIBUTOR,
            lane_id: 0,
            solver_pkh: [9u8; 20],
            nonce: [1u8; 32],
            secret: [2u8; 32],
            claim_digest: [3u8; 32],
            commitment_hash: Some([4u8; 32]),
        };
        let mk =
            |fee_bps: u16, fee_pkh: [u8; 20], root: Option<[u8; 32]>| Phase20ReceiptExtMirror {
                role_reward: RoleRewardMirror {
                    compute_contributor_pkh: [1u8; 20],
                    verify_contributor_pkh: [2u8; 20],
                    support_contributor_pkh: [3u8; 20],
                },
                compute_claim: claim.clone(),
                verify_claim: claim.clone(),
                support_claim: claim.clone(),
                fee_bps,
                fee_pkh,
                precommit_root: root,
                role_ticket_proofs: None,
                role_dominance_weights: None,
                candidate_set: None,
                role_puzzle_proofs: None,
                finality_proof: None,
                committed_admission: None,
                role_assignment_v2: None,
            };
        let fpkh = [0x7Fu8; 20];
        // Pre-6A (no precommit_root): fee parses correctly.
        assert_eq!(
            fee_terms_from_ext_hex(&hex::encode(mk(200, fpkh, None).serialize())),
            Some((200, fpkh))
        );
        // 6A+ (precommit_root present): trailing root must NOT corrupt the fee parse.
        assert_eq!(
            fee_terms_from_ext_hex(&hex::encode(mk(200, fpkh, Some([0xABu8; 32])).serialize())),
            Some((200, fpkh)),
            "trailing precommit_root must not be misread as fee"
        );
        // Official fee-0 WITH precommit_root stays fee-0 (no spurious fee output).
        assert_eq!(
            fee_terms_from_ext_hex(&hex::encode(
                mk(0, [0u8; 20], Some([0xCDu8; 32])).serialize()
            )),
            Some((0, [0u8; 20])),
            "official fee-0 stays fee-0 with precommit_root present"
        );
    }

    // Phase 21B: pool TicketProofMirror is byte-identical to the node TicketProof,
    // and a pool ext carrying tickets deserializes via the node lib + each proof
    // validates against the node validator.
    #[test]
    fn phase21b_pool_ticket_mirror_and_ext_parity() {
        let net = 1u8;
        let prev = [0x55u8; 32];
        let solver = [0xC7u8; 20];
        let apk = [0x02u8; 33];
        let nonce = [0x44u8; 32];
        // (1) ticket proof byte-identity vs node.
        let pm = TicketProofMirror::new(
            net,
            5,
            prev,
            ROLE_VERIFY_CONTRIBUTOR,
            solver,
            2,
            100,
            apk,
            nonce,
            0,
        );
        let nb = irium_node_rs::poawx_ticket::TicketProof::new(
            net,
            5,
            prev,
            irium_node_rs::poawx::ROLE_VERIFY_CONTRIBUTOR,
            solver,
            2,
            100,
            apk,
            nonce,
            0,
        );
        assert_eq!(
            pm.serialize(),
            nb.serialize(),
            "ticket proof mirror byte-identical"
        );
        let parsed =
            irium_node_rs::poawx_ticket::TicketProof::deserialize(&pm.serialize()).unwrap();
        assert!(parsed
            .validate(
                net,
                5,
                &prev,
                irium_node_rs::poawx::ROLE_VERIFY_CONTRIBUTOR,
                &solver,
                0,
                false
            )
            .is_ok());
        // (2) full pool ext WITH ticket proofs -> node deserialize -> proofs present + each validates.
        let prev = [0x55u8; 32];
        let h = 5u64;
        let c = [0xA1u8; 20];
        let v = [0xA2u8; 20];
        let s = [0xA3u8; 20];
        let mk_claim = |role: u8, solver: [u8; 20]| PoawxRoleClaimMirror {
            role_id: role,
            lane_id: assign_lane_id(net, h, &prev, role, 0),
            solver_pkh: solver,
            nonce: [role; 32],
            secret: [role.wrapping_add(9); 32],
            claim_digest: role_claim_digest(
                net,
                h,
                &prev,
                role,
                assign_lane_id(net, h, &prev, role, 0),
                &solver,
                &[role; 32],
                &[role.wrapping_add(9); 32],
            ),
            commitment_hash: None,
        };
        let rr = RoleRewardMirror {
            compute_contributor_pkh: c,
            verify_contributor_pkh: v,
            support_contributor_pkh: s,
        };
        let ext = Phase20ReceiptExtMirror {
            role_reward: rr.clone(),
            compute_claim: mk_claim(ROLE_COMPUTE_CONTRIBUTOR, c),
            verify_claim: mk_claim(ROLE_VERIFY_CONTRIBUTOR, v),
            support_claim: mk_claim(ROLE_SUPPORT_CONTRIBUTOR, s),
            fee_bps: 0,
            fee_pkh: [0u8; 20],
            precommit_root: None,
            role_ticket_proofs: Some(build_role_ticket_proofs(net, h, &prev, &rr)),
            role_dominance_weights: None,
            candidate_set: None,
            role_puzzle_proofs: None,
            finality_proof: None,
            committed_admission: None,
            role_assignment_v2: None,
        };
        let node_ext =
            irium_node_rs::poawx::Phase20ReceiptExt::deserialize(&ext.serialize()).unwrap();
        let proofs = node_ext
            .role_ticket_proofs
            .expect("node sees ticket proofs from pool ext");
        let roles = [
            (irium_node_rs::poawx::ROLE_COMPUTE_CONTRIBUTOR, c),
            (irium_node_rs::poawx::ROLE_VERIFY_CONTRIBUTOR, v),
            (irium_node_rs::poawx::ROLE_SUPPORT_CONTRIBUTOR, s),
        ];
        for (j, (role_id, pkh)) in roles.iter().enumerate() {
            assert!(
                proofs[j].validate(net, h, &prev, *role_id, pkh, 0, false).is_ok(),
                "node validates pool-built ticket proof for role {role_id}"
            );
        }
    }

    #[test]
    fn phase21b_pool_tickets_enforced_gate() {
        let _g = p20_env_lock().lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_NETWORK", "testnet");
        std::env::set_var("IRIUM_POAWX_TICKETS_ACTIVATION_HEIGHT", "1");
        std::env::set_var("IRIUM_POAWX_TICKETS_REQUIRED", "1");
        assert!(pool_tickets_enforced(5), "gate on in testnet");
        std::env::remove_var("IRIUM_POAWX_TICKETS_REQUIRED");
        assert!(!pool_tickets_enforced(5), "no required flag -> off");
        std::env::remove_var("IRIUM_NETWORK"); // mainnet
        std::env::set_var("IRIUM_POAWX_TICKETS_REQUIRED", "1");
        assert!(!pool_tickets_enforced(5), "mainnet hard-off");
        std::env::remove_var("IRIUM_POAWX_TICKETS_ACTIVATION_HEIGHT");
        std::env::remove_var("IRIUM_POAWX_TICKETS_REQUIRED");
    }
}
