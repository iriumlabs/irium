use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use bs58;
use pbkdf2::pbkdf2_hmac;
use rand_core::{OsRng, RngCore};
use ripemd::Ripemd160;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use zeroize::Zeroize;

const IRIUM_P2PKH_VERSION: u8 = 0x39;
const WIF_VERSION: u8 = 0x80;
const PBKDF2_ITERS: u32 = 100_000;
const WALLET_VERSION: u32 = 1;
const DEFAULT_AUTO_LOCK_MIN: u64 = 10;

/// Whether a wallet is missing, plaintext (legacy), or encrypted.
/// Exposed to RPC callers via `/wallet/info` and to the CLI via the
/// `info` subcommand so they can decide whether to prompt for a
/// password or force migration. Drives the bootstrap UX entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletMode {
    None,
    Plaintext,
    Encrypted,
}

/// On-disk wallet shape. Unified to accept either:
///   * Encrypted: { version, crypto: { salt, nonce, cipher } }
///     - what `encrypt_wallet` always produces and `save_wallet` always
///       writes going forward.
///   * Plaintext: { version, seed_hex|bip32_seed|mnemonic, next_index, keys }
///     - legacy shape written by older code eras and by the irium-wallet
///       CLI's own removed schema. Tolerated on LOAD only; never WRITTEN
///       by this code. The presence of `crypto` is the discriminator.
#[derive(Debug, Serialize, Deserialize)]
pub struct WalletFile {
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crypto: Option<WalletCrypto>,
    // Legacy plaintext fields. Tolerated on load via #[serde(default)],
    // never serialized when None (skip_serializing_if). After migration,
    // the file is rewritten with crypto = Some(..) and these become
    // omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bip32_seed: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,
    #[serde(default)]
    pub next_index: u32,
    #[serde(default)]
    pub keys: Vec<WalletKey>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WalletCrypto {
    salt: String,
    nonce: String,
    cipher: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
pub struct WalletPlain {
    pub keys: Vec<WalletKey>,
    #[serde(default)]
    pub seed_hex: Option<String>,
    /// Present iff the wallet was created via the BIP32 path (CLI's
    /// `create-wallet --bip32`). Preserved on migration so derivation
    /// remains consistent across reads/writes; round-trips through the
    /// encrypted form unchanged.
    #[serde(default)]
    pub bip32_seed: Option<String>,
    /// Present iff a BIP39 mnemonic was generated/imported. Preserved
    /// the same way as bip32_seed. Used by the recovery flow.
    #[serde(default)]
    pub mnemonic: Option<String>,
    #[serde(default)]
    pub next_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
pub struct WalletKey {
    pub address: String,
    pub pkh: String,
    pub pubkey: String,
    pub privkey: String,
}

#[derive(Default)]
struct WalletState {
    unlocked: Option<WalletPlain>,
    passphrase: Option<String>,
    last_touch: Option<Instant>,
}

impl Drop for WalletState {
    fn drop(&mut self) {
        if let Some(ref mut p) = self.passphrase { p.zeroize(); }
        if let Some(ref mut w) = self.unlocked { w.zeroize(); }
    }
}

pub struct WalletManager {
    path: PathBuf,
    state: WalletState,
}

impl WalletManager {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            state: WalletState::default(),
        }
    }

    pub fn default_path() -> PathBuf {
        if let Ok(path) = env::var("IRIUM_NODE_WALLET_FILE") {
            return PathBuf::from(path);
        }
        if let Ok(path) = env::var("IRIUM_WALLET_FILE") {
            return PathBuf::from(path);
        }
        let home = env::var("HOME").unwrap_or_else(|_| "/".to_string());
        let irium_dir = PathBuf::from(home).join(".irium");
        let new_path = irium_dir.join("wallet.json");
        let legacy_path = irium_dir.join("wallet.core.json");
        // Prefer the unified path (wallet.json — same path Irium Core and
        // irium-wallet CLI write to). Fall back to the legacy encrypted
        // filename only when wallet.json does not exist AND
        // wallet.core.json does, so users with an existing encrypted
        // wallet under the old name keep working without manual action.
        if !new_path.exists() && legacy_path.exists() {
            legacy_path
        } else {
            new_path
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    pub fn is_unlocked(&self) -> bool {
        self.state.unlocked.is_some()
    }

    pub fn create(&mut self, passphrase: &str) -> Result<WalletKey, String> {
        self.create_with_seed(passphrase, None)
    }

    pub fn create_with_seed(
        &mut self,
        passphrase: &str,
        seed_hex: Option<&str>,
    ) -> Result<WalletKey, String> {
        if passphrase.trim().is_empty() {
            return Err("passphrase required".to_string());
        }
        if self.path.exists() {
            return Err("wallet already exists".to_string());
        }

        let mut plain = WalletPlain {
            keys: Vec::new(),
            seed_hex: None,
            bip32_seed: None,
            mnemonic: None,
            next_index: 0,
        };

        let key = if let Some(seed) = seed_hex {
            let clean = normalize_seed_hex(seed)?;
            let secret = derive_secret_from_seed_hex(&clean, 0)?;
            plain.seed_hex = Some(clean);
            plain.next_index = 1;
            key_from_secret(&secret, true)
        } else {
            let clean = generate_seed_hex();
            let secret = derive_secret_from_seed_hex(&clean, 0)?;
            plain.seed_hex = Some(clean);
            plain.next_index = 1;
            key_from_secret(&secret, true)
        };

        plain.keys.push(key.clone());
        let file = encrypt_wallet(passphrase, &plain)?;
        save_wallet(&self.path, &file)?;
        self.state.unlocked = Some(plain);
        self.state.passphrase = Some(passphrase.to_string());
        self.touch();
        Ok(key)
    }

    pub fn unlock(&mut self, passphrase: &str) -> Result<(), String> {
        if passphrase.trim().is_empty() {
            return Err("passphrase required".to_string());
        }
        let file = load_wallet(&self.path)?;
        // Plaintext wallets cannot be unlocked directly — caller must
        // route through migrate_to_encrypted first to set a password.
        // This is the load-bearing invariant of the unified scheme:
        // post-migration, every wallet on disk has crypto = Some(..).
        if file.crypto.is_none() {
            return Err("wallet_needs_migration".to_string());
        }
        let mut plain = decrypt_wallet(passphrase, &file)?;
        if plain.next_index == 0
            && (plain.seed_hex.is_some() || plain.bip32_seed.is_some())
        {
            plain.next_index = plain.keys.len() as u32;
        }
        self.state.unlocked = Some(plain);
        self.state.passphrase = Some(passphrase.to_string());
        self.touch();
        Ok(())
    }

    /// Read the file on disk and report whether the wallet is missing,
    /// plaintext (legacy, needs migration), or already encrypted.
    /// Used by RPC `/wallet/info` and the CLI `info` subcommand. Does
    /// NOT mutate state and does NOT unlock anything.
    pub fn mode(&self) -> WalletMode {
        if !self.path.exists() {
            return WalletMode::None;
        }
        match load_wallet(&self.path) {
            Ok(file) => {
                if file.crypto.is_some() {
                    WalletMode::Encrypted
                } else {
                    WalletMode::Plaintext
                }
            }
            // Unparseable on-disk file — treat as missing rather than
            // crash callers. Operator can clean up manually.
            Err(_) => WalletMode::None,
        }
    }

    /// Enumerate timestamped plaintext-backup files left by
    /// `migrate_to_encrypted` so the frontend can warn the operator to
    /// delete them after verification. Pattern matched is
    /// `<wallet>.plaintext.bak.<unix-seconds>`.
    pub fn plaintext_backups(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let parent = match self.path.parent() {
            Some(p) => p,
            None => return out,
        };
        let stem = self
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("wallet.json")
            .to_string();
        let prefix = format!("{}.plaintext.bak.", stem);
        let read_dir = match fs::read_dir(parent) {
            Ok(r) => r,
            Err(_) => return out,
        };
        for entry in read_dir.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with(&prefix) {
                    out.push(entry.path());
                }
            }
        }
        out
    }

    /// Re-encrypt a legacy plaintext wallet under a new passphrase.
    /// Pre-condition: `mode() == Plaintext`. Post-condition: the file
    /// on disk is encrypted; in-memory state is unlocked; a backup of
    /// the original plaintext content lives at
    /// `<path>.plaintext.bak.<unix-seconds>`.
    ///
    /// Atomic write strategy: copy original to backup, encrypt to a
    /// temp file, then `fs::rename(tmp, final)` which is atomic on the
    /// same filesystem. If the rename fails for any reason the original
    /// is restored from backup and the error propagates.
    pub fn migrate_to_encrypted(&mut self, new_passphrase: &str) -> Result<(), String> {
        if new_passphrase.trim().is_empty() {
            return Err("passphrase required".to_string());
        }
        let file = load_wallet(&self.path)?;
        if file.crypto.is_some() {
            return Err("already_encrypted".to_string());
        }
        // Harvest the plaintext fields into a WalletPlain. Tolerate both
        // legacy shapes: wallet_store's old plaintext (seed_hex only) and
        // the irium-wallet CLI's shape (bip32_seed + mnemonic).
        let mut plain = WalletPlain {
            keys: file.keys.clone(),
            seed_hex: file.seed_hex.clone(),
            bip32_seed: file.bip32_seed.clone(),
            mnemonic: file.mnemonic.clone(),
            next_index: if file.next_index == 0 {
                file.keys.len() as u32
            } else {
                file.next_index
            },
        };
        // Defensive: if the legacy file had a seed but next_index was
        // zero, infer next_index from the keys array length so future
        // derivations don't collide with existing addresses.
        if plain.next_index == 0 && !plain.keys.is_empty() {
            plain.next_index = plain.keys.len() as u32;
        }

        // Backup the original plaintext content. fs::copy preserves the
        // original at its current location until the encrypted write
        // succeeds — defense against a crash between write and rename.
        let backup = self
            .path
            .with_file_name(format!(
                "{}.plaintext.bak.{}",
                self.path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("wallet.json"),
                now_secs()
            ));
        fs::copy(&self.path, &backup).map_err(|e| format!("backup failed: {e}"))?;

        // Encrypt under the new passphrase and write to a temp path.
        let encrypted = encrypt_wallet(new_passphrase, &plain)?;
        let tmp = self.path.with_extension("tmp");
        save_wallet(&tmp, &encrypted)?;

        // Atomic commit. On failure, restore the original.
        if let Err(e) = fs::rename(&tmp, &self.path) {
            let _ = fs::copy(&backup, &self.path);
            let _ = fs::remove_file(&tmp);
            return Err(format!("commit failed: {e}"));
        }

        self.state.unlocked = Some(plain);
        self.state.passphrase = Some(new_passphrase.to_string());
        self.touch();
        Ok(())
    }

    /// Build a fresh encrypted wallet from a seed. Accepts either a
    /// 64-char hex seed (wallet_store custom derivation) or a 128-char
    /// hex BIP32 seed (preserved as bip32_seed for downstream tools
    /// that derive via BIP32 — wallet_store itself only derives via
    /// `derive_secret_from_seed_hex` for now; BIP32 derivation lives
    /// in the irium-wallet binary).
    ///
    /// If `allow_overwrite` is false and a wallet file already exists,
    /// returns `Err("wallet_exists")`. If true, the existing file is
    /// preserved as `<path>.recovery-bak.<unix-seconds>` before being
    /// overwritten.
    pub fn recover_from_seed(
        &mut self,
        seed_hex: &str,
        new_passphrase: &str,
        allow_overwrite: bool,
    ) -> Result<WalletKey, String> {
        if new_passphrase.trim().is_empty() {
            return Err("passphrase required".to_string());
        }
        let seed_lower = seed_hex.trim().to_lowercase();
        let _ = hex::decode(&seed_lower).map_err(|_| "seed must be valid hex".to_string())?;
        if seed_lower.len() != 64 && seed_lower.len() != 128 {
            return Err(
                "seed must be 64-char (custom) or 128-char (BIP32) hex".to_string()
            );
        }

        if self.path.exists() {
            if !allow_overwrite {
                return Err("wallet_exists".to_string());
            }
            let backup = self.path.with_file_name(format!(
                "{}.recovery-bak.{}",
                self.path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("wallet.json"),
                now_secs()
            ));
            fs::copy(&self.path, &backup)
                .map_err(|e| format!("backup-before-overwrite failed: {e}"))?;
        }

        let (plain, key) = if seed_lower.len() == 64 {
            // wallet_store custom derivation path. Derive the first key
            // and store seed_hex so new_address keeps working.
            let secret = derive_secret_from_seed_hex(&seed_lower, 0)?;
            let key = key_from_secret(&secret, true);
            let plain = WalletPlain {
                keys: vec![key.clone()],
                seed_hex: Some(seed_lower),
                bip32_seed: None,
                mnemonic: None,
                next_index: 1,
            };
            (plain, key)
        } else {
            // 128-hex BIP32 seed. Without the BIP32 derive function
            // available here we store the seed as bip32_seed and
            // generate a holdover random key so the wallet has at
            // least one signer immediately. The CLI's recover-wallet
            // path should derive properly via bip32_derive_irium and
            // call recover_from_keys (separate flow) rather than this
            // one; this branch exists so the iriumd RPC path doesn't
            // fail outright on 128-hex input.
            let key = generate_key();
            let plain = WalletPlain {
                keys: vec![key.clone()],
                seed_hex: None,
                bip32_seed: Some(seed_lower),
                mnemonic: None,
                next_index: 1,
            };
            (plain, key)
        };

        let encrypted = encrypt_wallet(new_passphrase, &plain)?;
        save_wallet(&self.path, &encrypted)?;
        self.state.unlocked = Some(plain);
        self.state.passphrase = Some(new_passphrase.to_string());
        self.touch();
        Ok(key)
    }

    pub fn lock(&mut self) {
        self.state = WalletState::default();
    }

    pub fn addresses(&mut self) -> Result<Vec<String>, String> {
        self.ensure_unlocked()?;
        let addrs = self
            .state
            .unlocked
            .as_ref()
            .map(|w| w.keys.iter().map(|k| k.address.clone()).collect())
            .unwrap_or_default();
        self.touch();
        Ok(addrs)
    }

    pub fn current_address(&mut self) -> Result<String, String> {
        self.ensure_unlocked()?;
        let addr = self
            .state
            .unlocked
            .as_ref()
            .and_then(|w| w.keys.last())
            .map(|k| k.address.clone())
            .ok_or_else(|| "wallet has no keys".to_string())?;
        self.touch();
        Ok(addr)
    }

    pub fn new_address(&mut self) -> Result<WalletKey, String> {
        self.ensure_unlocked()?;
        let passphrase = self
            .state
            .passphrase
            .clone()
            .ok_or_else(|| "wallet locked".to_string())?;

        let key = if let Some(ref mut plain) = self.state.unlocked {
            let key = if let Some(seed_hex) = plain.seed_hex.clone() {
                let index = plain.next_index;
                let secret = derive_secret_from_seed_hex(&seed_hex, index)?;
                let k = key_from_secret(&secret, true);
                plain.next_index = plain.next_index.saturating_add(1);
                k
            } else {
                generate_key()
            };

            if plain.keys.iter().any(|k| k.address == key.address) {
                return Err("derived address already exists".to_string());
            }
            plain.keys.push(key.clone());
            key
        } else {
            return Err("wallet locked".to_string());
        };

        self.persist_unlocked(&passphrase)?;
        self.touch();
        Ok(key)
    }

    pub fn keys(&mut self) -> Result<Vec<WalletKey>, String> {
        self.ensure_unlocked()?;
        let keys = self
            .state
            .unlocked
            .as_ref()
            .map(|w| w.keys.clone())
            .unwrap_or_default();
        self.touch();
        Ok(keys)
    }

    pub fn export_wif(&mut self, address: &str) -> Result<String, String> {
        self.ensure_unlocked()?;
        let key = self
            .state
            .unlocked
            .as_ref()
            .and_then(|w| w.keys.iter().find(|k| k.address == address.trim()))
            .ok_or_else(|| "address not found in wallet".to_string())?;
        let priv_bytes = hex::decode(&key.privkey).map_err(|_| "invalid wallet key".to_string())?;
        if priv_bytes.len() != 32 {
            return Err("invalid wallet key length".to_string());
        }
        let mut sec = [0u8; 32];
        sec.copy_from_slice(&priv_bytes);
        self.touch();
        Ok(secret_to_wif(&sec, true))
    }

    pub fn import_wif(&mut self, wif: &str) -> Result<WalletKey, String> {
        self.ensure_unlocked()?;
        let passphrase = self
            .state
            .passphrase
            .clone()
            .ok_or_else(|| "wallet locked".to_string())?;

        let (secret, compressed) = wif_to_secret_and_compression(wif.trim())?;
        let secret_key =
            SecretKey::from_slice(&secret).map_err(|_| "invalid WIF secret".to_string())?;
        let key = key_from_secret(&secret_key, compressed);

        if let Some(ref mut plain) = self.state.unlocked {
            if plain.keys.iter().any(|k| k.address == key.address) {
                return Err("address already exists in wallet".to_string());
            }
            plain.keys.push(key.clone());
            // Imported-key wallet should not continue deterministic derivation blindly.
            plain.seed_hex = None;
            plain.next_index = plain.keys.len() as u32;
        }

        self.persist_unlocked(&passphrase)?;
        self.touch();
        Ok(key)
    }

    pub fn export_seed(&mut self) -> Result<String, String> {
        self.ensure_unlocked()?;
        let seed = self
            .state
            .unlocked
            .as_ref()
            .and_then(|w| w.seed_hex.clone())
            .ok_or_else(|| "no deterministic seed stored in wallet".to_string())?;
        self.touch();
        Ok(seed)
    }

    /// Return the BIP39 mnemonic phrase stored in the unlocked wallet. Mirrors
    /// `export_seed` — the wallet must be unlocked and must have a mnemonic
    /// (WIF-imported or raw-seed-imported wallets carry no mnemonic and will
    /// surface "no mnemonic stored in wallet"). The mnemonic is preserved
    /// across encrypt/decrypt cycles via the WalletPlain.mnemonic field.
    pub fn export_mnemonic(&mut self) -> Result<String, String> {
        self.ensure_unlocked()?;
        let mnemonic = self
            .state
            .unlocked
            .as_ref()
            .and_then(|w| w.mnemonic.clone())
            .ok_or_else(|| "no mnemonic stored in wallet".to_string())?;
        self.touch();
        Ok(mnemonic)
    }

    pub fn import_seed(&mut self, seed_hex: &str, force: bool) -> Result<WalletKey, String> {
        self.ensure_unlocked()?;
        let passphrase = self
            .state
            .passphrase
            .clone()
            .ok_or_else(|| "wallet locked".to_string())?;

        let clean = normalize_seed_hex(seed_hex)?;
        let secret = derive_secret_from_seed_hex(&clean, 0)?;
        let key = key_from_secret(&secret, true);

        if let Some(ref mut plain) = self.state.unlocked {
            if !force && !plain.keys.is_empty() {
                return Err("wallet already has keys; pass force=true to replace".to_string());
            }
            plain.seed_hex = Some(clean);
            plain.next_index = 1;
            plain.keys.clear();
            plain.keys.push(key.clone());
        }

        self.persist_unlocked(&passphrase)?;
        self.touch();
        Ok(key)
    }

    fn persist_unlocked(&self, passphrase: &str) -> Result<(), String> {
        let plain = self
            .state
            .unlocked
            .as_ref()
            .ok_or_else(|| "wallet locked".to_string())?;
        let file = encrypt_wallet(passphrase, plain)?;
        save_wallet(&self.path, &file)
    }

    fn ensure_unlocked(&mut self) -> Result<(), String> {
        self.maybe_auto_lock();
        if self.state.unlocked.is_none() {
            return Err("wallet locked".to_string());
        }
        Ok(())
    }

    fn touch(&mut self) {
        self.state.last_touch = Some(Instant::now());
    }

    fn maybe_auto_lock(&mut self) {
        let mins = auto_lock_minutes();
        if mins == 0 {
            return;
        }
        if let Some(last) = self.state.last_touch {
            if last.elapsed() >= Duration::from_secs(mins * 60) {
                self.lock();
            }
        }
    }
}

fn auto_lock_minutes() -> u64 {
    env::var("IRIUM_WALLET_AUTO_LOCK_MIN")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_AUTO_LOCK_MIN)
}

fn derive_key(passphrase: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), salt, PBKDF2_ITERS, &mut key);
    key
}

fn encrypt_wallet(passphrase: &str, plain: &WalletPlain) -> Result<WalletFile, String> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let key = derive_key(passphrase, &salt);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    let payload = serde_json::to_vec(plain).map_err(|e| e.to_string())?;
    #[allow(deprecated)]
    let nonce_ga = Nonce::from_slice(&nonce);
    let ciphertext = cipher
        .encrypt(nonce_ga, payload.as_ref())
        .map_err(|e| e.to_string())?;
    Ok(WalletFile {
        version: WALLET_VERSION,
        crypto: Some(WalletCrypto {
            salt: hex::encode(salt),
            nonce: hex::encode(nonce),
            cipher: hex::encode(ciphertext),
        }),
        // Encrypted shape — plaintext fields are absent on disk via
        // skip_serializing_if on the WalletFile struct.
        seed_hex: None,
        bip32_seed: None,
        mnemonic: None,
        next_index: 0,
        keys: Vec::new(),
    })
}

fn decrypt_wallet(passphrase: &str, file: &WalletFile) -> Result<WalletPlain, String> {
    if file.version != WALLET_VERSION {
        return Err("unsupported wallet version".to_string());
    }
    let crypto = file
        .crypto
        .as_ref()
        .ok_or_else(|| "wallet has no crypto block".to_string())?;
    let salt = hex::decode(&crypto.salt).map_err(|e| e.to_string())?;
    let nonce = hex::decode(&crypto.nonce).map_err(|e| e.to_string())?;
    let cipher_bytes = hex::decode(&crypto.cipher).map_err(|e| e.to_string())?;
    let key = derive_key(passphrase, &salt);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    #[allow(deprecated)]
    let payload = cipher
        .decrypt(Nonce::from_slice(&nonce), cipher_bytes.as_ref())
        .map_err(|_| "invalid passphrase".to_string())?;
    serde_json::from_slice(&payload).map_err(|e| e.to_string())
}

fn save_wallet(path: &Path, file: &WalletFile) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let raw = serde_json::to_string_pretty(file).map_err(|e| e.to_string())?;
    fs::write(path, raw).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, perms).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn load_wallet(path: &Path) -> Result<WalletFile, String> {
    let raw = fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&raw).map_err(|e| e.to_string())
}

fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let rip = Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&rip);
    out
}

fn base58_p2pkh_from_hash(pkh: &[u8; 20]) -> String {
    let mut body = Vec::with_capacity(1 + 20);
    body.push(IRIUM_P2PKH_VERSION);
    body.extend_from_slice(pkh);
    let first = Sha256::digest(&body);
    let second = Sha256::digest(first);
    let checksum = &second[0..4];
    let mut full = body;
    full.extend_from_slice(checksum);
    bs58::encode(full).into_string()
}

fn base58check_decode(input: &str) -> Option<Vec<u8>> {
    let data = bs58::decode(input).into_vec().ok()?;
    if data.len() < 5 {
        return None;
    }
    let (payload, check) = data.split_at(data.len() - 4);
    let first = Sha256::digest(payload);
    let second = Sha256::digest(first);
    if &second[0..4] != check {
        return None;
    }
    Some(payload.to_vec())
}

fn secret_to_wif(secret: &[u8; 32], compressed: bool) -> String {
    let mut payload = Vec::with_capacity(34);
    payload.push(WIF_VERSION);
    payload.extend_from_slice(secret);
    if compressed {
        payload.push(0x01);
    }
    let first = Sha256::digest(&payload);
    let second = Sha256::digest(first);
    let mut full = payload;
    full.extend_from_slice(&second[0..4]);
    bs58::encode(full).into_string()
}

fn wif_to_secret_and_compression(wif: &str) -> Result<([u8; 32], bool), String> {
    let data = base58check_decode(wif).ok_or_else(|| "invalid WIF".to_string())?;
    if data.len() != 33 && data.len() != 34 {
        return Err("invalid WIF length".to_string());
    }
    if data[0] != WIF_VERSION {
        return Err("unsupported WIF version".to_string());
    }
    let compressed = if data.len() == 34 {
        if data[33] != 0x01 {
            return Err("invalid WIF compression flag".to_string());
        }
        true
    } else {
        false
    };
    let mut sec = [0u8; 32];
    sec.copy_from_slice(&data[1..33]);
    Ok((sec, compressed))
}

fn normalize_seed_hex(seed_hex: &str) -> Result<String, String> {
    let s = seed_hex.trim().to_lowercase();
    if s.len() != 64 {
        return Err("seed must be 64-char hex".to_string());
    }
    let _ = hex::decode(&s).map_err(|_| "seed must be valid hex".to_string())?;
    Ok(s)
}

fn generate_seed_hex() -> String {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    hex::encode(seed)
}

fn derive_secret_from_seed_hex(seed_hex: &str, index: u32) -> Result<SecretKey, String> {
    let seed = hex::decode(seed_hex).map_err(|_| "seed must be valid hex".to_string())?;
    if seed.len() != 32 {
        return Err("seed must be 64-char hex".to_string());
    }
    for attempt in 0u32..=1024 {
        let mut h = Sha256::new();
        h.update(&seed);
        h.update(index.to_be_bytes());
        h.update(attempt.to_be_bytes());
        let digest = h.finalize();
        if let Ok(sec) = SecretKey::from_slice(&digest) {
            return Ok(sec);
        }
    }
    Err("failed to derive valid key from seed".to_string())
}

fn key_from_secret(secret: &SecretKey, compressed: bool) -> WalletKey {
    let public = secret.public_key();
    let pubkey = public.to_encoded_point(compressed);
    let pkh = hash160(pubkey.as_bytes());
    let address = base58_p2pkh_from_hash(&pkh);
    WalletKey {
        address,
        pkh: hex::encode(pkh),
        pubkey: hex::encode(pubkey.as_bytes()),
        privkey: hex::encode(secret.to_bytes()),
    }
}

fn generate_key() -> WalletKey {
    let secret = SecretKey::random(&mut OsRng);
    key_from_secret(&secret, true)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static UNIQ: AtomicU64 = AtomicU64::new(0);

    /// Per-test scratch path under tempdir. Caller is responsible for
    /// removing the file (each test does a best-effort cleanup at end).
    fn tmp_path(tag: &str) -> PathBuf {
        let n = UNIQ.fetch_add(1, Ordering::SeqCst);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "irium_wallet_test_{}_{}_{}_{}.json",
            tag,
            std::process::id(),
            now_secs(),
            n
        ));
        p
    }

    fn cleanup(path: &PathBuf) {
        let _ = fs::remove_file(path);
        if let Some(parent) = path.parent() {
            if let Ok(read_dir) = fs::read_dir(parent) {
                for entry in read_dir.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    if name_str.starts_with(
                        &path
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("")
                            .to_string(),
                    ) {
                        let _ = fs::remove_file(entry.path());
                    }
                }
            }
        }
    }

    /// Synthesise a legacy CLI plaintext wallet.json shape with one
    /// derived key + bip32_seed + mnemonic. Returns the path.
    fn write_legacy_cli_plaintext(path: &PathBuf) {
        let key = generate_key();
        let plain_json = serde_json::json!({
            "version": 1,
            "seed_hex": null,
            "bip32_seed": "01".repeat(64),
            "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "next_index": 1,
            "keys": [
                {
                    "address": key.address,
                    "pkh": key.pkh,
                    "pubkey": key.pubkey,
                    "privkey": key.privkey,
                }
            ]
        });
        fs::write(path, serde_json::to_string_pretty(&plain_json).unwrap()).unwrap();
    }

    /// Synthesise a legacy wallet_store plaintext shape (seed_hex only,
    /// no bip32_seed/mnemonic).
    fn write_legacy_ws_plaintext(path: &PathBuf) {
        let seed = "ab".repeat(32);
        let secret = derive_secret_from_seed_hex(&seed, 0).unwrap();
        let key = key_from_secret(&secret, true);
        let plain_json = serde_json::json!({
            "version": 1,
            "seed_hex": seed,
            "next_index": 1,
            "keys": [
                {
                    "address": key.address,
                    "pkh": key.pkh,
                    "pubkey": key.pubkey,
                    "privkey": key.privkey,
                }
            ]
        });
        fs::write(path, serde_json::to_string_pretty(&plain_json).unwrap()).unwrap();
    }

    #[test]
    fn unlock_rejects_plaintext_file_with_needs_migration_error() {
        let path = tmp_path("unlock_rejects_plaintext");
        write_legacy_cli_plaintext(&path);
        let mut mgr = WalletManager::new(path.clone());
        let err = mgr.unlock("any-passphrase").unwrap_err();
        assert_eq!(err, "wallet_needs_migration");
        cleanup(&path);
    }

    #[test]
    fn migrate_to_encrypted_round_trips_legacy_cli_plaintext_wallet_json() {
        let path = tmp_path("migrate_cli_roundtrip");
        write_legacy_cli_plaintext(&path);
        let mut mgr = WalletManager::new(path.clone());

        let pre_addr = {
            let raw = fs::read_to_string(&path).unwrap();
            let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
            v["keys"][0]["address"].as_str().unwrap().to_string()
        };

        mgr.migrate_to_encrypted("new-pass").unwrap();
        assert_eq!(mgr.mode(), WalletMode::Encrypted);
        let post_addr = mgr.addresses().unwrap()[0].clone();
        assert_eq!(pre_addr, post_addr, "addresses must survive migration");

        // Re-lock and re-unlock with the new password.
        mgr.lock();
        mgr.unlock("new-pass").unwrap();
        let post_unlock_addr = mgr.addresses().unwrap()[0].clone();
        assert_eq!(pre_addr, post_unlock_addr);
        cleanup(&path);
    }

    #[test]
    fn migrate_to_encrypted_round_trips_legacy_ws_plaintext_wallet() {
        let path = tmp_path("migrate_ws_roundtrip");
        write_legacy_ws_plaintext(&path);
        let mut mgr = WalletManager::new(path.clone());
        mgr.migrate_to_encrypted("ws-pass").unwrap();
        assert_eq!(mgr.mode(), WalletMode::Encrypted);

        mgr.lock();
        mgr.unlock("ws-pass").unwrap();
        // After migration the seed_hex (custom derivation) must survive
        // through the cipher round-trip.
        let plain = mgr.state.unlocked.as_ref().unwrap();
        assert!(plain.seed_hex.is_some());
        assert_eq!(plain.keys.len(), 1);
        cleanup(&path);
    }

    #[test]
    fn migrate_to_encrypted_creates_timestamped_backup() {
        let path = tmp_path("migrate_backup");
        write_legacy_cli_plaintext(&path);
        let mut mgr = WalletManager::new(path.clone());
        mgr.migrate_to_encrypted("p").unwrap();

        let backups = mgr.plaintext_backups();
        assert_eq!(backups.len(), 1, "exactly one backup expected");
        let bname = backups[0].file_name().unwrap().to_str().unwrap();
        assert!(bname.contains(".plaintext.bak."), "backup name shape: {bname}");

        // Cleanup
        for b in &backups {
            let _ = fs::remove_file(b);
        }
        cleanup(&path);
    }

    #[test]
    fn migrate_to_encrypted_fails_on_already_encrypted_file() {
        let path = tmp_path("migrate_already_encrypted");
        let mut mgr = WalletManager::new(path.clone());
        mgr.create_with_seed("p1", None).unwrap();

        let err = mgr.migrate_to_encrypted("p2").unwrap_err();
        assert_eq!(err, "already_encrypted");
        cleanup(&path);
    }

    #[test]
    fn migrate_to_encrypted_rejects_empty_passphrase() {
        let path = tmp_path("migrate_empty_pass");
        write_legacy_cli_plaintext(&path);
        let mut mgr = WalletManager::new(path.clone());
        let err = mgr.migrate_to_encrypted("   ").unwrap_err();
        assert!(err.contains("passphrase required"));
        cleanup(&path);
    }

    #[test]
    fn recover_from_seed_rejects_existing_file_without_overwrite() {
        let path = tmp_path("recover_existing");
        let mut mgr = WalletManager::new(path.clone());
        mgr.create_with_seed("p1", None).unwrap();

        let err = mgr
            .recover_from_seed(&"a".repeat(64), "p2", false)
            .unwrap_err();
        assert_eq!(err, "wallet_exists");
        cleanup(&path);
    }

    #[test]
    fn recover_from_seed_overwrite_creates_recovery_backup() {
        let path = tmp_path("recover_overwrite");
        let mut mgr = WalletManager::new(path.clone());
        mgr.create_with_seed("p1", None).unwrap();
        // Force-overwrite with a known seed; the original is preserved
        // as <path>.recovery-bak.<ts>.
        let _ = mgr
            .recover_from_seed(&"b".repeat(64), "p2", true)
            .unwrap();
        assert_eq!(mgr.mode(), WalletMode::Encrypted);
        // The overwrite happened: addresses now derive from the new seed.
        mgr.lock();
        mgr.unlock("p2").unwrap();
        assert_eq!(mgr.addresses().unwrap().len(), 1);

        // Check that a recovery backup exists alongside.
        let parent = path.parent().unwrap();
        let base = path.file_name().unwrap().to_str().unwrap();
        let mut found = false;
        for e in fs::read_dir(parent).unwrap().flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with(&format!("{base}.recovery-bak.")) {
                let _ = fs::remove_file(e.path());
                found = true;
            }
        }
        assert!(found, "recovery backup must exist");
        cleanup(&path);
    }

    #[test]
    fn recover_from_seed_accepts_64_hex_seed() {
        let path = tmp_path("recover_64hex");
        let mut mgr = WalletManager::new(path.clone());
        let key = mgr
            .recover_from_seed(&"c".repeat(64), "p", false)
            .unwrap();
        // 64-hex path uses wallet_store's custom derivation; same seed
        // must yield the same address.
        let mgr2_path = tmp_path("recover_64hex_verify");
        let mut mgr2 = WalletManager::new(mgr2_path.clone());
        let key2 = mgr2
            .recover_from_seed(&"c".repeat(64), "p2", false)
            .unwrap();
        assert_eq!(key.address, key2.address);
        cleanup(&path);
        cleanup(&mgr2_path);
    }

    #[test]
    fn recover_from_seed_accepts_128_hex_bip32_seed() {
        let path = tmp_path("recover_128hex");
        let mut mgr = WalletManager::new(path.clone());
        let _key = mgr
            .recover_from_seed(&"d".repeat(128), "p", false)
            .unwrap();
        // 128-hex path stores bip32_seed; round-trip through unlock.
        mgr.lock();
        mgr.unlock("p").unwrap();
        let plain = mgr.state.unlocked.as_ref().unwrap();
        assert_eq!(plain.bip32_seed.as_deref(), Some(&"d".repeat(128)[..]));
        assert!(plain.seed_hex.is_none());
        cleanup(&path);
    }

    #[test]
    fn recover_from_seed_rejects_empty_passphrase() {
        let path = tmp_path("recover_empty");
        let mut mgr = WalletManager::new(path.clone());
        let err = mgr
            .recover_from_seed(&"e".repeat(64), "", false)
            .unwrap_err();
        assert!(err.contains("passphrase required"));
        cleanup(&path);
    }

    #[test]
    fn recover_from_seed_rejects_invalid_hex_length() {
        let path = tmp_path("recover_bad_len");
        let mut mgr = WalletManager::new(path.clone());
        let err = mgr.recover_from_seed("deadbeef", "p", false).unwrap_err();
        assert!(err.contains("seed must be 64-char") || err.contains("128-char"));
        cleanup(&path);
    }

    #[test]
    fn mode_returns_correct_state_for_each_file_shape() {
        let path = tmp_path("mode_dispatch");

        // Mode: None (no file)
        {
            let mgr = WalletManager::new(path.clone());
            assert_eq!(mgr.mode(), WalletMode::None);
        }

        // Mode: Plaintext (legacy CLI shape)
        write_legacy_cli_plaintext(&path);
        {
            let mgr = WalletManager::new(path.clone());
            assert_eq!(mgr.mode(), WalletMode::Plaintext);
        }

        // Mode: Encrypted (after create_with_seed)
        let _ = fs::remove_file(&path);
        {
            let mut mgr = WalletManager::new(path.clone());
            mgr.create_with_seed("p", None).unwrap();
            assert_eq!(mgr.mode(), WalletMode::Encrypted);
        }

        cleanup(&path);
    }

    #[test]
    fn legacy_encrypted_wallet_still_unlocks_with_original_passphrase() {
        // Mimic the legacy wallet.core.json shape: {version, crypto:
        // {salt, nonce, cipher}} with no plaintext fields. The unified
        // schema must continue to deserialize and decrypt this.
        let path = tmp_path("legacy_encrypted_unlock");
        let mut mgr = WalletManager::new(path.clone());
        mgr.create_with_seed("legacy-pass", None).unwrap();

        // Confirm the on-disk file has crypto but no plaintext fields
        // (skip_serializing_if = Option::is_none).
        let raw = fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert!(v.get("crypto").is_some());
        assert!(v.get("seed_hex").is_none());
        assert!(v.get("bip32_seed").is_none());

        // Lock and re-unlock to confirm the round-trip.
        mgr.lock();
        mgr.unlock("legacy-pass").unwrap();
        assert!(!mgr.addresses().unwrap().is_empty());
        cleanup(&path);
    }

    #[test]
    fn unlock_rejects_empty_passphrase_on_encrypted_wallet() {
        let path = tmp_path("unlock_empty_pass");
        let mut mgr = WalletManager::new(path.clone());
        mgr.create_with_seed("p", None).unwrap();
        mgr.lock();
        let err = mgr.unlock("   ").unwrap_err();
        assert!(err.contains("passphrase required"));
        cleanup(&path);
    }
}
