use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

pub const BOND_ANCHOR_PREFIX: &str = "bond1:";
pub const WITHDRAW_ANCHOR_PREFIX: &str = "bond1w:";
pub const SLASH_ANCHOR_PREFIX: &str = "slash1:";
pub const BOND_COOLDOWN_BLOCKS: u64 = 1000;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct AttestorBondRecord {
    pub pubkey_hex: String,
    pub pkh_hex: String,
    pub address: String,
    pub bond_atoms: u64,
    pub registered_height: u64,
    pub last_attestation_height: Option<u64>,
    pub slash_count: u32,
    pub slashed_atoms: u64,
    pub registration_txid: String,
    pub withdrawn: bool,
    pub withdraw_height: Option<u64>,
    #[serde(default)]
    pub slash_records: Vec<SlashRecord>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SlashRecord {
    pub agreement_hash: String,
    pub slash_txid: String,
    pub proof1_id: String,
    pub proof2_id: String,
}

#[derive(Serialize, Deserialize, Default)]
pub struct AttestorBondStore {
    pub bonds: Vec<AttestorBondRecord>,
}

impl AttestorBondStore {
    pub fn load(path: &PathBuf) -> Self {
        fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &PathBuf) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).ok();
        }
        let s = serde_json::to_string_pretty(self)
            .map_err(|e| format!("serialize bond store: {e}"))?;
        fs::write(path, s).map_err(|e| format!("write bond store: {e}"))
    }

    pub fn find_by_address(&self, address: &str) -> Option<&AttestorBondRecord> {
        self.bonds.iter().find(|b| b.address == address)
    }

    pub fn find_by_address_mut(&mut self, address: &str) -> Option<&mut AttestorBondRecord> {
        self.bonds.iter_mut().find(|b| b.address == address)
    }

    pub fn find_by_pkh(&self, pkh_hex: &str) -> Option<&AttestorBondRecord> {
        self.bonds.iter().find(|b| b.pkh_hex.eq_ignore_ascii_case(pkh_hex))
    }
}

/// Build OP_RETURN locking script for bond registration.
/// Payload format: bond1:<pkh_hex_40>:<atoms_decimal>
/// Total payload length <= 63 bytes, well within the 75-byte OP_RETURN limit.
pub fn build_bond_anchor_script(pkh_hex: &str, atoms: u64) -> Vec<u8> {
    opreturn_script(format!("{}{}:{}", BOND_ANCHOR_PREFIX, pkh_hex, atoms).as_bytes())
}

/// Build OP_RETURN locking script for bond withdrawal announcement.
/// Payload format: bond1w:<pkh_hex_40>
pub fn build_withdraw_anchor_script(pkh_hex: &str) -> Vec<u8> {
    opreturn_script(format!("{}{}", WITHDRAW_ANCHOR_PREFIX, pkh_hex).as_bytes())
}

/// Build OP_RETURN locking script for slashing record.
/// Payload format: slash1:<attestor_pkh_hex_40>:<agreement_hash_hex_64>
pub fn build_slash_anchor_script(attestor_pkh_hex: &str, agreement_hash_hex: &str) -> Vec<u8> {
    opreturn_script(
        format!("{}{}:{}", SLASH_ANCHOR_PREFIX, attestor_pkh_hex, agreement_hash_hex).as_bytes(),
    )
}

fn opreturn_script(payload: &[u8]) -> Vec<u8> {
    let mut script = Vec::with_capacity(2 + payload.len());
    script.push(0x6a); // OP_RETURN
    script.push(payload.len() as u8);
    script.extend_from_slice(payload);
    script
}

fn extract_opreturn_payload(script: &[u8]) -> Option<&str> {
    if script.len() < 2 || script[0] != 0x6a {
        return None;
    }
    let len = script[1] as usize;
    if script.len() < 2 + len {
        return None;
    }
    std::str::from_utf8(&script[2..2 + len]).ok()
}

/// Parse OP_RETURN script as bond registration anchor.
/// Returns (pkh_hex, atoms) on success.
pub fn parse_bond_anchor(script: &[u8]) -> Option<(String, u64)> {
    let payload = extract_opreturn_payload(script)?;
    let rest = payload.strip_prefix(BOND_ANCHOR_PREFIX)?;
    let colon = rest.find(':')?;
    let pkh_hex = &rest[..colon];
    if pkh_hex.len() != 40 {
        return None;
    }
    let atoms: u64 = rest[colon + 1..].parse().ok()?;
    Some((pkh_hex.to_string(), atoms))
}

/// Parse OP_RETURN script as bond withdrawal anchor.
/// Returns pkh_hex on success.
pub fn parse_withdraw_anchor(script: &[u8]) -> Option<String> {
    let payload = extract_opreturn_payload(script)?;
    let pkh_hex = payload.strip_prefix(WITHDRAW_ANCHOR_PREFIX)?;
    if pkh_hex.len() != 40 {
        return None;
    }
    Some(pkh_hex.to_string())
}

pub fn bond_store_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".irium").join("attestor-bonds.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bond_anchor_roundtrip() {
        let pkh = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let atoms: u64 = 500_000_000;
        let script = build_bond_anchor_script(pkh, atoms);
        assert_eq!(script[0], 0x6a);
        let (parsed_pkh, parsed_atoms) = parse_bond_anchor(&script).expect("should parse");
        assert_eq!(parsed_pkh, pkh);
        assert_eq!(parsed_atoms, atoms);
    }

    #[test]
    fn withdraw_anchor_roundtrip() {
        let pkh = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let script = build_withdraw_anchor_script(pkh);
        let parsed = parse_withdraw_anchor(&script).expect("should parse");
        assert_eq!(parsed, pkh);
    }

    #[test]
    fn bond_anchor_payload_fits_opreturn_limit() {
        // 40-char pkh + max 16-digit atoms = 6 + 40 + 1 + 16 = 63 bytes
        let pkh = "ffffffffffffffffffffffffffffffffffffffff";
        let atoms = u64::MAX;
        let script = build_bond_anchor_script(pkh, atoms);
        let len = script[1] as usize;
        assert!(len <= 75, "OP_RETURN payload {} exceeds 75-byte limit", len);
    }

    #[test]
    fn bond_store_serde_roundtrip() {
        let rec = AttestorBondRecord {
            pubkey_hex: "02abcd".to_string(),
            pkh_hex: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".to_string(),
            address: "Qabc123".to_string(),
            bond_atoms: 100_000_000,
            registered_height: 20500,
            last_attestation_height: Some(20510),
            slash_count: 0,
            slashed_atoms: 0,
            registration_txid: "deadbeef".to_string(),
            withdrawn: false,
            withdraw_height: None,
            slash_records: vec![],
        };
        let store = AttestorBondStore { bonds: vec![rec] };
        let json = serde_json::to_string(&store).unwrap();
        let back: AttestorBondStore = serde_json::from_str(&json).unwrap();
        assert_eq!(back.bonds.len(), 1);
        assert_eq!(back.bonds[0].bond_atoms, 100_000_000);
    }
}
