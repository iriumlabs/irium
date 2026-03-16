use std::env;

/// Mainnet HTLCv1 activation height source-of-truth.
///
/// Set this to `Some(<height>)` only after activation governance is complete.
/// `None` keeps HTLCv1 disabled on mainnet.
pub const MAINNET_HTLCV1_ACTIVATION_HEIGHT: Option<u64> = Some(18677);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkKind {
    Mainnet,
    Testnet,
    Devnet,
}

impl NetworkKind {
    pub fn from_env_value(v: &str) -> Self {
        match v.trim().to_ascii_lowercase().as_str() {
            "testnet" => Self::Testnet,
            "devnet" | "regtest" | "trial" => Self::Devnet,
            _ => Self::Mainnet,
        }
    }
}

pub fn network_kind_from_env() -> NetworkKind {
    env::var("IRIUM_NETWORK")
        .map(|v| NetworkKind::from_env_value(&v))
        .unwrap_or(NetworkKind::Mainnet)
}

pub fn runtime_htlcv1_env_override() -> Option<u64> {
    env::var("IRIUM_HTLCV1_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

pub fn resolved_htlcv1_activation_height(network: NetworkKind) -> Option<u64> {
    match network {
        NetworkKind::Mainnet => MAINNET_HTLCV1_ACTIVATION_HEIGHT,
        NetworkKind::Testnet | NetworkKind::Devnet => runtime_htlcv1_env_override(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_ignores_env_override() {
        std::env::set_var("IRIUM_HTLCV1_ACTIVATION_HEIGHT", "42");
        let resolved = resolved_htlcv1_activation_height(NetworkKind::Mainnet);
        std::env::remove_var("IRIUM_HTLCV1_ACTIVATION_HEIGHT");
        assert_eq!(resolved, MAINNET_HTLCV1_ACTIVATION_HEIGHT);
    }

    #[test]
    fn non_mainnet_uses_env_override() {
        std::env::set_var("IRIUM_HTLCV1_ACTIVATION_HEIGHT", "42");
        assert_eq!(
            resolved_htlcv1_activation_height(NetworkKind::Devnet),
            Some(42)
        );
        assert_eq!(
            resolved_htlcv1_activation_height(NetworkKind::Testnet),
            Some(42)
        );
        std::env::remove_var("IRIUM_HTLCV1_ACTIVATION_HEIGHT");
    }
}
