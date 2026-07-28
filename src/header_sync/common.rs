//! Shared types and constants for the in-process header sync threads.

use std::env;

/// Number of blocks to stay behind the public external-chain tip. Same
/// rationale as the standalone binaries — keeps the relay clear of
/// near-tip reorgs without making submitted headers stale.
pub const SAFETY_LAG: u64 = 3;

/// Maximum headers submitted in a single cycle. Matches the standalone
/// binaries' BATCH_SIZE and iriumd's `MAX_*_HEADERS_PER_BATCH`.
pub const BATCH_SIZE: u64 = 144;

/// Number of retry attempts for a single header-fetch call before
/// giving up on the whole batch.
pub const PER_HEADER_RETRIES: u32 = 3;

/// Sleep between retry attempts on a single fetch call.
pub const RETRY_SLEEP_MS: u64 = 500;

/// Throttle between sequential public-API requests to stay polite to
/// upstream block-explorer APIs.
pub const POLITE_SLEEP_MS: u64 = 50;

/// HTTP client timeout for any single request.
pub const HTTP_TIMEOUT_SECS: u64 = 30;

/// Period between cycles inside the iriumd tokio task. Matches the
/// standalone binaries' systemd `OnUnitInactiveSec=10min` cadence.
pub const CYCLE_PERIOD_SECS: u64 = 600;

/// Header source dispatch for the LTC and DOGE syncs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Regtest,
    Mainnet,
}

impl Source {
    /// Reads the named env var and resolves it to a `Source`. Defaults
    /// to `Mainnet` when the env var is unset. Returns an error for any
    /// value other than "regtest" or "mainnet" (case-insensitive).
    pub fn from_env(env_var: &str) -> Result<Self, String> {
        let raw = env::var(env_var).unwrap_or_else(|_| "mainnet".to_string());
        match raw.trim().to_lowercase().as_str() {
            "regtest" => Ok(Source::Regtest),
            "mainnet" => Ok(Source::Mainnet),
            other => Err(format!(
                "{env_var} must be 'regtest' or 'mainnet'; got {other:?}"
            )),
        }
    }
}

/// Reads a u64 env var with a default fallback.
pub fn env_u64(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn lock() -> &'static Mutex<()> {
        static L: OnceLock<Mutex<()>> = OnceLock::new();
        L.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn source_from_env_defaults_to_mainnet_when_unset() {
        let _env = crate::test_env::guard();
        let _g = lock().lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("IRIUM_TEST_SOURCE_X");
        assert_eq!(
            Source::from_env("IRIUM_TEST_SOURCE_X").unwrap(),
            Source::Mainnet
        );
    }

    #[test]
    fn source_from_env_parses_regtest_and_mainnet_case_insensitively() {
        let _env = crate::test_env::guard();
        let _g = lock().lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_TEST_SOURCE_Y", " Regtest ");
        assert_eq!(
            Source::from_env("IRIUM_TEST_SOURCE_Y").unwrap(),
            Source::Regtest
        );
        std::env::set_var("IRIUM_TEST_SOURCE_Y", "MAINNET");
        assert_eq!(
            Source::from_env("IRIUM_TEST_SOURCE_Y").unwrap(),
            Source::Mainnet
        );
        std::env::remove_var("IRIUM_TEST_SOURCE_Y");
    }

    #[test]
    fn source_from_env_rejects_unknown_value() {
        let _env = crate::test_env::guard();
        let _g = lock().lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_TEST_SOURCE_Z", "garbage");
        assert!(Source::from_env("IRIUM_TEST_SOURCE_Z").is_err());
        std::env::remove_var("IRIUM_TEST_SOURCE_Z");
    }

    #[test]
    fn env_u64_returns_default_when_unset() {
        let _env = crate::test_env::guard();
        let _g = lock().lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("IRIUM_TEST_NUM_X");
        assert_eq!(env_u64("IRIUM_TEST_NUM_X", 42), 42);
    }

    #[test]
    fn env_u64_parses_when_set() {
        let _env = crate::test_env::guard();
        let _g = lock().lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("IRIUM_TEST_NUM_Y", "100");
        assert_eq!(env_u64("IRIUM_TEST_NUM_Y", 1), 100);
        std::env::remove_var("IRIUM_TEST_NUM_Y");
    }
}
