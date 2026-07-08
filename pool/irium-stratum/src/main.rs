mod block;
mod events;
mod pow;
mod stratum;
mod template;

use anyhow::{anyhow, Result};
use std::env;
use stratum::{run, AdapterMode, HashCmpMode, MinerFamilyMode, StratumConfig};
use tracing::warn;
use tracing_subscriber::EnvFilter;

fn env_required(key: &str) -> Result<String> {
    env::var(key).map_err(|_| anyhow!("missing env {key}"))
}

#[tokio::main]
async fn main() -> Result<()> {
    let log_level = env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string());
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(log_level))
        .with_target(false)
        .compact()
        .init();

    let bind = env::var("STRATUM_BIND").unwrap_or_else(|_| "0.0.0.0:3333".to_string());
    let default_diff_raw = env::var("STRATUM_DEFAULT_DIFF")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(16.0);
    let default_diff = default_diff_raw.max(1.0);
    let extranonce1_size = env::var("STRATUM_EXTRANONCE1_SIZE")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(4);
    let refresh_ms = env::var("TEMPLATE_REFRESH_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(1000);

    let metrics_bind = Some(
        env::var("STRATUM_METRICS_BIND")
            .ok()
            .filter(|v| {
                let t = v.trim();
                t.starts_with("127.0.0.1:") || t.starts_with("localhost:") || t.starts_with("[::1]:")
            })
            .unwrap_or_else(|| "127.0.0.1:3334".to_string())
    );

    let max_template_age_seconds = env::var("IRIUM_TEMPLATE_MAX_AGE_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(60);

    let pow_limit = env::var("IRIUM_POW_LIMIT_HEX")
        .ok()
        .and_then(|v| pow::parse_pow_limit_hex(&v))
        .unwrap_or_else(pow::default_pow_limit);

    let hash_cmp_mode = HashCmpMode::from_env(env::var("IRIUM_HASH_CMP_MODE").ok());

    let soft_accept_invalid_shares = env::var("IRIUM_STRATUM_SOFT_ACCEPT_INVALID_SHARES")
        .ok()
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(true);

    let miner_family_mode = MinerFamilyMode::from_env(env::var("IRIUM_STRATUM_MINER_FAMILY").ok());
    let adapter_mode = AdapterMode::from_env(env::var("IRIUM_STRATUM_ADAPTER_MODE").ok());
    let native_rewardable_enabled = env::var("IRIUM_STRATUM_NATIVE_REWARDABLE_ENABLED")
        .ok()
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);

    let sharecheck_samples = env::var("IRIUM_STRATUM_SHARECHECK_SAMPLES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(3);

    let vardiff_enabled = env::var("IRIUM_STRATUM_VARDIFF_ENABLED")
        .ok()
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(true);

    let vardiff_min_diff_raw = env::var("IRIUM_STRATUM_VARDIFF_MIN_DIFF")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(1.0);
    let vardiff_min_diff = vardiff_min_diff_raw.max(1.0);

    let vardiff_max_diff_raw = env::var("IRIUM_STRATUM_VARDIFF_MAX_DIFF")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(1024.0);
    let vardiff_max_diff = vardiff_max_diff_raw.max(vardiff_min_diff);

    let vardiff_target_share_secs = env::var("IRIUM_STRATUM_VARDIFF_TARGET_SHARE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(15);

    let vardiff_retarget_secs = env::var("IRIUM_STRATUM_VARDIFF_RETARGET_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(30);

    let coinbase_bip34 = env::var("IRIUM_STRATUM_COINBASE_BIP34")
        .ok()
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(true);

    let found_blocks_file = env::var("IRIUM_STRATUM_FOUND_BLOCKS_FILE")
        .unwrap_or_else(|_| "/opt/irium-pool/data/found_blocks.jsonl".to_string());

    let keepalive_notify_secs = env::var("IRIUM_STRATUM_KEEPALIVE_NOTIFY_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(120);

    let auxpow_activation_height = env::var("IRIUM_AUXPOW_ACTIVATION_HEIGHT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok());

    // v1.9.23 — connection-gate knobs. All optional; passing 0 disables
    // the corresponding limiter so operators can soft-launch on a per-pool
    // basis. The /etc/irium-pool/stratum*.env files are expected to set
    // these for the production deployment (the legacy CPU/GPU pool gets a
    // tighter cap than the ASIC pool by convention).
    let max_sessions = env::var("IRIUM_STRATUM_MAX_SESSIONS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(1000);
    let max_conn_per_ip = env::var("IRIUM_STRATUM_MAX_CONN_PER_IP")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(10);
    let conn_window_secs = env::var("IRIUM_STRATUM_CONN_WINDOW_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(60);
    let ban_threshold = env::var("IRIUM_STRATUM_BAN_THRESHOLD")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(5);
    // Default reduced from 3600s (1h) to 300s (5min): the rate-limit-then-ban
    // loop is meant to slow down obviously-bad reconnect spam, not punish
    // legitimate workers for transient flakiness. 5min is enough to defang
    // a runaway reconnect loop while letting genuine miners recover quickly.
    // Operators can still override via IRIUM_STRATUM_BAN_DURATION_SECS env var.
    let ban_duration_secs = env::var("IRIUM_STRATUM_BAN_DURATION_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(300);

    if default_diff_raw < 1.0 {
        warn!(
            "[config] STRATUM_DEFAULT_DIFF={} below diff1; clamped to 1",
            default_diff_raw
        );
    }
    if vardiff_min_diff_raw < 1.0 {
        warn!(
            "[config] IRIUM_STRATUM_VARDIFF_MIN_DIFF={} below diff1; clamped to 1",
            vardiff_min_diff_raw
        );
    }
    if vardiff_max_diff_raw < vardiff_min_diff {
        warn!(
            "[config] IRIUM_STRATUM_VARDIFF_MAX_DIFF={} below min {}; clamped",
            vardiff_max_diff_raw,
            vardiff_min_diff
        );
    }

    let cfg = StratumConfig {
        bind,
        metrics_bind,
        default_diff,
        extranonce1_size,
        refresh_ms,
        rpc_base: env_required("IRIUM_RPC_BASE")?,
        rpc_token: env_required("IRIUM_RPC_TOKEN")?,
        pow_limit,
        hash_cmp_mode,
        soft_accept_invalid_shares,
        miner_family_mode,
        adapter_mode,
        native_rewardable_enabled,
        sharecheck_samples,
        vardiff_enabled,
        vardiff_min_diff,
        vardiff_max_diff,
        vardiff_target_share_secs,
        vardiff_retarget_secs,
        max_template_age_seconds,
        coinbase_bip34,
        found_blocks_file,
        keepalive_notify_secs,
        auxpow_activation_height,
        max_sessions,
        max_conn_per_ip,
        conn_window_secs,
        ban_threshold,
        ban_duration_secs,
    };

    run(cfg).await
}
