//! SSE subscriber for iriumd's `/events` endpoint.
//!
//! Listens for `block.new` events and notifies a `tokio::sync::Notify` so the
//! template loop can immediately fetch a fresh template and broadcast a new
//! job to connected miners — eliminating the polling lag between iriumd
//! accepting a new tip and the pool's stratum advertising the next job.
//!
//! On connection failure the subscriber reconnects with exponential backoff
//! (capped at 30s). The polling-based template loop continues to run in
//! parallel as a fallback if the SSE stream stays disconnected.

use anyhow::{anyhow, Result};
use reqwest::Client;
use std::sync::Arc;
use tokio::sync::Notify;
use tokio::time::{sleep, Duration};
use tracing::{info, warn};

/// Long-lived task: maintain an SSE connection to iriumd and translate
/// every `block.new` event into a one-shot wake on `notify`. Returns only
/// if the client cannot be built; otherwise loops forever, reconnecting
/// on any error.
pub async fn subscribe_block_new(
    rpc_base: String,
    rpc_token: String,
    notify: Arc<Notify>,
) {
    let client = match Client::builder()
        .http1_only()
        .connect_timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("[sse] could not build client: {e}");
            return;
        }
    };

    let url = format!("{}/events", rpc_base.trim_end_matches('/'));
    let mut backoff_ms = 500u64;

    loop {
        match stream_events(&client, &url, &rpc_token, &notify).await {
            Ok(()) => {
                info!("[sse] stream ended cleanly; reconnecting");
                backoff_ms = 500;
            }
            Err(e) => {
                warn!("[sse] stream error: {e}; reconnecting in {backoff_ms}ms");
                sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = backoff_ms.saturating_mul(2).min(30_000);
            }
        }
    }
}

async fn stream_events(
    client: &Client,
    url: &str,
    token: &str,
    notify: &Arc<Notify>,
) -> Result<()> {
    let mut resp = client
        .get(url)
        .bearer_auth(token)
        .header("Accept", "text/event-stream")
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(anyhow!("SSE connect status {}", resp.status()));
    }

    info!("[sse] connected to {url}; listening for block.new events");

    let mut buf = String::new();
    while let Some(chunk) = resp.chunk().await? {
        buf.push_str(&String::from_utf8_lossy(&chunk));
        // SSE frames are delimited by a blank line ("\n\n"). Each frame has
        // one or more "data: <json>" lines (and optional "event:" / "id:" /
        // ":" comments which we ignore). Iriumd emits a single data line
        // per event.
        while let Some(idx) = buf.find("\n\n") {
            let frame: String = buf.drain(..idx + 2).collect();
            for line in frame.lines() {
                let payload = line.strip_prefix("data:").map(|s| s.trim_start());
                if let Some(p) = payload {
                    let p = p.trim();
                    if p.is_empty() {
                        continue;
                    }
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(p) {
                        let et = val.get("type").and_then(|t| t.as_str()).unwrap_or("");
                        if et == "block.new" {
                            info!("[sse] block.new event → notifying template refresh");
                            notify.notify_one();
                        }
                    }
                }
            }
        }
    }
    Ok(())
}
