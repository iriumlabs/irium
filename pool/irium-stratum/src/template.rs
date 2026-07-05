use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use serde::Deserialize;
use tokio::time::{sleep, Duration};
use tracing::debug;

#[derive(Debug, Clone, Deserialize)]
pub struct TemplateTx {
    pub hex: String,
}

/// v1.9.62 issue #60: zero-value coinbase output the stratum appends post
/// activation height. value is always 0; script is the encoded
/// BtcHeaderBatch / LtcHeaderBatch / DogeHeaderBatch payload.
#[derive(Debug, Clone, Deserialize)]
pub struct CoinbaseExtraOutput {
    pub value: u64,
    pub script_pubkey_hex: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GetBlockTemplate {
    pub height: u64,
    pub prev_hash: String,
    pub bits: String,
    pub target: String,
    pub time: u32,
    #[serde(default)]
    pub txs: Vec<TemplateTx>,
    pub coinbase_value: u64,
    /// v1.9.62 issue #60. `#[serde(default)]` so an iriumd that doesn't
    /// emit the field (e.g. pre-v1.9.62 or running with the cache empty)
    /// still produces a valid template.
    #[serde(default)]
    pub coinbase_extra_outputs: Vec<CoinbaseExtraOutput>,
    /// Phase 10-D: PoAW-X mode string ("active" or "").
    #[serde(default)]
    pub poawx_mode: String,
    /// Phase 10-D: pending puzzle receipts from /poawx/receipt.
    #[serde(default)]
    pub poawx_pending_receipts: Vec<PoawxPendingReceipt>,
    #[serde(default)]
    pub poawx_reg_activations: Vec<String>,
    #[serde(default)]
    pub poawx_reg_announces: Vec<String>,
    /// Phase 10-D: hex receipts_root computed by iriumd.
    #[serde(default)]
    pub receipts_root: String,
}

/// Phase 10-D: per-worker puzzle receipt as stored in iriumd pending list.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PoawxPendingReceipt {
    pub height: u64,
    pub lane: String,
    pub worker_pkh: String,
    pub solution: String,
    pub commitment_nonce: String,
    #[serde(default)]
    pub worker_pubkey: String,
    #[serde(default)]
    pub worker_sig: String,
    /// Phase 18B: hex of the canonical 226-byte `Delegation` for a mode-1
    /// (delegated) receipt. Empty => mode-0 (direct). `skip_serializing_if`
    /// keeps mode-0 submit JSON byte-identical.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub delegation: String,
    /// Phase 20: hex of the canonical `Phase20ReceiptExt` for a production block
    /// after activation. Empty => no extension (pre-activation / legacy), which
    /// keeps the submit JSON byte-identical to Phase 18/19. Matches the node's
    /// `PoawxPendingReceipt.phase20_ext` field so the node round-trips it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub phase20_ext: String,
}

/// Phase 18B: response of the node's `GET /poawx/assignment`. The pool uses this
/// as the single source of truth for the deterministic per-block puzzle context
/// (the node derives it exactly as consensus expects).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PoawxAssignment {
    /// Current chain tip height. The next block (the one being mined) is
    /// `height + 1`, which is the height a produced receipt must carry.
    pub height: u64,
    pub seed: String,
    pub commitment_nonce: String,
    pub puzzle_difficulty: u32,
    pub lane: String,
}

#[derive(Clone)]
pub struct TemplateClient {
    pub client: Client,
    pub base: String,
    pub token: String,
}

impl TemplateClient {
    pub fn new(base: String, token: String) -> Result<Self> {
        // Single global client reused for all template requests.
        let client = Client::builder()
            .http1_only()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| anyhow!("client build: {e}"))?;
        Ok(Self {
            client,
            base,
            token,
        })
    }

    async fn fetch_once(&self) -> Result<GetBlockTemplate> {
        let url = format!("{}/rpc/getblocktemplate", self.base.trim_end_matches('/'));
        let resp = self
            .client
            .get(url)
            .bearer_auth(&self.token)
            .send()
            .await
            .context("send request")?;

        if !resp.status().is_success() {
            return Err(anyhow!("template status {}", resp.status()));
        }

        let tpl = resp
            .json::<GetBlockTemplate>()
            .await
            .context("decode template json")?;

        Ok(tpl)
    }

    pub async fn fetch_template(&self) -> Result<GetBlockTemplate> {
        let backoffs_ms = [200u64, 400u64, 800u64];
        let mut last_err: Option<anyhow::Error> = None;

        for (attempt, backoff) in backoffs_ms.iter().enumerate() {
            match self.fetch_once().await {
                Ok(tpl) => return Ok(tpl),
                Err(e) => {
                    last_err = Some(e.context(format!("attempt {}", attempt + 1)));
                    if attempt + 1 < backoffs_ms.len() {
                        if let Some(err) = &last_err {
                            debug!(
                                "[tmpl] transient fetch error (attempt {}): {:#}",
                                attempt + 1,
                                err
                            );
                        }
                        sleep(Duration::from_millis(*backoff)).await;
                    }
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow!("template fetch failed after retries")))
    }
}
