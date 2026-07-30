use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize, Default, Clone)]
pub struct StratumMetrics {
    pub accepted_shares:        u64,
    pub rejected_shares:        u64,
    pub active_tcp_sessions:    u64,
    pub submit_accepted:        u64,
    pub submit_rejected:        u64,
    pub last_share_accepted_at: u64,
    #[serde(default)]
    pub global_reject_reasons:  HashMap<String, u64>,
    #[serde(default)]
    pub miners:                 HashMap<String, WorkerMetrics>,
}

#[derive(Deserialize, Default, Clone)]
pub struct WorkerMetrics {
    pub accepted:       u64,
    pub rejected:       u64,
    pub current_diff:   f64,
    pub last_share_at:  u64,
    #[serde(default)]
    pub reject_reasons: HashMap<String, u64>,
}

#[derive(Deserialize, Default, Clone)]
pub struct NodeStatus {
    pub height:           u64,
    pub peer_count:       u64,
    #[serde(default)]
    pub best_header_tip:  BestHeaderTip,
    #[serde(default)]
    pub persisted_height: u64,
}

#[derive(Deserialize, Default, Clone)]
pub struct BestHeaderTip {
    pub height: u64,
    #[serde(default)]
    pub hash: String,
}

#[derive(Deserialize, Default, Clone)]
pub struct MiningMetrics {
    pub difficulty:     f64,
    pub hashrate:       f64,
    pub avg_block_time: f64,
    pub tip_height:     u64,
    #[serde(default)]
    pub tip_time:       u64,
}

#[derive(Deserialize, Default, Clone)]
pub struct RelayTip {
    pub active:        bool,
    #[serde(default)]
    pub tip_height:    u64,
    #[serde(default)]
    pub tip_hash:      String,
    #[serde(default)]
    pub tip_time:      u64,
    #[serde(default)]
    pub anchor_height: u64,
}

#[derive(Deserialize, Clone)]
pub struct ExplorerBlock {
    pub height:        u64,
    #[serde(default)]
    pub miner_address: String,
    pub header:        ExplorerHeader,
    /// The block's actual coinbase split. Since the PoAW-X combined activation at 61,414 a
    /// coinbase pays FOUR role payees (55/22/13/10), so the finder does NOT receive the whole
    /// subsidy -- the primary share is 27.5 IRM, not 50. Empty on pre-activation blocks and on
    /// any node too old to report it, which is why the caller falls back to the flat subsidy.
    #[serde(default)]
    pub coinbase_payees: Vec<ExplorerPayee>,
}

/// One coinbase payout as the explorer reports it.
#[derive(Deserialize, Default, Clone)]
pub struct ExplorerPayee {
    #[serde(default)]
    pub address:    String,
    #[serde(default)]
    pub amount_irm: f64,
}

impl ExplorerBlock {
    /// What `miner_address` ACTUALLY received in this block, in sats.
    ///
    /// The recorded figure was a hardcoded 5_000_000_000 (50 IRM) for every block, which after
    /// activation overstates the finder's take by 82% (27.5 IRM paid vs 50 recorded) and makes
    /// any share-proportional payout computed from it overpay by the same factor. Sum the
    /// payees actually addressed to the finder instead; a payee may legitimately appear more
    /// than once when one identity holds several roles, so add them all up rather than taking
    /// the first match.
    ///
    /// Falls back to the flat subsidy only when the node reported no payee breakdown at all,
    /// which keeps pre-activation history unchanged.
    pub fn miner_reward_sats(&self) -> u64 {
        if self.coinbase_payees.is_empty() {
            return 5_000_000_000;
        }
        let irm: f64 = self
            .coinbase_payees
            .iter()
            .filter(|p| p.address == self.miner_address)
            .map(|p| p.amount_irm)
            .sum();
        (irm * 1e8).round().max(0.0) as u64
    }
}

#[derive(Deserialize, Default, Clone)]
pub struct ExplorerHeader {
    pub time: u64,
    #[serde(default)]
    pub hash: String,
    #[serde(default)]
    pub bits: String,
}

#[derive(Deserialize, Default, Clone)]
pub struct ExplorerBlocksResponse {
    pub blocks: Vec<ExplorerBlock>,
    #[serde(default)]
    pub total_blocks: u64,
}

#[derive(Deserialize, Default, Clone)]
pub struct ExplorerAddress {
    #[serde(default)]
    pub balance: AddressBalance,
}

#[derive(Deserialize, Default, Clone)]
pub struct AddressBalance {
    pub mined_blocks:  u64,
    pub mined_balance: u64,
    pub balance:       u64,
}

async fn fetch_json<T: for<'de> Deserialize<'de>>(
    client: &Client,
    url: &str,
    token: Option<&str>,
) -> Option<T> {
    let mut req = client.get(url);
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    req.send().await.ok()?.json().await.ok()
}

pub async fn get_stratum(client: &Client, url: &str) -> StratumMetrics {
    fetch_json::<StratumMetrics>(client, url, None)
        .await
        .unwrap_or_default()
}

pub async fn get_node_status(client: &Client, base: &str) -> NodeStatus {
    let url = format!("{}/status", base);
    fetch_json::<NodeStatus>(client, &url, None)
        .await
        .unwrap_or_default()
}

pub async fn get_mining_metrics(client: &Client, base: &str, token: &str) -> MiningMetrics {
    let url = format!("{}/rpc/mining_metrics", base);
    fetch_json::<MiningMetrics>(client, &url, Some(token))
        .await
        .unwrap_or_default()
}

pub async fn get_btc_relay(client: &Client, base: &str, token: &str) -> RelayTip {
    let url = format!("{}/rpc/btcrelaytip", base);
    fetch_json::<RelayTip>(client, &url, Some(token))
        .await
        .unwrap_or_default()
}

pub async fn get_ltc_relay(client: &Client, base: &str, token: &str) -> RelayTip {
    let url = format!("{}/rpc/ltcrelaytip", base);
    fetch_json::<RelayTip>(client, &url, Some(token))
        .await
        .unwrap_or_default()
}

pub async fn get_explorer_blocks(client: &Client, base: &str, limit: u64) -> Vec<ExplorerBlock> {
    let url = format!("{}/api/blocks?limit={}", base, limit);
    fetch_json::<ExplorerBlocksResponse>(client, &url, None)
        .await
        .unwrap_or_default()
        .blocks
}

pub async fn get_address_info(client: &Client, base: &str, address: &str) -> ExplorerAddress {
    let url = format!("{}/api/address/{}", base, address);
    fetch_json::<ExplorerAddress>(client, &url, None)
        .await
        .unwrap_or_default()
}

pub async fn check_reachable(client: &Client, url: &str, token: Option<&str>) -> bool {
    let mut req = client.get(url);
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    req.send().await
        .map(|r| r.status().as_u16() < 500)
        .unwrap_or(false)
}

#[cfg(test)]
mod reward_tests {
    use super::*;

    fn blk(miner: &str, payees: &[(&str, f64)]) -> ExplorerBlock {
        ExplorerBlock {
            height: 64_600,
            miner_address: miner.to_string(),
            header: ExplorerHeader::default(),
            coinbase_payees: payees
                .iter()
                .map(|(a, v)| ExplorerPayee { address: a.to_string(), amount_irm: *v })
                .collect(),
        }
    }

    #[test]
    fn records_the_finders_actual_share_not_the_flat_subsidy() {
        // The live 55/22/13/10 split: the finder takes 27.5 IRM, not 50.
        let b = blk("QF3", &[("QF3", 27.5), ("PzP", 11.0), ("PzP", 6.5), ("PzP", 5.0)]);
        assert_eq!(b.miner_reward_sats(), 2_750_000_000);
        assert_ne!(b.miner_reward_sats(), 5_000_000_000, "the old hardcode overstated by 82%");
    }

    #[test]
    fn sums_every_share_when_one_identity_holds_several_roles() {
        // Self-fill: the producer takes all four slices. Taking only the first match would
        // under-record it by 22.5 IRM.
        let b = blk("QF3", &[("QF3", 27.5), ("QF3", 11.0), ("QF3", 6.5), ("QF3", 5.0)]);
        assert_eq!(b.miner_reward_sats(), 5_000_000_000);
    }

    #[test]
    fn records_zero_when_the_finder_is_paid_nothing() {
        // Exactly today's pool case: the coinbase pays the node's keys, the pool address gets
        // nothing. Recording 50 IRM here is what made the pool look paid when it was not.
        let b = blk("POOL", &[("QF3", 27.5), ("PzP", 11.0), ("PzP", 6.5), ("PzP", 5.0)]);
        assert_eq!(b.miner_reward_sats(), 0);
    }

    #[test]
    fn falls_back_to_the_flat_subsidy_when_no_breakdown_is_reported() {
        // Pre-activation history and older nodes report no payees; leave those untouched.
        let b = blk("QF3", &[]);
        assert_eq!(b.miner_reward_sats(), 5_000_000_000);
    }
}
