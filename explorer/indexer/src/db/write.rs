
use anyhow::Result;
use sqlx::{PgPool, Postgres, Transaction};
use chrono::{DateTime, Utc};
use crate::decoder::{
    script::{classify_script, ScriptClass},
    tx::{decode_tx, TxInput, TxOutput},
};
use crate::rpc::RpcBlock;

/// PostgreSQL TEXT columns reject null bytes. Strip them before Postgres insertion.
#[inline]
fn clean(s: &str) -> String {
    if s.contains('\0') { s.replace('\0', "") } else { s.to_owned() }
}
#[inline]
fn clean_opt(s: Option<&str>) -> Option<String> {
    s.map(|v| if v.contains('\0') { v.replace('\0', "") } else { v.to_owned() })
}

// ─── Top-level entry point ─────────────────────────────────────────────────

pub async fn index_block(pool: &PgPool, block: &RpcBlock) -> Result<()> {
    let mut dbtx = pool.begin().await?;
    let timestamp: DateTime<Utc> = DateTime::from_timestamp(block.header.time, 0)
        .unwrap_or_default();

    let parsed_txs: Vec<_> = block.tx_hex.iter().enumerate()
        .map(|(i, hex)| {
            let tx = decode_tx(hex)?;
            Ok((i, tx))
        })
        .collect::<Result<Vec<_>>>()?;

    let total_reward: i64 = parsed_txs.get(0)
        .map(|(_, t)| t.outputs.iter().map(|o| o.value).sum())
        .unwrap_or(0);

    let coinbase_tag: Option<String> = parsed_txs.get(0)
        .and_then(|(_, t)| t.inputs.first())
        .and_then(|inp| extract_coinbase_tag(&inp.script_sig));

    // The node's convenience `miner_address` field is absent for some historical
    // block formats. The first positive-value address output is the canonical
    // primary/proposer payee (newer receipts place a zero-value commitment first),
    // so derive it from the transaction and use RPC only as a fallback.
    let decoded_miner_address: Option<String> = parsed_txs.first()
        .and_then(|(_, tx)| primary_payee_address(&tx.outputs));
    let miner_address = decoded_miner_address.as_deref().or(block.miner_address.as_deref());

    // Upsert block
    sqlx::query(
        "INSERT INTO blocks \
         (height,hash,prev_hash,merkle_root,timestamp,difficulty,nonce,tx_count,total_reward,miner_address,size_bytes,coinbase_tag) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) \
         ON CONFLICT (height) DO NOTHING"
    )
    .bind(block.height)
    .bind(&block.header.hash)
    .bind(&block.header.prev_hash)
    .bind(&block.header.merkle_root)
    .bind(timestamp)
    .bind(&block.header.bits)
    .bind(block.header.nonce.to_string())
    .bind(parsed_txs.len() as i32)
    .bind(total_reward)
    .bind(miner_address)
    .bind(0i32)
    .bind(clean_opt(coinbase_tag.as_deref()))
    .execute(&mut *dbtx)
    .await?;

    for (tx_index, parsed) in &parsed_txs {
        let is_coinbase = parsed.inputs.first().map(|i| i.is_coinbase()).unwrap_or(false);
        let total_out: i64 = parsed.outputs.iter().map(|o| o.value).sum();

        sqlx::query(
            "INSERT INTO txs \
             (txid,block_height,block_hash,tx_index,version,locktime,is_coinbase,input_count,output_count,total_out,fee) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) \
             ON CONFLICT (txid) DO NOTHING"
        )
        .bind(&parsed.txid)
        .bind(block.height)
        .bind(&block.header.hash)
        .bind(*tx_index as i32)
        .bind(parsed.version)
        .bind(parsed.locktime as i32)
        .bind(is_coinbase)
        .bind(parsed.inputs.len() as i32)
        .bind(parsed.outputs.len() as i32)
        .bind(total_out)
        .bind(0i64)
        .execute(&mut *dbtx)
        .await?;

        for (vin_idx, inp) in parsed.inputs.iter().enumerate() {
            insert_input(&mut dbtx, &parsed.txid, vin_idx, inp, is_coinbase).await?;
        }
        for (vout_idx, out) in parsed.outputs.iter().enumerate() {
            insert_output(&mut dbtx, &parsed.txid, vout_idx, out, block.height).await?;
        }
        if !is_coinbase {
            for inp in &parsed.inputs {
                mark_output_spent(&mut dbtx, &inp.prev_txid, inp.prev_vout, &parsed.txid).await?;
            }
        }
    }

    if let Some(miner) = miner_address {
        upsert_miner(&mut dbtx, miner, total_reward, block.height, &block.header.hash).await?;
    }

    sqlx::query(
        "UPDATE indexer_state SET synced_height=$1, synced_block_hash=$2, last_updated_at=NOW() WHERE id=1"
    )
    .bind(block.height)
    .bind(&block.header.hash)
    .execute(&mut *dbtx)
    .await?;

    dbtx.commit().await?;
    Ok(())
}

// ─── Helpers ──────────────────────────────────────────────────────────────

async fn insert_input(
    dbtx: &mut Transaction<'_, Postgres>,
    txid: &str,
    vin_idx: usize,
    inp: &TxInput,
    is_coinbase: bool,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO tx_inputs (txid,vin_index,prev_txid,prev_vout,script_sig_hex,sequence,is_coinbase) \
         VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING"
    )
    .bind(txid)
    .bind(vin_idx as i32)
    .bind(&inp.prev_txid)
    .bind(inp.prev_vout as i64)
    .bind(hex::encode(&inp.script_sig))
    .bind(inp.sequence as i64)
    .bind(is_coinbase)
    .execute(&mut **dbtx)
    .await?;
    Ok(())
}

async fn insert_output(
    dbtx: &mut Transaction<'_, Postgres>,
    txid: &str,
    vout_idx: usize,
    out: &TxOutput,
    block_height: i64,
) -> Result<()> {
    let class = classify_script(&out.script_pubkey, out.value);

    let script_type: &str;
    let address: Option<String>;
    let is_htlc: bool;
    let htlc_variant: Option<String>;
    let timeout_height: Option<i64>;
    let secret_hash: Option<String>;
    let recipient_addr: Option<String>;
    let refund_addr: Option<String>;

    match &class {
        ScriptClass::P2Pkh { address: addr, .. } => {
            script_type = "p2pkh";
            address = Some(addr.clone());
            is_htlc = false;
            htlc_variant = None; timeout_height = None;
            secret_hash = None; recipient_addr = None; refund_addr = None;
        }
        ScriptClass::Htlc(p) => {
            script_type = "htlc";
            address = Some(p.recipient_addr.clone());
            is_htlc = true;
            htlc_variant = Some(p.variant.as_str().to_string());
            timeout_height = Some(p.timeout_height as i64);
            secret_hash = Some(hex::encode(p.secret_hash));
            recipient_addr = Some(p.recipient_addr.clone());
            refund_addr = Some(p.refund_addr.clone());
        }
        ScriptClass::OpReturn { .. } => {
            script_type = "op_return";
            address = None; is_htlc = false;
            htlc_variant = None; timeout_height = None;
            secret_hash = None; recipient_addr = None; refund_addr = None;
        }
        ScriptClass::IriumData => {
            script_type = "irium_data";
            address = None; is_htlc = false;
            htlc_variant = None; timeout_height = None;
            secret_hash = None; recipient_addr = None; refund_addr = None;
        }
        ScriptClass::Unknown => {
            script_type = "unknown";
            address = None; is_htlc = false;
            htlc_variant = None; timeout_height = None;
            secret_hash = None; recipient_addr = None; refund_addr = None;
        }
    }

    sqlx::query(
        "INSERT INTO tx_outputs (txid,vout,value,script_hex,script_type,address) \
         VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (txid,vout) DO NOTHING"
    )
    .bind(txid)
    .bind(vout_idx as i32)
    .bind(out.value)
    .bind(hex::encode(&out.script_pubkey))
    .bind(script_type)
    .bind(address.as_deref())
    .execute(&mut **dbtx)
    .await?;

    if let Some(addr) = &address {
        sqlx::query(
            "INSERT INTO address_stats (address,balance,total_received,tx_count,first_seen_height,last_seen_height) \
             VALUES ($1,$2,$2,1,$3,$3) \
             ON CONFLICT (address) DO UPDATE SET \
               balance          = address_stats.balance + EXCLUDED.balance, \
               total_received   = address_stats.total_received + EXCLUDED.total_received, \
               tx_count         = address_stats.tx_count + 1, \
               last_seen_height = GREATEST(address_stats.last_seen_height, EXCLUDED.last_seen_height)"
        )
        .bind(addr)
        .bind(out.value)
        .bind(block_height)
        .execute(&mut **dbtx)
        .await?;
    }

    if is_htlc {
        sqlx::query(
            "INSERT INTO htlc_outputs \
             (txid,vout,block_height,htlc_type,value,recipient_addr,refund_addr,secret_hash,timeout_height) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (txid,vout) DO NOTHING"
        )
        .bind(txid)
        .bind(vout_idx as i32)
        .bind(block_height)
        .bind(htlc_variant.as_deref().unwrap_or(""))
        .bind(out.value)
        .bind(recipient_addr.as_deref().unwrap_or(""))
        .bind(refund_addr.as_deref().unwrap_or(""))
        .bind(secret_hash.as_deref().unwrap_or(""))
        .bind(timeout_height.unwrap_or(0))
        .execute(&mut **dbtx)
        .await?;
    }

    if let ScriptClass::OpReturn { anchor: Some(anch), .. } = &class {
        sqlx::query(
            "INSERT INTO agreements (agreement_hash,anchor_type,txid,block_height,milestone_id) \
             VALUES ($1,$2,$3,$4,$5) \
             ON CONFLICT (agreement_hash) DO UPDATE SET \
               anchor_type=$2, txid=$3, block_height=$4, milestone_id=$5"
        )
        .bind(&anch.agreement_hash)
        .bind(anch.anchor_type.as_str())
        .bind(txid)
        .bind(block_height)
        .bind(clean_opt(anch.milestone_id.as_deref()))
        .execute(&mut **dbtx)
        .await?;
    }

    Ok(())
}

async fn mark_output_spent(
    dbtx: &mut Transaction<'_, Postgres>,
    prev_txid: &str,
    prev_vout: u32,
    spending_txid: &str,
) -> Result<()> {
    sqlx::query(
        "UPDATE address_stats SET \
           balance    = address_stats.balance - COALESCE(o.value, 0), \
           total_sent = address_stats.total_sent + COALESCE(o.value, 0) \
         FROM tx_outputs o \
         WHERE o.txid=$1 AND o.vout=$2 AND address_stats.address=o.address"
    )
    .bind(prev_txid)
    .bind(prev_vout as i32)
    .execute(&mut **dbtx)
    .await?;

    sqlx::query("UPDATE tx_outputs SET spent_by_txid=$3 WHERE txid=$1 AND vout=$2")
        .bind(prev_txid).bind(prev_vout as i32).bind(spending_txid)
        .execute(&mut **dbtx).await?;

    sqlx::query("UPDATE htlc_outputs SET state='claimed', spend_txid=$3 WHERE txid=$1 AND vout=$2")
        .bind(prev_txid).bind(prev_vout as i32).bind(spending_txid)
        .execute(&mut **dbtx).await?;

    Ok(())
}

async fn upsert_miner(
    dbtx: &mut Transaction<'_, Postgres>,
    address: &str,
    reward: i64,
    block_height: i64,
    block_hash: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO mining_leaderboard (address,blocks_mined,total_reward,last_block_height,last_block_hash) \
         VALUES ($1,1,$2,$3,$4) \
         ON CONFLICT (address) DO UPDATE SET \
           blocks_mined      = mining_leaderboard.blocks_mined + 1, \
           total_reward      = mining_leaderboard.total_reward + EXCLUDED.total_reward, \
           last_block_height = GREATEST(mining_leaderboard.last_block_height, EXCLUDED.last_block_height), \
           last_block_hash   = CASE \
             WHEN mining_leaderboard.last_block_height < EXCLUDED.last_block_height \
             THEN EXCLUDED.last_block_hash \
             ELSE mining_leaderboard.last_block_hash \
           END"
    )
    .bind(address).bind(reward).bind(block_height).bind(block_hash)
    .execute(&mut **dbtx).await?;
    Ok(())
}

fn extract_coinbase_tag(script_sig: &[u8]) -> Option<String> {
    // Only works on ASCII text scriptSigs (solo miner format).
    // Pool BIP34 scriptSigs contain binary bytes that fail utf8 decode -> None.
    let text = std::str::from_utf8(script_sig).ok()?;
    // Strip trailing null bytes appended by stratum solo extranonce padding.
    let text = text.trim_end_matches('\0');

    // Text mode: "Block {height}/{tag}"
    if let Some(pos) = text.find('/') {
        let tag = &text[pos + 1..];
        if !tag.is_empty() && tag.len() <= 20 && tag.is_ascii() {
            let t = tag.replace('\0', "");
            if !t.is_empty() { return Some(t); }
        }
    }

    // Stratum solo mode: "Block {height} solo {tag} "
    if let Some(pos) = text.find(" solo ") {
        let after = text[pos + 6..].trim_end();
        if !after.is_empty() && after.len() <= 20 && after.is_ascii() {
            let t = after.replace('\0', "");
            if !t.is_empty() { return Some(t); }
        }
    }

    None
}

fn primary_payee_address(outputs: &[TxOutput]) -> Option<String> {
    outputs.iter().find_map(|output| {
        if output.value <= 0 { return None; }
        match classify_script(&output.script_pubkey, output.value) {
            ScriptClass::P2Pkh { address, .. } => Some(address),
            ScriptClass::Htlc(params) => Some(params.recipient_addr),
            _ => None,
        }
    })
}

pub async fn rollback_above(pool: &PgPool, reorg_height: i64) -> Result<()> {
    let mut dbtx = pool.begin().await?;

    // These tables do not have foreign keys to blocks/txs, so remove their
    // orphaned on-chain rows explicitly before deleting the forked blocks.
    sqlx::query("DELETE FROM proofs WHERE block_height > $1")
        .bind(reorg_height).execute(&mut *dbtx).await?;
    sqlx::query("DELETE FROM agreements WHERE block_height > $1")
        .bind(reorg_height).execute(&mut *dbtx).await?;
    sqlx::query("DELETE FROM htlc_outputs WHERE block_height > $1")
        .bind(reorg_height).execute(&mut *dbtx).await?;

    sqlx::query("DELETE FROM blocks WHERE height > $1")
        .bind(reorg_height).execute(&mut *dbtx).await?;

    // Spending references are intentionally denormalized and have no FK. A
    // reorg can remove their spending transaction while leaving the output.
    sqlx::query(
        "UPDATE tx_outputs o SET spent_by_txid=NULL, spent_by_vin=NULL \
         WHERE spent_by_txid IS NOT NULL \
           AND NOT EXISTS (SELECT 1 FROM txs t WHERE t.txid=o.spent_by_txid)"
    ).execute(&mut *dbtx).await?;
    sqlx::query(
        "UPDATE htlc_outputs h SET state='pending', spend_txid=NULL, spend_block_height=NULL \
         WHERE spend_txid IS NOT NULL \
           AND NOT EXISTS (SELECT 1 FROM txs t WHERE t.txid=h.spend_txid)"
    ).execute(&mut *dbtx).await?;

    // Recompute all incremental aggregates from the retained canonical rows.
    // This is deliberately comprehensive: subtracting only the removed fork's
    // visible rewards cannot repair repeated or previously partial rollbacks.
    sqlx::query("DELETE FROM address_stats")
        .execute(&mut *dbtx).await?;
    sqlx::query(
        "INSERT INTO address_stats \
         (address,balance,total_received,total_sent,tx_count,first_seen_height,last_seen_height) \
         SELECT o.address, \
                SUM(CASE WHEN o.spent_by_txid IS NULL THEN o.value ELSE 0 END), \
                SUM(o.value), \
                SUM(CASE WHEN o.spent_by_txid IS NOT NULL THEN o.value ELSE 0 END), \
                COUNT(*)::int, MIN(t.block_height), MAX(t.block_height) \
         FROM tx_outputs o JOIN txs t ON t.txid=o.txid \
         WHERE o.address IS NOT NULL GROUP BY o.address"
    ).execute(&mut *dbtx).await?;

    sqlx::query("DELETE FROM mining_leaderboard")
        .execute(&mut *dbtx).await?;
    sqlx::query(
        "INSERT INTO mining_leaderboard \
         (address,blocks_mined,total_reward,last_block_height,last_block_hash) \
         SELECT totals.address, totals.blocks_mined, totals.total_reward, \
                latest.height, latest.hash \
         FROM ( \
           SELECT miner_address AS address, COUNT(*)::int AS blocks_mined, \
                  SUM(total_reward) AS total_reward \
           FROM blocks WHERE miner_address IS NOT NULL GROUP BY miner_address \
         ) totals \
         JOIN LATERAL ( \
           SELECT height,hash FROM blocks \
           WHERE miner_address=totals.address ORDER BY height DESC LIMIT 1 \
         ) latest ON TRUE"
    ).execute(&mut *dbtx).await?;

    sqlx::query(
        "UPDATE indexer_state SET \
         synced_height=$1, \
         synced_block_hash=COALESCE((SELECT hash FROM blocks WHERE height=$1), ''), \
         last_updated_at=NOW() \
         WHERE id=1"
    )
        .bind(reorg_height).execute(&mut *dbtx).await?;
    dbtx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod rollback_tests {
    use super::{primary_payee_address, rollback_above};
    use crate::decoder::tx::TxOutput;
    use sqlx::{PgPool, Row};

    #[test]
    fn primary_payee_skips_zero_value_receipt_commitment() {
        let outputs = vec![
            TxOutput { value: 0, script_pubkey: vec![0x6a, 0x00] },
            TxOutput {
                value: 5_000_000_000,
                script_pubkey: hex::decode(
                    "76a914222a0b48f534f9e3ef98ee3261ef3f0a344cc41d88ac"
                ).unwrap(),
            },
        ];

        assert_eq!(
            primary_payee_address(&outputs).as_deref(),
            Some("PzP2TzB4Je6uu4uC7932s4RwCTwnidcBiX")
        );
    }

    #[tokio::test]
    async fn rollback_removes_fork_and_rebuilds_derived_state() -> anyhow::Result<()> {
        let Ok(url) = std::env::var("EXPLORER_TEST_DATABASE_URL") else {
            return Ok(());
        };
        let pool = PgPool::connect(&url).await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        sqlx::query(
            "TRUNCATE proofs,agreement_parties,agreements,htlc_outputs,tx_inputs,tx_outputs, \
             txs,blocks,address_stats,mining_leaderboard RESTART IDENTITY CASCADE"
        ).execute(&pool).await?;
        sqlx::query("UPDATE indexer_state SET synced_height=-1,synced_block_hash='' WHERE id=1")
            .execute(&pool).await?;

        for (height, hash, prev, miner) in [
            (0_i64, "h0", "genesis", "miner-a"),
            (1_i64, "fork-h1", "h0", "miner-b"),
        ] {
            sqlx::query(
                "INSERT INTO blocks \
                 (height,hash,prev_hash,merkle_root,timestamp,difficulty,nonce,tx_count, \
                  total_reward,miner_address,size_bytes) \
                 VALUES ($1,$2,$3,'m',NOW(),'d','0',1,5000,$4,0)"
            ).bind(height).bind(hash).bind(prev).bind(miner).execute(&pool).await?;
            let txid = format!("tx-{height}");
            sqlx::query(
                "INSERT INTO txs \
                 (txid,block_height,block_hash,tx_index,version,locktime,is_coinbase, \
                  input_count,output_count,total_out,fee) \
                 VALUES ($1,$2,$3,0,1,0,true,1,1,5000,0)"
            ).bind(&txid).bind(height).bind(hash).execute(&pool).await?;
            sqlx::query(
                "INSERT INTO tx_outputs (txid,vout,value,script_hex,script_type,address,spent_by_txid) \
                 VALUES ($1,0,5000,'','p2pkh','payee',$2)"
            ).bind(&txid).bind((height == 0).then_some("tx-1")).execute(&pool).await?;
        }
        sqlx::query(
            "INSERT INTO address_stats \
             (address,balance,total_received,total_sent,tx_count,first_seen_height,last_seen_height) \
             VALUES ('payee',999999,999999,0,99,0,99)"
        ).execute(&pool).await?;
        sqlx::query(
            "INSERT INTO mining_leaderboard \
             (address,blocks_mined,total_reward,last_block_height,last_block_hash) \
             VALUES ('miner-a',7,35000,1,'fork-h1')"
        ).execute(&pool).await?;
        sqlx::query(
            "UPDATE indexer_state SET synced_height=1,synced_block_hash='fork-h1' WHERE id=1"
        ).execute(&pool).await?;

        rollback_above(&pool, 0).await?;

        let block_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blocks")
            .fetch_one(&pool).await?;
        assert_eq!(block_count, 1);
        let output = sqlx::query(
            "SELECT spent_by_txid FROM tx_outputs WHERE txid='tx-0'"
        ).fetch_one(&pool).await?;
        assert!(output.get::<Option<String>, _>("spent_by_txid").is_none());
        let stats = sqlx::query(
            "SELECT balance,total_received,total_sent,tx_count,last_seen_height \
             FROM address_stats WHERE address='payee'"
        ).fetch_one(&pool).await?;
        assert_eq!(stats.get::<i64, _>("balance"), 5000);
        assert_eq!(stats.get::<i64, _>("total_received"), 5000);
        assert_eq!(stats.get::<i64, _>("total_sent"), 0);
        assert_eq!(stats.get::<i32, _>("tx_count"), 1);
        assert_eq!(stats.get::<i64, _>("last_seen_height"), 0);
        let miner = sqlx::query(
            "SELECT blocks_mined,total_reward,last_block_height,last_block_hash \
             FROM mining_leaderboard WHERE address='miner-a'"
        ).fetch_one(&pool).await?;
        assert_eq!(miner.get::<i32, _>("blocks_mined"), 1);
        assert_eq!(miner.get::<i64, _>("total_reward"), 5000);
        assert_eq!(miner.get::<i64, _>("last_block_height"), 0);
        assert_eq!(miner.get::<String, _>("last_block_hash"), "h0");
        Ok(())
    }
}
