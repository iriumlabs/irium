
use anyhow::Result;
use sqlx::{PgPool, Row};

/// Returns (synced_height, synced_block_hash).
/// synced_height = -1 means nothing indexed yet.
pub async fn get_indexer_state(pool: &PgPool) -> Result<(i64, String)> {
    let row = sqlx::query(
        "SELECT synced_height, synced_block_hash FROM indexer_state WHERE id = 1"
    )
    .fetch_one(pool)
    .await?;
    Ok((row.get("synced_height"), row.get("synced_block_hash")))
}

/// Returns the canonical hashes currently indexed in an inclusive height range.
pub async fn get_block_hashes(
    pool: &PgPool,
    from_height: i64,
    to_height: i64,
) -> Result<Vec<(i64, String)>> {
    let rows = sqlx::query(
        "SELECT height, hash FROM blocks WHERE height BETWEEN $1 AND $2 ORDER BY height",
    )
    .bind(from_height)
    .bind(to_height)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| (row.get("height"), row.get("hash")))
        .collect())
}
