
use axum::{extract::{Path, Query, State}, Json, Router, routing::get};
use serde::Deserialize;
use sqlx::PgPool;
use crate::{db, error::{ApiError, ApiResult}};
use axum::http::StatusCode;
use super::no_store_headers;

pub fn router() -> Router<PgPool> {
    Router::new()
        .route("/blocks", get(list_blocks))
        .route("/blocks/height/:height", get(get_by_height))
        .route("/blocks/hash/:hash", get(get_by_hash))
}

#[derive(Deserialize)]
struct Pagination { limit: Option<i64>, offset: Option<i64> }

async fn list_blocks(
    State(pool): State<PgPool>,
    Query(p): Query<Pagination>,
) -> ApiResult<(axum::http::HeaderMap, Json<Vec<crate::models::BlockSummary>>)> {
    let limit = p.limit.unwrap_or(20).min(100);
    let offset = p.offset.unwrap_or(0);
    Ok((no_store_headers(), Json(db::get_blocks(&pool, limit, offset).await?)))
}

async fn get_by_height(
    State(pool): State<PgPool>,
    Path(height): Path<i64>,
) -> ApiResult<Json<crate::models::BlockDetail>> {
    db::get_block_by_height(&pool, height).await?
        .map(Json)
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "block not found".into()))
}

async fn get_by_hash(
    State(pool): State<PgPool>,
    Path(hash): Path<String>,
) -> ApiResult<Json<crate::models::BlockDetail>> {
    db::get_block_by_hash(&pool, &hash).await?
        .map(Json)
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "block not found".into()))
}
