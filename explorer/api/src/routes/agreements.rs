use axum::{extract::{Path, Query, State}, Json, Router, routing::get};
use serde::Deserialize;
use sqlx::PgPool;
use crate::{db, error::{ApiError, ApiResult}};
use axum::http::StatusCode;

pub fn router() -> Router<PgPool> {
    Router::new()
        .route("/agreements", get(list_agreements))
        .route("/agreement/:hash", get(get_agreement))
        .route("/htlcs", get(list_htlcs))
}

#[derive(Deserialize)]
struct LimitParam { limit: Option<i64> }

async fn list_agreements(
    State(pool): State<PgPool>,
    Query(q): Query<LimitParam>,
) -> ApiResult<Json<Vec<crate::models::AgreementInfo>>> {
    let limit = q.limit.unwrap_or(50).min(200);
    Ok(Json(db::get_agreements_list(&pool, limit).await?))
}

async fn get_agreement(
    State(pool): State<PgPool>,
    Path(hash): Path<String>,
) -> ApiResult<Json<crate::models::AgreementInfo>> {
    db::get_agreement(&pool, &hash).await?
        .map(Json)
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "agreement not found".into()))
}

async fn list_htlcs(
    State(pool): State<PgPool>,
    Query(q): Query<LimitParam>,
) -> ApiResult<Json<Vec<crate::models::HtlcInfo>>> {
    let limit = q.limit.unwrap_or(50).min(200);
    Ok(Json(db::get_all_htlcs(&pool, limit).await?))
}
