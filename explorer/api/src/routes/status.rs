
use axum::{extract::State, Json, Router, routing::get};
use sqlx::PgPool;
use crate::{db, error::ApiResult};
use super::no_store_headers;

pub fn router() -> Router<PgPool> {
    Router::new().route("/status", get(handler))
}

async fn handler(State(pool): State<PgPool>) -> ApiResult<(axum::http::HeaderMap, Json<crate::models::ExplorerStatus>)> {
    Ok((no_store_headers(), Json(db::get_status(&pool).await?)))
}
