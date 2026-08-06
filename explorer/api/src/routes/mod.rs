mod blocks;
mod txs;
mod address;
mod agreements;
mod miners;
mod search;
mod stats;
mod status;

use axum::{
    Router,
    http::{HeaderMap, HeaderValue, header::CACHE_CONTROL},
};
use sqlx::PgPool;

pub fn router() -> Router<PgPool> {
    Router::new()
        .merge(status::router())
        .merge(blocks::router())
        .merge(txs::router())
        .merge(address::router())
        .merge(agreements::router())
        .merge(miners::router())
        .merge(search::router())
        .merge(stats::router())
}

pub(super) fn no_store_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers
}

#[cfg(test)]
mod tests {
    use super::no_store_headers;
    use axum::http::header::CACHE_CONTROL;

    #[test]
    fn live_endpoints_disable_intermediary_and_browser_caches() {
        assert_eq!(no_store_headers()[CACHE_CONTROL], "no-store");
    }
}
