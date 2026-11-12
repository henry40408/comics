use std::sync::Arc;

use axum::{
    extract::State,
    response::{Html, IntoResponse, Response},
};
use http::StatusCode;

use crate::auth::AuthConfig;
use crate::state::AppState;
use crate::views::{IndexView, index_page};

pub async fn index_route(State(state): State<Arc<AppState>>) -> Response {
    // Hold read lock through render — rendering is pure CPU, no await
    let locked = state.scan.read();
    let Some(scan) = locked.as_ref() else {
        return (StatusCode::SERVICE_UNAVAILABLE, Html(String::new())).into_response();
    };
    let view = IndexView {
        books: &scan.books,
        scan_duration_ms: scan.scan_duration.num_milliseconds() as f64,
        scanned_at: scan.scanned_at.to_rfc2822(),
        // Millis: HTML allows at most three fractional digits, `to_rfc3339` emits
        // the clock's full precision (six or nine).
        scanned_at_iso: scan
            .scanned_at
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        auth_enabled: matches!(state.auth_config, AuthConfig::Some { .. }),
    };
    (StatusCode::OK, index_page(&view)).into_response()
}
