use std::sync::Arc;

use axum::{Json, extract::State, response::IntoResponse};
use http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::state::AppState;

#[derive(Deserialize, Serialize)]
pub struct Healthz {
    pub scanned_at: i64,
}

pub async fn healthz_route(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let locked = state.scan.lock();
    let scan = match locked.as_ref() {
        None => return (StatusCode::SERVICE_UNAVAILABLE, Json(())).into_response(),
        Some(scan) => scan,
    };
    Json(Healthz {
        scanned_at: scan.scanned_at.timestamp_millis(),
    })
    .into_response()
}
