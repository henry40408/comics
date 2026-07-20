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
    let locked = state.scan.read();
    let Some(scan) = locked.as_ref() else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(())).into_response();
    };
    Json(Healthz {
        scanned_at: scan.scanned_at.timestamp_millis(),
    })
    .into_response()
}
