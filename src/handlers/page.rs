use std::sync::Arc;

use axum::{
    extract::{Path, State},
    response::IntoResponse,
};
use http::StatusCode;
use tracing::error;

use crate::state::AppState;

pub async fn show_page_route(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // Copy page path while holding lock, then release lock before I/O
    let page_path = {
        let locked = state.scan.lock();
        let scan = match locked.as_ref() {
            None => return (StatusCode::SERVICE_UNAVAILABLE, Vec::new()).into_response(),
            Some(scan) => scan,
        };
        match scan.pages_map.get(&*id) {
            None => return (StatusCode::NOT_FOUND, Vec::new()).into_response(),
            Some(page) => page.path.clone(),
        }
    };
    // Use async file read to avoid blocking other requests
    let content = match tokio::fs::read(&page_path).await {
        Ok(content) => content,
        Err(err) => {
            error!(%err, "failed to read page");
            return (StatusCode::NOT_FOUND, Vec::new()).into_response();
        }
    };
    (StatusCode::OK, content).into_response()
}
