use std::sync::Arc;

use axum::{
    extract::{Path, State},
    response::IntoResponse,
};
use http::{StatusCode, header};
use tracing::error;

use crate::state::AppState;

/// Infer Content-Type from file extension
fn content_type_from_path(path: &str) -> &'static str {
    match path
        .rsplit('.')
        .next()
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("png") => "image/png",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("avif") => "image/avif",
        _ => "application/octet-stream",
    }
}

pub async fn show_page_route(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // Copy page path while holding lock, then release lock before I/O
    let page_path = {
        let locked = state.scan.read();
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
            let status = if err.kind() == std::io::ErrorKind::NotFound {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            return (status, Vec::new()).into_response();
        }
    };
    let content_type = content_type_from_path(&page_path);
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "public, max-age=86400, immutable"),
        ],
        content,
    )
        .into_response()
}
