use std::sync::Arc;

use axum::{
    extract::{Path, State},
    response::{IntoResponse, Response},
};
use http::{StatusCode, header};
use image::ImageReader;
use tokio::fs;
use tracing::{debug, error};

use super::page::content_type_from_path;
use crate::state::AppState;

/// JPEG quality used for generated thumbnails.
const THUMB_QUALITY: u8 = 72;

/// Map a size keyword to a maximum edge length in pixels.
fn size_px(name: &str) -> Option<u32> {
    match name {
        "sm" => Some(120), // reader thumbnail rail
        "md" => Some(400), // library covers
        _ => None,
    }
}

/// Decode `path`, shrink it to fit within `max`×`max`, and JPEG-encode it.
fn generate(path: &str, max: u32) -> anyhow::Result<Vec<u8>> {
    let img = ImageReader::open(path)?.with_guessed_format()?.decode()?;
    let thumb = img.thumbnail(max, max).to_rgb8();
    let mut buf = Vec::new();
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut buf, THUMB_QUALITY)
        .encode_image(&thumb)?;
    Ok(buf)
}

fn jpeg_response(bytes: Vec<u8>) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "image/jpeg"),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        bytes,
    )
        .into_response()
}

/// Serve a cached or freshly generated thumbnail for a page.
///
/// `GET /thumb/{size}/{id}` where size is `sm` or `md`. Thumbnails are written
/// to the cache dir on first request and read back on subsequent ones, so the
/// full-resolution source is opened at most once per (size, page).
pub async fn show_thumb_route(
    State(state): State<Arc<AppState>>,
    Path((size, id)): Path<(String, String)>,
) -> impl IntoResponse {
    let max = match size_px(&size) {
        Some(m) => m,
        None => return (StatusCode::NOT_FOUND, Vec::new()).into_response(),
    };

    // Resolve the source path, releasing the lock before any I/O.
    let src = {
        let locked = state.scan.read();
        let scan = match locked.as_ref() {
            None => return (StatusCode::SERVICE_UNAVAILABLE, Vec::new()).into_response(),
            Some(scan) => scan,
        };
        match scan.page_by_id(&id) {
            None => return (StatusCode::NOT_FOUND, Vec::new()).into_response(),
            Some(page) => page.path.clone(),
        }
    };

    // Serve from cache when present.
    let cache_path = state.cache_dir.join(&size).join(format!("{id}.jpg"));
    if let Ok(bytes) = fs::read(&cache_path).await {
        return jpeg_response(bytes);
    }

    // Generate, bounding concurrency so opening a book does not spawn a decode
    // storm. The permit is held across the blocking work.
    let _permit = state.thumb_sem.acquire().await;
    let src_for_gen = src.clone();
    let bytes = match tokio::task::spawn_blocking(move || generate(&src_for_gen, max)).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(err)) => {
            // Undecodable source: fall back to the original so the UI still shows something.
            debug!(%err, path = %src, "thumbnail generation failed; serving original");
            return serve_original(&src).await;
        }
        Err(err) => {
            error!(%err, "thumbnail task panicked");
            return (StatusCode::INTERNAL_SERVER_ERROR, Vec::new()).into_response();
        }
    };

    // Best-effort cache write; serving succeeds even if the cache dir is not writable.
    if let Some(parent) = cache_path.parent() {
        let _ = fs::create_dir_all(parent).await;
    }
    if let Err(err) = fs::write(&cache_path, &bytes).await {
        debug!(%err, path = %cache_path.display(), "failed to write thumbnail cache");
    }
    jpeg_response(bytes)
}

/// Fallback: stream the original image when a thumbnail cannot be produced.
async fn serve_original(path: &str) -> Response {
    match fs::read(path).await {
        Ok(content) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, content_type_from_path(path)),
                (header::CACHE_CONTROL, "no-store"),
            ],
            content,
        )
            .into_response(),
        Err(_) => (StatusCode::NOT_FOUND, Vec::new()).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthConfig;
    use axum::extract::{Path as AxumPath, State};
    use parking_lot::RwLock;
    use std::path::PathBuf;
    use tokio::sync::Semaphore;

    fn state_without_scan() -> Arc<AppState> {
        Arc::new(AppState {
            auth_config: AuthConfig::None,
            key: cookie::Key::generate(),
            data_dir: PathBuf::from("/tmp"),
            scan: Arc::new(RwLock::new(None)),
            seed: 0,
            cache_dir: PathBuf::from("/tmp"),
            thumb_sem: Arc::new(Semaphore::new(1)),
        })
    }

    #[test]
    fn size_px_allowlist() {
        assert_eq!(size_px("sm"), Some(120));
        assert_eq!(size_px("md"), Some(400));
        assert_eq!(size_px("lg"), None);
    }

    #[tokio::test]
    async fn unknown_size_is_not_found() {
        let res = show_thumb_route(
            State(state_without_scan()),
            AxumPath(("lg".to_string(), "x".to_string())),
        )
        .await
        .into_response();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn unavailable_before_first_scan() {
        let res = show_thumb_route(
            State(state_without_scan()),
            AxumPath(("md".to_string(), "x".to_string())),
        )
        .await
        .into_response();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
