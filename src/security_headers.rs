use std::sync::Arc;

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use http::{HeaderValue, header};

use crate::state::AppState;

/// Adds `Pragma: no-cache` alongside, for HTTP/1.0 caches.
///
/// OWASP's *Web Content Caching* guidance is about the rendered page persisting
/// in the browser cache, where a back-button press after logout would still show
/// it. It runs after the handler and only fills in a header that is absent, so
/// the image routes' deliberate long-lived values (`handlers/page.rs`,
/// `handlers/thumb.rs`) are left untouched. It is scoped to `text/html` for the
/// same reason: a blanket `no-store` would make the reader re-read every page
/// image from disk on every turn, which is the performance trade-off comics is
/// built around. Those routes get `private` instead, so a shared cache still
/// cannot keep authenticated content.
pub async fn no_store_html(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let headers = res.headers_mut();
    if headers.contains_key(header::CACHE_CONTROL) {
        return res;
    }
    let is_html = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("text/html"));
    if is_html {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    }
    res
}

/// Applied as a global outer layer so it also covers `/login`, `/healthz`, and
/// the assets. Off unless configured: comics does not terminate TLS, so HSTS
/// properly belongs on the reverse proxy that does, and a browser that has
/// cached the header will refuse plain HTTP to this host for the whole max-age —
/// which would make an HTTP-only LAN deployment unreachable with no easy way
/// back.
pub async fn hsts_layer(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    if let Some(max_age) = state.hsts_max_age
        && let Ok(value) = HeaderValue::from_str(&format!("max-age={max_age}"))
    {
        res.headers_mut()
            .insert(header::STRICT_TRANSPORT_SECURITY, value);
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, routing::get};
    use axum_test::TestServer;

    async fn run(
        content_type: &'static str,
        cache_control: Option<&'static str>,
    ) -> axum_test::TestResponse {
        let router = Router::new()
            .route(
                "/",
                get(move || async move {
                    let mut res = Response::new(Body::from("body"));
                    let headers = res.headers_mut();
                    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
                    if let Some(value) = cache_control {
                        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(value));
                    }
                    res
                }),
            )
            .layer(axum::middleware::from_fn(no_store_html));
        TestServer::new(router).get("/").await
    }

    #[tokio::test]
    async fn adds_no_store_to_html_without_cache_control() {
        let res = run("text/html; charset=utf-8", None).await;
        assert_eq!(200, res.status_code());
        assert_eq!("no-store", res.headers()[header::CACHE_CONTROL]);
        assert_eq!("no-cache", res.headers()[header::PRAGMA]);
    }

    /// The image and asset routes set their own values deliberately; the
    /// middleware must never overwrite one.
    #[tokio::test]
    async fn leaves_existing_cache_control_untouched() {
        let res = run("text/html", Some("public, max-age=60")).await;
        assert_eq!("public, max-age=60", res.headers()[header::CACHE_CONTROL]);
        assert!(!res.headers().contains_key(header::PRAGMA));
    }

    #[tokio::test]
    async fn ignores_non_html_content_types() {
        let res = run("image/jpeg", None).await;
        assert!(!res.headers().contains_key(header::CACHE_CONTROL));
    }
}
