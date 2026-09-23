use std::sync::Arc;

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use http::{HeaderName, HeaderValue, header};

use crate::state::AppState;

/// `Cache-Control: no-store` (plus `Pragma` for HTTP/1.0) on HTML, so the back
/// button after logout cannot show a rendered page.
///
/// Only fills an *absent* header, and only on `text/html`: the image routes set
/// long-lived `private` values on purpose, since a blanket `no-store` would
/// re-read every page from disk on every turn.
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

/// Deny-by-default (`default-src 'none'`); each named directive is exactly
/// what the templates load, so a new feature must opt itself in.
///
/// - `script-src 'self'` — no `'unsafe-inline'`, which would admit *injected*
///   scripts too; that is why the pre-paint theme snippet is `theme.js`.
/// - `fonts.bunny.net` is the only third party (webfonts).
/// - `form-action`/`base-uri` stop an injection re-pointing the login form or
///   every relative URL.
/// - `frame-ancestors 'none'` is the clickjacking control; `SameSite=Strict`
///   does not stop framing.
const CSP: &str = "default-src 'none'; \
                   script-src 'self'; \
                   style-src 'self' https://fonts.bunny.net; \
                   font-src https://fonts.bunny.net; \
                   img-src 'self'; \
                   form-action 'self'; \
                   base-uri 'none'; \
                   frame-ancestors 'none'";

/// Features comics never uses, denied so an injection cannot reach them.
const PERMISSIONS_POLICY: &str = "accelerometer=(), autoplay=(), camera=(), \
                                  display-capture=(), encrypted-media=(), fullscreen=(), \
                                  geolocation=(), gyroscope=(), magnetometer=(), \
                                  microphone=(), midi=(), payment=(), usb=()";

/// Response headers that never depend on configuration.
///
/// `X-Frame-Options` backs up `frame-ancestors` for older browsers; CORP stops
/// hotlinking page images, which `frame-ancestors` does not cover.
/// `no-referrer` costs nothing (only fonts are cross-origin) and book URLs
/// reveal what someone reads.
///
/// Names are lowercase literals because [`header`] lacks the `Cross-Origin-*`
/// family; `from_static` panics on malformed input at the first request.
const CONSTANT_HEADERS: [(&str, &str); 7] = [
    ("content-security-policy", CSP),
    ("x-content-type-options", "nosniff"),
    ("x-frame-options", "DENY"),
    ("referrer-policy", "no-referrer"),
    ("cross-origin-resource-policy", "same-origin"),
    ("cross-origin-opener-policy", "same-origin"),
    ("permissions-policy", PERMISSIONS_POLICY),
];

/// Global outer layer, so it also covers `/login`, `/healthz` and the assets.
///
/// HSTS is off unless configured: comics does not terminate TLS, and a cached
/// HSTS strands an HTTP-only LAN deployment for the whole max-age.
pub async fn security_headers_layer(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let mut res = next.run(req).await;
    let headers = res.headers_mut();
    for (name, value) in CONSTANT_HEADERS {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    if let Some(max_age) = state.hsts_max_age
        && let Ok(value) = HeaderValue::from_str(&format!("max-age={max_age}"))
    {
        headers.insert(header::STRICT_TRANSPORT_SECURITY, value);
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

    /// `from_static` panics at request time, not compile time.
    #[test]
    fn every_constant_header_is_well_formed() {
        for (name, value) in CONSTANT_HEADERS {
            assert_eq!(name, name.to_ascii_lowercase(), "{name} must be lowercase");
            HeaderName::from_static(name);
            HeaderValue::from_static(value);
        }
    }

    #[test]
    fn csp_permits_no_inline_or_eval() {
        assert!(!CSP.contains("unsafe-inline"), "{CSP}");
        assert!(!CSP.contains("unsafe-eval"), "{CSP}");
    }
}
