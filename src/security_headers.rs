use std::sync::Arc;

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use http::{HeaderName, HeaderValue, header};

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

/// The policy every response carries.
///
/// `default-src 'none'` makes the whole thing deny-by-default: every fetch
/// directive not named below (`connect-src`, `media-src`, `object-src`,
/// `worker-src`, `manifest-src`) falls back to it, so a future feature has to
/// opt itself in rather than inherit permission. What is named is exactly what
/// the three templates load:
///
/// - `script-src 'self'` — `app.js` and `theme.js`, both same-origin files.
///   There is deliberately no `'unsafe-inline'`: the pre-paint theme snippet was
///   moved out of the templates precisely so this could stay clean, since
///   `'unsafe-inline'` permits every *injected* script too, which is the whole
///   attack it is supposed to stop.
/// - `style-src` and `font-src` name `fonts.bunny.net`, the one third party the
///   templates reference (`app.css` itself pulls in nothing external).
/// - `img-src 'self'` — pages and thumbnails are same-origin routes.
/// - `form-action 'self'` stops an injection from re-pointing the login form at
///   another host; `base-uri 'none'` stops a `<base>` tag from doing the same to
///   every relative asset URL.
/// - `frame-ancestors 'none'` is the clickjacking control. `SameSite=Strict`
///   already blocks cross-site *requests*, but not comics being framed and
///   click-baited by a page the reader is already visiting.
const CSP: &str = "default-src 'none'; \
                   script-src 'self'; \
                   style-src 'self' https://fonts.bunny.net; \
                   font-src https://fonts.bunny.net; \
                   img-src 'self'; \
                   form-action 'self'; \
                   base-uri 'none'; \
                   frame-ancestors 'none'";

/// Features comics never uses. Denying them outright costs nothing and means a
/// successful injection cannot reach the camera, microphone or location either.
const PERMISSIONS_POLICY: &str = "accelerometer=(), autoplay=(), camera=(), \
                                  display-capture=(), encrypted-media=(), fullscreen=(), \
                                  geolocation=(), gyroscope=(), magnetometer=(), \
                                  microphone=(), midi=(), payment=(), usb=()";

/// Response headers that never depend on configuration.
///
/// `X-Frame-Options` duplicates the CSP's `frame-ancestors` for browsers
/// predating it; `Cross-Origin-Resource-Policy` keeps another site from
/// embedding a page image directly, which `frame-ancestors` does not cover
/// because an `<img>` is not a frame. `Referrer-Policy: no-referrer` is
/// affordable here because nothing outbound needs a referrer — the only
/// cross-origin requests are the font ones — and book titles live in the path,
/// so a leaked URL leaks what someone is reading.
/// Names are spelled out rather than taken from [`header`] because the
/// `Cross-Origin-*` family has no constant there, and mixing the two styles
/// would hide which entry is which. `HeaderName::from_static` accepts only
/// lowercase, and panics on anything malformed — at the first request, which
/// every test in this module would catch.
const CONSTANT_HEADERS: [(&str, &str); 7] = [
    ("content-security-policy", CSP),
    ("x-content-type-options", "nosniff"),
    ("x-frame-options", "DENY"),
    ("referrer-policy", "no-referrer"),
    ("cross-origin-resource-policy", "same-origin"),
    ("cross-origin-opener-policy", "same-origin"),
    ("permissions-policy", PERMISSIONS_POLICY),
];

/// Applied as a global outer layer so it also covers `/login`, `/healthz`, and
/// the assets.
///
/// [`CONSTANT_HEADERS`] and the permissions policy are unconditional; HSTS is
/// off unless configured, because comics does not terminate TLS, so HSTS
/// properly belongs on the reverse proxy that does, and a browser that has
/// cached the header will refuse plain HTTP to this host for the whole max-age —
/// which would make an HTTP-only LAN deployment unreachable with no easy way
/// back.
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

    /// `HeaderName::from_static` and `HeaderValue::from_static` both panic on a
    /// malformed argument, and they run per request — so a typo would take the
    /// whole server down at the first hit rather than failing to compile.
    #[test]
    fn every_constant_header_is_well_formed() {
        for (name, value) in CONSTANT_HEADERS {
            assert_eq!(name, name.to_ascii_lowercase(), "{name} must be lowercase");
            HeaderName::from_static(name);
            HeaderValue::from_static(value);
        }
    }

    /// The point of moving the theme snippet into `theme.js` was to keep these
    /// two escape hatches out of the policy. Re-adding either would silently
    /// undo it.
    #[test]
    fn csp_permits_no_inline_or_eval() {
        assert!(!CSP.contains("unsafe-inline"), "{CSP}");
        assert!(!CSP.contains("unsafe-eval"), "{CSP}");
    }
}
