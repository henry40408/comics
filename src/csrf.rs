//! First-line CSRF defence: reject state-changing requests that a browser
//! reports, or reveals, to be cross-site.
//!
//! A header-only check, no token and no state. It runs on every unsafe-method
//! request across the whole router, but only ever *rejects* what is provably
//! cross-site; anything it cannot classify passes through, so it never breaks a
//! legitimate caller:
//!
//! - **`Sec-Fetch-Site`** (sent by every current browser) is authoritative when
//!   present. `same-origin`, `same-site`, and `none` (a direct navigation or a
//!   user-typed URL) are allowed; only `cross-site` is rejected.
//! - **`Origin`** is the fallback for the rare browser that omits it. Its host
//!   is compared against the request's own `Host`; a mismatch — or an opaque
//!   `Origin: null` — is rejected.
//! - **Neither header** means a non-browser client (`curl`, a server-to-server
//!   call), which rides no ambient session cookie and so is not exposed to CSRF.
//!
//! Scheme and port are ignored in that comparison: behind a TLS-terminating
//! proxy the browser's `Origin` is `https://` while the forwarded `Host` carries
//! no scheme and commonly no port, so host alone is what keeps the check working
//! in that standard deployment without a configured public URL.
//!
//! # The plain-HTTP LAN hole, and the escape hatch
//!
//! Fetch metadata only reaches *potentially trustworthy* origins — HTTPS, or
//! `localhost`. A plain-HTTP LAN host such as `http://nas.local` is neither, so
//! **no `Sec-Fetch-Site` ever arrives** and everything falls to the `Origin`
//! branch. That survives until a browser reports an opaque `Origin: null` (a
//! sandboxed iframe, or a privacy setting that suppresses the header): the login
//! `POST` is rejected, and the operator who cannot log in has no way back from
//! inside the app.
//!
//! `--disable-csrf-guard` / `COMICS_DISABLE_CSRF_GUARD` exists for that dead
//! end, removing this layer from the router altogether. Reaching the server over
//! HTTPS or through a `localhost` tunnel restores `Sec-Fetch-Site` and fixes the
//! same lockout while giving nothing up, so prefer it where available. What
//! survives the escape hatch is the session cookie's `SameSite=Strict`, which is
//! what actually stops a cross-site `POST` from carrying credentials; this
//! module is defence in depth layered on that, never the only lock.

use axum::{
    extract::Request,
    http::{Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

/// Reject a state-changing request that is provably cross-site; see the module
/// docs for the classification.
pub async fn csrf_origin_guard(req: Request, next: Next) -> Response {
    if is_safe(req.method()) || !is_cross_site(&req) {
        return next.run(req).await;
    }
    StatusCode::FORBIDDEN.into_response()
}

fn is_safe(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
    )
}

/// Only what a browser has *told us* is cross-site counts; anything unclassified
/// is passed through. See the module docs.
fn is_cross_site(req: &Request) -> bool {
    let headers = req.headers();

    if let Some(site) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        return site.eq_ignore_ascii_case("cross-site");
    }

    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        // No Sec-Fetch-Site and no Origin → a non-browser client.
        return false;
    };
    // Opaque: a sandboxed iframe or a cross-origin redirect, never legitimate
    // for a state-changing request here.
    if origin.eq_ignore_ascii_case("null") {
        return true;
    }
    let Some(origin_host) = host_of(origin) else {
        return true;
    };
    let request_host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(strip_port);
    // A missing/garbled Host with a present Origin cannot be confirmed
    // same-origin, so treat it as cross-site.
    request_host != Some(origin_host)
}

/// The host of an `Origin` value (`scheme://host[:port]`), lower-cased and with
/// any port removed. `None` when there is no `://` authority to read.
fn host_of(origin: &str) -> Option<String> {
    let authority = origin.split_once("://").map(|(_, rest)| rest)?;
    Some(strip_port(authority).to_ascii_lowercase())
}

/// Strip a trailing `:port` from a host authority, leaving the host. Handles
/// bracketed IPv6 literals (`[::1]:8080` → `[::1]`).
fn strip_port(authority: &str) -> String {
    if let Some(end) = authority
        .strip_prefix('[')
        .and_then(|_| authority.find(']'))
    {
        return authority[..=end].to_ascii_lowercase();
    }
    authority
        .rsplit_once(':')
        .map_or(authority, |(host, _)| host)
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    fn req(method: Method, headers: &[(&str, &str)]) -> Request {
        let mut b = Request::builder().method(method).uri("/anything");
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(Body::empty()).unwrap()
    }

    #[test]
    fn safe_methods_are_never_cross_site_checked() {
        // Even an obviously cross-site GET passes — GET must not change state.
        let r = req(Method::GET, &[("sec-fetch-site", "cross-site")]);
        assert!(is_safe(r.method()));
    }

    #[test]
    fn sec_fetch_site_is_authoritative() {
        for allowed in ["same-origin", "same-site", "none", "SAME-ORIGIN"] {
            assert!(
                !is_cross_site(&req(Method::POST, &[("sec-fetch-site", allowed)])),
                "{allowed} must be allowed"
            );
        }
        assert!(is_cross_site(&req(
            Method::POST,
            &[("sec-fetch-site", "cross-site")]
        )));
        // It wins over a same-looking Origin/Host, in both directions.
        assert!(is_cross_site(&req(
            Method::POST,
            &[
                ("sec-fetch-site", "cross-site"),
                ("origin", "https://app.example.com"),
                ("host", "app.example.com"),
            ]
        )));
    }

    #[test]
    fn origin_fallback_compares_host_ignoring_scheme_and_port() {
        // TLS-terminating proxy: Origin is https://, Host has no scheme/port.
        assert!(!is_cross_site(&req(
            Method::POST,
            &[
                ("origin", "https://app.example.com"),
                ("host", "app.example.com"),
            ]
        )));
        assert!(!is_cross_site(&req(
            Method::POST,
            &[("origin", "http://localhost:8080"), ("host", "localhost"),]
        )));
        assert!(is_cross_site(&req(
            Method::POST,
            &[
                ("origin", "https://evil.example.com"),
                ("host", "app.example.com"),
            ]
        )));
        assert!(is_cross_site(&req(
            Method::POST,
            &[("origin", "null"), ("host", "app.example.com")]
        )));
    }

    #[test]
    fn ipv6_literal_host_is_compared_without_its_port() {
        assert!(!is_cross_site(&req(
            Method::POST,
            &[("origin", "http://[::1]:8080"), ("host", "[::1]")]
        )));
    }

    #[test]
    fn non_browser_client_without_headers_passes() {
        // Rides no ambient cookie either, so it is not a CSRF vector.
        assert!(!is_cross_site(&req(Method::POST, &[])));
    }
}
