//! First-line CSRF defence: reject state-changing requests that a browser
//! reports, or reveals, to be cross-site.
//!
//! This is a header-only check with no token and no state. It runs on every
//! unsafe-method request across the whole router, but only ever *rejects* a
//! request that is provably cross-site; anything it cannot classify is passed
//! through, so it never breaks a legitimate caller:
//!
//! - **`Sec-Fetch-Site`** (sent by every current browser) normally identifies
//!   cross-site requests. A matching `Origin` and `Host` takes precedence,
//!   since a reverse proxy may inject or overwrite fetch-metadata headers.
//! - **`Origin`** is used to confirm same-origin requests or as the fallback
//!   for the rare browser that omits `Sec-Fetch-Site`. Its host is compared
//!   against the request's own `Host`; a mismatch — or an opaque `Origin: null`
//!   — is rejected.
//! - **Neither header** means a non-browser client (`curl`, a server-to-server
//!   call). Those do not ride an ambient session cookie, so they are not
//!   exposed to CSRF and are allowed through.
//!
//! Letting `Origin` overrule a `cross-site` label is a deliberate relaxation:
//! `Sec-Fetch-Site` is no longer an unappealable verdict. It costs nothing an
//! attacker can spend, because both headers are set by the browser and neither
//! is reachable from script. For the two hosts to match, the attacking page
//! would have to be served from the target host — at which point it is
//! same-origin and this is not CSRF. The one way a cross-site request arrives
//! carrying the target's own `Origin` is a redirect chain, and the browser
//! taints that to `null`, which is still rejected. What is *not* covered is a
//! proxy that strips `Origin` outright: there is nothing left to confirm with,
//! and an injected `cross-site` label then still wins.
//!
//! That last point has a sharper edge, and it is the one prerequisite this
//! relaxation carries: **a proxy in front must leave `Origin` alone.** A
//! configuration that rewrites it to the backend host — `proxy_set_header
//! Origin $host`, the usual way to talk a backend's own origin check into
//! accepting a WebSocket upgrade — makes `Origin` match unconditionally, and
//! this guard then accepts every request. That is strictly worse than the
//! `Sec-Fetch-Site`-only rule it replaces, which would have gone on rejecting a
//! genuine cross-site POST. The session cookie's `SameSite=Strict` is what
//! stops such a deployment from being exploitable; this layer is defence in
//! depth and must not be the one anything relies on.
//!
//! Scheme and port are deliberately ignored in the `Origin`/`Host` comparison:
//! behind a TLS-terminating reverse proxy the browser's `Origin` is `https://`
//! while the forwarded `Host` carries no scheme, and the proxy commonly strips
//! the port. Matching on host alone is what keeps the check working in that
//! standard deployment without a configured public URL.

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

    // A proxy can inject a stale or generic fetch-metadata value. A browser's
    // `Origin` is more specific evidence when it matches the target host, so
    // never reject that valid same-origin form submission. `&&` short-circuits,
    // so the comparison only runs for the requests that would be rejected.
    if let Some(site) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        return site.eq_ignore_ascii_case("cross-site") && origin_is_same(headers) != Some(true);
    }

    // No `Sec-Fetch-Site` at all: `None` here means no `Origin` either, which
    // makes this a non-browser client — see the module docs.
    origin_is_same(headers).is_some_and(|same| !same)
}

/// Whether the request's `Origin` names the same host as its `Host`.
///
/// `None` means there is no `Origin` to judge by; the caller decides what that
/// absence implies. `Some(false)` covers every `Origin` that cannot be
/// confirmed to match, including an opaque or unparseable one.
fn origin_is_same(headers: &http::HeaderMap) -> Option<bool> {
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok())?;
    // `Origin: null` is opaque (a sandboxed iframe, a cross-origin redirect) and
    // never legitimate for a state-changing request here.
    if origin.eq_ignore_ascii_case("null") {
        return Some(false);
    }
    let Some(origin_host) = host_of(origin) else {
        return Some(false);
    };
    let request_host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(strip_port);
    // A missing/garbled Host with a present Origin cannot be confirmed
    // same-origin, so treat it as cross-site.
    Some(request_host == Some(origin_host))
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
    fn sec_fetch_site_rejects_cross_site_requests() {
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
        // A mismatched Origin remains cross-site even when a proxy supplies
        // fetch metadata.
        assert!(is_cross_site(&req(
            Method::POST,
            &[
                ("sec-fetch-site", "cross-site"),
                ("origin", "https://evil.example.com"),
                ("host", "app.example.com"),
            ]
        )));
    }

    #[test]
    fn matching_origin_overrides_a_proxy_injected_cross_site_header() {
        assert!(!is_cross_site(&req(
            Method::POST,
            &[
                ("sec-fetch-site", "cross-site"),
                ("origin", "https://app.example.com"),
                ("host", "app.example.com"),
            ]
        )));
    }

    /// The `Origin` override only rescues a request whose origin is *confirmed*
    /// same-host. Anything short of that leaves the `cross-site` label standing.
    #[test]
    fn an_unconfirmable_origin_does_not_override_the_cross_site_header() {
        // A cross-origin redirect chain: the browser taints Origin to null.
        assert!(is_cross_site(&req(
            Method::POST,
            &[
                ("sec-fetch-site", "cross-site"),
                ("origin", "null"),
                ("host", "app.example.com"),
            ]
        )));
        // No Host to compare against.
        assert!(is_cross_site(&req(
            Method::POST,
            &[
                ("sec-fetch-site", "cross-site"),
                ("origin", "https://app.example.com"),
            ]
        )));
        // An Origin with no `://` authority cannot be parsed into a host.
        assert!(is_cross_site(&req(
            Method::POST,
            &[
                ("sec-fetch-site", "cross-site"),
                ("origin", "app.example.com"),
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
        // Port on the Origin, none on Host → still same host.
        assert!(!is_cross_site(&req(
            Method::POST,
            &[("origin", "http://localhost:8080"), ("host", "localhost"),]
        )));
        // Genuine cross-origin.
        assert!(is_cross_site(&req(
            Method::POST,
            &[
                ("origin", "https://evil.example.com"),
                ("host", "app.example.com"),
            ]
        )));
        // Opaque origin.
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
        // A curl / server-to-server call sends neither header and does not ride
        // an ambient cookie, so it is not a CSRF vector.
        assert!(!is_cross_site(&req(Method::POST, &[])));
    }
}
