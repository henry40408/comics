use std::sync::Arc;

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Redirect},
};
use chrono::Utc;
use cookie::{Cookie, CookieJar, SameSite, time::Duration};
use http::{Method, StatusCode, header};

use super::config::AuthConfig;
use super::key::hex_lower;
use crate::state::AppState;

/// Name of the signed session cookie.
pub const SESSION_COOKIE: &str = "comics_session";
/// How long a session stays valid after login.
const SESSION_TTL_DAYS: i64 = 7;
/// Length of the session nonce in bytes (128 bits), per OWASP's minimum
/// session-ID length.
const SESSION_NONCE_BYTES: usize = 16;

/// Authentication state after checking the request.
pub enum AuthState {
    /// No credentials are configured; everything is public.
    Public,
    /// A valid, unexpired session cookie was presented.
    Authenticated,
    /// No valid session cookie was presented.
    Unauthenticated,
}

/// Build a fresh, signed-cookie-ready session cookie.
///
/// The value is `<nonce-hex>.<expiry-unix>`: a 128-bit CSPRNG nonce makes it
/// meaningless and unguessable (OWASP Session Management Cheat Sheet, "Session
/// ID Properties" — at least 128 bits, at least 64 bits of entropy, and no
/// decodable content), while the appended expiry lets the server enforce the TTL
/// without a session store. Both halves are covered by the signature the caller's
/// [`cookie::SignedJar`] adds.
///
/// `secure` comes from the `--cookie-secure` option rather than being hardcoded:
/// a browser silently discards a `Secure` cookie delivered over plain HTTP, so
/// forcing it on would lock plain-HTTP LAN deployments out of the login form
/// with no visible error.
///
/// There is no session renewal (a cookie is issued once and expires), so no
/// `session_renewed` audit event exists. Introducing a sliding window would need
/// one — see `handlers/login.rs`.
pub fn build_session_cookie(secure: bool) -> Cookie<'static> {
    let nonce: [u8; SESSION_NONCE_BYTES] = rand::random();
    let expires_at = Utc::now().timestamp() + SESSION_TTL_DAYS * 24 * 60 * 60;
    let value = format!("{}.{expires_at}", hex_lower(&nonce));
    Cookie::build((SESSION_COOKIE, value))
        .http_only(true)
        .same_site(SameSite::Lax)
        .path("/")
        .secure(secure)
        .max_age(Duration::days(SESSION_TTL_DAYS))
        .build()
}

/// Parse a `<nonce-hex>.<expiry>` session value, returning the expiry when the
/// shape is valid.
///
/// A bare timestamp — the pre-nonce format — deliberately fails here, so
/// upgrading logs existing sessions out once rather than silently keeping a
/// value that violates the OWASP session-ID properties.
fn parse_session_value(value: &str) -> Option<i64> {
    let (nonce, expires_at) = value.split_once('.')?;
    if nonce.len() != SESSION_NONCE_BYTES * 2 || !nonce.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    expires_at.parse::<i64>().ok()
}

/// Parse the request's `Cookie` header into a jar.
fn jar_from_request(request: &Request) -> CookieJar {
    let mut jar = CookieJar::new();
    for value in request.headers().get_all(header::COOKIE) {
        let Ok(raw) = value.to_str() else { continue };
        for cookie in Cookie::split_parse_encoded(raw.to_owned()).flatten() {
            jar.add_original(cookie.into_owned());
        }
    }
    jar
}

/// Authenticate a request against the configured credentials.
pub fn authenticate(state: &Arc<AppState>, request: &Request) -> AuthState {
    if matches!(state.auth_config, AuthConfig::None) {
        return AuthState::Public;
    }
    let jar = jar_from_request(request);
    let Some(cookie) = jar.signed(&state.key).get(SESSION_COOKIE) else {
        return AuthState::Unauthenticated;
    };
    match parse_session_value(cookie.value()) {
        Some(expires_at) if Utc::now().timestamp() < expires_at => AuthState::Authenticated,
        _ => AuthState::Unauthenticated,
    }
}

/// Axum middleware function for authentication.
pub async fn auth_middleware_fn(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> impl IntoResponse {
    match authenticate(&state, &request) {
        AuthState::Public | AuthState::Authenticated => next.run(request).await,
        AuthState::Unauthenticated => {
            // Bounce browsers (GET navigations) to the login form, preserving
            // where they were headed; reject API-style writes with 401.
            if request.method() == Method::GET {
                let next_path = request.uri().path_and_query().map_or_else(
                    || request.uri().path().to_owned(),
                    |pq| pq.as_str().to_owned(),
                );
                let target = format!("/login?next={}", urlencode(&next_path));
                Redirect::to(&target).into_response()
            } else {
                StatusCode::UNAUTHORIZED.into_response()
            }
        }
    }
}

/// Minimal percent-encoding for the `next` query parameter.
fn urlencode(input: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request as HttpRequest;
    use cookie::Key;
    use parking_lot::RwLock;
    use std::path::PathBuf;

    fn create_state(auth_config: AuthConfig, key: Key) -> Arc<AppState> {
        Arc::new(AppState {
            auth_config,
            key,
            data_dir: PathBuf::from("/tmp"),
            scan: Arc::new(RwLock::new(None)),
            seed: 0,
            cache_dir: PathBuf::from("/tmp"),
            thumb_sem: Arc::new(tokio::sync::Semaphore::new(1)),
            cookie_secure: false,
            login_limiter: Arc::new(crate::auth::RateLimiter::new(5, 60)),
        })
    }

    fn some_auth() -> AuthConfig {
        AuthConfig::Some {
            username: "user".to_string(),
            password_hash: bcrypt::hash("pass", 4).unwrap(),
        }
    }

    /// Sign `cookie` with `key` and render it as a browser `Cookie` header value.
    fn signed_header(key: &Key, cookie: Cookie<'static>) -> String {
        let mut jar = CookieJar::new();
        jar.signed_mut(key).add(cookie);
        jar.get(SESSION_COOKIE)
            .unwrap()
            .clone()
            .stripped()
            .encoded()
            .to_string()
    }

    fn request_with_cookie(cookie_header: Option<&str>) -> Request {
        let mut builder = HttpRequest::builder().uri("/").method("GET");
        if let Some(value) = cookie_header {
            builder = builder.header(header::COOKIE, value);
        }
        builder.body(axum::body::Body::empty()).unwrap()
    }

    #[test]
    fn authenticate_public_when_no_auth_config() {
        let state = create_state(AuthConfig::None, Key::generate());
        let request = request_with_cookie(None);
        assert!(matches!(authenticate(&state, &request), AuthState::Public));
    }

    #[test]
    fn authenticate_unauthenticated_when_no_cookie() {
        let state = create_state(some_auth(), Key::generate());
        let request = request_with_cookie(None);
        assert!(matches!(
            authenticate(&state, &request),
            AuthState::Unauthenticated
        ));
    }

    #[test]
    fn authenticate_authenticated_with_valid_cookie() {
        let key = Key::generate();
        let state = create_state(some_auth(), key.clone());
        let header = signed_header(&key, build_session_cookie(false));
        let request = request_with_cookie(Some(&header));
        assert!(matches!(
            authenticate(&state, &request),
            AuthState::Authenticated
        ));
    }

    #[test]
    fn build_session_cookie_sets_secure_when_requested() {
        assert_eq!(Some(true), build_session_cookie(true).secure());
        assert_eq!(Some(false), build_session_cookie(false).secure());
    }

    #[test]
    fn build_session_cookie_value_is_nonce_dot_expiry() {
        let cookie = build_session_cookie(false);
        let (nonce, expires_at) = cookie.value().split_once('.').expect("nonce.expiry");
        assert_eq!(SESSION_NONCE_BYTES * 2, nonce.len());
        assert!(nonce.bytes().all(|b| b.is_ascii_hexdigit()), "{nonce}");

        let expires_at: i64 = expires_at.parse().unwrap();
        let expected = Utc::now().timestamp() + SESSION_TTL_DAYS * 24 * 60 * 60;
        assert!(
            (expires_at - expected).abs() <= 5,
            "{expires_at} vs {expected}"
        );
    }

    #[test]
    fn session_nonces_are_unique() {
        use std::collections::HashSet;
        let nonces: HashSet<String> = (0..100)
            .map(|_| {
                build_session_cookie(false)
                    .value()
                    .split_once('.')
                    .unwrap()
                    .0
                    .to_owned()
            })
            .collect();
        assert_eq!(100, nonces.len());
    }

    /// The pre-nonce cookie value was a bare timestamp. It must be refused even
    /// when correctly signed — upgrading logs sessions out once, by design.
    #[test]
    fn authenticate_rejects_legacy_bare_timestamp_cookie() {
        let key = Key::generate();
        let state = create_state(some_auth(), key.clone());
        let legacy = Cookie::build((SESSION_COOKIE, (Utc::now().timestamp() + 3600).to_string()))
            .path("/")
            .build();
        let header = signed_header(&key, legacy);
        let request = request_with_cookie(Some(&header));
        assert!(matches!(
            authenticate(&state, &request),
            AuthState::Unauthenticated
        ));
    }

    #[test]
    fn parse_session_value_rejects_malformed_shapes() {
        let nonce = "0".repeat(SESSION_NONCE_BYTES * 2);
        assert_eq!(Some(42), parse_session_value(&format!("{nonce}.42")));
        // No separator, short nonce, non-hex nonce, non-numeric expiry.
        assert_eq!(None, parse_session_value("42"));
        assert_eq!(None, parse_session_value("abc.42"));
        assert_eq!(None, parse_session_value(&format!("{}z.42", &nonce[1..])));
        assert_eq!(None, parse_session_value(&format!("{nonce}.soon")));
    }

    #[test]
    fn authenticate_unauthenticated_with_expired_cookie() {
        let key = Key::generate();
        let state = create_state(some_auth(), key.clone());
        let nonce = "0".repeat(SESSION_NONCE_BYTES * 2);
        let expired = Cookie::build((
            SESSION_COOKIE,
            format!("{nonce}.{}", Utc::now().timestamp() - 1),
        ))
        .path("/")
        .build();
        let header = signed_header(&key, expired);
        let request = request_with_cookie(Some(&header));
        assert!(matches!(
            authenticate(&state, &request),
            AuthState::Unauthenticated
        ));
    }

    #[test]
    fn authenticate_unauthenticated_with_tampered_cookie() {
        let state = create_state(some_auth(), Key::generate());
        // A cookie that was never signed with our key.
        let header = format!("{SESSION_COOKIE}=9999999999");
        let request = request_with_cookie(Some(&header));
        assert!(matches!(
            authenticate(&state, &request),
            AuthState::Unauthenticated
        ));
    }

    #[test]
    fn authenticate_unauthenticated_with_cookie_signed_by_other_key() {
        let state = create_state(some_auth(), Key::generate());
        let other_key = Key::generate();
        let header = signed_header(&other_key, build_session_cookie(false));
        let request = request_with_cookie(Some(&header));
        assert!(matches!(
            authenticate(&state, &request),
            AuthState::Unauthenticated
        ));
    }
}
