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
use crate::state::AppState;

/// Name of the signed session cookie.
pub const SESSION_COOKIE: &str = "comics_session";
/// How long a session stays valid after login.
const SESSION_TTL_DAYS: i64 = 7;

/// Authentication state after checking the request.
pub enum AuthState {
    /// No credentials are configured; everything is public.
    Public,
    /// A valid, unexpired session cookie was presented.
    Authenticated,
    /// No valid session cookie was presented.
    Unauthenticated,
}

/// Build a fresh, signed-cookie-ready session cookie whose value is the unix
/// timestamp at which it expires. The signature (added by the caller's
/// [`cookie::SignedJar`]) makes the value unforgeable; the timestamp lets the
/// server enforce expiry independently of the browser.
pub fn build_session_cookie() -> Cookie<'static> {
    let expires_at = Utc::now().timestamp() + SESSION_TTL_DAYS * 24 * 60 * 60;
    Cookie::build((SESSION_COOKIE, expires_at.to_string()))
        .http_only(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(Duration::days(SESSION_TTL_DAYS))
        .build()
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
    match cookie.value().parse::<i64>() {
        Ok(expires_at) if Utc::now().timestamp() < expires_at => AuthState::Authenticated,
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
        let header = signed_header(&key, build_session_cookie());
        let request = request_with_cookie(Some(&header));
        assert!(matches!(
            authenticate(&state, &request),
            AuthState::Authenticated
        ));
    }

    #[test]
    fn authenticate_unauthenticated_with_expired_cookie() {
        let key = Key::generate();
        let state = create_state(some_auth(), key.clone());
        let expired = Cookie::build((SESSION_COOKIE, (Utc::now().timestamp() - 1).to_string()))
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
        let header = signed_header(&other_key, build_session_cookie());
        let request = request_with_cookie(Some(&header));
        assert!(matches!(
            authenticate(&state, &request),
            AuthState::Unauthenticated
        ));
    }
}
