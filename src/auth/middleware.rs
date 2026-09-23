use std::sync::Arc;

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Redirect},
};
use cookie::{Cookie, CookieJar, SameSite, time::Duration};
use http::{HeaderMap, Method, StatusCode, header};
use tracing::{debug, info, warn};

use super::config::AuthConfig;
use super::session::{DEFAULT_ABSOLUTE_TTL, Expiry, Validation, is_session_id};
use crate::state::AppState;

/// Base name of the signed session cookie, without the `__Host-` prefix.
pub const SESSION_COOKIE: &str = "comics_session";
const SESSION_COOKIE_HOST_PREFIXED: &str = "__Host-comics_session";

/// Cookie name, `__Host-`-prefixed when `secure`.
///
/// The prefix has the browser guarantee a host-only, HTTPS, `Path=/` cookie,
/// closing subdomain overwrites as a session-fixation vector. **Only when
/// `secure`**: browsers reject a `__Host-` cookie without `Secure`, which would
/// silently break login on plain-HTTP LAN hosts.
pub fn session_cookie_name(secure: bool) -> &'static str {
    if secure {
        SESSION_COOKIE_HOST_PREFIXED
    } else {
        SESSION_COOKIE
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthState {
    /// No credentials are configured; everything is public.
    Public,
    /// The cookie named a live session.
    Authenticated {
        /// Worth logging, never acting on; see [`super::Validation`].
        user_agent_changed: bool,
    },
    Unauthenticated(Rejection),
}

/// Why a request was treated as unauthenticated. The reasons are logged at
/// different levels: a bad signature cannot happen by accident, while every
/// legitimate cookie becomes unknown after a restart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejection {
    Absent,
    /// Not signed by this key: forged, or from a different `COMICS_SECRET`.
    BadSignature,
    /// Correctly signed, but not the shape this version issues.
    Malformed,
    /// Names no live session.
    Unknown,
    /// The session was live and has just been ended.
    Expired(Expiry),
}

/// The value is the store's opaque identifier and nothing else.
///
/// It is still signed: not for validity (the store decides that) but to tell a
/// forged cookie from a stale one, and to reject junk before the store's lock.
///
/// `secure` is configurable because browsers silently discard a `Secure` cookie
/// over plain HTTP, which would lock LAN deployments out with no visible error.
///
/// `SameSite=Strict` is affordable here (no OAuth or third-party entry points);
/// the cost is that an external link to a book lands on the login form once.
///
/// `Max-Age` is a browser hint only; the server enforces both deadlines.
pub fn build_session_cookie(secure: bool, id: &str) -> Cookie<'static> {
    Cookie::build((session_cookie_name(secure), id.to_owned()))
        .http_only(true)
        .same_site(SameSite::Strict)
        .path("/")
        .secure(secure)
        .max_age(
            Duration::try_from(DEFAULT_ABSOLUTE_TTL).expect("the absolute TTL fits a cookie age"),
        )
        .build()
}

/// Every attribute must mirror [`build_session_cookie`]: browsers match a
/// removal on name, `Path` and `Domain`, and reject a `__Host-` name without
/// `Secure`.
pub fn build_session_removal_cookie(secure: bool) -> Cookie<'static> {
    Cookie::build((session_cookie_name(secure), ""))
        .http_only(true)
        .same_site(SameSite::Strict)
        .path("/")
        .secure(secure)
        .max_age(Duration::ZERO)
        .build()
}

/// The verified session identifier from the request's cookie. **Never log it
/// directly** — hash it with [`crate::auth::SessionAuditSalt`].
pub fn session_id_of(state: &Arc<AppState>, request: &Request) -> Option<String> {
    let jar = jar_from_request(request);
    let cookie = jar
        .signed(&state.key)
        .get(session_cookie_name(state.cookie_secure))?;
    is_session_id(cookie.value()).then(|| cookie.value().to_owned())
}

/// Absent or non-ASCII values become `-`, so every audit event carries the
/// field and the store always has something stable to compare.
pub fn user_agent(headers: &HeaderMap) -> &str {
    headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("-")
}

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

/// Three gates, cheapest first: signature, identifier shape, then the store —
/// the only one that takes a lock or can say the session is *live*.
pub fn authenticate(state: &Arc<AppState>, request: &Request) -> AuthState {
    if matches!(state.auth_config, AuthConfig::None) {
        return AuthState::Public;
    }
    // Exactly one name is accepted: taking the unprefixed one too once `Secure`
    // is on would cancel the `__Host-` guarantee.
    let name = session_cookie_name(state.cookie_secure);
    let jar = jar_from_request(request);
    let Some(cookie) = jar.signed(&state.key).get(name) else {
        // Only the unverified jar can tell "absent" from "badly signed".
        return AuthState::Unauthenticated(if jar.get(name).is_some() {
            Rejection::BadSignature
        } else {
            Rejection::Absent
        });
    };
    if !is_session_id(cookie.value()) {
        return AuthState::Unauthenticated(Rejection::Malformed);
    }
    match state
        .sessions
        .validate(cookie.value(), user_agent(request.headers()))
    {
        Validation::Valid { user_agent_changed } => AuthState::Authenticated { user_agent_changed },
        Validation::Unknown => AuthState::Unauthenticated(Rejection::Unknown),
        Validation::Expired(why) => AuthState::Unauthenticated(Rejection::Expired(why)),
    }
}

/// `Absent` is silent (ordinary anonymous visit). `Unknown` is `DEBUG`, since
/// every cookie becomes unknown on restart. `BadSignature` and `Malformed`
/// cannot happen by accident, so they `WARN`.
fn record_rejection(state: &Arc<AppState>, request: &Request, why: Rejection) {
    let user_agent = user_agent(request.headers());
    let session = session_id_of(state, request)
        .map_or_else(|| "-".to_string(), |id| state.audit_salt.fingerprint(&id));
    match why {
        Rejection::Absent => {}
        Rejection::Expired(expiry) => info!(
            event = "session_expired",
            session,
            reason = expiry.as_str(),
            user_agent,
            "session expired"
        ),
        Rejection::BadSignature => warn!(
            event = "session_rejected",
            reason = "bad_signature",
            user_agent,
            "session cookie was not signed by this key"
        ),
        Rejection::Malformed => warn!(
            event = "session_rejected",
            reason = "malformed",
            user_agent,
            "session cookie is not a session identifier"
        ),
        Rejection::Unknown => debug!(
            event = "session_rejected",
            session,
            reason = "unknown",
            user_agent,
            "session cookie names no live session"
        ),
    }
}

pub async fn auth_middleware_fn(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> impl IntoResponse {
    match authenticate(&state, &request) {
        AuthState::Public => next.run(request).await,
        AuthState::Authenticated { user_agent_changed } => {
            if user_agent_changed {
                // Reported, never enforced; see `Validation::Valid`.
                warn!(
                    event = "session_user_agent_changed",
                    session = session_id_of(&state, &request)
                        .map_or_else(|| "-".to_string(), |id| state.audit_salt.fingerprint(&id)),
                    user_agent = user_agent(request.headers()),
                    "User-Agent changed mid-session"
                );
            }
            next.run(request).await
        }
        AuthState::Unauthenticated(why) => {
            record_rejection(&state, &request, why);
            // Redirect navigations; other methods get a bare 401.
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
            verify_sem: Arc::new(tokio::sync::Semaphore::new(1)),
            cookie_secure: false,
            login_limiter: Arc::new(crate::auth::RateLimiter::new(5, 20, 60)),
            audit_salt: Arc::new(crate::auth::SessionAuditSalt::generate()),
            hsts_max_age: None,
            sessions: Arc::new(crate::auth::SessionStore::new(
                crate::auth::DEFAULT_IDLE_TTL,
                crate::auth::DEFAULT_ABSOLUTE_TTL,
            )),
            trusted_proxies: crate::auth::TrustedProxies::default(),
        })
    }

    fn some_auth() -> AuthConfig {
        AuthConfig::Some {
            username: "user".to_string(),
            password_hash: crate::test_password_hash("pass"),
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

    /// A request whose cookie is correctly signed and names `id`.
    fn request_for(key: &Key, id: &str) -> Request {
        let header = signed_header(key, build_session_cookie(false, id));
        request_with_cookie(Some(&header))
    }

    #[test]
    fn authenticate_public_when_no_auth_config() {
        let state = create_state(AuthConfig::None, Key::generate());
        let request = request_with_cookie(None);
        assert!(matches!(authenticate(&state, &request), AuthState::Public));
    }

    #[test]
    fn authenticate_authenticated_for_a_live_session() {
        let key = Key::generate();
        let state = create_state(some_auth(), key.clone());
        let id = state.sessions.create("test-agent");
        let request = request_for(&key, &id);
        assert!(matches!(
            authenticate(&state, &request),
            AuthState::Authenticated { .. }
        ));
    }

    #[test]
    fn authenticate_rejects_a_destroyed_session() {
        let key = Key::generate();
        let state = create_state(some_auth(), key.clone());
        let id = state.sessions.create("test-agent");
        let request = request_for(&key, &id);

        assert!(matches!(
            authenticate(&state, &request),
            AuthState::Authenticated { .. }
        ));
        assert!(state.sessions.destroy(&id));
        assert_eq!(
            AuthState::Unauthenticated(Rejection::Unknown),
            authenticate(&state, &request)
        );
    }

    #[test]
    fn authenticate_reports_why_it_refused() {
        let key = Key::generate();
        let state = create_state(some_auth(), key.clone());

        assert_eq!(
            AuthState::Unauthenticated(Rejection::Absent),
            authenticate(&state, &request_with_cookie(None))
        );

        // Right name, never signed by this key.
        let forged = format!("{SESSION_COOKIE}={}", "a".repeat(32));
        assert_eq!(
            AuthState::Unauthenticated(Rejection::BadSignature),
            authenticate(&state, &request_with_cookie(Some(&forged)))
        );

        // Correctly signed, but not an identifier shape.
        let malformed = signed_header(
            &key,
            Cookie::build((SESSION_COOKIE, "not-an-id"))
                .path("/")
                .build(),
        );
        assert_eq!(
            AuthState::Unauthenticated(Rejection::Malformed),
            authenticate(&state, &request_with_cookie(Some(&malformed)))
        );

        // Well-formed and correctly signed, but never issued.
        assert_eq!(
            AuthState::Unauthenticated(Rejection::Unknown),
            authenticate(&state, &request_for(&key, &"0".repeat(32)))
        );
    }

    #[test]
    fn authenticate_rejects_the_legacy_nonce_dot_expiry_cookie() {
        let key = Key::generate();
        let state = create_state(some_auth(), key.clone());
        let legacy = format!("{}.{}", "0".repeat(32), 9_999_999_999i64);
        let header = signed_header(
            &key,
            Cookie::build((SESSION_COOKIE, legacy)).path("/").build(),
        );
        assert_eq!(
            AuthState::Unauthenticated(Rejection::Malformed),
            authenticate(&state, &request_with_cookie(Some(&header)))
        );
    }

    #[test]
    fn authenticate_rejects_a_cookie_signed_by_another_key() {
        let state = create_state(some_auth(), Key::generate());
        let id = state.sessions.create("test-agent");
        let request = request_for(&Key::generate(), &id);
        assert_eq!(
            AuthState::Unauthenticated(Rejection::BadSignature),
            authenticate(&state, &request)
        );
    }

    #[test]
    fn authenticate_surfaces_a_changed_user_agent_without_refusing() {
        let key = Key::generate();
        let state = create_state(some_auth(), key.clone());
        let id = state.sessions.create("original-agent");

        let header = signed_header(&key, build_session_cookie(false, &id));
        let request = HttpRequest::builder()
            .uri("/")
            .method("GET")
            .header(header::COOKIE, header)
            .header(header::USER_AGENT, "a-different-agent")
            .body(axum::body::Body::empty())
            .unwrap();

        assert_eq!(
            AuthState::Authenticated {
                user_agent_changed: true
            },
            authenticate(&state, &request)
        );
    }

    #[test]
    fn build_session_cookie_sets_secure_when_requested() {
        assert_eq!(Some(true), build_session_cookie(true, "id").secure());
        assert_eq!(Some(false), build_session_cookie(false, "id").secure());
    }

    #[test]
    fn session_cookie_name_is_prefixed_only_when_secure() {
        assert_eq!("__Host-comics_session", session_cookie_name(true));
        assert_eq!("comics_session", session_cookie_name(false));
    }

    #[test]
    fn build_session_cookie_uses_the_prefixed_name_when_secure() {
        assert_eq!(
            "__Host-comics_session",
            build_session_cookie(true, "id").name()
        );
        assert_eq!("comics_session", build_session_cookie(false, "id").name());
    }

    #[test]
    fn build_session_cookie_value_is_the_bare_identifier() {
        let id = "0123456789abcdef0123456789abcdef";
        let cookie = build_session_cookie(false, id);
        assert_eq!(id, cookie.value());
        assert!(is_session_id(cookie.value()));
    }

    #[test]
    fn authenticate_rejects_unprefixed_cookie_when_secure_is_on() {
        let key = Key::generate();
        let mut state = create_state(some_auth(), key.clone());
        let id = Arc::get_mut(&mut state)
            .unwrap()
            .sessions
            .create("test-agent");
        Arc::get_mut(&mut state).unwrap().cookie_secure = true;

        let request = request_for(&key, &id);
        assert_eq!(
            AuthState::Unauthenticated(Rejection::Absent),
            authenticate(&state, &request)
        );
    }

    #[test]
    fn removal_cookie_mirrors_the_session_cookie() {
        for secure in [false, true] {
            let issued = build_session_cookie(secure, "id");
            let removal = build_session_removal_cookie(secure);
            assert_eq!(issued.name(), removal.name(), "secure={secure}");
            assert_eq!(issued.path(), removal.path(), "secure={secure}");
            assert_eq!(issued.http_only(), removal.http_only(), "secure={secure}");
            assert_eq!(issued.same_site(), removal.same_site(), "secure={secure}");
            assert_eq!(issued.secure(), removal.secure(), "secure={secure}");
            assert_eq!(issued.domain(), removal.domain(), "secure={secure}");
            assert_eq!("", removal.value(), "secure={secure}");
            assert_eq!(Some(Duration::ZERO), removal.max_age(), "secure={secure}");
        }
    }

    #[test]
    fn session_id_of_returns_the_identifier_it_was_given() {
        let key = Key::generate();
        let state = create_state(some_auth(), key.clone());
        let id = state.sessions.create("test-agent");
        assert_eq!(
            Some(id.clone()),
            session_id_of(&state, &request_for(&key, &id))
        );
        assert_eq!(None, session_id_of(&state, &request_with_cookie(None)));
    }

    #[test]
    fn user_agent_falls_back_to_a_placeholder() {
        let mut headers = HeaderMap::new();
        assert_eq!("-", user_agent(&headers));
        headers.insert(header::USER_AGENT, "curl/8.0".parse().unwrap());
        assert_eq!("curl/8.0", user_agent(&headers));
    }
}
