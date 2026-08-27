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

/// Cookie name with the `__Host-` prefix applied when it is legal to do so.
///
/// The prefix makes the browser itself guarantee the cookie was set by this
/// exact host, over HTTPS, with `Path=/` and no `Domain` — closing off subdomain
/// overwrites as a session-fixation vector (RFC 6265bis, quoted by the OWASP
/// Session Management Cheat Sheet under "Cookie Prefixes"). **Conditional on
/// `secure`**: a browser rejects a `__Host-` cookie arriving without `Secure`,
/// so applying it unconditionally would silently break login on the plain-HTTP
/// LAN deployment the configurable `Secure` exists for.
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
        /// The `User-Agent` changed since the last request on this session.
        /// Worth recording; never worth acting on. See [`super::SessionStore`].
        user_agent_changed: bool,
    },
    Unauthenticated(Rejection),
}

/// Why a request was treated as unauthenticated.
///
/// Not a plain boolean because the reasons differ enormously: a bad signature
/// cannot happen by accident, while an unknown identifier is what every
/// legitimate cookie becomes after a restart. One level would either bury the
/// first or cry wolf about the second.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejection {
    /// No session cookie at all — an anonymous visitor.
    Absent,
    /// A cookie of the right name that this server's key did not sign: forged,
    /// tampered with, or left over from a different `COMICS_SECRET`.
    BadSignature,
    /// Correctly signed, but not the shape this version issues.
    Malformed,
    /// Well-formed, but names no live session: already destroyed, long expired,
    /// or issued by a previous process.
    Unknown,
    /// The session was live and has just been ended for this reason.
    Expired(Expiry),
}

/// The value is the store's opaque identifier and nothing else — 128 CSPRNG
/// bits as hex, no expiry, no username, no structure, which is what the OWASP
/// Session Management Cheat Sheet asks under "Session ID Content". Everything
/// needed to judge the session lives in [`super::SessionStore`].
///
/// The signature stays even though the identifier is looked up rather than
/// parsed: it is not what makes the session valid, it is what separates a forged
/// cookie from a stale one — an alert worth acting on from the noise every
/// restart produces — and it rejects junk before the store's lock is touched.
///
/// `secure` comes from `--cookie-secure` rather than being hardcoded: a browser
/// silently discards a `Secure` cookie sent over plain HTTP, so forcing it on
/// would lock LAN deployments out of the login form with no visible error.
///
/// `SameSite=Strict` is the cheat sheet's preference, and comics can afford it
/// where a general web application cannot: no OAuth callback, no payment return,
/// no third party navigating *into* an authenticated URL. The cost is that an
/// external link to a book lands on the login form even while signed in, since
/// the browser withholds the cookie on that first cross-site navigation; the
/// next same-site one carries it. `Lax` would avoid that at the price of sending
/// the cookie on every top-level cross-site GET.
///
/// `Max-Age` mirrors the store's absolute ceiling, as a browser hint only — the
/// server enforces both deadlines itself.
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

/// A browser matches a removal cookie on name + `Path` + `Domain`, and rejects a
/// `__Host-` name missing `Secure`, so every attribute must mirror the issued
/// cookie. Kept below `build_session_cookie` so divergence shows up in review.
pub fn build_session_removal_cookie(secure: bool) -> Cookie<'static> {
    Cookie::build((session_cookie_name(secure), ""))
        .http_only(true)
        .same_site(SameSite::Strict)
        .path("/")
        .secure(secure)
        .max_age(Duration::ZERO)
        .build()
}

/// Exposed so logout can both end the session and fingerprint it for the audit
/// log without the handler having to know about jars or signatures. **Never log
/// the value directly** — hash it with [`crate::auth::SessionAuditSalt`].
pub fn session_id_of(state: &Arc<AppState>, request: &Request) -> Option<String> {
    let jar = jar_from_request(request);
    let cookie = jar
        .signed(&state.key)
        .get(session_cookie_name(state.cookie_secure))?;
    is_session_id(cookie.value()).then(|| cookie.value().to_owned())
}

/// Absent or non-ASCII values become `-` rather than being dropped, so every
/// audit event carries the field and the session store always has something
/// stable to compare against.
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

/// Three gates, cheapest first: the signature, the identifier's shape, then the
/// store. Only the last takes a lock, and only it can say the session is *live*
/// — which is what makes logout effective.
pub fn authenticate(state: &Arc<AppState>, request: &Request) -> AuthState {
    if matches!(state.auth_config, AuthConfig::None) {
        return AuthState::Public;
    }
    // Exactly one name is accepted, the one the current configuration issues.
    // Accepting both would let an unprefixed cookie keep working after `Secure`
    // is enabled, cancelling out the guarantee the prefix buys.
    let name = session_cookie_name(state.cookie_secure);
    let jar = jar_from_request(request);
    let Some(cookie) = jar.signed(&state.key).get(name) else {
        // The signed jar cannot tell "absent" from "badly signed", but the
        // unverified jar can, and the two mean completely different things.
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

/// The level is chosen to match what each rejection actually says.
///
/// `Absent` is silent: an anonymous visitor on a protected URL is the ordinary
/// case. `Unknown` is `DEBUG` because every valid cookie becomes unknown when
/// the process restarts, so warning would bury the log after every upgrade. The
/// two that cannot arise by accident — a cookie this key did not sign, and one
/// shaped like nothing this version issues — are `WARN`, the OWASP *Detecting
/// Session ID Anomalies* signal worth alerting on.
fn record_rejection(state: &Arc<AppState>, request: &Request, why: Rejection) {
    let user_agent = user_agent(request.headers());
    // Only ever a salted hash: the identifier itself must never reach the log.
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
                // Reported once per change — the store swaps the digest in — and
                // never enforced. See `SessionStore` for why terminating here
                // would cost more than it buys.
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
            // A GET is a browser navigation, so send it somewhere useful; any
            // other method is an API-style write, which gets a bare 401.
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

    /// The change this module exists for: once the store forgets the session,
    /// the very same cookie stops working. A signed self-describing cookie
    /// stayed valid until its own expiry.
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

    /// Each rejection reason must be distinguishable: they are logged at
    /// different levels precisely because they mean different things.
    #[test]
    fn authenticate_reports_why_it_refused() {
        let key = Key::generate();
        let state = create_state(some_auth(), key.clone());

        // No cookie at all.
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

    /// The pre-store cookie value was `<nonce>.<expiry>`, refused even when
    /// correctly signed: upgrading logs existing sessions out once, by design,
    /// and the value carries an expiry the server no longer honours.
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

    /// A changed `User-Agent` is surfaced but still authenticates.
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

    /// The cookie carries the identifier and nothing else — no expiry, no
    /// username, nothing to decode.
    #[test]
    fn build_session_cookie_value_is_the_bare_identifier() {
        let id = "0123456789abcdef0123456789abcdef";
        let cookie = build_session_cookie(false, id);
        assert_eq!(id, cookie.value());
        assert!(is_session_id(cookie.value()));
    }

    /// Once `Secure` is on, an unprefixed cookie must stop being accepted —
    /// otherwise the `__Host-` guarantee buys nothing.
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

    /// The removal cookie only deletes the real one if every matching attribute
    /// agrees, so this fails the moment `build_session_cookie` changes an
    /// attribute without the removal path following.
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
