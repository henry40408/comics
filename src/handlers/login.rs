use std::{net::SocketAddr, sync::Arc};

use argon2::{Argon2, PasswordHash, PasswordVerifier as _};
use askama::Template;
use axum::{
    Extension, Form,
    extract::{ConnectInfo, Query, Request, State},
    response::{Html, IntoResponse, Redirect, Response},
};
use cookie::CookieJar;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use serde::Deserialize;
use subtle::{Choice, ConstantTimeEq as _};
use tracing::{error, info, warn};

use crate::assets::assets_version;
use crate::auth::{
    AuthConfig, AuthState, Scope, Throttle, authenticate, build_session_cookie,
    build_session_removal_cookie, rate_limit_key, session_id_of, user_agent,
};
use crate::state::AppState;
use crate::{MAX_PASSWORD_BYTES, VERSION};

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    version: &'static str,
    assets_version: &'static str,
    error: bool,
    next: String,
}

fn default_next() -> String {
    "/".to_string()
}

#[derive(Deserialize)]
pub struct LoginQuery {
    #[serde(default = "default_next")]
    next: String,
}

#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
    #[serde(default = "default_next")]
    next: String,
}

/// Verify `password` against a stored Argon2 PHC string.
///
/// Parameters come from the stored hash ([`Argon2::default`] only supplies the
/// implementation), so raising the cost later needs no migration. An
/// unparseable hash refuses; `ensure_password_hash_is_usable` should have
/// rejected it at startup.
fn verify_password_hash(password: &str, stored: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Check submitted credentials; anything passes when auth is not configured.
///
/// **Both halves always run.** `username == expected && verify(…)` would
/// short-circuit, so a wrong username would answer in microseconds and a wrong
/// password in ~15 ms — a timing oracle enumerating the username (OWASP's
/// "quick exit"). Hence the unconditional verification, the non-branching `&`
/// on [`Choice`], and [`ConstantTimeEq`](subtle::ConstantTimeEq) for the username (which still leaks
/// whether the lengths match).
///
/// Callers must hold a permit from `AppState::verify_sem`: each call allocates
/// 19 MiB (see [`MAX_CONCURRENT_VERIFICATIONS`](crate::MAX_CONCURRENT_VERIFICATIONS)).
pub fn verify_credentials(auth: &AuthConfig, username: &str, password: &str) -> bool {
    match auth {
        AuthConfig::None => true,
        AuthConfig::Some {
            username: expected_user,
            password_hash,
        } => {
            // OWASP's "maximum input length". A branch, but on the attacker's
            // own input, so it leaks nothing. Mirrors `ensure_password_fits` in
            // `main.rs`, so any hashable password verifies.
            if password.len() > MAX_PASSWORD_BYTES {
                return false;
            }
            let username_ok = username.as_bytes().ct_eq(expected_user.as_bytes());
            let password_ok = Choice::from(u8::from(verify_password_hash(password, password_hash)));
            (username_ok & password_ok).into()
        }
    }
}

/// Constrain a post-login redirect target to a local path.
///
/// - **A path, not an authority:** `//evil.example` is protocol-relative, and
///   browsers read `/\evil.example` the same way (WHATWG treats `\` as `/` for
///   http(s)), so the second character must be neither.
/// - **A valid header value:** `next` arrives percent-decoded (`?next=/%0Ax`
///   holds a real newline) and `Redirect::to` *panics* on an invalid
///   `HeaderValue` — reachable anonymously via `GET /login`.
fn safe_next(next: &str) -> String {
    let mut chars = next.chars();
    let is_local_path = chars.next() == Some('/') && !matches!(chars.next(), Some('/' | '\\'));
    if is_local_path && HeaderValue::from_str(next).is_ok() {
        next.to_string()
    } else {
        "/".to_string()
    }
}

fn render_login(error: bool, next: &str) -> Response {
    let template = LoginTemplate {
        version: VERSION,
        assets_version: assets_version(),
        error,
        next: safe_next(next),
    };
    match template.render() {
        Ok(html) => {
            let status = if error {
                StatusCode::UNAUTHORIZED
            } else {
                StatusCode::OK
            };
            let mut response = (status, Html(html)).into_response();
            // Outside the auth layer, so `no_store_html` never sees it; it
            // carries the error state and `next`.
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
                .headers_mut()
                .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
            response
        }
        Err(err) => {
            error!(%err, "failed to render login");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Stamp `Cache-Control: no-store` (plus `Pragma` for HTTP/1.0) on a response.
///
/// For the 303s that set and remove the session cookie: OWASP wants `no-store`
/// on anything carrying a session ID, and `no_store_html` reaches neither
/// (outside the auth layer, and not `text/html`).
fn set_no_store(response: &mut Response) {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
}

/// Open a session and attach its signed cookie, returning the identifier for
/// the audit log's fingerprint.
fn set_session_cookie(response: &mut Response, state: &Arc<AppState>, user_agent: &str) -> String {
    let id = state.sessions.create(user_agent);
    let cookie = build_session_cookie(state.cookie_secure, &id);
    let mut jar = CookieJar::new();
    jar.signed_mut(&state.key).add(cookie);
    for cookie in jar.delta() {
        if let Ok(value) = HeaderValue::from_str(&cookie.encoded().to_string()) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
    id
}

static CLEAR_SITE_DATA: HeaderName = HeaderName::from_static("clear-site-data");

/// The quotes are part of the header grammar — keep them. `"executionContexts"`
/// is omitted: its forced reload would fight logout's own 303.
const CLEAR_SITE_DATA_VALUE: &str = "\"cache\", \"cookies\", \"storage\"";

/// `GET /login` — render the form, or redirect to `next` when auth is disabled
/// or the visitor is already signed in.
pub async fn login_route(
    Query(query): Query<LoginQuery>,
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Response {
    if matches!(state.auth_config, AuthConfig::None)
        || matches!(
            authenticate(&state, &request),
            AuthState::Authenticated { .. }
        )
    {
        return Redirect::to(&safe_next(&query.next)).into_response();
    }
    render_login(false, &query.next)
}

/// `POST /login`. The throttle runs *before* the credential check, so a
/// throttled attempt learns nothing.
///
/// `ConnectInfo` is optional so unit tests can call this directly; `Form` must
/// stay last, as the body extractor.
pub async fn login_submit_route(
    State(state): State<Arc<AppState>>,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let ip = rate_limit_key(
        connect.as_deref().map(|ci| ci.0.ip()),
        &headers,
        &state.trusted_proxies,
    );
    let user_agent = user_agent(&headers);
    if let Throttle::Refused {
        scope,
        retry_after_secs,
    } = state.login_limiter.try_acquire(ip)
    {
        // The global window is an account lockout (the reader is locked out
        // too), so it gets its own event name for alerting.
        if scope == Scope::Global {
            warn!(
                event = "login_lockout",
                retry_after_secs,
                %ip, user_agent,
                "login refused for every client address: the account-wide attempt \
                 budget is spent, which also locks out legitimate sign-ins until \
                 the window passes"
            );
        } else {
            warn!(
                event = "login_rate_limited",
                scope = scope.as_str(),
                retry_after_secs,
                %ip, user_agent,
                "login rate limited"
            );
        }
        let mut response = StatusCode::TOO_MANY_REQUESTS.into_response();
        if let Ok(value) = HeaderValue::from_str(&retry_after_secs.to_string()) {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
        return response;
    }
    // Acquired *after* the throttle, so a refused attempt never queues. The
    // semaphore is never closed; refuse rather than unwrap anyway.
    let Ok(_permit) = state.verify_sem.acquire().await else {
        error!("verification semaphore closed");
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if !verify_credentials(&state.auth_config, &form.username, &form.password) {
        // No credentials: a password typed into the username field would leak.
        warn!(event = "login_failed", %ip, user_agent, "login failed");
        return render_login(true, &form.next);
    }
    // Refund the attempt: only failures count against the windows.
    state.login_limiter.release(ip);
    let mut response = Redirect::to(&safe_next(&form.next)).into_response();
    let id = set_session_cookie(&mut response, &state, user_agent);
    set_no_store(&mut response);
    info!(
        event = "session_created",
        session = state.audit_salt.fingerprint(&id),
        %ip, user_agent, "session created"
    );
    response
}

/// `POST /logout` — end every live session, clear the cookie, redirect to the
/// login form.
///
/// Server-side destruction is what counts; the removal cookie and
/// `Clear-Site-Data` do nothing about a stolen copy. See
/// [`crate::auth::SessionStore::destroy_all`] for why store membership
/// authorises this on a public route.
pub async fn logout_route(
    State(state): State<Arc<AppState>>,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    let ip = rate_limit_key(
        connect.as_deref().map(|ci| ci.0.ip()),
        &headers,
        &state.trusted_proxies,
    );
    let id = session_id_of(&state, &request);
    // Zero means nothing was ended: an expired cookie, a double submit, or an
    // anonymous POST.
    let destroyed = id.as_deref().map_or(0, |id| state.sessions.destroy_all(id));
    let session = id.map_or_else(|| "-".to_string(), |id| state.audit_salt.fingerprint(&id));
    info!(
        event = "session_destroyed",
        session,
        destroyed,
        %ip,
        user_agent = user_agent(&headers),
        "session destroyed"
    );

    let removal = build_session_removal_cookie(state.cookie_secure);
    let mut response = Redirect::to("/login").into_response();
    if let Ok(value) = HeaderValue::from_str(&removal.encoded().to_string()) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    // Drops what the browser already holds (no-store only prevents new
    // entries). Inert outside a secure context, e.g. plain-HTTP LAN.
    response.headers_mut().insert(
        CLEAR_SITE_DATA.clone(),
        HeaderValue::from_static(CLEAR_SITE_DATA_VALUE),
    );
    set_no_store(&mut response);
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::{Mutex, RwLock};
    use std::{path::PathBuf, time::Instant};

    fn some_auth() -> AuthConfig {
        AuthConfig::Some {
            username: "alice".to_string(),
            password_hash: crate::test_password_hash("s3cret"),
        }
    }

    fn test_state() -> Arc<AppState> {
        test_state_with(crate::auth::RateLimiter::new(5, 20, 60))
    }

    fn test_state_with(limiter: crate::auth::RateLimiter) -> Arc<AppState> {
        Arc::new(AppState {
            auth_config: some_auth(),
            key: cookie::Key::generate(),
            data_dir: PathBuf::from("/tmp"),
            scan: Arc::new(RwLock::new(None)),
            seed: 0,
            cache_dir: PathBuf::from("/tmp"),
            thumb_sem: Arc::new(tokio::sync::Semaphore::new(1)),
            verify_sem: Arc::new(tokio::sync::Semaphore::new(1)),
            cookie_secure: false,
            login_limiter: Arc::new(limiter),
            audit_salt: Arc::new(crate::auth::SessionAuditSalt::generate()),
            hsts_max_age: None,
            sessions: Arc::new(crate::auth::SessionStore::new(
                crate::auth::DEFAULT_IDLE_TTL,
                crate::auth::DEFAULT_ABSOLUTE_TTL,
            )),
            trusted_proxies: crate::auth::TrustedProxies::default(),
        })
    }

    /// A `MakeWriter` collecting everything the subscriber emits.
    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// The session identifier in a `Set-Cookie` header: the last 32 characters
    /// of the signed value.
    fn id_from_set_cookie(header: &str) -> String {
        let value = header
            .split_once('=')
            .expect("a name=value pair")
            .1
            .split(';')
            .next()
            .expect("a value");
        value[value.len() - 32..].to_string()
    }

    /// Only a salted hash of the identifier may be logged. The handler is
    /// called directly so the thread-local subscriber sees its events.
    #[tokio::test]
    async fn session_events_do_not_leak_the_cookie_value() {
        let capture = Capture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let state = test_state();
        let response = login_submit_route(
            State(Arc::clone(&state)),
            None,
            HeaderMap::new(),
            Form(LoginForm {
                username: "alice".to_string(),
                password: "s3cret".to_string(),
                next: "/".to_string(),
            }),
        )
        .await;

        let set_cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .expect("a session cookie")
            .to_str()
            .unwrap()
            .to_string();
        let id = id_from_set_cookie(&set_cookie);

        let logs = String::from_utf8(capture.0.lock().clone()).unwrap();
        assert!(logs.contains("session_created"), "{logs}");
        assert!(
            logs.contains(&state.audit_salt.fingerprint(&id)),
            "expected the fingerprint in {logs}"
        );
        assert!(!logs.contains(&id), "identifier leaked into {logs}");
    }

    #[tokio::test]
    async fn failed_login_logs_no_credentials() {
        let capture = Capture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let response = login_submit_route(
            State(test_state()),
            None,
            HeaderMap::new(),
            Form(LoginForm {
                username: "alice".to_string(),
                password: "hunter2".to_string(),
                next: "/".to_string(),
            }),
        )
        .await;
        assert_eq!(StatusCode::UNAUTHORIZED, response.status());

        let logs = String::from_utf8(capture.0.lock().clone()).unwrap();
        assert!(logs.contains("login_failed"), "{logs}");
        assert!(!logs.contains("hunter2"), "password leaked into {logs}");
        assert!(!logs.contains("alice"), "username leaked into {logs}");
    }

    #[test]
    fn verify_credentials_accepts_correct_pair() {
        assert!(verify_credentials(&some_auth(), "alice", "s3cret"));
    }

    #[test]
    fn verify_credentials_rejects_wrong_password() {
        assert!(!verify_credentials(&some_auth(), "alice", "nope"));
    }

    #[test]
    fn verify_credentials_rejects_wrong_username() {
        assert!(!verify_credentials(&some_auth(), "bob", "s3cret"));
    }

    #[test]
    fn verify_credentials_public_when_unconfigured() {
        assert!(verify_credentials(&AuthConfig::None, "", ""));
    }

    /// The route must not depend on `ensure_password_hash_is_usable` having run.
    #[test]
    fn an_unusable_stored_hash_refuses_every_password() {
        for stored in ["", "not-a-hash", "$argon2id$v=19$m=19456$nope"] {
            let auth = AuthConfig::Some {
                username: "alice".to_string(),
                password_hash: stored.to_string(),
            };
            assert!(!verify_credentials(&auth, "alice", "s3cret"), "{stored:?}");
            assert!(!verify_credentials(&auth, "alice", ""), "{stored:?}");
        }
    }

    fn wrong_password() -> Form<LoginForm> {
        Form(LoginForm {
            username: "alice".to_string(),
            password: "nope".to_string(),
            next: "/".to_string(),
        })
    }

    fn captured(capture: &Capture) -> String {
        String::from_utf8(capture.0.lock().clone()).expect("utf-8 logs")
    }

    /// Operators' filters match on the event name; `scope` names the window.
    #[tokio::test]
    async fn a_per_ip_throttle_keeps_its_event_name() {
        let capture = Capture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let state = test_state_with(crate::auth::RateLimiter::new(1, 100, 60));
        let first = login_submit_route(
            State(Arc::clone(&state)),
            None,
            HeaderMap::new(),
            wrong_password(),
        )
        .await;
        assert_eq!(StatusCode::UNAUTHORIZED, first.status());

        let second = login_submit_route(
            State(Arc::clone(&state)),
            None,
            HeaderMap::new(),
            wrong_password(),
        )
        .await;
        assert_eq!(StatusCode::TOO_MANY_REQUESTS, second.status());

        let logs = captured(&capture);
        assert!(logs.contains("login_rate_limited"), "{logs}");
        assert!(logs.contains("per_ip"), "{logs}");
        assert!(!logs.contains("login_lockout"), "{logs}");
    }

    #[tokio::test]
    async fn a_global_lockout_logs_its_own_event() {
        let capture = Capture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let state = test_state_with(crate::auth::RateLimiter::new(100, 1, 60));
        let first = login_submit_route(
            State(Arc::clone(&state)),
            None,
            HeaderMap::new(),
            wrong_password(),
        )
        .await;
        assert_eq!(StatusCode::UNAUTHORIZED, first.status());

        let second = login_submit_route(
            State(Arc::clone(&state)),
            None,
            HeaderMap::new(),
            wrong_password(),
        )
        .await;
        assert_eq!(StatusCode::TOO_MANY_REQUESTS, second.status());

        let logs = captured(&capture);
        assert!(logs.contains("login_lockout"), "{logs}");
        assert!(
            !logs.contains("login_rate_limited"),
            "the lockout was logged as an ordinary throttle: {logs}"
        );
    }

    #[tokio::test]
    async fn a_throttled_login_says_when_to_retry() {
        let state = test_state_with(crate::auth::RateLimiter::new(1, 100, 60));
        login_submit_route(
            State(Arc::clone(&state)),
            None,
            HeaderMap::new(),
            wrong_password(),
        )
        .await;

        let response = login_submit_route(
            State(Arc::clone(&state)),
            None,
            HeaderMap::new(),
            wrong_password(),
        )
        .await;
        assert_eq!(StatusCode::TOO_MANY_REQUESTS, response.status());

        let value = response
            .headers()
            .get(header::RETRY_AFTER)
            .expect("a Retry-After header")
            .to_str()
            .expect("an ASCII header value");
        let seconds: u64 = value.parse().expect("delta-seconds");
        // Never zero — that would invite an immediate retry into the same refusal.
        assert!((1..=60).contains(&seconds), "Retry-After: {seconds}");
    }

    /// A server fault must not read as a wrong password, or the reader keeps
    /// retyping a correct one.
    #[tokio::test]
    async fn a_closed_verification_semaphore_is_not_reported_as_a_bad_password() {
        let state = test_state();
        state.verify_sem.close();

        let response = login_submit_route(
            State(Arc::clone(&state)),
            None,
            HeaderMap::new(),
            Form(LoginForm {
                username: "alice".to_string(),
                password: "s3cret".to_string(),
                next: "/".to_string(),
            }),
        )
        .await;

        assert_eq!(StatusCode::SERVICE_UNAVAILABLE, response.status());
    }

    /// Guards against a short-circuiting check. Even the cheap test hash is
    /// orders of magnitude above a string comparison, so the ratio does not need
    /// a quiet machine.
    #[test]
    fn wrong_username_costs_what_a_wrong_password_costs() {
        let auth = AuthConfig::Some {
            username: "alice".to_string(),
            password_hash: crate::test_password_hash("s3cret"),
        };

        let started = Instant::now();
        assert!(!verify_credentials(&auth, "alice", "nope"));
        let wrong_password = started.elapsed();

        let started = Instant::now();
        assert!(!verify_credentials(&auth, "mallory", "nope"));
        let wrong_username = started.elapsed();

        assert!(
            wrong_username * 4 >= wrong_password,
            "a wrong username took {wrong_username:?} against {wrong_password:?} \
             for a wrong password — the credential check is short-circuiting"
        );
    }

    /// Every byte counts — no bcrypt-style 72-byte truncation.
    #[test]
    fn a_long_password_is_not_merely_its_own_prefix() {
        let password = "x".repeat(100);
        let auth = AuthConfig::Some {
            username: "alice".to_string(),
            password_hash: crate::test_password_hash(&password),
        };
        assert!(verify_credentials(&auth, "alice", &password));
        assert!(!verify_credentials(
            &auth,
            "alice",
            &format!("{password}extra")
        ));
        assert!(!verify_credentials(&auth, "alice", &"x".repeat(99)));
    }

    /// Three bytes per character: a 72-byte ceiling would stop at 24.
    #[test]
    fn a_chinese_passphrase_is_not_cut_short() {
        let password = "密".repeat(100);
        assert_eq!(300, password.len());
        assert!(password.len() < MAX_PASSWORD_BYTES);
        let auth = AuthConfig::Some {
            username: "alice".to_string(),
            password_hash: crate::test_password_hash(&password),
        };
        assert!(verify_credentials(&auth, "alice", &password));
        assert!(!verify_credentials(&auth, "alice", &"密".repeat(99)));
    }

    #[test]
    fn a_password_past_the_ceiling_is_refused() {
        let password = "x".repeat(MAX_PASSWORD_BYTES);
        let auth = AuthConfig::Some {
            username: "alice".to_string(),
            password_hash: crate::test_password_hash(&password),
        };
        assert!(verify_credentials(&auth, "alice", &password));
        assert!(!verify_credentials(
            &auth,
            "alice",
            &"x".repeat(MAX_PASSWORD_BYTES + 1)
        ));
    }

    #[test]
    fn safe_next_allows_local_paths() {
        assert_eq!(safe_next("/book/abc"), "/book/abc");
        assert_eq!(safe_next("/"), "/");
    }

    #[test]
    fn safe_next_blocks_open_redirects() {
        assert_eq!(safe_next("//evil.example"), "/");
        assert_eq!(safe_next("https://evil.example"), "/");
        assert_eq!(safe_next("javascript:alert(1)"), "/");
    }

    #[test]
    fn safe_next_blocks_backslash_authorities() {
        for target in [
            r"/\evil.example",
            r"/\/evil.example",
            r"/\\evil.example",
            r"/\evil.example/path",
        ] {
            assert_eq!(safe_next(target), "/", "{target} was accepted");
        }
        assert_eq!(safe_next(r"\evil.example"), "/");
    }

    #[test]
    fn safe_next_rejects_values_a_header_cannot_carry() {
        for target in ["/foo\nbar", "/foo\rbar", "/foo\r\nSet-Cookie: x=y", "/\0"] {
            assert_eq!(safe_next(target), "/", "{target:?} was accepted");
        }
    }

    /// `next` from the auth middleware is percent-encoded, so always ASCII.
    #[test]
    fn safe_next_still_accepts_ordinary_paths() {
        for target in ["/", "/book/1f1c111677715adf", "/book/abc?page=2", "/a%20b"] {
            assert_eq!(safe_next(target), target, "{target} was rejected");
        }
    }
}
