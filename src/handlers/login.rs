use std::{net::SocketAddr, sync::Arc};

use askama::Template;
use axum::{
    Extension, Form,
    extract::{ConnectInfo, Query, Request, State},
    response::{Html, IntoResponse, Redirect, Response},
};
use cookie::CookieJar;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use serde::Deserialize;
use tracing::{error, info, warn};

use crate::VERSION;
use crate::assets::assets_version;
use crate::auth::{
    AuthConfig, AuthState, authenticate, build_session_cookie, build_session_removal_cookie,
    rate_limit_key, session_id_of, user_agent,
};
use crate::state::AppState;

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

/// Check submitted credentials against the configured ones. When no credentials
/// are configured every request is already public, so anything is accepted.
pub fn verify_credentials(auth: &AuthConfig, username: &str, password: &str) -> bool {
    match auth {
        AuthConfig::None => true,
        AuthConfig::Some {
            username: expected_user,
            password_hash,
        } => username == expected_user && bcrypt::verify(password, password_hash).unwrap_or(false),
    }
}

/// Constrain a post-login redirect target to a local path, blocking open
/// redirects to absolute URLs or protocol-relative `//host` targets.
fn safe_next(next: &str) -> String {
    if next.starts_with('/') && !next.starts_with("//") {
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
            // The login page sits outside the auth layer, so the `no_store_html`
            // middleware never sees it — and it must not be cached either: it
            // carries the error state and the `next` target.
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

/// Open a session and attach its signed cookie to a response, returning the
/// identifier so the caller can record a fingerprint of it in the audit log.
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

/// `Clear-Site-Data` is not in `http`'s constant list, so name it here.
static CLEAR_SITE_DATA: HeaderName = HeaderName::from_static("clear-site-data");

/// The quotes are part of the grammar — each directive is a quoted string — so
/// they must survive any future tidy-up of this literal.
///
/// `"executionContexts"` is deliberately omitted: it forces a reload of the
/// browsing context, which duplicates and can interfere with the 303 to
/// `/login` that logout already performs.
const CLEAR_SITE_DATA_VALUE: &str = "\"cache\", \"cookies\", \"storage\"";

/// `GET /login` — render the login form. Skips it (redirecting home) when auth
/// is disabled or the visitor already holds a valid session.
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

/// `POST /login` — verify credentials and, on success, issue a session cookie.
///
/// Failed attempts are throttled per client IP, and the throttle is consulted
/// *before* the credential check, so a throttled attacker cannot learn anything
/// from the response either.
/// `Option<Extension<ConnectInfo<…>>>` keeps the handler usable from unit tests
/// that build a request without the connection info; `Form` must stay last, as
/// the body extractor.
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
    if !state.login_limiter.try_acquire(ip) {
        warn!(
            event = "login_rate_limited",
            %ip, user_agent, "login rate limited"
        );
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    if !verify_credentials(&state.auth_config, &form.username, &form.password) {
        // Deliberately no username or password in the event: a failed login is
        // exactly where a mistyped password lands in the log otherwise.
        warn!(event = "login_failed", %ip, user_agent, "login failed");
        return render_login(true, &form.next);
    }
    // The reservation is taken before the ~100 ms bcrypt comparison so that
    // concurrent guesses cannot all slip past a stale count; only failures keep
    // it, so signing in repeatedly never exhausts the window.
    state.login_limiter.release(ip);
    let mut response = Redirect::to(&safe_next(&form.next)).into_response();
    let id = set_session_cookie(&mut response, &state, user_agent);
    info!(
        event = "session_created",
        session = state.audit_salt.fingerprint(&id),
        %ip, user_agent, "session created"
    );
    response
}

/// `POST /logout` — end the session, clear its cookie, and return to the login
/// form.
///
/// The session is destroyed **server-side** first. That is the half the OWASP
/// Session Expiration guidance calls mandatory and the half a cookie-only
/// implementation cannot do: the removal cookie and `Clear-Site-Data` below only
/// ask the browser to forget, which does nothing about a copy taken earlier.
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
    // `destroyed` distinguishes ending a live session from a logout that had
    // nothing to end (an already-expired cookie, a double submit).
    let destroyed = id.as_deref().is_some_and(|id| state.sessions.destroy(id));
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
    // Ask the browser to drop what it already holds for this origin, which is
    // the client-side half of what the OWASP Logout guidance requires (the
    // no-store headers only stop new entries from being written). Browsers act
    // on this only in a secure context, so it is inert on a plain-HTTP LAN
    // deployment — harmless, just ineffective there.
    response.headers_mut().insert(
        CLEAR_SITE_DATA.clone(),
        HeaderValue::from_static(CLEAR_SITE_DATA_VALUE),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::{Mutex, RwLock};
    use std::path::PathBuf;

    fn some_auth() -> AuthConfig {
        AuthConfig::Some {
            username: "alice".to_string(),
            password_hash: bcrypt::hash("s3cret", 4).unwrap(),
        }
    }

    fn test_state() -> Arc<AppState> {
        Arc::new(AppState {
            auth_config: some_auth(),
            key: cookie::Key::generate(),
            data_dir: PathBuf::from("/tmp"),
            scan: Arc::new(RwLock::new(None)),
            seed: 0,
            cache_dir: PathBuf::from("/tmp"),
            thumb_sem: Arc::new(tokio::sync::Semaphore::new(1)),
            cookie_secure: false,
            login_limiter: Arc::new(crate::auth::RateLimiter::new(5, 60)),
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

    /// The session identifier a `Set-Cookie` header carries: the signed value is
    /// the jar's signature followed by the identifier, so it is the last 32
    /// characters of the value before the attributes begin.
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

    /// OWASP is explicit that a session identifier must never be logged in
    /// cleartext — only a salted hash of it. The handler is called directly so
    /// the thread-local subscriber sees its events.
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
}
