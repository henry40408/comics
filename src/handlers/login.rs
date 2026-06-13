use std::sync::Arc;

use askama::Template;
use axum::{
    Form,
    extract::{Query, Request, State},
    response::{Html, IntoResponse, Redirect, Response},
};
use cookie::{Cookie, CookieJar, time::Duration};
use http::{HeaderValue, StatusCode, header};
use serde::Deserialize;
use tracing::error;

use crate::VERSION;
use crate::assets::assets_version;
use crate::auth::{AuthConfig, AuthState, SESSION_COOKIE, authenticate, build_session_cookie};
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
            (status, Html(html)).into_response()
        }
        Err(err) => {
            error!(%err, "failed to render login");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Attach a freshly-signed session cookie to a response.
fn set_session_cookie(response: &mut Response, state: &Arc<AppState>) {
    let mut jar = CookieJar::new();
    jar.signed_mut(&state.key).add(build_session_cookie());
    for cookie in jar.delta() {
        if let Ok(value) = HeaderValue::from_str(&cookie.encoded().to_string()) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
}

/// `GET /login` — render the login form. Skips it (redirecting home) when auth
/// is disabled or the visitor already holds a valid session.
pub async fn login_route(
    Query(query): Query<LoginQuery>,
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Response {
    if matches!(state.auth_config, AuthConfig::None)
        || matches!(authenticate(&state, &request), AuthState::Authenticated)
    {
        return Redirect::to(&safe_next(&query.next)).into_response();
    }
    render_login(false, &query.next)
}

/// `POST /login` — verify credentials and, on success, issue a session cookie.
pub async fn login_submit_route(
    State(state): State<Arc<AppState>>,
    Form(form): Form<LoginForm>,
) -> Response {
    if !verify_credentials(&state.auth_config, &form.username, &form.password) {
        return render_login(true, &form.next);
    }
    let mut response = Redirect::to(&safe_next(&form.next)).into_response();
    set_session_cookie(&mut response, &state);
    response
}

/// `POST /logout` — clear the session cookie and return to the login form.
pub async fn logout_route() -> Response {
    let removal = Cookie::build((SESSION_COOKIE, ""))
        .path("/")
        .max_age(Duration::ZERO)
        .build();
    let mut response = Redirect::to("/login").into_response();
    if let Ok(value) = HeaderValue::from_str(&removal.encoded().to_string()) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn some_auth() -> AuthConfig {
        AuthConfig::Some {
            username: "alice".to_string(),
            password_hash: bcrypt::hash("s3cret", 4).unwrap(),
        }
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
