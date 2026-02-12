use std::sync::Arc;

use anyhow::bail;
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::IntoResponse,
};
use base64::{Engine as _, engine::GeneralPurpose};
use http::{StatusCode, header};
use tracing::error;

use super::config::AuthConfig;
use crate::state::AppState;

const BASE64_ENGINE: GeneralPurpose = base64::engine::general_purpose::STANDARD;

type SingleHeader = [(header::HeaderName, &'static str); 1];
const WWW_AUTHENTICATE_HEADER: SingleHeader = [(header::WWW_AUTHENTICATE, "Basic realm=comics")];

/// Authentication state after checking credentials
pub enum AuthState {
    Public,
    Request,
    Success,
    Failed,
}

/// Authenticate a request against the configured credentials
pub fn authenticate(state: &Arc<AppState>, request: &Request) -> anyhow::Result<AuthState> {
    let (expected_username, expected_password) = match &state.auth_config {
        AuthConfig::None => return Ok(AuthState::Public),
        AuthConfig::Some {
            username,
            password_hash,
        } => (username, password_hash),
    };
    let header_value = match request.headers().get(header::AUTHORIZATION) {
        None => return Ok(AuthState::Request),
        Some(v) => v,
    };
    let header_str = header_value.to_str()?;
    let mut parts = header_str.splitn(2, ' ');
    let digest = match (parts.next(), parts.next()) {
        (Some(scheme), Some(digest)) if scheme.eq_ignore_ascii_case("basic") => digest,
        _ => return Ok(AuthState::Failed),
    };
    let decoded = BASE64_ENGINE.decode(digest)?;
    let decoded_str = String::from_utf8(decoded)?;
    let password = match decoded_str.split_once(':') {
        Some((u, p)) if u == expected_username => p,
        _ => return Ok(AuthState::Failed),
    };
    match bcrypt::verify(password, expected_password) {
        Ok(true) => Ok(AuthState::Success),
        Ok(false) => Ok(AuthState::Failed),
        Err(err) => {
            error!(?err, "failed to verify password");
            bail!("Bcrypt error: {err}")
        }
    }
}

/// Axum middleware function for authentication
pub async fn auth_middleware_fn(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> impl IntoResponse {
    match authenticate(&state, &request) {
        Ok(AuthState::Public | AuthState::Success) => next.run(request).await,
        Ok(AuthState::Failed) => StatusCode::UNAUTHORIZED.into_response(),
        Ok(AuthState::Request) => {
            (StatusCode::UNAUTHORIZED, WWW_AUTHENTICATE_HEADER, "").into_response()
        }
        Err(err) => {
            error!(%err, "failed to authenticate");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request as HttpRequest;
    use parking_lot::RwLock;
    use std::path::PathBuf;

    fn create_state(auth_config: AuthConfig) -> Arc<AppState> {
        Arc::new(AppState {
            auth_config,
            data_dir: PathBuf::from("/tmp"),
            scan: Arc::new(RwLock::new(None)),
            seed: 0,
        })
    }

    fn create_request_with_auth(auth_header: Option<&str>) -> Request {
        let mut builder = HttpRequest::builder().uri("/").method("GET");
        if let Some(auth) = auth_header {
            builder = builder.header(header::AUTHORIZATION, auth);
        }
        builder.body(axum::body::Body::empty()).unwrap()
    }

    #[test]
    fn authenticate_public_when_no_auth_config() {
        let state = create_state(AuthConfig::None);
        let request = create_request_with_auth(None);
        let result = authenticate(&state, &request).unwrap();
        assert!(matches!(result, AuthState::Public));
    }

    #[test]
    fn authenticate_request_when_no_header() {
        let state = create_state(AuthConfig::Some {
            username: "user".to_string(),
            password_hash: bcrypt::hash("pass", 4).unwrap(),
        });
        let request = create_request_with_auth(None);
        let result = authenticate(&state, &request).unwrap();
        assert!(matches!(result, AuthState::Request));
    }

    #[test]
    fn authenticate_success_with_valid_credentials() {
        let password_hash = bcrypt::hash("password", 4).unwrap();
        let state = create_state(AuthConfig::Some {
            username: "user".to_string(),
            password_hash,
        });
        let credentials = BASE64_ENGINE.encode("user:password");
        let request = create_request_with_auth(Some(&format!("Basic {credentials}")));
        let result = authenticate(&state, &request).unwrap();
        assert!(matches!(result, AuthState::Success));
    }

    #[test]
    fn authenticate_failed_with_wrong_scheme() {
        let password_hash = bcrypt::hash("password", 4).unwrap();
        let state = create_state(AuthConfig::Some {
            username: "user".to_string(),
            password_hash,
        });
        let credentials = BASE64_ENGINE.encode("user:password");
        let request = create_request_with_auth(Some(&format!("Bearer {credentials}")));
        let result = authenticate(&state, &request).unwrap();
        assert!(matches!(result, AuthState::Failed));
    }

    #[test]
    fn authenticate_failed_with_wrong_username() {
        let password_hash = bcrypt::hash("password", 4).unwrap();
        let state = create_state(AuthConfig::Some {
            username: "user".to_string(),
            password_hash,
        });
        let credentials = BASE64_ENGINE.encode("wronguser:password");
        let request = create_request_with_auth(Some(&format!("Basic {credentials}")));
        let result = authenticate(&state, &request).unwrap();
        assert!(matches!(result, AuthState::Failed));
    }

    #[test]
    fn authenticate_failed_with_wrong_password() {
        let password_hash = bcrypt::hash("password", 4).unwrap();
        let state = create_state(AuthConfig::Some {
            username: "user".to_string(),
            password_hash,
        });
        let credentials = BASE64_ENGINE.encode("user:wrongpassword");
        let request = create_request_with_auth(Some(&format!("Basic {credentials}")));
        let result = authenticate(&state, &request).unwrap();
        assert!(matches!(result, AuthState::Failed));
    }

    #[test]
    fn authenticate_failed_with_malformed_credentials() {
        let password_hash = bcrypt::hash("password", 4).unwrap();
        let state = create_state(AuthConfig::Some {
            username: "user".to_string(),
            password_hash,
        });
        // Missing colon separator
        let credentials = BASE64_ENGINE.encode("userpassword");
        let request = create_request_with_auth(Some(&format!("Basic {credentials}")));
        let result = authenticate(&state, &request).unwrap();
        assert!(matches!(result, AuthState::Failed));
    }
}
