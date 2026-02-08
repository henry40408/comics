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
    let parts: Vec<&str> = header_str.split_ascii_whitespace().collect();
    let digest = match (parts.first().map(|s| s.to_ascii_lowercase()), parts.get(1)) {
        (Some(scheme), Some(digest)) if scheme == "basic" => digest,
        _ => return Ok(AuthState::Failed),
    };
    let decoded = BASE64_ENGINE.decode(digest)?;
    let decoded_str = String::from_utf8(decoded)?;
    let actual: Vec<&str> = decoded_str.split(':').collect();
    let (username, password) = match (actual.first(), actual.get(1)) {
        (Some(u), Some(p)) if *u == expected_username => (*u, *p),
        _ => return Ok(AuthState::Failed),
    };
    match (
        username == expected_username,
        bcrypt::verify(password, expected_password),
    ) {
        (true, Ok(true)) => Ok(AuthState::Success),
        (true, Ok(false)) | (false, _) => Ok(AuthState::Failed),
        (true, Err(err)) => {
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
