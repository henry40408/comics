use axum::response::{IntoResponse, Response};
use http::StatusCode;

/// Application error types
#[derive(Debug)]
pub enum AppError {
    ServiceUnavailable,
    NotFound(String),
    InternalError(String),
    Unauthorized,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::ServiceUnavailable => {
                (StatusCode::SERVICE_UNAVAILABLE, "Service unavailable").into_response()
            }
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg).into_response(),
            AppError::InternalError(msg) => {
                (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response()
            }
            AppError::Unauthorized => StatusCode::UNAUTHORIZED.into_response(),
        }
    }
}

/// Result type alias for application errors
pub type AppResult<T> = Result<T, AppError>;
