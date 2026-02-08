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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[tokio::test]
    async fn service_unavailable_response() {
        let error = AppError::ServiceUnavailable;
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"Service unavailable");
    }

    #[tokio::test]
    async fn not_found_response() {
        let error = AppError::NotFound("Book not found".to_string());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"Book not found");
    }

    #[tokio::test]
    async fn internal_error_response() {
        let error = AppError::InternalError("Something went wrong".to_string());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"Something went wrong");
    }

    #[tokio::test]
    async fn unauthorized_response() {
        let error = AppError::Unauthorized;
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
