//! The backend error type and its mapping to the shared [`ApiError`] envelope
//! and HTTP status codes.
//!
//! Every fallible handler returns [`ApiResult<T>`]; on the error path the
//! [`IntoResponse`] impl serialises a `daygleve_schema::common::ApiError`,
//! guaranteeing the wire format matches the schema the frontend consumes.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use daygleve_schema::common::{ApiError, ErrorCode, FieldError};

/// Result alias used throughout the API layer.
pub type ApiResult<T> = Result<T, AppError>;

/// Backend-internal error. Carries the schema [`ErrorCode`] so the HTTP status
/// and wire body are derived consistently in one place.
#[derive(Debug)]
pub struct AppError {
    code: ErrorCode,
    message: String,
    details: Vec<FieldError>,
}

// Several constructors are part of the intended error vocabulary but not yet
// hit by a handler in this scaffold; keep them without dead-code noise.
#[allow(dead_code)]
impl AppError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: Vec::new(),
        }
    }

    pub fn with_details(mut self, details: Vec<FieldError>) -> Self {
        self.details = details;
        self
    }

    pub fn validation(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Validation, message)
    }
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Unauthorized, message)
    }
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Forbidden, message)
    }
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, message)
    }
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Conflict, message)
    }
    pub fn hypervisor(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::HypervisorError, message)
    }
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, message)
    }

    fn status(&self) -> StatusCode {
        match self.code {
            ErrorCode::Validation => StatusCode::BAD_REQUEST,
            ErrorCode::Unauthorized => StatusCode::UNAUTHORIZED,
            ErrorCode::Forbidden => StatusCode::FORBIDDEN,
            ErrorCode::NotFound => StatusCode::NOT_FOUND,
            ErrorCode::Conflict => StatusCode::CONFLICT,
            ErrorCode::HypervisorError => StatusCode::BAD_GATEWAY,
            ErrorCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status();
        if matches!(self.code, ErrorCode::Internal) {
            tracing::error!(message = %self.message, "internal error");
        }
        let body = ApiError {
            code: self.code,
            message: self.message,
            details: self.details,
            request_id: None,
        };
        (status, Json(body)).into_response()
    }
}
