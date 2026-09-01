//! Request-time authentication & RBAC enforcement.
//!
//! [`AuthUser`] is an Axum extractor: any handler that names it in its
//! signature is guaranteed an authenticated caller, with the caller's
//! effective permissions available for [`AuthUser::require`] checks.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use daygleve_schema::auth::{CurrentUser, Permission};

use crate::error::AppError;
use crate::state::AppState;

/// An authenticated caller, extracted from the `Authorization: Bearer` header.
#[derive(Debug, Clone)]
pub struct AuthUser(pub CurrentUser);

impl AuthUser {
    /// Enforce that the caller holds `permission`, else `403`.
    pub fn require(&self, permission: Permission) -> Result<(), AppError> {
        if self.0.permissions.contains(&permission) {
            Ok(())
        } else {
            Err(AppError::forbidden(format!(
                "missing permission: {permission:?}"
            )))
        }
    }
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(|| AppError::unauthorized("missing bearer token"))?;

        let current = state.services.auth.authenticate(token)?;
        Ok(AuthUser(current))
    }
}
