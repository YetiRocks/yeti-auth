//! JWT Token Refresh Resource
//!
//! Exchanges a valid refresh token for a new access + refresh token pair.
//! Re-resolves the user's current role and permissions from the database,
//! so permission changes take effect on next refresh.
//!
//! | Method | Path                    | Description                              |
//! |--------|-------------------------|------------------------------------------|
//! | POST   | /yeti-auth/jwt_refresh  | Exchange refresh token for new token pair |
//!
//! ## Request Body
//! ```json
//! { "refresh_token": "eyJ..." }
//! ```
//!
//! ## Response (200)
//! ```json
//! {
//!   "access_token": "eyJ...",
//!   "refresh_token": "eyJ...",
//!   "expires_in": 900,
//!   "token_type": "Bearer"
//! }
//! ```

use yeti_core::prelude::*;
use crate::auth::{SHARED_JWT_MANAGER, Permission};

pub type JwtRefresh = JwtRefreshResource;

#[derive(Default)]
pub struct JwtRefreshResource;

impl Resource for JwtRefreshResource {
    fn name(&self) -> &str {
        "jwt_refresh"
    }

    post!(request, ctx, {
        let body = request.json_value()?;
        let refresh_token = body.require_str("refresh_token")?;

        let jwt_manager = SHARED_JWT_MANAGER.get()
            .ok_or_else(|| YetiError::Internal("JWT not initialized".to_string()))?;

        // Validate the refresh token
        let claims = match jwt_manager.validate_token(&refresh_token) {
            Ok(c) => c,
            Err(AuthError::TokenExpired) => {
                return unauthorized("Refresh token expired — please log in again");
            }
            Err(_) => {
                return unauthorized("Invalid refresh token");
            }
        };

        // Must be a refresh token, not an access token
        if claims.token_type != "refresh" {
            return bad_request("Expected a refresh token, got an access token");
        }

        let username = &claims.sub;

        // Re-resolve role and permissions from DB (they may have changed)
        let user_table = ctx.get_table("User")?;
        let user_record: Option<serde_json::Value> = user_table.get(Some(username.as_str())).await?;

        let Some(user) = user_record else {
            return unauthorized("User no longer exists");
        };

        // Check if user is still active
        let active = user.get("active").and_then(|v| v.as_bool()).unwrap_or(false);
        if !active {
            return unauthorized("Account is disabled");
        }

        // Look up current role permissions
        let role_id = user.get("roleId").and_then(|v| v.as_str());
        let permissions = if let Some(role_id) = role_id {
            let role_table = ctx.get_table("Role")?;
            let role_record: Option<serde_json::Value> = role_table.get(Some(role_id)).await?;
            role_record
                .and_then(|r| r.get("permissions")?.as_str().map(|s| s.to_string()))
                .and_then(|s| serde_json::from_str::<Permission>(&s).ok())
        } else {
            None
        };

        // Generate new token pair with current permissions
        let tokens = jwt_manager.generate_token_pair(username, role_id, permissions)
            .map_err(|e| YetiError::Internal(format!("Token generation failed: {:?}", e)))?;

        reply().json(json!({
            "access_token": tokens.access_token,
            "refresh_token": tokens.refresh_token,
            "expires_in": tokens.expires_in,
            "token_type": "Bearer"
        }))
    });
}

register_resource!(JwtRefreshResource);
