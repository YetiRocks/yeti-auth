//! OAuth Token Refresh Resource
//!
//! Refreshes the OAuth access token using the stored refresh token.
//! Returns updated token info, or an error if no refresh token is available.
//!
//! # Endpoint
//!
//! `POST /yeti-auth/oauth_refresh`
//!
//! Requires an active OAuth session (yeti_session cookie).

use yeti_core::prelude::*;
use crate::auth::{SHARED_SESSION_CACHE, SHARED_OAUTH_PROVIDERS, OAuthTokens, update_session_tokens_in_db};

#[derive(Clone, Default)]
pub struct OauthRefresh;

/// Perform the token refresh using the blocking reqwest client.
/// Same approach as oauth_callback.rs — blocking is required in dylib plugins.
fn refresh_access_token(
    token_url: &str,
    client_id: &str,
    client_secret: &str,
    refresh_token: &str,
) -> std::result::Result<OAuthTokens, String> {
    let client = reqwest::blocking::Client::new();

    let form_body = format!(
        "grant_type=refresh_token&client_id={}&client_secret={}&refresh_token={}",
        urlencoding::encode(client_id),
        urlencoding::encode(client_secret),
        urlencoding::encode(refresh_token),
    );

    let response = client.post(token_url)
        .header("Accept", "application/json")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(form_body)
        .send()
        .map_err(|e| format!("Token refresh request failed: {}", e))?;

    if !response.status().is_success() {
        let error_text = response.text().unwrap_or_default();
        return Err(format!("Token refresh failed: {}", error_text));
    }

    let tokens: serde_json::Value = response.json()
        .map_err(|e| format!("Failed to parse refresh response: {}", e))?;

    if let Some(error) = tokens.get("error").and_then(|v| v.as_str()) {
        return Err(format!("Token refresh error: {}", error));
    }

    let access_token = tokens.get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "No access token in refresh response".to_string())?
        .to_string();

    // Refresh token may be rotated (new one returned) or absent (reuse old one)
    let new_refresh_token = tokens.get("refresh_token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| Some(refresh_token.to_string()));

    let expires_in = tokens.get("expires_in").and_then(|v| v.as_u64());

    Ok(OAuthTokens {
        access_token,
        refresh_token: new_refresh_token,
        expires_at: expires_in.map(|secs| {
            std::time::Instant::now() + std::time::Duration::from_secs(secs)
        }),
    })
}

impl Resource for OauthRefresh {
    fn name(&self) -> &str { "oauth_refresh" }

    fn post(&self, req: Request<Vec<u8>>, ctx: ResourceParams) -> ResourceFuture {
        Box::pin(async move {
            let session_id = match CookieParser::get_cookie(&req, "yeti_session") {
                Some(id) => id,
                None => return unauthorized("No OAuth session"),
            };

            let session_cache = match SHARED_SESSION_CACHE.get() {
                Some(c) => c,
                None => return unauthorized("Session store not initialized"),
            };

            // Get refresh token and provider for this session
            let (refresh_token, provider_key) = match session_cache.get_refresh_info(&session_id) {
                Some(info) => info,
                None => return bad_request("No refresh token available for this session"),
            };

            // Look up provider config to get token URL and credentials
            let providers = SHARED_OAUTH_PROVIDERS.get()
                .ok_or_else(|| YetiError::Internal("OAuth not initialized".to_string()))?;
            let provider = match providers.providers.get(&provider_key) {
                Some(p) => p,
                None => return internal_error(&format!("Provider '{}' not found", provider_key)),
            };

            // Perform the refresh
            match refresh_access_token(
                &provider.token_url,
                &provider.client_id,
                &provider.client_secret,
                &refresh_token,
            ) {
                Ok(new_tokens) => {
                    let expires_in = new_tokens.expires_at.map(|at| {
                        at.duration_since(std::time::Instant::now()).as_secs()
                    });
                    // Persist to DB
                    if let Ok(tables) = ctx.tables() {
                        update_session_tokens_in_db(&tables, &session_id, &new_tokens).await;
                    }
                    session_cache.update_tokens(&session_id, new_tokens);
                    ok(json!({
                        "refreshed": true,
                        "expires_in": expires_in,
                    }))
                }
                Err(error_msg) => {
                    bad_request(&format!("Token refresh failed: {}", error_msg))
                }
            }
        })
    }
}
