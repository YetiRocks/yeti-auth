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
use crate::auth::{OAuthTokens, update_session_tokens_in_db, get_session_cookie, get_session_cache, get_oauth_providers, curl_request};

#[derive(Clone, Default)]
pub struct OauthRefresh;

/// Perform the token refresh via curl subprocess.
/// reqwest::blocking crashes in dylib plugins — use curl instead.
fn refresh_access_token(
    token_url: &str,
    client_id: &str,
    client_secret: &str,
    refresh_token: &str,
) -> std::result::Result<OAuthTokens, String> {
    let form_body = format!(
        "grant_type=refresh_token&client_id={}&client_secret={}&refresh_token={}",
        urlencoding::encode(client_id),
        urlencoding::encode(client_secret),
        urlencoding::encode(refresh_token),
    );

    let response = curl_request(
        "POST",
        token_url,
        &[
            ("Accept", "application/json"),
            ("Content-Type", "application/x-www-form-urlencoded"),
        ],
        Some(&form_body),
    )?;

    if !response.is_success() {
        return Err(format!("Token refresh failed ({}): {}", response.status, response.body));
    }

    let tokens = response.json()?;

    if let Some(error) = tokens.opt_str("error") {
        return Err(format!("Token refresh error: {}", error));
    }

    let access_token = tokens.opt_str("access_token")
        .ok_or_else(|| "No access token in refresh response".to_string())?
        .to_string();

    // Refresh token may be rotated (new one returned) or absent (reuse old one)
    let new_refresh_token = tokens.opt_str("refresh_token")
        .map(|s| s.to_string())
        .or_else(|| Some(refresh_token.to_string()));

    let expires_in = tokens.opt_u64("expires_in");

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
            let Some(session_id) = get_session_cookie(&req) else {
                return unauthorized("No OAuth session");
            };
            let session_cache = get_session_cache()?;

            // Get refresh token and provider for this session
            let (refresh_token, provider_key) = match session_cache.get_refresh_info(&session_id) {
                Some(info) => info,
                None => return bad_request("No refresh token available for this session"),
            };

            // Look up provider config to get token URL and credentials
            let providers = get_oauth_providers()?;
            let provider = match providers.providers.get(&provider_key) {
                Some(p) => p,
                None => return internal_error(&format!("Provider '{}' not found", provider_key)),
            };

            // Perform the refresh via curl subprocess
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
