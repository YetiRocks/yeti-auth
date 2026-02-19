//! OAuth Callback Resource
//!
//! Handles the OAuth provider's redirect after user authorization.
//! Exchanges the authorization code for an access token, fetches user info,
//! creates a session, and redirects back to the application.
//!
//! # Endpoint
//!
//! `GET /yeti-auth/oauth_callback?code=...&state=...`
//!
//! # Note
//!
//! Uses `reqwest::blocking::Client` directly (not async reqwest or spawn_blocking)
//! because dynamically loaded plugins have a separate copy of Tokio's TLS and
//! cannot access the host's runtime handle. The blocking client creates its own
//! internal mini-runtime which works correctly in this context.

use yeti_core::prelude::*;
use crate::auth::{
    OAuthTokens, SESSION_COOKIE, SESSION_TTL_SECS,
    validate_csrf_state, build_callback_url, persist_session,
    get_oauth_providers, get_session_cache,
};

#[derive(Clone, Default)]
pub struct OauthCallback;

/// Result of a successful OAuth token exchange: user info + token data
pub struct OAuthExchangeResult {
    pub user: serde_json::Value,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<u64>,
}

fn exchange_token_and_fetch_user(
    token_url: &str,
    client_id: &str,
    client_secret: &str,
    code: &str,
    callback_url: &str,
    user_info_url: &str,
    user_emails_url: Option<&str>,
    provider_name: &str,
) -> std::result::Result<OAuthExchangeResult, String> {
    let client = reqwest::blocking::Client::new();

    // Exchange authorization code for access token
    // Use form-encoded body (required by Google, Microsoft; accepted by GitHub)
    let form_body = format!(
        "grant_type=authorization_code&client_id={}&client_secret={}&code={}&redirect_uri={}",
        urlencoding::encode(client_id),
        urlencoding::encode(client_secret),
        urlencoding::encode(code),
        urlencoding::encode(callback_url),
    );
    let token_response = client.post(token_url)
        .header("Accept", "application/json")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(form_body)
        .send()
        .map_err(|e| format!("Token exchange failed: {}", e))?;

    if !token_response.status().is_success() {
        let error_text = token_response.text().unwrap_or_default();
        tracing::warn!("OAuth token exchange failed: {}", error_text);
        return Err("Token exchange failed".to_string());
    }

    let tokens: serde_json::Value = token_response.json()
        .map_err(|e| format!("Failed to parse token response: {}", e))?;

    // Check for error in token response (GitHub returns 200 with error field)
    if let Some(error) = tokens.opt_str("error") {
        tracing::warn!("OAuth token error: {}", error);
        return Err(error.to_string());
    }

    let access_token = tokens.opt_str("access_token")
        .ok_or_else(|| "No access token in response".to_string())?
        .to_string();

    let refresh_token = tokens.opt_str("refresh_token")
        .map(|s| s.to_string());

    let expires_in = tokens.opt_u64("expires_in");

    // Fetch user info from provider
    let user_response = client.get(user_info_url)
        .header("Authorization", format!("Bearer {}", access_token))
        .header("User-Agent", "Yeti-Core")
        .send()
        .map_err(|e| format!("User info request failed: {}", e))?;

    if !user_response.status().is_success() {
        let error_text = user_response.text().unwrap_or_default();
        tracing::warn!("OAuth user info failed: {}", error_text);
        return Err("Failed to fetch user info".to_string());
    }

    let mut user: serde_json::Value = user_response.json()
        .map_err(|e| format!("Failed to parse user info: {}", e))?;

    // For GitHub: fetch primary email if not in profile
    if provider_name == "github" && user.opt_str("email").is_none() {
        if let Some(emails_url) = user_emails_url {
            if let Ok(emails_response) = client.get(emails_url)
                .header("Authorization", format!("Bearer {}", access_token))
                .header("User-Agent", "Yeti-Core")
                .send()
            {
                if emails_response.status().is_success() {
                    if let Ok(emails) = emails_response.json::<Vec<serde_json::Value>>() {
                        let primary_email = emails.iter()
                            .find(|e| {
                                e.get("primary").and_then(|v| v.as_bool()).unwrap_or(false)
                                    && e.get("verified").and_then(|v| v.as_bool()).unwrap_or(false)
                            })
                            .and_then(|e| e.get("email").and_then(|v| v.as_str()));

                        if let Some(email) = primary_email {
                            user["email"] = json!(email);
                        }
                    }
                }
            }
        }
    }

    Ok(OAuthExchangeResult {
        user,
        access_token,
        refresh_token,
        expires_in,
    })
}

impl Resource for OauthCallback {
    fn name(&self) -> &str { "oauth_callback" }

    fn get(&self, req: Request<Vec<u8>>, ctx: ResourceParams) -> ResourceFuture {
        Box::pin(async move {
            let uri = req.uri().to_string();
            let params = parse_query_string(&uri);

            // Check for error from provider (user denied, etc.)
            if let Some(error) = params.get("error") {
                let description = params.get("error_description")
                    .cloned()
                    .unwrap_or_else(|| error.clone());
                let redirect = format!("/?error={}", urlencoding::encode(&description));
                return reply().redirect(&redirect, Some(302));
            }

            let code = match params.get("code") {
                Some(c) => c.clone(),
                None => return bad_request("Missing 'code' parameter"),
            };

            let state = match params.get("state") {
                Some(s) => s.clone(),
                None => return bad_request("Missing 'state' parameter"),
            };

            // Validate CSRF state
            let csrf = match validate_csrf_state(&state) {
                Some(s) => s,
                None => {
                    return reply().redirect(
                        "/?error=Invalid%20or%20expired%20OAuth%20state",
                        Some(302),
                    );
                }
            };

            let app_redirect = csrf.redirect_uri.clone();
            let provider_name = csrf.provider.clone();

            // Get provider config
            let providers = get_oauth_providers()?;
            let provider = match providers.providers.get(&provider_name) {
                Some(p) => p,
                None => return internal_error(&format!("Provider '{}' not found", provider_name)),
            };

            let callback_url = build_callback_url(&req);

            // Perform blocking HTTP calls (see module-level note on why blocking)
            let result = match exchange_token_and_fetch_user(
                &provider.token_url,
                &provider.client_id,
                &provider.client_secret,
                &code,
                &callback_url,
                &provider.user_info_url,
                provider.user_emails_url.as_deref(),
                &provider_name,
            ) {
                Ok(r) => r,
                Err(error_msg) => {
                    let redirect = format!(
                        "{}?error={}",
                        app_redirect,
                        urlencoding::encode(&error_msg)
                    );
                    return reply().redirect(&redirect, Some(302));
                }
            };

            // Create session with token data for refresh support
            let session_id = generate_id();
            let session_cache = get_session_cache()?;

            let provider_type = provider.provider_type.clone();
            let expires_at_instant = result.expires_in.map(|secs| {
                std::time::Instant::now() + std::time::Duration::from_secs(secs)
            });
            let tokens = OAuthTokens {
                access_token: result.access_token.clone(),
                refresh_token: result.refresh_token.clone(),
                expires_at: expires_at_instant,
            };

            // Persist to DB first (best-effort — don't fail the login if DB write fails)
            if let Ok(tables) = ctx.tables() {
                let db_tokens = OAuthTokens {
                    access_token: result.access_token,
                    refresh_token: result.refresh_token,
                    expires_at: expires_at_instant,
                };
                if let Err(e) = persist_session(
                    &tables, &session_id, &result.user, &provider_name,
                    &provider_type, &db_tokens, SESSION_TTL_SECS,
                ).await {
                    eprintln!("[yeti-auth] Warning: failed to persist session to DB: {}", e);
                }
            }

            session_cache.set_with_tokens(session_id.clone(), result.user, provider_name, provider_type, tokens);

            // Build Set-Cookie header and redirect
            let cookie = CookieBuilder::new(SESSION_COOKIE, &session_id)
                .max_age(SESSION_TTL_SECS)
                .build();

            reply().redirect(&app_redirect, Some(302))
                .add_header("Set-Cookie", &cookie)
        })
    }
}
