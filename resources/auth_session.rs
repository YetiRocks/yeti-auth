//! Auth session management — Shared statics, CSRF, session cache, DB persistence

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use yeti_core::prelude::*;

use crate::auth_types::*;
use crate::auth_crypto::JwtManager;

// ============================================================================
// Shared State (accessible by OAuth flow resources in sibling modules)
// ============================================================================

/// Shared session cache — used by OAuthAuthProvider and OAuth flow resources
pub static SHARED_SESSION_CACHE: OnceLock<Arc<SessionCache>> = OnceLock::new();

/// Shared OAuth provider configurations — initialized from environment variables
pub static SHARED_OAUTH_PROVIDERS: OnceLock<Arc<OAuthProviders>> = OnceLock::new();

/// Shared JWT manager — used by login resource to generate tokens
pub static SHARED_JWT_MANAGER: OnceLock<Arc<JwtManager>> = OnceLock::new();

/// Shared auth hooks — registered by extensions for custom role resolution
pub static SHARED_AUTH_HOOKS: OnceLock<Vec<Arc<dyn AuthHook>>> = OnceLock::new();

/// CSRF state store — short-lived tokens for OAuth login flow
pub static CSRF_STORE: OnceLock<DashMap<String, CsrfState>> = OnceLock::new();

/// Counter for periodic CSRF cleanup (every 100 insertions)
static CSRF_CLEANUP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Max age for CSRF tokens (10 minutes)
const CSRF_MAX_AGE: Duration = Duration::from_secs(600);

/// OAuth session TTL (7 days)
pub const SESSION_TTL_SECS: u64 = 604800;

// ============================================================================
// Shared State Accessors
// ============================================================================

/// Get the shared JWT manager, or return 500 if not initialized.
pub fn get_jwt_manager() -> std::result::Result<&'static Arc<JwtManager>, YetiError> {
    SHARED_JWT_MANAGER.get()
        .ok_or_else(|| YetiError::Internal("JWT not initialized".to_string()))
}

/// Get the shared OAuth providers, or return 500 if not initialized.
pub fn get_oauth_providers() -> std::result::Result<&'static Arc<OAuthProviders>, YetiError> {
    SHARED_OAUTH_PROVIDERS.get()
        .ok_or_else(|| YetiError::Internal("OAuth not initialized".to_string()))
}

/// Get the shared session cache, or return 500 if not initialized.
pub fn get_session_cache() -> std::result::Result<&'static Arc<SessionCache>, YetiError> {
    SHARED_SESSION_CACHE.get()
        .ok_or_else(|| YetiError::Internal("Session cache not initialized".to_string()))
}

/// Extract session ID from the session cookie.
pub fn get_session_cookie(req: &Request<Vec<u8>>) -> Option<String> {
    CookieParser::get_cookie(req, SESSION_COOKIE)
}

// ============================================================================
// CSRF State Management
// ============================================================================

/// Store a CSRF state token for the OAuth login flow.
/// Every 100 insertions, sweeps expired entries to prevent unbounded growth
/// from abandoned OAuth flows.
pub fn store_csrf_state(state: &str, provider: &str, redirect_uri: &str) {
    let store = CSRF_STORE.get_or_init(DashMap::new);
    store.insert(state.to_string(), CsrfState {
        provider: provider.to_string(),
        redirect_uri: redirect_uri.to_string(),
        created_at: Instant::now(),
    });

    // Periodic cleanup: sweep expired tokens every 100 insertions
    let count = CSRF_CLEANUP_COUNTER.fetch_add(1, Ordering::Relaxed);
    if count % 100 == 99 {
        store.retain(|_, v| v.created_at.elapsed() < CSRF_MAX_AGE);
    }
}

/// Validate and consume a CSRF state token. Returns the stored state or None.
pub fn validate_csrf_state(state: &str) -> Option<CsrfState> {
    let store = CSRF_STORE.get_or_init(DashMap::new);
    let (_, csrf) = store.remove(state)?;
    if csrf.created_at.elapsed() > CSRF_MAX_AGE {
        return None;
    }
    Some(csrf)
}

/// Build the OAuth callback URL from the request Host header
pub fn build_callback_url(req: &Request<Vec<u8>>) -> String {
    let host = req.headers().get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost:9996");
    let scheme = req.headers().get("x-forwarded-proto")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("https");
    format!("{}://{}/yeti-auth/oauth_callback", scheme, host)
}

// ============================================================================
// Session Cache (for OAuth)
// ============================================================================

/// Cached OAuth session with TTL
struct CachedSession {
    user: serde_json::Value,
    provider: String,
    provider_type: String,
    tokens: Option<OAuthTokens>,
    created_at: Instant,
}

/// Session cache with automatic TTL cleanup
pub struct SessionCache {
    sessions: DashMap<String, CachedSession>,
    ttl: Duration,
}

impl SessionCache {
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            sessions: DashMap::new(),
            ttl: Duration::from_secs(ttl_seconds),
        }
    }

    /// Returns (user_json, provider_config_key, provider_type)
    pub fn get(&self, session_id: &str) -> Option<(serde_json::Value, String, String)> {
        let entry = self.sessions.get(session_id)?;
        if entry.created_at.elapsed() > self.ttl {
            drop(entry);
            self.sessions.remove(session_id);
            return None;
        }
        Some((entry.user.clone(), entry.provider.clone(), entry.provider_type.clone()))
    }

    pub fn set(&self, session_id: String, user: serde_json::Value, provider: String, provider_type: String) {
        self.sessions.insert(session_id, CachedSession {
            user,
            provider,
            provider_type,
            tokens: None,
            created_at: Instant::now(),
        });
    }

    /// Store session with OAuth token data for refresh support
    pub fn set_with_tokens(
        &self,
        session_id: String,
        user: serde_json::Value,
        provider: String,
        provider_type: String,
        tokens: OAuthTokens,
    ) {
        self.sessions.insert(session_id, CachedSession {
            user,
            provider,
            provider_type,
            tokens: Some(tokens),
            created_at: Instant::now(),
        });
    }

    /// Check if a session's OAuth token needs refresh (expires within 5 minutes)
    pub fn needs_refresh(&self, session_id: &str) -> bool {
        if let Some(entry) = self.sessions.get(session_id) {
            if let Some(ref tokens) = entry.tokens {
                if let Some(expires_at) = tokens.expires_at {
                    return expires_at.checked_duration_since(Instant::now())
                        .map(|remaining| remaining < Duration::from_secs(300))
                        .unwrap_or(true); // Already expired
                }
            }
        }
        false
    }

    /// Update tokens for an existing session after refresh
    pub fn update_tokens(&self, session_id: &str, new_tokens: OAuthTokens) {
        if let Some(mut entry) = self.sessions.get_mut(session_id) {
            entry.tokens = Some(new_tokens);
        }
    }

    /// Get the refresh token and provider for a session (if available)
    pub fn get_refresh_info(&self, session_id: &str) -> Option<(String, String)> {
        let entry = self.sessions.get(session_id)?;
        let refresh_token = entry.tokens.as_ref()?.refresh_token.clone()?;
        Some((refresh_token, entry.provider.clone()))
    }

    pub fn remove(&self, session_id: &str) {
        self.sessions.remove(session_id);
    }

    pub fn cleanup(&self) {
        self.sessions.retain(|_, v| v.created_at.elapsed() <= self.ttl);
    }
}

// ============================================================================
// OAuth Session DB Persistence
// ============================================================================

/// Persist an OAuth session to the OAuthSession table.
/// Called after creating a new session in oauth_callback.
pub async fn persist_session(
    tables: &Tables,
    session_id: &str,
    user: &serde_json::Value,
    provider: &str,
    provider_type: &str,
    tokens: &OAuthTokens,
    ttl_secs: u64,
) -> std::result::Result<(), String> {
    let session_table = tables.get(TABLE_OAUTH_SESSION)
        .map_err(|e| format!("OAuthSession table not found: {}", e))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let token_expires_at = tokens.expires_at
        .map(|at| {
            let remaining = at.saturating_duration_since(Instant::now());
            now + remaining.as_secs()
        })
        .unwrap_or(0);

    let record = json!({
        "sessionId": session_id,
        "provider": provider,
        "providerType": provider_type,
        "userData": serde_json::to_string(user).unwrap_or_default(),
        "accessToken": tokens.access_token,
        "refreshToken": tokens.refresh_token.as_deref().unwrap_or(""),
        "tokenExpiresAt": token_expires_at,
        "createdAt": now,
        "expiresAt": now + ttl_secs,
    });

    session_table.put(session_id, record).await
        .map_err(|e| format!("Failed to persist session: {}", e))?;
    Ok(())
}

/// Load an OAuth session from the OAuthSession table.
/// Returns (user_json, provider, provider_type, tokens) or None if not found/expired.
pub async fn load_session_from_db(
    tables: &Tables,
    session_id: &str,
) -> Option<(serde_json::Value, String, String, Option<OAuthTokens>)> {
    let session_table = tables.get(TABLE_OAUTH_SESSION).ok()?;
    let record: Option<serde_json::Value> = session_table.get(Some(session_id)).await.ok()?;
    let record = record?;

    // Check if session has expired
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let expires_at = record.get("expiresAt").and_then(|v| v.as_u64()).unwrap_or(0);
    if expires_at > 0 && now > expires_at {
        // Session expired — clean it up
        let _ = session_table.delete(session_id).await;
        return None;
    }

    let user_data_str = record.get("userData").and_then(|v| v.as_str())?;
    let user: serde_json::Value = serde_json::from_str(user_data_str).ok()?;
    let provider = record.get("provider").and_then(|v| v.as_str())?.to_string();
    let provider_type = record.get("providerType").and_then(|v| v.as_str())?.to_string();

    let access_token = record.get("accessToken").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let tokens = if !access_token.is_empty() {
        let refresh_token = record.get("refreshToken")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        let token_expires_at = record.get("tokenExpiresAt").and_then(|v| v.as_u64()).unwrap_or(0);
        let expires_at_instant = if token_expires_at > now {
            Some(Instant::now() + Duration::from_secs(token_expires_at - now))
        } else if token_expires_at > 0 {
            Some(Instant::now()) // Already expired
        } else {
            None
        };

        Some(OAuthTokens {
            access_token,
            refresh_token,
            expires_at: expires_at_instant,
        })
    } else {
        None
    };

    Some((user, provider, provider_type, tokens))
}

/// Delete an OAuth session from the OAuthSession table.
pub async fn delete_session_from_db(
    tables: &Tables,
    session_id: &str,
) {
    if let Ok(session_table) = tables.get(TABLE_OAUTH_SESSION) {
        let _ = session_table.delete(session_id).await;
    }
}

/// Update tokens for an existing session in the OAuthSession table.
pub async fn update_session_tokens_in_db(
    tables: &Tables,
    session_id: &str,
    tokens: &OAuthTokens,
) {
    if let Ok(session_table) = tables.get(TABLE_OAUTH_SESSION) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let token_expires_at = tokens.expires_at
            .map(|at| {
                let remaining = at.saturating_duration_since(Instant::now());
                now + remaining.as_secs()
            })
            .unwrap_or(0);

        // Read existing record and update token fields
        if let Ok(Some(mut record)) = session_table.get(Some(session_id)).await {
            record["accessToken"] = json!(tokens.access_token);
            if let Some(ref rt) = tokens.refresh_token {
                record["refreshToken"] = json!(rt);
            }
            record["tokenExpiresAt"] = json!(token_expires_at);
            let _ = session_table.put(session_id, record).await;
        }
    }
}
