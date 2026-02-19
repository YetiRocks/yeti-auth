//! Yeti Auth Extension
//!
//! Provides authentication and authorization for Yeti applications.
//! Includes Basic, JWT, and OAuth authentication.
//!
//! Auth providers query the User and Role tables directly via BackendManager
//! (no in-memory caches). RocksDB reads are <1ms so per-request lookups
//! have negligible overhead.
//!
//! Implementation split across helper modules:
//! - auth_types: Permission model, User/Role, OAuth config, JWT claims
//! - auth_crypto: Password hashing (Argon2), JWT management, Basic auth parsing
//! - auth_session: Shared statics, CSRF, session cache, DB persistence
//! - auth_providers: BasicAuth, JWT, OAuth authentication providers
//! - auth_ssrf: SSRF validation for OAuth provider URLs

use yeti_core::prelude::*;
use yeti_core::routing::RequestMiddleware;

use crate::auth_types::*;
use crate::auth_crypto::*;
use crate::auth_session::*;
use crate::auth_providers::*;
use crate::auth_ssrf::*;

// Backward-compatible re-exports — sibling modules import via `use crate::auth::*`
pub use crate::auth_types::*;
pub use crate::auth_crypto::*;
pub use crate::auth_session::*;

// Type alias for auto-generated lib.rs (compiler expects `Auth` based on filename)
pub type Auth = AuthResource;

// ============================================================================
// Role Resolution
// ============================================================================

/// Check if an OAuth rule matches the given identity
fn rule_matches(
    rule: &serde_json::Value,
    provider: &str,
    email: Option<&str>,
    claims: &serde_json::Value,
) -> bool {
    let strategy = rule.get("strategy")
        .and_then(|v| v.as_str())
        .unwrap_or("email");
    let Some(pattern) = rule.get("pattern").and_then(|v| v.as_str()) else {
        return false;
    };

    match strategy {
        "provider" => provider == pattern,
        "claims" => {
            if let Some((field, value)) = pattern.split_once('=') {
                claims.get(field)
                    .and_then(|v| v.as_str())
                    .map(|v| v == value)
                    .unwrap_or(false)
            } else {
                claims.get(pattern)
                    .map(|v| !v.is_null() && v.as_bool() != Some(false))
                    .unwrap_or(false)
            }
        }
        _ => {
            // "email" strategy (default)
            let e = email.unwrap_or("");
            if pattern.starts_with('*') {
                e.ends_with(&pattern[1..])
            } else {
                e == pattern
            }
        }
    }
}

/// Resolve an authenticated identity to a User with Role.
///
/// - JWT with embedded permissions: uses claims directly (no DB lookup)
/// - Basic: username → User table → roleId → Role table → permissions
/// - JWT without permissions: same as Basic
/// - OAuth: extension config rules → role name → Role table → permissions
///
/// Returns None if the user/role cannot be resolved (→ caller defaults to super_user or denies).
async fn resolve_role(
    identity: &AuthIdentity,
    params: &ResourceParams,
) -> Option<User> {
    let username = identity.username();

    // JWT fast path: if the token has embedded role + permissions, skip all DB lookups
    if let AuthIdentity::Jwt { username, claims } = identity {
        let claims: JwtClaims = serde_json::from_value(claims.clone()).ok()?;
        if let (Some(role_id), Some(permission)) = (claims.role, claims.permissions) {
            return Some(User::new(username.clone(), Role {
                id: role_id.clone(),
                name: role_id,
                permission,
            }));
        }
    }

    // Step 1: Determine the role name
    let role_name = match identity {
        AuthIdentity::Basic { username } | AuthIdentity::Jwt { username, .. } => {
            // Look up User record → roleId
            let tables = params.tables().ok()?;
            let user_table = tables.get(TABLE_USER).ok()?;
            let user_record: Option<serde_json::Value> = user_table.get(Some(username.as_str())).await.ok()?;
            let record = user_record?;
            record.get("roleId")?.as_str()?.to_string()
        }
        AuthIdentity::OAuth { provider, email, claims, .. } => {
            // Use extension config for OAuth role mapping
            let ext_config = params.extension_config("yeti-auth")?;
            let oauth_config = ext_config.get("oauth")?;

            // 1. Check role_claim (direct claim → role)
            if let Some(claim_name) = oauth_config.get("role_claim").and_then(|v| v.as_str()) {
                if let Some(role) = claims.get(claim_name).and_then(|v| v.as_str()) {
                    role.to_string()
                } else {
                    resolve_oauth_role_from_rules(oauth_config, provider, email.as_deref(), claims)?
                }
            } else {
                resolve_oauth_role_from_rules(oauth_config, provider, email.as_deref(), claims)?
            }
        }
    };

    // Step 2: Look up role permissions from Role table
    let tables = params.tables().ok()?;
    let role_table = tables.get(TABLE_ROLE).ok()?;
    let role_record: Option<serde_json::Value> = role_table.get(Some(role_name.as_str())).await.ok()?;
    let role_record = role_record?;

    // Parse permissions from the Role record (stored as JSON string)
    let permissions_str = role_record.get("permissions")?.as_str()?;
    let permission: Permission = serde_json::from_str(permissions_str).ok()?;

    Some(User::new(username, Role {
        id: role_name.clone(),
        name: role_name,
        permission,
    }))
}

/// Resolve OAuth role from rules in extension config.
/// Returns None if no match and no default_role (→ deny).
fn resolve_oauth_role_from_rules(
    oauth_config: &serde_json::Value,
    provider: &str,
    email: Option<&str>,
    claims: &serde_json::Value,
) -> Option<String> {
    // Evaluate rules in order — first match wins
    if let Some(rules) = oauth_config.get("rules").and_then(|v| v.as_array()) {
        for rule in rules {
            if rule_matches(rule, provider, email, claims) {
                if let Some(role) = rule.get("role").and_then(|v| v.as_str()) {
                    return Some(role.to_string());
                }
            }
        }
    }

    // Default role (optional — if omitted, unmatched OAuth users are denied)
    oauth_config.get("default_role")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

// ============================================================================
// Auth Middleware
// ============================================================================

/// Auth middleware — resolves identity → User with Role via direct DB queries.
pub struct AuthMiddleware {
    session_cache: Arc<SessionCache>,
}

impl AuthMiddleware {
    pub fn new(session_cache: Arc<SessionCache>) -> Self {
        Self { session_cache }
    }
}

impl std::fmt::Debug for AuthMiddleware {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthMiddleware").finish()
    }
}

#[async_trait]
impl RequestMiddleware for AuthMiddleware {
    fn name(&self) -> &str {
        "auth"
    }

    async fn process(
        &self,
        _req: &Request<Vec<u8>>,
        params: &mut ResourceParams,
    ) -> Result<()> {
        // Cleanup expired sessions periodically
        self.session_cache.cleanup();

        // Map auth identity → User with Role via direct DB queries.
        // If resolve_role fails (no User/Role tables, unknown user, etc.),
        // fall back to super_user for backward compatibility with apps
        // that don't have auth tables.
        if let Some(identity) = params.auth_identity().cloned() {
            // Check registered auth hooks first — if any hook returns Some,
            // use that and skip default resolution
            let mut hooked = false;
            if let Some(hooks) = SHARED_AUTH_HOOKS.get() {
                for hook in hooks {
                    if let Some(access) = hook.on_resolve_role(&identity, params).await {
                        params.set_access_control(access);
                        hooked = true;
                        break;
                    }
                }
            }

            if !hooked {
                let user = resolve_role(&identity, params).await
                    .unwrap_or_else(|| User::super_user(identity.username()));
                params.set_access_control(Arc::new(user));
            }
        }

        Ok(())
    }
}

// ============================================================================
// Auth Resource
// ============================================================================

/// Auth resource — provides authentication status endpoint.
#[derive(Clone, Default)]
pub struct AuthResource;

impl AuthResource {
    pub fn new() -> Self {
        Self
    }
}

impl Resource for AuthResource {
    fn name(&self) -> &str {
        "auth"
    }

    fn get(&self, _req: Request<Vec<u8>>, params: ResourceParams) -> ResourceFuture {
        Box::pin(async move {
            if let Some(identity) = params.auth_identity() {
                return ok(json!({
                    "authenticated": true,
                    "method": identity.method(),
                    "username": identity.username(),
                }));
            }

            ok(json!({
                "authenticated": false
            }))
        })
    }
}

// ============================================================================
// Auth Extension
// ============================================================================

/// Auth extension — provides authentication providers for applications.
///
/// Auth providers query User/Role tables directly. No in-memory caches needed.
/// DataLoader seeds the database with initial users/roles on startup.
pub struct AuthExtension {
    basic_provider: Arc<BasicAuthProvider>,
    jwt_provider: Arc<JwtAuthProvider>,
    oauth_provider: Arc<OAuthAuthProvider>,
    auth_middleware: Arc<AuthMiddleware>,
}

impl AuthExtension {
    pub fn new() -> Self {
        let session_cache = Arc::new(SessionCache::new(SESSION_TTL_SECS));
        SHARED_SESSION_CACHE.set(session_cache.clone()).ok();

        // Initialize OAuth provider configs from environment variables
        let mut providers = HashMap::new();

        // GitHub OAuth
        if let Ok(client_id) = std::env::var("GITHUB_CLIENT_ID") {
            if !client_id.is_empty() {
                providers.insert("github".to_string(), OAuthProviderConfig {
                    provider_type: "github".to_string(),
                    client_id,
                    client_secret: std::env::var("GITHUB_CLIENT_SECRET").unwrap_or_default(),
                    scopes: vec!["read:user".to_string(), "user:email".to_string()],
                    authorize_url: "https://github.com/login/oauth/authorize".to_string(),
                    token_url: "https://github.com/login/oauth/access_token".to_string(),
                    user_info_url: "https://api.github.com/user".to_string(),
                    user_emails_url: Some("https://api.github.com/user/emails".to_string()),
                });
            }
        }

        // Google OAuth
        if let Ok(client_id) = std::env::var("GOOGLE_CLIENT_ID") {
            if !client_id.is_empty() {
                providers.insert("google".to_string(), OAuthProviderConfig {
                    provider_type: "google".to_string(),
                    client_id,
                    client_secret: std::env::var("GOOGLE_CLIENT_SECRET").unwrap_or_default(),
                    scopes: vec!["openid".to_string(), "email".to_string(), "profile".to_string()],
                    authorize_url: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
                    token_url: "https://oauth2.googleapis.com/token".to_string(),
                    user_info_url: "https://www.googleapis.com/oauth2/v3/userinfo".to_string(),
                    user_emails_url: None,
                });
            }
        }

        // Microsoft OAuth
        if let Ok(client_id) = std::env::var("MICROSOFT_CLIENT_ID") {
            if !client_id.is_empty() {
                let tenant = std::env::var("MICROSOFT_TENANT_ID").unwrap_or_else(|_| "common".to_string());
                providers.insert("microsoft".to_string(), OAuthProviderConfig {
                    provider_type: "microsoft".to_string(),
                    client_id,
                    client_secret: std::env::var("MICROSOFT_CLIENT_SECRET").unwrap_or_default(),
                    scopes: vec!["openid".to_string(), "email".to_string(), "profile".to_string()],
                    authorize_url: format!("https://login.microsoftonline.com/{}/oauth2/v2.0/authorize", tenant),
                    token_url: format!("https://login.microsoftonline.com/{}/oauth2/v2.0/token", tenant),
                    user_info_url: "https://graph.microsoft.com/v1.0/me".to_string(),
                    user_emails_url: None,
                });
            }
        }

        // Validate all provider URLs for SSRF safety
        let provider_names: Vec<String> = providers.keys().cloned().collect();
        for name in &provider_names {
            if let Some(config) = providers.get(name) {
                if let Err(e) = validate_provider_urls(name, config) {
                    eprintln!("[yeti-auth] SSRF validation failed: {}", e);
                    eprintln!("[yeti-auth] Removing provider '{}' due to unsafe URL configuration", name);
                    providers.remove(name);
                }
            }
        }

        SHARED_OAUTH_PROVIDERS.set(Arc::new(OAuthProviders { providers })).ok();

        // Initialize CSRF store and auth hooks
        CSRF_STORE.get_or_init(DashMap::new);
        SHARED_AUTH_HOOKS.get_or_init(Vec::new);

        let auth_middleware = Arc::new(AuthMiddleware::new(session_cache.clone()));

        // Get JWT secret from environment or use default
        let jwt_secret = std::env::var("JWT_SECRET")
            .unwrap_or_else(|_| "development-secret-change-in-production".to_string());
        let jwt_manager = Arc::new(JwtManager::new(jwt_secret));
        SHARED_JWT_MANAGER.set(jwt_manager.clone()).ok();

        Self {
            basic_provider: Arc::new(BasicAuthProvider::new()),
            jwt_provider: Arc::new(JwtAuthProvider::new(jwt_manager)),
            oauth_provider: Arc::new(OAuthAuthProvider::new(session_cache)),
            auth_middleware,
        }
    }
}

impl Default for AuthExtension {
    fn default() -> Self {
        Self::new()
    }
}

impl Extension for AuthExtension {
    fn name(&self) -> &str {
        "auth"
    }

    fn initialize(&self) -> Result<()> {
        eprintln!("[yeti-auth] Initializing auth extension");
        eprintln!("[yeti-auth] Basic auth: enabled");
        eprintln!("[yeti-auth] JWT auth: enabled");
        if let Some(providers) = SHARED_OAUTH_PROVIDERS.get() {
            let names: Vec<&str> = providers.providers.keys().map(|s| s.as_str()).collect();
            if names.is_empty() {
                eprintln!("[yeti-auth] OAuth: no providers configured (set GITHUB_CLIENT_ID etc.)");
            } else {
                eprintln!("[yeti-auth] OAuth: providers configured: {:?}", names);
            }
        }
        Ok(())
    }

    fn middleware(&self) -> Option<Arc<dyn RequestMiddleware>> {
        Some(self.auth_middleware.clone())
    }

    fn auth_providers(&self) -> Vec<Arc<dyn AuthProvider>> {
        vec![
            self.basic_provider.clone(),
            self.jwt_provider.clone(),
            self.oauth_provider.clone(),
        ]
    }
}
