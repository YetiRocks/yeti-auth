//! Yeti Auth Extension
//!
//! Provides authentication and authorization for Yeti applications.
//! Includes Basic, JWT, and OAuth authentication.
//!
//! Auth providers query the User and Role tables directly via BackendManager
//! (no in-memory caches). RocksDB reads are <1ms so per-request lookups
//! have negligible overhead.

use std::hash::{Hash, Hasher, DefaultHasher};
use std::sync::{Arc, OnceLock};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use yeti_core::prelude::*;
use yeti_core::routing::RequestMiddleware;
use yeti_core::auth::AccessControl;
use yeti_core::backend::{BackendManager, TableExt};
use base64::{Engine as _, engine::general_purpose};
use argon2::{Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier};
use password_hash::SaltString;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

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

/// OAuth provider configuration (client credentials + endpoints)
pub struct OAuthProviderConfig {
    pub provider_type: String,
    pub client_id: String,
    pub client_secret: String,
    pub scopes: Vec<String>,
    pub authorize_url: String,
    pub token_url: String,
    pub user_info_url: String,
    pub user_emails_url: Option<String>,
}

/// Registry of configured OAuth providers
pub struct OAuthProviders {
    pub providers: HashMap<String, OAuthProviderConfig>,
}

/// CSRF state stored during OAuth login flow
pub struct CsrfState {
    pub provider: String,
    pub redirect_uri: String,
    pub created_at: Instant,
}

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

// Type alias for auto-generated lib.rs (compiler expects `Auth` based on filename)
pub type Auth = AuthResource;

// ============================================================================
// Password Hashing Utilities (Argon2)
// ============================================================================

/// OWASP minimum Argon2id params: m=19456 KiB, t=2 iterations, p=1 thread
fn argon2_instance() -> Argon2<'static> {
    let params = Params::new(19456, 2, 1, None)
        .expect("valid argon2 params");
    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
}

/// Hash a password using Argon2id (OWASP minimum params)
pub fn hash_password(password: &str) -> std::result::Result<String, AuthError> {
    let salt = SaltString::generate(&mut password_hash::rand_core::OsRng);
    argon2_instance()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| AuthError::InternalError(e.to_string()))
}

/// Verify a password against an Argon2 hash.
/// Uses stored params from the hash itself (supports both default and tuned hashes).
pub fn verify_password(password: &str, stored_hash: &str) -> std::result::Result<bool, AuthError> {
    let parsed = PasswordHash::new(stored_hash)
        .map_err(|e| AuthError::InternalError(e.to_string()))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

// ============================================================================
// JWT Utilities
// ============================================================================

/// JWT claims structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Subject (username)
    pub sub: String,
    /// Expiration time (Unix timestamp)
    pub exp: usize,
    /// Issued at (Unix timestamp)
    pub iat: usize,
    /// Token type ("access" or "refresh")
    pub token_type: String,
    /// User role ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Role permissions (embedded so no DB lookup needed on validation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Permission>,
}

/// JWT token pair (access + refresh)
#[derive(Debug, Clone, Serialize)]
pub struct JwtTokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
}

/// JWT manager for token generation and validation
pub struct JwtManager {
    secret: String,
    access_ttl: u64,
    refresh_ttl: u64,
}

impl JwtManager {
    pub fn new(secret: String) -> Self {
        Self {
            secret,
            access_ttl: 900,    // 15 minutes default
            refresh_ttl: 604800, // 7 days default
        }
    }

    pub fn with_ttls(secret: String, access_ttl: u64, refresh_ttl: u64) -> Self {
        Self {
            secret,
            access_ttl,
            refresh_ttl,
        }
    }

    /// Generate an access + refresh token pair.
    /// Permissions are embedded in the access token so no DB lookup is needed on validation.
    pub fn generate_token_pair(
        &self,
        username: &str,
        role: Option<&str>,
        permissions: Option<Permission>,
    ) -> std::result::Result<JwtTokenPair, AuthError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;

        // Access token — includes role + permissions
        let access_claims = JwtClaims {
            sub: username.to_string(),
            exp: now + self.access_ttl as usize,
            iat: now,
            token_type: "access".to_string(),
            role: role.map(|s| s.to_string()),
            permissions: permissions.clone(),
        };

        let access_token = encode(
            &Header::default(),
            &access_claims,
            &EncodingKey::from_secret(self.secret.as_bytes()),
        )
        .map_err(|e| AuthError::InternalError(e.to_string()))?;

        // Refresh token — no permissions (will re-resolve on refresh)
        let refresh_claims = JwtClaims {
            sub: username.to_string(),
            exp: now + self.refresh_ttl as usize,
            iat: now,
            token_type: "refresh".to_string(),
            role: role.map(|s| s.to_string()),
            permissions: None,
        };

        let refresh_token = encode(
            &Header::default(),
            &refresh_claims,
            &EncodingKey::from_secret(self.secret.as_bytes()),
        )
        .map_err(|e| AuthError::InternalError(e.to_string()))?;

        Ok(JwtTokenPair {
            access_token,
            refresh_token,
            expires_in: self.access_ttl,
        })
    }

    /// Validate a token and return claims
    pub fn validate_token(&self, token: &str) -> std::result::Result<JwtClaims, AuthError> {
        decode::<JwtClaims>(
            token,
            &DecodingKey::from_secret(self.secret.as_bytes()),
            &Validation::default(),
        )
        .map(|data| data.claims)
        .map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
            _ => AuthError::InvalidToken,
        })
    }
}

// ============================================================================
// Basic Auth Utilities
// ============================================================================

/// Basic authentication credentials extracted from Authorization header
#[derive(Debug, Clone)]
pub struct BasicAuthCredentials {
    pub username: String,
    pub password: String,
}

/// Parse HTTP Basic Authentication header
pub fn parse_basic_auth_header(header: &str) -> std::result::Result<BasicAuthCredentials, AuthError> {
    let encoded = header
        .strip_prefix("Basic ")
        .ok_or(AuthError::InvalidCredentials)?;

    let decoded_bytes = general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| AuthError::InvalidCredentials)?;

    let decoded = String::from_utf8(decoded_bytes)
        .map_err(|_| AuthError::InvalidCredentials)?;

    let (username, password) = decoded
        .split_once(':')
        .ok_or(AuthError::InvalidCredentials)?;

    Ok(BasicAuthCredentials {
        username: username.to_string(),
        password: password.to_string(),
    })
}

// ============================================================================
// User, Role, Permission Types
// ============================================================================

/// Table-level CRUD permissions
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TablePermission {
    pub read: bool,
    pub insert: bool,
    pub update: bool,
    pub delete: bool,
    #[serde(default)]
    pub attribute_permissions: HashMap<String, AttributePermission>,
}

/// Attribute-level permissions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributePermission {
    pub read: bool,
    pub write: bool,
}

/// Database-level permissions (contains tables)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DatabasePermission {
    pub tables: HashMap<String, TablePermission>,
}

/// Role permissions
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Permission {
    #[serde(default)]
    pub super_user: bool,
    #[serde(default)]
    pub databases: HashMap<String, DatabasePermission>,
}

/// User role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: String,
    pub name: String,
    pub permission: Permission,
}

/// Authenticated user with role
#[derive(Debug, Clone)]
pub struct User {
    pub username: String,
    pub role: Role,
}

impl User {
    pub fn new(username: String, role: Role) -> Self {
        Self { username, role }
    }

    pub fn super_user(username: String) -> Self {
        Self {
            username,
            role: Role {
                id: "super_user".to_string(),
                name: "Super User".to_string(),
                permission: Permission {
                    super_user: true,
                    databases: HashMap::new(),
                },
            },
        }
    }
}

// Implement AccessControl for User
impl AccessControl for User {
    fn is_super_user(&self) -> bool {
        self.role.permission.super_user
    }

    fn username(&self) -> &str {
        &self.username
    }

    fn can_read_table(&self, database: &str, table: &str) -> bool {
        if self.is_super_user() {
            return true;
        }
        self.role
            .permission
            .databases
            .get(database)
            .and_then(|db| db.tables.get(table))
            .map(|t| t.read)
            .unwrap_or(false)
    }

    fn can_insert_table(&self, database: &str, table: &str) -> bool {
        if self.is_super_user() {
            return true;
        }
        self.role
            .permission
            .databases
            .get(database)
            .and_then(|db| db.tables.get(table))
            .map(|t| t.insert)
            .unwrap_or(false)
    }

    fn can_update_table(&self, database: &str, table: &str) -> bool {
        if self.is_super_user() {
            return true;
        }
        self.role
            .permission
            .databases
            .get(database)
            .and_then(|db| db.tables.get(table))
            .map(|t| t.update)
            .unwrap_or(false)
    }

    fn can_delete_table(&self, database: &str, table: &str) -> bool {
        if self.is_super_user() {
            return true;
        }
        self.role
            .permission
            .databases
            .get(database)
            .and_then(|db| db.tables.get(table))
            .map(|t| t.delete)
            .unwrap_or(false)
    }

    fn can_read_attribute(&self, database: &str, table: &str, attr: &str) -> bool {
        if self.is_super_user() {
            return true;
        }
        if !self.can_read_table(database, table) {
            return false;
        }
        self.role
            .permission
            .databases
            .get(database)
            .and_then(|db| db.tables.get(table))
            .and_then(|t| t.attribute_permissions.get(attr))
            .map(|a| a.read)
            .unwrap_or(true)
    }

    fn can_write_attribute(&self, database: &str, table: &str, attr: &str) -> bool {
        if self.is_super_user() {
            return true;
        }
        let table_perm = self.role
            .permission
            .databases
            .get(database)
            .and_then(|db| db.tables.get(table));

        let can_write_table = table_perm
            .map(|t| t.insert || t.update)
            .unwrap_or(false);

        if !can_write_table {
            return false;
        }

        table_perm
            .and_then(|t| t.attribute_permissions.get(attr))
            .map(|a| a.write)
            .unwrap_or(true)
    }
}

// ============================================================================
// Session Cache (for OAuth)
// ============================================================================

/// OAuth token data stored alongside session
pub struct OAuthTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<Instant>,
}

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
    let session_table = tables.get("OAuthSession")
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
    let session_table = tables.get("OAuthSession").ok()?;
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
    if let Ok(session_table) = tables.get("OAuthSession") {
        let _ = session_table.delete(session_id).await;
    }
}

/// Update tokens for an existing session in the OAuthSession table.
pub async fn update_session_tokens_in_db(
    tables: &Tables,
    session_id: &str,
    tokens: &OAuthTokens,
) {
    if let Ok(session_table) = tables.get("OAuthSession") {
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

// ============================================================================
// Basic Auth Provider — queries User table directly via BackendManager
// ============================================================================

/// Cached credential verification result
struct CachedCredential {
    input_password_hash: u64,   // fast hash of the plaintext password (cache discriminator)
    db_password_hash: String,   // stored argon2 hash at time of verification
    verified_at: Instant,
}

/// Compute a fast (non-cryptographic) hash of a password for cache keying
fn fast_hash(s: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    s.hash(&mut hasher);
    hasher.finish()
}

/// Basic authentication provider — validates credentials against User table.
/// Caches successful verifications to avoid running argon2 on every request.
pub struct BasicAuthProvider {
    credential_cache: DashMap<String, CachedCredential>,
    cache_ttl: Duration,
}

impl BasicAuthProvider {
    pub fn new() -> Self {
        Self {
            credential_cache: DashMap::new(),
            cache_ttl: Duration::from_secs(300), // 5 minutes
        }
    }
}

impl Default for BasicAuthProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuthProvider for BasicAuthProvider {
    async fn authenticate(
        &self,
        req: &Request<Vec<u8>>,
        _cookies: &CookieJar,
        backend: Option<&BackendManager>,
    ) -> std::result::Result<Option<AuthIdentity>, AuthError> {
        let Some(auth_header) = req.headers().get("Authorization") else {
            return Ok(None);
        };

        let header_str = auth_header
            .to_str()
            .map_err(|_| AuthError::InvalidCredentials)?;

        if !header_str.starts_with("Basic ") {
            return Ok(None);
        }

        let credentials = parse_basic_auth_header(header_str)?;

        // Query User table directly via BackendManager
        let backend = backend.ok_or(AuthError::InvalidCredentials)?;
        let user_table = backend
            .get_backend_for_table("User")
            .map_err(|_| AuthError::InvalidCredentials)?;

        let user_record: Option<serde_json::Value> = TableExt::get(
            user_table.as_ref(),
            &credentials.username,
        )
            .await
            .map_err(|_| AuthError::InvalidCredentials)?;

        let Some(user) = user_record else {
            return Err(AuthError::InvalidCredentials);
        };

        // Check if user is active
        let active = user.get("active").and_then(|v| v.as_bool()).unwrap_or(false);
        if !active {
            return Err(AuthError::UserInactive);
        }

        // Verify password against stored hash (with credential cache)
        let pw_hash = user
            .get("passwordHash")
            .and_then(|v| v.as_str())
            .ok_or(AuthError::InvalidCredentials)?;

        let input_hash = fast_hash(&credentials.password);

        // Check credential cache: skip argon2 if we've already verified this exact combo
        if let Some(cached) = self.credential_cache.get(&credentials.username) {
            if cached.input_password_hash == input_hash
                && cached.db_password_hash == pw_hash
                && cached.verified_at.elapsed() < self.cache_ttl
            {
                return Ok(Some(AuthIdentity::Basic {
                    username: credentials.username,
                }));
            }
        }

        // Cache miss or stale — run argon2 verification
        match verify_password(&credentials.password, pw_hash) {
            Ok(true) => {
                self.credential_cache.insert(credentials.username.clone(), CachedCredential {
                    input_password_hash: input_hash,
                    db_password_hash: pw_hash.to_string(),
                    verified_at: Instant::now(),
                });
                Ok(Some(AuthIdentity::Basic {
                    username: credentials.username,
                }))
            }
            _ => {
                self.credential_cache.remove(&credentials.username);
                Err(AuthError::InvalidCredentials)
            }
        }
    }

    fn priority(&self) -> i32 {
        200
    }

    fn name(&self) -> &str {
        "basic"
    }
}

// ============================================================================
// JWT Auth Provider
// ============================================================================

/// JWT authentication provider — validates Bearer tokens.
pub struct JwtAuthProvider {
    jwt_manager: Arc<JwtManager>,
}

impl JwtAuthProvider {
    pub fn new(jwt_manager: Arc<JwtManager>) -> Self {
        Self { jwt_manager }
    }
}

#[async_trait]
impl AuthProvider for JwtAuthProvider {
    async fn authenticate(
        &self,
        req: &Request<Vec<u8>>,
        _cookies: &CookieJar,
        _backend: Option<&BackendManager>,
    ) -> std::result::Result<Option<AuthIdentity>, AuthError> {
        let Some(auth_header) = req.headers().get("Authorization") else {
            return Ok(None);
        };

        let header_str = auth_header
            .to_str()
            .map_err(|_| AuthError::InvalidCredentials)?;

        let Some(token) = header_str.strip_prefix("Bearer ") else {
            return Ok(None);
        };

        let claims = self.jwt_manager.validate_token(token)?;

        // Only accept access tokens (not refresh tokens)
        if claims.token_type != "access" {
            return Err(AuthError::InvalidToken);
        }

        let username = claims.sub.clone();
        Ok(Some(AuthIdentity::Jwt {
            username,
            claims: serde_json::to_value(&claims).unwrap_or_default(),
        }))
    }

    fn priority(&self) -> i32 {
        150
    }

    fn name(&self) -> &str {
        "jwt"
    }
}

// ============================================================================
// OAuth Auth Provider (Session-based)
// ============================================================================

/// OAuth authentication provider — validates session cookies.
pub struct OAuthAuthProvider {
    session_cache: Arc<SessionCache>,
    session_cookie_name: String,
}

impl OAuthAuthProvider {
    pub fn new(session_cache: Arc<SessionCache>) -> Self {
        Self {
            session_cache,
            session_cookie_name: "yeti_session".to_string(),
        }
    }
}

#[async_trait]
impl AuthProvider for OAuthAuthProvider {
    async fn authenticate(
        &self,
        _req: &Request<Vec<u8>>,
        cookies: &CookieJar,
        backend: Option<&BackendManager>,
    ) -> std::result::Result<Option<AuthIdentity>, AuthError> {
        let Some(session_id) = cookies.get(&self.session_cookie_name) else {
            return Ok(None);
        };

        // Try in-memory cache first
        if let Some((user, _provider_key, provider_type)) = self.session_cache.get(session_id) {
            let email = user.get("email")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            return Ok(Some(AuthIdentity::OAuth {
                email,
                provider: provider_type,
                claims: user,
            }));
        }

        // Cache miss — try the database (survives restarts)
        if let Some(bm) = backend {
            if let Ok(session_backend) = bm.get_backend_for_table("OAuthSession") {
                let record: Option<serde_json::Value> = TableExt::get(
                    session_backend.as_ref(), session_id,
                ).await.unwrap_or(None);

                if let Some(record) = record {
                    // Check session expiry
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let expires_at = record.get("expiresAt").and_then(|v| v.as_u64()).unwrap_or(0);
                    if expires_at > 0 && now > expires_at {
                        let _ = TableExt::delete(session_backend.as_ref(), session_id).await;
                        return Ok(None);
                    }

                    if let Some(user_data_str) = record.get("userData").and_then(|v| v.as_str()) {
                        if let Ok(user) = serde_json::from_str::<serde_json::Value>(user_data_str) {
                            let provider = record.get("provider").and_then(|v| v.as_str()).unwrap_or("").to_string();
                            let provider_type = record.get("providerType").and_then(|v| v.as_str()).unwrap_or("").to_string();

                            // Re-populate in-memory cache
                            self.session_cache.set(
                                session_id.to_string(), user.clone(),
                                provider, provider_type.clone(),
                            );

                            let email = user.get("email")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());
                            return Ok(Some(AuthIdentity::OAuth {
                                email,
                                provider: provider_type,
                                claims: user,
                            }));
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    fn priority(&self) -> i32 {
        100
    }

    fn name(&self) -> &str {
        "oauth"
    }
}

// ============================================================================
// Auth Middleware — resolves identity → User with Role via direct DB queries
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
            let user_table = tables.get("User").ok()?;
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
    let role_table = tables.get("Role").ok()?;
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
// SSRF Validation
// ============================================================================

/// Well-known OAuth provider domains that are always allowed
const TRUSTED_OAUTH_HOSTS: &[&str] = &[
    "github.com",
    "api.github.com",
    "accounts.google.com",
    "oauth2.googleapis.com",
    "www.googleapis.com",
    "login.microsoftonline.com",
    "graph.microsoft.com",
];

/// Validate that a URL is safe for server-side requests (prevents SSRF).
/// Rejects private IPs, localhost, and non-HTTPS URLs.
/// In development mode, non-HTTPS generates a warning instead of an error.
fn validate_provider_url(url: &str, label: &str) -> std::result::Result<(), String> {
    // Extract scheme
    let (scheme, rest) = url.split_once("://")
        .ok_or_else(|| format!("{}: invalid URL '{}' (no scheme)", label, url))?;

    // Check scheme — HTTPS required (warn in dev)
    if scheme != "https" {
        let is_dev = std::env::var("YETI_ENV")
            .unwrap_or_else(|_| "development".to_string()) == "development";
        if is_dev {
            eprintln!("[yeti-auth] WARNING: {} URL '{}' uses {} (non-HTTPS) — only acceptable in development", label, url, scheme);
        } else {
            return Err(format!("{}: URL '{}' must use HTTPS in production", label, url));
        }
    }

    // Extract host (strip path, port, query)
    let host_and_port = rest.split('/').next().unwrap_or(rest);
    let host = if host_and_port.starts_with('[') {
        // IPv6: [::1]:port
        host_and_port.split(']').next().unwrap_or(host_and_port).trim_start_matches('[')
    } else {
        host_and_port.split(':').next().unwrap_or(host_and_port)
    };

    if host.is_empty() {
        return Err(format!("{}: URL '{}' has no host", label, url));
    }

    // Trusted hosts are always allowed
    if TRUSTED_OAUTH_HOSTS.iter().any(|&trusted| host == trusted) {
        return Ok(());
    }

    // Reject localhost and loopback
    let host_lower = host.to_lowercase();
    if host_lower == "localhost" || host_lower == "127.0.0.1" || host_lower == "::1"
        || host_lower == "0.0.0.0"
    {
        return Err(format!("{}: URL '{}' points to localhost (SSRF risk)", label, url));
    }

    // Reject private IP ranges
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        let is_private = match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_private()       // 10.x, 172.16-31.x, 192.168.x
                    || v4.is_link_local()    // 169.254.x
                    || v4.octets()[0] == 0   // 0.0.0.0/8
            }
            std::net::IpAddr::V6(v6) => {
                v6.is_loopback()             // ::1
                    || v6.segments()[0] == 0xfe80 // link-local
                    || v6.segments()[0] == 0xfc00 || v6.segments()[0] == 0xfd00 // unique local
            }
        };
        if is_private {
            return Err(format!("{}: URL '{}' points to private/internal IP (SSRF risk)", label, url));
        }
    }

    Ok(())
}

/// Validate all URLs for an OAuth provider configuration
fn validate_provider_urls(name: &str, config: &OAuthProviderConfig) -> std::result::Result<(), String> {
    let label = format!("OAuth provider '{}'", name);
    validate_provider_url(&config.authorize_url, &format!("{} authorize_url", label))?;
    validate_provider_url(&config.token_url, &format!("{} token_url", label))?;
    validate_provider_url(&config.user_info_url, &format!("{} user_info_url", label))?;
    if let Some(ref emails_url) = config.user_emails_url {
        validate_provider_url(emails_url, &format!("{} user_emails_url", label))?;
    }
    Ok(())
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
