//! Auth providers — BasicAuth, JWT, OAuth session-based authentication

use std::hash::{Hash, Hasher, DefaultHasher};
use std::time::{Duration, Instant};
use yeti_core::prelude::*;

use crate::auth_types::*;
use crate::auth_crypto::*;
use crate::auth_session::*;

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
            .get_backend_for_table(TABLE_USER)
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
        let active = user.get_bool("active", false);
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
            session_cookie_name: SESSION_COOKIE.to_string(),
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

        yeti_log!(debug, "OAuth authenticate: session_id={}", &session_id[..16.min(session_id.len())]);

        // Try in-memory cache first
        if let Some((user, _provider_key, provider_type)) = self.session_cache.get(session_id) {
            yeti_log!(debug, "OAuth authenticate: cache hit, provider_type={}", provider_type);
            let email = user.opt_str("email")
                .map(|s| s.to_string());
            return Ok(Some(AuthIdentity::OAuth {
                email,
                provider: provider_type,
                claims: user,
            }));
        }

        yeti_log!(debug, "OAuth authenticate: cache miss, trying DB (backend={})", backend.is_some());

        // Cache miss — try the database (survives restarts)
        if let Some(bm) = backend {
            let has_session_table = bm.get_backend_for_table(TABLE_OAUTH_SESSION).is_ok();
            yeti_log!(debug, "OAuth authenticate: has OAuthSession backend={}", has_session_table);
            if let Ok(session_backend) = bm.get_backend_for_table(TABLE_OAUTH_SESSION) {
                let record: Option<serde_json::Value> = TableExt::get(
                    session_backend.as_ref(), session_id,
                ).await.unwrap_or(None);
                yeti_log!(debug, "OAuth authenticate: DB record found={}", record.is_some());

                if let Some(record) = record {
                    // Check session expiry
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let expires_at = record.get_u64("expiresAt", 0);
                    if expires_at > 0 && now > expires_at {
                        let _ = TableExt::delete(session_backend.as_ref(), session_id).await;
                        return Ok(None);
                    }

                    if let Some(user_data_str) = record.opt_str("userData") {
                        if let Ok(user) = serde_json::from_str::<serde_json::Value>(user_data_str) {
                            let provider = record.get("provider").and_then(|v| v.as_str()).unwrap_or_default().to_string();
                            let provider_type = record.get("providerType").and_then(|v| v.as_str()).unwrap_or_default().to_string();

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
