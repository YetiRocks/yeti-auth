//! Auth cryptography — Password hashing (Argon2), JWT management, Basic auth parsing

use yeti_core::prelude::*;
use base64::{Engine as _, engine::general_purpose};
use argon2::{Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier};
use password_hash::SaltString;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};

use crate::auth_types::*;

// ============================================================================
// Password Hashing Utilities (Argon2)
// ============================================================================

/// OWASP minimum Argon2id params: m=19456 KiB, t=2 iterations, p=1 thread
fn argon2_instance() -> Argon2<'static> {
    let params = Params::new(19456, 2, 1, None)
        .expect("valid argon2 params");
    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
}

/// Hash a password, converting AuthError to YetiError for resource handlers.
pub fn hash_password_or_err(password: &str) -> yeti_core::error::Result<String> {
    hash_password(password)
        .map_err(|e| YetiError::Internal(format!("Password hashing failed: {}", e)))
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
// JWT Manager
// ============================================================================

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

    /// Generate tokens, converting AuthError to YetiError for resource handlers.
    pub fn generate_tokens(
        &self, username: &str, role: Option<&str>, permissions: Option<Permission>,
    ) -> yeti_core::error::Result<JwtTokenPair> {
        self.generate_token_pair(username, role, permissions)
            .map_err(|e| YetiError::Internal(format!("Token generation failed: {:?}", e)))
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
// Basic Auth Parsing
// ============================================================================

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
