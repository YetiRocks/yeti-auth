//! Auth data types — Permission model, User/Role, OAuth config, JWT claims

use std::time::Instant;
use yeti_core::prelude::*;
use yeti_core::auth::AccessControl;
use serde::{Deserialize, Serialize};

// ============================================================================
// Constants
// ============================================================================

pub const TABLE_USER: &str = "User";
pub const TABLE_ROLE: &str = "Role";
pub const TABLE_OAUTH_SESSION: &str = "OAuthSession";
pub const SESSION_COOKIE: &str = "yeti_session";
pub const ROLE_SUPER_USER: &str = "super_user";

// ============================================================================
// OAuth Provider Configuration
// ============================================================================

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

// ============================================================================
// JWT Types
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

// ============================================================================
// Basic Auth Types
// ============================================================================

/// Basic authentication credentials extracted from Authorization header
#[derive(Debug, Clone)]
pub struct BasicAuthCredentials {
    pub username: String,
    pub password: String,
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
                id: ROLE_SUPER_USER.to_string(),
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
// OAuth Token Data
// ============================================================================

/// OAuth token data stored alongside session
pub struct OAuthTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<Instant>,
}
