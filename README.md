<p align="center">
  <img src="https://cdn.prod.website-files.com/68e09cef90d613c94c3671c0/697e805a9246c7e090054706_logo_horizontal_grey.png" alt="Yeti" width="200" />
</p>

---

# Yeti Auth

[![Yeti](https://img.shields.io/badge/Yeti-Extension-blue)](https://yetirocks.com)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Auth](https://img.shields.io/badge/Auth-4_Methods-orange)](https://yetirocks.com/docs/auth)

Authentication and authorization extension for Yeti. Provides Basic, JWT, and OAuth authentication with role-based access control (RBAC). Consumer applications declare this extension to get a unified auth pipeline with zero custom code.

## Features

- **Basic Authentication** - Username/password via `Authorization: Basic` header
- **JWT Authentication** - Stateless tokens via `Authorization: Bearer` header with refresh token support
- **OAuth Integration** - Google, GitHub, Microsoft sign-in with session persistence
- **Role-Based Access Control** - Hierarchical permissions with attribute-level filtering
- **Per-App Authorization** - Each consumer app defines its own OAuth rules and role mappings
- **Argon2id Hashing** - OWASP-compliant password hashing
- **Seed Data** - Ships with default admin/editor/viewer roles and demo users
- **Session Persistence** - OAuth sessions survive server restarts via database storage
- **CSRF Protection** - Token-based protection for OAuth flows

## Installation

```bash
# Clone into your Yeti applications folder
cd ~/yeti/applications
git clone https://github.com/yetirocks/yeti-auth.git

# Restart Yeti to load the extension
# yeti-auth will initialize its database and seed default roles/users
```

## Consumer App Setup

Add yeti-auth to any application's `config.yaml`:

```yaml
extensions:
  - yeti-auth:
      oauth:
        default_role: viewer    # Optional: role for unmatched OAuth users
        rules:
          - strategy: provider
            pattern: "google"
            role: admin
          - strategy: email
            pattern: "*@mycompany.com"
            role: standard
          - strategy: provider
            pattern: "github"
            role: standard
```

## Authentication Methods

| Method | Header / Mechanism | Priority |
|--------|-------------------|----------|
| **Local** | Requests from `127.0.0.1` / `::1` | 1000 (highest) |
| **Basic** | `Authorization: Basic base64(user:pass)` | 200 |
| **JWT** | `Authorization: Bearer <token>` | 150 |
| **OAuth** | Browser cookie (session-based) | 100 |

Priority determines which method wins when multiple credentials are present.

## Default Users (Seed Data)

| Username | Password | Role | Permissions |
|----------|----------|------|-------------|
| `alice` | `password123` | super_user | Full access (protected from deletion) |
| `bob` | `password123` | admin | read, insert, update, delete |
| `charlie` | `password123` | standard | read, insert, update (no delete) |

## Default Roles (Seed Data)

| Role | Permissions |
|------|-------------|
| `super_user` | `{"super_user": true}` - Full access, protected from deletion and privilege removal |
| `admin` | `{"read": true, "insert": true, "update": true, "delete": true}` |
| `standard` | `{"read": true, "insert": true, "update": true}` |
| `viewer` | `{"read": true}` |

## API Endpoints

### User Management

```bash
# List all users
curl -sk https://localhost:9996/yeti-auth/users

# Get a specific user
curl -sk https://localhost:9996/yeti-auth/users/alice

# Create a user
curl -sk -X POST https://localhost:9996/yeti-auth/users \
  -H "Content-Type: application/json" \
  -d '{
    "username": "dave",
    "password": "securepassword",
    "roleId": "standard",
    "email": "dave@example.com",
    "active": true
  }'

# Update a user
curl -sk -X PUT https://localhost:9996/yeti-auth/users/dave \
  -H "Content-Type: application/json" \
  -d '{"roleId": "admin", "email": "dave@newmail.com"}'

# Delete a user
curl -sk -X DELETE https://localhost:9996/yeti-auth/users/dave
```

### Role Management

```bash
# List all roles
curl -sk https://localhost:9996/yeti-auth/roles

# Get a specific role
curl -sk https://localhost:9996/yeti-auth/roles/admin

# Create a role
curl -sk -X POST https://localhost:9996/yeti-auth/roles \
  -H "Content-Type: application/json" \
  -d '{
    "id": "moderator",
    "name": "Moderator",
    "permissions": "{\"read\": true, \"update\": true, \"delete\": true}"
  }'

# Update a role
curl -sk -X PUT https://localhost:9996/yeti-auth/roles/moderator \
  -H "Content-Type: application/json" \
  -d '{"permissions": "{\"read\": true, \"update\": true}"}'

# Delete a role (super_user cannot be deleted)
curl -sk -X DELETE https://localhost:9996/yeti-auth/roles/moderator
```

### JWT Login & Refresh

```bash
# Login (returns access + refresh tokens)
curl -sk -X POST https://localhost:9996/yeti-auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "password123"}'
# Response: {"accessToken": "eyJ...", "refreshToken": "eyJ...", "expiresIn": 900}

# Refresh token (exchange refresh token for new token pair)
curl -sk -X POST https://localhost:9996/yeti-auth/jwt_refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken": "eyJ..."}'

# Use JWT for authenticated requests
curl -sk -H "Authorization: Bearer eyJ..." \
  https://localhost:9996/my-app/protected-resource
```

### OAuth Endpoints

```bash
# Initiate OAuth login (redirects to provider)
curl -sk https://localhost:9996/yeti-auth/oauth_login?provider=google

# OAuth callback (handled automatically by provider redirect)
# GET /yeti-auth/oauth_callback?code=...&state=...

# Get current OAuth session info
curl -sk https://localhost:9996/yeti-auth/oauth_user \
  --cookie "yeti_session=<session-id>"

# Logout (clears session from memory and database)
curl -sk -X POST https://localhost:9996/yeti-auth/oauth_logout \
  --cookie "yeti_session=<session-id>"

# Refresh OAuth provider access token
curl -sk -X POST https://localhost:9996/yeti-auth/oauth_refresh \
  --cookie "yeti_session=<session-id>"

# Auth status check
curl -sk https://localhost:9996/yeti-auth/auth
```

## Schema

```graphql
type User @table(database: "yeti-auth") @export {
  username: String @primaryKey
  passwordHash: String
  active: Boolean
  roleId: String @indexed
  role: Role @relationship(from: roleId)
  email: String @indexed
  createdAt: Int
  updatedAt: Int
}

type Role @table(database: "yeti-auth") @export {
  id: String @primaryKey
  name: String
  permissions: String    # JSON blob
  users: [User] @relationship(to: roleId)
  createdAt: Int
}

type CSRFToken @table(database: "yeti-auth") @export {
  state: String @primaryKey
  provider: String
  redirectUri: String
  expiresAt: Int
  createdAt: Int
}

type OAuthSession @table(database: "yeti-auth") @export {
  sessionId: String @primaryKey
  provider: String
  providerType: String
  userData: String         # JSON blob
  accessToken: String
  refreshToken: String
  tokenExpiresAt: Int
  createdAt: Int
  expiresAt: Int
}
```

## Configuration

### JWT Settings (config.yaml `custom` block)

| Setting | Default | Description |
|---------|---------|-------------|
| `jwt.secret` | `${JWT_SECRET}` | HMAC signing secret (use env var in production) |
| `jwt.access_ttl` | `900` | Access token TTL in seconds (15 minutes) |
| `jwt.refresh_ttl` | `604800` | Refresh token TTL in seconds (7 days) |

### OAuth Provider Settings

| Environment Variable | Description |
|---------------------|-------------|
| `GITHUB_CLIENT_ID` | GitHub OAuth App client ID |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth App client secret |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret |

## Project Structure

```
yeti-auth/
├── config.yaml          # Extension configuration (JWT, OAuth providers)
├── schema.graphql       # User, Role, CSRFToken, OAuthSession tables
├── data/
│   ├── roles.json       # Seed roles (super_user, admin, standard, viewer)
│   └── users.json       # Seed users (alice, bob, charlie) with argon2 hashes
└── resources/
    ├── auth.rs           # Auth status endpoint
    ├── login.rs          # JWT login (POST /login)
    ├── jwt_refresh.rs    # Token refresh (POST /jwt_refresh)
    ├── users.rs          # User CRUD (GET/POST/PUT/DELETE /users)
    ├── roles.rs          # Role CRUD (GET/POST/PUT/DELETE /roles)
    ├── oauth_login.rs    # Initiate OAuth flow
    ├── oauth_callback.rs # Handle OAuth provider redirect
    ├── oauth_user.rs     # Current OAuth session info
    ├── oauth_logout.rs   # Clear OAuth session
    └── oauth_refresh.rs  # Refresh OAuth access token
```

## Learn More

- [Yeti Documentation](https://yetirocks.com/docs)
- [Authentication Guide](https://yetirocks.com/docs/guides/auth-overview)
- [JWT Authentication](https://yetirocks.com/docs/guides/auth-jwt)
- [OAuth Integration](https://yetirocks.com/docs/guides/auth-oauth)
- [Roles & Permissions](https://yetirocks.com/docs/guides/auth-rbac)

---

Built with [Yeti](https://yetirocks.com) - The fast, declarative database platform.
