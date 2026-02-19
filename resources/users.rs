//! Users CRUD Resource
//!
//! REST API for managing users in the auth system.
//!
//! | Method | Path                        | Description                    |
//! |--------|-----------------------------|--------------------------------|
//! | GET    | /yeti-auth/users            | List all users (no pw hashes)  |
//! | GET    | /yeti-auth/users/{username}  | Get single user                |
//! | POST   | /yeti-auth/users            | Create user (hashes password)  |
//! | PUT    | /yeti-auth/users/{username}  | Update user                    |
//! | DELETE | /yeti-auth/users/{username}  | Delete user                    |

use yeti_core::prelude::*;

use crate::auth::{hash_password_or_err, TABLE_USER, TABLE_ROLE};

// Type alias for auto-generated lib.rs (compiler expects `Users` based on filename)
pub type Users = UsersResource;

#[derive(Default)]
pub struct UsersResource;

impl Resource for UsersResource {
    fn name(&self) -> &str {
        "users"
    }

    get!(request, ctx, {
        let user_table = ctx.get_table(TABLE_USER)?;

        // Single user by path ID
        if let Some(username) = ctx.path_id() {
            let record: Option<serde_json::Value> = user_table.get_by_id(username).await?;
            return match record {
                Some(mut user) => {
                    strip_password_hash(&mut user);
                    reply().json(user)
                }
                None => not_found(&format!("User '{}' not found", username)),
            };
        }

        // List all users
        let records: Vec<serde_json::Value> = user_table.scan_all().await?;
        let users: Vec<serde_json::Value> = records
            .into_iter()
            .map(|mut u| {
                strip_password_hash(&mut u);
                u
            })
            .collect();

        reply().json(json!(users))
    });

    post!(request, ctx, {
        let body = request.json_value()?;
        let username = body.require_str("username")?;
        let password = body.require_str("password")?;
        let role_id = body.opt_str("role").unwrap_or("viewer");
        let email = body.opt_str("email").unwrap_or("");

        let user_table = ctx.get_table(TABLE_USER)?;
        let role_table = ctx.get_table(TABLE_ROLE)?;

        // Check user doesn't already exist
        if user_table.get_by_id(&username).await?.is_some() {
            return bad_request(&format!("User '{}' already exists", username));
        }

        // Validate role exists
        if role_table.get_by_id(role_id).await?.is_none() {
            return bad_request(&format!("Role '{}' does not exist", role_id));
        }

        // Hash password
        let password_hash = hash_password_or_err(&password)?;

        let now = unix_timestamp()? as i64;
        let record = json!({
            "username": username,
            "passwordHash": password_hash,
            "active": body.get_bool("active", true),
            "roleId": role_id,
            "email": email,
            "createdAt": now,
            "updatedAt": now,
        });

        user_table.put(&username, record.clone()).await?;
        eprintln!("[yeti-auth] USER_CREATED: username={}", username);

        let mut response = record;
        strip_password_hash(&mut response);
        reply().code(201).json(response)
    });

    put!(request, ctx, {
        let username = ctx.require_id()?.to_string();
        let body = request.json_value()?;

        let user_table = ctx.get_table(TABLE_USER)?;
        let role_table = ctx.get_table(TABLE_ROLE)?;

        // Check user exists
        let existing: Option<serde_json::Value> = user_table.get_by_id(&username).await?;
        let Some(existing) = existing else {
            return not_found(&format!("User '{}' not found", username));
        };

        // If role is being changed, validate it exists
        if let Some(new_role) = body.opt_str("role") {
            if role_table.get_by_id(new_role).await?.is_none() {
                return bad_request(&format!("Role '{}' does not exist", new_role));
            }
        }

        let now = unix_timestamp()? as i64;
        let mut updated = existing.clone();

        // Update fields if provided
        if let Some(email) = body.opt_str("email") {
            updated["email"] = json!(email);
        }
        if let Some(role) = body.opt_str("role") {
            updated["roleId"] = json!(role);
        }
        if let Some(active) = body.opt_bool("active") {
            updated["active"] = json!(active);
        }
        if let Some(password) = body.opt_str("password") {
            let password_hash = hash_password_or_err(password)?;
            updated["passwordHash"] = json!(password_hash);
        }
        updated["updatedAt"] = json!(now);

        user_table.put(&username, updated.clone()).await?;
        eprintln!("[yeti-auth] USER_UPDATED: username={}", username);

        strip_password_hash(&mut updated);
        reply().json(updated)
    });

    delete!(_request, ctx, {
        let username = ctx.require_id()?.to_string();
        let user_table = ctx.get_table(TABLE_USER)?;

        let deleted = user_table.delete(&username).await?;
        if deleted {
            eprintln!("[yeti-auth] USER_DELETED: username={}", username);
            reply().json(json!({"deleted": true, "username": username}))
        } else {
            not_found(&format!("User '{}' not found", username))
        }
    });
}

/// Strip passwordHash from a user record before returning it
fn strip_password_hash(user: &mut serde_json::Value) {
    if let Some(obj) = user.as_object_mut() {
        obj.remove("passwordHash");
    }
}

register_resource!(UsersResource);
