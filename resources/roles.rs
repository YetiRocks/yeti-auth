//! Roles CRUD Resource
//!
//! REST API for managing roles in the auth system.
//!
//! | Method | Path                      | Description                     |
//! |--------|---------------------------|---------------------------------|
//! | GET    | /yeti-auth/roles          | List all roles with permissions |
//! | GET    | /yeti-auth/roles/{id}     | Get single role                 |
//! | POST   | /yeti-auth/roles          | Create role                     |
//! | PUT    | /yeti-auth/roles/{id}     | Update role permissions         |
//! | DELETE | /yeti-auth/roles/{id}     | Delete role (protected roles)   |

use yeti_core::prelude::*;
use crate::auth::{TABLE_ROLE, TABLE_USER, ROLE_SUPER_USER};

// Type alias for auto-generated lib.rs (compiler expects `Roles` based on filename)
pub type Roles = RolesResource;

#[derive(Default)]
pub struct RolesResource;

impl Resource for RolesResource {
    fn name(&self) -> &str {
        "roles"
    }

    get!(_request, ctx, {
        let role_table = ctx.get_table(TABLE_ROLE)?;

        // Single role by path ID
        if let Some(role_id) = ctx.path_id() {
            let record: Option<serde_json::Value> = role_table.get_by_id(role_id).await?;
            return match record {
                Some(role) => reply().json(enrich_role(role)),
                None => not_found(&format!("Role '{}' not found", role_id)),
            };
        }

        // List all roles
        let records: Vec<serde_json::Value> = role_table.scan_all().await?;
        let roles: Vec<serde_json::Value> = records.into_iter().map(enrich_role).collect();

        reply().json(json!(roles))
    });

    post!(request, ctx, {
        let body = request.json_value()?;
        let id = body.require_str("id")?;
        let name = body.opt_str("name").unwrap_or(&id);

        let role_table = ctx.get_table(TABLE_ROLE)?;

        // Check role doesn't already exist
        if role_table.get_by_id(&id).await?.is_some() {
            return bad_request(&format!("Role '{}' already exists", id));
        }

        // Serialize permissions to JSON string (stored as string in DB)
        let default_perms = json!({"super_user": false});
        let permissions = body.get("permissions")
            .unwrap_or(&default_perms);
        let permissions_str = serde_json::to_string(permissions)
            .map_err(|e| YetiError::Validation(format!("Invalid permissions: {}", e)))?;

        let now = unix_timestamp()? as i64;
        let record = json!({
            "id": id,
            "name": name,
            "permissions": permissions_str,
            "createdAt": now,
        });

        role_table.put(&id, record.clone()).await?;
        eprintln!("[yeti-auth] ROLE_CREATED: role_id={}", id);
        reply().code(201).json(enrich_role(record))
    });

    put!(request, ctx, {
        let role_id = ctx.require_id()?.to_string();
        let body = request.json_value()?;

        let role_table = ctx.get_table(TABLE_ROLE)?;

        // Check role exists
        let existing: Option<serde_json::Value> = role_table.get_by_id(&role_id).await?;
        let Some(existing) = existing else {
            return not_found(&format!("Role '{}' not found", role_id));
        };

        // Protect super_user: cannot remove super_user privilege
        if role_id == ROLE_SUPER_USER {
            if let Some(perms) = body.get("permissions") {
                let is_super = perms.get("super_user")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if !is_super {
                    return bad_request("Cannot remove super_user privilege from the super_user role");
                }
            }
        }

        let mut updated = existing;

        // Update fields if provided
        if let Some(name) = body.opt_str("name") {
            updated["name"] = json!(name);
        }
        if let Some(permissions) = body.get("permissions") {
            let permissions_str = serde_json::to_string(permissions)
                .map_err(|e| YetiError::Validation(format!("Invalid permissions: {}", e)))?;
            updated["permissions"] = json!(permissions_str);
        }

        role_table.put(&role_id, updated.clone()).await?;
        eprintln!("[yeti-auth] ROLE_UPDATED: role_id={}", role_id);
        reply().json(enrich_role(updated))
    });

    delete!(_request, ctx, {
        let role_id = ctx.require_id()?.to_string();

        // Protect super_user role from deletion
        if role_id == ROLE_SUPER_USER {
            return bad_request("Cannot delete the super_user role");
        }

        let role_table = ctx.get_table(TABLE_ROLE)?;

        // Check no users reference this role before deleting
        let user_table = ctx.get_table(TABLE_USER)?;
        let users: Vec<serde_json::Value> = user_table.scan_all().await?;
        let referencing_users: Vec<&str> = users.iter()
            .filter(|u| u.opt_str("roleId") == Some(role_id.as_str()))
            .filter_map(|u| u.opt_str("username"))
            .collect();

        if !referencing_users.is_empty() {
            return bad_request(&format!(
                "Cannot delete role '{}': referenced by users: {}",
                role_id,
                referencing_users.join(", ")
            ));
        }

        let deleted = role_table.delete(&role_id).await?;
        if deleted {
            eprintln!("[yeti-auth] ROLE_DELETED: role_id={}", role_id);
            reply().json(json!({"deleted": true, "id": role_id}))
        } else {
            not_found(&format!("Role '{}' not found", role_id))
        }
    });
}

/// Parse the permissions JSON string into a JSON object for the response.
/// DB stores permissions as a JSON string; enrich it to an object for the API.
fn enrich_role(mut role: serde_json::Value) -> serde_json::Value {
    if let Some(perms_str) = role.get("permissions").and_then(|v| v.as_str()) {
        if let Ok(perms_obj) = serde_json::from_str::<serde_json::Value>(perms_str) {
            role["permissions"] = perms_obj;
        }
    }
    role
}

register_resource!(RolesResource);
