//! OAuth Logout Resource
//!
//! Clears the OAuth session from both in-memory cache and database, and deletes the cookie.
//!
//! # Endpoint
//!
//! `POST /yeti-auth/oauth_logout`

use yeti_core::prelude::*;
use crate::auth::{SESSION_COOKIE, delete_session_from_db, get_session_cache};

#[derive(Clone, Default)]
pub struct OauthLogout;

impl Resource for OauthLogout {
    fn name(&self) -> &str { "oauth_logout" }

    fn post(&self, req: Request<Vec<u8>>, ctx: ResourceParams) -> ResourceFuture {
        Box::pin(async move {
            if let Some(session_id) = CookieParser::get_cookie(&req, SESSION_COOKIE) {
                if let Ok(cache) = get_session_cache() {
                    cache.remove(&session_id);
                }
                // Also remove from persistent storage
                if let Ok(tables) = ctx.tables() {
                    delete_session_from_db(&tables, &session_id).await;
                }
            }

            let delete_cookie = CookieBuilder::delete(SESSION_COOKIE);

            ok(json!({ "success": true, "message": "Logged out" }))
                .add_header("Set-Cookie", &delete_cookie)
        })
    }
}
