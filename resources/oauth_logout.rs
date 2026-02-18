//! OAuth Logout Resource
//!
//! Clears the OAuth session from both in-memory cache and database, and deletes the cookie.
//!
//! # Endpoint
//!
//! `POST /yeti-auth/oauth_logout`

use yeti_core::prelude::*;
use crate::auth::{SHARED_SESSION_CACHE, delete_session_from_db};

#[derive(Clone, Default)]
pub struct OauthLogout;

impl Resource for OauthLogout {
    fn name(&self) -> &str { "oauth_logout" }

    fn post(&self, req: Request<Vec<u8>>, ctx: ResourceParams) -> ResourceFuture {
        Box::pin(async move {
            if let Some(session_id) = CookieParser::get_cookie(&req, "yeti_session") {
                if let Some(cache) = SHARED_SESSION_CACHE.get() {
                    cache.remove(&session_id);
                }
                // Also remove from persistent storage
                if let Ok(tables) = ctx.tables() {
                    delete_session_from_db(&tables, &session_id).await;
                }
            }

            let delete_cookie = CookieBuilder::delete("yeti_session");

            ok(json!({ "success": true, "message": "Logged out" }))
                .add_header("Set-Cookie", &delete_cookie)
        })
    }
}
