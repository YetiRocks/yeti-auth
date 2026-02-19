//! OAuth User Info Resource
//!
//! Returns the current OAuth user's session info, or 401 if not authenticated.
//! Falls back to the OAuthSession table on in-memory cache miss (e.g. after restart).
//!
//! # Endpoint
//!
//! `GET /yeti-auth/oauth_user`

use yeti_core::prelude::*;
use crate::auth::{load_session_from_db, get_session_cookie, get_session_cache};

#[derive(Clone, Default)]
pub struct OauthUser;

impl Resource for OauthUser {
    fn name(&self) -> &str { "oauth_user" }

    fn get(&self, req: Request<Vec<u8>>, ctx: ResourceParams) -> ResourceFuture {
        Box::pin(async move {
            let Some(session_id) = get_session_cookie(&req) else {
                return unauthorized("No OAuth session");
            };
            let session_cache = get_session_cache()?;

            // Try in-memory cache first
            if let Some((user, provider, provider_type)) = session_cache.get(&session_id) {
                return ok(json!({
                    "authenticated": true,
                    "user": user,
                    "provider": provider,
                    "provider_type": provider_type,
                }));
            }

            // Cache miss — try the database (survives restarts)
            if let Ok(tables) = ctx.tables() {
                if let Some((user, provider, provider_type, tokens)) =
                    load_session_from_db(&tables, &session_id).await
                {
                    // Re-populate the in-memory cache
                    if let Some(t) = tokens {
                        session_cache.set_with_tokens(
                            session_id, user.clone(), provider.clone(),
                            provider_type.clone(), t,
                        );
                    } else {
                        session_cache.set(
                            session_id, user.clone(), provider.clone(),
                            provider_type.clone(),
                        );
                    }

                    return ok(json!({
                        "authenticated": true,
                        "user": user,
                        "provider": provider,
                        "provider_type": provider_type,
                    }));
                }
            }

            unauthorized("Invalid or expired session")
        })
    }
}
