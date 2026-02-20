//! OAuth Providers Resource
//!
//! Returns the list of configured OAuth providers with public info only.
//! Never exposes client secrets or client IDs.
//!
//! # Endpoint
//!
//! `GET /yeti-auth/oauth_providers`

use yeti_core::prelude::*;
use crate::auth::get_oauth_providers;

#[derive(Clone, Default)]
pub struct OauthProviders;

impl Resource for OauthProviders {
    fn name(&self) -> &str { "oauth_providers" }

    fn get(&self, _req: Request<Vec<u8>>, _ctx: ResourceParams) -> ResourceFuture {
        Box::pin(async move {
            let providers = get_oauth_providers()?;

            let list: Vec<serde_json::Value> = providers.providers.iter().map(|(name, config)| {
                json!({
                    "name": name,
                    "type": config.provider_type,
                    "authorize_url": config.authorize_url,
                    "scopes": config.scopes,
                })
            }).collect();

            ok(json!({ "providers": list }))
        })
    }
}
