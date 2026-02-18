//! OAuth Login Resource
//!
//! Initiates the OAuth authorization code flow by redirecting the user
//! to the provider's authorization URL.
//!
//! # Endpoint
//!
//! `GET /yeti-auth/oauth_login?provider=github&redirect_uri=/web-auth-demo/`

use yeti_core::prelude::*;
use crate::auth::{SHARED_OAUTH_PROVIDERS, store_csrf_state, build_callback_url};

#[derive(Clone, Default)]
pub struct OauthLogin;

impl Resource for OauthLogin {
    fn name(&self) -> &str { "oauth_login" }

    fn get(&self, req: Request<Vec<u8>>, _ctx: ResourceParams) -> ResourceFuture {
        Box::pin(async move {
            let uri = req.uri().to_string();
            let params = parse_query_string(&uri);

            let provider_name = match params.get("provider") {
                Some(p) => p.clone(),
                None => return bad_request("Missing 'provider' query parameter"),
            };

            let redirect_uri = params.get("redirect_uri")
                .cloned()
                .unwrap_or_else(|| "/".to_string());

            let providers = SHARED_OAUTH_PROVIDERS.get()
                .ok_or_else(|| YetiError::Internal("OAuth not initialized".to_string()))?;

            let provider = match providers.providers.get(&provider_name) {
                Some(p) => p,
                None => {
                    let available: Vec<&str> = providers.providers.keys().map(|s| s.as_str()).collect();
                    return bad_request(&format!(
                        "Unknown OAuth provider '{}'. Available: {:?}",
                        provider_name, available
                    ));
                }
            };

            // Generate CSRF state token
            let state = TokenGenerator::csrf_token();
            store_csrf_state(&state, &provider_name, &redirect_uri);

            // Build callback URL from request
            let callback_url = build_callback_url(&req);

            // Build provider authorize URL
            let authorize_url = format!(
                "{}?response_type=code&client_id={}&redirect_uri={}&state={}&scope={}",
                provider.authorize_url,
                urlencoding::encode(&provider.client_id),
                urlencoding::encode(&callback_url),
                urlencoding::encode(&state),
                urlencoding::encode(&provider.scopes.join(" ")),
            );

            reply().redirect(&authorize_url, Some(302))
        })
    }
}
