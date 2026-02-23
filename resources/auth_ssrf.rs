//! SSRF validation for OAuth provider URLs

use yeti_core::prelude::*;
use crate::auth_types::OAuthProviderConfig;

// ============================================================================
// SSRF Validation
// ============================================================================

/// Well-known OAuth provider domains that are always allowed
const TRUSTED_OAUTH_HOSTS: &[&str] = &[
    "github.com",
    "api.github.com",
    "accounts.google.com",
    "oauth2.googleapis.com",
    "www.googleapis.com",
    "login.microsoftonline.com",
    "graph.microsoft.com",
];

/// Validate that a URL is safe for server-side requests (prevents SSRF).
/// Rejects private IPs, localhost, and non-HTTPS URLs.
/// In development mode, non-HTTPS generates a warning instead of an error.
fn validate_provider_url(url: &str, label: &str) -> std::result::Result<(), String> {
    // Extract scheme
    let (scheme, rest) = url.split_once("://")
        .ok_or_else(|| format!("{}: invalid URL '{}' (no scheme)", label, url))?;

    // Check scheme — HTTPS required (warn in dev)
    if scheme != "https" {
        let is_dev = std::env::var("YETI_ENV")
            .unwrap_or_else(|_| "development".to_string()) == "development";
        if is_dev {
            yeti_log!(warn, "WARNING: {} URL '{}' uses {} (non-HTTPS) — only acceptable in development", label, url, scheme);
        } else {
            return Err(format!("{}: URL '{}' must use HTTPS in production", label, url));
        }
    }

    // Extract host (strip path, port, query)
    let host_and_port = rest.split('/').next().unwrap_or(rest);
    let host = if host_and_port.starts_with('[') {
        // IPv6: [::1]:port
        host_and_port.split(']').next().unwrap_or(host_and_port).trim_start_matches('[')
    } else {
        host_and_port.split(':').next().unwrap_or(host_and_port)
    };

    if host.is_empty() {
        return Err(format!("{}: URL '{}' has no host", label, url));
    }

    // Trusted hosts are always allowed
    if TRUSTED_OAUTH_HOSTS.iter().any(|&trusted| host == trusted) {
        return Ok(());
    }

    // Reject localhost and loopback
    let host_lower = host.to_lowercase();
    if host_lower == "localhost" || host_lower == "127.0.0.1" || host_lower == "::1"
        || host_lower == "0.0.0.0"
    {
        return Err(format!("{}: URL '{}' points to localhost (SSRF risk)", label, url));
    }

    // Reject private IP ranges
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        let is_private = match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_private()       // 10.x, 172.16-31.x, 192.168.x
                    || v4.is_link_local()    // 169.254.x
                    || v4.octets()[0] == 0   // 0.0.0.0/8
            }
            std::net::IpAddr::V6(v6) => {
                v6.is_loopback()             // ::1
                    || v6.segments()[0] == 0xfe80 // link-local
                    || v6.segments()[0] == 0xfc00 || v6.segments()[0] == 0xfd00 // unique local
            }
        };
        if is_private {
            return Err(format!("{}: URL '{}' points to private/internal IP (SSRF risk)", label, url));
        }
    }

    Ok(())
}

/// Validate all URLs for an OAuth provider configuration
pub fn validate_provider_urls(name: &str, config: &OAuthProviderConfig) -> std::result::Result<(), String> {
    let label = format!("OAuth provider '{}'", name);
    validate_provider_url(&config.authorize_url, &format!("{} authorize_url", label))?;
    validate_provider_url(&config.token_url, &format!("{} token_url", label))?;
    validate_provider_url(&config.user_info_url, &format!("{} user_info_url", label))?;
    if let Some(ref emails_url) = config.user_emails_url {
        validate_provider_url(emails_url, &format!("{} user_emails_url", label))?;
    }
    Ok(())
}
