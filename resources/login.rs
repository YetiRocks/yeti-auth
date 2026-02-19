//! JWT Login Resource
//!
//! Authenticates with username/password and returns JWT access + refresh tokens.
//! The access token embeds the user's role and permissions so no DB lookup
//! is needed when validating requests.
//!
//! | Method | Path              | Description                        |
//! |--------|-------------------|------------------------------------|
//! | POST   | /yeti-auth/login  | Login with credentials, get tokens |
//!
//! ## Request Body
//! ```json
//! { "username": "admin", "password": "admin123" }
//! ```
//!
//! ## Response (200)
//! ```json
//! {
//!   "access_token": "eyJ...",
//!   "refresh_token": "eyJ...",
//!   "expires_in": 900,
//!   "token_type": "Bearer"
//! }
//! ```

use std::sync::OnceLock;
use std::time::Instant;
use yeti_core::prelude::*;
use crate::auth::{Permission, verify_password, get_jwt_manager, TABLE_USER, TABLE_ROLE};

/// Per-username login attempt tracking for rate limiting
struct LoginAttempts {
    count: u32,
    first_attempt: Instant,
    last_failure: Option<Instant>,
    consecutive_failures: u32,
}

static LOGIN_TRACKER: OnceLock<DashMap<String, LoginAttempts>> = OnceLock::new();

fn login_tracker() -> &'static DashMap<String, LoginAttempts> {
    LOGIN_TRACKER.get_or_init(DashMap::new)
}

/// Max login attempts per username per minute
const MAX_ATTEMPTS_PER_MINUTE: u32 = 10;
/// Consecutive failures before exponential backoff kicks in
const BACKOFF_THRESHOLD: u32 = 5;

pub type Login = LoginResource;

#[derive(Default)]
pub struct LoginResource;

impl Resource for LoginResource {
    fn name(&self) -> &str {
        "login"
    }

    post!(request, ctx, {
        let body = request.json_value()?;
        let username = body.require_str("username")?;
        let password = body.require_str("password")?;

        // Rate limiting: check per-username login attempts
        let tracker = login_tracker();
        let rate_key = username.to_string();

        // Cleanup stale entries periodically (every 100 checks)
        static CLEANUP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        if CLEANUP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % 100 == 0 {
            let cutoff = Instant::now() - std::time::Duration::from_secs(60);
            tracker.retain(|_, v| v.first_attempt > cutoff);
        }

        // Check rate limit
        if let Some(attempts) = tracker.get(&rate_key) {
            let elapsed = attempts.first_attempt.elapsed();
            if elapsed < std::time::Duration::from_secs(60) && attempts.count >= MAX_ATTEMPTS_PER_MINUTE {
                eprintln!("[yeti-auth] LOGIN_RATE_LIMITED: username={}", username);
                return reply().status(429).json(json!({
                    "error": "Too many login attempts. Please try again later."
                }));
            }
            // Exponential backoff after consecutive failures
            if attempts.consecutive_failures >= BACKOFF_THRESHOLD {
                if let Some(last) = attempts.last_failure {
                    let backoff_secs = 2u64.pow((attempts.consecutive_failures - BACKOFF_THRESHOLD).min(4));
                    if last.elapsed() < std::time::Duration::from_secs(backoff_secs) {
                        eprintln!("[yeti-auth] LOGIN_BACKOFF: username={} backoff={}s", username, backoff_secs);
                        return reply().status(429).json(json!({
                            "error": "Too many failed attempts. Please wait before trying again."
                        }));
                    }
                }
            }
        }

        // Record this attempt
        {
            let mut entry = tracker.entry(rate_key.clone()).or_insert_with(|| LoginAttempts {
                count: 0,
                first_attempt: Instant::now(),
                last_failure: None,
                consecutive_failures: 0,
            });
            // Reset window if over 60s
            if entry.first_attempt.elapsed() >= std::time::Duration::from_secs(60) {
                entry.count = 0;
                entry.first_attempt = Instant::now();
            }
            entry.count += 1;
        }

        // Look up user in database
        let user_table = ctx.get_table(TABLE_USER)?;
        let user_record: Option<serde_json::Value> = user_table.get(Some(&username)).await?;

        let Some(user) = user_record else {
            if let Some(mut attempts) = tracker.get_mut(&rate_key) {
                attempts.consecutive_failures += 1;
                attempts.last_failure = Some(Instant::now());
            }
            eprintln!("[yeti-auth] LOGIN_FAILED: username={} reason=user_not_found", username);
            return unauthorized("Invalid username or password");
        };

        // Check if user is active
        let active = user.get_bool("active", false);
        if !active {
            if let Some(mut attempts) = tracker.get_mut(&rate_key) {
                attempts.consecutive_failures += 1;
                attempts.last_failure = Some(Instant::now());
            }
            eprintln!("[yeti-auth] LOGIN_FAILED: username={} reason=account_disabled", username);
            return unauthorized("Account is disabled");
        }

        // Verify password
        let pw_hash = match user.opt_str("passwordHash") {
            Some(h) => h,
            None => {
                if let Some(mut attempts) = tracker.get_mut(&rate_key) {
                    attempts.consecutive_failures += 1;
                    attempts.last_failure = Some(Instant::now());
                }
                eprintln!("[yeti-auth] LOGIN_FAILED: username={} reason=no_password_hash", username);
                return unauthorized("Invalid username or password");
            }
        };

        match verify_password(&password, pw_hash) {
            Ok(true) => {}
            _ => {
                if let Some(mut attempts) = tracker.get_mut(&rate_key) {
                    attempts.consecutive_failures += 1;
                    attempts.last_failure = Some(Instant::now());
                }
                eprintln!("[yeti-auth] LOGIN_FAILED: username={} reason=invalid_password", username);
                return unauthorized("Invalid username or password");
            }
        }

        // Look up role permissions to embed in token
        let role_id = user.opt_str("roleId");
        let permissions = if let Some(role_id) = role_id {
            let role_table = ctx.get_table(TABLE_ROLE)?;
            let role_record: Option<serde_json::Value> = role_table.get(Some(role_id)).await?;
            role_record
                .and_then(|r| r.get("permissions")?.as_str().map(|s| s.to_string()))
                .and_then(|s| serde_json::from_str::<Permission>(&s).ok())
        } else {
            None
        };

        // Generate JWT token pair with embedded permissions
        let jwt_manager = get_jwt_manager()?;
        let tokens = jwt_manager.generate_tokens(&username, role_id, permissions)?;

        // Reset failure tracking on successful login
        tracker.remove(&rate_key);

        eprintln!("[yeti-auth] LOGIN_SUCCESS: username={}", username);
        reply().json(json!({
            "access_token": tokens.access_token,
            "refresh_token": tokens.refresh_token,
            "expires_in": tokens.expires_in,
            "token_type": "Bearer"
        }))
    });
}

register_resource!(LoginResource);
