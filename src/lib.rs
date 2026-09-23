pub mod assets;
pub mod auth;
pub mod error;
pub mod handlers;
pub mod helpers;
pub mod models;
pub mod secret;
pub mod security_headers;
pub mod state;

pub use assets::{
    APP_CSS, APP_JS, APPLE_TOUCH_ICON_PNG, FAVICON_PNG, FAVICON_SVG, THEME_JS, assets_version,
};
pub use auth::{
    AuthConfig, DEFAULT_ABSOLUTE_TTL, DEFAULT_IDLE_TTL, RateLimiter, SessionAuditSalt,
    SessionStore, TrustedProxies, auth_middleware_fn, build_session_removal_cookie, rate_limit_key,
    session_cookie_name,
};
pub use error::{AppError, AppResult};
pub use handlers::{
    Healthz, healthz_route, index_route, login_route, login_submit_route, logout_route,
    rescan_books_route, show_book_route, show_page_route, show_thumb_route, shuffle_book_route,
    shuffle_route,
};
pub use models::{Book, BookScan, Page, scan_books};
pub use secret::{Secret, hex_lower};
pub use security_headers::{no_store_html, security_headers_layer};
pub use state::AppState;

pub const VERSION: &str = env!("APP_VERSION");

/// Longest password accepted, in bytes.
///
/// A backstop against absurd input (OWASP's "maximum input length"), not an
/// Argon2 limit. 1024 bytes is ~341 Traditional Chinese characters, well past
/// the 64 characters OWASP asks be supported.
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// Shortest password `hash-password` accepts without a warning, in
/// **characters** (OWASP's minimum without a second factor).
///
/// Advice, not a rule: the one user is the operator, and a hard floor would only
/// push them to hash elsewhere. Characters, not bytes like
/// [`MAX_PASSWORD_BYTES`]: the floor measures memorability, the ceiling
/// resource use.
pub const MIN_PASSWORD_CHARS: usize = 15;

/// How many password verifications may run at once.
///
/// Argon2id at the default parameters allocates **19 MiB per verification**, so
/// the 20 attempts the rate limiter admits could want 380 MiB at once — on what
/// may be a NAS. Four caps it near 76 MiB; excess requests queue, not fail.
pub const MAX_CONCURRENT_VERIFICATIONS: usize = 4;

/// A test-only Argon2 hash at far cheaper parameters (1 MiB, one pass).
/// Verification reads them from the hash, so tests use the real code path, and
/// it stays well above a string comparison, as the timing test needs.
#[cfg(test)]
pub(crate) fn test_password_hash(password: &str) -> String {
    use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher as _, Version};
    let params = Params::new(1024, 1, 1, None).expect("valid test parameters");
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let hash: PasswordHash = argon
        .hash_password(password.as_bytes())
        .expect("hashing a test password");
    hash.to_string()
}
