pub mod assets;
pub mod auth;
pub mod csrf;
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
pub use csrf::csrf_origin_guard;
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
pub const BCRYPT_COST: u32 = 11u32;

/// Bytes of a password bcrypt actually hashes.
///
/// The algorithm reads no further, and the `bcrypt` crate's `hash`/`verify`
/// *silently* drop the rest rather than erroring — so without a check of our own
/// a 100-character passphrase would be its first 72 bytes wearing a disguise,
/// and the operator would never be told. The OWASP Authentication Cheat Sheet
/// asks for the opposite ("Do not silently truncate passwords") and for a
/// maximum input length on the comparison function; this constant is both.
///
/// It bites soonest in the language this reader is written for: a Traditional
/// Chinese passphrase is three bytes per character, so the limit lands at 24
/// characters, well inside what someone might reasonably choose.
///
/// The crate offers `non_truncating_hash`/`non_truncating_verify`, which error
/// instead. They are not used here because they reject a *72*-byte password too
/// (the limit is exclusive there), and because rejecting at the prompt says more
/// than an error at verification time can.
pub const MAX_PASSWORD_BYTES: usize = 72;
