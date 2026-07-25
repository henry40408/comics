pub mod assets;
pub mod auth;
pub mod csrf;
pub mod error;
pub mod handlers;
pub mod helpers;
pub mod models;
pub mod security_headers;
pub mod state;

pub use assets::{APP_CSS, APP_JS, APPLE_TOUCH_ICON_PNG, FAVICON_PNG, FAVICON_SVG, assets_version};
pub use auth::{
    AuthConfig, RateLimiter, SessionAuditSalt, auth_middleware_fn, build_session_removal_cookie,
    hex_lower, parse_session_key, rate_limit_key, session_cookie_name,
};
pub use csrf::csrf_origin_guard;
pub use error::{AppError, AppResult};
pub use handlers::{
    Healthz, healthz_route, index_route, login_route, login_submit_route, logout_route,
    rescan_books_route, show_book_route, show_page_route, show_thumb_route, shuffle_book_route,
    shuffle_route,
};
pub use models::{Book, BookScan, Page, scan_books};
pub use security_headers::{hsts_layer, no_store_html};
pub use state::AppState;

pub const VERSION: &str = env!("APP_VERSION");
pub const BCRYPT_COST: u32 = 11u32;
