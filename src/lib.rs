pub mod assets;
pub mod auth;
pub mod error;
pub mod handlers;
pub mod helpers;
pub mod models;
pub mod state;

pub use assets::{APP_CSS, APP_JS, APPLE_TOUCH_ICON_PNG, FAVICON_PNG, FAVICON_SVG, assets_version};
pub use auth::{AuthConfig, auth_middleware_fn};
pub use error::{AppError, AppResult};
pub use handlers::{
    Healthz, healthz_route, index_route, rescan_books_route, show_book_route, show_page_route,
    shuffle_book_route, shuffle_route,
};
pub use models::{Book, BookScan, Dimension, Page, scan_books};
pub use state::AppState;

pub const VERSION: &str = env!("APP_VERSION");
pub const BCRYPT_COST: u32 = 11u32;
