pub mod auth;
pub mod error;
pub mod handlers;
pub mod helpers;
pub mod models;
pub mod state;

pub use auth::{AuthConfig, auth_middleware_fn};
pub use error::{AppError, AppResult};
pub use handlers::{
    healthz_route, index_route, rescan_books_route, show_book_route, show_page_route,
    shuffle_book_route, shuffle_route, Healthz,
};
pub use models::{scan_books, Book, BookScan, Dimension, Page};
pub use state::AppState;

pub const VERSION: &str = env!("APP_VERSION");
pub const BCRYPT_COST: u32 = 11u32;
