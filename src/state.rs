use std::{path::PathBuf, sync::Arc};

use cookie::Key;
use parking_lot::RwLock;
use tokio::sync::Semaphore;

use crate::auth::AuthConfig;
use crate::models::BookScan;

/// Application state shared across all handlers
#[derive(Clone)]
pub struct AppState {
    pub auth_config: AuthConfig,
    /// Secret key used to sign session cookies. Generated at startup, so a
    /// restart invalidates every existing session.
    pub key: Key,
    pub data_dir: PathBuf,
    pub scan: Arc<RwLock<Option<BookScan>>>,
    pub seed: u64,
    /// Directory where generated thumbnails are cached.
    pub cache_dir: PathBuf,
    /// Bounds concurrent thumbnail generation (CPU-bound decode + resize).
    pub thumb_sem: Arc<Semaphore>,
}
