use std::{path::PathBuf, sync::Arc};

use parking_lot::Mutex;

use crate::auth::AuthConfig;
use crate::models::BookScan;

/// Application state shared across all handlers
#[derive(Clone)]
pub struct AppState {
    pub auth_config: AuthConfig,
    pub data_dir: PathBuf,
    pub scan: Arc<Mutex<Option<BookScan>>>,
    pub seed: u64,
}
