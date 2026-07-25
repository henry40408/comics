use std::{path::PathBuf, sync::Arc};

use cookie::Key;
use parking_lot::RwLock;
use tokio::sync::Semaphore;

use crate::auth::{AuthConfig, RateLimiter, SessionAuditSalt};
use crate::models::BookScan;

/// Application state shared across all handlers
#[derive(Clone)]
pub struct AppState {
    pub auth_config: AuthConfig,
    /// Secret key used to sign session cookies. Taken from `COMICS_SESSION_KEY`
    /// when set; otherwise generated at startup, in which case a restart
    /// invalidates every existing session.
    pub key: Key,
    pub data_dir: PathBuf,
    pub scan: Arc<RwLock<Option<BookScan>>>,
    pub seed: u64,
    /// Directory where generated thumbnails are cached.
    pub cache_dir: PathBuf,
    /// Bounds concurrent thumbnail generation (CPU-bound decode + resize).
    pub thumb_sem: Arc<Semaphore>,
    /// Whether the session cookie is issued with the `Secure` attribute.
    pub cookie_secure: bool,
    /// Throttles `POST /login` per client IP.
    pub login_limiter: Arc<RateLimiter>,
    /// Salts session identifiers before they reach the audit log. Never logged.
    pub audit_salt: Arc<SessionAuditSalt>,
    /// `Strict-Transport-Security` max-age in seconds, when HSTS is enabled.
    pub hsts_max_age: Option<u64>,
}
