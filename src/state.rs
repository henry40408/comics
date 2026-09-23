use std::{path::PathBuf, sync::Arc};

use cookie::Key;
use parking_lot::RwLock;
use tokio::sync::Semaphore;

use crate::auth::{AuthConfig, RateLimiter, SessionAuditSalt, SessionStore, TrustedProxies};
use crate::models::BookScan;

#[derive(Clone)]
pub struct AppState {
    pub auth_config: AuthConfig,
    /// Signs session cookies; derived from `COMICS_SECRET`.
    pub key: Key,
    pub data_dir: PathBuf,
    pub scan: Arc<RwLock<Option<BookScan>>>,
    /// Salt for book/page IDs; derived from `COMICS_SECRET`.
    pub seed: u64,
    pub cache_dir: PathBuf,
    /// Bounds concurrent thumbnail generation.
    pub thumb_sem: Arc<Semaphore>,
    /// Bounds concurrent Argon2id verifications (19 MiB each); see
    /// [`MAX_CONCURRENT_VERIFICATIONS`](crate::MAX_CONCURRENT_VERIFICATIONS).
    pub verify_sem: Arc<Semaphore>,
    pub cookie_secure: bool,
    pub login_limiter: Arc<RateLimiter>,
    /// Proxies whose `X-Forwarded-For` is trusted for the client IP. Empty by
    /// default: the TCP peer is used.
    pub trusted_proxies: TrustedProxies,
    /// In memory only, so a restart ends every session.
    pub sessions: Arc<SessionStore>,
    /// Salts session identifiers before they reach the audit log. Never logged.
    pub audit_salt: Arc<SessionAuditSalt>,
    /// `Strict-Transport-Security` max-age, in seconds.
    pub hsts_max_age: Option<u64>,
}
