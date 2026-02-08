use std::sync::Arc;

use http::StatusCode;
use parking_lot::MutexGuard;

use crate::models::BookScan;
use crate::state::AppState;

/// Helper to acquire read access to the scan data
/// Returns `SERVICE_UNAVAILABLE` status if scan is not ready
pub fn with_scan<T, F>(state: &Arc<AppState>, f: F) -> Result<T, (StatusCode, &'static str)>
where
    F: FnOnce(&BookScan) -> T,
{
    let locked = state.scan.lock();
    match locked.as_ref() {
        None => Err((StatusCode::SERVICE_UNAVAILABLE, "Service unavailable")),
        Some(scan) => Ok(f(scan)),
    }
}

/// Helper to acquire mutable access to the scan data
/// Returns `SERVICE_UNAVAILABLE` status if scan is not ready
pub fn with_scan_mut<T, F>(state: &Arc<AppState>, f: F) -> Result<T, (StatusCode, &'static str)>
where
    F: FnOnce(&mut BookScan) -> T,
{
    let mut locked = state.scan.lock();
    match locked.as_mut() {
        None => Err((StatusCode::SERVICE_UNAVAILABLE, "Service unavailable")),
        Some(scan) => Ok(f(scan)),
    }
}

/// Get the lock guard for the scan data
pub fn get_scan_lock(state: &Arc<AppState>) -> MutexGuard<'_, Option<BookScan>> {
    state.scan.lock()
}
