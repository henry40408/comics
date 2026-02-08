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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthConfig;
    use crate::models::BookScan;
    use chrono::TimeDelta;
    use parking_lot::Mutex;
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn create_test_state(scan: Option<BookScan>) -> Arc<AppState> {
        Arc::new(AppState {
            auth_config: AuthConfig::None,
            data_dir: PathBuf::from("/tmp"),
            scan: Arc::new(Mutex::new(scan)),
            seed: 0,
        })
    }

    fn create_test_scan() -> BookScan {
        BookScan {
            books: vec![],
            pages_map: HashMap::new(),
            scan_duration: TimeDelta::zero(),
            scanned_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn with_scan_returns_error_when_none() {
        let state = create_test_state(None);
        let result = with_scan(&state, |_| 42);
        assert!(result.is_err());
        let (status, msg) = result.unwrap_err();
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(msg, "Service unavailable");
    }

    #[test]
    fn with_scan_returns_value_when_some() {
        let state = create_test_state(Some(create_test_scan()));
        let result = with_scan(&state, |scan| scan.books.len());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn with_scan_mut_returns_error_when_none() {
        let state = create_test_state(None);
        let result = with_scan_mut(&state, |_| 42);
        assert!(result.is_err());
        let (status, msg) = result.unwrap_err();
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(msg, "Service unavailable");
    }

    #[test]
    fn with_scan_mut_returns_value_when_some() {
        let state = create_test_state(Some(create_test_scan()));
        let result = with_scan_mut(&state, |scan| {
            scan.books.clear();
            scan.books.len()
        });
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn get_scan_lock_returns_guard() {
        let state = create_test_state(Some(create_test_scan()));
        let guard = get_scan_lock(&state);
        assert!(guard.is_some());
    }
}
