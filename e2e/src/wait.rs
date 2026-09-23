//! Retrying assertions.
//!
//! `WebDriver` has no retrying-assertion layer: a `find` that runs before
//! `app.js` has swapped a class reports the old state. `ElementQuery` covers
//! "wait for an element"; these cover computed values that have to settle,
//! like the URL after a form post.

use std::fmt::Debug;
use std::future::Future;
use std::time::Instant;

use anyhow::{Result, bail};

use crate::browser::{WAIT_INTERVAL, WAIT_TIMEOUT};

/// Polls `probe` until it reports the expected value; on timeout the error
/// names the last value seen.
pub async fn eventually_eq<T, E, F, Fut>(what: &str, expected: E, mut probe: F) -> Result<()>
where
    T: Debug,
    E: Debug + PartialEq<T>,
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let deadline = Instant::now() + WAIT_TIMEOUT;
    let mut last = probe().await?;
    loop {
        if expected == last {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("{what}: expected {expected:?}, last saw {last:?} after {WAIT_TIMEOUT:?}");
        }
        tokio::time::sleep(WAIT_INTERVAL).await;
        last = probe().await?;
    }
}

/// Polls `probe` until it reports `true`.
pub async fn eventually<F, Fut>(what: &str, mut probe: F) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<bool>>,
{
    let deadline = Instant::now() + WAIT_TIMEOUT;
    loop {
        if probe().await? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("{what}: still not true after {WAIT_TIMEOUT:?}");
        }
        tokio::time::sleep(WAIT_INTERVAL).await;
    }
}
