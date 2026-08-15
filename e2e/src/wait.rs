//! Retrying assertions.
//!
//! Playwright's `expect(...)` polls until the assertion holds or a timeout
//! expires, which is what let the old steps write `await expect(page).toHaveURL('/')`
//! straight after a click. `WebDriver` has no such layer: a `find` that runs
//! before `app.js` has finished swapping a class simply reports the old state.
//!
//! thirtyfour's `ElementQuery` filters cover the cases that are really "wait for
//! an element matching X", and the page objects use them. These two helpers
//! cover the rest — a computed value that has to settle, like the number of
//! displayed pages or the URL after a form post.

use std::fmt::Debug;
use std::future::Future;
use std::time::Instant;

use anyhow::{Result, bail};

use crate::browser::{WAIT_INTERVAL, WAIT_TIMEOUT};

/// Polls `probe` until it reports the expected value.
///
/// On timeout the failure names the last value seen, not merely that a wait
/// expired — that is the difference between "the counter never reached 2" and a
/// message you have to reproduce by hand to understand.
///
/// # Errors
///
/// Fails when `probe` errors, or when the value has still not matched by
/// [`WAIT_TIMEOUT`].
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
///
/// # Errors
///
/// Fails when `probe` errors, or when it has still not held by
/// [`WAIT_TIMEOUT`].
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
