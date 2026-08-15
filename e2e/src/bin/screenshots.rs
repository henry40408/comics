//! Regenerates the screenshots in `docs/screenshots/`, which `README.md` embeds.
//!
//! Run it with `cargo run --bin screenshots` from `e2e/`. It is a binary rather
//! than a scenario because it produces artefacts instead of asserting things —
//! `playwright.config.js` kept it apart for the same reason, as a project of
//! its own that `npm test` did not run.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use comics_e2e::browser::{Browser, Scripting, WAIT_INTERVAL, WAIT_TIMEOUT};
use comics_e2e::server::{BASE_URL, PASSWORD, Server, USERNAME};
use comics_e2e::wait::eventually;
use thirtyfour::prelude::*;

const THEMES: [&str; 2] = ["light", "dark"];

#[tokio::main]
async fn main() -> Result<()> {
    let _server = Server::start()?;
    let out = out_dir();
    std::fs::create_dir_all(&out).with_context(|| format!("creating {}", out.display()))?;

    for theme in THEMES {
        // A fresh session per theme, with no stored preference: an emulated
        // `prefers-color-scheme` and nothing in `localStorage` is the app's
        // system-follow path, which picks the matching palette pre-paint.
        let browser = Browser::open(Scripting::Enabled).await?;
        browser.emulate_color_scheme(theme).await?;

        let driver = browser.driver();
        log_in(driver).await?;

        driver.goto(BASE_URL).await?;
        capture(&browser, &out.join(format!("library-{theme}.png"))).await?;

        driver
            .query(By::Testid("book-card"))
            .wait(WAIT_TIMEOUT, WAIT_INTERVAL)
            .first()
            .await?
            .click()
            .await?;
        driver
            .query(By::Css("#pages img"))
            .wait(WAIT_TIMEOUT, WAIT_INTERVAL)
            .and_displayed()
            .first()
            .await?;
        capture(&browser, &out.join(format!("reader-{theme}.png"))).await?;

        browser.quit().await?;
        println!("wrote the {theme} pair");
    }

    Ok(())
}

async fn log_in(driver: &WebDriver) -> Result<()> {
    driver.goto(format!("{BASE_URL}/login")).await?;
    driver
        .find(By::Testid("login-username"))
        .await?
        .send_keys(USERNAME)
        .await?;
    driver
        .find(By::Testid("login-password"))
        .await?
        .send_keys(PASSWORD)
        .await?;
    driver
        .find(By::Testid("login-submit"))
        .await?
        .click()
        .await?;
    driver
        .query(By::Testid("book-card"))
        .wait(WAIT_TIMEOUT, WAIT_INTERVAL)
        .first()
        .await?;
    Ok(())
}

/// Waits for every `<img>` to finish decoding.
///
/// Replaces Playwright's `waitForLoadState('networkidle')`, which had no way to
/// say what it was actually waiting for. Thumbnails are generated on demand, so
/// the first run of a fresh cache is the slow one — and a screenshot taken
/// mid-generation shows empty covers.
///
/// Only the *rendered* images count, and only with the viewport already
/// stretched to the whole page. Every `<img>` here is `loading="lazy"`: one
/// still below the fold has not started loading, and in the reader's paged mode
/// the pages that are not current are `display: none`, so their images never
/// load at all. Waiting on those would be waiting forever — and they are not in
/// the screenshot either way.
async fn wait_for_images(browser: &Browser) -> Result<()> {
    eventually("every rendered image has loaded", || async {
        let ready = browser
            .driver()
            .execute(
                "return Array.from(document.images)
                    .filter((i) => i.getClientRects().length > 0)
                    .every((i) => i.complete && i.naturalWidth > 0);",
                Vec::new(),
            )
            .await?
            .json()
            .as_bool()
            .unwrap_or(false);
        Ok(ready)
    })
    .await?;
    // Thumbnails fade in; without this the covers are caught mid-transition.
    tokio::time::sleep(Duration::from_millis(300)).await;
    Ok(())
}

/// Takes a full-page screenshot.
///
/// `WebDriver`'s own "Take Screenshot" is viewport-sized, so the page is measured
/// first and the viewport stretched to fit — the CDP equivalent of Playwright's
/// `fullPage: true`.
async fn capture(browser: &Browser, path: &Path) -> Result<()> {
    // Measured twice: the first stretch brings the lazy images into view, and
    // loading them is what settles the final height.
    browser
        .stretch_viewport_to(page_height(browser).await?)
        .await?;
    wait_for_images(browser).await?;
    browser
        .stretch_viewport_to(page_height(browser).await?)
        .await?;

    browser.driver().screenshot(path).await?;
    browser.reset_viewport().await?;
    Ok(())
}

async fn page_height(browser: &Browser) -> Result<u64> {
    browser
        .driver()
        .execute(
            "return Math.ceil(Math.max(
                document.body.scrollHeight, document.documentElement.scrollHeight));",
            Vec::new(),
        )
        .await?
        .json()
        .as_u64()
        .context("could not measure the page height")
}

/// `docs/screenshots/`, next to the repository root.
fn out_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("e2e/ always has a parent")
        .join("docs/screenshots")
}
