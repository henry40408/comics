//! The browser session, and the two emulations the suite depends on.
//!
//! `WebDriver::managed` downloads and supervises a matching chromedriver
//! itself, so nothing has to be installed alongside the tests — but it does
//! *not* download the browser, unlike the Playwright setup this replaces. A
//! Chrome or Chromium in one of the well-known locations is a prerequisite now;
//! [`Browser::open`] says so in as many words when it is missing, because the
//! raw driver error does not.
//!
//! Both emulations go through CDP rather than `BiDi`.
//! `Emulation.setEmulatedMedia` is the only way to reach
//! `prefers-color-scheme` at all. `Emulation.setScriptExecutionDisabled` is a
//! choice: `BiDi`'s `emulation.setScriptingEnabled` would work, but pulls in the
//! non-default `bidi` feature and a WebSocket stack for something CDP already
//! does over the connection we have — and it is what Playwright's
//! `javaScriptEnabled: false` did underneath anyway.

use std::time::Duration;

use anyhow::{Context, Result};
use thirtyfour::prelude::*;

/// How long a query waits for a condition before giving up.
///
/// Only ever paid in full by a genuine failure, so it is set for the slowest
/// machine rather than the fastest: locally every wait settles well under a
/// second, while a two-core CI runner driving several browsers took longer than
/// the original 10 s to land a navigation.
pub const WAIT_TIMEOUT: Duration = Duration::from_secs(30);

/// How often a query re-checks while waiting.
pub const WAIT_INTERVAL: Duration = Duration::from_millis(100);

/// Viewport, matching the `Desktop Chrome` device the Playwright projects used.
const WINDOW: (u32, u32) = (1280, 720);

/// Whether the page's own scripts run — the `e2e` / `e2e-nojs` split.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scripting {
    /// The scripted path: `app.js` and `theme.js` run.
    Enabled,
    /// The `@nojs` path: the page's own scripts never execute.
    Disabled,
}

/// A browser session, scoped to one scenario.
#[derive(Debug)]
pub struct Browser {
    driver: WebDriver,
}

impl Browser {
    /// Starts a headless session with the page's scripts on or off.
    pub async fn open(scripting: Scripting) -> Result<Self> {
        let mut caps = DesiredCapabilities::chrome();
        caps.set_headless()?;
        caps.add_arg(&format!("--window-size={},{}", WINDOW.0, WINDOW.1))?;
        // Containers get a 64 MB /dev/shm by default, which Chrome outgrows.
        caps.add_arg("--disable-dev-shm-usage")?;
        // Chrome backgrounds a window it believes nobody is looking at, and a
        // backgrounded renderer throttles timers and stops servicing input
        // promptly — while script driven over CDP keeps answering, that path
        // being unthrottled. Exactly the shape of the clicks CI drops.
        //
        // Playwright passed all three of these and did not flake; the port did
        // not carry them over. They change nothing about what is tested, only
        // whether the browser is listening.
        caps.add_arg("--disable-backgrounding-occluded-windows")?;
        caps.add_arg("--disable-renderer-backgrounding")?;
        caps.add_arg("--disable-background-timer-throttling")?;

        let driver = WebDriver::managed(caps).await.context(
            "could not start a browser session — a local Chrome or Chromium is required \
             (`brew install --cask ungoogled-chromium`, or `google-chrome` on CI); \
             unlike Playwright, the driver manager downloads only the driver",
        )?;

        let browser = Self { driver };
        if scripting == Scripting::Disabled {
            browser.disable_scripting().await?;
        }
        Ok(browser)
    }

    /// Downloads and starts the driver once, before any scenario asks for it.
    ///
    /// `WebDriver::managed` builds a *new* manager per call, so each session
    /// prepares the driver for itself: harmless when it is cached, and a stall
    /// rather than a slowdown when it is not, as several sessions opening at
    /// once contend on the same download's lock file. CI has a cold cache every
    /// run, and is exactly where the scenarios run in parallel. One session
    /// opened and closed up front settles it.
    pub async fn prepare() -> Result<()> {
        Self::open(Scripting::Enabled).await?.quit().await
    }

    /// The underlying session, for the page objects.
    #[must_use]
    pub fn driver(&self) -> &WebDriver {
        &self.driver
    }

    /// Emulates `prefers-color-scheme`, with no stored preference — the app's
    /// system-follow path, which is what the screenshots are meant to show.
    pub async fn emulate_color_scheme(&self, scheme: &str) -> Result<()> {
        self.driver
            .cdp()
            .send_raw(
                "Emulation.setEmulatedMedia",
                serde_json::json!({
                    "media": "screen",
                    "features": [{ "name": "prefers-color-scheme", "value": scheme }],
                }),
            )
            .await?;
        Ok(())
    }

    /// Is the element intersecting the viewport?
    ///
    /// Rebuilds Playwright's `toBeInViewport`, whose default ratio is "any
    /// overlap at all"; `WebElement::rect` reports document coordinates, so it
    /// cannot answer this once the page has scrolled. Works under `@nojs` too:
    /// `Emulation.setScriptExecutionDisabled` stops the document's scripts, not
    /// `Execute Script`.
    pub async fn is_in_viewport(&self, id: &str) -> Result<bool> {
        let visible = self
            .driver
            .execute(
                r"
                const el = document.getElementById(arguments[0]);
                if (!el) { return null; }
                const r = el.getBoundingClientRect();
                return r.bottom > 0 && r.right > 0
                    && r.top < window.innerHeight && r.left < window.innerWidth;
                ",
                vec![serde_json::json!(id)],
            )
            .await?
            .json()
            .as_bool()
            .with_context(|| format!("no element with id `{id}`"))?;
        Ok(visible)
    }

    /// Grows the viewport to `height`, so a screenshot catches the whole page.
    pub async fn stretch_viewport_to(&self, height: u64) -> Result<()> {
        self.driver
            .cdp()
            .send_raw(
                "Emulation.setDeviceMetricsOverride",
                serde_json::json!({
                    "width": WINDOW.0,
                    "height": height.max(u64::from(WINDOW.1)),
                    "deviceScaleFactor": 1,
                    "mobile": false,
                }),
            )
            .await?;
        Ok(())
    }

    /// Undoes [`Browser::stretch_viewport_to`].
    pub async fn reset_viewport(&self) -> Result<()> {
        self.driver
            .cdp()
            .send_raw(
                "Emulation.clearDeviceMetricsOverride",
                serde_json::json!({}),
            )
            .await?;
        Ok(())
    }

    /// Ends the session.
    pub async fn quit(self) -> Result<()> {
        self.driver.quit().await?;
        Ok(())
    }

    /// Stops the page's own scripts from running.
    ///
    /// Takes effect on the *next* document, so it is issued before the first
    /// navigation — which is why sessions are per-scenario rather than shared.
    async fn disable_scripting(&self) -> Result<()> {
        self.driver
            .cdp()
            .send_raw(
                "Emulation.setScriptExecutionDisabled",
                serde_json::json!({ "value": true }),
            )
            .await?;
        Ok(())
    }
}
