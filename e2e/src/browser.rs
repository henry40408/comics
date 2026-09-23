//! The browser session, and the two emulations the suite depends on.
//!
//! `WebDriver::managed` downloads chromedriver but *not* the browser, so a
//! local Chrome or Chromium is a prerequisite; [`Browser::open`] says so when
//! it is missing, because the raw driver error does not.
//!
//! Both emulations use CDP. `Emulation.setEmulatedMedia` is the only way to
//! reach `prefers-color-scheme`; `BiDi`'s `emulation.setScriptingEnabled`
//! would work for scripting, but needs the non-default `bidi` feature and a
//! WebSocket stack.

use std::time::Duration;

use anyhow::{Context, Result};
use thirtyfour::prelude::*;

/// How long a query waits for a condition before giving up.
///
/// Only a genuine failure pays it in full, so it is sized for a two-core CI
/// runner driving several browsers, where 10 s was not enough.
pub const WAIT_TIMEOUT: Duration = Duration::from_secs(30);

/// How often a query re-checks while waiting.
pub const WAIT_INTERVAL: Duration = Duration::from_millis(100);

/// Viewport size.
const WINDOW: (u32, u32) = (1280, 720);

/// Whether the page's own scripts run — the `@nojs` split.
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
        // A backgrounded renderer throttles timers and stops servicing input
        // promptly while CDP script keeps answering — the shape of the clicks
        // CI drops. These change nothing about what is tested.
        caps.add_arg("--disable-backgrounding-occluded-windows")?;
        caps.add_arg("--disable-renderer-backgrounding")?;
        caps.add_arg("--disable-background-timer-throttling")?;

        let driver = WebDriver::managed(caps).await.context(
            "could not start a browser session — a local Chrome or Chromium is required \
             (`brew install --cask ungoogled-chromium`, or `google-chrome` on CI); \
             `WebDriver::managed` downloads only the driver, not the browser",
        )?;

        let browser = Self { driver };
        if scripting == Scripting::Disabled {
            browser.disable_scripting().await?;
        }
        Ok(browser)
    }

    /// Downloads and starts the driver once, before any scenario asks for it.
    ///
    /// `WebDriver::managed` prepares the driver per call; on a cold cache,
    /// several sessions opening at once contend on the download's lock file
    /// and stall rather than slow down.
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
    /// Any overlap counts. Not `WebElement::rect`, which reports document
    /// coordinates and so cannot answer once the page has scrolled. Works under
    /// `@nojs`, which stops the document's scripts but not `Execute Script`.
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
