//! The Cucumber world: one browser session per scenario.
//!
//! The session cannot be opened in `new`, because whether the page's scripts
//! run is decided by the scenario's `@nojs` tag and `World::new` never sees it.
//! A `before` hook opens it instead, which is also the only order that works:
//! `Emulation.setScriptExecutionDisabled` applies to the next document, so it
//! has to be issued before the first navigation.

use anyhow::{Context, Result};
use cucumber::World;
use thirtyfour::prelude::WebDriver;

use crate::browser::{Browser, Scripting};
use crate::pages::{LibraryPage, LoginPage, ReaderPage};

/// State shared by the steps of one scenario.
#[derive(Debug, World)]
#[world(init = Self::new)]
pub struct ComicsWorld {
    browser: Option<Browser>,
}

impl ComicsWorld {
    fn new() -> Self {
        Self { browser: None }
    }

    /// Opens the session for a scenario.
    ///
    /// # Errors
    ///
    /// Fails when no browser session can be started.
    pub async fn open(&mut self, scripting: Scripting) -> Result<()> {
        self.browser = Some(Browser::open(scripting).await?);
        Ok(())
    }

    /// Ends the session, if one was opened.
    ///
    /// # Errors
    ///
    /// Fails when the driver refuses to close.
    pub async fn close(&mut self) -> Result<()> {
        if let Some(browser) = self.browser.take() {
            browser.quit().await?;
        }
        Ok(())
    }

    /// The scenario's browser.
    ///
    /// # Errors
    ///
    /// Fails when no session was opened — a `before` hook that did not run.
    pub fn browser(&self) -> Result<&Browser> {
        self.browser
            .as_ref()
            .context("no browser session: the `before` hook did not open one")
    }

    /// The scenario's driver.
    ///
    /// # Errors
    ///
    /// Fails when no session was opened.
    pub fn driver(&self) -> Result<&WebDriver> {
        Ok(self.browser()?.driver())
    }

    /// The login page object.
    ///
    /// # Errors
    ///
    /// Fails when no session was opened.
    pub fn login_page(&self) -> Result<LoginPage<'_>> {
        Ok(LoginPage(self.driver()?))
    }

    /// The library page object.
    ///
    /// # Errors
    ///
    /// Fails when no session was opened.
    pub fn library_page(&self) -> Result<LibraryPage<'_>> {
        Ok(LibraryPage(self.driver()?))
    }

    /// The reader page object.
    ///
    /// # Errors
    ///
    /// Fails when no session was opened.
    pub fn reader_page(&self) -> Result<ReaderPage<'_>> {
        Ok(ReaderPage(self.driver()?))
    }

    /// The current URL's path, the shape the steps assert against.
    ///
    /// # Errors
    ///
    /// Fails when the driver cannot report a URL.
    pub async fn path(&self) -> Result<String> {
        Ok(self.driver()?.current_url().await?.path().to_string())
    }
}
