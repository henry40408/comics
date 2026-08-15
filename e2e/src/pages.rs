//! Page objects, one per surface, ported from `e2e/pages/*.js`.
//!
//! Two Playwright conveniences have no `WebDriver` equivalent and are rebuilt
//! here:
//!
//! * `.pg:visible` — Playwright's `:visible` pseudo-class. [`visible_pages`]
//!   asks each `.pg` whether it is displayed instead. That is a *driver-side*
//!   computation, not page script, so it keeps working in the `@nojs`
//!   scenarios where the page's own JavaScript is switched off.
//! * `toBeInViewport` — [`is_in_viewport`] compares the element's rect against
//!   the visual viewport reported by CDP, again for the same reason.

use anyhow::{Context, Result, bail};
use thirtyfour::prelude::*;

use std::time::{Duration, Instant};

use crate::browser::{WAIT_INTERVAL, WAIT_TIMEOUT};
use crate::server::BASE_URL;

/// How many times to click a book card that does not navigate.
const CLICK_ATTEMPTS: usize = 3;

/// How long to give a click before deciding it did not take.
const CLICK_SETTLE: Duration = Duration::from_secs(5);

/// The login page (`/login`).
pub struct LoginPage<'a>(pub &'a WebDriver);

impl LoginPage<'_> {
    /// Navigates to `/login`.
    ///
    /// # Errors
    ///
    /// Fails when the navigation does not complete.
    pub async fn goto(&self) -> Result<()> {
        self.0.goto(format!("{BASE_URL}/login")).await?;
        Ok(())
    }

    /// Fills the form and submits it.
    ///
    /// # Errors
    ///
    /// Fails when a field or the submit button is missing.
    pub async fn login(&self, username: &str, password: &str) -> Result<()> {
        self.0
            .find(By::Testid("login-username"))
            .await?
            .send_keys(username)
            .await?;
        self.0
            .find(By::Testid("login-password"))
            .await?
            .send_keys(password)
            .await?;
        self.0
            .find(By::Testid("login-submit"))
            .await?
            .click()
            .await?;
        Ok(())
    }

    /// The "wrong credentials" banner, if the page is showing one.
    ///
    /// # Errors
    ///
    /// Fails only on a driver error; a missing banner is `Ok(None)`.
    pub async fn error(&self) -> Result<Option<WebElement>> {
        optional(self.0, By::Testid("login-error")).await
    }
}

/// The library index (`/`).
pub struct LibraryPage<'a>(pub &'a WebDriver);

impl LibraryPage<'_> {
    /// Navigates to `/`.
    ///
    /// # Errors
    ///
    /// Fails when the navigation does not complete.
    pub async fn goto(&self) -> Result<()> {
        self.0.goto(BASE_URL).await?;
        Ok(())
    }

    /// Every book card on the page.
    ///
    /// # Errors
    ///
    /// Fails only on a driver error; no cards is an empty `Vec`.
    pub async fn cards(&self) -> Result<Vec<WebElement>> {
        Ok(self.0.find_all(By::Testid("book-card")).await?)
    }

    /// Clicks the first book card, and confirms it actually opened one.
    ///
    /// The card is a plain `<a href>`, so a click on it should navigate and
    /// nothing in `app.js` intercepts it. On a loaded CI runner it sometimes
    /// does not: the click reports success and the URL never changes. The most
    /// likely cause is the cover image — `loading="lazy"`, so it arrives after
    /// first paint and reflows the card out from under a click whose target
    /// point was computed a moment earlier.
    ///
    /// Rather than wait for every image and slow down the common path, this
    /// checks whether the navigation happened and clicks again if it did not.
    /// A click that silently does nothing is the one failure mode worth
    /// retrying: it is indistinguishable from a missed tap by a real reader,
    /// who would also just click again.
    ///
    /// # Errors
    ///
    /// Fails when the library is empty, nothing became clickable in time, or
    /// no attempt navigated.
    pub async fn open_first_book(&self) -> Result<()> {
        for attempt in 1..=CLICK_ATTEMPTS {
            let card = self
                .0
                .query(By::Testid("book-card"))
                .wait(WAIT_TIMEOUT, WAIT_INTERVAL)
                .and_clickable()
                .first()
                .await?;
            let before = card.rect().await?;
            card.click().await?;

            if self.reached_a_book().await? {
                if attempt > 1 {
                    eprintln!("e2e: the book card took {attempt} clicks to open");
                }
                return Ok(());
            }

            // Printed rather than swallowed: this path has only ever been seen
            // on CI, so the run that hits it is the only chance to learn why.
            // If `after` differs from `before`, the card moved out from under
            // the click and the lazy-loaded cover is the likely cause.
            let after = self.0.find(By::Testid("book-card")).await?.rect().await?;
            eprintln!(
                "e2e: click {attempt} on the book card did not navigate; \
                 url={} rect before={before:?} after={after:?}",
                self.0.current_url().await?
            );
        }
        bail!("clicked the first book card {CLICK_ATTEMPTS} times and never left the library")
    }

    /// Did the last click land us in a book? Polls briefly, not for the full
    /// [`WAIT_TIMEOUT`] — a click that worked navigates promptly, and this is
    /// on the path to trying again.
    async fn reached_a_book(&self) -> Result<bool> {
        let deadline = Instant::now() + CLICK_SETTLE;
        while Instant::now() < deadline {
            if self.0.current_url().await?.path().starts_with("/book/") {
                return Ok(true);
            }
            tokio::time::sleep(WAIT_INTERVAL).await;
        }
        Ok(false)
    }

    /// Submits the logout form.
    ///
    /// # Errors
    ///
    /// Fails when the button is missing.
    pub async fn logout(&self) -> Result<()> {
        self.0.find(By::Testid("logout")).await?.click().await?;
        Ok(())
    }
}

/// The reader (`/book/{id}`).
pub struct ReaderPage<'a>(pub &'a WebDriver);

impl ReaderPage<'_> {
    /// The topbar's live page number — script-written, and hidden without one.
    ///
    /// # Errors
    ///
    /// Fails only on a driver error.
    pub async fn current_page(&self) -> Result<Option<WebElement>> {
        optional(self.0, By::Testid("reader-current")).await
    }

    /// Clicks the "next page" zone.
    ///
    /// # Errors
    ///
    /// Fails when the zone is missing.
    pub async fn advance(&self) -> Result<()> {
        self.0
            .find(By::Testid("reader-next"))
            .await?
            .click()
            .await?;
        Ok(())
    }

    /// Clicks the shared segmented control's "scroll" half.
    ///
    /// # Errors
    ///
    /// Fails when the control is missing.
    pub async fn set_scroll_mode(&self) -> Result<()> {
        self.0
            .find(By::Testid("reader-mode-scroll"))
            .await?
            .click()
            .await?;
        Ok(())
    }

    /// Is this the reader's own `<body class="reader">`?
    ///
    /// # Errors
    ///
    /// Fails only on a driver error.
    pub async fn is_showing(&self) -> Result<bool> {
        Ok(self
            .0
            .query(By::Css("body.reader"))
            .nowait()
            .exists()
            .await?)
    }

    /// The reader stores its mode on `<body data-mode="…">`.
    ///
    /// # Errors
    ///
    /// Fails when `<body>` carries no `data-mode`.
    pub async fn mode(&self) -> Result<String> {
        self.0
            .find(By::Css("body"))
            .await?
            .attr("data-mode")
            .await?
            .context("<body> has no data-mode")
    }

    /// The page container with the given 1-based number.
    ///
    /// # Errors
    ///
    /// Fails when no such page exists.
    pub async fn page(&self, n: &str) -> Result<WebElement> {
        Ok(self.0.find(By::Id(format!("p{n}"))).await?)
    }

    /// The `.pg` elements the browser is actually displaying.
    ///
    /// # Errors
    ///
    /// Fails only on a driver error.
    pub async fn visible_pages(&self) -> Result<Vec<WebElement>> {
        let mut visible = Vec::new();
        for page in self.0.find_all(By::Css(".pg")).await? {
            if page.is_displayed().await? {
                visible.push(page);
            }
        }
        Ok(visible)
    }

    /// Clicks the script-less "next page" anchor on the displayed page.
    ///
    /// # Errors
    ///
    /// Fails when no page is displayed, or the displayed one has no such link.
    pub async fn follow_next(&self) -> Result<()> {
        self.click_on_visible_page(".nojs-next").await
    }

    /// Clicks the script-less "previous page" anchor on the displayed page.
    ///
    /// # Errors
    ///
    /// Fails when no page is displayed, or the displayed one has no such link.
    pub async fn follow_previous(&self) -> Result<()> {
        self.click_on_visible_page(".nojs-prev").await
    }

    /// The rail is anchors in both projects; with scripting on `app.js` cancels
    /// the jump, so this exercises the two paths through one control.
    ///
    /// # Errors
    ///
    /// Fails when the rail has no anchor for that page.
    pub async fn jump_from_rail(&self, n: &str) -> Result<()> {
        self.0
            .find(By::Css(format!(".thumbs a[href=\"#p{n}\"]")))
            .await?
            .click()
            .await?;
        Ok(())
    }

    /// The per-page counter on the displayed page (`3 / 3`).
    ///
    /// # Errors
    ///
    /// Fails when no page is displayed, or it carries no counter.
    pub async fn counter_text(&self) -> Result<String> {
        Ok(self
            .element_on_visible_page(".nojs-counter")
            .await?
            .text()
            .await?)
    }

    /// The theme toggle, which only a script can operate.
    ///
    /// # Errors
    ///
    /// Fails only on a driver error.
    pub async fn theme_toggle(&self) -> Result<Option<WebElement>> {
        optional(self.0, By::Id("theme")).await
    }

    /// The shared segmented control, which cannot carry your place across a
    /// script-less mode switch and so is hidden without a script.
    ///
    /// # Errors
    ///
    /// Fails only on a driver error.
    pub async fn shared_mode_control(&self) -> Result<Option<WebElement>> {
        optional(self.0, By::Id("seg")).await
    }

    /// The per-page mode switch, which carries that page's anchor across the
    /// change.
    ///
    /// # Errors
    ///
    /// Fails when that page has no switch.
    pub async fn switch_mode_from(&self, n: &str) -> Result<()> {
        self.0
            .find(By::Css(format!("#p{n} .nojs-mode")))
            .await?
            .click()
            .await?;
        Ok(())
    }

    /// The topbar's subtitle, as *rendered* text.
    ///
    /// `WebDriver`'s "Get Element Text" returns rendered text, so a
    /// `display: none` counter inside it does not contribute — which is what
    /// the old assertion needed `useInnerText: true` for.
    ///
    /// # Errors
    ///
    /// Fails when the topbar is missing.
    pub async fn topbar_subtitle(&self) -> Result<String> {
        Ok(self.0.find(By::Css(".titleblock .s")).await?.text().await?)
    }

    async fn click_on_visible_page(&self, css: &str) -> Result<()> {
        self.element_on_visible_page(css).await?.click().await?;
        Ok(())
    }

    async fn element_on_visible_page(&self, css: &str) -> Result<WebElement> {
        for page in self.visible_pages().await? {
            if let Ok(found) = page.find(By::Css(css)).await {
                return Ok(found);
            }
        }
        bail!("no displayed `.pg` carries `{css}`")
    }
}

/// Finds an element, mapping "not there" onto `None` rather than an error.
///
/// `nowait`, because every caller is asking about a page that has already
/// rendered — waiting 20 s to confirm an absence is the default poller's
/// behaviour, not ours.
async fn optional(driver: &WebDriver, by: By) -> Result<Option<WebElement>> {
    Ok(driver.query(by).nowait().first_opt().await?)
}
