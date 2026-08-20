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
//!
//! A third is [`click_until`], and it is the one that matters most. Playwright's
//! `click` waits for the element's box to hold still across two animation frames
//! before it dispatches anything; `WebElement::click` dispatches immediately and
//! reports success as long as the driver accepted the command. On CI that
//! difference shows up as a click that lands on nothing: the command succeeds,
//! and the page never reacts. Every control here goes through `click_until`,
//! which confirms the click did what it was for and clicks again when it did
//! not.

use anyhow::{Context, Result, bail};
use thirtyfour::prelude::*;

use std::time::{Duration, Instant};

use crate::browser::{WAIT_INTERVAL, WAIT_TIMEOUT};
use crate::server::BASE_URL;

/// How many times to click a control that does not react.
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
    /// The card is a plain `<a href>`: a click on it navigates, and nothing in
    /// `app.js` intercepts it. On CI it sometimes does not — see
    /// [`click_until`], which is what makes this and every other click here
    /// retry rather than assert on a page that never moved.
    ///
    /// # Errors
    ///
    /// Fails when the library is empty, nothing became clickable in time, or
    /// no attempt navigated.
    pub async fn open_first_book(&self) -> Result<()> {
        let driver = self.0;
        click_until(
            driver,
            "the first book card",
            async || {
                Ok(driver
                    .query(By::Testid("book-card"))
                    .wait(WAIT_TIMEOUT, WAIT_INTERVAL)
                    .and_clickable()
                    .first()
                    .await?)
            },
            async || Ok(driver.current_url().await?.path().starts_with("/book/")),
        )
        .await
    }

    /// Submits the logout form, and confirms it reached the login page.
    ///
    /// # Errors
    ///
    /// Fails when the button is missing, or no attempt signed us out.
    pub async fn logout(&self) -> Result<()> {
        let driver = self.0;
        click_until(
            driver,
            "the logout button",
            async || Ok(driver.find(By::Testid("logout")).await?),
            async || Ok(driver.current_url().await?.path() == "/login"),
        )
        .await
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

    /// Clicks the "next page" zone, and confirms the page turned.
    ///
    /// # Errors
    ///
    /// Fails when the zone is missing, or no attempt turned the page.
    pub async fn advance(&self) -> Result<()> {
        let driver = self.0;
        let before = self.current_page_text().await?;
        click_until(
            driver,
            "the next-page zone",
            async || Ok(driver.find(By::Testid("reader-next")).await?),
            async || Ok(self.current_page_text().await? != before),
        )
        .await
    }

    /// Clicks the shared segmented control's "scroll" half, and confirms the
    /// reader switched.
    ///
    /// # Errors
    ///
    /// Fails when the control is missing, or no attempt switched the mode.
    pub async fn set_scroll_mode(&self) -> Result<()> {
        let driver = self.0;
        click_until(
            driver,
            "the segmented control's scroll half",
            async || Ok(driver.find(By::Testid("reader-mode-scroll")).await?),
            async || Ok(self.mode().await? == "scroll"),
        )
        .await
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
    /// Fails when no page is displayed, the displayed one has no such link, or
    /// no attempt moved off it.
    pub async fn follow_next(&self) -> Result<()> {
        self.click_on_visible_page("the next-page link", ".nojs-next")
            .await
    }

    /// Clicks the script-less "previous page" anchor on the displayed page.
    ///
    /// # Errors
    ///
    /// Fails when no page is displayed, the displayed one has no such link, or
    /// no attempt moved off it.
    pub async fn follow_previous(&self) -> Result<()> {
        self.click_on_visible_page("the previous-page link", ".nojs-prev")
            .await
    }

    /// The rail is anchors in both projects; with scripting on `app.js` cancels
    /// the jump, so this exercises the two paths through one control.
    ///
    /// # Errors
    ///
    /// Fails when the rail has no anchor for that page, or no attempt showed
    /// it.
    pub async fn jump_from_rail(&self, n: &str) -> Result<()> {
        let driver = self.0;
        let wanted = format!("p{n}");
        click_until(
            driver,
            &format!("the rail's anchor for page {n}"),
            async || {
                Ok(driver
                    .find(By::Css(format!(".thumbs a[href=\"#p{n}\"]")))
                    .await?)
            },
            // The rail is one control on two paths, so "it worked" has two
            // shapes: `:target` leaves page n the only one displayed, while
            // `app.js` also writes n into the topbar. Either is proof the click
            // landed; requiring both would fail whichever path is not in play.
            async || {
                if self.displayed_page_ids().await? == [wanted.clone()] {
                    return Ok(true);
                }
                Ok(self
                    .current_page_text()
                    .await?
                    .is_some_and(|text| text.trim() == n))
            },
        )
        .await
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
    /// Fails when that page has no switch, or no attempt changed the mode.
    pub async fn switch_mode_from(&self, n: &str) -> Result<()> {
        let driver = self.0;
        let before = self.mode().await?;
        click_until(
            driver,
            &format!("page {n}'s mode switch"),
            async || Ok(driver.find(By::Css(format!("#p{n} .nojs-mode"))).await?),
            async || Ok(self.mode().await? != before),
        )
        .await
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

    /// The topbar's live page number, as text — `None` without a script, where
    /// it is hidden rather than shown lying.
    async fn current_page_text(&self) -> Result<Option<String>> {
        match self.current_page().await? {
            Some(element) => Ok(Some(element.text().await?)),
            None => Ok(None),
        }
    }

    /// The ids of the `.pg` elements the browser is displaying, in document
    /// order — what "page 3 is the only one showing" is asking about.
    async fn displayed_page_ids(&self) -> Result<Vec<String>> {
        let mut ids = Vec::new();
        for page in self.visible_pages().await? {
            if let Some(id) = page.attr("id").await? {
                ids.push(id);
            }
        }
        Ok(ids)
    }

    async fn click_on_visible_page(&self, what: &str, css: &str) -> Result<()> {
        let before = self.displayed_page_ids().await?;
        click_until(
            self.0,
            what,
            async || self.element_on_visible_page(css).await,
            async || Ok(self.displayed_page_ids().await? != before),
        )
        .await
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

/// Clicks what `locate` finds, and confirms `took_effect` before returning.
///
/// `WebElement::click` reports success once the driver has dispatched the
/// event, which is not the same as the page having reacted to it. On CI the two
/// come apart often enough to fail a run in two: the command succeeds, the
/// element is exactly where it was, and nothing happens — every control is
/// affected, including plain `<a href>`s that no script touches. Playwright's
/// `click`, which this suite used to go through, waited for the element's box to
/// hold still across two animation frames first.
///
/// So each attempt is checked and repeated, which is also what a reader who
/// missed a tap would do. A click that never takes is a failure worth reporting
/// loudly, so the last word is [`probe_click_target`]'s: it says whether the
/// point that was clicked still belongs to the element, which separates "the
/// event never arrived" from "it arrived somewhere else".
async fn click_until<L, E>(driver: &WebDriver, what: &str, locate: L, took_effect: E) -> Result<()>
where
    L: AsyncFn() -> Result<WebElement>,
    E: AsyncFn() -> Result<bool>,
{
    let mut probes = Vec::new();

    for attempt in 1..=CLICK_ATTEMPTS {
        let element = locate().await?;
        // Best-effort: a page that will not take the recorder is one the probe
        // has little to say about either, and that is not worth failing on.
        let _ = arm_recorder(driver).await;
        element.click().await?;

        if settled(&took_effect).await? {
            if attempt > 1 {
                eprintln!("e2e: {what} took {attempt} clicks");
            }
            return Ok(());
        }

        // Gathered on the spot: this has only ever been seen on CI, so the run
        // that hits it is the only chance to learn why.
        let probe = probe_click_target(driver, &element)
            .await
            .unwrap_or_else(|e| format!("probe failed: {e}"));
        let url = driver.current_url().await?;
        eprintln!("e2e: click {attempt} on {what} had no effect; url={url} {probe}");
        probes.push(probe);

        if attempt == CLICK_ATTEMPTS {
            let scripted = scripted_click_works(driver, &element, &took_effect).await;
            eprintln!("e2e: scripted click on {what}: {scripted}");
            probes.push(format!("scriptedClick={scripted}"));
        }
    }

    bail!(
        "clicked {what} {CLICK_ATTEMPTS} times and it never took effect ({})",
        probes.join(" | ")
    )
}

/// Arms the in-page recorder [`probe_click_target`] reads back.
///
/// Three questions `elementFromPoint` cannot answer on its own, and between
/// them they separate every remaining explanation for a click that does
/// nothing:
///
/// * **Did any mouse event reach the page at all?** A capture-phase listener on
///   `window` records what arrived and where. Nothing recorded means the event
///   was dropped before the renderer saw it; a `mousedown` and a `mouseup` with
///   no `click` between them means they landed on different elements, which is
///   the layout-shift flake Playwright's stability wait avoided.
/// * **Is the renderer drawing?** `requestAnimationFrame` only fires while the
///   compositor is producing frames. A page that answers `Execute Script` — as
///   every probe so far proves it does — but never runs a frame callback is one
///   whose input path is not being serviced either.
/// * `document.hasFocus()` and `visibilityState`, which the probe reports, say
///   whether the browser considers this window worth either.
///
/// Installed once and reset per attempt: re-registering the listeners would
/// report every event as many times as we had clicked by then.
///
/// The `@nojs` scenarios get nothing out of this. `Execute Script` still runs
/// with `Emulation.setScriptExecutionDisabled` set, which is what keeps the
/// probe itself working, but a listener and a frame callback are script the
/// *document* runs, and that is exactly what the emulation switches off.
async fn arm_recorder(driver: &WebDriver) -> Result<()> {
    driver
        .execute(
            r"
            if (window.__e2e) {
                window.__e2e.events.length = 0;
                window.__e2e.frames = 0;
                return;
            }
            const state = { events: [], frames: 0 };
            window.__e2e = state;
            const name = (n) => n === null ? null : n.tagName.toLowerCase()
                + (n.id ? '#' + n.id : '')
                + (n.getAttribute('data-testid') ? '@' + n.getAttribute('data-testid') : '');
            for (const type of ['pointerdown', 'mousedown', 'mouseup', 'pointerup', 'click']) {
                window.addEventListener(type, (e) => {
                    if (state.events.length < 24) {
                        state.events.push(type + ':' + name(e.target)
                            + '@' + Math.round(e.clientX) + ',' + Math.round(e.clientY));
                    }
                }, true);
            }
            const tick = () => { state.frames++; requestAnimationFrame(tick); };
            requestAnimationFrame(tick);
            ",
            Vec::new(),
        )
        .await?;
    Ok(())
}

/// Clicks the element from script, and reports whether *that* took effect.
///
/// The last question, asked once every native click has been spent.
/// `HTMLElement.click()` skips hit-testing and the browser's input plumbing
/// entirely and dispatches straight at the element, so it follows a link or
/// submits a form that a real click could not reach. `took effect` says the
/// page and its handlers are fine and only the native input is not arriving;
/// `no effect either` says the failure is in the page, and the retry loop was
/// never the thing to fix.
///
/// Reported, never used to rescue the click: a suite that clicks from script
/// has stopped testing that the control is clickable, which is most of the
/// point of clicking it.
async fn scripted_click_works<E>(
    driver: &WebDriver,
    element: &WebElement,
    took_effect: &E,
) -> String
where
    E: AsyncFn() -> Result<bool>,
{
    let Ok(json) = element.to_json() else {
        return "unavailable".to_owned();
    };
    if let Err(e) = driver.execute("arguments[0].click();", vec![json]).await {
        return format!("failed: {e}");
    }
    match settled(took_effect).await {
        Ok(true) => "took effect".to_owned(),
        Ok(false) => "no effect either".to_owned(),
        Err(e) => format!("failed: {e}"),
    }
}

/// Polls `took_effect` for [`CLICK_SETTLE`], not the full [`WAIT_TIMEOUT`] — a
/// click that worked lands promptly, and this is on the path to trying again.
async fn settled<E>(took_effect: &E) -> Result<bool>
where
    E: AsyncFn() -> Result<bool>,
{
    let deadline = Instant::now() + CLICK_SETTLE;
    while Instant::now() < deadline {
        if took_effect().await? {
            return Ok(true);
        }
        tokio::time::sleep(WAIT_INTERVAL).await;
    }
    Ok(false)
}

/// Asks the page what is at the point a click would have landed on.
///
/// `document.elementFromPoint` at the element's own centre is the question the
/// logs could not answer before: if it comes back as the element (or something
/// inside it), the click was aimed correctly and the event was lost downstream;
/// if it comes back as anything else — or `null` — the point belonged to
/// something else at the moment of the click.
///
/// It also reports back what [`arm_recorder`] collected — the mouse events the
/// page actually received, and how many frames it drew while we waited — which
/// is what says whether the event arrived at all.
///
/// The driver can still inject script into a page whose own scripts are
/// disabled, so the `elementFromPoint` half reports on the `@nojs` scenarios
/// too. The recorder's half does not: `events` and `frames` come back `null`
/// there, because a listener and a frame callback are script the document runs.
///
/// `probe failed: Element is stale` is itself an answer, and a different one:
/// the click *did* navigate, and it is the caller's idea of "took effect" that
/// is wrong. The flake this exists for leaves the element right where it was.
async fn probe_click_target(driver: &WebDriver, element: &WebElement) -> Result<String> {
    let probe = driver
        .execute(
            r"
            const el = arguments[0];
            if (!el || !el.isConnected) { return { connected: false }; }
            const r = el.getBoundingClientRect();
            const x = r.left + r.width / 2, y = r.top + r.height / 2;
            const hit = document.elementFromPoint(x, y);
            const name = (n) => n === null ? null : n.tagName.toLowerCase()
                + (n.id ? '#' + n.id : '')
                + (n.getAttribute('data-testid') ? '@' + n.getAttribute('data-testid') : '');
            const style = getComputedStyle(el);
            const rec = window.__e2e;
            return {
                connected: true,
                ready: document.readyState,
                rect: [r.x, r.y, r.width, r.height],
                point: [x, y],
                viewport: [window.innerWidth, window.innerHeight],
                scroll: [window.scrollX, window.scrollY],
                hit: name(hit),
                hitIsTarget: hit === null ? false : (hit === el || el.contains(hit)),
                visibility: style.visibility,
                pointerEvents: style.pointerEvents,
                hasFocus: document.hasFocus(),
                visibilityState: document.visibilityState,
                frames: rec ? rec.frames : null,
                events: rec ? rec.events : null,
            };
            ",
            vec![element.to_json()?],
        )
        .await?;
    Ok(format!("probe={}", probe.json()))
}

/// Finds an element, mapping "not there" onto `None` rather than an error.
///
/// `nowait`, because every caller is asking about a page that has already
/// rendered — waiting 20 s to confirm an absence is the default poller's
/// behaviour, not ours.
async fn optional(driver: &WebDriver, by: By) -> Result<Option<WebElement>> {
    Ok(driver.query(by).nowait().first_opt().await?)
}
