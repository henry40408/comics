//! Page objects, one per surface.
//!
//! Every click goes through `click_until`: on CI, `WebElement::click` can
//! succeed without the page ever receiving the event.

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
    pub async fn goto(&self) -> Result<()> {
        self.0.goto(format!("{BASE_URL}/login")).await?;
        Ok(())
    }

    /// Fills the form and submits it.
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
    pub async fn error(&self) -> Result<Option<WebElement>> {
        optional(self.0, By::Testid("login-error")).await
    }
}

/// The library index (`/`).
pub struct LibraryPage<'a>(pub &'a WebDriver);

impl LibraryPage<'_> {
    /// Navigates to `/`.
    pub async fn goto(&self) -> Result<()> {
        self.0.goto(BASE_URL).await?;
        Ok(())
    }

    /// Every book card on the page.
    pub async fn cards(&self) -> Result<Vec<WebElement>> {
        Ok(self.0.find_all(By::Testid("book-card")).await?)
    }

    /// Clicks the first book card, and confirms it actually opened one.
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
    pub async fn current_page(&self) -> Result<Option<WebElement>> {
        optional(self.0, By::Testid("reader-current")).await
    }

    /// Clicks the "next page" zone, and confirms the page turned.
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
    pub async fn is_showing(&self) -> Result<bool> {
        Ok(self
            .0
            .query(By::Css("body.reader"))
            .nowait()
            .exists()
            .await?)
    }

    /// The reader stores its mode on `<body data-mode="…">`.
    pub async fn mode(&self) -> Result<String> {
        self.0
            .find(By::Css("body"))
            .await?
            .attr("data-mode")
            .await?
            .context("<body> has no data-mode")
    }

    /// The page container with the given 1-based number.
    pub async fn page(&self, n: &str) -> Result<WebElement> {
        Ok(self.0.find(By::Id(format!("p{n}"))).await?)
    }

    /// The `.pg` elements the browser is actually displaying.
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
    pub async fn follow_next(&self) -> Result<()> {
        self.click_on_visible_page("the next-page link", ".nojs-next")
            .await
    }

    /// Clicks the script-less "previous page" anchor on the displayed page.
    pub async fn follow_previous(&self) -> Result<()> {
        self.click_on_visible_page("the previous-page link", ".nojs-prev")
            .await
    }

    /// Clicks the rail's anchor for page `n`. With scripting on, `app.js`
    /// cancels the jump and animates instead, so this covers both paths.
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
            // Either path's proof will do: `:target` leaves page n the only one
            // displayed, `app.js` writes n into the topbar. Requiring both would
            // fail whichever path is not in play.
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
    pub async fn counter_text(&self) -> Result<String> {
        Ok(self
            .element_on_visible_page(".nojs-counter")
            .await?
            .text()
            .await?)
    }

    /// The theme toggle, which only a script can operate.
    pub async fn theme_toggle(&self) -> Result<Option<WebElement>> {
        optional(self.0, By::Id("theme")).await
    }

    /// The shared segmented control, which cannot carry your place across a
    /// script-less mode switch and so is hidden without a script.
    pub async fn shared_mode_control(&self) -> Result<Option<WebElement>> {
        optional(self.0, By::Id("seg")).await
    }

    /// The per-page mode switch, which carries that page's anchor across the
    /// change.
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

    /// The topbar's subtitle, as *rendered* text: a `display: none` counter
    /// inside it does not contribute.
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
    /// order.
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
/// `WebElement::click` reports success once the event is dispatched, which on
/// CI is not the same as the page having reacted — for every control, plain
/// `<a href>`s included. So each attempt is checked and repeated.
///
/// Retrying alone does not recover: on CI, Chrome sometimes stops delivering
/// mouse events to the page for the rest of the session (the first click lands,
/// the second or third never arrives). Once every real click is spent,
/// [`probe_click_target`] tells that apart from a page fault:
///
/// * **The browser dropped the input** — the point belongs to the element, the
///   recorder saw nothing, and a scripted click works. The scripted click
///   stands in, with a `WARNING`, so the scenario keeps testing comics rather
///   than chromedriver.
/// * **Anything else fails.** A covered control reports `hitIsTarget: false`;
///   one whose handler or `href` is wrong receives the events and does nothing.
async fn click_until<L, E>(driver: &WebDriver, what: &str, locate: L, took_effect: E) -> Result<()>
where
    L: AsyncFn() -> Result<WebElement>,
    E: AsyncFn() -> Result<bool>,
{
    let mut probes = Vec::new();

    for attempt in 1..=CLICK_ATTEMPTS {
        let element = locate().await?;
        // Best-effort: the recorder only feeds diagnostics.
        let _ = arm_recorder(driver).await;
        element.click().await?;

        if settled(&took_effect).await? {
            if attempt > 1 {
                eprintln!("e2e: {what} took {attempt} clicks");
            }
            return Ok(());
        }

        // Logged on the spot: this only happens on CI.
        let probe = probe_click_target(driver, &element).await;
        let url = driver.current_url().await?;
        let reported = match &probe {
            Ok(probe) => format!("probe={probe}"),
            Err(e) => format!("probe failed: {e}"),
        };
        eprintln!("e2e: click {attempt} on {what} had no effect; url={url} {reported}");
        probes.push(reported.clone());

        if attempt < CLICK_ATTEMPTS {
            continue;
        }

        // Real clicks spent: is the browser deaf, or the page unresponsive?
        let nothing_arrived = probe.as_ref().is_ok_and(input_never_arrived);
        let scripted = scripted_click(driver, &element, &took_effect).await;
        eprintln!("e2e: scripted click on {what}: {scripted}");

        if nothing_arrived && scripted == ScriptedClick::TookEffect {
            eprintln!(
                "e2e: WARNING — stood in for {what} with a scripted click. The \
                 browser accepted {CLICK_ATTEMPTS} real clicks and delivered none \
                 of them to the page, so this scenario did not test that the \
                 control is reachable by a pointer. See {reported}"
            );
            return Ok(());
        }
        probes.push(format!("scriptedClick={scripted}"));
    }

    bail!(
        "clicked {what} {CLICK_ATTEMPTS} times and it never took effect ({})",
        probes.join(" | ")
    )
}

/// Did the browser drop the input, rather than the page ignore it?
///
/// Requires `hitIsTarget` (otherwise something covers the element — a page
/// bug) and no recorded events. With scripts on, an empty recorder is proof
/// (`frames` shows it was live); under `@nojs` [`arm_recorder`] cannot run
/// (`frames: 0`), so it is only ignorance. Accepting that is deliberate:
/// `@nojs` then rests on `hitIsTarget` plus a working scripted click, which
/// still fails a covered, missing or mis-wired control.
fn input_never_arrived(probe: &serde_json::Value) -> bool {
    let aimed_at_the_element = probe["hitIsTarget"].as_bool().unwrap_or(false);
    let recorded = probe["events"].as_array().map_or(0, Vec::len);
    aimed_at_the_element && recorded == 0
}

/// Arms the in-page recorder [`probe_click_target`] reads back.
///
/// * `events` — a capture-phase listener on `window` records which mouse and
///   pointer events arrived, and where. Empty means the input never reached
///   the renderer; `mousedown`/`mouseup` without `click` would instead suggest
///   a layout shift.
/// * `frames` — a `requestAnimationFrame` count, telling an empty `events` from
///   a recorder that never ran. On the CI failures it reads 300-plus: a
///   renderer drawing at 60fps and receiving nothing. (The probe's `hasFocus`
///   and `visibilityState` also come back affirmative there, ruling out what
///   the flags in [`crate::browser`] address.)
///
/// Installed once and reset per attempt; re-registering would duplicate every
/// event. Mute under `@nojs`: `Execute Script` still runs there, but the
/// listener and frame callback are document script, which the emulation stops.
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

/// What a scripted click on the same element did.
#[derive(Debug, PartialEq, Eq)]
enum ScriptedClick {
    /// The page reacted, so only the native input was missing.
    TookEffect,
    /// The page ignored this too: the control, not the browser, is the problem.
    NoEffect,
    /// The question could not be put — the element or the driver was gone.
    Unanswered(String),
}

impl std::fmt::Display for ScriptedClick {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TookEffect => f.write_str("took effect"),
            Self::NoEffect => f.write_str("no effect either"),
            Self::Unanswered(why) => write!(f, "unanswered: {why}"),
        }
    }
}

/// Clicks the element from script, and reports whether *that* took effect.
///
/// Dispatches `pointerdown` through `mouseup` before `click()`, because the
/// reader's tap zones are bound to `pointerup`, which `click()` alone never
/// fires; `click()` then triggers link and form activation.
///
/// Only trusted together with [`input_never_arrived`]: alone it bypasses
/// hit-testing, and the suite would stop testing that controls are reachable.
async fn scripted_click<E>(
    driver: &WebDriver,
    element: &WebElement,
    took_effect: &E,
) -> ScriptedClick
where
    E: AsyncFn() -> Result<bool>,
{
    let json = match element.to_json() {
        Ok(json) => json,
        Err(e) => return ScriptedClick::Unanswered(e.to_string()),
    };
    let dispatched = driver
        .execute(
            r"
            const el = arguments[0];
            const r = el.getBoundingClientRect();
            const at = {
                bubbles: true, cancelable: true, composed: true,
                clientX: r.left + r.width / 2, clientY: r.top + r.height / 2,
                button: 0, buttons: 1,
            };
            const released = { ...at, buttons: 0 };
            el.dispatchEvent(new PointerEvent('pointerdown', at));
            el.dispatchEvent(new MouseEvent('mousedown', at));
            el.dispatchEvent(new PointerEvent('pointerup', released));
            el.dispatchEvent(new MouseEvent('mouseup', released));
            el.click();
            ",
            vec![json],
        )
        .await;
    if let Err(e) = dispatched {
        return ScriptedClick::Unanswered(e.to_string());
    }
    match settled(took_effect).await {
        Ok(true) => ScriptedClick::TookEffect,
        Ok(false) => ScriptedClick::NoEffect,
        Err(e) => ScriptedClick::Unanswered(e.to_string()),
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

/// Asks the page what is at the element's centre (`elementFromPoint`, which
/// works under `@nojs` too) and what [`arm_recorder`] collected.
///
/// `probe failed: Element is stale` means the click *did* navigate, and the
/// caller's `took_effect` is what is wrong.
async fn probe_click_target(driver: &WebDriver, element: &WebElement) -> Result<serde_json::Value> {
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
    Ok(probe.json().clone())
}

/// Finds an element, mapping "not there" onto `None` rather than an error.
///
/// `nowait`: every caller asks about a page that has already rendered, so
/// waiting out the default poller would only delay confirming an absence.
async fn optional(driver: &WebDriver, by: By) -> Result<Option<WebElement>> {
    Ok(driver.query(by).nowait().first_opt().await?)
}
