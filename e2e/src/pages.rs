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
//! A third is [`click_until`], and it is the one that matters most.
//! `WebElement::click` reports success as long as the driver accepted the
//! command, which on CI is not the same as the page having reacted, so every
//! control here goes through `click_until` and clicks again when it did not.
//!
//! Retrying is not enough, because the fault does not pass: Chrome accepts the
//! click, says so, and never delivers a mouse event to the page for the rest of
//! that session. So once the retries are spent, `click_until` asks the page what
//! it received and stands in with a scripted click when the answer is "nothing",
//! rather than failing a run over a browser that stopped listening. Everything
//! else still fails.

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
    ///
    /// The card is a plain `<a href>` that nothing in `app.js` intercepts, and
    /// on CI the click sometimes still does nothing — see [`click_until`].
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

    /// The rail is anchors in both projects; with scripting on `app.js` cancels
    /// the jump, so this exercises the two paths through one control.
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

    /// The topbar's subtitle, as *rendered* text.
    ///
    /// `WebDriver`'s "Get Element Text" returns rendered text, so a
    /// `display: none` counter inside it does not contribute — which is what
    /// the old assertion needed `useInnerText: true` for.
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
/// event, which is not the same as the page having reacted. On CI the two come
/// apart often enough to fail a run in two, and every control is affected,
/// including plain `<a href>`s no script touches. (Playwright's `click`, which
/// this suite used to go through, first waited for the element's box to hold
/// still across two animation frames.) So each attempt is checked and repeated,
/// and a click that never takes goes to [`probe_click_target`], whose answer
/// decides between two things that look identical from here.
///
/// **The browser is not delivering input.** The point belongs to the element,
/// the recorder saw no `mousedown` at all, and `HTMLElement.click()` works
/// immediately: the CI fault this suite kept failing on, where the first click
/// of a session lands, the second or third stops arriving, and retrying does not
/// recover it. The scripted click stands in — loudly — so the scenario goes on
/// testing comics rather than chromedriver.
///
/// **Anything else** is the page's fault and fails, which is why the real click
/// comes first: a covered control reports `hitIsTarget: false`, and one whose
/// handler or `href` is wrong receives the events and does nothing.
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

        // Every real click is spent, so ask the two questions that separate a
        // browser that is not listening from a page that is not reacting.
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

/// Did the probe catch the browser dropping the input rather than the page
/// ignoring it?
///
/// Two conditions, the second meaning different things in the two modes:
///
/// * `hitIsTarget` — the point aimed at belongs to the element. Without it the
///   click landed on something else, a page problem that has to fail.
/// * nothing recorded. With the page's scripts running this is *proof*: the
///   recorder was live (`frames` counts animation frames) and no `pointerdown`,
///   `mousedown`, `mouseup` or `click` reached it. Under `@nojs` it is only
///   *ignorance* — [`arm_recorder`] is mute there and reports `frames: 0`.
///
/// Treating ignorance as proof is deliberate, and the weaker half of this:
/// nothing page-side can observe input when the document runs no script, so
/// `@nojs` rests on `hitIsTarget` plus a scripted click that works. That still
/// fails a control that is covered, missing, or wired to the wrong `href`.
fn input_never_arrived(probe: &serde_json::Value) -> bool {
    let aimed_at_the_element = probe["hitIsTarget"].as_bool().unwrap_or(false);
    let recorded = probe["events"].as_array().map_or(0, Vec::len);
    aimed_at_the_element && recorded == 0
}

/// Arms the in-page recorder [`probe_click_target`] reads back.
///
/// Three questions `elementFromPoint` cannot answer alone, which between them
/// separate every remaining explanation for a click that does nothing:
///
/// * **Did any mouse event reach the page?** A capture-phase listener on
///   `window` records what arrived and where. Nothing recorded means the event
///   was dropped before the renderer saw it — the fault [`input_never_arrived`]
///   looks for; a `mousedown` and `mouseup` with no `click` between them would
///   instead be the layout-shift flake Playwright's stability wait avoided.
/// * **Is the renderer drawing?** `requestAnimationFrame` only fires while the
///   compositor produces frames, so `frames` says whether an empty `events` was
///   proof or ignorance. On the CI failures it counts 300-plus over the five
///   seconds given: a renderer drawing at 60fps and receiving nothing.
/// * `document.hasFocus()` and `visibilityState` say whether the browser
///   considers the window worth either. Both come back affirmative on the
///   failures, ruling out the occlusion and backgrounding the flags in
///   [`crate::browser`] already address.
///
/// Installed once and reset per attempt: re-registering would report every event
/// as many times as we had clicked by then.
///
/// `@nojs` gets nothing out of this. `Execute Script` still runs under
/// `Emulation.setScriptExecutionDisabled` — that is what keeps the probe working
/// — but a listener and a frame callback are script the *document* runs, which
/// is exactly what the emulation switches off. Confirmed by forcing a `@nojs`
/// click to report failure where clicks work: it navigated, and the recorder
/// still came back `events: []`, `frames: 0`. So an empty `events` means
/// "nothing arrived" only when `frames` is non-zero.
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
/// The last question, asked once every native click is spent. It skips
/// hit-testing and the browser's input plumbing and dispatches straight at the
/// element, so it reaches a control a real click could not.
///
/// `HTMLElement.click()` alone fires only `click`, and the reader's tap zones
/// are bound to `pointerup` — so a tap need not survive a `click` a drag would
/// cancel — which would leave "Advancing turns to the next page" failing alone.
/// So the full `pointerdown`-through-`mouseup` sequence goes out and `click()`
/// finishes it, that last step being the specified path to a link's or form's
/// activation behaviour.
///
/// [`ScriptedClick::TookEffect`] is half of what lets [`click_until`] carry on
/// past a swallowed click; the other half is [`input_never_arrived`], without
/// which this would be a blanket "click from script when the real one is
/// inconvenient" and the suite would stop testing reachability at all.
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

/// Asks the page what is at the point a click would have landed on.
///
/// `document.elementFromPoint` at the element's own centre is the question the
/// logs could not answer before: the element (or something inside it) means the
/// click was aimed correctly and lost downstream; anything else — or `null` —
/// means the point belonged to something else at the moment of the click.
///
/// It also reports what [`arm_recorder`] collected — the events the page
/// received and the frames it drew while waiting — which is what
/// [`input_never_arrived`] reads. The driver can inject script into a page whose
/// own scripts are disabled, so the `elementFromPoint` half covers `@nojs` too;
/// the recorder's half does not, where `frames: 0` beside an empty `events` is
/// the recorder saying it never ran.
///
/// `probe failed: Element is stale` is a different answer again: the click *did*
/// navigate, and it is the caller's idea of "took effect" that is wrong. The
/// flake this exists for leaves the element right where it was.
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
/// `nowait`, because every caller is asking about a page that has already
/// rendered: waiting 20 s to confirm an absence is the default poller's idea.
async fn optional(driver: &WebDriver, by: By) -> Result<Option<WebElement>> {
    Ok(driver.query(by).nowait().first_opt().await?)
}
