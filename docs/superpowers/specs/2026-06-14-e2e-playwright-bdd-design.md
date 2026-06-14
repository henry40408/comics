# E2E tests (playwright-bdd) + screenshot pipeline — design

Date: 2026-06-14
Status: Approved (pending written-spec review)

## Overview

Add browser-level end-to-end tests for the three UI surfaces (login, library,
reader) using **playwright-bdd** (Gherkin `.feature` files backed by Playwright),
and a separate **screenshot generation pipeline** that captures the library and
reader in light/dark themes for documentation and the README.

The existing Rust unit/integration tests cover the HTTP and CLI layers but never
drive a real browser, so reader interactions (page turning, mode switching,
theme toggle, keyboard shortcuts) are currently untested. This work closes that
gap and produces presentable screenshots from real comic content.

## Goals

- E2E coverage of the **key user journeys** (not exhaustive edge cases).
- E2E runs as a **CI gate** on pull requests (Chromium only).
- A **screenshot pipeline** run manually/locally that writes committed PNGs to
  `docs/screenshots/` and is embedded in the README.
- Replace the synthetic placeholder fixtures with real, freely-licensed comic
  content (**Pepper&Carrot**, CC-BY 4.0) so screenshots look presentable.

## Non-goals (YAGNI)

- Visual-regression / baseline image diffing.
- Cross-browser (Firefox/WebKit) or mobile-viewport testing.
- Generating or comparing screenshots in CI.
- Exhaustive reader edge cases (every keyboard shortcut, first-visit hint
  animation, off-site `next` rejection — these stay covered by Rust tests where
  applicable).

## Architecture

A self-contained Node project under `e2e/` keeps the Node toolchain isolated
from the Rust crate. Step definitions are thin and delegate to small page
objects, so selectors live in one place and the screenshot pipeline reuses the
same navigation helpers.

```
e2e/
  package.json            # pinned deps (see Versions)
  playwright.config.js    # webServer + two projects: "e2e", "screenshots"
  jsconfig.json           # editor type hints via JSDoc (optional, no build step)
  features/
    login.feature
    library.feature
    reader.feature
  steps/
    fixtures.js           # playwright-bdd test object + page-object fixtures
    login.steps.js
    library.steps.js
    reader.steps.js
  pages/
    login.page.js         # data-testid locators + actions for /login
    library.page.js       # data-testid locators + actions for /
    reader.page.js        # data-testid locators + actions for /book/{id}
  screenshots.spec.js     # the screenshot pipeline (screenshots project)
  .gitignore              # .features-gen/, test-results/, node_modules/, playwright-report/
docs/
  screenshots/            # committed PNG output (library/reader × light/dark)
fixtures/data/            # replaced with 2 Pepper&Carrot episodes (see Fixtures)
templates/                # login.html, index.html, book.html get data-testid hooks
.github/workflows/ci.yaml # + new "e2e" job
README.md                 # embeds the generated screenshots
```

### Server lifecycle

Playwright's `webServer` builds and runs the app with authentication enabled
against the fixture data:

- command: `cargo run --release -- --bind 127.0.0.1:3030 --data-dir fixtures/data`
- cwd: repository root (the config resolves `..` from `e2e/`)
- env:
  - `AUTH_USERNAME=user`
  - `AUTH_PASSWORD_HASH=<bcrypt hash of "password">` — a precomputed, committed
    test credential (safe: it only unlocks the throwaway fixtures)
  - `SEED=1` — fixes the hashed book/page IDs so tests can target known URLs
- readiness: poll `http://127.0.0.1:3030/healthz` (public, returns 200)
- `reuseExistingServer: !process.env.CI` for fast local iteration

Auth is enabled (rather than running the server public) specifically so the
login journey is exercised end to end.

### BDD wiring

`defineBddConfig({ features: 'features/**/*.feature', steps: 'steps/**/*.js' })`
generates Playwright test files into `.features-gen/`, which is the `testDir`
for the `e2e` project. npm scripts:

- `test`        → `bddgen && playwright test --project=e2e`
- `screenshots` → `playwright test --project=screenshots`

## Selectors (test hooks)

Tests and page objects locate elements **only** by `data-testid` — never by CSS
class, element id, or visible text — so that styling or copy changes never break
the suite. The required attributes are added to the templates as a stable
contract. They are plain static attributes (not behind `{% if %}`), so they are
always present.

`templates/login.html`
- `login-username` — the username `<input>`
- `login-password` — the password `<input>`
- `login-submit` — the "Sign in" button
- `login-error` — the error banner (rendered only on a failed attempt)

`templates/index.html`
- `book-card` — each book link in the grid (one per book)
- `book-title` — the title text inside a card
- `logout` — the logout button

`templates/book.html`
- `reader-current` — the current-page number (`#cur`)
- `reader-next` — the next-page tap zone (`#next`)
- `reader-prev` — the previous-page tap zone (`#prev`)
- `reader-mode-paged` — the "paged" segmented-control button
- `reader-mode-scroll` — the "scroll" segmented-control button
- `logout` — the logout button

Adding these attributes does not affect the existing Rust tests, which assert on
text content and structure rather than on these hooks.

## E2E scenarios (key journeys)

`login.feature`
- Logging in with valid credentials lands on the library.
- Logging in with a wrong password shows the wrong-credentials error message
  (the literal string lives in `templates/login.html`) and stays on `/login`.

`library.feature`
- A logged-in user sees the expected number of books and a known title.
- Clicking a book opens the reader.

`reader.feature`
- The reader shows the first page on open.
- In paged mode, advancing (arrow tap / `next` control) moves to page 2 and the
  progress indicator updates.
- Switching to scroll mode via the segmented control changes the body mode.
- Logging out returns to `/login`.

This is ~6 scenarios — core paths, no edge-case gold-plating.

## Screenshot pipeline

`screenshots.spec.js` runs under the `screenshots` Playwright project, which is
**excluded from CI** (CI runs `--project=e2e`). For each theme in
`["light", "dark"]` it creates a browser context with the matching `colorScheme`
(exercising the app's system-follow path), logs in, and captures full-page PNGs:

- `docs/screenshots/library-light.png`, `library-dark.png`
- `docs/screenshots/reader-light.png`, `reader-dark.png`

After generation, the README is updated to embed these four images. Regenerate
with `npm run screenshots`; the PNGs are committed.

## Fixtures: Pepper&Carrot

The synthetic placeholder books in `fixtures/data/` are replaced with **two
short Pepper&Carrot episodes** (David Revoy, https://www.peppercarrot.com/),
licensed **CC-BY 4.0**. Each episode is one book directory of numbered page
images — a direct fit for the existing "directory = book, files = pages" model.

- Page images are **downscaled to ~1200px wide** to keep the repository light
  (~1–2 MB total). Downscaling is a modification, which CC-BY requires noting.
- A `fixtures/data/ATTRIBUTION.md` (and a short README credit) records the
  author, work, CC-BY 4.0 license, source URL, and the "images downscaled for
  testing" note.

### Impact on existing tests

Replacing the fixtures changes content the current Rust tests assert against, so
these are updated as part of this work (per the repo rule that implementation
updates related tests):

- `src/main.rs` tests: `DATA_IDS` (seeded book-id hashes), the `get_page` page
  id, and the `get_books` title/count assertions.
- `tests/integration_test.rs`: the `list` snapshot (titles, book/page counts).

New seeded IDs are recomputed with `SEED=1` (e.g. via `cargo run -- list` and
the page hashing) once the new fixtures are in place.

## CI

A new `e2e` job in `.github/workflows/ci.yaml`:

1. `actions/checkout`
2. `dtolnay/rust-toolchain` @ 1.94.0 + `actions/cache`
3. `cargo build --release`
4. `actions/setup-node` + `npm ci` (in `e2e/`)
5. `npx playwright install --with-deps chromium`
6. `npm test` (in `e2e/`)

Chromium only, runs on pull requests as a gate. All actions are pinned by commit
SHA, matching the existing workflow's convention.

## Versions

Pinned exactly in `e2e/package.json`:

- `@playwright/test` **1.60.0**
- `playwright-bdd` **9.0.0**

## Testing strategy

- The E2E suite *is* the test deliverable; it is validated by running locally
  against the Pepper&Carrot fixtures and confirming all scenarios pass.
- Existing Rust `cargo nextest run` and `tests/integration_test.rs` must still
  pass after the fixture swap and assertion updates.
- The screenshot pipeline is validated by running `npm run screenshots` and
  confirming four non-empty PNGs are produced.

## Licensing note

Pepper&Carrot is CC-BY 4.0: free to redistribute and modify (including
commercially) with attribution and an indication of changes. Attribution lives
in `fixtures/data/ATTRIBUTION.md`; the downscaling is noted there.
