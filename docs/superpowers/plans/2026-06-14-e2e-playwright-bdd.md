# E2E (playwright-bdd) + screenshot pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add browser-level E2E tests (playwright-bdd, JavaScript) for the login, library, and reader journeys, plus a manual screenshot pipeline that captures the library and reader in light/dark themes for the README — all driven against real, freely-licensed Pepper&Carrot fixture comics.

**Architecture:** A self-contained Node project under `e2e/` runs Playwright with two projects ("e2e" for BDD specs, "screenshots" for the capture pipeline). Playwright's `webServer` builds and launches the Rust app with auth enabled against `fixtures/data`. Thin step definitions delegate to small page objects that locate elements only by `data-testid`. The synthetic placeholder fixtures are replaced with two downscaled Pepper&Carrot episodes, and the existing Rust tests are updated to match.

**Tech Stack:** Rust/Axum app (unchanged behaviour), Node + `@playwright/test` 1.60.0 + `playwright-bdd` 9.0.0, Gherkin features, ImageMagick for downscaling.

**Spec:** `docs/superpowers/specs/2026-06-14-e2e-playwright-bdd-design.md`

**Branch:** `test/e2e-playwright-bdd` (already checked out).

**Prerequisites (notify the user if any is missing — do not auto-install):**
- `convert` (ImageMagick) for downscaling fixture images.
- Node.js ≥ 18 and `npm` for the E2E project.
- `curl` for downloading fixtures.

---

### Task 1: Replace placeholder fixtures with Pepper&Carrot

**Files:**
- Delete: `fixtures/data/Netherworld Nomads Journey to the Jade Jungle/` (9 files)
- Delete: `fixtures/data/Quantum Quest Legacy of the Luminous League/` (9 files)
- Create: `fixtures/data/Pepper and Carrot 01 - Potion of Flight/01.jpg`..`03.jpg`
- Create: `fixtures/data/Pepper and Carrot 02 - Rainbow Potions/01.jpg`..`05.jpg`

Note: each episode's *last* listed source image is a non-story trailer (a thin
decorative separator for ep01, the CC-BY credits banner for ep02). These are
intentionally excluded so each book contains only real comic pages — ep01 has 3
story pages, ep02 has 5.
- Create: `fixtures/ATTRIBUTION.md` (one level above the scanned `data/` dir)

- [ ] **Step 1: Remove the old placeholder books**

```bash
cd /home/nixos/Develop/claude/comics
git rm -r "fixtures/data/Netherworld Nomads Journey to the Jade Jungle" \
          "fixtures/data/Quantum Quest Legacy of the Luminous League"
```

- [ ] **Step 2: Download and downscale the two episodes**

Pepper&Carrot pages live at `…/0_sources/<ep-slug>/low-res/en_Pepper-and-Carrot_by-David-Revoy_<EXX>P<NN>.jpg`. Each page is downscaled to ≤1200px wide (`-resize '1200x>'` only shrinks) and renamed to a zero-padded sequence so the cover is `01.jpg`.

```bash
cd /home/nixos/Develop/claude/comics
set -euo pipefail
BASE=https://www.peppercarrot.com/0_sources

dl() {  # $1=book dir  $2=ep slug  $3=ep code  $4=page count
  local dir="fixtures/data/$1" slug="$2" code="$3" n="$4" i p url
  mkdir -p "$dir"
  for i in $(seq 1 "$n"); do
    p=$(printf '%02d' "$i")
    url="$BASE/$slug/low-res/en_Pepper-and-Carrot_by-David-Revoy_${code}P${p}.jpg"
    curl -fsSL "$url" -o "$dir/_tmp.jpg"
    convert "$dir/_tmp.jpg" -resize '1200x>' "$dir/$p.jpg"
    rm "$dir/_tmp.jpg"
  done
}

dl "Pepper and Carrot 01 - Potion of Flight" ep01_Potion-of-Flight E01 3
dl "Pepper and Carrot 02 - Rainbow Potions"  ep02_Rainbow-potions  E02 5
```

(The download stops before the trailing non-story image of each episode: ep01
has 4 source images — the 4th is a separator — so we fetch 3; ep02 has 6 — the
6th is the credits banner — so we fetch 5.)

- [ ] **Step 3: Write the attribution file**

Create `fixtures/ATTRIBUTION.md`. It lives one level **above** the scanned
`data/` directory so the scanner never sees it (a non-directory entry inside
`data/` would log an ERROR to stdout and break the integration `list` test):

```markdown
# Fixture artwork attribution

The sample books in this directory are episodes of **Pepper&Carrot** by
**David Revoy**, used here as test fixtures.

- Source: https://www.peppercarrot.com/
- License: Creative Commons Attribution 4.0 International (CC-BY 4.0)
  <https://creativecommons.org/licenses/by/4.0/>
- Episodes: 01 "Potion of Flight", 02 "Rainbow Potions"
- Modifications: page images were downscaled to a maximum width of 1200px for
  use as lightweight test fixtures.
```

- [ ] **Step 4: Verify the scan sees exactly two books / ten pages**

Run: `cargo run --quiet -- --data-dir ./fixtures/data list`
Expected (duration varies):

```
Pepper and Carrot 01 - Potion of Flight (3P)
Pepper and Carrot 02 - Rainbow Potions (5P)
2 book(s), 8 page(s), scanned in ...
```

If the counts differ, re-check the downloads before continuing.

- [ ] **Step 5: Commit**

```bash
cd /home/nixos/Develop/claude/comics
git add "fixtures/data/Pepper and Carrot 01 - Potion of Flight" \
        "fixtures/data/Pepper and Carrot 02 - Rainbow Potions" \
        fixtures/ATTRIBUTION.md
git commit -m "test: replace placeholder fixtures with Pepper&Carrot episodes"
```

---

### Task 2: Update the Rust tests for the new fixtures

The existing tests assert on the old titles, counts, and IDs. Update them to the new fixtures and remove the one hard-coded page-id magic constant by deriving it from rendered HTML.

**Files:**
- Modify: `src/main.rs` (the `#[cfg(test)] mod tests`)
- Modify: `tests/integration_test.rs` (the `list` snapshot)

- [ ] **Step 1: Get the two new book IDs**

Book IDs are `xxh3(seed=1, title)` and do not depend on the path. Read them from a running server (no auth needed for this throwaway run):

```bash
cd /home/nixos/Develop/claude/comics
SEED=1 cargo run --quiet -- --data-dir ./fixtures/data --bind 127.0.0.1:3999 &
SRV=$!
sleep 2
curl -s 127.0.0.1:3999/ | grep -oE '/book/[a-f0-9]+' | sort -u
kill $SRV
```

Note the two IDs and which title each belongs to (the cards render in title order: episode 01 first, then 02). You will paste them into `DATA_IDS` below.

- [ ] **Step 2: Update `DATA_IDS` and the fixture-dependent assertions in `src/main.rs`**

Replace the `DATA_IDS` constant (currently the two old hashes) with the two IDs from Step 1, in title order:

```rust
    const DATA_IDS: [&str; 2] = [
        // Pepper and Carrot 01 - Potion of Flight
        "<BOOK_ID_EP01>",
        // Pepper and Carrot 02 - Rainbow Potions
        "<BOOK_ID_EP02>",
    ];
```

In `get_books`, replace the two title assertions with the new titles (the count assertion stays):

```rust
        let t = res.text();
        assert!(t.contains("2 book(s)"));
        assert!(t.contains("Pepper and Carrot 01 - Potion of Flight"));
        assert!(t.contains("Pepper and Carrot 02 - Rainbow Potions"));
```

In `get_book`, update the title assertion:

```rust
        let t = res.text();
        assert!(t.contains("Pepper and Carrot 01 - Potion of Flight"));
```

- [ ] **Step 3: Rewrite `get_page` to derive the page id from HTML**

Replace the whole `get_page` test (it currently hard-codes a page-id hash) with a version that reads a real page id from the first book's reader page:

```rust
    #[tokio::test]
    async fn get_page() {
        let server = build_server().await;
        // Discover a real page id from the first book's reader page rather than
        // hard-coding a hash that changes whenever the fixtures change.
        let book_id = DATA_IDS.first().unwrap();
        let html = server.get(&format!("/book/{book_id}")).await.text();
        let marker = "/data/";
        let start = html.find(marker).expect("a page image") + marker.len();
        let page_id: String = html[start..].chars().take_while(|&c| c != '"').collect();
        assert!(!page_id.is_empty());

        let res = server.get(&format!("/data/{page_id}")).await;
        assert_eq!(200, res.status_code());
        let content = res.as_bytes();
        assert!(content.starts_with(b"\xFF\xD8\xFF")); // JPEG magic bytes
    }
```

- [ ] **Step 4: Update the `list` snapshot in `tests/integration_test.rs`**

Replace the `stdout_eq` block of the `list` test with the new titles and counts:

```rust
        .stdout_eq(str![[r#"
Pepper and Carrot 01 - Potion of Flight (3P)
Pepper and Carrot 02 - Rainbow Potions (5P)
2 book(s), 8 page(s), scanned in [..]

"#]])
```

- [ ] **Step 5: Run the Rust tests**

Run: `cargo nextest run`
Expected: PASS (all tests, including `get_books`, `get_book`, `get_page`, `shuffle`, the auth suite, and the integration `list`).

If `get_page` or the auth tests fail on an unknown id, re-check that `DATA_IDS` matches Step 1 output in title order.

- [ ] **Step 6: Commit**

```bash
cd /home/nixos/Develop/claude/comics
git add src/main.rs tests/integration_test.rs
git commit -m "test: point fixtures-dependent assertions at the new books"
```

---

### Task 3: Add `data-testid` hooks to the templates

Tests locate elements only by `data-testid`. Add the attributes from the spec's "Selectors (test hooks)" section. These are static attributes and do not change rendered text, so the Rust tests stay green.

**Files:**
- Modify: `templates/login.html`
- Modify: `templates/index.html`
- Modify: `templates/book.html`

- [ ] **Step 1: `templates/login.html`**

Add `data-testid` to the error banner, both inputs, and the submit button:

```html
        {% if error %}
        <div class="err" data-testid="login-error">帳號或密碼錯誤</div>
        {% endif %}
        <form method="POST" action="/login">
          <input type="hidden" name="next" value="{{ next }}" />
          <label>
            Username
            <input name="username" data-testid="login-username" autocomplete="username" autofocus required />
          </label>
          <label>
            Password
            <input name="password" data-testid="login-password" type="password" autocomplete="current-password" required />
          </label>
          <button class="lbtn key" type="submit" data-testid="login-submit">Sign in</button>
        </form>
```

- [ ] **Step 2: `templates/index.html`**

Add `data-testid="logout"` to the logout button, and `book-card` / `book-title` in the grid:

```html
          {% if auth_enabled %}
          <form method="POST" action="/logout">
            <button class="lbtn" type="submit" data-testid="logout">Logout</button>
          </form>
          {% endif %}
```

```html
          <a class="card" href="/book/{{ b.id }}" data-testid="book-card">
            <div class="cover">
              <img src="/thumb/md/{{ b.cover.id }}" alt="{{ b.title }}" loading="lazy" />
              <span class="idx">{{ loop.index }}</span>
            </div>
            <div class="info">
              <div class="t" data-testid="book-title">{{ b.title }}</div>
              <div class="p">{{ b.pages.len() }} pages</div>
            </div>
          </a>
```

- [ ] **Step 3: `templates/book.html`**

Add hooks to the current-page counter, the nav zones, the two mode buttons, and the logout button:

```html
        <div class="s"><b id="cur" data-testid="reader-current">1</b> / {{ book.pages.len() }} ページ</div>
```

```html
      <div class="seg" id="seg">
        <button type="button" data-m="paged" class="on" data-testid="reader-mode-paged">⇄ 翻頁</button>
        <button type="button" data-m="scroll" data-testid="reader-mode-scroll">↕ 捲動</button>
      </div>
```

```html
      {% if auth_enabled %}
      <form method="POST" action="/logout">
        <button class="tbtn" type="submit" data-testid="logout">Logout</button>
      </form>
      {% endif %}
```

```html
      <div class="zone next" id="next" title="Next" data-testid="reader-next"><span>‹</span></div>
      <div class="zone prev" id="prev" title="Previous" data-testid="reader-prev"><span>›</span></div>
```

- [ ] **Step 4: Confirm the app still builds and Rust tests still pass**

Run: `cargo nextest run`
Expected: PASS (no assertions depend on these attributes).

- [ ] **Step 5: Commit**

```bash
cd /home/nixos/Develop/claude/comics
git add templates/login.html templates/index.html templates/book.html
git commit -m "feat: add data-testid hooks for E2E selectors"
```

---

### Task 4: Scaffold the `e2e/` Node project

**Files:**
- Create: `e2e/package.json`
- Create: `e2e/playwright.config.js`
- Create: `e2e/jsconfig.json`
- Create: `e2e/.gitignore`
- Create: `e2e/package-lock.json` (generated)

- [ ] **Step 1: `e2e/package.json`** (deps pinned exactly)

```json
{
  "name": "comics-e2e",
  "private": true,
  "version": "0.0.0",
  "description": "Browser E2E tests and screenshot pipeline for Comics",
  "scripts": {
    "bddgen": "bddgen",
    "test": "bddgen && playwright test --project=e2e",
    "screenshots": "bddgen && playwright test --project=screenshots"
  },
  "devDependencies": {
    "@playwright/test": "1.60.0",
    "playwright-bdd": "9.0.0"
  }
}
```

- [ ] **Step 2: Generate a test password hash**

The webServer needs `AUTH_PASSWORD_HASH`. Generate a bcrypt hash of `password` with the app's own command (cost 11, matches production). Run it, type `password` twice, and copy the printed `$2b$11$…` line:

```bash
cd /home/nixos/Develop/claude/comics
cargo run --quiet -- hash-password
```

- [ ] **Step 3: `e2e/playwright.config.js`** (paste the hash from Step 2 into `TEST_PASSWORD_HASH`)

```js
const { defineConfig, devices } = require('@playwright/test');
const { defineBddConfig } = require('playwright-bdd');

const PORT = 3030;
const BASE_URL = `http://127.0.0.1:${PORT}`;

// bcrypt hash of "password" (cost 11) — a throwaway credential that only
// unlocks the committed test fixtures. Generated with `comics hash-password`.
const TEST_PASSWORD_HASH = '<PASTE_BCRYPT_HASH_HERE>';

const testDir = defineBddConfig({
  features: 'features/**/*.feature',
  steps: 'steps/**/*.js',
});

module.exports = defineConfig({
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['github'], ['html', { open: 'never' }]] : [['list']],
  use: {
    baseURL: BASE_URL,
    trace: 'on-first-retry',
  },
  webServer: {
    command: `cargo run --release -- --bind 127.0.0.1:${PORT} --data-dir fixtures/data`,
    cwd: '..',
    url: `${BASE_URL}/healthz`,
    timeout: 180_000,
    reuseExistingServer: !process.env.CI,
    env: {
      AUTH_USERNAME: 'user',
      AUTH_PASSWORD_HASH: TEST_PASSWORD_HASH,
      SEED: '1',
    },
  },
  projects: [
    {
      name: 'e2e',
      testDir,
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'screenshots',
      testDir: __dirname,
      testMatch: /screenshots\.spec\.js$/,
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});
```

- [ ] **Step 4: `e2e/jsconfig.json`** (editor hints only, no build step)

```json
{
  "compilerOptions": {
    "checkJs": false,
    "module": "CommonJS",
    "target": "ES2022"
  },
  "exclude": ["node_modules", ".features-gen"]
}
```

- [ ] **Step 5: `e2e/.gitignore`**

```gitignore
node_modules/
.features-gen/
test-results/
playwright-report/
blob-report/
```

- [ ] **Step 6: Install dependencies and the Chromium browser**

```bash
cd /home/nixos/Develop/claude/comics/e2e
npm install
npx playwright install chromium
```

`npm install` creates `package-lock.json` (the direct deps stay pinned at the versions above).

- [ ] **Step 7: Commit**

```bash
cd /home/nixos/Develop/claude/comics
git add e2e/package.json e2e/package-lock.json e2e/playwright.config.js e2e/jsconfig.json e2e/.gitignore
git commit -m "test: scaffold e2e playwright-bdd project"
```

---

### Task 5: Page objects

**Files:**
- Create: `e2e/pages/login.page.js`
- Create: `e2e/pages/library.page.js`
- Create: `e2e/pages/reader.page.js`

- [ ] **Step 1: `e2e/pages/login.page.js`**

```js
// Page object for /login. Locators use data-testid only.
class LoginPage {
  constructor(page) {
    this.page = page;
  }

  async goto() {
    await this.page.goto('/login');
  }

  async login(username, password) {
    await this.page.getByTestId('login-username').fill(username);
    await this.page.getByTestId('login-password').fill(password);
    await this.page.getByTestId('login-submit').click();
  }

  error() {
    return this.page.getByTestId('login-error');
  }
}

module.exports = { LoginPage };
```

- [ ] **Step 2: `e2e/pages/library.page.js`**

```js
// Page object for the library (/).
class LibraryPage {
  constructor(page) {
    this.page = page;
  }

  async goto() {
    await this.page.goto('/');
  }

  cards() {
    return this.page.getByTestId('book-card');
  }

  async openFirstBook() {
    await this.cards().first().click();
  }

  async logout() {
    await this.page.getByTestId('logout').click();
  }
}

module.exports = { LibraryPage };
```

- [ ] **Step 3: `e2e/pages/reader.page.js`**

```js
// Page object for the reader (/book/{id}).
class ReaderPage {
  constructor(page) {
    this.page = page;
  }

  currentPage() {
    return this.page.getByTestId('reader-current');
  }

  async advance() {
    await this.page.getByTestId('reader-next').click();
  }

  async setScrollMode() {
    await this.page.getByTestId('reader-mode-scroll').click();
  }

  mode() {
    // The reader stores its mode on <body data-mode="...">.
    return this.page.locator('body');
  }
}

module.exports = { ReaderPage };
```

- [ ] **Step 4: Commit**

```bash
cd /home/nixos/Develop/claude/comics
git add e2e/pages
git commit -m "test: add e2e page objects"
```

---

### Task 6: BDD fixtures + login feature

**Files:**
- Create: `e2e/steps/fixtures.js`
- Create: `e2e/features/login.feature`
- Create: `e2e/steps/login.steps.js`

- [ ] **Step 1: `e2e/steps/fixtures.js`** (wires page objects into playwright-bdd)

```js
const { test as base, createBdd } = require('playwright-bdd');
const { LoginPage } = require('../pages/login.page');
const { LibraryPage } = require('../pages/library.page');
const { ReaderPage } = require('../pages/reader.page');

// Expose the page objects as Playwright fixtures so steps can request them.
const test = base.extend({
  loginPage: async ({ page }, use) => {
    await use(new LoginPage(page));
  },
  libraryPage: async ({ page }, use) => {
    await use(new LibraryPage(page));
  },
  readerPage: async ({ page }, use) => {
    await use(new ReaderPage(page));
  },
});

const { Given, When, Then } = createBdd(test);

module.exports = { test, Given, When, Then };
```

- [ ] **Step 2: `e2e/features/login.feature`**

```gherkin
Feature: Login

  Scenario: Signing in with valid credentials reaches the library
    Given I am on the login page
    When I sign in with username "user" and password "password"
    Then I should see the library

  Scenario: Signing in with a wrong password shows an error
    Given I am on the login page
    When I sign in with username "user" and password "wrong"
    Then I should see the login error
    And I should be on the login page
```

- [ ] **Step 3: `e2e/steps/login.steps.js`**

```js
const { expect } = require('@playwright/test');
const { Given, When, Then } = require('./fixtures');

Given('I am on the login page', async ({ loginPage }) => {
  await loginPage.goto();
});

When(
  'I sign in with username {string} and password {string}',
  async ({ loginPage }, username, password) => {
    await loginPage.login(username, password);
  },
);

Then('I should see the library', async ({ page }) => {
  await expect(page).toHaveURL('/');
  await expect(page.getByTestId('book-card').first()).toBeVisible();
});

Then('I should see the login error', async ({ loginPage }) => {
  await expect(loginPage.error()).toBeVisible();
});

Then('I should be on the login page', async ({ page }) => {
  await expect(page).toHaveURL(/\/login/);
});
```

- [ ] **Step 4: Run the login feature**

Run: `cd e2e && npm test -- --grep "Login"`
Expected: PASS — 2 scenarios. (The first run builds the release binary via `webServer`; allow up to a few minutes.)

- [ ] **Step 5: Commit**

```bash
cd /home/nixos/Develop/claude/comics
git add e2e/steps/fixtures.js e2e/features/login.feature e2e/steps/login.steps.js
git commit -m "test: add login e2e scenarios"
```

---

### Task 7: Library feature

**Files:**
- Create: `e2e/features/library.feature`
- Create: `e2e/steps/library.steps.js`

- [ ] **Step 1: `e2e/features/library.feature`**

```gherkin
Feature: Library

  Background:
    Given I am logged in

  Scenario: The library lists the seeded books
    When I open the library
    Then I should see 2 books

  Scenario: Opening a book enters the reader
    When I open the library
    And I open the first book
    Then I should be in the reader
```

- [ ] **Step 2: `e2e/steps/library.steps.js`**

```js
const { expect } = require('@playwright/test');
const { Given, When, Then } = require('./fixtures');

Given('I am logged in', async ({ page, loginPage }) => {
  await loginPage.goto();
  await loginPage.login('user', 'password');
  await expect(page).toHaveURL('/');
});

When('I open the library', async ({ libraryPage }) => {
  await libraryPage.goto();
});

Then('I should see {int} books', async ({ libraryPage }, count) => {
  await expect(libraryPage.cards()).toHaveCount(count);
});

When('I open the first book', async ({ libraryPage }) => {
  await libraryPage.openFirstBook();
});

Then('I should be in the reader', async ({ page }) => {
  await expect(page).toHaveURL(/\/book\//);
  await expect(page.locator('body.reader')).toBeVisible();
});
```

- [ ] **Step 3: Run the library feature**

Run: `cd e2e && npm test -- --grep "Library"`
Expected: PASS — 2 scenarios.

- [ ] **Step 4: Commit**

```bash
cd /home/nixos/Develop/claude/comics
git add e2e/features/library.feature e2e/steps/library.steps.js
git commit -m "test: add library e2e scenarios"
```

---

### Task 8: Reader feature

**Files:**
- Create: `e2e/features/reader.feature`
- Create: `e2e/steps/reader.steps.js`

- [ ] **Step 1: `e2e/features/reader.feature`**

```gherkin
Feature: Reader

  Background:
    Given I am logged in
    And I am reading the first book

  Scenario: The reader opens on the first page
    Then the current page should be "1"

  Scenario: Advancing turns to the next page
    When I advance to the next page
    Then the current page should be "2"

  Scenario: Switching to scroll mode
    When I switch to scroll mode
    Then the reader should be in "scroll" mode

  Scenario: Logging out returns to the login page
    When I log out
    Then I should be on the login page
```

- [ ] **Step 2: `e2e/steps/reader.steps.js`**

`I am logged in` and `I should be on the login page` are already defined (Tasks 7 and 6). Only the reader-specific steps are added here.

```js
const { expect } = require('@playwright/test');
const { Given, When, Then } = require('./fixtures');

Given('I am reading the first book', async ({ libraryPage }) => {
  await libraryPage.goto();
  await libraryPage.openFirstBook();
});

Then('the current page should be {string}', async ({ readerPage }, n) => {
  await expect(readerPage.currentPage()).toHaveText(n);
});

When('I advance to the next page', async ({ readerPage }) => {
  await readerPage.advance();
});

When('I switch to scroll mode', async ({ readerPage }) => {
  await readerPage.setScrollMode();
});

Then('the reader should be in {string} mode', async ({ readerPage }, mode) => {
  await expect(readerPage.mode()).toHaveAttribute('data-mode', mode);
});

When('I log out', async ({ libraryPage }) => {
  await libraryPage.logout();
});
```

- [ ] **Step 3: Run the reader feature**

Run: `cd e2e && npm test -- --grep "Reader"`
Expected: PASS — 4 scenarios.

- [ ] **Step 4: Run the full E2E suite**

Run: `cd e2e && npm test`
Expected: PASS — 8 scenarios total (Login 2, Library 2, Reader 4).

- [ ] **Step 5: Commit**

```bash
cd /home/nixos/Develop/claude/comics
git add e2e/features/reader.feature e2e/steps/reader.steps.js
git commit -m "test: add reader e2e scenarios"
```

---

### Task 9: Screenshot pipeline

**Files:**
- Create: `e2e/screenshots.spec.js`
- Create: `docs/screenshots/{library,reader}-{light,dark}.png` (generated)

- [ ] **Step 1: `e2e/screenshots.spec.js`**

```js
const { test } = require('@playwright/test');
const path = require('node:path');

const OUT = path.join(__dirname, '..', 'docs', 'screenshots');
const THEMES = ['light', 'dark'];

async function login(page) {
  await page.goto('/login');
  await page.getByTestId('login-username').fill('user');
  await page.getByTestId('login-password').fill('password');
  await page.getByTestId('login-submit').click();
  await page.waitForURL('/');
}

for (const theme of THEMES) {
  test.describe(`theme: ${theme}`, () => {
    // No stored preference + emulated colorScheme exercises the app's
    // system-follow path, picking the matching palette pre-paint.
    test.use({ colorScheme: theme });

    test(`library ${theme}`, async ({ page }) => {
      await login(page);
      await page.goto('/');
      await page.getByTestId('book-card').first().waitFor();
      await page.waitForLoadState('networkidle');
      await page.screenshot({
        path: path.join(OUT, `library-${theme}.png`),
        fullPage: true,
      });
    });

    test(`reader ${theme}`, async ({ page }) => {
      await login(page);
      await page.goto('/');
      await page.getByTestId('book-card').first().click();
      await page.locator('body.reader').waitFor();
      await page.locator('#pages img').first().waitFor({ state: 'visible' });
      await page.waitForLoadState('networkidle');
      await page.screenshot({
        path: path.join(OUT, `reader-${theme}.png`),
        fullPage: true,
      });
    });
  });
}
```

- [ ] **Step 2: Generate the screenshots**

```bash
cd /home/nixos/Develop/claude/comics/e2e
npm run screenshots
```

Expected: PASS — 4 tests; four PNGs written to `docs/screenshots/`.

- [ ] **Step 3: Confirm four non-empty PNGs exist**

Run: `ls -l docs/screenshots/`
Expected: `library-light.png`, `library-dark.png`, `reader-light.png`, `reader-dark.png`, each non-zero size.

- [ ] **Step 4: Commit**

```bash
cd /home/nixos/Develop/claude/comics
git add e2e/screenshots.spec.js docs/screenshots
git commit -m "test: add screenshot pipeline and generated screenshots"
```

---

### Task 10: Embed screenshots in the README

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add a Screenshots section after the Overview**

Insert after the Overview section (before Background):

```markdown
## Screenshots

|  | Library | Reader |
| --- | --- | --- |
| Light | ![Library, light theme](docs/screenshots/library-light.png) | ![Reader, light theme](docs/screenshots/reader-light.png) |
| Dark | ![Library, dark theme](docs/screenshots/library-dark.png) | ![Reader, dark theme](docs/screenshots/reader-dark.png) |

> Sample artwork: [Pepper&Carrot](https://www.peppercarrot.com/) by David Revoy, CC-BY 4.0.
```

- [ ] **Step 2: Commit**

```bash
cd /home/nixos/Develop/claude/comics
git add README.md
git commit -m "docs: embed E2E screenshots in the README"
```

---

### Task 11: CI gate for E2E

Add an `e2e` job that builds the app and runs the E2E project on Chromium. It reuses the action SHAs already pinned in the workflow and relies on the Node preinstalled on `ubuntu-latest` (no new action to pin). The `screenshots` project is not run in CI.

**Files:**
- Modify: `.github/workflows/ci.yaml`

- [ ] **Step 1: Append the `e2e` job**

Add this job (sibling to `coverage` / `msrv`):

```yaml
  e2e:
    needs: [lint, check]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6
      - uses: dtolnay/rust-toolchain@3c5f7ea28cd621ae0bf5283f0e981fb97b8a7af9 # efa25f7f19611383d5b0ccf2d1c8914531636bf9
        with:
          toolchain: 1.94.0
      - uses: actions/cache@27d5ce7f107fe9357f9df03efb73ab90386fccae # v5
        with:
          path: |
            ~/.cargo/bin/
            ~/.cargo/registry/index/
            ~/.cargo/registry/cache/
            ~/.cargo/git/db/
            target/
          key: ${{ runner.os }}-cargo-e2e-${{ hashFiles('**/Cargo.lock') }}
      - run: cargo build --release
      - run: npm ci
        working-directory: e2e
      - run: npx playwright install --with-deps chromium
        working-directory: e2e
      - run: npm test
        working-directory: e2e
        env:
          CI: "true"
```

- [ ] **Step 2: Validate the workflow YAML**

Run: `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yaml'))" && echo OK`
Expected: `OK`

- [ ] **Step 3: Commit**

```bash
cd /home/nixos/Develop/claude/comics
git add .github/workflows/ci.yaml
git commit -m "ci: run E2E tests on pull requests"
```

---

### Task 12: Final verification

- [ ] **Step 1: Rust suite**

Run: `cargo nextest run`
Expected: PASS.

- [ ] **Step 2: Full E2E suite from a clean generated dir**

```bash
cd /home/nixos/Develop/claude/comics/e2e
rm -rf .features-gen
CI=true npm test
```

Expected: PASS — 8 scenarios.

- [ ] **Step 3: Confirm the working tree is clean and the branch is ready**

Run: `git status`
Expected: clean (all work committed on `test/e2e-playwright-bdd`).

The branch is then ready for a PR (open it only when the user asks).

---

## Self-Review

**Spec coverage:**
- E2E key journeys → Tasks 6 (login), 7 (library), 8 (reader). ✅
- `data-testid` selector contract → Task 3 + page objects (Task 5). ✅
- Server lifecycle (auth + fixtures + SEED=1) → Task 4 (`playwright.config.js`). ✅
- BDD wiring (`defineBddConfig`, npm scripts) → Tasks 4 & 6. ✅
- Screenshot pipeline (light/dark, library/reader, docs/screenshots, not in CI) → Task 9. ✅
- README embed → Task 10. ✅
- Pepper&Carrot fixtures, downscaled, attribution → Task 1. ✅
- Impact on existing Rust tests → Task 2. ✅
- CI gate, Chromium only → Task 11. ✅
- Pinned versions (1.60.0 / 9.0.0) → Task 4. ✅

**Placeholder scan:** The only intentional fill-ins are values that *must* be produced during execution and cannot be known in advance: the two book IDs (`<BOOK_ID_EP01/EP02>`, read from the running app in Task 2 Step 1) and the bcrypt hash (`<PASTE_BCRYPT_HASH_HERE>`, generated in Task 4 Step 2). Each has an explicit generating command and paste location. No vague "add error handling"-style steps remain.

**Type/name consistency:** Page-object methods (`login`, `error`, `cards`, `openFirstBook`, `logout`, `currentPage`, `advance`, `setScrollMode`, `mode`) are defined in Task 5 and used unchanged in Tasks 6–9. Fixture names (`loginPage`, `libraryPage`, `readerPage`) are defined in Task 6 Step 1 and used consistently. `data-testid` values match exactly between Task 3 (templates) and Task 5 (locators).
