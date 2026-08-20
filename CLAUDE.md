# CLAUDE.md

Guidance for Claude Code (claude.ai/code) working in this repository.

Design rationale is deliberately **not** duplicated here — it lives in the module-level doc comments (`csrf.rs`, `auth/session.rs`, `auth/ratelimit.rs`, `auth/trusted_proxies.rs`, `secret.rs`, `security_headers.rs`). Read those before changing anything security-related.

## Overview

Comics is a self-hosted file server for comic books, built with Rust and Axum. It scans a data directory whose immediate subdirectories are *books* and the image files inside each are *pages*. No nesting beyond one level is scanned.

## Commands

All commands run from the repository root.

- Build: `cargo build` (release: `cargo build --release`)
- Run: `cargo run` (serves `./data` on `127.0.0.1:8080`)
- Tests: `cargo nextest run` (per the user's global rule, not `cargo test`); single test: `cargo nextest run <test_name>`
- Coverage (as CI runs it): `cargo llvm-cov nextest --all-features --workspace --lcov --output-path lcov.info`
- Lint (must pass CI): `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo deny check`
- Format before committing: `cargo fmt`

`Cargo.toml` denies `unsafe_code` / `unexpected_cfgs` and enables a large pedantic Clippy set — expect strictness.

Subcommands: `cargo run -- list` (alias `ls`) prints books and page counts; `cargo run -- hash-password` emits an Argon2id PHC string for `COMICS_AUTH_PASSWORD_HASH`. It refuses an *empty* password but only warns below `MIN_PASSWORD_CHARS` (15, counted in characters where the ceiling counts bytes) — advice, not enforcement, for a service whose one user is its operator. The warning goes to **stderr**: the hash is stdout's only content, so `$(comics hash-password)` keeps working.

Browser tests live in `e2e/`, a **separate workspace** rather than a member of the root one — CI runs coverage as `--workspace`, which would otherwise drive a real browser on every coverage run. Run them with `cargo test --test e2e` from `e2e/`, and regenerate `docs/screenshots/` with `cargo run --bin screenshots` from the same place. Both need a local Chrome or Chromium installed: `WebDriver::managed` downloads a matching chromedriver by itself, but *not* the browser — unlike the Playwright setup this replaced, which shipped its own Chromium. The suite starts the server itself — the **dev** binary, built first if missing, because the release profile's LTO buys nothing for eight fixture pages — and adopts an already-listening `127.0.0.1:3030` so a re-run is fast. Scenarios run one per core up to four, and `Browser::prepare` opens a throwaway session before that starts: `WebDriver::managed` prepares a driver per call, so on a cold cache several sessions opening at once contend on the download and the run wedges rather than slows. Every click goes through `click_until` (`pages.rs`), which confirms the click did something and clicks again when it did not: `WebElement::click` reports success once the event is dispatched, which on CI is not the same as the page having reacted. Retrying alone was not enough, because on GitHub Actions Chrome sometimes accepts a click and then delivers **no** mouse event to the page at all, for the rest of that session — the first click of a session lands, the second or third stops arriving, and the three flags in `browser.rs` do not prevent it. So a click that never takes asks the page what it received: `document.elementFromPoint` at the point aimed for, a capture-phase recorder of the events that actually arrived, and a `requestAnimationFrame` count saying whether the recorder was even running. When the point belonged to the element and nothing arrived, `click_until` stands in with a scripted click (`pointerdown` through `mouseup`, then `HTMLElement.click()` — the reader's tap zones are bound to `pointerup`, so `click()` alone cannot drive them) and logs a `WARNING` naming the control. Everything else still fails: a covered control reports `hitIsTarget: false`, and one whose handler is wrong receives the events and does nothing. The `@nojs` scenarios cannot run the recorder at all — `Emulation.setScriptExecutionDisabled` stops the listener and the frame callback, though not `Execute Script` — so there the stand-in rests on `hitIsTarget` alone. `cargo nextest run` does not reach any of this.

Integration tests (`tests/integration_test.rs`) drive the compiled binary via `snapbox`. `initial_scan_finished` is the exception: the server never exits on its own, so a `snapbox` timeout would be the test's entire runtime *and* a race against the background scan. It spawns the process directly, reads stdout until the scan reports in, then kills it — `LOG_WAIT` bounds a wedged binary rather than pacing the test. Keep that shape for anything else that waits on a log line from a running server.

## Architecture

Thin binary (`src/main.rs`) + library (`src/lib.rs`), so tests can build routers directly.

| Module | Responsibility |
| --- | --- |
| `main.rs` | CLI (`clap`), tracing, router assembly in `init_route`, graceful shutdown, subcommands |
| `models/` | `scan_books` (parallel via `rayon`) → `BookScan` with `books_map` / `pages_map` for O(1) lookup; IDs are `xxh3(seed, …)` (`ids.rs`) |
| `handlers/` | One module per route: `index`, `book`, `page`, `thumb`, `shuffle`, `rescan`, `login`, `health` |
| `auth/` | `config`, `session`, `middleware`, `ratelimit`, `trusted_proxies`, `audit` |
| `csrf.rs` | Stateless `Sec-Fetch-Site`/`Origin` check on unsafe methods; global outer layer, omitted entirely under `COMICS_DISABLE_CSRF_GUARD` |
| `security_headers.rs` | `security_headers_layer` (global: CSP, `nosniff`, `X-Frame-Options`, `Referrer-Policy`, `Cross-Origin-*`, `Permissions-Policy`, plus HSTS when `COMICS_HSTS_MAX_AGE` is set), `no_store_html` (inside auth) |
| `secret.rs` | `Secret` → `session_key()` (SHA-512) and `id_seed()` (SHA-256), each domain-separated |
| `state.rs` | `AppState`: signing `Key`, `RwLock<Option<BookScan>>`, cache dir, thumbnail `Semaphore` |
| `assets.rs` | Embedded CSS/JS/icons + `assets_version()` (the `?v=<hash>` fingerprint) |
| `error.rs`, `helpers.rs` | `AppError`/`AppResult`; `with_scan` |
| `templates/`, `vendor/assets/` | Askama templates and the hand-written CSS/JS, embedded at compile time |

**Scanning performs no image I/O** — `Page::new` only stats the path; dimensions are never read (deliberate, for slow disks).

### Routes

Protected: `GET /`, `GET /book/{id}` (`?mode=paged|scroll`), `GET /data/{id}` (page image), `GET /thumb/{size}/{id}`, `POST /shuffle`, `POST /shuffle/{id}`, `POST /rescan`.

Public: `GET|POST /login`, `POST /logout`, `GET /healthz`, and the static assets (`/assets/app.css`, `/assets/app.js`, `/assets/theme.js`, `/favicon.svg`, `/favicon-32.png`, `/apple-touch-icon.png`).

Layers, outermost first: `security_headers_layer` → `csrf_origin_guard` → `TraceLayer` → *(protected only)* `auth_middleware_fn` → `no_store_html`. `COMICS_DISABLE_CSRF_GUARD` drops `csrf_origin_guard` out of that chain — it is an escape hatch for plain-HTTP LAN hosts that get no `Sec-Fetch-Site` and an opaque `Origin: null`, which otherwise locks the operator out of the login form. See the `csrf.rs` module docs before touching it.

### Content-Security-Policy

The policy is `default-src 'none'` with no `'unsafe-inline'`, which is what makes the `<head>` theme snippet a separate `/assets/theme.js` (loaded synchronously, *not* deferred) rather than an inline `<script>`. Adding an inline script or an `on*=` attribute to a template will be dropped by the browser — `rendered_pages_carry_no_inline_scripts` fails first. `style-src`/`font-src` name `fonts.bunny.net` because the templates load webfonts from it; drop the `<link>`s and the policy can drop the host too.

### Reading without JavaScript

The reader degrades on its own. `templates/book.html` renders `is-current` on the first page, and every page carries `#p{n}` anchors to its neighbours, which CSS `:target` resolves — so paging works with scripting off. All of it is scoped to `html:not(.js)`, and `theme.js` adds that `js` class in `<head>` before the first paint (its second job, next to `data-theme`), which is what keeps `:target` from fighting the `is-current` class `app.js` drives. `the_scripted_path_is_marked_before_first_paint` guards that coupling; the `@nojs`-tagged scenarios in `e2e/` are what prove the CSS actually resolves a page. They get a browser session with `Emulation.setScriptExecutionDisabled` set — which applies to the *next* document, so the session cannot be shared with a scripted scenario and is opened per-scenario from the tag.

The dark palette is defined twice: once for `html[data-theme="dark"]`, once under `@media (prefers-color-scheme: dark)` for `html:not([data-theme])`, since the attribute only exists when `theme.js` ran. `dark_theme_has_a_no_js_fallback` fails when the two lists drift.

The thumbnail rail is `<a href="#p{n}">`, not `<button>`, so it jumps on the same anchors; `app.js` calls `preventDefault` and animates instead. Each page also carries its own `nojs-counter`, because the rail's counter is script-written and would otherwise read 1 everywhere — without a script that counter and the progress bar are hidden rather than shown lying. The bar has no script-less form at all: its width is a computed percentage, and the CSP has no `'unsafe-inline'` for `style-src`.

The segmented control is a pair of links to `?mode=paged|scroll`, which `handlers/book.rs` renders straight onto `<body data-mode>`; `app.js` cancels the navigation and switches in place, so the scripted path keeps the current page instead of reloading to the top. An unrecognised `mode` renders the default rather than returning 400 — it is a display preference off a hand-edited URL. Note the `:has(.pg:target)` rule is scoped to paged: in scroll mode every page shows on purpose, and unscoped a leftover `#p{n}` would blank the first one.

Without a script that shared control is hidden, because it cannot carry your place across the switch — each page renders its own `nojs-mode` link to `?mode=…#p{n}` instead, the same reason the paging links are per-page. In scroll mode it is the only part of `.nojs` still shown, and it anchors to its own `.pg` rather than `.viewer`, or every page's link would stack in one spot.

Anything only a script can operate is hidden without one, rather than shown dead or — worse — showing stale state as if it were current. `.js-only` marks those controls (the theme toggle in all three templates, the topbar's live page number); `.counter` and `.progress` are named directly. The topbar keeps its *total*, which stays true, and the current page is stated per-page by `nojs-counter`. `script_only_controls_are_hidden_without_javascript` checks every template that renders a toggle — covering only the reader is how the topbar counter was missed initially.

Still script-only, deliberately: keyboard shortcuts (no UI to hide), the theme toggle, and the progress bar.

### Scan lifecycle

The initial scan runs on a background thread (`spawn_initial_scan`) *after* the server starts listening, so `/healthz` answers immediately; until it completes, content routes return `503`. `POST /rescan` replaces the `BookScan` in place. Always read `state.scan` through the `RwLock` and clone out what you need before releasing it — see the lock-then-drop pattern in `handlers/thumb.rs`.

### Authentication

Enabled only when both `COMICS_AUTH_USERNAME` and `COMICS_AUTH_PASSWORD_HASH` are set; otherwise the server is fully public (and logs a warning). Unauthenticated `GET`s redirect to `/login?next=…` (constrained by `safe_next`); other methods get `401`.

- Passwords are hashed with **Argon2id** at `Argon2::default()`'s parameters (`m=19456, t=2, p=1`, an OWASP-listed configuration). Verification reads its parameters from the stored PHC string, so raising them later leaves existing hashes working. Each verification wants **19 MiB**, so the login route holds a permit from `AppState::verify_sem` (`MAX_CONCURRENT_VERIFICATIONS`, 4) across it — without that bound the attempts the rate limiter admits could allocate together.
- `verify_credentials` deliberately does **not** short-circuit: the Argon2 verification runs even when the username is wrong, and the username is compared with `subtle::ConstantTimeEq`, so response time cannot enumerate it. Restoring the obvious `username == expected && verify(…)` reintroduces a timing oracle worth ~3 orders of magnitude. `MAX_PASSWORD_BYTES` (1024) is a backstop, not a truncation point — Argon2 reads the whole password, which is what the old bcrypt 72-byte ceiling could not do for a non-ASCII passphrase.
- Sessions live in the in-memory `SessionStore`; the cookie carries an opaque 128-bit identifier and nothing else. **Sessions do not survive a restart** — that is deliberate, and it is what makes logout enforceable.
- `POST /logout` ends **every** live session, not just the caller's — comics has one set of credentials, so they are all the same person's, and this is the only way to invalidate a stolen cookie short of a restart. The route is public, so store membership is what authorises the clear (`SessionStore::destroy_all`).
- Cookie: `HttpOnly`, `SameSite=Strict`, `Path=/`; `Secure` + renamed `__Host-comics_session` only when `COMICS_COOKIE_SECURE` is set. Exactly one name is accepted.
- TTLs: idle `DEFAULT_IDLE_TTL` (3 days), absolute `DEFAULT_ABSOLUTE_TTL` (7 days). Capacity 1 000, LRU-evicting.
- `POST /login` is rate-limited to 5 attempts per client IP per 60 s **and 20 across every address together** (`auth/ratelimit.rs`). `try_acquire` returns `Throttle`, naming which window refused (`Scope::PerIp` / `Shared` / `Global`) and when it resets; the handler turns that into `Retry-After` and into two distinct audit events — `login_lockout` for the account-wide case, `login_rate_limited` (with a `scope` field) for the rest. Collapsing them back into one event buries the only one worth alerting on. The global window is the account-scoped counter OWASP asks for — comics has one credential pair, so global *is* per-account — and it is what bounds a spray from addresses held in bulk. Both windows are checked before either is charged, and a successful login refunds both. Read the `RateLimiter` docs before changing the thresholds: the lockout trade is argued there. The key is the TCP peer unless `COMICS_TRUSTED_PROXIES` lists it — **empty by default**, so `X-Forwarded-For` is ignored out of the box.
- `ensure_password_hash_is_usable` fails startup on a `COMICS_AUTH_PASSWORD_HASH` the login route could not use; without it the server runs, reports auth as enabled, and rejects the correct password indistinguishably from a typo. A **bcrypt** hash gets its own message naming the migration — every pre-Argon2 configuration lands there. Note that a parse is not sufficient: a digest-less PHC string parses fine and `PasswordVerifier` reports the omission as `Error::Password`, identical to a wrong password, so `parsed.hash` is checked directly. Deliberately *not* applied to the `hash-password` subcommand, which is what fixes a bad hash.
- Audit events (`auth/audit.rs`) are INFO/WARN, so the default `error,comics=info` filter shows them; pair with `--log-format json`. Session identifiers are never logged in cleartext.

`auth_every_protected_route_rejects_anonymous` / `…reachable_when_logged_in` are the guardrails — keep them passing when touching routing. `removal_cookie_mirrors_the_session_cookie` keeps logout's removal cookie in step with the issued one. `wrong_username_costs_what_a_wrong_password_costs` and `a_password_at_the_limit_does_not_accept_its_own_suffixes` guard the two properties above.

### Thumbnails

`GET /thumb/{size}/{id}` serves on-demand JPEG thumbnails (`sm`=120px rail, `md`=400px covers; any other size → 404). Disk-cached under `COMICS_CACHE_DIR`, bounded by `thumb_sem`, generated in `spawn_blocking`. An undecodable source falls back to streaming the original bytes; cache writes are best-effort.

## Versioning & Release

`Cargo.toml` `version` stays at `0.0.0-dev`; the real version comes from `build.rs` via `git describe` (or `GIT_VERSION` in Docker builds) and is exposed as `comics::VERSION`. Releases are cut with `gh release create --generate-notes`; pushing the tag triggers `.github/workflows/docker.yaml` (multi-arch → GHCR). Do **not** hand-edit version fields or `git tag` manually.

## Conventions

- The toolchain is pinned in `rust-toolchain.toml`, which is the single source of the Rust version: CI installs nothing itself (runners ship rustup, so the first `cargo` call materialises the channel and its components), and the Dockerfile's base image carries no version tag. There is no separate MSRV.
- Test fixtures live in `fixtures/data/`; the two fixture books have stable IDs (derived from `TEST_SECRET` in `main.rs`) hard-coded in tests as `DATA_IDS`. Changing the secret or the derivation means recomputing them — run the binary with that secret against `fixtures/data` and read the `/book/…` hrefs off the index page.
- User-facing strings in templates/login are Traditional Chinese (e.g. the login error `帳號或密碼錯誤`).
- Config env vars all carry a `COMICS_` prefix (`NO_COLOR` and build-time `GIT_VERSION` excepted): `BIND`, `DATA_DIR`, `CACHE_DIR`, `LOG_FORMAT`, `SECRET`, `AUTH_USERNAME`, `AUTH_PASSWORD_HASH`, `COOKIE_SECURE`, `HSTS_MAX_AGE`, `TRUSTED_PROXIES`, `DISABLE_CSRF_GUARD`.
- `ensure_no_legacy_env_vars` fails fast on retired names. Keep `LEGACY_ENV_VARS` in sync when adding, renaming or removing a `#[arg(env = …)]` — a silently-ignored variable is worse than a startup failure, because the fallback (a random secret) looks like it works.
