# CLAUDE.md

Guidance for Claude Code (claude.ai/code) working in this repository.

Design rationale lives in the doc comments of `auth/session.rs`, `auth/ratelimit.rs`, `auth/trusted_proxies.rs`, `secret.rs`, `security_headers.rs` and, for CSRF, the comment on the layer in `init_route`. Read those before changing anything security-related.

## Overview

Comics is a self-hosted comic-book file server (Rust, Axum). Each immediate subdirectory of the data directory is a *book*; the images inside are its *pages*. Nothing deeper is scanned.

## Commands

Run from the repository root.

- Build: `cargo build` (`--release` for release)
- Run: `cargo run` (serves `./data` on `127.0.0.1:8080`)
- Tests: `cargo nextest run` (never `cargo test`); single test: `cargo nextest run <test_name>`
- Coverage (as CI): `cargo llvm-cov nextest --all-features --workspace --lcov --output-path lcov.info`
- Lint (CI-enforced): `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo deny check`
- Format before committing: `cargo fmt`

`Cargo.toml` denies `unsafe_code` / `unexpected_cfgs` and enables Clippy `pedantic` plus extra restriction lints.

Subcommands:
- `cargo run -- list` (alias `ls`): books and page counts.
- `cargo run -- hash-password`: prints an Argon2id PHC string for `COMICS_AUTH_PASSWORD_HASH`. Refuses an empty password; below `MIN_PASSWORD_CHARS` (15, counted in characters) it only warns, on **stderr** — the hash must stay stdout's only content so `$(comics hash-password)` works.

### E2E (`e2e/`)

- A **separate workspace**, not a root member, so `--workspace` coverage does not drive a browser. Run from `e2e/`: `cargo test --test e2e`; regenerate `docs/screenshots/` with `cargo run --bin screenshots`. `cargo nextest run` at the root does not run it.
- Needs a local Chrome/Chromium; `WebDriver::managed` fetches chromedriver but not the browser.
- Starts the **dev** server binary itself (building it if missing), or adopts one already listening on `127.0.0.1:3030`.
- Up to `CONCURRENCY_CEILING` (4) scenarios in parallel. `Browser::prepare` opens one throwaway session first so concurrent sessions do not race the cold driver download (that wedges the run).
- Every click goes through `click_until` (`pages.rs`). On CI, Chrome sometimes accepts a click but delivers no mouse event, for the rest of the session. When a click does not take, `click_until` probes the page (`elementFromPoint`, a capture-phase event recorder, a `requestAnimationFrame` count); if the point hit the element (`hitIsTarget`) and no event arrived, it dispatches a scripted click (`pointerdown`…`mouseup`, then `HTMLElement.click()` — the reader's tap zones listen on `pointerup`) and logs a `WARNING`. A covered control or a broken handler still fails. `@nojs` scenarios cannot run the recorder, so they rely on `hitIsTarget` alone.

### Integration tests

`tests/integration_test.rs` drives the binary via `snapbox`. Exception: `initial_scan_finished` spawns the server directly, reads stdout until the scan logs, then kills it (`LOG_WAIT` only bounds a wedged binary). Use that shape for anything waiting on a log line from a running server.

## Architecture

Thin binary (`src/main.rs`) + library (`src/lib.rs`), so tests can build routers directly.

| Module | Responsibility |
| --- | --- |
| `main.rs` | CLI (`clap`), tracing, router assembly in `init_route`, graceful shutdown, subcommands |
| `models/` | `scan_books` (parallel via `rayon`) → `BookScan` with `books_map` / `pages_map`; IDs are `xxh3(seed, …)` (`ids.rs`) |
| `handlers/` | One module per route: `index`, `book`, `page`, `thumb`, `shuffle`, `rescan`, `login`, `health` |
| `auth/` | `config`, `session`, `middleware`, `ratelimit`, `trusted_proxies`, `audit` |
| `security_headers.rs` | `security_headers_layer` (global: CSP, `nosniff`, `X-Frame-Options`, `Referrer-Policy`, `Cross-Origin-*`, `Permissions-Policy`, HSTS when `COMICS_HSTS_MAX_AGE` is set), `no_store_html` (inside auth) |
| `secret.rs` | `Secret` → `session_key()` (SHA-512) and `id_seed()` (SHA-256), domain-separated |
| `state.rs` | `AppState`: signing `Key`, `RwLock<Option<BookScan>>`, cache dir, `thumb_sem`, `verify_sem` |
| `assets.rs` | Embedded CSS/JS/icons + `assets_version()` (`?v=<hash>`) |
| `error.rs`, `helpers.rs` | `AppError`/`AppResult`; `with_scan` |
| `templates/`, `vendor/assets/` | Askama templates and hand-written CSS/JS, embedded at compile time |

**Scanning performs no image I/O** — `Page::new` only stats the path; dimensions are never read (deliberate, for slow disks).

### Routes

Protected: `GET /`, `GET /book/{id}` (`?mode=paged|scroll`), `GET /data/{id}`, `GET /thumb/{size}/{id}`, `POST /shuffle`, `POST /shuffle/{id}`, `POST /rescan`.

Public: `GET|POST /login`, `POST /logout`, `GET /healthz`, `/assets/app.css`, `/assets/app.js`, `/assets/theme.js`, `/favicon.svg`, `/favicon-32.png`, `/apple-touch-icon.png`.

Layers, outermost first: `security_headers_layer` → `CsrfLayer` → `TraceLayer` → *(protected only)* `auth_middleware_fn` → `no_store_html`. `COMICS_DISABLE_CSRF_GUARD` removes `CsrfLayer` (escape hatch for plain-HTTP LAN hosts sending `Origin: null`); read the comment on it in `init_route` first.

### CSRF

`tower_http::csrf::CsrfLayer`: stateless fetch-metadata check (Go 1.25's scheme) — `Sec-Fetch-Site` first, `Origin` vs. effective host as fallback, no tokens. Rules pinned by the `csrf_*` tests in `main.rs`:

- `Sec-Fetch-Site: same-site` is **rejected** (comics is one origin; its forms send `same-origin`).
- The `Origin`/host fallback compares the **whole authority, port included**. A TLS-terminating proxy forwarding a portless `Host` still matches; if a proxy rewrites only the port, use `add_trusted_origin`.
- Exempt methods are `GET`/`HEAD`/`OPTIONS`; **`TRACE` is checked**.
- Effective host = request-target authority (HTTP/2 `:authority`) if present, else `Host` — a proxy rewriting `Host` to an internal name breaks the fallback.

Rejections carry a `ProtectionError` extension; nothing reads it yet.

### Content-Security-Policy

`default-src 'none'`, no `'unsafe-inline'`. Inline `<script>` and `on*=` attributes are blocked — hence `/assets/theme.js` as a separate, synchronous (not deferred) `<head>` script. `rendered_pages_carry_no_inline_scripts` catches violations. `style-src`/`font-src` allow `fonts.bunny.net` only for the templates' webfont `<link>`s.

### Reading without JavaScript

The reader must work with scripting off:

- `theme.js` sets `data-theme` and adds the `js` class to `<html>` before first paint; all no-JS CSS is scoped to `html:not(.js)` so `:target` does not fight `app.js`'s `is-current`. Guarded by `the_scripted_path_is_marked_before_first_paint`; the `@nojs` e2e scenarios prove the CSS works (their session disables scripts via `Emulation.setScriptExecutionDisabled`, which applies to the next document, so it cannot be shared).
- Paging: `book.html` renders `is-current` on page 1 and `#p{n}` neighbour anchors resolved by CSS `:target`. The thumbnail rail is `<a href="#p{n}">` (`app.js` intercepts and animates).
- The `:has(.pg:target)` rule is scoped to paged mode; unscoped, a leftover `#p{n}` blanks the first page in scroll mode.
- Mode switch: links to `?mode=paged|scroll`, rendered by `handlers/book.rs` onto `<body data-mode>`; `app.js` switches in place. An unknown `mode` renders the default (no 400). Without JS the shared control is hidden and each page has its own `nojs-mode` link to `?mode=…#p{n}`, anchored to its `.pg`, not `.viewer`.
- Script-only UI is hidden without JS rather than shown dead or stale: `.js-only` (theme toggle in all three templates, topbar's live page number), plus `.counter` and `.progress`. Each page carries a `nojs-counter` instead. `script_only_controls_are_hidden_without_javascript` checks every template with a toggle.
- The dark palette is defined twice (`html[data-theme="dark"]` and `prefers-color-scheme: dark` for `html:not([data-theme])`); `dark_theme_has_a_no_js_fallback` fails if they drift.
- Deliberately script-only: keyboard shortcuts, theme toggle, progress bar.

### Scan lifecycle

`spawn_initial_scan` runs on a background thread *after* the server listens, so `/healthz` answers at once; content routes return `503` until it finishes. `POST /rescan` replaces the `BookScan` in place. Read `state.scan` through the `RwLock` and clone what you need before releasing it (see `handlers/thumb.rs`).

### Authentication

Enabled only when both `COMICS_AUTH_USERNAME` and `COMICS_AUTH_PASSWORD_HASH` are set; otherwise fully public (with a warning). Unauthenticated `GET`s redirect to `/login?next=…` (sanitised by `safe_next`); other methods get `401`.

- **Argon2id** at `Argon2::default()` (`m=19456, t=2, p=1`); verification reads parameters from the PHC string. Each verification uses 19 MiB, so `POST /login` holds an `AppState::verify_sem` permit (`MAX_CONCURRENT_VERIFICATIONS` = 4).
- `verify_credentials` must **not** short-circuit: Argon2 runs even for a wrong username, and the username is compared with `subtle`'s `ConstantTimeEq`. `username == expected && verify(…)` reintroduces a timing oracle. `MAX_PASSWORD_BYTES` (1024) is a rejection backstop, not truncation.
- Sessions live in the in-memory `SessionStore`; the cookie holds only an opaque 128-bit ID. **Sessions do not survive a restart** — deliberate; it makes logout enforceable.
- `POST /logout` ends **every** session (one credential pair = one person; revokes stolen cookies). The route is public; store membership authorises `SessionStore::destroy_all`.
- Cookie: `HttpOnly`, `SameSite=Strict`, `Path=/`; with `COMICS_COOKIE_SECURE`, also `Secure` and renamed `__Host-comics_session`. Exactly one name is accepted.
- TTLs: idle `DEFAULT_IDLE_TTL` (3 days), absolute `DEFAULT_ABSOLUTE_TTL` (7 days). Capacity 1 000 (`MAX_SESSIONS`), LRU-evicting.
- Login rate limit (`auth/ratelimit.rs`): 5 per client IP per 60 s **and** 20 globally. `try_acquire` returns `Throttle` naming the refusing `Scope` (`PerIp` / `Shared` / `Global`) and reset time → `Retry-After`. `Global` logs `login_lockout`; others log `login_rate_limited` with `scope`. Keep these separate — the lockout is the one worth alerting on. Both windows are checked before either is charged; a successful login refunds both. Read the `RateLimiter` docs before changing thresholds. The key is the TCP peer unless it is in `COMICS_TRUSTED_PROXIES` (**empty by default**, so `X-Forwarded-For` is ignored).
- `ensure_password_hash_is_usable` fails startup on a hash the login route could not use (bcrypt gets a dedicated migration message). A parse is not enough — a digest-less PHC string parses, then verifies as `Error::PasswordInvalid` like a wrong password — so `parsed.hash` is checked. Not applied to `hash-password`.
- Audit events (emitted from `handlers/login.rs` and `auth/middleware.rs`; `auth/audit.rs` holds the session-ID fingerprint) are INFO/WARN, visible under the default `error,comics=info` filter; pair with `--log-format json`. Never log session IDs in cleartext.

Guardrail tests: `auth_every_protected_route_rejects_anonymous` / `auth_every_protected_route_reachable_when_logged_in` (keep passing when touching routing), `removal_cookie_mirrors_the_session_cookie` (logout cookie matches the issued one), `wrong_username_costs_what_a_wrong_password_costs` and `a_long_password_is_not_merely_its_own_prefix` (the two properties above).

### Thumbnails

`GET /thumb/{size}/{id}`: on-demand JPEG (`sm` = 120 px rail, `md` = 400 px covers; others 404). Disk-cached under `COMICS_CACHE_DIR`, bounded by `thumb_sem`, generated in `spawn_blocking`. Undecodable sources fall back to the original bytes; cache writes are best-effort.

## Versioning & Release

`Cargo.toml` `version` stays `0.0.0-dev`; `build.rs` derives the real one from `git describe` (or `GIT_VERSION` in Docker) as `comics::VERSION`. Release with `gh release create --generate-notes`; the tag triggers `.github/workflows/docker.yaml` (multi-arch → GHCR). Never hand-edit versions or `git tag`.

## Conventions

- `rust-toolchain.toml` is the only source of the Rust version: CI and the Dockerfile install nothing version-specific. No separate MSRV.
- Fixtures: `fixtures/data/`. Their book IDs derive from `TEST_SECRET` in `main.rs` and are hard-coded as `DATA_IDS`; changing the secret or derivation means recomputing them (run the binary with that secret on `fixtures/data`, read `/book/…` hrefs from the index).
- User-facing template/login strings are Traditional Chinese (e.g. `帳號或密碼錯誤`).
- Config env vars carry a `COMICS_` prefix (except `NO_COLOR` and build-time `GIT_VERSION`): `BIND`, `DATA_DIR`, `CACHE_DIR`, `LOG_FORMAT`, `SECRET`, `AUTH_USERNAME`, `AUTH_PASSWORD_HASH`, `COOKIE_SECURE`, `HSTS_MAX_AGE`, `TRUSTED_PROXIES`, `DISABLE_CSRF_GUARD`.
- `ensure_no_legacy_env_vars` fails startup on retired names. Update `LEGACY_ENV_VARS` whenever an `#[arg(env = …)]` is added, renamed or removed — a silently ignored variable (e.g. falling back to a random secret) is worse than a startup failure.
