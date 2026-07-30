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

Subcommands: `cargo run -- list` (alias `ls`) prints books and page counts; `cargo run -- hash-password` emits a bcrypt hash for `COMICS_AUTH_PASSWORD_HASH`.

Integration tests (`tests/integration_test.rs`) drive the compiled binary via `snapbox`.

## Architecture

Thin binary (`src/main.rs`) + library (`src/lib.rs`), so tests can build routers directly.

| Module | Responsibility |
| --- | --- |
| `main.rs` | CLI (`clap`), tracing, router assembly in `init_route`, graceful shutdown, subcommands |
| `models/` | `scan_books` (parallel via `rayon`) → `BookScan` with `books_map` / `pages_map` for O(1) lookup; IDs are `xxh3(seed, …)` (`ids.rs`) |
| `handlers/` | One module per route: `index`, `book`, `page`, `thumb`, `shuffle`, `rescan`, `login`, `health` |
| `auth/` | `config`, `session`, `middleware`, `ratelimit`, `trusted_proxies`, `audit` |
| `csrf.rs` | Stateless `Sec-Fetch-Site`/`Origin` check on unsafe methods; global outer layer |
| `security_headers.rs` | `security_headers_layer` (global: CSP, `nosniff`, `X-Frame-Options`, `Referrer-Policy`, `Cross-Origin-*`, `Permissions-Policy`, plus HSTS when `COMICS_HSTS_MAX_AGE` is set), `no_store_html` (inside auth) |
| `secret.rs` | `Secret` → `session_key()` (SHA-512) and `id_seed()` (SHA-256), each domain-separated |
| `state.rs` | `AppState`: signing `Key`, `RwLock<Option<BookScan>>`, cache dir, thumbnail `Semaphore` |
| `assets.rs` | Embedded CSS/JS/icons + `assets_version()` (the `?v=<hash>` fingerprint) |
| `error.rs`, `helpers.rs` | `AppError`/`AppResult`; `with_scan` |
| `templates/`, `vendor/assets/` | Askama templates and the hand-written CSS/JS, embedded at compile time |

**Scanning performs no image I/O** — `Page::new` only stats the path; dimensions are never read (deliberate, for slow disks).

### Routes

Protected: `GET /`, `GET /book/{id}`, `GET /data/{id}` (page image), `GET /thumb/{size}/{id}`, `POST /shuffle`, `POST /shuffle/{id}`, `POST /rescan`.

Public: `GET|POST /login`, `POST /logout`, `GET /healthz`, and the static assets (`/assets/app.css`, `/assets/app.js`, `/assets/theme.js`, `/favicon.svg`, `/favicon-32.png`, `/apple-touch-icon.png`).

Layers, outermost first: `security_headers_layer` → `csrf_origin_guard` → `TraceLayer` → *(protected only)* `auth_middleware_fn` → `no_store_html`.

### Content-Security-Policy

The policy is `default-src 'none'` with no `'unsafe-inline'`, which is what makes the `<head>` theme snippet a separate `/assets/theme.js` (loaded synchronously, *not* deferred) rather than an inline `<script>`. Adding an inline script or an `on*=` attribute to a template will be dropped by the browser — `rendered_pages_carry_no_inline_scripts` fails first. `style-src`/`font-src` name `fonts.bunny.net` because the templates load webfonts from it; drop the `<link>`s and the policy can drop the host too.

### Scan lifecycle

The initial scan runs on a background thread (`spawn_initial_scan`) *after* the server starts listening, so `/healthz` answers immediately; until it completes, content routes return `503`. `POST /rescan` replaces the `BookScan` in place. Always read `state.scan` through the `RwLock` and clone out what you need before releasing it — see the lock-then-drop pattern in `handlers/thumb.rs`.

### Authentication

Enabled only when both `COMICS_AUTH_USERNAME` and `COMICS_AUTH_PASSWORD_HASH` are set; otherwise the server is fully public (and logs a warning). Unauthenticated `GET`s redirect to `/login?next=…` (constrained by `safe_next`); other methods get `401`.

- Sessions live in the in-memory `SessionStore`; the cookie carries an opaque 128-bit identifier and nothing else. **Sessions do not survive a restart** — that is deliberate, and it is what makes logout enforceable.
- `POST /logout` ends **every** live session, not just the caller's — comics has one set of credentials, so they are all the same person's, and this is the only way to invalidate a stolen cookie short of a restart. The route is public, so store membership is what authorises the clear (`SessionStore::destroy_all`).
- Cookie: `HttpOnly`, `SameSite=Strict`, `Path=/`; `Secure` + renamed `__Host-comics_session` only when `COMICS_COOKIE_SECURE` is set. Exactly one name is accepted.
- TTLs: idle `DEFAULT_IDLE_TTL` (3 days), absolute `DEFAULT_ABSOLUTE_TTL` (7 days). Capacity 1 000, LRU-evicting.
- `POST /login` is rate-limited to 5 attempts per client IP per 60 s (`auth/ratelimit.rs`). The key is the TCP peer unless `COMICS_TRUSTED_PROXIES` lists it — **empty by default**, so `X-Forwarded-For` is ignored out of the box.
- Audit events (`auth/audit.rs`) are INFO/WARN, so the default `error,comics=info` filter shows them; pair with `--log-format json`. Session identifiers are never logged in cleartext.

`auth_every_protected_route_rejects_anonymous` / `…reachable_when_logged_in` are the guardrails — keep them passing when touching routing. `removal_cookie_mirrors_the_session_cookie` keeps logout's removal cookie in step with the issued one.

### Thumbnails

`GET /thumb/{size}/{id}` serves on-demand JPEG thumbnails (`sm`=120px rail, `md`=400px covers; any other size → 404). Disk-cached under `COMICS_CACHE_DIR`, bounded by `thumb_sem`, generated in `spawn_blocking`. An undecodable source falls back to streaming the original bytes; cache writes are best-effort.

## Versioning & Release

`Cargo.toml` `version` stays at `0.0.0-dev`; the real version comes from `build.rs` via `git describe` (or `GIT_VERSION` in Docker builds) and is exposed as `comics::VERSION`. Releases are cut with `gh release create --generate-notes`; pushing the tag triggers `.github/workflows/docker.yaml` (multi-arch → GHCR). Do **not** hand-edit version fields or `git tag` manually.

## Conventions

- The toolchain is pinned in `rust-toolchain.toml` (currently `1.97.1`); CI reads the channel from that file. There is no separate MSRV.
- Test fixtures live in `fixtures/data/`; the two fixture books have stable IDs (derived from `TEST_SECRET` in `main.rs`) hard-coded in tests as `DATA_IDS`. Changing the secret or the derivation means recomputing them — run the binary with that secret against `fixtures/data` and read the `/book/…` hrefs off the index page.
- User-facing strings in templates/login are Traditional Chinese (e.g. the login error `帳號或密碼錯誤`).
- Config env vars all carry a `COMICS_` prefix (`NO_COLOR` and build-time `GIT_VERSION` excepted): `BIND`, `DATA_DIR`, `CACHE_DIR`, `LOG_FORMAT`, `SECRET`, `AUTH_USERNAME`, `AUTH_PASSWORD_HASH`, `COOKIE_SECURE`, `HSTS_MAX_AGE`, `TRUSTED_PROXIES`.
- `ensure_no_legacy_env_vars` fails fast on retired names. Keep `LEGACY_ENV_VARS` in sync when adding, renaming or removing a `#[arg(env = …)]` — a silently-ignored variable is worse than a startup failure, because the fallback (a random secret) looks like it works.
