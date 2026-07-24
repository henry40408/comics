# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Comics is a self-hosted file server for comic books, built with Rust and Axum. It scans a data directory whose immediate subdirectories are *books* and the image files inside each are *pages*. No nesting beyond one level is scanned.

## Commands

All commands run from the repository root.

- Build: `cargo build` (release: `cargo build --release`)
- Run the server: `cargo run` (serves `./data` on `127.0.0.1:8080` by default)
- Tests: `cargo nextest run` (per the user's global rule, not `cargo test`)
  - Single test: `cargo nextest run <test_name>` (e.g. `cargo nextest run auth_logout_clears_session`)
  - Integration tests live in `tests/integration_test.rs` and drive the compiled binary via `snapbox`.
- Coverage (as CI runs it): `cargo llvm-cov nextest --all-features --workspace --lcov --output-path lcov.info`
- Lint (must pass CI): `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo deny check`
- Format before committing: `cargo fmt`

The lint config in `Cargo.toml` denies `unsafe_code` and `unexpected_cfgs` and turns on a large set of pedantic Clippy lints — expect `cargo clippy` to be strict.

### CLI subcommands

- `cargo run -- list` (alias `ls`) — print books and page counts.
- `cargo run -- hash-password` — prompt for a password and emit a bcrypt hash for `COMICS_AUTH_PASSWORD_HASH`.

## Architecture

The crate is split into a thin binary (`src/main.rs`) and a library (`src/lib.rs`) so the test suite and integration tests can build routers directly.

- **`main.rs`** — CLI parsing (`clap`), tracing setup, router assembly in `init_route`, graceful shutdown, and the `list` / `hash-password` subcommands. Embedded static assets (CSS/JS/icons) are served from here with immutable cache headers fingerprinted by `?v=<hash>`.
- **`models/`** — the scan domain. `scan_books` walks the data dir in parallel (`rayon`), building `Book`s (each with a `cover`, sorted `pages`) into a `BookScan` that also holds `books_map` and `pages_map` (id → index/page) for O(1) lookups. IDs are `xxh3` hashes of the title/path salted with `seed` (`models/ids.rs`), so a fixed `COMICS_SEED` yields stable URLs. **Scanning performs no image I/O** — `Page::new` only stats the path; dimensions are never read (a deliberate perf choice for slow disks).
- **`handlers/`** — one module per route (`index`, `book`, `page`, `thumb`, `shuffle`, `rescan`, `login`, `health`). Handlers read shared state, never block the async runtime on CPU work without bounding it.
- **`auth/`** — form-login authentication. `auth_middleware_fn` guards content routes; `config.rs` models credentials as `AuthConfig::{Some, None}`.
- **`state.rs`** — `AppState` shared via `Arc`: the cookie signing `Key`, the `RwLock<Option<BookScan>>`, the thumbnail cache dir, and a `Semaphore` bounding concurrent thumbnail generation.
- **`templates/`** + **`vendor/assets/`** — Askama HTML templates and the hand-written CSS/JS bundle (embedded at compile time via `include_str!`/`include_bytes!`).

### Scan lifecycle

The initial scan runs on a background thread (`spawn_initial_scan`) *after* the server starts listening, so `/healthz` answers immediately. Until the scan completes, content routes return `503`. `POST /rescan` replaces the `BookScan` in place. Always read `state.scan` through the `RwLock` and clone out what you need before releasing it (see the lock-then-drop pattern in `handlers/thumb.rs`).

### Authentication model

Auth is enabled only when both `COMICS_AUTH_USERNAME` and `COMICS_AUTH_PASSWORD_HASH` are set; otherwise the server is fully public (and logs a warning). Login verifies the bcrypt hash once and issues a **signed session cookie** (`comics_session`) whose value is its own expiry timestamp (7-day TTL). The signing `Key` is generated at startup, so restarting invalidates all sessions. Every content route — including page images and thumbnails — sits behind the middleware; only `/login`, `/logout`, `/healthz`, and static assets are public. Unauthenticated `GET`s redirect to `/login?next=…` (the `next` target is validated to be same-site); other methods get `401`. The tests `auth_every_protected_route_rejects_anonymous` / `…reachable_when_logged_in` are the guardrails — keep them passing when touching routing.

### Thumbnails

`GET /thumb/{size}/{id}` serves on-demand JPEG thumbnails (`sm`=120px rail, `md`=400px covers; any other size → 404). Generation is disk-cached under `COMICS_CACHE_DIR`, bounded by the `thumb_sem` semaphore, and runs in `spawn_blocking`. An undecodable source falls back to streaming the original bytes; cache writes are best-effort.

## Versioning & Release

- `Cargo.toml` `version` stays at `0.0.0-dev`; the real version comes from `build.rs` via `git describe` (or the `GIT_VERSION` env var in Docker builds) and is exposed as `comics::VERSION`.
- Releases are cut with `gh release create --generate-notes`. Pushing the resulting tag triggers `.github/workflows/docker.yaml`, which builds multi-arch (`linux/amd64`, `linux/arm64`) images and pushes them to GHCR. Do **not** hand-edit version fields or `git tag` manually.

## Conventions

- The Rust toolchain is pinned via `rust-toolchain.toml` (currently `1.96.0`); CI reads the channel from that file (no version is hard-coded in `ci.yml`). There is no separate MSRV — bumping the toolchain is a single edit to `rust-toolchain.toml`.
- Test fixtures live in `fixtures/data/`; the two fixture books have stable IDs (with `seed=1`) hard-coded in tests.
- User-facing strings in templates/login are Traditional Chinese (e.g. the login error `帳號或密碼錯誤`).
- All configuration env vars carry a `COMICS_` prefix (`NO_COLOR` and the build-time `GIT_VERSION` are intentionally unprefixed). `main.rs` fails fast via `ensure_no_legacy_env_vars` if a pre-prefix name (`BIND`, `SEED`, …) is still set — keep the `LEGACY_ENV_VARS` list in sync when adding or renaming a `#[arg(env = …)]`.
