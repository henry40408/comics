# CLAUDE.md

Guidance for Claude Code (claude.ai/code) working in this repository.

Design rationale lives in the doc comments of `internal/auth/session.go`, `internal/auth/ratelimit.go`, `internal/auth/trustedproxies.go`, `internal/auth/authenticator.go`, `internal/secret/secret.go`, `internal/server/middleware.go` and, for CSRF, the comment on the layer in `Handler` (`internal/server/routes.go`). Read those before changing anything security-related.

## Overview

Comics is a self-hosted comic-book file server (Go, standard library `net/http`). Each immediate subdirectory of the data directory is a *book*; the images inside are its *pages*. Nothing deeper is scanned.

## Commands

Run from the repository root. The Go version comes from `go.mod` alone (`go` + `toolchain` lines); CI and the Dockerfile install nothing version-specific (the Docker image's Go is used when it is at least the `toolchain` line; `GOTOOLCHAIN=auto` only moves up).

- Build: `go build -o bin/comics ./cmd/comics`
- Run: `go run ./cmd/comics` (serves `./data` on `127.0.0.1:8080`)
- Tests: `go test -race ./...`; single test: `go test ./internal/server -run TestCSRF`
- Coverage (as CI): `COMICS_COVERDIR=$PWD/covdata go test -mod=vendor -coverprofile=coverage.out ./...`, then `go tool covdata textfmt -i=covdata -o coverage-bin.out` and concatenate the two profiles (drop the second `mode:` line). `-coverprofile` ignores the binary that `cmd/comics`'s `TestMain` builds and execs; with `COMICS_COVERDIR` set, `TestMain` builds it with `-cover` and sets `GOCOVERDIR` on every child, so the covdata dir holds its coverage. Unset, tests build a plain binary.
- Lint (CI-enforced): `gofmt -l` on the tracked non-vendor `.go` files (must print nothing), `go vet -mod=vendor ./...`, `go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...`
- Mutation testing (CI-enforced, the `mutation` job; about a minute): `go run github.com/go-gremlins/gremlins/cmd/gremlins@v0.6.0 unleash -E '^e2e/' -E '^vendor/' --threshold-efficacy 95 .`, after `go clean -testcache` (a cached coverage run makes gremlins' per-mutant timeout near zero, so most mutants "time out" and the score is meaningless; the job does this too). Gremlins only mutates code the tests already cover, so it complements the coverage number rather than replacing it. `e2e/` must be excluded: it is a separate module with no coverage profile, and its mutants all count as "not covered". A surviving `CONDITIONALS_BOUNDARY` mutant usually means a missing "exactly at the limit" test; a `TIMED OUT` one is counted as killed in spirit and needs no test.
- Dependency checks (CI-enforced): `go mod tidy -diff`, `go mod vendor`, then `git status --porcelain -- vendor go.mod go.sum` must print nothing (`git diff` would miss an untracked vendored package), `go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...`. Licences: `GOROOT=$(go env GOROOT) go run github.com/google/go-licenses/v2@v2.0.1 check ./... --include_tests --ignore github.com/henry40408/comics --allowed_licenses=<list>`, run at the root and again in `e2e/` (with `--ignore github.com/henry40408/comics/e2e`). The allow-list lives only in the `deps` job's `ALLOWED_LICENSES` in `.github/workflows/ci.yml`; `e2e/` also allows MPL-2.0 (godog pulls in MPL-2.0 modules), the root module must not. `GOROOT` must be set explicitly or go-licenses fails on the standard library. If it reports an unknown or disallowed licence, do not widen the list or swap the module without asking.
- Format before committing: `gofmt -w` on the files you touched.

Third-party modules are **vendored and committed** (`vendor/`); builds and tests use `-mod=vendor` (Go selects it automatically while `vendor/` exists). To add or update a dependency: `go get <module>@<version>`, `go mod tidy`, `go mod vendor`, and commit `go.mod`, `go.sum` and `vendor/` together. A `go get` without `go mod vendor` breaks the build, and the CI `deps` job catches it.

Subcommands:
- `go run ./cmd/comics list` (alias `ls`): books and page counts.
- `go run ./cmd/comics hash-password`: prints an Argon2id PHC string for `COMICS_AUTH_PASSWORD_HASH`. Reads the password from the terminal, or from stdin when there is none. Refuses an empty password; below `auth.MinPasswordChars` (15, counted in characters) it only warns, on **stderr** — the hash must stay stdout's only content so `$(comics hash-password)` works.
- `--version` prints the version and exits.

### E2E (`e2e/`)

Gherkin scenarios (`e2e/features/*.feature`) run through godog and drive the Go binary in a real browser via chromedp (Chrome DevTools Protocol; there is no driver to download).

- A **separate Go module** with its own `go.mod` and committed `vendor/`; `go test ./...` at the root does not run it. `e2e/go.mod` mirrors the root `go`/`toolchain` lines (CI checks it). Update its dependencies the same way as the root ones, inside `e2e/` (`go get`, `go mod tidy`, `go mod vendor`).
- Run from `e2e/`: `go test -count=1 -v ./...` (`-count=1` because the test cache cannot see a rebuilt `bin/comics`). One or more features: `E2E_FEATURES=features/reader.feature` (comma-separated). Regenerate `docs/screenshots/` with `go run ./cmd/screenshots`.
- godog runs two passes: `shared` (everything except `@logout`/`@rescan`, up to `ConcurrencyCeiling` (4) scenarios in parallel, one Chrome each) and `exclusive` (`@logout`, `@rescan`, one at a time, since they disturb every other live session). Undefined or pending steps fail.
- Regenerate the screenshots in the same change for visual edits (CSS, template layout, front-end JS); copy-only or logic-only edits do not need it.
- Run `gofmt -l`, `go vet ./...` and staticcheck inside `e2e/` before committing (the CI `lint` job does; the `deps` job runs the tidy/vendor/govulncheck checks there too).
- Needs a local Chromium or Chrome (chromedp starts it headless). `E2E_CHROME` pins the binary (unset: chromedp's own search, which prefers a `chromium` on `PATH` over `google-chrome`); CI sets it to `/usr/bin/google-chrome`, and the run logs which choice it used. On macOS `/Applications/Chromium.app` is found (`brew install --cask ungoogled-chromium`). A missing browser fails with one clear error, not one per scenario.
- Starts the server binary `bin/comics` itself (running `go build -mod=vendor -o bin/comics ./cmd/comics` if it is missing), or adopts one already listening on `127.0.0.1:3030`. An existing binary is not rebuilt, so rebuild it after changing server code before E2E.
- Every click goes through `clickUntil` (`e2e/internal/harness/click.go`). On CI, Chrome sometimes accepts a click but delivers no mouse event, for the rest of the session. When a click does not take, `clickUntil` probes the page (`elementFromPoint`, a capture-phase event recorder, a `requestAnimationFrame` count); if the point hit the element (`hitIsTarget`) and no event arrived, it dispatches a scripted `HTMLElement.click()` and logs a `WARNING`. Scrolling into view is instant, not smooth, so positions are stable when read. A covered control or a broken handler still fails. `@nojs` scenarios cannot run the recorder, so they rely on `hitIsTarget` alone.
- `@nojs` scenarios open a browser with scripting disabled (`Emulation.setScriptExecutionDisabled`, which applies to the next document).

### Integration tests

`cmd/comics/main_test.go` builds the binary once in `TestMain` and `exec`s it. `TestInitialScanFinished` spawns the server directly, reads stdout until the scan logs, then kills it. Use that shape for anything waiting on a log line from a running server.

### Golden pages

`internal/views/testdata/*.golden.html` pin the exact markup (the e2e suite and the no-JS CSS depend on it). They were captured from the former Rust server; `views_test.go` normalises the version, the assets hash and times before comparing. A deliberate markup change means regenerating the goldens and the e2e screenshots together.

## Architecture

Thin binary (`cmd/comics`) over internal packages, so tests can build the handler directly (`server.New(cfg).Handler()`).

| Package | Responsibility |
| --- | --- |
| `cmd/comics` | CLI (`flag`, precedence flag > env > default), `slog` logging, graceful shutdown (`serve.go`), `list`, `hash-password`, `legacyEnvVars` (`env.go`) |
| `internal/models` | `ScanBooks` (parallel) → `BookScan` with books and pages by ID; IDs are `xxh3(seed, …)` (`HashString` in `ids.go`) |
| `internal/server` | `App`, `Config`, `New`, `RunInitialScan`; `routes.go` (`Handler`), `middleware.go` (`securityHeaders`, `noStoreHTML`, `requireAuth`, `requestLog`), `handlers_library.go` (index, book, page, shuffle, rescan, health), `handlers_login.go`, `handlers_thumb.go` |
| `internal/auth` | `Authenticator`, `SessionStore`, `RateLimiter`, `ClientKeys`, `TrustedProxies`, `CookieSigner`, `AuditSalt`, password hashing (`password.go`) |
| `internal/secret` | `Secret` → `SessionKey()` (SHA-512) and `IDSeed()` (SHA-256), domain-separated |
| `internal/assets` | Embedded CSS/JS/icons (`go:embed`) + the `?v=<hash>` version |
| `internal/views` | Page builders (`layout` holds the shared `<head>`; `index`, `book`, `login`) returning strings with an escaping builder (`html.go`) |
| `internal/thumb` | Decode, resize, JPEG-encode |
| `internal/version` | `Version()` |
| `internal/assets/static/` | Hand-written CSS/JS, embedded at compile time |
| `vendor/` | Vendored third-party modules, committed |

`App` (`internal/server/server.go`) holds the cookie signer, the session store, the scan behind a `sync.RWMutex`, the cache dir, `thumbSem` and `verifySem`.

**Scanning performs no image I/O** — `models.newPage` only stats the path; dimensions are never read (deliberate, for slow disks).

### Routes

Protected: `GET /`, `GET /book/{id}` (`?mode=paged|scroll`), `GET /data/{id}`, `GET /thumb/{size}/{id}`, `POST /shuffle`, `POST /shuffle/{id}`, `POST /rescan`.

Public: `GET|POST /login`, `POST /logout`, `GET /healthz`, `/assets/app.css`, `/assets/app.js`, `/assets/theme.js`, `/favicon.svg`, `/favicon-32.png`, `/apple-touch-icon.png`.

Layers, outermost first: `securityHeaders` → `http.CrossOriginProtection` → `requestLog` → the mux; protected routes add `requireAuth` → `noStoreHTML`. `COMICS_DISABLE_CSRF_GUARD` removes the CSRF layer (escape hatch for plain-HTTP LAN hosts sending `Origin: null`); read the comment on it in `Handler` first.

### CSRF

`http.NewCrossOriginProtection` (stdlib): stateless fetch-metadata check — `Sec-Fetch-Site` first, `Origin` vs. the request `Host` as fallback, no tokens. Rules pinned by the `TestCSRF*` tests in `internal/server/security_test.go`:

- `Sec-Fetch-Site: same-site` is **rejected** (comics is one origin; its forms send `same-origin`).
- The `Origin`/host fallback compares the **whole authority, port included**. A TLS-terminating proxy forwarding a portless `Host` still matches; if a proxy rewrites only the port, a trusted origin would be needed (`AddTrustedOrigin`; not wired up).
- Exempt methods are `GET`/`HEAD`/`OPTIONS`; **`TRACE` is checked**.
- The host compared is `r.Host` (HTTP/2 `:authority`) — a proxy rewriting `Host` to an internal name breaks the fallback.

Rejections are a plain `403`.

### Content-Security-Policy

`default-src 'none'`, no `'unsafe-inline'`. Inline `<script>` and `on*=` attributes are blocked — hence `/assets/theme.js` as a separate, synchronous (not deferred) `<head>` script. `TestRenderedPagesCarryNoInlineScripts` catches violations. `style-src`/`font-src` allow `fonts.bunny.net` only for the views' webfont `<link>`s; `font-src` also allows `https://cdn.jsdelivr.net/fontsource/fonts/`, where Bunny's stylesheet points the font files (path-pinned: jsDelivr serves arbitrary npm/GitHub content).

### Reading without JavaScript

The reader must work with scripting off:

- `theme.js` sets `data-theme` and adds the `js` class to `<html>` before first paint; all no-JS CSS is scoped to `html:not(.js)` so `:target` does not fight `app.js`'s `is-current`. Guarded by `TestTheScriptedPathIsMarkedBeforeFirstPaint`; the `@nojs` e2e scenarios prove the CSS works (their session disables scripts via `Emulation.setScriptExecutionDisabled`, which applies to the next document, so it cannot be shared).
- Paging: `internal/views/book.go` (figure rendering) renders `is-current` on page 1 and `#p{n}` neighbour anchors resolved by CSS `:target`. The thumbnail rail is `<a href="#p{n}">` (`app.js` intercepts and animates).
- The `:has(.pg:target)` rule is scoped to paged mode; unscoped, a leftover `#p{n}` blanks the first page in scroll mode.
- Mode switch: links to `?mode=paged|scroll`, rendered by the book handler onto `<body data-mode>`; `app.js` switches in place. An unknown `mode` renders the default (no 400). Without JS the shared control is hidden and each page has its own `nojs-mode` link to `?mode=…#p{n}`, anchored to its `.pg`, not `.viewer`.
- Script-only UI is hidden without JS rather than shown dead or stale: `.js-only` (theme toggle in all three views, topbar's live page number), plus `.counter` and `.progress`. Each page carries a `nojs-counter` instead. `TestScriptOnlyControlsAreHiddenWithoutJavaScript` checks every view with a toggle.
- The dark palette is defined twice (`html[data-theme="dark"]` and `prefers-color-scheme: dark` for `html:not([data-theme])`); `TestDarkThemeHasANoJSFallback` fails if they drift.
- Deliberately script-only: keyboard shortcuts, theme toggle, progress bar.

### Scan lifecycle

`RunInitialScan` runs on a background goroutine *after* the server listens, so `/healthz` answers at once; content routes return `503` until it finishes. `POST /rescan` replaces the `BookScan` wholesale (`storeScan`). Read the scan through `currentScan()`: a stored `BookScan` is never mutated, so keep the pointer, not the lock (see `handlers_thumb.go`).

### Authentication

Enabled only when both `COMICS_AUTH_USERNAME` and `COMICS_AUTH_PASSWORD_HASH` are set; otherwise fully public (with a warning). Unauthenticated `GET`s redirect to `/login?next=…` (sanitised by `auth.SafeNext`); other methods get `401`.

- **Argon2id** at `auth.DefaultPasswordParams` (`m=19456, t=2, p=1`); verification reads parameters from the PHC string. Each verification uses 19 MiB, so `POST /login` holds an `App.verifySem` permit (`auth.MaxConcurrentVerifications` = 4).
- `auth.VerifyCredentials` must **not** short-circuit: Argon2 runs even for a wrong username, and the username is compared with `subtle.ConstantTimeCompare`. `username == expected && verify(…)` reintroduces a timing oracle. `auth.MaxPasswordBytes` (1024) is a rejection backstop, not truncation.
- Sessions live in the in-memory `SessionStore`; the cookie holds only an opaque 128-bit ID. **Sessions do not survive a restart** — deliberate; it makes logout enforceable.
- `POST /logout` ends **every** session (one credential pair = one person; revokes stolen cookies). The route is public; store membership authorises `SessionStore.DestroyAll`.
- Cookie: `HttpOnly`, `SameSite=Strict`, `Path=/`; with `COMICS_COOKIE_SECURE`, also `Secure` and renamed `__Host-comics_session`. Exactly one name is accepted.
- TTLs: idle `auth.DefaultIdleTTL` (3 days), absolute `auth.DefaultAbsoluteTTL` (7 days). Capacity 1 000 (`defaultMaxSessions`), LRU-evicting.
- Login rate limit (`internal/auth/ratelimit.go`): 5 per client IP per 60 s **and** 20 globally. `RateLimiter.TryAcquire` returns a `Throttle` naming the refusing `Scope` (`per_ip` / `shared` / `global` in logs) and reset time → `Retry-After`. `Global` logs `login_lockout`; others log `login_rate_limited` with `scope`. Keep these separate — the lockout is the one worth alerting on. Both windows are checked before either is charged; a successful login refunds both (`Release`). Read the `RateLimiter` docs before changing thresholds. The key is the TCP peer unless it is in `COMICS_TRUSTED_PROXIES` (**empty by default**, so `X-Forwarded-For` is ignored).
- `auth.EnsurePasswordHashUsable` (called from `ensurePasswordHashIsUsable` in `cmd/comics/serve.go`) fails startup on a hash the login route could not use (bcrypt gets a dedicated migration message). A parse is not enough — a digest-less PHC string parses, then verifies like a wrong password — so `HasDigest` is checked. Not applied to `hash-password`.
- `auth.SafeNext` accepts only a local path: the second character may be neither `/` nor `\` (browsers read both as an authority), and **every control byte, including tab, and DEL is rejected**. `next` arrives percent-decoded, so a raw newline would split the `Location` header; a tab is stricter than Go's own header check allows, but URL parsing strips tabs, so `/<TAB>/evil.example` would become the open redirect `//evil.example`.
- Audit events (emitted from `internal/server/handlers_login.go` and `internal/auth/authenticator.go`; `internal/auth/audit.go` holds the session-ID fingerprint) are INFO/WARN, visible at the default `COMICS_LOG_LEVEL=info`; pair with `--log-format json`. Never log session IDs in cleartext.

Guardrail tests: `TestAuthEveryProtectedRouteRejectsAnonymous` / `TestAuthEveryProtectedRouteReachableWhenLoggedIn` (keep passing when touching routing), `TestRemovalCookieMirrorsTheSessionCookie` (logout cookie matches the issued one), `TestWrongUsernameCostsWhatAWrongPasswordCosts` and `TestALongPasswordIsNotMerelyItsOwnPrefix` (the two properties above).

### Thumbnails

`GET /thumb/{size}/{id}`: on-demand JPEG (`sm` = 120 px rail, `md` = 400 px covers; others 404). Disk-cached under `COMICS_CACHE_DIR`, bounded by `App.thumbSem` (`generateBounded` in `internal/server/handlers_thumb.go`). Undecodable sources fall back to the original bytes; cache writes are best-effort.

## Versioning & Release

The version is never stored in a manifest: `internal/version.Version()` returns the `-ldflags "-X github.com/henry40408/comics/internal/version.version=$GIT_VERSION"` value when set (not empty, not `dev`), else the module version Go stamps from VCS, else `unknown`. Docker builds pass `GIT_VERSION` as a build arg because `.dockerignore` excludes `.git`. Release with `gh release create --generate-notes`; its tag makes `.github/workflows/docker.yml` publish the versioned image (multi-arch → GHCR), and every push to `main` publishes `nightly`. Never hand-edit versions or `git tag`.

## Conventions

- `go.mod` is the only source of the Go version (`go` and `toolchain` lines): CI and the Dockerfile install nothing version-specific (the Docker image's Go is used when it is at least the `toolchain` line; `GOTOOLCHAIN=auto` only moves up). `e2e/go.mod` mirrors those two lines (CI checks it).
- Fixtures: `fixtures/data/`. Their book IDs derive from `testSecret` in `internal/server/harness_test.go` and are hard-coded as `dataIDs`; changing the secret or derivation means recomputing them (run the binary with that secret on `fixtures/data`, read `/book/…` hrefs from the index).
- User-facing template/login strings are Traditional Chinese (e.g. `帳號或密碼錯誤`).
- Config env vars carry a `COMICS_` prefix (except build-time `GIT_VERSION`): `BIND`, `DATA_DIR`, `CACHE_DIR`, `LOG_FORMAT`, `LOG_LEVEL`, `SECRET`, `AUTH_USERNAME`, `AUTH_PASSWORD_HASH`, `COOKIE_SECURE`, `HSTS_MAX_AGE`, `TRUSTED_PROXIES`, `DISABLE_CSRF_GUARD`. `COMICS_LOG_FORMAT` accepts `full` or `json` only; `COMICS_LOG_LEVEL` (`debug|info|warn|error`, default `info`) is env-only, with no flag. `RUST_LOG` is a retired variable and fails startup.
- `ensureNoLegacyEnvVars` (`cmd/comics/env.go`) fails startup on retired names. Update `legacyEnvVars` there whenever an environment variable is added, renamed or removed — a silently ignored variable (e.g. falling back to a random secret) is worse than a startup failure.
- GitHub Actions are pinned by commit SHA with the tag as a trailing comment (`uses: owner/repo@<sha> # v1.2.3`).
