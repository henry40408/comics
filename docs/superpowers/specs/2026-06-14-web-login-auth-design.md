# Web form login (signed cookie) — design

Replace HTTP Basic Auth for the GUI with a form-based login backed by a
stateless, signed session cookie. Mirrors Syncthing's v1.26 change, motivated by
the same two problems: bcrypt runs on *every* request under Basic Auth (painful
on low-powered hardware), and the browser's native Basic Auth dialog plays badly
with password managers and has no logout.

## Decisions

- **Complete replacement**: Basic Auth is removed entirely (no compatibility mode).
- **Stateless signed cookie**: no server-side session store. A random signing
  key is generated at startup, so a restart invalidates all sessions. No
  individual revocation.
- **Fixed 7-day expiry**, no "remember me" checkbox, no configurable TTL.

## Architecture

Credential configuration is unchanged: `AuthConfig::{None, Some{username,
password_hash}}`, supplied via `--auth-username` / `--auth-password-hash` env/CLI
and the `hash-password` subcommand. Only the transport of credentials and the
"already logged in" check change.

- **Login**: `GET /login` renders a form; `POST /login` verifies credentials
  with bcrypt **once** and issues a signed cookie.
- **Subsequent requests**: middleware verifies the cookie signature and expiry
  (cheap) instead of running bcrypt per request.
- **Logout**: `POST /logout` clears the cookie.

## Dependencies

Add `axum-extra` with the `cookie-signed` feature. Its `SignedCookieJar` handles
HMAC signing/verification of the cookie, avoiding hand-rolled cryptography. At
startup, generate a random signing `Key` (via `rand`) and store it in
`AppState`; implement `FromRef<AppState>` for `Key` so the jar extractor works.

## Cookie

- Name `comics_session`; value = expiry unix timestamp (login time + 7 days).
- Attributes: `HttpOnly`, `SameSite=Lax`, `Path=/`, `Max-Age=604800`.
- The signature (via `SignedCookieJar`) makes the value unforgeable; the
  middleware additionally checks `now < expiry` so expiry is enforced
  server-side, not only by the browser.

## Routes & middleware

| Route | Behaviour |
|-------|-----------|
| `GET /login` | Public. If already authenticated, 303 to `/`. |
| `POST /login` | Form `username`/`password`; bcrypt verify. Success → set cookie + 303 to `next` (default `/`). Failure → re-render form with an error. |
| `POST /logout` | Remove cookie, 303 to `/login`. |
| Protected (`/`, `/book`, `/shuffle`, `/rescan`) | Middleware checks the cookie. Unauthenticated GET → 303 to `/login?next=<path>`; unauthenticated POST → 401. `AuthConfig::None` → fully public. |
| `/data`, `/thumb`, `/healthz`, assets | Public (unchanged). |

The Basic parsing in `authenticate()` is removed and replaced with cookie
verification. The `AuthState` enum is simplified (no `Request` /
`WWW-Authenticate` variant).

## UI

- New `templates/login.html`, reusing the existing layout (`layout`/`aside`/
  `lbtn` classes) and the pre-paint theme script.
- Add a **Logout** form button to the control rows in `index.html` and
  `book.html`, shown only when auth is enabled (template gets an `auth_enabled`
  flag).

## Testing

- Rewrite the existing `auth_*` tests (no more `WWW-Authenticate` / Basic base64).
- Add: login success sets cookie; wrong password re-renders; unauthenticated GET
  on a protected route → 303 to `/login`; logout clears the cookie;
  expired/tampered cookie treated as unauthenticated; `AuthConfig::None` stays
  fully public.
- Update the unit tests in `middleware.rs` to use cookies.

## Out of scope (YAGNI)

No Basic Auth compatibility, no "remember me" checkbox, no configurable TTL, no
session revocation.
