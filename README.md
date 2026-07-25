# Comics

> Simple file server for comic books

[![CI](https://github.com/henry40408/comics/actions/workflows/ci.yml/badge.svg)](https://github.com/henry40408/comics/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/henry40408/comics/graph/badge.svg?token=26VSHOGXLN)](https://codecov.io/gh/henry40408/comics)
[![Release](https://img.shields.io/github/v/release/henry40408/comics)](https://github.com/henry40408/comics/releases/latest)
[![License](https://img.shields.io/github/license/henry40408/comics)](LICENSE.txt)
[![Rust toolchain](https://img.shields.io/badge/dynamic/toml?url=https://raw.githubusercontent.com/henry40408/comics/main/rust-toolchain.toml&query=$.toolchain.channel&label=rust%20toolchain&logo=rust)](https://www.rust-lang.org/)
[![Docker](https://img.shields.io/badge/docker-ghcr.io-blue.svg)](https://ghcr.io/henry40408/comics)
[![Casual Maintenance Intended](https://casuallymaintained.tech/badge.svg)](https://casuallymaintained.tech/)
[![Vibe Coded](https://img.shields.io/badge/vibe_coded-Claude-d97757?logo=anthropic&logoColor=white)](https://claude.com/claude-code)

This project provides a self-hosted solution to serve comic books.

|       | Library                                                        | Reader                                                       |
| ----- | -------------------------------------------------------------- | ----------------------------------------------------------- |
| Light | ![Library, light theme](docs/screenshots/library-light.png)    | ![Reader, light theme](docs/screenshots/reader-light.png)   |
| Dark  | ![Library, dark theme](docs/screenshots/library-dark.png)      | ![Reader, dark theme](docs/screenshots/reader-dark.png)     |

> Sample artwork: [Pepper&Carrot](https://www.peppercarrot.com/) by David Revoy, CC-BY 4.0.

## Background

While several options exist for self-hosted comic readers like [Calibre](https://github.com/janeczku/calibre-web), [Komga](https://github.com/gotson/komga), and [Tanoshi](https://github.com/faldez/tanoshi), they often come with complications in setup or format restrictions. Comics seeks to offer a straightforward alternative.

## Features

- **Simple Structure**: Comics looks only at the immediate subdirectories of your chosen folder. Each directory is treated as a book, and the files inside as the pages. No nested subfolders will be scanned. This simplicity ensures you have a clear structure for your comics.
- **Manga-friendly Reader**: Read right-to-left page by page or as a continuous vertical scroll, switchable on the fly. Includes a progress bar, a thumbnail strip for jumping between pages, keyboard navigation, and a light/dark theme that follows your system and can be toggled manually. Covers and the thumbnail strip are served as small JPEG thumbnails generated on demand and cached on disk, so browsing stays light even on slow storage.
- **Web Login**: Safeguard your comics with a username-password login form backed by a signed session cookie (valid for 7 days). Credentials are verified once at login instead of on every request, and every page — including the images and thumbnails themselves — is served only to logged-in users. See [Commands](#commands) and [Configuration](#configuration) for setup.

## Configuration

| Variable | Description | Default |
| --- | --- | --- |
| `COMICS_AUTH_USERNAME` | Username for the login form | _(none)_ |
| `COMICS_AUTH_PASSWORD_HASH` | Hashed password for the login form | _(none)_ |
| `COMICS_COOKIE_SECURE` | Send the session cookie with the `Secure` attribute (enable when served over HTTPS) | _(off)_ |
| `COMICS_SECRET` | The one secret: at least 64 hex characters (`openssl rand -hex 32`). Signs the session cookie and salts hashed book/page IDs | _(random per start)_ |
| `COMICS_HSTS_MAX_AGE` | Send `Strict-Transport-Security` with this `max-age` in seconds (e.g. `63072000`) | _(off)_ |
| `COMICS_BIND` | Bind host & port (defaults to loopback; the container image sets `0.0.0.0:8080` so a reverse proxy can reach it) | `127.0.0.1:8080` |
| `COMICS_DATA_DIR` | Data directory | `./data` |
| `COMICS_CACHE_DIR` | Directory for cached thumbnails | `comics-thumbs` under the system temp dir |
| `COMICS_LOG_FORMAT` | Log format (`full`, `compact`, `pretty`, `json`) | `full` |
| `NO_COLOR` | Disable color output ([no-color.org](https://no-color.org/)) | _(off)_ |

> **`COMICS_SECRET`:** generate one with `openssl rand -hex 32` and supply it
> through the environment or a secret file — never on a shell command line (it
> lands in the history) and never committed. Two independent values are derived
> from it, each behind its own domain-separated hash: the key that signs session
> cookies, and the seed that salts hashed book and page IDs. Without it a random
> secret is generated at each start, which logs everyone out *and* changes every
> book/page URL on restart, and cannot be shared across replicas. Rotating the
> value does the same on purpose; anyone holding it can forge a session.

> **Audit logging:** logins, logouts, failed logins and throttled attempts are
> logged with the client IP and `User-Agent` (and, for sessions, a salted hash of
> the session identifier — never the identifier itself, and never the submitted
> username or password). If you would rather not record IP and `User-Agent`, drop
> the level with `RUST_LOG` (e.g. `RUST_LOG=comics=warn`).

> **Login throttling:** `POST /login` allows 5 *failed* attempts per client IP
> per 60 seconds; further attempts get `429` until the window passes. A
> successful login costs nothing. `X-Forwarded-For` is trusted only when the
> connection itself comes from loopback (comics on the same host or in the same
> compose stack as the proxy), and only its last entry — the hop the proxy
> appended. Behind a reverse proxy that is *not* on loopback, every request
> appears to come from the proxy and therefore shares one bucket — safe for a
> single-account service, but a burst of failed logins locks the form for a
> minute. If your proxy is chained behind another one, the last entry is the
> inner proxy rather than the client, and the same shared-bucket caveat applies.

> **`COMICS_COOKIE_SECURE`:** comics never terminates TLS itself, so it cannot
> tell whether it is reached over HTTPS behind a reverse proxy — hence the
> explicit opt-in. Turn it on when the site is always served over HTTPS. Setting
> it on a plain-HTTP deployment makes browsers silently discard the session
> cookie, so login will appear to do nothing. Enabling it also renames the cookie
> to `__Host-comics_session` (the prefix requires `Secure`), so existing sessions
> are logged out once — in both directions of the switch.

> **`COMICS_HSTS_MAX_AGE`:** prefer configuring HSTS on the reverse proxy that
> terminates TLS; this flag exists for deployments that cannot. Enable it only
> when comics is always reached over HTTPS: a browser that has seen the header
> will refuse plain HTTP to this host for the whole `max-age`, and recovering
> means clearing the browser's HSTS entry by hand (`chrome://net-internals/#hsts`).
> `includeSubDomains` and `preload` are deliberately not offered — their blast
> radius covers the whole domain, so they belong to whoever operates the proxy.

> **Migrating from an older release:** `COMICS_SEED` and `COMICS_SESSION_KEY`
> were folded into the single `COMICS_SECRET` both are now derived from, and
> before that these variables were unprefixed (`BIND`, `SEED`, `AUTH_USERNAME`,
> …). To catch stale configuration, the server **refuses to start** if any
> retired name is still set — rename (or unset) it. `NO_COLOR` is unchanged.
>
> Moving to `COMICS_SECRET` is a breaking change in both directions: the derived
> signing key differs from the old `COMICS_SESSION_KEY` (so everyone is logged
> out once) and the derived seed differs from the old `COMICS_SEED` (so every
> book and page URL changes once). Bookmarks pointing at the old URLs will 404.

## Quick Start

1. **Getting Started**:

   - Clone the repository to your local machine.
   - Navigate to the project directory and install any required dependencies (if applicable).

2. **Organize Your Comics**:

Make sure you have your comics structured as shown below:

```
data
├── book1
│   ├── page1.jpg
│   ├── page2.jpg
│   └── page3.jpg
├── book2
│   ├── page1.jpg
│   ├── page2.jpg
│   └── page3.jpg
└── book3
    ├── page1.jpg
    ├── page2.jpg
    └── page3.jpg
```

Each book directory represents an individual comic book, with image files as the pages.

3. **Run the Server**:

Navigate to the project directory in your terminal or command line and enter:

```bash
./comics
```

Now, open your web browser and head to http://localhost:8080/ to view your comics.

## Commands

### `hash-password`

Generate a bcrypt-hashed password for the login form:

```bash
$ comics hash-password
Password:
Confirmation:
$2a$10$...Ot6
```

### `list` (alias: `ls`)

List all books and their page counts:

```bash
$ comics list
Book Title 1 (10P)
Book Title 2 (5P)
2 book(s), 15 page(s), scanned in 1.23ms
```

## Need Help?

For a comprehensive list of options, type:

```bash
./comics -h
```

## License

MIT
