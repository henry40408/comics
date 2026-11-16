HTML goldens captured from the Rust binary (debug build) before it was removed.

Captured with:
  COMICS secret   0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  (TEST_SECRET in src/main.rs)
  data dir        fixtures/data
  no-auth server  127.0.0.1:3999   -> index, book-paged, book-scroll
  auth server     127.0.0.1:3998   -> login, login-failed
                  COMICS_AUTH_USERNAME=user, hash of "password" from e2e/src/server.rs
                  login-failed = POST /login username=user&password=wrong (HTTP 401)

Files:
  index.golden.html         GET /
  book-paged.golden.html    GET /book/1f1c111677715adf
  book-scroll.golden.html   GET /book/1f1c111677715adf?mode=scroll
  login.golden.html         GET /login
  login-failed.golden.html  failed POST /login

Values to normalise before comparing:
  Rust version string   9.4.1-3-g968f5ea-modified   (comics --version; git describe of a dirty tree)
                        appears in every <title> and in index's <div class="ver">
  assets ?v= hash       c7db4b09d947f4e6   (xxh3 seed 0 over app.css, app.js, theme.js,
                        favicon.svg, favicon-32.png, apple-touch-icon.png; the Go
                        internal/assets.Version() produces the same value)
  index time values     <time data-localtime datetime="2026-11-16T13:40:41.191Z">Mon, 16 Nov 2026 13:40:41 +0000</time>
                        <time datetime="PT0S">0ms</time>   (scan time and scan duration; change per scan)
