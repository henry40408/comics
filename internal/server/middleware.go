package server

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/henry40408/comics/internal/auth"
)

// Deny-by-default (default-src 'none'); each named directive is exactly what
// the views load, so a new feature must opt itself in.
//
//   - script-src 'self': no 'unsafe-inline', which would admit injected
//     scripts too; that is why the pre-paint theme snippet is theme.js.
//   - fonts.bunny.net (the stylesheet) and the fontsource path of
//     cdn.jsdelivr.net (the font files Bunny's stylesheet points at) are the
//     only third parties. The path is pinned so the rest of jsDelivr, which
//     serves arbitrary npm and GitHub content, stays out.
//   - form-action and base-uri stop an injection re-pointing the login form or
//     every relative URL.
//   - frame-ancestors 'none' is the clickjacking control; SameSite=Strict does
//     not stop framing.
const contentSecurityPolicy = "default-src 'none'; " +
	"script-src 'self'; " +
	"style-src 'self' https://fonts.bunny.net; " +
	"font-src https://fonts.bunny.net https://cdn.jsdelivr.net/fontsource/fonts/; " +
	"img-src 'self'; " +
	"form-action 'self'; " +
	"base-uri 'none'; " +
	"frame-ancestors 'none'"

// Features comics never uses, denied so an injection cannot reach them.
const permissionsPolicy = "accelerometer=(), autoplay=(), camera=(), " +
	"display-capture=(), encrypted-media=(), fullscreen=(), " +
	"geolocation=(), gyroscope=(), magnetometer=(), " +
	"microphone=(), midi=(), payment=(), usb=()"

// constantHeaders never depend on configuration. X-Frame-Options backs up
// frame-ancestors for older browsers; CORP stops hotlinking page images, which
// frame-ancestors does not cover. no-referrer costs nothing (only fonts are
// cross-origin) and book URLs reveal what someone reads.
var constantHeaders = [...][2]string{
	{"Content-Security-Policy", contentSecurityPolicy},
	{"X-Content-Type-Options", "nosniff"},
	{"X-Frame-Options", "DENY"},
	{"Referrer-Policy", "no-referrer"},
	{"Cross-Origin-Resource-Policy", "same-origin"},
	{"Cross-Origin-Opener-Policy", "same-origin"},
	{"Permissions-Policy", permissionsPolicy},
}

// securityHeaders is the outermost layer, so it also covers /login, /healthz,
// the assets, and the 403/404/405 the layers inside it produce. The headers
// are set before next runs, so no response path can skip them.
//
// HSTS is off unless configured: comics does not terminate TLS, and a cached
// HSTS strands an HTTP-only LAN deployment for the whole max-age.
func (a *App) securityHeaders(next http.Handler) http.Handler {
	hsts := ""
	if a.cfg.HSTSMaxAge != nil {
		hsts = "max-age=" + strconv.FormatUint(*a.cfg.HSTSMaxAge, 10)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := w.Header()
		for _, h := range constantHeaders {
			header.Set(h[0], h[1])
		}
		if hsts != "" {
			header.Set("Strict-Transport-Security", hsts)
		}
		next.ServeHTTP(w, r)
	})
}

// setNoStore keeps a response out of every cache (Pragma is for HTTP/1.0), so
// the back button after logout cannot show a page that was rendered for a
// session.
func setNoStore(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("Pragma", "no-cache")
}

// requireAuth sends anonymous requests to the login form (GET) or a bare 401
// (anything else, HEAD included). It is a no-op when auth is off.
func (a *App) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state := a.authenticator.Authenticate(r)
		switch state.Kind {
		case auth.AuthAuthenticated:
			if state.UserAgentChanged {
				a.authenticator.LogUserAgentChanged(r)
			}
		case auth.AuthUnauthenticated:
			a.authenticator.LogRejection(r, state.Rejection)
			rejectAnonymous(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func rejectAnonymous(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	seeOther(w, auth.LoginRedirectTarget(r.URL))
}

// seeOther is a 303 with only a Location and an empty body. http.Redirect
// would add an HTML body and a content type, and rewrite relative URLs.
func seeOther(w http.ResponseWriter, location string) {
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusSeeOther)
}

// requestLog logs every request at DEBUG: per-request lines are noisy for an
// image-heavy app.
func (a *App) requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.logger.Enabled(r.Context(), slog.LevelDebug) {
			next.ServeHTTP(w, r)
			return
		}
		started := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		a.logger.Debug("request",
			"method", r.Method, "path", r.URL.Path,
			"status", recorder.status, "latency_ms", time.Since(started).Milliseconds())
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }
