package server

import (
	"net/http"
	"strconv"

	"github.com/henry40408/comics/internal/assets"
)

// Assets are fingerprinted in the URL (?v=<hash>), so they can be cached
// forever.
const immutableAsset = "public, max-age=31536000, immutable"

// Handler is the complete HTTP handler. Layers, outermost first: security
// headers, CSRF, request log, the mux; protected routes add auth and
// noStoreHTML.
func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	a.registerProtected(mux)
	a.registerPublic(mux)

	handler := a.requestLog(mux)
	// Stateless fetch-metadata CSRF check. Global so it also covers the public
	// /login and /logout POSTs; inert for GET/HEAD/OPTIONS.
	//
	// Escape hatch: browsers send Sec-Fetch-Site only to HTTPS or localhost,
	// so a plain-HTTP LAN host falls back to Origin, and an opaque
	// "Origin: null" rejects the login POST with no way back in.
	// DisableCSRFGuard drops the layer for that case; HTTPS or a localhost
	// tunnel is the better fix. The cookie's SameSite=Strict is the real
	// cross-site defence; this layer is defence in depth.
	if !a.cfg.DisableCSRFGuard {
		handler = http.NewCrossOriginProtection().Handler(handler)
	}
	return a.securityHeaders(handler)
}

func (a *App) registerProtected(mux *http.ServeMux) {
	protect := func(handler http.HandlerFunc) http.Handler {
		return a.requireAuth(noStoreHTML(handler))
	}
	mux.Handle("GET /{$}", protect(a.handleIndex))
	mux.Handle("GET /book/{id}", protect(a.handleBook))
	mux.Handle("GET /data/{id}", protect(a.handlePage))
	mux.Handle("GET /thumb/{size}/{id}", protect(a.handleThumb))
	mux.Handle("POST /shuffle", protect(a.handleShuffle))
	mux.Handle("POST /shuffle/{id}", protect(a.handleShuffleFrom))
	mux.Handle("POST /rescan", protect(a.handleRescan))
}

func (a *App) registerPublic(mux *http.ServeMux) {
	mux.HandleFunc("GET /login", a.handleLoginPage)
	mux.HandleFunc("POST /login", a.handleLoginSubmit)
	mux.HandleFunc("POST /logout", a.handleLogout)
	mux.HandleFunc("GET /healthz", a.handleHealth)
	mux.Handle("GET /assets/app.css", asset("text/css", []byte(assets.AppCSS)))
	mux.Handle("GET /assets/app.js", asset("text/javascript", []byte(assets.AppJS)))
	// Separate from app.js: loaded synchronously in <head>.
	mux.Handle("GET /assets/theme.js", asset("text/javascript", []byte(assets.ThemeJS)))
	mux.Handle("GET /favicon.svg", asset("image/svg+xml", []byte(assets.FaviconSVG)))
	mux.Handle("GET /favicon-32.png", asset("image/png", assets.FaviconPNG))
	mux.Handle("GET /apple-touch-icon.png", asset("image/png", assets.AppleTouchIconPNG))
}

func asset(contentType string, body []byte) http.Handler {
	length := strconv.Itoa(len(body))
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		header := w.Header()
		header.Set("Content-Type", contentType)
		header.Set("Cache-Control", immutableAsset)
		header.Set("Content-Length", length)
		_, _ = w.Write(body)
	})
}
