// Package server wires comics' routes, middleware and handlers together.
package server

import (
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/henry40408/comics/internal/auth"
	"github.com/henry40408/comics/internal/models"
	"github.com/henry40408/comics/internal/secret"
)

// Config is everything the server needs from the outside.
type Config struct {
	DataDir  string
	CacheDir string
	Secret   secret.Secret
	// Auth is enabled only when both AuthUsername and AuthPasswordHash are set.
	AuthUsername     string
	AuthPasswordHash string
	CookieSecure     bool
	DisableCSRFGuard bool
	// HSTSMaxAge is a pointer because 0 is a valid max-age.
	HSTSMaxAge     *uint64
	TrustedProxies auth.TrustedProxies
	// Logger must not be nil.
	Logger *slog.Logger
}

// App is the comics server: its state and its HTTP handler.
type App struct {
	cfg    Config
	logger *slog.Logger
	seed   uint64

	// creds is nil when auth is off.
	creds         *auth.Credentials
	authenticator *auth.Authenticator
	signer        auth.CookieSigner
	sessions      *auth.SessionStore
	salt          *auth.AuditSalt
	limiter       *auth.RateLimiter
	clientKeys    *auth.ClientKeys

	// thumbSem bounds concurrent thumbnail generation.
	thumbSem chan struct{}
	// verifySem bounds concurrent Argon2id verifications (19 MiB each).
	verifySem chan struct{}

	// scan is replaced wholesale and never mutated after it is stored, so a
	// reader may keep the pointer after releasing scanMu.
	scanMu sync.RWMutex
	scan   *models.BookScan
}

// New builds the app. It does no I/O: the data directory is scanned by
// RunInitialScan.
func New(cfg Config) *App {
	if cfg.CacheDir == "" {
		cfg.CacheDir = filepath.Join(os.TempDir(), "comics-thumbs")
	}
	signer := auth.NewCookieSigner(cfg.Secret.SessionKey())
	sessions := auth.NewSessionStore(auth.DefaultIdleTTL, auth.DefaultAbsoluteTTL, nil)
	salt := auth.NewAuditSalt()
	app := &App{
		cfg:        cfg,
		logger:     cfg.Logger,
		seed:       cfg.Secret.IDSeed(),
		signer:     signer,
		sessions:   sessions,
		salt:       salt,
		limiter:    newLoginLimiter(),
		clientKeys: auth.NewClientKeys(cfg.TrustedProxies, cfg.Logger),
		thumbSem:   make(chan struct{}, runtime.NumCPU()),
		verifySem:  make(chan struct{}, auth.MaxConcurrentVerifications),
	}
	if cfg.AuthUsername != "" && cfg.AuthPasswordHash != "" {
		app.creds = &auth.Credentials{Username: cfg.AuthUsername, PasswordHash: cfg.AuthPasswordHash}
	}
	app.authenticator = &auth.Authenticator{
		Enabled:      app.creds != nil,
		CookieSecure: cfg.CookieSecure,
		Signer:       signer,
		Sessions:     sessions,
		Salt:         salt,
		Logger:       cfg.Logger,
	}
	return app
}

func newLoginLimiter() *auth.RateLimiter {
	return auth.NewRateLimiter(
		auth.LoginMaxAttemptsPerIP, auth.LoginMaxAttemptsGlobal, auth.LoginWindowSecs, nil)
}

// RunInitialScan scans the data directory and stores the result. It is
// synchronous; main runs it in a goroutine once the server listens, so
// /healthz answers at once. It logs its own outcome and returns the error for
// the caller to act on.
func (a *App) RunInitialScan() error {
	scan, err := models.ScanBooks(a.seed, a.cfg.DataDir, a.logger)
	if err != nil {
		a.logger.Error("initial scan failed", "err", err)
		return err
	}
	a.logger.Info("initial scan finished", scanFields(scan)...)
	a.storeScan(scan)
	return nil
}

func scanFields(scan *models.BookScan) []any {
	return []any{
		"books", len(scan.Books),
		"pages", pageCount(scan),
		"duration_ms", scan.ScanDuration.Milliseconds(),
	}
}

func pageCount(scan *models.BookScan) int {
	total := 0
	for _, book := range scan.Books {
		total += len(book.Pages)
	}
	return total
}

func (a *App) storeScan(scan *models.BookScan) {
	a.scanMu.Lock()
	a.scan = scan
	a.scanMu.Unlock()
}

// currentScan is nil until the first scan lands. The returned scan is
// immutable, so callers use it without holding the lock.
func (a *App) currentScan() *models.BookScan {
	a.scanMu.RLock()
	defer a.scanMu.RUnlock()
	return a.scan
}

// readyScan is currentScan for the content routes: until the first scan lands
// it answers a bare 503 and reports false.
func (a *App) readyScan(w http.ResponseWriter) (*models.BookScan, bool) {
	scan := a.currentScan()
	if scan == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return nil, false
	}
	return scan, true
}
