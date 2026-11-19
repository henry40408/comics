package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/henry40408/comics/internal/auth"
	"github.com/henry40408/comics/internal/secret"
	"github.com/henry40408/comics/internal/server"
	"github.com/henry40408/comics/internal/version"
)

const (
	shutdownTimeout   = 30 * time.Second
	readHeaderTimeout = 10 * time.Second
	idleTimeout       = 120 * time.Second
)

// serverConfig turns the options into the server's configuration, generating
// a random secret (with a warning) when none was given.
func serverConfig(opts options, logger *slog.Logger) server.Config {
	secretValue := secret.Generate()
	if opts.secret != nil {
		secretValue = *opts.secret
	} else {
		logger.Warn("no --secret provided; generating a random one — every session will " +
			"be invalidated and every book/page URL will change on restart. " +
			"Generate a persistent secret with `openssl rand -hex 32` and set " +
			"COMICS_SECRET.")
	}
	return server.Config{
		DataDir:          opts.dataDir,
		AuthUsername:     opts.authUsername,
		AuthPasswordHash: opts.authPasswordHash,
		CacheDir:         opts.cacheDir,
		Secret:           secretValue,
		CookieSecure:     opts.cookieSecure,
		DisableCSRFGuard: opts.disableCSRFGuard,
		HSTSMaxAge:       opts.hstsMaxAge,
		TrustedProxies:   opts.trustedProxies,
		Logger:           logger,
	}
}

// ensurePasswordHashIsUsable runs before the server is built, and never before
// hash-password, which is how an operator fixes a bad hash.
func ensurePasswordHashIsUsable(opts options) error {
	if opts.authPasswordHash == "" {
		return nil
	}
	return auth.EnsurePasswordHashUsable(opts.authPasswordHash)
}

func logConfigurationWarnings(opts options, logger *slog.Logger) {
	secure := opts.cookieSecure
	if opts.disableCSRFGuard {
		logger.Warn("CSRF origin guard disabled by --disable-csrf-guard; every " +
			"state-changing request is accepted whatever its origin. The " +
			"session cookie's SameSite=Strict is the only cross-site defence " +
			"left. Serving over HTTPS is the way to undo this.")
	}
	if opts.authUsername == "" || opts.authPasswordHash == "" {
		logger.Warn("no authorization enabled, server is publicly accessible")
	} else if !secure {
		logger.Warn("session cookie is issued without the Secure attribute; " +
			"set --cookie-secure (COMICS_COOKIE_SECURE=true) when serving over HTTPS")
	}
	if opts.hstsMaxAge != nil && !secure {
		logger.Warn("HSTS is enabled but the session cookie is not marked Secure; " +
			"set --cookie-secure (COMICS_COOKIE_SECURE=true) too")
	}
}

// runServer follows a fixed order. The signal handler goes in before the
// listener, so a signal arriving right after startup still shuts down
// gracefully instead of hitting the default action.
func runServer(opts options, logger *slog.Logger) error {
	if err := ensurePasswordHashIsUsable(opts); err != nil {
		return err
	}
	config := serverConfig(opts, logger)
	app := server.New(config)
	logConfigurationWarnings(opts, logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	listener, err := net.Listen("tcp", opts.bind)
	if err != nil {
		return err
	}
	logger.Info("server started", "addr", listener.Addr().String(), "version", version.Version())

	// No Read/WriteTimeout: they would cut off large image downloads.
	httpServer := &http.Server{
		Handler:           app.Handler(),
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- httpServer.Serve(listener) }()
	scanFailed := startInitialScan(app)

	select {
	case err := <-serveErr:
		return fmt.Errorf("failed to start the server: %w", err)
	case <-scanFailed:
		logger.Warn("fatal error occurred, shutdown the server")
	case <-ctx.Done():
		logger.Info("received shutdown signal")
	}
	shutdownGracefully(httpServer, logger)
	return nil
}

// startInitialScan scans in the background so /healthz answers at once. The
// returned channel closes if the scan fails; RunInitialScan logs the cause.
func startInitialScan(app *server.App) <-chan struct{} {
	failed := make(chan struct{})
	go func() {
		if app.RunInitialScan() != nil {
			close(failed)
		}
	}()
	return failed
}

func shutdownGracefully(httpServer *http.Server, logger *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	err := httpServer.Shutdown(ctx)
	if err == nil {
		return
	}
	logger.Error("graceful shutdown failed, closing connections", "err", err)
	if closeErr := httpServer.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
		logger.Error("failed to close the server", "err", closeErr)
	}
}
