// Command screenshots regenerates the images in docs/screenshots/, which
// README.md embeds.
//
// Run it with `go run ./cmd/screenshots` from e2e/. The -out flag writes
// somewhere else.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/henry40408/comics/e2e/internal/harness"
)

var themes = []string{"light", "dark"}

// fadeInSettle outlasts the thumbnails' fade-in transition.
const fadeInSettle = 300 * time.Millisecond

func main() {
	out := flag.String("out", defaultOutDir(), "directory the PNGs are written to")
	flag.Parse()

	if err := run(*out); err != nil {
		fmt.Fprintln(os.Stderr, "screenshots:", err)
		os.Exit(1)
	}
}

func run(out string) error {
	server, err := harness.Start()
	if err != nil {
		return err
	}
	defer server.Stop()

	if err := os.MkdirAll(out, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", out, err)
	}
	for _, theme := range themes {
		if err := capturePair(theme, out); err != nil {
			return fmt.Errorf("the %s pair: %w", theme, err)
		}
		fmt.Printf("wrote the %s pair\n", theme)
	}
	return nil
}

// capturePair takes the library and the reader in one theme.
//
// Each theme gets a fresh browser, so nothing in localStorage overrides the
// emulated prefers-color-scheme.
func capturePair(theme, out string) error {
	browser, err := harness.Open(harness.ScriptingEnabled)
	if err != nil {
		return err
	}
	defer browser.Close()

	if err := browser.EmulateColorScheme(theme); err != nil {
		return err
	}
	if err := logIn(browser); err != nil {
		return err
	}
	if err := browser.Library().Goto(); err != nil {
		return err
	}
	if err := capture(browser, filepath.Join(out, "library-"+theme+".png")); err != nil {
		return err
	}
	if err := openFirstBook(browser); err != nil {
		return err
	}
	return capture(browser, filepath.Join(out, "reader-"+theme+".png"))
}

func logIn(browser *harness.Browser) error {
	login := browser.Login()
	if err := login.Goto(); err != nil {
		return err
	}
	if err := login.Login(harness.Username, harness.Password); err != nil {
		return err
	}
	return harness.Eventually("the library to show a book card", func() (bool, error) {
		card, err := browser.Optional(harness.TestID("book-card"))
		return card != nil, err
	})
}

func openFirstBook(browser *harness.Browser) error {
	if err := browser.Library().OpenFirstBook(); err != nil {
		return err
	}
	return harness.Eventually("a page image to be displayed", func() (bool, error) {
		image, err := browser.Optional("#pages img")
		if err != nil || image == nil {
			return false, err
		}
		return image.Displayed()
	})
}

// capture takes a full-page screenshot.
//
// The viewport is stretched to the page first, and measured twice: the first
// stretch brings the lazy images into view, and loading them settles the
// final height.
func capture(browser *harness.Browser, path string) error {
	if err := stretchToPage(browser); err != nil {
		return err
	}
	if err := waitForImages(browser); err != nil {
		return err
	}
	if err := stretchToPage(browser); err != nil {
		return err
	}
	png, err := browser.Screenshot()
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, png, 0o644); err != nil {
		return err
	}
	return browser.ResetViewport()
}

func stretchToPage(browser *harness.Browser) error {
	height, err := harness.Eval[int64](browser, `Math.ceil(Math.max(
		document.body.scrollHeight, document.documentElement.scrollHeight))`)
	if err != nil {
		return fmt.Errorf("measuring the page height: %w", err)
	}
	return browser.StretchViewportTo(height)
}

// waitForImages waits for every rendered image to finish decoding; thumbnails
// are generated on demand, so a cold cache would otherwise show empty covers.
//
// Only rendered images count, with the viewport already stretched: every
// <img> is loading="lazy", and the reader's non-current pages are
// display: none, so their images never load.
func waitForImages(browser *harness.Browser) error {
	err := harness.Eventually("every rendered image has loaded", func() (bool, error) {
		return harness.Eval[bool](browser, `Array.from(document.images)
			.filter((i) => i.getClientRects().length > 0)
			.every((i) => i.complete && i.naturalWidth > 0)`)
	})
	if err != nil {
		return err
	}
	time.Sleep(fadeInSettle)
	return nil
}

// defaultOutDir is docs/screenshots/ at the repository root, found from this
// file's compile-time path so it works from any working directory.
func defaultOutDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "docs", "screenshots")
}
