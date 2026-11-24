// Package assets embeds the hand-written front-end files.
package assets

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
)

var (
	// AppCSS is the stylesheet.
	//
	//go:embed static/app.css
	AppCSS string
	// AppJS is the deferred front-end script.
	//
	//go:embed static/app.js
	AppJS string
	// ThemeJS is the pre-paint snippet: it runs synchronously in <head>, unlike
	// the deferred AppJS, and is a file rather than inline so the CSP needs no
	// 'unsafe-inline'.
	//
	//go:embed static/theme.js
	ThemeJS string
	// FaviconSVG is the SVG favicon.
	//
	//go:embed static/favicon.svg
	FaviconSVG string
	// FaviconPNG is the raster fallback for browsers that will not take the SVG.
	//
	//go:embed static/favicon-32.png
	FaviconPNG []byte
	// AppleTouchIconPNG is separate from the favicon because iOS does not
	// accept SVG for the home screen.
	//
	//go:embed static/apple-touch-icon.png
	AppleTouchIconPNG []byte

	version = computeVersion()
)

// versionBytes is how much of the SHA-256 digest the version keeps: 16 hex
// characters are plenty to tell two builds' asset URLs apart.
const versionBytes = 8

// computeVersion hashes every embedded asset in a fixed order. It is a pure
// function of the embedded bytes, so computing it once at init is safe.
func computeVersion() string {
	hasher := sha256.New()
	for _, asset := range [][]byte{[]byte(AppCSS), []byte(AppJS), []byte(ThemeJS), []byte(FaviconSVG), FaviconPNG, AppleTouchIconPNG} {
		_, _ = hasher.Write(asset)
	}
	return hex.EncodeToString(hasher.Sum(nil)[:versionBytes])
}

// Version is appended to asset URLs as ?v= so they can be served immutable.
func Version() string { return version }
