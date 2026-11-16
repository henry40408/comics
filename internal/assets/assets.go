// Package assets embeds the hand-written front-end files.
package assets

import (
	"embed"
	"strconv"

	"github.com/zeebo/xxh3"
)

//go:embed static/app.css static/app.js static/theme.js static/favicon.svg static/favicon-32.png static/apple-touch-icon.png
var files embed.FS

var (
	// AppCSS is the stylesheet.
	AppCSS = readText("app.css")
	// AppJS is the deferred front-end script.
	AppJS = readText("app.js")
	// ThemeJS is the pre-paint snippet: it runs synchronously in <head>, unlike
	// the deferred AppJS, and is a file rather than inline so the CSP needs no
	// 'unsafe-inline'.
	ThemeJS = readText("theme.js")
	// FaviconSVG is the SVG favicon.
	FaviconSVG = readText("favicon.svg")
	// FaviconPNG is the raster fallback for browsers that will not take the SVG.
	FaviconPNG = read("favicon-32.png")
	// AppleTouchIconPNG is separate from the favicon because iOS does not
	// accept SVG for the home screen.
	AppleTouchIconPNG = read("apple-touch-icon.png")

	version = computeVersion()
)

func read(name string) []byte {
	data, err := files.ReadFile("static/" + name)
	if err != nil {
		panic("assets: embedded file missing: " + err.Error())
	}
	return data
}

func readText(name string) string { return string(read(name)) }

// computeVersion hashes every embedded asset in a fixed order. It is a pure
// function of the embedded bytes, so computing it once at init is safe.
func computeVersion() string {
	hasher := xxh3.New()
	for _, asset := range [][]byte{[]byte(AppCSS), []byte(AppJS), []byte(ThemeJS), []byte(FaviconSVG), FaviconPNG, AppleTouchIconPNG} {
		_, _ = hasher.Write(asset)
	}
	return strconv.FormatUint(hasher.Sum64(), 16)
}

// Version is appended to asset URLs as ?v= so they can be served immutable.
func Version() string { return version }
