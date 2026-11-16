package views

import (
	"github.com/henry40408/comics/internal/assets"
	"github.com/henry40408/comics/internal/version"
)

const (
	defaultViewport = "width=device-width, initial-scale=1"
	// Only the reader asks for viewport-fit=cover.
	readerViewport = "width=device-width, initial-scale=1, viewport-fit=cover"
)

// head is the <head> every page shares.
func head(title, viewport string) node {
	v := assets.Version()
	return el("head", nil,
		el("title", nil, text(title)),
		void("meta", a("charset", "UTF-8")),
		void("meta", a("name", "viewport"), a("content", viewport)),
		// Sets the theme before paint; not deferred, and not inline (see theme.js).
		el("script", []attr{a("src", "/assets/theme.js?v="+v)}),
		void("link", a("rel", "preconnect"), a("href", "https://fonts.bunny.net")),
		void("link", a("href", "https://fonts.bunny.net/css?family=hanken-grotesk:400,500,600|shippori-mincho:500,700"), a("rel", "stylesheet")),
		void("link", a("rel", "icon"), a("type", "image/svg+xml"), a("href", "/favicon.svg?v="+v)),
		void("link", a("rel", "icon"), a("type", "image/png"), a("sizes", "32x32"), a("href", "/favicon-32.png?v="+v)),
		void("link", a("rel", "apple-touch-icon"), a("href", "/apple-touch-icon.png?v="+v)),
		void("link", a("href", "/assets/app.css?v="+v), a("rel", "stylesheet")),
		el("script", []attr{a("src", "/assets/app.js?v="+v), flag("defer")}),
	)
}

// document is a full page: doctype, <html>, the shared head, then body.
func document(title, viewport string, body node) string {
	return string(group(
		node("<!DOCTYPE html>"),
		el("html", []attr{a("lang", "en")}, head(title, viewport), body),
	))
}

func titleSuffix() string { return "Comics " + version.Version() }

// themeButton is shown only with a script (.js-only). Its class is the one
// thing that differs between pages.
func themeButton(class string) node {
	return el("button", []attr{
		a("class", class), a("id", "theme"), a("type", "button"),
		a("title", "Toggle theme"), a("aria-label", "Toggle theme"),
	}, text("◐"))
}

// spine is the vertical wordmark shared by the sidebar and the login box.
func spine() node {
	return el("div", []attr{a("class", "spine")}, text("漫画書架"), el("span", []attr{a("class", "en")}, text("／ COMICS")))
}
