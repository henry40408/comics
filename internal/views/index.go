package views

import (
	"strconv"
	"time"

	"github.com/henry40408/comics/internal/models"
	"github.com/henry40408/comics/internal/version"
)

// IndexView is the data of the library page.
type IndexView struct {
	Books        []models.Book
	ScannedAt    time.Time
	ScanDuration time.Duration
	AuthEnabled  bool
}

// IndexPage renders the library page.
func IndexPage(view IndexView) string {
	title := strconv.Itoa(len(view.Books)) + " book(s) | " + titleSuffix()
	cards := make([]node, len(view.Books))
	for i, book := range view.Books {
		cards[i] = card(book, i+1)
	}
	body := el("body", []attr{a("class", "lib")},
		el("div", []attr{a("class", "layout")},
			sidebar(),
			el("main", nil,
				header(view),
				el("div", []attr{a("class", "rule")}),
				controls(view),
				el("div", []attr{a("class", "grid")}, cards...),
			),
		),
	)
	return document(title, defaultViewport, body)
}

func sidebar() node {
	return el("aside", nil,
		el("div", []attr{a("class", "mark")}),
		spine(),
		el("div", []attr{a("class", "asidebot")},
			themeButton("themebtn js-only"),
			el("div", []attr{a("class", "ver")}, text(version.Version())),
		),
	)
}

func header(view IndexView) node {
	scannedAt := view.ScannedAt.UTC()
	// HTML allows at most three fractional digits in a datetime, hence the
	// fixed millisecond layout.
	display := scannedAt.Format(time.RFC1123Z)
	iso := scannedAt.Format("2006-01-02T15:04:05.000Z")
	ms := float64(view.ScanDuration.Milliseconds())
	return el("div", []attr{a("class", "head")},
		el("h1", nil, text("Library"), el("span", []attr{a("class", "dot")}, text("."))),
		el("div", []attr{a("class", "stat")},
			el("div", nil, el("b", nil, text(strconv.Itoa(len(view.Books)))), text(" volume(s)")),
			el("div", nil,
				text("scanned "),
				el("time", []attr{flag("data-localtime"), a("datetime", iso)}, text(display)),
				text(" · "),
				el("time", []attr{a("datetime", "PT"+formatFloat(ms/1000)+"S")}, text(formatFloat(ms)+"ms")),
			),
		),
	)
}

// formatFloat is the shortest form, with no exponent.
func formatFloat(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

func controls(view IndexView) node {
	var logout node
	if view.AuthEnabled {
		logout = el("form", []attr{a("method", "POST"), a("action", "/logout")},
			el("button", []attr{a("class", "lbtn"), a("type", "submit"), a("data-testid", "logout")}, text("Logout")))
	}
	return el("div", []attr{a("class", "controls")},
		el("form", []attr{a("method", "POST"), a("action", "/rescan")},
			el("button", []attr{a("class", "lbtn"), a("type", "submit")}, text("Re-scan"))),
		el("form", []attr{a("method", "POST"), a("action", "/shuffle")},
			el("button", []attr{a("class", "lbtn key"), a("type", "submit")}, text("Shuffle"))),
		logout,
		el("span", []attr{a("class", "note")}, text("所蔵 "+strconv.Itoa(len(view.Books))+" 冊")),
	)
}

func card(book models.Book, number int) node {
	return el("a", []attr{a("class", "card"), a("href", "/book/"+book.ID), a("data-testid", "book-card")},
		el("div", []attr{a("class", "cover")},
			void("img", a("src", "/thumb/md/"+book.Cover.ID), a("alt", book.Title), a("loading", "lazy")),
			el("span", []attr{a("class", "idx")}, text(strconv.Itoa(number))),
		),
		el("div", []attr{a("class", "info")},
			el("div", []attr{a("class", "t"), a("data-testid", "book-title")}, text(book.Title)),
			el("div", []attr{a("class", "p")}, text(strconv.Itoa(len(book.Pages))+" pages")),
		),
	)
}
