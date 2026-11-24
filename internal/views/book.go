package views

import (
	"strconv"

	"github.com/henry40408/comics/internal/models"
)

// Mode is the reader's layout.
type Mode string

const (
	ModePaged  Mode = "paged"
	ModeScroll Mode = "scroll"
)

// ParseMode maps the `mode` query value to a Mode. Anything unknown is the
// default, not an error.
func ParseMode(value string) Mode {
	if value == string(ModeScroll) {
		return ModeScroll
	}
	return ModePaged
}

// BookView is the data of the reader page.
type BookView struct {
	Book        models.Book
	AuthEnabled bool
	Mode        Mode
}

// BookPage renders the reader page.
func BookPage(view BookView) string {
	book := view.Book
	title := book.Title + " (" + strconv.Itoa(len(book.Pages)) + "P) | " + titleSuffix()
	figures := make([]node, len(book.Pages))
	for i, page := range book.Pages {
		figures[i] = figure(view, page, i+1)
	}
	body := el("body", []attr{a("class", "reader"), a("data-mode", string(view.Mode))},
		topbar(view),
		el("div", []attr{a("class", "viewer")},
			el("div", []attr{a("class", "zone next"), a("id", "next"), a("title", "Next"), a("data-testid", "reader-next")}, el("span", nil)),
			el("div", []attr{a("class", "zone prev"), a("id", "prev"), a("title", "Previous"), a("data-testid", "reader-prev")}, el("span", nil)),
			el("div", []attr{a("class", "pages"), a("id", "pages")}, figures...),
		),
		rail(book),
	)
	return document(title, readerViewport, body)
}

func topbar(view BookView) node {
	book := view.Book
	var logout node
	if view.AuthEnabled {
		logout = el("form", []attr{a("method", "POST"), a("action", "/logout")},
			el("button", []attr{a("class", "tbtn"), a("type", "submit"), a("data-testid", "logout")}, text("Logout")))
	}
	return el("div", []attr{a("class", "topbar")},
		el("a", []attr{a("class", "back"), a("href", "/"), a("title", "Home"), a("aria-label", "Home")}, text("←")),
		el("div", []attr{a("class", "titleblock")},
			el("div", []attr{a("class", "t")}, text(book.Title)),
			// The live number is script-written, so it is hidden without a script;
			// nojs-counter states the page instead.
			el("div", []attr{a("class", "s")},
				el("span", []attr{a("class", "js-only")},
					el("b", []attr{a("id", "cur"), a("data-testid", "reader-current")}, text("1")), text(" / ")),
				text(strconv.Itoa(len(book.Pages))+" ページ"),
			),
		),
		el("span", []attr{a("class", "grow")}),
		// Links, so the mode works without JavaScript; app.js switches in place.
		el("div", []attr{a("class", "seg"), a("id", "seg")},
			modeLink(view.Mode, ModePaged, "⇄ 翻頁"),
			modeLink(view.Mode, ModeScroll, "↕ 捲動"),
		),
		themeButton("iconbtn js-only"),
		el("form", []attr{a("method", "POST"), a("action", "/shuffle/"+book.ID)},
			el("button", []attr{a("class", "tbtn"), a("type", "submit")}, text("Shuffle"))),
		logout,
	)
}

func modeLink(current, target Mode, label string) node {
	class := ""
	if current == target {
		class = "on"
	}
	return el("a", []attr{
		a("href", "?mode="+string(target)), a("data-m", string(target)), a("class", class),
		a("data-testid", "reader-mode-"+string(target)),
	}, text(label))
}

// figure is one page of the book. number is 1-based, like the ids and anchors.
func figure(view BookView, page models.Page, number int) node {
	total := len(view.Book.Pages)
	// Server-rendered is-current, so page 1 shows without JavaScript.
	class := "pg"
	if number == 1 {
		class = "pg is-current"
	}
	return el("figure", []attr{a("class", class), a("id", "p"+strconv.Itoa(number))},
		void("img", a("src", "/data/"+page.ID), a("alt", page.Filename), a("loading", "lazy")),
		pageNav(view.Mode, number, total),
	)
}

// pageNav is the script-less paging, per page because the shared tap zones
// cannot know the current page; :target picks the one to show. Right-to-left
// like the zones: next sits on the left.
func pageNav(mode Mode, number, total int) node {
	var next, prev node
	if number != total {
		next = el("a", []attr{a("class", "nojs-next"), a("href", "#p"+strconv.Itoa(number+1)), a("rel", "next"), a("aria-label", "Next page")}, text("‹"))
	}
	if number != 1 {
		prev = el("a", []attr{a("class", "nojs-prev"), a("href", "#p"+strconv.Itoa(number-1)), a("rel", "prev"), a("aria-label", "Previous page")}, text("›"))
	}
	return el("nav", []attr{a("class", "nojs")},
		next, prev,
		el("span", []attr{a("class", "nojs-counter")}, text(strconv.Itoa(number)+" / "+strconv.Itoa(total))),
		nojsModeLink(mode, number),
	)
}

// nojsModeLink is per page, so switching keeps your place; the only link in
// the nav that shows in scroll mode.
func nojsModeLink(mode Mode, number int) node {
	anchor := "#p" + strconv.Itoa(number)
	if mode == ModePaged {
		return el("a", []attr{a("class", "nojs-mode"), a("href", "?mode=scroll"+anchor)}, text("↕ 捲動"))
	}
	return el("a", []attr{a("class", "nojs-mode"), a("href", "?mode=paged"+anchor)}, text("⇄ 翻頁"))
}

func rail(book models.Book) node {
	links := make([]node, len(book.Pages))
	for i, page := range book.Pages {
		n := strconv.Itoa(i + 1)
		// A link, so the rail works without a script; app.js animates instead.
		links[i] = el("a", []attr{a("href", "#p"+n), a("title", "第"+n+"頁")},
			void("img", a("src", "/thumb/sm/"+page.ID), a("alt", ""), a("loading", "lazy")))
	}
	return el("div", []attr{a("class", "rail")},
		el("span", []attr{a("class", "counter")}, el("b", []attr{a("id", "cur2")}, text("1")), text(" / "+strconv.Itoa(len(book.Pages)))),
		el("div", []attr{a("class", "progress")}, el("i", []attr{a("id", "bar")})),
		el("div", []attr{a("class", "thumbs"), a("id", "thumbs")}, links...),
	)
}
