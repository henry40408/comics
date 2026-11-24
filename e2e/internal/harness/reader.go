package harness

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// ReaderPage is the reader (/book/{id}).
type ReaderPage struct {
	browser *Browser
}

// Reader returns the reader page object for the browser.
func (b *Browser) Reader() ReaderPage {
	return ReaderPage{browser: b}
}

// CurrentPage is the topbar's live page number: script-written, and hidden
// without one. Nil when the page has none.
func (p ReaderPage) CurrentPage() (*Element, error) {
	return p.optionalAfterLoad(TestID("reader-current"))
}

// CurrentPageText is CurrentPage's text, empty without the element.
func (p ReaderPage) CurrentPageText() (string, error) {
	element, err := p.CurrentPage()
	if err != nil || element == nil {
		return "", err
	}
	return element.Text()
}

// optionalAfterLoad finds the element matching the CSS selector once the page
// has loaded. Nil when absent.
func (p ReaderPage) optionalAfterLoad(selector string) (*Element, error) {
	if err := p.browser.WaitForLoad(); err != nil {
		return nil, err
	}
	return p.browser.Optional(selector)
}

// Advance clicks the "next page" zone, and confirms the page turned.
func (p ReaderPage) Advance() error {
	return p.turnPage("the next-page zone", "reader-next")
}

// GoBack clicks the "previous page" zone, and confirms the page turned.
func (p ReaderPage) GoBack() error {
	return p.turnPage("the previous-page zone", "reader-prev")
}

func (p ReaderPage) turnPage(what, testid string) error {
	b := p.browser
	before, err := p.CurrentPageText()
	if err != nil {
		return err
	}
	return clickUntil(b, clickSpec{
		what:   what,
		locate: func() (*Element, error) { return b.Query(TestID(testid)) },
		tookEffect: func() (bool, error) {
			now, err := p.CurrentPageText()
			return now != before, err
		},
	})
}

// ArrowShown says whether the tap zone ("next" or "previous") is on screen; a
// zone past either end of the book is not offered.
func (p ReaderPage) ArrowShown(direction string) (bool, error) {
	testid, ok := map[string]string{"next": "reader-next", "previous": "reader-prev"}[direction]
	if !ok {
		return false, fmt.Errorf("unknown arrow direction %q", direction)
	}
	zone, err := p.browser.Query(TestID(testid))
	if err != nil {
		return false, err
	}
	return zone.Displayed()
}

// Title is the book title in the topbar.
func (p ReaderPage) Title() (string, error) {
	return pageText(p.browser, ".titleblock .t")
}

// HighlightedMode is the mode the segmented control highlights; empty when
// none is.
func (p ReaderPage) HighlightedMode() (string, error) {
	if err := p.browser.WaitForLoad(); err != nil {
		return "", err
	}
	highlighted, err := p.browser.Optional("#seg a.on")
	if err != nil || highlighted == nil {
		return "", err
	}
	mode, _, err := highlighted.Attr("data-m")
	return mode, err
}

// ProgressWidth is the progress bar's inline width, empty before a script
// sets it.
func (p ReaderPage) ProgressWidth() (string, error) {
	return Eval[string](p.browser, "document.getElementById('bar').style.width")
}

// FirstVisitHint is the flag the reader stores once the first-visit hint ran.
func (p ReaderPage) FirstVisitHint() (string, error) {
	if err := p.browser.WaitForLoad(); err != nil {
		return "", err
	}
	flag, err := Eval[*string](p.browser, "localStorage.getItem('comics-reader-hinted')")
	if err != nil || flag == nil {
		return "", err
	}
	return *flag, nil
}

// GoHome clicks the "←" link, and confirms it reached the library.
func (p ReaderPage) GoHome() error {
	b := p.browser
	return clickUntil(b, clickSpec{
		what:   "the back link",
		locate: func() (*Element, error) { return b.Query("a.back") },
		tookEffect: func() (bool, error) {
			path, err := b.Path()
			return path == "/", err
		},
	})
}

// Shuffle presses the topbar's "Shuffle", and confirms it opened another book.
func (p ReaderPage) Shuffle() error {
	b := p.browser
	before, err := b.URL()
	if err != nil {
		return err
	}
	return clickUntil(b, clickSpec{
		what:   "the reader's Shuffle button",
		locate: func() (*Element, error) { return b.Query(`form[action^="/shuffle/"] button`) },
		tookEffect: func() (bool, error) {
			now, err := b.URL()
			if err != nil {
				return false, err
			}
			return now.String() != before.String(), nil
		},
	})
}

// SetScrollMode clicks the shared segmented control's "scroll" half, and
// confirms the reader switched.
func (p ReaderPage) SetScrollMode() error {
	b := p.browser
	return clickUntil(b, clickSpec{
		what:   "the segmented control's scroll half",
		locate: func() (*Element, error) { return b.Query(TestID("reader-mode-scroll")) },
		tookEffect: func() (bool, error) {
			mode, err := p.Mode()
			return mode == "scroll", err
		},
	})
}

// IsShowing reports whether this is the reader's own <body class="reader">.
func (p ReaderPage) IsShowing() (bool, error) {
	found, err := p.browser.Optional("body.reader")
	return found != nil, err
}

// Mode is what the reader stores on <body data-mode="…">.
func (p ReaderPage) Mode() (string, error) {
	if err := p.browser.WaitForLoad(); err != nil {
		return "", err
	}
	body, err := p.browser.Query("body")
	if err != nil {
		return "", err
	}
	mode, present, err := body.Attr("data-mode")
	if err != nil {
		return "", err
	}
	if !present {
		return "", errors.New("<body> has no data-mode")
	}
	return mode, nil
}

// ReloadInMode opens the current book with ?mode=… and no fragment.
func (p ReaderPage) ReloadInMode(mode string) error {
	current, err := p.browser.URL()
	if err != nil {
		return err
	}
	current.RawQuery = "mode=" + mode
	current.Fragment = ""
	return p.browser.Goto(current.RequestURI())
}

// Page is the page container with the given 1-based number.
func (p ReaderPage) Page(n string) (*Element, error) {
	if err := p.browser.WaitForLoad(); err != nil {
		return nil, err
	}
	return p.browser.Query(pageSelector(n))
}

func pageSelector(n string) string {
	return "[id=" + jsLiteral("p"+n) + "]"
}

// VisiblePages is the .pg elements the browser is actually displaying.
func (p ReaderPage) VisiblePages() ([]*Element, error) {
	pages, err := p.browser.QueryAll(".pg")
	if err != nil {
		return nil, err
	}
	visible := make([]*Element, 0, len(pages))
	for _, page := range pages {
		shown, err := page.Displayed()
		if err != nil {
			return nil, err
		}
		if shown {
			visible = append(visible, page)
		}
	}
	return visible, nil
}

// DisplayedPageIDs is the ids of the displayed .pg elements, in document
// order.
func (p ReaderPage) DisplayedPageIDs() ([]string, error) {
	pages, err := p.VisiblePages()
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(pages))
	for _, page := range pages {
		id, present, err := page.Attr("id")
		if err != nil {
			return nil, err
		}
		if present {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// FollowNext clicks the script-less "next page" anchor on the displayed page.
func (p ReaderPage) FollowNext() error {
	return p.clickOnVisiblePage("the next-page link", ".nojs-next")
}

// FollowPrevious clicks the script-less "previous page" anchor on the
// displayed page.
func (p ReaderPage) FollowPrevious() error {
	return p.clickOnVisiblePage("the previous-page link", ".nojs-prev")
}

func (p ReaderPage) clickOnVisiblePage(what, selector string) error {
	before, err := p.DisplayedPageIDs()
	if err != nil {
		return err
	}
	return clickUntil(p.browser, clickSpec{
		what:   what,
		locate: func() (*Element, error) { return p.elementOnVisiblePage(selector) },
		tookEffect: func() (bool, error) {
			now, err := p.DisplayedPageIDs()
			return !slices.Equal(now, before), err
		},
	})
}

func (p ReaderPage) elementOnVisiblePage(selector string) (*Element, error) {
	pages, err := p.VisiblePages()
	if err != nil {
		return nil, err
	}
	for _, page := range pages {
		found, err := page.FindOptional(selector)
		if err != nil {
			return nil, err
		}
		if found != nil {
			return found, nil
		}
	}
	return nil, fmt.Errorf("no displayed `.pg` carries `%s`", selector)
}

// JumpFromRail clicks the rail's anchor for page n. With scripting on, app.js
// cancels the jump and animates instead, so this covers both paths.
func (p ReaderPage) JumpFromRail(n string) error {
	b := p.browser
	return clickUntil(b, clickSpec{
		what:   fmt.Sprintf("the rail's anchor for page %s", n),
		locate: func() (*Element, error) { return b.Query(".thumbs a[href=" + jsLiteral("#p"+n) + "]") },
		// Either path's proof will do: `:target` leaves page n the only one
		// displayed, app.js writes n into the topbar. Requiring both would
		// fail whichever path is not in play.
		tookEffect: func() (bool, error) {
			ids, err := p.DisplayedPageIDs()
			if err != nil {
				return false, err
			}
			if slices.Equal(ids, []string{"p" + n}) {
				return true, nil
			}
			text, err := p.CurrentPageText()
			return strings.TrimSpace(text) == n, err
		},
	})
}

// CounterText is the per-page counter on the displayed page ("3 / 3").
func (p ReaderPage) CounterText() (string, error) {
	counter, err := p.elementOnVisiblePage(".nojs-counter")
	if err != nil {
		return "", err
	}
	return counter.Text()
}

// ThemeToggle is the theme toggle, which only a script can operate. Nil when
// absent.
func (p ReaderPage) ThemeToggle() (*Element, error) {
	return p.optionalAfterLoad("#theme")
}

// SharedModeControl is the shared segmented control, which cannot carry your
// place across a script-less mode switch and so is hidden without a script.
// Nil when absent.
func (p ReaderPage) SharedModeControl() (*Element, error) {
	return p.optionalAfterLoad("#seg")
}

// SwitchModeFrom clicks page n's own mode switch, which carries that page's
// anchor across the change, and confirms the mode changed.
func (p ReaderPage) SwitchModeFrom(n string) error {
	b := p.browser
	before, err := p.Mode()
	if err != nil {
		return err
	}
	return clickUntil(b, clickSpec{
		what:   fmt.Sprintf("page %s's mode switch", n),
		locate: func() (*Element, error) { return b.Query(pageSelector(n) + " .nojs-mode") },
		tookEffect: func() (bool, error) {
			mode, err := p.Mode()
			return mode != before, err
		},
	})
}

// TopbarSubtitle is the topbar's subtitle as rendered text: a display:none
// counter inside it does not contribute.
func (p ReaderPage) TopbarSubtitle() (string, error) {
	return pageText(p.browser, ".titleblock .s")
}
