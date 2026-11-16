package harness

import "strings"

// LibraryPage is the library (/).
type LibraryPage struct {
	browser *Browser
}

// Library returns the library page object for the browser.
func (b *Browser) Library() LibraryPage {
	return LibraryPage{browser: b}
}

// Goto navigates to the library.
func (p LibraryPage) Goto() error {
	return p.browser.Goto("/")
}

// Cards is every book card on the page.
func (p LibraryPage) Cards() ([]*Element, error) {
	return p.browser.QueryAll(TestID("book-card"))
}

// OpenFirstBook clicks the first book card, and confirms it opened a book.
func (p LibraryPage) OpenFirstBook() error {
	b := p.browser
	return clickUntil(b, clickSpec{
		what:       "the first book card",
		locate:     p.firstDisplayedCard,
		tookEffect: func() (bool, error) { return pathStartsWith(b, "/book/") },
	})
}

// firstDisplayedCard waits for a card a click can reach.
func (p LibraryPage) firstDisplayedCard() (*Element, error) {
	var card *Element
	err := Eventually("the first book card is clickable", func() (bool, error) {
		found, err := p.browser.Optional(TestID("book-card"))
		if err != nil || found == nil {
			return false, err
		}
		card = found
		return found.Displayed()
	})
	return card, err
}

// Logout submits the logout form, and confirms it reached the login page.
func (p LibraryPage) Logout() error {
	b := p.browser
	return clickUntil(b, clickSpec{
		what:   "the logout button",
		locate: func() (*Element, error) { return b.Query(TestID("logout")) },
		tookEffect: func() (bool, error) {
			path, err := b.Path()
			return path == "/login", err
		},
	})
}

// CardSummary is what a library card shows.
type CardSummary struct {
	Title    string
	Pages    string
	Index    string
	CoverAlt string
}

// CardSummaries reads title, page count, index and cover alt text of every
// card.
func (p LibraryPage) CardSummaries() ([]CardSummary, error) {
	cards, err := p.Cards()
	if err != nil {
		return nil, err
	}
	summaries := make([]CardSummary, 0, len(cards))
	for _, card := range cards {
		summary, err := summarise(card)
		if err != nil {
			return nil, err
		}
		summaries = append(summaries, summary)
	}
	return summaries, nil
}

func summarise(card *Element) (CardSummary, error) {
	title, err := textOf(card, TestID("book-title"))
	if err != nil {
		return CardSummary{}, err
	}
	pages, err := textOf(card, ".p")
	if err != nil {
		return CardSummary{}, err
	}
	index, err := textOf(card, ".idx")
	if err != nil {
		return CardSummary{}, err
	}
	cover, err := card.Find("img")
	if err != nil {
		return CardSummary{}, err
	}
	alt, _, err := cover.Attr("alt")
	if err != nil {
		return CardSummary{}, err
	}
	return CardSummary{Title: title, Pages: pages, Index: index, CoverAlt: alt}, nil
}

func textOf(scope *Element, selector string) (string, error) {
	found, err := scope.Find(selector)
	if err != nil {
		return "", err
	}
	return found.Text()
}

// VolumeCounts is the header's volume count and the note beside the buttons.
func (p LibraryPage) VolumeCounts() (header, note string, err error) {
	header, err = pageText(p.browser, ".stat b")
	if err != nil {
		return "", "", err
	}
	note, err = pageText(p.browser, ".note")
	return header, note, err
}

func pageText(b *Browser, selector string) (string, error) {
	found, err := b.Query(selector)
	if err != nil {
		return "", err
	}
	return found.Text()
}

// ScanTimes is the text of the <time> elements in the header.
func (p LibraryPage) ScanTimes() ([]string, error) {
	times, err := p.browser.QueryAll(".stat time")
	if err != nil {
		return nil, err
	}
	texts := make([]string, 0, len(times))
	for _, element := range times {
		text, err := element.Text()
		if err != nil {
			return nil, err
		}
		texts = append(texts, text)
	}
	return texts, nil
}

// Rescan presses "Re-scan", and confirms the redirect back to the library
// loaded a new document. The library is already at "/" before the click, so
// the path alone would pass with a dead button.
func (p LibraryPage) Rescan() error {
	b := p.browser
	before, err := b.DocumentID()
	if err != nil {
		return err
	}
	err = p.pressFormButton("the Re-scan button", "/rescan", func() (bool, error) {
		path, err := b.Path()
		if err != nil || path != "/" {
			return false, err
		}
		now, err := b.DocumentID()
		return now != before, err
	})
	if err != nil {
		return err
	}
	return b.WaitForLoad()
}

// Shuffle presses "Shuffle", and confirms it opened a book.
func (p LibraryPage) Shuffle() error {
	return p.pressFormButton("the Shuffle button", "/shuffle", func() (bool, error) {
		return pathStartsWith(p.browser, "/book/")
	})
}

func (p LibraryPage) pressFormButton(what, action string, tookEffect func() (bool, error)) error {
	b := p.browser
	return clickUntil(b, clickSpec{
		what: what,
		locate: func() (*Element, error) {
			return b.Query("form[action=" + jsLiteral(action) + "] button")
		},
		tookEffect: tookEffect,
	})
}

// ClickThemeToggle clicks the theme toggle, and confirms the theme differs
// from before.
func (b *Browser) ClickThemeToggle(before string) error {
	return clickUntil(b, clickSpec{
		what:   "the theme toggle",
		locate: func() (*Element, error) { return b.Query("#theme") },
		tookEffect: func() (bool, error) {
			theme, err := b.Theme()
			return theme != before, err
		},
	})
}

// Title is the document title.
func (b *Browser) Title() (string, error) {
	return Eval[string](b, "document.title")
}

func pathStartsWith(b *Browser, prefix string) (bool, error) {
	path, err := b.Path()
	return strings.HasPrefix(path, prefix), err
}
