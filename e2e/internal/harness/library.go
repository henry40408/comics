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

func pathStartsWith(b *Browser, prefix string) (bool, error) {
	path, err := b.Path()
	return strings.HasPrefix(path, prefix), err
}
