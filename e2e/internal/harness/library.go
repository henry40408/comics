package harness

// LibraryPage is the library (/).
type LibraryPage struct {
	browser *Browser
}

// Library returns the library page object for the browser.
func (b *Browser) Library() LibraryPage {
	return LibraryPage{browser: b}
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
