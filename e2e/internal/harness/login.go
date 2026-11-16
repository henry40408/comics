package harness

// LoginPage is the login page (/login).
type LoginPage struct {
	browser *Browser
}

// Login returns the login page object for the browser.
func (b *Browser) Login() LoginPage {
	return LoginPage{browser: b}
}

// Goto navigates to /login.
func (p LoginPage) Goto() error {
	return p.browser.Goto("/login")
}

// Login fills the form and submits it with a single plain native click.
func (p LoginPage) Login(username, password string) error {
	if err := p.typeInto(TestID("login-username"), username); err != nil {
		return err
	}
	if err := p.typeInto(TestID("login-password"), password); err != nil {
		return err
	}
	submit, err := p.browser.Query(TestID("login-submit"))
	if err != nil {
		return err
	}
	return submit.Click()
}

func (p LoginPage) typeInto(selector, text string) error {
	field, err := p.browser.Query(selector)
	if err != nil {
		return err
	}
	return field.Type(text)
}

// Error is the "wrong credentials" banner, nil when the page shows none.
func (p LoginPage) Error() (*Element, error) {
	return p.browser.Optional(TestID("login-error"))
}

// NextTarget is where the form sends you after signing in: the hidden next
// field.
func (p LoginPage) NextTarget() (string, error) {
	field, err := p.browser.Query("input[name=next]")
	if err != nil {
		return "", err
	}
	return field.Value()
}

// FocusedTestID is the data-testid of the focused element, empty when nothing
// is focused.
func (p LoginPage) FocusedTestID() (string, error) {
	return Eval[string](p.browser, "document.activeElement?.getAttribute('data-testid') ?? ''")
}
