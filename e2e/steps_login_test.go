package e2e

import (
	"github.com/cucumber/godog"

	"github.com/henry40408/comics/e2e/internal/harness"
)

func registerLoginSteps(sc *godog.ScenarioContext, w *world) {
	sc.Step(`^I am on the login page$`, w.onTheLoginPage)
	sc.Step(`^I sign in with username `+quoted+` and password `+quoted+`$`, w.signIn)
	sc.Step(`^I should see the login error$`, w.shouldSeeTheLoginError)
	sc.Step(`^I should be at `+quoted+`$`, w.shouldBeAt)
	sc.Step(`^the login form should remember `+quoted+`$`, w.loginFormRemembers)
	sc.Step(`^the username field should be focused$`, w.usernameFieldFocused)
}

func (w *world) onTheLoginPage() error {
	b, err := w.browserOf()
	if err != nil {
		return err
	}
	return b.Login().Goto()
}

func (w *world) signIn(username, password string) error {
	b, err := w.browserOf()
	if err != nil {
		return err
	}
	return b.Login().Login(unquote(username), unquote(password))
}

func (w *world) shouldSeeTheLoginError() error {
	b, err := w.browserOf()
	if err != nil {
		return err
	}
	return harness.Eventually("the login error is showing", func() (bool, error) {
		banner, err := b.Login().Error()
		if err != nil || banner == nil {
			return false, err
		}
		return banner.Displayed()
	})
}

func (w *world) shouldBeAt(expected string) error {
	b, err := w.browserOf()
	if err != nil {
		return err
	}
	return harness.EventuallyEq("path and query", unquote(expected), b.PathAndQuery)
}

func (w *world) loginFormRemembers(expected string) error {
	b, err := w.browserOf()
	if err != nil {
		return err
	}
	return harness.EventuallyEq("the login form's next target", unquote(expected), b.Login().NextTarget)
}

func (w *world) usernameFieldFocused() error {
	b, err := w.browserOf()
	if err != nil {
		return err
	}
	return harness.EventuallyEq("the focused field", "login-username", b.Login().FocusedTestID)
}
