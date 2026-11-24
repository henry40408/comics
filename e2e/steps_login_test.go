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
	return w.browser.Login().Goto()
}

func (w *world) signIn(username, password string) error {
	return w.browser.Login().Login(unquote(username), unquote(password))
}

func (w *world) shouldSeeTheLoginError() error {
	return harness.Eventually("the login error is showing", func() (bool, error) {
		banner, err := w.browser.Login().Error()
		if err != nil || banner == nil {
			return false, err
		}
		return banner.Displayed()
	})
}

func (w *world) shouldBeAt(expected string) error {
	return harness.EventuallyEq("path and query", unquote(expected), w.browser.PathAndQuery)
}

func (w *world) loginFormRemembers(expected string) error {
	return harness.EventuallyEq("the login form's next target", unquote(expected), w.browser.Login().NextTarget)
}

func (w *world) usernameFieldFocused() error {
	return harness.EventuallyEq("the focused field", "login-username", w.browser.Login().FocusedTestID)
}
