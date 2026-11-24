package e2e

import (
	"fmt"
	"slices"
	"strings"

	"github.com/cucumber/godog"

	"github.com/henry40408/comics/e2e/internal/harness"
)

// quoted matches a step argument in either quote style: login.feature uses
// single quotes around a value that holds double quotes.
const quoted = `("[^"]*"|'[^']*')`

// unquote strips the quotes a quoted argument arrived with.
func unquote(argument string) string {
	return argument[1 : len(argument)-1]
}

// registerSteps wires every step to the scenario. A step returns its failure;
// godog reports it against the step.
func registerSteps(sc *godog.ScenarioContext, w *world) {
	registerCommonSteps(sc, w)
	registerLoginSteps(sc, w)
	registerLibrarySteps(sc, w)
	registerReaderSteps(sc, w)
}

func registerCommonSteps(sc *godog.ScenarioContext, w *world) {
	sc.Step(`^I should see the library$`, w.shouldSeeTheLibrary)
	sc.Step(`^I should be on the login page$`, w.shouldBeOnTheLoginPage)
	sc.Step(`^I am logged in$`, w.loggedIn)
	sc.Step(`^I log out$`, w.logOut)
	sc.Step(`^I visit `+quoted+`$`, w.visit)
	sc.Step(`^I reload the page$`, w.reload)
	sc.Step(`^every image and asset on the page should be served$`, w.assetsServed)
	sc.Step(`^the page should show images$`, w.pageShowsImages)
	sc.Step(`^the page should have no inline script or style$`, w.noInlineCode)
	sc.Step(`^the page should have no element `+quoted+`$`, w.pageHasNoElement)
	sc.Step(`^the system prefers the `+quoted+` colour scheme$`, w.systemPrefers)
	sc.Step(`^the theme should be `+quoted+`$`, w.themeShouldBe)
	sc.Step(`^I press `+quoted+`$`, w.pressKey)
}

func (w *world) shouldSeeTheLibrary() error {
	b := w.browser
	if err := harness.EventuallyEq("url after signing in", "/", b.Path); err != nil {
		return err
	}
	// A card, not merely the route: a 503 during the initial scan is at / too.
	return harness.Eventually("a book card is on the page", func() (bool, error) {
		cards, err := b.Library().Cards()
		return len(cards) > 0, err
	})
}

func (w *world) shouldBeOnTheLoginPage() error {
	return harness.Eventually("url is the login page", func() (bool, error) {
		path, err := w.browser.Path()
		return strings.HasPrefix(path, "/login"), err
	})
}

func (w *world) loggedIn() error {
	login := w.browser.Login()
	if err := login.Goto(); err != nil {
		return err
	}
	if err := login.Login(harness.Username, harness.Password); err != nil {
		return err
	}
	return harness.EventuallyEq("url after signing in", "/", w.browser.Path)
}

func (w *world) logOut() error {
	return w.browser.Library().Logout()
}

func (w *world) visit(path string) error {
	return w.browser.Goto(unquote(path))
}

func (w *world) reload() error {
	return w.browser.Reload()
}

func (w *world) assetsServed() error {
	audit, err := w.browser.AuditResources()
	if err != nil {
		return err
	}
	if len(audit.Failed) > 0 {
		return fmt.Errorf("failed requests: %v", audit.Failed)
	}
	if len(audit.Undecodable) > 0 {
		return fmt.Errorf("undecodable images: %v", audit.Undecodable)
	}
	// No entries means no failures, so a page that dropped its tags would pass.
	for _, asset := range []string{"/assets/app.css", "/assets/app.js", "/assets/theme.js"} {
		if !slices.Contains(audit.Linked, asset) {
			return fmt.Errorf("the page never loaded %s: %v", asset, audit.Linked)
		}
	}
	return nil
}

func (w *world) pageShowsImages() error {
	audit, err := w.browser.AuditResources()
	if err != nil {
		return err
	}
	if audit.Images == 0 {
		return fmt.Errorf("the page has no <img>")
	}
	return nil
}

func (w *world) noInlineCode() error {
	count, err := w.browser.InlineCodeCount()
	if err != nil {
		return err
	}
	if count != 0 {
		return fmt.Errorf("%d inline <script>/<style> element(s)", count)
	}
	return nil
}

func (w *world) pageHasNoElement(css string) error {
	selector := unquote(css)
	found, err := w.browser.QueryAll(selector)
	if err != nil {
		return err
	}
	if len(found) > 0 {
		return fmt.Errorf("found %d element(s) for `%s`", len(found), selector)
	}
	return nil
}

func (w *world) systemPrefers(scheme string) error {
	return w.browser.EmulateColorScheme(unquote(scheme))
}

func (w *world) themeShouldBe(theme string) error {
	return harness.EventuallyEq("the theme", unquote(theme), w.browser.Theme)
}

func (w *world) pressKey(key string) error {
	return w.browser.Press(unquote(key))
}
