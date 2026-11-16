package e2e

import (
	"fmt"

	"github.com/cucumber/godog"

	"github.com/henry40408/comics/e2e/internal/harness"
)

// registerSteps wires every step to the scenario. The smoke steps below only
// prove the harness; they are replaced by the real step files.
func registerSteps(sc *godog.ScenarioContext, w *world) {
	sc.Step(`^smoke: I visit "([^"]*)"$`, w.smokeVisit)
	sc.Step(`^smoke: the page is (scripted|not scripted)$`, w.smokeScripting)
	sc.Step(`^smoke: I sign in and out$`, w.smokeSignInAndOut)
}

func (w *world) smokeVisit(path string) error {
	browser, err := w.browserOf()
	if err != nil {
		return err
	}
	return browser.Goto(path)
}

func (w *world) smokeScripting(want string) error {
	browser, err := w.browserOf()
	if err != nil {
		return err
	}
	hasJS, err := harness.Eval[bool](browser, "document.documentElement.classList.contains('js')")
	if err != nil {
		return err
	}
	if hasJS != (want == "scripted") {
		return fmt.Errorf("page is %s, but the js class is %v", want, hasJS)
	}
	return nil
}

func (w *world) smokeSignInAndOut() error {
	browser, err := w.browserOf()
	if err != nil {
		return err
	}
	if err := browser.Login().Login(harness.Username, harness.Password); err != nil {
		return err
	}
	err = harness.EventuallyEq("the path after sign-in", "/", browser.Path)
	if err != nil {
		return err
	}
	return browser.Library().Logout()
}
