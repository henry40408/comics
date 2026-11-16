package e2e

import (
	"context"
	"fmt"
	"slices"

	"github.com/cucumber/godog"
	messages "github.com/cucumber/messages/go/v34"

	"github.com/henry40408/comics/e2e/internal/harness"
)

// world is the state shared by the steps of one scenario: one browser,
// opened by a Before hook rather than on first use, because only the hook
// sees the scenario's @nojs tag.
type world struct {
	browser *harness.Browser
}

// initializeScenario runs once per scenario, so every scenario gets its own
// world through the closure.
func initializeScenario(sc *godog.ScenarioContext) {
	w := &world{}
	sc.Before(w.openBrowser)
	sc.After(w.closeBrowser)
	registerSteps(sc, w)
}

func (w *world) openBrowser(ctx context.Context, scenario *godog.Scenario) (context.Context, error) {
	browser, err := harness.Open(scriptingFor(scenario))
	if err != nil {
		return ctx, fmt.Errorf("could not open a browser session: %w", err)
	}
	w.browser = browser
	return ctx, nil
}

// closeBrowser runs on every outcome, so a failed scenario leaves no Chrome.
func (w *world) closeBrowser(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
	if w.browser != nil {
		w.browser.Close()
		w.browser = nil
	}
	return ctx, nil
}

func scriptingFor(scenario *godog.Scenario) harness.Scripting {
	if hasTag(scenario, "@nojs") {
		return harness.ScriptingDisabled
	}
	return harness.ScriptingEnabled
}

func hasTag(scenario *godog.Scenario, name string) bool {
	return slices.ContainsFunc(scenario.Tags, func(tag *messages.PickleTag) bool {
		return tag.Name == name
	})
}

// browserOf is the scenario's browser, for steps that run after the hook.
func (w *world) browserOf() (*harness.Browser, error) {
	if w.browser == nil {
		return nil, fmt.Errorf("no browser session: the Before hook did not open one")
	}
	return w.browser, nil
}
