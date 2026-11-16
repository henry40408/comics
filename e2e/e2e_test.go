package e2e

import (
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/cucumber/godog"

	"github.com/henry40408/comics/e2e/internal/harness"
)

// ConcurrencyCeiling is the most scenarios, and so browsers, to run at once,
// whatever the machine.
//
// More browsers than cores makes pages settle slower than the steps wait. The
// login rate limiter (5 per IP per 60 s, all from 127.0.0.1) is not a
// constraint: a successful login refunds its slot.
const ConcurrencyCeiling = 4

const defaultFeatures = "features"

// pass is one godog run over a set of scenarios.
type pass struct {
	name        string
	tags        string
	concurrency int
}

// TestE2E is the suite.
//
//   - @nojs: the Before hook opens that scenario's browser with scripting
//     disabled.
//   - @logout: POST /logout ends every live session, so it would sign
//     concurrent scenarios out mid-run.
//   - @rescan: swaps the scan every other scenario reads.
//
// The last two get a second pass of their own, one scenario at a time.
func TestE2E(t *testing.T) {
	server, err := harness.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Stop()

	if err := preflight(); err != nil {
		t.Fatal(err)
	}

	passes := []pass{
		{name: "shared", tags: "~@logout && ~@rescan", concurrency: min(runtime.NumCPU(), ConcurrencyCeiling)},
		// One at a time: each of these disturbs every other live session.
		{name: "exclusive", tags: "@logout,@rescan", concurrency: 1},
	}
	// Both passes run before either can fail the test.
	for _, p := range passes {
		if status := run(p); status != 0 {
			t.Errorf("pass %q failed with status %d", p.name, status)
		}
	}
}

// preflight opens and closes one browser, so a missing Chromium gives one
// clear error rather than one per scenario.
func preflight() error {
	browser, err := harness.Open(harness.ScriptingEnabled)
	if err != nil {
		return err
	}
	browser.Close()
	return nil
}

func run(p pass) int {
	suite := godog.TestSuite{
		Name:                p.name,
		ScenarioInitializer: initializeScenario,
		Options: &godog.Options{
			Format:      "pretty",
			Output:      os.Stdout,
			Paths:       featurePaths(),
			Tags:        p.tags,
			Concurrency: p.concurrency,
			// Undefined and pending steps fail rather than skip.
			Strict: true,
		},
	}
	return suite.Run()
}

// featurePaths is E2E_FEATURES, a comma-separated list of feature paths, for
// running one file locally. It defaults to every feature.
func featurePaths() []string {
	value := os.Getenv("E2E_FEATURES")
	if value == "" {
		return []string{defaultFeatures}
	}
	return strings.Split(value, ",")
}
