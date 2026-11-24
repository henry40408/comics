package version

import "testing"

func TestInjectedVersionWins(t *testing.T) {
	t.Cleanup(func() { version = "" })
	version = "v1.2.3"
	if got := Version(); got != "v1.2.3" {
		t.Fatalf("got %q", got)
	}
}

// A test binary has no module version ("" or "(devel)"), so an unset or "dev"
// injected version falls through to "unknown".
func TestAnUnsetOrDevVersionFallsBackToUnknown(t *testing.T) {
	t.Cleanup(func() { version = "" })
	for _, injected := range []string{"", "dev"} {
		version = injected
		if got := Version(); got != "unknown" {
			t.Errorf("injected %q: got %q, want unknown", injected, got)
		}
	}
}
