package version

import "testing"

func TestInjectedVersionWins(t *testing.T) {
	t.Cleanup(func() { version = "" })
	version = "v1.2.3"
	if got := Version(); got != "v1.2.3" {
		t.Fatalf("got %q", got)
	}
}

func TestDevIsTreatedAsUnset(t *testing.T) {
	t.Cleanup(func() { version = "" })
	version = "dev"
	if got := Version(); got == "dev" || got == "" {
		t.Fatalf("got %q", got)
	}
}

// A test binary has no module version ("" or "(devel)"); neither may leak out.
func TestAnEmptyOrDevelModuleVersionFallsBackToUnknown(t *testing.T) {
	t.Cleanup(func() { version = "" })
	version = ""
	if got := Version(); got != "unknown" {
		t.Fatalf("got %q, want unknown", got)
	}
}

func TestVersionIsNeverEmpty(t *testing.T) {
	if Version() == "" {
		t.Fatal("empty version")
	}
}
