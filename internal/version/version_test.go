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

func TestVersionIsNeverEmpty(t *testing.T) {
	if Version() == "" {
		t.Fatal("empty version")
	}
}
