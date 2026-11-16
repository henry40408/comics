package assets

import "testing"

// Valid only for the asset bytes at port time (the ?v= the Rust binary
// rendered). Delete this test in the Rust cut-over (WP5) or when assets change.
const rustAssetsVersion = "c7db4b09d947f4e6"

func TestVersionMatchesRust(t *testing.T) {
	if got := Version(); got != rustAssetsVersion {
		t.Fatalf("Go computed %s, Rust rendered %s", got, rustAssetsVersion)
	}
}
