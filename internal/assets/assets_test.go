package assets

import (
	"strings"
	"testing"
)

func TestVersionIsStableAndSixteenHexCharacters(t *testing.T) {
	first, second := Version(), Version()
	if first != second {
		t.Fatal("version changed between calls")
	}
	if len(Version()) != 16 || strings.Trim(Version(), "0123456789abcdef") != "" {
		t.Fatalf("version %q is not 16 lowercase hex characters", Version())
	}
}

func TestEmbeddedFilesAreNotEmpty(t *testing.T) {
	texts := map[string]string{"app.css": AppCSS, "app.js": AppJS, "theme.js": ThemeJS, "favicon.svg": FaviconSVG}
	for name, text := range texts {
		if text == "" {
			t.Errorf("%s is empty", name)
		}
	}
	for name, data := range map[string][]byte{"favicon-32.png": FaviconPNG, "apple-touch-icon.png": AppleTouchIconPNG} {
		if !strings.HasPrefix(string(data), "\x89PNG") {
			t.Errorf("%s is not a PNG", name)
		}
	}
}
