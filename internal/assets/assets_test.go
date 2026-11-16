package assets

import (
	"strings"
	"testing"
)

func TestVersionIsStableAndHex(t *testing.T) {
	if Version() != Version() {
		t.Fatal("version changed between calls")
	}
	if Version() == "" || strings.Trim(Version(), "0123456789abcdef") != "" {
		t.Fatalf("version %q is not lowercase hex", Version())
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
