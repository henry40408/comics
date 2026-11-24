package server

import (
	"fmt"
	"strings"
	"testing"

	"github.com/henry40408/comics/internal/assets"
)

// figures are the <figure ...> fragments of a rendered book, each up to its
// closing tag.
func figures(t *testing.T, html string) []string {
	t.Helper()
	parts := strings.Split(html, "<figure")[1:]
	for i, part := range parts {
		before, _, found := strings.Cut(part, "</figure>")
		if !found {
			t.Fatal("an unclosed <figure>")
		}
		parts[i] = before
	}
	return parts
}

func bookHTML(ta *testApp, query string) string {
	return ta.get("/book/" + dataIDs[0] + query).text()
}

// The topbar switch would lose the page without a script, so each page carries
// its own.
func TestSwitchingModeWithoutJavaScriptKeepsThePage(t *testing.T) {
	ta := newTestApp(t)
	for query, target := range map[string]string{"?mode=paged": "scroll", "?mode=scroll": "paged"} {
		frags := figures(t, bookHTML(ta, query))
		if len(frags) <= 2 {
			t.Fatal("the fixture book needs several pages")
		}
		for i, page := range frags {
			link := fmt.Sprintf(`href="?mode=%s#p%d"`, target, i+1)
			if !strings.Contains(page, link) {
				t.Errorf("page %d in %s lacks %s: %s", i+1, query, link, page)
			}
		}
	}
}

// Checked on every template with a theme toggle, not just the reader.
func TestScriptOnlyControlsAreHiddenWithoutJavaScript(t *testing.T) {
	ta := newTestApp(t)
	pages := map[string]string{
		"/":      ta.get("/").text(),
		"/book":  bookHTML(ta, ""),
		"/login": newAuthApp(t).get("/login").text(),
	}
	for what, html := range pages {
		before, _, found := strings.Cut(html, `id="theme"`)
		if !found {
			t.Fatalf("%s: no theme toggle", what)
		}
		toggle := before[strings.LastIndex(before, "<"):]
		if !strings.Contains(toggle, "js-only") {
			t.Errorf("%s: toggle is not js-only: %s", what, toggle)
		}
	}

	// The topbar keeps its total; only the live page number is hidden.
	_, afterS, found := strings.Cut(bookHTML(ta, ""), `class="s"`)
	if !found {
		t.Fatal("no topbar counter")
	}
	titleblock, _, _ := strings.Cut(afterS, "</div>")
	_, live, found := strings.Cut(titleblock, "<span")
	if !found {
		t.Fatal("no script-driven half")
	}
	if !strings.Contains(live, "js-only") || !strings.Contains(live, `id="cur"`) {
		t.Errorf("live counter not hidden: %s", titleblock)
	}
	if !strings.Contains(titleblock, "ページ") {
		t.Error("the total went missing")
	}
	if !strings.Contains(assets.AppCSS, "html:not(.js) .js-only") {
		t.Error("app.css does not hide .js-only without JS")
	}
}

// An unrecognised mode renders the default rather than a 400.
func TestTheReaderModeIsServerRendered(t *testing.T) {
	ta := newTestApp(t)
	for query, expected := range map[string]string{
		"": "paged", "?mode=paged": "paged", "?mode=scroll": "scroll", "?mode=nonsense": "paged",
	} {
		res := ta.get("/book/" + dataIDs[0] + query)
		assertStatus(t, 200, res, "GET /book/…"+query)
		html := res.text()
		if !strings.Contains(html, fmt.Sprintf(`data-mode="%s"`, expected)) {
			t.Errorf("%q did not render %s", query, expected)
		}

		_, afterSeg, found := strings.Cut(html, `class="seg"`)
		if !found {
			t.Fatal("no segmented control")
		}
		control, _, _ := strings.Cut(afterSeg, "</div>")
		if strings.Contains(control, "<button") {
			t.Errorf("an inert button: %s", control)
		}
		var selected string
		for _, half := range strings.Split(control, "<a ")[1:] {
			if strings.Contains(half, `class="on"`) {
				selected = half
			}
		}
		if !strings.Contains(selected, fmt.Sprintf(`data-m="%s"`, expected)) {
			t.Errorf("%q: selected %q", query, selected)
		}
	}
}

// Each thumbnail anchors to its page, and each page states its own number,
// since the rail's counter is script-written.
func TestTheRailWorksWithoutJavaScript(t *testing.T) {
	html := bookHTML(newTestApp(t), "")
	total := len(strings.Split(html, "<figure")) - 1
	if total <= 2 {
		t.Fatal("the fixture book needs several pages")
	}
	_, afterRail, found := strings.Cut(html, `class="thumbs"`)
	if !found {
		t.Fatal("no thumbnail rail")
	}
	rail, _, _ := strings.Cut(afterRail, "</div>")
	for n := 1; n <= total; n++ {
		if !strings.Contains(rail, fmt.Sprintf(`href="#p%d"`, n)) {
			t.Errorf("no thumbnail for page %d", n)
		}
	}
	if strings.Contains(rail, "<button") {
		t.Errorf("an inert button: %s", rail)
	}
	for i, page := range figures(t, html) {
		if counter := fmt.Sprintf("%d / %d", i+1, total); !strings.Contains(page, counter) {
			t.Errorf("page %d lacks its number %q", i+1, counter)
		}
	}
}
