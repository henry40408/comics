package server

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
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

func openingTag(t *testing.T, fragment string) string {
	t.Helper()
	tag, _, found := strings.Cut(fragment, ">")
	if !found {
		t.Fatalf("an unclosed tag: %s", fragment)
	}
	return tag
}

func bookHTML(ta *testApp, query string) string {
	return ta.get("/book/" + dataIDs[0] + query).text()
}

// The CSP forbids inline scripts, so the browser would drop them.
func TestRenderedPagesCarryNoInlineScripts(t *testing.T) {
	ta := newTestApp(t)
	pages := []string{ta.get("/").text(), bookHTML(ta, ""), newAuthApp(t).get("/login").text()}
	for _, html := range pages {
		if !strings.Contains(html, "<script") {
			t.Fatal("no script rendered")
		}
		for _, tag := range strings.Split(html, "<script")[1:] {
			if open := openingTag(t, tag); !strings.Contains(open, "src=") {
				t.Errorf("inline script: <script%s>", open)
			}
		}
		if strings.Contains(html, "onclick=") {
			t.Error("inline onclick handler")
		}
	}
}

// Pins the escaping html/template does by default: a template.HTML around
// user-controlled text would pass every other test.
func TestUserControlledTextIsHTMLEscaped(t *testing.T) {
	dir := t.TempDir()
	// A / cannot appear in a file name, so no closing tags here.
	bookDir := filepath.Join(dir, `<i>"b"`)
	if err := os.Mkdir(bookDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bookDir, `<u>"p".jpg`), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	ta := newTestApp(t, withDataDir(dir))

	index := ta.get("/").text()
	bookID := firstAfter(t, index, `href="/book/`)
	book := ta.get("/book/" + bookID).text()
	login := newAuthApp(t).get("/login?next=" + url.QueryEscape(`/"><x`)).text()

	for _, c := range []struct{ what, html, raw string }{
		{"index title", index, "<i>"},
		{"book title", book, "<i>"},
		{"page filename", book, "<u>"},
		{"login next", login, "<x"},
	} {
		if strings.Contains(c.html, c.raw) {
			t.Errorf("%s is not escaped: %s", c.what, c.raw)
		}
	}
	if !strings.Contains(book, "&lt;i&gt;&#34;b&#34;") && !strings.Contains(book, "&lt;i&gt;&quot;b&quot;") {
		t.Errorf("book title escaping unexpected: %s", book)
	}
	if !strings.Contains(login, "&gt;&lt;x") {
		t.Errorf("login next escaping unexpected: %s", login)
	}
}

// .pg is hidden until is-current lands on it; without app.js the server has to
// set it on the first page.
func TestTheFirstPageIsVisibleWithoutJavaScript(t *testing.T) {
	tags := figures(t, bookHTML(newTestApp(t), ""))
	if len(tags) < 2 {
		t.Fatal("the fixture book needs several pages")
	}
	if !strings.Contains(openingTag(t, tags[0]), "is-current") {
		t.Errorf("first page lacks is-current: %s", tags[0])
	}
	for _, tag := range tags[1:] {
		if strings.Contains(openingTag(t, tag), "is-current") {
			t.Errorf("a later page is current: %s", openingTag(t, tag))
		}
	}
}

// Without a script, :target picks the page, so each carries links to its
// neighbours, and none past either end.
func TestAnchorPagingLinksEveryPageToItsNeighbours(t *testing.T) {
	frags := figures(t, bookHTML(newTestApp(t), ""))
	total := len(frags)
	if total <= 2 {
		t.Fatal("the fixture book needs several pages")
	}
	for i, fragment := range frags {
		n := i + 1
		if !strings.Contains(fragment, fmt.Sprintf(`id="p%d"`, n)) {
			t.Errorf("page %d has no id: %s", n, fragment)
		}
		hasNext := strings.Contains(fragment, fmt.Sprintf(`href="#p%d"`, n+1))
		if n < total && !hasNext {
			t.Errorf("page %d has no next", n)
		}
		if n == total && strings.Contains(fragment, `rel="next"`) {
			t.Errorf("last page has a next: %s", fragment)
		}
		hasPrev := strings.Contains(fragment, fmt.Sprintf(`href="#p%d"`, n-1))
		if n > 1 && !hasPrev {
			t.Errorf("page %d has no prev", n)
		}
		if n == 1 && strings.Contains(fragment, `rel="prev"`) {
			t.Errorf("first page has a prev: %s", fragment)
		}
	}
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
