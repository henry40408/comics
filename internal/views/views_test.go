package views

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/henry40408/comics/internal/assets"
	"github.com/henry40408/comics/internal/models"
	"github.com/henry40408/comics/internal/secret"
	"github.com/henry40408/comics/internal/version"
)

const (
	testSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	// Values baked into the Rust-rendered goldens (see testdata/README.txt).
	goldenVersion    = "9.4.1-3-g968f5ea-modified"
	goldenAssetsHash = "c7db4b09d947f4e6"
	firstBookID      = "1f1c111677715adf"
)

// testdataDir is absolute because fixtureScan changes the working directory.
var testdataDir = func() string {
	dir, err := filepath.Abs("testdata")
	if err != nil {
		panic(err)
	}
	return dir
}()

// goldenScannedAt is the scan time captured in index.golden.html.
var goldenScannedAt = time.Date(2026, 11, 16, 13, 40, 41, 191_000_000, time.UTC)

// fixtureScan scans fixtures/data by the same relative path the goldens were
// captured with: page IDs hash the path, so ../../fixtures/data would differ.
func fixtureScan(t *testing.T) *models.BookScan {
	t.Helper()
	parsed, err := secret.Parse(testSecret)
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir("../..")
	scan, err := models.ScanBooks(parsed.IDSeed(), "fixtures/data", nil)
	if err != nil {
		t.Fatal(err)
	}
	return scan
}

func firstBook(t *testing.T, scan *models.BookScan) models.Book {
	t.Helper()
	i, ok := scan.BooksMap[firstBookID]
	if !ok {
		t.Fatalf("book %s missing from the fixture scan", firstBookID)
	}
	return scan.Books[i]
}

// normalise swaps the build-specific values for placeholders.
func normalise(html string, versions ...string) string {
	for _, v := range versions {
		html = strings.ReplaceAll(html, v, "{{VERSION}}")
	}
	return strings.ReplaceAll(html, "?v="+assets.Version(), "?v={{HASH}}")
}

func golden(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(testdataDir, name+".golden.html"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(data), "?v="+goldenAssetsHash, "?v={{HASH}}")
}

func assertGolden(t *testing.T, name, got string) {
	t.Helper()
	want := strings.ReplaceAll(golden(t, name), goldenVersion, "{{VERSION}}")
	got = normalise(got, version.Version())
	if got != want {
		t.Fatalf("%s differs from the Rust golden\n got: %s\nwant: %s", name, got, want)
	}
}

func TestIndexMatchesRustGolden(t *testing.T) {
	scan := fixtureScan(t)
	got := IndexPage(IndexView{Books: scan.Books, ScannedAt: goldenScannedAt})
	assertGolden(t, "index", got)
}

func TestBookPagedMatchesRustGolden(t *testing.T) {
	scan := fixtureScan(t)
	got := BookPage(BookView{Book: firstBook(t, scan), Mode: ModePaged})
	assertGolden(t, "book-paged", got)
}

func TestBookScrollMatchesRustGolden(t *testing.T) {
	scan := fixtureScan(t)
	got := BookPage(BookView{Book: firstBook(t, scan), Mode: ModeScroll})
	assertGolden(t, "book-scroll", got)
}

func TestLoginMatchesRustGolden(t *testing.T) {
	assertGolden(t, "login", LoginPage(LoginView{Next: "/"}))
}

func TestFailedLoginMatchesRustGolden(t *testing.T) {
	assertGolden(t, "login-failed", LoginPage(LoginView{Error: true, Next: "/"}))
}

func TestAssetsHashMatchesTheGoldens(t *testing.T) {
	if assets.Version() != goldenAssetsHash {
		t.Fatalf("assets hash %s, goldens carry %s", assets.Version(), goldenAssetsHash)
	}
}

func TestAuthControlsAppearOnlyWhenAuthIsEnabled(t *testing.T) {
	scan := fixtureScan(t)
	book := firstBook(t, scan)
	for name, render := range map[string]func(bool) string{
		"index": func(on bool) string { return IndexPage(IndexView{Books: scan.Books, AuthEnabled: on}) },
		"book":  func(on bool) string { return BookPage(BookView{Book: book, AuthEnabled: on}) },
	} {
		if strings.Contains(render(false), `data-testid="logout"`) {
			t.Errorf("%s shows Logout without auth", name)
		}
		if !strings.Contains(render(true), `data-testid="logout"`) {
			t.Errorf("%s lacks Logout with auth", name)
		}
	}
}

// Ported from rendered_pages_carry_no_inline_scripts.
func TestRenderedPagesCarryNoInlineScripts(t *testing.T) {
	scan := fixtureScan(t)
	pages := []string{
		IndexPage(IndexView{Books: scan.Books}),
		BookPage(BookView{Book: firstBook(t, scan), Mode: ModePaged}),
		LoginPage(LoginView{Next: "/"}),
	}
	for _, html := range pages {
		if !strings.Contains(html, "<script") {
			t.Fatal("no script rendered")
		}
		for _, tag := range strings.Split(html, "<script")[1:] {
			open, _, found := strings.Cut(tag, ">")
			if !found {
				t.Fatal("an unclosed <script")
			}
			if !strings.Contains(open, "src=") {
				t.Errorf("inline script: <script%s>", open)
			}
		}
		if strings.Contains(html, "onclick=") {
			t.Error("inline onclick handler")
		}
	}
}

// Pins the escaping: a raw write of user-controlled text would pass every
// other test.
func TestUserControlledTextIsHTMLEscaped(t *testing.T) {
	page := models.Page{Filename: `<u>"p".jpg`, ID: "pid"}
	book := models.Book{Title: `<i>"b"`, ID: "bid", Pages: []models.Page{page}, Cover: page}
	index := IndexPage(IndexView{Books: []models.Book{book}})
	reader := BookPage(BookView{Book: book})
	login := LoginPage(LoginView{Next: `/"><x`})

	for _, c := range []struct{ what, html, raw string }{
		{"index title", index, "<i>"},
		{"book title", reader, "<i>"},
		{"page filename", reader, "<u>"},
		{"login next", login, "<x"},
	} {
		if strings.Contains(c.html, c.raw) {
			t.Errorf("%s is not escaped: %s", c.what, c.raw)
		}
	}
	if !strings.Contains(reader, "&lt;i&gt;&quot;b&quot;") {
		t.Errorf("book title escape missing: %s", reader)
	}
	if !strings.Contains(reader, "&lt;u&gt;&quot;p&quot;.jpg") {
		t.Errorf("filename escape missing: %s", reader)
	}
	if !strings.Contains(login, "&quot;&gt;&lt;x") {
		t.Errorf("next escape missing: %s", login)
	}
}

func TestEscapeCoversExactlyTheMaudCharacters(t *testing.T) {
	if got := escape(`a&b<c>d"e'f+g`); got != "a&amp;b&lt;c&gt;d&quot;e'f+g" {
		t.Fatalf("got %q", got)
	}
}

// Ported from the_first_page_is_visible_without_javascript.
func TestOnlyTheFirstPageStartsCurrent(t *testing.T) {
	scan := fixtureScan(t)
	html := BookPage(BookView{Book: firstBook(t, scan)})
	figures := strings.Split(html, "<figure")[1:]
	if len(figures) < 2 {
		t.Fatal("the fixture book needs several pages")
	}
	for i, fig := range figures {
		tag, _, _ := strings.Cut(fig, ">")
		if got := strings.Contains(tag, "is-current"); got != (i == 0) {
			t.Errorf("figure %d is-current=%v: %s", i+1, got, tag)
		}
	}
}

// Ported from anchor_paging_links_every_page_to_its_neighbours.
func TestEveryPageLinksToItsNeighbours(t *testing.T) {
	scan := fixtureScan(t)
	html := BookPage(BookView{Book: firstBook(t, scan)})
	figures := strings.Split(html, "<figure")[1:]
	last := len(figures)
	for i, fig := range figures {
		number := i + 1
		nav, _, _ := strings.Cut(fig, "</nav>")
		hasNext := strings.Contains(nav, `class="nojs-next"`)
		hasPrev := strings.Contains(nav, `class="nojs-prev"`)
		if hasNext != (number != last) || hasPrev != (number != 1) {
			t.Errorf("page %d: next=%v prev=%v", number, hasNext, hasPrev)
		}
	}
}

func TestParseModeFallsBackToPaged(t *testing.T) {
	for in, want := range map[string]Mode{
		"scroll": ModeScroll, "paged": ModePaged, "": ModePaged, "bogus": ModePaged, "SCROLL": ModePaged,
	} {
		if got := ParseMode(in); got != want {
			t.Errorf("ParseMode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIndexTimeFormats(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 6_000_000, time.FixedZone("x", 3600))
	html := IndexPage(IndexView{ScannedAt: at, ScanDuration: 3 * time.Millisecond})
	for _, want := range []string{
		`datetime="2026-01-02T02:04:05.006Z">Fri, 2 Jan 2026 02:04:05 +0000</time>`,
		`<time datetime="PT0.003S">3ms</time>`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("missing %s in %s", want, html)
		}
	}
	html = IndexPage(IndexView{ScannedAt: at, ScanDuration: 3 * time.Second})
	if !strings.Contains(html, `<time datetime="PT3S">3000ms</time>`) {
		t.Errorf("whole-second duration: %s", html)
	}
}
