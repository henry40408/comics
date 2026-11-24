package views

import (
	goflag "flag" // the package already has a flag() helper
	"fmt"
	"log/slog"
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
	testSecret  = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	firstBookID = "1f1c111677715adf"
)

var update = goflag.Bool("update", false, "rewrite testdata/*.golden.html")

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
	scan, err := models.ScanBooks(parsed.IDSeed(), "fixtures/data", slog.New(slog.DiscardHandler))
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

// normalise swaps the build-specific values for the placeholders the goldens
// carry.
func normalise(html string) string {
	html = strings.ReplaceAll(html, version.Version(), "{{VERSION}}")
	return strings.ReplaceAll(html, "?v="+assets.Version(), "?v={{HASH}}")
}

func golden(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(testdataDir, name+".golden.html"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func assertGolden(t *testing.T, name, got string) {
	t.Helper()
	got = normalise(got)
	if *update {
		path := filepath.Join(testdataDir, name+".golden.html")
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want := golden(t, name)
	if got != want {
		t.Fatalf("%s differs from the golden\n got: %s\nwant: %s", name, got, want)
	}
}

func TestIndexMatchesGolden(t *testing.T) {
	scan := fixtureScan(t)
	got := IndexPage(IndexView{Books: scan.Books, ScannedAt: goldenScannedAt})
	assertGolden(t, "index", got)
}

func TestBookPagedMatchesGolden(t *testing.T) {
	scan := fixtureScan(t)
	got := BookPage(BookView{Book: firstBook(t, scan), Mode: ModePaged})
	assertGolden(t, "book-paged", got)
}

func TestLoginMatchesGolden(t *testing.T) {
	assertGolden(t, "login", LoginPage(LoginView{Next: "/"}))
}

// The failed-login and scroll pages have no golden of their own: each is the
// plain page plus a short, fixed list of differences, spelled out below.
func TestAFailedLoginAddsOnlyTheErrorBanner(t *testing.T) {
	const banner = `<div class="err" data-testid="login-error">帳號或密碼錯誤</div>`
	plain := LoginPage(LoginView{Next: "/"})
	want := strings.Replace(plain, "<form", banner+"<form", 1)
	if got := LoginPage(LoginView{Error: true, Next: "/"}); got != want || got == plain {
		t.Fatalf("failed login page:\n got: %s\nwant: %s", got, want)
	}
}

func TestScrollModeDiffersFromPagedOnlyInTheModeMarkup(t *testing.T) {
	book := firstBook(t, fixtureScan(t))
	swaps := []string{
		`data-mode="paged"`, `data-mode="scroll"`,
		`data-m="paged" class="on"`, `data-m="paged" class=""`,
		`data-m="scroll" class=""`, `data-m="scroll" class="on"`,
	}
	for n := range book.Pages {
		swaps = append(swaps,
			fmt.Sprintf(`class="nojs-mode" href="?mode=scroll#p%d">↕ 捲動`, n+1),
			fmt.Sprintf(`class="nojs-mode" href="?mode=paged#p%d">⇄ 翻頁`, n+1))
	}
	paged := BookPage(BookView{Book: book, Mode: ModePaged})
	want := strings.NewReplacer(swaps...).Replace(paged)
	if got := BookPage(BookView{Book: book, Mode: ModeScroll}); got != want || got == paged {
		t.Fatalf("scroll page:\n got: %s\nwant: %s", got, want)
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
// other test. The spellings are html.EscapeString's: &#34; and &#39;.
func TestUserControlledTextIsHTMLEscaped(t *testing.T) {
	page := models.Page{Filename: `<u>"p".jpg`, ID: "pid"}
	book := models.Book{Title: `<i>"b"&c's`, ID: "bid", Pages: []models.Page{page}, Cover: page}
	index := IndexPage(IndexView{Books: []models.Book{book}})
	reader := BookPage(BookView{Book: book})
	login := LoginPage(LoginView{Next: `/"><x'`})

	for _, c := range []struct{ what, html, raw string }{
		{"index title", index, "<i>"},
		{"book title", reader, "<i>"},
		{"book title apostrophe", reader, "c's"},
		{"page filename", reader, "<u>"},
		{"login next", login, "<x"},
		{"login next apostrophe", login, "x'"},
	} {
		if strings.Contains(c.html, c.raw) {
			t.Errorf("%s is not escaped: %s", c.what, c.raw)
		}
	}
	if !strings.Contains(reader, "&lt;i&gt;&#34;b&#34;&amp;c&#39;s") {
		t.Errorf("book title escape missing: %s", reader)
	}
	if !strings.Contains(reader, "&lt;u&gt;&#34;p&#34;.jpg") {
		t.Errorf("filename escape missing: %s", reader)
	}
	if !strings.Contains(login, "&#34;&gt;&lt;x&#39;") {
		t.Errorf("next escape missing: %s", login)
	}
}

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
		// The CSS :target paging resolves these anchors, so pin the targets too.
		if want := fmt.Sprintf(`id="p%d"`, number); !strings.Contains(fig, want) {
			t.Errorf("page %d lacks %s", number, want)
		}
		if want := fmt.Sprintf(`class="nojs-next" href="#p%d"`, number+1); hasNext && !strings.Contains(nav, want) {
			t.Errorf("page %d next link is not %s", number, want)
		}
		if want := fmt.Sprintf(`class="nojs-prev" href="#p%d"`, number-1); hasPrev && !strings.Contains(nav, want) {
			t.Errorf("page %d previous link is not %s", number, want)
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
	// A single-digit day: the no-JS time is zero-padded (RFC 1123Z), not "Mon, 5".
	at := time.Date(2026, 1, 5, 3, 4, 5, 6_000_000, time.FixedZone("x", 3600))
	html := IndexPage(IndexView{ScannedAt: at, ScanDuration: 3 * time.Millisecond})
	for _, want := range []string{
		`datetime="2026-01-05T02:04:05.006Z">Mon, 05 Jan 2026 02:04:05 +0000</time>`,
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
