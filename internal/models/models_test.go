package models

import (
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"testing"

	"github.com/henry40408/comics/internal/secret"
)

const (
	fixtureDataDir = "../../fixtures/data"
	// Book IDs under testSecret. Every existing URL stays valid only while
	// these hold.
	firstBookTitle  = "Pepper and Carrot 01 - Potion of Flight"
	secondBookTitle = "Pepper and Carrot 02 - Rainbow Potions"
	firstBookID     = "ef4c3cd1ffa17dc1"
	secondBookID    = "ad99f34da8eb7ed6"
	testSecret      = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

var discardLogger = slog.New(slog.DiscardHandler)

func writeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

// The ID is spelled out as book/file: it must not contain the data dir, and
// Path must be dir + "/" + name exactly as given.
func TestPageNewBuildsFromAFile(t *testing.T) {
	book := filepath.Join(t.TempDir(), "My Book")
	mkdir(t, book)
	writeFile(t, filepath.Join(book, "01.jpg"))
	page, err := newPage(7, book, "01.jpg")
	if err != nil {
		t.Fatal(err)
	}
	want := Page{Filename: "01.jpg", ID: HashString(7, "My Book/01.jpg"), Path: book + "/01.jpg"}
	if page != want {
		t.Fatalf("got page %+v, want %+v", page, want)
	}
}

func TestBookNewBuildsWithSortedPages(t *testing.T) {
	dir := t.TempDir()
	book := filepath.Join(dir, "My Book")
	mkdir(t, book)
	writeFile(t, filepath.Join(book, "02.jpg"))
	writeFile(t, filepath.Join(book, "01.jpg"))
	got, err := newBook(1, dir, "My Book", discardLogger)
	if err != nil {
		t.Fatal(err)
	}
	if got.Title != "My Book" || len(got.Pages) != 2 || got.Cover.Filename != "01.jpg" {
		t.Fatalf("unexpected book %+v", got)
	}
}

func scanTwoBooks(t *testing.T) (*BookScan, string) {
	t.Helper()
	dir := t.TempDir()
	books := map[string][]string{"Alpha": {"01.jpg", "02.jpg"}, "Beta": {"01.png", "02.png"}}
	for book, pages := range books {
		mkdir(t, filepath.Join(dir, book))
		for _, page := range pages {
			writeFile(t, filepath.Join(dir, book, page))
		}
	}
	scan, err := ScanBooks(1, dir, discardLogger)
	if err != nil {
		t.Fatal(err)
	}
	return scan, dir
}

// idsByName maps each book title to its ID and each "title/filename" to its
// page ID, so scans can be compared without looking at their paths.
func idsByName(scan *BookScan) map[string]string {
	ids := make(map[string]string)
	for _, book := range scan.Books {
		ids[book.Title] = book.ID
		for _, page := range book.Pages {
			ids[book.Title+"/"+page.Filename] = page.ID
		}
	}
	return ids
}

func TestIDsDoNotDependOnHowTheDataDirIsSpelled(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "data")
	mkdir(t, data)
	for _, book := range []string{"Alpha", "Beta"} {
		mkdir(t, filepath.Join(data, book))
		writeFile(t, filepath.Join(data, book, "01.jpg"))
		writeFile(t, filepath.Join(data, book, "02.jpg"))
	}
	t.Chdir(root)

	scanIDs := func(dataDir string) map[string]string {
		scan, err := ScanBooks(3, dataDir, discardLogger)
		if err != nil {
			t.Fatal(err)
		}
		return idsByName(scan)
	}
	want := scanIDs(data)
	if len(want) != 6 {
		t.Fatalf("reference scan has %d IDs, want 2 books and 4 pages: %v", len(want), want)
	}
	for _, spelling := range []struct{ name, dataDir string }{
		{"absolute with a trailing slash", data + "/"},
		{"relative", "data"},
		{"relative with a dot", "./data"},
		{"relative with a trailing slash", "data/"},
	} {
		t.Run(spelling.name, func(t *testing.T) {
			if got := scanIDs(spelling.dataDir); !maps.Equal(got, want) {
				t.Fatalf("scanning %q gave %v, want %v", spelling.dataDir, got, want)
			}
		})
	}
}

func TestPagesWithTheSameFilenameInDifferentBooksGetDifferentIDs(t *testing.T) {
	dir := t.TempDir()
	for _, book := range []string{"Alpha", "Beta"} {
		mkdir(t, filepath.Join(dir, book))
		writeFile(t, filepath.Join(dir, book, "01.jpg"))
	}
	scan, err := ScanBooks(1, dir, discardLogger)
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Books) != 2 {
		t.Fatalf("got %d books, want 2", len(scan.Books))
	}
	alpha, beta := scan.Books[0].Pages[0], scan.Books[1].Pages[0]
	if alpha.ID == beta.ID {
		t.Fatalf("both pages are %q", alpha.ID)
	}
	for _, page := range []Page{alpha, beta} {
		resolved, ok := scan.PageByID(page.ID)
		if !ok || resolved.Path != page.Path {
			t.Errorf("page %q resolved to %+v, want the page at %s", page.ID, resolved, page.Path)
		}
	}
}

// "link/../data" names root/data: link points at root/target, and the OS
// resolves ".." from there. Cleaning the text would name cwd/data instead,
// which holds a decoy book of the same name.
func TestScanResolvesDotDotThroughASymlinkedDataDir(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	mkdir(t, target)
	mkdir(t, filepath.Join(root, "data"))
	mkdir(t, filepath.Join(root, "data", "Real"))
	writeFile(t, filepath.Join(root, "data", "Real", "01.jpg"))

	cwd := filepath.Join(root, "cwd")
	mkdir(t, cwd)
	symlink(t, target, filepath.Join(cwd, "link"))
	mkdir(t, filepath.Join(cwd, "data"))
	mkdir(t, filepath.Join(cwd, "data", "Real"))
	writeFile(t, filepath.Join(cwd, "data", "Real", "99.jpg"))
	t.Chdir(cwd)

	scan, err := ScanBooks(0, "link/../data", discardLogger)
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Books) != 1 || scan.Books[0].Title != "Real" || len(scan.Books[0].Pages) != 1 {
		t.Fatalf("got %+v, want one book Real with one page", scan.Books)
	}
	page := scan.Books[0].Pages[0]
	if page.Filename != "01.jpg" || page.Path != "link/../data/Real/01.jpg" {
		t.Fatalf("got page %+v, want 01.jpg at link/../data/Real/01.jpg", page)
	}
}

func TestPageByIDResolvesToTheOwningPage(t *testing.T) {
	scan, _ := scanTwoBooks(t)
	for _, book := range scan.Books {
		for _, page := range book.Pages {
			resolved, ok := scan.PageByID(page.ID)
			if !ok || resolved.ID != page.ID || resolved.Path != page.Path {
				t.Fatalf("page %q did not resolve to itself: %+v", page.ID, resolved)
			}
		}
	}
}

func TestPageByIDReturnsNoneForAnUnknownID(t *testing.T) {
	scan, _ := scanTwoBooks(t)
	if _, ok := scan.PageByID("deadbeef"); ok {
		t.Fatal("unknown id resolved")
	}
}

func TestScanSortsBooksByTitleAndIndexesThem(t *testing.T) {
	scan, _ := scanTwoBooks(t)
	if len(scan.Books) != 2 || scan.Books[0].Title != "Alpha" || scan.Books[1].Title != "Beta" {
		t.Fatalf("unexpected order %+v", scan.Books)
	}
	for idx, book := range scan.Books {
		if scan.BooksMap[book.ID] != idx {
			t.Errorf("book %q indexed at %d, want %d", book.Title, scan.BooksMap[book.ID], idx)
		}
	}
	if scan.ScannedAt.IsZero() {
		t.Error("ScannedAt not set")
	}
}

func TestScanSkipsLooseFilesAndEmptyBooks(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "loose.txt"))
	mkdir(t, filepath.Join(dir, "empty"))
	mkdir(t, filepath.Join(dir, "Real"))
	writeFile(t, filepath.Join(dir, "Real", "01.jpg"))
	scan, err := ScanBooks(1, dir, discardLogger)
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Books) != 1 || scan.Books[0].Title != "Real" {
		t.Fatalf("unexpected books %+v", scan.Books)
	}
}

func TestScanFailsWhenTheDataDirIsMissing(t *testing.T) {
	if _, err := ScanBooks(0, filepath.Join(t.TempDir(), "nope"), discardLogger); err == nil {
		t.Fatal("missing data dir scanned")
	}
}

func TestBookIDsAreStable(t *testing.T) {
	parsed, err := secret.Parse(testSecret)
	if err != nil {
		t.Fatal(err)
	}
	scan, err := ScanBooks(parsed.IDSeed(), fixtureDataDir, discardLogger)
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Books) != 2 {
		t.Fatalf("got %d books, want 2", len(scan.Books))
	}
	wantIDs := []struct{ title, id string }{
		{firstBookTitle, firstBookID},
		{secondBookTitle, secondBookID},
	}
	for i, want := range wantIDs {
		book := scan.Books[i]
		if book.Title != want.title || book.ID != want.id {
			t.Errorf("book %d = (%q, %q), want (%q, %q)", i, book.Title, book.ID, want.title, want.id)
		}
	}
	pages := 0
	for _, book := range scan.Books {
		pages += len(book.Pages)
	}
	if pages != 8 {
		t.Errorf("got %d pages, want 8", pages)
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
}

func TestScanFollowsASymlinkedBookDirectory(t *testing.T) {
	outside, root := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(outside, "01.jpg"))
	symlink(t, outside, filepath.Join(root, "Linked"))
	scan, err := ScanBooks(0, root, discardLogger)
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Books) != 1 || scan.Books[0].Title != "Linked" || len(scan.Books[0].Pages) != 1 {
		t.Fatalf("got %+v, want one book Linked with one page", scan.Books)
	}
}

func TestScanFollowsASymlinkedPageFile(t *testing.T) {
	outside, root := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(outside, "real.jpg"))
	book := filepath.Join(root, "Book")
	mkdir(t, book)
	symlink(t, filepath.Join(outside, "real.jpg"), filepath.Join(book, "01.jpg"))
	scan, err := ScanBooks(0, root, discardLogger)
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Books) != 1 || len(scan.Books[0].Pages) != 1 {
		t.Fatalf("got %+v, want one book with one page", scan.Books)
	}
}

func TestScanRejectsASymlinkToADirectoryInsideABook(t *testing.T) {
	outside, root := t.TempDir(), t.TempDir()
	book := filepath.Join(root, "Book")
	mkdir(t, book)
	writeFile(t, filepath.Join(book, "01.jpg"))
	symlink(t, outside, filepath.Join(book, "sub"))
	scan, err := ScanBooks(0, root, discardLogger)
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Books) != 1 || len(scan.Books[0].Pages) != 1 {
		t.Fatalf("got %+v, want only the regular file as a page", scan.Books)
	}
}

func TestNonUTF8NamesAreRejected(t *testing.T) {
	dir := t.TempDir()
	if _, err := newPage(0, dir, "\xff.jpg"); err == nil {
		t.Error("newPage accepted a non-UTF-8 name")
	}
	if _, err := newBook(0, dir, "\xff", discardLogger); err == nil {
		t.Error("newBook accepted a non-UTF-8 name")
	}
}
