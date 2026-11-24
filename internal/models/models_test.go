package models

import (
	"log/slog"
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
	firstBookID     = "1f1c111677715adf"
	secondBookID    = "b8799902927c8bf6"
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

func TestPageNewBuildsFromAFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "01.jpg"))
	page, err := newPage(7, dir, "01.jpg")
	if err != nil {
		t.Fatal(err)
	}
	if page.Filename != "01.jpg" || page.ID == "" || page.Path != dir+"/01.jpg" {
		t.Fatalf("unexpected page %+v", page)
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
