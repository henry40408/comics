//go:build unix

package models

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Opening a FIFO blocks until a writer appears, and newBook does not stat
// its path first. What keeps a FIFO beside the books from hanging the scan is
// that os.ReadDir opens with O_DIRECTORY, which fails at once on anything that
// is not a directory; and a page is only stat'ed, never opened. Both are
// stdlib or design details nothing else pins, so a regression would show up
// here as a hang, not as a wrong result.
func TestScanDoesNotBlockOnAFIFO(t *testing.T) {
	root := t.TempDir()
	book := filepath.Join(root, "Book")
	mkdir(t, book)
	writeFile(t, filepath.Join(book, "01.jpg"))
	for _, path := range []string{filepath.Join(book, "02.jpg"), filepath.Join(root, "Loose")} {
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	type result struct {
		scan *BookScan
		err  error
	}
	done := make(chan result, 1)
	go func() {
		scan, err := ScanBooks(0, root, discardLogger)
		done <- result{scan, err}
	}()
	var got result
	select {
	case got = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ScanBooks blocked on a FIFO")
	}

	if got.err != nil {
		t.Fatal(got.err)
	}
	books := got.scan.Books
	if len(books) != 1 || books[0].Title != "Book" || len(books[0].Pages) != 1 || books[0].Pages[0].Filename != "01.jpg" {
		t.Fatalf("got %+v, want only Book with the page 01.jpg", books)
	}
}
