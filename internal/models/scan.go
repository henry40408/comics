package models

import (
	"io"
	"log/slog"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
)

// pageRef locates a page inside BookScan.Books.
type pageRef struct {
	book, page int
}

// BookScan is the result of one scan of the data directory.
type BookScan struct {
	Books []Book
	// BooksMap maps a book ID to its index in Books.
	BooksMap map[string]int
	// pagesMap maps a page ID to its book and page indexes; PageByID is the
	// only accessor.
	pagesMap     map[string]pageRef
	ScanDuration time.Duration
	ScannedAt    time.Time
}

// PageByID resolves a page ID in O(1).
func (s *BookScan) PageByID(id string) (*Page, bool) {
	ref, ok := s.pagesMap[id]
	if !ok {
		return nil, false
	}
	return &s.Books[ref.book].Pages[ref.page], true
}

// ScanBooks treats every entry of dataDir that is a directory as a book and
// every file inside it as a page. Nothing deeper is scanned. A nil logger
// discards the per-entry errors.
func ScanBooks(seed uint64, dataDir string, logger *slog.Logger) (*BookScan, error) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	start := time.Now()
	names, err := readNames(dataDir)
	if err != nil {
		return nil, err
	}
	books := parallelMap(names, func(name string) (Book, bool) {
		book, err := newBook(seed, dataDir, name, logger)
		if err != nil {
			logger.Error("failed to create book", "err", err)
			return Book{}, false
		}
		return book, true
	})
	slices.SortFunc(books, func(a, b Book) int { return strings.Compare(a.Title, b.Title) })
	scan := &BookScan{Books: books, ScannedAt: start.UTC()}
	scan.index()
	scan.ScanDuration = time.Since(start)
	return scan, nil
}

func (s *BookScan) index() {
	s.BooksMap = make(map[string]int, len(s.Books))
	s.pagesMap = make(map[string]pageRef)
	for bookIdx, book := range s.Books {
		s.BooksMap[book.ID] = bookIdx
		for pageIdx, page := range book.Pages {
			s.pagesMap[page.ID] = pageRef{book: bookIdx, page: pageIdx}
		}
	}
}

func scanPages(seed uint64, bookDir string, logger *slog.Logger) ([]Page, error) {
	names, err := readNames(bookDir)
	if err != nil {
		return nil, err
	}
	// Sequential: books already scan in parallel, and nested pools would issue
	// NumCPU² concurrent stats on a slow disk.
	pages := make([]Page, 0, len(names))
	for _, name := range names {
		page, err := newPage(seed, bookDir, name)
		if err != nil {
			logger.Error("failed to create page", "err", err, "path", joinPath(bookDir, name))
			continue
		}
		pages = append(pages, page)
	}
	slices.SortFunc(pages, func(a, b Page) int { return strings.Compare(a.Path, b.Path) })
	return pages, nil
}

func readNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(entries))
	for i, entry := range entries {
		names[i] = entry.Name()
	}
	return names, nil
}

// parallelMap keeps the results fn accepts, in input order, using a pool of
// runtime.NumCPU workers.
func parallelMap[In, Out any](inputs []In, fn func(In) (Out, bool)) []Out {
	type slot struct {
		value Out
		ok    bool
	}
	slots := make([]slot, len(inputs))
	work := make(chan int)
	var wg sync.WaitGroup
	for range min(runtime.NumCPU(), len(inputs)) {
		wg.Go(func() {
			for i := range work {
				slots[i].value, slots[i].ok = fn(inputs[i])
			}
		})
	}
	for i := range inputs {
		work <- i
	}
	close(work)
	wg.Wait()

	kept := make([]Out, 0, len(inputs))
	for _, s := range slots {
		if s.ok {
			kept = append(kept, s.value)
		}
	}
	return kept
}
