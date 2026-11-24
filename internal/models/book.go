package models

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"unicode/utf8"
)

// Page is one file inside a book directory.
type Page struct {
	Filename string
	ID       string
	Path     string
}

// Book is an immediate subdirectory of the data directory.
type Book struct {
	Cover Page
	ID    string
	Title string
	Pages []Page
}

// newPage performs no image I/O, deliberately, so a scan never opens every
// image on a slow disk. It only stats the path.
func newPage(seed uint64, dir, name string) (Page, error) {
	// Not filepath.Join: Clean resolves ".." in the text, which names another
	// directory when the data dir goes through a symlink ("link/../data").
	path := dir + "/" + name
	if !utf8.ValidString(name) {
		return Page{}, fmt.Errorf("invalid path: %q", path)
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return Page{}, fmt.Errorf("not a file: %s", path)
	}
	// The ID uses only the book and file names, so moving the data directory
	// or writing its path differently does not change any URL.
	id := HashString(seed, filepath.Base(dir)+"/"+name)
	return Page{Filename: name, ID: id, Path: path}, nil
}

func newBook(seed uint64, dir, name string, logger *slog.Logger) (Book, error) {
	path := dir + "/" + name // not filepath.Join; see newPage
	if !utf8.ValidString(name) {
		return Book{}, fmt.Errorf("invalid path: %q", path)
	}
	// A path that is not a directory fails in scanPages' ReadDir, which opens
	// with O_DIRECTORY, so even a FIFO cannot block the scan.
	pages, err := scanPages(seed, path, logger)
	if err != nil {
		return Book{}, err
	}
	if len(pages) == 0 {
		return Book{}, fmt.Errorf("empty directory: %s", path)
	}
	return Book{Cover: pages[0], ID: HashString(seed, name), Title: name, Pages: pages}, nil
}
