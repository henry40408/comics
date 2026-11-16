package models

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
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

// joinPath mirrors Rust's Path::join: dir + "/" + name, with no separator
// added when dir is empty or already ends in one. filepath.Join would clean
// "./data" to "data" and change every page ID.
func joinPath(dir, name string) string {
	if dir == "" || strings.HasSuffix(dir, "/") {
		return dir + name
	}
	return dir + "/" + name
}

// newPage performs no image I/O, deliberately, so a scan never opens every
// image on a slow disk. It only stats the path.
func newPage(seed uint64, dir, name string) (Page, error) {
	path := joinPath(dir, name)
	if !utf8.ValidString(name) {
		return Page{}, fmt.Errorf("invalid path: %q", path)
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return Page{}, fmt.Errorf("not a file: %s", path)
	}
	return Page{Filename: name, ID: HashString(seed, path), Path: path}, nil
}

func newBook(seed uint64, dir, name string, logger *slog.Logger) (Book, error) {
	path := joinPath(dir, name)
	if !utf8.ValidString(name) {
		return Book{}, fmt.Errorf("invalid path: %q", path)
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return Book{}, fmt.Errorf("not a directory: %s", path)
	}
	pages, err := scanPages(seed, path, logger)
	if err != nil {
		return Book{}, err
	}
	if len(pages) == 0 {
		return Book{}, fmt.Errorf("empty directory: %s", path)
	}
	return Book{Cover: pages[0], ID: HashString(seed, name), Title: name, Pages: pages}, nil
}
