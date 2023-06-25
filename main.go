package main

import (
	"io/fs"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
	"time"
)

type Book struct {
	Cover string
	Name  string
	Pages []Page
}

type Page struct {
	Name string
	Path string
}

func ListBooks() ([]Book, error) {
	var books []Book

	err := filepath.Walk("data", func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.Name() == "data" {
			return nil // ignore self
		}

		if info.IsDir() {
			book := Book{
				Name: info.Name(),
			}

			d := filepath.Join("data", info.Name())

			var pages []Page

			err := filepath.Walk(d, func(path string, info fs.FileInfo, err error) error {
				if err != nil {
					return err
				}

				if info.Name() == d {
					return nil // ignore self
				}

				if !info.IsDir() {
					pages = append(pages, Page{
						Name: info.Name(),
						Path: filepath.Join(d, info.Name()),
					})
				}

				return nil
			})
			if err != nil {
				return err
			}

			sort.Slice(pages, func(i, j int) bool {
				return pages[i].Name < pages[j].Name
			})
			if len(pages) > 0 {
				book.Cover = pages[0].Path
			}
			book.Pages = pages
			books = append(books, book)
			return nil
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(books, func(i, j int) bool {
		return books[i].Name < books[j].Name
	})

	return books, nil
}

type IndexTemplateParams struct {
	Books   []Book
	Elapsed int64
}

type BookTemplateParams struct {
	Book    Book
	Elapsed int64
}

func main() {
	indexTemplate, err := template.ParseFiles("templates/index.html")
	if err != nil {
		panic(err)
	}
	bookTemplate, err := template.ParseFiles("templates/book.html")
	if err != nil {
		panic(err)
	}

	dir := "data"

	fs := http.FileServer(http.Dir(dir))
	http.Handle("/data/", http.StripPrefix("/data/", fs))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		books, err := ListBooks()
		elapsed := time.Since(start)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		params := IndexTemplateParams{
			Books:   books,
			Elapsed: elapsed.Milliseconds(),
		}
		err = indexTemplate.Execute(w, params)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	http.HandleFunc("/book/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/book/")

		start := time.Now()
		books, err := ListBooks()
		elapsed := time.Since(start)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		for _, book := range books {
			if book.Name == name {
				params := BookTemplateParams{
					Book:    book,
					Elapsed: elapsed.Milliseconds(),
				}
				err = bookTemplate.Execute(w, params)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				return
			}
		}

		http.Error(w, "not found", http.StatusNotFound)
	})

	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		panic(err)
	}
}
