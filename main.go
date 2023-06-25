package main

import (
	"io/fs"
	"net/http"
	"path/filepath"
	"sort"
)

type Book struct {
	Name  string
	Pages []string
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

			var pages []string

			err := filepath.Walk(d, func(path string, info fs.FileInfo, err error) error {
				if err != nil {
					return err
				}

				if info.Name() == d {
					return nil // ignore self
				}

				if !info.IsDir() {
					pages = append(pages, filepath.Join(d, info.Name()))
				}

				return nil
			})
			if err != nil {
				return err
			}

			sort.Strings(pages)
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
		return books[i].Name > books[j].Name
	})

	return books, nil
}

func main() {
	// books, err := ListBooks()
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Printf("%v", books)
	dir := "data"
	fs := http.FileServer(http.Dir(dir))
	http.Handle("/", fs)
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		panic(err)
	}
}
