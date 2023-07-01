package main

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
	"time"

	"comics.app/version"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/hashicorp/logutils"
	"github.com/spf13/cobra"
	"github.com/urfave/negroni"
)

//go:embed templates/*.html
var templateFiles embed.FS

var dataDir, host, expectedUsername, expectedPassword string
var port int

func init() {
	filter := &logutils.LevelFilter{
		Levels:   []logutils.LogLevel{"DEBUG", "INFO", "WARN"},
		MinLevel: logutils.LogLevel("INFO"),
		Writer:   os.Stderr,
	}
	if _, ok := os.LookupEnv("DEBUG"); ok {
		filter.MinLevel = logutils.LogLevel("DEBUG")
	}
	log.SetOutput(filter)

	rootCmd.Flags().StringVarP(&host, "host", "H", "0.0.0.0", "Host to bind")
	rootCmd.Flags().IntVarP(&port, "port", "p", 8080, "Port to bind")
	rootCmd.Flags().StringVarP(&dataDir, "data", "d", "data", "Data directory")
	rootCmd.Flags().StringVarP(&expectedUsername, "auth-username", "U", os.Getenv("AUTH_USERNAME"), "Basic auth username")
	rootCmd.Flags().StringVarP(&expectedPassword, "auth-password", "P", os.Getenv("AUTH_PASSWORD"), "Hashed basic auth password")
	rootCmd.AddCommand(hashPasswordCmd)
}

type Book struct {
	// PublicCover represents relative path from data directory
	PublicCover string
	Name        string
	Pages       []Page
}

type Page struct {
	Name string
	// PublicPath represents relative path from data directory
	PublicPath string
}

func IsImage(path string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, nil
	}
	defer file.Close()

	buf := make([]byte, 512)
	_, err = file.Read(buf)
	if err != nil {
		return false, err
	}

	contentType := http.DetectContentType(buf)
	return contentType[:5] == "image", nil
}

func ListBooks() ([]Book, error) {
	log.Printf("[DEBUG] scan data directory: %s\n", dataDir)

	var books []Book

	err := filepath.Walk(dataDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.Name() == dataDir {
			return nil // ignore self
		}

		if info.IsDir() {
			book := Book{
				Name: info.Name(),
			}

			bookName := info.Name()
			log.Printf("[DEBUG] found book: %s\n", bookName)

			bookPath := filepath.Join(dataDir, bookName)

			var pages []Page

			err := filepath.Walk(bookPath, func(path string, info fs.FileInfo, err error) error {
				if err != nil {
					return err
				}

				if info.Name() == bookPath {
					return nil // ignore self
				}

				if !info.IsDir() {
					imagePath := filepath.Join(bookPath, info.Name())
					isImage, err := IsImage(imagePath)
					if err != nil {
						return err
					}
					if isImage {
						log.Printf("[DEBUG] found page: %s\n", imagePath)
						publicPath := filepath.Join(bookName, info.Name())
						pages = append(pages, Page{
							Name:       info.Name(),
							PublicPath: publicPath,
						})
					} else {
						log.Printf("[DEBUG] file is not image: %s\n", imagePath)
					}
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
				p := pages[0]
				book.PublicCover = p.PublicPath
				log.Printf(`[DEBUG] set "%s" as cover of "%s"`, p.PublicPath, bookName)
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

func PubliclyAccessible() bool {
	return expectedUsername == "" || expectedPassword == ""
}

type BasicAuthMiddleware struct{}

func (b *BasicAuthMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if PubliclyAccessible() {
		next(w, r) // PASS
		return
	}

	username, password, ok := r.BasicAuth()
	if !ok { // AUTHORIZE
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if username != expectedUsername { // FAIL
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	err := bcrypt.CompareHashAndPassword([]byte(expectedPassword), []byte(password))
	if err != nil { // FAIL
		log.Printf("[ERROR] %v\n", err)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	next(w, r) // PASS
}

func NewTemplateParams() map[string]interface{} {
	params := make(map[string]interface{})
	params["Version"] = version.Version
	params["Commit"] = version.Commit
	params["BuildDate"] = version.BuildDate
	return params
}

func HandleIndex(tpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		start := time.Now()
		books, err := ListBooks()
		elapsed := time.Since(start)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		params := NewTemplateParams()
		params["Books"] = books
		params["Elapsed"] = elapsed.Milliseconds()

		err = tpl.Execute(w, params)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func HandleBook(tpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
				params := NewTemplateParams()
				params["Book"] = book
				params["Elapsed"] = elapsed.Milliseconds()

				err = tpl.Execute(w, params)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				return
			}
		}

		http.Error(w, "not found", http.StatusNotFound)
	}
}

func RunServer() error {
	mux := http.NewServeMux()

	indexTemplate, err := template.ParseFS(templateFiles, "templates/index.html")
	if err != nil {
		return err
	}
	mux.HandleFunc("/", HandleIndex(indexTemplate))

	bookTemplate, err := template.ParseFS(templateFiles, "templates/book.html")
	if err != nil {
		return err
	}
	mux.HandleFunc("/book/", HandleBook(bookTemplate))

	fs := http.FileServer(http.Dir(dataDir))
	mux.Handle("/public/", http.StripPrefix("/public/", fs))

	if PubliclyAccessible() {
		log.Printf("[WARN] Server is publicly accessible")
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	log.Printf("[INFO] Server is running on %s", addr)

	n := negroni.Classic()
	n.Use(&BasicAuthMiddleware{})
	n.UseHandler(mux)

	server := &http.Server{
		Addr:    addr,
		Handler: n,
	}

	err = server.ListenAndServe()
	if err != nil {
		return err
	}
	return nil
}

var rootCmd = &cobra.Command{
	Use:   "comics",
	Short: "Run the server",
	Long:  "Run the server.",
	RunE: func(cmd *cobra.Command, args []string) error {
		log.Printf("[INFO] Comics %s (%s), built at %s", version.Version, version.Commit, version.BuildDate)
		return RunServer()
	},
}

var hashPasswordCmd = &cobra.Command{
	Use:   "hash-password",
	Short: "Hashes a password and writes the output to stdout, then exits",
	Long:  "Hashes a password and writes the output to stdout, then exits",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Fprintf(os.Stderr, "Password: ")
		password, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return err
		}

		fmt.Fprintf(os.Stderr, "\nConfirmation: ")
		confirmation, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return err
		}

		if string(password) != string(confirmation) {
			return errors.New("Confirmation mismatches password")
		}

		hash, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
		if err != nil {
			return err
		}

		fmt.Fprintf(os.Stderr, "\n")
		fmt.Printf("%s\n", string(hash))

		return nil
	},
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
