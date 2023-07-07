package main

import (
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"comics.app/version"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/gin-gonic/gin"
	"github.com/hashicorp/logutils"
	"github.com/jwalton/go-supportscolor"
	"github.com/spf13/cobra"
)

const (
	RESCAN_INTERVAL = 24 * time.Hour
)

//go:embed assets/*.css templates/*.html
var embeddedFS embed.FS

var (
	dataDir, host                  string
	expectedUsername, passwordHash string
	port                           int
)

var completeVersion = fmt.Sprintf("%s (%s), built at %s", version.Version, version.Commit, version.BuildDate)

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

	rootCmd.AddCommand(hashPasswordCmd)

	serveCmd.Flags().StringVarP(&host, "host", "H", "0.0.0.0", "Host to bind")
	serveCmd.Flags().IntVarP(&port, "port", "p", 8080, "Port to bind")
	serveCmd.Flags().StringVarP(&dataDir, "data", "D", "data", "Data directory")
	serveCmd.Flags().StringVarP(&expectedUsername, "username", "u", os.Getenv("AUTH_USERNAME"), "Basic auth username")
	serveCmd.Flags().StringVar(&passwordHash, "password", os.Getenv("AUTH_PASSWORD_HASH"), "Hashed basic auth password")
	rootCmd.AddCommand(serveCmd)
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

var bookList []Book
var lastScanned time.Time

func ListBooks() error {
	if time.Now().Sub(lastScanned) < RESCAN_INTERVAL {
		log.Printf("[DEBUG] re-use book list scanned at %s\n", lastScanned.Format("2006-01-02T15:04:05-07:00"))
		return nil
	}

	lastScanned = time.Now()
	log.Printf("[DEBUG] scan data directory: %s\n", dataDir)

	bookList = []Book{}

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
			bookList = append(bookList, book)
			return nil
		}
		return nil
	})
	if err != nil {
		return err
	}

	sort.Slice(bookList, func(i, j int) bool {
		return bookList[i].Name < bookList[j].Name
	})

	return nil
}

func PubliclyAccessible() bool {
	return expectedUsername == "" || passwordHash == ""
}

func BasicAuth() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if PubliclyAccessible() {
			ctx.Next()
			return
		}

		username, password, ok := ctx.Request.BasicAuth()
		if !ok { // AUTHORIZE
			ctx.Header("WWW-Authenticate", `Basic realm="Restricted"`)
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if username != expectedUsername { // FAIL
			ctx.Status(http.StatusUnauthorized)
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
		if err != nil { // FAIL
			log.Printf("[ERROR] %v\n", err)
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		ctx.Next() // PASS
	}
}

func RunServer() error {
	if !supportscolor.Stdout().SupportsColor {
		gin.DisableConsoleColor()
	}

	gin.SetMode(gin.ReleaseMode)
	if _, ok := os.LookupEnv("DEBUG"); ok {
		gin.SetMode(gin.DebugMode)
	}

	r := gin.Default()

	templ := template.Must(template.New("").ParseFS(embeddedFS, "templates/*.html"))
	r.SetHTMLTemplate(templ)

	r.Use(BasicAuth())

	r.StaticFS("/static", http.FS(embeddedFS))

	r.StaticFS("/public", http.Dir(dataDir))

	r.GET("/", func(ctx *gin.Context) {
		start := time.Now()
		err := ListBooks()
		if err != nil {
			ctx.String(http.StatusInternalServerError, err.Error())
			return
		}
		elapsed := time.Since(start)
		ctx.HTML(http.StatusOK, "index.html", gin.H{
			"Books":       bookList,
			"Elapsed":     elapsed.Milliseconds(),
			"LastScanned": lastScanned.Format("2006-01-02T15:04:05-07:00"),
			"Version":     completeVersion,
		})
	})

	r.POST("/", func(ctx *gin.Context) {
		log.Printf("[DEBUG] reset last scanned timestamp\n")
		lastScanned = time.UnixMicro(0)
		ctx.Redirect(http.StatusFound, "/")
	})

	r.GET("/book/:name", func(ctx *gin.Context) {
		start := time.Now()
		err := ListBooks()
		if err != nil {
			ctx.String(http.StatusInternalServerError, err.Error())
			return
		}
		elapsed := time.Since(start)
		for _, book := range bookList {
			if book.Name == ctx.Param("name") {
				ctx.HTML(http.StatusOK, "book.html", gin.H{
					"Book":    book,
					"Elapsed": elapsed.Milliseconds(),
					"Version": completeVersion,
				})
				return
			}
		}
		ctx.String(http.StatusNotFound, "404 not found")
	})

	if PubliclyAccessible() {
		log.Printf("[WARN] Server is publicly accessible")
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	log.Printf("[INFO] Server is running on %s", addr)

	err := r.Run(addr)
	if err != nil {
		return err
	}
	return nil
}

var rootCmd = &cobra.Command{
	Use:     "comics",
	Short:   "Simple file server for comic books",
	Long:    "Simple file server for comic books.",
	Version: version.String(),
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run the server",
	Long:  "Run the server.",
	RunE: func(cmd *cobra.Command, args []string) error {
		log.Printf("[INFO] comics %s", version.String())
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
