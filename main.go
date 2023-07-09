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
	"sync/atomic"
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

type Scanned struct {
	Elapsed     time.Duration
	List        []Book
	LastScanned time.Time
}

var scanned atomic.Value

func ListBooks() error {
	if o := scanned.Load(); o != nil {
		o1 := o.(*Scanned)
		if time.Now().Sub(o1.LastScanned) < RESCAN_INTERVAL {
			log.Printf("[DEBUG] Re-use book list scanned at %s", o1.LastScanned.Format("2006-01-02T15:04:05-07:00"))
			return nil
		}
	}

	n := &Scanned{}
	n.LastScanned = time.Now()
	log.Printf("[DEBUG] Scan data directory: %s", dataDir)

	n.List = []Book{}

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
			log.Printf("[DEBUG] Found book: %s", bookName)

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
						log.Printf("[DEBUG] Found page: %s", imagePath)
						publicPath := filepath.Join(bookName, info.Name())
						pages = append(pages, Page{
							Name:       info.Name(),
							PublicPath: publicPath,
						})
					} else {
						log.Printf("[DEBUG] File is not image: %s", imagePath)
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
				log.Printf(`[DEBUG] Set "%s" as cover of "%s"`, p.PublicPath, bookName)
			}
			book.Pages = pages
			n.List = append(n.List, book)
			return nil
		}
		return nil
	})
	if err != nil {
		return err
	}

	sort.Slice(n.List, func(i, j int) bool {
		return n.List[i].Name < n.List[j].Name
	})

	n.Elapsed = time.Since(n.LastScanned)

	scanned.Store(n)

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
			log.Printf("[ERROR] %v", err)
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
		if o := scanned.Load(); o != nil {
			o1 := o.(*Scanned)
			ctx.HTML(http.StatusOK, "index.html", gin.H{
				"Books":       o1.List,
				"Elapsed":     o1.Elapsed.Milliseconds(),
				"LastScanned": o1.LastScanned.Format("2006-01-02T15:04:05-07:00"),
				"Version":     completeVersion,
			})
			return
		}
		ctx.String(http.StatusNotFound, "comics are not ready")
	})

	r.POST("/", func(ctx *gin.Context) {
		log.Printf("[DEBUG] Reset last scanned timestamp\n")
		go func() {
			// reset LastScanned to force re-scan
			if o := scanned.Load(); o != nil {
				o1 := o.(*Scanned)
				o1.LastScanned = time.UnixMilli(0)
				scanned.Store(o1)
			}

			err := ListBooks()
			if err != nil {
				log.Printf("[ERROR] Failed to scan comics: %v", err)
			}
		}()
		ctx.Redirect(http.StatusFound, "/")
	})

	r.GET("/book/:name", func(ctx *gin.Context) {
		if o := scanned.Load(); o != nil {
			o1 := o.(*Scanned)
			for _, book := range o1.List {
				if book.Name == ctx.Param("name") {
					ctx.HTML(http.StatusOK, "book.html", gin.H{
						"Book":    book,
						"Elapsed": o1.Elapsed.Milliseconds(),
						"Version": completeVersion,
					})
					return
				}
			}
		}
		ctx.String(http.StatusNotFound, "book is not found")
	})

	if PubliclyAccessible() {
		log.Printf("[WARN] Server is publicly accessible")
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	log.Printf("[INFO] Server is running on %s", addr)

	go func() {
		log.Printf("[INFO] Run the first-scan")
		start := time.Now()
		err := ListBooks()
		elapsed := time.Since(start)
		if err != nil {
			log.Printf("[ERROR] Failed to scan comics: %v", err)
			return
		}
		log.Printf("[INFO] First scan finished: %dms", elapsed.Milliseconds())
	}()

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
