package main

import (
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	passwordHashFile               string
	port                           int
)

var completeVersion = fmt.Sprintf("%s (%s), built at %s", version.Version, version.Commit, version.BuildDate)

var (
	ErrRescan = errors.New("Re-scan while scanning")
)

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
	serveCmd.Flags().StringVarP(&passwordHashFile, "password-file", "P", "", "File with hashed basic auth password")
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
	Map         map[string]Book
	LastScanned time.Time
}

var (
	scanning atomic.Bool
	scanned  atomic.Value
)

func ListBooks() error {
	if !scanning.CompareAndSwap(false, true) {
		return ErrRescan
	}
	defer scanning.Store(false)

	firstScan := false
	if o := scanned.Load(); o != nil {
		o1 := o.(*Scanned)
		if time.Now().Sub(o1.LastScanned) < RESCAN_INTERVAL {
			log.Printf("[DEBUG] Re-use book list scanned at %s", o1.LastScanned.Format("2006-01-02T15:04:05-07:00"))
			return nil
		}
	} else {
		firstScan = true
	}

	n := &Scanned{}
	n.LastScanned = time.Now()
	log.Printf("[DEBUG] Scan data directory: %s", dataDir)

	n.List = []Book{}
	n.Map = make(map[string]Book)

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
			log.Printf("[DEBUG] Scan directory: %s", bookName)

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

			// ignore empty directory
			if len(pages) <= 0 {
				log.Printf("[WARN] Ignore empty directory: %s", book.Name)
				return nil
			} else {
				if firstScan {
					log.Printf("[INFO] Found book: %s", book.Name)
				} else {
					log.Printf("[DEBUG] Found book: %s", book.Name)
				}
			}

			sort.Slice(pages, func(i, j int) bool {
				return pages[i].Name < pages[j].Name
			})

			p := pages[0]
			book.PublicCover = p.PublicPath
			log.Printf(`[DEBUG] Set "%s" as cover of "%s"`, p.PublicPath, book.Name)

			book.Pages = pages
			n.List = append(n.List, book)
			n.Map[book.Name] = book
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

func SetPassword() error {
	if passwordHashFile != "" {
		f, err := os.Open(passwordHashFile)
		log.Printf("[DEBUG] Open password hash file: %s", passwordHashFile)
		if err != nil {
			return err
		}
		defer f.Close()
		s, err := io.ReadAll(f)
		if err != nil {
			return err
		}
		passwordHash = strings.TrimSpace(string(s))
	} else if s, ok := os.LookupEnv("AUTH_PASSWORD_HASH"); ok {
		log.Printf("[DEBUG] Set password hash from environment variable")
		passwordHash = s
	}
	return nil
}

func RunServer() error {
	if err := SetPassword(); err != nil {
		return err
	}

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
		if s := scanned.Load(); s != nil {
			s1 := s.(*Scanned)
			ctx.HTML(http.StatusOK, "index.html", gin.H{
				"Books":       s1.List,
				"Elapsed":     s1.Elapsed.Milliseconds(),
				"LastScanned": s1.LastScanned.Format("2006-01-02T15:04:05-07:00"),
				"Scanning":    scanning.Load(),
				"Version":     completeVersion,
			})
			return
		}
		ctx.String(http.StatusNotFound, "comics are not ready")
	})

	r.POST("/shuffle", func(ctx *gin.Context) {
		rand.Seed(time.Now().Unix())
		if s := scanned.Load(); s != nil {
			s1 := s.(*Scanned)
			book := s1.List[rand.Intn(len(s1.List))]
			escaped := strings.Replace(book.Name, "%", "%25", -1) // handle '%'
			ctx.Redirect(http.StatusFound, fmt.Sprintf("/book/%s", escaped))
			return
		}
		ctx.String(http.StatusNotFound, "comics are not ready")
	})

	r.POST("/", func(ctx *gin.Context) {
		log.Printf("[INFO] Force re-scan")
		go func() {
			// reset LastScanned to force re-scan
			if s := scanned.Load(); s != nil {
				log.Printf("[DEBUG] Reset last scanned timestamp\n")
				s1 := s.(*Scanned)
				s1.LastScanned = time.UnixMilli(0)
				scanned.Store(s1)
			}

			start := time.Now()
			err := ListBooks()
			if err != nil {
				log.Printf("[ERROR] Failed to scan comics: %v", err)
				return
			}
			elapsed := time.Since(start)
			log.Printf("[INFO] Re-scan finished: %dms", elapsed.Milliseconds())
		}()
		ctx.Redirect(http.StatusFound, "/")
	})

	r.GET("/book/:name", func(ctx *gin.Context) {
		if s := scanned.Load(); s != nil {
			s1 := s.(*Scanned)
			book, ok := s1.Map[ctx.Param("name")]
			if ok {
				ctx.HTML(http.StatusOK, "book.html", gin.H{
					"Book":    book,
					"Version": completeVersion,
				})
				return
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
		if err != nil {
			log.Printf("[ERROR] Failed to scan comics: %v", err)
			return
		}
		elapsed := time.Since(start)
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
