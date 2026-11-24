package server

import (
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"net/http"
	"os"
	"slices"
	"strconv"

	"github.com/henry40408/comics/internal/models"
	"github.com/henry40408/comics/internal/thumb"
	"github.com/henry40408/comics/internal/views"
)

// writeHTML sends a rendered page. It is the only place comics writes
// text/html, which is how every page ends up no-store (the mux's own redirect
// for an unclean path is the one stdlib exception). The image routes do not
// come through here: they set long-lived private values on purpose, since a
// blanket no-store would re-read every page from disk on every turn.
func writeHTML(w http.ResponseWriter, status int, body string) {
	header := w.Header()
	header.Set("Content-Type", "text/html; charset=utf-8")
	setNoStore(header)
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func (a *App) handleIndex(w http.ResponseWriter, _ *http.Request) {
	scan, ready := a.readyScan(w)
	if !ready {
		return
	}
	writeHTML(w, http.StatusOK, views.IndexPage(views.IndexView{
		Books:        scan.Books,
		ScannedAt:    scan.ScannedAt,
		ScanDuration: scan.ScanDuration,
		AuthEnabled:  a.creds != nil,
	}))
}

// handleBook renders the reader. ?mode=paged|scroll picks the layout, so the
// mode switch works without JavaScript; anything unrecognised renders paged
// rather than a 400.
func (a *App) handleBook(w http.ResponseWriter, r *http.Request) {
	scan, ready := a.readyScan(w)
	if !ready {
		return
	}
	index, found := scan.BooksMap[r.PathValue("id")]
	if !found {
		http.NotFound(w, r)
		return
	}
	writeHTML(w, http.StatusOK, views.BookPage(views.BookView{
		Book:        scan.Books[index],
		AuthEnabled: a.creds != nil,
		Mode:        views.ParseMode(r.URL.Query().Get("mode")),
	}))
}

// handlePage serves a page image. The scan is read through a pointer to an
// immutable value, so no lock is held during the file read.
func (a *App) handlePage(w http.ResponseWriter, r *http.Request) {
	scan, ready := a.readyScan(w)
	if !ready {
		return
	}
	page, found := scan.PageByID(r.PathValue("id"))
	if !found {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	content, err := os.ReadFile(page.Path)
	if errors.Is(err, fs.ErrNotExist) {
		// The file vanished between scan and request: expected, not an error.
		a.logger.Debug("page file no longer exists", "err", err, "path", page.Path)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if err != nil {
		a.logger.Error("failed to read page", "err", err, "path", page.Path)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// private: authenticated content must stay out of shared caches. Not
	// no-store: the browser cache is what keeps slow disks fast.
	writeBytes(w, thumb.ContentTypeFromPath(page.Path), "private, max-age=86400, immutable", content)
}

func writeBytes(w http.ResponseWriter, contentType, cacheControl string, body []byte) {
	header := w.Header()
	header.Set("Content-Type", contentType)
	header.Set("Cache-Control", cacheControl)
	header.Set("Content-Length", strconv.Itoa(len(body)))
	_, _ = w.Write(body)
}

// handleShuffle serves POST /shuffle and POST /shuffle/{id}. It picks any book
// but the one in the path (no path value on the first route, so none is
// excluded), or goes home when none is left.
func (a *App) handleShuffle(w http.ResponseWriter, r *http.Request) {
	scan, ready := a.readyScan(w)
	if !ready {
		return
	}
	excluded := r.PathValue("id")
	candidates := slices.DeleteFunc(slices.Clone(scan.Books), func(book models.Book) bool {
		return book.ID == excluded
	})
	if len(candidates) == 0 {
		seeOther(w, "/")
		return
	}
	seeOther(w, "/book/"+candidates[rand.IntN(len(candidates))].ID)
}

// handleRescan rescans synchronously and always goes home; a failed scan keeps
// the previous one.
func (a *App) handleRescan(w http.ResponseWriter, _ *http.Request) {
	scan, err := models.ScanBooks(a.seed, a.cfg.DataDir, a.logger)
	if err != nil {
		a.logger.Error("failed to re-scan books", "err", err)
		seeOther(w, "/")
		return
	}
	a.logger.Info("re-scan finished", scanFields(scan)...)
	a.storeScan(scan)
	seeOther(w, "/")
}

func (a *App) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scan := a.currentScan()
	if scan == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("null"))
		return
	}
	_, _ = fmt.Fprintf(w, `{"scanned_at":%d}`, scan.ScannedAt.UnixMilli())
}
