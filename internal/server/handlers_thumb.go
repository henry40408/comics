package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/henry40408/comics/internal/thumb"
)

// handleThumb serves GET /thumb/{size}/{id}, size being sm or md. A thumbnail
// is generated on first request and cached on disk afterwards.
func (a *App) handleThumb(w http.ResponseWriter, r *http.Request) {
	size := r.PathValue("size")
	limit, allowed := thumb.SizePx(size)
	if !allowed {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	scan, ready := a.readyScan(w)
	if !ready {
		return
	}
	id := r.PathValue("id")
	page, found := scan.PageByID(id)
	if !found {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// id is a scan-issued hex string and size an allowlisted keyword, so the
	// path cannot escape the cache directory.
	cachePath := filepath.Join(a.cfg.CacheDir, size, id+".jpg")
	if cached, err := os.ReadFile(cachePath); err == nil {
		writeJPEG(w, cached)
		return
	}

	// The response is written only after the permit is released, so a slow
	// client cannot starve other thumbnails.
	jpeg, original, err := a.generateBounded(r.Context(), page.Path, limit)
	if r.Context().Err() != nil {
		return
	}
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if original != nil {
		writeBytes(w, thumb.ContentTypeFromPath(page.Path), "no-store", original)
		return
	}
	a.cacheThumb(cachePath, jpeg)
	writeJPEG(w, jpeg)
}

// generateBounded holds a thumbSem permit so opening a book does not spawn a
// decode storm. When the image is undecodable it returns the original bytes
// instead of a thumbnail.
func (a *App) generateBounded(ctx context.Context, path string, limit int) (jpeg, original []byte, err error) {
	select {
	case a.thumbSem <- struct{}{}:
		defer func() { <-a.thumbSem }()
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
	jpeg, err = generateThumb(path, limit)
	if err == nil {
		return jpeg, nil, nil
	}
	a.logger.Debug("thumbnail generation failed; serving original", "err", err, "path", path)
	original, err = os.ReadFile(path)
	return nil, original, err
}

// generateThumb turns a decoder panic on a hostile image into an error, so it
// is served as the original rather than dropping the connection.
func generateThumb(path string, limit int) (jpeg []byte, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("thumbnail decoder panicked: %v", recovered)
		}
	}()
	return thumb.Generate(path, limit)
}

// cacheThumb is best effort: serving succeeds even if the cache directory is
// not writable. The rename keeps a concurrent reader from seeing half a file.
func (a *App) cacheThumb(cachePath string, jpeg []byte) {
	err := writeFileAtomically(cachePath, jpeg)
	if err != nil {
		a.logger.Debug("failed to write thumbnail cache", "err", err, "path", cachePath)
	}
}

func writeFileAtomically(path string, content []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	staged, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(staged.Name()) }()
	if _, err := staged.Write(content); err != nil {
		_ = staged.Close()
		return err
	}
	if err := staged.Close(); err != nil {
		return err
	}
	if err := os.Chmod(staged.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(staged.Name(), path)
}

func writeJPEG(w http.ResponseWriter, jpeg []byte) {
	// private: see handlePage.
	writeBytes(w, "image/jpeg", "private, max-age=31536000, immutable", jpeg)
}
