package main

import (
	"fmt"
	"io"
	"log/slog"

	"github.com/henry40408/comics/internal/models"
)

// listCommand prints one line per book, then a summary. IDs are not printed,
// so any seed does.
func listCommand(dataDir string, out io.Writer, logger *slog.Logger) error {
	scan, err := models.ScanBooks(0, dataDir, logger)
	if err != nil {
		return err
	}
	totalPages := 0
	for _, book := range scan.Books {
		totalPages += len(book.Pages)
		// Write errors are ignored (e.g. a broken pipe into `head`).
		_, _ = fmt.Fprintf(out, "%s (%dP)\n", book.Title, len(book.Pages))
	}
	_, _ = fmt.Fprintf(out, "%d book(s), %d page(s), scanned in %v\n",
		len(scan.Books), totalPages, scan.ScanDuration)
	return nil
}
