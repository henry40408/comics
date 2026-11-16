package server

import (
	"strings"
	"testing"

	"github.com/henry40408/comics/internal/models"
)

const logoutControl = `data-testid="logout"`

func TestLibraryPagesShowTheLogoutControlOnlyWhenAuthIsEnabled(t *testing.T) {
	bookPath := "/book/" + dataIDs[0]

	open := newTestApp(t)
	for _, path := range []string{"/", bookPath} {
		if strings.Contains(open.get(path).text(), logoutControl) {
			t.Errorf("GET %s shows a logout control without auth", path)
		}
	}

	protected := newTestApp(t, withAuth()).browse()
	assertStatus(t, 303, protected.login(), "login")
	for _, path := range []string{"/", bookPath} {
		if !strings.Contains(protected.get(path).text(), logoutControl) {
			t.Errorf("GET %s has no logout control with auth", path)
		}
	}
}

func TestABookIndexPastTheEndOfTheScanIsNotFound(t *testing.T) {
	ta := newTestApp(t)
	// An index equal to len(Books) is already out of range.
	ta.app.storeScan(&models.BookScan{
		Books:    []models.Book{{}},
		BooksMap: map[string]int{"last": 0, "past": 1},
	})
	assertStatus(t, 200, ta.get("/book/last"), "the last book")
	assertStatus(t, 404, ta.get("/book/past"), "an index equal to len(Books)")
}
