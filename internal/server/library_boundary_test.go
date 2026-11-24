package server

import (
	"strings"
	"testing"
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
