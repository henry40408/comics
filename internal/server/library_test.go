package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/henry40408/comics/internal/models"
)

func TestGetBooks(t *testing.T) {
	ta := newTestApp(t)
	res := ta.get("/")
	assertStatus(t, 200, res, "GET /")
	for _, want := range []string{
		"2 book(s)",
		"Pepper and Carrot 01 - Potion of Flight",
		"Pepper and Carrot 02 - Rainbow Potions",
	} {
		if !strings.Contains(res.text(), want) {
			t.Errorf("index lacks %q", want)
		}
	}
}

func TestContentRoutesAnswer503UntilTheScanFinishes(t *testing.T) {
	ta := newUnscannedApp(t)
	for _, path := range []string{"/", "/book/" + dataIDs[0], "/data/x", "/thumb/md/x"} {
		assertStatus(t, 503, ta.get(path), "GET "+path)
	}
	for _, path := range []string{"/shuffle", "/shuffle/" + dataIDs[0]} {
		assertStatus(t, 503, ta.post(path), "POST "+path)
	}
}

// The 503 bodies are empty, and the HTML ones stay HTML so no-store applies.
func TestUnavailableBeforeFirstScanHasAnEmptyBody(t *testing.T) {
	ta := newUnscannedApp(t)
	for _, path := range []string{"/", "/book/" + dataIDs[0]} {
		res := ta.get(path)
		if len(res.body) != 0 {
			t.Errorf("GET %s: body %q, want empty", path, res.body)
		}
		if got := res.Header.Get("Content-Type"); got != "text/html; charset=utf-8" {
			t.Errorf("GET %s: content type %q", path, got)
		}
	}
	for _, path := range []string{"/data/x", "/thumb/md/x"} {
		if res := ta.get(path); len(res.body) != 0 {
			t.Errorf("GET %s: body %q, want empty", path, res.body)
		}
	}
}

func TestHealthzBeforeFirstScanIsNullAnd503(t *testing.T) {
	res := newUnscannedApp(t).get("/healthz")
	assertStatus(t, 503, res, "GET /healthz")
	if res.text() != "null" {
		t.Errorf("body %q, want null", res.text())
	}
	if got := res.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("content type %q", got)
	}
}

func TestHealthz(t *testing.T) {
	ta := newTestApp(t)
	before := time.Now().UnixMilli()
	res := ta.get("/healthz")
	assertStatus(t, 200, res, "GET /healthz")
	if got := res.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("content type %q", got)
	}
	var scannedAt int64
	if _, err := fmt.Sscanf(res.text(), `{"scanned_at":%d}`, &scannedAt); err != nil {
		t.Fatalf("body %q: %v", res.text(), err)
	}
	if scannedAt <= 0 || scannedAt > before {
		t.Errorf("scanned_at %d is not a past unix-millis time (now %d)", scannedAt, before)
	}
}

// Not a customised built-in (<time is="...">): WebKit lacks them. Opt-in per
// element, so the duration <time> is left alone.
func TestIndexOptsTimestampsIntoClientSideLocalisation(t *testing.T) {
	html := newTestApp(t).get("/").text()
	if strings.Contains(html, `is="x-time"`) {
		t.Error("index uses a customised built-in")
	}
	if got := strings.Count(html, "data-localtime"); got != 1 {
		t.Errorf("%d data-localtime attributes, want 1", got)
	}
}

// RFC 2822 is not a valid datetime, and new Date() only happens to parse it.
func TestIndexScanTimeHasAValidDatetimeAttribute(t *testing.T) {
	html := newTestApp(t).get("/").text()
	datetime := firstAfter(t, html, `<time data-localtime datetime="`)
	if _, err := time.Parse(time.RFC3339Nano, datetime); err != nil {
		t.Fatalf("not an RFC 3339 date-time: %s", datetime)
	}
	// HTML and ECMAScript's own format take at most three fractional digits.
	_, fraction, _ := strings.Cut(datetime, ".")
	digits := len(fraction) - len(strings.TrimLeft(fraction, "0123456789"))
	if digits = len(fraction) - len(strings.TrimLeft(fraction, "0123456789")); digits > 3 {
		t.Errorf("more than three fractional digits: %s", datetime)
	}
}

// Seconds need the T designator: P0.003S is invalid.
func TestIndexRendersTheScanDurationAsAValidDuration(t *testing.T) {
	html := newTestApp(t).get("/").text()
	duration := firstAfter(t, html, `<time datetime="`)
	if !strings.HasPrefix(duration, "PT") || !strings.HasSuffix(duration, "S") {
		t.Errorf("not a valid duration string: %s", duration)
	}
}

func TestGetBook(t *testing.T) {
	res := newTestApp(t).get("/book/" + dataIDs[0])
	assertStatus(t, 200, res, "GET /book")
	if !strings.Contains(res.text(), "Pepper and Carrot 01 - Potion of Flight") {
		t.Error("book page lacks its title")
	}
}

func TestGetPage(t *testing.T) {
	ta := newTestApp(t)
	// Discovered rather than hard-coded, so fixture changes do not break it.
	pageID := firstAfter(t, ta.get("/book/"+dataIDs[0]).text(), "/data/")
	if pageID == "" {
		t.Fatal("no page image in the book page")
	}
	res := ta.get("/data/" + pageID)
	assertStatus(t, 200, res, "GET /data")
	if !strings.HasPrefix(res.text(), jpegMagic) {
		t.Error("page is not a JPEG")
	}
	if got := res.Header.Get("Content-Type"); got != "image/jpeg" {
		t.Errorf("content type %q", got)
	}
}

func TestPageMissingFileReturns404(t *testing.T) {
	dir := t.TempDir()
	book := filepath.Join(dir, "Temp Book")
	if err := os.Mkdir(book, 0o755); err != nil {
		t.Fatal(err)
	}
	page := filepath.Join(book, "01.jpg")
	copyFile(t, "./fixtures/data/Pepper and Carrot 01 - Potion of Flight/01.jpg", page)
	ta := newTestApp(t, withDataDir(dir))

	id := ta.coverID()
	assertStatus(t, 200, ta.get("/data/"+id), "before removal")
	if err := os.Remove(page); err != nil {
		t.Fatal(err)
	}
	res := ta.get("/data/" + id)
	assertStatus(t, 404, res, "after removal")
	if len(res.body) != 0 {
		t.Errorf("body %q, want empty", res.body)
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	content, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, content, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestThumbnailServesJPEG(t *testing.T) {
	ta := newTestApp(t)
	id := ta.coverID()

	for _, size := range []string{"md", "sm"} {
		res := ta.get("/thumb/" + size + "/" + id)
		assertStatus(t, 200, res, "size "+size)
		if !strings.HasPrefix(res.text(), jpegMagic) {
			t.Errorf("no JPEG magic for %s", size)
		}
	}

	// A regenerated thumbnail could not carry the marker planted in the cache
	// file, so seeing it proves the response came from disk.
	cachePath := filepath.Join(ta.app.cfg.CacheDir, "md", id+".jpg")
	const marker = "served-from-cache"
	generated, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("no cache file after generation: %v", err)
	}
	if !strings.HasPrefix(string(generated), jpegMagic) {
		t.Fatal("cache file is not a JPEG")
	}
	if err := os.WriteFile(cachePath, []byte(marker), 0o644); err != nil {
		t.Fatalf("cannot overwrite cache file: %v", err)
	}
	cached := ta.get("/thumb/md/" + id)
	assertStatus(t, 200, cached, "cached")
	if cached.text() != marker {
		t.Error("thumbnail was regenerated instead of served from the cache")
	}

	assertStatus(t, 404, ta.get("/thumb/xl/"+id), "unknown size")
	assertStatus(t, 404, ta.get("/thumb/md/deadbeef"), "unknown id")
}

func TestThumbnailPermitIsHeldOnlyWhileGenerating(t *testing.T) {
	ta := newTestApp(t)
	app := ta.app
	id := ta.coverID()
	for len(app.thumbSem) < cap(app.thumbSem) {
		app.thumbSem <- struct{}{}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/thumb/md/"+id, nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		app.Handler().ServeHTTP(rec, req)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handler blocked on a full semaphore despite a cancelled request")
	}
	if rec.Body.Len() != 0 {
		t.Errorf("cancelled request wrote %d bytes", rec.Body.Len())
	}

	for len(app.thumbSem) > 0 {
		<-app.thumbSem
	}
	assertStatus(t, 200, ta.get("/thumb/md/"+id), "after draining")
	if got := len(app.thumbSem); got != 0 {
		t.Errorf("%d permits still held after the request", got)
	}
}

func TestUnknownThumbnailSizeIsNotFoundBeforeTheScan(t *testing.T) {
	ta := newUnscannedApp(t)
	assertStatus(t, 404, ta.get("/thumb/lg/x"), "GET /thumb/lg/x")
}

func TestThumbnailFallsBackToOriginalWhenUndecodable(t *testing.T) {
	dir := t.TempDir()
	book := filepath.Join(dir, "Bogus Book")
	if err := os.Mkdir(book, 0o755); err != nil {
		t.Fatal(err)
	}
	page := filepath.Join(book, "01.jpg")
	if err := os.WriteFile(page, []byte("this is not an image"), 0o644); err != nil {
		t.Fatal(err)
	}
	ta := newTestApp(t, withDataDir(dir))
	id := ta.coverID()

	res := ta.get("/thumb/sm/" + id)
	assertStatus(t, 200, res, "fallback")
	if res.text() != "this is not an image" {
		t.Errorf("body %q, want the original bytes", res.body)
	}
	if got := res.Header.Get("Content-Type"); got != "image/jpeg" {
		t.Errorf("content type %q", got)
	}
	if got := res.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("cache control %q", got)
	}

	if err := os.Remove(page); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, 404, ta.get("/thumb/sm/"+id), "original gone")
}

func TestShuffle(t *testing.T) {
	res := newTestApp(t).post("/shuffle")
	assertStatus(t, 303, res, "POST /shuffle")
	id, found := strings.CutPrefix(res.location(), "/book/")
	if !found || !slices.Contains(dataIDs[:], id) {
		t.Errorf("Location %q is not a known book", res.location())
	}
	assertRedirectIsBare(t, res)
}

func TestShuffleFromABook(t *testing.T) {
	res := newTestApp(t).post("/shuffle/" + dataIDs[0])
	assertStatus(t, 303, res, "POST /shuffle/{id}")
	id, found := strings.CutPrefix(res.location(), "/book/")
	if !found {
		t.Fatalf("Location %q", res.location())
	}
	if id == dataIDs[0] || !slices.Contains(dataIDs[:], id) {
		t.Errorf("redirected to %q, want the other book", id)
	}
}

func TestShuffleWithoutOtherBooksGoesHome(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "Only"), 0o755); err != nil {
		t.Fatal(err)
	}
	copyFile(t, "./fixtures/data/Pepper and Carrot 01 - Potion of Flight/01.jpg",
		filepath.Join(dir, "Only", "01.jpg"))
	ta := newTestApp(t, withDataDir(dir))
	onlyID := firstAfter(t, ta.get("/").text(), `href="/book/`)

	if got := ta.post("/shuffle/" + onlyID).location(); got != "/" {
		t.Errorf("Location %q, want /", got)
	}

	empty := newTestApp(t, withDataDir(t.TempDir()))
	if got := empty.post("/shuffle").location(); got != "/" {
		t.Errorf("empty library: Location %q, want /", got)
	}
}

// A redirect is a 303 with only a Location: http.Redirect would add a body.
func assertRedirectIsBare(t *testing.T, res *response) {
	t.Helper()
	if len(res.body) != 0 {
		t.Errorf("redirect body %q, want empty", res.body)
	}
	if got := res.Header.Get("Content-Type"); got != "" {
		t.Errorf("redirect content type %q, want none", got)
	}
}

func TestRescan(t *testing.T) {
	ta := newTestApp(t)
	res := ta.post("/rescan")
	assertStatus(t, 303, res, "POST /rescan")
	if res.location() != "/" {
		t.Errorf("Location %q, want /", res.location())
	}
	assertRedirectIsBare(t, res)
	if !strings.Contains(ta.logs.String(), `msg="re-scan finished"`) {
		t.Errorf("no re-scan log in %s", ta.logs)
	}
}

func TestRescanPicksUpNewBooks(t *testing.T) {
	dir := t.TempDir()
	ta := newTestApp(t, withDataDir(dir))
	if !strings.Contains(ta.get("/").text(), "0 book(s)") {
		t.Fatal("expected an empty library")
	}
	book := filepath.Join(dir, "Late")
	if err := os.Mkdir(book, 0o755); err != nil {
		t.Fatal(err)
	}
	copyFile(t, "./fixtures/data/Pepper and Carrot 01 - Potion of Flight/01.jpg",
		filepath.Join(book, "01.jpg"))

	ta.post("/rescan")
	if !strings.Contains(ta.get("/").text(), "1 book(s)") {
		t.Error("the rescan did not replace the scan")
	}
}

func TestFailedRescanKeepsThePreviousScan(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "Book"), 0o755); err != nil {
		t.Fatal(err)
	}
	copyFile(t, "./fixtures/data/Pepper and Carrot 01 - Potion of Flight/01.jpg",
		filepath.Join(dir, "Book", "01.jpg"))
	ta := newTestApp(t, withDataDir(dir))
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}

	res := ta.post("/rescan")
	assertStatus(t, 303, res, "POST /rescan")
	if res.location() != "/" {
		t.Errorf("Location %q, want /", res.location())
	}
	if !strings.Contains(ta.logs.String(), `msg="failed to re-scan books"`) {
		t.Errorf("no failure log in %s", ta.logs)
	}
	if !strings.Contains(ta.get("/").text(), "1 book(s)") {
		t.Error("the failed rescan dropped the previous scan")
	}
}

func TestInitialScanFailureIsReported(t *testing.T) {
	logs := &syncBuffer{}
	app := New(newConfig(t, logs, []option{withDataDir(filepath.Join(t.TempDir(), "missing"))}))
	if err := app.RunInitialScan(); err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(logs.String(), `msg="initial scan failed"`) {
		t.Errorf("no failure log in %s", logs)
	}
	if app.currentScan() != nil {
		t.Error("a failed scan was stored")
	}
}

func TestInitialScanFinishedLogsCounts(t *testing.T) {
	ta := newTestApp(t)
	logs := ta.logs.String()
	for _, want := range []string{`msg="initial scan finished"`, "books=2", "pages=8", "duration_ms="} {
		if !strings.Contains(logs, want) {
			t.Errorf("log lacks %q: %s", want, logs)
		}
	}
}

func TestBookNotFound(t *testing.T) {
	res := newTestApp(t).get("/book/nonexistent123")
	assertStatus(t, 404, res, "GET /book/nonexistent123")
	if res.text() != "not found" {
		t.Errorf("body %q, want %q", res.text(), "not found")
	}
}

func TestPageNotFound(t *testing.T) {
	res := newTestApp(t).get("/data/nonexistent123")
	assertStatus(t, 404, res, "GET /data/nonexistent123")
	if len(res.body) != 0 {
		t.Errorf("body %q, want empty", res.body)
	}
}

func TestPageContentTypeFollowsTheExtension(t *testing.T) {
	dir := t.TempDir()
	book := filepath.Join(dir, "Mixed")
	if err := os.Mkdir(book, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"a.PNG": "image/png", "b.webp": "image/webp", "c.txt": "application/octet-stream",
	} {
		if err := os.WriteFile(filepath.Join(book, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		_ = want
	}
	ta := newTestApp(t, withDataDir(dir))
	scan := ta.app.currentScan()
	got := map[string]string{}
	for _, page := range scan.Books[0].Pages {
		got[page.Filename] = ta.get("/data/" + page.ID).Header.Get("Content-Type")
	}
	want := map[string]string{
		"a.PNG": "image/png", "b.webp": "image/webp", "c.txt": "application/octet-stream",
	}
	for name, contentType := range want {
		if got[name] != contentType {
			t.Errorf("%s served as %q, want %q", name, got[name], contentType)
		}
	}
}

// The scan is read through a pointer that is replaced, never mutated: readers
// race a rescan without holding the lock across I/O.
func TestScansCanBeReadWhileRescanning(t *testing.T) {
	ta := newTestApp(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 5 {
			ta.post("/rescan")
		}
	}()
	for range 20 {
		assertStatus(t, 200, ta.get("/"), "GET / during rescans")
	}
	<-done
}

func TestCurrentScanIsNilBeforeTheFirstScan(t *testing.T) {
	app := New(Config{DataDir: fixtureData, Secret: mustSecret(testSecret)})
	if app.currentScan() != nil {
		t.Fatal("a scan exists before RunInitialScan")
	}
	app.storeScan(&models.BookScan{})
	if app.currentScan() == nil {
		t.Fatal("the stored scan is missing")
	}
}
