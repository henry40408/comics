package harness

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/chromedp"
	"github.com/chromedp/chromedp/kb"
)

// ScenarioTimeout bounds one scenario, so a wedged Chrome cannot hang the run.
const ScenarioTimeout = 3 * time.Minute

const (
	windowWidth  = 1280
	windowHeight = 720
	closeTimeout = 10 * time.Second
)

// Scripting says whether the page's own scripts run: the @nojs split.
type Scripting bool

const (
	// ScriptingEnabled is the scripted path: app.js and theme.js run.
	ScriptingEnabled Scripting = true
	// ScriptingDisabled is the @nojs path: the page's own scripts never run.
	ScriptingDisabled Scripting = false
)

// ResourceAudit is what AuditResources found.
type ResourceAudit struct {
	// Images is how many <img> the page has.
	Images int `json:"images"`
	// Undecodable lists images the browser could not decode.
	Undecodable []string `json:"undecodable"`
	// Failed lists same-origin requests that failed, with their status.
	Failed []string `json:"failed"`
	// Linked lists the paths of every same-origin resource the page loaded.
	Linked []string `json:"linked"`
}

// Browser is a headless Chrome of its own, scoped to one scenario.
//
// One process per scenario isolates cookies and localStorage, and lets @nojs
// disable scripting before the first document exists.
type Browser struct {
	ctx    context.Context
	cancel context.CancelFunc
}

// Open starts a headless Chrome with the page's scripts on or off.
func Open(scripting Scripting) (*Browser, error) {
	timeoutCtx, cancelTimeout := context.WithTimeout(context.Background(), ScenarioTimeout)
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(timeoutCtx, allocatorOptions()...)
	tabCtx, cancelTab := chromedp.NewContext(allocCtx)
	browser := &Browser{
		ctx: tabCtx,
		cancel: func() {
			cancelTab()
			cancelAlloc()
			cancelTimeout()
		},
	}

	if err := browser.start(scripting); err != nil {
		browser.cancel()
		return nil, err
	}
	return browser, nil
}

// ChromeEnv names the variable that pins the browser binary.
const ChromeEnv = "E2E_CHROME"

// BrowserChoice says which browser Open will start, for the run's log.
func BrowserChoice() string {
	if path := os.Getenv(ChromeEnv); path != "" {
		return ChromeEnv + "=" + path
	}
	return "chromedp's default search (" + ChromeEnv + " is unset)"
}

func allocatorOptions() []chromedp.ExecAllocatorOption {
	// The defaults already carry what the suite needs: headless,
	// no /dev/shm use, and no throttling of a backgrounded renderer (which
	// starves input while CDP script keeps answering, the shape of the clicks
	// CI drops).
	options := append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...)
	options = append(options, chromedp.WindowSize(windowWidth, windowHeight))
	// chromedp's own search prefers a chromium on PATH over google-chrome, so
	// CI pins the binary it reports.
	if path := os.Getenv(ChromeEnv); path != "" {
		options = append(options, chromedp.ExecPath(path))
	}
	return options
}

func (b *Browser) start(scripting Scripting) error {
	if err := chromedp.Do(b.ctx); err != nil {
		return fmt.Errorf("could not start a browser (%s): a local Chromium or Chrome is required "+
			"(`brew install --cask ungoogled-chromium`), or set %s to its path: %w", BrowserChoice(), ChromeEnv, err)
	}
	if err := b.ResetViewport(); err != nil {
		return err
	}
	if scripting == ScriptingEnabled {
		return nil
	}
	return b.disableScripting()
}

// Close ends the browser, and the profile directory goes with it.
func (b *Browser) Close() {
	closing, cancel := context.WithTimeout(b.ctx, closeTimeout)
	defer cancel()
	_ = chromedp.Cancel(closing)
	b.cancel()
}

// disableScripting stops the page's own scripts from running.
//
// It takes effect on the next document, so it runs before the first
// navigation, which is why browsers are per scenario rather than shared.
// Evaluating from CDP still works while scripting is disabled.
func (b *Browser) disableScripting() error {
	return send(b, emulation.SetScriptExecutionDisabled, emulation.SetScriptExecutionDisabledParams{Value: true})
}

// EmulateColorScheme emulates prefers-color-scheme with no stored
// preference: the app's system-follow path, which is what the screenshots are
// meant to show.
func (b *Browser) EmulateColorScheme(scheme string) error {
	return send(b, emulation.SetEmulatedMedia, emulation.SetEmulatedMediaParams{
		Media:    "screen",
		Features: []*emulation.MediaFeature{{Name: "prefers-color-scheme", Value: scheme}},
	})
}

// StretchViewportTo grows the viewport to height, so a screenshot catches the
// whole page.
func (b *Browser) StretchViewportTo(height int64) error {
	return b.setViewport(max(height, windowHeight))
}

// ResetViewport sets the viewport to exactly the window size.
//
// The window size flag alone leaves the viewport shorter than 720 px (the
// window's own chrome counts), and clearing the override is asynchronous, so
// the override is applied again instead.
func (b *Browser) ResetViewport() error {
	return b.setViewport(windowHeight)
}

func (b *Browser) setViewport(height int64) error {
	return send(b, emulation.SetDeviceMetricsOverride, emulation.SetDeviceMetricsOverrideParams{
		Width:             windowWidth,
		Height:            height,
		DeviceScaleFactor: 1,
	})
}

func send[P any](b *Browser, command cdp.Command[P, cdp.Empty], params P) error {
	_, err := chromedp.Call(b.ctx, command, params)
	return err
}

// Goto navigates to a path on the server and waits for the page to load.
func (b *Browser) Goto(path string) error {
	return chromedp.Do(b.ctx, chromedp.Navigate(BaseURL+path))
}

// Reload reloads the page and waits for it to load.
func (b *Browser) Reload() error {
	if err := chromedp.Do(b.ctx, chromedp.Reload()); err != nil {
		return err
	}
	return b.WaitForLoad()
}

// WaitForLoad waits for document.readyState to be "complete".
//
// CDP does not wait for a page load after a click, so every read or action
// that follows a navigation waits first. Without it, a key press can run
// before app.js has loaded, and a lookup can run against the old document.
func (b *Browser) WaitForLoad() error {
	return Eventually("the page to finish loading", func() (bool, error) {
		state, err := Eval[string](b, "document.readyState")
		return state == "complete", err
	})
}

// DocumentID identifies the current document: it differs after any
// navigation, even one back to the same URL.
func (b *Browser) DocumentID() (float64, error) {
	return Eval[float64](b, "performance.timeOrigin")
}

// URL is the page's current URL.
func (b *Browser) URL() (*url.URL, error) {
	location, err := chromedp.Run(b.ctx, chromedp.Location())
	if err != nil {
		return nil, err
	}
	return url.Parse(location)
}

// Path is the current URL's path, the shape the steps assert against.
func (b *Browser) Path() (string, error) {
	current, err := b.URL()
	if err != nil {
		return "", err
	}
	return current.Path, nil
}

// PathAndQuery is the current URL's path with its query, if any.
func (b *Browser) PathAndQuery() (string, error) {
	current, err := b.URL()
	if err != nil {
		return "", err
	}
	return current.RequestURI(), nil
}

// IsInViewport reports whether the element with the id intersects the
// viewport. Any overlap counts.
func (b *Browser) IsInViewport(id string) (bool, error) {
	visible, err := Eval[*bool](b, `(() => {
		const el = document.getElementById(`+jsLiteral(id)+`);
		if (!el) { return null; }
		const r = el.getBoundingClientRect();
		return r.bottom > 0 && r.right > 0
			&& r.top < window.innerHeight && r.left < window.innerWidth;
	})()`)
	if err != nil {
		return false, err
	}
	if visible == nil {
		return false, fmt.Errorf("no element with id `%s`", id)
	}
	return *visible, nil
}

// Theme is the value of <html data-theme>, empty when unset.
func (b *Browser) Theme() (string, error) {
	return Eval[string](b, "document.documentElement.getAttribute('data-theme') ?? ''")
}

// Press types a key at the page, as a reader would, and confirms that the
// page received it (see pressUntil).
func (b *Browser) Press(key string) error {
	if err := b.WaitForLoad(); err != nil {
		return err
	}
	return pressUntil(b, key)
}

func keyText(key string) string {
	switch key {
	case "ArrowLeft":
		return kb.ArrowLeft
	case "ArrowRight":
		return kb.ArrowRight
	case "Home":
		return kb.Home
	case "End":
		return kb.End
	case "Space":
		return " "
	}
	return key
}

// AuditResources counts the page's images and lists what the server failed to
// answer.
//
// Not fetch: the CSP has no connect-src. Lazy images are forced to load
// first, so every src is exercised; the failures come from the browser's own
// resource timings, so stylesheets and scripts are covered too. Same-origin
// only: the webfont host is not ours.
func (b *Browser) AuditResources() (ResourceAudit, error) {
	audit, err := chromedp.Run(b.ctx, chromedp.Evaluate[ResourceAudit](`(async () => {
		document.querySelectorAll('img[loading=lazy]').forEach((i) => { i.loading = 'eager'; });
		const images = [...document.images];
		const ok = await Promise.all(images.map((i) => i.decode().then(() => true, () => false)));
		const own = performance.getEntriesByType('resource').filter((e) => e.name.startsWith(location.origin));
		return {
			images: images.length,
			undecodable: images.filter((_, k) => !ok[k]).map((i) => i.src),
			failed: own.filter((e) => e.responseStatus >= 400 || e.responseStatus === 0)
				.map((e) => e.name + ' -> ' + e.responseStatus),
			linked: own.map((e) => new URL(e.name).pathname),
		};
	})()`, chromedp.EvalAwaitPromise))
	if err != nil {
		return ResourceAudit{}, err
	}
	return audit, nil
}

// InlineCodeCount is how many <script> and <style> elements have no external
// source. The CSP has no 'unsafe-inline', so each would be blocked.
func (b *Browser) InlineCodeCount() (int, error) {
	return Eval[int](b, "document.querySelectorAll('script:not([src]), style').length")
}

// Screenshot captures the viewport as a PNG.
func (b *Browser) Screenshot() ([]byte, error) {
	return chromedp.Run(b.ctx, chromedp.CaptureScreenshot())
}

// Eval evaluates a JavaScript expression in the page and decodes the result.
//
// Reads go through JavaScript rather than DOM-domain queries, because
// chromedp's queries wait forever by default and the suite's lookups are
// immediate. It also runs under @nojs, which is not subject to the page CSP.
func Eval[T any](b *Browser, expression string) (T, error) {
	return chromedp.Run(b.ctx, chromedp.Evaluate[T](expression))
}

// jsLiteral renders a Go value as a JavaScript literal.
func jsLiteral(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		// Only strings, numbers and bools are passed; this cannot happen.
		panic(fmt.Sprintf("encoding %v as a JavaScript literal: %v", value, err))
	}
	return string(encoded)
}
