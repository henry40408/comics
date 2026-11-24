package harness

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
)

// ClickAttempts is how many real clicks a control gets before the fallback.
const ClickAttempts = 3

// ClickSettle is how long one click gets to take effect. A click that worked
// lands promptly, and waiting out the full WaitTimeout would only delay the
// next attempt.
const ClickSettle = 5 * time.Second

// clickSpec says what to click, and how to tell that the page reacted.
type clickSpec struct {
	// what names the control in log lines and errors.
	what string
	// locate finds the element afresh for each attempt.
	locate func() (*Element, error)
	// tookEffect reports whether the page reacted to the click.
	tookEffect func() (bool, error)
}

// clickUntil clicks what locate finds, and confirms tookEffect before
// returning.
//
// A native click reports success once the event is dispatched, which on CI is
// not the same as the page having reacted, for every control, plain <a href>s
// included. So each attempt is checked and repeated.
//
// Retrying alone does not recover: on CI, Chrome sometimes stops delivering
// mouse events to the page for the rest of the session (the first click
// lands, the second or third never arrives). Once every real click is spent,
// probeClickTarget tells that apart from a page fault:
//
//   - The browser dropped the input: the point belongs to the element, the
//     recorder saw nothing, and a scripted click works. The scripted click
//     stands in, with a WARNING, so the scenario keeps testing comics rather
//     than the browser driver.
//   - Anything else fails. A covered control reports hitIsTarget false; one
//     whose handler or href is wrong receives the events and does nothing.
func clickUntil(b *Browser, spec clickSpec) error {
	var probes []string

	for attempt := 1; attempt <= ClickAttempts; attempt++ {
		element, err := spec.locate()
		if err != nil {
			return err
		}
		// Best-effort: the recorder only feeds diagnostics.
		_ = armRecorder(b)
		if err := element.Click(); err != nil {
			return err
		}

		took, settleErr := settled(spec.tookEffect)
		if took {
			if attempt > 1 {
				logf("e2e: %s took %d clicks", spec.what, attempt)
			}
			return nil
		}

		// Logged on the spot: this only happens on CI.
		probe, probeErr := probeClickTarget(element)
		reported := describeProbe(probe, probeErr, settleErr)
		logf("e2e: click %d on %s had no effect; url=%s %s", attempt, spec.what, currentURL(b), reported)
		probes = append(probes, reported)

		if attempt < ClickAttempts {
			continue
		}
		accepted, scripted := standIn(spec, element, probe, probeErr, reported)
		if accepted {
			return nil
		}
		probes = append(probes, "scriptedClick="+scripted.String())
	}

	return fmt.Errorf("clicked %s %d times and it never took effect (%s)",
		spec.what, ClickAttempts, strings.Join(probes, " | "))
}

// standIn is the last resort once every real click is spent: is the browser
// deaf, or the page unresponsive? It reports whether the scripted click may
// stand in for the real ones, and what that click did.
func standIn(spec clickSpec, element *Element, probe clickProbe, probeErr error, reported string) (bool, scriptedResult) {
	nothingArrived := probeErr == nil && inputNeverArrived(probe)
	scripted := scriptedClick(element, spec.tookEffect)
	logf("e2e: scripted click on %s: %s", spec.what, scripted)

	if !nothingArrived || scripted.kind != scriptedTookEffect {
		return false, scripted
	}
	logf("e2e: WARNING — stood in for %s with a scripted click. The "+
		"browser accepted %d real clicks and delivered none "+
		"of them to the page, so this scenario did not test that the "+
		"control is reachable by a pointer. See %s", spec.what, ClickAttempts, reported)
	return true, scripted
}

func describeProbe(probe clickProbe, probeErr, settleErr error) string {
	reported := "probe=" + probe.raw
	if probeErr != nil {
		reported = fmt.Sprintf("probe failed: %v", probeErr)
	}
	if settleErr != nil {
		reported += fmt.Sprintf(" (last check failed: %v)", settleErr)
	}
	return reported
}

func currentURL(b *Browser) string {
	current, err := b.URL()
	if err != nil {
		return fmt.Sprintf("<%v>", err)
	}
	return current.String()
}

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

// clickProbe is what probeClickTarget read back from the page.
type clickProbe struct {
	// raw is the probe as compact JSON, for log lines.
	raw string
	// HitIsTarget: the element at the click point is the target or inside it.
	HitIsTarget bool `json:"hitIsTarget"`
	// Events are the mouse and pointer events the recorder saw. Null when no
	// recorder ran.
	Events []string `json:"events"`
}

// inputNeverArrived says whether the browser dropped the input, rather than
// the page ignoring it.
//
// It requires HitIsTarget (otherwise something covers the element, which is a
// page bug) and no recorded events. With scripts on, an empty recorder is
// proof (frames shows it was live); under @nojs armRecorder cannot run
// (frames 0), so it is only ignorance. Accepting that is deliberate: @nojs
// then rests on HitIsTarget plus a working scripted click, which still fails a
// covered, missing or mis-wired control.
func inputNeverArrived(probe clickProbe) bool {
	return probe.HitIsTarget && len(probe.Events) == 0
}

func parseProbe(raw []byte) (clickProbe, error) {
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return clickProbe{}, err
	}
	probe := clickProbe{raw: compact.String()}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return clickProbe{}, err
	}
	return probe, nil
}

// armRecorder arms the in-page recorder probeClickTarget reads back.
//
//   - events: a capture-phase listener on window records which mouse and
//     pointer events arrived, and where. Empty means the input never reached
//     the renderer; mousedown/mouseup without click would instead suggest a
//     layout shift.
//   - keys: the same for keydown, which pressUntil reads back.
//   - frames: a requestAnimationFrame count, telling an empty events from a
//     recorder that never ran. On the CI failures it reads 300-plus: a
//     renderer drawing at 60fps and receiving nothing. (The probe's hasFocus
//     and visibilityState also come back affirmative there, ruling out what
//     the flags in allocatorOptions address.)
//
// Installed once and reset per attempt; re-registering would duplicate every
// event. Mute under @nojs: evaluating still runs there, but the listener and
// frame callback are document script, which the emulation stops.
func armRecorder(b *Browser) error {
	_, err := chromedp.Run(b.ctx, chromedp.Evaluate[chromedp.Void](`(() => {
		if (window.__e2e) {
			window.__e2e.events.length = 0;
			window.__e2e.keys.length = 0;
			window.__e2e.frames = 0;
			return;
		}
		const state = { events: [], keys: [], frames: 0 };
		window.__e2e = state;
		window.addEventListener('keydown', (e) => {
			if (state.keys.length < 24) { state.keys.push(e.key); }
		}, true);
		const name = (n) => n === null ? null : n.tagName.toLowerCase()
			+ (n.id ? '#' + n.id : '')
			+ (n.getAttribute('data-testid') ? '@' + n.getAttribute('data-testid') : '');
		for (const type of ['pointerdown', 'mousedown', 'mouseup', 'pointerup', 'click']) {
			window.addEventListener(type, (e) => {
				if (state.events.length < 24) {
					state.events.push(type + ':' + name(e.target)
						+ '@' + Math.round(e.clientX) + ',' + Math.round(e.clientY));
				}
			}, true);
		}
		const tick = () => { state.frames++; requestAnimationFrame(tick); };
		requestAnimationFrame(tick);
	})()`))
	return err
}

// probeClickTarget asks the page what is at the element's centre
// (elementFromPoint, which works under @nojs too) and what armRecorder
// collected.
//
// A "Cannot find context" error means the click did navigate, and the
// caller's tookEffect is what is wrong.
func probeClickTarget(element *Element) (clickProbe, error) {
	raw, err := callOn[[]byte](element, `function() {
		const el = this;
		if (!el || !el.isConnected) { return { connected: false }; }
		const r = el.getBoundingClientRect();
		const x = r.left + r.width / 2, y = r.top + r.height / 2;
		const hit = document.elementFromPoint(x, y);
		const name = (n) => n === null ? null : n.tagName.toLowerCase()
			+ (n.id ? '#' + n.id : '')
			+ (n.getAttribute('data-testid') ? '@' + n.getAttribute('data-testid') : '');
		const style = getComputedStyle(el);
		const rec = window.__e2e;
		return {
			connected: true,
			ready: document.readyState,
			rect: [r.x, r.y, r.width, r.height],
			point: [x, y],
			viewport: [window.innerWidth, window.innerHeight],
			scroll: [window.scrollX, window.scrollY],
			hit: name(hit),
			hitIsTarget: hit === null ? false : (hit === el || el.contains(hit)),
			visibility: style.visibility,
			pointerEvents: style.pointerEvents,
			hasFocus: document.hasFocus(),
			visibilityState: document.visibilityState,
			frames: rec ? rec.frames : null,
			events: rec ? rec.events : null,
		};
	}`)
	if err != nil {
		return clickProbe{}, err
	}
	return parseProbe(raw)
}

type scriptedKind int

const (
	// scriptedTookEffect: the page reacted, so only the native input was missing.
	scriptedTookEffect scriptedKind = iota
	// scriptedNoEffect: the page ignored this too, so the control, not the
	// browser, is the problem.
	scriptedNoEffect
	// scriptedUnanswered: the question could not be put, because the element
	// or the browser was gone.
	scriptedUnanswered
)

// scriptedResult is what a scripted click on the same element did.
type scriptedResult struct {
	kind scriptedKind
	why  string
}

func (r scriptedResult) String() string {
	switch r.kind {
	case scriptedTookEffect:
		return "took effect"
	case scriptedNoEffect:
		return "no effect either"
	}
	return "unanswered: " + r.why
}

// scriptedClick clicks the element from script, and reports whether that took
// effect.
//
// It calls click(), which covers link and form activation and every click
// listener (the reader's tap zones included). Only trust it together with
// inputNeverArrived: alone it bypasses hit-testing, and the suite would stop
// testing that controls are reachable.
func scriptedClick(element *Element, tookEffect func() (bool, error)) scriptedResult {
	if _, err := callOn[chromedp.Void](element, "function() { this.click(); }"); err != nil {
		return scriptedResult{kind: scriptedUnanswered, why: err.Error()}
	}
	took, err := settled(tookEffect)
	switch {
	case took:
		return scriptedResult{kind: scriptedTookEffect}
	case err != nil:
		return scriptedResult{kind: scriptedUnanswered, why: err.Error()}
	}
	return scriptedResult{kind: scriptedNoEffect}
}

// settled polls tookEffect for ClickSettle. An error is "not yet", as in
// Eventually; the last one is returned with a false result so the caller can
// report it.
func settled(tookEffect func() (bool, error)) (bool, error) {
	return poll(ClickSettle, tookEffect)
}
