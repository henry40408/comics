package harness

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
)

// KeyAttempts is how many real key presses a shortcut gets before the
// fallback.
const KeyAttempts = 2

// KeySettle is how long one key press gets to reach the page. A key that
// arrived is recorded within milliseconds; waiting longer only delays the
// next attempt.
const KeySettle = 2 * time.Second

// pressUntil types a key and confirms that it reached the page.
//
// It is clickUntil for the keyboard, for the same CI fault: Chrome sometimes
// stops delivering input to the page for the rest of the session, and a
// keyboard shortcut then does nothing for 30 seconds, until the assertion
// that follows gives up. What is confirmed is arrival, not effect: a shortcut
// has no effect of its own to read back here, and a handler that ignores a key
// that did arrive must still fail the scenario.
//
// Once every real press is spent, a keydown is dispatched from script, and
// only when the page is provably alive: the renderer drew frames and the
// recorder still heard no key. Anything else fails with the probe.
//
// Where the recorder cannot run (@nojs), nothing can be confirmed, and the
// key is sent once, as before.
func pressUntil(b *Browser, key string) error {
	var probes []string

	for attempt := 1; attempt <= KeyAttempts; attempt++ {
		// Best-effort: the recorder only feeds diagnostics and the fallback.
		_ = armRecorder(b)
		if err := chromedp.Do(b.ctx, chromedp.KeyEvent(keyText(key))); err != nil {
			return err
		}

		probe, err := awaitKey(b)
		if err != nil && probe.raw == "" {
			return fmt.Errorf("pressed %q and could not read whether it arrived: %w", key, err)
		}
		if len(probe.Keys) > 0 {
			if attempt > 1 {
				logf("e2e: key %q took %d presses", key, attempt)
			}
			return nil
		}
		if !probe.recorderRan() {
			return nil
		}

		logf("e2e: press %d of %q did not reach the page; probe=%s", attempt, key, probe.raw)
		probes = append(probes, probe.raw)
		if attempt < KeyAttempts {
			continue
		}
		if !keyNeverArrived(probe) {
			break
		}
		if err := scriptedKey(b, key); err != nil {
			return err
		}
		logf("e2e: WARNING — stood in for the %q key with a scripted keydown. The "+
			"browser accepted %d real presses and delivered none of them to the "+
			"page, so this scenario did not test that the key is reachable from "+
			"the keyboard. See probe=%s", key, KeyAttempts, probe.raw)
		return nil
	}

	return fmt.Errorf("pressed %q %d times and it never reached the page (%s)",
		key, KeyAttempts, strings.Join(probes, " | "))
}

// keyProbe is what the page reports after a key press.
type keyProbe struct {
	// raw is the probe as JSON, for log lines.
	raw string
	// Keys are the keydown events the recorder saw. Null when no recorder ran.
	Keys []string `json:"keys"`
	// Frames is the recorder's requestAnimationFrame count, telling an empty
	// Keys from a recorder that never ran. Null when no recorder ran.
	Frames *int `json:"frames"`
	// HasFocus and VisibilityState are only for the log line. Focus does not
	// gate delivery here: keys reach the page over the DevTools protocol
	// whichever window has the focus, and a suite running Chromes in parallel
	// has most of them without it.
	HasFocus        bool   `json:"hasFocus"`
	VisibilityState string `json:"visibilityState"`
}

func parseKeyProbe(raw string) (keyProbe, error) {
	probe := keyProbe{raw: raw}
	if err := json.Unmarshal([]byte(raw), &probe); err != nil {
		return keyProbe{}, err
	}
	return probe, nil
}

// recorderRan says whether the recorder was drawing frames. Under @nojs it
// cannot run, so an empty Keys means nothing there.
func (p keyProbe) recorderRan() bool {
	return p.Frames != nil && *p.Frames > 0
}

// keyNeverArrived says whether the browser dropped the key, rather than the
// page being unable to take it: the renderer is alive (it drew frames) and the
// recorder heard nothing.
func keyNeverArrived(probe keyProbe) bool {
	return probe.recorderRan() && len(probe.Keys) == 0
}

// awaitKey polls until the recorder holds a keydown or KeySettle passes, and
// returns the last probe it read.
func awaitKey(b *Browser) (keyProbe, error) {
	var last keyProbe
	_, err := poll(KeySettle, func() (bool, error) {
		probe, err := readKeyProbe(b)
		if err != nil {
			return false, err
		}
		last = probe
		return len(probe.Keys) > 0, nil
	})
	return last, err
}

func readKeyProbe(b *Browser) (keyProbe, error) {
	raw, err := Eval[string](b, `JSON.stringify((() => {
		const rec = window.__e2e;
		return {
			frames: rec ? rec.frames : null,
			keys: rec ? rec.keys : null,
			hasFocus: document.hasFocus(),
			visibilityState: document.visibilityState,
		};
	})())`)
	if err != nil {
		return keyProbe{}, err
	}
	return parseKeyProbe(raw)
}

// scriptedKey dispatches a keydown at the focused element, as a real key
// would be, so a shortcut ignored while a control has focus is ignored here
// too.
func scriptedKey(b *Browser, key string) error {
	_, err := Eval[chromedp.Void](b, `(() => {
		const target = document.activeElement || document.body;
		target.dispatchEvent(new KeyboardEvent('keydown', {
			key: `+jsLiteral(domKey(key))+`, bubbles: true, cancelable: true,
		}));
	})()`)
	return err
}

// domKey is the KeyboardEvent.key a real press of the key produces.
func domKey(key string) string {
	if key == "Space" {
		return " "
	}
	return key
}
