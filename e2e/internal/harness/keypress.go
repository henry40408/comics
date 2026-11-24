package harness

import (
	"encoding/json"
	"fmt"
	"slices"
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
// only when the renderer is provably alive (see judgeKey). The scripted key is
// itself checked to have reached the page.
//
// Where nothing can be confirmed (the recorder cannot run under @nojs, or
// could not be armed), the key is sent once, as before.
//
// Residual risk: a real press that arrives after KeySettle is not counted
// against the attempt that sent it, so a toggle key (t, m) could fire twice
// and cancel itself out. The CI fault is "never delivered", not "late", and
// the scenario's own assertion fails loudly if it happens.
func pressUntil(b *Browser, key string) error {
	for attempt := 1; attempt <= KeyAttempts; attempt++ {
		if err := armRecorder(b); err != nil {
			return chromedp.Do(b.ctx, chromedp.KeyEvent(keyText(key)))
		}
		if err := chromedp.Do(b.ctx, chromedp.KeyEvent(keyText(key))); err != nil {
			return err
		}

		probe, err := awaitKey(b, key)
		if err != nil && probe.raw == "" {
			return fmt.Errorf("pressed %q and could not read whether it arrived: %w", key, err)
		}
		switch judgeKey(probe, key) {
		case keyArrived:
			if attempt > 1 {
				logf("e2e: key %q took %d presses", key, attempt)
			}
			return nil
		case keyUnconfirmable:
			return nil
		}
		logf("e2e: press %d of %q did not reach the page; probe=%s", attempt, key, probe.raw)
	}
	return standInForKey(b, key)
}

// standInForKey dispatches the key from script, now that every real press was
// dropped, and checks that the page heard it.
func standInForKey(b *Browser, key string) error {
	if err := scriptedKey(b, key); err != nil {
		return err
	}
	probe, err := readKeyProbe(b)
	if err != nil {
		return fmt.Errorf("dispatched %q from script and could not read whether it arrived: %w", key, err)
	}
	if judgeKey(probe, key) != keyArrived {
		return fmt.Errorf("pressed %q %d times and dispatched it from script, and it never reached the page (probe=%s)",
			key, KeyAttempts, probe.raw)
	}
	logf("e2e: WARNING — stood in for the %q key with a scripted keydown. The "+
		"browser accepted %d real presses and delivered none of them to the "+
		"page, so this scenario did not test that the key is reachable from "+
		"the keyboard.", key, KeyAttempts)
	return nil
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
	// HasFocus and VisibilityState are only for the log line.
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

// keyVerdict is what a probe says about one key press.
type keyVerdict int

const (
	// keyArrived: the recorder heard this key.
	keyArrived keyVerdict = iota
	// keyUnconfirmable: the recorder was not drawing frames (@nojs), so an
	// empty recorder proves nothing.
	keyUnconfirmable
	// keyDropped: the renderer is alive (it drew frames) and the recorder did
	// not hear the key. That is the browser dropping the input, not the page
	// ignoring it, since a page that ignores a key still receives it.
	keyDropped
)

// judgeKey reads a probe taken after pressing key. Focus is not required: keys
// reach the page over the DevTools protocol whichever window has the focus, and
// a suite running Chromes in parallel has most of them without it.
func judgeKey(probe keyProbe, key string) keyVerdict {
	if slices.Contains(probe.Keys, domKey(key)) {
		return keyArrived
	}
	if !probe.recorderRan() {
		return keyUnconfirmable
	}
	return keyDropped
}

// awaitKey polls until the recorder holds the key or KeySettle passes, and
// returns the last probe it read.
func awaitKey(b *Browser, key string) (keyProbe, error) {
	var last keyProbe
	_, err := poll(KeySettle, func() (bool, error) {
		probe, err := readKeyProbe(b)
		if err != nil {
			return false, err
		}
		last = probe
		return judgeKey(probe, key) == keyArrived, nil
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
