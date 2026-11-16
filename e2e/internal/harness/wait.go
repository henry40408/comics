package harness

import (
	"fmt"
	"time"
)

// WaitTimeout is how long a query waits for a condition before giving up.
//
// Only a genuine failure pays it in full, so it is sized for a two-core CI
// runner driving several browsers, where 10 s was not enough.
const WaitTimeout = 30 * time.Second

// WaitInterval is how often a query re-checks while waiting.
const WaitInterval = 100 * time.Millisecond

// poll calls probe until it reports done or the timeout passes. An error from
// probe means "not yet", never a failure: during a navigation the page
// evaluates nothing ("Execution context was destroyed"), and the next poll
// succeeds. A probe that reports done together with an error is not done: its
// value is a zero value read from a page that was not there. The last error is
// returned so a timeout still names its cause.
func poll(timeout time.Duration, probe func() (bool, error)) (bool, error) {
	deadline := time.Now().Add(timeout)
	for {
		done, err := probe()
		if done && err == nil {
			return true, nil
		}
		if time.Now().After(deadline) {
			return false, err
		}
		time.Sleep(WaitInterval)
	}
}

// Eventually polls probe until it reports true.
func Eventually(what string, probe func() (bool, error)) error {
	done, lastErr := poll(WaitTimeout, probe)
	if done {
		return nil
	}
	if lastErr != nil {
		return fmt.Errorf("%s: still not true after %v, last error: %w", what, WaitTimeout, lastErr)
	}
	return fmt.Errorf("%s: still not true after %v", what, WaitTimeout)
}

// EventuallyEq polls probe until it reports the expected value; on timeout
// the error names the last value seen.
func EventuallyEq[T comparable](what string, expected T, probe func() (T, error)) error {
	var last T
	var seen bool
	done, lastErr := poll(WaitTimeout, func() (bool, error) {
		value, err := probe()
		if err != nil {
			return false, err
		}
		last, seen = value, true
		return value == expected, nil
	})
	if done {
		return nil
	}
	if !seen {
		return fmt.Errorf("%s: expected %v, never read a value in %v: %w", what, expected, WaitTimeout, lastErr)
	}
	if lastErr != nil {
		return fmt.Errorf("%s: expected %v, last saw %v after %v (last error: %w)", what, expected, last, WaitTimeout, lastErr)
	}
	return fmt.Errorf("%s: expected %v, last saw %v after %v", what, expected, last, WaitTimeout)
}
