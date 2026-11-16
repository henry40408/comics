package harness

import (
	"errors"
	"testing"
	"time"
)

func TestPollIsDoneWhenTheProbeIsDoneWithoutError(t *testing.T) {
	done, err := poll(time.Second, func() (bool, error) { return true, nil })
	if !done || err != nil {
		t.Fatalf("poll = (%v, %v), want (true, nil)", done, err)
	}
}

func TestPollDoesNotCountADoneProbeThatAlsoFailed(t *testing.T) {
	broken := errors.New("execution context was destroyed")
	calls := 0
	done, err := poll(250*time.Millisecond, func() (bool, error) {
		calls++
		return true, broken
	})
	if done {
		t.Fatal("poll accepted a probe that returned (true, error)")
	}
	if !errors.Is(err, broken) {
		t.Fatalf("poll error = %v, want the probe's error", err)
	}
	if calls < 2 {
		t.Fatalf("probe called %d times, want a retry", calls)
	}
}

func TestPollRecoversOnceTheErrorClears(t *testing.T) {
	calls := 0
	done, err := poll(5*time.Second, func() (bool, error) {
		calls++
		if calls == 1 {
			return true, errors.New("navigating")
		}
		return true, nil
	})
	if !done || err != nil {
		t.Fatalf("poll = (%v, %v), want (true, nil)", done, err)
	}
}
