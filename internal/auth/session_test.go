package auth

import (
	"strings"
	"testing"
	"time"
)

const testUA = "Mozilla/5.0 (X11; Linux x86_64)"

// fakeClock is an injectable elapsed-time clock.
type fakeClock struct{ elapsed time.Duration }

func (c *fakeClock) now() time.Duration { return c.elapsed }

func (c *fakeClock) advance(d time.Duration) { c.elapsed += d }

func newTestStore() *SessionStore {
	return NewSessionStore(DefaultIdleTTL, DefaultAbsoluteTTL, nil)
}

func isLive(store *SessionStore, id string) bool {
	return store.Validate(id, testUA).IsValid()
}

func TestACreatedSessionValidates(t *testing.T) {
	store := newTestStore()
	id := store.Create(testUA)
	if !isLive(store, id) {
		t.Fatal("a created session did not validate")
	}
	if store.Len() != 1 {
		t.Fatalf("Len = %d, want 1", store.Len())
	}
}

func TestIdentifiersAreOpaqueAndUnique(t *testing.T) {
	store := newTestStore()
	ids := map[string]bool{}
	for range 100 {
		ids[store.Create(testUA)] = true
	}
	if len(ids) != 100 {
		t.Fatalf("got %d unique ids, want 100", len(ids))
	}
	for id := range ids {
		if !IsSessionID(id) {
			t.Errorf("%q is not a session id", id)
		}
	}
}

func TestDestroyMakesTheIdentifierUseless(t *testing.T) {
	store := newTestStore()
	id := store.Create(testUA)
	if !isLive(store, id) {
		t.Fatal("session should be live")
	}

	if !store.Destroy(id) {
		t.Fatal("Destroy reported the session missing")
	}
	if got := store.Validate(id, testUA); got.Result != ValidationUnknown {
		t.Fatalf("Validate = %+v, want Unknown", got)
	}
	if !store.IsEmpty() {
		t.Fatal("store not empty")
	}
	if store.Destroy(id) {
		t.Fatal("second Destroy reported a session")
	}
}

func TestDestroyAllEndsEverySession(t *testing.T) {
	store := newTestStore()
	phone := store.Create(testUA)
	desktop := store.Create(testUA)
	stolen := store.Create(testUA)

	if got := store.DestroyAll(phone); got != 3 {
		t.Fatalf("DestroyAll = %d, want 3", got)
	}
	for _, id := range []string{desktop, stolen} {
		if got := store.Validate(id, testUA); got.Result != ValidationUnknown {
			t.Fatalf("Validate = %+v, want Unknown", got)
		}
	}
	if !store.IsEmpty() {
		t.Fatal("store not empty")
	}
}

// /logout is public, so membership is the authorisation.
func TestDestroyAllIgnoresAnIdentifierItNeverIssued(t *testing.T) {
	store := newTestStore()
	live := store.Create(testUA)

	if got := store.DestroyAll(strings.Repeat("0", 32)); got != 0 {
		t.Fatalf("DestroyAll = %d, want 0", got)
	}
	if !isLive(store, live) {
		t.Fatal("an outsider ended a live session")
	}
}

func TestAnUnissuedIdentifierIsUnknown(t *testing.T) {
	store := newTestStore()
	if got := store.Validate(strings.Repeat("0", 32), testUA); got.Result != ValidationUnknown {
		t.Fatalf("Validate = %+v, want Unknown", got)
	}
}

func TestIdleExpiryDestroysTheSession(t *testing.T) {
	store := NewSessionStore(0, DefaultAbsoluteTTL, nil)
	id := store.Create(testUA)

	want := Validation{Result: ValidationExpired, Expiry: ExpiryIdle}
	if got := store.Validate(id, testUA); got != want {
		t.Fatalf("Validate = %+v, want %+v", got, want)
	}
	// Expired means gone, not merely refused.
	if !store.IsEmpty() {
		t.Fatal("expired session still stored")
	}
	if got := store.Validate(id, testUA); got.Result != ValidationUnknown {
		t.Fatalf("Validate = %+v, want Unknown", got)
	}
}

func TestAbsoluteExpiryBeatsActivity(t *testing.T) {
	store := NewSessionStore(DefaultIdleTTL, 0, nil)
	id := store.Create(testUA)

	want := Validation{Result: ValidationExpired, Expiry: ExpiryAbsolute}
	if got := store.Validate(id, testUA); got != want {
		t.Fatalf("Validate = %+v, want %+v", got, want)
	}
	if !store.IsEmpty() {
		t.Fatal("expired session still stored")
	}
}

func TestAChangedUserAgentIsReportedButStillValid(t *testing.T) {
	store := newTestStore()
	id := store.Create(testUA)

	if got := store.Validate(id, testUA); !got.IsValid() || got.UserAgentChanged {
		t.Fatalf("same UA: %+v", got)
	}
	if got := store.Validate(id, "curl/8.0"); !got.IsValid() || !got.UserAgentChanged {
		t.Fatalf("changed UA: %+v", got)
	}
	if !isLive(store, id) {
		t.Fatal("session should still be live")
	}
}

func TestAChangedUserAgentIsReportedOnlyOnce(t *testing.T) {
	store := newTestStore()
	id := store.Create(testUA)

	if got := store.Validate(id, "curl/8.0"); !got.UserAgentChanged {
		t.Fatalf("first change not reported: %+v", got)
	}
	for range 5 {
		if got := store.Validate(id, "curl/8.0"); !got.IsValid() || got.UserAgentChanged {
			t.Fatalf("repeat reported again: %+v", got)
		}
	}
}

// Capacity one forces the choice: lastSeen has second resolution, so which of
// several same-second sessions is evicted is arbitrary.
func TestAtCapacityASessionIsEvictedRatherThanTheLoginRefused(t *testing.T) {
	store := newTestStore()
	store.maxSessions = 1

	first := store.Create(testUA)
	second := store.Create(testUA)

	if store.Len() != 1 {
		t.Fatalf("Len = %d, want 1", store.Len())
	}
	if got := store.Validate(first, testUA); got.Result != ValidationUnknown {
		t.Fatalf("first: %+v, want Unknown", got)
	}
	if !isLive(store, second) {
		t.Fatal("second session should be live")
	}
}

func TestEvictionTakesTheLeastRecentlyUsed(t *testing.T) {
	clock := &fakeClock{}
	store := NewSessionStore(DefaultIdleTTL, DefaultAbsoluteTTL, clock.now)
	store.maxSessions = 2

	older := store.Create(testUA)
	clock.advance(10 * time.Second)
	newer := store.Create(testUA)
	clock.advance(10 * time.Second)
	store.Create(testUA)

	if got := store.Validate(older, testUA); got.Result != ValidationUnknown {
		t.Fatalf("older: %+v, want evicted", got)
	}
	if !isLive(store, newer) {
		t.Fatal("newer session should survive")
	}
}

func TestCreatePrunesExpiredSessions(t *testing.T) {
	store := NewSessionStore(0, DefaultAbsoluteTTL, nil)
	for range 5 {
		store.Create(testUA)
	}
	if store.Len() != 1 {
		t.Fatalf("Len = %d, want 1", store.Len())
	}
}

func TestIsSessionIDAcceptsOnlyTheIssuedShape(t *testing.T) {
	store := newTestStore()
	if !IsSessionID(store.Create(testUA)) {
		t.Fatal("an issued id was refused")
	}

	for _, value := range []string{
		"",
		strings.Repeat("0", 31),
		strings.Repeat("0", 33),
		strings.Repeat("0", 31) + "z",
		strings.Repeat("0", 32) + ".1700000000",
	} {
		if IsSessionID(value) {
			t.Errorf("%q accepted", value)
		}
	}
}

// The policy in the doc comments: three days idle, seven days absolute.
func TestTheDefaultLifetimesAreThreeAndSevenDays(t *testing.T) {
	if DefaultIdleTTL != 3*24*time.Hour {
		t.Errorf("idle = %v", DefaultIdleTTL)
	}
	if DefaultAbsoluteTTL != 7*24*time.Hour {
		t.Errorf("absolute = %v", DefaultAbsoluteTTL)
	}
}

func TestAStoreIsEmptyOnlyUntilASessionIsCreated(t *testing.T) {
	store := newTestStore()
	if !store.IsEmpty() {
		t.Fatal("new store not empty")
	}
	store.Create(testUA)
	if store.IsEmpty() {
		t.Fatal("store empty after Create")
	}
}

// Idle time is measured on the store's own clock, so the session must really
// expire once that clock passes the idle window. The injected clock replaces
// the Rust test's two-second sleep.
func TestASessionUnusedForLongerThanTheIdleWindowExpires(t *testing.T) {
	clock := &fakeClock{}
	store := NewSessionStore(time.Second, DefaultAbsoluteTTL, clock.now)
	id := store.Create(testUA)
	if !isLive(store, id) {
		t.Fatal("fresh session should be live")
	}

	clock.advance(2100 * time.Millisecond)

	want := Validation{Result: ValidationExpired, Expiry: ExpiryIdle}
	if got := store.Validate(id, testUA); got != want {
		t.Fatalf("Validate = %+v, want %+v", got, want)
	}
}

// Activity refreshes the idle window but never moves the absolute deadline.
func TestActivityKeepsASessionAliveUntilTheAbsoluteDeadline(t *testing.T) {
	clock := &fakeClock{}
	store := NewSessionStore(time.Hour, 2*time.Hour, clock.now)
	id := store.Create(testUA)

	for range 2 {
		clock.advance(50 * time.Minute)
		if !isLive(store, id) {
			t.Fatal("active session expired early")
		}
	}
	clock.advance(50 * time.Minute)
	want := Validation{Result: ValidationExpired, Expiry: ExpiryAbsolute}
	if got := store.Validate(id, testUA); got != want {
		t.Fatalf("Validate = %+v, want %+v", got, want)
	}
}

func TestMonotonicClockDefaultKeepsSessionsLive(t *testing.T) {
	store := NewSessionStore(DefaultIdleTTL, DefaultAbsoluteTTL, nil)
	id := store.Create(testUA)
	time.Sleep(5 * time.Millisecond)
	if !isLive(store, id) {
		t.Fatal("session expired under the real clock")
	}
}
