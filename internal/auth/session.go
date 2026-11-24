// Package auth holds comics' authentication: server-side sessions, signed
// session cookies, the login rate limiter, trusted-proxy handling and the
// Argon2id password check. It owns no HTTP routing; the server package wires
// these pieces into handlers.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"
)

// sessionIDBytes is 128 bits: the OWASP Session Management Cheat Sheet's minimum.
const sessionIDBytes = 16

// SessionIDHexLen is the length of an issued session identifier.
const SessionIDHexLen = sessionIDBytes * 2

// userAgentDigestBytes: the digest is only ever compared, so eight bytes are
// ample, and exactly a uint64 so it fits an atomic.
const userAgentDigestBytes = 8

// DefaultIdleTTL is far above OWASP's 15-30 minutes: a reader is opened, left
// and returned to, and a short window would push the one user toward a weaker
// password. Three days still bounds a session abandoned on a borrowed device.
const DefaultIdleTTL = 72 * time.Hour

// DefaultAbsoluteTTL is the hard ceiling on a session's age regardless of
// activity.
const DefaultAbsoluteTTL = 7 * 24 * time.Hour

// defaultMaxSessions is a memory backstop, unreachable in practice (only
// successful logins grow the store). When full, the least recently used
// session is evicted; refusing would be a login lockout.
const defaultMaxSessions = 1000

// Validation is what SessionStore.Validate decided. The zero value is not
// valid, so a forgotten field fails closed.
type Validation struct {
	Valid bool
	// UserAgentChanged is set on a valid session whose User-Agent differs from
	// the last one seen. Reported, never enforced: browsers change it every
	// major version, and an attacker need only copy the header.
	UserAgentChanged bool
	// Rejection is why the session is not valid.
	Rejection Rejection
}

type sessionRecord struct {
	createdAt time.Duration
	// lastSeen is whole seconds since the store's clock origin at the most
	// recent request. Atomic so refreshing needs only a read lock: every image
	// request passes the auth middleware, and a write lock each would
	// serialise them.
	lastSeen atomic.Int64
	// userAgent is the digest of the last User-Agent seen. Swapped, not just
	// compared, so a change is reported once rather than on every image request.
	userAgent atomic.Uint64
}

// SessionStore holds the live sessions, in memory only.
//
// Sessions do not survive a restart. That is the price of server-side state,
// which is what makes logout enforceable: a self-describing signed cookie
// cannot be revoked short of rotating COMICS_SECRET, which also changes every
// book and page URL.
type SessionStore struct {
	mu          sync.RWMutex
	sessions    map[string]*sessionRecord
	clock       func() time.Duration
	idleTTL     time.Duration
	absoluteTTL time.Duration
	maxSessions int
}

// NewSessionStore builds an empty store. clock reports the time elapsed since
// some fixed origin; nil means real monotonic time since this call. Tests pass
// their own to move time without sleeping.
func NewSessionStore(idleTTL, absoluteTTL time.Duration, clock func() time.Duration) *SessionStore {
	if clock == nil {
		clock = monotonicClock()
	}
	return &SessionStore{
		sessions:    make(map[string]*sessionRecord),
		clock:       clock,
		idleTTL:     idleTTL,
		absoluteTTL: absoluteTTL,
		maxSessions: defaultMaxSessions,
	}
}

func monotonicClock() func() time.Duration {
	start := time.Now()
	return func() time.Duration { return time.Since(start) }
}

func (s *SessionStore) nowSecs() int64 { return int64(s.clock() / time.Second) }

// Create opens a session. The identifier is random hex with no structure; all
// state lives in the store.
func (s *SessionStore) Create(userAgent string) string {
	var raw [sessionIDBytes]byte
	_, _ = rand.Read(raw[:])
	id := hex.EncodeToString(raw[:])

	record := &sessionRecord{createdAt: s.clock()}
	record.lastSeen.Store(s.nowSecs())
	record.userAgent.Store(userAgentDigest(userAgent))

	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropExpired()
	if len(s.sessions) >= s.maxSessions {
		s.evictOldest()
	}
	s.sessions[id] = record
	return id
}

// Validate looks id up, refreshing its idle window when still valid. An
// expired session is destroyed immediately, not left to the next prune.
func (s *SessionStore) Validate(id, userAgent string) Validation {
	s.mu.RLock()
	record := s.sessions[id]
	s.mu.RUnlock()
	if record == nil {
		return Validation{Rejection: RejectionUnknown}
	}

	if s.clock()-record.createdAt >= s.absoluteTTL {
		s.Destroy(id)
		return Validation{Rejection: RejectionExpiredAbsolute}
	}
	now := s.nowSecs()
	if s.isIdle(record, now) {
		s.Destroy(id)
		return Validation{Rejection: RejectionExpiredIdle}
	}

	record.lastSeen.Store(now)
	digest := userAgentDigest(userAgent)
	return Validation{
		Valid:            true,
		UserAgentChanged: record.userAgent.Swap(digest) != digest,
	}
}

// Destroy ends one session and reports whether it existed.
func (s *SessionStore) Destroy(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, existed := s.sessions[id]
	delete(s.sessions, id)
	return existed
}

// DestroyAll ends every live session, but only when id names one of them.
// Logout calls this: one set of credentials means every session is the same
// person's, and it is the only way to kill a stolen cookie short of a restart.
//
// Membership is the authorisation. /logout is public and the CSRF guard passes
// header-less clients, so an unconditional clear would let any anonymous
// POST /logout sign everyone out.
func (s *SessionStore) DestroyAll(id string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, member := s.sessions[id]; !member {
		return 0
	}
	ended := len(s.sessions)
	clear(s.sessions)
	return ended
}

// Len is the number of live sessions.
func (s *SessionStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

// IsEmpty reports whether no session is live.
func (s *SessionStore) IsEmpty() bool { return s.Len() == 0 }

func (s *SessionStore) isIdle(record *sessionRecord, nowSecs int64) bool {
	idleFor := max(nowSecs-record.lastSeen.Load(), 0)
	return idleFor >= int64(s.idleTTL/time.Second)
}

// dropExpired must be called with the write lock held.
func (s *SessionStore) dropExpired() {
	now := s.nowSecs()
	elapsed := s.clock()
	for id, record := range s.sessions {
		pastCeiling := elapsed-record.createdAt >= s.absoluteTTL
		if pastCeiling || s.isIdle(record, now) {
			delete(s.sessions, id)
		}
	}
}

// evictOldest drops the least recently used session. Must be called with the
// write lock held.
func (s *SessionStore) evictOldest() {
	oldestID := ""
	var oldestSeen int64
	for id, record := range s.sessions {
		seen := record.lastSeen.Load()
		if oldestID == "" || seen < oldestSeen {
			oldestID, oldestSeen = id, seen
		}
	}
	delete(s.sessions, oldestID)
}

// userAgentDigest is a truncated SHA-256 of a User-Agent, for comparison only.
func userAgentDigest(userAgent string) uint64 {
	sum := sha256.Sum256([]byte(userAgent))
	return binary.BigEndian.Uint64(sum[:userAgentDigestBytes])
}

// IsSessionID is a shape check only, so a malformed cookie is refused without
// taking the store's lock.
func IsSessionID(value string) bool {
	if len(value) != SessionIDHexLen {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
