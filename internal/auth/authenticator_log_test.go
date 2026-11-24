package auth

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

type logLine struct {
	Level     string `json:"level"`
	Event     string `json:"event"`
	Reason    string `json:"reason"`
	Session   string `json:"session"`
	UserAgent string `json:"user_agent"`
}

func attachDebugLogger(a *Authenticator) *bytes.Buffer {
	var buffer bytes.Buffer
	a.Logger = slog.New(slog.NewJSONHandler(&buffer, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return &buffer
}

func parseLogLines(t *testing.T, buffer *bytes.Buffer) []logLine {
	t.Helper()
	var lines []logLine
	for _, raw := range strings.Split(strings.TrimSpace(buffer.String()), "\n") {
		if raw == "" {
			continue
		}
		var line logLine
		if err := json.Unmarshal([]byte(raw), &line); err != nil {
			t.Fatalf("log line %q: %v", raw, err)
		}
		lines = append(lines, line)
	}
	return lines
}

func TestLogRejectionRecordsEachReasonAtItsLevel(t *testing.T) {
	key := randomSessionKey(t)
	cases := []struct {
		name       string
		why        Rejection
		wantLevel  string
		wantEvent  string
		wantReason string
		withID     bool
	}{
		{"idle expiry", RejectionExpiredIdle, "INFO", "session_expired", "idle", true},
		{"absolute expiry", RejectionExpiredAbsolute, "INFO", "session_expired", "absolute", true},
		{"malformed", RejectionMalformed, "WARN", "session_rejected", "malformed", false},
		{"unknown", RejectionUnknown, "DEBUG", "session_rejected", "unknown", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newTestAuthenticator(t, key)
			buffer := attachDebugLogger(a)
			id := a.Sessions.Create("test-agent")
			request := requestFor(key, id)
			request.Header.Set("User-Agent", "audit-agent")

			a.LogRejection(request, tc.why)

			lines := parseLogLines(t, buffer)
			if len(lines) != 1 {
				t.Fatalf("got %d log lines: %s", len(lines), buffer.String())
			}
			got := lines[0]
			if got.Level != tc.wantLevel || got.Event != tc.wantEvent ||
				got.Reason != tc.wantReason || got.UserAgent != "audit-agent" {
				t.Fatalf("line = %+v", got)
			}
			if tc.withID && got.Session != a.Salt.Fingerprint(id) {
				t.Fatalf("session = %q, want the salted fingerprint", got.Session)
			}
			if strings.Contains(buffer.String(), id) {
				t.Fatalf("session ID appears in cleartext: %s", buffer.String())
			}
		})
	}
}

func TestLogRejectionIsSilentWhenTheCookieIsAbsentOrThereWasNoRejection(t *testing.T) {
	a := newTestAuthenticator(t, randomSessionKey(t))
	buffer := attachDebugLogger(a)
	a.LogRejection(requestWithCookie(""), RejectionAbsent)
	a.LogRejection(requestWithCookie(""), RejectionNone)
	if buffer.Len() != 0 {
		t.Fatalf("log = %s", buffer.String())
	}
}

func TestLogUserAgentChangedWarnsWithoutLeakingTheSessionID(t *testing.T) {
	key := randomSessionKey(t)
	a := newTestAuthenticator(t, key)
	buffer := attachDebugLogger(a)
	id := a.Sessions.Create("original-agent")
	request := requestFor(key, id)
	request.Header.Set("User-Agent", "new-agent")

	a.LogUserAgentChanged(request)

	lines := parseLogLines(t, buffer)
	if len(lines) != 1 {
		t.Fatalf("got %d log lines: %s", len(lines), buffer.String())
	}
	got := lines[0]
	if got.Level != "WARN" || got.Event != "session_user_agent_changed" ||
		got.UserAgent != "new-agent" || got.Session != a.Salt.Fingerprint(id) {
		t.Fatalf("line = %+v", got)
	}
	if strings.Contains(buffer.String(), id) {
		t.Fatalf("session ID appears in cleartext: %s", buffer.String())
	}
}

func TestSessionFingerprintIsADashWithoutAVerifiedSession(t *testing.T) {
	a := newTestAuthenticator(t, randomSessionKey(t))
	if got := a.SessionFingerprint(requestWithCookie("")); got != "-" {
		t.Fatalf("fingerprint = %q", got)
	}
}

func TestSessionFingerprintIsSaltedForAVerifiedSession(t *testing.T) {
	key := randomSessionKey(t)
	a := newTestAuthenticator(t, key)
	id := a.Sessions.Create("test-agent")
	got := a.SessionFingerprint(requestFor(key, id))
	if got != a.Salt.Fingerprint(id) || strings.Contains(got, id) {
		t.Fatalf("fingerprint = %q", got)
	}
}

func TestSessionIDRejectsCookiesThatAreNotAVerifiedSessionIdentifier(t *testing.T) {
	key := randomSessionKey(t)
	cases := map[string]*http.Request{
		"not a session id": requestFor(key, "not-a-session-id"),
		"unsigned value":   requestWithCookie(SessionCookieName(false) + "=plain"),
	}
	a := newTestAuthenticator(t, key)
	for name, request := range cases {
		if got, ok := a.SessionID(request); ok || got != "" {
			t.Errorf("%s: SessionID = %q, %v", name, got, ok)
		}
	}
}
