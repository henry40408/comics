package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestParseLogLevel(t *testing.T) {
	cases := []struct {
		text    string
		want    slog.Level
		wantErr bool
	}{
		{"debug", slog.LevelDebug, false},
		{"info", slog.LevelInfo, false},
		{"warn", slog.LevelWarn, false},
		{"error", slog.LevelError, false},
		{"trace", 0, true},
		{"", 0, true},
	}
	for _, tc := range cases {
		got, err := parseLogLevel(tc.text)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("parseLogLevel(%q) = %v, %v", tc.text, got, err)
		}
	}
}

func TestNewLoggerHonoursTheFormatAndLevel(t *testing.T) {
	cases := []struct {
		format   string
		wantJSON bool
	}{
		{"json", true},
		{defaultLogFormat, false},
	}
	for _, tc := range cases {
		var buffer bytes.Buffer
		logger := newLogger(&buffer, tc.format, slog.LevelWarn)
		logger.Info("hidden")
		logger.Warn("shown")
		out := buffer.String()
		if strings.Contains(out, "hidden") || !strings.Contains(out, "shown") {
			t.Errorf("%s: out = %q", tc.format, out)
		}
		if isJSON := strings.HasPrefix(out, "{"); isJSON != tc.wantJSON {
			t.Errorf("%s: out = %q", tc.format, out)
		}
	}
}
