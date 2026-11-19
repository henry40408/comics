package main

import (
	"fmt"
	"io"
	"log/slog"
	"slices"
)

var logFormats = []string{"full", "json"}

// parseLogFormat validates a --log-format value. slog has no compact or pretty
// layouts, so those names are rejected rather than silently ignored.
func parseLogFormat(text string) (string, error) {
	if slices.Contains(logFormats, text) {
		return text, nil
	}
	return "", fmt.Errorf("unknown log format %q (want full or json)", text)
}

func parseLogLevel(text string) (slog.Level, error) {
	switch text {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("unknown log level %q (want debug, info, warn or error)", text)
}

// newLogger writes to w, which is stdout in server mode.
func newLogger(w io.Writer, format string, level slog.Level) *slog.Logger {
	handlerOptions := &slog.HandlerOptions{Level: level}
	if format == "json" {
		return slog.New(slog.NewJSONHandler(w, handlerOptions))
	}
	return slog.New(slog.NewTextHandler(w, handlerOptions))
}
