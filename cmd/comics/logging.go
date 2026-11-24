package main

import (
	"fmt"
	"io"
	"log/slog"
)

// parseLogFormat validates a --log-format value.
func parseLogFormat(text string) (string, error) {
	if text == "text" || text == "json" {
		return text, nil
	}
	return "", fmt.Errorf("unknown log format %q (want text or json)", text)
}

// parseLogLevel reads a level name the way slog does: debug, info, warn or
// error in any case, optionally with an offset such as info+2.
func parseLogLevel(text string) (slog.Level, error) {
	var level slog.Level
	err := level.UnmarshalText([]byte(text))
	return level, err
}

// newLogger writes to w, which is stdout in server mode.
func newLogger(w io.Writer, format string, level slog.Level) *slog.Logger {
	handlerOptions := &slog.HandlerOptions{Level: level}
	if format == "json" {
		return slog.New(slog.NewJSONHandler(w, handlerOptions))
	}
	return slog.New(slog.NewTextHandler(w, handlerOptions))
}
