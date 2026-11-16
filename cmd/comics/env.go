package main

import (
	"fmt"
	"strings"
)

// legacyEnvVar pairs a retired environment variable with its replacement.
type legacyEnvVar struct{ old, replacement string }

// legacyEnvVars lists the retired variables. Update it whenever an environment
// variable is added, renamed or removed: a silently ignored one (say, falling
// back to a random secret) is worse than a startup failure.
var legacyEnvVars = []legacyEnvVar{
	{"AUTH_USERNAME", "COMICS_AUTH_USERNAME"},
	{"AUTH_PASSWORD_HASH", "COMICS_AUTH_PASSWORD_HASH"},
	{"BIND", "COMICS_BIND"},
	{"DATA_DIR", "COMICS_DATA_DIR"},
	{"CACHE_DIR", "COMICS_CACHE_DIR"},
	{"LOG_FORMAT", "COMICS_LOG_FORMAT"},
	{"SEED", "COMICS_SECRET"},
	{"COMICS_SEED", "COMICS_SECRET"},
	{"COMICS_SESSION_KEY", "COMICS_SECRET"},
	// A global RUST_LOG would otherwise be ignored without a word.
	{"RUST_LOG", "COMICS_LOG_LEVEL"},
}

// ensureNoLegacyEnvVars fails when a retired variable is set, even empty.
func ensureNoLegacyEnvVars(lookupEnv func(string) (string, bool)) error {
	var found []string
	for _, legacy := range legacyEnvVars {
		if _, ok := lookupEnv(legacy.old); ok {
			found = append(found, fmt.Sprintf("  %s -> %s", legacy.old, legacy.replacement))
		}
	}
	if len(found) == 0 {
		return nil
	}
	return fmt.Errorf("these environment variables no longer exist; "+
		"rename (or unset) them to continue:\n%s", strings.Join(found, "\n"))
}
