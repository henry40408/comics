package main

import (
	"fmt"
	"strings"
)

// legacyEnvVar pairs a retired environment variable with its replacement.
type legacyEnvVar struct{ old, replacement string }

// legacyEnvVars lists the retired variables that must still abort startup. Only
// these two stay: ignoring the old names would leave COMICS_AUTH_* unset and
// the server would silently come up fully public (fail-open). Any other
// retired name that is ignored merely leaves a setting unapplied, so it is not
// worth a table entry.
var legacyEnvVars = []legacyEnvVar{
	{"AUTH_USERNAME", "COMICS_AUTH_USERNAME"},
	{"AUTH_PASSWORD_HASH", "COMICS_AUTH_PASSWORD_HASH"},
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
