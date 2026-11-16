// Package e2e drives the comics server in a real browser through Gherkin
// scenarios.
//
// Run from this directory with `go test -count=1 ./...`. The count flag is
// needed because Go's test cache cannot see a rebuilt bin/comics. Set
// E2E_FEATURES to a comma-separated list of feature paths to run a subset.
package e2e
