package version

import "fmt"

var (
	Version   = "dev"
	Commit    = "HEAD"
	BuildDate = "undefined"
)

func String() string {
	return fmt.Sprintf("%s (%s), built at %s", Version, Commit, BuildDate)
}
