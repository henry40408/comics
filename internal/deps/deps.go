// Package deps keeps the pinned third-party modules in go.mod (and so in
// vendor/) until the packages that use them land. Delete it once
// golang.org/x/crypto/argon2, golang.org/x/image/webp, golang.org/x/image/draw
// and golang.org/x/term are each imported by real code.
package deps

import (
	_ "golang.org/x/term"
)
