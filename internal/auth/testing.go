package auth

// TestPasswordHash is a test-only Argon2 hash at far cheaper parameters (1 MiB,
// one pass). Verification reads them from the hash, so tests use the real code
// path, and it stays well above a string comparison, as the timing test needs.
// It panics on failure, as it only ever sees test input.
func TestPasswordHash(password string) string {
	hash, err := HashPasswordWith(password, PasswordParams{Memory: 1024, Time: 1, Threads: 1})
	if err != nil {
		panic("hashing a test password: " + err.Error())
	}
	return hash
}
