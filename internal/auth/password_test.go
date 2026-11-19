package auth

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func someAuth() *Credentials {
	return &Credentials{Username: "alice", PasswordHash: TestPasswordHash("s3cret")}
}

func credentialsFor(password string) *Credentials {
	return &Credentials{Username: "alice", PasswordHash: TestPasswordHash(password)}
}

func TestVerifyCredentialsAcceptsCorrectPair(t *testing.T) {
	if !VerifyCredentials(someAuth(), "alice", "s3cret") {
		t.Fatal("the correct pair was refused")
	}
}

func TestVerifyCredentialsRejectsWrongPassword(t *testing.T) {
	if VerifyCredentials(someAuth(), "alice", "nope") {
		t.Fatal("a wrong password was accepted")
	}
}

func TestVerifyCredentialsRejectsWrongUsername(t *testing.T) {
	if VerifyCredentials(someAuth(), "bob", "s3cret") {
		t.Fatal("a wrong username was accepted")
	}
}

func TestVerifyCredentialsPublicWhenUnconfigured(t *testing.T) {
	if !VerifyCredentials(nil, "", "") {
		t.Fatal("anything should pass when auth is off")
	}
}

// The route must not depend on EnsurePasswordHashUsable having run.
func TestAnUnusableStoredHashRefusesEveryPassword(t *testing.T) {
	for _, stored := range []string{"", "not-a-hash", "$argon2id$v=19$m=19456,t=2,p=1$MTIzNDU2Nzg"} {
		creds := &Credentials{Username: "alice", PasswordHash: stored}
		if VerifyCredentials(creds, "alice", "s3cret") || VerifyCredentials(creds, "alice", "") {
			t.Errorf("%q verified a password", stored)
		}
	}
}

// Guards against a short-circuiting check. Even the cheap test hash is orders
// of magnitude above a string comparison, so the ratio does not need a quiet
// machine.
func TestWrongUsernameCostsWhatAWrongPasswordCosts(t *testing.T) {
	creds := someAuth()

	// The minimum of several runs drops the cold first call and scheduler
	// noise, either of which can skew a single sample past the ratio.
	cheapest := func(username string) time.Duration {
		best := time.Duration(1<<63 - 1)
		for range 5 {
			started := time.Now()
			if VerifyCredentials(creds, username, "nope") {
				t.Fatal("a wrong pair was accepted")
			}
			best = min(best, time.Since(started))
		}
		return best
	}
	wrongPassword := cheapest("alice")
	wrongUsername := cheapest("mallory")

	if wrongUsername*4 < wrongPassword {
		t.Fatalf("a wrong username took %v against %v for a wrong password: "+
			"the credential check is short-circuiting", wrongUsername, wrongPassword)
	}
}

// Every byte counts: no bcrypt-style 72-byte truncation.
func TestALongPasswordIsNotMerelyItsOwnPrefix(t *testing.T) {
	password := strings.Repeat("x", 100)
	creds := credentialsFor(password)

	if !VerifyCredentials(creds, "alice", password) {
		t.Error("the full password was refused")
	}
	if VerifyCredentials(creds, "alice", password+"extra") {
		t.Error("the password plus a suffix was accepted")
	}
	if VerifyCredentials(creds, "alice", strings.Repeat("x", 99)) {
		t.Error("a prefix of the password was accepted")
	}
}

// Three bytes per character: a 72-byte ceiling would stop at 24.
func TestAChinesePassphraseIsNotCutShort(t *testing.T) {
	password := strings.Repeat("密", 100)
	if len(password) != 300 {
		t.Fatalf("len = %d, want 300", len(password))
	}
	creds := credentialsFor(password)

	if !VerifyCredentials(creds, "alice", password) {
		t.Error("the full passphrase was refused")
	}
	if VerifyCredentials(creds, "alice", strings.Repeat("密", 99)) {
		t.Error("a shorter passphrase was accepted")
	}
}

func TestAPasswordPastTheCeilingIsRefused(t *testing.T) {
	password := strings.Repeat("x", MaxPasswordBytes)
	creds := credentialsFor(password)

	if !VerifyCredentials(creds, "alice", password) {
		t.Error("a password at the ceiling was refused")
	}
	if VerifyCredentials(creds, "alice", strings.Repeat("x", MaxPasswordBytes+1)) {
		t.Error("a password past the ceiling was accepted")
	}
}

func usable(hash string) error { return EnsurePasswordHashUsable(hash) }

func TestAUsableHashPassesTheStartupCheck(t *testing.T) {
	for _, hash := range []string{TestPasswordHash("pw"), mustHash(t, "a-password-long-enough")} {
		if err := usable(hash); err != nil {
			t.Errorf("%q refused: %v", hash, err)
		}
	}
}

func mustHash(t *testing.T, password string) string {
	t.Helper()
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func TestAMalformedPasswordHashStopsStartup(t *testing.T) {
	cases := []string{
		"",
		"not-a-hash",
		"password",
		// Has a salt but no digest.
		"$argon2id$v=19$m=19456,t=2,p=1$MTIzNDU2Nzg",
		// Another algorithm's hash.
		"$pbkdf2-sha256$i=1000$c2FsdHNhbHQ$xEbJPmXjr2fBIf1RhJ1Kd0uGrjhOTOAgWnMYGVBLj4Y",
	}
	for _, hash := range cases {
		err := usable(hash)
		if err == nil {
			t.Errorf("%q was accepted", hash)
			continue
		}
		if !strings.Contains(err.Error(), "hash-password") {
			t.Errorf("%q: %q does not name hash-password", hash, err)
		}
	}
}

func TestABcryptHashNamesTheMigration(t *testing.T) {
	for _, prefix := range []string{"$2a$", "$2b$", "$2x$", "$2y$"} {
		hash := prefix + "11$JhuJ1rMv1wShbVrJyh0p2.wLkQWFDDrx4F3huF5DdphG38jkwwYVu"
		err := usable(hash)
		if err == nil {
			t.Fatalf("%s hash was accepted", prefix)
		}
		for _, want := range []string{"bcrypt", "Argon2id", "hash-password", "password itself is unchanged"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: %q lacks %q", prefix, err, want)
			}
		}
	}
}

func TestHashPasswordAcceptsAPasswordAtTheLimit(t *testing.T) {
	if err := EnsurePasswordFits(strings.Repeat("x", MaxPasswordBytes)); err != nil {
		t.Fatalf("a password at the limit was refused: %v", err)
	}
	cjk := strings.Repeat("密", 100)
	if len(cjk) != 300 {
		t.Fatalf("len = %d, want 300", len(cjk))
	}
	if err := EnsurePasswordFits(cjk); err != nil {
		t.Fatalf("a 300-byte password was refused: %v", err)
	}
	if !strings.HasPrefix(mustHash(t, cjk), "$argon2id$") {
		t.Fatal("not an argon2id hash")
	}
}

// DefaultPasswordParams is pinned so a change cannot silently move the cost.
func TestHashPasswordRecordsTheOWASPParameters(t *testing.T) {
	hash := mustHash(t, "a-password-long-enough")
	parsed, err := ParsePasswordHash(hash)
	if err != nil {
		t.Fatal(err)
	}

	if parsed.Algorithm != "argon2id" {
		t.Errorf("algorithm %q", parsed.Algorithm)
	}
	if want := (PasswordParams{Memory: 19456, Time: 2, Threads: 1}); parsed.Params != want {
		t.Errorf("params = %+v, want %+v", parsed.Params, want)
	}
	if len(parsed.Salt) != 16 {
		t.Errorf("salt is %d bytes, want 16", len(parsed.Salt))
	}
	if len(parsed.Digest) != 32 {
		t.Errorf("digest is %d bytes, want 32", len(parsed.Digest))
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Errorf("hash %q has the wrong PHC prefix", hash)
	}
	// v, m, t and p each contribute one "="; any more is base64 padding.
	if strings.Count(hash, "=") != 4 {
		t.Errorf("hash %q carries base64 padding", hash)
	}
}

// The message names the size: the passphrase was typed blind.
func TestHashPasswordRefusesAnOverLongPassword(t *testing.T) {
	long := strings.Repeat("x", MaxPasswordBytes+1)
	err := EnsurePasswordFits(long)
	if err == nil {
		t.Fatal("an over-long password was accepted")
	}
	if !strings.Contains(err.Error(), "1025 bytes") {
		t.Errorf("error %q does not name the size", err)
	}
	if _, err := HashPassword(long); err == nil {
		t.Fatal("HashPassword accepted an over-long password")
	}
}

func TestHashPasswordRefusesAnEmptyPassword(t *testing.T) {
	if EnsurePasswordFits("") == nil {
		t.Fatal("an empty password was accepted")
	}
	if _, err := HashPassword(""); err == nil {
		t.Fatal("HashPassword accepted an empty password")
	}
}

func TestEachHashGetsItsOwnSalt(t *testing.T) {
	a, b := TestPasswordHash("same"), TestPasswordHash("same")
	if a == b {
		t.Fatal("two hashes of one password are identical")
	}
	if !VerifyPassword("same", a) || !VerifyPassword("same", b) {
		t.Fatal("a fresh hash did not verify")
	}
}

func TestVerifyReadsParametersFromTheStoredHash(t *testing.T) {
	hash, err := HashPasswordWith("pw", PasswordParams{Memory: 2048, Time: 3, Threads: 2})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(hash, "m=2048,t=3,p=2") {
		t.Fatalf("hash %q does not record its parameters", hash)
	}
	if !VerifyPassword("pw", hash) || VerifyPassword("other", hash) {
		t.Fatal("verification ignored the stored parameters")
	}
}

func TestParsePasswordHashRefusesMissingFields(t *testing.T) {
	salt := base64.RawStdEncoding.EncodeToString([]byte("0123456789abcdef"))
	digest := base64.RawStdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))

	for name, hash := range map[string]string{
		"no version":          "$argon2id$m=1024,t=1,p=1$" + salt + "$" + digest,
		"missing t and p":     "$argon2id$v=19$m=1024$" + salt + "$" + digest,
		"no parameters":       "$argon2id$v=19$" + salt + "$" + digest,
		"parameters shuffled": "$argon2id$v=19$t=1,m=1024,p=1$" + salt + "$" + digest,
		"no digest":           "$argon2id$v=19$m=1024,t=1,p=1$" + salt,
		"empty":               "",
		"not a hash":          "x",
		"no leading dollar":   "argon2id$v=19$m=1,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2g",
	} {
		if _, err := ParsePasswordHash(hash); err == nil {
			t.Errorf("%s parsed", name)
		}
	}
}

func TestParsePasswordHashRefusesWhatItCannotVerify(t *testing.T) {
	salt := base64.RawStdEncoding.EncodeToString([]byte("0123456789abcdef"))
	digest := base64.RawStdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	tail := "$" + salt + "$" + digest

	for name, hash := range map[string]string{
		"argon2d":          "$argon2d$v=19$m=1024,t=1,p=1" + tail,
		"old version":      "$argon2id$v=16$m=1024,t=1,p=1" + tail,
		"zero time":        "$argon2id$v=19$m=1024,t=0,p=1" + tail,
		"zero threads":     "$argon2id$v=19$m=1024,t=1,p=0" + tail,
		"too little mem":   "$argon2id$v=19$m=1,t=1,p=1" + tail,
		"unknown param":    "$argon2id$v=19$m=1024,t=1,p=1,x=1" + tail,
		"bad number":       "$argon2id$v=19$m=lots,t=1,p=1" + tail,
		"short salt":       "$argon2id$v=19$m=1024,t=1,p=1$" + base64.RawStdEncoding.EncodeToString([]byte("1234567")) + "$" + digest,
		"bad salt":         "$argon2id$v=19$m=1024,t=1,p=1$!!!$" + digest,
		"bad digest":       "$argon2id$v=19$m=1024,t=1,p=1$" + salt + "$!!!",
		"too many fields":  "$argon2id$v=19$m=1024,t=1,p=1" + tail + "$extra",
		"threads past 255": "$argon2id$v=19$m=1024,t=1,p=256" + tail,
	} {
		if _, err := ParsePasswordHash(hash); err == nil {
			t.Errorf("%s parsed", name)
		}
	}
}

func TestArgon2iHashesVerify(t *testing.T) {
	// Computed with argon2.Key itself so the test pins the dispatch, not the
	// primitive.
	salt := []byte("0123456789abcdef")
	hash := "$argon2i$v=19$m=1024,t=1,p=1$" + base64.RawStdEncoding.EncodeToString(salt) + "$" +
		base64.RawStdEncoding.EncodeToString(argon2iKey("pw", salt))
	if !VerifyPassword("pw", hash) || VerifyPassword("other", hash) {
		t.Fatal("argon2i verification wrong")
	}
	idHash := strings.Replace(hash, "$argon2i$", "$argon2id$", 1)
	if VerifyPassword("pw", idHash) {
		t.Fatal("an argon2i digest verified as argon2id")
	}
}

func TestConstantsMatchTheDocumentedPolicy(t *testing.T) {
	if MaxPasswordBytes != 1024 || MinPasswordChars != 15 || MaxConcurrentVerifications != 4 {
		t.Fatalf("policy constants drifted: %d %d %d",
			MaxPasswordBytes, MinPasswordChars, MaxConcurrentVerifications)
	}
}
