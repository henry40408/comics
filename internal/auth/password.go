package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// MaxPasswordBytes is OWASP's "maximum input length": a rejection backstop,
// not truncation. It bounds what one request can make Argon2 chew on.
const MaxPasswordBytes = 1024

// MinPasswordChars is the shortest password hash-password accepts without a
// warning, in characters (OWASP's minimum without a second factor). Advice,
// not a rule: the one user is the operator, and a hard floor would only push
// them to hash elsewhere. Characters, not bytes like MaxPasswordBytes: the
// floor measures memorability, the ceiling resource use.
const MinPasswordChars = 15

// MaxConcurrentVerifications caps how many password verifications may run at
// once. Argon2id at the default parameters allocates 19 MiB per verification,
// so the 20 attempts the rate limiter admits could want 380 MiB at once, on
// what may be a NAS. Four caps it near 76 MiB; excess requests queue, not fail.
const MaxConcurrentVerifications = 4

const (
	argon2Version  = 19
	saltBytes      = 16
	digestBytes    = 32
	minDigestBytes = 4
	minSaltBytes   = 8
)

// bcryptPrefixes are matched only to name the migration: a bare parse error is
// unactionable.
var bcryptPrefixes = []string{"$2a$", "$2b$", "$2x$", "$2y$"}

// PasswordParams are Argon2 cost parameters. Memory is in KiB.
type PasswordParams struct {
	Memory  uint32
	Time    uint32
	Threads uint8
}

// DefaultPasswordParams is an OWASP-listed Argon2id configuration (m=19456,
// t=2, p=1). They are recorded in the PHC string, so raising them later leaves
// existing hashes verifiable.
var DefaultPasswordParams = PasswordParams{Memory: 19456, Time: 2, Threads: 1}

// EnsurePasswordFits refuses an empty password, or one past MaxPasswordBytes.
//
// Mirrors the ceiling in VerifyCredentials, so a password that hashes always
// verifies. Merely short passwords are the caller's advice, not a refusal.
func EnsurePasswordFits(password string) error {
	if password == "" {
		//lint:ignore ST1005 printed verbatim to the user, not wrapped into another error
		return errors.New("Password is empty.")
	}
	if len(password) > MaxPasswordBytes {
		//lint:ignore ST1005 printed verbatim to the user, not wrapped into another error
		return fmt.Errorf("Password is %d bytes, and comics accepts at most %d. "+
			"Shorten it — note that non-ASCII characters cost several bytes each.",
			len(password), MaxPasswordBytes)
	}
	return nil
}

// HashPassword hashes with Argon2id at DefaultPasswordParams into a PHC string.
func HashPassword(password string) (string, error) {
	if err := EnsurePasswordFits(password); err != nil {
		return "", err
	}
	return HashPasswordWith(password, DefaultPasswordParams)
}

// HashPasswordWith hashes at the given cost. It does not apply the length
// policy; HashPassword does.
func HashPasswordWith(password string, params PasswordParams) (string, error) {
	if err := validateParams(params); err != nil {
		return "", err
	}
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to hash the password: %w", err)
	}
	digest := argon2.IDKey([]byte(password), salt, params.Time, params.Memory, params.Threads, digestBytes)
	return formatPHC(params, salt, digest), nil
}

func formatPHC(params PasswordParams, salt, digest []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2Version, params.Memory, params.Time, params.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(digest))
}

// ParsedPasswordHash is a PHC string taken apart. Digest is empty when the
// string carried a salt but no hash after it.
type ParsedPasswordHash struct {
	Algorithm string
	Version   int
	Params    PasswordParams
	Salt      []byte
	Digest    []byte
}

// HasDigest reports whether the hash can ever match a password.
func (p ParsedPasswordHash) HasDigest() bool { return len(p.Digest) > 0 }

// ParsePasswordHash reads $argon2id$v=19$m=..,t=..,p=..$<salt>$<hash>. Salt and
// hash use standard base64 without padding. A field missing from the
// parameters takes the default. Only argon2id and argon2i at version 19 are
// supported; that is stricter than Rust's password-hash for argon2d, v=16 and
// p>255. Salts under 8 bytes are refused, as in Rust.
//
// A string with a salt but no digest (such as "$argon2id$v=19$m=19456$nope")
// parses; check HasDigest. A digest-less hash verifies as a wrong password, so
// the parse alone would let a useless hash through.
func ParsePasswordHash(phc string) (ParsedPasswordHash, error) {
	fields := strings.Split(phc, "$")
	if len(fields) < 3 || fields[0] != "" {
		return ParsedPasswordHash{}, errors.New("password hash string missing the `$` prefix")
	}
	hash := ParsedPasswordHash{Algorithm: fields[1], Version: argon2Version, Params: DefaultPasswordParams}
	if hash.Algorithm != "argon2id" && hash.Algorithm != "argon2i" {
		return ParsedPasswordHash{}, fmt.Errorf("unsupported algorithm %q", hash.Algorithm)
	}
	return parsePHCBody(hash, fields[2:])
}

func parsePHCBody(hash ParsedPasswordHash, fields []string) (ParsedPasswordHash, error) {
	if len(fields) > 0 && strings.HasPrefix(fields[0], "v=") {
		version, err := strconv.Atoi(fields[0][2:])
		if err != nil || version != argon2Version {
			return ParsedPasswordHash{}, fmt.Errorf("unsupported version %q", fields[0][2:])
		}
		fields = fields[1:]
	}
	if len(fields) > 0 && strings.Contains(fields[0], "=") {
		params, err := parseParams(fields[0])
		if err != nil {
			return ParsedPasswordHash{}, err
		}
		hash.Params = params
		fields = fields[1:]
	}
	if len(fields) == 0 || len(fields) > 2 {
		return ParsedPasswordHash{}, errors.New("password hash has no salt, or trailing fields")
	}
	return decodeSaltAndDigest(hash, fields)
}

func decodeSaltAndDigest(hash ParsedPasswordHash, fields []string) (ParsedPasswordHash, error) {
	salt, err := base64.RawStdEncoding.DecodeString(fields[0])
	if err != nil || len(salt) < minSaltBytes {
		return ParsedPasswordHash{}, errors.New("salt invalid")
	}
	hash.Salt = salt
	if len(fields) == 2 {
		digest, err := base64.RawStdEncoding.DecodeString(fields[1])
		if err != nil || len(digest) < minDigestBytes {
			return ParsedPasswordHash{}, errors.New("hash output invalid")
		}
		hash.Digest = digest
	}
	if err := validateParams(hash.Params); err != nil {
		return ParsedPasswordHash{}, err
	}
	return hash, nil
}

func parseParams(raw string) (PasswordParams, error) {
	params := DefaultPasswordParams
	for pair := range strings.SplitSeq(raw, ",") {
		name, value, ok := strings.Cut(pair, "=")
		if !ok {
			return PasswordParams{}, fmt.Errorf("parameter %q has no value", pair)
		}
		if err := setParam(&params, name, value); err != nil {
			return PasswordParams{}, err
		}
	}
	return params, nil
}

func setParam(params *PasswordParams, name, value string) error {
	bits := 32
	if name == "p" {
		bits = 8
	}
	number, err := strconv.ParseUint(value, 10, bits)
	if err != nil {
		return fmt.Errorf("parameter %s=%q invalid", name, value)
	}
	switch name {
	case "m":
		params.Memory = uint32(number)
	case "t":
		params.Time = uint32(number)
	case "p":
		params.Threads = uint8(number)
	default:
		return fmt.Errorf("unsupported parameter %q", name)
	}
	return nil
}

// validateParams rejects what argon2.IDKey would panic on.
func validateParams(params PasswordParams) error {
	if params.Time < 1 || params.Threads < 1 || params.Memory < 8*uint32(params.Threads) {
		return fmt.Errorf("parameters m=%d,t=%d,p=%d are out of range",
			params.Memory, params.Time, params.Threads)
	}
	return nil
}

// Matches reports whether password produces this hash's digest, reading cost,
// algorithm and output length from the parsed string. A hash with no digest
// matches nothing.
func (p ParsedPasswordHash) Matches(password string) bool {
	if !p.HasDigest() {
		return false
	}
	derive := argon2.IDKey
	if p.Algorithm == "argon2i" {
		derive = argon2.Key
	}
	got := derive([]byte(password), p.Salt, p.Params.Time, p.Params.Memory, p.Params.Threads, uint32(len(p.Digest)))
	return subtle.ConstantTimeCompare(got, p.Digest) == 1
}

// VerifyPassword checks password against a stored PHC string. An unparseable
// or digest-less hash refuses; EnsurePasswordHashUsable should have rejected
// it at startup.
func VerifyPassword(password, stored string) bool {
	parsed, err := ParsePasswordHash(stored)
	if err != nil {
		return false
	}
	return parsed.Matches(password)
}

// Credentials are the configured login. A nil *Credentials means auth is off.
type Credentials struct {
	Username     string
	PasswordHash string
}

// VerifyCredentials checks a submitted pair; anything passes when creds is nil
// (auth not configured).
//
// Both halves always run. "username == expected && verify(...)" would
// short-circuit, so a wrong username would answer in microseconds and a wrong
// password in ~15 ms: a timing oracle enumerating the username (OWASP's "quick
// exit"). Hence the unconditional verification, the non-branching & on ints,
// and ConstantTimeCompare for the username (which still leaks whether the
// lengths match).
//
// Callers must hold a verification permit: each call allocates 19 MiB (see
// MaxConcurrentVerifications).
func VerifyCredentials(creds *Credentials, username, password string) bool {
	if creds == nil {
		return true
	}
	// A branch, but on the attacker's own input, so it leaks nothing. Mirrors
	// EnsurePasswordFits, so any hashable password verifies.
	if len(password) > MaxPasswordBytes {
		return false
	}
	usernameOK := subtle.ConstantTimeCompare([]byte(username), []byte(creds.Username))
	passwordOK := 0
	if VerifyPassword(password, creds.PasswordHash) {
		passwordOK = 1
	}
	return usernameOK&passwordOK == 1
}

// EnsurePasswordHashUsable rejects a COMICS_AUTH_PASSWORD_HASH the login route
// could not use. Otherwise the server starts with auth enabled and refuses the
// correct password exactly as it refuses a typo. Deliberately not run before
// the hash-password subcommand, which is how the operator fixes a bad hash.
//
// A parse is not enough: a salt with no digest parses, then verifies as a
// wrong password, hence the HasDigest check.
func EnsurePasswordHashUsable(hash string) error {
	for _, prefix := range bcryptPrefixes {
		if strings.HasPrefix(hash, prefix) {
			//lint:ignore ST1005 printed verbatim to the user, not wrapped into another error
			return errors.New("COMICS_AUTH_PASSWORD_HASH is a bcrypt hash, which comics no longer accepts — " +
				"it now hashes passwords with Argon2id. Your password itself is unchanged: " +
				"run `comics hash-password`, enter it again, and replace the value of " +
				"COMICS_AUTH_PASSWORD_HASH with the new hash.")
		}
	}
	parsed, err := ParsePasswordHash(hash)
	if err != nil {
		return fmt.Errorf("COMICS_AUTH_PASSWORD_HASH is not an Argon2 hash (%w); "+
			"generate one with `comics hash-password`", err)
	}
	if !parsed.HasDigest() {
		return errors.New("COMICS_AUTH_PASSWORD_HASH carries no digest — it is a salt without a " +
			"hash after it, which can never match any password; " +
			"generate a complete one with `comics hash-password`")
	}
	return nil
}
