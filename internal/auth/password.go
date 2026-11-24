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
	// maxMemoryKiB and maxTime bound what a stored hash may demand. Argon2
	// touches all of m, so an unbounded m (up to 4 TiB) would exhaust memory on
	// the first login, and the startup check would not have caught it.
	// 256 MiB times MaxConcurrentVerifications is about 1 GiB at worst.
	maxMemoryKiB = 256 * 1024
	maxTime      = 16
)

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
		return errors.New("password is empty")
	}
	if len(password) > MaxPasswordBytes {
		return fmt.Errorf("password is %d bytes, and comics accepts at most %d. "+
			"Shorten it — note that non-ASCII characters cost several bytes each",
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
	_, _ = rand.Read(salt) // crypto/rand.Read never returns an error
	digest := argon2.IDKey([]byte(password), salt, params.Time, params.Memory, params.Threads, digestBytes)
	return formatPHC(params, salt, digest), nil
}

func formatPHC(params PasswordParams, salt, digest []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2Version, params.Memory, params.Time, params.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(digest))
}

// ParsedPasswordHash is a PHC string taken apart.
type ParsedPasswordHash struct {
	Params PasswordParams
	Salt   []byte
	Digest []byte
}

// ParsePasswordHash reads exactly what HashPassword writes,
// $argon2id$v=19$m=..,t=..,p=..$<salt>$<hash>, with every field present and the
// parameters in that order. Salt and hash use standard base64 without padding.
// Only argon2id at version 19 is supported. Salts under 8 bytes and digests
// under 4 bytes are refused.
//
// A missing field is an error, not a default: a hash that silently took the
// default cost would parse and then never verify.
func ParsePasswordHash(phc string) (ParsedPasswordHash, error) {
	fields := strings.Split(phc, "$")
	if len(fields) != 6 || fields[0] != "" {
		return ParsedPasswordHash{}, errors.New("password hash must look like " +
			"$argon2id$v=19$m=<memory>,t=<time>,p=<threads>$<salt>$<hash>")
	}
	if fields[1] != "argon2id" {
		return ParsedPasswordHash{}, fmt.Errorf("unsupported algorithm %q", fields[1])
	}
	if fields[2] != "v="+strconv.Itoa(argon2Version) {
		return ParsedPasswordHash{}, fmt.Errorf("unsupported version %q", fields[2])
	}
	params, err := parseParams(fields[3])
	if err != nil {
		return ParsedPasswordHash{}, err
	}
	hash := ParsedPasswordHash{Params: params}
	if hash.Salt, err = decodeBase64(fields[4], minSaltBytes, "salt"); err != nil {
		return ParsedPasswordHash{}, err
	}
	if hash.Digest, err = decodeBase64(fields[5], minDigestBytes, "hash output"); err != nil {
		return ParsedPasswordHash{}, err
	}
	return hash, nil
}

func decodeBase64(text string, minBytes int, what string) ([]byte, error) {
	decoded, err := base64.RawStdEncoding.DecodeString(text)
	if err != nil || len(decoded) < minBytes {
		return nil, fmt.Errorf("%s invalid", what)
	}
	return decoded, nil
}

// parseParams reads m=<memory>,t=<time>,p=<threads>, in that order.
func parseParams(raw string) (PasswordParams, error) {
	parts := strings.Split(raw, ",")
	if len(parts) != 3 {
		return PasswordParams{}, fmt.Errorf("parameters %q must look like m=<memory>,t=<time>,p=<threads>", raw)
	}
	var numbers [3]uint64
	for i, key := range []string{"m", "t", "p"} {
		text, ok := strings.CutPrefix(parts[i], key+"=")
		if !ok {
			return PasswordParams{}, fmt.Errorf("parameters %q must look like m=<memory>,t=<time>,p=<threads>", raw)
		}
		bits := 32
		if key == "p" {
			bits = 8
		}
		number, err := strconv.ParseUint(text, 10, bits)
		if err != nil {
			return PasswordParams{}, fmt.Errorf("parameter %s=%q invalid", key, text)
		}
		numbers[i] = number
	}
	params := PasswordParams{Memory: uint32(numbers[0]), Time: uint32(numbers[1]), Threads: uint8(numbers[2])}
	if err := validateParams(params); err != nil {
		return PasswordParams{}, err
	}
	return params, nil
}

// validateParams rejects what argon2.IDKey would panic on, and costs beyond
// maxMemoryKiB and maxTime.
func validateParams(params PasswordParams) error {
	if params.Time < 1 || params.Threads < 1 || params.Memory < 8*uint32(params.Threads) ||
		params.Memory > maxMemoryKiB || params.Time > maxTime {
		return fmt.Errorf("parameters m=%d,t=%d,p=%d are out of range",
			params.Memory, params.Time, params.Threads)
	}
	return nil
}

// Matches reports whether password produces this hash's digest, reading cost
// and output length from the parsed string.
func (p ParsedPasswordHash) Matches(password string) bool {
	got := argon2.IDKey([]byte(password), p.Salt, p.Params.Time, p.Params.Memory, p.Params.Threads, uint32(len(p.Digest)))
	return subtle.ConstantTimeCompare(got, p.Digest) == 1
}

// VerifyPassword checks password against a stored PHC string. An unparseable
// hash refuses; EnsurePasswordHashUsable should have rejected
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
func EnsurePasswordHashUsable(hash string) error {
	if _, err := ParsePasswordHash(hash); err != nil {
		return fmt.Errorf("COMICS_AUTH_PASSWORD_HASH is not an Argon2 hash (%w); "+
			"generate one with `comics hash-password`", err)
	}
	return nil
}
