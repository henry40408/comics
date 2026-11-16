package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"

	"github.com/henry40408/comics/internal/auth"
)

// passwordStrengthWarning is advice for a password shorter than
// auth.MinPasswordChars, not enforcement. Returned rather than printed so it
// can be tested.
func passwordStrengthWarning(password string) (string, bool) {
	chars := utf8.RuneCountInString(password)
	if chars >= auth.MinPasswordChars {
		return "", false
	}
	return fmt.Sprintf("password is %d characters; OWASP advises at least "+
		"%d when no second factor is available, and comics "+
		"has none. The hash below is still valid — this is advice, not a refusal.",
		chars, auth.MinPasswordChars), true
}

// emitPasswordHash writes the hash to out and any advice to errw.
//
// `$(comics hash-password)` captures stdout, so a warning there would be baked
// into the configured hash. Not a log line: slog also writes to stdout.
func emitPasswordHash(password string, out, errw io.Writer) error {
	hashed, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	if warning, ok := passwordStrengthWarning(password); ok {
		if _, err := fmt.Fprintf(errw, "warning: %s\n", warning); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintln(out, hashed)
	return err
}

// hashPasswordCommand prompts on a terminal. Without one it reads the password
// and its confirmation from two lines of stdin, which scripts and tests use.
func hashPasswordCommand(stdin *os.File, out, errw io.Writer) error {
	password, confirmation, err := readPasswordTwice(stdin, errw)
	if err != nil {
		return err
	}
	if password != confirmation {
		//lint:ignore ST1005 printed verbatim to the user, not wrapped into another error
		return errors.New("Password mismatch")
	}
	return emitPasswordHash(password, out, errw)
}

func readPasswordTwice(stdin *os.File, prompts io.Writer) (password, confirmation string, err error) {
	if !term.IsTerminal(int(stdin.Fd())) {
		return readPasswordLines(stdin)
	}
	password, err = promptPassword(stdin, prompts, "Password: ")
	if err != nil {
		return "", "", err
	}
	confirmation, err = promptPassword(stdin, prompts, "Confirmation: ")
	return password, confirmation, err
}

func promptPassword(stdin *os.File, prompts io.Writer, label string) (string, error) {
	_, _ = fmt.Fprint(prompts, label)
	typed, err := term.ReadPassword(int(stdin.Fd()))
	_, _ = fmt.Fprintln(prompts)
	return string(typed), err
}

func readPasswordLines(stdin io.Reader) (password, confirmation string, err error) {
	reader := bufio.NewReader(stdin)
	if password, err = readLine(reader); err != nil {
		return "", "", err
	}
	confirmation, err = readLine(reader)
	return password, confirmation, err
}

func readLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil && (!errors.Is(err, io.EOF) || line == "") {
		return "", fmt.Errorf("reading the password: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}
