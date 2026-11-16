package auth

import "golang.org/x/crypto/argon2"

func argon2iKey(password string, salt []byte) []byte {
	return argon2.Key([]byte(password), salt, 1, 1024, 1, digestBytes)
}
