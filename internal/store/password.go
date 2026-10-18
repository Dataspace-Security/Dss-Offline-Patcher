package store

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

// Local passwords: PBKDF2-SHA256, 16-byte random salt, stored as
// pbkdf2-sha256$<iterations>$<salt b64>$<hash b64>. Hashes never leave the
// store (not in API responses, logs or audit events).
const (
	passwordScheme  = "pbkdf2-sha256"
	passwordSaltLen = 16
	passwordKeyLen  = 32
	// MinPasswordLen / maxPasswordBytes: length rules for new passwords
	// (the maximum bounds hashing work per request).
	MinPasswordLen   = 12
	maxPasswordBytes = 256
)

// PasswordIterations is the PBKDF2 work factor for new hashes (OWASP 2023:
// 600 000 for PBKDF2-SHA256). Verification uses the count stored with each
// hash, so raising it later keeps old hashes valid. Tests lower it.
var PasswordIterations = DefaultPasswordIterations

// DefaultPasswordIterations is the production PBKDF2 work factor.
const DefaultPasswordIterations = 600_000

// HashPassword returns the encoded PBKDF2 hash of password.
func HashPassword(password string) (string, error) {
	salt := make([]byte, passwordSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	iter := PasswordIterations
	key, err := pbkdf2.Key(sha256.New, password, salt, iter, passwordKeyLen)
	if err != nil {
		return "", err
	}
	enc := base64.RawStdEncoding
	return fmt.Sprintf("%s$%d$%s$%s", passwordScheme, iter, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

// VerifyPassword reports whether password matches the encoded hash
// (constant-time comparison). A malformed hash never matches.
func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != passwordScheme {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 || iter > 10_000_000 {
		return false
	}
	enc := base64.RawStdEncoding
	salt, err1 := enc.DecodeString(parts[2])
	want, err2 := enc.DecodeString(parts[3])
	if err1 != nil || err2 != nil || len(want) == 0 {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

var (
	dummyOnce sync.Once
	dummyHash string
)

// WarmPasswordCheck prepares the throwaway hash (call at startup, so the
// first sign-in for an unknown account is not slower than the others).
func WarmPasswordCheck() { burnPasswordCheck("") }

// burnPasswordCheck does the work of one verification against a throwaway
// hash, so a sign-in for an unknown or locked account takes as long as one
// for a real account (no enumeration by timing).
func burnPasswordCheck(password string) {
	dummyOnce.Do(func() { dummyHash, _ = HashPassword(RandomSecret()) })
	VerifyPassword(dummyHash, password)
}

// ValidatePassword applies the rules for a new password of the account
// email: at least MinPasswordLen characters, not the email address (or its
// local part).
func ValidatePassword(email, password string) error {
	if len(password) > maxPasswordBytes {
		return Errf(ErrInvalid, "password is too long (at most %d bytes)", maxPasswordBytes)
	}
	if utf8.RuneCountInString(password) < MinPasswordLen {
		return Errf(ErrInvalid, "password must be at least %d characters", MinPasswordLen)
	}
	p := strings.ToLower(strings.TrimSpace(password))
	local, _, _ := strings.Cut(email, "@")
	if p == strings.ToLower(email) || p == strings.ToLower(local) {
		return Errf(ErrInvalid, "password must not be the email address")
	}
	return nil
}

// GeneratePassword returns a random 20-character password (letters and
// digits without look-alikes: about 115 bits), used for temporary and
// installer-created passwords.
func GeneratePassword() string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	b := make([]byte, 20)
	out := make([]byte, len(b))
	rand.Read(b)
	for i := range b {
		// Rejection sampling: no modulo bias.
		for b[i] >= 255-(255%byte(len(alphabet))) {
			var one [1]byte
			rand.Read(one[:])
			b[i] = one[0]
		}
		out[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(out)
}
