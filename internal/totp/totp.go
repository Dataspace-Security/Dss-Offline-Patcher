// Package totp implements time-based one-time passwords for authenticator
// apps: RFC 6238 over RFC 4226 HOTP with HMAC-SHA-1, 6 digits and a 30 s
// step (what Google Authenticator, Microsoft Authenticator and FreeOTP use
// by default). Standard library only.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	Digits = 6
	Period = 30 // seconds
	// Skew: steps accepted either side of the current one (clock drift).
	Skew = 1
	// SecretBytes: 160-bit secrets (RFC 4226 recommends at least 128).
	SecretBytes = 20
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret returns a random secret.
func NewSecret() ([]byte, error) {
	b := make([]byte, SecretBytes)
	_, err := rand.Read(b)
	return b, err
}

// EncodeSecret is the base32 form authenticator apps take (no padding).
func EncodeSecret(secret []byte) string { return b32.EncodeToString(secret) }

// DecodeSecret parses a base32 secret (case and spaces ignored).
func DecodeSecret(s string) ([]byte, error) {
	s = strings.ToUpper(strings.ReplaceAll(strings.TrimRight(s, "="), " ", ""))
	return b32.DecodeString(s)
}

// HOTP is RFC 4226 with HMAC-SHA-1 and the given number of digits.
func HOTP(secret []byte, counter uint64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, v%mod)
}

// Step is the RFC 6238 time step of t.
func Step(t time.Time) int64 { return t.Unix() / Period }

// Code is the 6-digit code for t.
func Code(secret []byte, t time.Time) string { return HOTP(secret, uint64(Step(t)), Digits) }

// Verify checks code against the steps around now (±Skew) that are later
// than lastStep (each code works once). It returns the matched step.
func Verify(secret []byte, code string, now time.Time, lastStep int64) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != Digits {
		return 0, false
	}
	cur := Step(now)
	for s := cur - Skew; s <= cur+Skew; s++ {
		if s <= lastStep || s < 0 {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(HOTP(secret, uint64(s), Digits)), []byte(code)) == 1 {
			return s, true
		}
	}
	return 0, false
}

// URI is the otpauth:// URI for a QR code: label "<issuer>:<account>".
func URI(issuer, account, secretB32 string) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	q := "secret=" + secretB32 + "&issuer=" + url.PathEscape(issuer) + fmt.Sprintf("&digits=%d&period=%d", Digits, Period)
	return "otpauth://totp/" + label + "?" + q
}
