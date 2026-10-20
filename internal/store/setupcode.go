package store

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// One-time setup code (security review S-1). The built-in super admin keeps
// its fixed, vendor-wide default password (an owner decision), so knowing
// that password must not be enough to take the account over between
// "installer finished" and "the bank operator signs in". While a local
// user's stored hash is still DefaultSuperAdminPasswordHash, a sign-in also
// needs a setup code that only someone with root on the server can obtain:
// pmserver setup-code (run by the installer) generates it, stores only its
// hash and prints it once.
//
//   - The code is checked after the (slow) password check, in the same
//     transaction that records the outcome, and a missing, wrong or expired
//     code is answered exactly like a wrong password (ErrBadCredentials,
//     same PBKDF2 work, counted by the lockout of authlimits.go, audited
//     with the real reason). The server never reveals whether the password
//     alone was right, so the setup code field cannot be used as an oracle
//     for the default password.
//   - It is valid until the password is changed (every password change
//     deletes it) or for SetupCodeValidFor, whichever comes first. A new
//     code replaces the previous one.
//   - Accounts with their own password are unaffected; a code sent for them
//     is ignored.
const setupCodesSchema = `CREATE TABLE IF NOT EXISTS setup_codes(
  email TEXT PRIMARY KEY, code_hash TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL)`

const (
	// SetupCodeValidFor: a setup code expires this long after it is made.
	SetupCodeValidFor = 7 * 24 * time.Hour
	// setupCodeAlphabet: upper-case letters and digits without look-alikes
	// (no 0/O, 1/I/L); 12 characters are about 59 bits.
	setupCodeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
	setupCodeLen      = 12
	setupCodeGroup    = 4
)

// defaultPasswordHash is the hash that makes a setup code necessary
// (DefaultSuperAdminPasswordHash; a variable only so tests can sign in
// without the plaintext default).
var defaultPasswordHash = DefaultSuperAdminPasswordHash

// GenerateSetupCode returns a random setup code in groups of four
// ("ABCD-EFGH-JKMN").
func GenerateSetupCode() string {
	var sb strings.Builder
	limit := byte(255 - (256 % len(setupCodeAlphabet)))
	for i := 0; i < setupCodeLen; i++ {
		if i > 0 && i%setupCodeGroup == 0 {
			sb.WriteByte('-')
		}
		var one [1]byte
		for { // rejection sampling: no modulo bias
			rand.Read(one[:])
			if one[0] <= limit {
				break
			}
		}
		sb.WriteByte(setupCodeAlphabet[int(one[0])%len(setupCodeAlphabet)])
	}
	return sb.String()
}

// normalizeSetupCode: what was typed, upper-case, without spaces and dashes.
func normalizeSetupCode(code string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '-', ' ', '\t':
			return -1
		}
		if r >= 'a' && r <= 'z' {
			return r - 'a' + 'A'
		}
		return r
	}, code)
}

// CreateSetupCode (pmserver setup-code) gives the local user email (whose
// password must still be the built-in default) a new setup code, replacing
// any earlier one, and returns it with its expiry. Only its hash is stored.
func (s *Store) CreateSetupCode(ctx context.Context, email string) (code string, expires time.Time, err error) {
	email, err = NormalizeEmail(email)
	if err != nil {
		return "", time.Time{}, err
	}
	code = GenerateSetupCode()
	now := s.Now()
	expires = now.Add(SetupCodeValidFor).UTC()
	expiresAt := expires.Format(time.RFC3339Nano)
	err = s.tx(ctx, func(tx *sql.Tx) error {
		var hash string
		err := tx.QueryRow(`SELECT password_hash FROM local_users WHERE email=?`, email).Scan(&hash)
		if errors.Is(err, sql.ErrNoRows) {
			return Errf(ErrNotFound, "local user %s", email)
		}
		if err != nil {
			return err
		}
		if hash != defaultPasswordHash {
			return Errf(ErrConflict, "%s no longer uses the default password: no setup code is needed", email)
		}
		if _, err := tx.Exec(`INSERT INTO setup_codes(email,code_hash,created_at,expires_at) VALUES(?,?,?,?)
			ON CONFLICT(email) DO UPDATE SET code_hash=excluded.code_hash, created_at=excluded.created_at, expires_at=excluded.expires_at`,
			email, HashSecret(normalizeSetupCode(code)), now.UTC().Format(time.RFC3339Nano), expiresAt); err != nil {
			return err
		}
		return s.audit(tx, Ev{Actor: "system:cli", Action: "user.setup_code_created", ObjectType: "user", ObjectID: email,
			Details: map[string]any{"expires_at": expiresAt}})
	})
	if err != nil {
		return "", time.Time{}, err
	}
	return code, expires, nil
}

// setupCodeOK reports whether code is email's current, unexpired setup code.
func (s *Store) setupCodeOK(tx *sql.Tx, email, code string) (bool, error) {
	var stored, expires string
	err := tx.QueryRow(`SELECT code_hash, expires_at FROM setup_codes WHERE email=?`, email).Scan(&stored, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	given := HashSecret(normalizeSetupCode(code))
	match := subtle.ConstantTimeCompare([]byte(given), []byte(stored)) == 1
	return match && s.Now().Before(parseTime(expires)), nil
}

// deleteSetupCode: the password changed, the setup code is no longer valid.
func deleteSetupCode(tx *sql.Tx, email string) error {
	_, err := tx.Exec(`DELETE FROM setup_codes WHERE email=?`, email)
	return err
}
