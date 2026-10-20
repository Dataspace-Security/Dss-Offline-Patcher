package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"offpatch/internal/totp"
)

// Authenticator-app MFA (TOTP, RFC 6238) for local users. Required for the
// bank roles (viewer, user, admin) and, by default, for super admins too
// (optional for them only with "require_mfa": false). Secrets are encrypted
// at rest with AES-256-GCM (key file, see SetMFAKey) and never returned after
// enrolment; each code works once (the last used step is kept); recovery
// codes are stored as SHA-256 hashes and work once. Wrong codes have their
// own lockout (authlimits.go), which a correct password does not reset. See
// docs/05-api.md "MFA".

const mfaSchema = `CREATE TABLE IF NOT EXISTS mfa(
  email TEXT PRIMARY KEY, secret_enc TEXT NOT NULL DEFAULT '', enrolled_at TEXT NOT NULL DEFAULT '',
  pending_enc TEXT NOT NULL DEFAULT '', pending_at TEXT NOT NULL DEFAULT '',
  last_step INTEGER NOT NULL DEFAULT 0, recovery TEXT NOT NULL DEFAULT '[]')`

const (
	// MFAIssuer is the account issuer authenticator apps show.
	MFAIssuer = "DSS Patcher"
	// RecoveryCodes generated at enrolment.
	RecoveryCodes = 10
	// mfaPendingFor: an unconfirmed enrolment expires.
	mfaPendingFor = 15 * time.Minute
)

var (
	// ErrMFAKey: no encryption key configured (SetMFAKey).
	ErrMFAKey = errors.New("MFA is not available: the server has no MFA key")
	// ErrBadMFACode is the answer to a wrong, reused or expired code.
	ErrBadMFACode = errors.New("wrong or expired code")
)

type mfaCipher struct {
	mu   sync.RWMutex
	aead cipher.AEAD
}

// SetMFAKey sets the 32-byte AES-256-GCM key that encrypts MFA secrets.
func (s *Store) SetMFAKey(key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("MFA key must be 32 bytes (got %d)", len(key))
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return err
	}
	s.mfaKey.mu.Lock()
	s.mfaKey.aead = g
	s.mfaKey.mu.Unlock()
	return nil
}

func (s *Store) sealSecret(email string, secret []byte) (string, error) {
	s.mfaKey.mu.RLock()
	g := s.mfaKey.aead
	s.mfaKey.mu.RUnlock()
	if g == nil {
		return "", ErrMFAKey
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	// The email is authenticated data: a secret copied to another row fails.
	return base64.StdEncoding.EncodeToString(g.Seal(nonce, nonce, secret, []byte(email))), nil
}

func (s *Store) openSecret(email, enc string) ([]byte, error) {
	s.mfaKey.mu.RLock()
	g := s.mfaKey.aead
	s.mfaKey.mu.RUnlock()
	if g == nil {
		return nil, ErrMFAKey
	}
	b, err := base64.StdEncoding.DecodeString(enc)
	if err != nil || len(b) < g.NonceSize() {
		return nil, errors.New("corrupt MFA secret")
	}
	out, err := g.Open(nil, b[:g.NonceSize()], b[g.NonceSize():], []byte(email))
	if err != nil {
		return nil, errors.New("MFA secret does not decrypt with the configured MFA key (key file replaced?)")
	}
	return out, nil
}

// MFARequired: bank roles always; super admins unless the server opted out
// (Policy.RequireMFA false, config "require_mfa": false).
func (s *Store) MFARequired(role string) bool {
	switch CanonicalRole(role) {
	case RoleViewer, RoleUser, RoleAdmin:
		return true
	case RoleSuperAdmin:
		return s.Policy.RequireMFA
	}
	return true
}

// MFAEnrolled reports whether email has a confirmed authenticator.
func (s *Store) MFAEnrolled(ctx context.Context, email string) (bool, error) {
	var at string
	err := s.db.QueryRowContext(ctx, `SELECT enrolled_at FROM mfa WHERE email=?`, email).Scan(&at)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return at != "", err
}

// MFAEnrollment is what enrolment start returns (once).
type MFAEnrollment struct {
	SecretBase32 string `json:"secret_base32"`
	OTPAuthURI   string `json:"otpauth_uri"`
}

func (s *Store) requireLocal(ctx context.Context, email string) error {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM local_users WHERE email=?`, email).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return Errf(ErrConflict, "only local (email + password) users enrol an authenticator here; SSO users use their identity provider's MFA")
	}
	return nil
}

// MFAEnrollStart creates a new pending secret for email (replacing an
// unconfirmed one). 409 when an authenticator is already enrolled (an
// admin resets it first).
func (s *Store) MFAEnrollStart(ctx context.Context, email string) (MFAEnrollment, error) {
	if err := s.requireLocal(ctx, email); err != nil {
		return MFAEnrollment{}, err
	}
	if ok, err := s.MFAEnrolled(ctx, email); err != nil {
		return MFAEnrollment{}, err
	} else if ok {
		return MFAEnrollment{}, Errf(ErrConflict, "an authenticator is already enrolled; ask an administrator to reset MFA to enrol a new one")
	}
	secret, err := totp.NewSecret()
	if err != nil {
		return MFAEnrollment{}, err
	}
	enc, err := s.sealSecret(email, secret)
	if err != nil {
		return MFAEnrollment{}, err
	}
	err = s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO mfa(email, pending_enc, pending_at) VALUES(?,?,?)
			ON CONFLICT(email) DO UPDATE SET pending_enc=excluded.pending_enc, pending_at=excluded.pending_at`, email, enc, s.now()); err != nil {
			return err
		}
		return s.audit(tx, Ev{Actor: "user:" + email, Action: "user.mfa_enrollment_started", ObjectType: "user", ObjectID: email})
	})
	b32 := totp.EncodeSecret(secret)
	return MFAEnrollment{SecretBase32: b32, OTPAuthURI: totp.URI(MFAIssuer, email, b32)}, err
}

func newRecoveryCode() string {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
	b := make([]byte, 10)
	rand.Read(b)
	out := make([]byte, 0, 11)
	for i, c := range b {
		if i == 5 {
			out = append(out, '-')
		}
		out = append(out, alphabet[int(c)%len(alphabet)])
	}
	return string(out)
}

func normRecovery(c string) string {
	return strings.NewReplacer("-", "", " ", "").Replace(strings.ToLower(strings.TrimSpace(c)))
}

// MFAEnrollConfirm checks code against the pending secret, enables MFA and
// returns RecoveryCodes one-time recovery codes (shown once). The session
// sessionToken (the enrolment-only one, or the super admin's) becomes a
// full, MFA-verified session.
func (s *Store) MFAEnrollConfirm(ctx context.Context, email, code, sessionToken string) ([]string, error) {
	var pending, pendingAt string
	err := s.db.QueryRowContext(ctx, `SELECT pending_enc, pending_at FROM mfa WHERE email=? AND enrolled_at=''`, email).Scan(&pending, &pendingAt)
	if errors.Is(err, sql.ErrNoRows) || err == nil && pending == "" {
		return nil, Errf(ErrConflict, "no enrolment in progress: start it first")
	}
	if err != nil {
		return nil, err
	}
	if s.Now().Sub(parseTime(pendingAt)) > mfaPendingFor {
		return nil, Errf(ErrConflict, "the enrolment expired: start it again")
	}
	secret, err := s.openSecret(email, pending)
	if err != nil {
		return nil, err
	}
	step, ok := totp.Verify(secret, code, s.Now(), 0)
	if !ok {
		s.Audit(ctx, Ev{Actor: "user:" + email, Action: "auth.mfa_failed", ObjectType: "user", ObjectID: email, Failure: true,
			Details: map[string]any{"stage": "enrolment"}})
		return nil, Errf(ErrInvalid, "%s", ErrBadMFACode.Error())
	}
	codes := make([]string, RecoveryCodes)
	hashes := make([]string, RecoveryCodes)
	for i := range codes {
		codes[i] = newRecoveryCode()
		hashes[i] = HashSecret(normRecovery(codes[i]))
	}
	err = s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`UPDATE mfa SET secret_enc=pending_enc, enrolled_at=?, pending_enc='', pending_at='', last_step=?, recovery=? WHERE email=?`,
			s.now(), step, mustJSON(hashes), email); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE sessions SET mfa=1, mfa_enroll_only=0 WHERE id_hash=? AND username=?`, HashSecret(sessionToken), email); err != nil {
			return err
		}
		return s.audit(tx, Ev{Actor: "user:" + email, Action: "user.mfa_enrolled", ObjectType: "user", ObjectID: email,
			Details: map[string]any{"recovery_codes": RecoveryCodes}})
	})
	return codes, err
}

// LoginMFA is the second sign-in step after LoginPassword returned
// MFAPending: a 6-digit code (each step once) or a recovery code (each
// once). Wrong codes count towards the authenticator lockout (not reset by
// a correct password): ErrMFALocked once it is locked. A locked account is
// refused like a wrong code. Success opens an MFA-verified session and
// clears the authenticator's failure count.
func (s *Store) LoginMFA(ctx context.Context, email, code, recovery string, ttl time.Duration) (PasswordLogin, error) {
	var role, lockedUntil, mfaLockedUntil, enc, rec string
	var must int
	var last int64
	err := s.db.QueryRowContext(ctx, `SELECT l.role, l.must_change_password, l.locked_until, f.locked_until, f.secret_enc, f.last_step, f.recovery
		FROM local_users l JOIN mfa f ON f.email=l.email WHERE l.email=? AND f.enrolled_at != ''`, email).Scan(&role, &must, &lockedUntil, &mfaLockedUntil, &enc, &last, &rec)
	fail := func(reason string, locked bool) (PasswordLogin, error) {
		s.Audit(ctx, Ev{Actor: "user:" + email, Action: "auth.mfa_failed", ObjectType: "user", ObjectID: email, Failure: true,
			Details: map[string]any{"reason": reason, "locked": locked}})
		if locked {
			return PasswordLogin{}, ErrMFALocked
		}
		return PasswordLogin{}, ErrBadMFACode
	}
	if errors.Is(err, sql.ErrNoRows) {
		return fail("no authenticator enrolled", false)
	}
	if err != nil {
		return PasswordLogin{}, err
	}
	if lockedUntil != "" && s.Now().Before(parseTime(lockedUntil)) {
		return fail("account locked", false)
	}
	if mfaLockedUntil != "" && s.Now().Before(parseTime(mfaLockedUntil)) {
		return fail("authenticator locked", true)
	}
	secret, err := s.openSecret(email, enc)
	if err != nil {
		return PasswordLogin{}, err
	}
	var hashes []string
	json.Unmarshal([]byte(rec), &hashes)
	usedRecovery := false
	var step int64
	switch {
	case strings.TrimSpace(recovery) != "":
		h := HashSecret(normRecovery(recovery))
		idx := -1
		for i, x := range hashes {
			if x == h {
				idx = i
			}
		}
		if idx < 0 {
			locked, err := s.recordMFAFailure(ctx, email, "recovery code")
			if err != nil {
				return PasswordLogin{}, err
			}
			return fail("wrong recovery code", locked)
		}
		hashes = append(hashes[:idx:idx], hashes[idx+1:]...)
		usedRecovery = true
	default:
		var ok bool
		if step, ok = totp.Verify(secret, code, s.Now(), last); !ok {
			reason := "wrong code"
			if _, any := totp.Verify(secret, code, s.Now(), -1); any {
				reason = "code already used"
			}
			locked, err := s.recordMFAFailure(ctx, email, "mfa code")
			if err != nil {
				return PasswordLogin{}, err
			}
			return fail(reason, locked)
		}
	}
	// The code is spent before the session exists (a concurrent replay of
	// the same step finds last_step moved on).
	var spent, lockedMeanwhile bool
	err = s.tx(ctx, func(tx *sql.Tx) error {
		var res sql.Result
		var err error
		// A lock set by a parallel wrong code since the read above wins.
		var until string
		if err := tx.QueryRow(`SELECT locked_until FROM mfa WHERE email=?`, email).Scan(&until); err != nil {
			return err
		}
		if until != "" && s.Now().Before(parseTime(until)) {
			lockedMeanwhile = true
			return nil
		}
		if usedRecovery {
			res, err = tx.Exec(`UPDATE mfa SET recovery=? WHERE email=? AND recovery=?`, mustJSON(hashes), email, rec)
		} else {
			res, err = tx.Exec(`UPDATE mfa SET last_step=? WHERE email=? AND last_step < ?`, step, email, step)
		}
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		spent = n == 1
		if !spent {
			return nil
		}
		if _, err := tx.Exec(`UPDATE mfa SET failed_attempts=0, locked_until='', lockouts=0 WHERE email=?`, email); err != nil {
			return err
		}
		if usedRecovery {
			return s.audit(tx, Ev{Actor: "user:" + email, Action: "auth.mfa_recovery_used", ObjectType: "user", ObjectID: email,
				Details: map[string]any{"recovery_codes_left": len(hashes)}})
		}
		return nil
	})
	if err != nil {
		return PasswordLogin{}, err
	}
	if lockedMeanwhile {
		return fail("authenticator locked", true)
	}
	if !spent {
		return fail("code already used", false)
	}
	tok, err := s.login(ctx, email, role, email, "password", true, false, ttl)
	if err != nil {
		return PasswordLogin{}, err
	}
	return PasswordLogin{Token: tok, Email: email, Role: canonicalOr(role), MustChangePassword: must == 1}, nil
}

// ResetMFA removes a user's authenticator and recovery codes and ends
// their sessions: they enrol again at the next sign-in. Admins reset
// viewers and users; only a super admin resets an admin or a super admin.
// The resetter becomes the account's credential steward.
func (s *Store) ResetMFA(ctx context.Context, by Manager, email, reason string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if by.is(email) {
		return Errf(ErrConflict, "you cannot reset your own MFA; ask another administrator")
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		t, err := getUserTarget(tx, email)
		if err != nil {
			return err
		}
		if err := checkCredentials(by, t.role, ""); err != nil {
			return err
		}
		if !t.local {
			return Errf(ErrConflict, "%s signs in with SSO; MFA is managed by the identity provider", email)
		}
		res, err := tx.Exec(`DELETE FROM mfa WHERE email=?`, email)
		if err != nil {
			return err
		}
		if err := s.setSteward(tx, by, email); err != nil {
			return err
		}
		had, _ := res.RowsAffected()
		if _, err := tx.Exec(`UPDATE sessions SET revoked=1 WHERE username=?`, email); err != nil {
			return err
		}
		return s.audit(tx, Ev{Actor: by.Actor, Action: "user.mfa_reset", ObjectType: "user", ObjectID: email,
			Details: map[string]any{"reason": reason, "role": t.role, "was_enrolled": had > 0}})
	})
}

// DisableOwnMFA: a super admin (for whom MFA is optional) removes their own
// authenticator, confirming with a current code. Bank roles cannot (MFA is
// required for them).
func (s *Store) DisableOwnMFA(ctx context.Context, email, role, code string) error {
	if CanonicalRole(role) != RoleSuperAdmin {
		return Errf(ErrForbidden, "MFA is required for your role; an administrator can reset it")
	}
	if s.MFARequired(role) {
		return Errf(ErrConflict, "this server requires MFA for every account (the default; only \"require_mfa\": false makes it optional for super admins)")
	}
	var enc string
	var last int64
	err := s.db.QueryRowContext(ctx, `SELECT secret_enc, last_step FROM mfa WHERE email=? AND enrolled_at != ''`, email).Scan(&enc, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return Errf(ErrConflict, "no authenticator is enrolled")
	}
	if err != nil {
		return err
	}
	secret, err := s.openSecret(email, enc)
	if err != nil {
		return err
	}
	if locked, err := s.mfaLocked(ctx, email); err != nil {
		return err
	} else if locked {
		return ErrMFALocked
	}
	if _, ok := totp.Verify(secret, code, s.Now(), last); !ok {
		if locked, err := s.recordMFAFailure(ctx, email, "mfa code (disable)"); err != nil {
			return err
		} else if locked {
			return ErrMFALocked
		}
		s.Audit(ctx, Ev{Actor: "user:" + email, Action: "auth.mfa_failed", ObjectType: "user", ObjectID: email, Failure: true,
			Details: map[string]any{"stage": "disable"}})
		return Errf(ErrInvalid, "%s", ErrBadMFACode.Error())
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`DELETE FROM mfa WHERE email=?`, email); err != nil {
			return err
		}
		return s.audit(tx, Ev{Actor: "user:" + email, Action: "user.mfa_disabled", ObjectType: "user", ObjectID: email})
	})
}
