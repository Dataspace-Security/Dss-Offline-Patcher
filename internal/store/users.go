package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Users are created on first SSO login (identity lives in the IdP) or by an
// admin as local (email + password) users (localusers.go); the store keeps
// last-login, role at last login, and a local disable switch for both.
const usersSchema = `
CREATE TABLE IF NOT EXISTS users(
  username TEXT PRIMARY KEY, role TEXT NOT NULL, source TEXT NOT NULL, email TEXT NOT NULL DEFAULT '',
  mfa INTEGER NOT NULL DEFAULT 0, first_login TEXT NOT NULL, last_login TEXT NOT NULL,
  disabled INTEGER NOT NULL DEFAULT 0, disabled_reason TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS sessions(
  id_hash TEXT PRIMARY KEY, username TEXT NOT NULL, role TEXT NOT NULL, mfa INTEGER NOT NULL,
  created_at TEXT NOT NULL, expires_at TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(username);
CREATE TABLE IF NOT EXISTS package_approvals(
  package_id TEXT NOT NULL, approver TEXT NOT NULL, reason TEXT NOT NULL, at TEXT NOT NULL,
  PRIMARY KEY(package_id, approver));
`

// User is one row of GET /api/users. Password hashes are never part of it.
type User struct {
	Username       string `json:"username"` // the sign-in id (the email for local users)
	Role           string `json:"role"`
	Source         string `json:"source"` // oidc (SSO) | local (email + password)
	Auth           string `json:"auth"`   // sso | password
	Email          string `json:"email"`
	DisplayName    string `json:"display_name"`
	MFA            bool   `json:"mfa"`
	FirstLogin     string `json:"first_login"`
	LastLogin      string `json:"last_login"`
	Disabled       bool   `json:"disabled"`
	DisabledReason string `json:"disabled_reason"`
	ActiveSessions int    `json:"active_sessions"`
	// Local (password) users only.
	MustChangePassword bool `json:"must_change_password"`
	// MFAEnrolled: a local user with an authenticator app enrolled.
	MFAEnrolled       bool   `json:"mfa_enrolled"`
	Locked            bool   `json:"locked"`
	LockedUntil       string `json:"locked_until,omitempty"`
	CreatedBy         string `json:"created_by,omitempty"`
	CreatedAt         string `json:"created_at,omitempty"`
	PasswordChangedAt string `json:"password_changed_at,omitempty"`
}

var ErrDisabled = errors.New("user disabled")

// Login records a successful sign-in (SSO, or a verified local password:
// source "password") and creates a session. Disabled users are refused
// (and the attempt audited). An SSO identity with the name of a local user
// is refused: it would act as that user.
func (s *Store) Login(ctx context.Context, username, role, email, source string, mfa bool, ttl time.Duration) (string, error) {
	return s.login(ctx, username, role, email, source, mfa, false, ttl)
}

// login opens a session; enrollOnly limits it to MFA enrolment (a local
// user who must enrol an authenticator before anything else).
func (s *Store) login(ctx context.Context, username, role, email, source string, mfa, enrollOnly bool, ttl time.Duration) (string, error) {
	token := "ses_" + RandomSecret()
	role = canonicalOr(role)
	err := s.tx(ctx, func(tx *sql.Tx) error {
		if source != "password" {
			var n int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM local_users WHERE email=lower(?)`, username).Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				return Errf(ErrConflict, "%s is a local (password) user; SSO sign-in with that name is refused", username)
			}
		}
		var disabled int
		err := tx.QueryRow(`SELECT disabled FROM users WHERE username=?`, username).Scan(&disabled)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if disabled == 1 {
			return ErrDisabled
		}
		now := s.now()
		m := 0
		if mfa {
			m = 1
		}
		if _, err := tx.Exec(`INSERT INTO users(username,role,source,email,mfa,first_login,last_login) VALUES(?,?,?,?,?,?,?)
			ON CONFLICT(username) DO UPDATE SET role=excluded.role, source=excluded.source, email=excluded.email, mfa=excluded.mfa, last_login=excluded.last_login,
			first_login=CASE WHEN users.first_login='' THEN excluded.first_login ELSE users.first_login END`,
			username, role, source, email, m, now, now); err != nil {
			return err
		}
		exp := s.Now().Add(ttl).UTC().Format(time.RFC3339Nano)
		if _, err := tx.Exec(`INSERT INTO sessions(id_hash,username,role,mfa,created_at,expires_at,source,mfa_enroll_only) VALUES(?,?,?,?,?,?,?,?)`,
			HashSecret(token), username, role, m, now, exp, source, boolInt(enrollOnly)); err != nil {
			return err
		}
		d := map[string]any{"role": role, "source": source, "mfa": mfa, "session_expires": exp}
		if enrollOnly {
			d["mfa_enrollment_required"] = true
		}
		return s.audit(tx, Ev{Actor: "user:" + username, Action: "auth.login", ObjectType: "user", ObjectID: username, Details: d})
	})
	if errors.Is(err, ErrDisabled) || errors.Is(err, ErrConflict) {
		reason := "user disabled"
		if errors.Is(err, ErrConflict) {
			reason = "SSO name is a local user"
		}
		s.Audit(ctx, Ev{Actor: "user:" + username, Action: "auth.login_denied", ObjectType: "user", ObjectID: username, Failure: true,
			Details: map[string]any{"reason": reason, "source": source}})
	}
	return token, err
}

// canonicalOr maps aliases to canonical role names, keeping unknown names
// as they are (they have no access: RoleRank 0).
func canonicalOr(role string) string {
	if c := CanonicalRole(role); c != "" {
		return c
	}
	return role
}

type Session struct {
	Username string
	Role     string
	MFA      bool
	// Source: oidc (SSO) | password (local user).
	Source string
	// MustChangePassword: a local user signed in with a temporary
	// password; only /api/me, password change and logout are allowed.
	MustChangePassword bool
	// MFAEnrollOnly: MFA is required and not enrolled yet; only /api/me,
	// enrolment, password change and logout are allowed.
	MFAEnrollOnly bool
}

func (s *Store) LookupSession(ctx context.Context, token string) (Session, error) {
	var ss Session
	var exp string
	var m, revoked, disabled, must, enroll int
	err := s.db.QueryRowContext(ctx, `SELECT s.username, s.role, s.mfa, s.expires_at, s.revoked, COALESCE(u.disabled,0), s.source, COALESCE(l.must_change_password,0), s.mfa_enroll_only
		FROM sessions s LEFT JOIN users u ON u.username=s.username LEFT JOIN local_users l ON l.email=s.username AND s.source='password'
		WHERE s.id_hash=?`, HashSecret(token)).Scan(&ss.Username, &ss.Role, &m, &exp, &revoked, &disabled, &ss.Source, &must, &enroll)
	if errors.Is(err, sql.ErrNoRows) {
		return ss, ErrNotFound
	}
	if err != nil {
		return ss, err
	}
	if revoked == 1 || disabled == 1 || s.Now().After(parseTime(exp)) {
		return ss, ErrNotFound
	}
	ss.MFA, ss.MustChangePassword, ss.MFAEnrollOnly = m == 1, must == 1, enroll == 1
	ss.Role = canonicalOr(ss.Role)
	return ss, nil
}

func (s *Store) Logout(ctx context.Context, token string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var user string
		if err := tx.QueryRow(`SELECT username FROM sessions WHERE id_hash=?`, HashSecret(token)).Scan(&user); err != nil {
			return nil
		}
		if _, err := tx.Exec(`UPDATE sessions SET revoked=1 WHERE id_hash=?`, HashSecret(token)); err != nil {
			return err
		}
		return s.audit(tx, Ev{Actor: "user:" + user, Action: "auth.logout", ObjectType: "user", ObjectID: user})
	})
}

// ListUsers returns SSO users (seen at sign-in) and local users. No
// password hashes.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	now := s.now()
	rows, err := s.db.QueryContext(ctx, `SELECT u.username,u.role,u.source,u.email,u.mfa,u.first_login,u.last_login,u.disabled,u.disabled_reason,
		(SELECT COUNT(*) FROM sessions s WHERE s.username=u.username AND s.revoked=0 AND s.expires_at > ?),
		l.email IS NOT NULL, COALESCE(l.display_name,''), COALESCE(l.role,''), COALESCE(l.must_change_password,0), COALESCE(l.locked_until,''),
		COALESCE(l.created_by,''), COALESCE(l.created_at,''), COALESCE(l.password_changed_at,''), COALESCE(f.enrolled_at,''),
		COALESCE(f.locked_until,''), (SELECT COALESCE(MAX(x.locked_until),'') FROM login_failures x WHERE x.email=u.username)
		FROM users u LEFT JOIN local_users l ON l.email=u.username LEFT JOIN mfa f ON f.email=u.username ORDER BY u.username`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		var u User
		var m, d, must int
		var local bool
		var lrole, mfaAt, mfaLock, srcLock string
		if err := rows.Scan(&u.Username, &u.Role, &u.Source, &u.Email, &m, &u.FirstLogin, &u.LastLogin, &d, &u.DisabledReason, &u.ActiveSessions,
			&local, &u.DisplayName, &lrole, &must, &u.LockedUntil, &u.CreatedBy, &u.CreatedAt, &u.PasswordChangedAt, &mfaAt, &mfaLock, &srcLock); err != nil {
			return nil, err
		}
		u.MFAEnrolled = mfaAt != ""
		u.MFA, u.Disabled, u.MustChangePassword = m == 1, d == 1, must == 1
		u.Auth = "sso"
		if local {
			u.Auth, u.Source, u.Role, u.Email = "password", "local", lrole, u.Username
			// Any sign-in lock (account, authenticator, or one address);
			// enabling the user clears them all.
			u.LockedUntil = s.anyAuthLock(u.LockedUntil, mfaLock, srcLock)
			u.Locked = u.LockedUntil != ""
		}
		u.Role = canonicalOr(u.Role)
		out = append(out, u)
	}
	return out, rows.Err()
}

// UserEmail is the email recorded for a user at sign-in ("" if none).
func (s *Store) UserEmail(ctx context.Context, username string) (string, error) {
	var e string
	err := s.db.QueryRowContext(ctx, `SELECT email FROM users WHERE username=?`, username).Scan(&e)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return e, err
}
