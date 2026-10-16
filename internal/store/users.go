package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Users are created on first SSO login (identity lives in the IdP); the
// store keeps last-login, role at last login, and a local disable switch.
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

type User struct {
	Username       string `json:"username"`
	Role           string `json:"role"`
	Source         string `json:"source"`
	Email          string `json:"email"`
	MFA            bool   `json:"mfa"`
	FirstLogin     string `json:"first_login"`
	LastLogin      string `json:"last_login"`
	Disabled       bool   `json:"disabled"`
	DisabledReason string `json:"disabled_reason"`
	ActiveSessions int    `json:"active_sessions"`
}

var ErrDisabled = errors.New("user disabled")

// Login records a successful SSO login and creates a session. Disabled
// users are refused (and the attempt audited).
func (s *Store) Login(ctx context.Context, username, role, email, source string, mfa bool, ttl time.Duration) (string, error) {
	token := "ses_" + RandomSecret()
	err := s.tx(ctx, func(tx *sql.Tx) error {
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
			ON CONFLICT(username) DO UPDATE SET role=excluded.role, source=excluded.source, email=excluded.email, mfa=excluded.mfa, last_login=excluded.last_login`,
			username, role, source, email, m, now, now); err != nil {
			return err
		}
		exp := s.Now().Add(ttl).UTC().Format(time.RFC3339Nano)
		if _, err := tx.Exec(`INSERT INTO sessions(id_hash,username,role,mfa,created_at,expires_at) VALUES(?,?,?,?,?,?)`, HashSecret(token), username, role, m, now, exp); err != nil {
			return err
		}
		return s.audit(tx, Ev{Actor: "user:" + username, Action: "auth.login", ObjectType: "user", ObjectID: username,
			Details: map[string]any{"role": role, "source": source, "mfa": mfa, "session_expires": exp}})
	})
	if errors.Is(err, ErrDisabled) {
		s.Audit(ctx, Ev{Actor: "user:" + username, Action: "auth.login_denied", ObjectType: "user", ObjectID: username, Failure: true,
			Details: map[string]any{"reason": "user disabled"}})
	}
	return token, err
}

type Session struct {
	Username string
	Role     string
	MFA      bool
}

func (s *Store) LookupSession(ctx context.Context, token string) (Session, error) {
	var ss Session
	var exp string
	var m, revoked, disabled int
	err := s.db.QueryRowContext(ctx, `SELECT s.username, s.role, s.mfa, s.expires_at, s.revoked, COALESCE(u.disabled,0)
		FROM sessions s LEFT JOIN users u ON u.username=s.username WHERE s.id_hash=?`, HashSecret(token)).Scan(&ss.Username, &ss.Role, &m, &exp, &revoked, &disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return ss, ErrNotFound
	}
	if err != nil {
		return ss, err
	}
	if revoked == 1 || disabled == 1 || s.Now().After(parseTime(exp)) {
		return ss, ErrNotFound
	}
	ss.MFA = m == 1
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

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT u.username,u.role,u.source,u.email,u.mfa,u.first_login,u.last_login,u.disabled,u.disabled_reason,
		(SELECT COUNT(*) FROM sessions s WHERE s.username=u.username AND s.revoked=0 AND s.expires_at > ?)
		FROM users u ORDER BY u.username`, s.now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		var u User
		var m, d int
		if err := rows.Scan(&u.Username, &u.Role, &u.Source, &u.Email, &m, &u.FirstLogin, &u.LastLogin, &d, &u.DisabledReason, &u.ActiveSessions); err != nil {
			return nil, err
		}
		u.MFA, u.Disabled = m == 1, d == 1
		out = append(out, u)
	}
	return out, rows.Err()
}

// SetUserDisabled blocks (or unblocks) a user locally and revokes sessions.
func (s *Store) SetUserDisabled(ctx context.Context, actor, username string, disabled bool, reason string) error {
	if err := requireReason(reason); err != nil {
		return err
	}
	if actor == "user:"+username && disabled {
		return Errf(ErrConflict, "you cannot disable yourself")
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		d := 0
		if disabled {
			d = 1
		}
		res, err := tx.Exec(`UPDATE users SET disabled=?, disabled_reason=? WHERE username=?`, d, reason, username)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return Errf(ErrNotFound, "user %s", username)
		}
		if disabled {
			if _, err := tx.Exec(`UPDATE sessions SET revoked=1 WHERE username=?`, username); err != nil {
				return err
			}
		}
		action := "user.enabled"
		if disabled {
			action = "user.disabled"
		}
		return s.audit(tx, Ev{Actor: actor, Action: action, ObjectType: "user", ObjectID: username, Details: map[string]any{"reason": reason}})
	})
}
