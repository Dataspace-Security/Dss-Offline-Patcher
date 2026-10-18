package store

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Local users sign in with email + password (no directory needed). The
// email is the sign-in id and the user's name everywhere else (sessions,
// the users table, audit actors "user:<email>"). The disable switch is the
// shared users.disabled (one switch for SSO and local users).
const localUsersSchema = `CREATE TABLE IF NOT EXISTS local_users(
  email TEXT PRIMARY KEY, display_name TEXT NOT NULL DEFAULT '', role TEXT NOT NULL, password_hash TEXT NOT NULL,
  must_change_password INTEGER NOT NULL DEFAULT 0, failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until TEXT NOT NULL DEFAULT '', created_by TEXT NOT NULL, created_at TEXT NOT NULL,
  password_changed_at TEXT NOT NULL DEFAULT '', builtin INTEGER NOT NULL DEFAULT 0)`

const (
	// MaxFailedLogins wrong passwords in a row lock the account for LockFor.
	MaxFailedLogins = 5
	LockFor         = 15 * time.Minute
)

// ErrBadCredentials is the only answer to a failed sign-in: unknown email,
// wrong password and locked account look the same (no enumeration).
var ErrBadCredentials = errors.New("wrong email or password")

var emailRe = regexp.MustCompile(`^[a-z0-9._+-]{1,64}@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

// NormalizeEmail lowercases and validates a sign-in email address.
func NormalizeEmail(s string) (string, error) {
	e := strings.ToLower(strings.TrimSpace(s))
	local, _, _ := strings.Cut(e, "@")
	if len(e) > 254 || !emailRe.MatchString(e) || strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") {
		return "", Errf(ErrInvalid, "a valid email address is required (letters, digits and . _ + - before the @)")
	}
	return e, nil
}

func cleanDisplayName(name, email string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		name, _, _ = strings.Cut(email, "@")
	}
	if utf8.RuneCountInString(name) > 100 || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return "", Errf(ErrInvalid, "display_name: at most 100 characters, no control characters")
	}
	return name, nil
}

// Manager is who manages users: the actor ("user:<name>", or "system:cli"
// for the pmserver commands) and their canonical role.
type Manager struct {
	Actor string
	Role  string
}

func (m Manager) is(username string) bool { return m.Actor == "user:"+username }

type NewLocalUser struct {
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
	Password    string `json:"password"`
}

// LocalUserCreated is returned by CreateLocalUser (no secrets).
type LocalUserCreated struct {
	Email              string `json:"email"`
	DisplayName        string `json:"display_name"`
	Role               string `json:"role"`
	MustChangePassword bool   `json:"must_change_password"`
}

// checkManage applies the role limits: only admins and super admins manage
// users; only a super admin may touch a super admin or grant that role.
func checkManage(by Manager, targetRole, newRole string) error {
	if RoleRank(by.Role) < RoleRank(RoleAdmin) {
		return Errf(ErrForbidden, "managing users requires role admin")
	}
	if by.Role != RoleSuperAdmin && (targetRole == RoleSuperAdmin || newRole == RoleSuperAdmin) {
		return Errf(ErrForbidden, "only a super admin can manage super admin accounts")
	}
	return nil
}

// otherSuperAdmins counts super admins that can still sign in besides
// email: enabled local super admins and static super_admin tokens.
func (s *Store) otherSuperAdmins(tx *sql.Tx, email string) (int, error) {
	var n int
	err := tx.QueryRow(`SELECT COUNT(*) FROM local_users l JOIN users u ON u.username=l.email
		WHERE l.role=? AND u.disabled=0 AND l.email != ?`, RoleSuperAdmin, email).Scan(&n)
	return n + s.Policy.TokenSuperAdmins, err
}

// CreateLocalUser adds an email + password user. mustChange: the password
// is temporary (set by an admin); the user must choose their own first.
func (s *Store) CreateLocalUser(ctx context.Context, by Manager, n NewLocalUser, mustChange bool) (LocalUserCreated, error) {
	return s.createLocalUser(ctx, by, n, mustChange, false)
}

// CreateBuiltinSuperAdmin (pmserver create-admin, run by the installer)
// creates the vendor's built-in super admin with a ready-to-use password.
func (s *Store) CreateBuiltinSuperAdmin(ctx context.Context, email, displayName, password string) (LocalUserCreated, error) {
	return s.createLocalUser(ctx, Manager{Actor: "system:cli", Role: RoleSuperAdmin},
		NewLocalUser{Email: email, DisplayName: displayName, Role: RoleSuperAdmin, Password: password}, false, true)
}

func (s *Store) createLocalUser(ctx context.Context, by Manager, n NewLocalUser, mustChange, builtin bool) (LocalUserCreated, error) {
	var out LocalUserCreated
	email, err := NormalizeEmail(n.Email)
	if err != nil {
		return out, err
	}
	role := CanonicalRole(n.Role)
	if role == "" {
		return out, Errf(ErrInvalid, "role must be one of %s", strings.Join(Roles, ", "))
	}
	name, err := cleanDisplayName(n.DisplayName, email)
	if err != nil {
		return out, err
	}
	if err := ValidatePassword(email, n.Password); err != nil {
		return out, err
	}
	if err := checkManage(by, "", role); err != nil {
		return out, err
	}
	if s.Policy.ReservedUsers[email] {
		return out, Errf(ErrConflict, "%s is the name of a static admin token", email)
	}
	hash, err := HashPassword(n.Password) // outside the transaction: hashing is slow
	if err != nil {
		return out, err
	}
	err = s.tx(ctx, func(tx *sql.Tx) error {
		var exists int
		if err := tx.QueryRow(`SELECT (SELECT COUNT(*) FROM users WHERE lower(username)=?) + (SELECT COUNT(*) FROM local_users WHERE email=?)`, email, email).Scan(&exists); err != nil {
			return err
		}
		if exists > 0 {
			return Errf(ErrConflict, "a user %s already exists", email)
		}
		now := s.now()
		if _, err := tx.Exec(`INSERT INTO local_users(email,display_name,role,password_hash,must_change_password,created_by,created_at,builtin) VALUES(?,?,?,?,?,?,?,?)`,
			email, name, role, hash, boolInt(mustChange), by.Actor, now, boolInt(builtin)); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO users(username,role,source,email,first_login,last_login) VALUES(?,?,'password',?,'','')`, email, role, email); err != nil {
			return err
		}
		return s.audit(tx, Ev{Actor: by.Actor, Action: "user.created", ObjectType: "user", ObjectID: email,
			Details: map[string]any{"role": role, "display_name": name, "auth": "password", "must_change_password": mustChange, "builtin": builtin}})
	})
	return LocalUserCreated{Email: email, DisplayName: name, Role: role, MustChangePassword: mustChange}, err
}

type userTarget struct {
	role     string
	local    bool
	disabled bool
}

func getUserTarget(tx *sql.Tx, username string) (userTarget, error) {
	var t userTarget
	var d int
	var lrole sql.NullString
	err := tx.QueryRow(`SELECT u.role, u.disabled, l.role FROM users u LEFT JOIN local_users l ON l.email=u.username WHERE u.username=?`, username).Scan(&t.role, &d, &lrole)
	if errors.Is(err, sql.ErrNoRows) {
		return t, Errf(ErrNotFound, "user %s", username)
	}
	t.disabled, t.local = d == 1, lrole.Valid
	if t.local {
		t.role = lrole.String
	}
	t.role = canonicalOr(t.role)
	return t, err
}

// SetUserDisabled blocks (or unblocks) a user (SSO or local) and revokes
// their sessions. Enabling a local user also clears a lockout. Nobody can
// disable themselves, and the last super admin cannot be disabled.
func (s *Store) SetUserDisabled(ctx context.Context, by Manager, username string, disabled bool, reason string) error {
	if by.is(username) && disabled {
		return Errf(ErrConflict, "you cannot disable yourself")
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		t, err := getUserTarget(tx, username)
		if err != nil {
			return err
		}
		if err := checkManage(by, t.role, ""); err != nil {
			return err
		}
		if disabled && t.local && t.role == RoleSuperAdmin {
			if n, err := s.otherSuperAdmins(tx, username); err != nil {
				return err
			} else if n == 0 {
				return Errf(ErrConflict, "%s is the last super admin; create another one first", username)
			}
		}
		if _, err := tx.Exec(`UPDATE users SET disabled=?, disabled_reason=? WHERE username=?`, boolInt(disabled), reason, username); err != nil {
			return err
		}
		if disabled {
			if _, err := tx.Exec(`UPDATE sessions SET revoked=1 WHERE username=?`, username); err != nil {
				return err
			}
		} else if _, err := tx.Exec(`UPDATE local_users SET failed_attempts=0, locked_until='' WHERE email=?`, username); err != nil {
			return err
		}
		action := "user.enabled"
		if disabled {
			action = "user.disabled"
		}
		return s.audit(tx, Ev{Actor: by.Actor, Action: action, ObjectType: "user", ObjectID: username,
			Details: map[string]any{"reason": reason, "role": t.role, "was_disabled": t.disabled}})
	})
}

// ResetLocalPassword sets a new temporary password for a local user (they
// must change it at the next sign-in), clears a lockout and ends their
// sessions. Not for yourself (use ChangeOwnPassword) or SSO users.
func (s *Store) ResetLocalPassword(ctx context.Context, by Manager, email, password, reason string) error {
	if by.is(email) {
		return Errf(ErrConflict, "use \"change password\" for your own account")
	}
	if err := ValidatePassword(email, password); err != nil {
		return err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		t, err := getUserTarget(tx, email)
		if err != nil {
			return err
		}
		if !t.local {
			return Errf(ErrConflict, "%s signs in with SSO; its password is managed by the identity provider", email)
		}
		if err := checkManage(by, t.role, ""); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE local_users SET password_hash=?, must_change_password=1, failed_attempts=0, locked_until='', password_changed_at='' WHERE email=?`,
			hash, email); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE sessions SET revoked=1 WHERE username=?`, email); err != nil {
			return err
		}
		return s.audit(tx, Ev{Actor: by.Actor, Action: "user.password_reset", ObjectType: "user", ObjectID: email,
			Details: map[string]any{"reason": reason, "must_change_password": true}})
	})
}

// SetLocalUserRole changes a local user's role and ends their sessions (the
// new role applies at the next sign-in). SSO roles come from the IdP groups.
func (s *Store) SetLocalUserRole(ctx context.Context, by Manager, email, role, reason string) error {
	if by.is(email) {
		return Errf(ErrConflict, "you cannot change your own role")
	}
	to := CanonicalRole(role)
	if to == "" {
		return Errf(ErrInvalid, "role must be one of %s", strings.Join(Roles, ", "))
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		t, err := getUserTarget(tx, email)
		if err != nil {
			return err
		}
		if !t.local {
			return Errf(ErrConflict, "%s signs in with SSO; its role comes from the identity provider groups", email)
		}
		if err := checkManage(by, t.role, to); err != nil {
			return err
		}
		if t.role == to {
			return Errf(ErrConflict, "%s already has role %s", email, to)
		}
		if t.role == RoleSuperAdmin && !t.disabled {
			if n, err := s.otherSuperAdmins(tx, email); err != nil {
				return err
			} else if n == 0 {
				return Errf(ErrConflict, "%s is the last super admin; create another one first", email)
			}
		}
		if _, err := tx.Exec(`UPDATE local_users SET role=? WHERE email=?`, to, email); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE users SET role=? WHERE username=?`, to, email); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE sessions SET revoked=1 WHERE username=?`, email); err != nil {
			return err
		}
		return s.audit(tx, Ev{Actor: by.Actor, Action: "user.role_changed", ObjectType: "user", ObjectID: email,
			Details: map[string]any{"from": t.role, "to": to, "reason": reason}})
	})
}

// PasswordLogin is the result of a successful email + password sign-in.
type PasswordLogin struct {
	Token              string
	Email              string
	Role               string
	MustChangePassword bool
}

// auditName is what a failed sign-in records as the attempted name: only
// a well-formed email (a password typed into the email field is not kept).
func auditName(email string) string {
	if e, err := NormalizeEmail(email); err == nil {
		return e
	}
	return "(invalid)"
}

// LoginPassword verifies an email + password and opens a session. Every
// failure is ErrBadCredentials (audited with the real reason), except a
// disabled account with the right password (ErrDisabled). MaxFailedLogins
// wrong passwords lock the account for LockFor.
func (s *Store) LoginPassword(ctx context.Context, email, password string, ttl time.Duration) (PasswordLogin, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	var hash, role, lockedUntil string
	var must int
	err := s.db.QueryRowContext(ctx, `SELECT password_hash, role, must_change_password, locked_until FROM local_users WHERE email=?`, email).Scan(&hash, &role, &must, &lockedUntil)
	fail := func(reason string, details map[string]any) (PasswordLogin, error) {
		name := auditName(email)
		d := map[string]any{"reason": reason, "source": "password"}
		for k, v := range details {
			d[k] = v
		}
		s.Audit(ctx, Ev{Actor: "user:" + name, Action: "auth.login_failed", ObjectType: "user", ObjectID: name, Failure: true, Details: d})
		return PasswordLogin{}, ErrBadCredentials
	}
	if errors.Is(err, sql.ErrNoRows) || len(password) > maxPasswordBytes {
		burnPasswordCheck(password)
		return fail("unknown user or invalid input", nil)
	}
	if err != nil {
		return PasswordLogin{}, err
	}
	ok := VerifyPassword(hash, password) // always: same work for locked accounts
	if lockedUntil != "" && s.Now().Before(parseTime(lockedUntil)) {
		return fail("account locked", map[string]any{"locked_until": lockedUntil})
	}
	if !ok {
		var locked bool
		var lockUntil string
		err := s.tx(ctx, func(tx *sql.Tx) error {
			var n int
			if err := tx.QueryRow(`UPDATE local_users SET failed_attempts=failed_attempts+1 WHERE email=? RETURNING failed_attempts`, email).Scan(&n); err != nil {
				return err
			}
			if n < MaxFailedLogins {
				return nil
			}
			locked, lockUntil = true, s.Now().Add(LockFor).UTC().Format(time.RFC3339Nano)
			if _, err := tx.Exec(`UPDATE local_users SET failed_attempts=0, locked_until=? WHERE email=?`, lockUntil, email); err != nil {
				return err
			}
			return s.audit(tx, Ev{Actor: "system:auth", Action: "auth.locked", ObjectType: "user", ObjectID: email, Failure: true,
				Details: map[string]any{"failed_attempts": n, "locked_until": lockUntil}})
		})
		if err != nil {
			return PasswordLogin{}, err
		}
		return fail("wrong password", map[string]any{"locked": locked})
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE local_users SET failed_attempts=0, locked_until='' WHERE email=?`, email); err != nil {
		return PasswordLogin{}, err
	}
	tok, err := s.Login(ctx, email, role, email, "password", false, ttl)
	if err != nil {
		return PasswordLogin{}, err
	}
	return PasswordLogin{Token: tok, Email: email, Role: role, MustChangePassword: must == 1}, nil
}

// ChangeOwnPassword: a signed-in local user replaces their password (also
// the forced change after a temporary one). Their other sessions end; the
// session keepToken stays. Wrong current passwords count towards lockout.
func (s *Store) ChangeOwnPassword(ctx context.Context, email, current, next, keepToken string) error {
	var hash, lockedUntil string
	err := s.db.QueryRowContext(ctx, `SELECT password_hash, locked_until FROM local_users WHERE email=?`, email).Scan(&hash, &lockedUntil)
	if errors.Is(err, sql.ErrNoRows) {
		return Errf(ErrConflict, "only local (password) users can change their password here")
	}
	if err != nil {
		return err
	}
	if len(current) > maxPasswordBytes || !VerifyPassword(hash, current) || (lockedUntil != "" && s.Now().Before(parseTime(lockedUntil))) {
		err := s.tx(ctx, func(tx *sql.Tx) error {
			var n int
			if err := tx.QueryRow(`UPDATE local_users SET failed_attempts=failed_attempts+1 WHERE email=? RETURNING failed_attempts`, email).Scan(&n); err != nil {
				return err
			}
			if n >= MaxFailedLogins {
				until := s.Now().Add(LockFor).UTC().Format(time.RFC3339Nano)
				if _, err := tx.Exec(`UPDATE local_users SET failed_attempts=0, locked_until=? WHERE email=?`, until, email); err != nil {
					return err
				}
				if _, err := tx.Exec(`UPDATE sessions SET revoked=1 WHERE username=?`, email); err != nil {
					return err
				}
				if err := s.audit(tx, Ev{Actor: "system:auth", Action: "auth.locked", ObjectType: "user", ObjectID: email, Failure: true,
					Details: map[string]any{"failed_attempts": n, "locked_until": until, "during": "password change"}}); err != nil {
					return err
				}
			}
			return s.audit(tx, Ev{Actor: "user:" + email, Action: "user.password_change_failed", ObjectType: "user", ObjectID: email, Failure: true,
				Details: map[string]any{"reason": "current password wrong (or account locked)"}})
		})
		if err != nil {
			return err
		}
		return Errf(ErrInvalid, "the current password is wrong")
	}
	if err := ValidatePassword(email, next); err != nil {
		return err
	}
	if next == current {
		return Errf(ErrInvalid, "the new password must differ from the current one")
	}
	nh, err := HashPassword(next)
	if err != nil {
		return err
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`UPDATE local_users SET password_hash=?, must_change_password=0, failed_attempts=0, locked_until='', password_changed_at=? WHERE email=?`,
			nh, s.now(), email); err != nil {
			return err
		}
		res, err := tx.Exec(`UPDATE sessions SET revoked=1 WHERE username=? AND id_hash != ? AND revoked=0`, email, HashSecret(keepToken))
		if err != nil {
			return err
		}
		ended, _ := res.RowsAffected()
		return s.audit(tx, Ev{Actor: "user:" + email, Action: "user.password_changed", ObjectType: "user", ObjectID: email,
			Details: map[string]any{"other_sessions_ended": ended}})
	})
}

// HasLocalSuperAdmin reports whether an enabled local super admin exists.
func (s *Store) HasLocalSuperAdmin(ctx context.Context) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM local_users l JOIN users u ON u.username=l.email WHERE l.role=? AND u.disabled=0`, RoleSuperAdmin).Scan(&n)
	return n > 0, err
}

// RecoverSuperAdmin (pmserver reset-admin, root on the server) gives a local
// super admin a new password that is ready to use, re-enables the account
// and clears a lockout. The recovery path when the password is lost.
func (s *Store) RecoverSuperAdmin(ctx context.Context, email, password string) error {
	email, err := NormalizeEmail(email)
	if err != nil {
		return err
	}
	if err := ValidatePassword(email, password); err != nil {
		return err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		t, err := getUserTarget(tx, email)
		if err != nil {
			return err
		}
		if !t.local || t.role != RoleSuperAdmin {
			return Errf(ErrConflict, "%s is not a local super admin (reset other users from the console)", email)
		}
		if _, err := tx.Exec(`UPDATE local_users SET password_hash=?, must_change_password=0, failed_attempts=0, locked_until='', password_changed_at='' WHERE email=?`,
			hash, email); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE users SET disabled=0, disabled_reason='' WHERE username=?`, email); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE sessions SET revoked=1 WHERE username=?`, email); err != nil {
			return err
		}
		return s.audit(tx, Ev{Actor: "system:cli", Action: "user.password_reset", ObjectType: "user", ObjectID: email,
			Details: map[string]any{"via": "pmserver reset-admin", "re_enabled": t.disabled}})
	})
}

// LocalProfile is what /api/me shows about a local user (no secrets).
type LocalProfile struct {
	DisplayName        string
	MustChangePassword bool
	PasswordChangedAt  string // "" until the user changed their password
	Builtin            bool   // the installer-created super admin
}

// GetLocalProfile returns the profile of local user email (ErrNotFound if
// email is not a local user).
func (s *Store) GetLocalProfile(ctx context.Context, email string) (LocalProfile, error) {
	var p LocalProfile
	var must, builtin int
	err := s.db.QueryRowContext(ctx, `SELECT display_name, must_change_password, password_changed_at, builtin FROM local_users WHERE email=?`, email).
		Scan(&p.DisplayName, &must, &p.PasswordChangedAt, &builtin)
	if errors.Is(err, sql.ErrNoRows) {
		return p, Errf(ErrNotFound, "local user %s", email)
	}
	p.MustChangePassword, p.Builtin = must == 1, builtin == 1
	return p, err
}
