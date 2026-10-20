package store

import (
	"context"
	"database/sql"
	"errors"
)

// The built-in super admin (the vendor) has a fixed default identity, an
// owner decision: pmserver create-admin and the installer create
// DefaultSuperAdminEmail with the vendor's default password, given in the
// vendor handbook. Only its PBKDF2 hash is in the source. While the default
// is in use the account has must_change_password (server-enforced: only
// /api/me, the password change and logout work), MFA enrolment follows,
// and pmserver warns at every start.
const (
	DefaultSuperAdminEmail = "superadmin@dataspacesecurity.com"
	// DefaultSuperAdminPasswordHash: PBKDF2-SHA256 (600 000 iterations) of
	// the default password, in the HashPassword format.
	DefaultSuperAdminPasswordHash = "pbkdf2-sha256$600000$njHsCWe+gDxBqaxbC74o5A$BcavK07iyM4T5LVXbSFYKxMWYG22gNKIQCC91F/LvPE"
)

// CreateBuiltinSuperAdminDefault creates the built-in super admin with the
// default password (DefaultSuperAdminPasswordHash). It must be changed at
// the first sign-in: the server refuses everything else until then
// (must_change_password), and the authenticator is set up next.
func (s *Store) CreateBuiltinSuperAdminDefault(ctx context.Context, email, displayName string) (LocalUserCreated, error) {
	return s.createLocalUserHash(ctx, Manager{Actor: "system:cli", Role: RoleSuperAdmin},
		NewLocalUser{Email: email, DisplayName: displayName, Role: RoleSuperAdmin}, DefaultSuperAdminPasswordHash, true, true)
}

// forceDefaultPasswordChange (every Open): a local user whose password is
// still the built-in default must change it before anything else (also
// accounts created by earlier versions, which were ready to use). Audited
// once per account (the flag stays until the password changes).
func (s *Store) forceDefaultPasswordChange(ctx context.Context) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT email FROM local_users WHERE password_hash=? AND must_change_password=0 ORDER BY email`, DefaultSuperAdminPasswordHash)
		if err != nil {
			return err
		}
		var emails []string
		for rows.Next() {
			var e string
			if err := rows.Scan(&e); err != nil {
				rows.Close()
				return err
			}
			emails = append(emails, e)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, e := range emails {
			if _, err := tx.Exec(`UPDATE local_users SET must_change_password=1 WHERE email=?`, e); err != nil {
				return err
			}
			if err := s.audit(tx, Ev{Actor: "system:startup", Action: "user.password_change_forced", ObjectType: "user", ObjectID: e,
				Details: map[string]any{"reason": "the built-in default password is still in use"}}); err != nil {
				return err
			}
		}
		return nil
	})
}

// DefaultSuperAdminPasswordInUse lists enabled local users whose password
// is still the built-in default (the stored hash is the embedded one).
func (s *Store) DefaultSuperAdminPasswordInUse(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT l.email FROM local_users l JOIN users u ON u.username=l.email WHERE l.password_hash=? AND u.disabled=0 ORDER BY l.email`,
		DefaultSuperAdminPasswordHash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
