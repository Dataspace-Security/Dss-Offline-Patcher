package store

import (
	"context"
	"database/sql"
	"errors"
)

// The built-in super admin (the vendor) has a fixed default identity, an
// owner decision: pmserver create-admin and the installer create
// DefaultSuperAdminEmail with the vendor's default password, given in the
// vendor handbook. Only its PBKDF2 hash is in the source. The console asks
// for a new password while the default is in use (/api/me builtin and an
// empty password_changed_at) and pmserver warns at every start.
const (
	DefaultSuperAdminEmail = "superadmin@dataspacesecurity.com"
	// DefaultSuperAdminPasswordHash: PBKDF2-SHA256 (600 000 iterations) of
	// the default password, in the HashPassword format.
	DefaultSuperAdminPasswordHash = "pbkdf2-sha256$600000$njHsCWe+gDxBqaxbC74o5A$BcavK07iyM4T5LVXbSFYKxMWYG22gNKIQCC91F/LvPE"
)

// CreateBuiltinSuperAdminDefault creates the built-in super admin with the
// default password (DefaultSuperAdminPasswordHash), ready to use; the
// console prompts for a new one.
func (s *Store) CreateBuiltinSuperAdminDefault(ctx context.Context, email, displayName string) (LocalUserCreated, error) {
	return s.createLocalUserHash(ctx, Manager{Actor: "system:cli", Role: RoleSuperAdmin},
		NewLocalUser{Email: email, DisplayName: displayName, Role: RoleSuperAdmin}, DefaultSuperAdminPasswordHash, false, true)
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
