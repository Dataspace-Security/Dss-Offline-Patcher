package store

import (
	"context"
	"database/sql"
)

// DeleteLocalUser removes a local (email + password) user: the account,
// its sessions and its MFA enrolment. Audit history is kept (events name
// the user). Admins delete bank roles, only a super admin deletes a super
// admin; nobody deletes themselves, and the last super admin stays. SSO
// users are disabled instead (the IdP owns them; they would come back at
// the next sign-in). Recovery when nobody can sign in: pmserver
// create-admin / reset-admin on the server.
func (s *Store) DeleteLocalUser(ctx context.Context, by Manager, email, reason string) error {
	email, err := NormalizeEmail(email)
	if err != nil {
		return err
	}
	if by.is(email) {
		return Errf(ErrConflict, "you cannot delete yourself")
	}
	return s.txChanged(ctx, func(tx *sql.Tx) error {
		t, err := getUserTarget(tx, email)
		if err != nil {
			return err
		}
		if err := checkManage(by, t.role, ""); err != nil {
			return err
		}
		if !t.local {
			return Errf(ErrConflict, "%s signs in with SSO; disable the user instead (the identity provider owns SSO accounts)", email)
		}
		if t.role == RoleSuperAdmin {
			if n, err := s.otherSuperAdmins(tx, email); err != nil {
				return err
			} else if n == 0 {
				return Errf(ErrConflict, "%s is the last super admin; create another one first", email)
			}
		}
		var builtin int
		tx.QueryRow(`SELECT builtin FROM local_users WHERE email=?`, email).Scan(&builtin)
		for _, q := range []string{`DELETE FROM sessions WHERE username=?`, `DELETE FROM mfa WHERE email=?`, `DELETE FROM setup_codes WHERE email=?`, `DELETE FROM local_users WHERE email=?`, `DELETE FROM users WHERE username=?`} {
			if _, err := tx.Exec(q, email); err != nil {
				return err
			}
		}
		return s.audit(tx, Ev{Actor: by.Actor, Action: "user.deleted", ObjectType: "user", ObjectID: email,
			Details: map[string]any{"reason": reason, "role": t.role, "was_disabled": t.disabled, "builtin": builtin == 1}})
	})
}
