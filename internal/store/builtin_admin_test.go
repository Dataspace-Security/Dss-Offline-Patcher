package store

import (
	"context"
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"
)

// The embedded default password is a production-strength PBKDF2 hash in
// the HashPassword format (never the plaintext).
func TestDefaultSuperAdminHashFormat(t *testing.T) {
	parts := strings.Split(DefaultSuperAdminPasswordHash, "$")
	if len(parts) != 4 || parts[0] != passwordScheme || parts[1] != "600000" {
		t.Fatalf("format: scheme %q iterations %q", parts[0], parts[1])
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[2])
	key, err2 := base64.RawStdEncoding.DecodeString(parts[3])
	if err1 != nil || err2 != nil || len(salt) != passwordSaltLen || len(key) != passwordKeyLen {
		t.Fatalf("salt %d bytes (%v), key %d bytes (%v)", len(salt), err1, len(key), err2)
	}
	if DefaultSuperAdminEmail != "superadmin@dataspacesecurity.com" {
		t.Fatalf("default email %s", DefaultSuperAdminEmail)
	}
}

// create-admin's store path: the built-in super admin gets exactly the
// embedded hash, is builtin with no password change yet (the console's
// change-password prompt), and stops counting as "default in use" once
// the password is changed.
func TestBuiltinSuperAdminDefaultPassword(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	u, err := s.CreateBuiltinSuperAdminDefault(ctx, DefaultSuperAdminEmail, "Vendor support")
	if err != nil || u.Email != DefaultSuperAdminEmail || u.Role != RoleSuperAdmin || u.MustChangePassword {
		t.Fatalf("create: %+v %v", u, err)
	}
	var stored string
	s.db.QueryRow(`SELECT password_hash FROM local_users WHERE email=?`, DefaultSuperAdminEmail).Scan(&stored)
	if stored != DefaultSuperAdminPasswordHash {
		t.Fatal("create-admin did not store the embedded default hash")
	}
	lp, err := s.GetLocalProfile(ctx, DefaultSuperAdminEmail)
	if err != nil || !lp.Builtin || lp.PasswordChangedAt != "" || lp.MustChangePassword {
		t.Fatalf("profile: %+v %v", lp, err)
	}
	who, err := s.DefaultSuperAdminPasswordInUse(ctx)
	if err != nil || len(who) != 1 || who[0] != DefaultSuperAdminEmail {
		t.Fatalf("default in use: %v %v", who, err)
	}
	if _, err := s.CreateBuiltinSuperAdminDefault(ctx, DefaultSuperAdminEmail, ""); err == nil {
		t.Fatal("second built-in super admin with the same email")
	}
	plain := os.Getenv("OFFPATCH_TEST_DEFAULT_SA_PW")
	if plain == "" {
		t.Log("OFFPATCH_TEST_DEFAULT_SA_PW not set: skipping the sign-in with the default password")
		return
	}
	l, err := s.LoginPassword(ctx, DefaultSuperAdminEmail, plain, time.Hour)
	if err != nil || l.Role != RoleSuperAdmin {
		t.Fatalf("sign in with the default password: %+v %v", l, err)
	}
	if err := s.ChangeOwnPassword(ctx, DefaultSuperAdminEmail, plain, "the vendor's own passphrase", l.Token); err != nil {
		t.Fatal(err)
	}
	if who, _ := s.DefaultSuperAdminPasswordInUse(ctx); len(who) != 0 {
		t.Fatalf("default still in use after the change: %v", who)
	}
}
