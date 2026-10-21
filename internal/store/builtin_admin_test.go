package store

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
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
// embedded hash, is builtin and must change the password before anything
// else (server-enforced), and stops counting as "default in use" once the
// password is changed.
func TestBuiltinSuperAdminDefaultPassword(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	u, err := s.CreateBuiltinSuperAdminDefault(ctx, DefaultSuperAdminEmail, "Vendor support")
	if err != nil || u.Email != DefaultSuperAdminEmail || u.Role != RoleSuperAdmin || !u.MustChangePassword {
		t.Fatalf("create: %+v %v", u, err)
	}
	var stored string
	s.db.QueryRow(`SELECT password_hash FROM local_users WHERE email=?`, DefaultSuperAdminEmail).Scan(&stored)
	if stored != DefaultSuperAdminPasswordHash {
		t.Fatal("create-admin did not store the embedded default hash")
	}
	lp, err := s.GetLocalProfile(ctx, DefaultSuperAdminEmail)
	if err != nil || !lp.Builtin || lp.PasswordChangedAt != "" || !lp.MustChangePassword {
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
	s.Policy.RequireSetupCode = true
	if _, err := s.LoginPassword(ctx, DefaultSuperAdminEmail, plain, time.Hour); err == nil {
		t.Fatal("the default password signed in without the setup code")
	}
	code, _, err := s.CreateSetupCode(ctx, DefaultSuperAdminEmail)
	if err != nil {
		t.Fatal(err)
	}
	l, err := s.LoginSetupCodeFrom(ctx, DefaultSuperAdminEmail, plain, code, "", time.Hour)
	if err != nil || l.Role != RoleSuperAdmin || !l.MustChangePassword {
		t.Fatalf("sign in with the default password: %+v %v", l, err)
	}
	if err := s.ChangeOwnPassword(ctx, DefaultSuperAdminEmail, plain, "the vendor's own passphrase", l.Token); err != nil {
		t.Fatal(err)
	}
	if who, _ := s.DefaultSuperAdminPasswordInUse(ctx); len(who) != 0 {
		t.Fatalf("default still in use after the change: %v", who)
	}
}

// An install from an earlier version (built-in super admin ready to use
// with the default password): the next Open forces the password change,
// audited once; an account with its own password is left alone.
func TestDefaultPasswordForcedChangeOnOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pm.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := s.createLocalUserHash(ctx, Manager{Actor: "system:cli", Role: RoleSuperAdmin},
		NewLocalUser{Email: DefaultSuperAdminEmail, Role: RoleSuperAdmin}, DefaultSuperAdminPasswordHash, false, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateLocalUser(ctx, bySuper, NewLocalUser{Email: "own@dataspacesecurity.test", Role: RoleSuperAdmin, Password: pw}, false); err != nil {
		t.Fatal(err)
	}
	s.Close()
	for i := 0; i < 2; i++ { // the second Open changes nothing
		s, err = Open(path)
		if err != nil {
			t.Fatal(err)
		}
		lp, _ := s.GetLocalProfile(ctx, DefaultSuperAdminEmail)
		own, _ := s.GetLocalProfile(ctx, "own@dataspacesecurity.test")
		if !lp.MustChangePassword || own.MustChangePassword {
			t.Fatalf("open %d: default %+v own %+v", i, lp, own)
		}
		var n int
		s.db.QueryRow(`SELECT COUNT(*) FROM audit WHERE action='user.password_change_forced' AND object_id=?`, DefaultSuperAdminEmail).Scan(&n)
		if n != 1 {
			t.Fatalf("open %d: %d password_change_forced events", i, n)
		}
		s.Close()
	}
}
