package store

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

// withTestDefault makes testDefaultPW play the built-in default password
// (the real one is never in the source) and creates the built-in super
// admin with it, as create-admin does.
const testDefaultPW = "the stand-in default password"

func withTestDefault(t *testing.T, s *Store) {
	t.Helper()
	h, err := HashPassword(testDefaultPW)
	if err != nil {
		t.Fatal(err)
	}
	old := defaultPasswordHash
	defaultPasswordHash = h
	t.Cleanup(func() { defaultPasswordHash = old })
	s.Policy.RequireSetupCode = true
	if _, err := s.createLocalUserHash(context.Background(), Manager{Actor: "system:cli", Role: RoleSuperAdmin},
		NewLocalUser{Email: DefaultSuperAdminEmail, Role: RoleSuperAdmin}, h, true, true); err != nil {
		t.Fatal(err)
	}
}

func failedFrom(t *testing.T, s *Store, source string) int {
	t.Helper()
	var n int
	s.db.QueryRow(`SELECT failed FROM login_failures WHERE email=? AND source=?`, DefaultSuperAdminEmail, source).Scan(&n)
	return n
}

func TestSetupCodeFormat(t *testing.T) {
	re := regexp.MustCompile(`^[` + setupCodeAlphabet + `]{4}-[` + setupCodeAlphabet + `]{4}-[` + setupCodeAlphabet + `]{4}$`)
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		c := GenerateSetupCode()
		if !re.MatchString(c) || seen[c] {
			t.Fatalf("code %q (repeat %v)", c, seen[c])
		}
		seen[c] = true
	}
	if normalizeSetupCode(" abcd-efgh jkmn ") != "ABCDEFGHJKMN" {
		t.Fatal("normalize")
	}
}

// S-1: the default password alone does not sign in; a wrong code is a wrong
// password (same error, counted, audited); the right code works, also typed
// in lower case without dashes.
func TestSetupCodeRequiredForDefaultPassword(t *testing.T) {
	s := openTest(t)
	withTestDefault(t, s)
	ctx := context.Background()

	if _, err := s.LoginSetupCodeFrom(ctx, DefaultSuperAdminEmail, testDefaultPW, "", "198.51.100.1", time.Hour); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("no code: %v", err)
	}
	if n := failedFrom(t, s, "198.51.100.1"); n != 1 {
		t.Fatalf("missing code not counted as a failure: %d", n)
	}
	var reason string
	s.db.QueryRow(`SELECT json_extract(details,'$.reason') FROM audit WHERE action='auth.login_failed' AND object_id=? ORDER BY seq DESC LIMIT 1`, DefaultSuperAdminEmail).Scan(&reason)
	if reason != "default password without a valid setup code" {
		t.Fatalf("audit reason %q", reason)
	}
	// No code made yet: even a well-formed guess fails.
	if _, err := s.LoginSetupCodeFrom(ctx, DefaultSuperAdminEmail, testDefaultPW, GenerateSetupCode(), "198.51.100.2", time.Hour); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("code before any was issued: %v", err)
	}

	code, exp, err := s.CreateSetupCode(ctx, DefaultSuperAdminEmail)
	if err != nil || exp.Sub(s.Now()) < SetupCodeValidFor-time.Minute {
		t.Fatalf("create: %v %v", exp, err)
	}
	var stored string
	s.db.QueryRow(`SELECT code_hash FROM setup_codes WHERE email=?`, DefaultSuperAdminEmail).Scan(&stored)
	if stored == "" || stored == code || stored != HashSecret(normalizeSetupCode(code)) {
		t.Fatal("the setup code must be stored hashed")
	}
	if _, err := s.LoginSetupCodeFrom(ctx, DefaultSuperAdminEmail, testDefaultPW, "AAAA-BBBB-CCCC", "198.51.100.3", time.Hour); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("wrong code: %v", err)
	}
	if n := failedFrom(t, s, "198.51.100.3"); n != 1 {
		t.Fatalf("wrong code not counted: %d", n)
	}
	// The right code with a wrong password: still a wrong password.
	if _, err := s.LoginSetupCodeFrom(ctx, DefaultSuperAdminEmail, "not the default password", code, "198.51.100.4", time.Hour); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("right code, wrong password: %v", err)
	}
	typed := normalizeSetupCode(code)
	l, err := s.LoginSetupCodeFrom(ctx, DefaultSuperAdminEmail, testDefaultPW, " "+strings.ToLower(typed)+" ", "198.51.100.5", time.Hour)
	if err != nil || l.Token == "" || !l.MustChangePassword || l.Role != RoleSuperAdmin {
		t.Fatalf("right code: %+v %v", l, err)
	}
	// A new code replaces the old one.
	code2, _, err := s.CreateSetupCode(ctx, DefaultSuperAdminEmail)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoginSetupCodeFrom(ctx, DefaultSuperAdminEmail, testDefaultPW, code, "198.51.100.6", time.Hour); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("replaced code still works: %v", err)
	}
	if _, err := s.LoginSetupCodeFrom(ctx, DefaultSuperAdminEmail, testDefaultPW, code2, "198.51.100.6", time.Hour); err != nil {
		t.Fatalf("new code: %v", err)
	}
	var created int
	s.db.QueryRow(`SELECT COUNT(*) FROM audit WHERE action='user.setup_code_created' AND object_id=?`, DefaultSuperAdminEmail).Scan(&created)
	if created != 2 {
		t.Fatalf("setup_code_created events: %d", created)
	}
}

// Missing setup codes lock the account like wrong passwords do.
func TestSetupCodeFailuresLock(t *testing.T) {
	s := openTest(t)
	withTestDefault(t, s)
	ctx := context.Background()
	code, _, err := s.CreateSetupCode(ctx, DefaultSuperAdminEmail)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxFailedLogins; i++ {
		s.LoginSetupCodeFrom(ctx, DefaultSuperAdminEmail, testDefaultPW, "", "203.0.113.9", time.Hour)
	}
	if _, err := s.LoginSetupCodeFrom(ctx, DefaultSuperAdminEmail, testDefaultPW, code, "203.0.113.9", time.Hour); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("locked source still signs in: %v", err)
	}
	if _, err := s.LoginSetupCodeFrom(ctx, DefaultSuperAdminEmail, testDefaultPW, code, "203.0.113.10", time.Hour); err != nil {
		t.Fatalf("other source: %v", err)
	}
}

func TestSetupCodeExpires(t *testing.T) {
	s := openTest(t)
	withTestDefault(t, s)
	ctx := context.Background()
	code, _, err := s.CreateSetupCode(ctx, DefaultSuperAdminEmail)
	if err != nil {
		t.Fatal(err)
	}
	start := s.Now()
	s.Now = func() time.Time { return start.Add(SetupCodeValidFor - time.Minute) }
	if _, err := s.LoginSetupCodeFrom(ctx, DefaultSuperAdminEmail, testDefaultPW, code, "", time.Hour); err != nil {
		t.Fatalf("before expiry: %v", err)
	}
	s.Now = func() time.Time { return start.Add(SetupCodeValidFor + time.Minute) }
	if _, err := s.LoginSetupCodeFrom(ctx, DefaultSuperAdminEmail, testDefaultPW, code, "", time.Hour); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("expired code: %v", err)
	}
}

// Changing the password deletes the code; the account then signs in with
// its own password alone and gets no new code.
func TestSetupCodeDeletedAfterPasswordChange(t *testing.T) {
	s := openTest(t)
	withTestDefault(t, s)
	ctx := context.Background()
	code, _, err := s.CreateSetupCode(ctx, DefaultSuperAdminEmail)
	if err != nil {
		t.Fatal(err)
	}
	l, err := s.LoginSetupCodeFrom(ctx, DefaultSuperAdminEmail, testDefaultPW, code, "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ChangeOwnPassword(ctx, DefaultSuperAdminEmail, testDefaultPW, "the vendor's own passphrase", l.Token); err != nil {
		t.Fatal(err)
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM setup_codes`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d setup codes left after the password change", n)
	}
	if _, err := s.LoginPassword(ctx, DefaultSuperAdminEmail, "the vendor's own passphrase", time.Hour); err != nil {
		t.Fatalf("own password without a code: %v", err)
	}
	if _, _, err := s.CreateSetupCode(ctx, DefaultSuperAdminEmail); !errors.Is(err, ErrConflict) {
		t.Fatalf("setup code for an account with its own password: %v", err)
	}
	if _, _, err := s.CreateSetupCode(ctx, "nobody@bank.example"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("setup code for an unknown account: %v", err)
	}
}

// reset-admin (a new password) also ends the code.
func TestSetupCodeDeletedByRecovery(t *testing.T) {
	s := openTest(t)
	withTestDefault(t, s)
	ctx := context.Background()
	if _, _, err := s.CreateSetupCode(ctx, DefaultSuperAdminEmail); err != nil {
		t.Fatal(err)
	}
	if err := s.RecoverSuperAdmin(ctx, DefaultSuperAdminEmail, "a recovered secret"); err != nil {
		t.Fatal(err)
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM setup_codes`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d setup codes left after reset-admin", n)
	}
}

// Users with their own password never need a code; one sent is ignored.
func TestSetupCodeOtherUsersUnaffected(t *testing.T) {
	s := openTest(t)
	withTestDefault(t, s)
	ctx := context.Background()
	mkUser(t, s, bySuper, "uma@bank.example", RoleUser)
	if _, err := s.LoginPassword(ctx, "uma@bank.example", pw, time.Hour); err != nil {
		t.Fatalf("no code: %v", err)
	}
	if _, err := s.LoginSetupCodeFrom(ctx, "uma@bank.example", pw, "AAAA-BBBB-CCCC", "", time.Hour); err != nil {
		t.Fatalf("stray code: %v", err)
	}
	if _, _, err := s.CreateSetupCode(ctx, "uma@bank.example"); !errors.Is(err, ErrConflict) {
		t.Fatalf("setup code for a normal user: %v", err)
	}
}

// Off by default (require_setup_code): the default password alone signs in
// (then the forced password change and MFA set-up follow).
func TestSetupCodeOffByDefault(t *testing.T) {
	s := openTest(t)
	withTestDefault(t, s)
	s.Policy.RequireSetupCode = false
	l, err := s.LoginSetupCodeFrom(context.Background(), DefaultSuperAdminEmail, testDefaultPW, "", "", time.Hour)
	if err != nil || !l.MustChangePassword {
		t.Fatalf("default password without a code (codes off): %+v %v", l, err)
	}
}
