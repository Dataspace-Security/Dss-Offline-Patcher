package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func init() { PasswordIterations = 1000 } // fast tests; production uses DefaultPasswordIterations

const pw = "correct horse battery"

var (
	bySuper = Manager{Actor: "user:vendor@dataspacesecurity.test", Role: RoleSuperAdmin}
	byAdmin = Manager{Actor: "user:adam@bank.example", Role: RoleAdmin}
	byUser  = Manager{Actor: "user:uma@bank.example", Role: RoleUser}
)

func mkUser(t *testing.T, s *Store, by Manager, email, role string) {
	t.Helper()
	if _, err := s.CreateLocalUser(context.Background(), by, NewLocalUser{Email: email, Role: role, Password: pw}, true); err != nil {
		t.Fatalf("create %s: %v", email, err)
	}
}

func TestPasswordHashing(t *testing.T) {
	if DefaultPasswordIterations != 600_000 {
		t.Fatalf("production work factor %d", DefaultPasswordIterations)
	}
	h, err := HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(h, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" || parts[1] != "1000" {
		t.Fatalf("format: %s", h)
	}
	h2, _ := HashPassword(pw)
	if h == h2 {
		t.Fatal("same salt twice")
	}
	if !VerifyPassword(h, pw) || VerifyPassword(h, pw+"x") || VerifyPassword("garbage", pw) || VerifyPassword("pbkdf2-sha256$0$AA$AA", pw) {
		t.Fatal("verify")
	}
	if g := GeneratePassword(); len(g) != 20 || ValidatePassword("a@b.example", g) != nil {
		t.Fatalf("generated %q", g)
	}
	for _, bad := range []string{"short", "uma@bank.example", "UMA@BANK.EXAMPLE", strings.Repeat("x", 300)} {
		if ValidatePassword("uma@bank.example", bad) == nil {
			t.Errorf("password %q accepted", bad)
		}
	}
	if ValidatePassword("umabanking@bank.example", "umabanking") == nil {
		t.Error("local part accepted as password")
	}
}

func TestNormalizeEmail(t *testing.T) {
	if e, err := NormalizeEmail("  Uma.Rao@Bank.Example "); err != nil || e != "uma.rao@bank.example" {
		t.Fatalf("%q %v", e, err)
	}
	for _, bad := range []string{"", "uma", "uma@", "@bank.example", "uma@bank", "a b@bank.example", "uma/x@bank.example", "uma@@bank.example", ".uma@bank.example", "u..ma@bank.example", "<uma@bank.example>"} {
		if _, err := NormalizeEmail(bad); err == nil {
			t.Errorf("email %q accepted", bad)
		}
	}
}

func TestCreateLocalUserRules(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	for _, c := range []struct {
		what string
		by   Manager
		n    NewLocalUser
		want error
	}{
		{"user role cannot manage users", byUser, NewLocalUser{Email: "a@bank.example", Role: RoleViewer, Password: pw}, ErrForbidden},
		{"admin cannot create a super admin", byAdmin, NewLocalUser{Email: "a@bank.example", Role: RoleSuperAdmin, Password: pw}, ErrForbidden},
		{"bad email", byAdmin, NewLocalUser{Email: "nope", Role: RoleUser, Password: pw}, ErrInvalid},
		{"bad role", byAdmin, NewLocalUser{Email: "a@bank.example", Role: "root", Password: pw}, ErrInvalid},
		{"short password", byAdmin, NewLocalUser{Email: "a@bank.example", Role: RoleUser, Password: "short"}, ErrInvalid},
		{"removed role name", byAdmin, NewLocalUser{Email: "a@bank.example", Role: "operator", Password: pw}, ErrInvalid},
	} {
		if _, err := s.CreateLocalUser(ctx, c.by, c.n, true); !errors.Is(err, c.want) {
			t.Errorf("%s: want %v, got %v", c.what, c.want, err)
		}
	}
	u, err := s.CreateLocalUser(ctx, byAdmin, NewLocalUser{Email: "Uma@Bank.Example", DisplayName: "Uma Rao", Role: "user", Password: pw}, true)
	if err != nil || u.Email != "uma@bank.example" || u.Role != RoleUser || !u.MustChangePassword {
		t.Fatalf("create: %v %+v", err, u)
	}
	if _, err := s.CreateLocalUser(ctx, byAdmin, NewLocalUser{Email: "uma@bank.example", Role: RoleUser, Password: pw}, true); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate: %v", err)
	}
	// An SSO user's name cannot be taken by a local user, and vice versa.
	if _, err := s.Login(ctx, "sso@bank.example", "user", "", "oidc", true, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateLocalUser(ctx, byAdmin, NewLocalUser{Email: "sso@bank.example", Role: RoleUser, Password: pw}, true); !errors.Is(err, ErrConflict) {
		t.Fatalf("local user with an SSO name: %v", err)
	}
	if _, err := s.Login(ctx, "uma@bank.example", "admin", "", "oidc", true, time.Hour); !errors.Is(err, ErrConflict) {
		t.Fatalf("SSO sign-in as a local user: want conflict, got %v", err)
	}
	if _, err := s.Login(ctx, "Uma@Bank.Example", "admin", "", "oidc", true, time.Hour); !errors.Is(err, ErrConflict) {
		t.Fatalf("SSO sign-in as a local user (other case): want conflict, got %v", err)
	}
	if _, err := s.CreateLocalUser(ctx, byAdmin, NewLocalUser{Email: "SSO@bank.example", Role: RoleUser, Password: pw}, true); !errors.Is(err, ErrConflict) {
		t.Fatalf("local user with an SSO name (other case): %v", err)
	}
	if _, err := s.CreateLocalUser(ctx, bySuper, NewLocalUser{Email: "vendor2@dataspacesecurity.test", Role: RoleSuperAdmin, Password: pw}, false); err != nil {
		t.Fatalf("super admin creates super admin: %v", err)
	}
	// Audit names the role, never the password or its hash.
	var det string
	s.db.QueryRow(`SELECT group_concat(details) FROM audit WHERE action='user.created'`).Scan(&det)
	if strings.Contains(det, pw) || strings.Contains(det, "pbkdf2") || !strings.Contains(det, `"role":"user"`) {
		t.Fatalf("audit: %s", det)
	}
}

func TestPasswordLoginAndLockout(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	mkUser(t, s, byAdmin, "uma@bank.example", RoleUser)
	now := time.Now().UTC()
	s.Now = func() time.Time { return now }

	l, err := s.LoginPassword(ctx, " UMA@bank.example", pw, time.Hour)
	if err != nil || l.Role != RoleUser || !l.MustChangePassword || l.Token == "" {
		t.Fatalf("login: %v %+v", err, l)
	}
	ss, err := s.LookupSession(ctx, l.Token)
	if err != nil || ss.Username != "uma@bank.example" || ss.Source != "password" || !ss.MustChangePassword || ss.MFA {
		t.Fatalf("session: %v %+v", err, ss)
	}
	// Unknown email and wrong password: the same error.
	if _, err := s.LoginPassword(ctx, "nobody@bank.example", pw, time.Hour); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("unknown: %v", err)
	}
	for i := 0; i < MaxFailedLogins; i++ {
		if _, err := s.LoginPassword(ctx, "uma@bank.example", "wrong password!", time.Hour); !errors.Is(err, ErrBadCredentials) {
			t.Fatalf("wrong %d: %v", i, err)
		}
	}
	// Locked: even the right password fails, with the same error.
	if _, err := s.LoginPassword(ctx, "uma@bank.example", pw, time.Hour); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("locked account signed in: %v", err)
	}
	us, _ := s.ListUsers(ctx)
	if len(us) != 1 || !us[0].Locked {
		t.Fatalf("list shows lock: %+v", us)
	}
	if hasAudit(auditActions(t, s, "uma@bank.example"), "auth.locked") == "" {
		t.Fatal("no auth.locked audit")
	}
	now = now.Add(LockFor + time.Second)
	if _, err := s.LoginPassword(ctx, "uma@bank.example", pw, time.Hour); err != nil {
		t.Fatalf("after lock expiry: %v", err)
	}
	// Admin enable clears a lock.
	for i := 0; i < MaxFailedLogins; i++ {
		s.LoginPassword(ctx, "uma@bank.example", "wrong password!", time.Hour)
	}
	if err := s.SetUserDisabled(ctx, byAdmin, "uma@bank.example", false, "unlock"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoginPassword(ctx, "uma@bank.example", pw, time.Hour); err != nil {
		t.Fatalf("after unlock: %v", err)
	}
	// Disabled: refused (the password was right, so the reason may be told).
	if err := s.SetUserDisabled(ctx, byAdmin, "uma@bank.example", true, "left"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LookupSession(ctx, l.Token); err == nil {
		t.Fatal("session survives disable")
	}
	if _, err := s.LoginPassword(ctx, "uma@bank.example", pw, time.Hour); !errors.Is(err, ErrDisabled) {
		t.Fatalf("disabled: %v", err)
	}
	// Failed attempts are audited without the password.
	var det string
	s.db.QueryRow(`SELECT group_concat(details) FROM audit WHERE action='auth.login_failed'`).Scan(&det)
	if strings.Contains(det, "wrong password!") || strings.Contains(det, pw) {
		t.Fatalf("password in audit: %s", det)
	}
}

func TestChangeOwnPassword(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	mkUser(t, s, byAdmin, "uma@bank.example", RoleUser)
	a, _ := s.LoginPassword(ctx, "uma@bank.example", pw, time.Hour)
	b, _ := s.LoginPassword(ctx, "uma@bank.example", pw, time.Hour)
	if err := s.ChangeOwnPassword(ctx, "uma@bank.example", "not it at all", "a brand new secret", a.Token); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong current: %v", err)
	}
	if err := s.ChangeOwnPassword(ctx, "uma@bank.example", pw, "short", a.Token); !errors.Is(err, ErrInvalid) {
		t.Fatalf("short new: %v", err)
	}
	if err := s.ChangeOwnPassword(ctx, "uma@bank.example", pw, pw, a.Token); !errors.Is(err, ErrInvalid) {
		t.Fatalf("same new: %v", err)
	}
	if err := s.ChangeOwnPassword(ctx, "uma@bank.example", pw, "a brand new secret", a.Token); err != nil {
		t.Fatal(err)
	}
	ss, err := s.LookupSession(ctx, a.Token)
	if err != nil || ss.MustChangePassword {
		t.Fatalf("current session: %v %+v", err, ss)
	}
	if _, err := s.LookupSession(ctx, b.Token); err == nil {
		t.Fatal("other session survives a password change")
	}
	if _, err := s.LoginPassword(ctx, "uma@bank.example", pw, time.Hour); err == nil {
		t.Fatal("old password still works")
	}
	if l, err := s.LoginPassword(ctx, "uma@bank.example", "a brand new secret", time.Hour); err != nil || l.MustChangePassword {
		t.Fatalf("new password: %v %+v", err, l)
	}
	p, _ := s.GetLocalProfile(ctx, "uma@bank.example")
	if p.PasswordChangedAt == "" {
		t.Fatal("password_changed_at not set")
	}
	if err := s.ChangeOwnPassword(ctx, "sso@bank.example", "x", "y", ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("non-local: %v", err)
	}
}

func TestUserManagementLimits(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if _, err := s.CreateBuiltinSuperAdmin(ctx, "vendor@dataspacesecurity.test", "", pw); err != nil {
		t.Fatal(err)
	}
	mkUser(t, s, bySuper, "adam@bank.example", RoleAdmin)
	mkUser(t, s, byAdmin, "uma@bank.example", RoleUser)
	p, _ := s.GetLocalProfile(ctx, "vendor@dataspacesecurity.test")
	if !p.Builtin || p.MustChangePassword {
		t.Fatalf("builtin super admin: %+v", p)
	}
	ok := func(what string, err error) {
		t.Helper()
		if err != nil {
			t.Errorf("%s: %v", what, err)
		}
	}
	is := func(what string, err, want error) {
		t.Helper()
		if !errors.Is(err, want) {
			t.Errorf("%s: want %v, got %v", what, want, err)
		}
	}
	// Admin: bank roles only.
	is("admin disables super admin", s.SetUserDisabled(ctx, byAdmin, "vendor@dataspacesecurity.test", true, "x"), ErrForbidden)
	is("admin resets super admin", s.ResetLocalPassword(ctx, byAdmin, "vendor@dataspacesecurity.test", "temporary password 1", "x"), ErrForbidden)
	is("admin demotes super admin", s.SetLocalUserRole(ctx, byAdmin, "vendor@dataspacesecurity.test", RoleAdmin, "x"), ErrForbidden)
	is("admin grants super admin", s.SetLocalUserRole(ctx, byAdmin, "uma@bank.example", RoleSuperAdmin, "x"), ErrForbidden)
	is("user manages users", s.SetUserDisabled(ctx, byUser, "adam@bank.example", true, "x"), ErrForbidden)
	is("unknown user", s.SetUserDisabled(ctx, byAdmin, "ghost@bank.example", true, "x"), ErrNotFound)
	ok("admin promotes user to admin", s.SetLocalUserRole(ctx, byAdmin, "uma@bank.example", RoleAdmin, "team lead"))
	// An admin does not set another admin's credentials or role (they could
	// sign in as them); only the super admin does.
	is("admin changes an admin's role", s.SetLocalUserRole(ctx, byAdmin, "uma@bank.example", RoleViewer, "x"), ErrForbidden)
	is("admin resets an admin's password", s.ResetLocalPassword(ctx, byAdmin, "uma@bank.example", "temporary password 1", "x"), ErrForbidden)
	is("admin resets an admin's MFA", s.ResetMFA(ctx, byAdmin, "uma@bank.example", "x"), ErrForbidden)
	is("same role", s.SetLocalUserRole(ctx, bySuper, "uma@bank.example", RoleAdmin, "x"), ErrConflict)
	ok("super admin demotes admin to viewer", s.SetLocalUserRole(ctx, bySuper, "uma@bank.example", RoleViewer, "audit only"))
	is("bad role", s.SetLocalUserRole(ctx, byAdmin, "uma@bank.example", "god", "x"), ErrInvalid)
	// Nobody changes themselves.
	is("disable self", s.SetUserDisabled(ctx, byAdmin, "adam@bank.example", true, "x"), ErrConflict)
	is("demote self", s.SetLocalUserRole(ctx, byAdmin, "adam@bank.example", RoleUser, "x"), ErrConflict)
	is("reset self", s.ResetLocalPassword(ctx, byAdmin, "adam@bank.example", "temporary password 1", "x"), ErrConflict)
	// The last super admin stays.
	vendor := Manager{Actor: "user:vendor2@dataspacesecurity.test", Role: RoleSuperAdmin}
	is("disable last super admin", s.SetUserDisabled(ctx, vendor, "vendor@dataspacesecurity.test", true, "x"), ErrConflict)
	is("demote last super admin", s.SetLocalUserRole(ctx, vendor, "vendor@dataspacesecurity.test", RoleAdmin, "x"), ErrConflict)
	mkUser(t, s, bySuper, "vendor2@dataspacesecurity.test", RoleSuperAdmin)
	ok("demote one of two super admins", s.SetLocalUserRole(ctx, bySuper, "vendor2@dataspacesecurity.test", RoleAdmin, "x"))
	// SSO users: disable yes, password/role no.
	s.Login(ctx, "sso@bank.example", "user", "", "oidc", true, time.Hour)
	ok("disable SSO user", s.SetUserDisabled(ctx, byAdmin, "sso@bank.example", true, "left"))
	is("reset SSO password", s.ResetLocalPassword(ctx, byAdmin, "sso@bank.example", "temporary password 1", "x"), ErrConflict)
	is("set SSO role", s.SetLocalUserRole(ctx, byAdmin, "sso@bank.example", RoleAdmin, "x"), ErrConflict)

	// Reset: temporary password, must change, sessions end.
	l, _ := s.LoginPassword(ctx, "uma@bank.example", pw, time.Hour)
	ok("reset", s.ResetLocalPassword(ctx, byAdmin, "uma@bank.example", "temporary password 1", "forgot"))
	if _, err := s.LookupSession(ctx, l.Token); err == nil {
		t.Error("session survives a reset")
	}
	if l, err := s.LoginPassword(ctx, "uma@bank.example", "temporary password 1", time.Hour); err != nil || !l.MustChangePassword || l.Role != RoleViewer {
		t.Errorf("after reset: %v %+v", err, l)
	}

	us, err := s.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(us)
	if strings.Contains(string(b), "pbkdf2") || strings.Contains(string(b), "password_hash") {
		t.Fatalf("hash in user list: %s", b)
	}
	byName := map[string]User{}
	for _, u := range us {
		byName[u.Username] = u
	}
	if u := byName["uma@bank.example"]; u.Source != "local" || u.Auth != "password" || u.Email != "uma@bank.example" || u.Role != RoleViewer || u.DisplayName != "uma" {
		t.Errorf("local user row: %+v", u)
	}
	if u := byName["sso@bank.example"]; u.Source != "oidc" || u.Auth != "sso" || !u.Disabled {
		t.Errorf("SSO user row: %+v", u)
	}
	if u := byName["adam@bank.example"]; u.LastLogin != "" || u.FirstLogin != "" {
		t.Errorf("never signed in: %+v", u)
	}

	// pmserver reset-admin: only for local super admins; re-enables.
	is("recover a non super admin", s.RecoverSuperAdmin(ctx, "uma@bank.example", "a recovered secret"), ErrConflict)
	ok("recover", s.RecoverSuperAdmin(ctx, "vendor@dataspacesecurity.test", "a recovered secret"))
	if l, err := s.LoginPassword(ctx, "vendor@dataspacesecurity.test", "a recovered secret", time.Hour); err != nil || l.MustChangePassword {
		t.Errorf("recovered login: %v %+v", err, l)
	}
	if has, _ := s.HasLocalSuperAdmin(ctx); !has {
		t.Error("HasLocalSuperAdmin")
	}
}
