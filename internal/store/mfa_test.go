package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"offpatch/internal/totp"
)

func mfaStore(t *testing.T) (*Store, *time.Time) {
	t.Helper()
	s := openTest(t)
	if err := s.SetMFAKey([]byte(strings.Repeat("k", 32))); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 18, 9, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return now }
	return s, &now
}

// enrol signs email in (bank role: enrolment-only session) and enrols an
// authenticator; returns the secret and the recovery codes.
func enrol(t *testing.T, s *Store, email string) ([]byte, []string, string) {
	t.Helper()
	ctx := context.Background()
	l, err := s.LoginPassword(ctx, email, pw, time.Hour)
	if err != nil || !l.MFAEnrollment || l.Token == "" {
		t.Fatalf("login before enrolment: %+v %v", l, err)
	}
	ss, err := s.LookupSession(ctx, l.Token)
	if err != nil || !ss.MFAEnrollOnly || ss.MFA {
		t.Fatalf("enrolment-only session: %+v %v", ss, err)
	}
	en, err := s.MFAEnrollStart(ctx, email)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(en.OTPAuthURI, "otpauth://totp/DSS%20Patcher:"+email+"?secret="+en.SecretBase32+"&issuer=DSS%20Patcher&digits=6&period=30") {
		t.Fatalf("uri %s", en.OTPAuthURI)
	}
	sec, _ := totp.DecodeSecret(en.SecretBase32)
	if _, err := s.MFAEnrollConfirm(ctx, email, "000000", l.Token); !errors.Is(err, ErrInvalid) && totp.Code(sec, s.Now()) != "000000" {
		t.Fatalf("wrong enrolment code: %v", err)
	}
	codes, err := s.MFAEnrollConfirm(ctx, email, totp.Code(sec, s.Now()), l.Token)
	if err != nil || len(codes) != RecoveryCodes {
		t.Fatalf("confirm: %v %v", codes, err)
	}
	if ss, _ := s.LookupSession(ctx, l.Token); ss.MFAEnrollOnly || !ss.MFA {
		t.Fatalf("session after enrolment: %+v", ss)
	}
	return sec, codes, l.Token
}

func TestMFARequiredByRole(t *testing.T) {
	s := openTest(t)
	for role, want := range map[string]bool{RoleViewer: true, RoleUser: true, RoleAdmin: true, RoleSuperAdmin: false} {
		if s.MFARequired(role) != want {
			t.Errorf("%s: required %v", role, !want)
		}
	}
	s.Policy.RequireMFA = true
	if !s.MFARequired(RoleSuperAdmin) {
		t.Error("require_mfa must include super admins")
	}
	mkUser(t, s, bySuper, "nokey@bank.example", RoleUser)
	if _, err := s.MFAEnrollStart(context.Background(), "nokey@bank.example"); !errors.Is(err, ErrMFAKey) {
		t.Fatalf("no key: %v", err)
	}
}

func TestMFAEnrolLoginReplayRecovery(t *testing.T) {
	s, now := mfaStore(t)
	ctx := context.Background()
	mkUser(t, s, byAdmin, "uma@bank.example", RoleUser)
	sec, codes, _ := enrol(t, s, "uma@bank.example")
	// The secret is stored encrypted, never in clear.
	var enc string
	s.db.QueryRow(`SELECT secret_enc FROM mfa WHERE email='uma@bank.example'`).Scan(&enc)
	if enc == "" || strings.Contains(enc, totp.EncodeSecret(sec)) {
		t.Fatal("secret not encrypted")
	}
	other := openTest(t)
	other.SetMFAKey([]byte(strings.Repeat("x", 32)))
	if _, err := other.openSecret("uma@bank.example", enc); err == nil {
		t.Fatal("decrypts with another key")
	}
	if _, err := s.openSecret("ivy@bank.example", enc); err == nil {
		t.Fatal("secret of one user decrypts for another")
	}
	if _, err := s.MFAEnrollStart(ctx, "uma@bank.example"); !errors.Is(err, ErrConflict) {
		t.Fatalf("second enrolment: %v", err)
	}
	// Password now leads to the second step: no session yet.
	l, err := s.LoginPassword(ctx, "uma@bank.example", pw, time.Hour)
	if err != nil || !l.MFAPending || l.Token != "" {
		t.Fatalf("password step: %+v %v", l, err)
	}
	// The enrolment code (current step) cannot be replayed.
	if _, err := s.LoginMFA(ctx, "uma@bank.example", totp.Code(sec, *now), "", time.Hour); !errors.Is(err, ErrBadMFACode) {
		t.Fatalf("replayed enrolment code: %v", err)
	}
	*now = now.Add(30 * time.Second)
	code := totp.Code(sec, *now)
	m, err := s.LoginMFA(ctx, "uma@bank.example", code, "", time.Hour)
	if err != nil || m.Token == "" {
		t.Fatalf("code: %v", err)
	}
	if ss, _ := s.LookupSession(ctx, m.Token); !ss.MFA || ss.MFAEnrollOnly {
		t.Fatalf("session: %+v", ss)
	}
	if _, err := s.LoginMFA(ctx, "uma@bank.example", code, "", time.Hour); !errors.Is(err, ErrBadMFACode) {
		t.Fatalf("replay: %v", err)
	}
	if _, err := s.LoginMFA(ctx, "uma@bank.example", "123456", "", time.Hour); !errors.Is(err, ErrBadMFACode) && totp.Code(sec, *now) != "123456" {
		t.Fatalf("wrong code: %v", err)
	}
	// Recovery codes: each once (case and dashes do not matter).
	if _, err := s.LoginMFA(ctx, "uma@bank.example", "", strings.ToUpper(strings.ReplaceAll(codes[3], "-", "")), time.Hour); err != nil {
		t.Fatalf("recovery code: %v", err)
	}
	if _, err := s.LoginMFA(ctx, "uma@bank.example", "", codes[3], time.Hour); !errors.Is(err, ErrBadMFACode) {
		t.Fatalf("recovery code reused: %v", err)
	}
	evs, _ := s.ListAudit(ctx, AuditQuery{Action: "auth.mfa"})
	kinds := map[string]bool{}
	for _, e := range evs {
		kinds[e.Action] = true
	}
	if !kinds["auth.mfa_failed"] || !kinds["auth.mfa_recovery_used"] {
		t.Fatalf("mfa audit: %v", kinds)
	}
	all, _ := s.ListAudit(ctx, AuditQuery{Limit: 1000})
	for _, e := range all {
		if strings.Contains(string(e.Details), totp.EncodeSecret(sec)) || strings.Contains(string(e.Details), codes[0]) {
			t.Fatal("secret or recovery code in the audit trail")
		}
	}
}

// Wrong codes count towards the password lockout.
func TestMFALockout(t *testing.T) {
	s, now := mfaStore(t)
	ctx := context.Background()
	mkUser(t, s, byAdmin, "ivy@bank.example", RoleViewer)
	sec, _, _ := enrol(t, s, "ivy@bank.example")
	*now = now.Add(time.Minute)
	good := totp.Code(sec, *now)
	bad := "000000"
	if bad == good {
		bad = "111111"
	}
	for i := 0; i < MaxFailedLogins; i++ {
		if _, err := s.LoginMFA(ctx, "ivy@bank.example", bad, "", time.Hour); !errors.Is(err, ErrBadMFACode) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if _, err := s.LoginMFA(ctx, "ivy@bank.example", good, "", time.Hour); !errors.Is(err, ErrBadMFACode) {
		t.Fatalf("locked account took a right code: %v", err)
	}
	if _, err := s.LoginPassword(ctx, "ivy@bank.example", pw, time.Hour); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("locked account took the password: %v", err)
	}
	*now = now.Add(LockFor + time.Minute)
	if _, err := s.LoginMFA(ctx, "ivy@bank.example", totp.Code(sec, *now), "", time.Hour); err != nil {
		t.Fatalf("after the lockout: %v", err)
	}
}

func TestResetAndDisableMFA(t *testing.T) {
	s, now := mfaStore(t)
	ctx := context.Background()
	mkUser(t, s, byAdmin, "uma@bank.example", RoleUser)
	_, _, tok := enrol(t, s, "uma@bank.example")
	if err := s.ResetMFA(ctx, Manager{Actor: "user:ivy@bank.example", Role: RoleUser}, "uma@bank.example", "x"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("user resets MFA: %v", err)
	}
	if err := s.ResetMFA(ctx, byAdmin, "adam@bank.example", "x"); !errors.Is(err, ErrConflict) {
		t.Fatalf("admin resets own MFA: %v", err)
	}
	if err := s.ResetMFA(ctx, byAdmin, "uma@bank.example", "lost phone"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.MFAEnrolled(ctx, "uma@bank.example"); ok {
		t.Fatal("still enrolled after reset")
	}
	if _, err := s.LookupSession(ctx, tok); err == nil {
		t.Fatal("session survives an MFA reset")
	}
	if l, _ := s.LoginPassword(ctx, "uma@bank.example", pw, time.Hour); !l.MFAEnrollment {
		t.Fatalf("after reset the user must enrol again: %+v", l)
	}
	// Super admins: optional, an admin cannot reset theirs; they may switch it off.
	mkUser(t, s, bySuper, "vendor@dataspacesecurity.test", RoleSuperAdmin)
	s.db.Exec(`UPDATE local_users SET must_change_password=0`)
	l, err := s.LoginPassword(ctx, "vendor@dataspacesecurity.test", pw, time.Hour)
	if err != nil || l.MFAEnrollment || l.MFAPending || l.Token == "" {
		t.Fatalf("super admin without MFA: %+v %v", l, err)
	}
	en, _ := s.MFAEnrollStart(ctx, "vendor@dataspacesecurity.test")
	sec, _ := totp.DecodeSecret(en.SecretBase32)
	if _, err := s.MFAEnrollConfirm(ctx, "vendor@dataspacesecurity.test", totp.Code(sec, *now), l.Token); err != nil {
		t.Fatal(err)
	}
	if err := s.ResetMFA(ctx, byAdmin, "vendor@dataspacesecurity.test", "x"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("admin resets a super admin's MFA: %v", err)
	}
	if err := s.DisableOwnMFA(ctx, "uma@bank.example", RoleUser, "123456"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("bank user disables MFA: %v", err)
	}
	*now = now.Add(30 * time.Second)
	if err := s.DisableOwnMFA(ctx, "vendor@dataspacesecurity.test", RoleSuperAdmin, totp.Code(sec, *now)); err != nil {
		t.Fatalf("super admin disables own MFA: %v", err)
	}
	// reset-admin also clears the super admin's MFA.
	en, _ = s.MFAEnrollStart(ctx, "vendor@dataspacesecurity.test")
	sec, _ = totp.DecodeSecret(en.SecretBase32)
	*now = now.Add(30 * time.Second)
	s.MFAEnrollConfirm(ctx, "vendor@dataspacesecurity.test", totp.Code(sec, *now), "")
	if err := s.RecoverSuperAdmin(ctx, "vendor@dataspacesecurity.test", "a recovery passphrase"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.MFAEnrolled(ctx, "vendor@dataspacesecurity.test"); ok {
		t.Fatal("reset-admin kept the MFA enrolment")
	}
	evs, _ := s.ListAudit(ctx, AuditQuery{Action: "user.mfa"})
	kinds := map[string]bool{}
	for _, e := range evs {
		kinds[e.Action] = true
	}
	for _, k := range []string{"user.mfa_enrollment_started", "user.mfa_enrolled", "user.mfa_reset", "user.mfa_disabled"} {
		if !kinds[k] {
			t.Errorf("not audited: %s (%v)", k, kinds)
		}
	}
}

func TestDeleteLocalUser(t *testing.T) {
	s, _ := mfaStore(t)
	ctx := context.Background()
	mkUser(t, s, bySuper, "vendor@dataspacesecurity.test", RoleSuperAdmin)
	mkUser(t, s, bySuper, "adam@bank.example", RoleAdmin)
	mkUser(t, s, byAdmin, "uma@bank.example", RoleUser)
	_, _, tok := enrol(t, s, "uma@bank.example")
	vendor := Manager{Actor: "user:vendor@dataspacesecurity.test", Role: RoleSuperAdmin}
	for _, c := range []struct {
		what  string
		by    Manager
		email string
		want  error
	}{
		{"user deletes", byUser, "adam@bank.example", ErrForbidden},
		{"admin deletes a super admin", byAdmin, "vendor@dataspacesecurity.test", ErrForbidden},
		{"admin deletes themselves", byAdmin, "adam@bank.example", ErrConflict},
		{"last super admin", Manager{Actor: "user:other@x.example", Role: RoleSuperAdmin}, "vendor@dataspacesecurity.test", ErrConflict},
		{"unknown", byAdmin, "ghost@bank.example", ErrNotFound},
	} {
		if err := s.DeleteLocalUser(ctx, c.by, c.email, "x"); !errors.Is(err, c.want) {
			t.Errorf("%s: want %v, got %v", c.what, c.want, err)
		}
	}
	s.Login(ctx, "sso@bank.example", "user", "", "oidc", true, time.Hour)
	if err := s.DeleteLocalUser(ctx, byAdmin, "sso@bank.example", "x"); !errors.Is(err, ErrConflict) {
		t.Fatalf("SSO user deleted: %v", err)
	}
	if err := s.DeleteLocalUser(ctx, byAdmin, "uma@bank.example", "left the bank"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LookupSession(ctx, tok); err == nil {
		t.Fatal("session survives deletion")
	}
	if _, err := s.LoginPassword(ctx, "uma@bank.example", pw, time.Hour); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("deleted user signs in: %v", err)
	}
	if ok, _ := s.MFAEnrolled(ctx, "uma@bank.example"); ok {
		t.Fatal("MFA row kept")
	}
	// The email can be used again; history stays.
	mkUser(t, s, byAdmin, "uma@bank.example", RoleViewer)
	evs, _ := s.ListAudit(ctx, AuditQuery{ObjectID: "uma@bank.example", Limit: 1000})
	var deleted, created int
	for _, e := range evs {
		switch e.Action {
		case "user.deleted":
			deleted++
		case "user.created":
			created++
		}
	}
	if deleted != 1 || created != 2 {
		t.Fatalf("history: deleted %d created %d", deleted, created)
	}
	mkUser(t, s, bySuper, "vendor2@dataspacesecurity.test", RoleSuperAdmin)
	if err := s.DeleteLocalUser(ctx, vendor, "vendor2@dataspacesecurity.test", "x"); err != nil {
		t.Fatalf("super admin deletes another super admin: %v", err)
	}
}
