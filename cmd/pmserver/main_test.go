package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

func init() { store.PasswordIterations = 1000 }

func labConfig(t *testing.T, extra ...string) (cfgPath, dataDir string) {
	t.Helper()
	dir := t.TempDir()
	pub, _, _ := manifest.GenerateKey()
	cfg := fmt.Sprintf(`{`+strings.Join(extra, "")+`"insecure_http": true, "data_dir": "data", "trusted_keys":[{"public_key": %q, "sources":["s"]}]}`, manifest.EncodePublic(pub))
	cfgPath = filepath.Join(dir, "pmserver.json")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, filepath.Join(dir, "data")
}

// create-admin without flags: the default email and the embedded default
// password hash; nothing secret is printed. -if-none then does nothing,
// reset-admin still generates a random password.
func TestCreateAdminUsesEmbeddedDefault(t *testing.T) {
	cfg, data := labConfig(t)
	var out bytes.Buffer
	if err := runAdminCmd("create-admin", []string{"-config", cfg, "-if-none"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "email:    "+store.DefaultSuperAdminEmail) || !strings.Contains(out.String(), "default_password: yes") || strings.Contains(out.String(), "\npassword: ") {
		t.Fatalf("output: %s", out.String())
	}
	st, err := store.Open(filepath.Join(data, "pm.db"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	who, err := st.DefaultSuperAdminPasswordInUse(ctx)
	if err != nil || len(who) != 1 || who[0] != store.DefaultSuperAdminEmail {
		t.Fatalf("default password in use: %v %v", who, err)
	}
	lp, _ := st.GetLocalProfile(ctx, store.DefaultSuperAdminEmail)
	if !lp.Builtin || lp.PasswordChangedAt != "" {
		t.Fatalf("profile %+v", lp)
	}
	if plain := os.Getenv("OFFPATCH_TEST_DEFAULT_SA_PW"); plain != "" {
		st.Policy.RequireSetupCode = true
		if _, err := st.LoginPassword(ctx, store.DefaultSuperAdminEmail, plain, time.Hour); err == nil {
			t.Fatal("the default password signed in without the setup code")
		}
		code, _, err := st.CreateSetupCode(ctx, store.DefaultSuperAdminEmail)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.LoginSetupCodeFrom(ctx, store.DefaultSuperAdminEmail, plain, code, "", time.Hour); err != nil {
			t.Fatalf("default password + setup code does not sign in: %v", err)
		}
	}
	st.Close()

	out.Reset()
	if err := runAdminCmd("create-admin", []string{"-config", cfg, "-if-none"}, &out); err != nil || !strings.Contains(out.String(), "already exists") {
		t.Fatalf("-if-none: %v %s", err, out.String())
	}
	out.Reset()
	if err := runAdminCmd("reset-admin", []string{"-config", cfg}, &out); err != nil || !strings.Contains(out.String(), "\npassword: ") {
		t.Fatalf("reset-admin: %v %s", err, out.String())
	}
	st, _ = store.Open(filepath.Join(data, "pm.db"))
	defer st.Close()
	if who, _ := st.DefaultSuperAdminPasswordInUse(ctx); len(who) != 0 {
		t.Fatalf("reset-admin kept the default password: %v", who)
	}
}

func openTestStore(t *testing.T, data string) *store.Store {
	t.Helper()
	if err := os.MkdirAll(data, 0o750); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(data, "pm.db"))
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// -if-fresh (installer): an empty database gets the built-in super admin; a
// database with any user (here: a bank super admin, the vendor account
// deleted) gets nothing, so an upgrade never re-creates the default account.
func TestCreateAdminIfFresh(t *testing.T) {
	cfg, _ := labConfig(t)
	var out bytes.Buffer
	if err := runAdminCmd("create-admin", []string{"-config", cfg, "-if-fresh"}, &out); err != nil || !strings.Contains(out.String(), "default_password: yes") {
		t.Fatalf("fresh: %v %s", err, out.String())
	}

	cfg2, data2 := labConfig(t)
	st := openTestStore(t, data2)
	if _, err := st.CreateBuiltinSuperAdmin(context.Background(), "bank-sa@bank.example", "Bank", store.GeneratePassword()); err != nil {
		t.Fatal(err)
	}
	st.Close()
	out.Reset()
	if err := runAdminCmd("create-admin", []string{"-config", cfg2, "-if-fresh"}, &out); err != nil || !strings.Contains(out.String(), "not a fresh install") {
		t.Fatalf("not fresh: %v %s", err, out.String())
	}
	st = openTestStore(t, data2)
	defer st.Close()
	if _, err := st.GetLocalProfile(context.Background(), store.DefaultSuperAdminEmail); err == nil {
		t.Fatal("-if-fresh created the default super admin in a database that already had users")
	}
}

// The built-in account exists but is disabled: create-admin (with or without
// -if-none) succeeds without changing anything instead of a conflict error.
func TestCreateAdminDisabledAccountIsIdempotent(t *testing.T) {
	cfg, data := labConfig(t)
	var out bytes.Buffer
	if err := runAdminCmd("create-admin", []string{"-config", cfg}, &out); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	st := openTestStore(t, data)
	if _, err := st.CreateBuiltinSuperAdmin(ctx, "bank-sa@bank.example", "Bank", store.GeneratePassword()); err != nil {
		t.Fatal(err)
	}
	by := store.Manager{Actor: "user:bank-sa@bank.example", Role: store.RoleSuperAdmin}
	if err := st.SetUserDisabled(ctx, by, store.DefaultSuperAdminEmail, true, "vendor access off"); err != nil {
		t.Fatal(err)
	}
	st.Close()
	for _, args := range [][]string{{"-config", cfg}, {"-config", cfg, "-if-none"}, {"-config", cfg, "-password-random"}} {
		out.Reset()
		if err := runAdminCmd("create-admin", args, &out); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if !strings.Contains(out.String(), "already exists") || !strings.Contains(out.String(), "disabled") || strings.Contains(out.String(), "password:") {
			t.Fatalf("%v: output %s", args, out.String())
		}
	}
	st = openTestStore(t, data)
	defer st.Close()
	users, err := st.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		if u.Username == store.DefaultSuperAdminEmail && !u.Disabled {
			t.Fatal("create-admin re-enabled the disabled account")
		}
	}
}

// -password-random keeps the old behaviour: a generated password, shown once.
func TestCreateAdminRandomPassword(t *testing.T) {
	cfg, _ := labConfig(t)
	var out bytes.Buffer
	if err := runAdminCmd("create-admin", []string{"-config", cfg, "-email", "vendor@dataspacesecurity.com", "-password-random"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "email:    vendor@dataspacesecurity.com") || !strings.Contains(out.String(), "password: ") {
		t.Fatalf("output: %s", out.String())
	}
}

// setup-code: a code for the built-in account while it has the default
// password (printed once, stored hashed); -if-needed is quiet once the
// account has its own password, without it that is an error.
func TestSetupCodeCmd(t *testing.T) {
	cfg, data := labConfig(t, `"require_setup_code": true,`)
	var out bytes.Buffer
	if err := runAdminCmd("create-admin", []string{"-config", cfg, "-if-fresh"}, &out); err != nil {
		t.Fatal(err)
	}
	defer func() { // only the hash is stored: the database never holds a printed code
		b, _ := os.ReadFile(filepath.Join(data, "pm.db"))
		if m := regexp.MustCompile(`[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}`).Find(b); m != nil {
			t.Errorf("a setup code in plaintext in the database: %s", m)
		}
	}()
	codeRe := regexp.MustCompile(`(?m)^setup_code: ([A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4})$`)
	for _, args := range [][]string{{"-config", cfg}, {"-config", cfg, "-if-needed"}} {
		out.Reset()
		if err := setupCodeCmd(args, &out); err != nil {
			t.Fatal(err)
		}
		m := codeRe.FindStringSubmatch(out.String())
		if m == nil || !strings.Contains(out.String(), "email:      "+store.DefaultSuperAdminEmail) || !strings.Contains(out.String(), "expires_at: ") {
			t.Fatalf("output: %s", out.String())
		}
		if strings.Count(out.String(), m[1]) != 1 {
			t.Fatalf("code printed more than once: %s", out.String())
		}
	}
	out.Reset()
	if err := runAdminCmd("reset-admin", []string{"-config", cfg}, &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := setupCodeCmd([]string{"-config", cfg, "-if-needed"}, &out); err != nil || !strings.Contains(out.String(), "no setup code needed") || codeRe.MatchString(out.String()) {
		t.Fatalf("-if-needed after reset-admin: %v %s", err, out.String())
	}
	if err := setupCodeCmd([]string{"-config", cfg}, &out); err == nil {
		t.Fatal("setup-code for an account with its own password must fail without -if-needed")
	}
	cfg2, _ := labConfig(t)
	out.Reset()
	if err := setupCodeCmd([]string{"-config", cfg2, "-if-needed"}, &out); err != nil || !strings.Contains(out.String(), "no setup code needed") {
		t.Fatalf("-if-needed without the account: %v %s", err, out.String())
	}
}
