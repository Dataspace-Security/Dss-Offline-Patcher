package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

func init() { store.PasswordIterations = 1000 }

func labConfig(t *testing.T) (cfgPath, dataDir string) {
	t.Helper()
	dir := t.TempDir()
	pub, _, _ := manifest.GenerateKey()
	cfg := fmt.Sprintf(`{"insecure_http": true, "data_dir": "data", "trusted_keys":[{"public_key": %q, "sources":["s"]}]}`, manifest.EncodePublic(pub))
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
		if _, err := st.LoginPassword(ctx, store.DefaultSuperAdminEmail, plain, time.Hour); err != nil {
			t.Fatalf("default password does not sign in: %v", err)
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
