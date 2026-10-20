package backup

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

type fixture struct {
	dir  string
	l    Layout
	st   *store.Store
	opts Options
	vo   VerifyOptions
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	pki := filepath.Join(dir, "pki")
	for _, d := range []string{filepath.Join(data, "repository", "ab"), pki} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	st, err := store.Open(filepath.Join(data, "pm.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if err := st.Audit(ctx, store.Ev{Actor: "system:test", Action: "test.event", ObjectType: "test", ObjectID: "1"}); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(data, "repository", "ab", "abcd"), []byte("package bytes"), 0o640)
	os.WriteFile(filepath.Join(data, "mfa.key"), []byte("MFA-SECRET-KEY"), 0o600)
	os.WriteFile(filepath.Join(pki, "ca.key"), []byte("CA-PRIVATE-KEY"), 0o600)
	os.WriteFile(filepath.Join(dir, "pmserver.json"), []byte(`{"data_dir": "x"}`), 0o600)
	pub, sk, _ := manifest.GenerateKey()
	idFile, recipient, err := GenerateIdentity("test")
	if err != nil {
		t.Fatal(err)
	}
	ids, err := age.ParseIdentities(strings.NewReader(idFile))
	if err != nil {
		t.Fatal(err)
	}
	rs, err := age.ParseRecipients(strings.NewReader(recipient))
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{dir: dir, st: st, l: Layout{DataDir: data, PKIDir: pki, ConfigFile: filepath.Join(dir, "pmserver.json")},
		opts: Options{Recipients: rs, SigningKey: sk, IncludePKI: true}, vo: VerifyOptions{Pub: pub, Identities: ids}}
}

// S-6: encrypt / decrypt round trip; the manifest is signed; nothing in
// the backup directory is plaintext.
func TestEncryptedBackupRoundTrip(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	out := filepath.Join(f.dir, "b1")
	if _, err := Create(ctx, f.st, f.l, out, Options{SigningKey: f.opts.SigningKey}); !errors.Is(err, ErrNoRecipients) {
		t.Fatalf("no recipients: %v", err)
	}
	m, err := Create(ctx, f.st, f.l, out, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Encrypted() || len(m.Parts) != 2 || m.Signature == nil || len(m.Recipients) != 1 {
		t.Fatalf("manifest: %+v", m)
	}
	entries, _ := os.ReadDir(out)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
		b, _ := os.ReadFile(filepath.Join(out, e.Name()))
		for _, secret := range []string{"MFA-SECRET-KEY", "CA-PRIVATE-KEY", "package bytes", "SQLite format"} {
			if strings.Contains(string(b), secret) {
				t.Errorf("%s contains %q in plaintext", e.Name(), secret)
			}
		}
	}
	if strings.Join(names, ",") != "backup.json,data.tar.age,keys.tar.age" {
		t.Fatalf("backup files: %v", names)
	}
	parts := map[string]string{}
	for _, fl := range m.Files {
		parts[fl.Path] = fl.Part
	}
	if parts["data/mfa.key"] != partKeys || parts["pki/ca.key"] != partKeys || parts["config/pmserver.json"] != partKeys ||
		parts["data/pm.db"] != partData || parts["data/repository/ab/abcd"] != partData {
		t.Fatalf("parts: %v", parts)
	}
	if left, _ := filepath.Glob(filepath.Join(f.l.DataDir, ".backup-snapshot-*")); len(left) != 0 {
		t.Errorf("snapshot left in data dir: %v", left)
	}

	// Verify: signature + parts without the identity; every file with it.
	if _, err := Verify(out, VerifyOptions{}); !errors.Is(err, ErrNeedPublicKey) {
		t.Fatalf("verify without key: %v", err)
	}
	if _, err := Verify(out, VerifyOptions{Pub: f.vo.Pub}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if _, err := Verify(out, f.vo); err != nil {
		t.Fatalf("deep verify: %v", err)
	}
	other, _ := age.GenerateHybridIdentity()
	if _, err := Verify(out, VerifyOptions{Pub: f.vo.Pub, Identities: []age.Identity{other}}); err == nil || !strings.Contains(err.Error(), "decrypt") {
		t.Fatalf("wrong identity: %v", err)
	}

	// Restore round trip.
	target := Layout{DataDir: filepath.Join(f.dir, "restored"), PKIDir: filepath.Join(f.dir, "pki2")}
	if _, err := Restore(ctx, out, target, false, VerifyOptions{Pub: f.vo.Pub}); !errors.Is(err, ErrNeedIdentity) {
		t.Fatalf("restore without identity: %v", err)
	}
	if _, err := Restore(ctx, out, target, false, f.vo); err != nil {
		t.Fatalf("restore: %v", err)
	}
	for p, want := range map[string]string{filepath.Join(target.DataDir, "mfa.key"): "MFA-SECRET-KEY", filepath.Join(target.PKIDir, "ca.key"): "CA-PRIVATE-KEY",
		filepath.Join(target.DataDir, "repository", "ab", "abcd"): "package bytes"} {
		if b, err := os.ReadFile(p); err != nil || string(b) != want {
			t.Errorf("%s after restore: %q %v", p, b, err)
		}
	}

	// Decrypt gives a plain (format 1) backup that verifies.
	plain := filepath.Join(f.dir, "plain")
	if _, err := Decrypt(out, plain, f.vo); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if pm, err := Verify(plain, VerifyOptions{}); err != nil || pm.Encrypted() || len(pm.Files) != len(m.Files) {
		t.Fatalf("decrypted backup: %+v %v", pm, err)
	}
	if b, _ := os.ReadFile(filepath.Join(plain, "config", "pmserver.json")); !strings.Contains(string(b), "data_dir") {
		t.Errorf("config not decrypted: %q", b)
	}
}

// S-6: backup.json is signed: an edited manifest, another key, a changed
// or an extra file are refused.
func TestBackupManifestSignature(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	out := filepath.Join(f.dir, "b1")
	if _, err := Create(ctx, f.st, f.l, out, f.opts); err != nil {
		t.Fatal(err)
	}
	mpath := filepath.Join(out, "backup.json")
	orig, _ := os.ReadFile(mpath)

	otherPub, _, _ := manifest.GenerateKey()
	if _, err := Verify(out, VerifyOptions{Pub: otherPub}); err == nil || !strings.Contains(err.Error(), "signed with key") {
		t.Fatalf("other key: %v", err)
	}

	var m Manifest
	json.Unmarshal(orig, &m)
	m.AuditSeq += 5
	b, _ := json.Marshal(m)
	os.WriteFile(mpath, b, 0o600)
	if _, err := Verify(out, VerifyOptions{Pub: f.vo.Pub}); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("edited manifest: %v", err)
	}
	m.Signature = nil
	b, _ = json.Marshal(m)
	os.WriteFile(mpath, b, 0o600)
	if _, err := Verify(out, VerifyOptions{Pub: f.vo.Pub}); err == nil || !strings.Contains(err.Error(), "not signed") {
		t.Fatalf("unsigned manifest: %v", err)
	}
	os.WriteFile(mpath, orig, 0o600)

	os.WriteFile(filepath.Join(out, "extra.txt"), []byte("x"), 0o600)
	if _, err := Verify(out, VerifyOptions{Pub: f.vo.Pub}); err == nil || !strings.Contains(err.Error(), "unexpected file extra.txt") {
		t.Fatalf("extra file: %v", err)
	}
	os.Remove(filepath.Join(out, "extra.txt"))

	keys := filepath.Join(out, "keys.tar.age")
	kb, _ := os.ReadFile(keys)
	kb[len(kb)-1] ^= 0xff
	os.WriteFile(keys, kb, 0o600)
	if _, err := Verify(out, VerifyOptions{Pub: f.vo.Pub}); err == nil || !strings.Contains(err.Error(), "modified keys.tar.age") {
		t.Fatalf("changed part: %v", err)
	}
}
