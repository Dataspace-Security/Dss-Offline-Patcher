package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"offpatch/internal/manifest"
)

func TestExecSigner(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "fakehsm")
	if out, err := exec.Command("go", "build", "-o", bin, "./testdata/fakehsm").CombinedOutput(); err != nil {
		t.Fatalf("build fakehsm: %v %s", err, out)
	}
	pub, priv, _ := manifest.GenerateKey()
	os.WriteFile(filepath.Join(dir, "k.key"), manifest.EncodePrivate(priv), 0o600)
	os.WriteFile(filepath.Join(dir, "k.pub"), manifest.EncodePublic(pub), 0o644)
	t.Setenv("FAKEHSM_KEY", filepath.Join(dir, "k.key"))

	s, err := openSigner("exec:"+bin, filepath.Join(dir, "k.pub"))
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte(`{"manifest":1}`)
	sig, err := s.Sign(msg)
	if err != nil || manifest.Verify(pub, msg, sig) != nil {
		t.Fatalf("exec signer: %v", err)
	}
	if s.KeyID() != manifest.KeyID(pub) {
		t.Fatal("key id")
	}
	for _, mode := range []string{"garbage", "fail"} {
		t.Setenv("FAKEHSM_MODE", mode)
		if _, err := s.Sign(msg); err == nil {
			t.Fatalf("%s: misbehaving signer accepted", mode)
		}
	}
	if _, err := openSigner("exec:"+bin, ""); err == nil {
		t.Fatal("exec signer without -pub accepted")
	}
}
