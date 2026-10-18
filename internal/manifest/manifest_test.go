package manifest

import (
	"archive/tar"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func validManifest(t *testing.T) *Manifest {
	now := time.Now().UTC()
	return &Manifest{
		SchemaVersion: 1, BundleID: "b-1", Source: "acq", Sequence: 1, KeyID: "ed25519:0011223344556677",
		CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour),
		Packages: []Package{{
			PackageID: "KB5000001-x64", Title: "t", Vendor: "Microsoft", Kind: "msu", KB: "KB5000001", Severity: "critical",
			Applicability:   Applicability{OS: "windows", Arch: "x64"},
			File:            FileRef{Name: "payload/a.msu", Size: 1, SHA256: strings.Repeat("a", 64)},
			VendorSignature: VendorSignature{Status: "not_checked"},
		}},
	}
}

func TestSchema(t *testing.T) {
	if err := validManifest(t).ValidateSchema(time.Now()); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
	cases := map[string]func(m *Manifest){
		"expired":   func(m *Manifest) { m.ExpiresAt = time.Now().Add(-time.Hour) },
		"lifetime":  func(m *Manifest) { m.ExpiresAt = m.CreatedAt.Add(100 * 24 * time.Hour) },
		"traversal": func(m *Manifest) { m.Packages[0].File.Name = "payload/../x" },
		"bad kb":    func(m *Manifest) { m.Packages[0].KB = "5000001" },
		"nil product": func(m *Manifest) {
			m.Packages[0].Kind, m.Packages[0].ProductCode = "msi", "{00000000-0000-0000-0000-000000000000}"
		},
		"vendor invalid": func(m *Manifest) { m.Packages[0].VendorSignature.Status = "invalid" },
		"msi no guid":    func(m *Manifest) { m.Packages[0].Kind = "msi" },
		"no packages":    func(m *Manifest) { m.Packages = nil },
		"seq zero":       func(m *Manifest) { m.Sequence = 0 },
	}
	for name, mut := range cases {
		m := validManifest(t)
		mut(m)
		if err := m.ValidateSchema(time.Now()); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}

func TestSignVerify(t *testing.T) {
	pub, priv, _ := GenerateKey()
	msg := []byte(`{"a":1}`)
	sig := Sign(priv, msg)
	if err := Verify(pub, msg, sig); err != nil {
		t.Fatal(err)
	}
	if err := Verify(pub, []byte(`{"a":2}`), sig); err == nil {
		t.Fatal("modified manifest verified")
	}
	pub2, _, _ := GenerateKey()
	if err := Verify(pub2, msg, sig); err == nil {
		t.Fatal("wrong key verified")
	}
	p, err := ParsePublic(string(EncodePublic(pub)))
	if err != nil || KeyID(p) != KeyID(pub) {
		t.Fatal("PEM round trip failed")
	}
}

func writeTar(t *testing.T, entries []tar.Header, bodies []string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "b.pmb")
	f, _ := os.Create(p)
	tw := tar.NewWriter(f)
	for i, h := range entries {
		h.Size = int64(len(bodies[i]))
		if h.Typeflag == 0 {
			h.Typeflag = tar.TypeReg
		}
		if h.Typeflag != tar.TypeReg {
			h.Size = 0
		}
		h.Mode = 0o644
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			tw.Write([]byte(bodies[i]))
		}
	}
	tw.Close()
	f.Close()
	return p
}

func TestExtractSafeRejects(t *testing.T) {
	base := []tar.Header{{Name: EntryManifest}, {Name: EntrySig}}
	bodies := []string{"{}", "sig"}
	cases := map[string]tar.Header{
		"traversal":  {Name: "payload/../../etc/passwd"},
		"absolute":   {Name: "/etc/passwd"},
		"symlink":    {Name: "payload/x", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"},
		"hardlink":   {Name: "payload/y", Typeflag: tar.TypeLink, Linkname: "manifest.json"},
		"unexpected": {Name: "evil.sh"},
		"nested":     {Name: "payload/a/b"},
	}
	for name, h := range cases {
		p := writeTar(t, append(append([]tar.Header{}, base...), h), append(append([]string{}, bodies...), "x"))
		if _, err := ExtractSafe(p, t.TempDir(), Limits{}); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
	// duplicates
	p := writeTar(t, []tar.Header{{Name: EntryManifest}, {Name: EntrySig}, {Name: "payload/a"}, {Name: "payload/a"}}, []string{"{}", "s", "1", "2"})
	if _, err := ExtractSafe(p, t.TempDir(), Limits{}); err == nil {
		t.Error("duplicate entry accepted")
	}
	// oversize
	p = writeTar(t, []tar.Header{{Name: EntryManifest}, {Name: EntrySig}, {Name: "payload/a"}}, []string{"{}", "s", "0123456789"})
	if _, err := ExtractSafe(p, t.TempDir(), Limits{MaxFileBytes: 5}); err == nil {
		t.Error("oversize file accepted")
	}
	// good
	p = writeTar(t, []tar.Header{{Name: EntryManifest}, {Name: EntrySig}, {Name: "payload/", Typeflag: tar.TypeDir}, {Name: "payload/a.msu"}}, []string{"{}", "s", "", "hello"})
	ex, err := ExtractSafe(p, t.TempDir(), Limits{})
	if err != nil {
		t.Fatalf("good bundle rejected: %v", err)
	}
	if ex.Files["payload/a.msu"].Size != 5 {
		t.Error("payload not extracted")
	}
}

// expected_ubr is optional (omitempty: manifests without it marshal exactly
// as before) and only valid on msu packages.
func TestExpectedUBR(t *testing.T) {
	m := validManifest(t)
	b, _ := json.Marshal(m.Packages[0])
	if strings.Contains(string(b), "expected_ubr") {
		t.Errorf("zero expected_ubr marshalled: %s", b)
	}
	m.Packages[0].ExpectedUBR = 9711
	if err := m.ValidateSchema(time.Now()); err != nil {
		t.Fatalf("msu with expected_ubr: %v", err)
	}
	b, _ = json.Marshal(m)
	p, err := Parse(b)
	if err != nil || p.Packages[0].ExpectedUBR != 9711 {
		t.Fatalf("parse: %v %+v", err, p)
	}
	for _, mut := range []func(*Package){
		func(p *Package) { p.ExpectedUBR = -1 },
		func(p *Package) { p.Kind, p.ProductCode = "msi", "{11111111-2222-3333-4444-555555555555}" },
	} {
		m := validManifest(t)
		m.Packages[0].ExpectedUBR = 9711
		mut(&m.Packages[0])
		if err := m.ValidateSchema(time.Now()); err == nil {
			t.Errorf("accepted: %+v", m.Packages[0])
		}
	}
}
