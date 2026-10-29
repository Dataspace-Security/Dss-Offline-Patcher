package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"offpatch/internal/manifest"
)

// Two product lines that share KB numbers (Windows 11 24H2 and Windows
// Server 2025) download one and the same catalog file. The spec then holds
// two packages with different ids that point at the same payload file, and
// the bundle must ship that file once — not refuse the build with
// "file.name duplicated" and sink the whole delivery run.
func TestSharedPayloadBuild(t *testing.T) {
	stubAuthenticode(t)
	dir := t.TempDir()
	cu := filepath.Join(dir, "dl", "windows11.0-kb5127699-x64_e4f8b7a19c02d5b8a6a4f3c1b9e8d7f6a5c4b3a2.msu")
	os.MkdirAll(filepath.Dir(cu), 0o755)
	os.WriteFile(cu, []byte("shared cumulative update"), 0o600)

	_, priv, _ := manifest.GenerateKey()
	os.WriteFile(filepath.Join(dir, "k.key"), manifest.EncodePrivate(priv), 0o600)

	spec := []specPackage{
		{Package: manifest.Package{
			PackageID: "KB5127699-x64", Title: "2026-10 CU (Win11 24H2)", Vendor: "Microsoft", Kind: "msu",
			KB: "KB5127699", Severity: "important", Applicability: manifest.Applicability{OS: "windows", Arch: "x64", MinBuild: 26100, MaxBuild: 26100},
		}, Path: "dl/" + filepath.Base(cu)},
		{Package: manifest.Package{
			PackageID: "KB5127699-x64-server", Title: "2026-10 CU (Server 2025)", Vendor: "Microsoft", Kind: "msu",
			KB: "KB5127699", Severity: "important", Applicability: manifest.Applicability{OS: "windows", Arch: "x64", MinBuild: 26100, MaxBuild: 26100},
		}, Path: "dl/" + filepath.Base(cu)},
	}
	state := filepath.Join(dir, "seq.json")
	br, err := buildFromSpec(buildOpts{Key: filepath.Join(dir, "k.key"), Out: filepath.Join(dir, "b.pmb"),
		Source: "acq-zone-1", State: state, TTL: time.Hour}, spec, dir)
	if err != nil {
		t.Fatalf("shared payload build refused: %v", err)
	}
	if br.Packages != 2 {
		t.Fatalf("packages %d, want 2", br.Packages)
	}
	// Both packages reference the one physical payload, and the bundle ships
	// it exactly once under that name.
	shared := "payload/" + filepath.Base(cu)
	ex, err := manifest.ExtractSafe(br.Path, t.TempDir(), manifest.Limits{MaxFiles: 500})
	if err != nil {
		t.Fatalf("extract built bundle: %v", err)
	}
	if f, ok := ex.Files[shared]; !ok || !strings.EqualFold(f.SHA256, br.PackageSHA256["KB5127699-x64"]) {
		t.Fatalf("shared payload in bundle: %+v (want sha %s)", ex.Files[shared], br.PackageSHA256["KB5127699-x64"])
	}
	if len(ex.Files) != 1 {
		t.Fatalf("bundle ships %d payload file(s), want 1: %v", len(ex.Files), ex.Files)
	}
	// The built manifest still passes strict schema validation.
	if err := exParsedManifest(ex).ValidateSchema(exParsedManifest(ex).CreatedAt); err != nil {
		t.Fatalf("built manifest: %v", err)
	}
}

// exParsedManifest decodes a bundle's manifest the way intake does.
func exParsedManifest(ex *manifest.Extracted) *manifest.Manifest {
	m, err := manifest.Parse(ex.ManifestBytes)
	if err != nil {
		panic(err) // a freshly built bundle must always parse
	}
	return m
}
