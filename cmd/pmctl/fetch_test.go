package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"offpatch/internal/acquire/acquiretest"
	"offpatch/internal/manifest"
)

// TestFetchThenBuild runs `pmctl fetch` and `pmctl fetch-url` against a fake
// catalog/MSRC/vendor (recorded fixtures), then `pmctl build` on the
// generated spec, and checks the result is a valid signed bundle.
func TestFetchThenBuild(t *testing.T) {
	stubAuthenticode(t)
	srv := acquiretest.New(t, "../../internal/acquire/testdata", acquiretest.Payload(250_000))
	msi := acquiretest.Payload(64_000)[1000:] // distinct content
	srv.Vendor["acme-agent-2.2.msi"] = msi
	msiSum := sha256.Sum256(msi)

	oldCat, oldMSRC, oldHC, oldOut := catalogBaseURL, msrcBaseURL, newHTTPClient, progressOut
	catalogBaseURL, msrcBaseURL = srv.URL, srv.URL
	newHTTPClient = func() *http.Client { return srv.Client() }
	progressOut = io.Discard
	t.Cleanup(func() { catalogBaseURL, msrcBaseURL, newHTTPClient, progressOut = oldCat, oldMSRC, oldHC, oldOut })

	dir := t.TempDir()
	spec := filepath.Join(dir, "spec.json")
	out := filepath.Join(dir, "downloads")

	if err := catalogSearch([]string{"-q", "KB5126657"}); err != nil {
		t.Fatal(err)
	}
	if err := msrcCmd([]string{"-month", "2026-Oct", "-product", "Windows 10 Version 22H2"}); err != nil {
		t.Fatal(err)
	}
	if err := fetchKB([]string{"-kb", "KB5126657", "-product", "Windows 10 Version 22H2", "-arch", "x64",
		"-min-build", "19045", "-max-build", "19045", "-msrc-month", "2026-Oct", "-out", out, "-spec", spec}); err != nil {
		t.Fatal(err)
	}
	if err := fetchURL([]string{"-url", srv.URL + "/vendor/acme-agent-2.2.msi", "-sha256", hex.EncodeToString(msiSum[:]),
		"-package-id", "AcmeAgent-2.2", "-title", "Acme Endpoint Agent 2.2", "-vendor", "Acme", "-kind", "msi",
		"-product-code", "{11111111-2222-3333-4444-555555555555}", "-severity", "important", "-version", "2.2.0",
		"-out", out, "-spec", spec}); err != nil {
		t.Fatal(err)
	}
	// Wrong hash: refused.
	if err := fetchURL([]string{"-url", srv.URL + "/vendor/acme-agent-2.2.msi", "-sha256", hex.EncodeToString(make([]byte, 32)),
		"-package-id", "AcmeAgent-2.2b", "-title", "x", "-vendor", "Acme", "-product-code", "{11111111-2222-3333-4444-555555555555}",
		"-severity", "low", "-file", "other.msi", "-out", out, "-spec", spec}); err == nil {
		t.Fatal("fetch-url accepted a wrong SHA-256")
	}

	// Sign with a fresh key through the real build code path.
	pub, priv, err := manifest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "bundle.key")
	os.WriteFile(keyPath, manifest.EncodePrivate(priv), 0o600)
	bundle := filepath.Join(dir, "out.pmb")
	if err := build([]string{"-key", keyPath, "-spec", spec, "-out", bundle, "-state", filepath.Join(dir, "state.json")}); err != nil {
		t.Fatalf("pmctl build rejected the generated spec: %v", err)
	}

	ex, err := manifest.ExtractSafe(bundle, t.TempDir(), manifest.Limits{MaxFiles: 500})
	if err != nil {
		t.Fatal(err)
	}
	if err := manifest.Verify(pub, ex.ManifestBytes, ex.Signature); err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Parse(ex.ManifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ValidateSchema(time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(m.Packages) != 2 {
		t.Fatalf("packages = %d", len(m.Packages))
	}
	p := m.Packages[0]
	paySum := sha256.Sum256(srv.Payload)
	if p.PackageID != "KB5126657-x64" || p.Kind != "msu" || p.Severity != "critical" || p.KB != "KB5126657" ||
		p.File.SHA256 != hex.EncodeToString(paySum[:]) || p.File.Name != "payload/"+srv.FileName ||
		p.Applicability.MinBuild != 19045 || len(p.Supersedes) == 0 || p.VendorSignature.Status == "" {
		t.Fatalf("msu package = %+v", p)
	}
	f, ok := ex.Files[p.File.Name]
	if !ok || f.SHA256 != p.File.SHA256 {
		t.Fatal("payload missing or hash differs in bundle")
	}
	q := m.Packages[1]
	if q.PackageID != "AcmeAgent-2.2" || q.Kind != "msi" || q.File.SHA256 != hex.EncodeToString(msiSum[:]) || q.Applicability.Arch != "any" {
		t.Fatalf("msi package = %+v", q)
	}
}
