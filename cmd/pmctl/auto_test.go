package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"offpatch/internal/acquire/acquiretest"
	"offpatch/internal/manifest"
)

// TestAutoAcquisition runs `pmctl auto` against recorded Microsoft fixtures
// and a fake vendor: one run fetches the October CU for Windows 10 22H2 x64
// and a new third-party version, builds one signed bundle and sends it; a
// second run sends nothing; a new vendor version is picked up; a vendor
// checksum mismatch is refused and retried.
func TestAutoAcquisition(t *testing.T) {
	srv := acquiretest.New(t, "../../internal/acquire/testdata", acquiretest.Payload(200_000))
	app := []byte("ACME agent 2.3 msi")
	setApp := func(ver string, content []byte, published []byte) {
		srv.Vendor["latest.json"] = []byte(`{"product":"acme","releases":[{"version":"` + ver + `"}]}`)
		srv.Vendor["acme-agent-"+ver+".msi"] = content
		sum := sha256.Sum256(published)
		srv.Vendor["SHA256SUMS-"+ver] = []byte(hex.EncodeToString(sum[:]) + "  acme-agent-" + ver + ".msi\n" +
			strings.Repeat("ab", 32) + "  acme-agent-" + ver + "-arm64.msi\n")
	}
	setApp("2.3.0", app, app)

	oldHTTP, oldNow := autoHTTP, autoNow
	autoHTTP = func() *http.Client { return srv.Client() }
	autoNow = func() time.Time { return time.Date(2026, 10, 16, 3, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { autoHTTP, autoNow = oldHTTP, oldNow })

	dir := t.TempDir()
	pub, priv, _ := manifest.GenerateKey()
	os.WriteFile(filepath.Join(dir, "bundle.key"), manifest.EncodePrivate(priv), 0o600)
	drop := filepath.Join(dir, "diode")
	os.MkdirAll(drop, 0o750)
	cfg := fmt.Sprintf(`{
	  "work_dir": "work", "key": "bundle.key", "source": "acq-zone-1",
	  "send": {"via": "dropdir", "to": "diode"},
	  "catalog_url": %q, "msrc_url": %q,
	  "microsoft": {"months": 2, "min_severity": "important",
	    "products": [{"msrc_product": "Windows 10 Version 22H2", "catalog_product": "Windows 10 Version 22H2", "arch": "x64", "min_build": 19045, "max_build": 19045}]},
	  "apps": [{"name": "acme-agent", "title": "Acme Endpoint Agent", "vendor": "Acme", "kind": "msi",
	    "product_code": "{11111111-2222-3333-4444-555555555555}", "arch": "x64", "severity": "important",
	    "version": {"url": "%s/vendor/latest.json", "json_path": "releases.0.version"},
	    "download_url": "%s/vendor/acme-agent-{version}.msi",
	    "sha256": {"url": "%s/vendor/SHA256SUMS-{version}"}}]
	}`, srv.URL, srv.URL, srv.URL, srv.URL, srv.URL)
	cfgPath := filepath.Join(dir, "acquire.json")
	os.WriteFile(cfgPath, []byte(cfg), 0o600)
	ctx := context.Background()

	// Dry run: lists, downloads nothing.
	rep, err := runAuto(ctx, cfgPath, true)
	if err != nil || len(rep.New) != 2 {
		t.Fatalf("dry run: %v %+v", err, rep)
	}
	if ents, _ := os.ReadDir(drop); len(ents) != 0 {
		t.Fatal("dry run sent something")
	}

	// Run 1: CU + app → one bundle, sent with a signed receipt.
	rep, err = runAuto(ctx, cfgPath, false)
	if err != nil || !rep.Sent || len(rep.New) != 2 || len(rep.Failures) != 0 {
		t.Fatalf("run 1: %v %+v", err, rep)
	}
	want := map[string]bool{"KB5126657-x64": true, "acme-agent-2.3.0": true}
	for _, id := range rep.New {
		delete(want, id)
	}
	if len(want) != 0 {
		t.Fatalf("missing packages: %v (got %v)", want, rep.New)
	}
	bundles, _ := filepath.Glob(filepath.Join(drop, "*.pmb"))
	receipts, _ := filepath.Glob(filepath.Join(drop, "*.receipt.json"))
	if len(bundles) != 1 || len(receipts) != 1 {
		t.Fatalf("expected 1 bundle + 1 receipt in the drop dir, got %d + %d", len(bundles), len(receipts))
	}
	statuses, _ := filepath.Glob(filepath.Join(drop, "*.status.json"))
	if len(statuses) != 1 || !rep.StatusSent {
		t.Fatalf("each real run should send a signed status report (dry runs none): %d", len(statuses))
	}
	ex, err := manifest.ExtractSafe(bundles[0], t.TempDir(), manifest.Limits{MaxFiles: 10})
	if err != nil {
		t.Fatal(err)
	}
	if err := manifest.Verify(pub, ex.ManifestBytes, ex.Signature); err != nil {
		t.Fatalf("bundle signature: %v", err)
	}
	m, _ := manifest.Parse(ex.ManifestBytes)
	if len(m.Packages) != 2 || m.Sequence != 1 {
		t.Fatalf("manifest: seq=%d pkgs=%d", m.Sequence, len(m.Packages))
	}

	// Run 2: nothing new → nothing sent.
	rep, err = runAuto(ctx, cfgPath, false)
	if err != nil || rep.Sent || len(rep.New) != 0 || rep.Skipped != 2 {
		t.Fatalf("run 2 should be a no-op: %v %+v", err, rep)
	}

	// Vendor ships 2.4.0 but the published checksum doesn't match the file:
	// refused, nothing sent, recorded for retry.
	bad := []byte("tampered 2.4.0")
	setApp("2.4.0", bad, []byte("what the vendor really published"))
	rep, _ = runAuto(ctx, cfgPath, false)
	if rep.Sent || rep.Failures["acme-agent"] == "" {
		t.Fatalf("checksum mismatch must be refused: %+v", rep)
	}
	// Vendor fixes it: next run picks it up as bundle sequence 2.
	setApp("2.4.0", []byte("good 2.4.0"), []byte("good 2.4.0"))
	os.Remove(filepath.Join(dir, "work", "downloads", "acme-agent-2.4.0.msi.part"))
	rep, err = runAuto(ctx, cfgPath, false)
	if err != nil || !rep.Sent || len(rep.New) != 1 || rep.New[0] != "acme-agent-2.4.0" {
		t.Fatalf("run after fix: %v %+v", err, rep)
	}
	var st autoState
	b, _ := os.ReadFile(filepath.Join(dir, "work", "state.json"))
	json.Unmarshal(b, &st)
	if len(st.Done) != 3 || len(st.Failed) != 0 {
		t.Fatalf("state: %+v", st)
	}

	// Overlapping runs are refused by the lock.
	os.WriteFile(filepath.Join(dir, "work", ".auto.lock"), []byte("1"), 0o600)
	if _, err := runAuto(ctx, cfgPath, false); err == nil || !strings.Contains(err.Error(), "in progress") {
		t.Fatalf("lock not enforced: %v", err)
	}
}

func TestAutoConfigRejectsUnverifiedApps(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.json")
	os.WriteFile(p, []byte(`{"work_dir":"w","key":"k","apps":[{"name":"x","title":"X","vendor":"V","kind":"msi",
	  "version":{"url":"https://v/x","regex":"(\\d+)"},"download_url":"https://v/x.msi"}]}`), 0o600)
	if _, err := loadAutoConfig(p); err == nil || !strings.Contains(err.Error(), "unverified") {
		t.Fatalf("app without checksum or signer accepted: %v", err)
	}
}

// The shipped example must keep parsing as the config schema evolves.
func TestAutoExampleConfigParses(t *testing.T) {
	c, err := loadAutoConfig("../../packaging/acquisition/acquire.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Microsoft.Products) != 3 || len(c.Apps) != 2 {
		t.Fatalf("%+v", c)
	}
}

func TestEvalPkgSignature(t *testing.T) {
	good := "Package \"GoogleChrome.pkg\":\n   Status: signed by a developer certificate issued by Apple for distribution\n   Notarization: trusted by the Apple notary service\n   Certificate Chain:\n    1. Developer ID Installer: Google LLC (EQHXZ8M8AV)\n       Expires: 2027\n    2. Developer ID Certification Authority\n    3. Apple Root CA\n"
	if err := evalPkgSignature(good, nil, "Developer ID Installer: Google LLC (EQHXZ8M8AV)"); err != nil {
		t.Fatal(err)
	}
	if err := evalPkgSignature(good, nil, "Developer ID Installer: Evil Corp"); err == nil {
		t.Fatal("wrong signer accepted")
	}
	if err := evalPkgSignature(strings.Replace(good, "Notarization: trusted by the Apple notary service", "", 1), nil, "Google LLC"); err == nil {
		t.Fatal("un-notarized package accepted")
	}
	if err := evalPkgSignature("Status: no signature\n", nil, "Google"); err == nil {
		t.Fatal("unsigned package accepted")
	}
}

// A real signed package on this Mac (if any) passes the live check.
func TestCheckPkgSignatureLive(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only")
	}
	// Our own unsigned test pkg must be refused.
	p := "../../demo/mac/offpatch-test-1.2.0.pkg"
	if _, err := os.Stat(p); err != nil {
		t.Skip("no local test pkg")
	}
	if err := checkPkgSignature(p, "offpatch"); err == nil {
		t.Fatal("unsigned pkg accepted")
	}
}
