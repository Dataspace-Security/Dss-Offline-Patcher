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
	"strings"
	"testing"
	"time"

	"offpatch/internal/acqrequest"
	"offpatch/internal/acquire/acquiretest"
	"offpatch/internal/manifest"
)

// wingetFixtures serves the recorded winget-pkgs manifests from the fake
// vendor host, with each installer URL pointed at the fake and its
// InstallerSha256 replaced by the hash of a small synthetic payload.
func wingetFixtures(t *testing.T, srv *acquiretest.Server, rels ...string) {
	t.Helper()
	root := "../../internal/acquire/testdata/winget"
	for _, rel := range rels {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, line := range strings.Split(string(b), "\n") {
			trim := strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(trim, "InstallerUrl: https://"):
				orig := strings.TrimPrefix(trim, "InstallerUrl: ")
				name := "dl/" + filepath.Base(orig)
				body := []byte("synthetic installer " + orig)
				srv.Vendor[name] = body
				sum := sha256.Sum256(body)
				indent := line[:len(line)-len(strings.TrimLeft(line, " "))]
				out = append(out, indent+"InstallerUrl: "+srv.URL+"/vendor/"+name, indent+"InstallerSha256: "+strings.ToUpper(hex.EncodeToString(sum[:])))
			case strings.HasPrefix(trim, "InstallerSha256:"):
				// replaced together with the URL above
			default:
				out = append(out, line)
			}
		}
		srv.Vendor["manifests/"+rel] = []byte(strings.Join(out, "\n"))
	}
}

func writeRequest(t *testing.T, dir, name string, r acqrequest.Request) {
	t.Helper()
	r.Format, r.Version = acqrequest.Format, acqrequest.Version
	if r.RequestID == "" {
		r.RequestID = strings.TrimSuffix(name, ".json")
	}
	r.CreatedAt, r.CreatedBy = "2026-10-17T08:00:00Z", "user:otto"
	b, _ := json.MarshalIndent(r, "", "  ")
	os.MkdirAll(dir, 0o750)
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o640); err != nil {
		t.Fatal(err)
	}
}

// TestAutoAcquisitionRequests: a request exported by the console is turned
// into MSI and KB packages in one signed bundle; EXE-only and unknown
// packages are warnings; the request moves to done/ once sent, a request
// with a failed item stays for the next run, and garbage is rejected.
func TestAutoAcquisitionRequests(t *testing.T) {
	stubAuthenticode(t)
	srv := acquiretest.New(t, "../../internal/acquire/testdata", acquiretest.Payload(50_000))
	wingetFixtures(t, srv,
		"g/Google/Chrome/155.0.8059.85/Google.Chrome.installer.yaml",
		"7/7zip/7zip/26.04/7zip.7zip.installer.yaml",
		"m/Microsoft/VisualStudioCode/1.142.0/Microsoft.VisualStudioCode.installer.yaml")

	oldHTTP, oldNow, oldAvail := autoHTTP, autoNow, msiCodeAvailable
	autoHTTP = func() *http.Client { return srv.Client() }
	autoNow = func() time.Time { return time.Date(2026, 10, 17, 3, 0, 0, 0, time.UTC) }
	msiCodeAvailable = false
	t.Cleanup(func() { autoHTTP, autoNow, msiCodeAvailable = oldHTTP, oldNow, oldAvail })

	dir := t.TempDir()
	pub, priv, _ := manifest.GenerateKey()
	os.WriteFile(filepath.Join(dir, "bundle.key"), manifest.EncodePrivate(priv), 0o600)
	drop := filepath.Join(dir, "diode")
	os.MkdirAll(drop, 0o750)
	cfg := fmt.Sprintf(`{"work_dir": "work", "key": "bundle.key", "source": "acq-zone-1",
	  "send": {"via": "dropdir", "to": "diode"}, "requests": "requests",
	  "catalog_url": %q, "msrc_url": %q, "winget_manifests_url": %q}`, srv.URL, srv.URL, srv.URL+"/vendor/manifests")
	cfgPath := filepath.Join(dir, "acquire.json")
	os.WriteFile(cfgPath, []byte(cfg), 0o600)
	reqDir := filepath.Join(dir, "requests")
	req := acqrequest.Request{
		Apps: []acqrequest.App{
			{WingetID: "Google.Chrome", Name: "Google Chrome", Version: "155.0.8059.85", Architectures: []string{"x64"}, Endpoints: 2,
				Installed: []acqrequest.Installed{{ProductCode: "{0228B730-26AA-39E9-B2E1-0FC0E3EA58C8}", Name: "Google Chrome", Version: "155.0.8059.82"}}},
			{WingetID: "7zip.7zip", Name: "7-Zip", Version: "26.04", Architectures: []string{"x64"}, Endpoints: 1,
				Installed: []acqrequest.Installed{{ProductCode: "{23170F69-40C1-2702-2603-000001000000}", Name: "7-Zip 26.03 (x64 edition)", Version: "26.03.00.0"}}},
			{WingetID: "Microsoft.VisualStudioCode", Name: "Microsoft Visual Studio Code", Version: "1.142.0", Architectures: []string{"x64"}, Endpoints: 1},
			{WingetID: "Contoso.Gone", Version: "1.0", Architectures: []string{"x64"}, Endpoints: 1},
		},
		KBs: []acqrequest.KB{{KB: acquiretest.KB, Product: "Windows 10 Version 22H2", Title: acquiretest.Title, Build: 19045, Arch: "x64", Endpoints: 3}},
	}
	writeRequest(t, reqDir, "acq-request-1.json", req)
	os.WriteFile(filepath.Join(reqDir, "notes.json"), []byte(`{"hello": "world"}`), 0o640)
	ctx := context.Background()

	// Dry run: lists the candidates, fetches and moves nothing.
	rep, err := runAuto(ctx, cfgPath, true)
	if err != nil || len(rep.New) != 5 {
		t.Fatalf("dry run: %v %+v", err, rep)
	}
	if _, err := os.Stat(filepath.Join(reqDir, "acq-request-1.json")); err != nil {
		t.Fatal("dry run moved the request")
	}

	rep, err = runAuto(ctx, cfgPath, false)
	if err != nil || !rep.Sent || len(rep.Failures) != 0 {
		t.Fatalf("run 1: %v %+v", err, rep)
	}
	want := map[string]bool{"Google.Chrome-155.0.8059.85": true, "7zip.7zip-26.04": true, "KB5126657-x64": true}
	if len(rep.New) != len(want) {
		t.Fatalf("new: %v", rep.New)
	}
	for _, id := range rep.New {
		if !want[id] {
			t.Fatalf("unexpected package %s (new: %v)", id, rep.New)
		}
	}
	warnings := strings.Join(rep.Warnings, "\n")
	for _, w := range []string{"Microsoft.VisualStudioCode-1.142.0 skipped", "only inno", "Contoso.Gone-1.0 skipped", "not in the winget repository", "notes.json rejected"} {
		if !strings.Contains(warnings, w) {
			t.Errorf("warning %q missing in:\n%s", w, warnings)
		}
	}
	var feed bool
	for _, f := range rep.Feeds {
		if f.Type == "request" && f.Name == "acq-request-1" && f.Status == "new" {
			feed = true
		}
	}
	if !feed {
		t.Errorf("no request feed: %+v", rep.Feeds)
	}
	if _, err := os.Stat(filepath.Join(reqDir, "done", "acq-request-1.json")); err != nil {
		t.Errorf("request not archived: %v", err)
	}
	if _, err := os.Stat(filepath.Join(reqDir, "rejected", "notes.json")); err != nil {
		t.Errorf("invalid request not rejected: %v", err)
	}

	// The bundle carries the MSIs with the manifest's product code, the
	// Apps & features name endpoints are matched on, and the KB.
	bundles, _ := filepath.Glob(filepath.Join(drop, "*.pmb"))
	if len(bundles) != 1 {
		t.Fatalf("bundles: %v", bundles)
	}
	ex, err := manifest.ExtractSafe(bundles[0], t.TempDir(), manifest.Limits{MaxFiles: 10})
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
	pk := map[string]manifest.Package{}
	for _, p := range m.Packages {
		pk[p.PackageID] = p
	}
	ch, sz, kb := pk["Google.Chrome-155.0.8059.85"], pk["7zip.7zip-26.04"], pk["KB5126657-x64"]
	if ch.Kind != "msi" || ch.ProductCode != "{0228B730-26AA-39E9-B2E1-0FC0E3EA58C8}" || ch.PackageName != "Google Chrome" || ch.Version != "155.0.8059.85" ||
		ch.Applicability.Arch != "x64" || ch.Vendor != "Google" || ch.ReleaseDate != "2026-10-15" || !strings.HasSuffix(ch.SourceURL, "googlechromestandaloneenterprise64.msi") {
		t.Errorf("chrome package: %+v", ch)
	}
	// The installed name carries a version, so the winget name is used.
	if sz.Kind != "msi" || sz.ProductCode != "{23170F69-40C1-2702-2604-000001000000}" || sz.PackageName != "7-Zip" {
		t.Errorf("7-zip package: %+v", sz)
	}
	if kb.Kind != "msu" || kb.KB != acquiretest.KB {
		t.Errorf("kb package: %+v", kb)
	}

	// The same request again: everything was sent already, nothing new.
	writeRequest(t, reqDir, "acq-request-1.json", req)
	rep, err = runAuto(ctx, cfgPath, false)
	if err != nil || rep.Sent || len(rep.New) != 0 || rep.Skipped != 3 {
		t.Fatalf("repeat: %v %+v", err, rep)
	}
	if ents, _ := os.ReadDir(filepath.Join(reqDir, "done")); len(ents) != 2 {
		t.Errorf("repeat request not archived next to the first: %d", len(ents))
	}

	// An installer that does not match its manifest hash fails; the request
	// stays for the next run.
	srv.Vendor["dl/googlechromestandaloneenterprise.msi"] = []byte("tampered")
	req2 := acqrequest.Request{Apps: []acqrequest.App{{WingetID: "Google.Chrome", Version: "155.0.8059.85", Architectures: []string{"x86"}, Endpoints: 1}}}
	writeRequest(t, reqDir, "acq-request-2.json", req2)
	rep, _ = runAuto(ctx, cfgPath, false)
	if rep.Failures["Google.Chrome-155.0.8059.85-x86"] == "" || rep.Sent {
		t.Fatalf("hash mismatch must fail: %+v", rep)
	}
	if _, err := os.Stat(filepath.Join(reqDir, "acq-request-2.json")); err != nil {
		t.Fatal("request with a failed item was archived")
	}
}

func TestWingetPackageID(t *testing.T) {
	if got := wingetPackageID("Google.Chrome", "155.0.8059.85", "arm64"); got != "Google.Chrome-155.0.8059.85-arm64" {
		t.Errorf("got %q", got)
	}
	// Replaced characters add a hash, so Foo+Bar and Foo-Bar never share an id.
	a, b := wingetPackageID("Foo+Bar.App", "1.0", "x64"), wingetPackageID("Foo-Bar.App", "1.0", "x64")
	if a == b || !strings.HasPrefix(a, "Foo-Bar.App-1.0-") || b != "Foo-Bar.App-1.0" {
		t.Errorf("collision: %q %q", a, b)
	}
	long := wingetPackageID(strings.Repeat("a", 32)+"."+strings.Repeat("b", 32), "1.2.3", "x64")
	if len(long) != 64 || !strings.HasPrefix(long, strings.Repeat("a", 32)) {
		t.Errorf("long id %q (%d)", long, len(long))
	}
}
