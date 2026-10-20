package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"offpatch/internal/acqpolicy"
	"offpatch/internal/acqstatus"
	"offpatch/internal/acquire"
)

// acqpolicy.Known is offered in the console; the downloader must know how
// to find each in the catalog (acquire.DefaultWindowsProducts).
func TestKnownWindowsMatchesAcquireDefaults(t *testing.T) {
	def := acquire.DefaultWindowsProducts()
	if len(def) != len(acqpolicy.Known) {
		t.Fatalf("acqpolicy.Known has %d releases, acquire.DefaultWindowsProducts %d", len(acqpolicy.Known), len(def))
	}
	for _, d := range def {
		k, ok := acqpolicy.LookupKnown(d.Product, d.Build, d.Arch)
		if !ok || k.Server != d.Server {
			t.Errorf("%s %d %s missing or different in acqpolicy.Known", d.Product, d.Build, d.Arch)
		}
	}
}

func writePolicy(t *testing.T, dir string, version int, p acqpolicy.Policy) string {
	t.Helper()
	if err := p.Normalize(); err != nil {
		t.Fatal(err)
	}
	b, _ := json.MarshalIndent(acqpolicy.NewFile(version, "user:sam", "2026-10-16T02:00:00Z", p), "", "  ")
	os.MkdirAll(dir, 0o750)
	path := filepath.Join(dir, acqpolicy.FileName(version))
	if err := os.WriteFile(path, b, 0o640); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestApplyPolicyMerge(t *testing.T) {
	autoWarn = func(string) {}
	c := &autoConfig{Intel: &intelOpts{}, Apps: []autoApp{{Name: "acme-agent", WingetID: "Acme.Agent"}, {Name: "other"}},
		AllowedSourceHosts: []string{"default", "catalog.mirror.example", "*.bank.example", "vendor.example"}}
	c.Microsoft = &struct {
		Months      int          `json:"months"`
		MinSeverity string       `json:"min_severity"`
		Products    []autoMSProd `json:"products"`
	}{Months: 1, MinSeverity: "critical", Products: []autoMSProd{
		{MSRCProduct: "Windows 10 Version 22H2", Arch: "x64", MinBuild: 19045, MaxBuild: 19045},
		{MSRCProduct: "Windows Server 2019", Arch: "x64", MinBuild: 17763, MaxBuild: 17763},
	}}
	p := acqpolicy.Policy{
		Windows: []acqpolicy.Windows{
			{Product: "Windows 10 Version 22H2", Build: 19045, Arch: "x64", Classification: "all", Enabled: true},
			{Product: "Windows Server 2019", Build: 17763, Arch: "x64", Enabled: false},
			{Product: "Windows Server 2022", Build: 20348, Arch: "x64", Enabled: true},
		},
		Apps: []acqpolicy.App{
			{ID: "Google.Chrome", Arch: []string{"x64"}, Enabled: true},
			{ID: "Acme.Agent", Arch: []string{"x64"}, Enabled: false},
		},
		Sources: []acqpolicy.Source{
			{ID: "microsoft-catalog", Type: "microsoft-catalog", Enabled: true, URL: "https://catalog.mirror.example"},
			{ID: "mirror", Type: "internal-mirror", Enabled: true, URL: "https://mirror.bank.example/winget", Replaces: "winget-manifests"},
			{ID: "tool", Type: "vendor-url", Enabled: true, Name: "Tool", URL: "https://vendor.example/tool.msi", ExpectedSHA256: strings.Repeat("a", 64), Kind: "msi", Version: "1.0.0"},
		},
		Limits: acqpolicy.Limits{MaxDownloadGBPerRun: 2, KeepLastNVersions: 3},
	}
	p.Normalize()
	f := acqpolicy.NewFile(1, "user:sam", "2026-10-16T02:00:00Z", p)
	pr := &policyRun{file: &f}
	applyPolicy(c, pr)

	prods := c.Microsoft.Products
	if len(prods) != 2 || prods[0].MinSeverity != "low" || prods[1].MSRCProduct != "Windows Server 2022" ||
		prods[1].CatalogProduct != "Microsoft server operating system version 21H2" || prods[1].PackageSuffix != "-server" {
		t.Fatalf("microsoft products: %+v", prods)
	}
	if c.CatalogURL != "https://catalog.mirror.example" || c.WingetManifestsURL != "https://mirror.bank.example/winget" {
		t.Errorf("source overrides: %q %q", c.CatalogURL, c.WingetManifestsURL)
	}
	if len(c.Apps) != 1 || c.Apps[0].Name != "other" {
		t.Errorf("disabled app's acquire.json feed not removed: %+v", c.Apps)
	}
	if len(pr.apps) != 1 || pr.apps[0].ID != "Google.Chrome" || !slices.Contains(c.Intel.Library, "Google.Chrome") {
		t.Errorf("policy apps: %+v library %v", pr.apps, c.Intel.Library)
	}
	if len(pr.vendors) != 1 || pr.maxBytes != 2<<30 || pr.keepLastN != 3 {
		t.Errorf("vendors / limits: %+v %d %d", pr.vendors, pr.maxBytes, pr.keepLastN)
	}

	// Switching off the catalog (or MSRC) stops all Windows downloads.
	p.Sources[0].Enabled = false
	f = acqpolicy.NewFile(2, "user:sam", "2026-10-16T02:00:00Z", p)
	c2 := &autoConfig{Microsoft: c.Microsoft}
	pr = &policyRun{file: &f}
	applyPolicy(c2, pr)
	if c2.Microsoft != nil {
		t.Fatal("Microsoft downloads still on with the catalog source off")
	}
	for _, r := range pr.results {
		if r.Kind == "windows" && r.ID == "Windows Server 2022 20348 x64" && !strings.Contains(r.Detail, "microsoft-catalog") {
			t.Errorf("result: %+v", r)
		}
	}
}

// End to end in pmctl: a delivered policy is validated, kept as the active
// policy, archived, merged (vendor download, winget app via a mirror,
// Windows release switched off) and reported in the signed status report;
// a damaged file is refused and the previous version stays; a "run now"
// request turns a requests-only run into a full run.
func TestAutoPolicyApplied(t *testing.T) {
	e := newAutoEnv(t, `"requests": "requests", "allowed_source_hosts": ["default", "127.0.0.1"],`)
	wingetFixtures(t, e.srv, "g/Google/Chrome/155.0.8059.85/Google.Chrome.installer.yaml")
	tool := []byte("vendor tool 4.1 msi")
	sum := sha256.Sum256(tool)
	e.srv.Vendor["tool-4.1.0.msi"] = tool
	readMSICode = func(string) (string, error) { return "{22222222-3333-4444-5555-666666666666}", nil }
	t.Cleanup(func() { readMSICode = msiProductCode })
	// The vendor MSI is checked by Authenticode (stubbed) as on a Windows acquisition host (S-4).
	authenticodeAnywhere = true
	t.Cleanup(func() { authenticodeAnywhere = false })

	work := filepath.Join(e.dir, "work")
	os.MkdirAll(work, 0o750)
	// The Library (from an earlier intelligence run) knows Chrome's newest version.
	os.WriteFile(filepath.Join(work, "state.json"), []byte(`{"library": {"Google.Chrome@155.0.8059.85":
	  {"id": "Google.Chrome", "version": "155.0.8059.85", "installers": [], "resolved_at": "2026-10-15T00:00:00Z"}}}`), 0o600)

	reqDir := filepath.Join(e.dir, "requests")
	pol := acqpolicy.Policy{
		Windows: []acqpolicy.Windows{{Product: "Windows 10 Version 22H2", Build: 19045, Arch: "x64", Enabled: false}},
		Apps:    []acqpolicy.App{{ID: "Google.Chrome", Arch: []string{"x64"}, Enabled: true}},
		Sources: []acqpolicy.Source{
			{ID: "mirror", Type: "internal-mirror", Enabled: true, URL: e.srv.URL + "/vendor/manifests", Replaces: "winget-manifests"},
			{ID: "tool", Type: "vendor-url", Enabled: true, Name: "Vendor Tool", URL: e.srv.URL + "/vendor/tool-4.1.0.msi",
				ExpectedSHA256: hex.EncodeToString(sum[:]), Kind: "msi", Version: "4.1.0"},
		},
		Limits: acqpolicy.Limits{KeepLastNVersions: 2},
	}
	writePolicy(t, reqDir, 1, pol)
	ctx := context.Background()

	rep, err := runAuto(ctx, e.cfgPath, false)
	if err != nil || !rep.Sent {
		t.Fatalf("run 1: %v %+v", err, rep)
	}
	for _, id := range []string{"tool-4.1.0", "Google.Chrome-155.0.8059.85", "acme-agent-2.3.0"} {
		if !slices.Contains(rep.New, id) {
			t.Errorf("%s not fetched (new: %v, failures: %v)", id, rep.New, rep.Failures)
		}
	}
	if slices.ContainsFunc(rep.New, func(id string) bool { return strings.HasPrefix(id, "KB") }) {
		t.Errorf("Windows release switched off by the policy was fetched: %v", rep.New)
	}
	if rep.PolicyVersion != 1 || rep.PolicyAppliedAt == "" || rep.PolicyError != "" {
		t.Fatalf("policy in report: v%d at %q err %q", rep.PolicyVersion, rep.PolicyAppliedAt, rep.PolicyError)
	}
	if _, err := os.Stat(filepath.Join(reqDir, "done", acqpolicy.FileName(1))); err != nil {
		t.Errorf("policy file not archived: %v", err)
	}
	if _, err := os.Stat(filepath.Join(work, activePolicyFile)); err != nil {
		t.Errorf("active policy not kept: %v", err)
	}
	results := map[string]string{}
	for _, r := range rep.Sources {
		results[r.Kind+":"+r.ID] = r.Result
	}
	if results["source:tool"] != "new" || results["app:Google.Chrome"] != "new" || results["windows:Windows 10 Version 22H2 19045 x64"] != "disabled" ||
		results["source:mirror"] != "applied" {
		t.Errorf("source results: %v", results)
	}
	if st := e.state(); st.Families["tool-4.1.0"] != "vendor:tool" {
		t.Errorf("families: %v", st.Families)
	}

	// The signed status report carries the policy version, results and acquire.json defaults.
	sr := lastStatus(t, e)
	if sr.PolicyVersion != 1 || sr.PolicySHA256 == "" || len(sr.Sources) == 0 || sr.Defaults == nil || len(sr.Defaults.Policy.Windows) != 1 {
		t.Fatalf("status report: v%d sha %q sources %d defaults %+v", sr.PolicyVersion, sr.PolicySHA256, len(sr.Sources), sr.Defaults)
	}

	// Next run: the policy stays in force without the file; nothing new.
	rep, err = runAuto(ctx, e.cfgPath, false)
	if err != nil || rep.PolicyVersion != 1 || len(rep.New) != 0 {
		t.Fatalf("run 2: %v v%d new %v", err, rep.PolicyVersion, rep.New)
	}

	// A damaged version 2 is refused; version 1 stays.
	p2 := writePolicy(t, reqDir, 2, pol)
	b, _ := os.ReadFile(p2)
	os.WriteFile(p2, []byte(strings.Replace(string(b), "Vendor Tool", "Evil Tool", 1)), 0o640)
	rep, err = runAuto(ctx, e.cfgPath, false)
	if err != nil || rep.PolicyVersion != 1 || !strings.Contains(rep.PolicyError, "sha256") {
		t.Fatalf("damaged policy: %v v%d %q", err, rep.PolicyVersion, rep.PolicyError)
	}
	if _, err := os.Stat(filepath.Join(reqDir, "rejected", acqpolicy.FileName(2))); err != nil {
		t.Errorf("damaged policy not moved to rejected/: %v", err)
	}

	// "Run now": a requests-only run becomes a full run.
	rr, _ := json.Marshal(acqpolicy.RunRequest{Format: acqpolicy.RunFormat, Version: acqpolicy.RunVersion, RunID: "run-20261016T030000Z-abc",
		RequestedBy: "user:sam", RequestedAt: "2026-10-16T03:00:00Z"})
	os.WriteFile(filepath.Join(reqDir, "run-20261016T030000Z-abc.json"), rr, 0o640)
	rep, err = runAutoRequests(ctx, e.cfgPath, false, "", true)
	if err != nil || rep.RunRequest != "run-20261016T030000Z-abc" {
		t.Fatalf("run now: %v %+v", err, rep)
	}
	if !slices.ContainsFunc(rep.Feeds, func(f acqstatus.Feed) bool { return f.Type == "app" && f.Name == "acme-agent" }) {
		t.Errorf("run now did not run the full acquisition: feeds %+v", rep.Feeds)
	}
	if _, err := os.Stat(filepath.Join(reqDir, "done", "run-20261016T030000Z-abc.json")); err != nil {
		t.Errorf("run request not archived: %v", err)
	}
}

func lastStatus(t *testing.T, e *autoEnv) acqstatus.Report {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(e.drop, "*"+acqstatus.FileSuffix))
	slices.Sort(files)
	if len(files) == 0 {
		t.Fatal("no status report sent")
	}
	b, err := os.ReadFile(files[len(files)-1])
	if err != nil {
		t.Fatal(err)
	}
	var s acqstatus.Signed
	json.Unmarshal(b, &s)
	k, _ := openSigner(filepath.Join(e.dir, "bundle.key"), "")
	r, err := acqstatus.Verify(s, map[string]ed25519.PublicKey{k.KeyID(): e.pub})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

type fixedBody struct{ n int }

func (f *fixedBody) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", f.n)))}, nil
}

func TestDownloadBudget(t *testing.T) {
	hc := withBudget(&http.Client{Transport: &fixedBody{n: 10}}, 15)
	get := func() error {
		resp, err := hc.Get("https://example.invalid/")
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		_, err = io.ReadAll(resp.Body)
		return err
	}
	if err := get(); err != nil {
		t.Fatalf("first download within the limit: %v", err)
	}
	if err := get(); !errors.Is(err, errDownloadLimit) {
		t.Fatalf("second download: %v", err)
	}
	if err := get(); !errors.Is(err, errDownloadLimit) {
		t.Fatalf("after the limit: %v", err)
	}
	if c := withBudget(http.DefaultClient, 0); c != http.DefaultClient {
		t.Error("no limit must not wrap the client")
	}
}

func TestPruneOldVersions(t *testing.T) {
	dir := t.TempDir()
	st := autoState{Done: map[string]autoDone{}, Families: map[string]string{}}
	for i, v := range []string{"1.0.0", "1.1.0", "1.2.0"} {
		id := "tool-" + v
		os.WriteFile(filepath.Join(dir, id+".msi"), []byte("x"), 0o640)
		st.Done[id] = autoDone{File: id + ".msi", SentAt: "2026-10-1" + string(rune('0'+i)) + "T00:00:00Z"}
		st.Families[id] = "vendor:tool"
	}
	os.WriteFile(filepath.Join(dir, "other.msi"), []byte("x"), 0o640)
	st.Done["other"] = autoDone{File: "other.msi", SentAt: "2026-01-01T00:00:00Z"}
	pruneOldVersions(dir, st, map[string]bool{}, 2, func(err error) { t.Error(err) })
	for name, want := range map[string]bool{"tool-1.0.0.msi": false, "tool-1.1.0.msi": true, "tool-1.2.0.msi": true, "other.msi": true} {
		_, err := os.Stat(filepath.Join(dir, name))
		if (err == nil) != want {
			t.Errorf("%s kept=%v, want %v", name, err == nil, want)
		}
	}
}
