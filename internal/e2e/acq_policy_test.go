package e2e

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"offpatch/internal/acqpolicy"
	"offpatch/internal/acqstatus"
	"offpatch/internal/store"
)

type policyGet struct {
	Version       int              `json:"version"`
	IsDefault     bool             `json:"is_default"`
	DefaultSource string           `json:"default_source"`
	Banner        string           `json:"banner"`
	SHA256        string           `json:"sha256"`
	Policy        acqpolicy.Policy `json:"policy"`
	Delivery      struct {
		Direct bool `json:"direct"`
	} `json:"delivery"`
	Choices    []acqpolicy.KnownWindows `json:"windows_choices"`
	Downloader *struct {
		PolicyVersion   int                      `json:"policy_version"`
		PolicyAppliedAt string                   `json:"policy_applied_at"`
		Sources         []acqstatus.SourceResult `json:"sources"`
		Schedule        string                   `json:"schedule"`
	} `json:"downloader"`
	LastRun *struct {
		RunID string `json:"run_id"`
	} `json:"last_run_request"`
}

// Only the super admin reads or changes the auto-download policy.
func TestAcqPolicyPermissions(t *testing.T) {
	e := newEnv(t)
	t.Setenv("OFFPATCH_ACQUIRE_CONFIG", filepath.Join(t.TempDir(), "missing.json"))
	for _, tok := range []string{tokViewer, tokOperator, tokApprover, tokAdmin} {
		for _, c := range []struct{ method, path string }{
			{"GET", "/api/acquisition/policy"}, {"PUT", "/api/acquisition/policy"}, {"GET", "/api/acquisition/policy/history"},
			{"GET", "/api/acquisition/policy/file"}, {"POST", "/api/acquisition/policy/queue"}, {"POST", "/api/acquisition/run"},
		} {
			if code := e.api(c.method, c.path, tok, acqpolicy.Empty(), nil); code != 403 {
				t.Errorf("%s %s as %s: %d, want 403", c.method, c.path, tok, code)
			}
		}
	}
	var g policyGet
	if c := e.api("GET", "/api/acquisition/policy", tokSuper, nil, &g); c != 200 || !g.IsDefault || g.DefaultSource != "none" || g.Banner == "" || g.Delivery.Direct {
		t.Fatalf("defaults: %d %+v", c, g)
	}
	if len(g.Choices) < len(acqpolicy.Known) {
		t.Errorf("windows choices: %d", len(g.Choices))
	}
	// No hand-off folder (two machines): run now is refused with a plain reason, the file can still be downloaded once saved.
	if c := e.api("POST", "/api/acquisition/run", tokSuper, map[string]any{}, nil); c != 409 {
		t.Errorf("run now without acquisition_requests_dir: %d", c)
	}
	if c := e.api("GET", "/api/acquisition/policy/file", tokSuper, nil, nil); c != 404 {
		t.Errorf("file before any save: %d", c)
	}
	var saved struct {
		Version  int    `json:"version"`
		QueuedTo string `json:"queued_to"`
	}
	if c := e.api("PUT", "/api/acquisition/policy?base_version=0", tokSuper, acqpolicy.Empty(), &saved); c != 200 || saved.Version != 1 || saved.QueuedTo != "" {
		t.Fatalf("save: %d %+v", c, saved)
	}
	var f acqpolicy.File
	if c := e.api("GET", "/api/acquisition/policy/file", tokSuper, nil, &f); c != 200 || f.Validate() != nil || f.PolicyVersion != 1 {
		t.Fatalf("carried file: %d %+v %v", c, f, f.Validate())
	}
}

// Save → the file lands in acquisition_requests_dir as pmctl reads it →
// the downloader's status report says it applied that version.
func TestAcqPolicySaveDeliverApply(t *testing.T) {
	dir := t.TempDir()
	acqCfg := filepath.Join(t.TempDir(), "acquire.json")
	os.WriteFile(acqCfg, []byte(`{"microsoft": {"min_severity": "critical", "products": [
	  {"msrc_product": "Windows 11 Version 24H2", "arch": "x64", "min_build": 26100, "max_build": 26100}]}, "apps": []}`), 0o640)
	t.Setenv("OFFPATCH_ACQUIRE_CONFIG", acqCfg)
	p, _ := json.Marshal(dir)
	e := newEnvOpts(t, false, `"acquisition_requests_dir": `+string(p)+`,`)

	var g policyGet
	if c := e.api("GET", "/api/acquisition/policy", tokSuper, nil, &g); c != 200 || !g.IsDefault || g.DefaultSource != "acquire.json" || !g.Delivery.Direct {
		t.Fatalf("get: %d %+v", c, g)
	}
	if len(g.Policy.Windows) != 1 || g.Policy.Windows[0].Product != "Windows 11 Version 24H2" || len(g.Policy.Sources) != 3 {
		t.Fatalf("imported from acquire.json: %+v", g.Policy)
	}

	pol := g.Policy
	pol.Apps = []acqpolicy.App{{ID: "Google.Chrome", Arch: []string{"x64"}, Enabled: true}}
	pol.Sources = append(pol.Sources, acqpolicy.Source{ID: "tool", Type: "vendor-url", Enabled: true, AddedBy: "someone-else", Name: "Tool",
		URL: "http://vendor.example/tool.msi", ExpectedSHA256: strings.Repeat("a", 64), Kind: "msi", Version: "1.0.0"})
	if c := e.api("PUT", "/api/acquisition/policy?base_version=0", tokSuper, pol, nil); c != 400 {
		t.Fatalf("http URL accepted: %d", c)
	}
	pol.Sources[3].URL = "https://vendor.example/tool.msi"
	var saved struct {
		Version  int              `json:"version"`
		SHA256   string           `json:"sha256"`
		Summary  []string         `json:"summary"`
		Policy   acqpolicy.Policy `json:"policy"`
		QueuedTo string           `json:"queued_to"`
	}
	if c := e.api("PUT", "/api/acquisition/policy?base_version=0", tokSuper, pol, &saved); c != 200 || saved.Version != 1 || saved.QueuedTo != dir {
		t.Fatalf("save: %d %+v", c, saved)
	}
	if by := saved.Policy.Sources[3].AddedBy; !strings.HasPrefix(by, "user:") || by == "someone-else" {
		t.Errorf("added_by taken from the browser: %q", by)
	}
	if strings.Join(saved.Summary, ";") != "added app Google.Chrome;added source tool (vendor-url)" {
		t.Errorf("summary: %v", saved.Summary)
	}
	// A second editor who loaded version 0 gets a conflict.
	if c := e.api("PUT", "/api/acquisition/policy?base_version=0", tokSuper, pol, nil); c != 409 {
		t.Fatalf("stale save: %d", c)
	}

	// Delivered exactly as pmctl parses it.
	path := filepath.Join(dir, acqpolicy.FileName(1))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("not queued: %v", err)
	}
	f, err := acqpolicy.ParseFile(bytes.NewReader(b))
	if err != nil || f.PolicyVersion != 1 || f.SHA256 != saved.SHA256 || len(f.Policy.Apps) != 1 {
		t.Fatalf("queued policy: %v %+v", err, f)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(path); st.Mode().Perm() != 0o640 {
			t.Errorf("mode %v, want 0640", st.Mode().Perm())
		}
	}

	// Run now: a run request the downloader parses.
	var run struct {
		RunID string `json:"run_id"`
	}
	if c := e.api("POST", "/api/acquisition/run", tokSuper, map[string]any{}, &run); c != 200 || !strings.HasPrefix(run.RunID, "run-") {
		t.Fatalf("run now: %d %+v", c, run)
	}
	rb, err := os.ReadFile(filepath.Join(dir, run.RunID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acqpolicy.ParseRun(bytes.NewReader(rb)); err != nil {
		t.Fatalf("run request: %v", err)
	}

	// The downloader applies it (pmctl's side is tested in cmd/pmctl) and reports so.
	now := time.Now().UTC()
	e.dropStatus(acqstatus.Report{Source: "acq-zone-1", Host: "acq01", Schedule: "hourly (systemd timer)", StartedAt: now.Add(-time.Minute).Format(time.RFC3339),
		FinishedAt: now.Format(time.RFC3339), Outcome: "ok", New: []string{}, Failures: map[string]string{}, Feeds: []acqstatus.Feed{},
		PolicyVersion: f.PolicyVersion, PolicySHA256: f.SHA256, PolicyEditedBy: f.EditedBy, PolicyAppliedAt: now.Format(time.RFC3339), RunRequest: run.RunID,
		Sources: []acqstatus.SourceResult{{Kind: "source", ID: "tool", Type: "vendor-url", Result: "new", Packages: []string{"tool-1.0.0"}}}}, nil)
	g = policyGet{}
	if c := e.api("GET", "/api/acquisition/policy", tokSuper, nil, &g); c != 200 || g.IsDefault || g.Version != 1 {
		t.Fatalf("get after save: %d %+v", c, g)
	}
	if g.Downloader == nil || g.Downloader.PolicyVersion != 1 || g.Downloader.PolicyAppliedAt == "" || len(g.Downloader.Sources) != 1 ||
		g.Downloader.Schedule != "hourly (systemd timer)" || g.LastRun == nil || g.LastRun.RunID != run.RunID {
		t.Fatalf("downloader view: %+v last run %+v", g.Downloader, g.LastRun)
	}

	var hist []store.AcqPolicyVersion
	if c := e.api("GET", "/api/acquisition/policy/history", tokSuper, nil, &hist); c != 200 || len(hist) != 1 || hist[0].Version != 1 {
		t.Fatalf("history: %d %+v", c, hist)
	}
	var audit []store.AuditEvent
	e.api("GET", "/api/audit", tokViewer, nil, &audit)
	seen := map[string]bool{}
	for _, ev := range audit {
		seen[ev.Action] = true
	}
	for _, a := range []string{"acquisition.policy_updated", "acquisition.policy_queued", "acquisition.run_requested"} {
		if !seen[a] {
			t.Errorf("%s not audited", a)
		}
	}
}

// The downloader's report of acquire.json is the starting policy when the
// server cannot read acquire.json itself (it belongs to the acquisition user).
func TestAcqPolicyDefaultsFromDownloader(t *testing.T) {
	e := newEnv(t)
	t.Setenv("OFFPATCH_ACQUIRE_CONFIG", filepath.Join(t.TempDir(), "missing.json"))
	base, err := acqpolicy.FromAcquireJSON([]byte(`{"microsoft": {"products": [{"msrc_product": "Windows 10 Version 22H2", "arch": "x64", "min_build": 19045, "max_build": 19045}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	e.dropStatus(acqstatus.Report{Source: "acq-zone-1", Host: "acq01", StartedAt: now.Add(-time.Minute).Format(time.RFC3339), FinishedAt: now.Format(time.RFC3339),
		Outcome: "ok", New: []string{}, Failures: map[string]string{}, Feeds: []acqstatus.Feed{}, Defaults: &base}, nil)
	var g policyGet
	if c := e.api("GET", "/api/acquisition/policy", tokSuper, nil, &g); c != 200 || g.DefaultSource != "downloader" || g.Banner != "" ||
		len(g.Policy.Windows) != 1 || g.Policy.Windows[0].Build != 19045 {
		t.Fatalf("defaults from the downloader: %d %+v", c, g)
	}
}
