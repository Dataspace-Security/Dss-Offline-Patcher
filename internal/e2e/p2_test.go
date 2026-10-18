package e2e

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"offpatch/internal/acqrequest"
	"offpatch/internal/agent"
	"offpatch/internal/intel"
	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

// P2 through the API (store-level detail in internal/store/p2_test.go).

type libItem struct {
	Kind          string `json:"kind"`
	ID            string `json:"id"`
	Name          string `json:"name"`
	Publisher     string `json:"publisher"`
	LatestVersion string `json:"latest_version"`
	Description   string `json:"description"`
	Links         struct {
		Homepage     string `json:"homepage"`
		PublisherURL string `json:"publisher_url"`
		Manifest     string `json:"manifest"`
	} `json:"links"`
	Installers []struct {
		Arch string `json:"arch"`
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"installers"`
	Importable       string `json:"importable"`
	ImportableReason string `json:"importable_reason"`
	Installed        struct {
		Endpoints int `json:"endpoints"`
		Outdated  int `json:"outdated"`
	} `json:"installed"`
	Catalog   *struct{ PackageID, State string } `json:"catalog"`
	Requested *store.AcqRequestRef               `json:"requested"`
	Endpoints []struct {
		EndpointID       string `json:"endpoint_id"`
		Hostname         string `json:"hostname"`
		InstalledVersion string `json:"installed_version"`
		Outdated         bool   `json:"outdated"`
	} `json:"endpoints"`
}

type libPage struct {
	Source      string    `json:"source"`
	GeneratedAt string    `json:"generated_at"`
	Total       int       `json:"total"`
	Page        int       `json:"page"`
	PerPage     int       `json:"per_page"`
	Items       []libItem `json:"items"`
}

func libIDs(p libPage) string {
	var ids []string
	for _, it := range p.Items {
		ids = append(ids, it.ID)
	}
	return strings.Join(ids, ",")
}

// A: the Library lists the intelligence with importable, installed,
// catalog and request state; only safe https links; detail with endpoints;
// Import of an app installed nowhere (app_archs) and of a KB no endpoint
// needs.
func TestLibrary(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	var empty libPage
	if c := e.api("GET", "/api/library", tokViewer, nil, &empty); c != 200 || empty.Total != 0 || empty.Items == nil {
		t.Fatalf("no intel: %d %+v", c, empty)
	}
	if c := e.api("GET", "/api/library", "", nil, nil); c != 401 {
		t.Fatalf("anonymous: %d", c)
	}
	a := e.enroll("pc-lib-01", []string{"pilot"}, agent.SimConfig{})
	if _, err := e.st.Checkin(ctx, a.id, store.CheckinRequest{Hostname: "pc-lib-01", OSVersion: "Windows 11 Pro 24H2 (26100.2000)", Build: 26100, Arch: "x64",
		Inventory: []store.InventoryItem{{Kind: "product", ID: "{0228B730-26AA-39E9-B2E1-0FC0E3EA58C8}", Name: "Google Chrome", Version: "155.0.8059.82"}}}); err != nil {
		t.Fatal(err)
	}
	gen := time.Now().UTC().Add(-time.Hour).Truncate(time.Second).Format(time.RFC3339)
	long := "https://example.com/" + strings.Repeat("a", 2100)
	e.dropIntel(intel.Doc{Source: "acq-zone-1", GeneratedAt: gen,
		Windows: []intel.WindowsRelease{{Product: "Windows 11 Version 21H2", Build: 22000, Arch: "x64", KB: "KB5044280", UBR: 3260, ReleaseDate: "2026-10-08",
			Title: "2026-10 Cumulative Update for Windows 11 (KB5044280)"}},
		Apps: []intel.App{
			{ID: "Google.Chrome", Name: "Google Chrome", Version: "155.0.8059.85", Codes: []string{"{0228b730-26aa-39e9-b2e1-0fc0e3ea58c8}"}, Names: []string{"googlechrome"}, Publishers: []string{"Google LLC"}},
			{ID: "7zip.7zip", Name: "7-Zip", Version: "26.04", Publishers: []string{"Igor Pavlov"}},
			{ID: "Notepad++.Notepad++", Name: "Notepad++", Version: "8.7"},
			{ID: "VideoLAN.VLC", Name: "VLC media player", Version: "3.0.24"},
			{ID: "Evil.App", Name: "Evil‮ App\x07", Version: "1.0"},
		},
		Resolved: []intel.Resolved{
			{ID: "Google.Chrome", Version: "155.0.8059.85", Publisher: "Google LLC", Homepage: "https://www.google.com/chrome/", ResolvedAt: gen,
				Installers: []intel.ResolvedInstaller{{Arch: "x64", Type: "wix", Scope: "machine", URL: "https://dl.google.com/chrome.msi", SHA256: strings.Repeat("A", 64), ProductCode: "{11111111-2222-3333-4444-555555555555}"}}},
			{ID: "7zip.7zip", Version: "26.04", Publisher: "Igor Pavlov", Homepage: "https://www.7-zip.org/", License: "LGPL", Description: "File archiver", ResolvedAt: gen,
				Installers: []intel.ResolvedInstaller{{Arch: "x64", Type: "msi", URL: "https://www.7-zip.org/a/7z2604-x64.msi"}, {Arch: "arm64", Type: "exe", URL: "https://www.7-zip.org/a/7z2604-arm64.exe"}}},
			{ID: "Notepad++.Notepad++", Version: "8.7", Publisher: "Notepad++ Team", ResolvedAt: gen,
				Installers: []intel.ResolvedInstaller{{Arch: "x64", Type: "nullsoft", URL: "https://github.com/notepad-plus-plus/npp.exe"}}},
			{ID: "Evil.App", Version: "1.0", Publisher: "Evil", Homepage: "javascript:alert(1)", PublisherURL: long, Description: strings.Repeat("d", 3000), ResolvedAt: gen,
				Installers: []intel.ResolvedInstaller{{Arch: "x64", Type: "msi", URL: "http://evil.example/x.msi", SHA256: "not-a-hash"}}},
		}}, e.priv, "intel-lib")

	var p libPage
	if c := e.api("GET", "/api/library", tokViewer, nil, &p); c != 200 {
		t.Fatalf("library: %d", c)
	}
	// available (default): importable or installed; installed first.
	if p.Source != "acq-zone-1" || p.GeneratedAt != gen || p.Page != 1 || p.PerPage != 50 || libIDs(p) != "Google.Chrome,KB5044280,7zip.7zip,Evil.App" {
		t.Fatalf("available: %s %+v", libIDs(p), p)
	}
	ch := p.Items[0]
	if ch.Installed.Endpoints != 1 || ch.Installed.Outdated != 1 || ch.Importable != "yes" || ch.Publisher != "Google LLC" || ch.Links.Homepage != "https://www.google.com/chrome/" ||
		len(ch.Installers) != 1 || ch.Installers[0].Type != "wix" {
		t.Errorf("chrome: %+v", ch)
	}
	if c := e.api("GET", "/api/library?view=all&sort=name", tokViewer, nil, &p); c != 200 || p.Total != 6 || p.Items[0].ID != "KB5044280" && p.Items[0].ID != "7zip.7zip" {
		t.Fatalf("all: %d %s", c, libIDs(p))
	}
	byID := map[string]libItem{}
	for _, it := range p.Items {
		byID[it.ID] = it
	}
	if it := byID["Notepad++.Notepad++"]; it.Importable != "no" || it.ImportableReason != "EXE installer only (nullsoft)" {
		t.Errorf("notepad++: %+v", it)
	}
	if it := byID["VideoLAN.VLC"]; it.Importable != "unknown" || it.Installers != nil {
		t.Errorf("vlc: %+v", it)
	}
	if it := byID["7zip.7zip"]; it.Importable != "yes" || it.ImportableReason != "MSI installer (x64)" ||
		it.Links.Manifest != "https://github.com/microsoft/winget-pkgs/tree/master/manifests/7/7zip/7zip/26.04" || it.Description != "File archiver" {
		t.Errorf("7zip: %+v", it)
	}
	if it := byID["Notepad++.Notepad++"]; it.Links.Manifest != "https://github.com/microsoft/winget-pkgs/tree/master/manifests/n/Notepad++/Notepad++/8.7" {
		t.Errorf("notepad++ manifest link: %q", it.Links.Manifest)
	}
	// Community text is data: no control/bidi characters, bounded; unsafe links dropped.
	ev := byID["Evil.App"]
	if ev.Name != "Evil App" || len(ev.Description) > 1010 || ev.Links.Homepage != "" || ev.Links.PublisherURL != "" || ev.Installers[0].URL != "" {
		t.Errorf("evil: name %q len(desc) %d links %+v installers %+v", ev.Name, len(ev.Description), ev.Links, ev.Installers)
	}
	if it := byID["KB5044280"]; it.Kind != "os" || it.LatestVersion != "22000.3260" || it.Importable != "yes" ||
		it.Links.Homepage != "https://www.catalog.update.microsoft.com/Search.aspx?q=KB5044280" {
		t.Errorf("kb: %+v", it)
	}
	// Search over name, id, publisher and product code; filters; paging.
	for q, want := range map[string]string{
		"/api/library?view=all&q=zip":                                           "7zip.7zip",
		"/api/library?view=all&q=igor":                                          "7zip.7zip",
		"/api/library?view=all&q=0228b730":                                      "Google.Chrome",
		"/api/library?view=all&q=GOOGLE+chrome":                                 "Google.Chrome",
		"/api/library?view=all&kind=os":                                         "KB5044280",
		"/api/library?view=installed":                                           "Google.Chrome",
		"/api/library?view=all&publisher=notepad%2B%2B+team":                    "Notepad++.Notepad++",
		"/api/library?view=all&sort=name&kind=app&per_page=2&page=2":            "Google.Chrome,Notepad++.Notepad++",
		"/api/library?view=all&q=nothing-matches-this":                          "",
		"/api/library?view=all&kind=app&sort=name&per_page=500&page=1&q=pavlov": "7zip.7zip",
	} {
		var r libPage
		if c := e.api("GET", q, tokViewer, nil, &r); c != 200 || libIDs(r) != want {
			t.Errorf("%s: %d %q, want %q", q, c, libIDs(r), want)
		}
		if strings.Contains(q, "per_page=500") && r.PerPage != 100 {
			t.Errorf("per_page not capped: %d", r.PerPage)
		}
	}
	for _, bad := range []string{"?kind=x", "?view=x", "?sort=x", "?page=0", "?per_page=-1"} {
		if c := e.api("GET", "/api/library"+bad, tokViewer, nil, nil); c != 400 {
			t.Errorf("%s: %d", bad, c)
		}
	}
	// Detail: the endpoints with their versions.
	var d libItem
	if c := e.api("GET", "/api/library/app/google.chrome", tokViewer, nil, &d); c != 200 || len(d.Endpoints) != 1 || d.Endpoints[0].Hostname != "pc-lib-01" ||
		!d.Endpoints[0].Outdated || d.Endpoints[0].InstalledVersion != "155.0.8059.82" {
		t.Fatalf("detail: %d %+v", c, d)
	}
	if c := e.api("GET", "/api/library/os/KB5044280", tokViewer, nil, &d); c != 200 || d.Endpoints == nil || len(d.Endpoints) != 0 {
		t.Errorf("os detail: %d %+v", c, d)
	}
	if c := e.api("GET", "/api/library/app/Nope.Nope", tokViewer, nil, nil); c != 404 {
		t.Errorf("unknown: %d", c)
	}

	// Import from the Library: 7-Zip (installed nowhere) for arm64, the KB
	// no endpoint needs.
	if c := e.api("POST", "/api/acquisition-requests", tokOperator, map[string]any{"apps": []string{"7zip.7zip"}, "app_archs": map[string]string{"7zip.7zip": "sparc"}}, nil); c != 400 {
		t.Errorf("bad arch: %d", c)
	}
	if c := e.api("POST", "/api/acquisition-requests", tokOperator, map[string]any{"apps": []string{"Contoso.Nothing"}}, nil); c != 400 {
		t.Errorf("not in intel: %d", c)
	}
	var raw json.RawMessage
	if c := e.api("POST", "/api/acquisition-requests", tokOperator, map[string]any{"apps": []string{"7zip.7zip", "Google.Chrome"}, "kbs": []string{"KB5044280"},
		"app_archs": map[string]string{"7zip.7zip": "arm64", "Google.Chrome": "arm64"}}, &raw); c != 200 {
		t.Fatalf("import: %d", c)
	}
	req, err := acqrequest.Parse(strings.NewReader(string(withoutQueuedTo(t, raw, ""))))
	if err != nil {
		t.Fatalf("request does not parse: %v %s", err, raw)
	}
	apps := map[string]acqrequest.App{}
	for _, ap := range req.Apps {
		apps[ap.WingetID] = ap
	}
	if z := apps["7zip.7zip"]; z.Version != "26.04" || z.Endpoints != 0 || strings.Join(z.Architectures, ",") != "arm64" || len(z.Installed) != 0 {
		t.Errorf("7zip item: %+v", z)
	}
	if c := apps["Google.Chrome"]; strings.Join(c.Architectures, ",") != "x64" || c.Endpoints != 1 {
		t.Errorf("installed app takes the fleet's arch, not app_archs: %+v", c)
	}
	if len(req.KBs) != 1 || req.KBs[0].KB != "KB5044280" || req.KBs[0].Arch != "x64" || req.KBs[0].Build != 22000 || req.KBs[0].Endpoints != 0 {
		t.Errorf("kb: %+v", req.KBs)
	}
	if c := e.api("GET", "/api/library?view=all&q=7-zip", tokViewer, nil, &p); c != 200 || len(p.Items) != 1 || p.Items[0].Requested == nil ||
		p.Items[0].Requested.Status != "requested" || p.Items[0].Requested.RequestID != req.RequestID {
		t.Errorf("requested state: %+v", p.Items)
	}
}

// B/D: summary says how old the intelligence is; intel_stale and
// out_of_support alerts name what they are about and close themselves.
func TestIntelStaleAndOutOfSupportAlerts(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	old := e.enroll("pc-old-build", []string{"pilot"}, agent.SimConfig{})
	if _, err := e.st.Checkin(ctx, old.id, store.CheckinRequest{Hostname: "pc-old-build", OSVersion: "Windows 11 Pro 21H2 (22000.2538)", Build: 22000, Arch: "x64",
		Inventory: []store.InventoryItem{{Kind: "kb", ID: "KB5044280"}}}); err != nil {
		t.Fatal(err)
	}
	var sm store.Summary
	if c := e.api("GET", "/api/summary", tokViewer, nil, &sm); c != 200 || sm.Intel != nil {
		t.Fatalf("no intel: %d %+v", c, sm.Intel)
	}
	now := time.Now().UTC()
	gen := now.Add(-10 * 24 * time.Hour).Truncate(time.Second)
	e.dropIntel(intel.Doc{Source: "acq-zone-1", GeneratedAt: gen.Format(time.RFC3339),
		Windows: []intel.WindowsRelease{{Product: "Windows 11 Version 21H2", Build: 22000, Arch: "x64", KB: "KB5044280", ReleaseDate: gen.AddDate(0, 0, -100).Format("2006-01-02"), Title: "last CU"}}},
		e.priv, "intel-old")
	if c := e.api("GET", "/api/summary", tokViewer, nil, &sm); c != 200 || sm.Intel == nil || !sm.Intel.Stale || sm.Intel.AgeHours < 239 || sm.Intel.GeneratedAt != gen.Format(time.RFC3339) {
		t.Fatalf("stale intel: %d %+v", c, sm.Intel)
	}
	if err := e.srvHandler.SweepIntelAlerts(ctx); err != nil {
		t.Fatal(err)
	}
	var alerts []store.Alert
	e.api("GET", "/api/alerts?open=1", tokViewer, nil, &alerts)
	got := map[string]store.Alert{}
	for _, a := range alerts {
		got[a.Kind] = a
	}
	if a, ok := got["intel_stale"]; !ok || a.Severity != "warning" || !strings.Contains(a.Message, "10 days old") || strings.Contains(a.Message, "pmctl") {
		t.Errorf("intel_stale: %+v", a)
	}
	oos, ok := got["out_of_support"]
	ids, _ := oos.Details["endpoint_ids"].([]any)
	if !ok || !strings.HasSuffix(oos.Message, ": pc-old-build") || len(ids) != 1 || ids[0] != old.id {
		t.Errorf("out_of_support: %+v", oos)
	}
	// Fresh intelligence: the build is supported again and the document is new.
	e.dropIntel(intel.Doc{Source: "acq-zone-1", GeneratedAt: now.Add(-time.Hour).Truncate(time.Second).Format(time.RFC3339),
		Windows: []intel.WindowsRelease{{Product: "Windows 11 Version 21H2", Build: 22000, Arch: "x64", KB: "KB5044280", ReleaseDate: now.AddDate(0, 0, -5).Format("2006-01-02"), Title: "CU"}}},
		e.priv, "intel-new")
	if err := e.srvHandler.SweepIntelAlerts(ctx); err != nil {
		t.Fatal(err)
	}
	alerts = nil
	e.api("GET", "/api/alerts?open=1", tokViewer, nil, &alerts)
	if hasAlert(alerts, "intel_stale") || hasAlert(alerts, "out_of_support") {
		t.Errorf("not resolved: %+v", alerts)
	}
	if c := e.api("GET", "/api/summary", tokViewer, nil, &sm); c != 200 || sm.Intel == nil || sm.Intel.Stale {
		t.Errorf("fresh intel: %+v", sm.Intel)
	}
}

// E: a cumulative update with expected_ubr verifies by build revision, and
// the evidence report lists the target with what proved it and who
// approved it.
func TestUBRVerificationAndEvidenceCSV(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	p := msuPkg("KB5099999-x64", "KB5099999")
	p.ExpectedUBR = 9711
	b := e.transferAndIntake(e.bundle(bundleOpts{seq: 1}, map[string]manifest.Package{p.PackageID: p},
		map[string]string{p.PackageID: e.payload("windows10.0-kb5099999-x64.msu", "MSU "+strings.Repeat("x", 1024))}))
	if b.State != "validated" {
		t.Fatalf("bundle: %+v", b)
	}
	var pkg store.Package
	if c := e.api("GET", "/api/packages/KB5099999-x64", tokViewer, nil, &pkg); c != 200 || pkg.ExpectedUBR != 9711 {
		t.Fatalf("expected_ubr not stored: %d %+v", c, pkg.ExpectedUBR)
	}
	if c := e.api("POST", "/api/packages/KB5099999-x64/approve", tokApprover, map[string]string{"reason": "CAB-1"}, nil); c != 200 {
		t.Fatalf("approve: %d", c)
	}
	a := e.enroll("pc-ubr", []string{"pilot"}, agent.SimConfig{})
	if _, err := e.st.Checkin(ctx, a.id, store.CheckinRequest{Hostname: "pc-ubr", OSVersion: "Windows 10 Pro 22H2 (19045.9000)", Build: 19045, Arch: "x64"}); err != nil {
		t.Fatal(err)
	}
	var d store.Deployment
	if c := e.createDep(tokOperator, store.NewDeployment{PackageID: "KB5099999-x64", Name: "lcu", Rings: []store.Ring{{Name: "pilot", Groups: []string{"pilot"}}},
		MaxFailurePct: 100, MaxRetries: 1}, &d); c != 201 {
		t.Fatalf("deploy: %d", c)
	}
	// Windows does not list the KB, but the endpoint is now at 19045.9711.
	if _, err := e.st.Checkin(ctx, a.id, store.CheckinRequest{Hostname: "pc-ubr", OSVersion: "Windows 10 Pro 22H2 (19045.9711)", Build: 19045, Arch: "x64"}); err != nil {
		t.Fatal(err)
	}
	if st := targetState(e.deployment(d.DeploymentID), a.id); st != "verified" {
		t.Fatalf("target: %s", st)
	}
	hreq, _ := http.NewRequest("GET", e.srv.URL+"/api/reports/targets.csv", nil)
	e.authorize(hreq, tokViewer)
	resp, err := http.DefaultClient.Do(hreq)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	rows, err := csv.NewReader(strings.NewReader(string(body))).ReadAll()
	if err != nil || resp.StatusCode != 200 || len(rows) != 2 {
		t.Fatalf("csv: %d %v %s", resp.StatusCode, err, body)
	}
	if strings.Join(rows[0], ",") != "endpoint,hostname,package_id,title,state,verified_at,evidence,approved_by,deployment_id" {
		t.Errorf("header: %v", rows[0])
	}
	r := rows[1]
	if r[0] != a.id || r[1] != "pc-ubr" || r[2] != "KB5099999-x64" || r[4] != "verified" || r[5] == "" || r[6] != "os_version build 19045.9711" || r[7] != "user:alice@bank.test" || r[8] != d.DeploymentID {
		t.Errorf("row: %v", r)
	}
}
