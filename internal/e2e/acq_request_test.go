package e2e

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"offpatch/internal/acqrequest"
	"offpatch/internal/agent"
	"offpatch/internal/intel"
	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

// Updates page → acquisition request: an operator exports the selected
// outdated apps and missing KBs as a file (audited, no host names, viewers
// refused); once the requested MSI comes back through intake it shows as
// "in catalog · quarantined", linked by product code (Chrome keeps its
// code) or by Apps & features name (7-Zip's code changes per version).
func TestAcquisitionRequestExport(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a := e.enroll("pc-req-01", []string{"pilot"}, agent.SimConfig{})
	if _, err := e.st.Checkin(ctx, a.id, store.CheckinRequest{
		Hostname: "pc-req-01", OSVersion: "Windows 11 Pro 21H2 (22000.2538)", Build: 22000, Arch: "x64",
		Inventory: []store.InventoryItem{
			{Kind: "product", ID: "{0228B730-26AA-39E9-B2E1-0FC0E3EA58C8}", Name: "Google Chrome", Version: "155.0.8059.82"},
			{Kind: "product", ID: "{23170F69-40C1-2702-2603-000001000000}", Name: "7-Zip 26.03 (x64 edition)", Version: "26.03.00.0"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	// An arm64 machine misses the same KB: the request must list both architectures.
	arm := e.enroll("pc-req-arm", []string{"pilot"}, agent.SimConfig{})
	if _, err := e.st.Checkin(ctx, arm.id, store.CheckinRequest{Hostname: "pc-req-arm", OSVersion: "Windows 11 Pro 21H2 (22000.2538)", Build: 22000, Arch: "arm64"}); err != nil {
		t.Fatal(err)
	}
	gen := time.Now().UTC().Add(-time.Hour).Truncate(time.Second).Format(time.RFC3339)
	e.dropIntel(intel.Doc{Source: "acq-zone-1", GeneratedAt: gen,
		Windows: []intel.WindowsRelease{{Product: "Windows 11 Version 21H2", Build: 22000, Arch: "x64", KB: "KB5044280",
			Title: "2024-10 Cumulative Update for Windows 11 for x64-based Systems (KB5044280)"},
			{Product: "Windows 11 Version 21H2", Build: 22000, Arch: "arm64", KB: "KB5044280",
				Title: "2024-10 Cumulative Update for Windows 11 for arm64-based Systems (KB5044280)"}},
		Apps: []intel.App{
			{ID: "Google.Chrome", Name: "Google Chrome", Version: "155.0.8059.85", Codes: []string{"{0228b730-26aa-39e9-b2e1-0fc0e3ea58c8}"}, Names: []string{"googlechrome"}},
			{ID: "7zip.7zip", Name: "7-Zip", Version: "26.04", ARPMax: "26.04.00.0", Codes: []string{"{23170f69-40c1-2702-2603-000001000000}"}, Names: []string{"7zip"}},
		}}, e.priv, "intel-req")

	body := map[string]any{"apps": []string{"Google.Chrome", "7zip.7zip"}, "kbs": []string{"KB5044280"}}
	if c := e.api("POST", "/api/acquisition-requests", tokViewer, body, nil); c != 403 {
		t.Fatalf("viewer export: %d", c)
	}
	if c := e.api("POST", "/api/acquisition-requests", tokOperator, map[string]any{"apps": []string{"Contoso.Nothing"}}, nil); c != 400 {
		t.Fatalf("unknown app: %d", c)
	}
	if c := e.api("POST", "/api/acquisition-requests", tokOperator, map[string]any{}, nil); c != 400 {
		t.Fatalf("empty selection: %d", c)
	}
	var raw json.RawMessage
	if c := e.api("POST", "/api/acquisition-requests", tokOperator, body, &raw); c != 200 {
		t.Fatalf("export: %d", c)
	}
	// What the browser saves (the response without queued_to) is exactly
	// what pmctl parses.
	raw = withoutQueuedTo(t, raw, "")
	req, err := acqrequest.Parse(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("exported file does not parse: %v\n%s", err, raw)
	}
	if req.CreatedBy != "user:otto" || req.IntelGeneratedAt != gen || len(req.Apps) != 2 || len(req.KBs) != 2 {
		t.Fatalf("request: %+v", req)
	}
	apps := map[string]acqrequest.App{}
	for _, ap := range req.Apps {
		apps[ap.WingetID] = ap
	}
	ch := apps["Google.Chrome"]
	if ch.Version != "155.0.8059.85" || ch.Endpoints != 1 || len(ch.Architectures) != 1 || ch.Architectures[0] != "x64" ||
		len(ch.Installed) != 1 || ch.Installed[0].ProductCode != "{0228B730-26AA-39E9-B2E1-0FC0E3EA58C8}" || ch.Installed[0].Version != "155.0.8059.82" {
		t.Errorf("chrome: %+v", ch)
	}
	if k := req.KBs[1]; k.KB != "KB5044280" || k.Build != 22000 || k.Arch != "x64" || k.Endpoints != 1 || !strings.Contains(k.Title, "x64-based") {
		t.Errorf("kb x64: %+v", k)
	}
	if k := req.KBs[0]; k.Arch != "arm64" || k.Endpoints != 1 || !strings.Contains(k.Title, "arm64-based") {
		t.Errorf("kb arm64: %+v", k)
	}
	if strings.Contains(string(raw), "pc-req-") || strings.Contains(string(raw), a.id) {
		t.Error("the request carries host names or endpoint ids out of the isolated zone")
	}

	var audit []store.AuditEvent
	e.api("GET", "/api/audit", tokViewer, nil, &audit)
	found := false
	for _, ev := range audit {
		if ev.Action == "acquisition.request_exported" && ev.ObjectID == req.RequestID && ev.Actor == "user:otto" &&
			strings.Contains(string(ev.Details), "Google.Chrome@155.0.8059.85") && strings.Contains(string(ev.Details), "KB5044280/x64") && strings.Contains(string(ev.Details), "KB5044280/arm64") {
			found = true
		}
	}
	if !found {
		t.Fatal("export not audited with who and what")
	}

	// pmctl brings the MSIs back (as winget sources them): both link.
	chrome := manifest.Package{PackageID: "Google.Chrome-155.0.8059.85", Title: "Google Chrome 155.0.8059.85", Vendor: "Google", Kind: "msi",
		Version: "155.0.8059.85", ProductCode: "{0228B730-26AA-39E9-B2E1-0FC0E3EA58C8}", PackageName: "Google Chrome", Severity: "important",
		ReleaseDate: "2026-10-15", Supersedes: []string{}, Applicability: manifest.Applicability{OS: "windows", Arch: "x64"},
		VendorSignature: manifest.VendorSignature{Status: "not_checked"}}
	sevenZip := chrome
	sevenZip.PackageID, sevenZip.Title, sevenZip.Vendor, sevenZip.Version = "7zip.7zip-26.04", "7-Zip 26.04", "7zip", "26.04"
	sevenZip.ProductCode, sevenZip.PackageName = "{23170F69-40C1-2702-2604-000001000000}", "7-Zip"
	b := e.transferAndIntake(e.bundle(bundleOpts{seq: 1}, map[string]manifest.Package{chrome.PackageID: chrome, sevenZip.PackageID: sevenZip},
		map[string]string{chrome.PackageID: e.payload("chrome.msi", "chrome"), sevenZip.PackageID: e.payload("7z.msi", "7z")}))
	if b.State != "validated" {
		t.Fatalf("bundle %s: %v", b.State, checksFailed(b))
	}
	var fleet struct {
		Updates []struct {
			Key     string `json:"key"`
			Catalog *struct {
				PackageID string `json:"package_id"`
				State     string `json:"state"`
			} `json:"catalog"`
		} `json:"updates"`
	}
	// The fleet view is cached for a minute; the per-endpoint view is not.
	var r struct {
		Apps []struct {
			AppID   string `json:"app_id"`
			Catalog *struct {
				PackageID string `json:"package_id"`
				State     string `json:"state"`
			} `json:"catalog"`
		} `json:"apps"`
	}
	if c := e.api("GET", "/api/endpoints/"+a.id+"/updates", tokViewer, nil, &r); c != 200 || len(r.Apps) != 2 {
		t.Fatalf("endpoint updates: %d %+v", c, r)
	}
	for _, ap := range r.Apps {
		want := map[string]string{"Google.Chrome": chrome.PackageID, "7zip.7zip": sevenZip.PackageID}[ap.AppID]
		if ap.Catalog == nil || ap.Catalog.PackageID != want || ap.Catalog.State != "quarantined" {
			t.Errorf("%s not linked to %s: %+v", ap.AppID, want, ap.Catalog)
		}
	}
	// The endpoint is offered both (7-Zip despite its versioned display name).
	var avail []store.Available
	if c := e.api("GET", "/api/endpoints/"+a.id+"/available", tokViewer, nil, &avail); c != 200 {
		t.Fatalf("available: %d", c)
	}
	offered := map[string]string{}
	for _, av := range avail {
		offered[av.PackageID] = av.InstalledVersion
	}
	if offered[chrome.PackageID] != "155.0.8059.82" || offered[sevenZip.PackageID] != "26.03.00.0" {
		t.Errorf("available updates: %+v", avail)
	}
	e.api("GET", "/api/updates", tokViewer, nil, &fleet)
	if len(fleet.Updates) != 3 {
		t.Fatalf("fleet: %+v", fleet)
	}

	// A KB no endpoint needs is refused.
	if c := e.api("POST", "/api/acquisition-requests", tokOperator, map[string]any{"kbs": []string{"KB0000001"}}, nil); c != 400 {
		t.Fatalf("unknown kb: %d", c)
	}
}
