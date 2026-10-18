package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	"offpatch/internal/acqstatus"
	"offpatch/internal/agent"
	"offpatch/internal/intel"
	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

// P1 fixes through the API (store-level detail in internal/store/p1_test.go).

// Items 5 and 7: compliant is refined by update intelligence
// (updates_available, out_of_support) in the list, the detail, the CSV and
// the summary counts; an endpoint that never checked in is
// awaiting_checkin. Item 3: per-item import results reach the update rows.
func TestHonestStatusAndImportResults(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	checkin := func(a *simAgent, build int, inv ...store.InventoryItem) {
		t.Helper()
		if _, err := e.st.Checkin(ctx, a.id, store.CheckinRequest{Hostname: "h-" + a.id, OSVersion: "Windows Pro", Build: build, Arch: "x64", Inventory: inv}); err != nil {
			t.Fatal(err)
		}
	}
	chrome := func(v string) store.InventoryItem {
		return store.InventoryItem{Kind: "product", ID: "{0228B730-26AA-39E9-B2E1-0FC0E3EA58C8}", Name: "Google Chrome", Version: v}
	}
	current := e.enroll("pc-current", []string{"pilot"}, agent.SimConfig{})
	checkin(current, 19045, store.InventoryItem{Kind: "kb", ID: "KB5099999"}, chrome("155.0.8059.85"))
	behind := e.enroll("pc-behind", []string{"pilot"}, agent.SimConfig{})
	checkin(behind, 19045, chrome("155.0.8059.82"))
	legacy := e.enroll("pc-legacy", []string{"pilot"}, agent.SimConfig{})
	checkin(legacy, 22000, store.InventoryItem{Kind: "kb", ID: "KB5044280"})
	fresh := e.enroll("pc-fresh", []string{"pilot"}, agent.SimConfig{}) // never checks in

	now := time.Now().UTC()
	e.dropIntel(intel.Doc{Source: "acq-zone-1", GeneratedAt: now.Add(-time.Hour).Truncate(time.Second).Format(time.RFC3339),
		Windows: []intel.WindowsRelease{
			{Product: "Windows 10 Version 22H2", Build: 19045, Arch: "x64", KB: "KB5099999", ReleaseDate: now.AddDate(0, 0, -10).Format("2006-01-02"), Title: "CU"},
			{Product: "Windows 11 Version 21H2", Build: 22000, Arch: "x64", KB: "KB5044280", ReleaseDate: "2024-10-08", Title: "last CU"}},
		Apps: []intel.App{{ID: "Google.Chrome", Name: "Google Chrome", Version: "155.0.8059.85", Codes: []string{"{0228b730-26aa-39e9-b2e1-0fc0e3ea58c8}"}, Names: []string{"googlechrome"}}},
	}, e.priv, "intel-p1")

	want := map[string]string{current.id: "compliant", behind.id: "updates_available", legacy.id: "out_of_support", fresh.id: "awaiting_checkin"}
	var eps []store.Endpoint
	if c := e.api("GET", "/api/endpoints", tokViewer, nil, &eps); c != 200 || len(eps) != 4 {
		t.Fatalf("endpoints: %d %d", c, len(eps))
	}
	for _, ep := range eps {
		if ep.Status != want[ep.EndpointID] {
			t.Errorf("%s: status %s, want %s (missing %+v)", ep.Hostname, ep.Status, want[ep.EndpointID], ep.Missing)
		}
	}
	for id, st := range want {
		var d store.EndpointDetail
		if c := e.api("GET", "/api/endpoints/"+id, tokViewer, nil, &d); c != 200 || d.Status != st {
			t.Errorf("detail %s: %d %s, want %s", id, c, d.Status, st)
		}
	}
	var sm store.Summary
	if c := e.api("GET", "/api/summary", tokViewer, nil, &sm); c != 200 {
		t.Fatalf("summary %d", c)
	}
	for st, n := range map[string]int{"compliant": 1, "updates_available": 1, "out_of_support": 1, "awaiting_checkin": 1, "stale": 0, "offline": 0} {
		if sm.Endpoints.ByStatus[st] != n {
			t.Errorf("summary %s = %d, want %d (%+v)", st, sm.Endpoints.ByStatus[st], n, sm.Endpoints.ByStatus)
		}
	}
	if err := e.st.SweepAlerts(ctx, store.DefaultThresholds); err != nil {
		t.Fatal(err)
	}
	if alerts, _ := e.st.ListAlerts(ctx, true); hasAlert(alerts, "endpoints_offline") || hasAlert(alerts, "inventory_stale") {
		t.Errorf("awaiting_checkin raised an offline/stale alert: %+v", alerts)
	}

	// Item 3: Chrome is requested; the acquisition run says it cannot be
	// imported. The fleet row and the endpoint's update row both say why.
	var req struct {
		RequestID string `json:"request_id"`
		Apps      []struct {
			WingetID string `json:"winget_id"`
			Version  string `json:"version"`
		} `json:"apps"`
	}
	if c := e.api("POST", "/api/acquisition-requests", tokOperator, map[string]any{"apps": []string{"Google.Chrome"}}, &req); c != 200 || len(req.Apps) != 1 {
		t.Fatalf("export: %d %+v", c, req)
	}
	e.dropStatus(acqstatus.Report{Source: "acq-zone-1", Host: "acq01", StartedAt: now.Format(time.RFC3339), FinishedAt: now.Add(time.Second).Format(time.RFC3339),
		Outcome: "partial", Failures: map[string]string{}, Feeds: []acqstatus.Feed{{Type: "request", Name: req.RequestID, Status: "failed"}},
		Items: []acqstatus.ItemResult{{RequestID: req.RequestID, Kind: "app", Key: "Google.Chrome", Version: req.Apps[0].Version,
			Result: acqstatus.ItemUnsupported, Reason: "no MSI installer for x64"}}}, nil)
	type ref struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	var up struct {
		Apps []struct {
			AppID     string `json:"app_id"`
			Requested *ref   `json:"requested"`
		} `json:"apps"`
	}
	if c := e.api("GET", "/api/endpoints/"+behind.id+"/updates", tokViewer, nil, &up); c != 200 || len(up.Apps) != 1 || up.Apps[0].Requested == nil ||
		up.Apps[0].Requested.Status != "unsupported" || up.Apps[0].Requested.Reason != "no MSI installer for x64" {
		t.Errorf("endpoint update row: %d %+v", c, up)
	}
	var fleet struct {
		Updates []struct {
			Key       string `json:"key"`
			Requested *ref   `json:"requested"`
		} `json:"updates"`
	}
	e.api("GET", "/api/updates", tokViewer, nil, &fleet)
	found := false
	for _, u := range fleet.Updates {
		if u.Key == "Google.Chrome" {
			found = u.Requested != nil && u.Requested.Status == "unsupported" && u.Requested.Reason == "no MSI installer for x64"
		}
	}
	if !found {
		t.Errorf("fleet update row: %+v", fleet.Updates)
	}
}

// Item 4 through intake and the API: rejected → delivered again →
// quarantined for a new review.
func TestImportAgainAfterReject(t *testing.T) {
	e := newEnv(t)
	pkgs := map[string]manifest.Package{"KB5000002-x64": msuPkg("KB5000002-x64", "KB5000002")}
	files := map[string]string{"KB5000002-x64": e.payload("windows10.0-kb5000002-x64.msu", "MSU payload "+strings.Repeat("x", 1024))}
	if b := e.transferAndIntake(e.bundle(bundleOpts{seq: 1}, pkgs, files)); b.State != "validated" {
		t.Fatalf("bundle 1: %+v", b)
	}
	var p store.Package
	if c := e.api("POST", "/api/packages/KB5000002-x64/reject", tokApprover, map[string]string{"reason": "wrong month"}, &p); c != 200 || p.State != "rejected" {
		t.Fatalf("reject: %d %s", c, p.State)
	}
	b2 := e.transferAndIntake(e.bundle(bundleOpts{seq: 2}, pkgs, files))
	if b2.State != "validated" {
		t.Fatalf("bundle 2: %+v", b2)
	}
	if c := e.api("GET", "/api/packages/KB5000002-x64", tokViewer, nil, &p); c != 200 || p.State != "quarantined" || p.BundleID != "b-test-0002" {
		t.Fatalf("re-imported: %d state=%s bundle=%s", c, p.State, p.BundleID)
	}
	// The new review can approve it; the content is published from the new bundle.
	if c := e.api("POST", "/api/packages/KB5000002-x64/approve", tokApprover, map[string]string{"reason": "right month after all"}, &p); c != 200 || p.State != "approved" {
		t.Fatalf("approve re-imported: %d %s", c, p.State)
	}
	// Revoked stays revoked.
	if c := e.api("POST", "/api/packages/KB5000002-x64/revoke", tokApprover, map[string]string{"reason": "vendor pulled it"}, &p); c != 200 {
		t.Fatalf("revoke: %d", c)
	}
	if b := e.transferAndIntake(e.bundle(bundleOpts{seq: 3}, pkgs, files)); b.State != "validated" {
		t.Fatalf("bundle 3: %+v", b)
	}
	if e.api("GET", "/api/packages/KB5000002-x64", tokViewer, nil, &p); p.State != "revoked" {
		t.Errorf("revoked package re-imported: %s", p.State)
	}
}

// Item 1 through the API with real (simulated) agents: "first machines,
// then everything else" advances on its own once the first ring verified.
func TestAutoAdvanceFirstMachines(t *testing.T) {
	e := newEnv(t)
	pkgs := map[string]manifest.Package{"KB5000002-x64": msuPkg("KB5000002-x64", "KB5000002")}
	files := map[string]string{"KB5000002-x64": e.payload("windows10.0-kb5000002-x64.msu", "MSU payload "+strings.Repeat("z", 1024))}
	e.transferAndIntake(e.bundle(bundleOpts{seq: 1}, pkgs, files))
	if c := e.api("POST", "/api/packages/KB5000002-x64/approve", tokApprover, map[string]string{"reason": "tested"}, nil); c != 200 {
		t.Fatalf("approve %d", c)
	}
	first := e.enroll("pc-first", []string{"pilot"}, agent.SimConfig{})
	rest := e.enroll("pc-rest", []string{"broad"}, agent.SimConfig{})
	e.cycle(first)
	e.cycle(rest)
	var d store.Deployment
	nd := store.NewDeployment{PackageID: "KB5000002-x64", Name: "Oct CU", MaxFailurePct: 0, AutoAdvance: true,
		Rings: []store.Ring{{Name: "First machines", Groups: []string{"endpoint:" + first.id}}, {Name: "Everything else", Groups: []string{"all"}}}}
	if c := e.api("POST", "/api/deployments", tokOperator, nd, &d); c != 201 || !d.AutoAdvance {
		t.Fatalf("create: %d %+v", c, d)
	}
	e.cycle(first) // installs
	e.cycle(first) // inventory shows the KB: verified, ring 0 finished
	dd := e.deployment(d.DeploymentID)
	if dd.CurrentRing != 1 || dd.State != "active" || targetState(dd, rest.id) != "pending" {
		t.Fatalf("not auto-advanced: ring=%d state=%s rest=%s (%s)", dd.CurrentRing, dd.State, targetState(dd, rest.id), dd.StateReason)
	}
	e.cycle(rest)
	e.cycle(rest)
	if dd = e.deployment(d.DeploymentID); dd.State != "completed" {
		t.Errorf("final: %s %+v", dd.State, dd.Counts)
	}
}
