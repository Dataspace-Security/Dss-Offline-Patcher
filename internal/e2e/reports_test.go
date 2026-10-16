package e2e

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"offpatch/internal/agent"
	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

func TestReportsAlertsMetrics(t *testing.T) {
	var mu sync.Mutex
	var hooks []store.Alert
	siem := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var a store.Alert
		json.NewDecoder(r.Body).Decode(&a)
		mu.Lock()
		hooks = append(hooks, a)
		mu.Unlock()
	}))
	defer siem.Close()
	e := newEnvOpts(t, false, `"metrics_token": "prom-secret", "patch_deadlines": {"critical": "24h"}, "notify": {"webhook_url": "`+siem.URL+`", "min_severity": "warning"},`)
	ctx := context.Background()

	old := msuPkg("KB5001001-x64", "KB5001001")
	old.ReleaseDate = time.Now().AddDate(0, 0, -10).Format("2006-01-02") // past the 24h critical deadline
	fresh := msuPkg("KB5001002-x64", "KB5001002")
	fresh.ReleaseDate = time.Now().Format("2006-01-02")
	fresh.Title = "=HYPERLINK(\"http://evil\")" // CSV injection attempt via catalog data
	pk := map[string]manifest.Package{old.PackageID: old, fresh.PackageID: fresh}
	files := map[string]string{old.PackageID: e.payload("a.msu", "a"), fresh.PackageID: e.payload("b.msu", "b")}
	e.transferAndIntake(e.bundle(bundleOpts{seq: 1}, pk, files))
	e.approve(old.PackageID)
	e.approve(fresh.PackageID)
	ok1 := e.enroll("pc-r1", []string{"r"}, agent.SimConfig{})
	bad := e.enroll("pc-r2", []string{"r"}, agent.SimConfig{FailKBs: []string{"KB5001001"}})
	r := []store.Ring{{Name: "r", Groups: []string{"r"}}}
	d := e.deploy(store.NewDeployment{PackageID: old.PackageID, Name: "old", Rings: r, MaxFailurePct: 10})
	e.deploy(store.NewDeployment{PackageID: fresh.PackageID, Name: "fresh", Rings: r})
	e.cycle(ok1)
	e.cycle(ok1)
	e.cycle(bad)

	// ---- compliance report ----
	var rep store.ComplianceReport
	if c := e.api("GET", "/api/reports/compliance", tokViewer, nil, &rep); c != 200 {
		t.Fatalf("report: %d", c)
	}
	crit := rep.BySeverity["critical"]
	if crit.Targets != 4 || crit.Verified != 2 || crit.Overdue != 1 {
		t.Fatalf("critical stats: %+v", crit)
	}
	if rep.Packages[0].PackageID != old.PackageID || rep.Packages[0].Overdue != 1 || rep.Packages[0].DaysReleaseToReceived < 9 {
		t.Fatalf("overdue package should sort first with latency: %+v", rep.Packages[0])
	}
	if rep.Fleet.Total != 2 || rep.Fleet.PctReporting != 100 {
		t.Fatalf("fleet: %+v", rep.Fleet)
	}

	// ---- CSV: formula injection neutralised ----
	req, _ := http.NewRequest("GET", e.srv.URL+"/api/reports/compliance.csv", nil)
	req.Header.Set("Authorization", "Bearer "+tokViewer)
	resp, _ := http.DefaultClient.Do(req)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), "'=HYPERLINK") || !strings.HasPrefix(string(b), "package_id,") {
		t.Fatalf("csv: %s", b)
	}

	// ---- alerts: auto-pause + install failure raised, delivered to SIEM, ack ----
	var alerts []store.Alert
	e.api("GET", "/api/alerts?open=1", tokViewer, nil, &alerts)
	kinds := map[string]bool{}
	for _, a := range alerts {
		kinds[a.Kind] = true
	}
	if !kinds["deployment_auto_paused"] || !kinds["install_failed"] {
		t.Fatalf("expected auto-pause and install-failed alerts: %v (deployment %s)", kinds, e.deployment(d.DeploymentID).State)
	}
	// Second failure on the same target must not duplicate the open alert.
	e.st.RaiseAlert(ctx, "warning", "install_failed", "target", d.DeploymentID+"/"+bad.id, "dup")
	var again []store.Alert
	e.api("GET", "/api/alerts?open=1", tokViewer, nil, &again)
	if len(again) != len(alerts) {
		t.Fatalf("duplicate open alert created: %d vs %d", len(again), len(alerts))
	}
	// Sweep: endpoints silent for 2h → offline alert.
	real := e.st.Now
	e.st.Now = func() time.Time { return real().Add(2 * time.Hour) }
	if err := e.st.SweepAlerts(ctx, store.DefaultThresholds); err != nil {
		t.Fatal(err)
	}
	e.st.Now = real
	alerts = nil
	e.api("GET", "/api/alerts?open=1", tokViewer, nil, &alerts)
	found := false
	for _, a := range alerts {
		if a.Kind == "endpoints_offline" && strings.Contains(a.Message, "2 endpoint") {
			found = true
		}
	}
	if !found {
		t.Fatalf("offline sweep alert missing: %+v", alerts)
	}
	// Delivery to the internal webhook.
	sctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { e.srvHandler.RunAlerts(sctx, time.Hour); close(done) }()
	time.Sleep(300 * time.Millisecond)
	cancel()
	<-done
	mu.Lock()
	n := len(hooks)
	mu.Unlock()
	if n < 3 {
		t.Fatalf("expected warning+critical alerts delivered to webhook, got %d", n)
	}
	if c := e.api("POST", "/api/alerts/"+itoa(alerts[0].ID)+"/ack", tokViewer, map[string]string{"reason": "x"}, nil); c != 403 {
		t.Fatalf("viewer ack: %d", c)
	}
	if c := e.api("POST", "/api/alerts/"+itoa(alerts[0].ID)+"/ack", tokOperator, map[string]string{"reason": "investigating"}, nil); c != 200 {
		t.Fatalf("ack: %d", c)
	}

	// ---- metrics ----
	if c := e.api("GET", "/metrics", "", nil, nil); c != 401 {
		t.Fatalf("metrics without token: %d", c)
	}
	req, _ = http.NewRequest("GET", e.srv.URL+"/metrics", nil)
	req.Header.Set("Authorization", "Bearer prom-secret")
	resp, _ = http.DefaultClient.Do(req)
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	for _, want := range []string{`offpatch_endpoints{status="compliant"}`, `offpatch_targets_overdue{severity="critical"} 1`, "offpatch_audit_chain_ok 1", "offpatch_fleet_reporting_percent"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("metrics missing %q", want)
		}
	}
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}
