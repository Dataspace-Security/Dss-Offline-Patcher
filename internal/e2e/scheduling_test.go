package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"offpatch/internal/agent"
	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

type checkinResp struct {
	Assignments      []store.Assignment `json:"assignments"`
	RebootNow        bool               `json:"reboot_now"`
	DownloadRateKbps int                `json:"download_rate_kbps"`
}

// rawCheckin checks in without processing assignments (lab bearer auth).
func (e *env) rawCheckin(a *simAgent) checkinResp {
	e.t.Helper()
	var r checkinResp
	if c := e.api("POST", "/api/agent/checkin", a.secret, store.CheckinRequest{Hostname: "h", Build: 19045, Arch: "x64", Inventory: []store.InventoryItem{}}, &r); c != 200 {
		e.t.Fatalf("checkin: %d", c)
	}
	return r
}

func (e *env) approve(id string) {
	e.t.Helper()
	if c := e.api("POST", "/api/packages/"+id+"/approve", tokApprover, map[string]string{"reason": "CAB"}, nil); c != 200 {
		e.t.Fatalf("approve %s: %d", id, c)
	}
}

func (e *env) deploy(n store.NewDeployment) store.Deployment {
	e.t.Helper()
	if n.MaxFailurePct == 0 {
		n.MaxFailurePct = 100
	}
	var d store.Deployment
	if c := e.api("POST", "/api/deployments", tokOperator, n, &d); c != 201 {
		e.t.Fatalf("deploy: %d", c)
	}
	return d
}

func hhmm(t time.Time) string { return t.UTC().Format("15:04") }

func TestScheduling(t *testing.T) {
	e := newEnvOpts(t, false, `"download_rate_kbps": 800, "site_download_kbps": {"hq": 4000},`)
	pk := map[string]manifest.Package{
		"KB5000101-x64": msuPkg("KB5000101-x64", "KB5000101"),
		"KB5000102-x64": msuPkg("KB5000102-x64", "KB5000102", "KB5000101"),
		"KB5000103-x64": msuPkg("KB5000103-x64", "KB5000103", "KB5000102"),
		"KB5000201-x64": msuPkg("KB5000201-x64", "KB5000201"),
		"KB5000301-x64": msuPkg("KB5000301-x64", "KB5000301"),
		"KB5000401-x64": msuPkg("KB5000401-x64", "KB5000401"),
	}
	files := map[string]string{}
	for id := range pk {
		files[id] = e.payload(strings.ToLower(id)+".msu", "payload "+id)
	}
	if b := e.transferAndIntake(e.bundle(bundleOpts{seq: 1}, pk, files)); b.State != "validated" {
		t.Fatalf("intake %+v", b)
	}
	for id := range pk {
		e.approve(id)
	}
	now := time.Now().UTC()

	// ---- maintenance windows + deadline + reboot policy ----
	night := e.enroll("pc-night", []string{"night"}, agent.SimConfig{})
	day := e.enroll("pc-day", []string{"day"}, agent.SimConfig{Reboot: true})
	free := e.enroll("pc-free", []string{"free"}, agent.SimConfig{})
	var w store.MaintenanceWindow
	if c := e.api("POST", "/api/maintenance-windows", tokOperator, store.MaintenanceWindow{Name: "closed now", Groups: []string{"night"},
		Days: []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}, Start: hhmm(now.Add(2 * time.Hour)), End: hhmm(now.Add(3 * time.Hour)), Timezone: "UTC"}, &w); c != 201 {
		t.Fatalf("create window: %d", c)
	}
	e.api("POST", "/api/maintenance-windows", tokOperator, store.MaintenanceWindow{Name: "open now", Groups: []string{"day"},
		Days: []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}, Start: hhmm(now.Add(-time.Hour)), End: hhmm(now.Add(time.Hour)), Timezone: "UTC", AllowReboot: true}, nil)
	if c := e.api("POST", "/api/maintenance-windows", tokOperator, store.MaintenanceWindow{Name: "bad", Groups: []string{"x"}, Days: []string{"funday"}, Start: "25:00", End: "01:00", Timezone: "Mars/Base"}, nil); c != 400 {
		t.Fatalf("invalid window accepted: %d", c)
	}
	all := []store.Ring{{Name: "all", Groups: []string{"all"}}}
	d1 := e.deploy(store.NewDeployment{PackageID: "KB5000201-x64", Name: "windowed", Rings: all, RebootPolicy: "in_window"})
	if n := len(e.rawCheckin(night).Assignments); n != 0 {
		t.Fatalf("endpoint outside its window got %d assignments", n)
	}
	if n := len(e.rawCheckin(free).Assignments); n != 1 {
		t.Fatalf("endpoint without windows should get work: %d", n)
	}
	r := e.rawCheckin(day)
	if len(r.Assignments) != 1 || !r.Assignments[0].RebootAllowed {
		t.Fatalf("endpoint in a reboot-allowed window: %+v", r.Assignments)
	}
	if r.DownloadRateKbps != 4000 {
		t.Fatalf("site bandwidth override: %d", r.DownloadRateKbps)
	}
	e.cycle(day) // installs → pending_reboot → reboots (sim) immediately
	simState := func(a *simAgent) map[string]any {
		b, _ := os.ReadFile(filepath.Join(a.dir, "sim-state.json"))
		m := map[string]any{}
		json.Unmarshal(b, &m)
		return m
	}
	if simState(day)["reboots"] != float64(1) {
		t.Fatalf("agent should have rebooted inside its window: %v", simState(day))
	}
	e.cycle(day)
	if s := targetState(e.deployment(d1.DeploymentID), day.id); s != "verified" {
		t.Fatalf("after reboot: %s", s)
	}
	// Past deadline: windows no longer hold the install back.
	e.deploy(store.NewDeployment{PackageID: "KB5000301-x64", Name: "overdue", Rings: all, Deadline: now.Add(-time.Minute).Format(time.RFC3339)})
	found := false
	for _, a := range e.rawCheckin(night).Assignments {
		if a.PackageID == "KB5000301-x64" {
			found = true
		}
		if a.PackageID == "KB5000201-x64" {
			t.Fatal("non-deadline deployment ignored the window")
		}
	}
	if !found {
		t.Fatal("past-deadline deployment should bypass the closed window")
	}

	// ---- concurrency cap ----
	c1 := e.enroll("pc-c1", []string{"cap"}, agent.SimConfig{})
	c2 := e.enroll("pc-c2", []string{"cap"}, agent.SimConfig{})
	e.deploy(store.NewDeployment{PackageID: "KB5000401-x64", Name: "capped", Rings: []store.Ring{{Name: "cap", Groups: []string{"cap"}}}, MaxConcurrent: 1})
	has := func(r checkinResp) bool {
		for _, a := range r.Assignments {
			if a.PackageID == "KB5000401-x64" {
				return true
			}
		}
		return false
	}
	if !has(e.rawCheckin(c1)) {
		t.Fatal("first endpoint should get the capped assignment")
	}
	if has(e.rawCheckin(c2)) {
		t.Fatal("second endpoint exceeded max_concurrent=1")
	}
	if !has(e.rawCheckin(c1)) {
		t.Fatal("lease holder keeps its assignment")
	}

	// ---- transitive supersedence: KB...103 supersedes 102 supersedes 101 ----
	old := e.enroll("pc-old", []string{"chain"}, agent.SimConfig{})
	os.WriteFile(filepath.Join(old.dir, "sim-state.json"), []byte(`{"kbs":["KB5000103"]}`), 0o600)
	e.cycle(old)
	dc := e.deploy(store.NewDeployment{PackageID: "KB5000101-x64", Name: "old", Rings: []store.Ring{{Name: "chain", Groups: []string{"chain"}}}})
	dd := e.deployment(dc.DeploymentID)
	if targetState(dd, old.id) != "verified" || !strings.Contains(dd.Targets[0].Detail, "KB5000103") {
		t.Fatalf("transitively superseded patch should verify: %+v", dd.Targets)
	}

	// ---- health checks feed auto-pause ----
	h1 := e.enroll("pc-h1", []string{"health"}, agent.SimConfig{UnhealthyServices: []string{"Spooler"}})
	e.enroll("pc-h2", []string{"health"}, agent.SimConfig{})
	if c := e.api("POST", "/api/deployments", tokOperator, store.NewDeployment{PackageID: "KB5000102-x64", Name: "bad check", Rings: all,
		HealthChecks: []store.HealthCheck{{Type: "run_script", Name: "rm -rf /"}}, MaxFailurePct: 10}, nil); c != 400 {
		t.Fatalf("arbitrary health check type accepted: %d", c)
	}
	dh := e.deploy(store.NewDeployment{PackageID: "KB5000102-x64", Name: "healthy?", Rings: []store.Ring{{Name: "h", Groups: []string{"health"}}},
		HealthChecks: []store.HealthCheck{{Type: "service_running", Name: "Spooler"}}, MaxFailurePct: 10})
	e.cycle(h1)
	dd = e.deployment(dh.DeploymentID)
	var ht store.Target
	for _, x := range dd.Targets {
		if x.EndpointID == h1.id {
			ht = x
		}
	}
	if ht.Health != "failed" || !strings.Contains(ht.HealthDetail, "Spooler") {
		t.Fatalf("health result not recorded: %+v", ht)
	}
	if dd.State != "paused" || !strings.Contains(dd.StateReason, "health check") {
		t.Fatalf("health failure should auto-pause: %s %q", dd.State, dd.StateReason)
	}
}
