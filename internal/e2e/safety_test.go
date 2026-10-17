package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	"offpatch/internal/agent"
	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

func targetOf(d store.DeploymentDetail, endpointID string) store.Target {
	for _, t := range d.Targets {
		if t.EndpointID == endpointID {
			return t
		}
	}
	return store.Target{}
}

func (e *env) endpointStatus(id string) string {
	e.t.Helper()
	var ep store.EndpointDetail
	if c := e.api("GET", "/api/endpoints/"+id, tokViewer, nil, &ep); c != 200 {
		e.t.Fatalf("get endpoint %d", c)
	}
	return ep.Status
}

func simHasKB(a *simAgent, kb string) bool {
	inv, _, _ := a.sim.Inventory()
	for _, it := range inv {
		if it.Kind == "kb" && it.ID == kb {
			return true
		}
	}
	return false
}

func (e *env) intakeApproved(pk map[string]manifest.Package, seq int64) {
	e.t.Helper()
	files := map[string]string{}
	for id := range pk {
		files[id] = e.payload(strings.ToLower(id)+".bin", "payload "+id+strings.Repeat("z", 1024))
	}
	if b := e.transferAndIntake(e.bundle(bundleOpts{seq: seq}, pk, files)); b.State != "validated" {
		e.t.Fatalf("intake %+v", b)
	}
	for id := range pk {
		e.approve(id)
	}
}

// Low disk or a laptop on battery defers the install (not a failure, no
// auto-pause) until conditions are met at a later check-in.
func TestPreinstallDeferral(t *testing.T) {
	e := newEnvOpts(t, false, `"preinstall": {"min_free_disk_mb": {"windows": 5120}, "min_battery_pct": 50},`)
	e.intakeApproved(map[string]manifest.Package{"KB5009001-x64": msuPkg("KB5009001-x64", "KB5009001")}, 1)
	disk := e.enroll("pc-full-disk", []string{"pilot"}, agent.SimConfig{FreeDiskBytes: 4 << 30})
	batt := e.enroll("laptop-batt", []string{"pilot"}, agent.SimConfig{OnBattery: true, BatteryPct: 20})
	ok := e.enroll("laptop-ok", []string{"pilot"}, agent.SimConfig{OnBattery: true, BatteryPct: 80})
	d := e.deploy(store.NewDeployment{PackageID: "KB5009001-x64", Name: "pre", Rings: []store.Ring{{Name: "pilot", Groups: []string{"pilot"}}}, MaxFailurePct: 0})
	for _, a := range []*simAgent{disk, batt, ok} {
		e.cycle(a)
	}
	dd := e.deployment(d.DeploymentID)
	if tg := targetOf(dd, disk.id); tg.State != "deferred" || !strings.Contains(tg.Detail, "free disk space") || !strings.Contains(tg.Detail, "5.0 GB") {
		t.Fatalf("low disk not deferred: %+v", tg)
	}
	if tg := targetOf(dd, batt.id); tg.State != "deferred" || !strings.Contains(tg.Detail, "battery at 20%") {
		t.Fatalf("battery not deferred: %+v", tg)
	}
	if s := targetState(dd, ok.id); s != "installed" {
		t.Fatalf("80%% battery should install: %s", s)
	}
	if dd.State != "active" || dd.Counts["deferred"] != 2 {
		t.Fatalf("deferral must not pause (max_failure_pct 0): %s %v", dd.State, dd.Counts)
	}
	if s := e.endpointStatus(disk.id); s != "noncompliant" {
		t.Fatalf("deferred endpoint status %s", s)
	}
	// Still deferred on the next check-in: no new audit event per check-in.
	var before []store.AuditEvent
	e.api("GET", "/api/audit?object_id="+d.DeploymentID+"/"+disk.id, tokViewer, nil, &before)
	e.cycle(disk)
	var after []store.AuditEvent
	e.api("GET", "/api/audit?object_id="+d.DeploymentID+"/"+disk.id, tokViewer, nil, &after)
	if len(after) != len(before) {
		t.Fatalf("repeated deferral wrote audit events: %d → %d", len(before), len(after))
	}
	// Conditions fixed: installs and verifies.
	disk.sim.SetConditions(50<<30, false, 0)
	batt.sim.SetConditions(0, false, 0) // plugged in
	for _, a := range []*simAgent{disk, batt, ok, disk, batt, ok} {
		e.cycle(a)
	}
	dd = e.deployment(d.DeploymentID)
	for _, a := range []*simAgent{disk, batt, ok} {
		if s := targetState(dd, a.id); s != "verified" {
			t.Fatalf("%s after conditions fixed: %s (%+v)", a.id, s, targetOf(dd, a.id))
		}
	}
	if targetOf(dd, disk.id).Attempts != 1 {
		t.Fatalf("deferrals counted as attempts: %+v", targetOf(dd, disk.id))
	}
}

// An endpoint that stops checking in after an install is lost_after_install:
// it counts towards auto-pause, raises a critical alert naming the host, and
// recovers when the endpoint comes back and verifies.
func TestLostAfterInstall(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.intakeApproved(map[string]manifest.Package{"KB5009101-x64": msuPkg("KB5009101-x64", "KB5009101")}, 1)
	dead := e.enroll("srv-dead", []string{"pilot"}, agent.SimConfig{Reboot: true})
	alive := e.enroll("srv-alive", []string{"pilot"}, agent.SimConfig{Reboot: true})
	d := e.deploy(store.NewDeployment{PackageID: "KB5009101-x64", Name: "lost", Rings: []store.Ring{{Name: "pilot", Groups: []string{"pilot"}}}, MaxFailurePct: 40})
	e.cycle(dead)
	e.cycle(alive)
	if s := targetState(e.deployment(d.DeploymentID), dead.id); s != "pending_reboot" {
		t.Fatalf("expected pending_reboot, got %s", s)
	}
	real := e.st.Now
	defer func() { e.st.Now = real }()
	// One hour later: not lost yet.
	e.st.Now = func() time.Time { return real().Add(time.Hour) }
	if err := e.st.SweepAlerts(ctx, store.DefaultThresholds); err != nil {
		t.Fatal(err)
	}
	if s := targetState(e.deployment(d.DeploymentID), dead.id); s != "pending_reboot" {
		t.Fatalf("lost too early: %s", s)
	}
	// Three hours later: srv-alive kept checking in, srv-dead did not.
	e.st.Now = func() time.Time { return real().Add(3 * time.Hour) }
	if _, err := e.st.Checkin(ctx, alive.id, store.CheckinRequest{Hostname: "srv-alive", Build: 19045, Arch: "x64", RebootPending: true,
		Inventory: []store.InventoryItem{{Kind: "kb", ID: "KB5009101"}}}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.SweepAlerts(ctx, store.DefaultThresholds); err != nil {
		t.Fatal(err)
	}
	dd := e.deployment(d.DeploymentID)
	if s := targetState(dd, dead.id); s != "lost_after_install" {
		t.Fatalf("dead endpoint: %s", s)
	}
	if s := targetState(dd, alive.id); s != "pending_reboot" {
		t.Fatalf("live endpoint must not be lost: %s", s)
	}
	if dd.State != "paused" || !strings.Contains(dd.StateReason, "1 lost after install") {
		t.Fatalf("1/2 lost > 40%% should auto-pause: %s %q", dd.State, dd.StateReason)
	}
	if s := e.endpointStatus(dead.id); s != "lost_after_install" {
		t.Fatalf("endpoint status %s", s)
	}
	var alerts []store.Alert
	e.api("GET", "/api/alerts?open=1", tokViewer, nil, &alerts)
	found := false
	for _, a := range alerts {
		if a.Kind == "lost_after_install" && a.Severity == "critical" && strings.Contains(a.Message, "srv-dead") && !strings.Contains(a.Message, "srv-alive") {
			found = true
		}
	}
	if !found {
		t.Fatalf("critical lost alert naming srv-dead missing: %+v", alerts)
	}
	// It comes back (reboot still pending once), then verifies.
	e.st.Now = real
	e.cycle(dead)
	if s := targetState(e.deployment(d.DeploymentID), dead.id); s != "pending_reboot" {
		t.Fatalf("after return: %s", s)
	}
	e.cycle(dead)
	if s := targetState(e.deployment(d.DeploymentID), dead.id); s != "verified" {
		t.Fatalf("after reboot: %s", s)
	}
	if s := e.endpointStatus(dead.id); s == "lost_after_install" {
		t.Fatalf("endpoint still lost after recovery")
	}
}

// Rollback: an operator deploys an uninstall of an approved package through
// the normal rings; agents run wusa /uninstall / msiexec /x; verification is
// the package being gone; install targets are marked rolled_back.
func TestRollback(t *testing.T) {
	e := newEnv(t)
	pk := map[string]manifest.Package{
		"KB5009201-x64": msuPkg("KB5009201-x64", "KB5009201"),
		"AcmeApp-3.0": {PackageID: "AcmeApp-3.0", Title: "Acme App 3.0", Vendor: "Acme", Kind: "msi", Version: "3.0", ProductCode: msiGUID,
			Severity: "important", Supersedes: []string{}, Applicability: manifest.Applicability{OS: "windows", Arch: "any"},
			VendorSignature: manifest.VendorSignature{Status: "not_checked"}},
		"Chrome-150": pkgPkg("Chrome-150", "com.google.Chrome", "150.0"),
	}
	e.intakeApproved(pk, 1)
	a1 := e.enroll("pc-rb-1", []string{"pilot"}, agent.SimConfig{})
	a2 := e.enroll("pc-rb-2", []string{"broad"}, agent.SimConfig{FailUninstall: []string{msiGUID}})
	never := e.enroll("pc-rb-never", []string{"late"}, agent.SimConfig{}) // never got the KB
	rings := []store.Ring{{Name: "pilot", Groups: []string{"pilot"}}, {Name: "broad", Groups: []string{"broad", "late"}}}
	inst := e.deploy(store.NewDeployment{PackageID: "KB5009201-x64", Name: "install", Rings: []store.Ring{{Name: "all", Groups: []string{"pilot", "broad"}}}})
	instMSI := e.deploy(store.NewDeployment{PackageID: "AcmeApp-3.0", Name: "install msi", Rings: []store.Ring{{Name: "all", Groups: []string{"pilot", "broad"}}}})
	for _, a := range []*simAgent{a1, a2, a1, a2} {
		e.cycle(a)
	}
	if d := e.deployment(inst.DeploymentID); targetState(d, a1.id) != "verified" || targetState(d, a2.id) != "verified" {
		t.Fatalf("install not verified: %+v", d.Targets)
	}
	e.cycle(never)

	var pkg store.Package
	e.api("GET", "/api/packages/Chrome-150", tokViewer, nil, &pkg)
	if !strings.Contains(pkg.RollbackUnsupported, "no uninstall") {
		t.Fatalf("pkg rollback_unsupported: %q", pkg.RollbackUnsupported)
	}
	rb := store.NewDeployment{PackageID: "KB5009201-x64", Name: "rollback KB5009201", Rings: rings, MaxFailurePct: 100, Operation: "rollback"}
	if c := e.api("POST", "/api/deployments", tokOperator, rb, nil); c != 400 {
		t.Fatalf("rollback without justification: %d", c)
	}
	rb.Justification = "CHG-1234: KB5009201 breaks the core banking client"
	if c := e.api("POST", "/api/deployments", tokOperator, store.NewDeployment{PackageID: "Chrome-150", Name: "rb mac", Rings: rings, Operation: "rollback", Justification: "x"}, nil); c != 409 {
		t.Fatalf("macOS pkg rollback must be refused: %d", c)
	}
	// The MSI install completed, so its rollback may start.
	var dep store.Deployment
	if c := e.api("POST", "/api/deployments", tokOperator, store.NewDeployment{PackageID: "AcmeApp-3.0", Name: "rb msi", Rings: rings, MaxFailurePct: 100, Operation: "rollback", Justification: "x"}, &dep); c != 201 {
		t.Fatalf("msi rollback: %d (install %s)", c, e.deployment(instMSI.DeploymentID).State)
	}
	var rbd store.Deployment
	if c := e.api("POST", "/api/deployments", tokOperator, rb, &rbd); c != 201 {
		t.Fatalf("rollback create: %d", c)
	}
	if rbd.Operation != "rollback" {
		t.Fatalf("operation %q", rbd.Operation)
	}
	if c := e.api("POST", "/api/deployments", tokOperator, store.NewDeployment{PackageID: "KB5009201-x64", Name: "reinstall", Rings: rings, MaxFailurePct: 100}, nil); c != 409 {
		t.Fatalf("install while a rollback is active must be refused: %d", c)
	}
	// Ring 1 (pilot) only.
	e.cycle(a1)
	e.cycle(a2)
	d := e.deployment(rbd.DeploymentID)
	if s := targetState(d, a1.id); s != "installed" {
		t.Fatalf("pilot rollback: %s (%+v)", s, targetOf(d, a1.id))
	}
	if targetState(d, a2.id) != "<none>" || !simHasKB(a2, "KB5009201") {
		t.Fatalf("broad ring rolled back before advance")
	}
	if simHasKB(a1, "KB5009201") {
		t.Fatalf("KB still present on pilot")
	}
	e.cycle(a1)
	if s := targetState(e.deployment(rbd.DeploymentID), a1.id); s != "verified" {
		t.Fatalf("rollback not verified: %s", s)
	}
	if s := targetState(e.deployment(inst.DeploymentID), a1.id); s != "rolled_back" {
		t.Fatalf("install target should be rolled_back: %s", s)
	}
	// Revoking the bad package does not cancel the rollback.
	if c := e.api("POST", "/api/packages/KB5009201-x64/revoke", tokApprover, map[string]string{"reason": "bad patch"}, nil); c != 200 {
		t.Fatalf("revoke %d", c)
	}
	if s := e.deployment(rbd.DeploymentID).State; s != "active" {
		t.Fatalf("rollback cancelled by revoke: %s", s)
	}
	if c := e.api("POST", "/api/deployments/"+rbd.DeploymentID+"/advance", tokOperator, map[string]string{"reason": "pilot ok"}, nil); c != 200 {
		t.Fatalf("advance %d", c)
	}
	for _, a := range []*simAgent{a2, never, a2, never} {
		e.cycle(a)
	}
	d = e.deployment(rbd.DeploymentID)
	if targetState(d, a2.id) != "verified" || simHasKB(a2, "KB5009201") {
		t.Fatalf("broad rollback (revoked package): %+v", targetOf(d, a2.id))
	}
	if s := targetState(d, never.id); s != "not_applicable" {
		t.Fatalf("endpoint without the KB: %s", s)
	}
	if d.State != "completed" {
		t.Fatalf("rollback deployment %s %v", d.State, d.Counts)
	}
	// Reports no longer count the KB as patched on rolled-back endpoints.
	var rep store.ComplianceReport
	e.api("GET", "/api/reports/compliance", tokViewer, nil, &rep)
	for _, p := range rep.Packages {
		if p.PackageID == "KB5009201-x64" && p.Verified != 0 {
			t.Fatalf("report still counts rolled-back endpoints as verified: %+v", p)
		}
	}
	// MSI rollback: uninstall failure is a normal failure (counts toward auto-pause).
	for _, a := range []*simAgent{a1, a1} {
		e.cycle(a)
	}
	e.api("POST", "/api/deployments/"+dep.DeploymentID+"/advance", tokOperator, map[string]string{"reason": "ok"}, nil)
	e.cycle(a2)
	dm := e.deployment(dep.DeploymentID)
	if targetState(dm, a1.id) != "verified" || targetState(dm, a2.id) != "failed" {
		t.Fatalf("msi rollback: %+v", dm.Targets)
	}
}
