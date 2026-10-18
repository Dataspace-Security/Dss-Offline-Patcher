package store

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"offpatch/internal/manifest"
)

// P2 (docs/proposals p2 contract): store side.

func openAlerts(t *testing.T, s *Store, kind string) []Alert {
	t.Helper()
	as, err := s.ListAlerts(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	var out []Alert
	for _, a := range as {
		if a.Kind == kind {
			out = append(out, a)
		}
	}
	return out
}

func TestHostList(t *testing.T) {
	if got := HostList([]string{"c", "a", "b"}); got != "a, b, c" {
		t.Errorf("3: %q", got)
	}
	if got := HostList([]string{"h7", "h1", "h2", "h3", "h4", "h5", "h6"}); got != "h1, h2, h3, h4, h5 +2 more" {
		t.Errorf("7: %q", got)
	}
}

// D: offline endpoints are named (five, then "+N more") with endpoint_ids
// in details; the alert follows the host list while open and closes itself
// (system:scheduler, audited) when every endpoint is back.
func TestConditionAlertsNameHostsAndResolve(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	clock := time.Now().UTC()
	s.Now = func() time.Time { return clock }
	for i := 1; i <= 7; i++ {
		addEndpoint(t, s, fmt.Sprintf("e-%d", i), []string{"pilot"}, []InventoryItem{})
	}
	th := Thresholds{OfflineAfter: time.Hour, StaleAfter: 48 * time.Hour}
	clock = clock.Add(2 * time.Hour)
	if err := s.SweepAlerts(ctx, th); err != nil {
		t.Fatal(err)
	}
	as := openAlerts(t, s, "endpoints_offline")
	if len(as) != 1 || !strings.Contains(as[0].Message, "7 endpoint(s)") || !strings.HasSuffix(as[0].Message, "host-e-1, host-e-2, host-e-3, host-e-4, host-e-5 +2 more") {
		t.Fatalf("offline alert: %+v", as)
	}
	if ids, _ := as[0].Details["endpoint_ids"].([]any); len(ids) != 7 || ids[0] != "e-1" {
		t.Errorf("endpoint_ids: %v", as[0].Details)
	}
	first := as[0].ID
	// Five come back: same alert, updated message.
	for i := 1; i <= 5; i++ {
		checkin(t, s, fmt.Sprintf("e-%d", i), []InventoryItem{}, false)
	}
	if err := s.SweepAlerts(ctx, th); err != nil {
		t.Fatal(err)
	}
	as = openAlerts(t, s, "endpoints_offline")
	if len(as) != 1 || as[0].ID != first || !strings.HasSuffix(as[0].Message, "2 endpoint(s) have not checked in recently and are NOT counted as compliant: host-e-6, host-e-7") {
		t.Fatalf("updated: %+v", as)
	}
	// All back: resolved, out of the open list, audited.
	checkin(t, s, "e-6", []InventoryItem{}, false)
	checkin(t, s, "e-7", []InventoryItem{}, false)
	if err := s.SweepAlerts(ctx, th); err != nil {
		t.Fatal(err)
	}
	if as := openAlerts(t, s, "endpoints_offline"); len(as) != 0 {
		t.Fatalf("still open: %+v", as)
	}
	all, _ := s.ListAlerts(ctx, false)
	var a Alert
	for _, x := range all {
		if x.ID == first {
			a = x
		}
	}
	if a.ResolvedAt == "" || a.ResolvedBy != "system:scheduler" || a.AcknowledgedBy != "system:scheduler" {
		t.Errorf("resolved alert: %+v", a)
	}
	if ev := hasAudit(auditActions(t, s, "endpoints_offline"), "alert.resolved|system:scheduler|"); ev == "" {
		t.Error("resolve not audited")
	}
	// The condition returns: a new alert.
	clock = clock.Add(2 * time.Hour)
	if err := s.SweepAlerts(ctx, th); err != nil {
		t.Fatal(err)
	}
	if as := openAlerts(t, s, "endpoints_offline"); len(as) != 1 || as[0].ID == first {
		t.Errorf("raised again: %+v", as)
	}
}

// D: install_failed closes once the target verified; lost_after_install
// once every lost endpoint is back.
func TestTargetAlertsResolve(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	addPackage(t, s, Package{PackageID: "Acme-3.0", Kind: "msi", Version: "3.0.0", PackageName: "Acme App", ProductCode: "{A}"})
	addEndpoint(t, s, "e-1", []string{"pilot"}, acmeOld)
	d, err := s.CreateDeployment(ctx, "user:otto", NewDeployment{PackageID: "Acme-3.0", Name: "acme", Rings: []Ring{{Name: "all", Groups: []string{"all"}}}, MaxFailurePct: 100, MaxRetries: 3})
	if err != nil {
		t.Fatal(err)
	}
	report(t, s, d.DeploymentID, "e-1", "Acme-3.0", "installing", "", 0)
	report(t, s, d.DeploymentID, "e-1", "Acme-3.0", "failed", "msiexec exit 1603", 1603)
	if as := openAlerts(t, s, "install_failed"); len(as) != 1 {
		t.Fatalf("install_failed: %+v", as)
	}
	if err := s.SweepAlerts(ctx, Thresholds{}); err != nil {
		t.Fatal(err)
	}
	if as := openAlerts(t, s, "install_failed"); len(as) != 1 {
		t.Fatal("resolved while the target is still failed")
	}
	checkin(t, s, "e-1", acmeCurrent, false) // a retry worked: verified
	if err := s.SweepAlerts(ctx, Thresholds{}); err != nil {
		t.Fatal(err)
	}
	if as := openAlerts(t, s, "install_failed"); len(as) != 0 {
		t.Errorf("install_failed not resolved after verification: %+v", as)
	}
	// lost_after_install without lost targets left: resolved.
	if err := s.RaiseAlert(ctx, "critical", "lost_after_install", "deployment", d.DeploymentID, "lost"); err != nil {
		t.Fatal(err)
	}
	if err := s.SweepAlerts(ctx, Thresholds{}); err != nil {
		t.Fatal(err)
	}
	if as := openAlerts(t, s, "lost_after_install"); len(as) != 0 {
		t.Errorf("lost_after_install not resolved: %+v", as)
	}
}

// B: an item is "stale" when the newest acquisition run finished more than
// 10 minutes after the request and did not list it.
func TestStaleRequest(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	created := time.Date(2026, 10, 17, 8, 0, 0, 0, time.UTC)
	rec := func(id string) {
		t.Helper()
		if err := s.RecordAcqRequest(ctx, AcqRequestRecord{RequestID: id, CreatedAt: created.Format(time.RFC3339), CreatedBy: "user:otto",
			Items: []AcqRequestItem{{Kind: "app", Key: "Microsoft.Edge", Version: "141.0"}}},
			Ev{Actor: "user:otto", Action: "acquisition.request_exported", ObjectType: "acquisition_request", ObjectID: id}); err != nil {
			t.Fatal(err)
		}
	}
	status := func(id string) AcqRequestItem {
		t.Helper()
		list, err := s.ListAcqRequests(ctx, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range list {
			if r.RequestID == id {
				return r.Items[0]
			}
		}
		t.Fatalf("no %s", id)
		return AcqRequestItem{}
	}
	run := func(finished time.Time, report string) {
		t.Helper()
		if err := s.RecordAcquisition(ctx, "acq-zone-1", finished.Format(time.RFC3339), "ok", "k", []byte(report), "ok"); err != nil {
			t.Fatal(err)
		}
	}
	rec("req-a")
	if it := status("req-a"); it.Status != "requested" {
		t.Fatalf("no run yet: %+v", it)
	}
	// A run finishing within the grace may have started before the request.
	run(created.Add(5*time.Minute), `{"feeds":[]}`)
	if it := status("req-a"); it.Status != "requested" {
		t.Fatalf("within grace: %+v", it)
	}
	run(created.Add(time.Hour), `{"feeds":[{"type":"app","name":"x"}]}`)
	if it := status("req-a"); it.Status != "stale" || it.Reason != "the acquisition run at 2026-10-17T09:00:00Z did not pick this request up" {
		t.Fatalf("missed: %+v", it)
	}
	refs, _ := s.AcqRequestRefs(ctx)
	if r := refs[AcqRefKey("app", "microsoft.edge")]; r.Status != "stale" || r.Reason == "" {
		t.Errorf("ref: %+v", r)
	}
	// The next run lists it (request feed): seen, not stale.
	run(created.Add(2*time.Hour), `{"feeds":[{"type":"request","name":"req-a","status":"new"}]}`)
	if it := status("req-a"); it.Status != "seen" {
		t.Fatalf("picked up: %+v", it)
	}
	// Fetched (item result) and a later run that no longer lists it (the
	// request was archived): on its way, not stale.
	run(created.Add(3*time.Hour), `{"feeds":[],"items":[{"request_id":"req-a","kind":"app","key":"Microsoft.Edge","version":"141.0","result":"fetched"}]}`)
	run(created.Add(4*time.Hour), `{"feeds":[]}`)
	if it := status("req-a"); it.Status != "seen" {
		t.Fatalf("on its way: %+v", it)
	}
}

// E: a Windows CU with expected_ubr verifies by build revision when the
// endpoint runs its min_build at that UBR or later, even without the KB in
// inventory.
func TestVerifyByUBR(t *testing.T) {
	p := Package{Kind: "msu", KB: "KB5099999", ExpectedUBR: 9711, Applicability: manifest.Applicability{OS: "windows", Arch: "x64", MinBuild: 26300, MaxBuild: 26300}}
	cases := []struct {
		osv   string
		build int
		want  bool
	}{
		{"Windows 11 Pro 25H2 (26300.9711)", 26300, true},
		{"Windows 11 Pro 25H2 (26300.9800)", 26300, true},
		{"Windows 11 Pro 25H2 (26300.9700)", 26300, false},
		{"Windows 11 Pro 24H2 (26100.9711)", 26100, false},
		{"Windows 11 Pro 25H2", 26300, false},
	}
	for _, c := range cases {
		ok, why, ev := presentOn(nil, osFacts(c.osv, c.build), p, nil)
		if ok != c.want {
			t.Errorf("%s: %v (%s)", c.osv, ok, why)
		}
		if ok && (ev != "os_version build 26300."+c.osv[len(c.osv)-5:len(c.osv)-1] || !strings.Contains(why, "26300.9711")) {
			t.Errorf("evidence %q / %q", ev, why)
		}
	}
	p.ExpectedUBR = 0
	if ok, _, _ := presentOn(nil, osFacts("Windows 11 Pro 25H2 (26300.9800)", 26300), p, nil); ok {
		t.Error("no expected_ubr: verify by KB only")
	}
}

// E: through check-in, with the evidence kept on the target and in the
// evidence report; F: a per-user install counts like a machine-wide one.
func TestUBRCheckinEvidenceAndUserScope(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	addPackage(t, s, Package{PackageID: "KB5099999-x64", Kind: "msu", KB: "KB5099999", Version: "1", ExpectedUBR: 9711,
		Applicability: manifest.Applicability{OS: "windows", Arch: "x64", MinBuild: 19045, MaxBuild: 19045}})
	addPackage(t, s, Package{PackageID: "Acme-3.0", Kind: "msi", Version: "3.0.0", PackageName: "Acme App", ProductCode: "{A}"})
	if _, err := s.db.Exec(`INSERT INTO package_approvals(package_id, approver, reason, at) VALUES('KB5099999-x64','user:alice','ok',?)`, s.now()); err != nil {
		t.Fatal(err)
	}
	userOld := []InventoryItem{{Kind: "product", ID: "Acme", Name: "Acme App", Version: "2.0.0", Scope: "user"}}
	addEndpoint(t, s, "e-1", []string{"pilot"}, userOld)
	needs, err := s.Needs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n := needs["Acme-3.0"]; n.Needed != 1 {
		t.Errorf("per-user install not counted as needing the update: %+v", n)
	}
	d, err := s.CreateDeployment(ctx, "user:otto", NewDeployment{PackageID: "KB5099999-x64", Name: "lcu", Rings: []Ring{{Name: "all", Groups: []string{"all"}}}, MaxFailurePct: 100})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Checkin(ctx, "e-1", CheckinRequest{Hostname: "host-e-1", OSVersion: "Windows 10 Pro 22H2 (19045.9711)", Build: 19045, Arch: "x64", Inventory: userOld}); err != nil {
		t.Fatal(err)
	}
	dd, err := s.GetDeployment(ctx, d.DeploymentID)
	if err != nil {
		t.Fatal(err)
	}
	if tg := dd.Targets[0]; tg.State != "verified" || tg.Evidence != "os_version build 19045.9711" || !strings.Contains(tg.Detail, "[os_version build 19045.9711]") {
		t.Fatalf("UBR target: %+v", tg)
	}
	// Per-user Acme 3.0 verifies the msi like a machine-wide install.
	d2, err := s.CreateDeployment(ctx, "user:otto", NewDeployment{PackageID: "Acme-3.0", Name: "acme", Rings: []Ring{{Name: "all", Groups: []string{"all"}}}, MaxFailurePct: 100})
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := targetRow(t, s, d2.DeploymentID, "e-1"); st != "pending" {
		t.Fatalf("per-user install not targeted: %s", st)
	}
	userNew := []InventoryItem{{Kind: "product", ID: "Acme", Name: "Acme App", Version: "3.0.0", Scope: "user"}}
	if _, err := s.Checkin(ctx, "e-1", CheckinRequest{Hostname: "host-e-1", OSVersion: "Windows 10 Pro 22H2 (19045.9711)", Build: 19045, Arch: "x64", Inventory: userNew}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.TargetEvidenceReport(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]TargetEvidence{}
	for _, r := range rows {
		got[r.PackageID] = r
	}
	if r := got["Acme-3.0"]; r.State != "verified" || r.Evidence != `product Acme "Acme App" 3.0.0 (user)` || r.VerifiedAt == "" || r.Hostname != "host-e-1" {
		t.Errorf("acme evidence: %+v", r)
	}
	if r := got["KB5099999-x64"]; r.ApprovedBy != "user:alice" || r.DeploymentID != d.DeploymentID || r.Title == "" {
		t.Errorf("lcu evidence: %+v", r)
	}
}

// E: compliance counts endpoints that need a package but are not targeted
// as outstanding (the denominator is "needed", not "targeted").
func TestComplianceNeededDenominator(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	addPackage(t, s, Package{PackageID: "Acme-3.0", Kind: "msi", Version: "3.0.0", PackageName: "Acme App", ProductCode: "{A}"})
	addEndpoint(t, s, "e-1", []string{"pilot"}, acmeOld)
	addEndpoint(t, s, "e-2", []string{"broad"}, acmeOld)
	addEndpoint(t, s, "e-3", []string{"broad"}, acmeOld)
	if _, err := s.CreateDeployment(ctx, "user:otto", NewDeployment{PackageID: "Acme-3.0", Name: "acme", Rings: []Ring{{Name: "pilot", Groups: []string{"pilot"}}}, MaxFailurePct: 100}); err != nil {
		t.Fatal(err)
	}
	checkin(t, s, "e-1", acmeCurrent, false) // verified
	if _, err := s.CreateException(ctx, "user:alice", NewException{EndpointID: "e-3", PackageID: "Acme-3.0", Owner: "ops", Reason: "kiosk",
		CompensatingControls: "isolated", ExpiresAt: time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
	rep, err := s.Compliance(ctx, Thresholds{})
	if err != nil {
		t.Fatal(err)
	}
	var pr PackageReport
	for _, p := range rep.Packages {
		if p.PackageID == "Acme-3.0" {
			pr = p
		}
	}
	if pr.Targets != 2 || pr.Verified != 1 || pr.Outstanding != 1 || pr.NotTargeted != 1 || pr.Needed != 2 || pr.Exceptions != 1 || pr.PctComplete != 50 {
		t.Errorf("compliance: %+v", pr)
	}
}

// E: "installed" that inventory never confirms within 6 h: flagged with a
// detail, alert install_unverified naming the host, counts towards the
// auto-pause; the alert closes once inventory confirms it.
func TestInstallUnverified(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	clock := time.Now().UTC()
	s.Now = func() time.Time { return clock }
	addPackage(t, s, Package{PackageID: "Acme-3.0", Kind: "msi", Version: "3.0.0", PackageName: "Acme App", ProductCode: "{A}"})
	addEndpoint(t, s, "e-1", []string{"pilot"}, acmeOld)
	addEndpoint(t, s, "e-2", []string{"pilot"}, acmeOld)
	d, err := s.CreateDeployment(ctx, "user:otto", NewDeployment{PackageID: "Acme-3.0", Name: "acme", Rings: []Ring{{Name: "all", Groups: []string{"all"}}}, MaxFailurePct: 40})
	if err != nil {
		t.Fatal(err)
	}
	report(t, s, d.DeploymentID, "e-1", "Acme-3.0", "installing", "", 0)
	report(t, s, d.DeploymentID, "e-1", "Acme-3.0", "installed", "exit 0", 0)
	th := Thresholds{OfflineAfter: 30 * 24 * time.Hour, StaleAfter: 30 * 24 * time.Hour}
	clock = clock.Add(5 * time.Hour)
	checkin(t, s, "e-1", acmeOld, false) // still the old version
	if err := s.SweepAlerts(ctx, th); err != nil {
		t.Fatal(err)
	}
	if as := openAlerts(t, s, "install_unverified"); len(as) != 0 {
		t.Fatal("flagged before 6 h")
	}
	clock = clock.Add(2 * time.Hour)
	checkin(t, s, "e-1", acmeOld, false)
	if err := s.SweepAlerts(ctx, th); err != nil {
		t.Fatal(err)
	}
	dd, _ := s.GetDeployment(ctx, d.DeploymentID)
	for _, tg := range dd.Targets {
		if tg.EndpointID == "e-1" && (tg.State != "installed" || tg.Detail != UnverifiedDetail) {
			t.Errorf("target: %+v", tg)
		}
	}
	as := openAlerts(t, s, "install_unverified")
	if len(as) != 1 || !strings.HasSuffix(as[0].Message, ": host-e-1") || as[0].ObjectID != d.DeploymentID {
		t.Fatalf("alert: %+v", as)
	}
	// 1 of 2 not confirmed > 40 %: paused.
	if st, _ := depState(t, s, d.DeploymentID); st != "paused" {
		t.Errorf("deployment: %s", st)
	}
	if ev := hasAudit(auditActions(t, s, d.DeploymentID+"/e-1"), "target.install_unverified|system:scheduler|"); ev == "" {
		t.Error("not audited")
	}
	// A second sweep does not re-flag or re-audit.
	n := len(auditActions(t, s, d.DeploymentID+"/e-1"))
	if err := s.SweepAlerts(ctx, th); err != nil {
		t.Fatal(err)
	}
	if m := len(auditActions(t, s, d.DeploymentID+"/e-1")); m != n {
		t.Errorf("re-flagged: %d -> %d audit events", n, m)
	}
	checkin(t, s, "e-1", acmeCurrent, false) // inventory confirms it after all
	if err := s.SweepAlerts(ctx, th); err != nil {
		t.Fatal(err)
	}
	if as := openAlerts(t, s, "install_unverified"); len(as) != 0 {
		t.Errorf("not resolved: %+v", as)
	}
}

// F (server part): health checks re-run after the restart reach a target
// that already verified: only health is recorded (state stays verified, no
// 409); a pass closes an open health_check_failed alert.
func TestHealthAfterRestartOnVerifiedTarget(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	addPackage(t, s, Package{PackageID: "Acme-3.0", Kind: "msi", Version: "3.0.0", PackageName: "Acme App", ProductCode: "{A}"})
	addEndpoint(t, s, "e-1", []string{"pilot"}, acmeOld)
	addEndpoint(t, s, "e-2", []string{"pilot"}, acmeOld)
	d, err := s.CreateDeployment(ctx, "user:otto", NewDeployment{PackageID: "Acme-3.0", Name: "acme", Rings: []Ring{{Name: "all", Groups: []string{"all"}}}, MaxFailurePct: 100})
	if err != nil {
		t.Fatal(err)
	}
	report(t, s, d.DeploymentID, "e-1", "Acme-3.0", "installing", "", 0)
	if err := s.ReportTarget(ctx, "e-1", Report{DeploymentID: d.DeploymentID, PackageID: "Acme-3.0", State: "pending_reboot", Detail: "restart required",
		Health: "failed", HealthDetail: "service AcmeSvc not running"}); err != nil {
		t.Fatal(err)
	}
	if as := openAlerts(t, s, "health_check_failed"); len(as) != 1 {
		t.Fatalf("health alert: %+v", as)
	}
	checkin(t, s, "e-1", acmeCurrent, false) // restarted, inventory confirms it
	if st, _ := targetRow(t, s, d.DeploymentID, "e-1"); st != "verified" {
		t.Fatalf("state: %s", st)
	}
	// Checks after the restart pass: recorded, state kept, alert closed.
	if err := s.ReportTarget(ctx, "e-1", Report{DeploymentID: d.DeploymentID, PackageID: "Acme-3.0", State: "installed", Detail: "installed; restart completed",
		Health: "ok", HealthDetail: "after restart: service AcmeSvc running"}); err != nil {
		t.Fatalf("health on verified target: %v", err)
	}
	var st, health, hd string
	s.db.QueryRow(`SELECT state, health, health_detail FROM targets WHERE deployment_id=? AND endpoint_id='e-1'`, d.DeploymentID).Scan(&st, &health, &hd)
	if st != "verified" || health != "ok" || hd != "after restart: service AcmeSvc running" {
		t.Errorf("target: %s %s %s", st, health, hd)
	}
	if as := openAlerts(t, s, "health_check_failed"); len(as) != 0 {
		t.Errorf("not resolved: %+v", as)
	}
	if ev := hasAudit(auditActions(t, s, "health_check_failed"), "alert.resolved|system:scheduler|"); ev == "" {
		t.Error("resolve not audited")
	}
	// A failure after the restart: alert, state still verified.
	if err := s.ReportTarget(ctx, "e-1", Report{DeploymentID: d.DeploymentID, PackageID: "Acme-3.0", State: "installed", Detail: "installed; restart completed",
		Health: "failed", HealthDetail: "after restart: port 443 not listening"}); err != nil {
		t.Fatal(err)
	}
	if st, _ := targetRow(t, s, d.DeploymentID, "e-1"); st != "verified" {
		t.Errorf("state after failed health: %s", st)
	}
	if as := openAlerts(t, s, "health_check_failed"); len(as) != 1 || !strings.Contains(as[0].Message, "port 443") {
		t.Errorf("failed health alert: %+v", as)
	}
	// Anything else on a verified target is still a conflict.
	if err := s.ReportTarget(ctx, "e-1", Report{DeploymentID: d.DeploymentID, PackageID: "Acme-3.0", State: "installed", Detail: "again"}); err == nil {
		t.Error("plain report on a verified target accepted")
	}
}
