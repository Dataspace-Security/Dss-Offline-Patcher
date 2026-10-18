package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"offpatch/internal/manifest"
)

// P1 fixes (docs/proposals/functional-review-*.md): store side.

var acmeOld = []InventoryItem{{Kind: "product", ID: "{OLD}", Name: "Acme App", Version: "2.0.0"}}

func checkin(t *testing.T, s *Store, ep string, inv []InventoryItem, rebootPending bool) CheckinResult {
	t.Helper()
	res, err := s.Checkin(context.Background(), ep, CheckinRequest{Hostname: "host-" + ep, OSVersion: "Windows 10", Build: 19045, Arch: "x64",
		AgentVersion: "1.0", Inventory: inv, RebootPending: rebootPending})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func report(t *testing.T, s *Store, dep, ep, pkg, state, detail string, code int) {
	t.Helper()
	if err := s.ReportTarget(context.Background(), ep, Report{DeploymentID: dep, PackageID: pkg, State: state, Detail: detail, ExitCode: code}); err != nil {
		t.Fatalf("report %s %s: %v", state, detail, err)
	}
}

func auditActions(t *testing.T, s *Store, objectID string) []string {
	t.Helper()
	rows, err := s.db.Query(`SELECT action || '|' || actor || '|' || details FROM audit WHERE object_id=? ORDER BY seq`, objectID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		rows.Scan(&a)
		out = append(out, a)
	}
	return out
}

func hasAudit(evs []string, prefix string) string {
	for _, e := range evs {
		if strings.HasPrefix(e, prefix) {
			return e
		}
	}
	return ""
}

func firstMachines() []Ring {
	return []Ring{{Name: "First machines", Groups: []string{"endpoint:e-1"}}, {Name: "Everything else", Groups: []string{"all"}}}
}

// Item 1: a finished first ring within the failure threshold advances by
// itself (agent report path and sweep path); without auto_advance it waits.
func TestAutoAdvance(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	addPackage(t, s, Package{PackageID: "Acme-3.0", Kind: "msi", Version: "3.0.0", PackageName: "Acme App", ProductCode: "{A}"})
	addEndpoint(t, s, "e-1", []string{"pilot"}, acmeOld)
	addEndpoint(t, s, "e-2", []string{"broad"}, acmeOld)

	create := func(auto bool) Deployment {
		t.Helper()
		d, err := s.CreateDeployment(ctx, "user:otto", NewDeployment{PackageID: "Acme-3.0", Name: "acme", Rings: firstMachines(), MaxFailurePct: 0, MaxRetries: 0, AutoAdvance: auto})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	d := create(true)
	if !d.AutoAdvance || d.CurrentRing != 0 {
		t.Fatalf("created: auto=%v ring=%d", d.AutoAdvance, d.CurrentRing)
	}
	if _, n := targetRow(t, s, d.DeploymentID, "e-1"); n != 0 {
		t.Fatal("e-1 target missing")
	}
	// e-1 is verified by its next check-in: ring 0 finished, 0 failures.
	checkin(t, s, "e-1", acmeCurrent, false)
	if st, ring := depState(t, s, d.DeploymentID); st != "active" || ring != 1 {
		t.Fatalf("after ring 0 finished: state=%s ring=%d (want active, 1)", st, ring)
	}
	if st, _ := targetRow(t, s, d.DeploymentID, "e-2"); st != "pending" {
		t.Errorf("ring 1 endpoint not targeted: %s", st)
	}
	ev := hasAudit(auditActions(t, s, d.DeploymentID), "deployment.advanced|system:scheduler|")
	if ev == "" || !strings.Contains(ev, `"auto":true`) || !strings.Contains(ev, `"ring":1`) {
		t.Errorf("auto advance audit: %q", ev)
	}
	// The final ring finishes: completed as before.
	checkin(t, s, "e-2", acmeCurrent, false)
	if st, _ := depState(t, s, d.DeploymentID); st != "completed" {
		t.Errorf("final ring finished: %s", st)
	}

	// Without auto_advance the finished ring waits for an operator.
	s.db.Exec(`UPDATE endpoints SET inventory=? WHERE endpoint_id IN ('e-1','e-2')`, mustJSON(acmeOld))
	d = create(false)
	checkin(t, s, "e-1", acmeCurrent, false)
	if st, ring := depState(t, s, d.DeploymentID); st != "active" || ring != 0 {
		t.Fatalf("manual rings: state=%s ring=%d", st, ring)
	}
	if _, err := s.DeploymentAction(ctx, "user:otto", d.DeploymentID, "cancel", "test"); err != nil {
		t.Fatal(err)
	}

	// Sweep path: the ring became terminal without an evaluated report.
	s.db.Exec(`UPDATE endpoints SET inventory=? WHERE endpoint_id IN ('e-1','e-2')`, mustJSON(acmeOld))
	d = create(true)
	if _, err := s.db.Exec(`UPDATE targets SET state='not_applicable' WHERE deployment_id=? AND endpoint_id='e-1'`, d.DeploymentID); err != nil {
		t.Fatal(err)
	}
	if err := s.sweepDeployments(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ring := depState(t, s, d.DeploymentID); ring != 1 {
		t.Errorf("sweep did not auto-advance: ring %d", ring)
	}
	if _, err := s.DeploymentAction(ctx, "user:otto", d.DeploymentID, "cancel", "test"); err != nil {
		t.Fatal(err)
	}

	// Over the failure threshold: auto-paused; after an operator resumes,
	// the finished ring still does not advance by itself.
	d = create(true)
	report(t, s, d.DeploymentID, "e-1", "Acme-3.0", "installing", "started", 0)
	report(t, s, d.DeploymentID, "e-1", "Acme-3.0", "failed", "installer exit code 1603", 1603)
	if st, ring := depState(t, s, d.DeploymentID); st != "paused" || ring != 0 {
		t.Fatalf("failed first machine: state=%s ring=%d", st, ring)
	}
	if _, err := s.DeploymentAction(ctx, "user:otto", d.DeploymentID, "resume", "looked at it"); err != nil {
		t.Fatal(err)
	}
	if st, ring := depState(t, s, d.DeploymentID); st != "active" || ring != 0 {
		t.Errorf("over threshold must not auto-advance: state=%s ring=%d", st, ring)
	}
	if _, err := s.DeploymentAction(ctx, "user:otto", d.DeploymentID, "cancel", "test"); err != nil {
		t.Fatal(err)
	}

	// Installed but waiting for a restart (policy never): the first ring
	// counts as succeeded and the rest follows; the final ring waiting for a
	// restart keeps the deployment active (not completed).
	s.db.Exec(`UPDATE endpoints SET inventory=? WHERE endpoint_id IN ('e-1','e-2')`, mustJSON(acmeOld))
	d = create(true)
	report(t, s, d.DeploymentID, "e-1", "Acme-3.0", "installing", "started", 0)
	report(t, s, d.DeploymentID, "e-1", "Acme-3.0", "pending_reboot", "installed; reboot required", 3010)
	if st, ring := depState(t, s, d.DeploymentID); st != "active" || ring != 1 {
		t.Fatalf("restart-pending first ring: state=%s ring=%d (want active, 1)", st, ring)
	}
	report(t, s, d.DeploymentID, "e-2", "Acme-3.0", "installing", "started", 0)
	report(t, s, d.DeploymentID, "e-2", "Acme-3.0", "pending_reboot", "installed; reboot required", 3010)
	if err := s.sweepDeployments(ctx); err != nil {
		t.Fatal(err)
	}
	if st, ring := depState(t, s, d.DeploymentID); st != "active" || ring != 1 {
		t.Errorf("final ring waiting for restarts: state=%s ring=%d (want active, 1)", st, ring)
	}
}

// Item 2: a restart the policy waits for, on an endpoint with no window
// that ever allows restarts, says so; a window that allows restarts clears it.
func TestRebootWithoutWindowDetail(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	addPackage(t, s, Package{PackageID: "Acme-3.0", Kind: "msi", Version: "3.0.0", PackageName: "Acme App", ProductCode: "{A}"})
	addEndpoint(t, s, "e-1", []string{"pilot"}, acmeOld)
	detail := func(dep string) string {
		var d string
		s.db.QueryRow(`SELECT detail FROM targets WHERE deployment_id=? AND endpoint_id='e-1'`, dep).Scan(&d)
		return d
	}
	d, err := s.CreateDeployment(ctx, "user:otto", NewDeployment{PackageID: "Acme-3.0", Name: "acme", Rings: []Ring{{Name: "all", Groups: []string{"all"}}},
		MaxFailurePct: 50, RebootPolicy: "in_window"})
	if err != nil {
		t.Fatal(err)
	}
	report(t, s, d.DeploymentID, "e-1", "Acme-3.0", "installing", "started", 0)
	report(t, s, d.DeploymentID, "e-1", "Acme-3.0", "pending_reboot", "installed; reboot required", 3010)
	if res := checkin(t, s, "e-1", acmeCurrent, true); res.RebootNow {
		t.Fatal("reboot requested without a window")
	}
	if got := detail(d.DeploymentID); got != noRebootWindowDetail {
		t.Fatalf("detail %q", got)
	}
	// A window that allows restarts (closed right now) removes the message.
	if _, err := s.CreateWindow(ctx, "user:otto", MaintenanceWindow{Name: "nights", Groups: []string{"pilot"}, Days: []string{"mon"}, Start: "02:00", End: "02:01",
		Timezone: "UTC", AllowReboot: true}); err != nil {
		t.Fatal(err)
	}
	checkin(t, s, "e-1", acmeCurrent, true)
	if got := detail(d.DeploymentID); got != rebootWaitDetail {
		t.Errorf("with a reboot window: %q", got)
	}

	// at_deadline past its deadline restarts anyway: no message.
	if !rebootNeverInWindow("at_deadline", windowState{}, false) || rebootNeverInWindow("at_deadline", windowState{}, true) ||
		rebootNeverInWindow("never", windowState{}, false) || rebootNeverInWindow("in_window", windowState{anyReboot: true}, false) {
		t.Error("rebootNeverInWindow")
	}
}

// Item 3: per-item results of status reports become item status + reason;
// the newest report wins and fulfilled wins over everything.
func TestAcqItemResults(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	clock := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return clock }
	if err := s.RecordAcqRequest(ctx, AcqRequestRecord{RequestID: "req-1", CreatedAt: clock.Add(-time.Hour).Format(time.RFC3339), CreatedBy: "user:otto",
		Items: []AcqRequestItem{{Kind: "app", Key: "Vendor.NoMsi", Version: "1.0"}, {Kind: "app", Key: "Vendor.Flaky", Version: "2.0"},
			{Kind: "kb", Key: "KB5044280", Version: "x64"}, {Kind: "kb", Key: "KB5044280", Version: "arm64"}}},
		Ev{Actor: "user:otto", Action: "acquisition.request_exported", ObjectType: "acquisition_request", ObjectID: "req-1"}); err != nil {
		t.Fatal(err)
	}
	rep := func(items string) {
		t.Helper()
		if err := s.RecordAcquisition(ctx, "acq-zone-1", clock.Format(time.RFC3339), "partial", "k",
			[]byte(`{"feeds":[{"type":"request","name":"req-1","status":"new"}],"items":[`+items+`]}`), "x"); err != nil {
			t.Fatal(err)
		}
	}
	rep(`{"request_id":"req-1","kind":"app","key":"vendor.nomsi","version":"1.0","result":"unsupported","reason":"no MSI installer for x64"},
		{"request_id":"req-1","kind":"app","key":"Vendor.Flaky","version":"2.0","result":"failed","reason":"download: timeout"},
		{"request_id":"req-1","kind":"kb","key":"KB5044280","version":"x64","result":"fetched","package_id":"KB5044280-x64"},
		{"request_id":"req-1","kind":"kb","key":"KB5044280","version":"arm64","result":"unsupported","reason":"KB not in the catalog for arm64"}`)
	items := func() map[string]AcqRequestItem {
		list, err := s.ListAcqRequests(ctx, 0)
		if err != nil {
			t.Fatal(err)
		}
		m := map[string]AcqRequestItem{}
		for _, it := range list[0].Items {
			m[it.Key+"/"+it.Version] = it
		}
		return m
	}
	got := items()
	if it := got["Vendor.NoMsi/1.0"]; it.Status != "unsupported" || it.Reason != "no MSI installer for x64" {
		t.Errorf("unsupported (key case-insensitive): %+v", it)
	}
	if it := got["Vendor.Flaky/2.0"]; it.Status != "failed" || it.Reason != "download: timeout" {
		t.Errorf("failed: %+v", it)
	}
	if it := got["KB5044280/x64"]; it.Status != "seen" || it.Reason != "" {
		t.Errorf("fetched, not arrived yet: %+v", it)
	}
	refs, err := s.AcqRequestRefs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if r := refs[AcqRefKey("kb", "KB5044280")]; r.Status != "unsupported" || r.Reason == "" {
		t.Errorf("a KB ref shows the architecture that cannot be imported: %+v", r)
	}
	if r := refs[AcqRefKey("app", "vendor.flaky")]; r.Status != "failed" || r.Reason != "download: timeout" {
		t.Errorf("app ref: %+v", r)
	}

	// A newer run fetches the flaky one; the x64 KB arrives in a bundle.
	clock = clock.Add(time.Minute)
	rep(`{"request_id":"req-1","kind":"app","key":"Vendor.Flaky","version":"2.0","result":"fetched"}`)
	s.db.Exec(`INSERT INTO bundles(bundle_id,state,filename,file_sha256,file_size,received_at) VALUES('b-1','validated','b.pmb','x',1,?)`, clock.Format(time.RFC3339))
	addPackage(t, s, Package{PackageID: "KB5044280-x64", Kind: "msu", KB: "KB5044280", Version: "1"})
	got = items()
	if it := got["Vendor.Flaky/2.0"]; it.Status != "seen" || it.Reason != "" {
		t.Errorf("newest report wins: %+v", it)
	}
	if it := got["KB5044280/x64"]; it.Status != "fulfilled" {
		t.Errorf("fulfilled: %+v", it)
	}
	if it := got["Vendor.NoMsi/1.0"]; it.Status != "unsupported" {
		t.Errorf("older result kept when the newer report does not list it: %+v", it)
	}
}

func ingest(t *testing.T, s *Store, seq int64, pkgs ...manifest.Package) Bundle {
	t.Helper()
	id := "b-" + itoa(int(seq))
	m := &manifest.Manifest{SchemaVersion: 1, BundleID: id, Source: "acq-zone-1", Sequence: seq, KeyID: "k", Packages: pkgs}
	b, err := s.IngestBundle(context.Background(), Intake{Bundle: Bundle{BundleID: id, Source: "acq-zone-1", Sequence: seq, KeyID: "k", Filename: id + ".pmb",
		FileSHA256: strings.Repeat("f", 60) + itoa(int(1000+seq)), Checks: []Check{}}, Manifest: m, ManifestBytes: []byte("{}"), QuarantineDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if b.State != "validated" {
		t.Fatalf("bundle %s: %s %s", id, b.State, b.Error)
	}
	return b
}

func intakePkg(sha string) manifest.Package {
	return manifest.Package{PackageID: "Acme-3.0", Title: "Acme 3.0", Vendor: "Acme", Kind: "msi", Version: "3.0.0", ProductCode: "{A}", Severity: "critical",
		ReleaseDate: "2026-10-01", Applicability: manifest.Applicability{OS: "windows", Arch: "x64"},
		File: manifest.FileRef{Name: "payload/acme.msi", Size: 10, SHA256: strings.Repeat(sha, 64)}}
}

// Item 4: a rejected package delivered again goes back to quarantine for a
// new review (approvals cleared, new bundle and content); a revoked one
// stays revoked and is listed as a skipped duplicate.
func TestReimportRejectedPackage(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	s.Policy = Policy{ApprovalsRequired: map[string]int{"critical": 2}}
	ingest(t, s, 1, intakePkg("a"))
	if _, err := s.SetPackageState(ctx, "user:alice", "Acme-3.0", "approve", "looks fine", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetPackageState(ctx, "user:bob", "Acme-3.0", "reject", "wrong build", nil); err != nil {
		t.Fatal(err)
	}

	b := ingest(t, s, 2, intakePkg("a"))
	p, err := s.GetPackage(ctx, "Acme-3.0")
	if err != nil {
		t.Fatal(err)
	}
	if p.State != "quarantined" || p.BundleID != "b-2" || len(p.Approvals) != 0 || p.StateBy != "system:intake" {
		t.Fatalf("re-imported: state=%s bundle=%s approvals=%d by=%s", p.State, p.BundleID, len(p.Approvals), p.StateBy)
	}
	if !strings.Contains(b.Checks[len(b.Checks)-1].Detail, "imported again") {
		t.Errorf("bundle check: %+v", b.Checks)
	}
	ev := hasAudit(auditActions(t, s, "Acme-3.0"), "package.reimported|system:intake|")
	if ev == "" || !strings.Contains(ev, `"approvals_cleared":1`) || !strings.Contains(ev, `"content_changed":false`) {
		t.Errorf("audit: %q", ev)
	}

	// Rejected again, then re-delivered with different content: replaced.
	if _, err := s.SetPackageState(ctx, "user:bob", "Acme-3.0", "reject", "still wrong", nil); err != nil {
		t.Fatal(err)
	}
	ingest(t, s, 3, intakePkg("b"))
	if p, _ = s.GetPackage(ctx, "Acme-3.0"); p.State != "quarantined" || p.SHA256 != strings.Repeat("b", 64) {
		t.Fatalf("new content: state=%s sha=%s", p.State, p.SHA256)
	}

	// Approved and revoked: a new delivery does not undo the revocation.
	for _, who := range []string{"user:alice", "user:carol"} {
		if _, err := s.SetPackageState(ctx, who, "Acme-3.0", "approve", "ok", nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.SetPackageState(ctx, "user:alice", "Acme-3.0", "revoke", "vendor pulled it", nil); err != nil {
		t.Fatal(err)
	}
	b = ingest(t, s, 4, intakePkg("c"))
	if p, _ = s.GetPackage(ctx, "Acme-3.0"); p.State != "revoked" || p.SHA256 != strings.Repeat("b", 64) {
		t.Errorf("revoked must stay revoked: state=%s sha=%s", p.State, p.SHA256)
	}
	if d := b.Checks[len(b.Checks)-1].Detail; !strings.Contains(d, "revoked; not imported again") {
		t.Errorf("revoked duplicate detail: %q", d)
	}

	// An approved package with different content is still a conflict.
	ingest(t, s, 5, manifest.Package{PackageID: "Other-1", Title: "o", Vendor: "v", Kind: "msi", Version: "1", ProductCode: "{O}", Severity: "low",
		ReleaseDate: "2026-10-01", Applicability: manifest.Applicability{OS: "windows", Arch: "x64"}, File: manifest.FileRef{Name: "payload/o.msi", Size: 1, SHA256: strings.Repeat("d", 64)}})
	s.db.Exec(`UPDATE packages SET state='approved' WHERE package_id='Other-1'`)
	m := &manifest.Manifest{SchemaVersion: 1, BundleID: "b-6", Source: "acq-zone-1", Sequence: 6, KeyID: "k", Packages: []manifest.Package{{PackageID: "Other-1",
		File: manifest.FileRef{Name: "payload/o.msi", Size: 1, SHA256: strings.Repeat("e", 64)}}}}
	bad, err := s.IngestBundle(ctx, Intake{Bundle: Bundle{BundleID: "b-6", FileSHA256: "x6", Checks: []Check{}}, Manifest: m, ManifestBytes: []byte("{}"), QuarantineDir: t.TempDir()})
	if err != nil || bad.State != "rejected" || !strings.Contains(bad.Error, "catalog_conflict") {
		t.Errorf("approved conflict: %v %s %s", err, bad.State, bad.Error)
	}
}

// Item 7: enrolled but never checked in is awaiting_checkin (no offline /
// stale alert) for 24 h, then offline.
func TestAwaitingFirstCheckin(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	addEndpoint(t, s, "e-new", []string{"pilot"}, nil)
	status := func() string {
		eps, err := s.ListEndpointsBrief(ctx, DefaultThresholds)
		if err != nil {
			t.Fatal(err)
		}
		return eps[0].Status
	}
	if st := status(); st != "awaiting_checkin" {
		t.Fatalf("new endpoint: %s", st)
	}
	// Even if its heartbeat is old (agent installed, not started yet).
	s.db.Exec(`UPDATE endpoints SET last_seen=? WHERE endpoint_id='e-new'`, s.Now().Add(-2*time.Hour).Format(time.RFC3339Nano))
	if st := status(); st != "awaiting_checkin" {
		t.Fatalf("silent new endpoint: %s", st)
	}
	if err := s.SweepAlerts(ctx, DefaultThresholds); err != nil {
		t.Fatal(err)
	}
	if as, _ := s.ListAlerts(ctx, true); len(as) != 0 {
		t.Errorf("alerts for an endpoint awaiting its first check-in: %+v", as)
	}
	sm, err := s.Summary(ctx, DefaultThresholds)
	if err != nil || sm.Endpoints.ByStatus["awaiting_checkin"] != 1 || sm.Endpoints.ByStatus["compliant"] != 0 {
		t.Errorf("summary: %v %+v", err, sm.Endpoints.ByStatus)
	}
	s.db.Exec(`UPDATE endpoints SET enrolled_at=? WHERE endpoint_id='e-new'`, s.Now().Add(-25*time.Hour).Format(time.RFC3339Nano))
	if st := status(); st != "offline" {
		t.Errorf("24 h after enrollment without a check-in: %s", st)
	}
	if err := s.SweepAlerts(ctx, DefaultThresholds); err != nil {
		t.Fatal(err)
	}
	if as, _ := s.ListAlerts(ctx, true); len(as) != 1 || as[0].Kind != "endpoints_offline" {
		t.Errorf("offline alert: %+v", as)
	}
	// After a first check-in it follows the normal rules.
	checkin(t, s, "e-new", acmeOld, false)
	if st := status(); st != "compliant" {
		t.Errorf("after check-in: %s", st)
	}
}

// Item 8: "installer busy" failures do not use up attempts for the first
// 10 in a row, then count normally; another result resets the run.
func TestInstallerBusyGrace(t *testing.T) {
	s := openTest(t)
	addPackage(t, s, Package{PackageID: "Acme-3.0", Kind: "msi", Version: "3.0.0", PackageName: "Acme App", ProductCode: "{A}"})
	addEndpoint(t, s, "e-1", []string{"pilot"}, acmeOld)
	d, err := s.CreateDeployment(context.Background(), "user:otto", NewDeployment{PackageID: "Acme-3.0", Name: "acme", Rings: []Ring{{Name: "all", Groups: []string{"all"}}},
		MaxFailurePct: 0, MaxRetries: 0})
	if err != nil {
		t.Fatal(err)
	}
	const busy = "retry later: installer busy (another installation or servicing operation is in progress, 0x00000652)"
	detail := func() string {
		var x string
		s.db.QueryRow(`SELECT detail FROM targets WHERE deployment_id=? AND endpoint_id='e-1'`, d.DeploymentID).Scan(&x)
		return x
	}
	for i := 1; i <= installerBusyGrace; i++ {
		report(t, s, d.DeploymentID, "e-1", "Acme-3.0", "installing", "msi installer started", 0)
		report(t, s, d.DeploymentID, "e-1", "Acme-3.0", "failed", busy, 1618)
		st, attempts := targetRow(t, s, d.DeploymentID, "e-1")
		if st != "failed" || attempts != 0 {
			t.Fatalf("busy %d: state=%s attempts=%d", i, st, attempts)
		}
		if want := "waiting: another installation is running on this machine (try " + itoa(i) + ")"; detail() != want {
			t.Fatalf("busy %d: detail %q", i, detail())
		}
		if dst, _ := depState(t, s, d.DeploymentID); dst != "active" {
			t.Fatalf("busy %d paused the deployment", i)
		}
		// Still offered at the next check-in.
		if res := checkin(t, s, "e-1", acmeOld, false); len(res.Assignments) != 1 {
			t.Fatalf("busy %d: not offered again", i)
		}
	}
	evs := auditActions(t, s, d.DeploymentID+"/e-1")
	n := 0
	for _, e := range evs {
		if strings.HasPrefix(e, "target.installer_busy|") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("installer_busy audited %d times, want once per run", n)
	}
	if as, _ := s.ListAlerts(context.Background(), true); len(as) != 0 {
		t.Errorf("alerts during the grace: %+v", as)
	}
	// The 11th counts: max_retries 0 exhausted, 0 % threshold auto-pauses.
	report(t, s, d.DeploymentID, "e-1", "Acme-3.0", "installing", "msi installer started", 0)
	report(t, s, d.DeploymentID, "e-1", "Acme-3.0", "failed", busy, 1618)
	if _, attempts := targetRow(t, s, d.DeploymentID, "e-1"); attempts != 1 {
		t.Errorf("after the grace: attempts %d", attempts)
	}
	if dst, _ := depState(t, s, d.DeploymentID); dst != "paused" {
		t.Errorf("after the grace the failure counts: %s", dst)
	}

	// Another result ends the run of busy results.
	s.db.Exec(`UPDATE targets SET busy_tries=5 WHERE deployment_id=?`, d.DeploymentID)
	report(t, s, d.DeploymentID, "e-1", "Acme-3.0", "failed", "installer exit code 1603", 1603)
	var tries int
	s.db.QueryRow(`SELECT busy_tries FROM targets WHERE deployment_id=?`, d.DeploymentID).Scan(&tries)
	if tries != 0 {
		t.Errorf("busy_tries not reset: %d", tries)
	}
}

// Item 9: one running (active or paused) deployment per package and
// operation; allowed again after cancel or completion. Rollbacks are a
// separate operation with the same rule.
func TestOneRunningDeploymentPerPackage(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	addPackage(t, s, Package{PackageID: "Acme-3.0", Kind: "msi", Version: "3.0.0", PackageName: "Acme App", ProductCode: "{A}"})
	addEndpoint(t, s, "e-old", []string{"pilot"}, acmeOld)
	all := []Ring{{Name: "all", Groups: []string{"all"}}}
	install := func() (Deployment, error) {
		return s.CreateDeployment(ctx, "user:otto", NewDeployment{PackageID: "Acme-3.0", Name: "acme", Rings: all, MaxFailurePct: 50})
	}
	rollback := func() (Deployment, error) {
		return s.CreateDeployment(ctx, "user:otto", NewDeployment{PackageID: "Acme-3.0", Name: "undo", Rings: all, MaxFailurePct: 50, Operation: "rollback", Justification: "bad"})
	}
	conflict := func(what string, _ Deployment, err error) {
		t.Helper()
		if !errors.Is(err, ErrConflict) {
			t.Errorf("%s: want ErrConflict, got %v", what, err)
		}
	}
	d1, err := install()
	if err != nil || d1.State != "active" {
		t.Fatalf("first install: %v %s", err, d1.State)
	}
	d, err := install()
	conflict("second install while active", d, err)
	if _, err := s.DeploymentAction(ctx, "user:otto", d1.DeploymentID, "pause", "hold"); err != nil {
		t.Fatal(err)
	}
	d, err = install()
	conflict("second install while paused", d, err)
	if _, err := s.DeploymentAction(ctx, "user:otto", d1.DeploymentID, "cancel", "redo"); err != nil {
		t.Fatal(err)
	}
	d2, err := install()
	if err != nil {
		t.Fatalf("install after cancel: %v", err)
	}
	checkin(t, s, "e-old", acmeCurrent, false) // verified: completes
	if st, _ := depState(t, s, d2.DeploymentID); st != "completed" {
		t.Fatalf("d2 %s", st)
	}
	d3, err := install()
	if err != nil || d3.State != "completed" { // nothing left to do
		t.Fatalf("install after completion: %v %s", err, d3.State)
	}

	// Rollback: e-old now has 3.0.0, so it is in scope.
	r1, err := rollback()
	if err != nil || r1.State != "active" {
		t.Fatalf("rollback: %v %s", err, r1.State)
	}
	d, err = rollback()
	conflict("second rollback while active", d, err)
	d, err = install()
	conflict("install while a rollback runs", d, err)
	if _, err := s.DeploymentAction(ctx, "user:otto", r1.DeploymentID, "cancel", "never mind"); err != nil {
		t.Fatal(err)
	}
	if _, err := rollback(); err != nil {
		t.Errorf("rollback after cancel: %v", err)
	}
}
