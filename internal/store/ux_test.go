package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"offpatch/internal/manifest"
)

func addPackage(t *testing.T, s *Store, p Package) {
	t.Helper()
	if p.State == "" {
		p.State = "approved"
	}
	if p.Applicability.OS == "" {
		p.Applicability = manifest.Applicability{OS: "windows", Arch: "x64"}
	}
	if p.Severity == "" {
		p.Severity = "important"
	}
	now := s.now()
	if _, err := s.db.Exec(`INSERT INTO packages(`+packageCols+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		p.PackageID, "b-1", p.PackageID, "Vendor", p.Kind, p.Version, p.KB, p.ProductCode, p.Severity, "2026-10-01", mustJSON(nonNil(p.Supersedes)),
		mustJSON(p.Applicability), "f.bin", 1, strings.Repeat("a", 63)+string(rune('a'+len(p.PackageID)%6)), "", `{}`, "", p.State, "", "", now, now, p.PackageName, "[]", "", p.ExpectedUBR); err != nil {
		t.Fatal(err)
	}
}

func addEndpoint(t *testing.T, s *Store, id string, groups []string, inv []InventoryItem) {
	t.Helper()
	now := s.now()
	invAt := now
	if inv == nil {
		invAt = ""
		inv = []InventoryItem{}
	}
	if _, err := s.db.Exec(`INSERT INTO endpoints(endpoint_id,hostname,os,os_version,build,arch,groups,site,last_seen,inventory_at,agent_version,enrolled_at,secret_hash,inventory)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, id, "host-"+id, "windows", "Windows 10", 19045, "x64", mustJSON(groups), "hq", now, invAt, "1.0", now, HashSecret(id), mustJSON(inv)); err != nil {
		t.Fatal(err)
	}
}

func addTarget(t *testing.T, s *Store, dep, ep, pkg, state string, ring, attempts int) {
	t.Helper()
	if _, err := s.db.Exec(`INSERT OR REPLACE INTO targets(deployment_id,endpoint_id,package_id,ring,state,attempts,updated_at) VALUES(?,?,?,?,?,?,?)`,
		dep, ep, pkg, ring, state, attempts, s.now()); err != nil {
		t.Fatal(err)
	}
}

// Needs: every applicable endpoint with inventory is exactly one of needed /
// up_to_date / not_installed; deployment and exception counts come from
// install targets and active exceptions.
func TestNeedsClassification(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	addPackage(t, s, Package{PackageID: "KB2-x64", Kind: "msu", KB: "KB2", Version: "1"})
	addPackage(t, s, Package{PackageID: "KB3-x64", Kind: "msu", KB: "KB3", Version: "1", Supersedes: []string{"KB2"}, State: "quarantined"})
	addPackage(t, s, Package{PackageID: "Acme-3.0", Kind: "msi", Version: "3.0.0", PackageName: "Acme App", ProductCode: "{A}"})
	addPackage(t, s, Package{PackageID: "Arm-1", Kind: "msu", KB: "KB9", Version: "1", Applicability: manifest.Applicability{OS: "windows", Arch: "arm64"}})

	addEndpoint(t, s, "e-has-kb", []string{"pilot"}, []InventoryItem{{Kind: "kb", ID: "KB3"}, {Kind: "product", ID: "{A}", Name: "Acme App", Version: "3.0.0"}})
	addEndpoint(t, s, "e-old", []string{"pilot"}, []InventoryItem{{Kind: "kb", ID: "KB1"}, {Kind: "product", ID: "{OLD}", Name: "Acme App", Version: "2.5.0"}})
	addEndpoint(t, s, "e-none", []string{"broad"}, []InventoryItem{{Kind: "kb", ID: "KB1"}})
	addEndpoint(t, s, "e-noinv", []string{"broad"}, nil)
	addEndpoint(t, s, "e-retired", []string{"broad"}, []InventoryItem{})
	s.db.Exec(`UPDATE endpoints SET retired_at=? WHERE endpoint_id='e-retired'`, s.now())

	n, err := s.Needs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := n["KB2-x64"]; ok {
		t.Error("KB2 is superseded by a live catalog package and should not be listed")
	}
	kb3 := n["KB3-x64"]
	// e-has-kb has it; e-old and e-none need it; e-noinv has no inventory; e-retired is excluded.
	if kb3.Needed != 2 || kb3.UpToDate != 1 || kb3.NotInstalled != 0 || kb3.Approved() {
		t.Errorf("KB3: %+v", kb3)
	}
	acme := n["Acme-3.0"]
	// current on e-has-kb, older on e-old, not installed on e-none.
	if acme.Needed != 1 || acme.Endpoints[0] != "e-old" || acme.UpToDate != 1 || acme.NotInstalled != 1 || !acme.Approved() {
		t.Errorf("Acme: %+v", acme)
	}
	if arm := n["Arm-1"]; arm.Needed+arm.UpToDate+arm.NotInstalled != 0 {
		t.Errorf("non-applicable endpoints must not be counted: %+v", arm)
	}

	// Deployment and exception counts.
	if _, err := s.db.Exec(`INSERT INTO deployments(deployment_id,package_id,name,state,emergency,justification,rings,current_ring,max_failure_pct,max_retries,window_start,window_end,created_by,created_at,updated_at)
		VALUES('d-1','Acme-3.0','d','active',0,'','[{"name":"all","groups":["all"]}]',0,100,1,'','','u',?,?),
		      ('d-0','Acme-3.0','old','cancelled',0,'','[{"name":"all","groups":["all"]}]',0,100,1,'','','u',?,?)`, s.now(), s.now(), s.now(), s.now()); err != nil {
		t.Fatal(err)
	}
	addTarget(t, s, "d-1", "e-has-kb", "Acme-3.0", "verified", 0, 0)
	addTarget(t, s, "d-1", "e-old", "Acme-3.0", "downloading", 0, 0)
	addTarget(t, s, "d-0", "e-none", "Acme-3.0", "failed", 0, 3) // cancelled: not counted as failed
	if _, err := s.db.Exec(`INSERT INTO exceptions(exception_id,endpoint_id,package_id,owner,reason,compensating_controls,expires_at,created_by,created_at)
		VALUES('x-1','e-none','','o','r','c',?,'u',?),('x-2','e-old','Acme-3.0','o','r','c',?,'u',?)`,
		s.Now().Add(time.Hour).Format(time.RFC3339Nano), s.now(), s.Now().Add(-time.Hour).Format(time.RFC3339Nano), s.now()); err != nil {
		t.Fatal(err)
	}
	n, _ = s.Needs(ctx)
	acme = n["Acme-3.0"]
	if acme.Verified != 1 || acme.Deploying != 1 || acme.Failed != 0 || acme.Exception != 1 || acme.ActiveDeploymentID != "d-1" {
		t.Errorf("Acme fleet counts: %+v", acme)
	}
	if kb3 := n["KB3-x64"]; kb3.Exception != 1 || kb3.ActiveDeploymentID != "" {
		t.Errorf("an all-packages exception counts for every applicable package: %+v", kb3)
	}
	s.db.Exec(`UPDATE deployments SET state='paused' WHERE deployment_id='d-0'`)
	if n, _ = s.Needs(ctx); n["Acme-3.0"].Failed != 1 {
		t.Errorf("failed in a paused deployment: %+v", n["Acme-3.0"])
	}
}

func newDeployment(t *testing.T, s *Store, pkg string, rings []Ring, maxRetries int) Deployment {
	t.Helper()
	d, err := s.CreateDeployment(context.Background(), "user:otto", NewDeployment{PackageID: pkg, Name: "d", Rings: rings, MaxFailurePct: 50, MaxRetries: maxRetries})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func targetRow(t *testing.T, s *Store, dep, ep string) (string, int) {
	t.Helper()
	var st string
	var n int
	if err := s.db.QueryRow(`SELECT state, attempts FROM targets WHERE deployment_id=? AND endpoint_id=?`, dep, ep).Scan(&st, &n); err != nil {
		t.Fatal(err)
	}
	return st, n
}

func TestRetryFailed(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	addPackage(t, s, Package{PackageID: "KB7-x64", Kind: "msu", KB: "KB7", Version: "1"})
	for _, id := range []string{"e-1", "e-2", "e-3"} {
		addEndpoint(t, s, id, []string{"pilot"}, []InventoryItem{})
	}
	addEndpoint(t, s, "e-broad", []string{"broad"}, []InventoryItem{})
	d := newDeployment(t, s, "KB7-x64", []Ring{{Name: "pilot", Groups: []string{"pilot"}}, {Name: "broad", Groups: []string{"broad"}}}, 1)

	if _, err := s.RetryFailed(ctx, "user:otto", d.DeploymentID, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("no reason: %v", err)
	}
	if _, err := s.RetryFailed(ctx, "user:otto", d.DeploymentID, "fixed disk"); !errors.Is(err, ErrConflict) {
		t.Fatalf("nothing to retry: %v", err)
	}
	// e-1 exhausted, e-2 failed with retries left, e-3 still pending.
	s.db.Exec(`UPDATE targets SET state='failed', attempts=2, detail='exit 1603' WHERE endpoint_id='e-1'`)
	s.db.Exec(`UPDATE targets SET state='failed', attempts=1 WHERE endpoint_id='e-2'`)
	s.db.Exec(`UPDATE deployments SET state='paused' WHERE deployment_id=?`, d.DeploymentID)

	out, err := s.RetryFailed(ctx, "user:otto", d.DeploymentID, "fixed disk")
	if err != nil {
		t.Fatal(err)
	}
	if out.State != "paused" {
		t.Errorf("a paused deployment stays paused: %s", out.State)
	}
	if st, n := targetRow(t, s, d.DeploymentID, "e-1"); st != "pending" || n != 0 {
		t.Errorf("e-1: %s/%d", st, n)
	}
	if st, n := targetRow(t, s, d.DeploymentID, "e-2"); st != "failed" || n != 1 {
		t.Errorf("e-2 has retries left and must not be touched: %s/%d", st, n)
	}
	evs, _ := s.ListAudit(ctx, AuditQuery{Action: "deployment.retry_failed"})
	if len(evs) != 1 || evs[0].Actor != "user:otto" || !strings.Contains(string(evs[0].Details), "e-1") || strings.Contains(string(evs[0].Details), "e-2") ||
		!strings.Contains(string(evs[0].Details), "fixed disk") {
		t.Fatalf("audit: %+v", evs)
	}

	// Active: after the retry the threshold is re-checked; health-check
	// failures still above it pause the deployment again.
	s.db.Exec(`UPDATE deployments SET state='active' WHERE deployment_id=?`, d.DeploymentID)
	s.db.Exec(`UPDATE targets SET state='failed', attempts=5 WHERE endpoint_id='e-1'`)
	s.db.Exec(`UPDATE targets SET state='installed', health='failed' WHERE endpoint_id IN ('e-2','e-3')`)
	if out, err = s.RetryFailed(ctx, "user:otto", d.DeploymentID, "again"); err != nil || out.State != "paused" || !strings.Contains(out.StateReason, "auto-pause") {
		t.Fatalf("threshold not re-checked: %v %+v", err, out)
	}

	s.db.Exec(`UPDATE deployments SET state='completed' WHERE deployment_id=?`, d.DeploymentID)
	if _, err := s.RetryFailed(ctx, "user:otto", d.DeploymentID, "x"); !errors.Is(err, ErrConflict) {
		t.Fatalf("completed deployment: %v", err)
	}
}

func TestAcqRequestTracking(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	clock := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return clock }
	rec := func(id string, at time.Time, items ...AcqRequestItem) {
		t.Helper()
		if err := s.RecordAcqRequest(ctx, AcqRequestRecord{RequestID: id, CreatedAt: at.Format(time.RFC3339), CreatedBy: "user:otto", Items: items},
			Ev{Actor: "user:otto", Action: "acquisition.request_exported", ObjectType: "acquisition_request", ObjectID: id}); err != nil {
			t.Fatal(err)
		}
	}
	rec("req-1", clock.Add(-2*time.Hour),
		AcqRequestItem{Kind: "app", Key: "Google.Chrome", Version: "155.0"},
		AcqRequestItem{Kind: "kb", Key: "KB5044280", Version: "x64"},
		AcqRequestItem{Kind: "kb", Key: "KB5044280", Version: "arm64"},
		AcqRequestItem{Kind: "app", Key: "Notepad++.Notepad++", Version: "8.7"})
	rec("req-2", clock.Add(-time.Hour), AcqRequestItem{Kind: "app", Key: "7zip.7zip", Version: "26.04"})

	list, err := s.ListAcqRequests(ctx, 0)
	if err != nil || len(list) != 2 || list[0].RequestID != "req-2" {
		t.Fatalf("list: %v %+v", err, list)
	}
	for _, it := range list[1].Items {
		if it.Status != "requested" || it.PackageID != "" {
			t.Errorf("before anything arrived: %+v", it)
		}
	}

	// The acquisition zone reports it ran req-1.
	if err := s.RecordAcquisition(ctx, "acq-zone-1", clock.Format(time.RFC3339), "ok", "k",
		[]byte(`{"feeds":[{"type":"app","name":"chrome"},{"type":"request","name":"req-1","status":"new"}]}`), "1 new"); err != nil {
		t.Fatal(err)
	}
	// A bundle brings Chrome 155.0.1 (not 155.0), the x64 KB and Notepad++ (hashed id).
	s.db.Exec(`INSERT INTO bundles(bundle_id,state,filename,file_sha256,file_size,received_at) VALUES('b-1','validated','b.pmb','x',1,?)`, clock.Format(time.RFC3339))
	addPackage(t, s, Package{PackageID: "Google.Chrome-155.01", Kind: "msi", Version: "155.01"})
	addPackage(t, s, Package{PackageID: "KB5044280-x64", Kind: "msu", KB: "KB5044280", Version: "1"})
	npp := wingetPackageID("Notepad++.Notepad++", "8.7", "x86")
	if !strings.HasPrefix(npp, "Notepad-.Notepad--8.7-x86-") || len(npp) != len("Notepad-.Notepad--8.7-x86-")+8 {
		t.Fatalf("pmctl id form: %s", npp)
	}
	addPackage(t, s, Package{PackageID: npp, Kind: "msi", Version: "8.7"})

	list, _ = s.ListAcqRequests(ctx, 0)
	r1 := list[1]
	if r1.SeenAt == "" {
		t.Fatal("req-1 not seen")
	}
	got := map[string]AcqRequestItem{}
	for _, it := range r1.Items {
		got[it.Key+"/"+it.Version] = it
	}
	if it := got["Google.Chrome/155.0"]; it.Status != "seen" {
		t.Errorf("Chrome 155.01 must not fulfil 155.0: %+v", it)
	}
	if it := got["KB5044280/x64"]; it.Status != "fulfilled" || it.PackageID != "KB5044280-x64" || it.FulfilledAt == "" {
		t.Errorf("kb x64: %+v", it)
	}
	if it := got["KB5044280/arm64"]; it.Status != "seen" {
		t.Errorf("kb arm64: %+v", it)
	}
	if it := got["Notepad++.Notepad++/8.7"]; it.Status != "fulfilled" {
		t.Errorf("notepad++ (sanitised id): %+v", it)
	}
	// req-2 (08:00) was not in the 09:00 run: not picked up (P2 "stale").
	if list[0].SeenAt != "" || list[0].Items[0].Status != "stale" || !strings.Contains(list[0].Items[0].Reason, "did not pick this request up") {
		t.Errorf("req-2: %+v", list[0])
	}

	addPackage(t, s, Package{PackageID: "Google.Chrome-155.0-arm64", Kind: "msi", Version: "155.0"})
	refs, err := s.AcqRequestRefs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if r := refs[AcqRefKey("app", "google.chrome")]; r.RequestID != "req-1" || r.Status != "fulfilled" {
		t.Errorf("chrome ref: %+v", r)
	}
	if r := refs[AcqRefKey("os", "kb5044280")]; r.Status != "seen" {
		t.Errorf("a KB is fulfilled only when every architecture arrived: %+v", r)
	}
	rec("req-3", clock, AcqRequestItem{Kind: "kb", Key: "KB5044280", Version: "arm64"})
	refs, _ = s.AcqRequestRefs(ctx)
	if r := refs[AcqRefKey("kb", "KB5044280")]; r.RequestID != "req-3" || r.Status != "requested" {
		t.Errorf("the latest request wins: %+v", r)
	}
}

func TestNextCheckinSeconds(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	clock := time.Now().UTC()
	s.Now = func() time.Time { return clock }
	addPackage(t, s, Package{PackageID: "KB8-x64", Kind: "msu", KB: "KB8", Version: "1"})
	addEndpoint(t, s, "e-1", []string{"pilot"}, []InventoryItem{})
	addEndpoint(t, s, "e-2", []string{"other"}, []InventoryItem{})
	checkin := func(id string) CheckinResult {
		t.Helper()
		r, err := s.Checkin(ctx, id, CheckinRequest{Hostname: "h-" + id, OSVersion: "Windows 10", Build: 19045, Arch: "x64", Inventory: []InventoryItem{}})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := checkin("e-1"); r.NextCheckinSeconds != 0 {
		t.Fatalf("nothing to do: %d", r.NextCheckinSeconds)
	}
	// A closed deployment window: no assignment, but the deployment was just created.
	closed := clock.Add(2 * time.Hour)
	d, err := s.CreateDeployment(ctx, "user:otto", NewDeployment{PackageID: "KB8-x64", Name: "d", Rings: []Ring{{Name: "p", Groups: []string{"pilot"}}},
		MaxFailurePct: 100, WindowStart: closed.Format("15:04"), WindowEnd: closed.Add(time.Hour).Format("15:04")})
	if err != nil {
		t.Fatal(err)
	}
	if r := checkin("e-1"); len(r.Assignments) != 0 || r.NextCheckinSeconds != FastCheckinSeconds {
		t.Fatalf("just created: %+v", r)
	}
	if r := checkin("e-2"); r.NextCheckinSeconds != 0 {
		t.Fatalf("not in the deployment's groups: %d", r.NextCheckinSeconds)
	}
	clock = clock.Add(3 * time.Minute)
	if r := checkin("e-1"); r.NextCheckinSeconds != 0 {
		t.Fatalf("pending outside its window, created 3 min ago: %d", r.NextCheckinSeconds)
	}
	s.db.Exec(`UPDATE targets SET state='downloading' WHERE deployment_id=?`, d.DeploymentID)
	if r := checkin("e-1"); r.NextCheckinSeconds != FastCheckinSeconds {
		t.Fatalf("download in progress: %d", r.NextCheckinSeconds)
	}
	// Assignable now: fast while there is work.
	s.db.Exec(`UPDATE targets SET state='pending' WHERE deployment_id=?`, d.DeploymentID)
	s.db.Exec(`UPDATE deployments SET window_start='', window_end='' WHERE deployment_id=?`, d.DeploymentID)
	if r := checkin("e-1"); len(r.Assignments) != 1 || r.NextCheckinSeconds != FastCheckinSeconds {
		t.Fatalf("assigned: %+v", r)
	}
}
