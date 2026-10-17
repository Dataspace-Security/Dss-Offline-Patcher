package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// A package that arrived before the request was exported does not fulfil
// it; a later bundle carrying it again (identical duplicate in its signed
// manifest) does, with that bundle's time.
func TestAcqFulfilledOnlyAfterRequest(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	clock := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return clock }
	s.db.Exec(`INSERT INTO bundles(bundle_id,state,filename,file_sha256,file_size,received_at) VALUES('b-1','validated','b.pmb','x',1,?)`, clock.Add(-time.Hour).Format(time.RFC3339Nano))
	addPackage(t, s, Package{PackageID: "KB5044280-x64", Kind: "msu", KB: "KB5044280", Version: "1"})
	if err := s.RecordAcqRequest(ctx, AcqRequestRecord{RequestID: "req-1", CreatedAt: clock.Format(time.RFC3339), CreatedBy: "user:otto",
		Items: []AcqRequestItem{{Kind: "kb", Key: "KB5044280", Version: "x64"}}},
		Ev{Actor: "user:otto", Action: "acquisition.request_exported", ObjectType: "acquisition_request", ObjectID: "req-1"}); err != nil {
		t.Fatal(err)
	}
	status := func() AcqRequestItem {
		t.Helper()
		list, err := s.ListAcqRequests(ctx, 0)
		if err != nil || len(list) != 1 {
			t.Fatalf("list: %v %+v", err, list)
		}
		return list[0].Items[0]
	}
	if it := status(); it.Status != "requested" || it.PackageID != "" {
		t.Fatalf("arrived an hour before the request: %+v", it)
	}
	later := clock.Add(30 * time.Minute)
	mf := []byte(`{"packages":[{"package_id":"KB5044280-x64"}]}`)
	s.db.Exec(`INSERT INTO bundles(bundle_id,state,filename,file_sha256,file_size,received_at,manifest) VALUES('b-2','validated','c.pmb','y',1,?,?)`, later.Format(time.RFC3339Nano), mf)
	s.db.Exec(`INSERT INTO bundles(bundle_id,state,filename,file_sha256,file_size,received_at,manifest) VALUES('b-3','rejected','d.pmb','z',1,?,?)`, clock.Add(10*time.Minute).Format(time.RFC3339Nano), mf)
	if it := status(); it.Status != "fulfilled" || it.PackageID != "KB5044280-x64" || !parseTime(it.FulfilledAt).Equal(later) {
		t.Fatalf("re-delivered after the request (rejected bundles ignored): %+v", it)
	}
}

func TestGenerationBumps(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	addPackage(t, s, Package{PackageID: "KB8-x64", Kind: "msu", KB: "KB8", Version: "1", State: "quarantined"})
	addEndpoint(t, s, "e-1", []string{"pilot"}, []InventoryItem{})
	g := s.Generation()
	step := func(what string, bumped bool) {
		t.Helper()
		if now := s.Generation(); (now != g) != bumped {
			t.Errorf("%s: generation %d -> %d (want bumped=%v)", what, g, now, bumped)
		}
		g = s.Generation()
	}
	if _, err := s.SetPackageState(ctx, "user:anna", "KB8-x64", "approve", "CAB", nil); err != nil {
		t.Fatal(err)
	}
	step("approve", true)
	req := CheckinRequest{Hostname: "h", OSVersion: "Windows 10", Build: 19045, Arch: "x64", Inventory: []InventoryItem{{Kind: "kb", ID: "KB1"}}}
	if _, err := s.Checkin(ctx, "e-1", req); err != nil {
		t.Fatal(err)
	}
	step("check-in with new inventory", true)
	if _, err := s.Checkin(ctx, "e-1", req); err != nil {
		t.Fatal(err)
	}
	step("check-in with the same inventory", false)
	if _, err := s.SetPackageState(ctx, "user:anna", "KB8-x64", "approve", "again", nil); err == nil {
		t.Fatal("approving twice should fail")
	}
	step("failed transaction", false)
	newDeployment(t, s, "KB8-x64", []Ring{{Name: "p", Groups: []string{"pilot"}}}, 0)
	step("deployment created", true)
}

// next_checkin_seconds: a pending reboot is hinted only when the reboot is
// requested (throttle elapsed), and a target stuck in installed stops
// hinting after fastInstalledFor.
func TestNextCheckinThrottleAndCap(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	clock := time.Now().UTC()
	s.Now = func() time.Time { return clock }
	addPackage(t, s, Package{PackageID: "KB8-x64", Kind: "msu", KB: "KB8", Version: "1"})
	addEndpoint(t, s, "e-1", []string{"pilot"}, []InventoryItem{})
	d := newDeployment(t, s, "KB8-x64", []Ring{{Name: "p", Groups: []string{"pilot"}}}, 0)
	checkin := func(rebootPending bool) CheckinResult {
		t.Helper()
		r, err := s.Checkin(ctx, "e-1", CheckinRequest{Hostname: "h", OSVersion: "Windows 10", Build: 19045, Arch: "x64", Inventory: []InventoryItem{}, RebootPending: rebootPending})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	clock = clock.Add(3 * time.Minute) // past the fast pickup of the new deployment

	s.db.Exec(`UPDATE deployments SET reboot_policy='at_deadline', deadline=? WHERE deployment_id=?`, clock.Add(-time.Hour).Format(time.RFC3339Nano), d.DeploymentID)
	s.db.Exec(`UPDATE targets SET state='pending_reboot', updated_at=? WHERE deployment_id=?`, s.now(), d.DeploymentID)
	if r := checkin(true); !r.RebootNow || r.NextCheckinSeconds != FastCheckinSeconds {
		t.Fatalf("reboot requested: %+v", r)
	}
	clock = clock.Add(time.Minute)
	if r := checkin(true); r.RebootNow || r.NextCheckinSeconds != 0 {
		t.Fatalf("reboot throttled: no fast hint: %+v", r)
	}
	clock = clock.Add(rebootRetry + time.Minute)
	if r := checkin(true); !r.RebootNow || r.NextCheckinSeconds != FastCheckinSeconds {
		t.Fatalf("throttle elapsed: %+v", r)
	}

	s.db.Exec(`UPDATE targets SET state='installed', updated_at=? WHERE deployment_id=?`, s.now(), d.DeploymentID)
	clock = clock.Add(time.Minute)
	if r := checkin(false); r.NextCheckinSeconds != FastCheckinSeconds {
		t.Fatalf("installed, waiting on verification: %+v", r)
	}
	clock = clock.Add(fastInstalledFor)
	if r := checkin(false); r.NextCheckinSeconds != 0 {
		t.Fatalf("stuck in installed for %s: hint must stop: %+v", fastInstalledFor, r)
	}
}

// retry_failed on a completed deployment: exhausted failures of every ring
// up to the current one go back to pending and the deployment is active again.
func TestRetryFailedCompleted(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	addPackage(t, s, Package{PackageID: "KB7-x64", Kind: "msu", KB: "KB7", Version: "1"})
	addEndpoint(t, s, "e-p", []string{"pilot"}, []InventoryItem{})
	addEndpoint(t, s, "e-b", []string{"broad"}, []InventoryItem{})
	addEndpoint(t, s, "e-ok", []string{"broad"}, []InventoryItem{})
	d := newDeployment(t, s, "KB7-x64", []Ring{{Name: "pilot", Groups: []string{"pilot"}}, {Name: "broad", Groups: []string{"broad"}}}, 0)
	s.db.Exec(`UPDATE targets SET state='failed', attempts=1 WHERE endpoint_id='e-p'`)
	addTarget(t, s, d.DeploymentID, "e-b", "KB7-x64", "failed", 1, 1)
	addTarget(t, s, d.DeploymentID, "e-ok", "KB7-x64", "verified", 1, 0)
	s.db.Exec(`UPDATE deployments SET state='completed', current_ring=1, max_failure_pct=100 WHERE deployment_id=?`, d.DeploymentID)

	out, err := s.RetryFailed(ctx, "user:otto", d.DeploymentID, "disk cleaned")
	if err != nil {
		t.Fatal(err)
	}
	if out.State != "active" || out.StateReason != "retry requested by otto: disk cleaned" {
		t.Errorf("deployment: %s %q", out.State, out.StateReason)
	}
	for _, ep := range []string{"e-p", "e-b"} {
		if st, n := targetRow(t, s, d.DeploymentID, ep); st != "pending" || n != 0 {
			t.Errorf("%s: %s/%d", ep, st, n)
		}
	}
	if st, _ := targetRow(t, s, d.DeploymentID, "e-ok"); st != "verified" {
		t.Errorf("e-ok touched: %s", st)
	}
	evs, _ := s.ListAudit(ctx, AuditQuery{Action: "deployment.retry_failed"})
	if len(evs) != 1 || !strings.Contains(string(evs[0].Details), `"completed"`) || !strings.Contains(string(evs[0].Details), "e-p") {
		t.Errorf("audit: %+v", evs)
	}

	// A completed deployment whose package is no longer approved is not reopened.
	s.db.Exec(`UPDATE targets SET state='failed', attempts=1`)
	s.db.Exec(`UPDATE deployments SET state='completed' WHERE deployment_id=?`, d.DeploymentID)
	s.db.Exec(`UPDATE packages SET state='revoked' WHERE package_id='KB7-x64'`)
	if _, err := s.RetryFailed(ctx, "user:otto", d.DeploymentID, "x"); !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "approved") {
		t.Errorf("revoked package: %v", err)
	}
	s.db.Exec(`UPDATE deployments SET state='cancelled' WHERE deployment_id=?`, d.DeploymentID)
	if _, err := s.RetryFailed(ctx, "user:otto", d.DeploymentID, "x"); !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "active, paused or completed") {
		t.Errorf("cancelled: %v", err)
	}
}
