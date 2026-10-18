package store

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// createApproved creates a deployment and approves it with two bank users
// (not the creator), so tests of what happens after approval read as before.
func createApproved(s *Store, ctx context.Context, actor string, n NewDeployment) (Deployment, error) {
	d, err := s.CreateDeployment(ctx, actor, n)
	if err != nil {
		return d, err
	}
	for i := 0; i < s.Policy.RequiredDeploymentApprovals(); i++ {
		if d, err = s.ApproveDeployment(ctx, "user:approver-"+string(rune('a'+i)), RoleUser, d.DeploymentID, "looks good"); err != nil {
			return d, err
		}
	}
	return d, nil
}

func approvalFixture(t *testing.T) (*Store, context.Context) {
	t.Helper()
	s := openTest(t)
	addPackage(t, s, Package{PackageID: "Acme-3.0", Kind: "msi", Version: "3.0.0", PackageName: "Acme App", ProductCode: "{A}"})
	addEndpoint(t, s, "e-old", []string{"pilot"}, acmeOld)
	return s, context.Background()
}

func targetCount(t *testing.T, s *Store, dep string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM targets WHERE deployment_id=?`, dep).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func openAlertsOf(t *testing.T, s *Store, kind, object string) int {
	t.Helper()
	as, err := s.ListAlerts(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, a := range as {
		if a.Kind == kind && a.ObjectID == object {
			n++
		}
	}
	return n
}

var allRing = []Ring{{Name: "all", Groups: []string{"all"}}}

func TestDeploymentNeedsTwoApprovals(t *testing.T) {
	s, ctx := approvalFixture(t)
	d, err := s.CreateDeployment(ctx, "user:otto", NewDeployment{PackageID: "Acme-3.0", Name: "acme", Rings: allRing, MaxFailurePct: 50})
	if err != nil {
		t.Fatal(err)
	}
	if d.State != "pending_approval" || d.ApprovalsRequired != 2 || len(d.Approvals) != 0 || d.ActivatedAt != "" {
		t.Fatalf("created: %+v", d)
	}
	if n := targetCount(t, s, d.DeploymentID); n != 0 {
		t.Fatalf("pending deployment has %d targets; nothing may be dispatched before approval", n)
	}
	if res := checkin(t, s, "e-old", acmeOld, false); len(res.Assignments) != 0 {
		t.Fatalf("pending deployment assigned: %+v", res.Assignments)
	}
	if openAlertsOf(t, s, "deployment_awaiting_approval", d.DeploymentID) != 1 {
		t.Fatal("no deployment_awaiting_approval alert")
	}
	id := d.DeploymentID
	for _, c := range []struct {
		what, actor, role, reason string
		want                      error
	}{
		{"creator", "user:otto", RoleUser, "ok", ErrConflict},
		{"viewer", "user:vera", RoleViewer, "ok", ErrForbidden},
		{"super admin (vendor)", "user:vendor", RoleSuperAdmin, "ok", ErrForbidden},
		{"no reason", "user:alice", RoleUser, " ", ErrInvalid},
	} {
		if _, err := s.ApproveDeployment(ctx, c.actor, c.role, id, c.reason); !errors.Is(err, c.want) {
			t.Errorf("approve by %s: want %v, got %v", c.what, c.want, err)
		}
	}
	d, err = s.ApproveDeployment(ctx, "user:alice", RoleUser, id, "tested in the lab")
	if err != nil || d.State != "pending_approval" || len(d.Approvals) != 1 || d.Approvals[0].By != "user:alice" || !strings.Contains(d.StateReason, "1 of 2") {
		t.Fatalf("first approval: %v %+v", err, d)
	}
	if _, err := s.ApproveDeployment(ctx, "user:alice", RoleAdmin, id, "again"); !errors.Is(err, ErrConflict) {
		t.Fatalf("same person twice: want conflict, got %v", err)
	}
	if n := targetCount(t, s, id); n != 0 {
		t.Fatalf("one approval dispatched %d targets", n)
	}
	d, err = s.ApproveDeployment(ctx, "user:bob", RoleAdmin, id, "change ticket CHG-1")
	if err != nil || d.State != "active" || len(d.Approvals) != 2 || d.ActivatedAt == "" {
		t.Fatalf("second approval: %v %+v", err, d)
	}
	if n := targetCount(t, s, id); n != 1 {
		t.Fatalf("active deployment: %d targets, want 1", n)
	}
	if res := checkin(t, s, "e-old", acmeOld, false); len(res.Assignments) != 1 {
		t.Fatalf("active deployment not assigned: %+v", res.Assignments)
	}
	if openAlertsOf(t, s, "deployment_awaiting_approval", id) != 0 {
		t.Fatal("awaiting-approval alert still open after activation")
	}
	evs := auditActions(t, s, id)
	if strings.Count(strings.Join(evs, ","), "deployment.approved") != 2 || hasAudit(evs, "deployment.activated") == "" {
		t.Fatalf("audit: %v", evs)
	}
	var det string
	s.db.QueryRow(`SELECT details FROM audit WHERE action='deployment.activated' AND object_id=?`, id).Scan(&det)
	if !strings.Contains(det, "alice") || !strings.Contains(det, "bob") {
		t.Fatalf("deployment.activated names both approvers: %s", det)
	}
	if _, err := s.ApproveDeployment(ctx, "user:carol", RoleUser, id, "late"); !errors.Is(err, ErrConflict) {
		t.Fatalf("approve active: want conflict, got %v", err)
	}
}

func TestDeploymentReject(t *testing.T) {
	s, ctx := approvalFixture(t)
	d, err := s.CreateDeployment(ctx, "user:otto", NewDeployment{PackageID: "Acme-3.0", Name: "acme", Rings: allRing, MaxFailurePct: 50})
	if err != nil {
		t.Fatal(err)
	}
	id := d.DeploymentID
	if _, err := s.ApproveDeployment(ctx, "user:alice", RoleUser, id, "ok"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RejectDeployment(ctx, "user:otto", RoleUser, id, "changed my mind"); !errors.Is(err, ErrConflict) {
		t.Fatalf("creator reject: want conflict (creator cancels instead), got %v", err)
	}
	if _, err := s.RejectDeployment(ctx, "user:vera", RoleViewer, id, "no"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("viewer reject: want forbidden, got %v", err)
	}
	if _, err := s.RejectDeployment(ctx, "user:bob", RoleUser, id, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("reject without reason: want invalid, got %v", err)
	}
	d, err = s.RejectDeployment(ctx, "user:bob", RoleUser, id, "not in the change window")
	if err != nil || d.State != "rejected" || d.RejectedBy != "user:bob" || d.RejectedAt == "" || d.StateReason != "not in the change window" {
		t.Fatalf("reject: %v %+v", err, d)
	}
	if targetCount(t, s, id) != 0 || openAlertsOf(t, s, "deployment_awaiting_approval", id) != 0 {
		t.Fatal("rejected deployment has targets or an open alert")
	}
	if _, err := s.ApproveDeployment(ctx, "user:carol", RoleUser, id, "ok"); !errors.Is(err, ErrConflict) {
		t.Fatalf("approve rejected: want conflict, got %v", err)
	}
	if _, err := s.DeploymentAction(ctx, "user:otto", id, "cancel", "x"); !errors.Is(err, ErrConflict) {
		t.Fatalf("cancel rejected: want conflict, got %v", err)
	}
	if hasAudit(auditActions(t, s, id), "deployment.rejected") == "" {
		t.Fatal("no deployment.rejected audit")
	}
	// Rejected is final and not running: a new deployment may be created.
	if _, err := s.CreateDeployment(ctx, "user:otto", NewDeployment{PackageID: "Acme-3.0", Name: "acme 2", Rings: allRing, MaxFailurePct: 50}); err != nil {
		t.Fatalf("create after reject: %v", err)
	}
}

func TestPendingDeploymentCountsAsRunning(t *testing.T) {
	s, ctx := approvalFixture(t)
	d, err := s.CreateDeployment(ctx, "user:otto", NewDeployment{PackageID: "Acme-3.0", Name: "acme", Rings: allRing, MaxFailurePct: 50})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateDeployment(ctx, "user:alice", NewDeployment{PackageID: "Acme-3.0", Name: "again", Rings: allRing}); !errors.Is(err, ErrConflict) {
		t.Fatalf("second install while pending: want conflict, got %v", err)
	}
	if _, err := s.CreateDeployment(ctx, "user:alice", NewDeployment{PackageID: "Acme-3.0", Name: "undo", Rings: allRing, Operation: "rollback", Justification: "x"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("rollback while install pending: want conflict, got %v", err)
	}
	for _, a := range []string{"pause", "resume", "advance"} {
		if _, err := s.DeploymentAction(ctx, "user:alice", d.DeploymentID, a, "x"); !errors.Is(err, ErrConflict) {
			t.Errorf("%s on pending: want conflict, got %v", a, err)
		}
	}
	if _, err := s.RetryFailed(ctx, "user:alice", d.DeploymentID, "x"); !errors.Is(err, ErrConflict) {
		t.Errorf("retry_failed on pending: want conflict, got %v", err)
	}
	d, err = s.DeploymentAction(ctx, "user:otto", d.DeploymentID, "cancel", "wrong package")
	if err != nil || d.State != "cancelled" {
		t.Fatalf("creator cancels pending: %v %s", err, d.State)
	}
	if openAlertsOf(t, s, "deployment_awaiting_approval", d.DeploymentID) != 0 {
		t.Fatal("alert still open after cancel")
	}
	if _, err := s.CreateDeployment(ctx, "user:otto", NewDeployment{PackageID: "Acme-3.0", Name: "acme 2", Rings: allRing}); err != nil {
		t.Fatalf("create after cancel: %v", err)
	}
}

func TestRollbackNeedsApproval(t *testing.T) {
	s, ctx := approvalFixture(t)
	addEndpoint(t, s, "e-new", []string{"pilot"}, acmeCurrent)
	r, err := s.CreateDeployment(ctx, "user:otto", NewDeployment{PackageID: "Acme-3.0", Name: "undo", Rings: allRing, MaxFailurePct: 50, Operation: "rollback", Justification: "breaks the teller app"})
	if err != nil || r.State != "pending_approval" || r.Operation != "rollback" {
		t.Fatalf("rollback: %v %+v", err, r)
	}
	if targetCount(t, s, r.DeploymentID) != 0 {
		t.Fatal("pending rollback has targets")
	}
	if _, err := s.ApproveDeployment(ctx, "user:otto", RoleAdmin, r.DeploymentID, "mine"); !errors.Is(err, ErrConflict) {
		t.Fatalf("creator approves own rollback: want conflict, got %v", err)
	}
	s.ApproveDeployment(ctx, "user:alice", RoleUser, r.DeploymentID, "ok")
	r, err = s.ApproveDeployment(ctx, "user:bob", RoleUser, r.DeploymentID, "ok")
	if err != nil || r.State != "active" || targetCount(t, s, r.DeploymentID) == 0 {
		t.Fatalf("approved rollback: %v %+v", err, r)
	}
}

func TestEmergencyDeploymentAlsoPending(t *testing.T) {
	s, ctx := approvalFixture(t)
	d, err := s.CreateDeployment(ctx, "user:otto", NewDeployment{PackageID: "Acme-3.0", Name: "now", Rings: allRing, Emergency: true, Justification: "exploited"})
	if err != nil || d.State != "pending_approval" {
		t.Fatalf("emergency: %v %s", err, d.State)
	}
}

func TestDeploymentApprovalsConfigurable(t *testing.T) {
	s, ctx := approvalFixture(t)
	s.Policy.DeploymentApprovals = 1
	d, err := s.CreateDeployment(ctx, "user:otto", NewDeployment{PackageID: "Acme-3.0", Name: "acme", Rings: allRing, MaxFailurePct: 50})
	if err != nil || d.ApprovalsRequired != 1 {
		t.Fatalf("%v %+v", err, d)
	}
	// The count is fixed at creation: raising it later does not change this one.
	s.Policy.DeploymentApprovals = 3
	if d, err = s.ApproveDeployment(ctx, "user:alice", RoleUser, d.DeploymentID, "ok"); err != nil || d.State != "active" {
		t.Fatalf("one approval with deployment_approvals=1: %v %s", err, d.State)
	}
}

func TestRevokeCancelsPendingDeployment(t *testing.T) {
	s, ctx := approvalFixture(t)
	d, err := s.CreateDeployment(ctx, "user:otto", NewDeployment{PackageID: "Acme-3.0", Name: "acme", Rings: allRing, MaxFailurePct: 50})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetPackageState(ctx, "user:adam", "Acme-3.0", "revoke", "bad build", nil); err != nil {
		t.Fatal(err)
	}
	if st, _ := depState(t, s, d.DeploymentID); st != "cancelled" {
		t.Fatalf("pending install after revoke: %s", st)
	}
	if openAlertsOf(t, s, "deployment_awaiting_approval", d.DeploymentID) != 0 {
		t.Fatal("alert still open")
	}
}

func TestListDeploymentsIncludesApprovals(t *testing.T) {
	s, ctx := approvalFixture(t)
	d, _ := s.CreateDeployment(ctx, "user:otto", NewDeployment{PackageID: "Acme-3.0", Name: "acme", Rings: allRing, MaxFailurePct: 50})
	s.ApproveDeployment(ctx, "user:alice", RoleUser, d.DeploymentID, "ok")
	ds, err := s.ListDeployments(ctx)
	if err != nil || len(ds) != 1 || len(ds[0].Approvals) != 1 || ds[0].ApprovalsRequired != 2 || ds[0].Approvals[0].Reason != "ok" {
		t.Fatalf("%v %+v", err, ds)
	}
	sm, err := s.Summary(ctx, Thresholds{})
	if err != nil || sm.Deployments["pending_approval"] != 1 {
		t.Fatalf("summary: %v %+v", err, sm.Deployments)
	}
}
