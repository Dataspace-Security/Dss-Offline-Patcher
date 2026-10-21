package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// at runs fn with the store clock moved by d (accounts set up in the past).
func at(s *Store, d time.Duration, fn func()) {
	real := s.Now
	s.Now = func() time.Time { return real().Add(d) }
	defer func() { s.Now = real }()
	fn()
}

func auditCount(t *testing.T, s *Store, action, object string) int {
	t.Helper()
	evs, err := s.ListAudit(context.Background(), AuditQuery{Action: action, ObjectID: object, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	return len(evs)
}

var twoRings = []Ring{{Name: "pilot", Groups: []string{"pilot"}}, {Name: "prod", Groups: []string{"prod"}}}

func newPending(t *testing.T, s *Store, creator string) Deployment {
	t.Helper()
	d, err := s.CreateDeployment(context.Background(), creator, NewDeployment{PackageID: "Acme-3.0", Name: "acme", Rings: allRing, MaxFailurePct: 50})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// Two approvals from any two people other than the creator, whoever set up
// their accounts (owner decision: no credential-steward rule). Approvals
// from accounts set up in the last FreshCredentials raise an alert.
func TestApprovalAnySetter(t *testing.T) {
	s, ctx := approvalFixture(t)
	mkUser(t, s, bySuper, "adam@bank.example", RoleAdmin)
	for _, u := range []string{"otto", "x1", "x2"} {
		mkUser(t, s, byAdmin, u+"@bank.example", RoleUser)
	}
	d := newPending(t, s, "user:otto@bank.example")
	if _, err := s.ApproveDeployment(ctx, "user:otto@bank.example", RoleUser, d.DeploymentID, "mine"); !errors.Is(err, ErrConflict) {
		t.Fatalf("creator approves: %v", err)
	}
	if _, err := s.ApproveDeployment(ctx, "user:x1@bank.example", RoleUser, d.DeploymentID, "ok"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApproveDeployment(ctx, "user:x1@bank.example", RoleUser, d.DeploymentID, "again"); !errors.Is(err, ErrConflict) {
		t.Fatalf("same person twice: %v", err)
	}
	got, err := s.ApproveDeployment(ctx, "user:x2@bank.example", RoleUser, d.DeploymentID, "ok")
	if err != nil || got.State != "active" {
		t.Fatalf("second approver set up by the same admin: %v %s", err, got.State)
	}
	if n := openAlertsOf(t, s, "approval_fresh_account", d.DeploymentID); n != 2 {
		t.Fatalf("fresh-account alerts: %d", n)
	}
	if auditCount(t, s, "deployment.approval_refused", d.DeploymentID) != 0 {
		t.Fatal("approval refused")
	}
}

func TestStewardRecordedAndMigrated(t *testing.T) {
	s, ctx := approvalFixture(t)
	mkUser(t, s, bySuper, "adam@bank.example", RoleAdmin)
	mkUser(t, s, byAdmin, "x1@bank.example", RoleUser)
	st, err := credSteward(ctx, s.db, "user:x1@bank.example")
	if err != nil || !st.local || st.by != byAdmin.Actor || st.at == "" {
		t.Fatalf("steward after create: %+v %v", st, err)
	}
	if err := s.ResetLocalPassword(ctx, bySuper, "x1@bank.example", "temporary password 9", "x"); err != nil {
		t.Fatal(err)
	}
	if st, _ = credSteward(ctx, s.db, "user:x1@bank.example"); st.by != bySuper.Actor {
		t.Fatalf("steward after reset: %+v", st)
	}
	// Accounts from before stewards: their creator.
	if _, err := s.db.Exec(`UPDATE local_users SET cred_set_by='', cred_set_at='' WHERE email='x1@bank.example'`); err != nil {
		t.Fatal(err)
	}
	if err := migrate(s.db); err != nil {
		t.Fatal(err)
	}
	if st, _ = credSteward(ctx, s.db, "user:x1@bank.example"); st.by != byAdmin.Actor {
		t.Fatalf("migrated steward: %+v", st)
	}
	if st, _ = credSteward(ctx, s.db, "user:sso@bank.example"); st.local {
		t.Fatalf("SSO user has a local steward: %+v", st)
	}
}
