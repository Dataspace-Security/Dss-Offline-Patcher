package store

import (
	"context"
	"errors"
	"strings"
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

// One admin creates two accounts and approves their own deployment with
// them: refused, whenever it happens.
func TestApprovalStewardIsCreator(t *testing.T) {
	s, ctx := approvalFixture(t)
	mkUser(t, s, bySuper, "adam@bank.example", RoleAdmin)
	at(s, -90*24*time.Hour, func() { mkUser(t, s, byAdmin, "x1@bank.example", RoleUser) })
	d := newPending(t, s, byAdmin.Actor)
	_, err := s.ApproveDeployment(ctx, "user:x1@bank.example", RoleUser, d.DeploymentID, "ok")
	if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "who created this deployment") {
		t.Fatalf("approval from an account the creator set up (90 days ago): %v", err)
	}
	if auditCount(t, s, "deployment.approval_refused", d.DeploymentID) != 1 {
		t.Fatal("refusal not audited")
	}
	// A password reset by the creator makes them the steward again.
	mkUser(t, s, bySuper, "carol@bank.example", RoleUser)
	if err := s.ResetLocalPassword(ctx, byAdmin, "carol@bank.example", "temporary password 9", "forgot"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApproveDeployment(ctx, "user:carol@bank.example", RoleUser, d.DeploymentID, "ok"); !errors.Is(err, ErrConflict) {
		t.Fatalf("approval after the creator reset the password: %v", err)
	}
	// ... and so does an MFA reset or a role change.
	mkUser(t, s, bySuper, "dave@bank.example", RoleUser)
	mkUser(t, s, bySuper, "erin@bank.example", RoleViewer)
	if err := s.ResetMFA(ctx, byAdmin, "dave@bank.example", "new phone"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetLocalUserRole(ctx, byAdmin, "erin@bank.example", RoleUser, "joins ops"); err != nil {
		t.Fatal(err)
	}
	for _, who := range []string{"dave", "erin"} {
		if _, err := s.ApproveDeployment(ctx, "user:"+who+"@bank.example", RoleUser, d.DeploymentID, "ok"); !errors.Is(err, ErrConflict) {
			t.Fatalf("%s: approval after the creator set the credentials: %v", who, err)
		}
	}
	if got, _ := s.GetDeployment(ctx, d.DeploymentID); len(got.Approvals) != 0 || got.State != "pending_approval" {
		t.Fatalf("refused approvals recorded: %+v", got.Deployment)
	}
}

// The super admin (vendor) creates two bank users and approves with both:
// two freshly provisioned accounts of one steward count as one person.
func TestApprovalSameFreshSteward(t *testing.T) {
	s, ctx := approvalFixture(t)
	mkUser(t, s, bySuper, "x1@bank.example", RoleUser)
	mkUser(t, s, bySuper, "x2@bank.example", RoleUser)
	d := newPending(t, s, "user:otto@bank.example")
	if _, err := s.ApproveDeployment(ctx, "user:x1@bank.example", RoleUser, d.DeploymentID, "ok"); err != nil {
		t.Fatal(err)
	}
	if n := openAlertsOf(t, s, "approval_fresh_account", d.DeploymentID); n != 1 {
		t.Fatalf("approval by a fresh account: %d alerts", n)
	}
	as, _ := s.ListAlerts(ctx, true)
	for _, a := range as {
		if a.Kind == "approval_fresh_account" && a.Severity != "critical" {
			t.Fatalf("fresh-account alert severity %s", a.Severity)
		}
	}
	_, err := s.ApproveDeployment(ctx, "user:x2@bank.example", RoleUser, d.DeploymentID, "ok")
	if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "do not count as two people") {
		t.Fatalf("second fresh account of the same steward: %v", err)
	}
	// A real colleague (not provisioned by the same person) completes it.
	got, err := s.ApproveDeployment(ctx, "user:approver-a", RoleUser, d.DeploymentID, "ok")
	if err != nil || got.State != "active" {
		t.Fatalf("colleague approves: %v %s", err, got.State)
	}
	// After the fresh window the same two accounts are ordinary colleagues.
	if _, err := s.DeploymentAction(ctx, "user:otto@bank.example", d.DeploymentID, "cancel", "redo"); err != nil {
		t.Fatal(err)
	}
	at(s, FreshCredentials+time.Hour, func() {
		d2 := newPending(t, s, "user:otto@bank.example")
		for _, x := range []string{"x1", "x2"} {
			if _, err := s.ApproveDeployment(ctx, "user:"+x+"@bank.example", RoleUser, d2.DeploymentID, "ok"); err != nil {
				t.Fatalf("%s after %v: %v", x, FreshCredentials, err)
			}
		}
		if n := openAlertsOf(t, s, "approval_fresh_account", d2.DeploymentID); n != 0 {
			t.Fatalf("accounts set up long ago raised %d alerts", n)
		}
	})
}

// The normal case: one admin created every bank account months ago,
// including the deployment's creator; two colleagues approve.
func TestApprovalAccountsCreatedLongAgoByOneAdmin(t *testing.T) {
	s, ctx := approvalFixture(t)
	at(s, -120*24*time.Hour, func() {
		mkUser(t, s, bySuper, "adam@bank.example", RoleAdmin)
		for _, u := range []string{"otto", "bob", "carol"} {
			mkUser(t, s, byAdmin, u+"@bank.example", RoleUser)
		}
	})
	d := newPending(t, s, "user:otto@bank.example")
	for _, u := range []string{"bob", "carol"} {
		if _, err := s.ApproveDeployment(ctx, "user:"+u+"@bank.example", RoleUser, d.DeploymentID, "CAB-1"); err != nil {
			t.Fatalf("%s approves: %v", u, err)
		}
	}
	got, _ := s.GetDeployment(ctx, d.DeploymentID)
	if got.State != "active" || openAlertsOf(t, s, "approval_fresh_account", d.DeploymentID) != 0 {
		t.Fatalf("normal approval: %s, alerts %d", got.State, openAlertsOf(t, s, "approval_fresh_account", d.DeploymentID))
	}
	// The admin who created everyone may also approve (they are not the creator).
	if _, err := s.DeploymentAction(ctx, "user:otto@bank.example", d.DeploymentID, "cancel", "redo"); err != nil {
		t.Fatal(err)
	}
	d2 := newPending(t, s, "user:otto@bank.example")
	if _, err := s.ApproveDeployment(ctx, byAdmin.Actor, RoleAdmin, d2.DeploymentID, "ok"); err != nil {
		t.Fatalf("admin approves: %v", err)
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
