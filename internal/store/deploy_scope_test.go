package store

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func hasTarget(t *testing.T, s *Store, dep, ep string) bool {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM targets WHERE deployment_id=? AND endpoint_id=?`, dep, ep).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n > 0
}

// After approval, adding endpoints to the deployment's ring groups (group
// edit, enrolment, check-in) does not widen it; snapshot members still get
// their later-ring targets.
func TestApprovedScopeIsFixed(t *testing.T) {
	s, ctx := approvalFixture(t) // e-old in pilot
	addEndpoint(t, s, "e-prod", []string{"prod"}, acmeOld)
	addEndpoint(t, s, "e-other", []string{"other"}, acmeOld)
	d, err := createApproved(s, ctx, "user:otto", NewDeployment{PackageID: "Acme-3.0", Name: "acme", Rings: twoRings, MaxFailurePct: 50})
	if err != nil {
		t.Fatal(err)
	}
	if d.State != "active" || d.ScopeEndpoints != 2 || d.ScopeExcluded != 0 {
		t.Fatalf("activated: %s scope %d excluded %d", d.State, d.ScopeEndpoints, d.ScopeExcluded)
	}
	evs, _ := s.ListAudit(ctx, AuditQuery{Action: "deployment.activated", ObjectID: d.DeploymentID})
	var det map[string]any
	if len(evs) != 1 || json.Unmarshal(evs[0].Details, &det) != nil || det["approved_endpoints"] != float64(2) {
		t.Fatalf("activation audit: %+v", evs)
	}
	// A user puts another existing endpoint, and a newly enrolled one, into pilot.
	pilot := []string{"pilot"}
	if _, err := s.UpdateEndpoint(ctx, "user:mallory", "e-other", EndpointPatch{Groups: &pilot}); err != nil {
		t.Fatal(err)
	}
	addEndpoint(t, s, "e-new", []string{"pilot"}, acmeOld)
	checkin(t, s, "e-new", acmeOld, false)
	checkin(t, s, "e-new", acmeOld, false)
	for _, ep := range []string{"e-other", "e-new"} {
		if hasTarget(t, s, d.DeploymentID, ep) {
			t.Fatalf("%s joined pilot after approval and got a target", ep)
		}
	}
	if !hasTarget(t, s, d.DeploymentID, "e-old") {
		t.Fatal("approved pilot endpoint has no target")
	}
	got, _ := s.GetDeployment(ctx, d.DeploymentID)
	if got.ScopeEndpoints != 2 || got.ScopeExcluded != 2 {
		t.Fatalf("scope %d excluded %d", got.ScopeEndpoints, got.ScopeExcluded)
	}
	if n := auditCount(t, s, "deployment.scope_excluded", d.DeploymentID); n != 2 {
		t.Fatalf("scope_excluded audited %d times (once per endpoint)", n)
	}
	// The next ring: the approved prod endpoint gets its target; the
	// excluded ones still do not (also if moved to prod).
	prod := []string{"prod"}
	if _, err := s.UpdateEndpoint(ctx, "user:mallory", "e-new", EndpointPatch{Groups: &prod}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeploymentAction(ctx, "user:otto", d.DeploymentID, "advance", ""); err != nil {
		t.Fatal(err)
	}
	if !hasTarget(t, s, d.DeploymentID, "e-prod") {
		t.Fatal("approved prod endpoint has no target after advance")
	}
	if hasTarget(t, s, d.DeploymentID, "e-new") || hasTarget(t, s, d.DeploymentID, "e-other") {
		t.Fatal("excluded endpoint targeted after advance")
	}
}

// Approving a deployment whose ring groups are empty: nothing can join
// later, so it completes instead of waiting forever.
func TestEmptyApprovedScopeCompletes(t *testing.T) {
	s, ctx := approvalFixture(t)
	d, err := createApproved(s, ctx, "user:otto", NewDeployment{PackageID: "Acme-3.0", Name: "acme", Rings: []Ring{{Name: "x", Groups: []string{"nobody"}}}, MaxFailurePct: 50})
	if err != nil {
		t.Fatal(err)
	}
	if d.State != "completed" || d.ScopeEndpoints != 0 {
		t.Fatalf("empty scope: %s %q scope %d", d.State, d.StateReason, d.ScopeEndpoints)
	}
}

// Deployments already running when scopes were introduced keep their
// targets and current ring members, and the scope is fixed only once.
func TestDeploymentScopeMigration(t *testing.T) {
	s, ctx := approvalFixture(t)
	addEndpoint(t, s, "e-prod", []string{"prod"}, acmeOld)
	d, err := createApproved(s, ctx, "user:otto", NewDeployment{PackageID: "Acme-3.0", Name: "acme", Rings: twoRings, MaxFailurePct: 50})
	if err != nil {
		t.Fatal(err)
	}
	// As before this version: no scope; a target whose endpoint left the groups.
	addEndpoint(t, s, "e-left", []string{"other"}, acmeOld)
	addTarget(t, s, d.DeploymentID, "e-left", "Acme-3.0", "pending", 0, 0)
	if _, err := s.db.Exec(`DELETE FROM deployment_scope; UPDATE deployments SET scope_at=''`); err != nil {
		t.Fatal(err)
	}
	addEndpoint(t, s, "e-late", []string{"prod"}, acmeOld)
	if err := migrate(s.db); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetDeployment(ctx, d.DeploymentID)
	if got.ScopeEndpoints != 4 {
		t.Fatalf("migrated scope: %d (want e-old, e-prod, e-late, e-left)", got.ScopeEndpoints)
	}
	addEndpoint(t, s, "e-after", []string{"prod"}, acmeOld)
	if err := migrate(s.db); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.GetDeployment(ctx, d.DeploymentID); got.ScopeEndpoints != 4 {
		t.Fatalf("second migration widened the scope: %d", got.ScopeEndpoints)
	}
}

// Group A, then group B: a second deployment of a package may run at the
// same time for other machines, never for a machine the first one covers.
func TestDeploymentsForOtherMachinesRunTogether(t *testing.T) {
	s, ctx := approvalFixture(t) // e-old in group pilot
	addEndpoint(t, s, "e-b1", []string{"branch"}, acmeOld)
	addEndpoint(t, s, "e-b2", []string{"branch"}, acmeOld)
	pilot := NewDeployment{PackageID: "Acme-3.0", Name: "pilot", Rings: []Ring{{Name: "p", Groups: []string{"pilot"}}}, MaxFailurePct: 50}
	if _, err := createApproved(s, ctx, "user:otto", pilot); err != nil {
		t.Fatal(err)
	}
	one := NewDeployment{PackageID: "Acme-3.0", Name: "b1", Rings: []Ring{{Name: "c", Groups: []string{"endpoint:e-b1"}}}, MaxFailurePct: 50}
	if _, err := s.CreateDeployment(ctx, "user:otto", one); err != nil {
		t.Fatalf("other machine while pilot runs: %v", err)
	}
	// e-b1 is covered by the waiting one; e-old by the active one.
	for _, n := range []NewDeployment{
		{PackageID: "Acme-3.0", Name: "branch", Rings: []Ring{{Name: "b", Groups: []string{"branch"}}}, MaxFailurePct: 50},
		{PackageID: "Acme-3.0", Name: "everyone", Rings: allRing, MaxFailurePct: 50},
	} {
		_, err := s.CreateDeployment(ctx, "user:otto", n)
		if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "already covers 1 of these machines") {
			t.Fatalf("%s: want overlap refusal, got %v", n.Name, err)
		}
	}
	two := NewDeployment{PackageID: "Acme-3.0", Name: "b2", Rings: []Ring{{Name: "c", Groups: []string{"endpoint:e-b2"}}}, MaxFailurePct: 50}
	if _, err := s.CreateDeployment(ctx, "user:otto", two); err != nil {
		t.Fatalf("third machine: %v", err)
	}
}
