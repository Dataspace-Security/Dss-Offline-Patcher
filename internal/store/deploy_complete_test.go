package store

import (
	"context"
	"testing"
)

func depState(t *testing.T, s *Store, id string) (string, int) {
	t.Helper()
	var st string
	var ring int
	if err := s.db.QueryRow(`SELECT state, current_ring FROM deployments WHERE deployment_id=?`, id).Scan(&st, &ring); err != nil {
		t.Fatal(err)
	}
	return st, ring
}

var acmeCurrent = []InventoryItem{{Kind: "product", ID: "{A}", Name: "Acme App", Version: "3.0.0"}}

// A deployment whose targets are all terminal at creation (already present
// per inventory) completes immediately instead of staying active forever.
func TestDeploymentCompletesAtCreationWhenNothingToDo(t *testing.T) {
	s := openTest(t)
	addPackage(t, s, Package{PackageID: "Acme-3.0", Kind: "msi", Version: "3.0.0", PackageName: "Acme App", ProductCode: "{A}"})
	addEndpoint(t, s, "e-1", []string{"pilot"}, acmeCurrent)
	addEndpoint(t, s, "e-2", []string{"pilot"}, acmeCurrent)

	d := newDeployment(t, s, "Acme-3.0", []Ring{{Name: "all", Groups: []string{"all"}}}, 1)
	if d.State != "completed" {
		t.Fatalf("single ring, all verified at creation: state=%s reason=%q counts=%+v", d.State, d.StateReason, d.Counts)
	}
	if st, _ := targetRow(t, s, d.DeploymentID, "e-1"); st != "verified" {
		t.Errorf("target state %s", st)
	}
}

func TestDeploymentMultiRingAtCreation(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	addPackage(t, s, Package{PackageID: "Acme-3.0", Kind: "msi", Version: "3.0.0", PackageName: "Acme App", ProductCode: "{A}"})
	addEndpoint(t, s, "e-pilot", []string{"pilot"}, acmeCurrent)
	rings := []Ring{{Name: "pilot", Groups: []string{"pilot"}}, {Name: "broad", Groups: []string{"broad"}}}

	// Later ring has no endpoints: nothing left to do, completes.
	if d := newDeployment(t, s, "Acme-3.0", rings, 1); d.State != "completed" {
		t.Fatalf("remaining rings empty: state=%s", d.State)
	}

	// Later ring has an endpoint: waits on ring 0 for an advance (existing rule).
	addEndpoint(t, s, "e-broad", []string{"broad"}, acmeCurrent)
	d := newDeployment(t, s, "Acme-3.0", rings, 1)
	if st, ring := depState(t, s, d.DeploymentID); st != "active" || ring != 0 {
		t.Fatalf("multi-ring with a later endpoint: state=%s ring=%d", st, ring)
	}
	// Advancing targets the broad endpoint, already verified: completes.
	out, err := s.DeploymentAction(ctx, "user:otto", d.DeploymentID, "advance", "")
	if err != nil {
		t.Fatal(err)
	}
	if out.State != "completed" || out.CurrentRing != 1 {
		t.Errorf("after advance: state=%s ring=%d", out.State, out.CurrentRing)
	}
}

// The periodic sweep completes an active deployment whose targets became
// terminal without an agent report (and leaves busy ones alone).
func TestSweepDeploymentsCompletesIdle(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	addPackage(t, s, Package{PackageID: "Acme-3.0", Kind: "msi", Version: "3.0.0", PackageName: "Acme App", ProductCode: "{A}"})
	addEndpoint(t, s, "e-1", []string{"pilot"}, []InventoryItem{{Kind: "product", ID: "{OLD}", Name: "Acme App", Version: "2.0.0"}})
	d := newDeployment(t, s, "Acme-3.0", []Ring{{Name: "all", Groups: []string{"all"}}}, 1)
	if d.State != "active" {
		t.Fatalf("pending target: state=%s", d.State)
	}
	if err := s.sweepDeployments(ctx); err != nil {
		t.Fatal(err)
	}
	if st, _ := depState(t, s, d.DeploymentID); st != "active" {
		t.Fatalf("pending target swept to %s", st)
	}
	if _, err := s.db.Exec(`UPDATE targets SET state='verified' WHERE deployment_id=?`, d.DeploymentID); err != nil {
		t.Fatal(err)
	}
	if err := s.sweepDeployments(ctx); err != nil {
		t.Fatal(err)
	}
	if st, _ := depState(t, s, d.DeploymentID); st != "completed" {
		t.Errorf("idle deployment not completed by sweep: %s", st)
	}
}
