package e2e

import (
	"encoding/json"
	"strings"
	"testing"

	"offpatch/internal/agent"
	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

// One person cannot pass the two-person rule through user management, and
// an approved deployment cannot be widened by editing endpoint groups.
func TestApprovalFreshAccountsAndFixedScope(t *testing.T) {
	e := newEnvOpts(t, false, `"deployment_approvals": 2,`) // several approvers (default is 1)
	e.intakeApproved(map[string]manifest.Package{"KB5009311-x64": msuPkg("KB5009311-x64", "KB5009311")}, 1)
	a1 := e.enroll("pc-1", []string{"pilot"}, agent.SimConfig{})
	a2 := e.enroll("pc-2", []string{"branch"}, agent.SimConfig{})
	reason := map[string]string{"reason": "CAB-77"}

	// The vendor creates two bank users and approves otto's deployment with them.
	for _, u := range []string{"y1", "y2"} {
		if c := e.api("POST", "/api/users", tokSuper, map[string]string{"email": u + "@bank.example", "role": "user", "password": "temporary password " + u}, nil); c != 201 {
			t.Fatalf("create %s: %d", u, c)
		}
	}
	y1 := e.passwordUser(t, "y1@bank.example", "temporary password y1", "y1's own passphrase")
	y2 := e.passwordUser(t, "y2@bank.example", "temporary password y2", "y2's own passphrase")
	var d store.Deployment
	dep := store.NewDeployment{PackageID: "KB5009311-x64", Name: "CU", Rings: []store.Ring{{Name: "pilot", Groups: []string{"pilot"}}}, MaxFailurePct: 50}
	if c := e.api("POST", "/api/deployments", tokOperator, dep, &d); c != 201 {
		t.Fatalf("create: %d", c)
	}
	path := e.srv.URL + "/api/deployments/" + d.DeploymentID + "/approve"
	if c, b := call(t, y1, "POST", path, reason, true); c != 200 {
		t.Fatalf("y1 approves: %d %s", c, b)
	}
	// Who set up the accounts does not matter (owner decision); fresh
	// accounts raise an alert per approval.
	c, b := call(t, y2, "POST", path, reason, true)
	json.Unmarshal(b, &d)
	if c != 200 || d.State != "active" || d.ScopeEndpoints != 1 {
		t.Fatalf("y2 approves: %d %s", c, b)
	}
	var as []store.Alert
	e.api("GET", "/api/alerts?open=1", tokViewer, nil, &as)
	fresh := 0
	for _, a := range as {
		if a.Kind == "approval_fresh_account" && a.ObjectID == d.DeploymentID && a.Severity == "critical" {
			fresh++
		}
	}
	if fresh != 2 {
		t.Fatalf("fresh-account approval alerts: %d", fresh)
	}
	// A user puts pc-2 into pilot: it is not added to the approved deployment.
	if c := e.api("PATCH", "/api/endpoints/"+a2.id, tokOperator, map[string]any{"groups": []string{"pilot", "branch"}}, nil); c != 200 {
		t.Fatalf("edit groups: %d", c)
	}
	e.cycle(a1)
	e.cycle(a2)
	got := e.deployment(d.DeploymentID)
	if len(got.Targets) != 1 || got.Targets[0].EndpointID != a1.id || got.ScopeExcluded != 1 {
		t.Fatalf("scope widened after approval: targets %+v excluded %d", got.Targets, got.ScopeExcluded)
	}
	if simHasKB(a2, "KB5009311") {
		t.Fatal("pc-2 installed a deployment it was not approved for")
	}
	var evs []store.AuditEvent
	e.api("GET", "/api/audit?action=deployment.scope_excluded&limit=10", tokViewer, nil, &evs)
	if len(evs) != 1 || !strings.Contains(string(evs[0].Details), a2.id) {
		t.Fatalf("exclusion audit: %+v", evs)
	}

	// A bank admin cannot take over another admin's account.
	if c := e.api("POST", "/api/users", tokSuper, map[string]string{"email": "boss@bank.example", "role": "admin", "password": "temporary password boss"}, nil); c != 201 {
		t.Fatal("create admin")
	}
	boss := e.passwordUser(t, "boss@bank.example", "temporary password boss", "boss's own passphrase")
	if c, b := call(t, boss, "POST", e.srv.URL+"/api/users/adam@bank.test/reset_password", map[string]string{"reason": "x"}, true); c != 403 {
		t.Fatalf("admin resets another admin: %d %s", c, b)
	}
}
