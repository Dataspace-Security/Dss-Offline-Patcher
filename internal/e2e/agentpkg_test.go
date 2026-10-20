package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"offpatch/internal/agent"
	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

func agentPkg(version string) manifest.Package {
	return manifest.Package{PackageID: "offpatch-agent-" + version, Title: "offpatch agent " + version, Vendor: "offpatch", Kind: "agent", Version: version,
		Severity: "important", Supersedes: []string{}, Applicability: manifest.Applicability{OS: "windows", Arch: "any"}, VendorSignature: manifest.VendorSignature{Status: "not_checked"}}
}

// secondBankAdmin creates a local bank admin (besides the adam token) and
// returns its signed-in client: agent deployments need two bank admins.
func (e *env) secondBankAdmin(t *testing.T) *http.Client {
	t.Helper()
	// Set up by neither the vendor who creates the agent deployments nor
	// adam who approves them too: accounts one person set up (or that set
	// up the other) don't count as two people.
	if _, err := e.st.CreateLocalUser(context.Background(), store.Manager{Actor: "system:setup-ada", Role: store.RoleSuperAdmin},
		store.NewLocalUser{Email: "ada.admin@bank.example", DisplayName: "Ada", Role: store.RoleAdmin, Password: "temporary password Ada"}, true); err != nil {
		t.Fatalf("create second admin: %v", err)
	}
	return e.passwordUser(t, "ada.admin@bank.example", "temporary password Ada", "ada's own passphrase")
}

// deployAgent creates an agent-version deployment as the super admin and
// approves it with two bank admins (adam's token and ada).
func (e *env) deployAgent(t *testing.T, n store.NewDeployment, ada *http.Client) store.Deployment {
	t.Helper()
	if n.MaxFailurePct == 0 {
		n.MaxFailurePct = 100
	}
	var d store.Deployment
	if c := e.api("POST", "/api/deployments", tokSuper, n, &d); c != 201 {
		t.Fatalf("super admin creates agent deployment: %d", c)
	}
	if c := e.api("POST", "/api/deployments/"+d.DeploymentID+"/approve", tokAdmin, map[string]string{"reason": "agent upgrade CAB"}, nil); c != 200 {
		t.Fatalf("adam approves agent deployment: %d", c)
	}
	c, b := call(t, ada, "POST", e.srv.URL+"/api/deployments/"+d.DeploymentID+"/approve", map[string]string{"reason": "agent upgrade CAB"}, true)
	if c != 200 {
		t.Fatalf("ada approves agent deployment: %d %s", c, b)
	}
	json.Unmarshal(b, &d)
	return d
}

// Agent versions are the vendor's: bank roles may not approve, reject,
// revoke or deploy them; agent deployments are created by the super admin
// and approved by two bank admins (not users).
func TestAgentPackagesVendorOnly(t *testing.T) {
	e := newEnv(t)
	up := agentPkg("0.3.0")
	cu := msuPkg("KB5009401-x64", "KB5009401")
	pk := map[string]manifest.Package{up.PackageID: up, cu.PackageID: cu}
	files := map[string]string{up.PackageID: e.payload("agent-030.bin", "agent 0.3.0"), cu.PackageID: e.payload("kb5009401.msu", "cu")}
	if b := e.transferAndIntake(e.bundle(bundleOpts{seq: 1}, pk, files)); b.State != "validated" {
		t.Fatalf("intake %+v", b)
	}
	reason := map[string]string{"reason": "CAB"}
	for _, tok := range []string{tokApprover, tokAdmin} {
		c, msg := e.apiErr("POST", "/api/packages/"+up.PackageID+"/approve", tok, reason)
		if c != 403 || msg != "agent versions are managed by the vendor (super admin)" {
			t.Fatalf("bank role approving an agent version: %d %q", c, msg)
		}
	}
	if c, _ := e.apiErr("POST", "/api/packages/"+up.PackageID+"/reject", tokAdmin, reason); c != 403 {
		t.Fatalf("bank admin rejecting an agent version: %d", c)
	}
	e.approve(cu.PackageID) // ordinary packages: unchanged
	if c := e.api("POST", "/api/packages/"+up.PackageID+"/approve", tokSuper, reason, nil); c != 200 {
		t.Fatalf("super admin approves the agent version: %d", c)
	}
	a := e.enroll("pc-ag1", []string{"z"}, agent.SimConfig{})
	z := []store.Ring{{Name: "z", Groups: []string{"z"}}}
	n := store.NewDeployment{PackageID: up.PackageID, Name: "agent 0.3.0", Rings: z, MaxFailurePct: 100}
	for _, tok := range []string{tokOperator, tokAdmin} {
		if c, msg := e.apiErr("POST", "/api/deployments", tok, n); c != 403 || !strings.Contains(msg, "vendor (super admin)") {
			t.Fatalf("bank role deploying an agent version: %d %q", c, msg)
		}
	}
	rb := n
	rb.Operation, rb.Name = "rollback", "undo agent"
	if c, _ := e.apiErr("POST", "/api/deployments", tokOperator, rb); c != 403 {
		t.Fatalf("bank user rolling back an agent version: %d", c)
	}
	var d store.Deployment
	if c := e.api("POST", "/api/deployments", tokSuper, n, &d); c != 201 || d.State != "pending_approval" {
		t.Fatalf("super admin creates the agent deployment: %d %+v", c, d)
	}
	// Users cannot approve it; neither can the vendor; bank admins can.
	if c, msg := e.apiErr("POST", "/api/deployments/"+d.DeploymentID+"/approve", tokApprover, reason); c != 403 || msg != "agent version deployments are approved by bank admins" {
		t.Fatalf("bank user approving an agent deployment: %d %q", c, msg)
	}
	if c, _ := e.apiErr("POST", "/api/deployments/"+d.DeploymentID+"/reject", tokUser2, reason); c != 403 {
		t.Fatalf("bank user rejecting an agent deployment: %d", c)
	}
	if c, _ := e.apiErr("POST", "/api/deployments/"+d.DeploymentID+"/approve", tokSuper, reason); c != 403 {
		t.Fatalf("super admin approving its own agent deployment: %d", c)
	}
	if c := e.api("POST", "/api/deployments/"+d.DeploymentID+"/approve", tokAdmin, reason, nil); c != 200 {
		t.Fatalf("adam approves: %d", c)
	}
	ada := e.secondBankAdmin(t)
	c, b := call(t, ada, "POST", e.srv.URL+"/api/deployments/"+d.DeploymentID+"/approve", reason, true)
	if c != 200 || !strings.Contains(string(b), `"state":"active"`) {
		t.Fatalf("second bank admin activates: %d %s", c, b)
	}
	// Running it is the vendor's too: bank roles cannot pause, resume,
	// advance, cancel or retry an agent-version rollout.
	for _, act := range []string{"pause", "resume", "advance", "cancel", "retry_failed"} {
		for _, tok := range []string{tokOperator, tokAdmin} {
			if c, msg := e.apiErr("POST", "/api/deployments/"+d.DeploymentID+"/"+act, tok, reason); c != 403 || !strings.Contains(msg, "vendor (super admin)") {
				t.Fatalf("bank role %s on an agent deployment: %d %q", act, c, msg)
			}
		}
	}
	for _, act := range []string{"pause", "resume"} {
		if c := e.api("POST", "/api/deployments/"+d.DeploymentID+"/"+act, tokSuper, reason, nil); c != 200 {
			t.Fatalf("super admin %s: %d", act, c)
		}
	}
	e.cycle(a)
	e.cycle(a)
	if s := targetState(e.deployment(d.DeploymentID), a.id); s != "verified" {
		t.Fatalf("agent upgrade after admin approvals: %s", s)
	}
	// Refusals are audited.
	var evs []store.AuditEvent
	e.api("GET", "/api/audit?action=access.denied&limit=50", tokViewer, nil, &evs)
	if len(evs) < 5 {
		t.Fatalf("agent refusals not audited: %d events", len(evs))
	}
}

// apiErr calls the API and returns the status and the error message.
func (e *env) apiErr(method, path, token string, body any) (int, string) {
	e.t.Helper()
	var out struct {
		Error string `json:"error"`
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, jsonBody(body))
	e.authorize(req, token)
	resp, err := e.hc.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out.Error
}

func jsonBody(v any) *strings.Reader {
	b, _ := json.Marshal(v)
	return strings.NewReader(string(b))
}
