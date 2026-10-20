package e2e

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"offpatch/internal/agent"
	"offpatch/internal/manifest"
	"offpatch/internal/store"
	"offpatch/internal/totp"
)

func init() { store.PasswordIterations = 1000 } // fast tests

// passwordUser signs a local user in (email + password) and returns a
// cookie client. When the password is temporary, it is changed to newPW.
func (e *env) passwordUser(t *testing.T, email, pw, newPW string) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	code, b := call(t, c, "POST", e.srv.URL+"/api/auth/login", map[string]string{"email": email, "password": pw}, true)
	var res map[string]any
	json.Unmarshal(b, &res)
	if code != 200 {
		t.Fatalf("login %s: %d %s", email, code, b)
	}
	if res["must_change_password"] == true {
		if code, b := call(t, c, "GET", e.srv.URL+"/api/summary", nil, false); code != 403 || !strings.Contains(string(b), "password_change_required") {
			t.Fatalf("temporary password allowed other calls: %d %s", code, b)
		}
		if code, b := call(t, c, "POST", e.srv.URL+"/api/auth/password", map[string]string{"current": pw, "new": newPW}, true); code != 200 {
			t.Fatalf("change password %s: %d %s", email, code, b)
		}
	}
	if res["mfa_enrollment_required"] == true {
		// Bank roles enrol an authenticator before anything else.
		if code, b := call(t, c, "GET", e.srv.URL+"/api/summary", nil, false); code != 403 || !strings.Contains(string(b), "mfa_enrollment_required") {
			t.Fatalf("MFA enrolment not enforced: %d %s", code, b)
		}
		code, b := call(t, c, "POST", e.srv.URL+"/api/auth/mfa/enroll/start", map[string]any{}, true)
		var en store.MFAEnrollment
		json.Unmarshal(b, &en)
		if code != 200 {
			t.Fatalf("enrol %s: %d %s", email, code, b)
		}
		sec, _ := totp.DecodeSecret(en.SecretBase32)
		e.mfa[email] = sec
		if code, b := call(t, c, "POST", e.srv.URL+"/api/auth/mfa/enroll/confirm", map[string]string{"code": totp.Code(sec, time.Now())}, true); code != 200 {
			t.Fatalf("confirm enrolment %s: %d %s", email, code, b)
		}
	}
	return c
}

// The two-person rule end to end, with console (email + password) users:
// create → nothing installs → creator and vendor cannot approve → two bank
// users approve → agents install. A rollback is rejected.
func TestTwoPersonDeploymentApproval(t *testing.T) {
	e := newEnv(t)
	e.intakeApproved(map[string]manifest.Package{"KB5009301-x64": msuPkg("KB5009301-x64", "KB5009301")}, 1)
	a1 := e.enroll("pc-1", []string{"pilot"}, agent.SimConfig{})
	a2 := e.enroll("pc-2", []string{"pilot"}, agent.SimConfig{})

	// The vendor super admin (break-glass token here) creates the bank admin;
	// the bank admin creates the bank users.
	var created map[string]any
	if c := e.api("POST", "/api/users", tokSuper, map[string]string{"email": "adam.bank@bank.example", "display_name": "Adam", "role": "admin", "password": "temporary password A"}, &created); c != 201 {
		t.Fatalf("create admin: %d", c)
	}
	adam := e.passwordUser(t, "adam.bank@bank.example", "temporary password A", "adam's own passphrase")
	// uma by adam, ivy by the vendor: set up by different people, so they
	// count as two (accounts one person set up would not).
	if c, b := call(t, adam, "POST", e.srv.URL+"/api/users", map[string]string{"email": "uma@bank.example", "role": "user", "password": "temporary password uma"}, true); c != 201 {
		t.Fatalf("create uma: %d %s", c, b)
	}
	if c := e.api("POST", "/api/users", tokSuper, map[string]string{"email": "ivy@bank.example", "role": "user", "password": "temporary password ivy"}, nil); c != 201 {
		t.Fatalf("create ivy: %d", c)
	}
	uma := e.passwordUser(t, "uma@bank.example", "temporary password uma", "uma's own passphrase")
	ivy := e.passwordUser(t, "ivy@bank.example", "temporary password ivy", "ivy's own passphrase")

	// Create: waits for approval, nothing is dispatched.
	dep := store.NewDeployment{PackageID: "KB5009301-x64", Name: "Nov CU", Rings: []store.Ring{{Name: "pilot", Groups: []string{"pilot"}}}, MaxFailurePct: 50}
	c, b := call(t, uma, "POST", e.srv.URL+"/api/deployments", dep, true)
	var d store.Deployment
	json.Unmarshal(b, &d)
	if c != 201 || d.State != "pending_approval" || d.ApprovalsRequired != 2 || d.CreatedBy != "user:uma@bank.example" {
		t.Fatalf("create: %d %s", c, b)
	}
	e.cycle(a1)
	e.cycle(a2)
	if simHasKB(a1, "KB5009301") || simHasKB(a2, "KB5009301") || len(e.deployment(d.DeploymentID).Targets) != 0 {
		t.Fatal("installed before approval")
	}
	approve := func(cl *http.Client, reason string) (int, store.Deployment) {
		t.Helper()
		c, b := call(t, cl, "POST", e.srv.URL+"/api/deployments/"+d.DeploymentID+"/approve", map[string]string{"reason": reason}, true)
		var out store.Deployment
		json.Unmarshal(b, &out)
		return c, out
	}
	if c, _ := approve(uma, "mine"); c != 409 {
		t.Fatalf("creator approves: %d", c)
	}
	if c := e.api("POST", "/api/deployments/"+d.DeploymentID+"/approve", tokSuper, map[string]string{"reason": "vendor"}, nil); c != 403 {
		t.Fatalf("super admin (vendor) approves: %d", c)
	}
	if c := e.api("POST", "/api/deployments/"+d.DeploymentID+"/approve", tokViewer, map[string]string{"reason": "x"}, nil); c != 403 {
		t.Fatalf("viewer approves: %d", c)
	}
	if c, _ := approve(ivy, ""); c != 400 {
		t.Fatalf("approval without reason: %d", c)
	}
	c, d1 := approve(ivy, "CHG-42 reviewed")
	if c != 200 || d1.State != "pending_approval" || len(d1.Approvals) != 1 || d1.Approvals[0].By != "user:ivy@bank.example" {
		t.Fatalf("first approval: %d %+v", c, d1)
	}
	if c, _ := approve(ivy, "again"); c != 409 {
		t.Fatalf("same person twice: %d", c)
	}
	e.cycle(a1)
	if simHasKB(a1, "KB5009301") {
		t.Fatal("installed after one approval")
	}
	// adam set up uma's account (the creator): not a second person.
	if c, _ := approve(adam, "CAB ok"); c != 409 {
		t.Fatalf("approval by the creator's admin: %d", c)
	}
	var d2 store.Deployment
	c = e.api("POST", "/api/deployments/"+d.DeploymentID+"/approve", tokApprover, map[string]string{"reason": "CAB ok"}, &d2)
	if c != 200 || d2.State != "active" || len(d2.Approvals) != 2 || d2.ActivatedAt == "" || !strings.Contains(d2.StateReason, "ivy@bank.example") {
		t.Fatalf("second approval: %d %+v", c, d2)
	}
	for i := 0; i < 2; i++ {
		e.cycle(a1)
		e.cycle(a2)
	}
	if !simHasKB(a1, "KB5009301") || !simHasKB(a2, "KB5009301") {
		t.Fatal("not installed after two approvals")
	}
	var evs []store.AuditEvent
	e.api("GET", "/api/audit?object_id="+d.DeploymentID, tokViewer, nil, &evs)
	var acts []string
	for _, ev := range evs {
		acts = append(acts, ev.Action)
		if ev.Action == "deployment.activated" && (!strings.Contains(string(ev.Details), "ivy@bank.example") || !strings.Contains(string(ev.Details), "alice@bank.test")) {
			t.Fatalf("activation names: %s", ev.Details)
		}
	}
	j := strings.Join(acts, ",")
	if strings.Count(j, "deployment.approved") != 2 || !strings.Contains(j, "deployment.activated") || !strings.Contains(j, "deployment.created") {
		t.Fatalf("audit: %s", j)
	}
	var alerts []store.Alert
	e.api("GET", "/api/alerts", tokViewer, nil, &alerts)
	for _, a := range alerts {
		if a.Kind == "deployment_awaiting_approval" && a.ObjectID == d.DeploymentID && a.ResolvedAt == "" {
			t.Fatalf("awaiting-approval alert still open: %+v", a)
		}
	}

	// A rollback also waits; a rejection is final and its reason shows.
	rb := store.NewDeployment{PackageID: "KB5009301-x64", Name: "undo", Rings: dep.Rings, MaxFailurePct: 50, Operation: "rollback", Justification: "breaks the teller app"}
	if st := e.deployment(d.DeploymentID).State; st != "completed" {
		t.Fatalf("install deployment: %s", st)
	}
	c, b = call(t, uma, "POST", e.srv.URL+"/api/deployments", rb, true)
	var r store.Deployment
	json.Unmarshal(b, &r)
	if c != 201 || r.State != "pending_approval" {
		t.Fatalf("rollback: %d %s", c, b)
	}
	if c, _ := call(t, uma, "POST", e.srv.URL+"/api/deployments/"+r.DeploymentID+"/reject", map[string]string{"reason": "x"}, true); c != 409 {
		t.Fatalf("creator rejects: %d", c)
	}
	if c, b := call(t, ivy, "POST", e.srv.URL+"/api/deployments/"+r.DeploymentID+"/reject", map[string]string{"reason": "outside the change window"}, true); c != 200 {
		t.Fatalf("reject: %d %s", c, b)
	}
	if r := e.deployment(r.DeploymentID); r.State != "rejected" || r.RejectedBy != "user:ivy@bank.example" || r.StateReason != "outside the change window" {
		t.Fatalf("rejected rollback: %+v", r.Deployment)
	}
	e.cycle(a1)
	if !simHasKB(a1, "KB5009301") {
		t.Fatal("rejected rollback removed the update")
	}
}
