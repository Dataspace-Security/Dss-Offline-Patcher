// Package e2e exercises the MVP acceptance criteria (docs/00 §9) end to end:
// acquisition → transfer → intake → approval → staged deployment → install →
// verification → audit, plus the negative security cases.
package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"offpatch/internal/agent"
	"offpatch/internal/intake"
	"offpatch/internal/manifest"
	"offpatch/internal/pki"
	"offpatch/internal/repo"
	"offpatch/internal/server"
	"offpatch/internal/store"
	"offpatch/internal/transfer"

	_ "modernc.org/sqlite"
)

const (
	tokViewer   = "viewer-token"
	tokOperator = "operator-token"
	tokApprover = "approver-token"
	msiGUID     = "{11111111-2222-3333-4444-555555555555}"
)

type env struct {
	t          *testing.T
	dir        string
	priv       ed25519.PrivateKey
	pubPEM     string
	st         *store.Store
	intake     *intake.Service
	inbox      string
	srv        *httptest.Server
	repoDir    string
	log        *slog.Logger
	hc         *http.Client // admin client (trusts the test CA in TLS mode)
	caFile     string
	cfg        *server.Config
	rootPEM    string // pinned by agents when set (trust tests)
	rootKey    ed25519.PrivateKey
	srvHandler *server.Server
}

func newEnv(t *testing.T) *env { return newEnvOpts(t, false, "") }

// newEnvOpts: tlsMode runs the server with the internal PKI (mTLS agents);
// extra is spliced into the config JSON (e.g. `"oidc": {...},`).
func newEnvOpts(t *testing.T, tlsMode bool, extra string) *env {
	t.Helper()
	dir := t.TempDir()
	pub, priv, _ := manifest.GenerateKey()
	e := &env{t: t, dir: dir, priv: priv, pubPEM: string(manifest.EncodePublic(pub)), log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	mode := `"insecure_http": true,`
	if tlsMode {
		if err := pki.Init(filepath.Join(dir, "pki"), []string{"127.0.0.1"}); err != nil {
			t.Fatal(err)
		}
		mode = `"pki_dir": "pki",`
	}
	cfgJSON := fmt.Sprintf(`{`+mode+extra+`"data_dir": %q, "trusted_keys":[{"public_key": %q, "sources":["acq-zone-1"]}],
	  "admin_tokens":[{"user":"vera","role":"viewer","token_sha256":%q},{"user":"otto","role":"operator","token_sha256":%q},{"user":"alice","role":"approver","token_sha256":%q}],
	  "intake_interval":"1h"}`, filepath.Join(dir, "data"), e.pubPEM, store.HashSecret(tokViewer), store.HashSecret(tokOperator), store.HashSecret(tokApprover))
	cfgPath := filepath.Join(dir, "pmserver.json")
	os.WriteFile(cfgPath, []byte(cfgJSON), 0o600)
	cfg, err := server.LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(cfg.DataDir, 0o750)
	e.st, err = store.Open(filepath.Join(cfg.DataDir, "pm.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.st.Close() })
	e.repoDir = filepath.Join(cfg.DataDir, "repository")
	rp, _ := repo.New(e.repoDir)
	icfg, err := cfg.IntakeConfig()
	if err != nil {
		t.Fatal(err)
	}
	e.inbox = icfg.Inbox
	e.intake, err = intake.New(icfg, e.st, e.log)
	if err != nil {
		t.Fatal(err)
	}
	ui := fstest.MapFS{"index.html": {Data: []byte("<html>console</html>")}}
	h, err := server.New(cfg, e.st, rp, ui, e.log)
	if err != nil {
		t.Fatal(err)
	}
	h.SetIntelKeys(e.intake.ActiveKeys)
	e.cfg = cfg
	e.srvHandler = h
	e.hc = http.DefaultClient
	if tlsMode {
		e.srv = httptest.NewUnstartedServer(h.Handler())
		e.srv.TLS = h.TLSConfig() // server certificate + CA chain, as pmserver serves it
		if len(e.srv.TLS.Certificates) == 0 {
			t.Fatal("TLSConfig did not load the server certificate")
		}
		e.srv.StartTLS()
		e.caFile = filepath.Join(dir, "pki", pki.CAFile)
		pool := x509.NewCertPool()
		caPEM, _ := os.ReadFile(e.caFile)
		pool.AppendCertsFromPEM(caPEM)
		e.hc = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	} else {
		e.srv = httptest.NewServer(h.Handler())
	}
	t.Cleanup(e.srv.Close)
	return e
}

// payload writes a fake vendor file.
func (e *env) payload(name, content string) string {
	p := filepath.Join(e.dir, "downloads", name)
	os.MkdirAll(filepath.Dir(p), 0o750)
	os.WriteFile(p, []byte(content), 0o640)
	return p
}

func msuPkg(id, kb string, supersedes ...string) manifest.Package {
	return manifest.Package{PackageID: id, Title: "Cumulative Update " + kb, Vendor: "Microsoft", Kind: "msu", Version: "19045.1", KB: kb,
		Severity: "critical", ReleaseDate: "2026-10-08", Supersedes: append([]string{}, supersedes...),
		Applicability:   manifest.Applicability{OS: "windows", Arch: "x64", MinBuild: 19045, MaxBuild: 19045},
		VendorSignature: manifest.VendorSignature{Status: "not_checked"}}
}

type bundleOpts struct {
	seq          int64
	key          ed25519.PrivateKey
	mutateBytes  func([]byte) []byte // after signing
	wrongHashFor string
	bundleID     string
}

// bundle builds and signs a .pmb (same steps as `pmctl build`).
func (e *env) bundle(o bundleOpts, pkgs map[string]manifest.Package, files map[string]string) string {
	if o.key == nil {
		o.key = e.priv
	}
	now := time.Now().UTC().Truncate(time.Second)
	if o.bundleID == "" {
		o.bundleID = fmt.Sprintf("b-test-%04d", o.seq)
	}
	m := manifest.Manifest{SchemaVersion: 1, BundleID: o.bundleID, Source: "acq-zone-1", Sequence: o.seq,
		KeyID: manifest.KeyID(o.key.Public().(ed25519.PublicKey)), CreatedAt: now, ExpiresAt: now.Add(72 * time.Hour)}
	tarFiles := map[string]string{}
	for id, p := range pkgs {
		path := files[id]
		size, sha, _ := manifest.HashFile(path)
		if id == o.wrongHashFor {
			sha = strings.Repeat("0", 64)
		}
		p.File = manifest.FileRef{Name: "payload/" + filepath.Base(path), Size: size, SHA256: sha}
		tarFiles[p.File.Name] = path
		m.Packages = append(m.Packages, p)
	}
	mb, _ := json.MarshalIndent(m, "", "  ")
	sig := manifest.Sign(o.key, mb)
	if o.mutateBytes != nil {
		mb = o.mutateBytes(mb)
	}
	out := filepath.Join(e.dir, "outbox", fmt.Sprintf("bundle-%d-%d.pmb", o.seq, time.Now().UnixNano()))
	os.MkdirAll(filepath.Dir(out), 0o750)
	if err := manifest.WriteBundle(out, mb, sig, tarFiles); err != nil {
		e.t.Fatal(err)
	}
	return out
}

// transferAndIntake sends through the drop-dir adapter and runs intake.
func (e *env) transferAndIntake(path string) store.Bundle {
	e.t.Helper()
	if _, err := (transfer.DropDir{Dir: e.inbox}).Send(path); err != nil {
		e.t.Fatal(err)
	}
	bs := e.intake.ScanOnce(context.Background())
	if len(bs) != 1 {
		e.t.Fatalf("expected 1 intake result, got %d", len(bs))
	}
	return bs[0]
}

func (e *env) api(method, path, token string, body any, out any) int {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := e.hc.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 && os.Getenv("E2E_DEBUG") != "" {
		e.t.Logf("%s %s -> %d %s", method, path, resp.StatusCode, b)
	}
	if out != nil && resp.StatusCode/100 == 2 {
		if err := json.Unmarshal(b, out); err != nil {
			e.t.Fatalf("%s %s: decode %v: %s", method, path, err, b)
		}
	}
	return resp.StatusCode
}

type simAgent struct {
	*agent.Agent
	dir    string
	secret string
	id     string
	sim    *agent.Sim
}

func (e *env) enroll(host string, groups []string, sim agent.SimConfig) *simAgent {
	e.t.Helper()
	var tok store.EnrollmentToken
	if c := e.api("POST", "/api/enrollment-tokens", tokOperator, map[string]any{"groups": groups, "site": "hq", "expires_in_hours": 1}, &tok); c != 201 {
		e.t.Fatalf("enrollment token: %d", c)
	}
	dir := filepath.Join(e.dir, "agents", host)
	sim.Hostname = host
	st0 := &agent.State{Platform: "sim", Sim: &sim}
	p, _ := agent.PlatformFor(st0, dir)
	os.MkdirAll(dir, 0o700)
	st, err := agent.Enroll(e.srv.URL, tok.Token, e.caFile, dir, []string{e.pubPEM}, e.rootPEM, p, "sim", &sim)
	if err != nil {
		e.t.Fatal(err)
	}
	// Token is single use.
	if _, err := agent.Enroll(e.srv.URL, tok.Token, e.caFile, dir+"-again", []string{e.pubPEM}, e.rootPEM, p, "sim", &sim); err == nil {
		e.t.Fatal("enrollment token reused")
	}
	a, err := agent.New(st, dir, p, e.log)
	if err != nil {
		e.t.Fatal(err)
	}
	sp, _ := p.(*agent.Sim)
	return &simAgent{Agent: a, dir: dir, secret: st.Secret, id: st.EndpointID, sim: sp}
}

func (e *env) cycle(a *simAgent) {
	e.t.Helper()
	if err := a.Cycle(context.Background()); err != nil {
		e.t.Fatalf("agent cycle: %v", err)
	}
}

func (e *env) deployment(id string) store.DeploymentDetail {
	var d store.DeploymentDetail
	if c := e.api("GET", "/api/deployments/"+id, tokViewer, nil, &d); c != 200 {
		e.t.Fatalf("get deployment %d", c)
	}
	return d
}

func targetState(d store.DeploymentDetail, endpointID string) string {
	for _, t := range d.Targets {
		if t.EndpointID == endpointID {
			return t.State
		}
	}
	return "<none>"
}

func checksFailed(b store.Bundle) []string {
	var out []string
	for _, c := range b.Checks {
		if !c.OK {
			out = append(out, c.Name)
		}
	}
	return out
}

func TestEndToEnd(t *testing.T) {
	e := newEnv(t)

	// ---- acquisition + transfer + intake ----
	pkgs := map[string]manifest.Package{
		"KB5000002-x64": msuPkg("KB5000002-x64", "KB5000002", "KB5000001"),
		"AcmeAgent-2.1": {PackageID: "AcmeAgent-2.1", Title: "Acme Agent 2.1", Vendor: "Acme", Kind: "msi", Version: "2.1.0", ProductCode: msiGUID,
			Severity: "important", Supersedes: []string{}, Applicability: manifest.Applicability{OS: "windows", Arch: "any"},
			VendorSignature: manifest.VendorSignature{Status: "not_checked"}},
	}
	files := map[string]string{
		"KB5000002-x64": e.payload("windows10.0-kb5000002-x64.msu", "MSU payload v2 "+strings.Repeat("x", 4096)),
		"AcmeAgent-2.1": e.payload("acme-agent-2.1.msi", "MSI payload "+strings.Repeat("y", 2048)),
	}
	b1path := e.bundle(bundleOpts{seq: 1}, pkgs, files)
	b1 := e.transferAndIntake(b1path)
	if b1.State != "validated" {
		t.Fatalf("bundle 1 not validated: %+v", b1)
	}
	var quarantined []store.Package
	e.api("GET", "/api/packages?state=quarantined", tokViewer, nil, &quarantined)
	if len(quarantined) != 2 {
		t.Fatalf("expected 2 quarantined packages, got %d", len(quarantined))
	}

	// ---- negative intake cases ----
	t.Run("replay rejected", func(t *testing.T) {
		b := e.transferAndIntake(e.bundle(bundleOpts{seq: 1, bundleID: "b-replay"}, pkgs, files))
		if b.State != "rejected" || !strings.Contains(strings.Join(checksFailed(b), ","), "replay") {
			t.Fatalf("replay not rejected: %+v", b)
		}
	})
	t.Run("modified file rejected", func(t *testing.T) {
		b := e.transferAndIntake(e.bundle(bundleOpts{seq: 10, wrongHashFor: "KB5000002-x64"}, pkgs, files))
		if b.State != "rejected" || checksFailed(b)[0] != "payload_hashes" {
			t.Fatalf("hash mismatch not rejected: %+v", checksFailed(b))
		}
	})
	t.Run("invalid signature rejected", func(t *testing.T) {
		mut := func(b []byte) []byte { return bytes.Replace(b, []byte("Cumulative"), []byte("Cumulativf"), 1) }
		b := e.transferAndIntake(e.bundle(bundleOpts{seq: 11, mutateBytes: mut}, pkgs, files))
		if b.State != "rejected" || checksFailed(b)[0] != "signature" {
			t.Fatalf("bad signature not rejected: %+v", checksFailed(b))
		}
	})
	t.Run("untrusted key rejected", func(t *testing.T) {
		_, other, _ := manifest.GenerateKey()
		b := e.transferAndIntake(e.bundle(bundleOpts{seq: 12, key: other}, pkgs, files))
		if b.State != "rejected" || checksFailed(b)[0] != "trusted_key" {
			t.Fatalf("untrusted key not rejected: %+v", checksFailed(b))
		}
	})
	t.Run("malformed manifest rejected", func(t *testing.T) {
		mut := func(b []byte) []byte { return append(b[:len(b)-5], []byte("!!")...) }
		b := e.transferAndIntake(e.bundle(bundleOpts{seq: 13, mutateBytes: mut}, pkgs, files))
		if b.State != "rejected" || checksFailed(b)[0] != "manifest_parse" {
			t.Fatalf("malformed manifest not rejected: %+v", checksFailed(b))
		}
	})
	t.Run("in-flight .part ignored", func(t *testing.T) {
		os.WriteFile(filepath.Join(e.inbox, "x.pmb.part"), []byte("partial"), 0o640)
		if n := len(e.intake.ScanOnce(context.Background())); n != 0 {
			t.Fatalf("partial file processed")
		}
	})

	// ---- endpoints ----
	pilot := e.enroll("pilot-01", []string{"pilot"}, agent.SimConfig{Reboot: true})
	broad1 := e.enroll("broad-01", []string{"broad"}, agent.SimConfig{})
	broad2 := e.enroll("broad-02", []string{"broad"}, agent.SimConfig{FailKBs: []string{"KB5000002"}})
	broad3 := e.enroll("broad-03", []string{"broad"}, agent.SimConfig{})
	oldBuild := e.enroll("legacy-01", []string{"broad"}, agent.SimConfig{Build: 17763})
	for _, a := range []*simAgent{pilot, broad1, broad2, broad3, oldBuild} {
		e.cycle(a)
	}

	// ---- approval gate ----
	ring := []store.Ring{{Name: "pilot", Groups: []string{"pilot"}}, {Name: "broad", Groups: []string{"broad"}}}
	newDep := store.NewDeployment{PackageID: "KB5000002-x64", Name: "Oct CU", Rings: ring, MaxFailurePct: 20, MaxRetries: 0}
	if c := e.api("POST", "/api/deployments", tokOperator, newDep, nil); c != 409 {
		t.Fatalf("deploying unapproved package: want 409, got %d", c)
	}
	if c := e.api("GET", "/api/agent/content/"+pkgs["KB5000002-x64"].File.SHA256, pilot.secret, nil, nil); c == 200 {
		t.Fatal("unapproved content served")
	}
	if c := e.api("POST", "/api/packages/KB5000002-x64/approve", tokOperator, map[string]string{"reason": "x"}, nil); c != 403 {
		t.Fatalf("operator approve: want 403, got %d", c)
	}
	if c := e.api("POST", "/api/packages/KB5000002-x64/approve", tokApprover, map[string]string{"reason": " "}, nil); c != 400 {
		t.Fatalf("approve without reason: want 400, got %d", c)
	}
	var p store.Package
	if c := e.api("POST", "/api/packages/KB5000002-x64/approve", tokApprover, map[string]string{"reason": "CAB-1234 tested in lab"}, &p); c != 200 || p.State != "approved" {
		t.Fatalf("approve: %d %s", c, p.State)
	}
	if _, err := os.Stat(filepath.Join(e.repoDir, p.SHA256[:2], p.SHA256)); err != nil {
		t.Fatalf("approved content not in repository: %v", err)
	}

	// Exception for broad-03 before the deployment starts.
	var x store.Exception
	if c := e.api("POST", "/api/exceptions", tokApprover, store.NewException{EndpointID: broad3.id, PackageID: "KB5000002-x64", Owner: "ops-lead",
		Reason: "vendor app incompatible", CompensatingControls: "host firewall lockdown", ExpiresAt: time.Now().Add(72 * time.Hour).UTC().Format(time.RFC3339)}, &x); c != 201 {
		t.Fatalf("create exception: %d (endpoint %s)", c, broad3.id)
	}

	// ---- staged deployment ----
	var d store.Deployment
	if c := e.api("POST", "/api/deployments", tokOperator, newDep, &d); c != 201 {
		t.Fatalf("create deployment: %d", c)
	}
	dd := e.deployment(d.DeploymentID)
	if len(dd.Targets) != 1 || targetState(dd, pilot.id) != "pending" {
		t.Fatalf("ring 0 should target only pilot: %+v", dd.Targets)
	}
	e.cycle(broad1) // not in current ring → nothing
	if s := targetState(e.deployment(d.DeploymentID), broad1.id); s != "<none>" {
		t.Fatalf("broad endpoint targeted during pilot: %s", s)
	}

	e.cycle(pilot) // installs → pending_reboot (sim requires reboot)
	if s := targetState(e.deployment(d.DeploymentID), pilot.id); s != "pending_reboot" {
		t.Fatalf("pilot after install: %s", s)
	}
	e.cycle(pilot) // reports reboot still pending → not verified yet
	if s := targetState(e.deployment(d.DeploymentID), pilot.id); s != "pending_reboot" {
		t.Fatalf("pilot verified before reboot completed: %s", s)
	}
	e.cycle(pilot) // reboot done, inventory shows KB → verified
	if s := targetState(e.deployment(d.DeploymentID), pilot.id); s != "verified" {
		t.Fatalf("pilot after reboot: %s", s)
	}

	if c := e.api("POST", "/api/deployments/"+d.DeploymentID+"/advance", tokOperator, map[string]string{"reason": "pilot ok"}, &d); c != 200 || d.CurrentRing != 1 {
		t.Fatalf("advance: %d ring %d", c, d.CurrentRing)
	}
	dd = e.deployment(d.DeploymentID)
	if targetState(dd, broad3.id) != "exception" || targetState(dd, oldBuild.id) != "not_applicable" {
		t.Fatalf("exception/not_applicable targeting wrong: %+v", dd.Targets)
	}
	e.cycle(broad3)
	e.cycle(broad1)
	e.cycle(broad2) // fails, max_retries 0 → 1/2 = 50% > 20% → auto-pause
	dd = e.deployment(d.DeploymentID)
	if targetState(dd, broad2.id) != "failed" || dd.State != "paused" || !strings.Contains(dd.StateReason, "auto-pause") {
		t.Fatalf("expected auto-pause after failure: state=%s reason=%q targets=%+v", dd.State, dd.StateReason, dd.Targets)
	}
	// Paused deployments issue no work.
	e.cycle(broad1)
	if targetState(e.deployment(d.DeploymentID), broad1.id) != "verified" {
		// broad1 installed before the pause; the verification check-in still counts.
		t.Fatalf("broad1 should verify from inventory even while paused")
	}
	if c := e.api("POST", "/api/deployments/"+d.DeploymentID+"/resume", tokOperator, map[string]string{"reason": "broad-02 investigated, isolated"}, &d); c != 200 {
		t.Fatalf("resume: %d", c)
	}
	dd = e.deployment(d.DeploymentID)
	if dd.State != "completed" {
		t.Fatalf("expected completed (all final-ring targets terminal), got %s %+v", dd.State, dd.Counts)
	}

	// ---- fleet status: silence is never compliance ----
	statuses := func() map[string]string {
		var eps []store.Endpoint
		e.api("GET", "/api/endpoints", tokViewer, nil, &eps)
		m := map[string]string{}
		for _, ep := range eps {
			m[ep.Hostname] = ep.Status
		}
		return m
	}
	s := statuses()
	if s["pilot-01"] != "compliant" || s["broad-02"] != "failed" || s["broad-01"] != "compliant" {
		t.Fatalf("statuses: %v", s)
	}
	realNow := e.st.Now
	e.st.Now = func() time.Time { return realNow().Add(2 * time.Hour) }
	s = statuses()
	e.st.Now = realNow
	for h, st := range s {
		if st != "offline" {
			t.Fatalf("%s should be offline after 2h silence, is %s", h, st)
		}
	}

	// ---- endpoint detects tampered repository content ----
	if c := e.api("POST", "/api/packages/AcmeAgent-2.1/approve", tokApprover, map[string]string{"reason": "CAB-1235"}, &p); c != 200 {
		t.Fatalf("approve msi: %d", c)
	}
	obj := filepath.Join(e.repoDir, p.SHA256[:2], p.SHA256)
	os.Chmod(obj, 0o640)
	os.WriteFile(obj, []byte("MSI payload TAMPERED"), 0o640)
	// App packages only update an installed app: give the pilot Acme 2.0.
	simState := filepath.Join(pilot.dir, "sim-state.json")
	var ss map[string]any
	sb, _ := os.ReadFile(simState)
	json.Unmarshal(sb, &ss)
	ss["products"] = []store.InventoryItem{{Kind: "product", ID: msiGUID, Name: "Acme Agent 2.0", Version: "2.0.0"}}
	sb, _ = json.Marshal(ss)
	os.WriteFile(simState, sb, 0o600)
	e.cycle(pilot)
	var d2 store.Deployment
	e.api("POST", "/api/deployments", tokOperator, store.NewDeployment{PackageID: "AcmeAgent-2.1", Name: "Acme", Rings: []store.Ring{{Name: "pilot", Groups: []string{"pilot"}}}, MaxFailurePct: 100, MaxRetries: 1}, &d2)
	e.cycle(pilot)
	dd = e.deployment(d2.DeploymentID)
	if dd.Targets[0].State != "failed" || !strings.Contains(dd.Targets[0].Detail, "tampering") {
		t.Fatalf("tampered content not detected on endpoint: %+v", dd.Targets[0])
	}
	items, _, _ := agent.NewSim(agent.SimConfig{}, simState).Inventory()
	for _, it := range items {
		if it.Version == "2.1.0" {
			t.Fatalf("tampered package must not be installed; inventory=%+v", items)
		}
	}

	// ---- agent may not fetch content it isn't assigned ----
	if c := e.api("GET", "/api/agent/content/"+p.SHA256, broad1.secret, nil, nil); c != 404 {
		t.Fatalf("unassigned content: want 404, got %d", c)
	}

	// ---- revoke cancels deployments ----
	e.api("POST", "/api/packages/AcmeAgent-2.1/revoke", tokApprover, map[string]string{"reason": "tampering incident"}, nil)
	if e.deployment(d2.DeploymentID).State != "cancelled" {
		t.Fatal("revoking a package must cancel its deployments")
	}

	// ---- audit: export + chain + append-only + tamper detection ----
	var exp map[string]any
	if c := e.api("GET", "/api/audit/export?package_id=KB5000002-x64", tokViewer, nil, &exp); c != 200 {
		t.Fatalf("export: %d", c)
	}
	evs := exp["events"].([]any)
	actions := map[string]bool{}
	for _, ev := range evs {
		actions[ev.(map[string]any)["action"].(string)] = true
	}
	for _, want := range []string{"bundle.validated", "package.quarantined", "package.approved", "deployment.created", "target.verified", "deployment.auto_paused", "deployment.completed"} {
		if !actions[want] {
			t.Errorf("lifecycle export missing %s", want)
		}
	}
	var chain store.ChainResult
	e.api("GET", "/api/audit/verify", tokViewer, nil, &chain)
	if !chain.OK || chain.Count < 30 {
		t.Fatalf("audit chain: %+v", chain)
	}
	db, _ := sql.Open("sqlite", filepath.Join(e.dir, "data", "pm.db"))
	defer db.Close()
	if _, err := db.Exec(`UPDATE audit SET actor='mallory' WHERE seq=5`); err == nil {
		t.Fatal("audit table accepted an UPDATE")
	}
	db.Exec(`DROP TRIGGER audit_no_update`)
	if _, err := db.Exec(`UPDATE audit SET actor='mallory' WHERE seq=5`); err != nil {
		t.Fatal(err)
	}
	e.api("GET", "/api/audit/verify", tokViewer, nil, &chain)
	if chain.OK || chain.FirstBadSeq != 5 {
		t.Fatalf("tampering not detected: %+v", chain)
	}

	// ---- agent setup: pinned key + staged binaries ----
	var setup struct {
		TrustedKeys []struct {
			KeyID     string `json:"key_id"`
			PublicKey string `json:"public_key"`
		} `json:"trusted_keys"`
		AgentFiles []struct {
			Name string `json:"name"`
		} `json:"agent_files"`
	}
	if c := e.api("GET", "/api/agent-setup", tokViewer, nil, &setup); c != 200 || len(setup.TrustedKeys) != 1 || setup.TrustedKeys[0].PublicKey != e.pubPEM {
		t.Fatalf("agent-setup keys: %d %+v", c, setup.TrustedKeys)
	}
	if len(setup.AgentFiles) != 0 {
		t.Fatalf("no files staged yet: %+v", setup.AgentFiles)
	}
	dist := filepath.Join(e.dir, "data", "agent-dist")
	os.MkdirAll(dist, 0o750)
	os.WriteFile(filepath.Join(dist, "pmagent.exe"), []byte("MZ fake agent"), 0o640)
	e.api("GET", "/api/agent-setup", tokViewer, nil, &setup)
	if len(setup.AgentFiles) != 1 || setup.AgentFiles[0].Name != "pmagent.exe" {
		t.Fatalf("staged agent not listed: %+v", setup.AgentFiles)
	}
	if c := e.api("GET", "/api/agent-setup/files/pmagent.exe", tokViewer, nil, nil); c != 200 {
		t.Fatalf("download staged agent: %d", c)
	}
	if c := e.api("GET", "/api/agent-setup/files/..%2Fpm.db", tokViewer, nil, nil); c == 200 {
		t.Fatal("agent-dist download escaped its directory")
	}
	if c := e.api("GET", "/api/agent-setup", "", nil, nil); c != 401 {
		t.Fatalf("agent-setup without auth: %d", c)
	}

	// ---- console served, unknown API 404, no auth 401 ----
	if c := e.api("GET", "/deployments/xyz", "", nil, nil); c != 200 {
		t.Fatalf("SPA fallback: %d", c)
	}
	if c := e.api("GET", "/api/summary", "", nil, nil); c != 401 {
		t.Fatalf("unauthenticated: %d", c)
	}
}
