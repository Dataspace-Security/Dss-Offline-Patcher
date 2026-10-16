package e2e

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"offpatch/internal/agent"
	"offpatch/internal/manifest"
	"offpatch/internal/store"
	"offpatch/internal/transfer"
	"offpatch/internal/trust"
)

// sendTrust signs a trust document with root and drops it in the inbox.
func (e *env) sendTrust(root ed25519.PrivateKey, doc trust.Document) {
	e.t.Helper()
	s, err := trust.Sign(doc, root)
	if err != nil {
		e.t.Fatal(err)
	}
	b, _ := json.Marshal(s)
	p := filepath.Join(e.dir, "outbox", fmt.Sprintf("keys-%d-%d.trust.json", doc.Sequence, len(b)))
	os.MkdirAll(filepath.Dir(p), 0o750)
	os.WriteFile(p, b, 0o644)
	if _, err := (transfer.DropDir{Dir: e.inbox}).Send(p); err != nil {
		e.t.Fatal(err)
	}
	e.intake.ScanOnce(context.Background())
}

func tkey(pub ed25519.PublicKey, status string) trust.Key {
	k := trust.Key{KeyID: manifest.KeyID(pub), PublicKey: string(manifest.EncodePublic(pub)), Status: status}
	if status == "active" {
		k.Sources = []string{"acq-zone-1"}
	}
	return k
}

func TestKeyRotationRevocationAndUpgrade(t *testing.T) {
	rootPub, rootPriv, _ := manifest.GenerateKey()
	rootFile := filepath.Join(t.TempDir(), "root.pub")
	os.WriteFile(rootFile, manifest.EncodePublic(rootPub), 0o644)
	e := newEnvOpts(t, false, fmt.Sprintf(`"root_public_key_file": %q,`, rootFile))
	e.rootPEM = string(manifest.EncodePublic(rootPub))
	ctx := context.Background()
	keyA := e.priv
	pubB, keyB, _ := manifest.GenerateKey()
	all := []store.Ring{{Name: "all", Groups: []string{"all"}}}

	// Content signed with key A, deployed and verified.
	pkA := map[string]manifest.Package{"KB5000801-x64": msuPkg("KB5000801-x64", "KB5000801")}
	fA := map[string]string{"KB5000801-x64": e.payload("kb5000801.msu", "A")}
	e.transferAndIntake(e.bundle(bundleOpts{seq: 1, key: keyA}, pkA, fA))
	e.approve("KB5000801-x64")
	a1 := e.enroll("pc-k1", []string{"k"}, agent.SimConfig{})
	dA := e.deploy(store.NewDeployment{PackageID: "KB5000801-x64", Name: "A", Rings: all})
	e.cycle(a1)
	e.cycle(a1)

	// ---- rotation: B active, A retired ----
	e.sendTrust(rootPriv, trust.Document{Version: 1, Sequence: 1, Keys: []trust.Key{tkey(pubB, "active"), tkey(keyA.Public().(ed25519.PublicKey), "retired")}})
	if b := e.transferAndIntake(e.bundle(bundleOpts{seq: 2, key: keyA}, map[string]manifest.Package{"KB5000802-x64": msuPkg("KB5000802-x64", "KB5000802")},
		map[string]string{"KB5000802-x64": e.payload("kb5000802.msu", "A2")})); b.State != "rejected" || !strings.Contains(b.Error, "retired") {
		t.Fatalf("bundle from retired key accepted: %+v", b)
	}
	pkB := map[string]manifest.Package{"KB5000803-x64": msuPkg("KB5000803-x64", "KB5000803")}
	if b := e.transferAndIntake(e.bundle(bundleOpts{seq: 3, key: keyB}, pkB, map[string]string{"KB5000803-x64": e.payload("kb5000803.msu", "B")})); b.State != "validated" {
		t.Fatalf("bundle from rotated-in key B rejected: %+v", b)
	}
	// Agents learn the new key set at check-in (verified against the pinned root).
	e.cycle(a1)
	st, _ := agent.LoadState(a1.dir)
	if st.TrustSeq != 1 || len(st.TrustedKeys) != 2 {
		t.Fatalf("agent did not apply trust update: seq=%d keys=%d", st.TrustSeq, len(st.TrustedKeys))
	}
	var setup struct {
		TrustedKeys []struct {
			KeyID string `json:"key_id"`
		} `json:"trusted_keys"`
	}
	e.api("GET", "/api/agent-setup", tokViewer, nil, &setup)
	if len(setup.TrustedKeys) != 2 {
		t.Fatalf("agent setup should list the rotated key set: %+v", setup.TrustedKeys)
	}
	e.approve("KB5000803-x64")
	dB := e.deploy(store.NewDeployment{PackageID: "KB5000803-x64", Name: "B", Rings: all})
	e.cycle(a1)
	e.cycle(a1)
	if s := targetState(e.deployment(dB.DeploymentID), a1.id); s != "verified" {
		t.Fatalf("agent should install content signed by rotated-in key: %s", s)
	}
	// Retired-key content stays installable on a newly enrolled endpoint.
	a2 := e.enroll("pc-k2", []string{"k2"}, agent.SimConfig{})
	dA2 := e.deploy(store.NewDeployment{PackageID: "KB5000801-x64", Name: "A to k2", Rings: []store.Ring{{Name: "k2", Groups: []string{"k2"}}}})
	e.cycle(a2)
	e.cycle(a2)
	if s := targetState(e.deployment(dA2.DeploymentID), a2.id); s != "verified" {
		t.Fatalf("retired-key content should remain valid: %s", s)
	}

	// ---- replay and forgery ----
	e.sendTrust(rootPriv, trust.Document{Version: 1, Sequence: 1, Keys: []trust.Key{tkey(pubB, "active")}})
	_, notRoot, _ := manifest.GenerateKey()
	e.sendTrust(notRoot, trust.Document{Version: 1, Sequence: 9, Keys: []trust.Key{tkey(pubB, "active")}})
	evs, _ := e.st.ListAudit(ctx, store.AuditQuery{Action: "trust.rejected"})
	if len(evs) != 2 {
		t.Fatalf("replayed and forged trust documents must be rejected: %d", len(evs))
	}

	// ---- compromise: revoke A; its packages are revoked everywhere ----
	e.sendTrust(rootPriv, trust.Document{Version: 1, Sequence: 2, Keys: []trust.Key{tkey(pubB, "active")},
		Revoked: []trust.Revoked{{KeyID: manifest.KeyID(keyA.Public().(ed25519.PublicKey)), Reason: "compromised"}}})
	p, _ := e.st.GetPackage(ctx, "KB5000801-x64")
	if p.State != "revoked" || !strings.Contains(p.StateReason, "compromised") {
		t.Fatalf("package signed by compromised key not revoked: %s %q", p.State, p.StateReason)
	}
	if d := e.deployment(dA.DeploymentID); d.State != "cancelled" && d.State != "completed" {
		t.Fatalf("deployment of compromised content: %s", d.State)
	}
	e.cycle(a1)
	st, _ = agent.LoadState(a1.dir)
	if st.TrustSeq != 2 || len(st.Revoked) != 1 {
		t.Fatalf("agent did not record revocation: %+v", st)
	}

	// ---- agent self-upgrade, prerequisites, editions (signed with B) ----
	up := manifest.Package{PackageID: "offpatch-agent-0.2.0", Title: "offpatch agent 0.2.0", Vendor: "offpatch", Kind: "agent", Version: "0.2.0",
		Severity: "important", Supersedes: []string{}, Applicability: manifest.Applicability{OS: "windows", Arch: "any"}, VendorSignature: manifest.VendorSignature{Status: "not_checked"}}
	pre := msuPkg("KB5000902-x64", "KB5000902")
	pre.Prerequisites = []string{"KB5000901"}
	ed := msuPkg("KB5000903-x64", "KB5000903")
	ed.Applicability.Editions = []string{"Professional"}
	base := msuPkg("KB5000901-x64", "KB5000901")
	pk := map[string]manifest.Package{up.PackageID: up, pre.PackageID: pre, ed.PackageID: ed, base.PackageID: base}
	files := map[string]string{}
	for id := range pk {
		files[id] = e.payload(strings.ToLower(id)+".bin", "x"+id)
	}
	if b := e.transferAndIntake(e.bundle(bundleOpts{seq: 4, key: keyB}, pk, files)); b.State != "validated" {
		t.Fatalf("bundle 4: %+v", b)
	}
	for id := range pk {
		e.approve(id)
	}
	a3 := e.enroll("pc-k3", []string{"z"}, agent.SimConfig{}) // Enterprise edition
	z := []store.Ring{{Name: "z", Groups: []string{"z"}}}
	dUp := e.deploy(store.NewDeployment{PackageID: up.PackageID, Name: "agent upgrade", Rings: z})
	dPre := e.deploy(store.NewDeployment{PackageID: pre.PackageID, Name: "needs prereq", Rings: z})
	dEd := e.deploy(store.NewDeployment{PackageID: ed.PackageID, Name: "pro only", Rings: z})
	e.cycle(a3)
	e.cycle(a3)
	if s := targetState(e.deployment(dUp.DeploymentID), a3.id); s != "verified" {
		t.Fatalf("agent self-upgrade not verified: %s", s)
	}
	var me store.EndpointDetail
	e.api("GET", "/api/endpoints/"+a3.id, tokViewer, nil, &me)
	if me.AgentVersion != "0.2.0" {
		t.Fatalf("endpoint should report upgraded agent version, got %s", me.AgentVersion)
	}
	dd := e.deployment(dPre.DeploymentID)
	if targetState(dd, a3.id) != "pending" || !strings.Contains(dd.Targets[0].Detail, "KB5000901") {
		t.Fatalf("prerequisite gating: %+v", dd.Targets)
	}
	if s := targetState(e.deployment(dEd.DeploymentID), a3.id); s != "not_applicable" {
		t.Fatalf("edition restriction: %s", s)
	}
	e.deploy(store.NewDeployment{PackageID: base.PackageID, Name: "prereq", Rings: z})
	e.cycle(a3) // installs prereq
	e.cycle(a3) // prereq now in inventory → dependent installs
	e.cycle(a3)
	if s := targetState(e.deployment(dPre.DeploymentID), a3.id); s != "verified" {
		t.Fatalf("dependent package after prerequisite: %s", s)
	}
}
