package e2e

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"offpatch/internal/agent"
	"offpatch/internal/auditexport"
	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

// A target that failed in a deployment that has since completed must
// still verify when the endpoint is fixed by hand (it used to stay failed).
func TestFailedTargetRecoversAfterCompletion(t *testing.T) {
	e := newEnv(t)
	pk := map[string]manifest.Package{"KB5002001-x64": msuPkg("KB5002001-x64", "KB5002001")}
	e.transferAndIntake(e.bundle(bundleOpts{seq: 1}, pk, map[string]string{"KB5002001-x64": e.payload("x.msu", "x")}))
	e.approve("KB5002001-x64")
	a := e.enroll("pc-fix", []string{"f"}, agent.SimConfig{FailKBs: []string{"KB5002001"}})
	d := e.deploy(store.NewDeployment{PackageID: "KB5002001-x64", Name: "f", Rings: []store.Ring{{Name: "f", Groups: []string{"f"}}}, MaxFailurePct: 100})
	e.cycle(a)
	dd := e.deployment(d.DeploymentID)
	if dd.State != "completed" || targetState(dd, a.id) != "failed" {
		t.Fatalf("setup: %s %s", dd.State, targetState(dd, a.id))
	}
	// Admin installs it manually; next check-in carries the evidence.
	os.WriteFile(filepath.Join(a.dir, "sim-state.json"), []byte(`{"kbs":["KB5002001"]}`), 0o600)
	e.cycle(a)
	if s := targetState(e.deployment(d.DeploymentID), a.id); s != "verified" {
		t.Fatalf("manually fixed endpoint should verify: %s", s)
	}
	var ep store.EndpointDetail
	e.api("GET", "/api/endpoints/"+a.id, tokViewer, nil, &ep)
	if ep.Status != "compliant" {
		t.Fatalf("status after fix: %s", ep.Status)
	}
}

// After a restore the database is behind the export directory; exporting
// again must refuse rather than write overlapping evidence.
func TestAuditExportRefusesAfterRestore(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	key, _ := auditexport.LoadOrCreateKey(filepath.Join(e.dir, "a.key"))
	x := &auditexport.Exporter{Store: e.st, Dir: filepath.Join(e.dir, "worm"), Key: key, Log: e.log}
	e.enroll("pc-x", []string{"x"}, agent.SimConfig{})
	if _, err := x.Export(ctx); err != nil {
		t.Fatal(err)
	}
	e.st.SetMeta(ctx, "audit_exported_seq", "0") // as if restored from an older backup
	if _, err := x.Export(ctx); err == nil || !strings.Contains(err.Error(), "restored") {
		t.Fatalf("expected refusal, got %v", err)
	}
	if rep, _ := auditexport.Verify(ctx, x.Dir, key.Public().(ed25519.PublicKey), nil); !rep.OK {
		t.Fatalf("existing evidence must stay intact: %+v", rep)
	}
}
