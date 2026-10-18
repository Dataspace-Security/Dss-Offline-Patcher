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
	"time"

	"offpatch/internal/agent"
	"offpatch/internal/intake"
	"offpatch/internal/manifest"
	"offpatch/internal/store"
	"offpatch/internal/transfer"
	"offpatch/internal/trust"
)

// copyInto places a copy of src at dst (bypassing the transfer adapter).
func copyInto(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Dir(dst), 0o750)
	if err := os.WriteFile(dst, b, 0o640); err != nil {
		t.Fatal(err)
	}
}

func onePkg(e *env, id, kb string) (map[string]manifest.Package, map[string]string) {
	return map[string]manifest.Package{id: msuPkg(id, kb)}, map[string]string{id: e.payload(strings.ToLower(id)+".msu", "payload "+id)}
}

// H1: a bundle moved to received/ whose intake was never recorded (the
// process stopped mid-intake) is re-ingested on the next scan.
func TestInterruptedIntakeRecovered(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	pk, files := onePkg(e, "KB5010001-x64", "KB5010001")
	path := e.bundle(bundleOpts{seq: 1}, pk, files)
	_, sha, _ := manifest.HashFile(path)
	copyInto(t, path, filepath.Join(e.cfg.DataDir, "received", sha+".pmb"))
	bs := e.intake.ScanOnce(ctx)
	if len(bs) != 1 || bs[0].State != "validated" || bs[0].FileSHA256 != sha {
		t.Fatalf("interrupted bundle not recovered: %+v", bs)
	}
	if bs := e.intake.ScanOnce(ctx); len(bs) != 0 {
		t.Fatalf("recovered bundle ingested twice: %+v", bs)
	}
	if p, err := e.st.GetPackage(ctx, "KB5010001-x64"); err != nil || p.State != "quarantined" {
		t.Fatalf("package: %v %+v", err, p)
	}
}

// H2: a trust document stored before its compromised-key revocation ran
// (stop between the two) is completed at startup.
func TestCompromisedRevocationReappliedAtStartup(t *testing.T) {
	rootPub, rootPriv, _ := manifest.GenerateKey()
	rootFile := filepath.Join(t.TempDir(), "root.pub")
	os.WriteFile(rootFile, manifest.EncodePublic(rootPub), 0o644)
	e := newEnvOpts(t, false, fmt.Sprintf(`"root_public_key_file": %q,`, rootFile))
	ctx := context.Background()
	e.intakeApproved(map[string]manifest.Package{"KB5010101-x64": msuPkg("KB5010101-x64", "KB5010101")}, 1)
	pubB, _, _ := manifest.GenerateKey()
	doc := trust.Document{Version: 1, Sequence: 1, Keys: []trust.Key{tkey(pubB, "active")},
		Revoked: []trust.Revoked{{KeyID: manifest.KeyID(e.priv.Public().(ed25519.PublicKey)), Reason: "compromised"}}}
	signed, err := trust.Sign(doc, rootPriv)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(signed)
	if err := e.st.SaveTrust(ctx, string(raw), doc.Sequence, doc); err != nil {
		t.Fatal(err)
	}
	if p, _ := e.st.GetPackage(ctx, "KB5010101-x64"); p.State != "approved" {
		t.Fatalf("precondition: %s", p.State)
	}
	if err := e.intake.LoadStoredTrust(ctx); err != nil {
		t.Fatal(err)
	}
	if p, _ := e.st.GetPackage(ctx, "KB5010101-x64"); p.State != "revoked" || !strings.Contains(p.StateReason, "compromised") {
		t.Fatalf("revocation not re-applied: %s %q", p.State, p.StateReason)
	}
	as, _ := e.st.ListAlerts(ctx, true)
	if len(as) == 0 || as[0].Kind != "signing_key_compromised" || as[0].Severity != "critical" {
		t.Fatalf("alerts: %+v", as)
	}
	// The same document re-delivered (stop before it left the inbox) is
	// completed, not rejected as a replay.
	// Exactly the stored bytes (re-signing would stamp a new signed_at).
	p := filepath.Join(e.dir, "outbox", "keys-1-again.trust.json")
	os.MkdirAll(filepath.Dir(p), 0o750)
	os.WriteFile(p, raw, 0o644)
	if _, err := (transfer.DropDir{Dir: e.inbox}).Send(p); err != nil {
		t.Fatal(err)
	}
	e.intake.ScanOnce(ctx)
	if evs, _ := e.st.ListAudit(ctx, store.AuditQuery{Action: "trust.rejected"}); len(evs) != 0 {
		t.Fatalf("re-delivered stored document rejected: %+v", evs)
	}
	if ents, _ := os.ReadDir(e.inbox); len(ents) != 0 {
		t.Fatalf("trust document left in the inbox: %v", ents)
	}
}

// H4: the publishing step runs outside the database transaction (it can
// use the store; inside the single-connection transaction it would block).
func TestApprovePublishesOutsideTransaction(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	pk, files := onePkg(e, "KB5010201-x64", "KB5010201")
	e.transferAndIntake(e.bundle(bundleOpts{seq: 1}, pk, files))
	called := false
	publish := func(p store.Package) error {
		called = true
		qctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		_, err := e.st.GetMeta(qctx, "trust_seq")
		return err
	}
	p, err := e.st.SetPackageState(ctx, "user:alice@bank.test", "KB5010201-x64", "approve", "CAB-9", publish)
	if err != nil || !called || p.State != "approved" {
		t.Fatalf("approve: %v called=%v %+v", err, called, p)
	}
}

func deployOne(e *env, pkg string, a *simAgent, n store.NewDeployment) store.Deployment {
	e.t.Helper()
	e.intakeApproved(map[string]manifest.Package{pkg: msuPkg(pkg, strings.TrimSuffix(pkg, "-x64"))}, 1)
	n.PackageID, n.Name = pkg, "d"
	if n.Rings == nil {
		n.Rings = []store.Ring{{Name: "pilot", Groups: []string{"pilot"}}}
	}
	return e.deploy(n)
}

// H6: failures before the installer starts count as attempts, so retries
// run out and auto-pause applies; repeats are not re-audited; manifest
// verification failures raise a critical alert.
func TestPreInstallFailuresCountAndAlert(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a := e.enroll("pc-h6", []string{"pilot"}, agent.SimConfig{})
	d := deployOne(e, "KB5010301-x64", a, store.NewDeployment{MaxRetries: 1, MaxFailurePct: 1})
	rep := store.Report{DeploymentID: d.DeploymentID, PackageID: "KB5010301-x64", State: "failed", ExitCode: -1, Detail: "manifest verification failed: ed25519: invalid signature"}
	if err := e.st.ReportTarget(ctx, a.id, rep); err != nil {
		t.Fatal(err)
	}
	dd := e.deployment(d.DeploymentID)
	if tg := targetOf(dd, a.id); tg.Attempts != 1 || dd.State != "active" {
		t.Fatalf("first failure: %s %+v", dd.State, tg)
	}
	as, _ := e.st.ListAlerts(ctx, true)
	if len(as) == 0 || as[0].Kind != "manifest_verification_failed" || as[0].Severity != "critical" {
		t.Fatalf("alerts: %+v", as)
	}
	if err := e.st.ReportTarget(ctx, a.id, rep); err != nil {
		t.Fatal(err)
	}
	dd = e.deployment(d.DeploymentID)
	if tg := targetOf(dd, a.id); tg.Attempts != 2 || dd.State != "paused" {
		t.Fatalf("retries exhausted must auto-pause: %s %+v", dd.State, tg)
	}
	evs, _ := e.st.ListAudit(ctx, store.AuditQuery{ObjectID: d.DeploymentID + "/" + a.id, Action: "target.failed"})
	if len(evs) != 1 {
		t.Fatalf("identical failure re-audited: %d events", len(evs))
	}
}

// M9: an in-flight target with no report and no endpoint activity for 6h
// is failed (one attempt), freeing its concurrency slot.
func TestStuckTargetFailed(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a := e.enroll("pc-m9", []string{"pilot"}, agent.SimConfig{})
	d := deployOne(e, "KB5010401-x64", a, store.NewDeployment{MaxRetries: 2, MaxFailurePct: 100, MaxConcurrent: 1})
	if err := e.st.ReportTarget(ctx, a.id, store.Report{DeploymentID: d.DeploymentID, PackageID: "KB5010401-x64", State: "downloading"}); err != nil {
		t.Fatal(err)
	}
	real := e.st.Now
	defer func() { e.st.Now = real }()
	e.st.Now = func() time.Time { return real().Add(5 * time.Hour) }
	e.st.SweepAlerts(ctx, store.DefaultThresholds)
	if s := targetState(e.deployment(d.DeploymentID), a.id); s != "downloading" {
		t.Fatalf("5h: %s", s)
	}
	e.st.Now = func() time.Time { return real().Add(7 * time.Hour) }
	if err := e.st.SweepAlerts(ctx, store.DefaultThresholds); err != nil {
		t.Fatal(err)
	}
	tg := targetOf(e.deployment(d.DeploymentID), a.id)
	if tg.State != "failed" || tg.Attempts != 1 || !strings.Contains(tg.Detail, "no report") {
		t.Fatalf("stuck target: %+v", tg)
	}
}

// M10: once the current ring is finished and no endpoint is in a later
// ring, the deployment completes instead of waiting for an advance.
func TestDeploymentCompletesWhenLaterRingsEmpty(t *testing.T) {
	e := newEnv(t)
	a := e.enroll("pc-m10", []string{"pilot"}, agent.SimConfig{})
	d := deployOne(e, "KB5010501-x64", a, store.NewDeployment{MaxFailurePct: 50,
		Rings: []store.Ring{{Name: "pilot", Groups: []string{"pilot"}}, {Name: "broad", Groups: []string{"nobody-here"}}}})
	e.cycle(a)
	e.cycle(a)
	dd := e.deployment(d.DeploymentID)
	if targetState(dd, a.id) != "verified" || dd.State != "completed" || !strings.Contains(dd.StateReason, "no endpoints") {
		t.Fatalf("deployment: %s %q %v", dd.State, dd.StateReason, dd.Counts)
	}
}

// M12: the same bundle delivered twice in one scan must not delete the
// first delivery's quarantine when the second is rejected.
func TestDuplicateDeliveryKeepsQuarantine(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	pk, files := onePkg(e, "KB5010601-x64", "KB5010601")
	path := e.bundle(bundleOpts{seq: 1}, pk, files)
	copyInto(t, path, filepath.Join(e.inbox, "a-first.pmb"))
	copyInto(t, path, filepath.Join(e.inbox, "b-again.pmb"))
	bs := e.intake.ScanOnce(ctx)
	if len(bs) != 2 || bs[0].State != "validated" || bs[1].State != "rejected" {
		t.Fatalf("intake: %+v", bs)
	}
	p, _ := e.st.GetPackage(ctx, "KB5010601-x64")
	if _, err := os.Stat(p.QuarantinePath); err != nil {
		t.Fatalf("quarantined payload of the accepted bundle was removed: %v", err)
	}
}

// TestHelperHangingScanner is a scan_command that never finishes (run as a
// subprocess by TestScanTimeout).
func TestHelperHangingScanner(t *testing.T) {
	if os.Getenv("OFFPATCH_HANG_SCANNER") != "1" {
		t.Skip("helper process")
	}
	time.Sleep(time.Minute)
}

// M17: a hanging scanner fails the content_scan check after scan_timeout.
func TestScanTimeout(t *testing.T) {
	e := newEnv(t)
	t.Setenv("OFFPATCH_HANG_SCANNER", "1")
	icfg, err := e.cfg.IntakeConfig()
	if err != nil {
		t.Fatal(err)
	}
	icfg.ScanCommand = []string{os.Args[0], "-test.run=^TestHelperHangingScanner$"}
	icfg.ScanTimeout = time.Second
	in, err := intake.New(icfg, e.st, e.log)
	if err != nil {
		t.Fatal(err)
	}
	pk, files := onePkg(e, "KB5010701-x64", "KB5010701")
	copyInto(t, e.bundle(bundleOpts{seq: 1}, pk, files), filepath.Join(e.inbox, "scan.pmb"))
	start := time.Now()
	bs := in.ScanOnce(context.Background())
	if len(bs) != 1 || bs[0].State != "rejected" || !strings.Contains(bs[0].Error, "timed out") {
		t.Fatalf("intake: %+v", bs)
	}
	if time.Since(start) > 30*time.Second {
		t.Fatalf("scan timeout not enforced: %v", time.Since(start))
	}
}
