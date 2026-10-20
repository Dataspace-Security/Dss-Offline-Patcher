package e2e

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"offpatch/internal/agent"
	"offpatch/internal/auditexport"
	"offpatch/internal/backup"
	"offpatch/internal/manifest"
	"offpatch/internal/store"
	"offpatch/internal/transfer"
)

func TestAuditCheckpointsAndRetention(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.enroll("pc-a", []string{"x"}, agent.SimConfig{})
	keyPath := filepath.Join(e.dir, "audit-signing.key")
	key, err := auditexport.LoadOrCreateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	pub := key.Public().(ed25519.PublicKey)
	exp := &auditexport.Exporter{Store: e.st, Dir: filepath.Join(e.dir, "worm"), Key: key, Log: e.log}
	cp1, err := exp.Export(ctx)
	if err != nil || cp1.Seq == 0 {
		t.Fatalf("export: %+v %v", cp1, err)
	}
	e.enroll("pc-b", []string{"x"}, agent.SimConfig{})
	cp2, _ := exp.Export(ctx)
	if cp2.FromSeq != cp1.Seq+1 && cp2.FromSeq != cp1.Seq {
		t.Fatalf("second export should continue after first: %+v", cp2)
	}
	rep, err := auditexport.Verify(ctx, exp.Dir, pub, e.st)
	if err != nil || !rep.OK {
		t.Fatalf("verify: %+v %v", rep, err)
	}

	// Retention: prune exported events; the chain still verifies from the anchor.
	n, err := e.st.PruneAudit(ctx, cp1.Seq, time.Now().Add(time.Hour))
	if err != nil || n == 0 {
		t.Fatalf("prune: %d %v", n, err)
	}
	e.enroll("pc-c", []string{"x"}, agent.SimConfig{})
	if cr, _ := e.st.VerifyAudit(ctx); !cr.OK {
		t.Fatalf("chain after prune: %+v", cr)
	}
	exp.Export(ctx)
	if rep, _ := auditexport.Verify(ctx, exp.Dir, pub, e.st); !rep.OK {
		t.Fatalf("verify after prune: %+v", rep)
	}

	// An attacker with DB access rewrites history AND recomputes every hash:
	// the database chain looks valid, but the signed off-box checkpoints catch it.
	db, _ := sql.Open("sqlite", filepath.Join(e.dir, "data", "pm.db"))
	defer db.Close()
	db.Exec(`DROP TRIGGER audit_no_update`)
	evs, _ := e.st.ListAudit(ctx, store.AuditQuery{Limit: 5000, Ascending: true})
	prev := evs[0].PrevHash
	for i, ev := range evs {
		if i == 2 {
			ev.Actor = "user:mallory"
		}
		ev.PrevHash = prev
		ev.Hash = store.ChainHash(prev, ev)
		db.Exec(`UPDATE audit SET actor=?, prev_hash=?, hash=? WHERE seq=?`, ev.Actor, ev.PrevHash, ev.Hash, ev.Seq)
		prev = ev.Hash
	}
	// (The pruned prefix's anchor no longer matches either; the signed
	// off-box checkpoints are what prove the rewrite.)
	rep, _ = auditexport.Verify(ctx, exp.Dir, pub, e.st)
	if rep.OK || !strings.Contains(strings.Join(rep.Problems, ";"), "rewritten") {
		t.Fatalf("rewritten database chain not detected: %+v", rep)
	}

	// Modified export file is detected without the database.
	files, _ := filepath.Glob(filepath.Join(exp.Dir, "audit-*.jsonl"))
	os.Chmod(files[0], 0o640)
	b, _ := os.ReadFile(files[0])
	os.WriteFile(files[0], []byte(strings.Replace(string(b), "pc-a", "pc-z", 1)), 0o640)
	if rep, _ := auditexport.Verify(ctx, exp.Dir, pub, nil); rep.OK {
		t.Fatal("modified export file not detected")
	}
	// Forged checkpoint (wrong key) is detected.
	_, otherPriv, _ := manifest.GenerateKey()
	if rep, _ := auditexport.Verify(ctx, exp.Dir, otherPriv.Public().(ed25519.PublicKey), nil); rep.OK {
		t.Fatal("checkpoints verified with the wrong key")
	}
}

func TestBackupRestore(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	pk := map[string]manifest.Package{"KB5000501-x64": msuPkg("KB5000501-x64", "KB5000501")}
	files := map[string]string{"KB5000501-x64": e.payload("kb5000501.msu", "payload 501")}
	e.transferAndIntake(e.bundle(bundleOpts{seq: 1}, pk, files))
	e.approve("KB5000501-x64")
	a := e.enroll("pc-bk", []string{"x"}, agent.SimConfig{})
	e.cycle(a)

	l := backup.Layout{DataDir: filepath.Join(e.dir, "data"), ConfigFile: filepath.Join(e.dir, "pmserver.json")}
	out := filepath.Join(e.dir, "backup1")
	idFile, recipient, err := backup.GenerateIdentity("test")
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(e.dir, "id.txt"), []byte(idFile), 0o600)
	os.WriteFile(filepath.Join(e.dir, "recipients.txt"), []byte(recipient+"\n"), 0o644)
	recips, err := backup.LoadRecipients(filepath.Join(e.dir, "recipients.txt"))
	if err != nil {
		t.Fatal(err)
	}
	ids, err := backup.LoadIdentities(filepath.Join(e.dir, "id.txt"))
	if err != nil {
		t.Fatal(err)
	}
	sk, err := auditexport.LoadOrCreateKey(filepath.Join(l.DataDir, "audit-signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	vo := backup.VerifyOptions{Pub: sk.Public().(ed25519.PublicKey), Identities: ids}
	opts := backup.Options{Recipients: recips, SigningKey: sk, IncludePKI: true}
	m, err := backup.Create(ctx, e.st, l, out, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backup.Verify(out, vo); err != nil {
		t.Fatalf("fresh backup fails verification: %v", err)
	}
	if _, err := backup.Create(ctx, e.st, l, out, opts); err == nil {
		t.Fatal("overwrote an existing backup")
	}
	// Nothing in the backup directory is readable without the identity.
	if b, _ := os.ReadFile(filepath.Join(out, "keys.tar.age")); strings.Contains(string(b), "PRIVATE KEY") {
		t.Fatal("keys part is not encrypted")
	}

	// Restore into an empty data dir and check integrity.
	target := backup.Layout{DataDir: filepath.Join(e.dir, "restored")}
	if _, err := backup.Restore(ctx, out, target, false, backup.VerifyOptions{Pub: vo.Pub}); err == nil {
		t.Fatal("restored an encrypted backup without the identity")
	}
	if _, err := backup.Restore(ctx, out, target, false, vo); err != nil {
		t.Fatalf("restore: %v", err)
	}
	st2, err := store.Open(filepath.Join(target.DataDir, "pm.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	p, err := st2.GetPackage(ctx, "KB5000501-x64")
	if err != nil || p.State != "approved" {
		t.Fatalf("package after restore: %+v %v", p, err)
	}
	eps, _ := st2.ListEndpoints(ctx, store.DefaultThresholds)
	if len(eps) != 1 {
		t.Fatalf("endpoints after restore: %d", len(eps))
	}
	if id, err := st2.EndpointIDBySecret(ctx, a.secret); err != nil || id != a.id {
		t.Fatal("agent credentials do not survive restore")
	}
	if seq, _, _ := st2.AuditHead(ctx); seq < m.AuditSeq {
		t.Fatalf("audit head %d < backup %d", seq, m.AuditSeq)
	}
	if _, err := backup.Restore(ctx, out, target, false, vo); err == nil {
		t.Fatal("restore over an existing database without -force")
	}
	if _, err := os.Stat(filepath.Join(target.DataDir, "audit-signing.key")); err != nil {
		t.Errorf("keys part not restored: %v", err)
	}

	// Tampered backup is refused.
	obj := filepath.Join(out, "data.tar.age")
	b, _ := os.ReadFile(obj)
	b[len(b)-10] ^= 1
	os.Chmod(obj, 0o640)
	os.WriteFile(obj, b, 0o640)
	if _, err := backup.Verify(out, vo); err == nil || !strings.Contains(err.Error(), "modified") {
		t.Fatalf("tampered backup verified: %v", err)
	}
	if _, err := backup.Restore(ctx, out, backup.Layout{DataDir: filepath.Join(e.dir, "r2")}, false, vo); err == nil {
		t.Fatal("tampered backup restored")
	}
}

func TestReceiptsAndRateLimit(t *testing.T) {
	e := newEnvOpts(t, false, `"intake_max_bundles_per_hour": 2,`)
	ctx := context.Background()
	pk := map[string]manifest.Package{"KB5000601-x64": msuPkg("KB5000601-x64", "KB5000601")}
	files := map[string]string{"KB5000601-x64": e.payload("kb5000601.msu", "payload 601")}

	send := func(seq int64, sign bool) transfer.Receipt {
		dd := transfer.DropDir{Dir: e.inbox}
		rc, err := dd.Send(e.bundle(bundleOpts{seq: seq}, pk, files))
		if err != nil {
			t.Fatal(err)
		}
		if sign {
			rc.Sign(e.priv)
		}
		if err := dd.SendReceipt(rc); err != nil {
			t.Fatal(err)
		}
		return rc
	}
	send(1, true)
	send(2, false) // unsigned receipt
	e.intake.ScanOnce(ctx)
	// A receipt for a bundle that never arrived (lost in transfer).
	lost := transfer.Receipt{Adapter: "dropdir", File: "lost.pmb", Size: 10, SHA256: strings.Repeat("ab", 32), SentAt: time.Now().UTC().Format(time.RFC3339)}
	lost.Sign(e.priv)
	transfer.DropDir{Dir: e.inbox}.SendReceipt(lost)
	e.intake.ScanOnce(ctx)

	var rec store.Reconciliation
	e.api("GET", "/api/transfer/reconcile", tokOperator, nil, &rec)
	if len(rec.Matched) != 2 || len(rec.ReceiptWithoutBundle) != 1 || rec.UnsignedReceipts != 1 || len(rec.BundleWithoutReceipt) != 1 {
		t.Fatalf("reconciliation: matched=%d lost=%d unsigned=%d unreceipted=%d", len(rec.Matched), len(rec.ReceiptWithoutBundle), rec.UnsignedReceipts, len(rec.BundleWithoutReceipt))
	}

	// Rate limit: 2 per hour already used; the third bundle waits in the inbox.
	send(3, true)
	if got := e.intake.ScanOnce(ctx); len(got) != 0 {
		t.Fatalf("rate limit not enforced: processed %d", len(got))
	}
	if _, err := os.Stat(filepath.Join(e.inbox)); err != nil {
		t.Fatal(err)
	}
	left, _ := filepath.Glob(filepath.Join(e.inbox, "*.pmb"))
	if len(left) != 1 {
		t.Fatalf("deferred bundle should stay in the inbox, found %d", len(left))
	}
	evs, _ := e.st.ListAudit(ctx, store.AuditQuery{Action: "intake.rate_limited"})
	if len(evs) != 1 {
		t.Fatalf("rate limiting should be audited once: %d", len(evs))
	}
}
