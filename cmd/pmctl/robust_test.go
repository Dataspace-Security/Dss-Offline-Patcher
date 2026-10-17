package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"offpatch/internal/acquire"
	"offpatch/internal/acquire/acquiretest"
	"offpatch/internal/manifest"
)

// autoEnv is a pmctl auto setup against the Microsoft fixtures and a fake
// vendor serving acme-agent 2.3.0.
type autoEnv struct {
	t                  *testing.T
	srv                *acquiretest.Server
	dir, drop, cfgPath string
	pub                ed25519.PublicKey
}

func newAutoEnv(t *testing.T, extra string) *autoEnv {
	t.Helper()
	stubAuthenticode(t)
	srv := acquiretest.New(t, "../../internal/acquire/testdata", acquiretest.Payload(200_000))
	app := []byte("ACME agent 2.3 msi")
	sum := sha256.Sum256(app)
	srv.Vendor["latest.json"] = []byte(`{"releases":[{"version":"2.3.0"}]}`)
	srv.Vendor["acme-agent-2.3.0.msi"] = app
	srv.Vendor["SHA256SUMS-2.3.0"] = []byte(hex.EncodeToString(sum[:]) + "  acme-agent-2.3.0.msi\n")

	oldHTTP, oldNow, oldBackoff := autoHTTP, autoNow, acquire.RetryBackoff
	autoHTTP = func() *http.Client { return srv.Client() }
	autoNow = func() time.Time { return time.Date(2026, 10, 16, 3, 0, 0, 0, time.UTC) }
	acquire.RetryBackoff = func(int) time.Duration { return time.Millisecond }
	t.Cleanup(func() { autoHTTP, autoNow, acquire.RetryBackoff = oldHTTP, oldNow, oldBackoff })

	e := &autoEnv{t: t, srv: srv, dir: t.TempDir()}
	pub, priv, _ := manifest.GenerateKey()
	e.pub = pub
	os.WriteFile(filepath.Join(e.dir, "bundle.key"), manifest.EncodePrivate(priv), 0o600)
	e.drop = filepath.Join(e.dir, "diode")
	os.MkdirAll(e.drop, 0o750)
	cfg := fmt.Sprintf(`{ %s
	  "work_dir": "work", "key": "bundle.key", "source": "acq-zone-1",
	  "send": {"via": "dropdir", "to": "diode"},
	  "catalog_url": %q, "msrc_url": %q,
	  "microsoft": {"months": 1, "min_severity": "important",
	    "products": [{"msrc_product": "Windows 10 Version 22H2", "catalog_product": "Windows 10 Version 22H2", "arch": "x64", "min_build": 19045, "max_build": 19045}]},
	  "apps": [{"name": "acme-agent", "title": "Acme Endpoint Agent", "vendor": "Acme", "kind": "msi",
	    "product_code": "{11111111-2222-3333-4444-555555555555}", "arch": "x64", "severity": "important",
	    "version": {"url": "%s/vendor/latest.json", "json_path": "releases.0.version"},
	    "download_url": "%s/vendor/acme-agent-{version}.msi",
	    "sha256": {"url": "%s/vendor/SHA256SUMS-{version}"}}]
	}`, extra, srv.URL, srv.URL, srv.URL, srv.URL, srv.URL)
	e.cfgPath = filepath.Join(e.dir, "acquire.json")
	os.WriteFile(e.cfgPath, []byte(cfg), 0o600)
	return e
}

func (e *autoEnv) run() autoReport {
	e.t.Helper()
	rep, err := runAuto(context.Background(), e.cfgPath, false)
	if err != nil {
		e.t.Fatalf("run: %v %+v", err, rep)
	}
	return rep
}

func (e *autoEnv) state() autoState {
	e.t.Helper()
	st, err := loadState(filepath.Join(e.dir, "work", "state.json"))
	if err != nil {
		e.t.Fatal(err)
	}
	return st
}

// bundles returns the manifests in the drop directory, by sequence.
func (e *autoEnv) bundles() []*manifest.Manifest {
	e.t.Helper()
	paths, _ := filepath.Glob(filepath.Join(e.drop, "*.pmb"))
	var out []*manifest.Manifest
	for _, p := range paths {
		ex, err := manifest.ExtractSafe(p, e.t.TempDir(), manifest.Limits{MaxFiles: 10})
		if err != nil {
			e.t.Fatal(err)
		}
		if err := manifest.Verify(e.pub, ex.ManifestBytes, ex.Signature); err != nil {
			e.t.Fatal(err)
		}
		m, err := manifest.Parse(ex.ManifestBytes)
		if err != nil {
			e.t.Fatal(err)
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Sequence < out[j].Sequence })
	return out
}

func ids(m *manifest.Manifest) []string {
	var out []string
	for _, p := range m.Packages {
		out = append(out, p.PackageID)
	}
	return out
}

// C1: the sequence only grows, -seq must be above it, and a corrupt state
// file stops the build instead of restarting at 1.
func TestSequenceState(t *testing.T) {
	p := filepath.Join(t.TempDir(), "seq.json")
	for want := int64(1); want <= 2; want++ {
		if got, err := reserveSequence(p, "a", 0); err != nil || got != want {
			t.Fatalf("next: %d %v, want %d", got, err, want)
		}
	}
	if _, err := reserveSequence(p, "a", 2); err == nil || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("-seq not above the stored value accepted: %v", err)
	}
	if got, err := reserveSequence(p, "a", 10); err != nil || got != 10 {
		t.Fatalf("explicit: %d %v", got, err)
	}
	if got, _ := reserveSequence(p, "a", 0); got != 11 {
		t.Fatalf("after explicit 10: %d", got)
	}
	if got, _ := reserveSequence(p, "b", 0); got != 1 {
		t.Fatalf("sources are independent: %d", got)
	}
	os.WriteFile(p, []byte(`{"sequences": {"a": 11`), 0o600)
	if _, err := reserveSequence(p, "a", 0); err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("corrupt state accepted: %v", err)
	}
}

// C1: a manual build pointed at an empty state file warns when the state of
// pmctl auto (or the build default) already has a sequence for the source.
func TestSequenceStateWarnings(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	os.WriteFile("acquire.json", []byte(`{"work_dir":"auto","key":"k.key","source":"acq-zone-1"}`), 0o600)
	os.MkdirAll("auto", 0o750)
	if _, err := reserveSequence(filepath.Join("auto", "sequence.json"), "acq-zone-1", 41); err != nil {
		t.Fatal(err)
	}
	w := sequenceStateWarnings(".pmctl-state.json", "acq-zone-1")
	if len(w) != 1 || !strings.Contains(w[0], "records 41") {
		t.Fatalf("warnings = %v", w)
	}
	if w := sequenceStateWarnings(filepath.Join(dir, "auto", "sequence.json"), "acq-zone-1"); len(w) != 0 {
		t.Fatalf("no warning expected for the right file: %v", w)
	}
	// pmctl build -config uses the auto state: sequence 42.
	_, priv, _ := manifest.GenerateKey()
	os.WriteFile("k.key", manifest.EncodePrivate(priv), 0o600)
	os.WriteFile("x.msi", []byte("msi"), 0o600)
	os.WriteFile("spec.json", []byte(`[{"package_id":"X-1","title":"X","vendor":"V","kind":"msi","product_code":"{11111111-2222-3333-4444-555555555555}",
	  "severity":"low","release_date":"2026-10-01","applicability":{"os":"windows","arch":"x64"},"source_url":"https://v/x.msi","path":"x.msi",
	  "vendor_signature":{"status":"not_checked"}}]`), 0o600)
	if err := build([]string{"-key", "k.key", "-spec", "spec.json", "-out", "x.pmb", "-config", "acquire.json"}); err != nil {
		t.Fatal(err)
	}
	st, _ := readSeqState(filepath.Join("auto", "sequence.json"))
	if st.Sequences["acq-zone-1"] != 42 {
		t.Fatalf("sequence = %v", st.Sequences)
	}
}

// C2: pending packages beyond max_bundle_packages go into further bundles,
// each with its own sequence; all are recorded as done.
func TestAutoSplitsBundles(t *testing.T) {
	e := newAutoEnv(t, `"max_bundle_packages": 1,`)
	rep := e.run()
	if !rep.Sent || len(rep.Bundles) != 2 || len(rep.Failures) != 0 {
		t.Fatalf("%+v", rep)
	}
	bs := e.bundles()
	if len(bs) != 2 || bs[0].Sequence != 1 || bs[1].Sequence != 2 || len(bs[0].Packages) != 1 || len(bs[1].Packages) != 1 {
		t.Fatalf("bundles: %v", bs)
	}
	if st := e.state(); len(st.Done) != 2 || st.Done["acme-agent-2.3.0"].File != "acme-agent-2.3.0.msi" || st.Done["acme-agent-2.3.0"].SHA256 == "" {
		t.Fatalf("state: %+v", st)
	}
}

func TestPartition(t *testing.T) {
	pk := func(id string, size int64) pendingPkg {
		return pendingPkg{sp: specPackage{Package: manifest.Package{PackageID: id}}, size: size}
	}
	failed := map[string]string{}
	fail := func(id string, err error) { failed[id] = err.Error() }
	max := int64(perBundleOverhead + 3*(100+perPackageOverhead))
	g := partition([]pendingPkg{pk("a", 100), pk("b", 100), pk("huge", max), pk("c", 100), pk("d", 100)}, max, 450, fail)
	if len(g) != 2 || len(g[0]) != 3 || len(g[1]) != 1 || failed["huge"] == "" {
		t.Fatalf("groups %v failed %v", g, failed)
	}
	if g := partition([]pendingPkg{pk("a", 1), pk("b", 1), pk("c", 1)}, 1<<30, 2, fail); len(g) != 2 {
		t.Fatalf("package cap: %v", g)
	}
}

// H1: a CU listed with a checkpoint update ships both; the CU names the
// checkpoint as a prerequisite; the next run sends nothing again.
func TestAutoShipsCheckpoint(t *testing.T) {
	e := newAutoEnv(t, "")
	e.srv.SetCheckpoint(acquiretest.Payload(1234))
	rep := e.run()
	cp := acquiretest.CheckpointKB + "-x64"
	if !slices.Contains(rep.New, cp) || !slices.Contains(rep.New, "KB5126657-x64") {
		t.Fatalf("new = %v", rep.New)
	}
	bs := e.bundles()
	if len(bs) != 1 {
		t.Fatalf("bundles: %d", len(bs))
	}
	var cu *manifest.Package
	for i, p := range bs[0].Packages {
		if p.PackageID == "KB5126657-x64" {
			cu = &bs[0].Packages[i]
		}
	}
	if cu == nil || !slices.Equal(cu.Prerequisites, []string{acquiretest.CheckpointKB}) || !slices.Contains(ids(bs[0]), cp) {
		t.Fatalf("manifest: %v %+v", ids(bs[0]), cu)
	}
	if rep := e.run(); rep.Sent || len(rep.New) != 0 {
		t.Fatalf("second run: %+v", rep)
	}
}

// H3: one package with an invalid vendor signature is left out (and
// retried); the rest is still sent.
func TestAutoLeavesOutInvalidSignature(t *testing.T) {
	e := newAutoEnv(t, "")
	old := vendorSig
	vendorSig = func(path string) manifest.VendorSignature {
		if strings.HasSuffix(path, ".msi") {
			return manifest.VendorSignature{Status: "invalid", Signer: "NotSigned"}
		}
		return manifest.VendorSignature{Status: "valid", Signer: "Microsoft Corporation"}
	}
	t.Cleanup(func() { vendorSig = old })
	rep := e.run()
	if !rep.Sent || !strings.Contains(rep.Failures["acme-agent-2.3.0"], "not valid") || slices.Contains(rep.New, "acme-agent-2.3.0") {
		t.Fatalf("%+v", rep)
	}
	if bs := e.bundles(); len(bs) != 1 || !slices.Equal(ids(bs[0]), []string{"KB5126657-x64"}) {
		t.Fatalf("bundle: %v", bs)
	}
	if st := e.state(); st.Failed["acme-agent-2.3.0"] == "" || len(st.Done) != 1 {
		t.Fatalf("state: %+v", st)
	}
}

// H2: once the bundle is across, a failing receipt/log is a warning and the
// packages are done (no resend next run).
func TestAutoPostDeliveryFailureStillDone(t *testing.T) {
	e := newAutoEnv(t, "")
	logDir := filepath.Join(e.dir, "logdir")
	os.MkdirAll(logDir, 0o750)
	b, _ := os.ReadFile(e.cfgPath)
	os.WriteFile(e.cfgPath, []byte(strings.Replace(string(b), `"to": "diode"`, `"to": "diode", "log": "logdir"`, 1)), 0o600)
	rep := e.run()
	if !rep.Sent || !strings.Contains(strings.Join(rep.Warnings, " "), "bundle delivered, but sender log") {
		t.Fatalf("%+v", rep)
	}
	if st := e.state(); len(st.Done) != 2 {
		t.Fatalf("state: %+v", st)
	}
	if rep := e.run(); rep.Sent {
		t.Fatalf("resent: %+v", rep)
	}
}

// H7: MSRC failing (5xx after retries) is not "up to date": the feed is
// failed and the run partial. Only a 404 for the newest month is benign.
func TestAutoMSRCFailureIsPartial(t *testing.T) {
	e := newAutoEnv(t, "")
	e.srv.Fail5xx = 3 // the MSRC GET is the first page request
	rep := e.run()
	if rep.Failures["msrc"] == "" || !partialRun(&rep) || rep.Feeds[0].Status != "failed" {
		t.Fatalf("%+v", rep)
	}
	// November not published yet (404), October fine: no failure.
	autoNow = func() time.Time { return time.Date(2026, 11, 2, 3, 0, 0, 0, time.UTC) }
	b, _ := os.ReadFile(e.cfgPath)
	os.WriteFile(e.cfgPath, []byte(strings.Replace(string(b), `"months": 1`, `"months": 2`, 1)), 0o600)
	rep = e.run()
	if rep.Failures["msrc"] != "" || !strings.Contains(strings.Join(rep.Warnings, " "), "not published yet") {
		t.Fatalf("%+v", rep)
	}
}

// A corrupt state.json stops the run instead of resending everything.
func TestAutoRefusesCorruptState(t *testing.T) {
	e := newAutoEnv(t, "")
	os.MkdirAll(filepath.Join(e.dir, "work"), 0o750)
	os.WriteFile(filepath.Join(e.dir, "work", "state.json"), []byte(`{"done": {`), 0o600)
	if _, err := runAuto(context.Background(), e.cfgPath, false); err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("corrupt state accepted: %v", err)
	}
	if ents, _ := os.ReadDir(e.drop); len(ents) != 0 {
		t.Fatal("something was sent")
	}
}

// H5: run directories and downloads of packages sent long ago are deleted;
// recent ones are kept.
func TestAutoRetention(t *testing.T) {
	e := newAutoEnv(t, `"keep_runs_days": 14, "keep_downloads_days": 30,`)
	work := filepath.Join(e.dir, "work")
	for _, d := range []string{"runs/20260901T000000Z-old", "runs/20261010T000000Z-recent", "downloads"} {
		os.MkdirAll(filepath.Join(work, filepath.FromSlash(d)), 0o750)
	}
	os.WriteFile(filepath.Join(work, "downloads", "old.msu"), []byte("x"), 0o600)
	os.WriteFile(filepath.Join(work, "downloads", "recent.msu"), []byte("x"), 0o600)
	stale := filepath.Join(work, "downloads", "gone.msu.part")
	os.WriteFile(stale, []byte("x"), 0o600)
	long := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	os.Chtimes(stale, long, long)
	saveJSON(filepath.Join(work, "state.json"), autoState{Done: map[string]autoDone{
		"KB1-x64": {File: "old.msu", SentAt: "2026-08-01T00:00:00Z"},
		"KB2-x64": {File: "recent.msu", SentAt: "2026-10-01T00:00:00Z"},
	}})
	e.run()
	gone := func(p string) bool {
		_, err := os.Stat(filepath.Join(work, filepath.FromSlash(p)))
		return os.IsNotExist(err)
	}
	if !gone("runs/20260901T000000Z-old") || gone("runs/20261010T000000Z-recent") || !gone("downloads/old.msu") ||
		gone("downloads/recent.msu") || !gone("downloads/gone.msu.part") || gone("downloads/acme-agent-2.3.0.msi") {
		t.Fatal("retention deleted the wrong things")
	}
}

// H6: a lock whose owner is gone is taken over; one that is refreshed, or
// whose owner still runs, is not.
func TestAutoLockStaleness(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".auto.lock")
	old := time.Now().Add(-2 * lockStale)
	os.WriteFile(p, []byte("0 2026-01-01T00:00:00Z\n"), 0o600) // pid 0: never running
	os.Chtimes(p, old, old)
	unlock, err := acquireLock(dir, time.Hour)
	if err != nil {
		t.Fatalf("stale lock of a dead process not taken over: %v", err)
	}
	unlock()
	os.WriteFile(p, []byte(strconv.Itoa(os.Getpid())+" now\n"), 0o600) // owner alive
	os.Chtimes(p, old, old)
	if _, err := acquireLock(dir, time.Hour); err == nil {
		t.Fatal("lock of a live process taken over")
	}
	// Refresh keeps the mtime fresh while the run lasts.
	os.Remove(p)
	oldRefresh := lockRefresh
	lockRefresh = 20 * time.Millisecond
	t.Cleanup(func() { lockRefresh = oldRefresh })
	unlock, err = acquireLock(dir, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	os.Chtimes(p, old, old)
	time.Sleep(200 * time.Millisecond)
	if fi, _ := os.Stat(p); time.Since(fi.ModTime()) > time.Minute {
		t.Fatal("lock not refreshed")
	}
	unlock()
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("lock not released")
	}
}

func TestSplitArgs(t *testing.T) {
	for in, want := range map[string][]string{
		`diodectl push {file}`:                            {"diodectl", "push", "{file}"},
		`"C:\Program Files\HSM\sign.exe" -k 'key one' -v`: {`C:\Program Files\HSM\sign.exe`, "-k", "key one", "-v"},
		`  /usr/bin/x   a""b  `:                           {"/usr/bin/x", "ab"},
		`x ""`:                                            {"x", ""},
		`C:\tools\gw.exe --to=\\gw\in {file}`:             {`C:\tools\gw.exe`, `--to=\\gw\in`, "{file}"},
	} {
		got, err := splitArgs(in)
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("splitArgs(%q) = %q %v, want %q", in, got, err, want)
		}
	}
	if _, err := splitArgs(`"unterminated`); err == nil {
		t.Error("unterminated quote accepted")
	}
}

// H6: a hung external signer is killed after signerTimeout.
func TestExecSignerTimeout(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake hsm")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if out, err := exec.Command("go", "build", "-o", bin, "./testdata/fakehsm").CombinedOutput(); err != nil {
		t.Fatalf("build fakehsm: %v %s", err, out)
	}
	pub, _, _ := manifest.GenerateKey()
	os.WriteFile(filepath.Join(dir, "k.pub"), manifest.EncodePublic(pub), 0o644)
	t.Setenv("FAKEHSM_MODE", "sleep")
	old := signerTimeout
	signerTimeout = 300 * time.Millisecond
	t.Cleanup(func() { signerTimeout = old })
	s, err := openSigner(`exec:"`+bin+`"`, filepath.Join(dir, "k.pub")) // quoted: the path has a space
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := s.Sign([]byte("x")); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("want timeout, got %v", err)
	}
	if time.Since(start) > 30*time.Second {
		t.Fatal("signer not killed")
	}
}

// Supersedence: an older KB is dropped only when the superseding KB is
// available (fetched or sent); if that failed, the older one is fetched.
func TestAutoSupersedenceNeedsAvailableSuperseder(t *testing.T) {
	cvrf := `{"ProductTree":{"FullProductName":[{"ProductID":"1","Value":"Windows 10 Version 22H2 for x64-based Systems"}]},
	  "Vulnerability":[{"CVE":"CVE-2026-1","Threats":[{"Type":3,"Description":{"Value":"Critical"},"ProductID":["1"]}],
	    "Remediations":[{"Type":2,"Description":{"Value":"5000002"},"ProductID":["1"],"Supercedence":"5000001"},
	                    {"Type":2,"Description":{"Value":"5000001"},"ProductID":["1"]}]}]}`
	noRes, _ := os.ReadFile("../../internal/acquire/testdata/search-noresults.html")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/cvrf/") {
			w.Write([]byte(cvrf))
			return
		}
		w.Write(noRes) // the catalog has neither KB: both fetches fail
	}))
	t.Cleanup(srv.Close)
	oldHTTP, oldNow := autoHTTP, autoNow
	autoHTTP = func() *http.Client { return srv.Client() }
	autoNow = func() time.Time { return time.Date(2026, 10, 16, 3, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { autoHTTP, autoNow = oldHTTP, oldNow })
	dir := t.TempDir()
	_, priv, _ := manifest.GenerateKey()
	os.WriteFile(filepath.Join(dir, "k.key"), manifest.EncodePrivate(priv), 0o600)
	os.MkdirAll(filepath.Join(dir, "drop"), 0o750)
	cfg := fmt.Sprintf(`{"work_dir":"w","key":"k.key","send":{"to":"drop"},"catalog_url":%q,"msrc_url":%q,
	  "microsoft":{"months":1,"products":[{"msrc_product":"Windows 10 Version 22H2","arch":"x64"}]}}`, srv.URL, srv.URL)
	cp := filepath.Join(dir, "a.json")
	os.WriteFile(cp, []byte(cfg), 0o600)

	rep, err := runAuto(context.Background(), cp, false)
	if err != nil || len(rep.Superseded) != 0 || rep.Failures["KB5000001-x64"] == "" || rep.Failures["KB5000002-x64"] == "" {
		t.Fatalf("superseder failed: the older KB must be tried: %v %+v", err, rep)
	}
	// Superseder delivered earlier: the older KB is skipped as superseded.
	b, _ := json.Marshal(autoState{Done: map[string]autoDone{"KB5000002-x64": {BundleID: "b-1"}}})
	os.WriteFile(filepath.Join(dir, "w", "state.json"), b, 0o600)
	rep, err = runAuto(context.Background(), cp, false)
	if err != nil || len(rep.Superseded) != 1 || rep.Failures["KB5000001-x64"] != "" {
		t.Fatalf("superseder available: %v %+v", err, rep)
	}
}
