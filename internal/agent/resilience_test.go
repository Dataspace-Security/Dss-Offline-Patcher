package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"debug/pe"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"offpatch/internal/manifest"
	"offpatch/internal/pki"
	"offpatch/internal/store"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestRenewDue(t *testing.T) {
	nb := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	na := nb.Add(365 * 24 * time.Hour)
	day := 24 * time.Hour
	cases := []struct {
		now  time.Time
		rb   time.Duration
		want bool
	}{
		{nb.Add(day), 30 * day, false},
		{nb.Add(182 * day), 30 * day, false},
		{nb.Add(183 * day), 30 * day, true}, // past half of the lifetime
		{na.Add(-day), 30 * day, true},
		{na.Add(day), 30 * day, true},  // expired: still try
		{nb.Add(day), 400 * day, true}, // renewBefore longer than the lifetime
	}
	for _, c := range cases {
		if got := renewDue(nb, na, c.now, c.rb); got != c.want {
			t.Errorf("renewDue(now=%s, rb=%s) = %v, want %v", c.now.Format(time.DateOnly), c.rb, got, c.want)
		}
	}
}

func TestBackoffDelay(t *testing.T) {
	m := time.Minute
	cases := []struct {
		interval time.Duration
		failures int
		want     time.Duration
	}{
		{m, 0, m},
		{m, 1, 2 * m},
		{m, 2, 4 * m},
		{m, 3, 8 * m},
		{m, 4, 15 * m},
		{m, 50, 15 * m},
		{30 * m, 0, 30 * m},
		{30 * m, 3, 30 * m}, // interval above the cap stays as is
	}
	for _, c := range cases {
		if got := backoffDelay(c.interval, c.failures); got != c.want {
			t.Errorf("backoffDelay(%s, %d) = %s, want %s", c.interval, c.failures, got, c.want)
		}
	}
}

func TestDecideUpgrade(t *testing.T) {
	pending := func(starts int) *upgradeMarker {
		return &upgradeMarker{From: "1.0.0", To: "1.1.0", State: "pending", Starts: starts}
	}
	cases := []struct {
		name    string
		m       *upgradeMarker
		running string
		want    upgradeAction
	}{
		{"no marker", nil, "1.1.0", upgradeNone},
		{"failed marker", &upgradeMarker{To: "1.1.0", State: "failed"}, "1.0.0", upgradeNone},
		{"first start of new binary", pending(0), "1.1.0", upgradeCount},
		{"second start", pending(2), "1.1.0", upgradeCount},
		{"keeps crashing", pending(3), "1.1.0", upgradeRollback},
		{"unstamped binary", pending(0), "0.1.0", upgradeFailed},
		{"old binary back", pending(1), "1.0.0", upgradeFailed},
	}
	for _, c := range cases {
		if got := decideUpgrade(c.m, c.running, maxUpgradeStarts); got != c.want {
			t.Errorf("%s: got %d want %d", c.name, got, c.want)
		}
	}
}

func TestUpgradeBlockedOnlyForSameBinary(t *testing.T) {
	a := &Agent{dir: t.TempDir(), log: quiet}
	if _, b := a.upgradeBlocked("1.1.0", "aa"); b {
		t.Fatal("blocked without marker")
	}
	saveMarker(a.dir, upgradeMarker{To: "1.1.0", SHA256: "aa", State: "failed", Reason: "x"})
	if _, b := a.upgradeBlocked("1.1.0", "aa"); !b {
		t.Fatal("same failed binary must not be retried")
	}
	if _, b := a.upgradeBlocked("1.1.0", "bb"); b {
		t.Fatal("a rebuilt package (new hash) may be tried")
	}
	saveMarker(a.dir, upgradeMarker{To: "1.1.0", SHA256: "aa", State: "pending"})
	if _, b := a.upgradeBlocked("1.1.0", "aa"); b {
		t.Fatal("pending is not blocked")
	}
}

func TestVerifyBinaryMissing(t *testing.T) {
	if err := verifyBinary(context.Background(), filepath.Join(t.TempDir(), "nope"), "1.0.0"); err == nil {
		t.Fatal("a binary that does not run must be refused")
	}
}

func TestSwapAndRestoreBinary(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "pmagent.exe")
	os.WriteFile(exe, []byte("old"), 0o755)
	os.WriteFile(exe+".new", []byte("new"), 0o755)
	if err := swapBinary(exe, exe+".new"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "new" {
		t.Fatalf("after swap: %q", b)
	}
	if err := restoreOld(exe); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "old" {
		t.Fatalf("after restore: %q", b)
	}
	if b, _ := os.ReadFile(exe + ".failed"); string(b) != "new" {
		t.Fatalf("failing binary not kept: %q", b)
	}
	if err := restoreOld(exe); err == nil {
		t.Fatal("restore without .old must fail")
	}
}

func TestMachineArch(t *testing.T) {
	for m, want := range map[uint16]string{pe.IMAGE_FILE_MACHINE_AMD64: "x64", pe.IMAGE_FILE_MACHINE_ARM64: "arm64", pe.IMAGE_FILE_MACHINE_I386: "x86", 0: ""} {
		if got := machineArch(m); got != want {
			t.Errorf("machineArch(%#x) = %q want %q", m, got, want)
		}
	}
}

func testState() *State {
	return &State{ServerURL: "https://pm.example", EndpointID: "ep-1", TrustedKeys: map[string]string{}}
}

func TestStateSaveAtomicWithBackup(t *testing.T) {
	dir := t.TempDir()
	s1 := testState()
	if err := s1.Save(dir); err != nil {
		t.Fatal(err)
	}
	s2 := testState()
	s2.TrustSeq = 2
	if err := s2.Save(dir); err != nil {
		t.Fatal(err)
	}
	bak, err := readState(statePath(dir) + ".bak")
	if err != nil || bak.TrustSeq != 0 {
		t.Fatalf("backup should hold the previous state: %+v %v", bak, err)
	}
	// A torn write (empty / truncated file) falls back to the backup.
	os.WriteFile(statePath(dir), []byte(`{"server_url": "htt`), 0o600)
	got, err := LoadState(dir)
	if err != nil || got.EndpointID != "ep-1" {
		t.Fatalf("fallback to .bak: %+v %v", got, err)
	}
	// Saving over a damaged file must not overwrite the good backup.
	if err := s2.Save(dir); err != nil {
		t.Fatal(err)
	}
	if bak, _ := readState(statePath(dir) + ".bak"); bak == nil || bak.TrustSeq != 0 {
		t.Fatal("damaged state replaced the good backup")
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("temporary file left behind: %s", e.Name())
		}
	}
	if _, err := LoadState(t.TempDir()); err == nil || !strings.Contains(err.Error(), "not enrolled") {
		t.Fatalf("missing state: %v", err)
	}
}

func TestEnrollRefusesExistingAndKeepsKey(t *testing.T) {
	dir := t.TempDir()
	sim := &SimConfig{Hostname: "h"}
	plat := NewSim(*sim, filepath.Join(dir, "sim-state.json"))
	pub, _, _ := manifest.GenerateKey()
	keys := []string{string(manifest.EncodePublic(pub))}
	if err := testState().Save(dir); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, keyName), []byte("old-key"), 0o600)
	os.WriteFile(filepath.Join(dir, certName), []byte("old-cert"), 0o644)
	// Unreachable server: nothing is listening on port 1.
	if _, err := Enroll("https://127.0.0.1:1", "tok", "", dir, keys, "", plat, "sim", sim); err == nil || !strings.Contains(err.Error(), "already enrolled") {
		t.Fatalf("existing enrollment must be refused without force: %v", err)
	}
	if _, err := Enroll("https://127.0.0.1:1", "tok", "", dir, keys, "", plat, "sim", sim, WithForce()); err == nil {
		t.Fatal("enroll against an unreachable server must fail")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, keyName)); string(b) != "old-key" {
		t.Fatalf("a failed re-enrollment destroyed the device key: %q", b)
	}
	if st, err := LoadState(dir); err != nil || st.EndpointID != "ep-1" {
		t.Fatalf("a failed re-enrollment changed the state: %+v %v", st, err)
	}
	if _, err := os.Stat(filepath.Join(dir, keyName+".new")); !os.IsNotExist(err) {
		t.Fatal("staged key left behind")
	}
}

func selfSigned(t *testing.T, key *ecdsa.PrivateKey, notAfter time.Time) []byte {
	t.Helper()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestCheckClientCert(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "client.key")
	if _, err := pki.NewClientKey(keyPath); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(keyPath)
	blk, _ := pem.Decode(b)
	key, err := x509.ParseECPrivateKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := checkClientCert(selfSigned(t, key, time.Now().Add(time.Hour)), keyPath); err != nil {
		t.Fatalf("matching certificate rejected: %v", err)
	}
	for name, c := range map[string][]byte{
		"empty":     nil,
		"garbage":   []byte("not a cert"),
		"other key": selfSigned(t, other, time.Now().Add(time.Hour)),
		"expired":   selfSigned(t, key, time.Now().Add(-time.Minute)),
	} {
		if _, err := checkClientCert(c, keyPath); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCleanCacheAndPruneLogs(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	old, fresh := filepath.Join(dir, "a.msu.part"), filepath.Join(dir, "b.msu")
	os.WriteFile(old, []byte("x"), 0o600)
	os.WriteFile(fresh, []byte("x"), 0o600)
	os.Chtimes(old, now.Add(-8*24*time.Hour), now.Add(-8*24*time.Hour))
	if n := cleanCache(dir, cacheMaxAge, now); n != 1 {
		t.Fatalf("removed %d, want 1", n)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatal("fresh payload removed")
	}

	logs := t.TempDir()
	for i := 0; i < 5; i++ {
		p := filepath.Join(logs, "p"+string(rune('0'+i))+".log")
		os.WriteFile(p, nil, 0o600)
		os.Chtimes(p, now.Add(time.Duration(i)*time.Minute), now.Add(time.Duration(i)*time.Minute))
	}
	os.WriteFile(filepath.Join(logs, "keep.txt"), nil, 0o600)
	pruneOldest(logs, ".log", 3)
	ents, _ := os.ReadDir(logs)
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != "keep.txt,p3.log,p4.log" {
		t.Fatalf("after prune: %v", names)
	}
}

func TestRotatingFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agent.log")
	r, err := OpenRotatingFile(p, 100)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.Repeat("x", 39) + "\n"
	for i := 0; i < 5; i++ {
		r.Write([]byte(line))
	}
	r.Close()
	cur, _ := os.ReadFile(p)
	prev, _ := os.ReadFile(p + ".1")
	if len(cur) > 100 || len(prev) == 0 || len(prev) > 100 {
		t.Fatalf("rotation: current %d bytes, previous %d bytes", len(cur), len(prev))
	}
}

// fakePlat is a controllable platform for check-in tests.
type fakePlat struct {
	mu      sync.Mutex
	invErr  error
	invRuns int
	slow    bool
}

func (p *fakePlat) Name() string { return "fake" }
func (p *fakePlat) Facts() (Facts, error) {
	return Facts{Hostname: "h", OS: "windows", Build: 19045, Arch: "x64"}, nil
}
func (p *fakePlat) Inventory() ([]store.InventoryItem, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.invRuns++
	if p.invErr != nil {
		return nil, false, p.invErr
	}
	return []store.InventoryItem{{Kind: "kb", ID: "KB1"}}, false, nil
}
func (p *fakePlat) Install(context.Context, manifest.Package, string) Result { return Result{} }
func (p *fakePlat) Reboot(context.Context, string) error                     { return nil }
func (p *fakePlat) Health(context.Context, []store.HealthCheck) (bool, string) {
	return true, ""
}

type slowFake struct{ *fakePlat }

func (slowFake) slowInventory() {}

type recorder struct {
	mu    sync.Mutex
	paths []string
	inv   [][]store.InventoryItem
}

func (rc *recorder) server(t *testing.T) *httptest.Server {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc.mu.Lock()
		defer rc.mu.Unlock()
		rc.paths = append(rc.paths, r.URL.Path)
		if r.URL.Path == "/api/agent/checkin" {
			var req store.CheckinRequest
			json.NewDecoder(r.Body).Decode(&req)
			rc.inv = append(rc.inv, req.Inventory)
		}
		w.Write([]byte(`{}`))
	}))
	t.Cleanup(s.Close)
	return s
}

func testAgent(t *testing.T, plat Platform, srv *httptest.Server) *Agent {
	u, _ := url.Parse(srv.URL)
	return &Agent{st: testState(), dir: t.TempDir(), plat: plat, hc: srv.Client(), base: u, log: quiet, interval: time.Minute, started: time.Now()}
}

func TestCycleWithoutInventorySendsHeartbeat(t *testing.T) {
	rc := &recorder{}
	srv := rc.server(t)
	p := &fakePlat{invErr: errors.New("WMI broken")}
	a := testAgent(t, p, srv)
	if err := a.Cycle(context.Background()); err == nil {
		t.Fatal("cycle without inventory must report an error (for backoff)")
	}
	if strings.Join(rc.paths, ",") != "/api/agent/heartbeat" {
		t.Fatalf("an empty inventory must never be checked in: %v", rc.paths)
	}
	p.invErr = nil
	if err := a.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Collection fails again: the last good inventory is reused.
	p.invErr = errors.New("WMI broken again")
	if err := a.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(rc.inv) != 2 || len(rc.inv[1]) != 2 || rc.inv[1][0].ID != "KB1" {
		t.Fatalf("check-ins: %+v", rc.inv)
	}
}

func TestSlowInventoryIsCached(t *testing.T) {
	rc := &recorder{}
	srv := rc.server(t)
	p := &fakePlat{}
	a := testAgent(t, slowFake{p}, srv)
	for i := 0; i < 3; i++ {
		if err := a.Cycle(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if p.invRuns != 1 {
		t.Fatalf("slow inventory collected %d times in 3 check-ins, want 1", p.invRuns)
	}
	a.invAt = time.Time{} // what an install does
	a.Cycle(context.Background())
	if p.invRuns != 2 {
		t.Fatalf("inventory not refreshed after an install: %d", p.invRuns)
	}
	// Plain platforms (sim) still collect at every check-in.
	b := testAgent(t, p, srv)
	b.Cycle(context.Background())
	b.Cycle(context.Background())
	if p.invRuns != 4 {
		t.Fatalf("uncached platform: %d", p.invRuns)
	}
}

func TestDownloadStallAborts(t *testing.T) {
	saved := downloadIdleTimeout
	downloadIdleTimeout = 200 * time.Millisecond
	defer func() { downloadIdleTimeout = saved }()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(200)
		w.Write([]byte("partial"))
		w.(http.Flusher).Flush()
		select { // then nothing: a stalled connection
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	a := testAgent(t, &fakePlat{}, srv)
	sha := strings.Repeat("a", 64)
	as := store.Assignment{URL: "/api/agent/content/" + sha}
	p := manifest.Package{File: manifest.FileRef{Name: "payload/x.msu", Size: 1000, SHA256: sha}}
	start := time.Now()
	_, err := a.download(context.Background(), as, p, nil)
	if err == nil || !strings.Contains(err.Error(), "stalled") {
		t.Fatalf("want a stall error, got %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("stall detection too slow")
	}
	if fi, err := os.Stat(filepath.Join(a.dir, "cache", sha+".msu.part")); err != nil || fi.Size() != int64(len("partial")) {
		t.Fatalf("partial download must be kept for resume: %v", err)
	}
}
