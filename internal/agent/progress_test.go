package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

// noJitter pins the hint jitter to 0 for the test.
func noJitter(t *testing.T) {
	t.Helper()
	old := jitterFrac
	jitterFrac = func() float64 { return 0 }
	t.Cleanup(func() { jitterFrac = old })
}

func TestNextWaitJitter(t *testing.T) {
	old := jitterFrac
	t.Cleanup(func() { jitterFrac = old })
	s, m := time.Second, time.Minute
	for _, c := range []struct {
		frac float64
		want time.Duration
	}{{-1, 8 * s}, {1, 12 * s}, {0.5, 11 * s}} {
		jitterFrac = func() float64 { return c.frac }
		if got := nextWait(m, 10*s, 0); got != c.want {
			t.Errorf("frac %v: %s, want %s", c.frac, got, c.want)
		}
	}
	jitterFrac = func() float64 { return 1 }
	if got := nextWait(11*s, 10*s, 0); got != 11*s {
		t.Errorf("jitter must not exceed the interval: %s", got)
	}
	jitterFrac = func() float64 { return -1 }
	if got := nextWait(m, 5*s, 0); got != minNextCheckin {
		t.Errorf("jitter must not go below the floor: %s", got)
	}
	jitterFrac = old
	lo, hi := time.Duration(float64(10*s)*0.8), time.Duration(float64(10*s)*1.2)
	for range 200 {
		if got := nextWait(m, 10*s, 0); got < lo || got > hi {
			t.Fatalf("random jitter out of ±20%%: %s", got)
		}
	}
}

func TestNextWait(t *testing.T) {
	noJitter(t)
	s, m := time.Second, time.Minute
	cases := []struct {
		name     string
		interval time.Duration
		hint     time.Duration
		failures int
		want     time.Duration
	}{
		{"no hint uses interval", m, 0, 0, m},
		{"hint shortens", m, 10 * s, 0, 10 * s},
		{"hint floored at 5s", m, 1 * s, 0, 5 * s},
		{"hint capped at interval", m, 10 * m, 0, m},
		{"interval below floor wins", 2 * s, 10 * s, 0, 2 * s},
		{"failures back off, hint ignored", m, 10 * s, 1, 2 * m},
		{"failures capped", m, 10 * s, 50, maxBackoff},
		{"negative hint ignored", m, -5 * s, 0, m},
	}
	for _, c := range cases {
		if got := nextWait(c.interval, c.hint, c.failures); got != c.want {
			t.Errorf("%s: nextWait(%s, %s, %d) = %s, want %s", c.name, c.interval, c.hint, c.failures, got, c.want)
		}
	}
}

func TestDownloadPct(t *testing.T) {
	cases := []struct {
		done, total int64
		want        int
	}{
		{0, 0, -1}, {5, 0, -1}, {5, -1, -1},
		{0, 100, 0}, {-3, 100, 0}, {1, 100, 1}, {999, 1000, 99}, {50, 100, 50},
		{100, 100, 100}, {150, 100, 100},
		{1 << 40, 1 << 41, 50}, // no overflow on large files
	}
	for _, c := range cases {
		if got := downloadPct(c.done, c.total); got != c.want {
			t.Errorf("downloadPct(%d, %d) = %d, want %d", c.done, c.total, got, c.want)
		}
	}
}

func TestSnapshotPerStage(t *testing.T) {
	as := store.Assignment{DeploymentID: "d1", PackageID: "p1"}
	lp := newLive(as, stageDownloading, 25, 100)
	if p := lp.snapshot(); p.Pct != 25 || p.BytesDone != 25 || p.BytesTotal != 100 || p.Stage != stageDownloading || p.DeploymentID != "d1" || p.PackageID != "p1" {
		t.Fatalf("downloading: %+v", p)
	}
	lp.add(500) // more than total (server sent extra): clamped
	if p := lp.snapshot(); p.Pct != 100 || p.BytesDone != 100 {
		t.Fatalf("clamped: %+v", p)
	}
	lp.setStage(stageVerifying)
	if p := lp.snapshot(); p.Pct != -1 || p.Stage != stageVerifying {
		t.Fatalf("verifying: %+v", p)
	}
	if p := newLive(as, stageInstalling, 0, 0).snapshot(); p.Pct != -1 || p.BytesTotal != 0 {
		t.Fatalf("installing: %+v", p)
	}
	var nilLP *liveProgress // nil is a no-op
	nilLP.add(1)
	nilLP.setDone(1)
	nilLP.setStage(stageVerifying)
}

func TestHeartbeatBodyCompat(t *testing.T) {
	b, _ := json.Marshal(heartbeatBody{})
	if string(b) != "{}" {
		t.Fatalf("heartbeat without progress must stay {} (old servers): %s", b)
	}
	b, _ = json.Marshal(heartbeatBody{Progress: &Progress{DeploymentID: "d", PackageID: "p", Stage: "downloading", Pct: 3, BytesDone: 3, BytesTotal: 100}})
	want := `{"progress":{"deployment_id":"d","package_id":"p","stage":"downloading","pct":3,"bytes_done":3,"bytes_total":100}}`
	if string(b) != want {
		t.Fatalf("got %s\nwant %s", b, want)
	}
}

// hbRecorder records heartbeat progress objects.
type hbRecorder struct {
	mu   sync.Mutex
	hbs  []*Progress
	at   []time.Time
	gate chan struct{} // optional: blocks /content until closed
}

func (h *hbRecorder) handle(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/api/agent/heartbeat" {
		return false
	}
	var body heartbeatBody
	json.NewDecoder(r.Body).Decode(&body)
	h.mu.Lock()
	h.hbs = append(h.hbs, body.Progress)
	h.at = append(h.at, time.Now())
	h.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
	return true
}

func (h *hbRecorder) stages() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for _, p := range h.hbs {
		if p == nil {
			out = append(out, "-")
		} else {
			out = append(out, p.Stage)
		}
	}
	return out
}

func shortCadence(t *testing.T, dl, inst time.Duration) {
	sd, si := progressDownloadEvery, progressInstallEvery
	progressDownloadEvery, progressInstallEvery = dl, inst
	t.Cleanup(func() { progressDownloadEvery, progressInstallEvery = sd, si })
}

func TestKeepAliveCadence(t *testing.T) {
	// Real timers: bounds are generous so a loaded CI host doesn't flake.
	shortCadence(t, 40*time.Millisecond, 150*time.Millisecond)
	h := &hbRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.handle(w, r) }))
	defer srv.Close()
	a := testAgent(t, &fakePlat{}, srv)
	as := store.Assignment{DeploymentID: "d", PackageID: "p"}

	// Downloading: immediate + roughly every 40 ms.
	lp := newLive(as, stageDownloading, 0, 1000)
	stop := a.keepAlive(context.Background(), lp)
	time.Sleep(300 * time.Millisecond)
	lp.setDone(400)
	// Wait for a heartbeat carrying the new progress (at most ~2 s).
	var last Progress
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		h.mu.Lock()
		if len(h.hbs) > 0 && h.hbs[len(h.hbs)-1] != nil {
			last = *h.hbs[len(h.hbs)-1]
		}
		h.mu.Unlock()
		if last.BytesDone == 400 {
			break
		}
	}
	stop()
	if n := len(h.stages()); n < 3 {
		t.Fatalf("downloading heartbeats in ~300ms at 40ms cadence: %d", n)
	}
	if last.Pct != 40 || last.BytesDone != 400 || last.BytesTotal != 1000 {
		t.Fatalf("last download progress: %+v", last)
	}

	// Installing: slower cadence.
	h.mu.Lock()
	h.hbs = nil
	h.mu.Unlock()
	stop = a.keepAlive(context.Background(), newLive(as, stageInstalling, 0, 0))
	time.Sleep(500 * time.Millisecond)
	stop()
	// Immediate + every 150 ms: at least 2; far fewer than the download cadence would give.
	if n := len(h.stages()); n < 2 || n > 8 {
		t.Fatalf("installing heartbeats in ~500ms at 150ms cadence: %d", n)
	}
	h.mu.Lock()
	for _, p := range h.hbs {
		if p == nil || p.Stage != stageInstalling || p.Pct != -1 {
			t.Fatalf("installing heartbeat: %+v", p)
		}
	}
	h.mu.Unlock()

	// Without progress: plain keep-alive at the interval, nothing at start.
	h.mu.Lock()
	h.hbs = nil
	h.mu.Unlock()
	a.interval = 20 * time.Millisecond
	stop = a.keepAlive(context.Background(), nil)
	time.Sleep(200 * time.Millisecond)
	stop()
	for _, s := range h.stages() {
		if s != "-" {
			t.Fatalf("plain keep-alive carried progress: %v", h.stages())
		}
	}
	if n := len(h.stages()); n < 2 {
		t.Fatalf("plain keep-alive heartbeats: %d", n)
	}
}

func TestStageChangeSentBeforeStop(t *testing.T) {
	shortCadence(t, time.Hour, time.Hour)
	h := &hbRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.handle(w, r) }))
	defer srv.Close()
	a := testAgent(t, &fakePlat{}, srv)
	lp := newLive(store.Assignment{DeploymentID: "d", PackageID: "p"}, stageDownloading, 0, 10)
	stop := a.keepAlive(context.Background(), lp)
	lp.setStage(stageVerifying)
	stop() // immediately: verifying must still go out exactly once
	// The first heartbeat may already see verifying (the change raced with
	// it); either way verifying goes out exactly once, last.
	got := h.stages()
	ok := (len(got) == 2 && got[0] == stageDownloading && got[1] == stageVerifying) || (len(got) == 1 && got[0] == stageVerifying)
	if !ok {
		t.Fatalf("stages: %v", got)
	}
}

func TestHeartbeatFailureDoesNotBlock(t *testing.T) {
	saved := heartbeatTimeout
	heartbeatTimeout = 50 * time.Millisecond
	defer func() { heartbeatTimeout = saved }()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select { // a hung server
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	a := testAgent(t, &fakePlat{}, srv)
	lp := newLive(store.Assignment{DeploymentID: "d", PackageID: "p"}, stageDownloading, 0, 10)
	start := time.Now()
	stop := a.keepAlive(context.Background(), lp)
	lp.add(10) // the download path never waits on the heartbeat
	if time.Since(start) > 20*time.Millisecond {
		t.Fatal("progress updates blocked")
	}
	stop()
	if time.Since(start) > time.Second {
		t.Fatal("stop must be bounded by heartbeatTimeout")
	}
}

// TestDownloadEmitsProgress: a real download sends downloading heartbeats
// with byte counts, then verifying, and the file is intact.
func TestDownloadEmitsProgress(t *testing.T) {
	shortCadence(t, 15*time.Millisecond, time.Hour)
	data := bytes.Repeat([]byte("0123456789"), 4000) // 40 KB
	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])
	h := &hbRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.handle(w, r) {
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.WriteHeader(http.StatusOK)
		for i := 0; i < len(data); i += 4000 { // slow trickle: ~100 ms total
			w.Write(data[i : i+4000])
			w.(http.Flusher).Flush()
			time.Sleep(10 * time.Millisecond)
		}
	}))
	defer srv.Close()
	a := testAgent(t, &fakePlat{}, srv)
	as := store.Assignment{DeploymentID: "d", PackageID: "p", URL: "/api/agent/content/" + sha}
	p := manifest.Package{File: manifest.FileRef{Name: "payload/x.msu", Size: int64(len(data)), SHA256: sha}}
	lp := newLive(as, stageDownloading, 0, p.File.Size)
	stop := a.keepAlive(context.Background(), lp)
	file, err := a.download(context.Background(), as, p, lp)
	stop()
	if err != nil {
		t.Fatal(err)
	}
	if n, hh, _ := manifest.HashFile(file); n != p.File.Size || hh != sha {
		t.Fatal("downloaded file corrupted by the counting writer")
	}
	got := h.stages()
	if len(got) < 3 || got[0] != stageDownloading || got[len(got)-1] != stageVerifying {
		t.Fatalf("stages: %v", got)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	prev := -2
	mid := false
	for _, hb := range h.hbs {
		if hb.Stage != stageDownloading {
			continue
		}
		if hb.Pct < prev {
			t.Fatalf("pct went backwards: %d after %d", hb.Pct, prev)
		}
		prev = hb.Pct
		if hb.Pct > 0 && hb.Pct < 100 {
			mid = true
		}
	}
	if !mid {
		t.Fatalf("no intermediate download progress seen: %+v", h.hbs)
	}
}

func TestNextCheckinHintAndWaitingReboot(t *testing.T) {
	noJitter(t)
	h := &hbRecorder{}
	var mu sync.Mutex
	hint := 10
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.handle(w, r) {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		// A newer server with fields this agent does not know.
		io.WriteString(w, `{"assignments":[],"next_checkin_seconds":`+strconv.Itoa(hint)+`,"some_future_field":{"x":1}}`)
	}))
	defer srv.Close()
	p := &fakePlat{}
	a := testAgent(t, p, srv)
	if err := a.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.nextHint != 10*time.Second || nextWait(a.interval, a.nextHint, a.failures) != 10*time.Second {
		t.Fatalf("hint not honoured: %s", a.nextHint)
	}
	mu.Lock()
	hint = 0
	mu.Unlock()
	if err := a.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.nextHint != 0 {
		t.Fatalf("hint must reset when the server stops sending it: %s", a.nextHint)
	}

	// waiting_reboot: sent right after the install, then once per cycle
	// while the reboot is pending, and forgotten after it.
	as := store.Assignment{DeploymentID: "d", PackageID: "p"}
	a.afterInstall(context.Background(), as, Result{State: "pending_reboot"}, 42)
	a.afterInstall(context.Background(), store.Assignment{DeploymentID: "d", PackageID: "q"}, Result{State: "installed"}, 1)
	a.reportAwaitingReboot(context.Background(), true)
	a.reportAwaitingReboot(context.Background(), false)
	a.reportAwaitingReboot(context.Background(), true) // forgotten: nothing sent
	got := h.stages()
	if len(got) != 2 || got[0] != stageWaitingReboot || got[1] != stageWaitingReboot {
		t.Fatalf("waiting_reboot heartbeats: %v", got)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if hb := h.hbs[0]; hb.PackageID != "p" || hb.Pct != -1 || hb.BytesTotal != 42 {
		t.Fatalf("waiting_reboot progress: %+v", hb)
	}
}
