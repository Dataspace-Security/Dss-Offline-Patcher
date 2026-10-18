package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"offpatch/internal/store"
)

func TestRebootHealthDue(t *testing.T) {
	rec := time.Date(2026, 10, 18, 10, 0, 0, 0, time.UTC)
	e := rebootHealth{RecordedAt: rec}
	now := rec.Add(30 * time.Minute)
	before := rec.Add(-time.Hour)       // still the boot from before the install
	after := rec.Add(11 * time.Minute)  // restarted 10 minutes after the install
	jitter := rec.Add(10 * time.Second) // uptime-derived boot time noise
	cases := []struct {
		name          string
		now, boot     time.Time
		bootKnown     bool
		started       time.Time
		rebootPending bool
		want          rebootHealthAction
	}{
		{"not restarted yet", now, before, true, before, false, rhWait},
		{"restarted", now, after, true, after, false, rhRun},
		{"restarted but another restart pending", now, after, true, after, true, rhWait},
		{"boot time jitter is not a restart", now, jitter, true, rec.Add(-time.Hour), false, rhWait},
		{"boot time wins over agent start", now, before, true, after, false, rhWait},
		{"no boot time: agent restarted", now, time.Time{}, false, after, false, rhRun},
		{"no boot time: same agent process", now, time.Time{}, false, before, false, rhWait},
		{"too old", rec.Add(15 * 24 * time.Hour), before, true, before, false, rhDrop},
		{"too old even if restarted", rec.Add(15 * 24 * time.Hour), after, true, after, false, rhDrop},
	}
	for _, c := range cases {
		if got := rebootHealthDue(e, c.now, c.boot, c.bootKnown, c.started, c.rebootPending); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

func TestSettleLeft(t *testing.T) {
	boot := time.Date(2026, 10, 18, 10, 0, 0, 0, time.UTC)
	settle := 3 * time.Minute
	if got := settleLeft(boot.Add(time.Minute), boot, true, boot.Add(2*time.Minute), settle); got != 2*time.Minute {
		t.Errorf("1 min after boot: %s", got)
	}
	if got := settleLeft(boot.Add(10*time.Minute), boot, true, boot, settle); got != 0 {
		t.Errorf("long after boot: %s", got)
	}
	// Without a boot time the agent start stands for it.
	if got := settleLeft(boot.Add(2*time.Minute), time.Time{}, false, boot.Add(90*time.Second), settle); got != 150*time.Second {
		t.Errorf("agent start: %s", got)
	}
}

func TestRestartedDetail(t *testing.T) {
	for in, want := range map[string]string{
		"installed; reboot required":   "installed; restart completed",
		"uninstalled; reboot required": "uninstalled; restart completed",
		"simulated install":            "simulated install; restart completed",
		"":                             "installed; restart completed",
	} {
		if got := restartedDetail(in); got != want {
			t.Errorf("restartedDetail(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseProcStatBtime(t *testing.T) {
	got, err := parseProcStatBtime([]byte("cpu  1 2 3\nintr 5\nbtime 1760781600\nprocesses 9\n"))
	if err != nil || !got.Equal(time.Unix(1760781600, 0)) {
		t.Fatalf("got %v, %v", got, err)
	}
	if _, err := parseProcStatBtime([]byte("cpu 1\n")); err == nil {
		t.Error("missing btime must fail")
	}
	if _, err := parseProcStatBtime([]byte("btime x\n")); err == nil {
		t.Error("bad btime must fail")
	}
}

// bootFake is a platform with a boot time, a pending-restart flag and
// health checks that pass from a given attempt on.
type bootFake struct {
	*fakePlat
	mu        sync.Mutex
	boot      time.Time
	pending   bool
	okFrom    int // health passes from this call on (1-based); 0 = always
	healthRun int
}

func (b *bootFake) BootTime() (time.Time, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.boot, nil
}

func (b *bootFake) Inventory() ([]store.InventoryItem, bool, error) {
	inv, _, err := b.fakePlat.Inventory()
	b.mu.Lock()
	defer b.mu.Unlock()
	return inv, b.pending, err
}

func (b *bootFake) Health(context.Context, []store.HealthCheck) (bool, string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.healthRun++
	if b.okFrom == 0 || b.healthRun >= b.okFrom {
		return true, "1 check(s) passed"
	}
	return false, "service Spooler not running"
}

func (b *bootFake) set(f func(*bootFake)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	f(b)
}

type reportRecorder struct {
	mu      sync.Mutex
	paths   []string
	reports []store.Report
	status  int // answer to /api/agent/report (0 = 200)
}

func (rr *reportRecorder) server(t *testing.T) *httptest.Server {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rr.mu.Lock()
		defer rr.mu.Unlock()
		rr.paths = append(rr.paths, r.URL.Path)
		if r.URL.Path == "/api/agent/report" {
			var rep store.Report
			json.NewDecoder(r.Body).Decode(&rep)
			rr.reports = append(rr.reports, rep)
			if rr.status != 0 {
				w.WriteHeader(rr.status)
				w.Write([]byte(`{"error":"target is verified"}`))
				return
			}
		}
		w.Write([]byte(`{}`))
	}))
	t.Cleanup(s.Close)
	return s
}

func (rr *reportRecorder) snapshot() ([]string, []store.Report) {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	return append([]string(nil), rr.paths...), append([]store.Report(nil), rr.reports...)
}

func (rr *reportRecorder) reset(status int) {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	rr.paths, rr.reports, rr.status = nil, nil, status
}

func shortSettle(t *testing.T, settle, retry time.Duration) {
	s, r := postRebootSettle, postRebootRetryEvery
	postRebootSettle, postRebootRetryEvery = settle, retry
	t.Cleanup(func() { postRebootSettle, postRebootRetryEvery = s, r })
}

var spooler = []store.HealthCheck{{Type: "service_running", Name: "Spooler"}}

func TestPostRebootHealthReportedBeforeCheckin(t *testing.T) {
	shortSettle(t, time.Second, 10*time.Millisecond)
	rr := &reportRecorder{}
	srv := rr.server(t)
	p := &bootFake{fakePlat: &fakePlat{}, boot: time.Now().Add(-time.Hour), pending: true}
	a := testAgent(t, p, srv)
	as := store.Assignment{DeploymentID: "d1", PackageID: "kb1", HealthChecks: spooler}

	// Installed, restart required, health checks: remembered. Without health
	// checks, or without a restart: not remembered.
	a.afterInstall(context.Background(), as, Result{State: "pending_reboot", ExitCode: 3010, Detail: "installed; reboot required"}, 10)
	a.afterInstall(context.Background(), store.Assignment{DeploymentID: "d1", PackageID: "kb2"}, Result{State: "pending_reboot"}, 10)
	a.afterInstall(context.Background(), store.Assignment{DeploymentID: "d1", PackageID: "kb3", HealthChecks: spooler}, Result{State: "installed"}, 10)
	if l := a.loadRebootHealth(); len(l) != 1 || l[0].PackageID != "kb1" || l[0].ExitCode != 3010 {
		t.Fatalf("remembered: %+v", l)
	}

	// Restart still pending: nothing re-checked.
	rr.reset(0)
	if err := a.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, reps := rr.snapshot(); len(reps) != 0 {
		t.Fatalf("reported before the restart: %+v", reps)
	}

	// The machine restarted (new agent process, same state dir); the first
	// health run fails while services start, a retry passes.
	p.set(func(b *bootFake) { b.boot, b.pending, b.okFrom, b.healthRun = time.Now().Add(time.Minute), false, 2, 0 })
	b := testAgent(t, p, srv)
	b.dir = a.dir
	rr.reset(0)
	if err := b.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	paths, reps := rr.snapshot()
	if len(reps) != 1 {
		t.Fatalf("reports: %+v (paths %v)", reps, paths)
	}
	r := reps[0]
	if r.DeploymentID != "d1" || r.PackageID != "kb1" || r.State != "installed" || r.ExitCode != 3010 ||
		r.Detail != "installed; restart completed" || r.Health != "ok" || r.HealthDetail != "after restart: 1 check(s) passed" {
		t.Fatalf("report: %+v", r)
	}
	iReport, iCheckin := -1, -1
	for i, pth := range paths {
		switch pth {
		case "/api/agent/report":
			iReport = i
		case "/api/agent/checkin":
			iCheckin = i
		}
	}
	if iReport < 0 || iCheckin < 0 || iReport > iCheckin {
		t.Fatalf("the report must precede the check-in: %v", paths)
	}
	if _, err := os.Stat(b.rebootHealthPath()); !os.IsNotExist(err) {
		t.Fatalf("a reported entry must be forgotten: %v", err)
	}
	rr.reset(0)
	if err := b.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, reps := rr.snapshot(); len(reps) != 0 {
		t.Fatalf("reported twice: %+v", reps)
	}
}

func TestPostRebootHealthFailureAndServerAnswers(t *testing.T) {
	shortSettle(t, 50*time.Millisecond, 10*time.Millisecond)
	rr := &reportRecorder{}
	srv := rr.server(t)
	p := &bootFake{fakePlat: &fakePlat{}, boot: time.Now().Add(-time.Hour), okFrom: 1 << 30} // never healthy
	a := testAgent(t, p, srv)
	a.rememberRebootHealth(store.Assignment{DeploymentID: "d", PackageID: "p", HealthChecks: spooler},
		Result{State: "pending_reboot", ExitCode: 3010, Detail: "installed; reboot required"})
	p.set(func(b *bootFake) { b.boot = time.Now().Add(time.Minute) }) // restarted after the install

	// Server error: kept for the next cycle.
	rr.reset(http.StatusInternalServerError)
	a.postRebootHealth(context.Background(), false)
	_, reps := rr.snapshot()
	if len(reps) != 1 || reps[0].Health != "failed" || reps[0].HealthDetail != "after restart: service Spooler not running" {
		t.Fatalf("report: %+v", reps)
	}
	p.set(func(b *bootFake) {
		if b.healthRun < 2 {
			t.Errorf("a failing check is retried while the machine settles: %d run(s)", b.healthRun)
		}
	})
	if len(a.loadRebootHealth()) != 1 {
		t.Fatal("must be kept after a server error")
	}
	// 409 (already verified): nothing to retry, forgotten.
	rr.reset(http.StatusConflict)
	a.postRebootHealth(context.Background(), false)
	if len(a.loadRebootHealth()) != 0 {
		t.Fatal("must be dropped after a 4xx answer")
	}
}

func TestRememberRebootHealthReplacesAndBounds(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	a := testAgent(t, &fakePlat{}, srv)
	res := Result{State: "pending_reboot", ExitCode: 3010}
	a.rememberRebootHealth(store.Assignment{DeploymentID: "d", PackageID: "p", HealthChecks: spooler}, res)
	a.rememberRebootHealth(store.Assignment{DeploymentID: "d", PackageID: "p", HealthChecks: spooler}, Result{State: "pending_reboot", ExitCode: 1641})
	if l := a.loadRebootHealth(); len(l) != 1 || l[0].ExitCode != 1641 {
		t.Fatalf("same target: replaced, %+v", l)
	}
	for i := 0; i < maxRebootHealth+5; i++ {
		a.rememberRebootHealth(store.Assignment{DeploymentID: "d", PackageID: fmt.Sprintf("pkg%d", i), HealthChecks: spooler}, res)
	}
	if l := a.loadRebootHealth(); len(l) != maxRebootHealth || l[len(l)-1].PackageID != fmt.Sprintf("pkg%d", maxRebootHealth+4) {
		t.Fatalf("bounded to the %d newest: %d", maxRebootHealth, len(l))
	}
	// A damaged file is ignored, not fatal.
	if err := os.WriteFile(a.rebootHealthPath(), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if l := a.loadRebootHealth(); l != nil {
		t.Fatalf("damaged: %+v", l)
	}
}
