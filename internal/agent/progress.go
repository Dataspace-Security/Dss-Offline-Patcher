package agent

import (
	"context"
	"io"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"offpatch/internal/store"
)

// Live progress (docs/proposals/ux-api-contract.md, "Agent ↔ server"): while
// the agent works an assignment it adds a progress object to its heartbeats
// so the console can show Target.live. Progress is informational only: it is
// not audited, and the report() state transitions are unchanged.

// Stages, matching TargetLive.stage in web/src/types.ts.
const (
	stageDownloading   = "downloading"
	stageVerifying     = "verifying"
	stageInstalling    = "installing"
	stageWaitingReboot = "waiting_reboot"
)

// Cadences (vars for tests).
var (
	progressDownloadEvery = 5 * time.Second  // while downloading
	progressInstallEvery  = 30 * time.Second // while installing / waiting for a reboot
	heartbeatTimeout      = 5 * time.Second  // one heartbeat request
)

const (
	// minNextCheckin is the floor for the server's next_checkin_seconds hint.
	minNextCheckin = 5 * time.Second
	// maxAwaitingReboot bounds the remembered pending-reboot targets.
	maxAwaitingReboot = 64
)

// Progress is the heartbeat progress object.
type Progress struct {
	DeploymentID string `json:"deployment_id"`
	PackageID    string `json:"package_id"`
	Stage        string `json:"stage"`
	Pct          int    `json:"pct"` // 0..100 while downloading, -1 when unknown
	BytesDone    int64  `json:"bytes_done"`
	BytesTotal   int64  `json:"bytes_total"`
}

// heartbeatBody is the optional heartbeat request body; with no progress it
// encodes as {} (what old agents send).
type heartbeatBody struct {
	Progress *Progress `json:"progress,omitempty"`
}

// downloadPct: whole percent of total done, -1 if the size is unknown.
func downloadPct(done, total int64) int {
	switch {
	case total <= 0:
		return -1
	case done <= 0:
		return 0
	case done >= total:
		return 100
	}
	return int(done * 100 / total)
}

// hintJitter is the spread applied to a hinted wait (±20 %), so endpoints
// released by the same deployment do not check in in lockstep.
const hintJitter = 0.2

// jitterFrac returns a uniform value in [-1, 1) (var for tests).
var jitterFrac = func() float64 { return rand.Float64()*2 - 1 }

// nextWait is the delay before the next cycle. After failures the backoff
// applies; otherwise a positive server hint (next_checkin_seconds) shortens
// the wait to clamp(hint ± 20 %, minNextCheckin, interval).
func nextWait(interval, hint time.Duration, failures int) time.Duration {
	if failures > 0 || hint <= 0 {
		return backoffDelay(interval, failures)
	}
	j := time.Duration(float64(hint) * hintJitter * jitterFrac())
	return min(max(hint+j, minNextCheckin), interval)
}

// liveProgress is the progress of one assignment. Safe for concurrent use;
// a nil *liveProgress is a no-op.
type liveProgress struct {
	deploymentID, packageID string
	total                   int64
	done                    atomic.Int64
	mu                      sync.Mutex
	stage                   string
	kick                    chan struct{} // stage changed: send now
}

func newLive(as store.Assignment, stage string, done, total int64) *liveProgress {
	l := &liveProgress{deploymentID: as.DeploymentID, packageID: as.PackageID, total: total, stage: stage, kick: make(chan struct{}, 1)}
	l.done.Store(done)
	return l
}

func (l *liveProgress) setDone(n int64) {
	if l != nil {
		l.done.Store(n)
	}
}

func (l *liveProgress) add(n int64) {
	if l != nil {
		l.done.Add(n)
	}
}

// setStage changes the stage and requests an immediate heartbeat.
func (l *liveProgress) setStage(stage string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	changed := l.stage != stage
	l.stage = stage
	l.mu.Unlock()
	if changed {
		select {
		case l.kick <- struct{}{}:
		default:
		}
	}
}

func (l *liveProgress) snapshot() Progress {
	l.mu.Lock()
	stage := l.stage
	l.mu.Unlock()
	done := min(l.done.Load(), max(l.total, 0))
	pct := -1
	if stage == stageDownloading {
		pct = downloadPct(done, l.total)
	}
	return Progress{DeploymentID: l.deploymentID, PackageID: l.packageID, Stage: stage, Pct: pct, BytesDone: max(done, 0), BytesTotal: max(l.total, 0)}
}

// cadence is how often the current stage is re-sent (0 = only on change).
func (l *liveProgress) cadence() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	switch l.stage {
	case stageDownloading:
		return progressDownloadEvery
	case stageInstalling, stageWaitingReboot:
		return progressInstallEvery
	}
	return 0
}

// countingWriter counts written bytes into a liveProgress; the heartbeat
// goroutine reads the counter, so the download itself never waits.
type countingWriter struct {
	w  io.Writer
	lp *liveProgress
}

func (c countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.lp.add(int64(n))
	return n, err
}

// heartbeat sends one heartbeat (with optional progress), bounded by
// heartbeatTimeout.
func (a *Agent) heartbeat(ctx context.Context, p *Progress) error {
	ctx, cancel := context.WithTimeout(ctx, heartbeatTimeout)
	defer cancel()
	return a.do(ctx, "POST", "/api/agent/heartbeat", heartbeatBody{Progress: p}, nil)
}

// keepAliveEvery: heartbeats while busy are at most a minute apart, whatever
// the check-in interval, so the server's offline threshold is never reached.
func keepAliveEvery(interval time.Duration) time.Duration {
	if interval <= 0 || interval > time.Minute {
		return time.Minute
	}
	return interval
}

// keepAlive sends heartbeats until the returned stop function is called.
// Installers (a Windows cumulative update takes 10+ minutes) and slow
// downloads block the cycle; without this the server would show the
// endpoint as offline while it is busy. With lp, each heartbeat carries the
// current progress: one immediately, one on every stage change, and then at
// the stage's cadence. stop waits for an in-flight heartbeat (bounded by
// heartbeatTimeout) so progress never arrives after the following report.
func (a *Agent) keepAlive(ctx context.Context, lp *liveProgress) (stop func()) {
	quit := make(chan struct{})
	done := make(chan struct{})
	lastStage := ""
	// send posts one heartbeat; onChange sends are skipped when the stage
	// already went out (the change raced with the previous snapshot).
	send := func(onChange bool) {
		var p *Progress
		if lp != nil {
			s := lp.snapshot()
			if onChange && s.Stage == lastStage {
				return
			}
			lastStage = s.Stage
			p = &s
		}
		if err := a.heartbeat(ctx, p); err != nil && ctx.Err() == nil {
			if p != nil {
				a.log.Debug("progress heartbeat failed", "stage", p.Stage, "err", err)
			} else {
				a.log.Warn("heartbeat failed", "err", err)
			}
		}
	}
	go func() {
		defer close(done)
		var kick chan struct{}
		if lp != nil {
			kick = lp.kick
			send(false)
		}
		keep := keepAliveEvery(a.interval)
		for {
			wait := keep
			if lp != nil {
				if c := lp.cadence(); c > 0 && c < wait {
					wait = c
				}
			}
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-quit:
				t.Stop()
				select { // a stage change not sent yet (e.g. verifying) still goes out
				case <-kick:
					send(true)
				default:
				}
				return
			case <-kick:
				t.Stop()
				send(true)
				continue
			case <-t.C:
			}
			send(false)
		}
	}()
	return func() { close(quit); <-done }
}

// rememberReboot records a target that installed but waits for a reboot,
// so its waiting_reboot progress is re-sent while the reboot is pending.
func (a *Agent) rememberReboot(as store.Assignment, size int64) {
	if a.awaitingReboot == nil {
		a.awaitingReboot = map[string]Progress{}
	}
	key := rebootKey(as)
	if _, ok := a.awaitingReboot[key]; !ok && len(a.awaitingReboot) >= maxAwaitingReboot {
		return
	}
	a.awaitingReboot[key] = Progress{DeploymentID: as.DeploymentID, PackageID: as.PackageID, Stage: stageWaitingReboot, Pct: -1, BytesDone: size, BytesTotal: size}
}

func rebootKey(as store.Assignment) string { return as.DeploymentID + "/" + as.PackageID }

// reportAwaitingReboot runs once per cycle: while the platform reports a
// pending reboot it re-sends waiting_reboot progress; once the reboot has
// happened it forgets the targets.
func (a *Agent) reportAwaitingReboot(ctx context.Context, rebootPending bool) {
	if !rebootPending {
		clear(a.awaitingReboot)
		return
	}
	for _, p := range a.awaitingReboot {
		if ctx.Err() != nil {
			return
		}
		if err := a.heartbeat(ctx, &p); err != nil {
			a.log.Debug("waiting_reboot heartbeat failed", "deployment", p.DeploymentID, "package", p.PackageID, "err", err)
		}
	}
}
