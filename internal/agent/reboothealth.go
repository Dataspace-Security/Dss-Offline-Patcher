package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"offpatch/internal/store"
)

// Post-restart health: an install that needs a restart is health-checked
// right away (finish), but the new version only runs after the restart. The
// agent therefore remembers such targets on disk (the restart ends the
// process) and, once the machine has restarted and no restart is pending,
// runs the checks again and reports the target "installed" with the new
// health result. That report goes out before the first check-in after the
// restart: the check-in verifies the target, and the server accepts no
// report for a verified target.

const (
	rebootHealthFile = "reboot-health.json"
	// maxRebootHealth bounds the file (one entry per deployment/package).
	maxRebootHealth = 32
	// rebootHealthMaxAge: a restart that never happens (policy never allows
	// it) eventually stops being waited for.
	rebootHealthMaxAge = 14 * 24 * time.Hour
	// bootMargin absorbs the jitter of a boot time computed from an uptime
	// counter and the wall clock.
	bootMargin = 30 * time.Second
)

var (
	// postRebootSettle: services set to delayed auto-start come up about two
	// minutes after boot; a failing check is retried until the machine has
	// been up this long. Vars for tests.
	postRebootSettle     = 3 * time.Minute
	postRebootRetryEvery = 20 * time.Second
)

// rebootHealth is one target waiting for its post-restart health check.
type rebootHealth struct {
	DeploymentID string              `json:"deployment_id"`
	PackageID    string              `json:"package_id"`
	Checks       []store.HealthCheck `json:"checks"`
	ExitCode     int                 `json:"exit_code"`
	Detail       string              `json:"detail"`
	RecordedAt   time.Time           `json:"recorded_at"`
}

// bootTimer is implemented by platforms that know when the OS started.
type bootTimer interface {
	BootTime() (time.Time, error)
}

type rebootHealthAction int

const (
	rhWait rebootHealthAction = iota // restart not done yet
	rhRun                            // restart done: check and report now
	rhDrop                           // too old: forget it
)

// rebootHealthDue decides what to do with one entry. boot is the OS start
// time when known (bootKnown); otherwise an agent process started after the
// entry was recorded stands for the restart (the service starts at boot).
func rebootHealthDue(e rebootHealth, now, boot time.Time, bootKnown bool, agentStarted time.Time, rebootPending bool) rebootHealthAction {
	if now.Sub(e.RecordedAt) > rebootHealthMaxAge {
		return rhDrop
	}
	restarted := agentStarted.After(e.RecordedAt)
	if bootKnown {
		restarted = boot.After(e.RecordedAt.Add(bootMargin))
	}
	if !restarted || rebootPending {
		return rhWait // another restart is still needed: check after that one
	}
	return rhRun
}

// settleLeft is how long a failing check may still be retried: until the
// machine (or, without a boot time, the agent) has run postRebootSettle.
func settleLeft(now, boot time.Time, bootKnown bool, agentStarted time.Time, settle time.Duration) time.Duration {
	ref := agentStarted
	if bootKnown {
		ref = boot
	}
	return min(max(settle-now.Sub(ref), 0), settle) // a boot time ahead of the clock cannot extend it
}

// restartedDetail turns the install-time detail ("installed; reboot
// required") into the post-restart one.
func restartedDetail(d string) string {
	d = strings.TrimSpace(strings.TrimSuffix(d, "; reboot required"))
	if d == "" {
		d = "installed"
	}
	return d + "; restart completed"
}

// parseProcStatBtime reads "btime <unix seconds>" from /proc/stat.
func parseProcStatBtime(b []byte) (time.Time, error) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "btime "); ok {
			s, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil {
				return time.Time{}, fmt.Errorf("btime: %w", err)
			}
			return time.Unix(s, 0), nil
		}
	}
	return time.Time{}, errors.New("no btime in /proc/stat")
}

func (a *Agent) rebootHealthPath() string { return filepath.Join(a.dir, rebootHealthFile) }

func (a *Agent) loadRebootHealth() []rebootHealth {
	b, err := os.ReadFile(a.rebootHealthPath())
	if err != nil {
		return nil
	}
	var l []rebootHealth
	if err := json.Unmarshal(b, &l); err != nil {
		a.log.Warn("ignoring unreadable post-restart health list", "err", err)
		return nil
	}
	return l
}

func (a *Agent) saveRebootHealth(l []rebootHealth) {
	if len(l) == 0 {
		if err := os.Remove(a.rebootHealthPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
			a.log.Warn("could not clear the post-restart health list", "err", err)
		}
		return
	}
	b, err := json.Marshal(l)
	if err == nil {
		err = writeFileAtomic(a.rebootHealthPath(), b, 0o600)
	}
	if err != nil {
		a.log.Warn("could not save the post-restart health list", "err", err)
	}
}

// rememberRebootHealth records a target that installed, waits for a restart
// and has health checks to run after it.
func (a *Agent) rememberRebootHealth(as store.Assignment, res Result) {
	if res.State != "pending_reboot" || len(as.HealthChecks) == 0 {
		return
	}
	e := rebootHealth{DeploymentID: as.DeploymentID, PackageID: as.PackageID, Checks: as.HealthChecks,
		ExitCode: res.ExitCode, Detail: res.Detail, RecordedAt: time.Now()}
	l := a.loadRebootHealth()
	out := make([]rebootHealth, 0, len(l)+1)
	for _, x := range l {
		if x.DeploymentID != e.DeploymentID || x.PackageID != e.PackageID {
			out = append(out, x)
		}
	}
	out = append(out, e)
	if len(out) > maxRebootHealth {
		out = out[len(out)-maxRebootHealth:]
	}
	a.saveRebootHealth(out)
}

func (a *Agent) bootTime() (time.Time, bool) {
	bt, ok := a.plat.(bootTimer)
	if !ok {
		return time.Time{}, false
	}
	t, err := bt.BootTime()
	if err != nil {
		a.log.Debug("boot time unknown", "err", err)
		return time.Time{}, false
	}
	return t, true
}

// postRebootHealth runs once per cycle, before the check-in.
func (a *Agent) postRebootHealth(ctx context.Context, rebootPending bool) {
	l := a.loadRebootHealth()
	if len(l) == 0 {
		return
	}
	boot, bootKnown := a.bootTime()
	keep := make([]rebootHealth, 0, len(l))
	changed := false
	for i, e := range l {
		if ctx.Err() != nil {
			keep = append(keep, l[i:]...)
			break
		}
		switch rebootHealthDue(e, time.Now(), boot, bootKnown, a.started, rebootPending) {
		case rhWait:
			keep = append(keep, e)
			continue
		case rhDrop:
			a.log.Info("no restart after the install for two weeks; post-restart health check dropped", "deployment", e.DeploymentID, "package", e.PackageID)
			changed = true
			continue
		}
		if !a.reportRebootHealth(ctx, e, boot, bootKnown) {
			keep = append(keep, e) // server unreachable: try again next cycle
			continue
		}
		changed = true
	}
	if changed {
		a.saveRebootHealth(keep)
	}
}

// reportRebootHealth checks one target and reports it; false means "keep it
// and try again" (the server could not be reached).
func (a *Agent) reportRebootHealth(ctx context.Context, e rebootHealth, boot time.Time, bootKnown bool) bool {
	log := a.log.With("deployment", e.DeploymentID, "package", e.PackageID)
	ok, detail := a.plat.Health(ctx, e.Checks)
	if left := settleLeft(time.Now(), boot, bootKnown, a.started, postRebootSettle); !ok && left > 0 {
		// Just booted: stay visible while services finish starting.
		if err := a.heartbeat(ctx, nil); err != nil {
			log.Debug("heartbeat before the post-restart health check failed", "err", err)
		}
		deadline := time.Now().Add(left)
		for !ok {
			left := time.Until(deadline)
			if left <= 0 {
				break
			}
			t := time.NewTimer(min(postRebootRetryEvery, left))
			select {
			case <-ctx.Done():
				t.Stop()
				return false
			case <-t.C:
			}
			ok, detail = a.plat.Health(ctx, e.Checks)
		}
	}
	health := map[bool]string{true: "ok", false: "failed"}[ok]
	if !ok {
		log.Warn("post-restart health check failed", "detail", detail)
	}
	rctx, cancel := context.WithTimeout(ctx, reportTimeout)
	defer cancel()
	err := a.do(rctx, "POST", "/api/agent/report", store.Report{DeploymentID: e.DeploymentID, PackageID: e.PackageID, State: "installed",
		ExitCode: e.ExitCode, Detail: restartedDetail(e.Detail), Health: health, HealthDetail: "after restart: " + detail}, nil)
	var se *serverError
	switch {
	case err == nil:
		log.Info("post-restart health reported", "health", health)
		return true
	case errors.As(err, &se) && se.Code/100 == 4:
		// Typically 409: the target was already verified (or cancelled). The
		// server records no health for a final target; nothing to retry.
		log.Info("post-restart health not recorded by the server", "err", err)
		return true
	default:
		log.Warn("post-restart health report failed; will retry", "err", err)
		return false
	}
}
