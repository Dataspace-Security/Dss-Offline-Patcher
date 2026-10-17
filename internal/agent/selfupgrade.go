package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

// ErrRestart tells the caller the agent replaced its own binary and must
// exit so the service manager (Windows SCM recovery / systemd / launchd)
// starts the new version.
var ErrRestart = errors.New("agent upgraded; restart required")

// versioned is implemented by platforms that report their own agent
// version (the simulator, which has no real binary to swap).
type versioned interface {
	AgentVersion() string
	SelfUpgrade(p manifest.Package) Result
}

func (a *Agent) agentVersion() string {
	if v, ok := a.plat.(versioned); ok {
		if s := v.AgentVersion(); s != "" {
			return s
		}
	}
	return Version
}

const (
	upgradeMarkerName = "upgrade.json"
	// maxUpgradeStarts: the new binary may be started this many times without
	// becoming healthy before the previous binary is restored.
	maxUpgradeStarts = 3
	// upgradeHealthyAfter: running this long (or one successful check-in)
	// proves the new binary works.
	upgradeHealthyAfter = 10 * time.Minute
)

// upgradeMarker records a binary swap across the restart. State "pending":
// the swap is done and the new binary has not proven itself yet. "failed":
// the upgrade to To was abandoned; it is reported once and not retried.
type upgradeMarker struct {
	From         string `json:"from"`
	To           string `json:"to"`
	DeploymentID string `json:"deployment_id"`
	PackageID    string `json:"package_id"`
	SHA256       string `json:"sha256"`
	State        string `json:"state"` // pending | failed
	Starts       int    `json:"starts"`
	Reason       string `json:"reason,omitempty"`
	Reported     bool   `json:"reported,omitempty"`
}

func loadMarker(dir string) *upgradeMarker {
	b, err := os.ReadFile(filepath.Join(dir, upgradeMarkerName))
	if err != nil {
		return nil
	}
	var m upgradeMarker
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	return &m
}

func saveMarker(dir string, m upgradeMarker) error {
	b, _ := json.MarshalIndent(m, "", "  ")
	return writeFileAtomic(filepath.Join(dir, upgradeMarkerName), b, 0o600)
}

func clearMarker(dir string) { os.Remove(filepath.Join(dir, upgradeMarkerName)) }

type upgradeAction int

const (
	upgradeNone     upgradeAction = iota
	upgradeCount                  // new binary starting: count the start
	upgradeRollback               // new binary keeps failing: restore the old one
	upgradeFailed                 // not running the version we swapped in
)

// decideUpgrade is what to do at startup given the marker and the version
// of the running binary.
func decideUpgrade(m *upgradeMarker, running string, maxStarts int) upgradeAction {
	if m == nil || m.State != "pending" {
		return upgradeNone
	}
	if running != m.To {
		return upgradeFailed
	}
	if m.Starts >= maxStarts {
		return upgradeRollback
	}
	return upgradeCount
}

// checkUpgrade runs once at startup. It returns ErrRestart after restoring
// the previous binary.
func (a *Agent) checkUpgrade() error {
	if _, ok := a.plat.(versioned); ok {
		return nil
	}
	m := loadMarker(a.dir)
	switch decideUpgrade(m, Version, maxUpgradeStarts) {
	case upgradeCount:
		n := *m
		n.Starts++
		a.log.Info("upgraded agent starting", "from", m.From, "to", m.To, "start", n.Starts)
		return saveMarker(a.dir, n)
	case upgradeFailed:
		n := *m
		n.State, n.Reason = "failed", fmt.Sprintf("agent restarted as version %s instead of %s (binary not stamped with the package version, or restored by hand)", Version, m.To)
		a.log.Error("self-upgrade failed", "reason", n.Reason)
		return saveMarker(a.dir, n)
	case upgradeRollback:
		n := *m
		n.State = "failed"
		exe, err := os.Executable()
		if err == nil {
			err = restoreOld(exe)
		}
		if err != nil {
			n.Reason = fmt.Sprintf("agent %s did not become healthy after %d starts and the previous binary could not be restored: %v", m.To, m.Starts, err)
			a.log.Error("self-upgrade rollback failed", "err", err)
			return saveMarker(a.dir, n)
		}
		n.Reason = fmt.Sprintf("agent %s did not become healthy after %d starts; restored %s", m.To, m.Starts, m.From)
		a.log.Error("self-upgrade rolled back", "reason", n.Reason)
		if err := saveMarker(a.dir, n); err != nil {
			return err
		}
		return ErrRestart
	}
	return nil
}

// upgradeHealthy is called after a successful check-in (or once the agent has
// run long enough): the new binary works, the marker goes. A failed marker
// is reported to the server once.
func (a *Agent) upgradeHealthy(ctx context.Context, checkedIn bool) {
	m := loadMarker(a.dir)
	if m == nil {
		return
	}
	switch {
	case m.State == "pending" && m.To == Version:
		a.log.Info("agent upgrade confirmed healthy", "version", Version)
		clearMarker(a.dir)
	case m.State == "failed" && !m.Reported && checkedIn:
		as := store.Assignment{DeploymentID: m.DeploymentID, PackageID: m.PackageID}
		if err := a.do(ctx, "POST", "/api/agent/report", store.Report{DeploymentID: as.DeploymentID, PackageID: as.PackageID, State: "failed", ExitCode: -1, Detail: m.Reason}, nil); err != nil {
			a.log.Warn("report of failed upgrade not delivered; will retry", "err", err)
			return
		}
		n := *m
		n.Reported = true
		saveMarker(a.dir, n)
	}
}

// upgradeBlocked reports whether an upgrade to this exact binary was already
// abandoned on this endpoint (it is not retried: the same binary would fail
// again, or restart-loop).
func (a *Agent) upgradeBlocked(version, sha string) (string, bool) {
	m := loadMarker(a.dir)
	if m == nil || m.State != "failed" || m.To != version || m.SHA256 != sha {
		return "", false
	}
	return m.Reason, true
}

// selfUpgrade swaps the running binary for the verified new one: stage it
// as <exe>.new (fsynced), check it runs and reports the package version,
// record the pending upgrade, then swap. The old binary stays as <exe>.old
// and is restored automatically if the new one does not stay up.
func (a *Agent) selfUpgrade(ctx context.Context, deploymentID string, p manifest.Package, file string) Result {
	if v, ok := a.plat.(versioned); ok {
		return v.SelfUpgrade(p)
	}
	exe, err := os.Executable()
	if err != nil {
		return Result{State: "failed", ExitCode: -1, Detail: "locate own binary: " + err.Error()}
	}
	staged := exe + ".new"
	os.Remove(staged)
	if err := copyFileSync(file, staged, 0o755); err != nil {
		return Result{State: "failed", ExitCode: -1, Detail: "stage new binary: " + err.Error()}
	}
	if err := verifyBinary(ctx, staged, p.Version); err != nil {
		os.Remove(staged)
		return Result{State: "failed", ExitCode: -1, Detail: err.Error()}
	}
	m := upgradeMarker{From: Version, To: p.Version, DeploymentID: deploymentID, PackageID: p.PackageID, SHA256: p.File.SHA256, State: "pending"}
	if err := saveMarker(a.dir, m); err != nil {
		os.Remove(staged)
		return Result{State: "failed", ExitCode: -1, Detail: "record pending upgrade: " + err.Error()}
	}
	if err := swapBinary(exe, staged); err != nil {
		clearMarker(a.dir)
		os.Remove(staged)
		return Result{State: "failed", ExitCode: -1, Detail: err.Error()}
	}
	a.restart = true
	return Result{State: "installed", Detail: fmt.Sprintf("agent %s → %s staged; restarting (%s)", Version, p.Version, runtime.GOOS)}
}

// verifyBinary runs `<bin> version` and requires it to print want. This
// catches a binary for the wrong OS/arch and one built without the version
// stamp, which would otherwise be re-installed at every check-in.
func verifyBinary(ctx context.Context, bin, want string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "version").Output()
	if err != nil {
		return fmt.Errorf("new binary does not run (`version`): %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != want {
		return fmt.Errorf("new binary reports version %q, package is %q: it was not built with -X offpatch/internal/agent.Version=%s; not installing", got, want, want)
	}
	return nil
}

// swapBinary moves exe to exe.old and staged into exe. Renaming a running
// executable is allowed on Windows and POSIX.
func swapBinary(exe, staged string) error {
	old := exe + ".old"
	os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		return fmt.Errorf("move current binary aside: %w", err)
	}
	if err := os.Rename(staged, exe); err != nil {
		os.Rename(old, exe) // put the working binary back
		return fmt.Errorf("install new binary: %w", err)
	}
	syncDir(filepath.Dir(exe))
	return nil
}

// restoreOld puts <exe>.old back; the failing binary is kept as <exe>.failed.
func restoreOld(exe string) error {
	old, bad := exe+".old", exe+".failed"
	if _, err := os.Stat(old); err != nil {
		return fmt.Errorf("no previous binary: %w", err)
	}
	os.Remove(bad)
	if err := os.Rename(exe, bad); err != nil {
		return fmt.Errorf("move failing binary aside: %w", err)
	}
	if err := os.Rename(old, exe); err != nil {
		os.Rename(bad, exe)
		return fmt.Errorf("restore previous binary: %w", err)
	}
	syncDir(filepath.Dir(exe))
	return nil
}
