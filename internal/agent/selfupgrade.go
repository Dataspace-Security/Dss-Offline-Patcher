package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"offpatch/internal/manifest"
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

// selfUpgrade swaps the running binary for the verified new one. The old
// binary is kept as <exe>.old for manual rollback.
func (a *Agent) selfUpgrade(ctx context.Context, p manifest.Package, file string) Result {
	if v, ok := a.plat.(versioned); ok {
		return v.SelfUpgrade(p)
	}
	exe, err := os.Executable()
	if err != nil {
		return Result{State: "failed", ExitCode: -1, Detail: "locate own binary: " + err.Error()}
	}
	old := exe + ".old"
	os.Remove(old)
	// Renaming a running executable is allowed on Windows and POSIX.
	if err := os.Rename(exe, old); err != nil {
		return Result{State: "failed", ExitCode: -1, Detail: "move current binary aside: " + err.Error()}
	}
	if err := copyExec(file, exe); err != nil {
		os.Rename(old, exe) // put the working binary back
		return Result{State: "failed", ExitCode: -1, Detail: "install new binary: " + err.Error()}
	}
	a.restart = true
	return Result{State: "installed", Detail: fmt.Sprintf("agent %s → %s staged; restarting (%s)", Version, p.Version, runtime.GOOS)}
}

func copyExec(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
