//go:build windows

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"offpatch/internal/agent"
)

const serviceName = "offpatch-agent"

const (
	// stopWait bounds how long a stop request waits for a running installer
	// (the agent never kills wusa/msiexec; they have a 2 h timeout).
	stopWait = 2*time.Hour + 5*time.Minute
	// stopHint is the wait hint reported to the SCM, renewed every half of it.
	stopHint = 60 * time.Second
	// maxLogBytes: agent.log is rotated to agent.log.1 at this size.
	maxLogBytes = 10 << 20
)

// singleInstance takes a machine-wide mutex so a manual `pmagent run` and
// the service never install at the same time. Creating Global\ objects
// needs SeCreateGlobalPrivilege, so a standard user cannot squat the name.
func singleInstance() (release func(), err error) {
	name, _ := windows.UTF16PtrFromString(`Global\offpatch-agent`)
	h, err := windows.CreateMutex(nil, false, name)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		windows.CloseHandle(h)
		return nil, errors.New("another pmagent is already running on this computer (service or `pmagent run`)")
	}
	if err != nil {
		return nil, fmt.Errorf("single-instance mutex: %w", err)
	}
	return func() { windows.CloseHandle(h) }, nil
}

func isService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

type handler struct {
	dir string
	log *slog.Logger
}

func (h *handler) Execute(args []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runAgent(ctx, h.dir, false, h.log) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				cancel()
				waitForAgent(done, status, h.log)
				return false, 0
			}
		case err := <-done:
			cancel()
			if errors.Is(err, agent.ErrRestart) {
				// Self-upgrade: come back on the new binary right away.
				if herr := spawnRestartHelper(); herr != nil {
					h.log.Error("restart helper not started; the service recovery actions will restart the agent", "err", herr)
				} else {
					h.log.Info("restarting on the upgraded agent")
				}
				return false, 1
			}
			if err != nil {
				h.log.Error("agent exited", "err", err)
				return false, 1
			}
			return false, 0
		}
	}
}

// waitForAgent lets a running installer finish before the service stops,
// keeping the SCM informed (StopPending with a renewed wait hint) up to
// stopWait. At system shutdown Windows enforces its own limit regardless.
func waitForAgent(done <-chan error, status chan<- svc.Status, log *slog.Logger) {
	cp := uint32(1)
	status <- svc.Status{State: svc.StopPending, CheckPoint: cp, WaitHint: uint32(stopHint / time.Millisecond)}
	tick := time.NewTicker(stopHint / 2)
	defer tick.Stop()
	deadline := time.After(stopWait)
	for {
		select {
		case <-done:
			return
		case <-tick.C:
			if cp == 1 {
				log.Info("stop requested; waiting for the running installer to finish")
			}
			cp++
			status <- svc.Status{State: svc.StopPending, CheckPoint: cp, WaitHint: uint32(stopHint / time.Millisecond)}
		case <-deadline:
			log.Error("installer still running; stopping anyway", "waited", stopWait)
			return
		}
	}
}

func runService(log *slog.Logger) {
	dir := defaultStateDir()
	for i, a := range os.Args {
		if a == "-state-dir" && i+1 < len(os.Args) {
			dir = os.Args[i+1]
		}
	}
	// Check the state dir before writing agent.log into it (as SYSTEM, a
	// planted link there would redirect the log). A refusal goes to the
	// Application event log, as there is nowhere safe to write it.
	if err := agent.SecureStateDir(dir); err != nil {
		if el, eerr := eventlog.Open(serviceName); eerr == nil {
			el.Error(1, "offpatch agent refusing to start: "+err.Error())
			el.Close()
		}
		log.Error("refusing to start", "err", err)
		os.Exit(1)
	}
	f, err := agent.OpenRotatingFile(filepath.Join(dir, "agent.log"), maxLogBytes)
	if err == nil {
		log = slog.New(slog.NewTextHandler(f, nil))
		defer f.Close()
	}
	if err := svc.Run(serviceName, &handler{dir: dir, log: log}); err != nil {
		log.Error("service failed", "err", err)
	}
}

func serviceCmd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: pmagent service install|uninstall [-state-dir dir]")
	}
	fs := flag.NewFlagSet("service", flag.ExitOnError)
	dir := fs.String("state-dir", defaultStateDir(), "agent state directory")
	fs.Parse(args[1:])
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	switch args[0] {
	case "install":
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		s, err := m.CreateService(serviceName, exe, mgr.Config{
			DisplayName: "offpatch Endpoint Agent",
			Description: "Installs approved updates from the internal offpatch server. No internet access.",
			StartType:   mgr.StartAutomatic,
		}, "-state-dir", *dir)
		if err != nil {
			return err
		}
		defer s.Close()
		// Restart on failure: also how a self-upgrade takes effect (the agent
		// exits non-zero after swapping its binary).
		if err := s.SetRecoveryActions([]mgr.RecoveryAction{
			{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
			{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
			{Type: mgr.ServiceRestart, Delay: 5 * time.Minute},
		}, 86400); err != nil {
			return fmt.Errorf("set recovery actions: %w", err)
		}
		// The agent exits cleanly-but-non-zero after a self-upgrade; without
		// this flag Windows only runs recovery actions on crashes.
		if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
			return fmt.Errorf("set failure flag: %w", err)
		}
		fmt.Println("service installed; start with: sc start", serviceName)
	case "uninstall":
		s, err := m.OpenService(serviceName)
		if err != nil {
			return err
		}
		defer s.Close()
		if err := s.Delete(); err != nil {
			return err
		}
		fmt.Println("service removed")
	default:
		return fmt.Errorf("unknown service command %q", args[0])
	}
	return nil
}
