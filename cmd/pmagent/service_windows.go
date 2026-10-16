//go:build windows

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "offpatch-agent"

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
				status <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				return false, 0
			}
		case err := <-done:
			cancel()
			if err != nil {
				h.log.Error("agent exited", "err", err)
				return false, 1
			}
			return false, 0
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
	f, err := os.OpenFile(filepath.Join(dir, "agent.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
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
