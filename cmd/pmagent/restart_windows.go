//go:build windows

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// After a self-upgrade the service process exits so Windows runs the new
// binary. Relying only on the service's failure actions restarts it after
// 15 s, 60 s and then 5 minutes (the counter resets once a day), so an
// endpoint that upgrades more than twice in a day sat idle for minutes.
// spawnRestartHelper starts `pmagent restart-service`, detached, which waits
// for this process to exit and starts the service at once. The non-zero exit
// code (and so the failure actions) stays as the fallback.
func spawnRestartHelper() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, "restart-service", "-after-pid", strconv.Itoa(os.Getpid()))
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
		HideWindow:    true,
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

// restartServiceCmd waits (bounded) for the old agent process to exit and
// for the service to stop, then starts it. A service that is already
// running again (the failure action won the race) is left alone.
func restartServiceCmd(args []string) error {
	fs := flag.NewFlagSet("restart-service", flag.ExitOnError)
	pid := fs.Int("after-pid", 0, "wait for this process to exit first")
	fs.Parse(args)
	if *pid > 0 {
		if h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(*pid)); err == nil {
			windows.WaitForSingleObject(h, 60_000)
			windows.CloseHandle(h)
		}
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(500 * time.Millisecond) {
		st, err := s.Query()
		if err != nil {
			return err
		}
		switch st.State {
		case svc.Running, svc.StartPending:
			return nil // already back
		case svc.Stopped:
			if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
				return fmt.Errorf("start %s: %w", serviceName, err)
			}
			return nil
		}
	}
	return fmt.Errorf("%s did not stop within 30 s; the service's recovery actions will restart it", serviceName)
}
