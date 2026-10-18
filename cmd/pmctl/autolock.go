package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// The run lock (work_dir/.auto.lock) prevents overlapping scheduled runs.
// It records the owner's pid, and the owner refreshes its modification time
// every lockRefresh. Another run takes it over only if it has not been
// refreshed for lockStale AND the recorded pid is not running (or it is so
// old that the pid must have been reused).
var (
	lockRefresh = time.Minute
	lockStale   = 15 * time.Minute
)

// errRunInProgress: another pmctl auto run holds the lock. `pmctl auto`
// then exits with exitSkipped (scheduled runs overlap harmlessly).
var errRunInProgress = errors.New("another pmctl auto run is in progress")

func acquireLock(dir string, runTimeout time.Duration) (func(), error) {
	p := filepath.Join(dir, ".auto.lock")
	if stale, why := lockIsStale(p, runTimeout); stale {
		if err := os.Remove(p); err == nil {
			autoWarn("removed a stale run lock: " + why)
		}
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("%w (%s)", errRunInProgress, p)
	}
	fmt.Fprintf(f, "%d %s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339))
	f.Close()
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(lockRefresh)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				now := time.Now()
				os.Chtimes(p, now, now)
			}
		}
	}()
	return func() {
		close(stop)
		<-done
		os.Remove(p)
	}, nil
}

func lockIsStale(p string, runTimeout time.Duration) (bool, string) {
	fi, err := os.Stat(p)
	if err != nil {
		return false, ""
	}
	age := time.Since(fi.ModTime())
	if age < lockStale {
		return false, ""
	}
	b, _ := os.ReadFile(p)
	pid, _ := strconv.Atoi(strings.Fields(string(b) + " 0")[0])
	if !processAlive(pid) {
		return true, fmt.Sprintf("pid %d is not running and the lock was last refreshed %s ago", pid, age.Round(time.Second))
	}
	if age > runTimeout+time.Hour {
		return true, fmt.Sprintf("pid %d exists but the lock was last refreshed %s ago, longer than run_timeout allows (pid reused)", pid, age.Round(time.Second))
	}
	return false, ""
}
