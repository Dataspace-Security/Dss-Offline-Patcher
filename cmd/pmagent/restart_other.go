//go:build !windows

package main

import "errors"

// Linux and macOS service managers restart the agent immediately (Restart=always / KeepAlive).
func spawnRestartHelper() error { return nil }

func restartServiceCmd([]string) error {
	return errors.New("restart-service is only used on Windows")
}
