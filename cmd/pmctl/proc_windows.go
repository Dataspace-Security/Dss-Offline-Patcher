//go:build windows

package main

import "syscall"

const (
	processQueryLimitedInformation = 0x1000
	stillActive                    = 259
)

// processAlive reports whether a process with this pid is running.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, uint32(pid))
	if err != nil {
		// Access denied means it exists (another user's process).
		return err == syscall.ERROR_ACCESS_DENIED
	}
	defer syscall.CloseHandle(h)
	var code uint32
	if err := syscall.GetExitCodeProcess(h, &code); err != nil {
		return true
	}
	return code == stillActive
}
