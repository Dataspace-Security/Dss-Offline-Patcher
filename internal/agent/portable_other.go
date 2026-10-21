//go:build !windows

package agent

import "errors"

// RemovePortable removes a portable app the agent installed (Windows only).
func RemovePortable(key string) error {
	return errors.New("portable apps exist on Windows only")
}
