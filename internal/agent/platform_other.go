//go:build !windows && !linux && !darwin

package agent

import "errors"

// NativePlatform: Windows, Linux and macOS have native platforms; elsewhere use "sim".
func NativePlatform(logDir string) (Platform, error) {
	return nil, errors.New("no native platform for this OS; enroll with -platform sim")
}
