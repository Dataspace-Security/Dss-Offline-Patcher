//go:build !windows

package agent

import "os"

// SecureStateDir creates the state directory (0700). On Linux and macOS it
// lives under a root-owned path (/var/lib, /Library), created by the package
// or by root, so no ownership check is needed here.
func SecureStateDir(dir string) error { return os.MkdirAll(dir, 0o700) }
