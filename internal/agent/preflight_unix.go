//go:build unix

package agent

import "syscall"

// freeDiskBytes is the space available to the (root) agent on path's volume.
func freeDiskBytes(path string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return int64(uint64(st.Bavail) * uint64(st.Bsize)), nil
}

func systemVolume() string { return "/" }
