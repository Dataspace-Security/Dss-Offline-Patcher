//go:build linux

package agent

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"offpatch/internal/store"
)

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (l *Linux) Hardware(ctx context.Context) store.Hardware {
	h := store.Hardware{
		Manufacturer: readTrim("/sys/class/dmi/id/sys_vendor"),
		Model:        readTrim("/sys/class/dmi/id/product_name"),
		SerialNumber: readTrim("/sys/class/dmi/id/product_serial"), // root only
	}
	if f, err := os.Open("/proc/cpuinfo"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			k, v, ok := strings.Cut(sc.Text(), ":")
			k = strings.TrimSpace(k)
			if !ok {
				continue
			}
			if k == "processor" {
				h.CPUCores++
			}
			if (k == "model name" || k == "Model") && h.CPU == "" {
				h.CPU = strings.TrimSpace(v)
			}
		}
		f.Close()
	}
	if f, err := os.Open("/proc/meminfo"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if f := strings.Fields(sc.Text()); len(f) >= 2 && f[0] == "MemTotal:" {
				kb, _ := strconv.ParseInt(f[1], 10, 64)
				h.MemoryBytes = kb * 1024
				break
			}
		}
		f.Close()
	}
	// Real local filesystems from /proc/mounts, one entry per device.
	seen := map[string]bool{}
	if f, err := os.Open("/proc/mounts"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fs := strings.Fields(sc.Text())
			if len(fs) < 3 || seen[fs[0]] || !strings.HasPrefix(fs[0], "/dev/") || strings.HasPrefix(fs[1], "/snap") || strings.HasPrefix(fs[1], "/boot") {
				continue
			}
			switch fs[2] {
			case "ext4", "ext3", "xfs", "btrfs", "zfs", "f2fs":
			default:
				continue
			}
			var st syscall.Statfs_t
			if syscall.Statfs(fs[1], &st) == nil && st.Blocks > 0 {
				seen[fs[0]] = true
				h.Disks = append(h.Disks, store.DiskInfo{Mount: fs[1], TotalBytes: int64(st.Blocks) * int64(st.Bsize), FreeBytes: int64(st.Bavail) * int64(st.Bsize)})
			}
		}
		f.Close()
	}
	if f, err := os.Open("/proc/stat"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if v, ok := strings.CutPrefix(sc.Text(), "btime "); ok {
				if sec, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
					h.BootTime = time.Unix(sec, 0).UTC().Format(time.RFC3339)
				}
				break
			}
		}
		f.Close()
	}
	if out, err := exec.CommandContext(ctx, "who").Output(); err == nil {
		if f := strings.Fields(string(out)); len(f) > 0 {
			h.LoggedInUser = f[0]
		}
	}
	fillNetwork(&h)
	return h
}
