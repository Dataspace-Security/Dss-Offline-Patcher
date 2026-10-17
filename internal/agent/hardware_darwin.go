//go:build darwin

package agent

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"offpatch/internal/store"
)

var (
	macStaticOnce sync.Once
	macStatic     store.Hardware
	bootSecRe     = regexp.MustCompile(`sec = ([0-9]+)`)
)

func sysctl(ctx context.Context, name string) string {
	out, err := exec.CommandContext(ctx, "/usr/sbin/sysctl", "-n", name).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// macStaticHardware reads what never changes while the agent runs. The
// model name needs system_profiler (about a second), so it runs once.
func macStaticHardware(ctx context.Context) store.Hardware {
	h := store.Hardware{Manufacturer: "Apple", CPU: sysctl(ctx, "machdep.cpu.brand_string"), Model: sysctl(ctx, "hw.model")}
	h.CPUCores, _ = strconv.Atoi(sysctl(ctx, "hw.ncpu"))
	h.MemoryBytes, _ = strconv.ParseInt(sysctl(ctx, "hw.memsize"), 10, 64)
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(cctx, "/usr/sbin/system_profiler", "SPHardwareDataType", "-json").Output(); err == nil {
		var sp struct {
			HW []struct {
				Name   string `json:"machine_name"`
				Model  string `json:"machine_model"`
				Serial string `json:"serial_number"`
			} `json:"SPHardwareDataType"`
		}
		if json.Unmarshal(out, &sp) == nil && len(sp.HW) > 0 {
			if sp.HW[0].Name != "" {
				h.Model = sp.HW[0].Name + " (" + h.Model + ")"
			}
			h.SerialNumber = sp.HW[0].Serial
		}
	}
	return h
}

func (m *MacOS) Hardware(ctx context.Context) store.Hardware {
	macStaticOnce.Do(func() { macStatic = macStaticHardware(ctx) })
	h := macStatic
	h.Disks, h.IPAddresses = nil, nil
	// On APFS "/" is the sealed system volume; the data volume shows real use.
	for _, mnt := range []string{"/System/Volumes/Data", "/"} {
		var st syscall.Statfs_t
		if syscall.Statfs(mnt, &st) == nil && st.Blocks > 0 {
			h.Disks = append(h.Disks, store.DiskInfo{Mount: "/", TotalBytes: int64(st.Blocks) * int64(st.Bsize), FreeBytes: int64(st.Bavail) * int64(st.Bsize)})
			break
		}
	}
	if m := bootSecRe.FindStringSubmatch(sysctl(ctx, "kern.boottime")); m != nil {
		if sec, err := strconv.ParseInt(m[1], 10, 64); err == nil {
			h.BootTime = time.Unix(sec, 0).UTC().Format(time.RFC3339)
		}
	}
	// The console's owner is the user logged in at the screen.
	if fi, err := os.Stat("/dev/console"); err == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
			if u, err := user.LookupId(strconv.Itoa(int(st.Uid))); err == nil {
				h.LoggedInUser = u.Username
			}
		}
	}
	fillNetwork(&h)
	return h
}
