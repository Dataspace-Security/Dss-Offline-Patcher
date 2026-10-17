package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"offpatch/internal/store"
)

// PowerStatus describes the endpoint's power source. HasBattery=false
// (desktops, servers, VMs) always passes the battery check.
type PowerStatus struct {
	HasBattery bool
	OnAC       bool
	Percent    int // 0-100; -1 = unknown
}

// hostConditions reports what the pre-install checks need. Errors mean
// "the OS does not tell us" and never block an install.
type hostConditions interface {
	FreeDisk(path string) (int64, error)
	Power(ctx context.Context) (PowerStatus, error)
}

type nativeConditions struct{}

func (nativeConditions) FreeDisk(path string) (int64, error)            { return freeDiskBytes(path) }
func (nativeConditions) Power(ctx context.Context) (PowerStatus, error) { return readPower(ctx) }

// defaultPreinstall applies when the server sends no policy (older server).
func defaultPreinstall(osName string) store.PreinstallPolicy {
	mb := map[string]int{"windows": 5120, "macos": 2048, "linux": 1024}[osName]
	if mb == 0 {
		mb = 1024
	}
	return store.PreinstallPolicy{MinFreeDiskMB: mb, MinBatteryPct: 40}
}

// preflight returns "" when the endpoint may install now, or why not. size
// is the package size (0 for an uninstall): the disk needs max(2×size, the
// configured minimum) free — room for the cached download plus what the
// installer unpacks.
func (a *Agent) preflight(ctx context.Context, size int64, osName string) string {
	pol := defaultPreinstall(osName)
	if a.preinstall != nil {
		pol = *a.preinstall
	}
	var cond hostConditions = nativeConditions{}
	if c, ok := a.plat.(hostConditions); ok {
		cond = c
	}
	need := 2 * size
	if min := int64(pol.MinFreeDiskMB) << 20; min > need {
		need = min
	}
	seen := map[string]bool{}
	for _, path := range []string{systemVolume(), filepath.Join(a.dir, "cache")} {
		if seen[path] {
			continue
		}
		seen[path] = true
		os.MkdirAll(path, 0o700) // the cache dir must exist to be measured
		free, err := cond.FreeDisk(path)
		if err != nil {
			a.log.Warn("free disk space unknown; not blocking the install", "path", path, "err", err)
			continue
		}
		if free < need {
			return fmt.Sprintf("not enough free disk space on %s: %s free, need %s (max of 2 × %s package and %s minimum); will retry at the next check-in",
				path, fmtSize(free), fmtSize(need), fmtSize(size), fmtSize(int64(pol.MinFreeDiskMB)<<20))
		}
	}
	if pol.MinBatteryPct > 0 {
		p, err := cond.Power(ctx)
		if err != nil {
			a.log.Warn("power status unknown; not blocking the install", "err", err)
		} else if p.HasBattery && !p.OnAC && p.Percent >= 0 && p.Percent < pol.MinBatteryPct {
			return fmt.Sprintf("on battery at %d%% (need AC power or at least %d%%); will retry at the next check-in", p.Percent, pol.MinBatteryPct)
		}
	}
	return ""
}

func fmtSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	}
	return fmt.Sprintf("%d bytes", n)
}

var pmsetPct = regexp.MustCompile(`(\d{1,3})%`)

// parsePmsetBatt reads `pmset -g batt` (macOS):
//
//	Now drawing from 'Battery Power'
//	 -InternalBattery-0 (id=4653155)	23%; discharging; 2:01 remaining present: true
func parsePmsetBatt(out string) PowerStatus {
	p := PowerStatus{OnAC: strings.Contains(out, "'AC Power'"), Percent: -1}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "InternalBattery") {
			p.HasBattery = true
			if m := pmsetPct.FindStringSubmatch(line); m != nil {
				p.Percent, _ = strconv.Atoi(m[1])
			}
		}
	}
	return p
}

// linuxPower reads /sys/class/power_supply (root is that directory). Mains
// supplies tell whether AC is connected; system batteries (not scope=Device,
// e.g. a wireless mouse) give the charge, averaged over all of them.
func linuxPower(root string) (PowerStatus, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return PowerStatus{}, err
	}
	read := func(dir, f string) string {
		b, _ := os.ReadFile(filepath.Join(root, dir, f))
		return strings.TrimSpace(string(b))
	}
	p := PowerStatus{Percent: -1}
	sum, n, mains, charging := 0, 0, false, false
	for _, e := range entries {
		d := e.Name()
		switch read(d, "type") {
		case "Mains":
			mains = true
			if read(d, "online") == "1" {
				p.OnAC = true
			}
		case "Battery":
			if strings.EqualFold(read(d, "scope"), "Device") {
				continue
			}
			p.HasBattery = true
			if c, err := strconv.Atoi(read(d, "capacity")); err == nil {
				sum += c
				n++
			}
			if st := read(d, "status"); st == "Charging" || st == "Full" {
				charging = true
			}
		}
	}
	if !mains && charging {
		p.OnAC = true // no Mains entry exposed, but the battery is charging
	}
	if n > 0 {
		p.Percent = sum / n
	}
	return p, nil
}

// winPower maps GetSystemPowerStatus: ACLineStatus 1 = online; BatteryFlag
// 128 = no system battery, 255 = unknown; BatteryLifePercent 255 = unknown.
func winPower(acLine, flag, pct byte) PowerStatus {
	p := PowerStatus{OnAC: acLine == 1, HasBattery: flag != 128 && flag != 255, Percent: int(pct)}
	if pct == 255 {
		p.Percent = -1
	}
	return p
}
