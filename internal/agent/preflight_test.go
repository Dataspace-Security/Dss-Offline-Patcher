package agent

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"offpatch/internal/store"
)

func TestParsePmsetBatt(t *testing.T) {
	cases := []struct {
		out  string
		want PowerStatus
	}{
		{"Now drawing from 'Battery Power'\n -InternalBattery-0 (id=4653155)\t23%; discharging; 2:01 remaining present: true\n", PowerStatus{HasBattery: true, Percent: 23}},
		{"Now drawing from 'AC Power'\n -InternalBattery-0 (id=4653155)\t100%; charged; 0:00 remaining present: true\n", PowerStatus{HasBattery: true, OnAC: true, Percent: 100}},
		{"Now drawing from 'AC Power'\n", PowerStatus{OnAC: true, Percent: -1}}, // Mac mini
	}
	for _, c := range cases {
		if got := parsePmsetBatt(c.out); got != c.want {
			t.Errorf("%q: got %+v want %+v", c.out, got, c.want)
		}
	}
}

func TestLinuxPower(t *testing.T) {
	root := t.TempDir()
	mk := func(name string, files map[string]string) {
		os.MkdirAll(filepath.Join(root, name), 0o755)
		for f, v := range files {
			os.WriteFile(filepath.Join(root, name, f), []byte(v+"\n"), 0o644)
		}
	}
	mk("AC", map[string]string{"type": "Mains", "online": "0"})
	mk("BAT0", map[string]string{"type": "Battery", "capacity": "30", "status": "Discharging"})
	mk("hidpp_battery_0", map[string]string{"type": "Battery", "scope": "Device", "capacity": "5"}) // mouse
	p, err := linuxPower(root)
	if err != nil || p != (PowerStatus{HasBattery: true, Percent: 30}) {
		t.Fatalf("laptop on battery: %+v %v", p, err)
	}
	mk("AC", map[string]string{"online": "1"})
	if p, _ := linuxPower(root); !p.OnAC {
		t.Fatalf("AC plugged in: %+v", p)
	}
	empty := t.TempDir() // server: no supplies at all
	if p, _ := linuxPower(empty); p.HasBattery {
		t.Fatalf("no battery expected: %+v", p)
	}
}

func TestWinPower(t *testing.T) {
	if p := winPower(0, 0, 25); p != (PowerStatus{HasBattery: true, Percent: 25}) {
		t.Fatalf("%+v", p)
	}
	if p := winPower(1, 128, 255); p.HasBattery || !p.OnAC || p.Percent != -1 {
		t.Fatalf("desktop: %+v", p)
	}
}

func TestPreflight(t *testing.T) {
	dir := t.TempDir()
	sim := NewSim(SimConfig{Hostname: "h", FreeDiskBytes: 6 << 30}, filepath.Join(dir, "sim.json"))
	a := &Agent{dir: dir, plat: sim, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if why := a.preflight(context.Background(), 1<<30, "windows"); why != "" {
		t.Fatalf("6 GB free, 1 GB package, 5 GB minimum: %s", why)
	}
	if why := a.preflight(context.Background(), 4<<30, "windows"); !strings.Contains(why, "need 8.0 GB") {
		t.Fatalf("2 × 4 GB package should need 8 GB: %q", why)
	}
	a.preinstall = &store.PreinstallPolicy{MinFreeDiskMB: 10240, MinBatteryPct: 50}
	if why := a.preflight(context.Background(), 0, "windows"); !strings.Contains(why, "need 10.0 GB") {
		t.Fatalf("server minimum ignored: %q", why)
	}
	a.preinstall = &store.PreinstallPolicy{MinFreeDiskMB: 0, MinBatteryPct: 50}
	sim.SetConditions(6<<30, true, 49)
	if why := a.preflight(context.Background(), 0, "windows"); !strings.Contains(why, "battery at 49%") {
		t.Fatalf("battery: %q", why)
	}
	a.preinstall.MinBatteryPct = 0 // battery check disabled
	if why := a.preflight(context.Background(), 0, "windows"); why != "" {
		t.Fatalf("disabled battery check: %q", why)
	}
}

// The native implementation must report something sane on the build host.
func TestFreeDiskBytesHost(t *testing.T) {
	n, err := freeDiskBytes(t.TempDir())
	if err != nil || n <= 0 {
		t.Fatalf("freeDiskBytes: %d %v", n, err)
	}
}
