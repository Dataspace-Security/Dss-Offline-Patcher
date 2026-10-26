package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

// SimConfig controls the simulated Windows endpoint used for demos and tests
// on non-Windows machines. It installs nothing; it records state in a file.
type SimConfig struct {
	Hostname string   `json:"hostname"`
	Build    int      `json:"build"`
	Arch     string   `json:"arch"`
	FailKBs  []string `json:"fail_kbs"` // installs of these KBs/product codes fail
	Reboot   bool     `json:"reboot"`   // installs require a reboot (cleared after one check-in)
	// UnhealthyServices simulate post-install health-check failures.
	UnhealthyServices []string `json:"unhealthy_services"`
	Edition           string   `json:"edition"`
	// Pre-install conditions: free disk bytes (0 = 100 GB) and battery.
	FreeDiskBytes int64 `json:"free_disk_bytes,omitempty"`
	OnBattery     bool  `json:"on_battery,omitempty"`
	BatteryPct    int   `json:"battery_pct,omitempty"`
	// FailUninstall: rollbacks of these KBs/product codes fail.
	FailUninstall []string `json:"fail_uninstall,omitempty"`
	// InstallDelayMs makes each simulated install take this long, so tests
	// and demos can observe live "installing" progress (0 = instant).
	InstallDelayMs int `json:"install_delay_ms,omitempty"`
	// NoUserSession: nobody is signed in (per-user installers wait).
	NoUserSession bool `json:"no_user_session,omitempty"`
	// RunningApps: portable app folders with a program running (updates
	// of them are retried later).
	RunningApps []string `json:"running_apps,omitempty"`
}

type simState struct {
	KBs             []string              `json:"kbs"`
	Products        []store.InventoryItem `json:"products"`
	RebootCountdown int                   `json:"reboot_countdown"`
	Reboots         int                   `json:"reboots"`
	AgentVersion    string                `json:"agent_version"`
}

type Sim struct {
	cfg  SimConfig
	path string
	mu   sync.Mutex
}

func NewSim(cfg SimConfig, statePath string) *Sim {
	if cfg.Build == 0 {
		cfg.Build = 19045
	}
	if cfg.Arch == "" {
		cfg.Arch = "x64"
	}
	return &Sim{cfg: cfg, path: statePath}
}

func (s *Sim) Name() string { return "sim" }

func (s *Sim) load() simState {
	var st simState
	if b, err := os.ReadFile(s.path); err == nil {
		json.Unmarshal(b, &st)
	}
	return st
}

func (s *Sim) save(st simState) error {
	b, _ := json.MarshalIndent(st, "", "  ")
	return os.WriteFile(s.path, b, 0o600)
}

func (s *Sim) Facts() (Facts, error) {
	ed := s.cfg.Edition
	if ed == "" {
		ed = "Enterprise"
	}
	return Facts{Hostname: s.cfg.Hostname, OS: "windows", OSVersion: fmt.Sprintf("Windows 10 22H2 (simulated, build %d)", s.cfg.Build), Build: s.cfg.Build, Arch: s.cfg.Arch, Edition: ed}, nil
}

func (s *Sim) Inventory() ([]store.InventoryItem, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.load()
	items := []store.InventoryItem{}
	for _, kb := range st.KBs {
		items = append(items, store.InventoryItem{Kind: "kb", ID: kb, Name: "Update for Windows (" + kb + ")"})
	}
	items = append(items, st.Products...)
	reboot := st.RebootCountdown > 0
	if reboot {
		// The simulated operator reboots the machine after one check-in.
		st.RebootCountdown--
		s.save(st)
	}
	return items, reboot, nil
}

func (s *Sim) Install(ctx context.Context, p manifest.Package, file string) Result {
	s.simulateWork(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := os.Stat(file); err != nil {
		return Result{State: "failed", ExitCode: 2, Detail: "file missing: " + err.Error()}
	}
	id := simID(p)
	for _, f := range s.cfg.FailKBs {
		if strings.EqualFold(f, id) {
			return Result{State: "failed", ExitCode: 1603, Detail: "simulated installer failure (fatal error during installation)"}
		}
	}
	st := s.load()
	if p.Archive != nil && p.Kind != manifest.KindPortable {
		// Like the platform: the archive is extracted and every file verified
		// before the installer inside would run.
		dir, err := os.MkdirTemp(filepath.Dir(s.path), "sim-archive-")
		if err != nil {
			return Result{State: "failed", ExitCode: -1, Detail: err.Error()}
		}
		err = extractArchive(p, file, dir)
		os.RemoveAll(dir)
		if err != nil {
			return archiveFailure(err)
		}
	}
	if p.Kind == "msu" {
		if slices.Contains(st.KBs, p.KB) {
			return Result{State: "installed", ExitCode: 2359302, Detail: "already installed"}
		}
		st.KBs = append(st.KBs, p.KB)
	} else if p.Kind == manifest.KindPortable {
		if p.Portable == nil {
			return Result{State: "failed", ExitCode: -1, Detail: "portable package without a portable block"}
		}
		env := portableEnv{parent: filepath.Join(filepath.Dir(s.path), "sim-programfiles", manifest.PortableParent),
			verify: func(string, string) error { return nil },
			running: func(dir string) string {
				if slices.Contains(s.cfg.RunningApps, p.Portable.Folder) {
					return filepath.Join(dir, p.Portable.Command)
				}
				return ""
			}}
		if _, res := installPortableFiles(p, file, env); res != nil {
			return *res
		}
		st.Products = slices.DeleteFunc(st.Products, func(it store.InventoryItem) bool { return portableMatch(p, it) })
		st.Products = append(st.Products, store.InventoryItem{Kind: "product", ID: p.Portable.ARPKey, Name: p.Portable.DisplayName, Version: formatWantVersion(p)})
	} else if p.Kind == manifest.KindMsix {
		if p.Msix == nil {
			return Result{State: "failed", ExitCode: -1, Detail: "msix package without an msix block"}
		}
		st.Products = slices.DeleteFunc(st.Products, func(it store.InventoryItem) bool { return msixMatch(p, it) })
		st.Products = append(st.Products, store.InventoryItem{Kind: "appx", ID: p.Msix.PackageFamilyName, Name: p.Msix.Name, Version: p.Msix.Version, Source: "provisioned"})
	} else if p.Kind == manifest.KindExe {
		if p.Exe == nil {
			return Result{State: "failed", ExitCode: -1, Detail: "exe package without an exe block"}
		}
		if _, err := exeArgs(p.Exe); err != nil {
			return Result{State: "failed", ExitCode: -1, Detail: "exe package refused: " + err.Error()}
		}
		if perUserExe(p) && s.cfg.NoUserSession {
			return aggregateUserRuns(nil)
		}
		// Like the EXE installer: an older version's ARP entry is replaced.
		st.Products = slices.DeleteFunc(st.Products, func(it store.InventoryItem) bool { return exeAppMatch(p, it) })
		it := store.InventoryItem{Kind: "product", ID: id, Name: exeDetect(p).DisplayName, Version: exeWantVersion(p)}
		if perUserExe(p) {
			it.Scope = "user"
		}
		st.Products = append(st.Products, it)
	} else {
		// An MSI upgrade replaces the product's entry (one per product code),
		// as Windows Installer does.
		st.Products = slices.DeleteFunc(st.Products, func(it store.InventoryItem) bool { return msiCopy(p, it) })
		st.Products = append(st.Products, store.InventoryItem{Kind: "product", ID: p.ProductCode, Name: p.Title, Version: p.Version})
	}
	res := Result{State: "installed", ExitCode: 0, Detail: "simulated install succeeded"}
	if s.cfg.Reboot {
		st.RebootCountdown = 1
		res = Result{State: "pending_reboot", ExitCode: 3010, Detail: "simulated install succeeded; reboot required"}
	}
	if err := s.save(st); err != nil {
		return Result{State: "failed", ExitCode: 1, Detail: err.Error()}
	}
	return res
}

// Uninstall removes the KB / product from the simulated inventory.
func (s *Sim) Uninstall(ctx context.Context, p manifest.Package) Result {
	s.simulateWork(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !p.RollbackSupported() {
		return Result{State: "failed", ExitCode: -1, Detail: exeRollbackUnsupported}
	}
	id := simID(p)
	for _, f := range s.cfg.FailUninstall {
		if strings.EqualFold(f, id) {
			return Result{State: "failed", ExitCode: 1603, Detail: "simulated uninstall failure"}
		}
	}
	st := s.load()
	n := len(st.KBs) + len(st.Products)
	st.KBs = slices.DeleteFunc(st.KBs, func(k string) bool { return strings.EqualFold(k, id) })
	st.Products = slices.DeleteFunc(st.Products, func(it store.InventoryItem) bool {
		return strings.EqualFold(it.ID, id) || (p.Kind == manifest.KindExe && exeAppMatch(p, it)) || portableMatch(p, it)
	})
	if p.Kind == manifest.KindPortable && p.Portable != nil {
		os.RemoveAll(portableDir(p, filepath.Join(filepath.Dir(s.path), "sim-programfiles", manifest.PortableParent)))
	}
	if len(st.KBs)+len(st.Products) == n {
		return Result{State: "installed", Detail: "not installed; nothing to remove"}
	}
	res := Result{State: "installed", Detail: "simulated uninstall succeeded"}
	if s.cfg.Reboot {
		st.RebootCountdown = 1
		res = Result{State: "pending_reboot", ExitCode: 3010, Detail: "simulated uninstall succeeded; reboot required"}
	}
	if err := s.save(st); err != nil {
		return Result{State: "failed", ExitCode: 1, Detail: err.Error()}
	}
	return res
}

// simulateWork waits InstallDelayMs (installer run time).
func (s *Sim) simulateWork(ctx context.Context) {
	s.mu.Lock()
	d := time.Duration(s.cfg.InstallDelayMs) * time.Millisecond
	s.mu.Unlock()
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// SignedInUsers simulates the signed-in users (one, unless NoUserSession).
func (s *Sim) SignedInUsers() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.NoUserSession {
		return 0, nil
	}
	return 1, nil
}

// SetUserSession signs the simulated user in or out (tests).
func (s *Sim) SetUserSession(signedIn bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg.NoUserSession = !signedIn
}

// FreeDisk and Power simulate the pre-install conditions.
func (s *Sim) FreeDisk(path string) (int64, error) {
	if s.cfg.FreeDiskBytes > 0 {
		return s.cfg.FreeDiskBytes, nil
	}
	return 100 << 30, nil
}

func (s *Sim) Power(ctx context.Context) (PowerStatus, error) {
	if !s.cfg.OnBattery {
		return PowerStatus{}, nil
	}
	return PowerStatus{HasBattery: true, Percent: s.cfg.BatteryPct}, nil
}

// SetConditions changes the simulated disk/power (tests: "the user plugged in").
func (s *Sim) SetConditions(freeDisk int64, onBattery bool, batteryPct int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg.FreeDiskBytes, s.cfg.OnBattery, s.cfg.BatteryPct = freeDisk, onBattery, batteryPct
}

// Reboot simulates an immediate, successful restart.
func (s *Sim) Reboot(ctx context.Context, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.load()
	st.RebootCountdown = 0
	st.Reboots++
	return s.save(st)
}

func (s *Sim) Health(ctx context.Context, checks []store.HealthCheck) (bool, string) {
	return runHealth(checks, func(name string) (bool, error) {
		for _, u := range s.cfg.UnhealthyServices {
			if strings.EqualFold(u, name) {
				return false, nil
			}
		}
		return true, nil
	})
}

func (s *Sim) AgentVersion() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load().AgentVersion
}

// SelfUpgrade records the new agent version (no binary to replace).
func (s *Sim) SelfUpgrade(p manifest.Package) Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.load()
	st.AgentVersion = p.Version
	if err := s.save(st); err != nil {
		return Result{State: "failed", ExitCode: 1, Detail: err.Error()}
	}
	return Result{State: "installed", Detail: "simulated agent upgrade to " + p.Version}
}

// Hardware returns a plausible, stable fake machine per simulated host.
func (s *Sim) Hardware(ctx context.Context) store.Hardware {
	n := 0
	for _, c := range s.cfg.Hostname {
		n = n*31 + int(c)
	}
	if n < 0 {
		n = -n
	}
	ram := []int64{8, 16, 16, 32}[n%4] << 30
	total := []int64{256, 512, 512, 1024}[n/4%4] << 30
	return store.Hardware{
		Manufacturer: "Simulated", Model: "Virtual PC " + []string{"G5", "G7", "G8"}[n%3], SerialNumber: fmt.Sprintf("SIM%07d", n%10000000),
		CPU: "Simulated x64 CPU @ 2.60GHz", CPUCores: []int{4, 8, 8, 16}[n/16%4], MemoryBytes: ram,
		Disks:       []store.DiskInfo{{Mount: "C:", TotalBytes: total, FreeBytes: total * int64(10+n%60) / 100}},
		BootTime:    time.Now().Add(-time.Duration(1+n%200) * time.Hour).UTC().Truncate(time.Hour).Format(time.RFC3339),
		Timezone:    "UTC",
		IPAddresses: []string{fmt.Sprintf("10.20.%d.%d", n/256%256, n%254+1)},
	}
}

// simID identifies a package in FailKBs / FailUninstall and in the
// simulated inventory: KB, MSI product code, or for EXE packages the ARP key
// (detect.product_code) or, without one, the Apps & features name.
func simID(p manifest.Package) string {
	switch p.Kind {
	case "msi":
		return p.ProductCode
	case manifest.KindExe:
		d := exeDetect(p)
		if d.ProductCode != "" {
			return d.ProductCode
		}
		return d.DisplayName
	case manifest.KindPortable:
		if p.Portable != nil {
			return p.Portable.ARPKey
		}
	case manifest.KindMsix:
		if p.Msix != nil {
			return p.Msix.PackageFamilyName
		}
	}
	return p.KB
}

// SetRunningApps sets the portable app folders with a running program (tests).
func (s *Sim) SetRunningApps(folders []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg.RunningApps = folders
}
