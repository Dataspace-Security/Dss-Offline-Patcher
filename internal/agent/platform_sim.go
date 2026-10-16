package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"

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
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := os.Stat(file); err != nil {
		return Result{State: "failed", ExitCode: 2, Detail: "file missing: " + err.Error()}
	}
	id := p.KB
	if p.Kind == "msi" {
		id = p.ProductCode
	}
	for _, f := range s.cfg.FailKBs {
		if strings.EqualFold(f, id) {
			return Result{State: "failed", ExitCode: 1603, Detail: "simulated installer failure (fatal error during installation)"}
		}
	}
	st := s.load()
	if p.Kind == "msu" {
		if slices.Contains(st.KBs, p.KB) {
			return Result{State: "installed", ExitCode: 2359302, Detail: "already installed"}
		}
		st.KBs = append(st.KBs, p.KB)
	} else {
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
