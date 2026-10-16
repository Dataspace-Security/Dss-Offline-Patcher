//go:build windows

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

// Windows installs .msu via wusa.exe and .msi via msiexec.exe. It reboots
// only when the server allows it (deployment reboot_policy + maintenance
// window) and never contacts Windows Update.
type Windows struct{ LogDir string }

func NativePlatform(logDir string) (Platform, error) { return &Windows{LogDir: logDir}, nil }

func (w *Windows) Name() string { return "windows" }

func powershell(ctx context.Context, script string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, filepath.Join(os.Getenv("SystemRoot"), `System32\WindowsPowerShell\v1.0\powershell.exe`),
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("powershell: %v: %s", err, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, err
	}
	return out, nil
}

func (w *Windows) Facts() (Facts, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out, err := powershell(ctx, `$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'; `+
		`[pscustomobject]@{Product=[string]$cv.ProductName; Display=[string]$cv.DisplayVersion; Build=[int]$cv.CurrentBuildNumber; UBR=[int]$cv.UBR; Edition=[string]$cv.EditionID} | ConvertTo-Json -Compress`)
	if err != nil {
		return Facts{}, err
	}
	var r struct {
		Product, Display, Edition string
		Build, UBR                int
	}
	if err := json.Unmarshal(out, &r); err != nil {
		return Facts{}, fmt.Errorf("facts: %w", err)
	}
	host, _ := os.Hostname()
	return Facts{Hostname: host, OS: "windows", OSVersion: fmt.Sprintf("%s %s (%d.%d)", r.Product, r.Display, r.Build, r.UBR), Build: r.Build, Arch: osArch(), Edition: r.Edition}, nil
}

func osArch() string {
	a := os.Getenv("PROCESSOR_ARCHITEW6432")
	if a == "" {
		a = os.Getenv("PROCESSOR_ARCHITECTURE")
	}
	switch strings.ToUpper(a) {
	case "AMD64":
		return "x64"
	case "ARM64":
		return "arm64"
	default:
		return "x86"
	}
}

const inventoryScript = `
$kb = @(Get-CimInstance -ClassName Win32_QuickFixEngineering | ForEach-Object { [string]$_.HotFixID })
$paths = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
$prod = @(Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^\{[0-9A-Fa-f-]{36}\}$' } |
  ForEach-Object { [pscustomobject]@{ id=[string]$_.PSChildName; name=[string]$_.DisplayName; version=[string]$_.DisplayVersion } })
$reboot = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
  (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
[pscustomobject]@{ kbs=$kb; products=$prod; reboot=[bool]$reboot } | ConvertTo-Json -Compress -Depth 4`

func (w *Windows) Inventory() ([]store.InventoryItem, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	out, err := powershell(ctx, inventoryScript)
	if err != nil {
		return nil, false, err
	}
	var r struct {
		KBs      []string `json:"kbs"`
		Products []struct {
			ID, Name, Version string
		} `json:"products"`
		Reboot bool `json:"reboot"`
	}
	if err := json.Unmarshal(out, &r); err != nil {
		return nil, false, fmt.Errorf("inventory: %w", err)
	}
	items := []store.InventoryItem{}
	for _, kb := range r.KBs {
		if kb = strings.ToUpper(strings.TrimSpace(kb)); strings.HasPrefix(kb, "KB") {
			items = append(items, store.InventoryItem{Kind: "kb", ID: kb})
		}
	}
	for _, p := range r.Products {
		items = append(items, store.InventoryItem{Kind: "product", ID: strings.ToUpper(p.ID), Name: p.Name, Version: p.Version})
	}
	return items, r.Reboot, nil
}

// Exit codes documented by Microsoft for wusa.exe / msiexec.exe.
const (
	exitOK              = 0
	exitRebootRequired  = 3010
	exitRebootInitiated = 1641
	exitWusaAlready     = 0x00240006 // WU_S_ALREADY_INSTALLED
	exitWusaNotApplic   = 0x80240017 // WU_E_NOT_APPLICABLE
	exitMsiBusy         = 1618
	exitMsiOtherVersion = 1638
)

func (w *Windows) Install(ctx context.Context, p manifest.Package, file string) Result {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Hour)
	defer cancel()
	sys := filepath.Join(os.Getenv("SystemRoot"), "System32")
	var cmd *exec.Cmd
	switch p.Kind {
	case "msu":
		cmd = exec.CommandContext(ctx, filepath.Join(sys, "wusa.exe"), file, "/quiet", "/norestart")
	case "msi":
		os.MkdirAll(w.LogDir, 0o750)
		logf := filepath.Join(w.LogDir, fmt.Sprintf("%s-%d.log", p.PackageID, time.Now().Unix()))
		cmd = exec.CommandContext(ctx, filepath.Join(sys, "msiexec.exe"), "/i", file, "/qn", "/norestart", "/l*v", logf)
	default:
		return Result{State: "failed", ExitCode: -1, Detail: "unsupported kind " + p.Kind}
	}
	err := cmd.Run()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return Result{State: "failed", ExitCode: -1, Detail: "could not start installer: " + err.Error()}
		}
		code = ee.ExitCode()
	}
	u := uint32(code)
	switch {
	case u == exitOK:
		return Result{State: "installed", ExitCode: code, Detail: p.Kind + " installed"}
	case u == exitRebootRequired || u == exitRebootInitiated:
		return Result{State: "pending_reboot", ExitCode: code, Detail: "installed; reboot required"}
	case p.Kind == "msu" && u == exitWusaAlready:
		return Result{State: "installed", ExitCode: code, Detail: "already installed"}
	case p.Kind == "msu" && u == exitWusaNotApplic:
		return Result{State: "not_applicable", ExitCode: code, Detail: "wusa: update not applicable to this computer"}
	case p.Kind == "msi" && u == exitMsiBusy:
		return Result{State: "failed", ExitCode: code, Detail: "another installation is in progress (will retry)"}
	case p.Kind == "msi" && u == exitMsiOtherVersion:
		return Result{State: "failed", ExitCode: code, Detail: "another version of this product is already installed"}
	}
	return Result{State: "failed", ExitCode: code, Detail: fmt.Sprintf("installer exit code %d (0x%08X)", code, u)}
}

// Reboot schedules a planned restart in 10 minutes with a visible warning
// (shutdown reason p:2:17 = planned, operating system: hot fix).
func (w *Windows) Reboot(ctx context.Context, reason string) error {
	msg := "offpatch: this computer will restart in 10 minutes to finish installing updates. " + reason
	if len(msg) > 500 {
		msg = msg[:500]
	}
	cmd := exec.CommandContext(ctx, filepath.Join(os.Getenv("SystemRoot"), "System32", "shutdown.exe"), "/r", "/t", "600", "/d", "p:2:17", "/c", msg)
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == 1190 {
		return nil // a shutdown is already scheduled
	}
	if err != nil {
		return fmt.Errorf("shutdown.exe: %v %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (w *Windows) Health(ctx context.Context, checks []store.HealthCheck) (bool, string) {
	return runHealth(checks, func(name string) (bool, error) {
		ctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		// Name is validated server-side (letters, digits, _ . $ - space) and is
		// passed via the environment, never interpolated into the script.
		cmd := exec.CommandContext(ctx, filepath.Join(os.Getenv("SystemRoot"), `System32\WindowsPowerShell\v1.0\powershell.exe`),
			"-NoProfile", "-NonInteractive", "-Command", `(Get-Service -Name $env:PM_SVC -ErrorAction Stop).Status.ToString()`)
		cmd.Env = append(os.Environ(), "PM_SVC="+name)
		out, err := cmd.Output()
		if err != nil {
			return false, fmt.Errorf("not found")
		}
		return strings.TrimSpace(string(out)) == "Running", nil
	})
}
