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
	"regexp"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

// Windows installs .msu via wusa.exe and .msi via msiexec.exe. It reboots
// only when the server allows it (deployment reboot_policy + maintenance
// window) and never contacts Windows Update.
type Windows struct{ LogDir string }

func NativePlatform(logDir string) (Platform, error) { return &Windows{LogDir: logDir}, nil }

func (w *Windows) Name() string { return "windows" }

// slowInventory: WMI/PowerShell collection is cached between check-ins.
func (w *Windows) slowInventory() {}

// psPrelude makes PowerShell write UTF-8 to the pipe: with the default OEM
// code page, non-ASCII names (and localized errors) arrive mangled.
const psPrelude = `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; $OutputEncoding = [System.Text.Encoding]::UTF8; `

func powershell(ctx context.Context, script string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, filepath.Join(os.Getenv("SystemRoot"), `System32\WindowsPowerShell\v1.0\powershell.exe`),
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", psPrelude+script)
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

// Facts reads the version straight from the registry: no PowerShell process
// at every check-in.
func (w *Windows) Facts() (Facts, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return Facts{}, fmt.Errorf("facts: %w", err)
	}
	defer k.Close()
	str := func(name string) string {
		v, _, _ := k.GetStringValue(name)
		return v
	}
	build, err := strconv.Atoi(str("CurrentBuildNumber"))
	if err != nil {
		return Facts{}, fmt.Errorf("facts: CurrentBuildNumber: %w", err)
	}
	ubr, _, _ := k.GetIntegerValue("UBR")
	display := str("DisplayVersion")
	if display == "" {
		display = str("ReleaseId") // before Windows 10 20H2
	}
	host, _ := os.Hostname()
	return Facts{Hostname: host, OS: "windows", OSVersion: fmt.Sprintf("%s %s (%d.%d)", windowsProductName(str("ProductName"), build), display, build, ubr),
		Build: build, Arch: osArch(), Edition: str("EditionID")}, nil
}

// osArch is the native machine architecture (IsWow64Process2), so an x86 or
// emulated agent still reports an x64 / ARM64 machine correctly. The
// environment is the fallback where the API is missing (Windows 10 < 1511).
func osArch() string {
	var proc, native uint16
	if err := windows.IsWow64Process2(windows.CurrentProcess(), &proc, &native); err == nil {
		if a := machineArch(native); a != "" {
			return a
		}
	}
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

// Installed updates still come from WMI (Win32_QuickFixEngineering has no
// registry equivalent). The agent caches inventory, so this runs every
// inventoryTTL or after an install, not at every check-in.
const kbScript = `ConvertTo-Json -Compress @(Get-CimInstance -ClassName Win32_QuickFixEngineering | ForEach-Object { [string]$_.HotFixID })`

// appxScript lists Microsoft Store / MSIX apps installed for any user:
// main packages only (no frameworks, resource or bundle parts) and not the
// ones signed as part of Windows itself. Shown in the inventory; MSIX
// packages (kind msix) are matched and verified by package family name.
const appxScript = `ConvertTo-Json -Compress @(Get-AppxPackage -AllUsers -PackageTypeFilter Main -ErrorAction SilentlyContinue |
  Where-Object { -not $_.IsFramework -and $_.SignatureKind -ne 'System' } |
  ForEach-Object { @{ id = [string]$_.PackageFamilyName; name = [string]$_.Name; version = [string]$_.Version } })`

// provisionedScript lists packages provisioned for all users (MSIX
// packages the agent installs, Add-AppxProvisionedPackage): existing users
// get them at their next sign-in, so their version is the machine's.
const provisionedScript = `ConvertTo-Json -Compress @(Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
  ForEach-Object { @{ name = [string]$_.DisplayName; version = [string]$_.Version; publisher_id = [string]$_.PublisherId } })`

var uninstallKeys = []string{
	`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
	`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
}

var rebootKeys = []string{
	`SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`,
	`SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`,
}

func (w *Windows) Inventory() ([]store.InventoryItem, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	out, err := powershell(ctx, kbScript)
	if err != nil {
		return nil, false, err
	}
	var kbs []string
	if err := json.Unmarshal(out, &kbs); err != nil {
		return nil, false, fmt.Errorf("inventory: %w", err)
	}
	items := []store.InventoryItem{}
	for _, kb := range mergeKBs(kbs, servicingKBs(ctx)) {
		items = append(items, store.InventoryItem{Kind: "kb", ID: kb})
	}
	prods, err := msiProducts()
	if err != nil {
		return nil, false, fmt.Errorf("inventory: %w", err)
	}
	items = append(items, mergeUserInventory(prods, userProducts())...)
	return append(items, storeApps(ctx)...), rebootPending(), nil
}

// servicingTimeout bounds the servicing-store listing (Get-WindowsPackage
// can take a while on a busy machine).
const servicingTimeout = 2 * time.Minute

// servicingKBs lists the KBs the servicing stack reports installed. Best
// effort: if Get-WindowsPackage is unavailable, slow or fails, the QFE list
// alone is reported.
func servicingKBs(ctx context.Context) []string {
	ctx, cancel := context.WithTimeout(ctx, servicingTimeout)
	defer cancel()
	out, err := powershell(ctx, servicingScript)
	if err != nil {
		return nil
	}
	return parseServicingKBs(out)
}

// storeApps is the Microsoft Store / MSIX part of the inventory. Best
// effort: if PowerShell cannot list them (Server Core, policy), the rest of
// the inventory is still reported.
func storeApps(ctx context.Context) []store.InventoryItem {
	out, err := powershell(ctx, appxScript)
	if err != nil {
		return nil
	}
	installed := parseStoreApps(out)
	if out, err := powershell(ctx, provisionedScript); err == nil {
		return mergeAppx(installed, parseProvisioned(out))
	}
	return installed
}

var productKeyRe = regexp.MustCompile(`^\{[0-9A-Fa-f-]{36}\}$`)

// msiProducts lists installed programs from the 64-bit and 32-bit registry
// views: Windows Installer products (keys named by a product code) and
// EXE-installed apps that Apps & features shows (keys named by the app).
func msiProducts() ([]store.InventoryItem, error) {
	var items []store.InventoryItem
	for i, path := range uninstallKeys {
		found, err := scanUninstall(registry.LOCAL_MACHINE, path, registry.WOW64_64KEY)
		if err != nil {
			return nil, err
		}
		v := uninstallView(i, osArch())
		for j := range found {
			found[j].View = v
		}
		items = append(items, found...)
	}
	return items, nil
}

// userProducts lists per-user installs from every loaded user hive
// (HKU\<SID>\Software\...\Uninstall). It is best effort: a hive that cannot
// be read (unloaded meanwhile, access denied) is skipped, and the machine
// inventory is still reported.
func userProducts() []store.InventoryItem {
	k, err := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	sids, err := k.ReadSubKeyNames(-1)
	k.Close()
	if err != nil {
		return nil
	}
	var items []store.InventoryItem
	for _, sid := range sids {
		if !isUserHive(sid) {
			continue
		}
		// HKU\<SID>\Software is shared by 32- and 64-bit apps: one view.
		found, err := scanUninstall(registry.USERS, sid+`\`+userUninstallKey, 0)
		if err != nil {
			continue
		}
		items = append(items, found...)
	}
	return items
}

// scanUninstall reads one Uninstall key. A missing key is not an error (no
// WOW6432Node on 32-bit Windows, no per-user installs in a profile).
func scanUninstall(root registry.Key, path string, view uint32) ([]store.InventoryItem, error) {
	k, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS|view)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	names, err := k.ReadSubKeyNames(-1)
	k.Close()
	if err != nil {
		return nil, fmt.Errorf("enumerate %s: %w", path, err)
	}
	var items []store.InventoryItem
	for _, n := range names {
		isMSI := productKeyRe.MatchString(n)
		it := store.InventoryItem{Kind: "product", ID: n}
		if isMSI {
			it.ID = strings.ToUpper(n)
		}
		sk, err := registry.OpenKey(root, path+`\`+n, registry.QUERY_VALUE|view)
		if err != nil {
			if isMSI {
				items = append(items, it)
			}
			continue
		}
		it.Name, _, _ = sk.GetStringValue("DisplayName")
		it.Version, _, _ = sk.GetStringValue("DisplayVersion")
		sysComp, _, _ := sk.GetIntegerValue("SystemComponent")
		_, _, perr := sk.GetStringValue("ParentKeyName")
		sk.Close()
		// EXE-installed apps (Chrome's EXE setup, Firefox, VLC…) appear under
		// their own key names; keep those Apps & features shows, and hidden
		// ones with a version (WebView2), marked Hidden.
		if keepUninstallEntry(isMSI, it.Name, it.Version, sysComp, perr == nil) {
			it.Hidden = !isMSI && sysComp == 1
			items = append(items, it)
		}
	}
	return items, nil
}

// rebootPending checks the servicing-stack and Windows Update flags.
// PendingFileRenameOperations is deliberately not used: many products leave
// entries there, which would keep endpoints flagged (and rebooted) forever.
func rebootPending() bool {
	for _, path := range rebootKeys {
		if k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE|registry.WOW64_64KEY); err == nil {
			k.Close()
			return true
		}
	}
	return false
}

// installTimeout bounds one wusa/msiexec run (a cumulative update can take
// well over an hour on slow disks).
const installTimeout = 2 * time.Hour

// runInstaller runs an installer to completion even when the agent is told
// to stop: killing wusa/msiexec mid-way can leave a half-applied update. Only
// installTimeout stops it, and that is reported explicitly.
func runInstaller(ctx context.Context, name string, args ...string) (code int, res *Result) {
	return runInstallerCmd(ctx, name, func(ctx context.Context) *exec.Cmd { return exec.CommandContext(ctx, name, args...) })
}

// runInstallerCmd is runInstaller for a prepared command (EXE installers:
// exact command line, private working and temp directory).
func runInstallerCmd(ctx context.Context, name string, build func(context.Context) *exec.Cmd) (code int, res *Result) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), installTimeout)
	defer cancel()
	err := build(ctx).Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return -1, &Result{State: "failed", ExitCode: -1, Detail: fmt.Sprintf("timed out: %s still running after %s; it was stopped", filepath.Base(name), installTimeout)}
	}
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return -1, &Result{State: "failed", ExitCode: -1, Detail: "could not start " + filepath.Base(name) + ": " + err.Error()}
		}
		return ee.ExitCode(), nil
	}
	return 0, nil
}

func (w *Windows) msiLog(p manifest.Package, op string) string {
	os.MkdirAll(w.LogDir, 0o750)
	pruneOldest(w.LogDir, ".log", maxInstallerLogs)
	return filepath.Join(w.LogDir, fmt.Sprintf("%s%s-%d.log", p.PackageID, op, time.Now().Unix()))
}

// Install installs p. Application updates first stop what runs from the
// app's install folder (appquiesce_windows.go) and start its services again
// afterwards.
func (w *Windows) Install(ctx context.Context, p manifest.Package, file string) Result {
	if !quiesceKind(p) {
		return w.install(ctx, p, file)
	}
	done, wait := w.quiesceApp(ctx, p)
	if wait != nil {
		return *wait
	}
	return done(w.install(ctx, p, file))
}

func (w *Windows) install(ctx context.Context, p manifest.Package, file string) Result {
	sys := filepath.Join(os.Getenv("SystemRoot"), "System32")
	var code int
	var res *Result
	logPath := "" // msiexec verbose log, quoted in the detail on failure
	switch {
	case p.Archive != nil && (p.Kind == "msi" || p.Kind == manifest.KindExe):
		return w.installArchive(ctx, p, file)
	case p.Kind == manifest.KindPortable:
		return w.installPortable(ctx, p, file)
	case p.Kind == manifest.KindMsix:
		return w.installMsix(ctx, p, file)
	case perUserExe(p):
		return w.installPerUser(ctx, p, file)
	}
	switch p.Kind {
	case "msu":
		// A wusa failure says why only in the servicing log: append its tail
		// to the detail, like the msiexec verbose log is appended below.
		cbs := cbsLogPathFor()
		code, res = runInstaller(ctx, filepath.Join(sys, "wusa.exe"), file, "/quiet", "/norestart")
		if res != nil {
			return withCBSLog(*res, cbs)
		}
		return withCBSLog(classifyInstall("msu", code), cbs)
	case manifest.KindExe:
		return w.installExe(ctx, p, file)
	case "msi":
		logPath = w.msiLog(p, "")
		code, res = runInstaller(ctx, filepath.Join(sys, "msiexec.exe"), "/i", file, "/qn", "/norestart", "/l*v", logPath)
	default:
		return Result{State: "failed", ExitCode: -1, Detail: "unsupported kind " + p.Kind}
	}
	if res != nil {
		return withMSILog(*res, logPath)
	}
	return withMSILog(classifyInstall(p.Kind, code), logPath)
}

// Uninstall rolls back an .msu (wusa /uninstall /kb:N) or an .msi
// (msiexec /x {ProductCode}). Nothing is downloaded: the KB / product code
// come from the signed manifest.
func (w *Windows) Uninstall(ctx context.Context, p manifest.Package) Result {
	if !quiesceKind(p) {
		return w.uninstall(ctx, p)
	}
	done, wait := w.quiesceApp(ctx, p)
	if wait != nil {
		return *wait
	}
	return done(w.uninstall(ctx, p))
}

func (w *Windows) uninstall(ctx context.Context, p manifest.Package) Result {
	sys := filepath.Join(os.Getenv("SystemRoot"), "System32")
	var code int
	var res *Result
	logPath := ""
	switch p.Kind {
	case "msu":
		kb := strings.TrimPrefix(strings.ToUpper(p.KB), "KB")
		if kb == "" || strings.Trim(kb, "0123456789") != "" {
			return Result{State: "failed", ExitCode: -1, Detail: "invalid KB " + p.KB}
		}
		cbs := cbsLogPathFor()
		code, res = runInstaller(ctx, filepath.Join(sys, "wusa.exe"), "/uninstall", "/kb:"+kb, "/quiet", "/norestart")
		if res != nil {
			return withCBSLog(*res, cbs)
		}
		return withCBSLog(classifyUninstall("msu", code), cbs)
	case "msi":
		if !msiGUID.MatchString(p.ProductCode) {
			return Result{State: "failed", ExitCode: -1, Detail: "invalid product code " + p.ProductCode}
		}
		logPath = w.msiLog(p, "-uninstall")
		code, res = runInstaller(ctx, filepath.Join(sys, "msiexec.exe"), "/x", p.ProductCode, "/qn", "/norestart", "/l*v", logPath)
	case manifest.KindExe:
		if !p.RollbackSupported() {
			return Result{State: "failed", ExitCode: -1, Detail: exeRollbackUnsupported}
		}
		return w.uninstallExe(ctx, p)
	case manifest.KindPortable:
		return w.uninstallPortable(p)
	default:
		return Result{State: "failed", ExitCode: -1, Detail: "rollback is not supported for kind " + p.Kind}
	}
	if res != nil {
		return withMSILog(*res, logPath)
	}
	return withMSILog(classifyUninstall(p.Kind, code), logPath)
}

var msiGUID = regexp.MustCompile(`^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$`)

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

var procGetTickCount64 = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetTickCount64")

// BootTime is when Windows last started: now minus GetTickCount64 (the
// milliseconds since boot). It tells the agent that a restart has happened.
func (w *Windows) BootTime() (time.Time, error) {
	if err := procGetTickCount64.Find(); err != nil {
		return time.Time{}, err
	}
	lo, hi, _ := procGetTickCount64.Call()
	ms := uint64(lo)
	if unsafe.Sizeof(lo) == 4 { // 386: the 64-bit result is EDX:EAX
		ms |= uint64(hi) << 32
	}
	return time.Now().Add(-time.Duration(ms) * time.Millisecond), nil
}
