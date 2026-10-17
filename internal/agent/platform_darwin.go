//go:build darwin

package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

// MacOS installs signed .pkg installers via /usr/sbin/installer. It does not
// handle macOS system (softwareupdate) updates, which need Apple's servers.
type MacOS struct{ LogDir string }

func NativePlatform(logDir string) (Platform, error) { return &MacOS{LogDir: logDir}, nil }

func (m *MacOS) Name() string { return "macos" }

func swVers(arg string) string {
	out, err := exec.Command("/usr/bin/sw_vers", arg).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func (m *MacOS) Facts() (Facts, error) {
	host, _ := os.Hostname()
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x64"
	}
	return Facts{Hostname: host, OS: "macos", OSVersion: fmt.Sprintf("macOS %s (%s)", swVers("-productVersion"), swVers("-buildVersion")), Arch: arch, Edition: "macOS"}, nil
}

// parsePkgInfo extracts version from `pkgutil --pkg-info` output.
func parsePkgInfo(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(line, "version: "); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func (m *MacOS) Inventory() ([]store.InventoryItem, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/sbin/pkgutil", "--pkgs").Output()
	if err != nil {
		return nil, false, fmt.Errorf("pkgutil: %w", err)
	}
	items := []store.InventoryItem{}
	for _, id := range strings.Fields(string(out)) {
		info, err := exec.CommandContext(ctx, "/usr/sbin/pkgutil", "--pkg-info", id).Output()
		if err != nil {
			continue
		}
		items = append(items, store.InventoryItem{Kind: "pkg", ID: id, Name: id, Version: parsePkgInfo(string(info))})
	}
	// Drag-installed apps have no package receipt; report them by bundle ID so
	// updates can be matched (e.g. com.google.Chrome 155 → 156).
	items = append(items, appBundles(ctx, "/Applications")...)
	return items, false, nil
}

// installNeedsRestart reports whether installer output asks for a restart.
func installNeedsRestart(out string) bool {
	l := strings.ToLower(out)
	return strings.Contains(l, "requires a restart") || strings.Contains(l, "restart required") || strings.Contains(l, "must restart")
}

func (m *MacOS) Install(ctx context.Context, p manifest.Package, file string) Result {
	if p.Kind != "pkg" {
		return Result{State: "not_applicable", Detail: "kind " + p.Kind + " is not installable on macOS"}
	}
	ctx, cancel := context.WithTimeout(ctx, time.Hour)
	defer cancel()
	// installer verifies the package signature itself; -target / needs root.
	out, err := exec.CommandContext(ctx, "/usr/sbin/installer", "-pkg", file, "-target", "/").CombinedOutput()
	tail := strings.TrimSpace(string(out))
	if err != nil {
		code := -1
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		}
		return Result{State: "failed", ExitCode: code, Detail: tail}
	}
	if installNeedsRestart(tail) {
		return Result{State: "pending_reboot", Detail: tail}
	}
	return Result{State: "installed", Detail: tail}
}

func (m *MacOS) Reboot(ctx context.Context, reason string) error {
	out, err := exec.CommandContext(ctx, "/sbin/shutdown", "-r", "+10").CombinedOutput()
	if err != nil {
		return fmt.Errorf("shutdown: %v %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *MacOS) Health(ctx context.Context, checks []store.HealthCheck) (bool, string) {
	return runHealth(checks, func(label string) (bool, error) {
		out, err := exec.CommandContext(ctx, "/bin/launchctl", "print", "system/"+label).Output()
		if err != nil {
			return false, nil
		}
		return strings.Contains(string(out), "state = running"), nil
	})
}

// appBundles lists *.app bundles in dir as inventory items of kind "app"
// (ID = CFBundleIdentifier, Version = CFBundleShortVersionString).
func appBundles(ctx context.Context, dir string) []store.InventoryItem {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []store.InventoryItem
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".app") {
			continue
		}
		plist := dir + "/" + e.Name() + "/Contents/Info.plist"
		read := func(key string) string {
			b, err := exec.CommandContext(ctx, "/usr/bin/plutil", "-extract", key, "raw", "-o", "-", plist).Output()
			if err != nil {
				return ""
			}
			return strings.TrimSpace(string(b))
		}
		id := read("CFBundleIdentifier")
		if id == "" {
			continue
		}
		it := store.InventoryItem{Kind: "app", ID: id, Name: strings.TrimSuffix(e.Name(), ".app"), Version: normalizeAppVersion(read("CFBundleShortVersionString"))}
		if _, err := os.Stat(dir + "/" + e.Name() + "/Contents/_MASReceipt/receipt"); err == nil {
			it.Source = "appstore"
		}
		out = append(out, it)
	}
	return out
}

// normalizeAppVersion turns "7.2.2 (88465)" into "7.2.2.88465" so versions
// compare numerically.
func normalizeAppVersion(v string) string {
	v = strings.TrimSpace(v)
	if i := strings.Index(v, " ("); i > 0 && strings.HasSuffix(v, ")") {
		return v[:i] + "." + strings.TrimSpace(v[i+2:len(v)-1])
	}
	return v
}
