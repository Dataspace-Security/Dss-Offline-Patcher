//go:build linux

package agent

import (
	"bufio"
	"bytes"
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

// Linux installs .deb (dpkg) and .rpm (rpm) packages from the internal
// repository only. It never calls apt/dnf against network repositories, so
// dependencies must already be present (or shipped as prerequisites).
type Linux struct{ LogDir string }

func NativePlatform(logDir string) (Platform, error) { return &Linux{LogDir: logDir}, nil }

func (l *Linux) Name() string { return "linux" }

func osRelease() map[string]string {
	m := map[string]string{}
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return m
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if ok {
			m[k] = strings.Trim(v, `"`)
		}
	}
	return m
}

func goArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x64"
	case "386":
		return "x86"
	default:
		return runtime.GOARCH
	}
}

func (l *Linux) Facts() (Facts, error) {
	r := osRelease()
	host, _ := os.Hostname()
	name := r["PRETTY_NAME"]
	if name == "" {
		name = "Linux"
	}
	// Edition carries the distribution ID (debian, ubuntu, rhel, rocky…) so
	// packages can be restricted with applicability.editions.
	return Facts{Hostname: host, OS: "linux", OSVersion: name, Arch: goArch(), Edition: r["ID"]}, nil
}

func have(cmd string) bool { _, err := exec.LookPath(cmd); return err == nil }

func (l *Linux) Inventory() ([]store.InventoryItem, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var out []byte
	var err error
	switch {
	case have("dpkg-query"):
		out, err = exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${db:Status-Abbrev}\t${Package}\t${Version}\n").Output()
	case have("rpm"):
		out, err = exec.CommandContext(ctx, "rpm", "-qa", "--qf", "ii \t%{NAME}\t%{VERSION}-%{RELEASE}\n").Output()
	default:
		return nil, false, errors.New("neither dpkg nor rpm found")
	}
	if err != nil {
		return nil, false, fmt.Errorf("package inventory: %w", err)
	}
	items := []store.InventoryItem{}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 3 || !strings.HasPrefix(f[0], "ii") {
			continue // only fully installed packages
		}
		items = append(items, store.InventoryItem{Kind: "pkg", ID: f[1], Name: f[1], Version: f[2]})
	}
	return items, rebootRequired(ctx), nil
}

func rebootRequired(ctx context.Context) bool {
	if _, err := os.Stat("/var/run/reboot-required"); err == nil {
		return true // Debian/Ubuntu
	}
	if have("needs-restarting") {
		// RHEL family: exit 1 means a reboot is required.
		err := exec.CommandContext(ctx, "needs-restarting", "-r").Run()
		var ee *exec.ExitError
		return errors.As(err, &ee) && ee.ExitCode() == 1
	}
	return false
}

func (l *Linux) Install(ctx context.Context, p manifest.Package, file string) Result {
	ctx, cancel := context.WithTimeout(ctx, time.Hour)
	defer cancel()
	var cmd *exec.Cmd
	switch p.Kind {
	case "deb":
		cmd = exec.CommandContext(ctx, "dpkg", "--force-confold", "-i", file)
		cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	case "rpm":
		cmd = exec.CommandContext(ctx, "rpm", "-U", "--replacepkgs", file)
	default:
		return Result{State: "not_applicable", Detail: "kind " + p.Kind + " is not installable on Linux"}
	}
	out, err := cmd.CombinedOutput()
	tail := lastLines(string(out), 6)
	if err != nil {
		code := -1
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		}
		if p.Kind == "deb" {
			// Leave dpkg consistent: unpacked-but-unconfigured packages block later installs.
			exec.Command("dpkg", "--configure", "-a").Run()
		}
		return Result{State: "failed", ExitCode: code, Detail: tail}
	}
	if rebootRequired(ctx) {
		return Result{State: "pending_reboot", Detail: "installed; reboot required. " + tail}
	}
	return Result{State: "installed", Detail: tail}
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

func (l *Linux) Reboot(ctx context.Context, reason string) error {
	out, err := exec.CommandContext(ctx, "shutdown", "-r", "+10", "offpatch: restarting in 10 minutes to finish installing updates. "+reason).CombinedOutput()
	if err != nil {
		return fmt.Errorf("shutdown: %v %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (l *Linux) Health(ctx context.Context, checks []store.HealthCheck) (bool, string) {
	return runHealth(checks, func(name string) (bool, error) {
		if !have("systemctl") {
			return false, errors.New("systemctl not available")
		}
		return exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", name).Run() == nil, nil
	})
}
