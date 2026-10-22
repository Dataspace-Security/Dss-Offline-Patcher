package agent

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"offpatch/internal/manifest"
)

// Before an application update the agent stops what runs from the app's
// real install folder (read from Apps & features, never a fixed path):
// its Windows services always (they are restarted afterwards), and its
// open windows only when the deployment allows closing apps. Otherwise an
// open app makes the target wait and retry, like a running portable app.

// closeAppsKey carries the assignment's close_apps flag to the platform.
type closeAppsKey struct{}

// withCloseApps marks ctx: open apps of the package may be closed.
func withCloseApps(ctx context.Context, close bool) context.Context {
	return context.WithValue(ctx, closeAppsKey{}, close)
}

func closeAppsAllowed(ctx context.Context) bool {
	v, _ := ctx.Value(closeAppsKey{}).(bool)
	return v
}

// quiesceKind: application packages installed for the whole machine by
// msiexec or the vendor's EXE. Windows updates, portable apps (handled on
// their own), MSIX, per-user installers and the agent itself are left out.
func quiesceKind(p manifest.Package) bool {
	switch {
	case p.Kind == "msi":
		return true
	case p.Kind == manifest.KindExe:
		return !perUserExe(p)
	}
	return false
}

// selfServiceName is the agent's own service: never stopped.
const selfServiceName = "offpatch-agent"

var (
	iconIndexRe = regexp.MustCompile(`,\s*-?\d+\s*$`)
	exePathRe   = regexp.MustCompile(`(?i)^\s*"?([^"]+?\.exe)\b`)
)

// installDirFrom is the app's folder from its Apps & features values:
// InstallLocation, else the folder of DisplayIcon, else of the uninstaller
// (not msiexec, which lives in System32). "" when none says.
func installDirFrom(installLocation, displayIcon, uninstallString string) string {
	if d := cleanDir(installLocation); d != "" {
		return d
	}
	if icon := strings.Trim(iconIndexRe.ReplaceAllString(strings.TrimSpace(displayIcon), ""), `" `); icon != "" {
		low := strings.ToLower(icon)
		if strings.HasSuffix(low, ".exe") || strings.HasSuffix(low, ".ico") || strings.HasSuffix(low, ".dll") {
			if d := cleanDir(winDir(icon)); d != "" {
				return d
			}
		}
	}
	if !strings.Contains(strings.ToLower(uninstallString), "msiexec") {
		if m := exePathRe.FindStringSubmatch(uninstallString); m != nil {
			return cleanDir(winDir(m[1]))
		}
	}
	return ""
}

// serviceExe is the program path of a service's ImagePath
// (`"C:\Program Files\App\svc.exe" -k x` → `C:\Program Files\App\svc.exe`).
func serviceExe(binaryPath string) string {
	if m := exePathRe.FindStringSubmatch(binaryPath); m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// winDir is the parent folder of a Windows path on any build platform.
func winDir(p string) string {
	p = strings.ReplaceAll(p, "/", `\`)
	if i := strings.LastIndex(p, `\`); i > 0 {
		return p[:i]
	}
	return ""
}

// cleanDir trims quotes and trailing separators; "" unless it is an
// absolute drive path (C:\...).
func cleanDir(d string) string {
	d = strings.TrimRight(strings.Trim(strings.TrimSpace(d), `"`), `\/ `)
	d = strings.ReplaceAll(d, "/", `\`)
	if len(d) < 3 || d[1] != ':' || d[2] != '\\' {
		return ""
	}
	return d
}

// safeAppDir refuses folders too broad to stop everything under them: a
// drive root, Windows, Program Files, ProgramData, Users or a profile
// root, and the agent's own folders (blocked, by prefix or exactly).
func safeAppDir(dir string, blockedTrees, blockedExact []string) bool {
	d := strings.ToLower(strings.TrimRight(dir, `\`))
	if d == "" || len(d) <= 3 { // "c:" / "c:\"
		return false
	}
	for _, b := range blockedTrees {
		b = strings.ToLower(strings.TrimRight(b, `\`))
		if b != "" && (d == b || strings.HasPrefix(d, b+`\`) || strings.HasPrefix(b, d+`\`)) {
			return false
		}
	}
	for _, b := range blockedExact {
		if b = strings.ToLower(strings.TrimRight(b, `\`)); b != "" && (d == b || strings.HasPrefix(b, d+`\`)) {
			return false
		}
	}
	// C:\Users\<name> itself is a profile, not an app folder.
	if parts := strings.Split(d, `\`); len(parts) == 3 && parts[1] == "users" {
		return false
	}
	return true
}

// underAnyDir: path is in one of dirs.
func underAnyDir(path string, dirs []string) bool {
	p := strings.ToLower(filepath.Clean(strings.ReplaceAll(path, "/", `\`)))
	for _, d := range dirs {
		d = strings.ToLower(strings.TrimRight(d, `\`))
		if p == d || strings.HasPrefix(p, d+`\`) {
			return true
		}
	}
	return false
}

// quiesceNote is what the target detail adds about stopped services and
// closed apps.
func quiesceNote(stopped, restarted, notRestarted, closed []string) string {
	var parts []string
	if len(stopped) > 0 {
		parts = append(parts, fmt.Sprintf("stopped service(s) %s during the update", strings.Join(stopped, ", ")))
	}
	if len(restarted) > 0 {
		parts = append(parts, "started again: "+strings.Join(restarted, ", "))
	}
	if len(notRestarted) > 0 {
		parts = append(parts, "could not start again: "+strings.Join(notRestarted, "; "))
	}
	if len(closed) > 0 {
		parts = append(parts, "closed open app(s): "+strings.Join(closed, ", "))
	}
	return strings.Join(parts, "; ")
}

// appendDetail adds note to a result's detail.
func appendDetail(r Result, note string) Result {
	if note == "" {
		return r
	}
	if r.Detail == "" {
		r.Detail = note
	} else {
		r.Detail += " · " + note
	}
	return r
}
