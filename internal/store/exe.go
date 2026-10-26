package store

import (
	"regexp"
	"strings"

	"offpatch/internal/intel"
	"offpatch/internal/manifest"
)

// EXE packages (kind exe): vendor EXE installers run silently by agents
// 0.9.0 and later. The installed app is recognised in Apps & features the
// way the agent does it (internal/agent/exe.go exeAppMatch): by its ARP key
// (exe.detect.product_code) when known, else by display name (SameAppName)
// with a compatible architecture tag (archCompatible), so the x86 and x64
// builds of one product (the VC++ redistributables) never satisfy each
// other, while a detection name without an architecture ("7-Zip") still
// finds "7-Zip 24.08 (x64)" (the catalog links such packages the same way,
// catalogIndex.byNameFor). A machine-wide package counts per-machine
// entries only; a per-user installer (exe.scope user, agents 0.10.0+)
// counts per-user entries (inventory Scope "user") only.

// RollbackNoQuietUninstall is why an EXE package without a known silent
// uninstall cannot be rolled back.
const RollbackNoQuietUninstall = "rollback not supported for this installer (no silent uninstall)"

// RollbackPerUser and RollbackMsix: the agent does not remove apps from
// user profiles, nor deprovision MSIX packages.
const (
	RollbackPerUser = "rollback not supported for per-user installers (each user removes the app in Apps & features)"
	RollbackMsix    = "rollback not supported for MSIX packages (remove the app with Remove-AppxProvisionedPackage and Remove-AppxPackage)"
)

var exeArchTagRe = regexp.MustCompile(`(?i)\b(x64|x86|amd64|arm64|64-bit|32-bit|ia64)\b`)

// ExeArchTag is the architecture an app name mentions ("" if none).
func ExeArchTag(name string) string {
	m := exeArchTagRe.FindString(name)
	switch strings.ToLower(m) {
	case "x64", "amd64", "64-bit":
		return "x64"
	case "x86", "32-bit":
		return "x86"
	}
	return strings.ToLower(m)
}

// exeAppMatch: inventory item it is the app EXE package p installs.
func exeAppMatch(p Package, it InventoryItem) bool {
	if p.Kind != manifest.KindExe || it.Kind != "product" || (it.Scope == "user") != perUserExe(p) {
		return false
	}
	d := exeDetect(p)
	if d.ProductCode != "" && strings.EqualFold(it.ID, d.ProductCode) {
		// An ARP key name is not unique across the 64- and 32-bit registry
		// views (both Notepad++ builds use "Notepad++"): the architecture
		// the names mention must still agree.
		return strings.TrimSpace(it.Name) == "" || strings.TrimSpace(d.DisplayName) == "" || itemArchCompatible(it, d.DisplayName)
	}
	if strings.TrimSpace(d.DisplayName) == "" || strings.TrimSpace(it.Name) == "" {
		return false
	}
	return SameAppName(it.Name, d.DisplayName) && itemArchCompatible(it, d.DisplayName)
}

// exeDetect is the package's detection block, via the one shared fallback
// rule (manifest.DetectFor) internal/agent and internal/server/updates.go
// also use, so none of the three can drift out of sync with the others.
func exeDetect(p Package) manifest.ExeDetect {
	return manifest.DetectFor(p.Exe, p.PackageName)
}

// exeWantVersion: the DisplayVersion the app shows once installed.
func exeWantVersion(p Package) string {
	if d := exeDetect(p); d.DisplayVersion != "" {
		return d.DisplayVersion
	}
	return p.Version
}

// exePresent: the app is installed at the package's version or later. An
// entry without a DisplayVersion proves nothing.
func exePresent(p Package, it InventoryItem) bool {
	want := exeWantVersion(p)
	return exeAppMatch(p, it) && want != "" && it.Version != "" && VersionAtLeast(it.Version, want)
}

// exeIdentity groups versions of one EXE app (newest wins in needs).
func exeIdentity(p Package) string {
	d := exeDetect(p)
	scope := ""
	if perUserExe(p) {
		scope = "/user"
	}
	if d.ProductCode != "" {
		return "exe:key:" + strings.ToLower(d.ProductCode) + scope
	}
	return "exe:" + intel.Normalize(d.DisplayName) + "/" + ExeArchTag(d.DisplayName) + scope
}

// AgentSupportsExe reports whether an agent version can install EXE
// packages (0.9.0 or later). Unknown versions cannot.
func AgentSupportsExe(agentVersion string) bool {
	v := strings.TrimPrefix(strings.TrimSpace(agentVersion), "v")
	return v != "" && v[0] >= '0' && v[0] <= '9' && VersionAtLeast(v, manifest.MinAgentVersionExe)
}
