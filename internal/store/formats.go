package store

import (
	"slices"
	"strings"

	"offpatch/internal/intel"
	"offpatch/internal/manifest"
)

// App formats (agents 0.10.0 and later; internal/manifest/formats.go):
//
//   - portable apps (kind portable) are recognised by the Apps & features
//     entry the agent writes (portable.arp_key), or by a per-machine entry
//     with the same display name (an earlier copy installed some other way);
//   - MSIX packages (kind msix) by the appx inventory item of their package
//     family name (Get-AppxPackage / Get-AppxProvisionedPackage);
//   - per-user installers (kind exe, exe.scope user) by per-user Apps &
//     features entries (inventory Scope "user") only.
//
// The agent applies the same rules (internal/agent/formats.go), so the
// server, the agent and verification always agree.

// agentGate is the not_applicable detail for a package the endpoint's agent
// is too old for ("" when it can install it): EXE packages need 0.9.0, the
// app formats 0.10.0. Unknown agent versions cannot install either.
func agentGate(p Package, e Endpoint) string {
	min, why := manifest.RequiredAgent(p.Kind, p.Exe, p.Archive)
	if min == "" || agentAtLeast(e.AgentVersion, min) {
		return ""
	}
	return why
}

// agentTooOld reports whether a target detail is an "agent too old"
// not_applicable reason.
func agentTooOld(detail string) bool { return slices.Contains(manifest.AgentTooOldDetails, detail) }

func agentAtLeast(agentVersion, min string) bool {
	v := strings.TrimPrefix(strings.TrimSpace(agentVersion), "v")
	return v != "" && v[0] >= '0' && v[0] <= '9' && VersionAtLeast(v, min)
}

// AgentSupportsFormats reports whether an agent version installs archive,
// portable, MSIX and per-user packages (0.10.0 or later).
func AgentSupportsFormats(agentVersion string) bool {
	return agentAtLeast(agentVersion, manifest.MinAgentVersionFormats)
}

// perUserExe: a per-user EXE installer.
func perUserExe(p Package) bool {
	return p.Kind == manifest.KindExe && p.Exe != nil && p.Exe.Scope == manifest.ExeScopeUser
}

// portableMatch: inventory item it is the portable app p installs.
func portableMatch(p Package, it InventoryItem) bool {
	if p.Kind != manifest.KindPortable || p.Portable == nil || it.Kind != "product" || it.Scope == "user" {
		return false
	}
	if strings.EqualFold(it.ID, p.Portable.ARPKey) {
		return true
	}
	n := p.Portable.DisplayName
	return strings.TrimSpace(it.Name) != "" && SameAppName(it.Name, n) && itemArchCompatible(it, n)
}

// portableWantVersion: the DisplayVersion the agent writes.
func portableWantVersion(p Package) string {
	if p.Portable != nil && p.Portable.DisplayVersion != "" {
		return p.Portable.DisplayVersion
	}
	return p.Version
}

// msixMatch: it is the appx package family of MSIX package p.
func msixMatch(p Package, it InventoryItem) bool {
	return p.Kind == manifest.KindMsix && p.Msix != nil && it.Kind == "appx" && strings.EqualFold(it.ID, p.Msix.PackageFamilyName)
}

// msixWantVersion: the identity version the endpoint reports once installed.
func msixWantVersion(p Package) string {
	if p.Msix != nil && p.Msix.Version != "" {
		return p.Msix.Version
	}
	return p.Version
}

// formatAppMatch: it is the app a portable or MSIX package installs.
func formatAppMatch(p Package, it InventoryItem) bool {
	return portableMatch(p, it) || msixMatch(p, it)
}

// formatWantVersion: the version a portable or MSIX package installs.
func formatWantVersion(p Package) string {
	if p.Kind == manifest.KindMsix {
		return msixWantVersion(p)
	}
	return portableWantVersion(p)
}

// formatPresent: the portable or MSIX app is at the package's version or
// later. An item without a version proves nothing.
func formatPresent(p Package, it InventoryItem) bool {
	want := formatWantVersion(p)
	return formatAppMatch(p, it) && want != "" && it.Version != "" && VersionAtLeast(it.Version, want)
}

// formatIdentity groups versions of one portable or MSIX app.
func formatIdentity(p Package) string {
	switch {
	case p.Kind == manifest.KindMsix && p.Msix != nil:
		return "msix:" + strings.ToLower(p.Msix.PackageFamilyName)
	case p.Kind == manifest.KindPortable && p.Portable != nil:
		return "portable:" + strings.ToLower(p.Portable.ARPKey)
	}
	return p.Kind + ":" + intel.Normalize(p.PackageName)
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
