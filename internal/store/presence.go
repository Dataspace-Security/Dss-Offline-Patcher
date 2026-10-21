package store

import (
	"fmt"
	"strconv"
	"strings"

	"offpatch/internal/manifest"
)

// Presence is the single answer to "what does package p mean for endpoint
// e?" that every caller shares: GET /api/packages-needs (NeedsFor), the
// per-endpoint list (AvailableFor), deployment targeting (ensureTarget),
// check-in reconciliation and the console's fleet view (Classify). Before
// this, each place repeated its own subset of the rules, and they disagreed
// (an app counted "up to date" in the fleet was still installed by a
// deployment, an x86 runtime verified an x64 package, ...).
type Presence string

const (
	// PresenceNotApplicable: OS, architecture, build or edition rule out the package.
	PresenceNotApplicable Presence = "not_applicable"
	// PresencePresent: inventory (or the Windows build revision) proves the
	// package, a superseding KB or a newer version is installed.
	PresencePresent Presence = "present"
	// PresenceStoreManaged: a macOS app from the Mac App Store (it updates it).
	PresenceStoreManaged Presence = "store_managed"
	// PresenceNotInstalled: a third-party app package whose app is not on the
	// endpoint (packages update installed apps; they never add new ones).
	PresenceNotInstalled Presence = "not_installed"
	// PresenceNeeded: a deployment would install it.
	PresenceNeeded Presence = "needed"
)

// Verdict is Presence with its explanation.
type Verdict struct {
	Presence Presence
	// Have: the installed (older) version, when needed.
	Have string
	// Why: human reason (target detail / available reason).
	Why string
	// Evidence: the inventory line or OS revision that proved presence.
	Evidence string
}

// classify decides what package p means for endpoint e with inventory inv.
// os carries the Windows build revision (and the UBR hint); sup is the set
// of KBs that supersede p.KB. The EXE agent gate (agent too old) is not a
// presence question and is left to deployment targeting.
func classify(p Package, e Endpoint, os OSFacts, inv []InventoryItem, sup map[string]bool) Verdict {
	if ok, why := applicable(p, e); !ok {
		return Verdict{Presence: PresenceNotApplicable, Why: why}
	}
	if ok, why, ev := presentOn(inv, os, p, sup); ok {
		return Verdict{Presence: PresencePresent, Why: why, Evidence: ev}
	}
	if appStoreManaged(inv, p) {
		return Verdict{Presence: PresenceStoreManaged, Why: appStoreDetail}
	}
	if !appInstalled(inv, p) {
		return Verdict{Presence: PresenceNotInstalled, Why: notInstalledDetail}
	}
	switch p.Kind {
	case "msu":
		return Verdict{Presence: PresenceNeeded, Why: "security update not installed"}
	case "agent":
		v := Verdict{Presence: PresenceNeeded, Why: "agent upgrade"}
		for _, it := range inv {
			if it.Kind == "agent" {
				v.Have = it.Version
			}
		}
		return v
	}
	// An app package: the app is installed but not at this version (or its
	// version is unknown, which proves nothing either way: the installer
	// runs, as the agent does too).
	v := Verdict{Presence: PresenceNeeded, Why: "update available"}
	for _, it := range inv {
		if appItemMatch(p, it) && it.Version != "" && (v.Have == "" || VersionAtLeast(it.Version, v.Have)) {
			v.Have = it.Version
		}
	}
	if v.Have == "" {
		v.Why = "installed version unknown"
	}
	return v
}

// Classify is classify for an endpoint loaded with its inventory (as by
// ListEndpoints / GetEndpoint), with the store's Windows revision hint. sup
// are the KBs superseding p.KB (SupersedingIndex).
func (s *Store) Classify(p Package, e Endpoint, sup map[string]bool) Verdict {
	if e.InventoryAt == "" {
		// Nothing reported yet: only applicability is known.
		if ok, why := applicable(p, e); !ok {
			return Verdict{Presence: PresenceNotApplicable, Why: why}
		}
		return Verdict{Presence: PresenceNeeded, Why: "no inventory yet"}
	}
	return classify(p, e, s.osFactsFor(e.OSVersion, e.Build, e.Arch), e.inventory, sup)
}

// SupersedingIndex returns, for a KB, the KBs of packages in pkgs that
// supersede it (transitively), as supersedingKBs does from the database.
func SupersedingIndex(pkgs []Package) func(kb string) map[string]bool {
	by := map[string][]string{} // superseded KB -> superseding KBs
	for _, p := range pkgs {
		if p.KB == "" {
			continue
		}
		for _, k := range p.Supersedes {
			by[strings.ToUpper(k)] = append(by[strings.ToUpper(k)], strings.ToUpper(p.KB))
		}
	}
	return func(kb string) map[string]bool {
		out := map[string]bool{}
		kb = strings.ToUpper(kb)
		if kb == "" {
			return out
		}
		frontier := []string{kb}
		for len(frontier) > 0 && len(out) < 1000 {
			cur := frontier[0]
			frontier = frontier[1:]
			for _, k := range by[cur] {
				if k != kb && !out[k] {
					out[k] = true
					frontier = append(frontier, k)
				}
			}
		}
		return out
	}
}

// ---- application matching ----

// archCompatible: an app name that mentions an architecture only matches a
// name that mentions the same one or none. The x86 and x64 builds of one
// product (VC++ "… (x86) - 14.40" / "… (x64) - 14.40", Notepad++ "(32-bit
// x86)" / "(64-bit x64)") never stand for each other; a package named
// without an architecture ("7-Zip") still matches "7-Zip 24.08 (x64)".
func archCompatible(a, b string) bool {
	ta, tb := ExeArchTag(a), ExeArchTag(b)
	return ta == tb || ta == "" || tb == ""
}

// msiAppMatch: inventory item it is the app MSI package p installs or
// upgrades, by product code or by display name (same architecture).
// Per-user installs count like machine-wide ones.
func msiAppMatch(p Package, it InventoryItem) bool {
	if p.Kind != "msi" || it.Kind != "product" {
		return false
	}
	if p.ProductCode != "" && strings.EqualFold(it.ID, p.ProductCode) {
		return true
	}
	return p.PackageName != "" && strings.TrimSpace(it.Name) != "" && SameAppName(it.Name, p.PackageName) && archCompatible(it.Name, p.PackageName)
}

// appItemMatch: inventory item it is p's app (any version).
func appItemMatch(p Package, it InventoryItem) bool {
	switch p.Kind {
	case "msi":
		return msiAppMatch(p, it)
	case manifest.KindExe:
		return exeAppMatch(p, it)
	case "deb", "rpm":
		return it.Kind == "pkg" && it.ID == p.PackageName
	case "pkg":
		return (it.Kind == "pkg" || it.Kind == "app") && it.ID == p.PackageName
	case "agent":
		return it.Kind == "agent"
	}
	return false
}

// AppWantVersion: the version inventory shows once app package p is
// installed (an EXE's detect.display_version, else the package version).
func AppWantVersion(p Package) string { return appWantVersion(p) }

// appWantVersion: the version inventory shows once p is installed.
func appWantVersion(p Package) string {
	if p.Kind == manifest.KindExe {
		return exeWantVersion(p)
	}
	return p.Version
}

// ---- Windows build revision ----

// UBRHint returns the build revision (UBR) a Windows update KB brings build
// to on arch (server: Windows Server), 0 when unknown. The server installs
// one backed by the update intelligence (SetUBRHint).
type UBRHint func(kb string, build int, arch string, server bool) int

// SetUBRHint installs h (nil removes it). Safe for concurrent use.
func (s *Store) SetUBRHint(h UBRHint) {
	if h == nil {
		s.ubrHint.Store(nil)
		return
	}
	s.ubrHint.Store(&h)
}

// osFactsFor is osFacts with the endpoint's architecture, edition family and
// the store's UBR hint.
func (s *Store) osFactsFor(osVersion string, build int, arch string) OSFacts {
	f := osFacts(osVersion, build)
	f.Arch = arch
	f.Server = strings.Contains(strings.ToLower(osVersion), "server")
	if h := s.ubrHint.Load(); h != nil {
		f.hint = *h
	}
	return f
}

// checkpointUBR: Windows checkpoint cumulative updates and the revision
// they bring each build to. They are prerequisites of later cumulative
// updates, and machines installed from media that already contains them
// (every 24H2 / 25H2 / Server 2025 image since late 2024) do not list them
// in Win32_QuickFixEngineering at all: the build revision is the proof.
var checkpointUBR = map[string]map[int]int{
	"KB5043080": {26100: 1742, 26200: 1742},
}

// titleUBRRe finds "(26100.6899)" in a Microsoft Update Catalog title.
var titleUBRRe = ubrRe

// titleUBR is the revision a catalog title names for build ("2025-10
// Cumulative Update for Windows 11 Version 24H2 for x64-based Systems
// (KB5066835) (26100.6899)" → 6899 for 26100), 0 if none.
func titleUBR(title string, build int) int {
	for _, m := range titleUBRRe.FindAllStringSubmatch(title, -1) {
		if b, _ := strconv.Atoi(m[1]); b == build {
			u, _ := strconv.Atoi(m[2])
			return u
		}
	}
	return 0
}

// kbUBR is the revision Windows update kb brings the endpoint's build to,
// 0 when unknown: the package's expected_ubr (for its min_build), the
// known checkpoint updates, the catalog title, then the update
// intelligence. Only Windows cumulative updates have one (.NET, servicing
// stack and Defender updates do not change the revision; their titles name
// none and the intelligence does not list them).
func kbUBR(p Package, os OSFacts) int {
	if os.Build <= 0 || p.KB == "" {
		return 0
	}
	if p.ExpectedUBR > 0 && p.Applicability.MinBuild > 0 && os.Build == p.Applicability.MinBuild {
		return p.ExpectedUBR
	}
	if u := checkpointUBR[strings.ToUpper(p.KB)][os.Build]; u > 0 {
		return u
	}
	if u := titleUBR(p.Title, os.Build); u > 0 {
		return u
	}
	if os.hint != nil {
		return os.hint(strings.ToUpper(p.KB), os.Build, os.Arch, os.Server)
	}
	return 0
}

// prereqMet: Windows prerequisite KB pr is installed: listed in inventory,
// or the endpoint's revision is at or past the one it brings.
func prereqMet(pr string, inv []InventoryItem, os OSFacts) bool {
	for _, it := range inv {
		if strings.EqualFold(it.ID, pr) {
			return true
		}
	}
	if os.UBR <= 0 {
		return false
	}
	u := kbUBR(Package{Kind: "msu", KB: pr}, os)
	return u > 0 && os.UBR >= u
}

// ---- explaining an unverified install ----

// missingProof says what inventory lacks for p to count as installed, for
// an install the agent reported done that never verified (sweepUnverified):
// "inventory shows Microsoft Edge WebView2 Runtime 154.0.1, expected ≥
// 155.0.4283.62", "app not found in inventory", "KB5066835 not in the
// installed-updates list; Windows reports 26100.6584, expected ≥ 26100.6899".
func missingProof(p Package, os OSFacts, inv []InventoryItem) string {
	switch p.Kind {
	case "msu":
		s := p.KB + " not in the endpoint's installed-updates list"
		if u := kbUBR(p, os); u > 0 {
			if os.UBR > 0 {
				s += fmt.Sprintf("; Windows reports build %d.%d, expected %d.%d or later", os.Build, os.UBR, os.Build, u)
			} else {
				s += fmt.Sprintf("; Windows did not report its build revision (expected %d.%d or later)", os.Build, u)
			}
		} else {
			s += "; the build revision it brings is unknown, so the revision cannot prove it"
		}
		return s
	case "agent":
		for _, it := range inv {
			if it.Kind == "agent" {
				return fmt.Sprintf("agent reports version %s, expected %s or later", it.Version, p.Version)
			}
		}
		return "agent version not reported"
	}
	want := appWantVersion(p)
	var best *InventoryItem
	for i, it := range inv {
		if appItemMatch(p, it) && (best == nil || VersionAtLeast(it.Version, best.Version)) {
			best = &inv[i]
		}
	}
	if best == nil {
		what := p.PackageName
		if p.Kind == manifest.KindExe {
			if d := exeDetect(p); d.DisplayName != "" {
				what = d.DisplayName
			}
		}
		if what == "" {
			what = p.ProductCode
		}
		s := "app not found in inventory (looked for " + strconv.Quote(what)
		if p.Kind == manifest.KindExe {
			s += ", machine-wide entries only"
		}
		return s + ")"
	}
	v := best.Version
	if v == "" {
		v = "without a version"
	}
	return fmt.Sprintf("inventory shows %s %s, expected %s or later", best.Name, v, want)
}
