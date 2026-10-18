package intel

import (
	"sort"
	"strings"
)

// The importable rule: whether offpatch can import a winget app as a
// signed catalog package today. The server computes it for the Library and
// pmctl applies the same rule when it resolves apps, so the console never
// offers an Import that the acquisition zone will refuse.
//
//   - "yes": a resolved installer for one of the wanted architectures has
//     type msi or wix, and its MSI ProductCode is known (in the manifest) or
//     can be read from the MSI itself (pmctl reads it on every OS, see
//     internal/msi).
//   - "no" with a reason: resolved, but no installer qualifies, e.g. "EXE
//     installer only (nullsoft)".
//   - "unknown": not resolved yet (no Resolved entry).

// Importable results.
const (
	ImportableYes     = "yes"
	ImportableNo      = "no"
	ImportableUnknown = "unknown"
)

// msiTypes are winget InstallerType values offpatch imports as msi packages.
var msiTypes = map[string]bool{"msi": true, "wix": true}

// exeTypes are winget's EXE installer flavours.
var exeTypes = map[string]bool{"exe": true, "inno": true, "nullsoft": true, "burn": true}

// Importable applies the rule to r. arches are the architectures the app
// is wanted for (the fleet's, where it is installed); empty means any
// architecture (the app is installed nowhere yet: the operator picks one at
// import). canReadMSI says whether a missing ProductCode can be read from
// the MSI file at import (true with the in-repo MSI reader).
func Importable(r *Resolved, arches []string, canReadMSI bool) (status, reason string) {
	if r == nil {
		return ImportableUnknown, "installer details not resolved yet (they arrive with a later update intelligence)"
	}
	want := map[string]bool{}
	for _, a := range arches {
		want[strings.ToLower(a)] = true
	}
	// As pmctl fetches (acquire.archFits): a neutral installer fits x64 and
	// x86 machines, and a 32-bit MSI also installs on x64.
	archOK := func(a string, isMSI bool) bool {
		a = strings.ToLower(a)
		if len(want) == 0 || want[a] {
			return true
		}
		for w := range want {
			if (a == "neutral" || a == "") && w != "arm64" || isMSI && a == "x86" && w == "x64" {
				return true
			}
		}
		return false
	}
	var types, otherArches []string
	noCode := false
	for _, in := range r.Installers {
		t := strings.ToLower(in.Type)
		if !archOK(in.Arch, msiTypes[t]) {
			otherArches = appendUnique(otherArches, strings.ToLower(in.Arch))
			continue
		}
		if msiTypes[t] {
			if in.ProductCode != "" || canReadMSI {
				return ImportableYes, "MSI installer (" + archLabel(in.Arch) + ")"
			}
			noCode = true
			continue
		}
		types = appendUnique(types, t)
	}
	switch {
	case noCode:
		return ImportableNo, "MSI installer without a ProductCode"
	case len(types) == 0 && len(otherArches) > 0:
		sort.Strings(otherArches)
		return ImportableNo, "no installer for " + strings.Join(sortedKeys(want), "/") + " (only " + strings.Join(otherArches, ", ") + ")"
	case len(types) == 0:
		return ImportableNo, "no installers listed in the winget manifest"
	}
	sort.Strings(types)
	allExe := true
	for _, t := range types {
		if !exeTypes[t] {
			allExe = false
		}
	}
	if allExe {
		return ImportableNo, "EXE installer only (" + strings.Join(types, ", ") + ")"
	}
	return ImportableNo, "no MSI installer (" + strings.Join(types, ", ") + ")"
}

func archLabel(a string) string {
	if a == "" {
		return "neutral"
	}
	return strings.ToLower(a)
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ResolvedFor picks the Resolved entry for app id: the one for version when
// present, else the newest version resolved. nil when none.
func (ix *Index) ResolvedFor(id, version string) *Resolved {
	if ix == nil {
		return nil
	}
	ix.resolvedOnce.Do(ix.buildResolved)
	rs := ix.resolved[strings.ToLower(id)]
	var best *Resolved
	for i := range rs {
		r := &rs[i]
		if r.Version == version {
			return r
		}
		if best == nil || CompareVersions(r.Version, best.Version) > 0 {
			best = r
		}
	}
	return best
}

func (ix *Index) buildResolved() {
	ix.resolved = map[string][]Resolved{}
	for _, r := range ix.Doc.Resolved {
		if r.ID == "" || r.Version == "" {
			continue // malformed entry: ignored, never fatal for the document
		}
		k := strings.ToLower(r.ID)
		ix.resolved[k] = append(ix.resolved[k], r)
	}
}
