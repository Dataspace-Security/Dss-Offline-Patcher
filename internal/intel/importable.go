package intel

import (
	"regexp"
	"sort"
	"strings"
)

// The importable rule: whether offpatch can import a winget app as a
// signed catalog package today. The server computes it for the Library and
// pmctl applies the same rule when it resolves apps (acquire.PickInstaller,
// acquire.LibraryImportable), so the console never offers an Import that
// the acquisition zone will refuse.
//
//   - "yes": a resolved installer for one of the wanted architectures is,
//     in this order of preference:
//     1. an MSI (type msi or wix) whose ProductCode is known (in the
//     manifest) or can be read from the MSI itself (pmctl reads it on
//     every OS, see internal/msi);
//     2. an EXE installer (exe, inno, nullsoft, burn) with machine (or
//     unspecified) scope, an https URL, a SHA-256 and a silent switch (the
//     manifest's, or the type's default for inno, nullsoft and burn);
//     3. an MSIX package (msix, appx) with an https URL and a SHA-256,
//     provisioned machine-wide by agents 0.10.0 and later;
//     4. a per-user EXE installer (scope user, otherwise as 2), run by
//     agents 0.10.0 and later in each signed-in user's session;
//     5. a portable app (portable, or a zip with NestedInstallerType
//     portable) with an https URL and a SHA-256, copied to Program Files
//     by agents 0.10.0 and later.
//     pmctl still verifies the Authenticode signature after download (EXE,
//     per-user and portable packages require a verified signer).
//   - A zip (winget InstallerType zip) whose NestedInstallerType is one of
//     those types and that names its installer (NestedInstallerFiles) is
//     judged like that installer, with an https URL and a SHA-256 of the
//     zip required; a plain installer is preferred over one in a zip.
//     pmctl downloads the zip and checks it; an installer that needs the
//     zip's other files becomes an archive package (agents 0.10.0+).
//   - "no" with a reason: resolved, but no installer qualifies, e.g.
//     "EXE installer without a documented silent switch".
//   - "unknown": not resolved yet (no Resolved entry).
//
// Per-user MSIs get no special handling: pmctl takes a machine-scope MSI
// first, as before (see docs/08-acquisition.md).

// Importable results.
const (
	ImportableYes     = "yes"
	ImportableNo      = "no"
	ImportableUnknown = "unknown"
)

// Reasons for EXE installers that cannot be imported (shared with pmctl).
const (
	ReasonExeNoSilent = "EXE installer without a documented silent switch"
	// ReasonPerUser is what documents and reports written before per-user
	// installers were supported say.
	ReasonPerUser    = "installs per user only"
	ReasonExeNoSHA   = "EXE installer without a SHA-256 in the winget manifest"
	ReasonExeNoHTTPS = "EXE installer URL is not HTTPS"
)

// Reasons for zip installers that cannot be imported (shared with pmctl).
const (
	// ReasonZipPortable is what documents written before portable apps
	// were supported say.
	ReasonZipPortable = "zip with a portable app (no installer)"
	ReasonZipNoFile   = "zip without a named installer file (NestedInstallerFiles)"
	ReasonZipNoSHA    = "zip without a SHA-256 in the winget manifest"
	ReasonZipNoHTTPS  = "zip URL is not HTTPS"
)

// Reasons for MSIX packages and portable apps that cannot be imported.
const (
	ReasonMsixNoSHA       = "MSIX package without a SHA-256 in the winget manifest"
	ReasonMsixNoHTTPS     = "MSIX package URL is not HTTPS"
	ReasonPortableNoSHA   = "portable app without a SHA-256 in the winget manifest"
	ReasonPortableNoHTTPS = "portable app URL is not HTTPS"
)

// "yes" reasons of the newer formats (the Library shows them).
const (
	YesPerUser  = "per-user installer (installs for signed-in users)"
	YesMsix     = "MSIX package (provisioned for all users)"
	YesPortable = "portable app (copied to Program Files)"
)

// msiTypes are winget InstallerType values offpatch imports as msi packages.
var msiTypes = map[string]bool{"msi": true, "wix": true}

// exeTypes are winget's EXE installer flavours, imported as kind exe.
var exeTypes = map[string]bool{"exe": true, "inno": true, "nullsoft": true, "burn": true}

// msixTypes are imported as kind msix.
var msixTypes = map[string]bool{"msix": true, "appx": true}

// exeDefaultSilent: types whose silent switches are well known.
var exeDefaultSilent = map[string]bool{"inno": true, "nullsoft": true, "burn": true}

var sha256Hex = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// installable: an installer type offpatch can deploy in some form.
func installable(t string) bool {
	return msiTypes[t] || exeTypes[t] || msixTypes[t] || t == "portable"
}

// zipNestable: the nested types of a zip that offpatch imports.
func zipNestable(t string) bool { return msiTypes[t] || exeTypes[t] || t == "portable" }

// InstallType is the type of installer offpatch would run: for a zip
// naming an MSI, EXE or portable program (NestedType, NestedPath), the
// nested type and inZip true; otherwise Type (lower case).
func InstallType(in ResolvedInstaller) (t string, inZip bool) {
	t = strings.ToLower(in.Type)
	if t != "zip" {
		return t, false
	}
	if nt := strings.ToLower(in.NestedType); zipNestable(nt) && in.NestedPath != "" {
		return nt, true
	}
	return t, false
}

// ZipReason returns why a zip installer cannot be imported, or "" (the
// nested installer is then judged by its own type's rule).
func ZipReason(in ResolvedInstaller) string {
	nt := strings.ToLower(in.NestedType)
	switch {
	case !zipNestable(nt):
		return ""
	case in.NestedPath == "":
		return ReasonZipNoFile
	case !strings.HasPrefix(strings.ToLower(in.URL), "https://"):
		return ReasonZipNoHTTPS
	case !sha256Hex.MatchString(in.SHA256):
		return ReasonZipNoSHA
	}
	return ""
}

// ExeReason returns why an EXE-type installer (also one in a zip, and a
// per-user one) cannot be imported, or "".
func ExeReason(in ResolvedInstaller) string {
	t, _ := InstallType(in)
	switch {
	case !strings.HasPrefix(strings.ToLower(in.URL), "https://"):
		return ReasonExeNoHTTPS
	case !sha256Hex.MatchString(in.SHA256):
		return ReasonExeNoSHA
	case !exeDefaultSilent[t] && !in.Silent:
		return ReasonExeNoSilent
	}
	return ""
}

// PerUser reports whether the installer installs per user (winget Scope user).
func PerUser(in ResolvedInstaller) bool { return strings.EqualFold(in.Scope, "user") }

// MsixReason returns why an MSIX package cannot be imported, or "".
func MsixReason(in ResolvedInstaller) string {
	switch {
	case !strings.HasPrefix(strings.ToLower(in.URL), "https://"):
		return ReasonMsixNoHTTPS
	case !sha256Hex.MatchString(in.SHA256):
		return ReasonMsixNoSHA
	}
	return ""
}

// PortableReason returns why a portable app (plain or in a zip) cannot be
// imported, or "".
func PortableReason(in ResolvedInstaller) string {
	switch {
	case !strings.HasPrefix(strings.ToLower(in.URL), "https://"):
		return ReasonPortableNoHTTPS
	case !sha256Hex.MatchString(in.SHA256):
		return ReasonPortableNoSHA
	}
	return ""
}

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
	// As pmctl fetches (acquire.archFits / exeArchFits): a neutral installer
	// fits x64 and x86 machines, and a 32-bit MSI also installs on x64.
	// An app published for x86 only (the x86 VC++ redistributable) has
	// its x86 installer used on x64 Windows too, as pmctl does (PickEXE).
	native := false
	for _, in := range r.Installers {
		a := strings.ToLower(in.Arch)
		t, _ := InstallType(in)
		if installable(t) && (want[a] || (a == "neutral" || a == "") && !want["arm64"]) {
			native = true
		}
	}
	archOK := func(a string, isMSI bool) bool {
		a = strings.ToLower(a)
		if len(want) == 0 || want[a] {
			return true
		}
		for w := range want {
			if (a == "neutral" || a == "") && w != "arm64" || (isMSI || !native) && a == "x86" && w == "x64" {
				return true
			}
		}
		return false
	}
	var types, otherArches, reasons []string
	noCode := false
	// The best "yes" of each preference rank (see the rule above).
	var yes [5]string
	for _, in := range r.Installers {
		t, inZip := InstallType(in)
		if !archOK(in.Arch, msiTypes[t]) {
			otherArches = appendUnique(otherArches, strings.ToLower(in.Arch))
			continue
		}
		where := ""
		if inZip {
			where = " in a zip"
		}
		if strings.EqualFold(in.Type, "zip") {
			if why := ZipReason(in); why != "" {
				reasons = appendUnique(reasons, why)
				types = appendUnique(types, zipLabel(in))
				continue
			}
		}
		// better: a plain installer over one in a zip, within a rank.
		better := func(cur string) bool { return cur == "" || !inZip && strings.Contains(cur, " in a zip") }
		switch {
		case msiTypes[t]:
			if in.ProductCode != "" || canReadMSI {
				if !inZip {
					return ImportableYes, "MSI installer (" + archLabel(in.Arch) + ")"
				}
				if yes[0] == "" {
					yes[0] = "MSI installer in a zip (" + archLabel(in.Arch) + ")"
				}
				continue
			}
			noCode = true
		case exeTypes[t]:
			switch why := ExeReason(in); {
			case why != "":
				reasons = appendUnique(reasons, why)
			case PerUser(in):
				if better(yes[3]) {
					yes[3] = YesPerUser + where + " (" + t + ")"
				}
			case better(yes[1]):
				yes[1] = "EXE installer" + where + " (" + t + ")"
			}
			types = appendUnique(types, t)
		case msixTypes[t]:
			if why := MsixReason(in); why != "" {
				reasons = appendUnique(reasons, why)
			} else if yes[2] == "" {
				yes[2] = YesMsix
			}
			types = appendUnique(types, t)
		case t == "portable":
			if why := PortableReason(in); why != "" {
				reasons = appendUnique(reasons, why)
			} else if better(yes[4]) {
				yes[4] = YesPortable + where
			}
			types = appendUnique(types, t)
		default:
			types = appendUnique(types, zipLabel(in))
		}
	}
	for _, y := range yes {
		if y != "" {
			return ImportableYes, y
		}
	}
	switch {
	case noCode:
		return ImportableNo, "MSI installer without a ProductCode"
	case len(reasons) > 0:
		return ImportableNo, bestExeReason(reasons)
	case len(types) == 0 && len(otherArches) > 0:
		sort.Strings(otherArches)
		return ImportableNo, "no installer for " + strings.Join(sortedKeys(want), "/") + " (only " + strings.Join(otherArches, ", ") + ")"
	case len(types) == 0:
		return ImportableNo, "no installers listed in the winget manifest"
	}
	sort.Strings(types)
	return ImportableNo, "no supported installer (" + strings.Join(types, ", ") + ")"
}

// zipLabel: "zip/msix" for a zip of another installer type, else the type.
func zipLabel(in ResolvedInstaller) string {
	t := strings.ToLower(in.Type)
	if nt := strings.ToLower(in.NestedType); t == "zip" && nt != "" {
		return t + "/" + nt
	}
	return t
}

// bestExeReason: the most telling reason when several EXE (or zip)
// installers fail.
func bestExeReason(rs []string) string {
	for _, want := range []string{ReasonExeNoSilent, ReasonExeNoSHA, ReasonExeNoHTTPS, ReasonZipNoFile, ReasonZipNoSHA,
		ReasonZipNoHTTPS, ReasonMsixNoSHA, ReasonMsixNoHTTPS, ReasonPortableNoSHA, ReasonPortableNoHTTPS} {
		for _, r := range rs {
			if r == want {
				return r
			}
		}
	}
	return rs[0]
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
