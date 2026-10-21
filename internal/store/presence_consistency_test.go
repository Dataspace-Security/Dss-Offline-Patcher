package store

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"offpatch/internal/intel"
	"offpatch/internal/manifest"
)

// Consistency suite: for realistic inventories (registry shapes as the
// Windows agent reports them), every place that decides "needed / already
// present / verified" must give the same answer:
//
//   - classify (the shared verdict) and needs (AvailableFor),
//   - NeedsFor (GET /api/packages-needs: needed / up to date / not installed),
//   - deployment targeting (ensureTarget: pending / verified / not_applicable),
//   - check-in verification after the install, or the unverified alert
//     saying what inventory lacks,
//   - update intelligence (intel.Match) where it can know (it does not see
//     the catalog's supersedence, architectures or per-user rules: the
//     console's fleet view overrides it with the store's verdict, see
//     internal/server fleet_consistency_test.go).

const (
	w11_24H2 = "Windows 11 Pro 24H2"
	w11_25H2 = "Windows 11 Pro 25H2"
	srv2025  = "Windows Server 2025 Datacenter 24H2"
)

// intelSays is what intel.Match alone reports for the case's item.
type intelSays string

const (
	intelNone    intelSays = ""        // not compared
	intelNeeded  intelSays = "needed"  // listed as missing
	intelCurrent intelSays = "current" // matched and current
	intelAbsent  intelSays = "absent"  // not matched at all
)

type presenceCase struct {
	name      string
	osVersion string // e.g. w11_24H2 + " (26100.6584)"
	build     int
	inv       []InventoryItem
	pkg       Package
	title     string   // catalog title of pkg (Windows updates)
	prereqs   []string // pkg prerequisites (checkpoint KBs)
	extra     []Package
	hint      map[string]int // "KB/build" -> UBR from the update intelligence
	want      Presence

	// After the agent reports the install done: the next inventory (and OS
	// version, "" = unchanged). verify: the target verifies; otherwise the
	// unverified detail must contain unverified.
	after      []InventoryItem
	afterOS    string
	verify     bool
	unverified string

	doc       *intel.Doc
	intelSays intelSays
}

var (
	webView2Pkg = Package{PackageID: "Microsoft.EdgeWebView2Runtime-141.0.3537.71", Kind: manifest.KindExe, Version: "141.0.3537.71", PackageName: "Microsoft Edge WebView2 Runtime",
		Exe: exeBlock("Microsoft Edge WebView2 Runtime", "141.0.3537.71", "Microsoft EdgeWebView")}
	// The winget manifest's product code for WebView2 is the EdgeUpdate
	// client GUID, not the ARP key name: the name must still find it.
	webView2GUIDPkg = Package{PackageID: "WebView2-guid", Kind: manifest.KindExe, Version: "141.0.3537.71", PackageName: "Microsoft Edge WebView2 Runtime",
		Exe: exeBlock("Microsoft Edge WebView2 Runtime", "141.0.3537.71", "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}")}
	webView2Old = InventoryItem{Kind: "product", ID: "Microsoft EdgeWebView", Name: "Microsoft Edge WebView2 Runtime", Version: "140.0.3485.94", Hidden: true}
	webView2New = InventoryItem{Kind: "product", ID: "Microsoft EdgeWebView", Name: "Microsoft Edge WebView2 Runtime", Version: "141.0.3537.71", Hidden: true}

	chromeMSI    = Package{PackageID: "Google.Chrome-141.0.7390.108", Kind: "msi", Version: "141.0.7390.108", PackageName: "Google Chrome", ProductCode: "{5B6A1BDE-2C9A-3F57-9B5D-8C0B0A1C3D41}"}
	chromeEXEOld = InventoryItem{Kind: "product", ID: "Google Chrome", Name: "Google Chrome", Version: "140.0.7339.208"}
	chromeMSIOld = InventoryItem{Kind: "product", ID: "{5B6A1BDE-2C9A-3F57-9B5D-8C0B0A1C3D41}", Name: "Google Chrome", Version: "140.0.7339.208"}
	chromeMSINew = InventoryItem{Kind: "product", ID: "{5B6A1BDE-2C9A-3F57-9B5D-8C0B0A1C3D41}", Name: "Google Chrome", Version: "141.0.7390.108"}
	chromeARPNew = InventoryItem{Kind: "product", ID: "Google Chrome", Name: "Google Chrome", Version: "141.0.7390.108"}
	sevenZipEXE  = Package{PackageID: "7zip.7zip-25.01", Kind: manifest.KindExe, Version: "25.01", PackageName: "7-Zip 25.01 (x64)", Exe: exeBlock("7-Zip 25.01 (x64)", "25.01", "7-Zip")}
	sevenZipMSI  = Package{PackageID: "7zip-msi-25.01", Kind: "msi", Version: "25.01.00.0", PackageName: "7-Zip", ProductCode: "{23170F69-40C1-2702-2501-000001000000}"}
	vcEXE64      = Package{PackageID: "VCRedist.x64-14.44", Kind: manifest.KindExe, Version: "14.44.35211.0", PackageName: "Microsoft Visual C++ 2015-2022 Redistributable (x64)",
		Exe: exeBlock("Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.44.35211", "14.44.35211.0", "")}
	vcMSI64       = Package{PackageID: "VCMin.x64-14.44", Kind: "msi", Version: "14.44.35211", PackageName: "Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.44.35211", ProductCode: "{D2A7D7C6-3D11-4C55-9E6A-44A2B1E3F001}"}
	vcBundle64Old = InventoryItem{Kind: "product", ID: "{1E9F6B4A-0000-4000-8000-000000001440}", Name: "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.40.33810", Version: "14.40.33810.0"}
	vcBundle86New = InventoryItem{Kind: "product", ID: "{2E9F6B4A-0000-4000-8000-000000001444}", Name: "Microsoft Visual C++ 2015-2022 Redistributable (x86) - 14.44.35211", Version: "14.44.35211.0"}
	vcMin64Old    = InventoryItem{Kind: "product", ID: "{A1A1A1A1-3D11-4C55-9E6A-44A2B1E3F001}", Name: "Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.40.33810", Version: "14.40.33810"}
	vcMin86New    = InventoryItem{Kind: "product", ID: "{B2B2B2B2-3D11-4C55-9E6A-44A2B1E3F001}", Name: "Microsoft Visual C++ 2022 X86 Minimum Runtime - 14.44.35211", Version: "14.44.35211"}
	zoomEXE       = Package{PackageID: "Zoom.Zoom-6.6.0", Kind: manifest.KindExe, Version: "6.6.0.16983", PackageName: "Zoom Workplace (64-bit)", Exe: exeBlock("Zoom Workplace (64-bit)", "6.6.0 (16983)", "")}
	zoomMSI       = Package{PackageID: "Zoom.MSI-6.6.0", Kind: "msi", Version: "6.6.0.16983", PackageName: "Zoom Workplace (64-bit)", ProductCode: "{F1E1D1C1-6600-4000-8000-000000016983}"}
	zoomUser      = InventoryItem{Kind: "product", ID: "ZoomUMX", Name: "Zoom Workplace", Version: "6.0.2 (33403)", Scope: "user"}
	zoomMachine   = InventoryItem{Kind: "product", ID: "{E1E1E1E1-6500-4000-8000-000000012345}", Name: "Zoom Workplace (64-bit)", Version: "6.5.0.12345"}
	nppEXE64      = Package{PackageID: "Notepad++.Notepad++-8.8.6", Kind: manifest.KindExe, Version: "8.8.6", PackageName: "Notepad++ (64-bit x64)", Exe: exeBlock("Notepad++ (64-bit x64)", "8.8.6", "Notepad++")}
	npp32         = InventoryItem{Kind: "product", ID: "Notepad++", Name: "Notepad++ (32-bit x86)", Version: "8.8.7"}
	npp64Old      = InventoryItem{Kind: "product", ID: "Notepad++", Name: "Notepad++ (64-bit x64)", Version: "8.8.5"}
	teamsMWI      = Package{PackageID: "Teams-MWI-1.7.0", Kind: "msi", Version: "1.7.0.33761", PackageName: "Teams Machine-Wide Installer", ProductCode: "{731F6BAA-A986-45A4-8936-7C3AAAAA760B}"}
	teamsMWIOld   = InventoryItem{Kind: "product", ID: "{731F6BAA-A986-45A4-8936-7C3AAAAA760B}", Name: "Teams Machine-Wide Installer", Version: "1.6.0.27573"}
	teamsNew      = InventoryItem{Kind: "appx", ID: "MSTeams_8wekyb3d8bbwe", Name: "MSTeams", Version: "25255.703.3981.7512"}

	lcuTitle24 = "2025-10 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5066835) (26100.6899)"
	lcuTitle25 = "2025-10 Cumulative Update for Windows 11 Version 25H2 for x64-based Systems (KB5066835) (26200.6899)"
	lcu24      = Package{PackageID: "KB5066835-x64-26100", Kind: "msu", KB: "KB5066835", Version: "26100.6899", Applicability: manifest.Applicability{OS: "windows", Arch: "x64", MinBuild: 26100, MaxBuild: 26100}}
	lcu25      = Package{PackageID: "KB5066835-x64-26200", Kind: "msu", KB: "KB5066835", Version: "26200.6899", Applicability: manifest.Applicability{OS: "windows", Arch: "x64", MinBuild: 26200, MaxBuild: 26200}}
	prevLCU24  = Package{PackageID: "KB5065426-x64-26100", Kind: "msu", KB: "KB5065426", Version: "26100.6584", Applicability: manifest.Applicability{OS: "windows", Arch: "x64", MinBuild: 26100, MaxBuild: 26100}}
	checkpoint = Package{PackageID: "KB5043080-x64", Kind: "msu", KB: "KB5043080", Version: "1", Applicability: manifest.Applicability{OS: "windows", Arch: "x64", MinBuild: 26100, MaxBuild: 26100}}
	dotnetCU   = Package{PackageID: "KB5066131-x64", Kind: "msu", KB: "KB5066131", Version: "1", Applicability: manifest.Applicability{OS: "windows", Arch: "x64", MinBuild: 26100, MaxBuild: 26100}}

	appsDoc = &intel.Doc{GeneratedAt: "2026-10-20T00:00:00Z", Apps: []intel.App{
		{ID: "Microsoft.EdgeWebView2Runtime", Name: "Microsoft Edge WebView2 Runtime", Version: "141.0.3537.71", Codes: []string{"microsoft edgewebview"}, Names: []string{"microsoftedgewebview2runtime"}},
		{ID: "Google.Chrome", Name: "Google Chrome", Version: "141.0.7390.108", Codes: []string{"google chrome", "{5b6a1bde-2c9a-3f57-9b5d-8c0b0a1c3d41}"}, Names: []string{"googlechrome"}},
		{ID: "7zip.7zip", Name: "7-Zip", Version: "25.01", Codes: []string{"7-zip"}, Names: []string{"7zip"}},
		{ID: "Notepad++.Notepad++", Name: "Notepad++", Version: "8.8.6", Codes: []string{"notepad++"}, Names: []string{"notepad"}},
		{ID: "Zoom.Zoom", Name: "Zoom Workplace", Version: "6.6.0.16983", ARPMax: "6.6.0.16983", Codes: []string{"zoomumx"}, Names: []string{"zoomworkplace"}},
		{ID: "Microsoft.VCRedist.2015+.x64", Name: "Microsoft Visual C++ 2015-2022 Redistributable (x64)", Version: "14.44.35211.0", Names: []string{"microsoftvisualc20152022redistributable"}},
		{ID: "Microsoft.VCRedist.2015+.x86", Name: "Microsoft Visual C++ 2015-2022 Redistributable (x86)", Version: "14.44.35211.0", Names: []string{"microsoftvisualc20152022redistributable"}},
		{ID: "Microsoft.Teams.Classic", Name: "Teams Machine-Wide Installer", Version: "1.7.0.33761", Codes: []string{"{731f6baa-a986-45a4-8936-7c3aaaaa760b}"}, Names: []string{"teamsmachinewideinstaller"}},
	}}
	osDoc = &intel.Doc{GeneratedAt: "2026-10-20T00:00:00Z", Windows: []intel.WindowsRelease{
		{Product: "Windows 11 Version 24H2", Build: 26100, Arch: "x64", KB: "KB5066835", UBR: 6899, Title: lcuTitle24},
		{Product: "Windows 11 Version 25H2", Build: 26200, Arch: "x64", KB: "KB5066835", UBR: 6899, Title: lcuTitle25},
		{Product: "Microsoft server operating system version 24H2", Build: 26100, Arch: "x64", Server: true, KB: "KB5066835", UBR: 6899},
	}}
)

func exeBlock(display, version, code string) *manifest.ExeInstall {
	return &manifest.ExeInstall{InstallerType: "exe", SilentArgs: []string{"/silent"}, SuccessCodes: []int{0}, Signer: "Vendor", Scope: "machine",
		Detect: manifest.ExeDetect{DisplayName: display, DisplayVersion: version, ProductCode: code}}
}

func presenceCases() []presenceCase {
	kb := func(id string) InventoryItem { return InventoryItem{Kind: "kb", ID: id} }
	on24 := func(ubr string) string { return w11_24H2 + " (26100." + ubr + ")" }
	return []presenceCase{
		// ---- EXE apps ----
		{name: "WebView2 hidden ARP entry, older: needed, verifies on the new version", osVersion: on24("6899"), build: 26100,
			inv: []InventoryItem{webView2Old}, pkg: webView2Pkg, want: PresenceNeeded,
			after: []InventoryItem{webView2New}, verify: true, doc: appsDoc, intelSays: intelNeeded},
		{name: "WebView2 already current (hidden): present", osVersion: on24("6899"), build: 26100,
			inv: []InventoryItem{webView2New}, pkg: webView2Pkg, want: PresencePresent, doc: appsDoc, intelSays: intelCurrent},
		{name: "WebView2 by name when the package names the EdgeUpdate GUID", osVersion: on24("6899"), build: 26100,
			inv: []InventoryItem{webView2Old}, pkg: webView2GUIDPkg, want: PresenceNeeded, after: []InventoryItem{webView2New}, verify: true},
		{name: "WebView2 install reported done, inventory still old: unverified says what it sees", osVersion: on24("6899"), build: 26100,
			inv: []InventoryItem{webView2Old}, pkg: webView2Pkg, want: PresenceNeeded,
			after: []InventoryItem{webView2Old}, unverified: "inventory shows Microsoft Edge WebView2 Runtime 140.0.3485.94, expected 141.0.3537.71 or later"},
		{name: "WebView2 entry gone from inventory (old agent skips hidden entries): unverified says not found", osVersion: on24("6899"), build: 26100,
			inv: []InventoryItem{webView2Old}, pkg: webView2Pkg, want: PresenceNeeded,
			after: []InventoryItem{}, unverified: `app not found in inventory (looked for "Microsoft Edge WebView2 Runtime"`},
		{name: "7-Zip version in DisplayName: older is needed, newer name verifies", osVersion: on24("6899"), build: 26100,
			inv: []InventoryItem{{Kind: "product", ID: "7-Zip", Name: "7-Zip 24.09 (x64)", Version: "24.09"}}, pkg: sevenZipEXE, want: PresenceNeeded,
			after: []InventoryItem{{Kind: "product", ID: "7-Zip", Name: "7-Zip 25.01 (x64)", Version: "25.01"}}, verify: true, doc: appsDoc, intelSays: intelNeeded},
		{name: "VC++ x64 EXE: newer x86 runtime does not count, older x64 is updated", osVersion: on24("6899"), build: 26100,
			inv: []InventoryItem{vcBundle86New, vcBundle64Old}, pkg: vcEXE64, want: PresenceNeeded,
			after: []InventoryItem{vcBundle86New, {Kind: "product", ID: "{3E9F6B4A-0000-4000-8000-000000001444}", Name: "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.44.35211", Version: "14.44.35211.0"}}, verify: true,
			doc: appsDoc, intelSays: intelNeeded},
		{name: "VC++ x64 EXE on a machine with only the x86 runtime: not installed", osVersion: on24("6899"), build: 26100,
			inv: []InventoryItem{vcBundle86New}, pkg: vcEXE64, want: PresenceNotInstalled},
		{name: "Zoom only per-user: an EXE (machine) package does not install it", osVersion: on24("6899"), build: 26100,
			inv: []InventoryItem{zoomUser}, pkg: zoomEXE, want: PresenceNotInstalled, doc: appsDoc, intelSays: intelNeeded},
		{name: "Zoom machine-wide old plus newer per-user copy: EXE package still needed for the machine copy", osVersion: on24("6899"), build: 26100,
			inv: []InventoryItem{zoomMachine, {Kind: "product", ID: "ZoomUMX", Name: "Zoom Workplace", Version: "6.6.1 (17000)", Scope: "user"}}, pkg: zoomEXE, want: PresenceNeeded,
			after: []InventoryItem{{Kind: "product", ID: "{E1E1E1E1-6600-4000-8000-000000016983}", Name: "Zoom Workplace (64-bit)", Version: "6.6.0 (16983)"}}, verify: true,
			doc: appsDoc, intelSays: intelCurrent},
		{name: "Zoom per-user only with an MSI package: per-user installs count for MSI", osVersion: on24("6899"), build: 26100,
			inv: []InventoryItem{{Kind: "product", ID: "{F1E1D1C1-6000-4000-8000-000000033403}", Name: "Zoom Workplace (64-bit)", Version: "6.0.2.33403", Scope: "user"}}, pkg: zoomMSI, want: PresenceNeeded},
		{name: "Notepad++ 32-bit view newer: the x64 package is not that app", osVersion: on24("6899"), build: 26100,
			inv: []InventoryItem{npp32}, pkg: nppEXE64, want: PresenceNotInstalled},
		{name: "Notepad++ 64-bit older next to a newer 32-bit copy: needed", osVersion: on24("6899"), build: 26100,
			inv: []InventoryItem{npp32, npp64Old}, pkg: nppEXE64, want: PresenceNeeded,
			after: []InventoryItem{npp32, {Kind: "product", ID: "Notepad++", Name: "Notepad++ (64-bit x64)", Version: "8.8.6"}}, verify: true},

		// ---- MSI apps ----
		{name: "Chrome MSI over an EXE install (ARP key 'Google Chrome'): needed by name", osVersion: on24("6899"), build: 26100,
			inv: []InventoryItem{chromeEXEOld}, pkg: chromeMSI, want: PresenceNeeded, after: []InventoryItem{chromeMSINew, chromeARPNew}, verify: true, doc: appsDoc, intelSays: intelNeeded},
		{name: "Chrome MSI keeps its product code across versions: older under the same code is needed", osVersion: on24("6899"), build: 26100,
			inv: []InventoryItem{chromeMSIOld}, pkg: chromeMSI, want: PresenceNeeded, after: []InventoryItem{chromeMSINew}, verify: true, doc: appsDoc, intelSays: intelNeeded},
		{name: "Chrome current (MSI + ARP entry): present", osVersion: on24("6899"), build: 26100,
			inv: []InventoryItem{chromeMSINew, chromeARPNew}, pkg: chromeMSI, want: PresencePresent, doc: appsDoc, intelSays: intelCurrent},
		{name: "7-Zip MSI named without version or architecture matches '7-Zip 24.09 (x64 edition)'", osVersion: on24("6899"), build: 26100,
			inv: []InventoryItem{{Kind: "product", ID: "{23170F69-40C1-2702-2409-000001000000}", Name: "7-Zip 24.09 (x64 edition)", Version: "24.09.00.0"}}, pkg: sevenZipMSI, want: PresenceNeeded,
			after: []InventoryItem{{Kind: "product", ID: "{23170F69-40C1-2702-2501-000001000000}", Name: "7-Zip 25.01 (x64 edition)", Version: "25.01.00.0"}}, verify: true, doc: appsDoc, intelSays: intelNeeded},
		{name: "VC++ x64 MSI: a newer x86 runtime does not make it present", osVersion: on24("6899"), build: 26100,
			inv: []InventoryItem{vcMin86New, vcMin64Old}, pkg: vcMSI64, want: PresenceNeeded,
			after: []InventoryItem{vcMin86New, {Kind: "product", ID: "{D2A7D7C6-3D11-4C55-9E6A-44A2B1E3F001}", Name: "Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.44.35211", Version: "14.44.35211"}}, verify: true},
		{name: "VC++ x64 MSI on a machine with only the x86 runtime: not installed", osVersion: on24("6899"), build: 26100,
			inv: []InventoryItem{vcMin86New}, pkg: vcMSI64, want: PresenceNotInstalled},
		{name: "Teams Machine-Wide Installer older (and new MSIX Teams): needed", osVersion: on24("6899"), build: 26100,
			inv: []InventoryItem{teamsMWIOld, teamsNew}, pkg: teamsMWI, want: PresenceNeeded,
			after: []InventoryItem{{Kind: "product", ID: "{731F6BAA-A986-45A4-8936-7C3AAAAA760B}", Name: "Teams Machine-Wide Installer", Version: "1.7.0.33761"}, teamsNew}, verify: true,
			doc: appsDoc, intelSays: intelNeeded},
		{name: "Only the new MSIX Teams: the classic MSI is not installed", osVersion: on24("6899"), build: 26100,
			inv: []InventoryItem{teamsNew}, pkg: teamsMWI, want: PresenceNotInstalled, doc: appsDoc, intelSays: intelAbsent},
		{name: "MSI app without a DisplayVersion: needed (version unknown), as a deployment installs it", osVersion: on24("6899"), build: 26100,
			inv: []InventoryItem{{Kind: "product", ID: "{99999999-0000-4000-8000-000000000001}", Name: "Google Chrome"}}, pkg: chromeMSI, want: PresenceNeeded},

		// ---- Windows updates ----
		{name: "LCU missing from QFE but the build revision proves it (catalog title)", osVersion: on24("6899"), build: 26100,
			inv: []InventoryItem{kb("KB5043080")}, pkg: lcu24, title: lcuTitle24, want: PresencePresent, doc: osDoc, intelSays: intelCurrent},
		{name: "LCU missing from QFE, revision proves it via the update intelligence (no title revision)", osVersion: on24("6900"), build: 26100,
			pkg: lcu24, title: "2025-10 Cumulative Update for Windows 11 Version 24H2 (KB5066835)", hint: map[string]int{"KB5066835/26100": 6899}, want: PresencePresent, doc: osDoc, intelSays: intelCurrent},
		{name: "LCU not installed: needed, verifies once QFE lists it", osVersion: on24("6584"), build: 26100,
			inv: []InventoryItem{kb("KB5065426")}, pkg: lcu24, title: lcuTitle24, want: PresenceNeeded,
			after: []InventoryItem{kb("KB5066835")}, afterOS: on24("6899"), verify: true, doc: osDoc, intelSays: intelNeeded},
		{name: "LCU installed after a reboot: QFE does not list it, the revision verifies", osVersion: on24("6584"), build: 26100,
			pkg: lcu24, title: lcuTitle24, want: PresenceNeeded, after: []InventoryItem{}, afterOS: on24("6899"), verify: true},
		{name: "LCU reported installed, revision unchanged: unverified names KB and revisions", osVersion: on24("6584"), build: 26100,
			pkg: lcu24, title: lcuTitle24, want: PresenceNeeded, after: []InventoryItem{},
			unverified: "KB5066835 not in the endpoint's installed-updates list; Windows reports build 26100.6584, expected 26100.6899 or later"},
		{name: "Superseded KB: a superseding package's KB in QFE", osVersion: on24("6899"), build: 26100,
			inv: []InventoryItem{kb("KB5066835")}, pkg: prevLCU24, extra: []Package{withSup(lcu24, "KB5065426")}, want: PresencePresent},
		{name: "Superseded KB: newer revision installed, superseding update not in the catalog", osVersion: on24("6899"), build: 26100,
			pkg: prevLCU24, title: "2025-09 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5065426) (26100.6584)", want: PresencePresent},
		{name: "Checkpoint update baked into the image: not in QFE, the revision proves it", osVersion: on24("6584"), build: 26100,
			pkg: checkpoint, title: "Checkpoint cumulative update KB5043080 (prerequisite of KB5066835: " + lcuTitle24 + ")", want: PresencePresent},
		{name: "LCU with a checkpoint prerequisite the image already has: offered, not waiting", osVersion: on24("6584"), build: 26100,
			pkg: lcu24, title: lcuTitle24, prereqs: []string{"KB5043080"}, want: PresenceNeeded, after: []InventoryItem{kb("KB5066835")}, afterOS: on24("6899"), verify: true},
		{name: "25H2 machine: the 24H2 package of the same KB does not apply", osVersion: w11_25H2 + " (26200.6584)", build: 26200,
			pkg: lcu24, title: lcuTitle24, want: PresenceNotApplicable},
		{name: "25H2 machine at the revision: its own package is present without QFE", osVersion: w11_25H2 + " (26200.6899)", build: 26200,
			pkg: lcu25, title: lcuTitle25, want: PresencePresent, doc: osDoc, intelSays: intelCurrent},
		{name: "25H2 machine behind: needed, verifies by revision", osVersion: w11_25H2 + " (26200.6584)", build: 26200,
			pkg: lcu25, title: lcuTitle25, want: PresenceNeeded, after: []InventoryItem{}, afterOS: w11_25H2 + " (26200.6899)", verify: true, doc: osDoc, intelSays: intelNeeded},
		{name: "Server 2025 shares build 26100 and the LCU: revision via the server release", osVersion: srv2025 + " (26100.6900)", build: 26100,
			pkg: lcu24, title: "2025-10 Cumulative Update for Microsoft server operating system version 24H2 (KB5066835)", hint: map[string]int{"KB5066835/26100/server": 6899},
			want: PresencePresent, doc: osDoc, intelSays: intelCurrent},
		{name: "Server 2025 behind: needed", osVersion: srv2025 + " (26100.6584)", build: 26100,
			pkg: lcu24, title: lcuTitle24, want: PresenceNeeded, doc: osDoc, intelSays: intelNeeded},
		{name: ".NET update: the build revision proves nothing", osVersion: on24("6899"), build: 26100,
			pkg: dotnetCU, title: "2025-10 Cumulative Update for .NET Framework 3.5 and 4.8.1 for Windows 11, version 24H2 for x64 (KB5066131)", want: PresenceNeeded,
			after: []InventoryItem{kb("KB5066131")}, verify: true},
	}
}

func withSup(p Package, kbs ...string) Package { p.Supersedes = kbs; return p }

// insertEndpoint adds a Windows endpoint with the given facts and inventory.
func insertEndpoint(t *testing.T, s *Store, id, osVersion string, build int, inv []InventoryItem) {
	t.Helper()
	now := s.now()
	if _, err := s.db.Exec(`INSERT INTO endpoints(endpoint_id,hostname,os,os_version,build,arch,groups,site,last_seen,inventory_at,agent_version,enrolled_at,secret_hash,inventory)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, id, "host-"+id, "windows", osVersion, build, "x64", `["pilot"]`, "hq", now, now, "1.2.0", now, HashSecret(id), mustJSON(inv)); err != nil {
		t.Fatal(err)
	}
}

func hintFrom(m map[string]int) UBRHint {
	return func(kb string, build int, arch string, server bool) int {
		k := kb + "/" + strconv.Itoa(build)
		if server {
			return m[k+"/server"]
		}
		return m[k]
	}
}

func TestPresenceConsistency(t *testing.T) {
	for _, c := range presenceCases() {
		t.Run(c.name, func(t *testing.T) { runPresenceCase(t, c) })
	}
}

func runPresenceCase(t *testing.T, c presenceCase) {
	ctx := context.Background()
	s := openTest(t)
	clock := time.Now().UTC()
	s.Now = func() time.Time { return clock }
	if c.hint != nil {
		s.SetUBRHint(hintFrom(c.hint))
	}
	p := c.pkg
	p.Title = c.title
	if p.Applicability.OS == "" {
		p.Applicability = manifest.Applicability{OS: "windows", Arch: "x64"}
	}
	for _, x := range c.extra {
		addPackage(t, s, x)
	}
	addPackage(t, s, p)
	if _, err := s.db.Exec(`UPDATE packages SET title=?, prerequisites=? WHERE package_id=?`, p.Title, mustJSON(nonNil(c.prereqs)), p.PackageID); err != nil {
		t.Fatal(err)
	}
	inv := c.inv
	if inv == nil {
		inv = []InventoryItem{}
	}
	insertEndpoint(t, s, "e-1", c.osVersion, c.build, inv)
	e, err := getEndpoint(ctx, s.db, "e-1")
	if err != nil {
		t.Fatal(err)
	}
	stored, err := s.GetPackage(ctx, p.PackageID)
	if err != nil {
		t.Fatal(err)
	}
	sup, err := supersedingKBs(ctx, s.db, p.KB)
	if err != nil {
		t.Fatal(err)
	}

	// 1. The shared verdict, and the exported form the console uses.
	v := s.Classify(stored, e, sup)
	if v.Presence != c.want {
		t.Fatalf("classify: %s (%s), want %s", v.Presence, v.Why, c.want)
	}
	allPkgs, _ := s.ListPackages(ctx, "")
	if v2 := s.Classify(stored, e, SupersedingIndex(allPkgs)(p.KB)); v2.Presence != v.Presence {
		t.Errorf("Classify with SupersedingIndex: %s, with the database: %s", v2.Presence, v.Presence)
	}

	// 2. needs / AvailableFor.
	need, _, _ := needs(stored, e, s.osFactsFor(e.OSVersion, e.Build, e.Arch), e.inventory, sup)
	if need != (c.want == PresenceNeeded) {
		t.Errorf("needs: %v, verdict %s", need, c.want)
	}
	av, err := s.AvailableFor(ctx, "e-1")
	if err != nil {
		t.Fatal(err)
	}
	listed := false
	for _, a := range av {
		listed = listed || a.PackageID == p.PackageID
	}
	if listed != (c.want == PresenceNeeded) && !supersededInCatalog(p, c.extra) {
		t.Errorf("AvailableFor lists it: %v, verdict %s", listed, c.want)
	}

	// 3. GET /api/packages-needs.
	nd, err := s.Needs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pn, ok := nd[p.PackageID]; ok {
		got := "none"
		switch {
		case contains(pn.Endpoints, "e-1"):
			got = "needed"
		case contains(pn.UpToDateIDs, "e-1"):
			got = "up_to_date"
		case contains(pn.NotInstalledIDs, "e-1"):
			got = "not_installed"
		}
		wantSet := map[Presence]string{PresenceNeeded: "needed", PresencePresent: "up_to_date", PresenceStoreManaged: "up_to_date",
			PresenceNotInstalled: "not_installed", PresenceNotApplicable: "none"}[c.want]
		if got != wantSet {
			t.Errorf("packages-needs puts it in %s, verdict %s", got, c.want)
		}
	}

	// 4. A deployment targets it accordingly.
	d, err := createApproved(s, ctx, "user:otto", NewDeployment{PackageID: p.PackageID, Name: "dep", Rings: allRing, MaxFailurePct: 100})
	if err != nil {
		t.Fatal(err)
	}
	tg := targetOf(t, s, d.DeploymentID)
	wantTarget := map[Presence]string{PresenceNeeded: "pending", PresencePresent: "verified", PresenceNotInstalled: "not_applicable",
		PresenceStoreManaged: "not_applicable", PresenceNotApplicable: "not_applicable"}[c.want]
	if tg.State != wantTarget {
		t.Fatalf("target %s (%s), want %s", tg.State, tg.Detail, wantTarget)
	}

	// 5. Intelligence alone.
	if c.doc != nil && c.intelSays != intelNone {
		if got := intelVerdict(c.doc, e, p); got != c.intelSays {
			t.Errorf("intel.Match: %s, want %s", got, c.intelSays)
		}
	}

	// 6. Install, then the next check-in verifies it (or says what is missing).
	if c.after == nil || c.want != PresenceNeeded {
		return
	}
	res := checkinAs(t, s, "e-1", c.osVersion, c.build, c.inv)
	if !offered(res, p.PackageID) {
		tg := targetOf(t, s, d.DeploymentID)
		t.Fatalf("not offered at check-in: %s (%s)", tg.State, tg.Detail)
	}
	report(t, s, d.DeploymentID, "e-1", p.PackageID, "installing", "", 0)
	report(t, s, d.DeploymentID, "e-1", p.PackageID, "installed", "exit 0", 0)
	osAfter := c.afterOS
	if osAfter == "" {
		osAfter = c.osVersion
	}
	checkinAs(t, s, "e-1", osAfter, c.build, c.after)
	tg = targetOf(t, s, d.DeploymentID)
	if c.verify {
		if tg.State != "verified" {
			t.Fatalf("after install: %s (%s), want verified", tg.State, tg.Detail)
		}
		return
	}
	if tg.State != "installed" {
		t.Fatalf("after install: %s (%s), want installed (unverified)", tg.State, tg.Detail)
	}
	clock = clock.Add(UnverifiedAfter + time.Hour)
	if err := s.SweepAlerts(ctx, Thresholds{OfflineAfter: 30 * 24 * time.Hour, StaleAfter: 30 * 24 * time.Hour}); err != nil {
		t.Fatal(err)
	}
	tg = targetOf(t, s, d.DeploymentID)
	if !IsUnverified(tg.Detail) || !strings.Contains(tg.Detail, c.unverified) {
		t.Fatalf("unverified detail %q, want it to contain %q", tg.Detail, c.unverified)
	}
}

func supersededInCatalog(p Package, extra []Package) bool {
	for _, x := range extra {
		for _, k := range x.Supersedes {
			if strings.EqualFold(k, p.KB) {
				return true
			}
		}
	}
	return false
}

func targetOf(t *testing.T, s *Store, dep string) Target {
	t.Helper()
	dd, err := s.GetDeployment(context.Background(), dep)
	if err != nil || len(dd.Targets) != 1 {
		t.Fatalf("deployment targets: %v %+v", err, dd.Targets)
	}
	return dd.Targets[0]
}

func checkinAs(t *testing.T, s *Store, ep, osVersion string, build int, inv []InventoryItem) CheckinResult {
	t.Helper()
	if inv == nil {
		inv = []InventoryItem{}
	}
	res, err := s.Checkin(context.Background(), ep, CheckinRequest{Hostname: "host-" + ep, OSVersion: osVersion, Build: build, Arch: "x64", AgentVersion: "1.2.0", Inventory: inv})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func offered(res CheckinResult, pkg string) bool {
	for _, a := range res.Assignments {
		if a.PackageID == pkg {
			return true
		}
	}
	return false
}

// intelVerdict is what intel.Match alone says about the case's item.
func intelVerdict(doc *intel.Doc, e Endpoint, p Package) intelSays {
	items := []intel.Item{}
	for _, it := range e.inventory {
		items = append(items, intel.Item{Kind: it.Kind, ID: it.ID, Name: it.Name, Version: it.Version})
	}
	res := intel.NewIndex(*doc).Match(intel.Endpoint{OS: "windows", OSVersion: e.OSVersion, Build: e.Build, Arch: e.Arch, Inventory: items})
	if p.Kind == "msu" {
		for _, o := range res.OS {
			if strings.EqualFold(o.KB, p.KB) {
				return intelNeeded
			}
		}
		for _, w := range res.CurrentOS {
			if strings.EqualFold(w.KB, p.KB) {
				return intelCurrent
			}
		}
		return intelAbsent
	}
	if len(res.Apps) > 0 {
		return intelNeeded
	}
	if len(res.CurrentApps) > 0 {
		return intelCurrent
	}
	return intelAbsent
}

// A restart the install asked for: the target waits (not verified, not
// "being patched") until the machine restarts, then verifies.
func TestPendingRebootIsRestartNeeded(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	p := lcu24
	addPackage(t, s, p)
	s.db.Exec(`UPDATE packages SET title=? WHERE package_id=?`, lcuTitle24, p.PackageID)
	insertEndpoint(t, s, "e-1", w11_24H2+" (26100.6584)", 26100, []InventoryItem{})
	d, err := createApproved(s, ctx, "user:otto", NewDeployment{PackageID: p.PackageID, Name: "lcu", Rings: allRing, MaxFailurePct: 100})
	if err != nil {
		t.Fatal(err)
	}
	report(t, s, d.DeploymentID, "e-1", p.PackageID, "installing", "", 0)
	report(t, s, d.DeploymentID, "e-1", p.PackageID, "pending_reboot", "installed; reboot required", 3010)
	// Windows already lists the KB, the restart is still pending.
	if _, err := s.Checkin(ctx, "e-1", CheckinRequest{Hostname: "host-e-1", OSVersion: w11_24H2 + " (26100.6584)", Build: 26100, Arch: "x64", AgentVersion: "1.2.0",
		Inventory: []InventoryItem{{Kind: "kb", ID: "KB5066835"}}, RebootPending: true}); err != nil {
		t.Fatal(err)
	}
	if tg := targetOf(t, s, d.DeploymentID); tg.State != "pending_reboot" {
		t.Fatalf("before the restart: %s (%s)", tg.State, tg.Detail)
	}
	ft, err := s.FleetTargets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st := ft.Status(p.PackageID, "e-1"); !st.RestartNeeded || st.Verified {
		t.Fatalf("fleet status: %+v", st)
	}
	nd, _ := s.Needs(ctx)
	if pn := nd[p.PackageID]; pn.RestartNeeded != 1 {
		t.Errorf("packages-needs restart_needed: %+v", pn)
	}
	// Restarted: the revision moved on, QFE no longer lists it: verified.
	checkinAs(t, s, "e-1", w11_24H2+" (26100.6899)", 26100, []InventoryItem{})
	if tg := targetOf(t, s, d.DeploymentID); tg.State != "verified" {
		t.Fatalf("after the restart: %s (%s)", tg.State, tg.Detail)
	}
}

// Targeted before its first inventory: once inventory shows the app is not
// there, the target is not_applicable (nothing is installed on it), as
// targeting with inventory would have decided.
func TestTargetedBeforeInventoryAppAbsent(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	addPackage(t, s, chromeMSI)
	now := s.now()
	if _, err := s.db.Exec(`INSERT INTO endpoints(endpoint_id,hostname,os,os_version,build,arch,groups,site,last_seen,inventory_at,agent_version,enrolled_at,secret_hash,inventory)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, "e-1", "host-e-1", "windows", w11_24H2+" (26100.6899)", 26100, "x64", `["pilot"]`, "hq", now, "", "1.2.0", now, HashSecret("e-1"), `[]`); err != nil {
		t.Fatal(err)
	}
	d, err := createApproved(s, ctx, "user:otto", NewDeployment{PackageID: chromeMSI.PackageID, Name: "chrome", Rings: allRing, MaxFailurePct: 100})
	if err != nil {
		t.Fatal(err)
	}
	if tg := targetOf(t, s, d.DeploymentID); tg.State != "pending" {
		t.Fatalf("without inventory: %s", tg.State)
	}
	res := checkinAs(t, s, "e-1", w11_24H2+" (26100.6899)", 26100, []InventoryItem{{Kind: "product", ID: "Mozilla Firefox", Name: "Mozilla Firefox (x64 en-US)", Version: "144.0"}})
	if offered(res, chromeMSI.PackageID) {
		t.Fatal("Chrome offered to a machine without Chrome")
	}
	if tg := targetOf(t, s, d.DeploymentID); tg.State != "not_applicable" || tg.Detail != notInstalledDetail {
		t.Fatalf("after inventory: %s (%s)", tg.State, tg.Detail)
	}
}

// Rollback of an EXE app with entries in both registry views: the entry at
// the package's version is found even when another entry comes first.
func TestRollbackPresentSeveralEntries(t *testing.T) {
	inv := []InventoryItem{
		{Kind: "product", ID: "7-Zip", Name: "7-Zip 24.09 (x64)", Version: "24.09"},
		{Kind: "product", ID: "7-Zip", Name: "7-Zip 25.01 (x64)", Version: "25.01"},
	}
	if ok, why := rollbackPresent(inv, sevenZipEXE); !ok {
		t.Fatalf("rollback present: %v %s", ok, why)
	}
}
