package store

import (
	"strings"
	"testing"

	"offpatch/internal/manifest"
)

// Several copies of one app, per-user evidence and provisioned MSIX
// packages, through the same consistency harness (classify, needs,
// targeting, verification, unverified detail).
func copyCases() []presenceCase {
	on24 := w11_24H2 + " (26100.6899)"
	rufus := Package{PackageID: "Akeo.Rufus-4.6", Kind: manifest.KindPortable, Version: "4.6", PackageName: "Rufus",
		Portable: &manifest.Portable{Folder: "Akeo.Rufus", Command: "rufus.exe", Signer: "Akeo Consulting", ARPKey: "DSSPatcher.Akeo.Rufus", DisplayName: "Rufus", DisplayVersion: "4.6"}}
	rufusPortable := InventoryItem{Kind: "product", ID: "DSSPatcher.Akeo.Rufus", Name: "Rufus", Version: "4.6", View: "64"}
	rufusOldEXE := InventoryItem{Kind: "product", ID: "Rufus_is1", Name: "Rufus", Version: "4.1", View: "64"}
	rufusNewEXE := InventoryItem{Kind: "product", ID: "Rufus_is1", Name: "Rufus", Version: "4.6", View: "64"}
	term := Package{PackageID: "Microsoft.WindowsTerminal-1.21", Kind: manifest.KindMsix, Version: "1.21.2361.0", PackageName: "Windows Terminal",
		Msix: &manifest.Msix{PackageFamilyName: "Microsoft.WindowsTerminal_8wekyb3d8bbwe", Name: "Microsoft.WindowsTerminal", Publisher: "CN=Microsoft Corporation", Version: "1.21.2361.0"}}
	termOld := InventoryItem{Kind: "appx", ID: "Microsoft.WindowsTerminal_8wekyb3d8bbwe", Name: "Microsoft.WindowsTerminal", Version: "1.20.11781.0", Source: "msstore"}
	termProvisioned := termOld
	termProvisioned.Provisioned = "1.21.2361.0"
	termNew := termOld
	termNew.Version = "1.21.2361.0"
	acme := Package{PackageID: "Acme-3.0", Kind: "msi", Version: "3.0.0", PackageName: "Acme App", ProductCode: "{A0000000-0000-4000-8000-000000000003}"}
	return []presenceCase{
		{name: "portable copy current next to an older EXE copy: still needed, verifies once both are current", osVersion: on24, build: 26100,
			inv: []InventoryItem{rufusPortable, rufusOldEXE}, pkg: rufus, want: PresenceNeeded,
			after: []InventoryItem{rufusPortable, rufusNewEXE}, verify: true},
		{name: "portable copy current next to an older EXE copy: unverified names the outdated copy", osVersion: on24, build: 26100,
			inv: []InventoryItem{rufusPortable, rufusOldEXE}, pkg: rufus, want: PresenceNeeded,
			after: []InventoryItem{rufusPortable, rufusOldEXE}, unverified: `inventory shows Rufus 4.1, expected 4.6 or later (the outdated copy of 2: product Rufus_is1 "Rufus" 4.1)`},
		{name: "7-Zip EXE current next to an old 7-Zip MSI copy: needed", osVersion: on24, build: 26100,
			inv: []InventoryItem{{Kind: "product", ID: "7-Zip", Name: "7-Zip 25.01 (x64)", Version: "25.01"}, {Kind: "product", ID: "{23170F69-40C1-2702-1900-000001000000}", Name: "7-Zip 19.00 (x64)", Version: "19.00.00.0"}},
			pkg: sevenZipEXE, want: PresenceNeeded},
		{name: "MSIX provisioned but users still on the old build: not verified, says waiting for sign-in", osVersion: on24, build: 26100,
			inv: []InventoryItem{termOld}, pkg: term, want: PresenceNeeded,
			after: []InventoryItem{termProvisioned}, unverified: "provisioned 1.21.2361.0; waiting for users to sign in"},
		{name: "MSIX: users signed in again: verifies", osVersion: on24, build: 26100,
			inv: []InventoryItem{termOld}, pkg: term, want: PresenceNeeded, after: []InventoryItem{termNew}, verify: true},
		{name: "MSIX per-user appx entry never proves the package", osVersion: on24, build: 26100,
			inv: []InventoryItem{{Kind: "appx", ID: term.Msix.PackageFamilyName, Version: "1.21.2361.0", Scope: "user"}}, pkg: term, want: PresenceNotInstalled},
		{name: "MSI: a current per-user copy does not prove the per-machine package", osVersion: on24, build: 26100,
			inv: []InventoryItem{{Kind: "product", ID: acme.ProductCode, Name: "Acme App", Version: "3.0.0", Scope: "user"}}, pkg: acme, want: PresenceNeeded,
			after: []InventoryItem{{Kind: "product", ID: acme.ProductCode, Name: "Acme App", Version: "3.0.0"}}, verify: true},
		{name: "per-user EXE: the lowest per-user copy decides", osVersion: on24, build: 26100,
			inv: []InventoryItem{{Kind: "product", ID: "etcher-a", Name: "balenaEtcher", Version: "2.1.0", Scope: "user"}, {Kind: "product", ID: "etcher-b", Name: "balenaEtcher", Version: "1.19.25", Scope: "user"}},
			pkg: Package{PackageID: "Balena.Etcher-2.1.0", Kind: manifest.KindExe, Version: "2.1.0", PackageName: "balenaEtcher",
				Exe: &manifest.ExeInstall{InstallerType: "nullsoft", SilentArgs: []string{"/S"}, SuccessCodes: []int{0}, Signer: "Balena Ltd", Scope: manifest.ExeScopeUser,
					Detect: manifest.ExeDetect{DisplayName: "balenaEtcher", DisplayVersion: "2.1.0"}}},
			want: PresenceNeeded},
	}
}

func TestPresenceSeveralCopies(t *testing.T) {
	for _, c := range copyCases() {
		t.Run(c.name, func(t *testing.T) { runPresenceCase(t, c) })
	}
}

// The verdict says which copy is outdated, and an MSIX package waiting for
// sign-ins says so.
func TestClassifyNamesOutdatedCopy(t *testing.T) {
	cs := copyCases()
	e := Endpoint{OS: "windows", OSVersion: cs[0].osVersion, Build: 26100, Arch: "x64"}
	p := cs[0].pkg
	p.Applicability = manifest.Applicability{OS: "windows", Arch: "x64"}
	v := classify(p, e, osFacts(e.OSVersion, e.Build), cs[0].inv, nil)
	if v.Presence != PresenceNeeded || v.Have != "4.1" || !strings.Contains(v.Why, `outdated copy: product Rufus_is1 "Rufus" 4.1`) {
		t.Errorf("portable: %+v", v)
	}
	m := cs[3].pkg
	m.Applicability = p.Applicability
	v = classify(m, e, osFacts(e.OSVersion, e.Build), cs[3].after, nil)
	if v.Presence != PresenceNeeded || !strings.Contains(v.Why, "provisioned 1.21.2361.0; waiting for users to sign in") || !strings.Contains(v.Why, "1.20.11781.0") {
		t.Errorf("msix: %+v", v)
	}
}
