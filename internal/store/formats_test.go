package store

import (
	"context"
	"strings"
	"testing"

	"offpatch/internal/manifest"
)

// Packages of the app formats (agents 0.10.0+), with the inventory line the
// agent reports for the old version and for the version they install.
type formatCase struct {
	name     string
	pkg      Package
	old, new InventoryItem
	tooOld   string
}

func formatCases() []formatCase {
	sum := strings.Repeat("a", 64)
	acro := Package{PackageID: "Adobe.Acrobat.Pro-25.001", Kind: manifest.KindExe, Version: "25.001.20531", PackageName: "Adobe Acrobat (64-bit)",
		Exe: &manifest.ExeInstall{InstallerType: "exe", SilentArgs: []string{"/sAll"}, SuccessCodes: []int{0}, Signer: "Adobe Inc.", Scope: manifest.ExeScopeMachine,
			Detect: manifest.ExeDetect{DisplayName: "Adobe Acrobat (64-bit)", DisplayVersion: "25.001.20531"}},
		Archive: &manifest.Archive{Format: "zip", Entry: "Adobe Acrobat/setup.exe", Files: []manifest.ArchiveFile{{Path: "Adobe Acrobat/setup.exe", Size: 1, SHA256: sum}}}}
	etcher := Package{PackageID: "Balena.Etcher-2.1.0", Kind: manifest.KindExe, Version: "2.1.0", PackageName: "balenaEtcher",
		Exe: &manifest.ExeInstall{InstallerType: "nullsoft", SilentArgs: []string{"/S"}, SuccessCodes: []int{0}, Signer: "Balena Ltd", Scope: manifest.ExeScopeUser,
			Detect: manifest.ExeDetect{DisplayName: "balenaEtcher", DisplayVersion: "2.1.0"}}}
	rufus := Package{PackageID: "Akeo.Rufus-4.6", Kind: manifest.KindPortable, Version: "4.6", PackageName: "Rufus",
		Portable: &manifest.Portable{Folder: "Akeo.Rufus", Command: "rufus.exe", Signer: "Akeo Consulting", ARPKey: "DSSPatcher.Akeo.Rufus", DisplayName: "Rufus", DisplayVersion: "4.6"}}
	term := Package{PackageID: "Microsoft.WindowsTerminal-1.21", Kind: manifest.KindMsix, Version: "1.21.2361.0", PackageName: "Windows Terminal",
		Msix: &manifest.Msix{PackageFamilyName: "Microsoft.WindowsTerminal_8wekyb3d8bbwe", Name: "Microsoft.WindowsTerminal", Publisher: "CN=Microsoft Corporation", Version: "1.21.2361.0"}}
	return []formatCase{
		{"archive", acro, InventoryItem{Kind: "product", ID: "{AC76BA86-1033-FFFF-7760-BC15014EA700}", Name: "Adobe Acrobat (64-bit)", Version: "24.005.20320"},
			InventoryItem{Kind: "product", ID: "{AC76BA86-1033-FFFF-7760-BC15014EA700}", Name: "Adobe Acrobat (64-bit)", Version: "25.001.20531"}, manifest.AgentTooOldForArchive},
		{"per-user", etcher, InventoryItem{Kind: "product", ID: "a0c9b8e4-etcher", Name: "balenaEtcher 1.19.25", Version: "1.19.25", Scope: "user"},
			InventoryItem{Kind: "product", ID: "a0c9b8e4-etcher", Name: "balenaEtcher 2.1.0", Version: "2.1.0", Scope: "user"}, manifest.AgentTooOldForPerUser},
		{"portable", rufus, InventoryItem{Kind: "product", ID: "Akeo.Rufus_Microsoft.Winget.Source_8wekyb3d8bbwe", Name: "Rufus", Version: "4.5"},
			InventoryItem{Kind: "product", ID: "DSSPatcher.Akeo.Rufus", Name: "Rufus", Version: "4.6"}, manifest.AgentTooOldForPortable},
		{"msix", term, InventoryItem{Kind: "appx", ID: "Microsoft.WindowsTerminal_8wekyb3d8bbwe", Name: "Microsoft.WindowsTerminal", Version: "1.20.11781.0", Source: "msstore"},
			InventoryItem{Kind: "appx", ID: "Microsoft.WindowsTerminal_8wekyb3d8bbwe", Name: "Microsoft.WindowsTerminal", Version: "1.21.2361.0", Source: "msstore"}, manifest.AgentTooOldForMsix},
	}
}

// Matching as the agent does it: the old version is installed and needs
// the update, the new one verifies; scope and kind are respected.
func TestFormatsMatching(t *testing.T) {
	e := Endpoint{OS: "windows", Arch: "x64", AgentVersion: "0.10.0"}
	for _, c := range formatCases() {
		c.pkg.Applicability = manifest.Applicability{OS: "windows", Arch: "x64"}
		if !appInstalled([]InventoryItem{c.old}, c.pkg) {
			t.Errorf("%s: old version not recognised as the app", c.name)
		}
		if need, have, _ := needs(c.pkg, e, []InventoryItem{c.old}, nil); !need || have != c.old.Version {
			t.Errorf("%s: needs %v %q", c.name, need, have)
		}
		if ok, _, _ := presentOn([]InventoryItem{c.old}, OSFacts{}, c.pkg, nil); ok {
			t.Errorf("%s: old version verified", c.name)
		}
		if ok, why, ev := presentOn([]InventoryItem{c.new}, OSFacts{}, c.pkg, nil); !ok || !strings.Contains(why, c.new.Version) || ev == "" {
			t.Errorf("%s: new version not verified: %v %q %q", c.name, ok, why, ev)
		}
		if need, _, _ := needs(c.pkg, e, []InventoryItem{c.new}, nil); need {
			t.Errorf("%s: still needed at the new version", c.name)
		}
		if appInstalled(nil, c.pkg) {
			t.Errorf("%s: installed on an empty inventory", c.name)
		}
	}
	// Scope: a per-user installer counts per-user entries only, a machine
	// package machine entries only; portable apps are per machine.
	cs := formatCases()
	etcher, rufus := cs[1].pkg, cs[2].pkg
	machineEtcher := cs[1].new
	machineEtcher.Scope = ""
	if exeAppMatch(etcher, machineEtcher) || appInstalled([]InventoryItem{machineEtcher}, etcher) {
		t.Error("per-user package matched a machine-wide entry")
	}
	userRufus := cs[2].new
	userRufus.Scope = "user"
	if portableMatch(rufus, userRufus) {
		t.Error("portable app matched a per-user entry")
	}
	machine := etcher
	machine.Exe = &manifest.ExeInstall{Scope: manifest.ExeScopeMachine, Detect: etcher.Exe.Detect}
	if exeIdentity(machine) == exeIdentity(etcher) {
		t.Error("per-user and machine packages of one app share an identity")
	}
	// Another family name or app never matches.
	other := cs[3].new
	other.ID = "Microsoft.WindowsNotepad_8wekyb3d8bbwe"
	if msixMatch(cs[3].pkg, other) {
		t.Error("MSIX matched another family")
	}
	// Rollback support.
	for want, p := range map[string]Package{RollbackMsix: cs[3].pkg, RollbackPerUser: etcher, "": rufus} {
		if got := RollbackUnsupported(p); got != want {
			t.Errorf("%s: rollback %q, want %q", p.PackageID, got, want)
		}
	}
	if ok, _ := rollbackPresent([]InventoryItem{cs[2].new}, rufus); !ok {
		t.Error("portable rollback: installed version not found")
	}
}

// Targets on agents before 0.10.0 are not_applicable with the format's
// detail and never assigned; after the upgrade they are in scope again.
func TestFormatsAgentGate(t *testing.T) {
	ctx := context.Background()
	for _, c := range formatCases() {
		s := openTest(t)
		addPackage(t, s, c.pkg)
		addEndpoint(t, s, "e1", []string{"pilot"}, []InventoryItem{c.old})
		addEndpoint(t, s, "e2", []string{"pilot"}, []InventoryItem{c.old}) // keeps the deployment active
		s.db.Exec(`UPDATE endpoints SET agent_version='0.9.8' WHERE endpoint_id='e1'`)
		d := newDeployment(t, s, c.pkg.PackageID, allRing, 3)
		if st, _ := targetRow(t, s, d.DeploymentID, "e1"); st != "not_applicable" {
			t.Fatalf("%s: old agent target %s", c.name, st)
		}
		dd, _ := s.GetDeployment(ctx, d.DeploymentID)
		for _, tg := range dd.Targets {
			if tg.EndpointID == "e1" && tg.Detail != c.tooOld {
				t.Fatalf("%s: detail %q", c.name, tg.Detail)
			}
		}
		res, err := s.Checkin(ctx, "e1", CheckinRequest{Hostname: "host-e1", OSVersion: "Windows 10", Build: 19045, Arch: "x64", AgentVersion: "0.9.8", Inventory: []InventoryItem{c.old}})
		if err != nil || len(res.Assignments) != 0 {
			t.Fatalf("%s: old agent offered the package: %v %+v", c.name, err, res.Assignments)
		}
		res, err = s.Checkin(ctx, "e1", CheckinRequest{Hostname: "host-e1", OSVersion: "Windows 10", Build: 19045, Arch: "x64", AgentVersion: "0.10.0", Inventory: []InventoryItem{c.old}})
		if err != nil || len(res.Assignments) != 1 || res.Assignments[0].Kind != c.pkg.Kind {
			t.Fatalf("%s: upgraded agent: %v %+v", c.name, err, res.Assignments)
		}
	}
	// EXE packages keep their own (older) gate.
	if why := agentGate(vcredist("x64", true), Endpoint{AgentVersion: "0.9.8"}); why != "" {
		t.Errorf("machine EXE gated on 0.9.8: %q", why)
	}
	for v, want := range map[string]bool{"0.10.0": true, "0.10.1": true, "1.0": true, "0.9.8": false, "": false, "dev": false} {
		if AgentSupportsFormats(v) != want {
			t.Errorf("AgentSupportsFormats(%q) != %v", v, want)
		}
	}
}

// A completed install flips the target to verified with the inventory the
// agent sends right after it, the app leaves "needed", and the fleet views'
// generation moves on (the server's caches are rebuilt).
func TestFormatsVerifiedAfterInstall(t *testing.T) {
	ctx := context.Background()
	for _, c := range formatCases() {
		s := openTest(t)
		addPackage(t, s, c.pkg)
		addEndpoint(t, s, "e1", []string{"pilot"}, []InventoryItem{c.old})
		d := newDeployment(t, s, c.pkg.PackageID, allRing, 3)
		res := checkin(t, s, "e1", []InventoryItem{c.old}, false)
		if len(res.Assignments) != 1 {
			t.Fatalf("%s: assignments %+v", c.name, res.Assignments)
		}
		if n, _ := s.Needs(ctx); n[c.pkg.PackageID].Needed != 1 {
			t.Fatalf("%s: not needed before install: %+v", c.name, n[c.pkg.PackageID])
		}
		report(t, s, d.DeploymentID, "e1", c.pkg.PackageID, "installing", "", 0)
		report(t, s, d.DeploymentID, "e1", c.pkg.PackageID, "installed", "done", 0)
		gen := s.Generation()
		checkin(t, s, "e1", []InventoryItem{c.new}, false)
		st, _ := targetRow(t, s, d.DeploymentID, "e1")
		if st != "verified" {
			t.Fatalf("%s: target %s after the fresh inventory", c.name, st)
		}
		if s.Generation() == gen {
			t.Errorf("%s: generation did not move after the inventory changed", c.name)
		}
		n, _ := s.Needs(ctx)
		if pn := n[c.pkg.PackageID]; pn.Needed != 0 || pn.UpToDate != 1 || pn.Verified != 1 {
			t.Errorf("%s: needs after install: %+v", c.name, pn)
		}
		if av, _ := s.AvailableFor(ctx, "e1"); len(av) != 0 {
			t.Errorf("%s: still available: %+v", c.name, av)
		}
	}
}
