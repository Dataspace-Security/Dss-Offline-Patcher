package e2e

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"offpatch/internal/agent"
	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

// zipOf returns a zip of path → content and the manifest's file list.
func zipOf(t *testing.T, files [][2]string) (string, []manifest.ArchiveFile) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	var list []manifest.ArchiveFile
	for _, f := range files {
		w, err := zw.Create(f[0])
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(f[1]))
		h := sha256.Sum256([]byte(f[1]))
		list = append(list, manifest.ArchiveFile{Path: f[0], Size: int64(len(f[1])), SHA256: hex.EncodeToString(h[:])})
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String(), list
}

func formatPkg(id, title, kind, version string) manifest.Package {
	return manifest.Package{PackageID: id, Title: title, Vendor: "Vendor", Kind: kind, Version: version, Severity: "important", ReleaseDate: "2026-10-16",
		Supersedes: []string{}, Applicability: manifest.Applicability{OS: "windows", Arch: "x64"}, SourceURL: "https://vendor.example/" + id,
		VendorSignature: manifest.VendorSignature{Status: "valid", Signer: "Vendor Inc."}}
}

// The app formats end to end (agents 0.10.0, simulated platform): an
// archive package (Acrobat's setup.exe with its .msi, .cab and setup.ini),
// a portable app in a zip, an MSIX package and a per-user installer go
// through intake, deployment and install, and each target is verified from
// the inventory the agent sends right after the install. An archive whose
// files differ from the signed list is refused as tampering; a per-user
// installer waits (deferred, no attempt used) until a user signs in; a
// portable app that is running is retried later.
func TestAppFormatsEndToEnd(t *testing.T) {
	e := newEnv(t)
	acroZip, acroFiles := zipOf(t, [][2]string{{"Adobe Acrobat/setup.exe", "MZ adobe setup"}, {"Adobe Acrobat/AcroPro.msi", "msi"},
		{"Adobe Acrobat/Data1.cab", "cab"}, {"Adobe Acrobat/setup.ini", "[Startup]"}})
	acro := formatPkg("Adobe.Acrobat.Pro-25.001", "Adobe Acrobat", manifest.KindExe, "25.001.20531")
	acro.PackageName = "Adobe Acrobat (64-bit)"
	acro.Exe = &manifest.ExeInstall{InstallerType: "exe", SilentArgs: []string{"/sAll", "/rs", "/msi", "EULA_ACCEPT=YES"}, SuccessCodes: []int{0, 3010, 1641},
		Signer: "Adobe Inc.", Scope: manifest.ExeScopeMachine, Detect: manifest.ExeDetect{DisplayName: "Adobe Acrobat (64-bit)", DisplayVersion: "25.001.20531"}}
	acro.Archive = &manifest.Archive{Format: "zip", Entry: "Adobe Acrobat/setup.exe", Files: acroFiles}
	// Tampered: the signed list says one thing, the zip holds another.
	bad := acro
	bad.PackageID, bad.Title = "Contoso.Bad-1.0", "Contoso Bad"
	bad.Exe = &manifest.ExeInstall{InstallerType: "exe", SilentArgs: []string{"/S"}, SuccessCodes: []int{0}, Signer: "Contoso", Scope: manifest.ExeScopeMachine,
		Detect: manifest.ExeDetect{DisplayName: "Contoso Bad", DisplayVersion: "1.0"}}
	bad.PackageName, bad.Version = "Contoso Bad", "1.0"
	badList := append([]manifest.ArchiveFile{}, acroFiles...)
	badList[2].SHA256 = strings.Repeat("0", 64)
	bad.Archive = &manifest.Archive{Format: "zip", Entry: "Adobe Acrobat/setup.exe", Files: badList}

	rufusZip, rufusFiles := zipOf(t, [][2]string{{"rufus.exe", "MZ rufus"}, {"README.txt", "readme"}})
	rufus := formatPkg("Akeo.Rufus-4.6", "Rufus", manifest.KindPortable, "4.6")
	rufus.PackageName = "Rufus"
	rufus.Portable = &manifest.Portable{Folder: "Akeo.Rufus", Command: "rufus.exe", Signer: "Akeo Consulting", ARPKey: "DSSPatcher.Akeo.Rufus",
		DisplayName: "Rufus", DisplayVersion: "4.6", Shortcut: "Rufus"}
	rufus.Archive = &manifest.Archive{Format: "zip", Entry: "rufus.exe", Files: rufusFiles}

	term := formatPkg("Microsoft.WindowsTerminal-1.21", "Windows Terminal", manifest.KindMsix, "1.21.2361.0")
	term.PackageName = "Windows Terminal"
	term.Msix = &manifest.Msix{PackageFamilyName: "Microsoft.WindowsTerminal_8wekyb3d8bbwe", Name: "Microsoft.WindowsTerminal",
		Publisher: "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US", Version: "1.21.2361.0"}

	etcher := formatPkg("Balena.Etcher-2.1.0", "balenaEtcher", manifest.KindExe, "2.1.0")
	etcher.PackageName = "balenaEtcher"
	etcher.Exe = &manifest.ExeInstall{InstallerType: "nullsoft", SilentArgs: []string{"/S"}, SuccessCodes: []int{0}, Signer: "Balena Ltd",
		Scope: manifest.ExeScopeUser, Detect: manifest.ExeDetect{DisplayName: "balenaEtcher", DisplayVersion: "2.1.0"}}

	pkgs := map[string]manifest.Package{acro.PackageID: acro, bad.PackageID: bad, rufus.PackageID: rufus, term.PackageID: term, etcher.PackageID: etcher}
	files := map[string]string{acro.PackageID: e.payload("acro.zip", acroZip), bad.PackageID: e.payload("bad.zip", acroZip),
		rufus.PackageID: e.payload("rufus.zip", rufusZip), term.PackageID: e.payload("term.msixbundle", "msix bundle"),
		etcher.PackageID: e.payload("etcher.exe", "MZ etcher")}
	term.Msix.Bundle = true
	pkgs[term.PackageID] = term
	if b := e.transferAndIntake(e.bundle(bundleOpts{seq: 1}, pkgs, files)); b.State != "validated" {
		t.Fatalf("intake: %+v", b)
	}
	var got store.Package
	if c := e.api("GET", "/api/packages/"+rufus.PackageID, tokViewer, nil, &got); c != 200 || got.Portable == nil || got.Archive == nil || got.Portable.ARPKey != rufus.Portable.ARPKey {
		t.Fatalf("stored portable package: %d %+v", c, got)
	}
	for id := range pkgs {
		e.approve(id)
	}

	inv := []store.InventoryItem{
		{Kind: "product", ID: "{AC76BA86-1033-FFFF-7760-BC15014EA700}", Name: "Adobe Acrobat (64-bit)", Version: "24.005.20320"},
		{Kind: "product", ID: "ContosoBad", Name: "Contoso Bad", Version: "0.9"},
		{Kind: "product", ID: "Akeo.Rufus_Microsoft.Winget.Source_8wekyb3d8bbwe", Name: "Rufus", Version: "4.5"},
		{Kind: "appx", ID: "Microsoft.WindowsTerminal_8wekyb3d8bbwe", Name: "Microsoft.WindowsTerminal", Version: "1.20.11781.0", Source: "msstore"},
		{Kind: "product", ID: "etcher-user", Name: "balenaEtcher", Version: "1.19.25", Scope: "user"},
	}
	seed, _ := json.Marshal(map[string]any{"products": inv})
	pc := e.enroll("pc-formats", []string{"pilot"}, agent.SimConfig{NoUserSession: true, RunningApps: []string{"Akeo.Rufus"}})
	os.WriteFile(filepath.Join(pc.dir, "sim-state.json"), seed, 0o600)
	e.cycle(pc)
	// An endpoint whose agent predates the formats is never offered them.
	old := e.enroll("pc-formats-old", []string{"pilot"}, agent.SimConfig{})
	oldCheckin := store.CheckinRequest{Hostname: "pc-formats-old", OSVersion: "Windows 10", Build: 19045, Arch: "x64", AgentVersion: "0.9.8", Inventory: inv}
	if _, err := e.st.Checkin(context.Background(), old.id, oldCheckin); err != nil {
		t.Fatal(err)
	}

	ring := []store.Ring{{Name: "pilot", Groups: []string{"pilot"}}}
	deps := map[string]string{}
	for id := range pkgs {
		deps[id] = e.deploy(store.NewDeployment{PackageID: id, Name: id, Rings: ring, MaxRetries: 5, MaxFailurePct: 100}).DeploymentID
	}
	tooOld := map[string]string{acro.PackageID: manifest.AgentTooOldForArchive, rufus.PackageID: manifest.AgentTooOldForPortable,
		term.PackageID: manifest.AgentTooOldForMsix, etcher.PackageID: manifest.AgentTooOldForPerUser}
	for id, want := range tooOld {
		for _, tg := range e.deployment(deps[id]).Targets {
			if tg.EndpointID == old.id && (tg.State != "not_applicable" || tg.Detail != want) {
				t.Fatalf("%s: old agent target %+v", id, tg)
			}
		}
	}
	if res, err := e.st.Checkin(context.Background(), old.id, oldCheckin); err != nil || len(res.Assignments) != 0 {
		t.Fatalf("old agent offered app formats: %v %+v", err, res.Assignments)
	}

	e.cycle(pc) // installs; the per-user installer waits, the running portable app is retried
	state := func(id string) store.Target {
		for _, tg := range e.deployment(deps[id]).Targets {
			if tg.EndpointID == pc.id {
				return tg
			}
		}
		t.Fatalf("%s: no target", id)
		return store.Target{}
	}
	if tg := state(etcher.PackageID); tg.State != "deferred" || !strings.Contains(tg.Detail, "waiting for the user to sign in") || tg.Attempts != 0 {
		t.Fatalf("per-user target with nobody signed in: %+v", tg)
	}
	if tg := state(rufus.PackageID); tg.State != "failed" || !strings.HasPrefix(tg.Detail, "waiting: ") && !strings.Contains(tg.Detail, "the app is running") {
		t.Fatalf("running portable app: %+v", tg)
	}
	if tg := state(bad.PackageID); tg.State != "failed" || !strings.Contains(tg.Detail, "archive does not match signed manifest") || !strings.Contains(tg.Detail, "possible tampering") {
		t.Fatalf("tampered archive: %+v", tg)
	}
	// The user signs in; the portable app is closed.
	pc.sim.SetUserSession(true)
	pc.sim.SetRunningApps(nil)
	e.cycle(pc) // fresh inventory verifies the first installs; per-user and portable install now
	e.cycle(pc) // ... and their fresh inventory verifies them
	for _, id := range []string{acro.PackageID, term.PackageID, rufus.PackageID, etcher.PackageID} {
		if tg := state(id); tg.State != "verified" || tg.Evidence == "" {
			t.Errorf("%s: %s %q (evidence %q)", id, tg.State, tg.Detail, tg.Evidence)
		}
	}
	// The apps no longer show as needed on this endpoint.
	var av []store.Available
	e.api("GET", "/api/endpoints/"+pc.id+"/available", tokViewer, nil, &av)
	for _, a := range av {
		if a.PackageID != bad.PackageID {
			t.Errorf("still available after install: %+v", a)
		}
	}
}
