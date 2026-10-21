package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"offpatch/internal/acqrequest"
	"offpatch/internal/acquire/acquiretest"
	"offpatch/internal/manifest"
)

// serveApp serves a winget installer manifest for id@version with one x64
// installer of body at dl/<file>; head is the root-level text
// (InstallerType, Scope, ...).
func serveApp(t *testing.T, srv *acquiretest.Server, id, version, head, file string, body []byte) {
	t.Helper()
	sum := sha256.Sum256(body)
	srv.Vendor["dl/"+file] = body
	segs := append([]string{strings.ToLower(id[:1])}, strings.Split(id, ".")...)
	rel := "manifests/" + strings.Join(segs, "/") + "/" + version + "/" + id + ".installer.yaml"
	srv.Vendor[rel] = []byte("PackageIdentifier: " + id + "\nPackageVersion: " + version + "\n" + head +
		"Installers:\n- Architecture: x64\n  InstallerUrl: " + srv.URL + "/vendor/dl/" + file + "\n  InstallerSha256: " +
		strings.ToUpper(hex.EncodeToString(sum[:])) + "\nManifestType: installer\n")
}

const testMsPublisher = "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"

// msixBody is a minimal MSIX container (the identity is all pmctl reads).
func msixBody(t *testing.T, name, version string) []byte {
	return makeZip(t, [][2]string{
		{"AppxManifest.xml", `<?xml version="1.0" encoding="utf-8"?><Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">` +
			`<Identity Name="` + name + `" Publisher="` + testMsPublisher + `" Version="` + version + `" ProcessorArchitecture="x64"/></Package>`},
		{"AppxSignature.p7x", "sig"}, {"app/notes.exe", "MZ notes"}})
}

// The app formats from requests: a per-user installer (balenaEtcher), a
// single-exe portable app (Rufus) and an MSIX package become packages for
// agents 0.10.0+, in a bundle of their own; an unsigned portable app and an
// MSIX that is not the package winget names are unsupported.
func TestRequestAppFormats(t *testing.T) {
	stubAuthenticode(t)
	stubExeVerify(t, "Contoso Ltd")
	authenticodeAnywhere = true
	t.Cleanup(func() { authenticodeAnywhere = false })
	e, reqDir := requestEnv(t)
	serveApp(t, e.srv, "Balena.Etcher", "2.1.0", "InstallerType: nullsoft\nScope: user\nAppsAndFeaturesEntries:\n- DisplayName: balenaEtcher\n  DisplayVersion: 2.1.0\n",
		"balenaEtcher-Setup-2.1.0.exe", []byte("MZ etcher setup"))
	serveApp(t, e.srv, "Akeo.Rufus", "4.6", "InstallerType: portable\nCommands:\n- rufus\n", "rufus-4.6.exe", []byte("MZ rufus"))
	serveApp(t, e.srv, "Contoso.Unsigned", "1.0", "InstallerType: portable\n", "tool.exe", []byte("MZ unsigned tool"))
	serveApp(t, e.srv, "Contoso.Notes", "2.1.0", "InstallerType: msix\nPackageFamilyName: Contoso.Notes_8wekyb3d8bbwe\n", "notes.msix", msixBody(t, "Contoso.Notes", "2.1.0.0"))
	serveApp(t, e.srv, "Contoso.Wrong", "1.0", "InstallerType: msix\nPackageFamilyName: Contoso.Wrong_8wekyb3d8bbwe\n", "wrong.msix", msixBody(t, "Contoso.Other", "1.0.0.0"))
	app := func(id, v string) acqrequest.App {
		return acqrequest.App{WingetID: id, Version: v, Architectures: []string{"x64"}, Endpoints: 1}
	}
	writeRequest(t, reqDir, "acq-request-formats.json", acqrequest.Request{Apps: []acqrequest.App{
		app("Balena.Etcher", "2.1.0"), app("Akeo.Rufus", "4.6"), app("Contoso.Unsigned", "1.0"), app("Contoso.Notes", "2.1.0"), app("Contoso.Wrong", "1.0")}})

	rep := runRequests(t, e)
	checkItems(t, rep.Items, "acq-request-formats", map[string][2]string{
		"Balena.Etcher": {"fetched", ""}, "Akeo.Rufus": {"fetched", ""}, "Contoso.Notes": {"fetched", ""},
		"Contoso.Unsigned": {"unsupported", "the portable app's program is not validly signed"},
		"Contoso.Wrong":    {"unsupported", "the MSIX package is not the one the winget manifest names"},
	})
	pkgs := map[string]manifest.Package{}
	bundleOf := map[string]string{}
	for _, m := range e.bundles() {
		for _, p := range m.Packages {
			pkgs[p.PackageID] = p
			bundleOf[p.PackageID] = m.BundleID
		}
	}
	et := pkgs["Balena.Etcher-2.1.0"]
	if et.Kind != manifest.KindExe || et.Exe == nil || et.Exe.Scope != manifest.ExeScopeUser || et.Exe.Detect.DisplayName != "balenaEtcher" || et.Archive != nil {
		t.Errorf("per-user package: %+v %+v", et, et.Exe)
	}
	ru := pkgs["Akeo.Rufus-4.6"]
	if ru.Kind != manifest.KindPortable || ru.Portable == nil || ru.Archive != nil || ru.Portable.Command != "rufus-4.6.exe" || ru.Portable.Signer != "Contoso Ltd" ||
		ru.Portable.ARPKey != "DSSPatcher.Akeo.Rufus" || !strings.HasSuffix(ru.File.Name, ".exe") || ru.VendorSignature.Status != "valid" {
		t.Errorf("portable package: %+v %+v", ru, ru.Portable)
	}
	no := pkgs["Contoso.Notes-2.1.0"]
	if no.Kind != manifest.KindMsix || no.Msix == nil || no.Msix.PackageFamilyName != "Contoso.Notes_8wekyb3d8bbwe" || no.Msix.Version != "2.1.0.0" ||
		no.Version != "2.1.0.0" || no.Msix.Signer != "test vendor" || !strings.HasSuffix(no.File.Name, ".msix") || no.Msix.Bundle {
		t.Errorf("msix package: %+v %+v", no, no.Msix)
	}
	if b := bundleOf["Balena.Etcher-2.1.0"]; b == "" || b != bundleOf["Akeo.Rufus-4.6"] || b != bundleOf["Contoso.Notes-2.1.0"] {
		t.Errorf("app formats not in one bundle of their own: %v", bundleOf)
	}
	for id, b := range bundleOf {
		p := pkgs[id]
		if g := p.FormatGeneration(); g != 2 && b == bundleOf["Akeo.Rufus-4.6"] {
			t.Errorf("%s (generation %d) shares a bundle with the app formats", id, g)
		}
	}
}

// pmctl build re-verifies an archive package against its zip: a payload
// whose files differ from the manifest's list is left out.
func TestCheckPayloadArchive(t *testing.T) {
	stubExeVerify(t, "Contoso Ltd")
	dir := t.TempDir()
	body := makeZip(t, [][2]string{{"app/setup.exe", "MZ setup"}, {"app/data.cab", "cab"}})
	zp := dir + "/a.zip"
	if err := os.WriteFile(zp, body, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
	p := manifest.Package{Kind: manifest.KindExe, Exe: &manifest.ExeInstall{Signer: "Contoso Ltd", Scope: manifest.ExeScopeMachine},
		Archive: &manifest.Archive{Format: "zip", Entry: "app/setup.exe", Files: []manifest.ArchiveFile{
			{Path: "app/setup.exe", Size: 8, SHA256: sum("MZ setup")}, {Path: "app/data.cab", Size: 3, SHA256: sum("cab")}}}}
	if vs, handled, err := checkPayload(p, zp); !handled || err != nil || vs.Status != "valid" {
		t.Fatalf("good archive: %v %v %+v", handled, err, vs)
	}
	p.Archive.Files[1].SHA256 = sum("other")
	if _, _, err := checkPayload(p, zp); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("tampered archive accepted: %v", err)
	}
	p.Archive.Files = p.Archive.Files[:1]
	if _, _, err := checkPayload(p, zp); err == nil {
		t.Fatal("archive with an unlisted file accepted")
	}
}
