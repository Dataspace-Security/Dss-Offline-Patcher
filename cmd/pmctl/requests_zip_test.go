package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"offpatch/internal/acqrequest"
	"offpatch/internal/acquire"
	"offpatch/internal/acquire/acquiretest"
	"offpatch/internal/manifest"
	"offpatch/internal/msi/msitest"
)

const zipMSICode = "{2B3F7C10-5D2E-4C8A-9B61-3E0F5A7D9C42}"

// makeZip returns a zip of name → content.
func makeZip(t *testing.T, files [][2]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range files {
		w, err := zw.Create(f[0])
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(f[1]))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// serveZipApp serves a winget installer manifest for id@version whose
// installer is a zip with files, at <id>.zip. head is the manifest's
// installer-level text (NestedInstallerType etc.) for one x64 installer.
func serveZipApp(t *testing.T, srv *acquiretest.Server, id, version, head string, files [][2]string) []byte {
	t.Helper()
	body := makeZip(t, files)
	sum := sha256.Sum256(body)
	srv.Vendor["dl/"+id+".zip"] = body
	segs := append([]string{strings.ToLower(id[:1])}, strings.Split(id, ".")...)
	rel := "manifests/" + strings.Join(segs, "/") + "/" + version + "/" + id + ".installer.yaml"
	srv.Vendor[rel] = []byte("PackageIdentifier: " + id + "\nPackageVersion: " + version + "\nInstallerType: zip\n" + head +
		"Installers:\n- Architecture: x64\n  InstallerUrl: " + srv.URL + "/vendor/dl/" + id + ".zip\n  InstallerSha256: " +
		strings.ToUpper(hex.EncodeToString(sum[:])) + "\nManifestType: installer\n")
	return body
}

// Apps whose winget installer is a zip: the MSI or EXE named by
// NestedInstallerFiles is extracted and packaged on its own (ProductCode
// read from it, signature checked on it, provenance naming the zip); a
// setup.exe that needs the zip's other files, a portable app and a zip
// without the named file are unsupported with a clear reason.
func TestRequestZipInstallers(t *testing.T) {
	stubAuthenticode(t)
	stubExeVerify(t, "Contoso Ltd")
	e, reqDir := requestEnv(t)
	msiBody := string(msitest.MSI([][2]string{{"ProductCode", zipMSICode}, {"ProductName", "Contoso Tool"}, {"ProductVersion", "1.2.0"}}, msitest.Options{}))
	exeBody := "MZ contoso setup"
	serveZipApp(t, e.srv, "Contoso.ZipMsi", "1.2.0", "NestedInstallerType: wix\nNestedInstallerFiles:\n- RelativeFilePath: Contoso\\ContosoTool.msi\n"+
		"AppsAndFeaturesEntries:\n- DisplayName: Contoso Tool\n",
		[][2]string{{"Contoso/ContosoTool.msi", msiBody}, {"Contoso/README.txt", "read me"}})
	zipExe := serveZipApp(t, e.srv, "Contoso.ZipExe", "2.0.0", "NestedInstallerType: inno\nNestedInstallerFiles:\n- RelativeFilePath: setup/contoso-setup.exe\nScope: machine\n"+
		"AppsAndFeaturesEntries:\n- DisplayName: Contoso Editor\n",
		[][2]string{{"setup/contoso-setup.exe", exeBody}})
	serveZipApp(t, e.srv, "Contoso.Portable", "1.0.0", "NestedInstallerType: portable\nNestedInstallerFiles:\n- RelativeFilePath: tool.exe\n  PortableCommandAlias: tool\n",
		[][2]string{{"tool.exe", "MZ tool"}})
	serveZipApp(t, e.srv, "Contoso.ZipMissing", "1.0.0", "NestedInstallerType: msi\nNestedInstallerFiles:\n- RelativeFilePath: Tool.msi\n",
		[][2]string{{"Other.msi", msiBody}})
	// Adobe Acrobat: setup.exe runs the .msi, cabinets and patches next to it.
	const acro = "a/Adobe/Acrobat/Pro/25.001.20756/Adobe.Acrobat.Pro.installer.yaml"
	wingetFixtures(t, e.srv, acro)
	acroZip := makeZip(t, [][2]string{{"Adobe Acrobat/setup.exe", "MZ adobe setup"}, {"Adobe Acrobat/AcroPro.msi", msiBody},
		{"Adobe Acrobat/Data1.cab", "cab"}, {"Adobe Acrobat/setup.ini", "[Startup]"}, {"Adobe Acrobat/AcrobatDCx64Upd.msp", "msp"}})
	for name, b := range e.srv.Vendor {
		if strings.HasSuffix(name, "Acrobat_DC_Web_x64_WWMUI.zip") {
			old := sha256.Sum256(b)
			sum := sha256.Sum256(acroZip)
			e.srv.Vendor[name] = acroZip
			m := "manifests/" + acro
			e.srv.Vendor[m] = []byte(strings.Replace(string(e.srv.Vendor[m]), strings.ToUpper(hex.EncodeToString(old[:])), strings.ToUpper(hex.EncodeToString(sum[:])), 1))
		}
	}
	app := func(id, v string) acqrequest.App {
		return acqrequest.App{WingetID: id, Version: v, Architectures: []string{"x64"}, Endpoints: 1}
	}
	writeRequest(t, reqDir, "acq-request-zip.json", acqrequest.Request{Apps: []acqrequest.App{
		app("Contoso.ZipMsi", "1.2.0"), app("Contoso.ZipExe", "2.0.0"), app("Contoso.Portable", "1.0.0"),
		app("Contoso.ZipMissing", "1.0.0"), app("Adobe.Acrobat.Pro", "25.001.20756")}})

	rep := runRequests(t, e)
	checkItems(t, rep.Items, "acq-request-zip", map[string][2]string{
		"Contoso.ZipMsi": {"fetched", ""}, "Contoso.ZipExe": {"fetched", ""},
		"Contoso.Portable":   {"unsupported", "zip with a portable app (no installer)"},
		"Contoso.ZipMissing": {"unsupported", "the zip cannot be used: the zip has no Tool.msi"},
		"Adobe.Acrobat.Pro":  {"unsupported", acquire.ReasonZipSiblings},
	})
	if w := strings.Join(rep.Warnings, "\n"); !strings.Contains(w, "Adobe Acrobat/setup.exe in the zip") || !strings.Contains(w, "AcroPro.msi") {
		t.Errorf("Acrobat warning does not name the files: %s", w)
	}

	pkgs := map[string]manifest.Package{}
	for _, m := range e.bundles() {
		for _, p := range m.Packages {
			pkgs[p.PackageID] = p
		}
	}
	msiSum, exeSum := sha256.Sum256([]byte(msiBody)), sha256.Sum256([]byte(exeBody))
	zm, ok := pkgs["Contoso.ZipMsi-1.2.0"]
	if !ok || zm.Kind != "msi" || zm.ProductCode != zipMSICode || zm.File.SHA256 != hex.EncodeToString(msiSum[:]) ||
		zm.File.Size != int64(len(msiBody)) || zm.SourceURL != e.srv.URL+"/vendor/dl/Contoso.ZipMsi.zip" || zm.PackageName != "Contoso Tool" {
		t.Errorf("zip MSI package: %+v", zm)
	}
	ze, ok := pkgs["Contoso.ZipExe-2.0.0"]
	if !ok || ze.Kind != manifest.KindExe || ze.Exe.InstallerType != "inno" || ze.Exe.Signer != "Contoso Ltd" || ze.File.SHA256 != hex.EncodeToString(exeSum[:]) {
		t.Errorf("zip EXE package: %+v %+v", ze, ze.Exe)
	}

	// The spec records where the files came from.
	specs, _ := filepath.Glob(filepath.Join(e.dir, "work", "runs", "*", "spec.json"))
	found := 0
	for _, sp := range specs {
		b, _ := os.ReadFile(sp)
		var entries []acquire.SpecEntry
		json.Unmarshal(b, &entries)
		for _, en := range entries {
			if en.PackageID != "Contoso.ZipExe-2.0.0" {
				continue
			}
			found++
			zs := sha256.Sum256(zipExe)
			a := en.Acquired
			if a == nil || a.Method != "zip" || a.ZipSHA256 != hex.EncodeToString(zs[:]) || a.ZipSize != int64(len(zipExe)) || a.ZipPath != "setup/contoso-setup.exe" ||
				a.SHA256 != hex.EncodeToString(exeSum[:]) || !strings.Contains(a.Verified, "+unzipped(setup/contoso-setup.exe)+authenticode(Contoso Ltd)") {
				t.Errorf("provenance: %+v", a)
			}
		}
	}
	if found == 0 {
		t.Errorf("no spec entry for the zip EXE in %v", specs)
	}
	// Neither the zips nor the extraction directories are left behind.
	left, _ := filepath.Glob(filepath.Join(e.dir, "work", "downloads", "*"))
	for _, p := range left {
		if strings.HasSuffix(p, ".zip") || strings.Contains(filepath.Base(p), ".unzip-") {
			t.Errorf("left in downloads: %s", p)
		}
	}
}
