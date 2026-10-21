package acquire

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

const acrobatDir = "a/Adobe/Acrobat/Pro/25.001.20756/"

// Zip installers: NestedInstallerType and NestedInstallerFiles at the root
// and per installer; the pickers take the installer inside.
func TestParseWingetZip(t *testing.T) {
	m, err := ParseWingetManifest(wingetFixture(t, acrobatDir+"Adobe.Acrobat.Pro.installer.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	in := m.Installers[0]
	if in.InstallerType != "zip" || in.NestedInstallerType != "exe" || !slices.Equal(in.NestedInstallerFiles, []string{`Adobe Acrobat\setup.exe`}) || in.ZipPath != "" {
		t.Fatalf("parsed %+v", in)
	}
	got, err := m.PickInstaller("x64")
	if err != nil {
		t.Fatal(err)
	}
	if got.InstallerType != "exe" || got.ZipPath != "Adobe Acrobat/setup.exe" || got.URL != in.URL || got.SHA256 != in.SHA256 || got.ExeUnsupportedReason() != "" {
		t.Errorf("picked %+v", got)
	}
	if args, _ := got.SilentArgs(); !slices.Equal(args, []string{"/sAll", "/rs", "/msi", "EULA_ACCEPT=YES"}) {
		t.Errorf("silent args %v", args)
	}

	sha := strings.Repeat("ab", 32)
	m, err = ParseWingetManifest([]byte(`PackageIdentifier: Contoso.Tool
PackageVersion: 1.0
InstallerType: zip
NestedInstallerType: portable
NestedInstallerFiles:
- RelativeFilePath: tool.exe
  PortableCommandAlias: tool
Installers:
- Architecture: x64
  NestedInstallerType: wix
  NestedInstallerFiles:
  - RelativeFilePath: Contoso\Tool.msi
  InstallerUrl: https://c.example/tool-x64.zip
  InstallerSha256: ` + sha + `
- Architecture: x86
  InstallerUrl: https://c.example/tool-x86.zip
  InstallerSha256: ` + sha + `
- Architecture: arm64
  InstallerType: msi
  InstallerUrl: https://c.example/tool-arm64.msi
  InstallerSha256: ` + sha + `
- Architecture: arm64
  NestedInstallerType: msi
  NestedInstallerFiles:
  - RelativeFilePath: Tool.msi
  InstallerUrl: https://c.example/tool-arm64.zip
  InstallerSha256: ` + sha + `
ManifestType: installer
`))
	if err != nil {
		t.Fatal(err)
	}
	if x := m.Installers[0]; x.NestedInstallerType != "wix" || !slices.Equal(x.NestedInstallerFiles, []string{`Contoso\Tool.msi`}) {
		t.Errorf("installer-level nested fields: %+v", x)
	}
	if x := m.Installers[1]; x.NestedInstallerType != "portable" || !slices.Equal(x.NestedInstallerFiles, []string{"tool.exe"}) {
		t.Errorf("root nested fields: %+v", x)
	}
	if in, err := m.PickInstaller("x64"); err != nil || in.InstallerType != "wix" || in.ZipPath != "Contoso/Tool.msi" {
		t.Errorf("x64: %v %+v", err, in)
	}
	// A plain MSI is preferred over one in a zip.
	if in, err := m.PickInstaller("arm64"); err != nil || in.ZipPath != "" || in.InstallerType != "msi" {
		t.Errorf("arm64: %v %+v", err, in)
	}
	// x86 has only a portable zip.
	_, err = m.PickInstaller("x86")
	var un *UnsupportedError
	if !errors.As(err, &un) || !strings.Contains(un.Reason, "is not importable: zip with a portable app (no installer)") {
		t.Errorf("x86 portable: %v", err)
	}
}

// A zip naming several files, or an unsafe path, is not taken.
func TestPickZipNeedsOneSafeFile(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	for _, files := range []string{"- RelativeFilePath: a.msi\n- RelativeFilePath: b.msi\n", "- RelativeFilePath: ..\\a.msi\n", ""} {
		m, err := ParseWingetManifest([]byte("PackageIdentifier: C.T\nPackageVersion: 1.0\nInstallerType: zip\nNestedInstallerType: msi\nNestedInstallerFiles:\n" + files +
			"Installers:\n- Architecture: x64\n  InstallerUrl: https://c.example/t.zip\n  InstallerSha256: " + sha + "\nManifestType: installer\n"))
		if err != nil {
			t.Fatal(err)
		}
		_, err = m.PickInstaller("x64")
		var un *UnsupportedError
		if !errors.As(err, &un) || !strings.Contains(un.Reason, "exactly one installer file") {
			t.Errorf("%q: %v", files, err)
		}
	}
}

// ResolveWinget describes a zip's nested installer for the importable rule.
func TestResolveWingetZip(t *testing.T) {
	files := map[string][]byte{acrobatDir + "Adobe.Acrobat.Pro.installer.yaml": wingetFixture(t, acrobatDir+"Adobe.Acrobat.Pro.installer.yaml")}
	srv := manifestServer(t, files)
	r, err := ResolveWinget(t.Context(), srv.Client(), srv.URL+"/manifests", "Adobe.Acrobat.Pro", "25.001.20756", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Installers) != 1 {
		t.Fatalf("installers: %+v", r.Installers)
	}
	in := r.Installers[0]
	if in.Type != "zip" || in.NestedType != "exe" || in.NestedPath != "Adobe Acrobat/setup.exe" || !in.Silent || in.SHA256 == "" || in.Scope != "machine" {
		t.Errorf("installer %+v", in)
	}
	if ok, why := LibraryImportable(r, []string{"x64"}); ok != "yes" || why != "EXE installer in a zip (exe)" {
		t.Errorf("importable: %s %s", ok, why)
	}
}
