package acquire

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"offpatch/internal/intel"
	"offpatch/internal/manifest"
)

// Recorded manifests (testdata/winget, from github.com/microsoft/winget-pkgs):
// how each resolves for an architecture, and the ExeInstall built from it.
func TestPickInstallerRecordedEXE(t *testing.T) {
	cases := []struct {
		rel, arch    string
		wantType     string
		wantArgs     []string
		wantSuccess  []int // must be contained
		wantBusy     []int
		wantARPKey   string
		wantQuiet    bool
		wantURLSufix string
	}{
		// WebView2: plain exe with a documented switch, user and machine
		// entries (machine taken), extra success codes as negative HRESULTs.
		{rel: "m/Microsoft/EdgeWebView2Runtime/155.0.4283.62/Microsoft.EdgeWebView2Runtime.installer.yaml", arch: "x64", wantType: "exe",
			wantArgs: []string{"/silent", "/install"}, wantSuccess: []int{0, 3010, 1641, -2147219416, -2147219187}, wantARPKey: "Microsoft EdgeWebView",
			wantURLSufix: "MicrosoftEdgeWebView2RuntimeInstallerX64.exe"},
		{rel: "m/Microsoft/EdgeWebView2Runtime/155.0.4283.62/Microsoft.EdgeWebView2Runtime.installer.yaml", arch: "arm64", wantType: "exe",
			wantArgs: []string{"/silent", "/install"}, wantURLSufix: "MicrosoftEdgeWebView2RuntimeInstallerARM64.exe"},
		// VC++ Redistributable: Burn bundle, default switches, 3010 success,
		// 1618 busy, bundle code as ARP key, quiet uninstall known.
		{rel: "m/Microsoft/VCRedist/2015+/x64/14.51.36247.0/Microsoft.VCRedist.2015+.x64.installer.yaml", arch: "x64", wantType: "burn",
			wantArgs: []string{"/quiet", "/norestart"}, wantSuccess: []int{0, 3010, 1641}, wantBusy: []int{1618},
			wantARPKey: "{0E3BB569-69D6-4C34-BFF9-C2F81DB5E5F0}", wantQuiet: true, wantURLSufix: "VC_redist.x64.exe"},
		// Notepad++ arm64: only NSIS (the x64 MSI does not fit arm64).
		{rel: "n/Notepad++/Notepad++/8.9.8.1/Notepad++.Notepad++.installer.yaml", arch: "arm64", wantType: "nullsoft",
			wantArgs: []string{"/S"}},
		// 7-Zip: the MSI wins on x64; arm64 has only the exe (/S).
		{rel: "7/7zip/7zip/26.04/7zip.7zip.installer.yaml", arch: "x64", wantType: "wix"},
		{rel: "7/7zip/7zip/26.04/7zip.7zip.installer.yaml", arch: "arm64", wantType: "exe", wantArgs: []string{"/S"}},
		// Inno Setup: the manifest's Silent switch replaces the default.
		{rel: "g/Git/Git/2.55.0.5/Git.Git.installer.yaml", arch: "x64", wantType: "inno",
			wantArgs: []string{"/SP-", "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"}, wantQuiet: true, wantURLSufix: "Git-2.55.0.5-64-bit.exe"},
		{rel: "m/Microsoft/VisualStudioCode/1.142.0/Microsoft.VisualStudioCode.installer.yaml", arch: "x64", wantType: "inno", wantQuiet: true},
	}
	for _, c := range cases {
		m, err := ParseWingetManifest(wingetFixture(t, c.rel))
		if err != nil {
			t.Fatalf("%s: %v", c.rel, err)
		}
		in, err := m.PickInstaller(c.arch)
		if err != nil {
			t.Fatalf("%s %s: %v", c.rel, c.arch, err)
		}
		if in.InstallerType != c.wantType || (c.wantURLSufix != "" && !strings.HasSuffix(in.URL, c.wantURLSufix)) {
			t.Errorf("%s %s: picked %s %s", c.rel, c.arch, in.InstallerType, in.URL)
			continue
		}
		if !in.IsEXE() {
			continue
		}
		if in.Scope == "user" {
			t.Errorf("%s %s: per-user installer picked", c.rel, c.arch)
		}
		ex, err := in.ExeInstall(ExeInstallOptions{Signer: "Microsoft Corporation", DisplayName: "Some App", Publisher: "Vendor"})
		if err != nil {
			t.Fatalf("%s %s: %v", c.rel, c.arch, err)
		}
		if c.wantArgs != nil && !slices.Equal(ex.SilentArgs, c.wantArgs) {
			t.Errorf("%s %s: args %q, want %q", c.rel, c.arch, ex.SilentArgs, c.wantArgs)
		}
		for _, code := range c.wantSuccess {
			if !slices.Contains(ex.SuccessCodes, code) {
				t.Errorf("%s %s: success codes %v lack %d", c.rel, c.arch, ex.SuccessCodes, code)
			}
		}
		if c.wantBusy != nil && !slices.Equal(ex.BusyCodes, c.wantBusy) {
			t.Errorf("%s %s: busy codes %v", c.rel, c.arch, ex.BusyCodes)
		}
		if c.wantARPKey != "" && ex.Detect.ProductCode != c.wantARPKey {
			t.Errorf("%s %s: ARP key %q", c.rel, c.arch, ex.Detect.ProductCode)
		}
		if ex.Uninstall.QuietUninstall != c.wantQuiet || ex.Scope != manifest.ExeScopeMachine || ex.InstallerType != c.wantType {
			t.Errorf("%s %s: %+v", c.rel, c.arch, ex)
		}
		// The block passes the manifest schema as pmctl will write it.
		e := SpecEntry{PackageID: "app-1", Title: "App 1", Vendor: "Vendor", Kind: manifest.KindExe, Version: m.Version, PackageName: "Some App",
			Severity: "important", ReleaseDate: "2026-10-18", Applicability: manifest.Applicability{OS: "windows", Arch: c.arch},
			SourceURL: in.URL, Path: "downloads/app-1.exe", Exe: ex}
		if err := ValidateEntry(e, 10, in.SHA256); err != nil {
			t.Errorf("%s %s: %v", c.rel, c.arch, err)
		}
	}
}

// The x86 VC++ entry points at the x64 file and says it is not for x64 or
// arm64 Windows: never picked for those.
func TestPickEXEUnsupportedOSArchitectures(t *testing.T) {
	m, err := ParseWingetManifest(wingetFixture(t, "m/Microsoft/VCRedist/2015+/x64/14.51.36247.0/Microsoft.VCRedist.2015+.x64.installer.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var x86 WingetInstaller
	for _, in := range m.Installers {
		if in.Architecture == "x86" {
			x86 = in
		}
	}
	if !slices.Equal(x86.UnsupportedArch, []string{"x64", "arm64"}) || exeArchFits(x86, "x64") || !exeArchFits(x86, "x86") {
		t.Fatalf("x86 entry: %+v", x86)
	}
	if in, err := m.PickEXE("x64"); err != nil || in.Architecture != "x64" {
		t.Fatalf("x64: %v %+v", err, in)
	}
}

func TestPickEXEReasons(t *testing.T) {
	sha := strings.Repeat("AB", 32)
	parse := func(body string) *WingetManifest {
		t.Helper()
		m, err := ParseWingetManifest([]byte("PackageIdentifier: Contoso.Tool\nPackageVersion: 2.0\n" + body + "ManifestType: installer\n"))
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	cases := []struct{ body, reason string }{
		{"InstallerType: exe\nInstallers:\n- Architecture: x64\n  InstallerUrl: https://c.example/t.exe\n  InstallerSha256: " + sha + "\n", intel.ReasonExeNoSilent},
		{"InstallerType: inno\nScope: user\nInstallers:\n- Architecture: x64\n  InstallerUrl: https://c.example/t.exe\n  InstallerSha256: " + sha + "\n", intel.ReasonPerUser},
		{"InstallerType: nullsoft\nInstallers:\n- Architecture: x64\n  InstallerUrl: https://c.example/t.exe\n", intel.ReasonExeNoSHA},
		{"InstallerType: burn\nInstallers:\n- Architecture: x64\n  InstallerUrl: http://c.example/t.exe\n  InstallerSha256: " + sha + "\n", intel.ReasonExeNoHTTPS},
		{"InstallerType: exe\nInstallerSwitches:\n  Silent: /S & calc\nInstallers:\n- Architecture: x64\n  InstallerUrl: https://c.example/t.exe\n  InstallerSha256: " + sha + "\n", intel.ReasonExeNoSilent},
	}
	for _, c := range cases {
		m := parse(c.body)
		_, err := m.PickInstaller("x64")
		var un *UnsupportedError
		if !errors.As(err, &un) || !strings.Contains(un.Reason, "is not importable: "+c.reason) || !strings.Contains(un.Reason, "EXE installer (") {
			t.Errorf("%q: %v", c.body, err)
		}
	}
	// Only msix/zip: neither MSI nor EXE.
	_, err := parse("Installers:\n- Architecture: x64\n  InstallerType: msix\n  InstallerUrl: https://c.example/t.msix\n  InstallerSha256: " + sha + "\n").PickInstaller("x64")
	if err == nil || !strings.Contains(err.Error(), "has no MSI or EXE installer for x64 (only msix)") {
		t.Errorf("msix: %v", err)
	}
	// Installer-level switches and codes override the root.
	m := parse("InstallerType: exe\nInstallerSwitches:\n  Silent: --root\nExpectedReturnCodes:\n- InstallerReturnCode: 5\n  ReturnResponse: installInProgress\n" +
		"Installers:\n- Architecture: x64\n  InstallerUrl: https://c.example/t.exe\n  InstallerSha256: " + sha + "\n  InstallerSwitches:\n    Silent: --quiet \"--dir=C:\\Program Files\\T\"\n    Custom: --no-telemetry\n" +
		"  ExpectedReturnCodes:\n  - InstallerReturnCode: 0x80070652\n    ReturnResponse: installInProgress\n  - InstallerReturnCode: 7\n    ReturnResponse: alreadyInstalled\n")
	in, err := m.PickInstaller("x64")
	if err != nil {
		t.Fatal(err)
	}
	args, _ := in.SilentArgs()
	if !slices.Equal(args, []string{"--quiet", `--dir=C:\Program Files\T`, "--no-telemetry"}) {
		t.Errorf("args %q", args)
	}
	success, busy := in.ExitCodes()
	if !slices.Equal(success, []int{0, 3010, 1641, 7}) || !slices.Equal(busy, []int{0x80070652}) {
		t.Errorf("codes %v %v", success, busy)
	}
}

func TestSplitSwitches(t *testing.T) {
	ok := map[string][]string{
		"/S":                         {"/S"},
		"  /quiet   /norestart ":     {"/quiet", "/norestart"},
		`/D="C:\Program Files\X" /S`: {`/D=C:\Program Files\X`, "/S"},
		`""`:                         {""},
	}
	for in, want := range ok {
		if got, err := SplitSwitches(in); err != nil || !slices.Equal(got, want) {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{`/S "x`, "/S | x", "/S\x00", "a > b"} {
		if _, err := SplitSwitches(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// ResolveWinget keeps EXE installers with what the importable rule needs.
func TestResolveWingetExe(t *testing.T) {
	const dir = "m/Microsoft/EdgeWebView2Runtime/155.0.4283.62/"
	files := map[string][]byte{}
	for _, f := range []string{"Microsoft.EdgeWebView2Runtime.installer.yaml", "Microsoft.EdgeWebView2Runtime.locale.en-US.yaml", "Microsoft.EdgeWebView2Runtime.yaml"} {
		files[dir+f] = wingetFixture(t, dir+f)
	}
	srv := manifestServer(t, files)
	r, err := ResolveWinget(t.Context(), srv.Client(), srv.URL+"/manifests", "Microsoft.EdgeWebView2Runtime", "155.0.4283.62", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Installers) != 6 {
		t.Fatalf("installers: %+v", r.Installers)
	}
	for _, in := range r.Installers {
		if in.Type != "exe" || !in.Silent || in.SHA256 == "" {
			t.Errorf("installer %+v", in)
		}
	}
	if ok, why := LibraryImportable(r, []string{"x64"}); ok != "yes" || why != "EXE installer (exe)" {
		t.Errorf("importable: %s %s", ok, why)
	}
	loc, err := FetchWingetLocale(t.Context(), srv.Client(), srv.URL+"/manifests", "Microsoft.EdgeWebView2Runtime", "155.0.4283.62")
	if err != nil || loc.PackageName != "Microsoft Edge WebView2 Runtime" {
		t.Errorf("locale: %v %+v", err, loc)
	}
}

// An app published for x86 only (the x86 VC++ redistributable) gets its
// 32-bit EXE on x64 machines; one that says it is not for x64 does not.
func TestPickEXEx86OnlyOnX64(t *testing.T) {
	sha := strings.Repeat("AB", 32)
	m, err := ParseWingetManifest([]byte("PackageIdentifier: Microsoft.VCRedist.2015+.x86\nPackageVersion: 14.51\nInstallerType: burn\nInstallers:\n- Architecture: x86\n  InstallerUrl: https://c.example/vc_redist.x86.exe\n  InstallerSha256: " + sha + "\nManifestType: installer\n"))
	if err != nil {
		t.Fatal(err)
	}
	if in, err := m.PickInstaller("x64"); err != nil || in.Architecture != "x86" {
		t.Fatalf("x86-only on x64: %v %+v", err, in)
	}
	if _, err := m.PickInstaller("arm64"); err == nil {
		t.Fatal("x86-only EXE picked for arm64")
	}
	m.Installers[0].UnsupportedArch = []string{"x64"}
	if _, err := m.PickEXE("x64"); err == nil {
		t.Fatal("x86 entry that is not for x64 was picked")
	}
}
