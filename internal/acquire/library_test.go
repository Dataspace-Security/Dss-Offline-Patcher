package acquire

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"offpatch/internal/intel"
)

// manifestServer serves files (path below /manifests/ → body) over TLS.
func manifestServer(t *testing.T, files map[string][]byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if b, ok := files[strings.TrimPrefix(r.URL.Path, "/manifests/")]; ok {
			w.Write(b)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestResolveWingetEdge(t *testing.T) {
	const dir = "m/Microsoft/Edge/155.0.4283.62/"
	srv := manifestServer(t, map[string][]byte{
		dir + "Microsoft.Edge.installer.yaml":    wingetFixture(t, dir+"Microsoft.Edge.installer.yaml"),
		dir + "Microsoft.Edge.locale.en-US.yaml": wingetFixture(t, dir+"Microsoft.Edge.locale.en-US.yaml"),
	})
	now := time.Date(2026, 10, 18, 7, 0, 0, 0, time.UTC)
	r, err := ResolveWinget(context.Background(), srv.Client(), srv.URL+"/manifests", "Microsoft.Edge", "155.0.4283.62", now)
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != "Microsoft.Edge" || r.Version != "155.0.4283.62" || r.Publisher != "Microsoft Corporation" ||
		r.Homepage != "https://www.microsoft.com/en-us/edge" || r.License != "Proprietary" ||
		!strings.HasPrefix(r.Description, "Microsoft Edge is a cross-platform web browser") || r.ResolvedAt != "2026-10-18T07:00:00Z" {
		t.Fatalf("resolved: %+v", r)
	}
	if len(r.Installers) != 3 {
		t.Fatalf("installers: %+v", r.Installers)
	}
	x64 := r.Installers[0]
	if x64.Arch != "x64" || x64.Type != "msi" || x64.Scope != "machine" || x64.ProductCode != "" ||
		x64.SHA256 != "20119979eb1670f670d38c093fd1c61f5a91d880c473f8614825ce9aef35f68a" ||
		!strings.HasSuffix(x64.URL, "/MicrosoftEdgeEnterpriseX64.msi") {
		t.Errorf("x64 installer: %+v", x64)
	}
	// No ProductCode in the manifest: still importable (pmctl reads it from the MSI).
	if ok, why := LibraryImportable(r, []string{"x64"}); ok != "yes" {
		t.Errorf("Edge not importable: %s", why)
	}
}

func TestResolveWingetLocaleFallbacks(t *testing.T) {
	inst := []byte(`PackageIdentifier: Contoso.Tool
PackageVersion: 2.0
Installers:
- Architecture: x64
  InstallerType: nullsoft
  InstallerUrl: https://contoso.example/tool.exe
  InstallerSha256: ` + strings.Repeat("AB", 32) + `
- Architecture: x86
  InstallerType: msi
  InstallerUrl: https://contoso.example/tool.msi
- Architecture: arm64
  InstallerType: exe
  InstallerUrl: http://contoso.example/tool-arm.exe
ManifestType: installer
`)
	const dir = "c/Contoso/Tool/2.0/"
	srv := manifestServer(t, map[string][]byte{
		dir + "Contoso.Tool.installer.yaml": inst,
		dir + "Contoso.Tool.yaml":           []byte("PackageIdentifier: Contoso.Tool\nPackageVersion: 2.0\nDefaultLocale: de-DE\nManifestType: version\n"),
		// Free text the small YAML reader refuses: the top-level keys are still read.
		dir + "Contoso.Tool.locale.de-DE.yaml": []byte("PackageIdentifier: Contoso.Tool\nPackageVersion: 2.0\nPublisher: Contoso GmbH\n" +
			"PublisherUrl: http://contoso.example\nPackageUrl: https://contoso.example/tool\nShortDescription: \"Ein\\u0007 Werkzeug\"\n" +
			"Agreements: {weird: flow}\nReleaseNotes: |-\n  * fixed\nManifestType: defaultLocale\n"),
	})
	r, err := ResolveWinget(context.Background(), srv.Client(), srv.URL+"/manifests", "Contoso.Tool", "2.0", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if r.Publisher != "Contoso GmbH" || r.PublisherURL != "" || r.Homepage != "https://contoso.example/tool" || r.Description == "" {
		t.Fatalf("locale: %+v", r)
	}
	// The MSI without a SHA-256 and the plain-http EXE are not fetchable: left out.
	if len(r.Installers) != 1 || r.Installers[0].Type != "nullsoft" {
		t.Fatalf("installers: %+v", r.Installers)
	}
	if ok, why := LibraryImportable(r, nil); ok != "no" || why != "EXE installer only (nullsoft)" {
		t.Errorf("importable: %s %s", ok, why)
	}
	// Installer manifest missing: ErrWingetNotFound.
	if _, err := ResolveWinget(context.Background(), srv.Client(), srv.URL+"/manifests", "Contoso.Gone", "1.0", time.Now()); !errors.Is(err, ErrWingetNotFound) {
		t.Errorf("missing package: %v", err)
	}
}

func TestLibraryImportable(t *testing.T) {
	in := func(arch, typ string) intel.ResolvedInstaller {
		return intel.ResolvedInstaller{Arch: arch, Type: typ, URL: "https://x/y"}
	}
	cases := []struct {
		inst   []intel.ResolvedInstaller
		arches []string
		want   string
		reason string
	}{
		{[]intel.ResolvedInstaller{in("x64", "wix")}, []string{"x64"}, "yes", ""},
		{[]intel.ResolvedInstaller{in("x86", "msi")}, []string{"x64"}, "yes", ""}, // 32-bit MSI on x64, like PickMSI
		{[]intel.ResolvedInstaller{in("neutral", "msi")}, []string{"x86"}, "yes", ""},
		{[]intel.ResolvedInstaller{in("arm64", "msi")}, nil, "yes", ""}, // nothing installed: any arch
		{[]intel.ResolvedInstaller{in("arm64", "msi"), in("x64", "inno")}, []string{"x64"}, "no", "EXE installer only (inno)"},
		{[]intel.ResolvedInstaller{in("x64", "msix"), in("x64", "zip")}, []string{"x64"}, "no", "no MSI installer (only msix, zip)"},
		{[]intel.ResolvedInstaller{in("x86", "exe")}, []string{"arm64"}, "no", "no installer for arm64"},
		{nil, nil, "no", "no installer pmctl can fetch"},
	}
	for i, c := range cases {
		got, why := LibraryImportable(intel.Resolved{Installers: c.inst}, c.arches)
		if got != c.want || why != c.reason {
			t.Errorf("%d: %s %q, want %s %q", i, got, why, c.want, c.reason)
		}
	}
}

func TestLibText(t *testing.T) {
	if got := libText("  a\tb\n\x00c  ", 100); got != "a b c" {
		t.Errorf("%q", got)
	}
	if got := libText(strings.Repeat("é", 50), 10); len([]rune(got)) != 10 || !strings.HasSuffix(got, "…") {
		t.Errorf("%q", got)
	}
	if libURL("javascript:alert(1)") != "" || libURL("https://"+strings.Repeat("a", 3000)) != "" || libURL("https://ok.example/x") == "" {
		t.Error("libURL")
	}
}

func TestTitleUBR(t *testing.T) {
	title := "2026-10 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5066835) (26100.6899)"
	if got := TitleUBR(title, 26100); got != 6899 {
		t.Errorf("got %d", got)
	}
	if TitleUBR(title, 26200) != 0 || TitleUBR(title, 0) != 0 || TitleUBR("Cumulative Update (KB5066835)", 26100) != 0 {
		t.Error("UBR for a build the title does not name")
	}
	if got := TitleUBR("Update (22621.6060) and (22631.6060)", 22631); got != 6060 {
		t.Errorf("second build: %d", got)
	}
}
