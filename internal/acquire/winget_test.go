package acquire

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Recorded manifests from github.com/microsoft/winget-pkgs (2026-10-17),
// laid out as in the repository under testdata/winget.
func wingetFixture(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "winget", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseWingetManifestRecorded(t *testing.T) {
	cases := []struct {
		rel, arch, wantURL, wantCode, wantType string
		unsupported                            bool
	}{
		// wix at the root, per-architecture product codes, root ReleaseDate.
		{rel: "g/Google/Chrome/155.0.8059.85/Google.Chrome.installer.yaml", arch: "x64", wantType: "wix",
			wantURL: "https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi", wantCode: "{0228B730-26AA-39E9-B2E1-0FC0E3EA58C8}"},
		{rel: "g/Google/Chrome/155.0.8059.85/Google.Chrome.installer.yaml", arch: "arm64", wantType: "wix",
			wantURL: "https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise_arm64.msi", wantCode: "{454EC48D-7E8D-3E28-A7C4-AA16C4F2438A}"},
		// exe and wix installers for the same architecture: the MSI wins; quoted version.
		{rel: "7/7zip/7zip/26.04/7zip.7zip.installer.yaml", arch: "x64", wantType: "wix",
			wantURL: "https://www.7-zip.org/a/7z2604-x64.msi", wantCode: "{23170F69-40C1-2702-2604-000001000000}"},
		{rel: "v/VideoLAN/VLC/3.0.24/VideoLAN.VLC.installer.yaml", arch: "x64", wantType: "wix", wantCode: "{585C109D-9729-4B98-A2B8-EACD8885D115}"},
		{rel: "n/Notepad++/Notepad++/8.9.8.1/Notepad++.Notepad++.installer.yaml", arch: "x64", wantType: "wix", wantCode: "{5C6F8543-7EA8-40B9-B78F-04C78300DE7F}"},
		// Only nullsoft / zip for arm64; Inno only for VS Code.
		{rel: "n/Notepad++/Notepad++/8.9.8.1/Notepad++.Notepad++.installer.yaml", arch: "arm64", unsupported: true},
		{rel: "m/Microsoft/VisualStudioCode/1.142.0/Microsoft.VisualStudioCode.installer.yaml", arch: "x64", unsupported: true},
	}
	for _, c := range cases {
		m, err := ParseWingetManifest(wingetFixture(t, c.rel))
		if err != nil {
			t.Fatalf("%s: %v", c.rel, err)
		}
		in, err := m.PickMSI(c.arch)
		if c.unsupported {
			var un *UnsupportedError
			if !errors.As(err, &un) || !strings.Contains(un.Reason, "MSI") {
				t.Errorf("%s %s: want unsupported, got %v (%+v)", c.rel, c.arch, err, in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s %s: %v", c.rel, c.arch, err)
		}
		if in.InstallerType != c.wantType || in.MSIProductCode() != c.wantCode || (c.wantURL != "" && in.URL != c.wantURL) || !hex64Re.MatchString(in.SHA256) {
			t.Errorf("%s %s: %+v code=%s", c.rel, c.arch, in, in.MSIProductCode())
		}
	}
	m, _ := ParseWingetManifest(wingetFixture(t, "7/7zip/7zip/26.04/7zip.7zip.installer.yaml"))
	if m.ID != "7zip.7zip" || m.Version != "26.04" {
		t.Errorf("7zip id/version: %q %q", m.ID, m.Version)
	}
	c, _ := ParseWingetManifest(wingetFixture(t, "g/Google/Chrome/155.0.8059.85/Google.Chrome.installer.yaml"))
	if c.Installers[1].ReleaseDate != "2026-10-15" || c.Installers[1].Scope != "machine" {
		t.Errorf("root defaults not applied: %+v", c.Installers[1])
	}
}

func TestPickMSIFallsBackToX86(t *testing.T) {
	m, err := ParseWingetManifest([]byte(`PackageIdentifier: Contoso.Tool
PackageVersion: 2.0
InstallerType: msi
Installers:
- Architecture: x86
  InstallerUrl: https://contoso.example/tool.msi
  InstallerSha256: ` + strings.Repeat("AB", 32) + `
  ProductCode: '{11111111-2222-3333-4444-555555555555}'
ManifestType: installer
`))
	if err != nil {
		t.Fatal(err)
	}
	in, err := m.PickMSI("x64")
	if err != nil || in.Architecture != "x86" {
		t.Fatalf("x64 endpoint, x86-only MSI: %v %+v", err, in)
	}
	if _, err := m.PickMSI("arm64"); err == nil {
		t.Fatal("arm64 must not fall back to x86")
	}
}

func TestYAMLMini(t *testing.T) {
	v, err := parseYAMLMini([]byte("\ufeff# c\nA: 'it''s' # note\nB: \"x\\ty\"\nL: [a, \"b\"]\nM:\n  N:\n  - 1\n  - k: v\n    j: w\nT: |\n  line1\n  line2\nU: https://h/x#frag\n"))
	if err != nil {
		t.Fatal(err)
	}
	m := v.(map[string]any)
	n := m["M"].(map[string]any)["N"].([]any)
	if m["A"] != "it's" || m["B"] != "x\ty" || len(m["L"].([]any)) != 2 || n[0] != "1" || n[1].(map[string]any)["j"] != "w" ||
		m["T"] != "line1\nline2" || m["U"] != "https://h/x#frag" {
		t.Fatalf("parsed: %#v", m)
	}
	for _, bad := range []string{"A: 1\nA: 2\n", "A: !x 1\n", "A: *nope\n", "A: & 1\n", "A: {b: 1}\n", "A:\n\tB: 1\n", "A: 1\n    B: 2\n", "just text\n"} {
		if _, err := parseYAMLMini([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestYAMLMiniAnchors(t *testing.T) {
	v, err := parseYAMLMini([]byte("A: &a x\nB: *a\nL:\n- &m\n  k: v\n- *m\n- &s s1\n- *s\nM: &n\n  q: 1\nN: *n\n"))
	if err != nil {
		t.Fatal(err)
	}
	m := v.(map[string]any)
	l := m["L"].([]any)
	if m["B"] != "x" || l[1].(map[string]any)["k"] != "v" || l[3] != "s1" || m["N"].(map[string]any)["q"] != "1" {
		t.Fatalf("parsed: %#v", m)
	}
	// An alias is a copy: changing one use leaves the anchor alone.
	l[1].(map[string]any)["k"] = "changed"
	if l[0].(map[string]any)["k"] != "v" {
		t.Fatal("alias shares the anchored map")
	}
	// Aliases that multiply at every level are refused, not expanded.
	bomb := "a: &a [x, x, x, x, x, x, x, x]\n"
	for i := 'b'; i <= 'j'; i++ {
		bomb += fmt.Sprintf("%c: &%c\n", i, i)
		for j := 0; j < 8; j++ {
			bomb += fmt.Sprintf("- *%c\n", i-1)
		}
	}
	if _, err := parseYAMLMini([]byte(bomb)); err == nil {
		t.Fatal("alias bomb accepted")
	}
}

// Python's real manifest anchors each AppsAndFeaturesEntries item ("- &o0")
// and repeats it in the machine-scope installer ("- *o0").
func TestParseWingetManifestWithAliases(t *testing.T) {
	m, err := ParseWingetManifest(wingetFixture(t, "p/Python/Python/3.10/3.10.11/Python.Python.3.10.installer.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != "Python.Python.3.10" || m.Version != "3.10.11" || len(m.Installers) != 4 {
		t.Fatalf("manifest: %+v", m)
	}
}

func TestFetchWingetManifest(t *testing.T) {
	chrome := wingetFixture(t, "g/Google/Chrome/155.0.8059.85/Google.Chrome.installer.yaml")
	var paths []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.URL.Path == "/manifests/g/Google/Chrome/155.0.8059.85/Google.Chrome.installer.yaml" {
			w.Write(chrome)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	ctx := context.Background()
	m, u, err := FetchWingetManifest(ctx, srv.Client(), srv.URL+"/manifests", "Google.Chrome", "155.0.8059.85")
	if err != nil || m.ID != "Google.Chrome" || !strings.HasSuffix(u, "Google.Chrome.installer.yaml") {
		t.Fatalf("fetch: %v %v %+v", err, u, m)
	}
	// Unknown version: both forms tried, then ErrWingetNotFound.
	paths = nil
	if _, _, err := FetchWingetManifest(ctx, srv.Client(), srv.URL+"/manifests", "Google.Chrome", "1.0"); !errors.Is(err, ErrWingetNotFound) || len(paths) != 2 {
		t.Fatalf("missing version: %v %v", err, paths)
	}
	// A manifest served for another version is refused.
	if _, _, err := FetchWingetManifest(ctx, srv.Client(), srv.URL+"/manifests", "Google.Chrome", "155.0.8059.85"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := FetchWingetManifest(ctx, srv.Client(), "http://example.invalid/manifests", "Google.Chrome", "1.0"); err == nil {
		t.Fatal("plain http accepted")
	}
	if got := WingetManifestURLs("https://x/m", "Notepad++.Notepad++", "8.9.8.1")[0]; got != "https://x/m/n/Notepad++/Notepad++/8.9.8.1/Notepad++.Notepad++.installer.yaml" {
		t.Fatalf("url: %s", got)
	}
}
