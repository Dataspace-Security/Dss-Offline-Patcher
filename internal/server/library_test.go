package server

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"offpatch/internal/intel"
)

func TestSafeLink(t *testing.T) {
	for in, want := range map[string]string{
		"https://www.7-zip.org/":                           "https://www.7-zip.org/",
		"https://example.com/a?b=c#d":                      "https://example.com/a?b=c#d",
		"http://example.com/":                              "",
		"javascript:alert(1)":                              "",
		"https://user:pw@example.com/":                     "",
		"https:///nohost":                                  "",
		"https://example.com/a b":                          "",
		"https://example.com/\"><script>":                  "",
		"https://exämple.com/":                             "",
		"//example.com/":                                   "",
		"https://example.com/" + strings.Repeat("a", 2100): "",
		"": "",
	} {
		if got := safeLink(in); got != want {
			t.Errorf("safeLink(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCleanLibText(t *testing.T) {
	if got := cleanLibText("Evil‮ App\x07\n\tline", 200); got != "Evil App line" {
		t.Errorf("clean: %q", got)
	}
	if got := cleanLibText(strings.Repeat("é", 300), 11); got != "ééééé…" {
		t.Errorf("cut on a rune boundary: %q", got)
	}
}

func TestWingetManifestURL(t *testing.T) {
	for id, want := range map[string]string{
		"Microsoft.VisualStudioCode": "https://github.com/microsoft/winget-pkgs/tree/master/manifests/m/Microsoft/VisualStudioCode/1.2",
		"Git.Git":                    "https://github.com/microsoft/winget-pkgs/tree/master/manifests/g/Git/Git/1.2",
		"Mozilla.Firefox.ESR":        "https://github.com/microsoft/winget-pkgs/tree/master/manifests/m/Mozilla/Firefox/ESR/1.2",
		"NoDots":                     "",
		"Bad..Id":                    "",
		"Bad/Id.X":                   "",
	} {
		if got := wingetManifestURL(id, "1.2"); got != want {
			t.Errorf("%s: %q, want %q", id, got, want)
		}
	}
	if got := wingetManifestURL("Git.Git", "../x"); got != "" {
		t.Errorf("path in version: %q", got)
	}
}

// The Library is built once per intelligence generation and a search over
// ~16k apps stays fast (a linear scan of precomputed keys).
func TestLibraryIndexScale(t *testing.T) {
	d := intel.Doc{Source: "acq-zone-1", GeneratedAt: time.Now().UTC().Format(time.RFC3339)}
	for i := 0; i < 16000; i++ {
		id := fmt.Sprintf("Vendor%d.App%d", i%900, i)
		d.Apps = append(d.Apps, intel.App{ID: id, Name: fmt.Sprintf("App number %d", i), Version: "1.0." + fmt.Sprint(i), Publishers: []string{fmt.Sprintf("Vendor %d", i%900)}})
		if i%5 == 0 {
			d.Resolved = append(d.Resolved, intel.Resolved{ID: id, Version: "1.0." + fmt.Sprint(i), Description: "an app",
				Installers: []intel.ResolvedInstaller{{Arch: "x64", Type: "msi", URL: "https://example.com/" + id + ".msi"}}})
		}
	}
	ix := intel.NewIndex(d)
	start := time.Now()
	li := buildLibIndex(ix)
	build := time.Since(start)
	if len(li.entries) != 16000 {
		t.Fatalf("entries: %d", len(li.entries))
	}
	ov := libOverlay{}
	start = time.Now()
	yes, hits := 0, 0
	for i := range li.entries {
		e := &li.entries[i]
		if matchesAll(e.search, []string{"vendor 12", "app"}) {
			hits++
		}
		if it, _ := ov.row(e); it.Importable == intel.ImportableYes {
			yes++
		}
	}
	scan := time.Since(start)
	if yes != 3200 || hits == 0 {
		t.Errorf("importable %d (want 3200), hits %d", yes, hits)
	}
	t.Logf("build %v, scan %v", build, scan)
	if scan > 250*time.Millisecond { // generous for slow CI; typically a few ms
		t.Errorf("scan of 16k entries took %v", scan)
	}
}
