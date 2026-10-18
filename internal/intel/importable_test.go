package intel

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
)

func TestImportable(t *testing.T) {
	msi := ResolvedInstaller{Arch: "x64", Type: "msi", URL: "https://x/a.msi"}
	sha := strings.Repeat("ab", 32)
	cases := []struct {
		name      string
		r         *Resolved
		arches    []string
		canRead   bool
		want, why string
	}{
		{"unresolved", nil, nil, true, ImportableUnknown, "not resolved"},
		{"msi any arch", &Resolved{Installers: []ResolvedInstaller{msi}}, nil, true, ImportableYes, "MSI installer (x64)"},
		{"wix fleet arch", &Resolved{Installers: []ResolvedInstaller{{Arch: "x64", Type: "wix", ProductCode: "{X}"}}}, []string{"x64"}, false, ImportableYes, "MSI installer (x64)"},
		{"msi no code, cannot read", &Resolved{Installers: []ResolvedInstaller{msi}}, nil, false, ImportableNo, "MSI installer without a ProductCode"},
		{"nullsoft only, no sha", &Resolved{Installers: []ResolvedInstaller{{Arch: "x64", Type: "nullsoft", URL: "https://x/a.exe"}}}, nil, true, ImportableNo, ReasonExeNoSHA},
		{"nullsoft", &Resolved{Installers: []ResolvedInstaller{{Arch: "x64", Type: "nullsoft", URL: "https://x/a.exe", SHA256: sha}}}, nil, true, ImportableYes, "EXE installer (nullsoft)"},
		{"burn", &Resolved{Installers: []ResolvedInstaller{{Arch: "x64", Type: "burn", URL: "https://x/a.exe", SHA256: sha, Scope: "machine"}}}, []string{"x64"}, true, ImportableYes, "EXE installer (burn)"},
		{"inno per user", &Resolved{Installers: []ResolvedInstaller{{Arch: "x64", Type: "inno", URL: "https://x/a.exe", SHA256: sha, Scope: "user"}}}, nil, true, ImportableNo, ReasonPerUser},
		{"inno user and machine", &Resolved{Installers: []ResolvedInstaller{{Arch: "x64", Type: "inno", URL: "https://x/u.exe", SHA256: sha, Scope: "user"}, {Arch: "x64", Type: "inno", URL: "https://x/m.exe", SHA256: sha, Scope: "machine"}}}, nil, true, ImportableYes, "EXE installer (inno)"},
		{"plain exe without switch", &Resolved{Installers: []ResolvedInstaller{{Arch: "x64", Type: "exe", URL: "https://x/a.exe", SHA256: sha}}}, nil, true, ImportableNo, ReasonExeNoSilent},
		{"plain exe with switch", &Resolved{Installers: []ResolvedInstaller{{Arch: "x64", Type: "Exe", URL: "https://x/a.exe", SHA256: sha, Silent: true}}}, nil, true, ImportableYes, "EXE installer (exe)"},
		{"exe http", &Resolved{Installers: []ResolvedInstaller{{Arch: "x64", Type: "inno", URL: "http://x/a.exe", SHA256: sha}}}, nil, true, ImportableNo, ReasonExeNoHTTPS},
		{"msi wins over exe", &Resolved{Installers: []ResolvedInstaller{{Arch: "x64", Type: "inno", URL: "https://x/a.exe", SHA256: sha}, msi}}, nil, true, ImportableYes, "MSI installer (x64)"},
		{"msix", &Resolved{Installers: []ResolvedInstaller{{Arch: "x64", Type: "msix"}}}, nil, true, ImportableNo, "no MSI or EXE installer (msix)"},
		{"portable zip", &Resolved{Installers: []ResolvedInstaller{{Arch: "x64", Type: "zip"}, {Arch: "x64", Type: "portable"}}}, nil, true, ImportableNo, "no MSI or EXE installer (portable, zip)"},
		{"msi only for another arch", &Resolved{Installers: []ResolvedInstaller{{Arch: "arm64", Type: "msi"}}}, []string{"x64"}, true, ImportableNo, "no installer for x64 (only arm64)"},
		{"msi neutral", &Resolved{Installers: []ResolvedInstaller{{Arch: "neutral", Type: "msi"}}}, []string{"x64"}, true, ImportableYes, "MSI installer (neutral)"},
		{"32-bit msi on x64", &Resolved{Installers: []ResolvedInstaller{{Arch: "x86", Type: "msi"}}}, []string{"x64"}, true, ImportableYes, "MSI installer (x86)"},
		{"neutral not for arm64", &Resolved{Installers: []ResolvedInstaller{{Arch: "neutral", Type: "msi"}}}, []string{"arm64"}, true, ImportableNo, "no installer for arm64"},
		{"32-bit exe not for x64", &Resolved{Installers: []ResolvedInstaller{{Arch: "x86", Type: "exe"}}}, []string{"x64"}, true, ImportableNo, "no installer for x64"},
		{"none listed", &Resolved{}, nil, true, ImportableNo, "no installers listed"},
	}
	for _, c := range cases {
		got, why := Importable(c.r, c.arches, c.canRead)
		if got != c.want || !strings.Contains(why, c.why) {
			t.Errorf("%s: %s %q, want %s %q", c.name, got, why, c.want, c.why)
		}
	}
}

// Resolved travels inside the signed document; documents without it
// (older pmctl) still read; ResolvedFor prefers the app's version.
func TestResolvedRoundTrip(t *testing.T) {
	pub, sign, kid := keyPair(t)
	d := sampleDoc()
	d.Resolved = []Resolved{
		{ID: "Google.Chrome", Version: "155.0.8059.80", Installers: []ResolvedInstaller{}},
		{ID: "Google.Chrome", Version: "155.0.8059.85", Publisher: "Google LLC", Installers: []ResolvedInstaller{{Arch: "x64", Type: "wix", URL: "https://dl.google.com/x.msi"}}, ResolvedAt: d.GeneratedAt},
		{ID: "VideoLAN.VLC", Version: "3.0.21", Installers: []ResolvedInstaller{}},
		{ID: "", Version: "1"},
	}
	var buf bytes.Buffer
	if err := Write(&buf, d, kid, sign); err != nil {
		t.Fatal(err)
	}
	got, _, err := Read(bytes.NewReader(buf.Bytes()), map[string]ed25519.PublicKey{kid: pub})
	if err != nil {
		t.Fatal(err)
	}
	ix := NewIndex(got)
	if r := ix.ResolvedFor("google.chrome", "155.0.8059.85"); r == nil || r.Publisher != "Google LLC" || r.Installers[0].Type != "wix" {
		t.Errorf("chrome: %+v", r)
	}
	if r := ix.ResolvedFor("VideoLAN.VLC", "3.0.24"); r == nil || r.Version != "3.0.21" {
		t.Errorf("vlc (newest resolved when the latest is not): %+v", r)
	}
	if r := ix.ResolvedFor("Mozilla.Firefox", "157.0.1"); r != nil {
		t.Errorf("firefox: %+v", r)
	}
	var old bytes.Buffer
	if err := Write(&old, sampleDoc(), kid, sign); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(old.String(), "resolved") {
		t.Error("resolved written for a document without it")
	}
}
