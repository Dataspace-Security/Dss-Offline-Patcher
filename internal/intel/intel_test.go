package intel

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"io"
	"strings"
	"testing"
	"time"

	"offpatch/internal/manifest"
)

func sampleDoc() Doc {
	return Doc{
		Source: "acq-zone-1", GeneratedAt: time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC).Format(time.RFC3339),
		Windows: []WindowsRelease{
			{Product: "Windows 11 Version 21H2", Build: 22000, Arch: "x64", KB: "KB5044280", Title: "2024-10 Cumulative Update for Windows 11 for x64-based Systems (KB5044280)"},
			{Product: "Windows 11 Version 26H2", Build: 26300, Arch: "x64", KB: "KB5127648", UBR: 9711},
			{Product: "Windows Server 2025", Build: 26100, Arch: "x64", KB: "KB5127700", UBR: 9711, Server: true},
		},
		Apps: []App{
			{ID: "Google.Chrome", Name: "Google Chrome", Version: "155.0.8059.85", Codes: []string{"{0228b730-26aa-39e9-b2e1-0fc0e3ea58c8}", "google chrome"}, Names: []string{"googlechrome"}},
			{ID: "Mozilla.Firefox", Name: "Mozilla Firefox (en-US)", Version: "157.0.1", Names: []string{"mozillafirefox", "mozillafirefox(X64)"}},
			{ID: "VideoLAN.VLC", Name: "VLC media player", Version: "3.0.24", Codes: []string{"vlc media player"}, Names: []string{"vlcmediaplayer"}},
			{ID: "Vendor.Tool", Name: "Tool", Version: "2026.1", ARPMax: "26.1.0", Names: []string{"vendortool"}},
			{ID: "A.Dup", Name: "Dup", Version: "2.0", Names: []string{"duptool"}},
			{ID: "B.Dup", Name: "Dup", Version: "3.0", Names: []string{"duptool"}},
			{ID: "Google.Chrome.EXE", Name: "Google Chrome", Version: "155.0.8059.85", Names: []string{"googlechrome"}},
			{ID: "Google.Chrome.Beta", Name: "Google Chrome Beta", Version: "156.0.1", Names: []string{"googlechromebeta", "googlechrome测试版"}},
			{ID: "Google.Chrome.Dev.EXE", Name: "Google Chrome Dev", Version: "157.0.1", Names: []string{"googlechrome"}},
			{ID: "C.Shared", Name: "Shared One", Version: "9.0", Codes: []string{"shared-key"}, Names: []string{"sharedone"}},
			{ID: "D.Shared", Name: "Shared Two", Version: "9.0", Codes: []string{"shared-key"}, Names: []string{"sharedtwo"}},
		},
	}
}

func keyPair(t *testing.T) (ed25519.PublicKey, func([]byte) (string, error), string) {
	t.Helper()
	pub, priv, err := manifest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return pub, func(b []byte) (string, error) { return manifest.Sign(priv, b), nil }, manifest.KeyID(pub)
}

func TestWriteReadRoundTrip(t *testing.T) {
	pub, sign, kid := keyPair(t)
	var buf bytes.Buffer
	if err := Write(&buf, sampleDoc(), kid, sign); err != nil {
		t.Fatal(err)
	}
	d, gotKID, err := Read(bytes.NewReader(buf.Bytes()), map[string]ed25519.PublicKey{kid: pub})
	if err != nil {
		t.Fatal(err)
	}
	if gotKID != kid || d.Version != 1 || len(d.Apps) != 11 || len(d.Windows) != 3 || d.GeneratedTime().IsZero() {
		t.Fatalf("round trip: kid=%s doc=%+v", gotKID, d)
	}

	if _, _, err := Read(bytes.NewReader(buf.Bytes()), map[string]ed25519.PublicKey{}); err == nil || !strings.Contains(err.Error(), "untrusted") {
		t.Fatalf("untrusted key accepted: %v", err)
	}

	// Change one byte of the signed document.
	zr, _ := gzip.NewReader(bytes.NewReader(buf.Bytes()))
	raw, _ := io.ReadAll(zr)
	tampered := bytes.Replace(raw, []byte("155.0.8059.85"), []byte("155.0.8059.86"), 1)
	var tb bytes.Buffer
	zw := gzip.NewWriter(&tb)
	zw.Write(tampered)
	zw.Close()
	if _, _, err := Read(&tb, map[string]ed25519.PublicKey{kid: pub}); err == nil {
		t.Fatal("tampered document accepted")
	}

	if _, _, err := Read(strings.NewReader("not gzip"), map[string]ed25519.PublicKey{kid: pub}); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestReadRejectsInvalidDocuments(t *testing.T) {
	pub, sign, kid := keyPair(t)
	for name, mut := range map[string]func(*Doc){
		"no source":     func(d *Doc) { d.Source = "" },
		"bad time":      func(d *Doc) { d.GeneratedAt = "yesterday" },
		"windows no kb": func(d *Doc) { d.Windows[0].KB = "" },
		"app no ver":    func(d *Doc) { d.Apps[0].Version = "" },
	} {
		d := sampleDoc()
		mut(&d)
		var buf bytes.Buffer
		if err := Write(&buf, d, kid, sign); err != nil {
			t.Fatal(err)
		}
		if _, _, err := Read(&buf, map[string]ed25519.PublicKey{kid: pub}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestMatch(t *testing.T) {
	ix := NewIndex(sampleDoc())
	vm := Endpoint{OS: "windows", OSVersion: "Windows 11 Pro 21H2 (22000.2538)", Build: 22000, Arch: "x64", Inventory: []Item{
		{Kind: "kb", ID: "KB5031358"},
		{Kind: "product", ID: "{0228B730-26AA-39E9-B2E1-0FC0E3EA58C8}", Name: "Google Chrome", Version: "155.0.8059.82"},
		{Kind: "product", ID: "Mozilla Firefox 157.0.1 (x64 en-US)", Name: "Mozilla Firefox (x64 en-US)", Version: "157.0.1"},
		{Kind: "product", ID: "VLC media player", Name: "VLC media player", Version: "3.0.20"},
		{Kind: "product", ID: "VendorTool", Name: "Vendor Tool 26.0", Version: "26.1.0"},
		{Kind: "product", ID: "dup", Name: "Dup Tool", Version: "1.0"},
		{Kind: "product", ID: "x", Name: "Something Unknown", Version: "1.0"},
		{Kind: "product", ID: "shared-key", Name: "Shared Two", Version: "1.0"},
		// Chrome's MSI product code changes every version: matched by name,
		// across Google.Chrome / Google.Chrome.EXE (same version), ignoring Beta.
		{Kind: "product", ID: "{CCFFC2EC-F561-3EF1-8038-F3608B52F935}", Name: "Google Chrome", Version: "155.0.8059.80"},
		{Kind: "product", ID: "shared-key", Name: "Neither", Version: "1.0"},
	}}
	res := ix.Match(vm)
	if len(res.OS) != 1 || res.OS[0].KB != "KB5044280" || res.OS[0].InstalledUBR != 2538 || res.OS[0].Basis != "kb_inventory" {
		t.Fatalf("os updates: %+v", res.OS)
	}
	got := map[string]AppUpdate{}
	for _, a := range res.Apps {
		if _, dup := got[a.AppID]; !dup || a.MatchedBy == "product_code" {
			got[a.AppID] = a
		}
	}
	if c := got["Google.Chrome"]; c.MatchedBy != "product_code" || c.LatestVersion != "155.0.8059.85" || c.ProductCode == "" {
		t.Errorf("chrome: %+v", c)
	}
	if v := got["VideoLAN.VLC"]; v.MatchedBy != "product_code" || v.InstalledVersion != "3.0.20" {
		t.Errorf("vlc: %+v", v)
	}
	if _, ok := got["Mozilla.Firefox"]; ok {
		t.Error("firefox is current but listed")
	}
	if _, ok := got["Vendor.Tool"]; ok {
		t.Error("ARPMax 26.1.0 installed but listed as outdated")
	}
	if s := got["D.Shared"]; s.MatchedBy != "product_code" {
		t.Errorf("shared code with matching name: %+v", s)
	}
	if _, ok := got["C.Shared"]; ok {
		t.Error("shared code without a matching name was guessed")
	}
	// dup is ambiguous by name, unknown is unknown, "Neither" claims a shared code
	nameChrome := 0
	for _, a := range res.Apps {
		if a.AppID == "Google.Chrome" && a.MatchedBy == "name" && a.InstalledVersion == "155.0.8059.80" {
			nameChrome++
		}
	}
	if nameChrome != 1 {
		t.Errorf("Chrome by name across package variants not matched: %+v", res.Apps)
	}
	if len(res.Apps) != 4 || res.Current != 2 || res.Unmatched != 3 {
		t.Errorf("apps=%d current=%d unmatched=%d", len(res.Apps), res.Current, res.Unmatched)
	}
	// The up-to-date apps are listed too (fleet status), with their installed form.
	if len(res.CurrentApps) != res.Current || len(res.CurrentOS) != 0 {
		t.Errorf("current lists: apps %+v os %+v", res.CurrentApps, res.CurrentOS)
	}
	cur := map[string]AppUpdate{}
	for _, a := range res.CurrentApps {
		cur[a.AppID] = a
	}
	if f := cur["Mozilla.Firefox"]; f.InstalledVersion != "157.0.1" || f.MatchedBy == "" {
		t.Errorf("current firefox: %+v", cur)
	}
	if _, ok := cur["Vendor.Tool"]; !ok {
		t.Errorf("current vendor tool missing: %+v", cur)
	}

	// Installing the KB (or any later revision) clears the OS update.
	vm.Inventory = append(vm.Inventory, Item{Kind: "kb", ID: "kb5044280"})
	if res := ix.Match(vm); len(res.OS) != 0 || len(res.CurrentOS) != 1 || res.CurrentOS[0].KB != "KB5044280" {
		t.Errorf("KB installed but still listed (or not current): %+v %+v", res.OS, res.CurrentOS)
	}
	pc := Endpoint{OS: "windows", OSVersion: "Windows 11 Pro N 26H2 (26300.9711)", Build: 26300, Arch: "x64"}
	if res := ix.Match(pc); len(res.OS) != 0 || len(res.CurrentOS) != 1 {
		t.Errorf("UBR already at 9711 but listed: %+v", res.OS)
	}
	pc.OSVersion = "Windows 11 Pro N 26H2 (26300.9500)"
	if res := ix.Match(pc); len(res.OS) != 1 || res.OS[0].Basis != "build_revision" {
		t.Errorf("older UBR not listed: %+v", res.OS)
	}
	srv := Endpoint{OS: "windows", OSVersion: "Windows 11 Pro 24H2 (26100.100)", Build: 26100, Arch: "x64"}
	if res := ix.Match(srv); len(res.OS) != 0 {
		t.Errorf("server update offered to a client: %+v", res.OS)
	}
	if res := ix.Match(Endpoint{OS: "linux"}); len(res.OS)+len(res.Apps) != 0 {
		t.Error("linux endpoint matched")
	}
	var nilIx *Index
	if res := nilIx.Match(vm); res.Apps == nil || res.OS == nil {
		t.Error("nil index must return empty, non-nil lists")
	}
}

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{
		"Mozilla Firefox (x64 en-US)":   "mozillafirefox",
		"7-Zip 24.08 (x64)":             "7zip",
		"Google Chrome":                 "googlechrome",
		"mozillafirefox(X64)":           "mozillafirefox",
		"Notepad++ v8.6.4 64-bit":       "notepad",
		"Microsoft Visual C++ 2013 x64": "microsoftvisualc2013",
		"googlechrome测试版":               "googlechrome测试版",
	} {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"155.0.8059.82", "155.0.8059.85", -1},
		{"10.0.10", "10.0.2", 1},
		{"1.2", "1.2.0", 0},
		{"3.0.24", "3.0.24", 0},
		{"26.1.0", "26.1", 0},
		{"2.0.0-beta", "2.0.0", 1},
		{"", "1.0", -1},
	} {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
