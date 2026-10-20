package acqpolicy

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func validPolicy() Policy {
	return Policy{
		Windows: []Windows{{Product: " Windows 11  Version 24H2", Build: 26100, Arch: "X64", Enabled: true}},
		Apps:    []App{{ID: "Google.Chrome", Arch: []string{"x64", "X64", "arm64"}, Enabled: true, Note: "browser"}},
		Sources: []Source{
			{ID: "winget", Type: "winget", Enabled: true},
			{ID: "acme", Type: "vendor-url", Enabled: true, Name: "Acme Agent", URL: "https://downloads.acme.example/agent-2.3.0.msi",
				ExpectedSHA256: strings.Repeat("AB", 32), Kind: "msi", Version: "2.3.0"},
			{ID: "mirror", Type: "internal-mirror", Enabled: true, URL: "https://mirror.bank.example/winget/", Replaces: "winget-manifests"},
		},
		Limits: Limits{MaxDownloadGBPerRun: 50, KeepLastNVersions: 3},
	}
}

func TestNormalizeDefaultsAndIdempotent(t *testing.T) {
	p := validPolicy()
	if err := p.Normalize(); err != nil {
		t.Fatal(err)
	}
	if p.Windows[0].Product != "Windows 11 Version 24H2" || p.Windows[0].Arch != "x64" || p.Windows[0].Classification != ClassSecurity {
		t.Errorf("windows not normalized: %+v", p.Windows[0])
	}
	if a := p.Apps[0]; a.Source != "winget" || a.Channel != "latest" || strings.Join(a.Arch, ",") != "x64,arm64" {
		t.Errorf("app not normalized: %+v", a)
	}
	if p.Sources[1].ExpectedSHA256 != strings.Repeat("ab", 32) {
		t.Errorf("sha not lower-cased")
	}
	before := Canonical(p)
	if err := p.Normalize(); err != nil || !bytes.Equal(before, Canonical(p)) {
		t.Errorf("normalize not idempotent: %v", err)
	}
}

func TestNormalizeRejects(t *testing.T) {
	cases := map[string]func(p *Policy){
		"must start with https://":       func(p *Policy) { p.Sources[1].URL = "http://downloads.acme.example/a.msi" },
		"user name or password":          func(p *Policy) { p.Sources[1].URL = "https://u:pw@downloads.acme.example/a.msi" },
		"credentials (query parameter":   func(p *Policy) { p.Sources[1].URL = "https://downloads.acme.example/a.msi?access_token=1" },
		"expected_sha256 or signer":      func(p *Policy) { p.Sources[1].ExpectedSHA256 = "" },
		"64 hexadecimal":                 func(p *Policy) { p.Sources[1].ExpectedSHA256 = "abc" },
		"not both":                       func(p *Policy) { p.Sources[1].Signer = "Acme Inc" },
		"exe is not supported":           func(p *Policy) { p.Sources[1].Kind = "exe" },
		"an msu needs its KB":            func(p *Policy) { p.Sources[1].Kind = "msu" },
		"not a winget package id":        func(p *Policy) { p.Apps[0].ID = "chrome" },
		"listed twice":                   func(p *Policy) { p.Apps = append(p.Apps, App{ID: "google.chrome", Arch: []string{"x64"}}) },
		"choose at least one":            func(p *Policy) { p.Apps[0].Arch = nil },
		"security or all":                func(p *Policy) { p.Windows[0].Classification = "optional" },
		"a Windows build number":         func(p *Policy) { p.Windows[0].Build = 0 },
		"only one enabled winget":        func(p *Policy) { p.Sources = append(p.Sources, Source{ID: "winget2", Type: "winget", Enabled: true}) },
		"used twice":                     func(p *Policy) { p.Sources[2].ID = "acme" },
		"replaces: one of":               func(p *Policy) { p.Sources[2].Replaces = "github" },
		"does not apply":                 func(p *Policy) { p.Sources[0].ExpectedSHA256 = strings.Repeat("a", 64) },
		"max_download_gb_per_run":        func(p *Policy) { p.Limits.MaxDownloadGBPerRun = -1 },
		"keep_last_n_versions":           func(p *Policy) { p.Limits.KeepLastNVersions = 1000 },
		"type: one of":                   func(p *Policy) { p.Sources[0].Type = "ftp" },
		"product_code: the MSI's {GUID}": func(p *Policy) { p.Sources[1].ProductCode = "{00000000-0000-0000-0000-000000000000}" },
		"must not contain a #fragment":   func(p *Policy) { p.Sources[2].URL = "https://mirror.bank.example/#x" },
		"version: like 1.2.3":            func(p *Policy) { p.Sources[1].Version = "latest" },
		"no control characters":          func(p *Policy) { p.Apps[0].Note = "a\x07b" },
	}
	for want, mut := range cases {
		p := validPolicy()
		mut(&p)
		err := p.Normalize()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v", want, err)
		}
	}
	// A disabled duplicate is fine (only enabled sources of a type are unique).
	p := validPolicy()
	p.Sources = append(p.Sources, Source{ID: "winget-old", Type: "winget", Enabled: false})
	if err := p.Normalize(); err != nil {
		t.Errorf("disabled duplicate refused: %v", err)
	}
}

func TestFileRoundTripAndTamper(t *testing.T) {
	p := validPolicy()
	if err := p.Normalize(); err != nil {
		t.Fatal(err)
	}
	f := NewFile(7, "user:sam", "2026-10-18T10:00:00Z", p)
	b, _ := json.MarshalIndent(f, "", "  ")
	got, err := ParseFile(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if got.PolicyVersion != 7 || got.SHA256 != Hash(p) {
		t.Fatalf("round trip: %+v", got)
	}
	tampered := bytes.Replace(b, []byte("Google.Chrome"), []byte("Google.Chrom2"), 1)
	if _, err := ParseFile(bytes.NewReader(tampered)); err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Errorf("tampered file accepted: %v", err)
	}
	unknown := bytes.Replace(b, []byte(`"format"`), []byte(`"extra": 1, "format"`), 1)
	if _, err := ParseFile(bytes.NewReader(unknown)); err == nil {
		t.Error("unknown field accepted")
	}
	// Hash matches but the content is invalid: still refused.
	bad := p
	bad.Sources = append([]Source{}, p.Sources...)
	bad.Sources[1].URL = "http://x.example/a.msi"
	bf := NewFile(8, "user:sam", "2026-10-18T10:00:00Z", bad)
	bb, _ := json.Marshal(bf)
	if _, err := ParseFile(bytes.NewReader(bb)); err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("invalid policy accepted: %v", err)
	}
}

func TestRunRequest(t *testing.T) {
	r := RunRequest{Format: RunFormat, Version: RunVersion, RunID: "run-20261018T100000Z-abc", RequestedBy: "user:sam", RequestedAt: "2026-10-18T10:00:00Z"}
	b, _ := json.Marshal(r)
	if _, err := ParseRun(bytes.NewReader(b)); err != nil {
		t.Fatal(err)
	}
	r.RunID = "../x"
	b, _ = json.Marshal(r)
	if _, err := ParseRun(bytes.NewReader(b)); err == nil {
		t.Error("bad run id accepted")
	}
}

func TestFromAcquireJSON(t *testing.T) {
	b := []byte(`{"work_dir": "/var/lib/x", "microsoft": {"months": 1, "min_severity": "critical", "products": [
	  {"msrc_product": "Windows 11 Version 24H2", "catalog_product": "Windows 11 Version 24H2", "arch": "x64", "min_build": 26100, "max_build": 26100},
	  {"msrc_product": "Windows 11 Version 23H2", "arch": "x64"},
	  {"msrc_product": "Contoso OS", "arch": "x64", "min_build": 1, "max_build": 9}]},
	  "catalog_url": "https://catalog.mirror.example", "apps": [{"name": "acme", "title": "Acme"}], "intel": {}}`)
	base, err := FromAcquireJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(base.Policy.Windows) != 2 || base.Policy.Windows[0].Build != 26100 || base.Policy.Windows[1].Build != 22631 {
		t.Errorf("windows: %+v", base.Policy.Windows)
	}
	if len(base.Policy.Sources) != 3 || base.Policy.Sources[1].URL != "https://catalog.mirror.example" {
		t.Errorf("sources: %+v", base.Policy.Sources)
	}
	if len(base.Feeds) != 2 {
		t.Errorf("feeds: %v", base.Feeds)
	}
}

func TestDiff(t *testing.T) {
	a := validPolicy()
	a.Normalize()
	b := validPolicy()
	b.Normalize()
	b.Apps[0].Enabled = false
	b.Apps = append(b.Apps, App{Source: "winget", ID: "7zip.7zip", Arch: []string{"x64"}, Channel: "latest", Enabled: true})
	b.Sources = b.Sources[:2]
	b.Limits.MaxDownloadGBPerRun = 0
	got := strings.Join(Diff(a, b), "\n")
	for _, w := range []string{"changed app Google.Chrome (off)", "added app 7zip.7zip", "removed source mirror (internal-mirror)", "50 GB → no limit"} {
		if !strings.Contains(got, w) {
			t.Errorf("diff missing %q:\n%s", w, got)
		}
	}
	if d := Diff(a, a); len(d) != 0 {
		t.Errorf("no change: %v", d)
	}
}

// Builds that share KB numbers get distinct package IDs; existing IDs stay.
func TestKBPackageSuffix(t *testing.T) {
	for _, c := range []struct {
		product string
		server  bool
		build   int
		want    string
	}{
		{"Windows 11 Version 24H2 for x64-based Systems", false, 26100, ""},
		{"Windows 11 Version 25H2 for x64-based Systems", false, 26200, "-26200"},
		{"Windows 11 Version 23H2 for x64-based Systems", false, 22631, "-22631"},
		{"Windows Server 2025", false, 26100, "-server"},
		{"Windows 11 Version 24H2", true, 26100, "-server"},
	} {
		if got := KBPackageSuffix(c.product, c.server, c.build); got != c.want {
			t.Errorf("%s %d: %q, want %q", c.product, c.build, got, c.want)
		}
	}
}
