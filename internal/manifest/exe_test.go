package manifest

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func exeManifest(t *testing.T) *Manifest {
	t.Helper()
	m := validManifest(t)
	m.Packages[0] = Package{
		PackageID: "Microsoft.EdgeWebView2Runtime-x64", Title: "Microsoft Edge WebView2 Runtime", Vendor: "Microsoft",
		Kind: KindExe, Version: "131.0.2903.112", Severity: "important",
		PackageName:     "Microsoft Edge WebView2 Runtime",
		Applicability:   Applicability{OS: "windows", Arch: "x64"},
		File:            FileRef{Name: "payload/MicrosoftEdgeWebView2RuntimeInstallerX64.exe", Size: 10, SHA256: strings.Repeat("b", 64)},
		SourceURL:       "https://msedge.sf.dl.delivery.mp.microsoft.com/x.exe",
		VendorSignature: VendorSignature{Status: "valid", Signer: "Microsoft Corporation"},
		Exe: &ExeInstall{
			InstallerType: ExeTypeBurn, SilentArgs: DefaultSilentArgs(ExeTypeBurn),
			SuccessCodes: []int{0, 3010, 1641}, BusyCodes: []int{1618},
			Signer: "Microsoft Corporation",
			Detect: ExeDetect{DisplayName: "Microsoft Edge WebView2 Runtime", DisplayVersion: "131.0.2903.112",
				ProductCode: "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}", Publisher: "Microsoft Corporation"},
			Uninstall: ExeUninstall{QuietUninstall: true},
			Scope:     ExeScopeMachine,
		},
	}
	return m
}

func TestExeManifestValidAndRoundTrip(t *testing.T) {
	m := exeManifest(t)
	if err := m.ValidateSchema(time.Now()); err != nil {
		t.Fatalf("valid exe manifest rejected: %v", err)
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{`"exe":{`, `"installer_type":"burn"`, `"silent_args":["/quiet","/norestart"]`,
		`"success_codes":[0,3010,1641]`, `"busy_codes":[1618]`, `"signer":"Microsoft Corporation"`,
		`"display_name":"Microsoft Edge WebView2 Runtime"`, `"quiet_uninstall":true`, `"scope":"machine"`} {
		if !bytes.Contains(b, []byte(k)) {
			t.Errorf("marshalled manifest lacks %s", k)
		}
	}
	back, err := Parse(b) // strict: unknown fields rejected
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back.Packages[0].Exe, m.Packages[0].Exe) {
		t.Fatalf("exe block round trip mismatch: %+v", back.Packages[0].Exe)
	}
	if !back.Packages[0].RollbackSupported() {
		t.Fatal("quiet_uninstall package should support rollback")
	}
	back.Packages[0].Exe.Uninstall.QuietUninstall = false
	if back.Packages[0].RollbackSupported() {
		t.Fatal("rollback must be unsupported without quiet_uninstall")
	}
}

// msi/msu manifests must stay byte-identical to the pre-EXE format.
func TestNonExeManifestHasNoExeKey(t *testing.T) {
	m := validManifest(t)
	b, _ := json.Marshal(m)
	if bytes.Contains(b, []byte(`"exe"`)) {
		t.Fatalf("msu manifest gained an exe key: %s", b)
	}
	const legacy = `"packages":[{"package_id":"KB5000001-x64","title":"t","vendor":"Microsoft","kind":"msu","version":"","kb":"KB5000001","product_code":"","severity":"critical","release_date":"","supersedes":null,"applicability":{"os":"windows","arch":"x64","min_build":0,"max_build":0},"file":{"name":"payload/a.msu","size":1,"sha256":"` + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + `"},"source_url":"","vendor_signature":{"status":"not_checked","signer":"","checked_at":""}}]}`
	if !strings.HasSuffix(string(b), legacy) {
		t.Fatalf("msu manifest bytes changed:\n%s", b)
	}
	if !(&m.Packages[0]).RollbackSupported() {
		t.Fatal("non-exe kinds keep their rollback behaviour")
	}
}

func TestExeManifestValidation(t *testing.T) {
	cases := map[string]func(p *Package){
		"no exe block":          func(p *Package) { p.Exe = nil },
		"bad installer type":    func(p *Package) { p.Exe.InstallerType = "msix" },
		"no silent args":        func(p *Package) { p.Exe.SilentArgs = nil },
		"quote in arg":          func(p *Package) { p.Exe.SilentArgs = []string{`/D="x"`} },
		"control in arg":        func(p *Package) { p.Exe.SilentArgs = []string{"/S\n"} },
		"no zero success":       func(p *Package) { p.Exe.SuccessCodes = []int{3010} },
		"busy overlaps success": func(p *Package) { p.Exe.BusyCodes = []int{3010} },
		"no signer":             func(p *Package) { p.Exe.Signer = "" },
		"no display name":       func(p *Package) { p.Exe.Detect.DisplayName = "" },
		"package name mismatch": func(p *Package) { p.PackageName = "Other" },
		"per user scope":        func(p *Package) { p.Exe.Scope = "user" },
		"no scope":              func(p *Package) { p.Exe.Scope = "" },
		"no version":            func(p *Package) { p.Version = "" },
		"msi product code":      func(p *Package) { p.ProductCode = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}" },
		"bad arp key":           func(p *Package) { p.Exe.Detect.ProductCode = `a\b` },
		"not .exe file":         func(p *Package) { p.File.Name = "payload/x.msi" },
		"linux os":              func(p *Package) { p.Applicability.OS = "linux" },
		"no sha256":             func(p *Package) { p.File.SHA256 = "" },
		"exe block on msi": func(p *Package) {
			p.Kind, p.ProductCode, p.File.Name = "msi", "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}", "payload/x.msi"
		},
	}
	for name, mut := range cases {
		m := exeManifest(t)
		mut(&m.Packages[0])
		if err := m.ValidateSchema(time.Now()); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
	// Types with a documented default are valid with those defaults.
	for _, typ := range []string{ExeTypeInno, ExeTypeNullsoft, ExeTypeBurn} {
		m := exeManifest(t)
		m.Packages[0].Exe.InstallerType, m.Packages[0].Exe.SilentArgs = typ, DefaultSilentArgs(typ)
		if err := m.ValidateSchema(time.Now()); err != nil {
			t.Errorf("%s defaults rejected: %v", typ, err)
		}
	}
	if DefaultSilentArgs(ExeTypeExe) != nil {
		t.Fatal("plain exe has no default silent switch")
	}
	// Plain exe is valid when the manifest supplies its documented switch.
	m := exeManifest(t)
	m.Packages[0].Exe.InstallerType, m.Packages[0].Exe.SilentArgs = ExeTypeExe, []string{"--silent", "--install"}
	if err := m.ValidateSchema(time.Now()); err != nil {
		t.Fatalf("plain exe with switch rejected: %v", err)
	}
}
