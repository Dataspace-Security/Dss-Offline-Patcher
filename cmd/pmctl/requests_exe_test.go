package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"offpatch/internal/acqrequest"
	"offpatch/internal/acquire/acquiretest"
	peauth "offpatch/internal/acquire/authenticode"
	"offpatch/internal/manifest"
)

// stubExeVerify makes synthetic payloads verify as signed by signer.
func stubExeVerify(t *testing.T, signer string) {
	t.Helper()
	orig := exeVerify
	exeVerify = func(path string) (*peauth.Result, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if strings.Contains(string(b), "unsigned") {
			return nil, peauth.ErrNotSigned
		}
		return &peauth.Result{Signer: signer, Digest: "sha256"}, nil
	}
	t.Cleanup(func() { exeVerify = orig; setExeTrust("", nil) })
}

// EXE installers from requests: WebView2 (exe), VC++ (burn), Git (inno)
// and Notepad++ arm64 (nullsoft) become kind exe packages, verified and
// delivered in a bundle of their own; the MSI goes in another.
func TestAutoAcquisitionRequestsExe(t *testing.T) {
	stubAuthenticode(t)
	stubExeVerify(t, "Microsoft Corporation")
	srv := acquiretest.New(t, "../../internal/acquire/testdata", acquiretest.Payload(50_000))
	const wv = "m/Microsoft/EdgeWebView2Runtime/155.0.4283.62/"
	const vc = "m/Microsoft/VCRedist/2015+/x64/14.51.36247.0/"
	wingetFixtures(t, srv,
		"g/Google/Chrome/155.0.8059.85/Google.Chrome.installer.yaml",
		wv+"Microsoft.EdgeWebView2Runtime.installer.yaml", wv+"Microsoft.EdgeWebView2Runtime.locale.en-US.yaml",
		vc+"Microsoft.VCRedist.2015+.x64.installer.yaml", vc+"Microsoft.VCRedist.2015+.x64.locale.en-US.yaml",
		"g/Git/Git/2.55.0.5/Git.Git.installer.yaml",
		"n/Notepad++/Notepad++/8.9.8.1/Notepad++.Notepad++.installer.yaml")
	oldHTTP, oldNow := autoHTTP, autoNow
	autoHTTP = func() *http.Client { return srv.Client() }
	autoNow = func() time.Time { return time.Date(2026, 10, 18, 3, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { autoHTTP, autoNow = oldHTTP, oldNow })

	dir := t.TempDir()
	pub, priv, _ := manifest.GenerateKey()
	os.WriteFile(filepath.Join(dir, "bundle.key"), manifest.EncodePrivate(priv), 0o600)
	drop := filepath.Join(dir, "diode")
	os.MkdirAll(drop, 0o750)
	cfgPath := filepath.Join(dir, "acquire.json")
	os.WriteFile(cfgPath, []byte(fmt.Sprintf(`{"work_dir": "work", "key": "bundle.key", "source": "acq-zone-1",
	  "send": {"via": "dropdir", "to": "diode"}, "requests": "requests", "winget_manifests_url": %q}`, srv.URL+"/vendor/manifests")), 0o600)
	req := acqrequest.Request{Apps: []acqrequest.App{
		{WingetID: "Google.Chrome", Name: "Google Chrome", Version: "155.0.8059.85", Architectures: []string{"x64"}, Endpoints: 1},
		{WingetID: "Microsoft.EdgeWebView2Runtime", Version: "155.0.4283.62", Architectures: []string{"x64"}, Endpoints: 3,
			Installed: []acqrequest.Installed{{Name: "Microsoft Edge WebView2 Runtime", Version: "154.0.4258.62"}}},
		{WingetID: "Microsoft.VCRedist.2015+.x64", Version: "14.51.36247.0", Architectures: []string{"x64"}, Endpoints: 2,
			Installed: []acqrequest.Installed{{Name: "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.40.33810", Version: "14.40.33810.0"}}},
		{WingetID: "Git.Git", Name: "Git", Version: "2.55.0.5", Architectures: []string{"x64"}, Endpoints: 1},
		{WingetID: "Notepad++.Notepad++", Name: "Notepad++", Version: "8.9.8.1", Architectures: []string{"arm64"}, Endpoints: 1},
	}}
	writeRequest(t, filepath.Join(dir, "requests"), "acq-request-exe.json", req)

	rep, err := runAuto(context.Background(), cfgPath, false)
	if err != nil || !rep.Sent || len(rep.Failures) != 0 || len(rep.New) != 5 {
		t.Fatalf("run: %v %+v", err, rep)
	}
	checkItems(t, rep.Items, "acq-request-exe", map[string][2]string{"Google.Chrome": {"fetched", ""}, "Microsoft.EdgeWebView2Runtime": {"fetched", ""},
		"Microsoft.VCRedist.2015+.x64": {"fetched", ""}, "Git.Git": {"fetched", ""}, "Notepad++.Notepad++": {"fetched", ""}})
	if w := strings.Join(rep.Warnings, "\n"); !strings.Contains(w, "nullsoft installer registers no known silent uninstall") {
		t.Errorf("no rollback warning for NSIS: %s", w)
	}

	bundles, _ := filepath.Glob(filepath.Join(drop, "*.pmb"))
	if len(bundles) != 2 {
		t.Fatalf("want an MSI bundle and an EXE bundle, got %v", bundles)
	}
	exes := map[string]manifest.Package{}
	for _, b := range bundles {
		ex, err := manifest.ExtractSafe(b, t.TempDir(), manifest.Limits{MaxFiles: 10})
		if err != nil {
			t.Fatal(err)
		}
		if err := manifest.Verify(pub, ex.ManifestBytes, ex.Signature); err != nil {
			t.Fatal(err)
		}
		m, err := manifest.Parse(ex.ManifestBytes)
		if err != nil {
			t.Fatal(err)
		}
		kinds := map[string]bool{}
		for _, p := range m.Packages {
			kinds[p.Kind] = true
			if p.Kind == manifest.KindExe {
				exes[p.Exe.InstallerType+"/"+p.Applicability.Arch] = p
			}
		}
		if len(kinds) != 1 {
			t.Errorf("bundle %s mixes kinds %v", m.BundleID, kinds)
		}
		if kinds["msi"] && strings.Contains(string(ex.ManifestBytes), `"exe"`) {
			t.Errorf("MSI bundle manifest mentions exe: %s", ex.ManifestBytes)
		}
	}
	if len(exes) != 4 {
		t.Fatalf("exe packages: %v", exes)
	}
	for k, p := range exes {
		if p.VendorSignature.Status != "valid" || p.VendorSignature.Signer != "Microsoft Corporation" || p.Exe.Signer != "Microsoft Corporation" ||
			p.PackageName != p.Exe.Detect.DisplayName || p.Exe.Scope != "machine" || !slices.Contains(p.Exe.SuccessCodes, 0) || !strings.HasSuffix(p.File.Name, ".exe") {
			t.Errorf("%s: %+v %+v", k, p, p.Exe)
		}
	}
	wv2 := exes["exe/x64"]
	if wv2.PackageName != "Microsoft Edge WebView2 Runtime" || !slices.Equal(wv2.Exe.SilentArgs, []string{"/silent", "/install"}) ||
		wv2.Exe.Detect.ProductCode != "Microsoft EdgeWebView" || wv2.Version != "155.0.4283.62" || wv2.Exe.Uninstall.QuietUninstall {
		t.Errorf("webview2: %+v %+v", wv2, wv2.Exe)
	}
	vcr := exes["burn/x64"]
	if vcr.PackageName != "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.40.33810" || !vcr.Exe.Uninstall.QuietUninstall ||
		!slices.Equal(vcr.Exe.BusyCodes, []int{1618}) || vcr.Vendor != "Microsoft Corporation" {
		t.Errorf("vcredist: %+v %+v", vcr, vcr.Exe)
	}
	if g := exes["inno/x64"]; g.PackageName != "Git" || !g.Exe.Uninstall.QuietUninstall || g.Exe.SilentArgs[0] != "/SP-" {
		t.Errorf("git: %+v %+v", g, g.Exe)
	}
	if n := exes["nullsoft/arm64"]; !slices.Equal(n.Exe.SilentArgs, []string{"/S"}) || n.Exe.Uninstall.QuietUninstall {
		t.Errorf("notepad++: %+v %+v", n, n.Exe)
	}
}

// An unsigned EXE is refused (unsupported, file deleted); exe_signers
// limits accepted signers; build refuses a payload whose signer differs
// from the manifest's.
func TestExeSignatureChecks(t *testing.T) {
	stubExeVerify(t, "Contoso Ltd")
	d := t.TempDir()
	signed, unsigned := filepath.Join(d, "a.exe"), filepath.Join(d, "b.exe")
	os.WriteFile(signed, []byte("signed payload"), 0o644)
	os.WriteFile(unsigned, []byte("unsigned payload"), 0o644)
	if s, err := verifyExeSigner(signed); err != nil || s != "Contoso Ltd" {
		t.Fatalf("signed: %q %v", s, err)
	}
	if _, err := verifyExeSigner(unsigned); !errors.Is(err, errExeSignature) || !errors.Is(err, peauth.ErrNotSigned) {
		t.Fatalf("unsigned: %v", err)
	}
	if err := setExeTrust("", []string{"Microsoft Corporation"}); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyExeSigner(signed); err == nil || !strings.Contains(err.Error(), "not one of exe_signers") {
		t.Fatalf("allowlist: %v", err)
	}
	setExeTrust("", []string{"contoso ltd"})
	p := manifest.Package{Kind: manifest.KindExe, Exe: &manifest.ExeInstall{Signer: "Contoso Ltd"}}
	if vs, err := checkExeSignature(p, signed); err != nil || vs.Status != "valid" || vs.Signer != "Contoso Ltd" {
		t.Fatalf("check: %+v %v", vs, err)
	}
	p.Exe.Signer = "Someone Else"
	if _, err := checkExeSignature(p, signed); err == nil || !strings.Contains(err.Error(), "manifest names") {
		t.Fatalf("mismatch: %v", err)
	}
	if err := setExeTrust(filepath.Join(d, "missing.pem"), nil); err == nil {
		t.Fatal("missing roots file accepted")
	}
}
