package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

func exeBlock(typ string) *manifest.ExeInstall {
	return &manifest.ExeInstall{
		InstallerType: typ,
		SilentArgs:    manifest.DefaultSilentArgs(typ),
		SuccessCodes:  []int{0, 3010, 1641, 8},
		BusyCodes:     []int{1618, 5},
		Signer:        "Example Corp",
		Detect:        manifest.ExeDetect{DisplayName: "Example App", DisplayVersion: "2.1.0"},
		Uninstall:     manifest.ExeUninstall{QuietUninstall: true},
		Scope:         manifest.ExeScopeMachine,
	}
}

func exePkg(typ string) manifest.Package {
	return manifest.Package{
		PackageID: "example-2.1.0", Title: "Example App 2.1.0", Kind: manifest.KindExe, Version: "2.1.0",
		PackageName: "Example App", Exe: exeBlock(typ),
		File: manifest.FileRef{Name: "payload/example-setup.exe"},
	}
}

func TestClassifyExe(t *testing.T) {
	burn := exeBlock(manifest.ExeTypeBurn)
	burn.BusyCodes = nil
	inno := exeBlock(manifest.ExeTypeInno)
	inno.BusyCodes = nil
	cases := []struct {
		name      string
		e         *manifest.ExeInstall
		code      int
		uninstall bool
		state     string
		want      string
	}{
		{"zero", exeBlock("exe"), 0, false, "installed", "exe installed"},
		{"listed success", exeBlock("exe"), 8, false, "installed", "exit code 8"},
		{"3010 even when listed", exeBlock("inno"), 3010, false, "pending_reboot", "reboot required"},
		{"1641", exeBlock("nullsoft"), 1641, false, "pending_reboot", "reboot required"},
		{"3010 not listed", inno, 3010, false, "pending_reboot", "reboot required"},
		{"HRESULT 3010", inno, hr(0x80070BC2), false, "pending_reboot", "reboot"},
		{"busy code", exeBlock("exe"), 5, false, "failed", retryLater},
		{"burn msi busy", burn, 1618, false, "failed", retryLater},
		{"1618 not busy for inno", inno, 1618, false, "failed", "installer exit code 1618 (0x00000652)"},
		{"other", exeBlock("nullsoft"), 2, false, "failed", "installer exit code 2 (0x00000002)"},
		{"negative", inno, -1, false, "failed", "installer exit code -1 (0xFFFFFFFF)"},
		{"hresult failure", burn, hr(0x80070643), false, "failed", "(0x80070643)"},
		{"uninstall ok", exeBlock("inno"), 0, true, "installed", "exe uninstalled"},
		{"uninstall reboot", exeBlock("burn"), 3010, true, "pending_reboot", "uninstalled; reboot required"},
		{"uninstall fail", inno, 1, true, "failed", "uninstaller exit code 1"},
	}
	for _, c := range cases {
		r := classifyExe(c.e, c.code, c.uninstall)
		if r.State != c.state || !strings.Contains(r.Detail, c.want) || r.ExitCode != c.code {
			t.Errorf("%s: classifyExe(%d) = %+v, want %s / %q", c.name, c.code, r, c.state, c.want)
		}
	}
	// A manifest code given as a negative int32 matches the uint32 exit code.
	e := exeBlock("exe")
	e.SuccessCodes = []int{0, -2147024891} // 0x80070005
	if r := classifyExe(e, hr(0x80070005), false); r.State != "installed" {
		t.Errorf("negative manifest code: %+v", r)
	}
}

func TestExeArgs(t *testing.T) {
	got, err := exeArgs(exeBlock(manifest.ExeTypeInno))
	if err != nil || !slices.Equal(got, []string{"/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-"}) {
		t.Fatalf("inno args: %v %v", got, err)
	}
	for name, args := range map[string][]string{
		"none":      nil,
		"empty arg": {"/S", ""},
		"quote":     {`/D="C:\x"`},
		"newline":   {"/S\n&calc"},
		"too long":  {strings.Repeat("a", maxExeArgLen+1)},
	} {
		e := exeBlock("exe")
		e.SilentArgs = args
		if _, err := exeArgs(e); err == nil {
			t.Errorf("%s: %q accepted", name, args)
		}
	}
	if _, err := exeArgs(nil); err == nil {
		t.Error("nil exe block accepted")
	}
}

func TestBuildCmdLine(t *testing.T) {
	exe := `C:\ProgramData\offpatch\exetmp\pkg-1\setup.exe`
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"/S"}, `"` + exe + `" /S`},
		{[]string{"/quiet", "/norestart"}, `"` + exe + `" /quiet /norestart`},
		{[]string{"/LOG=C:\\a b\\x.log"}, `"` + exe + `" "/LOG=C:\a b\x.log"`},
		{[]string{`C:\dir with space\`}, `"` + exe + `" "C:\dir with space\\"`},
		{[]string{"a&b", "x|y"}, `"` + exe + `" a&b x|y`}, // no shell: plain characters
	}
	for _, c := range cases {
		got := buildCmdLine(exe, c.args)
		if got != c.want {
			t.Errorf("buildCmdLine(%q) = %s, want %s", c.args, got, c.want)
		}
		if back := splitCommandLine(got); !slices.Equal(back, append([]string{exe}, c.args...)) {
			t.Errorf("round trip of %q: %q", c.args, back)
		}
	}
}

func TestSplitCommandLine(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{`"C:\Program Files\App\unins000.exe" /VERYSILENT`, []string{`C:\Program Files\App\unins000.exe`, "/VERYSILENT"}},
		{`C:\App\u.exe   /S  `, []string{`C:\App\u.exe`, "/S"}},
		{`"C:\P F\x.exe" "/arg with space" b`, []string{`C:\P F\x.exe`, "/arg with space", "b"}},
		{`x.exe a\\\"b`, []string{"x.exe", `a\"b`}},
		{`x.exe "a\\" b`, []string{"x.exe", `a\`, "b"}},
		{`x.exe a\b\\c`, []string{"x.exe", `a\b\\c`}},
		{`x.exe "a""b"`, []string{"x.exe", `a"b`}},
		{`x.exe "c""d" e`, []string{"x.exe", `c"d e`}},
		{`"C:\a\b\"x.exe`, []string{`C:\a\b\x.exe`}}, // argv[0]: backslashes are literal
		{`MsiExec.exe /X{11111111-2222-3333-4444-555555555555} /qn`, []string{"MsiExec.exe", "/X{11111111-2222-3333-4444-555555555555}", "/qn"}},
	}
	for _, c := range cases {
		if got := splitCommandLine(c.in); !slices.Equal(got, c.want) {
			t.Errorf("splitCommandLine(%s) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestQuietUninstall(t *testing.T) {
	sys := `C:\Windows\System32`
	ok := []struct {
		in, exe string
	}{
		{`"C:\Program Files\Example\unins000.exe" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART`, `C:\Program Files\Example\unins000.exe`},
		{`"C:\ProgramData\Package Cache\{0D2C}\vc_redist.x64.exe" /uninstall /quiet`, `C:\ProgramData\Package Cache\{0D2C}\vc_redist.x64.exe`},
		{`C:\Apps\Tool\uninst.exe /S`, `C:\Apps\Tool\uninst.exe`},
		{`MsiExec.exe /X{11111111-2222-3333-4444-555555555555} /qn`, sys + `\msiexec.exe`},
		{`msiexec /x {11111111-2222-3333-4444-555555555555} /quiet`, sys + `\msiexec.exe`},
		{`"C:\Program Files\A&B\uninst.exe" /S`, `C:\Program Files\A&B\uninst.exe`}, // & inside quotes is a path character
	}
	for _, c := range ok {
		exe, argv, err := quietUninstall(c.in, sys)
		if err != nil || !strings.EqualFold(exe, c.exe) || len(argv) == 0 {
			t.Errorf("quietUninstall(%s) = %q %q %v, want %s", c.in, exe, argv, err, c.exe)
		}
	}
	bad := map[string]string{
		``:                                       "empty",
		`cmd /c "C:\x\uninst.exe /S"`:            "shell",
		`cmd.exe /c C:\x\uninst.exe /S`:          "shell",
		`C:\Windows\System32\cmd.exe /c del C:\`: "shell",
		`powershell -c Remove-Item x`:            "shell",
		`"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -File x.ps1`: "shell",
		`rundll32.exe C:\x.dll,Uninstall`:                                         "shell",
		`"C:\x\uninst.exe" /S & calc.exe`:                                         "shell operator",
		`"C:\x\uninst.exe" /S > C:\log.txt`:                                       "shell operator",
		`"C:\x\uninst.exe" /S | more`:                                             "shell operator",
		`"%ProgramFiles%\x\uninst.exe" /S`:                                        "environment variables",
		`C:\Program Files\App\uninst.exe /S`:                                      "unquoted",
		`uninst.exe /S`:                                                           "absolute",
		`"\\server\share\uninst.exe" /S`:                                          "absolute",
		`"C:\x\uninstall.bat" /S`:                                                 "not an .exe",
		"\"C:\\x\\u.exe\" /S\r\nC:\\evil.exe":                                     "control characters",
	}
	for in, want := range bad {
		if _, _, err := quietUninstall(in, sys); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("quietUninstall(%q) err = %v, want %q", in, err, want)
		}
	}
}

func TestSignerMatches(t *testing.T) {
	cases := []struct {
		want, cn, org string
		ok            bool
	}{
		{"Microsoft Corporation", "Microsoft Corporation", "Microsoft Corporation", true},
		{"microsoft  corporation", "Microsoft Corporation", "", true},
		{"Microsoft", "Microsoft Corporation", "Microsoft", false}, // CN decides; no substring
		{"Microsoft Corporation", "Microsoft Corporation Fake Ltd", "", false},
		{"Example Corp", "", "Example Corp", true}, // no CN: the organisation
		{"Example Corp", "", "", false},
		{"", "", "", false},
		{"  ", "x", "x", false},
	}
	for _, c := range cases {
		if got := signerMatches(c.want, c.cn, c.org); got != c.ok {
			t.Errorf("signerMatches(%q, %q, %q) = %v", c.want, c.cn, c.org, got)
		}
	}
}

func TestSignatureCheckOrder(t *testing.T) {
	calls := 0
	fail := func(string) error { calls++; return errors.New("the file has no embedded Authenticode signature") }
	if err := signatureCheck("x", "Example Corp", fail); err == nil || calls != 1 {
		t.Fatalf("verify failure must stop the check: %v", err)
	}
	if err := signatureCheck("x", "", fail); err == nil || calls != 1 {
		t.Fatal("a manifest without signer must be refused before verifying")
	}
	r := sigFailure(errors.New("signed by \"Evil\", expected \"Example Corp\""))
	if r.State != "failed" || !strings.HasPrefix(r.Detail, sigCheckFailed) || !strings.Contains(r.Detail, "possible tampering") {
		t.Fatalf("sigFailure: %+v", r)
	}
}

// TestPKCS7Signer builds a SignedData with an extra certificate first and
// checks that the signer is found by issuer + serial.
func TestPKCS7Signer(t *testing.T) {
	mk := func(cn, org string, serial int64) []byte {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn, Organization: []string{org}},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	other, signer := mk("Timestamp CA", "TS Inc", 7), mk("Example Corp", "Example Corp Org", 42)
	sc, _ := x509.ParseCertificate(signer)
	type issuerSerial struct {
		Issuer asn1.RawValue
		Serial *big.Int
	}
	type si struct {
		Version         int
		IssuerAndSerial issuerSerial
		DigestAlgorithm pkix.AlgorithmIdentifier
		DigestEnc       pkix.AlgorithmIdentifier
		EncryptedDigest []byte
	}
	type sd struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		ContentInfo      asn1.RawValue
		Certificates     asn1.RawValue
		SignerInfos      []si `asn1:"set"`
	}
	sha256OID := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}}
	emptySet, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true})
	inner, _ := asn1.Marshal(struct{ OID asn1.ObjectIdentifier }{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}})
	body, err := asn1.Marshal(sd{
		Version:          1,
		DigestAlgorithms: asn1.RawValue{FullBytes: emptySet},
		ContentInfo:      asn1.RawValue{FullBytes: inner},
		Certificates:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: append(append([]byte{}, other...), signer...)},
		SignerInfos: []si{{Version: 1, IssuerAndSerial: issuerSerial{Issuer: asn1.RawValue{FullBytes: sc.RawIssuer}, Serial: big.NewInt(42)},
			DigestAlgorithm: sha256OID, DigestEnc: sha256OID, EncryptedDigest: []byte{1, 2, 3}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ci, err := asn1.Marshal(struct {
		OID     asn1.ObjectIdentifier
		Content asn1.RawValue
	}{oidSignedData, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: body}})
	if err != nil {
		t.Fatal(err)
	}
	c, err := pkcs7Signer(ci)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject.CommonName != "Example Corp" || c.SerialNumber.Int64() != 42 {
		t.Fatalf("wrong signer: %v", c.Subject)
	}
	if _, err := pkcs7Signer([]byte{0x30, 0x03, 0x02, 0x01, 0x01}); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestPESignerUnsignedAndNotPE(t *testing.T) {
	dir := t.TempDir()
	notPE := filepath.Join(dir, "x.exe")
	os.WriteFile(notPE, []byte("MZ but not really a PE file"), 0o600)
	if _, _, err := peSigner(notPE); err == nil {
		t.Fatal("non-PE file accepted")
	}
	// The test binary itself is a PE on Windows and has no signature.
	if self, err := os.Executable(); err == nil && strings.HasSuffix(strings.ToLower(self), ".exe") {
		if _, _, err := peSigner(self); err == nil || !strings.Contains(err.Error(), "no embedded Authenticode signature") {
			t.Fatalf("unsigned test binary: %v", err)
		}
	}
}

func TestExeInventoryMatching(t *testing.T) {
	p := exePkg(manifest.ExeTypeInno)
	item := func(id, name, ver string) store.InventoryItem {
		return store.InventoryItem{Kind: "product", ID: id, Name: name, Version: ver}
	}
	cases := []struct {
		name     string
		it       store.InventoryItem
		match    bool
		upToDate bool
	}{
		{"exact name, same version", item("Example App_is1", "Example App", "2.1.0"), true, true},
		{"newer", item("Example App_is1", "Example App", "2.2.0"), true, true},
		{"older", item("Example App_is1", "Example App", "2.0.9"), true, false},
		{"no version", item("Example App_is1", "Example App", ""), true, false},
		{"name with version suffix", item("x", "Example App 2.1.0", "2.1.0"), true, true},
		{"other app", item("y", "Example Tools", "9.0"), false, false},
		{"kb", store.InventoryItem{Kind: "kb", ID: "KB1", Name: "Example App"}, false, false},
		{"user scope", store.InventoryItem{Kind: "product", ID: "x", Name: "Example App", Version: "2.1.0", Scope: "user"}, false, false},
	}
	for _, c := range cases {
		if got := exeAppMatch(p, c.it); got != c.match {
			t.Errorf("%s: exeAppMatch = %v", c.name, got)
		}
		if got := exeUpToDate(p, c.it); got != c.upToDate {
			t.Errorf("%s: exeUpToDate = %v", c.name, got)
		}
	}
	// Architecture is part of the identity (VC++ x86 vs x64).
	vc := exePkg(manifest.ExeTypeBurn)
	vc.Exe.Detect = manifest.ExeDetect{DisplayName: "Microsoft Visual C++ 2015-2022 Redistributable (x64)", DisplayVersion: "14.40.33810.0"}
	if exeAppMatch(vc, item("{A}", "Microsoft Visual C++ 2015-2022 Redistributable (x86) - 14.40.33810", "14.40.33810.0")) {
		t.Error("x86 redistributable matched the x64 package")
	}
	if !exeUpToDate(vc, item("{B}", "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.40.33810", "14.40.33810.0")) {
		t.Error("x64 redistributable not recognised")
	}
	// The ARP key wins when known, whatever the name.
	vc.Exe.Detect.ProductCode = "{0D2C}"
	if !exeAppMatch(vc, item("{0d2c}", "renamed", "14.40.33810.0")) {
		t.Error("product code match")
	}
	// Without detect.display_version, the package version is expected.
	p.Exe.Detect.DisplayVersion = ""
	if !exeUpToDate(p, item("k", "Example App", "2.1.0")) || exeUpToDate(p, item("k", "Example App", "2.0")) {
		t.Error("package version fallback")
	}
}

func TestChooseARPEntry(t *testing.T) {
	p := exePkg(manifest.ExeTypeInno)
	entries := []arpEntry{
		{Key: "Other", DisplayName: "Other App", QuietUninstall: `"C:\o\u.exe" /S`},
		{Key: "Example App_is1", DisplayName: "Example App", DisplayVersion: "1.0"},
		{Key: "Example App 2_is1", DisplayName: "Example App", DisplayVersion: "2.1.0", QuietUninstall: `"C:\e\unins000.exe" /VERYSILENT`},
	}
	e, ok := chooseARPEntry(p, entries)
	if !ok || e.Key != "Example App 2_is1" {
		t.Fatalf("by name+version: %+v %v", e, ok)
	}
	p.Exe.Detect.ProductCode = "example app_is1"
	if e, ok := chooseARPEntry(p, entries); !ok || e.Key != "Example App_is1" {
		t.Fatalf("by key: %+v", e)
	}
	p.Exe.Detect = manifest.ExeDetect{DisplayName: "Missing"}
	if _, ok := chooseARPEntry(p, entries); ok {
		t.Fatal("missing app found")
	}
}

func TestNewestLogAndBurnTail(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "Bundle_20260101.log")
	os.WriteFile(old, []byte("old log\n"), 0o600)
	os.Chtimes(old, time.Now().Add(-time.Hour), time.Now().Add(-time.Hour))
	newer := filepath.Join(dir, "Bundle_20260102.log")
	os.WriteFile(newer, []byte("[0A2C:1B34][2026-01-02T10:00:00]i001: Burn v3.14\n[0A2C:1B34][2026-01-02T10:00:01]e000: Error 0x80070643: Failed to install MSI package.\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o600)
	if got := newestLog(dir); got != newer {
		t.Fatalf("newestLog = %s", got)
	}
	fail := Result{State: "failed", ExitCode: 1603, Detail: "installer exit code 1603 (0x00000643)"}
	r := withBurnLog(fail, exeBlock(manifest.ExeTypeBurn), dir)
	if !strings.Contains(r.Detail, burnLogHeader) || !strings.Contains(r.Detail, "Error 0x80070643") {
		t.Fatalf("burn tail missing: %q", r.Detail)
	}
	if r := withBurnLog(fail, exeBlock(manifest.ExeTypeInno), dir); r.Detail != fail.Detail {
		t.Fatalf("non-burn got a log tail: %q", r.Detail)
	}
	busy := Result{State: "failed", Detail: retryLater + " (x)"}
	if r := withBurnLog(busy, exeBlock(manifest.ExeTypeBurn), dir); r.Detail != busy.Detail {
		t.Fatal("retry-later detail must stay unchanged")
	}
	if newestLog(filepath.Join(dir, "missing")) != "" {
		t.Fatal("missing dir")
	}
}

func TestSimExeInstallAndRollback(t *testing.T) {
	dir := t.TempDir()
	sim := NewSim(SimConfig{Hostname: "h"}, filepath.Join(dir, "sim.json"))
	file := filepath.Join(dir, "setup.exe")
	os.WriteFile(file, []byte("MZ"), 0o600)
	p := exePkg(manifest.ExeTypeInno)
	p.Exe.Detect.ProductCode = "Example App_is1"
	// An older version is present; the install replaces its entry.
	st := sim.load()
	st.Products = append(st.Products, store.InventoryItem{Kind: "product", ID: "Example App_is1", Name: "Example App", Version: "1.0"})
	sim.save(st)
	if r := sim.Install(context.Background(), p, file); r.State != "installed" {
		t.Fatalf("install: %+v", r)
	}
	inv, _, _ := sim.Inventory()
	n, up := 0, false
	for _, it := range inv {
		if exeAppMatch(p, it) {
			n++
			up = exeUpToDate(p, it)
		}
	}
	if n != 1 || !up {
		t.Fatalf("inventory after install: %+v", inv)
	}
	// Rollback without a quiet uninstall is refused.
	noQ := p
	noQ.Exe = exeBlock(manifest.ExeTypeNullsoft)
	noQ.Exe.Uninstall.QuietUninstall = false
	if r := sim.Uninstall(context.Background(), noQ); r.State != "failed" || r.Detail != exeRollbackUnsupported {
		t.Fatalf("unsupported rollback: %+v", r)
	}
	if r := sim.Uninstall(context.Background(), p); r.State != "installed" || !strings.Contains(r.Detail, "uninstall succeeded") {
		t.Fatalf("rollback: %+v", r)
	}
	inv, _, _ = sim.Inventory()
	for _, it := range inv {
		if exeAppMatch(p, it) {
			t.Fatalf("still installed after rollback: %+v", it)
		}
	}
	// FailKBs names EXE packages by ARP key.
	failing := NewSim(SimConfig{FailKBs: []string{"example app_is1"}}, filepath.Join(dir, "sim2.json"))
	if r := failing.Install(context.Background(), p, file); r.State != "failed" {
		t.Fatalf("simulated failure: %+v", r)
	}
	// An exe package without silent args is never run.
	bad := exePkg("exe")
	bad.Exe.SilentArgs = nil
	if r := sim.Install(context.Background(), bad, file); r.State != "failed" {
		t.Fatalf("no silent args: %+v", r)
	}
}
