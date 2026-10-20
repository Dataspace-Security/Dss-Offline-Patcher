package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"offpatch/internal/acqpolicy"
	"offpatch/internal/manifest"
)

func writeSignedPolicy(t *testing.T, dir string, version int, p acqpolicy.Policy, k ed25519.PrivateKey) string {
	t.Helper()
	if err := p.Normalize(); err != nil {
		t.Fatal(err)
	}
	f := acqpolicy.NewFile(version, "user:sam", "2026-10-16T02:00:00Z", p)
	f.Sign(k)
	b, _ := json.MarshalIndent(f, "", "  ")
	os.MkdirAll(dir, 0o750)
	path := filepath.Join(dir, acqpolicy.FileName(version))
	if err := os.WriteFile(path, b, 0o640); err != nil {
		t.Fatal(err)
	}
	return path
}

// S-4: with policy_public_keys pinned, unsigned and wrongly signed policy
// files are refused (rejected/, reported) and the policy in force stays.
func TestPolicySignaturePinned(t *testing.T) {
	autoWarn = func(string) {}
	pub, priv, _ := manifest.GenerateKey()
	_, other, _ := manifest.GenerateKey()
	cdir := t.TempDir()
	c := &autoConfig{WorkDir: cdir, Requests: filepath.Join(cdir, "requests"), policyPins: []ed25519.PublicKey{pub}}
	p := acqpolicy.Empty()
	st := autoState{}

	writePolicy(t, c.Requests, 1, p) // unsigned
	pr := loadPolicy(c, false, &autoReport{}, &st)
	if pr.file != nil || !strings.Contains(strings.Join(pr.errs, ";"), "not signed") {
		t.Fatalf("unsigned policy: %+v %q", pr.file, pr.errs)
	}
	if _, err := os.Stat(filepath.Join(c.Requests, "rejected", acqpolicy.FileName(1))); err != nil {
		t.Errorf("unsigned policy not moved to rejected/: %v", err)
	}

	writeSignedPolicy(t, c.Requests, 2, p, other)
	if pr := loadPolicy(c, false, &autoReport{}, &st); pr.file != nil || !strings.Contains(strings.Join(pr.errs, ";"), "not in acquire.json policy_public_keys") {
		t.Fatalf("wrong key: %+v %q", pr.file, pr.errs)
	}

	writeSignedPolicy(t, c.Requests, 3, p, priv)
	rep := &autoReport{}
	pr = loadPolicy(c, false, rep, &st)
	if pr.file == nil || pr.file.PolicyVersion != 3 || pr.sigStatus != manifest.KeyID(pub) || len(pr.errs) != 0 {
		t.Fatalf("signed policy: %+v %q %q", pr.file, pr.sigStatus, pr.errs)
	}
	policyReport(rep, pr, filepath.Join(cdir, "missing.json"))
	if rep.PolicySignature != manifest.KeyID(pub) || strings.Contains(strings.Join(rep.Warnings, ";"), "without a signature check") {
		t.Fatalf("report: %q %q", rep.PolicySignature, rep.Warnings)
	}

	// A signed file whose envelope was edited afterwards is refused; v3 stays.
	path := writeSignedPolicy(t, c.Requests, 4, p, priv)
	b, _ := os.ReadFile(path)
	os.WriteFile(path, []byte(strings.Replace(string(b), "user:sam", "user:eve", 1)), 0o640)
	if pr := loadPolicy(c, false, &autoReport{}, &st); pr.file == nil || pr.file.PolicyVersion != 3 || !strings.Contains(strings.Join(pr.errs, ";"), "signature is not valid") {
		t.Fatalf("edited signed policy: %+v %q", pr.file, pr.errs)
	}
}

// S-4: without a pin (upgrades) policies are accepted with a warning; once
// the pin is added, the unsigned policy in force is refused and the signed
// copy of the same version the server queues is taken.
func TestPolicyUnpinnedWarns(t *testing.T) {
	autoWarn = func(string) {}
	pub, priv, _ := manifest.GenerateKey()
	cdir := t.TempDir()
	c := &autoConfig{WorkDir: cdir, Requests: filepath.Join(cdir, "requests")}
	st := autoState{}
	writePolicy(t, c.Requests, 1, acqpolicy.Empty())
	rep := &autoReport{}
	pr := loadPolicy(c, false, rep, &st)
	if pr.file == nil || !strings.HasPrefix(pr.sigStatus, unpinnedStatus) || !strings.Contains(strings.Join(rep.Warnings, ";"), "without a signature check") {
		t.Fatalf("unpinned: %+v %q %q", pr.file, pr.sigStatus, rep.Warnings)
	}

	c.policyPins = []ed25519.PublicKey{pub}
	pr = loadPolicy(c, false, &autoReport{}, &st)
	if pr.file != nil || !strings.Contains(strings.Join(pr.errs, ";"), "policy in force (version 1) is refused") {
		t.Fatalf("unsigned active policy after pinning: %+v %q", pr.file, pr.errs)
	}
	writeSignedPolicy(t, c.Requests, 1, acqpolicy.Empty(), priv)
	pr = loadPolicy(c, false, &autoReport{}, &st)
	if pr.file == nil || pr.file.PolicyVersion != 1 || pr.sigStatus != manifest.KeyID(pub) {
		t.Fatalf("signed copy of the same version: %+v %q %q", pr.file, pr.sigStatus, pr.errs)
	}
	// From now on the signed active policy is kept.
	if pr := loadPolicy(c, false, &autoReport{}, &st); pr.file == nil || len(pr.errs) != 0 {
		t.Fatalf("next run: %+v %q", pr.file, pr.errs)
	}
}

// S-4: raw.githubusercontent.com (anyone can publish there) is never a
// vendor-url source, even when allowed_source_hosts lists it; the winget
// manifests feed keeps using it.
func TestVendorURLNotFromSharedHosting(t *testing.T) {
	autoWarn = func(string) {}
	pol := acqpolicy.Policy{Sources: []acqpolicy.Source{
		{ID: "winget", Type: "winget", Enabled: true, ManifestsURL: "https://raw.githubusercontent.com/microsoft/winget-pkgs/master/manifests"},
		{ID: "evil", Type: "vendor-url", Enabled: true, Name: "Evil", URL: "https://raw.githubusercontent.com/evil/tools/main/tool.msi",
			ExpectedSHA256: strings.Repeat("a", 64), Kind: "msi", Version: "1.0.0"},
	}}
	if err := pol.Normalize(); err != nil {
		t.Fatal(err)
	}
	f := acqpolicy.NewFile(1, "user:sam", "2026-10-16T02:00:00Z", pol)
	for _, hosts := range [][]string{nil, {"default", "raw.githubusercontent.com"}} {
		c := &autoConfig{Intel: &intelOpts{}, AllowedSourceHosts: hosts}
		if err := setupNet(c); err != nil {
			t.Fatal(err)
		}
		pr := &policyRun{file: &f}
		applyPolicy(c, pr)
		res := map[string]string{}
		for _, r := range pr.results {
			res[r.ID] = r.Result + ": " + r.Detail
		}
		if len(pr.vendors) != 0 || !strings.Contains(res["evil"], "never a vendor-url download source") {
			t.Errorf("hosts %v: vendor-url on raw.githubusercontent.com: %+v %q", hosts, pr.vendors, res["evil"])
		}
		if !strings.HasPrefix(res["winget"], "applied") || c.WingetManifestsURL == "" {
			t.Errorf("hosts %v: winget manifests feed: %q", hosts, res["winget"])
		}
		// Redirects of a vendor download are held to the same rule.
		if err := c.netFor().vendor.CheckRawURL("https://raw.githubusercontent.com/a/b"); err == nil {
			t.Errorf("hosts %v: vendor guard allows raw.githubusercontent.com", hosts)
		}
	}
}

// S-4: a vendor-url source with expected_sha256 is still checked by
// Authenticode and the signer pin; the hash is an additional check. Where
// Authenticode is not available (MSI on Linux) the source is refused
// unless acquire.json vendor_sha256_pins confirms the hash.
func TestVendorHashPathChecksSigner(t *testing.T) {
	e := newAutoEnv(t, `"requests": "requests", "allowed_source_hosts": ["default", "127.0.0.1"],`)
	readMSICode = func(string) (string, error) { return "{22222222-3333-4444-5555-666666666666}", nil }
	authenticodeAnywhere = true
	t.Cleanup(func() { readMSICode, authenticodeAnywhere = msiProductCode, false })
	reqDir := filepath.Join(e.dir, "requests")
	ctx := context.Background()
	version := 0
	runWith := func(ver string, sha string, sig psSignature) string {
		t.Helper()
		body := []byte("vendor tool " + ver)
		e.srv.Vendor["tool-"+ver+".msi"] = body
		if sha == "" {
			s := sha256.Sum256(body)
			sha = hex.EncodeToString(s[:])
		}
		authenticode = func(string) (psSignature, error) { return sig, nil }
		version++
		writePolicy(t, reqDir, version, acqpolicy.Policy{Sources: []acqpolicy.Source{{ID: "tool", Type: "vendor-url", Enabled: true, Name: "Tool",
			URL: e.srv.URL + "/vendor/tool-" + ver + ".msi", ExpectedSHA256: sha, Kind: "msi", Version: ver}}})
		rep, err := runAuto(ctx, e.cfgPath, false)
		if err != nil {
			t.Fatalf("run %s: %v", ver, err)
		}
		for _, r := range rep.Sources {
			if r.ID == "tool" {
				return r.Result + ": " + r.Detail + " " + rep.Failures["tool-"+ver]
			}
		}
		t.Fatalf("no result for tool: %+v", rep.Sources)
		return ""
	}
	if got := runWith("1.0.0", "", psSignature{Status: "NotSigned"}); strings.HasPrefix(got, "new") {
		t.Fatalf("unsigned MSI with a matching hash accepted: %q", got)
	}
	if got := runWith("1.0.1", "", psSignature{Status: "Valid", Subject: "CN=Vendor A, O=Vendor A"}); !strings.HasPrefix(got, "new") {
		t.Fatalf("signed MSI with matching hash: %q", got)
	}
	pins, err := loadSignerPins(filepath.Join(e.dir, "work", signerPinsFile))
	if err != nil || pins.Pins["vendor:tool"] == nil || pins.Pins["vendor:tool"].CN != "Vendor A" {
		t.Fatalf("vendor signer not pinned: %+v %v", pins, err)
	}
	if got := runWith("1.0.2", "", psSignature{Status: "Valid", Subject: "CN=Someone Else, O=Someone Else"}); strings.HasPrefix(got, "new") || !strings.Contains(got, "signer changed") {
		t.Fatalf("signer change on the hash path accepted: %q", got)
	}
	if got := runWith("1.0.3", strings.Repeat("b", 64), psSignature{Status: "Valid", Subject: "CN=Vendor A, O=Vendor A"}); strings.HasPrefix(got, "new") || !strings.Contains(got, "expected_sha256") {
		t.Fatalf("hash mismatch with a valid signature accepted: %q", got)
	}

	// A host without MSI Authenticode (Linux): refused unless acquire.json pins the hash.
	orig := windowsAuthenticode
	windowsAuthenticode = func() bool { return false }
	t.Cleanup(func() { windowsAuthenticode = orig })
	if got := runWith("1.0.4", "", psSignature{}); !strings.HasPrefix(got, "unsupported") || !strings.Contains(got, "Windows") {
		t.Fatalf("MSI without Authenticode on this host: %q", got)
	}
	body := []byte("vendor tool 1.0.5")
	s := sha256.Sum256(body)
	cfg, _ := os.ReadFile(e.cfgPath)
	os.WriteFile(e.cfgPath, []byte(strings.Replace(string(cfg), `"requests": "requests",`,
		`"requests": "requests", "vendor_sha256_pins": {"tool": "`+hex.EncodeToString(s[:])+`"},`, 1)), 0o600)
	if got := runWith("1.0.5", "", psSignature{}); !strings.HasPrefix(got, "new") {
		t.Fatalf("hash pinned in acquire.json: %q", got)
	}
}
