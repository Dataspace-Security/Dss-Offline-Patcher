package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"offpatch/internal/acqpolicy"
	"offpatch/internal/acquire"
	peauth "offpatch/internal/acquire/authenticode"
)

// M-5: signer names compare as whole values, never as substrings.
func TestSignerExactMatch(t *testing.T) {
	cases := []struct {
		want, cn, o string
		ok          bool
	}{
		{"Google LLC", "Google LLC", "Google LLC", true},
		{"google llc", "Google  LLC", "", true},
		{"Google LLC", "Google LLC Services Ltd", "Google LLC", false},
		{"Google LLC", "Evil Google LLC", "", false},
		{"Google", "Google LLC", "", false},
		{"CN=Google LLC, O=Google LLC, L=Mountain View, C=US", "Google LLC", "Google LLC", true},
		{"CN=Google LLC, O=Google LLC", "Google LLC", "Evil Ltd", false},
		{`CN=Contoso, O="Contoso, Inc.", C=US`, "Contoso", "Contoso, Inc.", true},
		{`CN=Contoso, O="Contoso, Inc."`, "Contoso", "Contoso", false},
		{"", "Google LLC", "", false},
	}
	for _, c := range cases {
		if got := parseSignerSpec(c.want).matches(signerName{CN: c.cn, O: c.o}); got != c.ok {
			t.Errorf("%q vs CN=%q O=%q: %v, want %v", c.want, c.cn, c.o, got, c.ok)
		}
	}
	if dn := parseDN(`CN=A\, B, O=X`); dn["CN"] != "A, B" || dn["O"] != "X" {
		t.Errorf("escaped comma: %v", dn)
	}
}

func TestPkgSignerExact(t *testing.T) {
	leaf := "Developer ID Installer: Google LLC (EQHXZ8M8AV)"
	for signer, ok := range map[string]bool{
		leaf: true, "Google LLC (EQHXZ8M8AV)": true, "Google LLC": true, "google llc": true,
		"Google": false, "EQHXZ8M8AV": false, "Developer ID Installer: Google": false, "LLC": false,
	} {
		if got := pkgSignerMatches(leaf, signer); got != ok {
			t.Errorf("pkg_signer %q: %v, want %v", signer, got, ok)
		}
	}
	if pkgSignerMatches("Developer ID Installer: Google LLC Services Ltd (ABCDE12345)", "Google LLC") {
		t.Error("a longer company name matched")
	}
}

// exe_signers is an exact CN list (or DN with O).
func TestExeSignersExact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.exe")
	os.WriteFile(path, []byte("MZ signed"), 0o600)
	orig := exeVerify
	t.Cleanup(func() { exeVerify = orig; setExeTrust("", nil) })
	exeVerify = func(string) (*peauth.Result, error) {
		return &peauth.Result{Signer: "Google LLC Services Ltd", Organization: "Google LLC"}, nil
	}
	setExeTrust("", []string{"Google LLC"})
	if _, err := verifyExeResult(path); err == nil || !errors.Is(err, errExeSignature) {
		t.Fatalf("substring signer accepted: %v", err)
	}
	setExeTrust("", []string{"CN=Google LLC Services Ltd, O=Google LLC"})
	if _, err := verifyExeResult(path); err != nil {
		t.Fatal(err)
	}
	setExeTrust("", []string{"CN=Google LLC Services Ltd, O=Other"})
	if _, err := verifyExeResult(path); err == nil {
		t.Fatal("O mismatch accepted")
	}
	// The vendor-url / authenticode_signer path compares the same way.
	setExeTrust("", nil)
	info, err := signerOfFile(path)
	if err != nil || parseSignerSpec("Google LLC").matches(info.signerName) || !parseSignerSpec("Google LLC Services Ltd").matches(info.signerName) {
		t.Fatalf("signerOfFile: %+v %v", info, err)
	}
}

func sig(cn, o, tp string) signerInfo {
	return signerInfo{signerName: signerName{CN: cn, O: o}, Thumbprint: tp}
}

// H-7: trust on first use, renewals, a changed signer refused until
// approved, and the acquire.json overrides.
func TestSignerPins(t *testing.T) {
	setExeTrust("", nil)
	t.Cleanup(func() { setExeTrust("", nil) })
	c := &autoConfig{}
	pins, err := loadSignerPins(filepath.Join(t.TempDir(), signerPinsFile))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	key := pinKeyWinget("Google.Chrome")

	if note, err := pins.check(c, key, "1.0", sig("Google LLC", "Google LLC", "aa"), now); err != nil || !strings.Contains(note, "first seen") {
		t.Fatalf("first use: %q %v", note, err)
	}
	if note, err := pins.check(c, key, "1.1", sig("Google LLC", "Google LLC", "aa"), now); err != nil || note != "matches the pinned signer" {
		t.Fatalf("same signer: %q %v", note, err)
	}
	if note, err := pins.check(c, key, "1.2", sig("Google LLC", "Google LLC", "bb"), now); err != nil || !strings.Contains(note, "renewed") {
		t.Fatalf("renewed certificate: %q %v", note, err)
	}
	if pins.Pins[key].Thumbprint != "bb" || pins.Pins[key].LastVersion != "1.2" {
		t.Fatalf("pin not updated: %+v", pins.Pins[key])
	}
	for _, changed := range []signerInfo{sig("Evil Corp", "Evil Corp", "cc"), sig("Google LLC", "Evil Corp", "cc"), sig("Google LLC Services Ltd", "Google LLC", "cc")} {
		_, err := pins.check(c, key, "2.0", changed, now)
		if !errors.Is(err, errSignerChanged) || !strings.Contains(err.Error(), "pmctl trust-signer google.chrome") {
			t.Fatalf("changed signer %s: %v", changed.signerName, err)
		}
	}
	if p := pins.Pins[key]; p.CN != "Google LLC" || p.Pending == nil || p.Pending.CN != "Google LLC Services Ltd" {
		t.Fatalf("pending change not recorded: %+v", p)
	}
	if err := pins.save(); err != nil {
		t.Fatal(err)
	}

	// pmctl trust-signer approves the pending signer.
	if _, err := approveSigner(pins, "google.chrome", "sam", now); err != nil {
		t.Fatal(err)
	}
	if _, err := pins.check(c, key, "2.0", sig("Google LLC Services Ltd", "Google LLC", "cc"), now); err != nil {
		t.Fatalf("approved signer: %v", err)
	}
	if _, err := approveSigner(pins, "Google.Chrome", "sam", now); err == nil {
		t.Fatal("nothing pending, yet approved")
	}
	if _, err := approveSigner(pins, "Unknown.App", "sam", now); err == nil {
		t.Fatal("unknown id approved")
	}

	// exe_signers listing the new CN accepts the change.
	setExeTrust("", []string{"Mozilla Corporation"})
	vkey := pinKeyVendor("tool")
	pins.check(c, vkey, "1", sig("Tool Vendor", "", ""), now)
	if note, err := pins.check(c, vkey, "2", sig("Mozilla Corporation", "Mozilla Corporation", ""), now); err != nil || !strings.Contains(note, "exe_signers") {
		t.Fatalf("exe_signers approval: %q %v", note, err)
	}
	setExeTrust("", nil)

	// exe_signer_pins in acquire.json overrides the pinned signer.
	c.ExeSignerPins = map[string]signerPinConfig{"Mozilla.Firefox": {CN: "Mozilla Corporation", O: "Mozilla Corporation"}}
	fkey := pinKeyWinget("Mozilla.Firefox")
	if _, err := pins.check(c, fkey, "1", sig("Mozilla Corporation", "Mozilla Corporation", ""), now); err != nil {
		t.Fatal(err)
	}
	if _, err := pins.check(c, fkey, "2", sig("Mozilla Corporation", "Other", ""), now); !errors.Is(err, errSignerChanged) {
		t.Fatalf("exe_signer_pins mismatch: %v", err)
	}

	// The pins survive a reload; a corrupt file stops the run.
	pins.save()
	again, err := loadSignerPins(pins.path)
	if err != nil || again.Pins[key].CN != "Google LLC Services Ltd" {
		t.Fatalf("reload: %+v %v", again, err)
	}
	os.WriteFile(pins.path, []byte("{"), 0o600)
	if _, err := loadSignerPins(pins.path); err == nil {
		t.Fatal("corrupt pins file accepted")
	}
}

func TestTrustSignerCommand(t *testing.T) {
	dir := t.TempDir()
	work := filepath.Join(dir, "work")
	os.MkdirAll(work, 0o750)
	cfg := filepath.Join(dir, "acquire.json")
	os.WriteFile(cfg, []byte(`{"work_dir": "work", "key": "bundle.key"}`), 0o600)
	pins, _ := loadSignerPins(filepath.Join(work, signerPinsFile))
	now := time.Now()
	pins.check(&autoConfig{}, pinKeyWinget("Git.Git"), "1", sig("Johannes Schindelin", "Johannes Schindelin", "aa"), now)
	pins.check(&autoConfig{}, pinKeyWinget("Git.Git"), "2", sig("Git Project", "Git Project", "bb"), now)
	pins.save()
	if err := trustSignerCmd([]string{"-config", cfg, "-list"}); err != nil {
		t.Fatal(err)
	}
	if err := trustSignerCmd([]string{"-config", cfg, "Git.Git"}); err != nil {
		t.Fatal(err)
	}
	pins, _ = loadSignerPins(filepath.Join(work, signerPinsFile))
	if p := pins.Pins["winget:git.git"]; p.CN != "Git Project" || p.Pending != nil || !strings.HasPrefix(p.ApprovedBy, "trust-signer:") {
		t.Fatalf("after trust-signer: %+v", p)
	}
}

// Revocation: revoked is refused; unknown is recorded, and refused only
// with require_revocation_check. The details reach vendor_signature.
func TestPinInstallerRevocation(t *testing.T) {
	autoWarn = func(string) {}
	orig := revocationCheck
	t.Cleanup(func() { revocationCheck = orig })
	status := acquire.RevocationRevoked
	revocationCheck = func(context.Context, *autoConfig, signerInfo) acquire.Revocation {
		return acquire.Revocation{Status: status, Detail: "test"}
	}
	c := &autoConfig{}
	pins, _ := loadSignerPins(filepath.Join(t.TempDir(), signerPinsFile))
	s := sig("Google LLC", "Google LLC", "0123456789abcdef0123")
	ctx := context.Background()
	if _, err := pinInstaller(ctx, c, pins, pinKeyWinget("Google.Chrome"), "1", "Google LLC", s); !errors.Is(err, errSignerRevoked) {
		t.Fatalf("revoked: %v", err)
	}
	if len(pins.Pins) != 0 {
		t.Fatal("a revoked signer was pinned")
	}
	status = acquire.RevocationUnknown
	vs, err := pinInstaller(ctx, c, pins, pinKeyWinget("Google.Chrome"), "1", "Google LLC", s)
	if err != nil || vs.Status != "valid" {
		t.Fatalf("unknown: %+v %v", vs, err)
	}
	for _, part := range []string{"Google LLC (O=Google LLC", `winget publisher "Google LLC" matches`, "cert sha256 0123456789abcdef", "revocation unknown", "first seen"} {
		if !strings.Contains(vs.Signer, part) {
			t.Errorf("vendor_signature.signer %q lacks %q", vs.Signer, part)
		}
	}
	vs, _ = pinInstaller(ctx, c, pins, pinKeyWinget("Google.Chrome"), "2", "Mozilla", s)
	if !strings.Contains(vs.Signer, `winget publisher "Mozilla" DIFFERS`) {
		t.Errorf("publisher mismatch not shown: %q", vs.Signer)
	}
	c.RequireRevocationCheck = true
	if _, err := pinInstaller(ctx, c, pins, pinKeyWinget("Google.Chrome"), "3", "", s); !errors.Is(err, errSignerRevoked) {
		t.Fatalf("require_revocation_check: %v", err)
	}
	status = acquire.RevocationGood
	if _, err := pinInstaller(ctx, c, pins, pinKeyWinget("Google.Chrome"), "3", "", s); err != nil {
		t.Fatal(err)
	}
}

func TestPublisherMatches(t *testing.T) {
	for _, c := range []struct {
		pub, cn, o string
		ok         bool
	}{
		{"Google LLC", "Google LLC", "Google LLC", true},
		{"Mozilla", "Mozilla Corporation", "Mozilla Corporation", true},
		{"Microsoft Corporation", "Microsoft Corporation", "", true},
		{"Notepad++ Team", "Notepad++", "", false},
		{"Google LLC", "Evil Ltd", "Evil Ltd", false},
	} {
		if got := publisherMatches(c.pub, signerName{CN: c.cn, O: c.o}); got != c.ok {
			t.Errorf("%q vs %q/%q: %v", c.pub, c.cn, c.o, got)
		}
	}
}

// H-6: a policy may only point downloads at allowed_source_hosts; IP
// literals of private networks are refused even when listed.
func TestPolicySourcesHeldToAllowlist(t *testing.T) {
	autoWarn = func(string) {}
	sha := strings.Repeat("a", 64)
	pol := acqpolicy.Policy{Sources: []acqpolicy.Source{
		{ID: "winget", Type: "winget", Enabled: true, ManifestsURL: "https://evil.example/manifests"},
		{ID: "microsoft-catalog", Type: "microsoft-catalog", Enabled: true, URL: "https://catalog.mirror.example"},
		{ID: "mirror", Type: "internal-mirror", Enabled: true, URL: "https://10.0.0.9/msrc", Replaces: "msrc"},
		{ID: "tool", Type: "vendor-url", Enabled: true, Name: "Tool", URL: "https://downloads.vendor.example/tool.msi", ExpectedSHA256: sha, Kind: "msi", Version: "1.0.0"},
		{ID: "evil", Type: "vendor-url", Enabled: true, Name: "Evil", URL: "https://evil.example/tool.msi", ExpectedSHA256: sha, Kind: "msi", Version: "1.0.0"},
	}}
	if err := pol.Normalize(); err != nil {
		t.Fatal(err)
	}
	f := acqpolicy.NewFile(1, "user:sam", "2026-10-16T02:00:00Z", pol)
	c := &autoConfig{Intel: &intelOpts{}, AllowedSourceHosts: []string{"default", "catalog.mirror.example", "*.vendor.example", "10.0.0.9"}}
	if err := setupNet(c); err != nil {
		t.Fatal(err)
	}
	pr := &policyRun{file: &f}
	applyPolicy(c, pr)
	res := map[string]string{}
	for _, r := range pr.results {
		res[r.ID] = r.Result + ": " + r.Detail
	}
	if c.WingetManifestsURL != "" || !strings.HasPrefix(res["winget"], "failed: refused: manifests_url evil.example") {
		t.Errorf("winget manifests on an unlisted host: %q %q", c.WingetManifestsURL, res["winget"])
	}
	if c.CatalogURL != "https://catalog.mirror.example" || !c.net.fromPolicy[acqpolicy.UpstreamCatalog] {
		t.Errorf("listed catalog mirror: %q %v", c.CatalogURL, c.net.fromPolicy)
	}
	if c.MSRCURL != "" || !strings.Contains(res["mirror"], "private or link-local") {
		t.Errorf("private IP literal mirror: %q %q", c.MSRCURL, res["mirror"])
	}
	if len(pr.vendors) != 1 || pr.vendors[0].ID != "tool" || !strings.Contains(res["evil"], "not in allowed_source_hosts") {
		t.Errorf("vendor-url: %+v %q", pr.vendors, res["evil"])
	}
	if len(pr.errs) != 3 {
		t.Errorf("problems for the status report: %q", pr.errs)
	}

	// The default list: only the official hosts.
	c2 := &autoConfig{Intel: &intelOpts{}}
	pr2 := &policyRun{file: &f}
	applyPolicy(c2, pr2)
	if c2.CatalogURL != "" || len(pr2.vendors) != 0 {
		t.Errorf("default allowlist let the policy through: %q %+v", c2.CatalogURL, pr2.vendors)
	}
	if err := setupNet(&autoConfig{AllowedSourceHosts: []string{"*"}}); err == nil {
		t.Error("allowed_source_hosts [\"*\"] accepted")
	}
}

// H-6: policy_version may not jump more than maxPolicyJump past the last
// accepted one; older versions are ignored.
func TestPolicyVersionJump(t *testing.T) {
	autoWarn = func(string) {}
	dir := t.TempDir()
	p := acqpolicy.Empty()
	writePolicy(t, dir, 4, p)
	writePolicy(t, dir, 3+maxPolicyJump+1, p)
	pr := &policyRun{}
	f := pickPolicyFiles(dir, 3, false, pr)
	if f == nil || f.PolicyVersion != 4 {
		t.Fatalf("picked %+v", f)
	}
	if len(pr.errs) != 1 || !strings.Contains(pr.errs[0], fmt.Sprintf("policy_version %d is more than %d past the last accepted version 3", 4+maxPolicyJump, maxPolicyJump)) {
		t.Fatalf("errs %q", pr.errs)
	}
	if _, err := os.Stat(filepath.Join(dir, "rejected", acqpolicy.FileName(4+maxPolicyJump))); err != nil {
		t.Errorf("jumped file not moved to rejected/: %v", err)
	}
	// Exactly maxPolicyJump ahead is fine; older ones are ignored.
	writePolicy(t, dir, 4+maxPolicyJump, p)
	writePolicy(t, dir, 2, p)
	pr = &policyRun{}
	if f := pickPolicyFiles(dir, 4, false, pr); f == nil || f.PolicyVersion != 4+maxPolicyJump || len(pr.errs) != 0 {
		t.Fatalf("picked %+v errs %q", f, pr.errs)
	}
	// The first policy a downloader sees is taken at any version.
	writePolicy(t, dir, 5000, p)
	if f := pickPolicyFiles(dir, 0, false, &policyRun{}); f == nil || f.PolicyVersion != 5000 {
		t.Fatalf("first policy: %+v", f)
	}

	// loadPolicy remembers the accepted version in state.json, so a deleted
	// policy.json does not reset the baseline.
	cdir := t.TempDir()
	c := &autoConfig{WorkDir: cdir, Requests: filepath.Join(cdir, "requests")}
	writePolicy(t, c.Requests, 7, p)
	st := autoState{}
	rep := &autoReport{}
	if pr := loadPolicy(c, false, rep, &st); pr.file == nil || st.PolicyVersion != 7 {
		t.Fatalf("v7 not accepted: %+v %d", pr.file, st.PolicyVersion)
	}
	os.Remove(filepath.Join(cdir, activePolicyFile))
	writePolicy(t, c.Requests, 7+maxPolicyJump+5, p)
	if pr := loadPolicy(c, false, rep, &st); pr.file != nil || len(pr.errs) != 1 {
		t.Fatalf("jump after policy.json was removed: %+v %q", pr.file, pr.errs)
	}
}
