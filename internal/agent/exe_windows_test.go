//go:build windows

package agent

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// These tests only read files; nothing is installed or run.

// embeddedSignedSystemFile finds a system binary with an embedded
// Authenticode signature (most of System32 is catalog-signed instead).
func embeddedSignedSystemFile(t *testing.T) string {
	t.Helper()
	sys := filepath.Join(os.Getenv("SystemRoot"), "System32")
	cands := []string{"MRT.exe", "MpSigStub.exe", "ntoskrnl.exe", "WindowsPowerShell\\v1.0\\powershell.exe"}
	if all, err := filepath.Glob(filepath.Join(sys, "*.exe")); err == nil {
		for _, f := range all {
			cands = append(cands, filepath.Base(f))
		}
	}
	for _, c := range cands {
		f := filepath.Join(sys, c)
		if _, _, err := peSigner(f); err == nil && winVerifyTrust(f) == nil {
			return f
		}
	}
	t.Skip("no embedded-signed binary found in System32")
	return ""
}

func TestWinVerifyTrustSignedSystemFile(t *testing.T) {
	f := embeddedSignedSystemFile(t)
	cn, org, err := peSigner(f)
	if err != nil || cn == "" {
		t.Fatalf("%s: signer %q %q %v", f, cn, org, err)
	}
	if err := signatureCheck(f, cn, winVerifyTrust); err != nil {
		t.Fatalf("%s signed by %q rejected: %v", f, cn, err)
	}
	if err := signatureCheck(f, "Example Corp", winVerifyTrust); err == nil || !strings.Contains(err.Error(), "expected \"Example Corp\"") {
		t.Fatalf("%s: wrong signer accepted: %v", f, err)
	}
	t.Logf("%s: signer CN=%q O=%q", f, cn, org)
}

func TestWinVerifyTrustRejectsUnsignedAndModified(t *testing.T) {
	dir := t.TempDir()
	// The test binary is an unsigned PE.
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := filepath.Join(dir, "unsigned.exe")
	os.WriteFile(unsigned, b, 0o600)
	if err := winVerifyTrust(unsigned); err == nil || !strings.Contains(err.Error(), "no embedded Authenticode signature") {
		t.Fatalf("unsigned file: %v", err)
	}
	if err := signatureCheck(unsigned, "Microsoft Corporation", winVerifyTrust); err == nil {
		t.Fatal("unsigned file passed the signature check")
	}
	text := filepath.Join(dir, "not-pe.exe")
	os.WriteFile(text, []byte("hello"), 0o600)
	if err := winVerifyTrust(text); err == nil {
		t.Fatal("text file trusted")
	}
	// A signed file changed after signing fails the digest check.
	f := embeddedSignedSystemFile(t)
	sb, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	sb[len(sb)/3] ^= 0xFF
	mod := filepath.Join(dir, "modified.exe")
	os.WriteFile(mod, sb, 0o600)
	if err := winVerifyTrust(mod); err == nil {
		t.Fatal("modified signed file trusted")
	}
}

func TestWinVerifyTrustCatalogOnlyFile(t *testing.T) {
	// notepad.exe is catalog-signed: no embedded signature, so not accepted
	// as an EXE installer signature.
	f := filepath.Join(os.Getenv("SystemRoot"), "System32", "notepad.exe")
	if _, err := os.Stat(f); err != nil {
		t.Skip(err)
	}
	if _, _, err := peSigner(f); err == nil {
		t.Skip("notepad.exe has an embedded signature on this build")
	}
	if err := winVerifyTrust(f); err == nil {
		t.Fatal("catalog-only file accepted with WTD_CHOICE_FILE")
	}
}

// The pure parser agrees with CommandLineToArgvW.
func TestSplitCommandLineMatchesWindows(t *testing.T) {
	for _, s := range []string{
		`"C:\Program Files\App\unins000.exe" /VERYSILENT /SUPPRESSMSGBOXES`,
		`MsiExec.exe /X{11111111-2222-3333-4444-555555555555} /qn`,
		`C:\a\b.exe "x y" z\\"q" "a\\" b\c "" d`,
		`x.exe a\\\"b "c""d" e`,
		`"C:\a b\x.exe"   tail  `,
		buildCmdLine(`C:\run dir\setup.exe`, []string{"/S", "/D=C:\\Program Files\\X\\", "a b", `tr\`}),
	} {
		want, err := windows.DecomposeCommandLine(s)
		if err != nil {
			t.Fatal(err)
		}
		if got := splitCommandLine(s); !slices.Equal(got, want) {
			t.Errorf("splitCommandLine(%s) = %q, Windows %q", s, got, want)
		}
	}
}

func TestWithTempDir(t *testing.T) {
	env := withTempDir([]string{"PATH=x", "Temp=C:\\old", "TMP=C:\\old", "A=b"}, `C:\run`)
	if !slices.Equal(env, []string{"PATH=x", "A=b", `TEMP=C:\run`, `TMP=C:\run`}) {
		t.Fatalf("env: %q", env)
	}
}

// Dual-signed files (a nested signature in the primary's unauthenticated
// attributes) expose both signers, so a manifest naming the nested
// signature's publisher still matches. Read-only: scans installed programs.
func TestPESignersNested(t *testing.T) {
	var found string
	var signers [][2]string
	for _, root := range []string{`C:\Program Files`, `C:\Program Files (x86)`, `C:\Windows\System32`} {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if found != "" || err != nil {
				return filepath.SkipDir
			}
			if d.IsDir() || !strings.EqualFold(filepath.Ext(p), ".exe") {
				return nil
			}
			if s, err := peSigners(p); err == nil && len(s) > 1 {
				found, signers = p, s
			}
			return nil
		})
		if found != "" {
			break
		}
	}
	if found == "" {
		t.Skip("no dual-signed executable found on this machine")
	}
	for _, s := range signers {
		if s[0] == "" && s[1] == "" {
			t.Errorf("%s: a signer without a name: %v", found, signers)
		}
	}
	if err := signatureCheck(found, signers[len(signers)-1][0], winVerifyTrust); err != nil && !strings.Contains(err.Error(), "signed by") {
		t.Logf("%s: WinVerifyTrust: %v (file not trusted as a whole; the nested name check is not reached)", found, err)
	} else if err != nil {
		t.Errorf("%s: nested signer %q not accepted: %v", found, signers[len(signers)-1][0], err)
	}
	t.Logf("%s signers: %v", found, signers)
}
