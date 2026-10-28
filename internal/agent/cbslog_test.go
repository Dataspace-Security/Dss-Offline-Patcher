package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sampleCBSLog is shaped like the end of a servicing log after a failed
// cumulative update install: the per-component [Start]/[End] Opack= noise a
// real log is full of, then the errors that explain the failure.
func sampleCBSLog(noiseLines int) string {
	var sb strings.Builder
	for i := 0; i < noiseLines; i++ {
		sb.WriteString("2026-10-28 14:01:23, Info                  CSI    00000 [Start           ] Opack=0x514133: InstallPackage, package KB5134133\n")
		sb.WriteString("2026-10-28 14:01:23, Info                  CSI    00000 [End             ] Opack=0x514133: InstallPackage, package KB5134133\n")
	}
	sb.WriteString("2026-10-28 14:02:11, Info                  CBS    Begin operation \"InstallUpdate\"\n")
	sb.WriteString("2026-10-28 14:05:02, Error                 CBS    Failed to finalize the service session: unable to commit component changes. Error: 0x800f0068\n")
	sb.WriteString("2026-10-28 14:05:02, Error                 CBS    Operation \"InstallUpdate\" failed. Result: 0x800f0068\n")
	sb.WriteString("2026-10-28 14:05:02, Info                  CBS    End operation \"InstallUpdate\"\n")
	return sb.String()
}

func TestCbsLogTailFiltersNoise(t *testing.T) {
	p := filepath.Join(t.TempDir(), "CBS.log")
	if err := os.WriteFile(p, []byte(sampleCBSLog(200)), 0o600); err != nil {
		t.Fatal(err)
	}
	got := cbsLogTail(p)
	if got == "" {
		t.Fatal("no tail at all")
	}
	if strings.Contains(got, "Opack=") {
		t.Errorf("noise kept:\n%s", got)
	}
	if !strings.Contains(got, "0x800f0068") || !strings.Contains(got, "Failed to finalize the service session") {
		t.Errorf("cause missing:\n%s", got)
	}
	if !strings.Contains(got, "Begin operation") {
		t.Errorf("operation markers missing:\n%s", got)
	}
	// The byte budget is shared with the msiexec tail, header included.
	if len(got)+len(cbsLogHeader) > cbsLogTailChars {
		t.Errorf("tail is %d bytes with header (budget %d)", len(got)+len(cbsLogHeader), cbsLogTailChars)
	}
	if cbsLogTail(filepath.Join(t.TempDir(), "missing.log")) != "" {
		t.Error("missing log: expected empty tail")
	}
}

func TestCbsLogTailOnlyNoise(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "CBS.log")
	noise := strings.Repeat("2026-10-28 14:01:23, Info                  CSI    00000 [Start           ] Opack=0x1: Begin\n", 500)
	if err := os.WriteFile(p, []byte(noise), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := cbsLogTail(p); got != "" {
		t.Errorf("nothing useful in the log, got:\n%s", got)
	}
}

func TestWithCBSLog(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "CBS.log")
	if err := os.WriteFile(p, []byte(sampleCBSLog(50)), 0o600); err != nil {
		t.Fatal(err)
	}

	failed := withCBSLog(classifyInstall("msu", 0x800F0068), p)
	if !strings.HasPrefix(failed.Detail, "installer exit code 2148466792 (0x800F0068)"+cbsLogHeader) {
		t.Errorf("detail: %q", failed.Detail)
	}
	if !strings.Contains(failed.Detail, "0x800f0068") {
		t.Errorf("log tail dropped the cause:\n%s", failed.Detail)
	}
	// Uninstall shares the path.
	roll := withCBSLog(classifyUninstall("msu", 0x800F0068), p)
	if !strings.Contains(roll.Detail, "CBS log (last lines)") {
		t.Errorf("uninstall detail: %q", roll.Detail)
	}

	// Success, not-applicable and busy results stay unchanged.
	for _, r := range []Result{
		classifyInstall("msu", 0),
		classifyInstall("msu", 3010),
		classifyInstall("msu", 0x800F081E),
		classifyInstall("msu", 0x800F0902),
		classifyUninstall("msu", 0x800F0902),
	} {
		if got := withCBSLog(r, p); got != r {
			t.Errorf("%s / %q must stay unchanged: %q", r.State, r.Detail, got.Detail)
		}
	}
	// No log: detail unchanged.
	if got := withCBSLog(classifyInstall("msu", 0x800F0068), ""); got != classifyInstall("msu", 0x800F0068) {
		t.Errorf("no log path: %q", got.Detail)
	}
	// Log with no cause lines: detail unchanged.
	noise := filepath.Join(dir, "noise.log")
	if err := os.WriteFile(noise, []byte(strings.Repeat("2026-10-28 14:01:23, Info CSI 00000 [Start] Opack=1\n", 100)), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := withCBSLog(classifyInstall("msu", 0x800F0068), noise); got != classifyInstall("msu", 0x800F0068) {
		t.Errorf("noise-only log: %q", got.Detail)
	}
}

func TestCbsLogPathFor(t *testing.T) {
	// Deterministic parts: the path joins under SystemRoot.
	t.Setenv("SystemRoot", "X:")
	if got := cbsLogPathFor(); got != filepath.Join("X:", "Logs", "CBS", "CBS.log") && got != "" {
		// The file does not exist, so the function reports "" — that is
		// the documented contract when the log cannot be determined.
		t.Logf("SystemRoot with no log file: %q", got)
	}
	if got := cbsLogPathFor(); got != "" {
		t.Errorf("no such log: expected empty path, got %q", got)
	}
}
