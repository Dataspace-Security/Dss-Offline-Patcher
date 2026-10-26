package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

func utf16le(s string, bom bool) []byte {
	var b []byte
	if bom {
		b = append(b, 0xFF, 0xFE)
	}
	for _, u := range utf16.Encode([]rune(s)) {
		b = append(b, byte(u), byte(u>>8))
	}
	return b
}

// sampleMSILog is shaped like the end of a failed msiexec /l*v log.
func sampleMSILog(props int) string {
	var sb strings.Builder
	sb.WriteString("=== Verbose logging started: 18/10/2026  10:00:00  Build type: SHIP UNICODE 5.00.10011.00  Calling process: C:/Windows/System32/msiexec.exe ===\r\n")
	for i := 0; i < 30; i++ {
		fmt.Fprintf(&sb, "MSI (s) (2C:30) [10:00:%02d:001]: Doing action: Step%d\r\n", i, i)
		sb.WriteString("MSI (s) (2C:30) [10:00:01:002]: Note: 1: 2205 2:  3: Error \r\n")
		sb.WriteString("MSI (s) (2C:30) [10:00:01:003]: PROPERTY CHANGE: Adding X property. Its value is 'y'.\r\n")
	}
	sb.WriteString("CustomAction CA_ConfigureService returned actual error code 1603 (note this may not be 100% accurate if translation happened inside sandbox)\r\n")
	sb.WriteString("MSI (s) (2C:30) [10:01:00:000]: Product: Contoso Agent -- Error 1722. There is a problem with this Windows Installer package.\r\n")
	sb.WriteString("Action ended 10:01:00: CA_ConfigureService. Return value 3.\r\n")
	for i := 0; i < 25; i++ {
		fmt.Fprintf(&sb, "MSI (s) (2C:30) [10:01:01:%03d]: Executing op: Rollback%d\r\n", i, i)
	}
	sb.WriteString("Action ended 10:01:05: INSTALL. Return value 3.\r\n\r\n")
	for i := 0; i < props; i++ {
		fmt.Fprintf(&sb, "Property(S): PROP%d = value %d\r\n", i, i)
	}
	sb.WriteString("MSI (s) (2C:30) [10:01:06:000]: Product: Contoso Agent -- Installation failed.\r\n")
	sb.WriteString("MSI (s) (2C:30) [10:01:06:001]: Windows Installer installed the product. Product Name: Contoso Agent. Installation success or error status: 1603.\r\n")
	sb.WriteString("MSI (s) (2C:30) [10:01:06:002]: MainEngineThread is returning 1603\r\n")
	sb.WriteString("=== Verbose logging stopped: 18/10/2026  10:01:06 ===\r\n")
	return sb.String()
}

func TestDecodeLogText(t *testing.T) {
	text := "MSI (s) (2C:30) [10:00:00:000]: Produkt: Café — Fehler 1603\r\n"
	cases := map[string]struct {
		head, body []byte
		atStart    bool
	}{
		"utf16 bom":         {utf16le(text, true), utf16le(text, true), true},
		"utf16 no bom":      {utf16le(text, false), utf16le(text, false), true},
		"utf16 tail of bom": {utf16le(text, true), utf16le(text, false), false},
		"utf8 bom":          {append([]byte{0xEF, 0xBB, 0xBF}, text...), append([]byte{0xEF, 0xBB, 0xBF}, text...), true},
		"utf8":              {[]byte(text), []byte(text), true},
	}
	for name, c := range cases {
		if got := decodeLogText(c.head, c.body, c.atStart); got != text {
			t.Errorf("%s: %q", name, got)
		}
	}
	// ANSI (code page) bytes: ASCII survives, the rest is marked.
	ansi := []byte("Fehler: Datei \xe4nderung fehlgeschlagen\r\n")
	if got := decodeLogText(ansi, ansi, true); got != "Fehler: Datei ?nderung fehlgeschlagen\r\n" {
		t.Errorf("ansi: %q", got)
	}
}

func TestMeaningfulTail(t *testing.T) {
	got := meaningfulTail(sampleMSILog(400), 20, 1500)
	lines := strings.Split(got, "\n")
	if len(got) > 1500 || len(lines) > 20 {
		t.Fatalf("too long: %d bytes, %d lines", len(got), len(lines))
	}
	for _, bad := range []string{"Property(S)", "=== ", "MSI (s)", "Note: 1: 2205", "PROPERTY CHANGE"} {
		if strings.Contains(got, bad) {
			t.Errorf("noise %q kept:\n%s", bad, got)
		}
	}
	// The cause (first failing action) leads, then the end of the log.
	t.Logf("tail:\n%s", got)
	if !strings.Contains(got, "CustomAction CA_ConfigureService returned actual error code 1603") {
		t.Errorf("cause missing:\n%s", got)
	}
	if !strings.Contains(got, "Error 1722") || !strings.Contains(got, "CA_ConfigureService. Return value 3.") {
		t.Errorf("cause missing:\n%s", got)
	}
	if !strings.Contains(got, "\n…\n") {
		t.Errorf("no gap marker between the cause and the end:\n%s", got)
	}
	if lines[len(lines)-1] != "MainEngineThread is returning 1603" {
		t.Errorf("last line: %q", lines[len(lines)-1])
	}

	// A short log is returned whole, without a gap marker.
	short := "MSI (s) (2C:30) [10:00:00:000]: Product: X -- Error 1925.\r\n\r\nAction ended 10:00:01: INSTALL. Return value 3.\r\n"
	if got := meaningfulTail(short, 20, 1500); got != "Product: X -- Error 1925.\nAction ended 10:00:01: INSTALL. Return value 3." {
		t.Errorf("short: %q", got)
	}
	// The byte budget drops the oldest tail lines first, then the lead.
	small := meaningfulTail(sampleMSILog(10), 20, 200)
	if len(small) > 200 || !strings.HasSuffix(small, "MainEngineThread is returning 1603") {
		t.Errorf("small budget (%d bytes): %q", len(small), small)
	}
	// One huge line: cut to the budget at a rune boundary.
	huge := meaningfulTail(strings.Repeat("é", 1000), 20, 101)
	if len(huge) > 101 || !strings.HasPrefix(huge, "é") {
		t.Errorf("huge line: %d bytes %q", len(huge), huge[:8])
	}
	if meaningfulTail("\r\n=== Verbose logging stopped ===\r\nProperty(C): A = b\r\n", 20, 1500) != "" {
		t.Error("only noise: nothing to show")
	}
}

func TestMSILogTailFromFile(t *testing.T) {
	dir := t.TempDir()
	// Big enough that only the end is read (and from an odd offset).
	log := sampleMSILog(9000)
	for name, data := range map[string][]byte{
		"utf16.log": utf16le(log, true),
		"utf8.log":  []byte(log),
		"odd.log":   append([]byte{0xFF, 0xFE}, append(utf16le("x", false), utf16le(log, false)...)...),
	} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if int64(len(data)) <= msiLogReadMax {
			t.Fatalf("%s: sample too small (%d bytes)", name, len(data))
		}
		got := msiLogTail(p)
		if !strings.HasSuffix(got, "MainEngineThread is returning 1603") || len(got)+len(msiLogHeader) > msiLogTailChars {
			t.Errorf("%s: %d bytes:\n%s", name, len(got), got)
		}
	}
	if msiLogTail(filepath.Join(dir, "missing.log")) != "" {
		t.Error("missing log: empty tail")
	}
}

func TestWithMSILog(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.log")
	os.WriteFile(p, utf16le(sampleMSILog(50), true), 0o600)

	failed := withMSILog(classifyInstall("msi", 1603), p)
	if !strings.HasPrefix(failed.Detail, "installer exit code 1603 (0x00000643)"+msiLogHeader) || !strings.Contains(failed.Detail, "Error 1722") {
		t.Errorf("failed: %q", failed.Detail)
	}
	if n := len(failed.Detail) - len("installer exit code 1603 (0x00000643)"); n > msiLogTailChars {
		t.Errorf("log part is %d bytes", n)
	}
	for _, r := range []Result{classifyInstall("msi", 0), classifyInstall("msi", 3010), classifyInstall("msi", 1618)} {
		if got := withMSILog(r, p); got != r {
			t.Errorf("%s / %q must stay unchanged: %q", r.State, r.Detail, got.Detail)
		}
	}
	if got := withMSILog(classifyInstall("msi", 1603), ""); strings.Contains(got.Detail, "\n") {
		t.Errorf("no log: %q", got.Detail)
	}
}

func TestWithMSILogKnownConflict(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.log")
	var sb strings.Builder
	sb.WriteString("MSI (c) (F4:A8) [13:59:34:000]: Doing action: LaunchConditions\r\n")
	sb.WriteString("Action start 13:59:34: LaunchConditions.\r\n")
	sb.WriteString("Product: WinSCP -- WinSCP is already installed on this system using a standalone executable installer. Please uninstall that before running this MSI installer.\r\n")
	sb.WriteString("WinSCP is already installed on this system using a standalone executable installer. Please uninstall that before running this MSI installer.\r\n")
	sb.WriteString("Action ended 13:59:34: LaunchConditions. Return value 3.\r\n")
	sb.WriteString("Action ended 13:59:34: INSTALL. Return value 3.\r\n")
	os.WriteFile(p, []byte(sb.String()), 0o600)

	got := withMSILog(classifyInstall("msi", 1603), p)
	want := "blocked: already installed via a different (non-MSI) installer — uninstall it manually, then retry"
	if !strings.HasPrefix(got.Detail, want+msiLogHeader) {
		t.Errorf("detail: %q", got.Detail)
	}
	if !strings.Contains(got.Detail, "LaunchConditions") {
		t.Errorf("log tail dropped: %q", got.Detail)
	}

	// Exit codes other than 1603 are never rewritten, even with the same log text.
	if got := withMSILog(classifyInstall("msi", 1601), p); strings.HasPrefix(got.Detail, want) {
		t.Errorf("non-1603 code rewritten: %q", got.Detail)
	}
}
