package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"offpatch/internal/intel"
)

// pmctl intel end to end, offline: Windows only from a fake catalog (no
// apps), signed, and delivered through the drop-directory adapter.
func TestIntelCommandDelivers(t *testing.T) {
	dir := t.TempDir()
	if err := keygen([]string{"-out", filepath.Join(dir, "k")}); err != nil {
		t.Fatal(err)
	}
	inbox := filepath.Join(dir, "inbox")
	os.MkdirAll(inbox, 0o750)
	// No network in tests: skip both sources and expect the "nothing collected" error ...
	err := intelCmd([]string{"-key", filepath.Join(dir, "k.key"), "-out", dir, "-to", inbox, "-no-apps", "-no-windows"})
	if err == nil || !strings.Contains(err.Error(), "no update intelligence collected") {
		t.Fatalf("empty intel accepted: %v", err)
	}
	// ... and a signed document built by writeIntel goes through the adapter.
	d := intel.Doc{Source: "acq-zone-1", GeneratedAt: "2026-10-17T09:00:00Z",
		Windows: []intel.WindowsRelease{{Product: "Windows 11 Version 24H2", Build: 26100, Arch: "x64", KB: "KB5127648"}}}
	p, err := writeIntel(d, filepath.Join(dir, "k.key"), "", filepath.Join(dir, "out"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := adapterFor(sendOpts{Via: "dropdir", To: inbox})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Send(p); err != nil {
		t.Fatalf("intel refused by the transfer adapter: %v", err)
	}
	if _, err := os.Stat(filepath.Join(inbox, filepath.Base(p))); err != nil {
		t.Fatal("intel not in inbox")
	}
}
