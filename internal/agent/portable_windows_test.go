//go:build windows

package agent

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"golang.org/x/sys/windows/registry"

	"offpatch/internal/manifest"
)

// writePortableARP never overwrites an Uninstall key another installer
// wrote (no portableMarker), rewrites its own, and quotes the key in the
// UninstallString. HKCU stands in for HKLM (no administrator needed).
func TestWritePortableARPOwnership(t *testing.T) {
	b := make([]byte, 6)
	rand.Read(b)
	key := "DSSPatcher Test " + hex.EncodeToString(b)
	path := uninstallKeys[0] + `\` + key
	t.Cleanup(func() { registry.DeleteKey(registry.CURRENT_USER, path) })
	foreign, _, err := registry.CreateKey(registry.CURRENT_USER, path, registry.ALL_ACCESS|registry.WOW64_64KEY)
	if err != nil {
		t.Skipf("cannot create a test key: %v", err)
	}
	foreign.SetStringValue("DisplayName", "Vendor App")
	foreign.Close()
	p := manifest.Package{Kind: manifest.KindPortable, Version: "1.0",
		Portable: &manifest.Portable{Folder: "Test", Command: "t.exe", ARPKey: key, DisplayName: "Test App", DisplayVersion: "1.0"}}
	if err := writePortableARP(registry.CURRENT_USER, p, t.TempDir(), ""); err == nil || !strings.Contains(err.Error(), "did not write") {
		t.Fatalf("foreign key overwritten: %v", err)
	}
	k, _ := registry.OpenKey(registry.CURRENT_USER, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if name, _, _ := k.GetStringValue("DisplayName"); name != "Vendor App" {
		t.Errorf("foreign entry changed: %q", name)
	}
	k.Close()

	// The agent's own entry (marker set) is rewritten.
	registry.DeleteKey(registry.CURRENT_USER, path)
	if err := writePortableARP(registry.CURRENT_USER, p, t.TempDir(), ""); err != nil {
		t.Fatal(err)
	}
	p.Portable.DisplayVersion = "1.1"
	if err := writePortableARP(registry.CURRENT_USER, p, t.TempDir(), ""); err != nil {
		t.Fatalf("own entry not rewritten: %v", err)
	}
	k, _ = registry.OpenKey(registry.CURRENT_USER, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	defer k.Close()
	ver, _, _ := k.GetStringValue("DisplayVersion")
	un, _, _ := k.GetStringValue("UninstallString")
	args := splitCommandLine(un)
	if ver != "1.1" || len(args) != 3 || args[1] != "portable-remove" || args[2] != key {
		t.Errorf("entry: version %q, uninstall %q → %q", ver, un, args)
	}
}
