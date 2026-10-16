//go:build darwin

package agent

import "testing"

func TestMacParsers(t *testing.T) {
	if v := parsePkgInfo("package-id: com.apple.pkg.X\nversion: 14.2.1.0.1.1700000000\nvolume: /\n"); v != "14.2.1.0.1.1700000000" {
		t.Fatalf("version: %q", v)
	}
	if !installNeedsRestart("installer: Package name is Acme\ninstaller: The upgrade requires a restart.") || installNeedsRestart("installer: The upgrade was successful.") {
		t.Fatal("restart detection")
	}
}

// TestMacInventoryReadOnly exercises the real read-only macOS integration
// (sw_vers, pkgutil). Installs need root and are not run in tests.
func TestMacInventoryReadOnly(t *testing.T) {
	m := &MacOS{}
	f, err := m.Facts()
	if err != nil || f.OS != "macos" || f.OSVersion == "" {
		t.Fatalf("facts: %+v %v", f, err)
	}
	items, _, err := m.Inventory()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) == 0 {
		t.Fatal("pkgutil reported no packages")
	}
	withVersion := 0
	for _, it := range items {
		if (it.Kind != "pkg" && it.Kind != "app") || it.ID == "" {
			t.Fatalf("bad item %+v", it)
		}
		if it.Version != "" {
			withVersion++
		}
	}
	t.Logf("%s: %d receipts (%d with versions)", f.OSVersion, len(items), withVersion)
}

func TestNormalizeAppVersion(t *testing.T) {
	for in, want := range map[string]string{"7.2.2 (88465)": "7.2.2.88465", "155.0.8059.80": "155.0.8059.80", "1.0.0 (117)": "1.0.0.117"} {
		if got := normalizeAppVersion(in); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
	items := appBundles(t.Context(), "/Applications")
	if len(items) == 0 {
		t.Skip("no apps in /Applications")
	}
	for _, it := range items {
		if it.Kind != "app" || it.ID == "" {
			t.Fatalf("bad app item %+v", it)
		}
	}
	t.Logf("%d app bundles", len(items))
}
