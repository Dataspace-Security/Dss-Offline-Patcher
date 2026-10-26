package agent

import (
	"testing"

	"offpatch/internal/manifest"
)

// Regression: simID used to read p.Exe.Detect.DisplayName/ProductCode raw,
// bypassing exeDetect's package_name fallback. For a package with no
// product_code and no detect.display_name, this made simID return "" —
// colliding with any other such package in FailKBs/FailUninstall lookups
// and in the simulated inventory's own item id/name, so the simulator could
// never recognise its own "installed" app as present on a later check-in.
func TestSimIDFallsBackToPackageName(t *testing.T) {
	p := manifest.Package{PackageID: "GHDesktop", Kind: manifest.KindExe, Version: "3.6.9", PackageName: "GitHub Desktop",
		Exe: &manifest.ExeInstall{InstallerType: "msi", Detect: manifest.ExeDetect{DisplayVersion: "3.6.9"}}} // no display_name, no product_code
	if got := simID(p); got != "GitHub Desktop" {
		t.Fatalf("simID must fall back to package_name: %q", got)
	}
	// A product_code still wins over the name fallback.
	p.Exe.Detect.ProductCode = "{CODE}"
	if got := simID(p); got != "{CODE}" {
		t.Fatalf("simID must prefer product_code: %q", got)
	}
}
