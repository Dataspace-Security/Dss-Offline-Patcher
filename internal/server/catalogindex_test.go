package server

import (
	"testing"

	"offpatch/internal/intel"
)

// The x86 and x64 builds of one product normalize to the same name: the
// catalog link must not cross architectures (lab: the VM's x86 VC++ row
// showed the x64 EXE package as "in catalog").
func TestCatalogLinkKeepsArchitecture(t *testing.T) {
	ci := &catalogIndex{byKB: map[string]catalogLink{}, byCode: map[string]namedPackage{}, byName: map[string]namedPackage{}, byID: map[string]catalogLink{}}
	x64 := "Microsoft Visual C++ v14 Redistributable (x64) - 14.51.36247"
	ci.byName[nameKey(intel.Normalize(x64), x64)] = namedPackage{link: catalogLink{PackageID: "vc-x64", State: "approved"}, version: "14.51.36247.0"}

	got := ci.forApp(intel.AppUpdate{InstalledName: "Microsoft Visual C++ v14 Redistributable (x64) - 14.50.35719", InstalledVersion: "14.50.35719.0"})
	if got == nil || got.PackageID != "vc-x64" {
		t.Fatalf("x64 install not linked to the x64 package: %+v", got)
	}
	if got := ci.forApp(intel.AppUpdate{InstalledName: "Microsoft Visual C++ v14 Redistributable (x86) - 14.50.35719", InstalledVersion: "14.50.35719.0"}); got != nil {
		t.Errorf("x86 install linked to the x64 package: %+v", got)
	}
	if got := ci.forCurrentApp(intel.AppUpdate{InstalledName: "Microsoft Visual C++ v14 Redistributable (x86) - 14.51.36247"}); got != nil {
		t.Errorf("up-to-date x86 install linked to the x64 package: %+v", got)
	}
	// Names without an architecture keep matching as before.
	ci.byName[nameKey(intel.Normalize("7-Zip"), "7-Zip")] = namedPackage{link: catalogLink{PackageID: "7zip", State: "approved"}, version: "26.04"}
	if got := ci.forApp(intel.AppUpdate{InstalledName: "7-Zip", InstalledVersion: "26.03"}); got == nil || got.PackageID != "7zip" {
		t.Errorf("7-Zip not linked: %+v", got)
	}
}

// A package whose name has no architecture serves installs that mention one
// ("7-Zip" for "7-Zip 26.03 (x64 edition)").
func TestCatalogLinkArchlessPackage(t *testing.T) {
	ci := &catalogIndex{byKB: map[string]catalogLink{}, byCode: map[string]namedPackage{}, byName: map[string]namedPackage{}, byID: map[string]catalogLink{}}
	ci.byName[nameKey(intel.Normalize("7-Zip"), "7-Zip")] = namedPackage{link: catalogLink{PackageID: "7zip", State: "approved"}, version: "26.04"}
	if got := ci.forApp(intel.AppUpdate{InstalledName: "7-Zip 26.03 (x64 edition)", InstalledVersion: "26.03.00.0"}); got == nil || got.PackageID != "7zip" {
		t.Errorf("7-Zip (x64 edition) not linked to the arch-less 7-Zip package: %+v", got)
	}
}
