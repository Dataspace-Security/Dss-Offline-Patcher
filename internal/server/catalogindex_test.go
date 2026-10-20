package server

import (
	"testing"

	"offpatch/internal/intel"
	"offpatch/internal/manifest"
	"offpatch/internal/store"
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

// Windows 11 24H2 (26100) and 25H2 (26200) share KB numbers. A catalog with
// only the 24H2 package must not show 25H2 machines the KB as "in catalog"
// (lab: Patch this then said 0 machines will install).
func TestKBLinkFollowsBuild(t *testing.T) {
	ci := &catalogIndex{byKB: map[string]catalogLink{}, kbPkgs: map[string][]kbPackage{}, byCode: map[string]namedPackage{}, byName: map[string]namedPackage{}, byID: map[string]catalogLink{}}
	add := func(id, state string, build int) {
		p := store.Package{PackageID: id, State: state, KB: "KB5127648",
			Applicability: manifest.Applicability{OS: "windows", Arch: "x64", MinBuild: build, MaxBuild: build}}
		l := catalogLink{PackageID: id, State: state}
		ci.byID[id] = l
		ci.kbPkgs["KB5127648"] = append(ci.kbPkgs["KB5127648"], kbPackage{l, p})
	}
	add("KB5127648-x64", "approved", 26100)
	ep := func(build int) store.Endpoint { return store.Endpoint{OS: "windows", Arch: "x64", Build: build} }

	if got := ci.forOSAt("kb5127648", ep(26100)); got == nil || got.PackageID != "KB5127648-x64" {
		t.Fatalf("24H2 machine not linked: %+v", got)
	}
	if got := ci.forOSAt("KB5127648", ep(26200)); got != nil {
		t.Fatalf("25H2 machine linked to the 24H2 package: %+v", got)
	}

	row := &fleetUpdate{Kind: "os", Key: "KB5127648", Endpoints: []fleetNeed{
		{EndpointID: "a", build: 26200}, {EndpointID: "b", build: 26200},
	}}
	row.linkCatalog(ci)
	if row.Catalog != nil || row.Uncovered != 2 || len(row.UncoveredBuilds) != 1 || row.UncoveredBuilds[0] != 26200 {
		t.Fatalf("25H2-only row: catalog %+v uncovered %d builds %v", row.Catalog, row.Uncovered, row.UncoveredBuilds)
	}

	// With the 25H2 package imported (its own ID), each build gets its own.
	add("KB5127648-x64-26200", "quarantined", 26200)
	if got := ci.forOSAt("KB5127648", ep(26200)); got == nil || got.PackageID != "KB5127648-x64-26200" {
		t.Fatalf("25H2 machine not linked to the 25H2 package: %+v", got)
	}
	row = &fleetUpdate{Kind: "os", Key: "KB5127648", Endpoints: []fleetNeed{
		{EndpointID: "a", build: 26200, PackageID: "KB5127648-x64-26200"},
		{EndpointID: "b", build: 26200, PackageID: "KB5127648-x64-26200"},
		{EndpointID: "c", build: 26100, PackageID: "KB5127648-x64"},
	}}
	row.linkCatalog(ci)
	if row.Catalog == nil || row.Catalog.PackageID != "KB5127648-x64" || row.Uncovered != 0 {
		t.Fatalf("mixed row should prefer the approved package: %+v uncovered %d", row.Catalog, row.Uncovered)
	}
}
