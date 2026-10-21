package server

import (
	"path/filepath"
	"testing"

	"offpatch/internal/intel"
	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

// The console's fleet view (Patches → Needed, fleet status, Patch this,
// acquisition requests) starts from the update intelligence, which cannot
// see the catalog's supersedence, a package's architecture or the EXE
// per-machine rule. Where a catalog package is linked, the store's verdict
// (the one deployments and GET /api/packages-needs use) must win, so the
// views never disagree. Store-side cases: internal/store
// presence_consistency_test.go.

func exeBlock(display, version, code string) *manifest.ExeInstall {
	return &manifest.ExeInstall{InstallerType: "exe", SilentArgs: []string{"/silent"}, SuccessCodes: []int{0}, Signer: "Vendor", Scope: "machine",
		Detect: manifest.ExeDetect{DisplayName: display, DisplayVersion: version, ProductCode: code}}
}

var (
	fcX64 = manifest.Applicability{OS: "windows", Arch: "x64"}
	fcLCU = store.Package{PackageID: "KB5066835-x64-26100", Kind: "msu", KB: "KB5066835", Version: "26100.6899", State: "approved",
		Title:         "2025-10 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5066835) (26100.6899)",
		Applicability: manifest.Applicability{OS: "windows", Arch: "x64", MinBuild: 26100, MaxBuild: 26100}}
	fcZoom = store.Package{PackageID: "Zoom.Zoom-6.6.0", Kind: manifest.KindExe, Version: "6.6.0.16983", PackageName: "Zoom Workplace (64-bit)", State: "approved",
		Applicability: fcX64, Exe: exeBlock("Zoom Workplace (64-bit)", "6.6.0.16983", "")}
	fcChromeOld = store.Package{PackageID: "Google.Chrome-140.0.7339.100", Kind: "msi", Version: "140.0.7339.100", PackageName: "Google Chrome", State: "approved",
		ProductCode: "{5B6A1BDE-2C9A-3F57-9B5D-8C0B0A1C3D41}", Applicability: fcX64}
	fcChromeNew = store.Package{PackageID: "Google.Chrome-141.0.7390.108", Kind: "msi", Version: "141.0.7390.108", PackageName: "Google Chrome", State: "approved",
		ProductCode: "{5B6A1BDE-2C9A-3F57-9B5D-8C0B0A1C3D41}", Applicability: fcX64}

	fcDoc = intel.Doc{GeneratedAt: "2026-10-20T00:00:00Z",
		// No revision in the intelligence: it can only go by the KB list.
		Windows: []intel.WindowsRelease{{Product: "Windows 11 Version 24H2", Build: 26100, Arch: "x64", KB: "KB5066835"}},
		Apps: []intel.App{
			{ID: "Zoom.Zoom", Name: "Zoom Workplace", Version: "6.6.0.16983", Codes: []string{"zoomumx"}, Names: []string{"zoomworkplace"}},
			{ID: "Google.Chrome", Name: "Google Chrome", Version: "141.0.7390.108", Codes: []string{"{5b6a1bde-2c9a-3f57-9b5d-8c0b0a1c3d41}"}, Names: []string{"googlechrome"}},
		}}
)

type fleetCase struct {
	name string
	inv  []store.InventoryItem
	pkgs []store.Package
	kind string // os | app
	key  string
	// needed: the endpoint is in the row's Endpoints (Patches → Needed),
	// with this package ("" = no catalog package serves it: uncovered);
	// else it is among the row's current endpoints.
	needed bool
	pkgID  string
}

func TestFleetAgreesWithStore(t *testing.T) {
	zoomMachineOld := store.InventoryItem{Kind: "product", ID: "{E1E1E1E1-6500-4000-8000-000000012345}", Name: "Zoom Workplace (64-bit)", Version: "6.5.0.12345"}
	zoomUserNew := store.InventoryItem{Kind: "product", ID: "ZoomUMX", Name: "Zoom Workplace", Version: "6.6.1.17000", Scope: "user"}
	zoomUserOld := store.InventoryItem{Kind: "product", ID: "ZoomUMX", Name: "Zoom Workplace", Version: "6.0.2.33403", Scope: "user"}
	chrome := func(v string) store.InventoryItem {
		return store.InventoryItem{Kind: "product", ID: "{5B6A1BDE-2C9A-3F57-9B5D-8C0B0A1C3D41}", Name: "Google Chrome", Version: v}
	}
	cases := []fleetCase{
		{name: "KB not listed, the catalog package's revision proves it: current, not needed",
			pkgs: []store.Package{fcLCU}, kind: "os", key: "KB5066835", needed: false},
		{name: "KB not installed: needed with its package",
			inv: []store.InventoryItem{{Kind: "kb", ID: "KB5065426"}}, pkgs: []store.Package{fcLCU}, kind: "os", key: "KB5066835", needed: true, pkgID: fcLCU.PackageID},
		{name: "Zoom machine copy old, per-user copy new: the EXE package installs, so needed",
			inv: []store.InventoryItem{zoomMachineOld, zoomUserNew}, pkgs: []store.Package{fcZoom}, kind: "app", key: "Zoom.Zoom", needed: true, pkgID: fcZoom.PackageID},
		{name: "Zoom only per-user: outdated, but the EXE package does not serve it (uncovered)",
			inv: []store.InventoryItem{zoomUserOld}, pkgs: []store.Package{fcZoom}, kind: "app", key: "Zoom.Zoom", needed: true, pkgID: ""},
		{name: "Chrome newer than the catalog's (same product code): needs a newer import, not Patch this",
			inv: []store.InventoryItem{chrome("140.0.7339.208")}, pkgs: []store.Package{fcChromeOld}, kind: "app", key: "Google.Chrome", needed: true, pkgID: ""},
		{name: "Chrome older than the catalog's: needed with that package",
			inv: []store.InventoryItem{chrome("140.0.7339.208")}, pkgs: []store.Package{fcChromeOld, fcChromeNew}, kind: "app", key: "Google.Chrome", needed: true, pkgID: fcChromeNew.PackageID},
		{name: "Chrome at the catalog's version: current",
			inv: []store.InventoryItem{chrome("141.0.7390.108")}, pkgs: []store.Package{fcChromeNew}, kind: "app", key: "Google.Chrome", needed: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st, err := store.Open(filepath.Join(t.TempDir(), "pm.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { st.Close() })
			inv := c.inv
			if inv == nil {
				inv = []store.InventoryItem{}
			}
			e := store.Endpoint{EndpointID: "e-1", Hostname: "pc-1", OS: "windows", OSVersion: "Windows 11 Pro 24H2 (26100.6899)", Build: 26100, Arch: "x64",
				AgentVersion: "1.2.0"}.WithInventory(inv)
			if c.kind == "os" && len(c.inv) > 0 {
				e.OSVersion = "Windows 11 Pro 24H2 (26100.6584)"
			}
			ci := newCatalogIndex(c.pkgs, st)
			snap := buildFleet(intel.NewIndex(fcDoc), ci, []store.Endpoint{e})
			u := snap.byKey[c.kind+"/"+c.key]
			if u == nil {
				t.Fatalf("no row %s/%s", c.kind, c.key)
			}
			var need *fleetNeed
			for i := range u.Endpoints {
				if u.Endpoints[i].EndpointID == "e-1" {
					need = &u.Endpoints[i]
				}
			}
			cur := false
			for _, n := range u.current {
				cur = cur || n.EndpointID == "e-1"
			}
			if c.needed != (need != nil) || cur == c.needed {
				t.Fatalf("needed=%v current=%v, want needed=%v", need != nil, cur, c.needed)
			}
			if need != nil && need.PackageID != c.pkgID {
				t.Errorf("package %q, want %q", need.PackageID, c.pkgID)
			}
			inMissing := false
			for _, m := range snap.missing {
				inMissing = inMissing || m == u
			}
			if inMissing != c.needed {
				t.Errorf("in Patches → Needed: %v", inMissing)
			}
			if c.needed && c.pkgID == "" && u.Uncovered != 1 {
				t.Errorf("uncovered %d, want 1", u.Uncovered)
			}
			// The per-endpoint missing counts follow the same verdict.
			m := snap.perEP["e-1"]
			got := m.Apps
			if c.kind == "os" {
				got = m.OS
			}
			if (got > 0) != c.needed {
				t.Errorf("endpoint missing counts %+v", m)
			}
			// And the store says the same about the linked package.
			if c.pkgID != "" {
				p := ci.pkgs[c.pkgID]
				if v := st.Classify(p, e, nil); (v.Presence == store.PresenceNeeded) != c.needed {
					t.Errorf("store verdict %s", v.Presence)
				}
			}
		})
	}
}

// An install waiting for its restart is "restart needed", not "being
// patched".
func TestEndpointStatusRestartNeeded(t *testing.T) {
	if got := endpointStatus(store.TargetStatus{Deploying: true, RestartNeeded: true}, true); got != "restart_needed" {
		t.Errorf("pending_reboot: %s", got)
	}
	if got := endpointStatus(store.TargetStatus{Deploying: true}, true); got != "being_patched" {
		t.Errorf("installing: %s", got)
	}
	if got := endpointStatus(store.TargetStatus{Deploying: true, RestartNeeded: true, Failed: true}, true); got != "failed" {
		t.Errorf("failed elsewhere: %s", got)
	}
}
