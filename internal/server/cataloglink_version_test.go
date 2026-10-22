package server

import (
	"testing"

	"offpatch/internal/store"
)

// A row that says "latest 300" must not link (and open) the catalog package
// of version 200 that no machine on the row can use: the owner clicked a
// 300 row in Patches and the package page showed 200.
func TestAppRowLinksOnlyTheVersionItOffers(t *testing.T) {
	old := linkOf(store.Package{PackageID: "app-200", State: "approved", Version: "200"})
	cur := linkOf(store.Package{PackageID: "app-300", State: "approved", Version: "300"})
	ci := &catalogIndex{byID: map[string]catalogLink{old.PackageID: old, cur.PackageID: cur}}

	// Every machine already runs 200; only 300 would help: no package.
	row := &fleetUpdate{Kind: "app", Key: "Vendor.App", Latest: "300", Catalog: &old,
		Endpoints: []fleetNeed{{EndpointID: "a", Installed: "200"}}}
	row.linkCatalog(ci)
	if row.Catalog != nil || row.statusCatalog() != nil {
		t.Fatalf("row for 300 linked the 200 package: %+v", row.Catalog)
	}

	// One machine still runs 100: the 200 package serves it, and the link
	// carries its version so the row can say it is not the latest.
	row = &fleetUpdate{Kind: "app", Key: "Vendor.App", Latest: "300", Catalog: &old,
		Endpoints: []fleetNeed{{EndpointID: "a", Installed: "200"}, {EndpointID: "b", Installed: "100", PackageID: "app-200"}}}
	row.linkCatalog(ci)
	if row.Catalog == nil || row.Catalog.PackageID != "app-200" || row.Catalog.Version != "200" {
		t.Fatalf("serving package not linked with its version: %+v", row.Catalog)
	}

	// The 300 package is in the catalog but applies to none of these
	// machines (e.g. another architecture): the row still names it.
	row = &fleetUpdate{Kind: "app", Key: "Vendor.App", Latest: "300", Catalog: &cur,
		Endpoints: []fleetNeed{{EndpointID: "a", Installed: "200"}}}
	row.linkCatalog(ci)
	if row.Catalog == nil || row.Catalog.PackageID != "app-300" {
		t.Fatalf("package of the latest version dropped: %+v", row.Catalog)
	}

	// Up to date everywhere: the package of an older version found by name
	// is not the row's package; the one of the latest version is.
	row = &fleetUpdate{Kind: "app", Key: "Vendor.App", Latest: "300", currentCat: &old}
	if got := row.statusCatalog(); got != nil {
		t.Fatalf("up-to-date row linked the older package: %+v", got)
	}
	row.currentCat = &cur
	if got := row.statusCatalog(); got == nil || got.PackageID != "app-300" {
		t.Fatalf("up-to-date row lost its package: %+v", got)
	}
}
