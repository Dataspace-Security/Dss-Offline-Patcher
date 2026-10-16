package e2e

import (
	"testing"

	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

// rawEndpoint enrolls an endpoint directly over the API with a given OS and
// inventory (lets one test mix Windows and macOS machines).
func (e *env) rawEndpoint(host, os, arch string, build int, groups []string, inv []store.InventoryItem) (id, secret string) {
	e.t.Helper()
	var tok store.EnrollmentToken
	e.api("POST", "/api/enrollment-tokens", tokOperator, map[string]any{"groups": groups, "site": "hq", "expires_in_hours": 1}, &tok)
	var r struct {
		EndpointID string `json:"endpoint_id"`
		Secret     string `json:"secret"`
	}
	if c := e.api("POST", "/api/agent/enroll", "", store.EnrollRequest{Token: tok.Token, Hostname: host, OS: os, Build: build, Arch: arch}, &r); c != 201 {
		e.t.Fatalf("enroll %s: %d", host, c)
	}
	if c := e.api("POST", "/api/agent/checkin", r.Secret, store.CheckinRequest{Hostname: host, Build: build, Arch: arch, Inventory: inv}, nil); c != 200 {
		e.t.Fatalf("checkin %s: %d", host, c)
	}
	return r.EndpointID, r.Secret
}

func pkgPkg(id, name, ver string) manifest.Package {
	return manifest.Package{PackageID: id, Title: name + " " + ver, Vendor: "Acme", Kind: "pkg", Version: ver, PackageName: name,
		Severity: "important", Supersedes: []string{}, Applicability: manifest.Applicability{OS: "macos", Arch: "any"},
		VendorSignature: manifest.VendorSignature{Status: "not_checked"}}
}

func availIDs(e *env, endpointID string) map[string]store.Available {
	var av []store.Available
	if c := e.api("GET", "/api/endpoints/"+endpointID+"/available", tokViewer, nil, &av); c != 200 {
		e.t.Fatalf("available: %d", c)
	}
	m := map[string]store.Available{}
	for _, a := range av {
		m[a.PackageID] = a
	}
	return m
}

func TestAvailablePatches(t *testing.T) {
	e := newEnv(t)
	msiPkg := manifest.Package{PackageID: "AcmeApp-3.0", Title: "Acme App 3.0", Vendor: "Acme", Kind: "msi", Version: "3.0.0",
		ProductCode: "{22222222-2222-3333-4444-555555555555}", PackageName: "Acme App", Severity: "important", Supersedes: []string{},
		Applicability: manifest.Applicability{OS: "windows", Arch: "any"}, VendorSignature: manifest.VendorSignature{Status: "not_checked"}}
	pk := map[string]manifest.Package{
		"mac-app-1.5":   pkgPkg("mac-app-1.5", "com.acme.app", "1.5.0"),
		"mac-app-2.0":   pkgPkg("mac-app-2.0", "com.acme.app", "2.0.0"),
		"KB5003001-x64": msuPkg("KB5003001-x64", "KB5003001"),
		"KB5003002-x64": msuPkg("KB5003002-x64", "KB5003002", "KB5003001"), // newer CU
		"AcmeApp-3.0":   msiPkg,
	}
	files := map[string]string{}
	for id := range pk {
		files[id] = e.payload(id+".bin", "x"+id)
	}
	if b := e.transferAndIntake(e.bundle(bundleOpts{seq: 1}, pk, files)); b.State != "validated" {
		t.Fatalf("intake: %+v", b)
	}
	for _, id := range []string{"mac-app-1.5", "mac-app-2.0", "KB5003002-x64", "AcmeApp-3.0"} {
		e.approve(id)
	} // KB5003001 stays quarantined

	mac, _ := e.rawEndpoint("mac-old", "macos", "arm64", 0, []string{"mac"}, []store.InventoryItem{{Kind: "pkg", ID: "com.acme.app", Version: "1.0.0"}})
	macNoApp, _ := e.rawEndpoint("mac-noapp", "macos", "arm64", 0, []string{"mac"}, []store.InventoryItem{{Kind: "pkg", ID: "com.apple.other", Version: "9"}})
	win, _ := e.rawEndpoint("win-old", "windows", "x64", 19045, []string{"win"}, []store.InventoryItem{{Kind: "product", ID: "{11111111-0000-0000-0000-000000000000}", Name: "Acme App", Version: "2.1.0"}})
	winNew, _ := e.rawEndpoint("win-new", "windows", "x64", 19045, []string{"win"}, []store.InventoryItem{{Kind: "kb", ID: "KB5003002"}})

	// Mac with an old app version: only the NEWEST version is offered.
	a := availIDs(e, mac)
	if len(a) != 1 || a["mac-app-2.0"].InstalledVersion != "1.0.0" || a["mac-app-2.0"].PackageState != "approved" {
		t.Fatalf("mac-old available: %+v", a)
	}
	// App not installed → nothing pushed.
	if a := availIDs(e, macNoApp); len(a) != 0 {
		t.Fatalf("app not installed must not be offered: %+v", a)
	}
	// Windows: newest CU only (old one superseded), plus the MSI update by display name.
	a = availIDs(e, win)
	if _, ok := a["KB5003002-x64"]; !ok || len(a) != 2 || a["AcmeApp-3.0"].InstalledVersion != "2.1.0" {
		t.Fatalf("win-old available: %+v", a)
	}
	if _, ok := a["KB5003001-x64"]; ok {
		t.Fatal("superseded KB offered")
	}
	// Up-to-date Windows machine: only the MSI is irrelevant (not installed) → nothing.
	if a := availIDs(e, winNew); len(a) != 0 {
		t.Fatalf("win-new available: %+v", a)
	}

	// Fleet view.
	var needs map[string]store.PackageNeed
	e.api("GET", "/api/packages-needs", tokViewer, nil, &needs)
	if needs["mac-app-2.0"].Needed != 1 || needs["KB5003002-x64"].Needed != 1 || needs["AcmeApp-3.0"].Needed != 1 {
		t.Fatalf("needs: %+v", needs)
	}

	// One-click deploy to exactly the endpoints that need it.
	d := e.deploy(store.NewDeployment{PackageID: "mac-app-2.0", Name: "needed", Rings: []store.Ring{{Name: "needed", Groups: []string{"endpoint:" + mac}}}})
	dd := e.deployment(d.DeploymentID)
	if len(dd.Targets) != 1 || dd.Targets[0].EndpointID != mac {
		t.Fatalf("endpoint-targeted ring should reach only %s: %+v", mac, dd.Targets)
	}
	if a := availIDs(e, mac); a["mac-app-2.0"].DeploymentID != d.DeploymentID {
		t.Fatalf("available should show the deployment in progress: %+v", a)
	}

	// Awaiting approval is shown as such.
	pk2 := map[string]manifest.Package{"mac-app-2.1": pkgPkg("mac-app-2.1", "com.acme.app", "2.1.0")}
	e.transferAndIntake(e.bundle(bundleOpts{seq: 2}, pk2, map[string]string{"mac-app-2.1": e.payload("m21.pkg", "m21")}))
	a = availIDs(e, mac)
	if a["mac-app-2.1"].PackageState != "quarantined" || len(a) != 1 {
		t.Fatalf("newest version awaiting approval should be shown: %+v", a)
	}
}
