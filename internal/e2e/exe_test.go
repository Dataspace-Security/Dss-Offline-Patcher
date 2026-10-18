package e2e

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"offpatch/internal/agent"
	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

func exePkg() manifest.Package {
	const name = "Microsoft Edge WebView2 Runtime"
	return manifest.Package{PackageID: "Microsoft.EdgeWebView2Runtime-155.0.4283.62", Title: name + " 155.0.4283.62", Vendor: "Microsoft Corporation",
		Kind: manifest.KindExe, Version: "155.0.4283.62", Severity: "important", ReleaseDate: "2026-10-16", Supersedes: []string{}, PackageName: name,
		Applicability:   manifest.Applicability{OS: "windows", Arch: "x64"},
		SourceURL:       "https://msedge.sf.dl.delivery.mp.microsoft.com/MicrosoftEdgeWebView2RuntimeInstallerX64.exe",
		VendorSignature: manifest.VendorSignature{Status: "valid", Signer: "Microsoft Corporation"},
		Exe: &manifest.ExeInstall{InstallerType: "exe", SilentArgs: []string{"/silent", "/install"}, SuccessCodes: []int{0, 3010, 1641, -2147219416},
			Signer: "Microsoft Corporation", Scope: "machine",
			Detect: manifest.ExeDetect{DisplayName: name, ProductCode: "Microsoft EdgeWebView", Publisher: "Microsoft Corporation"}}}
}

// An EXE package goes through intake (exe block stored, rollback reported
// unsupported without a quiet uninstall), is approved and deployed: an
// agent 0.9.0 installs it and the server verifies it from Apps & features;
// an endpoint whose agent is older is not_applicable and never offered it.
func TestExePackageEndToEnd(t *testing.T) {
	e := newEnv(t)
	p := exePkg()
	files := map[string]string{p.PackageID: e.payload("MicrosoftEdgeWebView2RuntimeInstallerX64.exe", "MZ synthetic webview2")}
	if b := e.transferAndIntake(e.bundle(bundleOpts{seq: 1}, map[string]manifest.Package{p.PackageID: p}, files)); b.State != "validated" {
		t.Fatalf("intake: %+v", b)
	}
	var got store.Package
	if c := e.api("GET", "/api/packages/"+p.PackageID, tokViewer, nil, &got); c != 200 {
		t.Fatalf("package: %d", c)
	}
	if got.Kind != "exe" || got.Exe == nil || got.Exe.InstallerType != "exe" || got.Exe.Signer != "Microsoft Corporation" ||
		got.RollbackUnsupported != store.RollbackNoQuietUninstall || got.State != "quarantined" {
		t.Fatalf("stored package: %+v exe %+v", got, got.Exe)
	}
	e.approve(p.PackageID)

	oldInv := []store.InventoryItem{{Kind: "product", ID: "Microsoft EdgeWebView", Name: "Microsoft Edge WebView2 Runtime", Version: "154.0.4258.62"}}
	seed, _ := json.Marshal(map[string]any{"products": oldInv})
	fresh := e.enroll("pc-exe-090", []string{"pilot"}, agent.SimConfig{})
	os.WriteFile(filepath.Join(fresh.dir, "sim-state.json"), seed, 0o600)
	e.cycle(fresh)
	old := e.enroll("pc-exe-065", []string{"pilot"}, agent.SimConfig{})
	// The old endpoint reports agent 0.6.5 (it never runs the new agent here).
	if _, err := e.st.Checkin(context.Background(), old.id, store.CheckinRequest{Hostname: "pc-exe-065", OSVersion: "Windows 10", Build: 19045, Arch: "x64",
		AgentVersion: "0.6.5", Inventory: oldInv}); err != nil {
		t.Fatal(err)
	}

	d := e.deploy(store.NewDeployment{PackageID: p.PackageID, Name: "webview2", Rings: []store.Ring{{Name: "pilot", Groups: []string{"pilot"}}}})
	dd := e.deployment(d.DeploymentID)
	for _, tg := range dd.Targets {
		if tg.EndpointID == old.id && (tg.State != "not_applicable" || tg.Detail != manifest.AgentTooOldForExe) {
			t.Fatalf("old agent target: %+v", tg)
		}
	}
	res, err := e.st.Checkin(context.Background(), old.id, store.CheckinRequest{Hostname: "pc-exe-065", OSVersion: "Windows 10", Build: 19045, Arch: "x64",
		AgentVersion: "0.6.5", Inventory: oldInv})
	if err != nil || len(res.Assignments) != 0 {
		t.Fatalf("old agent offered the EXE package: %v %+v", err, res.Assignments)
	}

	e.cycle(fresh) // download, install
	e.cycle(fresh) // inventory shows 155.0.4283.62 → verified
	dd = e.deployment(d.DeploymentID)
	if s := targetState(dd, fresh.id); s != "verified" {
		t.Fatalf("agent 0.9.0 target: %s (%+v)", s, dd.Targets)
	}
	if s := targetState(dd, old.id); s != "not_applicable" {
		t.Fatalf("old agent target changed: %s", s)
	}
	// Rollback is refused: the installer registers no silent uninstall.
	if c, msg := e.apiErr("POST", "/api/deployments", tokOperator, map[string]any{"package_id": p.PackageID, "name": "undo", "operation": "rollback",
		"justification": "test", "rings": []store.Ring{{Name: "pilot", Groups: []string{"pilot"}}}}); c/100 == 2 || !strings.Contains(msg, "no silent uninstall") {
		t.Fatalf("rollback of an exe without quiet uninstall accepted: %d %s", c, msg)
	}
}
