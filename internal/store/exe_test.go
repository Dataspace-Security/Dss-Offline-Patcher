package store

import (
	"context"
	"strings"
	"testing"

	"offpatch/internal/manifest"
)

func vcredist(arch string, quiet bool) Package {
	name := "Microsoft Visual C++ 2015-2022 Redistributable (" + arch + ")"
	return Package{PackageID: "VCRedist-14.51-" + arch, Kind: manifest.KindExe, Version: "14.51.36247.0", PackageName: name,
		Applicability: manifest.Applicability{OS: "windows", Arch: "x64"},
		Exe: &manifest.ExeInstall{InstallerType: "burn", SilentArgs: []string{"/quiet", "/norestart"}, SuccessCodes: []int{0, 3010}, Signer: "Microsoft Corporation",
			Detect: manifest.ExeDetect{DisplayName: name}, Uninstall: manifest.ExeUninstall{QuietUninstall: quiet}, Scope: "machine"}}
}

func TestExeRollbackSupport(t *testing.T) {
	if why := RollbackUnsupported(vcredist("x64", true)); why != "" {
		t.Errorf("burn with quiet uninstall: %q", why)
	}
	if why := RollbackUnsupported(vcredist("x64", false)); why != RollbackNoQuietUninstall {
		t.Errorf("no quiet uninstall: %q", why)
	}
	p := vcredist("x64", true)
	p.Exe = nil
	if why := RollbackUnsupported(p); why != RollbackNoQuietUninstall {
		t.Errorf("no exe block: %q", why)
	}
	// Stored and read back: rollback_unsupported follows the exe block.
	s := openTest(t)
	addPackage(t, s, vcredist("x64", false))
	got, err := s.GetPackage(context.Background(), "VCRedist-14.51-x64")
	if err != nil || got.Exe == nil || got.Exe.InstallerType != "burn" || got.RollbackUnsupported != RollbackNoQuietUninstall {
		t.Fatalf("stored: %v %+v", err, got)
	}
	if _, err := s.CreateDeployment(context.Background(), "user:otto", NewDeployment{PackageID: got.PackageID, Name: "undo", Rings: allRing,
		Operation: "rollback", Justification: "x"}); err == nil || !strings.Contains(err.Error(), "no silent uninstall") {
		t.Fatalf("rollback of an exe without quiet uninstall: %v", err)
	}
}

// ARP matching as the agent does it: x86 and x64 builds never satisfy each
// other; the ARP key wins when known; per-user entries do not count; the
// installed DisplayVersion must reach the package's.
func TestExeMatching(t *testing.T) {
	x64, x86 := vcredist("x64", true), vcredist("x86", true)
	inst64 := InventoryItem{Kind: "product", ID: "{0E3BB569-69D6-4C34-BFF9-C2F81DB5E5F0}", Name: "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.51.36247", Version: "14.51.36247.0"}
	old64 := InventoryItem{Kind: "product", ID: "{11111111-69D6-4C34-BFF9-C2F81DB5E5F0}", Name: "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.40.33810", Version: "14.40.33810.0"}
	inst86 := InventoryItem{Kind: "product", ID: "{22222222-69D6-4C34-BFF9-C2F81DB5E5F0}", Name: "Microsoft Visual C++ 2015-2022 Redistributable (x86) - 14.51.36247", Version: "14.51.36247.0"}
	if !exeAppMatch(x64, inst64) || exeAppMatch(x64, inst86) || exeAppMatch(x86, inst64) || !exeAppMatch(x86, inst86) {
		t.Fatal("architecture tag not respected")
	}
	if ok, _, ev := presentOn([]InventoryItem{inst86}, OSFacts{}, x64, nil); ok {
		t.Fatalf("x86 runtime verified the x64 package: %s", ev)
	}
	if ok, why, _ := presentOn([]InventoryItem{inst64}, OSFacts{}, x64, nil); !ok || !strings.Contains(why, "14.51.36247.0") {
		t.Fatalf("x64 runtime at the version: %v %s", ok, why)
	}
	if ok, _, _ := presentOn([]InventoryItem{old64}, OSFacts{}, x64, nil); ok {
		t.Fatal("older version verified")
	}
	user := inst64
	user.Scope = "user"
	if exeAppMatch(x64, user) || appInstalled([]InventoryItem{user}, x64) {
		t.Fatal("per-user entry counted")
	}
	// detect.product_code (the ARP key) matches whatever the name says.
	wv := Package{PackageID: "WebView2", Kind: manifest.KindExe, Version: "155.0.4283.62", PackageName: "Microsoft Edge WebView2 Runtime",
		Exe: &manifest.ExeInstall{Detect: manifest.ExeDetect{DisplayName: "Microsoft Edge WebView2 Runtime", ProductCode: "Microsoft EdgeWebView", DisplayVersion: "155.0.4283.62"}}}
	if !exeAppMatch(wv, InventoryItem{Kind: "product", ID: "Microsoft EdgeWebView", Name: "Edge WebView (renamed)", Version: "155.0.4283.62"}) {
		t.Fatal("ARP key not matched")
	}
	// display_version decides when set.
	if ok, _, _ := presentOn([]InventoryItem{{Kind: "product", ID: "Microsoft EdgeWebView", Version: "155.0.4283.61"}}, OSFacts{}, wv, nil); ok {
		t.Fatal("older DisplayVersion verified")
	}
	// Needs: an older x64 runtime needs the x64 package, not the x86 one.
	e := Endpoint{OS: "windows", Arch: "x64", AgentVersion: "0.9.0"}
	if need, have, _ := needs(x64, e, OSFacts{}, []InventoryItem{old64}, nil); !need || have != "14.40.33810.0" {
		t.Fatalf("needs x64: %v %s", need, have)
	}
	x86.Applicability = manifest.Applicability{OS: "windows", Arch: "x64"}
	if need, _, _ := needs(x86, e, OSFacts{}, []InventoryItem{old64}, nil); need {
		t.Fatal("x86 package needed by an x64-only inventory")
	}
	if !appInstalled([]InventoryItem{old64}, x64) || appInstalled([]InventoryItem{old64}, x86) {
		t.Fatal("appInstalled")
	}
	if exeIdentity(x64) == exeIdentity(x86) {
		t.Fatal("x86 and x64 share an identity")
	}
	// Rollback scope: exactly this version.
	if ok, _ := rollbackPresent([]InventoryItem{inst64}, x64); !ok {
		t.Fatal("rollback: installed version not found")
	}
	if ok, why := rollbackPresent([]InventoryItem{old64}, x64); ok || !strings.Contains(why, "is not") {
		t.Fatalf("rollback of another version: %v %s", ok, why)
	}
}

// Regression: an exe package's detect.display_name empty (but package_name
// set) used to make exeDetect return an all-empty detection block, so
// exeAppMatch could never match any inventory item — the package counted as
// never installed, never needed, never verified, no matter what was really
// on the endpoint. exeDetect must fall back to package_name here exactly as
// it already does when the whole exe: block is missing.
func TestExeDetectFallsBackToPackageName(t *testing.T) {
	p := Package{PackageID: "GHDesktop", Kind: manifest.KindExe, Version: "3.6.9", PackageName: "GitHub Desktop",
		Applicability: manifest.Applicability{OS: "windows", Arch: "x64"},
		Exe:           &manifest.ExeInstall{InstallerType: "msi", Detect: manifest.ExeDetect{DisplayVersion: "3.6.9"}}} // no display_name
	old := InventoryItem{Kind: "product", ID: "{random-product-code}", Name: "GitHub Desktop", Version: "3.6.7"}
	if !exeAppMatch(p, old) {
		t.Fatal("exeAppMatch must fall back to package_name when detect.display_name is empty")
	}
	if ok, _, _ := presentOn([]InventoryItem{old}, OSFacts{}, p, nil); ok {
		t.Fatal("an older installed version must not verify")
	}
	if !appInstalled([]InventoryItem{old}, p) {
		t.Fatal("appInstalled must see the older copy (so it counts as needed, not not-installed)")
	}
	current := old
	current.Version = "3.6.9"
	if ok, _, _ := presentOn([]InventoryItem{current}, OSFacts{}, p, nil); !ok {
		t.Fatal("the current version must verify once display_name falls back to package_name")
	}
}

func TestAgentSupportsExe(t *testing.T) {
	for v, want := range map[string]bool{"0.9.0": true, "0.9.1": true, "1.0": true, "v0.10.0": true, "0.8.9": false, "0.6.5": false, "": false, "dev": false} {
		if got := AgentSupportsExe(v); got != want {
			t.Errorf("%q: %v", v, got)
		}
	}
}

// An EXE deployment: targets on agents before 0.9.0 are not_applicable
// with the contract's detail and never assigned; after the agent upgrade
// the target is back in scope and assigned.
func TestExeAgentVersionGate(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	p := vcredist("x64", true)
	addPackage(t, s, p)
	old := []InventoryItem{{Kind: "product", ID: "{OLD}", Name: "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.40.33810", Version: "14.40.33810.0"}}
	addEndpoint(t, s, "e-old-agent", []string{"pilot"}, old)
	addEndpoint(t, s, "e-new-agent", []string{"pilot"}, old)
	s.db.Exec(`UPDATE endpoints SET agent_version='0.6.5' WHERE endpoint_id='e-old-agent'`)
	d, err := createApproved(s, ctx, "user:otto", NewDeployment{PackageID: p.PackageID, Name: "vc++", Rings: allRing, MaxFailurePct: 50})
	if err != nil {
		t.Fatal(err)
	}
	dd, err := s.GetDeployment(ctx, d.DeploymentID)
	if err != nil {
		t.Fatal(err)
	}
	states := map[string]Target{}
	for _, tg := range dd.Targets {
		states[tg.EndpointID] = tg
	}
	if tg := states["e-old-agent"]; tg.State != "not_applicable" || tg.Detail != manifest.AgentTooOldForExe {
		t.Fatalf("old agent target: %+v", tg)
	}
	if tg := states["e-new-agent"]; tg.State != "pending" {
		t.Fatalf("new agent target: %+v", tg)
	}
	res, err := s.Checkin(ctx, "e-old-agent", CheckinRequest{Hostname: "host-e-old-agent", OSVersion: "Windows 10", Build: 19045, Arch: "x64", AgentVersion: "0.6.5", Inventory: old})
	if err != nil || len(res.Assignments) != 0 {
		t.Fatalf("old agent offered the EXE package: %v %+v", err, res.Assignments)
	}
	if res := checkin(t, s, "e-new-agent", old, false); len(res.Assignments) != 1 || res.Assignments[0].Kind != "exe" {
		t.Fatalf("new agent: %+v", res.Assignments)
	}
	// The old endpoint's agent is upgraded: in scope again.
	res, err = s.Checkin(ctx, "e-old-agent", CheckinRequest{Hostname: "host-e-old-agent", OSVersion: "Windows 10", Build: 19045, Arch: "x64", AgentVersion: "0.9.0", Inventory: old})
	if err != nil || len(res.Assignments) != 1 {
		t.Fatalf("upgraded agent: %v %+v", err, res.Assignments)
	}
}

// The agent's EXE signature failure detail raises the integrity alert.
func TestExeSignatureFailureIsIntegrity(t *testing.T) {
	if !integrityFailure("signature check failed: signer \"Evil Corp\" is not \"Microsoft Corporation\" — possible tampering") {
		t.Fatal("EXE signature failure not treated as an integrity failure")
	}
}
