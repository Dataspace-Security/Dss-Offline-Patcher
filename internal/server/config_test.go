package server

import "testing"

// The shipped example must stay loadable as the config schema evolves.
func TestExampleConfigLoads(t *testing.T) {
	c, err := LoadConfig("../../packaging/server/pmserver.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if c.OIDC == nil || !c.RequireMFA || c.ApprovalPolicy["critical"] != 2 || c.AuditRetention.Hours() != 26280 {
		t.Fatalf("example config not parsed as expected: %+v", c)
	}
}

func TestPreinstallDefaults(t *testing.T) {
	p := PreinstallConfig{MinFreeDiskMB: map[string]int{"windows": 8192}}
	if err := p.normalize(); err != nil {
		t.Fatal(err)
	}
	if got := p.policyFor("windows"); got.MinFreeDiskMB != 8192 || got.MinBatteryPct != 40 {
		t.Fatalf("windows: %+v", got)
	}
	if got := p.policyFor("macos"); got.MinFreeDiskMB != 2048 {
		t.Fatalf("macos default: %+v", got)
	}
	bad := PreinstallConfig{MinFreeDiskMB: map[string]int{"solaris": 1}}
	if bad.normalize() == nil {
		t.Fatal("unknown OS key accepted")
	}
	c, err := LoadConfig("../../packaging/server/pmserver.example.json")
	if err != nil || c.LostAfterInstall.Hours() != 2 || c.Preinstall.policyFor("linux").MinFreeDiskMB != 1024 {
		t.Fatalf("example: %v %+v", err, c)
	}
}
