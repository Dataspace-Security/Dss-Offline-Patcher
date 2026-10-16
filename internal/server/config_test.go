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
