package store

import (
	"context"
	"testing"
)

// Re-running the enrollment command on a PC creates a new endpoint; at its
// first check-in with hardware, the old record of the same machine is
// retired (its open targets close), a different machine with the same name
// is not.
func TestReenrollRetiresOldRecord(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	for _, id := range []string{"e-old", "e-other", "e-new"} {
		addEndpoint(t, s, id, []string{"pilot"}, nil)
		if _, err := s.db.Exec(`UPDATE endpoints SET hostname='DESKTOP-1' WHERE endpoint_id=?`, id); err != nil {
			t.Fatal(err)
		}
	}
	mustExec := func(q string, args ...any) {
		t.Helper()
		if _, err := s.db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	mustExec(`UPDATE endpoints SET hardware=? WHERE endpoint_id='e-old'`, mustJSON(Hardware{SerialNumber: "VMware-56 4d 12", MACAddress: "00:0c:29:aa:bb:cc"}))
	mustExec(`UPDATE endpoints SET hardware=? WHERE endpoint_id='e-other'`, mustJSON(Hardware{SerialNumber: "Default string", MACAddress: "00:0c:29:11:22:33"}))
	mustExec(`UPDATE endpoints SET enrolled_at='2026-01-01T00:00:00Z' WHERE endpoint_id IN ('e-old','e-other')`)

	hw := &Hardware{SerialNumber: "VMware-56 4d 12", MACAddress: "00:0c:29:aa:bb:cc"}
	if _, err := s.Checkin(ctx, "e-new", CheckinRequest{Hostname: "DESKTOP-1", OSVersion: "Windows 11", Build: 26200, Arch: "x64", AgentVersion: "0.9.8", Hardware: hw}); err != nil {
		t.Fatal(err)
	}
	old, err := getEndpoint(ctx, s.db, "e-old")
	if err != nil || old.RetiredAt == "" || old.RetiredReason != "re-enrolled as e-new" {
		t.Fatalf("old record not retired: %+v %v", old, err)
	}
	other, _ := getEndpoint(ctx, s.db, "e-other")
	if other.RetiredAt != "" {
		t.Fatal("a different machine with the same name was retired")
	}
	cur, _ := getEndpoint(ctx, s.db, "e-new")
	if cur.RetiredAt != "" {
		t.Fatal("the new record was retired")
	}
}
