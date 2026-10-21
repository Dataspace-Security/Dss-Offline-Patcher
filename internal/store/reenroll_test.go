package store

import (
	"context"
	"strings"
	"testing"
)

// reenrollFixture adds endpoints with host name DESKTOP-1, enrolled and
// last seen at old times, in site hq unless set otherwise.
func reenrollFixture(t *testing.T, s *Store, ids ...string) func(q string, args ...any) {
	t.Helper()
	mustExec := func(q string, args ...any) {
		t.Helper()
		if _, err := s.db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range ids {
		addEndpoint(t, s, id, []string{"pilot"}, nil)
		mustExec(`UPDATE endpoints SET hostname='DESKTOP-1', enrolled_at='2026-01-01T00:00:00Z', last_seen='2026-01-02T00:00:00Z' WHERE endpoint_id=?`, id)
	}
	return mustExec
}

func checkinHW(t *testing.T, s *Store, id string, hw Hardware) {
	t.Helper()
	if _, err := s.Checkin(context.Background(), id, CheckinRequest{Hostname: "DESKTOP-1", OSVersion: "Windows 11", Build: 26200, Arch: "x64", AgentVersion: "0.9.8", Hardware: &hw}); err != nil {
		t.Fatal(err)
	}
}

func retired(t *testing.T, s *Store, id string) bool {
	t.Helper()
	e, err := getEndpoint(context.Background(), s.db, id)
	if err != nil {
		t.Fatal(err)
	}
	return e.RetiredAt != ""
}

// Re-running the enrollment command on a PC creates a new endpoint; at its
// first check-in with hardware, the old record of the same machine is
// retired (its open targets close), a different machine with the same name
// is not.
func TestReenrollRetiresOldRecord(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	mustExec := reenrollFixture(t, s, "e-old", "e-other")
	addEndpoint(t, s, "e-new", []string{"pilot"}, nil)
	mustExec(`UPDATE endpoints SET hardware=? WHERE endpoint_id='e-old'`, mustJSON(Hardware{SerialNumber: "VMware-56 4d 12", MACAddress: "00:0c:29:aa:bb:cc"}))
	mustExec(`UPDATE endpoints SET hardware=? WHERE endpoint_id='e-other'`, mustJSON(Hardware{SerialNumber: "Default string", MACAddress: "00:0c:29:11:22:33"}))

	checkinHW(t, s, "e-new", Hardware{SerialNumber: "VMware-56 4d 12", MACAddress: "00:0c:29:aa:bb:cc"})
	old, err := getEndpoint(ctx, s.db, "e-old")
	if err != nil || old.RetiredAt == "" || old.RetiredReason != "re-enrolled as e-new" {
		t.Fatalf("old record not retired: %+v %v", old, err)
	}
	if retired(t, s, "e-other") {
		t.Fatal("a different machine with the same name was retired")
	}
	if retired(t, s, "e-new") {
		t.Fatal("the new record was retired")
	}
}

// A check-in's hardware is the endpoint's own claim: it never retires a
// record in another site, a record still checking in, a record whose real
// serial differs (even with the same MAC), or one matched only by MAC when
// one side has a real serial.
func TestReenrollRefusesSpoofedClaims(t *testing.T) {
	victimHW := Hardware{SerialNumber: "PF3ABCDE", MACAddress: "aa:bb:cc:dd:ee:01"}
	cases := []struct {
		name   string
		setup  string // SQL applied to e-old (the victim)
		claim  Hardware
		retire bool
	}{
		{"same site, stale, same serial", ``, victimHW, true},
		{"other site", `UPDATE endpoints SET site='branch-7' WHERE endpoint_id='e-old'`, victimHW, false},
		{"old record still checking in", `UPDATE endpoints SET last_seen='2099-01-01T00:00:00Z' WHERE endpoint_id='e-old'`, victimHW, false},
		{"other real serial, same MAC", ``, Hardware{SerialNumber: "PF3ZZZZZ", MACAddress: victimHW.MACAddress}, false},
		{"generic serial claim, same MAC as a real-serial record", ``, Hardware{SerialNumber: "To Be Filled By O.E.M.", MACAddress: victimHW.MACAddress}, false},
		{"empty serial claim, same MAC", ``, Hardware{MACAddress: victimHW.MACAddress}, false},
		{"other host name", `UPDATE endpoints SET hostname='DESKTOP-2' WHERE endpoint_id='e-old'`, victimHW, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := openTest(t)
			mustExec := reenrollFixture(t, s, "e-old")
			mustExec(`UPDATE endpoints SET hardware=? WHERE endpoint_id='e-old'`, mustJSON(victimHW))
			if c.setup != "" {
				mustExec(c.setup)
			}
			addEndpoint(t, s, "e-new", []string{"pilot"}, nil)
			checkinHW(t, s, "e-new", c.claim)
			if got := retired(t, s, "e-old"); got != c.retire {
				t.Errorf("retired=%v, want %v", got, c.retire)
			}
		})
	}
}

// Placeholder serials never identify a machine; the MAC decides only when
// both serials are placeholders.
func TestSameMachineSerials(t *testing.T) {
	for _, g := range []string{"", "   ", "0", "000000000000", "0000-0000", "FFFFFFFF", "ffff ffff", "123456789", "Invalid", "None",
		"Chassis Serial Number", "O.E.M.", "To be filled by O.E.M.", "Default string", "System Serial Number"} {
		if !genericSerial(g) {
			t.Errorf("%q not generic", g)
		}
	}
	for _, r := range []string{"PF3ABCDE", "VMware-56 4d 12", "5CG1234XYZ", "0001"} {
		if genericSerial(r) {
			t.Errorf("%q generic", r)
		}
	}
	mac := "aa:bb:cc:dd:ee:01"
	cases := []struct {
		a, b Hardware
		want bool
	}{
		{Hardware{SerialNumber: "PF3ABCDE"}, Hardware{SerialNumber: "pf3abcde "}, true},
		{Hardware{SerialNumber: "PF3ABCDE", MACAddress: mac}, Hardware{SerialNumber: "PF3XXXXX", MACAddress: mac}, false},
		{Hardware{SerialNumber: "PF3ABCDE", MACAddress: mac}, Hardware{SerialNumber: "0", MACAddress: mac}, false},
		{Hardware{SerialNumber: "Default string", MACAddress: mac}, Hardware{SerialNumber: "", MACAddress: strings.ToUpper(mac)}, true},
		{Hardware{SerialNumber: "Default string", MACAddress: mac}, Hardware{SerialNumber: "", MACAddress: "aa:bb:cc:dd:ee:02"}, false},
		{Hardware{SerialNumber: "0"}, Hardware{SerialNumber: "0"}, false},
	}
	for i, c := range cases {
		if sameMachine(c.a, c.b) != c.want {
			t.Errorf("%d: %+v / %+v: want %v", i, c.a, c.b, c.want)
		}
	}
}
