package server

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"offpatch/internal/store"
)

// Every signed-in role reads the trend; days is bounded; the first read
// takes today's snapshot, and repeated snapshots the same day are no-ops.
func TestDashboardTrend(t *testing.T) {
	s := newRolesServer(t, "", false)
	h := s.Handler()
	for role, tok := range roleTokens {
		w := do(h, req{method: "GET", path: "/api/dashboard/trend?days=30", token: tok})
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", role, w.Code, w.Body)
		}
	}
	w := do(h, req{method: "GET", path: "/api/dashboard/trend"})
	if w.Code != 401 {
		t.Fatalf("anonymous: %d", w.Code)
	}
	for _, bad := range []string{"0", "-1", "401", "x", "1.5"} {
		w := do(h, req{method: "GET", path: "/api/dashboard/trend?days=" + bad, token: roleTokens["viewer"]})
		if w.Code != 400 {
			t.Errorf("days=%s: %d %s", bad, w.Code, w.Body)
		}
	}
	w = do(h, req{method: "GET", path: "/api/dashboard/trend?days=400", token: roleTokens["viewer"]})
	if w.Code != 200 {
		t.Fatalf("days=400: %d %s", w.Code, w.Body)
	}
	var res struct {
		Days  int              `json:"days"`
		Today string           `json:"today"`
		Rows  []store.FleetDay `json:"rows"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Days != 400 || len(res.Rows) != 1 || res.Rows[0].Day != res.Today {
		t.Fatalf("trend = %+v", res)
	}
	ctx := context.Background()
	if ok, err := s.SnapshotFleetDay(ctx, FleetSnapshotEvery); err != nil || ok {
		t.Fatalf("fresh snapshot retaken: taken=%v err=%v", ok, err)
	}
	// Later the same day the row is refreshed, still one row per day.
	base := s.store.Now
	s.store.Now = func() time.Time { return base().Add(FleetSnapshotEvery + time.Minute) }
	t.Cleanup(func() { s.store.Now = base })
	if ok, err := s.SnapshotFleetDay(ctx, FleetSnapshotEvery); err != nil || !ok {
		t.Fatalf("stale snapshot not refreshed: taken=%v err=%v", ok, err)
	}
	rows, err := s.store.ListFleetDays(ctx, "2000-01-01")
	if err != nil {
		t.Fatal(err)
	}
	days := map[string]bool{}
	for _, r := range rows {
		if days[r.Day] {
			t.Fatalf("two rows for %s", r.Day)
		}
		days[r.Day] = true
	}
}

// /api/me says default_password only while the stored hash is the built-in
// default: an admin created with its own password never gets the banner.
func TestMeDefaultPassword(t *testing.T) {
	s := newRolesServer(t, "", false)
	w := do(s.Handler(), req{method: "GET", path: "/api/me", token: roleTokens["super_admin"]})
	var me map[string]any
	json.Unmarshal(w.Body.Bytes(), &me)
	if w.Code != 200 || me["default_password"] != false {
		t.Fatalf("me: %d %v", w.Code, me)
	}
}
