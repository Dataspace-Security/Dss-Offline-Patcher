package store

import (
	"context"
	"testing"
	"time"
)

// One row per day: a second snapshot the same day replaces the first.
func TestFleetDayOnePerDay(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if at, err := s.FleetDayTakenAt(ctx, "2026-10-20"); err != nil || !at.IsZero() {
		t.Fatalf("taken at before any snapshot: %v %v", at, err)
	}
	first := FleetDay{Day: "2026-10-20", Endpoints: 3, Compliant: 2, CriticalMissing: 4}
	if err := s.PutFleetDay(ctx, first); err != nil {
		t.Fatal(err)
	}
	again := first
	again.Compliant, again.CriticalMissing = 3, 0
	if err := s.PutFleetDay(ctx, again); err != nil {
		t.Fatal(err)
	}
	if at, err := s.FleetDayTakenAt(ctx, "2026-10-20"); err != nil || at.IsZero() {
		t.Fatalf("taken at: %v %v", at, err)
	}
	rows, err := s.ListFleetDays(ctx, "2026-01-01")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Compliant != 3 || rows[0].CriticalMissing != 0 || rows[0].TakenAt == "" {
		t.Fatalf("rows = %+v", rows)
	}
	if err := s.PutFleetDay(ctx, FleetDay{Day: "20-10-2026"}); err == nil {
		t.Fatal("bad day accepted")
	}
}

// Rows older than FleetDailyKeepDays are pruned when a day is written;
// ListFleetDays returns oldest first from the given day.
func TestFleetDayRetention(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	today := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	old := today.AddDate(0, 0, -FleetDailyKeepDays-1).Format(FleetDayLayout)
	edge := today.AddDate(0, 0, -FleetDailyKeepDays).Format(FleetDayLayout)
	for _, d := range []string{old, edge, "2026-10-19", today.Format(FleetDayLayout)} {
		if err := s.PutFleetDay(ctx, FleetDay{Day: d}); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := s.ListFleetDays(ctx, "2000-01-01")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range rows {
		got = append(got, r.Day)
	}
	want := []string{edge, "2026-10-19", "2026-10-21"}
	if len(got) != len(want) {
		t.Fatalf("days = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("days = %v, want %v", got, want)
		}
	}
	recent, _ := s.ListFleetDays(ctx, "2026-10-20")
	if len(recent) != 1 || recent[0].Day != "2026-10-21" {
		t.Fatalf("since 2026-10-20: %+v", recent)
	}
}
