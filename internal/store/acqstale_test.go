package store

import (
	"context"
	"testing"
	"time"
)

// Hourly acquisition: with the single-server threshold a source is stale
// after three missed runs; the default (two-machine) threshold is 26 h.
func TestAcquisitionStaleThreshold(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	finished := time.Date(2026, 10, 18, 6, 0, 0, 0, time.UTC)
	if err := s.RecordAcquisition(ctx, "acq-zone-1", finished.Format(time.RFC3339), "ok", "k", []byte(`{}`), "ok"); err != nil {
		t.Fatal(err)
	}
	stale := func(after time.Duration, age time.Duration) bool {
		t.Helper()
		s.AcqStaleAfter = after
		s.Now = func() time.Time { return finished.Add(age) }
		srcs, _, err := s.Acquisition(ctx, 1)
		if err != nil || len(srcs) != 1 {
			t.Fatalf("sources: %v %v", srcs, err)
		}
		return srcs[0].Stale
	}
	for _, c := range []struct {
		after, age time.Duration
		want       bool
	}{
		{SingleServerAcqStaleAfter, 2 * time.Hour, false},
		{SingleServerAcqStaleAfter, 3*time.Hour + time.Minute, true},
		{0, 25 * time.Hour, false}, // 0 = DefaultAcqStaleAfter
		{0, 27 * time.Hour, true},
	} {
		if got := stale(c.after, c.age); got != c.want {
			t.Errorf("threshold %v, age %v: stale = %v, want %v", c.after, c.age, got, c.want)
		}
	}
}
