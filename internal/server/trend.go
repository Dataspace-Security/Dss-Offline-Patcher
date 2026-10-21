package server

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"offpatch/internal/store"
)

// Dashboard trend: one fleet_daily row per day, taken from the numbers
// /api/summary (refined endpoint statuses) and the compliance report
// (outstanding endpoint-patches by severity) show, so the history agrees
// with what the console showed that day.

const (
	trendDefaultDays = 30
	trendMaxDays     = store.FleetDailyKeepDays
	// FleetSnapshotEvery: how often today's row is refreshed at most, so a
	// finished day keeps (nearly) its end-of-day state.
	FleetSnapshotEvery = 15 * time.Minute
)

// fleetDayOf is the calendar day (server local time) of t.
func fleetDayOf(t time.Time) string { return t.Local().Format(store.FleetDayLayout) }

// SnapshotFleetDay writes today's fleet_daily row when it is missing or
// older than every (0: only when missing). It runs with every alert sweep
// (the first one at startup), so a day is recorded as soon as the server
// runs on it and keeps following the fleet until the day ends. It reports
// whether a snapshot was taken.
func (s *Server) SnapshotFleetDay(ctx context.Context, every time.Duration) (bool, error) {
	now := s.store.Now()
	day := fleetDayOf(now)
	at, err := s.store.FleetDayTakenAt(ctx, day)
	if err != nil {
		return false, err
	}
	if !at.IsZero() && (every <= 0 || now.Sub(at) < every) {
		return false, nil
	}
	d, err := s.fleetDay(ctx, day)
	if err != nil {
		return false, err
	}
	return true, s.store.PutFleetDay(ctx, d)
}

func (s *Server) fleetDay(ctx context.Context, day string) (store.FleetDay, error) {
	sm, err := s.honestSummary(ctx)
	if err != nil {
		return store.FleetDay{}, err
	}
	rep, err := s.store.Compliance(ctx, s.th)
	if err != nil {
		return store.FleetDay{}, err
	}
	done, failedDeps, err := s.store.DeploymentTotals(ctx)
	if err != nil {
		return store.FleetDay{}, err
	}
	by := sm.Endpoints.ByStatus
	return store.FleetDay{
		Day:               day,
		Endpoints:         sm.Endpoints.Total,
		Compliant:         by["compliant"],
		UpdatesAvailable:  by["updates_available"] + by["noncompliant"] + by["out_of_support"],
		Failed:            by["failed"] + by["lost_after_install"],
		Offline:           by["offline"] + by["stale"],
		CriticalMissing:   rep.BySeverity["critical"].Outstanding,
		ImportantMissing:  rep.BySeverity["important"].Outstanding,
		DeploymentsDone:   done,
		DeploymentsFailed: failedDeps,
	}, nil
}

// dashboardTrend: GET /api/dashboard/trend?days=N (1..400, default 30):
// the daily snapshots of the last N days including today, oldest first.
// Today's row is taken first when missing or stale, so a fresh install shows
// one point at once.
func (s *Server) dashboardTrend(w http.ResponseWriter, r *http.Request) {
	days := trendDefaultDays
	if v := r.URL.Query().Get("days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > trendMaxDays {
			writeErr(w, http.StatusBadRequest, "days must be a whole number from 1 to "+strconv.Itoa(trendMaxDays))
			return
		}
		days = n
	}
	ctx := r.Context()
	if _, err := s.SnapshotFleetDay(ctx, FleetSnapshotEvery); err != nil {
		s.fail(w, err)
		return
	}
	since := s.store.Now().Local().AddDate(0, 0, -(days - 1)).Format(store.FleetDayLayout)
	rows, err := s.store.ListFleetDays(ctx, since)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"days": days, "today": fleetDayOf(s.store.Now()), "rows": rows})
}
