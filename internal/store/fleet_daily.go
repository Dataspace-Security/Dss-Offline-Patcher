package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Daily fleet history for the Overview trend charts: one row per calendar
// day, from the same numbers /api/summary and the compliance report show.
// Today's row is refreshed during the day (the server throttles that), so
// a finished day keeps its last snapshot, the state at the end of the day.
// Rows older than FleetDailyKeepDays are pruned whenever a row is written.
const fleetDailySchema = `CREATE TABLE IF NOT EXISTS fleet_daily(
  day TEXT PRIMARY KEY, endpoints INTEGER NOT NULL, compliant INTEGER NOT NULL,
  updates_available INTEGER NOT NULL, failed INTEGER NOT NULL, offline INTEGER NOT NULL,
  critical_missing INTEGER NOT NULL, important_missing INTEGER NOT NULL,
  deployments_done INTEGER NOT NULL, deployments_failed INTEGER NOT NULL, taken_at TEXT NOT NULL)`

// FleetDailyKeepDays: how much history is kept (a bit over a year, so a
// year-on-year comparison is possible).
const FleetDailyKeepDays = 400

// FleetDayLayout is the format of FleetDay.Day.
const FleetDayLayout = "2006-01-02"

// FleetDay is one day of fleet history. Endpoint counts are the refined
// statuses of non-retired endpoints at the snapshot; *_missing are
// endpoint-patches of catalog packages still outstanding; deployments_*
// are running totals (completed deployments, deployments with a failed
// target).
type FleetDay struct {
	Day               string `json:"day"`
	Endpoints         int    `json:"endpoints"`
	Compliant         int    `json:"compliant"`
	UpdatesAvailable  int    `json:"updates_available"`
	Failed            int    `json:"failed"`
	Offline           int    `json:"offline"`
	CriticalMissing   int    `json:"critical_missing"`
	ImportantMissing  int    `json:"important_missing"`
	DeploymentsDone   int    `json:"deployments_done"`
	DeploymentsFailed int    `json:"deployments_failed"`
	TakenAt           string `json:"taken_at"`
}

// FleetDayTakenAt returns when day's (FleetDayLayout) snapshot was taken
// (zero time: no snapshot yet).
func (s *Store) FleetDayTakenAt(ctx context.Context, day string) (time.Time, error) {
	var at string
	err := s.db.QueryRowContext(ctx, `SELECT taken_at FROM fleet_daily WHERE day=?`, day).Scan(&at)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	t, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return time.Time{}, nil // unreadable: take a new one
	}
	return t, nil
}

// PutFleetDay stores d as the snapshot of its day, replacing an earlier one
// of the same day (one row per day), and prunes rows older than
// FleetDailyKeepDays before d.Day.
func (s *Store) PutFleetDay(ctx context.Context, d FleetDay) error {
	day, err := time.Parse(FleetDayLayout, d.Day)
	if err != nil {
		return Errf(ErrInvalid, "fleet day %q: want YYYY-MM-DD", d.Day)
	}
	cutoff := day.AddDate(0, 0, -FleetDailyKeepDays).Format(FleetDayLayout)
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO fleet_daily(day, endpoints, compliant, updates_available, failed, offline,
		  critical_missing, important_missing, deployments_done, deployments_failed, taken_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)
		  ON CONFLICT(day) DO UPDATE SET endpoints=excluded.endpoints, compliant=excluded.compliant,
		  updates_available=excluded.updates_available, failed=excluded.failed, offline=excluded.offline,
		  critical_missing=excluded.critical_missing, important_missing=excluded.important_missing,
		  deployments_done=excluded.deployments_done, deployments_failed=excluded.deployments_failed, taken_at=excluded.taken_at`,
			d.Day, d.Endpoints, d.Compliant, d.UpdatesAvailable, d.Failed, d.Offline,
			d.CriticalMissing, d.ImportantMissing, d.DeploymentsDone, d.DeploymentsFailed, s.now()); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM fleet_daily WHERE day < ?`, cutoff)
		return err
	})
}

// ListFleetDays returns the snapshots from day since (inclusive,
// FleetDayLayout) on, oldest first.
func (s *Store) ListFleetDays(ctx context.Context, since string) ([]FleetDay, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT day, endpoints, compliant, updates_available, failed, offline,
	  critical_missing, important_missing, deployments_done, deployments_failed, taken_at
	  FROM fleet_daily WHERE day >= ? ORDER BY day`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FleetDay{}
	for rows.Next() {
		var d FleetDay
		if err := rows.Scan(&d.Day, &d.Endpoints, &d.Compliant, &d.UpdatesAvailable, &d.Failed, &d.Offline,
			&d.CriticalMissing, &d.ImportantMissing, &d.DeploymentsDone, &d.DeploymentsFailed, &d.TakenAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DeploymentTotals counts completed deployments and deployments (not
// cancelled) with a failed or lost target: running totals for FleetDay.
func (s *Store) DeploymentTotals(ctx context.Context) (done, failed int, err error) {
	if err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM deployments WHERE state='completed'`).Scan(&done); err != nil {
		return 0, 0, err
	}
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT t.deployment_id) FROM targets t JOIN deployments d ON d.deployment_id=t.deployment_id
	  WHERE d.state != 'cancelled' AND t.state IN ('failed','lost_after_install')`).Scan(&failed)
	return done, failed, err
}
