package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

const acquisitionSchema = `
CREATE TABLE IF NOT EXISTS acquisition_reports(
  id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL, received_at TEXT NOT NULL, finished_at TEXT NOT NULL,
  outcome TEXT NOT NULL, key_id TEXT NOT NULL, report TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS acq_source ON acquisition_reports(source, id);
`

// AcqRecord is one received acquisition status report.
type AcqRecord struct {
	ID         int64           `json:"id"`
	Source     string          `json:"source"`
	ReceivedAt string          `json:"received_at"`
	FinishedAt string          `json:"finished_at"`
	Outcome    string          `json:"outcome"`
	KeyID      string          `json:"key_id"`
	Report     json.RawMessage `json:"report"`
}

// AcqSource summarises the latest report from one acquisition source.
type AcqSource struct {
	Source string    `json:"source"`
	Last   AcqRecord `json:"last"`
	Stale  bool      `json:"stale"` // no report within StaleAfter
	AgeHrs float64   `json:"age_hours"`
}

// Acquisition staleness defaults. The unattended run is hourly: on a single
// server its status report arrives within the hour, so three missed runs
// are stale. In a two-machine layout reports cross the one-way transfer
// when the operator carries files, so a day (plus slack) is the default.
const (
	DefaultAcqStaleAfter      = 26 * time.Hour
	SingleServerAcqStaleAfter = 3 * time.Hour
)

// AcqStale is the configured staleness threshold.
func (s *Store) AcqStale() time.Duration {
	if s.AcqStaleAfter > 0 {
		return s.AcqStaleAfter
	}
	return DefaultAcqStaleAfter
}

// RecordAcquisition stores a verified report and raises an alert when the
// run failed or partly failed.
func (s *Store) RecordAcquisition(ctx context.Context, source, finishedAt, outcome, keyID string, report []byte, summary string) error {
	return s.txChanged(ctx, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO acquisition_reports(source,received_at,finished_at,outcome,key_id,report) VALUES(?,?,?,?,?,?)`,
			source, s.now(), finishedAt, outcome, keyID, string(report)); err != nil {
			return err
		}
		if outcome != "ok" {
			sev := "warning"
			if outcome == "failed" {
				sev = "critical"
			}
			if err := s.raiseAlert(tx, sev, "acquisition_"+outcome, "acquisition", source, "acquisition run on "+source+" "+outcome+": "+summary); err != nil {
				return err
			}
		}
		return s.audit(tx, Ev{Actor: "system:intake", Action: "acquisition.status", ObjectType: "acquisition", ObjectID: source, Failure: outcome == "failed",
			Details: map[string]any{"outcome": outcome, "finished_at": finishedAt, "summary": summary}})
	})
}

func scanAcq(rows *sql.Rows) ([]AcqRecord, error) {
	out := []AcqRecord{}
	for rows.Next() {
		var r AcqRecord
		var rep string
		if err := rows.Scan(&r.ID, &r.Source, &r.ReceivedAt, &r.FinishedAt, &r.Outcome, &r.KeyID, &rep); err != nil {
			return nil, err
		}
		r.Report = json.RawMessage(rep)
		out = append(out, r)
	}
	return out, rows.Err()
}

// Acquisition returns the latest report per source and recent history.
func (s *Store) Acquisition(ctx context.Context, limit int) ([]AcqSource, []AcqRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,source,received_at,finished_at,outcome,key_id,report FROM acquisition_reports
		WHERE id IN (SELECT MAX(id) FROM acquisition_reports GROUP BY source) ORDER BY source`)
	if err != nil {
		return nil, nil, err
	}
	last, err := scanAcq(rows)
	rows.Close()
	if err != nil {
		return nil, nil, err
	}
	srcs := []AcqSource{}
	for _, r := range last {
		age := s.Now().Sub(parseTime(r.FinishedAt))
		if t, e := time.Parse(time.RFC3339, r.FinishedAt); e == nil {
			age = s.Now().Sub(t)
		}
		srcs = append(srcs, AcqSource{Source: r.Source, Last: r, Stale: age > s.AcqStale(), AgeHrs: float64(int(age.Hours()*10)) / 10})
	}
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err = s.db.QueryContext(ctx, `SELECT id,source,received_at,finished_at,outcome,key_id,report FROM acquisition_reports ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, nil, err
	}
	hist, err := scanAcq(rows)
	rows.Close()
	return srcs, hist, err
}

// sweepAcquisition alerts on sources that have gone silent.
func (s *Store) sweepAcquisition(ctx context.Context) error {
	srcs, _, err := s.Acquisition(ctx, 1)
	if err != nil {
		return err
	}
	stale := map[string]bool{}
	for _, a := range srcs {
		if a.Stale {
			stale[a.Source] = true
			if err := s.RaiseAlert(ctx, "warning", "acquisition_stale", "acquisition", a.Source,
				"no acquisition status from "+a.Source+" for "+itoa(int(a.AgeHrs))+" h — ask the acquisition team whether the scheduled acquisition run is working"); err != nil {
				return err
			}
		}
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		return s.resolveAlertsExcept(tx, "acquisition_stale", stale, "a fresh acquisition status report arrived")
	})
}
