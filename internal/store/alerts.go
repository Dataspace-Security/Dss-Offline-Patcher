package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"time"
)

const alertsSchema = `
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, severity TEXT NOT NULL, kind TEXT NOT NULL,
  message TEXT NOT NULL, object_type TEXT NOT NULL, object_id TEXT NOT NULL,
  acknowledged_by TEXT NOT NULL DEFAULT '', acknowledged_at TEXT NOT NULL DEFAULT '', delivered INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS alerts_open ON alerts(kind, object_id, acknowledged_at);
`

// Alert is raised inside the isolated zone and delivered to the console and,
// optionally, an internal mail relay or SIEM webhook. No reverse path out of
// the zone is ever opened for alerting.
type Alert struct {
	ID             int64  `json:"id"`
	CreatedAt      string `json:"created_at"`
	Severity       string `json:"severity"` // info | warning | critical
	Kind           string `json:"kind"`
	Message        string `json:"message"`
	ObjectType     string `json:"object_type"`
	ObjectID       string `json:"object_id"`
	AcknowledgedBy string `json:"acknowledged_by"`
	AcknowledgedAt string `json:"acknowledged_at"`
	// Details: structured context, e.g. endpoint_ids for alerts that name
	// hosts. ResolvedAt: the condition cleared and the alert closed itself
	// (acknowledged_by is then system:scheduler).
	Details    map[string]any `json:"details,omitempty"`
	ResolvedAt string         `json:"resolved_at,omitempty"`
	ResolvedBy string         `json:"resolved_by,omitempty"`
}

const alertCols = `id,created_at,severity,kind,message,object_type,object_id,acknowledged_by,acknowledged_at,details,resolved_at`

func scanAlert(sc interface{ Scan(...any) error }) (Alert, error) {
	var a Alert
	var det string
	if err := sc.Scan(&a.ID, &a.CreatedAt, &a.Severity, &a.Kind, &a.Message, &a.ObjectType, &a.ObjectID, &a.AcknowledgedBy, &a.AcknowledgedAt, &det, &a.ResolvedAt); err != nil {
		return a, err
	}
	if det != "" && det != "{}" {
		json.Unmarshal([]byte(det), &a.Details)
	}
	if a.ResolvedAt != "" {
		a.ResolvedBy = a.AcknowledgedBy
	}
	return a, nil
}

// raiseAlert records an alert unless an identical one (kind+object) is
// still open, so a flapping condition does not flood operators.
func (s *Store) raiseAlert(tx *sql.Tx, severity, kind, objectType, objectID, message string) error {
	return s.raiseAlertWith(tx, severity, kind, objectType, objectID, message, nil)
}

// raiseAlertWith is raiseAlert with structured details (e.g. endpoint_ids).
func (s *Store) raiseAlertWith(tx *sql.Tx, severity, kind, objectType, objectID, message string, details map[string]any) error {
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM alerts WHERE kind=? AND object_id=? AND acknowledged_at=''`, kind, objectID).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	return s.addAlert(tx, severity, kind, objectType, objectID, message, details)
}

// addAlert records an alert for an event (not a condition): every
// occurrence counts, so no deduplication against open alerts.
func (s *Store) addAlert(tx *sql.Tx, severity, kind, objectType, objectID, message string, details map[string]any) error {
	det := "{}"
	if details != nil {
		det = mustJSON(details)
	}
	_, err := tx.Exec(`INSERT INTO alerts(created_at,severity,kind,message,object_type,object_id,details) VALUES(?,?,?,?,?,?,?)`, s.now(), severity, kind, message, objectType, objectID, det)
	return err
}

// RaiseAlert is the non-transactional form (used by background sweeps).
func (s *Store) RaiseAlert(ctx context.Context, severity, kind, objectType, objectID, message string) error {
	return s.tx(ctx, func(tx *sql.Tx) error { return s.raiseAlert(tx, severity, kind, objectType, objectID, message) })
}

func (s *Store) ListAlerts(ctx context.Context, openOnly bool) ([]Alert, error) {
	q := `SELECT ` + alertCols + ` FROM alerts`
	if openOnly {
		q += ` WHERE acknowledged_at=''`
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY id DESC LIMIT 500`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Alert{}
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) AckAlert(ctx context.Context, actor string, id int64, note string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var kind, ack string
		err := tx.QueryRow(`SELECT kind, acknowledged_at FROM alerts WHERE id=?`, id).Scan(&kind, &ack)
		if errors.Is(err, sql.ErrNoRows) {
			return Errf(ErrNotFound, "alert %d", id)
		}
		if err != nil {
			return err
		}
		if ack != "" {
			return Errf(ErrConflict, "already acknowledged")
		}
		if _, err := tx.Exec(`UPDATE alerts SET acknowledged_by=?, acknowledged_at=? WHERE id=?`, actor, s.now(), id); err != nil {
			return err
		}
		return s.audit(tx, Ev{Actor: actor, Action: "alert.acknowledged", ObjectType: "alert", ObjectID: kind, Details: map[string]any{"alert_id": id, "note": note}})
	})
}

// UndeliveredAlerts / MarkDelivered support external notification.
func (s *Store) UndeliveredAlerts(ctx context.Context) ([]Alert, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+alertCols+` FROM alerts WHERE delivered=0 ORDER BY id LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) MarkDelivered(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE alerts SET delivered=1 WHERE id=?`, id)
	return err
}

// SweepAlerts raises time-based alerts: endpoints lost after an install
// (which may auto-pause their deployment), installs inventory never
// confirmed, offline endpoints, stale inventory, exceptions expiring within
// a week, and certificates near expiry. Condition alerts name their hosts
// and close themselves once the condition clears (alerts_condition.go).
func (s *Store) SweepAlerts(ctx context.Context, th Thresholds) error {
	if err := s.sweepLost(ctx, th.LostAfterInstall); err != nil {
		return err
	}
	if err := s.sweepStuck(ctx, th.StuckAfter); err != nil {
		return err
	}
	if err := s.sweepAcquisition(ctx); err != nil {
		return err
	}
	if err := s.sweepDeployments(ctx); err != nil {
		return err
	}
	if err := s.sweepUnverified(ctx); err != nil {
		return err
	}
	if err := s.sweepResolved(ctx); err != nil {
		return err
	}
	eps, err := s.ListEndpointsBrief(ctx, th)
	if err != nil {
		return err
	}
	var offline, stale []HostRef
	for _, e := range eps {
		switch e.Status {
		case "offline", "lost_after_install": // lost endpoints are offline too
			offline = append(offline, HostRef{e.EndpointID, e.Hostname})
		case "stale":
			stale = append(stale, HostRef{e.EndpointID, e.Hostname})
		}
	}
	if err := s.SetHostAlert(ctx, "warning", "endpoints_offline", "fleet", "offline",
		itoa(len(offline))+" endpoint(s) have not checked in recently and are NOT counted as compliant", offline, "every endpoint checked in again (or was retired)"); err != nil {
		return err
	}
	if err := s.SetHostAlert(ctx, "warning", "inventory_stale", "fleet", "stale",
		itoa(len(stale))+" endpoint(s) have stale inventory", stale, "every endpoint reported fresh inventory (or was retired)"); err != nil {
		return err
	}
	expiring := map[string]bool{}
	for _, e := range eps {
		if e.Status != "retired" && e.CertNotAfter != "" && parseTime(e.CertNotAfter).Before(s.Now().Add(14*24*time.Hour)) {
			expiring[e.EndpointID] = true
			det, _ := hostDetails([]HostRef{{e.EndpointID, e.Hostname}})
			if err := s.SetConditionAlert(ctx, "warning", "cert_expiring", "endpoint", e.EndpointID,
				e.Hostname+": client certificate expires "+e.CertNotAfter[:10]+" and has not been renewed (agent offline?)", det); err != nil {
				return err
			}
		}
	}
	if err := s.tx(ctx, func(tx *sql.Tx) error {
		return s.resolveAlertsExcept(tx, "cert_expiring", expiring, "the client certificate was renewed (or the endpoint retired)")
	}); err != nil {
		return err
	}
	xs, err := s.ListExceptions(ctx)
	if err != nil {
		return err
	}
	soon := s.Now().Add(7 * 24 * time.Hour)
	for _, x := range xs {
		if x.Active && parseTime(x.ExpiresAt).Before(soon) {
			if err := s.RaiseAlert(ctx, "info", "exception_expiring", "exception", x.ExceptionID,
				"exception "+x.ExceptionID+" (owner "+x.Owner+") expires "+x.ExpiresAt[:10]+"; review or renew"); err != nil {
				return err
			}
		}
	}
	return nil
}

func itoa(n int) string { return strconv.Itoa(n) }
