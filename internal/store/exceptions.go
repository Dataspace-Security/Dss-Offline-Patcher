package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

type NewException struct {
	EndpointID           string `json:"endpoint_id"`
	PackageID            string `json:"package_id"`
	Owner                string `json:"owner"`
	Reason               string `json:"reason"`
	CompensatingControls string `json:"compensating_controls"`
	ExpiresAt            string `json:"expires_at"`
}

type Exception struct {
	NewException
	ExceptionID string `json:"exception_id"`
	CreatedBy   string `json:"created_by"`
	CreatedAt   string `json:"created_at"`
	Revoked     bool   `json:"revoked"`
	Active      bool   `json:"active"`
}

const excCols = `exception_id,endpoint_id,package_id,owner,reason,compensating_controls,expires_at,created_by,created_at,revoked`

func (s *Store) scanException(sc interface{ Scan(...any) error }) (Exception, error) {
	var x Exception
	var rv int
	err := sc.Scan(&x.ExceptionID, &x.EndpointID, &x.PackageID, &x.Owner, &x.Reason, &x.CompensatingControls, &x.ExpiresAt, &x.CreatedBy, &x.CreatedAt, &rv)
	x.Revoked = rv == 1
	x.Active = !x.Revoked && parseTime(x.ExpiresAt).After(s.Now())
	return x, err
}

func (s *Store) ListExceptions(ctx context.Context) ([]Exception, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+excCols+` FROM exceptions ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Exception{}
	for rows.Next() {
		x, err := s.scanException(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func (s *Store) CreateException(ctx context.Context, actor string, n NewException) (Exception, error) {
	var errs []string
	for k, v := range map[string]string{"endpoint_id": n.EndpointID, "owner": n.Owner, "reason": n.Reason, "compensating_controls": n.CompensatingControls} {
		if strings.TrimSpace(v) == "" {
			errs = append(errs, k+" required")
		}
	}
	exp, err := time.Parse(time.RFC3339, n.ExpiresAt)
	if err != nil {
		errs = append(errs, "expires_at must be RFC3339")
	} else if !exp.After(s.Now()) || exp.After(s.Now().AddDate(1, 0, 0)) {
		errs = append(errs, "expires_at must be in the future and within one year")
	}
	if len(errs) > 0 {
		return Exception{}, Errf(ErrInvalid, "%s", strings.Join(errs, "; "))
	}
	n.ExpiresAt = exp.UTC().Format(time.RFC3339Nano)
	var out Exception
	err = s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := getEndpoint(ctx, tx, n.EndpointID); err != nil {
			return err
		}
		if n.PackageID != "" {
			if _, err := getPackage(ctx, tx, n.PackageID); err != nil {
				return err
			}
		}
		id := NewID("x-")
		now := s.now()
		if _, err := tx.Exec(`INSERT INTO exceptions(`+excCols+`) VALUES(?,?,?,?,?,?,?,?,?,0)`,
			id, n.EndpointID, n.PackageID, n.Owner, n.Reason, n.CompensatingControls, n.ExpiresAt, actor, now); err != nil {
			return err
		}
		if err := s.audit(tx, Ev{Actor: actor, Action: "exception.created", ObjectType: "exception", ObjectID: id, PackageID: n.PackageID,
			Details: map[string]any{"endpoint_id": n.EndpointID, "owner": n.Owner, "reason": n.Reason, "compensating_controls": n.CompensatingControls, "expires_at": n.ExpiresAt}}); err != nil {
			return err
		}
		// Apply immediately to outstanding targets.
		where := `t.endpoint_id=? AND t.state IN ('pending','failed','deferred') AND d.state IN ('active','paused') AND d.operation='install'`
		args := []any{n.EndpointID}
		if n.PackageID != "" {
			where += ` AND t.package_id=?`
			args = append(args, n.PackageID)
		}
		ts, err := queryTargets(ctx, tx, where, args...)
		if err != nil {
			return err
		}
		for _, t := range ts {
			if err := s.setTarget(tx, actor, t, "exception", "covered by exception "+id, t.ExitCode, 0); err != nil {
				return err
			}
			if err := s.evaluateDeployment(ctx, tx, t.DeploymentID, false); err != nil {
				return err
			}
		}
		out, err = s.scanException(tx.QueryRowContext(ctx, `SELECT `+excCols+` FROM exceptions WHERE exception_id=?`, id))
		return err
	})
	return out, err
}

func (s *Store) RevokeException(ctx context.Context, actor, id, reason string) (Exception, error) {
	if err := requireReason(reason); err != nil {
		return Exception{}, err
	}
	var out Exception
	err := s.tx(ctx, func(tx *sql.Tx) error {
		x, err := s.scanException(tx.QueryRowContext(ctx, `SELECT `+excCols+` FROM exceptions WHERE exception_id=?`, id))
		if errors.Is(err, sql.ErrNoRows) {
			return Errf(ErrNotFound, "exception %s", id)
		}
		if err != nil {
			return err
		}
		if x.Revoked {
			return Errf(ErrConflict, "already revoked")
		}
		if _, err := tx.Exec(`UPDATE exceptions SET revoked=1, revoked_reason=? WHERE exception_id=?`, reason, id); err != nil {
			return err
		}
		if err := s.audit(tx, Ev{Actor: actor, Action: "exception.revoked", ObjectType: "exception", ObjectID: id, PackageID: x.PackageID,
			Details: map[string]any{"reason": reason, "endpoint_id": x.EndpointID}}); err != nil {
			return err
		}
		ts, err := queryTargets(ctx, tx, `t.endpoint_id=? AND t.state='exception' AND d.state IN ('active','paused')`, x.EndpointID)
		if err != nil {
			return err
		}
		for _, t := range ts {
			other, err := s.activeException(ctx, tx, t.EndpointID, t.PackageID)
			if err != nil {
				return err
			}
			if other == "" {
				if err := s.setTarget(tx, actor, t, "pending", "exception "+id+" revoked", 0, 0); err != nil {
					return err
				}
			}
		}
		out, err = s.scanException(tx.QueryRowContext(ctx, `SELECT `+excCols+` FROM exceptions WHERE exception_id=?`, id))
		return err
	})
	return out, err
}

func (s *Store) ExceptionsForPackage(ctx context.Context, packageID string) ([]Exception, error) {
	all, err := s.ListExceptions(ctx)
	if err != nil {
		return nil, err
	}
	out := []Exception{}
	for _, x := range all {
		if x.PackageID == packageID || x.PackageID == "" {
			out = append(out, x)
		}
	}
	return out, nil
}

// ---- summary ----

type Summary struct {
	Endpoints struct {
		Total    int            `json:"total"`
		Retired  int            `json:"retired"`
		ByStatus map[string]int `json:"by_status"`
	} `json:"endpoints"`
	Packages         map[string]int `json:"packages"`
	Bundles          map[string]int `json:"bundles"`
	Deployments      map[string]int `json:"deployments"`
	ActiveExceptions int            `json:"active_exceptions"`
	Audit            struct {
		OK    bool  `json:"ok"`
		Count int64 `json:"count"`
	} `json:"audit"`
}

func (s *Store) Summary(ctx context.Context, th Thresholds) (Summary, error) {
	var sm Summary
	sm.Endpoints.ByStatus = map[string]int{}
	for _, k := range []string{"compliant", "noncompliant", "pending_reboot", "failed", "exception", "stale", "offline", "lost_after_install"} {
		sm.Endpoints.ByStatus[k] = 0
	}
	eps, err := s.ListEndpoints(ctx, th)
	if err != nil {
		return sm, err
	}
	for _, e := range eps {
		if e.Status == "retired" {
			sm.Endpoints.Retired++
			continue
		}
		sm.Endpoints.Total++
		sm.Endpoints.ByStatus[e.Status]++
	}
	count := func(table string, keys ...string) (map[string]int, error) {
		m := map[string]int{}
		for _, k := range keys {
			m[k] = 0
		}
		rows, err := s.db.QueryContext(ctx, `SELECT state, COUNT(*) FROM `+table+` GROUP BY state`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var k string
			var n int
			rows.Scan(&k, &n)
			m[k] = n
		}
		return m, rows.Err()
	}
	if sm.Packages, err = count("packages", "quarantined", "approved", "rejected", "revoked"); err != nil {
		return sm, err
	}
	if sm.Bundles, err = count("bundles", "received", "validated", "rejected"); err != nil {
		return sm, err
	}
	if sm.Deployments, err = count("deployments", "active", "paused", "cancelled", "completed"); err != nil {
		return sm, err
	}
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM exceptions WHERE revoked=0 AND expires_at > ?`, s.now()).Scan(&sm.ActiveExceptions)
	cr, err := s.VerifyAudit(ctx)
	if err != nil {
		return sm, err
	}
	sm.Audit.OK, sm.Audit.Count = cr.OK, cr.Count
	return sm, nil
}
