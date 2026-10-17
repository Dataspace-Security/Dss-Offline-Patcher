package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"
)

// RetryFailed gives the failed targets whose retries are exhausted, in
// every ring up to the deployment's current ring, a fresh set of attempts
// (state pending, attempts 0). The deployment must be active, paused or
// completed: a paused one stays paused until an operator resumes it; a
// completed one becomes active again (state_reason says who retried it and
// why). Audited as deployment.retry_failed with the list of targets.
func (s *Store) RetryFailed(ctx context.Context, actor, id, reason string) (Deployment, error) {
	if err := requireReason(reason); err != nil {
		return Deployment{}, err
	}
	var out Deployment
	err := s.txChanged(ctx, func(tx *sql.Tx) error {
		d, err := getDeploymentCounted(ctx, tx, id)
		if err != nil {
			return err
		}
		if d.State != "active" && d.State != "paused" && d.State != "completed" {
			return Errf(ErrConflict, "only failed targets of an active, paused or completed deployment can be retried (this one is %s)", d.State)
		}
		if d.State == "completed" && d.Operation != "rollback" {
			p, err := getPackage(ctx, tx, d.PackageID)
			if err != nil {
				return err
			}
			if p.State != "approved" {
				return Errf(ErrConflict, "package %s is %s; a completed deployment can only be retried while its package is approved", d.PackageID, p.State)
			}
		}
		ts, err := queryTargets(ctx, tx, `t.deployment_id=? AND t.ring <= ? AND t.state='failed' AND t.attempts > ?`, id, d.CurrentRing, d.MaxRetries)
		if err != nil {
			return err
		}
		if len(ts) == 0 {
			return Errf(ErrConflict, "nothing to retry: no failed targets with exhausted retries (attempts > %d) in rings up to the current ring %q", d.MaxRetries, d.Rings[d.CurrentRing].Name)
		}
		now := s.now()
		why := "retry requested by " + strings.TrimPrefix(actor, "user:") + ": " + reason
		list := make([]map[string]any, 0, len(ts))
		for _, t := range ts {
			if _, err := tx.Exec(`UPDATE targets SET state='pending', attempts=0, leased_until='', detail=?, updated_at=? WHERE deployment_id=? AND endpoint_id=?`,
				why, now, id, t.EndpointID); err != nil {
				return err
			}
			list = append(list, map[string]any{"endpoint_id": t.EndpointID, "hostname": t.Hostname, "ring": t.Ring, "attempts": t.Attempts, "detail": t.Detail, "exit_code": t.ExitCode})
		}
		// updated_at: endpoints in the deployment pick the retry up quickly (next_checkin_seconds).
		if d.State == "completed" {
			if _, err := tx.Exec(`UPDATE deployments SET state='active', state_reason=?, updated_at=? WHERE deployment_id=?`, why, now, id); err != nil {
				return err
			}
		} else if _, err := tx.Exec(`UPDATE deployments SET updated_at=? WHERE deployment_id=?`, now, id); err != nil {
			return err
		}
		if err := s.audit(tx, Ev{Actor: actor, Action: "deployment.retry_failed", ObjectType: "deployment", ObjectID: id, PackageID: d.PackageID,
			Details: map[string]any{"reason": reason, "ring": d.CurrentRing, "ring_name": d.Rings[d.CurrentRing].Name, "state": d.State, "targets": list}}); err != nil {
			return err
		}
		// The failure threshold is checked as after any failure: what is
		// still failing (health checks, lost after install) can pause it again.
		if err := s.evaluateDeployment(ctx, tx, id, true); err != nil {
			return err
		}
		out, err = getDeploymentCounted(ctx, tx, id)
		return err
	})
	return out, err
}

// HasTarget reports whether the endpoint has a target in the deployment
// for the package (live progress is only kept for real targets).
func (s *Store) HasTarget(ctx context.Context, endpointID, deploymentID, packageID string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM targets WHERE endpoint_id=? AND deployment_id=? AND package_id=?`, endpointID, deploymentID, packageID).Scan(&n)
	return n > 0, err
}

// Fast pickup (CheckinResult.next_checkin_seconds).
const (
	FastCheckinSeconds = 10
	fastPickupAfter    = 2 * time.Minute
	// fastInstalledFor bounds fast check-ins for a target stuck in
	// "installed" (waiting on verification that does not come): after this
	// long without a state change the endpoint goes back to its interval.
	fastInstalledFor = 10 * time.Minute
)

// nextCheckin: FastCheckinSeconds while the endpoint has work it can act on
// now — an assignment handed out in this check-in, a target in progress
// (downloading..installing, or installed for less than fastInstalledFor), a
// reboot requested in this check-in (rebootNow: the reboot throttle has
// elapsed) — or when an active deployment covering its groups was created,
// advanced, resumed or retried in the last fastPickupAfter. Otherwise 0 (the
// configured interval). Runs inside the check-in transaction: it only reads
// deployments updated recently.
func (s *Store) nextCheckin(ctx context.Context, tx *sql.Tx, e Endpoint, assigned int, rebootNow bool) (int, error) {
	if assigned > 0 || rebootNow {
		return FastCheckinSeconds, nil
	}
	now := s.Now()
	var busy int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM targets t JOIN deployments d ON d.deployment_id=t.deployment_id
		WHERE t.endpoint_id=? AND d.state='active' AND t.ring <= d.current_ring
		AND (t.state IN ('downloading','downloaded','installing') OR (t.state='installed' AND t.updated_at >= ?))`,
		e.EndpointID, now.Add(-fastInstalledFor).UTC().Format(time.RFC3339Nano)).Scan(&busy); err != nil {
		return 0, err
	}
	if busy > 0 {
		return FastCheckinSeconds, nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT rings FROM deployments WHERE state='active' AND updated_at >= ?`,
		now.Add(-fastPickupAfter).UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return 0, err
		}
		var rings []Ring
		if json.Unmarshal([]byte(raw), &rings) == nil && ringFor(rings, e.Groups, e.EndpointID) >= 0 {
			return FastCheckinSeconds, nil
		}
	}
	return 0, rows.Err()
}
