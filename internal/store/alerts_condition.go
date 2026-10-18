package store

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Condition alerts (docs/03-state-model.md "Alerts"): an alert that
// describes a condition (endpoints offline, inventory stale, an install
// that never verified, intelligence too old, ...) names the hosts it is
// about and closes itself when the condition clears. While it is open, a
// changed host list updates the message and details in place (no new
// alert, no second notification). Closing is done by the sweep (actor
// system:scheduler) and audited as alert.resolved.

// maxAlertHosts is how many hostnames an alert message lists before "+N more".
const maxAlertHosts = 5

// HostList renders hostnames for an alert message: up to five, sorted,
// then "+N more".
func HostList(hosts []string) string {
	hs := append([]string(nil), hosts...)
	sort.Strings(hs)
	if len(hs) <= maxAlertHosts {
		return strings.Join(hs, ", ")
	}
	return strings.Join(hs[:maxAlertHosts], ", ") + fmt.Sprintf(" +%d more", len(hs)-maxAlertHosts)
}

// HostRef is an endpoint named by an alert.
type HostRef struct{ EndpointID, Hostname string }

// hostDetails is the details object of an alert about endpoints:
// endpoint_ids (all of them, sorted by hostname) and hostnames.
func hostDetails(hosts []HostRef) (map[string]any, string) {
	hs := append([]HostRef(nil), hosts...)
	sort.Slice(hs, func(i, j int) bool {
		if hs[i].Hostname != hs[j].Hostname {
			return hs[i].Hostname < hs[j].Hostname
		}
		return hs[i].EndpointID < hs[j].EndpointID
	})
	ids, names := make([]string, 0, len(hs)), make([]string, 0, len(hs))
	for _, h := range hs {
		ids = append(ids, h.EndpointID)
		names = append(names, h.Hostname)
	}
	return map[string]any{"endpoint_ids": ids, "hostnames": names}, HostList(names)
}

// conditionAlert raises an alert, or updates the open one of the same kind
// and object (message and details only; it is not delivered again).
func (s *Store) conditionAlert(tx *sql.Tx, severity, kind, objectType, objectID, message string, details map[string]any) error {
	det := "{}"
	if details != nil {
		det = mustJSON(details)
	}
	res, err := tx.Exec(`UPDATE alerts SET message=?, details=? WHERE kind=? AND object_id=? AND acknowledged_at='' AND (message != ? OR details != ?)`,
		message, det, kind, objectID, message, det)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	var open int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM alerts WHERE kind=? AND object_id=? AND acknowledged_at=''`, kind, objectID).Scan(&open); err != nil {
		return err
	}
	if open > 0 {
		return nil // unchanged
	}
	_, err = tx.Exec(`INSERT INTO alerts(created_at,severity,kind,message,object_type,object_id,details) VALUES(?,?,?,?,?,?,?)`,
		s.now(), severity, kind, message, objectType, objectID, det)
	return err
}

// hostAlert is a condition alert about endpoints: the message is
// "<prefix>: <hosts>" and details carry endpoint_ids.
func (s *Store) hostAlert(tx *sql.Tx, severity, kind, objectType, objectID, prefix string, hosts []HostRef) error {
	det, list := hostDetails(hosts)
	return s.conditionAlert(tx, severity, kind, objectType, objectID, prefix+": "+list, det)
}

// resolveAlert closes the open alerts of kind for objectID (every object
// when objectID is "") because the condition cleared.
func (s *Store) resolveAlert(tx *sql.Tx, kind, objectID, why string) error {
	q, args := `SELECT id, object_id FROM alerts WHERE kind=? AND acknowledged_at=''`, []any{kind}
	if objectID != "" {
		q += ` AND object_id=?`
		args = append(args, objectID)
	}
	rows, err := tx.Query(q, args...)
	if err != nil {
		return err
	}
	type open struct {
		id  int64
		obj string
	}
	var opens []open
	for rows.Next() {
		var o open
		if err := rows.Scan(&o.id, &o.obj); err != nil {
			rows.Close()
			return err
		}
		opens = append(opens, o)
	}
	rows.Close()
	now := s.now()
	for _, o := range opens {
		if _, err := tx.Exec(`UPDATE alerts SET acknowledged_by='system:scheduler', acknowledged_at=?, resolved_at=? WHERE id=? AND acknowledged_at=''`, now, now, o.id); err != nil {
			return err
		}
		if err := s.audit(tx, Ev{Actor: "system:scheduler", Action: "alert.resolved", ObjectType: "alert", ObjectID: kind,
			Details: map[string]any{"alert_id": o.id, "object_id": o.obj, "reason": why}}); err != nil {
			return err
		}
	}
	return nil
}

// resolveAlertsExcept closes open alerts of kind whose object is not in keep.
func (s *Store) resolveAlertsExcept(tx *sql.Tx, kind string, keep map[string]bool, why string) error {
	rows, err := tx.Query(`SELECT DISTINCT object_id FROM alerts WHERE kind=? AND acknowledged_at=''`, kind)
	if err != nil {
		return err
	}
	var gone []string
	for rows.Next() {
		var o string
		if err := rows.Scan(&o); err != nil {
			rows.Close()
			return err
		}
		if !keep[o] {
			gone = append(gone, o)
		}
	}
	rows.Close()
	for _, o := range gone {
		if err := s.resolveAlert(tx, kind, o, why); err != nil {
			return err
		}
	}
	return nil
}

// SetHostAlert raises or updates a condition alert naming endpoints (used
// by server-side sweeps that need update intelligence, e.g. out_of_support).
// With no hosts the open alert is resolved instead.
func (s *Store) SetHostAlert(ctx context.Context, severity, kind, objectType, objectID, prefix string, hosts []HostRef, resolveWhy string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if len(hosts) == 0 {
			return s.resolveAlert(tx, kind, objectID, resolveWhy)
		}
		return s.hostAlert(tx, severity, kind, objectType, objectID, prefix, hosts)
	})
}

// SetConditionAlert raises or updates a condition alert without hosts.
func (s *Store) SetConditionAlert(ctx context.Context, severity, kind, objectType, objectID, message string, details map[string]any) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		return s.conditionAlert(tx, severity, kind, objectType, objectID, message, details)
	})
}

// ResolveAlert closes open alerts of kind (and objectID, unless "") because
// the condition cleared.
func (s *Store) ResolveAlert(ctx context.Context, kind, objectID, why string) error {
	return s.tx(ctx, func(tx *sql.Tx) error { return s.resolveAlert(tx, kind, objectID, why) })
}

// sweepResolved closes target and deployment alerts whose condition
// cleared: an install failure on a target that has verified since, and
// endpoints lost after an install that all came back.
func (s *Store) sweepResolved(ctx context.Context) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT DISTINCT a.object_id FROM alerts a JOIN targets t ON a.object_id = t.deployment_id || '/' || t.endpoint_id
			WHERE a.kind='install_failed' AND a.acknowledged_at='' AND t.state='verified'`)
		if err != nil {
			return err
		}
		var fixed []string
		for rows.Next() {
			var o string
			if err := rows.Scan(&o); err != nil {
				rows.Close()
				return err
			}
			fixed = append(fixed, o)
		}
		rows.Close()
		for _, o := range fixed {
			if err := s.resolveAlert(tx, "install_failed", o, "the target has verified since"); err != nil {
				return err
			}
		}
		rows, err = tx.QueryContext(ctx, `SELECT DISTINCT a.object_id FROM alerts a WHERE a.kind='lost_after_install' AND a.acknowledged_at=''
			AND NOT EXISTS (SELECT 1 FROM targets t WHERE t.deployment_id=a.object_id AND t.state='lost_after_install')`)
		if err != nil {
			return err
		}
		var back []string
		for rows.Next() {
			var o string
			if err := rows.Scan(&o); err != nil {
				rows.Close()
				return err
			}
			back = append(back, o)
		}
		rows.Close()
		for _, o := range back {
			if err := s.resolveAlert(tx, "lost_after_install", o, "every endpoint lost after the install checked in again"); err != nil {
				return err
			}
		}
		return nil
	})
}

// UnverifiedAfter: an install the agent reported as done that inventory
// has not confirmed for this long is flagged (install_unverified) and
// counts towards the deployment's failure threshold.
const UnverifiedAfter = 6 * time.Hour

// UnverifiedDetail is the target detail of such an install.
var UnverifiedDetail = fmt.Sprintf("installed but not confirmed by inventory after %d h", int(UnverifiedAfter.Hours()))

// sweepUnverified flags installs that never verified: the target stays
// "installed" (inventory may still confirm it; check-in verifies it then)
// with UnverifiedDetail, counts as a failure for the auto-pause threshold,
// and one alert per deployment names the hosts. The alert closes once none
// is left. Only the detail changes (updated_at is kept, so "lost after
// install" timing is unaffected).
func (s *Store) sweepUnverified(ctx context.Context) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		cutoff := s.Now().Add(-UnverifiedAfter).UTC().Format(time.RFC3339Nano)
		rows, err := tx.QueryContext(ctx, `SELECT t.deployment_id, t.endpoint_id, t.package_id, e.hostname, t.ring, t.state, t.exit_code, t.updated_at
			FROM targets t JOIN endpoints e ON e.endpoint_id=t.endpoint_id JOIN deployments d ON d.deployment_id=t.deployment_id
			WHERE t.state='installed' AND t.detail != ? AND t.updated_at < ? AND d.state IN ('active','paused') AND d.operation='install' AND e.retired_at=''`,
			UnverifiedDetail, cutoff)
		if err != nil {
			return err
		}
		var found []Target
		for rows.Next() {
			var t Target
			if err := rows.Scan(&t.DeploymentID, &t.EndpointID, &t.PackageID, &t.Hostname, &t.Ring, &t.State, &t.ExitCode, &t.UpdatedAt); err != nil {
				rows.Close()
				return err
			}
			// updated_at is RFC 3339 with varying precision: compare as time.
			if s.Now().Sub(parseTime(t.UpdatedAt)) > UnverifiedAfter {
				found = append(found, t)
			}
		}
		rows.Close()
		rings := map[string]map[int]bool{}
		for _, t := range found {
			if _, err := tx.Exec(`UPDATE targets SET detail=? WHERE deployment_id=? AND endpoint_id=? AND state='installed'`, UnverifiedDetail, t.DeploymentID, t.EndpointID); err != nil {
				return err
			}
			if err := s.audit(tx, Ev{Actor: "system:scheduler", Action: "target.install_unverified", ObjectType: "target", ObjectID: t.DeploymentID + "/" + t.EndpointID,
				PackageID: t.PackageID, Details: map[string]any{"hostname": t.Hostname, "installed_at": t.UpdatedAt, "detail": UnverifiedDetail}}); err != nil {
				return err
			}
			if rings[t.DeploymentID] == nil {
				rings[t.DeploymentID] = map[int]bool{}
			}
			rings[t.DeploymentID][t.Ring] = true
		}
		// One alert per deployment with every unverified host (new and old).
		rows, err = tx.QueryContext(ctx, `SELECT t.deployment_id, d.name, d.package_id, t.endpoint_id, e.hostname FROM targets t
			JOIN endpoints e ON e.endpoint_id=t.endpoint_id JOIN deployments d ON d.deployment_id=t.deployment_id
			WHERE t.state='installed' AND t.detail=? AND d.state IN ('active','paused')`, UnverifiedDetail)
		if err != nil {
			return err
		}
		type dep struct {
			name, pkg string
			hosts     []HostRef
		}
		deps := map[string]*dep{}
		for rows.Next() {
			var id, name, pkg string
			var h HostRef
			if err := rows.Scan(&id, &name, &pkg, &h.EndpointID, &h.Hostname); err != nil {
				rows.Close()
				return err
			}
			if deps[id] == nil {
				deps[id] = &dep{name: name, pkg: pkg}
			}
			deps[id].hosts = append(deps[id].hosts, h)
		}
		rows.Close()
		keep := map[string]bool{}
		for id, d := range deps {
			keep[id] = true
			prefix := fmt.Sprintf("%s: %d endpoint(s) reported %s installed but inventory has not confirmed it after %d h", d.name, len(d.hosts), d.pkg, int(UnverifiedAfter.Hours()))
			if err := s.hostAlert(tx, "warning", "install_unverified", "deployment", id, prefix, d.hosts); err != nil {
				return err
			}
		}
		if err := s.resolveAlertsExcept(tx, "install_unverified", keep, "inventory confirmed the installs (or the targets moved on)"); err != nil {
			return err
		}
		for id, rs := range rings {
			for r := range rs {
				if err := s.evaluateRing(ctx, tx, id, r); err != nil {
					return err
				}
			}
		}
		return nil
	})
}
