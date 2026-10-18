package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Install safety: pre-install deferral, endpoints lost after an install,
// and manual rollback (docs/03-state-model.md).

// PreinstallPolicy is sent to agents on check-in: before downloading, the
// agent requires max(2 × package size, MinFreeDiskMB) free on the system
// volume, and AC power or MinBatteryPct (0 = no battery check). Failing
// either defers the install; it is not a failure.
type PreinstallPolicy struct {
	MinFreeDiskMB int `json:"min_free_disk_mb"`
	MinBatteryPct int `json:"min_battery_pct"`
}

// RollbackUnsupported returns why a package cannot be rolled back, or "".
func RollbackUnsupported(p Package) string {
	switch p.Kind {
	case "msu":
		if p.KB == "" {
			return "the package has no KB number"
		}
	case "msi":
		if p.ProductCode == "" {
			return "the package has no MSI product code"
		}
	case "deb", "rpm":
		if p.PackageName == "" {
			return "the package has no package name"
		}
	case "exe":
		if p.Exe == nil || !p.Exe.Uninstall.QuietUninstall {
			return RollbackNoQuietUninstall
		}
	case "pkg":
		return "macOS .pkg installers have no uninstall; deploy the previous version's .pkg instead, or remove the app by hand"
	case "agent":
		return "the agent cannot be rolled back by a deployment; reinstall the previous agent version (docs/runbooks/08-agent-upgrade.md)"
	default:
		return "unknown package kind " + p.Kind
	}
	return ""
}

// rollbackPresent reports whether inventory shows p as installed, i.e.
// whether a rollback has something to remove. deb/rpm must be at exactly
// p's version: removing a newer version would not undo this package.
func rollbackPresent(inv []InventoryItem, p Package) (bool, string) {
	for _, it := range inv {
		switch {
		case p.Kind == "msu" && it.Kind == "kb" && strings.EqualFold(it.ID, p.KB):
			return true, "inventory shows " + p.KB
		case p.Kind == "msi" && it.Kind == "product" && strings.EqualFold(it.ID, p.ProductCode):
			return true, "inventory shows product " + p.ProductCode
		case p.Kind == "exe" && exeAppMatch(p, it):
			// Only this version: removing a newer one would not undo this package.
			if want := exeWantVersion(p); want == "" || it.Version == "" || (VersionAtLeast(it.Version, want) && VersionAtLeast(want, it.Version)) {
				return true, "inventory shows " + it.Name + " " + it.Version
			}
			return false, fmt.Sprintf("installed version %s is not %s; nothing of this package to roll back", it.Version, exeWantVersion(p))
		case (p.Kind == "deb" || p.Kind == "rpm") && it.Kind == "pkg" && it.ID == p.PackageName:
			if VersionAtLeast(it.Version, p.Version) && VersionAtLeast(p.Version, it.Version) {
				return true, "inventory shows " + p.PackageName + " " + it.Version
			}
			return false, fmt.Sprintf("installed version %s is not %s; nothing of this package to roll back", it.Version, p.Version)
		}
	}
	return false, "not installed; nothing to roll back"
}

// markRolledBack records, on install targets for the same package and
// endpoint, that a rollback removed it — so reports stop counting it as
// patched.
func (s *Store) markRolledBack(tx *sql.Tx, rb Target) error {
	rows, err := tx.Query(`SELECT t.deployment_id, t.state FROM targets t JOIN deployments d ON d.deployment_id=t.deployment_id
		WHERE t.endpoint_id=? AND t.package_id=? AND d.operation='install' AND d.state != 'cancelled'
		AND t.state IN ('verified','installed','pending_reboot','lost_after_install')`, rb.EndpointID, rb.PackageID)
	if err != nil {
		return err
	}
	var ts []Target
	for rows.Next() {
		t := Target{EndpointID: rb.EndpointID, PackageID: rb.PackageID, Hostname: rb.Hostname}
		rows.Scan(&t.DeploymentID, &t.State)
		ts = append(ts, t)
	}
	rows.Close()
	for _, t := range ts {
		if err := s.setTarget(tx, "system:verifier", t, "rolled_back", "removed by rollback deployment "+rb.DeploymentID, 0, 0); err != nil {
			return err
		}
	}
	return nil
}

// sweepLost marks targets "lost_after_install" when the endpoint installed
// (or was asked to reboot for) a package and has not checked in for `after`
// since. They count towards the ring's auto-pause threshold, and a critical
// alert names the hosts. Check-in recovers them (Checkin).
func (s *Store) sweepLost(ctx context.Context, after time.Duration) error {
	if after <= 0 {
		return nil
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		// Activity = the endpoint's last check-in, reboot request, or report on
		// any of its targets (an agent working through several installs in one
		// cycle reports progress without checking in).
		rows, err := tx.QueryContext(ctx, `SELECT t.deployment_id, t.endpoint_id, t.package_id, e.hostname, t.ring, t.state,
			(SELECT MAX(t2.updated_at) FROM targets t2 WHERE t2.endpoint_id=t.endpoint_id AND t2.state IN ('downloading','downloaded','installing','installed','pending_reboot','failed','deferred')), e.last_seen, e.reboot_requested_at
			FROM targets t JOIN endpoints e ON e.endpoint_id=t.endpoint_id JOIN deployments d ON d.deployment_id=t.deployment_id
			WHERE t.state IN ('installed','pending_reboot') AND d.state IN ('active','paused') AND e.retired_at=''`)
		if err != nil {
			return err
		}
		type lost struct {
			t     Target
			since time.Time
		}
		var found []lost
		now := s.Now()
		for rows.Next() {
			var t Target
			var seen, reboot string
			if err := rows.Scan(&t.DeploymentID, &t.EndpointID, &t.PackageID, &t.Hostname, &t.Ring, &t.State, &t.UpdatedAt, &seen, &reboot); err != nil {
				rows.Close()
				return err
			}
			// The later of: the install report, the last check-in, the reboot request.
			since := parseTime(t.UpdatedAt)
			for _, ts := range []string{seen, reboot} {
				if v := parseTime(ts); v.After(since) {
					since = v
				}
			}
			if now.Sub(since) > after {
				found = append(found, lost{t, since})
			}
		}
		rows.Close()
		byDep := map[string][]lost{}
		for _, l := range found {
			why := fmt.Sprintf("endpoint has not checked in since %s (%s after it reported %s)", l.since.UTC().Format(time.RFC3339), after, strings.ReplaceAll(l.t.State, "_", " "))
			if err := s.setTarget(tx, "system:scheduler", l.t, "lost_after_install", why, 0, 0); err != nil {
				return err
			}
			byDep[l.t.DeploymentID] = append(byDep[l.t.DeploymentID], l)
		}
		for id, ls := range byDep {
			d, err := getDeployment(ctx, tx, id)
			if err != nil {
				return err
			}
			if err := s.alertLost(tx, d); err != nil {
				return err
			}
			rings := map[int]bool{}
			for _, l := range ls {
				rings[l.t.Ring] = true
			}
			for r := range rings {
				if err := s.evaluateRing(ctx, tx, id, r); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// DefaultStuckAfter is used when Thresholds.StuckAfter is 0.
const DefaultStuckAfter = 6 * time.Hour

// sweepStuck fails targets left downloading, downloaded or installing with
// no report (and no check-in or heartbeat from the endpoint) for `after`:
// the agent died or the endpoint vanished mid-install. Failing them frees the
// deployment's concurrency slot, counts an attempt, and lets the endpoint
// retry when it returns.
func (s *Store) sweepStuck(ctx context.Context, after time.Duration) error {
	if after <= 0 {
		after = DefaultStuckAfter
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT t.deployment_id, t.endpoint_id, t.package_id, e.hostname, t.ring, t.state, t.exit_code, t.updated_at, e.last_seen
			FROM targets t JOIN endpoints e ON e.endpoint_id=t.endpoint_id JOIN deployments d ON d.deployment_id=t.deployment_id
			WHERE t.state IN ('downloading','downloaded','installing') AND d.state IN ('active','paused')`)
		if err != nil {
			return err
		}
		now := s.Now()
		var stuck []Target
		for rows.Next() {
			var t Target
			var seen string
			if err := rows.Scan(&t.DeploymentID, &t.EndpointID, &t.PackageID, &t.Hostname, &t.Ring, &t.State, &t.ExitCode, &t.UpdatedAt, &seen); err != nil {
				rows.Close()
				return err
			}
			last := parseTime(t.UpdatedAt)
			if v := parseTime(seen); v.After(last) {
				last = v
			}
			if now.Sub(last) > after {
				stuck = append(stuck, t)
			}
		}
		rows.Close()
		rings := map[string]map[int]bool{}
		for _, t := range stuck {
			why := fmt.Sprintf("no report from the endpoint for %s while %s; marked failed (will be retried if retries remain)", after, t.State)
			if err := s.setTarget(tx, "system:scheduler", t, "failed", why, t.ExitCode, attemptDelta(t.State, "failed")); err != nil {
				return err
			}
			if rings[t.DeploymentID] == nil {
				rings[t.DeploymentID] = map[int]bool{}
			}
			rings[t.DeploymentID][t.Ring] = true
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

// alertLost raises (or, while one is open, updates and re-sends) the
// critical alert listing every endpoint currently lost in the deployment.
func (s *Store) alertLost(tx *sql.Tx, d Deployment) error {
	rows, err := tx.Query(`SELECT t.endpoint_id, e.hostname FROM targets t JOIN endpoints e ON e.endpoint_id=t.endpoint_id WHERE t.deployment_id=? AND t.state='lost_after_install' ORDER BY e.hostname`, d.DeploymentID)
	if err != nil {
		return err
	}
	var hosts []HostRef
	for rows.Next() {
		var h HostRef
		if err := rows.Scan(&h.EndpointID, &h.Hostname); err != nil {
			rows.Close()
			return err
		}
		hosts = append(hosts, h)
	}
	rows.Close()
	verb := "installing"
	if d.Operation == "rollback" {
		verb = "rolling back"
	}
	det, list := hostDetails(hosts)
	msg := fmt.Sprintf("%s: %d endpoint(s) stopped checking in after %s %s: %s. Check these machines (boot failure?) before resuming.", d.Name, len(hosts), verb, d.PackageID, list)
	res, err := tx.Exec(`UPDATE alerts SET message=?, details=?, delivered=0 WHERE kind='lost_after_install' AND object_id=? AND acknowledged_at=''`, msg, mustJSON(det), d.DeploymentID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	return s.raiseAlertWith(tx, "critical", "lost_after_install", "deployment", d.DeploymentID, msg, det)
}

// recoverLost: a lost endpoint checked in again but inventory does not (yet)
// confirm the change. Back to pending_reboot if a reboot is still pending,
// else installed (awaiting verification). The audit trail keeps the episode.
func (s *Store) recoverLost(tx *sql.Tx, t Target, rebootPending bool) error {
	if rebootPending {
		return s.setTarget(tx, "system:verifier", t, "pending_reboot", "endpoint checked in again after being lost; reboot still pending", t.ExitCode, 0)
	}
	return s.setTarget(tx, "system:verifier", t, "installed", "endpoint checked in again after being lost; waiting for inventory to confirm", t.ExitCode, 0)
}
