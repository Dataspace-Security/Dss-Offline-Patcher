package store

import (
	"context"
	"time"
)

// ---- policy, as the console shows it (GET /api/policy) ----

// RequiredApprovals is the number of approvals a package of this severity
// needs (default 1).
func (p Policy) RequiredApprovals(severity string) int { return p.required(severity) }

// DeadlineFor is the time from vendor release to required install for the
// severity (configured, else DefaultDeadlines).
func (p Policy) DeadlineFor(severity string) time.Duration { return p.deadline(severity) }

// Severities in display order.
var Severities = []string{"critical", "important", "moderate", "low"}

// ---- per package / endpoint deployment status ----

// TargetStatus says where one endpoint stands with one package across
// install deployments and exceptions.
type TargetStatus struct {
	Exception bool // active exception (for this package or all packages)
	Failed    bool // failed / lost_after_install in a deployment that is not cancelled
	Deploying bool // pending..pending_reboot (or deferred) in an active or paused deployment
	Verified  bool // verified in any install deployment
}

// FleetTargetIndex is a snapshot of install targets and active exceptions,
// indexed for TargetStatus lookups.
type FleetTargetIndex struct {
	byPkg      map[string]map[string]TargetStatus // package -> endpoint -> status
	exceptions map[string]map[string]bool         // endpoint -> package ("" = all) -> active
	active     map[string]string                  // package -> newest active/paused install deployment
}

// Status returns the endpoint's status for the package.
func (f *FleetTargetIndex) Status(packageID, endpointID string) TargetStatus {
	st := f.byPkg[packageID][endpointID]
	if x := f.exceptions[endpointID]; x[packageID] || x[""] {
		st.Exception = true
	}
	return st
}

// ActiveDeployment is the newest active or paused install deployment of the
// package ("" if none).
func (f *FleetTargetIndex) ActiveDeployment(packageID string) string { return f.active[packageID] }

var deployingStates = map[string]bool{"pending": true, "deferred": true, "downloading": true, "downloaded": true, "installing": true, "installed": true, "pending_reboot": true}

// FleetTargets loads every install target and active exception (one query
// each).
func (s *Store) FleetTargets(ctx context.Context) (*FleetTargetIndex, error) {
	f := &FleetTargetIndex{byPkg: map[string]map[string]TargetStatus{}, exceptions: map[string]map[string]bool{}, active: map[string]string{}}
	rows, err := s.db.QueryContext(ctx, `SELECT t.package_id, t.endpoint_id, t.state, d.state, d.deployment_id
		FROM targets t JOIN deployments d ON d.deployment_id=t.deployment_id
		WHERE d.operation='install' ORDER BY d.created_at, d.deployment_id`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var pid, eid, ts, ds, did string
		if err := rows.Scan(&pid, &eid, &ts, &ds, &did); err != nil {
			rows.Close()
			return nil, err
		}
		m := f.byPkg[pid]
		if m == nil {
			m = map[string]TargetStatus{}
			f.byPkg[pid] = m
		}
		st := m[eid]
		live := ds == "active" || ds == "paused"
		switch {
		case ts == "verified":
			st.Verified = true
		case (ts == "failed" || ts == "lost_after_install") && ds != "cancelled":
			st.Failed = true
		case deployingStates[ts] && live:
			st.Deploying = true
		}
		m[eid] = st
		if live {
			f.active[pid] = did // ordered by creation: the newest wins
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = s.db.QueryContext(ctx, `SELECT endpoint_id, package_id FROM exceptions WHERE revoked=0 AND expires_at > ?`, s.now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var eid, pid string
		if err := rows.Scan(&eid, &pid); err != nil {
			return nil, err
		}
		if f.exceptions[eid] == nil {
			f.exceptions[eid] = map[string]bool{}
		}
		f.exceptions[eid][pid] = true
	}
	return f, rows.Err()
}
