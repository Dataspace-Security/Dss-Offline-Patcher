package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Approved scope (docs/03-state-model.md): the approvers approve a
// deployment for the endpoints in its ring groups at that moment. When the
// last approval activates it, that endpoint set is fixed (in_scope 1) and
// targets are only ever created for those endpoints, in whatever ring they
// fall. An endpoint that joins a ring group later (group edit, enrollment
// token, first check-in) is not added: it is recorded once as excluded
// (in_scope 0, audit deployment.scope_excluded) so an operator can create a
// new deployment for it, which needs its own approvals.
const deploymentScopeSchema = `CREATE TABLE IF NOT EXISTS deployment_scope(
  deployment_id TEXT NOT NULL, endpoint_id TEXT NOT NULL, in_scope INTEGER NOT NULL, at TEXT NOT NULL,
  PRIMARY KEY(deployment_id, endpoint_id))`

// ScopeExcludedDetail is why an endpoint got no target although it is in
// one of the deployment's ring groups now.
const ScopeExcludedDetail = "joined the ring groups after the deployment was approved; create a new deployment to include it"

// scopeCandidates returns the endpoints d would cover now: not retired and
// in one of its ring groups (any ring).
func scopeCandidates(ctx context.Context, q querier, d Deployment) ([]string, error) {
	eps, err := listEndpointsCols(ctx, q, endpointColsBrief)
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for _, e := range eps {
		if e.RetiredAt == "" && ringFor(d.Rings, e.Groups, e.EndpointID) >= 0 {
			ids = append(ids, e.EndpointID)
		}
	}
	return ids, nil
}

// fixScope records d's approved endpoint set (at activation) and returns
// its size.
func (s *Store) fixScope(ctx context.Context, tx *sql.Tx, d Deployment) (int, error) {
	ids, err := scopeCandidates(ctx, tx, d)
	if err != nil {
		return 0, err
	}
	now := s.now()
	for _, id := range ids {
		if _, err := tx.Exec(`INSERT OR REPLACE INTO deployment_scope(deployment_id,endpoint_id,in_scope,at) VALUES(?,?,1,?)`, d.DeploymentID, id, now); err != nil {
			return 0, err
		}
	}
	if _, err := tx.Exec(`UPDATE deployments SET scope_at=? WHERE deployment_id=?`, now, d.DeploymentID); err != nil {
		return 0, err
	}
	return len(ids), nil
}

// inScope reports whether endpointID is in d's approved endpoint set.
func inScope(ctx context.Context, tx *sql.Tx, depID, endpointID string) (bool, error) {
	var in int
	err := tx.QueryRowContext(ctx, `SELECT in_scope FROM deployment_scope WHERE deployment_id=? AND endpoint_id=?`, depID, endpointID).Scan(&in)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return in == 1, err
}

// excludeFromScope records (once) that e joined d's ring groups after the
// approval and gets no target.
func (s *Store) excludeFromScope(ctx context.Context, tx *sql.Tx, d Deployment, e Endpoint, ring int) error {
	res, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO deployment_scope(deployment_id,endpoint_id,in_scope,at) VALUES(?,?,0,?)`, d.DeploymentID, e.EndpointID, s.now())
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil // already recorded
	}
	return s.audit(tx, Ev{Actor: "system:scheduler", Action: "deployment.scope_excluded", ObjectType: "deployment", ObjectID: d.DeploymentID, PackageID: d.PackageID,
		Details: map[string]any{"endpoint_id": e.EndpointID, "hostname": e.Hostname, "groups": e.Groups, "ring": ring, "ring_name": d.Rings[ring].Name,
			"operation": d.Operation, "reason": ScopeExcludedDetail}})
}

// fillScope sets the approved and excluded endpoint counts of d.
func fillScope(ctx context.Context, q querier, d *Deployment) error {
	return q.QueryRowContext(ctx, `SELECT COALESCE(SUM(in_scope=1),0), COALESCE(SUM(in_scope=0),0) FROM deployment_scope WHERE deployment_id=?`, d.DeploymentID).
		Scan(&d.ScopeEndpoints, &d.ScopeExcluded)
}

// migrateDeploymentScopes fixes the scope of deployments that were already
// active or paused before scopes existed (once: scope_at is set): their
// current targets plus the endpoints in their ring groups now.
func migrateDeploymentScopes(db *sql.DB) error {
	rows, err := db.Query(`SELECT deployment_id, rings FROM deployments WHERE state IN ('active','paused') AND scope_at=''`)
	if err != nil {
		return err
	}
	var ds []Deployment
	for rows.Next() {
		var d Deployment
		var rings string
		if err := rows.Scan(&d.DeploymentID, &rings); err != nil {
			rows.Close()
			return err
		}
		json.Unmarshal([]byte(rings), &d.Rings)
		ds = append(ds, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(ds) == 0 {
		return err
	}
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, d := range ds {
		ids, err := scopeCandidates(ctx, tx, d)
		if err != nil {
			return err
		}
		for _, id := range ids {
			if _, err := tx.Exec(`INSERT OR IGNORE INTO deployment_scope(deployment_id,endpoint_id,in_scope,at) VALUES(?,?,1,?)`, d.DeploymentID, id, now); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO deployment_scope(deployment_id,endpoint_id,in_scope,at) SELECT deployment_id, endpoint_id, 1, ? FROM targets WHERE deployment_id=?`,
			now, d.DeploymentID); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE deployments SET scope_at=? WHERE deployment_id=?`, now, d.DeploymentID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// overlappingDeployment refuses n when a deployment of the same package and
// operation that is waiting for approval, active or paused already covers
// one of the machines n would cover: its approved scope once active, the
// machines in its ring groups while it waits.
func overlappingDeployment(ctx context.Context, tx *sql.Tx, n NewDeployment) error {
	rows, err := tx.QueryContext(ctx, `SELECT `+depCols+` FROM deployments WHERE package_id=? AND operation=? AND state IN ('pending_approval','active','paused') ORDER BY created_at`, n.PackageID, n.Operation)
	if err != nil {
		return err
	}
	var others []Deployment
	for rows.Next() {
		d, err := scanDeployment(rows)
		if err != nil {
			rows.Close()
			return err
		}
		others = append(others, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(others) == 0 {
		return err
	}
	mine, err := scopeCandidates(ctx, tx, Deployment{NewDeployment: n})
	if err != nil {
		return err
	}
	want := map[string]bool{}
	for _, id := range mine {
		want[id] = true
	}
	for _, o := range others {
		var covered []string
		if o.State == "pending_approval" {
			if covered, err = scopeCandidates(ctx, tx, o); err != nil {
				return err
			}
		} else {
			r, err := tx.QueryContext(ctx, `SELECT endpoint_id FROM deployment_scope WHERE deployment_id=? AND in_scope=1
				UNION SELECT endpoint_id FROM targets WHERE deployment_id=?`, o.DeploymentID, o.DeploymentID)
			if err != nil {
				return err
			}
			for r.Next() {
				var id string
				if err := r.Scan(&id); err != nil {
					r.Close()
					return err
				}
				covered = append(covered, id)
			}
			r.Close()
			if err := r.Err(); err != nil {
				return err
			}
		}
		both := 0
		for _, id := range covered {
			if want[id] {
				both++
			}
		}
		if both > 0 {
			return Errf(ErrConflict, "deployment %s (%q, %s) of this package already covers %d of these machines; deploy to other machines, wait for it to finish, or cancel it first",
				o.DeploymentID, o.Name, strings.ReplaceAll(o.State, "_", " "), both)
		}
	}
	return nil
}
