package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// Two-person rule for deployments and rollbacks (docs/03-state-model.md):
// CreateDeployment leaves a deployment in pending_approval with no targets;
// ApproveDeployment records approvals from bank users or admins other than
// the creator, one per person, and the one that reaches the required count
// activates it. RejectDeployment ends it (state rejected, final).

func fillApprovals(ctx context.Context, q querier, d *Deployment) error {
	rows, err := q.QueryContext(ctx, `SELECT approver, reason, at FROM deployment_approvals WHERE deployment_id=? ORDER BY at, approver`, d.DeploymentID)
	if err != nil {
		return err
	}
	defer rows.Close()
	d.Approvals = []Approval{}
	for rows.Next() {
		var a Approval
		if err := rows.Scan(&a.By, &a.Reason, &a.At); err != nil {
			return err
		}
		d.Approvals = append(d.Approvals, a)
	}
	return rows.Err()
}

func awaitingReason(have, need int) string {
	return fmt.Sprintf("waiting for approval (%d of %d)", have, need)
}

// pendingFor loads a deployment that must be waiting for approval and
// checks that actor (with role) may decide on it.
func pendingFor(ctx context.Context, tx *sql.Tx, actor, role, id, verb string) (Deployment, error) {
	d, err := getDeploymentCounted(ctx, tx, id)
	if err != nil {
		return d, err
	}
	if d.State != "pending_approval" {
		return d, Errf(ErrConflict, "deployment %s is %s; only a deployment waiting for approval can be %s", id, d.State, verb)
	}
	if !CanApproveDeployments(role) {
		return d, Errf(ErrForbidden, "only bank users and admins approve or reject deployments (your role: %s)", role)
	}
	if actor == d.CreatedBy {
		return d, Errf(ErrConflict, "you created this deployment; %d other people must approve it", d.ApprovalsRequired)
	}
	return d, nil
}

// ApproveDeployment records actor's approval (role: their canonical role).
// The approval that reaches approvals_required activates the deployment.
func (s *Store) ApproveDeployment(ctx context.Context, actor, role, id, reason string) (Deployment, error) {
	if err := requireReason(reason); err != nil {
		return Deployment{}, err
	}
	var out Deployment
	err := s.txChanged(ctx, func(tx *sql.Tx) error {
		d, err := pendingFor(ctx, tx, actor, role, id, "approved")
		if err != nil {
			return err
		}
		for _, a := range d.Approvals {
			if a.By == actor {
				return Errf(ErrConflict, "you already approved this deployment; another person must approve it")
			}
		}
		now := s.now()
		if _, err := tx.Exec(`INSERT INTO deployment_approvals(deployment_id,approver,reason,at) VALUES(?,?,?,?)`, id, actor, reason, now); err != nil {
			return err
		}
		have, need := len(d.Approvals)+1, d.ApprovalsRequired
		if need < 1 {
			need = 1
		}
		if err := s.audit(tx, Ev{Actor: actor, Action: "deployment.approved", ObjectType: "deployment", ObjectID: id, PackageID: d.PackageID,
			Details: map[string]any{"reason": reason, "approvals": have, "approvals_required": need, "operation": d.Operation, "role": CanonicalRole(role)}}); err != nil {
			return err
		}
		if have < need {
			if _, err := tx.Exec(`UPDATE deployments SET state_reason=?, updated_at=? WHERE deployment_id=?`, awaitingReason(have, need), now, id); err != nil {
				return err
			}
		} else if err := s.activateDeployment(ctx, tx, d, append(d.Approvals, Approval{By: actor, Reason: reason, At: now})); err != nil {
			return err
		}
		out, err = getDeploymentCounted(ctx, tx, id)
		return err
	})
	return out, err
}

// activateDeployment starts an approved deployment: state active, targets
// created and evaluated (as CreateDeployment did before approvals existed).
func (s *Store) activateDeployment(ctx context.Context, tx *sql.Tx, d Deployment, approvals []Approval) error {
	p, err := getPackage(ctx, tx, d.PackageID)
	if err != nil {
		return err
	}
	if d.Operation == "rollback" && p.State != "approved" && p.State != "revoked" || d.Operation != "rollback" && p.State != "approved" {
		return Errf(ErrConflict, "package %s is %s now; this deployment can no longer start (cancel it)", d.PackageID, p.State)
	}
	names := make([]string, 0, len(approvals))
	for _, a := range approvals {
		names = append(names, strings.TrimPrefix(a.By, "user:"))
	}
	now := s.now()
	reason := "approved by " + strings.Join(names, " and ")
	if _, err := tx.Exec(`UPDATE deployments SET state='active', state_reason=?, activated_at=?, updated_at=? WHERE deployment_id=?`, reason, now, now, d.DeploymentID); err != nil {
		return err
	}
	if err := s.resolveAlert(tx, "deployment_awaiting_approval", d.DeploymentID, reason); err != nil {
		return err
	}
	if err := s.audit(tx, Ev{Actor: "system:scheduler", Action: "deployment.activated", ObjectType: "deployment", ObjectID: d.DeploymentID, PackageID: d.PackageID,
		Details: map[string]any{"approved_by": names, "created_by": d.CreatedBy, "operation": d.Operation}}); err != nil {
		return err
	}
	if err := s.ensureTargetsForDeployment(ctx, tx, d.DeploymentID); err != nil {
		return err
	}
	// Every target may already be terminal (e.g. verified because the
	// inventory shows the package): completion is otherwise only evaluated
	// on agent reports, which will never come.
	return s.evaluateDeployment(ctx, tx, d.DeploymentID, false)
}

// RejectDeployment ends a deployment waiting for approval (state rejected).
func (s *Store) RejectDeployment(ctx context.Context, actor, role, id, reason string) (Deployment, error) {
	if err := requireReason(reason); err != nil {
		return Deployment{}, err
	}
	var out Deployment
	err := s.txChanged(ctx, func(tx *sql.Tx) error {
		d, err := pendingFor(ctx, tx, actor, role, id, "rejected")
		if err != nil {
			return err
		}
		now := s.now()
		if _, err := tx.Exec(`UPDATE deployments SET state='rejected', state_reason=?, rejected_by=?, rejected_at=?, updated_at=? WHERE deployment_id=?`,
			reason, actor, now, now, id); err != nil {
			return err
		}
		if err := s.resolveAlert(tx, "deployment_awaiting_approval", id, "rejected by "+strings.TrimPrefix(actor, "user:")); err != nil {
			return err
		}
		if err := s.audit(tx, Ev{Actor: actor, Action: "deployment.rejected", ObjectType: "deployment", ObjectID: id, PackageID: d.PackageID,
			Details: map[string]any{"reason": reason, "approvals_before": len(d.Approvals), "operation": d.Operation, "role": CanonicalRole(role)}}); err != nil {
			return err
		}
		out, err = getDeploymentCounted(ctx, tx, id)
		return err
	})
	return out, err
}
