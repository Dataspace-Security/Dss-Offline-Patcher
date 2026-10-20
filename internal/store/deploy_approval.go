package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Two-person rule for deployments and rollbacks (docs/03-state-model.md):
// CreateDeployment leaves a deployment in pending_approval with no targets;
// ApproveDeployment records approvals from bank users or admins other than
// the creator, one per person, and the one that reaches the required count
// activates it. RejectDeployment ends it (state rejected, final).
// An approval must also come from someone the creator does not control
// (checkSteward): not from an account whose credentials the creator set,
// and not from a second account freshly set up by the same person.

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
	var refused map[string]any // audited after the transaction rolled back
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
		st, why, err := s.checkSteward(ctx, tx, d, actor)
		if err != nil {
			return err
		}
		if why != nil {
			refused = why.details
			return why.err
		}
		scope, err := scopeCandidates(ctx, tx, d)
		if err != nil {
			return err
		}
		now := s.now()
		if _, err := tx.Exec(`INSERT INTO deployment_approvals(deployment_id,approver,reason,at) VALUES(?,?,?,?)`, id, actor, reason, now); err != nil {
			return err
		}
		have, need := len(d.Approvals)+1, d.ApprovalsRequired
		if need < 1 {
			need = 1
		}
		details := map[string]any{"reason": reason, "approvals": have, "approvals_required": need, "operation": d.Operation, "role": CanonicalRole(role),
			"endpoints_in_scope": len(scope)}
		fresh := s.freshCredentials(st)
		if st.local {
			details["credentials_set_by"], details["credentials_set_at"], details["fresh_credentials"] = st.by, st.at, fresh
		}
		if err := s.audit(tx, Ev{Actor: actor, Action: "deployment.approved", ObjectType: "deployment", ObjectID: id, PackageID: d.PackageID, Details: details}); err != nil {
			return err
		}
		if fresh {
			// Allowed (a new colleague may approve), but worth a second look:
			// it is how one person would pass the two-person rule.
			name := strings.TrimPrefix(actor, "user:")
			if err := s.addAlert(tx, "critical", "approval_fresh_account", "deployment", id,
				fmt.Sprintf("%s approved deployment %q of %s; the account's credentials were set by %s on %s (less than %d days ago). Check that %s is a real, separate person.",
					name, d.Name, d.PackageID, strings.TrimPrefix(st.by, "user:"), dateOf(st.at), int(FreshCredentials.Hours()/24), name),
				map[string]any{"approver": actor, "credentials_set_by": st.by, "credentials_set_at": st.at, "created_by": d.CreatedBy}); err != nil {
				return err
			}
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
	if refused != nil {
		s.Audit(ctx, Ev{Actor: actor, Action: "deployment.approval_refused", ObjectType: "deployment", ObjectID: id, Failure: true, Details: refused})
	}
	return out, err
}

// FreshCredentials: an account whose credentials someone set (created it,
// reset its password or MFA, changed its role) this recently is freshly
// provisioned. Two approvals from fresh accounts of the same steward are
// refused, and any approval from a fresh account raises an alert.
const FreshCredentials = 7 * 24 * time.Hour

// steward is who last set a local account's credentials, and when
// (local_users.cred_set_by / cred_set_at). local false: not a local user
// (SSO: the identity provider manages credentials).
type steward struct {
	by, at string
	local  bool
}

func credSteward(ctx context.Context, q querier, actor string) (steward, error) {
	email, ok := strings.CutPrefix(actor, "user:")
	if !ok {
		return steward{}, nil
	}
	var st steward
	err := q.QueryRowContext(ctx, `SELECT cred_set_by, cred_set_at FROM local_users WHERE email=?`, email).Scan(&st.by, &st.at)
	if errors.Is(err, sql.ErrNoRows) {
		return steward{}, nil
	}
	st.local = err == nil
	return st, err
}

func (s *Store) freshCredentials(st steward) bool {
	return st.local && st.at != "" && s.Now().Sub(parseTime(st.at)) < FreshCredentials
}

func dateOf(ts string) string {
	if len(ts) >= 10 {
		return ts[:10]
	}
	return ts
}

type approvalRefusal struct {
	err     error
	details map[string]any
}

// checkSteward applies the credential-steward rules to actor's approval
// of d: whoever set up the approver's account must not be the creator of
// the deployment (that person could sign in as the approver), and two
// accounts freshly set up by the same person do not count as two people.
func (s *Store) checkSteward(ctx context.Context, tx *sql.Tx, d Deployment, actor string) (steward, *approvalRefusal, error) {
	st, err := credSteward(ctx, tx, actor)
	if err != nil || !st.local || st.by == "" {
		return st, nil, err
	}
	if st.by == d.CreatedBy {
		return st, &approvalRefusal{
			err: Errf(ErrConflict, "your account's credentials were last set (created or reset) by %s, who created this deployment, so your approval would not be a second person's; another approver is needed",
				strings.TrimPrefix(st.by, "user:")),
			details: map[string]any{"rule": "steward_is_creator", "credentials_set_by": st.by, "credentials_set_at": st.at, "created_by": d.CreatedBy},
		}, nil
	}
	if !s.freshCredentials(st) {
		return st, nil, nil
	}
	for _, a := range d.Approvals {
		o, err := credSteward(ctx, tx, a.By)
		if err != nil {
			return st, nil, err
		}
		if o.by == st.by && s.freshCredentials(o) {
			return st, &approvalRefusal{
				err: Errf(ErrConflict, "%s already approved, and %s set up both your accounts within the last %d days; approvals from accounts one person provisioned do not count as two people, so another approver is needed",
					strings.TrimPrefix(a.By, "user:"), strings.TrimPrefix(st.by, "user:"), int(FreshCredentials.Hours()/24)),
				details: map[string]any{"rule": "same_fresh_steward", "credentials_set_by": st.by, "credentials_set_at": st.at,
					"other_approver": a.By, "other_credentials_set_at": o.at},
			}, nil
		}
	}
	return st, nil, nil
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
	// The approved endpoint set is fixed now (deploy_scope.go): later
	// group changes or enrolments cannot widen what was approved.
	scope, err := s.fixScope(ctx, tx, d)
	if err != nil {
		return err
	}
	if err := s.audit(tx, Ev{Actor: "system:scheduler", Action: "deployment.activated", ObjectType: "deployment", ObjectID: d.DeploymentID, PackageID: d.PackageID,
		Details: map[string]any{"approved_by": names, "created_by": d.CreatedBy, "operation": d.Operation, "approved_endpoints": scope}}); err != nil {
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
