package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"offpatch/internal/acqpolicy"
)

// Two-person rule for download sources (finding S-4): an auto-download
// policy change that adds a source or changes a source's address or
// verification data (vendor-url, internal mirrors, winget / catalog / MSRC
// addresses) is stored as a proposal and becomes a policy version (and is
// written for pmctl) only when a second super admin approves it. The
// proposer cannot approve; the proposer or another super admin can reject
// (withdraw) it. One proposal at a time: a new one replaces it. Each step
// is audited (acquisition.policy_change_proposed / _approved / _rejected).

const acqPolicyPendingSchema = `CREATE TABLE IF NOT EXISTS acq_policy_pending(
  id INTEGER PRIMARY KEY CHECK (id = 1), policy TEXT NOT NULL, sha256 TEXT NOT NULL, base_version INTEGER NOT NULL,
  proposed_by TEXT NOT NULL, proposed_at TEXT NOT NULL, changes TEXT NOT NULL, summary TEXT NOT NULL)`

// AcqPolicyPending is a proposed policy change waiting for a second super admin.
type AcqPolicyPending struct {
	BaseVersion int              `json:"base_version"`
	ProposedBy  string           `json:"proposed_by"`
	ProposedAt  string           `json:"proposed_at"`
	SHA256      string           `json:"sha256"`
	Changes     []string         `json:"source_changes"` // why it needs approval
	Summary     []string         `json:"summary"`        // everything it changes
	Policy      acqpolicy.Policy `json:"policy"`
}

// ProposeAcqPolicy stores p as the pending change (replacing an earlier
// proposal). baseVersion as in SaveAcqPolicy.
func (s *Store) ProposeAcqPolicy(ctx context.Context, actor string, p acqpolicy.Policy, baseVersion int, defaults acqpolicy.Policy) (AcqPolicyPending, error) {
	if err := p.Normalize(); err != nil {
		return AcqPolicyPending{}, Errf(ErrInvalid, "%s", err.Error())
	}
	pend := AcqPolicyPending{ProposedBy: actor, ProposedAt: s.now(), SHA256: acqpolicy.Hash(p), Policy: p}
	err := s.tx(ctx, func(tx *sql.Tx) error {
		last, prev, err := latestAcqPolicyTx(tx, baseVersion, defaults)
		if err != nil {
			return err
		}
		pend.BaseVersion = last
		pend.Changes = acqpolicy.SourceChanges(prev, p)
		if len(pend.Changes) == 0 {
			return Errf(ErrInvalid, "this change adds or changes no download source: save it directly")
		}
		pend.Summary = acqpolicy.Diff(prev, p)
		replaced, _, err := pendingAcqPolicyTx(tx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO acq_policy_pending(id, policy, sha256, base_version, proposed_by, proposed_at, changes, summary) VALUES(1,?,?,?,?,?,?,?)
		  ON CONFLICT(id) DO UPDATE SET policy=excluded.policy, sha256=excluded.sha256, base_version=excluded.base_version,
		  proposed_by=excluded.proposed_by, proposed_at=excluded.proposed_at, changes=excluded.changes, summary=excluded.summary`,
			string(acqpolicy.Canonical(p)), pend.SHA256, last, actor, pend.ProposedAt, mustJSON(pend.Changes), mustJSON(pend.Summary)); err != nil {
			return err
		}
		details := map[string]any{"sha256": pend.SHA256, "base_version": last, "source_changes": pend.Changes, "changes": pend.Summary}
		if replaced != nil {
			details["replaced_proposal_by"], details["replaced_sha256"] = replaced.ProposedBy, replaced.SHA256
		}
		return s.audit(tx, Ev{Actor: actor, Action: "acquisition.policy_change_proposed", ObjectType: "acquisition_policy",
			ObjectID: fmt.Sprint(last + 1), Details: details})
	})
	return pend, err
}

// GetAcqPolicyPending returns the pending change, if any.
func (s *Store) GetAcqPolicyPending(ctx context.Context) (*AcqPolicyPending, error) {
	var out *AcqPolicyPending
	err := s.tx(ctx, func(tx *sql.Tx) error {
		p, _, err := pendingAcqPolicyTx(tx)
		out = p
		return err
	})
	return out, err
}

func pendingAcqPolicyTx(tx *sql.Tx) (*AcqPolicyPending, string, error) {
	var p AcqPolicyPending
	var body, changes, summary string
	err := tx.QueryRow(`SELECT policy, sha256, base_version, proposed_by, proposed_at, changes, summary FROM acq_policy_pending WHERE id=1`).
		Scan(&body, &p.SHA256, &p.BaseVersion, &p.ProposedBy, &p.ProposedAt, &changes, &summary)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	if err := json.Unmarshal([]byte(body), &p.Policy); err != nil {
		return nil, "", fmt.Errorf("pending auto-download policy: %w", err)
	}
	if err := p.Policy.Normalize(); err != nil {
		return nil, "", fmt.Errorf("pending auto-download policy no longer validates: %w", err)
	}
	json.Unmarshal([]byte(changes), &p.Changes)
	json.Unmarshal([]byte(summary), &p.Summary)
	if p.Changes == nil {
		p.Changes = []string{}
	}
	if p.Summary == nil {
		p.Summary = []string{}
	}
	return &p, body, nil
}

func sameActor(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

// ApproveAcqPolicy makes the pending change (identified by its sha256, the
// one the approver reviewed) the next policy version. The approver must
// not be the proposer; the policy must not have changed since the
// proposal. The version is recorded as edited by the proposer.
func (s *Store) ApproveAcqPolicy(ctx context.Context, approver, sha256 string) (AcqPolicyRecord, error) {
	var rec AcqPolicyRecord
	err := s.tx(ctx, func(tx *sql.Tx) error {
		p, _, err := pendingAcqPolicyTx(tx)
		if err != nil {
			return err
		}
		if p == nil {
			return Errf(ErrNotFound, "no auto-download policy change is waiting for approval")
		}
		if !strings.EqualFold(p.SHA256, strings.TrimSpace(sha256)) {
			return Errf(ErrConflict, "the pending change was replaced by a newer proposal: reload the page and review it again")
		}
		if sameActor(p.ProposedBy, approver) {
			return Errf(ErrForbidden, "you proposed this change: another super admin must approve it")
		}
		last, _, err := latestAcqPolicyTx(tx, p.BaseVersion, acqpolicy.Policy{})
		if errors.Is(err, ErrConflict) {
			return Errf(ErrConflict, "the auto-download policy changed after this proposal (now version %d, proposed on version %d): reject it and propose again", last, p.BaseVersion)
		} else if err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM acq_policy_pending WHERE id=1`); err != nil {
			return err
		}
		if err := s.audit(tx, Ev{Actor: approver, Action: "acquisition.policy_change_approved", ObjectType: "acquisition_policy",
			ObjectID: fmt.Sprint(last + 1), Details: map[string]any{"sha256": p.SHA256, "proposed_by": p.ProposedBy, "proposed_at": p.ProposedAt,
				"source_changes": p.Changes}}); err != nil {
			return err
		}
		// The base version is unchanged, so the proposal's summary still
		// describes the change (for version 1: relative to the defaults).
		rec, err = s.insertAcqPolicyTx(tx, p.ProposedBy, p.Policy, last, p.Summary, map[string]any{"approved_by": approver, "source_changes": p.Changes})
		return err
	})
	return rec, err
}

// RejectAcqPolicy discards the pending change (the proposer withdraws it,
// or another super admin rejects it).
func (s *Store) RejectAcqPolicy(ctx context.Context, actor, reason string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		p, _, err := pendingAcqPolicyTx(tx)
		if err != nil {
			return err
		}
		if p == nil {
			return Errf(ErrNotFound, "no auto-download policy change is waiting for approval")
		}
		if _, err := tx.Exec(`DELETE FROM acq_policy_pending WHERE id=1`); err != nil {
			return err
		}
		how := "rejected"
		if sameActor(p.ProposedBy, actor) {
			how = "withdrawn"
		}
		return s.audit(tx, Ev{Actor: actor, Action: "acquisition.policy_change_rejected", ObjectType: "acquisition_policy",
			ObjectID: fmt.Sprint(p.BaseVersion + 1), Details: map[string]any{"sha256": p.SHA256, "proposed_by": p.ProposedBy, "how": how,
				"reason": reason, "source_changes": p.Changes}})
	})
}
