package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"offpatch/internal/acqpolicy"
)

// Auto-download policy (internal/acqpolicy): what the acquisition zone
// downloads on every run, merged over acquire.json. Edited by the super
// admin only; every save is a new version (who, when, SHA-256, a plain
// summary of what changed), audited acquisition.policy_updated.

const acqPolicySchema = `CREATE TABLE IF NOT EXISTS acq_policies(
  version INTEGER PRIMARY KEY, policy TEXT NOT NULL, sha256 TEXT NOT NULL,
  edited_by TEXT NOT NULL, edited_at TEXT NOT NULL, summary TEXT NOT NULL DEFAULT '[]')`

// AcqPolicyRecord is one stored version (version 0: nothing saved yet).
type AcqPolicyRecord struct {
	Version  int              `json:"version"`
	EditedBy string           `json:"edited_by"`
	EditedAt string           `json:"edited_at"`
	SHA256   string           `json:"sha256"`
	Summary  []string         `json:"summary"`
	Policy   acqpolicy.Policy `json:"policy"`
}

// AcqPolicyVersion is a history entry (no policy body).
type AcqPolicyVersion struct {
	Version  int      `json:"version"`
	EditedBy string   `json:"edited_by"`
	EditedAt string   `json:"edited_at"`
	SHA256   string   `json:"sha256"`
	Summary  []string `json:"summary"`
}

// GetAcqPolicy returns the latest saved version; ok is false when none was
// saved (the caller supplies the defaults).
func (s *Store) GetAcqPolicy(ctx context.Context) (rec AcqPolicyRecord, ok bool, err error) {
	rec, err = s.acqPolicy(ctx, `SELECT version, policy, sha256, edited_by, edited_at, summary FROM acq_policies ORDER BY version DESC LIMIT 1`)
	if errors.Is(err, ErrNotFound) {
		return AcqPolicyRecord{}, false, nil
	}
	return rec, err == nil, err
}

// GetAcqPolicyVersion returns one saved version (ErrNotFound).
func (s *Store) GetAcqPolicyVersion(ctx context.Context, version int) (AcqPolicyRecord, error) {
	return s.acqPolicy(ctx, `SELECT version, policy, sha256, edited_by, edited_at, summary FROM acq_policies WHERE version=?`, version)
}

func (s *Store) acqPolicy(ctx context.Context, q string, args ...any) (AcqPolicyRecord, error) {
	var r AcqPolicyRecord
	var body, summary string
	err := s.db.QueryRowContext(ctx, q, args...).Scan(&r.Version, &body, &r.SHA256, &r.EditedBy, &r.EditedAt, &summary)
	if errors.Is(err, sql.ErrNoRows) {
		return r, Errf(ErrNotFound, "auto-download policy version not found")
	}
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal([]byte(body), &r.Policy); err != nil {
		return r, fmt.Errorf("auto-download policy version %d: %w", r.Version, err)
	}
	if err := r.Policy.Normalize(); err != nil {
		return r, fmt.Errorf("stored auto-download policy version %d no longer validates: %w", r.Version, err)
	}
	json.Unmarshal([]byte(summary), &r.Summary)
	if r.Summary == nil {
		r.Summary = []string{}
	}
	return r, nil
}

// AcqPolicyHistory lists saved versions, newest first.
func (s *Store) AcqPolicyHistory(ctx context.Context) ([]AcqPolicyVersion, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT version, sha256, edited_by, edited_at, summary FROM acq_policies ORDER BY version DESC LIMIT 500`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AcqPolicyVersion{}
	for rows.Next() {
		var v AcqPolicyVersion
		var summary string
		if err := rows.Scan(&v.Version, &v.SHA256, &v.EditedBy, &v.EditedAt, &summary); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(summary), &v.Summary)
		if v.Summary == nil {
			v.Summary = []string{}
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// SaveAcqPolicy validates p and stores it as a new version. baseVersion >=
// 0 makes the save conditional (ErrConflict if another version was saved
// since; -1 = unconditional). defaults is what version 0 meant (the
// summary of the first save is relative to it).
func (s *Store) SaveAcqPolicy(ctx context.Context, actor string, p acqpolicy.Policy, baseVersion int, defaults acqpolicy.Policy) (AcqPolicyRecord, error) {
	if err := p.Normalize(); err != nil {
		return AcqPolicyRecord{}, Errf(ErrInvalid, "%s", err.Error())
	}
	body := acqpolicy.Canonical(p)
	rec := AcqPolicyRecord{EditedBy: actor, EditedAt: s.now(), SHA256: acqpolicy.Hash(p), Policy: p}
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var last int
		var prevBody string
		err := tx.QueryRow(`SELECT version, policy FROM acq_policies ORDER BY version DESC LIMIT 1`).Scan(&last, &prevBody)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if baseVersion >= 0 && baseVersion != last {
			return Errf(ErrConflict, "the auto-download policy was changed by someone else (now version %d, you started from version %d): reload the page and make your change again", last, baseVersion)
		}
		prev := defaults
		if prevBody != "" {
			prev = acqpolicy.Policy{}
			json.Unmarshal([]byte(prevBody), &prev)
			prev.Normalize()
		}
		rec.Summary = acqpolicy.Diff(prev, p)
		if len(rec.Summary) == 0 {
			rec.Summary = []string{"saved without changes"}
		}
		rec.Version = last + 1
		if _, err := tx.Exec(`INSERT INTO acq_policies(version, policy, sha256, edited_by, edited_at, summary) VALUES(?,?,?,?,?,?)`,
			rec.Version, string(body), rec.SHA256, actor, rec.EditedAt, mustJSON(rec.Summary)); err != nil {
			return err
		}
		return s.audit(tx, Ev{Actor: actor, Action: "acquisition.policy_updated", ObjectType: "acquisition_policy", ObjectID: fmt.Sprint(rec.Version),
			Details: map[string]any{"version": rec.Version, "sha256": rec.SHA256, "previous_version": last, "changes": rec.Summary}})
	})
	return rec, err
}
