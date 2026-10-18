package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

// Lean loaders for the auditor compliance pack (internal/compliance): one
// query per data set, no per-row lookups, so a 20 000-endpoint fleet stays
// a handful of table scans.

// PackTarget is one deployment target without hostname or inventory.
type PackTarget struct {
	DeploymentID    string
	PackageID       string
	EndpointID      string
	State           string
	UpdatedAt       string
	Evidence        string
	Detail          string
	Attempts        int
	DeploymentState string
	Operation       string
	Emergency       bool
}

// PackTargets returns every target of every deployment (install and
// rollback, any deployment state).
func (s *Store) PackTargets(ctx context.Context) ([]PackTarget, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT t.deployment_id, t.package_id, t.endpoint_id, t.state, t.updated_at, t.evidence, t.detail, t.attempts,
		d.state, d.operation, d.emergency FROM targets t JOIN deployments d ON d.deployment_id=t.deployment_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PackTarget{}
	for rows.Next() {
		var t PackTarget
		var em int
		if err := rows.Scan(&t.DeploymentID, &t.PackageID, &t.EndpointID, &t.State, &t.UpdatedAt, &t.Evidence, &t.Detail, &t.Attempts,
			&t.DeploymentState, &t.Operation, &em); err != nil {
			return nil, err
		}
		t.Emergency = em == 1
		out = append(out, t)
	}
	return out, rows.Err()
}

// InstallTimes returns, per "deployment_id/endpoint_id", when the agent
// first reported the install (target.installed or target.pending_reboot)
// for targets of the given packages (uses the audit package index).
func (s *Store) InstallTimes(ctx context.Context, packageIDs []string) (map[string]string, error) {
	out := map[string]string{}
	const batch = 500
	for i := 0; i < len(packageIDs); i += batch {
		ids := packageIDs[i:min(i+batch, len(packageIDs))]
		args := make([]any, len(ids))
		for j, id := range ids {
			args[j] = id
		}
		rows, err := s.db.QueryContext(ctx, `SELECT object_id, MIN(ts) FROM audit WHERE package_id IN (`+strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")+`)
			AND action IN ('target.installed','target.pending_reboot') GROUP BY object_id`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id, ts string
			if err := rows.Scan(&id, &ts); err != nil {
				rows.Close()
				return nil, err
			}
			out[id] = ts
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// AuditBetween returns events with from <= ts < to whose action starts
// with one of prefixes (all when empty), oldest first, at most limit
// (truncated reports whether more matched).
func (s *Store) AuditBetween(ctx context.Context, from, to time.Time, prefixes []string, limit int) ([]AuditEvent, bool, error) {
	var conds []string
	// Stored timestamps are RFC 3339 with variable fractions: compare with a
	// one-second margin in SQL, exactly in Go.
	args := []any{from.Add(-time.Second).UTC().Format(time.RFC3339), to.Add(time.Second).UTC().Format(time.RFC3339)}
	for _, p := range prefixes {
		conds = append(conds, "action LIKE ?")
		args = append(args, p+"%")
	}
	q := `SELECT seq,ts,actor,action,object_type,object_id,outcome,package_id,details,prev_hash,hash FROM audit WHERE ts >= ? AND ts < ?`
	if len(conds) > 0 {
		q += " AND (" + strings.Join(conds, " OR ") + ")"
	}
	q += " ORDER BY seq"
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	out := []AuditEvent{}
	truncated := false
	for rows.Next() {
		var e AuditEvent
		var d string
		if err := rows.Scan(&e.Seq, &e.TS, &e.Actor, &e.Action, &e.ObjectType, &e.ObjectID, &e.Outcome, &e.PackageID, &d, &e.PrevHash, &e.Hash); err != nil {
			return nil, false, err
		}
		ts := parseTime(e.TS)
		if ts.Before(from) || !ts.Before(to) {
			continue
		}
		if limit > 0 && len(out) >= limit {
			truncated = true
			break
		}
		e.Details = json.RawMessage(d)
		out = append(out, e)
	}
	return out, truncated, rows.Err()
}

// ListReceipts returns every transfer receipt, oldest first.
func (s *Store) ListReceipts(ctx context.Context) ([]TransferReceipt, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,file,file_sha256,size,adapter,sent_at,received_at,key_id,signature_ok FROM transfer_receipts ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TransferReceipt{}
	for rows.Next() {
		var r TransferReceipt
		var ok int
		if err := rows.Scan(&r.ID, &r.File, &r.FileSHA256, &r.Size, &r.Adapter, &r.SentAt, &r.ReceivedAt, &r.KeyID, &ok); err != nil {
			return nil, err
		}
		r.SignatureOK = ok == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

// AcquisitionBetween returns acquisition status reports received in
// [from, to), oldest first.
func (s *Store) AcquisitionBetween(ctx context.Context, from, to time.Time) ([]AcqRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,source,received_at,finished_at,outcome,key_id,report FROM acquisition_reports WHERE received_at >= ? AND received_at < ? ORDER BY id`,
		from.Add(-time.Second).UTC().Format(time.RFC3339), to.Add(time.Second).UTC().Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	all, err := scanAcq(rows)
	rows.Close()
	if err != nil {
		return nil, err
	}
	out := []AcqRecord{}
	for _, r := range all {
		if t := parseTime(r.ReceivedAt); !t.Before(from) && t.Before(to) {
			out = append(out, r)
		}
	}
	return out, nil
}

// PseudonymSalt is the server's random salt for report pseudonyms (created
// once): redacted reports name the same host the same way every time, and
// names cannot be recovered by hashing guesses without the salt.
func (s *Store) PseudonymSalt(ctx context.Context) ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO meta(k,v) VALUES('report_pseudonym_salt',?) ON CONFLICT(k) DO NOTHING`, hex.EncodeToString(b)); err != nil {
		return nil, err
	}
	v, err := s.GetMeta(ctx, "report_pseudonym_salt")
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(v)
}
