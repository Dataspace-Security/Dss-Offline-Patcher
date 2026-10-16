package store

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"time"
)

type metaQuerier interface {
	QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row
}

// auditAnchor is where the verifiable chain starts: genesis, or the last
// pruned event (seq, hash) after retention pruning.
func (s *Store) auditAnchor(ctx context.Context, q metaQuerier) (string, int64, error) {
	var v string
	err := q.QueryRowContext(ctx, `SELECT v FROM meta WHERE k='audit_anchor'`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return genesis, 0, nil
	}
	if err != nil {
		return "", 0, err
	}
	seqS, hash, ok := strings.Cut(v, ":")
	seq, perr := strconv.ParseInt(seqS, 10, 64)
	if !ok || perr != nil {
		return "", 0, errors.New("corrupt audit anchor")
	}
	return hash, seq, nil
}

// AuditHead returns the latest event's seq and hash (for checkpoints).
func (s *Store) AuditHead(ctx context.Context) (int64, string, error) {
	var seq int64
	var hash string
	err := s.db.QueryRowContext(ctx, `SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1`).Scan(&seq, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		hash, seq, err = s.auditAnchor(ctx, s.db)
	}
	return seq, hash, err
}

// AuditEventAt returns one event's hash (to match checkpoints against the DB).
func (s *Store) AuditHashAt(ctx context.Context, seq int64) (string, error) {
	var h string
	err := s.db.QueryRowContext(ctx, `SELECT hash FROM audit WHERE seq=?`, seq).Scan(&h)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return h, err
}

// AuditRange returns events with from < seq <= to, ascending.
func (s *Store) AuditRange(ctx context.Context, from, to int64) ([]AuditEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT seq,ts,actor,action,object_type,object_id,outcome,package_id,details,prev_hash,hash FROM audit WHERE seq > ? AND seq <= ? ORDER BY seq`, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEvent
	for rows.Next() {
		var e AuditEvent
		var d string
		if err := rows.Scan(&e.Seq, &e.TS, &e.Actor, &e.Action, &e.ObjectType, &e.ObjectID, &e.Outcome, &e.PackageID, &d, &e.PrevHash, &e.Hash); err != nil {
			return nil, err
		}
		e.Details = []byte(d)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) GetMeta(ctx context.Context, k string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT v FROM meta WHERE k=?`, k).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

func (s *Store) SetMeta(ctx context.Context, k, v string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, k, v)
	return err
}

// PruneAudit removes events that are both older than the retention period
// and at or below upTo (the last exported, signed checkpoint). The chain
// stays verifiable from the new anchor; the pruned events live on in the
// signed off-box exports.
func (s *Store) PruneAudit(ctx context.Context, upTo int64, olderThan time.Time) (int64, error) {
	var pruned int64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var maxSeq int64
		var hash string
		err := tx.QueryRow(`SELECT seq, hash FROM audit WHERE seq <= ? AND ts < ? ORDER BY seq DESC LIMIT 1`, upTo, olderThan.UTC().Format(time.RFC3339Nano)).Scan(&maxSeq, &hash)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO meta(k,v) VALUES('audit_prune','1') ON CONFLICT(k) DO UPDATE SET v='1'`); err != nil {
			return err
		}
		res, err := tx.Exec(`DELETE FROM audit WHERE seq <= ?`, maxSeq)
		if err != nil {
			return err
		}
		pruned, _ = res.RowsAffected()
		if _, err := tx.Exec(`UPDATE meta SET v='0' WHERE k='audit_prune'`); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO meta(k,v) VALUES('audit_anchor',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, strconv.FormatInt(maxSeq, 10)+":"+hash); err != nil {
			return err
		}
		return s.audit(tx, Ev{Actor: "system:retention", Action: "audit.pruned", ObjectType: "audit", ObjectID: strconv.FormatInt(maxSeq, 10),
			Details: map[string]any{"pruned_events": pruned, "anchor_seq": maxSeq, "anchor_hash": hash}})
	})
	return pruned, err
}
