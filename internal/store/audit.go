package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type AuditEvent struct {
	Seq        int64           `json:"seq"`
	TS         string          `json:"ts"`
	Actor      string          `json:"actor"`
	Action     string          `json:"action"`
	ObjectType string          `json:"object_type"`
	ObjectID   string          `json:"object_id"`
	Outcome    string          `json:"outcome"`
	PackageID  string          `json:"package_id"`
	Details    json.RawMessage `json:"details"`
	PrevHash   string          `json:"prev_hash"`
	Hash       string          `json:"hash"`
}

// Ev is what callers supply; the store fills seq, ts and the chain.
type Ev struct {
	Actor      string
	Action     string
	ObjectType string
	ObjectID   string
	Failure    bool
	PackageID  string
	Details    map[string]any
}

const genesis = "0000000000000000000000000000000000000000000000000000000000000000"

func chainHash(prev string, e AuditEvent) string {
	h := sha256.New()
	for _, f := range []string{prev, strconv.FormatInt(e.Seq, 10), e.TS, e.Actor, e.Action, e.ObjectType, e.ObjectID, e.Outcome, e.PackageID, string(e.Details)} {
		h.Write([]byte(f))
		h.Write([]byte{0x1f})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (s *Store) audit(tx *sql.Tx, ev Ev) error {
	var prev string
	var last int64
	err := tx.QueryRow(`SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1`).Scan(&last, &prev)
	if errors.Is(err, sql.ErrNoRows) {
		prev, last, err = s.auditAnchor(context.Background(), tx)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if ev.Details == nil {
		ev.Details = map[string]any{}
	}
	e := AuditEvent{
		Seq: last + 1, TS: s.now(), Actor: ev.Actor, Action: ev.Action, ObjectType: ev.ObjectType,
		ObjectID: ev.ObjectID, Outcome: "success", PackageID: ev.PackageID,
		Details: json.RawMessage(mustJSON(ev.Details)), PrevHash: prev,
	}
	if ev.Failure {
		e.Outcome = "failure"
	}
	e.Hash = chainHash(prev, e)
	_, err = tx.Exec(`INSERT INTO audit(seq,ts,actor,action,object_type,object_id,outcome,package_id,details,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		e.Seq, e.TS, e.Actor, e.Action, e.ObjectType, e.ObjectID, e.Outcome, e.PackageID, string(e.Details), e.PrevHash, e.Hash)
	return err
}

// Audit records a standalone event (e.g. a failed login or a rejected request).
func (s *Store) Audit(ctx context.Context, ev Ev) error {
	return s.tx(ctx, func(tx *sql.Tx) error { return s.audit(tx, ev) })
}

type AuditQuery struct {
	ObjectID, Action, Actor, PackageID string
	Limit                              int
	BeforeSeq                          int64
	Ascending                          bool
}

func (s *Store) ListAudit(ctx context.Context, q AuditQuery) ([]AuditEvent, error) {
	var where []string
	var args []any
	if q.ObjectID != "" {
		where = append(where, "object_id = ?")
		args = append(args, q.ObjectID)
	}
	if q.Action != "" {
		where = append(where, "action LIKE ?")
		args = append(args, q.Action+"%")
	}
	if q.Actor != "" {
		where = append(where, "actor = ?")
		args = append(args, q.Actor)
	}
	if q.PackageID != "" {
		where = append(where, "package_id = ?")
		args = append(args, q.PackageID)
	}
	if q.BeforeSeq > 0 {
		where = append(where, "seq < ?")
		args = append(args, q.BeforeSeq)
	}
	sqlq := `SELECT seq,ts,actor,action,object_type,object_id,outcome,package_id,details,prev_hash,hash FROM audit`
	if len(where) > 0 {
		sqlq += " WHERE " + strings.Join(where, " AND ")
	}
	if q.Ascending {
		sqlq += " ORDER BY seq ASC"
	} else {
		sqlq += " ORDER BY seq DESC"
	}
	if q.Limit <= 0 || q.Limit > 5000 {
		q.Limit = 200
	}
	sqlq += fmt.Sprintf(" LIMIT %d", q.Limit)
	rows, err := s.db.QueryContext(ctx, sqlq, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEvent{}
	for rows.Next() {
		var e AuditEvent
		var d string
		if err := rows.Scan(&e.Seq, &e.TS, &e.Actor, &e.Action, &e.ObjectType, &e.ObjectID, &e.Outcome, &e.PackageID, &d, &e.PrevHash, &e.Hash); err != nil {
			return nil, err
		}
		e.Details = json.RawMessage(d)
		out = append(out, e)
	}
	return out, rows.Err()
}

type ChainResult struct {
	OK          bool   `json:"ok"`
	Count       int64  `json:"count"`
	FirstBadSeq int64  `json:"first_bad_seq"`
	Error       string `json:"error"`
}

// VerifyAudit walks the whole chain and reports the first broken link.
func (s *Store) VerifyAudit(ctx context.Context) (ChainResult, error) {
	// Start from the retention anchor (genesis if nothing was ever pruned).
	prev, n, err := s.auditAnchor(ctx, s.db)
	if err != nil {
		return ChainResult{}, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT seq,ts,actor,action,object_type,object_id,outcome,package_id,details,prev_hash,hash FROM audit ORDER BY seq ASC`)
	if err != nil {
		return ChainResult{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var e AuditEvent
		var d string
		if err := rows.Scan(&e.Seq, &e.TS, &e.Actor, &e.Action, &e.ObjectType, &e.ObjectID, &e.Outcome, &e.PackageID, &d, &e.PrevHash, &e.Hash); err != nil {
			return ChainResult{}, err
		}
		e.Details = json.RawMessage(d)
		n++
		switch {
		case e.Seq != n:
			return ChainResult{Count: n, FirstBadSeq: e.Seq, Error: "sequence gap"}, nil
		case e.PrevHash != prev:
			return ChainResult{Count: n, FirstBadSeq: e.Seq, Error: "prev_hash mismatch"}, nil
		case chainHash(prev, e) != e.Hash:
			return ChainResult{Count: n, FirstBadSeq: e.Seq, Error: "hash mismatch (event modified)"}, nil
		}
		prev = e.Hash
	}
	return ChainResult{OK: true, Count: n}, rows.Err()
}

// ChainHash recomputes an event's hash (exported for off-box verification).
func ChainHash(prev string, e AuditEvent) string { return chainHash(prev, e) }
