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
	"sync"
	"time"
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
	AfterSeq                           int64 // paging forwards (with Ascending)
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
	if q.AfterSeq > 0 {
		where = append(where, "seq > ?")
		args = append(args, q.AfterSeq)
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
	res, last, err := s.verifyAfter(ctx, prev, n)
	if err == nil {
		s.chain.remember(res, last, true)
	}
	return res, err
}

// auditFullVerifyEvery bounds how long AuditChainStatus trusts its cached
// prefix before walking the whole chain again.
var auditFullVerifyEvery = time.Hour

// chainCache remembers the last verified link so status pages (summary,
// system, metrics) only hash events appended since.
type chainCache struct {
	mu     sync.Mutex
	ok     bool
	seq    int64
	hash   string
	fullAt time.Time
}

func (c *chainCache) remember(res ChainResult, lastHash string, full bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ok = res.OK
	if !res.OK {
		return
	}
	c.seq, c.hash = res.Count, lastHash
	if full {
		c.fullAt = time.Now()
	}
}

// AuditChainStatus is VerifyAudit for status pages: it re-verifies only the
// events after the last verified one (checking that link is unchanged) and
// walks the whole chain at most every auditFullVerifyEvery, or whenever the
// last result was a failure. /api/audit/verify always walks everything.
func (s *Store) AuditChainStatus(ctx context.Context) (ChainResult, error) {
	c := &s.chain
	c.mu.Lock()
	ok, seq, hash, fullAt := c.ok, c.seq, c.hash, c.fullAt
	c.mu.Unlock()
	if !ok || fullAt.IsZero() || time.Since(fullAt) > auditFullVerifyEvery {
		return s.VerifyAudit(ctx)
	}
	var cur string
	err := s.db.QueryRowContext(ctx, `SELECT hash FROM audit WHERE seq=?`, seq).Scan(&cur)
	if errors.Is(err, sql.ErrNoRows) {
		// Pruned past the cached link (retention): start again from the anchor.
		return s.VerifyAudit(ctx)
	}
	if err != nil {
		return ChainResult{}, err
	}
	if cur != hash {
		return s.VerifyAudit(ctx)
	}
	res, last, err := s.verifyAfter(ctx, hash, seq)
	if err == nil {
		s.chain.remember(res, last, false)
	}
	return res, err
}

// verifyAfter checks every event with seq > n, starting from link prev.
func (s *Store) verifyAfter(ctx context.Context, prev string, n int64) (ChainResult, string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT seq,ts,actor,action,object_type,object_id,outcome,package_id,details,prev_hash,hash FROM audit WHERE seq > ? ORDER BY seq ASC`, n)
	if err != nil {
		return ChainResult{}, "", err
	}
	defer rows.Close()
	for rows.Next() {
		var e AuditEvent
		var d string
		if err := rows.Scan(&e.Seq, &e.TS, &e.Actor, &e.Action, &e.ObjectType, &e.ObjectID, &e.Outcome, &e.PackageID, &d, &e.PrevHash, &e.Hash); err != nil {
			return ChainResult{}, "", err
		}
		e.Details = json.RawMessage(d)
		n++
		switch {
		case e.Seq != n:
			return ChainResult{Count: n, FirstBadSeq: e.Seq, Error: "sequence gap"}, "", nil
		case e.PrevHash != prev:
			return ChainResult{Count: n, FirstBadSeq: e.Seq, Error: "prev_hash mismatch"}, "", nil
		case chainHash(prev, e) != e.Hash:
			return ChainResult{Count: n, FirstBadSeq: e.Seq, Error: "hash mismatch (event modified)"}, "", nil
		}
		prev = e.Hash
	}
	return ChainResult{OK: true, Count: n}, prev, rows.Err()
}

// ChainHash recomputes an event's hash (exported for off-box verification).
func ChainHash(prev string, e AuditEvent) string { return chainHash(prev, e) }
