package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
)

type EnrollRequest struct {
	Token        string `json:"token"`
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	OSVersion    string `json:"os_version"`
	Build        int    `json:"build"`
	Arch         string `json:"arch"`
	AgentVersion string `json:"agent_version"`
	CSR          string `json:"csr"` // PEM; required when the server runs with TLS
	// Source is the caller's address, set by the server (never from JSON).
	Source string `json:"-"`
}

// CertIssuer signs a client certificate for endpointID and returns the PEM,
// serial (lowercase hex) and expiry (RFC 3339).
type CertIssuer func(endpointID string) (certPEM, serial, notAfter string, err error)

// Enroll consumes a one-time token and creates the endpoint identity: a
// per-device secret (lab/HTTP mode) and, when issue is non-nil, an mTLS
// client certificate bound to the endpoint.
func (s *Store) Enroll(ctx context.Context, r EnrollRequest, issue CertIssuer) (endpointID, secret, certPEM string, err error) {
	if err := ValidHostname(r.Hostname); err != nil {
		return "", "", "", err
	}
	th := HashSecret(r.Token)
	err = s.txChanged(ctx, func(tx *sql.Tx) error {
		var groups, site, exp, used string
		var uses, maxUses int
		err := tx.QueryRow(`SELECT groups, site, expires_at, used_at, uses, max_uses FROM enrollment_tokens WHERE token_hash=?`, th).Scan(&groups, &site, &exp, &used, &uses, &maxUses)
		if errors.Is(err, sql.ErrNoRows) {
			return errEnrollDenied
		}
		if err != nil {
			return err
		}
		if maxUses < 1 {
			maxUses = 1
		}
		if uses >= maxUses || (maxUses == 1 && used != "") || s.Now().After(parseTime(exp)) {
			return errEnrollDenied
		}
		endpointID = NewID("e-")
		secret = "dev_" + RandomSecret()
		var serial, notAfter string
		if issue != nil {
			certPEM, serial, notAfter, err = issue(endpointID)
			if err != nil {
				return Errf(ErrInvalid, "certificate request rejected: %v", err)
			}
		}
		now := s.now()
		if _, err := tx.Exec(`UPDATE enrollment_tokens SET used_at=?, used_by=?, uses=uses+1 WHERE token_hash=?`, now, endpointID, th); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO endpoints(endpoint_id,hostname,os,os_version,build,arch,groups,site,last_seen,agent_version,enrolled_at,secret_hash,cert_serial,cert_not_after) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			endpointID, r.Hostname, r.OS, r.OSVersion, r.Build, r.Arch, groups, site, now, r.AgentVersion, now, HashSecret(secret), serial, notAfter); err != nil {
			return err
		}
		return s.audit(tx, Ev{Actor: "agent:" + r.Hostname, Action: "endpoint.enrolled", ObjectType: "endpoint", ObjectID: endpointID,
			Details: map[string]any{"hostname": r.Hostname, "os_version": r.OSVersion, "build": r.Build, "arch": r.Arch, "site": site,
				"groups": json.RawMessage(groups), "cert_serial": serial, "cert_not_after": notAfter}})
	})
	if errors.Is(err, errEnrollDenied) {
		// Unauthenticated callers can repeat this at will: at most one audit
		// event per source per deniedAuditEvery, counting those folded in.
		if n, ok := s.enrollDenied.take(r.Source, s.Now()); ok {
			s.Audit(ctx, Ev{Actor: "agent:" + r.Hostname, Action: "endpoint.enroll_denied", ObjectType: "endpoint", ObjectID: r.Hostname, Failure: true,
				Details: map[string]any{"reason": "token invalid, used or expired", "source": r.Source, "suppressed_before": n}})
		}
		return "", "", "", ErrEnrollDenied
	}
	return endpointID, secret, certPEM, err
}

var errEnrollDenied = errors.New("enroll denied")

// ErrEnrollDenied is returned for an unknown, used or expired token.
var ErrEnrollDenied = Errf(ErrInvalid, "enrollment token invalid, used or expired")

// MaxHostnameLen is the DNS limit for a fully qualified name.
const MaxHostnameLen = 253

// ValidHostname accepts DNS / NetBIOS style names: 1-253 characters of
// letters, digits, '.', '-' and '_'.
func ValidHostname(h string) error {
	if h == "" || len(h) > MaxHostnameLen {
		return Errf(ErrInvalid, "hostname must be 1-%d characters", MaxHostnameLen)
	}
	for _, c := range h {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '-', c == '_':
		default:
			return Errf(ErrInvalid, "hostname may only contain letters, digits, '.', '-' and '_'")
		}
	}
	return nil
}

// deniedAuditEvery: one enroll_denied audit event per source per interval.
const deniedAuditEvery = time.Minute

// deniedAudits throttles audit events for denied enrollments by source.
type deniedAudits struct {
	mu   sync.Mutex
	last map[string]deniedEntry
}

type deniedEntry struct {
	at         time.Time
	suppressed int
}

// take reports whether an audit event may be written for source now, and
// how many denials were suppressed since the previous one.
func (d *deniedAudits) take(source string, now time.Time) (int, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.last == nil {
		d.last = map[string]deniedEntry{}
	}
	e, seen := d.last[source]
	if seen && now.Sub(e.at) < deniedAuditEvery {
		e.suppressed++
		d.last[source] = e
		return 0, false
	}
	if len(d.last) >= 10000 { // bound memory: forget sources past their interval
		for k, v := range d.last {
			if now.Sub(v.at) >= deniedAuditEvery {
				delete(d.last, k)
			}
		}
	}
	d.last[source] = deniedEntry{at: now}
	return e.suppressed, true
}

// EnrollmentTokenUsable reports whether tok exists, has not expired and has
// uses left. It does not consume a use; Enroll does that.
func (s *Store) EnrollmentTokenUsable(ctx context.Context, tok string) bool {
	if !strings.HasPrefix(tok, "enr_") {
		return false
	}
	var exp, used string
	var uses, maxUses int
	err := s.db.QueryRowContext(ctx, `SELECT expires_at, used_at, uses, max_uses FROM enrollment_tokens WHERE token_hash=?`, HashSecret(tok)).Scan(&exp, &used, &uses, &maxUses)
	if err != nil {
		return false
	}
	if maxUses < 1 {
		maxUses = 1
	}
	return uses < maxUses && !(maxUses == 1 && used != "") && !s.Now().After(parseTime(exp))
}

// EndpointIDBySecret authenticates an agent in lab (HTTP) mode.
func (s *Store) EndpointIDBySecret(ctx context.Context, secret string) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT endpoint_id FROM endpoints WHERE secret_hash=? AND retired_at=''`, HashSecret(secret)).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return id, err
}

// CheckEndpointCert authenticates an agent by mTLS: the certificate's
// subject must be an active endpoint whose current serial matches. Older
// (renewed) and retired endpoints' certificates are rejected.
//
// After a renewal the previous serial stays valid until the new one is first
// used, so an agent that lost the renewal response (or stopped before saving
// the new certificate) is not locked out.
func (s *Store) CheckEndpointCert(ctx context.Context, endpointID, serial string) error {
	var cur, prev, retired string
	err := s.db.QueryRowContext(ctx, `SELECT cert_serial, prev_cert_serial, retired_at FROM endpoints WHERE endpoint_id=?`, endpointID).Scan(&cur, &prev, &retired)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	serial = strings.ToLower(serial)
	switch {
	case retired != "" || serial == "":
		return ErrNotFound
	case cur == serial:
		if prev != "" {
			// First use of the renewed certificate: the old one stops working.
			if _, err := s.db.ExecContext(ctx, `UPDATE endpoints SET prev_cert_serial='' WHERE endpoint_id=? AND cert_serial=?`, endpointID, cur); err != nil {
				return err
			}
		}
		return nil
	case prev == serial:
		return nil
	}
	return ErrNotFound
}

// RenewCert replaces an endpoint's client certificate.
func (s *Store) RenewCert(ctx context.Context, endpointID string, issue CertIssuer) (string, error) {
	var out string
	err := s.tx(ctx, func(tx *sql.Tx) error {
		e, err := getEndpoint(ctx, tx, endpointID)
		if err != nil {
			return err
		}
		if e.RetiredAt != "" {
			return Errf(ErrConflict, "endpoint retired")
		}
		certPEM, serial, notAfter, err := issue(endpointID)
		if err != nil {
			return Errf(ErrInvalid, "certificate request rejected: %v", err)
		}
		// Grace: the certificate the agent holds stays valid until the new one
		// is used. If an earlier renewal was never used, the agent still holds
		// the older certificate, so that one stays the fallback.
		if _, err := tx.Exec(`UPDATE endpoints SET prev_cert_serial=CASE WHEN prev_cert_serial='' THEN cert_serial ELSE prev_cert_serial END,
			cert_serial=?, cert_not_after=? WHERE endpoint_id=?`, serial, notAfter, endpointID); err != nil {
			return err
		}
		out = certPEM
		return s.audit(tx, Ev{Actor: "endpoint:" + endpointID, Action: "endpoint.cert_renewed", ObjectType: "endpoint", ObjectID: endpointID,
			Details: map[string]any{"cert_serial": serial, "cert_not_after": notAfter}})
	})
	return out, err
}

// RetireEndpoint decommissions an endpoint: its credentials stop working
// immediately, outstanding targets are closed, and history is kept.
func (s *Store) RetireEndpoint(ctx context.Context, actor, id, reason string) (Endpoint, error) {
	if err := requireReason(reason); err != nil {
		return Endpoint{}, err
	}
	var out Endpoint
	err := s.txChanged(ctx, func(tx *sql.Tx) error {
		var err error
		out, err = s.retireEndpointTx(ctx, tx, actor, id, reason)
		return err
	})
	return out, err
}

// retireEndpointTx is RetireEndpoint inside tx.
func (s *Store) retireEndpointTx(ctx context.Context, tx *sql.Tx, actor, id, reason string) (Endpoint, error) {
	var out Endpoint
	err := func() error {
		e, err := getEndpoint(ctx, tx, id)
		if err != nil {
			return err
		}
		if e.RetiredAt != "" {
			return Errf(ErrConflict, "endpoint already retired")
		}
		now := s.now()
		if _, err := tx.Exec(`UPDATE endpoints SET retired_at=?, retired_reason=?, cert_serial='', prev_cert_serial='', secret_hash=? WHERE endpoint_id=?`,
			now, reason, "retired:"+RandomSecret(), id); err != nil {
			return err
		}
		if err := s.audit(tx, Ev{Actor: actor, Action: "endpoint.retired", ObjectType: "endpoint", ObjectID: id,
			Details: map[string]any{"hostname": e.Hostname, "reason": reason}}); err != nil {
			return err
		}
		ts, err := queryTargets(ctx, tx, `t.endpoint_id=? AND d.state IN ('active','paused') AND t.state NOT IN ('verified','not_applicable','exception')`, id)
		if err != nil {
			return err
		}
		for _, t := range ts {
			if err := s.setTarget(tx, actor, t, "not_applicable", "endpoint retired: "+reason, t.ExitCode, 0); err != nil {
				return err
			}
			if err := s.evaluateDeployment(ctx, tx, t.DeploymentID, false); err != nil {
				return err
			}
		}
		out, err = getEndpoint(ctx, tx, id)
		out.Status = "retired"
		return err
	}()
	return out, err
}
