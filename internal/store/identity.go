package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
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
}

// CertIssuer signs a client certificate for endpointID and returns the PEM,
// serial (lowercase hex) and expiry (RFC 3339).
type CertIssuer func(endpointID string) (certPEM, serial, notAfter string, err error)

// Enroll consumes a one-time token and creates the endpoint identity: a
// per-device secret (lab/HTTP mode) and, when issue is non-nil, an mTLS
// client certificate bound to the endpoint.
func (s *Store) Enroll(ctx context.Context, r EnrollRequest, issue CertIssuer) (endpointID, secret, certPEM string, err error) {
	if strings.TrimSpace(r.Hostname) == "" {
		return "", "", "", Errf(ErrInvalid, "hostname required")
	}
	th := HashSecret(r.Token)
	err = s.tx(ctx, func(tx *sql.Tx) error {
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
		s.Audit(ctx, Ev{Actor: "agent:" + r.Hostname, Action: "endpoint.enroll_denied", ObjectType: "endpoint", ObjectID: r.Hostname, Failure: true,
			Details: map[string]any{"reason": "token invalid, used or expired"}})
		return "", "", "", Errf(ErrInvalid, "enrollment token invalid, used or expired")
	}
	return endpointID, secret, certPEM, err
}

var errEnrollDenied = errors.New("enroll denied")

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
func (s *Store) CheckEndpointCert(ctx context.Context, endpointID, serial string) error {
	var cur, retired string
	err := s.db.QueryRowContext(ctx, `SELECT cert_serial, retired_at FROM endpoints WHERE endpoint_id=?`, endpointID).Scan(&cur, &retired)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if retired != "" || cur == "" || cur != strings.ToLower(serial) {
		return ErrNotFound
	}
	return nil
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
		if _, err := tx.Exec(`UPDATE endpoints SET cert_serial=?, cert_not_after=? WHERE endpoint_id=?`, serial, notAfter, endpointID); err != nil {
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
	err := s.tx(ctx, func(tx *sql.Tx) error {
		e, err := getEndpoint(ctx, tx, id)
		if err != nil {
			return err
		}
		if e.RetiredAt != "" {
			return Errf(ErrConflict, "endpoint already retired")
		}
		now := s.now()
		if _, err := tx.Exec(`UPDATE endpoints SET retired_at=?, retired_reason=?, cert_serial='', secret_hash=? WHERE endpoint_id=?`,
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
	})
	return out, err
}
