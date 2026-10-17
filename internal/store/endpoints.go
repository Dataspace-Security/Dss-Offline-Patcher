package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type InventoryItem struct {
	Kind    string `json:"kind"` // "kb" | "product"
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	// Source is "appstore" for macOS apps installed from the Mac App Store.
	Source string `json:"source,omitempty"`
}

type Endpoint struct {
	EndpointID        string   `json:"endpoint_id"`
	Hostname          string   `json:"hostname"`
	OS                string   `json:"os"`
	OSVersion         string   `json:"os_version"`
	Build             int      `json:"build"`
	Arch              string   `json:"arch"`
	Groups            []string `json:"groups"`
	Site              string   `json:"site"`
	Owner             string   `json:"owner"`
	Criticality       string   `json:"criticality"`
	LastSeen          string   `json:"last_seen"`
	InventoryAt       string   `json:"inventory_at"`
	RebootPending     bool     `json:"reboot_pending"`
	AgentVersion      string   `json:"agent_version"`
	EnrolledAt        string   `json:"enrolled_at"`
	Edition           string   `json:"edition"`
	RebootRequestedAt string   `json:"reboot_requested_at"`
	CertNotAfter      string   `json:"cert_not_after"`
	RetiredAt         string   `json:"retired_at"`
	RetiredReason     string   `json:"retired_reason"`
	Status            string   `json:"status"`

	inventory []InventoryItem
}

type EndpointDetail struct {
	Endpoint
	Inventory []InventoryItem `json:"inventory"`
	Targets   []Target        `json:"targets"`
}

const endpointCols = `endpoint_id,hostname,os,os_version,build,arch,groups,site,owner,criticality,last_seen,inventory_at,reboot_pending,agent_version,enrolled_at,inventory,cert_not_after,retired_at,retired_reason,edition,reboot_requested_at`

func scanEndpoint(sc interface{ Scan(...any) error }) (Endpoint, error) {
	var e Endpoint
	var groups, inv string
	var rp int
	err := sc.Scan(&e.EndpointID, &e.Hostname, &e.OS, &e.OSVersion, &e.Build, &e.Arch, &groups, &e.Site, &e.Owner, &e.Criticality,
		&e.LastSeen, &e.InventoryAt, &rp, &e.AgentVersion, &e.EnrolledAt, &inv, &e.CertNotAfter, &e.RetiredAt, &e.RetiredReason, &e.Edition, &e.RebootRequestedAt)
	if err != nil {
		return e, err
	}
	e.RebootPending = rp == 1
	json.Unmarshal([]byte(groups), &e.Groups)
	e.Groups = nonNil(e.Groups)
	json.Unmarshal([]byte(inv), &e.inventory)
	return e, nil
}

func getEndpoint(ctx context.Context, q querier, id string) (Endpoint, error) {
	e, err := scanEndpoint(q.QueryRowContext(ctx, `SELECT `+endpointCols+` FROM endpoints WHERE endpoint_id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return e, Errf(ErrNotFound, "endpoint %s", id)
	}
	return e, err
}

func listEndpoints(ctx context.Context, q querier) ([]Endpoint, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+endpointCols+` FROM endpoints ORDER BY hostname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Endpoint{}
	for rows.Next() {
		e, err := scanEndpoint(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---- status derivation (docs/03-state-model.md) ----

// Thresholds for silence. Silence is never compliance.
type Thresholds struct {
	OfflineAfter time.Duration
	StaleAfter   time.Duration
}

var DefaultThresholds = Thresholds{OfflineAfter: 30 * time.Minute, StaleAfter: 24 * time.Hour}

func (s *Store) deriveStatus(e Endpoint, targets []Target, th Thresholds) string {
	now := s.Now()
	if e.RetiredAt != "" {
		return "retired"
	}
	if now.Sub(parseTime(e.LastSeen)) > th.OfflineAfter {
		return "offline"
	}
	if e.InventoryAt == "" || now.Sub(parseTime(e.InventoryAt)) > th.StaleAfter {
		return "stale"
	}
	has := map[string]bool{}
	for _, t := range targets {
		has[t.State] = true
	}
	switch {
	case has["failed"]:
		return "failed"
	case e.RebootPending || has["pending_reboot"]:
		return "pending_reboot"
	case has["exception"]:
		return "exception"
	case has["pending"] || has["downloading"] || has["downloaded"] || has["installing"] || has["installed"]:
		return "noncompliant"
	}
	return "compliant"
}

// relevantTargets: targets in deployments that still matter (not cancelled).
func relevantTargets(ctx context.Context, q querier, endpointID string) ([]Target, error) {
	where := `d.state != 'cancelled'`
	var args []any
	if endpointID != "" {
		where += ` AND t.endpoint_id=?`
		args = append(args, endpointID)
	}
	return queryTargets(ctx, q, where, args...)
}

func (s *Store) ListEndpoints(ctx context.Context, th Thresholds) ([]Endpoint, error) {
	eps, err := listEndpoints(ctx, s.db)
	if err != nil {
		return nil, err
	}
	ts, err := relevantTargets(ctx, s.db, "")
	if err != nil {
		return nil, err
	}
	byEP := map[string][]Target{}
	for _, t := range ts {
		byEP[t.EndpointID] = append(byEP[t.EndpointID], t)
	}
	for i := range eps {
		eps[i].Status = s.deriveStatus(eps[i], byEP[eps[i].EndpointID], th)
	}
	return eps, nil
}

func (s *Store) GetEndpoint(ctx context.Context, id string, th Thresholds) (EndpointDetail, error) {
	e, err := getEndpoint(ctx, s.db, id)
	if err != nil {
		return EndpointDetail{}, err
	}
	rel, err := relevantTargets(ctx, s.db, id)
	if err != nil {
		return EndpointDetail{}, err
	}
	all, err := queryTargets(ctx, s.db, `t.endpoint_id=?`, id)
	if err != nil {
		return EndpointDetail{}, err
	}
	e.Status = s.deriveStatus(e, rel, th)
	inv := e.inventory
	if inv == nil {
		inv = []InventoryItem{}
	}
	return EndpointDetail{Endpoint: e, Inventory: inv, Targets: all}, nil
}

type EndpointPatch struct {
	Groups      *[]string `json:"groups"`
	Site        *string   `json:"site"`
	Owner       *string   `json:"owner"`
	Criticality *string   `json:"criticality"`
}

func cleanGroups(gs []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, g := range gs {
		g = strings.ToLower(strings.TrimSpace(g))
		if g != "" && !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	return out
}

func (s *Store) UpdateEndpoint(ctx context.Context, actor, id string, p EndpointPatch) (Endpoint, error) {
	var out Endpoint
	err := s.tx(ctx, func(tx *sql.Tx) error {
		e, err := getEndpoint(ctx, tx, id)
		if err != nil {
			return err
		}
		changes := map[string]any{}
		if p.Groups != nil {
			e.Groups = cleanGroups(*p.Groups)
			changes["groups"] = e.Groups
		}
		if p.Site != nil {
			e.Site = strings.TrimSpace(*p.Site)
			changes["site"] = e.Site
		}
		if p.Owner != nil {
			e.Owner = strings.TrimSpace(*p.Owner)
			changes["owner"] = e.Owner
		}
		if p.Criticality != nil {
			e.Criticality = strings.TrimSpace(*p.Criticality)
			changes["criticality"] = e.Criticality
		}
		if _, err := tx.Exec(`UPDATE endpoints SET groups=?, site=?, owner=?, criticality=? WHERE endpoint_id=?`, mustJSON(e.Groups), e.Site, e.Owner, e.Criticality, id); err != nil {
			return err
		}
		if err := s.audit(tx, Ev{Actor: actor, Action: "endpoint.updated", ObjectType: "endpoint", ObjectID: id, Details: changes}); err != nil {
			return err
		}
		// Group changes may bring the endpoint into a ring of an active deployment.
		if err := s.ensureTargetsForEndpoint(ctx, tx, e); err != nil {
			return err
		}
		out = e
		return nil
	})
	return out, err
}

// ---- enrollment ----

type EnrollmentToken struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
	MaxUses   int    `json:"max_uses"`
}

// CreateEnrollmentToken: maxUses 1 (default) is a per-device token; larger
// values allow mass rollout (GPO/SCCM/Intune) for one site and group set.
func (s *Store) CreateEnrollmentToken(ctx context.Context, actor string, groups []string, site string, hours, maxUses int) (EnrollmentToken, error) {
	if maxUses <= 0 {
		maxUses = 1
	}
	if maxUses > 10000 {
		return EnrollmentToken{}, Errf(ErrInvalid, "max_uses must be <= 10000")
	}
	if maxUses > 1 && hours > 24*14 {
		return EnrollmentToken{}, Errf(ErrInvalid, "multi-use tokens may be valid for at most 336 hours (14 days)")
	}
	if hours <= 0 {
		hours = 24
	}
	if hours > 24*30 {
		return EnrollmentToken{}, Errf(ErrInvalid, "expires_in_hours must be <= 720")
	}
	tok := "enr_" + RandomSecret()
	exp := s.Now().Add(time.Duration(hours) * time.Hour).UTC().Format(time.RFC3339)
	g := cleanGroups(groups)
	err := s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO enrollment_tokens(token_hash,groups,site,expires_at,created_by,created_at,max_uses) VALUES(?,?,?,?,?,?,?)`,
			HashSecret(tok), mustJSON(g), site, exp, actor, s.now(), maxUses); err != nil {
			return err
		}
		return s.audit(tx, Ev{Actor: actor, Action: "enrollment_token.created", ObjectType: "enrollment_token", ObjectID: HashSecret(tok)[:12],
			Details: map[string]any{"groups": g, "site": site, "expires_at": exp, "max_uses": maxUses}})
	})
	return EnrollmentToken{Token: tok, ExpiresAt: exp, MaxUses: maxUses}, err
}
