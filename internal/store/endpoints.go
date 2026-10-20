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
	Kind    string `json:"kind"` // "kb" | "product" | "appx" (Windows Store/MSIX) | macOS kinds
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	// Source is "appstore" for macOS apps installed from the Mac App Store.
	Source string `json:"source,omitempty"`
	// Scope is "user" for a per-user install found in a loaded user hive
	// (HKU\<SID>\...\Uninstall), empty for a machine-wide install. Both
	// count the same for needs, targeting and verification.
	Scope string `json:"scope,omitempty"`
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
	Hardware          Hardware `json:"hardware"`
	// Missing is filled by the API (update intelligence + catalog); nil
	// without intelligence and nothing ready to deploy.
	Missing *EndpointMissing `json:"missing"`

	inventory []InventoryItem
}

// EndpointMissing: Windows updates and newer app versions the update
// intelligence says the endpoint lacks, and approved catalog packages it
// needs (ready to deploy).
type EndpointMissing struct {
	OS    int `json:"os"`
	Apps  int `json:"apps"`
	Ready int `json:"ready"`
	// Catalog: approved or quarantined catalog packages it needs (Ready
	// counts the approved ones). An endpoint is fully up to date only with
	// os, apps and catalog all 0.
	Catalog int `json:"catalog"`
	// OSSupport: "supported", "out_of_support" (Microsoft no longer ships
	// updates for this Windows build) or "" (unknown); OSLastUpdate is the
	// release date of its newest cumulative update.
	OSSupport    string `json:"os_support,omitempty"`
	OSLastUpdate string `json:"os_last_update,omitempty"`
}

// InventoryItems is the endpoint's last reported inventory (loaded by
// ListEndpoints and GetEndpoint).
func (e Endpoint) InventoryItems() []InventoryItem { return e.inventory }

type EndpointDetail struct {
	Endpoint
	Inventory []InventoryItem `json:"inventory"`
	Targets   []Target        `json:"targets"`
}

const endpointCols = `endpoint_id,hostname,os,os_version,build,arch,groups,site,owner,criticality,last_seen,inventory_at,reboot_pending,agent_version,enrolled_at,inventory,cert_not_after,retired_at,retired_reason,edition,reboot_requested_at,hardware`

func scanEndpoint(sc interface{ Scan(...any) error }) (Endpoint, error) {
	var e Endpoint
	var groups, inv, hw string
	var rp int
	err := sc.Scan(&e.EndpointID, &e.Hostname, &e.OS, &e.OSVersion, &e.Build, &e.Arch, &groups, &e.Site, &e.Owner, &e.Criticality,
		&e.LastSeen, &e.InventoryAt, &rp, &e.AgentVersion, &e.EnrolledAt, &inv, &e.CertNotAfter, &e.RetiredAt, &e.RetiredReason, &e.Edition, &e.RebootRequestedAt, &hw)
	if err != nil {
		return e, err
	}
	e.RebootPending = rp == 1
	json.Unmarshal([]byte(groups), &e.Groups)
	e.Groups = nonNil(e.Groups)
	json.Unmarshal([]byte(inv), &e.inventory)
	json.Unmarshal([]byte(hw), &e.Hardware)
	return e, nil
}

func getEndpoint(ctx context.Context, q querier, id string) (Endpoint, error) {
	e, err := scanEndpoint(q.QueryRowContext(ctx, `SELECT `+endpointCols+` FROM endpoints WHERE endpoint_id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return e, Errf(ErrNotFound, "endpoint %s", id)
	}
	return e, err
}

// endpointColsBrief skips the inventory document: list, summary and sweep
// paths need status, not every endpoint's parsed inventory.
var endpointColsBrief = strings.Replace(endpointCols, ",inventory,", ",'[]',", 1)

func listEndpoints(ctx context.Context, q querier) ([]Endpoint, error) {
	return listEndpointsCols(ctx, q, endpointCols)
}

func listEndpointsCols(ctx context.Context, q querier, cols string) ([]Endpoint, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+cols+` FROM endpoints ORDER BY hostname`)
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
	// LostAfterInstall: an endpoint silent this long after reporting
	// installed / pending_reboot (or after its reboot request) is
	// lost_after_install (0 = never).
	LostAfterInstall time.Duration
	// StuckAfter: a target downloading/downloaded/installing with no report
	// and no endpoint activity this long is failed (0 = DefaultStuckAfter).
	StuckAfter time.Duration
}

// AwaitingCheckinFor: how long after enrollment an endpoint that never sent
// an inventory is awaiting_checkin before it counts as offline.
const AwaitingCheckinFor = 24 * time.Hour

var DefaultThresholds = Thresholds{OfflineAfter: 30 * time.Minute, StaleAfter: 24 * time.Hour, LostAfterInstall: 2 * time.Hour}

func (s *Store) deriveStatus(e Endpoint, targets []Target, th Thresholds) string {
	now := s.Now()
	if e.RetiredAt != "" {
		return "retired"
	}
	has := map[string]bool{}
	for _, t := range targets {
		if t.Operation == "rollback" && t.State != "failed" && t.State != "pending_reboot" && t.State != "lost_after_install" {
			continue // a rollback in progress does not make the endpoint noncompliant
		}
		has[t.State] = true
	}
	// An endpoint that went silent right after an install is the loudest signal.
	if has["lost_after_install"] {
		return "lost_after_install"
	}
	if e.InventoryAt == "" {
		// Enrolled but never checked in with an inventory: a new machine
		// whose agent is still starting, not a silent one. Not compliant, not
		// alerted on; after AwaitingCheckinFor it is offline.
		if now.Sub(parseTime(e.EnrolledAt)) <= AwaitingCheckinFor {
			return "awaiting_checkin"
		}
		return "offline"
	}
	if now.Sub(parseTime(e.LastSeen)) > th.OfflineAfter {
		return "offline"
	}
	if e.InventoryAt == "" || now.Sub(parseTime(e.InventoryAt)) > th.StaleAfter {
		return "stale"
	}
	switch {
	case has["failed"]:
		return "failed"
	case e.RebootPending || has["pending_reboot"]:
		return "pending_reboot"
	case has["exception"]:
		return "exception"
	case has["pending"] || has["deferred"] || has["downloading"] || has["downloaded"] || has["installing"] || has["installed"]:
		return "noncompliant"
	}
	return "compliant"
}

// EndpointStatuses lists every status an active endpoint can have (the
// summary reports each, zero or not). updates_available and out_of_support
// are set by the API from update intelligence (they refine compliant).
var EndpointStatuses = []string{"compliant", "updates_available", "out_of_support", "noncompliant", "pending_reboot", "failed", "exception",
	"stale", "offline", "lost_after_install", "awaiting_checkin"}

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

// ListEndpoints returns every endpoint with its derived status and its
// inventory (InventoryItems).
func (s *Store) ListEndpoints(ctx context.Context, th Thresholds) ([]Endpoint, error) {
	return s.listEndpointStatus(ctx, th, endpointCols)
}

// ListEndpointsBrief is ListEndpoints without loading inventories.
func (s *Store) ListEndpointsBrief(ctx context.Context, th Thresholds) ([]Endpoint, error) {
	return s.listEndpointStatus(ctx, th, endpointColsBrief)
}

func (s *Store) listEndpointStatus(ctx context.Context, th Thresholds, cols string) ([]Endpoint, error) {
	eps, err := listEndpointsCols(ctx, s.db, cols)
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
	err := s.txChanged(ctx, func(tx *sql.Tx) error {
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

// Hardware is the endpoint's hardware and system snapshot, reported by the
// agent on check-in (all optional; fields an OS can't provide stay empty).
type Hardware struct {
	Manufacturer string     `json:"manufacturer,omitempty"`
	Model        string     `json:"model,omitempty"`
	SerialNumber string     `json:"serial_number,omitempty"`
	CPU          string     `json:"cpu,omitempty"`
	CPUCores     int        `json:"cpu_cores,omitempty"`
	MemoryBytes  int64      `json:"memory_bytes,omitempty"`
	Disks        []DiskInfo `json:"disks,omitempty"`
	IPAddresses  []string   `json:"ip_addresses,omitempty"`
	MACAddress   string     `json:"mac_address,omitempty"`
	BootTime     string     `json:"boot_time,omitempty"` // RFC 3339
	LoggedInUser string     `json:"logged_in_user,omitempty"`
	Timezone     string     `json:"timezone,omitempty"`
}

type DiskInfo struct {
	Mount      string `json:"mount"` // "/", "C:"
	TotalBytes int64  `json:"total_bytes"`
	FreeBytes  int64  `json:"free_bytes"`
}

// clean bounds what an agent can store (the report is untrusted input).
func (h Hardware) clean() Hardware {
	cut := func(s string, n int) string {
		s = strings.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f {
				return -1
			}
			return r
		}, strings.TrimSpace(s))
		if len(s) > n {
			s = s[:n]
		}
		return s
	}
	h.Manufacturer, h.Model, h.SerialNumber, h.CPU = cut(h.Manufacturer, 100), cut(h.Model, 100), cut(h.SerialNumber, 64), cut(h.CPU, 128)
	h.MACAddress, h.BootTime, h.LoggedInUser, h.Timezone = cut(h.MACAddress, 32), cut(h.BootTime, 40), cut(h.LoggedInUser, 100), cut(h.Timezone, 64)
	if h.CPUCores < 0 || h.CPUCores > 4096 {
		h.CPUCores = 0
	}
	if h.MemoryBytes < 0 {
		h.MemoryBytes = 0
	}
	if len(h.Disks) > 16 {
		h.Disks = h.Disks[:16]
	}
	for i := range h.Disks {
		h.Disks[i].Mount = cut(h.Disks[i].Mount, 64)
	}
	if len(h.IPAddresses) > 16 {
		h.IPAddresses = h.IPAddresses[:16]
	}
	for i := range h.IPAddresses {
		h.IPAddresses[i] = cut(h.IPAddresses[i], 64)
	}
	return h
}
