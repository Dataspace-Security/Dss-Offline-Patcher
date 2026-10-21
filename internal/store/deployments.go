package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"offpatch/internal/manifest"
)

type Ring struct {
	Name   string   `json:"name"`
	Groups []string `json:"groups"`
}

type NewDeployment struct {
	PackageID     string `json:"package_id"`
	Name          string `json:"name"`
	Rings         []Ring `json:"rings"`
	MaxFailurePct int    `json:"max_failure_pct"`
	MaxRetries    int    `json:"max_retries"`
	WindowStart   string `json:"window_start"`
	WindowEnd     string `json:"window_end"`
	Emergency     bool   `json:"emergency"`
	Justification string `json:"justification"`
	// Deadline (RFC 3339, optional): after it, endpoint maintenance windows
	// no longer hold the install back.
	Deadline string `json:"deadline"`
	// MaxConcurrent caps endpoints downloading/installing at once (0 = no cap).
	MaxConcurrent int `json:"max_concurrent"`
	// RebootPolicy: never | in_window (reboot inside a window that allows
	// reboots) | at_deadline (in a window, or anytime once past the deadline).
	RebootPolicy  string        `json:"reboot_policy"`
	IgnoreWindows bool          `json:"ignore_windows"`
	HealthChecks  []HealthCheck `json:"health_checks"`
	// Operation: install (default) | rollback (agents uninstall the package;
	// msu, msi, deb and rpm only — see RollbackUnsupported).
	Operation string `json:"operation"`
	// AutoAdvance: when the current ring is finished and stayed within the
	// failure threshold, move on to the next ring without an operator
	// ("first machines, then everything else"). Off by default: rings wait
	// for an explicit advance.
	AutoAdvance bool `json:"auto_advance"`
}

// HealthCheck is a fixed, non-executable post-install check (no arbitrary
// commands: the agent offers no remote execution).
type HealthCheck struct {
	Type string `json:"type"` // service_running | tcp_listening
	Name string `json:"name"` // service name, or port number
}

type Deployment struct {
	NewDeployment
	DeploymentID string         `json:"deployment_id"`
	State        string         `json:"state"`
	CurrentRing  int            `json:"current_ring"`
	StateReason  string         `json:"state_reason"`
	CreatedBy    string         `json:"created_by"`
	CreatedAt    string         `json:"created_at"`
	UpdatedAt    string         `json:"updated_at"`
	Counts       map[string]int `json:"counts"`
	// Two-person approval (deploy_approval.go): a deployment starts in
	// pending_approval and becomes active once ApprovalsRequired different
	// people (not the creator) approved it. ApprovalsRequired 0: created
	// before approvals existed. ActivatedAt: when it started.
	Approvals         []Approval `json:"approvals"`
	ApprovalsRequired int        `json:"approvals_required"`
	RejectedBy        string     `json:"rejected_by"`
	RejectedAt        string     `json:"rejected_at"`
	ActivatedAt       string     `json:"activated_at"`
	// Approved scope (deploy_scope.go): endpoints fixed at activation, and
	// endpoints that joined a ring group afterwards and were left out.
	ScopeEndpoints int `json:"scope_endpoints"`
	ScopeExcluded  int `json:"scope_excluded"`
}

type DeploymentDetail struct {
	Deployment
	Targets []Target `json:"targets"`
}

type Target struct {
	DeploymentID string `json:"deployment_id"`
	PackageID    string `json:"package_id"`
	EndpointID   string `json:"endpoint_id"`
	Hostname     string `json:"hostname"`
	Ring         int    `json:"ring"`
	State        string `json:"state"`
	Attempts     int    `json:"attempts"`
	Detail       string `json:"detail"`
	ExitCode     int    `json:"exit_code"`
	UpdatedAt    string `json:"updated_at"`
	Health       string `json:"health"` // "" | ok | failed
	HealthDetail string `json:"health_detail"`
	Operation    string `json:"operation"` // of the deployment: install | rollback
	// Evidence (verified targets): the inventory line, or OS revision, that
	// proved the install (see presentOn; GET /api/reports/targets.csv).
	Evidence string `json:"evidence,omitempty"`
}

const depCols = `deployment_id,package_id,name,state,emergency,justification,rings,current_ring,max_failure_pct,max_retries,window_start,window_end,created_by,created_at,updated_at,state_reason,deadline,max_concurrent,reboot_policy,ignore_windows,health_checks,operation,auto_advance,approvals_required,rejected_by,rejected_at,activated_at`

func scanDeployment(sc interface{ Scan(...any) error }) (Deployment, error) {
	var d Deployment
	var em, iw, aa int
	var rings, hc string
	err := sc.Scan(&d.DeploymentID, &d.PackageID, &d.Name, &d.State, &em, &d.Justification, &rings, &d.CurrentRing, &d.MaxFailurePct, &d.MaxRetries,
		&d.WindowStart, &d.WindowEnd, &d.CreatedBy, &d.CreatedAt, &d.UpdatedAt, &d.StateReason, &d.Deadline, &d.MaxConcurrent, &d.RebootPolicy, &iw, &hc, &d.Operation, &aa,
		&d.ApprovalsRequired, &d.RejectedBy, &d.RejectedAt, &d.ActivatedAt)
	if err != nil {
		return d, err
	}
	d.Emergency, d.IgnoreWindows, d.AutoAdvance = em == 1, iw == 1, aa == 1
	json.Unmarshal([]byte(rings), &d.Rings)
	json.Unmarshal([]byte(hc), &d.HealthChecks)
	if d.HealthChecks == nil {
		d.HealthChecks = []HealthCheck{}
	}
	d.Counts = map[string]int{}
	d.Approvals = []Approval{}
	return d, nil
}

// getDeployment loads a deployment without target counts (hot paths).
func getDeployment(ctx context.Context, q querier, id string) (Deployment, error) {
	d, err := scanDeployment(q.QueryRowContext(ctx, `SELECT `+depCols+` FROM deployments WHERE deployment_id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return d, Errf(ErrNotFound, "deployment %s", id)
	}
	return d, err
}

// getDeploymentCounted also fills per-state target counts (API responses).
func getDeploymentCounted(ctx context.Context, q querier, id string) (Deployment, error) {
	d, err := getDeployment(ctx, q, id)
	if err != nil {
		return d, err
	}
	return d, fillCounts(ctx, q, &d)
}

func fillCounts(ctx context.Context, q querier, d *Deployment) error {
	if err := fillApprovals(ctx, q, d); err != nil {
		return err
	}
	if err := fillScope(ctx, q, d); err != nil {
		return err
	}
	rows, err := q.QueryContext(ctx, `SELECT state, COUNT(*) FROM targets WHERE deployment_id=? GROUP BY state`, d.DeploymentID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var st string
		var n int
		rows.Scan(&st, &n)
		d.Counts[st] = n
	}
	return rows.Err()
}

func queryTargets(ctx context.Context, q querier, where string, args ...any) ([]Target, error) {
	rows, err := q.QueryContext(ctx, `SELECT t.deployment_id,t.package_id,t.endpoint_id,e.hostname,t.ring,t.state,t.attempts,t.detail,t.exit_code,t.updated_at,t.health,t.health_detail,d.operation,t.evidence
		FROM targets t JOIN endpoints e ON e.endpoint_id=t.endpoint_id JOIN deployments d ON d.deployment_id=t.deployment_id
		WHERE `+where+` ORDER BY t.ring, e.hostname`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Target{}
	for rows.Next() {
		var t Target
		if err := rows.Scan(&t.DeploymentID, &t.PackageID, &t.EndpointID, &t.Hostname, &t.Ring, &t.State, &t.Attempts, &t.Detail, &t.ExitCode, &t.UpdatedAt, &t.Health, &t.HealthDetail, &t.Operation, &t.Evidence); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) ListDeployments(ctx context.Context) ([]Deployment, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+depCols+` FROM deployments ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	out := []Deployment{}
	for rows.Next() {
		d, err := scanDeployment(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, d)
	}
	rows.Close()
	for i := range out {
		if err := fillCounts(ctx, s.db, &out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Store) GetDeployment(ctx context.Context, id string) (DeploymentDetail, error) {
	d, err := getDeploymentCounted(ctx, s.db, id)
	if err != nil {
		return DeploymentDetail{}, err
	}
	ts, err := queryTargets(ctx, s.db, `t.deployment_id=?`, id)
	return DeploymentDetail{Deployment: d, Targets: ts}, err
}

func (s *Store) DeploymentsForPackage(ctx context.Context, packageID string) ([]DeploymentDetail, error) {
	all, err := s.ListDeployments(ctx)
	if err != nil {
		return nil, err
	}
	out := []DeploymentDetail{}
	for _, d := range all {
		if d.PackageID == packageID {
			dd, err := s.GetDeployment(ctx, d.DeploymentID)
			if err != nil {
				return nil, err
			}
			out = append(out, dd)
		}
	}
	return out, nil
}

var svcNameRe = regexp.MustCompile(`^[A-Za-z0-9_.$ -]{1,80}$`)

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

var hhmm = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)

func (n *NewDeployment) validate() error {
	var errs []string
	n.Name = strings.TrimSpace(n.Name)
	if n.Name == "" {
		errs = append(errs, "name required")
	}
	if len(n.Rings) == 0 || len(n.Rings) > 10 {
		errs = append(errs, "1-10 rings required")
	}
	for i := range n.Rings {
		n.Rings[i].Name = strings.TrimSpace(n.Rings[i].Name)
		n.Rings[i].Groups = cleanGroups(n.Rings[i].Groups)
		if n.Rings[i].Name == "" || len(n.Rings[i].Groups) == 0 {
			errs = append(errs, fmt.Sprintf("ring %d needs a name and at least one group", i+1))
		}
	}
	if n.MaxFailurePct < 0 || n.MaxFailurePct > 100 {
		errs = append(errs, "max_failure_pct must be 0-100")
	}
	if n.MaxRetries < 0 || n.MaxRetries > 10 {
		errs = append(errs, "max_retries must be 0-10")
	}
	if (n.WindowStart == "") != (n.WindowEnd == "") {
		errs = append(errs, "window_start and window_end must both be set or both empty")
	} else if n.WindowStart != "" && (!hhmm.MatchString(n.WindowStart) || !hhmm.MatchString(n.WindowEnd)) {
		errs = append(errs, "window times must be HH:MM (UTC)")
	}
	if n.Emergency && strings.TrimSpace(n.Justification) == "" {
		errs = append(errs, "emergency deployments require a justification")
	}
	if n.Deadline != "" {
		dl, err := time.Parse(time.RFC3339, n.Deadline)
		if err != nil {
			errs = append(errs, "deadline must be RFC 3339")
		} else {
			n.Deadline = dl.UTC().Format(time.RFC3339)
		}
	}
	if n.MaxConcurrent < 0 {
		errs = append(errs, "max_concurrent must be >= 0")
	}
	switch n.RebootPolicy {
	case "":
		n.RebootPolicy = "never"
	case "never", "in_window", "at_deadline":
	default:
		errs = append(errs, "reboot_policy must be never, in_window or at_deadline")
	}
	if n.RebootPolicy == "at_deadline" && n.Deadline == "" {
		errs = append(errs, "reboot_policy at_deadline needs a deadline")
	}
	switch n.Operation {
	case "":
		n.Operation = "install"
	case "install":
	case "rollback":
		if strings.TrimSpace(n.Justification) == "" {
			errs = append(errs, "rollback deployments require a justification")
		}
	default:
		errs = append(errs, "operation must be install or rollback")
	}
	if n.HealthChecks == nil {
		n.HealthChecks = []HealthCheck{}
	}
	if len(n.HealthChecks) > 20 {
		errs = append(errs, "at most 20 health checks")
	}
	for i, h := range n.HealthChecks {
		switch h.Type {
		case "service_running":
			if !svcNameRe.MatchString(h.Name) {
				errs = append(errs, fmt.Sprintf("health_checks[%d]: invalid service name", i))
			}
		case "tcp_listening":
			if p, err := strconv.Atoi(h.Name); err != nil || p < 1 || p > 65535 {
				errs = append(errs, fmt.Sprintf("health_checks[%d]: name must be a port number", i))
			}
		default:
			errs = append(errs, fmt.Sprintf("health_checks[%d]: type must be service_running or tcp_listening", i))
		}
	}
	if len(errs) > 0 {
		return Errf(ErrInvalid, "%s", strings.Join(errs, "; "))
	}
	return nil
}

// InWindow reports whether now (UTC) falls in [start,end); wraps midnight.
func InWindow(start, end string, now time.Time) bool {
	if start == "" {
		return true
	}
	cur := now.UTC().Format("15:04")
	if start <= end {
		return cur >= start && cur < end
	}
	return cur >= start || cur < end
}

func (s *Store) CreateDeployment(ctx context.Context, actor string, n NewDeployment) (Deployment, error) {
	if err := n.validate(); err != nil {
		return Deployment{}, err
	}
	var out Deployment
	err := s.txChanged(ctx, func(tx *sql.Tx) error {
		p, err := getPackage(ctx, tx, n.PackageID)
		if err != nil {
			return err
		}
		rollback := n.Operation == "rollback"
		switch {
		case rollback && p.State != "approved" && p.State != "revoked":
			return Errf(ErrConflict, "package %s is %s; only approved or revoked packages can be rolled back", p.PackageID, p.State)
		case !rollback && p.State != "approved":
			return Errf(ErrConflict, "package %s is %s; only approved packages can be deployed", p.PackageID, p.State)
		}
		if rollback {
			if why := RollbackUnsupported(p); why != "" {
				return Errf(ErrConflict, "rollback not supported for %s: %s", p.PackageID, why)
			}
		}
		// An install and a rollback of the same package would undo each other.
		var other string
		err = tx.QueryRow(`SELECT deployment_id FROM deployments WHERE package_id=? AND state IN ('pending_approval','active','paused') AND operation != ? LIMIT 1`, n.PackageID, n.Operation).Scan(&other)
		if err == nil {
			return Errf(ErrConflict, "deployment %s (%s) of this package is still waiting for approval, active or paused; cancel it first", other, map[bool]string{true: "install", false: "rollback"}[rollback])
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		// One running deployment per package and operation: a second one
		// would target the same machines again (duplicate work, confusing
		// progress). Wait for it to finish, or cancel it first.
		err = tx.QueryRow(`SELECT deployment_id FROM deployments WHERE package_id=? AND state IN ('pending_approval','active','paused') AND operation = ? LIMIT 1`, n.PackageID, n.Operation).Scan(&other)
		if err == nil {
			return Errf(ErrConflict, "deployment %s of this package is already running or waiting for approval; open it, wait for it to finish, or cancel it first", other)
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if s.Policy.SeparationOfDuties {
			for _, a := range p.Approvals {
				if a.By == actor {
					return Errf(ErrConflict, "separation of duties: %s approved this package, so a different operator must deploy it", actor)
				}
			}
		}
		id := NewID("d-")
		now := s.now()
		em := 0
		if n.Emergency {
			em = 1
		}
		need := s.Policy.RequiredDeploymentApprovals()
		if _, err := tx.Exec(`INSERT INTO deployments(`+depCols+`) VALUES(?,?,?,'pending_approval',?,?,?,0,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'','','')`,
			id, n.PackageID, n.Name, em, n.Justification, mustJSON(n.Rings), n.MaxFailurePct, n.MaxRetries, n.WindowStart, n.WindowEnd, actor, now, now,
			awaitingReason(0, need), n.Deadline, n.MaxConcurrent, n.RebootPolicy, boolInt(n.IgnoreWindows), mustJSON(n.HealthChecks), n.Operation, boolInt(n.AutoAdvance), need); err != nil {
			return err
		}
		action := "deployment.created"
		if n.Emergency {
			action = "deployment.created_emergency"
		}
		if rollback {
			action = "deployment.created_rollback"
		}
		if err := s.audit(tx, Ev{Actor: actor, Action: action, ObjectType: "deployment", ObjectID: id, PackageID: n.PackageID,
			Details: map[string]any{"name": n.Name, "rings": n.Rings, "max_failure_pct": n.MaxFailurePct, "max_retries": n.MaxRetries,
				"window": n.WindowStart + "-" + n.WindowEnd, "emergency": n.Emergency, "justification": n.Justification,
				"deadline": n.Deadline, "max_concurrent": n.MaxConcurrent, "reboot_policy": n.RebootPolicy, "ignore_windows": n.IgnoreWindows, "health_checks": n.HealthChecks, "operation": n.Operation,
				"auto_advance": n.AutoAdvance, "approvals_required": need}}); err != nil {
			return err
		}
		// No targets yet: nothing is dispatched until the approvals are in
		// (activateDeployment).
		kind := map[bool]string{true: "Rollback", false: "Deployment"}[rollback]
		if err := s.raiseAlert(tx, "info", "deployment_awaiting_approval", "deployment", id,
			fmt.Sprintf("%s %q of %s by %s is waiting for %d approval(s)", kind, n.Name, n.PackageID, strings.TrimPrefix(actor, "user:"), need)); err != nil {
			return err
		}
		out, err = getDeploymentCounted(ctx, tx, id)
		return err
	})
	return out, err
}

// sweepDeployments evaluates active deployments whose current ring has no
// target left in a non-terminal state, so one that has nothing to do
// completes even though no agent will ever report on it again.
func (s *Store) sweepDeployments(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT d.deployment_id FROM deployments d WHERE d.state='active'
		AND EXISTS (SELECT 1 FROM targets t WHERE t.deployment_id=d.deployment_id AND t.ring=d.current_ring)
		AND NOT EXISTS (SELECT 1 FROM targets t WHERE t.deployment_id=d.deployment_id AND t.ring=d.current_ring
			AND t.state NOT IN ('not_applicable','exception','verified','failed')
			AND NOT (d.auto_advance=1 AND t.state='pending_reboot'))`)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range ids {
		// State and ring: an auto-advance changes the ring, not the state.
		var before, after string
		const stateRing = `SELECT state || '/' || current_ring FROM deployments WHERE deployment_id=?`
		err := s.tx(ctx, func(tx *sql.Tx) error {
			if err := tx.QueryRowContext(ctx, stateRing, id).Scan(&before); err != nil {
				return err
			}
			if err := s.evaluateDeployment(ctx, tx, id, false); err != nil {
				return err
			}
			return tx.QueryRowContext(ctx, stateRing, id).Scan(&after)
		})
		if err != nil {
			return fmt.Errorf("evaluate deployment %s: %w", id, err)
		}
		if before != after {
			s.Changed()
		}
	}
	return nil
}

// DeploymentAction applies pause/resume/cancel/advance.
func (s *Store) DeploymentAction(ctx context.Context, actor, id, action, reason string) (Deployment, error) {
	if action != "advance" {
		if err := requireReason(reason); err != nil {
			return Deployment{}, err
		}
	}
	var out Deployment
	err := s.txChanged(ctx, func(tx *sql.Tx) error {
		d, err := getDeploymentCounted(ctx, tx, id)
		if err != nil {
			return err
		}
		to := d.State
		ring := d.CurrentRing
		switch action {
		case "pause":
			if d.State != "active" {
				return Errf(ErrConflict, "can only pause an active deployment (is %s)", d.State)
			}
			to = "paused"
		case "resume":
			if d.State != "paused" {
				return Errf(ErrConflict, "can only resume a paused deployment (is %s)", d.State)
			}
			to = "active"
		case "cancel":
			if d.State != "active" && d.State != "paused" && d.State != "pending_approval" {
				return Errf(ErrConflict, "cannot cancel a %s deployment", d.State)
			}
			to = "cancelled"
		case "advance":
			if d.State != "active" {
				return Errf(ErrConflict, "can only advance an active deployment (is %s)", d.State)
			}
			if d.CurrentRing >= len(d.Rings)-1 {
				return Errf(ErrConflict, "already on the last ring")
			}
			var busy int
			tx.QueryRow(`SELECT COUNT(*) FROM targets WHERE deployment_id=? AND ring=? AND state IN ('downloading','downloaded','installing')`, id, d.CurrentRing).Scan(&busy)
			if busy > 0 {
				return Errf(ErrConflict, "%d endpoint(s) in the current ring are still downloading or installing", busy)
			}
			ring++
		default:
			return Errf(ErrInvalid, "unknown action %s", action)
		}
		if _, err := tx.Exec(`UPDATE deployments SET state=?, current_ring=?, state_reason=?, updated_at=? WHERE deployment_id=?`, to, ring, reason, s.now(), id); err != nil {
			return err
		}
		if d.State == "pending_approval" {
			if err := s.resolveAlert(tx, "deployment_awaiting_approval", id, "cancelled by "+strings.TrimPrefix(actor, "user:")); err != nil {
				return err
			}
		}
		evAction := "deployment." + map[string]string{"pause": "paused", "resume": "resumed", "cancel": "cancelled", "advance": "advanced"}[action]
		if err := s.audit(tx, Ev{Actor: actor, Action: evAction, ObjectType: "deployment", ObjectID: id, PackageID: d.PackageID,
			Details: map[string]any{"from": d.State, "to": to, "ring": ring, "ring_name": d.Rings[ring].Name, "reason": reason, "counts": d.Counts}}); err != nil {
			return err
		}
		if action == "advance" {
			if err := s.ensureTargetsForDeployment(ctx, tx, id); err != nil {
				return err
			}
		}
		if action == "advance" || action == "resume" {
			if err := s.evaluateDeployment(ctx, tx, id, false); err != nil {
				return err
			}
		}
		out, err = getDeploymentCounted(ctx, tx, id)
		return err
	})
	return out, err
}

// ---- targeting ----

// ringFor returns the first ring whose groups match the endpoint, or -1.
// The group "all" matches every endpoint.
// A ring group may also be "endpoint:<id>" to target one specific endpoint
// (used by "deploy to the endpoints that need it").
func ringFor(rings []Ring, groups []string, endpointID string) int {
	gs := map[string]bool{"endpoint:" + endpointID: true}
	for _, g := range groups {
		gs[g] = true
	}
	for i, r := range rings {
		for _, g := range r.Groups {
			if g == "all" || gs[g] {
				return i
			}
		}
	}
	return -1
}

// Applicable reports whether package p applies to endpoint e and, if not, why
// (the rule deployments resolve targets with).
func Applicable(p Package, e Endpoint) (bool, string) { return applicable(p, e) }

func applicable(p Package, e Endpoint) (bool, string) {
	a := p.Applicability
	if !strings.EqualFold(e.OS, a.OS) {
		return false, fmt.Sprintf("os %s != %s", e.OS, a.OS)
	}
	if a.Arch != "any" && a.Arch != e.Arch {
		return false, fmt.Sprintf("arch %s != %s", e.Arch, a.Arch)
	}
	if a.MinBuild > 0 && e.Build < a.MinBuild {
		return false, fmt.Sprintf("build %d < %d", e.Build, a.MinBuild)
	}
	if a.MaxBuild > 0 && e.Build > a.MaxBuild {
		return false, fmt.Sprintf("build %d > %d", e.Build, a.MaxBuild)
	}
	if len(a.Editions) > 0 && e.Edition != "" {
		ok := false
		for _, ed := range a.Editions {
			if strings.EqualFold(ed, e.Edition) {
				ok = true
			}
		}
		if !ok {
			return false, fmt.Sprintf("edition %s not in %v", e.Edition, a.Editions)
		}
	}
	return true, ""
}

// supersedingKBs returns KBs of catalog packages that supersede kb,
// transitively (A superseded by B superseded by C → {B, C}).
func supersedingKBs(ctx context.Context, q querier, kb string) (map[string]bool, error) {
	out := map[string]bool{}
	if kb == "" {
		return out, nil
	}
	frontier := []string{kb}
	for len(frontier) > 0 && len(out) < 1000 {
		cur := frontier[0]
		frontier = frontier[1:]
		rows, err := q.QueryContext(ctx, `SELECT p.kb FROM packages p, json_each(p.supersedes) j WHERE j.value=? AND p.kb != ''`, cur)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var k string
			rows.Scan(&k)
			if k != kb && !out[k] {
				out[k] = true
				frontier = append(frontier, k)
			}
		}
		rows.Close()
	}
	return out, nil
}

// presentIn reports whether inventory shows p (or a superseding KB, or a
// same-or-newer package version) installed.
func presentIn(inv []InventoryItem, p Package, sup map[string]bool) (bool, string) {
	ok, why, _ := presentOn(inv, OSFacts{}, p, sup)
	return ok, why
}

// OSFacts is what verification needs to know about the endpoint's Windows
// besides inventory: the build and its revision (UBR, the "9711" of
// "(26300.9711)" in os_version; 0 = unknown).
type OSFacts struct{ Build, UBR int }

var ubrRe = regexp.MustCompile(`\((\d{4,6})\.(\d+)\)`)

// osFacts parses the UBR out of an os_version such as
// "Windows 11 Pro 25H2 (26300.9711)"; the build must match the reported one.
func osFacts(osVersion string, build int) OSFacts {
	f := OSFacts{Build: build}
	if m := ubrRe.FindStringSubmatch(osVersion); m != nil {
		if b, _ := strconv.Atoi(m[1]); b == build || build == 0 {
			f.UBR, _ = strconv.Atoi(m[2])
		}
	}
	return f
}

// evidenceLine renders the inventory line that proved an install, for the
// target detail and the evidence report.
func evidenceLine(it InventoryItem) string {
	s := it.Kind + " " + it.ID
	if it.Name != "" && it.Name != it.ID {
		s += " \"" + it.Name + "\""
	}
	if it.Version != "" {
		s += " " + it.Version
	}
	if it.Scope != "" {
		s += " (" + it.Scope + ")"
	}
	return s
}

// presentOn is presentIn plus the endpoint's OS revision, and returns the
// evidence: the matching inventory line, or the OS revision for a Windows
// cumulative update verified by build revision. A cumulative update with
// expected_ubr counts as installed when the endpoint runs exactly its
// min_build at that revision or later, even if Windows does not list the KB
// (some LCUs never show up in the QFE list). Per-user installs (Scope
// "user") count like machine-wide ones.
func presentOn(inv []InventoryItem, os OSFacts, p Package, sup map[string]bool) (bool, string, string) {
	for _, it := range inv {
		switch {
		case p.Kind == "agent" && it.Kind == "agent" && VersionAtLeast(it.Version, p.Version):
			return true, "agent version " + it.Version, evidenceLine(it)
		case p.Kind == "pkg" && it.Kind == "app" && it.ID == p.PackageName && VersionAtLeast(it.Version, p.Version):
			return true, "inventory shows app " + it.Name + " " + it.Version, evidenceLine(it)
		case (p.Kind == "deb" || p.Kind == "rpm" || p.Kind == "pkg") && it.Kind == "pkg" && it.ID == p.PackageName && VersionAtLeast(it.Version, p.Version):
			return true, "inventory shows " + p.PackageName + " " + it.Version, evidenceLine(it)
		case p.Kind == "msi" && p.PackageName != "" && it.Kind == "product" && SameAppName(it.Name, p.PackageName) && p.Version != "" && VersionAtLeast(it.Version, p.Version):
			return true, "inventory shows " + it.Name + " " + it.Version, evidenceLine(it)
		case p.Kind == manifest.KindExe && exePresent(p, it):
			return true, "inventory shows " + it.Name + " " + it.Version, evidenceLine(it)
		case (p.Kind == manifest.KindPortable || p.Kind == manifest.KindMsix) && formatPresent(p, it):
			return true, "inventory shows " + firstNonEmpty(it.Name, it.ID) + " " + it.Version, evidenceLine(it)
		case it.Kind == "kb" && p.KB != "" && strings.EqualFold(it.ID, p.KB):
			return true, "inventory shows " + p.KB, evidenceLine(it)
		case it.Kind == "kb" && sup[strings.ToUpper(it.ID)]:
			return true, "inventory shows superseding " + it.ID, evidenceLine(it)
		// Some MSIs keep their product code across versions (Chrome's
		// enterprise MSI): the same code at an older version is not installed.
		case it.Kind == "product" && p.ProductCode != "" && strings.EqualFold(it.ID, p.ProductCode) &&
			(p.Version == "" || it.Version == "" || VersionAtLeast(it.Version, p.Version)):
			return true, "inventory shows product " + p.ProductCode, evidenceLine(it)
		}
	}
	if p.Kind == "msu" && p.ExpectedUBR > 0 && os.UBR > 0 && p.Applicability.MinBuild > 0 && os.Build == p.Applicability.MinBuild && os.UBR >= p.ExpectedUBR {
		rev := fmt.Sprintf("%d.%d", os.Build, os.UBR)
		return true, fmt.Sprintf("Windows reports build %s, at or past %d.%d (%s)", rev, os.Build, p.ExpectedUBR, p.KB), "os_version build " + rev
	}
	return false, "", ""
}

func (s *Store) activeException(ctx context.Context, q querier, endpointID, packageID string) (string, error) {
	var id string
	err := q.QueryRowContext(ctx, `SELECT exception_id FROM exceptions WHERE endpoint_id=? AND (package_id=? OR package_id='') AND revoked=0 AND expires_at > ? LIMIT 1`,
		endpointID, packageID, s.now()).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return id, err
}

func (s *Store) ensureTargetsForDeployment(ctx context.Context, tx *sql.Tx, depID string) error {
	eps, err := listEndpoints(ctx, tx)
	if err != nil {
		return err
	}
	d, err := getDeployment(ctx, tx, depID)
	if err != nil {
		return err
	}
	for _, e := range eps {
		if err := s.ensureTarget(ctx, tx, d, e); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ensureTargetsForEndpoint(ctx context.Context, tx *sql.Tx, e Endpoint) error {
	rows, err := tx.QueryContext(ctx, `SELECT deployment_id FROM deployments WHERE state='active'`)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		d, err := getDeployment(ctx, tx, id)
		if err != nil {
			return err
		}
		if err := s.ensureTarget(ctx, tx, d, e); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ensureTarget(ctx context.Context, tx *sql.Tx, d Deployment, e Endpoint) error {
	if e.RetiredAt != "" {
		return nil
	}
	ring := ringFor(d.Rings, e.Groups, e.EndpointID)
	if ring < 0 {
		return nil
	}
	// Only endpoints of the approved scope (fixed at activation) are
	// targeted; a later member of a ring group is recorded as excluded.
	if ok, err := inScope(ctx, tx, d.DeploymentID, e.EndpointID); err != nil {
		return err
	} else if !ok {
		return s.excludeFromScope(ctx, tx, d, e, ring)
	}
	if ring > d.CurrentRing {
		return nil
	}
	var n int
	tx.QueryRow(`SELECT COUNT(*) FROM targets WHERE deployment_id=? AND endpoint_id=?`, d.DeploymentID, e.EndpointID).Scan(&n)
	if n > 0 {
		return nil
	}
	p, err := getPackage(ctx, tx, d.PackageID)
	if err != nil {
		return err
	}
	state, detail, evidence := "pending", "", ""
	if ok, why := applicable(p, e); !ok {
		state, detail = "not_applicable", why
	} else if why := agentGate(p, e); why != "" {
		state, detail = "not_applicable", why
	} else if d.Operation == "rollback" {
		// Only endpoints that have this package (this version) are in scope.
		if ok, why := rollbackPresent(e.inventory, p); !ok && e.InventoryAt != "" {
			state, detail = "not_applicable", why
		}
	} else {
		sup, err := supersedingKBs(ctx, tx, p.KB)
		if err != nil {
			return err
		}
		if ok, why, ev := presentOn(e.inventory, osFacts(e.OSVersion, e.Build), p, sup); ok && e.InventoryAt != "" {
			state, detail, evidence = "verified", "already present: "+withEvidence(why, ev), ev
		} else if appStoreManaged(e.inventory, p) {
			state, detail = "not_applicable", appStoreDetail
		} else if e.InventoryAt != "" && !appInstalled(e.inventory, p) {
			state, detail = "not_applicable", notInstalledDetail
		} else if xid, err := s.activeException(ctx, tx, e.EndpointID, p.PackageID); err != nil {
			return err
		} else if xid != "" {
			state, detail = "exception", "covered by exception "+xid
		}
	}
	if _, err := tx.Exec(`INSERT INTO targets(deployment_id,endpoint_id,package_id,ring,state,detail,updated_at,evidence) VALUES(?,?,?,?,?,?,?,?)`,
		d.DeploymentID, e.EndpointID, d.PackageID, ring, state, detail, s.now(), evidence); err != nil {
		return err
	}
	return s.audit(tx, Ev{Actor: "system:scheduler", Action: "target." + state, ObjectType: "target", ObjectID: d.DeploymentID + "/" + e.EndpointID, PackageID: d.PackageID,
		Details: map[string]any{"hostname": e.Hostname, "ring": ring, "detail": detail}})
}

// withEvidence appends the evidence line to a verification reason.
func withEvidence(why, evidence string) string {
	if evidence == "" {
		return why
	}
	return why + " [" + evidence + "]"
}

// setVerified marks t verified by inventory (system:verifier) and keeps the
// evidence: in the detail, and on its own for the evidence report.
func (s *Store) setVerified(tx *sql.Tx, t Target, why, evidence string) error {
	if err := s.setTarget(tx, "system:verifier", t, "verified", withEvidence(why, evidence), t.ExitCode, 0); err != nil {
		return err
	}
	_, err := tx.Exec(`UPDATE targets SET evidence=? WHERE deployment_id=? AND endpoint_id=?`, evidence, t.DeploymentID, t.EndpointID)
	return err
}

func (s *Store) setTarget(tx *sql.Tx, actor string, t Target, state, detail string, exitCode int, attemptsDelta int) error {
	if _, err := tx.Exec(`UPDATE targets SET state=?, detail=?, exit_code=?, attempts=attempts+?, updated_at=? WHERE deployment_id=? AND endpoint_id=?`,
		state, detail, exitCode, attemptsDelta, s.now(), t.DeploymentID, t.EndpointID); err != nil {
		return err
	}
	return s.audit(tx, Ev{Actor: actor, Action: "target." + state, ObjectType: "target", ObjectID: t.DeploymentID + "/" + t.EndpointID, PackageID: t.PackageID,
		Details: map[string]any{"from": t.State, "detail": detail, "exit_code": exitCode, "hostname": t.Hostname}})
}

// evaluateDeployment auto-pauses on failure threshold (only when triggered by
// a new failure, so an operator's resume isn't immediately undone) and
// completes the deployment when the last ring is finished.
func (s *Store) evaluateDeployment(ctx context.Context, tx *sql.Tx, id string, failureTrigger bool) error {
	ring := -1
	if failureTrigger {
		ring = -2 // the current ring
	}
	return s.evaluate(ctx, tx, id, ring)
}

// evaluateRing is evaluateDeployment triggered by a new failure in ring r
// (an endpoint lost after install may be in an earlier ring).
func (s *Store) evaluateRing(ctx context.Context, tx *sql.Tx, id string, r int) error {
	return s.evaluate(ctx, tx, id, r)
}

// evaluate: failRing -1 = no new failure, -2 = check the current ring, else
// check that ring's failure threshold.
func (s *Store) evaluate(ctx context.Context, tx *sql.Tx, id string, failRing int) error {
	d, err := getDeployment(ctx, tx, id)
	if err != nil || d.State != "active" {
		return err
	}
	if failRing == -2 || failRing > d.CurrentRing {
		failRing = d.CurrentRing
	}
	// One indexed aggregate per ring (no per-target rows) so agent reports
	// stay cheap however large the ring is.
	// Unverified installs (UnverifiedDetail, see sweepUnverified) count as
	// failures for the threshold: an install that inventory never confirms
	// is not a success, and a package that "installs" everywhere without
	// effect must stop the rollout like one that fails.
	count := func(ring int) (total, skipped, verified, exhausted, unhealthy, lost, restart, unverified int, err error) {
		err = tx.QueryRowContext(ctx, `SELECT COUNT(*),
		COALESCE(SUM(state IN ('not_applicable','exception')),0),
		COALESCE(SUM(state='verified'),0),
		COALESCE(SUM(state='failed' AND attempts > ?),0),
		COALESCE(SUM(health='failed' AND state NOT IN ('failed','lost_after_install')),0),
		COALESCE(SUM(state='lost_after_install'),0),
		COALESCE(SUM(state='pending_reboot'),0),
		COALESCE(SUM(state='installed' AND detail=? AND health != 'failed'),0)
		FROM targets WHERE deployment_id=? AND ring=?`, d.MaxRetries, UnverifiedDetail, id, ring).Scan(&total, &skipped, &verified, &exhausted, &unhealthy, &lost, &restart, &unverified)
		return
	}
	now := s.now()
	if failRing >= 0 {
		total, skipped, _, exhausted, unhealthy, lost, _, unverified, err := count(failRing)
		if err != nil {
			return err
		}
		considered := total - skipped
		if bad := exhausted + unhealthy + lost + unverified; considered > 0 && bad*100 > d.MaxFailurePct*considered {
			return s.autoPause(tx, d, fmt.Sprintf("auto-pause: %d/%d endpoints failed (%d install, %d health check, %d lost after install, %d not confirmed by inventory) in ring %q (threshold %d%%)",
				bad, considered, exhausted, unhealthy, lost, unverified, d.Rings[failRing].Name, d.MaxFailurePct))
		}
	}
	total, skipped, verified, exhausted, unhealthy, lost, restart, unverified, err := count(d.CurrentRing)
	if err != nil {
		return err
	}
	terminal := skipped + verified + exhausted
	// For moving on, an install waiting only for a restart succeeded: with
	// no window allowing restarts it may wait for days, and holding the rest
	// of the fleet back for that would stall the rollout. The deployment
	// still completes only once those restarts happened.
	advanceable := d.AutoAdvance && d.CurrentRing < len(d.Rings)-1 && terminal+restart == total
	if terminal != total && !advanceable {
		return nil
	}
	// An empty first ring (no pilot machine in the approved scope) is not
	// "finished": moving on would skip the pilot, so an operator decides;
	// an empty later ring is skipped like a finished one.
	if d.AutoAdvance && (total > 0 || d.CurrentRing > 0) && d.CurrentRing < len(d.Rings)-1 {
		// The ring is finished. Move on only if it stayed within the failure
		// threshold (the same test as the auto-pause); otherwise it waits for
		// an operator, who decides whether to advance anyway.
		considered := total - skipped
		if bad := exhausted + unhealthy + lost + unverified; considered > 0 && bad*100 > d.MaxFailurePct*considered {
			return nil
		}
		return s.autoAdvance(ctx, tx, d)
	}
	reason := ""
	if d.CurrentRing == len(d.Rings)-1 && total > 0 {
		reason = "all targets in final ring finished"
	} else {
		// Nothing left to do if no endpoint falls in a later ring (or the
		// final ring is empty): waiting for an advance would hang forever.
		done, err := s.remainingRingsEmpty(ctx, tx, d)
		if err != nil {
			return err
		}
		if done && d.CurrentRing == 0 && total == 0 {
			reason = "no endpoint was in the ring groups when it was approved (the approved scope is empty)"
		} else if done {
			reason = "all targets finished; remaining rings have no endpoints"
		}
	}
	if reason != "" {
		if err := fillCounts(ctx, tx, &d); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE deployments SET state='completed', state_reason=?, updated_at=? WHERE deployment_id=?`, reason, now, id); err != nil {
			return err
		}
		return s.audit(tx, Ev{Actor: "system:scheduler", Action: "deployment.completed", ObjectType: "deployment", ObjectID: id, PackageID: d.PackageID,
			Details: map[string]any{"counts": d.Counts}})
	}
	return nil
}

// autoAdvance moves an auto-advancing deployment to its next ring, targets
// the endpoints of that ring, and evaluates again (the new ring may already
// be finished, e.g. every endpoint already has the package; at most one
// recursion per ring).
func (s *Store) autoAdvance(ctx context.Context, tx *sql.Tx, d Deployment) error {
	ring := d.CurrentRing + 1
	reason := fmt.Sprintf("ring %q finished within the failure threshold; started ring %q automatically", d.Rings[d.CurrentRing].Name, d.Rings[ring].Name)
	if err := fillCounts(ctx, tx, &d); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE deployments SET current_ring=?, state_reason=?, updated_at=? WHERE deployment_id=? AND state='active'`, ring, reason, s.now(), d.DeploymentID); err != nil {
		return err
	}
	if err := s.audit(tx, Ev{Actor: "system:scheduler", Action: "deployment.advanced", ObjectType: "deployment", ObjectID: d.DeploymentID, PackageID: d.PackageID,
		Details: map[string]any{"ring": ring, "ring_name": d.Rings[ring].Name, "auto": true, "counts": d.Counts}}); err != nil {
		return err
	}
	if err := s.ensureTargetsForDeployment(ctx, tx, d.DeploymentID); err != nil {
		return err
	}
	return s.evaluate(ctx, tx, d.DeploymentID, -1)
}

// remainingRingsEmpty reports whether no endpoint of d's approved scope
// (still active) belongs to a ring after the current one. The scope is
// fixed at activation, so endpoints enrolling later never fill a ring.
func (s *Store) remainingRingsEmpty(ctx context.Context, tx *sql.Tx, d Deployment) (bool, error) {
	if d.CurrentRing >= len(d.Rings)-1 {
		return true, nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT e.endpoint_id, e.groups FROM deployment_scope s JOIN endpoints e ON e.endpoint_id=s.endpoint_id
		WHERE s.deployment_id=? AND s.in_scope=1 AND e.retired_at=''`, d.DeploymentID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, gs string
		if err := rows.Scan(&id, &gs); err != nil {
			return false, err
		}
		var groups []string
		json.Unmarshal([]byte(gs), &groups)
		if ringFor(d.Rings, groups, id) > d.CurrentRing {
			return false, nil
		}
	}
	return true, rows.Err()
}

func (s *Store) autoPause(tx *sql.Tx, d Deployment, reason string) error {
	id := d.DeploymentID
	if _, err := tx.Exec(`UPDATE deployments SET state='paused', state_reason=?, updated_at=? WHERE deployment_id=?`, reason, s.now(), id); err != nil {
		return err
	}
	if err := s.raiseAlert(tx, "critical", "deployment_auto_paused", "deployment", id, d.Name+": "+reason); err != nil {
		return err
	}
	return s.audit(tx, Ev{Actor: "system:scheduler", Action: "deployment.auto_paused", ObjectType: "deployment", ObjectID: id, PackageID: d.PackageID,
		Details: map[string]any{"reason": reason}})
}

// ---- agent interaction ----

type CheckinRequest struct {
	Hostname      string          `json:"hostname"`
	OSVersion     string          `json:"os_version"`
	Build         int             `json:"build"`
	Arch          string          `json:"arch"`
	AgentVersion  string          `json:"agent_version"`
	RebootPending bool            `json:"reboot_pending"`
	Inventory     []InventoryItem `json:"inventory"`
	Edition       string          `json:"edition"`
	// Hardware is nil from agents older than this field: keep the last value.
	Hardware *Hardware `json:"hardware,omitempty"`
}

type Assignment struct {
	DeploymentID string `json:"deployment_id"`
	PackageID    string `json:"package_id"`
	Kind         string `json:"kind"`
	KB           string `json:"kb"`
	ProductCode  string `json:"product_code"`
	FileName     string `json:"file_name"`
	Size         int64  `json:"size"`
	SHA256       string `json:"sha256"`
	URL          string `json:"url"`
	ManifestURL  string `json:"manifest_url"`
	// RebootAllowed: the agent may reboot right after this install if needed.
	RebootAllowed bool          `json:"reboot_allowed"`
	HealthChecks  []HealthCheck `json:"health_checks"`
	// Operation is "rollback" for uninstalls (omitted for installs).
	Operation string `json:"operation,omitempty"`
}

// Checkin records heartbeat + inventory, reconciles targets (exceptions,
// verification) and returns the assignments the endpoint should work on now.
func (s *Store) Checkin(ctx context.Context, endpointID string, r CheckinRequest) (CheckinResult, error) {
	if r.Inventory == nil {
		r.Inventory = []InventoryItem{}
	}
	for i := range r.Inventory {
		if r.Inventory[i].Kind == "kb" {
			r.Inventory[i].ID = strings.ToUpper(r.Inventory[i].ID)
		}
	}
	res := CheckinResult{Assignments: []Assignment{}}
	changed := false // inventory, OS facts or target states changed (Generation)
	err := s.tx(ctx, func(tx *sql.Tx) error {
		now := s.now()
		rp := 0
		if r.RebootPending {
			rp = 1
		}
		var oldInv, oldInvAt, oldOSVersion, oldArch string
		var oldBuild int
		if err := tx.QueryRowContext(ctx, `SELECT inventory, inventory_at, os_version, build, arch FROM endpoints WHERE endpoint_id=?`, endpointID).
			Scan(&oldInv, &oldInvAt, &oldOSVersion, &oldBuild, &oldArch); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		newInv := mustJSON(r.Inventory)
		changed = oldInvAt == "" || oldInv != newInv || oldOSVersion != r.OSVersion || oldBuild != r.Build || oldArch != r.Arch
		if _, err := tx.Exec(`UPDATE endpoints SET hostname=?, os_version=?, build=?, arch=?, agent_version=?, reboot_pending=?, inventory=?, last_seen=?, inventory_at=?, edition=? WHERE endpoint_id=?`,
			r.Hostname, r.OSVersion, r.Build, r.Arch, r.AgentVersion, rp, newInv, now, now, r.Edition, endpointID); err != nil {
			return err
		}
		if r.Hardware != nil {
			if _, err := tx.Exec(`UPDATE endpoints SET hardware=? WHERE endpoint_id=?`, mustJSON(r.Hardware.clean()), endpointID); err != nil {
				return err
			}
		}
		e, err := getEndpoint(ctx, tx, endpointID)
		if err != nil {
			return err
		}
		if err := s.ensureTargetsForEndpoint(ctx, tx, e); err != nil {
			return err
		}
		ts, err := queryTargets(ctx, tx, `t.endpoint_id=? AND d.state IN ('active','paused','completed')`, endpointID)
		if err != nil {
			return err
		}
		touched := map[string]bool{}
		for _, t := range ts {
			// EXE packages wait for agent 0.9.0, the app formats (archive,
			// portable, MSIX, per-user) for 0.10.0: once the agent is
			// upgraded, the target is back in scope.
			if t.State == "not_applicable" && agentTooOld(t.Detail) {
				p, err := getPackage(ctx, tx, t.PackageID)
				if err != nil {
					return err
				}
				if agentGate(p, e) == "" {
					if err := s.setTarget(tx, "system:scheduler", t, "pending", "agent upgraded to "+e.AgentVersion+"; package in scope again", 0, 0); err != nil {
						return err
					}
					touched[t.DeploymentID] = true
					t.State = "pending"
				}
			}
			if t.State == "verified" || t.State == "not_applicable" {
				continue
			}
			p, err := getPackage(ctx, tx, t.PackageID)
			if err != nil {
				return err
			}
			if why := agentGate(p, e); why != "" && (t.State == "pending" || t.State == "deferred" || t.State == "failed") {
				// Never offered: older agents refuse manifests they do not know.
				if err := s.setTarget(tx, "system:scheduler", t, "not_applicable", why, t.ExitCode, 0); err != nil {
					return err
				}
				touched[t.DeploymentID] = true
				continue
			}
			// Waiting on a reboot the install (or uninstall) asked for.
			rebootWait := (t.State == "pending_reboot" || t.State == "lost_after_install") && r.RebootPending
			if t.Operation == "rollback" {
				present, _ := rollbackPresent(r.Inventory, p)
				switch {
				case !present && (t.State == "pending" || t.State == "deferred"):
					err = s.setTarget(tx, "system:verifier", t, "not_applicable", "inventory does not show it; nothing to roll back", t.ExitCode, 0)
				case !present && !rebootWait:
					if err = s.setTarget(tx, "system:verifier", t, "verified", "inventory no longer shows "+t.PackageID, t.ExitCode, 0); err == nil {
						err = s.markRolledBack(tx, t)
					}
				case t.State == "lost_after_install":
					err = s.recoverLost(tx, t, r.RebootPending)
				default:
					continue
				}
				if err != nil {
					return err
				}
				touched[t.DeploymentID] = true
				continue
			}
			sup, err := supersedingKBs(ctx, tx, p.KB)
			if err != nil {
				return err
			}
			// Verification: fresh inventory evidence, and no outstanding reboot
			// if the install itself asked for one.
			if ok, why, ev := presentOn(r.Inventory, osFacts(r.OSVersion, r.Build), p, sup); ok && !rebootWait {
				if err := s.setVerified(tx, t, why, ev); err != nil {
					return err
				}
				touched[t.DeploymentID] = true
				continue
			}
			if t.State == "lost_after_install" {
				if err := s.recoverLost(tx, t, r.RebootPending); err != nil {
					return err
				}
				touched[t.DeploymentID] = true
				continue
			}
			retryable := t.State == "pending" || t.State == "failed" || t.State == "deferred"
			if appStoreManaged(r.Inventory, p) && retryable {
				if err := s.setTarget(tx, "system:scheduler", t, "not_applicable", appStoreDetail, t.ExitCode, 0); err != nil {
					return err
				}
				touched[t.DeploymentID] = true
				continue
			}
			xid, err := s.activeException(ctx, tx, endpointID, t.PackageID)
			if err != nil {
				return err
			}
			switch {
			case xid != "" && retryable:
				if err := s.setTarget(tx, "system:scheduler", t, "exception", "covered by exception "+xid, t.ExitCode, 0); err != nil {
					return err
				}
				touched[t.DeploymentID] = true
			case xid == "" && t.State == "exception":
				if err := s.setTarget(tx, "system:scheduler", t, "pending", "exception no longer active", 0, 0); err != nil {
					return err
				}
			}
		}
		if len(touched) > 0 {
			changed = true
		}
		for id := range touched {
			if err := s.evaluateDeployment(ctx, tx, id, false); err != nil {
				return err
			}
		}
		// Assignments: current state after reconciliation.
		res.Site, res.OS = e.Site, e.OS
		windows, err := listWindows(ctx, tx)
		if err != nil {
			return err
		}
		nowT := s.Now()
		ws := endpointWindows(windows, e.Groups, nowT)
		type cand struct {
			a                      Assignment
			state                  string
			attempts, maxRetries   int
			winStart, winEnd       string
			deadline, rebootPolicy string
			ignoreWindows, maxConc int
			healthJSON, prereqJSON string
			detail, operation      string
		}
		var cands []cand
		actionable := 0
		rows, err := tx.QueryContext(ctx, `SELECT t.deployment_id, t.state, t.attempts, d.max_retries, d.window_start, d.window_end, d.deadline, d.reboot_policy, d.ignore_windows, d.max_concurrent, d.health_checks,
			p.package_id, p.kind, p.kb, p.product_code, p.file_name, p.size, p.sha256, p.prerequisites, t.detail, d.operation
			FROM targets t JOIN deployments d ON d.deployment_id=t.deployment_id JOIN packages p ON p.package_id=t.package_id
			WHERE t.endpoint_id=? AND d.state='active' AND t.ring <= d.current_ring
			AND (p.state='approved' OR (d.operation='rollback' AND p.state='revoked'))
			AND t.state IN ('pending','deferred','downloading','downloaded','installing','failed')
			ORDER BY d.emergency DESC, d.created_at`, endpointID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var c cand
			if err := rows.Scan(&c.a.DeploymentID, &c.state, &c.attempts, &c.maxRetries, &c.winStart, &c.winEnd, &c.deadline, &c.rebootPolicy, &c.ignoreWindows, &c.maxConc, &c.healthJSON,
				&c.a.PackageID, &c.a.Kind, &c.a.KB, &c.a.ProductCode, &c.a.FileName, &c.a.Size, &c.a.SHA256, &c.prereqJSON, &c.detail, &c.operation); err != nil {
				rows.Close()
				return err
			}
			cands = append(cands, c)
		}
		rows.Close()
		for _, c := range cands {
			if c.state == "failed" && c.attempts > c.maxRetries {
				continue
			}
			if !InWindow(c.winStart, c.winEnd, nowT) {
				continue
			}
			var prereqs []string
			if c.operation == "install" {
				json.Unmarshal([]byte(c.prereqJSON), &prereqs)
			}
			if miss := missingPrereqs(prereqs, r.Inventory); len(miss) > 0 {
				msg := "waiting for prerequisite(s) " + strings.Join(miss, ", ")
				if c.detail != msg {
					if _, err := tx.Exec(`UPDATE targets SET detail=? WHERE deployment_id=? AND endpoint_id=?`, msg, c.a.DeploymentID, endpointID); err != nil {
						return err
					}
				}
				continue
			}
			pastDeadline := c.deadline != "" && !nowT.Before(parseTime(c.deadline))
			// Endpoint maintenance windows hold installs back until the deadline.
			if c.ignoreWindows == 0 && ws.has && !ws.open && !pastDeadline {
				continue
			}
			// Concurrency cap: count in-flight work plus fresh leases on other endpoints.
			starting := c.state == "pending" || c.state == "failed" || c.state == "deferred"
			if starting && c.maxConc > 0 {
				var inflight int
				if err := tx.QueryRow(`SELECT COUNT(*) FROM targets WHERE deployment_id=? AND endpoint_id != ? AND
					(state IN ('downloading','downloaded','installing') OR (state IN ('pending','failed') AND leased_until > ?))`,
					c.a.DeploymentID, endpointID, now).Scan(&inflight); err != nil {
					return err
				}
				if inflight >= c.maxConc {
					continue
				}
			}
			if starting {
				lease := nowT.Add(leaseFor).UTC().Format(time.RFC3339Nano)
				if _, err := tx.Exec(`UPDATE targets SET leased_until=? WHERE deployment_id=? AND endpoint_id=?`, lease, c.a.DeploymentID, endpointID); err != nil {
					return err
				}
			}
			c.a.RebootAllowed = rebootAllowed(c.rebootPolicy, ws, pastDeadline)
			json.Unmarshal([]byte(c.healthJSON), &c.a.HealthChecks)
			if c.a.HealthChecks == nil {
				c.a.HealthChecks = []HealthCheck{}
			}
			if c.operation == "rollback" {
				c.a.Operation = "rollback" // uninstall: nothing to download
			} else {
				c.a.URL = "/api/agent/content/" + c.a.SHA256
			}
			c.a.ManifestURL = "/api/agent/manifest/" + c.a.PackageID
			res.Assignments = append(res.Assignments, c.a)
			if c.state != "deferred" {
				actionable++ // deferred: waiting on disk space / power, not worth polling for
			}
		}
		// Reboot: endpoints waiting on a reboot get one only where policy allows,
		// and at most once per rebootRetry so a slow reboot isn't spammed.
		pend, err := tx.QueryContext(ctx, `SELECT t.deployment_id, t.detail, d.reboot_policy, d.deadline FROM targets t JOIN deployments d ON d.deployment_id=t.deployment_id
			WHERE t.endpoint_id=? AND t.state='pending_reboot' AND d.state IN ('active','paused')`, endpointID)
		if err != nil {
			return err
		}
		want := false
		type detailFix struct{ dep, detail string }
		var fixes []detailFix
		for pend.Next() {
			var dep, detail, pol, dl string
			if err := pend.Scan(&dep, &detail, &pol, &dl); err != nil {
				pend.Close()
				return err
			}
			past := dl != "" && !nowT.Before(parseTime(dl))
			if rebootAllowed(pol, ws, past) {
				want = true
			}
			// Say why nothing happens when no window can ever allow the restart
			// the policy waits for (the deadline lifts that for at_deadline).
			switch never := rebootNeverInWindow(pol, ws, past); {
			case never && detail != noRebootWindowDetail:
				fixes = append(fixes, detailFix{dep, noRebootWindowDetail})
			case !never && detail == noRebootWindowDetail:
				fixes = append(fixes, detailFix{dep, rebootWaitDetail})
			}
		}
		pend.Close()
		for _, f := range fixes {
			if _, err := tx.Exec(`UPDATE targets SET detail=? WHERE deployment_id=? AND endpoint_id=?`, f.detail, f.dep, endpointID); err != nil {
				return err
			}
			changed = true
		}
		if want && (e.RebootRequestedAt == "" || nowT.Sub(parseTime(e.RebootRequestedAt)) > rebootRetry) {
			res.RebootNow = true
			if _, err := tx.Exec(`UPDATE endpoints SET reboot_requested_at=? WHERE endpoint_id=?`, now, endpointID); err != nil {
				return err
			}
			if err := s.audit(tx, Ev{Actor: "system:scheduler", Action: "endpoint.reboot_requested", ObjectType: "endpoint", ObjectID: endpointID,
				Details: map[string]any{"hostname": e.Hostname, "in_window": ws.open}}); err != nil {
				return err
			}
		}
		res.NextCheckinSeconds, err = s.nextCheckin(ctx, tx, e, actionable, res.RebootNow)
		return err
	})
	if err == nil && changed {
		s.Changed()
	}
	return res, err
}

const (
	leaseFor    = 15 * time.Minute
	rebootRetry = 30 * time.Minute
)

// Target details for installs waiting on a restart.
const (
	noRebootWindowDetail = "installed; waiting for a restart: no maintenance window allows automatic restarts (restart the machine or add a window)"
	rebootWaitDetail     = "installed; waiting for a restart"
)

// rebootNeverInWindow: the policy restarts only inside a window that allows
// reboots, and the endpoint has no such window (and, for at_deadline, the
// deadline has not passed yet), so no automatic restart will come.
func rebootNeverInWindow(policy string, ws windowState, pastDeadline bool) bool {
	switch policy {
	case "in_window":
		return !ws.anyReboot
	case "at_deadline":
		return !ws.anyReboot && !pastDeadline
	}
	return false
}

func rebootAllowed(policy string, ws windowState, pastDeadline bool) bool {
	switch policy {
	case "in_window":
		return ws.open && ws.reboot
	case "at_deadline":
		return (ws.open && ws.reboot) || pastDeadline
	}
	return false
}

// CheckinResult is what the agent receives.
type CheckinResult struct {
	Assignments []Assignment `json:"assignments"`
	RebootNow   bool         `json:"reboot_now"`
	// NextCheckinSeconds > 0 asks the agent to check in again sooner than
	// its configured interval (work in progress or just released); 0 = use
	// the configured interval.
	NextCheckinSeconds int    `json:"next_checkin_seconds"`
	Site               string `json:"-"`
	OS                 string `json:"-"`
}

var agentStates = map[string]bool{"downloading": true, "downloaded": true, "installing": true, "installed": true, "pending_reboot": true, "failed": true, "not_applicable": true, "deferred": true}

type Report struct {
	DeploymentID string `json:"deployment_id"`
	PackageID    string `json:"package_id"`
	State        string `json:"state"`
	Detail       string `json:"detail"`
	ExitCode     int    `json:"exit_code"`
	Health       string `json:"health"` // "" | ok | failed (post-install checks)
	HealthDetail string `json:"health_detail"`
}

// Heartbeat marks an endpoint as alive without a full check-in: the agent
// sends it while a long installer runs, so the endpoint is not shown offline.
func (s *Store) Heartbeat(ctx context.Context, endpointID string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE endpoints SET last_seen=? WHERE endpoint_id=?`, s.now(), endpointID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ReportTarget(ctx context.Context, endpointID string, r Report) error {
	if !agentStates[r.State] {
		return Errf(ErrInvalid, "state %q cannot be reported by an agent", r.State)
	}
	if len(r.Detail) > 2000 {
		r.Detail = r.Detail[:2000]
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		ts, err := queryTargets(ctx, tx, `t.deployment_id=? AND t.endpoint_id=?`, r.DeploymentID, endpointID)
		if err != nil {
			return err
		}
		if len(ts) == 0 || ts[0].PackageID != r.PackageID {
			return Errf(ErrNotFound, "no such target for this endpoint")
		}
		t := ts[0]
		if t.State == "verified" && r.State == "installed" && r.Health != "" {
			// Health checks re-run after the restart the install asked for
			// (the target may have verified meanwhile): record only the
			// result, the state stays verified.
			return s.reportHealth(ctx, tx, endpointID, t, r)
		}
		switch t.State {
		case "verified", "exception", "not_applicable":
			return Errf(ErrConflict, "target is %s", t.State)
		}
		if r.State == "deferred" && t.State == "deferred" {
			// Re-deferred at every check-in: refresh the reason, don't flood the audit log.
			_, err := tx.Exec(`UPDATE targets SET detail=?, updated_at=? WHERE deployment_id=? AND endpoint_id=?`, r.Detail, s.now(), r.DeploymentID, endpointID)
			return err
		}
		busy := r.State == "failed" && strings.HasPrefix(r.Detail, installerBusyPrefix)
		if busy {
			handled, err := s.installerBusy(ctx, tx, endpointID, t, r)
			if err != nil || handled {
				return err
			}
			// Past the grace: counts as a normal failure below.
		} else if r.State != "downloading" && r.State != "downloaded" && r.State != "installing" && r.State != "deferred" {
			// Any other result ends a run of "installer busy" results.
			if _, err := tx.Exec(`UPDATE targets SET busy_tries=0 WHERE deployment_id=? AND endpoint_id=? AND busy_tries != 0`, r.DeploymentID, endpointID); err != nil {
				return err
			}
		}
		delta := attemptDelta(t.State, r.State)
		if r.State == "failed" && t.State == "failed" && r.Detail == t.Detail && r.ExitCode == t.ExitCode && r.Health == "" {
			// The same failure again (e.g. a manifest that never verifies): it
			// counts as an attempt, so retries run out and auto-pause applies,
			// but writes no new audit event or alert.
			if _, err := tx.Exec(`UPDATE targets SET attempts=attempts+?, updated_at=? WHERE deployment_id=? AND endpoint_id=?`, delta, s.now(), r.DeploymentID, endpointID); err != nil {
				return err
			}
			return s.evaluateDeployment(ctx, tx, r.DeploymentID, true)
		}
		if err := s.setTarget(tx, "endpoint:"+endpointID, t, r.State, r.Detail, r.ExitCode, delta); err != nil {
			return err
		}
		if r.State == "failed" {
			sev, kind := "warning", "install_failed"
			if integrityFailure(r.Detail) {
				// The endpoint refused what the server offered: the signed
				// manifest or the content did not verify. Tampering or a
				// trust mismatch until shown otherwise.
				sev, kind = "critical", "manifest_verification_failed"
			}
			det, _ := hostDetails([]HostRef{{endpointID, t.Hostname}})
			if err := s.raiseAlertWith(tx, sev, kind, "target", r.DeploymentID+"/"+endpointID, t.Hostname+": "+r.PackageID+" failed: "+r.Detail, det); err != nil {
				return err
			}
		}
		if r.Health != "" {
			if err := s.recordHealth(tx, endpointID, t, r); err != nil {
				return err
			}
		}
		return s.evaluateDeployment(ctx, tx, r.DeploymentID, r.State == "failed" || r.Health == "failed")
	})
}

// recordHealth stores a health-check result: a failure raises
// health_check_failed and is audited; a pass closes an open
// health_check_failed alert for the target (the condition cleared, e.g.
// the service came up after the restart).
func (s *Store) recordHealth(tx *sql.Tx, endpointID string, t Target, r Report) error {
	if r.Health != "ok" && r.Health != "failed" {
		return Errf(ErrInvalid, "health must be ok or failed")
	}
	if len(r.HealthDetail) > 2000 {
		r.HealthDetail = r.HealthDetail[:2000]
	}
	obj := r.DeploymentID + "/" + endpointID
	if _, err := tx.Exec(`UPDATE targets SET health=?, health_detail=? WHERE deployment_id=? AND endpoint_id=?`, r.Health, r.HealthDetail, r.DeploymentID, endpointID); err != nil {
		return err
	}
	if r.Health == "ok" {
		return s.resolveAlert(tx, "health_check_failed", obj, "health checks passed: "+truncate(r.HealthDetail, 300))
	}
	det, _ := hostDetails([]HostRef{{endpointID, t.Hostname}})
	if err := s.raiseAlertWith(tx, "warning", "health_check_failed", "target", obj, t.Hostname+": post-install health check failed: "+r.HealthDetail, det); err != nil {
		return err
	}
	return s.audit(tx, Ev{Actor: "endpoint:" + endpointID, Action: "target.health_failed", ObjectType: "target", ObjectID: obj,
		PackageID: r.PackageID, Details: map[string]any{"detail": r.HealthDetail}})
}

// reportHealth handles health results for a target that already verified
// (checks re-run after the restart): only health is recorded; a failure
// still counts towards the deployment's failure threshold.
func (s *Store) reportHealth(ctx context.Context, tx *sql.Tx, endpointID string, t Target, r Report) error {
	if err := s.recordHealth(tx, endpointID, t, r); err != nil {
		return err
	}
	if r.Health == "ok" {
		if err := s.audit(tx, Ev{Actor: "endpoint:" + endpointID, Action: "target.health_ok", ObjectType: "target", ObjectID: r.DeploymentID + "/" + endpointID,
			PackageID: r.PackageID, Details: map[string]any{"detail": r.HealthDetail, "report": r.Detail}}); err != nil {
			return err
		}
	}
	return s.evaluateDeployment(ctx, tx, r.DeploymentID, r.Health == "failed")
}

// installerBusyPrefix starts the detail of a failure the agent reports when
// another installation is running (msiexec 1618, CBS busy, ...).
const installerBusyPrefix = "retry later: installer busy"

// installerBusyGrace: this many consecutive busy results per target are not
// counted as attempts (another installer, often Windows Update itself, can
// run for a while); after that they count normally, so a machine that is
// always busy still runs out of retries.
const installerBusyGrace = 10

// installerBusy handles an "installer busy" failure inside the grace: the
// target is failed (so it is offered again at the next check-in) but the
// attempt the installer start counted is given back, no alert is raised and
// the failure threshold is not checked. handled=false: the grace is used
// up; the caller records an ordinary failure.
func (s *Store) installerBusy(ctx context.Context, tx *sql.Tx, endpointID string, t Target, r Report) (bool, error) {
	var tries int
	if err := tx.QueryRowContext(ctx, `SELECT busy_tries FROM targets WHERE deployment_id=? AND endpoint_id=?`, t.DeploymentID, endpointID).Scan(&tries); err != nil {
		return false, err
	}
	tries++
	if _, err := tx.Exec(`UPDATE targets SET busy_tries=? WHERE deployment_id=? AND endpoint_id=?`, tries, t.DeploymentID, endpointID); err != nil {
		return false, err
	}
	if tries > installerBusyGrace {
		return false, nil
	}
	// The installer start ("installing") already counted an attempt.
	delta := 0
	if t.State == "installing" {
		delta = -1
	}
	detail := fmt.Sprintf("waiting: another installation is running on this machine (try %d)", tries)
	if tries > 1 {
		// Repeats are not audited one by one: the first one is, with the
		// agent's own detail (and exit code).
		_, err := tx.Exec(`UPDATE targets SET state='failed', detail=?, exit_code=?, attempts=MAX(attempts+?,0), updated_at=? WHERE deployment_id=? AND endpoint_id=?`,
			detail, r.ExitCode, delta, s.now(), t.DeploymentID, endpointID)
		return true, err
	}
	if t.Attempts+delta < 0 {
		delta = -t.Attempts
	}
	if err := s.setTarget(tx, "endpoint:"+endpointID, t, "failed", detail, r.ExitCode, delta); err != nil {
		return false, err
	}
	return true, s.audit(tx, Ev{Actor: "endpoint:" + endpointID, Action: "target.installer_busy", ObjectType: "target", ObjectID: t.DeploymentID + "/" + endpointID,
		PackageID: t.PackageID, Details: map[string]any{"agent_detail": r.Detail, "exit_code": r.ExitCode, "try": tries, "grace": installerBusyGrace}})
}

// attemptDelta: one install attempt is counted when the installer starts,
// and a failure that never reached the installer (manifest verification,
// download, hash check) counts as an attempt of its own — otherwise those
// retry forever and never reach the auto-pause threshold.
func attemptDelta(from, to string) int {
	switch {
	case to == "installing":
		return 1
	case to == "failed" && from != "installing":
		return 1
	}
	return 0
}

// integrityFailure recognises agent reports that the signed manifest or the
// downloaded content did not verify.
func integrityFailure(detail string) bool {
	d := strings.ToLower(detail)
	return strings.HasPrefix(d, "manifest verification failed") || strings.Contains(d, "possible tampering")
}

// ContentAllowed: an endpoint may only fetch content for an approved package
// it has an open target for.
func (s *Store) ContentAllowed(ctx context.Context, endpointID, sha string) (Package, error) {
	var pid string
	err := s.db.QueryRowContext(ctx, `SELECT p.package_id FROM targets t JOIN packages p ON p.package_id=t.package_id JOIN deployments d ON d.deployment_id=t.deployment_id
		WHERE t.endpoint_id=? AND p.sha256=? AND p.state='approved' AND d.state='active' AND d.operation='install' AND t.state NOT IN ('verified','exception','not_applicable') LIMIT 1`, endpointID, sha).Scan(&pid)
	if errors.Is(err, sql.ErrNoRows) {
		return Package{}, ErrNotFound
	}
	if err != nil {
		return Package{}, err
	}
	return s.GetPackage(ctx, pid)
}

// PackageAssigned: manifest access is limited the same way.
func (s *Store) PackageAssigned(ctx context.Context, endpointID, packageID string) bool {
	var n int
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM targets t JOIN packages p ON p.package_id=t.package_id JOIN deployments d ON d.deployment_id=t.deployment_id
		WHERE t.endpoint_id=? AND t.package_id=? AND (p.state='approved' OR (p.state='revoked' AND d.operation='rollback'))`, endpointID, packageID).Scan(&n)
	return n > 0
}

// VersionAtLeast compares dotted versions numerically segment by segment
// ("10.0.19045.5011" >= "10.0.19045.4894"; "3.0.13-1" >= "3.0.13"). Non-numeric
// suffixes are compared as strings when numeric parts are equal.
func VersionAtLeast(have, want string) bool {
	have, want = strings.TrimPrefix(strings.TrimPrefix(have, "v"), "V"), strings.TrimPrefix(strings.TrimPrefix(want, "v"), "V")
	split := func(v string) []string {
		return strings.FieldsFunc(v, func(r rune) bool { return r == '.' || r == '-' || r == '+' || r == '~' || r == ':' })
	}
	h, w := split(have), split(want)
	for i := 0; i < len(w); i++ {
		if i >= len(h) {
			return false
		}
		hn, herr := strconv.Atoi(h[i])
		wn, werr := strconv.Atoi(w[i])
		if herr == nil && werr == nil {
			if hn != wn {
				return hn > wn
			}
			continue
		}
		if h[i] != w[i] {
			return h[i] > w[i]
		}
	}
	return true
}

// missingPrereqs returns prerequisites not shown in the inventory.
func missingPrereqs(prereqs []string, inv []InventoryItem) []string {
	var missing []string
	for _, pr := range prereqs {
		found := false
		for _, it := range inv {
			if strings.EqualFold(it.ID, pr) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, pr)
		}
	}
	return missing
}

// appStoreManaged reports whether inventory shows p's app installed from the
// Mac App Store. Apple's installer refuses to replace those ("You've already
// installed X from the App Store"), and the App Store keeps them updated.
func appStoreManaged(inv []InventoryItem, p Package) bool {
	if p.Kind != "pkg" || p.PackageName == "" {
		return false
	}
	for _, it := range inv {
		if it.Kind == "app" && it.Source == "appstore" && it.ID == p.PackageName {
			return true
		}
	}
	return false
}

const appStoreDetail = "installed from the Mac App Store, which keeps it updated"
