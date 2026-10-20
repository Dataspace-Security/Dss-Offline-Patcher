package server

import (
	"context"
	"net/http"
	"strings"
	"time"

	"offpatch/internal/intake"
	"offpatch/internal/store"
)

// Console helpers of the UX iteration (docs/proposals/ux-api-contract.md):
// policy, fleet status, missing counts on endpoints, tracked acquisition
// requests and retrying exhausted targets.

// ---- GET /api/policy ----

type policyView struct {
	ApprovalsRequired  map[string]int    `json:"approvals_required"`
	SeparationOfDuties bool              `json:"separation_of_duties"`
	Deadlines          map[string]string `json:"deadlines"`
	// DeploymentApprovals: different people who approve each deployment and
	// rollback before it starts (two-person rule).
	DeploymentApprovals int `json:"deployment_approvals"`
}

func (s *Server) policy(w http.ResponseWriter, r *http.Request) {
	p := s.store.Policy
	v := policyView{ApprovalsRequired: map[string]int{}, SeparationOfDuties: p.SeparationOfDuties, Deadlines: map[string]string{},
		DeploymentApprovals: p.RequiredDeploymentApprovals()}
	for _, sev := range store.Severities {
		v.ApprovalsRequired[sev] = p.RequiredApprovals(sev)
		v.Deadlines[sev] = p.DeadlineFor(sev).String()
	}
	writeJSON(w, 200, v)
}

// ---- Endpoint.missing ----

// fillMissing sets Missing on each endpoint from the cached fleet view (os,
// apps) and the cached catalog needs (ready = approved packages it needs,
// catalog = approved or quarantined). snap may be nil (no usable
// intelligence): then Missing is set only when catalog > 0.
func fillMissing(eps []store.Endpoint, snap *fleetSnapshot, ready, catalog map[string]int) {
	for i := range eps {
		e := &eps[i]
		if e.RetiredAt != "" {
			e.Missing = nil
			continue
		}
		m := store.EndpointMissing{Ready: ready[e.EndpointID], Catalog: catalog[e.EndpointID]}
		if snap != nil {
			c := snap.perEP[e.EndpointID]
			m.OS, m.Apps, m.OSSupport, m.OSLastUpdate = c.OS, c.Apps, c.OSSupport, c.OSLastUpdate
		} else if m.Catalog == 0 {
			e.Missing = nil
			continue
		}
		e.Missing = &m
	}
}

// listEndpoints lists endpoints without parsing inventories; missing comes
// from the cached fleet snapshot and needs (rebuilt at most once per
// fleetTTL or store change).
func (s *Server) listEndpoints(w http.ResponseWriter, r *http.Request) {
	eps, err := s.honestEndpoints(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, eps)
}

func (s *Server) getEndpoint(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	v, err := s.store.GetEndpoint(ctx, r.PathValue("id"), s.th)
	if err != nil {
		s.fail(w, err)
		return
	}
	one := []store.Endpoint{v.Endpoint}
	if err := s.missingFor(ctx, one); err != nil {
		s.fail(w, err)
		return
	}
	refineStatus(one)
	v.Endpoint = one[0]
	writeJSON(w, 200, v)
}

// missingFor fills Missing from the cached views.
func (s *Server) missingFor(ctx context.Context, eps []store.Endpoint) error {
	_, snap, err := s.fleetSnap(ctx, nil)
	if err != nil {
		return err
	}
	nv, err := s.fleetNeeds(ctx)
	if err != nil {
		return err
	}
	fillMissing(eps, snap, nv.ready, nv.catalog)
	return nil
}

// ---- GET /api/fleet/status ----

type fleetStatusEndpoint struct {
	EndpointID string `json:"endpoint_id"`
	Hostname   string `json:"hostname"`
	Status     string `json:"status"` // up_to_date | outdated | being_patched | verified | failed | exception
	Installed  string `json:"installed"`
}

type fleetStatusRow struct {
	Kind      string               `json:"kind"`
	Key       string               `json:"key"`
	Name      string               `json:"name"`
	Latest    string               `json:"latest"`
	Catalog   *catalogLink         `json:"catalog"`
	Requested *store.AcqRequestRef `json:"requested"`
	// Importable / ImportableReason: as on GET /api/updates and the Library.
	Importable       string `json:"importable"`
	ImportableReason string `json:"importable_reason"`
	UpToDate         int    `json:"up_to_date"`
	Outdated         int    `json:"outdated"`
	BeingPatched     int    `json:"being_patched"`
	Verified         int    `json:"verified"`
	Failed           int    `json:"failed"`
	Exception        int    `json:"exception"`
	// Uncovered / UncoveredBuilds: as on GET /api/updates (machines needing
	// it that no catalog package applies to, e.g. 25H2 with only the 24H2
	// package of a shared KB). Import stays offered for them.
	Uncovered       int                   `json:"uncovered"`
	UncoveredBuilds []int                 `json:"uncovered_builds,omitempty"`
	Endpoints       []fleetStatusEndpoint `json:"endpoints"`
}

type fleetStatus struct {
	Intel *intake.IntelSummary `json:"intel"`
	Rows  []fleetStatusRow     `json:"rows"`
}

// fleetStatusCache: the status built from one fleet snapshot, for fleetTTL.
type fleetStatusCache struct {
	snap *fleetSnapshot
	at   time.Time
	v    fleetStatus
}

// endpointStatus applies the precedence exception > failed > being_patched >
// verified > outdated > up_to_date.
func endpointStatus(st store.TargetStatus, outdated bool) string {
	switch {
	case st.Exception:
		return "exception"
	case st.Failed:
		return "failed"
	case st.Deploying:
		return "being_patched"
	case st.Verified:
		return "verified"
	case outdated:
		return "outdated"
	}
	return "up_to_date"
}

// fleetStatusHandler: GET /api/fleet/status. Without ?key every row has its
// counts and an empty endpoints list; with ?key=<KB or winget id> (and
// optionally kind=os|app) rows holds just that row with its full endpoint
// list (404 if there is no such row).
func (s *Server) fleetStatusHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	key, kind := strings.TrimSpace(q.Get("key")), q.Get("kind")
	if kind != "" && kind != "os" && kind != "app" {
		writeErr(w, http.StatusBadRequest, "kind must be os or app")
		return
	}
	if key == "" && kind != "" {
		writeErr(w, http.StatusBadRequest, "kind needs key")
		return
	}
	if len(key) > 256 {
		writeErr(w, http.StatusBadRequest, "key too long")
		return
	}
	v, err := s.fleetStatus(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	if key == "" {
		writeJSON(w, 200, v.summary())
		return
	}
	row, ok := v.row(kind, key)
	if !ok {
		writeErr(w, http.StatusNotFound, "no fleet status row for "+key)
		return
	}
	writeJSON(w, 200, fleetStatus{Intel: v.Intel, Rows: []fleetStatusRow{row}})
}

// summary is the status with every row's endpoint list left empty (the
// counts stay). v is shared: the rows are copied.
func (v fleetStatus) summary() fleetStatus {
	out := fleetStatus{Intel: v.Intel, Rows: make([]fleetStatusRow, len(v.Rows))}
	for i, r := range v.Rows {
		r.Endpoints = []fleetStatusEndpoint{}
		out.Rows[i] = r
	}
	return out
}

// row finds a row by key (KB or winget id, case-insensitive) and, if
// given, kind.
func (v fleetStatus) row(kind, key string) (fleetStatusRow, bool) {
	for _, r := range v.Rows {
		if (kind == "" || r.Kind == kind) && strings.EqualFold(r.Key, key) {
			return r, true
		}
	}
	return fleetStatusRow{}, false
}

func (s *Server) fleetStatus(ctx context.Context) (fleetStatus, error) {
	sum, snap, err := s.fleetSnap(ctx, nil)
	if err != nil {
		return fleetStatus{}, err
	}
	if snap == nil {
		return fleetStatus{Intel: sum, Rows: []fleetStatusRow{}}, nil
	}
	s.intel.statusMu.Lock() // one build per snapshot
	defer s.intel.statusMu.Unlock()
	s.intel.mu.Lock()
	c := s.intel.status
	s.intel.mu.Unlock()
	if c != nil && c.snap == snap && time.Since(c.at) < fleetTTL {
		return c.v, nil
	}
	ft, err := s.store.FleetTargets(ctx)
	if err != nil {
		return fleetStatus{}, err
	}
	refs, err := s.acqRefs(ctx)
	if err != nil {
		return fleetStatus{}, err
	}
	out := fleetStatus{Intel: sum, Rows: make([]fleetStatusRow, 0, len(snap.all))}
	for _, u := range snap.all {
		cat := u.statusCatalog()
		row := fleetStatusRow{Kind: u.Kind, Key: u.Key, Name: u.Name, Latest: u.Latest, Catalog: cat, Requested: refFor(refs, u.Kind, u.Key),
			Importable: u.Importable, ImportableReason: u.ImportableReason, Uncovered: u.Uncovered, UncoveredBuilds: u.UncoveredBuilds,
			Endpoints: make([]fleetStatusEndpoint, 0, len(u.Endpoints)+len(u.current))}
		add := func(n fleetNeed, outdated bool) {
			var st store.TargetStatus
			switch {
			case n.PackageID != "":
				st = ft.Status(n.PackageID, n.EndpointID) // the package for its build
			case cat != nil && (u.Kind == "app" || !outdated):
				st = ft.Status(cat.PackageID, n.EndpointID)
			}
			e := fleetStatusEndpoint{EndpointID: n.EndpointID, Hostname: n.Hostname, Status: endpointStatus(st, outdated), Installed: n.Installed}
			switch e.Status {
			case "exception":
				row.Exception++
			case "failed":
				row.Failed++
			case "being_patched":
				row.BeingPatched++
			case "verified":
				row.Verified++
			case "outdated":
				row.Outdated++
			default:
				row.UpToDate++
			}
			row.Endpoints = append(row.Endpoints, e)
		}
		for _, n := range u.Endpoints {
			add(n, true)
		}
		for _, n := range u.current {
			add(n, false)
		}
		out.Rows = append(out.Rows, row)
	}
	s.intel.mu.Lock()
	if s.intel.fleet == snap { // not replaced meanwhile
		s.intel.status = &fleetStatusCache{snap: snap, at: time.Now(), v: out}
	}
	s.intel.mu.Unlock()
	return out, nil
}

// ---- GET /api/acquisition-requests ----

func (s *Server) listAcqRequests(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.ListAcqRequests(r.Context(), store.MaxAcqRequests)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, v)
}

// ---- POST /api/deployments/{id}/retry_failed ----

func (s *Server) retryFailed(w http.ResponseWriter, r *http.Request) {
	var body reasonBody
	if !decode(w, r, &body) {
		return
	}
	if !s.agentDeploymentManaged(w, r, r.PathValue("id")) {
		return
	}
	v, err := s.store.RetryFailed(r.Context(), actor(r), r.PathValue("id"), body.Reason)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, v)
}
