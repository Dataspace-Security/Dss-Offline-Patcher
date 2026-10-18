package server

import (
	"context"
	"fmt"
	"time"

	"offpatch/internal/intake"
	"offpatch/internal/store"
)

// Honest endpoint status (docs/03-state-model.md): the store derives
// "compliant" from deployment targets alone, so a machine nobody deployed
// anything to is compliant even when update intelligence says it is
// missing Windows or app updates, or runs a Windows build Microsoft no
// longer updates. The API refines compliant with the intelligence:
//
//   - out_of_support: missing.os_support is "out_of_support";
//   - updates_available: missing.os + missing.apps > 0, or it needs an
//     approved or quarantined catalog package (missing.catalog > 0: the
//     catalog may know a patch the intelligence does not);
//
// out_of_support wins over updates_available. Neither overrides a status
// that already says something is wrong or unknown (failed, pending_reboot,
// offline, stale, ...): only compliant is refined.
func honestStatus(e store.Endpoint) string {
	if e.Status != "compliant" || e.Missing == nil {
		return e.Status
	}
	switch {
	case e.Missing.OSSupport == "out_of_support":
		return "out_of_support"
	case e.Missing.OS+e.Missing.Apps+e.Missing.Catalog > 0:
		return "updates_available"
	}
	return e.Status
}

// refineStatus applies honestStatus to endpoints whose Missing is filled.
func refineStatus(eps []store.Endpoint) {
	for i := range eps {
		eps[i].Status = honestStatus(eps[i])
	}
}

// honestEndpoints lists endpoints (no inventories) with Missing and the
// refined status: what lists, reports and counts must agree on.
func (s *Server) honestEndpoints(ctx context.Context) ([]store.Endpoint, error) {
	eps, err := s.store.ListEndpointsBrief(ctx, s.th)
	if err != nil {
		return nil, err
	}
	if err := s.missingFor(ctx, eps); err != nil {
		return nil, err
	}
	refineStatus(eps)
	return eps, nil
}

// honestSummary is store.Summary with endpoint counts by refined status.
func (s *Server) honestSummary(ctx context.Context) (store.Summary, error) {
	sm, err := s.store.Summary(ctx, s.th)
	if err != nil {
		return sm, err
	}
	eps, err := s.honestEndpoints(ctx)
	if err != nil {
		return sm, err
	}
	by := map[string]int{}
	for _, k := range store.EndpointStatuses {
		by[k] = 0
	}
	total, retired := 0, 0
	for _, e := range eps {
		if e.Status == "retired" {
			retired++
			continue
		}
		total++
		by[e.Status]++
	}
	sm.Endpoints.ByStatus, sm.Endpoints.Total, sm.Endpoints.Retired = by, total, retired
	if sm.Intel, err = s.intelAge(ctx); err != nil {
		return sm, err
	}
	return sm, nil
}

// IntelStaleAfter: update intelligence older than this no longer says
// reliably what endpoints are missing (pmctl builds it daily; a week of
// missed runs means the acquisition side needs attention).
const IntelStaleAfter = 8 * 24 * time.Hour

// intelAge is how old the current update intelligence is (nil: none).
func (s *Server) intelAge(ctx context.Context) (*store.IntelAge, error) {
	gen, err := s.store.GetMeta(ctx, intake.MetaIntelGenerated)
	if err != nil || gen == "" {
		return nil, err
	}
	t, err := time.Parse(time.RFC3339, gen)
	if err != nil {
		return nil, nil
	}
	age := s.store.Now().Sub(t)
	return &store.IntelAge{GeneratedAt: gen, AgeHours: float64(int(age.Hours()*10)) / 10, Stale: age > IntelStaleAfter}, nil
}

// SweepIntelAlerts raises and resolves the alerts that need update intelligence:
// intel_stale (the document is older than IntelStaleAfter; closes when a
// fresh one arrives) and out_of_support (endpoints on a Windows build
// Microsoft no longer updates, by hostname; closes when none is left).
// Without usable intelligence out_of_support is left as it is: nothing can
// be said either way.
func (s *Server) SweepIntelAlerts(ctx context.Context) error {
	age, err := s.intelAge(ctx)
	if err != nil {
		return err
	}
	if age != nil && age.Stale {
		msg := fmt.Sprintf("update intelligence is %d days old (generated %s): missing updates shown may be out of date; ask the acquisition team whether the daily acquisition run is working",
			int(age.AgeHours/24), age.GeneratedAt)
		if err := s.store.SetConditionAlert(ctx, "warning", "intel_stale", "intel", "intel", msg,
			map[string]any{"generated_at": age.GeneratedAt, "age_hours": age.AgeHours}); err != nil {
			return err
		}
	} else if err := s.store.ResolveAlert(ctx, "intel_stale", "", "fresh update intelligence arrived"); err != nil {
		return err
	}
	ix, _, err := s.intelIndex(ctx)
	if err != nil || ix == nil {
		return err
	}
	eps, err := s.honestEndpoints(ctx)
	if err != nil {
		return err
	}
	var hosts []store.HostRef
	for _, e := range eps {
		if e.Status != "retired" && e.Missing != nil && e.Missing.OSSupport == "out_of_support" {
			hosts = append(hosts, store.HostRef{EndpointID: e.EndpointID, Hostname: e.Hostname})
		}
	}
	return s.store.SetHostAlert(ctx, "warning", "out_of_support", "fleet", "out_of_support",
		fmt.Sprintf("%d endpoint(s) run a Windows build Microsoft no longer updates (plan an upgrade)", len(hosts)), hosts,
		"no endpoint runs an out-of-support Windows build any more")
}
