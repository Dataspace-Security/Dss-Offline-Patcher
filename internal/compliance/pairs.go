package compliance

import (
	"sort"
	"time"

	"offpatch/internal/store"
)

// pair is one applicable endpoint/update pair, compact (indexes into the
// input) so a 20 000-endpoint fleet with many updates stays small.
type pair struct {
	ep, pkg      int32
	t            *store.PackTarget // best install target, nil when needed only
	outcome      string
	pastDeadline bool
	priority     string
	clock        time.Time
	deadline     time.Time
	verifiedAt   string
	installedAt  string
	exceptionID  string
	basis        string
}

// staleStatuses: no current inventory (silence is never compliance).
var staleStatuses = map[string]bool{"stale": true, "offline": true, "awaiting_checkin": true, "lost_after_install": true}

// targetRank orders the states of one endpoint's targets for one package
// across install deployments: the most conclusive wins.
var targetRank = map[string]int{"verified": 7, "exception": 6, "not_applicable": 5, "installed": 4, "pending_reboot": 4,
	"pending": 3, "deferred": 3, "downloading": 3, "downloaded": 3, "installing": 3, "failed": 2, "lost_after_install": 2, "rolled_back": 1}

type pairsResult struct {
	pairs       []pair
	byEP        map[int32][]int // endpoint index → pair indexes
	excluded    int             // packages revoked / rejected (not required)
	noClock     int             // pairs without a deadline (clock start unknown)
	emergencyPk map[int32]bool  // packages handled as emergency
}

func parseTS(s string) time.Time {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	return time.Time{}
}

// clockStart is when the deadline clock starts for package p.
func clockStart(p store.Package, how string, loc *time.Location) time.Time {
	switch how {
	case "acquired":
		return parseTS(p.CreatedAt)
	case "approved":
		if p.State != "approved" && p.State != "revoked" || len(p.Approvals) == 0 {
			return time.Time{}
		}
		return parseTS(p.Approvals[len(p.Approvals)-1].At)
	}
	t, err := time.ParseInLocation("2006-01-02", p.ReleaseDate, loc)
	if err != nil {
		return time.Time{}
	}
	return t
}

func approvedAt(p store.Package) string {
	if (p.State == "approved" || p.State == "revoked") && len(p.Approvals) > 0 {
		return p.Approvals[len(p.Approvals)-1].At
	}
	return ""
}

// buildPairs evaluates every applicable endpoint/update pair at asOf.
func buildPairs(in *Input, asOf time.Time) pairsResult {
	res := pairsResult{byEP: map[int32][]int{}, emergencyPk: map[int32]bool{}}
	epIdx := make(map[string]int32, len(in.Endpoints))
	for i, e := range in.Endpoints {
		if e.RetiredAt == "" && e.Status != "retired" {
			epIdx[e.EndpointID] = int32(i)
		}
	}
	pkIdx := map[string]int32{}
	for i, p := range in.Packages {
		switch p.State {
		case "approved", "quarantined":
			pkIdx[p.PackageID] = int32(i)
		default:
			res.excluded++
		}
	}
	type key struct{ pkg, ep int32 }
	best := map[key]*store.PackTarget{}
	for i := range in.Targets {
		t := &in.Targets[i]
		if t.Operation != "install" {
			continue
		}
		pi, ok1 := pkIdx[t.PackageID]
		ei, ok2 := epIdx[t.EndpointID]
		if !ok1 || !ok2 {
			continue
		}
		if t.DeploymentState == "cancelled" && t.State != "verified" || t.DeploymentState == "rejected" || t.DeploymentState == "pending_approval" {
			continue
		}
		if t.Emergency {
			res.emergencyPk[pi] = true
		}
		k := key{pi, ei}
		if cur, ok := best[k]; !ok || targetRank[t.State] > targetRank[cur.State] {
			best[k] = t
		}
	}
	keys := make(map[key]string, len(best))
	for k := range best {
		keys[k] = "targeted"
	}
	for pkg, eps := range in.Needs {
		pi, ok := pkIdx[pkg]
		if !ok {
			continue
		}
		for _, ep := range eps {
			if ei, ok := epIdx[ep]; ok {
				if _, seen := keys[key{pi, ei}]; !seen {
					keys[key{pi, ei}] = "needed"
				}
			}
		}
	}
	// Active exceptions: per endpoint, by package ("" = all packages).
	exc := map[string]map[string]string{}
	for _, x := range in.Exceptions {
		if !x.Active {
			continue
		}
		if exc[x.EndpointID] == nil {
			exc[x.EndpointID] = map[string]string{}
		}
		exc[x.EndpointID][x.PackageID] = x.ExceptionID
		if x.PackageID != "" {
			pi, ok1 := pkIdx[x.PackageID]
			ei, ok2 := epIdx[x.EndpointID]
			if ok1 && ok2 {
				if _, seen := keys[key{pi, ei}]; !seen {
					keys[key{pi, ei}] = "exception"
				}
			}
		}
	}
	ordered := make([]key, 0, len(keys))
	for k := range keys {
		ordered = append(ordered, k)
	}
	sort.Slice(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		if in.Endpoints[a.ep].Hostname != in.Endpoints[b.ep].Hostname {
			return in.Endpoints[a.ep].Hostname < in.Endpoints[b.ep].Hostname
		}
		return in.Packages[a.pkg].PackageID < in.Packages[b.pkg].PackageID
	})
	res.pairs = make([]pair, 0, len(ordered))
	for _, k := range ordered {
		p := in.Packages[k.pkg]
		e := in.Endpoints[k.ep]
		pr := pair{ep: k.ep, pkg: k.pkg, t: best[k], basis: keys[k]}
		pr.priority = store.PriorityForSeverity(p.Severity)
		if res.emergencyPk[k.pkg] {
			pr.priority = "emergency"
		}
		rule := in.Profile.Profile.DeadlineFor(in.Policy, pr.priority)
		pr.clock = clockStart(p, rule.ClockStart, in.Loc)
		if !pr.clock.IsZero() {
			pr.deadline = pr.clock.Add(time.Duration(rule.MaxDays) * 24 * time.Hour)
		} else {
			res.noClock++
		}
		if pr.t != nil {
			pr.installedAt = in.InstallTimes[pr.t.DeploymentID+"/"+pr.t.EndpointID]
		}
		if x := exc[e.EndpointID]; x != nil {
			if id, ok := x[p.PackageID]; ok {
				pr.exceptionID = id
			} else if id, ok := x[""]; ok {
				pr.exceptionID = id
			}
		}
		pr.outcome, pr.pastDeadline = outcomeOf(&pr, p, e, asOf)
		res.byEP[k.ep] = append(res.byEP[k.ep], len(res.pairs))
		res.pairs = append(res.pairs, pr)
	}
	return res
}

func outcomeOf(pr *pair, p store.Package, e store.Endpoint, asOf time.Time) (string, bool) {
	t := pr.t
	if t != nil && t.State == "verified" {
		v := parseTS(t.UpdatedAt)
		if !v.After(asOf) {
			pr.verifiedAt = t.UpdatedAt
			if pr.deadline.IsZero() || !v.After(pr.deadline) {
				return OutcomeCompliant, false
			}
			return OutcomeVerifiedLate, false
		}
	}
	if t != nil && t.State == "not_applicable" && pr.basis == "targeted" {
		return OutcomeNotApplicable, false
	}
	if pr.exceptionID != "" || t != nil && t.State == "exception" {
		return OutcomeException, false
	}
	if p.SupersededBy != "" {
		// The superseding update's own pair carries the requirement.
		return OutcomeNotApplicable, false
	}
	past := !pr.deadline.IsZero() && asOf.After(pr.deadline)
	switch {
	case t != nil && (t.State == "failed" || t.State == "lost_after_install"):
		return OutcomeFailed, past
	case staleStatuses[e.Status]:
		return OutcomeOffline, past
	case past:
		return OutcomeOverdue, true
	}
	return OutcomePending, false
}

// exported is the JSON / CSV form of a pair.
func (pk *Pack) exported(pr pair) Pair {
	in := pk.in
	p := in.Packages[pr.pkg]
	e := in.Endpoints[pr.ep]
	rule := in.Profile.Profile.DeadlineFor(in.Policy, pr.priority)
	out := Pair{EndpointID: e.EndpointID, Hostname: e.Hostname, PackageID: p.PackageID, Title: p.Title, KB: p.KB, Severity: p.Severity,
		Priority: pr.priority, ReleaseDate: p.ReleaseDate, AcquiredAt: p.CreatedAt, ApprovedAt: approvedAt(p), ClockStart: rule.ClockStart,
		DeadlineSource: rule.Source, InstalledAt: pr.installedAt, VerifiedAt: pr.verifiedAt, Outcome: pr.outcome, PastDeadline: pr.pastDeadline,
		ExceptionID: pr.exceptionID, Basis: pr.basis}
	if !pr.deadline.IsZero() {
		out.Deadline = pr.deadline.In(in.Loc).Format(time.RFC3339)
	}
	if pr.t != nil {
		out.DeploymentID, out.Evidence = pr.t.DeploymentID, pr.t.Evidence
	}
	return out
}

// PairsLimit bounds the pairs listed in the JSON pack (all pairs are in
// evidence E-007 of the ZIP package).
const PairsLimit = 1000

var outcomeOrder = map[string]int{OutcomeOverdue: 0, OutcomeFailed: 1, OutcomeOffline: 2, OutcomeVerifiedLate: 3, OutcomeException: 4, OutcomePending: 5, OutcomeCompliant: 6, OutcomeNotApplicable: 7}

func (pk *Pack) timeliness(asOf time.Time, res pairsResult) Timeliness {
	in := pk.in
	tl := Timeliness{AsOf: asOf.In(in.Loc).Format(time.RFC3339), OutcomeCounts: map[string]int{}, PairsTotal: len(res.pairs), PairsLimit: PairsLimit, Pairs: []Pair{}}
	for _, o := range Outcomes {
		tl.OutcomeCounts[o] = 0
	}
	by := map[string]*PriorityStats{}
	for _, pr := range store.DeadlinePriorities {
		r := in.Profile.Profile.DeadlineFor(in.Policy, pr)
		by[pr] = &PriorityStats{Priority: pr, MaxDays: r.MaxDays, Source: r.Source, ClockStart: r.ClockStart, ExceptionProcess: r.ExceptionProcess}
	}
	for _, p := range res.pairs {
		tl.OutcomeCounts[p.outcome]++
		s := by[p.priority]
		s.Pairs++
		switch p.outcome {
		case OutcomeCompliant:
			s.Compliant++
		case OutcomeVerifiedLate:
			s.VerifiedLate++
		case OutcomeOverdue:
			s.Overdue++
		case OutcomePending:
			s.Pending++
		case OutcomeFailed:
			s.Failed++
		case OutcomeOffline:
			s.Offline++
		case OutcomeException:
			s.Exception++
		case OutcomeNotApplicable:
			s.NotApplicable++
		}
		if p.pastDeadline {
			s.PastDeadlineOpen++
		}
	}
	for _, pr := range store.DeadlinePriorities {
		s := by[pr]
		s.PctOnTime = pctOf(s.Compliant, s.Pairs-s.NotApplicable-s.Exception)
		tl.ByPriority = append(tl.ByPriority, *s)
	}
	idx := make([]int, len(res.pairs))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool {
		return outcomeOrder[res.pairs[idx[a]].outcome] < outcomeOrder[res.pairs[idx[b]].outcome]
	})
	for _, i := range idx {
		if len(tl.Pairs) >= PairsLimit {
			tl.PairsTruncated = true
			break
		}
		tl.Pairs = append(tl.Pairs, pk.exported(res.pairs[i]))
	}
	return tl
}

// pctOf is a/b in percent with one decimal (0 when b is 0: nothing to
// measure is never 100 %).
func pctOf(a, b int) float64 {
	if b <= 0 {
		return 0
	}
	return float64(int(float64(a)*1000/float64(b)+0.5)) / 10
}
