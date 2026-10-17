package store

import (
	"context"
	"sort"
	"time"
)

// DefaultDeadlines: time from vendor release to required installation.
var DefaultDeadlines = map[string]time.Duration{
	"critical":  7 * 24 * time.Hour,
	"important": 30 * 24 * time.Hour,
	"moderate":  60 * 24 * time.Hour,
	"low":       90 * 24 * time.Hour,
}

func (p Policy) deadline(sev string) time.Duration {
	if d, ok := p.Deadlines[sev]; ok && d > 0 {
		return d
	}
	return DefaultDeadlines[sev]
}

type SeverityStats struct {
	Targets     int     `json:"targets"`
	Verified    int     `json:"verified"`
	Outstanding int     `json:"outstanding"`
	Overdue     int     `json:"overdue"`
	Exceptions  int     `json:"exceptions"`
	PctComplete float64 `json:"pct_compliant"`
}

type PackageReport struct {
	PackageID   string  `json:"package_id"`
	Title       string  `json:"title"`
	Severity    string  `json:"severity"`
	State       string  `json:"state"`
	ReleaseDate string  `json:"release_date"`
	Deadline    string  `json:"deadline"`
	ReceivedAt  string  `json:"received_at"`
	ApprovedAt  string  `json:"approved_at"`
	FirstVerify string  `json:"first_verified_at"`
	P90Verify   string  `json:"p90_verified_at"`
	Targets     int     `json:"targets"`
	Verified    int     `json:"verified"`
	Outstanding int     `json:"outstanding"`
	Overdue     int     `json:"overdue"`
	Exceptions  int     `json:"exceptions"`
	PctComplete float64 `json:"pct_compliant"`
	// Latency in days (−1 = not yet reached).
	DaysReleaseToReceived  float64 `json:"days_release_to_received"`
	DaysReceivedToApproved float64 `json:"days_received_to_approved"`
	DaysApprovedToFirst    float64 `json:"days_approved_to_first_verified"`
	DaysReleaseToP90       float64 `json:"days_release_to_90pct_verified"`
}

type ComplianceReport struct {
	GeneratedAt string                   `json:"generated_at"`
	Deadlines   map[string]string        `json:"deadlines"`
	BySeverity  map[string]SeverityStats `json:"by_severity"`
	Packages    []PackageReport          `json:"packages"`
	Fleet       struct {
		Total        int     `json:"total"`
		Reporting    int     `json:"reporting"` // checked in within offline_after
		Offline      int     `json:"offline"`
		Stale        int     `json:"stale"`
		PendingBoot  int     `json:"pending_reboot"`
		PctReporting float64 `json:"pct_reporting"`
	} `json:"fleet"`
	Exceptions struct {
		Active        int     `json:"active"`
		ExpiringIn7d  int     `json:"expiring_in_7d"`
		OldestAgeDays float64 `json:"oldest_age_days"`
	} `json:"exceptions"`
	Intake struct {
		Validated int `json:"validated"`
		Rejected  int `json:"rejected"`
	} `json:"intake"`
}

func days(a, b time.Time) float64 {
	if a.IsZero() || b.IsZero() {
		return -1
	}
	return float64(int(b.Sub(a).Hours()/24*10)) / 10
}

func pct(a, b int) float64 {
	if b == 0 {
		return 100
	}
	return float64(int(float64(a)*1000/float64(b))) / 10
}

// Compliance builds the report the workflow's §11 metrics call for.
func (s *Store) Compliance(ctx context.Context, th Thresholds) (ComplianceReport, error) {
	now := s.Now()
	r := ComplianceReport{GeneratedAt: now.Format(time.RFC3339), Deadlines: map[string]string{}, BySeverity: map[string]SeverityStats{}, Packages: []PackageReport{}}
	for _, sev := range []string{"critical", "important", "moderate", "low"} {
		r.Deadlines[sev] = s.Policy.deadline(sev).String()
		r.BySeverity[sev] = SeverityStats{}
	}
	pkgs, err := s.ListPackages(ctx, "")
	if err != nil {
		return r, err
	}
	targets, err := queryTargets(ctx, s.db, `d.state != 'cancelled' AND d.operation='install'`)
	if err != nil {
		return r, err
	}
	// Best state per (package, endpoint) across deployments.
	rank := map[string]int{"verified": 5, "exception": 4, "not_applicable": 3, "pending_reboot": 2, "installed": 2}
	type key struct{ pkg, ep string }
	best := map[key]Target{}
	for _, t := range targets {
		k := key{t.PackageID, t.EndpointID}
		if cur, ok := best[k]; !ok || rank[t.State] > rank[cur.State] {
			best[k] = t
		}
	}
	byPkg := map[string][]Target{}
	for k, t := range best {
		byPkg[k.pkg] = append(byPkg[k.pkg], t)
	}
	for _, p := range pkgs {
		ts := byPkg[p.PackageID]
		if p.State != "approved" && len(ts) == 0 {
			continue
		}
		pr := PackageReport{PackageID: p.PackageID, Title: p.Title, Severity: p.Severity, State: p.State, ReleaseDate: p.ReleaseDate, ReceivedAt: p.CreatedAt}
		release, _ := time.Parse("2006-01-02", p.ReleaseDate)
		received := parseTime(p.CreatedAt)
		var approved time.Time
		if p.State == "approved" || p.State == "revoked" {
			if len(p.Approvals) > 0 {
				approved = parseTime(p.Approvals[len(p.Approvals)-1].At)
			}
			pr.ApprovedAt = formatOrEmpty(approved)
		}
		var deadline time.Time
		if !release.IsZero() {
			deadline = release.Add(s.Policy.deadline(p.Severity))
			pr.Deadline = deadline.Format(time.RFC3339)
		}
		var verifiedAt []time.Time
		for _, t := range ts {
			switch t.State {
			case "not_applicable":
				continue
			case "exception":
				pr.Exceptions++
				continue
			}
			pr.Targets++
			if t.State == "verified" {
				pr.Verified++
				verifiedAt = append(verifiedAt, parseTime(t.UpdatedAt))
			} else {
				pr.Outstanding++
				if !deadline.IsZero() && now.After(deadline) {
					pr.Overdue++
				}
			}
		}
		sort.Slice(verifiedAt, func(i, j int) bool { return verifiedAt[i].Before(verifiedAt[j]) })
		var first, p90 time.Time
		if len(verifiedAt) > 0 {
			first = verifiedAt[0]
			pr.FirstVerify = first.Format(time.RFC3339)
		}
		if need := (pr.Targets*9 + 9) / 10; pr.Targets > 0 && len(verifiedAt) >= need && need > 0 {
			p90 = verifiedAt[need-1]
			pr.P90Verify = p90.Format(time.RFC3339)
		}
		pr.PctComplete = pct(pr.Verified, pr.Targets)
		pr.DaysReleaseToReceived = days(release, received)
		pr.DaysReceivedToApproved = days(received, approved)
		pr.DaysApprovedToFirst = days(approved, first)
		pr.DaysReleaseToP90 = days(release, p90)
		r.Packages = append(r.Packages, pr)

		ss := r.BySeverity[p.Severity]
		ss.Targets += pr.Targets
		ss.Verified += pr.Verified
		ss.Outstanding += pr.Outstanding
		ss.Overdue += pr.Overdue
		ss.Exceptions += pr.Exceptions
		ss.PctComplete = pct(ss.Verified, ss.Targets)
		r.BySeverity[p.Severity] = ss
	}
	sort.Slice(r.Packages, func(i, j int) bool {
		if r.Packages[i].Overdue != r.Packages[j].Overdue {
			return r.Packages[i].Overdue > r.Packages[j].Overdue
		}
		return r.Packages[i].PackageID < r.Packages[j].PackageID
	})

	eps, err := s.ListEndpoints(ctx, th)
	if err != nil {
		return r, err
	}
	for _, e := range eps {
		if e.Status == "retired" {
			continue
		}
		r.Fleet.Total++
		switch e.Status {
		case "offline":
			r.Fleet.Offline++
		case "stale":
			r.Fleet.Stale++
		}
		if e.Status != "offline" {
			r.Fleet.Reporting++
		}
		if e.RebootPending || e.Status == "pending_reboot" {
			r.Fleet.PendingBoot++
		}
	}
	r.Fleet.PctReporting = pct(r.Fleet.Reporting, r.Fleet.Total)

	xs, err := s.ListExceptions(ctx)
	if err != nil {
		return r, err
	}
	for _, x := range xs {
		if !x.Active {
			continue
		}
		r.Exceptions.Active++
		if parseTime(x.ExpiresAt).Before(now.Add(7 * 24 * time.Hour)) {
			r.Exceptions.ExpiringIn7d++
		}
		if age := days(parseTime(x.CreatedAt), now); age > r.Exceptions.OldestAgeDays {
			r.Exceptions.OldestAgeDays = age
		}
	}
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM bundles WHERE state='validated'`).Scan(&r.Intake.Validated)
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM bundles WHERE state='rejected'`).Scan(&r.Intake.Rejected)
	return r, nil
}

func formatOrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
