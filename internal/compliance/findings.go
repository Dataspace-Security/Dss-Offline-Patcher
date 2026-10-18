package compliance

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"offpatch/internal/store"
)

// severityPriority: the deadline rule that sets a finding's due date.
var severityPriority = map[string]string{SevCritical: "critical", SevHigh: "high", SevMedium: "moderate", SevLow: "low"}

var severityRank = map[string]int{SevCritical: 0, SevHigh: 1, SevMedium: 2, SevLow: 3}

func sample(xs []string) []string {
	ys := append([]string{}, xs...)
	sort.Strings(ys)
	if len(ys) > 20 {
		ys = ys[:20]
	}
	return ys
}

// findings derives the corrective-action findings (template §7) from the
// period's facts. Root causes are for the owner to determine.
func (pk *Pack) findings(f *facts, res pairsResult) []Finding {
	in := pk.in
	prof := in.Profile.Profile
	owner := prof.AssessmentOwner
	if owner == "" {
		owner = "Unassigned (set the assessment owner in the report profile)"
	}
	due := func(sev string) string {
		r := prof.DeadlineFor(in.Policy, severityPriority[sev])
		return f.asOf.In(in.Loc).Add(time.Duration(r.MaxDays) * 24 * time.Hour).Format("2006-01-02")
	}
	var out []Finding
	add := func(fd Finding) {
		fd.Owner, fd.DueDate, fd.Status = owner, due(fd.Severity), "Open"
		if fd.RootCause == "" {
			fd.RootCause = "To be determined by the owner"
		}
		if fd.Affected == nil {
			fd.Affected = []string{}
		}
		out = append(out, fd)
	}
	hostsOf := func(idx []int) []string {
		seen := map[string]bool{}
		var hs []string
		for _, i := range idx {
			h := in.Endpoints[res.pairs[i].ep].Hostname
			if !seen[h] {
				seen[h] = true
				hs = append(hs, h)
			}
		}
		return hs
	}

	// Overdue, by priority.
	for _, pr := range store.DeadlinePriorities {
		var idx []int
		pkgs := map[string]bool{}
		for i, p := range res.pairs {
			if p.pastDeadline && p.priority == pr {
				idx = append(idx, i)
				pkgs[in.Packages[p.pkg].PackageID] = true
			}
		}
		if len(idx) == 0 {
			continue
		}
		sev := map[string]string{"emergency": SevCritical, "critical": SevCritical, "high": SevHigh, "moderate": SevMedium, "low": SevLow}[pr]
		hosts := hostsOf(idx)
		var ids []string
		for id := range pkgs {
			ids = append(ids, id)
		}
		r := prof.DeadlineFor(in.Policy, pr)
		add(Finding{Title: fmt.Sprintf("%s updates past their deadline", strings.ToUpper(pr[:1])+pr[1:]), Control: "PM-06", Source: "PM-06 / PM-10; " + r.Source,
			Observation: fmt.Sprintf("%d endpoint/update pairs (%d endpoints, %d updates: %s) are not installed and verified %d days after %s, and have no approved exception.",
				len(idx), len(hosts), len(ids), strings.Join(sample(ids), ", "), r.MaxDays, r.ClockStart),
			EvidenceIDs: []string{"E-003", "E-007"}, Risk: "Known vulnerabilities stay exploitable on the affected endpoints beyond the accepted window.", Severity: sev,
			CorrectiveAction: "Deploy (or retry) the updates to the affected endpoints, or raise approved, time-bound exceptions with compensating controls.",
			AffectedCount:    len(hosts), Affected: sample(hosts)})
	}
	if late := countOutcome(res, OutcomeVerifiedLate); late > 0 {
		add(Finding{Title: "Updates installed after their deadline", Control: "PM-06", Source: "PM-06",
			Observation: fmt.Sprintf("%d endpoint/update pairs were installed and verified, but after the configured deadline.", late),
			EvidenceIDs: []string{"E-007"}, Risk: "The policy timeline was not met during the period.", Severity: SevMedium,
			CorrectiveAction: "Review the causes of late deployment (approval lead time, maintenance windows, offline endpoints) and adjust the process.", AffectedCount: late})
	}
	if len(f.failedPairs) > 0 {
		hosts := hostsOf(f.failedPairs)
		add(Finding{Title: "Failed installations", Control: "PM-11", Source: "PM-10 / PM-11",
			Observation: fmt.Sprintf("%d endpoint/update pairs failed (%d of them endpoints that went silent after installing) on %d endpoints.", len(f.failedPairs), f.lostPairs, len(hosts)),
			EvidenceIDs: []string{"E-007", "E-008"}, Risk: "Failed endpoints remain unpatched; silent endpoints may be unusable.", Severity: SevHigh,
			CorrectiveAction: "Investigate the failure details, retry or repair, and record an owner (exception) where the update cannot be applied.",
			AffectedCount:    len(hosts), Affected: sample(hosts)})
	}
	if f.stale > 0 {
		sev := SevMedium
		if f.stale*10 > f.inScope {
			sev = SevHigh
		}
		add(Finding{Title: "Endpoints without current inventory", Control: "PM-02", Source: "PM-02",
			Observation: fmt.Sprintf("%d of %d in-scope endpoints are stale, offline or have not reported (%.1f %%). They are not counted as compliant.", f.stale, f.inScope, pctOf(f.stale, f.inScope)),
			EvidenceIDs: []string{"E-002"}, Risk: "Patch exposure of these endpoints is unknown.", Severity: sev,
			CorrectiveAction: "Restore agent connectivity or retire decommissioned endpoints; investigate silent machines.",
			AffectedCount:    f.stale, Affected: sample(f.staleHosts)})
	}
	if len(f.outOfSupport) > 0 {
		var hosts []string
		for _, i := range f.outOfSupport {
			hosts = append(hosts, in.Endpoints[i].Hostname)
		}
		add(Finding{Title: "Unsupported operating system builds", Control: "PM-17", Source: "PM-17",
			Observation: fmt.Sprintf("%d endpoints run a Windows build the vendor no longer updates.", len(hosts)),
			EvidenceIDs: []string{"E-002"}, Risk: "No security updates are available for these endpoints.", Severity: SevHigh,
			CorrectiveAction: "Upgrade or remove the endpoints; until then record risk acceptance (exception) with compensating controls.",
			AffectedCount:    len(hosts), Affected: sample(hosts)})
	}
	if len(f.approvalProblems) > 0 {
		add(Finding{Title: "Deployments without complete approval evidence", Control: "PM-07", Source: "PM-07",
			Observation: fmt.Sprintf("%d production deployments: %s.", len(f.approvalProblems), orNone(f.approvalProblems, 5)),
			EvidenceIDs: []string{"E-006"}, Risk: "Changes reached production without demonstrable change control.", Severity: SevHigh,
			CorrectiveAction: "Obtain retrospective change approval and confirm the two-person rule is configured (deployment_approvals ≥ 2).",
			AffectedCount:    len(f.approvalProblems)})
	}
	unsigned, noReceipt := 0, 0
	receipted := map[string]bool{}
	for _, r := range f.receiptsIn {
		if r.SignatureOK {
			receipted[r.FileSHA256] = true
		} else {
			unsigned++
		}
	}
	for _, b := range f.bundlesIn {
		if !receipted[b.FileSHA256] {
			noReceipt++
		}
	}
	if unsigned+noReceipt > 0 {
		add(Finding{Title: "Transfers without a valid receipt", Control: "PM-04", Source: "PM-04",
			Observation: fmt.Sprintf("%d bundles arrived without a matching signed sender receipt; %d receipts are unsigned or invalid.", noReceipt, unsigned),
			EvidenceIDs: []string{"E-004"}, Risk: "Transfers across the boundary cannot all be traced to the acquisition zone.", Severity: SevMedium,
			CorrectiveAction: "Reconcile the transfers with the acquisition team; use the receipt-producing transfer adapter for every transfer.", AffectedCount: unsigned + noReceipt})
	}
	if !in.Chain.OK {
		add(Finding{Title: "Audit trail integrity failure", Control: "PM-14", Source: "PM-14",
			Observation: fmt.Sprintf("Audit hash chain verification failed at event %d: %s.", in.Chain.FirstBadSeq, in.Chain.Error),
			EvidenceIDs: []string{"E-009"}, Risk: "Records may have been altered; evidence in this report may be unreliable.", Severity: SevCritical,
			CorrectiveAction: "Follow runbook 07 (audit verification): compare with the signed off-box export and investigate as a security incident.", AffectedCount: 1})
	} else if !in.Settings.AuditExportDir {
		add(Finding{Title: "Audit trail not exported off the server", Control: "PM-14", Source: "PM-14",
			Observation: "audit_export_dir is not configured: audit evidence exists only in the server database.",
			EvidenceIDs: []string{"E-009"}, Risk: "Loss or rewrite of the server would also lose the audit evidence.", Severity: SevMedium,
			CorrectiveAction: "Configure audit_export_dir on write-once storage (signed checkpoints).", AffectedCount: 1})
	}
	if len(f.privilegedNoMFA) > 0 {
		add(Finding{Title: "Privileged accounts without MFA", Control: "PM-13", Source: "PM-13",
			Observation: fmt.Sprintf("%d admin or super admin accounts have no multi-factor authentication.", len(f.privilegedNoMFA)),
			EvidenceIDs: []string{"E-009"}, Risk: "A stolen password is enough to change patch policy or approve changes.", Severity: SevMedium,
			CorrectiveAction: "Enrol an authenticator for every privileged account (or set require_mfa).", AffectedCount: len(f.privilegedNoMFA), Affected: sample(f.privilegedNoMFA)})
	}
	if in.Settings.InsecureHTTP {
		add(Finding{Title: "Management server in insecure lab mode", Control: "PM-16", Source: "PM-16",
			Observation: "insecure_http is enabled: no TLS and no agent certificates.", EvidenceIDs: []string{"E-009"},
			Risk: "Traffic and device credentials can be intercepted on the internal network.", Severity: SevHigh,
			CorrectiveAction: "Configure the internal PKI (pki_dir) and re-enrol endpoints (runbook 01).", AffectedCount: 1})
	}
	pol := prof.Policy
	if pol.ApprovedBy == "" && pol.Reference == "" {
		add(Finding{Title: "No approved patch policy recorded", Control: "PM-01", Source: "PM-01",
			Observation: "The report profile records no approved patch and change policy (version, approver, review date).",
			EvidenceIDs: []string{"E-001"}, Risk: "Timelines and responsibilities cannot be shown to be approved by management.", Severity: SevMedium,
			CorrectiveAction: "Record the approved policy in Reports → Report profile and attach it to the evidence package.", AffectedCount: 1})
	} else if rd, err := time.ParseInLocation("2006-01-02", pol.ReviewDate, in.Loc); err == nil && f.asOf.After(rd) {
		add(Finding{Title: "Patch policy review overdue", Control: "PM-01", Source: "PM-01",
			Observation: "The policy review date " + pol.ReviewDate + " has passed.", EvidenceIDs: []string{"E-001"},
			Risk: "The policy may no longer reflect current regulatory requirements.", Severity: SevLow,
			CorrectiveAction: "Review and re-approve the policy; update the report profile.", AffectedCount: 1})
	}
	expiring := 0
	for _, x := range f.activeExc {
		if parseTS(x.ExpiresAt).Before(f.asOf.Add(7 * 24 * time.Hour)) {
			expiring++
		}
	}
	if expiring > 0 {
		add(Finding{Title: "Exceptions expiring within 7 days", Control: "PM-11", Source: "PM-11",
			Observation: fmt.Sprintf("%d active exceptions expire within 7 days.", expiring), EvidenceIDs: []string{"E-008"},
			Risk: "Endpoints fall back to non-compliant when exceptions lapse.", Severity: SevLow,
			CorrectiveAction: "Patch the endpoints or review and renew the exceptions before they expire.", AffectedCount: expiring})
	}
	if in.IntelAge != nil && in.IntelAge.Stale {
		add(Finding{Title: "Update intelligence out of date", Control: "PM-02", Source: "PM-02 / PM-17",
			Observation: fmt.Sprintf("The update intelligence was generated %s (%.0f hours ago).", in.IntelAge.GeneratedAt, in.IntelAge.AgeHours),
			EvidenceIDs: []string{"E-002"}, Risk: "Missing updates and unsupported builds may be under-reported.", Severity: SevMedium,
			CorrectiveAction: "Ask the acquisition team to restore the daily acquisition run.", AffectedCount: 1})
	}
	sort.SliceStable(out, func(i, j int) bool { return severityRank[out[i].Severity] < severityRank[out[j].Severity] })
	for i := range out {
		out[i].ID = fmt.Sprintf("F-%03d", i+1)
	}
	if out == nil {
		out = []Finding{}
	}
	return out
}

func countOutcome(res pairsResult, o string) int {
	n := 0
	for _, p := range res.pairs {
		if p.outcome == o {
			n++
		}
	}
	return n
}
