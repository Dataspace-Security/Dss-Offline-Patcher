package compliance

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"offpatch/internal/store"
)

// facts are the period's numbers that controls and findings share.
type facts struct {
	asOf               time.Time
	inScope, stale     int
	staleHosts         []string
	pendingRestart     int
	outOfSupport       []int // endpoint indexes
	intelKnown         bool  // update intelligence says something about OS support
	compliantEPs       int
	overdueEPs         int
	emergencyOpen      map[int32]bool
	bundlesIn          []store.Bundle // received in the period
	receiptsIn         []store.TransferReceipt
	depsIn             []store.Deployment // created or activated in the period
	pkgsIn             []store.Package    // received in the period
	failedPairs        []int
	verifiedPairs      int
	verifiedNoEvidence int
	lostPairs          int
	activeExc          []store.Exception
	privileged         []store.User
	privilegedNoMFA    []string
	approvalProblems   []string // deployment-level PM-07 problems
	approvalsOK        int
	autoPauses         int
	manualPauses       int
	rollbacksDone      int
	reportRuns         int
}

func inPeriod(in *Input, ts string) bool {
	t := parseTS(ts)
	return !t.IsZero() && !t.Before(in.From) && t.Before(in.To)
}

func (pk *Pack) collectFacts(asOf time.Time, res pairsResult) *facts {
	in := pk.in
	f := &facts{asOf: asOf, emergencyOpen: map[int32]bool{}}
	for i, e := range in.Endpoints {
		if e.RetiredAt != "" || e.Status == "retired" {
			continue
		}
		f.inScope++
		if staleStatuses[e.Status] {
			f.stale++
			if len(f.staleHosts) < 20 {
				f.staleHosts = append(f.staleHosts, e.Hostname)
			}
		}
		if e.RebootPending || e.Status == "pending_reboot" {
			f.pendingRestart++
		}
		if e.Missing != nil && e.Missing.OSSupport != "" {
			f.intelKnown = true
			if e.Missing.OSSupport == "out_of_support" {
				f.outOfSupport = append(f.outOfSupport, i)
			}
		}
		bad, overdue := e.Status == "out_of_support" || staleStatuses[e.Status], false
		for _, pi := range res.byEP[int32(i)] {
			p := res.pairs[pi]
			switch p.outcome {
			case OutcomeOverdue, OutcomeFailed, OutcomeOffline, OutcomeException, OutcomeVerifiedLate:
				bad = true
			}
			if p.pastDeadline {
				bad, overdue = true, true
			}
		}
		if !bad {
			f.compliantEPs++
		}
		if overdue {
			f.overdueEPs++
		}
	}
	for i, p := range res.pairs {
		if p.pastDeadline && p.priority == "emergency" {
			f.emergencyOpen[p.pkg] = true
		}
		switch p.outcome {
		case OutcomeFailed:
			f.failedPairs = append(f.failedPairs, i)
			if p.t != nil && p.t.State == "lost_after_install" {
				f.lostPairs++
			}
		case OutcomeCompliant, OutcomeVerifiedLate:
			f.verifiedPairs++
			if p.t != nil && p.t.Evidence == "" {
				f.verifiedNoEvidence++
			}
		}
	}
	for _, b := range in.Bundles {
		if inPeriod(in, b.ReceivedAt) {
			f.bundlesIn = append(f.bundlesIn, b)
		}
	}
	for _, r := range in.Receipts {
		if inPeriod(in, r.ReceivedAt) {
			f.receiptsIn = append(f.receiptsIn, r)
		}
	}
	for _, p := range in.Packages {
		if inPeriod(in, p.CreatedAt) {
			f.pkgsIn = append(f.pkgsIn, p)
		}
	}
	for _, d := range in.Deployments {
		if inPeriod(in, d.CreatedAt) || inPeriod(in, d.ActivatedAt) {
			f.depsIn = append(f.depsIn, d)
		}
	}
	for _, x := range in.Exceptions {
		if x.Active {
			f.activeExc = append(f.activeExc, x)
		}
	}
	for _, u := range in.Users {
		if u.Disabled || store.RoleRank(u.Role) < store.RoleRank(store.RoleAdmin) {
			continue
		}
		f.privileged = append(f.privileged, u)
		if !u.MFA && !u.MFAEnrolled {
			f.privilegedNoMFA = append(f.privilegedNoMFA, u.Username)
		}
	}
	pkgByID := map[string]store.Package{}
	for _, p := range in.Packages {
		pkgByID[p.PackageID] = p
	}
	for _, d := range f.depsIn {
		if d.State == "pending_approval" || d.State == "rejected" || d.ActivatedAt == "" && d.ApprovalsRequired > 0 {
			continue // never reached production
		}
		if msg := approvalProblem(d, pkgByID[d.PackageID], in.Settings.SeparationOfDuties); msg != "" {
			f.approvalProblems = append(f.approvalProblems, d.DeploymentID+": "+msg)
		} else {
			f.approvalsOK++
		}
		if d.Operation == "rollback" && d.State == "completed" {
			f.rollbacksDone++
		}
	}
	for _, e := range in.DeploymentEvents {
		switch e.Action {
		case "deployment.auto_paused":
			f.autoPauses++
		case "deployment.paused":
			f.manualPauses++
		}
	}
	for _, e := range in.ReportEvents {
		if e.Action == "report.compliance_generated" || e.Action == "report.exported" {
			f.reportRuns++
		}
	}
	return f
}

// approvalProblem checks one production deployment for PM-07: enough
// distinct approvers, none the creator, all approvals before activation,
// the package approved before the deployment was created, and (when
// configured) package approvers not deploying.
func approvalProblem(d store.Deployment, p store.Package, sod bool) string {
	if d.ApprovalsRequired == 0 {
		return "created before deployment approvals existed: no approval record"
	}
	seen := map[string]bool{}
	act := parseTS(d.ActivatedAt)
	for _, a := range d.Approvals {
		if a.By == d.CreatedBy {
			return "approved by its creator"
		}
		seen[a.By] = true
		if !act.IsZero() && parseTS(a.At).After(act) {
			return "approval recorded after activation"
		}
	}
	if len(seen) < d.ApprovalsRequired {
		return fmt.Sprintf("%d of %d required approvals", len(seen), d.ApprovalsRequired)
	}
	if d.Operation != "rollback" {
		if len(p.Approvals) == 0 {
			return "package has no approval record"
		}
		if parseTS(p.Approvals[len(p.Approvals)-1].At).After(parseTS(d.CreatedAt)) {
			return "deployment created before the package was approved"
		}
	}
	if sod {
		for _, a := range p.Approvals {
			if a.By == d.CreatedBy {
				return "separation of duties: the package approver created the deployment"
			}
		}
	}
	return ""
}

func ctl(id string) Control {
	for _, d := range controlDefs {
		if d.id == id {
			return Control{ID: id, Objective: d.objective, AuditorEvidence: d.evidence, SuggestedTest: d.test, EvidenceIDs: []string{}}
		}
	}
	return Control{ID: id, EvidenceIDs: []string{}}
}

func auto(c Control, status, rationale string) Control {
	c.Status, c.Source, c.Rationale = status, "automatic", rationale
	return c
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

func (pk *Pack) controls(f *facts, res pairsResult) []Control {
	in := pk.in
	prof := in.Profile.Profile
	manual := func(id string) (store.ManualControl, bool) {
		m, ok := prof.ManualControls[id]
		return m, ok
	}
	var out []Control

	// PM-01 policy: the organisation's record; the product cannot judge coverage.
	c := ctl("PM-01")
	c.EvidenceIDs = []string{"E-001"}
	pol := prof.Policy
	if pol.ApprovedBy != "" || pol.Version != "" || pol.Reference != "" {
		c.Evidence = fmt.Sprintf("Policy record in the report profile: version %s, approved by %s on %s, review date %s, reference %s. Deadlines configured for %s.",
			orDash(pol.Version), orDash(pol.ApprovedBy), orDash(pol.ApprovedAt), orDash(pol.ReviewDate), orDash(pol.Reference), strings.Join(store.DeadlinePriorities, ", "))
	} else {
		c.Evidence = "No approved policy is recorded in the report profile. Deadlines in use are the DSS Patcher configured defaults."
	}
	c.TestPerformed = "Policy record and deadline table read from the report profile."
	c = auto(c, store.StatusNotAssessed, "Policy content, approval and coverage must be confirmed by the reviewer (manual control).")
	out = append(out, c)

	// PM-02 inventory and stale assets.
	c = ctl("PM-02")
	c.EvidenceIDs = []string{"E-002"}
	c.Evidence = fmt.Sprintf("%s in scope; %d with current inventory; %d stale, offline or not yet reporting (silence is not compliance). Thresholds: offline after %s, inventory stale after %s.",
		plural(f.inScope, "endpoint", "endpoints"), f.inScope-f.stale, f.stale, in.Settings.OfflineAfter, in.Settings.StaleAfter)
	c.TestPerformed = "Every in-scope endpoint's last check-in and inventory time compared with the thresholds at " + f.asOf.In(in.Loc).Format(time.RFC3339) + ". Reconciliation with an independent CMDB/network source is outside the product."
	switch {
	case f.inScope == 0:
		c = auto(c, store.StatusNotAssessed, "No enrolled endpoints.")
	case f.stale == 0:
		c = auto(c, store.StatusCompliant, "All in-scope endpoints report current inventory. Completeness against an independent source still needs the reviewer's reconciliation.")
	case f.stale*10 <= f.inScope:
		c = auto(c, store.StatusPartial, fmt.Sprintf("%d of %d endpoints (%.1f %%) have no current inventory.", f.stale, f.inScope, pctOf(f.stale, f.inScope)))
	default:
		c = auto(c, store.StatusNonCompliant, fmt.Sprintf("%d of %d endpoints (%.1f %%) have no current inventory: patch exposure cannot be determined for them.", f.stale, f.inScope, pctOf(f.stale, f.inScope)))
	}
	if in.IntelAge != nil && in.IntelAge.Stale && c.Status == store.StatusCompliant {
		c = auto(c, store.StatusPartial, "Endpoint inventory is current, but the update intelligence is older than 8 days: missing updates may be under-reported.")
	}
	out = append(out, c)

	// PM-03 acquisition records.
	c = ctl("PM-03")
	c.EvidenceIDs = []string{"E-003", "E-004"}
	noSource, notVerified, invalid := 0, 0, 0
	for _, p := range f.pkgsIn {
		if p.SourceURL == "" || p.Vendor == "" {
			noSource++
		}
		switch p.VendorSignature.Status {
		case "valid":
		case "invalid":
			invalid++
		default:
			notVerified++
		}
	}
	c.Evidence = fmt.Sprintf("%s received in the period from %s; %s; %d acquisition status reports. Vendor signature: %d not checked, %d invalid; %d without vendor or source URL.",
		plural(len(f.pkgsIn), "package", "packages"), plural(len(f.bundlesIn), "bundle", "bundles"), "every bundle signed by a trusted acquisition key (intake refuses others)", len(in.Acquisitions), notVerified, invalid, noSource)
	c.TestPerformed = "Each package received in the period traced to its signed bundle (source, key, sequence) and its vendor, source URL, SHA-256 and vendor signature status."
	switch {
	case len(f.pkgsIn) == 0:
		c = auto(c, store.StatusNotAssessed, "No packages were acquired in the period.")
	case invalid > 0:
		c = auto(c, store.StatusNonCompliant, plural(invalid, "package carries", "packages carry")+" an invalid vendor signature.")
	case noSource > 0 || notVerified > 0:
		c = auto(c, store.StatusPartial, "Acquisition is traceable to signed bundles, but some packages lack a vendor source URL or a checked vendor signature.")
	default:
		c = auto(c, store.StatusCompliant, "Every package acquired in the period has a vendor, source URL, SHA-256, a valid vendor signature and a signed bundle.")
	}
	out = append(out, c)

	// PM-04 transfer boundary.
	c = ctl("PM-04")
	c.EvidenceIDs = []string{"E-004"}
	receipted := map[string]bool{}
	unsigned := 0
	for _, r := range f.receiptsIn {
		if r.SignatureOK {
			receipted[r.FileSHA256] = true
		} else {
			unsigned++
		}
	}
	noReceipt := 0
	for _, b := range f.bundlesIn {
		if !receipted[b.FileSHA256] {
			noReceipt++
		}
	}
	egress := strings.TrimSpace(prof.OfflineModel.EgressEvidence)
	if m, ok := manual("PM-04"); ok && m.EvidenceRef != "" {
		egress = strings.TrimSpace(egress + " " + m.EvidenceRef)
	}
	c.Evidence = fmt.Sprintf("%s and %s in the period; %d bundles without a valid sender receipt; %d unsigned or invalid receipts. Egress evidence reference: %s.",
		plural(len(f.bundlesIn), "bundle received", "bundles received"), plural(len(f.receiptsIn), "transfer receipt", "transfer receipts"), noReceipt, unsigned, orDash(egress))
	c.TestPerformed = "Bundles that arrived reconciled with signed sender receipts (file SHA-256). Endpoint egress restrictions are network controls outside the product: the profile's evidence reference is used."
	switch {
	case len(f.bundlesIn) == 0 && len(f.receiptsIn) == 0:
		c = auto(c, store.StatusNotAssessed, "No transfers in the period.")
	case unsigned > 0:
		c = auto(c, store.StatusNonCompliant, plural(unsigned, "transfer receipt is", "transfer receipts are")+" unsigned or failed signature verification.")
	case noReceipt > 0:
		c = auto(c, store.StatusPartial, plural(noReceipt, "bundle has", "bundles have")+" no matching signed transfer receipt.")
	case egress == "":
		c = auto(c, store.StatusPartial, "Every bundle has a signed transfer receipt, but no endpoint egress-enforcement evidence is referenced in the profile.")
	default:
		c = auto(c, store.StatusCompliant, "Every bundle in the period has a matching signed transfer receipt; egress evidence is referenced.")
	}
	out = append(out, c)

	// PM-05 quarantine and verification.
	c = ctl("PM-05")
	c.EvidenceIDs = []string{"E-005"}
	validated, rejected, sigHashOK, scanned := 0, 0, 0, 0
	for _, b := range f.bundlesIn {
		if b.State == "validated" {
			validated++
			sig, hash := false, false
			for _, ch := range b.Checks {
				switch ch.Name {
				case "signature":
					sig = ch.OK
				case "payload_hashes":
					hash = ch.OK
				case "content_scan":
					if ch.OK && !strings.Contains(ch.Detail, "no scanner configured") {
						scanned++
					}
				}
			}
			if sig && hash {
				sigHashOK++
			}
		} else {
			rejected++
		}
	}
	c.Evidence = fmt.Sprintf("%d bundles validated, %d rejected by intake checks (tamper, replay, untrusted key, hash mismatch, scan). %d validated bundles with signature and payload-hash checks passed; %d content-scanned. Every package enters quarantine on intake and is deployable only after approval.",
		validated, rejected, sigHashOK, scanned)
	c.TestPerformed = "Intake check results of every bundle in the period (signature, payload hashes, replay sequence, content scan); quarantine-to-approval state of every package."
	switch {
	case len(f.bundlesIn) == 0:
		c = auto(c, store.StatusNotAssessed, "No bundles were received in the period.")
	case sigHashOK < validated:
		c = auto(c, store.StatusNonCompliant, "A validated bundle lacks a passing signature or hash check.")
	case !in.Settings.ScannerConfigured || scanned < validated:
		c = auto(c, store.StatusPartial, "Signatures and hashes are verified for every bundle, but no malware scan result is recorded for all of them (scan_command not configured or skipped).")
	default:
		c = auto(c, store.StatusCompliant, "Every bundle was signature-, hash- and scan-verified before its packages could be approved.")
	}
	out = append(out, c)

	// PM-06 prioritisation and deadlines.
	c = ctl("PM-06")
	c.EvidenceIDs = []string{"E-001", "E-003", "E-007"}
	defaultSrc := 0
	for _, d := range prof.Deadlines {
		if strings.HasPrefix(d.Source, "DSS Patcher") || d.Source == "" {
			defaultSrc++
		}
	}
	overdueCrit, overdueOther := 0, 0
	for _, p := range res.pairs {
		if p.pastDeadline {
			if p.priority == "emergency" || p.priority == "critical" {
				overdueCrit++
			} else {
				overdueOther++
			}
		}
	}
	c.Evidence = fmt.Sprintf("%s evaluated against the configured deadlines (%s); %d emergency/critical and %d other pairs open past their deadline; %d pairs have no deadline (clock start unknown). %d of %d deadline rows still cite the product default as their source.",
		plural(len(res.pairs), "endpoint/update pair", "endpoint/update pairs"), deadlineSummary(prof.Deadlines), overdueCrit, overdueOther, res.noClock, defaultSrc, len(prof.Deadlines))
	c.TestPerformed = "Priority derived from each package's severity (emergency deployments as emergency); deadline = clock start + configured maximum; outcome evaluated per pair at " + f.asOf.In(in.Loc).Format(time.RFC3339) + ". Exploitation and asset-criticality rationale are not recorded by the product."
	switch {
	case len(res.pairs) == 0:
		c = auto(c, store.StatusNotAssessed, "No applicable endpoint/update pairs.")
	case overdueCrit > 0:
		c = auto(c, store.StatusNonCompliant, fmt.Sprintf("%d emergency/critical endpoint/update pairs are past their deadline without an approved exception.", overdueCrit))
	case overdueOther > 0 || defaultSrc > 0:
		c = auto(c, store.StatusPartial, "Deadlines are applied, but some pairs are overdue or the deadlines are not yet confirmed against an approved policy.")
	default:
		c = auto(c, store.StatusCompliant, "Every pair is within or met its policy deadline; deadlines cite an approved source.")
	}
	out = append(out, c)

	// PM-07 approvals (two-person rule, SoD).
	c = ctl("PM-07")
	c.EvidenceIDs = []string{"E-006"}
	prod := f.approvalsOK + len(f.approvalProblems)
	c.Evidence = fmt.Sprintf("%s reached production in the period; %d with complete approval evidence (%d distinct approvers other than the creator, all before activation, package approved first%s). Problems: %s.",
		plural(prod, "deployment", "deployments"), f.approvalsOK, in.Policy.RequiredDeploymentApprovals(), map[bool]string{true: ", package approver not the deployer", false: ""}[in.Settings.SeparationOfDuties], orNone(f.approvalProblems, 5))
	c.TestPerformed = "Every deployment and rollback created or activated in the period: approval records, approvers, timestamps against activation, and the package approval."
	switch {
	case prod == 0:
		c = auto(c, store.StatusNotAssessed, "No deployments reached production in the period.")
	case len(f.approvalProblems) == 0:
		c = auto(c, store.StatusCompliant, "Every production deployment was approved by different people before it started.")
	case f.approvalsOK == 0:
		c = auto(c, store.StatusNonCompliant, "No production deployment in the period has complete approval evidence.")
	default:
		c = auto(c, store.StatusPartial, plural(len(f.approvalProblems), "deployment lacks", "deployments lack")+" complete approval evidence.")
	}
	out = append(out, c)

	// PM-08 testing before broad rollout: product data is supporting only.
	c = ctl("PM-08")
	c.EvidenceIDs = []string{"E-006", "E-007"}
	staged, health := 0, 0
	for _, d := range f.depsIn {
		if len(d.Rings) > 1 {
			staged++
		}
		if len(d.HealthChecks) > 0 {
			health++
		}
	}
	c.Evidence = fmt.Sprintf("%d of %d deployments in the period used more than one ring (pilot first); %d configured post-install health checks.", staged, len(f.depsIn), health)
	c.TestPerformed = "Ring configuration and health checks of the period's deployments. Test results and go/no-go decisions are recorded outside the product."
	c = auto(c, store.StatusNotAssessed, "Testing evidence and go/no-go approval must be confirmed by the reviewer (manual control).")
	out = append(out, c)

	// PM-09 staging and pause.
	c = ctl("PM-09")
	c.EvidenceIDs = []string{"E-006"}
	single, noThreshold := 0, 0
	for _, d := range f.depsIn {
		if d.Operation != "install" || d.State == "pending_approval" || d.State == "rejected" {
			continue
		}
		if len(d.Rings) < 2 && !d.Emergency {
			single++
		}
		if d.MaxFailurePct <= 0 || d.MaxFailurePct >= 100 {
			noThreshold++
		}
	}
	c.Evidence = fmt.Sprintf("%d deployments in the period; %d single-ring (non-emergency); %d without an effective failure threshold; %d automatic pauses and %d manual pauses recorded.",
		len(f.depsIn), single, noThreshold, f.autoPauses, f.manualPauses)
	c.TestPerformed = "Ring/wave configuration, failure thresholds and pause events (deployment.auto_paused, deployment.paused) of the period's deployments."
	switch {
	case len(f.depsIn) == 0:
		c = auto(c, store.StatusNotAssessed, "No deployments in the period.")
	case single == 0 && noThreshold == 0:
		c = auto(c, store.StatusCompliant, "Every deployment was staged with a failure threshold that pauses it automatically.")
	default:
		c = auto(c, store.StatusPartial, "Some deployments ran in a single ring or without an effective failure threshold.")
	}
	out = append(out, c)

	// PM-10 verification by inventory.
	c = ctl("PM-10")
	c.EvidenceIDs = []string{"E-007"}
	c.Evidence = fmt.Sprintf("%d pairs verified by fresh inventory; %d verified without a recorded evidence line (verified before evidence was kept); %d endpoints went silent after installing (lost_after_install); %d endpoints pending restart.",
		f.verifiedPairs, f.verifiedNoEvidence, f.lostPairs, f.pendingRestart)
	c.TestPerformed = "Verified targets checked for the inventory line or OS revision that proved them (agents' own success reports are not accepted as verification)."
	switch {
	case f.verifiedPairs == 0 && len(res.pairs) == 0:
		c = auto(c, store.StatusNotAssessed, "No deployments to verify.")
	case f.verifiedPairs == 0:
		c = auto(c, store.StatusNotAssessed, "No pair is verified yet.")
	case f.verifiedNoEvidence == 0 && f.lostPairs == 0:
		c = auto(c, store.StatusCompliant, "Every verified install is backed by inventory evidence.")
	default:
		c = auto(c, store.StatusPartial, "Some verified installs lack an evidence line, or endpoints went silent after installing.")
	}
	out = append(out, c)

	// PM-11 failures and exceptions.
	c = ctl("PM-11")
	c.EvidenceIDs = []string{"E-008"}
	incomplete, longExc, expiredOpen := 0, 0, 0
	for _, x := range f.activeExc {
		if x.Owner == "" || x.Reason == "" || x.CompensatingControls == "" || x.ExpiresAt == "" {
			incomplete++
		}
		if parseTS(x.ExpiresAt).Sub(parseTS(x.CreatedAt)) > 366*24*time.Hour {
			longExc++
		}
	}
	failedPast := 0
	for _, i := range f.failedPairs {
		if res.pairs[i].pastDeadline {
			failedPast++
		}
	}
	for _, x := range in.Exceptions {
		if !x.Revoked && !x.Active {
			expiredOpen++
		}
	}
	c.Evidence = fmt.Sprintf("%d active exceptions (owner, reason, compensating controls and expiry are mandatory fields); %d longer than one year; %d expired. %d failed pairs, %d of them past their deadline without an exception.",
		len(f.activeExc), longExc, expiredOpen, len(f.failedPairs), failedPast)
	c.TestPerformed = "Every exception record (owner, approver, rationale, compensating controls, expiry) and every failed endpoint/update pair."
	switch {
	case len(f.activeExc) == 0 && len(f.failedPairs) == 0:
		c = auto(c, store.StatusNotAssessed, "No failures or exceptions to sample in the period.")
	case incomplete > 0:
		c = auto(c, store.StatusNonCompliant, "Exceptions without owner, rationale, compensating controls or expiry.")
	case failedPast > 0 || longExc > 0:
		c = auto(c, store.StatusPartial, "Failures past their deadline lack an owner/exception, or exceptions run longer than a year.")
	default:
		c = auto(c, store.StatusCompliant, "Every exception is owned, justified, compensated and time-bound; failures are within deadline.")
	}
	out = append(out, c)

	// PM-12 recovery.
	c = ctl("PM-12")
	c.EvidenceIDs = []string{"E-008"}
	rb := 0
	for _, p := range in.Packages {
		if (p.State == "approved") && store.RollbackUnsupported(p) == "" {
			rb++
		}
	}
	approved := 0
	for _, p := range in.Packages {
		if p.State == "approved" {
			approved++
		}
	}
	m12, _ := manual("PM-12")
	c.Evidence = fmt.Sprintf("Rollback (uninstall) supported for %d of %d approved packages; %d rollback deployments completed in the period; %d backups recorded. Recovery evidence reference: %s.",
		rb, approved, f.rollbacksDone, len(in.BackupEvents), orDash(m12.EvidenceRef))
	c.TestPerformed = "Rollback support per package type, completed rollback deployments, recorded backups; restore/reimage procedures are documents outside the product."
	switch {
	case approved == 0:
		c = auto(c, store.StatusNotAssessed, "No approved packages.")
	case f.rollbacksDone > 0 || m12.EvidenceRef != "":
		c = auto(c, store.StatusCompliant, "Recovery is supported and was exercised (rollback in the product, or the referenced recovery evidence).")
	default:
		c = auto(c, store.StatusPartial, "Rollback is supported, but no recovery exercise is evidenced in the period.")
	}
	out = append(out, c)

	// PM-13 privileged access.
	c = ctl("PM-13")
	c.EvidenceIDs = []string{"E-009"}
	m13, _ := manual("PM-13")
	c.Evidence = fmt.Sprintf("%d enabled admin and super admin accounts; %d without MFA (%s); require_mfa %v; %d privileged actions audited in the period%s. Access review / key custody reference: %s.",
		len(f.privileged), len(f.privilegedNoMFA), orNone(f.privilegedNoMFA, 5), in.Settings.RequireMFA, len(in.PrivilegedEvents),
		map[bool]string{true: " (list truncated)", false: ""}[in.PrivilegedTruncated], orDash(m13.EvidenceRef))
	c.TestPerformed = "Role assignments and MFA enrolment of every privileged account; privileged audit events (user, approval, deployment, exception, key, audit actions) in the period."
	switch {
	case len(f.privileged) == 0:
		c = auto(c, store.StatusNotAssessed, "No privileged accounts recorded.")
	case len(f.privilegedNoMFA) == 0 && m13.EvidenceRef != "":
		c = auto(c, store.StatusCompliant, "Every privileged account uses MFA, privileged actions are audited, and the access review is referenced.")
	default:
		c = auto(c, store.StatusPartial, "Privileged actions are restricted by role and audited, but some privileged accounts lack MFA or no periodic access review is referenced.")
	}
	out = append(out, c)

	// PM-14 audit trail.
	c = ctl("PM-14")
	c.EvidenceIDs = []string{"E-009"}
	lag := in.AuditHeadSeq - in.Settings.AuditExportedSeq
	c.Evidence = fmt.Sprintf("Hash-chained, append-only audit trail: %d events verified, chain %s. Signed off-box export %s (exported to event %d of %d); retention %s.",
		in.Chain.Count, map[bool]string{true: "intact", false: "BROKEN at event " + fmt.Sprint(in.Chain.FirstBadSeq)}[in.Chain.OK],
		map[bool]string{true: "configured", false: "NOT configured"}[in.Settings.AuditExportDir], in.Settings.AuditExportedSeq, in.AuditHeadSeq, retention(in.Settings.AuditRetention))
	c.TestPerformed = "Full audit chain verification at generation; export checkpoint position; retention setting. Retention against the applicable requirement is the reviewer's judgement."
	switch {
	case !in.Chain.OK:
		c = auto(c, store.StatusNonCompliant, "The audit hash chain failed verification: records may have been altered.")
	case !in.Settings.AuditExportDir:
		c = auto(c, store.StatusPartial, "The audit trail is tamper-evident, but it is not exported to write-once storage with signed checkpoints.")
	case lag > 0 && in.Settings.AuditCheckpointEvery > 0 && lag > 100000:
		c = auto(c, store.StatusPartial, "Off-box audit export is far behind the database.")
	default:
		c = auto(c, store.StatusCompliant, "The audit trail is hash-chained, verified and exported with signed checkpoints.")
	}
	out = append(out, c)

	// PM-15 reporting to governance.
	c = ctl("PM-15")
	c.EvidenceIDs = []string{"E-010"}
	m15, _ := manual("PM-15")
	c.Evidence = fmt.Sprintf("%d compliance report generations or exports in the period before this one; governance pack reference: %s.", f.reportRuns, orDash(m15.EvidenceRef))
	c.TestPerformed = "Report generation history (audit events report.*). Committee packs, minutes and escalation are outside the product."
	switch {
	case f.reportRuns == 0:
		c = auto(c, store.StatusNotAssessed, "No earlier compliance report in the period.")
	case m15.EvidenceRef != "":
		c = auto(c, store.StatusCompliant, "Compliance is measured in the product and the governance reporting is referenced.")
	default:
		c = auto(c, store.StatusPartial, "Compliance reports are produced, but reporting to a governance forum is not referenced.")
	}
	out = append(out, c)

	// PM-16 the patch service itself.
	c = ctl("PM-16")
	c.EvidenceIDs = []string{"E-009"}
	m16, _ := manual("PM-16")
	c.Evidence = fmt.Sprintf("DSS Patcher %s; TLS %v, agent mTLS %v, insecure lab mode %v; %d backups recorded by pmserver backup; audit chain %s. Hardening / restore-test reference: %s.",
		in.ProductVersion, in.Settings.TLS, in.Settings.MTLSAgents, in.Settings.InsecureHTTP, len(in.BackupEvents), map[bool]string{true: "intact", false: "broken"}[in.Chain.OK], orDash(m16.EvidenceRef))
	c.TestPerformed = "Server security settings and version; backup records. Vulnerability results, monitoring and restore tests of the server are outside the product."
	switch {
	case in.Settings.InsecureHTTP:
		c = auto(c, store.StatusNonCompliant, "The management server runs in insecure lab mode (no TLS, bearer device secrets).")
	case len(in.BackupEvents) > 0 && m16.EvidenceRef != "":
		c = auto(c, store.StatusCompliant, "TLS and mTLS are enforced, backups are recorded and hardening/restore evidence is referenced.")
	default:
		c = auto(c, store.StatusPartial, "TLS and mTLS are enforced, but backup records or hardening/restore-test evidence are missing.")
	}
	out = append(out, c)

	// PM-17 end of life.
	c = ctl("PM-17")
	c.EvidenceIDs = []string{"E-002", "E-008"}
	excAll := map[string]bool{}
	for _, x := range f.activeExc {
		if x.PackageID == "" {
			excAll[x.EndpointID] = true
		}
	}
	unmanaged := 0
	for _, i := range f.outOfSupport {
		if !excAll[in.Endpoints[i].EndpointID] {
			unmanaged++
		}
	}
	c.Evidence = fmt.Sprintf("%d endpoints run an operating system build the vendor no longer updates; %d of them without an active exception (risk acceptance).", len(f.outOfSupport), unmanaged)
	c.TestPerformed = "Operating-system support status from the update intelligence for every in-scope endpoint; exceptions covering them. Application end-of-life is not tracked by the product."
	switch {
	case !f.intelKnown:
		c = auto(c, store.StatusNotAssessed, "No update intelligence is available to determine support status.")
	case len(f.outOfSupport) == 0:
		c = auto(c, store.StatusCompliant, "No in-scope endpoint runs an unsupported operating system build.")
	case unmanaged == 0:
		c = auto(c, store.StatusCompliant, "Every unsupported endpoint is covered by an approved, time-bound exception.")
	default:
		c = auto(c, store.StatusPartial, "Unsupported endpoints are identified, but not all are risk-managed by an exception.")
	}
	out = append(out, c)

	// Manual conclusions: used where the product could not conclude.
	for i := range out {
		m, ok := manual(out[i].ID)
		if !ok {
			continue
		}
		mc := m
		out[i].Manual = &mc
		if out[i].Status == store.StatusNotAssessed && m.Status != "" {
			out[i].Status, out[i].Source = m.Status, "manual"
			out[i].Rationale = strings.TrimSpace("Reviewer conclusion: " + orDash(m.Note) + " Evidence: " + orDash(m.EvidenceRef) + ". (Product: " + out[i].Rationale + ")")
		}
	}
	for i := range out {
		if out[i].Status == store.StatusNotAssessed && out[i].Source == "automatic" && (out[i].ID == "PM-01" || out[i].ID == "PM-08") {
			out[i].Source = "none"
		}
	}
	return out
}

func deadlineSummary(ds []store.DeadlineRule) string {
	var parts []string
	for _, d := range ds {
		parts = append(parts, fmt.Sprintf("%s %dd from %s", d.Priority, d.MaxDays, d.ClockStart))
	}
	return strings.Join(parts, ", ")
}

func retention(d time.Duration) string {
	if d <= 0 {
		return "keep forever"
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "none recorded"
	}
	return s
}

func orNone(xs []string, max int) string {
	if len(xs) == 0 {
		return "none"
	}
	ys := append([]string{}, xs...)
	sort.Strings(ys)
	if len(ys) > max {
		return strings.Join(ys[:max], "; ") + fmt.Sprintf("; and %d more", len(ys)-max)
	}
	return strings.Join(ys, "; ")
}
