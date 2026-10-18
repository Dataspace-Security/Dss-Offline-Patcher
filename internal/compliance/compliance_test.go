package compliance

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

var (
	now   = time.Date(2026, 10, 18, 10, 0, 0, 0, time.UTC)
	from  = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	to    = time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	ts    = func(t time.Time) string { return t.Format(time.RFC3339Nano) }
	fresh = ts(now.Add(-5 * time.Minute))
)

func ep(id, host, status string) store.Endpoint {
	return store.Endpoint{EndpointID: id, Hostname: host, OS: "windows", Build: 19045, Status: status, LastSeen: fresh, InventoryAt: fresh, EnrolledAt: ts(from), Groups: []string{"g"}, Site: "hq"}
}

func pkg(id, sev, release string) store.Package {
	return store.Package{PackageID: id, Title: "Update " + id, Vendor: "Microsoft", Kind: "msu", KB: id, Severity: sev, ReleaseDate: release, State: "approved",
		CreatedAt: ts(from.Add(24 * time.Hour)), SourceURL: "https://catalog.update.microsoft.com/", SHA256: strings.Repeat("a", 64),
		VendorSignature: manifest.VendorSignature{Status: "valid"},
		Approvals:       []store.Approval{{By: "user:alice@bank.test", At: ts(from.Add(48 * time.Hour)), Reason: "CAB"}}}
}

func target(dep, pkgID, epID, state string, at time.Time) store.PackTarget {
	return store.PackTarget{DeploymentID: dep, PackageID: pkgID, EndpointID: epID, State: state, UpdatedAt: ts(at), DeploymentState: "active", Operation: "install",
		Evidence: map[bool]string{true: "kb " + pkgID}[state == "verified"]}
}

// fixture: one fleet that exercises every executive-summary measure.
func fixture() *Input {
	p := store.Policy{}
	rec := store.ReportProfileRecord{IsDefault: true, Profile: p.DefaultReportProfile()}
	crit := pkg("KB1", "critical", "2026-10-02") // deadline 2026-10-09 (7 days)
	emerg := pkg("KB2", "low", "2026-10-10")     // emergency deployment → 7 days → 2026-10-17
	low := pkg("KB3", "low", "2026-10-15")       // 90 days: not due
	rej := pkg("KB4", "critical", "2026-10-01")
	rej.State = "rejected"
	in := &Input{Now: now, Loc: time.UTC, From: from, To: to, GeneratedBy: User{User: "vera@bank.test", Role: "viewer"}, ProductVersion: "1.2.3",
		Policy: p, Profile: rec,
		Endpoints: []store.Endpoint{
			ep("e-ok", "pc-ok", "compliant"),
			ep("e-stale", "pc-stale", "stale"),
			ep("e-fail", "pc-fail", "failed"),
			ep("e-exc", "pc-exc", "exception"),
			ep("e-boot", "pc-boot", "pending_reboot"),
			ep("e-late", "pc-late", "compliant"),
			{EndpointID: "e-ret", Hostname: "pc-retired", Status: "retired", RetiredAt: ts(from)},
		},
		Packages: []store.Package{crit, emerg, low, rej},
		Targets: []store.PackTarget{
			target("d1", "KB1", "e-ok", "verified", time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)),
			target("d1", "KB1", "e-stale", "pending", now),
			target("d1", "KB1", "e-fail", "failed", now),
			target("d1", "KB1", "e-exc", "pending", now),
			target("d1", "KB1", "e-boot", "pending_reboot", now),
			target("d1", "KB1", "e-late", "verified", time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)),
			target("d1", "KB1", "e-ret", "pending", now),
			{DeploymentID: "d2", PackageID: "KB2", EndpointID: "e-fail", State: "pending", UpdatedAt: ts(now), DeploymentState: "active", Operation: "install", Emergency: true},
			target("d3", "KB3", "e-ok", "pending", now),
			target("d4", "KB4", "e-ok", "pending", now),
		},
		Needs:      map[string][]string{"KB3": {"e-late"}},
		Exceptions: []store.Exception{{NewException: store.NewException{EndpointID: "e-exc", PackageID: "KB1", Owner: "Ops lead", Reason: "app freeze", CompensatingControls: "isolated VLAN", ExpiresAt: ts(now.Add(30 * 24 * time.Hour))}, ExceptionID: "x-1", CreatedBy: "user:adam@bank.test", CreatedAt: ts(from.Add(72 * time.Hour)), Active: true}},
		Deployments: []store.Deployment{
			{NewDeployment: store.NewDeployment{PackageID: "KB1", Name: "Oct CU", Rings: []store.Ring{{Name: "pilot"}, {Name: "broad"}}, MaxFailurePct: 20}, DeploymentID: "d1", State: "active",
				CreatedBy: "user:otto@bank.test", CreatedAt: ts(from.Add(50 * time.Hour)), ApprovalsRequired: 2, ActivatedAt: ts(from.Add(60 * time.Hour)),
				Approvals: []store.Approval{{By: "user:alice@bank.test", At: ts(from.Add(55 * time.Hour))}, {By: "user:bob@bank.test", At: ts(from.Add(60 * time.Hour))}}},
		},
		Users:    []store.User{{Username: "adam@bank.test", Role: "admin", Auth: "password", MFAEnrolled: true}},
		Chain:    store.ChainResult{OK: true, Count: 100},
		Settings: Settings{OfflineAfter: 30 * time.Minute, StaleAfter: 24 * time.Hour, TLS: true, MTLSAgents: true, AuditExportDir: true},
	}
	return in
}

func build(t *testing.T, in *Input) *Pack {
	t.Helper()
	pk, err := Build(in, []byte("salt"))
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

func control(pk *Pack, id string) Control {
	for _, c := range pk.Controls {
		if c.ID == id {
			return c
		}
	}
	return Control{}
}

func outcomes(pk *Pack) map[string]string {
	out := map[string]string{}
	for _, p := range pk.pairs {
		e := pk.exported(p)
		out[e.Hostname+"/"+e.PackageID] = e.Outcome
	}
	return out
}

func TestExecutiveSummaryMeasures(t *testing.T) {
	pk := build(t, fixture())
	es := pk.ExecutiveSummary
	if es.InScopeEndpoints != 6 {
		t.Fatalf("in scope (retired excluded): %d", es.InScopeEndpoints)
	}
	if es.StaleInventory.Count != 1 || es.CurrentInventory.Count != 5 || es.CurrentInventory.Pct != 83.3 {
		t.Fatalf("inventory: %+v %+v", es.StaleInventory, es.CurrentInventory)
	}
	// pc-ok: verified on time, KB3 pending within deadline → compliant.
	// pc-boot: KB1 installed, pending reboot, past deadline → overdue.
	// pc-stale: stale → never compliant. pc-exc: exception → not counted as patched.
	// pc-late: verified after the deadline. pc-fail: failed past deadline.
	if es.CompliantWithPolicy.Count != 1 {
		t.Fatalf("compliant: %+v (outcomes %v)", es.CompliantWithPolicy, outcomes(pk))
	}
	if es.Overdue.Count != 3 { // pc-stale (offline, past), pc-fail, pc-boot
		t.Fatalf("overdue: %+v (outcomes %v)", es.Overdue, outcomes(pk))
	}
	if es.PendingRestart != 1 || es.ActiveExceptions != 1 || es.EmergencyOpenPastTarget != 1 {
		t.Fatalf("restart %d, exceptions %d, emergency %d", es.PendingRestart, es.ActiveExceptions, es.EmergencyOpenPastTarget)
	}
	want := map[string]string{"pc-ok/KB1": OutcomeCompliant, "pc-ok/KB3": OutcomePending, "pc-stale/KB1": OutcomeOffline, "pc-fail/KB1": OutcomeFailed,
		"pc-fail/KB2": OutcomeOverdue, "pc-exc/KB1": OutcomeException, "pc-boot/KB1": OutcomeOverdue, "pc-late/KB1": OutcomeVerifiedLate, "pc-late/KB3": OutcomePending}
	got := outcomes(pk)
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %s, want %s", k, got[k], v)
		}
	}
	if len(got) != len(want) {
		t.Errorf("pairs %v (rejected package and retired endpoint must be excluded)", got)
	}
	if es.FindingsBySeverity["critical"] == 0 || es.EvidenceCompletenessPct <= 0 || es.EvidenceCompletenessPct > 100 {
		t.Fatalf("findings %v completeness %v", es.FindingsBySeverity, es.EvidenceCompletenessPct)
	}
	// The emergency deployment puts KB2 under the emergency deadline.
	for _, p := range pk.Timeliness.Pairs {
		if p.PackageID == "KB2" && (p.Priority != "emergency" || p.Deadline != "2026-10-17T00:00:00Z" || !p.PastDeadline) {
			t.Fatalf("emergency pair: %+v", p)
		}
		if p.PackageID == "KB1" && p.Hostname == "pc-exc" && p.ExceptionID != "x-1" {
			t.Fatalf("exception pair: %+v", p)
		}
	}
	var crit PriorityStats
	for _, s := range pk.Timeliness.ByPriority {
		if s.Priority == "critical" {
			crit = s
		}
	}
	// KB1: 6 pairs: 1 on time, 1 late, 1 failed, 1 offline, 1 overdue, 1 exception → 1/5 on time.
	if crit.Pairs != 6 || crit.Compliant != 1 || crit.Exception != 1 || crit.PctOnTime != 20 {
		t.Fatalf("critical stats: %+v", crit)
	}
	if pk.OverallAssessment.Suggested != store.StatusNonCompliant || pk.OverallAssessment.Source != "computed" {
		t.Fatalf("overall: %+v", pk.OverallAssessment)
	}
	if !strings.HasPrefix(pk.Meta.ReportID, "CR-") || pk.Meta.Period.From != "2026-10-01" || pk.Meta.Period.To != "2026-10-18" {
		t.Fatalf("meta: %+v", pk.Meta)
	}
}

// Missing telemetry is never compliant, whatever the deployment says.
func TestStaleEndpointNeverCompliant(t *testing.T) {
	in := fixture()
	in.Endpoints = []store.Endpoint{ep("e-ok", "pc-ok", "offline")}
	in.Targets = []store.PackTarget{target("d1", "KB1", "e-ok", "verified", time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC))}
	in.Exceptions = nil
	pk := build(t, in)
	es := pk.ExecutiveSummary
	if es.CompliantWithPolicy.Count != 0 || es.StaleInventory.Count != 1 {
		t.Fatalf("offline endpoint counted compliant: %+v", es)
	}
	if c := control(pk, "PM-02"); c.Status != store.StatusNonCompliant {
		t.Fatalf("PM-02 with every endpoint stale: %s", c.Status)
	}
}

// Exceptions are reported separately and never counted as patched.
func TestExceptionNotCountedAsPatched(t *testing.T) {
	in := fixture()
	in.Endpoints = []store.Endpoint{ep("e-exc", "pc-exc", "exception")}
	in.Targets = []store.PackTarget{target("d1", "KB1", "e-exc", "exception", now)}
	pk := build(t, in)
	if pk.ExecutiveSummary.CompliantWithPolicy.Count != 0 || pk.ExecutiveSummary.ActiveExceptions != 1 || len(pk.Exceptions) != 1 {
		t.Fatalf("exception: %+v %+v", pk.ExecutiveSummary, pk.Exceptions)
	}
	for _, s := range pk.Timeliness.ByPriority {
		if s.Priority == "critical" && (s.Compliant != 0 || s.Exception != 1) {
			t.Fatalf("exception counted as patched: %+v", s)
		}
	}
	if pk.Exceptions[0].Status != "Active" || pk.Exceptions[0].Owner != "Ops lead" || pk.Exceptions[0].Approver != "user:adam@bank.test" {
		t.Fatalf("register row: %+v", pk.Exceptions[0])
	}
}

// PM-07: two different approvers, both before activation, not the creator.
func TestTwoPersonApprovalEvidence(t *testing.T) {
	pk := build(t, fixture())
	if c := control(pk, "PM-07"); c.Status != store.StatusCompliant || c.Source != "automatic" {
		t.Fatalf("PM-07 with two approvals before activation: %+v", c)
	}
	for name, mutate := range map[string]func(*store.Deployment){
		"creator approved":     func(d *store.Deployment) { d.Approvals[0].By = d.CreatedBy },
		"one approval":         func(d *store.Deployment) { d.Approvals = d.Approvals[:1] },
		"after activation":     func(d *store.Deployment) { d.Approvals[1].At = ts(parseTS(d.ActivatedAt).Add(time.Hour)) },
		"no approvals (older)": func(d *store.Deployment) { d.ApprovalsRequired, d.Approvals = 0, nil },
	} {
		in := fixture()
		d := in.Deployments[0]
		d.Approvals = append([]store.Approval{}, d.Approvals...)
		mutate(&d)
		in.Deployments = []store.Deployment{d}
		pk := build(t, in)
		c := control(pk, "PM-07")
		if c.Status != store.StatusNonCompliant {
			t.Errorf("%s: %s %s", name, c.Status, c.Rationale)
		}
		found := false
		for _, f := range pk.Findings {
			found = found || f.Control == "PM-07"
		}
		if !found {
			t.Errorf("%s: no PM-07 finding", name)
		}
	}
	// One good and one bad deployment: partially compliant.
	in := fixture()
	bad := in.Deployments[0]
	bad.DeploymentID, bad.ApprovalsRequired, bad.Approvals = "d9", 0, nil
	in.Deployments = append(in.Deployments, bad)
	if c := control(build(t, in), "PM-07"); c.Status != store.StatusPartial {
		t.Fatalf("mixed: %s", c.Status)
	}
}

func TestControlsWithoutDataNotAssessed(t *testing.T) {
	in := fixture()
	in.Endpoints, in.Targets, in.Packages, in.Deployments, in.Exceptions, in.Users = nil, nil, nil, nil, nil, nil
	pk := build(t, in)
	for _, id := range []string{"PM-01", "PM-02", "PM-03", "PM-05", "PM-06", "PM-07", "PM-08", "PM-09", "PM-10", "PM-11", "PM-12", "PM-13", "PM-15", "PM-17"} {
		if c := control(pk, id); c.Status != store.StatusNotAssessed {
			t.Errorf("%s without data: %s", id, c.Status)
		}
	}
	if pk.OverallAssessment.Suggested != store.StatusNotAssessed {
		t.Fatalf("overall without endpoints: %s", pk.OverallAssessment.Suggested)
	}
	if len(pk.Controls) != 17 {
		t.Fatalf("controls: %d", len(pk.Controls))
	}
}

func TestManualControlsAndMappings(t *testing.T) {
	in := fixture()
	prof := in.Profile.Profile
	prof.ManualControls = map[string]store.ManualControl{
		"PM-01": {Status: store.StatusCompliant, EvidenceRef: "POL-7 v3", Note: "Board-approved policy"},
		"PM-02": {Status: store.StatusCompliant, Note: "must not override automatic"},
	}
	prof.RegulatoryMappings[0].Applicable, prof.RegulatoryMappings[0].Reviewer, prof.RegulatoryMappings[0].ReviewedAt = "yes", "Legal (R. Iyer)", "2026-10-10"
	prof.RegulatoryMappings[0].ClauseRef, prof.RegulatoryMappings[0].Result = "§ 4.3", store.StatusPartial
	prof.OverallAssessment = store.AssessmentOverride{Status: store.StatusPartial, Rationale: "Reviewer view"}
	in.Profile.Profile = prof
	pk := build(t, in)
	if c := control(pk, "PM-01"); c.Status != store.StatusCompliant || c.Source != "manual" || !strings.Contains(c.Rationale, "POL-7") {
		t.Fatalf("manual PM-01: %+v", c)
	}
	if c := control(pk, "PM-02"); c.Source != "automatic" || c.Manual == nil {
		t.Fatalf("manual must not override an automatic result: %+v", c)
	}
	if c := control(pk, "PM-08"); c.Status != store.StatusNotAssessed || c.Source != "none" {
		t.Fatalf("PM-08 without a manual entry: %+v", c)
	}
	m := pk.RegulatoryMappings
	if m[0].NeedsReview || !strings.Contains(m[0].Conclusion, "§ 4.3") || !strings.Contains(m[0].Conclusion, "Partially compliant") {
		t.Fatalf("reviewed mapping: %+v", m[0])
	}
	if !m[1].NeedsReview || m[1].Conclusion != NotAssessedReview || len(m) != 7 {
		t.Fatalf("unreviewed mapping: %+v", m[1])
	}
	if pk.OverallAssessment.Status != store.StatusPartial || pk.OverallAssessment.Source != "profile" || pk.OverallAssessment.Suggested != store.StatusNonCompliant {
		t.Fatalf("override: %+v", pk.OverallAssessment)
	}
}

// The report keeps the template's structure and wording.
func TestMarkdownTemplateStructure(t *testing.T) {
	md := build(t, fixture()).Markdown()
	for _, h := range []string{"# Patch Management Compliance Report", "**Report type:**", "**Regulatory review date:**", "**Prepared for:**", "**Report ID:**",
		"> **Important:** " + Disclaimer, "## 1. Executive summary", "| Endpoints compliant with applicable patch policy |", "### Overall assessment", "### Key findings",
		"## 2. Scope and methodology", "### 2.1 Organization and regulatory profile", "### 2.2 Offline update-delivery model", "### 2.3 Assessment method",
		"### 2.4 Status values", "## 3. Common patch management control matrix", "| PM-01 |", "| PM-17 |", "## 4. India regulatory mapping", "### Applicability note",
		"### 4.1 Regulatory mapping fields required in the product", "## 5. Patch timeliness and compliance calculation", "### 5.1 Policy-defined deadlines",
		"| Emergency / actively exploited |", "| High / critical |", "**Important SEBI note:**", "### 5.2 Calculation rules",
		"## 6. Evidence register and export manifest", "| E-001 | Approved patch policy |", "| E-010 | Governance reporting and corrective actions |",
		"### Export integrity and handling", "## 7. Findings and corrective action plan", "### Risk acceptance / exception register",
		"## 8. Auditor review and sign-off", "| Independent auditor |", "**Scope limitations:**", "**Management response:**",
		"## 9. Official references for mapping maintenance", NotAssessedReview, "**RBI — Master Direction on Information Technology Governance",
		"**PFRDA / other sector-specific regulator or critical-sector direction**", "| F-001 |", "| x-1 |"} {
		if !strings.Contains(md, h) {
			t.Errorf("report.md lacks %q", h)
		}
	}
	if strings.Contains(md, "## 10.") || strings.Contains(strings.ToLower(md), "rbi compliant") && !strings.Contains(md, "“RBI compliant”") {
		t.Error("section 10 or a compliance claim in the report")
	}
}

func TestRedaction(t *testing.T) {
	in := fixture()
	in.Redact = true
	in.PrivilegedEvents = []store.AuditEvent{{Seq: 7, TS: ts(now), Actor: "user:adam@bank.test", Action: "user.created", ObjectType: "user", ObjectID: "uma@bank.test",
		Details: json.RawMessage(`{"note":"pc-fail at 10.20.30.40"}`)}}
	pk := build(t, in)
	var buf bytes.Buffer
	json.NewEncoder(&buf).Encode(pk)
	all := buf.String() + pk.Markdown()
	for _, id := range []string{"E-002", "E-006", "E-007", "E-008", "E-009"} {
		pk.WriteEvidence(id, &buf)
	}
	all += buf.String()
	for _, secret := range []string{"pc-ok", "pc-fail", "pc-stale", "e-fail", "alice@bank.test", "adam@bank.test", "otto@bank.test", "vera@bank.test", "uma@bank.test", "10.20.30.40"} {
		if strings.Contains(all, secret) {
			t.Errorf("redacted pack contains %q", secret)
		}
	}
	// Stable: the same salt gives the same pseudonyms; another salt others.
	again, _ := Build(in, []byte("salt"))
	other, _ := Build(in, []byte("other salt"))
	if again.Timeliness.Pairs[0].Hostname != pk.Timeliness.Pairs[0].Hostname || other.Timeliness.Pairs[0].Hostname == pk.Timeliness.Pairs[0].Hostname ||
		!strings.HasPrefix(pk.Timeliness.Pairs[0].Hostname, "host-") {
		t.Fatalf("pseudonyms: %s %s %s", pk.Timeliness.Pairs[0].Hostname, again.Timeliness.Pairs[0].Hostname, other.Timeliness.Pairs[0].Hostname)
	}
	if !pk.Meta.Redacted || in.Endpoints[0].Hostname != "pc-ok" {
		t.Fatal("input modified or meta not marked")
	}
	// Same numbers as the unredacted pack.
	plain := build(t, fixture())
	if plain.ExecutiveSummary.CompliantWithPolicy != pk.ExecutiveSummary.CompliantWithPolicy || plain.ExecutiveSummary.Overdue != pk.ExecutiveSummary.Overdue {
		t.Fatal("redaction changed the measures")
	}
}

func TestZipManifestAndSignature(t *testing.T) {
	pk := build(t, fixture())
	pub, priv, _ := ed25519.GenerateKey(nil)
	var buf bytes.Buffer
	var sealed string
	m, err := pk.WriteZip(&buf, priv, func(sum string) error { sealed = sum; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) != 64 || m.PublicKeyFingerprint != KeyFingerprint(pub) || m.ReportID != pk.Meta.ReportID || len(m.Files) != 12 {
		t.Fatalf("manifest: %+v", m)
	}
	got, err := VerifyZip(buf.Bytes(), pub)
	if err != nil {
		t.Fatal(err)
	}
	// Evidence hashes in the register (summary.json, report.md) are the files' hashes.
	files := map[string]string{}
	for _, f := range got.Files {
		files[f.Path] = f.SHA256
	}
	for _, e := range pk.EvidenceRegister {
		if files[e.Included] != e.SHA256 {
			t.Errorf("%s: register %s, manifest %s", e.ID, e.SHA256, files[e.Included])
		}
	}
	other, _, _ := ed25519.GenerateKey(nil)
	if _, err := VerifyZip(buf.Bytes(), other); err == nil {
		t.Fatal("verified with another key")
	}
	// Tamper with one evidence file: the manifest no longer matches.
	zr, _ := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		if f.Name == "evidence/E-007-endpoint-results.csv" {
			b = bytes.Replace(b, []byte("overdue"), []byte("compliant"), 1)
		}
		w, _ := zw.Create(f.Name)
		w.Write(b)
	}
	zw.Close()
	if _, err := VerifyZip(out.Bytes(), pub); err == nil || !strings.Contains(err.Error(), "E-007") {
		t.Fatalf("tampered package verified: %v", err)
	}
	// An audit failure before sealing leaves an incomplete package.
	var broken bytes.Buffer
	if _, err := pk.WriteZip(&broken, priv, func(string) error { return io.ErrUnexpectedEOF }); err == nil {
		t.Fatal("seal error ignored")
	}
	if _, err := VerifyZip(broken.Bytes(), pub); err == nil {
		t.Fatal("unsealed package verifies")
	}
}

// 20 000 endpoints × 10 updates: well under a few seconds and bounded JSON.
func TestLargeFleet(t *testing.T) {
	if testing.Short() {
		t.Skip("large fleet")
	}
	in := fixture()
	in.Endpoints, in.Targets, in.Exceptions = nil, nil, nil
	in.Needs = map[string][]string{}
	var pkgs []store.Package
	for p := 0; p < 10; p++ {
		pk := pkg(fmt.Sprintf("KB9%d", p), "important", "2026-09-01")
		pkgs = append(pkgs, pk)
	}
	in.Packages = pkgs
	for i := 0; i < 20000; i++ {
		id := fmt.Sprintf("e-%05d", i)
		in.Endpoints = append(in.Endpoints, ep(id, "pc-"+id, "compliant"))
		for _, p := range pkgs {
			if i%2 == 0 {
				in.Targets = append(in.Targets, target("d1", p.PackageID, id, "verified", time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)))
			} else {
				in.Needs[p.PackageID] = append(in.Needs[p.PackageID], id)
			}
		}
	}
	start := time.Now()
	pk := build(t, in)
	if d := time.Since(start); d > 20*time.Second {
		t.Fatalf("20 000 endpoints took %v", d)
	}
	if pk.Timeliness.PairsTotal != 200000 || len(pk.Timeliness.Pairs) != PairsLimit || !pk.Timeliness.PairsTruncated || pk.ExecutiveSummary.CompliantWithPolicy.Count != 10000 {
		t.Fatalf("large fleet: total %d listed %d compliant %d", pk.Timeliness.PairsTotal, len(pk.Timeliness.Pairs), pk.ExecutiveSummary.CompliantWithPolicy.Count)
	}
}
