package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"offpatch/internal/compliance"
	"offpatch/internal/pdf"
	"offpatch/internal/store"
)

// Server-generated PDF reports (vendor super admin only, like every
// report route): the auditor report for a period, the patch compliance
// report (the Reports page) and the audit log for a period. Every
// generation is audited with the file's SHA-256.

// auditLogPDFLimit bounds the events listed in one audit log PDF (the
// signed off-box audit export has them all).
const auditLogPDFLimit = 20000

// reportID: <prefix>-<UTC time>-<random>, unique per generation.
func reportID(prefix string, now time.Time) string {
	var b [3]byte
	rand.Read(b[:])
	return prefix + "-" + now.UTC().Format("20060102T150405Z") + "-" + strings.ToUpper(hex.EncodeToString(b[:]))
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func servePDF(w http.ResponseWriter, name string, b []byte) {
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(200)
	w.Write(b)
}

// compliancePackPDF: GET /api/reports/compliance-pack.pdf?from=&to=[&redact=1][&tz=]
func (s *Server) compliancePackPDF(w http.ResponseWriter, r *http.Request) {
	pk, err := s.buildPack(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	b, err := pk.PDF()
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.auditPackGenerated(r.Context(), actor(r), pk, "pdf", ""); err != nil {
		s.fail(w, err)
		return
	}
	servePDF(w, pk.FileName(), b)
}

// compliancePDF: GET /api/reports/compliance.pdf — the patch compliance
// report (what the Reports page shows).
func (s *Server) compliancePDF(w http.ResponseWriter, r *http.Request) {
	rep, err := s.store.Compliance(r.Context(), s.th)
	if err != nil {
		s.fail(w, err)
		return
	}
	now := s.store.Now()
	id := reportID("PC", now)
	b, err := patchCompliancePDF(rep, id, now, principalName(r))
	if err != nil {
		s.fail(w, err)
		return
	}
	name := compliance.PDFFileName("patch-compliance", now.Format("2006-01-02"), id)
	if err := s.store.Audit(r.Context(), store.Ev{Actor: actor(r), Action: "report.exported", ObjectType: "report", ObjectID: "compliance.pdf",
		Details: map[string]any{"report_id": id, "format": "pdf", "sha256": sha256Hex(b), "packages": len(rep.Packages)}}); err != nil {
		s.fail(w, err)
		return
	}
	servePDF(w, name, b)
}

// auditPDF: GET /api/audit.pdf?from=&to=[&tz=] — the audit log of a period.
func (s *Server) auditPDF(w http.ResponseWriter, r *http.Request) {
	from, to, loc, err := s.reportPeriod(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	evs, truncated, err := s.store.AuditBetween(r.Context(), from, to, nil, auditLogPDFLimit)
	if err != nil {
		s.fail(w, err)
		return
	}
	chain, err := s.store.AuditChainStatus(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	now := s.store.Now()
	id := reportID("AL", now)
	period := from.Format("2006-01-02") + "_" + to.AddDate(0, 0, -1).Format("2006-01-02")
	b, err := auditLogPDF(auditLogInput{ID: id, Now: now.In(loc), From: from, To: to, Loc: loc, Events: evs, Truncated: truncated,
		ChainOK: chain.OK, ChainCount: chain.Count, By: principalName(r)})
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.store.Audit(r.Context(), store.Ev{Actor: actor(r), Action: "report.exported", ObjectType: "report", ObjectID: "audit.pdf",
		Details: map[string]any{"report_id": id, "format": "pdf", "sha256": sha256Hex(b), "period_from": from.Format("2006-01-02"),
			"period_to": to.AddDate(0, 0, -1).Format("2006-01-02"), "events": len(evs), "truncated": truncated}}); err != nil {
		s.fail(w, err)
		return
	}
	servePDF(w, compliance.PDFFileName("audit-log", period, id), b)
}

func principalName(r *http.Request) string {
	p, _ := r.Context().Value(keyPrincipal).(*principal)
	if p == nil {
		return ""
	}
	return p.User + " / " + p.Role
}

func pctTone(p float64, n int) pdf.Tone {
	switch {
	case n == 0:
		return pdf.ToneGrey
	case p >= 95:
		return pdf.ToneGreen
	case p >= 80:
		return pdf.ToneAmber
	}
	return pdf.ToneRed
}

func daysCell(v float64) pdf.Cell {
	if v < 0 {
		return pdf.T("—")
	}
	return pdf.T(strconv.FormatFloat(v, 'f', 1, 64))
}

var severityOrder = []string{"critical", "important", "moderate", "low"}

// patchCompliancePDF renders the Reports page: compliance by severity,
// fleet, exceptions, intake and the per-package table.
func patchCompliancePDF(rep store.ComplianceReport, id string, now time.Time, by string) ([]byte, error) {
	d := pdf.New(pdf.Info{Title: "Patch compliance report " + id, Subject: "Patch compliance by severity and package", Created: now}, "DSS Patcher · "+id)
	compliance.Cover(d, "Offline patch management · patch compliance report")
	d.Text(pdf.MarginLeft, d.Y()+18, pdf.HelveticaBold, 20, pdf.Navy, "Patch compliance report")
	d.SetY(d.Y() + 28)
	d.Paragraph(fmt.Sprintf("Generated %s · report %s · %s", rep.GeneratedAt, id, by), pdf.Style{Font: pdf.Helvetica, Size: 9.5, Color: pdf.Grey, After: 10})

	d.Heading(1, "Compliance by severity")
	d.Paragraph("Confirmed installs out of the machines that need each update, against the deadline counted from the vendor release.", pdf.Body)
	keys := append([]string{}, severityOrder...)
	for k := range rep.BySeverity {
		if !contains(severityOrder, k) {
			keys = append(keys, k)
		}
	}
	st := pdf.Table{Columns: []pdf.Column{{Header: "Severity", Weight: 1.1}, {Header: "Deadline", Weight: 1}, {Header: "Need it / targets", Align: pdf.Right}, {Header: "Verified", Align: pdf.Right},
		{Header: "Outstanding", Align: pdf.Right}, {Header: "Overdue", Align: pdf.Right}, {Header: "Exceptions", Align: pdf.Right}, {Header: "Compliant", Weight: 1.1}}, Size: 8.5, Zebra: true}
	for _, k := range keys {
		v, ok := rep.BySeverity[k]
		if !ok {
			continue
		}
		over := pdf.T(strconv.Itoa(v.Overdue))
		if v.Overdue > 0 {
			over = pdf.Cell{Text: over.Text, Bold: true, Tone: pdf.ToneRed}
		}
		pct := "—"
		if v.Targets > 0 {
			pct = fmt.Sprintf("%.1f %%", v.PctComplete)
		}
		st.Rows = append(st.Rows, []pdf.Cell{pdf.B(k), pdf.T(goDuration(rep.Deadlines[k])), pdf.T(strconv.Itoa(v.Targets)), pdf.T(strconv.Itoa(v.Verified)),
			pdf.T(strconv.Itoa(v.Outstanding)), over, pdf.T(strconv.Itoa(v.Exceptions)), pdf.PillCell(pct, pctTone(v.PctComplete, v.Targets))})
	}
	if len(st.Rows) == 0 {
		d.Paragraph("No machine needs a catalog package yet.", pdf.Body)
	} else {
		d.Table(st)
	}

	d.Heading(1, "Fleet, exceptions and intake")
	f := rep.Fleet
	d.KeyValues([][2]string{
		{"Endpoints", strconv.Itoa(f.Total)},
		{"Reporting", fmt.Sprintf("%.1f %% (%d)", f.PctReporting, f.Reporting)},
		{"Offline", strconv.Itoa(f.Offline)},
		{"Stale", strconv.Itoa(f.Stale)},
		{"Restart needed", strconv.Itoa(f.PendingBoot)},
		{"Active exceptions", strconv.Itoa(rep.Exceptions.Active)},
		{"Exceptions expiring in 7 days", strconv.Itoa(rep.Exceptions.ExpiringIn7d)},
		{"Oldest active exception", map[bool]string{true: fmt.Sprintf("%.1f days", rep.Exceptions.OldestAgeDays), false: "—"}[rep.Exceptions.Active > 0]},
		{"Bundles validated", strconv.Itoa(rep.Intake.Validated)},
		{"Bundles rejected", strconv.Itoa(rep.Intake.Rejected)},
	}, 0.4)

	d.Heading(1, fmt.Sprintf("Packages (%d)", len(rep.Packages)))
	d.Paragraph("Latency in days. “—” means the milestone has not been reached yet. Machines that need a package but are not in any deployment count as outstanding.", pdf.Body)
	pt := pdf.Table{Columns: []pdf.Column{{Header: "Package", Weight: 2.6}, {Header: "Severity", Weight: 1.1}, {Header: "State", Weight: 1}, {Header: "Released", Weight: 1.1},
		{Header: "Deadline", Weight: 1.1}, {Header: "Need it", Weight: 0.7, Align: pdf.Right}, {Header: "Verified", Weight: 0.75, Align: pdf.Right}, {Header: "Outst.", Weight: 0.7, Align: pdf.Right},
		{Header: "Overdue", Weight: 0.75, Align: pdf.Right}, {Header: "Exc.", Weight: 0.55, Align: pdf.Right}, {Header: "Compliant", Weight: 1.05},
		{Header: "Rel→recv", Weight: 0.75, Align: pdf.Right}, {Header: "Recv→appr", Weight: 0.8, Align: pdf.Right}, {Header: "Appr→1st", Weight: 0.75, Align: pdf.Right},
		{Header: "Rel→90%", Weight: 0.75, Align: pdf.Right}}, Size: 6.5, Zebra: true}
	for _, p := range rep.Packages {
		title := p.PackageID
		if p.Title != "" {
			title = p.Title + "\n" + p.PackageID
		}
		need := p.Needed
		if need == 0 {
			need = max(p.Targets, p.Verified+p.Outstanding)
		}
		over := pdf.T(strconv.Itoa(p.Overdue))
		var fill *pdf.Color
		if p.Overdue > 0 {
			over = pdf.Cell{Text: over.Text, Bold: true, Tone: pdf.ToneRed}
			c, _ := pdf.ToneColors(pdf.ToneRed)
			fill = &c
		}
		pct := "—"
		if need > 0 {
			pct = fmt.Sprintf("%.1f %%", p.PctComplete)
		}
		rel := "—"
		if len(p.ReleaseDate) >= 10 {
			rel = p.ReleaseDate[:10]
		}
		dl := "—"
		if len(p.Deadline) >= 10 {
			dl = p.Deadline[:10]
		}
		pt.Rows = append(pt.Rows, []pdf.Cell{{Text: title, Bold: true, Fill: fill}, pdf.T(p.Severity), pdf.T(p.State), pdf.T(rel), pdf.T(dl), pdf.T(strconv.Itoa(need)),
			pdf.T(strconv.Itoa(p.Verified)), pdf.T(strconv.Itoa(p.Outstanding)), over, pdf.T(strconv.Itoa(p.Exceptions)), pdf.PillCell(pct, pctTone(p.PctComplete, need)),
			daysCell(p.DaysReleaseToReceived), daysCell(p.DaysReceivedToApproved), daysCell(p.DaysApprovedToFirst), daysCell(p.DaysReleaseToP90)})
	}
	if len(pt.Rows) == 0 {
		d.Paragraph("No packages.", pdf.Body)
	} else {
		d.Table(pt)
	}
	return d.Bytes()
}

// goDuration: "336h0m0s" → "14 days".
func goDuration(s string) string {
	dur, err := time.ParseDuration(s)
	if err != nil || s == "" {
		return dash(s)
	}
	if h := dur.Hours(); h >= 24 && int(h)%24 == 0 {
		n := int(h) / 24
		if n == 1 {
			return "1 day"
		}
		return strconv.Itoa(n) + " days"
	}
	return dur.String()
}

func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

type auditLogInput struct {
	ID         string
	Now        time.Time
	From, To   time.Time // To exclusive
	Loc        *time.Location
	Events     []store.AuditEvent
	Truncated  bool
	ChainOK    bool
	ChainCount int64
	By         string
}

// auditLogPDF renders the audit events of a period, oldest first.
func auditLogPDF(in auditLogInput) ([]byte, error) {
	last := in.To.AddDate(0, 0, -1).Format("2006-01-02")
	d := pdf.New(pdf.Info{Title: "Audit log " + in.ID, Subject: "Audit events " + in.From.Format("2006-01-02") + " to " + last, Created: in.Now}, "DSS Patcher · "+in.ID)
	compliance.Cover(d, "Offline patch management · audit log")
	d.Text(pdf.MarginLeft, d.Y()+18, pdf.HelveticaBold, 20, pdf.Navy, "Audit log")
	d.SetY(d.Y() + 28)
	d.Paragraph(fmt.Sprintf("Period %s to %s (%s) · report %s", in.From.Format("2006-01-02"), last, in.Loc.String(), in.ID), pdf.Style{Font: pdf.Helvetica, Size: 9.5, Color: pdf.Grey, After: 10})
	failures := 0
	actions := map[string]int{}
	for _, e := range in.Events {
		if e.Outcome == "failure" {
			failures++
		}
		actions[strings.SplitN(e.Action, ".", 2)[0]]++
	}
	chain := fmt.Sprintf("verified (%d events in the chain)", in.ChainCount)
	if !in.ChainOK {
		chain = "FAILED verification: the audit trail may have been altered"
	}
	listed := strconv.Itoa(len(in.Events))
	if in.Truncated {
		listed += fmt.Sprintf(" (first %d only; the signed off-box audit export has every event)", auditLogPDFLimit)
	}
	d.KeyValues([][2]string{
		{"Events in the period", listed},
		{"Failures (denied, failed)", strconv.Itoa(failures)},
		{"Audit chain", chain},
		{"Generated", in.Now.Format(time.RFC3339) + " by " + dash(in.By)},
	}, 0.32)
	if !in.ChainOK {
		d.Callout([]pdf.Run{{Text: "Audit chain check failed.", Bold: true}, {Text: " Investigate before relying on this log (runbook: audit verification and evidence)."}}, pdf.ToneRed)
	}
	if len(actions) > 0 {
		var kinds []string
		for k := range actions {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds)
		var parts []string
		for _, k := range kinds {
			parts = append(parts, fmt.Sprintf("%s %d", k, actions[k]))
		}
		d.Rich([]pdf.Run{{Text: "By area:", Bold: true}, {Text: " " + strings.Join(parts, " · ")}}, pdf.Body)
	}

	d.Heading(1, "Events")
	t := pdf.Table{Columns: []pdf.Column{{Header: "Seq", Weight: 0.5, Align: pdf.Right}, {Header: "Time", Weight: 1.25}, {Header: "Actor", Weight: 1.4}, {Header: "Action", Weight: 1.35},
		{Header: "Object", Weight: 1.4}, {Header: "Outcome", Weight: 0.8}, {Header: "Details", Weight: 2.6}}, Size: 6.5, Zebra: true}
	for _, e := range in.Events {
		ts := e.TS
		if tm, err := time.Parse(time.RFC3339Nano, e.TS); err == nil {
			ts = tm.In(in.Loc).Format("2006-01-02 15:04:05")
		}
		obj := e.ObjectType
		if e.ObjectID != "" {
			obj += " " + e.ObjectID
		}
		det := string(e.Details)
		if det == "{}" || det == "null" {
			det = ""
		}
		if len(det) > 400 {
			det = det[:400] + "…"
		}
		out := pdf.PillCell("ok", pdf.ToneGreen)
		if e.Outcome == "failure" {
			out = pdf.PillCell("failure", pdf.ToneRed)
		}
		t.Rows = append(t.Rows, []pdf.Cell{pdf.T(strconv.FormatInt(e.Seq, 10)), pdf.T(ts), pdf.T(e.Actor), pdf.B(e.Action), pdf.T(obj), out, pdf.M(det)})
	}
	if len(t.Rows) == 0 {
		d.Paragraph("No audit events in this period.", pdf.Body)
	} else {
		d.Table(t)
	}
	return d.Bytes()
}
