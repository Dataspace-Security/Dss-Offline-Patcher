package server

import (
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"offpatch/internal/compliance"
	"offpatch/internal/manifest"
	"offpatch/internal/pdf"
	"offpatch/internal/store"
)

// Report profile: everyone reads, admins and super admins write; each save
// is a new version. The pack: viewers generate it (JSON and signed ZIP),
// each generation audited.
func TestComplianceReportAPI(t *testing.T) {
	s := newRolesServer(t, "", false)
	h := s.Handler()
	var rec store.ReportProfileRecord
	w := do(h, req{method: "GET", path: "/api/reports/profile", token: roleTokens["viewer"]})
	json.Unmarshal(w.Body.Bytes(), &rec)
	if w.Code != 200 || !rec.IsDefault || len(rec.Profile.Deadlines) != 5 || rec.Profile.RegulatoryMappings[0].Applicable != "unknown" {
		t.Fatalf("default profile: %d %s", w.Code, w.Body)
	}
	p := rec.Profile
	p.LegalEntity, p.AssessmentOwner = "Example Bank Ltd", "Head of IT Operations"
	for _, role := range []string{"viewer", "user"} {
		if w := do(h, req{method: "PUT", path: "/api/reports/profile", body: p, token: roleTokens[role]}); w.Code != 403 {
			t.Fatalf("%s writes the profile: %d", role, w.Code)
		}
	}
	for i, role := range []string{"admin", "super_admin"} {
		w := do(h, req{method: "PUT", path: "/api/reports/profile", body: p, token: roleTokens[role]})
		json.Unmarshal(w.Body.Bytes(), &rec)
		if w.Code != 200 || rec.Version != i+1 {
			t.Fatalf("%s writes the profile: %d %s", role, w.Code, w.Body)
		}
	}
	if w := do(h, req{method: "PUT", path: "/api/reports/profile?base_version=1", body: p, token: roleTokens["admin"]}); w.Code != 409 {
		t.Fatalf("stale base_version: %d", w.Code)
	}
	bad := p
	bad.Regulators = []string{"FCA"}
	if w := do(h, req{method: "PUT", path: "/api/reports/profile", body: bad, token: roleTokens["admin"]}); w.Code != 400 {
		t.Fatalf("invalid profile: %d", w.Code)
	}
	if w := do(h, req{method: "PUT", path: "/api/reports/profile", body: map[string]any{"legal_entity": "x", "unknown_field": 1}, token: roleTokens["admin"]}); w.Code != 400 {
		t.Fatalf("unknown field: %d", w.Code)
	}
	var hist []store.ReportProfileVersion
	json.Unmarshal(do(h, req{method: "GET", path: "/api/reports/profile/history", token: roleTokens["viewer"]}).Body.Bytes(), &hist)
	if len(hist) != 2 || hist[0].EditedBy != "user:super-admin@roles.test" {
		t.Fatalf("history: %+v", hist)
	}
	if w := do(h, req{method: "GET", path: "/api/reports/profile?version=1", token: roleTokens["viewer"]}); w.Code != 200 || !strings.Contains(w.Body.String(), `"version":1`) {
		t.Fatalf("version 1: %d %s", w.Code, w.Body)
	}

	// JSON pack.
	w = do(h, req{method: "GET", path: "/api/reports/compliance-pack?from=2026-01-01&to=2026-12-31", token: roleTokens["viewer"]})
	var pk compliance.Pack
	if err := json.Unmarshal(w.Body.Bytes(), &pk); w.Code != 200 || err != nil {
		t.Fatalf("pack: %d %v %s", w.Code, err, w.Body)
	}
	if pk.Meta.Period.From != "2026-01-01" || pk.Meta.Period.To != "2026-12-31" || pk.Profile.LegalEntity != "Example Bank Ltd" || pk.ProfileVersion.Version != 2 ||
		len(pk.Controls) != 17 || len(pk.EvidenceRegister) != 10 || pk.Meta.GeneratedBy.User != "viewer@roles.test" || pk.Disclaimer != compliance.Disclaimer {
		t.Fatalf("pack content: %+v", pk.Meta)
	}
	for _, bad := range []string{"from=2026-13-01", "from=2026-05-02&to=2026-05-01", "from=2000-01-01&to=2026-01-01", "tz=Mars/Base", "from=2999-01-01&to=2999-01-02"} {
		if w := do(h, req{method: "GET", path: "/api/reports/compliance-pack?" + bad, token: roleTokens["viewer"]}); w.Code != 400 {
			t.Errorf("%s: %d", bad, w.Code)
		}
	}
	if w := do(h, req{method: "GET", path: "/api/reports/compliance-pack"}); w.Code != 401 {
		t.Fatalf("anonymous pack: %d", w.Code)
	}

	// Signed ZIP: verifies with the server's audit-signing key.
	w = do(h, req{method: "GET", path: "/api/reports/compliance-pack.zip?redact=1", token: roleTokens["viewer"]})
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/zip" || !strings.Contains(w.Header().Get("Content-Disposition"), "-redacted.zip") {
		t.Fatalf("zip: %d %v", w.Code, w.Header())
	}
	pub, err := manifest.LoadPublic(filepath.Join(s.cfg.DataDir, "audit-signing.pub"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := compliance.VerifyZip(w.Body.Bytes(), pub)
	if err != nil || !m.Redacted || m.PublicKeyFingerprint != compliance.KeyFingerprint(pub) {
		t.Fatalf("verify: %v %+v", err, m)
	}
	if strings.Contains(w.Body.String(), "viewer@roles.test") {
		t.Fatal("redacted package names the user") // deflated; also checked in the compliance tests
	}
	evs, _ := s.store.ListAudit(context.Background(), store.AuditQuery{Action: "report.compliance_generated"})
	if len(evs) != 2 || !strings.Contains(string(evs[0].Details), `"format":"zip"`) || !strings.Contains(string(evs[0].Details), "manifest_sha256") ||
		!strings.Contains(string(evs[1].Details), `"format":"json"`) {
		t.Fatalf("generation audit: %+v", evs)
	}
}

// Server PDFs (every signed-in role; here a viewer): the auditor report, the patch compliance
// report and the audit log, each a valid PDF with its headings, a
// DSS-Patcher-… file name, and audited.
func TestReportPDFs(t *testing.T) {
	s := newRolesServer(t, "", false)
	h := s.Handler()
	for _, c := range []struct{ path, name, heading, action string }{
		{"/api/reports/compliance-pack.pdf?from=2026-01-01&to=2026-12-31", "DSS-Patcher-compliance-report-2026-01-01_2026-12-31-CR-", "1. Executive summary", "report.compliance_generated"},
		{"/api/reports/compliance.pdf", "DSS-Patcher-patch-compliance-", "Compliance by severity", "report.exported"},
		{"/api/audit.pdf?from=2026-01-01&to=2026-12-31", "DSS-Patcher-audit-log-2026-01-01_2026-12-31-AL-", "Events", "report.exported"},
	} {
		w := do(h, req{method: "GET", path: c.path, token: roleTokens["viewer"]})
		if w.Code != 200 || w.Header().Get("Content-Type") != "application/pdf" || !strings.Contains(w.Header().Get("Content-Disposition"), `filename="`+c.name) {
			t.Fatalf("%s: %d %v %.200s", c.path, w.Code, w.Header(), w.Body)
		}
		if _, err := pdf.Check(w.Body.Bytes()); err != nil {
			t.Fatalf("%s: %v", c.path, err)
		}
		pages, err := pdf.PageTexts(w.Body.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		var all []string
		for _, p := range pages {
			all = append(all, p...)
		}
		if !slices.Contains(all, c.heading) {
			t.Errorf("%s: no %q heading", c.path, c.heading)
		}
		evs, _ := s.store.ListAudit(context.Background(), store.AuditQuery{Action: c.action, Limit: 1})
		if len(evs) == 0 || !strings.Contains(string(evs[0].Details), `"format":"pdf"`) {
			t.Errorf("%s: not audited: %+v", c.path, evs)
		}
	}
}
