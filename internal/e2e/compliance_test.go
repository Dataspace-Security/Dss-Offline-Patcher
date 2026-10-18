package e2e

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"offpatch/internal/agent"
	"offpatch/internal/compliance"
	"offpatch/internal/manifest"
	"offpatch/internal/pdf"
	"offpatch/internal/store"
)

func (e *env) get(t *testing.T, path, tok string) []byte {
	t.Helper()
	req, _ := http.NewRequest("GET", e.srv.URL+path, nil)
	e.authorize(req, tok)
	resp, err := e.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s: %d %s", path, resp.StatusCode, b)
	}
	return b
}

// The auditor compliance pack after a real (simulated) deployment: the
// measures, outcomes and controls follow from what the agents did, and the
// ZIP verifies with the server's audit-signing key.
func TestCompliancePackAfterDeployment(t *testing.T) {
	e := newEnv(t)
	today := time.Now().UTC()
	fresh := msuPkg("KB5011001-x64", "KB5011001") // within its 7-day deadline
	fresh.ReleaseDate = today.AddDate(0, 0, -2).Format("2006-01-02")
	old := msuPkg("KB5011002-x64", "KB5011002") // needed everywhere, never deployed, past deadline
	old.ReleaseDate = today.AddDate(0, 0, -20).Format("2006-01-02")
	e.intakeApproved(map[string]manifest.Package{fresh.PackageID: fresh, old.PackageID: old}, 1)
	ok := e.enroll("pc-c-ok", []string{"c"}, agent.SimConfig{})
	bad := e.enroll("pc-c-bad", []string{"c"}, agent.SimConfig{FailKBs: []string{"KB5011001"}})
	exc := e.enroll("pc-c-exc", []string{"c"}, agent.SimConfig{})
	for _, a := range []*simAgent{ok, bad, exc} {
		e.cycle(a) // inventory: the endpoints need both updates
	}
	if c := e.api("POST", "/api/exceptions", tokAdmin, map[string]string{"endpoint_id": exc.id, "package_id": fresh.PackageID, "owner": "Branch IT lead",
		"reason": "teller application freeze", "compensating_controls": "isolated VLAN", "expires_at": today.Add(30 * 24 * time.Hour).Format(time.RFC3339)}, nil); c != 201 {
		t.Fatalf("exception: %d", c)
	}
	e.deploy(store.NewDeployment{PackageID: fresh.PackageID, Name: "fresh CU", Rings: []store.Ring{{Name: "c", Groups: []string{"c"}}}})
	for i := 0; i < 2; i++ {
		e.cycle(ok)
		e.cycle(bad)
		e.cycle(exc)
	}

	from := today.AddDate(0, 0, -30).Format("2006-01-02")
	to := today.Format("2006-01-02")
	q := "/api/reports/compliance-pack?tz=UTC&from=" + from + "&to=" + to
	var pk compliance.Pack
	if err := json.Unmarshal(e.get(t, q, tokViewer), &pk); err != nil {
		t.Fatal(err)
	}
	es := pk.ExecutiveSummary
	if es.InScopeEndpoints != 3 || es.CurrentInventory.Count != 3 || es.StaleInventory.Count != 0 || es.ActiveExceptions != 1 {
		t.Fatalf("summary: %+v", es)
	}
	// Every endpoint misses the old update past its deadline: none compliant.
	if es.Overdue.Count != 3 || es.CompliantWithPolicy.Count != 0 {
		t.Fatalf("overdue / compliant: %+v", es)
	}
	got := map[string]string{}
	for _, p := range pk.Timeliness.Pairs {
		got[p.Hostname+"/"+p.PackageID] = p.Outcome
		if p.Hostname == "pc-c-ok" && p.PackageID == fresh.PackageID && (p.VerifiedAt == "" || p.Evidence == "" || p.InstalledAt == "" || p.Deadline == "") {
			t.Fatalf("verified pair lacks evidence: %+v", p)
		}
	}
	want := map[string]string{"pc-c-ok/" + fresh.PackageID: "compliant", "pc-c-bad/" + fresh.PackageID: "failed", "pc-c-exc/" + fresh.PackageID: "exception",
		"pc-c-ok/" + old.PackageID: "overdue", "pc-c-bad/" + old.PackageID: "overdue", "pc-c-exc/" + old.PackageID: "overdue"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %s, want %s (all %v)", k, got[k], v, got)
		}
	}
	ctl := map[string]compliance.Control{}
	for _, c := range pk.Controls {
		ctl[c.ID] = c
	}
	if ctl["PM-07"].Status != store.StatusCompliant || ctl["PM-10"].Status != store.StatusCompliant || ctl["PM-06"].Status != store.StatusNonCompliant ||
		ctl["PM-02"].Status != store.StatusCompliant || ctl["PM-01"].Status != store.StatusNotAssessed {
		for _, id := range []string{"PM-01", "PM-02", "PM-06", "PM-07", "PM-10"} {
			t.Logf("%s %s: %s", id, ctl[id].Status, ctl[id].Rationale)
		}
		t.Fatal("control statuses")
	}
	if ctl["PM-05"].Status == store.StatusNotAssessed || ctl["PM-03"].Status == store.StatusNotAssessed {
		t.Fatalf("acquisition / verification controls not evaluated: %s / %s", ctl["PM-03"].Status, ctl["PM-05"].Status)
	}
	if pk.OverallAssessment.Suggested != store.StatusNonCompliant || len(pk.Findings) == 0 || pk.Findings[0].Severity != compliance.SevCritical {
		t.Fatalf("assessment %+v findings %+v", pk.OverallAssessment, pk.Findings)
	}

	// The signed package.
	zb := e.get(t, strings.Replace(q, "compliance-pack?", "compliance-pack.zip?", 1), tokViewer)
	pub, err := manifest.LoadPublic(filepath.Join(e.cfg.DataDir, "audit-signing.pub"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := compliance.VerifyZip(zb, pub)
	if err != nil || m.Period.From != from || m.ProductVersion == "" {
		t.Fatalf("verify: %v %+v", err, m)
	}
	zr, _ := zip.NewReader(bytes.NewReader(zb), int64(len(zb)))
	files := map[string][]byte{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		files[f.Name], _ = io.ReadAll(rc)
		rc.Close()
	}
	if !bytes.Contains(files["report.md"], []byte("## 7. Findings and corrective action plan")) || !bytes.Contains(files["report.md"], []byte("pc-c-bad")) {
		t.Fatal("report.md")
	}
	// report.pdf: a real PDF of the same report, covered by the manifest.
	if _, err := pdf.Check(files["report.pdf"]); err != nil {
		t.Fatalf("report.pdf: %v", err)
	}
	if pages, err := pdf.PageTexts(files["report.pdf"]); err != nil || !strings.Contains(strings.Join(pages[0], " "), m.ReportID) {
		t.Fatalf("report.pdf text: %v", err)
	}
	csv := string(files["evidence/E-007-endpoint-results.csv"])
	if strings.Count(csv, "\n") != 7 || !strings.Contains(csv, "pc-c-exc") || !strings.Contains(csv, ",exception,") {
		t.Fatalf("E-007:\n%s", csv)
	}
	if !strings.Contains(string(files["evidence/E-006-approvals.csv"]), "user:alice@bank.test; user:bob@bank.test") {
		t.Fatalf("E-006:\n%s", files["evidence/E-006-approvals.csv"])
	}
	var summary compliance.Pack
	if err := json.Unmarshal(files["summary.json"], &summary); err != nil || summary.Meta.ReportID != m.ReportID {
		t.Fatalf("summary.json: %v", err)
	}

	// Redacted: no hostnames or user names, same numbers.
	rb := e.get(t, q+"&redact=1", tokViewer)
	for _, s := range []string{"pc-c-ok", "pc-c-bad", ok.id, "alice@bank.test", "vera@bank.test"} {
		if bytes.Contains(rb, []byte(s)) {
			t.Errorf("redacted pack contains %s", s)
		}
	}
	var red compliance.Pack
	json.Unmarshal(rb, &red)
	if red.ExecutiveSummary.Overdue != es.Overdue || !red.Meta.Redacted {
		t.Fatalf("redacted summary: %+v", red.ExecutiveSummary)
	}
	var evs []store.AuditEvent
	e.api("GET", "/api/audit?action=report.compliance_generated&limit=10", tokViewer, nil, &evs)
	if len(evs) != 3 {
		t.Fatalf("generations audited: %d", len(evs))
	}
	// The next pack sees the earlier generations (PM-15).
	var again compliance.Pack
	json.Unmarshal(e.get(t, q, tokViewer), &again)
	for _, c := range again.Controls {
		if c.ID == "PM-15" && c.Status != store.StatusPartial {
			t.Fatalf("PM-15 after earlier reports: %s %s", c.Status, c.Rationale)
		}
	}
}
