package e2e

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"offpatch/internal/acqstatus"
	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

func (e *env) dropStatus(r acqstatus.Report, key []byte) {
	e.t.Helper()
	var k = e.priv
	if key != nil {
		_, other, _ := manifest.GenerateKey()
		k = other
	}
	s, err := acqstatus.Sign(r, manifest.KeyID(k.Public().(ed25519.PublicKey)), func(b []byte) (string, error) { return manifest.Sign(k, b), nil })
	if err != nil {
		e.t.Fatal(err)
	}
	b, _ := json.Marshal(s)
	os.WriteFile(filepath.Join(e.inbox, "acq-"+r.FinishedAt[11:19]+r.Outcome+acqstatus.FileSuffix), b, 0o640)
	e.intake.ScanOnce(context.Background())
}

func TestAcquisitionStatusAndSystem(t *testing.T) {
	e := newEnv(t)
	now := time.Now().UTC()
	ok := acqstatus.Report{Source: "acq-zone-1", Host: "acq01", Schedule: "daily at 07:00", StartedAt: now.Add(-time.Minute).Format(time.RFC3339),
		FinishedAt: now.Format(time.RFC3339), Outcome: "ok", New: []string{"chrome-mac-156"}, Failures: map[string]string{},
		Feeds: []acqstatus.Feed{{Type: "app", Name: "chrome-mac", LatestVersion: "156", Status: "new"}}}
	e.dropStatus(ok, nil)

	var resp struct {
		Sources []store.AcqSource `json:"sources"`
		History []store.AcqRecord `json:"history"`
	}
	if c := e.api("GET", "/api/acquisition", tokViewer, nil, &resp); c != 200 || len(resp.Sources) != 1 || resp.Sources[0].Last.Outcome != "ok" || resp.Sources[0].Stale {
		t.Fatalf("acquisition: %d %+v", c, resp)
	}
	var rep acqstatus.Report
	json.Unmarshal(resp.Sources[0].Last.Report, &rep)
	if rep.Schedule != "daily at 07:00" || len(rep.Feeds) != 1 || rep.Feeds[0].LatestVersion != "156" {
		t.Fatalf("report content: %+v", rep)
	}

	// A partial run raises an alert; a report signed by an unknown key is rejected.
	part := ok
	part.Outcome, part.FinishedAt = "partial", now.Add(time.Second).Format(time.RFC3339)
	part.Failures = map[string]string{"zoom-mac": "signature mismatch"}
	e.dropStatus(part, nil)
	forged := ok
	forged.FinishedAt = now.Add(2 * time.Second).Format(time.RFC3339)
	e.dropStatus(forged, []byte("x"))
	e.api("GET", "/api/acquisition", tokViewer, nil, &resp)
	if len(resp.History) != 2 || resp.Sources[0].Last.Outcome != "partial" {
		t.Fatalf("history: %d, last %s", len(resp.History), resp.Sources[0].Last.Outcome)
	}
	var alerts []store.Alert
	e.api("GET", "/api/alerts?open=1", tokViewer, nil, &alerts)
	kinds := []string{}
	for _, a := range alerts {
		kinds = append(kinds, a.Kind)
	}
	if !strings.Contains(strings.Join(kinds, ","), "acquisition_partial") || !strings.Contains(strings.Join(kinds, ","), "acquisition_status_rejected") {
		t.Fatalf("alerts: %v", kinds)
	}

	// Silence for > 26 h → stale + alert.
	real := e.st.Now
	e.st.Now = func() time.Time { return real().Add(30 * time.Hour) }
	e.st.SweepAlerts(context.Background(), store.DefaultThresholds)
	e.api("GET", "/api/acquisition", tokViewer, nil, &resp)
	e.st.Now = real
	if !resp.Sources[0].Stale {
		t.Fatal("acquisition should be stale after 30 h of silence")
	}

	// Server details.
	var sys map[string]any
	if c := e.api("GET", "/api/system", tokViewer, nil, &sys); c != 200 {
		t.Fatalf("system: %d", c)
	}
	tr := sys["trust"].(map[string]any)
	if len(tr["bundle_keys"].([]any)) != 1 || sys["version"] == "" || sys["security"].(map[string]any)["insecure_http"] != true {
		t.Fatalf("system: %+v", sys)
	}
	if b, _ := json.Marshal(sys); strings.Contains(string(b), tokViewer) || strings.Contains(string(b), "token_sha256") {
		t.Fatal("system details must not expose tokens")
	}
}
