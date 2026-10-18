package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"offpatch/internal/acqrequest"
	"offpatch/internal/agent"
	"offpatch/internal/intel"
	"offpatch/internal/store"
)

// withoutQueuedTo checks the response's queued_to and returns the document
// without it (what the console saves as the carried file).
func withoutQueuedTo(t *testing.T, raw json.RawMessage, want string) json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	q, ok := m["queued_to"]
	if !ok {
		t.Fatalf("response has no queued_to: %s", raw)
	}
	var got string
	json.Unmarshal(q, &got)
	if got != want {
		t.Fatalf("queued_to = %q, want %q", got, want)
	}
	delete(m, "queued_to")
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func queueEnv(t *testing.T, dir string) *env {
	t.Helper()
	p, _ := json.Marshal(dir)
	e := newEnvOpts(t, false, `"acquisition_requests_dir": `+string(p)+`,`)
	a := e.enroll("pc-q-01", []string{"pilot"}, agent.SimConfig{})
	if _, err := e.st.Checkin(context.Background(), a.id, store.CheckinRequest{
		Hostname: "pc-q-01", OSVersion: "Windows 11 Pro 21H2 (22000.2538)", Build: 22000, Arch: "x64",
		Inventory: []store.InventoryItem{{Kind: "product", ID: "{0228B730-26AA-39E9-B2E1-0FC0E3EA58C8}", Name: "Google Chrome", Version: "155.0.8059.82"}},
	}); err != nil {
		t.Fatal(err)
	}
	e.dropIntel(intel.Doc{Source: "acq-zone-1", GeneratedAt: time.Now().UTC().Add(-time.Hour).Truncate(time.Second).Format(time.RFC3339),
		Apps: []intel.App{{ID: "Google.Chrome", Name: "Google Chrome", Version: "155.0.8059.85", Codes: []string{"{0228b730-26aa-39e9-b2e1-0fc0e3ea58c8}"}}}},
		e.priv, "intel-q")
	return e
}

func exportAudit(t *testing.T, e *env, id string) map[string]any {
	t.Helper()
	var audit []store.AuditEvent
	e.api("GET", "/api/audit", tokViewer, nil, &audit)
	for _, ev := range audit {
		if ev.Action == "acquisition.request_exported" && ev.ObjectID == id {
			var d map[string]any
			json.Unmarshal(ev.Details, &d)
			return d
		}
	}
	t.Fatalf("export %s not audited", id)
	return nil
}

// acquisition_requests_dir set: the request is also written there, as the
// exact document pmctl parses, and the response/audit say where.
func TestAcquisitionRequestQueuedDirect(t *testing.T) {
	dir := t.TempDir()
	e := queueEnv(t, dir)
	var raw json.RawMessage
	if c := e.api("POST", "/api/acquisition-requests", tokOperator, map[string]any{"apps": []string{"Google.Chrome"}}, &raw); c != 200 {
		t.Fatalf("export: %d", c)
	}
	doc := withoutQueuedTo(t, raw, dir)
	resp, err := acqrequest.Parse(bytes.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, resp.RequestID+".json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("not queued: %v", err)
	}
	queued, err := acqrequest.Parse(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("queued file does not parse: %v\n%s", err, b)
	}
	qj, _ := json.Marshal(queued)
	rj, _ := json.Marshal(resp)
	if !bytes.Equal(qj, rj) {
		t.Errorf("queued file differs from the response document:\n%s\n%s", qj, rj)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(path); st.Mode().Perm() != 0o640 {
			t.Errorf("mode %v, want 0640", st.Mode().Perm())
		}
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Errorf("temp files left behind: %v", ents)
	}
	if d := exportAudit(t, e, resp.RequestID); d["queued_to"] != dir || d["queued_error"] != nil {
		t.Errorf("audit details: %v", d)
	}
}

// A failed write still returns the document (the operator carries it) and
// is audited with the error.
func TestAcquisitionRequestQueueFailure(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "requests")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	e := queueEnv(t, dir)
	os.Remove(dir) // gone after startup
	var raw json.RawMessage
	if c := e.api("POST", "/api/acquisition-requests", tokOperator, map[string]any{"apps": []string{"Google.Chrome"}}, &raw); c != 200 {
		t.Fatalf("export: %d", c)
	}
	resp, err := acqrequest.Parse(bytes.NewReader(withoutQueuedTo(t, raw, "")))
	if err != nil {
		t.Fatal(err)
	}
	d := exportAudit(t, e, resp.RequestID)
	if d["queued_to"] != "" || !strings.Contains(d["queued_error"].(string), "requests") {
		t.Errorf("audit details: %v", d)
	}
}
