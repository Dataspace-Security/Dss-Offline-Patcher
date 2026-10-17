package e2e

import (
	"testing"
	"time"

	"offpatch/internal/agent"
	"offpatch/internal/store"
)

// A heartbeat keeps an endpoint "seen" while a long installer blocks the
// agent's check-in cycle; it needs the agent's client certificate.
func TestAgentHeartbeat(t *testing.T) {
	e := newEnvOpts(t, true, "")
	a := e.enroll("pc-hb-01", []string{"pilot"}, agent.SimConfig{})
	e.cycle(a)

	past := time.Now().Add(-2 * time.Hour).UTC()
	e.st.Now = func() time.Time { return past }
	if err := e.st.Heartbeat(t.Context(), a.id); err != nil {
		t.Fatal(err)
	}
	e.st.Now = time.Now
	before := e.lastSeen(a.id)

	if c := status(t, e.hc, "POST", e.srv.URL+"/api/agent/heartbeat"); c != 401 {
		t.Fatalf("heartbeat without client certificate: %d, want 401", c)
	}
	if c := status(t, e.clientFor(a), "POST", e.srv.URL+"/api/agent/heartbeat"); c != 204 {
		t.Fatalf("heartbeat: %d, want 204", c)
	}
	if after := e.lastSeen(a.id); !after.After(before.Add(time.Hour)) {
		t.Fatalf("last_seen not refreshed: before %v after %v", before, after)
	}
	if err := e.st.Heartbeat(t.Context(), "e-unknown"); err != store.ErrNotFound {
		t.Fatalf("unknown endpoint: %v, want ErrNotFound", err)
	}
}

func (e *env) lastSeen(id string) time.Time {
	e.t.Helper()
	var ep store.Endpoint
	if c := e.api("GET", "/api/endpoints/"+id, tokViewer, nil, &ep); c != 200 {
		e.t.Fatalf("get endpoint: %d", c)
	}
	ts, err := time.Parse(time.RFC3339Nano, ep.LastSeen)
	if err != nil {
		e.t.Fatalf("last_seen %q: %v", ep.LastSeen, err)
	}
	return ts
}
