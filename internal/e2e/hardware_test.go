package e2e

import (
	"context"
	"testing"

	"offpatch/internal/agent"
	"offpatch/internal/store"
)

// Agents report a hardware snapshot on check-in; the console reads it back
// from the endpoint, and a check-in without one (older agent) keeps it.
func TestHardwareReported(t *testing.T) {
	e := newEnv(t)
	a := e.enroll("hw-pc-01", []string{"pilot"}, agent.SimConfig{})
	e.cycle(a)
	var ep store.EndpointDetail
	if c := e.api("GET", "/api/endpoints/"+a.id, tokViewer, nil, &ep); c != 200 {
		t.Fatalf("get endpoint %d", c)
	}
	h := ep.Hardware
	if h.Model == "" || h.MemoryBytes <= 0 || h.CPUCores <= 0 || len(h.Disks) != 1 || h.Disks[0].TotalBytes <= 0 || h.SerialNumber == "" {
		t.Fatalf("hardware not stored: %+v", h)
	}
	// An agent without hardware support sends no "hardware": keep the old value.
	if _, err := e.st.Checkin(context.Background(), a.id, store.CheckinRequest{Hostname: "hw-pc-01", Arch: "x64", Inventory: []store.InventoryItem{}}); err != nil {
		t.Fatal(err)
	}
	var ep2 store.EndpointDetail
	e.api("GET", "/api/endpoints/"+a.id, tokViewer, nil, &ep2)
	if ep2.Hardware.SerialNumber != h.SerialNumber {
		t.Fatalf("hardware lost on a check-in without it: %+v", ep2.Hardware)
	}
}
