package server

import (
	"strings"
	"testing"
	"time"

	"offpatch/internal/store"
)

func TestProgressMapExpiry(t *testing.T) {
	clock := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	pm := newProgressMap()
	pm.now = func() time.Time { return clock }
	p := heartbeatProgress{DeploymentID: "d-1", PackageID: "KB1-x64", Stage: "downloading", Pct: 40, BytesDone: 40, BytesTotal: 100}
	pm.put("e-1", p)
	tgt := store.Target{DeploymentID: "d-1", EndpointID: "e-1", PackageID: "KB1-x64", State: "downloading"}

	if l := pm.get(tgt); l == nil || l.Pct != 40 || l.Stage != "downloading" || l.At != clock.Format(time.RFC3339) {
		t.Fatalf("live: %+v", l)
	}
	// Pending (the agent has not reported downloading yet): kept, not shown.
	tgt.State = "pending"
	if l := pm.get(tgt); l != nil || pm.len() != 1 {
		t.Fatalf("pending: %+v (%d entries)", l, pm.len())
	}
	// Another package for the same deployment id: not this target's progress.
	if l := pm.get(store.Target{DeploymentID: "d-1", EndpointID: "e-1", PackageID: "other", State: "installing"}); l != nil {
		t.Fatalf("wrong package: %+v", l)
	}
	// Leaving the live states drops the entry.
	pm.put("e-1", p)
	tgt.State = "verified"
	if l := pm.get(tgt); l != nil || pm.len() != 0 {
		t.Fatalf("verified: %+v (%d entries)", l, pm.len())
	}
	// Older than 10 minutes: dropped.
	pm.put("e-1", p)
	clock = clock.Add(progressTTL + time.Second)
	tgt.State = "installing"
	if l := pm.get(tgt); l != nil || pm.len() != 0 {
		t.Fatalf("expired: %+v", l)
	}
	// put sweeps expired entries of other targets.
	pm.put("e-2", p)
	clock = clock.Add(progressTTL + progressSweepEvery)
	pm.put("e-3", p)
	if pm.len() != 1 {
		t.Fatalf("sweep: %d entries", pm.len())
	}
}

func TestHeartbeatProgressValidate(t *testing.T) {
	ok := heartbeatProgress{DeploymentID: "d-1", PackageID: "p", Stage: "installing", Pct: -1}
	if err := ok.validate(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*heartbeatProgress){
		"stage":    func(p *heartbeatProgress) { p.Stage = "running" },
		"pct low":  func(p *heartbeatProgress) { p.Pct = -2 },
		"pct high": func(p *heartbeatProgress) { p.Pct = 101 },
		"bytes":    func(p *heartbeatProgress) { p.BytesDone = -1 },
		"total":    func(p *heartbeatProgress) { p.BytesTotal = -1 },
		"no dep":   func(p *heartbeatProgress) { p.DeploymentID = "" },
		"long id":  func(p *heartbeatProgress) { p.PackageID = strings.Repeat("x", 129) },
	} {
		p := ok
		mut(&p)
		if p.validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestEndpointStatusPrecedence(t *testing.T) {
	all := store.TargetStatus{Exception: true, Failed: true, Deploying: true, Verified: true}
	for _, c := range []struct {
		st       store.TargetStatus
		outdated bool
		want     string
	}{
		{all, true, "exception"},
		{store.TargetStatus{Failed: true, Deploying: true, Verified: true}, true, "failed"},
		{store.TargetStatus{Deploying: true, Verified: true}, false, "being_patched"},
		{store.TargetStatus{Verified: true}, true, "verified"},
		{store.TargetStatus{}, true, "outdated"},
		{store.TargetStatus{}, false, "up_to_date"},
	} {
		if got := endpointStatus(c.st, c.outdated); got != c.want {
			t.Errorf("%+v outdated=%v: %s, want %s", c.st, c.outdated, got, c.want)
		}
	}
}
