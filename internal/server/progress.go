package server

import (
	"errors"
	"sync"
	"time"

	"offpatch/internal/store"
)

// Live progress of downloads and installs, from agent heartbeats. Kept in
// memory only (not in SQLite, not audited): it is a display aid, and the
// audited state transitions still come from /api/agent/report.

const (
	heartbeatMaxBody = 16 << 10
	progressTTL      = 10 * time.Minute
	maxProgressID    = 128
	// progressSweepEvery bounds how often put() drops expired entries.
	progressSweepEvery = time.Minute
)

var progressStages = map[string]bool{"downloading": true, "verifying": true, "installing": true, "waiting_reboot": true}

// liveStates: target states for which live progress is shown.
var liveStates = map[string]bool{"downloading": true, "downloaded": true, "installing": true, "pending_reboot": true}

type heartbeatBody struct {
	Progress *heartbeatProgress `json:"progress"`
}

type heartbeatProgress struct {
	DeploymentID string `json:"deployment_id"`
	PackageID    string `json:"package_id"`
	Stage        string `json:"stage"`
	Pct          int    `json:"pct"`
	BytesDone    int64  `json:"bytes_done"`
	BytesTotal   int64  `json:"bytes_total"`
}

func (p heartbeatProgress) validate() error {
	switch {
	case p.DeploymentID == "" || p.PackageID == "" || len(p.DeploymentID) > maxProgressID || len(p.PackageID) > maxProgressID:
		return errors.New("progress: deployment_id and package_id required (at most 128 characters)")
	case !progressStages[p.Stage]:
		return errors.New("progress: stage must be downloading, verifying, installing or waiting_reboot")
	case p.Pct < -1 || p.Pct > 100:
		return errors.New("progress: pct must be -1..100")
	case p.BytesDone < 0 || p.BytesTotal < 0:
		return errors.New("progress: sizes must be >= 0")
	}
	return nil
}

// targetLive is Target.live in GET /api/deployments/{id}.
type targetLive struct {
	Stage      string `json:"stage"`
	Pct        int    `json:"pct"`
	BytesDone  int64  `json:"bytes_done"`
	BytesTotal int64  `json:"bytes_total"`
	At         string `json:"at"`
}

type progressEntry struct {
	packageID string
	live      targetLive
	at        time.Time
}

type progressKey struct{ endpoint, deployment string }

type progressMap struct {
	mu        sync.Mutex
	m         map[progressKey]progressEntry
	now       func() time.Time
	lastSweep time.Time
}

func newProgressMap() *progressMap {
	return &progressMap{m: map[progressKey]progressEntry{}, now: time.Now}
}

func (pm *progressMap) put(endpointID string, p heartbeatProgress) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	now := pm.now()
	pm.m[progressKey{endpointID, p.DeploymentID}] = progressEntry{packageID: p.PackageID, at: now,
		live: targetLive{Stage: p.Stage, Pct: p.Pct, BytesDone: p.BytesDone, BytesTotal: p.BytesTotal, At: now.UTC().Format(time.RFC3339)}}
	pm.sweepLocked(now)
}

// sweepLocked drops expired entries, at most every progressSweepEvery (on
// writes and reads, so entries of agents that went silent do not linger).
// pm.mu must be held.
func (pm *progressMap) sweepLocked(now time.Time) {
	if now.Sub(pm.lastSweep) < progressSweepEvery {
		return
	}
	pm.lastSweep = now
	for k, e := range pm.m {
		if now.Sub(e.at) > progressTTL {
			delete(pm.m, k)
		}
	}
}

// get returns the live progress for a target in state, dropping entries that
// are too old or whose target is no longer downloading/installing/waiting
// for a reboot (a pending target keeps its entry: the agent may report the
// first state change after its first heartbeat).
func (pm *progressMap) get(t store.Target) *targetLive {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.sweepLocked(pm.now())
	k := progressKey{t.EndpointID, t.DeploymentID}
	e, ok := pm.m[k]
	if !ok {
		return nil
	}
	if pm.now().Sub(e.at) > progressTTL || e.packageID != t.PackageID || (!liveStates[t.State] && t.State != "pending") {
		delete(pm.m, k)
		return nil
	}
	if !liveStates[t.State] {
		return nil
	}
	l := e.live
	return &l
}

func (pm *progressMap) len() int {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return len(pm.m)
}

// targetView is a target with its live progress (null when none).
type targetView struct {
	store.Target
	Live *targetLive `json:"live"`
}

type deploymentView struct {
	store.Deployment
	Targets []targetView `json:"targets"`
}

func (s *Server) withLive(d store.DeploymentDetail) deploymentView {
	v := deploymentView{Deployment: d.Deployment, Targets: make([]targetView, 0, len(d.Targets))}
	for _, t := range d.Targets {
		v.Targets = append(v.Targets, targetView{Target: t, Live: s.progress.get(t)})
	}
	return v
}
