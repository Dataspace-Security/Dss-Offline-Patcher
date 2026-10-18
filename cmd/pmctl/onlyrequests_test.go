package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"offpatch/internal/acqrequest"
	"offpatch/internal/acquire/acquiretest"
)

// pmctl auto -only-requests (the role-all request watcher): only the queued
// acquisition requests are handled; Microsoft and the configured apps are
// not fetched, the bundle and the status report are sent as usual, and the
// run lock still applies.
func TestAutoOnlyRequests(t *testing.T) {
	e := newAutoEnv(t, `"requests": "requests",`)
	ctx := context.Background()
	reqDir := filepath.Join(e.dir, "requests")
	writeRequest(t, reqDir, "acq-request-9.json", acqrequest.Request{
		KBs: []acqrequest.KB{{KB: acquiretest.KB, Product: "Windows 10 Version 22H2", Title: acquiretest.Title, Build: 19045, Arch: "x64", Endpoints: 1}},
	})

	// The lock is honoured: a run in progress refuses a second one.
	work := filepath.Join(e.dir, "work")
	os.MkdirAll(work, 0o750)
	unlock, err := acquireLock(work, defaultRunTimeout)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runAutoRequests(ctx, e.cfgPath, false, "", true); err == nil || !strings.Contains(err.Error(), "in progress") {
		t.Fatalf("lock not honoured: %v", err)
	}
	unlock()

	rep, err := runAutoRequests(ctx, e.cfgPath, false, "", true)
	if err != nil || !rep.Sent || len(rep.Failures) != 0 {
		t.Fatalf("run: %v %+v", err, rep)
	}
	if len(rep.New) != 1 || rep.New[0] != acquiretest.KB+"-x64" {
		t.Fatalf("new: %v (apps/Microsoft must not be fetched)", rep.New)
	}
	if slices.ContainsFunc(rep.New, func(id string) bool { return strings.HasPrefix(id, "acme-agent") }) {
		t.Errorf("configured app fetched: %v", rep.New)
	}
	for _, f := range rep.Feeds {
		if f.Type != "request" {
			t.Errorf("unexpected %s feed %s in a requests-only run", f.Type, f.Name)
		}
	}
	if !rep.StatusSent {
		t.Error("status report not sent")
	}
	if !strings.Contains(strings.Join(rep.Warnings, "\n"), "requests-only run") {
		t.Errorf("warnings: %v", rep.Warnings)
	}
	if _, err := os.Stat(filepath.Join(reqDir, "done", "acq-request-9.json")); err != nil {
		t.Errorf("request not archived: %v", err)
	}
	if bundles, _ := filepath.Glob(filepath.Join(e.drop, "*.pmb")); len(bundles) != 1 {
		t.Errorf("bundles: %v", bundles)
	}

	// Nothing pending: a quick, successful no-op.
	rep, err = runAutoRequests(ctx, e.cfgPath, false, "", true)
	if err != nil || rep.Sent || len(rep.New) != 0 || partialRun(&rep) {
		t.Fatalf("idle run: %v %+v", err, rep)
	}
}

func TestAutoOnlyRequestsNeedsRequestsDir(t *testing.T) {
	e := newAutoEnv(t, "")
	if _, err := runAutoRequests(context.Background(), e.cfgPath, false, "", true); err == nil || !strings.Contains(err.Error(), "-only-requests") {
		t.Fatalf("no requests dir: %v", err)
	}
}
