package acquire

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"offpatch/internal/acquire/acquiretest"
)

func noBackoff(t *testing.T) {
	t.Helper()
	old := RetryBackoff
	RetryBackoff = func(int) time.Duration { return time.Millisecond }
	t.Cleanup(func() { RetryBackoff = old })
}

// Windows 11 24H2+ download dialogs list the cumulative update together with
// its checkpoint update: both become packages, the checkpoint is a
// prerequisite of the CU, and it is never listed as superseded.
func TestFetchKBPackagesCheckpoint(t *testing.T) {
	srv := acquiretest.New(t, "testdata", acquiretest.Payload(50_000))
	srv.SetCheckpoint(acquiretest.Payload(30_000)[:29_999])
	dir := t.TempDir()
	cat := &Catalog{BaseURL: srv.URL, HTTP: srv.Client()}
	o := FetchKBOptions{KB: "KB5126657", Product: "Windows 10 Version 22H2", Arch: "x64", Severity: "critical",
		OutDir: filepath.Join(dir, "downloads"), SpecPath: filepath.Join(dir, "spec.json")}
	res, err := FetchKB(context.Background(), cat, nil, o)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.Entry.Prerequisites, []string{acquiretest.CheckpointKB}) {
		t.Fatalf("prerequisites = %v", res.Entry.Prerequisites)
	}
	if slices.Contains(res.Entry.Supersedes, acquiretest.CheckpointKB) {
		t.Fatal("checkpoint listed as superseded")
	}
	if len(res.Prerequisites) != 1 || res.Prerequisites[0].PackageID != acquiretest.CheckpointKB+"-x64" || res.Prerequisites[0].KB != acquiretest.CheckpointKB {
		t.Fatalf("checkpoint packages = %+v", res.Prerequisites)
	}
	spec := readSpec(t, o.SpecPath)
	if len(spec) != 2 || spec[0]["package_id"] != acquiretest.CheckpointKB+"-x64" || spec[1]["package_id"] != "KB5126657-x64" {
		t.Fatalf("spec = %v", spec)
	}
	if _, err := os.Stat(filepath.Join(o.OutDir, srv.CheckpointName)); err != nil {
		t.Fatalf("checkpoint not downloaded: %v", err)
	}

	// Delivered earlier: not downloaded or written again, still a prerequisite.
	os.Remove(o.SpecPath)
	o.SkipPrerequisite = func(id string) bool { return id == acquiretest.CheckpointKB+"-x64" }
	res, err = FetchKB(context.Background(), cat, nil, o)
	if err != nil || len(res.Prerequisites) != 0 || len(res.SkippedPrerequisites) != 1 || len(res.Entry.Prerequisites) != 1 {
		t.Fatalf("skip: %v %+v", err, res)
	}
	if spec := readSpec(t, o.SpecPath); len(spec) != 1 {
		t.Fatalf("spec = %v", spec)
	}
}

// Same file name, new content (unversioned vendor URL): the stale file is
// replaced instead of failing on every run.
func TestDownloadReplacesStaleFile(t *testing.T) {
	srv := acquiretest.New(t, "testdata", acquiretest.Payload(20_000))
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, srv.FileName), []byte("old build with the same name"), 0o644)
	res, err := Download(context.Background(), srv.Client(), catalogReq(srv, dir))
	if err != nil || !res.ReplacedStale || res.Size != 20_000 {
		t.Fatalf("stale file not replaced: %+v %v", res, err)
	}
}

// A .part that does not fit what the server now serves is deleted, so the
// next run starts over instead of failing forever.
func TestDownloadDropsMismatchedPart(t *testing.T) {
	srv := acquiretest.New(t, "testdata", acquiretest.Payload(20_000))
	srv.Served = append(acquiretest.Payload(20_000), make([]byte, 100)...)
	dir := t.TempDir()
	part := filepath.Join(dir, srv.FileName+".part")
	os.WriteFile(part, srv.Payload[:5_000], 0o644)
	if _, err := Download(context.Background(), srv.Client(), catalogReq(srv, dir)); err == nil || !strings.Contains(err.Error(), "expected 20000") {
		t.Fatalf("want size error, got %v", err)
	}
	if _, err := os.Stat(part); !os.IsNotExist(err) {
		t.Fatal("mismatched .part kept")
	}
}

// Catalog and MSRC requests are retried on 5xx; a 404 is not retried and is
// recognisable (the current month 404s until Patch Tuesday).
func TestPageRequestsRetry(t *testing.T) {
	noBackoff(t)
	srv := acquiretest.New(t, "testdata", acquiretest.Payload(10))
	cat := &Catalog{BaseURL: srv.URL, HTTP: srv.Client()}
	ms := &MSRC{BaseURL: srv.URL, HTTP: srv.Client()}
	srv.Fail5xx = 2
	if _, err := cat.Search(context.Background(), "KB5126657"); err != nil {
		t.Fatalf("two 503s then success should pass: %v", err)
	}
	srv.Fail5xx = 3
	if _, err := ms.Month(context.Background(), "2026-Oct"); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("three 503s should fail: %v", err)
	}
	_, err := ms.Month(context.Background(), "2026-Nov")
	if !IsNotFound(err) {
		t.Fatalf("404 not recognised: %v", err)
	}
	if IsNotFound(nil) {
		t.Fatal("nil is not a 404")
	}
}
