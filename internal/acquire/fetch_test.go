package acquire

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"offpatch/internal/acquire/acquiretest"
)

func readSpec(t *testing.T, path string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("spec not valid JSON: %v\n%s", err, b)
	}
	return out
}

func TestSpecUpsert(t *testing.T) {
	dir := t.TempDir()
	spec := filepath.Join(dir, "spec.json")
	// Existing hand-written entry with a field this package doesn't know.
	os.WriteFile(spec, []byte(`[{"package_id":"Keep-1","title":"keep","custom_note":"hand written","path":"x.msi"}]`), 0o640)

	e := SpecEntry{PackageID: "KB1-x64", Title: "first", Kind: "msu", KB: "KB1000001", Path: "a.msu"}
	if replaced, err := UpsertSpec(spec, e); err != nil || replaced {
		t.Fatalf("append: %v %v", replaced, err)
	}
	e.Title = "second"
	if replaced, err := UpsertSpec(spec, e); err != nil || !replaced {
		t.Fatalf("replace: %v %v", replaced, err)
	}
	got := readSpec(t, spec)
	if len(got) != 2 || got[0]["custom_note"] != "hand written" || got[1]["title"] != "second" {
		t.Fatalf("spec = %v", got)
	}
	if _, ok := got[1]["file"]; ok {
		t.Fatal(`entry must not contain "file"`)
	}
	if _, ok := got[1]["vendor_signature"]; ok {
		t.Fatal(`entry must not contain "vendor_signature" (pmctl build fills it)`)
	}
	if fi, _ := os.Stat(spec); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o640 { // no Unix modes on Windows
		t.Fatalf("mode changed to %v", fi.Mode().Perm())
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("temp files left: %v", ents)
	}
	// A corrupt spec is not overwritten.
	os.WriteFile(spec, []byte(`{"not":"an array"}`), 0o644)
	if _, err := UpsertSpec(spec, e); err == nil {
		t.Fatal("corrupt spec overwritten")
	}
}

func TestFetchKB(t *testing.T) {
	srv := acquiretest.New(t, "testdata", acquiretest.Payload(150_000))
	dir := t.TempDir()
	cat := &Catalog{BaseURL: srv.URL, HTTP: srv.Client()}
	ms := &MSRC{BaseURL: srv.URL, HTTP: srv.Client()}
	o := FetchKBOptions{
		KB: "KB5126657", Product: "Windows 10 Version 22H2", Arch: "x64", MinBuild: 19045, MaxBuild: 19045,
		MSRCMonth: "2026-Oct", OutDir: filepath.Join(dir, "downloads"), SpecPath: filepath.Join(dir, "spec.json"),
	}
	res, err := FetchKB(context.Background(), cat, ms, o)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Warnings) != 0 {
		t.Fatalf("warnings: %v", res.Warnings)
	}
	got := readSpec(t, o.SpecPath)
	if len(got) != 1 {
		t.Fatalf("spec = %v", got)
	}
	g := got[0]
	sum := sha256.Sum256(srv.Payload)
	checks := map[string]any{
		"package_id": "KB5126657-x64", "title": acquiretest.Title, "vendor": "Microsoft", "kind": "msu",
		"kb": "KB5126657", "severity": "critical", "release_date": "2026-10-13",
		"source_url": srv.URL + "/dl/" + srv.FileName, "path": "downloads/" + srv.FileName,
	}
	for k, v := range checks {
		if g[k] != v {
			t.Errorf("%s = %v, want %v", k, g[k], v)
		}
	}
	if _, ok := g["version"]; ok {
		t.Errorf("version should be omitted when catalog shows n/a")
	}
	if !reflect.DeepEqual(g["applicability"], map[string]any{"os": "windows", "arch": "x64", "min_build": 19045.0, "max_build": 19045.0}) {
		t.Errorf("applicability = %v", g["applicability"])
	}
	sup, _ := g["supersedes"].([]any)
	if len(sup) < 5 || sup[0] != "KB5120249" {
		t.Errorf("supersedes = %v", sup)
	}
	acq := g["acquired"].(map[string]any)
	if acq["sha256"] != hex.EncodeToString(sum[:]) || acq["verified"] != "sha1(catalog)+size(catalog)" || acq["catalog_update_id"] != acquiretest.UpdateID {
		t.Errorf("acquired = %v", acq)
	}

	// Explicit -severity wins; re-run replaces the entry and reuses the file.
	o.Severity, o.MSRCMonth = "low", ""
	res, err = FetchKB(context.Background(), cat, ms, o)
	if err != nil || !res.Replaced || !res.Download.Reused {
		t.Fatalf("rerun: %+v %v", res, err)
	}
	if got := readSpec(t, o.SpecPath); len(got) != 1 || got[0]["severity"] != "low" {
		t.Fatalf("spec after rerun = %v", got)
	}

	// No severity source except the catalog details: taken from there, with a warning.
	o.Severity = ""
	res, err = FetchKB(context.Background(), cat, ms, o)
	if err != nil || res.Entry.Severity != "critical" || len(res.Warnings) != 1 {
		t.Fatalf("catalog severity: %+v %v", res, err)
	}
}

func TestFetchKBErrors(t *testing.T) {
	srv := acquiretest.New(t, "testdata", acquiretest.Payload(1000))
	dir := t.TempDir()
	cat := &Catalog{BaseURL: srv.URL, HTTP: srv.Client()}
	base := FetchKBOptions{KB: "KB5126657", Product: "Windows 10", Arch: "x64", OutDir: dir, SpecPath: filepath.Join(dir, "spec.json")}
	if _, err := FetchKB(context.Background(), cat, nil, base); err == nil || !strings.Contains(err.Error(), "2 catalog rows match") {
		t.Fatalf("ambiguous: %v", err)
	}
	o := base
	o.KB = "KB5044273"
	if _, err := FetchKB(context.Background(), cat, nil, o); err == nil || !strings.Contains(err.Error(), "no results") {
		t.Fatalf("no results: %v", err)
	}
	// Tampered download: rejected and nothing written to spec.
	srv.Served = acquiretest.Payload(999)
	srv.Served = append(srv.Served, 0)
	o = base
	o.Product = "Windows 10 Version 22H2"
	if _, err := FetchKB(context.Background(), cat, nil, o); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("tampered: %v", err)
	}
	if _, err := os.Stat(o.SpecPath); !os.IsNotExist(err) {
		t.Fatal("spec written despite hash mismatch")
	}
}

func TestFetchURL(t *testing.T) {
	srv := acquiretest.New(t, "testdata", acquiretest.Payload(1))
	msi := acquiretest.Payload(40_000)
	srv.Vendor["acme-agent-2.2.msi"] = msi
	sum := sha256.Sum256(msi)
	dir := t.TempDir()
	o := FetchURLOptions{
		URL: srv.URL + "/vendor/acme-agent-2.2.msi", SHA256: hex.EncodeToString(sum[:]),
		PackageID: "AcmeAgent-2.2", Title: "Acme Endpoint Agent 2.2", Vendor: "Acme", ProductCode: "{11111111-2222-3333-4444-555555555555}",
		Version: "2.2.0", Severity: "important", ReleaseDate: "2026-10-10",
		OutDir: filepath.Join(dir, "dl"), SpecPath: filepath.Join(dir, "spec.json"), HTTP: srv.Client(),
	}

	// Hash mismatch is rejected; nothing is kept.
	bad := o
	bad.SHA256 = strings.Repeat("0", 64)
	if _, err := FetchURL(context.Background(), bad); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("want mismatch, got %v", err)
	}
	if ents, _ := os.ReadDir(o.OutDir); len(ents) != 0 {
		t.Fatalf("files left: %v", ents)
	}
	if _, err := os.Stat(o.SpecPath); !os.IsNotExist(err) {
		t.Fatal("spec written despite mismatch")
	}
	// Refusals before download.
	for name, mut := range map[string]func(*FetchURLOptions){
		"http":         func(x *FetchURLOptions) { x.URL = strings.Replace(x.URL, "https", "http", 1) },
		"no sha256":    func(x *FetchURLOptions) { x.SHA256 = "" },
		"no product":   func(x *FetchURLOptions) { x.ProductCode = "" },
		"bad severity": func(x *FetchURLOptions) { x.Severity = "urgent" },
	} {
		x := o
		mut(&x)
		if _, err := FetchURL(context.Background(), x); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	res, err := FetchURL(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if res.Entry.Kind != "msi" || res.Entry.Applicability.Arch != "any" || res.Entry.Path != "dl/acme-agent-2.2.msi" {
		t.Fatalf("entry = %+v", res.Entry)
	}
}
