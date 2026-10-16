//go:build live

package acquire

// Live smoke test against the real Microsoft endpoints (connected zone only):
//
//	go test -tags live -run Live -v ./internal/acquire/
//
// It never downloads a payload: it only checks that the pages still parse and
// that the advertised download URL answers a HEAD with the catalog's size.

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestLiveCatalogAndMSRC(t *testing.T) {
	kb := os.Getenv("LIVE_KB")
	if kb == "" {
		kb = "KB5126657"
	}
	product := os.Getenv("LIVE_PRODUCT")
	if product == "" {
		product = "Windows 10 Version 22H2"
	}
	month := os.Getenv("LIVE_MONTH")
	if month == "" {
		month = "2026-Oct"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cat := NewCatalog()
	sr, err := cat.Search(ctx, kb)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("search %s: %d rows (%s)", kb, len(sr.Updates), sr.Summary)
	u, err := PickUpdate(sr.Updates, PickOptions{KB: kb, Product: product, Arch: "x64"})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("picked %s %s size=%d date=%s", u.ID, u.Title, u.SizeBytes, u.LastUpdated)
	files, err := cat.DownloadLinks(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		t.Logf("file %s sha1=%s sha256=%s url=%s", f.FileName, f.SHA1, f.SHA256, f.URL)
	}
	d, err := cat.Details(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("details severity=%s supersedes=%d superseded_by=%v", d.MSRCSeverity, len(d.Supersedes), d.SupersededBy)

	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, files[0].URL, nil)
	resp, err := DefaultHTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	t.Logf("HEAD %d content-length=%d accept-ranges=%s", resp.StatusCode, resp.ContentLength, resp.Header.Get("Accept-Ranges"))
	if len(files) == 1 && u.SizeBytes > 0 && resp.ContentLength != u.SizeBytes {
		t.Errorf("catalog size %d != content-length %d", u.SizeBytes, resp.ContentLength)
	}

	list, err := NewMSRC().Month(ctx, month)
	if err != nil {
		t.Fatal(err)
	}
	su, ok := FindKB(list, kb)
	t.Logf("msrc %s: %d KBs; %s present=%v", month, len(list), kb, ok)
	if ok {
		s, _ := su.ForProduct(product, "x64")
		t.Logf("msrc %s for %q x64: severity=%s cves=%d products=%v", kb, product, s.Severity, len(s.CVEs), s.Products)
	}
}
