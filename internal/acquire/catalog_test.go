package acquire

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"offpatch/internal/acquire/acquiretest"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseSearch(t *testing.T) {
	res, err := ParseSearch(fixture(t, "search-KB5126657.html"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Updates) != 6 {
		t.Fatalf("got %d rows, want 6", len(res.Updates))
	}
	var row *Update
	for i := range res.Updates {
		if res.Updates[i].ID == acquiretest.UpdateID {
			row = &res.Updates[i]
		}
	}
	if row == nil {
		t.Fatal("row ac395651 not found")
	}
	want := Update{
		ID: acquiretest.UpdateID, Title: acquiretest.Title,
		Products: "Windows 10, version 1903 and later", Classification: "Security Updates",
		LastUpdated: "10/13/2026", Version: "", Size: "1179.1 MB", SizeBytes: 1236404149,
	}
	if *row != want {
		t.Fatalf("row:\n got %+v\nwant %+v", *row, want)
	}
	if row.KB() != "KB5126657" {
		t.Fatalf("KB() = %q", row.KB())
	}
	if d, _ := row.ReleaseDate(); d != "2026-10-13" {
		t.Fatalf("ReleaseDate = %q", d)
	}
}

func TestParseSearchNoResultsAndGarbage(t *testing.T) {
	res, err := ParseSearch(fixture(t, "search-noresults.html"))
	if err != nil || len(res.Updates) != 0 {
		t.Fatalf("no-results page: %v %+v", err, res)
	}
	if _, err := ParseSearch([]byte("<html><body>Service unavailable</body></html>")); !errors.Is(err, ErrPageFormat) {
		t.Fatalf("garbage page: want ErrPageFormat, got %v", err)
	}
}

func TestPickUpdate(t *testing.T) {
	res, err := ParseSearch(fixture(t, "search-KB5126657.html"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		product, arch, wantID, wantErr string
	}{
		{"Windows 10 Version 22H2", "x64", acquiretest.UpdateID, ""},
		{"windows 10 version 22h2", "x86", "ee0732a6-81ab-4d93-bff3-e985d6b3612a", ""},
		{"Windows 10 Version 21H2", "arm64", "4909d92c-b704-4e96-aa71-b979e1b57314", ""},
		{"Windows 10", "x64", "", "2 catalog rows match"},
		{"Windows 11", "x64", "", "no catalog row matches"},
	}
	for _, c := range cases {
		u, err := PickUpdate(res.Updates, PickOptions{KB: "KB5126657", Product: c.product, Arch: c.arch})
		if c.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("%s/%s: want error %q, got %v", c.product, c.arch, c.wantErr, err)
			}
			if err != nil && !strings.Contains(err.Error(), "Windows 10 Version") {
				t.Errorf("%s/%s: error should list candidates: %v", c.product, c.arch, err)
			}
			continue
		}
		if err != nil || u.ID != c.wantID {
			t.Errorf("%s/%s: got %s %v, want %s", c.product, c.arch, u.ID, err, c.wantID)
		}
	}
	// -match disambiguates.
	if u, err := PickUpdate(res.Updates, PickOptions{KB: "KB5126657", Product: "Windows 10", Arch: "x64", Match: "22H2"}); err != nil || u.ID != acquiretest.UpdateID {
		t.Fatalf("match: %v %v", u.ID, err)
	}
	// Wrong KB yields nothing.
	if _, err := PickUpdate(res.Updates, PickOptions{KB: "KB1234567", Product: "Windows 10 Version 22H2", Arch: "x64"}); err == nil {
		t.Fatal("expected no match for other KB")
	}
}

func TestParseDownloadDialog(t *testing.T) {
	files, err := ParseDownloadDialog(fixture(t, "downloaddialog-ac395651.html"), acquiretest.UpdateID)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("files = %d", len(files))
	}
	f := files[0]
	if f.FileName != "windows10.0-kb5126657-x64_6ea46ad975176d6c6e9dcc79859d67c5193d6fc0.msu" ||
		f.URL != "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2026/10/"+f.FileName ||
		f.SHA1 != "6ea46ad975176d6c6e9dcc79859d67c5193d6fc0" || f.SHA256 != "" {
		t.Fatalf("file = %+v", f)
	}
	if _, err := ParseDownloadDialog(fixture(t, "downloaddialog-ac395651.html"), "95498edf-5b3a-42f3-9f39-b220d4c08e80"); err == nil {
		t.Fatal("dialog for a different update id must be rejected")
	}
	// Digest that disagrees with the file name hash is rejected.
	bad := strings.Replace(string(fixture(t, "downloaddialog-ac395651.html")), "bqRq2XUXbWxuncx5hZ1nxRk9b8A=", "AAAAAAAAAAAAAAAAAAAAAAAAAAA=", 1)
	if _, err := ParseDownloadDialog([]byte(bad), acquiretest.UpdateID); err == nil || !strings.Contains(err.Error(), "disagrees") {
		t.Fatalf("want digest disagreement error, got %v", err)
	}
	// Plain-HTTP catalog content URLs are upgraded to HTTPS.
	http := strings.ReplaceAll(string(fixture(t, "downloaddialog-ac395651.html")), "https://catalog.s.download", "http://catalog.s.download")
	files, err = ParseDownloadDialog([]byte(http), acquiretest.UpdateID)
	if err != nil || !strings.HasPrefix(files[0].URL, "https://") {
		t.Fatalf("http upgrade: %v %v", files, err)
	}
}

func TestParseDetails(t *testing.T) {
	d, err := ParseDetails(fixture(t, "details-ac395651.html"))
	if err != nil {
		t.Fatal(err)
	}
	if d.UpdateID != acquiretest.UpdateID || d.Title != acquiretest.Title || d.MSRCSeverity != "critical" {
		t.Fatalf("details = %+v", d)
	}
	has := map[string]bool{}
	for _, kb := range d.Supersedes {
		has[kb] = true
	}
	for _, kb := range []string{"KB5129236", "KB5120249", "KB5094127", "KB5074976"} {
		if !has[kb] {
			t.Errorf("supersedes missing %s: %v", kb, d.Supersedes)
		}
	}
	if has["KB5126657"] {
		t.Error("supersedes must not include the update's own KB")
	}
	if len(d.SupersededBy) != 0 {
		t.Errorf("superseded_by = %v, want none", d.SupersededBy)
	}
}

func TestCatalogClientAgainstFake(t *testing.T) {
	srv := acquiretest.New(t, "testdata", acquiretest.Payload(1000))
	c := &Catalog{BaseURL: srv.URL, HTTP: srv.Client()}
	ctx := context.Background()
	res, err := c.Search(ctx, "KB5126657")
	if err != nil || len(res.Updates) != 6 {
		t.Fatalf("search: %v", err)
	}
	files, err := c.DownloadLinks(ctx, acquiretest.UpdateID)
	if err != nil || len(files) != 1 || files[0].FileName != srv.FileName {
		t.Fatalf("links: %+v %v", files, err)
	}
	if want := `[{"size":0,"languages":"","uidInfo":"` + acquiretest.UpdateID + `","updateID":"` + acquiretest.UpdateID + `"}]`; srv.DialogForm != want {
		t.Fatalf("dialog form = %s", srv.DialogForm)
	}
	if _, err := c.Details(ctx, acquiretest.UpdateID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Details(ctx, "not-a-guid"); err == nil {
		t.Fatal("invalid guid accepted")
	}
}
