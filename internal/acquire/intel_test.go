package acquire

import (
	"archive/zip"
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The recorded search page lists KB5126657 for Windows 10 21H2/22H2 (x64,
// x86, ARM64) and the "Windows 10 LTSB" variants.
func TestNewestCU(t *testing.T) {
	page, err := os.ReadFile("testdata/search-KB5126657.html")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(page) }))
	defer srv.Close()
	cat := &Catalog{BaseURL: srv.URL, HTTP: srv.Client()}

	rels, warns := WindowsReleases(context.Background(), cat, []WindowsProduct{
		{Product: "Windows 10 Version 22H2", Build: 19045, Arch: "x64", Query: "q", Match: "Windows 10 Version 22H2 for x64"},
		{Product: "Windows 10 Version 22H2 ARM", Build: 19045, Arch: "arm64", Query: "q", Match: "windows 10 version 22h2 for arm64"},
		{Product: "Windows 11 Version 24H2", Build: 26100, Arch: "x64", Query: "q", Match: "windows 11 version 24h2 for x64"},
	})
	if len(rels) != 2 || len(warns) != 1 || !strings.Contains(warns[0], "Windows 11 Version 24H2") {
		t.Fatalf("releases=%+v warnings=%v", rels, warns)
	}
	x64 := rels[0]
	if x64.KB != "KB5126657" || x64.Build != 19045 || x64.ReleaseDate != "2026-10-13" || !strings.Contains(x64.Title, "x64-based") || x64.SizeMB < 1000 {
		t.Errorf("x64: %+v", x64)
	}
	if !strings.Contains(strings.ToLower(rels[1].Title), "arm64") {
		t.Errorf("arm64 picked %q", rels[1].Title)
	}

	// A pinned final KB of a build out of servicing must match exactly.
	rels, warns = WindowsReleases(context.Background(), cat, []WindowsProduct{
		{Product: "pinned", Build: 19045, Arch: "x64", Match: "windows 10 version 22h2 for x64", FinalKB: "KB5000000"},
	})
	if len(rels) != 0 || len(warns) != 1 {
		t.Errorf("wrong pinned KB accepted: %+v %v", rels, warns)
	}
}

func TestReadWingetIndex(t *testing.T) {
	allowInsecureIntelURL = true
	defer func() { allowInsecureIntelURL = false }()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "index.db")
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{
		`CREATE TABLE metadata(name TEXT PRIMARY KEY, value TEXT)`,
		`INSERT INTO metadata VALUES('majorVersion','2'),('lastwritetime','1792208300')`,
		`CREATE TABLE packages(rowid INTEGER PRIMARY KEY, id TEXT, name TEXT, moniker TEXT, latest_version TEXT, arp_min_version TEXT, arp_max_version TEXT, hash BLOB)`,
		`INSERT INTO packages VALUES(1,'Google.Chrome','Google Chrome',NULL,'155.0.8059.85',NULL,NULL,NULL),(2,'VideoLAN.VLC','VLC media player','vlc','3.0.24','3.0.0','3.0.24',NULL)`,
		`CREATE TABLE productcodes2(productcode TEXT, package INT)`,
		`INSERT INTO productcodes2 VALUES('{0228B730-26AA-39E9-B2E1-0FC0E3EA58C8}',1),('vlc media player',2)`,
		`CREATE TABLE norm_names2(norm_name TEXT, package INT)`,
		`INSERT INTO norm_names2 VALUES('googlechrome',1),('vlcmediaplayer',2),('vlcmediaplayer(X64)',2)`,
		`CREATE TABLE norm_publishers2(norm_publisher TEXT, package INT)`,
		`INSERT INTO norm_publishers2 VALUES('google',1),('videolan',2)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	// Serve it the way winget does: Public/index.db inside an .msix (zip).
	msix := filepath.Join(dir, "source2.msix")
	f, _ := os.Create(msix)
	zw := zip.NewWriter(f)
	w, _ := zw.Create("Public/index.db")
	b, _ := os.ReadFile(dbPath)
	w.Write(b)
	zw.Close()
	f.Close()
	body, _ := os.ReadFile(msix)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(body) }))
	defer srv.Close()

	apps, src, err := WingetApps(context.Background(), srv.Client(), srv.URL+"/source2.msix", filepath.Join(dir, "work"))
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 2 || !strings.HasPrefix(src, "winget source2 (2026-") {
		t.Fatalf("apps=%+v src=%q", apps, src)
	}
	chrome, vlc := apps[0], apps[1]
	if chrome.ID != "Google.Chrome" || chrome.Version != "155.0.8059.85" || len(chrome.Codes) != 1 || chrome.Codes[0] != "{0228b730-26aa-39e9-b2e1-0fc0e3ea58c8}" || chrome.Publishers[0] != "google" {
		t.Errorf("chrome: %+v", chrome)
	}
	if vlc.ARPMax != "3.0.24" || len(vlc.Names) != 2 {
		t.Errorf("vlc: %+v", vlc)
	}

	srvBad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "nope", 404) }))
	defer srvBad.Close()
	if _, _, err := WingetApps(context.Background(), srvBad.Client(), srvBad.URL, filepath.Join(dir, "work2")); err == nil {
		t.Error("HTTP 404 accepted")
	}
}

func TestWingetRequiresHTTPS(t *testing.T) {
	if _, _, err := WingetApps(context.Background(), nil, "http://cdn.example/source2.msix", t.TempDir()); err == nil || !strings.Contains(err.Error(), "must be https") {
		t.Fatalf("plain http accepted: %v", err)
	}
}
