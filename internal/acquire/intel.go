package acquire

import (
	"archive/zip"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"offpatch/internal/intel"
)

// Update intelligence, acquisition side: the newest Windows cumulative update
// per build (Microsoft Update Catalog) and the newest version of Windows
// applications (winget community index). See internal/intel.

// DefaultWingetURL is the winget community source (index v2).
const DefaultWingetURL = "https://cdn.winget.microsoft.com/cache/source2.msix"

const maxWingetDownload = 200 << 20

// allowInsecureIntelURL lets tests serve the index over plain HTTP.
var allowInsecureIntelURL = false

// WindowsProduct is one Windows build whose newest cumulative update is tracked.
type WindowsProduct struct {
	Product string `json:"product"` // display name, e.g. "Windows 11 Version 24H2"
	Build   int    `json:"build"`
	Arch    string `json:"arch"`
	Server  bool   `json:"server,omitempty"`
	// Query is the catalog search; Match must appear in the (normalised) title.
	Query string `json:"query"`
	Match string `json:"match"`
	// FinalKB pins the last update of a build that is out of servicing, and
	// FinalUBR its build revision when the catalog title does not show it.
	FinalKB  string `json:"final_kb,omitempty"`
	FinalUBR int    `json:"final_ubr,omitempty"`
}

// DefaultWindowsProducts covers the Windows client and server builds in
// general use (x64).
func DefaultWindowsProducts() []WindowsProduct {
	client := func(ver string, build int) WindowsProduct {
		return WindowsProduct{Product: "Windows 11 Version " + ver, Build: build, Arch: "x64",
			Query: "Cumulative Update for Windows 11 Version " + ver + " x64", Match: "windows 11 version " + strings.ToLower(ver) + " for x64"}
	}
	return []WindowsProduct{
		{Product: "Windows 10 Version 22H2", Build: 19045, Arch: "x64", Query: "Cumulative Update for Windows 10 Version 22H2 x64", Match: "windows 10 version 22h2 for x64"},
		// Windows 11 21H2 left servicing in October 2024; its titles do not name the version.
		{Product: "Windows 11 Version 21H2", Build: 22000, Arch: "x64", Match: "windows 11 for x64", FinalKB: "KB5044280", FinalUBR: 3260},
		client("22H2", 22621), client("23H2", 22631), client("24H2", 26100), client("25H2", 26200), client("26H2", 26300),
		{Product: "Windows Server 2019", Build: 17763, Arch: "x64", Server: true, Query: "Cumulative Update for Windows Server 2019 x64", Match: "windows server 2019 for x64"},
		{Product: "Windows Server 2022", Build: 20348, Arch: "x64", Server: true, Query: "Cumulative Update for Microsoft server operating system version 21H2 x64", Match: "microsoft server operating system version 21h2 for x64"},
		{Product: "Windows Server 2025", Build: 26100, Arch: "x64", Server: true, Query: "Cumulative Update for Microsoft server operating system version 24H2 x64", Match: "microsoft server operating system version 24h2 for x64"},
	}
}

var (
	excludeCURe = regexp.MustCompile(`(?i)\b(dynamic|preview|\.net|framework|servicing stack)\b`)
	cuTitleRe   = regexp.MustCompile(`(?i)\bcumulative update for\b`)
	buildUBRRe  = regexp.MustCompile(`\((\d{5})\.(\d+)\)`)
)

// WindowsReleases finds the newest cumulative update for each product.
// Products that fail are reported as warnings so one catalog hiccup does not
// drop the whole document.
func WindowsReleases(ctx context.Context, cat *Catalog, products []WindowsProduct) ([]intel.WindowsRelease, []string) {
	var out []intel.WindowsRelease
	var warns []string
	for _, p := range products {
		r, err := newestCU(ctx, cat, p)
		if err != nil {
			warns = append(warns, fmt.Sprintf("%s: %v", p.Product, err))
			continue
		}
		out = append(out, r)
	}
	return out, warns
}

func newestCU(ctx context.Context, cat *Catalog, p WindowsProduct) (intel.WindowsRelease, error) {
	q := p.Query
	if p.FinalKB != "" {
		q = p.FinalKB
	}
	res, err := cat.Search(ctx, q)
	if err != nil {
		return intel.WindowsRelease{}, err
	}
	var best *Update
	var bestDate time.Time
	for i := range res.Updates {
		u := res.Updates[i]
		t := normTitle(u.Title)
		if !cuTitleRe.MatchString(u.Title) || excludeCURe.MatchString(u.Title) || !MatchesArch(u.Title, p.Arch) || !strings.Contains(t, normTitle(p.Match)) {
			continue
		}
		if p.FinalKB != "" && !strings.EqualFold(u.KB(), p.FinalKB) {
			continue
		}
		d, err := time.Parse("1/2/2006", u.LastUpdated)
		if err != nil {
			continue
		}
		if best == nil || d.After(bestDate) {
			best, bestDate = &u, d
		}
	}
	if best == nil {
		return intel.WindowsRelease{}, fmt.Errorf("no cumulative update found in the catalog for %q", q)
	}
	r := intel.WindowsRelease{Product: p.Product, Build: p.Build, Arch: p.Arch, Server: p.Server, KB: best.KB(), Title: best.Title,
		ReleaseDate: bestDate.Format("2006-01-02"), SizeMB: int(best.SizeBytes >> 20)}
	if m := buildUBRRe.FindStringSubmatch(best.Title); m != nil && m[1] == strconv.Itoa(p.Build) {
		r.UBR, _ = strconv.Atoi(m[2])
	}
	if r.UBR == 0 && p.FinalUBR > 0 {
		r.UBR = p.FinalUBR
	}
	if r.KB == "" {
		return intel.WindowsRelease{}, fmt.Errorf("no KB number in %q", best.Title)
	}
	return r, nil
}

// WingetApps downloads the winget community index and returns every package
// with its newest version, product codes / uninstall keys and normalised names.
func WingetApps(ctx context.Context, hc *http.Client, url, workDir string) ([]intel.App, string, error) {
	if url == "" {
		url = DefaultWingetURL
	}
	if !strings.HasPrefix(url, "https://") && !allowInsecureIntelURL {
		return nil, "", fmt.Errorf("winget index URL must be https: %s", url)
	}
	if hc == nil {
		hc = DefaultHTTPClient()
	}
	if err := os.MkdirAll(workDir, 0o750); err != nil {
		return nil, "", err
	}
	msix := filepath.Join(workDir, "winget-source2.msix")
	if err := fetchFile(ctx, hc, url, msix, maxWingetDownload); err != nil {
		return nil, "", fmt.Errorf("winget index: %w", err)
	}
	db := filepath.Join(workDir, "winget-index.db")
	if err := extractZipFile(msix, "Public/index.db", db, maxWingetDownload); err != nil {
		return nil, "", fmt.Errorf("winget index: %w", err)
	}
	defer os.Remove(db)
	return readWingetIndex(ctx, db)
}

func readWingetIndex(ctx context.Context, path string) ([]intel.App, string, error) {
	// Downloaded content: open read-only, immutable, without trusting the schema.
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=ro&immutable=1&_pragma=trusted_schema(0)&_pragma=query_only(1)")
	if err != nil {
		return nil, "", err
	}
	defer db.Close()
	var major, written string
	db.QueryRowContext(ctx, `SELECT value FROM metadata WHERE name='majorVersion'`).Scan(&major)
	db.QueryRowContext(ctx, `SELECT value FROM metadata WHERE name='lastwritetime'`).Scan(&written)
	if major != "2" {
		return nil, "", fmt.Errorf("winget index: schema major version %q, want 2", major)
	}
	rows, err := db.QueryContext(ctx, `SELECT rowid, id, name, latest_version, COALESCE(arp_min_version,''), COALESCE(arp_max_version,'') FROM packages`)
	if err != nil {
		return nil, "", fmt.Errorf("winget index: %w", err)
	}
	apps := map[int64]*intel.App{}
	var order []int64
	for rows.Next() {
		var id int64
		a := &intel.App{}
		if err := rows.Scan(&id, &a.ID, &a.Name, &a.Version, &a.ARPMin, &a.ARPMax); err != nil {
			rows.Close()
			return nil, "", err
		}
		apps[id] = a
		order = append(order, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	for table, set := range map[string]func(*intel.App, string){
		"productcodes2":    func(a *intel.App, v string) { a.Codes = append(a.Codes, strings.ToLower(v)) },
		"norm_names2":      func(a *intel.App, v string) { a.Names = append(a.Names, v) },
		"norm_publishers2": func(a *intel.App, v string) { a.Publishers = append(a.Publishers, v) },
	} {
		col := map[string]string{"productcodes2": "productcode", "norm_names2": "norm_name", "norm_publishers2": "norm_publisher"}[table]
		rs, err := db.QueryContext(ctx, `SELECT package, `+col+` FROM `+table)
		if err != nil {
			return nil, "", fmt.Errorf("winget index: %w", err)
		}
		for rs.Next() {
			var pkg int64
			var v string
			if err := rs.Scan(&pkg, &v); err != nil {
				rs.Close()
				return nil, "", err
			}
			if a := apps[pkg]; a != nil && v != "" {
				set(a, v)
			}
		}
		rs.Close()
		if err := rs.Err(); err != nil {
			return nil, "", err
		}
	}
	out := make([]intel.App, 0, len(order))
	for _, id := range order {
		a := apps[id]
		if a.ID == "" || a.Version == "" {
			continue
		}
		sort.Strings(a.Codes)
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	src := "winget source2"
	if sec, err := strconv.ParseInt(written, 10, 64); err == nil && sec > 0 {
		src += " (" + time.Unix(sec, 0).UTC().Format(time.RFC3339) + ")"
	}
	return out, src, nil
}

func fetchFile(ctx context.Context, hc *http.Client, url, dst string, max int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", DefaultUserAgent)
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(resp.Body, max+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > max {
		err = fmt.Errorf("GET %s: larger than %d bytes", url, max)
	}
	return err
}

func extractZipFile(zipPath, name, dst string, max int64) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name != name {
			continue
		}
		if int64(f.UncompressedSize64) > max {
			return fmt.Errorf("%s: larger than %d bytes", name, max)
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		out, err := os.Create(dst)
		if err != nil {
			return err
		}
		n, err := io.Copy(out, io.LimitReader(rc, max+1))
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err == nil && n > max {
			err = fmt.Errorf("%s: larger than %d bytes", name, max)
		}
		return err
	}
	return errors.New(name + " not found in " + filepath.Base(zipPath))
}
