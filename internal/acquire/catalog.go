package acquire

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DefaultCatalogURL is the Microsoft Update Catalog. It has no official API;
// this client scrapes its HTML and may break if Microsoft changes the pages.
const DefaultCatalogURL = "https://www.catalog.update.microsoft.com"

// Catalog is a Microsoft Update Catalog client.
type Catalog struct {
	BaseURL string       // default DefaultCatalogURL; injectable for tests
	HTTP    *http.Client // default DefaultHTTPClient()
}

// NewCatalog returns a client for the public catalog.
func NewCatalog() *Catalog {
	return &Catalog{BaseURL: DefaultCatalogURL, HTTP: DefaultHTTPClient()}
}

// ErrPageFormat signals that a catalog page did not look as expected —
// most likely Microsoft changed the site and the scraper needs updating.
var ErrPageFormat = errors.New("unexpected Microsoft Update Catalog page format")

// Update is one row of a catalog search result.
type Update struct {
	ID             string `json:"id"` // update GUID
	Title          string `json:"title"`
	Products       string `json:"products"`
	Classification string `json:"classification"`
	LastUpdated    string `json:"last_updated"` // as shown, M/D/YYYY
	Version        string `json:"version"`      // "" when the catalog shows n/a
	Size           string `json:"size"`         // as shown, e.g. "78.2 MB"
	SizeBytes      int64  `json:"size_bytes"`   // exact, 0 if absent
}

// KB returns the KB number in the title ("KB5044273"), or "".
func (u Update) KB() string {
	m := titleKBRe.FindStringSubmatch(u.Title)
	if m == nil {
		return ""
	}
	return "KB" + m[1]
}

// ReleaseDate converts LastUpdated (M/D/YYYY) to YYYY-MM-DD.
func (u Update) ReleaseDate() (string, error) {
	t, err := time.Parse("1/2/2006", strings.TrimSpace(u.LastUpdated))
	if err != nil {
		return "", fmt.Errorf("catalog date %q: %w", u.LastUpdated, err)
	}
	return t.Format("2006-01-02"), nil
}

// SearchResult is a parsed search page.
type SearchResult struct {
	Updates []Update
	Summary string // e.g. "1 - 25 of 734 (page 1 of 30)"; "" when no results
}

var (
	guidRe       = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	rowStartRe   = regexp.MustCompile(`<tr[^>]*\sid="([0-9a-fA-F-]{36})_R(\d+)"`)
	cellRe       = regexp.MustCompile(`(?s)\sid="([0-9a-fA-F-]{36})_C(\d+)_R\d+"[^>]*>(.*?)</td>`)
	tagRe        = regexp.MustCompile(`(?s)<[^>]*>`)
	spaceRe      = regexp.MustCompile(`\s+`)
	titleKBRe    = regexp.MustCompile(`(?i)\bKB(\d{4,10})\b`)
	summaryRe    = regexp.MustCompile(`(?s)id="ctl00_catalogBody_searchDuration"[^>]*>(.*?)</span>`)
	resultsTblRe = regexp.MustCompile(`id="ctl00_catalogBody_updateMatches"`)
	noResultsRe  = regexp.MustCompile(`id="ctl00_catalogBody_noResultText"`)
	sizeShownRe  = regexp.MustCompile(`_size"[^>]*>([^<]*)<`)
	sizeExactRe  = regexp.MustCompile(`_originalSize"[^>]*>\s*(\d+)\s*<`)
)

func cleanText(s string) string {
	s = tagRe.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	return strings.TrimSpace(spaceRe.ReplaceAllString(s, " "))
}

// Search queries the catalog (first result page, up to 25 rows).
func (c *Catalog) Search(ctx context.Context, query string) (*SearchResult, error) {
	query = strings.TrimSpace(query)
	if query == "" || len(query) > 100 {
		return nil, errors.New("catalog query must be 1-100 characters")
	}
	u := c.base() + "/Search.aspx?q=" + url.QueryEscape(query)
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	setPageHeaders(req)
	b, err := doRead(ctx, c.HTTP, req, maxPageBytes)
	if err != nil {
		return nil, err
	}
	return ParseSearch(b)
}

// ParseSearch parses a catalog Search.aspx page.
func ParseSearch(page []byte) (*SearchResult, error) {
	s := string(page)
	if noResultsRe.MatchString(s) && !resultsTblRe.MatchString(s) {
		return &SearchResult{}, nil
	}
	if !resultsTblRe.MatchString(s) {
		return nil, fmt.Errorf("%w: search results table not found", ErrPageFormat)
	}
	res := &SearchResult{}
	if m := summaryRe.FindStringSubmatch(s); m != nil {
		res.Summary = cleanText(m[1])
	}
	starts := rowStartRe.FindAllStringSubmatchIndex(s, -1)
	for i, st := range starts {
		id := strings.ToLower(s[st[2]:st[3]])
		end := len(s)
		if i+1 < len(starts) {
			end = starts[i+1][0]
		}
		row := s[st[0]:end]
		u := Update{ID: id}
		for _, cm := range cellRe.FindAllStringSubmatch(row, -1) {
			if !strings.EqualFold(cm[1], id) {
				continue
			}
			col, _ := strconv.Atoi(cm[2])
			txt := cleanText(cm[3])
			switch col {
			case 1:
				u.Title = txt
			case 2:
				u.Products = txt
			case 3:
				u.Classification = txt
			case 4:
				u.LastUpdated = txt
			case 5:
				if !strings.EqualFold(txt, "n/a") {
					u.Version = txt
				}
			case 6:
				if m := sizeShownRe.FindStringSubmatch(cm[3]); m != nil {
					u.Size = cleanText(m[1])
				}
				if m := sizeExactRe.FindStringSubmatch(cm[3]); m != nil {
					u.SizeBytes, _ = strconv.ParseInt(m[1], 10, 64)
				}
			}
		}
		if !guidRe.MatchString(u.ID) || u.Title == "" {
			return nil, fmt.Errorf("%w: row %d has no update id/title", ErrPageFormat, i)
		}
		res.Updates = append(res.Updates, u)
	}
	if len(res.Updates) == 0 {
		return nil, fmt.Errorf("%w: results table has no rows", ErrPageFormat)
	}
	return res, nil
}

// archPatterns match architecture wording used in catalog/MSRC titles.
var archPatterns = map[string]*regexp.Regexp{
	"x64":   regexp.MustCompile(`(?i)\b(x64|amd64)\b`),
	"x86":   regexp.MustCompile(`(?i)\bx86\b|\b32-bit\b`),
	"arm64": regexp.MustCompile(`(?i)\barm64\b`),
}

// MatchesArch reports whether text mentions arch (x64|x86|arm64).
func MatchesArch(text, arch string) bool {
	re, ok := archPatterns[strings.ToLower(arch)]
	return ok && re.MatchString(text)
}

// PickOptions selects exactly one catalog row.
type PickOptions struct {
	KB      string // "KB5044273"
	Product string // substring of title or products column, case-insensitive
	Arch    string // x64|x86|arm64
	Match   string // optional extra substring that the title must contain
}

// PickUpdate returns the single row matching opts, or an error that lists
// the candidates when zero or several rows match.
func PickUpdate(updates []Update, o PickOptions) (Update, error) {
	if _, ok := archPatterns[strings.ToLower(o.Arch)]; !ok {
		return Update{}, fmt.Errorf("arch must be x64, x86 or arm64 (got %q)", o.Arch)
	}
	kb := strings.ToUpper(strings.TrimSpace(o.KB))
	prod := normTitle(o.Product)
	match := normTitle(o.Match)
	var hits []Update
	for _, u := range updates {
		if kb != "" && !strings.EqualFold(u.KB(), kb) {
			continue
		}
		if prod != "" && !strings.Contains(normTitle(u.Title), prod) && !strings.Contains(normTitle(u.Products), prod) {
			continue
		}
		if !MatchesArch(u.Title, o.Arch) {
			continue
		}
		if match != "" && !strings.Contains(normTitle(u.Title), match) {
			continue
		}
		hits = append(hits, u)
	}
	if len(hits) == 1 {
		return hits[0], nil
	}
	var b strings.Builder
	if len(hits) == 0 {
		fmt.Fprintf(&b, "no catalog row matches kb=%s product=%q arch=%s", kb, o.Product, o.Arch)
		if match != "" {
			fmt.Fprintf(&b, " match=%q", o.Match)
		}
		b.WriteString("; rows returned by the catalog:")
		for _, u := range updates {
			fmt.Fprintf(&b, "\n  %s  %s", u.ID, u.Title)
		}
	} else {
		fmt.Fprintf(&b, "%d catalog rows match; narrow with -product or -match:", len(hits))
		for _, u := range hits {
			fmt.Fprintf(&b, "\n  %s  %s", u.ID, u.Title)
		}
	}
	return Update{}, errors.New(b.String())
}

// DownloadFile is one file offered by the catalog download dialog.
type DownloadFile struct {
	URL      string `json:"url"`
	FileName string `json:"file_name"`
	SHA1     string `json:"sha1"`   // lowercase hex, from the dialog digest and/or file name
	SHA256   string `json:"sha256"` // lowercase hex, when the catalog provides it
}

var (
	dlFieldRe  = regexp.MustCompile(`downloadInformation\[0\]\.files\[(\d+)\]\.(url|digest|sha256|fileName)\s*=\s*'((?:[^'\\]|\\.)*)'`)
	dlUpdateRe = regexp.MustCompile(`downloadInformation\[0\]\.updateID\s*=\s*'([0-9a-fA-F-]{36})'`)
)

// DownloadLinks asks the catalog's download dialog for the files of an update.
func (c *Catalog) DownloadLinks(ctx context.Context, updateID string) ([]DownloadFile, error) {
	if !guidRe.MatchString(updateID) {
		return nil, fmt.Errorf("invalid update id %q", updateID)
	}
	updateID = strings.ToLower(updateID)
	form := url.Values{}
	form.Set("updateIDs", fmt.Sprintf(`[{"size":0,"languages":"","uidInfo":"%s","updateID":"%s"}]`, updateID, updateID))
	req, err := http.NewRequest(http.MethodPost, c.base()+"/DownloadDialog.aspx", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setPageHeaders(req)
	b, err := doRead(ctx, c.HTTP, req, maxPageBytes)
	if err != nil {
		return nil, err
	}
	return ParseDownloadDialog(b, updateID)
}

// ParseDownloadDialog extracts downloadInformation[0].files[N] entries. If
// updateID is non-empty it must match downloadInformation[0].updateID.
func ParseDownloadDialog(page []byte, updateID string) ([]DownloadFile, error) {
	s := string(page)
	if updateID != "" {
		m := dlUpdateRe.FindStringSubmatch(s)
		if m == nil {
			return nil, fmt.Errorf("%w: download dialog has no downloadInformation", ErrPageFormat)
		}
		if !strings.EqualFold(m[1], updateID) {
			return nil, fmt.Errorf("download dialog is for update %s, asked for %s", m[1], updateID)
		}
	}
	files := map[int]*DownloadFile{}
	for _, m := range dlFieldRe.FindAllStringSubmatch(s, -1) {
		i, _ := strconv.Atoi(m[1])
		f := files[i]
		if f == nil {
			f = &DownloadFile{}
			files[i] = f
		}
		v := unescapeJS(m[3])
		switch m[2] {
		case "url":
			f.URL = v
		case "fileName":
			f.FileName = v
		case "digest":
			if h := decodeDigest(v, 20); h != "" {
				f.SHA1 = h
			}
		case "sha256":
			if h := decodeDigest(v, 32); h != "" {
				f.SHA256 = h
			}
		}
	}
	idx := make([]int, 0, len(files))
	for i := range files {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	var out []DownloadFile
	for _, i := range idx {
		f := files[i]
		if f.URL == "" {
			continue
		}
		pu, err := url.Parse(f.URL)
		if err != nil || pu.Host == "" {
			return nil, fmt.Errorf("%w: bad download url %q", ErrPageFormat, f.URL)
		}
		// Catalog content hosts serve HTTPS; never fetch updates over HTTP.
		if pu.Scheme == "http" && strings.HasSuffix(strings.ToLower(pu.Hostname()), ".windowsupdate.com") {
			pu.Scheme = "https"
			f.URL = pu.String()
		}
		if f.FileName == "" {
			f.FileName = pathBase(pu.Path)
		}
		if n := SHA1FromCatalogName(f.FileName); n != "" {
			if f.SHA1 != "" && f.SHA1 != n {
				return nil, fmt.Errorf("catalog digest %s disagrees with file name hash %s for %s", f.SHA1, n, f.FileName)
			}
			f.SHA1 = n
		}
		out = append(out, *f)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no download files listed", ErrPageFormat)
	}
	return out, nil
}

func pathBase(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		p = p[i+1:]
	}
	if u, err := url.PathUnescape(p); err == nil {
		return u
	}
	return p
}

func unescapeJS(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	r := strings.NewReplacer(`\'`, `'`, `\"`, `"`, `\\`, `\`, `\/`, `/`)
	return r.Replace(s)
}

// decodeDigest accepts base64 or hex of the given byte length and returns hex.
func decodeDigest(v string, n int) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if len(v) == 2*n {
		if b, err := hex.DecodeString(v); err == nil {
			return hex.EncodeToString(b)
		}
	}
	if b, err := base64.StdEncoding.DecodeString(v); err == nil && len(b) == n {
		return hex.EncodeToString(b)
	}
	return ""
}

// Details is the subset of ScopedViewInline.aspx we use.
type Details struct {
	UpdateID     string   `json:"update_id"`
	Title        string   `json:"title"`
	MSRCSeverity string   `json:"msrc_severity"` // lowercase manifest severity, or ""
	Supersedes   []string `json:"supersedes"`    // KBs this update replaces
	SupersededBy []string `json:"superseded_by"` // KBs that replace this update
}

var (
	detTitleRe = regexp.MustCompile(`(?s)id="ScopedViewHandler_titleText"[^>]*>(.*?)</span>`)
	detIDRe    = regexp.MustCompile(`(?s)id="ScopedViewHandler_UpdateID"[^>]*>(.*?)</span>`)
	detSevRe   = regexp.MustCompile(`(?s)id="ScopedViewHandler_msrcSeverity"[^>]*>(.*?)</span>`)
)

// Details fetches the catalog details page of an update.
func (c *Catalog) Details(ctx context.Context, updateID string) (*Details, error) {
	if !guidRe.MatchString(updateID) {
		return nil, fmt.Errorf("invalid update id %q", updateID)
	}
	req, err := http.NewRequest(http.MethodGet, c.base()+"/ScopedViewInline.aspx?updateid="+url.QueryEscape(strings.ToLower(updateID)), nil)
	if err != nil {
		return nil, err
	}
	setPageHeaders(req)
	b, err := doRead(ctx, c.HTTP, req, maxPageBytes)
	if err != nil {
		return nil, err
	}
	return ParseDetails(b)
}

// ParseDetails extracts title, MSRC severity and supersedence from a details page.
func ParseDetails(page []byte) (*Details, error) {
	s := string(page)
	d := &Details{}
	if m := detIDRe.FindStringSubmatch(s); m != nil {
		d.UpdateID = strings.ToLower(cleanText(m[1]))
	}
	if m := detTitleRe.FindStringSubmatch(s); m != nil {
		d.Title = cleanText(m[1])
	}
	if d.UpdateID == "" || d.Title == "" {
		return nil, fmt.Errorf("%w: details page has no update id/title", ErrPageFormat)
	}
	if m := detSevRe.FindStringSubmatch(s); m != nil {
		d.MSRCSeverity = NormalizeSeverity(cleanText(m[1]))
	}
	own := Update{Title: d.Title}.KB()
	byIdx := strings.Index(s, `id="supersededbyInfo"`)
	supIdx := strings.Index(s, `id="supersedesInfo"`)
	if supIdx >= 0 {
		end := len(s)
		for _, marker := range []string{`id="languageBox"`, `id="installBox"`} {
			if i := strings.Index(s[supIdx:], marker); i >= 0 && supIdx+i < end {
				end = supIdx + i
			}
		}
		d.Supersedes = kbsIn(s[supIdx:end], own)
	}
	if byIdx >= 0 {
		end := len(s)
		if supIdx > byIdx {
			end = supIdx
		}
		d.SupersededBy = kbsIn(s[byIdx:end], own)
	}
	return d, nil
}

func kbsIn(s, exclude string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, m := range titleKBRe.FindAllStringSubmatch(cleanText(s), -1) {
		kb := "KB" + m[1]
		if kb == exclude || seen[kb] {
			continue
		}
		seen[kb] = true
		out = append(out, kb)
	}
	return out
}

func (c *Catalog) base() string {
	if c.BaseURL == "" {
		return DefaultCatalogURL
	}
	return strings.TrimRight(c.BaseURL, "/")
}

func setPageHeaders(req *http.Request) {
	req.Header.Set("User-Agent", DefaultUserAgent)
	// Without this the catalog localises titles by client location, which
	// breaks product/arch matching.
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
}

// NormalizeSeverity maps MSRC wording to manifest severities ("" if unknown).
func NormalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "important":
		return "important"
	case "moderate":
		return "moderate"
	case "low":
		return "low"
	}
	return ""
}

var sevRank = map[string]int{"low": 1, "moderate": 2, "important": 3, "critical": 4}

// MaxSeverity returns the more severe of a and b (manifest severities).
func MaxSeverity(a, b string) string {
	if sevRank[b] > sevRank[a] {
		return b
	}
	return a
}

// normTitle lowercases, drops commas and collapses spaces, so the MSRC
// spelling "Windows 11 Version 24H2" matches catalog titles that say
// "Windows 11, version 24H2".
func normTitle(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(strings.ToLower(s), ",", " ")), " ")
}
