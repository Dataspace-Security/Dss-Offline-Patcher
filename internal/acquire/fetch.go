package acquire

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"offpatch/internal/manifest"
)

var (
	kbArgRe   = regexp.MustCompile(`^KB\d{4,10}$`)
	productRe = regexp.MustCompile(`^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$`)
)

// FetchKBOptions drives FetchKB (pmctl fetch).
type FetchKBOptions struct {
	KB          string // KB5044273
	Product     string // e.g. "Windows 10 Version 22H2"
	Arch        string // x64|x86|arm64
	Match       string // optional extra title substring to disambiguate rows
	FileMatch   string // optional substring to pick one of several files
	MinBuild    int
	MaxBuild    int
	Severity    string // explicit; wins over MSRC/catalog
	MSRCMonth   string // e.g. 2026-Oct; look severity up in MSRC
	ProductCode string // required only if the catalog file is an .msi
	PackageID   string // default <KB>-<arch>
	OutDir      string
	SpecPath    string
	Progress    func(done, total int64)
	// SkipPrerequisite, if set, is asked for each checkpoint package id
	// (<KB>-<arch>); true means it was delivered earlier and is neither
	// downloaded nor written to the spec again (it stays a prerequisite).
	SkipPrerequisite func(packageID string) bool
	// RecordUBR: write expected_ubr into the spec entry. Off by default:
	// agents up to 0.6.2 refuse a bundle whose manifest has the field.
	RecordUBR bool
	// ExpectedUBR: the build revision the update brings MinBuild to, when
	// known otherwise (update intelligence). The catalog title's
	// "(26100.6899)" wins when it names MinBuild. Recorded for msu only.
	ExpectedUBR int
}

// FetchResult reports what FetchKB/FetchURL did.
type FetchResult struct {
	Entry    SpecEntry
	Download *DownloadResult
	Update   *Update // catalog row (FetchKB only)
	Replaced bool    // an existing spec entry with this package_id was replaced
	Warnings []string
	// Prerequisites are the checkpoint packages written to the spec next to
	// Entry (Windows 11 24H2+ updates list them in the same download dialog).
	Prerequisites []SpecEntry
	// SkippedPrerequisites are checkpoint package ids SkipPrerequisite declined.
	SkippedPrerequisites []string
}

// FetchKB searches the catalog for o.KB, picks the single row for
// product+arch, downloads and verifies the file, and upserts a spec entry.
func FetchKB(ctx context.Context, cat *Catalog, ms *MSRC, o FetchKBOptions) (*FetchResult, error) {
	o.KB = strings.ToUpper(strings.TrimSpace(o.KB))
	o.Arch = strings.ToLower(strings.TrimSpace(o.Arch))
	if !kbArgRe.MatchString(o.KB) {
		return nil, fmt.Errorf("-kb must look like KB5044273 (got %q)", o.KB)
	}
	if strings.TrimSpace(o.Product) == "" {
		return nil, errors.New("-product is required (e.g. \"Windows 10 Version 22H2\")")
	}
	if _, ok := archPatterns[o.Arch]; !ok {
		return nil, fmt.Errorf("-arch must be x64, x86 or arm64 (got %q)", o.Arch)
	}
	if o.Severity != "" && NormalizeSeverity(o.Severity) != strings.ToLower(o.Severity) {
		return nil, fmt.Errorf("-severity must be critical|important|moderate|low (got %q)", o.Severity)
	}
	o.Severity = strings.ToLower(o.Severity)
	if o.MSRCMonth != "" && !ValidMonth(o.MSRCMonth) {
		return nil, fmt.Errorf("-msrc-month must look like 2026-Oct (got %q)", o.MSRCMonth)
	}
	if o.OutDir == "" || o.SpecPath == "" {
		return nil, errors.New("-out and -spec are required")
	}
	if o.MaxBuild != 0 && o.MaxBuild < o.MinBuild {
		return nil, errors.New("-max-build must be >= -min-build")
	}
	if o.PackageID == "" {
		o.PackageID = o.KB + "-" + o.Arch
	}
	res := &FetchResult{}
	warn := func(f string, a ...any) { res.Warnings = append(res.Warnings, fmt.Sprintf(f, a...)) }

	sr, err := cat.Search(ctx, o.KB)
	if err != nil {
		return nil, fmt.Errorf("catalog search: %w", err)
	}
	if len(sr.Updates) == 0 {
		return nil, fmt.Errorf("catalog has no results for %s", o.KB)
	}
	upd, err := PickUpdate(sr.Updates, PickOptions{KB: o.KB, Product: o.Product, Arch: o.Arch, Match: o.Match})
	if err != nil {
		return nil, err
	}
	res.Update = &upd

	files, err := cat.DownloadLinks(ctx, upd.ID)
	if err != nil {
		return nil, fmt.Errorf("catalog download links: %w", err)
	}
	file, err := pickFile(files, o.KB, o.FileMatch)
	if err != nil {
		return nil, err
	}
	checkpoints := checkpointFiles(files, file, o.KB, warn)
	if file.SHA1 == "" && file.SHA256 == "" {
		return nil, fmt.Errorf("catalog gave no hash for %s; refusing an unverifiable download (use fetch-url with a vendor-published SHA-256)", file.FileName)
	}
	kind, err := kindFromName(file.FileName)
	if err != nil {
		return nil, err
	}
	if kind == "msi" && !productRe.MatchString(o.ProductCode) {
		return nil, fmt.Errorf("%s is an .msi: -product-code {GUID} is required", file.FileName)
	}
	rel, err := upd.ReleaseDate()
	if err != nil {
		return nil, err
	}

	// Details: supersedence and the catalog's MSRC severity (advisory).
	var det *Details
	if d, err := cat.Details(ctx, upd.ID); err != nil {
		warn("catalog details unavailable (supersedes left empty): %v", err)
	} else {
		det = d
	}

	sev := o.Severity
	var msrcSup []string
	if o.MSRCMonth != "" {
		list, err := ms.Month(ctx, o.MSRCMonth)
		if err != nil {
			return nil, fmt.Errorf("msrc %s: %w", o.MSRCMonth, err)
		}
		if su, ok := FindKB(list, o.KB); ok {
			msrcSup = su.Supersedes
			scoped, ok := su.ForProduct(o.Product, o.Arch)
			if !ok {
				warn("MSRC %s lists %s but not for product %q; using its overall severity", o.MSRCMonth, o.KB, o.Product)
				scoped = su
			}
			if sev == "" && scoped.Severity != "" {
				sev = scoped.Severity
			}
		} else {
			warn("%s not found in MSRC %s release", o.KB, o.MSRCMonth)
		}
	}
	if sev == "" && det != nil && det.MSRCSeverity != "" {
		sev = det.MSRCSeverity
		warn("severity %q taken from the catalog's MSRC severity field; pass -severity or -msrc-month to set it explicitly", sev)
	}
	if sev == "" {
		sev = "important"
		warn("no severity known for %s; defaulting to \"important\" (pass -severity or -msrc-month)", o.KB)
	}

	sup := []string{}
	if det != nil {
		sup = append(sup, det.Supersedes...)
	}
	if len(sup) == 0 && len(msrcSup) > 0 {
		sup = append(sup, msrcSup...)
	}
	sup = filterKBs(sup, o.KB)
	prereqs := make([]string, 0, len(checkpoints))
	for _, c := range checkpoints {
		prereqs = append(prereqs, c.kb)
	}
	// A checkpoint update is a prerequisite, never something this update
	// replaces: keep it out of supersedes so nothing hides it.
	sup = slices.DeleteFunc(sup, func(kb string) bool { return slices.Contains(prereqs, kb) })

	size := int64(0)
	if len(files) == 1 {
		size = upd.SizeBytes
	}
	dl, err := Download(ctx, cat.HTTP, DownloadRequest{
		URL: file.URL, DestDir: o.OutDir, FileName: file.FileName,
		SHA1: file.SHA1, SHA256: file.SHA256, Size: size, Progress: o.Progress,
	})
	if err != nil {
		return nil, err
	}
	res.Download = dl
	verified := []string{}
	if file.SHA1 != "" {
		verified = append(verified, "sha1(catalog)")
	}
	if file.SHA256 != "" {
		verified = append(verified, "sha256(catalog)")
	}
	if size > 0 {
		verified = append(verified, "size(catalog)")
	}

	path, err := RelPath(o.SpecPath, dl.Path)
	if err != nil {
		return nil, err
	}
	e := SpecEntry{
		PackageID:     o.PackageID,
		Title:         upd.Title,
		Vendor:        "Microsoft",
		Kind:          kind,
		Version:       upd.Version,
		KB:            o.KB,
		Severity:      sev,
		ReleaseDate:   rel,
		Supersedes:    sup,
		Applicability: manifest.Applicability{OS: "windows", Arch: o.Arch, MinBuild: o.MinBuild, MaxBuild: o.MaxBuild},
		SourceURL:     file.URL,
		Path:          path,
		Acquired: &Provenance{
			At: time.Now().UTC().Format(time.RFC3339), Method: "catalog", CatalogUpdateID: upd.ID,
			SHA1: dl.SHA1, SHA256: dl.SHA256, Size: dl.Size, Verified: strings.Join(verified, "+"),
		},
	}
	if kind == "msi" {
		e.ProductCode = o.ProductCode
	}
	if len(prereqs) > 0 {
		e.Prerequisites = prereqs
	}
	if kind == "msu" && o.RecordUBR {
		e.ExpectedUBR = TitleUBR(upd.Title, o.MinBuild)
		if e.ExpectedUBR == 0 && o.MinBuild > 0 {
			e.ExpectedUBR = o.ExpectedUBR
		}
	}
	if err := ValidateEntry(e, dl.Size, dl.SHA256); err != nil {
		return nil, err
	}
	// Checkpoint packages: each is its own package, downloaded and verified
	// like the main file. All of them must succeed before the spec changes.
	for _, c := range checkpoints {
		id := c.kb + "-" + o.Arch
		if o.SkipPrerequisite != nil && o.SkipPrerequisite(id) {
			res.SkippedPrerequisites = append(res.SkippedPrerequisites, id)
			continue
		}
		ce, err := fetchCheckpoint(ctx, cat.HTTP, o, upd, c, id, sev, rel)
		if err != nil {
			return nil, fmt.Errorf("checkpoint update %s (prerequisite of %s): %w", c.kb, o.KB, err)
		}
		res.Prerequisites = append(res.Prerequisites, ce)
	}
	for _, ce := range res.Prerequisites {
		if _, err := UpsertSpec(o.SpecPath, ce); err != nil {
			return nil, err
		}
	}
	replaced, err := UpsertSpec(o.SpecPath, e)
	if err != nil {
		return nil, err
	}
	res.Entry, res.Replaced = e, replaced
	return res, nil
}

type checkpointFile struct {
	DownloadFile
	kb string
}

// checkpointFiles returns the other .msu files of a catalog download dialog
// that carry their own KB: on Windows 11 24H2 and later the dialog lists the
// cumulative update together with the checkpoint update(s) it requires.
func checkpointFiles(files []DownloadFile, main DownloadFile, kb string, warn func(string, ...any)) []checkpointFile {
	var out []checkpointFile
	seen := map[string]bool{}
	for _, f := range files {
		if f.URL == main.URL && f.FileName == main.FileName {
			continue
		}
		if !strings.EqualFold(filepath.Ext(f.FileName), ".msu") {
			warn("%s: the catalog also lists %s, which is not an .msu; it was not packaged", kb, f.FileName)
			continue
		}
		m := titleKBRe.FindStringSubmatch(f.FileName)
		if m == nil || strings.EqualFold("KB"+m[1], kb) {
			warn("%s: the catalog also lists %s, which names no separate KB; it was not packaged (endpoints may need it)", kb, f.FileName)
			continue
		}
		ckb := "KB" + m[1]
		if seen[ckb] {
			continue
		}
		seen[ckb] = true
		out = append(out, checkpointFile{DownloadFile: f, kb: ckb})
	}
	return out
}

func fetchCheckpoint(ctx context.Context, hc *http.Client, o FetchKBOptions, upd Update, c checkpointFile, id, sev, rel string) (SpecEntry, error) {
	if c.SHA1 == "" && c.SHA256 == "" {
		return SpecEntry{}, fmt.Errorf("catalog gave no hash for %s; refusing an unverifiable download", c.FileName)
	}
	dl, err := Download(ctx, hc, DownloadRequest{URL: c.URL, DestDir: o.OutDir, FileName: c.FileName, SHA1: c.SHA1, SHA256: c.SHA256, Progress: o.Progress})
	if err != nil {
		return SpecEntry{}, err
	}
	path, err := RelPath(o.SpecPath, dl.Path)
	if err != nil {
		return SpecEntry{}, err
	}
	verified := []string{}
	if c.SHA1 != "" {
		verified = append(verified, "sha1(catalog)")
	}
	if c.SHA256 != "" {
		verified = append(verified, "sha256(catalog)")
	}
	e := SpecEntry{
		PackageID:     id,
		Title:         fmt.Sprintf("Checkpoint cumulative update %s (prerequisite of %s: %s)", c.kb, o.KB, upd.Title),
		Vendor:        "Microsoft",
		Kind:          "msu",
		KB:            c.kb,
		Severity:      sev,
		ReleaseDate:   rel,
		Supersedes:    []string{},
		Applicability: manifest.Applicability{OS: "windows", Arch: o.Arch, MinBuild: o.MinBuild, MaxBuild: o.MaxBuild},
		SourceURL:     c.URL,
		Path:          path,
		Acquired: &Provenance{
			At: time.Now().UTC().Format(time.RFC3339), Method: "catalog", CatalogUpdateID: upd.ID,
			SHA1: dl.SHA1, SHA256: dl.SHA256, Size: dl.Size, Verified: strings.Join(verified, "+"),
		},
	}
	return e, ValidateEntry(e, dl.Size, dl.SHA256)
}

func pickFile(files []DownloadFile, kb, fileMatch string) (DownloadFile, error) {
	if len(files) == 1 && fileMatch == "" {
		return files[0], nil
	}
	needle := strings.ToLower(fileMatch)
	if needle == "" {
		needle = strings.ToLower(kb) // e.g. "kb5044273" in windows10.0-kb5044273-x64_<sha1>.msu
	}
	var hits []DownloadFile
	for _, f := range files {
		if strings.Contains(strings.ToLower(f.FileName), needle) {
			hits = append(hits, f)
		}
	}
	if len(hits) == 1 {
		return hits[0], nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "update has %d files and %d match %q; choose one with -file:", len(files), len(hits), needle)
	for _, f := range files {
		fmt.Fprintf(&b, "\n  %s", f.FileName)
	}
	b.WriteString("\n(checkpoint updates with their own KB are packaged automatically as prerequisites of the chosen file)")
	return DownloadFile{}, errors.New(b.String())
}

func filterKBs(in []string, own string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		s = strings.ToUpper(strings.TrimSpace(s))
		if !kbArgRe.MatchString(s) || s == own || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// FetchURLOptions drives FetchURL (pmctl fetch-url) for third-party vendors.
type FetchURLOptions struct {
	URL         string // https only
	SHA256      string // required: obtained by the operator from the vendor
	FileName    string // default: last URL path segment
	PackageID   string
	Title       string
	Vendor      string
	Kind        string // msi|msu (default from extension)
	KB          string
	ProductCode string
	PackageName string // deb/rpm package or macOS pkg receipt id
	OS          string // windows|linux|macos (default from kind)
	Version     string
	Severity    string
	ReleaseDate string // YYYY-MM-DD, default today (UTC)
	Supersedes  []string
	Arch        string // default any
	MinBuild    int
	MaxBuild    int
	OutDir      string
	SpecPath    string
	HTTP        *http.Client
	// Verified describes where SHA256 came from (default "sha256(operator)").
	Verified string
	// Exe: the EXE install block (Kind "exe" only).
	Exe *manifest.ExeInstall
	// VerifyPayload, if set, runs on the downloaded, hash-checked file
	// before the spec entry is written (e.g. the Authenticode check of an
	// EXE installer). An error leaves the spec unchanged.
	VerifyPayload func(path string) error
	// VendorSignature, if set, is the signature already verified at fetch
	// time (signer, pin, revocation); pmctl build keeps it.
	VendorSignature *manifest.VendorSignature
	Progress        func(done, total int64)
}

// FetchURL downloads a vendor file over HTTPS, requires it to match the
// operator-supplied SHA-256, and upserts a spec entry.
func FetchURL(ctx context.Context, o FetchURLOptions) (*FetchResult, error) {
	u, err := url.Parse(o.URL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("-url invalid: %q", o.URL)
	}
	if u.Scheme != "https" {
		return nil, errors.New("-url must be https://")
	}
	o.SHA256 = strings.ToLower(strings.TrimSpace(o.SHA256))
	if !hex64Re.MatchString(o.SHA256) {
		return nil, errors.New("-sha256 is required: 64 hex chars published by the vendor")
	}
	if o.OutDir == "" || o.SpecPath == "" {
		return nil, errors.New("-out and -spec are required")
	}
	if o.FileName == "" {
		o.FileName = pathBase(u.Path)
	}
	if !safeNameRe.MatchString(o.FileName) {
		return nil, fmt.Errorf("file name %q from URL is not [A-Za-z0-9._-]; pass -file", o.FileName)
	}
	if o.Kind == "" {
		if o.Kind, err = kindFromName(o.FileName); err != nil {
			return nil, err
		}
	}
	if o.Arch == "" {
		o.Arch = "any"
	}
	if o.ReleaseDate == "" {
		o.ReleaseDate = time.Now().UTC().Format("2006-01-02")
	} else if _, err := time.Parse("2006-01-02", o.ReleaseDate); err != nil {
		return nil, fmt.Errorf("-release-date must be YYYY-MM-DD (got %q)", o.ReleaseDate)
	}
	o.KB = strings.ToUpper(strings.TrimSpace(o.KB))
	if o.Vendor == "" {
		return nil, errors.New("-vendor is required")
	}
	if o.PackageID == "" || o.Title == "" || o.Severity == "" {
		return nil, errors.New("-package-id, -title and -severity are required")
	}
	o.Severity = strings.ToLower(o.Severity)

	path, err := RelPath(o.SpecPath, filepath.Join(o.OutDir, o.FileName))
	if err != nil {
		return nil, err
	}
	e := SpecEntry{
		PackageID: o.PackageID, Title: o.Title, Vendor: o.Vendor, Kind: o.Kind, Version: o.Version,
		KB: o.KB, ProductCode: o.ProductCode, PackageName: o.PackageName, Severity: o.Severity, ReleaseDate: o.ReleaseDate,
		Supersedes:    filterKBs(o.Supersedes, o.KB),
		Applicability: manifest.Applicability{OS: osForKind(o.Kind, o.OS), Arch: o.Arch, MinBuild: o.MinBuild, MaxBuild: o.MaxBuild},
		SourceURL:     o.URL, Path: path, Exe: o.Exe, VendorSignature: o.VendorSignature,
	}
	// Validate metadata before spending bandwidth.
	if err := ValidateEntry(e, 1, o.SHA256); err != nil {
		return nil, err
	}
	dl, err := Download(ctx, o.HTTP, DownloadRequest{
		URL: o.URL, DestDir: o.OutDir, FileName: o.FileName, SHA256: o.SHA256, Progress: o.Progress,
	})
	if err != nil {
		return nil, err
	}
	if o.VerifyPayload != nil {
		if err := o.VerifyPayload(dl.Path); err != nil {
			return nil, err
		}
	}
	e.Acquired = &Provenance{
		At: time.Now().UTC().Format(time.RFC3339), Method: "url",
		SHA1: dl.SHA1, SHA256: dl.SHA256, Size: dl.Size, Verified: verifiedOr(o.Verified, "sha256(operator)"),
	}
	if err := ValidateEntry(e, dl.Size, dl.SHA256); err != nil {
		return nil, err
	}
	replaced, err := UpsertSpec(o.SpecPath, e)
	if err != nil {
		return nil, err
	}
	return &FetchResult{Entry: e, Download: dl, Replaced: replaced}, nil
}

func verifiedOr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// TitleUBR returns the build revision a catalog title states for build
// ("... (KB5066835) (26100.6899)" → 6899), or 0.
func TitleUBR(title string, build int) int {
	if build <= 0 {
		return 0
	}
	for _, m := range buildUBRRe.FindAllStringSubmatch(title, -1) {
		if b, _ := strconv.Atoi(m[1]); b == build {
			ubr, _ := strconv.Atoi(m[2])
			return ubr
		}
	}
	return 0
}
