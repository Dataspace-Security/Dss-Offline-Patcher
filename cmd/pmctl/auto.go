package main

// pmctl auto: unattended acquisition for the connected zone. One run checks
// Microsoft's monthly security release for the configured products and each
// configured third-party app for a new version, downloads and verifies
// everything new, builds ONE signed bundle and sends it through the transfer
// boundary. Packages are recorded as done only after a successful send, so a
// failed run is simply retried by the next scheduled run.
//
// Nothing here installs anything: bundles land in quarantine on the isolated
// side and still need approval there.

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"offpatch/internal/acqstatus"
	"offpatch/internal/acquire"
	"offpatch/internal/manifest"
)

type autoConfig struct {
	WorkDir       string   `json:"work_dir"`       // downloads/, runs/, state.json, auto-log.jsonl
	SequenceState string   `json:"sequence_state"` // shared with manual pmctl build (-state)
	Source        string   `json:"source"`
	Key           string   `json:"key"` // bundle signing key file or exec:<hsm cli>
	Pub           string   `json:"pub"`
	TTL           Duration `json:"bundle_ttl"`
	Schedule      string   `json:"schedule"` // shown in the console, e.g. "daily at 07:00"
	Send          sendOpts `json:"send"`

	Microsoft *struct {
		Months      int          `json:"months"`       // how many monthly releases to look back (default 2)
		MinSeverity string       `json:"min_severity"` // default important
		Products    []autoMSProd `json:"products"`
	} `json:"microsoft"`
	Apps []autoApp `json:"apps"`
	// Intel: also send update intelligence (newest Windows cumulative updates
	// and application versions) so the console can show what every endpoint
	// is missing. Omit to skip; {} for the defaults.
	Intel *intelOpts `json:"intel"`
	// Requests: directory of acquisition requests exported from the
	// console's Updates page (see requests.go). Overridden by -requests.
	Requests string `json:"requests"`

	// Advanced: alternative endpoints (tests, or an internal mirror).
	CatalogURL         string `json:"catalog_url"`
	MSRCURL            string `json:"msrc_url"`
	WingetManifestsURL string `json:"winget_manifests_url"` // default: the winget-pkgs repository
}

type autoMSProd struct {
	MSRCProduct    string `json:"msrc_product"`    // substring of the MSRC product name
	CatalogProduct string `json:"catalog_product"` // substring of the catalog title/products
	Arch           string `json:"arch"`            // x64|x86|arm64
	MinBuild       int    `json:"min_build"`
	MaxBuild       int    `json:"max_build"`
	Match          string `json:"match"`          // optional extra title filter
	PackageSuffix  string `json:"package_suffix"` // disambiguates IDs if two products share a KB
}

type autoSource struct {
	URL      string `json:"url"`       // https; {version} is substituted for checksum URLs
	Regex    string `json:"regex"`     // first capture group (or whole match)
	JSONPath string `json:"json_path"` // alternative to regex: dotted path, e.g. "releases.0.version"
	// Redirect: read the version from the redirect Location of url (e.g.
	// Zoom's .../latest/X.pkg → .../prod/7.2.2.88465/X.pkg); regex applies to it.
	Redirect bool `json:"redirect"`
}

type autoApp struct {
	Name        string      `json:"name"` // short id, used as package_id prefix
	Title       string      `json:"title"`
	Vendor      string      `json:"vendor"`
	Kind        string      `json:"kind"` // msi | msu | deb | rpm | pkg
	OS          string      `json:"os"`   // default from kind
	Arch        string      `json:"arch"`
	Severity    string      `json:"severity"`
	Version     autoSource  `json:"version"`
	DownloadURL string      `json:"download_url"` // {version} is substituted
	FileName    string      `json:"file_name"`    // default: last URL segment; {version} substituted
	SHA256      *autoSource `json:"sha256"`       // vendor checksum feed (preferred)
	// AuthenticodeSigner: if the vendor publishes no checksum, accept a file
	// whose Authenticode signature is Valid and whose signer contains this
	// text (Windows acquisition host only).
	AuthenticodeSigner string `json:"authenticode_signer"`
	// PkgSigner: for macOS .pkg files with no published checksum, accept a
	// package whose Apple signature is valid (Developer ID, notarized) and
	// whose signing certificate contains this text, ideally including the
	// Team ID, e.g. "Developer ID Installer: Google LLC (EQHXZ8M8AV)".
	PkgSigner string `json:"pkg_signer"`
	// LabelFromPkg: the feed version is only a change trigger (e.g. a release
	// tag or build number); the package is always labelled with the app
	// version inside the .pkg, without a mismatch warning.
	LabelFromPkg       bool   `json:"label_from_pkg"`
	ProductCode        string `json:"product_code"`          // msi: fixed product code
	ProductCodeFromMSI bool   `json:"product_code_from_msi"` // msi: read it from the file (Windows host)
	PackageName        string `json:"package_name"`          // deb/rpm/pkg
	MinBuild           int    `json:"min_build"`
	MaxBuild           int    `json:"max_build"`
}

// Duration parses "720h"-style strings in JSON.
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	d.Duration = v
	return err
}

type autoState struct {
	Done   map[string]autoDone `json:"done"`   // package_id → when/where sent
	Failed map[string]string   `json:"failed"` // package_id → last error (retried next run)
	// FeedSeen: app → "feedVersion=realVersion" when a vendor feed announced a
	// version the download link did not (yet) serve.
	FeedSeen map[string]string `json:"feed_seen,omitempty"`
}

type autoDone struct {
	SHA256   string `json:"sha256"`
	BundleID string `json:"bundle_id"`
	SentAt   string `json:"sent_at"`
}

type autoReport struct {
	StartedAt  string            `json:"started_at"`
	Finished   string            `json:"finished_at"`
	DryRun     bool              `json:"dry_run"`
	New        []string          `json:"new_packages"`
	Skipped    int               `json:"already_sent"`
	Superseded []string          `json:"skipped_superseded,omitempty"`
	Failures   map[string]string `json:"failures"`
	Bundle     string            `json:"bundle,omitempty"`
	BundleID   string            `json:"bundle_id,omitempty"`
	Sent       bool              `json:"sent"`
	Warnings   []string          `json:"warnings,omitempty"`
	Feeds      []acqstatus.Feed  `json:"feeds"`
	Error      string            `json:"error,omitempty"`
	StatusSent bool              `json:"status_report_sent"`
}

// Hooks overridable in tests.
var (
	autoHTTP = acquire.DefaultHTTPClient
	autoNow  = time.Now
)

const exitPartial = 2

func autoCmd(args []string) error {
	fs := flag.NewFlagSet("auto", flag.ExitOnError)
	cfgPath := fs.String("config", "acquire.json", "auto-acquisition config")
	dry := fs.Bool("dry-run", false, "list what would be fetched; download and send nothing")
	reqDir := fs.String("requests", "", "directory of acquisition requests exported from the console (default: \"requests\" in the config)")
	fs.Parse(args)
	rep, err := runAutoRequests(context.Background(), *cfgPath, *dry, *reqDir)
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	if err != nil {
		return err
	}
	if len(rep.Failures) > 0 {
		fmt.Fprintf(os.Stderr, "%d item(s) failed; they will be retried next run\n", len(rep.Failures))
		os.Exit(exitPartial)
	}
	return nil
}

func loadAutoConfig(path string) (*autoConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	c := &autoConfig{}
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	base := filepath.Dir(path)
	abs := func(p string) string {
		if p == "" || filepath.IsAbs(p) || strings.HasPrefix(p, "exec:") {
			return p
		}
		return filepath.Join(base, p)
	}
	c.WorkDir, c.SequenceState, c.Key, c.Pub = abs(c.WorkDir), abs(c.SequenceState), abs(c.Key), abs(c.Pub)
	c.Send.To, c.Send.Log = abs(c.Send.To), abs(c.Send.Log)
	c.Requests = abs(c.Requests)
	if c.WorkDir == "" || c.Key == "" {
		return nil, errors.New("config: work_dir and key are required")
	}
	if c.SequenceState == "" {
		c.SequenceState = filepath.Join(c.WorkDir, "sequence.json")
	}
	if c.Send.Via == "" {
		c.Send.Via = "dropdir"
	}
	if c.Send.Log == "" {
		c.Send.Log = filepath.Join(c.WorkDir, "sent.jsonl")
	}
	if c.Microsoft != nil {
		if c.Microsoft.Months <= 0 {
			c.Microsoft.Months = 2
		}
		if c.Microsoft.MinSeverity == "" {
			c.Microsoft.MinSeverity = "important"
		}
		if sevRank[c.Microsoft.MinSeverity] == 0 {
			return nil, fmt.Errorf("config: microsoft.min_severity must be critical|important|moderate|low")
		}
		for i, p := range c.Microsoft.Products {
			if p.MSRCProduct == "" || p.Arch == "" {
				return nil, fmt.Errorf("config: microsoft.products[%d] needs msrc_product and arch", i)
			}
		}
	}
	for i, a := range c.Apps {
		if !nameRe.MatchString(a.Name) || a.Title == "" || a.Vendor == "" || a.Version.URL == "" || a.DownloadURL == "" {
			return nil, fmt.Errorf("config: apps[%d] needs name ([a-z0-9-]), title, vendor, version.url and download_url", i)
		}
		if a.SHA256 == nil && a.AuthenticodeSigner == "" && a.PkgSigner == "" {
			return nil, fmt.Errorf("config: apps[%d] (%s) needs a sha256 checksum source, authenticode_signer or pkg_signer — unverified downloads are never accepted", i, a.Name)
		}
		if a.Kind == "msi" && !a.ProductCodeFromMSI && (a.ProductCode == "" || manifest.IsNilGUID(a.ProductCode)) {
			return nil, fmt.Errorf("config: apps[%d] (%s) needs the MSI's real product_code (not a placeholder), or product_code_from_msi on a Windows acquisition host", i, a.Name)
		}
	}
	return c, nil
}

var (
	nameRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)
	sevRank = map[string]int{"low": 1, "moderate": 2, "important": 3, "critical": 4}
	verRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
	// pkgVerRe mirrors the manifest's version rule.
	pkgVerRe = regexp.MustCompile(`^[0-9]+(\.[0-9]+){1,3}([-+][A-Za-z0-9.]+)?$`)
)

// acquireLock prevents overlapping scheduled runs; a lock older than 6h is
// considered stale (crashed run).
func acquireLock(dir string) (func(), error) {
	p := filepath.Join(dir, ".auto.lock")
	if fi, err := os.Stat(p); err == nil && time.Since(fi.ModTime()) > 6*time.Hour {
		os.Remove(p)
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("another pmctl auto run is in progress (%s)", p)
	}
	fmt.Fprintf(f, "%d %s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339))
	f.Close()
	return func() { os.Remove(p) }, nil
}

func loadState(path string) autoState {
	st := autoState{Done: map[string]autoDone{}, Failed: map[string]string{}}
	if b, err := os.ReadFile(path); err == nil {
		json.Unmarshal(b, &st)
	}
	if st.Done == nil {
		st.Done = map[string]autoDone{}
	}
	if st.Failed == nil {
		st.Failed = map[string]string{}
	}
	if st.FeedSeen == nil {
		st.FeedSeen = map[string]string{}
	}
	return st
}

func saveJSON(path string, v any) error {
	b, _ := json.MarshalIndent(v, "", "  ")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// recentMonths returns MSRC month ids, newest first ("2026-Oct", "2026-Sep").
func recentMonths(now time.Time, n int) []string {
	var out []string
	t := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		out = append(out, t.Format("2006-Jan"))
		t = t.AddDate(0, -1, 0)
	}
	return out
}

// autoWarn records a warning in the current run's report (set by runAuto).
var autoWarn = func(string) {}

func runAuto(ctx context.Context, cfgPath string, dry bool) (autoReport, error) {
	return runAutoRequests(ctx, cfgPath, dry, "")
}

// runAutoRequests is runAuto with the requests directory overridden
// (pmctl auto -requests).
func runAutoRequests(ctx context.Context, cfgPath string, dry bool, requestsDir string) (rep autoReport, err error) {
	autoWarn = func(s string) { rep.Warnings = append(rep.Warnings, s) }
	defer func() { autoWarn = func(string) {} }()
	rep = autoReport{StartedAt: autoNow().UTC().Format(time.RFC3339), DryRun: dry, Failures: map[string]string{}, New: []string{}}
	c, err := loadAutoConfig(cfgPath)
	if err != nil {
		return rep, err
	}
	if requestsDir != "" {
		c.Requests = requestsDir
	}
	downloads := filepath.Join(c.WorkDir, "downloads")
	if err := os.MkdirAll(downloads, 0o750); err != nil {
		return rep, err
	}
	unlock, err := acquireLock(c.WorkDir)
	if err != nil {
		return rep, err
	}
	defer unlock()
	statePath := filepath.Join(c.WorkDir, "state.json")
	st := loadState(statePath)
	// A fresh run directory every time (never reuse an older spec.json).
	runs := filepath.Join(c.WorkDir, "runs")
	if err := os.MkdirAll(runs, 0o750); err != nil {
		return rep, err
	}
	runDir, err := os.MkdirTemp(runs, autoNow().UTC().Format("20060102T150405Z")+"-")
	if err != nil {
		return rep, err
	}
	spec := filepath.Join(runDir, "spec.json")
	hc := autoHTTP()
	fail := func(id string, err error) {
		rep.Failures[id] = err.Error()
		st.Failed[id] = err.Error()
	}
	added := func(id string) {
		rep.New = append(rep.New, id)
		delete(st.Failed, id)
	}

	// ---- Microsoft security updates ----
	if m := c.Microsoft; m != nil && len(m.Products) > 0 {
		ms := acquire.NewMSRC()
		ms.HTTP = hc
		if c.MSRCURL != "" {
			ms.BaseURL = c.MSRCURL
		}
		cat := acquire.NewCatalog()
		cat.HTTP = hc
		if c.CatalogURL != "" {
			cat.BaseURL = c.CatalogURL
		}
		// Collect candidates across months first, then drop any KB that a
		// newer candidate supersedes (e.g. last month's cumulative update once
		// this month's is out): no point carrying ~1 GB of obsolete content.
		type cand struct {
			id, kb, severity string
			p                autoMSProd
		}
		var cands []cand
		superseded := map[string]string{} // KB → superseding KB
		seen := map[string]bool{}
		for _, month := range recentMonths(autoNow(), m.Months) {
			updates, err := ms.Month(ctx, month)
			if err != nil {
				// The current month 404s until Patch Tuesday; not an error.
				rep.Warnings = append(rep.Warnings, fmt.Sprintf("MSRC %s: %v", month, err))
				continue
			}
			sort.Slice(updates, func(i, j int) bool { return updates[i].KB < updates[j].KB })
			for _, p := range m.Products {
				for _, u := range updates {
					fu, ok := u.ForProduct(p.MSRCProduct, p.Arch)
					if !ok || sevRank[fu.Severity] < sevRank[m.MinSeverity] {
						continue
					}
					for _, s := range fu.Supersedes {
						superseded[strings.ToUpper(s)] = fu.KB
					}
					id := fu.KB + "-" + p.Arch + p.PackageSuffix
					if seen[id] {
						continue
					}
					seen[id] = true
					cands = append(cands, cand{id: id, kb: fu.KB, severity: fu.Severity, p: p})
				}
			}
		}
		for _, cd := range cands {
			if by, ok := superseded[strings.ToUpper(cd.kb)]; ok {
				rep.Superseded = append(rep.Superseded, cd.id+" (superseded by "+by+")")
				continue
			}
			if _, done := st.Done[cd.id]; done {
				rep.Skipped++
				continue
			}
			if dry {
				added(cd.id)
				continue
			}
			p := cd.p
			catProd := p.CatalogProduct
			if catProd == "" {
				catProd = p.MSRCProduct
			}
			_, err := acquire.FetchKB(ctx, cat, ms, acquire.FetchKBOptions{KB: cd.kb, Product: catProd, Arch: p.Arch, Match: p.Match,
				MinBuild: p.MinBuild, MaxBuild: p.MaxBuild, Severity: cd.severity, PackageID: cd.id, OutDir: downloads, SpecPath: spec})
			if err != nil {
				fail(cd.id, err)
				continue
			}
			added(cd.id)
		}
		for _, p := range m.Products {
			name := p.MSRCProduct + " " + p.Arch + p.PackageSuffix
			var kbs, fresh, failed []string
			for _, cd := range cands {
				if cd.p != p {
					continue
				}
				kbs = append(kbs, cd.kb)
				if rep.Failures[cd.id] != "" {
					failed = append(failed, cd.kb+": "+rep.Failures[cd.id])
				} else if slices.Contains(rep.New, cd.id) {
					fresh = append(fresh, cd.kb)
				}
			}
			f := acqstatus.Feed{Type: "microsoft", Name: name, LatestVersion: strings.Join(kbs, ", "), Status: "up_to_date"}
			switch {
			case len(failed) > 0:
				f.Status, f.Detail = "failed", strings.Join(failed, "; ")
			case len(fresh) > 0:
				f.Status, f.Detail = "new", strings.Join(fresh, ", ")
			case len(kbs) == 0:
				f.Detail = "no qualifying updates in the checked months"
			}
			rep.Feeds = append(rep.Feeds, f)
		}
	}

	// ---- third-party applications ----
	for _, a := range c.Apps {
		id, ver, err := fetchApp(ctx, hc, a, downloads, spec, st, dry)
		f := acqstatus.Feed{Type: "app", Name: a.Name, Title: a.Title, LatestVersion: ver}
		switch {
		case err != nil:
			fail(a.Name, err)
			f.Status, f.Detail = "failed", err.Error()
		case id == "":
			rep.Skipped++
			delete(st.Failed, a.Name)
			f.Status = "up_to_date"
		default:
			added(id)
			delete(st.Failed, a.Name)
			f.Status, f.Detail = "new", id
		}
		rep.Feeds = append(rep.Feeds, f)
	}

	// ---- acquisition requests carried over from the console ----
	var reqs []*loadedRequest
	if c.Requests != "" {
		reqs = processRequests(&requestRun{ctx: ctx, c: c, hc: hc, downloads: downloads, spec: spec, st: st, dry: dry, rep: &rep,
			fail: fail, added: added, handled: map[string]bool{}}, c.Requests)
	}

	defer func() {
		rep.Finished = autoNow().UTC().Format(time.RFC3339)
		if err != nil {
			rep.Error = err.Error()
		}
		// Done with a request once its packages are on their way (or there
		// was nothing new to send); failed items keep it for the next run.
		if !dry && err == nil && (rep.Sent || len(rep.New) == 0) {
			archiveRequests(c.Requests, reqs, &rep)
		}
		if !dry && c.Intel != nil && !c.Intel.Disabled {
			d, ierr := sendIntel(ctx, c)
			rep.Warnings = append(rep.Warnings, d.Warnings...)
			if ierr != nil {
				rep.Warnings = append(rep.Warnings, "update intelligence not sent: "+ierr.Error())
			} else {
				rep.Feeds = append(rep.Feeds, acqstatus.Feed{Type: "intel", Name: "update intelligence",
					LatestVersion: fmt.Sprintf("%d Windows builds, %d apps", len(d.Windows), len(d.Apps)), Status: "up_to_date", Detail: d.AppsSource})
			}
		}
		if !dry {
			if serr := sendStatus(c, &rep); serr != nil {
				rep.Warnings = append(rep.Warnings, "status report not sent: "+serr.Error())
			}
		}
		saveJSON(statePath, st)
		line, _ := json.Marshal(rep)
		if f, err := os.OpenFile(filepath.Join(c.WorkDir, "auto-log.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
			f.Write(append(line, '\n'))
			f.Close()
		}
	}()
	if dry || len(rep.New) == 0 {
		os.RemoveAll(runDir)
		return rep, nil
	}

	// ---- one signed bundle, sent automatically ----
	tmpOut := filepath.Join(runDir, "bundle.pmb")
	br, err := buildBundle(buildOpts{Key: c.Key, Pub: c.Pub, Spec: spec, Out: tmpOut, Source: c.Source, State: c.SequenceState, TTL: c.TTL.Duration})
	if err != nil {
		return rep, fmt.Errorf("build: %w", err)
	}
	// Name the file after the unique bundle ID (sequence-based) so it never
	// collides with an earlier bundle still waiting in the transfer path.
	out := filepath.Join(runDir, br.BundleID+".pmb")
	if err := os.Rename(tmpOut, out); err != nil {
		return rep, err
	}
	br.Path = out
	rep.Bundle, rep.BundleID = br.Path, br.BundleID
	so := c.Send
	so.Key, so.Pub = c.Key, c.Pub
	if _, err := sendBundle(so, br.Path); err != nil {
		return rep, fmt.Errorf("send (packages will be retried next run): %w", err)
	}
	rep.Sent = true
	var entries []struct {
		PackageID string `json:"package_id"`
		Path      string `json:"path"`
	}
	b, _ := os.ReadFile(spec)
	json.Unmarshal(b, &entries)
	for _, e := range entries {
		p := e.Path
		if !filepath.IsAbs(p) {
			p = filepath.Join(runDir, p)
		}
		_, sha, _ := manifest.HashFile(p)
		st.Done[e.PackageID] = autoDone{SHA256: sha, BundleID: br.BundleID, SentAt: autoNow().UTC().Format(time.RFC3339)}
	}
	return rep, nil
}

// ---- third-party helpers ----

func getSmall(ctx context.Context, hc *http.Client, rawURL string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" {
		return nil, fmt.Errorf("%q: only https URLs are allowed", rawURL)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GET %s: %s", rawURL, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// extract applies JSONPath ("a.b.0.c") or Regex (first group) to body.
func extract(body []byte, s autoSource, what string) (string, error) {
	if s.JSONPath != "" {
		var v any
		if err := json.Unmarshal(body, &v); err != nil {
			return "", fmt.Errorf("%s: not JSON: %w", what, err)
		}
		for _, part := range strings.Split(s.JSONPath, ".") {
			switch node := v.(type) {
			case map[string]any:
				v = node[part]
			case []any:
				i, err := strconv.Atoi(part)
				if err != nil || i < 0 || i >= len(node) {
					return "", fmt.Errorf("%s: json_path %q: bad index %q", what, s.JSONPath, part)
				}
				v = node[i]
			default:
				return "", fmt.Errorf("%s: json_path %q not found", what, s.JSONPath)
			}
		}
		out := strings.TrimSpace(fmt.Sprint(v))
		if v == nil || out == "" {
			return "", fmt.Errorf("%s: json_path %q empty", what, s.JSONPath)
		}
		return out, nil
	}
	if s.Regex == "" {
		return "", fmt.Errorf("%s: set regex or json_path", what)
	}
	re, err := regexp.Compile(s.Regex)
	if err != nil {
		return "", fmt.Errorf("%s: regex: %w", what, err)
	}
	m := re.FindSubmatch(body)
	if m == nil {
		return "", fmt.Errorf("%s: regex %q did not match", what, s.Regex)
	}
	if len(m) > 1 {
		return strings.TrimSpace(string(m[1])), nil
	}
	return strings.TrimSpace(string(m[0])), nil
}

func sub(tmpl, version string) string { return strings.ReplaceAll(tmpl, "{version}", version) }

var hex64 = regexp.MustCompile(`(?i)\b([0-9a-f]{64})\b`)

// checksumFor finds the SHA-256 for fileName in a vendor checksum document:
// the configured regex, else a "<hash>  <file>" line, else a lone hash.
func checksumFor(body []byte, s autoSource, fileName string) (string, error) {
	if s.Regex != "" || s.JSONPath != "" {
		v, err := extract(body, s, "sha256")
		if err != nil {
			return "", err
		}
		if !hex64.MatchString(v) || len(v) != 64 {
			return "", fmt.Errorf("sha256 source returned %q, not a SHA-256", v)
		}
		return strings.ToLower(v), nil
	}
	for _, line := range strings.Split(string(body), "\n") {
		if strings.Contains(line, fileName) {
			if m := hex64.FindStringSubmatch(line); m != nil {
				return strings.ToLower(m[1]), nil
			}
		}
	}
	if all := hex64.FindAllString(string(body), -1); len(all) == 1 {
		return strings.ToLower(all[0]), nil
	}
	return "", fmt.Errorf("no SHA-256 for %s in checksum document", fileName)
}

// fetchApp returns the new package_id, "" if this version was already sent.
func fetchApp(ctx context.Context, hc *http.Client, a autoApp, downloads, spec string, st autoState, dry bool) (id, ver string, err error) {
	id, ver, err = fetchAppInner(ctx, hc, a, downloads, spec, st, dry)
	return
}

func fetchAppInner(ctx context.Context, hc *http.Client, a autoApp, downloads, spec string, st autoState, dry bool) (string, string, error) {
	var body []byte
	var err error
	if a.Version.Redirect {
		body, err = redirectTarget(ctx, hc, a.Version.URL)
	} else {
		body, err = getSmall(ctx, hc, a.Version.URL)
	}
	if err != nil {
		return "", "", fmt.Errorf("version check: %w", err)
	}
	ver, err := extract(body, a.Version, "version")
	if err != nil {
		return "", "", err
	}
	if !verRe.MatchString(ver) {
		return "", ver, fmt.Errorf("version %q from vendor feed is not a plain version string", ver)
	}
	// The feed already announced this version earlier, but the download link
	// served an older build that we have already sent: don't re-download it.
	if seen := st.FeedSeen[a.Name]; seen != "" {
		if feedV, realV, ok := strings.Cut(seen, "="); ok && feedV == ver {
			if _, done := st.Done[a.Name+"-"+realV]; done {
				return "", realV, nil
			}
		}
	}
	id := a.Name + "-" + ver
	if _, done := st.Done[id]; done {
		return "", ver, nil
	}
	if dry {
		return id, ver, nil
	}
	dl := sub(a.DownloadURL, ver)
	name := sub(a.FileName, ver)
	if name == "" {
		u, _ := url.Parse(dl)
		name = filepath.Base(u.Path)
	}
	var sha string
	switch {
	case a.SHA256 != nil:
		sb, err := getSmall(ctx, hc, sub(a.SHA256.URL, ver))
		if err != nil {
			return "", ver, fmt.Errorf("checksum feed: %w", err)
		}
		if sha, err = checksumFor(sb, autoSource{Regex: sub(a.SHA256.Regex, ver), JSONPath: a.SHA256.JSONPath}, name); err != nil {
			return "", ver, err
		}
		if _, err := acquire.Download(ctx, hc, acquire.DownloadRequest{URL: dl, DestDir: downloads, FileName: name, SHA256: sha}); err != nil {
			return "", ver, err
		}
	case a.PkgSigner != "":
		if sha, err = downloadVerified(ctx, hc, dl, downloads, name, func(p string) error { return checkPkgSignature(p, a.PkgSigner) }); err != nil {
			return "", ver, err
		}
	default:
		if sha, err = downloadAuthenticode(ctx, hc, dl, downloads, name, a.AuthenticodeSigner); err != nil {
			return "", ver, err
		}
	}
	// Trust the installer, not the feed: label .pkg packages with the version
	// the file really contains (vendors' feeds can run ahead of the fixed
	// download link during staged rollouts).
	if a.Kind == "pkg" {
		realV, perr := acquire.PkgVersion(filepath.Join(downloads, name), a.PackageName)
		switch {
		case perr != nil:
			autoWarn(a.Name + ": could not read the version inside the .pkg (" + perr.Error() + "); using the feed version " + ver)
		case realV != ver && !pkgVerRe.MatchString(realV):
			autoWarn(fmt.Sprintf("%s: the installer reports version %q, which is not a valid package version; using the feed version %s", a.Name, realV, ver))
		case realV != ver:
			if !a.LabelFromPkg {
				autoWarn(fmt.Sprintf("%s: vendor feed says %s but the installer contains %s; labelled with the real version", a.Name, ver, realV))
			}
			st.FeedSeen[a.Name] = ver + "=" + realV
			if a.FileName != "" {
				newName := strings.ReplaceAll(sub(a.FileName, realV), "+", "_")
				if newName != name {
					if err := os.Rename(filepath.Join(downloads, name), filepath.Join(downloads, newName)); err == nil {
						name = newName
					}
				}
			}
			ver = realV
			id = a.Name + "-" + ver
			if _, done := st.Done[id]; done {
				return "", ver, nil
			}
		}
	}
	productCode := a.ProductCode
	if a.Kind == "msi" && a.ProductCodeFromMSI {
		if productCode, err = msiProductCode(filepath.Join(downloads, name)); err != nil {
			return "", ver, fmt.Errorf("read ProductCode: %w", err)
		}
	}
	sev := a.Severity
	if sev == "" {
		sev = "important"
	}
	// The verified file is already in place, so FetchURL reuses it and only
	// writes the spec entry (with its own schema validation).
	_, err = acquire.FetchURL(ctx, acquire.FetchURLOptions{URL: dl, SHA256: sha, FileName: name, PackageID: id, Title: a.Title + " " + ver,
		Vendor: a.Vendor, Kind: a.Kind, ProductCode: productCode, PackageName: a.PackageName, OS: a.OS, Version: ver, Severity: sev,
		Arch: a.Arch, MinBuild: a.MinBuild, MaxBuild: a.MaxBuild, OutDir: downloads, SpecPath: spec, HTTP: hc})
	if err != nil {
		return "", ver, err
	}
	return id, ver, nil
}

// downloadAuthenticode accepts a Windows installer only if its Authenticode
// signature is Valid and from the expected signer (Windows host only).
func downloadAuthenticode(ctx context.Context, hc *http.Client, rawURL, downloads, name, signer string) (string, error) {
	if runtime.GOOS != "windows" {
		return "", errors.New("authenticode_signer verification needs a Windows acquisition host; configure a sha256 checksum source instead")
	}
	return downloadVerified(ctx, hc, rawURL, downloads, name, func(p string) error {
		status, who, err := authenticode(p)
		if err != nil || !strings.EqualFold(status, "Valid") || !strings.Contains(strings.ToLower(who), strings.ToLower(signer)) {
			return fmt.Errorf("authenticode check failed (status %q, signer %q, want signer containing %q): %v", status, who, signer, err)
		}
		return nil
	})
}

// downloadVerified fetches a file with no published checksum into a holding
// area, runs verify on it, and only then moves it into downloads. Returns
// the SHA-256, which from here on protects the file end to end.
func downloadVerified(ctx context.Context, hc *http.Client, rawURL, downloads, name string, verify func(path string) error) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" {
		return "", fmt.Errorf("%q: only https downloads are allowed", rawURL)
	}
	final := filepath.Join(downloads, name)
	if _, err := os.Stat(final); err == nil {
		// Already verified on an earlier run (e.g. send failed): re-verify.
		if err := verify(final); err == nil {
			_, sha, err := manifest.HashFile(final)
			return sha, err
		}
		os.Remove(final)
	}
	hold := filepath.Join(downloads, ".unverified")
	os.MkdirAll(hold, 0o750)
	p := filepath.Join(hold, name)
	// Large installers (Office is 1+ GB) outlive the client's short total
	// timeout: allow up to 2 h per file, but abort if no data arrives for 2 min.
	big := *hc
	big.Timeout = 0
	dctx, cancel := context.WithTimeout(ctx, 2*time.Hour)
	defer cancel()
	req, _ := http.NewRequestWithContext(dctx, http.MethodGet, rawURL, nil)
	resp, err := big.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("GET %s: %s", rawURL, resp.Status)
	}
	f, err := os.Create(p)
	if err != nil {
		return "", err
	}
	_, err = io.Copy(f, io.LimitReader(&stallReader{r: resp.Body, cancel: cancel, idle: 2 * time.Minute}, acquire.MaxDownloadBytes))
	f.Close()
	if err != nil {
		os.Remove(p)
		return "", err
	}
	if err := verify(p); err != nil {
		os.Remove(p)
		return "", err
	}
	_, sha, err := manifest.HashFile(p)
	if err != nil {
		return "", err
	}
	return sha, os.Rename(p, final)
}

// redirectTarget returns the Location a URL redirects to (not followed).
func redirectTarget(ctx context.Context, hc *http.Client, rawURL string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" {
		return nil, fmt.Errorf("%q: only https URLs are allowed", rawURL)
	}
	c := *hc
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, rawURL, nil)
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode/100 != 3 || loc == "" {
		return nil, fmt.Errorf("HEAD %s: expected a redirect, got %s", rawURL, resp.Status)
	}
	return []byte(loc), nil
}

// checkPkgSignature verifies a macOS installer package with pkgutil: it must
// be signed with an Apple-issued Developer ID certificate, notarized, and the
// leaf certificate must contain signer (macOS acquisition host only).
func checkPkgSignature(path, signer string) error {
	if runtime.GOOS != "darwin" {
		return errors.New("pkg_signer verification needs a macOS acquisition host (pkgutil); configure a sha256 checksum source instead")
	}
	out, err := exec.Command("/usr/sbin/pkgutil", "--check-signature", path).CombinedOutput()
	return evalPkgSignature(string(out), err, signer)
}

// evalPkgSignature is the pure decision logic (unit-tested).
func evalPkgSignature(out string, runErr error, signer string) error {
	if runErr != nil {
		return fmt.Errorf("pkgutil --check-signature failed: %v: %s", runErr, strings.TrimSpace(out))
	}
	if !strings.Contains(out, "Status: signed by a developer certificate issued by Apple") {
		return fmt.Errorf("package is not signed with an Apple-issued Developer ID certificate")
	}
	if !strings.Contains(out, "Notarization: trusted by the Apple notary service") {
		return fmt.Errorf("package is not notarized by Apple")
	}
	leaf := ""
	for _, line := range strings.Split(out, "\n") {
		if t := strings.TrimSpace(line); strings.HasPrefix(t, "1. ") {
			leaf = strings.TrimPrefix(t, "1. ")
			break
		}
	}
	if leaf == "" || !strings.Contains(strings.ToLower(leaf), strings.ToLower(signer)) {
		return fmt.Errorf("package signed by %q, want %q", leaf, signer)
	}
	return nil
}

// sendStatus signs a status report for this run and sends it through the
// same one-way transfer, so the console can show acquisition health.
func sendStatus(c *autoConfig, rep *autoReport) error {
	host, _ := os.Hostname()
	outcome := "ok"
	switch {
	case rep.Error != "":
		outcome = "failed"
	case len(rep.Failures) > 0:
		outcome = "partial"
	}
	fin := rep.Finished
	if fin == "" {
		fin = autoNow().UTC().Format(time.RFC3339)
	}
	src := c.Source
	if src == "" {
		src = "acq-zone-1"
	}
	r := acqstatus.Report{Source: src, Host: host, Schedule: c.Schedule, StartedAt: rep.StartedAt, FinishedAt: fin, Outcome: outcome,
		Error: rep.Error, New: rep.New, Skipped: rep.Skipped, Superseded: rep.Superseded, Failures: rep.Failures, Warnings: rep.Warnings,
		BundleID: rep.BundleID, Sent: rep.Sent, Feeds: rep.Feeds}
	if r.Feeds == nil {
		r.Feeds = []acqstatus.Feed{}
	}
	k, err := openSigner(c.Key, c.Pub)
	if err != nil {
		return err
	}
	signed, err := acqstatus.Sign(r, k.KeyID(), k.Sign)
	if err != nil {
		return err
	}
	dir := filepath.Join(c.WorkDir, "status")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	p := filepath.Join(dir, fmt.Sprintf("acq-%s-%d%s", src, autoNow().UnixNano(), acqstatus.FileSuffix))
	b, _ := json.MarshalIndent(signed, "", "  ")
	if err := os.WriteFile(p, b, 0o640); err != nil {
		return err
	}
	a, err := adapterFor(c.Send)
	if err != nil {
		return err
	}
	if _, err := a.Send(p); err != nil {
		return err
	}
	rep.StatusSent = true
	return nil
}

// stallReader cancels the download if no bytes arrive for idle.
type stallReader struct {
	r      io.Reader
	cancel context.CancelFunc
	idle   time.Duration
	t      *time.Timer
}

func (s *stallReader) Read(p []byte) (int, error) {
	if s.t == nil {
		s.t = time.AfterFunc(s.idle, s.cancel)
	}
	n, err := s.r.Read(p)
	if n > 0 {
		s.t.Reset(s.idle)
	}
	if err != nil {
		s.t.Stop()
	}
	return n, err
}
