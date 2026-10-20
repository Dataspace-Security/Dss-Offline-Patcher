package main

// pmctl auto: unattended acquisition for the connected zone. One run checks
// Microsoft's monthly security release for the configured products and each
// configured third-party app for a new version, downloads and verifies
// everything new, builds signed bundles (one, or several when the pending
// packages exceed max_bundle_bytes / max_bundle_packages) and sends them
// through the transfer boundary. Packages are recorded as done right after
// the send of their bundle, so a failed run is simply retried by the next
// scheduled run.
//
// Nothing here installs anything: bundles land in quarantine on the isolated
// side and still need approval there.

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"offpatch/internal/acqpolicy"
	"offpatch/internal/acqrequest"
	"offpatch/internal/acqstatus"
	"offpatch/internal/acquire"
	"offpatch/internal/intel"
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

	// MaxBundleBytes / MaxBundlePackages cap one bundle below the isolated
	// server's max_bundle_bytes (32 GiB) and max_files (500); more pending
	// packages are split over several bundles, each with its own sequence.
	MaxBundleBytes    int64 `json:"max_bundle_bytes"`    // default 28 GiB
	MaxBundlePackages int   `json:"max_bundle_packages"` // default 450
	// RunTimeout bounds a whole run (default 6h); it then stops cleanly,
	// sends what is finished and reports the rest for the next run.
	RunTimeout Duration `json:"run_timeout"`
	// Retention (days; 0 = default 14, negative = keep forever): run
	// directories (bundles as built) and downloaded files of packages that
	// were sent that long ago.
	KeepRunsDays      int `json:"keep_runs_days"`
	KeepDownloadsDays int `json:"keep_downloads_days"`

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
	// ExpectedUBR: record expected_ubr (the build revision a Windows
	// cumulative update brings) in KB packages. Default off: agents up to
	// 0.6.2 refuse bundles with the field; enable only after every agent
	// runs 0.6.5 or later.
	ExpectedUBR bool `json:"expected_ubr"`

	// EXE installers (kind exe), verified by Authenticode in pure Go:
	// AuthenticodeRoots adds trust anchors (a PEM file) to the system roots
	// and the code-signing roots shipped with pmctl; ExeSigners, if set,
	// accepts only EXE installers whose verified signer CommonName is listed.
	AuthenticodeRoots string   `json:"authenticode_roots"`
	ExeSigners        []string `json:"exe_signers"`

	// ExeSignerPins: per package (winget id, or "vendor:<source id>") the
	// exact signer CN (and O) its installers must carry; overrides the
	// signer pmctl pinned on first use (signerpin.go).
	ExeSignerPins map[string]signerPinConfig `json:"exe_signer_pins"`
	// RequireRevocationCheck: refuse installers whose signing certificate's
	// CRL cannot be checked (default: record revocation "unknown").
	RequireRevocationCheck bool `json:"require_revocation_check"`

	// AllowedSourceHosts: the only hosts an auto-download policy may point
	// downloads at (winget index / manifests, catalog, MSRC, mirrors,
	// vendor-url), also for redirects. Exact names or "*.domain"; "default"
	// stands for the built-in official hosts (acquire.DefaultSourceHosts),
	// which also apply when this is not set. The policy cannot extend it.
	AllowedSourceHosts []string `json:"allowed_source_hosts"`
	// AllowedPrivateHosts: host names that may resolve to private/loopback
	// addresses (an internal mirror). Hosts in this file's own URLs
	// (catalog_url, msrc_url, winget_manifests_url, intel.winget_url, apps)
	// are allowed too; everything else is refused at dial time (SSRF).
	AllowedPrivateHosts []string `json:"allowed_private_hosts"`

	// PolicyPublicKeys pins the server's auto-download policy signing key
	// (base64 Ed25519, `pmserver policy-key`; S-4): policy files not signed
	// by one of them are refused. Empty: unsigned policies are accepted with
	// a warning in the status report (upgrades).
	PolicyPublicKeys []string `json:"policy_public_keys"`
	// VendorSHA256Pins: per vendor-url source id, the SHA-256 the operator
	// of this host confirmed. Where Authenticode cannot be checked (MSI/MSU
	// on a Linux acquisition host) a vendor-url source is downloaded only
	// when its expected_sha256 equals this pin (S-4).
	VendorSHA256Pins map[string]string `json:"vendor_sha256_pins"`

	// Advanced: alternative endpoints (tests, or an internal mirror).
	CatalogURL         string `json:"catalog_url"`
	MSRCURL            string `json:"msrc_url"`
	WingetManifestsURL string `json:"winget_manifests_url"` // default: the winget-pkgs repository

	// keepLastN: from the auto-download policy (limits.keep_last_n_versions).
	keepLastN int
	// net: the network guards (netpolicy.go), set by setupNet.
	net *netPolicy
	// policyPins: PolicyPublicKeys, parsed by loadAutoConfig.
	policyPins []ed25519.PublicKey
}

type autoMSProd struct {
	MSRCProduct    string `json:"msrc_product"`    // substring of the MSRC product name
	CatalogProduct string `json:"catalog_product"` // substring of the catalog title/products
	Arch           string `json:"arch"`            // x64|x86|arm64
	MinBuild       int    `json:"min_build"`
	MaxBuild       int    `json:"max_build"`
	Match          string `json:"match"`          // optional extra title filter
	PackageSuffix  string `json:"package_suffix"` // disambiguates IDs if two products share a KB
	// MinSeverity overrides microsoft.min_severity for this product (the
	// auto-download policy's "all" classification sets low).
	MinSeverity string `json:"min_severity"`
}

// idSuffix is PackageSuffix, or for a product pinned to one build that
// shares KB numbers with another (25H2 with 24H2), the build: so both
// builds' packages of one KB get different IDs.
func (p autoMSProd) idSuffix() string {
	if p.PackageSuffix == "" && p.MinBuild > 0 && p.MinBuild == p.MaxBuild {
		return acqpolicy.KBPackageSuffix(p.MSRCProduct, false, p.MinBuild)
	}
	return p.PackageSuffix
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
	ProductCodeFromMSI bool   `json:"product_code_from_msi"` // msi: read it from the file
	PackageName        string `json:"package_name"`          // deb/rpm/pkg
	MinBuild           int    `json:"min_build"`
	MaxBuild           int    `json:"max_build"`
	// WingetID: the app's winget package id, if it has one: lists it in the
	// console's Library (update intelligence) with its winget details.
	WingetID string `json:"winget_id"`
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
	// RequestSent: acquisition request id → package id → bundle id, for the
	// requests still waiting (one with a failed item is retried): what was
	// already sent for that request, so a retry does not send it again.
	RequestSent map[string]map[string]string `json:"request_sent,omitempty"`
	// Library: winget id@version → installer and description details (see
	// library.go); only the newest version of each package is kept.
	Library map[string]intel.Resolved `json:"library,omitempty"`
	// Requested: every winget id an acquisition request asked for → the
	// newest such request's created_at (the Library keeps describing it).
	Requested map[string]string `json:"requested_apps,omitempty"`
	// WindowsUBR: "<KB>/<build>" → build revision, from update intelligence,
	// for expected_ubr when the catalog title of a KB does not state it.
	WindowsUBR map[string]int `json:"windows_ubr,omitempty"`
	// Families: package id → policy app ("winget:<id>/<arch>") or vendor
	// source ("vendor:<id>"), for limits.keep_last_n_versions.
	Families map[string]string `json:"families,omitempty"`
	// PolicyVersion: the newest auto-download policy_version accepted
	// (policy.go refuses older files and jumps beyond maxPolicyJump).
	PolicyVersion int `json:"policy_version,omitempty"`
}

type autoDone struct {
	SHA256   string `json:"sha256"`
	BundleID string `json:"bundle_id"`
	SentAt   string `json:"sent_at"`
	File     string `json:"file,omitempty"` // downloads/<file>, for retention
}

type autoReport struct {
	StartedAt  string                 `json:"started_at"`
	Finished   string                 `json:"finished_at"`
	DryRun     bool                   `json:"dry_run"`
	New        []string               `json:"new_packages"`
	Skipped    int                    `json:"already_sent"`
	Superseded []string               `json:"skipped_superseded,omitempty"`
	Failures   map[string]string      `json:"failures"`
	Bundle     string                 `json:"bundle,omitempty"`    // last bundle sent
	BundleID   string                 `json:"bundle_id,omitempty"` // every bundle sent, comma-separated
	Bundles    []string               `json:"bundles,omitempty"`
	Sent       bool                   `json:"sent"`
	Warnings   []string               `json:"warnings,omitempty"`
	Feeds      []acqstatus.Feed       `json:"feeds"`
	Items      []acqstatus.ItemResult `json:"items,omitempty"` // per requested item
	Error      string                 `json:"error,omitempty"`
	StatusSent bool                   `json:"status_report_sent"`

	// Auto-download policy (policy.go).
	PolicyVersion   int                      `json:"policy_version,omitempty"`
	PolicySHA256    string                   `json:"policy_sha256,omitempty"`
	PolicyEditedBy  string                   `json:"policy_edited_by,omitempty"`
	PolicyAppliedAt string                   `json:"policy_applied_at,omitempty"`
	PolicyError     string                   `json:"policy_error,omitempty"`
	PolicySignature string                   `json:"policy_signature,omitempty"`
	Sources         []acqstatus.SourceResult `json:"sources,omitempty"`
	RunRequest      string                   `json:"run_request,omitempty"`
	Defaults        *acqpolicy.Base          `json:"-"` // acquire.json as policy entries (status report only)
}

// Hooks overridable in tests.
var (
	autoHTTP = acquire.DefaultHTTPClient
	autoNow  = time.Now
)

const (
	exitPartial = 2
	// exitSkipped: another run holds the lock; nothing was done. The systemd
	// units list it in SuccessExitStatus (an hourly run that finds the
	// previous one still downloading is not a failure).
	exitSkipped = 3

	defaultMaxBundleBytes    = 28 << 30
	defaultMaxBundlePackages = 450
	defaultRunTimeout        = 6 * time.Hour
	defaultKeepDays          = 14
)

func autoCmd(args []string) error {
	fs := flag.NewFlagSet("auto", flag.ExitOnError)
	cfgPath := fs.String("config", "acquire.json", "auto-acquisition config")
	dry := fs.Bool("dry-run", false, "list what would be fetched; download and send nothing")
	reqDir := fs.String("requests", "", "directory of acquisition requests exported from the console (default: \"requests\" in the config)")
	onlyReq := fs.Bool("only-requests", false, "handle only the acquisition requests (skip Microsoft, apps and intelligence); bundles and the status report are sent as usual")
	fs.Parse(args)
	// SIGINT/SIGTERM (systemd stop, Ctrl-C): stop fetching, keep what was
	// delivered recorded in state.json, and still send the status report.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	rep, err := runAutoRequests(ctx, *cfgPath, *dry, *reqDir, *onlyReq)
	if errors.Is(err, errRunInProgress) {
		fmt.Fprintf(os.Stderr, "skipped: %v; this run did nothing (exit %d)\n", err, exitSkipped)
		stop()
		os.Exit(exitSkipped)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	if err != nil {
		return err
	}
	if partialRun(&rep) {
		fmt.Fprintf(os.Stderr, "%d item(s) or feed(s) failed; they will be retried next run\n", len(rep.Failures)+len(failedFeeds(rep.Feeds)))
		stop()
		os.Exit(exitPartial)
	}
	return nil
}

// partialRun: some item failed, or a feed could not be read (an unread
// feed must never look like "nothing new").
func partialRun(rep *autoReport) bool {
	return len(rep.Failures) > 0 || len(failedFeeds(rep.Feeds)) > 0
}

func failedFeeds(feeds []acqstatus.Feed) []string {
	var out []string
	for _, f := range feeds {
		if f.Status == "failed" {
			out = append(out, f.Type+":"+f.Name)
		}
	}
	return out
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
	c.AuthenticodeRoots = abs(c.AuthenticodeRoots)
	if c.policyPins, err = acqpolicy.ParsePins(c.PolicyPublicKeys); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	for id, sum := range c.VendorSHA256Pins {
		if len(sum) != 64 || strings.Trim(strings.ToLower(sum), "0123456789abcdef") != "" {
			return nil, fmt.Errorf("config: vendor_sha256_pins[%q]: 64 hexadecimal characters", id)
		}
	}
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
	if c.MaxBundleBytes == 0 {
		c.MaxBundleBytes = defaultMaxBundleBytes
	}
	if c.MaxBundleBytes < 0 {
		return nil, errors.New("config: max_bundle_bytes must be positive")
	}
	if c.MaxBundlePackages == 0 {
		c.MaxBundlePackages = defaultMaxBundlePackages
	}
	if c.MaxBundlePackages < 0 || c.MaxBundlePackages > manifest.MaxPackages {
		return nil, fmt.Errorf("config: max_bundle_packages must be 1..%d", manifest.MaxPackages)
	}
	if c.RunTimeout.Duration <= 0 {
		c.RunTimeout.Duration = defaultRunTimeout
	}
	if c.KeepRunsDays == 0 {
		c.KeepRunsDays = defaultKeepDays
	}
	if c.KeepDownloadsDays == 0 {
		c.KeepDownloadsDays = defaultKeepDays
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
			return nil, fmt.Errorf("config: apps[%d] (%s) needs the MSI's real product_code (not a placeholder), or product_code_from_msi", i, a.Name)
		}
		if a.WingetID != "" && !acqrequest.ValidWingetID(a.WingetID) {
			return nil, fmt.Errorf("config: apps[%d] (%s): winget_id %q is not a winget package id", i, a.Name, a.WingetID)
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

// loadState reads work_dir/state.json. A missing file is a first run; an
// unreadable or corrupt one stops the run, because treating every package
// as new would fetch and send everything again.
func loadState(path string) (autoState, error) {
	st := autoState{}
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return st, fmt.Errorf("state %s: %w", path, err)
	default:
		if err := json.Unmarshal(b, &st); err != nil {
			return st, fmt.Errorf("%s is corrupt (%v); refusing to run, because every package would look new and be fetched and sent again: restore it from a backup or repair the JSON", path, err)
		}
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
	if st.RequestSent == nil {
		st.RequestSent = map[string]map[string]string{}
	}
	if st.Library == nil {
		st.Library = map[string]intel.Resolved{}
	}
	if st.Requested == nil {
		st.Requested = map[string]string{}
	}
	if st.WindowsUBR == nil {
		st.WindowsUBR = map[string]int{}
	}
	if st.Families == nil {
		st.Families = map[string]string{}
	}
	return st, nil
}

func saveJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, b, 0o600)
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
	return runAutoRequests(ctx, cfgPath, dry, "", false)
}

// runAutoRequests is runAuto with the requests directory overridden
// (pmctl auto -requests) and, with onlyRequests (pmctl auto
// -only-requests), only the acquisition requests handled: no Microsoft
// updates, configured apps or intelligence. Used by the role-all request
// watcher so a queued request is served without waiting for the schedule.
func runAutoRequests(ctx context.Context, cfgPath string, dry bool, requestsDir string, onlyRequests bool) (rep autoReport, err error) {
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
	if err := setExeTrust(c.AuthenticodeRoots, c.ExeSigners); err != nil {
		return rep, err
	}
	if err := setupNet(c); err != nil {
		return rep, err
	}
	if onlyRequests && c.Requests == "" {
		return rep, fmt.Errorf("-only-requests: no requests directory (set \"requests\" in %s or pass -requests)", cfgPath)
	}
	ctx, cancel := context.WithTimeout(ctx, c.RunTimeout.Duration)
	defer cancel()
	downloads := filepath.Join(c.WorkDir, "downloads")
	if err := os.MkdirAll(downloads, 0o750); err != nil {
		return rep, err
	}
	unlock, err := acquireLock(c.WorkDir, c.RunTimeout.Duration)
	if err != nil {
		return rep, err
	}
	defer unlock()
	statePath := filepath.Join(c.WorkDir, "state.json")
	st, err := loadState(statePath)
	if err != nil {
		return rep, err
	}
	// A fresh run directory every time (never reuse an older spec.json).
	runs := filepath.Join(c.WorkDir, "runs")
	if err := os.MkdirAll(runs, 0o750); err != nil {
		return rep, err
	}
	runDir, err := os.MkdirTemp(runs, autoNow().UTC().Format(runDirTimeFormat)+"-")
	if err != nil {
		return rep, err
	}
	spec := filepath.Join(runDir, "spec.json")

	// ---- auto-download policy from the console, merged over acquire.json ----
	pol := loadPolicy(c, dry, &rep, &st)
	applyPolicy(c, pol)
	c.keepLastN = pol.keepLastN
	if pol.runID != "" && onlyRequests {
		onlyRequests = false
		rep.Warnings = append(rep.Warnings, "full run requested from the console ("+pol.runID+" by "+pol.runBy+")")
	}
	hc := withBudget(c.guarded(autoHTTP()), pol.maxBytes)
	pins, err := loadSignerPins(filepath.Join(c.WorkDir, signerPinsFile))
	if err != nil {
		return rep, err
	}
	fail := func(id string, err error) {
		rep.Failures[id] = err.Error()
		st.Failed[id] = err.Error()
	}
	added := func(id string) {
		if !slices.Contains(rep.New, id) {
			rep.New = append(rep.New, id)
		}
		delete(st.Failed, id)
	}

	if onlyRequests {
		rep.Warnings = append(rep.Warnings, "requests-only run (-only-requests): Microsoft, application and intelligence feeds were not checked")
	}

	// ---- Microsoft security updates ----
	if m := c.Microsoft; !onlyRequests && m != nil && len(m.Products) > 0 {
		fetchMicrosoft(&msRun{ctx: ctx, c: c, hc: c.msClient(hc), downloads: downloads, spec: spec, st: st, dry: dry, rep: &rep, fail: fail, added: added})
	}
	windowsResults(pol, rep.Feeds)

	// ---- third-party applications ----
	for _, a := range c.Apps {
		if onlyRequests {
			break
		}
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

	// ---- policy winget apps and vendor downloads ----
	rr := &requestRun{ctx: ctx, c: c, hc: hc, downloads: downloads, spec: spec, st: st, dry: dry, rep: &rep,
		fail: fail, added: added, outcomes: map[string]itemOutcome{}, pins: pins}
	if !onlyRequests {
		fetchPolicyApps(rr, pol)
		fetchVendorSources(rr, pol)
	}

	// ---- acquisition requests carried over from the console ----
	var reqs []*loadedRequest
	if c.Requests != "" {
		reqs = processRequests(rr, c.Requests)
	}

	defer func() {
		rep.Finished = autoNow().UTC().Format(time.RFC3339)
		// Done with a request once its packages are on their way (or there
		// was nothing new to send); failed items keep it for the next run.
		requestsDone := !dry && err == nil && (rep.Sent || len(rep.New) == 0)
		rep.Items = finishItems(reqs, st, &rep, dry, err, requestsDone)
		// State first: whatever happens below, delivered packages stay done.
		if serr := saveJSON(statePath, st); serr != nil && err == nil {
			err = fmt.Errorf("state not saved: %w", serr)
		}
		if !dry {
			if serr := pins.save(); serr != nil {
				rep.Warnings = append(rep.Warnings, "installer signer pins not saved: "+serr.Error())
			}
		}
		if err != nil {
			rep.Error = err.Error()
		}
		if requestsDone {
			archiveRequests(c.Requests, reqs, &rep)
		}
		if !dry {
			archiveRuns(c.Requests, pol)
		}
		policyReport(&rep, pol, cfgPath)
		if !dry && !onlyRequests && c.Intel != nil && !c.Intel.Disabled {
			rep.Feeds = append(rep.Feeds, intelFeed(ctx, c, &rep, &st))
			// The Library cache and Windows build revisions it updated.
			if serr := saveJSON(statePath, st); serr != nil && err == nil {
				err = fmt.Errorf("state not saved: %w", serr)
				rep.Error = err.Error()
			}
		}
		if !dry {
			applyRetention(c, st, runDir, specFiles(spec), &rep)
		}
		if !dry {
			if serr := sendStatus(c, &rep); serr != nil {
				rep.Warnings = append(rep.Warnings, "status report not sent: "+serr.Error())
			}
		}
		if lerr := appendLine(filepath.Join(c.WorkDir, "auto-log.jsonl"), rep); lerr != nil {
			fmt.Fprintln(os.Stderr, "warning: auto-log.jsonl:", lerr)
		}
	}()
	if dry || len(rep.New) == 0 {
		os.RemoveAll(runDir)
		return rep, nil
	}
	return rep, deliver(&deliveryRun{ctx: ctx, c: c, runDir: runDir, spec: spec, st: st, statePath: statePath, rep: &rep, fail: fail})
}

// intelFeed sends update intelligence and reports it as a feed: failed if
// nothing could be sent or it is incomplete (a feed that was not read must
// not look up to date).
func intelFeed(ctx context.Context, c *autoConfig, rep *autoReport, st *autoState) acqstatus.Feed {
	d, lib, ierr := sendIntel(ctx, c, st)
	rep.Warnings = append(rep.Warnings, d.Warnings...)
	rep.Warnings = append(rep.Warnings, lib.warnings...) // never fail the feed: the Library only describes
	f := acqstatus.Feed{Type: "intel", Name: "update intelligence", Status: "up_to_date", Detail: d.AppsSource}
	if lib.ran {
		f.Detail = strings.TrimPrefix(f.Detail+"; "+lib.summary(), "; ")
	}
	switch {
	case ierr != nil:
		rep.Warnings = append(rep.Warnings, "update intelligence not sent: "+ierr.Error())
		f.Status, f.Detail = "failed", "not sent: "+ierr.Error()
	default:
		f.LatestVersion = fmt.Sprintf("%d Windows builds, %d apps", len(d.Windows), len(d.Apps))
		if lib.ran {
			f.LatestVersion += fmt.Sprintf(", %d in the library", len(d.Resolved))
		}
		if len(d.Warnings) > 0 {
			f.Status, f.Detail = "failed", "sent incomplete: "+strings.Join(d.Warnings, "; ")
		}
	}
	return f
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
		if sha, _, err = downloadAuthenticode(ctx, hc, dl, downloads, name, a.AuthenticodeSigner); err != nil {
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
// signature is Valid and from exactly the expected signer: signer is a CN
// ("Google LLC") or a subject DN whose CN and O must both match
// ("CN=Google LLC, O=Google LLC"); never a substring (finding M-5). MSI and
// MSU files need a Windows acquisition host; EXE files verify anywhere.
func downloadAuthenticode(ctx context.Context, hc *http.Client, rawURL, downloads, name, signer string) (string, signerInfo, error) {
	if runtime.GOOS != "windows" && !authenticodeAnywhere && !strings.EqualFold(filepath.Ext(name), ".exe") {
		return "", signerInfo{}, errors.New("authenticode_signer verification needs a Windows acquisition host; configure a sha256 checksum source instead")
	}
	want := parseSignerSpec(signer)
	var got signerInfo
	sha, err := downloadVerified(ctx, hc, rawURL, downloads, name, func(p string) error {
		info, err := signerOfFile(p)
		if err != nil {
			return fmt.Errorf("authenticode check failed: %w", err)
		}
		if !want.matches(info.signerName) {
			return fmt.Errorf("%w: authenticode check failed: signed by %s, want exactly %s", errExeSignature, info.signerName, want)
		}
		got = info
		return nil
	})
	return sha, got, err
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
	if resp.ContentLength > 0 {
		if err := acquire.CheckDiskSpace(downloads, resp.ContentLength); err != nil {
			return "", err
		}
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
	if leaf == "" || !pkgSignerMatches(leaf, signer) {
		return fmt.Errorf("package signed by %q, want exactly %q", leaf, signer)
	}
	return nil
}

// pkgSignerMatches compares the leaf line pkgutil prints ("Developer ID
// Installer: Google LLC (EQHXZ8M8AV)") with pkg_signer as whole values, never
// as a substring (finding M-5): pkg_signer may be the full line, the name
// with the Team ID ("Google LLC (EQHXZ8M8AV)"), or the name alone.
func pkgSignerMatches(leaf, signer string) bool {
	leaf, signer = cleanName(leaf), cleanName(signer)
	if signer == "" {
		return false
	}
	nameTeam := leaf
	if _, rest, ok := strings.Cut(leaf, ": "); ok {
		nameTeam = rest
	}
	name := nameTeam
	if i := strings.LastIndex(nameTeam, " ("); i > 0 && strings.HasSuffix(nameTeam, ")") {
		name = nameTeam[:i]
	}
	for _, v := range []string{leaf, nameTeam, name} {
		if strings.EqualFold(v, signer) {
			return true
		}
	}
	return false
}

// sendStatus signs a status report for this run and sends it through the
// same one-way transfer, so the console can show acquisition health.
func sendStatus(c *autoConfig, rep *autoReport) error {
	host, _ := os.Hostname()
	outcome := "ok"
	switch {
	case rep.Error != "":
		outcome = "failed"
	case partialRun(rep):
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
		BundleID: rep.BundleID, Sent: rep.Sent, Feeds: rep.Feeds, Items: rep.Items,
		PolicyVersion: rep.PolicyVersion, PolicySHA256: rep.PolicySHA256, PolicyEditedBy: rep.PolicyEditedBy, PolicyAppliedAt: rep.PolicyAppliedAt,
		PolicyError: rep.PolicyError, PolicySignature: rep.PolicySignature, Sources: rep.Sources, Defaults: rep.Defaults, RunRequest: rep.RunRequest}
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
