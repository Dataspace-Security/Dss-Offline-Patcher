// Package acqpolicy is the "auto-download policy": what the acquisition
// zone (pmctl auto) downloads on every run, edited by the super admin in the
// console (Settings → Auto-download) and stored versioned on the server.
//
// acquire.json (written by the installer) stays the base: the policy is
// merged over it on every run. Policy entries add Windows products, winget
// apps and vendor downloads, override download sources (mirrors), or switch
// off something acquire.json configures.
//
// Delivery is the same channel as acquisition requests: the server writes
// policy-<version>.json into acquisition_requests_dir (single-server
// layout), or the super admin downloads the file and carries it to the
// acquisition host's requests folder (two-machine layout). The file carries
// the editor and a SHA-256 of the policy content; pmctl validates it as
// strictly as the server does and never trusts it beyond what the policy
// can express: every download is still verified (vendor SHA-256, winget
// manifest hash, Microsoft catalog hash or Authenticode signer) and arrives
// on the isolated side as a signed bundle in quarantine.
package acqpolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"

	"offpatch/internal/acqrequest"
)

const (
	Format  = "offpatch.acquisition-policy"
	Version = 1
	// RunFormat marks a "run now" request (see RunRequest).
	RunFormat  = "offpatch.acquisition-run"
	RunVersion = 1

	// FilePrefix / RunPrefix: file names in the requests folder.
	FilePrefix = "policy-"
	RunPrefix  = "run-"

	MaxSize       = 1 << 20
	MaxWindows    = 50
	MaxApps       = 500
	MaxSources    = 100
	MaxURLLen     = 2048
	maxText       = 256
	MaxDownloadGB = 10000
	MaxKeepLast   = 100
)

// Source types.
const (
	SourceWinget         = "winget"
	SourceCatalog        = "microsoft-catalog"
	SourceMSRC           = "msrc"
	SourceVendorURL      = "vendor-url"
	SourceInternalMirror = "internal-mirror"
)

// SourceTypes lists the source types in display order.
var SourceTypes = []string{SourceWinget, SourceCatalog, SourceMSRC, SourceVendorURL, SourceInternalMirror}

// Upstreams an internal mirror can replace.
const (
	UpstreamWingetIndex     = "winget-index"
	UpstreamWingetManifests = "winget-manifests"
	UpstreamCatalog         = "microsoft-catalog"
	UpstreamMSRC            = "msrc"
)

// Upstreams lists what an internal mirror can stand in for.
var Upstreams = []string{UpstreamWingetIndex, UpstreamWingetManifests, UpstreamCatalog, UpstreamMSRC}

// Windows update classifications.
const (
	// ClassSecurity: Microsoft's monthly security release at the minimum
	// severity in acquire.json (important when acquire.json has none).
	ClassSecurity = "security"
	// ClassAll: every severity of the monthly security release.
	ClassAll = "all"
)

// Policy is the editable content (what is versioned and hashed).
type Policy struct {
	Windows []Windows `json:"windows"`
	Apps    []App     `json:"apps"`
	Sources []Source  `json:"sources"`
	Limits  Limits    `json:"limits"`
}

// Windows is one Windows release whose cumulative updates are downloaded.
type Windows struct {
	Product        string `json:"product"` // "Windows 11 Version 24H2"
	Build          int    `json:"build"`   // 26100
	Arch           string `json:"arch"`    // x64 | x86 | arm64
	Classification string `json:"classification"`
	Enabled        bool   `json:"enabled"`
}

// App is one application kept at its newest version.
type App struct {
	Source  string   `json:"source"` // winget
	ID      string   `json:"id"`     // winget package id
	Arch    []string `json:"arch"`
	Channel string   `json:"channel"` // latest
	Enabled bool     `json:"enabled"`
	Note    string   `json:"note"`
}

// Source is a download source. Which fields apply depends on Type:
//   - winget: URL overrides the community index (source2.msix) and
//     ManifestsURL the winget-pkgs manifests base, e.g. for a mirror.
//   - microsoft-catalog, msrc: URL optionally overrides the service base.
//     Switching either off stops the Windows (Microsoft) downloads.
//   - vendor-url: one vendor installer at a fixed HTTPS URL; Name, URL,
//     Kind (msi | msu), Version and ExpectedSHA256 or Signer are required.
//   - internal-mirror: URL is the HTTPS base of a bank-approved mirror
//     that stands in for the upstream named by Replaces.
type Source struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Enabled bool   `json:"enabled"`
	AddedBy string `json:"added_by"`
	Note    string `json:"note"`

	URL          string `json:"url,omitempty"`
	ManifestsURL string `json:"manifests_url,omitempty"` // winget only

	// vendor-url
	Name           string `json:"name,omitempty"`
	Vendor         string `json:"vendor,omitempty"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
	Signer         string `json:"signer,omitempty"` // Authenticode subject (Windows acquisition host only)
	Kind           string `json:"kind,omitempty"`   // msi | msu
	Version        string `json:"version,omitempty"`
	ProductCode    string `json:"product_code,omitempty"` // msi; read from the file when empty
	KB             string `json:"kb,omitempty"`           // msu
	Arch           string `json:"arch,omitempty"`

	// internal-mirror
	Replaces string `json:"replaces,omitempty"`
}

// Limits bound what one run does.
type Limits struct {
	// MaxDownloadGBPerRun stops further downloads in a run once this much
	// was downloaded (0 = no limit); the rest follows on the next run.
	MaxDownloadGBPerRun int `json:"max_download_gb_per_run"`
	// KeepLastNVersions keeps the downloaded files of only the newest N
	// sent versions of each policy app and vendor download (0 = keep them
	// for keep_downloads_days as before).
	KeepLastNVersions int `json:"keep_last_n_versions"`
}

// File is the document delivered to the acquisition zone.
type File struct {
	Format        string `json:"format"`
	Version       int    `json:"version"`
	PolicyVersion int    `json:"policy_version"`
	EditedBy      string `json:"edited_by"`
	EditedAt      string `json:"edited_at"`
	// SHA256 is the hex SHA-256 of Canonical(Policy).
	SHA256 string `json:"sha256"`
	Policy Policy `json:"policy"`
}

// FileName is the file name of a policy version in the requests folder.
func FileName(version int) string { return fmt.Sprintf("%s%06d.json", FilePrefix, version) }

// RunRequest asks the downloader for a full run now ("Run now").
type RunRequest struct {
	Format      string `json:"format"`
	Version     int    `json:"version"`
	RunID       string `json:"run_id"`
	RequestedBy string `json:"requested_by"`
	RequestedAt string `json:"requested_at"`
}

var (
	productRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 .()+-]{0,79}$`)
	sourceIDRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)
	sha256Re    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	pkgVersion  = regexp.MustCompile(`^[0-9]+(\.[0-9]+){1,3}([-+][A-Za-z0-9.]+)?$`)
	runIDRe     = regexp.MustCompile(`^run-[A-Za-z0-9._-]{1,76}$`)
	secretQuery = regexp.MustCompile(`(?i)(token|key|secret|passw|pwd|auth|sig|credential|session)`)
	arches      = map[string]bool{"x64": true, "x86": true, "arm64": true}
)

// Problems collects validation errors.
type Problems []string

func (p Problems) Error() string { return strings.Join(p, "; ") }

func validText(s string, max int) bool {
	if len(s) > max {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// CheckURL accepts only https URLs with a host, no credentials (user info,
// or query parameters that look like tokens or keys) and no fragment.
func CheckURL(raw string) error {
	if raw == "" {
		return errors.New("is empty")
	}
	if len(raw) > MaxURLLen {
		return fmt.Errorf("is longer than %d characters", MaxURLLen)
	}
	if !validText(raw, MaxURLLen) || strings.ContainsAny(raw, " \\") {
		return errors.New("contains spaces or control characters")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("is not a URL")
	}
	if u.Scheme != "https" {
		return errors.New("must start with https://")
	}
	if u.Host == "" || u.Hostname() == "" {
		return errors.New("has no host name")
	}
	if u.User != nil {
		return errors.New("must not contain a user name or password")
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return errors.New("must not contain a #fragment")
	}
	for k := range u.Query() {
		if secretQuery.MatchString(k) {
			return fmt.Errorf("must not contain credentials (query parameter %q)", k)
		}
	}
	return nil
}

// Normalize trims, lower-cases and defaults fields, then validates.
// Normalizing a normalized policy changes nothing.
func (p *Policy) Normalize() error {
	var errs Problems
	bad := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }
	if p.Windows == nil {
		p.Windows = []Windows{}
	}
	if p.Apps == nil {
		p.Apps = []App{}
	}
	if p.Sources == nil {
		p.Sources = []Source{}
	}
	if len(p.Windows) > MaxWindows {
		bad("windows: at most %d entries", MaxWindows)
	}
	if len(p.Apps) > MaxApps {
		bad("apps: at most %d entries", MaxApps)
	}
	if len(p.Sources) > MaxSources {
		bad("sources: at most %d entries", MaxSources)
	}

	seenW := map[string]bool{}
	for i := range p.Windows {
		w := &p.Windows[i]
		at := fmt.Sprintf("windows[%d]", i)
		w.Product = strings.Join(strings.Fields(w.Product), " ")
		w.Arch = strings.ToLower(strings.TrimSpace(w.Arch))
		w.Classification = strings.ToLower(strings.TrimSpace(w.Classification))
		if w.Classification == "" {
			w.Classification = ClassSecurity
		}
		if !productRe.MatchString(w.Product) {
			bad("%s.product %q: a Windows release name like \"Windows 11 Version 24H2\"", at, w.Product)
		}
		if w.Build < 1 || w.Build > 99999 {
			bad("%s.build: a Windows build number like 26100", at)
		}
		if !arches[w.Arch] {
			bad("%s.arch: x64, x86 or arm64", at)
		}
		if w.Classification != ClassSecurity && w.Classification != ClassAll {
			bad("%s.classification: security or all", at)
		}
		k := strings.ToLower(w.Product) + "/" + fmt.Sprint(w.Build) + "/" + w.Arch
		if seenW[k] {
			bad("%s: %s %d %s is listed twice", at, w.Product, w.Build, w.Arch)
		}
		seenW[k] = true
	}

	seenA := map[string]bool{}
	for i := range p.Apps {
		a := &p.Apps[i]
		at := fmt.Sprintf("apps[%d]", i)
		a.Source = strings.ToLower(strings.TrimSpace(a.Source))
		if a.Source == "" {
			a.Source = SourceWinget
		}
		a.ID = strings.TrimSpace(a.ID)
		a.Channel = strings.ToLower(strings.TrimSpace(a.Channel))
		if a.Channel == "" {
			a.Channel = "latest"
		}
		a.Note = strings.TrimSpace(a.Note)
		if a.Source != SourceWinget {
			bad("%s.source: only winget apps are supported", at)
		}
		if !acqrequest.ValidWingetID(a.ID) {
			bad("%s.id %q: not a winget package id (like Google.Chrome)", at, a.ID)
		}
		if a.Channel != "latest" {
			bad("%s.channel: only latest is supported", at)
		}
		if !validText(a.Note, maxText) {
			bad("%s.note: at most %d characters, no control characters", at, maxText)
		}
		arch := []string{}
		for _, ar := range a.Arch {
			ar = strings.ToLower(strings.TrimSpace(ar))
			if !arches[ar] {
				bad("%s.arch %q: x64, x86 or arm64", at, ar)
				continue
			}
			if !contains(arch, ar) {
				arch = append(arch, ar)
			}
		}
		if len(arch) == 0 {
			bad("%s.arch: choose at least one of x64, x86, arm64", at)
		}
		a.Arch = arch
		if k := strings.ToLower(a.ID); seenA[k] {
			bad("%s: %s is listed twice", at, a.ID)
		} else {
			seenA[k] = true
		}
	}

	seenS := map[string]bool{}
	single := map[string]string{} // type or mirror target → id of the enabled one
	for i := range p.Sources {
		s := &p.Sources[i]
		at := fmt.Sprintf("sources[%d]", i)
		normalizeSource(s)
		if !sourceIDRe.MatchString(s.ID) {
			bad("%s.id %q: 1-41 lower-case letters, digits or '-'", at, s.ID)
		} else if seenS[s.ID] {
			bad("%s.id %q is used twice", at, s.ID)
		}
		seenS[s.ID] = true
		if !validText(s.AddedBy, maxText) || !validText(s.Note, maxText) {
			bad("%s: added_by / note at most %d characters, no control characters", at, maxText)
		}
		for _, e := range checkSource(*s) {
			bad("%s (%s): %s", at, s.ID, e)
		}
		if !s.Enabled {
			continue
		}
		key := s.Type
		switch s.Type {
		case SourceVendorURL:
			key = ""
		case SourceInternalMirror:
			key = "mirror:" + s.Replaces
		}
		if key != "" {
			if prev, dup := single[key]; dup {
				bad("%s (%s): only one enabled %s source is allowed (%s is enabled too)", at, s.ID, strings.TrimPrefix(key, "mirror:"), prev)
			}
			single[key] = s.ID
		}
	}

	if p.Limits.MaxDownloadGBPerRun < 0 || p.Limits.MaxDownloadGBPerRun > MaxDownloadGB {
		bad("limits.max_download_gb_per_run: 0 (no limit) to %d", MaxDownloadGB)
	}
	if p.Limits.KeepLastNVersions < 0 || p.Limits.KeepLastNVersions > MaxKeepLast {
		bad("limits.keep_last_n_versions: 0 (keep by age) to %d", MaxKeepLast)
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func normalizeSource(s *Source) {
	trim := func(p *string) { *p = strings.TrimSpace(*p) }
	for _, f := range []*string{&s.ID, &s.AddedBy, &s.Note, &s.URL, &s.ManifestsURL, &s.Name, &s.Vendor, &s.Signer, &s.Version, &s.ProductCode} {
		trim(f)
	}
	s.Type = strings.ToLower(strings.TrimSpace(s.Type))
	s.Kind = strings.ToLower(strings.TrimSpace(s.Kind))
	s.Arch = strings.ToLower(strings.TrimSpace(s.Arch))
	s.Replaces = strings.ToLower(strings.TrimSpace(s.Replaces))
	s.ExpectedSHA256 = strings.ToLower(strings.TrimSpace(s.ExpectedSHA256))
	s.KB = strings.ToUpper(strings.TrimSpace(s.KB))
	s.ProductCode = strings.ToUpper(s.ProductCode)
}

// checkSource returns the type-specific problems of a normalized source.
func checkSource(s Source) []string {
	var out []string
	urlErr := func(field, v string, required bool) {
		if v == "" {
			if required {
				out = append(out, field+" is required")
			}
			return
		}
		if err := CheckURL(v); err != nil {
			out = append(out, field+" "+err.Error())
		}
	}
	unused := func(fields map[string]string) {
		for name, v := range fields {
			if v != "" {
				out = append(out, name+" does not apply to a "+s.Type+" source")
			}
		}
	}
	switch s.Type {
	case SourceWinget:
		urlErr("url", s.URL, false)
		urlErr("manifests_url", s.ManifestsURL, false)
		unused(map[string]string{"name": s.Name, "expected_sha256": s.ExpectedSHA256, "signer": s.Signer, "kind": s.Kind, "version": s.Version,
			"product_code": s.ProductCode, "kb": s.KB, "replaces": s.Replaces, "vendor": s.Vendor, "arch": s.Arch})
	case SourceCatalog, SourceMSRC:
		urlErr("url", s.URL, false)
		unused(map[string]string{"manifests_url": s.ManifestsURL, "name": s.Name, "expected_sha256": s.ExpectedSHA256, "signer": s.Signer, "kind": s.Kind,
			"version": s.Version, "product_code": s.ProductCode, "kb": s.KB, "replaces": s.Replaces, "vendor": s.Vendor, "arch": s.Arch})
	case SourceInternalMirror:
		urlErr("url", s.URL, true)
		if !contains(Upstreams, s.Replaces) {
			out = append(out, "replaces: one of "+strings.Join(Upstreams, ", "))
		}
		unused(map[string]string{"manifests_url": s.ManifestsURL, "name": s.Name, "expected_sha256": s.ExpectedSHA256, "signer": s.Signer, "kind": s.Kind,
			"version": s.Version, "product_code": s.ProductCode, "kb": s.KB, "vendor": s.Vendor, "arch": s.Arch})
	case SourceVendorURL:
		urlErr("url", s.URL, true)
		if s.Name == "" || !validText(s.Name, 100) {
			out = append(out, "name is required (at most 100 characters)")
		}
		if !validText(s.Vendor, 100) {
			out = append(out, "vendor: at most 100 characters")
		}
		switch {
		case s.ExpectedSHA256 == "" && s.Signer == "":
			out = append(out, "expected_sha256 or signer is required: unverified downloads are never accepted")
		case s.ExpectedSHA256 != "" && s.Signer != "":
			out = append(out, "give expected_sha256 or signer, not both")
		case s.ExpectedSHA256 != "" && !sha256Re.MatchString(s.ExpectedSHA256):
			out = append(out, "expected_sha256: 64 hexadecimal characters")
		case s.Signer != "" && (len(s.Signer) < 3 || !validText(s.Signer, 200)):
			out = append(out, "signer: the Authenticode subject, 3-200 characters")
		}
		switch s.Kind {
		case "msi":
			if s.ProductCode != "" && (!acqrequest.ValidProductCode(s.ProductCode) || strings.Trim(s.ProductCode, "{}0-") == "") {
				out = append(out, "product_code: the MSI's {GUID} (or leave it empty to read it from the file)")
			}
			if s.KB != "" {
				out = append(out, "kb applies to msu only")
			}
		case "msu":
			if !acqrequest.ValidKB(s.KB) {
				out = append(out, "kb: an msu needs its KB number, like KB5044284")
			}
			if s.ProductCode != "" {
				out = append(out, "product_code applies to msi only")
			}
		case "exe":
			out = append(out, "kind exe is not supported: DSS Patcher installs MSI and MSU packages only")
		default:
			out = append(out, "kind: msi or msu")
		}
		if !pkgVersion.MatchString(s.Version) {
			out = append(out, "version: like 1.2.3 (the version this URL serves)")
		}
		if s.Arch != "" && !arches[s.Arch] {
			out = append(out, "arch: x64, x86, arm64 or empty (any)")
		}
		unused(map[string]string{"manifests_url": s.ManifestsURL, "replaces": s.Replaces})
	default:
		out = append(out, "type: one of "+strings.Join(SourceTypes, ", "))
	}
	return out
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// Canonical is the byte form that is hashed (compact JSON).
func Canonical(p Policy) []byte {
	b, _ := json.Marshal(p)
	return b
}

// Hash is the hex SHA-256 of Canonical(p).
func Hash(p Policy) string {
	h := sha256.Sum256(Canonical(p))
	return hex.EncodeToString(h[:])
}

// NewFile builds the delivered document for a normalized policy.
func NewFile(version int, editedBy, editedAt string, p Policy) File {
	return File{Format: Format, Version: Version, PolicyVersion: version, EditedBy: editedBy, EditedAt: editedAt, SHA256: Hash(p), Policy: p}
}

// Validate checks the envelope, the SHA-256 and the policy.
func (f *File) Validate() error {
	var errs Problems
	if f.Format != Format {
		errs = append(errs, fmt.Sprintf("format must be %q", Format))
	}
	if f.Version != Version {
		errs = append(errs, fmt.Sprintf("version must be %d", Version))
	}
	if f.PolicyVersion < 1 {
		errs = append(errs, "policy_version must be 1 or more")
	}
	if !validText(f.EditedBy, maxText) || f.EditedBy == "" {
		errs = append(errs, "edited_by invalid")
	}
	if _, err := time.Parse(time.RFC3339, f.EditedAt); err != nil {
		errs = append(errs, "edited_at must be RFC 3339")
	}
	if got := Hash(f.Policy); !strings.EqualFold(got, f.SHA256) {
		errs = append(errs, "sha256 does not match the policy content (the file was changed or damaged)")
	}
	if len(errs) > 0 {
		return errs
	}
	before := Canonical(f.Policy)
	if err := f.Policy.Normalize(); err != nil {
		return err
	}
	if !bytes.Equal(before, Canonical(f.Policy)) {
		return errors.New("policy is not in normalized form (it was not written by the server)")
	}
	return nil
}

func decodeStrict(rd io.Reader, v any, what string) error {
	b, err := io.ReadAll(io.LimitReader(rd, MaxSize+1))
	if err != nil {
		return err
	}
	if len(b) > MaxSize {
		return fmt.Errorf("%s is larger than %d bytes", what, MaxSize)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("not %s: %w", what, err)
	}
	if dec.More() {
		return fmt.Errorf("not %s: trailing data", what)
	}
	return nil
}

// ParseFile reads and validates a delivered policy file (strict: unknown
// fields are refused).
func ParseFile(rd io.Reader) (*File, error) {
	f := &File{}
	if err := decodeStrict(rd, f, "an auto-download policy"); err != nil {
		return nil, err
	}
	if err := f.Validate(); err != nil {
		return nil, err
	}
	return f, nil
}

// NewRunID returns an id like run-20261018T101500Z-1a2b3c.
func NewRunID(now time.Time, suffix string) string {
	return RunPrefix + now.UTC().Format("20060102T150405Z") + "-" + suffix
}

// Validate checks a run request.
func (r *RunRequest) Validate() error {
	var errs Problems
	if r.Format != RunFormat || r.Version != RunVersion {
		errs = append(errs, fmt.Sprintf("format must be %q version %d", RunFormat, RunVersion))
	}
	if !runIDRe.MatchString(r.RunID) {
		errs = append(errs, "run_id invalid")
	}
	if r.RequestedBy == "" || !validText(r.RequestedBy, maxText) {
		errs = append(errs, "requested_by invalid")
	}
	if _, err := time.Parse(time.RFC3339, r.RequestedAt); err != nil {
		errs = append(errs, "requested_at must be RFC 3339")
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

// ParseRun reads and validates a run request.
func ParseRun(rd io.Reader) (*RunRequest, error) {
	r := &RunRequest{}
	if err := decodeStrict(rd, r, "a run request"); err != nil {
		return nil, err
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}
