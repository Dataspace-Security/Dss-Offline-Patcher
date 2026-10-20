package main

// The auto-download policy in pmctl auto (see internal/acqpolicy): the super
// admin's settings from the console, delivered as policy-<version>.json in
// the requests folder (the server writes it there on a single server; on two
// machines a person carries it, like a request file). Every run:
//
//  1. picks up the newest valid policy file, keeps it as the active policy
//     in work_dir/policy.json and moves the file to done/ (invalid files go
//     to rejected/; the previous policy stays in force);
//  2. merges the active policy over acquire.json, which stays the base:
//     Windows entries add, re-classify or switch off Microsoft products;
//     winget apps are kept at their newest version (as known from the update
//     intelligence's Library); vendor-url sources are fetched with their
//     SHA-256 or Authenticode signer; winget / catalog / MSRC sources and
//     internal mirrors change where things are downloaded from;
//  3. reports the applied version, per-entry results and acquire.json's own
//     settings (the console's starting policy) in the status report.
//
// A run-<id>.json file ("Run now" in the console) turns a requests-only run
// (the request watcher) into a full run.

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"offpatch/internal/acqpolicy"
	"offpatch/internal/acqrequest"
	"offpatch/internal/acqstatus"
	"offpatch/internal/acquire"
	"offpatch/internal/manifest"
)

// activePolicy is work_dir/policy.json: the policy in force.
type activePolicy struct {
	File      acqpolicy.File `json:"file"`
	AppliedAt string         `json:"applied_at"` // when this downloader first applied it
}

type policyRun struct {
	file      *acqpolicy.File
	appliedAt string
	errs      []string
	runFiles  []string // run requests to archive after the run
	runID     string
	runBy     string

	apps    []acqpolicy.App    // winget apps to keep current (not covered by acquire.json)
	vendors []acqpolicy.Source // enabled vendor-url sources
	windows []acqpolicy.Windows
	results []acqstatus.SourceResult

	maxBytes  int64
	keepLastN int

	// pins: acquire.json policy_public_keys (S-4); sigStatus: how the
	// policy in force was verified; acceptEqual: the active policy was
	// refused for its signature, so a signed copy of the same version is
	// taken.
	pins        []ed25519.PublicKey
	sigStatus   string
	acceptEqual bool
}

const activePolicyFile = "policy.json"

func (pr *policyRun) result(r acqstatus.SourceResult) { pr.results = append(pr.results, r) }

// unpinnedStatus starts the signature status of a policy accepted without
// a pin.
const unpinnedStatus = "not verified: acquire.json has no policy_public_keys"

// checkSignature verifies f against the pinned policy keys: the key id,
// or an error (refused). Without pins every file is accepted and the
// status says so (the caller warns).
func (pr *policyRun) checkSignature(f *acqpolicy.File) (string, error) {
	if len(pr.pins) == 0 {
		if f.Signature != nil {
			return unpinnedStatus + " (file signed by " + f.Signature.KeyID + ")", nil
		}
		return unpinnedStatus + " (file unsigned)", nil
	}
	id, err := f.VerifySignature(pr.pins)
	if err != nil {
		return "", fmt.Errorf("%w (acquire.json policy_public_keys pins the server's policy signing key)", err)
	}
	return id, nil
}

// loadPolicy reads the active policy, takes over newer policy files and
// collects run requests from the requests folder.
func loadPolicy(c *autoConfig, dry bool, rep *autoReport, st *autoState) *policyRun {
	pr := &policyRun{pins: c.policyPins}
	activePath := filepath.Join(c.WorkDir, activePolicyFile)
	var active *activePolicy
	refusedVersion := 0
	if b, err := os.ReadFile(activePath); err == nil {
		var a activePolicy
		if err := json.Unmarshal(b, &a); err != nil {
			pr.errs = append(pr.errs, fmt.Sprintf("%s is damaged (%v): acquire.json alone applies until the console delivers the policy again", activePath, err))
		} else if err := a.File.Validate(); err != nil {
			pr.errs = append(pr.errs, fmt.Sprintf("%s no longer validates (%v): acquire.json alone applies until the console delivers the policy again", activePath, err))
		} else if stat, err := pr.checkSignature(&a.File); err != nil {
			pr.errs = append(pr.errs, fmt.Sprintf("the policy in force (version %d) is refused: %v: acquire.json alone applies until the console delivers a signed policy",
				a.File.PolicyVersion, err))
			refusedVersion, pr.acceptEqual = a.File.PolicyVersion, true
		} else {
			active, pr.sigStatus = &a, stat
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		pr.errs = append(pr.errs, "active policy: "+err.Error())
	}

	// The last accepted policy_version (state.json, and the active policy):
	// older files are ignored, files too far ahead refused.
	seen := max(st.PolicyVersion, refusedVersion)
	if active != nil && active.File.PolicyVersion > seen {
		seen = active.File.PolicyVersion
	}
	if c.Requests != "" {
		newest := pickPolicyFiles(c.Requests, seen, dry, pr)
		if newest != nil {
			active = &activePolicy{File: *newest, AppliedAt: autoNow().UTC().Format(time.RFC3339)}
			pr.sigStatus, _ = pr.checkSignature(newest)
			if !dry {
				if err := saveJSON(activePath, active); err != nil {
					pr.errs = append(pr.errs, "policy not kept: "+err.Error())
				}
			}
		}
		pickRunRequests(c.Requests, dry, pr)
	}
	if !dry && active != nil && active.File.PolicyVersion > st.PolicyVersion {
		st.PolicyVersion = active.File.PolicyVersion
	}
	if active != nil {
		pr.file, pr.appliedAt = &active.File, active.AppliedAt
		if strings.HasPrefix(pr.sigStatus, unpinnedStatus) {
			w := fmt.Sprintf("auto-download policy version %d applied without a signature check: %s; add the server's key (pmserver policy-key) to policy_public_keys",
				active.File.PolicyVersion, pr.sigStatus)
			fmt.Fprintln(os.Stderr, "WARN:", w)
			rep.Warnings = append(rep.Warnings, w)
		}
	}
	for _, e := range pr.errs {
		rep.Warnings = append(rep.Warnings, "auto-download policy: "+e)
	}
	return pr
}

// maxPolicyJump: a policy file may be at most this many versions past the
// last accepted one. The server counts one version per save, so a larger
// jump is not a console edit; accepting it would block every later
// legitimate policy (finding H-6). The first policy a downloader sees is
// accepted at any version (nothing to compare with).
const maxPolicyJump = 100

// pickPolicyFiles validates every policy-*.json in dir and returns the
// newest one that is newer than the last accepted version cur (nil if
// none). Files are archived (done/ or rejected/) unless dry.
func pickPolicyFiles(dir string, cur int, dry bool, pr *policyRun) *acqpolicy.File {
	paths, _ := filepath.Glob(filepath.Join(dir, acqpolicy.FilePrefix+"*.json"))
	sort.Strings(paths)
	type cand struct {
		path string
		f    *acqpolicy.File
	}
	var good []cand
	for _, p := range paths {
		if fi, err := os.Lstat(p); err != nil || !fi.Mode().IsRegular() {
			continue
		}
		f, err := readPolicyFile(p)
		if err == nil {
			_, err = pr.checkSignature(f)
		}
		if err != nil {
			pr.errs = append(pr.errs, fmt.Sprintf("%s refused: %v", filepath.Base(p), err))
			if !dry {
				moveInto(p, filepath.Join(dir, "rejected"))
			}
			continue
		}
		if cur > 0 && f.PolicyVersion > cur+maxPolicyJump {
			pr.errs = append(pr.errs, fmt.Sprintf("%s refused: policy_version %d is more than %d past the last accepted version %d (the console adds one per save); the policy in force stays",
				filepath.Base(p), f.PolicyVersion, maxPolicyJump, cur))
			if !dry {
				moveInto(p, filepath.Join(dir, "rejected"))
			}
			continue
		}
		good = append(good, cand{p, f})
	}
	var newest *acqpolicy.File
	for _, cd := range good {
		switch {
		case (cd.f.PolicyVersion > cur || pr.acceptEqual && cd.f.PolicyVersion == cur) && (newest == nil || cd.f.PolicyVersion > newest.PolicyVersion):
			newest = cd.f
		case cd.f.PolicyVersion < cur:
			autoWarn(fmt.Sprintf("auto-download policy: %s is version %d, older than the applied version %d; ignored", filepath.Base(cd.path), cd.f.PolicyVersion, cur))
		}
	}
	if !dry {
		for _, cd := range good {
			moveInto(cd.path, filepath.Join(dir, "done"))
		}
	}
	return newest
}

func readPolicyFile(p string) (*acqpolicy.File, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return acqpolicy.ParseFile(f)
}

func pickRunRequests(dir string, dry bool, pr *policyRun) {
	paths, _ := filepath.Glob(filepath.Join(dir, acqpolicy.RunPrefix+"*.json"))
	sort.Strings(paths)
	for _, p := range paths {
		if fi, err := os.Lstat(p); err != nil || !fi.Mode().IsRegular() {
			continue
		}
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		rr, err := acqpolicy.ParseRun(f)
		f.Close()
		if err != nil {
			autoWarn(fmt.Sprintf("run request %s refused: %v", filepath.Base(p), err))
			if !dry {
				moveInto(p, filepath.Join(dir, "rejected"))
			}
			continue
		}
		pr.runFiles = append(pr.runFiles, p)
		pr.runID, pr.runBy = rr.RunID, rr.RequestedBy
	}
}

// archiveRuns moves the served run requests to done/.
func archiveRuns(dir string, pr *policyRun) {
	for _, p := range pr.runFiles {
		moveInto(p, filepath.Join(dir, "done"))
	}
}

// isControlFile: policy and run files share the requests folder with
// acquisition requests but are not requests.
func isControlFile(name string) bool {
	return strings.HasPrefix(name, acqpolicy.FilePrefix) || strings.HasPrefix(name, acqpolicy.RunPrefix)
}

// applyPolicy merges the active policy over the loaded acquire.json.
func applyPolicy(c *autoConfig, pr *policyRun) {
	if pr.file == nil {
		return
	}
	p := pr.file.Policy
	pr.maxBytes = int64(p.Limits.MaxDownloadGBPerRun) << 30
	pr.keepLastN = p.Limits.KeepLastNVersions

	// ---- sources: where things come from ----
	enabled, disabled := map[string]string{}, map[string]string{}
	for _, s := range p.Sources {
		if s.Type == acqpolicy.SourceVendorURL || s.Type == acqpolicy.SourceInternalMirror {
			continue
		}
		if s.Enabled {
			enabled[s.Type] = s.ID
		} else {
			disabled[s.Type] = s.ID
		}
	}
	off := func(typ string) string {
		if _, on := enabled[typ]; on {
			return ""
		}
		return disabled[typ]
	}
	n := c.netFor()
	for _, s := range p.Sources {
		r := acqstatus.SourceResult{Kind: "source", ID: s.ID, Type: s.Type, Result: "applied"}
		if !s.Enabled {
			r.Result, r.Detail = "disabled", "switched off"
			pr.result(r)
			continue
		}
		// Every address the policy sets must be on acquire.json's
		// allowed_source_hosts (netpolicy.go); otherwise the source is
		// refused and the built-in / acquire.json addresses stay.
		if bad := policySourceProblem(c, s); bad != "" {
			r.Result, r.Detail = "failed", "refused: "+bad
			pr.errs = append(pr.errs, "source "+s.ID+" refused: "+bad)
			pr.result(r)
			continue
		}
		switch s.Type {
		case acqpolicy.SourceWinget:
			r.Detail = "default addresses"
			if s.URL != "" {
				if c.Intel != nil {
					c.Intel.WingetURL = s.URL
					n.fromPolicy[acqpolicy.UpstreamWingetIndex] = true
				}
				r.Detail = "index " + hostOf(s.URL)
			}
			if s.ManifestsURL != "" {
				c.WingetManifestsURL = s.ManifestsURL
				n.fromPolicy[acqpolicy.UpstreamWingetManifests] = true
				r.Detail += ", manifests " + hostOf(s.ManifestsURL)
			}
		case acqpolicy.SourceCatalog:
			r.Detail = "default address"
			if s.URL != "" {
				c.CatalogURL, r.Detail = s.URL, hostOf(s.URL)
				n.fromPolicy[acqpolicy.UpstreamCatalog] = true
			}
		case acqpolicy.SourceMSRC:
			r.Detail = "default address"
			if s.URL != "" {
				c.MSRCURL, r.Detail = s.URL, hostOf(s.URL)
				n.fromPolicy[acqpolicy.UpstreamMSRC] = true
			}
		case acqpolicy.SourceVendorURL:
			pr.vendors = append(pr.vendors, s)
			continue // its result comes from the download
		case acqpolicy.SourceInternalMirror:
			switch s.Replaces {
			case acqpolicy.UpstreamWingetIndex:
				if c.Intel != nil {
					c.Intel.WingetURL = s.URL
				}
			case acqpolicy.UpstreamWingetManifests:
				c.WingetManifestsURL = s.URL
			case acqpolicy.UpstreamCatalog:
				c.CatalogURL = s.URL
			case acqpolicy.UpstreamMSRC:
				c.MSRCURL = s.URL
			}
			n.fromPolicy[s.Replaces] = true
			r.Detail = s.Replaces + " from " + hostOf(s.URL)
		}
		pr.result(r)
	}
	msOff := off(acqpolicy.SourceCatalog)
	if msOff == "" {
		msOff = off(acqpolicy.SourceMSRC)
	}
	if msOff != "" && c.Microsoft != nil {
		c.Microsoft = nil
		autoWarn("auto-download policy: Windows updates are off (source " + msOff + " is switched off)")
	}

	// ---- Windows releases ----
	for _, w := range p.Windows {
		r := acqstatus.SourceResult{Kind: "windows", ID: fmt.Sprintf("%s %d %s", w.Product, w.Build, w.Arch), Result: "applied"}
		matches := func(mp autoMSProd) bool {
			return strings.EqualFold(strings.Join(strings.Fields(mp.MSRCProduct), " "), w.Product) && strings.EqualFold(mp.Arch, w.Arch) &&
				(mp.MinBuild == 0 || mp.MinBuild <= w.Build) && (mp.MaxBuild == 0 || w.Build <= mp.MaxBuild)
		}
		if !w.Enabled {
			r.Result, r.Detail = "disabled", "switched off"
			if c.Microsoft != nil {
				kept := c.Microsoft.Products[:0:0]
				for _, mp := range c.Microsoft.Products {
					if !matches(mp) {
						kept = append(kept, mp)
					}
				}
				if len(kept) < len(c.Microsoft.Products) {
					r.Detail = "switched off (it was configured in acquire.json)"
				}
				c.Microsoft.Products = kept
			}
			pr.result(r)
			continue
		}
		if msOff != "" {
			r.Result, r.Detail = "disabled", "Windows updates are off: source "+msOff+" is switched off"
			pr.result(r)
			continue
		}
		if c.Microsoft == nil {
			c.Microsoft = &struct {
				Months      int          `json:"months"`
				MinSeverity string       `json:"min_severity"`
				Products    []autoMSProd `json:"products"`
			}{Months: 2, MinSeverity: "important"}
		}
		sev := ""
		if w.Classification == acqpolicy.ClassAll {
			sev = "low"
		}
		found := false
		for i, mp := range c.Microsoft.Products {
			if matches(mp) {
				c.Microsoft.Products[i].MinSeverity = sev
				found = true
			}
		}
		if found {
			r.Detail = "configured in acquire.json"
		} else {
			catProd := w.Product
			if k, ok := acqpolicy.LookupKnown(w.Product, w.Build, w.Arch); ok {
				catProd = k.CatalogProduct
			}
			suffix := acqpolicy.KBPackageSuffix(w.Product, false, w.Build) // Server and 25H2/23H2 share KB numbers
			c.Microsoft.Products = append(c.Microsoft.Products, autoMSProd{MSRCProduct: w.Product, CatalogProduct: catProd, Arch: w.Arch,
				MinBuild: w.Build, MaxBuild: w.Build, MinSeverity: sev, PackageSuffix: suffix})
			r.Detail = "added by the policy"
		}
		pr.windows = append(pr.windows, w)
		pr.result(r)
	}

	// ---- winget apps ----
	wingetOff := off(acqpolicy.SourceWinget)
	for _, a := range p.Apps {
		r := acqstatus.SourceResult{Kind: "app", ID: a.ID, Type: acqpolicy.SourceWinget}
		if !a.Enabled {
			kept := c.Apps[:0:0]
			for _, ca := range c.Apps {
				if !strings.EqualFold(ca.WingetID, a.ID) {
					kept = append(kept, ca)
				}
			}
			r.Result, r.Detail = "disabled", "switched off"
			if len(kept) < len(c.Apps) {
				r.Detail = "switched off (its acquire.json feed is skipped)"
			}
			c.Apps = kept
			pr.result(r)
			continue
		}
		covered := ""
		for _, ca := range c.Apps {
			if strings.EqualFold(ca.WingetID, a.ID) {
				covered = ca.Name
			}
		}
		switch {
		case covered != "":
			r.Result, r.Detail = "applied", "downloaded by the acquire.json feed "+covered
			pr.result(r)
		case wingetOff != "":
			r.Result, r.Detail = "disabled", "the winget source "+wingetOff+" is switched off"
			pr.result(r)
		default:
			pr.apps = append(pr.apps, a)
			if c.Intel != nil {
				c.Intel.Library = append(c.Intel.Library, a.ID) // the Library learns its newest version
			}
		}
	}
}

// policySourceProblem: why acquire.json does not let the policy use the
// addresses of s ("" = it may).
func policySourceProblem(c *autoConfig, s acqpolicy.Source) string {
	for _, f := range []struct{ name, url string }{{"url", s.URL}, {"manifests_url", s.ManifestsURL}} {
		if f.url == "" {
			continue
		}
		check := c.checkPolicyURL
		if s.Type == acqpolicy.SourceVendorURL {
			check = c.checkVendorURL
		}
		if err := check(f.url); err != nil {
			return f.name + " " + hostOf(f.url) + ": " + strings.TrimPrefix(err.Error(), acquire.ErrNetworkRefused.Error()+": ")
		}
	}
	return ""
}

func hostOf(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	return raw
}

// libraryVersion: the newest version of a winget id the Library knows.
func libraryVersion(st autoState, id string) string {
	best, at := "", ""
	for k, r := range st.Library {
		kid, _, ok := strings.Cut(k, "@")
		if ok && strings.EqualFold(kid, id) && acqrequest.ValidVersion(r.Version) && (best == "" || r.ResolvedAt > at) {
			best, at = r.Version, r.ResolvedAt
		}
	}
	return best
}

// fetchPolicyApps keeps every policy winget app at its newest version.
func fetchPolicyApps(r *requestRun, pr *policyRun) {
	intelOn := r.c.Intel != nil && !r.c.Intel.Disabled && !r.c.Intel.NoApps && !r.c.Intel.NoLibrary
	for _, a := range pr.apps {
		res := acqstatus.SourceResult{Kind: "app", ID: a.ID, Type: acqpolicy.SourceWinget}
		feed := acqstatus.Feed{Type: "app", Name: a.ID, Title: "winget " + a.ID, Status: "up_to_date"}
		ver := libraryVersion(r.st, a.ID)
		if ver == "" {
			res.Result = "waiting"
			res.Detail = "newest version not known yet: the update intelligence looks it up this run; it is downloaded on the next run"
			if !intelOn {
				res.Result = "unsupported"
				res.Detail = "update intelligence (with its Library) is off in acquire.json: winget apps need it to learn the newest version"
			}
			feed.Detail = res.Detail
			pr.result(res)
			r.rep.Feeds = append(r.rep.Feeds, feed)
			continue
		}
		feed.LatestVersion = ver
		var fresh, failed, unsup []string
		for _, arch := range a.Arch {
			id := wingetPackageID(a.ID, ver, arch)
			family := "winget:" + strings.ToLower(a.ID) + "/" + arch
			if _, done := r.st.Done[id]; done {
				r.rep.Skipped++
				continue
			}
			if r.rep.Failures[id] != "" {
				failed = append(failed, arch+": "+shortReason(r.rep.Failures[id]))
				continue
			}
			if containsStr(r.rep.New, id) || r.dry {
				r.added(id)
				fresh = append(fresh, id)
				continue
			}
			err := r.fetchWinget(acqrequest.App{WingetID: a.ID, Version: ver, Architectures: []string{arch}}, arch)
			if err == nil {
				r.added(id)
				r.st.Families[id] = family
				fresh = append(fresh, id)
				continue
			}
			o := classify(err)
			if o.result == acqstatus.ItemUnsupported {
				autoWarn(fmt.Sprintf("auto-download %s %s %s skipped: %s", a.ID, ver, arch, err.Error()))
				delete(r.st.Failed, id)
				unsup = append(unsup, arch+": "+o.reason)
				continue
			}
			r.fail(id, err)
			failed = append(failed, arch+": "+o.reason)
		}
		switch {
		case len(failed) > 0:
			res.Result, feed.Status = "failed", "failed"
			res.Detail = strings.Join(failed, "; ")
		case len(fresh) > 0:
			res.Result, feed.Status = "new", "new"
			res.Detail = ver
		case len(unsup) > 0:
			res.Result = "unsupported"
			res.Detail = "can't download: " + strings.Join(unsup, "; ")
		default:
			res.Result, res.Detail = "up_to_date", ver
		}
		res.Packages = fresh
		feed.Detail = res.Detail
		pr.result(res)
		r.rep.Feeds = append(r.rep.Feeds, feed)
	}
}

func containsStr(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// fetchVendorSources downloads every enabled vendor-url source.
func fetchVendorSources(r *requestRun, pr *policyRun) {
	for _, s := range pr.vendors {
		res := acqstatus.SourceResult{Kind: "source", ID: s.ID, Type: s.Type}
		feed := acqstatus.Feed{Type: "app", Name: s.ID, Title: s.Name, LatestVersion: s.Version}
		id, err := fetchVendor(r, s)
		switch {
		case err != nil:
			o := classify(err)
			if o.result == acqstatus.ItemUnsupported {
				autoWarn(fmt.Sprintf("auto-download source %s skipped: %s", s.ID, err.Error()))
				res.Result, res.Detail = "unsupported", "can't download: "+o.reason
				feed.Status, feed.Detail = "up_to_date", res.Detail
				break
			}
			r.fail(vendorPackageID(s), err)
			res.Result, res.Detail = "failed", o.reason
			feed.Status, feed.Detail = "failed", err.Error()
		case id == "":
			r.rep.Skipped++
			res.Result, res.Detail = "up_to_date", s.Version+" was sent earlier"
			feed.Status = "up_to_date"
		default:
			r.added(id)
			res.Result, res.Detail, res.Packages = "new", s.Version, []string{id}
			feed.Status, feed.Detail = "new", id
		}
		pr.result(res)
		r.rep.Feeds = append(r.rep.Feeds, feed)
	}
}

func vendorPackageID(s acqpolicy.Source) string {
	id := unsafeIDChars.ReplaceAllString(s.ID+"-"+s.Version, "-")
	if len(id) > 64 {
		id = id[:64]
	}
	return id
}

// fetchVendor: the new package id, "" if this version was sent before.
func fetchVendor(r *requestRun, s acqpolicy.Source) (string, error) {
	id := vendorPackageID(s)
	if _, done := r.st.Done[id]; done {
		return "", nil
	}
	if r.dry {
		return id, nil
	}
	u, _ := url.Parse(s.URL)
	name := filepath.Base(u.Path)
	if name == "" || name == "." || name == "/" || !strings.EqualFold(filepath.Ext(name), "."+s.Kind) {
		name = id + "." + s.Kind
	}
	name = unsafeIDChars.ReplaceAllString(name, "_")
	// The URL comes from the policy: held to allowed_source_hosts (never
	// shared hosting), redirects too.
	hc := r.c.netFor().vendor.Client(r.hc)
	sha, verified, vs, err := downloadVendor(r, hc, s, name)
	if err != nil {
		return "", err
	}
	code := s.ProductCode
	if s.Kind == "msi" && code == "" {
		if code, err = readMSICode(filepath.Join(r.downloads, name)); err != nil || !acqrequest.ValidProductCode(code) {
			return "", unsupportedItem("MSI has no ProductCode", fmt.Sprintf("%s: could not read ProductCode from the MSI: %v; set product_code", s.ID, err))
		}
	}
	vendor := s.Vendor
	if vendor == "" {
		vendor = s.Name
	}
	if _, err := acquire.FetchURL(r.ctx, acquire.FetchURLOptions{URL: s.URL, SHA256: sha, FileName: name, PackageID: id, Title: s.Name + " " + s.Version,
		Vendor: vendor, Kind: s.Kind, KB: s.KB, ProductCode: code, OS: "windows", Version: s.Version, Severity: "important", Arch: s.Arch,
		OutDir: r.downloads, SpecPath: r.spec, HTTP: hc, Verified: verified, VendorSignature: vs}); err != nil {
		return "", err
	}
	r.st.Families[id] = "vendor:" + s.ID
	return id, nil
}

// downloadVendor fetches and verifies a vendor-url download (finding S-4).
// Every file must pass Authenticode and the signer pin (signerpin.go); a
// policy expected_sha256 is checked as well, never instead. Where this host
// cannot check Authenticode (MSI and MSU on a non-Windows acquisition
// host), the source is downloaded only when its expected_sha256 equals the
// local pin in acquire.json vendor_sha256_pins; otherwise it is refused
// (reported "unsupported"). Returns the SHA-256, the "verified" label and
// the vendor signature.
func downloadVendor(r *requestRun, hc *http.Client, s acqpolicy.Source, name string) (string, string, *manifest.VendorSignature, error) {
	if !authenticodeAvailable(name) {
		pin := strings.ToLower(r.c.VendorSHA256Pins[s.ID])
		if pin == "" || s.ExpectedSHA256 == "" || pin != s.ExpectedSHA256 {
			return "", "", nil, unsupportedItem("Authenticode needs a Windows acquisition host",
				fmt.Sprintf("%s: %s signatures cannot be checked on this acquisition host, and acquire.json vendor_sha256_pins does not confirm the policy's expected_sha256 for this source: use a Windows acquisition host, or pin the SHA-256 in acquire.json", s.ID, strings.ToUpper(s.Kind)))
		}
		if _, err := acquire.Download(r.ctx, hc, acquire.DownloadRequest{URL: s.URL, DestDir: r.downloads, FileName: name, SHA256: pin}); err != nil {
			return "", "", nil, err
		}
		return pin, "sha256(acquire.json vendor_sha256_pins " + s.ID + "; Authenticode not available on this host)", nil, nil
	}
	want := parseSignerSpec(s.Signer)
	var got signerInfo
	sha, err := downloadVerified(r.ctx, hc, s.URL, r.downloads, name, func(p string) error {
		if s.ExpectedSHA256 != "" {
			if _, h, err := manifest.HashFile(p); err != nil || h != s.ExpectedSHA256 {
				return fmt.Errorf("%w: sha256 %s does not match the policy's expected_sha256", errExeSignature, h)
			}
		}
		info, err := signerOfFile(p)
		if err != nil {
			return fmt.Errorf("authenticode check failed: %w", err)
		}
		if s.Signer != "" && !want.matches(info.signerName) {
			return fmt.Errorf("%w: authenticode check failed: signed by %s, want exactly %s", errExeSignature, info.signerName, want)
		}
		got = info
		return nil
	})
	if err != nil {
		return "", "", nil, err
	}
	v, err := pinInstaller(r.ctx, r.c, r.pins, pinKeyVendor(s.ID), s.Version, "", got)
	if err != nil {
		os.Remove(filepath.Join(r.downloads, name)) // never left where a later run could pick it up unchecked
		return "", "", nil, err
	}
	verified := "authenticode(" + got.CN + ")"
	if s.ExpectedSHA256 != "" {
		verified += "+sha256(auto-download policy source " + s.ID + ")"
	}
	return sha, verified, &v, nil
}

// authenticodeAvailable: this host can check the Authenticode signature
// of the file name (PE files everywhere, MSI / MSU on Windows only).
func authenticodeAvailable(name string) bool {
	return windowsAuthenticode() || strings.EqualFold(filepath.Ext(name), ".exe")
}

// windowsAuthenticode: MSI / MSU signatures can be checked here (a hook
// for tests of the Linux acquisition host).
var windowsAuthenticode = func() bool { return runtime.GOOS == "windows" || authenticodeAnywhere }

// windowsResults copies the Microsoft feed outcome onto the policy's
// Windows entries that are downloaded this run.
func windowsResults(pr *policyRun, feeds []acqstatus.Feed) {
	for i, res := range pr.results {
		if res.Kind != "windows" || res.Result != "applied" {
			continue
		}
		for _, w := range pr.windows {
			if fmt.Sprintf("%s %d %s", w.Product, w.Build, w.Arch) != res.ID {
				continue
			}
			for _, f := range feeds {
				name := strings.Join(strings.Fields(strings.TrimSuffix(f.Name, "-server")), " ")
				if f.Type != "microsoft" || !strings.EqualFold(name, w.Product+" "+w.Arch) {
					continue
				}
				pr.results[i].Result = f.Status
				if d := strings.TrimSpace(f.LatestVersion + " " + f.Detail); d != "" {
					pr.results[i].Detail = res.Detail + "; " + d
				}
			}
		}
	}
}

// ---- per-run download limit ----

var errDownloadLimit = errors.New("the auto-download policy's download limit for one run was reached; the rest follows on the next run")

type downloadBudget struct {
	mu   sync.Mutex
	max  int64
	used int64
}

func (b *downloadBudget) add(n int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.used += int64(n)
	return b.used <= b.max
}

func (b *downloadBudget) exhausted() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used >= b.max
}

type budgetTransport struct {
	rt http.RoundTripper
	b  *downloadBudget
}

func (t *budgetTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.b.exhausted() {
		return nil, errDownloadLimit
	}
	resp, err := t.rt.RoundTrip(req)
	if resp != nil && resp.Body != nil {
		resp.Body = &budgetBody{ReadCloser: resp.Body, b: t.b}
	}
	return resp, err
}

type budgetBody struct {
	io.ReadCloser
	b *downloadBudget
}

func (bb *budgetBody) Read(p []byte) (int, error) {
	n, err := bb.ReadCloser.Read(p)
	if n > 0 && !bb.b.add(n) {
		return n, errDownloadLimit
	}
	return n, err
}

// withBudget wraps hc so that one run downloads at most max bytes.
func withBudget(hc *http.Client, max int64) *http.Client {
	if max <= 0 {
		return hc
	}
	c := *hc
	rt := hc.Transport
	if rt == nil {
		rt = http.DefaultTransport
	}
	c.Transport = &budgetTransport{rt: rt, b: &downloadBudget{max: max}}
	return &c
}

// ---- keep the last N versions ----

// pruneOldVersions deletes the downloaded files of policy apps and vendor
// downloads beyond the newest keep sent versions of each.
func pruneOldVersions(dir string, st autoState, inUse map[string]bool, keep int, warn func(error)) {
	if keep <= 0 {
		return
	}
	byFam := map[string][]string{}
	for id, fam := range st.Families {
		if _, ok := st.Done[id]; ok {
			byFam[fam] = append(byFam[fam], id)
		}
	}
	for _, ids := range byFam {
		sort.Slice(ids, func(i, j int) bool { return st.Done[ids[i]].SentAt > st.Done[ids[j]].SentAt })
		for _, id := range ids[min(keep, len(ids)):] {
			d := st.Done[id]
			if d.File == "" || inUse[d.File] || d.File != filepath.Base(d.File) {
				continue
			}
			if err := os.Remove(filepath.Join(dir, d.File)); err != nil && !errors.Is(err, os.ErrNotExist) {
				warn(err)
			}
		}
	}
}

// policyReport fills the policy part of the run report.
func policyReport(rep *autoReport, pr *policyRun, cfgPath string) {
	if b, err := os.ReadFile(cfgPath); err == nil {
		if base, err := acqpolicy.FromAcquireJSON(b); err == nil {
			rep.Defaults = &base
		}
	}
	rep.PolicyError = strings.Join(pr.errs, "; ")
	if pr.file != nil {
		rep.PolicySignature = pr.sigStatus
	}
	rep.RunRequest = pr.runID
	if pr.file != nil {
		rep.PolicyVersion, rep.PolicySHA256, rep.PolicyEditedBy, rep.PolicyAppliedAt = pr.file.PolicyVersion, pr.file.SHA256, pr.file.EditedBy, pr.appliedAt
	}
	rep.Sources = pr.results
}
