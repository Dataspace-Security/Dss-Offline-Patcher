package main

// Acquisition requests in pmctl auto: files exported from the console's
// Updates page and carried here on approved media (see internal/acqrequest).
// Each requested winget app is resolved from its winget manifest, the MSI
// for every requested architecture is downloaded over HTTPS and checked
// against the manifest's InstallerSha256; each requested KB goes through the
// Microsoft Update Catalog like pmctl fetch. Everything lands in the same
// signed bundle as the rest of the run, in quarantine on the isolated side.
//
// Items offpatch cannot package (no MSI installer, no product code, not in
// the winget repository) are warnings, not failures: retrying will not help.
// A request whose items all succeeded or were warned about moves to
// <requests>/done after the run; one with failures stays and is retried.
// Files that are not valid requests move to <requests>/rejected.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	"offpatch/internal/acqrequest"
	"offpatch/internal/acqstatus"
	"offpatch/internal/acquire"
)

// Hooks overridable in tests: reading ProductCode from an .msi needs the
// Windows Installer API.
var (
	msiCodeAvailable = runtime.GOOS == "windows"
	readMSICode      = msiProductCode
)

var (
	// The manifest's rule for an msi package_name (Apps & features display name).
	displayNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 .+_()-]{0,127}$`)
	unsafeIDChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)
	versionInName = regexp.MustCompile(`\d+\.\d+`)
)

type loadedRequest struct {
	path string
	req  *acqrequest.Request
	ids  []string // package ids this request asked for
}

type requestRun struct {
	ctx       context.Context
	c         *autoConfig
	hc        *http.Client
	downloads string
	spec      string
	st        autoState
	dry       bool
	rep       *autoReport
	fail      func(id string, err error)
	added     func(id string)
	handled   map[string]bool
	cat       *acquire.Catalog
	ms        *acquire.MSRC
}

// processRequests handles every *.json request in dir and returns the
// valid ones (archived by archiveRequests after the run).
func processRequests(r *requestRun, dir string) []*loadedRequest {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		r.rep.Warnings = append(r.rep.Warnings, "acquisition requests: "+err.Error())
		return nil
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		r.rep.Warnings = append(r.rep.Warnings, "acquisition requests: "+err.Error())
		return nil
	}
	var out []*loadedRequest
	for _, e := range ents {
		if !e.Type().IsRegular() || !strings.EqualFold(filepath.Ext(e.Name()), ".json") {
			continue
		}
		p := filepath.Join(dir, e.Name())
		req, err := readRequest(p)
		if err != nil {
			r.rep.Warnings = append(r.rep.Warnings, fmt.Sprintf("acquisition request %s rejected: %v", e.Name(), err))
			if !r.dry {
				moveInto(p, filepath.Join(dir, "rejected"))
			}
			continue
		}
		lr := &loadedRequest{path: p, req: req}
		r.one(lr)
		out = append(out, lr)
	}
	return out
}

func readRequest(p string) (*acqrequest.Request, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return acqrequest.Parse(f)
}

func (r *requestRun) one(lr *loadedRequest) {
	req := lr.req
	var warned []string
	item := func(id string, fetch func() error) {
		lr.ids = append(lr.ids, id)
		if r.handled[id] {
			return
		}
		r.handled[id] = true
		if _, done := r.st.Done[id]; done {
			r.rep.Skipped++
			return
		}
		if r.dry {
			r.added(id)
			return
		}
		err := fetch()
		var un *acquire.UnsupportedError
		switch {
		case err == nil:
			r.added(id)
		case errors.As(err, &un):
			msg := fmt.Sprintf("request %s: %s skipped: %s", req.RequestID, id, un.Reason)
			r.rep.Warnings = append(r.rep.Warnings, msg)
			warned = append(warned, id)
			delete(r.st.Failed, id)
		default:
			r.fail(id, err)
		}
	}
	for _, a := range req.Apps {
		for _, arch := range a.Architectures {
			a, arch := a, arch
			item(wingetPackageID(a.WingetID, a.Version, arch), func() error { return r.fetchWinget(a, arch) })
		}
	}
	for _, k := range req.KBs {
		k := k
		item(k.KB+"-"+k.Arch, func() error { return r.fetchKB(k) })
	}

	f := acqstatus.Feed{Type: "request", Name: req.RequestID, Status: "up_to_date",
		Title:         fmt.Sprintf("%d app(s), %d KB(s) requested by %s", len(req.Apps), len(req.KBs), req.CreatedBy),
		LatestVersion: fmt.Sprintf("%d package(s)", len(lr.ids))}
	var failed, fresh []string
	for _, id := range lr.ids {
		switch {
		case r.rep.Failures[id] != "":
			failed = append(failed, id+": "+r.rep.Failures[id])
		case slices.Contains(r.rep.New, id):
			fresh = append(fresh, id)
		}
	}
	switch {
	case len(failed) > 0:
		f.Status, f.Detail = "failed", strings.Join(failed, "; ")
	case len(fresh) > 0:
		f.Status, f.Detail = "new", strings.Join(fresh, ", ")
	case len(warned) > 0:
		f.Detail = "nothing packageable: " + strings.Join(warned, ", ")
	default:
		f.Detail = "everything requested was sent earlier"
	}
	if len(warned) > 0 && f.Status != "up_to_date" {
		f.Detail += " (skipped: " + strings.Join(warned, ", ") + ")"
	}
	r.rep.Feeds = append(r.rep.Feeds, f)
}

// wingetPackageID: <winget id>-<version>[-<arch>], within the manifest's
// package_id rule (64 chars of [A-Za-z0-9._-]).
func wingetPackageID(id, version, arch string) string {
	s := id + "-" + version
	if arch != "x64" {
		s += "-" + arch
	}
	clean := unsafeIDChars.ReplaceAllString(s, "-")
	// Characters were replaced ("Notepad++") or the id is too long: add a
	// hash of the original so different packages never share an id.
	if clean != s || len(clean) > 64 {
		h := sha256.Sum256([]byte(s))
		clean = clean[:min(len(clean), 55)] + "-" + hex.EncodeToString(h[:4])
	}
	s = clean
	return s
}

func (r *requestRun) fetchWinget(a acqrequest.App, arch string) error {
	m, murl, err := acquire.FetchWingetManifest(r.ctx, r.hc, r.c.WingetManifestsURL, a.WingetID, a.Version)
	if errors.Is(err, acquire.ErrWingetNotFound) {
		return &acquire.UnsupportedError{Reason: fmt.Sprintf("%s %s is not in the winget repository (newer version published, or package renamed)", a.WingetID, a.Version)}
	}
	if err != nil {
		return fmt.Errorf("winget manifest: %w", err)
	}
	in, err := m.PickMSI(arch)
	if err != nil {
		return err
	}
	if in.Architecture != arch && in.Architecture != "neutral" {
		autoWarn(fmt.Sprintf("%s %s: no %s MSI; using the %s MSI for %s endpoints", a.WingetID, m.Version, arch, in.Architecture, arch))
	}
	code := in.MSIProductCode()
	if code == "" && !msiCodeAvailable {
		return &acquire.UnsupportedError{Reason: fmt.Sprintf("%s %s: the winget manifest states no ProductCode; run pmctl auto on a Windows acquisition host to read it from the MSI", a.WingetID, m.Version)}
	}
	ver := m.Version
	if v := in.ARPVersion(); acqrequest.ValidVersion(v) {
		ver = v // what Apps & features will show, compared with endpoint inventory
	}
	file := wingetPackageID(a.WingetID, m.Version, arch) + ".msi"
	dl, err := acquire.Download(r.ctx, r.hc, acquire.DownloadRequest{URL: in.URL, DestDir: r.downloads, FileName: file, SHA256: in.SHA256})
	if err != nil {
		return err
	}
	if code == "" {
		if code, err = readMSICode(dl.Path); err != nil || !acqrequest.ValidProductCode(code) {
			return &acquire.UnsupportedError{Reason: fmt.Sprintf("%s %s: could not read ProductCode from the MSI: %v", a.WingetID, m.Version, err)}
		}
	}
	name := msiDisplayName(in, a, m)
	if name == "" {
		autoWarn(fmt.Sprintf("%s %s: no usable Apps & features name in the manifest or inventory; endpoints will not be offered it as an update automatically", a.WingetID, m.Version))
	}
	rel := in.ReleaseDate
	if _, err := time.Parse("2006-01-02", rel); err != nil {
		rel = ""
	}
	title := a.Name
	if title == "" {
		title = m.PackageName
	}
	if title == "" {
		title = a.WingetID
	}
	_, err = acquire.FetchURL(r.ctx, acquire.FetchURLOptions{URL: in.URL, SHA256: in.SHA256, FileName: file, PackageID: wingetPackageID(a.WingetID, a.Version, arch),
		Title: title + " " + ver, Vendor: wingetPublisher(in, m), Kind: "msi", ProductCode: code, PackageName: name, OS: "windows",
		Version: ver, Severity: "important", ReleaseDate: rel, Arch: arch, OutDir: r.downloads, SpecPath: r.spec, HTTP: r.hc,
		Verified: "sha256(winget manifest " + murl + ")"})
	return err
}

// msiDisplayName picks the package_name endpoints will be matched on: the
// manifest's Apps & features name, else the name the endpoints themselves
// report (if they agree and it carries no version), else the winget name.
func msiDisplayName(in acquire.WingetInstaller, a acqrequest.App, m *acquire.WingetManifest) string {
	cands := []string{in.ARPName()}
	var inv string
	agree := true
	for _, i := range a.Installed {
		if i.Name == "" {
			continue
		}
		if versionInName.MatchString(i.Name) {
			agree = false // "7-Zip 26.03 (x64 edition)": changes with every version
		}
		if inv == "" {
			inv = i.Name
		} else if !strings.EqualFold(inv, i.Name) {
			agree = false
		}
	}
	if agree {
		cands = append(cands, inv)
	}
	cands = append(cands, m.PackageName, a.Name)
	for _, c := range cands {
		if c = strings.TrimSpace(c); displayNameRe.MatchString(c) {
			return c
		}
	}
	return ""
}

func wingetPublisher(in acquire.WingetInstaller, m *acquire.WingetManifest) string {
	if m.Publisher != "" {
		return m.Publisher
	}
	for _, e := range in.ARP {
		if e.Publisher != "" {
			return e.Publisher
		}
	}
	pub, _, _ := strings.Cut(m.ID, ".")
	return pub
}

func (r *requestRun) fetchKB(k acqrequest.KB) error {
	prod := k.Title
	if prod == "" {
		prod = k.Product
	}
	if prod == "" {
		return &acquire.UnsupportedError{Reason: k.KB + ": the request names no product"}
	}
	if r.cat == nil {
		r.cat, r.ms = acquire.NewCatalog(), acquire.NewMSRC()
		r.cat.HTTP, r.ms.HTTP = r.hc, r.hc
		if r.c.CatalogURL != "" {
			r.cat.BaseURL = r.c.CatalogURL
		}
		if r.c.MSRCURL != "" {
			r.ms.BaseURL = r.c.MSRCURL
		}
	}
	res, err := acquire.FetchKB(r.ctx, r.cat, r.ms, acquire.FetchKBOptions{KB: k.KB, Product: prod, Arch: k.Arch, MinBuild: k.Build, MaxBuild: k.Build,
		PackageID: k.KB + "-" + k.Arch, OutDir: r.downloads, SpecPath: r.spec})
	if err != nil {
		return err
	}
	for _, w := range res.Warnings {
		autoWarn(k.KB + ": " + w)
	}
	return nil
}

// archiveRequests moves requests with no failed item to <dir>/done.
func archiveRequests(dir string, reqs []*loadedRequest, rep *autoReport) {
	for _, lr := range reqs {
		if slices.ContainsFunc(lr.ids, func(id string) bool { return rep.Failures[id] != "" }) {
			continue
		}
		moveInto(lr.path, filepath.Join(dir, "done"))
	}
}

// moveInto moves p into dir, never overwriting an earlier file.
func moveInto(p, dir string) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		autoWarn("acquisition requests: " + err.Error())
		return
	}
	dst := filepath.Join(dir, filepath.Base(p))
	if _, err := os.Stat(dst); err == nil {
		dst = filepath.Join(dir, fmt.Sprintf("%d-%s", autoNow().UnixNano(), filepath.Base(p)))
	}
	if err := os.Rename(p, dst); err != nil {
		autoWarn("acquisition requests: " + err.Error())
	}
}
