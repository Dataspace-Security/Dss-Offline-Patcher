package server

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"offpatch/internal/acqrequest"
	"offpatch/internal/intake"
	"offpatch/internal/intel"
	"offpatch/internal/store"
)

// Update intelligence on the console: every update an endpoint is missing
// (Windows cumulative updates and newer application versions), whether or
// not it has been imported into the catalog yet. Intake verifies and stores
// the document; the matching index is (re)built here when it changes.

type intelCache struct {
	mu        sync.Mutex
	keys      func() map[string]ed25519.PublicKey // intake's active keys (SetIntelKeys)
	generated string                              // MetaIntelGenerated the index was built from
	ix        *intel.Index
	err       error // last load failure, retried after intelRetry
	errAt     time.Time

	fleetAt       time.Time
	fleetGen      string // MetaIntelGenerated the snapshot was built from
	fleetStoreGen uint64 // store.Generation it was built at
	fleet         *fleetSnapshot
	fleetBuild    sync.Mutex // one buildFleet at a time

	status   *fleetStatusCache
	statusMu sync.Mutex
}

const (
	intelRetry = 30 * time.Second
	fleetTTL   = 60 * time.Second
)

// SetIntelKeys tells the server which bundle keys are trusted right now, so
// the stored document is re-verified with the same keys intake uses
// (including rotations by trust documents). Without it the configured keys
// are used.
func (s *Server) SetIntelKeys(f func() map[string]ed25519.PublicKey) { s.intel.keys = f }

func (s *Server) intelKeys() (map[string]ed25519.PublicKey, error) {
	if s.intel.keys != nil {
		return s.intel.keys(), nil
	}
	icfg, err := s.cfg.IntakeConfig()
	if err != nil {
		return nil, err
	}
	keys := map[string]ed25519.PublicKey{}
	for id, k := range icfg.Keys {
		if !k.Retired {
			keys[id] = k.Pub
		}
	}
	return keys, nil
}

// intelIndex returns the current matching index and its summary. The index
// is nil when no document has been received, or when the stored document no
// longer verifies (its key was revoked); sum.Error then says why.
func (s *Server) intelIndex(ctx context.Context) (*intel.Index, *intake.IntelSummary, error) {
	gen, err := s.store.GetMeta(ctx, intake.MetaIntelGenerated)
	if err != nil || gen == "" {
		return nil, nil, err
	}
	var sum intake.IntelSummary
	if raw, _ := s.store.GetMeta(ctx, intake.MetaIntelSummary); raw != "" {
		json.Unmarshal([]byte(raw), &sum)
	}
	s.intel.mu.Lock()
	defer s.intel.mu.Unlock()
	if s.intel.generated == gen {
		if s.intel.ix != nil {
			return s.intel.ix, &sum, nil
		}
		if s.intel.err != nil && time.Since(s.intel.errAt) < intelRetry {
			sum.Error = s.intel.err.Error()
			return nil, &sum, nil
		}
	}
	ix, err := s.loadIntel()
	hadIndex := s.intel.ix != nil
	s.intel.generated, s.intel.ix, s.intel.err, s.intel.errAt = gen, ix, err, time.Now()
	s.intel.fleet, s.intel.status = nil, nil
	// The store proves a cumulative update by the endpoint's build revision
	// when Windows no longer lists its KB: it needs the revision each KB
	// brings, which the intelligence knows (also for packages imported
	// without expected_ubr). Needs and fleet caches follow the change.
	if err != nil {
		s.store.SetUBRHint(nil)
	} else {
		s.store.SetUBRHint(ix.ReleaseUBR)
	}
	if err == nil || hadIndex {
		s.store.Changed()
	}
	if err != nil {
		s.log.Error("update intelligence unusable", "err", err)
		sum.Error = err.Error()
		return nil, &sum, nil
	}
	return ix, &sum, nil
}

func (s *Server) loadIntel() (*intel.Index, error) {
	icfg, err := s.cfg.IntakeConfig()
	if err != nil {
		return nil, err
	}
	keys, err := s.intelKeys()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(filepath.Join(icfg.IntelDir, intake.CurrentIntelFile))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// Re-verify: the file on disk is only trusted because of its signature.
	d, _, err := intel.Read(f, keys)
	if err != nil {
		return nil, err
	}
	return intel.NewIndex(d), nil
}

func toIntelEndpoint(e store.Endpoint, inv []store.InventoryItem) intel.Endpoint {
	items := make([]intel.Item, 0, len(inv))
	for _, it := range inv {
		items = append(items, intel.Item{Kind: it.Kind, ID: it.ID, Name: it.Name, Version: it.Version})
	}
	return intel.Endpoint{OS: e.OS, OSVersion: e.OSVersion, Build: e.Build, Arch: e.Arch, Inventory: items}
}

// catalogLink says whether an available update is already in the catalog.
type catalogLink struct {
	PackageID string `json:"package_id"`
	State     string `json:"state"` // quarantined | approved | rejected | revoked
	// Version: the package's version (what its Catalog page shows), so a
	// row can say which version the link opens.
	Version string `json:"version,omitempty"`
	// Severity: the package's severity (critical | important | moderate | low).
	Severity string `json:"severity,omitempty"`
	want     string // the version inventory shows once it is installed
}

// linkOf is the catalog link to p.
func linkOf(p store.Package) catalogLink {
	return catalogLink{PackageID: p.PackageID, State: p.State, Version: p.Version, Severity: p.Severity, want: store.AppWantVersion(p)}
}

// catalogIndex finds catalog packages for available updates: Windows updates
// by KB, applications by MSI product code or, because a new MSI version
// usually has a new product code, by its Apps & features display name
// (package_name, compared normalised like the intelligence does, so "7-Zip"
// matches "7-Zip 26.03 (x64 edition)") when the package is newer than what
// is installed.
type catalogIndex struct {
	byKB           map[string]catalogLink
	kbPkgs         map[string][]kbPackage // every package of a KB with its applicability
	byCode, byName map[string]namedPackage
	byID           map[string]catalogLink // every package by package_id (Library: pmctl's winget package ids)

	// pkgs: every package by package_id. classify (nil in unit tests that
	// build an index by hand) is the store's verdict for a package on an
	// endpoint, so the fleet view never calls "needed" what a deployment
	// would skip as already present, or "current" what it would install.
	pkgs     map[string]store.Package
	classify func(p store.Package, e store.Endpoint) store.Verdict
}

// verdict is the store's verdict for the linked package on e (ok false
// without a link or a classifier).
func (ci *catalogIndex) verdict(l *catalogLink, e store.Endpoint) (store.Package, store.Verdict, bool) {
	if ci.classify == nil || l == nil {
		return store.Package{}, store.Verdict{}, false
	}
	p, ok := ci.pkgs[l.PackageID]
	if !ok {
		return store.Package{}, store.Verdict{}, false
	}
	return p, ci.classify(p, e), true
}

// kbPackage is one Windows update package and the builds it applies to. One
// KB number can name several packages: Windows 11 24H2 (26100) and 25H2
// (26200) share KB numbers, and so do 22H2 and 23H2.
type kbPackage struct {
	link catalogLink
	pkg  store.Package
}

type namedPackage struct {
	link    catalogLink
	version string
}

func (s *Server) catalogIndex(ctx context.Context) (*catalogIndex, error) {
	pkgs, err := s.store.ListPackages(ctx, "")
	if err != nil {
		return nil, err
	}
	return newCatalogIndex(pkgs, s.store), nil
}

// newCatalogIndex indexes pkgs; st (nil: intelligence alone decides) gives
// the store's verdict per endpoint.
func newCatalogIndex(pkgs []store.Package, st *store.Store) *catalogIndex {
	ci := &catalogIndex{byKB: map[string]catalogLink{}, kbPkgs: map[string][]kbPackage{}, byCode: map[string]namedPackage{}, byName: map[string]namedPackage{}, byID: map[string]catalogLink{},
		pkgs: map[string]store.Package{}}
	// keep the newest version per product; on a tie, the approved one.
	keep := func(m map[string]namedPackage, k string, p store.Package) {
		cur, ok := m[k]
		if v := store.AppWantVersion(p); !ok || !store.VersionAtLeast(cur.version, v) ||
			(cur.version == v && cur.link.State != "approved" && p.State == "approved") {
			m[k] = namedPackage{link: linkOf(p), version: store.AppWantVersion(p)}
		}
	}
	if st != nil {
		sup := store.SupersedingIndex(pkgs)
		ci.classify = func(p store.Package, e store.Endpoint) store.Verdict { return st.Classify(p, e, sup(p.KB)) }
	}
	for _, p := range pkgs {
		ci.pkgs[p.PackageID] = p
		ci.byID[p.PackageID] = linkOf(p)
		if p.KB != "" {
			if cur, ok := ci.byKB[strings.ToUpper(p.KB)]; !ok || cur.State != "approved" {
				ci.byKB[strings.ToUpper(p.KB)] = linkOf(p)
			}
			ci.kbPkgs[strings.ToUpper(p.KB)] = append(ci.kbPkgs[strings.ToUpper(p.KB)], kbPackage{linkOf(p), p})
		}
		if p.ProductCode != "" {
			keep(ci.byCode, strings.ToLower(p.ProductCode), p)
		}
		// EXE packages are found in Apps & features by their detection name,
		// portable apps by the name of the entry the agent writes.
		name := p.PackageName
		if p.Kind == "exe" && p.Exe != nil && strings.TrimSpace(p.Exe.Detect.DisplayName) != "" {
			name = p.Exe.Detect.DisplayName
		}
		if p.Kind == "portable" && p.Portable != nil && strings.TrimSpace(p.Portable.DisplayName) != "" {
			name = p.Portable.DisplayName
		}
		if k := intel.Normalize(name); (p.Kind == "msi" || p.Kind == "exe" || p.Kind == "portable") && k != "" && p.Version != "" {
			keep(ci.byName, nameKey(k, name), p)
		}
		if p.Kind == "exe" && p.Exe != nil && p.Exe.Detect.ProductCode != "" {
			keep(ci.byCode, strings.ToLower(p.Exe.Detect.ProductCode), p) // the ARP key inventory reports as the id
		}
		if p.Kind == "portable" && p.Portable != nil {
			keep(ci.byCode, strings.ToLower(p.Portable.ARPKey), p) // the Uninstall key the agent writes
		}
		if p.Kind == "msix" && p.Msix != nil {
			keep(ci.byCode, strings.ToLower(p.Msix.PackageFamilyName), p) // appx inventory id
		}
	}
	return ci
}

// nameKey keys the by-name index by normalized name and the architecture
// the name mentions, so the x86 and x64 builds of one product (the VC++
// redistributables: "… (x64) - 14.51" vs "… (x86) - 14.51") never link to
// each other's package.
func nameKey(normalized, displayName string) string {
	return normalized + "|" + store.ExeArchTag(displayName)
}

// byNameFor finds the package for an installed display name: one built for
// the same architecture the name mentions, else one whose name mentions none
// (a package for "7-Zip" serves "7-Zip 26.03 (x64 edition)"), never one for
// another architecture.
func (ci *catalogIndex) byNameFor(normalized, installedName string) (namedPackage, bool) {
	if n, ok := ci.byName[nameKey(normalized, installedName)]; ok {
		return n, true
	}
	n, ok := ci.byName[normalized+"|"]
	if ok || store.ExeArchTag(installedName) != "" {
		return n, ok
	}
	// The installed name mentions no architecture ("Zoom Workplace") and
	// the package's does ("Zoom Workplace (64-bit)"): the one package for
	// a single architecture serves it (the store matches it the same way);
	// several are ambiguous.
	var found namedPackage
	hits := 0
	for _, tag := range []string{"x64", "x86", "arm64", "ia64"} {
		if c, ok := ci.byName[normalized+"|"+tag]; ok {
			found, hits = c, hits+1
		}
	}
	return found, hits == 1
}

func (ci *catalogIndex) forOS(kb string) *catalogLink {
	if l, ok := ci.byKB[strings.ToUpper(kb)]; ok {
		return &l
	}
	return nil
}

// forOSAt is the package of kb that applies to endpoint e (an approved one
// first), or nil: a 24H2 package is no answer for a 25H2 machine even though
// both updates carry the same KB number. Same rule as deployments use.
func (ci *catalogIndex) forOSAt(kb string, e store.Endpoint) *catalogLink {
	var found *catalogLink
	for _, p := range ci.kbPkgs[strings.ToUpper(kb)] {
		if ok, _ := store.Applicable(p.pkg, e); !ok {
			continue
		}
		if found == nil || (found.State != "approved" && p.link.State == "approved") {
			l := p.link
			found = &l
		}
	}
	return found
}

func (ci *catalogIndex) forApp(u intel.AppUpdate) *catalogLink {
	if n, ok := ci.byCode[strings.ToLower(u.ProductCode)]; ok && u.ProductCode != "" {
		l := n.link
		return &l
	}
	if k := intel.Normalize(u.InstalledName); k != "" {
		if n, ok := ci.byNameFor(k, u.InstalledName); ok && !store.VersionAtLeast(u.InstalledVersion, n.version) {
			l := n.link
			return &l
		}
	}
	return nil
}

// forCurrentApp links an up-to-date app to its catalog package: by product
// code, or by display name whatever the version.
func (ci *catalogIndex) forCurrentApp(u intel.AppUpdate) *catalogLink {
	if n, ok := ci.byCode[strings.ToLower(u.ProductCode)]; ok && u.ProductCode != "" {
		l := n.link
		return &l
	}
	if k := intel.Normalize(u.InstalledName); k != "" {
		if n, ok := ci.byNameFor(k, u.InstalledName); ok {
			l := n.link
			return &l
		}
	}
	return nil
}

// Requested is the latest acquisition request listing the update (with
// its status and, for unsupported / failed, the reason), as on GET
// /api/updates.
type osUpdateView struct {
	intel.OSUpdate
	Catalog   *catalogLink         `json:"catalog"`
	Requested *store.AcqRequestRef `json:"requested"`
}

type appUpdateView struct {
	intel.AppUpdate
	Catalog          *catalogLink         `json:"catalog"`
	Requested        *store.AcqRequestRef `json:"requested"`
	Importable       string               `json:"importable"` // yes | no | unknown (intel.Importable for this endpoint's arch)
	ImportableReason string               `json:"importable_reason"`
}

// osImportableReason: Windows updates always come from the catalog.
const osImportableReason = "Windows cumulative update (Microsoft Update Catalog)"

// importableFor applies the Library's import rule to an update row.
func importableFor(ix *intel.Index, kind, key, version string, arches []string) (string, string) {
	if kind == "os" {
		return intel.ImportableYes, osImportableReason
	}
	return intel.Importable(ix.ResolvedFor(key, version), arches, true)
}

// fleetArches: architectures of the endpoints that have the app (outdated
// or current), as the Library computes them.
func (u *fleetUpdate) fleetArches() []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range append(append([]fleetNeed{}, u.Endpoints...), u.current...) {
		if a := strings.ToLower(n.arch); a != "" && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	sort.Strings(out)
	return out
}

type endpointUpdates struct {
	Intel     *intake.IntelSummary `json:"intel"` // nil: no update intelligence received yet
	OS        []osUpdateView       `json:"os"`
	Apps      []appUpdateView      `json:"apps"`
	Current   int                  `json:"current"`
	Unmatched int                  `json:"unmatched"`
}

func (s *Server) endpointUpdates(w http.ResponseWriter, r *http.Request) {
	e, err := s.store.GetEndpoint(r.Context(), r.PathValue("id"), s.th)
	if err != nil {
		s.fail(w, err)
		return
	}
	ix, sum, err := s.intelIndex(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	out := endpointUpdates{Intel: sum, OS: []osUpdateView{}, Apps: []appUpdateView{}}
	if ix != nil {
		ci, err := s.catalogIndex(r.Context())
		if err != nil {
			s.fail(w, err)
			return
		}
		refs, err := s.acqRefs(r.Context())
		if err != nil {
			s.fail(w, err)
			return
		}
		ep := e.Endpoint // loaded with its inventory (GetEndpoint)
		res := ix.Match(toIntelEndpoint(ep, e.Inventory))
		m := reconcile(ci, ep, res)
		out.Current, out.Unmatched = len(m.curApps), res.Unmatched
		for _, u := range m.os {
			out.OS = append(out.OS, osUpdateView{OSUpdate: u.OSUpdate, Catalog: u.cat, Requested: refFor(refs, "os", u.KB)})
		}
		for _, u := range m.apps {
			imp, why := importableFor(ix, "app", u.AppID, u.LatestVersion, []string{strings.ToLower(e.Arch)})
			var cat *catalogLink
			if u.pkgID != "" {
				l := ci.byID[u.pkgID]
				cat = &l
			}
			u.InstalledVersion = u.installed
			out.Apps = append(out.Apps, appUpdateView{AppUpdate: u.AppUpdate, Catalog: cat, Requested: liveRef(refFor(refs, "app", u.AppID), imp),
				Importable: imp, ImportableReason: why})
		}
	}
	writeJSON(w, 200, out)
}

// fleetUpdate is one available update and the endpoints that need it.
type fleetUpdate struct {
	Kind      string       `json:"kind"` // os | app
	Key       string       `json:"key"`  // KB or winget id
	Name      string       `json:"name"`
	Latest    string       `json:"latest"`
	Catalog   *catalogLink `json:"catalog"`
	Endpoints []fleetNeed  `json:"endpoints"`
	// Importable: the Library's import rule (intel.Importable with the
	// architectures of the endpoints that have the app): yes | no | unknown.
	// "no" rows get "Can't import: <reason>" instead of an Import button,
	// and requests for them are refused.
	Importable       string `json:"importable"`
	ImportableReason string `json:"importable_reason"`
	// Uncovered: endpoints needing it that no catalog package applies to
	// (Windows: the catalog has the KB only for another build, e.g. the 24H2
	// package of a KB 25H2 shares). Their builds go in UncoveredBuilds.
	Uncovered       int   `json:"uncovered"`
	UncoveredBuilds []int `json:"uncovered_builds,omitempty"`

	// For acquisition requests (not shown): the Windows release, and the
	// architectures and installed forms of an app seen across the fleet.
	releases  map[string]intel.WindowsRelease // by architecture and build (a KB can cover x64 and arm64, 24H2 and 25H2)
	arches    map[string]bool
	installed map[acqrequest.Installed]bool
	// For fleet status (not shown): endpoints that already have it, and the
	// catalog package of their (current) version.
	current    []fleetNeed
	currentCat *catalogLink
}

// releaseKey keys fleetUpdate.releases.
func releaseKey(arch string, build int) string {
	return strings.ToLower(arch) + "/" + strconv.Itoa(build)
}

// linkCatalog sets the row's package and its uncovered endpoints. Rows link
// to the package that serves most endpoints needing the update (approved
// first), so "Patch this" never offers a package that applies to none of
// them. An app row none of whose endpoints a package serves keeps its link
// only if the package is the version the row names: the package of an older
// version (one the machines already run) is no offer for it, and opening it
// from a row that says "latest 300" showed version 200.
func (u *fleetUpdate) linkCatalog(ci *catalogIndex) {
	builds := map[int]bool{}
	u.Uncovered, u.UncoveredBuilds = 0, nil
	for _, n := range u.Endpoints {
		if n.PackageID == "" {
			u.Uncovered++
			if u.Kind == "os" && n.build > 0 && !builds[n.build] {
				builds[n.build] = true
				u.UncoveredBuilds = append(u.UncoveredBuilds, n.build)
			}
		}
	}
	sort.Ints(u.UncoveredBuilds)
	if len(u.Endpoints) == 0 {
		if !u.offers(u.Catalog) {
			u.Catalog = nil
		}
		return
	}
	count := map[string]int{}
	for _, n := range u.Endpoints {
		if n.PackageID != "" {
			count[n.PackageID]++
		}
	}
	var best *catalogLink
	for id, c := range count {
		l := ci.byID[id]
		if best == nil {
			best = &l
			continue
		}
		bc := count[best.PackageID]
		better := (l.State == "approved") != (best.State == "approved") && l.State == "approved"
		if better || ((l.State == "approved") == (best.State == "approved") && (c > bc || (c == bc && id < best.PackageID))) {
			best = &l
		}
	}
	if best != nil || u.Kind == "os" || !u.offers(u.Catalog) {
		u.Catalog = best
	}
}

// offers: l (nil: none) is a package for the version the row names. Windows
// rows are keyed by KB, so any package of the KB is; an app row needs a
// package at least its latest version (a link without a version is trusted).
func (u *fleetUpdate) offers(l *catalogLink) bool {
	if l == nil || u.Kind != "app" || u.Latest == "" || (l.want == "" && l.Version == "") {
		return true
	}
	return store.VersionAtLeast(l.want, u.Latest) || store.VersionAtLeast(l.Version, u.Latest)
}

// statusCatalog is the package whose targets decide fleet status.
func (u *fleetUpdate) statusCatalog() *catalogLink {
	if u.Catalog != nil {
		return u.Catalog
	}
	if u.Kind == "os" && len(u.Endpoints) > 0 {
		// Machines need the KB but no package applies to their build: the
		// package other builds installed is no offer for them.
		return nil
	}
	if !u.offers(u.currentCat) {
		// The package of an older version than the row's latest (linked by
		// name whatever the version): not the update the row shows.
		return nil
	}
	return u.currentCat
}

type fleetNeed struct {
	EndpointID string `json:"endpoint_id"`
	Hostname   string `json:"hostname"`
	Installed  string `json:"installed"`
	// PackageID: the catalog package that applies to this endpoint ("" =
	// none; for Windows updates the package must match its build).
	PackageID string `json:"package_id,omitempty"`
	arch      string
	build     int
}

// fleetSnapshot is the matcher's view of the whole fleet. Shared: read only.
type fleetSnapshot struct {
	missing []*fleetUpdate // updates some endpoint is missing (GET /api/updates)
	all     []*fleetUpdate // missing plus updates matched endpoints already have
	perEP   map[string]store.EndpointMissing
	cat     *catalogIndex // the catalog the snapshot was built with (Library)
	// byKey: kind+"/"+key -> entry of all (Library overlay).
	byKey map[string]*fleetUpdate
}

// fleet returns every update the fleet is missing (nil without usable
// intelligence), cached for fleetTTL. The result is shared: read only.
func (s *Server) fleet(ctx context.Context) (*intake.IntelSummary, []*fleetUpdate, error) {
	sum, snap, err := s.fleetSnap(ctx, nil)
	if snap == nil {
		return sum, nil, err
	}
	return sum, snap.missing, err
}

// fleetSnap returns the cached fleet view: rebuilt when older than
// fleetTTL, when the intelligence document changed or when the store
// changed (catalog states, deployments, inventory: store.Generation). One
// rebuild at a time; concurrent callers wait for it. eps, if not nil, are
// the endpoints with inventory (as from ListEndpoints) to build from;
// otherwise a fresh list is loaded. nil without usable intelligence.
func (s *Server) fleetSnap(ctx context.Context, eps []store.Endpoint) (*intake.IntelSummary, *fleetSnapshot, error) {
	ix, sum, err := s.intelIndex(ctx)
	if err != nil || ix == nil {
		return sum, nil, err
	}
	if f := s.cachedFleet(sum.GeneratedAt); f != nil {
		return sum, f, nil
	}
	s.intel.fleetBuild.Lock()
	defer s.intel.fleetBuild.Unlock()
	if f := s.cachedFleet(sum.GeneratedAt); f != nil {
		return sum, f, nil
	}
	gen := s.store.Generation() // before reading: a change meanwhile leaves it stale
	if eps == nil {
		if eps, err = s.store.ListEndpoints(ctx, s.th); err != nil {
			return nil, nil, err
		}
	}
	ci, err := s.catalogIndex(ctx)
	if err != nil {
		return nil, nil, err
	}
	snap := buildFleet(ix, ci, eps)
	snap.cat = ci
	s.intel.mu.Lock()
	s.intel.fleet, s.intel.fleetGen, s.intel.fleetStoreGen, s.intel.fleetAt = snap, sum.GeneratedAt, gen, time.Now()
	s.intel.mu.Unlock()
	return sum, snap, nil
}

// cachedFleet is the cached snapshot if still valid for the intelligence
// generation, else nil.
func (s *Server) cachedFleet(intelGen string) *fleetSnapshot {
	s.intel.mu.Lock()
	defer s.intel.mu.Unlock()
	if s.intel.fleet != nil && s.intel.fleetGen == intelGen && s.intel.fleetStoreGen == s.store.Generation() && time.Since(s.intel.fleetAt) < fleetTTL {
		return s.intel.fleet
	}
	return nil
}

// endpointMatch is one endpoint's intelligence result with the store's
// verdict applied: where a catalog package is linked, the store (the rule
// deployments and GET /api/packages-needs use) decides "needed" vs
// "current". Both the fleet view and the endpoint's own update list use it.
type endpointMatch struct {
	os      []osNeed
	curOS   []intel.WindowsRelease
	apps    []appNeed
	curApps []appCurrent
}

type osNeed struct {
	intel.OSUpdate
	cat *catalogLink // the package for the endpoint's build, nil if none
}

type appNeed struct {
	intel.AppUpdate
	rowCat    *catalogLink // the catalog link found for the update (row)
	pkgID     string       // the package that serves this endpoint ("" = none)
	installed string       // the version a deployment would update
}

type appCurrent struct {
	intel.AppUpdate
	cat *catalogLink
}

func reconcile(ci *catalogIndex, e store.Endpoint, res intel.Result) endpointMatch {
	m := endpointMatch{curOS: append([]intel.WindowsRelease(nil), res.CurrentOS...)}
	for _, o := range res.OS {
		cat := ci.forOSAt(o.KB, e)
		if _, v, ok := ci.verdict(cat, e); ok && v.Presence == store.PresencePresent {
			// The catalog package is installed after all (a superseding KB,
			// or the build revision proves it): not missing.
			m.curOS = append(m.curOS, o.WindowsRelease)
			continue
		}
		m.os = append(m.os, osNeed{o, cat})
	}
	for _, a := range res.Apps {
		cat := ci.forApp(a)
		n := appNeed{AppUpdate: a, rowCat: cat, installed: a.InstalledVersion}
		if cat != nil {
			n.pkgID = cat.PackageID
		}
		if p, v, ok := ci.verdict(cat, e); ok {
			switch v.Presence {
			case store.PresencePresent:
				if store.VersionAtLeast(store.AppWantVersion(p), a.Target) {
					// The package is installed and is what the intelligence
					// calls current (versions written differently): current.
					m.curApps = append(m.curApps, appCurrent{a, cat})
					continue
				}
				n.pkgID = "" // the catalog only has an older version: it does not help
			case store.PresenceNeeded:
			default:
				n.pkgID = "" // not for this machine (architecture, per-user install, ...)
			}
		}
		m.apps = append(m.apps, n)
	}
	for _, a := range res.CurrentApps {
		cat := ci.forCurrentApp(a)
		if _, v, ok := ci.verdict(cat, e); ok && v.Presence == store.PresenceNeeded {
			// A deployment of the catalog package would install it here (it
			// is newer than what the machine runs, or the copy the
			// intelligence saw is a per-user one an EXE package does not
			// count): needed, as GET /api/packages-needs says.
			have := v.Have
			if have == "" {
				have = a.InstalledVersion
			}
			m.apps = append(m.apps, appNeed{AppUpdate: a, rowCat: cat, pkgID: cat.PackageID, installed: have})
			continue
		}
		m.curApps = append(m.curApps, appCurrent{a, cat})
	}
	return m
}

// needApp records that endpoint e needs app update a (installed: the
// version it runs; pkgID: the catalog package that serves it, "" if none).
func needApp(u *fleetUpdate, e store.Endpoint, a intel.AppUpdate, installed, pkgID string) {
	u.arches[strings.ToLower(e.Arch)] = true
	u.installed[acqrequest.Installed{ProductCode: a.ProductCode, Name: a.InstalledName, Version: a.InstalledVersion}] = true
	u.Endpoints = append(u.Endpoints, fleetNeed{EndpointID: e.EndpointID, Hostname: e.Hostname, Installed: installed, PackageID: pkgID, arch: e.Arch, build: e.Build})
}

// buildFleet matches every endpoint against the intelligence. Where a
// catalog package is linked, the store's verdict (store.Classify, the rule
// deployments and GET /api/packages-needs use) has the last word on
// "needed" vs "current", so Patches → Needed, the fleet status, Patch this
// and acquisition requests agree with what a deployment would do.
func buildFleet(ix *intel.Index, ci *catalogIndex, eps []store.Endpoint) *fleetSnapshot {
	agg := map[string]*fleetUpdate{}
	get := func(kind, key, name, latest string, cat *catalogLink) *fleetUpdate {
		if u := agg[kind+"/"+key]; u != nil {
			if u.Catalog == nil {
				u.Catalog = cat
			}
			return u
		}
		u := &fleetUpdate{Kind: kind, Key: key, Name: name, Latest: latest, Catalog: cat, arches: map[string]bool{}, installed: map[acqrequest.Installed]bool{}}
		agg[kind+"/"+key] = u
		return u
	}
	snap := &fleetSnapshot{perEP: map[string]store.EndpointMissing{}}
	for _, e := range eps {
		if e.RetiredAt != "" {
			continue
		}
		ie := toIntelEndpoint(e, e.InventoryItems())
		m := reconcile(ci, e, ix.Match(ie))
		support, last := ix.OSSupport(ie)
		for _, o := range m.os {
			u := get("os", o.KB, o.Title, o.KB, nil)
			if u.releases == nil {
				u.releases = map[string]intel.WindowsRelease{}
			}
			u.releases[releaseKey(o.Arch, o.Build)] = o.WindowsRelease
			n := fleetNeed{EndpointID: e.EndpointID, Hostname: e.Hostname, Installed: e.OSVersion, arch: e.Arch, build: e.Build}
			if o.cat != nil {
				n.PackageID = o.cat.PackageID
			}
			u.Endpoints = append(u.Endpoints, n)
		}
		for _, a := range m.apps {
			needApp(get("app", a.AppID, a.Name, a.LatestVersion, a.rowCat), e, a.AppUpdate, a.installed, a.pkgID)
		}
		for _, w := range m.curOS {
			u := get("os", w.KB, w.Title, w.KB, nil)
			if u.currentCat == nil {
				u.currentCat = ci.forOSAt(w.KB, e)
			}
			u.current = append(u.current, fleetNeed{EndpointID: e.EndpointID, Hostname: e.Hostname, Installed: e.OSVersion, arch: e.Arch})
		}
		for _, a := range m.curApps {
			u := get("app", a.AppID, a.Name, a.LatestVersion, nil)
			if u.currentCat == nil {
				u.currentCat = a.cat
			}
			u.current = append(u.current, fleetNeed{EndpointID: e.EndpointID, Hostname: e.Hostname, Installed: a.InstalledVersion, arch: e.Arch})
		}
		nOS, nApps := len(m.os), len(m.apps)
		snap.perEP[e.EndpointID] = store.EndpointMissing{OS: nOS, Apps: nApps, OSSupport: support, OSLastUpdate: last}
	}
	snap.byKey = agg
	for _, u := range agg {
		u.linkCatalog(ci)
		u.Importable, u.ImportableReason = importableFor(ix, u.Kind, u.Key, u.Latest, u.fleetArches())
		snap.all = append(snap.all, u)
	}
	sort.Slice(snap.all, func(i, j int) bool {
		a, b := snap.all[i], snap.all[j]
		if a.Kind != b.Kind {
			return a.Kind == "os" // Windows updates first
		}
		if len(a.Endpoints) != len(b.Endpoints) {
			return len(a.Endpoints) > len(b.Endpoints)
		}
		if len(a.current) != len(b.current) {
			return len(a.current) > len(b.current)
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
	snap.missing = make([]*fleetUpdate, 0, len(snap.all))
	for _, u := range snap.all {
		if len(u.Endpoints) > 0 {
			snap.missing = append(snap.missing, u)
		}
	}
	return snap
}

// fleetUpdateView is a cached row plus the latest acquisition request listing it.
type fleetUpdateView struct {
	*fleetUpdate
	Requested *store.AcqRequestRef `json:"requested"`
}

func (s *Server) fleetUpdates(w http.ResponseWriter, r *http.Request) {
	sum, updates, err := s.fleet(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	refs, err := s.acqRefs(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	out := make([]fleetUpdateView, 0, len(updates))
	for _, u := range updates {
		out = append(out, fleetUpdateView{fleetUpdate: u, Requested: liveRef(refFor(refs, u.Kind, u.Key), u.Importable)})
	}
	writeJSON(w, 200, struct {
		Intel   *intake.IntelSummary `json:"intel"`
		Updates []fleetUpdateView    `json:"updates"`
	}{sum, out})
}

func refFor(refs map[string]store.AcqRequestRef, kind, key string) *store.AcqRequestRef {
	if r, ok := refs[store.AcqRefKey(kind, key)]; ok {
		return &r
	}
	return nil
}

// liveRef drops an old "can't import" (unsupported) result once the current
// import rule says the app can be imported: it was reported by an older
// acquisition (before EXE, zip, MSIX or portable support, or for an older
// version), so the row offers Import again instead of a stale refusal.
func liveRef(r *store.AcqRequestRef, importable string) *store.AcqRequestRef {
	if r != nil && r.Status == "unsupported" && importable == intel.ImportableYes {
		return nil
	}
	return r
}

func (s *Server) intelStatus(w http.ResponseWriter, r *http.Request) {
	_, sum, err := s.intelIndex(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"intel": sum})
}
