package server

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
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
	s.intel.generated, s.intel.ix, s.intel.err, s.intel.errAt = gen, ix, err, time.Now()
	s.intel.fleet, s.intel.status = nil, nil
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
}

// catalogIndex finds catalog packages for available updates: Windows updates
// by KB, applications by MSI product code or, because a new MSI version
// usually has a new product code, by its Apps & features display name
// (package_name, compared normalised like the intelligence does, so "7-Zip"
// matches "7-Zip 26.03 (x64 edition)") when the package is newer than what
// is installed.
type catalogIndex struct {
	byKB           map[string]catalogLink
	byCode, byName map[string]namedPackage
	byID           map[string]catalogLink // every package by package_id (Library: pmctl's winget package ids)
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
	ci := &catalogIndex{byKB: map[string]catalogLink{}, byCode: map[string]namedPackage{}, byName: map[string]namedPackage{}, byID: map[string]catalogLink{}}
	// keep the newest version per product; on a tie, the approved one.
	keep := func(m map[string]namedPackage, k string, p store.Package) {
		cur, ok := m[k]
		if !ok || !store.VersionAtLeast(cur.version, p.Version) ||
			(cur.version == p.Version && cur.link.State != "approved" && p.State == "approved") {
			m[k] = namedPackage{link: catalogLink{PackageID: p.PackageID, State: p.State}, version: p.Version}
		}
	}
	for _, p := range pkgs {
		ci.byID[p.PackageID] = catalogLink{PackageID: p.PackageID, State: p.State}
		if p.KB != "" {
			if cur, ok := ci.byKB[strings.ToUpper(p.KB)]; !ok || cur.State != "approved" {
				ci.byKB[strings.ToUpper(p.KB)] = catalogLink{PackageID: p.PackageID, State: p.State}
			}
		}
		if p.ProductCode != "" {
			keep(ci.byCode, strings.ToLower(p.ProductCode), p)
		}
		if k := intel.Normalize(p.PackageName); (p.Kind == "msi" || p.Kind == "exe") && k != "" && p.Version != "" {
			keep(ci.byName, nameKey(k, p.PackageName), p)
		}
		if p.Kind == "exe" && p.Exe != nil && p.Exe.Detect.ProductCode != "" {
			keep(ci.byCode, strings.ToLower(p.Exe.Detect.ProductCode), p) // the ARP key inventory reports as the id
		}
	}
	return ci, nil
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
	return n, ok
}

func (ci *catalogIndex) forOS(kb string) *catalogLink {
	if l, ok := ci.byKB[strings.ToUpper(kb)]; ok {
		return &l
	}
	return nil
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
		res := ix.Match(toIntelEndpoint(e.Endpoint, e.Inventory))
		out.Current, out.Unmatched = res.Current, res.Unmatched
		for _, u := range res.OS {
			out.OS = append(out.OS, osUpdateView{OSUpdate: u, Catalog: ci.forOS(u.KB), Requested: refFor(refs, "os", u.KB)})
		}
		for _, u := range res.Apps {
			imp, why := importableFor(ix, "app", u.AppID, u.LatestVersion, []string{strings.ToLower(e.Arch)})
			out.Apps = append(out.Apps, appUpdateView{AppUpdate: u, Catalog: ci.forApp(u), Requested: refFor(refs, "app", u.AppID),
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

	// For acquisition requests (not shown): the Windows release, and the
	// architectures and installed forms of an app seen across the fleet.
	releases  map[string]intel.WindowsRelease // by architecture (a KB can cover x64 and arm64)
	arches    map[string]bool
	installed map[acqrequest.Installed]bool
	// For fleet status (not shown): endpoints that already have it, and the
	// catalog package of their (current) version.
	current    []fleetNeed
	currentCat *catalogLink
}

// statusCatalog is the package whose targets decide fleet status.
func (u *fleetUpdate) statusCatalog() *catalogLink {
	if u.Catalog != nil {
		return u.Catalog
	}
	return u.currentCat
}

type fleetNeed struct {
	EndpointID string `json:"endpoint_id"`
	Hostname   string `json:"hostname"`
	Installed  string `json:"installed"`
	arch       string
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
		res := ix.Match(ie)
		support, last := ix.OSSupport(ie)
		snap.perEP[e.EndpointID] = store.EndpointMissing{OS: len(res.OS), Apps: len(res.Apps), OSSupport: support, OSLastUpdate: last}
		for _, o := range res.OS {
			u := get("os", o.KB, o.Title, o.KB, ci.forOS(o.KB))
			if cur, ok := u.releases[o.Arch]; ok && cur.Build != o.Build {
				o.Build = 0 // one KB for several builds (e.g. 22H2 and 23H2): do not pin the build
			}
			if u.releases == nil {
				u.releases = map[string]intel.WindowsRelease{}
			}
			u.releases[o.Arch] = o.WindowsRelease
			u.Endpoints = append(u.Endpoints, fleetNeed{EndpointID: e.EndpointID, Hostname: e.Hostname, Installed: e.OSVersion, arch: e.Arch})
		}
		for _, a := range res.Apps {
			u := get("app", a.AppID, a.Name, a.LatestVersion, ci.forApp(a))
			u.arches[strings.ToLower(e.Arch)] = true
			u.installed[acqrequest.Installed{ProductCode: a.ProductCode, Name: a.InstalledName, Version: a.InstalledVersion}] = true
			u.Endpoints = append(u.Endpoints, fleetNeed{EndpointID: e.EndpointID, Hostname: e.Hostname, Installed: a.InstalledVersion, arch: e.Arch})
		}
		for _, w := range res.CurrentOS {
			u := get("os", w.KB, w.Title, w.KB, nil)
			if u.currentCat == nil {
				u.currentCat = ci.forOS(w.KB)
			}
			u.current = append(u.current, fleetNeed{EndpointID: e.EndpointID, Hostname: e.Hostname, Installed: e.OSVersion, arch: e.Arch})
		}
		for _, a := range res.CurrentApps {
			u := get("app", a.AppID, a.Name, a.LatestVersion, nil)
			if u.currentCat == nil {
				u.currentCat = ci.forCurrentApp(a)
			}
			u.current = append(u.current, fleetNeed{EndpointID: e.EndpointID, Hostname: e.Hostname, Installed: a.InstalledVersion, arch: e.Arch})
		}
	}
	snap.byKey = agg
	for _, u := range agg {
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
		out = append(out, fleetUpdateView{fleetUpdate: u, Requested: refFor(refs, u.Kind, u.Key)})
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

func (s *Server) intelStatus(w http.ResponseWriter, r *http.Request) {
	_, sum, err := s.intelIndex(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"intel": sum})
}
