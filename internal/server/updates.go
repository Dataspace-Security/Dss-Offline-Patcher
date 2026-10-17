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

	fleetAt  time.Time
	fleetGen string
	fleet    []*fleetUpdate
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
	s.intel.fleet = nil
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
	ci := &catalogIndex{byKB: map[string]catalogLink{}, byCode: map[string]namedPackage{}, byName: map[string]namedPackage{}}
	// keep the newest version per product; on a tie, the approved one.
	keep := func(m map[string]namedPackage, k string, p store.Package) {
		cur, ok := m[k]
		if !ok || !store.VersionAtLeast(cur.version, p.Version) ||
			(cur.version == p.Version && cur.link.State != "approved" && p.State == "approved") {
			m[k] = namedPackage{link: catalogLink{PackageID: p.PackageID, State: p.State}, version: p.Version}
		}
	}
	for _, p := range pkgs {
		if p.KB != "" {
			if cur, ok := ci.byKB[strings.ToUpper(p.KB)]; !ok || cur.State != "approved" {
				ci.byKB[strings.ToUpper(p.KB)] = catalogLink{PackageID: p.PackageID, State: p.State}
			}
		}
		if p.ProductCode != "" {
			keep(ci.byCode, strings.ToLower(p.ProductCode), p)
		}
		if k := intel.Normalize(p.PackageName); p.Kind == "msi" && k != "" && p.Version != "" {
			keep(ci.byName, k, p)
		}
	}
	return ci, nil
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
		if n, ok := ci.byName[k]; ok && !store.VersionAtLeast(u.InstalledVersion, n.version) {
			l := n.link
			return &l
		}
	}
	return nil
}

type osUpdateView struct {
	intel.OSUpdate
	Catalog *catalogLink `json:"catalog"`
}

type appUpdateView struct {
	intel.AppUpdate
	Catalog *catalogLink `json:"catalog"`
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
		res := ix.Match(toIntelEndpoint(e.Endpoint, e.Inventory))
		out.Current, out.Unmatched = res.Current, res.Unmatched
		for _, u := range res.OS {
			out.OS = append(out.OS, osUpdateView{OSUpdate: u, Catalog: ci.forOS(u.KB)})
		}
		for _, u := range res.Apps {
			out.Apps = append(out.Apps, appUpdateView{AppUpdate: u, Catalog: ci.forApp(u)})
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

	// For acquisition requests (not shown): the Windows release, and the
	// architectures and installed forms of an app seen across the fleet.
	releases  map[string]intel.WindowsRelease // by architecture (a KB can cover x64 and arm64)
	arches    map[string]bool
	installed map[acqrequest.Installed]bool
}

type fleetNeed struct {
	EndpointID string `json:"endpoint_id"`
	Hostname   string `json:"hostname"`
	Installed  string `json:"installed"`
	arch       string
}

// fleet returns every update the fleet is missing (nil without usable
// intelligence), cached for fleetTTL. The result is shared: read only.
func (s *Server) fleet(ctx context.Context) (*intake.IntelSummary, []*fleetUpdate, error) {
	ix, sum, err := s.intelIndex(ctx)
	if err != nil || ix == nil {
		return sum, nil, err
	}
	s.intel.mu.Lock()
	if s.intel.fleet != nil && s.intel.fleetGen == sum.GeneratedAt && time.Since(s.intel.fleetAt) < fleetTTL {
		f := s.intel.fleet
		s.intel.mu.Unlock()
		return sum, f, nil
	}
	s.intel.mu.Unlock()
	eps, err := s.store.ListEndpoints(ctx, s.th)
	if err != nil {
		return nil, nil, err
	}
	ci, err := s.catalogIndex(ctx)
	if err != nil {
		return nil, nil, err
	}
	agg := map[string]*fleetUpdate{}
	get := func(kind, key, name, latest string, cat *catalogLink) *fleetUpdate {
		if u := agg[kind+"/"+key]; u != nil {
			return u
		}
		u := &fleetUpdate{Kind: kind, Key: key, Name: name, Latest: latest, Catalog: cat, arches: map[string]bool{}, installed: map[acqrequest.Installed]bool{}}
		agg[kind+"/"+key] = u
		return u
	}
	for _, e := range eps {
		if e.RetiredAt != "" {
			continue
		}
		res := ix.Match(toIntelEndpoint(e, e.InventoryItems()))
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
			if u.Catalog == nil {
				u.Catalog = ci.forApp(a)
			}
			u.arches[strings.ToLower(e.Arch)] = true
			u.installed[acqrequest.Installed{ProductCode: a.ProductCode, Name: a.InstalledName, Version: a.InstalledVersion}] = true
			u.Endpoints = append(u.Endpoints, fleetNeed{EndpointID: e.EndpointID, Hostname: e.Hostname, Installed: a.InstalledVersion, arch: e.Arch})
		}
	}
	out := make([]*fleetUpdate, 0, len(agg))
	for _, u := range agg {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Kind != b.Kind {
			return a.Kind == "os" // Windows updates first
		}
		if len(a.Endpoints) != len(b.Endpoints) {
			return len(a.Endpoints) > len(b.Endpoints)
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
	s.intel.mu.Lock()
	s.intel.fleet, s.intel.fleetGen, s.intel.fleetAt = out, sum.GeneratedAt, time.Now()
	s.intel.mu.Unlock()
	return sum, out, nil
}

func (s *Server) fleetUpdates(w http.ResponseWriter, r *http.Request) {
	sum, updates, err := s.fleet(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	if updates == nil {
		updates = []*fleetUpdate{}
	}
	writeJSON(w, 200, struct {
		Intel   *intake.IntelSummary `json:"intel"`
		Updates []*fleetUpdate       `json:"updates"`
	}{sum, updates})
}

func (s *Server) intelStatus(w http.ResponseWriter, r *http.Request) {
	_, sum, err := s.intelIndex(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"intel": sum})
}
