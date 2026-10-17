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

func (s *Server) catalogByKB(ctx context.Context) (map[string]catalogLink, map[string]catalogLink, error) {
	pkgs, err := s.store.ListPackages(ctx, "")
	if err != nil {
		return nil, nil, err
	}
	byKB, byCode := map[string]catalogLink{}, map[string]catalogLink{}
	for _, p := range pkgs {
		l := catalogLink{PackageID: p.PackageID, State: p.State}
		if p.KB != "" {
			if cur, ok := byKB[strings.ToUpper(p.KB)]; !ok || cur.State != "approved" {
				byKB[strings.ToUpper(p.KB)] = l
			}
		}
		if p.ProductCode != "" {
			byCode[strings.ToLower(p.ProductCode)] = l
		}
	}
	return byKB, byCode, nil
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
		byKB, byCode, err := s.catalogByKB(r.Context())
		if err != nil {
			s.fail(w, err)
			return
		}
		res := ix.Match(toIntelEndpoint(e.Endpoint, e.Inventory))
		out.Current, out.Unmatched = res.Current, res.Unmatched
		for _, u := range res.OS {
			v := osUpdateView{OSUpdate: u}
			if l, ok := byKB[strings.ToUpper(u.KB)]; ok {
				v.Catalog = &l
			}
			out.OS = append(out.OS, v)
		}
		for _, u := range res.Apps {
			v := appUpdateView{AppUpdate: u}
			if l, ok := byCode[strings.ToLower(u.ProductCode)]; ok && u.ProductCode != "" {
				v.Catalog = &l
			}
			out.Apps = append(out.Apps, v)
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
}

type fleetNeed struct {
	EndpointID string `json:"endpoint_id"`
	Hostname   string `json:"hostname"`
	Installed  string `json:"installed"`
}

func (s *Server) fleetUpdates(w http.ResponseWriter, r *http.Request) {
	ix, sum, err := s.intelIndex(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	out := struct {
		Intel   *intake.IntelSummary `json:"intel"`
		Updates []*fleetUpdate       `json:"updates"`
	}{Intel: sum, Updates: []*fleetUpdate{}}
	if ix == nil {
		writeJSON(w, 200, out)
		return
	}
	s.intel.mu.Lock()
	cached := s.intel.fleet != nil && s.intel.fleetGen == sum.GeneratedAt && time.Since(s.intel.fleetAt) < fleetTTL
	if cached {
		out.Updates = s.intel.fleet
	}
	s.intel.mu.Unlock()
	if cached {
		writeJSON(w, 200, out)
		return
	}
	eps, err := s.store.ListEndpoints(r.Context(), s.th)
	if err != nil {
		s.fail(w, err)
		return
	}
	byKB, byCode, err := s.catalogByKB(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	agg := map[string]*fleetUpdate{}
	get := func(kind, key, name, latest string, cat *catalogLink) *fleetUpdate {
		if u := agg[kind+"\x00"+key]; u != nil {
			return u
		}
		u := &fleetUpdate{Kind: kind, Key: key, Name: name, Latest: latest, Catalog: cat}
		agg[kind+"\x00"+key] = u
		return u
	}
	for _, e := range eps {
		if e.RetiredAt != "" {
			continue
		}
		res := ix.Match(toIntelEndpoint(e, e.InventoryItems()))
		for _, o := range res.OS {
			var cat *catalogLink
			if l, ok := byKB[strings.ToUpper(o.KB)]; ok {
				cat = &l
			}
			u := get("os", o.KB, o.Title, o.KB, cat)
			u.Endpoints = append(u.Endpoints, fleetNeed{EndpointID: e.EndpointID, Hostname: e.Hostname, Installed: e.OSVersion})
		}
		for _, a := range res.Apps {
			var cat *catalogLink
			if l, ok := byCode[strings.ToLower(a.ProductCode)]; ok && a.ProductCode != "" {
				cat = &l
			}
			u := get("app", a.AppID, a.Name, a.LatestVersion, cat)
			u.Endpoints = append(u.Endpoints, fleetNeed{EndpointID: e.EndpointID, Hostname: e.Hostname, Installed: a.InstalledVersion})
		}
	}
	for _, u := range agg {
		out.Updates = append(out.Updates, u)
	}
	sort.Slice(out.Updates, func(i, j int) bool {
		a, b := out.Updates[i], out.Updates[j]
		if a.Kind != b.Kind {
			return a.Kind == "os" // Windows updates first
		}
		if len(a.Endpoints) != len(b.Endpoints) {
			return len(a.Endpoints) > len(b.Endpoints)
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
	s.intel.mu.Lock()
	s.intel.fleet, s.intel.fleetGen, s.intel.fleetAt = out.Updates, sum.GeneratedAt, time.Now()
	s.intel.mu.Unlock()
	writeJSON(w, 200, out)
}

func (s *Server) intelStatus(w http.ResponseWriter, r *http.Request) {
	_, sum, err := s.intelIndex(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"intel": sum})
}
