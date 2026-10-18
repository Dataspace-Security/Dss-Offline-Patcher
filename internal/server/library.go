package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"offpatch/internal/intake"
	"offpatch/internal/intel"
	"offpatch/internal/store"
)

// The Library (docs/05-api.md "Library"): one searchable list of everything
// the update intelligence knows upstream (~16k winget apps and the Windows
// cumulative updates per build), with what offpatch can import, what the
// fleet has installed, what is in the catalog and what was requested.
//
// The index is untrusted community data inside a signed document: the
// server never fetches anything and never uses a link. Text is returned as
// data (bounded, control characters removed) and only https URLs of at most
// 2 KB are returned; anything else is dropped. Importing still goes through
// an acquisition request and arrives as a signed bundle in quarantine.
//
// Search keys and per-entry static fields are built once per intelligence
// generation (libIndex, one build at a time); the per-request overlay
// (installed counts, catalog, requests) comes from the cached fleet
// snapshot and request refs. A request scans the ~16k entries linearly.

const (
	libDefaultPerPage = 50
	libMaxPerPage     = 100
	maxLinkLen        = 2048
	maxLibName        = 200
	maxLibDescription = 1000
	maxLibInstallers  = 20
)

type libLinks struct {
	Homepage     string `json:"homepage"`
	PublisherURL string `json:"publisher_url"`
	Manifest     string `json:"manifest"`
}

type libInstaller struct {
	Arch        string `json:"arch"`
	Type        string `json:"type"`
	Scope       string `json:"scope,omitempty"`
	URL         string `json:"url"`
	SHA256      string `json:"sha256,omitempty"`
	ProductCode string `json:"product_code,omitempty"`
}

type libInstalled struct {
	Endpoints int `json:"endpoints"`
	Outdated  int `json:"outdated"`
}

// libraryItem is one Library row (GET /api/library).
type libraryItem struct {
	Kind             string               `json:"kind"` // app | os
	ID               string               `json:"id"`   // winget id or KB
	Name             string               `json:"name"`
	Publisher        string               `json:"publisher"`
	LatestVersion    string               `json:"latest_version"`
	Description      string               `json:"description"`
	Links            libLinks             `json:"links"`
	Installers       []libInstaller       `json:"installers"` // null: not resolved
	ResolvedAt       string               `json:"resolved_at"`
	Importable       string               `json:"importable"` // yes | no | unknown
	ImportableReason string               `json:"importable_reason"`
	Installed        libInstalled         `json:"installed"`
	Catalog          *catalogLink         `json:"catalog"`
	Requested        *store.AcqRequestRef `json:"requested"`
}

// libEntry is the per-generation, request-independent part of a row.
type libEntry struct {
	item   libraryItem // Installed/Catalog/Requested/Importable filled per request
	search string      // lower-case name, id, publisher, product codes
	pub    string      // lower-case publisher (facet)
	date   string      // sort=date: release date (os) or resolved_at (app)
	res    *intel.Resolved
	kbs    []intel.WindowsRelease // os: the releases (per arch) of this KB
	appVer string
	// The importable rule for an app installed nowhere (any architecture),
	// computed once; rows of installed apps apply it to the fleet's arches.
	impAny, impAnyWhy string
}

type libIndex struct {
	ix      *intel.Index
	entries []libEntry
	byKey   map[string]int // kind + "\x00" + lower-case id
}

type libCache struct {
	mu    sync.Mutex
	build sync.Mutex
	v     *libIndex
}

// libraryIndex returns the Library index for the current intelligence (nil
// without usable intelligence), building it once per generation.
func (s *Server) libraryIndex(ctx context.Context) (*libIndex, error) {
	ix, _, err := s.intelIndex(ctx)
	if err != nil || ix == nil {
		return nil, err
	}
	get := func() *libIndex {
		s.lib.mu.Lock()
		defer s.lib.mu.Unlock()
		if s.lib.v != nil && s.lib.v.ix == ix {
			return s.lib.v
		}
		return nil
	}
	if v := get(); v != nil {
		return v, nil
	}
	s.lib.build.Lock()
	defer s.lib.build.Unlock()
	if v := get(); v != nil {
		return v, nil
	}
	v := buildLibIndex(ix)
	s.lib.mu.Lock()
	s.lib.v = v
	s.lib.mu.Unlock()
	return v, nil
}

func libKey(kind, id string) string { return kind + "\x00" + strings.ToLower(id) }

func buildLibIndex(ix *intel.Index) *libIndex {
	d := ix.Doc
	li := &libIndex{ix: ix, entries: make([]libEntry, 0, len(d.Apps)+len(d.Windows)), byKey: map[string]int{}}
	// Windows cumulative updates: one row per KB (a KB can cover x64 and arm64).
	for _, w := range d.Windows {
		k := libKey("os", w.KB)
		if i, ok := li.byKey[k]; ok {
			e := &li.entries[i]
			e.kbs = append(e.kbs, w)
			continue
		}
		kb := strings.ToUpper(w.KB)
		ver := strconv.Itoa(w.Build)
		if w.UBR > 0 {
			ver += "." + strconv.Itoa(w.UBR)
		}
		it := libraryItem{Kind: "os", ID: kb, Name: cleanLibText(w.Title, maxLibName), Publisher: "Microsoft", LatestVersion: ver,
			Description: cleanLibText(w.Product, maxLibName),
			Links:       libLinks{Homepage: safeLink("https://www.catalog.update.microsoft.com/Search.aspx?q=" + url.QueryEscape(kb))},
			Importable:  intel.ImportableYes, ImportableReason: "Windows cumulative update (Microsoft Update Catalog)"}
		li.byKey[k] = len(li.entries)
		li.entries = append(li.entries, libEntry{item: it, pub: "microsoft", date: w.ReleaseDate, kbs: []intel.WindowsRelease{w},
			search: strings.ToLower(strings.Join([]string{it.Name, kb, "microsoft windows", w.Product}, "\x00"))})
	}
	for _, a := range d.Apps {
		k := libKey("app", a.ID)
		if _, dup := li.byKey[k]; dup {
			continue
		}
		res := ix.ResolvedFor(a.ID, a.Version)
		it := libraryItem{Kind: "app", ID: a.ID, Name: cleanLibText(a.Name, maxLibName), LatestVersion: a.Version,
			Links: libLinks{Manifest: wingetManifestURL(a.ID, a.Version)}}
		if it.Name == "" {
			it.Name = a.ID
		}
		if len(a.Publishers) > 0 {
			it.Publisher = cleanLibText(a.Publishers[0], maxLibName)
		}
		if res != nil {
			if p := cleanLibText(res.Publisher, maxLibName); p != "" {
				it.Publisher = p
			}
			it.Description = cleanLibText(res.Description, maxLibDescription)
			it.Links.Homepage, it.Links.PublisherURL = safeLink(res.Homepage), safeLink(res.PublisherURL)
			it.ResolvedAt = cleanLibText(res.ResolvedAt, 40)
			it.Installers = make([]libInstaller, 0, len(res.Installers))
			for i, in := range res.Installers {
				if i >= maxLibInstallers {
					break
				}
				it.Installers = append(it.Installers, libInstaller{Arch: cleanToken(in.Arch), Type: cleanToken(in.Type), Scope: cleanToken(in.Scope),
					URL: safeLink(in.URL), SHA256: cleanHex(in.SHA256), ProductCode: cleanProductCode(in.ProductCode)})
			}
		}
		parts := []string{it.Name, a.ID, it.Publisher}
		parts = append(parts, a.Codes...)
		if res != nil {
			for _, in := range res.Installers {
				if in.ProductCode != "" {
					parts = append(parts, in.ProductCode)
				}
			}
		}
		imp, why := intel.Importable(res, nil, true)
		li.byKey[k] = len(li.entries)
		li.entries = append(li.entries, libEntry{item: it, res: res, appVer: a.Version, pub: strings.ToLower(it.Publisher), date: it.ResolvedAt,
			search: strings.ToLower(strings.Join(parts, "\x00")), impAny: imp, impAnyWhy: why})
	}
	return li
}

// libOverlay is the per-request view: fleet snapshot (may be nil), request
// refs and the catalog.
type libOverlay struct {
	snap *fleetSnapshot
	refs map[string]store.AcqRequestRef
}

// row fills the dynamic fields of entry e.
func (o libOverlay) row(e *libEntry) (libraryItem, *fleetUpdate) {
	it := e.item
	var u *fleetUpdate
	if o.snap != nil {
		u = o.snap.byKey[it.Kind+"/"+fleetKey(e)]
	}
	var arches []string
	if u != nil {
		it.Installed = libInstalled{Endpoints: len(u.Endpoints) + len(u.current), Outdated: len(u.Endpoints)}
		it.Catalog = u.statusCatalog()
		seen := map[string]bool{}
		for _, n := range append(append([]fleetNeed{}, u.Endpoints...), u.current...) {
			if a := strings.ToLower(n.arch); a != "" && !seen[a] {
				seen[a] = true
				arches = append(arches, a)
			}
		}
		sort.Strings(arches)
	}
	if it.Kind == "app" {
		if it.Catalog == nil && o.snap != nil && o.snap.cat != nil {
			// Not installed anywhere (or not linked by product code/name):
			// the package pmctl builds for this version.
			for _, ar := range []string{"x64", "x86", "arm64"} {
				if l, ok := o.snap.cat.byID[store.WingetPackageID(it.ID, e.appVer, ar)]; ok {
					l := l
					it.Catalog = &l
					break
				}
			}
		}
		if len(arches) == 0 {
			it.Importable, it.ImportableReason = e.impAny, e.impAnyWhy
		} else {
			it.Importable, it.ImportableReason = intel.Importable(e.res, arches, true)
		}
	} else if it.Catalog == nil && o.snap != nil && o.snap.cat != nil {
		it.Catalog = o.snap.cat.forOS(it.ID)
	}
	it.Requested = refFor(o.refs, it.Kind, it.ID)
	return it, u
}

// fleetKey is the key buildFleet used for the entry (the intelligence's own
// spelling of the id or KB).
func fleetKey(e *libEntry) string {
	if e.item.Kind == "os" && len(e.kbs) > 0 {
		return e.kbs[0].KB
	}
	return e.item.ID
}

type libraryPage struct {
	Source      string        `json:"source"`
	GeneratedAt string        `json:"generated_at"`
	Total       int           `json:"total"`
	Page        int           `json:"page"`
	PerPage     int           `json:"per_page"`
	Items       []libraryItem `json:"items"`
}

func (s *Server) library(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	kind, view, sortBy := q.Get("kind"), orDefault(q.Get("view"), "available"), orDefault(q.Get("sort"), "installed")
	switch kind {
	case "", "app", "os":
	default:
		writeErr(w, http.StatusBadRequest, "kind must be app or os")
		return
	}
	switch view {
	case "available", "installed", "catalog", "all":
	default:
		writeErr(w, http.StatusBadRequest, "view must be available, installed, catalog or all")
		return
	}
	switch sortBy {
	case "installed", "name", "date":
	default:
		writeErr(w, http.StatusBadRequest, "sort must be installed, name or date")
		return
	}
	page, perPage := atoiDefault(q.Get("page"), 1), atoiDefault(q.Get("per_page"), libDefaultPerPage)
	if page < 1 || perPage < 1 {
		writeErr(w, http.StatusBadRequest, "page and per_page must be positive")
		return
	}
	perPage = min(perPage, libMaxPerPage)
	words := strings.Fields(strings.ToLower(q.Get("q")))
	if len(words) > 10 {
		words = words[:10]
	}
	publisher := strings.ToLower(strings.TrimSpace(q.Get("publisher")))

	ctx := r.Context()
	li, ov, sum, err := s.libraryState(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	out := libraryPage{Page: page, PerPage: perPage, Items: []libraryItem{}}
	if sum != nil {
		out.Source, out.GeneratedAt = sum.Source, sum.GeneratedAt
	}
	if li == nil {
		writeJSON(w, 200, out)
		return
	}
	type hit struct {
		it   libraryItem
		date string
	}
	var hits []hit
	for i := range li.entries {
		e := &li.entries[i]
		if kind != "" && e.item.Kind != kind {
			continue
		}
		if publisher != "" && e.pub != publisher {
			continue
		}
		if !matchesAll(e.search, words) {
			continue
		}
		it, _ := ov.row(e)
		switch view {
		case "available":
			if it.Importable != intel.ImportableYes && it.Installed.Endpoints == 0 {
				continue
			}
		case "installed":
			if it.Installed.Endpoints == 0 {
				continue
			}
		case "catalog":
			if it.Catalog == nil {
				continue
			}
		}
		hits = append(hits, hit{it, e.date})
	}
	sort.SliceStable(hits, func(i, j int) bool {
		a, b := hits[i], hits[j]
		switch sortBy {
		case "installed":
			if a.it.Installed.Endpoints != b.it.Installed.Endpoints {
				return a.it.Installed.Endpoints > b.it.Installed.Endpoints
			}
		case "date":
			if a.date != b.date {
				return a.date > b.date
			}
		}
		an, bn := strings.ToLower(a.it.Name), strings.ToLower(b.it.Name)
		if an != bn {
			return an < bn
		}
		return a.it.ID < b.it.ID
	})
	out.Total = len(hits)
	from := (page - 1) * perPage
	for i := from; i < len(hits) && i < from+perPage; i++ {
		out.Items = append(out.Items, hits[i].it)
	}
	writeJSON(w, 200, out)
}

type libEndpoint struct {
	EndpointID       string `json:"endpoint_id"`
	Hostname         string `json:"hostname"`
	InstalledVersion string `json:"installed_version"`
	Outdated         bool   `json:"outdated"`
}

func (s *Server) libraryItem(w http.ResponseWriter, r *http.Request) {
	kind, id := r.PathValue("kind"), r.PathValue("id")
	if kind != "app" && kind != "os" {
		writeErr(w, http.StatusNotFound, "kind must be app or os")
		return
	}
	li, ov, _, err := s.libraryState(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	if li == nil {
		writeErr(w, http.StatusNotFound, "no usable update intelligence")
		return
	}
	i, ok := li.byKey[libKey(kind, id)]
	if !ok {
		writeErr(w, http.StatusNotFound, "not in the library")
		return
	}
	it, u := ov.row(&li.entries[i])
	eps := []libEndpoint{}
	if u != nil {
		for _, n := range u.Endpoints {
			eps = append(eps, libEndpoint{EndpointID: n.EndpointID, Hostname: n.Hostname, InstalledVersion: n.Installed, Outdated: true})
		}
		for _, n := range u.current {
			eps = append(eps, libEndpoint{EndpointID: n.EndpointID, Hostname: n.Hostname, InstalledVersion: n.Installed})
		}
		sort.Slice(eps, func(a, b int) bool { return eps[a].Hostname < eps[b].Hostname })
	}
	writeJSON(w, 200, struct {
		libraryItem
		Endpoints []libEndpoint `json:"endpoints"`
	}{it, eps})
}

// libraryState gathers what a Library request needs: the index (nil
// without usable intelligence), the overlay and the intelligence summary.
func (s *Server) libraryState(ctx context.Context) (*libIndex, libOverlay, *intake.IntelSummary, error) {
	li, err := s.libraryIndex(ctx)
	if err != nil {
		return nil, libOverlay{}, nil, err
	}
	sum, snap, err := s.fleetSnap(ctx, nil)
	if err != nil {
		return nil, libOverlay{}, nil, err
	}
	refs, err := s.acqRefs(ctx)
	if err != nil {
		return nil, libOverlay{}, nil, err
	}
	return li, libOverlay{snap: snap, refs: refs}, sum, nil
}

func matchesAll(s string, words []string) bool {
	for _, w := range words {
		if !strings.Contains(s, w) {
			return false
		}
	}
	return true
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return -1
	}
	return n
}

// safeLink returns u when it is an absolute https URL with a host, at most
// maxLinkLen bytes, without whitespace, control characters or credentials;
// otherwise "". The console renders links as plain, copyable text.
func safeLink(u string) string {
	if u == "" || len(u) > maxLinkLen {
		return ""
	}
	for _, r := range u {
		if r <= ' ' || r == 0x7f || r == '"' || r == '<' || r == '>' || r == '\\' || r > unicode.MaxASCII {
			return ""
		}
	}
	p, err := url.Parse(u)
	if err != nil || p.Scheme != "https" || p.Host == "" || p.User != nil || p.Opaque != "" {
		return ""
	}
	return u
}

// cleanLibText bounds community text and drops control characters.
func cleanLibText(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t' || r == '\r':
			return ' '
		case unicode.IsControl(r) || r == unicode.ReplacementChar || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069):
			return -1 // incl. bidi overrides
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > max {
		cut := max
		for cut > 0 && !utf8RuneStart(s[cut]) {
			cut--
		}
		s = strings.TrimSpace(s[:cut]) + "…"
	}
	return s
}

func utf8RuneStart(b byte) bool { return b&0xC0 != 0x80 }

var tokenRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`)

func cleanToken(s string) string {
	if tokenRe.MatchString(s) {
		return strings.ToLower(s)
	}
	return ""
}

var (
	hex64Re = regexp.MustCompile(`^[0-9A-Fa-f]{64}$`)
	guidRe  = regexp.MustCompile(`^\{[0-9A-Fa-f-]{36}\}$`)
	// winget PackageIdentifier segments (conservative).
	wingetSegRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+_-]*$`)
)

func cleanHex(s string) string {
	if hex64Re.MatchString(s) {
		return strings.ToLower(s)
	}
	return ""
}

func cleanProductCode(s string) string {
	if guidRe.MatchString(s) {
		return s
	}
	return ""
}

// wingetManifestURL is the winget-pkgs folder of an app version:
// manifests/<first letter, lower case>/<Publisher>/<Name…>/<version>.
func wingetManifestURL(id, version string) string {
	segs := strings.Split(id, ".")
	if len(segs) < 2 || version == "" || strings.ContainsAny(version, "/\\") || version == "." || version == ".." {
		return ""
	}
	for _, s := range segs {
		if !wingetSegRe.MatchString(s) {
			return ""
		}
	}
	p := "https://github.com/microsoft/winget-pkgs/tree/master/manifests/" + strings.ToLower(segs[0][:1])
	for _, s := range segs {
		p += "/" + url.PathEscape(s)
	}
	return safeLink(p + "/" + url.PathEscape(version))
}

// libraryArchFor is the architecture recorded for an app imported from
// the Library that no endpoint has installed (app_archs; default x64).
func libraryArchFor(archs map[string]string, id string) (string, error) {
	for k, v := range archs {
		if strings.EqualFold(k, id) {
			a := strings.ToLower(strings.TrimSpace(v))
			switch a {
			case "x64", "x86", "arm64":
				return a, nil
			}
			return "", fmt.Errorf("app_archs[%q] must be x64, x86 or arm64", id)
		}
	}
	return "x64", nil
}

// entry finds a Library entry by kind and id (case-insensitive); nil when
// li is nil or it is not there.
func (li *libIndex) entry(kind, id string) *libEntry {
	if li == nil {
		return nil
	}
	if i, ok := li.byKey[libKey(kind, id)]; ok {
		return &li.entries[i]
	}
	return nil
}
