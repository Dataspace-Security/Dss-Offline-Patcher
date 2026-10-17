package intel

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Item is one installed thing reported by an endpoint (store.InventoryItem).
type Item struct {
	Kind    string // kb | product | app | pkg | agent
	ID      string // KB number, MSI product code or uninstall-registry key name
	Name    string // display name
	Version string // display version
}

// Endpoint is what the matcher needs to know about one machine.
type Endpoint struct {
	OS        string // windows | linux | macos
	OSVersion string // e.g. "Windows 11 Pro 21H2 (22000.2538)"
	Build     int
	Arch      string // x64 | arm64 | x86
	Inventory []Item
}

// OSUpdate is a newer Windows cumulative update for the endpoint.
type OSUpdate struct {
	WindowsRelease
	InstalledUBR int `json:"installed_ubr"`
	// Basis: build_revision when both revisions are known (reliable), else
	// kb_inventory (the KB is not in the endpoint's installed-updates list).
	Basis string `json:"basis"`
}

// AppUpdate is an installed application with a newer version available.
type AppUpdate struct {
	AppID            string `json:"app_id"`
	Name             string `json:"name"`
	InstalledName    string `json:"installed_name"`
	InstalledVersion string `json:"installed_version"`
	LatestVersion    string `json:"latest_version"`
	MatchedBy        string `json:"matched_by"` // product_code | name
	ProductCode      string `json:"product_code,omitempty"`
}

// Result is everything the endpoint is missing according to the intelligence.
type Result struct {
	OS []OSUpdate `json:"os"`
	// Apps with a newer version; Current counts matched apps that are up to date.
	Apps      []AppUpdate `json:"apps"`
	Current   int         `json:"current"`
	Unmatched int         `json:"unmatched"` // installed apps not found in the index
}

// Index is a Doc prepared for matching. It is read-only after NewIndex.
type Index struct {
	Doc       Doc
	byCode    map[string][]int
	byName    map[string][]int
	normNames [][]string // per app, Normalize(Names[i]) computed once
	windows   map[int][]WindowsRelease
	memo      sync.Map // Item ID+name -> lookupResult
}

type memoKey struct{ id, name string }

type lookupResult struct {
	i  int
	by string
}

func NewIndex(d Doc) *Index {
	ix := &Index{Doc: d, byCode: map[string][]int{}, byName: map[string][]int{}, windows: map[int][]WindowsRelease{},
		normNames: make([][]string, len(d.Apps))}
	for i, a := range d.Apps {
		for _, c := range a.Codes {
			ix.byCode[strings.ToLower(c)] = append(ix.byCode[strings.ToLower(c)], i)
		}
		seen := map[string]bool{}
		for _, n := range a.Names {
			k := Normalize(n)
			if k != "" && !seen[k] {
				seen[k] = true
				ix.byName[k] = append(ix.byName[k], i)
				ix.normNames[i] = append(ix.normNames[i], k)
			}
		}
	}
	for _, w := range d.Windows {
		ix.windows[w.Build] = append(ix.windows[w.Build], w)
	}
	return ix
}

var ubrRe = regexp.MustCompile(`\((\d{4,6})\.(\d+)\)`)

// Match lists what ep is missing. Only Windows endpoints are matched: the
// app index (winget) and the cumulative updates are Windows-specific.
func (ix *Index) Match(ep Endpoint) Result {
	res := Result{OS: []OSUpdate{}, Apps: []AppUpdate{}}
	if ix == nil || ep.OS != "windows" {
		return res
	}
	kbs := map[string]bool{}
	for _, it := range ep.Inventory {
		if it.Kind == "kb" {
			kbs[strings.ToUpper(it.ID)] = true
		}
	}
	ubr := 0
	if m := ubrRe.FindStringSubmatch(ep.OSVersion); m != nil {
		ubr, _ = strconv.Atoi(m[2])
	}
	server := strings.Contains(strings.ToLower(ep.OSVersion), "server")
	for _, w := range ix.windows[ep.Build] {
		if w.Server != server || !strings.EqualFold(w.Arch, ep.Arch) || kbs[strings.ToUpper(w.KB)] {
			continue
		}
		basis := "kb_inventory"
		if w.UBR > 0 && ubr > 0 {
			if ubr >= w.UBR {
				continue // already at or past that revision (a later update is installed)
			}
			basis = "build_revision"
		}
		res.OS = append(res.OS, OSUpdate{WindowsRelease: w, InstalledUBR: ubr, Basis: basis})
	}

	seenApp := map[string]bool{}
	for _, it := range ep.Inventory {
		if it.Kind != "product" || it.Name == "" {
			continue
		}
		i, by := ix.lookup(it)
		if i < 0 {
			res.Unmatched++
			continue
		}
		a := ix.Doc.Apps[i]
		if seenApp[a.ID+"\x00"+it.ID] {
			continue
		}
		seenApp[a.ID+"\x00"+it.ID] = true
		target := a.Version
		if a.ARPMax != "" {
			target = a.ARPMax
		}
		if it.Version == "" || CompareVersions(it.Version, target) >= 0 {
			res.Current++
			continue
		}
		u := AppUpdate{AppID: a.ID, Name: a.Name, InstalledName: it.Name, InstalledVersion: it.Version, LatestVersion: a.Version, MatchedBy: by}
		if strings.HasPrefix(it.ID, "{") {
			u.ProductCode = it.ID
		}
		res.Apps = append(res.Apps, u)
	}
	sort.Slice(res.Apps, func(i, j int) bool { return strings.ToLower(res.Apps[i].Name) < strings.ToLower(res.Apps[j].Name) })
	return res
}

// lookup finds the app for an installed item: by product code / registry
// key name first (exact), then by normalised display name. Ambiguous
// matches are not guessed. Results are memoised (the fleet view looks up the
// same programs on every endpoint).
func (ix *Index) lookup(it Item) (int, string) {
	key := memoKey{it.ID, it.Name}
	if v, ok := ix.memo.Load(key); ok {
		r := v.(lookupResult)
		return r.i, r.by
	}
	i, by := ix.lookupSlow(it)
	ix.memo.Store(key, lookupResult{i, by})
	return i, by
}

func (ix *Index) lookupSlow(it Item) (int, string) {
	norm := Normalize(it.Name)
	if c := ix.byCode[strings.ToLower(it.ID)]; len(c) > 0 {
		if len(c) == 1 {
			return c[0], "product_code"
		}
		for _, i := range c { // several packages claim this code: the name decides
			for _, n := range ix.normNames[i] {
				if n == norm {
					return i, "product_code"
				}
			}
		}
		return -1, ""
	}
	if norm != "" {
		if i := ix.sameAppByName(ix.byName[norm]); i >= 0 {
			return i, "name"
		}
	}
	return -1, ""
}

// variantSuffixes mark pre-release or alternative packagings of an app
// (Google.Chrome.Beta, Mozilla.Firefox.MSIX, VideoLAN.VLC.Nightly…).
var variantSuffixes = map[string]bool{"beta": true, "dev": true, "canary": true, "nightly": true, "preview": true, "insiders": true,
	"insider": true, "alpha": true, "rc": true, "ptb": true, "msix": true, "portable": true, "esr": true}

// isVariant reports whether a winget id names a pre-release or alternative
// packaging: any segment after the publisher (Google.Chrome.Beta.EXE).
func isVariant(id string) bool {
	segs := strings.Split(id, ".")
	for _, s := range segs[1:] {
		if variantSuffixes[strings.ToLower(s)] {
			return true
		}
	}
	return false
}

// sameAppByName resolves a display-name match. One candidate is used as is.
// Several candidates (e.g. Google.Chrome and Google.Chrome.EXE, or
// Firefox's per-language packages) count as one app only when, ignoring
// pre-release/alternative packagings, they all agree on the latest version;
// otherwise the match is ambiguous and not guessed.
func (ix *Index) sameAppByName(cands []int) int {
	if len(cands) == 1 {
		return cands[0]
	}
	best, version := -1, ""
	for _, i := range cands {
		a := ix.Doc.Apps[i]
		if isVariant(a.ID) {
			continue
		}
		switch {
		case best < 0:
			best, version = i, a.Version
		case a.Version != version:
			return -1
		case len(a.ID) < len(ix.Doc.Apps[best].ID):
			best = i // prefer the base package id (Google.Chrome over Google.Chrome.EXE)
		}
	}
	return best
}

var (
	parenRe   = regexp.MustCompile(`\([^)]*\)`)
	versionRe = regexp.MustCompile(`\bv?\d+(\.\d+)+\b`)
	archRe    = regexp.MustCompile(`\b(x64|x86|amd64|arm64|64-bit|32-bit|64 bit|32 bit|win64|win32)\b`)
	nonAlnum  = regexp.MustCompile(`[^\p{L}\p{N}]+`) // keep letters of every script
)

// Normalize reduces a display name to letters and digits without versions,
// architecture or parenthetical qualifiers, in the spirit of winget's
// normalised names: "Mozilla Firefox (x64 en-US)" → "mozillafirefox",
// "7-Zip 24.08 (x64)" → "7zip". winget's own "(X64)" suffixes are dropped too.
func Normalize(s string) string {
	s = strings.ToLower(s)
	s = parenRe.ReplaceAllString(s, " ")
	s = versionRe.ReplaceAllString(s, " ")
	s = archRe.ReplaceAllString(s, " ")
	return nonAlnum.ReplaceAllString(s, "")
}

// CompareVersions compares dotted versions numerically segment by segment
// ("10.0.2" < "10.0.10"); non-numeric parts compare as text. -1, 0 or 1.
func CompareVersions(a, b string) int {
	as, bs := splitVersion(a), splitVersion(b)
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y string
		if i < len(as) {
			x = as[i]
		}
		if i < len(bs) {
			y = bs[i]
		}
		xn, xerr := strconv.Atoi(x)
		yn, yerr := strconv.Atoi(y)
		switch {
		case x == y:
			continue
		case xerr == nil && yerr == nil:
			if xn < yn {
				return -1
			}
			if xn > yn {
				return 1
			}
		case x == "":
			if yn == 0 && yerr == nil {
				continue // 1.2 == 1.2.0
			}
			return -1
		case y == "":
			if xn == 0 && xerr == nil {
				continue
			}
			return 1
		default:
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func splitVersion(v string) []string {
	return strings.FieldsFunc(strings.TrimSpace(v), func(r rune) bool { return r == '.' || r == '-' || r == '_' || r == '+' || r == ' ' })
}
