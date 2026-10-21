package acqpolicy

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// KnownWindows is one Windows release the downloader knows how to find in
// the Microsoft Update Catalog (kept in step with
// acquire.DefaultWindowsProducts; a pmctl test checks it).
type KnownWindows struct {
	Product string `json:"product"`
	Build   int    `json:"build"`
	Arch    string `json:"arch"`
	Server  bool   `json:"server,omitempty"`
	// CatalogProduct: the text catalog titles use for it.
	CatalogProduct string `json:"catalog_product"`
}

// Known lists the Windows releases offered in the console.
var Known = []KnownWindows{
	{Product: "Windows 10 Version 22H2", Build: 19045, Arch: "x64", CatalogProduct: "Windows 10 Version 22H2"},
	{Product: "Windows 11 Version 21H2", Build: 22000, Arch: "x64", CatalogProduct: "Windows 11"},
	{Product: "Windows 11 Version 22H2", Build: 22621, Arch: "x64", CatalogProduct: "Windows 11 Version 22H2"},
	{Product: "Windows 11 Version 23H2", Build: 22631, Arch: "x64", CatalogProduct: "Windows 11 Version 23H2"},
	{Product: "Windows 11 Version 24H2", Build: 26100, Arch: "x64", CatalogProduct: "Windows 11 Version 24H2"},
	{Product: "Windows 11 Version 25H2", Build: 26200, Arch: "x64", CatalogProduct: "Windows 11 Version 25H2"},
	{Product: "Windows 11 Version 26H2", Build: 26300, Arch: "x64", CatalogProduct: "Windows 11 Version 26H2"},
	{Product: "Windows Server 2019", Build: 17763, Arch: "x64", Server: true, CatalogProduct: "Windows Server 2019"},
	{Product: "Windows Server 2022", Build: 20348, Arch: "x64", Server: true, CatalogProduct: "Microsoft server operating system version 21H2"},
	{Product: "Windows Server 2025", Build: 26100, Arch: "x64", Server: true, CatalogProduct: "Microsoft server operating system version 24H2"},
}

// LookupKnown finds a known release by product, build and arch.
func LookupKnown(product string, build int, arch string) (KnownWindows, bool) {
	for _, k := range Known {
		if strings.EqualFold(k.Product, product) && k.Build == build && k.Arch == arch {
			return k, true
		}
	}
	return KnownWindows{}, false
}

// IsServer reports whether a Windows product name is a server release.
func IsServer(product string) bool { return strings.Contains(strings.ToLower(product), "server") }

// sharedKBBuilds are Windows builds that get the same KB numbers as an older
// build of the same family (25H2 with 24H2, 23H2 with 22H2, 21H2 with 22H2
// on Windows 10). Their packages get the build in the ID so both can be in
// the catalog; the older build keeps the plain ID existing catalogs use.
var sharedKBBuilds = map[int]bool{26200: true, 22631: true, 19044: true}

// SharedKBBase is the older build whose cumulative update a shared-KB
// build installs too (26200 → 26100), or 0.
func SharedKBBase(build int) int {
	switch build {
	case 26200:
		return 26100
	case 22631:
		return 22621
	case 19044:
		return 19045
	}
	return 0
}

// KBPackageSuffix is what follows "<KB>-<arch>" in the package ID of a
// Windows update for product at build: "-server" for Windows Server (it
// shares KB numbers with the client release of the same build), "-<build>"
// for a build that shares KB numbers with an older one, else "".
func KBPackageSuffix(product string, server bool, build int) string {
	if server || IsServer(product) {
		return "-server"
	}
	if sharedKBBuilds[build] {
		return "-" + strconv.Itoa(build)
	}
	return ""
}

// Empty is a policy with nothing in it (acquire.json alone applies).
func Empty() Policy {
	return Policy{Windows: []Windows{}, Apps: []App{}, Sources: []Source{}}
}

// Base is what acquire.json configures, as policy entries, plus the names
// of its custom vendor feeds (not expressible as policy entries; they keep
// running from acquire.json).
type Base struct {
	Policy Policy   `json:"policy"`
	Feeds  []string `json:"feeds"`
}

// acquireJSON is the part of pmctl's acquire.json the policy mirrors
// (read leniently: unknown fields are pmctl's business).
type acquireJSON struct {
	Microsoft *struct {
		MinSeverity string `json:"min_severity"`
		Products    []struct {
			MSRCProduct    string `json:"msrc_product"`
			CatalogProduct string `json:"catalog_product"`
			Arch           string `json:"arch"`
			MinBuild       int    `json:"min_build"`
			MaxBuild       int    `json:"max_build"`
		} `json:"products"`
	} `json:"microsoft"`
	Intel *struct {
		WingetURL string `json:"winget_url"`
	} `json:"intel"`
	CatalogURL         string `json:"catalog_url"`
	MSRCURL            string `json:"msrc_url"`
	WingetManifestsURL string `json:"winget_manifests_url"`
	Apps               []struct {
		Name  string `json:"name"`
		Title string `json:"title"`
	} `json:"apps"`
}

// FromAcquireJSON derives the default policy from acquire.json: its
// Microsoft products as Windows entries, its endpoint overrides as sources
// (the built-in winget / catalog / MSRC sources are always listed). Entries
// that cannot be expressed (a build range) are skipped with a note in Feeds.
func FromAcquireJSON(b []byte) (Base, error) {
	var c acquireJSON
	if err := json.Unmarshal(b, &c); err != nil {
		return Base{}, fmt.Errorf("acquire.json: %w", err)
	}
	out := Base{Policy: Empty(), Feeds: []string{}}
	if m := c.Microsoft; m != nil {
		class := ClassSecurity
		if strings.EqualFold(m.MinSeverity, "low") {
			class = ClassAll
		}
		seen := map[string]bool{}
		for _, p := range m.Products {
			arch := strings.ToLower(p.Arch)
			builds := []int{}
			switch {
			case p.MinBuild > 0 && p.MinBuild == p.MaxBuild:
				builds = append(builds, p.MinBuild)
			default:
				for _, k := range Known {
					if strings.EqualFold(k.Product, p.MSRCProduct) && k.Arch == arch &&
						(p.MinBuild == 0 || k.Build >= p.MinBuild) && (p.MaxBuild == 0 || k.Build <= p.MaxBuild) {
						builds = append(builds, k.Build)
					}
				}
			}
			if len(builds) == 0 {
				out.Feeds = append(out.Feeds, fmt.Sprintf("Microsoft: %s %s (build range %d-%d, kept from acquire.json)", p.MSRCProduct, p.Arch, p.MinBuild, p.MaxBuild))
				continue
			}
			for _, bd := range builds {
				w := Windows{Product: strings.Join(strings.Fields(p.MSRCProduct), " "), Build: bd, Arch: arch, Classification: class, Enabled: true}
				k := strings.ToLower(w.Product) + "/" + fmt.Sprint(bd) + "/" + arch
				if seen[k] {
					continue
				}
				seen[k] = true
				out.Policy.Windows = append(out.Policy.Windows, w)
			}
		}
	}
	add := func(s Source) {
		s.Enabled, s.AddedBy, s.Note = true, "installer (acquire.json)", "from acquire.json"
		out.Policy.Sources = append(out.Policy.Sources, s)
	}
	winget := Source{ID: "winget", Type: SourceWinget}
	if c.Intel != nil && CheckURL(c.Intel.WingetURL) == nil {
		winget.URL = c.Intel.WingetURL
	}
	if CheckURL(c.WingetManifestsURL) == nil {
		winget.ManifestsURL = c.WingetManifestsURL
	}
	add(winget)
	cat := Source{ID: "microsoft-catalog", Type: SourceCatalog}
	if CheckURL(c.CatalogURL) == nil {
		cat.URL = c.CatalogURL
	}
	add(cat)
	ms := Source{ID: "msrc", Type: SourceMSRC}
	if CheckURL(c.MSRCURL) == nil {
		ms.URL = c.MSRCURL
	}
	add(ms)
	for _, a := range c.Apps {
		name := a.Name
		if a.Title != "" {
			name += " (" + a.Title + ")"
		}
		out.Feeds = append(out.Feeds, "App feed: "+name)
	}
	if err := out.Policy.Normalize(); err != nil {
		return Base{}, fmt.Errorf("acquire.json: %w", err)
	}
	return out, nil
}

// Diff summarises what changed from a to b in plain words.
func Diff(a, b Policy) []string {
	out := []string{}
	type entry struct {
		label string
		val   string
	}
	diff := func(kind string, old, cur map[string]entry, order []string) {
		if kind != "" {
			kind += " "
		}
		for _, k := range order {
			o, had := old[k]
			n := cur[k]
			switch {
			case !had:
				out = append(out, "added "+kind+n.label)
			case o.val != n.val:
				out = append(out, "changed "+kind+n.label)
			}
		}
		var gone []string
		for k, o := range old {
			if _, ok := cur[k]; !ok {
				gone = append(gone, "removed "+kind+o.label)
			}
		}
		sort.Strings(gone)
		out = append(out, gone...)
	}
	mk := func(enabled bool) string {
		if enabled {
			return ""
		}
		return " (off)"
	}
	js := func(v any) string { b, _ := json.Marshal(v); return string(b) }

	wOld, wCur, wOrd := map[string]entry{}, map[string]entry{}, []string{}
	for _, w := range a.Windows {
		wOld[strings.ToLower(w.Product)+"/"+fmt.Sprint(w.Build)+"/"+w.Arch] = entry{fmt.Sprintf("%s %d %s", w.Product, w.Build, w.Arch), js(w)}
	}
	for _, w := range b.Windows {
		k := strings.ToLower(w.Product) + "/" + fmt.Sprint(w.Build) + "/" + w.Arch
		wCur[k] = entry{fmt.Sprintf("%s %d %s%s", w.Product, w.Build, w.Arch, mk(w.Enabled)), js(w)}
		wOrd = append(wOrd, k)
	}
	diff("", wOld, wCur, wOrd) // the label names Windows already

	aOld, aCur, aOrd := map[string]entry{}, map[string]entry{}, []string{}
	for _, x := range a.Apps {
		aOld[strings.ToLower(x.ID)] = entry{x.ID, js(x)}
	}
	for _, x := range b.Apps {
		k := strings.ToLower(x.ID)
		aCur[k] = entry{x.ID + mk(x.Enabled), js(x)}
		aOrd = append(aOrd, k)
	}
	diff("app", aOld, aCur, aOrd)

	sOld, sCur, sOrd := map[string]entry{}, map[string]entry{}, []string{}
	for _, x := range a.Sources {
		sOld[x.ID] = entry{x.ID + " (" + x.Type + ")", js(x)}
	}
	for _, x := range b.Sources {
		sCur[x.ID] = entry{x.ID + " (" + x.Type + ")" + mk(x.Enabled), js(x)}
		sOrd = append(sOrd, x.ID)
	}
	diff("source", sOld, sCur, sOrd)

	if a.Limits.MaxDownloadGBPerRun != b.Limits.MaxDownloadGBPerRun {
		out = append(out, fmt.Sprintf("download limit per run %s → %s", gb(a.Limits.MaxDownloadGBPerRun), gb(b.Limits.MaxDownloadGBPerRun)))
	}
	if a.Limits.KeepLastNVersions != b.Limits.KeepLastNVersions {
		out = append(out, fmt.Sprintf("keep last versions %s → %s", keep(a.Limits.KeepLastNVersions), keep(b.Limits.KeepLastNVersions)))
	}
	return out
}

func gb(n int) string {
	if n == 0 {
		return "no limit"
	}
	return fmt.Sprintf("%d GB", n)
}

func keep(n int) string {
	if n == 0 {
		return "by age"
	}
	return fmt.Sprint(n)
}
