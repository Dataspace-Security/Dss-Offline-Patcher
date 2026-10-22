package acquire

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"offpatch/internal/manifest"
)

// winget manifests: resolve a requested package id + version to a concrete
// installer (URL and the manifest's InstallerSha256) from the community
// repository's per-version YAML (github.com/microsoft/winget-pkgs).

// DefaultWingetManifestsURL is the raw manifests tree of the community repository.
const DefaultWingetManifestsURL = "https://raw.githubusercontent.com/microsoft/winget-pkgs/master/manifests"

const maxWingetManifest = 1 << 20

// ErrWingetNotFound: the repository has no manifest for this id/version.
var ErrWingetNotFound = errors.New("no winget manifest for this package version")

// UnsupportedError means the package cannot be packaged by offpatch (no
// MSI installer for the architecture, no product code, ...). It is reported
// as a warning, not retried.
type UnsupportedError struct{ Reason string }

func (e *UnsupportedError) Error() string { return e.Reason }

func unsupported(f string, a ...any) error { return &UnsupportedError{Reason: fmt.Sprintf(f, a...)} }

// WingetARPEntry is one AppsAndFeaturesEntries item.
type WingetARPEntry struct {
	DisplayName    string
	DisplayVersion string
	Publisher      string
	ProductCode    string
	UpgradeCode    string
}

// WingetInstaller is one Installers item, with root-level defaults applied.
type WingetInstaller struct {
	Architecture        string
	InstallerType       string // msi | wix | exe | inno | nullsoft | burn | msix | zip | ...
	NestedInstallerType string // InstallerType zip: msi | wix | exe | inno | nullsoft | burn | portable | ...
	Scope               string // machine | user | ""
	Locale              string
	URL                 string
	SHA256              string // lower-case hex
	ProductCode         string
	ReleaseDate         string
	ARP                 []WingetARPEntry
	// NestedInstallerFiles: the RelativeFilePath of each file named in the
	// zip, as the manifest writes it; NestedAliases their
	// PortableCommandAlias ("" when none), index for index.
	NestedInstallerFiles []string
	NestedAliases        []string
	// Commands: the manifest's Commands (portable apps: the command names).
	Commands []string
	// PackageFamilyName: MSIX/APPX installers (Name_PublisherId).
	PackageFamilyName string
	// ZipPath: set by the pickers (zipped) when the installer offpatch
	// takes is inside the zip at URL: its RelativeFilePath with forward
	// slashes (for a portable app, the first file the manifest names).
	// InstallerType is then the nested type; URL and SHA256 are the zip's.
	ZipPath string
	// ZipAlias: the PortableCommandAlias of ZipPath ("" when none).
	ZipAlias string
	// EXE installers (winget_exe.go): switches, extra success codes,
	// ExpectedReturnCodes and the OS architectures the entry is not for.
	Switches        WingetSwitches
	SuccessCodes    []int
	ReturnCodes     []WingetReturnCode
	UnsupportedArch []string
}

// WingetManifest is the installer manifest of one package version.
type WingetManifest struct {
	ID          string
	Version     string
	PackageName string // singleton manifests only
	Publisher   string // singleton manifests only
	Installers  []WingetInstaller
}

// WingetManifestURLs returns the per-version manifest URLs to try: the
// multi-file installer manifest, then the older singleton form.
func WingetManifestURLs(base, id, version string) []string {
	if base == "" {
		base = DefaultWingetManifestsURL
	}
	base = strings.TrimRight(base, "/")
	segs := []string{url.PathEscape(strings.ToLower(id[:1]))}
	for _, s := range strings.Split(id, ".") {
		segs = append(segs, url.PathEscape(s))
	}
	dir := base + "/" + strings.Join(segs, "/") + "/" + url.PathEscape(version) + "/"
	return []string{dir + url.PathEscape(id) + ".installer.yaml", dir + url.PathEscape(id) + ".yaml"}
}

// FetchWingetManifest downloads and parses the installer manifest for
// id@version over HTTPS. It returns ErrWingetNotFound if neither form exists.
func FetchWingetManifest(ctx context.Context, hc *http.Client, base, id, version string) (*WingetManifest, string, error) {
	if id == "" || version == "" {
		return nil, "", errors.New("winget id and version are required")
	}
	if hc == nil {
		hc = DefaultHTTPClient()
	}
	for _, u := range WingetManifestURLs(base, id, version) {
		if !strings.HasPrefix(u, "https://") {
			return nil, "", fmt.Errorf("winget manifests URL must be https: %s", u)
		}
		body, err := getManifest(ctx, hc, u)
		if errors.Is(err, ErrWingetNotFound) {
			continue
		}
		if err != nil {
			return nil, u, err
		}
		m, err := ParseWingetManifest(body)
		if err != nil {
			return nil, u, fmt.Errorf("winget manifest %s not understood (kept for retry; report it): %w", u, err)
		}
		if !strings.EqualFold(m.ID, id) || m.Version != version {
			return nil, u, fmt.Errorf("winget manifest %s is for %s %s, not %s %s", u, m.ID, m.Version, id, version)
		}
		return m, u, nil
	}
	return nil, "", ErrWingetNotFound
}

func getManifest(ctx context.Context, hc *http.Client, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", DefaultUserAgent)
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrWingetNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", u, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxWingetManifest+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxWingetManifest {
		return nil, fmt.Errorf("GET %s: manifest larger than %d bytes", u, maxWingetManifest)
	}
	return b, nil
}

// ParseWingetManifest reads an installer (or singleton) manifest.
func ParseWingetManifest(b []byte) (*WingetManifest, error) {
	v, err := parseYAMLMini(b)
	if err != nil {
		return nil, err
	}
	root, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("manifest is not a mapping")
	}
	switch t := str(root, "ManifestType"); t {
	case "installer", "singleton", "":
	default:
		return nil, fmt.Errorf("ManifestType %q is not an installer manifest", t)
	}
	m := &WingetManifest{ID: str(root, "PackageIdentifier"), Version: str(root, "PackageVersion"),
		PackageName: str(root, "PackageName"), Publisher: str(root, "Publisher")}
	if m.ID == "" || m.Version == "" {
		return nil, errors.New("PackageIdentifier and PackageVersion are required")
	}
	def := WingetInstaller{InstallerType: str(root, "InstallerType"), NestedInstallerType: str(root, "NestedInstallerType"),
		Scope: str(root, "Scope"), Locale: str(root, "InstallerLocale"), ProductCode: str(root, "ProductCode"),
		ReleaseDate: str(root, "ReleaseDate"), ARP: arpEntries(root), NestedInstallerFiles: nestedFiles(root, "RelativeFilePath"),
		NestedAliases: nestedFiles(root, "PortableCommandAlias"), Commands: strList(root, "Commands"), PackageFamilyName: str(root, "PackageFamilyName")}
	var err2 error
	if def.Switches, def.SuccessCodes, def.ReturnCodes, def.UnsupportedArch, err2 = exeFields(root); err2 != nil {
		return nil, err2
	}
	list, _ := root["Installers"].([]any)
	if len(list) == 0 {
		return nil, errors.New("manifest lists no installers")
	}
	for _, it := range list {
		im, ok := it.(map[string]any)
		if !ok {
			return nil, errors.New("Installers entry is not a mapping")
		}
		in := def
		in.Architecture = strings.ToLower(str(im, "Architecture"))
		in.URL = str(im, "InstallerUrl")
		in.SHA256 = strings.ToLower(str(im, "InstallerSha256"))
		for f, dst := range map[string]*string{"InstallerType": &in.InstallerType, "NestedInstallerType": &in.NestedInstallerType,
			"Scope": &in.Scope, "InstallerLocale": &in.Locale, "ProductCode": &in.ProductCode, "ReleaseDate": &in.ReleaseDate,
			"PackageFamilyName": &in.PackageFamilyName} {
			if s := str(im, f); s != "" {
				*dst = s
			}
		}
		if a := arpEntries(im); len(a) > 0 {
			in.ARP = a
		}
		if nf := nestedFiles(im, "RelativeFilePath"); nf != nil {
			in.NestedInstallerFiles, in.NestedAliases = nf, nestedFiles(im, "PortableCommandAlias")
		}
		if c := strList(im, "Commands"); c != nil {
			in.Commands = c
		}
		sw, succ, codes, unsup, err := exeFields(im)
		if err != nil {
			return nil, err
		}
		for _, f := range []struct {
			dst *string
			v   string
		}{{&in.Switches.Silent, sw.Silent}, {&in.Switches.SilentWithProgress, sw.SilentWithProgress}, {&in.Switches.Custom, sw.Custom}} {
			if f.v != "" {
				*f.dst = f.v
			}
		}
		if succ != nil {
			in.SuccessCodes = succ
		}
		if codes != nil {
			in.ReturnCodes = codes
		}
		if unsup != nil {
			in.UnsupportedArch = unsup
		}
		in.InstallerType = strings.ToLower(in.InstallerType)
		in.NestedInstallerType = strings.ToLower(in.NestedInstallerType)
		in.Scope = strings.ToLower(in.Scope)
		m.Installers = append(m.Installers, in)
	}
	applyKnownSwitches(m)
	return m, nil
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return strings.TrimSpace(s)
}

// nestedFiles reads one field of every NestedInstallerFiles entry that has
// a RelativeFilePath (nil when the key is absent): field RelativeFilePath
// gives the files, PortableCommandAlias their aliases ("" when none).
func nestedFiles(m map[string]any, field string) []string {
	list, ok := m["NestedInstallerFiles"].([]any)
	if !ok {
		return nil
	}
	out := []string{}
	for _, it := range list {
		if e, ok := it.(map[string]any); ok {
			if p := str(e, "RelativeFilePath"); p != "" {
				out = append(out, str(e, field))
			}
		}
	}
	return out
}

// strList reads a list of strings (nil when the key is absent).
func strList(m map[string]any, k string) []string {
	list, ok := m[k].([]any)
	if !ok {
		return nil
	}
	out := []string{}
	for _, v := range list {
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}

func arpEntries(m map[string]any) []WingetARPEntry {
	list, _ := m["AppsAndFeaturesEntries"].([]any)
	var out []WingetARPEntry
	for _, it := range list {
		e, ok := it.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, WingetARPEntry{DisplayName: str(e, "DisplayName"), DisplayVersion: str(e, "DisplayVersion"),
			Publisher: str(e, "Publisher"), ProductCode: str(e, "ProductCode"), UpgradeCode: str(e, "UpgradeCode")})
	}
	return out
}

// msiTypes are installer types offpatch can deploy (as kind msi).
var msiTypes = map[string]bool{"msi": true, "wix": true}

// PickMSI chooses the MSI installer for arch: machine scope over user
// scope, a neutral or en-US locale over others. It returns an
// UnsupportedError if the manifest has no usable MSI for arch.
func (m *WingetManifest) PickMSI(arch string) (WingetInstaller, error) {
	var cands []WingetInstaller
	var other []string
	for _, in := range m.zipped() {
		if in.Architecture != arch && !(in.Architecture == "neutral" && arch != "arm64") {
			continue
		}
		if !msiTypes[in.InstallerType] {
			t := in.InstallerType
			if in.NestedInstallerType != "" {
				t += "/" + in.NestedInstallerType
			}
			other = append(other, t)
			continue
		}
		cands = append(cands, in)
	}
	if len(cands) == 0 && arch == "x64" {
		// 32-bit-only MSIs (common) install on x64 Windows; the caller says so.
		for _, in := range m.zipped() {
			if in.Architecture == "x86" && msiTypes[in.InstallerType] {
				cands = append(cands, in)
			}
		}
	}
	if len(cands) == 0 {
		if len(other) > 0 {
			sort.Strings(other)
			return WingetInstaller{}, unsupported("%s %s has no MSI installer for %s (only %s)",
				m.ID, m.Version, arch, strings.Join(dedupe(other), ", "))
		}
		return WingetInstaller{}, unsupported("%s %s has no installer for %s", m.ID, m.Version, arch)
	}
	rank := func(in WingetInstaller) int {
		r := 0
		if in.Scope == "user" {
			r += 4
		}
		switch strings.ToLower(in.Locale) {
		case "", "en-us":
		case "en-gb", "en":
			r++
		default:
			r += 2
		}
		if in.Architecture == "neutral" {
			r++
		}
		if in.ZipPath != "" {
			r += 8 // a plain MSI over one in a zip
		}
		return r
	}
	sort.SliceStable(cands, func(i, j int) bool { return rank(cands[i]) < rank(cands[j]) })
	in := cands[0]
	if u, err := url.Parse(in.URL); err != nil || u.Scheme != "https" || u.Host == "" {
		return WingetInstaller{}, unsupported("%s %s: installer URL %q is not https", m.ID, m.Version, in.URL)
	}
	if !hex64Re.MatchString(in.SHA256) {
		return WingetInstaller{}, unsupported("%s %s: manifest has no valid InstallerSha256", m.ID, m.Version)
	}
	return in, nil
}

// zipped returns the installers with each zip that names one MSI or EXE
// installer (NestedInstallerType msi, wix, exe, inno, nullsoft or burn,
// exactly one NestedInstallerFiles entry) turned into that installer:
// InstallerType the nested type, ZipPath the file in the zip. A zip of a
// portable app (NestedInstallerType portable, one or more files) becomes
// InstallerType "portable" with ZipPath its first file. Other zips are
// returned as they are ("zip", with NestedInstallerType kept), so the
// pickers report them by type.
func (m *WingetManifest) zipped() []WingetInstaller {
	out := make([]WingetInstaller, 0, len(m.Installers))
	for _, in := range m.Installers {
		nt := in.NestedInstallerType
		one := len(in.NestedInstallerFiles) == 1
		if in.InstallerType == "zip" && ((msiTypes[nt] || manifest.IsExeInstallerType(nt)) && one || nt == "portable" && len(in.NestedInstallerFiles) > 0) {
			if p, err := CleanZipPath(in.NestedInstallerFiles[0]); err == nil {
				in.InstallerType, in.ZipPath = nt, p
				if len(in.NestedAliases) > 0 {
					in.ZipAlias = in.NestedAliases[0]
				}
			}
		}
		out = append(out, in)
	}
	return out
}

// zipUnsupported: why a zip installer for arch cannot be imported (not one
// named installer), or "" if there is none.
func (m *WingetManifest) zipUnsupported(arch string) string {
	for _, in := range m.zipped() {
		if in.InstallerType != "zip" || !exeArchFits(in, arch) && !(arch == "x64" && in.Architecture == "x86") {
			continue
		}
		nt := in.NestedInstallerType
		switch {
		case nt == "portable":
			return "zip with a portable app whose program path is unsafe or missing (NestedInstallerFiles)"
		case msiTypes[nt] || manifest.IsExeInstallerType(nt):
			return "zip that does not name exactly one installer file (NestedInstallerFiles)"
		}
	}
	return ""
}

// MSIProductCode returns the installer's product code from the manifest,
// or "" if the manifest does not state one.
func (in WingetInstaller) MSIProductCode() string {
	if productRe.MatchString(in.ProductCode) {
		return strings.ToUpper(in.ProductCode)
	}
	for _, a := range in.ARP {
		if productRe.MatchString(a.ProductCode) {
			return strings.ToUpper(a.ProductCode)
		}
	}
	return ""
}

// ARPName and ARPVersion: what Windows will show in Apps & features after
// install, when the manifest says.
func (in WingetInstaller) ARPName() string {
	for _, a := range in.ARP {
		if a.DisplayName != "" {
			return a.DisplayName
		}
	}
	return ""
}

func (in WingetInstaller) ARPVersion() string {
	for _, a := range in.ARP {
		if a.DisplayVersion != "" {
			return a.DisplayVersion
		}
	}
	return ""
}

func dedupe(in []string) []string {
	var out []string
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}
