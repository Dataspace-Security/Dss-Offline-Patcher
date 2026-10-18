package acquire

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"offpatch/internal/intel"
)

// The Library: installer and description details of winget packages, looked
// up from the per-version manifests (installer + defaultLocale) so the
// console can show what could be imported before anyone asks for it. It is
// community-supplied text and only describes; what gets deployed is still
// resolved again, downloaded and hash-checked by an acquisition request.

// WingetLocale is the descriptive part of a package version (the
// defaultLocale manifest, or a singleton manifest).
type WingetLocale struct {
	Publisher        string
	PackageName      string // the product name, e.g. "Microsoft Edge WebView2 Runtime"
	PublisherURL     string
	PackageURL       string // the product's home page
	License          string
	ShortDescription string
	Description      string
}

const (
	maxLibraryText = 1000 // runes, descriptions
	maxLibraryName = 200  // runes, publisher / license
	maxLibraryURL  = 2048 // bytes
)

// FetchWingetLocale reads the defaultLocale manifest of id@version: the
// en-US locale file (the default for almost every package), else the
// DefaultLocale named by the version manifest, or the singleton manifest.
func FetchWingetLocale(ctx context.Context, hc *http.Client, base, id, version string) (*WingetLocale, error) {
	if id == "" || version == "" {
		return nil, errors.New("winget id and version are required")
	}
	if hc == nil {
		hc = DefaultHTTPClient()
	}
	dir := wingetDir(base, id, version)
	if !strings.HasPrefix(dir, "https://") {
		return nil, fmt.Errorf("winget manifests URL must be https: %s", dir)
	}
	get := func(name string) (map[string]string, error) {
		body, err := getManifest(ctx, hc, dir+url.PathEscape(name))
		if err != nil {
			return nil, err
		}
		return topLevelScalars(body), nil
	}
	fields, err := get(id + ".locale.en-US.yaml")
	if errors.Is(err, ErrWingetNotFound) {
		var ver map[string]string
		if ver, err = get(id + ".yaml"); err != nil {
			return nil, err
		}
		switch loc := ver["DefaultLocale"]; {
		case ver["ManifestType"] == "singleton":
			fields = ver
		case loc == "" || loc == "en-US" || strings.ContainsAny(loc, "/\\"):
			return nil, ErrWingetNotFound
		default:
			fields, err = get(id + ".locale." + loc + ".yaml")
		}
	}
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(fields["PackageIdentifier"], id) {
		return nil, fmt.Errorf("winget locale manifest is for %q, not %s", fields["PackageIdentifier"], id)
	}
	return &WingetLocale{Publisher: fields["Publisher"], PackageName: fields["PackageName"], PublisherURL: fields["PublisherUrl"], PackageURL: fields["PackageUrl"],
		License: fields["License"], ShortDescription: fields["ShortDescription"], Description: fields["Description"]}, nil
}

func wingetDir(base, id, version string) string {
	u := WingetManifestURLs(base, id, version)[0]
	return u[:strings.LastIndex(u, "/")+1]
}

// topLevelScalars returns the top-level string values of a manifest. Locale
// manifests carry free text (release notes, tags, documentation lists) the
// small YAML reader may refuse; then the single-line top-level keys are
// read on their own, which is all the Library needs.
func topLevelScalars(b []byte) map[string]string {
	out := map[string]string{}
	if v, err := parseYAMLMini(b); err == nil {
		if m, ok := v.(map[string]any); ok {
			for k, x := range m {
				if s, ok := x.(string); ok {
					out[k] = strings.TrimSpace(s)
				}
			}
			return out
		}
	}
	for _, line := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
		if line == "" || line[0] == ' ' || line[0] == '#' || line[0] == '-' {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok || strings.ContainsAny(k, " \t\"'") {
			continue
		}
		v = strings.TrimSpace(v)
		if i := strings.Index(v, " #"); i >= 0 && !strings.HasPrefix(v, "'") && !strings.HasPrefix(v, `"`) {
			v = strings.TrimSpace(v[:i])
		}
		if n := len(v); n >= 2 && (v[0] == '\'' && v[n-1] == '\'' || v[0] == '"' && v[n-1] == '"') {
			v = v[1 : n-1]
		}
		if v == "" || v == "|" || v == "|-" || v == ">" || v == ">-" || strings.HasPrefix(v, "[") || strings.HasPrefix(v, "{") {
			continue
		}
		out[k] = v
	}
	return out
}

// ResolveWinget looks up id@version in the winget manifests for the
// Library. The installer manifest is required; the description is best
// effort (a missing or unreadable locale manifest leaves it empty).
// Only installers pmctl could fetch are listed: an https URL and, for
// MSI-type installers, a SHA-256 to check the download against.
func ResolveWinget(ctx context.Context, hc *http.Client, base, id, version string, now time.Time) (intel.Resolved, error) {
	m, _, err := FetchWingetManifest(ctx, hc, base, id, version)
	if err != nil {
		return intel.Resolved{}, err
	}
	r := intel.Resolved{ID: m.ID, Version: m.Version, Publisher: libText(m.Publisher, maxLibraryName),
		Installers: []intel.ResolvedInstaller{}, ResolvedAt: now.UTC().Format(time.RFC3339)}
	seen := map[intel.ResolvedInstaller]bool{}
	for _, in := range m.Installers {
		ri := intel.ResolvedInstaller{Arch: in.Architecture, Type: in.InstallerType, Scope: in.Scope, URL: libURL(in.URL)}
		if hex64Re.MatchString(in.SHA256) {
			ri.SHA256 = in.SHA256
		}
		if in.IsEXE() {
			// Plain "exe" needs the manifest's silent switch (the others have
			// documented defaults); the flag is only sent where it matters.
			ri.Silent = in.InstallerType == "exe" && in.Switches.Silent != ""
		}
		if msiTypes[ri.Type] {
			if ri.SHA256 == "" {
				continue
			}
			ri.ProductCode = in.MSIProductCode()
		}
		if ri.URL == "" || ri.Arch == "" || ri.Type == "" || seen[ri] {
			continue
		}
		seen[ri] = true
		r.Installers = append(r.Installers, ri)
	}
	loc, err := FetchWingetLocale(ctx, hc, base, m.ID, m.Version)
	if err == nil {
		if loc.Publisher != "" {
			r.Publisher = libText(loc.Publisher, maxLibraryName)
		}
		r.Homepage, r.PublisherURL = libURL(loc.PackageURL), libURL(loc.PublisherURL)
		r.License = libText(loc.License, maxLibraryName)
		r.Description = libText(loc.ShortDescription, maxLibraryText)
		if r.Description == "" {
			r.Description = libText(loc.Description, maxLibraryText)
		}
	} else if ctx.Err() != nil {
		return intel.Resolved{}, ctx.Err()
	}
	return r, nil
}

// libURL keeps only https URLs of reasonable length.
func libURL(s string) string {
	s = strings.TrimSpace(s)
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || len(s) > maxLibraryURL {
		return ""
	}
	return s
}

// libText drops control characters, folds whitespace and truncates.
func libText(s string, max int) string {
	s = strings.Join(strings.FieldsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f || r == ' ' }), " ")
	if utf8.RuneCountInString(s) > max {
		r := []rune(s)
		s = strings.TrimSpace(string(r[:max-1])) + "…"
	}
	return s
}

// LibraryImportable applies the Library's import rule to a resolved
// package: exactly intel.Importable (the rule the server shows), with the
// MSI ProductCode readable from the file (pmctl reads it with
// internal/msi). arches empty means any architecture (nothing installed
// yet). It returns "yes"/"no" and the reason.
func LibraryImportable(r intel.Resolved, arches []string) (string, string) {
	return intel.Importable(&r, arches, true)
}

func archFits(arch string, want []string, isMSI bool) bool {
	for _, w := range want {
		switch {
		case strings.EqualFold(arch, w), arch == "neutral" && w != "arm64", isMSI && arch == "x86" && w == "x64":
			return true
		}
	}
	return false
}
