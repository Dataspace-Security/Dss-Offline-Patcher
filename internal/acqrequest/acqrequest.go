// Package acqrequest is the "acquisition request": a small JSON file an
// operator exports from the isolated console (Updates page) and carries to
// the connected acquisition zone on approved media. It lists winget package
// ids and Windows KBs the fleet is missing; `pmctl auto` reads it from its
// requests directory and fetches them.
//
// The isolated server never sends anything out: the file only leaves as a
// browser download that a person moves across. It is deliberately unsigned
// and advisory. pmctl validates it strictly, resolves every item itself from
// the vendor sources (winget manifests over HTTPS with their SHA-256, the
// Microsoft Update Catalog), and everything it fetches still arrives on the
// isolated side as a signed bundle in quarantine awaiting approval. It
// carries no host names: only ids, versions, product codes and counts.
package acqrequest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	Format  = "offpatch.acquisition-request"
	Version = 1
	// MaxSize bounds a request file; MaxItems the apps and KBs in it.
	MaxSize  = 1 << 20
	MaxItems = 500
)

// Request is one exported acquisition request.
type Request struct {
	Format    string `json:"format"`
	Version   int    `json:"version"`
	RequestID string `json:"request_id"`
	CreatedAt string `json:"created_at"`
	CreatedBy string `json:"created_by"` // console user, as in the audit log
	// IntelGeneratedAt: the update intelligence the selection was made from.
	IntelGeneratedAt string `json:"intel_generated_at,omitempty"`
	Apps             []App  `json:"apps"`
	KBs              []KB   `json:"kbs"`
}

// App is one outdated application, identified by its winget package id.
type App struct {
	WingetID string `json:"winget_id"`
	Name     string `json:"name,omitempty"`
	Version  string `json:"version"` // newest winget PackageVersion per the intelligence
	// Architectures of the endpoints that have it installed (x64 | x86 | arm64);
	// for an app no endpoint has (imported from the console's Library,
	// endpoints 0), the architecture the operator chose. pmctl fetches the
	// MSI (or else a deployable EXE installer) for each listed architecture.
	Architectures []string    `json:"architectures"`
	Installed     []Installed `json:"installed,omitempty"`
	Endpoints     int         `json:"endpoints"`
}

// Installed is one distinct installed form of the app seen in inventory.
type Installed struct {
	ProductCode string `json:"product_code,omitempty"` // MSI {GUID}, when the app is an MSI
	Name        string `json:"name"`                   // display name in Apps & features
	Version     string `json:"version"`
}

// KB is one missing Windows cumulative update.
type KB struct {
	KB        string `json:"kb"`
	Product   string `json:"product,omitempty"` // "Windows 11 Version 24H2"
	Title     string `json:"title,omitempty"`   // catalog title per the intelligence
	Build     int    `json:"build"`
	Arch      string `json:"arch"`
	Server    bool   `json:"server,omitempty"`
	Endpoints int    `json:"endpoints"`
}

var (
	requestIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$`)
	// A conservative subset of winget's PackageIdentifier rule: 2-8 dotted
	// segments of ASCII letters, digits, '-', '_' and '+', each 1-32 long.
	wingetIDRe  = regexp.MustCompile(`^[A-Za-z0-9_+-]{1,32}(\.[A-Za-z0-9_+-]{1,32}){1,7}$`)
	versionRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
	kbRe        = regexp.MustCompile(`^KB[0-9]{4,10}$`)
	productRe   = regexp.MustCompile(`^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$`)
	arches      = map[string]bool{"x64": true, "x86": true, "arm64": true}
	maxTextLen  = 256
	errTooLarge = fmt.Errorf("acquisition request is larger than %d bytes", MaxSize)
)

// ValidWingetID reports whether id is an acceptable winget package id.
func ValidWingetID(id string) bool {
	if !wingetIDRe.MatchString(id) {
		return false
	}
	// The id becomes a file name on the acquisition host: no Windows device names.
	first, _, _ := strings.Cut(strings.ToUpper(id), ".")
	switch {
	case first == "CON" || first == "PRN" || first == "AUX" || first == "NUL":
		return false
	case len(first) == 4 && (strings.HasPrefix(first, "COM") || strings.HasPrefix(first, "LPT")) && first[3] >= '0' && first[3] <= '9':
		return false
	}
	return true
}

// ValidVersion reports whether v is an acceptable package version string
// (it becomes a path segment of the manifest URL).
func ValidVersion(v string) bool { return versionRe.MatchString(v) && !strings.Contains(v, "..") }

// ValidProductCode reports whether c is an MSI product code {GUID}.
func ValidProductCode(c string) bool { return productRe.MatchString(c) }

// CleanText drops control characters and truncates s to what Validate
// accepts (inventory text is endpoint-reported).
func CleanText(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	for len(s) > maxTextLen {
		_, n := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-n]
	}
	return s
}

// ValidKB reports whether kb looks like KB5044280.
func ValidKB(kb string) bool { return kbRe.MatchString(kb) }

// ValidArch reports whether a is x64, x86 or arm64.
func ValidArch(a string) bool { return arches[a] }

// NewID returns a request id like acq-request-20261017T101500Z-1a2b3c.
func NewID(now time.Time, suffix string) string {
	return "acq-request-" + now.UTC().Format("20060102T150405Z") + "-" + suffix
}

func validText(s string) bool {
	if len(s) > maxTextLen {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// Validate checks every field; the file comes from removable media and is
// treated as untrusted input.
func (r *Request) Validate() error {
	var errs []string
	add := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }
	if r.Format != Format {
		add("format must be %q", Format)
	}
	if r.Version != Version {
		add("version must be %d", Version)
	}
	if !requestIDRe.MatchString(r.RequestID) {
		add("request_id invalid")
	}
	if _, err := time.Parse(time.RFC3339, r.CreatedAt); err != nil {
		add("created_at must be RFC 3339")
	}
	if !validText(r.CreatedBy) || !validText(r.IntelGeneratedAt) {
		add("created_by / intel_generated_at invalid")
	}
	if len(r.Apps)+len(r.KBs) == 0 {
		add("request lists no apps and no KBs")
	}
	if len(r.Apps)+len(r.KBs) > MaxItems {
		add("request lists %d items, over the %d limit", len(r.Apps)+len(r.KBs), MaxItems)
	}
	seen := map[string]bool{}
	for i, a := range r.Apps {
		p := fmt.Sprintf("apps[%d]", i)
		if !ValidWingetID(a.WingetID) {
			add("%s.winget_id %q invalid", p, a.WingetID)
		} else if seen[strings.ToLower(a.WingetID)] {
			add("%s.winget_id %q duplicated", p, a.WingetID)
		}
		seen[strings.ToLower(a.WingetID)] = true
		if !ValidVersion(a.Version) {
			add("%s.version %q invalid", p, a.Version)
		}
		if !validText(a.Name) {
			add("%s.name invalid", p)
		}
		if len(a.Architectures) == 0 || len(a.Architectures) > 3 {
			add("%s.architectures must list 1-3 of x64, x86, arm64", p)
		}
		for _, ar := range a.Architectures {
			if !ValidArch(ar) {
				add("%s.architectures entry %q invalid", p, ar)
			}
		}
		if len(a.Installed) > 50 {
			add("%s.installed lists more than 50 entries", p)
		}
		for j, in := range a.Installed {
			if in.ProductCode != "" && !productRe.MatchString(in.ProductCode) {
				add("%s.installed[%d].product_code invalid", p, j)
			}
			if !validText(in.Name) || !validText(in.Version) {
				add("%s.installed[%d] name/version invalid", p, j)
			}
		}
		if a.Endpoints < 0 {
			add("%s.endpoints negative", p)
		}
	}
	seenKB := map[string]bool{}
	for i, k := range r.KBs {
		p := fmt.Sprintf("kbs[%d]", i)
		if !ValidKB(k.KB) {
			add("%s.kb %q invalid", p, k.KB)
		}
		if !ValidArch(k.Arch) {
			add("%s.arch %q invalid", p, k.Arch)
		}
		// One KB can serve several builds (24H2 and 25H2): one entry per
		// KB, architecture and build.
		kbKey := fmt.Sprintf("%s/%s/%d", k.KB, k.Arch, k.Build)
		if seenKB[kbKey] {
			add("%s %s/%s build %d duplicated", p, k.KB, k.Arch, k.Build)
		}
		seenKB[kbKey] = true
		if k.Build < 0 || k.Build > 99999 || k.Endpoints < 0 {
			add("%s.build/endpoints out of range", p)
		}
		if !validText(k.Product) || !validText(k.Title) {
			add("%s product/title invalid", p)
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// Parse reads and validates a request (strict: unknown fields are refused).
func Parse(rd io.Reader) (*Request, error) {
	b, err := io.ReadAll(io.LimitReader(rd, MaxSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxSize {
		return nil, errTooLarge
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	r := &Request{}
	if err := dec.Decode(r); err != nil {
		return nil, fmt.Errorf("not an acquisition request: %w", err)
	}
	if dec.More() {
		return nil, errors.New("not an acquisition request: trailing data")
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}
