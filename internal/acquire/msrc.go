package acquire

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

// DefaultMSRCURL is the MSRC security update API (CVRF v3).
const DefaultMSRCURL = "https://api.msrc.microsoft.com"

// MSRC is a client for the monthly CVRF documents.
type MSRC struct {
	BaseURL string       // default DefaultMSRCURL; injectable for tests
	HTTP    *http.Client // default DefaultHTTPClient()
}

// NewMSRC returns a client for the public MSRC API.
func NewMSRC() *MSRC { return &MSRC{BaseURL: DefaultMSRCURL, HTTP: DefaultHTTPClient()} }

// SecurityUpdate is one KB from a monthly MSRC release.
type SecurityUpdate struct {
	KB         string   `json:"kb"`
	Products   []string `json:"products"`
	Severity   string   `json:"severity"` // max over products; manifest severity or ""
	CVEs       []string `json:"cves"`
	Supersedes []string `json:"supersedes,omitempty"` // KBs from the remediation "Supercedence" field

	// Per-product detail, used to scope severity to what is actually fetched.
	ProductSeverity map[string]string   `json:"-"`
	productCVEs     map[string][]string // product -> CVEs
}

var monthRe = regexp.MustCompile(`^(\d{4})-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$`)

// ValidMonth reports whether s looks like "2026-Oct".
func ValidMonth(s string) bool { return monthRe.MatchString(s) }

// Month fetches and parses the CVRF document for month ("2026-Oct").
func (m *MSRC) Month(ctx context.Context, month string) ([]SecurityUpdate, error) {
	if !ValidMonth(month) {
		return nil, fmt.Errorf("month must look like 2026-Oct (got %q)", month)
	}
	base := m.BaseURL
	if base == "" {
		base = DefaultMSRCURL
	}
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(base, "/")+"/cvrf/v3.0/cvrf/"+month, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	b, err := doRead(ctx, m.HTTP, req, maxJSONBytes)
	if err != nil {
		return nil, err
	}
	return ParseCVRF(b)
}

type cvrfValue struct {
	Value *string `json:"Value"`
}

func (v cvrfValue) String() string {
	if v.Value == nil {
		return ""
	}
	return *v.Value
}

type cvrfDoc struct {
	ProductTree struct {
		FullProductName []struct {
			ProductID string `json:"ProductID"`
			Value     string `json:"Value"`
		} `json:"FullProductName"`
	} `json:"ProductTree"`
	Vulnerability []struct {
		CVE     string `json:"CVE"`
		Threats []struct {
			Type        int       `json:"Type"`
			Description cvrfValue `json:"Description"`
			ProductID   []string  `json:"ProductID"`
		} `json:"Threats"`
		Remediations []struct {
			Type         int       `json:"Type"`
			Description  cvrfValue `json:"Description"`
			ProductID    []string  `json:"ProductID"`
			Supercedence string    `json:"Supercedence"`
		} `json:"Remediations"`
	} `json:"Vulnerability"`
}

const (
	cvrfThreatSeverity      = 3
	cvrfRemedyNoneAvailable = 3
	cvrfRemedyWillNotFix    = 4
)

var (
	numericRe = regexp.MustCompile(`^\d{4,10}$`)
	digitsRe  = regexp.MustCompile(`\d{4,10}`)
)

// ParseCVRF extracts per-KB products, max severity and CVEs.
func ParseCVRF(b []byte) ([]SecurityUpdate, error) {
	var doc cvrfDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("msrc cvrf: %w", err)
	}
	if len(doc.Vulnerability) == 0 {
		return nil, fmt.Errorf("msrc cvrf: no vulnerabilities in document")
	}
	names := map[string]string{}
	for _, p := range doc.ProductTree.FullProductName {
		names[p.ProductID] = p.Value
	}
	name := func(id string) string {
		if n, ok := names[id]; ok && n != "" {
			return n
		}
		return "product " + id
	}

	type agg struct {
		prodSev  map[string]string
		prodCVEs map[string]map[string]bool
		cves     map[string]bool
		sup      map[string]bool
	}
	byKB := map[string]*agg{}

	for _, v := range doc.Vulnerability {
		sevByProduct := map[string]string{}
		vulnMax := ""
		for _, t := range v.Threats {
			if t.Type != cvrfThreatSeverity {
				continue
			}
			s := NormalizeSeverity(t.Description.String())
			if s == "" {
				continue
			}
			vulnMax = MaxSeverity(vulnMax, s)
			for _, pid := range t.ProductID {
				sevByProduct[pid] = MaxSeverity(sevByProduct[pid], s)
			}
		}
		for _, r := range v.Remediations {
			if r.Type == cvrfRemedyNoneAvailable || r.Type == cvrfRemedyWillNotFix {
				continue
			}
			d := strings.TrimSpace(r.Description.String())
			if !numericRe.MatchString(d) {
				continue // e.g. "Release Notes", version strings
			}
			kb := "KB" + d
			a := byKB[kb]
			if a == nil {
				a = &agg{prodSev: map[string]string{}, prodCVEs: map[string]map[string]bool{}, cves: map[string]bool{}, sup: map[string]bool{}}
				byKB[kb] = a
			}
			if v.CVE != "" {
				a.cves[v.CVE] = true
			}
			for _, s := range digitsRe.FindAllString(r.Supercedence, -1) {
				if "KB"+s != kb {
					a.sup["KB"+s] = true
				}
			}
			for _, pid := range r.ProductID {
				pn := name(pid)
				s := sevByProduct[pid]
				if s == "" {
					s = vulnMax // product not scored separately: use the CVE's max
				}
				a.prodSev[pn] = MaxSeverity(a.prodSev[pn], s)
				if a.prodCVEs[pn] == nil {
					a.prodCVEs[pn] = map[string]bool{}
				}
				if v.CVE != "" {
					a.prodCVEs[pn][v.CVE] = true
				}
			}
		}
	}

	out := make([]SecurityUpdate, 0, len(byKB))
	for kb, a := range byKB {
		u := SecurityUpdate{KB: kb, ProductSeverity: a.prodSev, productCVEs: map[string][]string{}}
		for p, s := range a.prodSev {
			u.Products = append(u.Products, p)
			u.Severity = MaxSeverity(u.Severity, s)
		}
		for p, set := range a.prodCVEs {
			u.productCVEs[p] = sortedKeys(set)
		}
		sort.Strings(u.Products)
		u.CVEs = sortedKeys(a.cves)
		u.Supersedes = sortedKeys(a.sup)
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].KB < out[j].KB })
	return out, nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ForProduct narrows u to products whose name contains product
// (case-insensitive) and, if arch is set, that mention arch. If the arch
// filter removes everything, the product-only match is used. Severity and
// CVEs are recomputed for the remaining products. ok=false if none match.
func (u SecurityUpdate) ForProduct(product, arch string) (SecurityUpdate, bool) {
	p := strings.ToLower(strings.TrimSpace(product))
	var byProd []string
	for _, name := range u.Products {
		if p == "" || strings.Contains(strings.ToLower(name), p) {
			byProd = append(byProd, name)
		}
	}
	if len(byProd) == 0 {
		return SecurityUpdate{}, false
	}
	sel := byProd
	if arch != "" && arch != "any" {
		var byArch []string
		for _, name := range byProd {
			if MatchesArch(name, arch) {
				byArch = append(byArch, name)
			}
		}
		if len(byArch) > 0 {
			sel = byArch
		}
	}
	r := SecurityUpdate{KB: u.KB, Supersedes: u.Supersedes, ProductSeverity: map[string]string{}, productCVEs: map[string][]string{}}
	cves := map[string]bool{}
	for _, name := range sel {
		r.Products = append(r.Products, name)
		s := u.ProductSeverity[name]
		r.ProductSeverity[name] = s
		r.Severity = MaxSeverity(r.Severity, s)
		r.productCVEs[name] = u.productCVEs[name]
		for _, c := range u.productCVEs[name] {
			cves[c] = true
		}
	}
	r.CVEs = sortedKeys(cves)
	return r, true
}

// FindKB returns the update for kb, if present.
func FindKB(list []SecurityUpdate, kb string) (SecurityUpdate, bool) {
	for _, u := range list {
		if strings.EqualFold(u.KB, kb) {
			return u, true
		}
	}
	return SecurityUpdate{}, false
}
