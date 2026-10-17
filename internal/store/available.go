package store

import (
	"context"
	"sort"
	"strings"
)

// Available is a catalog package an endpoint still needs.
type Available struct {
	PackageID        string `json:"package_id"`
	Title            string `json:"title"`
	Kind             string `json:"kind"`
	Severity         string `json:"severity"`
	Version          string `json:"version"`
	KB               string `json:"kb"`
	InstalledVersion string `json:"installed_version"` // older version present ("" = none / KB missing)
	PackageState     string `json:"package_state"`     // approved | quarantined
	Reason           string `json:"reason"`
	// DeploymentID is set when an active/paused deployment already targets
	// this endpoint with this package.
	DeploymentID string `json:"deployment_id"`
	TargetState  string `json:"target_state"`
}

// identity groups versions of the same product so only the newest is shown.
func identity(p Package) string {
	switch p.Kind {
	case "msu":
		return "kb:" + p.KB
	case "agent":
		return "agent"
	case "msi":
		if p.PackageName != "" {
			return "msi:" + strings.ToLower(p.PackageName)
		}
		return "msi:" + p.ProductCode
	}
	return p.Kind + ":" + p.PackageName
}

// needs decides whether endpoint e (with inventory inv) needs package p.
// Third-party apps are offered as UPDATES only: an app that is not installed
// at all is never "needed" (we don't push Chrome to machines without it).
func needs(p Package, e Endpoint, inv []InventoryItem, sup map[string]bool) (bool, string, string) {
	if ok, _ := applicable(p, e); !ok {
		return false, "", ""
	}
	if ok, _ := presentIn(inv, p, sup); ok {
		return false, "", ""
	}
	if appStoreManaged(inv, p) {
		return false, "", ""
	}
	switch p.Kind {
	case "msu":
		return true, "", "security update not installed"
	case "agent":
		for _, it := range inv {
			if it.Kind == "agent" {
				return true, it.Version, "agent upgrade"
			}
		}
		return true, "", "agent upgrade"
	case "deb", "rpm", "pkg":
		for _, it := range inv {
			if (it.Kind == "pkg" || (it.Kind == "app" && p.Kind == "pkg")) && it.ID == p.PackageName && !VersionAtLeast(it.Version, p.Version) {
				return true, it.Version, "update available"
			}
		}
	case "msi":
		if p.PackageName == "" {
			return false, "", ""
		}
		for _, it := range inv {
			if it.Kind == "product" && strings.EqualFold(strings.TrimSpace(it.Name), p.PackageName) && !VersionAtLeast(it.Version, p.Version) {
				return true, it.Version, "update available"
			}
		}
	}
	return false, "", ""
}

// catalogForNeeds: approved + quarantined packages, minus any superseded by
// another live catalog package, keeping only the newest version per product.
func (s *Store) catalogForNeeds(ctx context.Context) ([]Package, error) {
	all, err := s.ListPackages(ctx, "")
	if err != nil {
		return nil, err
	}
	live := []Package{}
	supersededKB := map[string]bool{}
	for _, p := range all {
		if p.State == "approved" || p.State == "quarantined" {
			live = append(live, p)
			for _, k := range p.Supersedes {
				supersededKB[strings.ToUpper(k)] = true
			}
		}
	}
	newest := map[string]Package{}
	for _, p := range live {
		if p.Kind == "msu" && supersededKB[strings.ToUpper(p.KB)] {
			continue
		}
		id := identity(p)
		cur, ok := newest[id]
		if !ok || (p.Version != "" && !VersionAtLeast(cur.Version, p.Version)) || (cur.State != "approved" && p.State == "approved" && cur.Version == p.Version) {
			newest[id] = p
		}
	}
	out := make([]Package, 0, len(newest))
	for _, p := range newest {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		ri, rj := sevOrder[out[i].Severity], sevOrder[out[j].Severity]
		if ri != rj {
			return ri > rj
		}
		return out[i].PackageID < out[j].PackageID
	})
	return out, nil
}

var sevOrder = map[string]int{"critical": 4, "important": 3, "moderate": 2, "low": 1}

// AvailableFor lists what one endpoint still needs.
func (s *Store) AvailableFor(ctx context.Context, endpointID string) ([]Available, error) {
	e, err := getEndpoint(ctx, s.db, endpointID)
	if err != nil {
		return nil, err
	}
	pkgs, err := s.catalogForNeeds(ctx)
	if err != nil {
		return nil, err
	}
	targets, err := queryTargets(ctx, s.db, `t.endpoint_id=? AND d.state IN ('active','paused')`, endpointID)
	if err != nil {
		return nil, err
	}
	out := []Available{}
	if e.RetiredAt != "" {
		return out, nil
	}
	for _, p := range pkgs {
		sup, err := supersedingKBs(ctx, s.db, p.KB)
		if err != nil {
			return nil, err
		}
		ok, have, why := needs(p, e, e.inventory, sup)
		if !ok {
			continue
		}
		a := Available{PackageID: p.PackageID, Title: p.Title, Kind: p.Kind, Severity: p.Severity, Version: p.Version, KB: p.KB,
			InstalledVersion: have, PackageState: p.State, Reason: why}
		for _, t := range targets {
			if t.PackageID == p.PackageID {
				a.DeploymentID, a.TargetState = t.DeploymentID, t.State
			}
		}
		out = append(out, a)
	}
	return out, nil
}

// PackageNeed summarises, per package, which endpoints still need it.
type PackageNeed struct {
	PackageID string   `json:"package_id"`
	Needed    int      `json:"needed"`
	Endpoints []string `json:"endpoint_ids"`
	Hostnames []string `json:"hostnames"`
}

// Needs computes PackageNeed for every live catalog package across the fleet.
func (s *Store) Needs(ctx context.Context) (map[string]PackageNeed, error) {
	pkgs, err := s.catalogForNeeds(ctx)
	if err != nil {
		return nil, err
	}
	eps, err := listEndpoints(ctx, s.db)
	if err != nil {
		return nil, err
	}
	out := map[string]PackageNeed{}
	for _, p := range pkgs {
		sup, err := supersedingKBs(ctx, s.db, p.KB)
		if err != nil {
			return nil, err
		}
		pn := PackageNeed{PackageID: p.PackageID, Endpoints: []string{}, Hostnames: []string{}}
		for _, e := range eps {
			if e.RetiredAt != "" || e.InventoryAt == "" {
				continue
			}
			if ok, _, _ := needs(p, e, e.inventory, sup); ok {
				pn.Needed++
				pn.Endpoints = append(pn.Endpoints, e.EndpointID)
				pn.Hostnames = append(pn.Hostnames, e.Hostname)
			}
		}
		out[p.PackageID] = pn
	}
	return out, nil
}
