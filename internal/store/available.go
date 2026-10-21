package store

import (
	"context"
	"sort"
	"strings"

	"offpatch/internal/intel"
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
	case "exe":
		return exeIdentity(p)
	case "msi":
		if p.PackageName != "" {
			return "msi:" + strings.ToLower(p.PackageName)
		}
		return "msi:" + p.ProductCode
	}
	return p.Kind + ":" + p.PackageName
}

// needs decides whether endpoint e (with inventory inv) needs package p
// (classify: the verdict every caller shares). Third-party apps are offered
// as UPDATES only: an app that is not installed at all is never "needed"
// (we don't push Chrome to machines without it).
func needs(p Package, e Endpoint, os OSFacts, inv []InventoryItem, sup map[string]bool) (bool, string, string) {
	v := classify(p, e, os, inv, sup)
	if v.Presence != PresenceNeeded {
		return false, "", ""
	}
	return true, v.Have, v.Why
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
	targets, err := queryTargets(ctx, s.db, `t.endpoint_id=? AND d.state IN ('active','paused') AND d.operation='install'`, endpointID)
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
		ok, have, why := needs(p, e, s.osFactsFor(e.OSVersion, e.Build, e.Arch), e.inventory, sup)
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

// PackageNeed summarises, per package, which endpoints still need it and
// where the rest of the fleet stands (GET /api/packages-needs, PackageFleet).
type PackageNeed struct {
	PackageID string   `json:"package_id"`
	Needed    int      `json:"needed"`
	Endpoints []string `json:"endpoint_ids"`
	Hostnames []string `json:"hostnames"`
	// Every applicable endpoint with inventory is exactly one of needed,
	// up_to_date (present, superseded, newer, or otherwise not needed) and
	// not_installed (a third-party app that is not on it).
	UpToDate     int `json:"up_to_date"`
	NotInstalled int `json:"not_installed"`
	// Which endpoints those are, so the console can show per machine what a
	// deployment will do (install, skip as up to date, skip as not installed).
	UpToDateIDs     []string `json:"up_to_date_ids"`
	NotInstalledIDs []string `json:"not_installed_ids"`
	// Targets of install deployments and active exceptions, per endpoint
	// (may overlap with needed).
	Deploying int `json:"deploying"`
	// RestartNeeded: of those deploying, installed and waiting for a restart.
	RestartNeeded      int    `json:"restart_needed"`
	Verified           int    `json:"verified"`
	Failed             int    `json:"failed"`
	Exception          int    `json:"exception"`
	ActiveDeploymentID string `json:"active_deployment_id"`

	state string // package state (approved | quarantined)
}

// Approved reports whether the package is approved (deployable now).
func (n PackageNeed) Approved() bool { return n.state == "approved" }

// Needs computes PackageNeed for every live catalog package across the fleet.
func (s *Store) Needs(ctx context.Context) (map[string]PackageNeed, error) {
	eps, err := listEndpoints(ctx, s.db)
	if err != nil {
		return nil, err
	}
	return s.NeedsFor(ctx, eps)
}

// NeedsFor is Needs over the given endpoints (loaded with their inventory,
// e.g. by ListEndpoints), so callers that already hold the fleet do not
// parse every inventory again.
func (s *Store) NeedsFor(ctx context.Context, eps []Endpoint) (map[string]PackageNeed, error) {
	pkgs, err := s.catalogForNeeds(ctx)
	if err != nil {
		return nil, err
	}
	fl, err := s.FleetTargets(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]PackageNeed{}
	for _, p := range pkgs {
		sup, err := supersedingKBs(ctx, s.db, p.KB)
		if err != nil {
			return nil, err
		}
		pn := PackageNeed{PackageID: p.PackageID, Endpoints: []string{}, Hostnames: []string{}, UpToDateIDs: []string{}, NotInstalledIDs: []string{}, state: p.State,
			ActiveDeploymentID: fl.ActiveDeployment(p.PackageID)}
		for _, e := range eps {
			if e.RetiredAt != "" {
				continue
			}
			if ok, _ := applicable(p, e); !ok {
				continue
			}
			st := fl.Status(p.PackageID, e.EndpointID)
			if st.Exception {
				pn.Exception++
			}
			switch {
			case st.Verified:
				pn.Verified++
			case st.Deploying:
				pn.Deploying++
				if st.RestartNeeded {
					pn.RestartNeeded++
				}
			case st.Failed:
				pn.Failed++
			}
			if e.InventoryAt == "" {
				continue
			}
			switch classify(p, e, s.osFactsFor(e.OSVersion, e.Build, e.Arch), e.inventory, sup).Presence {
			case PresenceNeeded:
				pn.Needed++
				pn.Endpoints = append(pn.Endpoints, e.EndpointID)
				pn.Hostnames = append(pn.Hostnames, e.Hostname)
			case PresenceNotInstalled:
				pn.NotInstalled++
				pn.NotInstalledIDs = append(pn.NotInstalledIDs, e.EndpointID)
			default: // present, or kept current by the Mac App Store
				pn.UpToDate++
				pn.UpToDateIDs = append(pn.UpToDateIDs, e.EndpointID)
			}
		}
		out[p.PackageID] = pn
	}
	return out, nil
}

// SameAppName reports whether an installed program's display name (Apps &
// features) is the app an MSI package's package_name names. Names are
// compared exactly, or normalised like update intelligence does (version
// numbers, architecture and parenthesised qualifiers dropped), so a
// package_name "7-Zip" matches "7-Zip 26.03 (x64 edition)", whose name
// changes with every version.
func SameAppName(installed, packageName string) bool {
	if strings.EqualFold(strings.TrimSpace(installed), strings.TrimSpace(packageName)) {
		return true
	}
	a, b := intel.Normalize(installed), intel.Normalize(packageName)
	return len(a) >= 3 && a == b
}

const notInstalledDetail = "app not installed: third-party packages update an installed app and are never installed on machines without it"

// appInstalled reports whether a third-party app package (msi, deb, rpm,
// pkg) has any version of its app on the endpoint. Windows updates and agent
// packages are not apps and always count as installed.
func appInstalled(inv []InventoryItem, p Package) bool {
	switch p.Kind {
	case "msi", "exe", "deb", "rpm", "pkg":
		for _, it := range inv {
			if appItemMatch(p, it) {
				return true
			}
		}
		return false
	}
	return true
}
