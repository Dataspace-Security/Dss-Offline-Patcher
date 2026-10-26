package store

import (
	"database/sql"
	"fmt"
	"io"
	"strings"

	"offpatch/internal/manifest"
)

// RunLiveMatchDiagnostic is a READ-ONLY diagnostic: it opens a pm.db
// (mode=ro, no migrations, no writes) and runs the actual production
// matching rules (classify/appItemMatch/presenceCopy/copyCurrent/exeDetect,
// not a reimplementation) against the real packages and endpoints rows,
// printing to w exactly why each app package does or does not match each
// endpoint's inventory. It exists to diagnose a "dashboard says needed,
// catalog detail says no endpoint needs it" report without guessing at what
// the live data actually looks like.
//
// filter (optional) is a comma-separated, case-insensitive list of
// substrings matched against each package's title/package_name; "" prints
// every app-kind (msi/exe/portable/msix) package in the catalog.
//
// Nothing here is called by the running server; it is reached only via the
// diag-livematch command (scripts/diag-livematch.go) or go test -run
// TestDiagnoseLiveMatch.
func RunLiveMatchDiagnostic(w io.Writer, path, filter string) error {
	var filters []string
	filter = strings.ToLower(filter)
	if filter != "" {
		filters = strings.Split(filter, ",")
		for i := range filters {
			filters[i] = strings.TrimSpace(filters[i])
		}
	}

	dsn := "file:" + path + "?mode=ro&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer db.Close()

	rows, err := db.Query(`SELECT ` + packageCols + ` FROM packages WHERE kind IN ('msi','exe','portable','msix') ORDER BY title`)
	if err != nil {
		return fmt.Errorf("query packages (is this really a pm.db?): %w", err)
	}
	var pkgs []Package
	for rows.Next() {
		p, err := scanPackage(rows)
		if err != nil {
			rows.Close()
			return fmt.Errorf("scan package: %w", err)
		}
		pkgs = append(pkgs, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("rows: %w", err)
	}

	erows, err := db.Query(`SELECT ` + endpointCols + ` FROM endpoints`)
	if err != nil {
		return fmt.Errorf("query endpoints: %w", err)
	}
	var eps []Endpoint
	for erows.Next() {
		e, err := scanEndpoint(erows)
		if err != nil {
			erows.Close()
			return fmt.Errorf("scan endpoint: %w", err)
		}
		eps = append(eps, e)
	}
	erows.Close()
	if err := erows.Err(); err != nil {
		return fmt.Errorf("rows: %w", err)
	}

	matches := func(p Package) bool {
		if len(filters) == 0 {
			return true
		}
		hay := strings.ToLower(p.Title + " " + p.PackageName)
		for _, f := range filters {
			if f != "" && strings.Contains(hay, f) {
				return true
			}
		}
		return false
	}

	st := &Store{} // zero-value is fine: osFactsFor only needs the UBR hint, nil here
	sup := map[string]bool{}

	fmt.Fprintf(w, "\n%d app-kind package(s), %d endpoint(s)\n", len(pkgs), len(eps))
	var totalNoMatch, totalNeeded, totalCurrentOnly, totalNotApplicable, totalNoInventory int
	for _, p := range pkgs {
		if !matches(p) {
			continue
		}
		fmt.Fprintf(w, "\n=== %s [%s] state=%s version=%q package_name=%q product_code=%q\n", p.Title, p.Kind, p.State, p.Version, p.PackageName, p.ProductCode)
		if p.Kind == manifest.KindExe {
			d := exeDetect(p)
			fmt.Fprintf(w, "    exeDetect: display_name=%q display_version=%q product_code=%q scope_user=%v\n", d.DisplayName, d.DisplayVersion, d.ProductCode, perUserExe(p))
		}
		anyEndpointHasApp := false
		anyNeeded := false
		for _, e := range eps {
			if ok, why := applicable(p, e); !ok {
				fmt.Fprintf(w, "    endpoint=%-20s -> applicable()=false (%s) — excluded from NeedsFor entirely\n", e.Hostname, why)
				totalNotApplicable++
				continue
			}
			if e.InventoryAt == "" {
				fmt.Fprintf(w, "    endpoint=%-20s -> InventoryAt empty — excluded from NeedsFor entirely (no inventory yet)\n", e.Hostname)
				totalNoInventory++
				continue
			}
			v := classify(p, e, st.osFactsFor(e.OSVersion, e.Build, e.Arch), e.inventory, sup)
			switch v.Presence {
			case PresenceNeeded:
				totalNeeded++
			default:
				totalCurrentOnly++
			}
			epHadMatch := false
			for _, it := range e.inventory {
				am := appItemMatch(p, it)
				if !am {
					continue
				}
				epHadMatch, anyEndpointHasApp = true, true
				cur := copyCurrent(p, it)
				pc := presenceCopy(p, it)
				if !cur {
					anyNeeded = true
				}
				fmt.Fprintf(w, "    endpoint=%-20s inv.kind=%-8s inv.name=%-45q inv.id=%-40q inv.version=%-12s inv.scope=%-5s inv.view=%-3s -> appItemMatch=%v presenceCopy=%v copyCurrent=%v\n",
					e.Hostname, it.Kind, it.Name, it.ID, it.Version, it.Scope, it.View, am, pc, cur)
			}
			fmt.Fprintf(w, "    endpoint=%-20s -> classify()=%s have=%q why=%q\n", e.Hostname, v.Presence, v.Have, v.Why)
			if !epHadMatch {
				totalNoMatch++
			}
		}
		if !anyEndpointHasApp {
			fmt.Fprintf(w, "    -> NO inventory item on ANY endpoint matches appItemMatch for this package (this is why \"no endpoint needs it\")\n")
		} else if !anyNeeded {
			fmt.Fprintf(w, "    -> every matching inventory item is already current (copyCurrent=true)\n")
		} else {
			fmt.Fprintf(w, "    -> at least one endpoint should show as needing this package\n")
		}
	}
	fmt.Fprintf(w, "\n--- totals across printed (package,endpoint) pairs ---\n")
	fmt.Fprintf(w, "classify()=needed: %d   classify()=present/other: %d   no inventory item matched appItemMatch at all: %d   excluded (not applicable): %d   excluded (no inventory yet): %d\n",
		totalNeeded, totalCurrentOnly, totalNoMatch, totalNotApplicable, totalNoInventory)
	return nil
}
