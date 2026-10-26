// Command audit-exe-packages is a READ-ONLY diagnostic: it opens pm.db
// directly (mode=ro, no schema/migration, no writes) and flags EXE-kind
// catalog packages that the exeDetect package_name-fallback bug (fixed in
// v0.10.7/v0.10.8) could affect — specifically rows that predate the
// manifest's own validation rule (which requires detect.display_name to be
// set and equal to package_name for any package validated today).
//
// Run it on the machine/volume where pm.db actually lives (it never talks
// to the network):
//
//	go run ./scripts/audit-exe-packages /var/lib/offpatch-server/pm.db
//
// or, from a built binary carried to the server:
//
//	go build -o audit-exe-packages ./scripts/audit-exe-packages
//	./audit-exe-packages /var/lib/offpatch-server/pm.db
package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"

	_ "modernc.org/sqlite"

	"offpatch/internal/manifest"
)

type row struct {
	packageID, title, state, version, packageName, exeJSON string
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: audit-exe-packages <path to pm.db>")
		os.Exit(2)
	}
	path := os.Args[1]
	dsn := "file:" + path + "?mode=ro&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open:", err)
		os.Exit(1)
	}
	defer db.Close()

	rows, err := db.Query(`SELECT package_id, title, state, version, package_name, exe FROM packages WHERE kind='exe' ORDER BY package_id`)
	if err != nil {
		fmt.Fprintln(os.Stderr, "query (is this really a pm.db?):", err)
		os.Exit(1)
	}
	defer rows.Close()

	var all []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.packageID, &r.title, &r.state, &r.version, &r.packageName, &r.exeJSON); err != nil {
			fmt.Fprintln(os.Stderr, "scan:", err)
			os.Exit(1)
		}
		all = append(all, r)
	}
	if err := rows.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "rows:", err)
		os.Exit(1)
	}

	fmt.Printf("%d exe-kind package(s) in the catalog\n\n", len(all))
	noVersion, noName, mismatch := 0, 0, 0
	for _, r := range all {
		var exe *manifest.ExeInstall
		if r.exeJSON != "" {
			exe = &manifest.ExeInstall{}
			if err := json.Unmarshal([]byte(r.exeJSON), exe); err != nil {
				fmt.Printf("[PARSE ERROR] %s (%s): %v\n", r.packageID, r.title, err)
				continue
			}
		}
		d := manifest.DetectFor(exe, r.packageName)
		want := d.DisplayVersion
		if want == "" {
			want = r.version
		}

		switch {
		case want == "":
			noVersion++
			fmt.Printf("[NO VERSION]   %-30s state=%-10s title=%q package_name=%q — can never verify or go up-to-date; will install/reinstall on every check-in once matched\n",
				r.packageID, r.state, r.title, r.packageName)
		case d.DisplayName == "":
			noName++
			fmt.Printf("[NO NAME]      %-30s state=%-10s title=%q — no detect.display_name AND no package_name; can never match any inventory, ever\n",
				r.packageID, r.state, r.title)
		case exe != nil && exe.Detect.DisplayName != "" && exe.Detect.DisplayName != r.packageName:
			mismatch++
			fmt.Printf("[NAME DIFFERS] %-30s state=%-10s detect.display_name=%q vs package_name=%q — informational, not necessarily wrong (the real ARP name wins), but worth eyeballing\n",
				r.packageID, r.state, exe.Detect.DisplayName, r.packageName)
		}
	}

	fmt.Printf("\n%d with no detectable version, %d with no name at all, %d with a display_name/package_name difference\n", noVersion, noName, mismatch)
	if noVersion == 0 && noName == 0 {
		fmt.Println("No live risk found from the exeDetect fallback fix.")
	}
}
