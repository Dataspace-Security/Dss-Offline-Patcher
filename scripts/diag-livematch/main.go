// Command diag-livematch is a READ-ONLY diagnostic: it opens pm.db directly
// (mode=ro, no schema/migration, no writes) and runs the real production
// package-matching rules (internal/store's classify/appItemMatch/
// presenceCopy/copyCurrent — not a reimplementation) against every app-kind
// catalog package and every endpoint's real inventory, printing exactly why
// each one does or does not match. It exists to diagnose a "dashboard says
// needed, catalog detail says no endpoint needs it" report from the real
// data instead of guessing.
//
// Build it where this repo is checked out (a dev machine, not the server):
//
//	go build -o diag-livematch ./scripts/diag-livematch
//
// then copy the resulting binary to the server and run it there directly —
// it needs no Go toolchain, no network access, and never writes to pm.db:
//
//	./diag-livematch /var/lib/offpatch-server/pm.db
//	./diag-livematch /var/lib/offpatch-server/pm.db "visual studio code,postman,notion,openssl,github desktop,java,wsl"
//
// The second, optional argument is a comma-separated, case-insensitive list
// of substrings matched against each package's title/package_name; omit it
// to print every app-kind package in the catalog.
package main

import (
	"fmt"
	"os"

	"offpatch/internal/store"
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		fmt.Fprintln(os.Stderr, "usage: diag-livematch <path to pm.db> [comma,separated,app,name,filters]")
		os.Exit(2)
	}
	var filter string
	if len(os.Args) == 3 {
		filter = os.Args[2]
	}
	if err := store.RunLiveMatchDiagnostic(os.Stdout, os.Args[1], filter); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
