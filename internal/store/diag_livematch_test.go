package store

// TestDiagnoseLiveMatch is a thin go-test entry point for a Go dev machine
// that already has this repo checked out. On the production server itself,
// build and copy the standalone scripts/diag-livematch.go binary instead
// (no Go toolchain needed there) — see its doc comment.
//
//	PMDB_PATH=/var/lib/offpatch-server/pm.db go test ./internal/store/ -run TestDiagnoseLiveMatch -v
//
//	PMDB_PATH=... APP_FILTER="visual studio code,postman,notion,openssl,github desktop,java,wsl" \
//	  go test ./internal/store/ -run TestDiagnoseLiveMatch -v

import (
	"os"
	"testing"

	_ "modernc.org/sqlite"
)

func TestDiagnoseLiveMatch(t *testing.T) {
	path := os.Getenv("PMDB_PATH")
	if path == "" {
		t.Skip("PMDB_PATH not set; this is a manual diagnostic, not a real test")
	}
	if err := RunLiveMatchDiagnostic(os.Stdout, path, os.Getenv("APP_FILTER")); err != nil {
		t.Fatal(err)
	}
}
