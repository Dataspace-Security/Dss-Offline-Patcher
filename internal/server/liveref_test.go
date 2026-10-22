package server

import (
	"testing"

	"offpatch/internal/intel"
	"offpatch/internal/store"
)

// An old "can't import" result (from before EXE/zip support) no longer
// hides Import once the current rule says the app can be imported.
func TestLiveRefDropsStaleUnsupported(t *testing.T) {
	un := &store.AcqRequestRef{Status: "unsupported", Reason: "no MSI installer for x64 in winget (only nullsoft)"}
	if liveRef(un, intel.ImportableYes) != nil {
		t.Fatal("stale unsupported kept although importable")
	}
	if liveRef(un, intel.ImportableNo) != un || liveRef(un, "") != un {
		t.Fatal("unsupported dropped although still not importable")
	}
	pending := &store.AcqRequestRef{Status: "pending"}
	if liveRef(pending, intel.ImportableYes) != pending || liveRef(nil, intel.ImportableYes) != nil {
		t.Fatal("other states must be kept")
	}
}
