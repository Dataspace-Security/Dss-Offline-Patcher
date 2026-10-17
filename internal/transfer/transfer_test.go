package transfer

import (
	"os"
	"path/filepath"
	"testing"

	"offpatch/internal/intel"
)

func TestTransferable(t *testing.T) {
	for name, want := range map[string]bool{
		"october.pmb":                           true,
		"rotation-3.trust.json":                 true,
		"acq-zone-1-1.status.json":              true,
		"intel-acq-zone-1-1" + intel.FileSuffix: true,
		"payload.exe":                           false,
		"notes.json":                            false,
		"intel.gz":                              false,
		"x.pmb.exe":                             false,
	} {
		if got := Transferable(name); got != want {
			t.Errorf("Transferable(%q) = %v, want %v", name, got, want)
		}
	}
}

// Update intelligence must go through the drop-directory adapter like the
// other signed documents; anything else is refused.
func TestDropDirSendsIntel(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	ok := filepath.Join(src, "intel-acq-zone-1-1"+intel.FileSuffix)
	bad := filepath.Join(src, "tool.exe")
	os.WriteFile(ok, []byte("x"), 0o640)
	os.WriteFile(bad, []byte("x"), 0o640)
	if _, err := (DropDir{Dir: dst}).Send(ok); err != nil {
		t.Fatalf("intel not transferable: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, filepath.Base(ok))); err != nil {
		t.Fatalf("intel not delivered: %v", err)
	}
	if _, err := (DropDir{Dir: dst}).Send(bad); err == nil {
		t.Fatal(".exe transferred")
	}
}
