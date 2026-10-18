//go:build windows

package agent

import (
	"testing"

	"golang.org/x/sys/windows/registry"
)

// TestUserProductsReadOnly enumerates the loaded user hives of this machine
// (read-only) and checks the per-user scan is consistent with the registry.
func TestUserProductsReadOnly(t *testing.T) {
	items := userProducts()
	k, err := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		t.Skipf("HKEY_USERS not readable: %v", err)
	}
	sids, _ := k.ReadSubKeyNames(-1)
	k.Close()
	expect := 0
	for _, sid := range sids {
		if !isUserHive(sid) {
			continue
		}
		found, err := scanUninstall(registry.USERS, sid+`\`+userUninstallKey, 0)
		if err == nil {
			expect += len(found)
		}
	}
	if len(items) != expect {
		t.Fatalf("userProducts found %d entries, direct scan %d", len(items), expect)
	}
	for _, it := range items {
		if it.Kind != "product" || it.ID == "" {
			t.Errorf("bad item %+v", it)
		}
	}
	machine, err := msiProducts()
	if err != nil {
		t.Fatal(err)
	}
	merged := mergeUserInventory(machine, items)
	users := 0
	for _, it := range merged {
		if it.Scope == "user" {
			users++
		}
	}
	t.Logf("loaded user hives: %d; per-user entries: %d (%d after merging with %d machine entries)", len(sids), len(items), users, len(machine))
}
