package agent

import (
	"testing"

	"offpatch/internal/store"
)

func TestIsUserHive(t *testing.T) {
	cases := map[string]bool{
		"S-1-5-21-3623811015-3361044348-30300820-1013":         true,
		"s-1-5-21-3623811015-3361044348-30300820-1013":         true,
		"S-1-12-1-1234567890-1234567890-1234567890-1234567890": true, // Entra ID user
		"S-1-5-21-3623811015-3361044348-30300820-1013_Classes": false,
		"S-1-5-21-3623811015-3361044348-30300820-1013_CLASSES": false,
		".DEFAULT":            false,
		".default":            false,
		"S-1-5-18":            false, // LocalSystem
		"S-1-5-19":            false, // LocalService
		"S-1-5-20":            false, // NetworkService
		"":                    false,
		"Software":            false,
		"S-1-5-21-abc":        false,
		`S-1-5-21-1\Software`: false,
	}
	for name, want := range cases {
		if got := isUserHive(name); got != want {
			t.Errorf("isUserHive(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestKeepUninstallEntry(t *testing.T) {
	cases := []struct {
		msi       bool
		name      string
		sysComp   uint64
		hasParent bool
		want      bool
	}{
		{true, "", 1, true, true}, // MSI products are always kept
		{false, "Zoom Workplace", 0, false, true},
		{false, "  ", 0, false, false},
		{false, "Hidden component", 1, false, false},
		{false, "Update for X", 0, true, false},
	}
	for _, c := range cases {
		if got := keepUninstallEntry(c.msi, c.name, c.sysComp, c.hasParent); got != c.want {
			t.Errorf("keepUninstallEntry(%+v) = %v", c, got)
		}
	}
}

func TestMergeUserInventory(t *testing.T) {
	machine := []store.InventoryItem{
		{Kind: "kb", ID: "KB5000001"},
		{Kind: "product", ID: "{11111111-1111-1111-1111-111111111111}", Name: "Agent", Version: "2.0"},
		{Kind: "product", ID: "Google Chrome", Name: "Google Chrome", Version: "130.0"},
	}
	user := []store.InventoryItem{
		// also installed machine-wide (case differs): the machine entry wins
		{Kind: "product", ID: "{11111111-1111-1111-1111-111111111111}", Name: "Agent", Version: "1.0"},
		{Kind: "product", ID: "google chrome", Name: "Google Chrome", Version: "129.0"},
		// two profiles with Zoom: the oldest copy is reported
		{Kind: "product", ID: "ZoomUMX", Name: "Zoom", Version: "6.2.0"},
		{Kind: "product", ID: "ZoomUMX", Name: "Zoom", Version: "5.17.1"},
		{Kind: "product", ID: "ZoomUMX", Name: "Zoom", Version: ""},
		{Kind: "product", ID: "Microsoft VS Code", Name: "VS Code", Version: ""},
		{Kind: "product", ID: "Microsoft VS Code", Name: "VS Code", Version: "1.95"},
	}
	got := mergeUserInventory(machine, user)
	if len(got) != 5 {
		t.Fatalf("merged: %+v", got)
	}
	for i := range machine {
		if got[i] != machine[i] {
			t.Errorf("machine entry %d changed: %+v", i, got[i])
		}
	}
	if z := got[3]; z.ID != "ZoomUMX" || z.Version != "5.17.1" || z.Scope != "user" {
		t.Errorf("zoom: %+v", z)
	}
	if c := got[4]; c.Version != "1.95" || c.Scope != "user" {
		t.Errorf("a known version beats an unknown one: %+v", c)
	}
	if user[2].Scope != "" {
		t.Error("input must not be modified")
	}
	if len(mergeUserInventory(machine, nil)) != len(machine) {
		t.Error("no user hives: machine inventory unchanged")
	}
}
