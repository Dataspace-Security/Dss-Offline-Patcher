package agent

import (
	"encoding/json"
	"strings"

	"offpatch/internal/store"
)

// parseStoreApps turns the appx listing (JSON array of {id,name,version})
// into inventory items of kind "appx", one per package family (an app
// installed for several users is listed once, at its highest version).
func parseStoreApps(out []byte) []store.InventoryItem {
	var raw []struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil
	}
	seen := map[string]int{}
	var items []store.InventoryItem
	for _, r := range raw {
		id := strings.TrimSpace(r.ID)
		if id == "" {
			continue
		}
		if i, ok := seen[id]; ok {
			if store.VersionAtLeast(r.Version, items[i].Version) {
				items[i].Version = r.Version
			}
			continue
		}
		seen[id] = len(items)
		items = append(items, store.InventoryItem{Kind: "appx", ID: id, Name: strings.TrimSpace(r.Name), Version: strings.TrimSpace(r.Version), Source: "msstore"})
	}
	return items
}
