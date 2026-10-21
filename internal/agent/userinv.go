package agent

import (
	"regexp"
	"strings"

	"offpatch/internal/store"
)

// Per-user installs (Zoom, Teams, VS Code user setup, ...) register under
// the user's own hive, HKU\<SID>\Software\...\Uninstall. Only hives that are
// loaded (signed-in users, running services) can be read; that is enough to
// show the server what the people using this machine run.

// userUninstallKey is relative to HKU\<SID>.
const userUninstallKey = `Software\Microsoft\Windows\CurrentVersion\Uninstall`

// sidRe accepts a SID string (S-1-5-21-…, S-1-12-1-… for Entra ID users).
var sidRe = regexp.MustCompile(`^S-1-[0-9]+(-[0-9]+)+$`)

// wellKnownServiceSIDs: LocalSystem, LocalService, NetworkService. Their
// hives hold no user-installed applications.
var wellKnownServiceSIDs = map[string]bool{"S-1-5-18": true, "S-1-5-19": true, "S-1-5-20": true}

// isUserHive reports whether a subkey name of HKEY_USERS is a loaded user
// profile worth scanning: not .DEFAULT, not a <SID>_Classes hive, not a
// service account.
func isUserHive(name string) bool {
	n := strings.ToUpper(strings.TrimSpace(name))
	if strings.HasSuffix(n, "_CLASSES") || n == ".DEFAULT" || wellKnownServiceSIDs[n] {
		return false
	}
	return sidRe.MatchString(n)
}

// keepUninstallEntry is the rule shared by the machine and the per-user
// scans: Windows Installer products (key named by a product code) are always
// kept; other entries need a display name and must not be an update of
// another entry (ParentKeyName). Entries marked SystemComponent (hidden in
// Apps & features) are kept only with a DisplayVersion: Microsoft Edge
// WebView2 Runtime marks itself so, and without it an installed update
// never verifies. Hidden entries without a version are Windows internals.
func keepUninstallEntry(isMSI bool, displayName, displayVersion string, systemComponent uint64, hasParent bool) bool {
	if isMSI {
		return true
	}
	if strings.TrimSpace(displayName) == "" || hasParent {
		return false
	}
	return systemComponent != 1 || strings.TrimSpace(displayVersion) != ""
}

func inventoryKey(it store.InventoryItem) string { return it.Kind + "\x00" + strings.ToUpper(it.ID) }

// mergeUserInventory adds per-user entries (marked Scope "user") to the
// machine inventory. A product also installed machine-wide is reported once,
// as the machine entry: after a per-machine install the endpoint verifies.
// The same product in several user profiles is reported once, with the
// lowest version, so an outdated copy still shows as needing the update.
func mergeUserInventory(machine, user []store.InventoryItem) []store.InventoryItem {
	out := make([]store.InventoryItem, 0, len(machine)+len(user))
	seen := make(map[string]bool, len(machine))
	for _, it := range machine {
		seen[inventoryKey(it)] = true
		out = append(out, it)
	}
	idx := map[string]int{} // key → index in out for user entries
	for _, it := range user {
		k := inventoryKey(it)
		if seen[k] {
			continue
		}
		it.Scope = "user"
		i, dup := idx[k]
		if !dup {
			idx[k] = len(out)
			out = append(out, it)
			continue
		}
		if cur := out[i]; lowerVersion(it.Version, cur.Version) {
			out[i] = it
		}
	}
	return out
}

// lowerVersion: a is a better "oldest copy" than b. A known version beats an
// unknown one (it is the evidence the server can compare).
func lowerVersion(a, b string) bool {
	switch {
	case a == "":
		return false
	case b == "":
		return true
	}
	return !store.VersionAtLeast(a, b)
}
