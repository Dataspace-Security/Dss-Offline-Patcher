package agent

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

// uninstallView names the registry view of uninstallKeys[i] on a machine
// of architecture arch: the native key is the 64-bit view ("64"), except on
// 32-bit Windows where it is "32"; WOW6432Node is always "32".
func uninstallView(i int, arch string) string {
	if i == 0 && arch != "x86" {
		return "64"
	}
	return "32"
}

// servicingScript lists the update packages the servicing stack reports
// as installed (Get-WindowsPackage). Some updates never appear in
// Win32_QuickFixEngineering (checkpoint and some .NET updates); their
// package names carry the KB ("Package_for_KB5043080~31bf3856ad364e35~amd64~~26100.1742.1.10").
const servicingScript = `ConvertTo-Json -Compress @(Get-WindowsPackage -Online -ErrorAction Stop |
  Where-Object { $_.PackageState -eq 'Installed' } | ForEach-Object { [string]$_.PackageName })`

// servicingKBRe finds the KB number in a servicing package name.
var servicingKBRe = regexp.MustCompile(`(?i)(?:^|[_~-])KB(\d{6,8})(?:[~_.-]|$)`)

// parseServicingKBs returns the KB numbers ("KB5043080") named by the
// installed servicing packages (JSON array of package names), sorted and
// without duplicates. RollupFix packages carry the build revision, not a
// KB; the revision is already in the reported OS version.
func parseServicingKBs(out []byte) []string {
	var names []string
	if err := json.Unmarshal(out, &names); err != nil {
		return nil
	}
	seen := map[string]bool{}
	var kbs []string
	for _, n := range names {
		for _, m := range servicingKBRe.FindAllStringSubmatch(n, -1) {
			kb := "KB" + m[1]
			if !seen[kb] {
				seen[kb] = true
				kbs = append(kbs, kb)
			}
		}
	}
	sort.Strings(kbs)
	return kbs
}

// mergeKBs adds the servicing KBs to the QFE list (both upper-case KB ids),
// without duplicates, in a stable order.
func mergeKBs(qfe, servicing []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, list := range [][]string{qfe, servicing} {
		for _, kb := range list {
			kb = strings.ToUpper(strings.TrimSpace(kb))
			if strings.HasPrefix(kb, "KB") && !seen[kb] {
				seen[kb] = true
				out = append(out, kb)
			}
		}
	}
	return out
}
