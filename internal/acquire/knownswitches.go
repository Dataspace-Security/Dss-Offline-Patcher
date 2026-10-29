package acquire

import "strings"

// knownSilent: well-known apps whose winget manifest lists a plain "exe"
// without InstallerSwitches.Silent, although the vendor's installer has a
// documented silent mode. Kept short and vetted by hand: a wrong switch
// would show a setup window on users' PCs. Squirrel installers (Discord,
// GitHub Desktop, Postman) install silently with --silent, per user. The
// Google Chrome standalone setup documents /silent (per user) and
// /system-level /silent (machine-wide); per-machine entries take the latter.
var knownSilent = map[string]struct{ silentMachine, silentUser, scope string }{
	"discord.discord":      {"--silent", "--silent", "user"},
	"github.githubdesktop": {"--silent", "--silent", "user"},
	"postman.postman":      {"--silent", "--silent", "user"},
	"google.chrome.exe":    {"/system-level /silent", "/silent", "user"},
}

// applyKnownSwitches fills in the silent switch (and scope, when the
// manifest does not say) of a known app's plain EXE installers.
func applyKnownSwitches(m *WingetManifest) {
	k, ok := knownSilent[strings.ToLower(m.ID)]
	if !ok {
		return
	}
	for i := range m.Installers {
		in := &m.Installers[i]
		if in.InstallerType != "exe" || in.Switches.Silent != "" {
			continue
		}
		if strings.ToLower(in.Scope) == "machine" {
			in.Switches.Silent = k.silentMachine
		} else {
			in.Switches.Silent = k.silentUser
		}
		if in.Scope == "" {
			in.Scope = k.scope
		}
	}
}
