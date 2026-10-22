package acquire

import "strings"

// knownSilent: well-known apps whose winget manifest lists a plain "exe"
// without InstallerSwitches.Silent, although the vendor's installer has a
// documented silent mode. Kept short and vetted by hand: a wrong switch
// would show a setup window on users' PCs. Squirrel installers (Discord,
// GitHub Desktop, Postman) install silently with --silent, per user.
var knownSilent = map[string]struct{ silent, scope string }{
	"discord.discord":      {"--silent", "user"},
	"github.githubdesktop": {"--silent", "user"},
	"postman.postman":      {"--silent", "user"},
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
		in.Switches.Silent = k.silent
		if in.Scope == "" {
			in.Scope = k.scope
		}
	}
}
