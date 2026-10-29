package acquire

import "testing"

// Discord's winget manifest has a plain exe without a silent switch: the
// vetted list makes it a per-user EXE with --silent; other apps are untouched.
func TestKnownSwitches(t *testing.T) {
	m := &WingetManifest{ID: "Discord.Discord", Version: "1.0.9264", Installers: []WingetInstaller{
		{Architecture: "x64", InstallerType: "exe", URL: "https://dl.discordapp.net/x/DiscordSetup.exe"},
		{Architecture: "x64", InstallerType: "nullsoft"},
	}}
	applyKnownSwitches(m)
	if in := m.Installers[0]; in.Switches.Silent != "--silent" || in.Scope != "user" {
		t.Fatalf("discord exe: %+v", in)
	}
	if m.Installers[1].Switches.Silent != "" {
		t.Fatal("non-exe installer changed")
	}
	o := &WingetManifest{ID: "Other.App", Installers: []WingetInstaller{{InstallerType: "exe"}}}
	applyKnownSwitches(o)
	if o.Installers[0].Switches.Silent != "" {
		t.Fatal("unknown app got a switch")
	}
	keep := &WingetManifest{ID: "discord.discord", Installers: []WingetInstaller{{InstallerType: "exe", Scope: "machine", Switches: WingetSwitches{Silent: "/S"}}}}
	applyKnownSwitches(keep)
	if keep.Installers[0].Switches.Silent != "/S" || keep.Installers[0].Scope != "machine" {
		t.Fatal("manifest's own switch/scope overridden")
	}

	// Chrome's standalone setup documents two silent modes: /silent per
	// user, /system-level /silent machine-wide; the scope picks the mode.
	ch := &WingetManifest{ID: "Google.Chrome.EXE", Installers: []WingetInstaller{
		{Architecture: "x86", InstallerType: "exe"},
		{Architecture: "x86", InstallerType: "exe", Scope: "machine"},
	}}
	applyKnownSwitches(ch)
	if in := ch.Installers[0]; in.Switches.Silent != "/silent" || in.Scope != "user" {
		t.Fatalf("chrome user exe: %+v", in)
	}
	if in := ch.Installers[1]; in.Switches.Silent != "/system-level /silent" || in.Scope != "machine" {
		t.Fatalf("chrome machine exe: %+v", in)
	}
}
