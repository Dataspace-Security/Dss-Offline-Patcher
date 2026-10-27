package web

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The console's Windows enrollment one-liner: agents connect by the server's
// IP (agent_url from /api/agent-setup), never by the console's server name,
// and the line never edits the PC's hosts file. The console has no JS test
// runner, so this guards the source.
func TestWindowsOneLinerUsesAgentURLWithoutHostsEdit(t *testing.T) {
	b, err := os.ReadFile("src/components/AgentSetup.tsx")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)

	for _, bad := range []string{`drivers\\etc\\hosts`, `drivers\etc\hosts`, "hostsPrelude", "hostsName", "Clear-DnsClientCache", "# DSS Patcher"} {
		if strings.Contains(src, bad) {
			t.Errorf("AgentSetup.tsx still contains %q (no hosts-file edits on endpoints)", bad)
		}
	}

	// The one-liner downloads the installer from the agent URL it is given.
	fn := regexp.MustCompile(`(?s)export function windowsOneLiner\((\w+): string.*?\n}\n`).FindStringSubmatch(src)
	if fn == nil {
		t.Fatal("windowsOneLiner not found")
	}
	if !strings.Contains(fn[0], "irm '${"+fn[1]+"}/api/agent-setup/bootstrap/windows.ps1'") {
		t.Errorf("windowsOneLiner must fetch the installer from its agent URL parameter %q:\n%s", fn[1], fn[0])
	}

	// The URL comes from /api/agent-setup's agent_url, not the browser's address bar.
	if strings.Contains(src, "window.location") {
		t.Error("AgentSetup.tsx must not derive the agent URL from window.location")
	}
	if !strings.Contains(src, "setServerURL(data.agent_url)") {
		t.Error("AgentSetup.tsx must fill the URL from agent_url returned by /api/agent-setup")
	}
}

// The cmd.exe one-liner (for endpoints where PowerShell itself is blocked) must fetch the
// installer from the same agent URL parameter, never shell out to PowerShell, and never edit the
// hosts file either.
func TestWindowsOneLinerCmdUsesAgentURLWithoutPowerShell(t *testing.T) {
	b, err := os.ReadFile("src/components/AgentSetup.tsx")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)

	fn := regexp.MustCompile(`(?s)export function windowsOneLinerCmd\((\w+): string.*?\n\}\n`).FindStringSubmatch(src)
	if fn == nil {
		t.Fatal("windowsOneLinerCmd not found")
	}
	if !strings.Contains(fn[0], "${"+fn[1]+"}/api/agent-setup/bootstrap/windows.cmd") {
		t.Errorf("windowsOneLinerCmd must fetch the installer from its agent URL parameter %q:\n%s", fn[1], fn[0])
	}
	for _, bad := range []string{"powershell", "PowerShell", "Invoke-WebRequest", "iex ", "irm '"} {
		if strings.Contains(fn[0], bad) {
			t.Errorf("windowsOneLinerCmd must not shell out to PowerShell (found %q):\n%s", bad, fn[0])
		}
	}
}
