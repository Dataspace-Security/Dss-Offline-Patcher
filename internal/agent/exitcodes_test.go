package agent

import (
	"strings"
	"testing"
)

// hr converts an HRESULT to the int Go reports (wraps on 32-bit builds).
func hr(u uint32) int { return int(u) }

func TestClassifyInstall(t *testing.T) {
	cases := []struct {
		kind  string
		code  int
		state string
		want  string // substring of Detail
	}{
		{"msu", 0, "installed", "installed"},
		{"msi", 0, "installed", "installed"},
		{"msi", 3010, "pending_reboot", "reboot"},
		{"msu", 1641, "pending_reboot", "reboot"},
		{"msu", hr(0x80070BC2), "pending_reboot", "reboot required"},
		{"msu", hr(0x00240006), "installed", "already installed"},
		{"msu", hr(0x80240017), "not_applicable", "not applicable"},
		{"msu", hr(0x800F081E), "not_applicable", "not applicable"},
		{"msi", hr(0x800F081E), "failed", "exit code"}, // CBS code is wusa-only
		{"msi", 1618, "failed", retryLater},
		{"msu", 1618, "failed", retryLater},
		{"msu", hr(0x80240016), "failed", retryLater},
		{"msu", hr(0x8024001E), "failed", retryLater},
		{"msu", hr(0x800F0902), "failed", retryLater},
		{"msi", 1638, "failed", "another version"},
		{"msi", 1603, "failed", "exit code 1603 (0x00000643)"},
		{"msu", hr(0x80070005), "failed", "0x80070005"},
	}
	for _, c := range cases {
		r := classifyInstall(c.kind, c.code)
		if r.State != c.state || !strings.Contains(r.Detail, c.want) || r.ExitCode != c.code {
			t.Errorf("classifyInstall(%s, 0x%08X) = %+v, want state %s detail ~%q", c.kind, uint32(c.code), r, c.state, c.want)
		}
	}
}

func TestClassifyUninstall(t *testing.T) {
	cases := []struct {
		kind  string
		code  int
		state string
		want  string
	}{
		{"msu", 0, "installed", "uninstalled"},
		{"msi", 3010, "pending_reboot", "reboot"},
		{"msu", hr(0x80070BC2), "pending_reboot", "reboot"},
		{"msu", hr(0x00240007), "installed", "nothing to remove"},
		{"msi", 1605, "installed", "nothing to remove"},
		{"msu", 1605, "failed", "uninstaller exit code"},
		{"msi", 1618, "failed", retryLater},
		{"msu", hr(0x800F0902), "failed", retryLater},
		{"msi", 1603, "failed", "uninstaller exit code 1603"},
	}
	for _, c := range cases {
		r := classifyUninstall(c.kind, c.code)
		if r.State != c.state || !strings.Contains(r.Detail, c.want) {
			t.Errorf("classifyUninstall(%s, 0x%08X) = %+v, want state %s detail ~%q", c.kind, uint32(c.code), r, c.state, c.want)
		}
	}
}

// Every state the classifier produces must be one the server accepts.
func TestClassifyStatesKnown(t *testing.T) {
	known := map[string]bool{"installed": true, "pending_reboot": true, "failed": true, "not_applicable": true}
	for _, kind := range []string{"msu", "msi"} {
		for _, u := range []uint32{0, 3010, 1641, 1605, 1618, 1638, 0x80070BC2, 0x00240006, 0x00240007, 0x80240017, 0x800F081E, 0x80240016, 0x8024001E, 0x800F0902, 42} {
			for _, r := range []Result{classifyInstall(kind, hr(u)), classifyUninstall(kind, hr(u))} {
				if !known[r.State] {
					t.Errorf("%s 0x%08X: unknown state %q", kind, u, r.State)
				}
			}
		}
	}
}
