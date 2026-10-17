package agent

import "testing"

func TestWindowsProductName(t *testing.T) {
	for _, c := range []struct {
		product string
		build   int
		want    string
	}{
		{"Windows 10 Pro N", 26300, "Windows 11 Pro N"},
		{"Windows 10 Enterprise", 22621, "Windows 11 Enterprise"},
		{"Windows 10 Pro", 19045, "Windows 10 Pro"},
		{"Windows Server 2022 Standard", 20348, "Windows Server 2022 Standard"},
		{"Windows Server 2025 Datacenter", 26100, "Windows Server 2025 Datacenter"},
	} {
		if got := windowsProductName(c.product, c.build); got != c.want {
			t.Errorf("%q build %d: got %q, want %q", c.product, c.build, got, c.want)
		}
	}
}
