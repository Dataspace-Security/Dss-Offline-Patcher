package agent

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

// Facts describe the endpoint for applicability and fleet reporting.
type Facts struct {
	Hostname  string
	OS        string // always "windows" for supported platforms
	OSVersion string
	Build     int
	Arch      string // x64 | x86 | arm64
	Edition   string // Windows EditionID, e.g. Enterprise, Professional, ServerStandard
}

// Result of an install attempt, already mapped to a target state.
type Result struct {
	State    string // installed | pending_reboot | failed | not_applicable
	ExitCode int
	Detail   string
}

// Platform is the OS integration. Implementations must not reach any network.
type Platform interface {
	Name() string
	Facts() (Facts, error)
	Inventory() (items []store.InventoryItem, rebootPending bool, err error)
	Install(ctx context.Context, p manifest.Package, file string) Result
	// Reboot schedules a restart (with user warning where the OS supports it).
	Reboot(ctx context.Context, reason string) error
	// Health runs fixed post-install checks; no arbitrary commands.
	Health(ctx context.Context, checks []store.HealthCheck) (ok bool, detail string)
}

// tcpListening is shared by platforms for the tcp_listening check.
func tcpListening(port string) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), 3*time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// runHealth evaluates checks using a platform-specific service probe.
func runHealth(checks []store.HealthCheck, serviceRunning func(string) (bool, error)) (bool, string) {
	var bad []string
	for _, c := range checks {
		switch c.Type {
		case "service_running":
			ok, err := serviceRunning(c.Name)
			if err != nil {
				bad = append(bad, fmt.Sprintf("service %s: %v", c.Name, err))
			} else if !ok {
				bad = append(bad, "service "+c.Name+" not running")
			}
		case "tcp_listening":
			if !tcpListening(c.Name) {
				bad = append(bad, "nothing listening on port "+c.Name)
			}
		default:
			bad = append(bad, "unknown check "+c.Type)
		}
	}
	if len(bad) > 0 {
		return false, strings.Join(bad, "; ")
	}
	return true, fmt.Sprintf("%d check(s) passed", len(checks))
}

// hardwareReporter is implemented by platforms that can describe the
// machine (model, CPU, RAM, disks...). It must be cheap: it runs on every
// check-in.
type hardwareReporter interface {
	Hardware(ctx context.Context) store.Hardware
}

// fillNetwork adds non-loopback IP addresses, the MAC address of the first
// interface carrying an IPv4 address, and the local time zone.
func fillNetwork(h *store.Hardware) {
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.IsLinkLocalUnicast() || ipn.IP.IsLoopback() {
				continue
			}
			h.IPAddresses = append(h.IPAddresses, ipn.IP.String())
			if ipn.IP.To4() != nil && h.MACAddress == "" && len(i.HardwareAddr) > 0 {
				h.MACAddress = i.HardwareAddr.String()
			}
		}
	}
	// IPv4 first: easier to read than (often several) IPv6 addresses.
	sort.SliceStable(h.IPAddresses, func(i, j int) bool {
		return strings.Contains(h.IPAddresses[i], ".") && !strings.Contains(h.IPAddresses[j], ".")
	})
	h.Timezone = time.Local.String()
	if h.Timezone == "Local" {
		if l, err := os.Readlink("/etc/localtime"); err == nil && strings.Contains(l, "zoneinfo/") {
			h.Timezone = l[strings.Index(l, "zoneinfo/")+len("zoneinfo/"):]
		} else {
			h.Timezone, _ = time.Now().Zone()
		}
	}
}

// windowsProductName corrects the registry ProductName, which still reads
// "Windows 10 …" on Windows 11 (first Windows 11 build: 22000).
func windowsProductName(product string, build int) string {
	if build >= 22000 && strings.HasPrefix(product, "Windows 10") {
		return "Windows 11" + strings.TrimPrefix(product, "Windows 10")
	}
	return product
}
