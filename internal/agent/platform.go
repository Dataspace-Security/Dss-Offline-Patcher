package agent

import (
	"context"
	"fmt"
	"net"
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
