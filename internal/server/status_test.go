package server

import (
	"testing"

	"offpatch/internal/store"
)

// Only compliant is refined; out_of_support beats updates_available; no
// intelligence (Missing nil) leaves the status alone.
func TestHonestStatus(t *testing.T) {
	m := func(os, apps int, support string) *store.EndpointMissing {
		return &store.EndpointMissing{OS: os, Apps: apps, OSSupport: support}
	}
	for _, c := range []struct {
		status  string
		missing *store.EndpointMissing
		want    string
	}{
		{"compliant", nil, "compliant"},
		{"compliant", m(0, 0, "supported"), "compliant"},
		{"compliant", m(0, 0, ""), "compliant"},
		{"compliant", m(1, 0, "supported"), "updates_available"},
		{"compliant", m(0, 2, ""), "updates_available"},
		{"compliant", m(0, 0, "out_of_support"), "out_of_support"},
		{"compliant", m(3, 1, "out_of_support"), "out_of_support"},
		{"failed", m(1, 1, "out_of_support"), "failed"},
		{"pending_reboot", m(1, 0, "out_of_support"), "pending_reboot"},
		{"offline", m(1, 0, "out_of_support"), "offline"},
		{"noncompliant", m(1, 0, ""), "noncompliant"},
		{"awaiting_checkin", m(0, 0, ""), "awaiting_checkin"},
	} {
		if got := honestStatus(store.Endpoint{Status: c.status, Missing: c.missing}); got != c.want {
			t.Errorf("%s %+v: got %s, want %s", c.status, c.missing, got, c.want)
		}
	}
}
