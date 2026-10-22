package store

import (
	"context"
	"strings"
	"testing"
)

func targetDetail(t *testing.T, s *Store, dep, ep string) string {
	t.Helper()
	var d string
	if err := s.db.QueryRow(`SELECT detail FROM targets WHERE deployment_id=? AND endpoint_id=?`, dep, ep).Scan(&d); err != nil {
		t.Fatal(err)
	}
	return d
}

// Network limits hold back new downloads across all deployments: per site
// and fleet-wide. A machine that gets its slot later loses the waiting note.
func TestNetworkLimits(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	s.Policy.MaxDownloadsTotal, s.Policy.MaxDownloadsPerSite = 3, 2
	addPackage(t, s, Package{PackageID: "Acme-3.0", Kind: "msi", Version: "3.0.0", PackageName: "Acme App", ProductCode: "{A}"})
	for _, id := range []string{"h1", "h2", "h3", "b1", "b2", "n1"} {
		addEndpoint(t, s, id, []string{"all"}, acmeOld)
	}
	if _, err := s.db.Exec(`UPDATE endpoints SET site='branch-1' WHERE endpoint_id IN ('b1','b2')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE endpoints SET site='' WHERE endpoint_id='n1'`); err != nil {
		t.Fatal(err)
	}
	d, err := createApproved(s, ctx, "user:otto", NewDeployment{PackageID: "Acme-3.0", Name: "acme", Rings: allRing, MaxFailurePct: 50})
	if err != nil || d.State != "active" {
		t.Fatalf("%v %+v", err, d)
	}
	got := func(ep string) int { return len(checkin(t, s, ep, acmeOld, false).Assignments) }
	if got("h1") != 1 || got("h2") != 1 {
		t.Fatal("first two at hq should start")
	}
	if got("h3") != 0 || !strings.Contains(targetDetail(t, s, d.DeploymentID, "h3"), "site limit 2") {
		t.Fatalf("third at hq: site limit expected, detail %q", targetDetail(t, s, d.DeploymentID, "h3"))
	}
	if got("b1") != 1 {
		t.Fatal("another site has its own slots")
	}
	if got("b2") != 0 || !strings.Contains(targetDetail(t, s, d.DeploymentID, "b2"), "network limit 3") {
		t.Fatalf("fleet limit expected, detail %q", targetDetail(t, s, d.DeploymentID, "b2"))
	}
	if got("n1") != 0 {
		t.Fatal("no site: the fleet limit still applies")
	}
	// h1 finished downloading: hq has a slot again, and the note goes.
	if _, err := s.db.Exec(`UPDATE targets SET state='installing' WHERE endpoint_id='h1'`); err != nil {
		t.Fatal(err)
	}
	if got("h3") != 1 || targetDetail(t, s, d.DeploymentID, "h3") != "" {
		t.Fatalf("h3 after a slot freed: detail %q", targetDetail(t, s, d.DeploymentID, "h3"))
	}
	// A machine already handed its download keeps it on later check-ins.
	if got("h2") != 1 {
		t.Fatal("h2 keeps its assignment")
	}
	// No limits: everyone may start.
	s.Policy.MaxDownloadsTotal, s.Policy.MaxDownloadsPerSite = 0, 0
	if got("b2") != 1 || got("n1") != 1 {
		t.Fatal("limits off")
	}
}

func TestSiteDownloadLimit(t *testing.T) {
	p := Policy{MaxDownloadsPerSite: 5, SiteMaxDownloads: map[string]int{"tiny": 1, "hq": 0}}
	for site, want := range map[string]int{"": 0, "branch": 5, "tiny": 1, "hq": 0} {
		if got := p.SiteDownloadLimit(site); got != want {
			t.Errorf("%q: %d, want %d", site, got, want)
		}
	}
}
